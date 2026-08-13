// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::consts::*;
use crate::fd::read_file_to_buf;
use crate::path::CStrBuf;
use crate::types::Service;
use core::ffi::c_char;
use core::mem;
use core::ptr;
use libc::{gid_t, uid_t};

fn resolve_uid(name: &[u8]) -> Option<uid_t> {
    let mut end = name.len();
    while end > 0 && matches!(name[end - 1], b'\n' | b'\r' | b' ' | 0) {
        end -= 1;
    }
    if end == 0 || end >= NAME_BUF {
        return None;
    }

    let mut clean = [0u8; NAME_BUF];
    clean[..end].copy_from_slice(&name[..end]);
    clean[end] = 0;
    if clean[..end].contains(&0) {
        return None;
    }

    let mut pwd: libc::passwd = unsafe { mem::zeroed() };
    let mut buf = [0u8; PASSWD_BUF];
    let mut result: *mut libc::passwd = ptr::null_mut();
    let ret = unsafe {
        libc::getpwnam_r(
            clean.as_ptr() as *const c_char,
            &mut pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        )
    };
    if ret == 0 && !result.is_null() {
        Some(pwd.pw_uid)
    } else {
        None
    }
}

fn resolve_gid(name: &[u8]) -> Option<gid_t> {
    let mut end = name.len();
    while end > 0 && matches!(name[end - 1], b'\n' | b'\r' | b' ' | 0) {
        end -= 1;
    }
    if end == 0 || end >= NAME_BUF {
        return None;
    }

    let mut clean = [0u8; NAME_BUF];
    clean[..end].copy_from_slice(&name[..end]);
    clean[end] = 0;
    if clean[..end].contains(&0) {
        return None;
    }

    let mut grp: libc::group = unsafe { mem::zeroed() };
    let mut buf = [0u8; GROUP_BUF];
    let mut result: *mut libc::group = ptr::null_mut();
    let ret = unsafe {
        libc::getgrnam_r(
            clean.as_ptr() as *const c_char,
            &mut grp,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        )
    };
    if ret == 0 && !result.is_null() {
        Some(grp.gr_gid)
    } else {
        None
    }
}

fn parse_numeric_or_name(data: &[u8]) -> Option<u32> {
    let mut end = data.len();
    while end > 0 && matches!(data[end - 1], b'\n' | b'\r' | b' ') {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let mut val: u32 = 0;
    let mut numeric = true;
    for &c in &data[..end] {
        if c >= b'0' && c <= b'9' {
            val = val.saturating_mul(10).saturating_add((c - b'0') as u32);
        } else {
            numeric = false;
            break;
        }
    }
    if numeric { Some(val) } else { None }
}

pub fn parse_user_group(s: &mut Service) {
    s.uid = 0;
    s.gid = 0;
    s.has_uid = false;
    let dir = CStrBuf::from_bytes(s.dir_bytes());

    let mut user_path = CStrBuf::from_bytes(dir.as_bytes());
    user_path.push(b"/user");
    let mut ubuf = [0u8; NAME_BUF];
    let nr = read_file_to_buf(&user_path, &mut ubuf);
    if nr > 0 {
        let data = &ubuf[..nr as usize];
        if let Some(uid) = parse_numeric_or_name(data) {
            s.uid = uid;
            s.has_uid = true;
        } else if let Some(uid) = resolve_uid(data) {
            s.uid = uid;
            s.has_uid = true;
        }
    }

    let mut grp_path = CStrBuf::from_bytes(dir.as_bytes());
    grp_path.push(b"/group");
    let mut gbuf = [0u8; NAME_BUF];
    let gnr = read_file_to_buf(&grp_path, &mut gbuf);
    if gnr > 0 {
        let data = &gbuf[..gnr as usize];
        if let Some(gid) = parse_numeric_or_name(data) {
            s.gid = gid;
        } else if let Some(gid) = resolve_gid(data) {
            s.gid = gid;
        }
    }
}

pub fn read_env(s: &mut Service) {
    let mut env_path = CStrBuf::from_bytes(s.dir_bytes());
    env_path.push(b"/env");
    let fd = unsafe { libc::open(env_path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        s.env_count = 0;
        s.env_ptrs[0] = ptr::null();
        return;
    }
    let mut buf = [0u8; ENV_BUF];
    let nr = crate::fd::read_all_nonblock(fd, &mut buf);
    unsafe { crate::fd::close_fd(fd) };
    if nr <= 0 {
        s.env_count = 0;
        s.env_ptrs[0] = ptr::null();
        return;
    }

    let data = &buf[..nr as usize];
    let mut pos = 0;
    let mut env_pos = 0;
    s.env_count = 0;

    while pos < data.len() && s.env_count < MAX_ENV_VARS {
        let mut end = pos;
        while end < data.len() && data[end] != b'\n' && data[end] != b'\r' {
            end += 1;
        }
        let mut start = pos;
        while start < end && matches!(data[start], b' ' | b'\t') {
            start += 1;
        }
        let mut line_end = end;
        while line_end > start && matches!(data[line_end - 1], b' ' | b'\t') {
            line_end -= 1;
        }

        if line_end > start && data[start] != b'#' {
            let mut eq = start;
            while eq < line_end && data[eq] != b'=' {
                eq += 1;
            }
            if eq > start && eq < line_end {
                let key_len = eq - start;
                let val_len = line_end - eq - 1;
                let total_len = key_len + 1 + val_len;
                if env_pos + total_len + 1 <= ENV_BUF {
                    s.env_buf[env_pos..env_pos + key_len].copy_from_slice(&data[start..eq]);
                    env_pos += key_len;
                    s.env_buf[env_pos] = b'=';
                    env_pos += 1;
                    s.env_buf[env_pos..env_pos + val_len].copy_from_slice(&data[eq + 1..line_end]);
                    env_pos += val_len;
                    s.env_buf[env_pos] = 0;
                    unsafe {
                        s.env_ptrs[s.env_count] =
                            s.env_buf.as_ptr().add(env_pos - total_len) as *const c_char;
                    }
                    s.env_count += 1;
                    env_pos += 1;
                }
            }
        }
        pos = end + 1;
        while pos < data.len() && matches!(data[pos], b'\n' | b'\r') {
            pos += 1;
        }
    }
    s.env_ptrs[s.env_count] = ptr::null();
}

pub fn check_chroot(s: &Service) -> bool {
    let mut root_path = CStrBuf::from_bytes(s.dir_bytes());
    root_path.push(b"/root");
    unsafe { libc::access(root_path.as_ptr(), libc::F_OK) == 0 }
}

pub fn prepare_service_env(s: &mut Service) {
    read_env(s);
    s.chroot_enabled = check_chroot(s);
}
