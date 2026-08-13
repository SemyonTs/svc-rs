// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::fd::read_file_to_buf;
use crate::path::CStrBuf;
use crate::types::Service;

fn read_rlimit_value(s: &Service, filename: &[u8]) -> Option<libc::rlim_t> {
    let mut path = CStrBuf::from_bytes(s.dir_bytes());
    path.push(filename);
    let mut buf = [0u8; 32];
    let nr = read_file_to_buf(&path, &mut buf);
    if nr <= 0 {
        return None;
    }
    let mut val: u64 = 0;
    let mut has_digit = false;
    for &c in &buf[..nr as usize] {
        if c >= b'0' && c <= b'9' {
            val = val.saturating_mul(10).saturating_add((c - b'0') as u64);
            has_digit = true;
        } else {
            break;
        }
    }
    if has_digit {
        Some(val as libc::rlim_t)
    } else {
        None
    }
}

fn read_nice_value(s: &Service) -> Option<libc::c_int> {
    let mut path = CStrBuf::from_bytes(s.dir_bytes());
    path.push(b"/nice");
    let mut buf = [0u8; 16];
    let nr = read_file_to_buf(&path, &mut buf);
    if nr <= 0 {
        return None;
    }
    let mut val: i32 = 0;
    let mut sign: i32 = 1;
    let mut i = 0;
    if i < nr as usize && buf[i] == b'-' {
        sign = -1;
        i += 1;
    }
    let mut has_digit = false;
    while i < nr as usize && i < buf.len() {
        let c = buf[i];
        if c >= b'0' && c <= b'9' {
            val = val.saturating_mul(10).saturating_add((c - b'0') as i32);
            has_digit = true;
        } else {
            break;
        }
        i += 1;
    }
    if has_digit {
        Some(sign.saturating_mul(val))
    } else {
        None
    }
}

/// SECURITY: MUST be called BEFORE chroot().
/// Reads rlimit/nice files using absolute host paths from s.dir_bytes().
///
/// # Safety
/// Calls libc::setrlimit and libc::nice.
pub unsafe fn apply_security_restrictions(s: &Service) {
    macro_rules! set_rlimit {
        ($resource:expr, $file:expr) => {
            if let Some(val) = read_rlimit_value(s, $file) {
                let rlim = libc::rlimit {
                    rlim_cur: val,
                    rlim_max: val,
                };
                libc::setrlimit($resource, &rlim);
            }
        };
    }
    set_rlimit!(libc::RLIMIT_CPU, b"/rlimit_cpu");
    set_rlimit!(libc::RLIMIT_AS, b"/rlimit_as");
    set_rlimit!(libc::RLIMIT_NOFILE, b"/rlimit_nofile");
    set_rlimit!(libc::RLIMIT_FSIZE, b"/rlimit_fsize");
    set_rlimit!(libc::RLIMIT_NPROC, b"/rlimit_nproc");
    set_rlimit!(libc::RLIMIT_CORE, b"/rlimit_core");

    if let Some(nice_val) = read_nice_value(s) {
        libc::nice(nice_val);
    }
}
