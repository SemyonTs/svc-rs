// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::consts::*;
use crate::fd::{bytes_eq, read_file_to_buf};
use crate::log::supervisor_log;
use crate::path::CStrBuf;
use crate::service::find_service_by_dir;
use crate::status::write_status_file;
use crate::types::*;
use crate::user::{parse_user_group, prepare_service_env};
use core::ffi::CStr;

pub fn add_service(services: &mut [Service], name: &[u8], dir: &CStrBuf) {
    for s in services.iter_mut() {
        if !s.active {
            *s = SERVICE_EMPTY;
            s.active = true;
            s.present = true;
            s.stopping = false;
            s.set_dir(dir);
            s.set_name(name);
            s.state = STATE_DOWN;
            s.restart_at = 0;

            let mut down_path = CStrBuf::from_bytes(dir.as_bytes());
            down_path.push(b"/down");
            if unsafe { libc::access(down_path.as_ptr(), libc::F_OK) } == 0 {
                s.auto_start = false;
            }
            let mut once_path = CStrBuf::from_bytes(dir.as_bytes());
            once_path.push(b"/once");
            if unsafe { libc::access(once_path.as_ptr(), libc::F_OK) } == 0 {
                s.once = true;
            }

            let mut deps_path = CStrBuf::from_bytes(dir.as_bytes());
            deps_path.push(b"/depends");
            let mut dep_buf = [0u8; DEP_FILE_BUF];
            let nr = read_file_to_buf(&deps_path, &mut dep_buf);
            if nr > 0 {
                let data = &dep_buf[..nr as usize];
                let mut start = 0;
                let mut di = 0;
                while start < data.len() && di < MAX_DEPENDENCIES {
                    let mut end = start;
                    while end < data.len() && data[end] != b'\n' && data[end] != b'\r' {
                        end += 1;
                    }
                    let line = &data[start..end];
                    let mut l = 0;
                    while l < line.len() && line[l] == b' ' {
                        l += 1;
                    }
                    let mut r = line.len();
                    while r > l && matches!(line[r - 1], b' ' | b'\t') {
                        r -= 1;
                    }
                    let clean = &line[l..r];
                    if !clean.is_empty() {
                        let (soft, dep_name) = if clean.starts_with(b"?") {
                            (true, &clean[1..])
                        } else {
                            (false, clean)
                        };
                        let nlen = core::cmp::min(dep_name.len(), NAME_BUF - 1);
                        s.deps[di].name_len = nlen;
                        s.deps[di].name[..nlen].copy_from_slice(&dep_name[..nlen]);
                        s.deps[di].name[nlen] = 0;
                        s.deps[di].soft = soft;
                        di += 1;
                    }
                    start = end + 1;
                    while start < data.len() && matches!(data[start], b'\n' | b'\r') {
                        start += 1;
                    }
                }
                s.deps_count = di;
            }

            let mut log_run = CStrBuf::from_bytes(dir.as_bytes());
            log_run.push(b"/log/run");
            if unsafe { libc::access(log_run.as_ptr(), libc::X_OK) } == 0 {
                s.has_log = true;
            }

            parse_user_group(s);
            prepare_service_env(s);
            write_status_file(s);
            supervisor_log(b"service added: ");
            supervisor_log(name);
            return;
        }
    }
}

pub fn scan_services(root: &CStrBuf, services: &mut [Service]) -> bool {
    unsafe {
        let dp = libc::opendir(root.as_ptr());
        if dp.is_null() {
            return false;
        }
        for s in services.iter_mut() {
            if s.active {
                s.present = false;
            }
        }
        loop {
            let ent = libc::readdir(dp);
            if ent.is_null() {
                break;
            }
            let name = CStr::from_ptr((*ent).d_name.as_ptr()).to_bytes();
            if name.is_empty() || bytes_eq(name, b".") || bytes_eq(name, b"..") {
                continue;
            }
            let mut dir = CStrBuf::from_bytes(root.as_bytes());
            dir.push(b"/");
            dir.push(name);
            let mut run = CStrBuf::from_bytes(dir.as_bytes());
            run.push(b"/run");
            if libc::access(run.as_ptr(), libc::X_OK) == 0 {
                let idx = find_service_by_dir(services, &dir);
                if idx != usize::MAX {
                    services[idx].present = true;
                    services[idx].stopping = false;
                    parse_user_group(&mut services[idx]);
                    prepare_service_env(&mut services[idx]);
                } else {
                    add_service(services, name, &dir);
                }
            }
        }
        libc::closedir(dp);
    }
    true
}

pub fn handle_missing_services(services: &mut [Service]) {
    use crate::service::{close_service_fds, stop_transitive_deps};
    let mut i = 0;
    while i < services.len() {
        if services[i].active && !services[i].present {
            if services[i].pid > 0 && !services[i].stopping {
                stop_transitive_deps(services);
                unsafe { libc::kill(-services[i].pid, libc::SIGTERM) };
                services[i].stopping = true;
                services[i].state = STATE_STOPPING;
                supervisor_log(b"stopping removed service: ");
                supervisor_log(services[i].name_bytes());
            }
            if services[i].log_pid > 0 && !services[i].log_stopping {
                unsafe { libc::kill(services[i].log_pid, libc::SIGTERM) };
                services[i].log_stopping = true;
            }
            if services[i].pid <= 0 && services[i].log_pid <= 0 {
                close_service_fds(&mut services[i]);
                services[i].active = false;
                services[i].state = STATE_DOWN;
                write_status_file(&services[i]);
                supervisor_log(b"service removed: ");
                supervisor_log(services[i].name_bytes());
            }
        }
        i += 1;
    }
}
