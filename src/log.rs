// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::consts::*;
use crate::fd::{close_fd, set_cloexec, wall_now, write_all};
use crate::path::CStrBuf;
use core::ffi::c_int;

static mut SUPERVISOR_LOG_FD: c_int = -1;
static mut SUPERVISOR_LOG_LEN: libc::off_t = 0;

/// # Safety
/// Call once at startup.
pub unsafe fn supervisor_log_init() {
    let fd = libc::open(
        SUPERVISOR_LOG_PATH.as_ptr() as *const core::ffi::c_char,
        libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
        0o644 as libc::mode_t,
    );
    if fd >= 0 {
        set_cloexec(fd);
        SUPERVISOR_LOG_LEN = libc::lseek(fd, 0, libc::SEEK_END);
        SUPERVISOR_LOG_FD = fd;
    }
}

fn supervisor_log_rotate() {
    unsafe {
        close_fd(SUPERVISOR_LOG_FD);
        SUPERVISOR_LOG_FD = -1;
        SUPERVISOR_LOG_LEN = 0;
    }
    let ts = wall_now();
    let mut old = CStrBuf::from_bytes(SUPERVISOR_LOG_PATH);
    old.push_byte(b'.');
    old.push_u64(ts as u64);
    unsafe {
        libc::rename(
            SUPERVISOR_LOG_PATH.as_ptr() as *const core::ffi::c_char,
            old.as_ptr(),
        );
        supervisor_log_init();
    }
}

pub fn supervisor_log(msg: &[u8]) {
    unsafe {
        if SUPERVISOR_LOG_FD < 0 {
            return;
        }
        let ts = wall_now();
        let mut buf = [0u8; 256];
        let mut p = CStrBuf::new();
        p.push_u64(ts as u64);
        p.push(b" [svc-rs] ");
        let prefix = p.as_bytes();
        let max_copy = core::cmp::min(buf.len(), prefix.len() + msg.len());
        buf[..prefix.len()].copy_from_slice(prefix);
        let msg_len = core::cmp::min(msg.len(), max_copy - prefix.len());
        buf[prefix.len()..prefix.len() + msg_len].copy_from_slice(&msg[..msg_len]);
        let total = prefix.len() + msg_len;
        if write_all(SUPERVISOR_LOG_FD, &buf[..total]) {
            SUPERVISOR_LOG_LEN += total as libc::off_t + 1;
            write_all(SUPERVISOR_LOG_FD, b"\n");
            if SUPERVISOR_LOG_LEN > SUPERVISOR_LOG_LIMIT {
                supervisor_log_rotate();
            }
        }
    }
}

/// Returns the current supervisor log FD for cleanup on shutdown.
pub unsafe fn supervisor_log_fd() -> c_int {
    SUPERVISOR_LOG_FD
}
