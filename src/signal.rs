// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::fd::{FdGuard, Pipe};
use core::ffi::{c_int, c_void};
use core::ptr;

static mut SIG_PIPE_W: c_int = -1;

extern "C" fn signal_handler(sig: c_int) {
    unsafe {
        let fd = SIG_PIPE_W;
        if fd >= 0 {
            let b = sig as u8;
            libc::write(fd, &b as *const u8 as *const c_void, 1);
        }
    }
}

/// # Safety
/// Must be called once during init, before any signals arrive.
pub unsafe fn init_signal_pipe() -> c_int {
    let pipe = match Pipe::new() {
        Some(p) => p,
        None => return -1,
    };
    let (read, write) = pipe.split();
    SIG_PIPE_W = write.into_raw();
    read.into_raw()
}

unsafe fn set_signal_action(sig: c_int) {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = signal_handler as *const () as usize as libc::sighandler_t;
    libc::sigemptyset(&mut sa.sa_mask);
    sa.sa_flags = libc::SA_RESTART;
    libc::sigaction(sig, &sa, ptr::null_mut());
}

/// # Safety
/// Must be called after init_signal_pipe().
pub unsafe fn install_signal_handlers() {
    libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    set_signal_action(libc::SIGTERM);
    set_signal_action(libc::SIGINT);
    set_signal_action(libc::SIGCHLD);
    set_signal_action(libc::SIGHUP);
}

pub fn drain_signal_pipe(sig_fd: c_int) -> Option<c_int> {
    let mut buf = [0u8; 64];
    loop {
        let r = unsafe { libc::read(sig_fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if r <= 0 {
            break;
        }
        for &sig in &buf[..r as usize] {
            let s = sig as c_int;
            if s == libc::SIGTERM || s == libc::SIGINT || s == libc::SIGHUP {
                return Some(s);
            }
        }
    }
    None
}
