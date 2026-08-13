// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::consts::DEV_NULL;
use core::ffi::c_int;

/// RAII guard for file descriptors. Zero-cost.
pub struct FdGuard(c_int);

impl FdGuard {
    /// # Safety
    /// Caller must ensure fd is valid and not owned elsewhere.
    pub unsafe fn from_raw(fd: c_int) -> Option<Self> {
        if fd >= 0 { Some(Self(fd)) } else { None }
    }

    pub fn as_raw(&self) -> c_int {
        self.0
    }

    pub fn into_raw(self) -> c_int {
        let fd = self.0;
        core::mem::forget(self);
        fd
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { close_fd(self.0) }
    }
}

pub struct Pipe {
    pub read: FdGuard,
    pub write: FdGuard,
}

impl Pipe {
    /// # Safety
    /// Requires working libc pipe().
    pub unsafe fn new() -> Option<Self> {
        let mut fds: [c_int; 2] = [-1, -1];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return None;
        }
        let read = FdGuard::from_raw(fds[0])?;
        let write = FdGuard::from_raw(fds[1])?;
        set_nonblock(read.as_raw());
        set_nonblock(write.as_raw());
        set_cloexec(read.as_raw());
        set_cloexec(write.as_raw());
        Some(Pipe { read, write })
    }

    pub fn split(self) -> (FdGuard, FdGuard) {
        let r = unsafe { FdGuard::from_raw(self.read.as_raw()).unwrap() };
        let w = unsafe { FdGuard::from_raw(self.write.as_raw()).unwrap() };
        core::mem::forget(self);
        (r, w)
    }
}

// --- Low-level FD utilities ---

pub unsafe fn close_fd(fd: c_int) {
    if fd >= 0 {
        loop {
            if libc::close(fd) == 0 || !is_eintr() {
                break;
            }
        }
    }
}

pub unsafe fn set_nonblock(fd: c_int) -> bool {
    let flags = libc::fcntl(fd, libc::F_GETFL, 0);
    flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
}

pub unsafe fn set_cloexec(fd: c_int) -> bool {
    let flags = libc::fcntl(fd, libc::F_GETFD, 0);
    flags >= 0 && libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) >= 0
}

pub unsafe fn close_from(min: c_int) {
    let mut max = libc::sysconf(libc::_SC_OPEN_MAX);
    if max <= 0 {
        max = 1024;
    }
    if max > 65536 {
        max = 65536;
    }
    let mut fd = min;
    while fd < max as c_int {
        libc::close(fd);
        fd += 1;
    }
}

pub unsafe fn ensure_stdio() {
    for fd in 0..3 {
        if libc::fcntl(fd, libc::F_GETFL, 0) < 0 {
            let nfd = libc::open(DEV_NULL.as_ptr() as *const core::ffi::c_char, libc::O_RDWR);
            if nfd >= 0 && nfd != fd {
                libc::dup2(nfd, fd);
                libc::close(nfd);
            }
        }
    }
}

pub fn is_eintr() -> bool {
    unsafe { get_errno() == libc::EINTR }
}

pub fn is_eagain() -> bool {
    unsafe { get_errno() == libc::EAGAIN || get_errno() == libc::EWOULDBLOCK }
}

#[cfg(target_os = "linux")]
unsafe fn get_errno() -> c_int {
    *libc::__errno_location()
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
unsafe fn get_errno() -> c_int {
    *libc::__error()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
unsafe fn get_errno() -> c_int {
    0
}

pub fn write_all(fd: c_int, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let r = unsafe { libc::write(fd, data.as_ptr() as *const core::ffi::c_void, data.len()) };
        if r > 0 {
            data = &data[r as usize..];
        } else if r == 0 || !is_eintr() {
            return false;
        }
    }
    true
}

pub fn read_all_nonblock(fd: c_int, buf: &mut [u8]) -> isize {
    loop {
        let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut core::ffi::c_void, buf.len()) };
        if r >= 0 || !is_eintr() {
            return r;
        }
    }
}

pub fn read_file_to_buf(path: &crate::path::CStrBuf, buf: &mut [u8]) -> isize {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return -1;
    }
    let nr = read_all_nonblock(fd, buf);
    unsafe { close_fd(fd) };
    nr
}

pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == y)
}

pub fn wall_now() -> libc::time_t {
    unsafe { libc::time(core::ptr::null_mut()) }
}

pub fn mono_now() -> i64 {
    unsafe {
        let mut ts: libc::timespec = core::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) == 0 {
            ts.tv_sec as i64
        } else {
            libc::time(core::ptr::null_mut()) as i64
        }
    }
}

pub fn sleep_ms(ms: i64) {
    unsafe {
        let mut ts: libc::timespec = core::mem::zeroed();
        ts.tv_sec = (ms / 1000) as libc::time_t;
        ts.tv_nsec = ((ms % 1000) * 1_000_000) as core::ffi::c_long;
        loop {
            let ret = libc::nanosleep(&ts, &mut ts);
            if ret == 0 || !is_eintr() {
                break;
            }
        }
    }
}
