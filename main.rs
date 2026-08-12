// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

#![no_std]
#![no_main]

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::mem::{self};
use core::ptr;
use libc::{gid_t, mode_t, nfds_t, off_t, pid_t, sockaddr, sockaddr_un, socklen_t, time_t, uid_t};

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { libc::_exit(101) }
}

// ============================================================================
// Constants
// ============================================================================

const MAX_SERVICES: usize = 256;
const PATH_BUF: usize = 1024;
const NAME_BUF: usize = 64;
const IO_BUF: usize = 4096;
const CMD_BUF: usize = 512;
const RESP_BUF: usize = 8192;
const PASSWD_BUF: usize = 4096;
const GROUP_BUF: usize = 4096;
const ENV_BUF: usize = 4096;
const MAX_ENV_VARS: usize = 64;

const MAX_DEPENDENCIES: usize = 16;
const DEP_FILE_BUF: usize = 512;

const LOG_LIMIT: off_t = 1_048_576;
const SUPERVISOR_LOG_LIMIT: off_t = 1_048_576;
const POLL_TIMEOUT_MS: c_int = 500;
const SHUTDOWN_TIMEOUT_S: i64 = 5;
const MAX_POLL_FDS: usize = MAX_SERVICES * 2 + 2;

const RESTART_WINDOW_S: i64 = 60;
const MAX_RESTARTS_IN_WINDOW: u32 = 5;
const BACKOFF_SHORT: i64 = 2;
const BACKOFF_MED: i64 = 10;
const BACKOFF_LONG: i64 = 60;

const DEV_NULL: &[u8] = b"/dev/null\0";
const SOCK_SUFFIX: &[u8] = b"/.control.sock";
const SUPERVISOR_LOG_PATH: &[u8] = b"/var/log/svc-rs.log\0";

const STATE_DOWN: u8 = 0;
const STATE_RUNNING: u8 = 1;
const STATE_EXITED: u8 = 2;
const STATE_SIGNALED: u8 = 3;
const STATE_FAILED: u8 = 4;
const STATE_STOPPING: u8 = 5;

// ============================================================================
// Zero-Cost Abstractions & Safety Helpers
// ============================================================================

/// Safe, stack-allocated C-string builder. Prevents interior nulls and guarantees termination.
struct CStrBuf {
    buf: [u8; PATH_BUF],
    len: usize,
}

impl CStrBuf {
    fn new() -> Self {
        let mut s = Self {
            buf: [0; PATH_BUF],
            len: 0,
        };
        s.buf[0] = 0;
        s
    }

    fn from_bytes(b: &[u8]) -> Self {
        let mut s = Self::new();
        s.push(b);
        s
    }

    fn push(&mut self, b: &[u8]) {
        for &c in b {
            self.push_byte(c);
        }
    }

    fn push_byte(&mut self, c: u8) {
        // Prevent interior nulls and ensure space for terminator
        if c == 0 {
            return;
        }
        if self.len + 1 < PATH_BUF {
            self.buf[self.len] = c;
            self.len += 1;
            self.buf[self.len] = 0;
        }
    }

    fn push_u64(&mut self, mut v: u64) {
        if v == 0 {
            self.push_byte(b'0');
            return;
        }
        let mut tmp = [0u8; 20];
        let mut n = 0;
        while v > 0 {
            tmp[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        while n > 0 {
            n -= 1;
            self.push_byte(tmp[n]);
        }
    }

    fn push_i64(&mut self, v: i64) {
        if v < 0 {
            self.push_byte(b'-');
            if v == i64::MIN {
                self.push_u64(9223372036854775808u64);
            } else {
                self.push_u64((-v) as u64);
            }
        } else {
            self.push_u64(v as u64);
        }
    }

    fn as_ptr(&self) -> *const c_char {
        self.buf.as_ptr() as *const c_char
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Returns a safe CStr reference. Guaranteed valid due to push_byte invariants.
    fn as_cstr(&self) -> &CStr {
        // SAFETY: We guarantee no interior nulls and proper termination in push_byte
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.buf[..=self.len]) }
    }
}

/// RAII guard for file descriptors. Zero-cost abstraction over raw c_int.
struct FdGuard(c_int);

impl FdGuard {
    unsafe fn from_raw(fd: c_int) -> Option<Self> {
        if fd >= 0 { Some(Self(fd)) } else { None }
    }

    fn as_raw(&self) -> c_int {
        self.0
    }

    fn into_raw(self) -> c_int {
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

struct Pipe {
    read: FdGuard,
    write: FdGuard,
}

impl Pipe {
    unsafe fn new() -> Option<Self> {
        unsafe {
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
    }

    fn split(self) -> (FdGuard, FdGuard) {
        let r = unsafe { FdGuard::from_raw(self.read.as_raw()).unwrap() };
        let w = unsafe { FdGuard::from_raw(self.write.as_raw()).unwrap() };
        core::mem::forget(self);
        (r, w)
    }
}

// ============================================================================
// Portable errno & Utilities
// ============================================================================

#[cfg(target_os = "linux")]
unsafe fn get_errno() -> c_int {
    unsafe { *libc::__errno_location() }
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

fn is_eintr() -> bool {
    unsafe { get_errno() == libc::EINTR }
}

fn is_eagain() -> bool {
    unsafe { get_errno() == libc::EAGAIN || get_errno() == libc::EWOULDBLOCK }
}

fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == y)
}

fn wall_now() -> time_t {
    unsafe { libc::time(ptr::null_mut()) }
}

fn mono_now() -> i64 {
    unsafe {
        let mut ts: libc::timespec = mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) == 0 {
            ts.tv_sec as i64
        } else {
            libc::time(ptr::null_mut()) as i64
        }
    }
}

fn sleep_ms(ms: i64) {
    unsafe {
        let mut ts: libc::timespec = mem::zeroed();
        ts.tv_sec = (ms / 1000) as time_t;
        ts.tv_nsec = ((ms % 1000) * 1_000_000) as c_long;
        loop {
            let ret = libc::nanosleep(&ts, &mut ts);
            if ret == 0 || !is_eintr() {
                break;
            }
        }
    }
}

unsafe fn close_fd(fd: c_int) {
    unsafe {
        if fd >= 0 {
            loop {
                if libc::close(fd) == 0 || !is_eintr() {
                    break;
                }
            }
        }
    }
}

unsafe fn set_nonblock(fd: c_int) -> bool {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
    }
}

unsafe fn set_cloexec(fd: c_int) -> bool {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD, 0);
        flags >= 0 && libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) >= 0
    }
}

unsafe fn close_from(min: c_int) {
    unsafe {
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
}

unsafe fn ensure_stdio() {
    unsafe {
        for fd in 0..3 {
            if libc::fcntl(fd, libc::F_GETFL, 0) < 0 {
                let nfd = libc::open(DEV_NULL.as_ptr() as *const c_char, libc::O_RDWR);
                if nfd >= 0 && nfd != fd {
                    libc::dup2(nfd, fd);
                    libc::close(nfd);
                }
            }
        }
    }
}

fn write_all(fd: c_int, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let r = unsafe { libc::write(fd, data.as_ptr() as *const c_void, data.len()) };
        if r > 0 {
            data = &data[r as usize..];
        } else if r == 0 || !is_eintr() {
            return false;
        }
    }
    true
}

fn read_all_nonblock(fd: c_int, buf: &mut [u8]) -> isize {
    loop {
        let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if r >= 0 || !is_eintr() {
            return r;
        }
    }
}

fn read_file_to_buf(path: &CStrBuf, buf: &mut [u8]) -> isize {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return -1;
    }
    let nr = read_all_nonblock(fd, buf);
    unsafe { close_fd(fd) };
    nr
}

// ============================================================================
// Signal Self-Pipe
// ============================================================================

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

unsafe fn init_signal_pipe() -> c_int {
    unsafe {
        let pipe = match Pipe::new() {
            Some(p) => p,
            None => return -1,
        };
        let (read, write) = pipe.split();
        SIG_PIPE_W = write.into_raw();
        read.into_raw()
    }
}

unsafe fn set_signal_action(sig: c_int) {
    unsafe {
        let mut sa: libc::sigaction = mem::zeroed();
        sa.sa_sigaction = signal_handler as *const () as usize as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(sig, &sa, ptr::null_mut());
    }
}

unsafe fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        set_signal_action(libc::SIGTERM);
        set_signal_action(libc::SIGINT);
        set_signal_action(libc::SIGCHLD);
        set_signal_action(libc::SIGHUP);
    }
}

fn drain_signal_pipe(sig_fd: c_int) -> Option<c_int> {
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

// ============================================================================
// Supervisor Log
// ============================================================================

static mut SUPERVISOR_LOG_FD: c_int = -1;
static mut SUPERVISOR_LOG_LEN: off_t = 0;

unsafe fn supervisor_log_init() {
    unsafe {
        let fd = libc::open(
            SUPERVISOR_LOG_PATH.as_ptr() as *const c_char,
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o644 as mode_t,
        );
        if fd >= 0 {
            set_cloexec(fd);
            SUPERVISOR_LOG_LEN = libc::lseek(fd, 0, libc::SEEK_END);
            SUPERVISOR_LOG_FD = fd;
        }
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
        libc::rename(SUPERVISOR_LOG_PATH.as_ptr() as *const c_char, old.as_ptr());
        supervisor_log_init();
    }
}

fn supervisor_log(msg: &[u8]) {
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
            SUPERVISOR_LOG_LEN += total as off_t + 1;
            write_all(SUPERVISOR_LOG_FD, b"\n");
            if SUPERVISOR_LOG_LEN > SUPERVISOR_LOG_LIMIT {
                supervisor_log_rotate();
            }
        }
    }
}

// ============================================================================
// User/Group Resolution (Safe CStr handling)
// ============================================================================

fn resolve_uid(name: &[u8]) -> Option<uid_t> {
    // Trim whitespace and nulls safely
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

    // Check for interior nulls to prevent UB
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

fn parse_user_group(s: &mut Service) {
    s.uid = 0;
    s.gid = 0;
    s.has_uid = false;

    let dir = CStrBuf::from_bytes(s.dir_bytes());

    // Parse user
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

    // Parse group
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

// ============================================================================
// Environment & Chroot Helpers
// ============================================================================

fn read_env(s: &mut Service) {
    let mut env_path = CStrBuf::from_bytes(s.dir_bytes());
    env_path.push(b"/env");
    let fd = unsafe { libc::open(env_path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        s.env_count = 0;
        s.env_ptrs[0] = ptr::null();
        return;
    }
    let mut buf = [0u8; ENV_BUF];
    let nr = read_all_nonblock(fd, &mut buf);
    unsafe { close_fd(fd) };
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

fn check_chroot(s: &Service) -> bool {
    let mut root_path = CStrBuf::from_bytes(s.dir_bytes());
    root_path.push(b"/root");
    unsafe { libc::access(root_path.as_ptr(), libc::F_OK) == 0 }
}

fn prepare_service_env(s: &mut Service) {
    read_env(s);
    s.chroot_enabled = check_chroot(s);
}

// ============================================================================
// Security Restrictions (Fixed: Must be called BEFORE chroot)
// ============================================================================

fn read_rlimit_value(s: &Service, filename: &[u8]) -> Option<libc::rlim_t> {
    let mut path = CStrBuf::from_bytes(s.dir_bytes());
    path.push(filename);
    let mut buf = [0u8; 32];
    let nr = read_file_to_buf(&path, &mut buf);
    if nr <= 0 {
        return None;
    }

    let mut val: u64 = 0;
    for &c in &buf[..nr as usize] {
        if c >= b'0' && c <= b'9' {
            val = val.saturating_mul(10).saturating_add((c - b'0') as u64);
        } else {
            break;
        }
    }
    if nr > 0 && buf[0] >= b'0' && buf[0] <= b'9' {
        Some(val as libc::rlim_t)
    } else {
        None
    }
}

fn read_nice_value(s: &Service) -> Option<c_int> {
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
    if buf[i] == b'-' {
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

/// SECURITY FIX: This MUST be called before chroot() because it reads files
/// using absolute host paths from s.dir_bytes().
unsafe fn apply_security_restrictions(s: &Service) {
    unsafe {
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
}

// ============================================================================
// Dependency & Service Structures
// ============================================================================

#[derive(Clone, Copy)]
struct Dependency {
    name: [u8; NAME_BUF],
    name_len: usize,
    soft: bool,
}

const DEP_EMPTY: Dependency = Dependency {
    name: [0; NAME_BUF],
    name_len: 0,
    soft: false,
};

#[derive(Clone, Copy)]
struct Stream {
    read_fd: c_int,
    log_fd: c_int,
    log_len: off_t,
    rotations: u32,
}

const STREAM_EMPTY: Stream = Stream {
    read_fd: -1,
    log_fd: -1,
    log_len: 0,
    rotations: 0,
};

#[derive(Clone, Copy)]
struct Service {
    active: bool,
    present: bool,
    stopping: bool,
    manual_start: bool,

    name: [u8; NAME_BUF],
    name_len: usize,

    dir: [u8; PATH_BUF],
    dir_len: usize,

    pid: pid_t,
    streams: [Stream; 2],

    restart_at: i64,
    started_at: i64,
    restarts: u32,

    last_status: c_int,
    state: u8,
    exit_code: c_int,
    term_signal: c_int,

    auto_start: bool,
    once: bool,

    deps: [Dependency; MAX_DEPENDENCIES],
    deps_count: usize,

    has_log: bool,
    log_pid: pid_t,
    log_state: u8,
    log_started_at: i64,
    log_stopping: bool,

    uid: uid_t,
    gid: gid_t,
    has_uid: bool,

    env_buf: [u8; ENV_BUF],
    env_ptrs: [*const c_char; MAX_ENV_VARS + 1],
    env_count: usize,
    chroot_enabled: bool,
}

const SERVICE_EMPTY: Service = Service {
    active: false,
    present: false,
    stopping: false,
    manual_start: false,
    name: [0; NAME_BUF],
    name_len: 0,
    dir: [0; PATH_BUF],
    dir_len: 0,
    pid: -1,
    streams: [STREAM_EMPTY; 2],
    restart_at: 0,
    started_at: 0,
    restarts: 0,
    last_status: 0,
    state: STATE_DOWN,
    exit_code: 0,
    term_signal: 0,
    auto_start: true,
    once: false,
    deps: [DEP_EMPTY; MAX_DEPENDENCIES],
    deps_count: 0,
    has_log: false,
    log_pid: -1,
    log_state: STATE_DOWN,
    log_started_at: 0,
    log_stopping: false,
    uid: 0,
    gid: 0,
    has_uid: false,
    env_buf: [0; ENV_BUF],
    env_ptrs: [ptr::null(); MAX_ENV_VARS + 1],
    env_count: 0,
    chroot_enabled: false,
};

impl Service {
    fn dir_bytes(&self) -> &[u8] {
        &self.dir[..self.dir_len]
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    fn set_dir(&mut self, p: &CStrBuf) {
        self.dir_len = p.len;
        self.dir[..p.len].copy_from_slice(p.as_bytes());
        self.dir[p.len] = 0;
    }

    fn set_name(&mut self, b: &[u8]) {
        let n = core::cmp::min(b.len(), NAME_BUF - 1);
        self.name_len = n;
        self.name[..n].copy_from_slice(&b[..n]);
        self.name[n] = 0;
    }

    fn uptime_seconds(&self, now: i64) -> i64 {
        if self.state == STATE_RUNNING && self.started_at > 0 {
            now - self.started_at
        } else {
            0
        }
    }

    fn log_uptime_seconds(&self, now: i64) -> i64 {
        if self.log_state == STATE_RUNNING && self.log_started_at > 0 {
            now - self.log_started_at
        } else {
            0
        }
    }
}

// ============================================================================
// Control Socket (Fixed TOCTOU)
// ============================================================================

unsafe fn create_control_socket(root: &CStrBuf) -> c_int {
    unsafe {
        let mut sock_path = CStrBuf::from_bytes(root.as_bytes());
        sock_path.push(SOCK_SUFFIX);

        libc::unlink(sock_path.as_ptr());

        // SECURITY FIX: Set restrictive umask before bind to prevent race window
        let old_umask = libc::umask(0o077);

        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            libc::umask(old_umask);
            return -1;
        }

        let mut addr: sockaddr_un = mem::zeroed();
        addr.sun_family = libc::AF_UNIX as u16;

        let path_bytes = sock_path.as_bytes();
        let max_len = core::mem::size_of_val(&addr.sun_path) - 1;
        let copy_len = core::cmp::min(path_bytes.len(), max_len);

        for i in 0..copy_len {
            addr.sun_path[i] = path_bytes[i] as c_char;
        }
        addr.sun_path[copy_len] = 0;

        let addr_len = (core::mem::size_of::<sockaddr_un>() - max_len + copy_len + 1) as socklen_t;

        if libc::bind(fd, &addr as *const sockaddr_un as *const sockaddr, addr_len) < 0 {
            close_fd(fd);
            libc::umask(old_umask);
            return -1;
        }

        // Restore umask after successful bind
        libc::umask(old_umask);

        // Explicit chmod as defense-in-depth (umask already set 0600)
        libc::chmod(sock_path.as_ptr(), 0o660);

        if libc::listen(fd, 5) < 0 {
            close_fd(fd);
            return -1;
        }

        set_nonblock(fd);
        fd
    }
}

// ============================================================================
// Service Lifecycle (Fixed dangling pointer & chroot bypass)
// ============================================================================

fn deps_satisfied(s: &Service, services: &[Service]) -> bool {
    for i in 0..s.deps_count {
        let dep = &s.deps[i];
        if dep.soft {
            continue;
        }
        let dep_name = &dep.name[..dep.name_len];
        let idx = find_service_by_name(services, dep_name);
        if idx == usize::MAX || services[idx].state != STATE_RUNNING {
            return false;
        }
    }
    true
}

fn find_service_by_name(services: &[Service], name: &[u8]) -> usize {
    for (i, s) in services.iter().enumerate() {
        if s.active && bytes_eq(s.name_bytes(), name) {
            return i;
        }
    }
    usize::MAX
}

fn start_service(s: &mut Service) {
    if !s.active || !s.present || s.stopping || s.pid > 0 {
        return;
    }

    prepare_service_env(s);

    unsafe {
        close_fd(s.streams[0].read_fd);
        close_fd(s.streams[1].read_fd);
    }
    s.streams[0].read_fd = -1;
    s.streams[1].read_fd = -1;

    let mut out_fds: [c_int; 2] = [-1, -1];
    let mut err_fds: [c_int; 2] = [-1, -1];

    if s.has_log {
        let mut log_run = CStrBuf::from_bytes(s.dir_bytes());
        log_run.push(b"/log/run");
        if unsafe { libc::access(log_run.as_ptr(), libc::X_OK) } == 0 {
            if let Some(pipe) = unsafe { Pipe::new() } {
                let (pipe_read, pipe_write) = pipe.split();
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    unsafe {
                        libc::setsid();
                        libc::dup2(pipe_read.as_raw(), 0);
                        drop(pipe_read);
                        drop(pipe_write);
                        close_from(3);

                        // SECURITY FIX: Apply restrictions BEFORE chroot
                        apply_security_restrictions(s);

                        if s.chroot_enabled {
                            if libc::chroot(s.dir.as_ptr() as *const c_char) != 0 {
                                libc::_exit(126);
                            }
                            libc::chdir(b"/\0".as_ptr() as *const c_char);
                            // Inside chroot, use relative path
                            let run_path = b"/log/run\0".as_ptr() as *const c_char;
                            let argv: [*const c_char; 2] = [run_path, ptr::null()];
                            let envp = s.env_ptrs.as_ptr();
                            libc::execve(run_path, argv.as_ptr(), envp);
                        } else {
                            libc::chdir(s.dir.as_ptr() as *const c_char);
                            let argv: [*const c_char; 2] = [log_run.as_ptr(), ptr::null()];
                            let envp = s.env_ptrs.as_ptr();
                            libc::execve(log_run.as_ptr(), argv.as_ptr(), envp);
                        }
                        libc::_exit(126);
                    }
                } else if pid > 0 {
                    s.log_pid = pid;
                    s.log_state = STATE_RUNNING;
                    s.log_started_at = mono_now();
                    s.log_stopping = false;
                    out_fds[0] = pipe_write.into_raw();
                    out_fds[1] = -1;
                } else {
                    s.has_log = false;
                }
            } else {
                s.has_log = false;
            }
        } else {
            s.has_log = false;
        }
    }

    if !s.has_log {
        let pipe_out = match unsafe { Pipe::new() } {
            Some(p) => p,
            None => {
                s.state = STATE_FAILED;
                s.restart_at = mono_now() + BACKOFF_SHORT;
                write_status_file(s);
                return;
            }
        };
        let (out_read, out_write) = pipe_out.split();
        out_fds[0] = out_read.into_raw();
        out_fds[1] = out_write.into_raw();

        let pipe_err = match unsafe { Pipe::new() } {
            Some(p) => p,
            None => {
                unsafe {
                    close_fd(out_fds[0]);
                    close_fd(out_fds[1]);
                }
                s.state = STATE_FAILED;
                s.restart_at = mono_now() + BACKOFF_SHORT;
                write_status_file(s);
                return;
            }
        };
        let (err_read, err_write) = pipe_err.split();
        err_fds[0] = err_read.into_raw();
        err_fds[1] = err_write.into_raw();
    }

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::setsid();

            // SECURITY FIX: Apply restrictions BEFORE chroot
            apply_security_restrictions(s);

            if s.chroot_enabled {
                if libc::chroot(s.dir.as_ptr() as *const c_char) != 0 {
                    libc::_exit(126);
                }
                libc::chdir(b"/\0".as_ptr() as *const c_char);
            } else {
                libc::chdir(s.dir.as_ptr() as *const c_char);
            }

            if s.has_uid {
                if s.gid != 0 {
                    libc::setgid(s.gid as gid_t);
                    libc::setgroups(1, &(s.gid as gid_t) as *const gid_t);
                }
                libc::setuid(s.uid as uid_t);
                if libc::getuid() != s.uid as uid_t {
                    libc::_exit(125);
                }
            }

            let null = libc::open(DEV_NULL.as_ptr() as *const c_char, libc::O_RDONLY);
            if null >= 0 {
                libc::dup2(null, 0);
                if null != 0 {
                    libc::close(null);
                }
            }

            if s.has_log {
                libc::dup2(out_fds[0], 1);
                libc::dup2(out_fds[0], 2);
                libc::close(out_fds[0]);
            } else {
                libc::dup2(out_fds[1], 1);
                libc::dup2(err_fds[1], 2);
                libc::close(out_fds[0]);
                libc::close(err_fds[0]);
                libc::close(out_fds[1]);
                libc::close(err_fds[1]);
            }
            close_from(3);

            // FIX: Dangling pointer resolved. Buffer lives in correct scope.
            // For chroot, we use static relative path. For non-chroot, we build
            // the path in a local variable that lives until execve.
            let run_path_ptr: *const c_char;
            let mut run_buf = CStrBuf::new(); // Lives until end of this block

            if s.chroot_enabled {
                run_path_ptr = b"/run\0".as_ptr() as *const c_char;
            } else {
                run_buf = CStrBuf::from_bytes(s.dir_bytes());
                run_buf.push(b"/run");
                run_path_ptr = run_buf.as_ptr();
            }

            let argv: [*const c_char; 2] = [run_path_ptr, ptr::null()];
            let envp = s.env_ptrs.as_ptr();
            libc::execve(run_path_ptr, argv.as_ptr(), envp);
            libc::_exit(127);
        }
    }

    // Parent: close write ends
    if s.has_log {
        unsafe { close_fd(out_fds[0]) };
    } else {
        unsafe {
            close_fd(out_fds[1]);
            close_fd(err_fds[1]);
        }
    }

    if pid > 0 {
        s.pid = pid;
        s.state = STATE_RUNNING;
        s.exit_code = 0;
        s.term_signal = 0;
        s.started_at = mono_now();
        s.manual_start = false;
        if s.has_log {
            s.streams[0].read_fd = -1;
            s.streams[1].read_fd = -1;
        } else {
            s.streams[0].read_fd = out_fds[0];
            s.streams[1].read_fd = err_fds[0];
            open_log(s, 0);
            open_log(s, 1);
        }
        write_status_file(s);
        supervisor_log(b"service started: ");
        supervisor_log(s.name_bytes());
    } else {
        if !s.has_log {
            unsafe {
                close_fd(out_fds[0]);
                close_fd(err_fds[0]);
            }
        }
        s.pid = -1;
        s.state = STATE_FAILED;
        s.restart_at = mono_now() + BACKOFF_SHORT;
        write_status_file(s);
        supervisor_log(b"fork failed for service: ");
        supervisor_log(s.name_bytes());
    }
}

fn run_finish(s: &Service) {
    let mut finish_path = CStrBuf::from_bytes(s.dir_bytes());
    finish_path.push(b"/finish");
    if unsafe { libc::access(finish_path.as_ptr(), libc::X_OK) } == 0 {
        let mut s_clone = *s;
        prepare_service_env(&mut s_clone);

        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                // SECURITY FIX: Apply restrictions BEFORE chroot
                apply_security_restrictions(&s_clone);

                if s_clone.chroot_enabled {
                    if libc::chroot(s_clone.dir.as_ptr() as *const c_char) != 0 {
                        libc::_exit(126);
                    }
                    libc::chdir(b"/\0".as_ptr() as *const c_char);
                } else {
                    libc::chdir(s_clone.dir.as_ptr() as *const c_char);
                }

                if s_clone.has_uid {
                    if s_clone.gid != 0 {
                        libc::setgid(s_clone.gid as gid_t);
                        libc::setgroups(1, &(s_clone.gid as gid_t) as *const gid_t);
                    }
                    libc::setuid(s_clone.uid as uid_t);
                    if libc::getuid() != s_clone.uid as uid_t {
                        libc::_exit(125);
                    }
                }

                let exit_str = format_i64_buf(s_clone.exit_code as i64);
                let sig_str = format_i64_buf(s_clone.term_signal as i64);

                // FIX: Use relative path inside chroot
                let finish_ptr: *const c_char;
                let mut finish_buf = CStrBuf::new();

                if s_clone.chroot_enabled {
                    finish_ptr = b"/finish\0".as_ptr() as *const c_char;
                } else {
                    finish_buf = CStrBuf::from_bytes(s_clone.dir_bytes());
                    finish_buf.push(b"/finish");
                    finish_ptr = finish_buf.as_ptr();
                }

                let argv: [*const c_char; 4] = [
                    finish_ptr,
                    exit_str.as_ptr() as *const c_char,
                    sig_str.as_ptr() as *const c_char,
                    ptr::null(),
                ];
                let envp = s_clone.env_ptrs.as_ptr();
                libc::execve(finish_ptr, argv.as_ptr(), envp);
                libc::_exit(127);
            }
        }
    }
}

fn format_i64_buf(v: i64) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let mut p = CStrBuf::new();
    p.push_i64(v);
    let b = p.as_bytes();
    let n = core::cmp::min(b.len(), 19);
    buf[..n].copy_from_slice(&b[..n]);
    buf[n] = 0;
    buf
}

// ============================================================================
// Remaining Service Management Functions
// ============================================================================

fn find_service_by_dir(services: &[Service], dir: &CStrBuf) -> usize {
    for (i, s) in services.iter().enumerate() {
        if s.active && s.dir_bytes() == dir.as_bytes() {
            return i;
        }
    }
    usize::MAX
}

fn add_service(services: &mut [Service], name: &[u8], dir: &CStrBuf) {
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

fn scan_services(root: &CStrBuf, services: &mut [Service]) -> bool {
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

fn handle_missing_services(services: &mut [Service]) {
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

fn kill_main_on_log_death(services: &mut [Service]) {
    for s in services.iter_mut() {
        if s.active
            && s.has_log
            && s.log_pid <= 0
            && s.pid > 0
            && !s.stopping
            && s.state == STATE_RUNNING
        {
            supervisor_log(b"log process died, stopping main service: ");
            supervisor_log(s.name_bytes());
            unsafe { libc::kill(-s.pid, libc::SIGTERM) };
            s.stopping = true;
            s.state = STATE_STOPPING;
            write_status_file(s);
        }
    }
}

fn reap_children(services: &mut [Service]) {
    let mut need_stop_deps = false;

    loop {
        let mut status: c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status as *mut c_int, libc::WNOHANG) };
        if pid <= 0 {
            break;
        }

        let t = mono_now();
        let mut handled = false;

        for s in services.iter_mut() {
            if s.active && s.log_pid == pid {
                s.log_pid = -1;
                s.log_state = STATE_DOWN;
                s.log_stopping = false;
                supervisor_log(b"log process exited for service: ");
                supervisor_log(s.name_bytes());
                handled = true;
                break;
            }
        }
        if handled {
            continue;
        }

        for s in services.iter_mut() {
            if s.active && s.pid == pid {
                s.pid = -1;
                s.last_status = status;
                let (state, exit_code, term_signal) = decode_wait_status(status);
                s.state = state;
                s.exit_code = exit_code;
                s.term_signal = term_signal;

                run_finish(s);
                supervisor_log(b"service exited: ");
                supervisor_log(s.name_bytes());
                {
                    let mut msg = CStrBuf::new();
                    msg.push(b" exit=");
                    msg.push_i64(exit_code as i64);
                    msg.push(b" sig=");
                    msg.push_i64(term_signal as i64);
                    supervisor_log(msg.as_bytes());
                }

                if !s.stopping && state != STATE_RUNNING {
                    need_stop_deps = true;
                }

                if s.log_pid > 0 && (s.stopping || state == STATE_FAILED || state == STATE_DOWN) {
                    unsafe { libc::kill(s.log_pid, libc::SIGTERM) };
                    s.log_stopping = true;
                }

                if s.stopping || s.once {
                    s.restart_at = i64::MAX;
                    if s.once {
                        s.once = false;
                    }
                } else {
                    if t - s.started_at > RESTART_WINDOW_S {
                        s.restarts = 0;
                    } else {
                        s.restarts += 1;
                    }

                    if s.restarts > MAX_RESTARTS_IN_WINDOW {
                        s.state = STATE_FAILED;
                        s.restart_at = i64::MAX;
                        supervisor_log(b"service failed (too many restarts): ");
                        supervisor_log(s.name_bytes());
                    } else {
                        let delay: i64 = if s.restarts < 5 {
                            BACKOFF_SHORT
                        } else if s.restarts < 20 {
                            BACKOFF_MED
                        } else {
                            BACKOFF_LONG
                        };
                        s.restart_at = t + delay;
                    }
                }

                write_status_file(s);
                break;
            }
        }
    }

    if need_stop_deps {
        stop_transitive_deps(services);
    }

    kill_main_on_log_death(services);
}

fn decode_wait_status(status: c_int) -> (u8, c_int, c_int) {
    if (status & 0x7f) == 0 {
        (STATE_EXITED, (status >> 8) & 0xff, 0)
    } else if (status & 0x7f) == 0x7f {
        (STATE_DOWN, 0, 0)
    } else {
        (STATE_SIGNALED, 0, status & 0x7f)
    }
}

fn any_open_services(services: &[Service]) -> bool {
    services.iter().any(|s| {
        s.active
            && (s.pid > 0
                || s.streams[0].read_fd >= 0
                || s.streams[1].read_fd >= 0
                || s.log_pid > 0)
    })
}

fn shutdown_services(services: &mut [Service]) {
    supervisor_log(b"shutting down services");
    let mut buf = [0u8; IO_BUF];

    stop_all_in_order(services);

    let deadline = mono_now() + SHUTDOWN_TIMEOUT_S;
    loop {
        reap_children(services);
        drain_all_once(services, &mut buf);
        if !any_open_services(services) || mono_now() >= deadline {
            break;
        }
        sleep_ms(100);
    }

    for s in services.iter_mut() {
        if s.active && s.pid > 0 {
            unsafe { libc::kill(-s.pid, libc::SIGKILL) };
        }
        if s.active && s.log_pid > 0 {
            unsafe { libc::kill(s.log_pid, libc::SIGKILL) };
        }
    }

    let deadline2 = mono_now() + 2;
    loop {
        reap_children(services);
        drain_all_once(services, &mut buf);
        if !any_open_services(services) || mono_now() >= deadline2 {
            break;
        }
        sleep_ms(50);
    }

    for s in services.iter_mut() {
        if s.active {
            close_service_fds(s);
            s.pid = -1;
            s.log_pid = -1;
            s.state = STATE_DOWN;
            s.log_state = STATE_DOWN;
            write_status_file(s);
        }
    }
    supervisor_log(b"shutdown complete");
}

fn stop_transitive_deps(services: &mut [Service]) {
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..services.len() {
            let s = &services[i];
            if !s.active || s.stopping || s.pid <= 0 || s.state != STATE_RUNNING {
                continue;
            }
            let mut depends = false;
            for d in 0..s.deps_count {
                if s.deps[d].soft {
                    continue;
                }
                let dep_name = &s.deps[d].name[..s.deps[d].name_len];
                let dep_idx = find_service_by_name(services, dep_name);
                if dep_idx == usize::MAX || services[dep_idx].state != STATE_RUNNING {
                    depends = true;
                    break;
                }
            }
            if depends {
                services[i].stopping = true;
                services[i].state = STATE_STOPPING;
                unsafe { libc::kill(-services[i].pid, libc::SIGTERM) };
                write_status_file(&services[i]);
                changed = true;
            }
        }
    }
}

fn stop_all_in_order(services: &mut [Service]) {
    let mut order = [0usize; MAX_SERVICES];
    let mut remaining = [false; MAX_SERVICES];
    let mut count = 0;

    for (i, s) in services.iter().enumerate() {
        if s.active && (s.state == STATE_RUNNING || s.state == STATE_STOPPING) {
            remaining[i] = true;
            count += 1;
        }
    }

    let mut pos = 0;
    while pos < count {
        let mut found = false;
        for i in 0..services.len() {
            if !remaining[i] {
                continue;
            }
            let mut ready = true;
            for d in 0..services[i].deps_count {
                if services[i].deps[d].soft {
                    continue;
                }
                let dep_name = &services[i].deps[d].name[..services[i].deps[d].name_len];
                let dep_idx = find_service_by_name(services, dep_name);
                if dep_idx != usize::MAX && remaining[dep_idx] {
                    ready = false;
                    break;
                }
            }
            if ready {
                order[pos] = i;
                remaining[i] = false;
                pos += 1;
                found = true;
            }
        }
        if !found {
            break;
        }
    }
    for idx in order.iter().take(pos) {
        let s = &mut services[*idx];
        if s.active && s.pid > 0 {
            unsafe { libc::kill(-s.pid, libc::SIGTERM) };
            s.stopping = true;
            s.state = STATE_STOPPING;
            write_status_file(s);
        }
        if s.log_pid > 0 && !s.log_stopping {
            unsafe { libc::kill(s.log_pid, libc::SIGTERM) };
            s.log_stopping = true;
        }
    }
    for i in 0..services.len() {
        if remaining[i] && services[i].active && services[i].pid > 0 {
            unsafe { libc::kill(-services[i].pid, libc::SIGTERM) };
            services[i].stopping = true;
            services[i].state = STATE_STOPPING;
        }
        if remaining[i]
            && services[i].active
            && services[i].log_pid > 0
            && !services[i].log_stopping
        {
            unsafe { libc::kill(services[i].log_pid, libc::SIGTERM) };
            services[i].log_stopping = true;
        }
    }
}

// ============================================================================
// Logging & Stream Draining
// ============================================================================

fn open_log(s: &mut Service, stream: usize) {
    let dir_path = CStrBuf::from_bytes(s.dir_bytes());
    let st = &mut s.streams[stream];
    unsafe { close_fd(st.log_fd) };
    st.log_fd = -1;

    let mut logdir = CStrBuf::from_bytes(dir_path.as_bytes());
    logdir.push(b"/log");
    unsafe { libc::mkdir(logdir.as_ptr(), 0o755 as mode_t) };

    let mut path = CStrBuf::from_bytes(logdir.as_bytes());
    if stream == 0 {
        path.push(b"/current.out");
    } else {
        path.push(b"/current.err");
    }

    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o644 as mode_t,
        )
    };

    st.log_fd = fd;
    st.log_len = if fd >= 0 {
        unsafe { libc::lseek(fd, 0, libc::SEEK_END) }
    } else {
        0
    };
}

fn rotate_log(s: &mut Service, stream: usize) {
    let dir_path = CStrBuf::from_bytes(s.dir_bytes());
    let st = &mut s.streams[stream];
    unsafe { close_fd(st.log_fd) };
    st.log_fd = -1;
    st.rotations += 1;

    let ts = wall_now();
    let rotations = st.rotations;
    let suffix: &[u8] = if stream == 0 {
        b"/current.out"
    } else {
        b"/current.err"
    };

    let mut src = CStrBuf::from_bytes(dir_path.as_bytes());
    src.push(suffix);

    let mut arch = CStrBuf::from_bytes(dir_path.as_bytes());
    arch.push(suffix);
    arch.push_byte(b'.');
    arch.push_u64(ts as u64);
    arch.push_byte(b'.');
    arch.push_u64(rotations as u64);

    unsafe { libc::rename(src.as_ptr(), arch.as_ptr()) };

    open_log(s, stream);
}

fn write_log(s: &mut Service, stream: usize, data: &[u8]) {
    if s.streams[stream].log_fd < 0 {
        open_log(s, stream);
    }
    if s.streams[stream].log_fd < 0 {
        return;
    }

    let current_len = s.streams[stream].log_len;
    let add_len = data.len() as off_t;

    if current_len + add_len > LOG_LIMIT {
        rotate_log(s, stream);
        if s.streams[stream].log_fd < 0 {
            return;
        }
    }

    let fd = s.streams[stream].log_fd;
    if write_all(fd, data) {
        s.streams[stream].log_len += add_len;
    } else {
        unsafe { close_fd(fd) };
        s.streams[stream].log_fd = -1;
    }
}

fn drain_stream(s: &mut Service, stream: usize, buf: &mut [u8; IO_BUF]) {
    loop {
        let fd = s.streams[stream].read_fd;
        if fd < 0 {
            return;
        }

        let r = read_all_nonblock(fd, buf);

        if r > 0 {
            let n = r as usize;
            if !s.has_log {
                write_log(s, stream, &buf[..n]);
            }
            if n < buf.len() {
                return;
            }
        } else if r == 0 {
            unsafe { close_fd(fd) };
            s.streams[stream].read_fd = -1;
            return;
        } else if is_eagain() {
            return;
        } else {
            unsafe { close_fd(fd) };
            s.streams[stream].read_fd = -1;
            return;
        }
    }
}

fn drain_all_once(services: &mut [Service], buf: &mut [u8; IO_BUF]) {
    for s in services.iter_mut() {
        if s.active {
            for stream in 0..2 {
                if s.streams[stream].read_fd >= 0 {
                    drain_stream(s, stream, buf);
                }
            }
        }
    }
}

fn close_service_fds(s: &mut Service) {
    for stream in 0..2 {
        unsafe {
            close_fd(s.streams[stream].read_fd);
            close_fd(s.streams[stream].log_fd);
        }
        s.streams[stream].read_fd = -1;
        s.streams[stream].log_fd = -1;
    }
}

// ============================================================================
// Status File & Formatting
// ============================================================================

fn write_status_file(s: &Service) {
    let mut p = CStrBuf::from_bytes(s.dir_bytes());
    p.push(b"/status");

    let fd = unsafe {
        libc::open(
            p.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644 as mode_t,
        )
    };
    if fd < 0 {
        return;
    }

    let now = mono_now();
    let mut t = CStrBuf::new();

    t.push(b"name=");
    t.push(s.name_bytes());
    t.push(b"\npid=");
    t.push_i64(s.pid as i64);
    t.push(b"\nstate=");
    let st: &[u8] = match s.state {
        STATE_RUNNING => b"running",
        STATE_EXITED => b"exited",
        STATE_SIGNALED => b"signaled",
        STATE_FAILED => b"failed",
        STATE_STOPPING => b"stopping",
        _ => b"down",
    };
    t.push(st);
    t.push(b"\nuptime=");
    t.push_i64(s.uptime_seconds(now));
    t.push(b"\nrestarts=");
    t.push_u64(s.restarts as u64);
    t.push(b"\nexit_code=");
    t.push_i64(s.exit_code as i64);
    t.push(b"\nterm_signal=");
    t.push_i64(s.term_signal as i64);
    t.push(b"\nlast_wait_status=");
    t.push_i64(s.last_status as i64);
    t.push(b"\nstarted_at_mono=");
    t.push_i64(s.started_at);
    t.push(b"\nauto_start=");
    t.push(if s.auto_start { b"yes" } else { b"no" });
    t.push(b"\nonce=");
    t.push(if s.once { b"yes" } else { b"no" });
    if s.has_uid {
        t.push(b"\nuid=");
        t.push_u64(s.uid as u64);
        t.push(b"\ngid=");
        t.push_u64(s.gid as u64);
    }
    t.push(b"\n");

    write_all(fd, t.as_bytes());
    unsafe { libc::close(fd) };
}

fn format_service_status(s: &Service, now: i64, buf: &mut [u8; RESP_BUF]) -> usize {
    let mut p = CStrBuf::new();

    p.push(s.name_bytes());
    p.push(b" state=");
    let st: &[u8] = match s.state {
        STATE_RUNNING => b"running",
        STATE_EXITED => b"exited",
        STATE_SIGNALED => b"signaled",
        STATE_FAILED => b"failed",
        STATE_STOPPING => b"stopping",
        _ => b"down",
    };
    p.push(st);

    p.push(b" pid=");
    p.push_i64(s.pid as i64);

    p.push(b" uptime=");
    p.push_i64(s.uptime_seconds(now));

    p.push(b" restarts=");
    p.push_u64(s.restarts as u64);

    p.push(b" exit_code=");
    p.push_i64(s.exit_code as i64);

    p.push(b" signal=");
    p.push_i64(s.term_signal as i64);

    p.push(b" auto=");
    p.push(if s.auto_start { b"yes" } else { b"no" });

    p.push(b" once=");
    p.push(if s.once { b"yes" } else { b"no" });

    if s.has_uid {
        p.push(b" uid=");
        p.push_u64(s.uid as u64);
        p.push(b" gid=");
        p.push_u64(s.gid as u64);
    }

    p.push(b" deps=[");
    let mut first = true;
    for i in 0..s.deps_count {
        if !first {
            p.push_byte(b',');
        }
        if s.deps[i].soft {
            p.push_byte(b'?');
        }
        p.push(&s.deps[i].name[..s.deps[i].name_len]);
        first = false;
    }
    p.push(b"]");

    if s.has_log {
        p.push(b" log_pid=");
        p.push_i64(s.log_pid as i64);
        p.push(b" log_state=");
        let lst: &[u8] = match s.log_state {
            STATE_RUNNING => b"running",
            _ => b"down",
        };
        p.push(lst);
        p.push(b" log_uptime=");
        p.push_i64(s.log_uptime_seconds(now));
    }

    p.push(b"\n");

    let out = p.as_bytes();
    let copy_len = core::cmp::min(out.len(), buf.len());
    buf[..copy_len].copy_from_slice(&out[..copy_len]);
    copy_len
}

fn format_error(buf: &mut [u8; RESP_BUF], msg: &[u8]) -> usize {
    let prefix = b"ERROR: ";
    let total = prefix.len() + msg.len();
    let copy = core::cmp::min(total, buf.len());
    for i in 0..copy {
        if i < prefix.len() {
            buf[i] = prefix[i];
        } else {
            buf[i] = msg[i - prefix.len()];
        }
    }
    copy
}

fn format_ok(buf: &mut [u8; RESP_BUF], msg: &[u8]) -> usize {
    let prefix = b"OK: ";
    let total = prefix.len() + msg.len();
    let copy = core::cmp::min(total, buf.len());
    for i in 0..copy {
        if i < prefix.len() {
            buf[i] = prefix[i];
        } else {
            buf[i] = msg[i - prefix.len()];
        }
    }
    copy
}

fn split_cmd(line: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i < line.len() && !matches!(line[i], b' ' | b'\n' | b'\r') {
        i += 1;
    }
    let cmd = &line[..i];
    let mut rest_start = i;
    while rest_start < line.len() && matches!(line[rest_start], b' ' | b'\n' | b'\r') {
        rest_start += 1;
    }
    let mut rest_end = line.len();
    while rest_end > rest_start && matches!(line[rest_end - 1], b'\n' | b'\r' | b' ') {
        rest_end -= 1;
    }
    (cmd, &line[rest_start..rest_end])
}

fn signal_from_name(name: &[u8]) -> c_int {
    if bytes_eq(name, b"hup") {
        libc::SIGHUP
    } else if bytes_eq(name, b"int") {
        libc::SIGINT
    } else if bytes_eq(name, b"term") {
        libc::SIGTERM
    } else if bytes_eq(name, b"kill") {
        libc::SIGKILL
    } else if bytes_eq(name, b"usr1") {
        libc::SIGUSR1
    } else if bytes_eq(name, b"usr2") {
        libc::SIGUSR2
    } else if bytes_eq(name, b"quit") {
        libc::SIGQUIT
    } else if bytes_eq(name, b"alrm") {
        libc::SIGALRM
    } else if bytes_eq(name, b"cont") {
        libc::SIGCONT
    } else {
        0
    }
}

// ============================================================================
// Control Command Handling (Fixed signal overflow)
// ============================================================================

fn handle_signal_command(client_fd: c_int, sig_name: &[u8], arg: &[u8], services: &mut [Service]) {
    let sig = signal_from_name(sig_name);
    if sig == 0 {
        let mut resp = [0u8; RESP_BUF];
        let len = format_error(&mut resp, b"unknown signal\n");
        write_all(client_fd, &resp[..len]);
        return;
    }

    if arg.is_empty() {
        let mut resp = [0u8; RESP_BUF];
        let len = format_error(&mut resp, b"usage: <signal> <name>\n");
        write_all(client_fd, &resp[..len]);
        return;
    }

    let idx = find_service_by_name(services, arg);
    if idx == usize::MAX {
        let mut resp = [0u8; RESP_BUF];
        let len = format_error(&mut resp, b"service not found\n");
        write_all(client_fd, &resp[..len]);
        return;
    }

    let s = &services[idx];
    if s.pid <= 0 {
        let mut resp = [0u8; RESP_BUF];
        let len = format_error(&mut resp, b"service not running\n");
        write_all(client_fd, &resp[..len]);
        return;
    }

    unsafe { libc::kill(-s.pid, sig) };

    let mut resp = [0u8; RESP_BUF];
    let len = format_ok(&mut resp, b"signal sent\n");
    write_all(client_fd, &resp[..len]);
}

fn handle_control_command(client_fd: c_int, cmd_line: &[u8], services: &mut [Service]) {
    let mut resp = [0u8; RESP_BUF];
    let mut resp_len;

    let (cmd, arg) = split_cmd(cmd_line);

    if bytes_eq(cmd, b"list") || bytes_eq(cmd, b"stat") {
        let mut p = CStrBuf::new();
        let now = mono_now();
        for s in services.iter() {
            if s.active {
                let n = format_service_status(s, now, &mut resp);
                p.push(&resp[..n]);
            }
        }
        let out = p.as_bytes();
        resp_len = core::cmp::min(out.len(), RESP_BUF);
        resp[..resp_len].copy_from_slice(&out[..resp_len]);
    } else if bytes_eq(cmd, b"status") {
        if arg.is_empty() {
            resp_len = format_error(&mut resp, b"usage: status <name>\n");
        } else {
            let idx = find_service_by_name(services, arg);
            if idx == usize::MAX {
                resp_len = format_error(&mut resp, b"service not found\n");
            } else {
                resp_len = format_service_status(&services[idx], mono_now(), &mut resp);
            }
        }
    } else if bytes_eq(cmd, b"start") {
        if arg.is_empty() {
            resp_len = format_error(&mut resp, b"usage: start <name>\n");
        } else {
            let idx = find_service_by_name(services, arg);
            if idx == usize::MAX {
                resp_len = format_error(&mut resp, b"service not found\n");
            } else {
                let s = &mut services[idx];
                s.manual_start = true;
                s.restart_at = 0;
                s.stopping = false;
                resp_len = format_ok(&mut resp, b"starting\n");
            }
        }
    } else if bytes_eq(cmd, b"stop") {
        if arg.is_empty() {
            resp_len = format_error(&mut resp, b"usage: stop <name>\n");
        } else {
            let idx = find_service_by_name(services, arg);
            if idx == usize::MAX {
                resp_len = format_error(&mut resp, b"service not found\n");
            } else {
                stop_transitive_deps(services);

                let s = &mut services[idx];
                s.stopping = true;
                s.state = STATE_STOPPING;
                if s.pid > 0 {
                    unsafe { libc::kill(-s.pid, libc::SIGTERM) };
                }
                if s.log_pid > 0 {
                    unsafe { libc::kill(s.log_pid, libc::SIGTERM) };
                    s.log_stopping = true;
                }
                write_status_file(s);
                resp_len = format_ok(&mut resp, b"stopping\n");
            }
        }
    } else if bytes_eq(cmd, b"restart") {
        if arg.is_empty() {
            resp_len = format_error(&mut resp, b"usage: restart <name>\n");
        } else {
            let idx = find_service_by_name(services, arg);
            if idx == usize::MAX {
                resp_len = format_error(&mut resp, b"service not found\n");
            } else {
                let s = &mut services[idx];
                s.stopping = true;
                s.state = STATE_STOPPING;
                s.manual_start = true;
                if s.pid > 0 {
                    unsafe { libc::kill(-s.pid, libc::SIGTERM) };
                }
                if s.log_pid > 0 {
                    unsafe { libc::kill(s.log_pid, libc::SIGTERM) };
                    s.log_stopping = true;
                }
                write_status_file(s);
                resp_len = format_ok(&mut resp, b"restarting\n");
            }
        }
    } else if bytes_eq(cmd, b"down") {
        if arg.is_empty() {
            resp_len = format_error(&mut resp, b"usage: down <name>\n");
        } else {
            let idx = find_service_by_name(services, arg);
            if idx == usize::MAX {
                resp_len = format_error(&mut resp, b"service not found\n");
            } else {
                let s = &mut services[idx];
                s.auto_start = false;
                let mut down_path = CStrBuf::from_bytes(s.dir_bytes());
                down_path.push(b"/down");
                unsafe {
                    let fd = libc::open(
                        down_path.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                        0o644,
                    );
                    if fd >= 0 {
                        libc::close(fd);
                    }
                }
                if s.pid > 0 {
                    s.stopping = true;
                    s.state = STATE_STOPPING;
                    unsafe { libc::kill(-s.pid, libc::SIGTERM) };
                    if s.log_pid > 0 {
                        unsafe { libc::kill(s.log_pid, libc::SIGTERM) };
                        s.log_stopping = true;
                    }
                }
                write_status_file(s);
                resp_len = format_ok(&mut resp, b"set down and stopping\n");
            }
        }
    } else if bytes_eq(cmd, b"up") {
        if arg.is_empty() {
            resp_len = format_error(&mut resp, b"usage: up <name>\n");
        } else {
            let idx = find_service_by_name(services, arg);
            if idx == usize::MAX {
                resp_len = format_error(&mut resp, b"service not found\n");
            } else {
                let s = &mut services[idx];
                s.auto_start = true;
                let mut down_path = CStrBuf::from_bytes(s.dir_bytes());
                down_path.push(b"/down");
                unsafe { libc::unlink(down_path.as_ptr()) };
                s.restart_at = mono_now();
                s.stopping = false;
                write_status_file(s);
                resp_len = format_ok(&mut resp, b"set up\n");
            }
        }
    } else if bytes_eq(cmd, b"once") {
        if arg.is_empty() {
            resp_len = format_error(&mut resp, b"usage: once <name>\n");
        } else {
            let idx = find_service_by_name(services, arg);
            if idx == usize::MAX {
                resp_len = format_error(&mut resp, b"service not found\n");
            } else {
                let s = &mut services[idx];
                s.once = true;
                let mut once_path = CStrBuf::from_bytes(s.dir_bytes());
                once_path.push(b"/once");
                unsafe {
                    let fd = libc::open(
                        once_path.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                        0o644,
                    );
                    if fd >= 0 {
                        libc::close(fd);
                    }
                }
                write_status_file(s);
                resp_len = format_ok(&mut resp, b"once flag set\n");
            }
        }
    } else if bytes_eq(cmd, b"check") {
        if arg.is_empty() {
            resp_len = format_error(&mut resp, b"usage: check <name>\n");
        } else {
            let idx = find_service_by_name(services, arg);
            if idx == usize::MAX {
                resp_len = format_error(&mut resp, b"service not found\n");
            } else {
                let s = &services[idx];
                let mut check_path = CStrBuf::from_bytes(s.dir_bytes());
                check_path.push(b"/check");

                let mut s_clone = *s;
                prepare_service_env(&mut s_clone);

                if unsafe { libc::access(check_path.as_ptr(), libc::X_OK) } == 0 {
                    let pid = unsafe { libc::fork() };
                    if pid == 0 {
                        unsafe {
                            // SECURITY FIX: Apply restrictions BEFORE chroot
                            apply_security_restrictions(&s_clone);

                            if s_clone.chroot_enabled {
                                if libc::chroot(s_clone.dir.as_ptr() as *const c_char) != 0 {
                                    libc::_exit(126);
                                }
                                libc::chdir(b"/\0".as_ptr() as *const c_char);
                            } else {
                                libc::chdir(s_clone.dir.as_ptr() as *const c_char);
                            }
                            if s_clone.has_uid {
                                if s_clone.gid != 0 {
                                    libc::setgid(s_clone.gid as gid_t);
                                    libc::setgroups(1, &(s_clone.gid as gid_t) as *const gid_t);
                                }
                                libc::setuid(s_clone.uid as uid_t);
                                if libc::getuid() != s_clone.uid as uid_t {
                                    libc::_exit(125);
                                }
                            }

                            // FIX: Use relative path inside chroot
                            let check_ptr: *const c_char;
                            let mut check_buf = CStrBuf::new();

                            if s_clone.chroot_enabled {
                                check_ptr = b"/check\0".as_ptr() as *const c_char;
                            } else {
                                check_buf = CStrBuf::from_bytes(s_clone.dir_bytes());
                                check_buf.push(b"/check");
                                check_ptr = check_buf.as_ptr();
                            }

                            let argv: [*const c_char; 2] = [check_ptr, ptr::null()];
                            let envp = s_clone.env_ptrs.as_ptr();
                            libc::execve(check_ptr, argv.as_ptr(), envp);
                            libc::_exit(126);
                        }
                    } else if pid > 0 {
                        let mut status: c_int = 0;
                        unsafe { libc::waitpid(pid, &mut status, 0) };
                        if (status & 0x7f) == 0 {
                            resp_len = format_ok(&mut resp, b"check exited with ");
                            let ec = ((status >> 8) & 0xff) as i64;
                            let mut p2 = CStrBuf::new();
                            p2.push_i64(ec);
                            p2.push(b"\n");
                            let extra = p2.as_bytes();
                            if resp_len + extra.len() < RESP_BUF {
                                resp[resp_len..resp_len + extra.len()].copy_from_slice(extra);
                                resp_len += extra.len();
                            }
                        } else if (status & 0x7f) == 0x7f {
                            resp_len = format_error(&mut resp, b"check stopped\n");
                        } else {
                            resp_len = format_error(&mut resp, b"check killed by signal\n");
                        }
                    } else {
                        resp_len = format_error(&mut resp, b"fork failed\n");
                    }
                } else {
                    resp_len = format_error(&mut resp, b"no check script\n");
                }
            }
        }
    } else if bytes_eq(cmd, b"reload") {
        supervisor_log(b"reload requested via control socket");
        unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
        resp_len = format_ok(&mut resp, b"reload scheduled\n");
    } else if signal_from_name(cmd) != 0 {
        handle_signal_command(client_fd, cmd, arg, services);
        return;
    } else if bytes_eq(cmd, b"signal") {
        if arg.is_empty() {
            let mut resp = [0u8; RESP_BUF];
            let len = format_error(&mut resp, b"usage: signal <name> <signum>\n");
            write_all(client_fd, &resp[..len]);
            return;
        }
        let (svc_name, sig_num_part) = split_cmd(arg);
        if svc_name.is_empty() || sig_num_part.is_empty() {
            let mut resp = [0u8; RESP_BUF];
            let len = format_error(&mut resp, b"usage: signal <name> <signum>\n");
            write_all(client_fd, &resp[..len]);
            return;
        }

        // FIX: Safe parsing with overflow protection
        let signum: Option<c_int> = {
            let mut n: u64 = 0;
            let mut valid = false;
            for &c in sig_num_part {
                if c >= b'0' && c <= b'9' {
                    n = n.saturating_mul(10).saturating_add((c - b'0') as u64);
                    valid = true;
                } else {
                    break;
                }
            }
            if valid && n > 0 && n <= libc::SIGRTMAX() as u64 {
                Some(n as c_int)
            } else {
                None
            }
        };

        if signum.is_none() {
            let mut resp = [0u8; RESP_BUF];
            let len = format_error(&mut resp, b"invalid signal number\n");
            write_all(client_fd, &resp[..len]);
            return;
        }
        let signum = signum.unwrap();

        let idx = find_service_by_name(services, svc_name);
        if idx == usize::MAX {
            let mut resp = [0u8; RESP_BUF];
            let len = format_error(&mut resp, b"service not found\n");
            write_all(client_fd, &resp[..len]);
            return;
        }
        let s = &services[idx];
        if s.pid <= 0 {
            let mut resp = [0u8; RESP_BUF];
            let len = format_error(&mut resp, b"service not running\n");
            write_all(client_fd, &resp[..len]);
            return;
        }
        unsafe { libc::kill(-s.pid, signum) };
        let mut resp = [0u8; RESP_BUF];
        let len = format_ok(&mut resp, b"signal sent\n");
        write_all(client_fd, &resp[..len]);
        return;
    } else {
        resp_len = format_error(
            &mut resp,
            b"unknown command. use: list|stat|status|start|stop|restart|down|up|once|check|reload|signal|hup|term|kill|usr1|usr2|int|quit|alrm|cont|stop\n",
        );
    }

    write_all(client_fd, &resp[..resp_len]);
}

// ============================================================================
// Main
// ============================================================================

static mut SERVICES: [Service; MAX_SERVICES] = unsafe { core::mem::zeroed() };

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        ensure_stdio();
    }

    let mut root = CStrBuf::new();
    if argc > 1 && !argv.is_null() {
        let argp = unsafe { *argv.add(1) };
        if !argp.is_null() {
            root.push(unsafe { CStr::from_ptr(argp) }.to_bytes());
        }
    }
    if root.len == 0 {
        root.push(b"/etc/svc");
    }

    unsafe { supervisor_log_init() };
    supervisor_log(b"svc-rs starting");

    let sig_fd = unsafe { init_signal_pipe() };
    if sig_fd >= 0 {
        unsafe { install_signal_handlers() };
    }

    let ctrl_fd = unsafe { create_control_socket(&root) };

    let services = unsafe { &mut *ptr::addr_of_mut!(SERVICES) };
    let mut buf = [0u8; IO_BUF];
    let mut next_scan = mono_now();
    let mut reload_needed = false;

    loop {
        reap_children(services);

        let t = mono_now();

        if t >= next_scan || reload_needed {
            let ok = scan_services(&root, services);
            if ok {
                handle_missing_services(services);
            }
            next_scan = t + 15;
            reload_needed = false;
            supervisor_log(b"configuration reloaded");
        }

        for i in 0..MAX_SERVICES {
            let svc = &services[i];
            if svc.active && svc.present && !svc.stopping && svc.pid <= 0 && t >= svc.restart_at {
                if svc.manual_start || (svc.auto_start && !svc.once) {
                    if !deps_satisfied(svc, services) {
                        services[i].restart_at = mono_now() + 1;
                    } else {
                        start_service(&mut services[i]);
                    }
                }
            }
        }

        let mut pfds: [libc::pollfd; MAX_POLL_FDS] = [libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        }; MAX_POLL_FDS];
        let mut map_service = [0usize; MAX_POLL_FDS];
        let mut map_stream = [0usize; MAX_POLL_FDS];
        let mut n: usize = 0;
        let mut sig_idx: usize = usize::MAX;
        let mut ctrl_idx: usize = usize::MAX;

        if sig_fd >= 0 {
            pfds[n].fd = sig_fd;
            pfds[n].events = libc::POLLIN as libc::c_short;
            sig_idx = n;
            n += 1;
        }

        if ctrl_fd >= 0 {
            pfds[n].fd = ctrl_fd;
            pfds[n].events = libc::POLLIN as libc::c_short;
            ctrl_idx = n;
            n += 1;
        }

        for i in 0..MAX_SERVICES {
            if services[i].active {
                for stream in 0..2 {
                    if services[i].streams[stream].read_fd >= 0 {
                        pfds[n].fd = services[i].streams[stream].read_fd;
                        pfds[n].events = libc::POLLIN as libc::c_short;
                        map_service[n] = i;
                        map_stream[n] = stream;
                        n += 1;
                    }
                }
            }
        }

        let r = unsafe { libc::poll(pfds.as_mut_ptr(), n as nfds_t, POLL_TIMEOUT_MS) };

        if r < 0 {
            if is_eintr() {
                continue;
            }
            sleep_ms(50);
            continue;
        }

        let mut shutdown = false;

        for j in 0..n {
            let mask = (libc::POLLIN | libc::POLLHUP | libc::POLLERR) as libc::c_short;

            if (pfds[j].revents & mask) != 0 {
                if j == sig_idx {
                    if let Some(sig) = drain_signal_pipe(sig_fd) {
                        if sig == libc::SIGTERM || sig == libc::SIGINT {
                            shutdown = true;
                            break;
                        }
                        if sig == libc::SIGHUP {
                            reload_needed = true;
                        }
                    }
                } else if j == ctrl_idx {
                    let client = unsafe { libc::accept(ctrl_fd, ptr::null_mut(), ptr::null_mut()) };
                    if client >= 0 {
                        unsafe { set_cloexec(client) };
                        let mut cmd_buf = [0u8; CMD_BUF];
                        let nr = read_all_nonblock(client, &mut cmd_buf);
                        if nr > 0 {
                            handle_control_command(client, &cmd_buf[..nr as usize], services);
                        }
                        unsafe { close_fd(client) };
                    }
                } else {
                    let idx = map_service[j];
                    let stream = map_stream[j];
                    drain_stream(&mut services[idx], stream, &mut buf);
                }
            }
        }

        if shutdown {
            break;
        }
    }

    shutdown_services(services);

    unsafe {
        close_fd(ctrl_fd);
        let mut sock_path = CStrBuf::from_bytes(root.as_bytes());
        sock_path.push(SOCK_SUFFIX);
        libc::unlink(sock_path.as_ptr());
        close_fd(SUPERVISOR_LOG_FD);
        SUPERVISOR_LOG_FD = -1;
    }

    0
}

#[used]
#[unsafe(link_section = ".license")]
static LICENSE: [u8; 436] = *b"\
svc-rs Copyright (c) 2026 Semyon Tsarev
This project is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
project, You can obtain one at https://mozilla.org/MPL/2.0/.
This project is \"Incompatible With Secondary Licenses\",
as defined by the Mozilla Public License, v. 2.0.
You can download the source code from:
https://github.com/SemyonTs/svc-rs/archive/refs/heads/main.zip\x00";
