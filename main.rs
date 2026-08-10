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

use core::ffi::CStr;
use core::mem;
use core::ptr;
use libc::{
    c_char, c_int, c_long, c_void, gid_t, nfds_t, off_t, pid_t, sockaddr, sockaddr_un, socklen_t,
    time_t, uid_t,
};

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
const PASSWD_LINE: usize = 256;

const MAX_DEPENDENCIES: usize = 16;
const DEP_FILE_BUF: usize = 512;

const LOG_LIMIT: off_t = 1_048_576; // 1 MiB
const POLL_TIMEOUT_MS: c_int = 500;
const SHUTDOWN_TIMEOUT_S: i64 = 5;
const MAX_POLL_FDS: usize = MAX_SERVICES * 2 + 2;

// Backoff & Circuit Breaker
const RESTART_WINDOW_S: i64 = 60;
const MAX_RESTARTS_IN_WINDOW: u32 = 5;
const BACKOFF_SHORT: i64 = 2;
const BACKOFF_MED: i64 = 10;
const BACKOFF_LONG: i64 = 60;

const DEV_NULL: &[u8] = b"/dev/null\0";
const SOCK_SUFFIX: &[u8] = b"/.control.sock";

const STATE_DOWN: u8 = 0;
const STATE_RUNNING: u8 = 1;
const STATE_EXITED: u8 = 2;
const STATE_SIGNALED: u8 = 3;
const STATE_FAILED: u8 = 4;
const STATE_STOPPING: u8 = 5;

// ============================================================================
// Portable errno
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
    unsafe { *libc::__error() }
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

// ============================================================================
// Signal self-pipe
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

// ============================================================================
// Path helper
// ============================================================================

#[derive(Clone, Copy)]
struct Path {
    buf: [u8; PATH_BUF],
    len: usize,
}

impl Path {
    const fn new() -> Self {
        Self {
            buf: [0; PATH_BUF],
            len: 0,
        }
    }

    fn from_bytes(b: &[u8]) -> Self {
        let mut p = Self::new();
        p.push(b);
        p
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn as_ptr(&self) -> *const c_char {
        self.buf.as_ptr() as *const c_char
    }

    fn push(&mut self, b: &[u8]) {
        for &c in b {
            self.push_byte(c);
        }
    }

    fn push_byte(&mut self, c: u8) {
        if self.len + 1 < PATH_BUF {
            self.buf[self.len] = c;
            self.len += 1;
        }
        self.buf[self.len] = 0;
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
}

// ============================================================================
// Dependency descriptor
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

// ============================================================================
// Stream / Service
// ============================================================================

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
    stopping_deps_checked: bool,

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
    log_restart_at: i64,
    log_started_at: i64,
    log_restarts: u32,
    log_stopping: bool,

    uid: uid_t,
    gid: gid_t,
    has_uid: bool,
}

const SERVICE_EMPTY: Service = Service {
    active: false,
    present: false,
    stopping: false,
    manual_start: false,
    stopping_deps_checked: false,
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
    log_restart_at: 0,
    log_started_at: 0,
    log_restarts: 0,
    log_stopping: false,
    uid: 0,
    gid: 0,
    has_uid: false,
};

impl Service {
    fn dir_bytes(&self) -> &[u8] {
        &self.dir[..self.dir_len]
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    fn set_dir(&mut self, p: &Path) {
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
// Utility functions
// ============================================================================


fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

fn wall_now() -> time_t {
    unsafe { libc::time(ptr::null_mut()) }
}

fn mono_now() -> i64 {
    unsafe {
        let mut ts: libc::timespec = mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) == 0 {
            return ts.tv_sec as i64;
        }
        libc::time(ptr::null_mut()) as i64
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
    if fd >= 0 {
        loop {
            if unsafe { libc::close(fd) } == 0 || !is_eintr() {
                break;
            }
        }
    }
}

unsafe fn set_nonblock(fd: c_int) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return false;
    }
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0 }
}

unsafe fn set_cloexec(fd: c_int) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD, 0) };
    if flags < 0 {
        return false;
    }
    unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) >= 0 }
}

unsafe fn close_from(min: c_int) {
    let mut max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if max <= 0 {
        max = 1024;
    }
    if max > 65536 {
        max = 65536;
    }
    let mut fd = min;
    while fd < max as c_int {
        unsafe { libc::close(fd) };
        fd += 1;
    }
}

unsafe fn ensure_stdio() {
    let mut fd: c_int = 0;
    while fd < 3 {
        if unsafe { libc::fcntl(fd, libc::F_GETFL, 0) } < 0 {
            let nfd = unsafe { libc::open(DEV_NULL.as_ptr() as *const c_char, libc::O_RDWR) };
            if nfd >= 0 {
                if nfd != fd {
                    unsafe { libc::dup2(nfd, fd) };
                    unsafe { libc::close(nfd) };
                }
            }
        }
        fd += 1;
    }
}

fn write_all(fd: c_int, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let r = unsafe { libc::write(fd, data.as_ptr() as *const c_void, data.len()) };
        if r > 0 {
            data = &data[r as usize..];
        } else if r == 0 {
            return false;
        } else if is_eintr() {
            continue;
        } else {
            return false;
        }
    }
    true
}

fn read_all_nonblock(fd: c_int, buf: &mut [u8]) -> isize {
    loop {
        let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if r >= 0 {
            return r;
        }
        if is_eintr() {
            continue;
        }
        return r;
    }
}

fn read_file_to_buf(path: &Path, buf: &mut [u8]) -> isize {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return -1;
    }
    let nr = read_all_nonblock(fd, buf);
    unsafe { close_fd(fd) };
    nr
}

// ============================================================================
// User/Group Resolution (no_std safe)
// ============================================================================

fn resolve_id_from_file(path: &[u8], name: &[u8], want_gid: bool) -> Option<u32> {
    let fd = unsafe { libc::open(path.as_ptr() as *const c_char, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }

    let mut buf = [0u8; PASSWD_LINE];
    let mut found = None;

    loop {
        let nr = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if nr <= 0 {
            break;
        }

        let data = &buf[..nr as usize];
        let mut line_start = 0;

        while line_start < data.len() {
            let mut line_end = line_start;
            while line_end < data.len() && data[line_end] != b'\n' {
                line_end += 1;
            }

            let line = &data[line_start..line_end];
            let mut colons = 0;
            let mut field_start = 0;
            let mut id_val: u32 = 0;
            let mut name_match = false;

            for (i, &c) in line.iter().enumerate() {
                if c == b':' || i == line.len() - 1 {
                    let end_idx = if c == b':' { i } else { i + 1 };
                    let field = &line[field_start..end_idx];

                    if colons == 0 {
                        name_match = bytes_eq(field, name);
                    } else {
                        let target_col = if want_gid && path.ends_with(b"group") {
                            2
                        } else if want_gid {
                            3
                        } else {
                            2
                        };

                        if colons == target_col {
                            let mut n: u32 = 0;
                            for &d in field {
                                if d >= b'0' && d <= b'9' {
                                    n = n.saturating_mul(10).saturating_add((d - b'0') as u32);
                                } else {
                                    break;
                                }
                            }
                            id_val = n;
                        }
                    }

                    field_start = i + 1;
                    colons += 1;
                }
            }

            if name_match && colons >= 3 {
                found = Some(id_val);
                break;
            }

            line_start = line_end + 1;
        }

        if found.is_some() {
            break;
        }
    }

    unsafe { libc::close(fd) };
    found
}

fn parse_user_group(s: &mut Service) {
    s.uid = 0;
    s.gid = 0;
    s.has_uid = false;

    // Fix E0506: Copy dir bytes to local buffer to avoid borrowing `s` immutably
    // while we need to mutate `s.uid` later.
    let mut dir_buf = [0u8; PATH_BUF];
    let dir_len = s.dir_len;
    dir_buf[..dir_len].copy_from_slice(&s.dir[..dir_len]);
    let dir = &dir_buf[..dir_len];

    // Parse user
    let mut user_path = Path::from_bytes(dir);
    user_path.push(b"/user");
    let mut ubuf = [0u8; NAME_BUF];
    let nr = read_file_to_buf(&user_path, &mut ubuf);

    if nr > 0 {
        let uname = &ubuf[..nr as usize];
        let mut end = uname.len();
        while end > 0
            && (uname[end - 1] == b'\n' || uname[end - 1] == b'\r' || uname[end - 1] == b' ')
        {
            end -= 1;
        }
        let clean_name = &uname[..end];

        if !clean_name.is_empty() {
            let mut numeric = true;
            let mut uid_val: u32 = 0;
            for &c in clean_name {
                if c >= b'0' && c <= b'9' {
                    uid_val = uid_val.saturating_mul(10).saturating_add((c - b'0') as u32);
                } else {
                    numeric = false;
                    break;
                }
            }

            if numeric {
                s.uid = uid_val;
                s.has_uid = true;
            } else if let Some(uid) = resolve_id_from_file(b"/etc/passwd\0", clean_name, false) {
                s.uid = uid;
                s.has_uid = true;
            }
        }
    }

    // Parse group
    let mut grp_path = Path::from_bytes(dir);
    grp_path.push(b"/group");
    let mut gbuf = [0u8; NAME_BUF];
    let gnr = read_file_to_buf(&grp_path, &mut gbuf);

    if gnr > 0 {
        let gname = &gbuf[..gnr as usize];
        let mut end = gname.len();
        while end > 0
            && (gname[end - 1] == b'\n' || gname[end - 1] == b'\r' || gname[end - 1] == b' ')
        {
            end -= 1;
        }
        let clean_gname = &gname[..end];

        if !clean_gname.is_empty() {
            let mut numeric = true;
            let mut gid_val: u32 = 0;
            for &c in clean_gname {
                if c >= b'0' && c <= b'9' {
                    gid_val = gid_val.saturating_mul(10).saturating_add((c - b'0') as u32);
                } else {
                    numeric = false;
                    break;
                }
            }

            if numeric {
                s.gid = gid_val;
            } else if let Some(gid) = resolve_id_from_file(b"/etc/group\0", clean_gname, true) {
                s.gid = gid;
            }
        }
    }
}

// ============================================================================
// Signal pipe setup
// ============================================================================

unsafe fn init_signal_pipe() -> c_int {
    let mut fds: [c_int; 2] = [-1, -1];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return -1;
    }
    unsafe { set_nonblock(fds[0]) };
    unsafe { set_nonblock(fds[1]) };
    unsafe { set_cloexec(fds[0]) };
    unsafe { set_cloexec(fds[1]) };
    unsafe { SIG_PIPE_W = fds[1] };
    fds[0]
}

unsafe fn set_signal_action(sig: c_int) {
    let mut sa: libc::sigaction = unsafe { mem::zeroed() };
    sa.sa_sigaction = signal_handler as *const () as usize as libc::sighandler_t;
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };
    sa.sa_flags = libc::SA_RESTART;
    unsafe { libc::sigaction(sig, &sa, ptr::null_mut()) };
}

unsafe fn install_signal_handlers() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    unsafe { set_signal_action(libc::SIGTERM) };
    unsafe { set_signal_action(libc::SIGINT) };
    unsafe { set_signal_action(libc::SIGCHLD) };
}

fn drain_signal_pipe(sig_fd: c_int) -> bool {
    let mut buf = [0u8; 64];
    loop {
        let r = unsafe { libc::read(sig_fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if r <= 0 {
            break;
        }
        let n = r as usize;
        for i in 0..n {
            let sig = buf[i] as c_int;
            if sig == libc::SIGTERM || sig == libc::SIGINT {
                return true;
            }
        }
    }
    false
}

// ============================================================================
// Control socket
// ============================================================================

unsafe fn create_control_socket(root: &Path) -> c_int {
    let mut sock_path = Path::from_bytes(root.as_bytes());
    sock_path.push(SOCK_SUFFIX);

    unsafe { libc::unlink(sock_path.as_ptr()) };

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return -1;
    }

    let mut addr: sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;

    let path_bytes = sock_path.as_bytes();
    let max_len = core::mem::size_of_val(&addr.sun_path) - 1;
    let copy_len = core::cmp::min(path_bytes.len(), max_len);

    for i in 0..copy_len {
        addr.sun_path[i] = path_bytes[i] as c_char;
    }
    addr.sun_path[copy_len] = 0;

    let addr_len = (core::mem::size_of::<sockaddr_un>() - max_len + copy_len + 1) as socklen_t;

    if unsafe { libc::bind(fd, &addr as *const sockaddr_un as *const sockaddr, addr_len) } < 0 {
        unsafe { close_fd(fd) };
        return -1;
    }

    unsafe { libc::chmod(sock_path.as_ptr(), 0o660) };

    if unsafe { libc::listen(fd, 5) } < 0 {
        unsafe { close_fd(fd) };
        return -1;
    }

    unsafe { set_nonblock(fd) };
    fd
}

fn find_service_by_name(services: &[Service], name: &[u8]) -> usize {
    for (i, s) in services.iter().enumerate() {
        if s.active && bytes_eq(s.name_bytes(), name) {
            return i;
        }
    }
    usize::MAX
}

fn format_service_status(s: &Service, now: i64, buf: &mut [u8; RESP_BUF]) -> usize {
    let mut p = Path::new();

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
    while i < line.len() && line[i] != b' ' && line[i] != b'\n' && line[i] != b'\r' {
        i += 1;
    }
    let cmd = &line[..i];
    let mut rest_start = i;
    while rest_start < line.len()
        && (line[rest_start] == b' ' || line[rest_start] == b'\n' || line[rest_start] == b'\r')
    {
        rest_start += 1;
    }
    let mut rest_end = line.len();
    while rest_end > rest_start
        && (line[rest_end - 1] == b'\n'
            || line[rest_end - 1] == b'\r'
            || line[rest_end - 1] == b' ')
    {
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
    } else if bytes_eq(name, b"stop") {
        libc::SIGSTOP
    } else {
        0
    }
}

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

    unsafe {
        libc::kill(-s.pid, sig);
    }

    let mut resp = [0u8; RESP_BUF];
    let len = format_ok(&mut resp, b"signal sent\n");
    write_all(client_fd, &resp[..len]);
}

/// Reverse dependency shutdown: stop all services that depend on target_name
fn stop_reverse_deps(services: &mut [Service], target_name: &[u8]) -> usize {
    let mut count = 0;
    let mut changed = true;

    while changed {
        changed = false;
        for i in 0..services.len() {
            if !services[i].active
                || services[i].stopping
                || services[i].pid <= 0
                || services[i].stopping_deps_checked
            {
                continue;
            }

            let mut depends_on_target = false;
            for d in 0..services[i].deps_count {
                if bytes_eq(
                    &services[i].deps[d].name[..services[i].deps[d].name_len],
                    target_name,
                ) {
                    depends_on_target = true;
                    break;
                }
            }

            if depends_on_target {
                services[i].stopping = true;
                services[i].state = STATE_STOPPING;
                services[i].stopping_deps_checked = true;
                unsafe { libc::kill(-services[i].pid, libc::SIGTERM) };
                write_status_file(&services[i]);
                count += 1;
                changed = true;
            }
        }
    }

    count
}

fn handle_control_command(client_fd: c_int, cmd_line: &[u8], services: &mut [Service]) {
    let mut resp = [0u8; RESP_BUF];
    let mut resp_len;

    let (cmd, arg) = split_cmd(cmd_line);

    if bytes_eq(cmd, b"list") || bytes_eq(cmd, b"stat") {
        let mut p = Path::new();
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
                s.stopping_deps_checked = false;
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
                // Reverse dependency shutdown
                let mut name_buf = [0u8; NAME_BUF];
                let nlen = services[idx].name_len;
                name_buf[..nlen].copy_from_slice(&services[idx].name[..nlen]);
                stop_reverse_deps(services, &name_buf[..nlen]);

                let s = &mut services[idx];
                s.stopping = true;
                s.state = STATE_STOPPING;
                if s.pid > 0 {
                    unsafe {
                        libc::kill(-s.pid, libc::SIGTERM);
                    }
                }
                if s.log_pid > 0 {
                    unsafe {
                        libc::kill(s.log_pid, libc::SIGTERM);
                    }
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
                    unsafe {
                        libc::kill(-s.pid, libc::SIGTERM);
                    }
                }
                if s.log_pid > 0 {
                    unsafe {
                        libc::kill(s.log_pid, libc::SIGTERM);
                    }
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
                let mut down_path = Path::from_bytes(s.dir_bytes());
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
                let mut down_path = Path::from_bytes(s.dir_bytes());
                down_path.push(b"/down");
                unsafe {
                    libc::unlink(down_path.as_ptr());
                }
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
                let mut once_path = Path::from_bytes(s.dir_bytes());
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
                let mut check_path = Path::from_bytes(s.dir_bytes());
                check_path.push(b"/check");
                if unsafe { libc::access(check_path.as_ptr(), libc::X_OK) } == 0 {
                    let pid = unsafe { libc::fork() };
                    if pid == 0 {
                        unsafe {
                            libc::chdir(s.dir.as_ptr() as *const c_char);
                            let argv: [*const c_char; 2] = [check_path.as_ptr(), ptr::null()];
                            libc::execv(check_path.as_ptr(), argv.as_ptr());
                            libc::_exit(126);
                        }
                    } else if pid > 0 {
                        let mut status: c_int = 0;
                        unsafe { libc::waitpid(pid, &mut status, 0) };
                        if (status & 0x7f) == 0 {
                            resp_len = format_ok(&mut resp, b"check exited with ");
                            let ec = ((status >> 8) & 0xff) as i64;
                            let mut p2 = Path::new();
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
        let signum: c_int = {
            let mut n: c_int = 0;
            for &c in sig_num_part {
                if c >= b'0' && c <= b'9' {
                    n = n * 10 + (c - b'0') as c_int;
                } else {
                    break;
                }
            }
            n
        };
        if signum <= 0 {
            let mut resp = [0u8; RESP_BUF];
            let len = format_error(&mut resp, b"invalid signal number\n");
            write_all(client_fd, &resp[..len]);
            return;
        }
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
// Logging
// ============================================================================

fn decode_wait_status(status: c_int) -> (u8, c_int, c_int) {
    if (status & 0x7f) == 0 {
        (STATE_EXITED, (status >> 8) & 0xff, 0)
    } else if (status & 0x7f) == 0x7f {
        (STATE_DOWN, 0, 0)
    } else {
        (STATE_SIGNALED, 0, status & 0x7f)
    }
}

fn write_status_file(s: &Service) {
    let mut p = Path::from_bytes(s.dir_bytes());
    p.push(b"/status");

    let fd = unsafe {
        libc::open(
            p.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644 as libc::mode_t,
        )
    };
    if fd < 0 {
        return;
    }

    let now = mono_now();
    let mut t = Path::new();

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
    unsafe {
        libc::close(fd);
    }
}

fn open_log(s: &mut Service, stream: usize) {
    let dir = Path::from_bytes(s.dir_bytes());
    let st = &mut s.streams[stream];

    unsafe {
        close_fd(st.log_fd);
    }
    st.log_fd = -1;

    let mut logdir = dir;
    logdir.push(b"/log");
    unsafe {
        libc::mkdir(logdir.as_ptr(), 0o755 as libc::mode_t);
    }

    let mut path = logdir;
    if stream == 0 {
        path.push(b"/current.out");
    } else {
        path.push(b"/current.err");
    }

    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o644 as libc::mode_t,
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
    let dir = Path::from_bytes(s.dir_bytes());

    {
        let st = &mut s.streams[stream];
        unsafe {
            close_fd(st.log_fd);
        }
        st.log_fd = -1;
        st.rotations += 1;
    }

    let ts = wall_now();
    let rotations = s.streams[stream].rotations;

    let suffix: &[u8] = if stream == 0 {
        b"/current.out"
    } else {
        b"/current.err"
    };

    let mut src = dir;
    src.push(suffix);

    let mut arch = dir;
    arch.push(suffix);
    arch.push_byte(b'.');
    arch.push_u64(ts as u64);
    arch.push_byte(b'.');
    arch.push_u64(rotations as u64);

    unsafe {
        libc::rename(src.as_ptr(), arch.as_ptr());
    }

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
        unsafe {
            close_fd(fd);
        }
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
            unsafe {
                close_fd(fd);
            }
            s.streams[stream].read_fd = -1;
            return;
        } else if is_eagain() {
            return;
        } else {
            unsafe {
                close_fd(fd);
            }
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
// Service lifecycle
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

fn start_service(s: &mut Service) {
    if !s.active || !s.present || s.stopping || s.pid > 0 {
        return;
    }

    unsafe {
        close_fd(s.streams[0].read_fd);
        close_fd(s.streams[1].read_fd);
    }
    s.streams[0].read_fd = -1;
    s.streams[1].read_fd = -1;

    let mut out_fds: [c_int; 2] = [-1, -1];
    let mut err_fds: [c_int; 2] = [-1, -1];

    let mut log_pipe_wr: c_int = -1;
    if s.has_log {
        let mut log_run = Path::from_bytes(s.dir_bytes());
        log_run.push(b"/log/run");
        if unsafe { libc::access(log_run.as_ptr(), libc::X_OK) } == 0 {
            let mut pipe_fds: [c_int; 2] = [-1, -1];
            if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } == 0 {
                let pipe_rd = pipe_fds[0];
                let pipe_wr = pipe_fds[1];
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    unsafe {
                        libc::setsid();
                        libc::dup2(pipe_rd, 0);
                        libc::close(pipe_rd);
                        libc::close(pipe_wr);
                        close_from(3);
                        libc::chdir(s.dir.as_ptr() as *const c_char);
                        let argv: [*const c_char; 2] = [log_run.as_ptr(), ptr::null()];
                        libc::execv(log_run.as_ptr(), argv.as_ptr());
                        libc::_exit(126);
                    }
                } else if pid > 0 {
                    unsafe { close_fd(pipe_rd) };
                    s.log_pid = pid;
                    s.log_state = STATE_RUNNING;
                    s.log_started_at = mono_now();
                    s.log_stopping = false;
                    s.log_restarts = 0;
                    s.log_restart_at = 0;
                    log_pipe_wr = pipe_wr;
                } else {
                    unsafe {
                        close_fd(pipe_rd);
                        close_fd(pipe_wr);
                    }
                    s.has_log = false;
                }
            }
        } else {
            s.has_log = false;
        }
    }

    if !s.has_log {
        if unsafe { libc::pipe(out_fds.as_mut_ptr()) } != 0 {
            s.state = STATE_FAILED;
            s.restart_at = mono_now() + BACKOFF_SHORT;
            write_status_file(s);
            return;
        }
        unsafe {
            set_nonblock(out_fds[0]);
            set_cloexec(out_fds[0]);
            set_cloexec(out_fds[1]);
        }

        if unsafe { libc::pipe(err_fds.as_mut_ptr()) } != 0 {
            unsafe {
                close_fd(out_fds[0]);
                close_fd(out_fds[1]);
            }
            s.state = STATE_FAILED;
            s.restart_at = mono_now() + BACKOFF_SHORT;
            write_status_file(s);
            return;
        }
        unsafe {
            set_nonblock(err_fds[0]);
            set_cloexec(err_fds[0]);
            set_cloexec(err_fds[1]);
        }
    }

    let pid = unsafe { libc::fork() };

    if pid == 0 {
        unsafe {
            libc::setsid();

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

            if log_pipe_wr >= 0 {
                libc::dup2(log_pipe_wr, 1);
                libc::dup2(log_pipe_wr, 2);
                libc::close(log_pipe_wr);
            } else {
                libc::dup2(out_fds[1], 1);
                libc::dup2(err_fds[1], 2);
                libc::close(out_fds[0]);
                libc::close(err_fds[0]);
                if out_fds[1] > 2 {
                    libc::close(out_fds[1]);
                }
                if err_fds[1] > 2 {
                    libc::close(err_fds[1]);
                }
            }

            close_from(3);

            libc::chdir(s.dir.as_ptr() as *const c_char);

            let mut run = Path::from_bytes(s.dir_bytes());
            run.push(b"/run");

            let argv: [*const c_char; 2] = [run.as_ptr(), ptr::null()];
            libc::execv(run.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    if !s.has_log {
        unsafe {
            libc::close(out_fds[1]);
            libc::close(err_fds[1]);
        }
    } else {
        unsafe { close_fd(log_pipe_wr) };
    }

    if pid > 0 {
        s.pid = pid;
        s.state = STATE_RUNNING;
        s.exit_code = 0;
        s.term_signal = 0;
        s.started_at = mono_now();
        s.manual_start = false;
        if !s.has_log {
            s.streams[0].read_fd = out_fds[0];
            s.streams[1].read_fd = err_fds[0];
            open_log(s, 0);
            open_log(s, 1);
        }
        write_status_file(s);
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
    }
}

fn find_service_by_dir(services: &[Service], dir: &Path) -> usize {
    for (i, s) in services.iter().enumerate() {
        if s.active && s.dir_bytes() == dir.as_bytes() {
            return i;
        }
    }
    usize::MAX
}

fn add_service(services: &mut [Service], name: &[u8], dir: &Path) {
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

            let mut down_path = Path::from_bytes(dir.as_bytes());
            down_path.push(b"/down");
            if unsafe { libc::access(down_path.as_ptr(), libc::F_OK) } == 0 {
                s.auto_start = false;
            }
            let mut once_path = Path::from_bytes(dir.as_bytes());
            once_path.push(b"/once");
            if unsafe { libc::access(once_path.as_ptr(), libc::F_OK) } == 0 {
                s.once = true;
            }

            let mut deps_path = Path::from_bytes(dir.as_bytes());
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
                    while r > l && (line[r - 1] == b' ' || line[r - 1] == b'\t') {
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
                    while start < data.len() && (data[start] == b'\n' || data[start] == b'\r') {
                        start += 1;
                    }
                }
                s.deps_count = di;
            }

            let mut log_run = Path::from_bytes(dir.as_bytes());
            log_run.push(b"/log/run");
            if unsafe { libc::access(log_run.as_ptr(), libc::X_OK) } == 0 {
                s.has_log = true;
            }

            parse_user_group(s);

            write_status_file(s);
            return;
        }
    }
}

fn scan_services(root: &Path, services: &mut [Service]) -> bool {
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

            let mut dir = Path::from_bytes(root.as_bytes());
            dir.push(b"/");
            dir.push(name);

            let mut run = dir;
            run.push(b"/run");

            if libc::access(run.as_ptr(), libc::X_OK) == 0 {
                let idx = find_service_by_dir(services, &dir);
                if idx != usize::MAX {
                    services[idx].present = true;
                    services[idx].stopping = false;
                    parse_user_group(&mut services[idx]);
                } else {
                    add_service(services, name, &dir);
                }
            }
        }

        libc::closedir(dp);
    }
    true
}

fn run_finish(s: &Service) {
    let mut finish_path = Path::from_bytes(s.dir_bytes());
    finish_path.push(b"/finish");
    if unsafe { libc::access(finish_path.as_ptr(), libc::X_OK) } == 0 {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::chdir(s.dir.as_ptr() as *const c_char);
                let exit_str = {
                    let mut buf = [0u8; 20];
                    let mut p = Path::new();
                    p.push_i64(s.exit_code as i64);
                    let b = p.as_bytes();
                    let n = core::cmp::min(b.len(), 19);
                    buf[..n].copy_from_slice(&b[..n]);
                    buf[n] = 0;
                    buf
                };
                let sig_str = {
                    let mut buf = [0u8; 20];
                    let mut p = Path::new();
                    p.push_i64(s.term_signal as i64);
                    let b = p.as_bytes();
                    let n = core::cmp::min(b.len(), 19);
                    buf[..n].copy_from_slice(&b[..n]);
                    buf[n] = 0;
                    buf
                };
                let argv: [*const c_char; 4] = [
                    finish_path.as_ptr(),
                    exit_str.as_ptr() as *const c_char,
                    sig_str.as_ptr() as *const c_char,
                    ptr::null(),
                ];
                libc::execv(finish_path.as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
        }
    }
}

fn handle_missing_services(services: &mut [Service]) {
    // Fix E0499: Use index-based iteration to allow passing `services` mutably
    // to stop_reverse_deps while iterating.
    let mut i = 0;
    while i < services.len() {
        if services[i].active && !services[i].present {
            if services[i].pid > 0 {
                if !services[i].stopping {
                    let mut name_buf = [0u8; NAME_BUF];
                    let nlen = services[i].name_len;
                    name_buf[..nlen].copy_from_slice(&services[i].name[..nlen]);

                    stop_reverse_deps(services, &name_buf[..nlen]);

                    unsafe {
                        libc::kill(-services[i].pid, libc::SIGTERM);
                    }
                    services[i].stopping = true;
                    services[i].state = STATE_STOPPING;
                }
            }
            if services[i].log_pid > 0 && !services[i].log_stopping {
                unsafe {
                    libc::kill(services[i].log_pid, libc::SIGTERM);
                }
                services[i].log_stopping = true;
            }
            if services[i].pid <= 0 && services[i].log_pid <= 0 {
                close_service_fds(&mut services[i]);
                services[i].active = false;
                services[i].state = STATE_DOWN;
                write_status_file(&services[i]);
            }
        }
        i += 1;
    }
}

fn reap_children(services: &mut [Service]) {
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
                if !s.log_stopping {
                    s.log_restart_at = t + 1;
                } else {
                    s.log_stopping = false;
                }
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
}

fn any_open_services(services: &[Service]) -> bool {
    for s in services.iter() {
        if s.active
            && (s.pid > 0
                || s.streams[0].read_fd >= 0
                || s.streams[1].read_fd >= 0
                || s.log_pid > 0)
        {
            return true;
        }
    }
    false
}

fn shutdown_services(services: &mut [Service]) {
    let mut buf = [0u8; IO_BUF];

    for s in services.iter_mut() {
        if s.active {
            if s.pid > 0 {
                unsafe {
                    libc::kill(-s.pid, libc::SIGTERM);
                }
                s.stopping = true;
                s.state = STATE_STOPPING;
            }
            if s.log_pid > 0 {
                unsafe {
                    libc::kill(s.log_pid, libc::SIGTERM);
                }
                s.log_stopping = true;
            }
            write_status_file(s);
        }
    }

    let deadline = mono_now() + SHUTDOWN_TIMEOUT_S;

    loop {
        reap_children(services);
        drain_all_once(services, &mut buf);
        if !any_open_services(services) {
            break;
        }
        if mono_now() >= deadline {
            break;
        }
        sleep_ms(100);
    }

    for s in services.iter_mut() {
        if s.active && s.pid > 0 {
            unsafe {
                libc::kill(-s.pid, libc::SIGKILL);
            }
        }
        if s.active && s.log_pid > 0 {
            unsafe {
                libc::kill(s.log_pid, libc::SIGKILL);
            }
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
}

// ============================================================================
// Main
// ============================================================================

const SERVICES_ZERO: [Service; MAX_SERVICES] = unsafe { core::mem::zeroed() };
static mut SERVICES: [Service; MAX_SERVICES] = SERVICES_ZERO;

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        ensure_stdio();
    }

    let mut root = Path::new();
    if argc > 1 && !argv.is_null() {
        let argp = unsafe { *argv.add(1) };
        if !argp.is_null() {
            root.push(unsafe { CStr::from_ptr(argp) }.to_bytes());
        }
    }
    if root.len == 0 {
        root.push(b"/etc/svc");
    }

    let sig_fd = unsafe { init_signal_pipe() };
    if sig_fd >= 0 {
        unsafe {
            install_signal_handlers();
        }
    }

    let ctrl_fd = unsafe { create_control_socket(&root) };

    let services = unsafe { &mut *ptr::addr_of_mut!(SERVICES) };
    let mut buf = [0u8; IO_BUF];
    let mut next_scan = mono_now();

    loop {
        reap_children(services);

        let t = mono_now();

        if t >= next_scan {
            let ok = scan_services(&root, services);
            if ok {
                handle_missing_services(services);
            }
            next_scan = t + 15;
        }

        for i in 0..MAX_SERVICES {
            let svc_active = services[i].active;
            let svc_present = services[i].present;
            let svc_stopping = services[i].stopping;
            let svc_pid = services[i].pid;
            let svc_restart_at = services[i].restart_at;
            let svc_manual_start = services[i].manual_start;
            let svc_auto_start = services[i].auto_start;
            let svc_once = services[i].once;

            if svc_active && svc_present && !svc_stopping && svc_pid <= 0 && t >= svc_restart_at {
                if svc_manual_start || (svc_auto_start && !svc_once) {
                    if !deps_satisfied(&services[i], services) {
                        services[i].restart_at = mono_now() + 1;
                    } else {
                        start_service(&mut services[i]);
                    }
                }
            }

            if services[i].active
                && services[i].has_log
                && services[i].pid > 0
                && services[i].state == STATE_RUNNING
                && services[i].log_pid <= 0
                && services[i].log_state != STATE_RUNNING
                && t >= services[i].log_restart_at
                && !services[i].log_stopping
            {
                let s = &mut services[i];
                let mut log_run = Path::from_bytes(s.dir_bytes());
                log_run.push(b"/log/run");
                if unsafe { libc::access(log_run.as_ptr(), libc::X_OK) } == 0 {
                    let mut pipe_fds: [c_int; 2] = [-1, -1];
                    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } == 0 {
                        let pid = unsafe { libc::fork() };
                        if pid == 0 {
                            unsafe {
                                libc::setsid();
                                libc::dup2(pipe_fds[0], 0);
                                libc::close(pipe_fds[0]);
                                libc::close(pipe_fds[1]);
                                close_from(3);
                                libc::chdir(s.dir.as_ptr() as *const c_char);
                                let argv: [*const c_char; 2] = [log_run.as_ptr(), ptr::null()];
                                libc::execv(log_run.as_ptr(), argv.as_ptr());
                                libc::_exit(126);
                            }
                        } else if pid > 0 {
                            unsafe {
                                close_fd(pipe_fds[0]);
                                close_fd(pipe_fds[1]);
                            }
                            s.log_pid = pid;
                            s.log_state = STATE_RUNNING;
                            s.log_started_at = t;
                            s.log_restarts += 1;
                            s.log_restart_at = 0;
                        } else {
                            unsafe {
                                close_fd(pipe_fds[0]);
                                close_fd(pipe_fds[1]);
                            }
                        }
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
                    if drain_signal_pipe(sig_fd) {
                        shutdown = true;
                        break;
                    }
                } else if j == ctrl_idx {
                    let client = unsafe { libc::accept(ctrl_fd, ptr::null_mut(), ptr::null_mut()) };
                    if client >= 0 {
                        unsafe {
                            set_cloexec(client);
                        }
                        let mut cmd_buf = [0u8; CMD_BUF];
                        let nr = read_all_nonblock(client, &mut cmd_buf);
                        if nr > 0 {
                            handle_control_command(client, &cmd_buf[..nr as usize], services);
                        }
                        unsafe {
                            close_fd(client);
                        }
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
        let mut sock_path = Path::from_bytes(root.as_bytes());
        sock_path.push(SOCK_SUFFIX);
        libc::unlink(sock_path.as_ptr());
    }

    0
}
