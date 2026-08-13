// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::consts::*;
use crate::fd::*;
use crate::log::supervisor_log;
use crate::path::CStrBuf;
use crate::security::apply_security_restrictions;
use crate::service::*;
use crate::status::*;
use crate::types::*;
use crate::user::prepare_service_env;
use core::ffi::c_int;
use core::ptr;

/// Create control socket with TOCTOU-safe permissions.
///
/// # Safety
/// Creates filesystem socket.
pub unsafe fn create_control_socket(root: &CStrBuf) -> c_int {
    let mut sock_path = CStrBuf::from_bytes(root.as_bytes());
    sock_path.push(SOCK_SUFFIX);
    libc::unlink(sock_path.as_ptr());

    let old_umask = libc::umask(0o077);
    let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        libc::umask(old_umask);
        return -1;
    }

    let mut addr: libc::sockaddr_un = core::mem::zeroed();
    addr.sun_family = libc::AF_UNIX as u16;
    let path_bytes = sock_path.as_bytes();
    let max_len = core::mem::size_of_val(&addr.sun_path) - 1;
    let copy_len = core::cmp::min(path_bytes.len(), max_len);
    for i in 0..copy_len {
        addr.sun_path[i] = path_bytes[i] as core::ffi::c_char;
    }
    addr.sun_path[copy_len] = 0;
    let addr_len =
        (core::mem::size_of::<libc::sockaddr_un>() - max_len + copy_len + 1) as libc::socklen_t;

    if libc::bind(
        fd,
        &addr as *const libc::sockaddr_un as *const libc::sockaddr,
        addr_len,
    ) < 0
    {
        close_fd(fd);
        libc::umask(old_umask);
        return -1;
    }
    libc::umask(old_umask);
    libc::chmod(sock_path.as_ptr(), 0o660);
    if libc::listen(fd, 5) < 0 {
        close_fd(fd);
        return -1;
    }
    set_nonblock(fd);
    fd
}

fn split_cmd(line: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i < line.len() && !matches!(line[i], b' ' | b'\n' | b'\r') {
        i += 1;
    }
    let cmd = &line[..i];
    let mut rs = i;
    while rs < line.len() && matches!(line[rs], b' ' | b'\n' | b'\r') {
        rs += 1;
    }
    let mut re = line.len();
    while re > rs && matches!(line[re - 1], b'\n' | b'\r' | b' ') {
        re -= 1;
    }
    (cmd, &line[rs..re])
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

fn handle_signal_command(client_fd: c_int, sig_name: &[u8], arg: &[u8], services: &mut [Service]) {
    let sig = signal_from_name(sig_name);
    if sig == 0 {
        let mut r = [0u8; RESP_BUF];
        let l = format_error(&mut r, b"unknown signal\n");
        write_all(client_fd, &r[..l]);
        return;
    }
    if arg.is_empty() {
        let mut r = [0u8; RESP_BUF];
        let l = format_error(&mut r, b"usage: <signal> <name>\n");
        write_all(client_fd, &r[..l]);
        return;
    }
    let idx = find_service_by_name(services, arg);
    if idx == usize::MAX {
        let mut r = [0u8; RESP_BUF];
        let l = format_error(&mut r, b"service not found\n");
        write_all(client_fd, &r[..l]);
        return;
    }
    if services[idx].pid <= 0 {
        let mut r = [0u8; RESP_BUF];
        let l = format_error(&mut r, b"service not running\n");
        write_all(client_fd, &r[..l]);
        return;
    }
    unsafe { libc::kill(-services[idx].pid, sig) };
    let mut r = [0u8; RESP_BUF];
    let l = format_ok(&mut r, b"signal sent\n");
    write_all(client_fd, &r[..l]);
}

pub fn handle_control_command(client_fd: c_int, cmd_line: &[u8], services: &mut [Service]) {
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
                let mut dp = CStrBuf::from_bytes(s.dir_bytes());
                dp.push(b"/down");
                unsafe {
                    let fd = libc::open(
                        dp.as_ptr(),
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
                let mut dp = CStrBuf::from_bytes(s.dir_bytes());
                dp.push(b"/down");
                unsafe { libc::unlink(dp.as_ptr()) };
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
                let mut op = CStrBuf::from_bytes(s.dir_bytes());
                op.push(b"/once");
                unsafe {
                    let fd = libc::open(
                        op.as_ptr(),
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
                            apply_security_restrictions(&s_clone);
                            if s_clone.chroot_enabled {
                                if libc::chroot(s_clone.dir.as_ptr() as *const core::ffi::c_char)
                                    != 0
                                {
                                    libc::_exit(126);
                                }
                                libc::chdir(b"/\0".as_ptr() as *const core::ffi::c_char);
                            } else {
                                libc::chdir(s_clone.dir.as_ptr() as *const core::ffi::c_char);
                            }
                            if s_clone.has_uid {
                                if s_clone.gid != 0 {
                                    libc::setgid(s_clone.gid as libc::gid_t);
                                    libc::setgroups(
                                        1,
                                        &(s_clone.gid as libc::gid_t) as *const libc::gid_t,
                                    );
                                }
                                libc::setuid(s_clone.uid as libc::uid_t);
                                if libc::getuid() != s_clone.uid as libc::uid_t {
                                    libc::_exit(125);
                                }
                            }
                            let cp: *const core::ffi::c_char;
                            let mut cb = CStrBuf::new();
                            if s_clone.chroot_enabled {
                                cp = b"/check\0".as_ptr() as *const core::ffi::c_char;
                            } else {
                                cb = CStrBuf::from_bytes(s_clone.dir_bytes());
                                cb.push(b"/check");
                                cp = cb.as_ptr();
                            }
                            let argv: [*const core::ffi::c_char; 2] = [cp, ptr::null()];
                            libc::execve(cp, argv.as_ptr(), s_clone.env_ptrs.as_ptr());
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
            let mut r = [0u8; RESP_BUF];
            let l = format_error(&mut r, b"usage: signal <name> <signum>\n");
            write_all(client_fd, &r[..l]);
            return;
        }
        let (svc_name, sig_num_part) = split_cmd(arg);
        if svc_name.is_empty() || sig_num_part.is_empty() {
            let mut r = [0u8; RESP_BUF];
            let l = format_error(&mut r, b"usage: signal <name> <signum>\n");
            write_all(client_fd, &r[..l]);
            return;
        }
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
            let mut r = [0u8; RESP_BUF];
            let l = format_error(&mut r, b"invalid signal number\n");
            write_all(client_fd, &r[..l]);
            return;
        }
        let signum = signum.unwrap();
        let idx = find_service_by_name(services, svc_name);
        if idx == usize::MAX {
            let mut r = [0u8; RESP_BUF];
            let l = format_error(&mut r, b"service not found\n");
            write_all(client_fd, &r[..l]);
            return;
        }
        if services[idx].pid <= 0 {
            let mut r = [0u8; RESP_BUF];
            let l = format_error(&mut r, b"service not running\n");
            write_all(client_fd, &r[..l]);
            return;
        }
        unsafe { libc::kill(-services[idx].pid, signum) };
        let mut r = [0u8; RESP_BUF];
        let l = format_ok(&mut r, b"signal sent\n");
        write_all(client_fd, &r[..l]);
        return;
    } else {
        resp_len = format_error(&mut resp, b"unknown command. use: list|stat|status|start|stop|restart|down|up|once|check|reload|signal|hup|term|kill|usr1|usr2|int|quit|alrm|cont\n");
    }
    write_all(client_fd, &resp[..resp_len]);
}
