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
use crate::status::write_status_file;
use crate::types::*;
use crate::user::prepare_service_env;
use core::ffi::c_int;
use core::ptr;
use libc::{gid_t, pid_t};

pub fn deps_satisfied(s: &Service, services: &[Service]) -> bool {
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

pub fn find_service_by_name(services: &[Service], name: &[u8]) -> usize {
    for (i, s) in services.iter().enumerate() {
        if s.active && bytes_eq(s.name_bytes(), name) {
            return i;
        }
    }
    usize::MAX
}

pub fn find_service_by_dir(services: &[Service], dir: &CStrBuf) -> usize {
    for (i, s) in services.iter().enumerate() {
        if s.active && s.dir_bytes() == dir.as_bytes() {
            return i;
        }
    }
    usize::MAX
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

pub fn start_service(s: &mut Service) {
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
                        apply_security_restrictions(s);
                        if s.chroot_enabled {
                            if libc::chroot(s.dir.as_ptr() as *const core::ffi::c_char) != 0 {
                                libc::_exit(126);
                            }
                            libc::chdir(b"/\0".as_ptr() as *const core::ffi::c_char);
                            let rp = b"/log/run\0".as_ptr() as *const core::ffi::c_char;
                            let argv: [*const core::ffi::c_char; 2] = [rp, ptr::null()];
                            libc::execve(rp, argv.as_ptr(), s.env_ptrs.as_ptr());
                        } else {
                            libc::chdir(s.dir.as_ptr() as *const core::ffi::c_char);
                            let argv: [*const core::ffi::c_char; 2] =
                                [log_run.as_ptr(), ptr::null()];
                            libc::execve(log_run.as_ptr(), argv.as_ptr(), s.env_ptrs.as_ptr());
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
            apply_security_restrictions(s);
            if s.chroot_enabled {
                if libc::chroot(s.dir.as_ptr() as *const core::ffi::c_char) != 0 {
                    libc::_exit(126);
                }
                libc::chdir(b"/\0".as_ptr() as *const core::ffi::c_char);
            } else {
                libc::chdir(s.dir.as_ptr() as *const core::ffi::c_char);
            }
            if s.has_uid {
                if s.gid != 0 {
                    libc::setgid(s.gid as gid_t);
                    libc::setgroups(1, &(s.gid as gid_t) as *const gid_t);
                }
                libc::setuid(s.uid as libc::uid_t);
                if libc::getuid() != s.uid as libc::uid_t {
                    libc::_exit(125);
                }
            }
            let null = libc::open(
                DEV_NULL.as_ptr() as *const core::ffi::c_char,
                libc::O_RDONLY,
            );
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

            // FIX: Buffer lives until execve. No dangling pointer.
            let run_path_ptr: *const core::ffi::c_char;
            let mut run_buf = CStrBuf::new();
            if s.chroot_enabled {
                run_path_ptr = b"/run\0".as_ptr() as *const core::ffi::c_char;
            } else {
                run_buf = CStrBuf::from_bytes(s.dir_bytes());
                run_buf.push(b"/run");
                run_path_ptr = run_buf.as_ptr();
            }
            let argv: [*const core::ffi::c_char; 2] = [run_path_ptr, ptr::null()];
            libc::execve(run_path_ptr, argv.as_ptr(), s.env_ptrs.as_ptr());
            libc::_exit(127);
        }
    }

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

pub fn run_finish(s: &Service) {
    let mut finish_path = CStrBuf::from_bytes(s.dir_bytes());
    finish_path.push(b"/finish");
    if unsafe { libc::access(finish_path.as_ptr(), libc::X_OK) } != 0 {
        return;
    }

    let mut s_clone = *s;
    prepare_service_env(&mut s_clone);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            apply_security_restrictions(&s_clone);
            if s_clone.chroot_enabled {
                if libc::chroot(s_clone.dir.as_ptr() as *const core::ffi::c_char) != 0 {
                    libc::_exit(126);
                }
                libc::chdir(b"/\0".as_ptr() as *const core::ffi::c_char);
            } else {
                libc::chdir(s_clone.dir.as_ptr() as *const core::ffi::c_char);
            }
            if s_clone.has_uid {
                if s_clone.gid != 0 {
                    libc::setgid(s_clone.gid as gid_t);
                    libc::setgroups(1, &(s_clone.gid as gid_t) as *const gid_t);
                }
                libc::setuid(s_clone.uid as libc::uid_t);
                if libc::getuid() != s_clone.uid as libc::uid_t {
                    libc::_exit(125);
                }
            }
            let exit_str = format_i64_buf(s_clone.exit_code as i64);
            let sig_str = format_i64_buf(s_clone.term_signal as i64);

            let finish_ptr: *const core::ffi::c_char;
            let mut finish_buf = CStrBuf::new();
            if s_clone.chroot_enabled {
                finish_ptr = b"/finish\0".as_ptr() as *const core::ffi::c_char;
            } else {
                finish_buf = CStrBuf::from_bytes(s_clone.dir_bytes());
                finish_buf.push(b"/finish");
                finish_ptr = finish_buf.as_ptr();
            }
            let argv: [*const core::ffi::c_char; 4] = [
                finish_ptr,
                exit_str.as_ptr() as *const core::ffi::c_char,
                sig_str.as_ptr() as *const core::ffi::c_char,
                ptr::null(),
            ];
            libc::execve(finish_ptr, argv.as_ptr(), s_clone.env_ptrs.as_ptr());
            libc::_exit(127);
        }
    }
}

pub fn decode_wait_status(status: c_int) -> (u8, c_int, c_int) {
    if (status & 0x7f) == 0 {
        (STATE_EXITED, (status >> 8) & 0xff, 0)
    } else if (status & 0x7f) == 0x7f {
        (STATE_DOWN, 0, 0)
    } else {
        (STATE_SIGNALED, 0, status & 0x7f)
    }
}

pub fn stop_transitive_deps(services: &mut [Service]) {
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

pub fn stop_all_in_order(services: &mut [Service]) {
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

pub fn kill_main_on_log_death(services: &mut [Service]) {
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

pub fn any_open_services(services: &[Service]) -> bool {
    services.iter().any(|s| {
        s.active
            && (s.pid > 0
                || s.streams[0].read_fd >= 0
                || s.streams[1].read_fd >= 0
                || s.log_pid > 0)
    })
}

pub fn close_service_fds(s: &mut Service) {
    for stream in 0..2 {
        unsafe {
            close_fd(s.streams[stream].read_fd);
            close_fd(s.streams[stream].log_fd);
        }
        s.streams[stream].read_fd = -1;
        s.streams[stream].log_fd = -1;
    }
}

// --- Log rotation & draining ---

pub fn open_log(s: &mut Service, stream: usize) {
    let dir_path = CStrBuf::from_bytes(s.dir_bytes());
    let st = &mut s.streams[stream];
    unsafe { close_fd(st.log_fd) };
    st.log_fd = -1;
    let mut logdir = CStrBuf::from_bytes(dir_path.as_bytes());
    logdir.push(b"/log");
    unsafe { libc::mkdir(logdir.as_ptr(), 0o755 as libc::mode_t) };
    let mut path = CStrBuf::from_bytes(logdir.as_bytes());
    path.push(if stream == 0 {
        b"/current.out"
    } else {
        b"/current.err"
    });
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
    let dir_path = CStrBuf::from_bytes(s.dir_bytes());
    let st = &mut s.streams[stream];
    unsafe { close_fd(st.log_fd) };
    st.log_fd = -1;
    st.rotations += 1;
    let ts = wall_now();
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
    arch.push_u64(st.rotations as u64);
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
    let add_len = data.len() as libc::off_t;
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

pub fn drain_stream(s: &mut Service, stream: usize, buf: &mut [u8; IO_BUF]) {
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

pub fn drain_all_once(services: &mut [Service], buf: &mut [u8; IO_BUF]) {
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
