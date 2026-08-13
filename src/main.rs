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

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

mod consts;
mod ctrl;
mod fd;
mod log;
mod path;
mod scan;
mod security;
mod service;
mod signal;
mod status;
mod types;
mod user;

use consts::*;
use ctrl::*;
use fd::*;
use log::{supervisor_log, supervisor_log_fd, supervisor_log_init};
use path::CStrBuf;
use scan::*;
use service::*;
use signal::*;
use types::*;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { libc::_exit(101) }
}

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
            if scan_services(&root, services) {
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

        // Build pollfd array
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

        let r = unsafe { libc::poll(pfds.as_mut_ptr(), n as libc::nfds_t, POLL_TIMEOUT_MS) };
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

    // Shutdown
    supervisor_log(b"shutting down services");
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
            crate::status::write_status_file(s);
        }
    }
    supervisor_log(b"shutdown complete");

    unsafe {
        close_fd(ctrl_fd);
        let mut sock_path = CStrBuf::from_bytes(root.as_bytes());
        sock_path.push(SOCK_SUFFIX);
        libc::unlink(sock_path.as_ptr());
        close_fd(supervisor_log_fd());
    }
    0
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
                        let delay = if s.restarts < 5 {
                            BACKOFF_SHORT
                        } else if s.restarts < 20 {
                            BACKOFF_MED
                        } else {
                            BACKOFF_LONG
                        };
                        s.restart_at = t + delay;
                    }
                }
                crate::status::write_status_file(s);
                break;
            }
        }
    }
    if need_stop_deps {
        stop_transitive_deps(services);
    }
    kill_main_on_log_death(services);
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
