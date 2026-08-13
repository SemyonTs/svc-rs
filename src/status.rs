// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::consts::*;
use crate::fd::{mono_now, write_all};
use crate::path::CStrBuf;
use crate::types::Service;

pub fn write_status_file(s: &Service) {
    let mut p = CStrBuf::from_bytes(s.dir_bytes());
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
    let mut t = CStrBuf::new();
    t.push(b"name=");
    t.push(s.name_bytes());
    t.push(b"\npid=");
    t.push_i64(s.pid as i64);
    t.push(b"\nstate=");
    t.push(match s.state {
        STATE_RUNNING => b"running",
        STATE_EXITED => b"exited",
        STATE_SIGNALED => b"signaled",
        STATE_FAILED => b"failed",
        STATE_STOPPING => b"stopping",
        _ => b"down",
    });
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

pub fn format_service_status(s: &Service, now: i64, buf: &mut [u8; RESP_BUF]) -> usize {
    let mut p = CStrBuf::new();
    p.push(s.name_bytes());
    p.push(b" state=");
    p.push(match s.state {
        STATE_RUNNING => b"running",
        STATE_EXITED => b"exited",
        STATE_SIGNALED => b"signaled",
        STATE_FAILED => b"failed",
        STATE_STOPPING => b"stopping",
        _ => b"down",
    });
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
        p.push(match s.log_state {
            STATE_RUNNING => b"running",
            _ => b"down",
        });
        p.push(b" log_uptime=");
        p.push_i64(s.log_uptime_seconds(now));
    }
    p.push(b"\n");
    let out = p.as_bytes();
    let copy_len = core::cmp::min(out.len(), buf.len());
    buf[..copy_len].copy_from_slice(&out[..copy_len]);
    copy_len
}

pub fn format_error(buf: &mut [u8; RESP_BUF], msg: &[u8]) -> usize {
    let prefix = b"ERROR: ";
    let total = prefix.len() + msg.len();
    let copy = core::cmp::min(total, buf.len());
    for i in 0..copy {
        buf[i] = if i < prefix.len() {
            prefix[i]
        } else {
            msg[i - prefix.len()]
        };
    }
    copy
}

pub fn format_ok(buf: &mut [u8; RESP_BUF], msg: &[u8]) -> usize {
    let prefix = b"OK: ";
    let total = prefix.len() + msg.len();
    let copy = core::cmp::min(total, buf.len());
    for i in 0..copy {
        buf[i] = if i < prefix.len() {
            prefix[i]
        } else {
            msg[i - prefix.len()]
        };
    }
    copy
}
