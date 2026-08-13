// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::consts::*;
use crate::path::CStrBuf;
use core::ffi::c_int;
use core::ptr;
use libc::{gid_t, off_t, pid_t, uid_t};

#[derive(Clone, Copy)]
pub struct Dependency {
    pub name: [u8; NAME_BUF],
    pub name_len: usize,
    pub soft: bool,
}

pub const DEP_EMPTY: Dependency = Dependency {
    name: [0; NAME_BUF],
    name_len: 0,
    soft: false,
};

#[derive(Clone, Copy)]
pub struct Stream {
    pub read_fd: c_int,
    pub log_fd: c_int,
    pub log_len: off_t,
    pub rotations: u32,
}

pub const STREAM_EMPTY: Stream = Stream {
    read_fd: -1,
    log_fd: -1,
    log_len: 0,
    rotations: 0,
};

#[derive(Clone, Copy)]
pub struct Service {
    pub active: bool,
    pub present: bool,
    pub stopping: bool,
    pub manual_start: bool,
    pub name: [u8; NAME_BUF],
    pub name_len: usize,
    pub dir: [u8; PATH_BUF],
    pub dir_len: usize,
    pub pid: pid_t,
    pub streams: [Stream; 2],
    pub restart_at: i64,
    pub started_at: i64,
    pub restarts: u32,
    pub last_status: c_int,
    pub state: u8,
    pub exit_code: c_int,
    pub term_signal: c_int,
    pub auto_start: bool,
    pub once: bool,
    pub deps: [Dependency; MAX_DEPENDENCIES],
    pub deps_count: usize,
    pub has_log: bool,
    pub log_pid: pid_t,
    pub log_state: u8,
    pub log_started_at: i64,
    pub log_stopping: bool,
    pub uid: uid_t,
    pub gid: gid_t,
    pub has_uid: bool,
    pub env_buf: [u8; ENV_BUF],
    pub env_ptrs: [*const core::ffi::c_char; MAX_ENV_VARS + 1],
    pub env_count: usize,
    pub chroot_enabled: bool,
}

pub const SERVICE_EMPTY: Service = Service {
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
    pub fn dir_bytes(&self) -> &[u8] {
        &self.dir[..self.dir_len]
    }
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn set_dir(&mut self, p: &CStrBuf) {
        self.dir_len = p.len;
        self.dir[..p.len].copy_from_slice(p.as_bytes());
        self.dir[p.len] = 0;
    }

    pub fn set_name(&mut self, b: &[u8]) {
        let n = core::cmp::min(b.len(), NAME_BUF - 1);
        self.name_len = n;
        self.name[..n].copy_from_slice(&b[..n]);
        self.name[n] = 0;
    }

    pub fn uptime_seconds(&self, now: i64) -> i64 {
        if self.state == STATE_RUNNING && self.started_at > 0 {
            now - self.started_at
        } else {
            0
        }
    }

    pub fn log_uptime_seconds(&self, now: i64) -> i64 {
        if self.log_state == STATE_RUNNING && self.log_started_at > 0 {
            now - self.log_started_at
        } else {
            0
        }
    }
}
