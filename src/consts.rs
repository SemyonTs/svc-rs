// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

pub const MAX_SERVICES: usize = 256;
pub const PATH_BUF: usize = 1024;
pub const NAME_BUF: usize = 64;
pub const IO_BUF: usize = 4096;
pub const CMD_BUF: usize = 512;
pub const RESP_BUF: usize = 8192;
pub const PASSWD_BUF: usize = 4096;
pub const GROUP_BUF: usize = 4096;
pub const ENV_BUF: usize = 4096;
pub const MAX_ENV_VARS: usize = 64;

pub const MAX_DEPENDENCIES: usize = 16;
pub const DEP_FILE_BUF: usize = 512;

pub const LOG_LIMIT: libc::off_t = 1_048_576;
pub const SUPERVISOR_LOG_LIMIT: libc::off_t = 1_048_576;
pub const POLL_TIMEOUT_MS: libc::c_int = 500;
pub const SHUTDOWN_TIMEOUT_S: i64 = 5;
pub const MAX_POLL_FDS: usize = MAX_SERVICES * 2 + 2;

pub const RESTART_WINDOW_S: i64 = 60;
pub const MAX_RESTARTS_IN_WINDOW: u32 = 5;
pub const BACKOFF_SHORT: i64 = 2;
pub const BACKOFF_MED: i64 = 10;
pub const BACKOFF_LONG: i64 = 60;

pub const DEV_NULL: &[u8] = b"/dev/null\0";
pub const SOCK_SUFFIX: &[u8] = b"/.control.sock";
pub const SUPERVISOR_LOG_PATH: &[u8] = b"/var/log/svc-rs.log\0";

pub const STATE_DOWN: u8 = 0;
pub const STATE_RUNNING: u8 = 1;
pub const STATE_EXITED: u8 = 2;
pub const STATE_SIGNALED: u8 = 3;
pub const STATE_FAILED: u8 = 4;
pub const STATE_STOPPING: u8 = 5;
