// =============================================================================
// svc-rs Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
// This Source Code Form is “Incompatible With Secondary Licenses”,
// as defined by the Mozilla Public License, v. 2.0.
// =============================================================================

use crate::consts::PATH_BUF;
use core::ffi::{CStr, c_char};

/// Safe, stack-allocated C-string builder.
/// Guarantees: no interior nulls, always null-terminated, no UB.
pub struct CStrBuf {
    buf: [u8; PATH_BUF],
    pub len: usize,
}

impl CStrBuf {
    pub fn new() -> Self {
        let mut s = Self {
            buf: [0; PATH_BUF],
            len: 0,
        };
        s.buf[0] = 0;
        s
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        let mut s = Self::new();
        s.push(b);
        s
    }

    pub fn push(&mut self, b: &[u8]) {
        for &c in b {
            self.push_byte(c);
        }
    }

    pub fn push_byte(&mut self, c: u8) {
        if c == 0 {
            return; // Prevent interior nulls
        }
        if self.len + 1 < PATH_BUF {
            self.buf[self.len] = c;
            self.len += 1;
            self.buf[self.len] = 0;
        }
    }

    pub fn push_u64(&mut self, mut v: u64) {
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

    pub fn push_i64(&mut self, v: i64) {
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

    pub fn as_ptr(&self) -> *const c_char {
        self.buf.as_ptr() as *const c_char
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Guaranteed safe: no interior nulls, always terminated.
    pub fn as_cstr(&self) -> &CStr {
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.buf[..=self.len]) }
    }
}
