// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The diag log budget's low-disk pause (diag plan A14).
//!
//! Below 100 MB free on the data directory's filesystem every diag writer
//! stops, except runs.log and crash.log, and runs.log says so once
//! (`diag-paused`); writing goes on once there is room again
//! (`diag-resumed`). The free space is sampled at start and on every A6
//! health tick; a writer only reads the flag, it never calls `statvfs`.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// Free bytes below which the diag writers stop
pub const FLOOR: u64 = 100 << 20;

static PAUSED: AtomicBool = AtomicBool::new(false);

/// Whether the diag writers other than runs.log and crash.log are stopped
pub fn paused() -> bool {
    PAUSED.load(Ordering::Relaxed)
}

/// The pause after a sample of `free` bytes, when it changes from `was`
fn transition(was: bool, free: u64) -> Option<bool> {
    let now = free < FLOOR;
    (now != was).then_some(now)
}

/// A sample of the free space on the data directory's filesystem
pub fn sample(free: u64) {
    let was = PAUSED.load(Ordering::Relaxed);
    let Some(now) = transition(was, free) else {
        return;
    };
    // One thread samples at a time (start, then the health tick); a lost
    // race would only repeat the record
    if PAUSED
        .compare_exchange(was, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    crate::runs_log::record(
        if now { "diag-paused" } else { "diag-resumed" },
        &format!(
            "reason=\"diag logs {}\" free_mb={} floor_mb={}",
            if now { "paused" } else { "resumed" },
            free >> 20,
            FLOOR >> 20
        ),
    );
}

/// Sample the free space under `dir` now (start-up, before the first tick)
pub fn sample_dir(dir: &Path) {
    if let Some(free) = free_bytes(dir) {
        sample(free);
    }
}

/// Free bytes for an unprivileged writer on `dir`'s filesystem
pub fn free_bytes(dir: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
            return None;
        }
        // c_ulong and fsblkcnt_t differ by target
        #[allow(clippy::unnecessary_cast)]
        Some(st.f_bavail as u64 * st.f_frsize as u64)
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pause_changes_only_across_the_floor() {
        assert_eq!(transition(false, FLOOR), None);
        assert_eq!(transition(false, FLOOR - 1), Some(true));
        assert_eq!(transition(true, FLOOR - 1), None);
        assert_eq!(transition(true, 0), None);
        assert_eq!(transition(true, FLOOR), Some(false));
        assert_eq!(transition(false, u64::MAX), None);
    }

    #[test]
    fn the_free_space_of_a_real_directory_is_read() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        assert!(free_bytes(dir.path()).is_some());
        #[cfg(not(unix))]
        assert!(free_bytes(dir.path()).is_none());
    }
}
