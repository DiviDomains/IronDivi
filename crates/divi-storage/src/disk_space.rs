// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Divi Core's CheckDiskSpace (BlockDiskAccessor.cpp:13-25): at least 50 MB
//! must stay free on the data directory's filesystem, beyond what a write is
//! about to add. Below that the node aborts with "Disk space is low!": at
//! start (init.cpp:1604-1605), before it writes a block
//! (BlockFileHelpers.cpp:132-142) and before it flushes the coins
//! (FlushChainState.cpp:31-40).

use crate::error::StorageError;
use std::path::Path;

/// Divi Core's nMinDiskSpace: 50 MB (BlockDiskAccessor.cpp:17)
pub const MIN_DISK_SPACE: u64 = 52_428_800;

/// Bytes free to this process on the filesystem holding `dir`, or None when
/// the lookup fails
pub fn free_bytes(dir: &Path) -> Option<u64> {
    #[cfg(test)]
    if let Some(bytes) = FREE_FOR_TEST.with(|f| f.get()) {
        return Some(bytes);
    }
    statvfs_available(dir)
}

#[cfg(unix)]
fn statvfs_available(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    // boost::filesystem::space().available: blocks free to a non-root user
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(unix))]
fn statvfs_available(_dir: &Path) -> Option<u64> {
    None
}

/// True when `additional` bytes can be written to `dir` and 50 MB stay free.
/// A free space that cannot be read does not stop the node.
pub fn check_disk_space(dir: &Path, additional: u64) -> bool {
    match free_bytes(dir) {
        Some(free) => free >= MIN_DISK_SPACE.saturating_add(additional),
        None => true,
    }
}

/// Abort the node for low disk space, as Divi Core's state.Abort("Disk space
/// is low!") does; the error to return
pub fn disk_space_low() -> StorageError {
    crate::abort::abort_node("Disk space is low!");
    StorageError::ChainState("Disk space is low!".into())
}

#[cfg(test)]
thread_local! {
    static FREE_FOR_TEST: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Make this thread's free space lookups answer `bytes` (None: the real one)
#[cfg(test)]
pub(crate) fn set_free_for_test(bytes: Option<u64>) {
    FREE_FOR_TEST.with(|f| f.set(bytes));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifty_megabytes_must_stay_free() {
        let dir = Path::new(".");
        set_free_for_test(Some(MIN_DISK_SPACE));
        assert!(check_disk_space(dir, 0));
        assert!(!check_disk_space(dir, 1));
        set_free_for_test(Some(MIN_DISK_SPACE - 1));
        assert!(!check_disk_space(dir, 0));
        set_free_for_test(Some(MIN_DISK_SPACE + 1000));
        assert!(check_disk_space(dir, 1000));
        assert!(!check_disk_space(dir, 1001));
        set_free_for_test(None);
    }

    #[test]
    fn the_real_lookup_reads_the_filesystem() {
        assert!(free_bytes(Path::new(".")).is_some());
    }
}
