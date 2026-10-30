// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! File modes for what the daemon writes.
//!
//! The datadir holds the wallet, the RPC cookie and debug.log, so nothing in it is for other
//! local users. As Divi Core does (umask 077 unless -sysperms), everything the process creates
//! is private to its owner; directories that already exist are checked and reported.

use std::io::{self, Write};
use std::path::Path;
use tracing::warn;

/// Make every file and directory this process creates private to its owner (Core's
/// `umask(077)`). Call first, before anything is written.
pub fn restrict_umask() {
    #[cfg(unix)]
    // SAFETY: umask only swaps the process file-mode mask.
    unsafe {
        libc::umask(0o077);
    }
}

/// Stop the process from writing core dumps, which would hold unlocked wallet keys
/// (NODE-10). Call first, before the wallet is opened.
pub fn disable_core_dumps() -> io::Result<()> {
    #[cfg(unix)]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads the struct passed by reference and changes only this process.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // A pipe core_pattern (systemd-coredump passes its own size limit) is run whatever
    // RLIMIT_CORE says, and stores the core; the kernel does not hand a non-dumpable
    // process to it. This also makes /proc/<pid> root-owned and blocks same-user ptrace.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: PR_SET_DUMPABLE takes only integer arguments and changes only this process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Create `dir` with mode 0700 if it is missing. If it exists and other users can read or
/// enter it, warn, and with `tighten` set it to 0700. Returns whether it was loose.
pub fn ensure_private_dir(dir: &Path, tighten: bool) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            return Ok(false);
        }
        let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode & 0o077 == 0 {
            return Ok(false);
        }
        if tighten {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            warn!(
                "{:?} was readable by other users (mode {:o}); set it to 700",
                dir, mode
            );
        } else {
            warn!(
                "{:?} is readable by other users (mode {:o}); run chmod 700 on it",
                dir, mode
            );
        }
        Ok(true)
    }
    #[cfg(not(unix))]
    {
        let _ = tighten;
        std::fs::create_dir_all(dir)?;
        Ok(false)
    }
}

/// Set an existing file this process owns, such as debug.log, to mode 0600.
pub fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Write `contents` to `path` atomically with mode 0600: a temporary file next to it is
/// written, synced and renamed into place, so a reader or a crash never sees half a file.
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = tempfile::Builder::new()
        .prefix(".tmp-")
        .tempfile_in(dir.unwrap_or_else(|| Path::new(".")))?;
    // tempfile creates the file with mode 0600
    tmp.write_all(contents)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn node03_new_dirs_are_private_and_loose_ones_are_reported() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();

        let fresh = root.path().join("a/b/wallet");
        assert!(!ensure_private_dir(&fresh, false).unwrap());
        assert_eq!(mode(&fresh), 0o700);

        let loose = root.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Only warned about
        assert!(ensure_private_dir(&loose, false).unwrap());
        assert_eq!(mode(&loose), 0o755);
        // Tightened
        assert!(ensure_private_dir(&loose, true).unwrap());
        assert_eq!(mode(&loose), 0o700);
        assert!(!ensure_private_dir(&loose, true).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn node23_existing_log_file_is_made_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let log = root.path().join("debug.log");
        std::fs::write(&log, b"x").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        restrict_file(&log);
        assert_eq!(mode(&log), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn node10_core_dumps_are_disabled() {
        disable_core_dumps().unwrap();
        let mut lim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes into the struct passed by reference.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) }, 0);
        assert_eq!(lim.rlim_cur, 0);
        assert_eq!(lim.rlim_max, 0);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: PR_GET_DUMPABLE takes no pointers.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }

    #[test]
    fn node23_pid_file_is_written_atomically_and_privately() {
        let root = tempfile::tempdir().unwrap();
        let pid = root.path().join("irondivid.pid");
        std::fs::write(&pid, b"old contents that are longer").unwrap();
        write_private_atomic(&pid, b"4242").unwrap();
        assert_eq!(std::fs::read(&pid).unwrap(), b"4242");
        #[cfg(unix)]
        assert_eq!(mode(&pid), 0o600);
        // No temporary file is left behind
        let names: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("irondivid.pid")]);
    }
}
