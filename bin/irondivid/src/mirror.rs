// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The diag mirror directory and the path record (diag plan A14).
//!
//! runs.log, the last 256 KB of crash.log and the last 1 MB of events.log
//! are also kept outside the data directory, in `<root>/<id>/`, so they
//! outlive a lost or full data directory. `<root>` is the first writable
//! candidate on another filesystem than the data directory:
//!
//! 1. `~/Library/Logs/IronDivi` on macOS; `/var/log/irondivi` as root on
//!    Linux; else `$XDG_STATE_HOME/irondivi` (`~/.local/state/irondivi`)
//! 2. `$XDG_STATE_HOME/irondivi` as root
//! 3. `/var/tmp/irondivi-<uid>`
//!
//! When every candidate shares the data directory's filesystem the first
//! writable one is used and the start record says `mirror-same-fs=yes`;
//! with none, `mirror=unavailable`. A candidate that exists counts only as
//! a real directory (not a symlink) owned by this user: `/var/tmp` is
//! shared.
//!
//! `<id>` is the first 16 hex digits of the sha256 of the canonical data
//! directory path. `<root>/<id>/running/<pid>` (0600, in a 0700 directory)
//! is the path record a diag run uses to find a running node's data
//! directory and config file: `key=value` lines `datadir`, `conf`, `cwd`,
//! `exe`, `pid`, `start` and `uid`. It is removed when the node exits.

#[cfg(unix)]
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// What `open` found
pub enum Status {
    At { dir: PathBuf, same_fs: bool },
    Unavailable,
}

static STATUS: OnceLock<Status> = OnceLock::new();
/// `running/<pid>`, for the exit paths (the signal handler's too)
#[cfg(unix)]
static RECORD: OnceLock<CString> = OnceLock::new();

/// `<root>/<id>`, when there is one
pub fn dir() -> Option<&'static Path> {
    match STATUS.get()? {
        Status::At { dir, .. } => Some(dir),
        Status::Unavailable => None,
    }
}

/// The start record's mirror field: ` mirror-same-fs=yes|no`, or
/// ` mirror=unavailable`; empty before `open`
pub fn start_field() -> &'static str {
    match STATUS.get() {
        Some(Status::At { same_fs: true, .. }) => " mirror-same-fs=yes",
        Some(Status::At { same_fs: false, .. }) => " mirror-same-fs=no",
        Some(Status::Unavailable) => " mirror=unavailable",
        None => "",
    }
}

/// Whether `open` found no writable mirror
pub fn unavailable() -> bool {
    matches!(STATUS.get(), Some(Status::Unavailable))
}

/// Choose the mirror for `data_dir`, write the path record and point the
/// events.log mirror at it. Called once, after the -daemon forks and before
/// runs.log is opened (which mirrors itself through [`dir`]).
pub fn open(data_dir: &Path, conf: &Path) {
    #[cfg(unix)]
    {
        let status = choose_and_create(data_dir);
        if let Status::At { dir, .. } = &status {
            crate::events::set_mirror_dir(dir);
            write_record(dir, data_dir, conf);
        }
        let _ = STATUS.set(status);
    }
    #[cfg(not(unix))]
    {
        let _ = (data_dir, conf);
        let _ = STATUS.set(Status::Unavailable);
    }
}

/// The data directory's id: 16 hex digits of the sha256 of its canonical path
pub fn id_of(data_dir: &Path) -> String {
    let canon = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        canon.as_os_str().as_bytes()
    };
    #[cfg(not(unix))]
    let bytes = canon.as_os_str().as_encoded_bytes();
    hex::encode(divi_crypto::sha256(bytes))[..16].to_string()
}

#[cfg(unix)]
fn is_temp_datadir(data_dir: &Path) -> bool {
    let canon = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let tmp = std::env::temp_dir();
    let tmp_canon = std::fs::canonicalize(&tmp).unwrap_or_else(|_| tmp.clone());
    for p in [data_dir, canon.as_path()] {
        if p.starts_with(&tmp)
            || p.starts_with(&tmp_canon)
            || p.starts_with("/tmp")
            || p.starts_with("/private/tmp")
            || p.starts_with("/var/tmp")
        {
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn candidates(data_dir: &Path) -> Vec<PathBuf> {
    if let Some(root) = std::env::var_os("IRONDIVI_TEST_MIRROR_ROOT").filter(|p| !p.is_empty()) {
        return vec![PathBuf::from(root)];
    }
    let uid = unsafe { libc::getuid() };
    if std::env::var_os("CARGO").is_some() && is_temp_datadir(data_dir) {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME")
            .filter(|x| Path::new(x).is_absolute() && is_temp_datadir(Path::new(x)))
        {
            return vec![PathBuf::from(xdg).join("irondivi")];
        }
        return vec![std::env::temp_dir().join(format!("irondivi-test-mirror-{}", uid))];
    }
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from);
    let xdg = std::env::var_os("XDG_STATE_HOME")
        .filter(|x| Path::new(x).is_absolute())
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".local/state")))
        .map(|x| x.join("irondivi"));
    let mut out = Vec::new();
    if cfg!(target_os = "macos") {
        out.extend(home.as_ref().map(|h| h.join("Library/Logs/IronDivi")));
        if uid == 0 {
            out.extend(xdg);
        }
    } else if uid == 0 {
        out.push(PathBuf::from("/var/log/irondivi"));
        out.extend(xdg);
    } else {
        out.extend(xdg);
    }
    out.push(PathBuf::from(format!("/var/tmp/irondivi-{}", uid)));
    out
}

/// The first candidate whose device differs from `data_dev`, else the first
/// usable one with `same_fs`; `None` for an unusable candidate
#[cfg(any(unix, test))]
fn choose(devs: &[Option<u64>], data_dev: u64) -> Option<(usize, bool)> {
    if let Some(i) = devs.iter().position(|d| d.is_some_and(|d| d != data_dev)) {
        return Some((i, false));
    }
    devs.iter().position(Option::is_some).map(|i| (i, true))
}

/// The device a candidate root would be on: its own when it exists (a real
/// directory owned by us), else its nearest existing ancestor's when that
/// can be written; `None` when it cannot be used
#[cfg(unix)]
fn probe(root: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = std::fs::symlink_metadata(root) {
        let ours = meta.uid() == unsafe { libc::getuid() };
        return (meta.is_dir() && ours && writable(root)).then_some(meta.dev());
    }
    let mut up = root.parent();
    while let Some(p) = up {
        if let Ok(meta) = std::fs::metadata(p) {
            return (meta.is_dir() && writable(p)).then_some(meta.dev());
        }
        up = p.parent();
    }
    None
}

#[cfg(unix)]
fn writable(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    CString::new(dir.as_os_str().as_bytes())
        .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) } == 0)
}

#[cfg(unix)]
fn choose_and_create(data_dir: &Path) -> Status {
    use std::os::unix::fs::MetadataExt;
    let Ok(data_dev) = std::fs::metadata(data_dir).map(|m| m.dev()) else {
        return Status::Unavailable;
    };
    let roots = candidates(data_dir);
    let mut devs: Vec<Option<u64>> = roots.iter().map(|r| probe(r)).collect();
    let id = id_of(data_dir);
    while let Some((i, same_fs)) = choose(&devs, data_dev) {
        let dir = roots[i].join(&id);
        if create(&roots[i], &dir) {
            return Status::At { dir, same_fs };
        }
        devs[i] = None;
    }
    Status::Unavailable
}

/// Create `<root>/<id>/running`, each 0700; the root must end up a real
/// directory owned by us
#[cfg(unix)]
fn create(root: &Path, dir: &Path) -> bool {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !root.exists()
        && std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .is_err()
    {
        return false;
    }
    let ok = std::fs::symlink_metadata(root)
        .is_ok_and(|m| m.is_dir() && m.uid() == unsafe { libc::getuid() });
    ok && crate::private_files::ensure_private_dir(dir, true).is_ok()
        && crate::private_files::ensure_private_dir(&dir.join("running"), true).is_ok()
}

/// Write `<dir>/running/<pid>` through a temporary file, and drop the
/// records of this data directory's runs whose process is gone
#[cfg(unix)]
fn write_record(dir: &Path, data_dir: &Path, conf: &Path) {
    let running = dir.join("running");
    prune(&running);
    let pid = std::process::id();
    let text = record_text(data_dir, conf, pid);
    let path = running.join(pid.to_string());
    if crate::private_files::write_private_atomic(&path, text.as_bytes()).is_ok() {
        use std::os::unix::ffi::OsStrExt;
        if let Ok(c) = CString::new(path.as_os_str().as_bytes()) {
            let _ = RECORD.set(c);
        }
    }
}

#[cfg(unix)]
fn record_text(data_dir: &Path, conf: &Path, pid: u32) -> String {
    let one = |p: &Path| p.display().to_string().replace('\n', "?");
    let canon = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let conf = if conf.is_absolute() {
        conf.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| conf.to_path_buf(), |d| d.join(conf))
    };
    let mut s = format!("datadir={}\nconf={}\n", one(&canon), one(&conf));
    if let Some(cwd) = crate::startup::start_cwd().filter(|c| !c.starts_with("unreadable")) {
        s.push_str(&format!("cwd={}\n", cwd.replace('\n', "?")));
    }
    let exe = std::fs::read_link("/proc/self/exe").or_else(|_| std::env::current_exe());
    if let Ok(exe) = exe {
        s.push_str(&format!("exe={}\n", one(&exe)));
    }
    s.push_str(&format!(
        "pid={}\nstart={}\nuid={}\n",
        pid,
        own_start(),
        unsafe { libc::getuid() }
    ));
    s
}

/// This process's start: `/proc/self/stat` field 22 (clock ticks since
/// boot) on Linux, the launch time in unix seconds elsewhere
#[cfg(unix)]
fn own_start() -> String {
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| stat_start(&s))
        .unwrap_or_else(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            now.saturating_sub(crate::runs_log::since_launch())
                .as_secs()
                .to_string()
        })
}

/// Field 22 (`starttime`) of a `/proc/<pid>/stat` line
#[cfg(unix)]
fn stat_start(stat: &str) -> Option<String> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19).map(str::to_string)
}

/// Remove the records in `running` whose process is gone (or, on Linux,
/// is another process with the same pid). Only this data directory's.
#[cfg(unix)]
fn prune(running: &Path) {
    let Ok(entries) = std::fs::read_dir(running) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue;
        };
        if pid <= 0 || !gone(pid, &e.path()) {
            continue;
        }
        let _ = std::fs::remove_file(e.path());
    }
}

#[cfg(unix)]
fn gone(pid: i32, record: &Path) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    {
        return true;
    }
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) else {
        return false;
    };
    let kept = std::fs::read_to_string(record).unwrap_or_default();
    let kept = kept.lines().find_map(|l| l.strip_prefix("start="));
    matches!((kept, stat_start(&stat)), (Some(k), Some(now)) if k != now)
}

/// Remove this run's path record (every exit path; async-signal-safe)
pub fn remove_record() {
    #[cfg(unix)]
    if let Some(c) = RECORD.get() {
        unsafe { libc::unlink(c.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_other_filesystem_wins_else_the_first_usable_one() {
        assert_eq!(choose(&[Some(1), Some(2), Some(3)], 1), Some((1, false)));
        assert_eq!(choose(&[None, Some(2)], 1), Some((1, false)));
        assert_eq!(choose(&[Some(1), Some(1)], 1), Some((0, true)));
        assert_eq!(choose(&[None, Some(1)], 1), Some((1, true)));
        assert_eq!(choose(&[None, None], 1), None);
        assert_eq!(choose(&[], 1), None);
    }

    #[test]
    fn a_symlinked_or_foreign_candidate_is_not_used() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(probe(&real).is_some());
        assert!(probe(&link).is_none());
        // Missing: the nearest existing ancestor's device
        assert_eq!(probe(&dir.path().join("a/b")), probe(&real));
        if unsafe { libc::getuid() } != 0 {
            assert!(probe(Path::new("/")).is_none());
        }
    }

    #[test]
    fn the_path_record_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let text = record_text(&data, &data.join("divi.conf"), 4242);
        let get = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
                .unwrap_or("")
                .to_string()
        };
        assert_eq!(
            get("datadir"),
            std::fs::canonicalize(&data).unwrap().display().to_string()
        );
        assert!(get("conf").ends_with("divi.conf"));
        assert_eq!(get("pid"), "4242");
        assert!(get("start").parse::<u64>().is_ok(), "{text}");
        assert_eq!(get("uid"), unsafe { libc::getuid() }.to_string());
        assert!(!get("exe").is_empty());
        assert_eq!(id_of(&data).len(), 16);
        assert_eq!(id_of(&data), id_of(&data.join("..").join("data")));
    }

    #[test]
    fn a_dead_record_is_pruned_and_a_live_one_kept() {
        let dir = tempfile::tempdir().unwrap();
        let me = std::process::id();
        std::fs::write(
            dir.path().join(me.to_string()),
            format!("pid={}\nstart={}\n", me, own_start()),
        )
        .unwrap();
        // Above the default pid_max: no such process
        std::fs::write(dir.path().join("2147483000"), "pid=2147483000\n").unwrap();
        std::fs::write(dir.path().join("notes"), "").unwrap();
        prune(dir.path());
        assert!(dir.path().join(me.to_string()).exists());
        assert!(!dir.path().join("2147483000").exists());
        assert!(dir.path().join("notes").exists());
    }

    #[test]
    fn the_start_is_stat_field_22() {
        let line = "42 (a b) c) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 19";
        assert_eq!(stat_start(line).as_deref(), Some("777"));
    }

    #[test]
    fn cargo_test_temp_datadir_isolates_mirror_outside_user_state() {
        let dir = tempfile::tempdir().unwrap();
        let roots = candidates(dir.path());
        assert_eq!(roots.len(), 1, "{roots:?}");
        assert!(
            is_temp_datadir(&roots[0]),
            "expected temp mirror root under cargo test, got {roots:?}"
        );
        assert!(
            !roots[0].to_string_lossy().contains(".local/state/irondivi"),
            "{roots:?}"
        );
    }
}
