// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The append-only logs in `<datadir>/diag` besides runs.log and crash.log:
//! `events.log` and `chain-events.log` (A12: state transitions, written and
//! fdatasynced one record at a time, 4 MB × 2 each) and `health.log` (A6:
//! written, not synced, 1 MB × 5).
//!
//! A record is `<time> mono=<s> <kind> run=<n> <fields>`, as in runs.log.
//! Nothing is written until the data directory is known; a write error is
//! ignored (the node goes on). A writer never panics: the panic hook calls
//! it. A record asked for while the same thread is writing (a panic inside
//! the writer) is dropped rather than waiting on itself.
//!
//! A14: nothing is written while the low-disk pause is on
//! ([`crate::budget`]), and the last 1 MB of events.log is also kept in
//! the mirror directory ([`crate::mirror`]), written first.

use std::cell::Cell;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// One rotated log in `<datadir>/diag`
pub struct Log {
    name: &'static str,
    /// Bytes before the file is rotated
    cap: u64,
    /// Files kept, the current one included
    keep: usize,
    /// fdatasync after each record
    durable: bool,
    /// A copy written first, in the A14 mirror directory
    mirror: Option<&'static Log>,
    state: Mutex<Option<Open>>,
}

struct Open {
    path: PathBuf,
    file: Option<File>,
    size: u64,
}

thread_local! {
    /// This thread is inside a writer
    static WRITING: Cell<bool> = const { Cell::new(false) };
}

/// State transitions (A12)
pub static EVENTS: Log = Log::mirrored("events.log", 4 << 20, 2, true, &EVENTS_MIRROR);
/// The last 1 MB of events.log, in the mirror directory (A14)
static EVENTS_MIRROR: Log = Log::new("events.log", 512 << 10, 2, true);
/// Chain transitions: stalls for now (A12)
pub static CHAIN_EVENTS: Log = Log::new("chain-events.log", 4 << 20, 2, true);
/// One line per tick (A6)
pub static HEALTH: Log = Log::new("health.log", 1 << 20, 5, false);

impl Log {
    pub(crate) const fn new(name: &'static str, cap: u64, keep: usize, durable: bool) -> Self {
        Log {
            name,
            cap,
            keep,
            durable,
            mirror: None,
            state: Mutex::new(None),
        }
    }

    /// A log that writes `mirror` first
    pub(crate) const fn mirrored(
        name: &'static str,
        cap: u64,
        keep: usize,
        durable: bool,
        mirror: &'static Log,
    ) -> Self {
        Log {
            name,
            cap,
            keep,
            durable,
            mirror: Some(mirror),
            state: Mutex::new(None),
        }
    }

    pub(crate) fn set_dir(&self, diag: &Path) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.is_none() {
            *state = Some(Open {
                path: diag.join(self.name),
                file: None,
                size: 0,
            });
        }
    }

    /// Write one record of `kind`
    pub fn record(&self, kind: &str, fields: &str) {
        let line = format!(
            "{} mono={} {} run={} {}\n",
            crate::runs_log::utc_now(),
            crate::runs_log::mono_now(),
            kind,
            crate::runs_log::run_number(),
            fields
        );
        self.write_line(line.as_bytes());
    }

    fn write_line(&self, line: &[u8]) {
        self.write_gated(line, crate::budget::paused());
    }

    /// `write_line` with the pause given (the tests' way past the global)
    fn write_gated(&self, line: &[u8], paused: bool) {
        if paused {
            return;
        }
        if WRITING.with(|w| w.replace(true)) {
            return;
        }
        if let Some(mirror) = self.mirror {
            let mut state = mirror.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(open) = state.as_mut() {
                mirror.write_locked(open, line);
            }
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(open) = state.as_mut() {
            self.write_locked(open, line);
        }
        drop(state);
        WRITING.with(|w| w.set(false));
    }

    fn write_locked(&self, open: &mut Open, line: &[u8]) {
        if open.file.is_some() && open.size > 0 && open.size + line.len() as u64 > self.cap {
            open.file = None;
            for i in (1..self.keep.saturating_sub(1)).rev() {
                let _ = std::fs::rename(numbered(&open.path, i), numbered(&open.path, i + 1));
            }
            if self.keep > 1 {
                let _ = std::fs::rename(&open.path, numbered(&open.path, 1));
            }
        }
        if open.file.is_none() {
            let mut options = std::fs::OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let Ok(file) = options.open(&open.path) else {
                return;
            };
            open.size = file.metadata().map_or(0, |m| m.len());
            open.file = Some(file);
        }
        let Some(file) = open.file.as_mut() else {
            return;
        };
        if file.write_all(line).is_ok() {
            open.size += line.len() as u64;
            if self.durable {
                let _ = file.sync_data();
            }
        }
    }
}

fn numbered(path: &Path, n: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}", n));
    PathBuf::from(name)
}

/// The logs go into `<data_dir>/diag` from here on (the directory runs.log
/// made)
pub fn set_data_dir(data_dir: &Path) {
    let diag = data_dir.join("diag");
    for log in [&EVENTS, &CHAIN_EVENTS, &HEALTH] {
        log.set_dir(&diag);
    }
}

/// The events.log mirror goes into `dir` (A14)
pub fn set_mirror_dir(dir: &Path) {
    EVENTS_MIRROR.set_dir(dir);
}

/// A record in events.log
pub fn event(kind: &str, fields: &str) {
    EVENTS.record(kind, fields);
}

/// The `config` event (A12): whether the config file's sha256 differs
/// from the last start's, kept in `diag/config.sha256`. The hash itself is
/// never written to a log.
pub fn note_config(data_dir: &Path, conf: &Path) {
    let now = match std::fs::read(conf) {
        Ok(bytes) => hex::encode(divi_crypto::sha256(&bytes)),
        Err(_) => "none".to_string(),
    };
    let kept = data_dir.join("diag").join("config.sha256");
    let prev = std::fs::read_to_string(&kept).ok();
    if let Some(changed) = config_change(prev.as_deref(), &now) {
        event("config", &format!("changed={}", changed));
        let _ = crate::private_files::write_private_atomic(&kept, now.as_bytes());
    }
}

/// `first` with no hash kept, `yes` for a different one, none for the same
fn config_change(prev: Option<&str>, now: &str) -> Option<&'static str> {
    match prev.map(str::trim) {
        None => Some("first"),
        Some(p) if p != now => Some("yes"),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_change_is_reported_once_and_never_its_hash() {
        assert_eq!(config_change(None, "ab"), Some("first"));
        assert_eq!(config_change(Some("ab\n"), "ab"), None);
        assert_eq!(config_change(Some("ab"), "none"), Some("yes"));
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("diag")).unwrap();
        let conf = dir.path().join("divi.conf");
        std::fs::write(&conf, "rpcuser=x\n").unwrap();
        note_config(dir.path(), &conf);
        let kept = std::fs::read_to_string(dir.path().join("diag/config.sha256")).unwrap();
        assert_eq!(kept.len(), 64);
        note_config(dir.path(), &conf);
        std::fs::write(&conf, "rpcuser=y\n").unwrap();
        note_config(dir.path(), &conf);
        assert_ne!(
            std::fs::read_to_string(dir.path().join("diag/config.sha256")).unwrap(),
            kept
        );
    }

    #[test]
    fn a_full_log_is_rotated_and_only_keep_files_stay() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::new("t.log", 100, 3, true);
        log.set_dir(dir.path());
        for i in 0..20 {
            log.write_line(format!("line {:02} {}\n", i, "x".repeat(30)).as_bytes());
        }
        let read = |n: &str| std::fs::read_to_string(dir.path().join(n)).unwrap_or_default();
        assert!(read("t.log").len() <= 100, "{}", read("t.log"));
        assert!(read("t.log").contains("line 19"));
        assert!(!read("t.log.1").is_empty());
        assert!(!read("t.log.2").is_empty());
        assert!(!dir.path().join("t.log.3").exists());
        // Oldest first across the files, nothing between them lost
        let all = format!("{}{}{}", read("t.log.2"), read("t.log.1"), read("t.log"));
        let first: Vec<u32> = all.lines().map(|l| l[5..7].parse().unwrap()).collect();
        assert!(first.windows(2).all(|w| w[1] == w[0] + 1), "{all}");
        assert_eq!(*first.last().unwrap(), 19);
    }

    #[test]
    fn nothing_is_written_while_paused_and_the_mirror_comes_first() {
        static M: Log = Log::new("m.log", 1 << 20, 2, false);
        let dir = tempfile::tempdir().unwrap();
        let log = Log::mirrored("t.log", 1 << 20, 2, false, &M);
        log.set_dir(dir.path());
        log.write_gated(b"dropped\n", true);
        assert!(!dir.path().join("t.log").exists());
        log.write_gated(b"kept\n", false);
        assert_eq!(std::fs::read(dir.path().join("t.log")).unwrap(), b"kept\n");
        let mdir = dir.path().join("mirror");
        std::fs::create_dir(&mdir).unwrap();
        M.set_dir(&mdir);
        log.write_gated(b"both\n", false);
        assert_eq!(std::fs::read(mdir.join("m.log")).unwrap(), b"both\n");
        assert_eq!(
            std::fs::read(dir.path().join("t.log")).unwrap(),
            b"kept\nboth\n"
        );
    }

    #[test]
    fn nothing_is_written_before_the_directory_is_known() {
        let log = Log::new("t.log", 100, 2, false);
        log.write_line(b"dropped\n");
        assert!(log.state.lock().unwrap().is_none());
    }
}
