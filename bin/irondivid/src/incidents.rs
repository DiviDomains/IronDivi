// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A12 incidents: `<datadir>/diag/incidents/<n>/` with `info.txt` (kind,
//! run, time, detail), `ring.txt` (the debug ring, A8), `debug.log.tail`
//! (its last 256 KB) and `health.txt` (the last health record, A6).
//!
//! The last 10 are kept, but the first incident of each kind stays
//! (consensus N-k), so a long run of one kind cannot push out the incident
//! that explains it. Written so far: a stall over 10 minutes (once per
//! stall, A6) and a supervised task's panic (A4). Not yet: `getdiaginfo`
//! output, and the other triggers A12 lists (invalid block, ban storm,
//! watchdog, SIGQUIT/SIGUSR1), which come with their own parts.
//!
//! Never panics: the panic hook calls it.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// `<datadir>`, once it is known
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
/// One incident at a time
static WRITING: Mutex<()> = Mutex::new(());

const KEEP: usize = 10;
const DEBUG_TAIL: u64 = 256 * 1024;

pub fn set_data_dir(data_dir: &Path) {
    let _ = DATA_DIR.set(data_dir.to_path_buf());
}

/// Write an incident of `kind` (a word) with `detail` (key=value fields);
/// returns its number
pub fn write(kind: &str, detail: &str) -> Option<u64> {
    let data_dir = DATA_DIR.get()?;
    // A panic while an incident is being written is not waited on
    let _guard = match WRITING.try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return None,
    };
    let root = data_dir.join("diag").join("incidents");
    let _ = crate::private_files::ensure_private_dir(&root, true);
    let n = numbered(&root).last().map_or(1, |(n, _)| n + 1);
    let dir = root.join(n.to_string());
    if crate::private_files::ensure_private_dir(&dir, true).is_err() {
        return None;
    }
    let info = format!(
        "kind={}\nrun={}\ntime={}\nmono={}\n{}\ngetdiaginfo: n/a (not built yet)\n",
        kind,
        crate::runs_log::run_number(),
        crate::runs_log::utc_now(),
        crate::runs_log::mono_now(),
        detail
    );
    put(&dir.join("info.txt"), info.as_bytes());
    let mut ring = Vec::new();
    crate::log_delivery::RING.for_each(|l| ring.extend_from_slice(l));
    put(&dir.join("ring.txt"), &ring);
    put(&dir.join("debug.log.tail"), &tail(&data_dir.join("debug.log")));
    put(&dir.join("health.txt"), crate::health::last_line().as_bytes());
    prune(&root);
    Some(n)
}

fn put(path: &Path, bytes: &[u8]) {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    if let Ok(mut file) = options.open(path) {
        let _ = file.write_all(bytes);
    }
}

fn tail(path: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    if let Ok(mut file) = std::fs::File::open(path) {
        let len = file.metadata().map_or(0, |m| m.len());
        if file.seek(SeekFrom::Start(len.saturating_sub(DEBUG_TAIL))).is_ok() {
            let _ = file.take(DEBUG_TAIL).read_to_end(&mut out);
        }
    }
    out
}

/// The incident directories, oldest first, with their kinds
fn numbered(root: &Path) -> Vec<(u64, String)> {
    let mut out: Vec<(u64, String)> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n: u64 = e.file_name().to_str()?.parse().ok()?;
            let info = std::fs::read_to_string(e.path().join("info.txt")).unwrap_or_default();
            let kind = info
                .lines()
                .find_map(|l| l.strip_prefix("kind="))
                .unwrap_or("-")
                .to_string();
            Some((n, kind))
        })
        .collect();
    out.sort();
    out
}

fn prune(root: &Path) {
    for n in to_remove(&numbered(root)) {
        let _ = std::fs::remove_dir_all(root.join(n.to_string()));
    }
}

/// The oldest incidents past [`KEEP`], never the first of a kind
fn to_remove(incidents: &[(u64, String)]) -> Vec<u64> {
    let mut first = std::collections::HashSet::new();
    let mut protected = std::collections::HashSet::new();
    for (n, kind) in incidents {
        if first.insert(kind.as_str()) {
            protected.insert(*n);
        }
    }
    let mut excess = incidents.len().saturating_sub(KEEP);
    let mut out = Vec::new();
    for (n, _) in incidents {
        if excess == 0 {
            break;
        }
        if !protected.contains(n) {
            out.push(*n);
            excess -= 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_keeps_ten_and_the_first_of_each_kind() {
        let mut list = vec![(1, "panic".to_string())];
        for n in 2..=13 {
            list.push((n, "stall".to_string()));
        }
        // 13 incidents: 3 go, the oldest stalls after the first one
        assert_eq!(to_remove(&list), vec![3, 4, 5]);
        assert!(to_remove(&list[..10]).is_empty());
    }
}
