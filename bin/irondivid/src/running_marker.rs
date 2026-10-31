// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `<datadir>/diag/irondivid.running` (diag.md A2): created once the data
//! directory's lock is held, removed by the `exit` record. A marker found at
//! the next start means the previous run ended without reaching an exit
//! record, and runs.log gets an `unclean-previous` record saying what the
//! marker and the system show about why.
//!
//! The marker is `key=value` lines: the run, pid, start time, boot id,
//! PID 1's start time, the last phase, the stop request if any, and the
//! cgroup (or, without one, system) memory counters. Each write goes to a
//! temporary file, is synced and renamed over the marker, and the directory
//! is synced, so the marker is the old one or the new one.
//!
//! (Interim: A6's health tick does not exist yet, so the marker is rewritten
//! at each phase and at the stop request, not every tick; crash.log (A4/A5),
//! the kernel log, seccomp, jetsam, OpenVZ and ancestor cgroups are not read
//! yet, and the verdict says so.)

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const NAME: &str = "irondivid.running";

/// What the marker holds, once this run created it
static STATE: Mutex<Option<State>> = Mutex::new(None);

struct State {
    dir: PathBuf,
    fields: BTreeMap<String, String>,
}

/// After the data directory's lock is held: record any marker the previous
/// run left in runs.log, then write this run's. `run` is this run's number.
pub fn create(diag_dir: &Path, run: u64) {
    let path = diag_dir.join(NAME);
    if let Ok(text) = std::fs::read_to_string(&path) {
        crate::runs_log::record("unclean-previous", &unclean_previous(&text, diag_dir));
    }
    let mut fields = BTreeMap::new();
    fields.insert("run".into(), run.to_string());
    fields.insert("pid".into(), unsafe { libc::getpid() }.to_string());
    fields.insert("start".into(), crate::runs_log::utc_now());
    fields.insert("boot_id".into(), boot_id());
    fields.insert("pid1_start".into(), pid1_start());
    fields.insert("phase".into(), "lock".into());
    let mut state = State {
        dir: diag_dir.to_path_buf(),
        fields,
    };
    match write(&mut state) {
        Ok(()) => *STATE.lock().unwrap_or_else(|e| e.into_inner()) = Some(state),
        Err(e) => tracing::warn!("diag/{} is not kept: {}", NAME, e),
    }
}

/// Rewrite the marker with `key=value` (a no-op unless this run created it)
fn update(key: &str, value: &str) {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(state) = guard.as_mut() {
        state.fields.insert(key.into(), value.into());
        let _ = write(state);
    }
}

pub fn phase(name: &str) {
    update("phase", name);
}

pub fn stop_requested(by: &str) {
    update("stop", by);
}

/// The run reached its exit record: the end is accounted for. Only the run
/// that created the marker removes it (a second instance refused at the
/// lock never does).
pub fn remove() {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(state) = state {
        if std::fs::remove_file(state.dir.join(NAME)).is_ok() {
            // Or a power loss right after a clean stop reads as unclean
            let _ = File::open(&state.dir).and_then(|d| d.sync_all());
        }
    }
}

fn write(state: &mut State) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    for (k, v) in counters() {
        state.fields.insert(k, v);
    }
    let mut text = String::new();
    for (k, v) in &state.fields {
        text.push_str(&format!("{}={}\n", k, v));
    }
    let tmp = state.dir.join(format!("{}.tmp", NAME));
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_data()?;
    std::fs::rename(&tmp, state.dir.join(NAME))?;
    File::open(&state.dir)?.sync_all()
}

fn parse(text: &str) -> Option<BTreeMap<String, String>> {
    let map: BTreeMap<String, String> = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    (map.contains_key("run") && map.contains_key("pid")).then_some(map)
}

/// The `unclean-previous` fields for a marker left behind
fn unclean_previous(text: &str, diag_dir: &Path) -> String {
    let Some(old) = parse(text) else {
        return "verdict=marker-unreadable counters=lost".into();
    };
    let get = |k: &str| old.get(k).map(String::as_str).unwrap_or("-");
    let compare = |old: &str, now: String| match (old, now.as_str()) {
        ("-", _) | (_, "-") => "unknown",
        (a, b) if a == b => "same",
        _ => "changed",
    };
    let boot = compare(get("boot_id"), boot_id());
    let pid1 = compare(get("pid1_start"), pid1_start());
    let now = counters();
    // The OOM-kill count, in the same cgroup only
    let oom = match (old.get("cgroup"), now.get("cgroup")) {
        (Some(a), Some(b)) if a == b => {
            match (
                old.get(OOM_KILL).and_then(|s| s.parse::<u64>().ok()),
                now.get(OOM_KILL).and_then(|s| s.parse::<u64>().ok()),
            ) {
                (Some(a), Some(b)) if b > a => "rose",
                (Some(a), Some(b)) if b < a => "reset",
                (Some(_), Some(_)) => "same",
                _ => "unknown",
            }
        }
        _ => "unknown",
    };
    let wsl = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .is_ok_and(|s| s.to_lowercase().contains("microsoft"));
    let verdict = if boot == "changed" && wsl {
        "wsl-vm-stopped"
    } else if boot == "changed" {
        "rebooted-or-power-loss"
    } else if pid1 == "changed" {
        "container-restarted"
    } else if oom == "rose" {
        "memory-limit-kill-probable"
    } else if old.contains_key("stop") {
        "killed-after-stop-request"
    } else {
        "no-trace"
    };
    let run: u64 = get("run").parse().unwrap_or(0);
    format!(
        "run={} pid={} phase={} stop={} verdict={} boot={} pid1={} oom_kill={} \
         exit_recorded={} crash_log=not-read kernel_log=not-read",
        run,
        get("pid"),
        get("phase"),
        get("stop"),
        verdict,
        boot,
        pid1,
        oom,
        crate::runs_log::yes(exit_recorded(&diag_dir.join("runs.log"), run)),
    )
}

const OOM_KILL: &str = "memory.events.oom_kill";

/// Whether runs.log has an `exit` record for run `run` (the process may have
/// died between that record and removing the marker)
fn exit_recorded(runs_log: &Path, run: u64) -> bool {
    let text = std::fs::read_to_string(runs_log).unwrap_or_default();
    let start = format!(" start run={} ", run);
    let mut inside = false;
    for line in text.lines() {
        if line.contains(&start) {
            inside = true;
        } else if line.contains(" start run=") {
            inside = false;
        } else if inside && line.contains(" exit code=") {
            return true;
        }
    }
    false
}

/// `/proc/sys/kernel/random/boot_id` (Linux); "-" elsewhere
fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "-".into())
}

/// PID 1's start time in clock ticks since boot (`/proc/1/stat` field 22),
/// in this pid namespace: it changes when a container restarts
fn pid1_start() -> String {
    std::fs::read_to_string("/proc/1/stat")
        .ok()
        .and_then(|s| {
            let after = &s[s.rfind(')')? + 1..];
            // Fields from 3 on; field 22 is the 20th
            after.split_whitespace().nth(19).map(str::to_string)
        })
        .unwrap_or_else(|| "-".into())
}

/// The memory counters of this process's cgroup (v2 or v1), or of the
/// system without one. Keys are `<file>.<key>` or `<file>`.
fn counters() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") else {
        return out;
    };
    let v2 = cgroup.lines().find_map(|l| l.strip_prefix("0::"));
    let v1 = cgroup.lines().find_map(|l| {
        let mut parts = l.splitn(3, ':');
        let (_, controllers, path) = (parts.next()?, parts.next()?, parts.next()?);
        controllers
            .split(',')
            .any(|c| c == "memory")
            .then_some(path)
    });
    if let Some(path) = v1 {
        out.insert("cgroup".into(), format!("v1:{}", path));
        let dir = Path::new("/sys/fs/cgroup/memory").join(path.trim_start_matches('/'));
        keyed(&mut out, &dir, "memory.oom_control");
        for f in [
            "memory.failcnt",
            "memory.max_usage_in_bytes",
            "memory.limit_in_bytes",
        ] {
            single(&mut out, &dir, f);
        }
        // Under the v1 names the A2 table compares
        if let Some(n) = out.get("memory.oom_control.oom_kill").cloned() {
            out.insert(OOM_KILL.into(), n);
        }
    } else if let Some(path) =
        v2.filter(|_| Path::new("/sys/fs/cgroup/cgroup.controllers").exists())
    {
        out.insert("cgroup".into(), format!("v2:{}", path));
        let dir = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
        for f in [
            "memory.events",
            "memory.swap.events",
            "pids.events",
            "cgroup.events",
        ] {
            keyed(&mut out, &dir, f);
        }
        for f in ["memory.current", "memory.peak", "memory.max", "pids.max"] {
            single(&mut out, &dir, f);
        }
        if let Ok(text) = std::fs::read_to_string(dir.join("cpu.stat")) {
            for (k, v) in text.lines().filter_map(|l| l.split_once(' ')) {
                if k.contains("throttled") {
                    out.insert(format!("cpu.stat.{}", k), v.trim().to_string());
                }
            }
        }
    }
    if !out.contains_key("cgroup") {
        out.insert("cgroup".into(), "none".into());
        if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
            for line in text.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    if ["MemAvailable", "Committed_AS", "CommitLimit"].contains(&k) {
                        out.insert(format!("meminfo.{}", k), v.trim().to_string());
                    }
                }
            }
        }
        single(&mut out, Path::new("/proc/sys/vm"), "overcommit_memory");
    }
    out
}

/// A file of `key value` lines, each as `<file>.<key>`
fn keyed(out: &mut BTreeMap<String, String>, dir: &Path, file: &str) {
    if let Ok(text) = std::fs::read_to_string(dir.join(file)) {
        for (k, v) in text.lines().filter_map(|l| l.split_once(' ')) {
            out.insert(format!("{}.{}", file, k), v.trim().to_string());
        }
    }
}

/// A file holding one value
fn single(out: &mut BTreeMap<String, String>, dir: &Path, file: &str) {
    if let Ok(text) = std::fs::read_to_string(dir.join(file)) {
        out.insert(file.to_string(), text.trim().to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unparseable_marker_is_unclean_with_counters_lost() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            unclean_previous("garbage", dir.path()),
            "verdict=marker-unreadable counters=lost"
        );
    }

    #[test]
    fn a_rebooted_machine_is_the_verdict_over_a_stop_request() {
        let dir = tempfile::tempdir().unwrap();
        let text = "run=3\npid=42\nboot_id=not-this-boot\nphase=running\nstop=signal=TERM\n";
        let fields = unclean_previous(text, dir.path());
        if boot_id() == "-" {
            // No boot id here: the stop request decides
            assert!(
                fields.contains(" verdict=killed-after-stop-request "),
                "{fields}"
            );
        } else {
            assert!(
                fields.contains(" verdict=rebooted-or-power-loss "),
                "{fields}"
            );
        }
        assert!(
            fields.starts_with("run=3 pid=42 phase=running stop=signal=TERM "),
            "{fields}"
        );
    }

    #[test]
    fn the_exit_record_is_looked_for_in_that_run_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runs.log");
        std::fs::write(
            &path,
            "t m start run=1 pid=1\nt m exit code=0\nt m start run=2 pid=2\nt m phase name=lock\n\
             t m start run=3 pid=3\nt m exit code=0\n",
        )
        .unwrap();
        assert!(exit_recorded(&path, 1));
        assert!(!exit_recorded(&path, 2));
        assert!(exit_recorded(&path, 3));
    }

    #[test]
    fn pid1_start_is_a_number_on_linux() {
        if cfg!(target_os = "linux") {
            assert!(pid1_start().parse::<u64>().is_ok(), "{}", pid1_start());
        }
    }
}
