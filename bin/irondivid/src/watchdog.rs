// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A17: the watchdog
//!
//! An OS thread, awake every second. It writes an incident when the health
//! tick has not run for its interval plus 60 s, when the tokio runtime has
//! not run its 1 s beat for 60 s, when an RPC call has been in flight for
//! 60 s, when a main lock has been waited on for 60 s, and when
//! `<datadir>/diag/snapshot-request` exists (the file is removed).
//!
//! One incident per item each 10 minutes; at most 10 a UTC day per class,
//! except that a run's first health or runtime stall is always written; a
//! snapshot at most every 10 s and 20 a day. The day a class runs out,
//! events.log has `incident-budget class=<class>` once.
//!
//! The watchdog itself waking 30 s or more late is a `late-wake` event
//! with its cause (`stopped`: a SIGCONT came in the gap; `starved`: the
//! cgroup's CPU throttling covers half the gap; `frozen`: neither, the
//! process did not run; `uncertain`: system-wide CPU pressure is high), and
//! the gap is taken off every hang clock it falls in.
//!
//! Each second it also compares the A5 thread table with
//! `/proc/self/task` (Linux): a thread in the table, not in /proc, and
//! still in the table after the read, ended without unwinding; that is a
//! `thread-vanished` line in crash.log and in events.log.
//!
//! Files (the snapshot request, incidents) are read and written by the
//! `watchdog-files` helper thread, so a hung disk does not stop the checks.
//!
//! Not here (Revision 16): the per-thread stack sweep and the macOS thread
//! walk; the snapshot request through the mirror (A14).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// A hang that is an incident
const HANG_MS: u64 = 60_000;
/// A wake this late is classified
const LATE_MS: u64 = 30_000;
const SAME_ITEM_MS: u64 = 10 * 60_000;
const PER_DAY: u32 = 10;
const SNAPSHOTS_PER_DAY: u32 = 20;
const SNAPSHOT_GAP_MS: u64 = 10_000;

static HEALTH_BEAT: AtomicU64 = AtomicU64::new(0);
static RUNTIME_BEAT: AtomicU64 = AtomicU64::new(0);
/// The snapshot request was seen by the helper
static SNAPSHOT: AtomicBool = AtomicBool::new(false);

/// CLOCK_MONOTONIC in ms (the clock signals.rs stamps SIGCONT with)
pub(crate) fn mono_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

/// The health tick ran
pub fn beat_health() {
    HEALTH_BEAT.store(mono_ms(), Ordering::Relaxed);
}

/// Start the watchdog, its helper, and the runtime beat (inside tokio)
pub fn start(data_dir: PathBuf) {
    let now = mono_ms();
    HEALTH_BEAT.store(now, Ordering::Relaxed);
    RUNTIME_BEAT.store(now, Ordering::Relaxed);
    crate::tasks::spawn_supervised("watchdog-beat", async {
        loop {
            RUNTIME_BEAT.store(mono_ms(), Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let runtime = tokio::runtime::Handle::current();
    let (tx, rx) = mpsc::channel::<(String, String)>();
    let files = crate::tasks::thread(
        "watchdog-files",
        crate::tasks::Kind::Supervised,
        move || files(data_dir, rx),
    );
    if let Err(e) = files {
        tracing::warn!("could not start the watchdog-files thread: {}", e);
        return;
    }
    let started = crate::tasks::thread("watchdog", crate::tasks::Kind::Supervised, move || {
        let mut w = Watch::new(mono_ms());
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let now = mono_ms();
            for (kind, detail) in w.tick(now, &probe(), wall_day()) {
                let detail = format!("{}\n{}", detail, snapshot_detail(&runtime));
                let _ = tx.send((kind, detail));
            }
            for (tid, name) in vanished() {
                let fields = format!("tid={} thread={}", tid, crate::runs_log::quote(&name));
                crate::crash::note(&format!("thread-vanished {}", fields));
                crate::events::event("thread-vanished", &fields);
            }
        }
    });
    if let Err(e) = started {
        tracing::warn!("could not start the watchdog thread: {}", e);
    }
}

/// The helper: the snapshot request and the incident writes
fn files(data_dir: PathBuf, rx: mpsc::Receiver<(String, String)>) {
    let request = data_dir.join("diag").join("snapshot-request");
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok((kind, detail)) => {
                if let Some(n) = crate::incidents::write(&kind, &detail) {
                    crate::events::event("incident", &format!("n={} kind={}", n, kind));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        if request.exists() && std::fs::remove_file(&request).is_ok() {
            SNAPSHOT.store(true, Ordering::Relaxed);
        }
    }
}

fn wall_day() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86_400)
}

/// What one tick looks at
#[derive(Default)]
struct Probe {
    health_beat: u64,
    health_interval_ms: u64,
    runtime_beat: u64,
    /// (method, ms)
    in_flight: Vec<(String, u64)>,
    /// (lock, ms, waiter, holder)
    lock_waits: Vec<(String, u64, String, String)>,
    snapshot: bool,
    /// SIGCONT's CLOCK_MONOTONIC ms, 0 for none
    cont_at: u64,
    /// The cgroup's throttled CPU time, µs
    throttled_us: Option<u64>,
    /// System-wide CPU pressure, `some avg10`
    psi_cpu: Option<f64>,
}

fn probe() -> Probe {
    Probe {
        health_beat: HEALTH_BEAT.load(Ordering::Relaxed),
        health_interval_ms: crate::health::interval().as_millis() as u64,
        runtime_beat: RUNTIME_BEAT.load(Ordering::Relaxed),
        in_flight: divi_primitives::diag_rpc::in_flight()
            .into_iter()
            .map(|c| (c.method.to_string(), c.for_ms))
            .collect(),
        lock_waits: divi_primitives::diag_lock::waiting()
            .into_iter()
            .map(|w| (w.lock.as_str().to_string(), w.for_ms, w.waiter, w.holder))
            .collect(),
        snapshot: SNAPSHOT.swap(false, Ordering::Relaxed),
        cont_at: crate::signals::cont_at_ms(),
        throttled_us: throttled_us(),
        psi_cpu: psi_cpu(),
    }
}

/// The watchdog's state between ticks
struct Watch {
    last_wake: u64,
    last_throttled_us: Option<u64>,
    /// (when, how long) of late wakes, to take off the hang clocks
    late: Vec<(u64, u64)>,
    /// item -> when its last incident was
    items: HashMap<String, u64>,
    /// (day, class) -> incidents written
    budget: HashMap<(u64, &'static str), u32>,
    exhausted: HashMap<(u64, &'static str), bool>,
    first_stall: [bool; 2],
    last_snapshot: Option<u64>,
}

impl Watch {
    fn new(now: u64) -> Watch {
        Watch {
            last_wake: now,
            last_throttled_us: None,
            late: Vec::new(),
            items: HashMap::new(),
            budget: HashMap::new(),
            exhausted: HashMap::new(),
            first_stall: [true, true],
            last_snapshot: None,
        }
    }

    /// The gap of the late wakes within the last `age` ms
    fn excused(&self, now: u64, age: u64) -> u64 {
        let since = now.saturating_sub(age);
        self.late
            .iter()
            .filter(|(at, _)| *at >= since)
            .map(|(_, ms)| ms)
            .sum()
    }

    /// The incidents this tick writes, as (kind, detail)
    fn tick(&mut self, now: u64, p: &Probe, day: u64) -> Vec<(String, String)> {
        let gap = now.saturating_sub(self.last_wake);
        self.last_wake = now;
        if gap >= LATE_MS + 1000 {
            let late = gap - 1000;
            let cause = classify(late, now, p, self.last_throttled_us);
            crate::events::event("late-wake", &format!("late_ms={} cause={}", late, cause));
            self.late.push((now, late));
        }
        self.last_throttled_us = p.throttled_us;
        self.late.retain(|(at, _)| now - at < 24 * 3_600_000);
        self.items.retain(|_, at| now - *at < SAME_ITEM_MS);

        let mut found: Vec<(&'static str, String, String)> = Vec::new();
        let age = |beat: u64| now.saturating_sub(beat);
        let health = age(p.health_beat);
        let health = health.saturating_sub(self.excused(now, health));
        if health > p.health_interval_ms + HANG_MS {
            found.push((
                "health-stall",
                "health".into(),
                format!("stalled_ms={}", health),
            ));
        }
        let runtime = age(p.runtime_beat);
        let runtime = runtime.saturating_sub(self.excused(now, runtime));
        if runtime > HANG_MS {
            found.push((
                "runtime-stall",
                "runtime".into(),
                format!("stalled_ms={}", runtime),
            ));
        }
        for (method, ms) in &p.in_flight {
            let ms = ms.saturating_sub(self.excused(now, *ms));
            if ms > HANG_MS {
                found.push((
                    "rpc-stuck",
                    format!("rpc:{}", method),
                    format!("method={} in_flight_ms={}", method, ms),
                ));
            }
        }
        for (lock, ms, waiter, holder) in &p.lock_waits {
            let ms = ms.saturating_sub(self.excused(now, *ms));
            if ms > HANG_MS {
                found.push((
                    "lock-wait",
                    format!("lock:{}:{}", lock, waiter),
                    format!(
                        "lock={} waited_ms={} waiter={} holder={}",
                        lock,
                        ms,
                        crate::runs_log::quote(waiter),
                        crate::runs_log::quote(holder)
                    ),
                ));
            }
        }
        let mut out = Vec::new();
        for (class, item, detail) in found {
            if self.items.contains_key(&item) {
                continue;
            }
            let first = match class {
                "health-stall" => std::mem::take(&mut self.first_stall[0]),
                "runtime-stall" => std::mem::take(&mut self.first_stall[1]),
                _ => false,
            };
            if !first && !self.spend(day, class, PER_DAY) {
                continue;
            }
            self.items.insert(item, now);
            out.push((class.to_string(), detail));
        }
        if p.snapshot {
            let soon = self
                .last_snapshot
                .is_some_and(|at| now - at < SNAPSHOT_GAP_MS);
            if !soon && self.spend(day, "snapshot", SNAPSHOTS_PER_DAY) {
                self.last_snapshot = Some(now);
                out.push(("snapshot".to_string(), "requested=file".to_string()));
            }
        }
        out
    }

    fn spend(&mut self, day: u64, class: &'static str, max: u32) -> bool {
        let n = self.budget.entry((day, class)).or_insert(0);
        if *n < max {
            *n += 1;
            return true;
        }
        if !self.exhausted.insert((day, class), true).unwrap_or(false) {
            crate::events::event("incident-budget", &format!("class={} exhausted", class));
        }
        false
    }
}

fn classify(late: u64, now: u64, p: &Probe, last_throttled_us: Option<u64>) -> &'static str {
    if p.cont_at != 0 && p.cont_at + late + 2000 >= now {
        return "stopped";
    }
    if let (Some(a), Some(b)) = (last_throttled_us, p.throttled_us) {
        if b.saturating_sub(a) / 1000 >= late / 2 {
            return "starved";
        }
    }
    if p.psi_cpu.is_some_and(|v| v >= 50.0) {
        return "uncertain";
    }
    "frozen"
}

/// The cgroup v2 `cpu.stat` throttled_usec of this process (Linux)
fn throttled_us() -> Option<u64> {
    let cg = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = cg.lines().find_map(|l| l.strip_prefix("0::"))?;
    let stat = std::fs::read_to_string(format!("/sys/fs/cgroup{}/cpu.stat", path)).ok()?;
    stat.lines()
        .find_map(|l| l.strip_prefix("throttled_usec "))
        .and_then(|v| v.trim().parse().ok())
}

fn psi_cpu() -> Option<f64> {
    let psi = std::fs::read_to_string("/proc/pressure/cpu").ok()?;
    let some = psi.lines().find(|l| l.starts_with("some "))?;
    some.split_whitespace()
        .find_map(|f| f.strip_prefix("avg10="))
        .and_then(|v| v.parse().ok())
}

/// Threads in the A5 table that /proc no longer has (Linux)
fn vanished() -> Vec<(i64, String)> {
    #[cfg(target_os = "linux")]
    {
        let before = crate::crash::threads();
        let Ok(dir) = std::fs::read_dir("/proc/self/task") else {
            return Vec::new();
        };
        let live: std::collections::HashSet<i64> = dir
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        let after = crate::crash::threads();
        before
            .into_iter()
            .filter(|t| !live.contains(&t.0) && after.contains(t))
            .collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// The incident's state: threads, locks, calls, runtime, counters
fn snapshot_detail(runtime: &tokio::runtime::Handle) -> String {
    let mut out = String::new();
    let (threads, refused) = threads();
    out.push_str(&threads);
    out.push_str(&format!("refused by kernel: {}\n", refused));
    for (lock, holder) in divi_primitives::diag_lock::holders() {
        out.push_str(&format!(
            "lock {} last_holder={}\n",
            lock.as_str(),
            crate::runs_log::quote(&holder)
        ));
    }
    for w in divi_primitives::diag_lock::waiting() {
        out.push_str(&format!(
            "lock-wait {} for_ms={} waiter={} holder={}\n",
            w.lock.as_str(),
            w.for_ms,
            crate::runs_log::quote(&w.waiter),
            crate::runs_log::quote(&w.holder)
        ));
    }
    for (lock, over, longest) in divi_primitives::diag_lock::counts() {
        out.push_str(&format!(
            "lock-waits {} over_1s={} longest_ms={}\n",
            lock.as_str(),
            over,
            longest
        ));
    }
    for c in divi_primitives::diag_rpc::in_flight() {
        out.push_str(&format!(
            "in-flight method={} transport={} for_ms={}\n",
            c.method,
            c.transport.as_str(),
            c.for_ms
        ));
    }
    let m = runtime.metrics();
    out.push_str(&format!(
        "tokio workers={} alive_tasks={} global_queue={}\n",
        m.num_workers(),
        m.num_alive_tasks(),
        m.global_queue_depth()
    ));
    crate::counts::raw_copy(|l| {
        out.push_str(l.as_str().trim_end());
        out.push('\n');
    });
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } == 0 {
        out.push_str(&format!(
            "rusage inblock={} oublock={} nvcsw={} nivcsw={}\n",
            ru.ru_inblock, ru.ru_oublock, ru.ru_nvcsw, ru.ru_nivcsw
        ));
    }
    #[cfg(target_os = "linux")]
    out.push_str(&format!(
        "hwcap={:#x} hwcap2={:#x}\n",
        unsafe { libc::getauxval(libc::AT_HWCAP) },
        unsafe { libc::getauxval(libc::AT_HWCAP2) }
    ));
    out
}

/// Every thread's name, state and wchan (Linux), and how many reads the
/// kernel refused (also `getdiaginfo`, A10)
pub(crate) fn threads() -> (String, u32) {
    #[cfg(target_os = "linux")]
    {
        let mut out = String::new();
        let mut refused = 0;
        let Ok(dir) = std::fs::read_dir("/proc/self/task") else {
            return ("threads: n/a\n".into(), 1);
        };
        let mut tids: Vec<u64> = dir
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        tids.sort_unstable();
        for tid in tids {
            let base = format!("/proc/self/task/{}", tid);
            let stat = std::fs::read_to_string(format!("{}/stat", base)).unwrap_or_default();
            // pid (comm) S ...: comm may hold spaces and parentheses
            let (name, state) = match (stat.find('('), stat.rfind(')')) {
                (Some(a), Some(b)) if a < b => (
                    stat[a + 1..b].to_string(),
                    stat[b + 1..]
                        .split_whitespace()
                        .next()
                        .unwrap_or("?")
                        .to_string(),
                ),
                _ => {
                    refused += 1;
                    ("?".into(), "?".into())
                }
            };
            let wchan = match std::fs::read_to_string(format!("{}/wchan", base)) {
                Ok(w) if w.trim() == "0" || w.trim().is_empty() => {
                    if state == "R" {
                        "running".to_string()
                    } else {
                        "hidden".to_string()
                    }
                }
                Ok(w) => w.trim().to_string(),
                Err(_) => {
                    refused += 1;
                    "refused".to_string()
                }
            };
            out.push_str(&format!(
                "thread {} name={} state={} wchan={}\n",
                tid,
                crate::runs_log::quote(&name),
                state,
                wchan
            ));
        }
        (out, refused)
    }
    #[cfg(not(target_os = "linux"))]
    {
        ("threads: n/a on this system\n".into(), 0)
    }
}

/// Lock waits of 1 s or more, to events.log (installed once in main)
pub fn install_lock_sink() {
    divi_primitives::diag_lock::install(Box::new(|w| {
        crate::events::event(
            "lock-wait",
            &format!(
                "lock={} waited_ms={} waiter={} holder={}",
                w.lock.as_str(),
                w.waited.as_millis(),
                crate::runs_log::quote(&w.waiter),
                crate::runs_log::quote(&w.holder)
            ),
        );
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet(now: u64) -> Probe {
        Probe {
            health_beat: now,
            health_interval_ms: 10_000,
            runtime_beat: now,
            ..Probe::default()
        }
    }

    #[test]
    fn a_health_stall_is_one_incident_per_ten_minutes() {
        let mut w = Watch::new(100_000);
        let mut now = 100_000;
        let mut written = 0;
        for _ in 0..1200 {
            now += 1000;
            let mut p = quiet(now);
            p.health_beat = 0;
            written += w.tick(now, &p, 1).len();
        }
        // 20 minutes of a stall: one at the start, one 10 minutes later
        assert_eq!(written, 2);
    }

    #[test]
    fn nothing_is_written_while_the_beats_run() {
        let mut w = Watch::new(0);
        let mut now = 0;
        for _ in 0..200 {
            now += 1000;
            assert!(w.tick(now, &quiet(now), 1).is_empty());
        }
    }

    #[test]
    fn a_class_stops_at_ten_a_day_the_first_stall_aside() {
        let mut w = Watch::new(100_000);
        let mut written = 0;
        let mut now = 100_000;
        for i in 0..20u64 {
            now += 1000;
            let mut p = quiet(now);
            p.lock_waits = vec![("chain".into(), 70_000, format!("t{}", i), "h".into())];
            written += w.tick(now, &p, 1).len();
        }
        assert_eq!(written, 10);
        // The first runtime stall is written with the lock class spent
        now += 1000;
        let mut p = quiet(now);
        p.runtime_beat = 0;
        assert_eq!(w.tick(now, &p, 1).len(), 1);
    }

    #[test]
    fn snapshots_are_ten_seconds_apart() {
        let mut w = Watch::new(0);
        let mut now = 0;
        let mut written = 0;
        for _ in 0..30 {
            now += 1000;
            let mut p = quiet(now);
            p.snapshot = true;
            written += w.tick(now, &p, 1).len();
        }
        assert_eq!(written, 3);
    }

    #[test]
    fn a_late_wake_is_taken_off_the_hang_clocks() {
        let mut w = Watch::new(0);
        // Beats at 1 s, then the process is stopped for 90 s
        let p = quiet(1000);
        assert!(w.tick(1000, &p, 1).is_empty());
        let mut p = quiet(1000);
        p.cont_at = 91_500;
        assert!(w.tick(92_000, &p, 1).is_empty());
    }

    #[test]
    fn late_wakes_are_classified() {
        let p = Probe {
            cont_at: 95_000,
            ..Default::default()
        };
        assert_eq!(classify(60_000, 96_000, &p, None), "stopped");
        let p = Probe {
            throttled_us: Some(50_000_000),
            ..Default::default()
        };
        assert_eq!(classify(60_000, 96_000, &p, Some(10_000_000)), "starved");
        let p = Probe {
            psi_cpu: Some(80.0),
            ..Default::default()
        };
        assert_eq!(classify(60_000, 96_000, &p, None), "uncertain");
        assert_eq!(classify(60_000, 96_000, &Probe::default(), None), "frozen");
    }
}
