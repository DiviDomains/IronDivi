// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A6: `health.log`, one line every 10 s for the first 10 minutes of a run,
//! then every 60 s, from the `health` thread; and the A12 stall record.
//!
//! The line holds process, system, time, chain, staking and counter
//! fields. A field with no source yet is written `n/a`, never left out: on
//! macOS `n/a (macOS)`. `/proc/self/io` is never read (D5: the node is not
//! dumpable); I/O comes from `getrusage` as block counts.
//!
//! A stall (consensus N-i): the tip has not moved for over 2 minutes while
//! a peer is ahead (any lag, never the `far_behind` gate). One
//! `chain-events.log` `stall` record per stall, and one incident once it
//! passes 10 minutes (consensus N-k); both re-arm when the tip moves. The
//! tip age is measured on `CLOCK_BOOTTIME`, which a wall clock step cannot
//! move (platforms R15-1); the record still carries the clock state.

use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use divi_network::{BlockSync, PeerManager, SporkManager};
use divi_node::Mempool;
use divi_primitives::hash::Hash256;
use divi_storage::Chain;

/// The last `PR_GET_DUMPABLE` the `dumpable-check` thread read (-1: not yet)
pub static DUMPABLE: AtomicI32 = AtomicI32::new(-1);
/// Times it found the flag set and cleared it
pub static DUMPABLE_RESETS: AtomicU64 = AtomicU64::new(0);

/// What the staking line needs from the staker and wallet (main registers
/// it once they exist)
pub struct Staking {
    pub enabled: bool,
    pub mintable_coins: bool,
    pub wallet_locked: bool,
    /// Unix time of the last stake found, 0 for never
    pub last_stake_time: u64,
}

type StakingFn = Box<dyn Fn() -> Staking + Send + Sync>;
static STAKING: Mutex<Option<StakingFn>> = Mutex::new(None);
/// The last line written, for incidents
static LAST: Mutex<String> = Mutex::new(String::new());
/// Wakes the `health` thread to write an immediate health record (e.g. SIGUSR1)
static WAKE: (Mutex<bool>, std::sync::Condvar) = (Mutex::new(false), std::sync::Condvar::new());

pub fn wake() {
    if let Ok(mut w) = WAKE.0.try_lock() {
        *w = true;
        WAKE.1.notify_all();
    }
}

pub fn set_staking(f: StakingFn) {
    *STAKING.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
}

/// The last health record (empty before the first); never waits
pub fn last_line() -> String {
    LAST.try_lock().map(|l| l.clone()).unwrap_or_default()
}

/// The tick: 10 s for the first 10 minutes of the run, then 60 s
pub fn interval() -> Duration {
    interval_at(crate::runs_log::since_launch())
}

fn interval_at(since_launch: Duration) -> Duration {
    if since_launch < Duration::from_secs(600) {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(60)
    }
}

pub struct Handles {
    pub chain: Arc<Chain>,
    pub block_sync: Arc<BlockSync>,
    pub peers: Arc<PeerManager>,
    pub mempool: Arc<Mempool>,
    pub sporks: Arc<SporkManager>,
    pub data_dir: PathBuf,
}

/// Start the `health` thread
pub fn start(h: Handles) {
    let started = crate::tasks::thread("health", crate::tasks::Kind::Supervised, move || {
        let mut tick = Tick::default();
        let mut prev: Option<Snap> = None;
        loop {
            let line = tick.line(&h);
            crate::events::HEALTH.record("health", &line);
            // A12: the changes between this tick and the last, as events
            let sporks = h
                .sporks
                .active_sporks()
                .iter()
                .map(|s| (s.spork_id, s.time_signed))
                .collect();
            let snap = Snap::of(&line, sporks);
            if let Some(prev) = &prev {
                for (kind, fields) in transitions(prev, &snap) {
                    crate::events::event(kind, &fields);
                }
            }
            prev = Some(snap);
            *LAST.lock().unwrap_or_else(|e| e.into_inner()) = line;
            // A15: a quiet minute after a busy one is still written
            crate::rpc_log::tick();
            #[cfg(unix)]
            crate::watchdog::beat_health();
            let guard = WAKE.0.lock().unwrap_or_else(|e| e.into_inner());
            let (mut guard, _) = WAKE
                .1
                .wait_timeout_while(guard, interval(), |w| !*w)
                .unwrap_or_else(|e| e.into_inner());
            *guard = false;
        }
    });
    if let Err(e) = started {
        tracing::warn!("could not start the health thread: {}", e);
    }
}

/// What one tick carries to the next
#[derive(Default)]
struct Tick {
    /// Wall clock minus monotonic at the previous tick
    wall_offset: Option<f64>,
    stall: StallLatch,
    reason: Option<&'static str>,
    stakes: StakeDays,
}

impl Tick {
    fn line(&mut self, h: &Handles) -> String {
        let mut f = Fields::default();
        process(&mut f);
        system(&mut f, h);
        let clock = self.time(&mut f, h);
        self.chain(&mut f, h, &clock);
        self.staking(&mut f, h);
        counters(&mut f);
        f.0.join(" ")
    }

    fn time(&mut self, f: &mut Fields, h: &Handles) -> Clock {
        let wall = wall_clock();
        let mono = mono_clock();
        let boot = boot_clock();
        f.put("wall", format!("{:.0}", wall));
        f.put("mono", format!("{:.3}", mono));
        match boot {
            Some(b) => {
                f.put("boot", format!("{:.3}", b));
                f.put("suspended_s", format!("{:.0}", b - mono));
            }
            None => {
                f.na_mac("boot");
                f.na_mac("suspended_s");
            }
        }
        let offset = wall - mono;
        let jump = self.wall_offset.map_or(0.0, |o| offset - o);
        self.wall_offset = Some(offset);
        f.put("wall_jump_s", format!("{:.0}", jump));
        let synced = clock_synced();
        f.put("clock_synced", synced);
        f.put("time_offset", time_offset(&h.peers).to_string());
        f.na("future_headers_rejected");
        Clock {
            boot: boot.unwrap_or(mono),
            synced,
        }
    }

    fn chain(&mut self, f: &mut Fields, h: &Handles, clock: &Clock) {
        let tip = h.chain.tip();
        let height = h.chain.height();
        let progress = h.block_sync.progress();
        let lag = progress.target_height.saturating_sub(height);
        f.put("height", height.to_string());
        f.put("headers", h.block_sync.best_header_height().to_string());
        f.put(
            "best",
            tip.as_ref().map_or("-".to_string(), |t| t.hash.to_string()),
        );
        f.put("sync", format!("{:?}", progress.state).to_lowercase());
        f.put("peers_in", h.peers.inbound_count().to_string());
        f.put("peers_out", h.peers.outbound_count().to_string());
        f.put("in_flight", progress.blocks_in_flight.to_string());
        f.put("lag", lag.to_string());
        let mempool = h.mempool.stats();
        f.put("mempool_txs", mempool.tx_count.to_string());
        f.put("mempool_bytes", mempool.total_bytes.to_string());
        f.na("rocksdb_memtable_bytes");
        f.na("rocksdb_block_cache_bytes");
        let hash = tip.map(|t| t.hash).unwrap_or_default();
        let action = self.stall.observe(height, hash, lag, clock.boot);
        f.put(
            "tip_moved_s",
            format!("{:.0}", self.stall.since_moved(clock.boot)),
        );
        let detail = |secs: f64| {
            format!(
                "height={} lag={} tip_moved_s={:.0} clock=boottime clock_synced={}",
                height, lag, secs, clock.synced
            )
        };
        match action {
            StallAction::None => {}
            StallAction::Stall(secs) => crate::events::CHAIN_EVENTS.record("stall", &detail(secs)),
            StallAction::Incident(secs) => {
                // The health line is written after this tick; the incident
                // gets the one before it
                if let Some(n) = crate::incidents::write("stall", &detail(secs)) {
                    crate::events::event("incident", &format!("n={} kind=stall", n));
                }
            }
        }
    }

    fn staking(&mut self, f: &mut Fields, h: &Handles) {
        let staking = STAKING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|s| s());
        let Some(s) = staking else {
            f.put("staking", "n/a");
            f.put("staking_reason", "no-wallet-or-staker");
            for k in ["wallet", "last_stake", "stakes_30d", "stake_ratio"] {
                f.na(k);
            }
            masternode(f);
            return;
        };
        let now = wall_clock() as u64;
        let tip_age = h.chain.tip().map(|t| now.saturating_sub(t.time as u64));
        let reason = staking_reason(&s, h.peers.peer_count(), h.chain.is_ibd(), tip_age);
        if self.reason != Some(reason) {
            // A12: every change of the "not staking because" reason
            if self.reason.is_some() {
                crate::events::event("staking", &format!("reason={}", reason));
            }
            self.reason = Some(reason);
        }
        f.put("staking", crate::runs_log::yes(reason == "none"));
        f.put("staking_reason", reason);
        f.put(
            "wallet",
            if s.wallet_locked {
                "locked"
            } else {
                "unlocked"
            },
        );
        f.put("last_stake", stake_age_bucket(s.last_stake_time, now));
        if let Some(day) = self.stakes.observe(s.last_stake_time, now) {
            crate::events::event("stakes", &day);
        }
        f.na("stakes_30d");
        f.na("stake_ratio");
        masternode(f);
    }
}

/// Stakes found per UTC day (A12): a stake is a rise of the staker's last
/// stake time between two ticks, so two stakes within one tick count once.
/// The day in progress is lost at a stop.
#[derive(Default)]
struct StakeDays {
    seen: Option<u64>,
    day: Option<i64>,
    n: u32,
}

impl StakeDays {
    /// Count a tick; the `day= n=` record of the day that just ended
    fn observe(&mut self, last_stake_time: u64, now: u64) -> Option<String> {
        let today = (now / 86_400) as i64;
        let mut out = None;
        if let Some(day) = self.day.filter(|d| *d != today) {
            let date = crate::runs_log::format_utc(day * 86_400, 0);
            out = Some(format!("day={} n={}", &date[..10], self.n));
            self.n = 0;
        }
        self.day = Some(today);
        if self.seen.is_some_and(|s| last_stake_time > s) {
            self.n += 1;
        }
        self.seen = Some(last_stake_time);
        out
    }
}

/// The fields of a health line A12's transition events compare
#[derive(Debug, Default, PartialEq)]
struct Snap {
    sync: Option<String>,
    wallet: Option<String>,
    disk_mb: Option<u64>,
    /// `psi_mem`'s `some` ten-second average
    psi_some: Option<f64>,
    cgroup_high: Option<u64>,
    time_offset: Option<i64>,
    /// (id, time signed), sorted
    sporks: Vec<(i32, i64)>,
}

impl Snap {
    fn of(line: &str, mut sporks: Vec<(i32, i64)>) -> Snap {
        let field = |key: &str| {
            line.split(' ')
                .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
                .filter(|v| !v.starts_with("n/a") && !v.starts_with('"'))
        };
        sporks.sort_unstable();
        Snap {
            sync: field("sync").map(str::to_string),
            wallet: field("wallet").map(str::to_string),
            disk_mb: field("disk_free_mb").and_then(|v| v.parse().ok()),
            psi_some: field("psi_mem")
                .and_then(|v| v.strip_prefix("some:")?.split('/').next()?.parse().ok()),
            cgroup_high: field("cgroup_mem_high_events").and_then(|v| v.parse().ok()),
            time_offset: field("time_offset").and_then(|v| v.parse().ok()),
            sporks,
        }
    }
}

/// Peer time offset above which the clock is called wrong (seconds)
const OFFSET_WARN_S: i64 = 300;

/// The events between two ticks: each a change of state or band, never a
/// value that only moved within one
fn transitions(prev: &Snap, now: &Snap) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    // A field that was not read on one side is not a change
    fn both<T, U: PartialEq>(a: &Option<T>, b: &Option<T>, f: impl Fn(&T) -> U) -> Option<U> {
        match (a, b) {
            (Some(a), Some(b)) if f(a) != f(b) => Some(f(b)),
            _ => None,
        }
    }
    if let Some(s) = both(&prev.sync, &now.sync, |s| s.clone()) {
        out.push(("sync", format!("state={}", s)));
    }
    if let Some(s) = both(&prev.wallet, &now.wallet, |s| s.clone()) {
        out.push(("wallet", format!("state={}", s)));
    }
    let band = |mb: &u64| match *mb {
        0..=99 => "below-100mb",
        100..=1023 => "below-1gb",
        _ => "above-1gb",
    };
    if let Some(b) = both(&prev.disk_mb, &now.disk_mb, band) {
        out.push(("disk", format!("free={}", b)));
    }
    let over = |p: &f64| if *p > 10.0 { "over-10" } else { "under-10" };
    if let Some(b) = both(&prev.psi_some, &now.psi_some, over) {
        out.push(("memory-pressure", format!("psi_mem={}", b)));
    }
    if let (Some(a), Some(b)) = (prev.cgroup_high, now.cgroup_high) {
        if b > a {
            out.push(("memory-pressure", format!("cgroup_high_events=+{}", b - a)));
        }
    }
    let warn = |o: &i64| o.abs() > OFFSET_WARN_S;
    if let Some(w) = both(&prev.time_offset, &now.time_offset, warn) {
        out.push((
            "time-offset",
            format!(
                "warning={} offset_s={}",
                crate::runs_log::yes(w),
                now.time_offset.unwrap_or_default()
            ),
        ));
    }
    for s in now.sporks.iter().filter(|s| !prev.sporks.contains(s)) {
        out.push(("spork", format!("id={} signed={}", s.0, s.1)));
    }
    out
}

struct Clock {
    boot: f64,
    synced: &'static str,
}

fn masternode(f: &mut Fields) {
    f.na("masternode");
    f.na("mnsync");
}

/// The first reason in A6's order that stops staking now, or `none`
fn staking_reason(s: &Staking, peers: usize, ibd: bool, tip_age: Option<u64>) -> &'static str {
    if !s.enabled {
        "disabled"
    } else if s.wallet_locked {
        "wallet-locked"
    } else if peers == 0 {
        "no-peers"
    } else if ibd {
        "not-synced"
    } else if tip_age.is_none_or(|a| a > 600) {
        "stale-tip"
    } else if !s.mintable_coins {
        "no-mature-coins"
    } else {
        "none"
    }
}

/// The age of the last stake found, as A6's bucket only
fn stake_age_bucket(last: u64, now: u64) -> &'static str {
    if last == 0 {
        return "never";
    }
    let age = now.saturating_sub(last);
    match age {
        a if a < 86_400 => "lt-1d",
        a if a < 7 * 86_400 => "1-7d",
        a if a <= 30 * 86_400 => "7-30d",
        _ => "gt-30d",
    }
}

fn counters(f: &mut Fields) {
    f.put("panics", crate::tasks::panics().to_string());
    f.put(
        "dropped_lines",
        crate::log_delivery::dropped_total().to_string(),
    );
    #[cfg(unix)]
    {
        let (sigpipes, epipes) = crate::signals::counts();
        f.put("sigpipe", sigpipes.to_string());
        f.put("epipe", epipes.to_string());
    }
    // A17: waits of 1 s or more on the main locks since start
    let waits: u64 = divi_primitives::diag_lock::counts()
        .iter()
        .map(|w| w.1)
        .sum();
    f.put("lock_waits", waits.to_string());
    f.put("rpc_calls", divi_primitives::diag_rpc::calls().to_string());
    match DUMPABLE.load(Ordering::Relaxed) {
        -1 if cfg!(target_os = "linux") => f.put("dumpable", "not-yet"),
        -1 => f.na_mac("dumpable"),
        d => f.put("dumpable", d.to_string()),
    }
    f.put(
        "dumpable_resets",
        DUMPABLE_RESETS.load(Ordering::Relaxed).to_string(),
    );
}

#[derive(Default)]
struct Fields(Vec<String>);

impl Fields {
    fn put(&mut self, key: &str, value: impl AsRef<str>) {
        let v = value.as_ref();
        if v.is_empty() || v.contains([' ', '"', '\n']) {
            self.0
                .push(format!("{}={}", key, crate::runs_log::quote(v)));
        } else {
            self.0.push(format!("{}={}", key, v));
        }
    }
    fn na(&mut self, key: &str) {
        self.0.push(format!("{}=n/a", key));
    }
    fn na_mac(&mut self, key: &str) {
        if cfg!(target_os = "macos") {
            self.0.push(format!("{}=\"n/a (macOS)\"", key));
        } else {
            self.na(key);
        }
    }
}

#[cfg(unix)]
fn clock(id: libc::clockid_t) -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

#[cfg(unix)]
fn wall_clock() -> f64 {
    clock(libc::CLOCK_REALTIME)
}

#[cfg(not(unix))]
fn wall_clock() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(unix)]
fn mono_clock() -> f64 {
    clock(libc::CLOCK_MONOTONIC)
}

#[cfg(not(unix))]
fn mono_clock() -> f64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs_f64()
}

fn boot_clock() -> Option<f64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Some(clock(libc::CLOCK_BOOTTIME))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

/// `yes`, `no` or `unknown`: a read-only `adjtimex` (modes 0, which needs
/// no capability) says whether the kernel clock is synchronised
pub(crate) fn clock_synced() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        let state = unsafe { libc::adjtimex(&mut tx) };
        if state < 0 {
            "unknown"
        } else if state == libc::TIME_ERROR || tx.status & libc::STA_UNSYNC != 0 {
            "no"
        } else {
            "yes"
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        "unknown"
    }
}

/// The network-adjusted time offset: the median peer offset once at least
/// 5 peers are connected (as `getnetworkinfo`'s `timeoffset`)
fn time_offset(peers: &PeerManager) -> i64 {
    let mut offsets: Vec<i64> = peers
        .get_peer_details()
        .iter()
        .map(|(_, _, _, st, _)| st.time_offset.load(Ordering::Relaxed))
        .collect();
    if offsets.len() < 5 {
        return 0;
    }
    offsets.sort_unstable();
    offsets[offsets.len() / 2]
}

/// What a tick's tip observation asks for
#[derive(Debug, PartialEq)]
enum StallAction {
    None,
    /// The `stall` record, with the seconds since the tip moved
    Stall(f64),
    /// The incident
    Incident(f64),
}

/// One stall record and one incident per stall, re-armed when the tip moves
#[derive(Default)]
struct StallLatch {
    tip: Option<(u32, Hash256)>,
    moved_at: f64,
    recorded: bool,
    incident: bool,
}

impl StallLatch {
    const STALL: f64 = 120.0;
    const INCIDENT: f64 = 600.0;

    fn observe(&mut self, height: u32, hash: Hash256, lag: u32, now: f64) -> StallAction {
        if self.tip != Some((height, hash)) {
            self.tip = Some((height, hash));
            self.moved_at = now;
            self.recorded = false;
            self.incident = false;
            return StallAction::None;
        }
        let secs = now - self.moved_at;
        if lag == 0 {
            return StallAction::None;
        }
        if !self.recorded && secs > Self::STALL {
            self.recorded = true;
            return StallAction::Stall(secs);
        }
        if self.recorded && !self.incident && secs > Self::INCIDENT {
            self.incident = true;
            return StallAction::Incident(secs);
        }
        StallAction::None
    }

    fn since_moved(&self, now: f64) -> f64 {
        now - self.moved_at
    }
}

fn process(f: &mut Fields) {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let get = |key: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
                .map(|v| v.trim().trim_end_matches(" kB").to_string())
        };
        for (key, name) in [
            ("VmRSS", "rss_kb"),
            ("VmPeak", "vm_peak_kb"),
            ("VmSize", "vm_size_kb"),
            ("Threads", "threads"),
        ] {
            match get(key) {
                Some(v) => f.put(name, v),
                None => f.na(name),
            }
        }
        let fd_size: usize = get("FDSize").and_then(|v| v.parse().ok()).unwrap_or(0);
        let (fds, source, inodes) = fds(fd_size);
        match fds {
            Some(n) => f.put("fds", n.to_string()),
            None => f.na("fds"),
        }
        f.put("fd_source", source);
        match inodes {
            Some(inodes) => f.put("sockets", sockets(&inodes)),
            None => f.na("sockets"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    for k in [
        "rss_kb",
        "vm_peak_kb",
        "vm_size_kb",
        "threads",
        "fds",
        "fd_source",
        "sockets",
    ] {
        f.na_mac(k);
    }
    #[cfg(unix)]
    {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } == 0 {
            let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
            f.put(
                "cpu_s",
                format!("{:.1}", secs(ru.ru_utime) + secs(ru.ru_stime)),
            );
            f.put("major_faults", ru.ru_majflt.to_string());
            f.put("io_blocks_in", ru.ru_inblock.to_string());
            f.put("io_blocks_out", ru.ru_oublock.to_string());
        } else {
            for k in ["cpu_s", "major_faults", "io_blocks_in", "io_blocks_out"] {
                f.na(k);
            }
        }
    }
    #[cfg(not(unix))]
    for k in ["cpu_s", "major_faults", "io_blocks_in", "io_blocks_out"] {
        f.na(k);
    }
    f.na("allocator");
}

/// The open fd count, where it came from, and the socket inodes (when
/// `fd/` could be listed)
#[cfg(target_os = "linux")]
fn fds(fd_size: usize) -> (Option<usize>, String, Option<Vec<u64>>) {
    if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
        let mut count: usize = 0;
        let mut inodes = Vec::new();
        for entry in dir.flatten() {
            count += 1;
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let t = target.to_string_lossy();
                if let Some(i) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    inodes.extend(i.parse::<u64>().ok());
                }
            }
        }
        // The directory's own fd is in the listing
        return (Some(count.saturating_sub(1)), "fd/".into(), Some(inodes));
    }
    if fd_size == 0 {
        return (None, "none".into(), None);
    }
    let open = (0..fd_size as i32)
        .filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1)
        .count();
    (Some(open), format!("probe-fdsize-{}", fd_size), None)
}

/// The node's TCP sockets by state, from `net/tcp` and `net/tcp6`, matched
/// to its own fds by inode; other sockets (UDP, Unix) as `other`
#[cfg(target_os = "linux")]
fn sockets(inodes: &[u64]) -> String {
    let own: std::collections::HashSet<u64> = inodes.iter().copied().collect();
    let mut by_state = std::collections::BTreeMap::<&'static str, usize>::new();
    let mut tcp = 0;
    for table in ["/proc/self/net/tcp", "/proc/self/net/tcp6"] {
        let text = std::fs::read_to_string(table).unwrap_or_default();
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let (Some(st), Some(inode)) = (cols.get(3), cols.get(9)) else {
                continue;
            };
            if !inode.parse::<u64>().is_ok_and(|i| own.contains(&i)) {
                continue;
            }
            tcp += 1;
            *by_state.entry(tcp_state(st)).or_default() += 1;
        }
    }
    let mut out: Vec<String> = by_state
        .into_iter()
        .map(|(s, n)| format!("{}:{}", s, n))
        .collect();
    out.push(format!("other:{}", own.len().saturating_sub(tcp)));
    out.join(",")
}

#[cfg(target_os = "linux")]
fn tcp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "established",
        "02" => "syn_sent",
        "03" => "syn_recv",
        "04" => "fin_wait1",
        "05" => "fin_wait2",
        "06" => "time_wait",
        "07" => "close",
        "08" => "close_wait",
        "09" => "last_ack",
        "0A" => "listen",
        "0B" => "closing",
        _ => "unknown",
    }
}

fn system(f: &mut Fields, h: &Handles) {
    #[cfg(target_os = "linux")]
    {
        cgroup(f);
        for (res, name) in [("memory", "psi_mem"), ("io", "psi_io"), ("cpu", "psi_cpu")] {
            match psi(res) {
                Some(v) => f.put(name, v),
                None => f.na(name),
            }
        }
        let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
        let load: Vec<&str> = load.split_whitespace().take(3).collect();
        if load.len() == 3 {
            f.put("load", load.join(","));
        } else {
            f.na("load");
        }
        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        for (key, name) in [
            ("MemAvailable", "mem_available_kb"),
            ("SwapTotal", "swap_total_kb"),
            ("SwapFree", "swap_free_kb"),
        ] {
            let v = meminfo
                .lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
                .map(|v| v.trim().trim_end_matches(" kB").to_string());
            match v {
                Some(v) => f.put(name, v),
                None => f.na(name),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    for k in [
        "cgroup_mem_current",
        "cgroup_mem_max",
        "cgroup_mem_high_events",
        "cgroup_oom_kills",
        "psi_mem",
        "psi_io",
        "psi_cpu",
        "load",
        "mem_available_kb",
        "swap_total_kb",
        "swap_free_kb",
    ] {
        f.na_mac(k);
    }
    disk(f, h);
}

#[cfg(target_os = "linux")]
fn cgroup(f: &mut Fields) {
    let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let dir = own
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| PathBuf::from("/sys/fs/cgroup").join(p.trim_start_matches('/')));
    let read = |name: &str| {
        dir.as_ref()
            .and_then(|d| std::fs::read_to_string(d.join(name)).ok())
    };
    match read("memory.current") {
        Some(v) => f.put("cgroup_mem_current", v.trim()),
        None => f.na("cgroup_mem_current"),
    }
    match read("memory.max") {
        Some(v) => f.put("cgroup_mem_max", v.trim()),
        None => f.na("cgroup_mem_max"),
    }
    let events = read("memory.events");
    let event = |key: &str| {
        events.as_ref().and_then(|e| {
            e.lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
                .map(|v| v.trim().to_string())
        })
    };
    match event("high") {
        Some(v) => f.put("cgroup_mem_high_events", v),
        None => f.na("cgroup_mem_high_events"),
    }
    match event("oom_kill") {
        Some(v) => f.put("cgroup_oom_kills", v),
        None => f.na("cgroup_oom_kills"),
    }
}

/// `some:<avg10>/full:<avg10>` (`full` is missing for CPU on older kernels)
#[cfg(target_os = "linux")]
fn psi(resource: &str) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/pressure/{}", resource)).ok()?;
    let avg10 = |kind: &str| {
        text.lines()
            .find(|l| l.starts_with(kind))?
            .split_whitespace()
            .find_map(|w| w.strip_prefix("avg10="))
            .map(str::to_string)
    };
    Some(format!(
        "some:{}/full:{}",
        avg10("some")?,
        avg10("full").unwrap_or_else(|| "n/a".into())
    ))
}

fn disk(f: &mut Fields, h: &Handles) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::ffi::CString::new(h.data_dir.as_os_str().as_bytes()).ok();
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if path.is_some_and(|p| unsafe { libc::statvfs(p.as_ptr(), &mut st) } == 0) {
            let free = st.f_bavail as u64 * st.f_frsize as u64;
            // A14: the low-disk pause follows this sample
            crate::budget::sample(free);
            f.put("disk_free_mb", (free >> 20).to_string());
            f.put("inodes_free", (st.f_favail as u64).to_string());
        } else {
            f.na("disk_free_mb");
            f.na("inodes_free");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = h;
        f.na("disk_free_mb");
        f.na("inodes_free");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(b: u8) -> Hash256 {
        Hash256::from_bytes([b; 32])
    }

    #[test]
    fn the_tick_is_10_s_for_ten_minutes_then_60_s() {
        assert_eq!(interval_at(Duration::ZERO), Duration::from_secs(10));
        assert_eq!(
            interval_at(Duration::from_secs(599)),
            Duration::from_secs(10)
        );
        assert_eq!(
            interval_at(Duration::from_secs(600)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn one_stall_record_and_one_incident_per_stall_rearmed_when_the_tip_moves() {
        let mut l = StallLatch::default();
        assert_eq!(l.observe(5, hash(1), 3, 0.0), StallAction::None);
        assert_eq!(l.observe(5, hash(1), 3, 100.0), StallAction::None);
        assert_eq!(l.observe(5, hash(1), 3, 130.0), StallAction::Stall(130.0));
        assert_eq!(l.observe(5, hash(1), 3, 300.0), StallAction::None);
        assert_eq!(
            l.observe(5, hash(1), 3, 610.0),
            StallAction::Incident(610.0)
        );
        assert_eq!(l.observe(5, hash(1), 3, 5000.0), StallAction::None);
        // The tip moves: both re-arm
        assert_eq!(l.observe(6, hash(2), 3, 5010.0), StallAction::None);
        assert_eq!(l.observe(6, hash(2), 3, 5140.0), StallAction::Stall(130.0));
        // Same height, another hash (a reorg) is a move too
        assert_eq!(l.observe(6, hash(3), 3, 5150.0), StallAction::None);
    }

    #[test]
    fn no_stall_without_a_peer_ahead() {
        let mut l = StallLatch::default();
        l.observe(5, hash(1), 0, 0.0);
        assert_eq!(l.observe(5, hash(1), 0, 1000.0), StallAction::None);
        // Any lag counts, 1 included
        assert_eq!(l.observe(5, hash(1), 1, 1001.0), StallAction::Stall(1001.0));
    }

    #[test]
    fn the_reason_is_the_first_in_a6_order() {
        let mut s = Staking {
            enabled: true,
            mintable_coins: true,
            wallet_locked: false,
            last_stake_time: 0,
        };
        assert_eq!(staking_reason(&s, 3, false, Some(30)), "none");
        assert_eq!(staking_reason(&s, 3, false, Some(601)), "stale-tip");
        assert_eq!(staking_reason(&s, 3, true, Some(30)), "not-synced");
        assert_eq!(staking_reason(&s, 0, true, Some(30)), "no-peers");
        s.mintable_coins = false;
        assert_eq!(staking_reason(&s, 3, false, Some(30)), "no-mature-coins");
        s.wallet_locked = true;
        assert_eq!(staking_reason(&s, 0, true, None), "wallet-locked");
        s.enabled = false;
        assert_eq!(staking_reason(&s, 0, true, None), "disabled");
    }

    #[test]
    fn the_last_stake_is_a_bucket_only() {
        let now = 100 * 86_400;
        assert_eq!(stake_age_bucket(0, now), "never");
        assert_eq!(stake_age_bucket(now - 10, now), "lt-1d");
        assert_eq!(stake_age_bucket(now - 3 * 86_400, now), "1-7d");
        assert_eq!(stake_age_bucket(now - 20 * 86_400, now), "7-30d");
        assert_eq!(stake_age_bucket(now - 40 * 86_400, now), "gt-30d");
    }

    #[test]
    fn stakes_are_counted_per_utc_day_from_the_second_tick() {
        let day = 20_000 * 86_400;
        let mut s = StakeDays::default();
        // The first tick is the baseline, whatever the last stake
        assert_eq!(s.observe(day - 5, day + 10), None);
        assert_eq!(s.observe(day + 20, day + 60), None);
        assert_eq!(s.observe(day + 20, day + 120), None);
        assert_eq!(s.observe(day + 500, day + 600), None);
        let next = s.observe(day + 500, day + 86_400 + 5).unwrap();
        assert_eq!(next, "day=2024-10-04 n=2");
        assert_eq!(
            s.observe(day + 500, day + 2 * 86_400).as_deref(),
            Some("day=2024-10-05 n=0")
        );
    }

    #[test]
    fn health_transitions_are_changes_of_state_or_band() {
        let line = |sync: &str, disk: u64, psi: &str, high: u64, off: i64| {
            format!(
                "pid=1 psi_mem={} cgroup_mem_high_events={} disk_free_mb={} \
                 time_offset={} sync={} staking=no wallet=locked",
                psi, high, disk, off, sync
            )
        };
        let a = Snap::of(
            &line("headers", 5000, "some:0.00/full:0.00", 3, 2),
            vec![(10007, 5)],
        );
        assert_eq!(a.psi_some, Some(0.0));
        assert!(transitions(&a, &a).is_empty());
        // Values moving within a band are no event
        let b = Snap::of(
            &line("headers", 4000, "some:9.99/full:1.00", 3, -250),
            vec![(10007, 5)],
        );
        assert!(transitions(&a, &b).is_empty());
        let c = Snap::of(
            &line("synced", 50, "some:12.50/full:3.00", 7, 400),
            vec![(10008, 9), (10007, 5)],
        );
        assert_eq!(
            transitions(&b, &c),
            vec![
                ("sync", "state=synced".to_string()),
                ("disk", "free=below-100mb".to_string()),
                ("memory-pressure", "psi_mem=over-10".to_string()),
                ("memory-pressure", "cgroup_high_events=+4".to_string()),
                ("time-offset", "warning=yes offset_s=400".to_string()),
                ("spork", "id=10008 signed=9".to_string()),
            ]
        );
        // A field not read (macOS) is never a change
        let mac = Snap::of("psi_mem=\"n/a (macOS)\" sync=synced", vec![]);
        assert_eq!(mac.psi_some, None);
        assert!(transitions(&c, &mac)
            .iter()
            .all(|(k, _)| *k != "memory-pressure"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_clock_state_is_read_without_a_capability() {
        assert!(["yes", "no"].contains(&clock_synced()));
    }
}
