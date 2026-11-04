// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `rpc-methods.log` and its aggregates (diag plan A15)
//!
//! Every finished call ([`divi_primitives::diag_rpc`]) is counted in the
//! per-minute and per-hour aggregates. A per-call line is written only
//! for the calls A15 lists, each kind under its own hourly cap, and the
//! lines that must survive a flood are written a second time to the
//! reserved segments, which capped lines never enter. Never a parameter:
//! the method, transport, caller pseudonym, result code and duration.
//! [`decide`] holds the policy and is pure; [`State`] is its memory.

use crate::events::Log;
use divi_primitives::diag_rpc::{self, Done, Transport};
use divi_primitives::redact::PeerAddr;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

// A14's budget: 1 MB × 2 each
pub static METHODS: Log = Log::new("rpc-methods.log", 1 << 20, 2, false);
pub static AGG_MINUTE: Log = Log::new("rpc-aggregate.log", 1 << 20, 2, false);
pub static AGG_HOUR: Log = Log::new("rpc-aggregate-hourly.log", 1 << 20, 2, false);

/// Lines a capped method may write in an hour
const PER_METHOD: u32 = 100;
/// Capped lines of every kind together in an hour
const TOTAL: u32 = 200;
/// Error-style lines: per (method, result, transport), and in all
const ERR_EACH: u32 = 5;
const ERR_ALL: u32 = 50;
/// Masked error messages kept per method
const KEEP_ERRORS: usize = 20;
/// Methods tracked per interval; more are counted under `other`
const METHODS_MAX: usize = 256;
/// Callers counted per aggregate line, durations sampled per line
const CALLERS_MAX: usize = 10_000;
const SAMPLES_MAX: usize = 4096;
/// The reserved segments' total size
const RESERVED_CAP: u64 = 1 << 20;
/// Bytes of `diag/sent-txids`; when full, the oldest quarter is dropped
const SENT_CAP: usize = 1 << 20;

/// What A15 does with a method
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Rare and state-changing: every call, uncapped, also reserved
    Rare,
    /// `import*`, `dump*`, `*passphrase*`: 100 an hour per method
    Secret,
    /// `send*`, `*broadcast*`, `sign*`
    HighRate,
    Other,
}

pub fn kind(method: &str) -> Kind {
    const RARE: &[&str] = &[
        "stop",
        "setlogconfig",
        "walletlock",
        "reservebalance",
        "setstaking",
        "encryptwallet",
        "keypoolrefill",
        "settxfee",
        "setgenerate",
        "lockunspent",
        "addnode",
        "disconnectnode",
        "setban",
        "clearbanned",
        "invalidateblock",
        "reconsiderblock",
        "spork",
        "startmasternode",
        "fundmasternode",
        "allocatefunds",
        "rescanblockchain",
        "setaccount",
        "setlabel",
    ];
    if RARE.contains(&method) || method.starts_with("backup") {
        Kind::Rare
    } else if method.starts_with("import")
        || method.starts_with("dump")
        || method.contains("passphrase")
    {
        Kind::Secret
    } else if method.starts_with("send")
        || method.contains("broadcast")
        || method.starts_with("sign")
    {
        Kind::HighRate
    } else {
        Kind::Other
    }
}

/// The caller as written: `loopback`, a pseudonym, or `unknown`
fn caller_text(ip: Option<IpAddr>) -> String {
    match ip {
        Some(ip) if ip.is_loopback() => "loopback".to_string(),
        Some(ip) => PeerAddr(ip).to_string(),
        None => "unknown".to_string(),
    }
}

/// Local, or an authenticated JSON-RPC caller (A15's trusted callers)
fn trusted(d: &Done<'_>) -> bool {
    let local = d.caller.is_some_and(|ip| ip.is_loopback());
    match d.transport {
        Transport::JsonRpc => local || d.authenticated,
        Transport::WebUi => local,
        Transport::Electrum => local,
    }
}

/// What one call writes
#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    /// The `rpc-methods.log` line
    pub line: Option<String>,
    /// Write the call to the reserved segments (even when the total cap
    /// left it out of `rpc-methods.log`)
    pub reserved: bool,
}

/// The hourly counters the caps read
#[derive(Default)]
pub struct Hour {
    pub start: u64,
    per_method: HashMap<String, u32>,
    over: BTreeMap<String, u32>,
    total: u32,
    total_over: u32,
    first: HashSet<(String, String)>,
    err_each: HashMap<(String, i64, Transport), u32>,
    err_all: u32,
}

impl Hour {
    fn note_method(&self, method: &str) -> bool {
        self.per_method.contains_key(method) || self.per_method.len() < METHODS_MAX
    }

    /// The `more calls not listed` lines for this hour
    pub fn overflow_lines(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .over
            .iter()
            .map(|(m, n)| format!("{}: {} more calls not listed", m, n))
            .collect();
        if self.total_over > 0 {
            out.push(format!(
                "{} more calls suppressed (total cap)",
                self.total_over
            ));
        }
        out
    }
}

fn line(d: &Done<'_>) -> String {
    let result = match d.error {
        None => "ok".to_string(),
        Some((code, _)) => code.to_string(),
    };
    format!(
        "method={} transport={} caller={} result={} ms={}",
        d.method,
        d.transport.as_str(),
        caller_text(d.caller),
        result,
        d.micros / 1000
    )
}

/// The policy: whether a call gets a line, and whether it is reserved
pub fn decide(h: &mut Hour, d: &Done<'_>) -> Plan {
    let full = line(d);
    // An unknown method is only ever an error line, so a caller cannot
    // make up names that pass for state-changing ones
    let k = match d.error {
        Some((-32601, _)) => Kind::Other,
        _ => kind(d.method),
    };
    let known = h.note_method(d.method);
    let trusted = trusted(d);
    match k {
        Kind::Rare => {
            return Plan {
                line: Some(full),
                reserved: true,
            }
        }
        Kind::Secret | Kind::HighRate if trusted || k == Kind::Secret => {
            if !known {
                h.total_over += 1;
                return Plan::default();
            }
            let n = h.per_method.entry(d.method.to_string()).or_default();
            *n += 1;
            let first = *n == 1;
            if *n > PER_METHOD {
                *h.over.entry(d.method.to_string()).or_default() += 1;
                return Plan::default();
            }
            if h.total >= TOTAL {
                h.total_over += 1;
                return Plan {
                    line: None,
                    reserved: first,
                };
            }
            h.total += 1;
            return Plan {
                line: Some(full),
                reserved: first,
            };
        }
        Kind::HighRate => {
            // Remote and state-changing: the error-style cap
            let code = d.error.map_or(0, |e| e.0);
            if !known {
                return Plan::default();
            }
            let n = h
                .err_each
                .entry((d.method.to_string(), code, d.transport))
                .or_default();
            *n += 1;
            if *n > ERR_EACH || h.err_all >= ERR_ALL || h.total >= TOTAL {
                if *n <= ERR_EACH {
                    h.total_over += 1;
                }
                return Plan::default();
            }
            h.err_all += 1;
            h.total += 1;
            return Plan {
                line: Some(full),
                reserved: false,
            };
        }
        Kind::Other | Kind::Secret => {}
    }
    if let Some((code, _)) = d.error {
        if !known {
            return Plan::default();
        }
        let n = h
            .err_each
            .entry((d.method.to_string(), code, d.transport))
            .or_default();
        *n += 1;
        if *n <= ERR_EACH && h.err_all < ERR_ALL {
            h.err_all += 1;
            return Plan {
                line: Some(full),
                reserved: false,
            };
        }
        return Plan::default();
    }
    // The first call of each (method, caller) in the hour, for trusted
    // JSON-RPC callers only
    if d.transport == Transport::JsonRpc
        && trusted
        && known
        && h.first.len() < CALLERS_MAX
        && h.first
            .insert((d.method.to_string(), caller_text(d.caller)))
    {
        return Plan {
            line: Some(full),
            reserved: false,
        };
    }
    Plan::default()
}

/// One aggregate line's counts
#[derive(Default)]
struct Agg {
    n: u64,
    errors: BTreeMap<i64, u64>,
    micros: Vec<u64>,
    callers: HashSet<String>,
}

impl Agg {
    fn add(&mut self, d: &Done<'_>) {
        self.n += 1;
        if let Some((code, _)) = d.error {
            *self.errors.entry(code).or_default() += 1;
        }
        if self.micros.len() < SAMPLES_MAX {
            self.micros.push(d.micros);
        }
        if self.callers.len() < CALLERS_MAX {
            self.callers.insert(caller_text(d.caller));
        }
    }

    fn fields(&mut self, method: &str, transport: Transport) -> String {
        self.micros.sort_unstable();
        let at = |q: usize| {
            self.micros
                .get((self.micros.len().saturating_sub(1) * q) / 100)
                .map_or(0, |m| m / 1000)
        };
        let errors = if self.errors.is_empty() {
            "-".to_string()
        } else {
            self.errors
                .iter()
                .map(|(c, n)| format!("{}:{}", c, n))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "method={} transport={} n={} errors={} p50_ms={} p99_ms={} callers={}",
            method,
            transport.as_str(),
            self.n,
            errors,
            at(50),
            at(99),
            self.callers.len()
        )
    }
}

/// Counts for one interval (a minute or an hour)
#[derive(Default)]
struct Interval {
    start: u64,
    by: BTreeMap<(String, Transport), Agg>,
}

impl Interval {
    fn add(&mut self, d: &Done<'_>) {
        let known = self.by.len() < METHODS_MAX
            || self.by.contains_key(&(d.method.to_string(), d.transport));
        let method = if known { d.method } else { "other" };
        self.by
            .entry((method.to_string(), d.transport))
            .or_default()
            .add(d);
    }

    /// The lines of an interval that ended, and the counts reset
    fn take(&mut self, start: u64) -> Vec<String> {
        let by = std::mem::take(&mut self.by);
        self.start = start;
        by.into_iter()
            .map(|((m, t), mut a)| a.fields(&m, t))
            .collect()
    }
}

/// Error text with every value replaced by its kind (A15 "never
/// parameters"): quoted strings, numbers, and address- or hash-shaped
/// tokens; only the fixed text stays
pub fn mask(message: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    for word in split_keep(message) {
        if let Some(q) = quote {
            if word.ends_with(q) {
                quote = None;
            }
            continue;
        }
        let first = word.chars().next().unwrap_or(' ');
        if first == '"' || first == '\'' {
            out.push_str("<str>");
            if !(word.len() > 1 && word.ends_with(first)) {
                quote = Some(first);
            }
            continue;
        }
        let core = word.trim_end_matches([',', '.', ':', ';', ')']);
        let tail = &word[core.len()..];
        if !core.is_empty()
            && core
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
            && core.chars().any(|c| c.is_ascii_digit())
        {
            out.push_str("<num>");
            out.push_str(tail);
        } else if core.len() >= 20 && core.chars().all(|c| c.is_ascii_alphanumeric()) {
            out.push_str("<addr>");
            out.push_str(tail);
        } else if core.chars().any(|c| c.is_ascii_digit()) && core.len() >= 8 {
            out.push_str("<str>");
            out.push_str(tail);
        } else {
            out.push_str(word);
        }
    }
    out
}

/// Words and the spaces between them, in order
fn split_keep(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut space = None;
    for (i, c) in s.char_indices() {
        let is = c == ' ';
        if space != Some(is) {
            if i > start {
                out.push(&s[start..i]);
            }
            start = i;
            space = Some(is);
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// The reserved segments: one file per method in
/// `diag/rpc-methods-reserved/`, 1 MB in all; when full, the oldest line
/// of the method holding the most is dropped, rewriting only its segment
pub struct Reserved {
    dir: PathBuf,
    sizes: HashMap<String, u64>,
}

impl Reserved {
    pub fn open(dir: PathBuf) -> Reserved {
        let mut sizes = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some(m) = name.strip_suffix(".log") {
                    sizes.insert(m.to_string(), e.metadata().map_or(0, |m| m.len()));
                }
            }
        }
        Reserved { dir, sizes }
    }

    fn path(&self, method: &str) -> PathBuf {
        self.dir.join(format!("{}.log", method))
    }

    pub fn append(&mut self, method: &str, line: &str) {
        if method.is_empty()
            || !method
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
        {
            return;
        }
        // A14: not while the low-disk pause is on
        if crate::budget::paused() {
            return;
        }
        if crate::private_files::ensure_private_dir(&self.dir, true).is_err() {
            return;
        }
        let add = line.len() as u64 + 1;
        while self.sizes.values().sum::<u64>() + add > RESERVED_CAP {
            let Some((big, _)) = self
                .sizes
                .iter()
                .max_by_key(|(m, n)| (**n, std::cmp::Reverse((*m).clone())))
                .map(|(m, n)| (m.clone(), *n))
            else {
                break;
            };
            let path = self.path(&big);
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let rest = text.split_once('\n').map_or("", |(_, r)| r);
            if rest.is_empty() {
                let _ = std::fs::remove_file(&path);
                self.sizes.remove(&big);
            } else {
                let _ = crate::private_files::write_private_atomic(&path, rest.as_bytes());
                self.sizes.insert(big, rest.len() as u64);
            }
        }
        use std::io::Write as _;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        if let Ok(mut f) = options.open(self.path(method)) {
            if writeln!(f, "{}", line).is_ok() {
                *self.sizes.entry(method.to_string()).or_default() += add;
            }
        }
    }
}

struct State {
    hour: Hour,
    minute: Interval,
    hourly: Interval,
    errors: HashMap<String, VecDeque<String>>,
    reserved: Option<Reserved>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        let now = unix_now();
        Mutex::new(State {
            hour: Hour {
                start: now / 3600,
                ..Hour::default()
            },
            minute: Interval {
                start: now / 60,
                ..Interval::default()
            },
            hourly: Interval {
                start: now / 3600,
                ..Interval::default()
            },
            errors: HashMap::new(),
            reserved: None,
        })
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl State {
    /// Close the intervals that ended before `now`
    fn roll(&mut self, now: u64) {
        if now / 60 != self.minute.start {
            for l in self.minute.take(now / 60) {
                AGG_MINUTE.record("minute", &l);
            }
        }
        if now / 3600 != self.hourly.start {
            for l in self.hourly.take(now / 3600) {
                AGG_HOUR.record("hour", &l);
            }
        }
        if now / 3600 != self.hour.start {
            for l in self.hour.overflow_lines() {
                METHODS.record("suppressed", &l);
            }
            self.hour = Hour {
                start: now / 3600,
                ..Hour::default()
            };
        }
    }

    fn call(&mut self, d: &Done<'_>) {
        self.roll(unix_now());
        self.minute.add(d);
        self.hourly.add(d);
        let plan = decide(&mut self.hour, d);
        if let Some(l) = &plan.line {
            METHODS.record("call", l);
            // A12: a state-changing call, by name only, under the same caps
            if matches!(kind(d.method), Kind::Rare | Kind::Secret) {
                crate::events::event(
                    "rpc",
                    &format!(
                        "method={} transport={} result={}",
                        d.method,
                        d.transport.as_str(),
                        if d.error.is_some() { "error" } else { "ok" }
                    ),
                );
            }
        }
        if plan.reserved {
            if let Some(r) = self.reserved.as_mut() {
                r.append(
                    d.method,
                    &format!("{} {}", crate::runs_log::utc_now(), line(d)),
                );
            }
        }
        if let Some((code, msg)) = d.error {
            if self.errors.len() < METHODS_MAX || self.errors.contains_key(d.method) {
                let kept = self.errors.entry(d.method.to_string()).or_default();
                if kept.len() == KEEP_ERRORS {
                    kept.pop_front();
                }
                kept.push_back(format!("{} {}", code, mask(msg)));
            }
        }
    }
}

/// Transactions a local caller submitted for broadcast, accepted or not
/// (A15 "sent from here"): `diag/sent-txids`, mode 0600, one txid and UTC
/// day per line, never packaged. The node treats them as the user's own.
pub struct Sent {
    path: PathBuf,
    lines: VecDeque<String>,
    bytes: usize,
    set: HashSet<divi_primitives::hash::Hash256>,
}

impl Sent {
    pub fn open(path: PathBuf) -> Sent {
        let mut sent = Sent {
            path,
            lines: VecDeque::new(),
            bytes: 0,
            set: HashSet::new(),
        };
        let text = std::fs::read_to_string(&sent.path).unwrap_or_default();
        for l in text.lines() {
            let Some(hex) = l.split(' ').next() else {
                continue;
            };
            if let Ok(h) = divi_primitives::hash::Hash256::from_hex(hex) {
                sent.set.insert(h);
                sent.bytes += l.len() + 1;
                sent.lines.push_back(l.to_string());
            }
        }
        sent
    }

    pub fn contains(&self, txid: &divi_primitives::hash::Hash256) -> bool {
        self.set.contains(txid)
    }

    pub fn add(&mut self, txid: &divi_primitives::hash::Hash256, day: &str) {
        if !self.set.insert(*txid) {
            return;
        }
        let l = format!("{} {}", txid.to_hex(), day);
        self.bytes += l.len() + 1;
        self.lines.push_back(l);
        // A14: the file catches up after the low-disk pause
        if crate::budget::paused() {
            return;
        }
        if let Some(dir) = self.path.parent() {
            if crate::private_files::ensure_private_dir(dir, true).is_err() {
                return;
            }
        }
        if self.bytes > SENT_CAP {
            while self.bytes > SENT_CAP * 3 / 4 {
                let Some(old) = self.lines.pop_front() else {
                    break;
                };
                self.bytes -= old.len() + 1;
                if let Some(h) = old
                    .split(' ')
                    .next()
                    .and_then(|x| divi_primitives::hash::Hash256::from_hex(x).ok())
                {
                    self.set.remove(&h);
                }
            }
            let mut text = String::with_capacity(self.bytes);
            for l in &self.lines {
                text.push_str(l);
                text.push('\n');
            }
            let _ = crate::private_files::write_private_atomic(&self.path, text.as_bytes());
            return;
        }
        use std::io::Write as _;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        if let Ok(mut f) = options.open(&self.path) {
            let _ = writeln!(f, "{}", self.lines.back().map_or("", |l| l.as_str()));
        }
    }
}

fn sent_store() -> &'static Mutex<Option<Sent>> {
    static SENT: OnceLock<Mutex<Option<Sent>>> = OnceLock::new();
    SENT.get_or_init(|| Mutex::new(None))
}

/// Whether a local caller submitted this transaction (A12 keeps it out
/// of `chain-events.log` like the wallet's own)
pub fn is_sent(txid: &divi_primitives::hash::Hash256) -> bool {
    sent_store()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|s| s.contains(txid))
}

/// Txids submitted locally from `diag/sent-txids` (`getdiaginfo` A10 `known_values`);
/// non-blocking so it never stalls when the store lock is contended.
pub fn sent_txids() -> Vec<String> {
    let guard = match sent_store().try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return Vec::new(),
    };
    let Some(sent) = guard.as_ref() else {
        return Vec::new();
    };
    let mut out: Vec<String> = sent.set.iter().map(|h| h.to_hex()).collect();
    out.sort();
    out
}

/// The logs go into `<data_dir>/diag`, and the sink is installed
pub fn install(data_dir: &Path) {
    let diag = data_dir.join("diag");
    for log in [&METHODS, &AGG_MINUTE, &AGG_HOUR] {
        log.set_dir(&diag);
    }
    state().lock().unwrap_or_else(|e| e.into_inner()).reserved =
        Some(Reserved::open(diag.join("rpc-methods-reserved")));
    diag_rpc::install(Box::new(|d| {
        state().lock().unwrap_or_else(|e| e.into_inner()).call(d);
    }));
    *sent_store().lock().unwrap_or_else(|e| e.into_inner()) =
        Some(Sent::open(diag.join("sent-txids")));
    diag_rpc::install_sent(Box::new(|txid| {
        let day = crate::runs_log::utc_now();
        if let Some(s) = sent_store()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            s.add(txid, &day[..day.len().min(10)]);
        }
    }));
}

/// Close the intervals that ended (the health tick calls it, so a quiet
/// minute after a busy one is still written)
pub fn tick() {
    state()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .roll(unix_now());
}

/// The last masked error messages per method (`getdiaginfo`, A10);
/// `None` while another thread holds the table (the incident writer and
/// the panic hook read it, so it never waits)
pub fn recent_errors() -> Option<BTreeMap<String, Vec<String>>> {
    let st = match state().try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return None,
    };
    Some(
        st.errors
            .iter()
            .map(|(m, v)| (m.clone(), v.iter().cloned().collect()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn sent_txids_persist_and_drop_the_oldest_quarter_when_full() {
        use divi_primitives::hash::Hash256;
        let dir = std::env::temp_dir().join(format!("rpc-log-sent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("diag").join("sent-txids");
        let h = |i: u32| {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            Hash256(b)
        };
        let mut s = Sent::open(path.clone());
        s.add(&h(1), "2026-10-31");
        s.add(&h(1), "2026-10-31");
        assert!(s.contains(&h(1)));
        assert!(!s.contains(&h(2)));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, format!("{} 2026-10-31\n", h(1).to_hex()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Reopened: the set comes back from the file
        let mut s = Sent::open(path.clone());
        assert!(s.contains(&h(1)));
        // Fill past 1 MB: the oldest go, the newest stay, the file shrinks
        let per = 64 + 1 + 10 + 1;
        let n = (SENT_CAP / per + 2) as u32;
        for i in 2..n + 2 {
            s.add(&h(i), "2026-10-31");
        }
        assert!(!s.contains(&h(1)));
        assert!(s.contains(&h(n + 1)));
        let len = std::fs::metadata(&path).unwrap().len() as usize;
        assert!(len <= SENT_CAP, "{}", len);
        let again = Sent::open(path);
        assert!(again.contains(&h(n + 1)));
        assert!(!again.contains(&h(1)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn done<'a>(m: &'a str, t: Transport, ip: [u8; 4], err: Option<(i64, &'a str)>) -> Done<'a> {
        Done {
            method: m,
            transport: t,
            caller: Some(IpAddr::V4(Ipv4Addr::from(ip))),
            authenticated: false,
            error: err,
            micros: 1500,
        }
    }
    const LO: [u8; 4] = [127, 0, 0, 1];
    const FAR: [u8; 4] = [203, 0, 113, 9];

    #[test]
    fn methods_are_sorted_into_the_a15_kinds() {
        assert_eq!(kind("stop"), Kind::Rare);
        assert_eq!(kind("backupwallet"), Kind::Rare);
        assert_eq!(kind("importprivkey"), Kind::Secret);
        assert_eq!(kind("dumpwallet"), Kind::Secret);
        assert_eq!(kind("walletpassphrase"), Kind::Secret);
        assert_eq!(kind("sendtoaddress"), Kind::HighRate);
        assert_eq!(kind("blockchain.transaction.broadcast"), Kind::HighRate);
        assert_eq!(kind("signrawtransaction"), Kind::HighRate);
        assert_eq!(kind("getinfo"), Kind::Other);
    }

    #[test]
    fn rare_calls_are_never_capped_and_always_reserved() {
        let mut h = Hour::default();
        for _ in 0..500 {
            let p = decide(&mut h, &done("stop", Transport::JsonRpc, FAR, None));
            assert!(p.line.is_some() && p.reserved);
        }
    }

    #[test]
    fn a_polling_client_costs_one_line_an_hour_and_remote_ones_none() {
        let mut h = Hour::default();
        let p = decide(&mut h, &done("getinfo", Transport::JsonRpc, LO, None));
        assert_eq!(
            p.line.as_deref(),
            Some("method=getinfo transport=jsonrpc caller=loopback result=ok ms=1")
        );
        assert!(!p.reserved);
        for _ in 0..100 {
            assert_eq!(
                decide(&mut h, &done("getinfo", Transport::JsonRpc, LO, None)),
                Plan::default()
            );
        }
        // Electrum and remote unauthenticated callers: no first-call line
        assert!(
            decide(&mut h, &done("server.ping", Transport::Electrum, FAR, None))
                .line
                .is_none()
        );
        let mut d = done("getinfo", Transport::JsonRpc, FAR, None);
        assert!(decide(&mut h, &d).line.is_none());
        d.authenticated = true;
        let p = decide(&mut h, &d);
        assert!(p.line.unwrap().contains("caller=peer-"));
    }

    #[test]
    fn capped_methods_stop_at_100_each_and_200_in_all() {
        let mut h = Hour::default();
        let mut lines = 0;
        let mut reserved = 0;
        for m in ["sendtoaddress", "signrawtransaction", "importaddress"] {
            for _ in 0..150 {
                let p = decide(&mut h, &done(m, Transport::JsonRpc, LO, None));
                lines += p.line.is_some() as u32;
                reserved += p.reserved as u32;
            }
        }
        assert_eq!(lines, TOTAL);
        // The first of each capped method in the hour is reserved, even
        // one the total cap left out
        assert_eq!(reserved, 3);
        let over = h.overflow_lines();
        assert!(over.contains(&"sendtoaddress: 50 more calls not listed".to_string()));
        assert!(over.contains(&"importaddress: 50 more calls not listed".to_string()));
        assert_eq!(
            over.last().unwrap(),
            "100 more calls suppressed (total cap)"
        );
        // A rare call still gets through after the total cap
        assert!(decide(&mut h, &done("stop", Transport::JsonRpc, LO, None))
            .line
            .is_some());
    }

    #[test]
    fn a_remote_broadcast_flood_gets_the_error_style_cap() {
        let mut h = Hour::default();
        let m = "blockchain.transaction.broadcast";
        let mut lines = 0;
        for _ in 0..1000 {
            lines += decide(&mut h, &done(m, Transport::Electrum, FAR, Some((1, "x"))))
                .line
                .is_some() as u32;
        }
        assert_eq!(lines, ERR_EACH);
        // Secret methods are capped per method whoever calls them
        let p = decide(
            &mut h,
            &done("walletpassphrase", Transport::WebUi, FAR, None),
        );
        assert!(p.line.is_some() && p.reserved);
    }

    #[test]
    fn errors_are_listed_five_per_code_and_fifty_in_all() {
        let mut h = Hour::default();
        let mut lines = 0;
        for code in 0..20 {
            for _ in 0..10 {
                lines += decide(
                    &mut h,
                    &done("getblock", Transport::JsonRpc, LO, Some((code, "e"))),
                )
                .line
                .is_some() as u32;
            }
        }
        assert_eq!(lines, ERR_ALL);
        // An unknown method that looks state-changing is only an error line
        let p = decide(
            &mut h,
            &done("sendfake", Transport::JsonRpc, LO, Some((-32601, "nope"))),
        );
        assert!(p.line.is_none() && !p.reserved);
    }

    #[test]
    fn error_text_keeps_only_the_fixed_words() {
        assert_eq!(
            mask("Invalid Divi address: DQh3ZQ9hn9UiRrj8q6nYwM6ezrzuPYnKkQ"),
            "Invalid Divi address: <addr>"
        );
        assert_eq!(
            mask("Invalid passphrase for \"my savings\" after 3 tries"),
            "Invalid passphrase for <str> after <num> tries"
        );
        assert_eq!(
            mask("amount 1.23456789 too small."),
            "amount <num> too small."
        );
        assert_eq!(mask("bad-txns-in-belowout"), "bad-txns-in-belowout");
    }

    #[test]
    fn aggregates_have_counts_errors_percentiles_and_callers() {
        let mut i = Interval::default();
        for n in 0..10u64 {
            let mut d = done("getinfo", Transport::JsonRpc, [10, 0, 0, n as u8 % 3], None);
            d.micros = (n + 1) * 1000;
            if n == 9 {
                d.error = Some((-5, "x"));
            }
            i.add(&d);
        }
        assert_eq!(
            i.take(1),
            vec!["method=getinfo transport=jsonrpc n=10 errors=-5:1 p50_ms=5 p99_ms=9 callers=3"]
        );
        assert!(i.take(2).is_empty());
    }

    #[test]
    fn the_reserved_segments_drop_the_biggest_methods_oldest_line() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = Reserved::open(dir.path().join("res"));
        r.append("stop", "first stop");
        let long = "x".repeat(1000);
        for _ in 0..1100 {
            r.append("backupwallet", &long);
        }
        let stop = std::fs::read_to_string(dir.path().join("res/stop.log")).unwrap();
        assert_eq!(stop, "first stop\n");
        let total: u64 = std::fs::read_dir(dir.path().join("res"))
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        assert!(total <= RESERVED_CAP, "{total}");
        // A name that is not a plain method name never becomes a file
        r.append("../x", "no");
        assert!(!dir.path().join("x.log").exists());
    }
}
