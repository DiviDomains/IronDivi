// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A tiny UTXO set for one P2PKH key, for a chain with no address or spent index.
//!
//! Coins enter via [`Wallet::apply_tx`] (a txid we were told about, a block scan, or a
//! transaction we broadcast). Selected coins are *reserved* until their spending transaction
//! is broadcast (then they are tombstoned) or the reservation is dropped. Only public data
//! is persisted.
//!
//! More than one process may hold the same file (two `divi-swap` takers on one wallet).
//! Each write, and [`Wallet::refresh`], first takes in the tombstones and exclusions another
//! process wrote, so one process's write never brings back a coin the other spent; only a
//! coin this process gave back itself ([`Wallet::release_dead_tx`]) is left untombstoned.
//! Which process selects which coin is settled by the swap database's `input_reservation`
//! table, not here.
//!
//! A write goes to `<wallet file name>.tmp.<pid>.<n>` and is renamed over the file; a write
//! that fails removes its own temporary file. One left by a process that died mid-write is
//! removed by the next [`Wallet::open`], once no running process has that pid and the file
//! is older than [`STALE_TEMP_FILE_AGE`]. The age matters for a writer in another pid
//! namespace (a container sharing the wallet volume): it looks dead from here, but its
//! in-flight file is only milliseconds old. The temporary file write may take at most
//! [`WRITE_TIMEOUT`] (a tenth of that age); one that takes longer is abandoned, its file
//! removed and never renamed, and the write is an error.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use divi_swap::{Outpoint, SwapError, Txid};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One spendable output paying the wallet's P2PKH script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    /// Where it lives.
    pub outpoint: Outpoint,
    /// Value in satoshis.
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Reservation {
    utxo: Utxo,
    by: Txid,
}

/// Persisted wallet state.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Wallet {
    utxos: Vec<Utxo>,
    reserved: Vec<Reservation>,
    spent: Vec<Outpoint>,
    excluded: Vec<Txid>,
    /// Next block height a scan should start at.
    pub scanned_height: Option<u64>,
    #[serde(skip)]
    path: Option<PathBuf>,
    /// Tombstones this process lifted ([`Self::release_dead_tx`]): a copy of them still on
    /// disk is not taken back in.
    #[serde(skip)]
    revived: Vec<Outpoint>,
}

impl Wallet {
    /// Load from `path` (created empty if missing); `None` keeps everything in memory.
    /// Temporary files of writers that are no longer running are removed first.
    pub fn open(path: Option<PathBuf>) -> Result<Self, SwapError> {
        if let Some(p) = &path {
            sweep_dead_temp_files(p);
        }
        let mut w = match &path {
            Some(p) if p.exists() => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| SwapError::Storage(format!("read {}: {e}", p.display())))?;
                serde_json::from_str::<Wallet>(&text)
                    .map_err(|e| SwapError::Storage(format!("parse {}: {e}", p.display())))?
            }
            _ => Wallet::default(),
        };
        w.path = path;
        Ok(w)
    }

    /// Take in the tombstones and exclusions another process on the same file wrote since
    /// this one read it. An unreadable file adds nothing (the next write replaces it).
    pub fn refresh(&mut self) {
        let Some(p) = &self.path else { return };
        let Some(disk) = std::fs::read_to_string(p)
            .ok()
            .and_then(|t| serde_json::from_str::<Wallet>(&t).ok())
        else {
            return;
        };
        for op in disk.spent {
            if !self.revived.contains(&op) {
                self.mark_spent(op);
            }
        }
        for txid in disk.excluded {
            if !self.excluded.contains(&txid) {
                self.excluded.push(txid);
                self.utxos.retain(|u| u.outpoint.txid != txid);
            }
        }
    }

    fn persist(&mut self) -> Result<(), SwapError> {
        self.persist_with(WRITE_TIMEOUT, |tmp, bytes| std::fs::write(tmp, bytes))
    }

    /// [`Self::persist`] with the temporary file written by `writer` (a test seam) under
    /// `bound`. A write that has not answered within `bound` is a `Storage` error; the
    /// wallet file is left as it was, and the in-memory state keeps the caller's change,
    /// as after any other failed write.
    fn persist_with(&mut self, bound: Duration, writer: TempWriter) -> Result<(), SwapError> {
        self.refresh();
        static WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let Some(p) = &self.path else { return Ok(()) };
        // Each write has its own temporary file: two processes (or two backends in one) on
        // the same wallet file must not interleave their bytes in one before the rename.
        let n = WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = temp_path(p, std::process::id(), n);
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| SwapError::Storage(format!("serialize wallet: {e}")))?;
        write_temp_file(&tmp, text.into_bytes(), bound, writer)
            .and_then(|_| std::fs::rename(&tmp, p))
            .map_err(|e| {
                // Ours alone (our pid and counter); it may not exist if the write failed early.
                let _ = std::fs::remove_file(&tmp);
                SwapError::Storage(format!("write {}: {e}", p.display()))
            })
    }

    /// Never use outputs of `txid` (e.g. another process's probe funds).
    pub fn exclude_txid(&mut self, txid: Txid) -> Result<(), SwapError> {
        if !self.excluded.contains(&txid) {
            self.excluded.push(txid);
            self.utxos.retain(|u| u.outpoint.txid != txid);
        }
        self.persist()
    }

    /// Spendable (known, unreserved) coins.
    pub fn available(&self) -> Vec<Utxo> {
        self.utxos.to_vec()
    }

    /// Total of spendable coins.
    pub fn balance(&self) -> u64 {
        self.utxos.iter().map(|u| u.value).sum()
    }

    /// Number of currently reserved coins.
    pub fn reserved_count(&self) -> usize {
        self.reserved.len()
    }

    /// Learn from a verbose `getrawtransaction`/block-tx JSON: drop coins it spends, add
    /// outputs paying `spk_hex`. Returns how many coins were added.
    pub fn apply_tx(&mut self, tx: &Value, spk_hex: &str) -> Result<usize, SwapError> {
        let txid: Txid = tx["txid"]
            .as_str()
            .ok_or_else(|| SwapError::Other("tx json without txid".into()))?
            .parse()?;
        if let Some(vin) = tx["vin"].as_array() {
            for i in vin {
                let (Some(t), Some(n)) = (i["txid"].as_str(), i["vout"].as_u64()) else {
                    continue;
                };
                let op = Outpoint {
                    txid: t.parse()?,
                    vout: n as u32,
                };
                self.mark_spent(op);
            }
        }
        let mut added = 0;
        if !self.excluded.contains(&txid) {
            for o in tx["vout"].as_array().into_iter().flatten() {
                if o["scriptPubKey"]["hex"].as_str() != Some(spk_hex) {
                    continue;
                }
                let vout = o["n"].as_u64().unwrap_or(0) as u32;
                let value = o["valueSat"]
                    .as_u64()
                    .or_else(|| o["value"].as_f64().map(|v| (v * 1e8).round() as u64))
                    .ok_or_else(|| SwapError::Other("output without value".into()))?;
                added += usize::from(self.add(Utxo {
                    outpoint: Outpoint { txid, vout },
                    value,
                }));
            }
        }
        self.persist()?;
        Ok(added)
    }

    fn add(&mut self, u: Utxo) -> bool {
        let known = self.utxos.iter().any(|k| k.outpoint == u.outpoint)
            || self.reserved.iter().any(|r| r.utxo.outpoint == u.outpoint)
            || self.spent.contains(&u.outpoint);
        if !known {
            self.utxos.push(u);
        }
        !known
    }

    fn mark_spent(&mut self, op: Outpoint) {
        self.revived.retain(|r| *r != op);
        self.utxos.retain(|u| u.outpoint != op);
        self.reserved.retain(|r| r.utxo.outpoint != op);
        if !self.spent.contains(&op) {
            self.spent.push(op);
        }
    }

    /// Move `coins` from spendable to reserved for the transaction `by`.
    pub fn reserve(&mut self, coins: &[Utxo], by: Txid) -> Result<(), SwapError> {
        self.utxos.retain(|u| !coins.contains(u));
        for c in coins {
            self.reserved.push(Reservation { utxo: *c, by });
        }
        self.persist()
    }

    /// Give back the coins reserved for `by` (the transaction will not be sent).
    pub fn release(&mut self, by: &Txid) -> Result<(), SwapError> {
        let all = std::mem::take(&mut self.reserved);
        let (back, keep): (Vec<Reservation>, Vec<Reservation>) =
            all.into_iter().partition(|r| &r.by == by);
        let back: Vec<Utxo> = back.into_iter().map(|r| r.utxo).collect();
        self.reserved = keep;
        self.utxos.extend(back);
        self.persist()
    }

    /// Give back every reservation whose transaction is not in `keep` (reservations are
    /// persisted, so one made just before a crash outlives the process). Returns the
    /// distinct transactions released, in reservation order.
    pub fn release_unreferenced(&mut self, keep: &[Txid]) -> Result<Vec<Txid>, SwapError> {
        let all = std::mem::take(&mut self.reserved);
        let (kept, orphan): (Vec<Reservation>, Vec<Reservation>) =
            all.into_iter().partition(|r| keep.contains(&r.by));
        let mut released: Vec<Txid> = Vec::new();
        for r in &orphan {
            if !released.contains(&r.by) {
                released.push(r.by);
            }
        }
        self.reserved = kept;
        self.utxos.extend(orphan.into_iter().map(|r| r.utxo));
        self.persist()?;
        Ok(released)
    }
}

impl Wallet {
    /// Record that a transaction we built was accepted by the chain: its inputs are spent
    /// for good and its outputs paying us (change, claim/refund proceeds) become coins.
    pub fn record_broadcast(
        &mut self,
        inputs: &[Outpoint],
        own_outputs: &[Utxo],
    ) -> Result<(), SwapError> {
        for op in inputs {
            self.mark_spent(*op);
        }
        for u in own_outputs {
            self.add(*u);
        }
        self.persist()
    }
}

impl Wallet {
    /// Undo [`record_broadcast`](Self::record_broadcast) for a transaction that can never
    /// confirm: drop every coin created by `txid` (its phantom change) and give the
    /// tombstoned `inputs` back as spendable coins. Returns whether anything changed, so a
    /// repeat call is a no-op. An input that is not tombstoned (never recorded, or already
    /// released and perhaps reserved again) is left alone.
    pub fn release_dead_tx(&mut self, txid: Txid, inputs: &[Utxo]) -> Result<bool, SwapError> {
        let before = self.utxos.len() + self.reserved.len();
        self.utxos.retain(|u| u.outpoint.txid != txid);
        self.reserved.retain(|r| r.utxo.outpoint.txid != txid);
        let mut changed = self.utxos.len() + self.reserved.len() != before;
        for u in inputs {
            if let Some(i) = self.spent.iter().position(|s| *s == u.outpoint) {
                self.spent.remove(i);
                self.revived.push(u.outpoint);
                self.add(*u);
                changed = true;
            }
        }
        if changed {
            self.persist()?;
        }
        Ok(changed)
    }
}

/// A dead writer's temporary file is removed only once its mtime is at least this old. A
/// write takes milliseconds; ten minutes leaves room for a slow disk or a paused container.
const STALE_TEMP_FILE_AGE: Duration = Duration::from_secs(10 * 60);

/// How long the temporary file write of [`Wallet::persist`] may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Writes a wallet's temporary file.
type TempWriter = fn(&Path, &[u8]) -> std::io::Result<()>;

/// Write `tmp` with `writer` on its own thread, waiting at most `bound`; only an answer in
/// time lets the caller rename `tmp`. `bound` is far below [`STALE_TEMP_FILE_AGE`], so a
/// file we rename is never old enough for another process's sweep. Past it the write is
/// abandoned: the caller removes `tmp`, and the thread, should its write ever return, finds
/// nobody waiting and removes `tmp` itself, so a late write is never renamed over anything.
fn write_temp_file(
    tmp: &Path,
    bytes: Vec<u8>,
    bound: Duration,
    writer: TempWriter,
) -> std::io::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let path = tmp.to_path_buf();
    let thread = std::thread::Builder::new()
        .name("wallet-write".into())
        .spawn(move || {
            let res = writer(&path, &bytes);
            if tx.send(res).is_err() {
                let _ = std::fs::remove_file(&path);
            }
        })?;
    match rx.recv_timeout(bound) {
        Ok(res) => {
            let _ = thread.join();
            res
        }
        Err(e) => {
            // Dropped before the caller removes `tmp`: whichever runs last removes it.
            drop(rx);
            let (kind, why) = match e {
                std::sync::mpsc::RecvTimeoutError::Timeout => (
                    std::io::ErrorKind::TimedOut,
                    format!("the temporary file write did not finish within {bound:?}"),
                ),
                std::sync::mpsc::RecvTimeoutError::Disconnected => (
                    std::io::ErrorKind::Other,
                    "the temporary file writer stopped".to_string(),
                ),
            };
            Err(std::io::Error::new(
                kind,
                format!("{why}; the wallet file is unchanged"),
            ))
        }
    }
}

/// Whether a file modified at `mtime` is old enough to be swept at `now`. An mtime in the
/// future is not.
fn is_stale(mtime: SystemTime, now: SystemTime) -> bool {
    now.duration_since(mtime)
        .is_ok_and(|age| age >= STALE_TEMP_FILE_AGE)
}

/// The temporary file of write `n` by process `pid` to `wallet`.
fn temp_path(wallet: &Path, pid: u32, n: u64) -> PathBuf {
    let mut name = wallet.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{pid}.{n}"));
    wallet.with_file_name(name)
}

/// The writer pid in `name` if it is exactly `<wallet_name>.tmp.<pid>.<n>` (digits only).
fn temp_file_pid(name: &str, wallet_name: &str) -> Option<u32> {
    let rest = name.strip_prefix(wallet_name)?.strip_prefix(".tmp.")?;
    let (pid, n) = rest.split_once('.')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(pid) || !digits(n) {
        return None;
    }
    n.parse::<u64>().ok()?;
    pid.parse().ok()
}

/// Whether a process with this pid is running. When it cannot be told, it is taken to be
/// running, so its file is kept.
fn pid_running(pid: u32) -> bool {
    if Path::new("/proc/self").exists() {
        return Path::new(&format!("/proc/{pid}")).exists();
    }
    if cfg!(unix) {
        // macOS and other Unix without /proc: `ps -p` succeeds when the pid exists, whatever
        // its owner (unlike `kill -0`).
        return std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "pid="])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_or(true, |s| s.success());
    }
    true
}

/// Remove the temporary files next to `wallet` left by writers that are no longer running,
/// once older than [`STALE_TEMP_FILE_AGE`]; a file whose mtime cannot be read, or is in the
/// future, is kept. Only regular files are removed (never a symlink or what it points to); errors are
/// ignored, as another process may sweep the same file.
fn sweep_dead_temp_files(wallet: &Path) {
    let Some(wallet_name) = wallet.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let dir = match wallet.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| temp_file_pid(n, wallet_name)) else {
            continue;
        };
        // `file_type` does not follow symlinks.
        if !entry.file_type().is_ok_and(|t| t.is_file()) || pid_running(pid) {
            continue;
        }
        // `DirEntry::metadata` does not follow symlinks either.
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| is_stale(t, SystemTime::now()));
        if !stale {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => tracing::info!("removed stale wallet temp file {}", entry.path().display()),
            Err(e) => tracing::debug!("stale wallet temp file {}: {e}", entry.path().display()),
        }
    }
}

#[cfg(test)]
mod orphan_tests {
    use super::*;

    fn coin(n: u8, value: u64) -> Utxo {
        Utxo {
            outpoint: Outpoint {
                txid: Txid([n; 32]),
                vout: 0,
            },
            value,
        }
    }

    #[test]
    fn release_unreferenced_frees_only_reservations_outside_keep() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let (a, b, c) = (Txid([0xa; 32]), Txid([0xb; 32]), Txid([0xc; 32]));
        let mut w = Wallet::open(Some(path.clone())).unwrap();
        w.utxos = vec![coin(1, 10), coin(2, 20), coin(3, 30)];
        w.reserve(&[coin(1, 10)], a).unwrap();
        w.reserve(&[coin(2, 20), coin(3, 30)], b).unwrap();
        // Reloaded from disk: what a restarted process sees.
        let mut w = Wallet::open(Some(path.clone())).unwrap();
        assert_eq!(w.reserved_count(), 3);
        assert_eq!(w.release_unreferenced(&[a, c]).unwrap(), vec![b]);
        assert_eq!(w.reserved_count(), 1, "a's coin stays reserved");
        assert_eq!(w.balance(), 50, "b's two coins are spendable again");
        assert!(
            w.release_unreferenced(&[a]).unwrap().is_empty(),
            "idempotent"
        );
        assert_eq!(
            Wallet::open(Some(path)).unwrap().reserved_count(),
            1,
            "persisted"
        );
    }

    #[test]
    fn a_write_never_brings_back_a_coin_another_process_spent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut seed = Wallet::open(Some(path.clone())).unwrap();
        seed.record_broadcast(&[], &[coin(1, 10), coin(2, 20)])
            .unwrap();
        // Two processes read the same file.
        let mut a = Wallet::open(Some(path.clone())).unwrap();
        let mut b = Wallet::open(Some(path.clone())).unwrap();
        a.record_broadcast(&[coin(1, 10).outpoint], &[]).unwrap();
        // `b` never saw `a`'s lock: its write keeps `a`'s tombstone, and it takes it in.
        b.record_broadcast(&[coin(2, 20).outpoint], &[]).unwrap();
        assert!(b.available().is_empty(), "{:?}", b.available());
        assert!(Wallet::open(Some(path.clone()))
            .unwrap()
            .available()
            .is_empty());
        // An exclusion travels the same way.
        let mut c = Wallet::open(Some(path.clone())).unwrap();
        c.record_broadcast(&[], &[coin(3, 30)]).unwrap();
        let mut d = Wallet::open(Some(path.clone())).unwrap();
        c.exclude_txid(Txid([3; 32])).unwrap();
        d.refresh();
        assert!(d.available().is_empty());
    }

    #[test]
    fn a_coin_this_process_gave_back_is_not_tombstoned_again_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut w = Wallet::open(Some(path.clone())).unwrap();
        w.record_broadcast(&[], &[coin(1, 10)]).unwrap();
        w.record_broadcast(&[coin(1, 10).outpoint], &[]).unwrap();
        // A stale process still holding the tombstone writes after the give-back.
        let mut stale = Wallet::open(Some(path.clone())).unwrap();
        assert!(w.release_dead_tx(Txid([9; 32]), &[coin(1, 10)]).unwrap());
        stale.record_broadcast(&[], &[]).unwrap();
        w.refresh();
        assert_eq!(w.available(), vec![coin(1, 10)], "this process keeps it");
        // A real spend of it later is tombstoned as usual.
        w.record_broadcast(&[coin(1, 10).outpoint], &[]).unwrap();
        assert!(w.available().is_empty());
    }
}

#[cfg(test)]
mod temp_file_tests {
    use super::*;
    use std::path::Path;

    fn coin(n: u8, value: u64) -> Utxo {
        Utxo {
            outpoint: Outpoint {
                txid: Txid([n; 32]),
                vout: 0,
            },
            value,
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    /// The pid of a child that has exited and been reaped: no running process has it.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// Set the mtime of `path` to `secs` seconds ago (negative: in the future).
    fn set_age(path: &Path, secs: i64) {
        let now = std::time::SystemTime::now();
        let d = std::time::Duration::from_secs(secs.unsigned_abs());
        let t = if secs >= 0 { now - d } else { now + d };
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    /// Older than the sweep's age threshold (10 minutes).
    const OLD: i64 = 11 * 60;

    #[test]
    fn a_failed_write_removes_its_own_temp_file_and_returns_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut w = Wallet::open(Some(path.clone())).unwrap();
        // A directory where the wallet file should be: the temp file is written, the
        // rename over it fails.
        std::fs::create_dir(&path).unwrap();
        let err = w.record_broadcast(&[], &[coin(1, 10)]).unwrap_err();
        assert!(matches!(err, SwapError::Storage(_)), "{err:?}");
        assert_eq!(names(dir.path()), vec!["w.json".to_string()]);
        // The write itself fails (no such directory): an error, and nothing left behind.
        let gone = dir.path().join("gone");
        let mut w = Wallet::open(Some(gone.join("w.json"))).unwrap();
        assert!(w.record_broadcast(&[], &[coin(1, 10)]).is_err());
        assert!(!gone.exists());
        assert_eq!(names(dir.path()), vec!["w.json".to_string()]);
    }

    #[test]
    fn opening_a_wallet_removes_only_dead_writers_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut w = Wallet::open(Some(path.clone())).unwrap();
        w.record_broadcast(&[], &[coin(1, 10)]).unwrap();
        let wallet_bytes = std::fs::read(&path).unwrap();
        let (dead, live) = (dead_pid(), std::process::id());
        let touch = |name: String| std::fs::write(dir.path().join(name), b"partial").unwrap();
        let swept = [
            format!("w.json.tmp.{dead}.0"),
            format!("w.json.tmp.{dead}.17"),
        ];
        let kept = [
            // A running writer (this test stands in for it).
            format!("w.json.tmp.{live}.3"),
            // Other wallets in the same directory.
            format!("other.json.tmp.{dead}.0"),
            format!("w.json2.tmp.{dead}.0"),
            format!("x.w.json.tmp.{dead}.0"),
            // Not the exact pattern.
            format!("w.json.tmp.{dead}"),
            format!("w.json.tmp.{dead}."),
            "w.json.tmp..0".to_string(),
            format!("w.json.tmp.{dead}.0.bak"),
            format!("w.json.tmp.{dead}.x"),
            format!("w.json.tmp.+{dead}.0"),
            format!("w.json.tmp.{dead}.+0"),
            format!("w.json.TMP.{dead}.0"),
        ];
        for n in swept.iter().chain(&kept) {
            touch(n.clone());
            // Every file is old: only the pid and the name decide here.
            set_age(&dir.path().join(n), OLD);
        }
        // A symlink and a directory with a matching name are never removed, nor is what
        // the symlink points to.
        let target = dir.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, dir.path().join(format!("w.json.tmp.{dead}.5")))
            .unwrap();
        std::fs::create_dir(dir.path().join(format!("w.json.tmp.{dead}.6"))).unwrap();

        let w = Wallet::open(Some(path.clone())).unwrap();
        assert_eq!(w.available(), vec![coin(1, 10)]);
        let mut expect: Vec<String> = kept.to_vec();
        expect.extend([
            "w.json".to_string(),
            "target".to_string(),
            format!("w.json.tmp.{dead}.6"),
        ]);
        #[cfg(unix)]
        expect.push(format!("w.json.tmp.{dead}.5"));
        expect.sort();
        assert_eq!(names(dir.path()), expect);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            wallet_bytes,
            "wallet unchanged"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        for n in &kept {
            assert_eq!(
                std::fs::read(dir.path().join(n)).unwrap(),
                b"partial",
                "{n}"
            );
        }
    }

    #[test]
    fn a_crash_before_the_first_rename_is_swept_with_no_wallet_file_yet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let dead = dead_pid();
        let tmp = dir.path().join(format!("w.json.tmp.{dead}.0"));
        std::fs::write(&tmp, b"{").unwrap();
        set_age(&tmp, OLD);
        let w = Wallet::open(Some(path.clone())).unwrap();
        assert!(w.available().is_empty());
        assert!(names(dir.path()).is_empty(), "{:?}", names(dir.path()));
    }
    #[test]
    fn a_dead_writers_temp_file_is_removed_only_once_it_is_old() {
        // A writer in another pid namespace (a container sharing the wallet volume) looks
        // dead from here; its in-flight file is recent, so it is kept.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let dead = dead_pid();
        let file = |n: u32| dir.path().join(format!("w.json.tmp.{dead}.{n}"));
        let ages: [(u32, Option<i64>); 6] = [
            (0, None),              // just written
            (1, Some(9 * 60)),      // under the threshold
            (2, Some(-3600)),       // in the future
            (3, Some(OLD)),         // just over
            (4, Some(86_400)),      // a day old
            (5, Some(10 * 86_400)), // ten days old
        ];
        for (n, age) in ages {
            std::fs::write(file(n), b"partial").unwrap();
            if let Some(a) = age {
                set_age(&file(n), a);
            }
        }
        Wallet::open(Some(path.clone())).unwrap();
        let mut expect: Vec<String> = (0..3).map(|n| format!("w.json.tmp.{dead}.{n}")).collect();
        expect.sort();
        assert_eq!(names(dir.path()), expect);
        for n in 0..3 {
            assert_eq!(std::fs::read(file(n)).unwrap(), b"partial");
        }
    }

    #[test]
    fn a_running_writers_temp_file_is_kept_whatever_its_age() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let live = std::process::id();
        let mut expect = Vec::new();
        for (n, age) in [(0u32, 0i64), (1, OLD), (2, 10 * 86_400), (3, -3600)] {
            let name = format!("w.json.tmp.{live}.{n}");
            std::fs::write(dir.path().join(&name), b"partial").unwrap();
            set_age(&dir.path().join(&name), age);
            expect.push(name);
        }
        Wallet::open(Some(path.clone())).unwrap();
        expect.sort();
        assert_eq!(names(dir.path()), expect);
    }

    #[test]
    fn an_in_flight_write_of_another_namespace_survives_an_open_and_completes() {
        // The other writer's file, under a pid no process here has, just written.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let tmp = dir.path().join(format!("w.json.tmp.{}.0", dead_pid()));
        let mut other = Wallet::default();
        other.add(coin(7, 70));
        std::fs::write(&tmp, serde_json::to_vec(&other).unwrap()).unwrap();
        // This process opens the same wallet meanwhile.
        Wallet::open(Some(path.clone())).unwrap();
        // The other writer's rename still finds its file.
        std::fs::rename(&tmp, &path).unwrap();
        let w = Wallet::open(Some(path.clone())).unwrap();
        assert_eq!(w.available(), vec![coin(7, 70)]);
    }
    #[test]
    fn the_age_threshold_is_ten_minutes_and_a_future_mtime_is_never_stale() {
        let now = SystemTime::now();
        let ago = |s: u64| now - Duration::from_secs(s);
        assert!(!is_stale(now, now));
        assert!(!is_stale(ago(599), now));
        assert!(is_stale(ago(600), now));
        assert!(is_stale(ago(86_400), now));
        assert!(!is_stale(now + Duration::from_secs(3600), now));
    }
}

#[cfg(test)]
mod stalled_write_tests {
    use super::*;
    use std::sync::{Barrier, LazyLock};

    fn coin(n: u8, value: u64) -> Utxo {
        Utxo {
            outpoint: Outpoint {
                txid: Txid([n; 32]),
                vout: 0,
            },
            value,
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    /// Run `f` on its own thread; a call that has not returned within 5 s fails the test
    /// instead of hanging it.
    fn within_5s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(Duration::from_secs(5))
            .expect("persist did not return within 5 s")
    }

    /// A write step that writes half the bytes and then never returns.
    fn hangs(tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(tmp, &bytes[..bytes.len() / 2])?;
        loop {
            std::thread::park();
        }
    }

    const TEST_BOUND: Duration = Duration::from_millis(200);

    #[test]
    fn a_write_that_never_returns_times_out_and_leaves_the_wallet_file_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut w = Wallet::open(Some(path.clone())).unwrap();
        w.record_broadcast(&[], &[coin(1, 10)]).unwrap();
        let before: Vec<u8> = std::fs::read(&path).unwrap();
        let started = std::time::Instant::now();
        let res = within_5s(move || {
            w.add(coin(2, 20));
            w.persist_with(TEST_BOUND, hangs)
        });
        let took = started.elapsed();
        let Err(SwapError::Storage(msg)) = res else {
            panic!("expected a Storage error, got {res:?}");
        };
        assert!(msg.contains(&path.display().to_string()), "{msg}");
        assert!(msg.contains("200ms"), "{msg}");
        assert!(took < Duration::from_secs(2), "{took:?}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "wallet file unchanged"
        );
        // The half-written temporary file is gone: nothing is left to rename over it.
        assert_eq!(names(dir.path()), vec!["w.json".to_string()]);
    }

    static RELEASE: LazyLock<Barrier> = LazyLock::new(|| Barrier::new(2));

    /// A write step that waits until the test releases it, then writes its (by then stale)
    /// bytes in full and returns.
    fn released_late(tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
        RELEASE.wait();
        std::fs::write(tmp, bytes)
    }

    #[test]
    fn a_write_released_after_the_timeout_never_lands_over_a_newer_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        Wallet::open(Some(path.clone()))
            .unwrap()
            .record_broadcast(&[], &[coin(1, 10)])
            .unwrap();
        let mut stale = Wallet::open(Some(path.clone())).unwrap();
        let res = within_5s(move || {
            stale.add(coin(9, 90));
            stale.persist_with(TEST_BOUND, released_late)
        });
        assert!(matches!(res, Err(SwapError::Storage(_))), "{res:?}");
        // A newer write succeeds meanwhile.
        let mut newer = Wallet::open(Some(path.clone())).unwrap();
        newer.record_broadcast(&[], &[coin(2, 20)]).unwrap();
        let newer_bytes = std::fs::read(&path).unwrap();
        // The stalled writer now finishes its temporary file.
        RELEASE.wait();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while names(dir.path()) != ["w.json"] && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(names(dir.path()), vec!["w.json".to_string()]);
        assert_eq!(std::fs::read(&path).unwrap(), newer_bytes);
        assert_eq!(
            Wallet::open(Some(path)).unwrap().available(),
            vec![coin(1, 10), coin(2, 20)]
        );
    }

    #[test]
    fn a_fast_write_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut w = Wallet::open(Some(path.clone())).unwrap();
        w.record_broadcast(&[], &[coin(1, 10)]).unwrap();
        w.scanned_height = Some(7);
        w.persist().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            serde_json::to_string_pretty(&w).unwrap()
        );
        assert_eq!(names(dir.path()), vec!["w.json".to_string()]);
    }

    #[test]
    fn the_write_bound_is_a_minute_well_under_the_sweep_age() {
        assert_eq!(WRITE_TIMEOUT, Duration::from_secs(60));
        assert!(WRITE_TIMEOUT * 10 <= STALE_TEMP_FILE_AGE);
    }
}
