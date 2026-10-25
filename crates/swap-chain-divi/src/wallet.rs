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

use std::path::PathBuf;

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
    pub fn open(path: Option<PathBuf>) -> Result<Self, SwapError> {
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
        self.refresh();
        static WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let Some(p) = &self.path else { return Ok(()) };
        // Each write has its own temporary file: two processes (or two backends in one) on
        // the same wallet file must not interleave their bytes in one before the rename.
        let n = WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = p.with_extension(format!("tmp.{}.{n}", std::process::id()));
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| SwapError::Storage(format!("serialize wallet: {e}")))?;
        std::fs::write(&tmp, text)
            .and_then(|_| std::fs::rename(&tmp, p))
            .map_err(|e| SwapError::Storage(format!("write {}: {e}", p.display())))
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
