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

    fn persist(&self) -> Result<(), SwapError> {
        let Some(p) = &self.path else { return Ok(()) };
        let tmp = p.with_extension("tmp");
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
