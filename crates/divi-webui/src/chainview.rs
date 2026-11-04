// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A wallet's balance, coins and history, read through the node's Electrum
//! backend (`divi_electrum::Backend`), so spends still in the mempool count.
//! Every call here blocks on the database: run it in `spawn_blocking`.

use std::collections::{HashMap, HashSet};

use divi_electrum::backend::ElectrumError;
use divi_electrum::Backend;
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::deserialize;
use divi_primitives::transaction::Transaction;
use divi_wallet::{Address, Network};
use sha2::{Digest, Sha256};

use crate::wallets::Coin;

/// History lines whose amounts are worked out, newest first
pub const HISTORY: usize = 100;

/// What the wallet page shows
pub struct View {
    /// Satoshis in blocks
    pub confirmed: i64,
    /// What the mempool adds or takes away
    pub pending: i64,
    /// Coins not spent in a block nor in the mempool, the mempool's own included
    pub coins: Vec<Coin>,
    pub history: Vec<Line>,
}

/// One transaction's net effect on the wallet
pub struct Line {
    pub txid: String,
    /// 0 in the mempool, -1 when it spends a mempool output
    pub height: i64,
    pub satoshis: i64,
}

/// The backend's message, which says plainly when an index is off
fn text(e: ElectrumError) -> String {
    e.message
}

/// The transaction, from the mempool or the transaction index, kept for reuse
fn fetch<'a>(
    backend: &Backend,
    cache: &'a mut HashMap<Hash256, Option<Transaction>>,
    txid: &Hash256,
) -> Option<&'a Transaction> {
    cache
        .entry(*txid)
        .or_insert_with(|| {
            let raw = backend.raw_transaction(txid).ok()?;
            deserialize::<Transaction>(&raw).ok()
        })
        .as_ref()
}

pub fn read(backend: &Backend, addresses: &[String], network: Network) -> Result<View, String> {
    // Each address's output script; the backend keys everything by its SHA-256
    let mut scripts: Vec<(Vec<u8>, &String)> = Vec::with_capacity(addresses.len());
    for a in addresses {
        let address = Address::from_base58_for_network(a, network).map_err(|e| e.to_string())?;
        scripts.push((address.script_pubkey().as_bytes().to_vec(), a));
    }
    let ours: HashSet<&[u8]> = scripts.iter().map(|(s, _)| s.as_slice()).collect();

    let mut view = View {
        confirmed: 0,
        pending: 0,
        coins: Vec::new(),
        history: Vec::new(),
    };
    let mut heights: HashMap<Hash256, i64> = HashMap::new();
    for (script, address) in &scripts {
        let sh: [u8; 32] = Sha256::digest(script).into();
        let (confirmed, pending) = backend.balance(&sh).map_err(text)?;
        view.confirmed += confirmed;
        view.pending += pending;
        for u in backend.listunspent(&sh).map_err(text)? {
            view.coins.push(Coin {
                address: (*address).clone(),
                txid: u.txid.to_hex(),
                vout: u.vout,
                value: u.value,
                script_hex: hex::encode(script),
                height: (u.height > 0).then_some(u.height as u32),
            });
        }
        for e in backend.history(&sh).map_err(text)? {
            heights.insert(e.txid, e.height);
        }
    }

    // Newest first: the mempool, then blocks from the tip down
    let mut lines: Vec<(Hash256, i64)> = heights.into_iter().collect();
    let rank = |h: i64| if h <= 0 { i64::MAX } else { h };
    lines.sort_by(|a, b| {
        rank(b.1)
            .cmp(&rank(a.1))
            .then_with(|| a.0.to_hex().cmp(&b.0.to_hex()))
    });

    // Net amount: our outputs, less the outputs of ours that its inputs spend
    let mut cache: HashMap<Hash256, Option<Transaction>> = HashMap::new();
    for (txid, height) in lines.into_iter().take(HISTORY) {
        let Some(tx) = fetch(backend, &mut cache, &txid).cloned() else {
            return Err(format!(
                "transaction {} is not in the transaction index: set txindex=1 and restart the node",
                txid.to_hex()
            ));
        };
        let mut satoshis: i64 = tx
            .vout
            .iter()
            .filter(|o| ours.contains(o.script_pubkey.as_bytes()))
            .map(|o| o.value.as_sat())
            .sum();
        for input in tx.vin.iter().filter(|i| !i.prevout.is_null()) {
            if let Some(prev) = fetch(backend, &mut cache, &input.prevout.txid) {
                if let Some(o) = prev.vout.get(input.prevout.vout as usize) {
                    if ours.contains(o.script_pubkey.as_bytes()) {
                        satoshis -= o.value.as_sat();
                    }
                }
            }
        }
        view.history.push(Line {
            txid: txid.to_hex(),
            height,
            satoshis,
        });
    }
    Ok(view)
}
