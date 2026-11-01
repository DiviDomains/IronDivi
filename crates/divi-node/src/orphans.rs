// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Relayed transactions whose inputs are not known yet, kept until a parent
//! arrives, as Divi Core's mapOrphanTransactions (OrphanTransactions.cpp)

use divi_network::PeerId;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::Transaction;
use parking_lot::Mutex;
use rand::Rng;
use std::collections::{HashMap, HashSet};

/// Divi Core's -maxorphantx default (DEFAULT_MAX_ORPHAN_TRANSACTIONS)
pub const DEFAULT_MAX_ORPHAN_TXS: usize = 100;

/// Larger orphans are not kept (OrphanTransactions.cpp:52-61)
pub const MAX_ORPHAN_TX_SIZE: usize = 5000;

#[derive(Default)]
struct Inner {
    txs: HashMap<Hash256, (Transaction, PeerId)>,
    by_prev: HashMap<Hash256, HashSet<Hash256>>,
}

/// The orphan transactions, by txid and by the transactions they spend from
#[derive(Default)]
pub struct OrphanPool {
    inner: Mutex<Inner>,
}

impl OrphanPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// AddOrphanTx: keep `tx` from `peer`; false if it is known already or
    /// larger than 5000 bytes
    pub fn add(&self, tx: Transaction, peer: PeerId) -> bool {
        let txid = tx.txid();
        let mut inner = self.inner.lock();
        if inner.txs.contains_key(&txid) {
            return false;
        }
        let size = tx.size();
        if size > MAX_ORPHAN_TX_SIZE {
            tracing::debug!("ignoring large orphan tx (size: {}, hash: {})", size, txid);
            return false;
        }
        for input in &tx.vin {
            inner
                .by_prev
                .entry(input.prevout.txid)
                .or_default()
                .insert(txid);
        }
        inner.txs.insert(txid, (tx, peer));
        tracing::debug!(
            "stored orphan tx {} (mapsz {} prevsz {})",
            txid,
            inner.txs.len(),
            inner.by_prev.len()
        );
        true
    }

    /// OrphanTransactionIsKnown
    pub fn contains(&self, txid: &Hash256) -> bool {
        self.inner.lock().txs.contains_key(txid)
    }

    /// The orphan and the peer it came from
    pub fn get(&self, txid: &Hash256) -> Option<(Transaction, PeerId)> {
        self.inner.lock().txs.get(txid).cloned()
    }

    /// GetOrphanSpendingTransactionIds: the orphans spending an output of `txid`
    pub fn spending(&self, txid: &Hash256) -> Vec<Hash256> {
        self.inner
            .lock()
            .by_prev
            .get(txid)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// EraseOrphanTx
    pub fn erase(&self, txid: &Hash256) {
        Self::erase_locked(&mut self.inner.lock(), txid);
    }

    fn erase_locked(inner: &mut Inner, txid: &Hash256) {
        let Some((tx, _)) = inner.txs.remove(txid) else {
            return;
        };
        for input in &tx.vin {
            if let Some(set) = inner.by_prev.get_mut(&input.prevout.txid) {
                set.remove(txid);
                if set.is_empty() {
                    inner.by_prev.remove(&input.prevout.txid);
                }
            }
        }
    }

    /// EraseOrphansFor: drop what a peer sent when it disconnects
    pub fn erase_for_peer(&self, peer: PeerId) -> usize {
        let mut inner = self.inner.lock();
        let from: Vec<Hash256> = inner
            .txs
            .iter()
            .filter(|(_, (_, p))| *p == peer)
            .map(|(txid, _)| *txid)
            .collect();
        for txid in &from {
            Self::erase_locked(&mut inner, txid);
        }
        if !from.is_empty() {
            tracing::debug!("Erased {} orphan tx from peer {}", from.len(), peer);
        }
        from.len()
    }

    /// LimitOrphanTxSize: evict random orphans until at most `max` are left;
    /// returns how many were evicted
    pub fn limit(&self, max: usize) -> usize {
        let mut inner = self.inner.lock();
        let mut evicted = 0;
        let mut rng = rand::thread_rng();
        while inner.txs.len() > max {
            let n = rng.gen_range(0..inner.txs.len());
            let txid = *inner.txs.keys().nth(n).expect("index within the map");
            Self::erase_locked(&mut inner, &txid);
            evicted += 1;
        }
        evicted
    }

    pub fn len(&self) -> usize {
        self.inner.lock().txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::amount::Amount;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::{OutPoint, TxIn, TxOut};

    fn spending(prev: Hash256, n: u32, script_len: usize) -> Transaction {
        Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(prev, n),
                Script::from_bytes(vec![0u8; script_len]),
                0xffff_ffff,
            )],
            vout: vec![TxOut::new(Amount::from_sat(1000), Script::new())],
            lock_time: 0,
        }
    }

    #[test]
    fn orphans_are_kept_found_by_parent_and_erased() {
        let pool = OrphanPool::new();
        let parent = Hash256::from_bytes([1u8; 32]);
        let a = spending(parent, 0, 10);
        let b = spending(parent, 1, 10);
        assert!(pool.add(a.clone(), 7));
        assert!(!pool.add(a.clone(), 8), "a known orphan was added again");
        assert!(pool.add(b.clone(), 8));
        let mut kids = pool.spending(&parent);
        kids.sort_by_key(|h| h.to_string());
        let mut want = vec![a.txid(), b.txid()];
        want.sort_by_key(|h| h.to_string());
        assert_eq!(kids, want);
        assert_eq!(pool.get(&a.txid()).map(|(_, p)| p), Some(7));

        assert_eq!(pool.erase_for_peer(7), 1);
        assert!(!pool.contains(&a.txid()));
        pool.erase(&b.txid());
        assert!(pool.is_empty());
        assert!(pool.spending(&parent).is_empty());
    }

    #[test]
    fn large_orphans_are_not_kept() {
        let pool = OrphanPool::new();
        let big = spending(Hash256::from_bytes([2u8; 32]), 0, MAX_ORPHAN_TX_SIZE);
        assert!(big.size() > MAX_ORPHAN_TX_SIZE);
        assert!(!pool.add(big, 1));
        assert!(pool.is_empty());
    }

    #[test]
    fn limit_evicts_down_to_the_maximum() {
        let pool = OrphanPool::new();
        for i in 0..8u8 {
            assert!(pool.add(spending(Hash256::from_bytes([i + 10; 32]), 0, 10), 1));
        }
        assert_eq!(pool.limit(5), 3);
        assert_eq!(pool.len(), 5);
        assert_eq!(pool.limit(0), 5);
        assert!(pool.is_empty());
    }
}
