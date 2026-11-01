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

//! Divi Core's periodic mempool rebroadcast (main.cpp:1245-1294): at a random
//! time within 30 minutes of the last check, if the chain tip has moved since
//! the last rebroadcast, up to 32 mempool transactions are announced to every
//! peer again, so a peer that missed one (it was down, or connected later)
//! gets it.

use crate::mempool::Mempool;
use divi_primitives::hash::Hash256;
use std::collections::HashSet;

/// At most this many transactions per rebroadcast (main.cpp:1248)
pub const MAX_REBROADCAST: usize = 32;

/// Upper bound of the random wait between two checks, in seconds
/// (main.cpp:1286, `GetRand(30*60)`)
pub const MAX_WAIT_SECS: i64 = 30 * 60;

/// When to rebroadcast, as Divi Core's PeriodicallyRebroadcastMempoolTxs
/// (main.cpp:1280-1294) decides it. Times are unix seconds.
#[derive(Debug, Default)]
pub struct RebroadcastTimer {
    /// The next check; none before the first call
    next: Option<i64>,
    last_broadcast: i64,
}

impl RebroadcastTimer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether to rebroadcast now. `last_tip_update` is when the chain tip
    /// last moved (0: not since the start); `wait` draws the seconds to the
    /// next check. The first call only sets the next check.
    pub fn due(&mut self, now: i64, last_tip_update: i64, wait: impl FnOnce() -> i64) -> bool {
        if self.next.is_some_and(|next| now < next) {
            return false;
        }
        let first = self.next.is_none();
        self.next = Some(now + wait());
        if first {
            return false;
        }
        if last_tip_update < self.last_broadcast {
            return false;
        }
        self.last_broadcast = now;
        last_tip_update > 0
    }
}

/// The transactions to announce again: the mempool in txid order (Core's
/// `mapTx`, a map by uint256), leaving out each one that spends another
/// mempool transaction, at most [`MAX_REBROADCAST`] (main.cpp:1256-1275)
pub fn rebroadcast_candidates(mempool: &Mempool) -> Vec<Hash256> {
    let mut txids = mempool.get_txids();
    txids.sort();
    let in_pool: HashSet<Hash256> = txids.iter().copied().collect();
    let mut out = Vec::new();
    for txid in txids {
        let Some(entry) = mempool.get(&txid) else {
            continue;
        };
        if entry
            .tx
            .vin
            .iter()
            .any(|input| in_pool.contains(&input.prevout.txid))
        {
            continue;
        }
        out.push(txid);
        if out.len() >= MAX_REBROADCAST {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_check_only_sets_the_next() {
        let mut t = RebroadcastTimer::new();
        assert!(!t.due(1000, 900, || 60));
        // before the next check: nothing
        assert!(!t.due(1059, 900, || 60));
        // at it, with the tip moved since the start: rebroadcast
        assert!(t.due(1060, 900, || 60));
    }

    #[test]
    fn only_after_the_tip_moved_since_the_last_rebroadcast() {
        let mut t = RebroadcastTimer::new();
        t.due(1000, 0, || 10);
        // the tip has not moved since the start
        assert!(!t.due(1010, 0, || 10));
        assert!(t.due(1020, 1015, || 10));
        // no tip move since the rebroadcast at 1020
        assert!(!t.due(1030, 1015, || 10));
        assert!(t.due(1040, 1035, || 10));
    }

    #[test]
    fn the_next_check_is_set_at_each_check_even_without_a_rebroadcast() {
        let mut t = RebroadcastTimer::new();
        t.due(1000, 0, || 100);
        assert!(!t.due(1100, 0, || 500));
        // the next check is now 1600, whatever the tip does
        assert!(!t.due(1599, 1500, || 1));
        assert!(t.due(1600, 1500, || 1));
    }

    fn tx(prevout: Hash256, value: i64) -> divi_primitives::transaction::Transaction {
        use divi_primitives::amount::Amount;
        use divi_primitives::constants::SEQUENCE_FINAL;
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
        Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(prevout, 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(
                Amount::from_divi(value),
                Script::new_p2pkh(&[0u8; 20]),
            )],
            lock_time: 0,
        }
    }

    /// In txid order, leaving out a transaction that spends another one in
    /// the mempool, at most 32 (main.cpp:1248-1275)
    #[test]
    fn candidates_are_in_txid_order_without_children_and_at_most_32() {
        use divi_primitives::amount::Amount;
        let mempool = Mempool::new(crate::config::MempoolConfig::default());
        let mut roots = Vec::new();
        for i in 0..40u8 {
            let t = tx(Hash256::from_bytes([i + 1; 32]), 1);
            roots.push(mempool.add(t, Amount::from_sat(100_000)).unwrap());
        }
        let child = tx(roots[0], 1);
        let child_id = mempool.add(child, Amount::from_sat(100_000)).unwrap();
        let picked = rebroadcast_candidates(&mempool);
        assert_eq!(picked.len(), MAX_REBROADCAST);
        assert!(!picked.contains(&child_id));
        let mut sorted = roots.clone();
        sorted.push(child_id);
        sorted.sort();
        let expected: Vec<Hash256> = sorted
            .into_iter()
            .filter(|t| *t != child_id)
            .take(32)
            .collect();
        assert_eq!(picked, expected);
    }
}
