// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Transaction mempool
//!
//! Manages unconfirmed transactions waiting to be included in blocks.

use crate::config::MempoolConfig;
use crate::error::NodeError;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::Transaction;
use parking_lot::RwLock;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

/// Transaction entry in the mempool
#[derive(Clone)]
pub struct MempoolEntry {
    /// The transaction
    pub tx: Transaction,

    /// Transaction ID
    pub txid: Hash256,

    /// Time added to mempool
    pub time: Instant,

    /// Fee in satoshis
    pub fee: Amount,

    /// Transaction size in bytes
    pub size: usize,

    /// Fee rate (satoshis per byte)
    pub fee_rate: f64,

    /// Ancestors (transactions this depends on)
    pub ancestors: HashSet<Hash256>,

    /// Descendants (transactions that depend on this)
    pub descendants: HashSet<Hash256>,
}

impl MempoolEntry {
    /// Create a new mempool entry
    pub fn new(tx: Transaction, fee: Amount) -> Self {
        let txid = tx.txid();
        let size = tx.size();
        let fee_rate = fee.as_sat() as f64 / size as f64;

        MempoolEntry {
            tx,
            txid,
            time: Instant::now(),
            fee,
            size,
            fee_rate,
            ancestors: HashSet::new(),
            descendants: HashSet::new(),
        }
    }

    /// Get age of the entry
    pub fn age(&self) -> Duration {
        self.time.elapsed()
    }
}

/// Entry for priority queue ordering by fee rate
struct PriorityEntry {
    _txid: Hash256,
    fee_rate: f64,
}

impl PartialEq for PriorityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.fee_rate == other.fee_rate
    }
}

impl Eq for PriorityEntry {}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher fee rate = higher priority
        self.fee_rate
            .partial_cmp(&other.fee_rate)
            .unwrap_or(Ordering::Equal)
    }
}

/// Transaction mempool
pub struct Mempool {
    /// Configuration
    config: MempoolConfig,

    /// All transactions indexed by txid
    txs: RwLock<HashMap<Hash256, MempoolEntry>>,

    /// Transactions ordered by fee rate
    priority_queue: RwLock<BinaryHeap<PriorityEntry>>,

    /// Outpoint to spending transaction
    spenders: RwLock<HashMap<(Hash256, u32), Hash256>>,

    /// Total size of all transactions
    total_size: RwLock<usize>,

    /// Priority deltas for transactions (txid -> (priority_delta, fee_delta))
    priority_deltas: RwLock<HashMap<Hash256, (f64, i64)>>,
}

impl Mempool {
    /// Create a new mempool
    pub fn new(config: MempoolConfig) -> Self {
        Mempool {
            config,
            txs: RwLock::new(HashMap::new()),
            priority_queue: RwLock::new(BinaryHeap::new()),
            spenders: RwLock::new(HashMap::new()),
            total_size: RwLock::new(0),
            priority_deltas: RwLock::new(HashMap::new()),
        }
    }

    /// Check if a transaction is in the mempool
    pub fn contains(&self, txid: &Hash256) -> bool {
        self.txs.read().contains_key(txid)
    }

    /// Get a transaction from the mempool
    pub fn get(&self, txid: &Hash256) -> Option<MempoolEntry> {
        self.txs.read().get(txid).cloned()
    }

    /// Get all transaction IDs in the mempool
    pub fn get_txids(&self) -> Vec<Hash256> {
        self.txs.read().keys().cloned().collect()
    }

    /// Get transaction count
    pub fn size(&self) -> usize {
        self.txs.read().len()
    }

    /// Get total bytes of all transactions
    pub fn bytes(&self) -> usize {
        *self.total_size.read()
    }

    /// Add a transaction to the mempool
    pub fn add(&self, tx: Transaction, fee: Amount) -> Result<Hash256, NodeError> {
        let entry = MempoolEntry::new(tx.clone(), fee);
        let txid = entry.txid;

        // Check if already exists
        if self.contains(&txid) {
            return Ok(txid);
        }

        // Check size limits
        let new_size = *self.total_size.read() + entry.size;
        if new_size > self.config.max_size {
            // Need to evict transactions
            self.evict_for_space(entry.size)?;
        }

        // Check fee rate
        if entry.fee_rate < self.config.min_relay_fee as f64 {
            return Err(NodeError::TransactionValidation(
                "Fee rate below minimum relay fee".into(),
            ));
        }

        // Check for conflicts (double spends)
        for input in &tx.vin {
            let outpoint = (input.prevout.txid, input.prevout.vout);
            if let Some(existing) = self.spenders.read().get(&outpoint) {
                return Err(NodeError::TransactionValidation(format!(
                    "Conflicts with transaction {}",
                    existing
                )));
            }
        }

        // Add to mempool
        {
            let mut txs = self.txs.write();
            let mut spenders = self.spenders.write();
            let mut total_size = self.total_size.write();

            // Track which outputs this transaction spends
            for input in &tx.vin {
                let outpoint = (input.prevout.txid, input.prevout.vout);
                spenders.insert(outpoint, txid);
            }

            *total_size += entry.size;
            txs.insert(txid, entry.clone());
        }

        // Add to priority queue
        self.priority_queue.write().push(PriorityEntry {
            _txid: txid,
            fee_rate: entry.fee_rate,
        });

        tracing::debug!(
            "Added tx {} to mempool (fee: {}, size: {})",
            txid,
            fee.as_sat(),
            entry.size
        );

        Ok(txid)
    }

    /// Remove a transaction from the mempool
    pub fn remove(&self, txid: &Hash256) -> Option<MempoolEntry> {
        let entry = self.txs.write().remove(txid)?;

        // Remove from spenders
        {
            let mut spenders = self.spenders.write();
            for input in &entry.tx.vin {
                let outpoint = (input.prevout.txid, input.prevout.vout);
                spenders.remove(&outpoint);
            }
        }

        // Update total size
        *self.total_size.write() -= entry.size;

        tracing::debug!("Removed tx {} from mempool", txid);

        Some(entry)
    }

    /// Remove transactions that are now confirmed in a block
    pub fn remove_for_block(&self, txids: &[Hash256]) {
        for txid in txids {
            self.remove(txid);
        }
    }

    /// Get transactions for a new block, sorted by fee rate
    pub fn get_block_txs(&self, max_size: usize) -> Vec<Transaction> {
        let txs = self.txs.read();
        let mut result = Vec::new();
        let mut total_size = 0;

        // Get entries sorted by fee rate (descending)
        let mut entries: Vec<_> = txs.values().collect();
        entries.sort_by(|a, b| {
            b.fee_rate
                .partial_cmp(&a.fee_rate)
                .unwrap_or(Ordering::Equal)
        });

        for entry in entries {
            if total_size + entry.size > max_size {
                continue; // Skip this one, might fit smaller txs
            }
            total_size += entry.size;
            result.push(entry.tx.clone());
        }

        result
    }

    /// Check if an outpoint is spent by a mempool transaction
    pub fn is_spent(&self, txid: &Hash256, vout: u32) -> bool {
        self.spenders.read().contains_key(&(*txid, vout))
    }

    /// Get the transaction that spends an outpoint
    pub fn get_spender(&self, txid: &Hash256, vout: u32) -> Option<Hash256> {
        self.spenders.read().get(&(*txid, vout)).copied()
    }

    /// Remove expired transactions
    pub fn expire_old(&self) -> usize {
        let expiry = Duration::from_secs(self.config.expiry_time);
        let mut to_remove = Vec::new();

        for (txid, entry) in self.txs.read().iter() {
            if entry.age() > expiry {
                to_remove.push(*txid);
            }
        }

        let count = to_remove.len();
        for txid in to_remove {
            self.remove(&txid);
        }

        if count > 0 {
            tracing::info!("Expired {} old transactions from mempool", count);
        }

        count
    }

    /// Evict transactions to make room for new ones
    fn evict_for_space(&self, needed: usize) -> Result<(), NodeError> {
        let mut freed = 0;
        let mut to_remove = Vec::new();

        // Remove lowest fee rate transactions first
        let txs = self.txs.read();
        let mut entries: Vec<_> = txs.values().collect();
        entries.sort_by(|a, b| {
            a.fee_rate
                .partial_cmp(&b.fee_rate)
                .unwrap_or(Ordering::Equal)
        });

        for entry in entries {
            if freed >= needed {
                break;
            }
            to_remove.push(entry.txid);
            freed += entry.size;
        }

        drop(txs);

        for txid in to_remove {
            self.remove(&txid);
        }

        if freed < needed {
            return Err(NodeError::TransactionValidation(
                "Mempool full, cannot accept transaction".into(),
            ));
        }

        Ok(())
    }

    /// Get mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let txs = self.txs.read();
        let total_fee: i64 = txs.values().map(|e| e.fee.as_sat()).sum();

        MempoolStats {
            tx_count: txs.len(),
            total_bytes: *self.total_size.read(),
            total_fee: Amount::from_sat(total_fee),
            max_size: self.config.max_size,
        }
    }

    pub fn prioritise_transaction(
        &self,
        txid: &Hash256,
        priority_delta: f64,
        fee_delta: i64,
    ) -> bool {
        let mut deltas = self.priority_deltas.write();

        let entry = deltas.entry(*txid).or_insert((0.0, 0));
        entry.0 += priority_delta;
        entry.1 += fee_delta;

        true
    }

    pub fn get_priority_delta(&self, txid: &Hash256) -> Option<(f64, i64)> {
        self.priority_deltas.read().get(txid).copied()
    }

    /// Clear all transactions from mempool
    pub fn clear(&self) {
        self.txs.write().clear();
        self.spenders.write().clear();
        self.priority_queue.write().clear();
        *self.total_size.write() = 0;
        self.priority_deltas.write().clear();
        tracing::info!("Mempool cleared");
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    /// Number of transactions
    pub tx_count: usize,

    /// Total bytes
    pub total_bytes: usize,

    /// Total fees
    pub total_fee: Amount,

    /// Maximum allowed size
    pub max_size: usize,
}

impl divi_rpc::blockchain::MempoolProvider for Mempool {
    fn get_txids(&self) -> Vec<Hash256> {
        self.get_txids()
    }

    fn prioritise_transaction(&self, txid: &Hash256, priority_delta: f64, fee_delta: i64) -> bool {
        self.prioritise_transaction(txid, priority_delta, fee_delta)
    }

    fn get_stats(&self) -> divi_rpc::blockchain::MempoolStats {
        divi_rpc::blockchain::MempoolStats {
            size: self.size(),
            bytes: self.bytes(),
            usage: self.bytes() + self.size() * 200, // Estimate overhead per entry
            max_mempool: self.config.max_size,
            min_fee: self.config.min_relay_fee as f64 / 100_000_000.0, // Convert satoshis to DIVI/kB
        }
    }

    fn estimate_fee(&self, conf_target: u32) -> f64 {
        // Use mempool-based fee estimation
        // Look at fee rates in current mempool
        let txs = self.txs.read();
        if txs.is_empty() {
            return 0.00001; // Minimum fee rate
        }

        // Collect all fee rates
        let mut fee_rates: Vec<f64> = txs.values().map(|e| e.fee_rate).collect();
        fee_rates.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        // For lower confirmation targets, use higher fee rates
        // conf_target of 1-2 = top 10%, 3-6 = top 50%, 7+ = median
        let percentile_idx = if conf_target <= 2 {
            fee_rates.len() / 10
        } else if conf_target <= 6 {
            fee_rates.len() / 2
        } else {
            fee_rates.len() * 3 / 4
        };

        let idx = percentile_idx.min(fee_rates.len().saturating_sub(1));
        let fee_per_byte = fee_rates.get(idx).copied().unwrap_or(1.0);

        // Convert from sat/byte to DIVI/kB
        let fee_per_kb = fee_per_byte * 1000.0;
        let fee_divi = fee_per_kb / 100_000_000.0;

        fee_divi.max(0.00001) // Ensure minimum fee
    }

    fn estimate_smart_fee(&self, conf_target: u32) -> divi_rpc::blockchain::FeeEstimate {
        let fee_rate = self.estimate_fee(conf_target);
        let blocks = conf_target.min(25); // Cap at 25 blocks for estimation

        divi_rpc::blockchain::FeeEstimate { fee_rate, blocks }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::constants::SEQUENCE_FINAL;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::{OutPoint, TxIn, TxOut};

    fn test_config() -> MempoolConfig {
        MempoolConfig {
            min_relay_fee: 1, // Very low for testing
            ..MempoolConfig::default()
        }
    }

    fn create_test_tx(prevout_txid: [u8; 32], value: i64) -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes(prevout_txid), 0),
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

    #[test]
    fn test_mempool_new() {
        let mempool = Mempool::new(test_config());
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.bytes(), 0);
    }

    #[test]
    fn test_mempool_add_remove() {
        let mempool = Mempool::new(test_config());

        let tx = create_test_tx([1u8; 32], 50);
        let txid = tx.txid();
        let fee = Amount::from_sat(10000);

        mempool.add(tx, fee).unwrap();
        assert_eq!(mempool.size(), 1);
        assert!(mempool.contains(&txid));

        let entry = mempool.remove(&txid).unwrap();
        assert_eq!(entry.fee, fee);
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn test_mempool_conflict_detection() {
        let mempool = Mempool::new(test_config());

        // Add first tx
        let tx1 = create_test_tx([1u8; 32], 50);
        mempool.add(tx1, Amount::from_sat(10000)).unwrap();

        // Try to add conflicting tx (same input)
        let tx2 = create_test_tx([1u8; 32], 40);
        let result = mempool.add(tx2, Amount::from_sat(10000));
        assert!(result.is_err());
    }

    #[test]
    fn test_mempool_get_block_txs() {
        let mempool = Mempool::new(test_config());

        // Add transactions with different fee rates
        for i in 0..5 {
            let tx = create_test_tx([i + 1; 32], 10);
            let fee = Amount::from_sat((i as i64 + 1) * 1000);
            mempool.add(tx, fee).unwrap();
        }

        let block_txs = mempool.get_block_txs(1_000_000);
        assert_eq!(block_txs.len(), 5);
    }

    #[test]
    fn test_mempool_is_spent() {
        let mempool = Mempool::new(test_config());

        let prev_txid = Hash256::from_bytes([1u8; 32]);
        let tx = create_test_tx([1u8; 32], 50);
        mempool.add(tx, Amount::from_sat(10000)).unwrap();

        assert!(mempool.is_spent(&prev_txid, 0));
        assert!(!mempool.is_spent(&prev_txid, 1));
    }

    #[test]
    fn test_mempool_stats() {
        let mempool = Mempool::new(test_config());

        let tx = create_test_tx([1u8; 32], 50);
        let fee = Amount::from_sat(10000);
        mempool.add(tx, fee).unwrap();

        let stats = mempool.stats();
        assert_eq!(stats.tx_count, 1);
        assert_eq!(stats.total_fee.as_sat(), 10000);
        assert!(stats.total_bytes > 0);
    }

    #[test]
    fn test_mempool_clear() {
        let mempool = Mempool::new(test_config());

        for i in 0..3 {
            let tx = create_test_tx([i + 1; 32], 50);
            mempool.add(tx, Amount::from_sat(10000)).unwrap();
        }

        assert_eq!(mempool.size(), 3);
        mempool.clear();
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.bytes(), 0);
    }

    #[test]
    fn test_low_fee_rejection() {
        let config = MempoolConfig {
            min_relay_fee: 100000, // High minimum
            ..MempoolConfig::default()
        };
        let mempool = Mempool::new(config);

        let tx = create_test_tx([1u8; 32], 50);
        let result = mempool.add(tx, Amount::from_sat(1)); // Very low fee
        assert!(result.is_err());
    }

    // ============================================================
    // COMPREHENSIVE MEMPOOL TESTS
    // Added 2026-01-19 for test pyramid completeness
    // ============================================================

    #[test]
    fn test_mempool_reject_duplicate_add() {
        let mempool = Mempool::new(test_config());
        let tx = create_test_tx([1u8; 32], 50);
        let fee = Amount::from_sat(10000);

        // Add once - should succeed
        let txid1 = mempool.add(tx.clone(), fee).unwrap();
        assert_eq!(mempool.size(), 1);

        // Add again - should return same txid (idempotent)
        let txid2 = mempool.add(tx, fee).unwrap();
        assert_eq!(txid1, txid2);
        assert_eq!(mempool.size(), 1); // Still only 1 tx
    }

    #[test]
    fn test_mempool_remove_nonexistent() {
        let mempool = Mempool::new(test_config());
        let fake_txid = Hash256::from_bytes([0xff; 32]);

        let result = mempool.remove(&fake_txid);
        assert!(result.is_none());
    }

    #[test]
    fn test_mempool_fee_rate_calculation() {
        let mempool = Mempool::new(test_config());
        let tx = create_test_tx([1u8; 32], 50);
        let fee = Amount::from_sat(10000);

        mempool.add(tx.clone(), fee).unwrap();
        let entry = mempool.get(&tx.txid()).unwrap();

        // Fee rate should be fee / size
        let expected_rate = 10000.0 / (entry.size as f64);
        assert!((entry.fee_rate - expected_rate).abs() < 0.01);
    }

    #[test]
    fn test_mempool_priority_ordering() {
        let mempool = Mempool::new(test_config());

        // Add txs with different fee rates
        let tx1 = create_test_tx([1u8; 32], 50);
        let tx2 = create_test_tx([2u8; 32], 50);
        let tx3 = create_test_tx([3u8; 32], 50);

        mempool.add(tx1, Amount::from_sat(1000)).unwrap(); // Low fee
        mempool.add(tx2, Amount::from_sat(10000)).unwrap(); // High fee
        mempool.add(tx3, Amount::from_sat(5000)).unwrap(); // Medium fee

        // get_block_txs should return in high-to-low fee order
        let block_txs = mempool.get_block_txs(1_000_000);
        assert_eq!(block_txs.len(), 3);

        // Verify fee order (highest first)
        let entry1 = mempool.get(&block_txs[0].txid()).unwrap();
        let entry2 = mempool.get(&block_txs[1].txid()).unwrap();
        let entry3 = mempool.get(&block_txs[2].txid()).unwrap();

        assert!(entry1.fee_rate >= entry2.fee_rate);
        assert!(entry2.fee_rate >= entry3.fee_rate);
    }

    #[test]
    fn test_mempool_size_limit_eviction() {
        let mut config = test_config();
        config.max_size = 1000; // Very small mempool
        let mempool = Mempool::new(config);

        // Add multiple transactions
        for i in 0..10 {
            let tx = create_test_tx([i + 1; 32], 10);
            let _ = mempool.add(tx, Amount::from_sat((i as i64 + 1) * 1000));
        }

        // Mempool should have evicted some transactions
        assert!(mempool.bytes() <= 1000);
    }

    #[test]
    fn test_mempool_block_tx_size_limit() {
        let mempool = Mempool::new(test_config());

        // Add many transactions
        for i in 0..20 {
            let tx = create_test_tx([i + 1; 32], 10);
            mempool.add(tx, Amount::from_sat(10000)).unwrap();
        }

        // Request with very small size limit
        let block_txs = mempool.get_block_txs(500);

        // Should return fewer than all txs
        assert!(block_txs.len() < 20);

        // Total size should be <= limit
        let total_size: usize = block_txs.iter().map(|tx| tx.size()).sum();
        assert!(total_size <= 500);
    }

    #[test]
    fn test_mempool_spender_tracking() {
        let mempool = Mempool::new(test_config());

        let prev_txid = Hash256::from_bytes([1u8; 32]);
        let tx = create_test_tx([1u8; 32], 50);
        let txid = tx.txid();

        mempool.add(tx, Amount::from_sat(10000)).unwrap();

        // Check spender is tracked
        let spender = mempool.get_spender(&prev_txid, 0);
        assert_eq!(spender, Some(txid));

        // Remove tx
        mempool.remove(&txid);

        // Spender should be cleared
        let spender_after = mempool.get_spender(&prev_txid, 0);
        assert_eq!(spender_after, None);
    }

    #[test]
    fn test_mempool_remove_for_block() {
        let mempool = Mempool::new(test_config());

        let tx1 = create_test_tx([1u8; 32], 50);
        let tx2 = create_test_tx([2u8; 32], 50);
        let tx3 = create_test_tx([3u8; 32], 50);

        let txid1 = tx1.txid();
        let txid2 = tx2.txid();
        let txid3 = tx3.txid();

        mempool.add(tx1, Amount::from_sat(10000)).unwrap();
        mempool.add(tx2, Amount::from_sat(10000)).unwrap();
        mempool.add(tx3, Amount::from_sat(10000)).unwrap();

        assert_eq!(mempool.size(), 3);

        // Remove tx1 and tx2 (as if they were in a block)
        mempool.remove_for_block(&[txid1, txid2]);

        assert_eq!(mempool.size(), 1);
        assert!(!mempool.contains(&txid1));
        assert!(!mempool.contains(&txid2));
        assert!(mempool.contains(&txid3));
    }

    #[test]
    fn test_mempool_double_spend_rejection() {
        let mempool = Mempool::new(test_config());

        // Add first transaction
        let tx1 = create_test_tx([1u8; 32], 50);
        mempool.add(tx1.clone(), Amount::from_sat(10000)).unwrap();

        // Create second transaction spending same input
        let tx2 = create_test_tx([1u8; 32], 40); // Same prevout!
        let result = mempool.add(tx2, Amount::from_sat(15000));

        // Should be rejected
        assert!(result.is_err());
        if let Err(NodeError::TransactionValidation(msg)) = result {
            assert!(msg.contains("Conflicts"));
        } else {
            panic!("Expected TransactionValidation error");
        }
    }

    #[test]
    fn test_mempool_get_nonexistent() {
        let mempool = Mempool::new(test_config());
        let fake_txid = Hash256::from_bytes([0xaa; 32]);

        assert!(!mempool.contains(&fake_txid));
        assert!(mempool.get(&fake_txid).is_none());
    }

    #[test]
    fn test_mempool_stats_accumulation() {
        let mempool = Mempool::new(test_config());

        let initial_stats = mempool.stats();
        assert_eq!(initial_stats.tx_count, 0);
        assert_eq!(initial_stats.total_fee.as_sat(), 0);
        assert_eq!(initial_stats.total_bytes, 0);

        // Add transactions
        for i in 0..5 {
            let tx = create_test_tx([i + 1; 32], 10);
            mempool
                .add(tx, Amount::from_sat((i as i64 + 1) * 1000))
                .unwrap();
        }

        let stats = mempool.stats();
        assert_eq!(stats.tx_count, 5);
        assert_eq!(stats.total_fee.as_sat(), 15000); // 1+2+3+4+5 = 15
        assert!(stats.total_bytes > 0);
    }

    #[test]
    fn test_mempool_age_tracking() {
        let mempool = Mempool::new(test_config());
        let tx = create_test_tx([1u8; 32], 50);
        let txid = tx.txid();

        mempool.add(tx, Amount::from_sat(10000)).unwrap();

        // Age should be very small (just added)
        let entry = mempool.get(&txid).unwrap();
        assert!(entry.age().as_secs() < 1);

        // Sleep would make age grow, but we don't want to slow down tests
        // Just verify age() works without panicking
        let _ = entry.age();
    }

    #[test]
    fn test_mempool_eviction_lowest_fee_first() {
        let mut config = test_config();
        config.max_size = 2000;
        let mempool = Mempool::new(config);

        // Add low fee tx
        let tx_low = create_test_tx([1u8; 32], 10);
        let txid_low = tx_low.txid();
        mempool.add(tx_low, Amount::from_sat(100)).unwrap();

        // Add many high fee txs to trigger eviction
        for i in 0..50 {
            let tx = create_test_tx([i + 10; 32], 10);
            let _ = mempool.add(tx, Amount::from_sat(100000));
        }

        // Low fee tx should have been evicted
        assert!(!mempool.contains(&txid_low));
    }

    #[test]
    fn test_mempool_clear_removes_all() {
        let mempool = Mempool::new(test_config());

        // Add multiple transactions
        for i in 0..10 {
            let tx = create_test_tx([i + 1; 32], 10);
            mempool.add(tx, Amount::from_sat(10000)).unwrap();
        }

        assert_eq!(mempool.size(), 10);
        assert!(mempool.bytes() > 0);

        mempool.clear();

        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.bytes(), 0);

        // All spenders should be cleared too
        let prev_txid = Hash256::from_bytes([1u8; 32]);
        assert!(!mempool.is_spent(&prev_txid, 0));
    }

    #[test]
    fn test_mempool_multiple_inputs_same_tx() {
        let mempool = Mempool::new(test_config());

        // Create tx with multiple inputs
        let tx = Transaction {
            version: 2,
            vin: vec![
                TxIn::new(
                    OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                    Script::new(),
                    SEQUENCE_FINAL,
                ),
                TxIn::new(
                    OutPoint::new(Hash256::from_bytes([2u8; 32]), 1),
                    Script::new(),
                    SEQUENCE_FINAL,
                ),
            ],
            vout: vec![TxOut::new(
                Amount::from_divi(50),
                Script::new_p2pkh(&[0u8; 20]),
            )],
            lock_time: 0,
        };

        mempool.add(tx.clone(), Amount::from_sat(10000)).unwrap();

        // Both inputs should be marked as spent
        assert!(mempool.is_spent(&Hash256::from_bytes([1u8; 32]), 0));
        assert!(mempool.is_spent(&Hash256::from_bytes([2u8; 32]), 1));

        // Different outputs should not be spent
        assert!(!mempool.is_spent(&Hash256::from_bytes([1u8; 32]), 1));
        assert!(!mempool.is_spent(&Hash256::from_bytes([2u8; 32]), 0));
    }

    #[test]
    fn test_mempool_empty_operations() {
        let mempool = Mempool::new(test_config());

        // Operations on empty mempool
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.bytes(), 0);

        let block_txs = mempool.get_block_txs(1_000_000);
        assert!(block_txs.is_empty());

        mempool.remove_for_block(&[]);
        assert_eq!(mempool.size(), 0);

        let expired = mempool.expire_old();
        assert_eq!(expired, 0);

        mempool.clear(); // Should not panic
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn test_mempool_fee_rate_extremes() {
        let mempool = Mempool::new(test_config());

        // Very high fee
        let tx_high = create_test_tx([1u8; 32], 10);
        mempool
            .add(tx_high.clone(), Amount::from_sat(100_000_000))
            .unwrap();
        let entry_high = mempool.get(&tx_high.txid()).unwrap();
        assert!(entry_high.fee_rate > 10000.0);

        // Low fee (but still above minimum relay of 1 sat/byte)
        let tx_low = create_test_tx([2u8; 32], 10);
        let tx_size = tx_low.size();
        mempool
            .add(tx_low.clone(), Amount::from_sat(tx_size as i64 + 1))
            .unwrap();
        let entry_low = mempool.get(&tx_low.txid()).unwrap();
        assert!(entry_low.fee_rate >= 1.0);
        assert!(entry_low.fee_rate < 2.0);
    }
}
