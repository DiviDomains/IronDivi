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

//! Fee estimation based on recent block data
//!
//! Tracks fees from recent blocks to provide fee rate estimates for different
//! confirmation targets.

use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

const MAX_BLOCK_HISTORY: usize = 1000;
const MIN_FEE_RATE: f64 = 0.00001;

#[derive(Debug, Clone)]
struct BlockFeeData {
    height: u32,
    total_fees: Amount,
    total_size: usize,
    tx_count: usize,
}

pub struct FeeEstimator {
    recent_blocks: Arc<RwLock<VecDeque<BlockFeeData>>>,
}

impl FeeEstimator {
    pub fn new() -> Self {
        Self {
            recent_blocks: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_BLOCK_HISTORY))),
        }
    }

    pub fn add_block(&self, height: u32, block: &Block, total_fees: Amount) {
        let mut blocks = self.recent_blocks.write().unwrap();

        let total_size: usize = block
            .transactions
            .iter()
            .map(|tx| {
                let mut size = 4 + 4;
                size += tx.vin.len() * 150;
                size += tx.vout.len() * 50;
                size
            })
            .sum();

        let fee_data = BlockFeeData {
            height,
            total_fees,
            total_size,
            tx_count: block.transactions.len(),
        };

        blocks.push_back(fee_data);

        if blocks.len() > MAX_BLOCK_HISTORY {
            blocks.pop_front();
        }
    }

    pub fn estimate_fee(&self, conf_target: u32) -> f64 {
        let blocks = self.recent_blocks.read().unwrap();

        if blocks.is_empty() {
            return MIN_FEE_RATE;
        }

        let sample_size = conf_target.min(blocks.len() as u32) as usize;
        if sample_size == 0 {
            return MIN_FEE_RATE;
        }

        let recent: Vec<&BlockFeeData> = blocks.iter().rev().take(sample_size).collect();

        let total_fees: i64 = recent.iter().map(|b| b.total_fees.as_sat()).sum();
        let total_size: usize = recent.iter().map(|b| b.total_size).sum();

        if total_size == 0 {
            return MIN_FEE_RATE;
        }

        let fee_per_kb = (total_fees as f64) / (total_size as f64 / 1024.0);
        let fee_rate_divi = fee_per_kb / 100_000_000.0;

        fee_rate_divi.max(MIN_FEE_RATE)
    }

    pub fn estimate_smart_fee(&self, conf_target: u32) -> (f64, u32) {
        let blocks = self.recent_blocks.read().unwrap();

        if blocks.is_empty() {
            return (MIN_FEE_RATE, conf_target);
        }

        let available_blocks = blocks.len() as u32;
        let actual_target = conf_target.min(available_blocks).max(1);

        let fee_rate = self.estimate_fee(actual_target);

        (fee_rate, actual_target)
    }

    pub fn get_stats(&self) -> FeeEstimatorStats {
        let blocks = self.recent_blocks.read().unwrap();

        FeeEstimatorStats {
            blocks_tracked: blocks.len(),
            latest_height: blocks.back().map(|b| b.height).unwrap_or(0),
            min_fee_rate: MIN_FEE_RATE,
        }
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct FeeEstimatorStats {
    pub blocks_tracked: usize,
    pub latest_height: u32,
    pub min_fee_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use divi_primitives::Hash256;

    fn create_test_block(tx_count: usize) -> Block {
        let mut txs = Vec::new();
        for _ in 0..tx_count {
            txs.push(Transaction {
                version: 1,
                vin: vec![TxIn {
                    prevout: OutPoint::new(Hash256::zero(), 0),
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                }],
                vout: vec![TxOut {
                    value: Amount::from_sat(1000000),
                    script_pubkey: Script::new(),
                }],
                lock_time: 0,
            });
        }

        Block {
            header: divi_primitives::block::BlockHeader {
                version: 1,
                prev_block: Hash256::zero(),
                merkle_root: Hash256::zero(),
                time: 0,
                bits: 0,
                nonce: 0,
                accumulator_checkpoint: Hash256::zero(),
            },
            transactions: txs,
            block_sig: vec![],
        }
    }

    #[test]
    fn test_new_estimator() {
        let estimator = FeeEstimator::new();
        let stats = estimator.get_stats();
        assert_eq!(stats.blocks_tracked, 0);
    }

    #[test]
    fn test_empty_estimator_returns_min_fee() {
        let estimator = FeeEstimator::new();
        let fee = estimator.estimate_fee(6);
        assert_eq!(fee, MIN_FEE_RATE);
    }

    #[test]
    fn test_add_block() {
        let estimator = FeeEstimator::new();
        let block = create_test_block(5);

        estimator.add_block(100, &block, Amount::from_sat(5000));

        let stats = estimator.get_stats();
        assert_eq!(stats.blocks_tracked, 1);
        assert_eq!(stats.latest_height, 100);
    }

    #[test]
    fn test_estimate_with_blocks() {
        let estimator = FeeEstimator::new();

        for i in 0..10 {
            let block = create_test_block(10);
            estimator.add_block(100 + i, &block, Amount::from_sat(10000));
        }

        let fee = estimator.estimate_fee(6);
        assert!(fee >= MIN_FEE_RATE);
    }

    #[test]
    fn test_max_block_history() {
        let estimator = FeeEstimator::new();

        for i in 0..(MAX_BLOCK_HISTORY + 100) {
            let block = create_test_block(5);
            estimator.add_block(i as u32, &block, Amount::from_sat(5000));
        }

        let stats = estimator.get_stats();
        assert_eq!(stats.blocks_tracked, MAX_BLOCK_HISTORY);
    }

    #[test]
    fn test_smart_fee_estimation() {
        let estimator = FeeEstimator::new();

        for i in 0..20 {
            let block = create_test_block(10);
            estimator.add_block(100 + i, &block, Amount::from_sat(10000));
        }

        let (fee_rate, blocks) = estimator.estimate_smart_fee(6);
        assert!(fee_rate >= MIN_FEE_RATE);
        assert_eq!(blocks, 6);
    }

    #[test]
    fn test_smart_fee_with_limited_blocks() {
        let estimator = FeeEstimator::new();

        for i in 0..3 {
            let block = create_test_block(10);
            estimator.add_block(100 + i, &block, Amount::from_sat(10000));
        }

        let (fee_rate, blocks) = estimator.estimate_smart_fee(10);
        assert!(fee_rate >= MIN_FEE_RATE);
        assert_eq!(blocks, 3);
    }

    // ============================================================
    // MISSING TESTS: default fee, update on block connect
    // ============================================================

    #[test]
    fn test_default_fee_is_min_fee_rate() {
        // Empty estimator returns MIN_FEE_RATE as default
        let estimator = FeeEstimator::new();
        assert_eq!(estimator.estimate_fee(1), MIN_FEE_RATE);
        assert_eq!(estimator.estimate_fee(6), MIN_FEE_RATE);
        assert_eq!(estimator.estimate_fee(100), MIN_FEE_RATE);
    }

    #[test]
    fn test_fee_updates_after_block_connect() {
        let estimator = FeeEstimator::new();

        // Before any block: default fee
        assert_eq!(estimator.estimate_fee(1), MIN_FEE_RATE);
        assert_eq!(estimator.get_stats().blocks_tracked, 0);

        // Connect a block with a non-trivial fee
        let block = create_test_block(5);
        estimator.add_block(100, &block, Amount::from_sat(100_000));

        // After block: stats updated
        assert_eq!(estimator.get_stats().blocks_tracked, 1);
        assert_eq!(estimator.get_stats().latest_height, 100);

        // Fee rate should now be non-trivial (based on actual block data)
        let fee = estimator.estimate_fee(1);
        assert!(fee >= MIN_FEE_RATE);
    }

    #[test]
    fn test_fee_increases_with_higher_block_fees() {
        // Higher fees in the block should yield a higher fee rate estimate
        let estimator_low = FeeEstimator::new();
        let estimator_high = FeeEstimator::new();

        let block = create_test_block(10);

        estimator_low.add_block(100, &block, Amount::from_sat(1_000));
        estimator_high.add_block(100, &block, Amount::from_sat(1_000_000));

        let fee_low = estimator_low.estimate_fee(1);
        let fee_high = estimator_high.estimate_fee(1);

        assert!(fee_high > fee_low);
    }

    #[test]
    fn test_stats_latest_height_updates() {
        let estimator = FeeEstimator::new();
        let block = create_test_block(5);

        estimator.add_block(200, &block, Amount::from_sat(5000));
        assert_eq!(estimator.get_stats().latest_height, 200);

        estimator.add_block(201, &block, Amount::from_sat(5000));
        assert_eq!(estimator.get_stats().latest_height, 201);
    }

    #[test]
    fn test_estimate_fee_zero_target_returns_min() {
        let estimator = FeeEstimator::new();
        let block = create_test_block(5);
        estimator.add_block(100, &block, Amount::from_sat(5000));

        // conf_target of 0 should return MIN_FEE_RATE (sample_size = 0)
        let fee = estimator.estimate_fee(0);
        assert_eq!(fee, MIN_FEE_RATE);
    }

    #[test]
    fn test_fee_estimator_default_is_new() {
        let e1 = FeeEstimator::new();
        let e2 = FeeEstimator::default();
        // Both should have 0 blocks and the same min fee
        assert_eq!(e1.get_stats().blocks_tracked, 0);
        assert_eq!(e2.get_stats().blocks_tracked, 0);
        assert_eq!(e1.estimate_fee(6), e2.estimate_fee(6));
    }

    #[test]
    fn test_smart_fee_empty_returns_requested_target() {
        let estimator = FeeEstimator::new();
        let (fee, target) = estimator.estimate_smart_fee(6);
        assert_eq!(fee, MIN_FEE_RATE);
        assert_eq!(target, 6);
    }
}
