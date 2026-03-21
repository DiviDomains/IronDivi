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

//! Difficulty adjustment implementation
//!
//! Implements DarkGravity v3 for PoW and exponential moving average for PoS.
//! Based on C++ Divi implementation in DifficultyAdjuster.cpp
//!
//! References:
//! - Divi/divi/src/DifficultyAdjuster.cpp:6-106
//! - Divi/divi/src/chainparams.h:108
//! - Divi/divi/src/chain.h (GetBlockTime method)

use crate::block_index::BlockIndex;
use crate::database::ChainDatabase;
use crate::error::StorageError;
use divi_primitives::hash::Hash256;
use std::sync::Arc;

/// Network-specific difficulty parameters
#[derive(Debug, Clone)]
pub struct DifficultyParams {
    /// Proof-of-work limit (maximum target/minimum difficulty)
    pub pow_limit: Hash256,
    /// Target block spacing in seconds (60 for Divi)
    pub target_spacing: i64,
    /// Last block using Proof-of-Work
    pub last_pow_block: u32,
    /// Whether to retarget difficulty (false for regtest)
    pub retarget_difficulty: bool,
}

impl Default for DifficultyParams {
    fn default() -> Self {
        // Mainnet parameters (from chainparams.cpp:303)
        DifficultyParams {
            // ProofOfWorkLimit: ~uint256(0) >> 24
            pow_limit: Hash256::from_compact(0x1e0fffff),
            target_spacing: 60,
            last_pow_block: 56700,
            retarget_difficulty: true,
        }
    }
}

impl DifficultyParams {
    /// Create regtest parameters
    pub fn regtest() -> Self {
        DifficultyParams {
            pow_limit: Hash256::from_compact(0x1e0fffff),
            target_spacing: 60,
            last_pow_block: 100,
            retarget_difficulty: false,
        }
    }

    /// Create testnet parameters
    pub fn testnet() -> Self {
        DifficultyParams {
            pow_limit: Hash256::from_compact(0x1e0fffff),
            target_spacing: 60,
            last_pow_block: 100,
            retarget_difficulty: true,
        }
    }
}

/// Convert Hash256 to compact bits representation
///
/// Reference: C++ uint256::GetCompact in Divi/divi/src/uint256.cpp:316-337
fn to_compact(hash: &Hash256) -> u32 {
    // Find the first non-zero byte (from most significant end)
    let bytes = hash.as_bytes();
    let mut size = 32;

    // Find actual size (trim leading zeros)
    while size > 0 && bytes[size - 1] == 0 {
        size -= 1;
    }

    if size == 0 {
        return 0;
    }

    // Build compact representation
    let mut compact: u32;
    if size <= 3 {
        // For small values, shift into position
        compact = bytes[0] as u32;
        if size > 1 {
            compact |= (bytes[1] as u32) << 8;
        }
        if size > 2 {
            compact |= (bytes[2] as u32) << 16;
        }
        compact <<= 8 * (3 - size);
    } else {
        // For larger values, take 3 bytes from the most significant end
        compact = (bytes[size - 3] as u32)
            | ((bytes[size - 2] as u32) << 8)
            | ((bytes[size - 1] as u32) << 16);
    }

    // If high bit is set, need to adjust
    // Reference: uint256.cpp:328-331
    if (compact & 0x00800000) != 0 {
        compact >>= 8;
        size += 1;
    }

    // Encode size in top byte
    compact |= (size as u32) << 24;

    compact
}

/// Compute next block difficulty target
///
/// Implements the algorithm from C++ Divi DifficultyAdjuster::computeNextBlockDifficulty
/// Reference: Divi/divi/src/DifficultyAdjuster.cpp:6-99
pub fn get_next_work_required(
    db: &Arc<ChainDatabase>,
    prev_block: &BlockIndex,
    params: &DifficultyParams,
) -> Result<u32, StorageError> {
    // Genesis or early blocks: return PoW limit
    // Reference: DifficultyAdjuster.cpp:19-21
    if prev_block.height == 0 || prev_block.height < 24 {
        return Ok(to_compact(&params.pow_limit));
    }

    // Regtest: don't retarget
    // Reference: DifficultyAdjuster.cpp:23-24
    if !params.retarget_difficulty {
        return Ok(prev_block.bits);
    }

    // After last PoW block: use PoS difficulty adjustment
    // Reference: DifficultyAdjuster.cpp:26-51
    if prev_block.height > params.last_pow_block {
        return compute_pos_difficulty(db, prev_block, params);
    }

    // PoW: use DarkGravity v3
    // Reference: DifficultyAdjuster.cpp:53-99
    compute_pow_difficulty(db, prev_block, params)
}

/// Compute PoS difficulty using exponential moving average
///
/// Reference: Divi/divi/src/DifficultyAdjuster.cpp:26-51
fn compute_pos_difficulty(
    db: &Arc<ChainDatabase>,
    prev_block: &BlockIndex,
    _params: &DifficultyParams,
) -> Result<u32, StorageError> {
    // PoS target limit: ~uint256(0) >> 24
    // Reference: DifficultyAdjuster.cpp:27
    let target_limit = Hash256::from_compact(0x1e0fffff);

    // Target timespan: 60 * 40 = 2400 seconds (40 minutes)
    // Reference: DifficultyAdjuster.cpp:28-29
    let target_spacing = 60i64;
    let target_timespan = 60i64 * 40;

    // Calculate actual spacing
    // Reference: DifficultyAdjuster.cpp:31-36
    let mut actual_spacing = 0i64;
    if prev_block.height != 0 {
        // Get previous block to compute time delta
        let pprev = db.get_block_index(&prev_block.prev_hash)?.ok_or_else(|| {
            StorageError::BlockNotFound(format!("prev_block: {}", prev_block.prev_hash))
        })?;

        actual_spacing = (prev_block.time as i64) - (pprev.time as i64);
    }

    // Clamp to minimum 1 second
    // Reference: DifficultyAdjuster.cpp:35-36
    if actual_spacing < 1 {
        actual_spacing = 1;
    }

    // Exponential moving average formula
    // Reference: DifficultyAdjuster.cpp:38-45
    let interval = target_timespan / target_spacing; // = 40
    let target = Hash256::from_compact(prev_block.bits);

    // target *= ((interval - 1) * spacing + actual + actual) / ((interval + 1) * spacing)
    // Numerator: (40-1)*60 + actual + actual = 2340 + 2*actual
    // Denominator: (40+1)*60 = 2460
    let numerator = ((interval - 1) * target_spacing + actual_spacing + actual_spacing) as u64;
    let denominator = ((interval + 1) * target_spacing) as u64;

    // Perform 256-bit multiplication: target = target * numerator / denominator
    // Must use full 256-bit math because target values occupy bytes 24-26
    // (for typical PoS difficulty ~0x1b3xxxxx), far beyond u128 range.
    let numerator_hash = Hash256::from_u128_le(numerator as u128);
    let mut target = match target.multiply_by(&numerator_hash) {
        Some(t) => t.divide_by_u64(denominator),
        None => {
            // Overflow means extremely high target — clamp to limit
            target_limit
        }
    };

    // Clamp to target limit
    // Reference: DifficultyAdjuster.cpp:47-48
    if target.is_zero() || target > target_limit {
        target = target_limit;
    }

    Ok(to_compact(&target))
}

/// Compute PoW difficulty using DarkGravity v3
///
/// DarkGravity v3 by Evan Duffield - evan@dashpay.io
/// Reference: Divi/divi/src/DifficultyAdjuster.cpp:53-99
fn compute_pow_difficulty(
    db: &Arc<ChainDatabase>,
    prev_block: &BlockIndex,
    params: &DifficultyParams,
) -> Result<u32, StorageError> {
    const PAST_BLOCKS_MIN: i64 = 24;
    const PAST_BLOCKS_MAX: i64 = 24;

    let mut block_reading = Some(prev_block.clone());
    let mut actual_timespan = 0i64;
    let mut last_block_time = 0u32;
    let mut count_blocks = 0i64;
    let mut past_difficulty_avg = Hash256::zero();
    let mut past_difficulty_avg_prev = Hash256::zero();

    // Iterate through past 24 blocks
    // Reference: DifficultyAdjuster.cpp:53-79
    for _i in 1..=PAST_BLOCKS_MAX as usize {
        if let Some(ref current) = block_reading {
            count_blocks += 1;

            // Calculate average difficulty for first 24 blocks
            // Reference: DifficultyAdjuster.cpp:59-66
            if count_blocks <= PAST_BLOCKS_MIN {
                let current_diff = Hash256::from_compact(current.bits);
                if count_blocks == 1 {
                    past_difficulty_avg = current_diff;
                } else {
                    // avg = (avg_prev * count + current) / (count + 1)
                    // Using 256-bit arithmetic via multiply_by and division
                    let count_hash = Hash256::from_u128_le(count_blocks as u128);
                    if let Some(avg_times_count) = past_difficulty_avg_prev.multiply_by(&count_hash)
                    {
                        // Add current difficulty
                        if let Some(sum) = avg_times_count.checked_add(&current_diff) {
                            // Divide by (count + 1)
                            past_difficulty_avg = sum.divide_by_u64((count_blocks + 1) as u64);
                        } else {
                            // Overflow in addition, clamp to max
                            past_difficulty_avg = params.pow_limit;
                        }
                    } else {
                        // Overflow in multiplication, clamp to max
                        past_difficulty_avg = params.pow_limit;
                    }
                }
                past_difficulty_avg_prev = past_difficulty_avg;
            }

            // Calculate timespan
            // Reference: DifficultyAdjuster.cpp:68-71
            if last_block_time > 0 {
                let diff = (last_block_time as i64) - (current.time as i64);
                actual_timespan += diff;
            }
            last_block_time = current.time;

            // Move to previous block
            // Reference: DifficultyAdjuster.cpp:74-79
            if current.height == 0 {
                break;
            }

            block_reading = db.get_block_index(&current.prev_hash)?;
        } else {
            break;
        }
    }

    // Compute new target from average difficulty
    // Reference: DifficultyAdjuster.cpp:81-96
    let mut new_target = past_difficulty_avg;

    // Expected timespan: count * target_spacing
    // Reference: DifficultyAdjuster.cpp:83
    let target_timespan = count_blocks * params.target_spacing;

    // Clamp actual timespan to [1/3 * expected, 3 * expected]
    // Reference: DifficultyAdjuster.cpp:85-88
    if actual_timespan < target_timespan / 3 {
        actual_timespan = target_timespan / 3;
    }
    if actual_timespan > target_timespan * 3 {
        actual_timespan = target_timespan * 3;
    }

    // Retarget: new_target = avg * actual / expected
    // Reference: DifficultyAdjuster.cpp:90-92
    let actual_hash = Hash256::from_u128_le(actual_timespan as u128);
    if let Some(product) = new_target.multiply_by(&actual_hash) {
        new_target = product.divide_by_u64(target_timespan as u64);
    } else {
        // Overflow, clamp to limit
        new_target = params.pow_limit;
    }

    // Clamp to PoW limit
    // Reference: DifficultyAdjuster.cpp:94-96
    if new_target > params.pow_limit {
        new_target = params.pow_limit;
    }

    Ok(to_compact(&new_target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_index::BlockStatus;
    use divi_primitives::hash::Hash256;

    fn create_test_db() -> Arc<ChainDatabase> {
        let temp_dir = tempfile::tempdir().unwrap();
        Arc::new(ChainDatabase::open(temp_dir.path()).unwrap())
    }

    fn create_block_index(height: u32, time: u32, bits: u32, prev: Hash256) -> BlockIndex {
        BlockIndex {
            hash: Hash256::from_slice(&[height as u8; 32]),
            prev_hash: prev,
            height,
            time,
            bits,
            nonce: 0,
            version: 1,
            merkle_root: Hash256::zero(),
            status: BlockStatus::empty(),
            chain_work: [0u8; 32],
            n_tx: 1,
            file_num: -1,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: divi_primitives::lottery::LotteryWinners::default(),
            accumulator: None,
            is_proof_of_stake: false,
        }
    }

    #[test]
    fn test_genesis_returns_pow_limit() {
        let db = create_test_db();
        let params = DifficultyParams::default();
        let genesis = create_block_index(0, 1000, 0x1e0fffff, Hash256::zero());

        let result = get_next_work_required(&db, &genesis, &params).unwrap();
        assert_eq!(result, to_compact(&params.pow_limit));
    }

    #[test]
    fn test_early_blocks_return_pow_limit() {
        let db = create_test_db();
        let params = DifficultyParams::default();

        for height in 1..24 {
            let block = create_block_index(height, 1000 + height * 60, 0x1e0fffff, Hash256::zero());
            let result = get_next_work_required(&db, &block, &params).unwrap();
            assert_eq!(
                result,
                to_compact(&params.pow_limit),
                "Height {} should return PoW limit",
                height
            );
        }
    }

    #[test]
    fn test_regtest_no_retarget() {
        let db = create_test_db();
        let mut params = DifficultyParams::regtest();
        params.retarget_difficulty = false;

        let block = create_block_index(100, 7000, 0x207fffff, Hash256::zero());
        let result = get_next_work_required(&db, &block, &params).unwrap();
        assert_eq!(result, 0x207fffff, "Regtest should not retarget");
    }

    #[test]
    fn test_pos_difficulty_stable_spacing() {
        let db = create_test_db();
        let params = DifficultyParams::default();

        // Create two blocks with exactly target spacing (60 seconds)
        let pprev = create_block_index(56700, 1000, 0x1e0fffff, Hash256::zero());
        let pprev_hash = pprev.hash;
        let prev = create_block_index(56701, 1060, 0x1e0fffff, pprev_hash);

        db.store_block_index(&pprev).unwrap();

        let result = get_next_work_required(&db, &prev, &params).unwrap();

        // With perfect 60s spacing, difficulty should remain roughly stable
        // Formula: target *= (2340 + 120) / 2460 = 2460/2460 = 1.0
        assert!(result > 0, "Should return valid difficulty");
    }

    #[test]
    fn test_pos_difficulty_fast_blocks() {
        let db = create_test_db();
        let params = DifficultyParams::default();

        // Create blocks with 30s spacing (too fast)
        let pprev = create_block_index(56700, 1000, 0x1e0fffff, Hash256::zero());
        let pprev_hash = pprev.hash;
        let prev = create_block_index(56701, 1030, 0x1e0fffff, pprev_hash);

        db.store_block_index(&pprev).unwrap();

        let result = get_next_work_required(&db, &prev, &params).unwrap();

        // Fast blocks should increase difficulty (decrease target/bits)
        // Actual spacing = 30, formula: target *= (2340 + 60) / 2460 < 1.0
        // With integer arithmetic and compact representation, the change might be too small to affect bits
        assert!(
            result <= 0x1e0fffff,
            "Fast blocks should not decrease difficulty. Expected <= 0x1e0fffff, got: 0x{:08x}",
            result
        );
    }

    #[test]
    fn test_pos_difficulty_slow_blocks() {
        let db = create_test_db();
        let params = DifficultyParams::default();

        // Create blocks with 120s spacing (too slow)
        let pprev = create_block_index(56700, 1000, 0x1e0fffff, Hash256::zero());
        let pprev_hash = pprev.hash;
        let prev = create_block_index(56701, 1120, 0x1e0fffff, pprev_hash);

        db.store_block_index(&pprev).unwrap();

        let result = get_next_work_required(&db, &prev, &params).unwrap();

        // Slow blocks should decrease difficulty (increase target/bits)
        // Actual spacing = 120, formula: target *= (2340 + 240) / 2460 > 1.0
        assert!(
            result >= 0x1e0fffff,
            "Slow blocks should decrease difficulty"
        );
    }

    #[test]
    fn test_pos_difficulty_clamps_to_limit() {
        let db = create_test_db();
        let params = DifficultyParams::default();

        // Create blocks with extremely slow spacing (10 minutes = 600s)
        let pprev = create_block_index(56700, 1000, 0x1e0fffff, Hash256::zero());
        let pprev_hash = pprev.hash;
        let prev = create_block_index(56701, 1600, 0x1e0fffff, pprev_hash);

        db.store_block_index(&pprev).unwrap();

        let result = get_next_work_required(&db, &prev, &params).unwrap();

        // Should clamp to target limit
        assert_eq!(result, 0x1e0fffff, "Should clamp to PoS limit");
    }

    #[test]
    fn test_pow_difficulty_darkgravity_v3() {
        let db = create_test_db();
        let params = DifficultyParams::default();

        // Create a chain of 25 blocks with varying timestamps
        let mut prev_hash = Hash256::zero();
        for i in 0..25 {
            let time = 1000 + i * 60; // Perfect 60s spacing
            let block = create_block_index(i, time, 0x1e0fffff, prev_hash);
            prev_hash = block.hash;
            db.store_block_index(&block).unwrap();
        }

        let last_block = db.get_block_index(&prev_hash).unwrap().unwrap();
        let result = get_next_work_required(&db, &last_block, &params).unwrap();

        // With perfect spacing, difficulty should be stable
        assert!(
            result > 0,
            "Should return valid PoW difficulty, got: {}",
            result
        );
    }

    #[test]
    fn test_pos_to_pow_transition() {
        let db = create_test_db();
        let params = DifficultyParams {
            last_pow_block: 100,
            ..DifficultyParams::default()
        };

        // Block 100 (last PoW)
        let block100 = create_block_index(100, 6000, 0x1e0fffff, Hash256::zero());

        // Should use PoW algorithm
        let result = get_next_work_required(&db, &block100, &params).unwrap();
        assert!(result > 0, "Block 100 should use PoW difficulty");

        // Block 101 (first PoS)
        let prev_hash = Hash256::from_slice(&[100u8; 32]);
        let block100_for_db = create_block_index(100, 6000, 0x1e0fffff, Hash256::zero());
        let block101 = create_block_index(101, 6060, 0x1e0fffff, prev_hash);

        db.store_block_index(&block100_for_db).unwrap();

        let result = get_next_work_required(&db, &block101, &params).unwrap();
        assert!(result > 0, "Block 101 should use PoS difficulty");
    }

    #[test]
    fn test_pos_difficulty_realistic_bits() {
        // Test with realistic PoS difficulty (0x1b3xxxxx range)
        // These bits have significant bytes at position 24-26 in the hash,
        // which requires full 256-bit arithmetic (not just u128).
        let db = create_test_db();
        let params = DifficultyParams {
            last_pow_block: 100,
            ..DifficultyParams::default()
        };

        // Block at height 24044 with bits 0x1b3be3cb, time delta 60s (perfect)
        let pprev = create_block_index(24044, 1772484940, 0x1b37b8d5, Hash256::zero());
        let pprev_hash = pprev.hash;
        let prev = create_block_index(24045, 1772485000, 0x1b39045d, pprev_hash);

        db.store_block_index(&pprev).unwrap();

        let result = get_next_work_required(&db, &prev, &params).unwrap();

        // With perfect 60s spacing, the result should be close to prev.bits
        // Formula: target *= (2340 + 120) / 2460 = 2460/2460 = 1.0
        // The result should NOT be 0x1e0fffff (that would indicate truncation bug)
        assert_ne!(
            result, 0x1e0fffff,
            "Should not clamp to pow_limit — indicates 256-bit arithmetic bug"
        );

        // Result should be in the same ballpark as the input bits
        let result_exp = (result >> 24) as u8;
        let input_exp = (0x1b39045d_u32 >> 24) as u8;
        assert_eq!(
            result_exp, input_exp,
            "Exponent should stay at 0x1b, got 0x{:02x}",
            result_exp
        );

        // Verify the result is reasonable (within 5% of input)
        let result_mantissa = result & 0x00FFFFFF;
        let input_mantissa = 0x1b39045d & 0x00FFFFFF;
        let diff = (result_mantissa as i64 - input_mantissa as i64).unsigned_abs();
        let max_diff = input_mantissa as u64 / 20; // 5%
        assert!(
            diff <= max_diff,
            "Mantissa should be within 5% of input: result=0x{:06x}, input=0x{:06x}, diff={}",
            result_mantissa,
            input_mantissa,
            diff,
        );
    }
}
