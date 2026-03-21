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

//! Block reward calculation matching C++ Divi implementation
//!
//! This module implements the block subsidy and reward distribution logic
//! exactly as implemented in the C++ Divi codebase.

use divi_primitives::amount::Amount;
use divi_primitives::constants::COIN;

/// Block rewards distribution for a single block
///
/// Matches C++ `CBlockRewards` structure from blocksubsidy.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRewards {
    /// Reward for the staker (PoS) or miner (PoW)
    pub staker_reward: Amount,
    /// Reward for masternode
    pub masternode_reward: Amount,
    /// Reward for treasury
    pub treasury_reward: Amount,
    /// Reward for charity
    pub charity_reward: Amount,
    /// Reward for lottery
    pub lottery_reward: Amount,
    /// Reward for proposals
    pub proposals_reward: Amount,
}

impl BlockRewards {
    /// Create a new BlockRewards with all fields set to zero
    pub fn zero() -> Self {
        Self {
            staker_reward: Amount::ZERO,
            masternode_reward: Amount::ZERO,
            treasury_reward: Amount::ZERO,
            charity_reward: Amount::ZERO,
            lottery_reward: Amount::ZERO,
            proposals_reward: Amount::ZERO,
        }
    }

    /// Create a BlockRewards where all rewards go to the staker/miner
    pub fn all_to_staker(amount: Amount) -> Self {
        Self {
            staker_reward: amount,
            masternode_reward: Amount::ZERO,
            treasury_reward: Amount::ZERO,
            charity_reward: Amount::ZERO,
            lottery_reward: Amount::ZERO,
            proposals_reward: Amount::ZERO,
        }
    }

    /// Get the total of all rewards
    pub fn total(&self) -> Amount {
        self.staker_reward
            + self.masternode_reward
            + self.treasury_reward
            + self.charity_reward
            + self.lottery_reward
            + self.proposals_reward
    }
}

impl Default for BlockRewards {
    fn default() -> Self {
        Self::zero()
    }
}

/// Network-specific reward parameters
#[derive(Debug, Clone, Copy)]
pub struct RewardParams {
    /// Amount for block 1 premine
    pub premine_amount: Amount,
    /// Last block that uses Proof of Work (blocks 0-100 are PoW on mainnet)
    pub last_pow_block: u32,
    /// First block that participates in lottery
    pub lottery_start_block: u32,
    /// Number of blocks between lottery payouts
    pub lottery_cycle: u32,
    /// First block that participates in treasury
    pub treasury_start_block: u32,
    /// Number of blocks between treasury payouts
    pub treasury_cycle: u32,
    /// Number of blocks between subsidy halvings
    pub subsidy_halving_interval: u32,
}

impl RewardParams {
    /// Mainnet parameters matching C++ Divi
    pub fn mainnet() -> Self {
        Self {
            premine_amount: Amount::from_sat(617_222_416 * COIN),
            last_pow_block: 100,
            lottery_start_block: 101,
            lottery_cycle: 10_080, // ~1 week at 1 block/minute
            treasury_start_block: 101,
            treasury_cycle: 10_081,            // Slightly offset from lottery
            subsidy_halving_interval: 525_600, // 60 * 24 * 365 = 1 year in minutes
        }
    }

    /// Testnet parameters
    pub fn testnet() -> Self {
        Self {
            premine_amount: Amount::from_sat(617_222_416 * COIN),
            last_pow_block: 100,
            lottery_start_block: 101,
            lottery_cycle: 200,              // C++ testnet: 200
            treasury_start_block: 102,       // C++ testnet: 102
            treasury_cycle: 201,             // C++ testnet: 201
            subsidy_halving_interval: 1_000, // C++ testnet: 1000
        }
    }

    /// Regtest parameters (shorter cycles for testing)
    pub fn regtest() -> Self {
        Self {
            premine_amount: Amount::from_sat(1_250 * COIN), // C++ regtest: 1250 COIN
            last_pow_block: 100,
            lottery_start_block: 101,
            lottery_cycle: 10,             // C++ regtest: 10
            treasury_start_block: 102,     // C++ regtest: 102
            treasury_cycle: 50,            // C++ regtest: 50
            subsidy_halving_interval: 100, // C++ regtest: 100
        }
    }
}

/// Calculate the base block subsidy for a given height
///
/// Matches C++ `BlockSubsidy()` from blocksubsidy.cpp
///
/// # Formula
/// - Block 0: 50 COIN (genesis block)
/// - Block 1: 617,222,416 COIN (premine)
/// - Other blocks: max(1250 - 100 * max(height/halving_interval - 1, 0), 250) COIN
///
/// The halving interval is 525,600 blocks (1 year at 1 block/minute)
pub fn block_subsidy(height: u32, params: &RewardParams) -> Amount {
    // Genesis block
    if height == 0 {
        return Amount::from_sat(50 * COIN);
    }

    // Premine block
    if height == 1 {
        return params.premine_amount;
    }

    // Regular blocks use halving formula
    // C++ formula: max(1250 - 100 * max(nHeight/nSubsidyHalvingInterval - 1, 0), 250) * COIN
    let halving_number = height / params.subsidy_halving_interval;
    let reduction = if halving_number > 0 {
        halving_number - 1
    } else {
        0
    };

    let subsidy_divi = 1250i64.saturating_sub((reduction as i64) * 100).max(250);

    Amount::from_sat(subsidy_divi * COIN)
}

/// Distribution percentages for PoS blocks (in basis points, 10000 = 100%)
/// Matches C++ nStakeReward, nMasternodeReward, etc. from chainparams.cpp
const STAKER_PERCENT: i64 = 3800; // 38%
const MASTERNODE_PERCENT: i64 = 4500; // 45%
const TREASURY_PERCENT: i64 = 1600; // 16%
const CHARITY_PERCENT: i64 = 100; // 1%
const PROPOSALS_PERCENT: i64 = 0; // 0%

/// Fixed lottery contribution per block (50 COIN)
const LOTTERY_CONTRIBUTION: i64 = 50 * COIN;

/// Calculate block rewards with distribution
///
/// Matches C++ `GetBlockSubsidy()` from blocksubsidy.cpp
///
/// # Distribution
/// - For PoW blocks (height <= last_pow_block): All reward goes to miner
/// - For PoS blocks:
///   - 50 COIN is set aside for lottery (if lottery has started)
///   - Remaining is distributed: 38% staker, 45% masternode, 16% treasury, 1% charity
pub fn get_block_rewards(height: u32, params: &RewardParams) -> BlockRewards {
    let total_subsidy = block_subsidy(height, params);

    // PoW blocks: all reward goes to miner/staker
    if height <= params.last_pow_block {
        return BlockRewards::all_to_staker(total_subsidy);
    }

    // PoS blocks: distribute according to percentages
    let lottery_reward = if height >= params.lottery_start_block {
        Amount::from_sat(LOTTERY_CONTRIBUTION)
    } else {
        Amount::ZERO
    };

    // Remaining after lottery contribution
    let distributable = total_subsidy.saturating_sub(lottery_reward);
    let distributable_sat = distributable.as_sat();

    // Calculate each component's share
    // Using integer arithmetic to match C++ behavior
    let staker_reward = Amount::from_sat((distributable_sat * STAKER_PERCENT) / 10000);
    let masternode_reward = Amount::from_sat((distributable_sat * MASTERNODE_PERCENT) / 10000);
    let treasury_reward = Amount::from_sat((distributable_sat * TREASURY_PERCENT) / 10000);
    let charity_reward = Amount::from_sat((distributable_sat * CHARITY_PERCENT) / 10000);
    let proposals_reward = Amount::from_sat((distributable_sat * PROPOSALS_PERCENT) / 10000);

    BlockRewards {
        staker_reward,
        masternode_reward,
        treasury_reward,
        charity_reward,
        lottery_reward,
        proposals_reward,
    }
}

/// Check if a block is a lottery payout block
///
/// Lottery blocks occur every `lottery_cycle` blocks starting from `lottery_start_block`
pub fn is_lottery_block(height: u32, params: &RewardParams) -> bool {
    if height < params.lottery_start_block {
        return false;
    }

    let blocks_since_start = height - params.lottery_start_block;
    blocks_since_start > 0 && (blocks_since_start % params.lottery_cycle) == 0
}

/// Check if a block is a treasury payout block
///
/// Treasury blocks occur every `treasury_cycle` blocks starting from `treasury_start_block`
pub fn is_treasury_block(height: u32, params: &RewardParams) -> bool {
    if height < params.treasury_start_block {
        return false;
    }

    let blocks_since_start = height - params.treasury_start_block;
    blocks_since_start > 0 && (blocks_since_start % params.treasury_cycle) == 0
}

/// Get accumulated lottery reward up to a lottery payout block
///
/// The lottery accumulates 50 COIN per block between payouts
pub fn get_lottery_reward(height: u32, params: &RewardParams) -> Amount {
    if !is_lottery_block(height, params) {
        return Amount::ZERO;
    }

    // Lottery accumulates 50 COIN per block for lottery_cycle blocks
    Amount::from_sat(LOTTERY_CONTRIBUTION * params.lottery_cycle as i64)
}

/// Get accumulated treasury reward up to a treasury payout block
///
/// The treasury accumulates its share (16%) of each block's distribution
pub fn get_treasury_reward(height: u32, params: &RewardParams) -> Amount {
    if !is_treasury_block(height, params) {
        return Amount::ZERO;
    }

    // Treasury accumulates over treasury_cycle blocks
    // For simplicity, we calculate based on average block subsidy
    // In practice, this should account for any subsidy changes during the period
    let rewards = get_block_rewards(height, params);
    Amount::from_sat(rewards.treasury_reward.as_sat() * params.treasury_cycle as i64)
}

/// Get accumulated charity reward
///
/// Charity receives 1% of each block's distribution
pub fn get_charity_reward(height: u32, params: &RewardParams) -> Amount {
    let rewards = get_block_rewards(height, params);
    rewards.charity_reward
}

/// Calculate a conservative block reward estimate (75% of base subsidy)
///
/// This is used for economic estimates where we want a lower bound.
///
/// # Deprecated
/// This function is deprecated. Use `get_block_rewards()` for accurate
/// reward calculations or `block_subsidy()` for raw subsidy.
#[deprecated(
    since = "0.2.0",
    note = "Use get_block_rewards() for accurate calculations"
)]
pub fn get_conservative_block_reward(height: u32) -> Amount {
    let params = RewardParams::mainnet();
    let base_reward = block_subsidy(height, &params);

    // 75% of base reward as conservative estimate
    Amount::from_sat((base_reward.as_sat() * 75) / 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // Genesis and Premine Tests
    // ========================================

    #[test]
    fn test_genesis_block_subsidy() {
        let params = RewardParams::mainnet();
        let subsidy = block_subsidy(0, &params);
        assert_eq!(subsidy.as_sat(), 50 * COIN);
        assert_eq!(subsidy.as_divi(), 50);
    }

    #[test]
    fn test_block_1_premine() {
        let params = RewardParams::mainnet();
        let subsidy = block_subsidy(1, &params);
        assert_eq!(subsidy.as_sat(), 617_222_416 * COIN);
        assert_eq!(subsidy.as_divi(), 617_222_416);
    }

    #[test]
    fn test_premine_rewards_distribution() {
        // Block 1 is a PoW block, so all goes to staker
        let params = RewardParams::mainnet();
        let rewards = get_block_rewards(1, &params);
        assert_eq!(rewards.staker_reward.as_divi(), 617_222_416);
        assert_eq!(rewards.masternode_reward.as_sat(), 0);
        assert_eq!(rewards.treasury_reward.as_sat(), 0);
        assert_eq!(rewards.total().as_divi(), 617_222_416);
    }

    // ========================================
    // Regular Block Subsidy Tests
    // ========================================

    #[test]
    fn test_early_block_subsidy() {
        let params = RewardParams::mainnet();
        // Before first halving, subsidy is 1250 DIVI
        let subsidy = block_subsidy(1000, &params);
        assert_eq!(subsidy.as_sat(), 1250 * COIN);
        assert_eq!(subsidy.as_divi(), 1250);
    }

    #[test]
    fn test_first_halving_boundary() {
        let params = RewardParams::mainnet();
        let interval = params.subsidy_halving_interval;

        // Just before first halving: 1250 DIVI
        let subsidy_before = block_subsidy(interval - 1, &params);
        assert_eq!(subsidy_before.as_divi(), 1250);

        // At first halving: still 1250 DIVI (formula: max(1250 - 100 * max(1-1, 0), 250))
        let subsidy_at = block_subsidy(interval, &params);
        assert_eq!(subsidy_at.as_divi(), 1250);

        // After first halving: still 1250 until second interval
        let subsidy_after = block_subsidy(interval + 1, &params);
        assert_eq!(subsidy_after.as_divi(), 1250);
    }

    #[test]
    fn test_second_halving_boundary() {
        let params = RewardParams::mainnet();
        let interval = params.subsidy_halving_interval;

        // At second halving: 1150 DIVI (1250 - 100 * 1)
        let subsidy = block_subsidy(interval * 2, &params);
        assert_eq!(subsidy.as_divi(), 1150);
    }

    #[test]
    fn test_third_halving() {
        let params = RewardParams::mainnet();
        let interval = params.subsidy_halving_interval;

        // At third halving: 1050 DIVI (1250 - 100 * 2)
        let subsidy = block_subsidy(interval * 3, &params);
        assert_eq!(subsidy.as_divi(), 1050);
    }

    #[test]
    fn test_minimum_subsidy() {
        let params = RewardParams::mainnet();

        // Very far in the future, subsidy floors at 250 DIVI
        let subsidy = block_subsidy(100_000_000, &params);
        assert_eq!(subsidy.as_divi(), 250);
    }

    #[test]
    fn test_subsidy_halving_formula() {
        let params = RewardParams::mainnet();
        let interval = params.subsidy_halving_interval;

        // Test the formula: max(1250 - 100 * max(height/interval - 1, 0), 250)
        let expected = [
            (0, 50),               // Genesis special case
            (1, 617_222_416),      // Premine special case
            (100, 1250),           // Early block
            (interval, 1250),      // First interval: max(1250 - 100*0, 250) = 1250
            (interval * 2, 1150),  // Second interval: max(1250 - 100*1, 250) = 1150
            (interval * 3, 1050),  // Third interval: max(1250 - 100*2, 250) = 1050
            (interval * 4, 950),   // Fourth interval: max(1250 - 100*3, 250) = 950
            (interval * 5, 850),   // Fifth interval: max(1250 - 100*4, 250) = 850
            (interval * 10, 350),  // Tenth interval: max(1250 - 100*9, 250) = 350
            (interval * 11, 250),  // Eleventh interval: max(1250 - 100*10, 250) = 250
            (interval * 12, 250),  // Floor reached
            (interval * 100, 250), // Still at floor
        ];

        for (height, expected_divi) in expected {
            let subsidy = block_subsidy(height, &params);
            assert_eq!(
                subsidy.as_divi(),
                expected_divi,
                "Height {} should have subsidy {} DIVI, got {}",
                height,
                expected_divi,
                subsidy.as_divi()
            );
        }
    }

    // ========================================
    // Reward Distribution Tests
    // ========================================

    #[test]
    fn test_pow_block_all_to_staker() {
        let params = RewardParams::mainnet();

        // All PoW blocks (0-100) should have all rewards go to staker
        for height in 0..=100 {
            let rewards = get_block_rewards(height, &params);
            let total = block_subsidy(height, &params);
            assert_eq!(
                rewards.staker_reward, total,
                "Height {} should have all reward to staker",
                height
            );
            assert_eq!(rewards.masternode_reward, Amount::ZERO);
            assert_eq!(rewards.treasury_reward, Amount::ZERO);
            assert_eq!(rewards.charity_reward, Amount::ZERO);
            assert_eq!(rewards.lottery_reward, Amount::ZERO);
        }
    }

    #[test]
    fn test_pos_block_distribution() {
        let params = RewardParams::mainnet();
        let height = 1000; // Well into PoS

        let rewards = get_block_rewards(height, &params);
        let total_subsidy = block_subsidy(height, &params);

        // Lottery takes 50 DIVI
        assert_eq!(rewards.lottery_reward.as_divi(), 50);

        // Remaining 1200 DIVI distributed according to percentages
        let distributable = 1200 * COIN;

        // 38% to staker
        assert_eq!(rewards.staker_reward.as_sat(), (distributable * 38) / 100);

        // 45% to masternode
        assert_eq!(
            rewards.masternode_reward.as_sat(),
            (distributable * 45) / 100
        );

        // 16% to treasury
        assert_eq!(rewards.treasury_reward.as_sat(), (distributable * 16) / 100);

        // 1% to charity
        assert_eq!(rewards.charity_reward.as_sat(), (distributable * 1) / 100);

        // 0% to proposals
        assert_eq!(rewards.proposals_reward.as_sat(), 0);

        // Total should match (with small rounding tolerance)
        let sum = rewards.total();
        // Due to integer division, total may be slightly less than subsidy
        assert!(sum.as_sat() <= total_subsidy.as_sat());
        assert!(sum.as_sat() >= total_subsidy.as_sat() - 10); // Within rounding error
    }

    #[test]
    fn test_distribution_percentages() {
        let params = RewardParams::mainnet();
        let rewards = get_block_rewards(1000, &params);

        // After lottery, check relative percentages
        let distributable = (1250 - 50) * COIN; // 1200 DIVI
        let staker_pct = (rewards.staker_reward.as_sat() * 100) / distributable;
        let mn_pct = (rewards.masternode_reward.as_sat() * 100) / distributable;
        let treasury_pct = (rewards.treasury_reward.as_sat() * 100) / distributable;
        let charity_pct = (rewards.charity_reward.as_sat() * 100) / distributable;

        assert_eq!(staker_pct, 38);
        assert_eq!(mn_pct, 45);
        assert_eq!(treasury_pct, 16);
        assert_eq!(charity_pct, 1);
    }

    // ========================================
    // Lottery and Treasury Block Tests
    // ========================================

    #[test]
    fn test_is_lottery_block() {
        let params = RewardParams::mainnet();

        // Before lottery starts
        assert!(!is_lottery_block(0, &params));
        assert!(!is_lottery_block(100, &params));
        assert!(!is_lottery_block(101, &params)); // Start block itself is not a lottery block

        // First lottery block
        let first_lottery = params.lottery_start_block + params.lottery_cycle;
        assert!(is_lottery_block(first_lottery, &params));

        // Second lottery block
        let second_lottery = params.lottery_start_block + params.lottery_cycle * 2;
        assert!(is_lottery_block(second_lottery, &params));

        // Non-lottery blocks
        assert!(!is_lottery_block(first_lottery - 1, &params));
        assert!(!is_lottery_block(first_lottery + 1, &params));
    }

    #[test]
    fn test_is_treasury_block() {
        let params = RewardParams::mainnet();

        // Before treasury starts
        assert!(!is_treasury_block(0, &params));
        assert!(!is_treasury_block(100, &params));
        assert!(!is_treasury_block(101, &params)); // Start block itself is not a treasury block

        // First treasury block
        let first_treasury = params.treasury_start_block + params.treasury_cycle;
        assert!(is_treasury_block(first_treasury, &params));

        // Second treasury block
        let second_treasury = params.treasury_start_block + params.treasury_cycle * 2;
        assert!(is_treasury_block(second_treasury, &params));

        // Non-treasury blocks
        assert!(!is_treasury_block(first_treasury - 1, &params));
        assert!(!is_treasury_block(first_treasury + 1, &params));
    }

    #[test]
    fn test_lottery_treasury_different_cycles() {
        let params = RewardParams::mainnet();

        // Lottery cycle is 10080, treasury cycle is 10081
        // They should rarely coincide
        let first_lottery = params.lottery_start_block + params.lottery_cycle;
        let first_treasury = params.treasury_start_block + params.treasury_cycle;

        assert_ne!(first_lottery, first_treasury);
        assert!(is_lottery_block(first_lottery, &params));
        assert!(!is_treasury_block(first_lottery, &params));
        assert!(is_treasury_block(first_treasury, &params));
        assert!(!is_lottery_block(first_treasury, &params));
    }

    #[test]
    fn test_lottery_reward_accumulation() {
        let params = RewardParams::mainnet();

        // Non-lottery block returns 0
        assert_eq!(get_lottery_reward(1000, &params).as_sat(), 0);

        // Lottery block returns accumulated amount (50 COIN * cycle)
        let lottery_block = params.lottery_start_block + params.lottery_cycle;
        let expected = 50 * COIN * params.lottery_cycle as i64;
        assert_eq!(
            get_lottery_reward(lottery_block, &params).as_sat(),
            expected
        );
    }

    // ========================================
    // BlockRewards Struct Tests
    // ========================================

    #[test]
    fn test_block_rewards_zero() {
        let rewards = BlockRewards::zero();
        assert_eq!(rewards.total().as_sat(), 0);
        assert_eq!(rewards.staker_reward.as_sat(), 0);
        assert_eq!(rewards.masternode_reward.as_sat(), 0);
    }

    #[test]
    fn test_block_rewards_all_to_staker() {
        let amount = Amount::from_divi(1000);
        let rewards = BlockRewards::all_to_staker(amount);

        assert_eq!(rewards.staker_reward, amount);
        assert_eq!(rewards.masternode_reward.as_sat(), 0);
        assert_eq!(rewards.total(), amount);
    }

    #[test]
    fn test_block_rewards_total() {
        let params = RewardParams::mainnet();
        let rewards = get_block_rewards(1000, &params);

        let manual_total = rewards.staker_reward
            + rewards.masternode_reward
            + rewards.treasury_reward
            + rewards.charity_reward
            + rewards.lottery_reward
            + rewards.proposals_reward;

        assert_eq!(rewards.total(), manual_total);
    }

    // ========================================
    // RewardParams Tests
    // ========================================

    #[test]
    fn test_mainnet_params() {
        let params = RewardParams::mainnet();
        assert_eq!(params.premine_amount.as_divi(), 617_222_416);
        assert_eq!(params.last_pow_block, 100);
        assert_eq!(params.lottery_start_block, 101);
        assert_eq!(params.lottery_cycle, 10_080);
        assert_eq!(params.treasury_start_block, 101);
        assert_eq!(params.treasury_cycle, 10_081);
        assert_eq!(params.subsidy_halving_interval, 525_600);
    }

    #[test]
    fn test_regtest_params() {
        let params = RewardParams::regtest();
        // Regtest premine is 1,250 DIVI
        assert_eq!(params.premine_amount.as_divi(), 1_250);
        // Shorter cycles for testing
        assert_eq!(params.lottery_cycle, 10);
        assert_eq!(params.treasury_cycle, 50);
        assert_eq!(params.treasury_start_block, 102);
        assert_eq!(params.subsidy_halving_interval, 100);
    }

    // ========================================
    // Backward Compatibility Tests
    // ========================================

    #[test]
    #[allow(deprecated)]
    fn test_conservative_block_reward_genesis() {
        let reward = get_conservative_block_reward(0);
        assert_eq!(reward.as_divi_f64(), 37.5); // 75% of 50
    }

    #[test]
    #[allow(deprecated)]
    fn test_conservative_block_reward_premine() {
        let reward = get_conservative_block_reward(1);
        // 75% of 617,222,416
        let expected = (617_222_416.0 * 0.75) as i64;
        assert_eq!(reward.as_divi(), expected);
    }

    #[test]
    #[allow(deprecated)]
    fn test_conservative_block_reward_regular() {
        let reward = get_conservative_block_reward(1000);
        assert_eq!(reward.as_divi_f64(), 937.5); // 75% of 1250
    }

    // ========================================
    // Edge Cases
    // ========================================

    #[test]
    fn test_block_at_pow_pos_boundary() {
        let params = RewardParams::mainnet();

        // Block 100 is last PoW block
        let rewards_100 = get_block_rewards(100, &params);
        assert_eq!(rewards_100.lottery_reward.as_sat(), 0);
        assert_eq!(rewards_100.masternode_reward.as_sat(), 0);

        // Block 101 is first PoS block
        let rewards_101 = get_block_rewards(101, &params);
        assert!(rewards_101.lottery_reward.as_sat() > 0);
        assert!(rewards_101.masternode_reward.as_sat() > 0);
    }

    #[test]
    fn test_very_large_height() {
        let params = RewardParams::mainnet();
        let height = u32::MAX - 1;

        // Should not panic and should return minimum subsidy
        let subsidy = block_subsidy(height, &params);
        assert_eq!(subsidy.as_divi(), 250);

        let rewards = get_block_rewards(height, &params);
        assert!(rewards.total().as_sat() > 0);
    }

    #[test]
    fn test_network_premine_values() {
        // Mainnet and testnet have same premine
        assert_eq!(
            RewardParams::mainnet().premine_amount,
            RewardParams::testnet().premine_amount
        );
        // Regtest has a smaller premine for testing
        assert_ne!(
            RewardParams::mainnet().premine_amount,
            RewardParams::regtest().premine_amount
        );
        assert_eq!(RewardParams::regtest().premine_amount.as_divi(), 1_250);
    }
}
