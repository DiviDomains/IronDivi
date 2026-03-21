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

// Block subsidy calculation matching C++ Divi's LegacyBlockSubsidies.cpp and BlockSubsidyProvider.cpp
//
// This module implements the exact subsidy calculation logic from C++ Divi:
// - Halving schedule (1250 DIVI decreasing by 100 DIVI per year to minimum 250 DIVI)
// - Reward distribution (stakers, masternodes, treasury, charity, lottery)
// - Weighted calculation for treasury/lottery payments crossing halving boundaries

use divi_primitives::Amount;

/// Halving interval: 60 * 24 * 365 = 525,600 blocks (~1 year at 1 minute/block)
pub const SUBSIDY_HALVING_INTERVAL: u32 = 525_600;

/// Initial block reward (year 0-1)
const INITIAL_SUBSIDY: i64 = 1250;

/// Decrease per halving interval
const SUBSIDY_DECREASE_PER_YEAR: i64 = 100;

/// Minimum block reward (floor)
const MINIMUM_SUBSIDY: i64 = 250;

/// Lottery allocation per block (after height 101)
const LOTTERY_PER_BLOCK: i64 = 50;

/// Last proof-of-work block
const LAST_POW_BLOCK: u32 = 100;

/// Block rewards distribution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRewards {
    /// Staker reward
    pub stake: Amount,
    /// Masternode reward
    pub masternode: Amount,
    /// Treasury reward (per-block portion, or weighted total for treasury blocks)
    pub treasury: Amount,
    /// Charity reward (per-block portion, or weighted total for treasury blocks)
    pub charity: Amount,
    /// Lottery reward
    pub lottery: Amount,
    /// Proposals reward (unused currently)
    pub proposals: Amount,
}

impl BlockRewards {
    /// Zero rewards
    pub const ZERO: Self = Self {
        stake: Amount::ZERO,
        masternode: Amount::ZERO,
        treasury: Amount::ZERO,
        charity: Amount::ZERO,
        lottery: Amount::ZERO,
        proposals: Amount::ZERO,
    };
}

/// Calculate base block subsidy at a given height
///
/// Implements the C++ function:
/// ```cpp
/// CAmount BlockSubsidy(int nHeight, const CChainParams& chainParameters)
/// ```
/// Source: LegacyBlockSubsidies.cpp lines 15-28
fn block_subsidy(height: u32, halving_interval: u32) -> i64 {
    if height == 0 {
        return 50; // Genesis block
    } else if height == 1 {
        // Premine: 617,222,416 DIVI
        // We don't handle this here - it's a special case
        return 617_222_416;
    }

    // Halving formula: max(1250 - 100 * max(height / halving_interval - 1, 0), 250)
    let num_intervals = (height / halving_interval) as i64;
    let decrease_factor = std::cmp::max(num_intervals - 1, 0);

    std::cmp::max(
        INITIAL_SUBSIDY - SUBSIDY_DECREASE_PER_YEAR * decrease_factor,
        MINIMUM_SUBSIDY,
    )
}

/// Get block rewards distribution for a given height
///
/// Implements the C++ function:
/// ```cpp
/// CBlockRewards GetBlockSubsidity(int nHeight, const CChainParams& chainParameters, const CSporkManager& sporkManager)
/// ```
/// Source: LegacyBlockSubsidies.cpp lines 45-92
///
/// This calculates the **per-block** portions of each reward type.
/// For treasury/charity, the actual payment on treasury blocks requires weighted calculation.
pub fn get_block_subsidy(height: u32, halving_interval: u32) -> BlockRewards {
    let subsidy = block_subsidy(height, halving_interval);

    // POW blocks (height <= 100): no distribution
    if height <= LAST_POW_BLOCK {
        return BlockRewards {
            stake: Amount::from_divi(subsidy),
            masternode: Amount::ZERO,
            treasury: Amount::ZERO,
            charity: Amount::ZERO,
            lottery: Amount::ZERO,
            proposals: Amount::ZERO,
        };
    }

    // Subtract lottery allocation (50 DIVI per block after height 101)
    let lottery = LOTTERY_PER_BLOCK;
    let distributable = subsidy - lottery;

    // Default reward distribution (sporks can override, but we use defaults):
    // - Stakers: 38%
    // - Masternodes: 45%
    // - Treasury: 16%
    // - Charity: 1%
    // - Proposals: 0%
    let stake = (distributable * 38) / 100;
    let masternode = (distributable * 45) / 100;
    let treasury = (distributable * 16) / 100;
    let charity = distributable / 100;
    let proposals = 0;

    BlockRewards {
        stake: Amount::from_divi(stake),
        masternode: Amount::from_divi(masternode),
        treasury: Amount::from_divi(treasury),
        charity: Amount::from_divi(charity),
        lottery: Amount::from_divi(lottery),
        proposals: Amount::from_divi(proposals),
    }
}

/// Calculate treasury and charity payments with weighted accumulation
///
/// Implements the C++ function:
/// ```cpp
/// void BlockSubsidyProvider::updateTreasuryReward(int nHeight, CBlockRewards& rewards, bool isTreasuryBlock)
/// ```
/// Source: BlockSubsidyProvider.cpp lines 19-37
///
/// This function handles the weighted blending of rewards when a treasury cycle
/// crosses a halving boundary. The weights ensure that the payment reflects the
/// actual per-block rewards that accumulated during the cycle.
///
/// # Arguments
/// * `height` - Current treasury block height
/// * `cycle_length` - Treasury cycle length (usually 10,081 blocks)
/// * `halving_interval` - Network-specific halving interval (mainnet: 525_600, testnet: 1_000, regtest: 100)
///
/// # Returns
/// Tuple of (treasury_payment, charity_payment) in DIVI
///
/// # Algorithm
/// 1. Calculate prior treasury block height (current - cycle)
/// 2. Get per-block rewards at both prior and current heights
/// 3. Find the halving boundary
/// 4. Calculate weights:
///    - `prior_weight`: blocks from prior treasury to halving boundary
///    - `current_weight`: blocks from halving boundary to current height
/// 5. Weighted sum: prior_rewards * prior_weight + current_rewards * current_weight
///
/// # Edge Cases
/// - **Same halving period**: Weights have opposite signs, formula simplifies to `per_block * cycle_length`
/// - **Crossing halving**: Weights proportionally blend the two reward rates
/// - **First treasury block**: Uses full cycle length for accumulation
///
/// Note: For the first treasury block (height == cycle_length on mainnet),
/// we accumulate the full cycle_length blocks worth of rewards, not height - start_block.
/// This matches the C++ Divi implementation behavior.
pub fn calculate_weighted_treasury_payment(
    height: u32,
    cycle_length: u32,
    halving_interval: u32,
) -> (Amount, Amount) {
    // Get prior treasury block height
    let prior_treasury_height = if height <= cycle_length {
        // First treasury block: accumulate full cycle length
        // C++ uses cycle_length blocks, not height - start_block
        // This is verified against actual mainnet block 10081
        let current_rewards = get_block_subsidy(height, halving_interval);
        let blocks = cycle_length as i64;
        return (
            current_rewards.treasury * blocks,
            current_rewards.charity * blocks,
        );
    } else {
        height - cycle_length
    };

    // Get per-block rewards at both heights
    let prior_rewards = get_block_subsidy(prior_treasury_height, halving_interval);
    let current_rewards = get_block_subsidy(height, halving_interval);

    // Calculate halving boundary
    // numberOfSubsidyIntervals = nHeight / SubsidyHalvingInterval()
    let num_intervals = height / halving_interval;
    let halving_boundary = num_intervals * halving_interval;

    // Calculate weights
    // priorRewardWeight = halvingBoundary - priorTreasuryBlockHeight
    // currentRewardWeight = currentHeight - halvingBoundary
    let prior_weight = (halving_boundary as i64) - (prior_treasury_height as i64);
    let current_weight = (height as i64) - (halving_boundary as i64);

    // Weighted sum
    // This IS the final payment amount (not per-block!)
    let treasury_payment =
        prior_rewards.treasury * prior_weight + current_rewards.treasury * current_weight;
    let charity_payment =
        prior_rewards.charity * prior_weight + current_rewards.charity * current_weight;

    (treasury_payment, charity_payment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_subsidy_schedule() {
        // Test halving schedule matches C++ logic

        // Height 0: Genesis
        assert_eq!(block_subsidy(0, SUBSIDY_HALVING_INTERVAL), 50);

        // Height 1: Premine
        assert_eq!(block_subsidy(1, SUBSIDY_HALVING_INTERVAL), 617_222_416);

        // Height 2-525,599: Year 0 (first interval)
        // Formula: max(1250 - 100 * max(0 / 525600 - 1, 0), 250) = max(1250 - 100 * max(-1, 0), 250) = 1250
        assert_eq!(block_subsidy(2, SUBSIDY_HALVING_INTERVAL), 1250);
        assert_eq!(block_subsidy(100, SUBSIDY_HALVING_INTERVAL), 1250);
        assert_eq!(block_subsidy(525_599, SUBSIDY_HALVING_INTERVAL), 1250);

        // Height 525,600-1,051,199: Year 1 (second interval)
        // Formula: max(1250 - 100 * max(1 / 525600 - 1, 0), 250) = max(1250 - 100 * max(0, 0), 250) = 1250
        assert_eq!(block_subsidy(525_600, SUBSIDY_HALVING_INTERVAL), 1250);
        assert_eq!(block_subsidy(1_051_199, SUBSIDY_HALVING_INTERVAL), 1250);

        // Height 1,051,200-1,576,799: Year 2 (third interval)
        // Formula: max(1250 - 100 * max(2 / 525600 - 1, 0), 250) = max(1250 - 100 * 1, 250) = 1150
        assert_eq!(block_subsidy(1_051_200, SUBSIDY_HALVING_INTERVAL), 1150);

        // Height 2,102,400: Year 4
        assert_eq!(block_subsidy(2_102_400, SUBSIDY_HALVING_INTERVAL), 950);

        // Height 3,153,600: Year 6
        assert_eq!(block_subsidy(3_153_600, SUBSIDY_HALVING_INTERVAL), 750);

        // Height 3,679,200: Year 7 (current mainnet)
        assert_eq!(block_subsidy(3_679_200, SUBSIDY_HALVING_INTERVAL), 650);

        // Height 4,204,800: Year 8
        assert_eq!(block_subsidy(4_204_800, SUBSIDY_HALVING_INTERVAL), 550);

        // Very far future: should floor at 250 DIVI
        assert_eq!(block_subsidy(10_000_000, SUBSIDY_HALVING_INTERVAL), 250);
    }

    #[test]
    fn test_get_block_subsidy_pow() {
        // POW blocks (height <= 100): full subsidy goes to stake
        let rewards = get_block_subsidy(100, SUBSIDY_HALVING_INTERVAL);
        assert_eq!(rewards.stake, Amount::from_divi(1250));
        assert_eq!(rewards.masternode, Amount::ZERO);
        assert_eq!(rewards.treasury, Amount::ZERO);
        assert_eq!(rewards.charity, Amount::ZERO);
        assert_eq!(rewards.lottery, Amount::ZERO);
    }

    #[test]
    fn test_get_block_subsidy_pos_early() {
        // Height 101: First POS block
        // Subsidy: 1250 DIVI
        // Lottery: 50 DIVI
        // Distributable: 1200 DIVI
        // Stake: 1200 * 38 / 100 = 456 DIVI
        // Masternode: 1200 * 45 / 100 = 540 DIVI
        // Treasury: 1200 * 16 / 100 = 192 DIVI
        // Charity: 1200 * 1 / 100 = 12 DIVI
        let rewards = get_block_subsidy(101, SUBSIDY_HALVING_INTERVAL);
        assert_eq!(rewards.stake, Amount::from_divi(456));
        assert_eq!(rewards.masternode, Amount::from_divi(540));
        assert_eq!(rewards.treasury, Amount::from_divi(192));
        assert_eq!(rewards.charity, Amount::from_divi(12));
        assert_eq!(rewards.lottery, Amount::from_divi(50));
    }

    #[test]
    fn test_get_block_subsidy_halving_7() {
        // Height 3,861,023 (current mainnet, halving 7)
        // Subsidy: 650 DIVI
        // Lottery: 50 DIVI
        // Distributable: 600 DIVI
        // Stake: 600 * 38 / 100 = 228 DIVI
        // Masternode: 600 * 45 / 100 = 270 DIVI
        // Treasury: 600 * 16 / 100 = 96 DIVI
        // Charity: 600 * 1 / 100 = 6 DIVI
        let rewards = get_block_subsidy(3_861_023, SUBSIDY_HALVING_INTERVAL);
        assert_eq!(rewards.stake, Amount::from_divi(228));
        assert_eq!(rewards.masternode, Amount::from_divi(270));
        assert_eq!(rewards.treasury, Amount::from_divi(96));
        assert_eq!(rewards.charity, Amount::from_divi(6));
        assert_eq!(rewards.lottery, Amount::from_divi(50));
    }

    #[test]
    fn test_weighted_treasury_same_halving() {
        // Test block 3,861,023 (treasury block in halving 7)
        // Both prior (3,850,942) and current are in same halving period
        // Cycle: 10,081 blocks
        // Per-block treasury: 96 DIVI
        // Per-block charity: 6 DIVI
        // Expected: 96 * 10,081 = 967,776 DIVI treasury
        //           6 * 10,081 = 60,486 DIVI charity

        let (treasury, charity) =
            calculate_weighted_treasury_payment(3_861_023, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(treasury, Amount::from_divi(967_776));
        assert_eq!(charity, Amount::from_divi(60_486));
    }

    #[test]
    fn test_weighted_treasury_crossing_halving() {
        // Test block 3,679,565 (first treasury after halving 7 starts)
        // Prior: 3,669,484 (in halving 6, reward 750 DIVI)
        // Current: 3,679,565 (in halving 7, reward 650 DIVI)
        // Halving boundary: 3,679,200
        //
        // Prior distributable: 750 - 50 = 700 DIVI
        // Prior treasury per-block: 700 * 16 / 100 = 112 DIVI
        // Prior charity per-block: 700 * 1 / 100 = 7 DIVI
        //
        // Current distributable: 650 - 50 = 600 DIVI
        // Current treasury per-block: 600 * 16 / 100 = 96 DIVI
        // Current charity per-block: 600 * 1 / 100 = 6 DIVI
        //
        // Weights:
        // prior_weight = 3,679,200 - 3,669,484 = 9,716 blocks
        // current_weight = 3,679,565 - 3,679,200 = 365 blocks
        //
        // Treasury: 112 * 9,716 + 96 * 365 = 1,088,192 + 35,040 = 1,123,232 DIVI
        // Charity: 7 * 9,716 + 6 * 365 = 68,012 + 2,190 = 70,202 DIVI

        let (treasury, charity) =
            calculate_weighted_treasury_payment(3_679_565, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(treasury, Amount::from_divi(1_123_232));
        assert_eq!(charity, Amount::from_divi(70_202));
    }

    // ============================================================
    // MAINNET VERIFICATION TESTS
    // These tests use ACTUAL mainnet block data to prove our
    // calculation matches the C++ implementation exactly
    // ============================================================

    #[test]
    fn test_mainnet_block_10081_first_treasury() {
        // First treasury block on mainnet
        // Block hash: 9ba2c6112a1eec0ead4508b91ce573d50cbcc3b72b453c222be70747fbab7ab1
        // Coinstake txid: df90e9ead77f794b5eab7d2a1f1d7a51de0de048c3f6210118103b219b840e51
        //
        // Actual payments from mainnet:
        // Treasury: 1,935,552.00000000 DIVI (DPhJsztbZafDc1YeyrRqSjmKjkmLJpQpUn)
        // Charity: 120,972.00000000 DIVI (DPujt2XAdHyRcZNB5ySZBBVKjzY2uXZGYq)

        let (treasury, charity) =
            calculate_weighted_treasury_payment(10_081, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(
            treasury,
            Amount::from_divi(1_935_552),
            "Treasury payment mismatch for block 10081"
        );
        assert_eq!(
            charity,
            Amount::from_divi(120_972),
            "Charity payment mismatch for block 10081"
        );
    }

    #[test]
    fn test_mainnet_block_1008100() {
        // Treasury block 100 on mainnet
        // Block hash: 7bf2269efb31bd8018e09e10e0d208176a36799c810a957ed8861370c4e5afdf
        //
        // Actual payments from mainnet:
        // Treasury: 1,935,552.00000000 DIVI
        // Charity: 120,972.00000000 DIVI

        let (treasury, charity) =
            calculate_weighted_treasury_payment(1_008_100, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(
            treasury,
            Amount::from_divi(1_935_552),
            "Treasury payment mismatch for block 1008100"
        );
        assert_eq!(
            charity,
            Amount::from_divi(120_972),
            "Charity payment mismatch for block 1008100"
        );
    }

    #[test]
    fn test_mainnet_block_3679565_halving_boundary() {
        // First treasury block after halving 7 starts (3,679,200)
        // Block hash: 72c2245f1f2ec519a2e73defb92b4fae82de0bba6e010640b2df34485c812f08
        //
        // This block CROSSES a halving boundary, so uses weighted calculation
        //
        // Actual payments from mainnet:
        // Treasury: 1,123,232.00000000 DIVI
        // Charity: 70,202.00000000 DIVI

        let (treasury, charity) =
            calculate_weighted_treasury_payment(3_679_565, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(
            treasury,
            Amount::from_divi(1_123_232),
            "Treasury payment mismatch for block 3679565"
        );
        assert_eq!(
            charity,
            Amount::from_divi(70_202),
            "Charity payment mismatch for block 3679565"
        );
    }

    #[test]
    fn test_mainnet_block_3760213() {
        // Treasury block well into halving 7
        // Block hash: (from mainnet query)
        //
        // Actual payments from mainnet:
        // Treasury: 967,776.00000000 DIVI
        // Charity: 60,486.00000000 DIVI

        let (treasury, charity) =
            calculate_weighted_treasury_payment(3_760_213, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(
            treasury,
            Amount::from_divi(967_776),
            "Treasury payment mismatch for block 3760213"
        );
        assert_eq!(
            charity,
            Amount::from_divi(60_486),
            "Charity payment mismatch for block 3760213"
        );
    }

    #[test]
    fn test_mainnet_block_3830780() {
        // Actual payments from mainnet:
        // Treasury: 967,776.00000000 DIVI
        // Charity: 60,486.00000000 DIVI

        let (treasury, charity) =
            calculate_weighted_treasury_payment(3_830_780, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(
            treasury,
            Amount::from_divi(967_776),
            "Treasury payment mismatch for block 3830780"
        );
        assert_eq!(
            charity,
            Amount::from_divi(60_486),
            "Charity payment mismatch for block 3830780"
        );
    }

    #[test]
    fn test_mainnet_block_3840861() {
        // Actual payments from mainnet:
        // Treasury: 967,776.00000000 DIVI
        // Charity: 60,486.00000000 DIVI

        let (treasury, charity) =
            calculate_weighted_treasury_payment(3_840_861, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(
            treasury,
            Amount::from_divi(967_776),
            "Treasury payment mismatch for block 3840861"
        );
        assert_eq!(
            charity,
            Amount::from_divi(60_486),
            "Charity payment mismatch for block 3840861"
        );
    }

    #[test]
    fn test_mainnet_block_3850942() {
        // Actual payments from mainnet:
        // Treasury: 967,776.00000000 DIVI
        // Charity: 60,486.00000000 DIVI

        let (treasury, charity) =
            calculate_weighted_treasury_payment(3_850_942, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(
            treasury,
            Amount::from_divi(967_776),
            "Treasury payment mismatch for block 3850942"
        );
        assert_eq!(
            charity,
            Amount::from_divi(60_486),
            "Charity payment mismatch for block 3850942"
        );
    }

    #[test]
    fn test_mainnet_block_3861023() {
        // Current mainnet height (as of test creation)
        // Actual payments from mainnet:
        // Treasury: 967,776.00000000 DIVI
        // Charity: 60,486.00000000 DIVI

        let (treasury, charity) =
            calculate_weighted_treasury_payment(3_861_023, 10_081, SUBSIDY_HALVING_INTERVAL);

        assert_eq!(
            treasury,
            Amount::from_divi(967_776),
            "Treasury payment mismatch for block 3861023"
        );
        assert_eq!(
            charity,
            Amount::from_divi(60_486),
            "Charity payment mismatch for block 3861023"
        );
    }

    // ============================================================
    // ADDITIONAL BLOCK SUBSIDY TESTS
    // ============================================================

    /// SUBSIDY_HALVING_INTERVAL must be 525_600 (60 * 24 * 365).
    #[test]
    fn test_subsidy_halving_interval_constant() {
        assert_eq!(SUBSIDY_HALVING_INTERVAL, 525_600);
        // Verify it's exactly 60 minutes * 24 hours * 365 days
        assert_eq!(SUBSIDY_HALVING_INTERVAL, 60 * 24 * 365);
    }

    /// BlockRewards::ZERO must have all fields set to Amount::ZERO.
    #[test]
    fn test_block_rewards_zero() {
        let zero = BlockRewards::ZERO;
        assert_eq!(zero.stake, Amount::ZERO);
        assert_eq!(zero.masternode, Amount::ZERO);
        assert_eq!(zero.treasury, Amount::ZERO);
        assert_eq!(zero.charity, Amount::ZERO);
        assert_eq!(zero.lottery, Amount::ZERO);
        assert_eq!(zero.proposals, Amount::ZERO);
    }

    /// At height 0 (genesis block) subsidy is 50 DIVI.
    #[test]
    fn test_block_subsidy_genesis() {
        let rewards = get_block_subsidy(0, SUBSIDY_HALVING_INTERVAL);
        assert_eq!(rewards.stake, Amount::from_divi(50));
        assert_eq!(rewards.masternode, Amount::ZERO);
    }

    /// At height 1 (premine) subsidy is 617_222_416 DIVI.
    #[test]
    fn test_block_subsidy_premine() {
        let rewards = get_block_subsidy(1, SUBSIDY_HALVING_INTERVAL);
        assert_eq!(rewards.stake, Amount::from_divi(617_222_416));
    }

    /// Subsidy must floor at MINIMUM_SUBSIDY (250 DIVI) far into the future.
    #[test]
    fn test_block_subsidy_minimum_floor() {
        // At year 11+ the subsidy formula would go below 250; it must be clamped.
        // Year 11 = height 5_781_600 (intervals ≥ 11)
        // Formula: max(1250 - 100*(11-1), 250) = max(250, 250) = 250
        let rewards = get_block_subsidy(5_781_600, SUBSIDY_HALVING_INTERVAL);
        assert_eq!(rewards.lottery, Amount::from_divi(50));
        // Distributable = 250 - 50 = 200
        let distributable = 200i64;
        assert_eq!(rewards.stake, Amount::from_divi(distributable * 38 / 100));
        assert_eq!(
            rewards.masternode,
            Amount::from_divi(distributable * 45 / 100)
        );
        assert_eq!(
            rewards.treasury,
            Amount::from_divi(distributable * 16 / 100)
        );
        assert_eq!(rewards.charity, Amount::from_divi(distributable / 100));
    }

    /// Far-future blocks (year 20) must still return exactly 250 DIVI subsidy.
    #[test]
    fn test_block_subsidy_far_future_floor() {
        // Year 20 = height 10_512_000
        let rewards = get_block_subsidy(10_512_000, SUBSIDY_HALVING_INTERVAL);
        // Total distributable floor: 250 - 50 = 200
        let distributable = 200i64;
        assert_eq!(rewards.stake, Amount::from_divi(distributable * 38 / 100));
        assert_eq!(rewards.lottery, Amount::from_divi(50));
    }

    /// At halving year 2 (height 1_051_200) subsidy steps down to 1150 DIVI.
    #[test]
    fn test_block_subsidy_year2_step_down() {
        // Year 2: formula = max(1250 - 100*(2-1), 250) = 1150
        let rewards = get_block_subsidy(1_051_200, SUBSIDY_HALVING_INTERVAL);
        let distributable = 1150 - 50; // 1100
        assert_eq!(rewards.lottery, Amount::from_divi(50));
        assert_eq!(rewards.stake, Amount::from_divi(distributable * 38 / 100));
        assert_eq!(
            rewards.masternode,
            Amount::from_divi(distributable * 45 / 100)
        );
        assert_eq!(
            rewards.treasury,
            Amount::from_divi(distributable * 16 / 100)
        );
        assert_eq!(rewards.charity, Amount::from_divi(distributable / 100));
    }

    /// PoW block at height 50 has only stake reward, no distributions.
    #[test]
    fn test_block_subsidy_pow_block() {
        let rewards = get_block_subsidy(50, SUBSIDY_HALVING_INTERVAL);
        assert_eq!(rewards.stake, Amount::from_divi(1250));
        assert_eq!(rewards.masternode, Amount::ZERO);
        assert_eq!(rewards.treasury, Amount::ZERO);
        assert_eq!(rewards.charity, Amount::ZERO);
        assert_eq!(rewards.lottery, Amount::ZERO);
        assert_eq!(rewards.proposals, Amount::ZERO);
    }

    /// The sum of stake+masternode+treasury+charity+lottery+proposals for a PoS block
    /// must exactly equal the block subsidy (no rounding leakage).
    #[test]
    fn test_block_subsidy_sum_equals_total() {
        // Height 101, year 0 — subsidy = 1250 DIVI
        let rewards = get_block_subsidy(101, SUBSIDY_HALVING_INTERVAL);
        let total = rewards.stake.as_sat()
            + rewards.masternode.as_sat()
            + rewards.treasury.as_sat()
            + rewards.charity.as_sat()
            + rewards.lottery.as_sat()
            + rewards.proposals.as_sat();

        // Integer-divide rounding: 1200 * (38+45+16+1) / 100 = 1200 * 100 / 100 = 1200
        // Plus lottery 50 → 1250
        assert_eq!(total, Amount::from_divi(1250).as_sat());
    }

    /// Rewards at the exact boundary between year 0 and year 1 (height 525_600)
    /// must still be 1250 DIVI (no decrease yet).
    #[test]
    fn test_block_subsidy_at_year1_boundary() {
        // Year 1: max(1250 - 100*max(1-1,0), 250) = max(1250, 250) = 1250
        let rewards = get_block_subsidy(525_600, SUBSIDY_HALVING_INTERVAL);
        assert_eq!(rewards.lottery, Amount::from_divi(50));
        let distributable = 1200;
        assert_eq!(rewards.stake, Amount::from_divi(distributable * 38 / 100));
    }

    /// calculate_weighted_treasury_payment for the very first treasury block
    /// (height == cycle_length) uses the full cycle_length as block count.
    #[test]
    fn test_weighted_treasury_first_block_uses_full_cycle() {
        // For regtest-like parameters: cycle=50, halving=100
        // At height 50 (first treasury block, height == cycle_length):
        // per-block treasury at height 50: distributable = 1250-50=1200; treasury = 1200*16/100 = 192
        // total = 192 * 50 = 9600
        let (treasury, _charity) =
            calculate_weighted_treasury_payment(50, 50, SUBSIDY_HALVING_INTERVAL);
        let expected_per_block = get_block_subsidy(50, SUBSIDY_HALVING_INTERVAL).treasury;
        let expected = Amount::from_sat(expected_per_block.as_sat() * 50);
        assert_eq!(
            treasury, expected,
            "First treasury block uses full cycle length"
        );
    }

    /// weighted treasury crossing halving boundary with regtest parameters:
    /// halving_interval=100, cycle=50.  At height 150 (crosses height 100 boundary).
    #[test]
    fn test_weighted_treasury_crossing_halving_regtest() {
        let halving_interval = 100u32;
        let cycle = 50u32;

        // At height 150: prior=100, current=150, boundary=100
        // prior_rewards at 100: subsidy=1250, lottery=50, distributable=1200
        //   treasury = 1200*16/100 = 192 DIVI
        // current_rewards at 150: same halving interval=100, num_intervals=1
        //   subsidy = max(1250 - 100*max(1-1,0), 250) = 1250, treasury = 192
        //
        // Halving boundary = (150/100)*100 = 100
        // prior_weight = 100 - 100 = 0
        // current_weight = 150 - 100 = 50
        // total = 192*0 + 192*50 = 9600
        let (treasury, _) = calculate_weighted_treasury_payment(150, cycle, halving_interval);
        assert_eq!(treasury, Amount::from_divi(192 * 50));
    }
}
