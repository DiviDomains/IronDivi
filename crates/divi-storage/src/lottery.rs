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

//! Lottery winner selection system matching C++ Divi implementation
//!
//! This module implements the lottery system for distributing accumulated rewards
//! to stakers. The lottery accumulates 50 DIVI per block and pays out to winners
//! every lottery cycle (10,080 blocks on mainnet = ~1 week).
//!
//! Reference: Divi/divi/src/LotteryWinnersCalculator.cpp

use divi_primitives::amount::Amount;
use divi_primitives::constants::COIN;
use divi_primitives::Hash256;
use sha2::{Digest, Sha256};

/// Minimum coinstake amount to qualify for lottery ticket
///
/// Default is 10,000 DIVI unless overridden by spork
/// Reference: LotteryWinnersCalculator::minimumCoinstakeForTicket()
pub const DEFAULT_LOTTERY_TICKET_MINIMUM: i64 = 10_000 * COIN;

/// Number of lottery winners selected per cycle
///
/// The top 11 scoring coinstakes become lottery winners
pub const LOTTERY_WINNER_COUNT: usize = 11;

/// Number of lottery cycles a winner is vetoed from winning again
///
/// Winners cannot win again for 3 cycles after their win
/// Reference: LotteryWinnersCalculator::IsPaymentScriptVetoed()
pub const LOTTERY_VETO_CYCLES: usize = 3;

/// A lottery coinstake entry (transaction hash + payment script hash)
///
/// Matches C++ LotteryCoinstake = std::pair<uint256, CScript>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LotteryCoinstake {
    /// Transaction hash of the coinstake
    pub tx_hash: Hash256,
    /// Hash of the payment script (scriptPubKey)
    pub script_hash: Hash256,
}

impl LotteryCoinstake {
    /// Create a new lottery coinstake entry
    pub fn new(tx_hash: Hash256, script_hash: Hash256) -> Self {
        Self {
            tx_hash,
            script_hash,
        }
    }
}

/// Lottery score with ranking information
///
/// Matches C++ RankAwareScore struct
#[derive(Debug, Clone)]
pub struct RankAwareScore {
    /// Deterministic score for this coinstake
    pub score: Hash256,
    /// Rank among all coinstakes (0 = highest score)
    pub rank: usize,
    /// Whether this payment script is a duplicate
    pub is_duplicate_script: bool,
}

/// Calculate the lottery score for a coinstake
///
/// Matches C++ LotteryWinnersCalculator::CalculateLotteryScore()
///
/// The score is calculated by hashing the coinstake transaction hash together
/// with the hash of the last lottery block. This ensures deterministic but
/// unpredictable winner selection.
pub fn calculate_lottery_score(
    coinstake_tx_hash: &Hash256,
    last_lottery_block_hash: &Hash256,
) -> Hash256 {
    // In C++: CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    //         ss << hashCoinbaseTx << hashLastLotteryBlock;
    //         return ss.GetHash();

    // Combine both hashes and hash again
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(coinstake_tx_hash.as_bytes());
    combined.extend_from_slice(last_lottery_block_hash.as_bytes());

    // Double SHA256
    let first_hash = Sha256::digest(&combined);
    let second_hash = Sha256::digest(first_hash);
    Hash256::from_bytes(second_hash.into())
}

/// Check if a coinstake amount qualifies for lottery
///
/// Matches C++ LotteryWinnersCalculator::IsCoinstakeValidForLottery()
///
/// A coinstake is valid if its total staked amount exceeds the minimum
/// lottery ticket threshold (default 10,000 DIVI).
pub fn is_coinstake_valid_for_lottery(stake_amount: Amount, minimum_ticket: Amount) -> bool {
    stake_amount > minimum_ticket
}

/// Get the minimum stake amount required for lottery entry
///
/// Matches C++ LotteryWinnersCalculator::minimumCoinstakeForTicket()
///
/// This can be overridden by spork, but defaults to 10,000 DIVI
pub fn get_minimum_lottery_ticket() -> Amount {
    Amount::from_sat(DEFAULT_LOTTERY_TICKET_MINIMUM)
}

/// Compute ranked scores for a set of lottery coinstakes
///
/// Matches C++ LotteryWinnersCalculator::computeRankedScoreAwareCoinstakes()
///
/// This calculates a lottery score for each coinstake, assigns ranks based on
/// score ordering, and marks duplicate payment scripts.
pub fn compute_ranked_scores(
    coinstakes: &[LotteryCoinstake],
    last_lottery_block_hash: &Hash256,
) -> Vec<(LotteryCoinstake, RankAwareScore)> {
    let mut scored: Vec<_> = coinstakes
        .iter()
        .map(|coinstake| {
            let score = calculate_lottery_score(&coinstake.tx_hash, last_lottery_block_hash);
            (coinstake.clone(), score)
        })
        .collect();

    // Sort by score descending (highest scores first)
    scored.sort_by(|a, b| b.1.cmp(&a.1));

    // Track seen script hashes to detect duplicates
    let mut seen_scripts = std::collections::HashSet::new();

    scored
        .into_iter()
        .enumerate()
        .map(|(rank, (coinstake, score))| {
            let is_duplicate = !seen_scripts.insert(coinstake.script_hash);
            (
                coinstake,
                RankAwareScore {
                    score,
                    rank,
                    is_duplicate_script: is_duplicate,
                },
            )
        })
        .collect()
}

/// Select top lottery winners from ranked coinstakes
///
/// Selects the top LOTTERY_WINNER_COUNT (11) coinstakes with the highest scores.
/// After the UniformLotteryWinners fork, duplicate payment scripts are filtered out.
pub fn select_lottery_winners(
    ranked_scores: &[(LotteryCoinstake, RankAwareScore)],
    trim_duplicates: bool,
) -> Vec<LotteryCoinstake> {
    let mut winners = Vec::new();

    for (coinstake, rank_aware_score) in ranked_scores {
        // Skip duplicates if trimming is enabled (after fork)
        if trim_duplicates && rank_aware_score.is_duplicate_script {
            continue;
        }

        winners.push(coinstake.clone());

        // Stop once we have enough winners
        if winners.len() >= LOTTERY_WINNER_COUNT {
            break;
        }
    }

    winners
}

/// Calculate total lottery payout for a lottery block
///
/// The lottery accumulates 50 DIVI per block over the lottery cycle.
/// At lottery payout height, all accumulated funds are distributed among winners.
pub fn calculate_total_lottery_payout(lottery_cycle_length: u32) -> Amount {
    Amount::from_sat(50 * COIN * lottery_cycle_length as i64)
}

/// Calculate individual winner payout
///
/// DEPRECATED: This function uses incorrect equal distribution logic.
/// Use `divi_consensus::lottery::calculate_lottery_payments()` instead.
///
/// Payment distribution matches C++ BlockIncentivesPopulator.cpp:
/// - Winner #1 (best score): 50% of total pot
/// - Winners #2-11: 5% of total pot each
///
/// Reference: Divi/divi/src/BlockIncentivesPopulator.cpp:128-140
#[deprecated(
    since = "0.1.0",
    note = "Uses incorrect equal distribution. Use divi_consensus::lottery::calculate_lottery_payments() instead."
)]
pub fn calculate_winner_payout(
    total_pot: Amount,
    winner_index: usize,
    _winner_count: usize,
) -> Amount {
    if winner_index == 0 {
        // First place: 50% of pot
        Amount::from_sat(total_pot.as_sat() / 2)
    } else {
        // Remaining winners: 5% of pot each (10% of the 50% split)
        let big_reward = total_pot.as_sat() / 2;
        Amount::from_sat(big_reward / 10)
    }
}

/// Check if a payment script hash is vetoed from winning the lottery
///
/// Matches C++ LotteryWinnersCalculator::IsPaymentScriptVetoed()
///
/// A script is vetoed if it appears in the lottery winners from any of the last
/// LOTTERY_VETO_CYCLES (3) lottery cycles. This prevents the same address from
/// winning multiple times in consecutive cycles.
///
/// # Arguments
/// * `script_hash` - The hash of the payment script to check
/// * `current_height` - Current block height being processed
/// * `lottery_cycle_length` - Number of blocks between lottery payouts
/// * `get_lottery_winners` - Closure to get lottery winners for a given height
///
/// # Returns
/// `true` if the script is vetoed (appears in recent winners), `false` otherwise
pub fn is_payment_script_vetoed<F>(
    script_hash: &Hash256,
    current_height: u32,
    lottery_cycle_length: u32,
    mut get_lottery_winners: F,
) -> bool
where
    F: FnMut(u32) -> Option<Vec<Hash256>>,
{
    // Get the last lottery block height before current height
    // For C++ reference: nLastLotteryHeight = height - (height % lottery_cycle)
    let last_lottery_height = if current_height >= lottery_cycle_length {
        (current_height / lottery_cycle_length) * lottery_cycle_length
    } else {
        return false; // No previous lottery cycles to check
    };

    // Check last LOTTERY_VETO_CYCLES (3) lottery cycles
    // Matches C++ loop: for (int lotteryCycleCount = 0; lotteryCycleCount < numberOfLotteryCyclesToVetoFor; ++lotteryCycleCount)
    for cycle_offset in 0..LOTTERY_VETO_CYCLES {
        // Calculate the lottery block height to check
        // C++: nLastLotteryHeight - lotteryBlockPaymentCycle * lotteryCycleCount - 1
        // We check the block BEFORE the lottery payout (where winners are stored)
        let check_height =
            match last_lottery_height.checked_sub(lottery_cycle_length * cycle_offset as u32) {
                Some(h) if h > 0 => h - 1, // Block before lottery payout
                _ => break,                // No more previous cycles
            };

        // Get winners from that lottery cycle
        if let Some(winner_scripts) = get_lottery_winners(check_height) {
            // Check if our script appears in those winners
            if winner_scripts.contains(script_hash) {
                return true; // Script is vetoed
            }
        }
    }

    false // Script not found in any recent winners
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // Constant Tests
    // ========================================

    #[test]
    fn test_lottery_constants() {
        assert_eq!(DEFAULT_LOTTERY_TICKET_MINIMUM, 10_000 * COIN);
        assert_eq!(LOTTERY_WINNER_COUNT, 11);
        assert_eq!(LOTTERY_VETO_CYCLES, 3);
    }

    #[test]
    fn test_minimum_lottery_ticket() {
        let minimum = get_minimum_lottery_ticket();
        assert_eq!(minimum.as_divi(), 10_000);
    }

    // ========================================
    // Score Calculation Tests
    // ========================================

    #[test]
    fn test_calculate_lottery_score_deterministic() {
        let tx_hash = Hash256::from_slice(&[1u8; 32]);
        let block_hash = Hash256::from_slice(&[2u8; 32]);

        let score1 = calculate_lottery_score(&tx_hash, &block_hash);
        let score2 = calculate_lottery_score(&tx_hash, &block_hash);

        // Same inputs should produce same score
        assert_eq!(score1, score2);
    }

    #[test]
    fn test_calculate_lottery_score_different_inputs() {
        let tx_hash1 = Hash256::from_slice(&[1u8; 32]);
        let tx_hash2 = Hash256::from_slice(&[2u8; 32]);
        let block_hash = Hash256::from_slice(&[3u8; 32]);

        let score1 = calculate_lottery_score(&tx_hash1, &block_hash);
        let score2 = calculate_lottery_score(&tx_hash2, &block_hash);

        // Different inputs should produce different scores
        assert_ne!(score1, score2);
    }

    #[test]
    fn test_calculate_lottery_score_block_hash_matters() {
        let tx_hash = Hash256::from_slice(&[1u8; 32]);
        let block_hash1 = Hash256::from_slice(&[2u8; 32]);
        let block_hash2 = Hash256::from_slice(&[3u8; 32]);

        let score1 = calculate_lottery_score(&tx_hash, &block_hash1);
        let score2 = calculate_lottery_score(&tx_hash, &block_hash2);

        // Different block hashes should produce different scores
        assert_ne!(score1, score2);
    }

    // ========================================
    // Coinstake Validity Tests
    // ========================================

    #[test]
    fn test_coinstake_valid_above_minimum() {
        let minimum = Amount::from_divi(10_000);
        let stake = Amount::from_divi(10_001);

        assert!(is_coinstake_valid_for_lottery(stake, minimum));
    }

    #[test]
    fn test_coinstake_invalid_at_minimum() {
        let minimum = Amount::from_divi(10_000);
        let stake = Amount::from_divi(10_000);

        assert!(!is_coinstake_valid_for_lottery(stake, minimum));
    }

    #[test]
    fn test_coinstake_invalid_below_minimum() {
        let minimum = Amount::from_divi(10_000);
        let stake = Amount::from_divi(9_999);

        assert!(!is_coinstake_valid_for_lottery(stake, minimum));
    }

    #[test]
    fn test_coinstake_invalid_zero() {
        let minimum = Amount::from_divi(10_000);
        let stake = Amount::ZERO;

        assert!(!is_coinstake_valid_for_lottery(stake, minimum));
    }

    // ========================================
    // Ranking Tests
    // ========================================

    #[test]
    fn test_compute_ranked_scores_empty() {
        let coinstakes: Vec<LotteryCoinstake> = vec![];
        let block_hash = Hash256::from_slice(&[1u8; 32]);

        let ranked = compute_ranked_scores(&coinstakes, &block_hash);

        assert_eq!(ranked.len(), 0);
    }

    #[test]
    fn test_compute_ranked_scores_single() {
        let coinstake = LotteryCoinstake::new(
            Hash256::from_slice(&[1u8; 32]),
            Hash256::from_slice(&[2u8; 32]),
        );
        let block_hash = Hash256::from_slice(&[3u8; 32]);

        let ranked = compute_ranked_scores(std::slice::from_ref(&coinstake), &block_hash);

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].0, coinstake);
        assert_eq!(ranked[0].1.rank, 0);
        assert!(!ranked[0].1.is_duplicate_script);
    }

    #[test]
    fn test_compute_ranked_scores_ordering() {
        let coinstake1 = LotteryCoinstake::new(
            Hash256::from_slice(&[1u8; 32]),
            Hash256::from_slice(&[10u8; 32]),
        );
        let coinstake2 = LotteryCoinstake::new(
            Hash256::from_slice(&[2u8; 32]),
            Hash256::from_slice(&[20u8; 32]),
        );
        let coinstake3 = LotteryCoinstake::new(
            Hash256::from_slice(&[3u8; 32]),
            Hash256::from_slice(&[30u8; 32]),
        );
        let block_hash = Hash256::from_slice(&[100u8; 32]);

        let ranked = compute_ranked_scores(&[coinstake1, coinstake2, coinstake3], &block_hash);

        assert_eq!(ranked.len(), 3);
        // Ranks should be 0, 1, 2 (sorted by score descending)
        assert_eq!(ranked[0].1.rank, 0);
        assert_eq!(ranked[1].1.rank, 1);
        assert_eq!(ranked[2].1.rank, 2);
        // Scores should be descending
        assert!(ranked[0].1.score >= ranked[1].1.score);
        assert!(ranked[1].1.score >= ranked[2].1.score);
    }

    #[test]
    fn test_compute_ranked_scores_detects_duplicates() {
        let shared_script = Hash256::from_slice(&[99u8; 32]);

        let coinstake1 = LotteryCoinstake::new(Hash256::from_slice(&[1u8; 32]), shared_script);
        let coinstake2 = LotteryCoinstake::new(
            Hash256::from_slice(&[2u8; 32]),
            shared_script, // Duplicate script
        );
        let coinstake3 = LotteryCoinstake::new(
            Hash256::from_slice(&[3u8; 32]),
            Hash256::from_slice(&[30u8; 32]),
        );
        let block_hash = Hash256::from_slice(&[100u8; 32]);

        let ranked = compute_ranked_scores(&[coinstake1, coinstake2, coinstake3], &block_hash);

        // First occurrence of shared_script should NOT be marked duplicate
        // Second occurrence should be marked duplicate
        let duplicate_count = ranked.iter().filter(|(_, r)| r.is_duplicate_script).count();
        assert_eq!(duplicate_count, 1, "Should have exactly one duplicate");
    }

    // ========================================
    // Winner Selection Tests
    // ========================================

    #[test]
    fn test_select_lottery_winners_empty() {
        let ranked: Vec<(LotteryCoinstake, RankAwareScore)> = vec![];

        let winners = select_lottery_winners(&ranked, false);

        assert_eq!(winners.len(), 0);
    }

    #[test]
    fn test_select_lottery_winners_fewer_than_max() {
        let coinstakes: Vec<_> = (0..5)
            .map(|i| {
                let coinstake = LotteryCoinstake::new(
                    Hash256::from_slice(&[i as u8; 32]),
                    Hash256::from_slice(&[(i + 100) as u8; 32]),
                );
                let score = RankAwareScore {
                    score: Hash256::from_slice(&[(100 - i) as u8; 32]),
                    rank: i,
                    is_duplicate_script: false,
                };
                (coinstake, score)
            })
            .collect();

        let winners = select_lottery_winners(&coinstakes, false);

        assert_eq!(winners.len(), 5);
    }

    #[test]
    fn test_select_lottery_winners_exactly_max() {
        let coinstakes: Vec<_> = (0..11)
            .map(|i| {
                let coinstake = LotteryCoinstake::new(
                    Hash256::from_slice(&[i as u8; 32]),
                    Hash256::from_slice(&[(i + 100) as u8; 32]),
                );
                let score = RankAwareScore {
                    score: Hash256::from_slice(&[(100 - i) as u8; 32]),
                    rank: i,
                    is_duplicate_script: false,
                };
                (coinstake, score)
            })
            .collect();

        let winners = select_lottery_winners(&coinstakes, false);

        assert_eq!(winners.len(), 11);
    }

    #[test]
    fn test_select_lottery_winners_more_than_max() {
        let coinstakes: Vec<_> = (0..20)
            .map(|i| {
                let coinstake = LotteryCoinstake::new(
                    Hash256::from_slice(&[i as u8; 32]),
                    Hash256::from_slice(&[(i + 100) as u8; 32]),
                );
                let score = RankAwareScore {
                    score: Hash256::from_slice(&[(100 - i) as u8; 32]),
                    rank: i,
                    is_duplicate_script: false,
                };
                (coinstake, score)
            })
            .collect();

        let winners = select_lottery_winners(&coinstakes, false);

        // Should cap at LOTTERY_WINNER_COUNT (11)
        assert_eq!(winners.len(), 11);
    }

    #[test]
    fn test_select_lottery_winners_skip_duplicates_when_trimming() {
        let coinstakes = vec![
            (
                LotteryCoinstake::new(
                    Hash256::from_slice(&[1u8; 32]),
                    Hash256::from_slice(&[10u8; 32]),
                ),
                RankAwareScore {
                    score: Hash256::from_slice(&[100u8; 32]),
                    rank: 0,
                    is_duplicate_script: false,
                },
            ),
            (
                LotteryCoinstake::new(
                    Hash256::from_slice(&[2u8; 32]),
                    Hash256::from_slice(&[10u8; 32]),
                ),
                RankAwareScore {
                    score: Hash256::from_slice(&[99u8; 32]),
                    rank: 1,
                    is_duplicate_script: true, // Duplicate
                },
            ),
            (
                LotteryCoinstake::new(
                    Hash256::from_slice(&[3u8; 32]),
                    Hash256::from_slice(&[30u8; 32]),
                ),
                RankAwareScore {
                    score: Hash256::from_slice(&[98u8; 32]),
                    rank: 2,
                    is_duplicate_script: false,
                },
            ),
        ];

        let winners_with_trim = select_lottery_winners(&coinstakes, true);
        let winners_no_trim = select_lottery_winners(&coinstakes, false);

        // With trimming: should skip the duplicate
        assert_eq!(winners_with_trim.len(), 2);
        assert_eq!(
            winners_with_trim[0].tx_hash,
            Hash256::from_slice(&[1u8; 32])
        );
        assert_eq!(
            winners_with_trim[1].tx_hash,
            Hash256::from_slice(&[3u8; 32])
        );

        // Without trimming: should include all
        assert_eq!(winners_no_trim.len(), 3);
    }

    // ========================================
    // Payout Calculation Tests
    // ========================================

    #[test]
    fn test_calculate_total_lottery_payout_mainnet() {
        let cycle_length = 10_080; // Mainnet cycle
        let total = calculate_total_lottery_payout(cycle_length);

        // 50 DIVI per block * 10,080 blocks = 504,000 DIVI
        assert_eq!(total.as_divi(), 504_000);
    }

    #[test]
    fn test_calculate_total_lottery_payout_regtest() {
        let cycle_length = 100; // Regtest cycle
        let total = calculate_total_lottery_payout(cycle_length);

        // 50 DIVI per block * 100 blocks = 5,000 DIVI
        assert_eq!(total.as_divi(), 5_000);
    }

    #[test]
    #[allow(deprecated)]
    fn test_calculate_winner_payout_first_place() {
        let total = Amount::from_divi(504_000);
        let winner_count = 11;

        // First place gets 50%
        let first_place = calculate_winner_payout(total, 0, winner_count);
        assert_eq!(first_place.as_divi(), 252_000);
    }

    #[test]
    #[allow(deprecated)]
    fn test_calculate_winner_payout_second_place() {
        let total = Amount::from_divi(504_000);
        let winner_count = 11;

        // Second through eleventh place get 5% each
        let second_place = calculate_winner_payout(total, 1, winner_count);
        assert_eq!(second_place.as_divi(), 25_200);
    }

    #[test]
    #[allow(deprecated)]
    fn test_calculate_winner_payout_tenth_place() {
        let total = Amount::from_divi(504_000);
        let winner_count = 11;

        // All places after first get same amount (5%)
        let tenth_place = calculate_winner_payout(total, 9, winner_count);
        assert_eq!(tenth_place.as_divi(), 25_200);
    }

    #[test]
    #[allow(deprecated)]
    fn test_calculate_winner_payout_cpp_parity() {
        // Verify exact match with C++ BlockIncentivesPopulator.cpp logic
        let lottery_reward = Amount::from_divi(504_000);

        // C++ code: auto nBigReward = nLotteryReward / 2;
        let big_reward = calculate_winner_payout(lottery_reward, 0, 11);
        assert_eq!(big_reward.as_sat(), lottery_reward.as_sat() / 2);

        // C++ code: auto nSmallReward = nBigReward / 10;
        let small_reward = calculate_winner_payout(lottery_reward, 1, 11);
        assert_eq!(small_reward.as_sat(), big_reward.as_sat() / 10);

        // Verify total distribution
        let total_distributed = big_reward.as_sat() + (small_reward.as_sat() * 10);
        // Should be close to total (may differ by rounding)
        assert_eq!(
            total_distributed,
            25_200_000_000_000 + (2_520_000_000_000 * 10)
        );
        assert_eq!(total_distributed, 50_400_000_000_000);
    }

    // ========================================
    // Integration Tests
    // ========================================

    #[test]
    #[allow(deprecated)]
    fn test_full_lottery_workflow() {
        // Simulate a lottery cycle with multiple coinstakes
        let coinstakes: Vec<_> = (0..20)
            .map(|i| {
                LotteryCoinstake::new(
                    Hash256::from_slice(&[i as u8; 32]),
                    Hash256::from_slice(&[(i * 2) as u8; 32]),
                )
            })
            .collect();

        let last_lottery_block = Hash256::from_slice(&[255u8; 32]);

        // Step 1: Compute ranked scores
        let ranked = compute_ranked_scores(&coinstakes, &last_lottery_block);
        assert_eq!(ranked.len(), 20);

        // Step 2: Select winners (with duplicate trimming enabled)
        let winners = select_lottery_winners(&ranked, true);
        assert!(winners.len() <= LOTTERY_WINNER_COUNT);

        // Step 3: Calculate payouts with 50%/5% distribution
        let total_pot = calculate_total_lottery_payout(10_080);

        // First place: 50%
        let first_place_payout = calculate_winner_payout(total_pot, 0, winners.len());
        assert_eq!(first_place_payout.as_sat(), total_pot.as_sat() / 2);

        // Other winners: 5% each
        if winners.len() > 1 {
            let other_payout = calculate_winner_payout(total_pot, 1, winners.len());
            assert_eq!(other_payout.as_sat(), first_place_payout.as_sat() / 10);
        }

        // Verify total distribution adds up correctly
        let total_distributed = if !winners.is_empty() {
            first_place_payout.as_sat()
                + (calculate_winner_payout(total_pot, 1, winners.len()).as_sat()
                    * (winners.len() - 1) as i64)
        } else {
            0
        };

        // Should equal total pot (50% + 10×5% = 100%)
        if winners.len() == LOTTERY_WINNER_COUNT {
            assert_eq!(total_distributed, total_pot.as_sat());
        }
    }

    // ========================================
    // Veto Cycle Tests
    // ========================================

    #[test]
    fn test_veto_no_previous_cycles() {
        let script_hash = Hash256::from_slice(&[1u8; 32]);
        let current_height = 5;
        let lottery_cycle = 10;

        // No previous lottery cycles, should not be vetoed
        let is_vetoed =
            is_payment_script_vetoed(&script_hash, current_height, lottery_cycle, |_| None);

        assert!(!is_vetoed);
    }

    #[test]
    fn test_veto_script_not_in_previous_winners() {
        let script_hash = Hash256::from_slice(&[1u8; 32]);
        let other_script = Hash256::from_slice(&[2u8; 32]);
        let current_height = 35;
        let lottery_cycle = 10;

        // Previous winners don't include our script
        let is_vetoed =
            is_payment_script_vetoed(&script_hash, current_height, lottery_cycle, |_height| {
                Some(vec![other_script])
            });

        assert!(!is_vetoed);
    }

    #[test]
    fn test_veto_script_in_most_recent_cycle() {
        let script_hash = Hash256::from_slice(&[1u8; 32]);
        let current_height = 35;
        let lottery_cycle = 10;

        // Script appears in most recent lottery cycle (height 30)
        let is_vetoed =
            is_payment_script_vetoed(&script_hash, current_height, lottery_cycle, |height| {
                if height == 29 {
                    // Block before lottery payout at 30
                    Some(vec![script_hash])
                } else {
                    Some(vec![])
                }
            });

        assert!(is_vetoed);
    }

    #[test]
    fn test_veto_script_in_second_cycle() {
        let script_hash = Hash256::from_slice(&[1u8; 32]);
        let current_height = 45;
        let lottery_cycle = 10;

        // Script appears in second-to-last lottery cycle (height 30)
        let is_vetoed =
            is_payment_script_vetoed(&script_hash, current_height, lottery_cycle, |height| {
                if height == 29 {
                    // Block before lottery payout at 30
                    Some(vec![script_hash])
                } else {
                    Some(vec![])
                }
            });

        assert!(is_vetoed);
    }

    #[test]
    fn test_veto_script_in_third_cycle() {
        let script_hash = Hash256::from_slice(&[1u8; 32]);
        let current_height = 55;
        let lottery_cycle = 10;

        // Script appears in third-to-last lottery cycle (height 30)
        let is_vetoed =
            is_payment_script_vetoed(&script_hash, current_height, lottery_cycle, |height| {
                if height == 29 {
                    // Block before lottery payout at 30
                    Some(vec![script_hash])
                } else {
                    Some(vec![])
                }
            });

        assert!(is_vetoed);
    }

    #[test]
    fn test_veto_script_in_fourth_cycle_not_vetoed() {
        let script_hash = Hash256::from_slice(&[1u8; 32]);
        let current_height = 65;
        let lottery_cycle = 10;

        // Script appears in fourth-to-last lottery cycle (height 30)
        // Should NOT be vetoed (only checks last 3 cycles)
        let is_vetoed =
            is_payment_script_vetoed(&script_hash, current_height, lottery_cycle, |height| {
                if height == 29 {
                    // Block before lottery payout at 30
                    Some(vec![script_hash])
                } else {
                    Some(vec![])
                }
            });

        assert!(!is_vetoed);
    }

    #[test]
    fn test_veto_multiple_winners_script_found() {
        let script_hash = Hash256::from_slice(&[1u8; 32]);
        let other_scripts = vec![
            Hash256::from_slice(&[2u8; 32]),
            Hash256::from_slice(&[3u8; 32]),
            script_hash, // Our script is in the list
            Hash256::from_slice(&[4u8; 32]),
        ];
        let current_height = 35;
        let lottery_cycle = 10;

        let is_vetoed =
            is_payment_script_vetoed(&script_hash, current_height, lottery_cycle, |height| {
                if height == 29 {
                    Some(other_scripts.clone())
                } else {
                    Some(vec![])
                }
            });

        assert!(is_vetoed);
    }

    #[test]
    fn test_veto_exact_cycle_boundaries() {
        let script_hash = Hash256::from_slice(&[1u8; 32]);
        let lottery_cycle = 10;

        // Test at exact lottery block height (should check previous cycles)
        let current_height = 30;
        let is_vetoed =
            is_payment_script_vetoed(&script_hash, current_height, lottery_cycle, |height| {
                if height == 19 {
                    // Block before lottery at 20
                    Some(vec![script_hash])
                } else {
                    Some(vec![])
                }
            });

        assert!(is_vetoed);
    }

    #[test]
    fn test_veto_realistic_scenario() {
        // Simulate realistic lottery scenario with cycle=10
        let winner_script = Hash256::from_slice(&[0xaa; 32]);
        let other_script1 = Hash256::from_slice(&[0xbb; 32]);
        let other_script2 = Hash256::from_slice(&[0xcc; 32]);

        let lottery_cycle = 10;
        let current_height = 45;

        // Winner at height 30 tries to win again at height 40
        let is_vetoed =
            is_payment_script_vetoed(&winner_script, current_height, lottery_cycle, |height| {
                match height {
                    29 => Some(vec![winner_script, other_script1, other_script2]), // Winners at lottery 30
                    19 => Some(vec![other_script1, other_script2]), // Winners at lottery 20
                    9 => Some(vec![other_script2]),                 // Winners at lottery 10
                    _ => Some(vec![]),
                }
            });

        assert!(
            is_vetoed,
            "Script that won at cycle 30 should be vetoed at cycle 40"
        );

        // After 4 cycles, the script should be allowed again
        let current_height = 65;
        let is_vetoed_after_4_cycles =
            is_payment_script_vetoed(&winner_script, current_height, lottery_cycle, |height| {
                match height {
                    59 => Some(vec![other_script1]),
                    49 => Some(vec![other_script2]),
                    39 => Some(vec![other_script1, other_script2]),
                    29 => Some(vec![winner_script, other_script1, other_script2]), // This is now 4 cycles ago
                    _ => Some(vec![]),
                }
            });

        assert!(
            !is_vetoed_after_4_cycles,
            "Script should be allowed after 4 cycles (veto is only 3 cycles)"
        );
    }
}
