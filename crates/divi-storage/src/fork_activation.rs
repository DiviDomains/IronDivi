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

// Copyright (c) 2020 The DIVI Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Fork activation logic for consensus changes on the Divi network.
//!
//! This module implements the fork activation system that determines when
//! protocol changes should be activated based on block timestamps.
//!
//! Reference: Divi/divi/src/ForkActivation.h:1-62
//! Reference: Divi/divi/src/ForkActivation.cpp:1-61

use crate::block_index::BlockIndex;

/// The list of consensus changes ("forks") that have been introduced
/// on the network since its launch.
///
/// Reference: Divi/divi/src/ForkActivation.h:19-28
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fork {
    /// Test fork for unit tests only
    TestByTimestamp,
    /// Hardened stake modifier calculation
    HardenedStakeModifier,
    /// Uniform lottery winner selection
    UniformLotteryWinners,
    /// BIP65: CHECKLOCKTIMEVERIFY opcode
    CheckLockTimeVerify,
    /// Deprecate masternodes from the protocol
    DeprecateMasternodes,
    /// Limit transfer verification
    LimitTransferVerify,
}

/// Unix timestamp for December 31st, 2020 at 23:59:59 UTC
///
/// Reference: Divi/divi/src/ForkActivation.cpp:19
const UNIX_TIMESTAMP_FOR_DEC_31ST_MIDNIGHT: i64 = 1609459199;

/// Unix timestamp for August 23rd at midnight GMT
///
/// Reference: Divi/divi/src/ForkActivation.cpp:20
const UNIX_TIMESTAMP_FOR_AUGUST_23_MIDNIGHT_GMT: i64 = 1692792000;

/// Returns the activation timestamp for a given fork.
///
/// Reference: Divi/divi/src/ForkActivation.cpp:26-33
fn get_activation_timestamp(fork: Fork) -> i64 {
    match fork {
        Fork::TestByTimestamp => 1000000000,
        Fork::HardenedStakeModifier => UNIX_TIMESTAMP_FOR_DEC_31ST_MIDNIGHT,
        Fork::UniformLotteryWinners => UNIX_TIMESTAMP_FOR_DEC_31ST_MIDNIGHT,
        Fork::CheckLockTimeVerify => UNIX_TIMESTAMP_FOR_AUGUST_23_MIDNIGHT_GMT,
        Fork::DeprecateMasternodes => UNIX_TIMESTAMP_FOR_AUGUST_23_MIDNIGHT_GMT,
        Fork::LimitTransferVerify => UNIX_TIMESTAMP_FOR_AUGUST_23_MIDNIGHT_GMT,
    }
}

/// Returns whether a fork requires block index context (uses MTP instead of block time).
///
/// Reference: Divi/divi/src/ForkActivation.cpp:35-39
fn requires_block_index_context(fork: Fork) -> bool {
    matches!(
        fork,
        Fork::DeprecateMasternodes | Fork::CheckLockTimeVerify | Fork::LimitTransferVerify
    )
}

/// Activation state for a specific block.
///
/// This structure is used to query whether forks are active at a given block.
///
/// Reference: Divi/divi/src/ForkActivation.h:30-59
pub struct ActivationState {
    block_time: i64,
    median_time_past: i64,
}

impl ActivationState {
    /// Creates an activation state for the given block index.
    ///
    /// For forks that require MTP, you must provide it via `new_with_mtp()`.
    /// For forks that only use block time (like HardenedStakeModifier), use this method.
    ///
    /// Reference: Divi/divi/src/ForkActivation.cpp:43-46
    pub fn new(block_index: &BlockIndex) -> Self {
        Self {
            block_time: block_index.time as i64,
            median_time_past: 0, // Not computed yet, will be computed on demand if needed
        }
    }

    /// Creates an activation state with pre-computed median time past.
    ///
    /// Use this constructor when checking forks that require MTP
    /// (CheckLockTimeVerify, DeprecateMasternodes, LimitTransferVerify).
    pub fn new_with_mtp(block_index: &BlockIndex, median_time_past: i64) -> Self {
        Self {
            block_time: block_index.time as i64,
            median_time_past,
        }
    }

    /// Returns true if the indicated fork should be considered active
    /// for processing the associated block.
    ///
    /// Reference: Divi/divi/src/ForkActivation.cpp:48-60
    pub fn is_active(&self, fork: Fork) -> bool {
        // For most forks, we use the block's timestamp directly.
        // For certain forks (CheckLockTimeVerify, DeprecateMasternodes, LimitTransferVerify),
        // we use the Median Time Past instead.
        let current_time = if requires_block_index_context(fork) {
            // Use Median Time Past for these forks
            debug_assert!(
                self.median_time_past > 0,
                "Fork {:?} requires MTP context. Use ActivationState::new_with_mtp() instead of new()",
                fork
            );
            self.median_time_past
        } else {
            // Use block timestamp directly
            self.block_time
        };

        let activation_time = get_activation_timestamp(fork);
        current_time >= activation_time
    }

    /// Convenience method specifically for checking if HardenedStakeModifier fork is active.
    ///
    /// This is the most commonly checked fork in the codebase.
    pub fn is_hardened_stake_modifier_active(&self) -> bool {
        self.is_active(Fork::HardenedStakeModifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_index::{BlockIndex, BlockStatus};
    use divi_primitives::lottery::LotteryWinners;
    use divi_primitives::Hash256;

    /// Helper to create a test block index with a specific timestamp
    fn create_test_block_index(block_time: i64, _median_time_past: i64) -> BlockIndex {
        BlockIndex {
            hash: Hash256::default(),
            prev_hash: Hash256::default(),
            height: 100,
            version: 1,
            merkle_root: Hash256::default(),
            time: block_time as u32,
            bits: 0,
            nonce: 0,
            accumulator: None,
            n_tx: 0,
            chain_work: [0u8; 32],
            status: BlockStatus::empty(),
            file_num: 0,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: LotteryWinners::default(),
            is_proof_of_stake: false,
        }
    }

    #[test]
    fn test_hardened_stake_modifier_not_active_before_activation() {
        let block = create_test_block_index(1609459198, 1609459198);
        let state = ActivationState::new(&block);
        assert!(!state.is_hardened_stake_modifier_active());
    }

    #[test]
    fn test_hardened_stake_modifier_active_at_activation() {
        let block = create_test_block_index(1609459199, 1609459199);
        let state = ActivationState::new(&block);
        assert!(state.is_hardened_stake_modifier_active());
    }

    #[test]
    fn test_hardened_stake_modifier_active_after_activation() {
        let block = create_test_block_index(1609459200, 1609459200);
        let state = ActivationState::new(&block);
        assert!(state.is_hardened_stake_modifier_active());
    }

    #[test]
    fn test_fork_activation_uses_block_time_for_hardened_modifier() {
        let block = create_test_block_index(1609459200, 1609459000);
        let state = ActivationState::new(&block);
        assert!(state.is_active(Fork::HardenedStakeModifier));
    }

    #[test]
    fn test_fork_activation_uses_mtp_for_checklocktimeverify() {
        let block = create_test_block_index(1692792001, 1692791999);
        let state = ActivationState::new_with_mtp(&block, 1692791999);
        assert!(!state.is_active(Fork::CheckLockTimeVerify));
    }

    #[test]
    fn test_fork_activation_uses_mtp_for_deprecate_masternodes() {
        let block = create_test_block_index(1692792001, 1692792001);
        let state = ActivationState::new_with_mtp(&block, 1692792001);
        assert!(state.is_active(Fork::DeprecateMasternodes));
    }

    #[test]
    fn test_uniform_lottery_winners_same_activation_as_hardened_modifier() {
        let block_before = create_test_block_index(1609459198, 1609459198);
        let state_before = ActivationState::new(&block_before);
        assert!(!state_before.is_active(Fork::UniformLotteryWinners));

        let block_after = create_test_block_index(1609459200, 1609459200);
        let state_after = ActivationState::new(&block_after);
        assert!(state_after.is_active(Fork::UniformLotteryWinners));
    }

    #[test]
    fn test_test_fork_activation() {
        let block = create_test_block_index(1000000001, 1000000001);
        let state = ActivationState::new(&block);
        assert!(state.is_active(Fork::TestByTimestamp));
    }
}
