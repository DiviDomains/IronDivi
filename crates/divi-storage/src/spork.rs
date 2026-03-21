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

//! Spork system for dynamic network parameter overrides
//!
//! Sporks allow the network to dynamically adjust protocol parameters without
//! requiring a hard fork. This includes things like block rewards, fees, and
//! lottery ticket minimums.
//!
//! Reference: Divi/divi/src/spork.h, spork.cpp

use divi_primitives::amount::Amount;
use divi_primitives::constants::COIN;

/// Spork identifiers (matching C++ constants)
///
/// These IDs should never be reused to avoid confusion with older clients
pub mod spork_ids {
    pub const SPORK_2_SWIFTTX_ENABLED: i32 = 10001;
    pub const SPORK_3_SWIFTTX_BLOCK_FILTERING: i32 = 10002;
    pub const SPORK_5_INSTANTSEND_MAX_VALUE: i32 = 10004;
    pub const SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT: i32 = 10007;
    pub const SPORK_9_SUPERBLOCKS_ENABLED: i32 = 10008;
    pub const SPORK_10_MASTERNODE_PAY_UPDATED_NODES: i32 = 10009;
    pub const SPORK_12_RECONSIDER_BLOCKS: i32 = 10011;
    pub const SPORK_13_BLOCK_PAYMENTS: i32 = 10012;
    pub const SPORK_14_TX_FEE: i32 = 10013;
    pub const SPORK_15_BLOCK_VALUE: i32 = 10014;
    pub const SPORK_16_LOTTERY_TICKET_MIN_VALUE: i32 = 10015;

    pub const SPORK_START: i32 = SPORK_2_SWIFTTX_ENABLED;
    pub const SPORK_END: i32 = SPORK_16_LOTTERY_TICKET_MIN_VALUE;
}

/// Block payment distribution percentages
///
/// Matches C++ BlockPaymentSporkValue struct
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockPaymentSpork {
    /// Percentage for stakers (in basis points, 10000 = 100%)
    pub stake_reward: i32,
    /// Percentage for masternodes (in basis points)
    pub masternode_reward: i32,
    /// Percentage for treasury (in basis points)
    pub treasury_reward: i32,
    /// Percentage for proposals (in basis points)
    pub proposals_reward: i32,
    /// Percentage for charity (in basis points)
    pub charity_reward: i32,
    /// Block height where this spork activates
    pub activation_height: u32,
}

impl BlockPaymentSpork {
    /// Create a new block payment spork
    pub fn new(
        stake_reward: i32,
        masternode_reward: i32,
        treasury_reward: i32,
        proposals_reward: i32,
        charity_reward: i32,
        activation_height: u32,
    ) -> Self {
        Self {
            stake_reward,
            masternode_reward,
            treasury_reward,
            proposals_reward,
            charity_reward,
            activation_height,
        }
    }

    /// Check if percentages are valid (should sum to 10000 or less)
    pub fn is_valid(&self) -> bool {
        // All fields must be non-negative
        if self.stake_reward < 0
            || self.masternode_reward < 0
            || self.treasury_reward < 0
            || self.proposals_reward < 0
            || self.charity_reward < 0
        {
            return false;
        }

        // Total must not exceed 10000 (100%)
        let total = self.stake_reward
            + self.masternode_reward
            + self.treasury_reward
            + self.proposals_reward
            + self.charity_reward;
        total <= 10000
    }

    /// Get default mainnet distribution (38% stake, 45% masternode, 16% treasury, 0% proposals, 1% charity)
    pub fn default_mainnet() -> Self {
        Self {
            stake_reward: 3800,
            masternode_reward: 4500,
            treasury_reward: 1600,
            proposals_reward: 0,
            charity_reward: 100,
            activation_height: 0,
        }
    }
}

impl Default for BlockPaymentSpork {
    fn default() -> Self {
        Self::default_mainnet()
    }
}

/// Block subsidy override
///
/// Matches C++ BlockSubsiditySporkValue struct
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSubsidySpork {
    /// Block subsidy amount in satoshis
    pub subsidy: Amount,
    /// Block height where this spork activates
    pub activation_height: u32,
}

impl BlockSubsidySpork {
    /// Create a new block subsidy spork
    pub fn new(subsidy: Amount, activation_height: u32) -> Self {
        Self {
            subsidy,
            activation_height,
        }
    }

    /// Check if the subsidy is valid (positive and reasonable)
    pub fn is_valid(&self) -> bool {
        self.subsidy.as_sat() > 0 && self.subsidy.as_sat() <= 10_000 * COIN
    }
}

/// Lottery ticket minimum value
///
/// Matches C++ LotteryTicketMinValueSporkValue struct
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LotteryTicketMinSpork {
    /// Minimum stake amount to qualify for lottery
    pub min_value: Amount,
    /// Block height where this spork activates
    pub activation_height: u32,
}

impl LotteryTicketMinSpork {
    /// Create a new lottery ticket minimum spork
    pub fn new(min_value: Amount, activation_height: u32) -> Self {
        Self {
            min_value,
            activation_height,
        }
    }

    /// Check if the minimum is valid
    pub fn is_valid(&self) -> bool {
        self.min_value.as_sat() > 0 && self.min_value.as_sat() <= 1_000_000 * COIN
    }

    /// Get default minimum (10,000 DIVI)
    pub fn default_minimum() -> Amount {
        Amount::from_sat(10_000 * COIN)
    }
}

/// Transaction fee parameters
///
/// Matches C++ TxFeeSporkValue struct
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxFeeSpork {
    /// Transaction value multiplier
    pub tx_value_multiplier: i32,
    /// Transaction size multiplier
    pub tx_size_multiplier: i32,
    /// Maximum fee
    pub max_fee: Amount,
    /// Minimum fee per kilobyte
    pub min_fee_per_kb: Amount,
    /// Block height where this spork activates
    pub activation_height: u32,
}

impl TxFeeSpork {
    /// Create a new transaction fee spork
    pub fn new(
        tx_value_multiplier: i32,
        tx_size_multiplier: i32,
        max_fee: Amount,
        min_fee_per_kb: Amount,
        activation_height: u32,
    ) -> Self {
        Self {
            tx_value_multiplier,
            tx_size_multiplier,
            max_fee,
            min_fee_per_kb,
            activation_height,
        }
    }

    /// Check if the fee parameters are valid
    pub fn is_valid(&self) -> bool {
        self.tx_value_multiplier >= 0
            && self.tx_size_multiplier >= 0
            && self.max_fee.as_sat() > 0
            && self.min_fee_per_kb.as_sat() > 0
    }
}

/// Simplified spork manager for querying active spork values
///
/// Note: This is a simplified version for basic feature parity.
/// Full implementation would include network messaging, signature verification,
/// and database persistence.
#[derive(Debug, Clone)]
pub struct SporkManager {
    /// Active block payment distributions
    block_payments: Vec<BlockPaymentSpork>,
    /// Active block subsidy overrides
    block_subsidies: Vec<BlockSubsidySpork>,
    /// Active lottery ticket minimums
    lottery_minimums: Vec<LotteryTicketMinSpork>,
    /// Active transaction fee parameters
    tx_fees: Vec<TxFeeSpork>,
}

impl SporkManager {
    /// Create a new spork manager with default values
    pub fn new() -> Self {
        Self {
            block_payments: vec![BlockPaymentSpork::default_mainnet()],
            block_subsidies: vec![],
            lottery_minimums: vec![],
            tx_fees: vec![],
        }
    }

    /// Get active block payment distribution at a given height
    ///
    /// Returns the most recent spork that has activated before or at the given height
    pub fn get_block_payment_at_height(&self, height: u32) -> BlockPaymentSpork {
        self.block_payments
            .iter()
            .filter(|s| s.activation_height <= height)
            .max_by_key(|s| s.activation_height)
            .copied()
            .unwrap_or_default()
    }

    /// Get active block subsidy at a given height
    ///
    /// Returns None if no spork override is active
    pub fn get_block_subsidy_at_height(&self, height: u32) -> Option<Amount> {
        self.block_subsidies
            .iter()
            .filter(|s| s.activation_height <= height)
            .max_by_key(|s| s.activation_height)
            .map(|s| s.subsidy)
    }

    /// Get active lottery ticket minimum at a given height
    ///
    /// Returns default if no spork override is active
    pub fn get_lottery_min_at_height(&self, height: u32) -> Amount {
        self.lottery_minimums
            .iter()
            .filter(|s| s.activation_height <= height)
            .max_by_key(|s| s.activation_height)
            .map(|s| s.min_value)
            .unwrap_or_else(LotteryTicketMinSpork::default_minimum)
    }

    /// Get active transaction fee parameters at a given height
    ///
    /// Returns None if no spork override is active
    pub fn get_tx_fee_at_height(&self, height: u32) -> Option<TxFeeSpork> {
        self.tx_fees
            .iter()
            .filter(|s| s.activation_height <= height)
            .max_by_key(|s| s.activation_height)
            .copied()
    }

    /// Add a block payment spork
    pub fn add_block_payment_spork(&mut self, spork: BlockPaymentSpork) -> bool {
        if !spork.is_valid() {
            return false;
        }
        self.block_payments.push(spork);
        self.block_payments.sort_by_key(|s| s.activation_height);
        true
    }

    /// Add a block subsidy spork
    pub fn add_block_subsidy_spork(&mut self, spork: BlockSubsidySpork) -> bool {
        if !spork.is_valid() {
            return false;
        }
        self.block_subsidies.push(spork);
        self.block_subsidies.sort_by_key(|s| s.activation_height);
        true
    }

    /// Add a lottery ticket minimum spork
    pub fn add_lottery_min_spork(&mut self, spork: LotteryTicketMinSpork) -> bool {
        if !spork.is_valid() {
            return false;
        }
        self.lottery_minimums.push(spork);
        self.lottery_minimums.sort_by_key(|s| s.activation_height);
        true
    }

    /// Add a transaction fee spork
    pub fn add_tx_fee_spork(&mut self, spork: TxFeeSpork) -> bool {
        if !spork.is_valid() {
            return false;
        }
        self.tx_fees.push(spork);
        self.tx_fees.sort_by_key(|s| s.activation_height);
        true
    }
}

impl Default for SporkManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // BlockPaymentSpork Tests
    // ========================================

    #[test]
    fn test_block_payment_spork_default() {
        let spork = BlockPaymentSpork::default();

        assert_eq!(spork.stake_reward, 3800); // 38%
        assert_eq!(spork.masternode_reward, 4500); // 45%
        assert_eq!(spork.treasury_reward, 1600); // 16%
        assert_eq!(spork.proposals_reward, 0); // 0%
        assert_eq!(spork.charity_reward, 100); // 1%
        assert!(spork.is_valid());
    }

    #[test]
    fn test_block_payment_spork_valid() {
        let spork = BlockPaymentSpork::new(5000, 3000, 2000, 0, 0, 1000);
        assert!(spork.is_valid());

        let spork = BlockPaymentSpork::new(10000, 0, 0, 0, 0, 1000);
        assert!(spork.is_valid());
    }

    #[test]
    fn test_block_payment_spork_invalid_sum() {
        let spork = BlockPaymentSpork::new(6000, 5000, 2000, 0, 0, 1000);
        assert!(!spork.is_valid()); // Sum > 10000
    }

    #[test]
    fn test_block_payment_spork_invalid_negative() {
        let spork = BlockPaymentSpork::new(-100, 5000, 2000, 0, 0, 1000);
        assert!(!spork.is_valid());
    }

    // ========================================
    // BlockSubsidySpork Tests
    // ========================================

    #[test]
    fn test_block_subsidy_spork_valid() {
        let spork = BlockSubsidySpork::new(Amount::from_divi(1000), 1000);
        assert!(spork.is_valid());
    }

    #[test]
    fn test_block_subsidy_spork_invalid_zero() {
        let spork = BlockSubsidySpork::new(Amount::ZERO, 1000);
        assert!(!spork.is_valid());
    }

    #[test]
    fn test_block_subsidy_spork_invalid_too_large() {
        let spork = BlockSubsidySpork::new(Amount::from_sat(20_000 * COIN), 1000);
        assert!(!spork.is_valid());
    }

    // ========================================
    // LotteryTicketMinSpork Tests
    // ========================================

    #[test]
    fn test_lottery_min_spork_default() {
        let min = LotteryTicketMinSpork::default_minimum();
        assert_eq!(min.as_divi(), 10_000);
    }

    #[test]
    fn test_lottery_min_spork_valid() {
        let spork = LotteryTicketMinSpork::new(Amount::from_divi(5_000), 1000);
        assert!(spork.is_valid());
    }

    #[test]
    fn test_lottery_min_spork_invalid_zero() {
        let spork = LotteryTicketMinSpork::new(Amount::ZERO, 1000);
        assert!(!spork.is_valid());
    }

    #[test]
    fn test_lottery_min_spork_invalid_too_large() {
        let spork = LotteryTicketMinSpork::new(Amount::from_sat(2_000_000 * COIN), 1000);
        assert!(!spork.is_valid());
    }

    // ========================================
    // TxFeeSpork Tests
    // ========================================

    #[test]
    fn test_tx_fee_spork_valid() {
        let spork = TxFeeSpork::new(100, 200, Amount::from_divi(10), Amount::from_divi(1), 1000);
        assert!(spork.is_valid());
    }

    #[test]
    fn test_tx_fee_spork_invalid_negative_multiplier() {
        let spork = TxFeeSpork::new(-100, 200, Amount::from_divi(10), Amount::from_divi(1), 1000);
        assert!(!spork.is_valid());
    }

    #[test]
    fn test_tx_fee_spork_invalid_zero_max_fee() {
        let spork = TxFeeSpork::new(100, 200, Amount::ZERO, Amount::from_divi(1), 1000);
        assert!(!spork.is_valid());
    }

    // ========================================
    // SporkManager Tests
    // ========================================

    #[test]
    fn test_spork_manager_default() {
        let manager = SporkManager::new();

        let payment = manager.get_block_payment_at_height(1000);
        assert_eq!(payment.stake_reward, 3800);
    }

    #[test]
    fn test_spork_manager_add_block_payment() {
        let mut manager = SporkManager::new();

        let spork = BlockPaymentSpork::new(5000, 4000, 1000, 0, 0, 1000);
        assert!(manager.add_block_payment_spork(spork));

        // Before activation
        let payment = manager.get_block_payment_at_height(999);
        assert_eq!(payment.stake_reward, 3800); // Default

        // After activation
        let payment = manager.get_block_payment_at_height(1000);
        assert_eq!(payment.stake_reward, 5000); // New spork
    }

    #[test]
    fn test_spork_manager_block_subsidy() {
        let mut manager = SporkManager::new();

        assert!(manager.get_block_subsidy_at_height(1000).is_none());

        let spork = BlockSubsidySpork::new(Amount::from_divi(2000), 1000);
        assert!(manager.add_block_subsidy_spork(spork));

        assert!(manager.get_block_subsidy_at_height(999).is_none());
        assert_eq!(
            manager.get_block_subsidy_at_height(1000),
            Some(Amount::from_divi(2000))
        );
    }

    #[test]
    fn test_spork_manager_lottery_min() {
        let mut manager = SporkManager::new();

        // Default value
        assert_eq!(manager.get_lottery_min_at_height(1000).as_divi(), 10_000);

        let spork = LotteryTicketMinSpork::new(Amount::from_divi(5_000), 1000);
        assert!(manager.add_lottery_min_spork(spork));

        assert_eq!(manager.get_lottery_min_at_height(999).as_divi(), 10_000);
        assert_eq!(manager.get_lottery_min_at_height(1000).as_divi(), 5_000);
    }

    #[test]
    fn test_spork_manager_multiple_sporks_same_type() {
        let mut manager = SporkManager::new();

        let spork1 = BlockPaymentSpork::new(5000, 4000, 1000, 0, 0, 1000);
        let spork2 = BlockPaymentSpork::new(4000, 5000, 1000, 0, 0, 2000);
        let spork3 = BlockPaymentSpork::new(3000, 6000, 1000, 0, 0, 3000);

        assert!(manager.add_block_payment_spork(spork1));
        assert!(manager.add_block_payment_spork(spork2));
        assert!(manager.add_block_payment_spork(spork3));

        // At height 999: default
        assert_eq!(manager.get_block_payment_at_height(999).stake_reward, 3800);

        // At height 1500: spork1 active
        assert_eq!(manager.get_block_payment_at_height(1500).stake_reward, 5000);

        // At height 2500: spork2 active
        assert_eq!(manager.get_block_payment_at_height(2500).stake_reward, 4000);

        // At height 3500: spork3 active
        assert_eq!(manager.get_block_payment_at_height(3500).stake_reward, 3000);
    }

    #[test]
    fn test_spork_manager_reject_invalid() {
        let mut manager = SporkManager::new();

        // Invalid block payment (sum > 10000)
        let invalid_payment = BlockPaymentSpork::new(6000, 5000, 2000, 0, 0, 1000);
        assert!(!manager.add_block_payment_spork(invalid_payment));

        // Invalid block subsidy (zero)
        let invalid_subsidy = BlockSubsidySpork::new(Amount::ZERO, 1000);
        assert!(!manager.add_block_subsidy_spork(invalid_subsidy));

        // Invalid lottery min (zero)
        let invalid_lottery = LotteryTicketMinSpork::new(Amount::ZERO, 1000);
        assert!(!manager.add_lottery_min_spork(invalid_lottery));
    }

    // ================================================================
    // SporkManager tx_fee operations
    // ================================================================

    #[test]
    fn test_spork_manager_tx_fee_no_spork() {
        let manager = SporkManager::new();
        // No tx_fee spork by default
        assert!(manager.get_tx_fee_at_height(0).is_none());
        assert!(manager.get_tx_fee_at_height(1_000_000).is_none());
    }

    #[test]
    fn test_spork_manager_add_tx_fee_spork() {
        let mut manager = SporkManager::new();
        let spork = TxFeeSpork::new(100, 200, Amount::from_divi(10), Amount::from_divi(1), 500);
        assert!(manager.add_tx_fee_spork(spork));

        // Before activation
        assert!(manager.get_tx_fee_at_height(499).is_none());

        // At and after activation
        let active = manager.get_tx_fee_at_height(500).unwrap();
        assert_eq!(active.tx_value_multiplier, 100);
        assert_eq!(active.tx_size_multiplier, 200);
        assert_eq!(active.activation_height, 500);

        let later = manager.get_tx_fee_at_height(10000).unwrap();
        assert_eq!(later.tx_value_multiplier, 100);
    }

    #[test]
    fn test_spork_manager_reject_invalid_tx_fee() {
        let mut manager = SporkManager::new();

        // Negative multiplier
        let invalid = TxFeeSpork::new(-1, 100, Amount::from_divi(5), Amount::from_divi(1), 0);
        assert!(!manager.add_tx_fee_spork(invalid));

        // Zero max fee
        let invalid2 = TxFeeSpork::new(100, 100, Amount::ZERO, Amount::from_divi(1), 0);
        assert!(!manager.add_tx_fee_spork(invalid2));

        // Zero min fee per kb
        let invalid3 = TxFeeSpork::new(100, 100, Amount::from_divi(5), Amount::ZERO, 0);
        assert!(!manager.add_tx_fee_spork(invalid3));

        // Nothing should have been added
        assert!(manager.get_tx_fee_at_height(0).is_none());
    }

    #[test]
    fn test_spork_manager_tx_fee_multiple_sporks_latest_wins() {
        let mut manager = SporkManager::new();

        let spork1 = TxFeeSpork::new(100, 200, Amount::from_divi(10), Amount::from_divi(1), 1000);
        let spork2 = TxFeeSpork::new(150, 250, Amount::from_divi(20), Amount::from_divi(2), 2000);

        assert!(manager.add_tx_fee_spork(spork1));
        assert!(manager.add_tx_fee_spork(spork2));

        // At height 1500: only spork1 active
        let fee1500 = manager.get_tx_fee_at_height(1500).unwrap();
        assert_eq!(fee1500.tx_value_multiplier, 100);

        // At height 2000: spork2 overrides
        let fee2000 = manager.get_tx_fee_at_height(2000).unwrap();
        assert_eq!(fee2000.tx_value_multiplier, 150);

        // At height 3000: still spork2
        let fee3000 = manager.get_tx_fee_at_height(3000).unwrap();
        assert_eq!(fee3000.tx_value_multiplier, 150);
    }

    // ================================================================
    // BlockPaymentSpork: sum exactly 10000 is valid
    // ================================================================

    #[test]
    fn test_block_payment_spork_sum_exactly_10000() {
        let spork = BlockPaymentSpork::new(3000, 3000, 2000, 1000, 1000, 0);
        assert_eq!(
            spork.stake_reward
                + spork.masternode_reward
                + spork.treasury_reward
                + spork.proposals_reward
                + spork.charity_reward,
            10000
        );
        assert!(spork.is_valid());
    }

    #[test]
    fn test_block_payment_spork_zero_amounts() {
        // All zeros - sum = 0, still valid (≤ 10000 and all non-negative)
        let spork = BlockPaymentSpork::new(0, 0, 0, 0, 0, 0);
        assert!(spork.is_valid());
    }

    // ================================================================
    // BlockSubsidySpork: boundary validations
    // ================================================================

    #[test]
    fn test_block_subsidy_spork_boundary() {
        // Exactly 10,000 DIVI - valid
        let valid = BlockSubsidySpork::new(Amount::from_sat(10_000 * COIN), 1000);
        assert!(valid.is_valid());

        // One sat over - invalid
        let too_large = BlockSubsidySpork::new(Amount::from_sat(10_000 * COIN + 1), 1000);
        assert!(!too_large.is_valid());

        // One sat - valid
        let one_sat = BlockSubsidySpork::new(Amount::from_sat(1), 0);
        assert!(one_sat.is_valid());
    }

    // ================================================================
    // LotteryTicketMinSpork: boundary validations
    // ================================================================

    #[test]
    fn test_lottery_min_spork_boundary() {
        // Exactly 1,000,000 DIVI - valid
        let valid = LotteryTicketMinSpork::new(Amount::from_sat(1_000_000 * COIN), 0);
        assert!(valid.is_valid());

        // One sat over - invalid
        let too_large = LotteryTicketMinSpork::new(Amount::from_sat(1_000_000 * COIN + 1), 0);
        assert!(!too_large.is_valid());
    }

    // ================================================================
    // TxFeeSpork: both multipliers zero is valid (fee disabled scenario)
    // ================================================================

    #[test]
    fn test_tx_fee_spork_zero_multipliers_valid() {
        // Both multipliers = 0 is valid (fee enforcement disabled by multiplier)
        let spork = TxFeeSpork::new(0, 0, Amount::from_divi(10), Amount::from_divi(1), 0);
        assert!(spork.is_valid());
    }

    // ================================================================
    // SporkManager default()
    // ================================================================

    #[test]
    fn test_spork_manager_default_trait() {
        let manager = SporkManager::default();
        // Should behave identically to new()
        let payment = manager.get_block_payment_at_height(0);
        assert_eq!(payment.stake_reward, 3800);
        assert!(manager.get_block_subsidy_at_height(0).is_none());
        assert!(manager.get_tx_fee_at_height(0).is_none());
    }

    // ================================================================
    // Spork IDs constants
    // ================================================================

    #[test]
    fn test_spork_ids_range() {
        use super::spork_ids::*;
        assert_eq!(SPORK_START, SPORK_2_SWIFTTX_ENABLED);
        assert_eq!(SPORK_END, SPORK_16_LOTTERY_TICKET_MIN_VALUE);
        // Verify ordering: START < END (10001 < 10015)
        assert_eq!(SPORK_START, 10001);
        assert_eq!(SPORK_END, 10015);
    }
}
