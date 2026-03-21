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

//! Coin selection algorithms for UTXO selection
//!
//! This module provides various strategies for selecting UTXOs to fund transactions.

use crate::error::WalletError;
use crate::wallet_db::WalletUtxo;
use divi_primitives::amount::Amount;
use divi_primitives::transaction::OutPoint;
use std::collections::HashSet;

/// Result of a coin selection operation
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// Selected UTXOs
    pub utxos: Vec<WalletUtxo>,
    /// Total value of selected UTXOs
    pub total_value: Amount,
    /// Estimated transaction fee
    pub estimated_fee: Amount,
    /// Change amount (total_value - target - fee)
    pub change_amount: Amount,
}

impl SelectionResult {
    /// Create a new selection result
    pub fn new(
        utxos: Vec<WalletUtxo>,
        total_value: Amount,
        estimated_fee: Amount,
        target: Amount,
    ) -> Self {
        let change_amount = total_value - target - estimated_fee;
        SelectionResult {
            utxos,
            total_value,
            estimated_fee,
            change_amount,
        }
    }

    /// Get the outpoints of selected UTXOs
    pub fn outpoints(&self) -> Vec<OutPoint> {
        self.utxos.iter().map(|u| u.outpoint()).collect()
    }
}

/// Trait for coin selection strategies
pub trait CoinSelector {
    /// Select UTXOs to meet the target amount plus fee
    ///
    /// # Arguments
    /// * `available_utxos` - Pool of UTXOs to select from
    /// * `target` - Target amount to send (excluding fee)
    /// * `fee_rate` - Fee rate in satoshis per byte
    /// * `num_outputs` - Number of outputs in the transaction
    /// * `excluded` - Set of outpoints to exclude from selection
    ///
    /// # Returns
    /// SelectionResult containing selected UTXOs and computed values
    fn select(
        &self,
        available_utxos: &[WalletUtxo],
        target: Amount,
        fee_rate: u64,
        num_outputs: usize,
        excluded: &HashSet<OutPoint>,
    ) -> Result<SelectionResult, WalletError>;
}

/// Calculate estimated transaction fee
///
/// Fee = fee_rate * estimated_tx_size
/// Estimated size = 10 + (34 * num_outputs) + (148 * num_inputs)
///
/// This is a simplified formula for legacy P2PKH transactions:
/// - 10 bytes: transaction overhead (version, locktime, etc.)
/// - 34 bytes per output: amount (8) + script length (1) + script (25)
/// - 148 bytes per input: txid (32) + vout (4) + script_sig length (1) +
///   script_sig (107 for P2PKH) + sequence (4)
fn calculate_fee(num_inputs: usize, num_outputs: usize, fee_rate: u64) -> Amount {
    let estimated_size = 10 + (34 * num_outputs) + (148 * num_inputs);
    let fee_sats = (estimated_size as u64 * fee_rate) as i64;
    Amount::from_sat(fee_sats)
}

/// Minimum coin selection - select fewest UTXOs to meet target + fee
pub struct MinimumSelector;

impl CoinSelector for MinimumSelector {
    fn select(
        &self,
        available_utxos: &[WalletUtxo],
        target: Amount,
        fee_rate: u64,
        num_outputs: usize,
        excluded: &HashSet<OutPoint>,
    ) -> Result<SelectionResult, WalletError> {
        // Filter out excluded UTXOs
        let mut utxos: Vec<_> = available_utxos
            .iter()
            .filter(|u| !excluded.contains(&u.outpoint()))
            .cloned()
            .collect();

        // Sort by value descending (largest first)
        utxos.sort_by(|a, b| b.value.cmp(&a.value));

        let mut selected = Vec::new();
        let mut total_value = Amount::ZERO;

        // Greedily add largest UTXOs until we have enough
        for utxo in utxos {
            selected.push(utxo.clone());
            total_value += utxo.value;

            // Calculate fee with current number of inputs
            // Add 1 to num_outputs to account for potential change output
            let estimated_fee = calculate_fee(selected.len(), num_outputs + 1, fee_rate);

            // Check if we have enough
            if total_value >= target + estimated_fee {
                return Ok(SelectionResult::new(
                    selected,
                    total_value,
                    estimated_fee,
                    target,
                ));
            }
        }

        // Insufficient funds
        let estimated_fee = calculate_fee(selected.len(), num_outputs + 1, fee_rate);
        Err(WalletError::InsufficientFunds {
            need: (target + estimated_fee).as_sat() as i64,
            have: total_value.as_sat(),
        })
    }
}

/// Largest-first selection - prioritizes largest UTXOs
///
/// This strategy reduces UTXO set size and can be more efficient
/// for consolidation purposes.
pub struct LargestFirstSelector;

impl CoinSelector for LargestFirstSelector {
    fn select(
        &self,
        available_utxos: &[WalletUtxo],
        target: Amount,
        fee_rate: u64,
        num_outputs: usize,
        excluded: &HashSet<OutPoint>,
    ) -> Result<SelectionResult, WalletError> {
        // This is identical to MinimumSelector for now
        // Both select largest UTXOs first
        MinimumSelector.select(available_utxos, target, fee_rate, num_outputs, excluded)
    }
}

/// Confirmation-based selection - only use UTXOs with minimum confirmations
pub struct ConfirmationSelector {
    /// Minimum number of confirmations required
    min_confirmations: u32,
    /// Current block height
    current_height: u32,
}

impl ConfirmationSelector {
    /// Create a new confirmation-based selector
    pub fn new(min_confirmations: u32, current_height: u32) -> Self {
        ConfirmationSelector {
            min_confirmations,
            current_height,
        }
    }
}

impl CoinSelector for ConfirmationSelector {
    fn select(
        &self,
        available_utxos: &[WalletUtxo],
        target: Amount,
        fee_rate: u64,
        num_outputs: usize,
        excluded: &HashSet<OutPoint>,
    ) -> Result<SelectionResult, WalletError> {
        // Filter for confirmed UTXOs
        let confirmed_utxos: Vec<_> = available_utxos
            .iter()
            .filter(|u| {
                !excluded.contains(&u.outpoint())
                    && u.confirmations(self.current_height) >= self.min_confirmations
            })
            .cloned()
            .collect();

        // Use minimum selector on filtered set
        MinimumSelector.select(&confirmed_utxos, target, fee_rate, num_outputs, excluded)
    }
}

/// Convenience functions for coin selection
pub mod select {
    use super::*;

    /// Select minimum UTXOs to meet target + fee
    pub fn select_minimum(
        available_utxos: &[WalletUtxo],
        target: Amount,
        fee_rate: u64,
        num_outputs: usize,
    ) -> Result<SelectionResult, WalletError> {
        let excluded = HashSet::new();
        MinimumSelector.select(available_utxos, target, fee_rate, num_outputs, &excluded)
    }

    /// Select largest UTXOs first
    pub fn select_largest_first(
        available_utxos: &[WalletUtxo],
        target: Amount,
        fee_rate: u64,
        num_outputs: usize,
    ) -> Result<SelectionResult, WalletError> {
        let excluded = HashSet::new();
        LargestFirstSelector.select(available_utxos, target, fee_rate, num_outputs, &excluded)
    }

    /// Select UTXOs with minimum confirmations
    pub fn select_by_confirmations(
        available_utxos: &[WalletUtxo],
        target: Amount,
        fee_rate: u64,
        num_outputs: usize,
        min_confirmations: u32,
        current_height: u32,
    ) -> Result<SelectionResult, WalletError> {
        let excluded = HashSet::new();
        let selector = ConfirmationSelector::new(min_confirmations, current_height);
        selector.select(available_utxos, target, fee_rate, num_outputs, &excluded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;

    fn create_utxo(txid_byte: u8, vout: u32, value_sat: u64, height: Option<u32>) -> WalletUtxo {
        let mut utxo = WalletUtxo::new(
            Hash256::from_bytes([txid_byte; 32]),
            vout,
            Amount::from_sat(value_sat as i64),
            Script::default(),
            "test_address".to_string(),
        );
        utxo.height = height;
        utxo
    }

    #[test]
    fn test_calculate_fee() {
        // 1 input, 2 outputs, 1 sat/byte fee rate
        let fee = calculate_fee(1, 2, 1);
        // Size = 10 + (34 * 2) + (148 * 1) = 10 + 68 + 148 = 226 bytes
        assert_eq!(fee.as_sat(), 226);

        // 2 inputs, 2 outputs, 10 sat/byte fee rate
        let fee = calculate_fee(2, 2, 10);
        // Size = 10 + (34 * 2) + (148 * 2) = 10 + 68 + 296 = 374 bytes
        assert_eq!(fee.as_sat(), 3740);
    }

    #[test]
    fn test_basic_selection_with_enough_funds() {
        let utxos = vec![
            create_utxo(1, 0, 100_000, Some(100)),
            create_utxo(2, 0, 50_000, Some(101)),
            create_utxo(3, 0, 25_000, Some(102)),
        ];

        let target = Amount::from_sat(60_000);
        let fee_rate = 1; // 1 sat/byte

        let result = select::select_minimum(&utxos, target, fee_rate, 1).unwrap();

        // Should select the 100k UTXO (largest first)
        assert_eq!(result.utxos.len(), 1);
        assert_eq!(result.utxos[0].value.as_sat(), 100_000);
        assert_eq!(result.total_value.as_sat(), 100_000);

        // Fee for 1 input, 2 outputs (including change)
        // Size = 10 + (34 * 2) + (148 * 1) = 226 bytes
        assert_eq!(result.estimated_fee.as_sat(), 226);

        // Change = 100_000 - 60_000 - 226 = 39_774
        assert_eq!(result.change_amount.as_sat(), 39_774);
    }

    #[test]
    fn test_selection_exact_match() {
        let utxos = vec![
            create_utxo(1, 0, 100_000, Some(100)),
            create_utxo(2, 0, 50_000, Some(101)),
        ];

        // Target + fee should require both UTXOs
        let target = Amount::from_sat(100_000);
        let fee_rate = 1;

        let result = select::select_minimum(&utxos, target, fee_rate, 1).unwrap();

        // Should select both UTXOs
        assert!(!result.utxos.is_empty());
        assert!(result.total_value >= target + result.estimated_fee);
    }

    #[test]
    fn test_insufficient_funds_error() {
        let utxos = vec![
            create_utxo(1, 0, 10_000, Some(100)),
            create_utxo(2, 0, 5_000, Some(101)),
        ];

        let target = Amount::from_sat(50_000);
        let fee_rate = 1;

        let result = select::select_minimum(&utxos, target, fee_rate, 1);

        assert!(result.is_err());
        match result {
            Err(WalletError::InsufficientFunds { need, have }) => {
                assert_eq!(have, 15_000);
                assert!(need > 50_000);
            }
            _ => panic!("Expected InsufficientFunds error"),
        }
    }

    #[test]
    fn test_correct_fee_calculation() {
        let utxos = vec![
            create_utxo(1, 0, 50_000, Some(100)),
            create_utxo(2, 0, 50_000, Some(101)),
            create_utxo(3, 0, 50_000, Some(102)),
        ];

        let target = Amount::from_sat(80_000);
        let fee_rate = 10; // 10 sat/byte

        let result = select::select_minimum(&utxos, target, fee_rate, 1).unwrap();

        // Should select 2 UTXOs (100k total)
        assert_eq!(result.utxos.len(), 2);
        assert_eq!(result.total_value.as_sat(), 100_000);

        // Fee for 2 inputs, 2 outputs
        // Size = 10 + (34 * 2) + (148 * 2) = 374 bytes
        // Fee = 374 * 10 = 3740
        assert_eq!(result.estimated_fee.as_sat(), 3740);

        // Change = 100_000 - 80_000 - 3740 = 16_260
        assert_eq!(result.change_amount.as_sat(), 16_260);
    }

    #[test]
    fn test_change_amount_calculation() {
        let utxos = vec![create_utxo(1, 0, 200_000, Some(100))];

        let target = Amount::from_sat(100_000);
        let fee_rate = 5;

        let result = select::select_minimum(&utxos, target, fee_rate, 1).unwrap();

        assert_eq!(result.utxos.len(), 1);
        assert_eq!(result.total_value.as_sat(), 200_000);

        // Fee for 1 input, 2 outputs = 226 * 5 = 1130
        assert_eq!(result.estimated_fee.as_sat(), 1130);

        // Change = 200_000 - 100_000 - 1130 = 98_870
        assert_eq!(result.change_amount.as_sat(), 98_870);
    }

    #[test]
    fn test_exclusion_set() {
        let utxos = vec![
            create_utxo(1, 0, 100_000, Some(100)),
            create_utxo(2, 0, 50_000, Some(101)),
        ];

        let target = Amount::from_sat(40_000);
        let fee_rate = 1;

        // Exclude the largest UTXO
        let mut excluded = HashSet::new();
        excluded.insert(utxos[0].outpoint());

        let result = MinimumSelector
            .select(&utxos, target, fee_rate, 1, &excluded)
            .unwrap();

        // Should only use the 50k UTXO
        assert_eq!(result.utxos.len(), 1);
        assert_eq!(result.utxos[0].value.as_sat(), 50_000);
    }

    #[test]
    fn test_confirmation_filter() {
        let utxos = vec![
            create_utxo(1, 0, 100_000, Some(100)), // 6 confs at height 105
            create_utxo(2, 0, 50_000, Some(104)),  // 2 confs at height 105
            create_utxo(3, 0, 75_000, None),       // 0 confs
        ];

        let target = Amount::from_sat(40_000);
        let fee_rate = 1;
        let current_height = 105;

        // Require 3+ confirmations
        let result =
            select::select_by_confirmations(&utxos, target, fee_rate, 1, 3, current_height)
                .unwrap();

        // Should only use the 100k UTXO (6 confirmations)
        assert_eq!(result.utxos.len(), 1);
        assert_eq!(result.utxos[0].value.as_sat(), 100_000);
    }

    #[test]
    fn test_confirmation_insufficient_funds() {
        let utxos = vec![
            create_utxo(1, 0, 10_000, Some(100)), // Confirmed
            create_utxo(2, 0, 90_000, None),      // Unconfirmed
        ];

        let target = Amount::from_sat(50_000);
        let fee_rate = 1;
        let current_height = 105;

        // Require 1+ confirmations - should exclude unconfirmed 90k UTXO
        let result =
            select::select_by_confirmations(&utxos, target, fee_rate, 1, 1, current_height);

        assert!(result.is_err());
        match result {
            Err(WalletError::InsufficientFunds { have, .. }) => {
                assert_eq!(have, 10_000);
            }
            _ => panic!("Expected InsufficientFunds error"),
        }
    }

    #[test]
    fn test_largest_first_selector() {
        let utxos = vec![
            create_utxo(1, 0, 30_000, Some(100)),
            create_utxo(2, 0, 100_000, Some(101)),
            create_utxo(3, 0, 50_000, Some(102)),
        ];

        let target = Amount::from_sat(40_000);
        let fee_rate = 1;

        let result = select::select_largest_first(&utxos, target, fee_rate, 1).unwrap();

        // Should select largest UTXO first (100k)
        assert_eq!(result.utxos.len(), 1);
        assert_eq!(result.utxos[0].value.as_sat(), 100_000);
    }

    #[test]
    fn test_multiple_outputs_fee_calculation() {
        let utxos = vec![create_utxo(1, 0, 200_000, Some(100))];

        let target = Amount::from_sat(100_000);
        let fee_rate = 2;
        let num_outputs = 3; // Multiple recipients

        let result = select::select_minimum(&utxos, target, fee_rate, num_outputs).unwrap();

        // Fee for 1 input, 4 outputs (3 + change)
        // Size = 10 + (34 * 4) + (148 * 1) = 10 + 136 + 148 = 294 bytes
        // Fee = 294 * 2 = 588
        assert_eq!(result.estimated_fee.as_sat(), 588);

        // Change = 200_000 - 100_000 - 588 = 99_412
        assert_eq!(result.change_amount.as_sat(), 99_412);
    }

    // -------- Prefer fewer inputs --------

    #[test]
    fn test_prefer_single_large_input_over_many_small() {
        // Pool: one large UTXO (200k) and many small ones (10k each).
        // Selector sorts largest-first, so 200k is tried first and is enough on its own.
        let mut utxos = vec![create_utxo(0xff, 0, 200_000, Some(100))];
        for i in 0u8..10 {
            utxos.push(create_utxo(i, 1, 10_000, Some(100)));
        }

        let target = Amount::from_sat(80_000);
        let result = select::select_minimum(&utxos, target, 1, 1).unwrap();

        // Should use exactly 1 UTXO (the 200k one)
        assert_eq!(result.utxos.len(), 1);
        assert_eq!(result.utxos[0].value.as_sat(), 200_000);
    }

    #[test]
    fn test_multiple_inputs_when_single_insufficient() {
        // Each UTXO is 30k; need 50k → must pick 2
        let utxos = vec![
            create_utxo(1, 0, 30_000, Some(100)),
            create_utxo(2, 0, 30_000, Some(101)),
            create_utxo(3, 0, 30_000, Some(102)),
        ];

        let target = Amount::from_sat(50_000);
        let result = select::select_minimum(&utxos, target, 1, 1).unwrap();

        // Must use at least 2 inputs to cover target + fee
        assert!(result.utxos.len() >= 2);
        assert!(result.total_value >= target + result.estimated_fee);
    }

    // -------- Immature / underage UTXO (< 20 confirmations) --------

    #[test]
    fn test_confirmation_filter_excludes_underage_utxos() {
        // At height 120, a UTXO confirmed at height 101 has 20 confirmations (120-101+1=20).
        // A UTXO confirmed at height 102 has only 19 confirmations (120-102+1=19).
        let utxos = vec![
            create_utxo(1, 0, 50_000, Some(101)), // 20 confs → included
            create_utxo(2, 0, 50_000, Some(102)), // 19 confs → excluded
        ];

        let result =
            select::select_by_confirmations(&utxos, Amount::from_sat(1_000), 1, 1, 20, 120)
                .unwrap();

        // Only the 50k UTXO at height 101 qualifies
        assert_eq!(result.utxos.len(), 1);
        assert_eq!(result.utxos[0].value.as_sat(), 50_000);
        // Verify it's the one at height 101
        let h = result.utxos[0].height.unwrap();
        assert_eq!(h, 101);
    }

    #[test]
    fn test_unconfirmed_utxo_excluded_by_confirmation_filter() {
        let utxos = vec![
            create_utxo(1, 0, 100_000, None),   // unconfirmed
            create_utxo(2, 0, 50_000, Some(1)), // confirmed
        ];

        // Require at least 1 confirmation at height 100
        let result =
            select::select_by_confirmations(&utxos, Amount::from_sat(40_000), 1, 1, 1, 100)
                .unwrap();

        assert_eq!(result.utxos.len(), 1);
        assert_eq!(result.utxos[0].value.as_sat(), 50_000);
    }

    // -------- Exclusion set with all UTXOs excluded --------

    #[test]
    fn test_all_excluded_returns_insufficient_funds() {
        let utxos = vec![
            create_utxo(1, 0, 100_000, Some(100)),
            create_utxo(2, 0, 50_000, Some(101)),
        ];

        let mut excluded = HashSet::new();
        excluded.insert(utxos[0].outpoint());
        excluded.insert(utxos[1].outpoint());

        let result = MinimumSelector.select(&utxos, Amount::from_sat(10_000), 1, 1, &excluded);
        assert!(result.is_err());
    }

    // -------- outpoints() helper --------

    #[test]
    fn test_selection_result_outpoints() {
        let utxos = vec![
            create_utxo(1, 0, 100_000, Some(100)),
            create_utxo(2, 1, 50_000, Some(101)),
        ];

        let result = select::select_minimum(&utxos, Amount::from_sat(80_000), 1, 1).unwrap();
        let outpoints = result.outpoints();

        // outpoints() must return exactly one entry (largest first picked 100k)
        assert_eq!(outpoints.len(), result.utxos.len());
    }
}
