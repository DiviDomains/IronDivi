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

//! Staking data structures
//!
//! Contains the data required for proof-of-stake calculations.

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::OutPoint;

/// Data required for staking calculations
///
/// This contains all the information needed to compute a proof-of-stake
/// hash and verify it meets the required target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingData {
    /// Compact difficulty target (nBits from block header)
    pub n_bits: u32,

    /// Block time of the first confirmation block for the UTXO being staked
    /// This is used to calculate coin age
    pub block_time_of_first_confirmation: u32,

    /// Block hash of the first confirmation block for the UTXO being staked
    pub block_hash_of_first_confirmation: Hash256,

    /// The UTXO being staked (txid:vout reference)
    pub utxo_being_staked: OutPoint,

    /// Value of the UTXO being staked in satoshis
    pub utxo_value: Amount,

    /// Block hash of the current chain tip (used for stake modifier lookup)
    pub block_hash_of_chain_tip: Hash256,
}

impl StakingData {
    /// Create new staking data
    pub fn new(
        n_bits: u32,
        block_time_of_first_confirmation: u32,
        block_hash_of_first_confirmation: Hash256,
        utxo_being_staked: OutPoint,
        utxo_value: Amount,
        block_hash_of_chain_tip: Hash256,
    ) -> Self {
        StakingData {
            n_bits,
            block_time_of_first_confirmation,
            block_hash_of_first_confirmation,
            utxo_being_staked,
            utxo_value,
            block_hash_of_chain_tip,
        }
    }
}

impl Default for StakingData {
    fn default() -> Self {
        StakingData {
            n_bits: 0,
            block_time_of_first_confirmation: 0,
            block_hash_of_first_confirmation: Hash256::zero(),
            utxo_being_staked: OutPoint::null(),
            utxo_value: Amount::ZERO,
            block_hash_of_chain_tip: Hash256::zero(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staking_data_creation() {
        let data = StakingData::new(
            0x1d00ffff,
            1538645320,
            Hash256::from_bytes([1u8; 32]),
            OutPoint::new(Hash256::from_bytes([2u8; 32]), 0),
            Amount::from_sat(1000000000000),
            Hash256::from_bytes([3u8; 32]),
        );

        assert_eq!(data.n_bits, 0x1d00ffff);
        assert_eq!(data.block_time_of_first_confirmation, 1538645320);
        assert_eq!(data.utxo_value.as_sat(), 1000000000000);
    }

    #[test]
    fn test_staking_data_default() {
        let data = StakingData::default();
        assert_eq!(data.n_bits, 0);
        assert!(data.block_hash_of_first_confirmation.is_zero());
        assert!(data.utxo_being_staked.is_null());
    }
}
