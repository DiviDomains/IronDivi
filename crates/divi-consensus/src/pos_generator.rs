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

//! Proof-of-Stake generator
//!
//! This module provides the high-level API for generating and verifying
//! proof-of-stake blocks.

use crate::error::ConsensusError;
use crate::pos_calculator::{create_hashproof, HashproofResult, ProofOfStakeCalculator};
use crate::stake_modifier::StakeModifierService;
use crate::staking_data::StakingData;
use divi_primitives::hash::Hash256;

/// Proof-of-stake generator
///
/// This struct provides the high-level interface for creating and verifying
/// proof-of-stake blocks. It combines the stake modifier service with the
/// PoS calculator.
pub struct ProofOfStakeGenerator<S: StakeModifierService> {
    /// Service to retrieve stake modifiers from the chain
    stake_modifier_service: S,

    /// Minimum coin age required for staking (in seconds)
    minimum_coin_age: u32,
}

impl<S: StakeModifierService> ProofOfStakeGenerator<S> {
    /// Create a new PoS generator
    pub fn new(stake_modifier_service: S, minimum_coin_age: u32) -> Self {
        ProofOfStakeGenerator {
            stake_modifier_service,
            minimum_coin_age,
        }
    }

    /// Check if the time requirements for staking are met
    ///
    /// This verifies:
    /// 1. The hashproof timestamp is not before the coinstake start time
    /// 2. The minimum coin age requirement is satisfied
    pub fn time_requirements_met(
        &self,
        coinstake_start_time: u32,
        hashproof_timestamp: u32,
    ) -> Result<(), ConsensusError> {
        // Check timestamp ordering
        if hashproof_timestamp < coinstake_start_time {
            return Err(ConsensusError::TimestampViolation {
                hashproof_time: hashproof_timestamp,
                coinstake_time: coinstake_start_time,
            });
        }

        // Check minimum coin age
        let actual_age = hashproof_timestamp - coinstake_start_time;
        if actual_age < self.minimum_coin_age {
            return Err(ConsensusError::MinimumCoinAgeNotMet {
                required: self.minimum_coin_age,
                actual: actual_age,
            });
        }

        Ok(())
    }

    /// Create a PoS calculator for the given staking data
    fn create_calculator(
        &self,
        staking_data: &StakingData,
        hashproof_timestamp: u32,
    ) -> Result<ProofOfStakeCalculator, ConsensusError> {
        // Check time requirements
        self.time_requirements_met(
            staking_data.block_time_of_first_confirmation,
            hashproof_timestamp,
        )?;

        // Get stake modifier
        let stake_modifier = self
            .stake_modifier_service
            .get_stake_modifier(staking_data)?;

        Ok(ProofOfStakeCalculator::new(staking_data, stake_modifier))
    }

    /// Compute and verify a proof-of-stake
    ///
    /// This validates that the given hashproof timestamp produces a valid
    /// proof-of-stake hash for the provided staking data.
    ///
    /// # Returns
    /// The computed proof-of-stake hash if validation succeeds
    pub fn compute_and_verify(
        &self,
        staking_data: &StakingData,
        hashproof_timestamp: u32,
    ) -> Result<Hash256, ConsensusError> {
        let calculator = self.create_calculator(staking_data, hashproof_timestamp)?;

        let mut hash_proof = Hash256::zero();
        if calculator.compute_and_check_target(hashproof_timestamp, &mut hash_proof, false)? {
            Ok(hash_proof)
        } else {
            Err(ConsensusError::ProofOfStakeTargetNotMet)
        }
    }

    /// Create a hashproof timestamp for staking
    ///
    /// This tries multiple timestamps to find one that produces a valid
    /// proof-of-stake hash.
    ///
    /// # Arguments
    /// * `staking_data` - The staking parameters
    /// * `initial_timestamp` - The starting timestamp to try
    ///
    /// # Returns
    /// The result of the hashproof creation attempt
    pub fn create_hashproof_timestamp(
        &self,
        staking_data: &StakingData,
        initial_timestamp: u32,
    ) -> HashproofResult {
        match self.create_calculator(staking_data, initial_timestamp) {
            Ok(calculator) => create_hashproof(&calculator, initial_timestamp),
            Err(e) => {
                tracing::debug!(
                    "Hashproof setup failed for UTXO {}:{}: {:?} (hashproof_ts={}, block_time={}, age={}s, min_age={})",
                    staking_data.utxo_being_staked.txid,
                    staking_data.utxo_being_staked.vout,
                    e,
                    initial_timestamp,
                    staking_data.block_time_of_first_confirmation,
                    initial_timestamp.saturating_sub(staking_data.block_time_of_first_confirmation),
                    self.minimum_coin_age,
                );
                HashproofResult::FailedSetup
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stake_modifier::MockStakeModifierService;
    use divi_primitives::amount::Amount;
    use divi_primitives::transaction::OutPoint;

    #[test]
    fn test_time_requirements_met() {
        let service = MockStakeModifierService::new(0);
        let generator = ProofOfStakeGenerator::new(service, 3600); // 1 hour min age

        // Valid: timestamp is 2 hours after coinstake
        let result = generator.time_requirements_met(1000, 1000 + 7200);
        assert!(result.is_ok());

        // Invalid: timestamp before coinstake
        let result = generator.time_requirements_met(2000, 1000);
        assert!(matches!(
            result,
            Err(ConsensusError::TimestampViolation { .. })
        ));

        // Invalid: coin age too low
        let result = generator.time_requirements_met(1000, 1000 + 1800);
        assert!(matches!(
            result,
            Err(ConsensusError::MinimumCoinAgeNotMet { .. })
        ));
    }

    #[test]
    fn test_compute_and_verify() {
        // Use test vector from C++ block 10k
        let staking_data = StakingData::new(
            470026099,
            1538645320,
            Hash256::from_hex("967b03e3c1daf39633ed73ffb29abfcab9ae5b384dc5b95dabee0890bf8b4546")
                .unwrap(),
            OutPoint::new(
                Hash256::from_hex(
                    "4266403b499375917920311b1af704805d3fa2d6d6f4e3217026618028423607",
                )
                .unwrap(),
                1,
            ),
            Amount::from_sat(62542750000000),
            Hash256::from_hex("acf49c06030a7a76059a25b174dc7adcdc5f4ad36c91b564c585743af4829f7a")
                .unwrap(),
        );

        let service = MockStakeModifierService::new(13260253192);
        let generator = ProofOfStakeGenerator::new(service, 0);

        let result = generator.compute_and_verify(&staking_data, 1538663336);
        assert!(result.is_ok(), "Block 10k PoS should verify");
    }

    #[test]
    fn test_create_hashproof_timestamp() {
        // Use test vector that we know should pass at the exact timestamp
        let staking_data = StakingData::new(
            470026099,
            1538645320,
            Hash256::from_hex("967b03e3c1daf39633ed73ffb29abfcab9ae5b384dc5b95dabee0890bf8b4546")
                .unwrap(),
            OutPoint::new(
                Hash256::from_hex(
                    "4266403b499375917920311b1af704805d3fa2d6d6f4e3217026618028423607",
                )
                .unwrap(),
                1,
            ),
            Amount::from_sat(62542750000000),
            Hash256::from_hex("acf49c06030a7a76059a25b174dc7adcdc5f4ad36c91b564c585743af4829f7a")
                .unwrap(),
        );

        let service = MockStakeModifierService::new(13260253192);
        let generator = ProofOfStakeGenerator::new(service, 0);

        // The test vector says timestamp 1538663336 should work
        let result = generator.create_hashproof_timestamp(&staking_data, 1538663336);

        assert!(result.succeeded(), "Should find valid hashproof");
        assert_eq!(result.timestamp(), Some(1538663336));
    }

    #[test]
    fn test_hashproof_failed_generation() {
        // Use an impossible target (very low nBits)
        let staking_data = StakingData::new(
            0x01000001, // Extremely hard target
            1538645320,
            Hash256::from_bytes([1u8; 32]),
            OutPoint::new(Hash256::from_bytes([2u8; 32]), 0),
            Amount::from_sat(100000000), // 1 DIVI
            Hash256::from_bytes([3u8; 32]),
        );

        let service = MockStakeModifierService::new(12345);
        let generator = ProofOfStakeGenerator::new(service, 0);

        let result = generator.create_hashproof_timestamp(&staking_data, 1538663336);

        // Should fail to generate (target too hard)
        assert!(!result.succeeded());
        assert!(!result.failed_at_setup());
    }
}
