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

//! Stake modifier service
//!
//! The stake modifier is a value derived from the blockchain that adds
//! entropy to proof-of-stake calculations, preventing attackers from
//! pre-computing valid stakes.
//!
//! In Divi, there are two stake modifier algorithms:
//! 1. Legacy: Uses a selection interval to find a stake modifier
//! 2. Hardened (post-fork): Uses the most recent generated stake modifier

use crate::error::ConsensusError;
use crate::staking_data::StakingData;

/// Modifier interval ratio for legacy stake modifier selection
pub const MODIFIER_INTERVAL_RATIO: i64 = 3;

/// Base modifier interval in seconds
pub const MODIFIER_INTERVAL: i64 = 60;

/// Trait for stake modifier lookup
pub trait StakeModifierService {
    /// Get the stake modifier for the given staking data
    ///
    /// Returns (stake_modifier, success)
    fn get_stake_modifier(&self, staking_data: &StakingData) -> Result<u64, ConsensusError>;
}

/// Get the stake modifier selection interval for a given section
///
/// This implements the variable-width interval selection from the C++ code.
/// The intervals get progressively smaller to add more randomness.
pub fn get_stake_modifier_selection_interval_section(section: usize) -> i64 {
    assert!(section < 64, "Section must be 0-63");
    MODIFIER_INTERVAL * 63 / (63 + ((63 - section as i64) * (MODIFIER_INTERVAL_RATIO - 1)))
}

/// Get the total stake modifier selection interval
///
/// This is the sum of all 64 section intervals.
pub fn get_stake_modifier_selection_interval() -> i64 {
    let mut total = 0i64;
    for section in 0..64 {
        total += get_stake_modifier_selection_interval_section(section);
    }
    total
}

/// Block index trait for stake modifier lookups
///
/// This trait must be implemented by the chain storage to enable
/// stake modifier retrieval.
pub trait BlockIndex {
    /// Get the block height
    fn height(&self) -> u32;

    /// Get the block time
    fn block_time(&self) -> u32;

    /// Get the stake modifier if this block generated one
    fn stake_modifier(&self) -> Option<u64>;

    /// Check if this block generated a new stake modifier
    fn generated_stake_modifier(&self) -> bool;
}

/// A simple stake modifier service that uses a lookup function
///
/// This is primarily useful for testing.
pub struct SimpleStakeModifierService<F>
where
    F: Fn(&StakingData) -> Result<u64, ConsensusError>,
{
    lookup: F,
}

impl<F> SimpleStakeModifierService<F>
where
    F: Fn(&StakingData) -> Result<u64, ConsensusError>,
{
    /// Create a new simple stake modifier service
    pub fn new(lookup: F) -> Self {
        SimpleStakeModifierService { lookup }
    }
}

impl<F> StakeModifierService for SimpleStakeModifierService<F>
where
    F: Fn(&StakingData) -> Result<u64, ConsensusError>,
{
    fn get_stake_modifier(&self, staking_data: &StakingData) -> Result<u64, ConsensusError> {
        (self.lookup)(staking_data)
    }
}

/// A mock stake modifier service for testing that returns fixed values
#[derive(Default)]
pub struct MockStakeModifierService {
    modifier: u64,
}

impl MockStakeModifierService {
    /// Create a new mock service with the given modifier
    pub fn new(modifier: u64) -> Self {
        MockStakeModifierService { modifier }
    }
}

impl StakeModifierService for MockStakeModifierService {
    fn get_stake_modifier(&self, _staking_data: &StakingData) -> Result<u64, ConsensusError> {
        Ok(self.modifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_modifier_selection_interval() {
        // The total selection interval should be the sum of all 64 sections
        let total = get_stake_modifier_selection_interval();

        // Manually compute expected value
        let mut expected = 0i64;
        for section in 0..64 {
            expected += get_stake_modifier_selection_interval_section(section);
        }

        assert_eq!(total, expected);
        assert!(total > 0);
    }

    #[test]
    fn test_stake_modifier_section_intervals() {
        // Early sections should have smaller intervals (more variation)
        let section_0 = get_stake_modifier_selection_interval_section(0);
        let section_63 = get_stake_modifier_selection_interval_section(63);

        // Section 0 has divisor (63 + 63*2) = 189, so 60*63/189 = 20
        // Section 63 has divisor (63 + 0*2) = 63, so 60*63/63 = 60
        assert!(section_0 < section_63);
    }

    #[test]
    fn test_mock_stake_modifier_service() {
        let service = MockStakeModifierService::new(12345);
        let staking_data = StakingData::default();

        let result = service.get_stake_modifier(&staking_data);
        assert_eq!(result.unwrap(), 12345);
    }

    #[test]
    fn test_simple_stake_modifier_service() {
        let service = SimpleStakeModifierService::new(|_data| Ok(67890));
        let staking_data = StakingData::default();

        let result = service.get_stake_modifier(&staking_data);
        assert_eq!(result.unwrap(), 67890);
    }
}
