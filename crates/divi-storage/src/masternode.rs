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

//! Masternode tier system matching C++ Divi implementation
//!
//! This module implements the 5-tier masternode collateral system and related
//! functionality exactly as implemented in the C++ Divi codebase.
//!
//! Reference: Divi/divi/src/masternode-tier.h, masternode.cpp, chainparams.cpp

use divi_primitives::amount::Amount;
use divi_primitives::constants::COIN;

/// Masternode tier levels
///
/// Matches C++ `MasternodeTier` enum from masternode-tier.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum MasternodeTier {
    /// Copper tier - lowest collateral requirement
    Copper,
    /// Silver tier
    Silver,
    /// Gold tier
    Gold,
    /// Platinum tier
    Platinum,
    /// Diamond tier - highest collateral requirement
    Diamond,
    /// Invalid tier (used for error conditions)
    #[default]
    Invalid,
}

impl MasternodeTier {
    /// Get all valid tiers (excludes Invalid)
    pub fn valid_tiers() -> &'static [MasternodeTier] {
        &[
            MasternodeTier::Copper,
            MasternodeTier::Silver,
            MasternodeTier::Gold,
            MasternodeTier::Platinum,
            MasternodeTier::Diamond,
        ]
    }

    /// Check if this tier is valid (not Invalid)
    pub fn is_valid(&self) -> bool {
        !matches!(self, MasternodeTier::Invalid)
    }
}

/// Network-specific masternode collateral requirements
#[derive(Debug, Clone, Copy)]
pub struct MasternodeCollateral {
    pub copper: Amount,
    pub silver: Amount,
    pub gold: Amount,
    pub platinum: Amount,
    pub diamond: Amount,
}

impl MasternodeCollateral {
    /// Mainnet collateral requirements
    ///
    /// Matches C++ mnCollateralsMainnet from chainparams.cpp:136-142
    pub fn mainnet() -> Self {
        Self {
            copper: Amount::from_sat(100_000 * COIN),
            silver: Amount::from_sat(300_000 * COIN),
            gold: Amount::from_sat(1_000_000 * COIN),
            platinum: Amount::from_sat(3_000_000 * COIN),
            diamond: Amount::from_sat(10_000_000 * COIN),
        }
    }

    /// Testnet collateral requirements (same as mainnet)
    pub fn testnet() -> Self {
        Self::mainnet()
    }

    /// Regtest collateral requirements (cheaper for testing)
    ///
    /// Matches C++ mnCollateralsRegtest from chainparams.cpp:147-152
    pub fn regtest() -> Self {
        Self {
            copper: Amount::from_sat(100 * COIN),
            silver: Amount::from_sat(300 * COIN),
            gold: Amount::from_sat(1_000 * COIN),
            platinum: Amount::from_sat(3_000 * COIN),
            diamond: Amount::from_sat(10_000 * COIN),
        }
    }

    /// Get collateral amount for a specific tier
    ///
    /// Matches C++ CMasternode::GetTierCollateralAmount() from masternode.cpp:17-24
    pub fn get_tier_collateral(&self, tier: MasternodeTier) -> Amount {
        match tier {
            MasternodeTier::Copper => self.copper,
            MasternodeTier::Silver => self.silver,
            MasternodeTier::Gold => self.gold,
            MasternodeTier::Platinum => self.platinum,
            MasternodeTier::Diamond => self.diamond,
            MasternodeTier::Invalid => Amount::ZERO,
        }
    }

    /// Get tier by collateral amount
    ///
    /// Matches C++ CMasternode::GetTierByCollateralAmount() from masternode.cpp:181-187
    pub fn get_tier_by_collateral(&self, amount: Amount) -> MasternodeTier {
        if amount == self.copper {
            MasternodeTier::Copper
        } else if amount == self.silver {
            MasternodeTier::Silver
        } else if amount == self.gold {
            MasternodeTier::Gold
        } else if amount == self.platinum {
            MasternodeTier::Platinum
        } else if amount == self.diamond {
            MasternodeTier::Diamond
        } else {
            MasternodeTier::Invalid
        }
    }

    /// Check if an amount is a valid masternode collateral
    pub fn is_valid_collateral(&self, amount: Amount) -> bool {
        self.get_tier_by_collateral(amount).is_valid()
    }

    /// Get all valid collateral amounts for this network
    pub fn all_collaterals(&self) -> Vec<Amount> {
        vec![
            self.copper,
            self.silver,
            self.gold,
            self.platinum,
            self.diamond,
        ]
    }
}

/// Get the number of hash rounds for masternode score calculation
///
/// Matches C++ GetHashRoundsForTierMasternodes() from masternode.cpp:26-39
///
/// Higher tier masternodes get more hash rounds, which gives them better
/// chances of winning block rewards in the deterministic selection.
pub fn get_hash_rounds_for_tier(tier: MasternodeTier) -> usize {
    match tier {
        MasternodeTier::Copper => 20,
        MasternodeTier::Silver => 63,
        MasternodeTier::Gold => 220,
        MasternodeTier::Platinum => 690,
        MasternodeTier::Diamond => 2400,
        MasternodeTier::Invalid => 0,
    }
}

/// Convert tier to string representation
///
/// Matches C++ CMasternode::TierToString() from masternode.cpp:204-217
pub fn tier_to_string(tier: MasternodeTier) -> &'static str {
    match tier {
        MasternodeTier::Copper => "COPPER",
        MasternodeTier::Silver => "SILVER",
        MasternodeTier::Gold => "GOLD",
        MasternodeTier::Platinum => "PLATINUM",
        MasternodeTier::Diamond => "DIAMOND",
        MasternodeTier::Invalid => "INVALID",
    }
}

/// Parse tier from string (case-insensitive)
pub fn tier_from_string(s: &str) -> MasternodeTier {
    match s.to_uppercase().as_str() {
        "COPPER" => MasternodeTier::Copper,
        "SILVER" => MasternodeTier::Silver,
        "GOLD" => MasternodeTier::Gold,
        "PLATINUM" => MasternodeTier::Platinum,
        "DIAMOND" => MasternodeTier::Diamond,
        _ => MasternodeTier::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // MasternodeTier Tests
    // ========================================

    #[test]
    fn test_tier_ordering() {
        // Tiers should be ordered from lowest to highest
        assert!(MasternodeTier::Copper < MasternodeTier::Silver);
        assert!(MasternodeTier::Silver < MasternodeTier::Gold);
        assert!(MasternodeTier::Gold < MasternodeTier::Platinum);
        assert!(MasternodeTier::Platinum < MasternodeTier::Diamond);
    }

    #[test]
    fn test_tier_is_valid() {
        assert!(MasternodeTier::Copper.is_valid());
        assert!(MasternodeTier::Silver.is_valid());
        assert!(MasternodeTier::Gold.is_valid());
        assert!(MasternodeTier::Platinum.is_valid());
        assert!(MasternodeTier::Diamond.is_valid());
        assert!(!MasternodeTier::Invalid.is_valid());
    }

    #[test]
    fn test_valid_tiers() {
        let valid = MasternodeTier::valid_tiers();
        assert_eq!(valid.len(), 5);
        assert!(valid.contains(&MasternodeTier::Copper));
        assert!(valid.contains(&MasternodeTier::Silver));
        assert!(valid.contains(&MasternodeTier::Gold));
        assert!(valid.contains(&MasternodeTier::Platinum));
        assert!(valid.contains(&MasternodeTier::Diamond));
        assert!(!valid.contains(&MasternodeTier::Invalid));
    }

    #[test]
    fn test_tier_default() {
        assert_eq!(MasternodeTier::default(), MasternodeTier::Invalid);
    }

    // ========================================
    // Mainnet Collateral Tests
    // ========================================

    #[test]
    fn test_mainnet_collaterals() {
        let collateral = MasternodeCollateral::mainnet();

        assert_eq!(collateral.copper.as_divi(), 100_000);
        assert_eq!(collateral.silver.as_divi(), 300_000);
        assert_eq!(collateral.gold.as_divi(), 1_000_000);
        assert_eq!(collateral.platinum.as_divi(), 3_000_000);
        assert_eq!(collateral.diamond.as_divi(), 10_000_000);
    }

    #[test]
    fn test_mainnet_get_tier_collateral() {
        let collateral = MasternodeCollateral::mainnet();

        assert_eq!(
            collateral.get_tier_collateral(MasternodeTier::Copper),
            Amount::from_sat(100_000 * COIN)
        );
        assert_eq!(
            collateral.get_tier_collateral(MasternodeTier::Silver),
            Amount::from_sat(300_000 * COIN)
        );
        assert_eq!(
            collateral.get_tier_collateral(MasternodeTier::Gold),
            Amount::from_sat(1_000_000 * COIN)
        );
        assert_eq!(
            collateral.get_tier_collateral(MasternodeTier::Platinum),
            Amount::from_sat(3_000_000 * COIN)
        );
        assert_eq!(
            collateral.get_tier_collateral(MasternodeTier::Diamond),
            Amount::from_sat(10_000_000 * COIN)
        );
        assert_eq!(
            collateral.get_tier_collateral(MasternodeTier::Invalid),
            Amount::ZERO
        );
    }

    #[test]
    fn test_mainnet_get_tier_by_collateral() {
        let collateral = MasternodeCollateral::mainnet();

        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(100_000 * COIN)),
            MasternodeTier::Copper
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(300_000 * COIN)),
            MasternodeTier::Silver
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(1_000_000 * COIN)),
            MasternodeTier::Gold
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(3_000_000 * COIN)),
            MasternodeTier::Platinum
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(10_000_000 * COIN)),
            MasternodeTier::Diamond
        );
    }

    #[test]
    fn test_mainnet_invalid_collateral() {
        let collateral = MasternodeCollateral::mainnet();

        // Test various invalid amounts
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::ZERO),
            MasternodeTier::Invalid
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(99_999 * COIN)),
            MasternodeTier::Invalid
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(100_001 * COIN)),
            MasternodeTier::Invalid
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(500_000 * COIN)),
            MasternodeTier::Invalid
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(20_000_000 * COIN)),
            MasternodeTier::Invalid
        );
    }

    #[test]
    fn test_mainnet_is_valid_collateral() {
        let collateral = MasternodeCollateral::mainnet();

        assert!(collateral.is_valid_collateral(Amount::from_sat(100_000 * COIN)));
        assert!(collateral.is_valid_collateral(Amount::from_sat(300_000 * COIN)));
        assert!(collateral.is_valid_collateral(Amount::from_sat(1_000_000 * COIN)));
        assert!(collateral.is_valid_collateral(Amount::from_sat(3_000_000 * COIN)));
        assert!(collateral.is_valid_collateral(Amount::from_sat(10_000_000 * COIN)));

        assert!(!collateral.is_valid_collateral(Amount::ZERO));
        assert!(!collateral.is_valid_collateral(Amount::from_sat(99_999 * COIN)));
        assert!(!collateral.is_valid_collateral(Amount::from_sat(500_000 * COIN)));
    }

    #[test]
    fn test_mainnet_all_collaterals() {
        let collateral = MasternodeCollateral::mainnet();
        let all = collateral.all_collaterals();

        assert_eq!(all.len(), 5);
        assert!(all.contains(&Amount::from_sat(100_000 * COIN)));
        assert!(all.contains(&Amount::from_sat(300_000 * COIN)));
        assert!(all.contains(&Amount::from_sat(1_000_000 * COIN)));
        assert!(all.contains(&Amount::from_sat(3_000_000 * COIN)));
        assert!(all.contains(&Amount::from_sat(10_000_000 * COIN)));
    }

    // ========================================
    // Regtest Collateral Tests
    // ========================================

    #[test]
    fn test_regtest_collaterals() {
        let collateral = MasternodeCollateral::regtest();

        assert_eq!(collateral.copper.as_divi(), 100);
        assert_eq!(collateral.silver.as_divi(), 300);
        assert_eq!(collateral.gold.as_divi(), 1_000);
        assert_eq!(collateral.platinum.as_divi(), 3_000);
        assert_eq!(collateral.diamond.as_divi(), 10_000);
    }

    #[test]
    fn test_regtest_get_tier_by_collateral() {
        let collateral = MasternodeCollateral::regtest();

        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(100 * COIN)),
            MasternodeTier::Copper
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(300 * COIN)),
            MasternodeTier::Silver
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(1_000 * COIN)),
            MasternodeTier::Gold
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(3_000 * COIN)),
            MasternodeTier::Platinum
        );
        assert_eq!(
            collateral.get_tier_by_collateral(Amount::from_sat(10_000 * COIN)),
            MasternodeTier::Diamond
        );
    }

    #[test]
    fn test_regtest_collaterals_much_cheaper_than_mainnet() {
        let mainnet = MasternodeCollateral::mainnet();
        let regtest = MasternodeCollateral::regtest();

        // Regtest collaterals should be 1/1000 of mainnet
        assert_eq!(mainnet.copper.as_sat() / 1000, regtest.copper.as_sat());
        assert_eq!(mainnet.silver.as_sat() / 1000, regtest.silver.as_sat());
        assert_eq!(mainnet.gold.as_sat() / 1000, regtest.gold.as_sat());
        assert_eq!(mainnet.platinum.as_sat() / 1000, regtest.platinum.as_sat());
        assert_eq!(mainnet.diamond.as_sat() / 1000, regtest.diamond.as_sat());
    }

    // ========================================
    // Hash Rounds Tests
    // ========================================

    #[test]
    fn test_hash_rounds_for_tier() {
        assert_eq!(get_hash_rounds_for_tier(MasternodeTier::Copper), 20);
        assert_eq!(get_hash_rounds_for_tier(MasternodeTier::Silver), 63);
        assert_eq!(get_hash_rounds_for_tier(MasternodeTier::Gold), 220);
        assert_eq!(get_hash_rounds_for_tier(MasternodeTier::Platinum), 690);
        assert_eq!(get_hash_rounds_for_tier(MasternodeTier::Diamond), 2400);
        assert_eq!(get_hash_rounds_for_tier(MasternodeTier::Invalid), 0);
    }

    #[test]
    fn test_hash_rounds_increase_with_tier() {
        // Higher tiers should get more hash rounds
        assert!(
            get_hash_rounds_for_tier(MasternodeTier::Copper)
                < get_hash_rounds_for_tier(MasternodeTier::Silver)
        );
        assert!(
            get_hash_rounds_for_tier(MasternodeTier::Silver)
                < get_hash_rounds_for_tier(MasternodeTier::Gold)
        );
        assert!(
            get_hash_rounds_for_tier(MasternodeTier::Gold)
                < get_hash_rounds_for_tier(MasternodeTier::Platinum)
        );
        assert!(
            get_hash_rounds_for_tier(MasternodeTier::Platinum)
                < get_hash_rounds_for_tier(MasternodeTier::Diamond)
        );
    }

    // ========================================
    // String Conversion Tests
    // ========================================

    #[test]
    fn test_tier_to_string() {
        assert_eq!(tier_to_string(MasternodeTier::Copper), "COPPER");
        assert_eq!(tier_to_string(MasternodeTier::Silver), "SILVER");
        assert_eq!(tier_to_string(MasternodeTier::Gold), "GOLD");
        assert_eq!(tier_to_string(MasternodeTier::Platinum), "PLATINUM");
        assert_eq!(tier_to_string(MasternodeTier::Diamond), "DIAMOND");
        assert_eq!(tier_to_string(MasternodeTier::Invalid), "INVALID");
    }

    #[test]
    fn test_tier_from_string() {
        assert_eq!(tier_from_string("COPPER"), MasternodeTier::Copper);
        assert_eq!(tier_from_string("SILVER"), MasternodeTier::Silver);
        assert_eq!(tier_from_string("GOLD"), MasternodeTier::Gold);
        assert_eq!(tier_from_string("PLATINUM"), MasternodeTier::Platinum);
        assert_eq!(tier_from_string("DIAMOND"), MasternodeTier::Diamond);
        assert_eq!(tier_from_string("INVALID"), MasternodeTier::Invalid);
    }

    #[test]
    fn test_tier_from_string_case_insensitive() {
        assert_eq!(tier_from_string("copper"), MasternodeTier::Copper);
        assert_eq!(tier_from_string("Copper"), MasternodeTier::Copper);
        assert_eq!(tier_from_string("COPPER"), MasternodeTier::Copper);
        assert_eq!(tier_from_string("silver"), MasternodeTier::Silver);
        assert_eq!(tier_from_string("SiLvEr"), MasternodeTier::Silver);
    }

    #[test]
    fn test_tier_from_string_invalid() {
        assert_eq!(tier_from_string(""), MasternodeTier::Invalid);
        assert_eq!(tier_from_string("bronze"), MasternodeTier::Invalid);
        assert_eq!(tier_from_string("unknown"), MasternodeTier::Invalid);
        assert_eq!(tier_from_string("123"), MasternodeTier::Invalid);
    }

    #[test]
    fn test_tier_string_round_trip() {
        for tier in MasternodeTier::valid_tiers() {
            let s = tier_to_string(*tier);
            let parsed = tier_from_string(s);
            assert_eq!(parsed, *tier);
        }
    }

    // ========================================
    // Integration Tests
    // ========================================

    #[test]
    fn test_collateral_to_hash_rounds_correlation() {
        let collateral = MasternodeCollateral::mainnet();

        // Higher collateral should give more hash rounds
        for tier in MasternodeTier::valid_tiers() {
            let amount = collateral.get_tier_collateral(*tier);
            let rounds = get_hash_rounds_for_tier(*tier);

            // Verify tier can be recovered from collateral
            assert_eq!(collateral.get_tier_by_collateral(amount), *tier);

            // Verify hash rounds are non-zero for valid tiers
            assert!(
                rounds > 0,
                "Tier {:?} should have positive hash rounds",
                tier
            );
        }
    }

    #[test]
    fn test_testnet_same_as_mainnet() {
        let mainnet = MasternodeCollateral::mainnet();
        let testnet = MasternodeCollateral::testnet();

        assert_eq!(mainnet.copper, testnet.copper);
        assert_eq!(mainnet.silver, testnet.silver);
        assert_eq!(mainnet.gold, testnet.gold);
        assert_eq!(mainnet.platinum, testnet.platinum);
        assert_eq!(mainnet.diamond, testnet.diamond);
    }
}
