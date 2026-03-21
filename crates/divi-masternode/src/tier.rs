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

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum MasternodeTier {
    #[default]
    Invalid = 255,
    Copper = 0,
    Silver = 1,
    Gold = 2,
    Platinum = 3,
    Diamond = 4,
}

pub const TIER_INVALID: MasternodeTier = MasternodeTier::Invalid;

pub const MASTERNODE_TIERS: [MasternodeTier; 5] = [
    MasternodeTier::Copper,
    MasternodeTier::Silver,
    MasternodeTier::Gold,
    MasternodeTier::Platinum,
    MasternodeTier::Diamond,
];

impl MasternodeTier {
    pub fn collateral_amount(self) -> i64 {
        match self {
            MasternodeTier::Copper => 100_000 * 100_000_000,
            MasternodeTier::Silver => 300_000 * 100_000_000,
            MasternodeTier::Gold => 1_000_000 * 100_000_000,
            MasternodeTier::Platinum => 3_000_000 * 100_000_000,
            MasternodeTier::Diamond => 10_000_000 * 100_000_000,
            MasternodeTier::Invalid => 0,
        }
    }

    pub fn score_multiplier(self) -> u32 {
        match self {
            MasternodeTier::Copper => 20,
            MasternodeTier::Silver => 63,
            MasternodeTier::Gold => 220,
            MasternodeTier::Platinum => 690,
            MasternodeTier::Diamond => 2400,
            MasternodeTier::Invalid => 0,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            MasternodeTier::Copper => "COPPER",
            MasternodeTier::Silver => "SILVER",
            MasternodeTier::Gold => "GOLD",
            MasternodeTier::Platinum => "PLATINUM",
            MasternodeTier::Diamond => "DIAMOND",
            MasternodeTier::Invalid => "INVALID",
        }
    }

    pub fn from_collateral(amount: i64) -> Self {
        for tier in &MASTERNODE_TIERS {
            if amount == tier.collateral_amount() {
                return *tier;
            }
        }
        MasternodeTier::Invalid
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => MasternodeTier::Copper,
            1 => MasternodeTier::Silver,
            2 => MasternodeTier::Gold,
            3 => MasternodeTier::Platinum,
            4 => MasternodeTier::Diamond,
            _ => MasternodeTier::Invalid,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Get collateral amount in satoshis (alternative to collateral_amount() for u64)
    pub fn collateral_amount_satoshis(self) -> u64 {
        match self {
            MasternodeTier::Copper => 10_000_000_000_000,
            MasternodeTier::Silver => 30_000_000_000_000,
            MasternodeTier::Gold => 100_000_000_000_000,
            MasternodeTier::Platinum => 300_000_000_000_000,
            MasternodeTier::Diamond => 1_000_000_000_000_000,
            MasternodeTier::Invalid => 0,
        }
    }
}

impl std::fmt::Display for MasternodeTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collateral_amounts() {
        assert_eq!(
            MasternodeTier::Copper.collateral_amount(),
            10_000_000_000_000
        );
        assert_eq!(
            MasternodeTier::Silver.collateral_amount(),
            30_000_000_000_000
        );
        assert_eq!(
            MasternodeTier::Gold.collateral_amount(),
            100_000_000_000_000
        );
        assert_eq!(
            MasternodeTier::Platinum.collateral_amount(),
            300_000_000_000_000
        );
        assert_eq!(
            MasternodeTier::Diamond.collateral_amount(),
            1_000_000_000_000_000
        );
        assert_eq!(MasternodeTier::Invalid.collateral_amount(), 0);
    }

    #[test]
    fn test_score_multipliers() {
        assert_eq!(MasternodeTier::Copper.score_multiplier(), 20);
        assert_eq!(MasternodeTier::Silver.score_multiplier(), 63);
        assert_eq!(MasternodeTier::Gold.score_multiplier(), 220);
        assert_eq!(MasternodeTier::Platinum.score_multiplier(), 690);
        assert_eq!(MasternodeTier::Diamond.score_multiplier(), 2400);
        assert_eq!(MasternodeTier::Invalid.score_multiplier(), 0);
    }

    #[test]
    fn test_tier_names() {
        assert_eq!(MasternodeTier::Copper.name(), "COPPER");
        assert_eq!(MasternodeTier::Silver.name(), "SILVER");
        assert_eq!(MasternodeTier::Gold.name(), "GOLD");
        assert_eq!(MasternodeTier::Platinum.name(), "PLATINUM");
        assert_eq!(MasternodeTier::Diamond.name(), "DIAMOND");
        assert_eq!(MasternodeTier::Invalid.name(), "INVALID");
    }

    #[test]
    fn test_from_collateral() {
        assert_eq!(
            MasternodeTier::from_collateral(10_000_000_000_000),
            MasternodeTier::Copper
        );
        assert_eq!(
            MasternodeTier::from_collateral(30_000_000_000_000),
            MasternodeTier::Silver
        );
        assert_eq!(
            MasternodeTier::from_collateral(100_000_000_000_000),
            MasternodeTier::Gold
        );
        assert_eq!(
            MasternodeTier::from_collateral(300_000_000_000_000),
            MasternodeTier::Platinum
        );
        assert_eq!(
            MasternodeTier::from_collateral(1_000_000_000_000_000),
            MasternodeTier::Diamond
        );
        assert_eq!(
            MasternodeTier::from_collateral(999),
            MasternodeTier::Invalid
        );
        assert_eq!(
            MasternodeTier::from_collateral(10_000_000_000_001),
            MasternodeTier::Invalid
        );
    }

    #[test]
    fn test_exact_match_required() {
        let copper_collateral = MasternodeTier::Copper.collateral_amount();
        assert_eq!(
            MasternodeTier::from_collateral(copper_collateral + 1),
            MasternodeTier::Invalid
        );
        assert_eq!(
            MasternodeTier::from_collateral(copper_collateral - 1),
            MasternodeTier::Invalid
        );
    }

    #[test]
    fn test_from_u8() {
        assert_eq!(MasternodeTier::from_u8(0), MasternodeTier::Copper);
        assert_eq!(MasternodeTier::from_u8(1), MasternodeTier::Silver);
        assert_eq!(MasternodeTier::from_u8(2), MasternodeTier::Gold);
        assert_eq!(MasternodeTier::from_u8(3), MasternodeTier::Platinum);
        assert_eq!(MasternodeTier::from_u8(4), MasternodeTier::Diamond);
        assert_eq!(MasternodeTier::from_u8(255), MasternodeTier::Invalid);
        assert_eq!(MasternodeTier::from_u8(99), MasternodeTier::Invalid);
    }

    #[test]
    fn test_to_u8() {
        assert_eq!(MasternodeTier::Copper.to_u8(), 0);
        assert_eq!(MasternodeTier::Silver.to_u8(), 1);
        assert_eq!(MasternodeTier::Gold.to_u8(), 2);
        assert_eq!(MasternodeTier::Platinum.to_u8(), 3);
        assert_eq!(MasternodeTier::Diamond.to_u8(), 4);
        assert_eq!(MasternodeTier::Invalid.to_u8(), 255);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", MasternodeTier::Copper), "COPPER");
        assert_eq!(format!("{}", MasternodeTier::Silver), "SILVER");
        assert_eq!(format!("{}", MasternodeTier::Gold), "GOLD");
        assert_eq!(format!("{}", MasternodeTier::Platinum), "PLATINUM");
        assert_eq!(format!("{}", MasternodeTier::Diamond), "DIAMOND");
        assert_eq!(format!("{}", MasternodeTier::Invalid), "INVALID");
    }

    #[test]
    fn test_default() {
        assert_eq!(MasternodeTier::default(), MasternodeTier::Invalid);
    }

    #[test]
    fn test_all_tiers_constant() {
        assert_eq!(MASTERNODE_TIERS.len(), 5);
        assert_eq!(MASTERNODE_TIERS[0], MasternodeTier::Copper);
        assert_eq!(MASTERNODE_TIERS[1], MasternodeTier::Silver);
        assert_eq!(MASTERNODE_TIERS[2], MasternodeTier::Gold);
        assert_eq!(MASTERNODE_TIERS[3], MasternodeTier::Platinum);
        assert_eq!(MASTERNODE_TIERS[4], MasternodeTier::Diamond);
    }

    #[test]
    fn test_tier_invalid_constant() {
        assert_eq!(TIER_INVALID, MasternodeTier::Invalid);
    }

    // ============================================================
    // MISSING TIER VALIDATION TESTS
    // ============================================================

    #[test]
    fn test_from_collateral_invalid_150k_divi() {
        // 150k DIVI is between Copper (100k) and Silver (300k) — must be Invalid
        let amount_150k = 150_000i64 * 100_000_000;
        assert_eq!(
            MasternodeTier::from_collateral(amount_150k),
            MasternodeTier::Invalid
        );
    }

    #[test]
    fn test_from_collateral_invalid_50k_divi() {
        // 50k DIVI is below Copper (100k) — must be Invalid
        let amount_50k = 50_000i64 * 100_000_000;
        assert_eq!(
            MasternodeTier::from_collateral(amount_50k),
            MasternodeTier::Invalid
        );
    }

    #[test]
    fn test_from_collateral_invalid_zero() {
        assert_eq!(MasternodeTier::from_collateral(0), MasternodeTier::Invalid);
    }

    #[test]
    fn test_from_collateral_invalid_negative() {
        assert_eq!(MasternodeTier::from_collateral(-1), MasternodeTier::Invalid);
    }

    #[test]
    fn test_from_collateral_invalid_between_silver_and_gold() {
        // 500k DIVI is between Silver (300k) and Gold (1M) — must be Invalid
        let amount_500k = 500_000i64 * 100_000_000;
        assert_eq!(
            MasternodeTier::from_collateral(amount_500k),
            MasternodeTier::Invalid
        );
    }

    #[test]
    fn test_from_collateral_invalid_between_gold_and_platinum() {
        // 2M DIVI is between Gold (1M) and Platinum (3M) — must be Invalid
        let amount_2m = 2_000_000i64 * 100_000_000;
        assert_eq!(
            MasternodeTier::from_collateral(amount_2m),
            MasternodeTier::Invalid
        );
    }

    #[test]
    fn test_from_collateral_invalid_between_platinum_and_diamond() {
        // 5M DIVI is between Platinum (3M) and Diamond (10M) — must be Invalid
        let amount_5m = 5_000_000i64 * 100_000_000;
        assert_eq!(
            MasternodeTier::from_collateral(amount_5m),
            MasternodeTier::Invalid
        );
    }

    #[test]
    fn test_from_collateral_invalid_above_diamond() {
        // 20M DIVI is above Diamond (10M) — must be Invalid
        let amount_20m = 20_000_000i64 * 100_000_000;
        assert_eq!(
            MasternodeTier::from_collateral(amount_20m),
            MasternodeTier::Invalid
        );
    }

    #[test]
    fn test_five_valid_tiers_only() {
        // Exactly 5 valid tiers exist
        assert_eq!(MASTERNODE_TIERS.len(), 5);
        // All 5 are distinct
        let tier_amounts: Vec<i64> = MASTERNODE_TIERS
            .iter()
            .map(|t| t.collateral_amount())
            .collect();
        let unique: std::collections::HashSet<i64> = tier_amounts.into_iter().collect();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn test_tier_collateral_amounts_are_correct_divi_amounts() {
        // Verify collateral amounts match expected DIVI values from the spec
        assert_eq!(
            MasternodeTier::Copper.collateral_amount(),
            100_000i64 * 100_000_000
        );
        assert_eq!(
            MasternodeTier::Silver.collateral_amount(),
            300_000i64 * 100_000_000
        );
        assert_eq!(
            MasternodeTier::Gold.collateral_amount(),
            1_000_000i64 * 100_000_000
        );
        assert_eq!(
            MasternodeTier::Platinum.collateral_amount(),
            3_000_000i64 * 100_000_000
        );
        assert_eq!(
            MasternodeTier::Diamond.collateral_amount(),
            10_000_000i64 * 100_000_000
        );
    }

    #[test]
    fn test_tier_roundtrip_u8() {
        // All valid tiers survive u8 roundtrip
        for tier in &MASTERNODE_TIERS {
            let as_u8 = tier.to_u8();
            let back = MasternodeTier::from_u8(as_u8);
            assert_eq!(*tier, back);
        }
    }

    #[test]
    fn test_collateral_amount_satoshis() {
        // Verify u64 version matches i64 version
        assert_eq!(
            MasternodeTier::Copper.collateral_amount_satoshis(),
            10_000_000_000_000
        );
        assert_eq!(
            MasternodeTier::Silver.collateral_amount_satoshis(),
            30_000_000_000_000
        );
        assert_eq!(
            MasternodeTier::Gold.collateral_amount_satoshis(),
            100_000_000_000_000
        );
        assert_eq!(
            MasternodeTier::Platinum.collateral_amount_satoshis(),
            300_000_000_000_000
        );
        assert_eq!(
            MasternodeTier::Diamond.collateral_amount_satoshis(),
            1_000_000_000_000_000
        );
        assert_eq!(MasternodeTier::Invalid.collateral_amount_satoshis(), 0);

        // Verify they match the i64 versions
        assert_eq!(
            MasternodeTier::Copper.collateral_amount_satoshis(),
            MasternodeTier::Copper.collateral_amount() as u64
        );
        assert_eq!(
            MasternodeTier::Diamond.collateral_amount_satoshis(),
            MasternodeTier::Diamond.collateral_amount() as u64
        );
    }
}
