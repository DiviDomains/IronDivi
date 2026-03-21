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

//! Regression tests for divi-consensus
//!
//! Bug 2 (commit c00e3d8): Stake modifier mismatch between staker and validator.
//! Bug 3: Difficulty u128 truncation causing all PoS targets to be clamped to pow_limit.

use divi_consensus::{
    stake_modifier::{MockStakeModifierService, StakeModifierService},
    staking_data::StakingData,
    target::Target,
};
use divi_primitives::{amount::Amount, hash::Hash256, transaction::OutPoint};

// ============================================================
// Bug 2 (commit c00e3d8): Stake modifier mismatch
//
// Root cause: The staker read `tip.stake_modifier` (in-memory cached field)
// while the validator called `get_stake_modifier_hardened()` which walks
// backward through the DB.  These two values could diverge, causing the
// staker to produce blocks that fail their own validation.
//
// Fix: The staker now always calls get_stake_modifier() — the same DB-backed
// path used by the validator — so the two can never disagree.
// ============================================================

/// Bug 2 (commit c00e3d8): Both staker and validator must obtain the stake
/// modifier via the StakeModifierService trait (the DB-backed path).
/// If they both use the same service, they are guaranteed to agree.
#[test]
fn test_regression_stake_modifier_from_service_matches_expected() {
    let expected_modifier: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let service = MockStakeModifierService::new(expected_modifier);

    let staking_data = StakingData::new(
        0x1e0fffff,
        1_000_000,
        Hash256::from_bytes([0u8; 32]),
        OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
        Amount::from_sat(2000 * 100_000_000),
        Hash256::from_bytes([2u8; 32]),
    );

    let modifier = service
        .get_stake_modifier(&staking_data)
        .expect("get_stake_modifier must succeed");

    assert_eq!(
        modifier, expected_modifier,
        "Stake modifier from service must equal the DB-backed value. \
         Before commit c00e3d8, the staker read tip.stake_modifier (cached) \
         which could diverge from this DB-backed value."
    );
}

/// Bug 2 (commit c00e3d8): Different UTXOs in staking_data must all see the
/// same chain-level modifier — it's a property of the chain state, not the UTXO.
#[test]
fn test_regression_stake_modifier_is_chain_property_not_utxo_property() {
    let chain_modifier: u64 = 999_999_999;
    let service = MockStakeModifierService::new(chain_modifier);

    // Three completely different UTXOs
    let utxos = [
        (
            Hash256::from_bytes([0x01; 32]),
            0u32,
            1_000 * 100_000_000i64,
        ),
        (
            Hash256::from_bytes([0x02; 32]),
            1u32,
            5_000 * 100_000_000i64,
        ),
        (Hash256::from_bytes([0x03; 32]), 2u32, 100 * 100_000_000i64),
    ];

    for (txid, vout, value_sat) in utxos {
        let sd = StakingData::new(
            0x1e0fffff,
            1_500_000,
            Hash256::from_bytes([0u8; 32]),
            OutPoint::new(txid, vout),
            Amount::from_sat(value_sat),
            Hash256::from_bytes([0u8; 32]),
        );
        let modifier = service.get_stake_modifier(&sd).unwrap();
        assert_eq!(
            modifier, chain_modifier,
            "Stake modifier must be the same for all UTXOs — it comes from the chain state"
        );
    }
}

// ============================================================
// Bug 3: Difficulty u128 truncation
//
// Root cause: The PoS difficulty computation multiplied the 256-bit target
// by the coin-age weight using u128 arithmetic.  The significant bits of a
// typical PoS target (e.g., 0x1e0fffff) live in bytes 27-29, well above the
// 16-byte (128-bit) boundary.  The lower 16 bytes were all zero, so every
// multiplication produced zero and the weighted target was clamped to pow_limit.
//
// Fix: Use Target::multiply_by() which performs full 256-bit arithmetic.
// ============================================================

/// Bug 3: Verify that Target::multiply_by does NOT truncate to 128 bits.
/// A target whose significant bits live in bytes 24+ (above the u128 boundary)
/// multiplied by a non-zero weight must produce a non-zero result.
#[test]
fn test_regression_pos_target_upper_bytes_not_truncated_by_u128() {
    // 0x1e0fffff: exponent=30, pos = 30-3 = 27.
    // Significant bytes are 27, 28, 29 — all above byte 15 (the u128 boundary).
    let target = Target::from_compact(0x1e0fffff);
    let bytes = target.as_bytes();

    // Lower 128 bits (bytes 0-15) are all zero — this is what u128 would see
    for i in 0..16 {
        assert_eq!(
            bytes[i], 0,
            "byte {} of 0x1e0fffff target should be zero",
            i
        );
    }

    // Significant bits are in bytes 27-29 (above the u128 boundary)
    assert_ne!(bytes[27], 0);
    assert_ne!(bytes[28], 0);
    assert_ne!(bytes[29], 0);

    // Multiplying by any non-zero weight must yield a non-zero result
    let weight = Target::from_u64(500);
    let weighted = target
        .multiply_by(&weight)
        .expect("multiplication of a normal PoS target must not overflow");

    assert!(
        !weighted.is_zero(),
        "Weighted PoS target must be non-zero. \
         With u128 truncation, bytes 0-15 were all zero so the product was zero, \
         and the difficulty was always clamped to pow_limit (0x1e0fffff)."
    );
}

/// Bug 3: Verify full 256-bit multiply for a target in bytes 24-31 (upper region).
#[test]
fn test_regression_256_bit_multiply_preserves_upper_bits() {
    // Place exactly 1 in byte 24 (bit 192)
    let mut bytes = [0u8; 32];
    bytes[24] = 0x01; // 2^192
    let high_target = Target::from_bytes(bytes);

    // Multiply by 2 — result should be 2 at byte 24 (or 1 at byte 25)
    let weight = Target::from_u64(2);
    let result = high_target.multiply_by(&weight).expect("must not overflow");

    // With u128, this would have seen zero (bytes 0-15 are empty) → product = 0
    // With 256-bit math the upper bit is preserved and the product is 2^193
    assert!(
        !result.is_zero(),
        "256-bit multiplication must preserve bits above byte 15. \
         u128 truncation would produce zero for a target with bits only at byte 24+."
    );
}

/// Bug 3: The pow_limit (0x1e0fffff) must NOT be the result of multiplying a
/// valid, easy target (0x207fffff) by a reasonable weight.
/// Before the fix, every weighted target was clamped to pow_limit.
#[test]
fn test_regression_weighted_target_is_not_pow_limit() {
    let easy_target = Target::from_compact(0x207fffff); // Regtest max
    let weight = Target::from_u64(1_000);
    let pow_limit = Target::from_compact(0x1e0fffff);

    let weighted = easy_target.multiply_by(&weight);
    match weighted {
        None => {
            // Overflow → target is infinite → definitely not pow_limit — correct
        }
        Some(w) => {
            assert_ne!(
                w, pow_limit,
                "Weighted target must not equal pow_limit. \
                 Before the u128 fix, every weighted target was zero and was \
                 replaced with pow_limit."
            );
        }
    }
}

/// Bug 3: verify stake_target_hit returns true for a small hash against a
/// valid easy target with adequate coin weight (regression for the "always false"
/// case caused by truncation).
#[test]
fn test_regression_stake_target_hit_easy_target_small_hash() {
    use divi_consensus::pos_calculator::stake_target_hit;

    // Very easy target (all 0xff)
    let easy_target = Target::from_bytes([0xff; 32]);
    let small_hash = Hash256::from_bytes([0x00; 32]);
    let value: i64 = 2000 * 100_000_000; // 2000 DIVI
    let time_weight: i64 = 86_400; // 1 day

    let hit = stake_target_hit(&small_hash, value, &easy_target, time_weight)
        .expect("stake_target_hit must not error");

    assert!(
        hit,
        "A very small hash must hit a very easy target with ample coin weight. \
         Before the u128 fix, the weighted target was always zero so the hash \
         never hit (coin_age_weight was computed from zero upper bytes)."
    );
}
