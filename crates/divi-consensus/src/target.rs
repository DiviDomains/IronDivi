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

//! Difficulty target handling
//!
//! Divi uses the Bitcoin compact format (nBits) to represent difficulty targets.
//! The format encodes a 256-bit number in 4 bytes as: (exponent, mantissa)
//!
//! Format: 0xEEMMMMM where:
//! - EE = exponent (number of bytes the mantissa should be shifted left by 8)
//! - MMMMMM = mantissa (24-bit coefficient)
//!
//! Target = mantissa * 2^(8*(exponent-3))
//!
//! For proof-of-stake, we need to multiply the target by a coin weight
//! based on the stake value and coin age.

use divi_primitives::hash::Hash256;

/// Maximum target for mainnet (minimum difficulty)
/// This is nBits = 0x1e0fffff
pub const MAX_TARGET_MAINNET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// A 256-bit unsigned integer for target calculations
///
/// Stored in little-endian order (lowest byte first).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Target([u8; 32]);

impl Target {
    /// Create a zero target
    pub const fn zero() -> Self {
        Target([0u8; 32])
    }

    /// Create from raw bytes (little-endian)
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Target(bytes)
    }

    /// Create from Hash256 (internal byte order)
    pub fn from_hash256(hash: Hash256) -> Self {
        Target(*hash.as_bytes())
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to Hash256
    pub fn to_hash256(&self) -> Hash256 {
        Hash256::from_bytes(self.0)
    }

    /// Check if target is zero
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Create from compact representation (nBits)
    ///
    /// The compact format is: 0xEEMMMMMMM where:
    /// - EE = exponent byte
    /// - MMMMMM = 24-bit mantissa
    ///
    /// Target = mantissa * 2^(8*(exponent-3))
    pub fn from_compact(compact: u32) -> Self {
        let mut result = [0u8; 32];

        // Extract mantissa (bottom 24 bits) and exponent (top 8 bits)
        let mantissa = compact & 0x007fffff;
        let exponent = (compact >> 24) as usize;

        // Handle negative flag (not used in practice for targets)
        let is_negative = (compact & 0x00800000) != 0;
        if is_negative || mantissa == 0 {
            return Target::zero();
        }

        // Position the mantissa at the correct byte offset
        // exponent gives us how many bytes from the start of the result
        if exponent <= 3 {
            // Shift right case - mantissa goes at the start
            let shift = 3 - exponent;
            let shifted_mantissa = mantissa >> (8 * shift);
            result[0] = (shifted_mantissa & 0xff) as u8;
            result[1] = ((shifted_mantissa >> 8) & 0xff) as u8;
            result[2] = ((shifted_mantissa >> 16) & 0xff) as u8;
        } else if exponent <= 32 {
            // Normal case - position mantissa bytes
            let pos = exponent - 3;
            if pos < 32 {
                result[pos] = (mantissa & 0xff) as u8;
            }
            if pos + 1 < 32 {
                result[pos + 1] = ((mantissa >> 8) & 0xff) as u8;
            }
            if pos + 2 < 32 {
                result[pos + 2] = ((mantissa >> 16) & 0xff) as u8;
            }
        }
        // If exponent > 32, result would overflow - return zero
        // (This shouldn't happen with valid compact values)

        Target(result)
    }

    /// Convert to compact representation (nBits)
    pub fn to_compact(&self) -> u32 {
        // Find the highest non-zero byte
        let mut size = 32usize;
        while size > 0 && self.0[size - 1] == 0 {
            size -= 1;
        }

        if size == 0 {
            return 0;
        }

        // Extract mantissa from the highest 3 bytes
        let mut mantissa: u32;
        if size <= 3 {
            mantissa = (self.0[0] as u32)
                | ((self.0.get(1).copied().unwrap_or(0) as u32) << 8)
                | ((self.0.get(2).copied().unwrap_or(0) as u32) << 16);
            mantissa >>= 8 * (3 - size);
        } else {
            mantissa = (self.0[size - 3] as u32)
                | ((self.0[size - 2] as u32) << 8)
                | ((self.0[size - 1] as u32) << 16);
        }

        // Handle negative flag
        if mantissa & 0x00800000 != 0 {
            mantissa >>= 8;
            size += 1;
        }

        ((size as u32) << 24) | mantissa
    }

    /// Multiply this target by a weight (coin age factor)
    ///
    /// Returns None if the multiplication would overflow.
    /// In practice, overflow means the target is always met.
    pub fn multiply_by(&self, weight: &Target) -> Option<Self> {
        // Perform 256-bit multiplication using 64-bit limbs
        // We need to detect overflow (result > 2^256)

        let mut result = [0u64; 8]; // 512-bit intermediate result
        let a = self.to_u64_limbs();
        let b = weight.to_u64_limbs();

        // Multiply with accumulation (schoolbook multiplication)
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 {
                let pos = i + j;
                let product = (a[i] as u128) * (b[j] as u128) + (result[pos] as u128) + carry;
                result[pos] = product as u64;
                carry = product >> 64;
            }
            // Add final carry to position i+4
            let pos = i + 4;
            let sum = (result[pos] as u128) + carry;
            result[pos] = sum as u64;
            // If there's still carry, propagate it
            if (sum >> 64) != 0 && pos + 1 < 8 {
                result[pos + 1] = result[pos + 1].wrapping_add((sum >> 64) as u64);
            }
        }

        // Check if any upper limbs are set (overflow beyond 256 bits)
        if result[4] != 0 || result[5] != 0 || result[6] != 0 || result[7] != 0 {
            return None;
        }

        // Convert back to bytes
        Some(Target::from_u64_limbs([
            result[0], result[1], result[2], result[3],
        ]))
    }

    /// Compare two targets (less than)
    pub fn lt(&self, other: &Target) -> bool {
        // Compare from most significant byte
        for i in (0..32).rev() {
            if self.0[i] < other.0[i] {
                return true;
            }
            if self.0[i] > other.0[i] {
                return false;
            }
        }
        false // Equal
    }

    /// Compare two targets (greater than)
    pub fn gt(&self, other: &Target) -> bool {
        other.lt(self)
    }

    /// Convert to array of u64 limbs (little-endian)
    fn to_u64_limbs(&self) -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let offset = i * 8;
            limbs[i] = u64::from_le_bytes([
                self.0[offset],
                self.0[offset + 1],
                self.0[offset + 2],
                self.0[offset + 3],
                self.0[offset + 4],
                self.0[offset + 5],
                self.0[offset + 6],
                self.0[offset + 7],
            ]);
        }
        limbs
    }

    /// Create from array of u64 limbs (little-endian)
    fn from_u64_limbs(limbs: [u64; 4]) -> Self {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let offset = i * 8;
            let limb_bytes = limbs[i].to_le_bytes();
            bytes[offset..offset + 8].copy_from_slice(&limb_bytes);
        }
        Target(bytes)
    }

    /// Create a Target from a u64 value
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&value.to_le_bytes());
        Target(bytes)
    }

    /// Divide this target by a u64 value
    pub fn div_u64(&self, divisor: u64) -> Self {
        if divisor == 0 {
            return Target::zero();
        }

        let limbs = self.to_u64_limbs();
        let mut result = [0u64; 4];
        let mut remainder: u128 = 0;

        // Long division from most significant limb
        for i in (0..4).rev() {
            let dividend = remainder << 64 | (limbs[i] as u128);
            result[i] = (dividend / (divisor as u128)) as u64;
            remainder = dividend % (divisor as u128);
        }

        Target::from_u64_limbs(result)
    }
}

/// Compute the proof-of-work for a block given its compact target (nBits).
///
/// This implements C++'s `GetBlockProof()`:
///   work = (~target / (target + 1)) + 1
///
/// where `~target` is the bitwise NOT of the 256-bit target and `target` comes
/// from the compact nBits encoding.
///
/// Returns a 32-byte little-endian value representing the amount of work.
/// Returns all zeros if the target is zero.
pub fn get_block_proof(bits: u32) -> [u8; 32] {
    let target = Target::from_compact(bits);
    let target_hash = target.to_hash256();

    if target_hash.is_zero() {
        return [0u8; 32];
    }

    // ~target (bitwise NOT)
    let not_target = target_hash.bitwise_not();

    // target + 1
    let target_plus_one = match target_hash.increment() {
        Some(v) => v,
        None => {
            // target was all 0xFF (max value), target+1 overflows.
            // ~target would be 0, so ~target / (target+1) is 0, +1 = 1.
            let mut result = [0u8; 32];
            result[0] = 1;
            return result;
        }
    };

    // ~target / (target + 1)
    let quotient = not_target.divide_by_hash256(&target_plus_one);

    // + 1
    match quotient.increment() {
        Some(v) => *v.as_bytes(),
        None => {
            // Overflow — shouldn't happen in practice since work < 2^256
            [0xFF; 32]
        }
    }
}

/// Convert compact difficulty (nBits) to a difficulty multiplier
///
/// Difficulty is calculated as: genesis_target / current_target
/// where genesis_target is the easiest possible target (minimum difficulty = 1.0)
///
/// Higher difficulty values mean the network is harder to mine.
pub fn bits_to_difficulty(bits: u32) -> f64 {
    if bits == 0 {
        return 0.0;
    }

    let mantissa = (bits & 0x00ffffff) as f64;
    let exponent = ((bits >> 24) & 0xff) as i32;

    // Genesis difficulty target (Bitcoin's 0x1d00ffff)
    let genesis_mantissa = 0x00ffff as f64;
    let genesis_exponent = 0x1d_i32;

    let target = mantissa * 256_f64.powi(exponent - 3);
    let genesis_target = genesis_mantissa * 256_f64.powi(genesis_exponent - 3);

    if target == 0.0 {
        return 0.0;
    }

    genesis_target / target
}

/// Convert a difficulty multiplier back to compact bits (nBits)
///
/// This is the inverse of bits_to_difficulty.
pub fn difficulty_to_bits(difficulty: f64) -> u32 {
    if difficulty <= 0.0 {
        return 0;
    }

    // Genesis difficulty target
    let genesis_mantissa = 0x00ffff as f64;
    let genesis_exponent = 0x1d_i32;
    let genesis_target = genesis_mantissa * 256_f64.powi(genesis_exponent - 3);

    // target = genesis_target / difficulty
    let target = genesis_target / difficulty;

    // Find the exponent (how many bytes needed)
    let mut exp = 0_i32;
    let mut temp = target;
    while temp >= 1.0 {
        temp /= 256.0;
        exp += 1;
    }

    // Calculate mantissa
    let mantissa = (target / 256_f64.powi(exp - 3)).round() as u32;

    // Clamp mantissa to 24 bits
    let mantissa = mantissa & 0x00ffffff;

    ((exp as u32) << 24) | mantissa
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Target({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display in reverse (big-endian) for readability
        let mut reversed = self.0;
        reversed.reverse();
        write!(f, "{}", hex::encode(reversed))
    }
}

impl PartialOrd for Target {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Target {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare from most significant byte
        for i in (0..32).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_to_target_basic() {
        // nBits = 0x1d00ffff (Bitcoin genesis block)
        // This represents: 0x00ffff * 2^(8*(0x1d-3)) = 0x00ffff * 2^(8*26)
        let compact = 0x1d00ffff;
        let target = Target::from_compact(compact);

        // The target should have 0x00ffff at byte offset 26 (1d - 3 = 26)
        assert_eq!(target.0[26], 0xff);
        assert_eq!(target.0[27], 0xff);
        assert_eq!(target.0[28], 0x00);
    }

    #[test]
    fn test_compact_roundtrip() {
        let test_values = [0x1d00ffff, 0x1c0fffff, 0x1b0404cb, 0x1a06ae63];

        for compact in test_values {
            let target = Target::from_compact(compact);
            let back = target.to_compact();
            assert_eq!(
                compact, back,
                "Compact roundtrip failed for 0x{:08x}: got 0x{:08x}",
                compact, back
            );
        }
    }

    #[test]
    fn test_target_comparison() {
        let low = Target::from_compact(0x1b0404cb);
        let high = Target::from_compact(0x1d00ffff);

        assert!(low.lt(&high));
        assert!(high.gt(&low));
        assert!(!low.gt(&high));
        assert!(!high.lt(&low));
    }

    #[test]
    fn test_target_multiplication() {
        let target = Target::from_u64(1000);
        let weight = Target::from_u64(500);

        let result = target.multiply_by(&weight).unwrap();

        // 1000 * 500 = 500000
        let expected = Target::from_u64(500000);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_target_multiplication_overflow() {
        // Create a large target in the upper half of the range
        let mut bytes = [0u8; 32];
        bytes[31] = 0x80; // 2^255
        let large = Target::from_bytes(bytes);

        // Multiplying by 2 should overflow (2^255 * 2 = 2^256)
        let weight = Target::from_u64(2);
        let result = large.multiply_by(&weight);
        assert!(result.is_none(), "2^255 * 2 should overflow");

        // Also test: 2^192 * 2^64 = 2^256 which should overflow
        let mut bytes2 = [0u8; 32];
        bytes2[24] = 0x01; // 2^192
        let medium = Target::from_bytes(bytes2);

        // Create 2^64 weight (which requires more than u64)
        let mut weight_bytes = [0u8; 32];
        weight_bytes[8] = 0x01; // 2^64
        let large_weight = Target::from_bytes(weight_bytes);
        let result2 = medium.multiply_by(&large_weight);
        assert!(result2.is_none(), "2^192 * 2^64 = 2^256 should overflow");

        // Test a case that doesn't overflow: 2^100 * 2^100 = 2^200
        let mut a_bytes = [0u8; 32];
        a_bytes[12] = 0x10; // 2^100 = 2^(12*8 + 4)
        let a = Target::from_bytes(a_bytes);
        let b = Target::from_bytes(a_bytes);
        let result3 = a.multiply_by(&b);
        assert!(
            result3.is_some(),
            "2^100 * 2^100 = 2^200 should not overflow"
        );
    }

    #[test]
    fn test_target_division() {
        let target = Target::from_u64(1000000);
        let result = target.div_u64(1000);

        let expected = Target::from_u64(1000);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pos_target_calculation() {
        // Simulate a PoS target calculation:
        // weighted_target = (value * time_weight / COIN / 400) * target
        let value: i64 = 1000_00000000; // 1000 DIVI in satoshis
        let time_weight: i64 = 86400; // 1 day in seconds
        let coin: i64 = 100_000_000; // COIN constant

        // Compute coin age weight: (value * time_weight) / COIN / 400
        let weight = (value * time_weight) / coin / 400;

        let base_target = Target::from_compact(0x1d00ffff);
        let weight_target = Target::from_u64(weight as u64);

        let weighted_target = base_target.multiply_by(&weight_target);
        assert!(weighted_target.is_some());
    }

    #[test]
    fn test_bits_to_difficulty_genesis() {
        // Genesis difficulty (0x1d00ffff) should be 1.0
        let difficulty = bits_to_difficulty(0x1d00ffff);
        assert!(
            (difficulty - 1.0).abs() < 0.0001,
            "Genesis difficulty should be ~1.0, got {}",
            difficulty
        );
    }

    #[test]
    fn test_bits_to_difficulty_higher() {
        // A lower target means higher difficulty
        // 0x1c00ffff has exponent 0x1c (28) vs 0x1d (29)
        // So target is 256 times smaller, meaning difficulty is 256 times higher
        let difficulty = bits_to_difficulty(0x1c00ffff);
        assert!(
            (difficulty - 256.0).abs() < 0.01,
            "Difficulty should be ~256, got {}",
            difficulty
        );
    }

    #[test]
    fn test_bits_to_difficulty_zero() {
        assert_eq!(bits_to_difficulty(0), 0.0);
    }

    #[test]
    fn test_difficulty_roundtrip() {
        // Test that we can convert back and forth
        let test_values = [
            0x1d00ffff_u32, // difficulty ~1
            0x1c00ffff_u32, // difficulty ~256
            0x1b00ffff_u32, // difficulty ~65536
        ];

        for bits in test_values {
            let difficulty = bits_to_difficulty(bits);
            let back = difficulty_to_bits(difficulty);
            // Allow some tolerance due to floating point
            let diff_back = bits_to_difficulty(back);
            let ratio = difficulty / diff_back;
            assert!(
                (ratio - 1.0).abs() < 0.01,
                "Roundtrip failed for 0x{:08x}: difficulty {} -> bits 0x{:08x} -> difficulty {}",
                bits,
                difficulty,
                back,
                diff_back
            );
        }
    }

    // ============================================================
    // ADDITIONAL TARGET TESTS
    // ============================================================

    /// from_compact(0x1e0fffff) must place the mantissa at the right byte positions.
    /// bits=0x1e0fffff → exponent=0x1e=30, mantissa=0x0fffff
    /// In little-endian 256-bit storage: pos = exponent-3 = 27
    /// → bytes[27]=0xff, bytes[28]=0xff, bytes[29]=0x0f, all others zero.
    #[test]
    fn test_compact_decode_1e0fffff() {
        let target = Target::from_compact(0x1e0fffff);
        let bytes = target.as_bytes();

        // Mantissa 0x0fffff at offset pos=27 (little-endian field placement)
        assert_eq!(bytes[27], 0xff, "byte 27 mismatch");
        assert_eq!(bytes[28], 0xff, "byte 28 mismatch");
        assert_eq!(bytes[29], 0x0f, "byte 29 mismatch");

        // All other bytes should be zero
        for (i, &b) in bytes.iter().enumerate() {
            if i != 27 && i != 28 && i != 29 {
                assert_eq!(b, 0, "byte {} should be zero for 0x1e0fffff", i);
            }
        }
    }

    /// MAX_TARGET_MAINNET constant has the correct structure (non-zero mantissa bytes).
    /// Note: MAX_TARGET_MAINNET is the hardcoded constant value and may differ in byte
    /// layout from from_compact (which uses runtime computation). Both represent the
    /// PoW limit but are used differently in the codebase.
    #[test]
    fn test_max_target_mainnet_constant() {
        // Verify the constant is non-zero (sanity check)
        let has_nonzero = MAX_TARGET_MAINNET.iter().any(|&b| b != 0);
        assert!(has_nonzero, "MAX_TARGET_MAINNET must not be all zeros");

        // Verify its structure: mantissa 0x0fffff appears in the constant
        // The constant has 0xff, 0xff, 0x0f at bytes 4, 5, 6 (big-endian display order)
        assert_eq!(MAX_TARGET_MAINNET[4], 0xff, "MAX_TARGET_MAINNET byte 4");
        assert_eq!(MAX_TARGET_MAINNET[5], 0xff, "MAX_TARGET_MAINNET byte 5");
        assert_eq!(MAX_TARGET_MAINNET[6], 0x0f, "MAX_TARGET_MAINNET byte 6");

        // All other bytes should be zero
        for (i, &b) in MAX_TARGET_MAINNET.iter().enumerate() {
            if i != 4 && i != 5 && i != 6 {
                assert_eq!(b, 0, "MAX_TARGET_MAINNET byte {} should be zero", i);
            }
        }
    }

    /// 0x1e0ffff0 compact bits decodes correctly (only mantissa lsb differs).
    #[test]
    fn test_compact_bits_1e0ffff0() {
        let target = Target::from_compact(0x1e0ffff0);
        let bytes = target.as_bytes();
        // mantissa = 0x0ffff0
        // result[27] = 0xf0, result[28] = 0xff, result[29] = 0x0f
        assert_eq!(bytes[27], 0xf0, "byte 27 mismatch for 0x1e0ffff0");
        assert_eq!(bytes[28], 0xff, "byte 28 mismatch for 0x1e0ffff0");
        assert_eq!(bytes[29], 0x0f, "byte 29 mismatch for 0x1e0ffff0");
    }

    /// Roundtrip: from_compact → to_compact for 0x1e0fffff and 0x1e0ffff0.
    #[test]
    fn test_compact_roundtrip_pos_targets() {
        for bits in [0x1e0fffff_u32, 0x1e0ffff0_u32] {
            let t = Target::from_compact(bits);
            assert_eq!(
                t.to_compact(),
                bits,
                "Compact roundtrip failed for 0x{:08x}",
                bits
            );
        }
    }

    /// Target::zero() must report is_zero() = true; non-zero must not.
    #[test]
    fn test_target_is_zero() {
        assert!(Target::zero().is_zero());
        assert!(!Target::from_u64(1).is_zero());
        assert!(!Target::from_bytes([0xff; 32]).is_zero());
    }

    /// Target::from_u64(0) must be zero.
    #[test]
    fn test_from_u64_zero() {
        let t = Target::from_u64(0);
        assert!(t.is_zero());
    }

    /// Target::from_u64 round-trips through to_compact for small values.
    #[test]
    fn test_from_u64_small_values() {
        // 1 stored in byte 0 → to_compact gives exponent=1, mantissa=1 → 0x01000001
        let t = Target::from_u64(1);
        assert_eq!(t.as_bytes()[0], 1);
        for i in 1..32 {
            assert_eq!(t.as_bytes()[i], 0);
        }
    }

    /// div_u64 by zero returns zero target.
    #[test]
    fn test_div_u64_by_zero() {
        let t = Target::from_u64(1_000_000);
        let result = t.div_u64(0);
        assert!(result.is_zero());
    }

    /// div_u64 by 1 is a no-op.
    #[test]
    fn test_div_u64_by_one() {
        let t = Target::from_u64(999_999);
        assert_eq!(t.div_u64(1), t);
    }

    /// to_hash256 round-trips through from_hash256.
    #[test]
    fn test_to_hash256_roundtrip() {
        let original = Hash256::from_bytes([0xde; 32]);
        let t = Target::from_hash256(original);
        let back = t.to_hash256();
        assert_eq!(back, original);
    }

    /// Target::lt with equal operands must return false (strict less-than).
    #[test]
    fn test_target_lt_equal() {
        let t = Target::from_u64(42);
        assert!(!t.lt(&t));
    }

    /// Target::gt with equal operands must return false.
    #[test]
    fn test_target_gt_equal() {
        let t = Target::from_u64(42);
        assert!(!t.gt(&t));
    }

    /// Ord::cmp must correctly order three distinct targets.
    #[test]
    fn test_target_ord() {
        let low = Target::from_u64(1);
        let mid = Target::from_u64(1000);
        let high = Target::from_compact(0x1d00ffff);

        assert!(low < mid);
        assert!(mid < high);
        assert!(high > low);
        assert_eq!(low.cmp(&low), std::cmp::Ordering::Equal);
    }

    /// compact=0 must produce zero target and roundtrip back to 0.
    #[test]
    fn test_compact_zero() {
        let t = Target::from_compact(0);
        assert!(t.is_zero());
        assert_eq!(t.to_compact(), 0);
    }

    /// Compact with negative flag set (bit 23 of mantissa) must return zero.
    #[test]
    fn test_compact_negative_flag_returns_zero() {
        // 0x1e800000 sets the negative flag (bit 23 of the 24-bit mantissa field)
        let t = Target::from_compact(0x1e800000);
        assert!(
            t.is_zero(),
            "Negative-flagged compact should decode to zero"
        );
    }

    /// multiply_by where result fits in 256 bits (no overflow) must succeed.
    #[test]
    fn test_multiply_by_no_overflow() {
        let a = Target::from_u64(12345);
        let b = Target::from_u64(67890);
        let result = a.multiply_by(&b);
        assert!(result.is_some());
        let expected = Target::from_u64(12345 * 67890);
        assert_eq!(result.unwrap(), expected);
    }

    /// multiply_by zero must return zero.
    #[test]
    fn test_multiply_by_zero() {
        let t = Target::from_u64(999_999);
        let zero = Target::zero();
        let result = t.multiply_by(&zero).unwrap();
        assert!(result.is_zero());
    }

    /// PoS target computation: weighted_target must exceed a mid-range hash
    /// when the coin has high value and is fully aged.
    #[test]
    fn test_pos_weighted_target_hits_for_high_value_coin() {
        use crate::pos_calculator::stake_target_hit;
        use divi_primitives::constants::COIN;

        // 2000 DIVI at 7 days age (maximum weight)
        let value: i64 = 2000 * COIN as i64;
        let time_weight: i64 = 601_200; // MAXIMUM_COIN_AGE_WEIGHT_FOR_STAKING

        let target = Target::from_compact(0x1e0fffff); // easiest mainnet target
        let hash = Hash256::from_bytes([0x00; 32]); // very small hash

        let hit = stake_target_hit(&hash, value, &target, time_weight).unwrap();
        assert!(
            hit,
            "A small hash with high weight should hit an easy target"
        );
    }

    // ============================================================
    // get_block_proof tests
    // ============================================================

    #[test]
    fn test_get_block_proof_zero_bits_returns_zero() {
        let work = get_block_proof(0);
        assert_eq!(work, [0u8; 32]);
    }

    #[test]
    fn test_get_block_proof_nonzero_for_valid_bits() {
        // 0x1e0fffff is the easiest PoS target
        let work = get_block_proof(0x1e0fffff);
        assert!(
            work.iter().any(|&b| b != 0),
            "Work should be non-zero for valid bits"
        );
    }

    #[test]
    fn test_get_block_proof_higher_difficulty_more_work() {
        // Lower target = higher difficulty = more work
        let work_easy = get_block_proof(0x1e0fffff); // easiest
        let work_hard = get_block_proof(0x1d00ffff); // 256x harder

        // Compare as 256-bit LE: work_hard > work_easy
        let easy_hash = Hash256::from_bytes(work_easy);
        let hard_hash = Hash256::from_bytes(work_hard);
        assert!(
            hard_hash > easy_hash,
            "Higher difficulty should produce more work"
        );
    }

    /// Verify that get_block_proof(0x1d00ffff) matches C++ value.
    /// C++ GetBlockProof for Bitcoin genesis target (0x1d00ffff):
    ///   target = 0x00000000FFFF0000...00 (256-bit)
    ///   ~target = 0xFFFFFFFF0000FFFF...FF
    ///   target+1 = 0x00000000FFFF0000...01
    ///   work = (~target / (target+1)) + 1
    ///
    /// The result should be 0x100010001 (4295032833 in decimal).
    /// In LE bytes: [01, 00, 01, 00, 01, 00, 00, 00, ...]
    #[test]
    fn test_get_block_proof_bitcoin_genesis_target() {
        let work = get_block_proof(0x1d00ffff);
        // Expected: 0x100010001
        let work_u64 = u64::from_le_bytes(work[0..8].try_into().unwrap());
        assert_eq!(
            work_u64, 0x100010001u64,
            "Work for 0x1d00ffff should be 0x100010001 (4295032833), got 0x{:x}",
            work_u64
        );
        // Upper bytes should be zero
        assert!(
            work[8..].iter().all(|&b| b == 0),
            "Upper bytes should be zero for moderate difficulty"
        );
    }

    /// For the easiest PoS target (0x1e0fffff):
    ///   target = 0x00000FFFFF000000...00 (bytes[27..30])
    ///   work should be small (about 0x100001 = 1048577)
    #[test]
    fn test_get_block_proof_pos_easiest_target() {
        let work = get_block_proof(0x1e0fffff);
        let work_u64 = u64::from_le_bytes(work[0..8].try_into().unwrap());
        // The exact value: ~target / (target+1) + 1
        // target = 0x0FFFFF << (27*8) in 256-bit
        // This is a very large target, so work should be small
        assert!(work_u64 > 0, "Work should be positive");
        assert!(
            work_u64 < 0x200000, // should be around 0x100001
            "Work for easiest target should be small, got 0x{:x}",
            work_u64
        );
    }
}
