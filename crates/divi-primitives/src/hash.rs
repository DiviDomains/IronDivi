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

//! Hash types for Divi
//!
//! - Hash256: 32-byte hash (SHA256d - double SHA256)
//! - Hash160: 20-byte hash (RIPEMD160(SHA256))

use crate::error::Error;
use crate::serialize::{Decodable, Encodable};
use std::fmt;
use std::io::{Read, Write};
use std::str::FromStr;

/// A 256-bit (32-byte) hash
///
/// Stored as raw bytes in memory in little-endian order (byte[0] is least significant).
/// Display shows bytes in reverse order (Bitcoin convention for txids/block hashes).
///
/// IMPORTANT: Comparison operators treat this as a 256-bit little-endian integer,
/// comparing from most significant byte (byte[31]) to least significant (byte[0]).
/// This matches Bitcoin/Divi's uint256 comparison semantics.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
pub struct Hash256(pub [u8; 32]);

impl PartialOrd for Hash256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare as 256-bit little-endian integer: most significant byte first
        // byte[31] is most significant, byte[0] is least significant
        for i in (0..32).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                non_equal => return non_equal,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl Hash256 {
    /// Create a new zero hash
    pub const fn zero() -> Self {
        Hash256([0u8; 32])
    }

    /// Create from raw bytes
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash256(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get the raw bytes as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Convert to little-endian bytes array (for arithmetic operations)
    pub fn to_le_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Check if this is a zero hash
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Create from a hex string (display order - reversed)
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex).map_err(|e| Error::InvalidHex(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(Error::InvalidLength {
                expected: 32,
                got: bytes.len(),
            });
        }

        let mut arr = [0u8; 32];
        // Reverse because display format is reversed
        for (i, &b) in bytes.iter().enumerate() {
            arr[31 - i] = b;
        }
        Ok(Hash256(arr))
    }

    /// Create from raw bytes in hex (internal order - not reversed)
    pub fn from_raw_hex(hex: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex).map_err(|e| Error::InvalidHex(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(Error::InvalidLength {
                expected: 32,
                got: bytes.len(),
            });
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash256(arr))
    }

    /// Convert to hex string (display order - reversed)
    pub fn to_hex(&self) -> String {
        let mut reversed = self.0;
        reversed.reverse();
        hex::encode(reversed)
    }

    /// Convert to raw hex string (internal order - not reversed)
    pub fn to_raw_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from a byte slice (must be exactly 32 bytes)
    ///
    /// # Panics
    /// Panics if slice length is not exactly 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Self {
        assert!(
            slice.len() == 32,
            "Hash256::from_slice requires exactly 32 bytes, got {}",
            slice.len()
        );
        let mut arr = [0u8; 32];
        arr.copy_from_slice(slice);
        Hash256(arr)
    }

    /// Create from a u128 value in little-endian format
    pub fn from_u128_le(value: u128) -> Self {
        let mut arr = [0u8; 32];
        arr[..16].copy_from_slice(&value.to_le_bytes());
        Hash256(arr)
    }

    /// Create from compact bits (difficulty encoding)
    /// Reference: Bitcoin's uint256::SetCompact
    pub fn from_compact(compact: u32) -> Self {
        let size = (compact >> 24) as usize;
        let mut word = compact & 0x00FFFFFF;

        let mut arr = [0u8; 32];

        if size <= 3 {
            word >>= 8 * (3 - size);
            arr[0] = (word & 0xFF) as u8;
            arr[1] = ((word >> 8) & 0xFF) as u8;
            arr[2] = ((word >> 16) & 0xFF) as u8;
        } else {
            let offset = size - 3;
            if offset < 32 {
                arr[offset] = (word & 0xFF) as u8;
                if offset + 1 < 32 {
                    arr[offset + 1] = ((word >> 8) & 0xFF) as u8;
                }
                if offset + 2 < 32 {
                    arr[offset + 2] = ((word >> 16) & 0xFF) as u8;
                }
            }
        }

        Hash256(arr)
    }

    /// Multiply this hash by another, returning None if overflow
    /// Used for stake target calculation
    /// Performs full 256-bit multiplication with overflow detection
    pub fn multiply_by(&self, other: &Hash256) -> Option<Self> {
        // Check if either is zero
        if self.is_zero() || other.is_zero() {
            return Some(Hash256::zero());
        }

        // Perform 256-bit multiplication using 64-bit limbs
        // Store as little-endian u64 limbs for easier computation
        let a: [u64; 4] = [
            u64::from_le_bytes([
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6],
                self.0[7],
            ]),
            u64::from_le_bytes([
                self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14],
                self.0[15],
            ]),
            u64::from_le_bytes([
                self.0[16], self.0[17], self.0[18], self.0[19], self.0[20], self.0[21], self.0[22],
                self.0[23],
            ]),
            u64::from_le_bytes([
                self.0[24], self.0[25], self.0[26], self.0[27], self.0[28], self.0[29], self.0[30],
                self.0[31],
            ]),
        ];

        let b: [u64; 4] = [
            u64::from_le_bytes([
                other.0[0], other.0[1], other.0[2], other.0[3], other.0[4], other.0[5], other.0[6],
                other.0[7],
            ]),
            u64::from_le_bytes([
                other.0[8],
                other.0[9],
                other.0[10],
                other.0[11],
                other.0[12],
                other.0[13],
                other.0[14],
                other.0[15],
            ]),
            u64::from_le_bytes([
                other.0[16],
                other.0[17],
                other.0[18],
                other.0[19],
                other.0[20],
                other.0[21],
                other.0[22],
                other.0[23],
            ]),
            u64::from_le_bytes([
                other.0[24],
                other.0[25],
                other.0[26],
                other.0[27],
                other.0[28],
                other.0[29],
                other.0[30],
                other.0[31],
            ]),
        ];

        // Result needs 8 limbs to handle potential overflow
        let mut result: [u64; 8] = [0; 8];

        // Standard long multiplication
        for (i, &ai) in a.iter().enumerate() {
            let mut carry: u128 = 0;
            for (j, &bj) in b.iter().enumerate() {
                let idx = i + j;
                let product = (ai as u128) * (bj as u128) + (result[idx] as u128) + carry;
                result[idx] = product as u64;
                carry = product >> 64;
            }
            // Propagate carry
            let mut idx = i + 4;
            while carry > 0 && idx < 8 {
                let sum = (result[idx] as u128) + carry;
                result[idx] = sum as u64;
                carry = sum >> 64;
                idx += 1;
            }
            if carry > 0 {
                return None; // Overflow beyond 512 bits
            }
        }

        // Check for overflow (upper 4 limbs must be zero for result to fit in 256 bits)
        if result[4] != 0 || result[5] != 0 || result[6] != 0 || result[7] != 0 {
            return None; // Overflow
        }

        // Convert back to bytes
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&result[0].to_le_bytes());
        out[8..16].copy_from_slice(&result[1].to_le_bytes());
        out[16..24].copy_from_slice(&result[2].to_le_bytes());
        out[24..32].copy_from_slice(&result[3].to_le_bytes());

        Some(Hash256(out))
    }

    /// Add two Hash256 values, returning None on overflow
    pub fn checked_add(&self, other: &Hash256) -> Option<Self> {
        let mut result = [0u8; 32];
        let mut carry = 0u16;

        // Little-endian addition with carry
        for ((r, &a), &b) in result.iter_mut().zip(self.0.iter()).zip(other.0.iter()) {
            let sum = a as u16 + b as u16 + carry;
            *r = sum as u8;
            carry = sum >> 8;
        }

        if carry > 0 {
            None
        } else {
            Some(Hash256(result))
        }
    }

    /// Divide Hash256 by a u64 value
    pub fn divide_by_u64(&self, divisor: u64) -> Self {
        if divisor == 0 {
            return Hash256::zero();
        }

        let mut result = [0u8; 32];
        let mut remainder = 0u64;

        // Divide from most significant byte to least significant
        for i in (0..32).rev() {
            let dividend = (remainder << 8) | (self.0[i] as u64);
            result[i] = (dividend / divisor) as u8;
            remainder = dividend % divisor;
        }

        Hash256(result)
    }

    /// Bitwise NOT of all 32 bytes
    pub fn bitwise_not(&self) -> Self {
        let mut result = [0u8; 32];
        for (r, &b) in result.iter_mut().zip(self.0.iter()) {
            *r = !b;
        }
        Hash256(result)
    }

    /// Add 1 to this value (little-endian), returning the result.
    /// Returns None on overflow (all 0xFF bytes).
    pub fn increment(&self) -> Option<Self> {
        let mut result = self.0;
        for i in 0..32 {
            if result[i] == 0xFF {
                result[i] = 0;
                // carry continues
            } else {
                result[i] += 1;
                return Some(Hash256(result));
            }
        }
        // All bytes were 0xFF, overflow
        None
    }

    /// Divide this Hash256 by another Hash256 (256-bit by 256-bit division).
    /// Uses binary long division. Returns zero if divisor is zero.
    /// Both values are treated as unsigned 256-bit little-endian integers.
    pub fn divide_by_hash256(&self, divisor: &Hash256) -> Self {
        if divisor.is_zero() {
            return Hash256::zero();
        }

        // Binary long division on 256-bit integers
        // We work bit-by-bit from the most significant bit down
        let mut quotient = [0u8; 32];
        let mut remainder = [0u8; 32]; // accumulates the remainder

        // Process each bit from MSB (bit 255) to LSB (bit 0)
        for bit_pos in (0..256).rev() {
            // Shift remainder left by 1 bit
            let mut carry = 0u8;
            for r in remainder.iter_mut() {
                let new_carry = *r >> 7;
                *r = (*r << 1) | carry;
                carry = new_carry;
            }

            // Bring down the next bit from the numerator
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            let bit = (self.0[byte_idx] >> bit_idx) & 1;
            remainder[0] |= bit;

            // If remainder >= divisor, subtract divisor and set quotient bit
            if Self::ge_256(&remainder, &divisor.0) {
                Self::sub_256(&mut remainder, &divisor.0);
                let q_byte = bit_pos / 8;
                let q_bit = bit_pos % 8;
                quotient[q_byte] |= 1 << q_bit;
            }
        }

        Hash256(quotient)
    }

    /// Compare two 256-bit little-endian values: a >= b
    fn ge_256(a: &[u8; 32], b: &[u8; 32]) -> bool {
        for i in (0..32).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true // equal
    }

    /// Subtract b from a in-place (a -= b), assuming a >= b. Little-endian.
    fn sub_256(a: &mut [u8; 32], b: &[u8; 32]) {
        let mut borrow: i16 = 0;
        for i in 0..32 {
            let diff = (a[i] as i16) - (b[i] as i16) - borrow;
            if diff < 0 {
                a[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                a[i] = diff as u8;
                borrow = 0;
            }
        }
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for Hash256 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash256::from_hex(s)
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Hash256(bytes)
    }
}

impl Encodable for Hash256 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(&self.0)?;
        Ok(32)
    }

    fn encoded_size(&self) -> usize {
        32
    }
}

impl Decodable for Hash256 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        Ok(Hash256(bytes))
    }
}

/// A 160-bit (20-byte) hash
///
/// Used for addresses (RIPEMD160(SHA256(pubkey)))
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub struct Hash160(pub [u8; 20]);

impl Hash160 {
    /// Create a new zero hash
    pub const fn zero() -> Self {
        Hash160([0u8; 20])
    }

    /// Create from raw bytes
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Hash160(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Get the raw bytes as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Check if this is a zero hash
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }

    /// Create from a hex string
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex).map_err(|e| Error::InvalidHex(e.to_string()))?;

        if bytes.len() != 20 {
            return Err(Error::InvalidLength {
                expected: 20,
                got: bytes.len(),
            });
        }

        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Hash160(arr))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash160({})", self.to_hex())
    }
}

impl fmt::Display for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for Hash160 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash160::from_hex(s)
    }
}

impl AsRef<[u8]> for Hash160 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for Hash160 {
    fn from(bytes: [u8; 20]) -> Self {
        Hash160(bytes)
    }
}

impl Encodable for Hash160 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(&self.0)?;
        Ok(20)
    }

    fn encoded_size(&self) -> usize {
        20
    }
}

impl Decodable for Hash160 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut bytes = [0u8; 20];
        reader.read_exact(&mut bytes)?;
        Ok(Hash160(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::{deserialize, serialize};
    use sha2::{Digest, Sha256};

    // --------------- double-SHA256 helper used by tests ---------------
    fn double_sha256(data: &[u8]) -> [u8; 32] {
        let first = Sha256::digest(data);
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out
    }

    #[test]
    fn test_hash256_zero() {
        let hash = Hash256::zero();
        assert!(hash.is_zero());
        assert_eq!(hash.to_hex(), "0".repeat(64));
    }

    #[test]
    fn test_hash256_hex_roundtrip() {
        // Bitcoin genesis block hash (display format is reversed)
        let hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let hash = Hash256::from_hex(hex).unwrap();
        assert_eq!(hash.to_hex(), hex);
    }

    #[test]
    fn test_hash256_serialization() {
        let hash = Hash256::from_bytes([
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
            0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);

        let encoded = serialize(&hash);
        assert_eq!(encoded.len(), 32);

        let decoded: Hash256 = deserialize(&encoded).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_hash160_serialization() {
        let hash = Hash160::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ]);

        let encoded = serialize(&hash);
        assert_eq!(encoded.len(), 20);

        let decoded: Hash160 = deserialize(&encoded).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_hash256_comparison_little_endian() {
        // Test that Hash256 compares as a 256-bit little-endian integer
        // byte[31] is most significant, byte[0] is least significant

        // Create two hashes where byte[31] differs
        let mut smaller = [0u8; 32];
        let mut larger = [0u8; 32];
        smaller[31] = 0x01; // MSB = 1
        larger[31] = 0x02; // MSB = 2

        let hash_smaller = Hash256::from_bytes(smaller);
        let hash_larger = Hash256::from_bytes(larger);

        assert!(hash_smaller < hash_larger, "MSB comparison failed");

        // Test where byte[0] differs but byte[31] is same
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 0xFF; // LSB = 255, but MSB = 0
        b[31] = 0x01; // LSB = 0, but MSB = 1

        let hash_a = Hash256::from_bytes(a);
        let hash_b = Hash256::from_bytes(b);

        // hash_b should be larger because its MSB is greater
        assert!(
            hash_a < hash_b,
            "LSB vs MSB comparison failed: 0x00...FF < 0x01...00"
        );

        // Test a realistic stake target scenario
        // Target: 0x0011bbb9c7780000... (small number, most bytes are 0)
        // Hash:   0x3cc51d644a9a64ca... (larger number)
        // The hash should be GREATER than the target (fails stake check)

        // Simplified: target has zeros in high bytes, hash has non-zero in high bytes
        let mut target_bytes = [0u8; 32];
        target_bytes[29] = 0x11; // Some small value near MSB

        let mut hash_bytes = [0u8; 32];
        hash_bytes[31] = 0x3c; // Higher MSB value

        let target = Hash256::from_bytes(target_bytes);
        let hash = Hash256::from_bytes(hash_bytes);

        assert!(
            hash > target,
            "Stake target comparison failed: hash should be > target"
        );
    }

    #[test]
    fn test_hash256_comparison_equals() {
        let a = Hash256::from_bytes([0x42; 32]);
        let b = Hash256::from_bytes([0x42; 32]);
        assert_eq!(a, b);
        assert!(a >= b);
        assert!(a <= b);
    }

    // ---- NEW: Hash256::hash() double-SHA256 test vector ----

    /// Hash256("abc") via double-SHA256 must match the known test vector
    /// from test_vectors::hashes::hash256::ABC.
    ///
    /// sha2 outputs bytes in natural byte order. Hash256::from_bytes() stores
    /// them as-is. Hash256::to_raw_hex() returns those bytes as hex without any
    /// reversal. The test vector constant is the SHA256d output in natural byte
    /// order (same as what sha2 produces).
    #[test]
    fn test_hash256_double_sha256_abc_vector() {
        let raw = double_sha256(b"abc");
        let result = Hash256::from_bytes(raw);
        // to_raw_hex() returns the sha2 output bytes directly as hex
        let expected_raw_hex = crate::test_vectors::hashes::hash256::ABC;
        assert_eq!(
            result.to_raw_hex(),
            expected_raw_hex,
            "double-SHA256('abc') raw hex mismatch: got {} expected {}",
            result.to_raw_hex(),
            expected_raw_hex
        );
    }

    /// Verify that double-SHA256 of the empty string produces the correct result.
    ///
    /// SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    /// SHA256(SHA256("")) as raw hex (matching sha2 output byte order):
    ///   5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    #[test]
    fn test_hash256_double_sha256_empty() {
        let raw = double_sha256(b"");
        let result = Hash256::from_bytes(raw);
        let expected_raw_hex = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";
        assert_eq!(
            result.to_raw_hex(),
            expected_raw_hex,
            "double-SHA256('') raw hex mismatch: got {}",
            result.to_raw_hex()
        );
    }

    // ---- NEW: from_hex / to_hex byte-order round-trip ----

    /// from_hex stores bytes reversed (display convention), to_hex reverses them back.
    #[test]
    fn test_hash256_hex_byte_order() {
        // A simple all-zero-except-last hash in display order
        let display_hex = "0100000000000000000000000000000000000000000000000000000000000000";
        let hash = Hash256::from_hex(display_hex).unwrap();
        // Internal byte[31] should be 0x01 (because we reversed the display bytes)
        assert_eq!(
            hash.0[31], 0x01,
            "MSB should be 0x01 after from_hex reverse"
        );
        assert_eq!(hash.0[0], 0x00, "LSB should be 0x00");
        assert_eq!(hash.to_hex(), display_hex);
    }

    /// from_raw_hex does NOT reverse; to_raw_hex returns the same ordering.
    #[test]
    fn test_hash256_raw_hex_no_reversal() {
        let raw_hex = "0100000000000000000000000000000000000000000000000000000000000000";
        let hash = Hash256::from_raw_hex(raw_hex).unwrap();
        // byte[0] = 0x01 (no reversal)
        assert_eq!(hash.0[0], 0x01);
        assert_eq!(hash.to_raw_hex(), raw_hex);
    }

    // ---- NEW: multiply_by ----

    #[test]
    fn test_hash256_multiply_by_zero() {
        let a = Hash256::from_bytes([0xFF; 32]);
        let zero = Hash256::zero();
        let result = a.multiply_by(&zero).unwrap();
        assert!(result.is_zero());
    }

    #[test]
    fn test_hash256_multiply_by_one() {
        // Construct value 1 (little-endian: byte[0]=1, rest=0)
        let mut one_bytes = [0u8; 32];
        one_bytes[0] = 1;
        let one = Hash256::from_bytes(one_bytes);

        let mut val_bytes = [0u8; 32];
        val_bytes[0] = 42;
        let val = Hash256::from_bytes(val_bytes);

        let result = val.multiply_by(&one).unwrap();
        assert_eq!(result, val, "x * 1 should equal x");
    }

    #[test]
    fn test_hash256_multiply_overflow_returns_none() {
        // Two max-value hashes multiplied will overflow
        let max = Hash256::from_bytes([0xFF; 32]);
        let result = max.multiply_by(&max);
        assert!(result.is_none(), "MAX * MAX should overflow");
    }

    #[test]
    fn test_hash256_multiply_small_values() {
        // 2 * 3 = 6 (all in byte[0])
        let mut two_bytes = [0u8; 32];
        two_bytes[0] = 2;
        let two = Hash256::from_bytes(two_bytes);

        let mut three_bytes = [0u8; 32];
        three_bytes[0] = 3;
        let three = Hash256::from_bytes(three_bytes);

        let result = two.multiply_by(&three).unwrap();
        assert_eq!(result.0[0], 6);
        assert_eq!(&result.0[1..], &[0u8; 31][..]);
    }

    // ---- NEW: divide_by_u64 ----

    #[test]
    fn test_hash256_divide_by_zero_returns_zero() {
        let val = Hash256::from_bytes([0xFF; 32]);
        let result = val.divide_by_u64(0);
        assert!(result.is_zero());
    }

    #[test]
    fn test_hash256_divide_by_one() {
        let val = Hash256::from_bytes([0xAB; 32]);
        let result = val.divide_by_u64(1);
        assert_eq!(result, val, "x / 1 should equal x");
    }

    #[test]
    fn test_hash256_divide_small_value() {
        // Value 6 / 2 = 3
        let mut six_bytes = [0u8; 32];
        six_bytes[0] = 6;
        let six = Hash256::from_bytes(six_bytes);
        let result = six.divide_by_u64(2);
        assert_eq!(result.0[0], 3);
        assert_eq!(&result.0[1..], &[0u8; 31][..]);
    }

    // ---- NEW: checked_add ----

    #[test]
    fn test_hash256_checked_add_no_overflow() {
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 10;
        let a = Hash256::from_bytes(a_bytes);

        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 20;
        let b = Hash256::from_bytes(b_bytes);

        let result = a.checked_add(&b).unwrap();
        assert_eq!(result.0[0], 30);
        assert_eq!(&result.0[1..], &[0u8; 31][..]);
    }

    #[test]
    fn test_hash256_checked_add_overflow_returns_none() {
        let max = Hash256::from_bytes([0xFF; 32]);
        let mut one_bytes = [0u8; 32];
        one_bytes[0] = 1;
        let one = Hash256::from_bytes(one_bytes);
        let result = max.checked_add(&one);
        assert!(result.is_none(), "MAX + 1 should overflow");
    }

    #[test]
    fn test_hash256_checked_add_carry_propagates() {
        // 0xFF + 0x01 in byte[0] should carry into byte[1]
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 0xFF;
        let a = Hash256::from_bytes(a_bytes);

        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 0x01;
        let b = Hash256::from_bytes(b_bytes);

        let result = a.checked_add(&b).unwrap();
        assert_eq!(result.0[0], 0x00);
        assert_eq!(result.0[1], 0x01);
    }

    // ---- NEW: from_compact ----

    #[test]
    fn test_hash256_from_compact_mainnet_pow_limit() {
        // 0x1e0ffff0 is the mainnet PoW limit bits value
        let compact = 0x1e0ffff0u32;
        let target = Hash256::from_compact(compact);
        // Should not be zero
        assert!(!target.is_zero());
        // The mantissa bytes (0x0f, 0xff, 0xf0) should be in positions 27-29
        // size = 0x1e = 30; offset = 30 - 3 = 27
        assert_eq!(
            target.0[27], 0xf0,
            "byte[27] should be 0xf0 (low mantissa byte)"
        );
        assert_eq!(target.0[28], 0xff, "byte[28] should be 0xff");
        assert_eq!(
            target.0[29], 0x0f,
            "byte[29] should be 0x0f (high mantissa byte)"
        );
    }

    #[test]
    fn test_hash256_from_compact_zero_mantissa() {
        // Compact with zero mantissa → zero hash
        let result = Hash256::from_compact(0x00000000);
        assert!(result.is_zero());
    }

    // ---- NEW: from_u128_le ----

    #[test]
    fn test_hash256_from_u128_le() {
        let val: u128 = 0x0102030405060708090a0b0c0d0e0f10;
        let hash = Hash256::from_u128_le(val);
        // Low bytes should match the little-endian encoding of val
        assert_eq!(&hash.0[..16], &val.to_le_bytes()[..]);
        // Upper bytes should be zero
        assert_eq!(&hash.0[16..], &[0u8; 16][..]);
    }

    // ---- NEW: Hash160 ----

    #[test]
    fn test_hash160_zero() {
        let hash = Hash160::zero();
        assert!(hash.is_zero());
        assert_eq!(hash.to_hex(), "0".repeat(40));
    }

    #[test]
    fn test_hash160_from_hex_roundtrip() {
        let hex = "89abcdefab89abcdefab89abcdefab89abcdefab";
        let hash = Hash160::from_hex(hex).unwrap();
        assert_eq!(hash.to_hex(), hex);
    }

    #[test]
    fn test_hash160_from_hex_wrong_length_errors() {
        let result = Hash160::from_hex("deadbeef"); // only 4 bytes
        assert!(result.is_err());
    }

    // ---- NEW: Hash256 error cases ----

    #[test]
    fn test_hash256_from_hex_wrong_length_errors() {
        let result = Hash256::from_hex("deadbeef"); // only 4 bytes
        assert!(result.is_err());
    }

    #[test]
    fn test_hash256_from_raw_hex_wrong_length_errors() {
        let result = Hash256::from_raw_hex("deadbeef");
        assert!(result.is_err());
    }

    #[test]
    fn test_hash256_from_str_parse() {
        use std::str::FromStr;
        let hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let hash: Hash256 = Hash256::from_str(hex).unwrap();
        assert_eq!(hash.to_hex(), hex);
    }

    // ---- NEW: multiply + divide consistency ----

    #[test]
    fn test_hash256_multiply_then_divide() {
        // (2 * 6) / 3 = 4
        let mut two_bytes = [0u8; 32];
        two_bytes[0] = 2;
        let two = Hash256::from_bytes(two_bytes);

        let mut six_bytes = [0u8; 32];
        six_bytes[0] = 6;
        let six = Hash256::from_bytes(six_bytes);

        let product = two.multiply_by(&six).unwrap(); // 12
        let result = product.divide_by_u64(3); // 4
        assert_eq!(result.0[0], 4);
        assert_eq!(&result.0[1..], &[0u8; 31][..]);
    }

    // ---- bitwise_not ----

    #[test]
    fn test_hash256_bitwise_not_zero() {
        let zero = Hash256::zero();
        let result = zero.bitwise_not();
        assert_eq!(result, Hash256::from_bytes([0xFF; 32]));
    }

    #[test]
    fn test_hash256_bitwise_not_max() {
        let max = Hash256::from_bytes([0xFF; 32]);
        let result = max.bitwise_not();
        assert!(result.is_zero());
    }

    #[test]
    fn test_hash256_bitwise_not_double_inverse() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[15] = 0xCD;
        bytes[31] = 0xEF;
        let val = Hash256::from_bytes(bytes);
        assert_eq!(val.bitwise_not().bitwise_not(), val);
    }

    // ---- increment ----

    #[test]
    fn test_hash256_increment_zero() {
        let zero = Hash256::zero();
        let one = zero.increment().unwrap();
        assert_eq!(one.0[0], 1);
        assert_eq!(&one.0[1..], &[0u8; 31][..]);
    }

    #[test]
    fn test_hash256_increment_with_carry() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;
        let val = Hash256::from_bytes(bytes);
        let result = val.increment().unwrap();
        assert_eq!(result.0[0], 0);
        assert_eq!(result.0[1], 0);
        assert_eq!(result.0[2], 1);
    }

    #[test]
    fn test_hash256_increment_max_overflows() {
        let max = Hash256::from_bytes([0xFF; 32]);
        assert!(max.increment().is_none());
    }

    // ---- divide_by_hash256 ----

    #[test]
    fn test_hash256_divide_by_hash256_small() {
        // 10 / 3 = 3 (integer division)
        let mut ten = [0u8; 32];
        ten[0] = 10;
        let mut three = [0u8; 32];
        three[0] = 3;
        let result = Hash256::from_bytes(ten).divide_by_hash256(&Hash256::from_bytes(three));
        assert_eq!(result.0[0], 3);
        assert_eq!(&result.0[1..], &[0u8; 31][..]);
    }

    #[test]
    fn test_hash256_divide_by_hash256_exact() {
        // 12 / 4 = 3
        let mut twelve = [0u8; 32];
        twelve[0] = 12;
        let mut four = [0u8; 32];
        four[0] = 4;
        let result = Hash256::from_bytes(twelve).divide_by_hash256(&Hash256::from_bytes(four));
        assert_eq!(result.0[0], 3);
        assert_eq!(&result.0[1..], &[0u8; 31][..]);
    }

    #[test]
    fn test_hash256_divide_by_hash256_zero_divisor() {
        let val = Hash256::from_bytes([0xAB; 32]);
        let result = val.divide_by_hash256(&Hash256::zero());
        assert!(result.is_zero());
    }

    #[test]
    fn test_hash256_divide_by_hash256_one() {
        // x / 1 = x
        let mut val = [0u8; 32];
        val[0] = 42;
        val[16] = 0xBE;
        let x = Hash256::from_bytes(val);
        let mut one = [0u8; 32];
        one[0] = 1;
        let result = x.divide_by_hash256(&Hash256::from_bytes(one));
        assert_eq!(result, x);
    }

    #[test]
    fn test_hash256_divide_by_hash256_self() {
        // x / x = 1
        let mut val = [0u8; 32];
        val[0] = 0xFF;
        val[8] = 0xAB;
        val[31] = 0x01;
        let x = Hash256::from_bytes(val);
        let result = x.divide_by_hash256(&x);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(result, Hash256::from_bytes(expected));
    }

    #[test]
    fn test_hash256_divide_by_hash256_large_numerator() {
        // ~0 / 1 should be ~0 (0xFF..FF)
        let max = Hash256::from_bytes([0xFF; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        let result = max.divide_by_hash256(&Hash256::from_bytes(one));
        assert_eq!(result, max);
    }

    /// Verify GetBlockProof formula: (~target / (target+1)) + 1
    /// For target = 1: ~1 = 0xFF..FE, (target+1) = 2,
    /// 0xFF..FE / 2 = 0x7F..FF, + 1 = 0x80..00
    #[test]
    fn test_hash256_get_block_proof_formula_target_1() {
        let mut target_bytes = [0u8; 32];
        target_bytes[0] = 1;
        let target = Hash256::from_bytes(target_bytes);

        let not_target = target.bitwise_not();
        let target_plus_one = target.increment().unwrap();
        let quotient = not_target.divide_by_hash256(&target_plus_one);
        let result = quotient.increment().unwrap();

        // ~1 = 0xFE FF..FF (LE), target+1 = 2
        // 0xFF..FE / 2 = 0x7F..FF
        // + 1 = 0x80..00 (with byte[31]=0x80, rest=0 in BE; in LE that's byte[31]=0x80)
        let mut expected = [0u8; 32];
        expected[31] = 0x80;
        assert_eq!(
            result,
            Hash256::from_bytes(expected),
            "GetBlockProof for target=1 should be 2^255"
        );
    }
}
