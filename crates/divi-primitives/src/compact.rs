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

//! CompactSize encoding (Bitcoin/Divi variable-length integer)
//!
//! Format:
//! - 0-252: 1 byte (value directly)
//! - 253-0xFFFF: 3 bytes (0xFD + 2 bytes little-endian)
//! - 0x10000-0xFFFFFFFF: 5 bytes (0xFE + 4 bytes little-endian)
//! - 0x100000000-0xFFFFFFFFFFFFFFFF: 9 bytes (0xFF + 8 bytes little-endian)

use crate::error::Error;
use crate::serialize::{Decodable, Encodable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

/// A variable-length integer encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompactSize(pub u64);

impl CompactSize {
    /// Create a new CompactSize
    pub fn new(value: u64) -> Self {
        CompactSize(value)
    }

    /// Get the inner value
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl From<u64> for CompactSize {
    fn from(value: u64) -> Self {
        CompactSize(value)
    }
}

impl From<usize> for CompactSize {
    fn from(value: usize) -> Self {
        CompactSize(value as u64)
    }
}

impl From<CompactSize> for u64 {
    fn from(cs: CompactSize) -> Self {
        cs.0
    }
}

impl From<CompactSize> for usize {
    fn from(cs: CompactSize) -> Self {
        cs.0 as usize
    }
}

impl Encodable for CompactSize {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        if self.0 < 253 {
            writer.write_u8(self.0 as u8)?;
            Ok(1)
        } else if self.0 <= 0xFFFF {
            writer.write_u8(253)?;
            writer.write_u16::<LittleEndian>(self.0 as u16)?;
            Ok(3)
        } else if self.0 <= 0xFFFFFFFF {
            writer.write_u8(254)?;
            writer.write_u32::<LittleEndian>(self.0 as u32)?;
            Ok(5)
        } else {
            writer.write_u8(255)?;
            writer.write_u64::<LittleEndian>(self.0)?;
            Ok(9)
        }
    }

    fn encoded_size(&self) -> usize {
        if self.0 < 253 {
            1
        } else if self.0 <= 0xFFFF {
            3
        } else if self.0 <= 0xFFFFFFFF {
            5
        } else {
            9
        }
    }
}

impl Decodable for CompactSize {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let first = reader.read_u8()?;

        let value = if first < 253 {
            first as u64
        } else if first == 253 {
            let v = reader.read_u16::<LittleEndian>()? as u64;
            // Check canonical encoding
            if v < 253 {
                return Err(Error::NonCanonical(
                    "CompactSize encoded as 3 bytes but value fits in 1".to_string(),
                ));
            }
            v
        } else if first == 254 {
            let v = reader.read_u32::<LittleEndian>()? as u64;
            // Check canonical encoding
            if v <= 0xFFFF {
                return Err(Error::NonCanonical(
                    "CompactSize encoded as 5 bytes but value fits in 3".to_string(),
                ));
            }
            v
        } else {
            // first == 255
            let v = reader.read_u64::<LittleEndian>()?;
            // Check canonical encoding
            if v <= 0xFFFFFFFF {
                return Err(Error::NonCanonical(
                    "CompactSize encoded as 9 bytes but value fits in 5".to_string(),
                ));
            }
            v
        };

        Ok(CompactSize(value))
    }
}

/// Get the encoded size of a CompactSize for a given value
pub fn compact_size_len(value: u64) -> usize {
    CompactSize(value).encoded_size()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::{deserialize, serialize};

    #[test]
    fn test_compact_size_small() {
        // Values 0-252 use 1 byte
        let cs = CompactSize(0);
        assert_eq!(serialize(&cs), vec![0]);

        let cs = CompactSize(252);
        assert_eq!(serialize(&cs), vec![252]);
    }

    #[test]
    fn test_compact_size_two_byte() {
        // Values 253-65535 use 3 bytes (0xFD + 2 bytes)
        let cs = CompactSize(253);
        assert_eq!(serialize(&cs), vec![253, 253, 0]);

        let cs = CompactSize(0xFFFF);
        assert_eq!(serialize(&cs), vec![253, 0xFF, 0xFF]);
    }

    #[test]
    fn test_compact_size_four_byte() {
        // Values 65536-0xFFFFFFFF use 5 bytes (0xFE + 4 bytes)
        let cs = CompactSize(0x10000);
        assert_eq!(serialize(&cs), vec![254, 0, 0, 1, 0]);

        let cs = CompactSize(0xFFFFFFFF);
        assert_eq!(serialize(&cs), vec![254, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_compact_size_eight_byte() {
        // Values > 0xFFFFFFFF use 9 bytes (0xFF + 8 bytes)
        let cs = CompactSize(0x100000000);
        assert_eq!(serialize(&cs), vec![255, 0, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn test_compact_size_roundtrip() {
        let values = vec![
            0u64,
            1,
            252,
            253,
            254,
            255,
            0xFFFF,
            0x10000,
            0xFFFFFFFF,
            0x100000000,
        ];
        for v in values {
            let cs = CompactSize(v);
            let encoded = serialize(&cs);
            let decoded: CompactSize = deserialize(&encoded).unwrap();
            assert_eq!(decoded.0, v, "Roundtrip failed for {}", v);
        }
    }

    #[test]
    fn test_non_canonical_rejected() {
        // 253 encoded as 3 bytes when it could fit in 1
        // This would be [253, 252, 0] for value 252 - non-canonical
        let non_canonical = vec![253u8, 252, 0];
        let result: Result<CompactSize, _> = deserialize(&non_canonical);
        assert!(result.is_err());
    }

    // ---- NEW: encoded_size matches actual serialized length ----

    #[test]
    fn test_compact_size_encoded_size_boundaries() {
        // Boundary: 252 → 1 byte
        assert_eq!(CompactSize(252).encoded_size(), 1);
        // Boundary: 253 → 3 bytes
        assert_eq!(CompactSize(253).encoded_size(), 3);
        // Boundary: 65535 → 3 bytes
        assert_eq!(CompactSize(0xFFFF).encoded_size(), 3);
        // Boundary: 65536 → 5 bytes
        assert_eq!(CompactSize(0x10000).encoded_size(), 5);
        // Boundary: 0xFFFFFFFF → 5 bytes
        assert_eq!(CompactSize(0xFFFFFFFF).encoded_size(), 5);
        // Boundary: 0x100000000 → 9 bytes
        assert_eq!(CompactSize(0x100000000).encoded_size(), 9);
        // Max u64
        assert_eq!(CompactSize(u64::MAX).encoded_size(), 9);
    }

    #[test]
    fn test_compact_size_encoded_size_matches_actual() {
        let values = [
            0u64,
            1,
            252,
            253,
            0xFFFF,
            0x10000,
            0xFFFFFFFF,
            0x100000000,
            u64::MAX,
        ];
        for &v in &values {
            let cs = CompactSize(v);
            let encoded = serialize(&cs);
            assert_eq!(
                encoded.len(),
                cs.encoded_size(),
                "encoded_size() mismatch for value {}",
                v
            );
        }
    }

    // ---- NEW: value() accessor ----

    #[test]
    fn test_compact_size_value_accessor() {
        let cs = CompactSize::new(12345);
        assert_eq!(cs.value(), 12345);
    }

    // ---- NEW: From conversions ----

    #[test]
    fn test_compact_size_from_usize_and_back() {
        let cs = CompactSize::from(42usize);
        assert_eq!(cs.0, 42);
        let as_usize: usize = cs.into();
        assert_eq!(as_usize, 42);
    }

    #[test]
    fn test_compact_size_from_u64_and_back() {
        let cs = CompactSize::from(9999u64);
        assert_eq!(cs.0, 9999);
        let as_u64: u64 = cs.into();
        assert_eq!(as_u64, 9999);
    }

    // ---- NEW: non-canonical 5-byte for value fitting in 3 bytes ----

    #[test]
    fn test_non_canonical_5byte_for_small_value_rejected() {
        // Encode value 1000 (fits in 3 bytes) using 5-byte form [0xFE, ...]
        let mut data = vec![0xFEu8];
        data.extend_from_slice(&1000u32.to_le_bytes());
        let result: Result<CompactSize, _> = deserialize(&data);
        assert!(
            result.is_err(),
            "5-byte encoding of value ≤ 0xFFFF should be rejected"
        );
    }

    // ---- NEW: non-canonical 9-byte for value fitting in 5 bytes ----

    #[test]
    fn test_non_canonical_9byte_for_small_value_rejected() {
        // Encode value 0x10000 (fits in 5 bytes) using 9-byte form [0xFF, ...]
        let mut data = vec![0xFFu8];
        data.extend_from_slice(&0x10000u64.to_le_bytes());
        let result: Result<CompactSize, _> = deserialize(&data);
        assert!(
            result.is_err(),
            "9-byte encoding of value ≤ 0xFFFFFFFF should be rejected"
        );
    }

    // ---- NEW: 254 boundary encodes as max 3-byte value + 1 ----

    #[test]
    fn test_compact_size_254_is_single_byte() {
        // 254 < 253? No, 254 >= 253, so 254 uses 3 bytes
        let cs = CompactSize(254);
        let encoded = serialize(&cs);
        assert_eq!(encoded.len(), 3, "254 should encode as 3 bytes");
        assert_eq!(encoded[0], 253u8); // 0xFD marker
        assert_eq!(encoded[1], 254u8);
        assert_eq!(encoded[2], 0u8);
        let decoded: CompactSize = deserialize(&encoded).unwrap();
        assert_eq!(decoded.0, 254);
    }
}
