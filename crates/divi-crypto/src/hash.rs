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

//! Hash functions for Divi
//!
//! Divi uses the same hash functions as Bitcoin:
//! - SHA256: Single SHA-256 hash
//! - Hash256 (double_sha256): SHA256(SHA256(data))
//! - Hash160: RIPEMD160(SHA256(data)) - used for addresses

use divi_primitives::hash::{Hash160, Hash256};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Compute SHA256 hash of data
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute double SHA256 hash: SHA256(SHA256(data))
///
/// This is Bitcoin's "Hash256" and is used for:
/// - Block hashes
/// - Transaction IDs
/// - Merkle tree nodes
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = sha256(data);
    sha256(&first)
}

/// Compute Hash256 (double SHA256) and return as Hash256 type
pub fn hash256(data: &[u8]) -> Hash256 {
    Hash256::from_bytes(double_sha256(data))
}

/// Compute RIPEMD160 hash of data
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute Hash160: RIPEMD160(SHA256(data))
///
/// This is used for:
/// - Public key hashes (P2PKH addresses)
/// - Script hashes (P2SH addresses)
pub fn hash160(data: &[u8]) -> Hash160 {
    let sha = sha256(data);
    Hash160::from_bytes(ripemd160(&sha))
}

/// Compute the hash of a serializable value
pub fn hash_serialized<T: divi_primitives::serialize::Encodable>(value: &T) -> Hash256 {
    let data = divi_primitives::serialize::serialize(value);
    hash256(&data)
}

/// Compute the correct hash for a block header
///
/// Divi uses different hash algorithms depending on the block version:
/// - Version < 4: Quark hash (9-step chained hash with Blake512, BMW512, etc.)
/// - Version >= 4: SHA256d (standard Bitcoin double SHA256)
///
/// This matches the C++ `CBlockHeader::GetHash()` implementation:
/// ```cpp
/// if(nVersion < 4)
///     return HashQuark(BEGIN(nVersion), END(nNonce));
/// return Hash(BEGIN(nVersion), END(nAccumulatorCheckpoint));
/// ```
pub fn compute_block_hash(header: &divi_primitives::block::BlockHeader) -> Hash256 {
    let serialized = divi_primitives::serialize::serialize(header);
    if header.version < 4 {
        // Quark hash for legacy PoW blocks (version 1-3)
        // Note: For version < 4, the accumulator checkpoint is NOT serialized,
        // so the serialized data is exactly 80 bytes (version + prev_block + merkle_root + time + bits + nonce)
        Hash256::from_bytes(crate::quark::hash_quark(&serialized))
    } else {
        // SHA256d for PoS blocks (version 4+)
        // Includes accumulator checkpoint in the serialization
        hash256(&serialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        // Test vector: SHA256("")
        let empty_hash = sha256(&[]);
        assert_eq!(
            hex::encode(empty_hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Test vector: SHA256("abc")
        let abc_hash = sha256(b"abc");
        assert_eq!(
            hex::encode(abc_hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_double_sha256() {
        // Test vector: Hash256("abc")
        let result = double_sha256(b"abc");
        assert_eq!(
            hex::encode(result),
            "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
        );
    }

    #[test]
    fn test_ripemd160() {
        // Test vector: RIPEMD160("")
        let empty_hash = ripemd160(&[]);
        assert_eq!(
            hex::encode(empty_hash),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );

        // Test vector: RIPEMD160("abc")
        let abc_hash = ripemd160(b"abc");
        assert_eq!(
            hex::encode(abc_hash),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn test_hash160() {
        // Test: Hash160("abc") = RIPEMD160(SHA256("abc"))
        let result = hash160(b"abc");
        let sha = sha256(b"abc");
        let expected = ripemd160(&sha);
        assert_eq!(result.as_bytes(), &expected);
    }

    #[test]
    fn test_hash256_type() {
        let result = hash256(b"test");
        assert!(!result.is_zero());
        assert_eq!(result.as_bytes().len(), 32);
    }

    // Tests against C++ test vectors from crypto_tests.cpp
    mod cpp_compatibility {
        use super::*;
        use divi_primitives::test_vectors::hashes;

        #[test]
        fn test_sha256_matches_cpp() {
            // Empty string
            assert_eq!(hex::encode(sha256(&[])), hashes::sha256::EMPTY);

            // "abc"
            assert_eq!(hex::encode(sha256(b"abc")), hashes::sha256::ABC);

            // "message digest"
            assert_eq!(
                hex::encode(sha256(b"message digest")),
                hashes::sha256::MESSAGE_DIGEST
            );
        }

        #[test]
        fn test_ripemd160_matches_cpp() {
            // Empty string
            assert_eq!(hex::encode(ripemd160(&[])), hashes::ripemd160::EMPTY);

            // "abc"
            assert_eq!(hex::encode(ripemd160(b"abc")), hashes::ripemd160::ABC);

            // "message digest"
            assert_eq!(
                hex::encode(ripemd160(b"message digest")),
                hashes::ripemd160::MESSAGE_DIGEST
            );
        }

        #[test]
        fn test_double_sha256_matches_cpp() {
            // Hash256("abc")
            assert_eq!(hex::encode(double_sha256(b"abc")), hashes::hash256::ABC);
        }
    }

    // --- Edge-case coverage ---

    #[test]
    fn test_sha256_single_byte() {
        // SHA256 of a single 0x00 byte
        let result = sha256(&[0x00]);
        // Known value: SHA256("\x00")
        assert_eq!(
            hex::encode(result),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn test_double_sha256_empty() {
        // Hash256("") = SHA256(SHA256(""))
        let result = double_sha256(&[]);
        let expected = sha256(&sha256(&[]));
        assert_eq!(result, expected);
        // Must not be all zeros
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_double_sha256_single_byte() {
        // Determinism check for single-byte input
        let r1 = double_sha256(&[0x42]);
        let r2 = double_sha256(&[0x42]);
        assert_eq!(r1, r2);
        // Must differ from SHA256 of same byte
        assert_ne!(r1, sha256(&[0x42]));
    }

    #[test]
    fn test_double_sha256_64_byte_boundary() {
        // SHA-256 internal block is 64 bytes; test inputs at and around that boundary
        let data_63 = [0xFFu8; 63];
        let data_64 = [0xFFu8; 64];
        let data_65 = [0xFFu8; 65];

        let h63 = double_sha256(&data_63);
        let h64 = double_sha256(&data_64);
        let h65 = double_sha256(&data_65);

        // All three must be different
        assert_ne!(h63, h64);
        assert_ne!(h64, h65);
        assert_ne!(h63, h65);

        // All must be deterministic
        assert_eq!(h64, double_sha256(&data_64));
    }

    #[test]
    fn test_hash256_type_empty_input() {
        let result = hash256(&[]);
        assert_eq!(result.as_bytes().len(), 32);
        assert!(!result.is_zero());
    }

    #[test]
    fn test_hash256_type_single_byte() {
        let result = hash256(&[0x01]);
        let expected = double_sha256(&[0x01]);
        assert_eq!(result.as_bytes(), &expected);
    }

    #[test]
    fn test_ripemd160_single_byte() {
        // RIPEMD160 of a single 0x00 byte — known vector
        let result = ripemd160(&[0x00]);
        // sha2/ripemd: compute: RIPEMD160("\x00") = c81b94933420221a7ac004a90242d8b1d3e5070d
        assert_eq!(
            hex::encode(result),
            "c81b94933420221a7ac004a90242d8b1d3e5070d"
        );
    }

    #[test]
    fn test_hash160_empty() {
        // hash160("") = RIPEMD160(SHA256(""))
        let result = hash160(&[]);
        let sha = sha256(&[]);
        let expected = ripemd160(&sha);
        assert_eq!(result.as_bytes(), &expected);
    }

    #[test]
    fn test_sha256_64_byte_boundary() {
        // Exactly one SHA-256 block (64 bytes) — determinism check
        let data = [0xAAu8; 64];
        let r1 = sha256(&data);
        let r2 = sha256(&data);
        assert_eq!(r1, r2);

        // One byte less and one byte more must differ
        let r_63 = sha256(&[0xAAu8; 63]);
        let r_65 = sha256(&[0xAAu8; 65]);
        assert_ne!(r1, r_63);
        assert_ne!(r1, r_65);
    }
}
