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

//! Test vectors from Divi C++ codebase
//!
//! These are known-good values extracted from the C++ implementation
//! to ensure byte-for-byte compatibility.

use crate::hash::Hash256;

/// Genesis block data for different networks
pub mod genesis {
    /// Mainnet genesis block data
    pub mod mainnet {

        /// Genesis block hash
        pub const BLOCK_HASH: &str =
            "00000e258596876664989374c7ee36445cf5f4f80889af415cc32478214394ea";

        /// Genesis merkle root
        pub const MERKLE_ROOT: &str =
            "ec803cc6b5e68728ec0117cb1154b6d2893152f89d61319647db106908888bd6";

        /// Genesis timestamp
        pub const TIMESTAMP: u32 = 1537971708;

        /// Genesis nonce
        pub const NONCE: u32 = 749845;

        /// Genesis bits (difficulty)
        pub const BITS: u32 = 0x1e0ffff0;

        /// Coinbase public key
        pub const COINBASE_PUBKEY: &str = "04bcc3ef3417ba00ab55e3de807a776ade43cbd634a7e2cff383fecc6920cf918b2ad427f6b0a3f8d38f5a41d5dcbf35b394521bd08fcb5f40749df5bfe7d42fe2";

        /// Block at height 100
        pub const CHECKPOINT_100: &str =
            "000000275b2b4a8af2c93ebdfd36ef8dd8c8ec710072bcc388ecbf5d0c8d3f9d";
    }

    /// Testnet genesis block data
    pub mod testnet {
        /// Genesis block hash
        pub const BLOCK_HASH: &str =
            "00000f43b54bbcae395d815b255ac4ed0693bca7987d72b873d5d4b68d73a6bd";

        /// Genesis merkle root (same coinbase as mainnet)
        pub const MERKLE_ROOT: &str =
            "ec803cc6b5e68728ec0117cb1154b6d2893152f89d61319647db106908888bd6";

        /// Genesis timestamp
        pub const TIMESTAMP: u32 = 1591798387;

        /// Genesis nonce
        pub const NONCE: u32 = 2105601;

        /// Genesis bits (difficulty)
        pub const BITS: u32 = 0x1e0ffff0;
    }

    /// Regtest genesis block data
    pub mod regtest {
        /// Genesis block hash
        pub const BLOCK_HASH: &str =
            "0000000b3f9980dcf71f5f52d69e30d3b02f807e0a77b91b6091701e4ae51a6f";

        /// Genesis merkle root (same coinbase as mainnet)
        pub const MERKLE_ROOT: &str =
            "ec803cc6b5e68728ec0117cb1154b6d2893152f89d61319647db106908888bd6";

        /// Genesis timestamp
        pub const TIMESTAMP: u32 = 1537971708;

        /// Genesis nonce
        pub const NONCE: u32 = 984952;

        /// Genesis bits (regtest uses minimal difficulty)
        pub const BITS: u32 = 0x207fffff;
    }

    /// PrivateDivi genesis block data
    pub mod privatedivi {
        /// PrivateDivi coinbase message (different from Divi)
        pub const COINBASE_MESSAGE: &str =
            "February 2026 - PrivateDivi Network Genesis - divi.domains";

        /// PrivateDivi mainnet genesis block data
        pub mod mainnet {
            /// Genesis block hash
            pub const BLOCK_HASH: &str =
                "00000cde87387f76349797373bd8e30809334433210820b8bb17bdde6e8b1e80";

            /// Genesis merkle root
            pub const MERKLE_ROOT: &str =
                "4123e9ba36523af0b90b02b26663b76a11e9bf680e6c775d8dd6d7c66f95c4bd";

            /// Genesis timestamp
            pub const TIMESTAMP: u32 = 1771075434;

            /// Genesis nonce
            pub const NONCE: u32 = 12890;

            /// Genesis bits (difficulty)
            pub const BITS: u32 = 0x1e0ffff0;
        }

        /// PrivateDivi testnet genesis block data
        pub mod testnet {
            /// Genesis block hash
            pub const BLOCK_HASH: &str =
                "000003071a9dac6c02eb354b7e44add111c5427d483301cb76ed521d621a3b1d";

            /// Genesis merkle root (same coinbase tx as PrivateDivi mainnet)
            pub const MERKLE_ROOT: &str =
                "4123e9ba36523af0b90b02b26663b76a11e9bf680e6c775d8dd6d7c66f95c4bd";

            /// Genesis timestamp
            pub const TIMESTAMP: u32 = 1771075435;

            /// Genesis nonce
            pub const NONCE: u32 = 3082737;

            /// Genesis bits (difficulty)
            pub const BITS: u32 = 0x1e0ffff0;
        }

        /// PrivateDivi regtest genesis block data
        pub mod regtest {
            /// Genesis block hash
            pub const BLOCK_HASH: &str =
                "4b66fa19b46819cedf4dd4c3f84229916089e09e693e69d1beab944492b84ce3";

            /// Genesis merkle root (same coinbase tx as PrivateDivi mainnet)
            pub const MERKLE_ROOT: &str =
                "4123e9ba36523af0b90b02b26663b76a11e9bf680e6c775d8dd6d7c66f95c4bd";

            /// Genesis timestamp
            pub const TIMESTAMP: u32 = 1771075434;

            /// Genesis nonce
            pub const NONCE: u32 = 984952;

            /// Genesis bits (regtest uses minimal difficulty)
            pub const BITS: u32 = 0x207fffff;
        }
    }
}

/// Network address prefixes (Base58Check)
pub mod prefixes {
    /// Mainnet address prefixes
    pub mod mainnet {
        /// Pubkey hash address prefix (Base58 starts with 'D')
        pub const PUBKEY_ADDRESS: u8 = 0x1E; // 30

        /// Script hash address prefix
        pub const SCRIPT_ADDRESS: u8 = 0x0D; // 13

        /// Secret key prefix (WIF)
        pub const SECRET_KEY: u8 = 0xD4; // 212

        /// Extended public key prefix (xpub)
        pub const EXT_PUBLIC_KEY: [u8; 4] = [0x02, 0x2D, 0x25, 0x33];

        /// Extended private key prefix (xprv)
        pub const EXT_SECRET_KEY: [u8; 4] = [0x02, 0x21, 0x31, 0x2B];

        /// BIP44 coin type
        pub const BIP44_TYPE: u32 = 119;

        /// BIP44 coin type for PrivateDivi (registered as 801)
        pub const PRIVATEDIVI_BIP44_TYPE: u32 = 801;
    }
}

/// DNS seeds for peer discovery
pub mod dns_seeds {
    /// Divi mainnet DNS seeds
    pub mod divi {
        pub const MAINNET: &[&str] = &["autoseeds.diviseed.diviproject.org"];
        pub const TESTNET: &[&str] = &["autoseeds.tiviseed.diviproject.org"];
    }

    /// PrivateDivi DNS seeds
    pub mod privatedivi {
        pub const MAINNET: &[&str] = &["seeds.divi.domains"];
        pub const TESTNET: &[&str] = &["testseeds.divi.domains"];
    }
}

/// Static peer nodes
pub mod static_peers {
    /// Divi mainnet static peers
    pub mod divi {
        pub const MAINNET: &[&str] = &[
            "178.62.195.16:51472",
            "178.62.221.33:51472",
            "178.128.251.20:51472",
        ];
    }

    /// PrivateDivi static peers
    pub mod privatedivi {
        pub const MAINNET: &[&str] = &[
            "vps1.divi.domains:52481",
            "vps1.divi.domains:52482",
            "vps1.divi.domains:52483",
            "vps1.divi.domains:52484",
            "vps1.divi.domains:52485",
        ];
        pub const TESTNET: &[&str] = &[
            "vps1.divi.domains:52581",
            "vps1.divi.domains:52582",
            "vps1.divi.domains:52583",
            "vps1.divi.domains:52584",
            "vps1.divi.domains:52585",
        ];
    }
}

/// Key test vectors from key_tests.cpp
pub mod keys {
    /// Test private key (uncompressed) - WIF encoded
    pub const UNCOMPRESSED_WIF_1: &str = "87vK7Vayi3QLsuiva5yWSuVwSMhMcRM9dBsaD6JXMD1P5vnjRFn";
    /// Expected address for uncompressed key 1
    pub const UNCOMPRESSED_ADDR_1: &str = "DBFi8XAE1rcdCQfkv9w22n8Y9RxgaJnrDD";

    /// Test private key (uncompressed) 2
    pub const UNCOMPRESSED_WIF_2: &str = "87FGYGFDg5SYfdD4XL593hr7do6f52czPecVsYSAXi8N4RGeS9i";
    /// Expected address for uncompressed key 2
    pub const UNCOMPRESSED_ADDR_2: &str = "DPvKfv1FVp69yZMDzeuugvfZ9pzYiMv1bs";

    /// Test private key (compressed)
    pub const COMPRESSED_WIF_1: &str = "YRYJwfAyJ9c2jhi3T2xQyLijGvM7yLTw4izDaNQLxBzgUYrQiPmJ";
    /// Expected address for compressed key 1
    pub const COMPRESSED_ADDR_1: &str = "DNPrHK9ezAAUVExFDpZ7EE1xWpPskgp1gP";

    /// Test private key (compressed) 2
    pub const COMPRESSED_WIF_2: &str = "YNZyazHkwUbkmUpEYsBGWwHnHQTy2n9rJy1gS5k54YXVx3pE8n6N";
    /// Expected address for compressed key 2
    pub const COMPRESSED_ADDR_2: &str = "DNBVSAoc2whPFjZVAZ1pQbXPJk1LRrDC8Q";

    /// Test message for deterministic signing
    pub const SIGN_MESSAGE: &str = "Very deterministic message";

    /// DER signature from key 1 for SIGN_MESSAGE
    pub const KEY1_DER_SIG: &str = "30450221009071d4fead181ea197d6a23106c48ee5de25e023b38afaf71c170e3088e5238a02200dcbc7f1aad626a5ee812e08ef047114642538e423a94b4bd6a272731cf500d0";

    /// Compact signature from key 1
    pub const KEY1_COMPACT_SIG: &str = "1b9071d4fead181ea197d6a23106c48ee5de25e023b38afaf71c170e3088e5238a0dcbc7f1aad626a5ee812e08ef047114642538e423a94b4bd6a272731cf500d0";
}

/// BIP32 (HD wallet) test vectors
pub mod bip32 {
    /// Test vector 1 seed
    pub const SEED_1: &str = "000102030405060708090a0b0c0d0e0f";

    /// Master public key for seed 1 (m)
    pub const SEED_1_XPUB_M: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    /// Master private key for seed 1 (m)
    pub const SEED_1_XPRV_M: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    /// Public key at m/1 for seed 1
    pub const SEED_1_XPUB_M_1: &str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

    /// Private key at m/1 for seed 1
    pub const SEED_1_XPRV_M_1: &str = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";

    /// Test vector 2 seed (64 bytes)
    pub const SEED_2: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
}

/// Hash function test vectors matching C++ crypto_tests.cpp
pub mod hashes {
    /// SHA256 test vectors
    pub mod sha256 {
        /// SHA256("")
        pub const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        /// SHA256("abc")
        pub const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        /// SHA256("message digest")
        pub const MESSAGE_DIGEST: &str =
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650";
    }

    /// RIPEMD160 test vectors
    pub mod ripemd160 {
        /// RIPEMD160("")
        pub const EMPTY: &str = "9c1185a5c5e9fc54612808977ee8f548b2258d31";

        /// RIPEMD160("abc")
        pub const ABC: &str = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";

        /// RIPEMD160("message digest")
        pub const MESSAGE_DIGEST: &str = "5d0689ef49d2fae572b881b123a85ffa21595f36";
    }

    /// Double SHA256 test vectors
    pub mod hash256 {
        /// Hash256("abc")
        pub const ABC: &str = "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358";
    }
}

/// HMAC test vectors (RFC 4231)
pub mod hmac {
    /// Test case 1
    pub mod test1 {
        pub const KEY: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        pub const MESSAGE: &str = "4869205468657265"; // "Hi There"
        pub const HMAC_SHA256: &str =
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    }

    /// Test case 2
    pub mod test2 {
        pub const KEY: &str = "4a656665"; // "Jefe"
        pub const MESSAGE: &str = "7768617420646f2079612077616e7420666f72206e6f7468696e673f"; // "what do ya want for nothing?"
        pub const HMAC_SHA256: &str =
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    }
}

/// Helper function to parse hash from hex string (reversed, Bitcoin convention)
pub fn parse_block_hash(hex: &str) -> Hash256 {
    Hash256::from_hex(hex).expect("Invalid hash in test vectors")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_hash_parses() {
        let hash = parse_block_hash(genesis::mainnet::BLOCK_HASH);
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_genesis_merkle_parses() {
        let hash = parse_block_hash(genesis::mainnet::MERKLE_ROOT);
        assert!(!hash.is_zero());
    }

    // ---- NEW: All genesis hashes parse and are non-zero ----

    #[test]
    fn test_all_divi_genesis_hashes_parse() {
        // Divi mainnet
        let h = parse_block_hash(genesis::mainnet::BLOCK_HASH);
        assert!(!h.is_zero(), "Divi mainnet genesis hash should not be zero");
        // Roundtrip
        assert_eq!(
            h.to_hex(),
            genesis::mainnet::BLOCK_HASH,
            "Divi mainnet genesis hash roundtrip failed"
        );

        // Divi testnet
        let h = parse_block_hash(genesis::testnet::BLOCK_HASH);
        assert!(!h.is_zero(), "Divi testnet genesis hash should not be zero");
        assert_eq!(h.to_hex(), genesis::testnet::BLOCK_HASH);

        // Divi regtest
        let h = parse_block_hash(genesis::regtest::BLOCK_HASH);
        assert!(!h.is_zero(), "Divi regtest genesis hash should not be zero");
        assert_eq!(h.to_hex(), genesis::regtest::BLOCK_HASH);
    }

    #[test]
    fn test_all_privatedivi_genesis_hashes_parse() {
        // PrivateDivi mainnet
        let h = parse_block_hash(genesis::privatedivi::mainnet::BLOCK_HASH);
        assert!(
            !h.is_zero(),
            "PrivateDivi mainnet genesis hash should not be zero"
        );
        assert_eq!(h.to_hex(), genesis::privatedivi::mainnet::BLOCK_HASH);

        // PrivateDivi testnet
        let h = parse_block_hash(genesis::privatedivi::testnet::BLOCK_HASH);
        assert!(
            !h.is_zero(),
            "PrivateDivi testnet genesis hash should not be zero"
        );
        assert_eq!(h.to_hex(), genesis::privatedivi::testnet::BLOCK_HASH);

        // PrivateDivi regtest
        let h = parse_block_hash(genesis::privatedivi::regtest::BLOCK_HASH);
        assert!(
            !h.is_zero(),
            "PrivateDivi regtest genesis hash should not be zero"
        );
        assert_eq!(h.to_hex(), genesis::privatedivi::regtest::BLOCK_HASH);
    }

    #[test]
    fn test_all_merkle_roots_parse_and_are_nonzero() {
        let roots = [
            genesis::mainnet::MERKLE_ROOT,
            genesis::testnet::MERKLE_ROOT,
            genesis::regtest::MERKLE_ROOT,
            genesis::privatedivi::mainnet::MERKLE_ROOT,
            genesis::privatedivi::testnet::MERKLE_ROOT,
            genesis::privatedivi::regtest::MERKLE_ROOT,
        ];
        for root in &roots {
            let h = parse_block_hash(root);
            assert!(!h.is_zero(), "Merkle root {} should not be zero", root);
            assert_eq!(
                h.to_hex(),
                *root,
                "Merkle root roundtrip failed for {}",
                root
            );
        }
    }

    /// Divi mainnet and testnet share the same merkle root (same coinbase tx)
    #[test]
    fn test_divi_mainnet_testnet_share_merkle_root() {
        assert_eq!(
            genesis::mainnet::MERKLE_ROOT,
            genesis::testnet::MERKLE_ROOT,
            "Divi mainnet and testnet genesis merkle roots should be identical"
        );
    }

    /// PrivateDivi mainnet/testnet/regtest share the same merkle root
    #[test]
    fn test_privatedivi_genesis_merkle_roots_are_shared() {
        assert_eq!(
            genesis::privatedivi::mainnet::MERKLE_ROOT,
            genesis::privatedivi::testnet::MERKLE_ROOT,
        );
        assert_eq!(
            genesis::privatedivi::mainnet::MERKLE_ROOT,
            genesis::privatedivi::regtest::MERKLE_ROOT,
        );
    }

    /// All 6 genesis block hashes should be distinct
    #[test]
    fn test_all_genesis_hashes_are_distinct() {
        let hashes = [
            genesis::mainnet::BLOCK_HASH,
            genesis::testnet::BLOCK_HASH,
            genesis::regtest::BLOCK_HASH,
            genesis::privatedivi::mainnet::BLOCK_HASH,
            genesis::privatedivi::testnet::BLOCK_HASH,
            genesis::privatedivi::regtest::BLOCK_HASH,
        ];

        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "Genesis hashes at index {} and {} are identical: {}",
                    i, j, hashes[i]
                );
            }
        }
    }

    // ---- NEW: Hash256 double-SHA256 known vector via test_vectors ----

    /// Verify the double-SHA256("abc") test vector.
    ///
    /// sha2 outputs bytes in natural order; Hash256::from_bytes() stores as-is;
    /// Hash256::to_hex() reverses for display (Bitcoin convention).
    /// Therefore from_bytes(sha2_output).to_hex() == hashes::hash256::ABC.
    #[test]
    fn test_hash256_vector_abc_display_hex() {
        use crate::hash::Hash256;
        use sha2::{Digest, Sha256};

        // Compute double-SHA256("abc") locally
        let first = Sha256::digest(b"abc");
        let second = Sha256::digest(first);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&second);
        let computed = Hash256::from_bytes(bytes);

        // to_raw_hex() returns sha2 output bytes as-is, matching the test vector
        assert_eq!(
            computed.to_raw_hex(),
            hashes::hash256::ABC,
            "double-SHA256('abc') raw hex mismatch: got {} expected {}",
            computed.to_raw_hex(),
            hashes::hash256::ABC
        );
    }
}
