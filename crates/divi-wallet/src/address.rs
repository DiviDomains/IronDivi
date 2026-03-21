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

//! Divi address types and encoding
//!
//! Implements Base58Check address encoding for Divi addresses.
//! - P2PKH addresses start with 'D' (mainnet)
//! - P2SH addresses start with 'S' (mainnet)

use crate::error::WalletError;
use divi_crypto::hash160;
use divi_crypto::keys::PublicKey;
use divi_primitives::hash::Hash160;
use sha2::{Digest, Sha256};

/// Divi mainnet P2PKH version byte
pub const PUBKEY_ADDRESS_VERSION: u8 = 30; // 'D'

/// Divi mainnet P2SH version byte
pub const SCRIPT_ADDRESS_VERSION: u8 = 13; // 'S'

/// Divi testnet P2PKH version byte
pub const PUBKEY_ADDRESS_VERSION_TESTNET: u8 = 139;

/// Divi testnet P2SH version byte
pub const SCRIPT_ADDRESS_VERSION_TESTNET: u8 = 19;

/// WIF private key version byte (mainnet)
pub const WIF_VERSION_MAINNET: u8 = 212; // Divi mainnet WIF

/// WIF private key version byte (testnet/regtest)
pub const WIF_VERSION_TESTNET: u8 = 239; // Divi testnet/regtest WIF

/// Address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Pay to public key hash
    P2PKH,
    /// Pay to script hash
    P2SH,
}

/// Network type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Mainnet
    Mainnet,
    /// Testnet
    Testnet,
    /// Regtest (regression test mode)
    Regtest,
}

/// A Divi address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Address type
    pub addr_type: AddressType,
    /// Network
    pub network: Network,
    /// 20-byte hash (pubkey hash or script hash)
    pub hash: Hash160,
}

impl Address {
    /// Create a P2PKH address from a public key
    pub fn p2pkh(pubkey: &PublicKey, network: Network) -> Self {
        let pubkey_bytes = pubkey.to_bytes();
        let hash = hash160(&pubkey_bytes);
        Address {
            addr_type: AddressType::P2PKH,
            network,
            hash,
        }
    }

    /// Create a P2SH address from a script hash
    pub fn p2sh(script_hash: Hash160, network: Network) -> Self {
        Address {
            addr_type: AddressType::P2SH,
            network,
            hash: script_hash,
        }
    }

    /// Create a P2PKH address from a pubkey hash
    pub fn from_pubkey_hash(hash: Hash160, network: Network) -> Self {
        Address {
            addr_type: AddressType::P2PKH,
            network,
            hash,
        }
    }

    /// Get the version byte for this address
    pub fn version_byte(&self) -> u8 {
        match (self.addr_type, self.network) {
            (AddressType::P2PKH, Network::Mainnet) => PUBKEY_ADDRESS_VERSION,
            (AddressType::P2PKH, Network::Testnet) => PUBKEY_ADDRESS_VERSION_TESTNET,
            (AddressType::P2PKH, Network::Regtest) => PUBKEY_ADDRESS_VERSION_TESTNET, // Regtest uses testnet prefixes
            (AddressType::P2SH, Network::Mainnet) => SCRIPT_ADDRESS_VERSION,
            (AddressType::P2SH, Network::Testnet) => SCRIPT_ADDRESS_VERSION_TESTNET,
            (AddressType::P2SH, Network::Regtest) => SCRIPT_ADDRESS_VERSION_TESTNET, // Regtest uses testnet prefixes
        }
    }

    /// Encode as Base58Check string
    pub fn to_base58(&self) -> String {
        let mut data = vec![self.version_byte()];
        data.extend_from_slice(self.hash.as_bytes());

        // Double SHA256 checksum
        let checksum = double_sha256(&data);
        data.extend_from_slice(&checksum[0..4]);

        bs58::encode(data).into_string()
    }

    /// Decode from Base58Check string
    pub fn from_base58(s: &str) -> Result<Self, WalletError> {
        let data = bs58::decode(s)
            .into_vec()
            .map_err(|e| WalletError::AddressNotFound(format!("Invalid base58: {}", e)))?;

        if data.len() != 25 {
            return Err(WalletError::AddressNotFound(format!(
                "Invalid address length: {}",
                data.len()
            )));
        }

        // Verify checksum
        let checksum = double_sha256(&data[0..21]);
        if checksum[0..4] != data[21..25] {
            return Err(WalletError::AddressNotFound("Invalid checksum".into()));
        }

        let version = data[0];
        let (addr_type, network) = match version {
            PUBKEY_ADDRESS_VERSION => (AddressType::P2PKH, Network::Mainnet),
            PUBKEY_ADDRESS_VERSION_TESTNET => (AddressType::P2PKH, Network::Testnet),
            SCRIPT_ADDRESS_VERSION => (AddressType::P2SH, Network::Mainnet),
            SCRIPT_ADDRESS_VERSION_TESTNET => (AddressType::P2SH, Network::Testnet),
            _ => {
                return Err(WalletError::AddressNotFound(format!(
                    "Unknown address version: {}",
                    version
                )))
            }
        };

        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&data[1..21]);

        Ok(Address {
            addr_type,
            network,
            hash: Hash160::from_bytes(hash_bytes),
        })
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl std::str::FromStr for Address {
    type Err = WalletError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_base58(s)
    }
}

/// Double SHA256 hash
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Decoded WIF private key
pub struct WifKey {
    /// The 32-byte private key
    pub key_bytes: [u8; 32],
    /// Whether this is a compressed key
    pub compressed: bool,
    /// Network (Mainnet, Testnet, or Regtest)
    pub network: Network,
}

/// Decode a WIF (Wallet Import Format) private key
///
/// WIF format:
/// - Version byte (1 byte): 212 for Divi mainnet, 239 for testnet/regtest
/// - Private key (32 bytes)
/// - Optional compression flag (1 byte): 0x01 if compressed
/// - Checksum (4 bytes): first 4 bytes of double SHA256 of the above
pub fn decode_wif(wif: &str) -> Result<WifKey, WalletError> {
    let data = bs58::decode(wif)
        .into_vec()
        .map_err(|e| WalletError::InvalidKey(format!("Invalid WIF base58: {}", e)))?;

    // WIF is either 37 bytes (uncompressed) or 38 bytes (compressed)
    if data.len() != 37 && data.len() != 38 {
        return Err(WalletError::InvalidKey(format!(
            "Invalid WIF length: {} (expected 37 or 38)",
            data.len()
        )));
    }

    let compressed = data.len() == 38;
    let payload_len = if compressed { 34 } else { 33 };

    // Verify checksum
    let checksum = double_sha256(&data[0..payload_len]);
    if checksum[0..4] != data[payload_len..payload_len + 4] {
        return Err(WalletError::InvalidKey("Invalid WIF checksum".into()));
    }

    // Check compression flag if present
    if compressed && data[33] != 0x01 {
        return Err(WalletError::InvalidKey(format!(
            "Invalid compression flag: {} (expected 0x01)",
            data[33]
        )));
    }

    // Determine network from version byte
    let network = match data[0] {
        WIF_VERSION_MAINNET => Network::Mainnet,
        WIF_VERSION_TESTNET => Network::Testnet, // Also used for regtest
        _ => {
            return Err(WalletError::InvalidKey(format!(
                "Unknown WIF version byte: {}",
                data[0]
            )))
        }
    };

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&data[1..33]);

    Ok(WifKey {
        key_bytes,
        compressed,
        network,
    })
}

/// Encode a private key to WIF format
pub fn encode_wif(key_bytes: &[u8; 32], compressed: bool, network: Network) -> String {
    let version = match network {
        Network::Mainnet => WIF_VERSION_MAINNET,
        Network::Testnet | Network::Regtest => WIF_VERSION_TESTNET,
    };

    let mut data = vec![version];
    data.extend_from_slice(key_bytes);
    if compressed {
        data.push(0x01);
    }

    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[0..4]);

    bs58::encode(data).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_crypto::keys::SecretKey;

    #[test]
    fn test_p2pkh_address() {
        // Generate a key and create address
        let secret = SecretKey::new_random();
        let pubkey = secret.public_key();
        let addr = Address::p2pkh(&pubkey, Network::Mainnet);

        assert_eq!(addr.addr_type, AddressType::P2PKH);
        assert_eq!(addr.network, Network::Mainnet);
    }

    #[test]
    fn test_address_roundtrip() {
        let secret = SecretKey::new_random();
        let pubkey = secret.public_key();
        let addr = Address::p2pkh(&pubkey, Network::Mainnet);

        let encoded = addr.to_base58();
        let decoded = Address::from_base58(&encoded).unwrap();

        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_mainnet_address_prefix() {
        let secret = SecretKey::new_random();
        let pubkey = secret.public_key();
        let addr = Address::p2pkh(&pubkey, Network::Mainnet);
        let encoded = addr.to_base58();

        // Mainnet P2PKH addresses start with 'D'
        assert!(encoded.starts_with('D'));
    }

    #[test]
    fn test_testnet_address_prefix() {
        let secret = SecretKey::new_random();
        let pubkey = secret.public_key();
        let addr = Address::p2pkh(&pubkey, Network::Testnet);
        let encoded = addr.to_base58();

        // Testnet addresses start with different letter
        assert!(!encoded.starts_with('D'));
    }

    #[test]
    fn test_invalid_checksum() {
        let secret = SecretKey::new_random();
        let pubkey = secret.public_key();
        let addr = Address::p2pkh(&pubkey, Network::Mainnet);
        let encoded = addr.to_base58();

        // Corrupt the last character
        let mut chars: Vec<char> = encoded.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let corrupted: String = chars.into_iter().collect();

        assert!(Address::from_base58(&corrupted).is_err());
    }

    #[test]
    fn test_address_display() {
        let secret = SecretKey::new_random();
        let pubkey = secret.public_key();
        let addr = Address::p2pkh(&pubkey, Network::Mainnet);

        let display = format!("{}", addr);
        assert_eq!(display, addr.to_base58());
    }

    #[test]
    fn test_address_from_str() {
        let secret = SecretKey::new_random();
        let pubkey = secret.public_key();
        let addr = Address::p2pkh(&pubkey, Network::Mainnet);
        let encoded = addr.to_base58();

        let parsed: Address = encoded.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    // -------- Version byte values --------

    #[test]
    fn test_p2pkh_mainnet_version_byte_is_30() {
        // 0x1e == 30 decimal
        assert_eq!(PUBKEY_ADDRESS_VERSION, 30);
        let hash = Hash160::from_bytes([0u8; 20]);
        let addr = Address::from_pubkey_hash(hash, Network::Mainnet);
        assert_eq!(addr.version_byte(), 30);
    }

    #[test]
    fn test_p2pkh_testnet_version_byte_is_139() {
        // 0x8b == 139 decimal (listed as 0x8c in some docs – match the constant)
        assert_eq!(PUBKEY_ADDRESS_VERSION_TESTNET, 139);
        let hash = Hash160::from_bytes([0u8; 20]);
        let addr = Address::from_pubkey_hash(hash, Network::Testnet);
        assert_eq!(addr.version_byte(), 139);
    }

    #[test]
    fn test_p2sh_mainnet_version_byte_is_13() {
        // 0x0d == 13 decimal
        assert_eq!(SCRIPT_ADDRESS_VERSION, 13);
        let hash = Hash160::from_bytes([0u8; 20]);
        let addr = Address::p2sh(hash, Network::Mainnet);
        assert_eq!(addr.version_byte(), 13);
    }

    #[test]
    fn test_p2sh_testnet_version_byte_is_19() {
        // 0x13 == 19 decimal
        assert_eq!(SCRIPT_ADDRESS_VERSION_TESTNET, 19);
        let hash = Hash160::from_bytes([0u8; 20]);
        let addr = Address::p2sh(hash, Network::Testnet);
        assert_eq!(addr.version_byte(), 19);
    }

    // -------- P2SH address encoding --------

    #[test]
    fn test_p2sh_mainnet_roundtrip() {
        let hash = Hash160::from_bytes([0xabu8; 20]);
        let addr = Address::p2sh(hash, Network::Mainnet);
        assert_eq!(addr.addr_type, AddressType::P2SH);
        assert_eq!(addr.network, Network::Mainnet);

        let encoded = addr.to_base58();
        let decoded = Address::from_base58(&encoded).unwrap();
        assert_eq!(decoded.addr_type, AddressType::P2SH);
        assert_eq!(decoded.network, Network::Mainnet);
        assert_eq!(decoded.hash, hash);
    }

    #[test]
    fn test_p2sh_testnet_roundtrip() {
        let hash = Hash160::from_bytes([0x55u8; 20]);
        let addr = Address::p2sh(hash, Network::Testnet);
        let encoded = addr.to_base58();
        let decoded = Address::from_base58(&encoded).unwrap();
        assert_eq!(decoded.addr_type, AddressType::P2SH);
        assert_eq!(decoded.network, Network::Testnet);
        assert_eq!(decoded.hash, hash);
    }

    #[test]
    fn test_unknown_version_byte_rejected() {
        // Build a raw 25-byte payload with an unknown version byte
        let mut data = vec![0xffu8]; // unknown version
        data.extend_from_slice(&[0u8; 20]);
        let checksum = double_sha256(&data[0..21]);
        data.extend_from_slice(&checksum[0..4]);
        let encoded = bs58::encode(data).into_string();

        assert!(Address::from_base58(&encoded).is_err());
    }

    #[test]
    fn test_wrong_length_rejected() {
        // A string that decodes to fewer than 25 bytes
        let short_data = vec![0x1eu8; 10]; // too short
        let encoded = bs58::encode(short_data).into_string();
        assert!(Address::from_base58(&encoded).is_err());
    }

    // -------- WIF encode / decode --------

    #[test]
    fn test_wif_mainnet_roundtrip() {
        let key_bytes = [0x12u8; 32];
        let wif = encode_wif(&key_bytes, true, Network::Mainnet);
        let decoded = decode_wif(&wif).unwrap();
        assert_eq!(decoded.key_bytes, key_bytes);
        assert!(decoded.compressed);
        assert!(matches!(decoded.network, Network::Mainnet));
    }

    #[test]
    fn test_wif_testnet_roundtrip() {
        let key_bytes = [0x34u8; 32];
        let wif = encode_wif(&key_bytes, false, Network::Testnet);
        let decoded = decode_wif(&wif).unwrap();
        assert_eq!(decoded.key_bytes, key_bytes);
        assert!(!decoded.compressed);
        assert!(matches!(decoded.network, Network::Testnet));
    }

    #[test]
    fn test_wif_mainnet_version_byte() {
        assert_eq!(WIF_VERSION_MAINNET, 212);
    }

    #[test]
    fn test_wif_testnet_version_byte() {
        assert_eq!(WIF_VERSION_TESTNET, 239);
    }

    #[test]
    fn test_wif_invalid_checksum_rejected() {
        let key_bytes = [0xabu8; 32];
        let mut wif = encode_wif(&key_bytes, true, Network::Mainnet);
        // Flip a character near the end to corrupt the checksum
        let mut chars: Vec<char> = wif.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
        wif = chars.into_iter().collect();
        assert!(decode_wif(&wif).is_err());
    }

    #[test]
    fn test_regtest_uses_testnet_prefix() {
        let hash = Hash160::from_bytes([0x11u8; 20]);
        let addr_testnet = Address::from_pubkey_hash(hash, Network::Testnet);
        let addr_regtest = Address::from_pubkey_hash(hash, Network::Regtest);
        // Both should produce the same version byte (testnet prefix)
        assert_eq!(addr_testnet.version_byte(), addr_regtest.version_byte());
        assert_eq!(addr_testnet.to_base58(), addr_regtest.to_base58());
    }
}
