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

//! BIP38 private key encryption
//!
//! Implements BIP38 standard for encrypting Bitcoin/Divi private keys with a passphrase.
//! This provides secure paper wallet storage with password protection.
//!
//! Specification: https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

use crate::error::CryptoError;
use crate::hash::{double_sha256, hash160};
use crate::keys::{PublicKey, SecretKey};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::{Digest, Sha256};

/// BIP38 magic bytes for non-EC-multiply encrypted keys
const BIP38_MAGIC_NON_EC: [u8; 2] = [0x01, 0x42];

/// BIP38 flag byte for compressed keys
const BIP38_FLAG_COMPRESSED: u8 = 0xE0;

/// BIP38 flag byte for uncompressed keys
const BIP38_FLAG_UNCOMPRESSED: u8 = 0xC0;

/// Encrypt a private key using BIP38 with a passphrase
///
/// # Arguments
/// * `private_key` - 32-byte private key
/// * `passphrase` - User-provided passphrase for encryption
/// * `compressed` - Whether the corresponding public key should be compressed
///
/// # Returns
/// Base58Check-encoded encrypted private key starting with "6P"
pub fn encrypt(
    private_key: &[u8; 32],
    passphrase: &str,
    compressed: bool,
) -> Result<String, CryptoError> {
    // 1. Compute the public key and its address
    let secret = SecretKey::from_bytes(private_key)?;
    let pubkey = secret.public_key();

    // Compute the Divi address from the public key
    // This uses the standard P2PKH address format
    let address = compute_address(&pubkey, compressed);

    // 2. Take SHA256 hash of the address string to get addresshash
    let address_hash = Sha256::digest(address.as_bytes());
    let address_hash_prefix = &address_hash[0..4];

    // 3. Derive key material using scrypt
    // Parameters: N=16384, r=8, p=8, dkLen=64
    let params = ScryptParams::new(14, 8, 8, 64)
        .map_err(|e| CryptoError::Custom(format!("Invalid scrypt params: {}", e)))?;

    let mut derived = [0u8; 64];
    scrypt(
        passphrase.as_bytes(),
        address_hash_prefix,
        &params,
        &mut derived,
    )
    .map_err(|e| CryptoError::Custom(format!("scrypt failed: {}", e)))?;

    // Split derived key: first 32 bytes for XOR, last 32 bytes for AES
    let derivedhalf1 = &derived[0..32];
    let derivedhalf2 = &derived[32..64];

    // 4. XOR private key with derivedhalf1
    let mut encrypted_half1 = [0u8; 16];
    let mut encrypted_half2 = [0u8; 16];

    for i in 0..16 {
        encrypted_half1[i] = private_key[i] ^ derivedhalf1[i];
        encrypted_half2[i] = private_key[i + 16] ^ derivedhalf1[i + 16];
    }

    // 5. Encrypt using AES256 with derivedhalf2 as the key
    let cipher = Aes256::new_from_slice(derivedhalf2)
        .map_err(|e| CryptoError::Custom(format!("AES key error: {}", e)))?;

    let mut block1 = aes::Block::from(encrypted_half1);
    let mut block2 = aes::Block::from(encrypted_half2);

    cipher.encrypt_block(&mut block1);
    cipher.encrypt_block(&mut block2);

    // 6. Assemble the encrypted key
    let flag_byte = if compressed {
        BIP38_FLAG_COMPRESSED
    } else {
        BIP38_FLAG_UNCOMPRESSED
    };

    let mut result = Vec::with_capacity(39);
    result.extend_from_slice(&BIP38_MAGIC_NON_EC);
    result.push(flag_byte);
    result.extend_from_slice(address_hash_prefix);
    result.extend_from_slice(&block1);
    result.extend_from_slice(&block2);

    // 7. Base58Check encode
    let checksum = double_sha256(&result);
    result.extend_from_slice(&checksum[0..4]);

    Ok(bs58::encode(result).into_string())
}

/// Decrypt a BIP38 encrypted private key
///
/// # Arguments
/// * `encrypted` - Base58Check-encoded encrypted key (starts with "6P")
/// * `passphrase` - User-provided passphrase for decryption
///
/// # Returns
/// Tuple of (private_key, compressed) where compressed indicates key format
pub fn decrypt(encrypted: &str, passphrase: &str) -> Result<([u8; 32], bool), CryptoError> {
    // 1. Base58Check decode
    let data = bs58::decode(encrypted)
        .into_vec()
        .map_err(|e| CryptoError::Custom(format!("Invalid base58: {}", e)))?;

    if data.len() != 43 {
        return Err(CryptoError::Custom(format!(
            "Invalid BIP38 key length: {} (expected 43)",
            data.len()
        )));
    }

    // Verify checksum
    let checksum = double_sha256(&data[0..39]);
    if checksum[0..4] != data[39..43] {
        return Err(CryptoError::Custom("Invalid BIP38 checksum".into()));
    }

    // 2. Verify magic bytes
    if data[0..2] != BIP38_MAGIC_NON_EC {
        return Err(CryptoError::Custom("Invalid BIP38 magic bytes".into()));
    }

    // 3. Parse flag byte
    let flag_byte = data[2];
    let compressed = match flag_byte {
        BIP38_FLAG_COMPRESSED => true,
        BIP38_FLAG_UNCOMPRESSED => false,
        _ => {
            return Err(CryptoError::Custom(format!(
                "Invalid BIP38 flag byte: 0x{:02X}",
                flag_byte
            )))
        }
    };

    // 4. Extract components
    let address_hash = &data[3..7];
    let encrypted_half1 = &data[7..23];
    let encrypted_half2 = &data[23..39];

    // 5. Derive key material using scrypt
    let params = ScryptParams::new(14, 8, 8, 64)
        .map_err(|e| CryptoError::Custom(format!("Invalid scrypt params: {}", e)))?;

    let mut derived = [0u8; 64];
    scrypt(passphrase.as_bytes(), address_hash, &params, &mut derived)
        .map_err(|e| CryptoError::Custom(format!("scrypt failed: {}", e)))?;

    let derivedhalf1 = &derived[0..32];
    let derivedhalf2 = &derived[32..64];

    // 6. Decrypt using AES256
    let cipher = Aes256::new_from_slice(derivedhalf2)
        .map_err(|e| CryptoError::Custom(format!("AES key error: {}", e)))?;

    let mut block1 = aes::Block::clone_from_slice(encrypted_half1);
    let mut block2 = aes::Block::clone_from_slice(encrypted_half2);

    cipher.decrypt_block(&mut block1);
    cipher.decrypt_block(&mut block2);

    // 7. XOR with derivedhalf1 to recover private key
    let mut private_key = [0u8; 32];
    for i in 0..16 {
        private_key[i] = block1[i] ^ derivedhalf1[i];
        private_key[i + 16] = block2[i] ^ derivedhalf1[i + 16];
    }

    // 8. Verify the decryption was successful by checking address hash
    let secret = SecretKey::from_bytes(&private_key)?;
    let pubkey = secret.public_key();
    let address = compute_address(&pubkey, compressed);

    let verification_hash = Sha256::digest(address.as_bytes());
    if verification_hash[0..4] != address_hash[0..4] {
        return Err(CryptoError::Custom(
            "Incorrect passphrase or corrupted data".into(),
        ));
    }

    Ok((private_key, compressed))
}

/// Compute the Divi address string from a public key
///
/// This is used for BIP38's address hash verification.
/// Uses Divi mainnet P2PKH address format.
fn compute_address(pubkey: &PublicKey, compressed: bool) -> String {
    // Get the appropriate public key format
    let pubkey_bytes = if compressed {
        pubkey.serialize_compressed().to_vec()
    } else {
        pubkey.serialize_uncompressed().to_vec()
    };

    // Hash160 (RIPEMD160(SHA256(pubkey)))
    let pubkey_hash = hash160(&pubkey_bytes);

    // Build address: version_byte + hash160 + checksum
    // Divi mainnet P2PKH version byte is 30 (produces addresses starting with 'D')
    const DIVI_PUBKEY_VERSION: u8 = 30;

    let mut addr_data = vec![DIVI_PUBKEY_VERSION];
    addr_data.extend_from_slice(pubkey_hash.as_bytes());

    let checksum = double_sha256(&addr_data);
    addr_data.extend_from_slice(&checksum[0..4]);

    bs58::encode(addr_data).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip38_roundtrip_compressed() {
        // Test with a known private key
        let private_key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let passphrase = "test passphrase";

        // Encrypt
        let encrypted = encrypt(&private_key, passphrase, true).unwrap();
        assert!(encrypted.starts_with("6P"));

        // Decrypt
        let (decrypted, compressed) = decrypt(&encrypted, passphrase).unwrap();

        assert_eq!(private_key, decrypted);
        assert!(compressed);
    }

    #[test]
    fn test_bip38_roundtrip_uncompressed() {
        let private_key = [
            0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
            0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05,
            0x04, 0x03, 0x02, 0x01,
        ];
        let passphrase = "another test";

        let encrypted = encrypt(&private_key, passphrase, false).unwrap();
        assert!(encrypted.starts_with("6P"));

        let (decrypted, compressed) = decrypt(&encrypted, passphrase).unwrap();

        assert_eq!(private_key, decrypted);
        assert!(!compressed);
    }

    #[test]
    fn test_bip38_wrong_passphrase() {
        let private_key = [0x42; 32];
        let passphrase = "correct passphrase";

        let encrypted = encrypt(&private_key, passphrase, true).unwrap();

        // Try to decrypt with wrong passphrase
        let result = decrypt(&encrypted, "wrong passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_bip38_invalid_format() {
        // Test with invalid base58
        let result = decrypt("invalid", "passphrase");
        assert!(result.is_err());

        // Test with wrong length
        let result = decrypt("6PRV", "passphrase");
        assert!(result.is_err());
    }

    // BIP38 test vector 1: No compression, no EC multiply
    #[test]
    fn test_bip38_vector_1() {
        // Test vector from BIP38
        // Private key: 5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR (uncompressed WIF)
        // Passphrase: "TestingOneTwoThree"
        // Expected: 6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg

        // This is the private key from the WIF (decoded)
        let private_key =
            hex::decode("CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5")
                .unwrap();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_key);

        let passphrase = "TestingOneTwoThree";

        let encrypted = encrypt(&key_bytes, passphrase, false).unwrap();

        // The exact encrypted value depends on the address format
        // We verify round-trip instead
        let (decrypted, compressed) = decrypt(&encrypted, passphrase).unwrap();
        assert_eq!(key_bytes, decrypted);
        assert!(!compressed);
    }

    // BIP38 test vector 2: Compression, no EC multiply
    #[test]
    fn test_bip38_vector_2() {
        // Private key: L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP (compressed WIF)
        // Passphrase: "Satoshi"
        // Expected: 6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo

        let private_key =
            hex::decode("09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE")
                .unwrap();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_key);

        let passphrase = "Satoshi";

        let encrypted = encrypt(&key_bytes, passphrase, true).unwrap();

        let (decrypted, compressed) = decrypt(&encrypted, passphrase).unwrap();
        assert_eq!(key_bytes, decrypted);
        assert!(compressed);
    }

    // --- Empty passphrase ---

    #[test]
    fn test_bip38_empty_passphrase_compressed() {
        // BIP38 is agnostic about passphrase content; empty string must work.
        let private_key = [0x11u8; 32];
        let passphrase = "";

        let encrypted = encrypt(&private_key, passphrase, true).unwrap();
        assert!(
            encrypted.starts_with("6P"),
            "BIP38 ciphertext must start with '6P'"
        );

        let (decrypted, compressed) = decrypt(&encrypted, passphrase).unwrap();
        assert_eq!(private_key, decrypted);
        assert!(compressed);
    }

    #[test]
    fn test_bip38_empty_passphrase_uncompressed() {
        let private_key = [0x22u8; 32];
        let passphrase = "";

        let encrypted = encrypt(&private_key, passphrase, false).unwrap();
        let (decrypted, compressed) = decrypt(&encrypted, passphrase).unwrap();
        assert_eq!(private_key, decrypted);
        assert!(!compressed);
    }

    #[test]
    fn test_bip38_empty_passphrase_wrong_passphrase_rejected() {
        // Encrypting with empty passphrase and decrypting with non-empty must fail
        let private_key = [0x33u8; 32];
        let encrypted = encrypt(&private_key, "", true).unwrap();
        let result = decrypt(&encrypted, "notEmpty");
        assert!(result.is_err());
    }

    // --- Encrypted output always starts with "6P" ---

    #[test]
    fn test_bip38_output_prefix() {
        // BIP38 spec requires Base58Check output to start with "6P"
        let key = [0x55u8; 32];
        assert!(encrypt(&key, "abc", true).unwrap().starts_with("6P"));
        assert!(encrypt(&key, "abc", false).unwrap().starts_with("6P"));
    }

    // --- Different passphrases produce different ciphertexts ---

    #[test]
    fn test_bip38_different_passphrases_different_ciphertext() {
        let key = [0x77u8; 32];
        let enc1 = encrypt(&key, "passA", true).unwrap();
        let enc2 = encrypt(&key, "passB", true).unwrap();
        assert_ne!(enc1, enc2);
    }
}
