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
//!
//! The address hash is the double SHA-256 of the key's P2PKH address on the
//! network the key is used on (`pubkey_version`), as in the specification and
//! in Divi Core (bip38.cpp AddressToBip38Hash), so keys encrypted by divid's
//! bip38paperwallet decrypt here and the other way round.

use crate::error::CryptoError;
use crate::hash::{double_sha256, hash160};
use crate::keys::{PublicKey, SecretKey};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use scrypt::{scrypt, Params as ScryptParams};

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
/// * `pubkey_version` - The P2PKH address version byte of the network
///
/// # Returns
/// Base58Check-encoded encrypted private key starting with "6P"
pub fn encrypt(
    private_key: &[u8; 32],
    passphrase: &str,
    compressed: bool,
    pubkey_version: u8,
) -> Result<String, CryptoError> {
    // 1. Compute the public key and its address
    let secret = SecretKey::from_bytes(private_key)?;
    let pubkey = secret.public_key();

    // Compute the Divi address from the public key
    // This uses the standard P2PKH address format
    let address = compute_address(&pubkey, compressed, pubkey_version);

    // 2. addresshash: the first 4 bytes of SHA256(SHA256(address))
    let address_hash = double_sha256(address.as_bytes());
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
/// * `pubkey_version` - The P2PKH address version byte of the network, for the
///   address hash check
///
/// # Returns
/// Tuple of (private_key, compressed) where compressed indicates key format
pub fn decrypt(
    encrypted: &str,
    passphrase: &str,
    pubkey_version: u8,
) -> Result<([u8; 32], bool), CryptoError> {
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
    let address = compute_address(&pubkey, compressed, pubkey_version);

    let verification_hash = double_sha256(address.as_bytes());
    if verification_hash[0..4] != address_hash[0..4] {
        return Err(CryptoError::Custom(
            "Incorrect passphrase or corrupted data".into(),
        ));
    }

    Ok((private_key, compressed))
}

/// The P2PKH address string of a public key for the network whose address
/// version byte is `pubkey_version`, as BIP38's address hash takes it
fn compute_address(pubkey: &PublicKey, compressed: bool, pubkey_version: u8) -> String {
    // Get the appropriate public key format
    let pubkey_bytes = if compressed {
        pubkey.serialize_compressed().to_vec()
    } else {
        pubkey.serialize_uncompressed().to_vec()
    };

    // Hash160 (RIPEMD160(SHA256(pubkey)))
    let pubkey_hash = hash160(&pubkey_bytes);

    // Build address: version_byte + hash160 + checksum
    let mut addr_data = vec![pubkey_version];
    addr_data.extend_from_slice(pubkey_hash.as_bytes());

    let checksum = double_sha256(&addr_data);
    addr_data.extend_from_slice(&checksum[0..4]);

    bs58::encode(addr_data).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Divi mainnet's P2PKH address version
    const D: u8 = 30;

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
        let encrypted = encrypt(&private_key, passphrase, true, D).unwrap();
        assert!(encrypted.starts_with("6P"));

        // Decrypt
        let (decrypted, compressed) = decrypt(&encrypted, passphrase, D).unwrap();

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

        let encrypted = encrypt(&private_key, passphrase, false, D).unwrap();
        assert!(encrypted.starts_with("6P"));

        let (decrypted, compressed) = decrypt(&encrypted, passphrase, D).unwrap();

        assert_eq!(private_key, decrypted);
        assert!(!compressed);
    }

    #[test]
    fn test_bip38_wrong_passphrase() {
        let private_key = [0x42; 32];
        let passphrase = "correct passphrase";

        let encrypted = encrypt(&private_key, passphrase, true, D).unwrap();

        // Try to decrypt with wrong passphrase
        let result = decrypt(&encrypted, "wrong passphrase", D);
        assert!(result.is_err());
    }

    #[test]
    fn test_bip38_invalid_format() {
        // Test with invalid base58
        let result = decrypt("invalid", "passphrase", D);
        assert!(result.is_err());

        // Test with wrong length
        let result = decrypt("6PRV", "passphrase", D);
        assert!(result.is_err());
    }

    /// The test vectors of the BIP38 specification without EC multiply
    /// (Bitcoin addresses, version 0): the exact ciphertexts, and back
    #[test]
    fn bip38_specification_vectors() {
        let cbf4 = "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5";
        let c268 = "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE";
        for (key, passphrase, compressed, expected) in [
            (
                cbf4,
                "TestingOneTwoThree",
                false,
                "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
            ),
            (
                c268,
                "Satoshi",
                false,
                "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
            ),
            (
                cbf4,
                "TestingOneTwoThree",
                true,
                "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
            ),
            (
                c268,
                "Satoshi",
                true,
                "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
            ),
        ] {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hex::decode(key).unwrap());
            assert_eq!(
                encrypt(&bytes, passphrase, compressed, 0).unwrap(),
                expected,
                "{passphrase} {compressed}"
            );
            assert_eq!(
                decrypt(expected, passphrase, 0).unwrap(),
                (bytes, compressed),
                "{passphrase} {compressed}"
            );
        }
    }

    /// The address hash belongs to the network: a key encrypted for one does not
    /// pass the check on another
    #[test]
    fn address_hash_is_the_networks() {
        let key = [0x42u8; 32];
        let regtest = encrypt(&key, "pw", true, 139).unwrap();
        assert_eq!(decrypt(&regtest, "pw", 139).unwrap(), (key, true));
        assert!(decrypt(&regtest, "pw", D).is_err());
    }

    // --- Empty passphrase ---

    #[test]
    fn test_bip38_empty_passphrase_compressed() {
        // BIP38 is agnostic about passphrase content; empty string must work.
        let private_key = [0x11u8; 32];
        let passphrase = "";

        let encrypted = encrypt(&private_key, passphrase, true, D).unwrap();
        assert!(
            encrypted.starts_with("6P"),
            "BIP38 ciphertext must start with '6P'"
        );

        let (decrypted, compressed) = decrypt(&encrypted, passphrase, D).unwrap();
        assert_eq!(private_key, decrypted);
        assert!(compressed);
    }

    #[test]
    fn test_bip38_empty_passphrase_uncompressed() {
        let private_key = [0x22u8; 32];
        let passphrase = "";

        let encrypted = encrypt(&private_key, passphrase, false, D).unwrap();
        let (decrypted, compressed) = decrypt(&encrypted, passphrase, D).unwrap();
        assert_eq!(private_key, decrypted);
        assert!(!compressed);
    }

    #[test]
    fn test_bip38_empty_passphrase_wrong_passphrase_rejected() {
        // Encrypting with empty passphrase and decrypting with non-empty must fail
        let private_key = [0x33u8; 32];
        let encrypted = encrypt(&private_key, "", true, D).unwrap();
        let result = decrypt(&encrypted, "notEmpty", D);
        assert!(result.is_err());
    }

    // --- Encrypted output always starts with "6P" ---

    #[test]
    fn test_bip38_output_prefix() {
        // BIP38 spec requires Base58Check output to start with "6P"
        let key = [0x55u8; 32];
        assert!(encrypt(&key, "abc", true, D).unwrap().starts_with("6P"));
        assert!(encrypt(&key, "abc", false, D).unwrap().starts_with("6P"));
    }

    // --- Different passphrases produce different ciphertexts ---

    #[test]
    fn test_bip38_different_passphrases_different_ciphertext() {
        let key = [0x77u8; 32];
        let enc1 = encrypt(&key, "passA", true, D).unwrap();
        let enc2 = encrypt(&key, "passB", true, D).unwrap();
        assert_ne!(enc1, enc2);
    }
}
