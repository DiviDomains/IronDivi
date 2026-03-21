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

//! ECDSA key management for Divi
//!
//! Divi uses secp256k1 ECDSA, the same as Bitcoin.

use crate::error::CryptoError;
use crate::hash::{double_sha256, hash160};
use divi_primitives::hash::Hash160;
use secp256k1::{Message, Secp256k1};
use std::fmt;

/// A secp256k1 secret key (32 bytes)
#[derive(Clone)]
pub struct SecretKey {
    inner: secp256k1::SecretKey,
}

impl SecretKey {
    /// Generate a new random secret key
    pub fn new_random() -> Self {
        let secp = Secp256k1::new();
        let (sk, _pk) = secp.generate_keypair(&mut rand::thread_rng());
        SecretKey { inner: sk }
    }

    /// Create a secret key from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: data.len(),
            });
        }
        let sk = secp256k1::SecretKey::from_slice(data)?;
        Ok(SecretKey { inner: sk })
    }

    /// Create a secret key from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Get the raw bytes of this secret key
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_ref()
    }

    /// Export as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Get the public key corresponding to this secret key
    pub fn public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &self.inner);
        PublicKey { inner: pk }
    }

    /// Get the inner secp256k1 secret key
    pub(crate) fn inner(&self) -> &secp256k1::SecretKey {
        &self.inner
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't expose secret key bytes in debug output
        f.debug_struct("SecretKey")
            .field("pubkey", &self.public_key().to_hex())
            .finish()
    }
}

/// A secp256k1 public key
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: secp256k1::PublicKey,
}

impl PublicKey {
    /// Create a public key from compressed format (33 bytes)
    pub fn from_compressed(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != 33 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 33,
                actual: data.len(),
            });
        }
        let pk = secp256k1::PublicKey::from_slice(data)?;
        Ok(PublicKey { inner: pk })
    }

    /// Create a public key from uncompressed format (65 bytes)
    pub fn from_uncompressed(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != 65 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 65,
                actual: data.len(),
            });
        }
        let pk = secp256k1::PublicKey::from_slice(data)?;
        Ok(PublicKey { inner: pk })
    }

    /// Create from either compressed or uncompressed bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        let pk = secp256k1::PublicKey::from_slice(data)?;
        Ok(PublicKey { inner: pk })
    }

    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Get the compressed public key (33 bytes)
    pub fn serialize_compressed(&self) -> [u8; 33] {
        self.inner.serialize()
    }

    /// Get the uncompressed public key (65 bytes)
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        self.inner.serialize_uncompressed()
    }

    /// Get compressed format as Vec
    pub fn to_bytes(&self) -> Vec<u8> {
        self.serialize_compressed().to_vec()
    }

    /// Export as hex string (compressed format)
    pub fn to_hex(&self) -> String {
        hex::encode(self.serialize_compressed())
    }

    /// Get the Hash160 of this public key (for P2PKH addresses)
    pub fn pubkey_hash(&self) -> Hash160 {
        hash160(&self.serialize_compressed())
    }

    /// Get the inner secp256k1 public key
    pub(crate) fn inner(&self) -> &secp256k1::PublicKey {
        &self.inner
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("compressed", &self.to_hex())
            .finish()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A key pair (secret key + public key)
#[derive(Clone)]
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn new_random() -> Self {
        let secret = SecretKey::new_random();
        let public = secret.public_key();
        KeyPair { secret, public }
    }

    /// Create a key pair from a secret key
    pub fn from_secret_key(secret: SecretKey) -> Self {
        let public = secret.public_key();
        KeyPair { secret, public }
    }

    /// Create from raw secret key bytes
    pub fn from_secret_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        let secret = SecretKey::from_bytes(data)?;
        Ok(Self::from_secret_key(secret))
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public.to_hex())
            .finish()
    }
}

/// Create a message hash for signing (double SHA256)
pub fn message_hash(data: &[u8]) -> Message {
    let hash = double_sha256(data);
    Message::from_digest(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_generation() {
        let sk = SecretKey::new_random();
        assert_eq!(sk.as_bytes().len(), 32);

        // Should generate different keys
        let sk2 = SecretKey::new_random();
        assert_ne!(sk.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_secret_key_from_bytes() {
        let bytes = [1u8; 32];
        let sk = SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.as_bytes(), &bytes);
    }

    #[test]
    fn test_secret_key_hex_roundtrip() {
        let sk = SecretKey::new_random();
        let hex_str = sk.to_hex();
        let sk2 = SecretKey::from_hex(&hex_str).unwrap();
        assert_eq!(sk.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_public_key_from_secret() {
        let sk = SecretKey::new_random();
        let pk = sk.public_key();

        // Compressed public key should be 33 bytes
        assert_eq!(pk.serialize_compressed().len(), 33);

        // First byte should be 0x02 or 0x03 (compressed)
        let compressed = pk.serialize_compressed();
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn test_public_key_formats() {
        let sk = SecretKey::new_random();
        let pk = sk.public_key();

        let compressed = pk.serialize_compressed();
        let uncompressed = pk.serialize_uncompressed();

        assert_eq!(compressed.len(), 33);
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04); // Uncompressed prefix

        // Both should parse back to the same key
        let pk_from_compressed = PublicKey::from_compressed(&compressed).unwrap();
        let pk_from_uncompressed = PublicKey::from_uncompressed(&uncompressed).unwrap();
        assert_eq!(pk_from_compressed, pk_from_uncompressed);
    }

    #[test]
    fn test_pubkey_hash() {
        let sk = SecretKey::new_random();
        let pk = sk.public_key();
        let hash = pk.pubkey_hash();

        assert_eq!(hash.as_bytes().len(), 20);
    }

    #[test]
    fn test_keypair() {
        let kp = KeyPair::new_random();

        // Public key from keypair should match public key from secret
        let pk_from_kp = kp.public_key();
        let pk_from_sk = kp.secret_key().public_key();
        assert_eq!(pk_from_kp, &pk_from_sk);
    }

    #[test]
    fn test_known_keypair() {
        // Test with known test vector
        // Private key: 1 (not for real use!)
        let sk_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.public_key();

        // Known public key for private key = 1
        assert_eq!(
            pk.to_hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_secret_key_from_bytes_wrong_length() {
        // Too short
        let result = SecretKey::from_bytes(&[0x01u8; 16]);
        assert!(result.is_err());
        if let Err(CryptoError::InvalidKeyLength { expected, actual }) = result {
            assert_eq!(expected, 32);
            assert_eq!(actual, 16);
        } else {
            panic!("expected InvalidKeyLength error");
        }

        // Too long
        let result = SecretKey::from_bytes(&[0x01u8; 33]);
        assert!(result.is_err());
        if let Err(CryptoError::InvalidKeyLength { expected, actual }) = result {
            assert_eq!(expected, 32);
            assert_eq!(actual, 33);
        } else {
            panic!("expected InvalidKeyLength error");
        }

        // Empty
        let result = SecretKey::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_key_zero_bytes_invalid() {
        // All-zero bytes are not a valid secp256k1 key
        let result = SecretKey::from_bytes(&[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_from_compressed_wrong_length() {
        // 32 bytes — too short for compressed
        let result = PublicKey::from_compressed(&[0x02u8; 32]);
        assert!(result.is_err());
        if let Err(CryptoError::InvalidKeyLength { expected, actual }) = result {
            assert_eq!(expected, 33);
            assert_eq!(actual, 32);
        } else {
            panic!("expected InvalidKeyLength error");
        }
    }

    #[test]
    fn test_public_key_from_uncompressed_wrong_length() {
        // 33 bytes — too short for uncompressed
        let result = PublicKey::from_uncompressed(&[0x04u8; 33]);
        assert!(result.is_err());
        if let Err(CryptoError::InvalidKeyLength { expected, actual }) = result {
            assert_eq!(expected, 65);
            assert_eq!(actual, 33);
        } else {
            panic!("expected InvalidKeyLength error");
        }
    }

    #[test]
    fn test_keypair_from_secret_bytes() {
        // Round-trip: build keypair from raw bytes, check public key matches
        let sk_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        let kp = KeyPair::from_secret_bytes(&sk_bytes).unwrap();
        assert_eq!(
            kp.public_key().to_hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_keypair_from_secret_bytes_invalid() {
        let result = KeyPair::from_secret_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_compressed_prefix() {
        // Verify that for a known key, the compressed form starts with 0x02 or 0x03
        // and uncompressed starts with 0x04
        let sk = SecretKey::new_random();
        let pk = sk.public_key();
        let compressed = pk.serialize_compressed();
        let uncompressed = pk.serialize_uncompressed();

        assert!(
            compressed[0] == 0x02 || compressed[0] == 0x03,
            "compressed pubkey must start with 0x02 or 0x03, got 0x{:02x}",
            compressed[0]
        );
        assert_eq!(
            uncompressed[0], 0x04,
            "uncompressed pubkey must start with 0x04"
        );
    }

    #[test]
    fn test_public_key_to_bytes_is_compressed() {
        // to_bytes() should return the compressed form (33 bytes)
        let sk = SecretKey::new_random();
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes.as_slice(), pk.serialize_compressed().as_ref());
    }

    #[test]
    fn test_public_key_from_hex_roundtrip() {
        // to_hex then from_hex should give same key
        let sk = SecretKey::new_random();
        let pk = sk.public_key();
        let hex_str = pk.to_hex();
        let pk2 = PublicKey::from_hex(&hex_str).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_pubkey_hash_known_vector() {
        // For private key = 1, the compressed pubkey is known.
        // hash160 of that is RIPEMD160(SHA256(pubkey)).
        let sk_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.public_key();
        let h160 = pk.pubkey_hash();

        // Compute expected manually via hash module
        let compressed = pk.serialize_compressed();
        let expected = hash160(&compressed);
        assert_eq!(h160.as_bytes(), expected.as_bytes());
        // Hash160 is 20 bytes
        assert_eq!(h160.as_bytes().len(), 20);
    }
}
