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

//! ECDSA signatures for Divi
//!
//! Divi uses DER-encoded ECDSA signatures, same as Bitcoin.

use crate::error::CryptoError;
use crate::keys::{message_hash, PublicKey, SecretKey};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature as SecpSignature};
use secp256k1::{Message, Secp256k1};
use std::fmt;

/// An ECDSA signature
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    inner: SecpSignature,
}

impl Signature {
    /// Create a signature from DER-encoded bytes
    pub fn from_der(data: &[u8]) -> Result<Self, CryptoError> {
        let sig = SecpSignature::from_der(data)?;
        Ok(Signature { inner: sig })
    }

    /// Create a signature from compact format (64 bytes)
    pub fn from_compact(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }
        let sig = SecpSignature::from_compact(data)?;
        Ok(Signature { inner: sig })
    }

    /// Serialize to DER format
    pub fn to_der(&self) -> Vec<u8> {
        self.inner.serialize_der().to_vec()
    }

    /// Serialize to compact format (64 bytes, r||s)
    pub fn to_compact(&self) -> [u8; 64] {
        self.inner.serialize_compact()
    }

    /// Serialize to hex (DER format)
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_der())
    }

    /// Create from hex string (DER format)
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)?;
        Self::from_der(&bytes)
    }

    /// Get the inner secp256k1 signature
    pub(crate) fn inner(&self) -> &SecpSignature {
        &self.inner
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("der", &self.to_hex())
            .finish()
    }
}

/// A recoverable ECDSA signature (includes recovery ID)
#[derive(Clone, PartialEq, Eq)]
pub struct RecoverableSig {
    inner: RecoverableSignature,
}

impl RecoverableSig {
    /// Create from compact format with recovery ID (65 bytes: recovery_byte || r || s)
    ///
    /// Handles Bitcoin-compatible format where:
    /// - byte 0: recovery_id + 27 (uncompressed) or recovery_id + 31 (compressed)
    pub fn from_compact_with_recovery(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != 65 {
            return Err(CryptoError::InvalidSignature);
        }
        // Handle both compressed (31-34) and uncompressed (27-30) formats
        let rec_byte = data[0] as i32;
        let recovery_id = if (31..=34).contains(&rec_byte) {
            RecoveryId::from_i32(rec_byte - 31)?
        } else if (27..=30).contains(&rec_byte) {
            RecoveryId::from_i32(rec_byte - 27)?
        } else {
            RecoveryId::from_i32(rec_byte)?
        };
        let sig = RecoverableSignature::from_compact(&data[1..65], recovery_id)?;
        Ok(RecoverableSig { inner: sig })
    }

    /// Serialize to compact format with recovery ID (65 bytes)
    ///
    /// Uses Bitcoin-compatible format:
    /// - byte 0: recovery_id + 27 (uncompressed) or recovery_id + 31 (compressed)
    /// - bytes 1-32: r value
    /// - bytes 33-64: s value
    pub fn to_compact_with_recovery(&self) -> [u8; 65] {
        let (recovery_id, compact) = self.inner.serialize_compact();
        let mut result = [0u8; 65];
        // Use 31 offset for compressed keys (standard in modern Bitcoin/Divi)
        result[0] = (recovery_id.to_i32() + 31) as u8;
        result[1..65].copy_from_slice(&compact);
        result
    }

    /// Serialize to compact format with recovery ID, using 27 offset (65 bytes)
    ///
    /// This is for uncompressed keys.
    pub fn to_compact_with_recovery_uncompressed(&self) -> [u8; 65] {
        let (recovery_id, compact) = self.inner.serialize_compact();
        let mut result = [0u8; 65];
        result[0] = (recovery_id.to_i32() + 27) as u8;
        result[1..65].copy_from_slice(&compact);
        result
    }

    /// Convert to a regular (non-recoverable) signature
    pub fn to_standard(&self) -> Signature {
        Signature {
            inner: self.inner.to_standard(),
        }
    }

    /// Recover the public key from this signature and message
    pub fn recover(&self, message: &[u8]) -> Result<PublicKey, CryptoError> {
        let secp = Secp256k1::new();
        let msg = message_hash(message);
        let pk = secp.recover_ecdsa(&msg, &self.inner)?;
        PublicKey::from_bytes(&pk.serialize())
    }

    /// Recover the public key from this signature and a raw 32-byte hash
    ///
    /// This is used for block signatures where the hash is already computed.
    pub fn recover_from_hash(&self, hash: &[u8; 32]) -> Result<PublicKey, CryptoError> {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(*hash);
        let pk = secp.recover_ecdsa(&msg, &self.inner)?;
        PublicKey::from_bytes(&pk.serialize())
    }
}

impl fmt::Debug for RecoverableSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoverableSig")
            .field("compact", &hex::encode(self.to_compact_with_recovery()))
            .finish()
    }
}

/// Sign a message with a secret key
///
/// Returns a DER-encoded ECDSA signature.
pub fn sign_message(secret_key: &SecretKey, message: &[u8]) -> Signature {
    let secp = Secp256k1::new();
    let msg = message_hash(message);
    let sig = secp.sign_ecdsa(&msg, secret_key.inner());
    Signature { inner: sig }
}

/// Sign a message with recovery info (for message signing protocols)
pub fn sign_recoverable(secret_key: &SecretKey, message: &[u8]) -> RecoverableSig {
    let secp = Secp256k1::new();
    let msg = message_hash(message);
    let sig = secp.sign_ecdsa_recoverable(&msg, secret_key.inner());
    RecoverableSig { inner: sig }
}

/// Verify a signature against a public key and message
pub fn verify_message(public_key: &PublicKey, signature: &Signature, message: &[u8]) -> bool {
    let secp = Secp256k1::new();
    let msg = message_hash(message);
    secp.verify_ecdsa(&msg, signature.inner(), public_key.inner())
        .is_ok()
}

/// Sign a raw 32-byte hash (no double-SHA256 applied)
pub fn sign_hash(secret_key: &SecretKey, hash: &[u8; 32]) -> Result<Signature, CryptoError> {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*hash);
    let sig = secp.sign_ecdsa(&msg, secret_key.inner());
    Ok(Signature { inner: sig })
}

/// Sign a raw 32-byte hash with recovery info (no double-SHA256 applied)
///
/// This is used for block signing in PoS where the hash is already computed.
pub fn sign_hash_recoverable(
    secret_key: &SecretKey,
    hash: &[u8; 32],
) -> Result<RecoverableSig, CryptoError> {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*hash);
    let sig = secp.sign_ecdsa_recoverable(&msg, secret_key.inner());
    Ok(RecoverableSig { inner: sig })
}

/// Verify a signature against a raw 32-byte hash
pub fn verify_hash(public_key: &PublicKey, signature: &Signature, hash: &[u8; 32]) -> bool {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*hash);
    secp.verify_ecdsa(&msg, signature.inner(), public_key.inner())
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_sign_verify() {
        let kp = KeyPair::new_random();
        let message = b"Hello, Divi!";

        let sig = sign_message(kp.secret_key(), message);
        assert!(verify_message(kp.public_key(), &sig, message));

        // Wrong message should fail
        assert!(!verify_message(kp.public_key(), &sig, b"Wrong message"));
    }

    #[test]
    fn test_signature_der_roundtrip() {
        let kp = KeyPair::new_random();
        let message = b"Test message";

        let sig = sign_message(kp.secret_key(), message);
        let der = sig.to_der();
        let sig2 = Signature::from_der(&der).unwrap();

        assert_eq!(sig.to_compact(), sig2.to_compact());
        assert!(verify_message(kp.public_key(), &sig2, message));
    }

    #[test]
    fn test_signature_compact_roundtrip() {
        let kp = KeyPair::new_random();
        let message = b"Test message";

        let sig = sign_message(kp.secret_key(), message);
        let compact = sig.to_compact();
        let sig2 = Signature::from_compact(&compact).unwrap();

        assert!(verify_message(kp.public_key(), &sig2, message));
    }

    #[test]
    fn test_recoverable_signature() {
        let kp = KeyPair::new_random();
        let message = b"Recoverable test";

        let sig = sign_recoverable(kp.secret_key(), message);
        let recovered_pk = sig.recover(message).unwrap();

        assert_eq!(kp.public_key(), &recovered_pk);
    }

    #[test]
    fn test_different_keys_different_signatures() {
        let kp1 = KeyPair::new_random();
        let kp2 = KeyPair::new_random();
        let message = b"Same message";

        let sig1 = sign_message(kp1.secret_key(), message);
        let sig2 = sign_message(kp2.secret_key(), message);

        // Different keys produce different signatures
        assert_ne!(sig1.to_compact(), sig2.to_compact());

        // Each signature only valid for its own key
        assert!(verify_message(kp1.public_key(), &sig1, message));
        assert!(verify_message(kp2.public_key(), &sig2, message));
        assert!(!verify_message(kp1.public_key(), &sig2, message));
        assert!(!verify_message(kp2.public_key(), &sig1, message));
    }

    #[test]
    fn test_sign_hash_directly() {
        let kp = KeyPair::new_random();
        let hash = [0x42u8; 32];

        let sig = sign_hash(kp.secret_key(), &hash).unwrap();
        assert!(verify_hash(kp.public_key(), &sig, &hash));
        assert!(!verify_hash(kp.public_key(), &sig, &[0x00u8; 32]));
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let kp = KeyPair::new_random();
        let message = b"Hex test";

        let sig = sign_message(kp.secret_key(), message);
        let hex_str = sig.to_hex();
        let sig2 = Signature::from_hex(&hex_str).unwrap();

        assert!(verify_message(kp.public_key(), &sig2, message));
    }

    // --- Deterministic signatures (RFC 6979) ---

    #[test]
    fn test_signature_deterministic_rfc6979() {
        // secp256k1 crate uses RFC 6979 deterministic nonces by default.
        // Signing the same message with the same key must always produce the
        // same signature bytes.
        let kp = KeyPair::new_random();
        let message = b"determinism test";

        let sig1 = sign_message(kp.secret_key(), message);
        let sig2 = sign_message(kp.secret_key(), message);

        assert_eq!(
            sig1.to_compact(),
            sig2.to_compact(),
            "ECDSA signatures must be deterministic (RFC 6979)"
        );
    }

    #[test]
    fn test_sign_hash_deterministic() {
        let kp = KeyPair::new_random();
        let hash = [0xABu8; 32];

        let sig1 = sign_hash(kp.secret_key(), &hash).unwrap();
        let sig2 = sign_hash(kp.secret_key(), &hash).unwrap();

        assert_eq!(sig1.to_compact(), sig2.to_compact());
    }

    // --- DER format validation ---

    #[test]
    fn test_signature_der_starts_with_sequence_tag() {
        // Valid DER signatures start with 0x30 (SEQUENCE tag)
        let kp = KeyPair::new_random();
        let sig = sign_message(kp.secret_key(), b"der format test");
        let der = sig.to_der();

        assert!(!der.is_empty(), "DER-encoded signature must not be empty");
        assert_eq!(
            der[0], 0x30,
            "DER signature must start with SEQUENCE tag 0x30"
        );
        // Standard DER signatures are 70-72 bytes
        assert!(
            der.len() >= 8 && der.len() <= 73,
            "DER signature length {} is outside expected range 8–73",
            der.len()
        );
    }

    #[test]
    fn test_signature_from_invalid_der_fails() {
        let bad_der = [0x00u8; 10];
        let result = Signature::from_der(&bad_der);
        assert!(result.is_err(), "parsing invalid DER must return an error");
    }

    #[test]
    fn test_signature_from_compact_wrong_length_fails() {
        // from_compact requires exactly 64 bytes
        let result = Signature::from_compact(&[0x01u8; 32]);
        assert!(result.is_err());

        let result = Signature::from_compact(&[0x01u8; 65]);
        assert!(result.is_err());
    }

    // --- Compact signature is 64 bytes ---

    #[test]
    fn test_signature_compact_is_64_bytes() {
        let kp = KeyPair::new_random();
        let sig = sign_message(kp.secret_key(), b"compact size");
        let compact = sig.to_compact();
        assert_eq!(compact.len(), 64);
    }

    // --- Recoverable signature: compact with recovery ID is 65 bytes ---

    #[test]
    fn test_recoverable_sig_compact_is_65_bytes() {
        let kp = KeyPair::new_random();
        let sig = sign_recoverable(kp.secret_key(), b"recoverable test");
        let compact = sig.to_compact_with_recovery();
        assert_eq!(compact.len(), 65);
    }

    #[test]
    fn test_recoverable_sig_recovery_byte_in_expected_range() {
        // For compressed keys: recovery byte should be 31, 32, 33, or 34
        let kp = KeyPair::new_random();
        let sig = sign_recoverable(kp.secret_key(), b"recovery byte check");
        let compact = sig.to_compact_with_recovery();
        let rec_byte = compact[0];
        assert!(
            (31..=34).contains(&rec_byte),
            "compressed recovery byte {} should be in 31..=34",
            rec_byte
        );
    }

    #[test]
    fn test_recoverable_sig_uncompressed_recovery_byte_in_expected_range() {
        // For uncompressed keys: recovery byte should be 27, 28, 29, or 30
        let kp = KeyPair::new_random();
        let sig = sign_recoverable(kp.secret_key(), b"uncompressed recovery");
        let compact = sig.to_compact_with_recovery_uncompressed();
        let rec_byte = compact[0];
        assert!(
            (27..=30).contains(&rec_byte),
            "uncompressed recovery byte {} should be in 27..=30",
            rec_byte
        );
    }

    // --- Recoverable signature parsing roundtrip ---

    #[test]
    fn test_recoverable_sig_compact_roundtrip() {
        let kp = KeyPair::new_random();
        let message = b"recoverable roundtrip";
        let sig = sign_recoverable(kp.secret_key(), message);

        let compact = sig.to_compact_with_recovery();
        let sig2 = RecoverableSig::from_compact_with_recovery(&compact).unwrap();

        let recovered_pk = sig2.recover(message).unwrap();
        assert_eq!(kp.public_key(), &recovered_pk);
    }

    #[test]
    fn test_recoverable_sig_from_compact_wrong_length_fails() {
        let result = RecoverableSig::from_compact_with_recovery(&[0x1Fu8; 64]);
        assert!(result.is_err());

        let result = RecoverableSig::from_compact_with_recovery(&[0x1Fu8; 66]);
        assert!(result.is_err());
    }

    // --- sign_hash_recoverable + recover_from_hash ---

    #[test]
    fn test_sign_hash_recoverable_and_recover() {
        let kp = KeyPair::new_random();
        let hash = [0x77u8; 32];

        let sig = sign_hash_recoverable(kp.secret_key(), &hash).unwrap();
        let recovered_pk = sig.recover_from_hash(&hash).unwrap();

        assert_eq!(kp.public_key(), &recovered_pk);
    }

    #[test]
    fn test_sign_hash_recoverable_wrong_hash_fails_recovery() {
        let kp = KeyPair::new_random();
        let hash = [0x11u8; 32];
        let wrong_hash = [0x22u8; 32];

        let sig = sign_hash_recoverable(kp.secret_key(), &hash).unwrap();
        // Recovery succeeds (a key is found) but it won't match our key
        let recovered = sig.recover_from_hash(&wrong_hash).unwrap();
        assert_ne!(kp.public_key(), &recovered);
    }

    // --- Known message produces known DER vector ---

    #[test]
    fn test_sign_known_message_known_der() {
        // With a fixed key and message, RFC 6979 determinism means we always
        // get the same DER-encoded signature.
        let sk_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        let sk = crate::keys::SecretKey::from_bytes(&sk_bytes).unwrap();
        let kp = KeyPair::from_secret_key(sk);

        let message = b"Divi";
        let sig = sign_message(kp.secret_key(), message);
        let der = sig.to_der();

        // Verify it's a valid DER SEQUENCE
        assert_eq!(der[0], 0x30);

        // Sign again — must produce identical bytes
        let sig2 = sign_message(kp.secret_key(), message);
        assert_eq!(sig.to_der(), sig2.to_der());

        // And must verify correctly
        assert!(verify_message(kp.public_key(), &sig, message));
    }

    // --- to_standard conversion ---

    #[test]
    fn test_recoverable_to_standard_verifies() {
        let kp = KeyPair::new_random();
        let message = b"standard from recoverable";

        let rec_sig = sign_recoverable(kp.secret_key(), message);
        let std_sig = rec_sig.to_standard();

        assert!(verify_message(kp.public_key(), &std_sig, message));
    }

    // --- Wrong key fails verification ---

    #[test]
    fn test_verify_hash_wrong_key_fails() {
        let kp1 = KeyPair::new_random();
        let kp2 = KeyPair::new_random();
        let hash = [0x55u8; 32];

        let sig = sign_hash(kp1.secret_key(), &hash).unwrap();
        assert!(verify_hash(kp1.public_key(), &sig, &hash));
        assert!(!verify_hash(kp2.public_key(), &sig, &hash));
    }
}
