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

//! Cryptographic signature verification for masternode messages
//!
//! This module implements ECDSA signature signing and verification for
//! masternode broadcast messages, pings, and payment winner votes.
//!
//! ## Canonical Serialization
//!
//! Each message type has a canonical serialization for signing that:
//! - Excludes the signature field itself
//! - Uses consistent little-endian byte ordering
//! - Includes all relevant fields in a deterministic order
//!
//! ## C++ Compatibility
//!
//! The serialization format matches the C++ Divi implementation to ensure
//! signature compatibility across nodes.

use crate::manager::MasternodeError;
use crate::masternode::{MasternodeBroadcast, MasternodePaymentWinner, MasternodePing};
use divi_crypto::keys::{PublicKey, SecretKey};
use divi_crypto::sign_recoverable;
use divi_crypto::signature::{verify_message, RecoverableSig, Signature as CryptoSignature};
use divi_primitives::serialize::Encodable;

/// Error types specific to signature operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature bytes are malformed or invalid
    InvalidSignature,
    /// Public key bytes are malformed or invalid
    InvalidPublicKey,
    /// Signature verification failed
    VerificationFailed,
    /// Message serialization failed
    SerializationError(String),
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::InvalidSignature => write!(f, "Invalid signature format"),
            SignatureError::InvalidPublicKey => write!(f, "Invalid public key format"),
            SignatureError::VerificationFailed => write!(f, "Signature verification failed"),
            SignatureError::SerializationError(msg) => {
                write!(f, "Message serialization error: {}", msg)
            }
        }
    }
}

impl std::error::Error for SignatureError {}

impl From<SignatureError> for MasternodeError {
    fn from(err: SignatureError) -> Self {
        MasternodeError::Serialization(err.to_string())
    }
}

/// Serialize a MasternodeBroadcast for signing (excludes signature field)
///
/// The canonical format includes:
/// - vin (OutPoint): 36 bytes
/// - addr (ServiceAddr): 18 bytes
/// - pubkey_collateral: variable length with varint prefix
/// - pubkey_masternode: variable length with varint prefix
/// - sig_time: 8 bytes (i64 LE)
/// - protocol_version: 4 bytes (i32 LE)
/// - tier: 1 byte (u8)
fn serialize_broadcast_for_signing(
    broadcast: &MasternodeBroadcast,
) -> Result<Vec<u8>, SignatureError> {
    let mut buffer = Vec::with_capacity(128);

    broadcast
        .vin
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    broadcast
        .addr
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    broadcast
        .pubkey_collateral
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    broadcast
        .pubkey_masternode
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    broadcast
        .sig_time
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    broadcast
        .protocol_version
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    broadcast
        .tier
        .to_u8()
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;

    Ok(buffer)
}

/// Serialize a MasternodePing for signing (excludes signature field)
///
/// The canonical format includes:
/// - vin (OutPoint): 36 bytes
/// - block_hash (Hash256): 32 bytes
/// - sig_time: 8 bytes (i64 LE)
fn serialize_ping_for_signing(ping: &MasternodePing) -> Result<Vec<u8>, SignatureError> {
    let mut buffer = Vec::with_capacity(80);

    ping.vin
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    ping.block_hash
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    ping.sig_time
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;

    Ok(buffer)
}

/// Serialize a MasternodePaymentWinner for signing (excludes signature field)
///
/// The canonical format includes:
/// - vin_masternode (OutPoint): 36 bytes
/// - block_height: 4 bytes (i32 LE)
/// - payee_script: variable length with varint prefix
fn serialize_winner_for_signing(
    winner: &MasternodePaymentWinner,
) -> Result<Vec<u8>, SignatureError> {
    let mut buffer = Vec::with_capacity(64);

    winner
        .vin_masternode
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    winner
        .block_height
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;
    winner
        .payee_script
        .encode(&mut buffer)
        .map_err(|e| SignatureError::SerializationError(e.to_string()))?;

    Ok(buffer)
}

/// Verify a masternode broadcast signature
///
/// Verifies that the signature in the broadcast was created by the owner of
/// the provided public key, over the canonical serialization of the broadcast
/// (excluding the signature field itself).
///
/// # Arguments
/// * `broadcast` - The masternode broadcast message to verify
/// * `pubkey` - The public key to verify against
///
/// # Returns
/// * `Ok(true)` if the signature is valid
/// * `Err(SignatureError::VerificationFailed)` if the signature is invalid
/// * `Err(SignatureError::InvalidSignature)` if the signature bytes are malformed
pub fn verify_broadcast_signature(
    broadcast: &MasternodeBroadcast,
    pubkey: &PublicKey,
) -> Result<bool, SignatureError> {
    if broadcast.signature.is_empty() {
        return Err(SignatureError::InvalidSignature);
    }

    let message = serialize_broadcast_for_signing(broadcast)?;

    // Try compact recoverable format first (65 bytes), then DER format
    let is_valid = if broadcast.signature.len() == 65 {
        // Compact recoverable signature format
        verify_recoverable_signature(&broadcast.signature, &message, pubkey)?
    } else {
        // DER-encoded signature
        let sig = CryptoSignature::from_der(&broadcast.signature)
            .map_err(|_| SignatureError::InvalidSignature)?;
        verify_message(pubkey, &sig, &message)
    };

    if is_valid {
        Ok(true)
    } else {
        Err(SignatureError::VerificationFailed)
    }
}

/// Verify a masternode ping signature
///
/// Verifies that the signature in the ping was created by the owner of
/// the provided public key.
///
/// # Arguments
/// * `ping` - The masternode ping message to verify
/// * `pubkey` - The public key to verify against
///
/// # Returns
/// * `Ok(true)` if the signature is valid
/// * `Err(SignatureError::VerificationFailed)` if the signature is invalid
pub fn verify_ping_signature(
    ping: &MasternodePing,
    pubkey: &PublicKey,
) -> Result<bool, SignatureError> {
    if ping.signature.is_empty() {
        return Err(SignatureError::InvalidSignature);
    }

    let message = serialize_ping_for_signing(ping)?;

    let is_valid = if ping.signature.len() == 65 {
        verify_recoverable_signature(&ping.signature, &message, pubkey)?
    } else {
        let sig = CryptoSignature::from_der(&ping.signature)
            .map_err(|_| SignatureError::InvalidSignature)?;
        verify_message(pubkey, &sig, &message)
    };

    if is_valid {
        Ok(true)
    } else {
        Err(SignatureError::VerificationFailed)
    }
}

/// Verify a payment winner signature
///
/// Verifies that the signature in the payment winner vote was created by
/// the owner of the provided public key.
///
/// # Arguments
/// * `winner` - The masternode payment winner vote to verify
/// * `pubkey` - The public key to verify against
///
/// # Returns
/// * `Ok(true)` if the signature is valid
/// * `Err(SignatureError::VerificationFailed)` if the signature is invalid
pub fn verify_winner_signature(
    winner: &MasternodePaymentWinner,
    pubkey: &PublicKey,
) -> Result<bool, SignatureError> {
    if winner.signature.is_empty() {
        return Err(SignatureError::InvalidSignature);
    }

    let message = serialize_winner_for_signing(winner)?;

    let is_valid = if winner.signature.len() == 65 {
        verify_recoverable_signature(&winner.signature, &message, pubkey)?
    } else {
        let sig = CryptoSignature::from_der(&winner.signature)
            .map_err(|_| SignatureError::InvalidSignature)?;
        verify_message(pubkey, &sig, &message)
    };

    if is_valid {
        Ok(true)
    } else {
        Err(SignatureError::VerificationFailed)
    }
}

/// Verify a recoverable signature (65-byte compact format)
fn verify_recoverable_signature(
    sig_bytes: &[u8],
    message: &[u8],
    expected_pubkey: &PublicKey,
) -> Result<bool, SignatureError> {
    if sig_bytes.len() != 65 {
        return Err(SignatureError::InvalidSignature);
    }

    let recoverable_sig = RecoverableSig::from_compact_with_recovery(sig_bytes)
        .map_err(|_| SignatureError::InvalidSignature)?;

    // Recover the public key from the signature
    let recovered_pubkey = recoverable_sig
        .recover(message)
        .map_err(|_| SignatureError::VerificationFailed)?;

    // Compare recovered key with expected key
    Ok(recovered_pubkey.to_bytes() == expected_pubkey.to_bytes())
}

/// Sign a masternode broadcast
///
/// Creates a recoverable ECDSA signature over the canonical serialization
/// of the broadcast (excluding the signature field). The signature is stored
/// in the broadcast's signature field in 65-byte compact format.
///
/// # Arguments
/// * `broadcast` - The masternode broadcast to sign (signature field will be updated)
/// * `secret_key` - The secret key to sign with
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if serialization fails
pub fn sign_broadcast(
    broadcast: &mut MasternodeBroadcast,
    secret_key: &SecretKey,
) -> Result<(), SignatureError> {
    let message = serialize_broadcast_for_signing(broadcast)?;
    let sig = sign_recoverable(secret_key, &message);
    broadcast.signature = sig.to_compact_with_recovery().to_vec();
    Ok(())
}

/// Sign a masternode ping
///
/// Creates a recoverable ECDSA signature over the canonical serialization
/// of the ping. The signature is stored in the ping's signature field.
///
/// # Arguments
/// * `ping` - The masternode ping to sign (signature field will be updated)
/// * `secret_key` - The secret key to sign with
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if serialization fails
pub fn sign_ping(ping: &mut MasternodePing, secret_key: &SecretKey) -> Result<(), SignatureError> {
    let message = serialize_ping_for_signing(ping)?;
    let sig = sign_recoverable(secret_key, &message);
    ping.signature = sig.to_compact_with_recovery().to_vec();
    Ok(())
}

/// Sign a payment winner vote
///
/// Creates a recoverable ECDSA signature over the canonical serialization
/// of the payment winner. The signature is stored in the winner's signature field.
///
/// # Arguments
/// * `winner` - The payment winner vote to sign (signature field will be updated)
/// * `secret_key` - The secret key to sign with
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if serialization fails
pub fn sign_winner(
    winner: &mut MasternodePaymentWinner,
    secret_key: &SecretKey,
) -> Result<(), SignatureError> {
    let message = serialize_winner_for_signing(winner)?;
    let sig = sign_recoverable(secret_key, &message);
    winner.signature = sig.to_compact_with_recovery().to_vec();
    Ok(())
}

/// Parse a public key from raw bytes
///
/// Accepts both compressed (33 bytes) and uncompressed (65 bytes) format.
pub fn parse_pubkey(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
    PublicKey::from_bytes(bytes).map_err(|_| SignatureError::InvalidPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masternode::ServiceAddr;
    use crate::tier::MasternodeTier;
    use divi_crypto::keys::KeyPair;
    use divi_primitives::hash::Hash256;
    use divi_primitives::transaction::OutPoint;
    use std::net::{Ipv6Addr, SocketAddrV6};

    fn create_test_broadcast(keypair: &KeyPair) -> MasternodeBroadcast {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            keypair.public_key().to_bytes(),
            keypair.public_key().to_bytes(),
            MasternodeTier::Gold,
            70000,
            1234567890,
        )
    }

    fn create_test_ping() -> MasternodePing {
        MasternodePing::new(
            OutPoint::new(Hash256::zero(), 0),
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            1234567890,
        )
    }

    fn create_test_winner() -> MasternodePaymentWinner {
        MasternodePaymentWinner::new(
            OutPoint::new(Hash256::zero(), 0),
            12345,
            vec![0x76, 0xa9, 0x14, 0x01, 0x02, 0x03],
        )
    }

    #[test]
    fn test_broadcast_sign_verify() {
        let keypair = KeyPair::new_random();
        let mut broadcast = create_test_broadcast(&keypair);

        // Sign the broadcast
        sign_broadcast(&mut broadcast, keypair.secret_key()).unwrap();

        // Verify the signature is populated
        assert!(!broadcast.signature.is_empty());
        assert_eq!(broadcast.signature.len(), 65);

        // Verify the signature
        let result = verify_broadcast_signature(&broadcast, keypair.public_key());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_ping_sign_verify() {
        let keypair = KeyPair::new_random();
        let mut ping = create_test_ping();

        // Sign the ping
        sign_ping(&mut ping, keypair.secret_key()).unwrap();

        // Verify the signature is populated
        assert!(!ping.signature.is_empty());
        assert_eq!(ping.signature.len(), 65);

        // Verify the signature
        let result = verify_ping_signature(&ping, keypair.public_key());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_winner_sign_verify() {
        let keypair = KeyPair::new_random();
        let mut winner = create_test_winner();

        // Sign the winner
        sign_winner(&mut winner, keypair.secret_key()).unwrap();

        // Verify the signature is populated
        assert!(!winner.signature.is_empty());
        assert_eq!(winner.signature.len(), 65);

        // Verify the signature
        let result = verify_winner_signature(&winner, keypair.public_key());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let keypair1 = KeyPair::new_random();
        let keypair2 = KeyPair::new_random();

        let mut broadcast = create_test_broadcast(&keypair1);

        // Sign with keypair1
        sign_broadcast(&mut broadcast, keypair1.secret_key()).unwrap();

        // Try to verify with keypair2's public key - should fail
        let result = verify_broadcast_signature(&broadcast, keypair2.public_key());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SignatureError::VerificationFailed);
    }

    #[test]
    fn test_empty_signature_rejected() {
        let keypair = KeyPair::new_random();
        let broadcast = create_test_broadcast(&keypair);

        // Broadcast has empty signature by default
        assert!(broadcast.signature.is_empty());

        // Should fail verification
        let result = verify_broadcast_signature(&broadcast, keypair.public_key());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SignatureError::InvalidSignature);
    }

    #[test]
    fn test_tampered_message_rejected() {
        let keypair = KeyPair::new_random();
        let mut broadcast = create_test_broadcast(&keypair);

        // Sign the broadcast
        sign_broadcast(&mut broadcast, keypair.secret_key()).unwrap();

        // Tamper with the message after signing
        broadcast.sig_time = 9999999999;

        // Verification should fail
        let result = verify_broadcast_signature(&broadcast, keypair.public_key());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SignatureError::VerificationFailed);
    }

    #[test]
    fn test_ping_tampered_block_hash_rejected() {
        let keypair = KeyPair::new_random();
        let mut ping = create_test_ping();

        // Sign the ping
        sign_ping(&mut ping, keypair.secret_key()).unwrap();

        // Tamper with the block hash
        ping.block_hash =
            Hash256::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();

        // Verification should fail
        let result = verify_ping_signature(&ping, keypair.public_key());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SignatureError::VerificationFailed);
    }

    #[test]
    fn test_winner_tampered_height_rejected() {
        let keypair = KeyPair::new_random();
        let mut winner = create_test_winner();

        // Sign the winner
        sign_winner(&mut winner, keypair.secret_key()).unwrap();

        // Tamper with the block height
        winner.block_height = 99999;

        // Verification should fail
        let result = verify_winner_signature(&winner, keypair.public_key());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SignatureError::VerificationFailed);
    }

    #[test]
    fn test_corrupted_signature_bytes_rejected() {
        let keypair = KeyPair::new_random();
        let mut broadcast = create_test_broadcast(&keypair);

        // Sign the broadcast
        sign_broadcast(&mut broadcast, keypair.secret_key()).unwrap();

        // Corrupt the signature bytes
        broadcast.signature[10] ^= 0xff;
        broadcast.signature[20] ^= 0xff;

        // Verification should fail
        let result = verify_broadcast_signature(&broadcast, keypair.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pubkey_compressed() {
        let keypair = KeyPair::new_random();
        let compressed = keypair.public_key().serialize_compressed();

        let parsed = parse_pubkey(&compressed);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().to_bytes(), keypair.public_key().to_bytes());
    }

    #[test]
    fn test_parse_pubkey_uncompressed() {
        let keypair = KeyPair::new_random();
        let uncompressed = keypair.public_key().serialize_uncompressed();

        let parsed = parse_pubkey(&uncompressed);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().to_bytes(), keypair.public_key().to_bytes());
    }

    #[test]
    fn test_parse_pubkey_invalid() {
        let invalid_bytes = vec![0x00; 33];
        let result = parse_pubkey(&invalid_bytes);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SignatureError::InvalidPublicKey);
    }

    #[test]
    fn test_signature_deterministic() {
        let keypair = KeyPair::new_random();
        let mut broadcast1 = create_test_broadcast(&keypair);
        let mut broadcast2 = create_test_broadcast(&keypair);

        sign_broadcast(&mut broadcast1, keypair.secret_key()).unwrap();
        sign_broadcast(&mut broadcast2, keypair.secret_key()).unwrap();

        // Both signatures should verify (deterministic message)
        assert!(verify_broadcast_signature(&broadcast1, keypair.public_key()).is_ok());
        assert!(verify_broadcast_signature(&broadcast2, keypair.public_key()).is_ok());
    }

    #[test]
    fn test_different_tiers_different_signatures() {
        let keypair = KeyPair::new_random();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        let mut broadcast_copper = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            keypair.public_key().to_bytes(),
            keypair.public_key().to_bytes(),
            MasternodeTier::Copper,
            70000,
            1234567890,
        );

        let mut broadcast_gold = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            keypair.public_key().to_bytes(),
            keypair.public_key().to_bytes(),
            MasternodeTier::Gold,
            70000,
            1234567890,
        );

        sign_broadcast(&mut broadcast_copper, keypair.secret_key()).unwrap();
        sign_broadcast(&mut broadcast_gold, keypair.secret_key()).unwrap();

        // Each should verify with its own signature
        assert!(verify_broadcast_signature(&broadcast_copper, keypair.public_key()).is_ok());
        assert!(verify_broadcast_signature(&broadcast_gold, keypair.public_key()).is_ok());

        // Swapping signatures should fail
        let copper_sig = broadcast_copper.signature.clone();
        broadcast_copper.signature = broadcast_gold.signature.clone();
        broadcast_gold.signature = copper_sig;

        assert!(verify_broadcast_signature(&broadcast_copper, keypair.public_key()).is_err());
        assert!(verify_broadcast_signature(&broadcast_gold, keypair.public_key()).is_err());
    }
}
