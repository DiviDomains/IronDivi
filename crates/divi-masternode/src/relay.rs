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

use crate::masternode::{MasternodeBroadcast, MasternodePaymentWinner, MasternodePing};
use crate::signature::{
    parse_pubkey, verify_broadcast_signature, verify_ping_signature, verify_winner_signature,
};
use crate::tier::MasternodeTier;
use divi_crypto::keys::PublicKey;
use divi_primitives::transaction::OutPoint;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_INVENTORY_SIZE: usize = 10000;
const INVENTORY_EXPIRE_SECONDS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    Broadcast,
    Ping,
    PaymentVote,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageInventoryKey {
    msg_type: MessageType,
    vin: OutPoint,
    sig_time: i64,
}

impl MessageInventoryKey {
    fn from_broadcast(mnb: &MasternodeBroadcast) -> Self {
        MessageInventoryKey {
            msg_type: MessageType::Broadcast,
            vin: mnb.vin,
            sig_time: mnb.sig_time,
        }
    }

    fn from_ping(ping: &MasternodePing) -> Self {
        MessageInventoryKey {
            msg_type: MessageType::Ping,
            vin: ping.vin,
            sig_time: ping.sig_time,
        }
    }

    fn from_payment_vote(vote: &MasternodePaymentWinner) -> Self {
        MessageInventoryKey {
            msg_type: MessageType::PaymentVote,
            vin: vote.vin_masternode,
            sig_time: vote.block_height as i64,
        }
    }
}

#[derive(Debug, Clone)]
struct InventoryEntry {
    timestamp: u64,
}

impl InventoryEntry {
    fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        InventoryEntry { timestamp }
    }

    fn is_expired(&self, now: u64) -> bool {
        now - self.timestamp > INVENTORY_EXPIRE_SECONDS
    }
}

pub struct RelayManager {
    inventory: Arc<RwLock<HashMap<MessageInventoryKey, InventoryEntry>>>,
}

impl RelayManager {
    pub fn new() -> Self {
        RelayManager {
            inventory: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn should_relay_broadcast(&self, mnb: &MasternodeBroadcast) -> bool {
        let key = MessageInventoryKey::from_broadcast(mnb);
        self.should_relay_internal(&key)
    }

    pub fn should_relay_ping(&self, ping: &MasternodePing) -> bool {
        let key = MessageInventoryKey::from_ping(ping);
        self.should_relay_internal(&key)
    }

    pub fn should_relay_payment_vote(&self, vote: &MasternodePaymentWinner) -> bool {
        let key = MessageInventoryKey::from_payment_vote(vote);
        self.should_relay_internal(&key)
    }

    fn should_relay_internal(&self, key: &MessageInventoryKey) -> bool {
        let inventory = self.inventory.read();
        !inventory.contains_key(key)
    }

    pub fn mark_broadcast_seen(&self, mnb: &MasternodeBroadcast) {
        let key = MessageInventoryKey::from_broadcast(mnb);
        self.mark_seen_internal(key);
    }

    pub fn mark_ping_seen(&self, ping: &MasternodePing) {
        let key = MessageInventoryKey::from_ping(ping);
        self.mark_seen_internal(key);
    }

    pub fn mark_payment_vote_seen(&self, vote: &MasternodePaymentWinner) {
        let key = MessageInventoryKey::from_payment_vote(vote);
        self.mark_seen_internal(key);
    }

    fn mark_seen_internal(&self, key: MessageInventoryKey) {
        let mut inventory = self.inventory.write();

        if inventory.len() >= MAX_INVENTORY_SIZE {
            self.cleanup_expired(&mut inventory);
        }

        if inventory.len() >= MAX_INVENTORY_SIZE {
            self.cleanup_oldest(&mut inventory);
        }

        inventory.insert(key, InventoryEntry::new());
    }

    fn cleanup_expired(&self, inventory: &mut HashMap<MessageInventoryKey, InventoryEntry>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        inventory.retain(|_, entry| !entry.is_expired(now));
    }

    fn cleanup_oldest(&self, inventory: &mut HashMap<MessageInventoryKey, InventoryEntry>) {
        if inventory.is_empty() {
            return;
        }

        let to_remove = inventory.len() / 4;
        let mut entries: Vec<_> = inventory
            .iter()
            .map(|(k, v)| (k.clone(), v.timestamp))
            .collect();
        entries.sort_by_key(|(_, ts)| *ts);

        for (key, _) in entries.iter().take(to_remove) {
            inventory.remove(key);
        }
    }

    pub fn clear(&self) {
        let mut inventory = self.inventory.write();
        inventory.clear();
    }

    pub fn inventory_size(&self) -> usize {
        let inventory = self.inventory.read();
        inventory.len()
    }
}

impl Default for RelayManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    InvalidSignature,
    InvalidTier,
    InvalidProtocolVersion,
    ExpiredTimestamp,
    FutureTimestamp,
    InvalidOutpoint,
    InvalidAddress,
}

pub struct MessageValidator;

impl MessageValidator {
    /// Validate a masternode broadcast without signature verification
    ///
    /// This performs basic structural validation. For full validation including
    /// signature verification, use `validate_broadcast_with_signature`.
    pub fn validate_broadcast(mnb: &MasternodeBroadcast) -> Result<(), ValidationError> {
        if mnb.tier == MasternodeTier::Invalid {
            return Err(ValidationError::InvalidTier);
        }

        if mnb.protocol_version < 70000 {
            return Err(ValidationError::InvalidProtocolVersion);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if mnb.sig_time > now + 3600 {
            return Err(ValidationError::FutureTimestamp);
        }

        if mnb.sig_time < now - 86400 {
            return Err(ValidationError::ExpiredTimestamp);
        }

        if mnb.vin.is_null() {
            return Err(ValidationError::InvalidOutpoint);
        }

        Ok(())
    }

    /// Validate a masternode broadcast with signature verification
    ///
    /// Performs all structural validation from `validate_broadcast` plus
    /// verifies the signature using the collateral public key embedded in
    /// the broadcast message.
    pub fn validate_broadcast_with_signature(
        mnb: &MasternodeBroadcast,
    ) -> Result<(), ValidationError> {
        // First do structural validation
        Self::validate_broadcast(mnb)?;

        // Parse the collateral public key from the broadcast
        let pubkey =
            parse_pubkey(&mnb.pubkey_collateral).map_err(|_| ValidationError::InvalidSignature)?;

        // Verify the signature
        verify_broadcast_signature(mnb, &pubkey).map_err(|_| ValidationError::InvalidSignature)?;

        Ok(())
    }

    /// Validate a masternode broadcast with a provided public key
    ///
    /// Use this when you have the public key from a separate source
    /// (e.g., from an existing masternode record in the database).
    pub fn validate_broadcast_with_pubkey(
        mnb: &MasternodeBroadcast,
        pubkey: &PublicKey,
    ) -> Result<(), ValidationError> {
        // First do structural validation
        Self::validate_broadcast(mnb)?;

        // Verify the signature
        verify_broadcast_signature(mnb, pubkey).map_err(|_| ValidationError::InvalidSignature)?;

        Ok(())
    }

    /// Validate a masternode ping without signature verification
    ///
    /// This performs basic structural validation. For full validation including
    /// signature verification, use `validate_ping_with_signature`.
    pub fn validate_ping(ping: &MasternodePing) -> Result<(), ValidationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if ping.sig_time > now + 3600 {
            return Err(ValidationError::FutureTimestamp);
        }

        if ping.sig_time < now - 86400 {
            return Err(ValidationError::ExpiredTimestamp);
        }

        if ping.vin.is_null() {
            return Err(ValidationError::InvalidOutpoint);
        }

        if ping.block_hash.is_zero() {
            return Err(ValidationError::InvalidOutpoint);
        }

        Ok(())
    }

    /// Validate a masternode ping with signature verification
    ///
    /// # Arguments
    /// * `ping` - The ping message to validate
    /// * `pubkey` - The masternode's public key (obtained from the masternode record)
    pub fn validate_ping_with_signature(
        ping: &MasternodePing,
        pubkey: &PublicKey,
    ) -> Result<(), ValidationError> {
        // First do structural validation
        Self::validate_ping(ping)?;

        // Verify the signature
        verify_ping_signature(ping, pubkey).map_err(|_| ValidationError::InvalidSignature)?;

        Ok(())
    }

    /// Validate a payment winner vote without signature verification
    ///
    /// This performs basic structural validation. For full validation including
    /// signature verification, use `validate_payment_vote_with_signature`.
    pub fn validate_payment_vote(vote: &MasternodePaymentWinner) -> Result<(), ValidationError> {
        if vote.vin_masternode.is_null() {
            return Err(ValidationError::InvalidOutpoint);
        }

        if vote.block_height < 0 {
            return Err(ValidationError::InvalidOutpoint);
        }

        if vote.payee_script.is_empty() {
            return Err(ValidationError::InvalidOutpoint);
        }

        Ok(())
    }

    /// Validate a payment winner vote with signature verification
    ///
    /// # Arguments
    /// * `vote` - The payment winner vote to validate
    /// * `pubkey` - The masternode's public key (obtained from the masternode record)
    pub fn validate_payment_vote_with_signature(
        vote: &MasternodePaymentWinner,
        pubkey: &PublicKey,
    ) -> Result<(), ValidationError> {
        // First do structural validation
        Self::validate_payment_vote(vote)?;

        // Verify the signature
        verify_winner_signature(vote, pubkey).map_err(|_| ValidationError::InvalidSignature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masternode::ServiceAddr;
    use crate::signature::{sign_broadcast, sign_ping, sign_winner};
    use divi_crypto::keys::KeyPair;
    use divi_primitives::hash::Hash256;
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn test_relay_manager_creation() {
        let relay_mgr = RelayManager::new();
        assert_eq!(relay_mgr.inventory_size(), 0);
    }

    #[test]
    fn test_should_relay_broadcast_new_message() {
        let relay_mgr = RelayManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mnb = MasternodeBroadcast::new(
            OutPoint::null(),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
            1234567890,
        );

        assert!(relay_mgr.should_relay_broadcast(&mnb));
    }

    #[test]
    fn test_should_not_relay_seen_broadcast() {
        let relay_mgr = RelayManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mnb = MasternodeBroadcast::new(
            OutPoint::null(),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
            1234567890,
        );

        relay_mgr.mark_broadcast_seen(&mnb);
        assert!(!relay_mgr.should_relay_broadcast(&mnb));
    }

    #[test]
    fn test_should_relay_ping_new_message() {
        let relay_mgr = RelayManager::new();
        let ping = MasternodePing::new(OutPoint::null(), Hash256::zero(), 1234567890);

        assert!(relay_mgr.should_relay_ping(&ping));
    }

    #[test]
    fn test_should_not_relay_seen_ping() {
        let relay_mgr = RelayManager::new();
        let ping = MasternodePing::new(OutPoint::null(), Hash256::zero(), 1234567890);

        relay_mgr.mark_ping_seen(&ping);
        assert!(!relay_mgr.should_relay_ping(&ping));
    }

    #[test]
    fn test_should_relay_payment_vote_new_message() {
        let relay_mgr = RelayManager::new();
        let vote = MasternodePaymentWinner::new(OutPoint::null(), 12345, vec![0x76, 0xa9, 0x14]);

        assert!(relay_mgr.should_relay_payment_vote(&vote));
    }

    #[test]
    fn test_should_not_relay_seen_payment_vote() {
        let relay_mgr = RelayManager::new();
        let vote = MasternodePaymentWinner::new(OutPoint::null(), 12345, vec![0x76, 0xa9, 0x14]);

        relay_mgr.mark_payment_vote_seen(&vote);
        assert!(!relay_mgr.should_relay_payment_vote(&vote));
    }

    #[test]
    fn test_inventory_cleanup() {
        let relay_mgr = RelayManager::new();

        for i in 0..100 {
            let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
            let mnb = MasternodeBroadcast::new(
                OutPoint::new(Hash256::zero(), i),
                addr,
                vec![1, 2, 3],
                vec![4, 5, 6],
                MasternodeTier::Gold,
                70000,
                1234567890 + i as i64,
            );
            relay_mgr.mark_broadcast_seen(&mnb);
        }

        assert_eq!(relay_mgr.inventory_size(), 100);

        relay_mgr.clear();
        assert_eq!(relay_mgr.inventory_size(), 0);
    }

    #[test]
    fn test_validate_broadcast_valid() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mnb = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
            now,
        );

        assert!(MessageValidator::validate_broadcast(&mnb).is_ok());
    }

    #[test]
    fn test_validate_broadcast_invalid_tier() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mnb = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Invalid,
            70000,
            now,
        );

        assert_eq!(
            MessageValidator::validate_broadcast(&mnb),
            Err(ValidationError::InvalidTier)
        );
    }

    #[test]
    fn test_validate_broadcast_future_timestamp() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mnb = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
            now + 7200,
        );

        assert_eq!(
            MessageValidator::validate_broadcast(&mnb),
            Err(ValidationError::FutureTimestamp)
        );
    }

    #[test]
    fn test_validate_broadcast_expired_timestamp() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mnb = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
            now - 90000,
        );

        assert_eq!(
            MessageValidator::validate_broadcast(&mnb),
            Err(ValidationError::ExpiredTimestamp)
        );
    }

    #[test]
    fn test_validate_ping_valid() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let ping = MasternodePing::new(
            OutPoint::new(Hash256::zero(), 0),
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            now,
        );

        assert!(MessageValidator::validate_ping(&ping).is_ok());
    }

    #[test]
    fn test_validate_payment_vote_valid() {
        let vote = MasternodePaymentWinner::new(
            OutPoint::new(Hash256::zero(), 0),
            12345,
            vec![0x76, 0xa9, 0x14],
        );

        assert!(MessageValidator::validate_payment_vote(&vote).is_ok());
    }

    #[test]
    fn test_validate_payment_vote_invalid_outpoint() {
        let vote = MasternodePaymentWinner::new(OutPoint::null(), 12345, vec![0x76, 0xa9, 0x14]);

        assert_eq!(
            MessageValidator::validate_payment_vote(&vote),
            Err(ValidationError::InvalidOutpoint)
        );
    }

    // ============================================================
    // SIGNATURE VALIDATION TESTS
    // ============================================================

    #[test]
    fn test_validate_broadcast_with_signature_success() {
        let keypair = KeyPair::new_random();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut mnb = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            keypair.public_key().to_bytes(),
            keypair.public_key().to_bytes(),
            MasternodeTier::Gold,
            70000,
            now,
        );

        // Sign the broadcast
        sign_broadcast(&mut mnb, keypair.secret_key()).unwrap();

        // Should pass full validation including signature
        assert!(MessageValidator::validate_broadcast_with_signature(&mnb).is_ok());
    }

    #[test]
    fn test_validate_broadcast_with_signature_invalid_sig() {
        let keypair = KeyPair::new_random();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mnb = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            keypair.public_key().to_bytes(),
            keypair.public_key().to_bytes(),
            MasternodeTier::Gold,
            70000,
            now,
        );

        // No signature - should fail
        assert_eq!(
            MessageValidator::validate_broadcast_with_signature(&mnb),
            Err(ValidationError::InvalidSignature)
        );
    }

    #[test]
    fn test_validate_broadcast_with_pubkey_success() {
        let keypair = KeyPair::new_random();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut mnb = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            keypair.public_key().to_bytes(),
            keypair.public_key().to_bytes(),
            MasternodeTier::Gold,
            70000,
            now,
        );

        sign_broadcast(&mut mnb, keypair.secret_key()).unwrap();

        // Validate with explicit public key
        assert!(
            MessageValidator::validate_broadcast_with_pubkey(&mnb, keypair.public_key()).is_ok()
        );
    }

    #[test]
    fn test_validate_broadcast_with_wrong_pubkey() {
        let keypair1 = KeyPair::new_random();
        let keypair2 = KeyPair::new_random();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut mnb = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            keypair1.public_key().to_bytes(),
            keypair1.public_key().to_bytes(),
            MasternodeTier::Gold,
            70000,
            now,
        );

        sign_broadcast(&mut mnb, keypair1.secret_key()).unwrap();

        // Validate with wrong public key - should fail
        assert_eq!(
            MessageValidator::validate_broadcast_with_pubkey(&mnb, keypair2.public_key()),
            Err(ValidationError::InvalidSignature)
        );
    }

    #[test]
    fn test_validate_ping_with_signature_success() {
        let keypair = KeyPair::new_random();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut ping = MasternodePing::new(
            OutPoint::new(Hash256::zero(), 0),
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            now,
        );

        sign_ping(&mut ping, keypair.secret_key()).unwrap();

        // Should pass full validation
        assert!(
            MessageValidator::validate_ping_with_signature(&ping, keypair.public_key()).is_ok()
        );
    }

    #[test]
    fn test_validate_ping_with_wrong_pubkey() {
        let keypair1 = KeyPair::new_random();
        let keypair2 = KeyPair::new_random();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut ping = MasternodePing::new(
            OutPoint::new(Hash256::zero(), 0),
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            now,
        );

        sign_ping(&mut ping, keypair1.secret_key()).unwrap();

        // Validate with wrong public key - should fail
        assert_eq!(
            MessageValidator::validate_ping_with_signature(&ping, keypair2.public_key()),
            Err(ValidationError::InvalidSignature)
        );
    }

    #[test]
    fn test_validate_payment_vote_with_signature_success() {
        let keypair = KeyPair::new_random();

        let mut vote = MasternodePaymentWinner::new(
            OutPoint::new(Hash256::zero(), 0),
            12345,
            vec![0x76, 0xa9, 0x14],
        );

        sign_winner(&mut vote, keypair.secret_key()).unwrap();

        // Should pass full validation
        assert!(MessageValidator::validate_payment_vote_with_signature(
            &vote,
            keypair.public_key()
        )
        .is_ok());
    }

    #[test]
    fn test_validate_payment_vote_with_wrong_pubkey() {
        let keypair1 = KeyPair::new_random();
        let keypair2 = KeyPair::new_random();

        let mut vote = MasternodePaymentWinner::new(
            OutPoint::new(Hash256::zero(), 0),
            12345,
            vec![0x76, 0xa9, 0x14],
        );

        sign_winner(&mut vote, keypair1.secret_key()).unwrap();

        // Validate with wrong public key - should fail
        assert_eq!(
            MessageValidator::validate_payment_vote_with_signature(&vote, keypair2.public_key()),
            Err(ValidationError::InvalidSignature)
        );
    }

    #[test]
    fn test_structural_validation_runs_first() {
        let keypair = KeyPair::new_random();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Create broadcast with invalid tier
        let mut mnb = MasternodeBroadcast::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            keypair.public_key().to_bytes(),
            keypair.public_key().to_bytes(),
            MasternodeTier::Invalid, // Invalid tier
            70000,
            now,
        );

        sign_broadcast(&mut mnb, keypair.secret_key()).unwrap();

        // Should fail with InvalidTier before signature verification
        assert_eq!(
            MessageValidator::validate_broadcast_with_signature(&mnb),
            Err(ValidationError::InvalidTier)
        );
    }
}
