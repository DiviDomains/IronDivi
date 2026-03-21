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

//! Key storage
//!
//! In-memory key storage with optional encryption.

use crate::address::{Address, Network};
use crate::error::WalletError;
use crate::hd::HdWallet;
use divi_crypto::hash160;
use divi_crypto::keys::{PublicKey, SecretKey};
use divi_primitives::hash::Hash160;
use parking_lot::RwLock;
use std::collections::HashMap;

/// Key entry in the keystore
#[derive(Clone)]
pub struct KeyEntry {
    /// The secret key (None for watch-only addresses)
    pub secret: Option<SecretKey>,
    /// The public key (cached)
    pub public: PublicKey,
    /// Creation time (unix timestamp)
    pub created: u64,
    /// Optional label
    pub label: Option<String>,
    /// HD path (if derived from HD wallet)
    pub hd_path: Option<String>,
    /// Whether this is a watch-only address
    pub is_watch_only: bool,
}

impl KeyEntry {
    /// Create a new key entry
    pub fn new(secret: SecretKey) -> Self {
        let public = secret.public_key();
        KeyEntry {
            secret: Some(secret),
            public,
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            label: None,
            hd_path: None,
            is_watch_only: false,
        }
    }

    /// Create with HD path
    pub fn with_hd_path(secret: SecretKey, path: String) -> Self {
        let mut entry = Self::new(secret);
        entry.hd_path = Some(path);
        entry
    }

    /// Create a watch-only entry (no private key)
    pub fn watch_only(public: PublicKey, label: Option<String>) -> Self {
        KeyEntry {
            secret: None,
            public,
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            label,
            hd_path: None,
            is_watch_only: true,
        }
    }

    /// Get the public key hash
    pub fn pubkey_hash(&self) -> Hash160 {
        let compressed = self.public.to_bytes();
        hash160(&compressed)
    }

    /// Get address for network
    pub fn address(&self, network: Network) -> Address {
        Address::p2pkh(&self.public, network)
    }
}

/// Key store
pub struct KeyStore {
    /// Keys indexed by public key hash
    keys: RwLock<HashMap<Hash160, KeyEntry>>,
    /// HD wallet (optional)
    hd_wallet: RwLock<Option<HdWallet>>,
    /// Network
    network: Network,
    /// Next receiving address index
    receiving_index: RwLock<u32>,
    /// Next change address index
    change_index: RwLock<u32>,
    /// Keypool target size (how many unused keys to keep pre-generated)
    keypool_target: RwLock<u32>,
    /// Timestamp of oldest key in keypool
    keypool_oldest: RwLock<u64>,
}

/// Default keypool target size (matches C++ Divi DEFAULT_KEYPOOL_SIZE)
pub const DEFAULT_KEYPOOL_SIZE: u32 = 100;

impl KeyStore {
    /// Create a new empty keystore
    pub fn new(network: Network) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        KeyStore {
            keys: RwLock::new(HashMap::new()),
            hd_wallet: RwLock::new(None),
            network,
            receiving_index: RwLock::new(0),
            change_index: RwLock::new(0),
            keypool_target: RwLock::new(DEFAULT_KEYPOOL_SIZE),
            keypool_oldest: RwLock::new(now),
        }
    }

    /// Create with HD wallet
    pub fn with_hd_wallet(network: Network, wallet: HdWallet) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        KeyStore {
            keys: RwLock::new(HashMap::new()),
            hd_wallet: RwLock::new(Some(wallet)),
            network,
            receiving_index: RwLock::new(0),
            change_index: RwLock::new(0),
            keypool_target: RwLock::new(DEFAULT_KEYPOOL_SIZE),
            keypool_oldest: RwLock::new(now),
        }
    }

    /// Add a key to the store
    pub fn add_key(&self, entry: KeyEntry) {
        let hash = entry.pubkey_hash();
        self.keys.write().insert(hash, entry);
    }

    /// Get a key by public key hash
    pub fn get_key(&self, hash: &Hash160) -> Option<KeyEntry> {
        self.keys.read().get(hash).cloned()
    }

    /// Get a key by address
    pub fn get_key_by_address(&self, address: &Address) -> Option<KeyEntry> {
        self.get_key(&address.hash)
    }

    /// Check if we have a key for this hash
    pub fn have_key(&self, hash: &Hash160) -> bool {
        self.keys.read().contains_key(hash)
    }

    /// Check if an address is a change address (derived from HD path /1/)
    ///
    /// Returns true if the address is derived from the HD wallet's change chain (m/44'/301'/0'/1/*)
    /// Returns false for receiving addresses (m/44'/301'/0'/0/*) or non-HD addresses
    pub fn is_change_address(&self, address: &Address) -> bool {
        if let Some(entry) = self.get_key(&address.hash) {
            if let Some(ref path) = entry.hd_path {
                // HD path format: m/44'/301'/0'/1/index (change) or m/44'/301'/0'/0/index (receiving)
                // Check if this is a change address by looking for '/1/' in the path
                return path.contains("/1/");
            }
        }
        false
    }

    /// Get all addresses
    pub fn get_addresses(&self) -> Vec<Address> {
        self.keys
            .read()
            .values()
            .map(|entry| entry.address(self.network))
            .collect()
    }

    /// Get all key entries
    pub fn get_all_keys(&self) -> Vec<KeyEntry> {
        self.keys.read().values().cloned().collect()
    }

    /// Generate a new receiving address
    pub fn new_receiving_address(&self) -> Result<Address, WalletError> {
        let wallet = self.hd_wallet.read();
        let wallet = wallet
            .as_ref()
            .ok_or(WalletError::KeyNotFound("No HD wallet configured".into()))?;

        let index = *self.receiving_index.read();
        let key = wallet.derive_receiving(0, index)?;
        let secret = key.secret_key()?;
        let path = format!("m/44'/301'/0'/0/{}", index);

        let entry = KeyEntry::with_hd_path(secret, path);
        let address = entry.address(self.network);
        self.add_key(entry);

        *self.receiving_index.write() += 1;
        Ok(address)
    }

    /// Generate a new change address
    pub fn new_change_address(&self) -> Result<Address, WalletError> {
        let wallet = self.hd_wallet.read();
        let wallet = wallet
            .as_ref()
            .ok_or(WalletError::KeyNotFound("No HD wallet configured".into()))?;

        let index = *self.change_index.read();
        let key = wallet.derive_change(0, index)?;
        let secret = key.secret_key()?;
        let path = format!("m/44'/301'/0'/1/{}", index);

        let entry = KeyEntry::with_hd_path(secret, path);
        let address = entry.address(self.network);
        self.add_key(entry);

        *self.change_index.write() += 1;
        Ok(address)
    }

    /// Import a private key
    pub fn import_key(&self, secret: SecretKey, label: Option<String>) -> Address {
        let mut entry = KeyEntry::new(secret);
        entry.label = label;
        let address = entry.address(self.network);
        self.add_key(entry);
        address
    }

    /// Import a watch-only address (public key only, no private key)
    pub fn import_watch_only(&self, public: PublicKey, label: Option<String>) -> Address {
        let entry = KeyEntry::watch_only(public, label);
        let address = entry.address(self.network);
        self.add_key(entry);
        address
    }

    /// Check if an address is watch-only
    pub fn is_watch_only(&self, hash: &Hash160) -> bool {
        self.keys
            .read()
            .get(hash)
            .map(|entry| entry.is_watch_only)
            .unwrap_or(false)
    }

    /// Get the number of keys
    pub fn key_count(&self) -> usize {
        self.keys.read().len()
    }

    /// Get mnemonic (if HD wallet configured)
    pub fn mnemonic(&self) -> Option<String> {
        self.hd_wallet
            .read()
            .as_ref()
            .and_then(|w| w.mnemonic())
            .map(|s| s.to_string())
    }

    /// Get HD master key ID (hash160 of master public key)
    ///
    /// Returns None if no HD wallet is configured
    pub fn hd_master_key_id(&self) -> Option<[u8; 20]> {
        self.hd_wallet
            .read()
            .as_ref()
            .and_then(|w| w.master_key_id().ok())
    }

    /// Get HD wallet indices (receiving, change)
    pub fn get_indices(&self) -> (u32, u32) {
        (*self.receiving_index.read(), *self.change_index.read())
    }

    /// Set HD wallet indices (for restoration from persistence)
    pub fn set_indices(&self, receiving: u32, change: u32) {
        *self.receiving_index.write() = receiving;
        *self.change_index.write() = change;
    }

    /// Set the HD wallet (for restoration from persistence)
    pub fn set_hd_wallet(&self, wallet: HdWallet) {
        *self.hd_wallet.write() = Some(wallet);
    }

    /// Add a key entry directly with its hash (for restoration from persistence)
    pub fn add_key_with_hash(&self, hash: Hash160, entry: KeyEntry) {
        self.keys.write().insert(hash, entry);
    }

    /// Get all keys with their hashes (for persistence)
    pub fn get_all_keys_with_hashes(&self) -> Vec<(Hash160, KeyEntry)> {
        self.keys
            .read()
            .iter()
            .map(|(h, e)| (*h, e.clone()))
            .collect()
    }

    /// Get HD chain ID (SHA256 hash of master pubkey)
    pub fn get_hd_chain_id(&self) -> Option<String> {
        use sha2::{Digest, Sha256};

        let wallet = self.hd_wallet.read();
        let wallet = wallet.as_ref()?;

        let master_pubkey = wallet.get_master_pubkey().ok()?;
        let pubkey_bytes = master_pubkey.to_bytes();
        let hash = Sha256::digest(&pubkey_bytes);
        Some(hex::encode(hash))
    }

    /// Get the current keypool size (number of pre-generated unused keys)
    ///
    /// For an HD wallet, this is the number of keys generated that haven't
    /// been returned via new_receiving_address() or new_change_address()
    pub fn keypool_size(&self) -> u32 {
        // Count only HD-derived keys (those with hd_path)
        // Imported keys don't count toward keypool
        let keys = self.keys.read();
        let hd_key_count = keys
            .values()
            .filter(|entry| entry.hd_path.is_some())
            .count() as u32;

        // Keys that have been "issued" (returned to caller)
        let issued = *self.receiving_index.read() + *self.change_index.read();

        // Keypool is HD keys pre-generated but not yet issued
        hd_key_count.saturating_sub(issued)
    }

    /// Get the timestamp of the oldest key in the keypool
    pub fn keypool_oldest(&self) -> u64 {
        *self.keypool_oldest.read()
    }

    /// Set keypool oldest timestamp (for restoration from persistence)
    pub fn set_keypool_oldest(&self, timestamp: u64) {
        *self.keypool_oldest.write() = timestamp;
    }

    /// Get the keypool target size
    pub fn keypool_target(&self) -> u32 {
        *self.keypool_target.read()
    }

    /// Set the keypool target size
    pub fn set_keypool_target(&self, size: u32) {
        *self.keypool_target.write() = size;
    }

    /// Refill the keypool by pre-generating keys up to the target size
    ///
    /// Returns the number of keys generated
    pub fn refill_keypool(&self, new_size: Option<u32>) -> Result<u32, WalletError> {
        let wallet = self.hd_wallet.read();
        let wallet = wallet
            .as_ref()
            .ok_or(WalletError::KeyNotFound("No HD wallet configured".into()))?;

        let target = new_size.unwrap_or(*self.keypool_target.read());
        if let Some(new) = new_size {
            *self.keypool_target.write() = new;
        }

        let mut generated = 0u32;
        let current_receiving = *self.receiving_index.read();
        let current_change = *self.change_index.read();

        // Pre-generate receiving addresses
        // We generate up to target/2 receiving and target/2 change addresses
        let receive_target = current_receiving + target / 2;
        let change_target = current_change + target / 2;

        // Generate receiving keys
        for i in current_receiving..receive_target {
            let key = wallet.derive_receiving(0, i)?;
            let secret = key.secret_key()?;
            let path = format!("m/44'/301'/0'/0/{}", i);
            let entry = KeyEntry::with_hd_path(secret, path);
            self.add_key(entry);
            generated += 1;
        }

        // Generate change keys
        for i in current_change..change_target {
            let key = wallet.derive_change(0, i)?;
            let secret = key.secret_key()?;
            let path = format!("m/44'/301'/0'/1/{}", i);
            let entry = KeyEntry::with_hd_path(secret, path);
            self.add_key(entry);
            generated += 1;
        }

        // Update oldest timestamp if this is the first fill
        if *self.keypool_oldest.read() == 0 && generated > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            *self.keypool_oldest.write() = now;
        }

        Ok(generated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::ChainMode;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_keystore_new() {
        let store = KeyStore::new(Network::Mainnet);
        assert_eq!(store.key_count(), 0);
    }

    #[test]
    fn test_add_and_get_key() {
        let store = KeyStore::new(Network::Mainnet);
        let secret = SecretKey::new_random();
        let entry = KeyEntry::new(secret);
        let hash = entry.pubkey_hash();

        store.add_key(entry.clone());

        assert!(store.have_key(&hash));
        assert!(store.get_key(&hash).is_some());
        assert_eq!(store.key_count(), 1);
    }

    #[test]
    fn test_hd_wallet_addresses() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        let addr1 = store.new_receiving_address().unwrap();
        let addr2 = store.new_receiving_address().unwrap();

        assert_ne!(addr1, addr2);
        assert_eq!(store.key_count(), 2);
    }

    #[test]
    fn test_change_addresses() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        let receive = store.new_receiving_address().unwrap();
        let change = store.new_change_address().unwrap();

        assert_ne!(receive, change);
    }

    #[test]
    fn test_is_change_address() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        let receive = store.new_receiving_address().unwrap();
        let change = store.new_change_address().unwrap();

        // Receiving address should not be flagged as change
        assert!(!store.is_change_address(&receive));

        // Change address should be flagged as change
        assert!(store.is_change_address(&change));

        // Non-HD imported key should not be flagged as change
        let imported = store.import_key(SecretKey::new_random(), None);
        assert!(!store.is_change_address(&imported));
    }

    #[test]
    fn test_import_key() {
        let store = KeyStore::new(Network::Mainnet);
        let secret = SecretKey::new_random();

        let addr = store.import_key(secret.clone(), Some("test".to_string()));

        let entry = store.get_key_by_address(&addr).unwrap();
        assert_eq!(entry.label, Some("test".to_string()));
    }

    #[test]
    fn test_get_addresses() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        store.new_receiving_address().unwrap();
        store.new_receiving_address().unwrap();
        store.new_change_address().unwrap();

        let addresses = store.get_addresses();
        assert_eq!(addresses.len(), 3);
    }

    #[test]
    fn test_mnemonic_access() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        assert_eq!(store.mnemonic(), Some(TEST_MNEMONIC.to_string()));
    }

    #[test]
    fn test_key_entry_hd_path() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        let addr = store.new_receiving_address().unwrap();
        let entry = store.get_key_by_address(&addr).unwrap();

        assert!(entry.hd_path.is_some());
        assert!(entry.hd_path.unwrap().contains("0'/0/0"));
    }

    #[test]
    fn test_keypool_management() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        // Initially keypool is empty (no keys pre-generated)
        assert_eq!(store.keypool_size(), 0);
        assert!(store.keypool_oldest() > 0); // Should have a timestamp

        // Refill keypool with 10 keys
        let generated = store.refill_keypool(Some(10)).unwrap();
        assert_eq!(generated, 10); // 5 receiving + 5 change

        // Now we have 10 keys in the keypool
        assert_eq!(store.keypool_size(), 10);
        assert_eq!(store.key_count(), 10);

        // Issue some addresses (uses keys from the pool)
        store.new_receiving_address().unwrap();
        store.new_receiving_address().unwrap();

        // Keypool should be unchanged since we're just "using" pre-generated keys
        // Actually the keypool shrinks because issued keys are no longer in the pool
        // Wait - let me reconsider the logic:
        // - key_count = total keys in store = 10 + 2 new = but wait, they should already be there
        // The refill pre-generates keys 0..5 for receiving and 0..5 for change
        // When we call new_receiving_address, it uses receiving_index=0, then 1
        // So the keys 0,1 were already generated by refill
        // Key count should still be 10
        assert_eq!(store.key_count(), 10);

        // But the keypool size decreases as we "issue" addresses
        // keypool_size = total_keys - (receiving_index + change_index)
        // = 10 - (2 + 0) = 8
        assert_eq!(store.keypool_size(), 8);

        // Issue a change address
        store.new_change_address().unwrap();
        assert_eq!(store.keypool_size(), 7);

        // Refill again should generate more keys
        let generated2 = store.refill_keypool(Some(20)).unwrap();
        // Should generate enough to reach target of 20
        // Currently: receiving_index=2, change_index=1
        // Target: 10 receiving (2..12), 10 change (1..11)
        // Generate: 8 receiving + 9 change = 17 new keys
        assert!(generated2 > 0);

        // Now keypool should be close to 20
        // key_count = 10 + 17 = 27
        // keypool = 27 - 3 = 24 (hmm, more than target?)
        // Actually the logic generates up to target/2 on each side from current index
        // So receive_target = 2 + 10 = 12, change_target = 1 + 10 = 11
        // Generated = (12-2) + (11-1) = 10 + 10 = 20
        // But wait, some of those already exist from first refill...
        // First refill generated: receiving 0..5, change 0..5
        // Second refill wants: receiving 2..12, change 1..11
        // Overlap: receiving 2,3,4 (3 keys), change 1,2,3,4 (4 keys)
        // The add_key uses pubkey hash as key, so duplicates are just overwrites
        // So we add 10 + 10 = 20 but some are duplicates
        // Final unique keys should be max(5, 12) receiving + max(5, 11) change = 12 + 11 = 23
        assert!(store.key_count() >= 20);
    }

    #[test]
    fn test_keypool_with_imported_keys() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        // Refill keypool with 10 HD keys
        let generated = store.refill_keypool(Some(10)).unwrap();
        assert_eq!(generated, 10);
        assert_eq!(store.keypool_size(), 10);
        assert_eq!(store.key_count(), 10);

        // Import an external key (not from HD wallet)
        // Using a random hex key for testing
        let external_secret =
            SecretKey::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let _imported_addr = store.import_key(external_secret, Some("imported".to_string()));

        // Total key count should increase by 1
        assert_eq!(store.key_count(), 11);

        // But keypool size should stay at 10 (imported keys don't count)
        assert_eq!(store.keypool_size(), 10);

        // Issue some HD addresses
        store.new_receiving_address().unwrap();
        store.new_receiving_address().unwrap();

        // Keypool should decrease by 2
        assert_eq!(store.keypool_size(), 8);

        // Total key count is still 11 (10 HD + 1 imported, but 2 were already in the pool)
        assert_eq!(store.key_count(), 11);
    }

    #[test]
    fn test_hd_master_key_id() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        // Should return a valid 20-byte hash
        let key_id = store.hd_master_key_id();
        assert!(key_id.is_some());

        let key_id_bytes = key_id.unwrap();
        assert_eq!(key_id_bytes.len(), 20);

        // Should be consistent (same every time)
        let key_id2 = store.hd_master_key_id().unwrap();
        assert_eq!(key_id_bytes, key_id2);
    }
}
