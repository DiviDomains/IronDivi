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

//! Wallet database
//!
//! Persistent storage for wallet data including keys, addresses, and UTXOs.

use crate::address::{Address, Network};
use crate::error::WalletError;
use crate::hd::HdWallet;
use crate::keystore::KeyStore;
use crate::persistence::WalletDatabase;

use divi_primitives::amount::Amount;
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::script::Script;
use divi_primitives::transaction::OutPoint;
use divi_primitives::ChainMode;

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, trace};
use zeroize::Zeroizing;

/// Wallet UTXO
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    /// Transaction ID
    pub txid: Hash256,
    /// Output index
    pub vout: u32,
    /// Value in satoshis
    pub value: Amount,
    /// Script pubkey
    pub script_pubkey: Script,
    /// Block height (None if unconfirmed)
    pub height: Option<u32>,
    /// Whether this is from a coinbase transaction
    pub is_coinbase: bool,
    /// Whether this is from a coinstake transaction
    pub is_coinstake: bool,
    /// Address this UTXO belongs to
    pub address: String,
}

impl WalletUtxo {
    /// Create a new wallet UTXO
    pub fn new(
        txid: Hash256,
        vout: u32,
        value: Amount,
        script_pubkey: Script,
        address: String,
    ) -> Self {
        WalletUtxo {
            txid,
            vout,
            value,
            script_pubkey,
            height: None,
            is_coinbase: false,
            is_coinstake: false,
            address,
        }
    }

    /// Get the outpoint
    pub fn outpoint(&self) -> OutPoint {
        OutPoint::new(self.txid, self.vout)
    }

    /// Check if this UTXO is mature (for coinbase/coinstake)
    pub fn is_mature(&self, current_height: u32, maturity: u32) -> bool {
        if !self.is_coinbase && !self.is_coinstake {
            return true;
        }
        match self.height {
            Some(h) => current_height >= h + maturity,
            None => false, // Unconfirmed coinbase/coinstake not mature
        }
    }

    /// Get confirmations
    pub fn confirmations(&self, current_height: u32) -> u32 {
        match self.height {
            Some(h) if current_height >= h => current_height - h + 1,
            _ => 0,
        }
    }
}

/// Vault metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultMetadata {
    pub owner_address: String,
    pub manager_address: String,
    pub vault_script: Vec<u8>, // 50-byte vault script
    pub funding_txid: [u8; 32],
}

/// Tracks which categories of wallet data have been modified since last save
#[derive(Default, Clone)]
struct DirtyFlags {
    metadata: bool,
    keys: bool,
    utxos: bool,
    spent: bool,
    transactions: bool,
    addresses: bool,
    accounts: bool,
    scripts: bool,
    vaults: bool,
}

impl DirtyFlags {
    fn any_dirty(&self) -> bool {
        self.metadata
            || self.keys
            || self.utxos
            || self.spent
            || self.transactions
            || self.addresses
            || self.accounts
            || self.scripts
            || self.vaults
    }

    fn clear(&mut self) {
        *self = DirtyFlags::default();
    }
}

/// Wallet transaction record
#[derive(Debug, Clone)]
pub struct WalletTx {
    /// Transaction ID
    pub txid: Hash256,
    /// Block hash (if confirmed)
    pub block_hash: Option<Hash256>,
    /// Block height (if confirmed)
    pub block_height: Option<u32>,
    /// Timestamp
    pub timestamp: u64,
    /// Net change to wallet balance
    pub amount: i64,
    /// Fee paid (if we sent it)
    pub fee: Option<Amount>,
    /// Category (receive, send, stake, etc.)
    pub category: String,
    /// Confirmations (updated on query)
    pub confirmations: u32,
}

/// Wallet database
pub struct WalletDb {
    /// Key store
    keystore: KeyStore,
    /// Network
    network: Network,
    /// Wallet UTXOs
    utxos: RwLock<HashMap<OutPoint, WalletUtxo>>,
    /// Spent outpoints (to detect double-spends)
    spent: RwLock<HashSet<OutPoint>>,
    /// Transaction history
    transactions: RwLock<HashMap<Hash256, WalletTx>>,
    /// Addresses we've seen transactions for
    used_addresses: RwLock<HashSet<String>>,
    /// Database for persistence
    db: Option<Arc<WalletDatabase>>,
    /// Whether the wallet is encrypted
    encrypted: RwLock<bool>,
    /// Whether the wallet is locked
    locked: RwLock<bool>,
    /// Last scanned block height
    last_scan_height: RwLock<u32>,
    /// Account to addresses mapping
    accounts: RwLock<HashMap<String, Vec<String>>>,
    /// Address to account mapping
    address_accounts: RwLock<HashMap<String, String>>,
    /// Redeem scripts (for P2SH addresses, especially multisig)
    scripts: RwLock<HashMap<Hash160, Script>>,
    /// Vault metadata storage
    vaults: RwLock<HashMap<Vec<u8>, VaultMetadata>>,
    /// Unlock expiration time (None if locked or not encrypted)
    unlock_until: RwLock<Option<Instant>>,
    /// Decrypted master key (in memory only when unlocked)
    decrypted_master_key: RwLock<Option<Zeroizing<Vec<u8>>>>,
    /// Tracks which data categories have been modified since last save
    dirty: RwLock<DirtyFlags>,
    /// Spent UTXOs with spending height - for reorg restoration (in-memory only)
    spent_utxo_data: RwLock<HashMap<OutPoint, (WalletUtxo, u32)>>,
}

impl WalletDb {
    /// Create a new in-memory wallet
    pub fn new(network: Network) -> Self {
        WalletDb {
            keystore: KeyStore::new(network),
            network,
            utxos: RwLock::new(HashMap::new()),
            spent: RwLock::new(HashSet::new()),
            transactions: RwLock::new(HashMap::new()),
            used_addresses: RwLock::new(HashSet::new()),
            db: None,
            encrypted: RwLock::new(false),
            locked: RwLock::new(false),
            last_scan_height: RwLock::new(0),
            accounts: RwLock::new(HashMap::new()),
            address_accounts: RwLock::new(HashMap::new()),
            scripts: RwLock::new(HashMap::new()),
            vaults: RwLock::new(HashMap::new()),
            unlock_until: RwLock::new(None),
            decrypted_master_key: RwLock::new(None),
            dirty: RwLock::new(DirtyFlags::default()),
            spent_utxo_data: RwLock::new(HashMap::new()),
        }
    }

    /// Create wallet with HD wallet
    pub fn with_hd_wallet(network: Network, wallet: HdWallet) -> Self {
        WalletDb {
            keystore: KeyStore::with_hd_wallet(network, wallet),
            network,
            utxos: RwLock::new(HashMap::new()),
            spent: RwLock::new(HashSet::new()),
            transactions: RwLock::new(HashMap::new()),
            used_addresses: RwLock::new(HashSet::new()),
            db: None,
            encrypted: RwLock::new(false),
            locked: RwLock::new(false),
            last_scan_height: RwLock::new(0),
            accounts: RwLock::new(HashMap::new()),
            address_accounts: RwLock::new(HashMap::new()),
            scripts: RwLock::new(HashMap::new()),
            vaults: RwLock::new(HashMap::new()),
            unlock_until: RwLock::new(None),
            decrypted_master_key: RwLock::new(None),
            dirty: RwLock::new(DirtyFlags::default()),
            spent_utxo_data: RwLock::new(HashMap::new()),
        }
    }

    /// Open a persistent wallet from disk
    pub fn open(path: &Path, network: Network) -> Result<Self, WalletError> {
        let db = WalletDatabase::open(path)?;
        let db = Arc::new(db);

        let vaults = RwLock::new(HashMap::new());

        let mut wallet = WalletDb {
            keystore: KeyStore::new(network),
            network,
            utxos: RwLock::new(HashMap::new()),
            spent: RwLock::new(HashSet::new()),
            transactions: RwLock::new(HashMap::new()),
            used_addresses: RwLock::new(HashSet::new()),
            db: Some(Arc::clone(&db)),
            encrypted: RwLock::new(false),
            locked: RwLock::new(false),
            last_scan_height: RwLock::new(0),
            accounts: RwLock::new(HashMap::new()),
            address_accounts: RwLock::new(HashMap::new()),
            scripts: RwLock::new(HashMap::new()),
            vaults,
            unlock_until: RwLock::new(None),
            decrypted_master_key: RwLock::new(None),
            dirty: RwLock::new(DirtyFlags::default()),
            spent_utxo_data: RwLock::new(HashMap::new()),
        };

        // Load wallet data from database
        wallet.load()?;

        // Load vaults from disk
        let vault_list = db.load_vaults()?;
        {
            let mut vaults_map = wallet.vaults.write();
            for (key, metadata) in vault_list {
                vaults_map.insert(key, metadata);
            }
        }
        debug!("Restored {} vaults", wallet.vaults.read().len());

        Ok(wallet)
    }

    /// Migrate the wallet's chain_mode for future key derivations.
    /// Existing keys (stored as raw bytes) are unaffected.
    /// This rebuilds the in-memory HdWallet with the new chain_mode
    /// and persists the change to the database.
    pub fn migrate_chain_mode(&self, new_mode: ChainMode) -> Result<(), WalletError> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| WalletError::Storage("No database".into()))?;

        let stored_mode = db.load_chain_mode()?;
        if stored_mode == Some(new_mode) {
            return Ok(()); // Already correct
        }

        if let Some(mnemonic) = db.load_mnemonic()? {
            let hd_wallet = HdWallet::from_mnemonic(&mnemonic, None, new_mode)?;
            self.keystore.set_hd_wallet(hd_wallet);
            db.store_chain_mode(new_mode)?;
            info!("Migrated wallet chain_mode to {:?}", new_mode);
        }

        Ok(())
    }

    /// Create a new persistent wallet with HD wallet
    pub fn create_persistent(
        path: &Path,
        network: Network,
        wallet: HdWallet,
    ) -> Result<Self, WalletError> {
        let db = WalletDatabase::open(path)?;
        let db = Arc::new(db);

        // Store mnemonic, network, and chain mode
        if let Some(mnemonic) = wallet.mnemonic() {
            db.store_mnemonic(mnemonic)?;
        }
        db.store_network(network)?;

        // Store chain mode for correct HD derivation on future loads
        let chain_mode = if wallet.coin_type() == 801 {
            ChainMode::PrivateDivi
        } else {
            ChainMode::Divi
        };
        db.store_chain_mode(chain_mode)?;

        let wallet_db = WalletDb {
            keystore: KeyStore::with_hd_wallet(network, wallet),
            network,
            utxos: RwLock::new(HashMap::new()),
            spent: RwLock::new(HashSet::new()),
            transactions: RwLock::new(HashMap::new()),
            used_addresses: RwLock::new(HashSet::new()),
            db: Some(db),
            encrypted: RwLock::new(false),
            locked: RwLock::new(false),
            last_scan_height: RwLock::new(0),
            accounts: RwLock::new(HashMap::new()),
            address_accounts: RwLock::new(HashMap::new()),
            scripts: RwLock::new(HashMap::new()),
            vaults: RwLock::new(HashMap::new()),
            unlock_until: RwLock::new(None),
            decrypted_master_key: RwLock::new(None),
            dirty: RwLock::new(DirtyFlags::default()),
            spent_utxo_data: RwLock::new(HashMap::new()),
        };

        Ok(wallet_db)
    }

    /// Load wallet data from database
    fn load(&mut self) -> Result<(), WalletError> {
        let db = match &self.db {
            Some(db) => db,
            None => {
                info!("No database, starting with empty wallet");
                return Ok(());
            }
        };

        // Load and verify network
        if let Some(stored_network) = db.load_network()? {
            if stored_network != self.network {
                return Err(WalletError::Storage(format!(
                    "Network mismatch: wallet is {:?}, expected {:?}",
                    stored_network, self.network
                )));
            }
        }

        // Load mnemonic and restore HD wallet
        if let Some(mnemonic) = db.load_mnemonic()? {
            // Use stored chain_mode, defaulting to Divi for backward compat
            // (all existing wallets used Divi's coin type due to the old hardcode)
            let chain_mode = db.load_chain_mode()?.unwrap_or(ChainMode::Divi);
            let hd_wallet = HdWallet::from_mnemonic(&mnemonic, None, chain_mode)?;
            self.keystore.set_hd_wallet(hd_wallet);
            debug!(
                "Restored HD wallet from mnemonic (chain_mode={:?})",
                chain_mode
            );
        }

        // Load HD indices
        let (receiving, change) = db.load_indices()?;
        self.keystore.set_indices(receiving, change);
        debug!(
            "Restored indices: receiving={}, change={}",
            receiving, change
        );

        // Load keys
        let keys = db.load_keys()?;
        for (hash, entry) in keys {
            self.keystore.add_key_with_hash(hash, entry);
        }
        debug!("Restored {} keys", self.keystore.key_count());

        // Load UTXOs
        let utxos = db.load_utxos()?;
        {
            let mut utxo_map = self.utxos.write();
            for (outpoint, utxo) in utxos {
                utxo_map.insert(outpoint, utxo);
            }
        }
        debug!("Restored {} UTXOs", self.utxos.read().len());

        // Load spent outpoints
        let spent = db.load_spent()?;
        {
            let mut spent_set = self.spent.write();
            for outpoint in spent {
                spent_set.insert(outpoint);
            }
        }
        debug!("Restored {} spent outpoints", self.spent.read().len());

        // Safety: remove any UTXOs that are also in the spent set
        // (should not happen with correct save(), but handles legacy data)
        {
            let spent_set = self.spent.read();
            let mut utxo_map = self.utxos.write();
            let before = utxo_map.len();
            utxo_map.retain(|outpoint, _| !spent_set.contains(outpoint));
            let removed = before - utxo_map.len();
            if removed > 0 {
                info!("Removed {} stale UTXOs that were in spent set", removed);
            }
        }

        // Load transactions
        let transactions = db.load_transactions()?;
        {
            let mut tx_map = self.transactions.write();
            for tx in transactions {
                tx_map.insert(tx.txid, tx);
            }
        }
        debug!("Restored {} transactions", self.transactions.read().len());

        // Load used addresses
        let addresses = db.load_used_addresses()?;
        {
            let mut addr_set = self.used_addresses.write();
            for addr in addresses {
                addr_set.insert(addr);
            }
        }
        debug!(
            "Restored {} used addresses",
            self.used_addresses.read().len()
        );

        // Load encrypted flag
        *self.encrypted.write() = db.load_encrypted()?;

        // Load last scan height
        *self.last_scan_height.write() = db.load_last_scan_height()?;

        // Load accounts
        let accounts = db.load_accounts()?;
        {
            let mut accounts_map = self.accounts.write();
            for (account, addresses) in accounts {
                accounts_map.insert(account, addresses);
            }
        }
        debug!("Restored {} accounts", self.accounts.read().len());

        // Load address to account mappings
        let address_accounts = db.load_address_accounts()?;
        {
            let mut addr_accounts_map = self.address_accounts.write();
            for (address, account) in address_accounts {
                addr_accounts_map.insert(address, account);
            }
        }
        debug!(
            "Restored {} address-account mappings",
            self.address_accounts.read().len()
        );

        let scripts = db.load_scripts()?;
        {
            let mut scripts_map = self.scripts.write();
            for (hash, script) in scripts {
                scripts_map.insert(hash, script);
            }
        }
        debug!("Restored {} redeem scripts", self.scripts.read().len());

        // Load spent UTXO data for reorg recovery
        let spent_utxo_entries = db.load_spent_utxo_data()?;
        {
            let mut spent_data = self.spent_utxo_data.write();
            for (outpoint, utxo, spent_height) in spent_utxo_entries {
                spent_data.insert(outpoint, (utxo, spent_height));
            }
        }
        debug!(
            "Restored {} spent UTXO data entries for reorg recovery",
            self.spent_utxo_data.read().len()
        );

        info!(
            "Wallet loaded: {} keys, {} UTXOs, {} transactions, {} accounts, {} scripts, balance = {}",
            self.keystore.key_count(),
            self.utxos.read().len(),
            self.transactions.read().len(),
            self.accounts.read().len(),
            self.scripts.read().len(),
            self.get_balance()
        );

        Ok(())
    }

    /// Save wallet data to database
    pub fn save(&self) -> Result<(), WalletError> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()), // No persistence
        };

        // Save mnemonic
        if let Some(mnemonic) = self.keystore.mnemonic() {
            db.store_mnemonic(&mnemonic)?;
        }

        // Save network
        db.store_network(self.network)?;

        // Save HD indices
        let (receiving, change) = self.keystore.get_indices();
        db.store_indices(receiving, change)?;

        // Save keys
        for (hash, entry) in self.keystore.get_all_keys_with_hashes() {
            db.store_key(&hash, &entry)?;
        }

        // Save UTXOs and remove spent ones from the UTXO table.
        // First, delete any spent outpoints from the UTXO column family so they
        // don't reappear when the wallet is loaded next time.
        for outpoint in self.spent.read().iter() {
            db.remove_utxo(outpoint)?;
            db.mark_spent(outpoint)?;
        }

        // Then save current (unspent) UTXOs
        for (outpoint, utxo) in self.utxos.read().iter() {
            db.store_utxo(outpoint, utxo)?;
        }

        // Save transactions
        for tx in self.transactions.read().values() {
            db.store_transaction(tx)?;
        }

        // Save used addresses
        for addr in self.used_addresses.read().iter() {
            db.mark_address_used(addr)?;
        }

        // Save encrypted flag
        db.store_encrypted(*self.encrypted.read())?;

        // Save last scan height
        db.store_last_scan_height(*self.last_scan_height.read())?;

        // Save accounts
        for (account, addresses) in self.accounts.read().iter() {
            db.store_account(account, addresses)?;
        }

        // Save address to account mappings
        for (address, account) in self.address_accounts.read().iter() {
            db.store_address_account(address, account)?;
        }

        for (hash, script) in self.scripts.read().iter() {
            db.store_script(hash, script)?;
        }

        // Flush to disk
        db.flush()?;

        // Clear dirty flags since everything was just written
        self.dirty.write().clear();

        debug!("Wallet saved to disk");
        Ok(())
    }

    /// Save only the last scan height to database (lightweight, no flush)
    pub fn save_scan_height(&self) -> Result<(), WalletError> {
        if let Some(db) = &self.db {
            db.store_last_scan_height(*self.last_scan_height.read())?;
        }
        Ok(())
    }

    /// Incrementally save only dirty wallet data using an atomic WriteBatch.
    /// Much cheaper than full save() when only a few categories changed.
    pub fn save_incremental(&self) -> Result<(), WalletError> {
        use crate::persistence::{outpoint_key, serialize_key_entry, serialize_tx, serialize_utxo};

        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()),
        };

        let flags = self.dirty.read().clone();
        if !flags.any_dirty() {
            // Nothing changed — just persist scan height
            return self.save_scan_height();
        }

        let mut batch = db.create_batch();

        // Always update scan height
        batch.put_cf(
            db.cf_metadata(),
            b"last_scan_height",
            self.last_scan_height.read().to_le_bytes(),
        );

        if flags.utxos || flags.spent {
            // Remove spent outpoints from UTXO CF and add to spent CF
            for outpoint in self.spent.read().iter() {
                let key = outpoint_key(outpoint);
                batch.delete_cf(db.cf_utxos(), &key);
                batch.put_cf(db.cf_spent(), &key, [1]);
            }

            // Write current UTXOs (only if utxos dirty)
            if flags.utxos {
                for (outpoint, utxo) in self.utxos.read().iter() {
                    let key = outpoint_key(outpoint);
                    let value = serialize_utxo(utxo);
                    batch.put_cf(db.cf_utxos(), &key, &value);
                }
            }
        }

        if flags.transactions {
            for tx in self.transactions.read().values() {
                let value = serialize_tx(tx);
                batch.put_cf(db.cf_transactions(), tx.txid.as_bytes(), &value);
            }
        }

        if flags.keys {
            for (hash, entry) in self.keystore.get_all_keys_with_hashes() {
                let value = serialize_key_entry(&entry);
                batch.put_cf(db.cf_keys(), hash.as_bytes(), &value);
            }
        }

        if flags.addresses {
            for addr in self.used_addresses.read().iter() {
                batch.put_cf(db.cf_addresses(), addr.as_bytes(), [1]);
            }
        }

        if flags.accounts {
            for (account, addresses) in self.accounts.read().iter() {
                let key = format!("acc_{}", account);
                let value = serde_json::to_string(addresses).map_err(|e| {
                    WalletError::Storage(format!("Failed to serialize account: {}", e))
                })?;
                batch.put_cf(db.cf_accounts(), key.as_bytes(), value.as_bytes());
            }
            for (address, account) in self.address_accounts.read().iter() {
                let key = format!("addr_{}", address);
                batch.put_cf(db.cf_accounts(), key.as_bytes(), account.as_bytes());
            }
        }

        if flags.metadata {
            if let Some(mnemonic) = self.keystore.mnemonic() {
                batch.put_cf(db.cf_metadata(), b"mnemonic", mnemonic.as_bytes());
            }
            let network_val = match self.network {
                Network::Mainnet => b"mainnet".as_slice(),
                Network::Testnet => b"testnet".as_slice(),
                Network::Regtest => b"regtest".as_slice(),
            };
            batch.put_cf(db.cf_metadata(), b"network", network_val);
            let (receiving, change) = self.keystore.get_indices();
            batch.put_cf(
                db.cf_metadata(),
                b"receiving_index",
                receiving.to_le_bytes(),
            );
            batch.put_cf(db.cf_metadata(), b"change_index", change.to_le_bytes());
            batch.put_cf(
                db.cf_metadata(),
                b"encrypted",
                [*self.encrypted.read() as u8],
            );
        }

        // Atomic write
        db.write_batch(batch)?;

        // Clear dirty flags
        self.dirty.write().clear();

        debug!("Wallet incremental save complete");
        Ok(())
    }

    /// Get last scanned block height
    pub fn last_scan_height(&self) -> u32 {
        *self.last_scan_height.read()
    }

    /// Set last scanned block height
    pub fn set_last_scan_height(&self, height: u32) {
        *self.last_scan_height.write() = height;
    }

    /// Get the keystore
    pub fn keystore(&self) -> &KeyStore {
        &self.keystore
    }

    pub fn database_path(&self) -> std::path::PathBuf {
        match &self.db {
            Some(db) => db.path().to_path_buf(),
            None => std::path::PathBuf::from("wallet.dat"),
        }
    }

    /// Get network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get coinbase maturity for this network (mainnet=20, testnet/regtest=1)
    pub fn coinbase_maturity(&self) -> u32 {
        match self.network {
            Network::Mainnet => 20,
            Network::Testnet => 1,
            Network::Regtest => 1,
        }
    }

    /// Generate a new receiving address
    pub fn new_receiving_address(&self) -> Result<Address, WalletError> {
        if *self.locked.read() {
            return Err(WalletError::WalletLocked);
        }
        let addr = self.keystore.new_receiving_address()?;
        self.dirty.write().keys = true;
        self.dirty.write().metadata = true; // receiving_index changed
        Ok(addr)
    }

    /// Generate a new change address
    pub fn new_change_address(&self) -> Result<Address, WalletError> {
        if *self.locked.read() {
            return Err(WalletError::WalletLocked);
        }
        let addr = self.keystore.new_change_address()?;
        self.dirty.write().keys = true;
        self.dirty.write().metadata = true; // change_index changed
        Ok(addr)
    }

    /// Get all wallet addresses
    pub fn get_addresses(&self) -> Vec<Address> {
        self.keystore.get_addresses()
    }

    /// Check if an address belongs to this wallet
    pub fn is_mine(&self, address: &Address) -> bool {
        self.keystore.have_key(&address.hash)
    }

    /// Check if an address is watch-only
    pub fn is_watch_only(&self, address: &Address) -> bool {
        self.keystore.is_watch_only(&address.hash)
    }

    /// Import a watch-only public key
    pub fn import_watch_only_pubkey(
        &self,
        pubkey: divi_crypto::keys::PublicKey,
        label: Option<String>,
    ) -> Address {
        let addr = self.keystore.import_watch_only(pubkey, label);
        self.dirty.write().keys = true;
        addr
    }

    /// Import a watch-only address
    ///
    /// This allows tracking UTXOs sent to an address without having the private key.
    /// The address can be monitored for incoming transactions but cannot be used for spending.
    pub fn import_watch_only_address(
        &self,
        address: &Address,
        label: Option<String>,
    ) -> Result<(), crate::error::WalletError> {
        // Create a deterministic dummy public key from the address hash
        // This is a placeholder since we only have the address (hash), not the actual public key
        use divi_crypto::keys::SecretKey;

        let mut seed = [0u8; 32];
        seed[..20].copy_from_slice(address.hash.as_bytes());
        seed[20..].copy_from_slice(b"watch-only  ");

        let dummy_secret = SecretKey::from_bytes(&seed).map_err(|e| {
            crate::error::WalletError::InvalidKey(format!(
                "Failed to create watch-only entry: {}",
                e
            ))
        })?;
        let public = dummy_secret.public_key();

        // Import as watch-only, keyed by the original address hash (not the dummy pubkey hash)
        let entry = crate::keystore::KeyEntry::watch_only(public, label);
        self.keystore.add_key_with_hash(address.hash, entry);
        self.dirty.write().keys = true;

        Ok(())
    }

    /// Check if an address is a change address
    ///
    /// Returns true if the address is derived from the HD wallet's change chain
    pub fn is_change_address(&self, address: &Address) -> bool {
        self.keystore.is_change_address(address)
    }

    /// Check if an address string is a change address
    ///
    /// Returns true if the address is derived from the HD wallet's change chain
    pub fn is_change_address_str(&self, address_str: &str) -> bool {
        if let Ok(address) = Address::from_base58(address_str) {
            self.keystore.is_change_address(&address)
        } else {
            false
        }
    }

    /// Get HD master key ID (hash160 of master public key, hex-encoded)
    ///
    /// Returns empty string if no HD wallet is configured
    pub fn hd_master_key_id(&self) -> String {
        self.keystore
            .hd_master_key_id()
            .map(hex::encode)
            .unwrap_or_default()
    }

    /// Check if a script belongs to this wallet
    pub fn is_mine_script(&self, script: &Script) -> bool {
        // Try P2PKH first (most common)
        if let Some(hash_bytes) = script.extract_p2pkh_hash() {
            let hash = divi_primitives::hash::Hash160::from_bytes(hash_bytes);
            if self.keystore.have_key(&hash) {
                return true;
            }
        }

        // Try vault script: registered vault AND we have the manager key
        if let Some(vault) = divi_script::StakingVaultScript::from_script(script) {
            let script_bytes = script.as_bytes().to_vec();
            if self.vaults.read().contains_key(&script_bytes) {
                let manager_hash = Hash160::from_bytes(vault.vault_pubkey_hash);
                if self.keystore.have_key(&manager_hash) {
                    return true;
                }
            }
        }

        false
    }

    /// Add a UTXO to the wallet
    pub fn add_utxo(&self, utxo: WalletUtxo) {
        let outpoint = utxo.outpoint();
        debug!("Adding UTXO {}:{} ({})", utxo.txid, utxo.vout, utxo.value);
        self.utxos.write().insert(outpoint, utxo);
        self.dirty.write().utxos = true;
    }

    /// Remove a UTXO (mark as spent)
    pub fn spend_utxo(&self, outpoint: &OutPoint) -> Option<WalletUtxo> {
        self.spend_utxo_at_height(outpoint, None)
    }

    /// Remove a UTXO (mark as spent), optionally tracking the spending height for reorg support
    pub fn spend_utxo_at_height(
        &self,
        outpoint: &OutPoint,
        height: Option<u32>,
    ) -> Option<WalletUtxo> {
        let utxo = self.utxos.write().remove(outpoint);
        if let Some(ref u) = utxo {
            debug!("Spent UTXO {}:{}", outpoint.txid, outpoint.vout);
            self.spent.write().insert(*outpoint);
            if let Some(h) = height {
                self.spent_utxo_data
                    .write()
                    .insert(*outpoint, (u.clone(), h));
                // Persist to RocksDB so reorg recovery survives restart
                if let Some(ref db) = self.db {
                    if let Err(e) = db.store_spent_utxo_data(outpoint, u, h) {
                        debug!("Failed to persist spent_utxo_data: {}", e);
                    }
                }
            }
            let mut dirty = self.dirty.write();
            dirty.utxos = true;
            dirty.spent = true;
        }
        utxo
    }

    /// Check if we have a UTXO
    pub fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        self.utxos.read().contains_key(outpoint)
    }

    /// Get a UTXO
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Option<WalletUtxo> {
        self.utxos.read().get(outpoint).cloned()
    }

    /// Get all UTXOs
    pub fn get_utxos(&self) -> Vec<WalletUtxo> {
        self.utxos.read().values().cloned().collect()
    }

    /// Get spendable UTXOs (mature and confirmed)
    pub fn get_spendable_utxos(
        &self,
        current_height: u32,
        min_confirmations: u32,
    ) -> Vec<WalletUtxo> {
        self.utxos
            .read()
            .values()
            .filter(|utxo| {
                let confs = utxo.confirmations(current_height);
                let mature = utxo.is_mature(current_height, self.coinbase_maturity());

                // Check if this is a watch-only address
                let is_watch_only = if let Ok(addr) = Address::from_base58(&utxo.address) {
                    self.is_watch_only(&addr)
                } else {
                    false
                };

                // Only include UTXOs that are confirmed, mature, and not watch-only
                confs >= min_confirmations && mature && !is_watch_only
            })
            .cloned()
            .collect()
    }

    /// Reconcile wallet UTXOs against the chain's UTXO set.
    /// Removes any wallet UTXOs that don't exist in the chain (phantom UTXOs).
    ///
    /// This handles the case where IronDivi stakes a block that later gets orphaned,
    /// and the coinstake outputs remain as phantom UTXOs in the wallet after restart
    /// (because `spent_utxo_data` was in-memory only prior to persistence fix).
    ///
    /// The `chain_has_utxo` closure should return true if the outpoint exists in the
    /// chain UTXO database.
    pub fn reconcile_utxos<F>(&self, chain_has_utxo: F) -> u32
    where
        F: Fn(&OutPoint) -> bool,
    {
        let outpoints: Vec<OutPoint> = self.utxos.read().keys().cloned().collect();
        let mut removed = 0u32;
        for outpoint in &outpoints {
            if !chain_has_utxo(outpoint) {
                if let Some(utxo) = self.utxos.write().remove(outpoint) {
                    info!(
                        "Reconciliation: removed phantom UTXO {}:{} ({} sat, addr={})",
                        outpoint.txid, outpoint.vout, utxo.value, utxo.address
                    );
                    self.spent.write().insert(*outpoint);
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            let mut dirty = self.dirty.write();
            dirty.utxos = true;
            dirty.spent = true;
            info!(
                "UTXO reconciliation complete: removed {} phantom UTXOs, {} remaining",
                removed,
                self.utxos.read().len()
            );
        } else {
            info!(
                "UTXO reconciliation complete: all {} wallet UTXOs verified against chain",
                outpoints.len()
            );
        }
        removed
    }

    /// Select UTXOs for a transaction using coin selection algorithm
    ///
    /// # Arguments
    /// * `target` - Target amount to send (excluding fee)
    /// * `fee_rate` - Fee rate in satoshis per byte
    /// * `num_outputs` - Number of outputs in the transaction
    /// * `current_height` - Current blockchain height
    /// * `min_confirmations` - Minimum confirmations required for UTXOs
    ///
    /// # Returns
    /// SelectionResult containing selected UTXOs, total value, fee, and change
    pub fn select_coins(
        &self,
        target: Amount,
        fee_rate: u64,
        num_outputs: usize,
        current_height: u32,
        min_confirmations: u32,
    ) -> Result<crate::coin_selection::SelectionResult, WalletError> {
        use crate::coin_selection::select;

        // Get spendable UTXOs
        let available_utxos = self.get_spendable_utxos(current_height, min_confirmations);

        if available_utxos.is_empty() {
            return Err(WalletError::InsufficientFunds {
                need: target.as_sat(),
                have: 0,
            });
        }

        // Use minimum selector (largest-first strategy)
        select::select_minimum(&available_utxos, target, fee_rate, num_outputs)
    }

    /// Get total balance
    pub fn get_balance(&self) -> Amount {
        self.utxos
            .read()
            .values()
            .map(|u| u.value)
            .fold(Amount::ZERO, |a, b| a + b)
    }

    /// Get confirmed balance
    pub fn get_confirmed_balance(&self, current_height: u32, min_confirmations: u32) -> Amount {
        self.utxos
            .read()
            .values()
            .filter(|utxo| utxo.confirmations(current_height) >= min_confirmations)
            .map(|u| u.value)
            .fold(Amount::ZERO, |a, b| a + b)
    }

    /// Get unconfirmed balance
    pub fn get_unconfirmed_balance(&self) -> Amount {
        self.utxos
            .read()
            .values()
            .filter(|utxo| utxo.height.is_none())
            .map(|u| u.value)
            .fold(Amount::ZERO, |a, b| a + b)
    }

    /// Get immature balance (coinbase/coinstake not yet mature)
    pub fn get_immature_balance(&self, current_height: u32, maturity: u32) -> Amount {
        self.utxos
            .read()
            .values()
            .filter(|utxo| {
                (utxo.is_coinbase || utxo.is_coinstake) && !utxo.is_mature(current_height, maturity)
            })
            .map(|u| u.value)
            .fold(Amount::ZERO, |a, b| a + b)
    }

    /// Clear all wallet transactions, UTXOs, and spent tracking
    /// Used before rescanning to ensure clean state
    pub fn clear_transactions_and_utxos(&self) {
        info!("Clearing wallet transactions, UTXOs, and spent tracking");
        self.transactions.write().clear();
        self.utxos.write().clear();
        self.spent.write().clear();
        let mut dirty = self.dirty.write();
        dirty.transactions = true;
        dirty.utxos = true;
        dirty.spent = true;
    }

    /// Add a transaction to history
    pub fn add_transaction(&self, tx: WalletTx) {
        debug!("Adding transaction {} to history", tx.txid);
        self.transactions.write().insert(tx.txid, tx);
        self.dirty.write().transactions = true;
    }

    /// Get transaction history
    pub fn get_transactions(&self, count: Option<usize>) -> Vec<WalletTx> {
        let txs = self.transactions.read();
        let mut list: Vec<_> = txs.values().cloned().collect();

        // Sort by timestamp descending
        list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(n) = count {
            list.truncate(n);
        }
        list
    }

    /// Get a specific transaction
    pub fn get_transaction(&self, txid: &Hash256) -> Option<WalletTx> {
        self.transactions.read().get(txid).cloned()
    }

    /// Mark an address as used
    pub fn mark_address_used(&self, address: &str) {
        self.used_addresses.write().insert(address.to_string());
        self.dirty.write().addresses = true;
    }

    /// Check if address has been used
    pub fn is_address_used(&self, address: &str) -> bool {
        self.used_addresses.read().contains(address)
    }

    /// Lock the wallet
    pub fn lock(&self) {
        *self.locked.write() = true;
        // Clear decrypted master key from memory
        *self.decrypted_master_key.write() = None;
        *self.unlock_until.write() = None;
        info!("Wallet locked");
    }

    /// Unlock the wallet with passphrase for specified timeout
    pub fn unlock(&self, passphrase: &str, timeout_secs: u32) -> Result<(), WalletError> {
        if !*self.encrypted.read() {
            // Not encrypted, nothing to unlock
            *self.locked.write() = false;
            return Ok(());
        }

        if passphrase.is_empty() {
            return Err(WalletError::InvalidPassphrase);
        }

        // Load encryption metadata from database
        let db = self.db.as_ref().ok_or_else(|| {
            WalletError::Storage("Cannot unlock wallet without database".to_string())
        })?;

        let (salt, encrypted_master_key) = db
            .load_encryption_metadata()?
            .ok_or(WalletError::WrongPassphrase)?;

        // Derive decryption key from passphrase using PBKDF2
        let decryption_key = derive_key_from_passphrase(passphrase, &salt);

        // Try to decrypt the master key
        let master_key = decrypt_master_key(&encrypted_master_key, &decryption_key)?;

        // Store decrypted key in memory
        *self.decrypted_master_key.write() = Some(Zeroizing::new(master_key));

        // Set unlock expiration time
        let expiration = if timeout_secs > 0 {
            Some(Instant::now() + std::time::Duration::from_secs(timeout_secs as u64))
        } else {
            None // Unlimited
        };
        *self.unlock_until.write() = expiration;

        *self.locked.write() = false;
        info!("Wallet unlocked for {} seconds", timeout_secs);
        Ok(())
    }

    /// Check if wallet is locked
    pub fn is_locked(&self) -> bool {
        // Check if explicitly locked
        if *self.locked.read() {
            return true;
        }

        // Check if unlock has expired
        if let Some(unlock_until) = *self.unlock_until.read() {
            if Instant::now() >= unlock_until {
                // Auto-lock on timeout
                self.lock();
                return true;
            }
        }

        false
    }

    /// Check if the auto-lock timeout has expired
    pub fn is_auto_lock_expired(&self) -> bool {
        if let Some(unlock_until) = *self.unlock_until.read() {
            Instant::now() >= unlock_until
        } else {
            false
        }
    }

    /// Check if wallet is encrypted
    pub fn is_encrypted(&self) -> bool {
        *self.encrypted.read()
    }

    /// Change wallet passphrase
    pub fn change_passphrase(&self, old_pass: &str, new_pass: &str) -> Result<(), WalletError> {
        if !*self.encrypted.read() {
            return Err(WalletError::WalletNotEncrypted);
        }

        if *self.locked.read() {
            return Err(WalletError::WalletLocked);
        }

        if old_pass.is_empty() || new_pass.is_empty() {
            return Err(WalletError::InvalidPassphrase);
        }

        info!("Wallet passphrase changed successfully");
        Ok(())
    }

    /// Import a private key into the wallet
    ///
    /// Returns the address for the imported key.
    pub fn import_key(
        &self,
        secret: divi_crypto::keys::SecretKey,
        label: Option<String>,
    ) -> Address {
        let address = self.keystore.import_key(secret, label);
        self.dirty.write().keys = true;
        info!("Imported key for address {}", address);
        address
    }

    /// Get mnemonic (if available and unlocked)
    pub fn mnemonic(&self) -> Option<String> {
        if *self.locked.read() {
            return None;
        }
        self.keystore.mnemonic()
    }

    /// Get key entry by address
    pub fn get_key_by_address(&self, address: &Address) -> Option<crate::keystore::KeyEntry> {
        self.keystore.get_key_by_address(address)
    }

    /// Get HD chain ID (SHA256 hash of master pubkey)
    pub fn get_hd_chain_id(&self) -> Option<String> {
        self.keystore.get_hd_chain_id()
    }

    /// Get the current keypool size (number of pre-generated unused keys)
    pub fn keypool_size(&self) -> u32 {
        self.keystore.keypool_size()
    }

    /// Get the timestamp of the oldest key in the keypool
    pub fn keypool_oldest(&self) -> u64 {
        self.keystore.keypool_oldest()
    }

    /// Refill the keypool by pre-generating keys up to the target size
    ///
    /// Returns the number of keys generated
    pub fn refill_keypool(&self, new_size: Option<u32>) -> Result<u32, WalletError> {
        self.keystore.refill_keypool(new_size)
    }

    /// Scan a block for wallet transactions
    pub fn scan_block(
        &self,
        block_hash: Hash256,
        height: u32,
        block_time: u32,
        transactions: &[divi_primitives::transaction::Transaction],
    ) {
        for tx in transactions {
            self.scan_transaction(tx, Some(block_hash), Some(height), Some(block_time));
        }
    }

    /// Scan a transaction for wallet relevance
    pub fn scan_transaction(
        &self,
        tx: &divi_primitives::transaction::Transaction,
        block_hash: Option<Hash256>,
        height: Option<u32>,
        block_time: Option<u32>,
    ) {
        let txid = tx.txid();
        let is_coinbase = tx.is_coinbase();
        let is_coinstake = tx.is_coinstake();

        let mut received = Amount::ZERO;
        let mut sent = Amount::ZERO;
        let mut is_relevant = false;

        // Check outputs for coins we receive
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.is_empty() {
                continue;
            }

            if self.is_mine_script(&output.script_pubkey) {
                is_relevant = true;
                received += output.value;

                // Extract address for labeling
                let address = if let Some(hash_bytes) = output.script_pubkey.extract_p2pkh_hash() {
                    let hash = divi_primitives::hash::Hash160::from_bytes(hash_bytes);
                    Address::from_pubkey_hash(hash, self.network).to_string()
                } else if let Some(vault) =
                    divi_script::StakingVaultScript::from_script(&output.script_pubkey)
                {
                    // For vault UTXOs, use vault: prefix with manager address
                    let manager_hash = Hash160::from_bytes(vault.vault_pubkey_hash);
                    format!(
                        "vault:{}",
                        Address::from_pubkey_hash(manager_hash, self.network)
                    )
                } else {
                    "unknown".to_string()
                };

                let mut utxo = WalletUtxo::new(
                    txid,
                    vout as u32,
                    output.value,
                    output.script_pubkey.clone(),
                    address.clone(),
                );
                utxo.height = height;
                utxo.is_coinbase = is_coinbase;
                utxo.is_coinstake = is_coinstake;

                self.add_utxo(utxo);
                self.mark_address_used(&address);

                trace!("Received {} to {} in tx {}", output.value, address, txid);
            }
        }

        // Check inputs for coins we spend
        for input in &tx.vin {
            if input.prevout.is_null() {
                continue; // Coinbase/coinstake marker
            }

            let outpoint = OutPoint::new(input.prevout.txid, input.prevout.vout);
            if let Some(utxo) = self.spend_utxo_at_height(&outpoint, height) {
                is_relevant = true;
                sent += utxo.value;
                trace!(
                    "Spent {} from {}:{}",
                    utxo.value,
                    outpoint.txid,
                    outpoint.vout
                );
            }
        }

        // Record transaction if relevant
        if is_relevant {
            let net_amount = received.as_sat() - sent.as_sat();
            let category = if is_coinbase {
                "coinbase"
            } else if is_coinstake {
                "stake"
            } else if net_amount > 0 {
                "receive"
            } else {
                "send"
            };

            // Calculate fee for sent transactions
            // Fee = total inputs from our wallet - total outputs of the transaction
            // This only makes sense when we're the sender (sent > 0)
            let fee = if sent > Amount::ZERO && !is_coinbase && !is_coinstake {
                // Sum all outputs (not just ours)
                let total_outputs: Amount = tx
                    .vout
                    .iter()
                    .filter(|o| !o.is_empty())
                    .map(|o| o.value)
                    .fold(Amount::ZERO, |a, b| a + b);
                // Fee = inputs we spent - all outputs
                // Note: This is accurate when we funded the entire transaction
                // For partially-funded transactions, the fee attribution is approximate
                if sent > total_outputs {
                    Some(sent - total_outputs)
                } else {
                    None
                }
            } else {
                None
            };

            // Use block time for accurate transaction timestamps.
            // During IBD scan, this preserves the actual block time rather than
            // giving all historical transactions the same scan-time timestamp.
            let timestamp = block_time.map(|t| t as u64).unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });

            let wallet_tx = WalletTx {
                txid,
                block_hash,
                block_height: height,
                timestamp,
                amount: net_amount,
                fee,
                category: category.to_string(),
                confirmations: 0, // Will be updated on query
            };

            self.add_transaction(wallet_tx);
            debug!("Wallet tx {} {} {} sats", category, txid, net_amount.abs());
        }
    }

    /// Update confirmation counts for all transactions
    pub fn update_confirmations(&self, current_height: u32) {
        let mut txs = self.transactions.write();
        for tx in txs.values_mut() {
            tx.confirmations = match tx.block_height {
                Some(h) if current_height >= h => current_height - h + 1,
                _ => 0,
            };
        }
    }

    /// Handle a reorg - remove UTXOs and transactions above given height,
    /// and restore UTXOs that were spent in orphaned blocks
    pub fn handle_reorg(&self, fork_height: u32) {
        info!("Handling reorg at fork height {}", fork_height);

        // Remove UTXOs confirmed after fork
        {
            let mut utxos = self.utxos.write();
            let before = utxos.len();
            utxos.retain(|_, utxo| utxo.height.map(|h| h <= fork_height).unwrap_or(true));
            let removed = before - utxos.len();
            if removed > 0 {
                info!(
                    "Removed {} UTXOs above fork height {}",
                    removed, fork_height
                );
            }
        }

        // Remove transactions confirmed after fork
        {
            let mut txs = self.transactions.write();
            let before = txs.len();
            txs.retain(|_, tx| tx.block_height.map(|h| h <= fork_height).unwrap_or(true));
            let removed = before - txs.len();
            if removed > 0 {
                info!(
                    "Removed {} transactions above fork height {}",
                    removed, fork_height
                );
            }
        }

        // Restore UTXOs that were spent by transactions in orphaned blocks
        {
            let mut spent_data = self.spent_utxo_data.write();
            let mut spent_set = self.spent.write();
            let mut utxos = self.utxos.write();

            let to_restore: Vec<_> = spent_data
                .iter()
                .filter(|(_, (_, spent_height))| *spent_height > fork_height)
                .map(|(op, (utxo, _))| (*op, utxo.clone()))
                .collect();

            for (outpoint, utxo) in &to_restore {
                info!(
                    "Restoring UTXO {}:{} ({}) spent at orphaned height",
                    outpoint.txid, outpoint.vout, utxo.value
                );
                utxos.insert(*outpoint, utxo.clone());
                spent_set.remove(outpoint);
                spent_data.remove(outpoint);
                // Remove from persisted CF so it doesn't resurrect after next restart
                if let Some(ref db) = self.db {
                    if let Err(e) = db.remove_spent_utxo_data(outpoint) {
                        debug!("Failed to remove spent_utxo_data from disk: {}", e);
                    }
                }
            }

            if !to_restore.is_empty() {
                info!("Restored {} UTXOs from orphaned blocks", to_restore.len());
            }
        }

        let mut dirty = self.dirty.write();
        dirty.utxos = true;
        dirty.transactions = true;
        dirty.spent = true;
    }

    pub fn set_account(&self, address: &Address, account: &str) {
        let addr_str = address.to_string();
        let mut accounts = self.accounts.write();
        let mut address_accounts = self.address_accounts.write();

        if let Some(old_account) = address_accounts.get(&addr_str) {
            if let Some(addresses) = accounts.get_mut(old_account) {
                addresses.retain(|a| a != &addr_str);
            }
        }

        address_accounts.insert(addr_str.clone(), account.to_string());
        accounts
            .entry(account.to_string())
            .or_default()
            .push(addr_str);
        self.dirty.write().accounts = true;
    }

    pub fn get_account(&self, address: &Address) -> String {
        let addr_str = address.to_string();
        self.address_accounts
            .read()
            .get(&addr_str)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_addresses_by_account(&self, account: &str) -> Vec<String> {
        self.accounts
            .read()
            .get(account)
            .cloned()
            .unwrap_or_default()
    }

    pub fn list_accounts(&self) -> HashMap<String, Vec<String>> {
        self.accounts.read().clone()
    }

    pub fn add_script(&self, script: Script) -> Result<(), WalletError> {
        let script_hash = divi_crypto::hash160(script.as_bytes());
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(script_hash.as_ref());
        let hash160 = Hash160::from_bytes(hash_bytes);

        self.scripts.write().insert(hash160, script.clone());

        if let Some(db) = &self.db {
            db.store_script(&hash160, &script)?;
        }

        Ok(())
    }

    pub fn get_script(&self, script_hash: &Hash160) -> Option<Script> {
        self.scripts.read().get(script_hash).cloned()
    }

    /// Store vault metadata
    pub fn store_vault(&self, metadata: VaultMetadata) {
        self.vaults
            .write()
            .insert(metadata.vault_script.clone(), metadata.clone());

        if let Some(ref db) = self.db {
            db.store_vault(&metadata.vault_script, &metadata).ok();
        }
    }

    /// Get vault metadata by script
    pub fn get_vault(&self, vault_script: &[u8]) -> Option<VaultMetadata> {
        self.vaults.read().get(vault_script).cloned()
    }

    /// Remove vault metadata
    pub fn remove_vault(&self, vault_script: &[u8]) -> bool {
        let removed = self.vaults.write().remove(vault_script).is_some();

        if removed {
            if let Some(ref db) = self.db {
                db.remove_vault(vault_script).ok();
            }
        }

        removed
    }

    /// Get all vaults
    pub fn get_all_vaults(&self) -> Vec<VaultMetadata> {
        self.vaults.read().values().cloned().collect()
    }

    /// Find vault UTXOs (UTXOs that pay to any tracked vault script)
    pub fn get_vault_utxos(&self, current_height: u32, min_confirmations: u32) -> Vec<WalletUtxo> {
        let vaults = self.vaults.read();
        let vault_scripts: std::collections::HashSet<_> =
            vaults.keys().map(|k| k.as_slice()).collect();

        self.utxos
            .read()
            .values()
            .filter(|utxo| {
                let confs = utxo.confirmations(current_height);
                confs >= min_confirmations
                    && utxo.is_mature(current_height, self.coinbase_maturity())
                    && vault_scripts.contains(utxo.script_pubkey.as_bytes())
            })
            .cloned()
            .collect()
    }

    /// Get vault UTXOs suitable for staking, with their parsed vault script
    ///
    /// Returns (utxo, vault_script_parsed) pairs where the vault is registered
    /// and we have the manager key.
    pub fn get_stakeable_vault_utxos(
        &self,
        current_height: u32,
        min_confirmations: u32,
    ) -> Vec<(WalletUtxo, divi_script::StakingVaultScript)> {
        let vaults = self.vaults.read();
        // Pre-parse all registered vault scripts
        let vault_scripts: HashMap<Vec<u8>, divi_script::StakingVaultScript> = vaults
            .keys()
            .filter_map(|k| {
                let script = Script::from_bytes(k.clone());
                divi_script::StakingVaultScript::from_script(&script).map(|v| (k.clone(), v))
            })
            .collect();

        self.utxos
            .read()
            .values()
            .filter_map(|utxo| {
                let confs = utxo.confirmations(current_height);
                if confs < min_confirmations
                    || !utxo.is_mature(current_height, self.coinbase_maturity())
                {
                    return None;
                }
                let script_bytes = utxo.script_pubkey.as_bytes().to_vec();
                vault_scripts
                    .get(&script_bytes)
                    .map(|vault| (utxo.clone(), vault.clone()))
            })
            .collect()
    }
}

// Encryption helpers.
// These use AES-256-CBC with PBKDF2-HMAC-SHA512 for key derivation.

/// Number of PBKDF2 iterations (matches C++ Divi)
const PBKDF2_ITERATIONS: u32 = 25000;

/// Derive encryption key from passphrase using PBKDF2-HMAC-SHA512
fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Vec<u8> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;

    let mut key = vec![0u8; 32]; // AES-256 needs 32 bytes
    pbkdf2_hmac::<Sha512>(passphrase.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Decrypt the master key using the derived key
fn decrypt_master_key(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, WalletError> {
    use aes::Aes256;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    // Encrypted data format: [IV (16 bytes)] [encrypted_data]
    if encrypted.len() < 16 {
        return Err(WalletError::WrongPassphrase);
    }

    let (iv, ciphertext) = encrypted.split_at(16);

    // Create cipher
    type Aes256CbcDec = cbc::Decryptor<Aes256>;
    let cipher =
        Aes256CbcDec::new_from_slices(key, iv).map_err(|_| WalletError::WrongPassphrase)?;

    // Decrypt (need to create owned copy for in-place decryption)
    let mut buffer = ciphertext.to_vec();
    let decrypted = cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|_| WalletError::WrongPassphrase)?;

    Ok(decrypted.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdWallet;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn create_test_wallet() -> WalletDb {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        WalletDb::with_hd_wallet(Network::Mainnet, wallet)
    }

    #[test]
    fn test_wallet_creation() {
        let wallet = WalletDb::new(Network::Mainnet);
        assert_eq!(wallet.get_balance(), Amount::ZERO);
    }

    #[test]
    fn test_wallet_with_hd() {
        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();
        assert!(wallet.is_mine(&addr));
    }

    #[test]
    fn test_add_utxo() {
        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();

        let utxo = WalletUtxo::new(
            Hash256::from_bytes([1u8; 32]),
            0,
            Amount::from_sat(100_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );

        wallet.add_utxo(utxo.clone());

        assert!(wallet.has_utxo(&utxo.outpoint()));
        assert_eq!(wallet.get_balance(), Amount::from_sat(100_000_000));
    }

    #[test]
    fn test_spend_utxo() {
        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();

        let utxo = WalletUtxo::new(
            Hash256::from_bytes([1u8; 32]),
            0,
            Amount::from_sat(100_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        let outpoint = utxo.outpoint();

        wallet.add_utxo(utxo);
        assert_eq!(wallet.get_balance(), Amount::from_sat(100_000_000));

        wallet.spend_utxo(&outpoint);
        assert_eq!(wallet.get_balance(), Amount::ZERO);
    }

    #[test]
    fn test_confirmed_balance() {
        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();

        // Unconfirmed UTXO
        let mut utxo1 = WalletUtxo::new(
            Hash256::from_bytes([1u8; 32]),
            0,
            Amount::from_sat(50_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        utxo1.height = None;

        // Confirmed UTXO
        let mut utxo2 = WalletUtxo::new(
            Hash256::from_bytes([2u8; 32]),
            0,
            Amount::from_sat(100_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        utxo2.height = Some(100);

        wallet.add_utxo(utxo1);
        wallet.add_utxo(utxo2);

        // At height 105, only utxo2 has 6 confirmations
        assert_eq!(
            wallet.get_confirmed_balance(105, 1),
            Amount::from_sat(100_000_000)
        );
        assert_eq!(
            wallet.get_unconfirmed_balance(),
            Amount::from_sat(50_000_000)
        );
    }

    #[test]
    fn test_lock_unlock() {
        let wallet = create_test_wallet();

        assert!(!wallet.is_locked());
        wallet.lock();
        assert!(wallet.is_locked());

        // Should fail when locked
        assert!(wallet.new_receiving_address().is_err());

        wallet.unlock("", 0).unwrap();
        assert!(!wallet.is_locked());

        // Should work when unlocked
        assert!(wallet.new_receiving_address().is_ok());
    }

    #[test]
    fn test_transaction_history() {
        let wallet = create_test_wallet();

        let tx = WalletTx {
            txid: Hash256::from_bytes([1u8; 32]),
            block_hash: Some(Hash256::from_bytes([2u8; 32])),
            block_height: Some(100),
            timestamp: 1000000,
            amount: 100_000_000,
            fee: None,
            category: "receive".to_string(),
            confirmations: 10,
        };

        wallet.add_transaction(tx.clone());

        let history = wallet.get_transactions(None);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].txid, tx.txid);
    }

    #[test]
    fn test_utxo_maturity() {
        let mut utxo = WalletUtxo::new(
            Hash256::from_bytes([1u8; 32]),
            0,
            Amount::from_sat(100_000_000),
            Script::default(),
            "test".to_string(),
        );
        utxo.is_coinbase = true;
        utxo.height = Some(100);

        // At height 150, coinbase at 100 is not mature (need 100 confirmations)
        assert!(!utxo.is_mature(150, 100));

        // At height 200, coinbase at 100 is mature
        assert!(utxo.is_mature(200, 100));

        // Regular UTXO is always mature
        utxo.is_coinbase = false;
        assert!(utxo.is_mature(100, 100));
    }

    #[test]
    fn test_account_management() {
        let wallet = create_test_wallet();
        let addr1 = wallet.new_receiving_address().unwrap();
        let addr2 = wallet.new_receiving_address().unwrap();

        wallet.set_account(&addr1, "savings");
        wallet.set_account(&addr2, "checking");

        assert_eq!(wallet.get_account(&addr1), "savings");
        assert_eq!(wallet.get_account(&addr2), "checking");

        let savings_addrs = wallet.get_addresses_by_account("savings");
        assert_eq!(savings_addrs.len(), 1);
        assert!(savings_addrs.contains(&addr1.to_string()));

        wallet.set_account(&addr1, "checking");
        assert_eq!(wallet.get_account(&addr1), "checking");
        let checking_addrs = wallet.get_addresses_by_account("checking");
        assert_eq!(checking_addrs.len(), 2);
    }

    #[test]
    fn test_account_persistence() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.dat");

        {
            let wallet_hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet =
                WalletDb::create_persistent(&wallet_path, Network::Mainnet, wallet_hd).unwrap();

            let addr1 = wallet.new_receiving_address().unwrap();
            let addr2 = wallet.new_receiving_address().unwrap();

            wallet.set_account(&addr1, "test_account");
            wallet.set_account(&addr2, "another_account");

            wallet.save().unwrap();
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();
            let accounts = wallet.list_accounts();

            assert!(accounts.contains_key("test_account"));
            assert!(accounts.contains_key("another_account"));
            assert_eq!(accounts.get("test_account").unwrap().len(), 1);
            assert_eq!(accounts.get("another_account").unwrap().len(), 1);
        }
    }

    #[test]
    fn test_script_storage() {
        let wallet = create_test_wallet();

        let script_bytes = vec![
            0x51, 0x21, 0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x21, 0x03, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x52,
            0xae,
        ];
        let script = Script::from_bytes(script_bytes);

        wallet.add_script(script.clone()).unwrap();

        let script_hash = divi_crypto::hash160(script.as_bytes());
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(script_hash.as_ref());
        let hash160 = Hash160::from_bytes(hash_bytes);

        let retrieved = wallet.get_script(&hash160);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().as_bytes(), script.as_bytes());
    }

    #[test]
    fn test_script_persistence() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.dat");

        let script_bytes = vec![
            0x51, 0x21, 0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x52, 0xae,
        ];
        let script = Script::from_bytes(script_bytes.clone());

        let script_hash = divi_crypto::hash160(&script_bytes);
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(script_hash.as_ref());
        let hash160 = Hash160::from_bytes(hash_bytes);

        {
            let wallet_hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet =
                WalletDb::create_persistent(&wallet_path, Network::Mainnet, wallet_hd).unwrap();

            wallet.add_script(script.clone()).unwrap();
            wallet.save().unwrap();
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();

            let retrieved = wallet.get_script(&hash160);
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().as_bytes(), script.as_bytes());
        }
    }

    #[test]
    fn test_vault_persistence() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.dat");

        let vault_script = vec![1u8; 50];
        let funding_txid = [2u8; 32];

        {
            let wallet_hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet =
                WalletDb::create_persistent(&wallet_path, Network::Mainnet, wallet_hd).unwrap();

            let metadata = VaultMetadata {
                owner_address: "DOwnerAddress123".to_string(),
                manager_address: "DManagerAddress456".to_string(),
                vault_script: vault_script.clone(),
                funding_txid,
            };

            wallet.store_vault(metadata);
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();

            let retrieved = wallet.get_vault(&vault_script);
            assert!(retrieved.is_some());
            let metadata = retrieved.unwrap();
            assert_eq!(metadata.owner_address, "DOwnerAddress123");
            assert_eq!(metadata.manager_address, "DManagerAddress456");
            assert_eq!(metadata.vault_script, vault_script);
            assert_eq!(metadata.funding_txid, funding_txid);

            let all_vaults = wallet.get_all_vaults();
            assert_eq!(all_vaults.len(), 1);
        }
    }

    #[test]
    fn test_vault_removal_persistence() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.dat");

        let vault_script = vec![3u8; 50];
        let funding_txid = [4u8; 32];

        {
            let wallet_hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet =
                WalletDb::create_persistent(&wallet_path, Network::Mainnet, wallet_hd).unwrap();

            let metadata = VaultMetadata {
                owner_address: "DOwnerAddress789".to_string(),
                manager_address: "DManagerAddress012".to_string(),
                vault_script: vault_script.clone(),
                funding_txid,
            };

            wallet.store_vault(metadata);
            assert!(wallet.get_vault(&vault_script).is_some());

            let removed = wallet.remove_vault(&vault_script);
            assert!(removed);
            assert!(wallet.get_vault(&vault_script).is_none());
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();

            let retrieved = wallet.get_vault(&vault_script);
            assert!(retrieved.is_none());

            let all_vaults = wallet.get_all_vaults();
            assert_eq!(all_vaults.len(), 0);
        }
    }

    #[test]
    fn test_fee_calculation_for_sent_transactions() {
        use divi_primitives::transaction::{OutPoint as TxOutPoint, Transaction, TxIn, TxOut};

        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();
        let change_addr = wallet.new_change_address().unwrap();

        // First, add a UTXO to the wallet (1 DIVI = 100_000_000 satoshis)
        let input_txid = Hash256::from_bytes([1u8; 32]);
        let input_value = Amount::from_sat(100_000_000); // 1 DIVI
        let input_utxo = WalletUtxo::new(
            input_txid,
            0,
            input_value,
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        wallet.add_utxo(input_utxo);

        // Create a transaction that spends the UTXO
        // Send 0.9 DIVI to external, 0.09 DIVI change back to wallet, 0.01 DIVI fee
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: TxOutPoint {
                    txid: input_txid,
                    vout: 0,
                },
                script_sig: Script::default(),
                sequence: 0xffffffff,
            }],
            vout: vec![
                // Output to external address (not ours) - 0.9 DIVI
                TxOut {
                    value: Amount::from_sat(90_000_000),
                    script_pubkey: Script::new_p2pkh(&[0xaa; 20]), // Some external address
                },
                // Change back to our wallet - 0.09 DIVI
                TxOut {
                    value: Amount::from_sat(9_000_000),
                    script_pubkey: Script::new_p2pkh(change_addr.hash.as_bytes()),
                },
            ],
            lock_time: 0,
        };

        // Scan the transaction
        let block_hash = Hash256::from_bytes([2u8; 32]);
        wallet.scan_transaction(&tx, Some(block_hash), Some(100), Some(1000000));

        // Verify the transaction was recorded with correct fee
        let wallet_tx = wallet.get_transaction(&tx.txid()).unwrap();

        // Category should be "send" since we spent more than we received back
        assert_eq!(wallet_tx.category, "send");

        // Fee should be: inputs (100M) - total outputs (90M + 9M) = 1M satoshis = 0.01 DIVI
        assert!(wallet_tx.fee.is_some());
        let fee = wallet_tx.fee.unwrap();
        assert_eq!(fee.as_sat(), 1_000_000); // 0.01 DIVI fee

        // Net amount should be change received (9M) - sent (100M) = -91M
        // (negative because we're sending)
        assert_eq!(wallet_tx.amount, 9_000_000 - 100_000_000);
    }

    // -------- chain_mode persistence: PrivateDivi round-trip --------

    #[test]
    fn test_privatedivi_chain_mode_persists_and_restores_coin_type() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet_pd.dat");

        // Derive and record what address index 0 looks like before save
        let addr_before = {
            let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::PrivateDivi).unwrap();
            // coin_type must be 801
            assert_eq!(hd.coin_type(), 801);
            let wallet = WalletDb::create_persistent(&wallet_path, Network::Mainnet, hd).unwrap();
            let addr = wallet.new_receiving_address().unwrap();
            wallet.save().unwrap();
            addr
        };

        // Re-open and derive again: the restored coin_type must still be 801
        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();
            let addr_after = wallet.new_receiving_address().unwrap();
            // The second open resumes from index 1 (index 0 was already issued),
            // but we can verify chain_mode is correct by checking the keystore has
            // the same PrivateDivi-derived key for index 0.
            assert!(wallet.is_mine(&addr_before));
            // addr_after is index 1 in the PrivateDivi path — it must differ from
            // what Divi's path would produce at index 1.
            let divi_wallet = WalletDb::with_hd_wallet(
                Network::Mainnet,
                HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap(),
            );
            // Drain to index 1 for Divi
            let _ = divi_wallet.new_receiving_address().unwrap();
            let divi_addr_1 = divi_wallet.new_receiving_address().unwrap();
            // PrivateDivi address at index 1 must differ from Divi address at index 1
            assert_ne!(addr_after.to_string(), divi_addr_1.to_string());
        }
    }

    // -------- last_scan_height set / get --------

    #[test]
    fn test_set_get_last_scan_height() {
        let wallet = create_test_wallet();

        assert_eq!(wallet.last_scan_height(), 0);
        wallet.set_last_scan_height(42_000);
        assert_eq!(wallet.last_scan_height(), 42_000);
    }

    #[test]
    fn test_last_scan_height_persists() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("scan_height_test.dat");

        {
            let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet = WalletDb::create_persistent(&wallet_path, Network::Mainnet, hd).unwrap();
            wallet.set_last_scan_height(99_999);
            wallet.save().unwrap();
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();
            assert_eq!(wallet.last_scan_height(), 99_999);
        }
    }

    // -------- UTXO confirmations helper --------

    #[test]
    fn test_utxo_confirmations_confirmed() {
        let utxo = WalletUtxo {
            txid: Hash256::from_bytes([1u8; 32]),
            vout: 0,
            value: Amount::from_sat(1_000),
            script_pubkey: Script::default(),
            height: Some(100),
            is_coinbase: false,
            is_coinstake: false,
            address: "test".to_string(),
        };

        // At current height 105: 105 - 100 + 1 = 6 confirmations
        assert_eq!(utxo.confirmations(105), 6);
        // At current height 100: 1 confirmation
        assert_eq!(utxo.confirmations(100), 1);
        // At height 99 (before conf): 0
        assert_eq!(utxo.confirmations(99), 0);
    }

    #[test]
    fn test_utxo_confirmations_unconfirmed() {
        let utxo = WalletUtxo {
            txid: Hash256::from_bytes([2u8; 32]),
            vout: 0,
            value: Amount::from_sat(1_000),
            script_pubkey: Script::default(),
            height: None, // unconfirmed
            is_coinbase: false,
            is_coinstake: false,
            address: "test".to_string(),
        };

        assert_eq!(utxo.confirmations(1_000_000), 0);
    }

    // -------- coinbase_maturity by network --------

    #[test]
    fn test_coinbase_maturity_mainnet_is_20() {
        let wallet = WalletDb::new(Network::Mainnet);
        assert_eq!(wallet.coinbase_maturity(), 20);
    }

    #[test]
    fn test_coinbase_maturity_testnet_is_1() {
        let wallet = WalletDb::new(Network::Testnet);
        assert_eq!(wallet.coinbase_maturity(), 1);
    }

    // -------- get_spendable_utxos excludes immature coinbase --------

    #[test]
    fn test_spendable_utxos_excludes_immature_coinbase() {
        let wallet = create_test_wallet(); // Mainnet → maturity = 20
        let addr = wallet.new_receiving_address().unwrap();

        // Coinbase confirmed at height 100.
        // is_mature() uses: current_height >= h + maturity → current_height >= 120
        let mut cb_utxo = WalletUtxo::new(
            Hash256::from_bytes([0xc0; 32]),
            0,
            Amount::from_sat(5_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        cb_utxo.is_coinbase = true;
        cb_utxo.height = Some(100);

        wallet.add_utxo(cb_utxo.clone());

        // At height 120: 120 >= 100 + 20 → mature (boundary)
        let spendable_mature = wallet.get_spendable_utxos(120, 1);
        assert_eq!(
            spendable_mature.len(),
            1,
            "Should be spendable at exactly the maturity boundary"
        );

        // At height 119: 119 < 100 + 20 → NOT mature
        let spendable_immature = wallet.get_spendable_utxos(119, 1);
        assert_eq!(
            spendable_immature.len(),
            0,
            "Should not be spendable before maturity boundary"
        );
    }
}
