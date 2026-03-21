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

//! Wallet database persistence
//!
//! Provides persistent storage for wallet data using RocksDB.

use crate::address::Network;
use crate::error::WalletError;
use crate::keystore::KeyEntry;
use crate::wallet_db::{WalletTx, WalletUtxo};

use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::script::Script;
use divi_primitives::transaction::OutPoint;
use divi_primitives::ChainMode;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;
use tracing::{debug, info};

/// Column family names
const CF_DEFAULT: &str = "default";
const CF_METADATA: &str = "wallet_metadata";
const CF_KEYS: &str = "wallet_keys";
const CF_UTXOS: &str = "wallet_utxos";
const CF_SPENT: &str = "wallet_spent";
const CF_TRANSACTIONS: &str = "wallet_transactions";
const CF_ADDRESSES: &str = "wallet_addresses";
const CF_ACCOUNTS: &str = "wallet_accounts";
const CF_SCRIPTS: &str = "wallet_scripts";
const CF_VAULTS: &str = "wallet_vaults";
const CF_SPENT_UTXO_DATA: &str = "spent_utxo_data";
// Legacy column families - kept for backward compatibility with existing databases
const CF_WATCH_ONLY_ADDRESSES: &str = "watch_only_addresses";
const CF_VAULTS_LEGACY: &str = "vaults";

/// Metadata keys
const KEY_MNEMONIC: &[u8] = b"mnemonic";
const KEY_NETWORK: &[u8] = b"network";
const KEY_ENCRYPTED: &[u8] = b"encrypted";
const KEY_RECEIVING_INDEX: &[u8] = b"receiving_index";
const KEY_CHANGE_INDEX: &[u8] = b"change_index";
const KEY_LAST_SCAN_HEIGHT: &[u8] = b"last_scan_height";
const KEY_ENCRYPTION_SALT: &[u8] = b"encryption_salt";
const KEY_ENCRYPTED_MASTER_KEY: &[u8] = b"encrypted_master_key";
const KEY_CHAIN_MODE: &[u8] = b"chain_mode";

/// Wallet database for persistence
pub struct WalletDatabase {
    db: DB,
}

impl WalletDatabase {
    /// Open or create a wallet database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, WalletError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        // Limit WAL size to prevent unbounded growth (wallet data is tiny ~2 MB)
        opts.set_max_total_wal_size(16 * 1024 * 1024); // 16 MB max WAL
        opts.set_max_background_jobs(2);

        // Per-CF options with small write buffers (default 64 MB is way too large
        // for wallet data that totals ~2 MB across all CFs)
        let mut cf_opts = Options::default();
        cf_opts.set_write_buffer_size(2 * 1024 * 1024); // 2 MB (not 64 MB default)
        cf_opts.set_max_write_buffer_number(2);
        cf_opts.set_level_compaction_dynamic_level_bytes(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_DEFAULT, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_METADATA, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_KEYS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_UTXOS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_SPENT, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_TRANSACTIONS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_ADDRESSES, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_ACCOUNTS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_SCRIPTS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_VAULTS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_SPENT_UTXO_DATA, cf_opts.clone()),
            // Legacy column families for backward compatibility
            ColumnFamilyDescriptor::new(CF_WATCH_ONLY_ADDRESSES, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_VAULTS_LEGACY, cf_opts),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| WalletError::Storage(e.to_string()))?;

        info!("Wallet database opened");
        Ok(WalletDatabase { db })
    }

    pub fn path(&self) -> &Path {
        self.db.path()
    }

    // ========== Metadata ==========

    /// Store the mnemonic (should be encrypted in production)
    pub fn store_mnemonic(&self, mnemonic: &str) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        self.db
            .put_cf(cf, KEY_MNEMONIC, mnemonic.as_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        debug!("Stored mnemonic");
        Ok(())
    }

    /// Load the mnemonic
    pub fn load_mnemonic(&self) -> Result<Option<String>, WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        match self
            .db
            .get_cf(cf, KEY_MNEMONIC)
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) => {
                let mnemonic =
                    String::from_utf8(data).map_err(|e| WalletError::Storage(e.to_string()))?;
                Ok(Some(mnemonic))
            }
            None => Ok(None),
        }
    }

    /// Store network type
    pub fn store_network(&self, network: Network) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        let value = match network {
            Network::Mainnet => b"mainnet".to_vec(),
            Network::Testnet => b"testnet".to_vec(),
            Network::Regtest => b"regtest".to_vec(),
        };
        self.db
            .put_cf(cf, KEY_NETWORK, value)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load network type
    pub fn load_network(&self) -> Result<Option<Network>, WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        match self
            .db
            .get_cf(cf, KEY_NETWORK)
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) => {
                let network = match data.as_slice() {
                    b"mainnet" => Network::Mainnet,
                    b"testnet" => Network::Testnet,
                    b"regtest" => Network::Regtest,
                    _ => return Err(WalletError::Storage("Invalid network".into())),
                };
                Ok(Some(network))
            }
            None => Ok(None),
        }
    }

    /// Store chain mode (Divi vs PrivateDivi) for correct HD derivation on reload
    pub fn store_chain_mode(&self, mode: ChainMode) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        let value = match mode {
            ChainMode::Divi => b"divi".to_vec(),
            ChainMode::PrivateDivi => b"privatedivi".to_vec(),
        };
        self.db
            .put_cf(cf, KEY_CHAIN_MODE, value)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load chain mode
    pub fn load_chain_mode(&self) -> Result<Option<ChainMode>, WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        match self
            .db
            .get_cf(cf, KEY_CHAIN_MODE)
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) => {
                let mode = match data.as_slice() {
                    b"divi" => ChainMode::Divi,
                    b"privatedivi" => ChainMode::PrivateDivi,
                    _ => return Err(WalletError::Storage("Invalid chain mode".into())),
                };
                Ok(Some(mode))
            }
            None => Ok(None),
        }
    }

    /// Store encrypted flag
    pub fn store_encrypted(&self, encrypted: bool) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        self.db
            .put_cf(cf, KEY_ENCRYPTED, &[encrypted as u8])
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load encrypted flag
    pub fn load_encrypted(&self) -> Result<bool, WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        match self
            .db
            .get_cf(cf, KEY_ENCRYPTED)
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) => Ok(!data.is_empty() && data[0] != 0),
            None => Ok(false),
        }
    }

    /// Store encryption metadata (salt and encrypted master key)
    pub fn store_encryption_metadata(
        &self,
        salt: &[u8],
        encrypted_master_key: &[u8],
    ) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        self.db
            .put_cf(cf, KEY_ENCRYPTION_SALT, salt)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        self.db
            .put_cf(cf, KEY_ENCRYPTED_MASTER_KEY, encrypted_master_key)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load encryption metadata (salt and encrypted master key)
    pub fn load_encryption_metadata(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();

        let salt = match self
            .db
            .get_cf(cf, KEY_ENCRYPTION_SALT)
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) => data,
            None => return Ok(None),
        };

        let encrypted_key = match self
            .db
            .get_cf(cf, KEY_ENCRYPTED_MASTER_KEY)
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) => data,
            None => return Ok(None),
        };

        Ok(Some((salt, encrypted_key)))
    }

    /// Store HD wallet indices
    pub fn store_indices(&self, receiving: u32, change: u32) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        self.db
            .put_cf(cf, KEY_RECEIVING_INDEX, &receiving.to_le_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        self.db
            .put_cf(cf, KEY_CHANGE_INDEX, &change.to_le_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load HD wallet indices
    pub fn load_indices(&self) -> Result<(u32, u32), WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();

        let receiving = match self
            .db
            .get_cf(cf, KEY_RECEIVING_INDEX)
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) if data.len() == 4 => {
                u32::from_le_bytes([data[0], data[1], data[2], data[3]])
            }
            _ => 0,
        };

        let change = match self
            .db
            .get_cf(cf, KEY_CHANGE_INDEX)
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) if data.len() == 4 => {
                u32::from_le_bytes([data[0], data[1], data[2], data[3]])
            }
            _ => 0,
        };

        Ok((receiving, change))
    }

    /// Store last scan height
    pub fn store_last_scan_height(&self, height: u32) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        self.db
            .put_cf(cf, KEY_LAST_SCAN_HEIGHT, &height.to_le_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load last scan height
    pub fn load_last_scan_height(&self) -> Result<u32, WalletError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        match self
            .db
            .get_cf(cf, KEY_LAST_SCAN_HEIGHT)
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) if data.len() == 4 => {
                Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
            }
            _ => Ok(0),
        }
    }

    // ========== Keys ==========

    /// Store a key entry
    pub fn store_key(&self, hash: &Hash160, entry: &KeyEntry) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_KEYS).unwrap();
        let key = hash.as_bytes();
        let value = serialize_key_entry(entry);
        self.db
            .put_cf(cf, key, value)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load all keys
    pub fn load_keys(&self) -> Result<Vec<(Hash160, KeyEntry)>, WalletError> {
        let cf = self.db.cf_handle(CF_KEYS).unwrap();
        let mut keys = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            if key.len() == 20 {
                let hash = Hash160::from_bytes(key[..20].try_into().unwrap());
                match deserialize_key_entry(&value) {
                    Ok(entry) => keys.push((hash, entry)),
                    Err(e) => {
                        debug!("Failed to deserialize key: {}", e);
                    }
                }
            }
        }

        Ok(keys)
    }

    // ========== UTXOs ==========

    /// Store a UTXO
    pub fn store_utxo(&self, outpoint: &OutPoint, utxo: &WalletUtxo) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_UTXOS).unwrap();
        let key = outpoint_key(outpoint);
        let value = serialize_utxo(utxo);
        self.db
            .put_cf(cf, key, value)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Remove a UTXO
    pub fn remove_utxo(&self, outpoint: &OutPoint) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_UTXOS).unwrap();
        let key = outpoint_key(outpoint);
        self.db
            .delete_cf(cf, key)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load all UTXOs
    pub fn load_utxos(&self) -> Result<Vec<(OutPoint, WalletUtxo)>, WalletError> {
        let cf = self.db.cf_handle(CF_UTXOS).unwrap();
        let mut utxos = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            if key.len() == 36 {
                let outpoint = outpoint_from_key(&key);
                match deserialize_utxo(&value) {
                    Ok(utxo) => utxos.push((outpoint, utxo)),
                    Err(e) => {
                        debug!("Failed to deserialize UTXO: {}", e);
                    }
                }
            }
        }

        Ok(utxos)
    }

    // ========== Spent Outpoints ==========

    /// Mark an outpoint as spent
    pub fn mark_spent(&self, outpoint: &OutPoint) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_SPENT).unwrap();
        let key = outpoint_key(outpoint);
        self.db
            .put_cf(cf, key, &[1])
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load all spent outpoints
    pub fn load_spent(&self) -> Result<Vec<OutPoint>, WalletError> {
        let cf = self.db.cf_handle(CF_SPENT).unwrap();
        let mut spent = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            if key.len() == 36 {
                spent.push(outpoint_from_key(&key));
            }
        }

        Ok(spent)
    }

    // ========== Transactions ==========

    /// Store a transaction record
    pub fn store_transaction(&self, tx: &WalletTx) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_TRANSACTIONS).unwrap();
        let key = tx.txid.as_bytes();
        let value = serialize_tx(tx);
        self.db
            .put_cf(cf, key, value)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load all transactions
    pub fn load_transactions(&self) -> Result<Vec<WalletTx>, WalletError> {
        let cf = self.db.cf_handle(CF_TRANSACTIONS).unwrap();
        let mut transactions = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (_, value) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            match deserialize_tx(&value) {
                Ok(tx) => transactions.push(tx),
                Err(e) => {
                    debug!("Failed to deserialize transaction: {}", e);
                }
            }
        }

        Ok(transactions)
    }

    // ========== Used Addresses ==========

    /// Mark an address as used
    pub fn mark_address_used(&self, address: &str) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_ADDRESSES).unwrap();
        self.db
            .put_cf(cf, address.as_bytes(), &[1])
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load all used addresses
    pub fn load_used_addresses(&self) -> Result<Vec<String>, WalletError> {
        let cf = self.db.cf_handle(CF_ADDRESSES).unwrap();
        let mut addresses = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            if let Ok(addr) = String::from_utf8(key.to_vec()) {
                addresses.push(addr);
            }
        }

        Ok(addresses)
    }

    // ========== Accounts ==========

    /// Store account to addresses mapping
    pub fn store_account(&self, account: &str, addresses: &[String]) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_ACCOUNTS).unwrap();
        let key = format!("acc_{}", account);
        let value = serde_json::to_string(addresses)
            .map_err(|e| WalletError::Storage(format!("Failed to serialize account: {}", e)))?;
        self.db
            .put_cf(cf, key.as_bytes(), value.as_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Store address to account mapping
    pub fn store_address_account(&self, address: &str, account: &str) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_ACCOUNTS).unwrap();
        let key = format!("addr_{}", address);
        self.db
            .put_cf(cf, key.as_bytes(), account.as_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load all accounts with their addresses
    pub fn load_accounts(&self) -> Result<Vec<(String, Vec<String>)>, WalletError> {
        let cf = self.db.cf_handle(CF_ACCOUNTS).unwrap();
        let mut accounts = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                if key_str.starts_with("acc_") {
                    let account = key_str[4..].to_string();
                    let addresses: Vec<String> = serde_json::from_slice(&value).map_err(|e| {
                        WalletError::Storage(format!("Failed to deserialize account: {}", e))
                    })?;
                    accounts.push((account, addresses));
                }
            }
        }

        Ok(accounts)
    }

    /// Load address to account mappings
    pub fn load_address_accounts(&self) -> Result<Vec<(String, String)>, WalletError> {
        let cf = self.db.cf_handle(CF_ACCOUNTS).unwrap();
        let mut mappings = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                if key_str.starts_with("addr_") {
                    let address = key_str[5..].to_string();
                    let account = String::from_utf8(value.to_vec())
                        .map_err(|e| WalletError::Storage(e.to_string()))?;
                    mappings.push((address, account));
                }
            }
        }

        Ok(mappings)
    }

    pub fn store_script(&self, script_hash: &Hash160, script: &Script) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_SCRIPTS).unwrap();
        self.db
            .put_cf(cf, script_hash.as_bytes(), script.as_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_script(&self, script_hash: &Hash160) -> Result<Option<Script>, WalletError> {
        let cf = self.db.cf_handle(CF_SCRIPTS).unwrap();
        match self
            .db
            .get_cf(cf, script_hash.as_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(data) => Ok(Some(Script::from_bytes(data))),
            None => Ok(None),
        }
    }

    pub fn load_scripts(&self) -> Result<Vec<(Hash160, Script)>, WalletError> {
        let cf = self.db.cf_handle(CF_SCRIPTS).unwrap();
        let mut scripts = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            if key.len() == 20 {
                let hash = Hash160::from_bytes(key[..20].try_into().unwrap());
                let script = Script::from_bytes(value.to_vec());
                scripts.push((hash, script));
            }
        }

        Ok(scripts)
    }

    // ========== Vaults ==========

    /// Store vault metadata
    pub fn store_vault(
        &self,
        vault_script: &[u8],
        metadata: &crate::wallet_db::VaultMetadata,
    ) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_VAULTS).unwrap();
        let value = serialize_vault_metadata(metadata);
        self.db
            .put_cf(cf, vault_script, value)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        debug!("Stored vault metadata for script");
        Ok(())
    }

    /// Load all vaults
    pub fn load_vaults(
        &self,
    ) -> Result<Vec<(Vec<u8>, crate::wallet_db::VaultMetadata)>, WalletError> {
        let cf = self.db.cf_handle(CF_VAULTS).unwrap();
        let mut vaults = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            match deserialize_vault_metadata(&value) {
                Ok(metadata) => vaults.push((key.to_vec(), metadata)),
                Err(e) => {
                    debug!("Failed to deserialize vault metadata: {}", e);
                }
            }
        }

        Ok(vaults)
    }

    /// Remove vault metadata
    pub fn remove_vault(&self, vault_script: &[u8]) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_VAULTS).unwrap();
        self.db
            .delete_cf(cf, vault_script)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        debug!("Removed vault metadata");
        Ok(())
    }

    pub fn flush(&self) -> Result<(), WalletError> {
        self.db
            .flush()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    // ========== WriteBatch support ==========

    /// Create a new WriteBatch for atomic writes
    pub fn create_batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Write a batch atomically
    pub fn write_batch(&self, batch: WriteBatch) -> Result<(), WalletError> {
        self.db
            .write(batch)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get a column family handle by name
    pub fn cf(&self, name: &str) -> &rocksdb::ColumnFamily {
        self.db.cf_handle(name).unwrap()
    }

    // ========== Column family name accessors ==========

    pub fn cf_metadata(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_METADATA)
    }

    pub fn cf_keys(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_KEYS)
    }

    pub fn cf_utxos(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_UTXOS)
    }

    pub fn cf_spent(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_SPENT)
    }

    pub fn cf_transactions(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_TRANSACTIONS)
    }

    pub fn cf_addresses(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_ADDRESSES)
    }

    pub fn cf_accounts(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_ACCOUNTS)
    }

    pub fn cf_scripts(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_SCRIPTS)
    }

    pub fn cf_vaults_cf(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_VAULTS)
    }

    pub fn cf_spent_utxo_data(&self) -> &rocksdb::ColumnFamily {
        self.cf(CF_SPENT_UTXO_DATA)
    }

    // ========== Spent UTXO Data (for reorg restoration) ==========

    /// Store a spent UTXO with its spending height for reorg recovery.
    /// Key: OutPoint (36 bytes), Value: serialized WalletUtxo + spent_height (4 bytes)
    pub fn store_spent_utxo_data(
        &self,
        outpoint: &OutPoint,
        utxo: &WalletUtxo,
        spent_height: u32,
    ) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_SPENT_UTXO_DATA).unwrap();
        let key = outpoint_key(outpoint);
        let mut value = serialize_utxo(utxo);
        value.extend_from_slice(&spent_height.to_le_bytes());
        self.db
            .put_cf(cf, &key, &value)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Remove a spent UTXO data entry (after reorg restores it)
    pub fn remove_spent_utxo_data(&self, outpoint: &OutPoint) -> Result<(), WalletError> {
        let cf = self.db.cf_handle(CF_SPENT_UTXO_DATA).unwrap();
        let key = outpoint_key(outpoint);
        self.db
            .delete_cf(cf, &key)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load all spent UTXO data entries from disk
    pub fn load_spent_utxo_data(&self) -> Result<Vec<(OutPoint, WalletUtxo, u32)>, WalletError> {
        let cf = self.db.cf_handle(CF_SPENT_UTXO_DATA).unwrap();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut results = Vec::new();

        for item in iter {
            let (key, value) = item.map_err(|e| WalletError::Storage(e.to_string()))?;
            if key.len() != 36 {
                continue;
            }
            let outpoint = outpoint_from_key(&key);
            // Value = serialized WalletUtxo + 4 bytes spent_height
            if value.len() < 4 {
                continue;
            }
            let spent_height_bytes = &value[value.len() - 4..];
            let spent_height = u32::from_le_bytes([
                spent_height_bytes[0],
                spent_height_bytes[1],
                spent_height_bytes[2],
                spent_height_bytes[3],
            ]);
            let utxo_data = &value[..value.len() - 4];
            match deserialize_utxo(utxo_data) {
                Ok(utxo) => results.push((outpoint, utxo, spent_height)),
                Err(e) => {
                    debug!("Skipping corrupt spent_utxo_data entry: {}", e);
                    continue;
                }
            }
        }

        Ok(results)
    }
}

// ========== Serialization Helpers ==========

pub(crate) fn outpoint_key(outpoint: &OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.vout.to_le_bytes());
    key
}

fn outpoint_from_key(key: &[u8]) -> OutPoint {
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&key[0..32]);
    let vout = u32::from_le_bytes([key[32], key[33], key[34], key[35]]);
    OutPoint::new(Hash256::from_bytes(txid_bytes), vout)
}

pub(crate) fn serialize_key_entry(entry: &KeyEntry) -> Vec<u8> {
    // Format v2: version(1) + flags(1) + [secret(32) OR pubkey(33)] + created(8) + label_len(4) + label + path_len(4) + path
    let mut data = Vec::new();

    // Version byte (2 = watch-only support)
    data.push(2u8);

    // Flags: bit 0 = watch_only
    let flags = if entry.is_watch_only { 0x01 } else { 0x00 };
    data.push(flags);

    // Key data
    if let Some(ref secret) = entry.secret {
        // Regular key with private key (32 bytes)
        data.extend_from_slice(secret.as_bytes());
    } else {
        // Watch-only: store public key (33 bytes compressed)
        data.extend_from_slice(&entry.public.to_bytes());
    }

    // Created timestamp (8 bytes)
    data.extend_from_slice(&entry.created.to_le_bytes());

    // Label (length-prefixed)
    if let Some(ref label) = entry.label {
        let bytes = label.as_bytes();
        data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(bytes);
    } else {
        data.extend_from_slice(&0u32.to_le_bytes());
    }

    // HD path (length-prefixed)
    if let Some(ref path) = entry.hd_path {
        let bytes = path.as_bytes();
        data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(bytes);
    } else {
        data.extend_from_slice(&0u32.to_le_bytes());
    }

    data
}

fn deserialize_key_entry(data: &[u8]) -> Result<KeyEntry, WalletError> {
    use divi_crypto::keys::PublicKey;

    if data.len() < 44 {
        return Err(WalletError::Storage("Invalid key entry data".into()));
    }

    let mut pos = 0;

    // Check for version byte (v2 starts with version 2)
    let (is_watch_only, secret, public) = if data[0] == 2 {
        // New format with version and flags
        pos = 1; // Skip version
        let flags = data[pos];
        pos += 1;
        let is_watch_only = (flags & 0x01) != 0;

        if is_watch_only {
            // Watch-only: read public key (33 bytes)
            if data.len() < pos + 33 {
                return Err(WalletError::Storage("Invalid watch-only key data".into()));
            }
            let pubkey_bytes: [u8; 33] = data[pos..pos + 33].try_into().unwrap();
            let public = PublicKey::from_bytes(&pubkey_bytes)
                .map_err(|e| WalletError::Storage(format!("Invalid public key: {}", e)))?;
            pos += 33;
            (true, None, public)
        } else {
            // Regular key: read secret (32 bytes)
            if data.len() < pos + 32 {
                return Err(WalletError::Storage("Invalid key data".into()));
            }
            let secret_bytes: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
            let secret = SecretKey::from_bytes(&secret_bytes)
                .map_err(|e| WalletError::Storage(format!("Invalid secret key: {}", e)))?;
            let public = secret.public_key();
            pos += 32;
            (false, Some(secret), public)
        }
    } else {
        // Old format (no version byte) - starts with secret key
        let secret_bytes: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
        let secret = SecretKey::from_bytes(&secret_bytes)
            .map_err(|e| WalletError::Storage(format!("Invalid secret key: {}", e)))?;
        let public = secret.public_key();
        pos += 32;
        (false, Some(secret), public)
    };

    // Created timestamp
    let created = u64::from_le_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
        data[pos + 4],
        data[pos + 5],
        data[pos + 6],
        data[pos + 7],
    ]);
    pos += 8;

    // Label
    let label_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    let label = if label_len > 0 && pos + label_len <= data.len() {
        Some(
            String::from_utf8(data[pos..pos + label_len].to_vec())
                .map_err(|e| WalletError::Storage(e.to_string()))?,
        )
    } else {
        None
    };
    pos += label_len;

    // HD path
    let path = if pos + 4 <= data.len() {
        let path_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if path_len > 0 && pos + path_len <= data.len() {
            Some(
                String::from_utf8(data[pos..pos + path_len].to_vec())
                    .map_err(|e| WalletError::Storage(e.to_string()))?,
            )
        } else {
            None
        }
    } else {
        None
    };

    Ok(KeyEntry {
        secret,
        public,
        created,
        label,
        hd_path: path,
        is_watch_only,
    })
}

pub(crate) fn serialize_utxo(utxo: &WalletUtxo) -> Vec<u8> {
    // Format: txid(32) + vout(4) + value(8) + height(4, 0xFFFFFFFF=None) + flags(1) + script_len(4) + script + addr_len(4) + addr
    let mut data = Vec::new();

    // txid
    data.extend_from_slice(utxo.txid.as_bytes());

    // vout
    data.extend_from_slice(&utxo.vout.to_le_bytes());

    // value
    data.extend_from_slice(&utxo.value.as_sat().to_le_bytes());

    // height (None = 0xFFFFFFFF)
    let height = utxo.height.unwrap_or(0xFFFFFFFF);
    data.extend_from_slice(&height.to_le_bytes());

    // flags: bit 0 = coinbase, bit 1 = coinstake
    let mut flags = 0u8;
    if utxo.is_coinbase {
        flags |= 1;
    }
    if utxo.is_coinstake {
        flags |= 2;
    }
    data.push(flags);

    // script
    let script_bytes = utxo.script_pubkey.as_bytes();
    data.extend_from_slice(&(script_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(script_bytes);

    // address
    let addr_bytes = utxo.address.as_bytes();
    data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(addr_bytes);

    data
}

fn deserialize_utxo(data: &[u8]) -> Result<WalletUtxo, WalletError> {
    if data.len() < 53 {
        // 32 + 4 + 8 + 4 + 1 + 4
        return Err(WalletError::Storage("Invalid UTXO data".into()));
    }

    let mut pos = 0;

    // txid
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&data[pos..pos + 32]);
    let txid = Hash256::from_bytes(txid_bytes);
    pos += 32;

    // vout
    let vout = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    // value
    let value = i64::from_le_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
        data[pos + 4],
        data[pos + 5],
        data[pos + 6],
        data[pos + 7],
    ]);
    let value = Amount::from_sat(value);
    pos += 8;

    // height
    let height_val = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    let height = if height_val == 0xFFFFFFFF {
        None
    } else {
        Some(height_val)
    };
    pos += 4;

    // flags
    let flags = data[pos];
    let is_coinbase = (flags & 1) != 0;
    let is_coinstake = (flags & 2) != 0;
    pos += 1;

    // script
    let script_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    let script_pubkey = Script::from_bytes(data[pos..pos + script_len].to_vec());
    pos += script_len;

    // address
    let addr_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    let address = String::from_utf8(data[pos..pos + addr_len].to_vec())
        .map_err(|e| WalletError::Storage(e.to_string()))?;

    Ok(WalletUtxo {
        txid,
        vout,
        value,
        script_pubkey,
        height,
        is_coinbase,
        is_coinstake,
        address,
    })
}

pub(crate) fn serialize_tx(tx: &WalletTx) -> Vec<u8> {
    // Format: txid(32) + block_hash(33, 0x00=None) + block_height(4) + timestamp(8) + amount(8) + fee(9) + cat_len(4) + cat + confirmations(4)
    let mut data = Vec::new();

    // txid
    data.extend_from_slice(tx.txid.as_bytes());

    // block_hash (None indicator + hash)
    if let Some(hash) = &tx.block_hash {
        data.push(1);
        data.extend_from_slice(hash.as_bytes());
    } else {
        data.push(0);
        data.extend_from_slice(&[0u8; 32]);
    }

    // block_height
    data.extend_from_slice(&tx.block_height.unwrap_or(0xFFFFFFFF).to_le_bytes());

    // timestamp
    data.extend_from_slice(&tx.timestamp.to_le_bytes());

    // amount
    data.extend_from_slice(&tx.amount.to_le_bytes());

    // fee (None indicator + amount)
    if let Some(fee) = &tx.fee {
        data.push(1);
        data.extend_from_slice(&fee.as_sat().to_le_bytes());
    } else {
        data.push(0);
        data.extend_from_slice(&[0u8; 8]);
    }

    // category
    let cat_bytes = tx.category.as_bytes();
    data.extend_from_slice(&(cat_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(cat_bytes);

    // confirmations
    data.extend_from_slice(&tx.confirmations.to_le_bytes());

    data
}

fn deserialize_tx(data: &[u8]) -> Result<WalletTx, WalletError> {
    if data.len() < 98 {
        // 32 + 33 + 4 + 8 + 8 + 9 + 4
        return Err(WalletError::Storage("Invalid transaction data".into()));
    }

    let mut pos = 0;

    // txid
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&data[pos..pos + 32]);
    let txid = Hash256::from_bytes(txid_bytes);
    pos += 32;

    // block_hash
    let has_block_hash = data[pos] != 0;
    pos += 1;
    let block_hash = if has_block_hash {
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        Some(Hash256::from_bytes(hash_bytes))
    } else {
        pos += 32;
        None
    };

    // block_height
    let height_val = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    let block_height = if height_val == 0xFFFFFFFF {
        None
    } else {
        Some(height_val)
    };
    pos += 4;

    // timestamp
    let timestamp = u64::from_le_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
        data[pos + 4],
        data[pos + 5],
        data[pos + 6],
        data[pos + 7],
    ]);
    pos += 8;

    // amount
    let amount = i64::from_le_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
        data[pos + 4],
        data[pos + 5],
        data[pos + 6],
        data[pos + 7],
    ]);
    pos += 8;

    // fee
    let has_fee = data[pos] != 0;
    pos += 1;
    let fee = if has_fee {
        let fee_val = i64::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;
        Some(Amount::from_sat(fee_val))
    } else {
        pos += 8;
        None
    };

    // category
    let cat_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    let category = String::from_utf8(data[pos..pos + cat_len].to_vec())
        .map_err(|e| WalletError::Storage(e.to_string()))?;
    pos += cat_len;

    // confirmations
    let confirmations =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);

    Ok(WalletTx {
        txid,
        block_hash,
        block_height,
        timestamp,
        amount,
        fee,
        category,
        confirmations,
    })
}

pub(crate) fn serialize_vault_metadata(metadata: &crate::wallet_db::VaultMetadata) -> Vec<u8> {
    // Format: owner_len(4) + owner + manager_len(4) + manager + script_len(4) + script + funding_txid(32)
    let mut data = Vec::new();

    // Owner address
    let owner_bytes = metadata.owner_address.as_bytes();
    data.extend_from_slice(&(owner_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(owner_bytes);

    // Manager address
    let manager_bytes = metadata.manager_address.as_bytes();
    data.extend_from_slice(&(manager_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(manager_bytes);

    // Vault script
    data.extend_from_slice(&(metadata.vault_script.len() as u32).to_le_bytes());
    data.extend_from_slice(&metadata.vault_script);

    // Funding txid
    data.extend_from_slice(&metadata.funding_txid);

    data
}

fn deserialize_vault_metadata(data: &[u8]) -> Result<crate::wallet_db::VaultMetadata, WalletError> {
    if data.len() < 44 {
        // Minimum: 4 + 1 + 4 + 1 + 4 + 1 + 32
        return Err(WalletError::Storage("Invalid vault metadata".into()));
    }

    let mut pos = 0;

    // Owner address
    let owner_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    if pos + owner_len > data.len() {
        return Err(WalletError::Storage(
            "Invalid vault metadata: owner address".into(),
        ));
    }
    let owner_address = String::from_utf8(data[pos..pos + owner_len].to_vec())
        .map_err(|e| WalletError::Storage(format!("Invalid owner address: {}", e)))?;
    pos += owner_len;

    // Manager address
    if pos + 4 > data.len() {
        return Err(WalletError::Storage(
            "Invalid vault metadata: manager length".into(),
        ));
    }
    let manager_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    if pos + manager_len > data.len() {
        return Err(WalletError::Storage(
            "Invalid vault metadata: manager address".into(),
        ));
    }
    let manager_address = String::from_utf8(data[pos..pos + manager_len].to_vec())
        .map_err(|e| WalletError::Storage(format!("Invalid manager address: {}", e)))?;
    pos += manager_len;

    // Vault script
    if pos + 4 > data.len() {
        return Err(WalletError::Storage(
            "Invalid vault metadata: script length".into(),
        ));
    }
    let script_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    if pos + script_len > data.len() {
        return Err(WalletError::Storage(
            "Invalid vault metadata: script".into(),
        ));
    }
    let vault_script = data[pos..pos + script_len].to_vec();
    pos += script_len;

    // Funding txid
    if pos + 32 > data.len() {
        return Err(WalletError::Storage(
            "Invalid vault metadata: funding txid".into(),
        ));
    }
    let mut funding_txid = [0u8; 32];
    funding_txid.copy_from_slice(&data[pos..pos + 32]);

    Ok(crate::wallet_db::VaultMetadata {
        owner_address,
        manager_address,
        vault_script,
        funding_txid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_open_database() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();
        assert!(db.load_mnemonic().unwrap().is_none());
    }

    #[test]
    fn test_store_load_mnemonic() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        db.store_mnemonic(mnemonic).unwrap();

        let loaded = db.load_mnemonic().unwrap();
        assert_eq!(loaded, Some(mnemonic.to_string()));
    }

    #[test]
    fn test_store_load_network() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        db.store_network(Network::Testnet).unwrap();
        assert_eq!(db.load_network().unwrap(), Some(Network::Testnet));
    }

    #[test]
    fn test_store_load_indices() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        db.store_indices(5, 3).unwrap();
        let (recv, change) = db.load_indices().unwrap();
        assert_eq!(recv, 5);
        assert_eq!(change, 3);
    }

    #[test]
    fn test_utxo_serialization() {
        let utxo = WalletUtxo {
            txid: Hash256::from_bytes([1u8; 32]),
            vout: 0,
            value: Amount::from_sat(100_000_000),
            script_pubkey: Script::from_bytes(vec![0x76, 0xa9, 0x14]),
            height: Some(12345),
            is_coinbase: false,
            is_coinstake: true,
            address: "DTestAddress123".to_string(),
        };

        let serialized = serialize_utxo(&utxo);
        let deserialized = deserialize_utxo(&serialized).unwrap();

        assert_eq!(utxo.txid, deserialized.txid);
        assert_eq!(utxo.vout, deserialized.vout);
        assert_eq!(utxo.value, deserialized.value);
        assert_eq!(utxo.height, deserialized.height);
        assert_eq!(utxo.is_coinbase, deserialized.is_coinbase);
        assert_eq!(utxo.is_coinstake, deserialized.is_coinstake);
        assert_eq!(utxo.address, deserialized.address);
    }

    #[test]
    fn test_tx_serialization() {
        let tx = WalletTx {
            txid: Hash256::from_bytes([2u8; 32]),
            block_hash: Some(Hash256::from_bytes([3u8; 32])),
            block_height: Some(100),
            timestamp: 1234567890,
            amount: 50_000_000,
            fee: Some(Amount::from_sat(10000)),
            category: "receive".to_string(),
            confirmations: 10,
        };

        let serialized = serialize_tx(&tx);
        let deserialized = deserialize_tx(&serialized).unwrap();

        assert_eq!(tx.txid, deserialized.txid);
        assert_eq!(tx.block_hash, deserialized.block_hash);
        assert_eq!(tx.block_height, deserialized.block_height);
        assert_eq!(tx.timestamp, deserialized.timestamp);
        assert_eq!(tx.amount, deserialized.amount);
        assert_eq!(tx.fee, deserialized.fee);
        assert_eq!(tx.category, deserialized.category);
        assert_eq!(tx.confirmations, deserialized.confirmations);
    }

    // -------- chain_mode persistence --------

    #[test]
    fn test_store_load_chain_mode_divi() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        db.store_chain_mode(ChainMode::Divi).unwrap();
        let loaded = db.load_chain_mode().unwrap();
        assert_eq!(loaded, Some(ChainMode::Divi));
    }

    #[test]
    fn test_store_load_chain_mode_privatedivi() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        db.store_chain_mode(ChainMode::PrivateDivi).unwrap();
        let loaded = db.load_chain_mode().unwrap();
        assert_eq!(loaded, Some(ChainMode::PrivateDivi));
    }

    #[test]
    fn test_chain_mode_absent_returns_none() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        // Nothing stored → None
        let loaded = db.load_chain_mode().unwrap();
        assert_eq!(loaded, None);
    }

    // -------- last_scan_height persistence --------

    #[test]
    fn test_store_load_last_scan_height() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        // Default (nothing stored) → 0
        assert_eq!(db.load_last_scan_height().unwrap(), 0);

        db.store_last_scan_height(12345).unwrap();
        assert_eq!(db.load_last_scan_height().unwrap(), 12345);
    }

    #[test]
    fn test_last_scan_height_overwrite() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        db.store_last_scan_height(100).unwrap();
        db.store_last_scan_height(200).unwrap();
        assert_eq!(db.load_last_scan_height().unwrap(), 200);
    }

    // -------- mnemonic absent → None --------

    #[test]
    fn test_mnemonic_absent_returns_none() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();
        assert_eq!(db.load_mnemonic().unwrap(), None);
    }

    // -------- default indices are 0 --------

    #[test]
    fn test_default_indices_are_zero() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();
        let (recv, change) = db.load_indices().unwrap();
        assert_eq!(recv, 0);
        assert_eq!(change, 0);
    }

    // -------- UTXO store and load --------

    #[test]
    fn test_store_and_load_utxo() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        let outpoint =
            divi_primitives::transaction::OutPoint::new(Hash256::from_bytes([7u8; 32]), 2);
        let utxo = WalletUtxo {
            txid: Hash256::from_bytes([7u8; 32]),
            vout: 2,
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(vec![0x76, 0xa9, 0x14]),
            height: Some(999),
            is_coinbase: false,
            is_coinstake: false,
            address: "DTestStore".to_string(),
        };

        db.store_utxo(&outpoint, &utxo).unwrap();

        let loaded = db.load_utxos().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1.txid, utxo.txid);
        assert_eq!(loaded[0].1.value, utxo.value);
    }

    #[test]
    fn test_remove_utxo() {
        let dir = tempdir().unwrap();
        let db = WalletDatabase::open(dir.path()).unwrap();

        let outpoint =
            divi_primitives::transaction::OutPoint::new(Hash256::from_bytes([8u8; 32]), 0);
        let utxo = WalletUtxo {
            txid: Hash256::from_bytes([8u8; 32]),
            vout: 0,
            value: Amount::from_sat(1_000),
            script_pubkey: Script::default(),
            height: Some(1),
            is_coinbase: false,
            is_coinstake: false,
            address: "DRemoveTest".to_string(),
        };

        db.store_utxo(&outpoint, &utxo).unwrap();
        assert_eq!(db.load_utxos().unwrap().len(), 1);

        db.remove_utxo(&outpoint).unwrap();
        assert_eq!(db.load_utxos().unwrap().len(), 0);
    }
}
