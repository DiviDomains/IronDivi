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

//! Address Index for Lite Wallet Services
//!
//! Provides indexing of UTXOs and transaction history by address (script_pubkey).
//! This enables external address queries without requiring a local wallet.

use crate::error::StorageError;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction};
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::collections::HashSet;

/// Column family names for address indexing
pub const CF_ADDRESS_UTXO: &str = "address_utxo";
pub const CF_ADDRESS_HISTORY: &str = "address_history";
pub const CF_TX_INDEX: &str = "tx_index";

/// A UTXO entry indexed by address
#[derive(Debug, Clone)]
pub struct AddressUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub height: u32,
    pub is_coinbase: bool,
    pub is_coinstake: bool,
}

impl AddressUtxo {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(53);
        bytes.extend_from_slice(self.outpoint.txid.as_bytes());
        bytes.extend_from_slice(&self.outpoint.vout.to_le_bytes());
        bytes.extend_from_slice(&self.value.as_sat().to_le_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.push(if self.is_coinbase { 1 } else { 0 });
        bytes.push(if self.is_coinstake { 1 } else { 0 });
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, StorageError> {
        if data.len() < 50 {
            return Err(StorageError::Deserialization(
                "AddressUtxo too short".into(),
            ));
        }

        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&data[0..32]);

        let vout = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let value = i64::from_le_bytes([
            data[36], data[37], data[38], data[39], data[40], data[41], data[42], data[43],
        ]);
        let height = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let is_coinbase = data[48] != 0;
        let is_coinstake = data[49] != 0;

        Ok(AddressUtxo {
            outpoint: OutPoint::new(Hash256::from_bytes(txid_bytes), vout),
            value: Amount::from_sat(value),
            height,
            is_coinbase,
            is_coinstake,
        })
    }
}

/// A transaction history entry for an address
#[derive(Debug, Clone)]
pub struct AddressHistoryEntry {
    pub txid: Hash256,
    pub block_hash: Hash256,
    pub height: u32,
    pub timestamp: u32,
    pub value_change: i64, // Positive for received, negative for sent
    pub is_confirmed: bool,
}

impl AddressHistoryEntry {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(81);
        bytes.extend_from_slice(self.txid.as_bytes());
        bytes.extend_from_slice(self.block_hash.as_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.value_change.to_le_bytes());
        bytes.push(if self.is_confirmed { 1 } else { 0 });
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, StorageError> {
        if data.len() < 81 {
            return Err(StorageError::Deserialization(
                "AddressHistoryEntry too short".into(),
            ));
        }

        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&data[0..32]);

        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&data[32..64]);

        let height = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
        let timestamp = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
        let value_change = i64::from_le_bytes([
            data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
        ]);
        let is_confirmed = data[80] != 0;

        Ok(AddressHistoryEntry {
            txid: Hash256::from_bytes(txid_bytes),
            block_hash: Hash256::from_bytes(block_hash_bytes),
            height,
            timestamp,
            value_change,
            is_confirmed,
        })
    }
}

/// Transaction index entry
#[derive(Debug, Clone)]
pub struct TxIndexEntry {
    pub block_hash: Hash256,
    pub block_height: u32,
    pub tx_index: u32,
}

impl TxIndexEntry {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(self.block_hash.as_bytes());
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.tx_index.to_le_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, StorageError> {
        if data.len() < 40 {
            return Err(StorageError::Deserialization(
                "TxIndexEntry too short".into(),
            ));
        }

        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&data[0..32]);

        let block_height = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let tx_index = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

        Ok(TxIndexEntry {
            block_hash: Hash256::from_bytes(block_hash_bytes),
            block_height,
            tx_index,
        })
    }
}

/// Address index for lite wallet services
pub struct AddressIndex {
    db: std::sync::Arc<DB>,
}

impl AddressIndex {
    /// Create column family descriptors for address indexing
    pub fn column_families() -> Vec<ColumnFamilyDescriptor> {
        vec![
            ColumnFamilyDescriptor::new(CF_ADDRESS_UTXO, Options::default()),
            ColumnFamilyDescriptor::new(CF_ADDRESS_HISTORY, Options::default()),
            ColumnFamilyDescriptor::new(CF_TX_INDEX, Options::default()),
        ]
    }

    /// Create a new address index with an existing DB handle
    pub fn new(db: std::sync::Arc<DB>) -> Self {
        AddressIndex { db }
    }

    /// Generate key for address UTXO lookup
    fn address_utxo_key(script: &Script, outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::with_capacity(script.len() + 36);
        key.extend_from_slice(script.as_bytes());
        key.extend_from_slice(outpoint.txid.as_bytes());
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }

    /// Generate prefix key for address lookup (all UTXOs for an address)
    fn address_prefix_key(script: &Script) -> Vec<u8> {
        script.as_bytes().to_vec()
    }

    /// Generate key for address history
    fn address_history_key(script: &Script, height: u32, txid: &Hash256) -> Vec<u8> {
        let mut key = Vec::with_capacity(script.len() + 36);
        key.extend_from_slice(script.as_bytes());
        key.extend_from_slice(&height.to_be_bytes()); // Big endian for proper ordering
        key.extend_from_slice(txid.as_bytes());
        key
    }

    /// Add a UTXO to the address index
    pub fn add_utxo(
        &self,
        script: &Script,
        outpoint: &OutPoint,
        utxo: &AddressUtxo,
    ) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_ADDRESS_UTXO)
            .ok_or_else(|| StorageError::Deserialization("Missing CF_ADDRESS_UTXO".into()))?;
        let key = Self::address_utxo_key(script, outpoint);
        self.db.put_cf(cf, key, utxo.to_bytes())?;
        Ok(())
    }

    /// Remove a UTXO from the address index
    pub fn remove_utxo(&self, script: &Script, outpoint: &OutPoint) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_ADDRESS_UTXO)
            .ok_or_else(|| StorageError::Deserialization("Missing CF_ADDRESS_UTXO".into()))?;
        let key = Self::address_utxo_key(script, outpoint);
        self.db.delete_cf(cf, key)?;
        Ok(())
    }

    /// Get all UTXOs for an address
    pub fn get_utxos_for_address(&self, script: &Script) -> Result<Vec<AddressUtxo>, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_ADDRESS_UTXO)
            .ok_or_else(|| StorageError::Deserialization("Missing CF_ADDRESS_UTXO".into()))?;

        let prefix = Self::address_prefix_key(script);
        let mut utxos = Vec::new();

        let iter = self.db.prefix_iterator_cf(cf, &prefix);
        for item in iter {
            let (key, value) = item?;

            // Check if key still matches our prefix
            if !key.starts_with(&prefix) {
                break;
            }

            let utxo = AddressUtxo::from_bytes(&value)?;
            utxos.push(utxo);
        }

        Ok(utxos)
    }

    /// Get balance for an address
    ///
    /// `coinbase_maturity` is network-specific: mainnet=20, testnet/regtest=1.
    pub fn get_balance(
        &self,
        script: &Script,
        min_confirmations: u32,
        current_height: u32,
        coinbase_maturity: u32,
    ) -> Result<Amount, StorageError> {
        let utxos = self.get_utxos_for_address(script)?;

        let mut balance = 0i64;
        for utxo in utxos {
            let confirmations = if current_height >= utxo.height {
                current_height - utxo.height + 1
            } else {
                0
            };

            // Check maturity for coinbase/coinstake
            let mature = if utxo.is_coinbase || utxo.is_coinstake {
                confirmations >= coinbase_maturity
            } else {
                true
            };

            if confirmations >= min_confirmations && mature {
                balance += utxo.value.as_sat();
            }
        }

        Ok(Amount::from_sat(balance))
    }

    /// Add transaction history entry
    pub fn add_history_entry(
        &self,
        script: &Script,
        entry: &AddressHistoryEntry,
    ) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_ADDRESS_HISTORY)
            .ok_or_else(|| StorageError::Deserialization("Missing CF_ADDRESS_HISTORY".into()))?;
        let key = Self::address_history_key(script, entry.height, &entry.txid);
        self.db.put_cf(cf, key, entry.to_bytes())?;
        Ok(())
    }

    /// Get transaction history for an address
    pub fn get_history(
        &self,
        script: &Script,
        skip: usize,
        limit: usize,
    ) -> Result<Vec<AddressHistoryEntry>, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_ADDRESS_HISTORY)
            .ok_or_else(|| StorageError::Deserialization("Missing CF_ADDRESS_HISTORY".into()))?;

        let prefix = Self::address_prefix_key(script);
        let mut entries = Vec::new();

        let iter = self.db.prefix_iterator_cf(cf, &prefix);
        let mut count = 0;

        for item in iter {
            let (key, value) = item?;

            // Check if key still matches our prefix
            if !key.starts_with(&prefix) {
                break;
            }

            if count >= skip {
                let entry = AddressHistoryEntry::from_bytes(&value)?;
                entries.push(entry);

                if entries.len() >= limit {
                    break;
                }
            }
            count += 1;
        }

        // Return in reverse order (newest first)
        entries.reverse();
        Ok(entries)
    }

    /// Add transaction to index
    pub fn add_tx_index(&self, txid: &Hash256, entry: &TxIndexEntry) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TX_INDEX)
            .ok_or_else(|| StorageError::Deserialization("Missing CF_TX_INDEX".into()))?;
        self.db.put_cf(cf, txid.as_bytes(), entry.to_bytes())?;
        Ok(())
    }

    /// Get transaction index entry
    pub fn get_tx_index(&self, txid: &Hash256) -> Result<Option<TxIndexEntry>, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TX_INDEX)
            .ok_or_else(|| StorageError::Deserialization("Missing CF_TX_INDEX".into()))?;

        match self.db.get_cf(cf, txid.as_bytes())? {
            Some(data) => Ok(Some(TxIndexEntry::from_bytes(&data)?)),
            None => Ok(None),
        }
    }

    /// Index a block - update address index with all transactions
    pub fn index_block(
        &self,
        block_hash: &Hash256,
        height: u32,
        timestamp: u32,
        transactions: &[Transaction],
        spent_outputs: &[(OutPoint, Script, Amount)], // Outputs being spent
    ) -> Result<(), StorageError> {
        // Track which addresses are affected
        let mut affected_scripts: HashSet<Vec<u8>> = HashSet::new();

        // Process each transaction
        for (tx_index, tx) in transactions.iter().enumerate() {
            let txid = tx.txid();
            let is_coinbase = tx.is_coinbase();
            let is_coinstake = tx.is_coinstake();

            // Index the transaction
            let tx_entry = TxIndexEntry {
                block_hash: *block_hash,
                block_height: height,
                tx_index: tx_index as u32,
            };
            self.add_tx_index(&txid, &tx_entry)?;

            // Add new UTXOs (outputs)
            for (vout, output) in tx.vout.iter().enumerate() {
                if output.value.as_sat() <= 0 {
                    continue; // Skip OP_RETURN and zero-value outputs
                }

                let outpoint = OutPoint::new(txid, vout as u32);
                let utxo = AddressUtxo {
                    outpoint: outpoint.clone(),
                    value: output.value,
                    height,
                    is_coinbase,
                    is_coinstake,
                };

                self.add_utxo(&output.script_pubkey, &outpoint, &utxo)?;
                affected_scripts.insert(output.script_pubkey.as_bytes().to_vec());

                // Add history entry for receiving
                let history = AddressHistoryEntry {
                    txid,
                    block_hash: *block_hash,
                    height,
                    timestamp,
                    value_change: output.value.as_sat(),
                    is_confirmed: true,
                };
                self.add_history_entry(&output.script_pubkey, &history)?;
            }
        }

        // Remove spent UTXOs
        for (outpoint, script, value) in spent_outputs {
            self.remove_utxo(script, outpoint)?;
            affected_scripts.insert(script.as_bytes().to_vec());

            // Add history entry for spending
            let history = AddressHistoryEntry {
                txid: outpoint.txid,
                block_hash: *block_hash,
                height,
                timestamp,
                value_change: -value.as_sat(),
                is_confirmed: true,
            };
            self.add_history_entry(script, &history)?;
        }

        Ok(())
    }

    /// Unindex a block (for reorg handling)
    pub fn unindex_block(
        &self,
        transactions: &[Transaction],
        restored_outputs: &[(OutPoint, Script, AddressUtxo)], // Outputs to restore
    ) -> Result<(), StorageError> {
        // Remove UTXOs created by this block
        for tx in transactions {
            let txid = tx.txid();

            for (vout, output) in tx.vout.iter().enumerate() {
                let outpoint = OutPoint::new(txid, vout as u32);
                self.remove_utxo(&output.script_pubkey, &outpoint)?;
            }
        }

        // Restore previously spent UTXOs
        for (outpoint, script, utxo) in restored_outputs {
            self.add_utxo(script, outpoint, utxo)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::Options;
    use tempfile::tempdir;

    fn create_test_db() -> (std::sync::Arc<DB>, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = AddressIndex::column_families();
        let db = DB::open_cf_descriptors(&opts, dir.path(), cfs).unwrap();
        (std::sync::Arc::new(db), dir)
    }

    #[test]
    fn test_address_utxo_serialization() {
        let utxo = AddressUtxo {
            outpoint: OutPoint::new(Hash256::from_bytes([1u8; 32]), 5),
            value: Amount::from_sat(1000000),
            height: 12345,
            is_coinbase: false,
            is_coinstake: true,
        };

        let bytes = utxo.to_bytes();
        let restored = AddressUtxo::from_bytes(&bytes).unwrap();

        assert_eq!(restored.outpoint.txid, utxo.outpoint.txid);
        assert_eq!(restored.outpoint.vout, 5);
        assert_eq!(restored.value.as_sat(), 1000000);
        assert_eq!(restored.height, 12345);
        assert!(!restored.is_coinbase);
        assert!(restored.is_coinstake);
    }

    #[test]
    fn test_address_history_serialization() {
        let entry = AddressHistoryEntry {
            txid: Hash256::from_bytes([1u8; 32]),
            block_hash: Hash256::from_bytes([2u8; 32]),
            height: 12345,
            timestamp: 1638000000,
            value_change: -500000,
            is_confirmed: true,
        };

        let bytes = entry.to_bytes();
        let restored = AddressHistoryEntry::from_bytes(&bytes).unwrap();

        assert_eq!(restored.txid, entry.txid);
        assert_eq!(restored.block_hash, entry.block_hash);
        assert_eq!(restored.height, 12345);
        assert_eq!(restored.timestamp, 1638000000);
        assert_eq!(restored.value_change, -500000);
        assert!(restored.is_confirmed);
    }

    #[test]
    fn test_utxo_operations() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let script = Script::new_p2pkh(&[0u8; 20]);
        let outpoint = OutPoint::new(Hash256::from_bytes([1u8; 32]), 0);
        let utxo = AddressUtxo {
            outpoint: outpoint.clone(),
            value: Amount::from_sat(1000000),
            height: 100,
            is_coinbase: false,
            is_coinstake: false,
        };

        // Add UTXO
        index.add_utxo(&script, &outpoint, &utxo).unwrap();

        // Get UTXOs
        let utxos = index.get_utxos_for_address(&script).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].value.as_sat(), 1000000);

        // Get balance
        let balance = index.get_balance(&script, 1, 200, 20).unwrap();
        assert_eq!(balance.as_sat(), 1000000);

        // Remove UTXO
        index.remove_utxo(&script, &outpoint).unwrap();
        let utxos = index.get_utxos_for_address(&script).unwrap();
        assert_eq!(utxos.len(), 0);
    }

    #[test]
    fn test_history_operations() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let script = Script::new_p2pkh(&[0u8; 20]);

        // Add history entries
        for i in 0..5u32 {
            let entry = AddressHistoryEntry {
                txid: Hash256::from_bytes([i as u8; 32]),
                block_hash: Hash256::from_bytes([(i + 100) as u8; 32]),
                height: 100 + i,
                timestamp: 1638000000 + i,
                value_change: (i as i64 + 1) * 100000,
                is_confirmed: true,
            };
            index.add_history_entry(&script, &entry).unwrap();
        }

        // Get history (newest first)
        let history = index.get_history(&script, 0, 10).unwrap();
        assert_eq!(history.len(), 5);
        assert_eq!(history[0].height, 104); // Newest first
        assert_eq!(history[4].height, 100); // Oldest last
    }

    #[test]
    fn test_tx_index() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let txid = Hash256::from_bytes([1u8; 32]);
        let entry = TxIndexEntry {
            block_hash: Hash256::from_bytes([2u8; 32]),
            block_height: 12345,
            tx_index: 3,
        };

        index.add_tx_index(&txid, &entry).unwrap();

        let retrieved = index.get_tx_index(&txid).unwrap().unwrap();
        assert_eq!(retrieved.block_hash, entry.block_hash);
        assert_eq!(retrieved.block_height, 12345);
        assert_eq!(retrieved.tx_index, 3);
    }

    // ================================================================
    // TxIndexEntry serialization edge cases
    // ================================================================

    #[test]
    fn test_tx_index_entry_serialization() {
        let entry = TxIndexEntry {
            block_hash: Hash256::from_bytes([0xde; 32]),
            block_height: 999_999,
            tx_index: 255,
        };

        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), 40);

        let decoded = TxIndexEntry::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.block_hash, entry.block_hash);
        assert_eq!(decoded.block_height, 999_999);
        assert_eq!(decoded.tx_index, 255);
    }

    #[test]
    fn test_tx_index_entry_too_short() {
        let short = vec![0u8; 30];
        let result = TxIndexEntry::from_bytes(&short);
        assert!(result.is_err());
    }

    #[test]
    fn test_tx_index_get_nonexistent() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let txid = Hash256::from_bytes([0xff; 32]);
        assert!(index.get_tx_index(&txid).unwrap().is_none());
    }

    // ================================================================
    // AddressUtxo: deserialization error cases
    // ================================================================

    #[test]
    fn test_address_utxo_too_short() {
        let short = vec![0u8; 30];
        let result = AddressUtxo::from_bytes(&short);
        assert!(result.is_err());
    }

    // ================================================================
    // AddressHistoryEntry: deserialization error cases
    // ================================================================

    #[test]
    fn test_address_history_entry_too_short() {
        let short = vec![0u8; 50];
        let result = AddressHistoryEntry::from_bytes(&short);
        assert!(result.is_err());
    }

    // ================================================================
    // Balance with no UTXOs
    // ================================================================

    #[test]
    fn test_balance_empty_address() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let script = Script::new_p2pkh(&[0xff; 20]);
        let balance = index.get_balance(&script, 1, 1000, 20).unwrap();
        assert_eq!(balance.as_sat(), 0);
    }

    // ================================================================
    // Balance with coinbase maturity constraint
    // ================================================================

    #[test]
    fn test_balance_coinbase_immature() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let script = Script::new_p2pkh(&[0x10; 20]);
        let outpoint = OutPoint::new(Hash256::from_bytes([0x10; 32]), 0);
        let utxo = AddressUtxo {
            outpoint: outpoint.clone(),
            value: Amount::from_sat(1_000_000),
            height: 1000,
            is_coinbase: true,
            is_coinstake: false,
        };

        index.add_utxo(&script, &outpoint, &utxo).unwrap();

        // Current height 1010: only 11 confirmations - immature (maturity=20)
        let immature_balance = index.get_balance(&script, 1, 1010, 20).unwrap();
        assert_eq!(immature_balance.as_sat(), 0);

        // Current height 1020: exactly 21 confirmations - mature
        let mature_balance = index.get_balance(&script, 1, 1020, 20).unwrap();
        assert_eq!(mature_balance.as_sat(), 1_000_000);
    }

    // ================================================================
    // Balance with min_confirmations
    // ================================================================

    #[test]
    fn test_balance_min_confirmations() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let script = Script::new_p2pkh(&[0x20; 20]);
        let outpoint = OutPoint::new(Hash256::from_bytes([0x20; 32]), 0);
        let utxo = AddressUtxo {
            outpoint: outpoint.clone(),
            value: Amount::from_sat(500_000),
            height: 100,
            is_coinbase: false,
            is_coinstake: false,
        };

        index.add_utxo(&script, &outpoint, &utxo).unwrap();

        // 6 confirmations: current_height=105
        let bal6 = index.get_balance(&script, 6, 105, 1).unwrap();
        assert_eq!(bal6.as_sat(), 500_000);

        // Requiring 10 confirmations: not satisfied at height 105 (only 6 conf)
        let bal10 = index.get_balance(&script, 10, 105, 1).unwrap();
        assert_eq!(bal10.as_sat(), 0);
    }

    // ================================================================
    // Multiple UTXOs for same address
    // ================================================================

    #[test]
    fn test_multiple_utxos_same_address() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let script = Script::new_p2pkh(&[0x30; 20]);

        for i in 0..5u32 {
            let outpoint = OutPoint::new(Hash256::from_bytes([i as u8 + 1; 32]), i);
            let utxo = AddressUtxo {
                outpoint: outpoint.clone(),
                value: Amount::from_sat((i as i64 + 1) * 100_000),
                height: 100,
                is_coinbase: false,
                is_coinstake: false,
            };
            index.add_utxo(&script, &outpoint, &utxo).unwrap();
        }

        let utxos = index.get_utxos_for_address(&script).unwrap();
        assert_eq!(utxos.len(), 5);

        // Total: 1+2+3+4+5 = 15 * 100_000 = 1_500_000
        let total_balance = index.get_balance(&script, 1, 1000, 1).unwrap();
        assert_eq!(total_balance.as_sat(), 1_500_000);
    }

    // ================================================================
    // UTXOs for different addresses are isolated
    // ================================================================

    #[test]
    fn test_utxos_isolated_by_address() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let script1 = Script::new_p2pkh(&[0x01; 20]);
        let script2 = Script::new_p2pkh(&[0x02; 20]);

        let op1 = OutPoint::new(Hash256::from_bytes([0x01; 32]), 0);
        let op2 = OutPoint::new(Hash256::from_bytes([0x02; 32]), 0);

        let utxo1 = AddressUtxo {
            outpoint: op1.clone(),
            value: Amount::from_sat(100_000),
            height: 100,
            is_coinbase: false,
            is_coinstake: false,
        };
        let utxo2 = AddressUtxo {
            outpoint: op2.clone(),
            value: Amount::from_sat(200_000),
            height: 100,
            is_coinbase: false,
            is_coinstake: false,
        };

        index.add_utxo(&script1, &op1, &utxo1).unwrap();
        index.add_utxo(&script2, &op2, &utxo2).unwrap();

        let utxos1 = index.get_utxos_for_address(&script1).unwrap();
        let utxos2 = index.get_utxos_for_address(&script2).unwrap();

        assert_eq!(utxos1.len(), 1);
        assert_eq!(utxos2.len(), 1);
        assert_eq!(utxos1[0].value.as_sat(), 100_000);
        assert_eq!(utxos2[0].value.as_sat(), 200_000);
    }

    // ================================================================
    // get_history with skip/limit
    // ================================================================

    #[test]
    fn test_history_skip_limit() {
        let (db, _dir) = create_test_db();
        let index = AddressIndex::new(db);

        let script = Script::new_p2pkh(&[0x40; 20]);

        for i in 0..10u32 {
            let entry = AddressHistoryEntry {
                txid: Hash256::from_bytes([i as u8; 32]),
                block_hash: Hash256::from_bytes([(i + 50) as u8; 32]),
                height: 100 + i,
                timestamp: 1_638_000_000 + i,
                value_change: i as i64 * 10_000,
                is_confirmed: true,
            };
            index.add_history_entry(&script, &entry).unwrap();
        }

        // Limit to 3 results
        let limited = index.get_history(&script, 0, 3).unwrap();
        assert_eq!(limited.len(), 3);

        // All 10
        let all = index.get_history(&script, 0, 100).unwrap();
        assert_eq!(all.len(), 10);

        // Newest first (reversed)
        assert!(all[0].height > all[9].height);
    }

    // ================================================================
    // AddressHistoryEntry: negative value_change (sending)
    // ================================================================

    #[test]
    fn test_history_negative_value_change() {
        let entry = AddressHistoryEntry {
            txid: Hash256::from_bytes([0xee; 32]),
            block_hash: Hash256::from_bytes([0xdd; 32]),
            height: 5000,
            timestamp: 1_700_000_000,
            value_change: -999_999,
            is_confirmed: false,
        };

        let bytes = entry.to_bytes();
        let decoded = AddressHistoryEntry::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.value_change, -999_999);
        assert!(!decoded.is_confirmed);
    }
}
