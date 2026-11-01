// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Transaction index for efficient transaction lookups
//!
//! Maps transaction hashes to their location in the blockchain (block hash + position).
//! Eliminates need to scan all blocks when looking up a specific transaction.

use divi_primitives::script::Script;
use divi_primitives::transaction::Transaction;
use divi_primitives::Hash256;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::Arc;

use crate::error::StorageError;

const CF_TXINDEX: &str = "txindex";

/// Key prefix of the bare txid entries (Core's DB_BARETXIDINDEX); a txid key
/// is the bare 32 bytes
const BARE_TXID_PREFIX: u8 = b'b';

/// Key of the newest block whose transactions were indexed (no txid key is
/// this short)
const INDEXED_TIP_KEY: &[u8] = b"tip";

/// The txid of `tx` with every input's scriptSig cleared (Core's
/// `CTransaction::GetBareTxid`); a coinbase's bare txid is its txid
pub fn bare_txid(tx: &Transaction) -> Hash256 {
    if tx.is_coinbase() {
        return tx.txid();
    }
    let mut stripped = tx.clone();
    for input in &mut stripped.vin {
        input.script_sig = Script::new();
    }
    stripped.txid()
}

fn bare_key(bare: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(BARE_TXID_PREFIX);
    key.extend_from_slice(bare.as_bytes());
    key
}

#[derive(Debug, Clone)]
pub struct TxLocation {
    pub block_hash: Hash256,
    pub tx_index: u32,
}

impl TxLocation {
    pub fn new(block_hash: Hash256, tx_index: u32) -> Self {
        Self {
            block_hash,
            tx_index,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(self.block_hash.as_bytes());
        bytes.extend_from_slice(&self.tx_index.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != 36 {
            return Err(StorageError::Deserialization(format!(
                "Invalid TxLocation bytes length: {}",
                bytes.len()
            )));
        }

        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&bytes[0..32]);
        let block_hash = Hash256::from_bytes(block_hash_bytes);

        let mut tx_index_bytes = [0u8; 4];
        tx_index_bytes.copy_from_slice(&bytes[32..36]);
        let tx_index = u32::from_le_bytes(tx_index_bytes);

        Ok(Self {
            block_hash,
            tx_index,
        })
    }
}

pub struct TxIndex {
    db: Arc<DB>,
}

impl TxIndex {
    pub fn new(db: Arc<DB>) -> Result<Self, StorageError> {
        Ok(Self { db })
    }

    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        crate::datadir::refuse_foreign_database(path.as_ref())?;
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_descriptors = vec![ColumnFamilyDescriptor::new(CF_TXINDEX, Options::default())];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| StorageError::ChainState(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Write the write-ahead log out and sync it to disk
    pub fn sync_wal(&self) -> Result<(), StorageError> {
        self.db
            .flush_wal(true)
            .map_err(|e| StorageError::ChainState(e.to_string()))
    }

    pub fn get_location(&self, txid: &Hash256) -> Result<Option<TxLocation>, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;

        // By txid, then by bare txid, as Core's ReadTxIndex (txdb.cpp:206-218)
        for key in [txid.as_bytes().to_vec(), bare_key(txid)] {
            match self.db.get_cf(cf, key) {
                Ok(Some(bytes)) => return Ok(Some(TxLocation::from_bytes(&bytes)?)),
                Ok(None) => {}
                Err(e) => return Err(StorageError::ChainState(e.to_string())),
            }
        }
        Ok(None)
    }

    pub fn put_location(&self, txid: &Hash256, location: &TxLocation) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;

        self.db
            .put_cf(cf, txid.as_bytes(), location.to_bytes())
            .map_err(|e| StorageError::ChainState(e.to_string()))
    }

    pub fn put_locations_batch(
        &self,
        locations: &[(Hash256, TxLocation)],
    ) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;

        let mut batch = WriteBatch::default();
        for (txid, location) in locations {
            batch.put_cf(cf, txid.as_bytes(), location.to_bytes());
        }

        self.db
            .write(batch)
            .map_err(|e| StorageError::ChainState(e.to_string()))
    }

    /// Index a block's transactions under both txid and bare txid
    /// (Core's WriteTxIndex, txdb.cpp:222-231)
    pub fn put_tx_locations(
        &self,
        entries: &[(Hash256, Hash256, TxLocation)],
    ) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;

        let mut batch = WriteBatch::default();
        for (txid, bare, location) in entries {
            batch.put_cf(cf, txid.as_bytes(), location.to_bytes());
            batch.put_cf(cf, bare_key(bare), location.to_bytes());
        }

        self.db
            .write(batch)
            .map_err(|e| StorageError::ChainState(e.to_string()))
    }

    /// Index a connected block's transactions and record the block as the
    /// newest one indexed, in one write
    pub fn put_block_tx_locations(
        &self,
        entries: &[(Hash256, Hash256, TxLocation)],
        height: u32,
        block_hash: &Hash256,
    ) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;

        let mut batch = WriteBatch::default();
        for (txid, bare, location) in entries {
            batch.put_cf(cf, txid.as_bytes(), location.to_bytes());
            batch.put_cf(cf, bare_key(bare), location.to_bytes());
        }
        let mut tip = height.to_le_bytes().to_vec();
        tip.extend_from_slice(block_hash.as_bytes());
        batch.put_cf(cf, INDEXED_TIP_KEY, tip);

        self.db
            .write(batch)
            .map_err(|e| StorageError::ChainState(e.to_string()))
    }

    /// Height and hash of the newest block whose transactions were indexed
    /// (None for an index written before this was kept)
    pub fn indexed_tip(&self) -> Result<Option<(u32, Hash256)>, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;
        let raw = self
            .db
            .get_cf(cf, INDEXED_TIP_KEY)
            .map_err(|e| StorageError::ChainState(e.to_string()))?;
        Ok(raw.filter(|v| v.len() == 36).map(|v| {
            let height = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&v[4..]);
            (height, Hash256::from_bytes(hash))
        }))
    }

    pub fn delete_location(&self, txid: &Hash256) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;

        self.db
            .delete_cf(cf, txid.as_bytes())
            .map_err(|e| StorageError::ChainState(e.to_string()))
    }

    pub fn delete_locations_batch(&self, txids: &[Hash256]) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;

        let mut batch = WriteBatch::default();
        for txid in txids {
            batch.delete_cf(cf, txid.as_bytes());
        }

        self.db
            .write(batch)
            .map_err(|e| StorageError::ChainState(e.to_string()))
    }

    pub fn has_transaction(&self, txid: &Hash256) -> Result<bool, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;

        self.db
            .get_cf(cf, txid.as_bytes())
            .map(|opt| opt.is_some())
            .map_err(|e| StorageError::ChainState(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_txid(value: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        Hash256::from_bytes(bytes)
    }

    fn create_test_block_hash(value: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        Hash256::from_bytes(bytes)
    }

    #[test]
    fn test_tx_location_serialization() {
        let location = TxLocation::new(create_test_block_hash(1), 42);
        let bytes = location.to_bytes();
        assert_eq!(bytes.len(), 36);

        let decoded = TxLocation::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.block_hash, location.block_hash);
        assert_eq!(decoded.tx_index, location.tx_index);
    }

    #[test]
    fn test_tx_location_invalid_bytes() {
        let invalid_bytes = vec![0u8; 20];
        assert!(TxLocation::from_bytes(&invalid_bytes).is_err());
    }

    #[test]
    fn test_new_index() {
        let dir = tempdir().unwrap();
        let index = TxIndex::open(dir.path()).unwrap();

        let txid = create_test_txid(1);
        assert!(!index.has_transaction(&txid).unwrap());
    }

    #[test]
    fn test_put_and_get() {
        let dir = tempdir().unwrap();
        let index = TxIndex::open(dir.path()).unwrap();

        let txid = create_test_txid(1);
        let location = TxLocation::new(create_test_block_hash(1), 5);

        index.put_location(&txid, &location).unwrap();

        assert!(index.has_transaction(&txid).unwrap());

        let retrieved = index.get_location(&txid).unwrap().unwrap();
        assert_eq!(retrieved.block_hash, location.block_hash);
        assert_eq!(retrieved.tx_index, location.tx_index);
    }

    #[test]
    fn test_get_nonexistent() {
        let dir = tempdir().unwrap();
        let index = TxIndex::open(dir.path()).unwrap();

        let txid = create_test_txid(1);
        assert!(index.get_location(&txid).unwrap().is_none());
    }

    #[test]
    fn test_delete() {
        let dir = tempdir().unwrap();
        let index = TxIndex::open(dir.path()).unwrap();

        let txid = create_test_txid(1);
        let location = TxLocation::new(create_test_block_hash(1), 5);

        index.put_location(&txid, &location).unwrap();
        assert!(index.has_transaction(&txid).unwrap());

        index.delete_location(&txid).unwrap();
        assert!(!index.has_transaction(&txid).unwrap());
        assert!(index.get_location(&txid).unwrap().is_none());
    }

    #[test]
    fn test_batch_operations() {
        let dir = tempdir().unwrap();
        let index = TxIndex::open(dir.path()).unwrap();

        let locations = vec![
            (
                create_test_txid(1),
                TxLocation::new(create_test_block_hash(1), 0),
            ),
            (
                create_test_txid(2),
                TxLocation::new(create_test_block_hash(1), 1),
            ),
            (
                create_test_txid(3),
                TxLocation::new(create_test_block_hash(2), 0),
            ),
        ];

        index.put_locations_batch(&locations).unwrap();

        for (txid, location) in &locations {
            let retrieved = index.get_location(txid).unwrap().unwrap();
            assert_eq!(retrieved.block_hash, location.block_hash);
            assert_eq!(retrieved.tx_index, location.tx_index);
        }

        let txids: Vec<Hash256> = locations.iter().map(|(txid, _)| *txid).collect();
        index.delete_locations_batch(&txids).unwrap();

        for (txid, _) in &locations {
            assert!(!index.has_transaction(txid).unwrap());
        }
    }

    #[test]
    fn test_multiple_blocks() {
        let dir = tempdir().unwrap();
        let index = TxIndex::open(dir.path()).unwrap();

        let block1 = create_test_block_hash(1);
        let block2 = create_test_block_hash(2);

        let tx1 = create_test_txid(10);
        let tx2 = create_test_txid(20);
        let tx3 = create_test_txid(30);

        index
            .put_location(&tx1, &TxLocation::new(block1, 0))
            .unwrap();
        index
            .put_location(&tx2, &TxLocation::new(block1, 1))
            .unwrap();
        index
            .put_location(&tx3, &TxLocation::new(block2, 0))
            .unwrap();

        let loc1 = index.get_location(&tx1).unwrap().unwrap();
        assert_eq!(loc1.block_hash, block1);
        assert_eq!(loc1.tx_index, 0);

        let loc2 = index.get_location(&tx2).unwrap().unwrap();
        assert_eq!(loc2.block_hash, block1);
        assert_eq!(loc2.tx_index, 1);

        let loc3 = index.get_location(&tx3).unwrap().unwrap();
        assert_eq!(loc3.block_hash, block2);
        assert_eq!(loc3.tx_index, 0);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let txid = create_test_txid(1);
        let location = TxLocation::new(create_test_block_hash(1), 5);

        {
            let index = TxIndex::open(dir.path()).unwrap();
            index.put_location(&txid, &location).unwrap();
        }

        {
            let index = TxIndex::open(dir.path()).unwrap();
            let retrieved = index.get_location(&txid).unwrap().unwrap();
            assert_eq!(retrieved.block_hash, location.block_hash);
            assert_eq!(retrieved.tx_index, location.tx_index);
        }
    }
}
