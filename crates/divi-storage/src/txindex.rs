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

//! Transaction index for efficient transaction lookups
//!
//! Maps transaction hashes to their location in the blockchain (block hash + position).
//! Eliminates need to scan all blocks when looking up a specific transaction.

use divi_primitives::Hash256;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::Arc;

use crate::error::StorageError;

const CF_TXINDEX: &str = "txindex";

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
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_descriptors = vec![ColumnFamilyDescriptor::new(CF_TXINDEX, Options::default())];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| StorageError::ChainState(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    pub fn get_location(&self, txid: &Hash256) -> Result<Option<TxLocation>, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TXINDEX)
            .ok_or_else(|| StorageError::ChainState("Column family not found".to_string()))?;

        match self.db.get_cf(cf, txid.as_bytes()) {
            Ok(Some(bytes)) => Ok(Some(TxLocation::from_bytes(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::ChainState(e.to_string())),
        }
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
