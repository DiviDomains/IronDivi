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

//! Spent transaction index
//!
//! This module implements a spent transaction output index that tracks
//! which outputs have been spent and by which inputs. This enables
//! the `gettxout` RPC command to determine if an output is still unspent.
//!
//! Design based on C++ Divi's spentindex.h implementation.

use crate::database::ChainDatabase;
use crate::error::StorageError;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use std::sync::Arc;

/// Column family name for spent index
pub const CF_SPENT_INDEX: &str = "spent_index";

/// Spent index key - identifies an output by txid + vout
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpentIndexKey {
    /// Transaction ID containing the output
    pub txid: Hash256,
    /// Output index within the transaction
    pub output_index: u32,
}

impl SpentIndexKey {
    /// Create new spent index key
    pub fn new(txid: Hash256, output_index: u32) -> Self {
        Self { txid, output_index }
    }

    /// Create RocksDB key (37 bytes: 1 prefix + 32 txid + 4 vout)
    pub fn to_db_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(37);
        key.push(b'S'); // Prefix for spent index
        key.extend_from_slice(&self.txid.0);
        key.extend_from_slice(&self.output_index.to_le_bytes());
        key
    }

    /// Parse from RocksDB key
    pub fn from_db_key(key: &[u8]) -> Option<Self> {
        if key.len() != 37 || key[0] != b'S' {
            return None;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&key[1..33]);
        let output_index = u32::from_le_bytes([key[33], key[34], key[35], key[36]]);
        Some(Self {
            txid: Hash256(txid),
            output_index,
        })
    }
}

/// Spent index value - stores information about how an output was spent
#[derive(Debug, Clone)]
pub struct SpentIndexValue {
    /// Transaction ID that spent the output
    pub spending_txid: Hash256,
    /// Input index within the spending transaction
    pub input_index: u32,
    /// Block height where the output was spent
    pub block_height: i32,
    /// Amount of the spent output
    pub amount: Amount,
    /// Address type (1=P2PKH, 2=P2SH, 3=P2PK, etc.)
    pub address_type: u8,
    /// Address hash (20 bytes for P2PKH/P2SH)
    pub address_hash: [u8; 20],
}

impl SpentIndexValue {
    /// Create new spent index value
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spending_txid: Hash256,
        input_index: u32,
        block_height: i32,
        amount: Amount,
        address_type: u8,
        address_hash: [u8; 20],
    ) -> Self {
        Self {
            spending_txid,
            input_index,
            block_height,
            amount,
            address_type,
            address_hash,
        }
    }

    /// Serialize to bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(69);
        bytes.extend_from_slice(&self.spending_txid.0);
        bytes.extend_from_slice(&self.input_index.to_le_bytes());
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.amount.as_sat().to_le_bytes());
        bytes.push(self.address_type);
        bytes.extend_from_slice(&self.address_hash);
        bytes
    }

    /// Deserialize from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != 69 {
            return Err(StorageError::Deserialization(format!(
                "invalid spent index value length: expected 69, got {}",
                bytes.len()
            )));
        }

        let mut spending_txid = [0u8; 32];
        spending_txid.copy_from_slice(&bytes[0..32]);

        let input_index = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
        let block_height = i32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        let amount_sat = i64::from_le_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]);

        let address_type = bytes[48];
        let mut address_hash = [0u8; 20];
        address_hash.copy_from_slice(&bytes[49..69]);

        Ok(Self {
            spending_txid: Hash256(spending_txid),
            input_index,
            block_height,
            amount: Amount::from_sat(amount_sat),
            address_type,
            address_hash,
        })
    }
}

/// Spent index manager
pub struct SpentIndex {
    db: Arc<ChainDatabase>,
}

impl SpentIndex {
    /// Create new spent index
    pub fn new(db: Arc<ChainDatabase>) -> Self {
        Self { db }
    }

    /// Record a spent output
    ///
    /// Called when connecting a block to mark an output as spent.
    pub fn mark_spent(
        &self,
        key: &SpentIndexKey,
        value: &SpentIndexValue,
    ) -> Result<(), StorageError> {
        let db = self.db.inner_db();
        let cf = db.cf_handle(CF_SPENT_INDEX).ok_or_else(|| {
            StorageError::ChainState("spent_index column family not found".into())
        })?;

        let db_key = key.to_db_key();
        let db_value = value.to_bytes();

        db.put_cf(&cf, &db_key, &db_value)
            .map_err(StorageError::Database)?;
        Ok(())
    }

    /// Mark output as unspent (for reorg)
    pub fn mark_unspent(&self, key: &SpentIndexKey) -> Result<(), StorageError> {
        let db = self.db.inner_db();
        let cf = db.cf_handle(CF_SPENT_INDEX).ok_or_else(|| {
            StorageError::ChainState("spent_index column family not found".into())
        })?;

        let db_key = key.to_db_key();

        db.delete_cf(&cf, &db_key).map_err(StorageError::Database)?;
        Ok(())
    }

    /// Check if an output is spent
    pub fn is_spent(&self, key: &SpentIndexKey) -> Result<bool, StorageError> {
        let db = self.db.inner_db();
        let cf = db.cf_handle(CF_SPENT_INDEX).ok_or_else(|| {
            StorageError::ChainState("spent_index column family not found".into())
        })?;

        let db_key = key.to_db_key();

        match db.get_cf(&cf, &db_key) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(StorageError::Database(e)),
        }
    }

    /// Get spending information for an output
    pub fn get_spent_info(
        &self,
        key: &SpentIndexKey,
    ) -> Result<Option<SpentIndexValue>, StorageError> {
        let db = self.db.inner_db();
        let cf = db.cf_handle(CF_SPENT_INDEX).ok_or_else(|| {
            StorageError::ChainState("spent_index column family not found".into())
        })?;

        let db_key = key.to_db_key();

        match db.get_cf(&cf, &db_key) {
            Ok(Some(data)) => {
                let value = SpentIndexValue::from_bytes(&data)?;
                Ok(Some(value))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::ChainDatabase;
    use tempfile::tempdir;

    fn create_test_db() -> (Arc<ChainDatabase>, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db = ChainDatabase::open(dir.path()).unwrap();
        (Arc::new(db), dir)
    }

    #[test]
    fn test_spent_index_key_serialization() {
        let key = SpentIndexKey::new(Hash256::from_bytes([1u8; 32]), 42);

        let db_key = key.to_db_key();
        assert_eq!(db_key.len(), 37);
        assert_eq!(db_key[0], b'S');

        let decoded = SpentIndexKey::from_db_key(&db_key).unwrap();
        assert_eq!(decoded.txid, key.txid);
        assert_eq!(decoded.output_index, 42);
    }

    #[test]
    fn test_spent_index_key_invalid() {
        // Too short
        assert!(SpentIndexKey::from_db_key(&[b'S'; 10]).is_none());

        // Wrong prefix
        let mut key = vec![b'X'];
        key.extend_from_slice(&[0u8; 36]);
        assert!(SpentIndexKey::from_db_key(&key).is_none());
    }

    #[test]
    fn test_mark_spent_and_query() {
        let (db, _dir) = create_test_db();
        let index = SpentIndex::new(db);

        let key = SpentIndexKey::new(Hash256::from_bytes([1u8; 32]), 0);
        let value = SpentIndexValue::new(
            Hash256::from_bytes([2u8; 32]),
            5,
            100,
            Amount::from_sat(1000000),
            1,
            [3u8; 20],
        );

        // Initially unspent
        assert!(!index.is_spent(&key).unwrap());
        assert!(index.get_spent_info(&key).unwrap().is_none());

        // Mark as spent
        index.mark_spent(&key, &value).unwrap();
        assert!(index.is_spent(&key).unwrap());

        // Retrieve spending info
        let retrieved = index.get_spent_info(&key).unwrap().unwrap();
        assert_eq!(retrieved.spending_txid, value.spending_txid);
        assert_eq!(retrieved.input_index, 5);
        assert_eq!(retrieved.block_height, 100);
        assert_eq!(retrieved.amount, Amount::from_sat(1000000));
    }

    #[test]
    fn test_mark_unspent() {
        let (db, _dir) = create_test_db();
        let index = SpentIndex::new(db);

        let key = SpentIndexKey::new(Hash256::from_bytes([1u8; 32]), 0);
        let value = SpentIndexValue::new(
            Hash256::from_bytes([2u8; 32]),
            5,
            100,
            Amount::from_sat(1000000),
            1,
            [3u8; 20],
        );

        // Mark as spent
        index.mark_spent(&key, &value).unwrap();
        assert!(index.is_spent(&key).unwrap());

        // Mark as unspent (reorg)
        index.mark_unspent(&key).unwrap();
        assert!(!index.is_spent(&key).unwrap());
        assert!(index.get_spent_info(&key).unwrap().is_none());
    }

    #[test]
    fn test_multiple_outputs() {
        let (db, _dir) = create_test_db();
        let index = SpentIndex::new(db);

        let txid = Hash256::from_bytes([1u8; 32]);

        // Mark output 0 as spent
        let key0 = SpentIndexKey::new(txid, 0);
        let value0 = SpentIndexValue::new(
            Hash256::from_bytes([2u8; 32]),
            0,
            100,
            Amount::from_sat(1000000),
            1,
            [3u8; 20],
        );
        index.mark_spent(&key0, &value0).unwrap();

        // Output 1 remains unspent
        let key1 = SpentIndexKey::new(txid, 1);
        assert!(!index.is_spent(&key1).unwrap());

        // Mark output 1 as spent
        let value1 = SpentIndexValue::new(
            Hash256::from_bytes([3u8; 32]),
            2,
            101,
            Amount::from_sat(2000000),
            1,
            [4u8; 20],
        );
        index.mark_spent(&key1, &value1).unwrap();

        // Both are now spent
        assert!(index.is_spent(&key0).unwrap());
        assert!(index.is_spent(&key1).unwrap());
    }

    // ================================================================
    // SpentIndexValue: address_type and address_hash fields
    // ================================================================

    #[test]
    fn test_spent_index_value_address_fields() {
        let (db, _dir) = create_test_db();
        let index = SpentIndex::new(db);

        let key = SpentIndexKey::new(Hash256::from_bytes([0xAA; 32]), 7);
        let addr_hash = [0xBB; 20];
        let value = SpentIndexValue::new(
            Hash256::from_bytes([0xCC; 32]),
            3,
            500,
            Amount::from_sat(2_500_000),
            2, // P2SH
            addr_hash,
        );

        index.mark_spent(&key, &value).unwrap();

        let retrieved = index.get_spent_info(&key).unwrap().unwrap();
        assert_eq!(retrieved.address_type, 2);
        assert_eq!(retrieved.address_hash, addr_hash);
        assert_eq!(retrieved.input_index, 3);
        assert_eq!(retrieved.block_height, 500);
        assert_eq!(retrieved.amount.as_sat(), 2_500_000);
    }

    #[test]
    fn test_spent_index_key_vout_zero() {
        let key = SpentIndexKey::new(Hash256::from_bytes([0x01; 32]), 0);
        let db_key = key.to_db_key();
        let decoded = SpentIndexKey::from_db_key(&db_key).unwrap();
        assert_eq!(decoded.output_index, 0);
    }

    #[test]
    fn test_spent_index_key_vout_max() {
        let key = SpentIndexKey::new(Hash256::from_bytes([0x01; 32]), u32::MAX);
        let db_key = key.to_db_key();
        let decoded = SpentIndexKey::from_db_key(&db_key).unwrap();
        assert_eq!(decoded.output_index, u32::MAX);
    }

    #[test]
    fn test_spent_index_negative_block_height() {
        // Negative block heights can appear during mempool tracking
        let (db, _dir) = create_test_db();
        let index = SpentIndex::new(db);

        let key = SpentIndexKey::new(Hash256::from_bytes([0x05; 32]), 0);
        let value = SpentIndexValue::new(
            Hash256::from_bytes([0x06; 32]),
            0,
            -1, // mempool / unconfirmed
            Amount::from_sat(100_000),
            1,
            [0u8; 20],
        );

        index.mark_spent(&key, &value).unwrap();

        let retrieved = index.get_spent_info(&key).unwrap().unwrap();
        assert_eq!(retrieved.block_height, -1);
    }

    #[test]
    fn test_spent_index_mark_spent_overwrites() {
        // Re-spending (overwrite) should update the record
        let (db, _dir) = create_test_db();
        let index = SpentIndex::new(db);

        let key = SpentIndexKey::new(Hash256::from_bytes([0x10; 32]), 0);

        let v1 = SpentIndexValue::new(
            Hash256::from_bytes([0x11; 32]),
            0,
            100,
            Amount::from_sat(1_000),
            1,
            [0u8; 20],
        );
        index.mark_spent(&key, &v1).unwrap();

        // Overwrite with different data
        let v2 = SpentIndexValue::new(
            Hash256::from_bytes([0x22; 32]),
            5,
            200,
            Amount::from_sat(2_000),
            2,
            [0xffu8; 20],
        );
        index.mark_spent(&key, &v2).unwrap();

        let retrieved = index.get_spent_info(&key).unwrap().unwrap();
        assert_eq!(retrieved.spending_txid, Hash256::from_bytes([0x22; 32]));
        assert_eq!(retrieved.block_height, 200);
        assert_eq!(retrieved.amount.as_sat(), 2_000);
    }
}
