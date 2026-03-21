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

//! Chain database implementation
//!
//! Provides persistent storage for blocks, block index, and UTXO set
//! using RocksDB as the backend.

use crate::block_index::{block_index_key, height_key, BlockIndex};
use crate::error::StorageError;
use crate::utxo::{outpoint_from_key, utxo_key, Utxo};
use crate::utxo_cache::UtxoCache;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::OutPoint;
use moka::sync::Cache as MokaCache;
use rocksdb::{BlockBasedOptions, Cache, ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::Arc;
use tracing::info;

/// Default RocksDB block cache size (128 MB)
const DEFAULT_BLOCK_CACHE_SIZE: usize = 128 * 1024 * 1024;
/// Default write buffer size (64 MB)
const DEFAULT_WRITE_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Column family names
const CF_DEFAULT: &str = "default";
const CF_BLOCKS: &str = "blocks";
const CF_BLOCK_INDEX: &str = "block_index";
const CF_UTXO: &str = "utxo";
const CF_METADATA: &str = "metadata";
const CF_MASTERNODES: &str = "masternodes";
const CF_SPENT_INDEX: &str = "spent_index";
const CF_UNDO: &str = "undo";

/// Metadata keys
const KEY_BEST_BLOCK: &[u8] = b"best_block";
const KEY_CHAIN_HEIGHT: &[u8] = b"chain_height";

#[derive(Debug, Clone)]
pub struct UtxoStats {
    pub transactions: u64,
    pub txouts: u64,
    pub total_amount: u64,
    pub bytes_serialized: u64,
    /// SHA256 hash over all UTXO entries (txid, vout, height, is_coinbase, amount, scriptPubKey)
    pub hash_serialized: [u8; 32],
}

/// Default block index cache size (10,000 entries - covers recent blocks for MTP, stake modifier, etc.)
const DEFAULT_BLOCK_INDEX_CACHE_SIZE: u64 = 10_000;

/// Chain database
pub struct ChainDatabase {
    db: Arc<DB>,
    /// Optional in-memory UTXO cache for faster lookups
    utxo_cache: Option<UtxoCache>,
    /// In-memory block index cache for faster lookups (especially during staking)
    block_index_cache: MokaCache<Hash256, BlockIndex>,
    /// Cache for height -> hash mapping
    height_to_hash_cache: MokaCache<u32, Hash256>,
}

impl ChainDatabase {
    /// Open or create a chain database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        Self::open_with_cache_size(path, DEFAULT_BLOCK_CACHE_SIZE)
    }

    /// Open or create a chain database with configurable cache size
    pub fn open_with_cache_size<P: AsRef<Path>>(
        path: P,
        block_cache_size: usize,
    ) -> Result<Self, StorageError> {
        // === Database-wide options ===
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Performance tuning for blockchain workload
        opts.set_write_buffer_size(DEFAULT_WRITE_BUFFER_SIZE); // 64MB write buffer
        opts.set_max_write_buffer_number(3); // Keep up to 3 buffers
        opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB SST files
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_max_background_jobs(4); // Parallel compaction/flush

        // === Shared block cache for reads ===
        let cache = Cache::new_lru_cache(block_cache_size);

        // === Block-based table options with bloom filter ===
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_cache(&cache);
        block_opts.set_bloom_filter(10.0, false); // 10 bits per key, ~1% false positive
        block_opts.set_cache_index_and_filter_blocks(true); // Cache index/filter in block cache
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true); // Pin L0 for faster reads

        // === Column family options ===
        // Default CF - standard options
        let default_opts = Options::default();

        // Blocks CF - larger blocks, less frequent reads, compression beneficial
        let mut blocks_opts = Options::default();
        blocks_opts.set_write_buffer_size(DEFAULT_WRITE_BUFFER_SIZE);
        blocks_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        // Block Index CF - needs fast iteration
        let mut block_index_opts = Options::default();
        let mut block_index_block_opts = BlockBasedOptions::default();
        block_index_block_opts.set_block_cache(&cache);
        block_index_block_opts.set_bloom_filter(10.0, false);
        block_index_opts.set_block_based_table_factory(&block_index_block_opts);

        // UTXO CF - highest read performance needed (most accessed)
        let mut utxo_opts = Options::default();
        let mut utxo_block_opts = BlockBasedOptions::default();
        utxo_block_opts.set_block_cache(&cache);
        utxo_block_opts.set_bloom_filter(10.0, false); // Critical for has_utxo lookups
        utxo_block_opts.set_cache_index_and_filter_blocks(true);
        utxo_block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        utxo_opts.set_block_based_table_factory(&utxo_block_opts);
        utxo_opts.set_write_buffer_size(DEFAULT_WRITE_BUFFER_SIZE);

        // Metadata CF - small, accessed infrequently
        let metadata_opts = Options::default();

        // Masternodes CF - moderate access
        let mut mn_opts = Options::default();
        let mut mn_block_opts = BlockBasedOptions::default();
        mn_block_opts.set_block_cache(&cache);
        mn_opts.set_block_based_table_factory(&mn_block_opts);

        // Spent Index CF - similar to UTXO
        let mut spent_opts = Options::default();
        let mut spent_block_opts = BlockBasedOptions::default();
        spent_block_opts.set_block_cache(&cache);
        spent_block_opts.set_bloom_filter(10.0, false);
        spent_opts.set_block_based_table_factory(&spent_block_opts);

        // Undo CF - stores previous UTXO state for block disconnection (like C++ CBlockUndo)
        let mut undo_opts = Options::default();
        undo_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_DEFAULT, default_opts),
            ColumnFamilyDescriptor::new(CF_BLOCKS, blocks_opts),
            ColumnFamilyDescriptor::new(CF_BLOCK_INDEX, block_index_opts),
            ColumnFamilyDescriptor::new(CF_UTXO, utxo_opts),
            ColumnFamilyDescriptor::new(CF_METADATA, metadata_opts),
            ColumnFamilyDescriptor::new(CF_MASTERNODES, mn_opts),
            ColumnFamilyDescriptor::new(CF_SPENT_INDEX, spent_opts),
            ColumnFamilyDescriptor::new(CF_UNDO, undo_opts),
        ];

        tracing::info!(
            "Opening RocksDB with optimized settings: block_cache={}MB, write_buffer={}MB",
            block_cache_size / (1024 * 1024),
            DEFAULT_WRITE_BUFFER_SIZE / (1024 * 1024)
        );

        let db = DB::open_cf_descriptors(&opts, path, cfs)?;

        // Create block index caches for faster lookups during staking
        let block_index_cache = MokaCache::builder()
            .max_capacity(DEFAULT_BLOCK_INDEX_CACHE_SIZE)
            .build();
        let height_to_hash_cache = MokaCache::builder()
            .max_capacity(DEFAULT_BLOCK_INDEX_CACHE_SIZE)
            .build();

        Ok(ChainDatabase {
            db: Arc::new(db),
            utxo_cache: None,
            block_index_cache,
            height_to_hash_cache,
        })
    }

    /// Open or create a chain database with UTXO cache enabled
    ///
    /// The UTXO cache provides significant performance improvements during sync
    /// by caching hot UTXOs in memory with LRU eviction.
    pub fn open_with_utxo_cache<P: AsRef<Path>>(
        path: P,
        utxo_cache_entries: u64,
    ) -> Result<Self, StorageError> {
        let mut db = Self::open_with_cache_size(path, DEFAULT_BLOCK_CACHE_SIZE)?;
        if utxo_cache_entries > 0 {
            db.utxo_cache = Some(UtxoCache::new(utxo_cache_entries));
            info!("UTXO cache enabled with {} max entries", utxo_cache_entries);
        }
        Ok(db)
    }

    /// Enable UTXO cache on an existing database
    pub fn enable_utxo_cache(&mut self, max_entries: u64) {
        self.utxo_cache = Some(UtxoCache::new(max_entries));
        info!("UTXO cache enabled with {} max entries", max_entries);
    }

    /// Check if UTXO cache is enabled
    pub fn has_utxo_cache(&self) -> bool {
        self.utxo_cache.is_some()
    }

    /// Get UTXO cache statistics
    pub fn utxo_cache_stats(&self) -> Option<crate::utxo_cache::CacheStats> {
        self.utxo_cache.as_ref().map(|c| c.stats())
    }

    /// Open a database with default options (for testing)
    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        Self::open(path)
    }

    // ========== Block Storage ==========

    /// Store a block
    pub fn store_block(&self, hash: &Hash256, block: &Block) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_BLOCKS).unwrap();
        let key = hash.as_bytes();
        let value = serialize(block);
        self.db.put_cf(cf, key, value)?;
        Ok(())
    }

    /// Get a block by hash
    pub fn get_block(&self, hash: &Hash256) -> Result<Option<Block>, StorageError> {
        let cf = self.db.cf_handle(CF_BLOCKS).unwrap();
        match self.db.get_cf(cf, hash.as_bytes())? {
            Some(data) => {
                let block: Block =
                    deserialize(&data).map_err(|e| StorageError::Deserialization(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Check if a block exists
    pub fn has_block(&self, hash: &Hash256) -> Result<bool, StorageError> {
        let cf = self.db.cf_handle(CF_BLOCKS).unwrap();
        Ok(self.db.get_cf(cf, hash.as_bytes())?.is_some())
    }

    // ========== Block Index ==========

    /// Store a block index entry
    pub fn store_block_index(&self, index: &BlockIndex) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_BLOCK_INDEX).unwrap();
        let key = block_index_key(&index.hash);
        let value = index.to_bytes();
        self.db.put_cf(cf, key, value)?;

        // Also store height -> hash mapping
        let height_k = height_key(index.height);
        self.db.put_cf(cf, height_k, index.hash.as_bytes())?;

        // Update caches
        self.block_index_cache.insert(index.hash, index.clone());
        self.height_to_hash_cache.insert(index.height, index.hash);

        Ok(())
    }

    /// Get a block index by hash
    pub fn get_block_index(&self, hash: &Hash256) -> Result<Option<BlockIndex>, StorageError> {
        // Check cache first
        if let Some(index) = self.block_index_cache.get(hash) {
            return Ok(Some(index));
        }

        // Cache miss - fetch from DB
        let cf = self.db.cf_handle(CF_BLOCK_INDEX).unwrap();
        let key = block_index_key(hash);
        match self.db.get_cf(cf, key)? {
            Some(data) => {
                let index = BlockIndex::from_bytes(&data)?;
                // Populate cache for future lookups
                self.block_index_cache.insert(*hash, index.clone());
                Ok(Some(index))
            }
            None => Ok(None),
        }
    }

    /// Get a block index by height
    pub fn get_block_index_by_height(
        &self,
        height: u32,
    ) -> Result<Option<BlockIndex>, StorageError> {
        // Check height->hash cache first
        if let Some(hash) = self.height_to_hash_cache.get(&height) {
            return self.get_block_index(&hash);
        }

        // Cache miss - fetch hash from DB
        let cf = self.db.cf_handle(CF_BLOCK_INDEX).unwrap();
        let key = height_key(height);

        match self.db.get_cf(cf, key)? {
            Some(hash_data) => {
                if hash_data.len() != 32 {
                    return Err(StorageError::Deserialization("invalid hash length".into()));
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&hash_data);
                let hash = Hash256::from_bytes(hash_bytes);

                // Populate height->hash cache
                self.height_to_hash_cache.insert(height, hash);

                self.get_block_index(&hash)
            }
            None => Ok(None),
        }
    }

    /// Check if a block index exists
    pub fn has_block_index(&self, hash: &Hash256) -> Result<bool, StorageError> {
        let cf = self.db.cf_handle(CF_BLOCK_INDEX).unwrap();
        let key = block_index_key(hash);
        Ok(self.db.get_cf(cf, key)?.is_some())
    }

    /// Remove height→hash mapping for a given height (used during disconnect)
    pub fn remove_height_mapping(&self, height: u32) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_BLOCK_INDEX).unwrap();
        self.db.delete_cf(cf, height_key(height))?;
        self.height_to_hash_cache.invalidate(&height);
        Ok(())
    }

    // ========== UTXO Set ==========

    /// Add a UTXO
    ///
    /// If UTXO cache is enabled, the entry is added to cache and marked dirty.
    /// Otherwise, it's written directly to the database.
    pub fn add_utxo(&self, outpoint: &OutPoint, utxo: &Utxo) -> Result<(), StorageError> {
        // Always write to RocksDB for durability
        let cf = self.db.cf_handle(CF_UTXO).unwrap();
        let key = utxo_key(outpoint);
        let value = utxo.to_bytes();
        self.db.put_cf(cf, key, value)?;

        // Also populate cache for fast reads
        if let Some(ref cache) = self.utxo_cache {
            cache.insert(*outpoint, utxo.clone());
        }
        Ok(())
    }

    /// Get a UTXO
    ///
    /// If UTXO cache is enabled, checks cache first and populates on miss.
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, StorageError> {
        if let Some(ref cache) = self.utxo_cache {
            // Check cache first
            if let Some(result) = cache.get(outpoint) {
                return Ok(result);
            }
            // Cache miss: fetch from DB and populate cache
            let cf = self.db.cf_handle(CF_UTXO).unwrap();
            let key = utxo_key(outpoint);
            match self.db.get_cf(cf, key)? {
                Some(data) => {
                    let utxo = Utxo::from_bytes(&data)?;
                    cache.populate_from_db(*outpoint, Some(utxo.clone()));
                    Ok(Some(utxo))
                }
                None => Ok(None),
            }
        } else {
            // No cache: fetch directly from DB
            let cf = self.db.cf_handle(CF_UTXO).unwrap();
            let key = utxo_key(outpoint);
            match self.db.get_cf(cf, key)? {
                Some(data) => Ok(Some(Utxo::from_bytes(&data)?)),
                None => Ok(None),
            }
        }
    }

    /// Remove a UTXO
    ///
    /// If UTXO cache is enabled, marks as deleted (tombstone) in cache.
    /// Otherwise, deletes directly from database.
    pub fn remove_utxo(&self, outpoint: &OutPoint) -> Result<(), StorageError> {
        // Always delete from RocksDB for durability
        let cf = self.db.cf_handle(CF_UTXO).unwrap();
        let key = utxo_key(outpoint);
        self.db.delete_cf(cf, key)?;

        // Also update cache
        if let Some(ref cache) = self.utxo_cache {
            cache.remove(*outpoint);
        }
        Ok(())
    }

    /// Check if a UTXO exists
    ///
    /// If UTXO cache is enabled, checks cache first.
    pub fn has_utxo(&self, outpoint: &OutPoint) -> Result<bool, StorageError> {
        if let Some(ref cache) = self.utxo_cache {
            // Check cache first
            if let Some(exists) = cache.contains(outpoint) {
                return Ok(exists);
            }
            // Cache miss: check DB
            let cf = self.db.cf_handle(CF_UTXO).unwrap();
            let key = utxo_key(outpoint);
            let exists = self.db.get_cf(cf, key)?.is_some();
            // Populate cache on miss if the UTXO exists
            if exists {
                if let Ok(Some(utxo)) = self.get_utxo_direct(outpoint) {
                    cache.populate_from_db(*outpoint, Some(utxo));
                }
            }
            Ok(exists)
        } else {
            // No cache: check DB directly
            let cf = self.db.cf_handle(CF_UTXO).unwrap();
            let key = utxo_key(outpoint);
            Ok(self.db.get_cf(cf, key)?.is_some())
        }
    }

    /// Get a UTXO directly from database (bypassing cache)
    fn get_utxo_direct(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).unwrap();
        let key = utxo_key(outpoint);
        match self.db.get_cf(cf, key)? {
            Some(data) => Ok(Some(Utxo::from_bytes(&data)?)),
            None => Ok(None),
        }
    }

    /// Flush the UTXO cache to database
    ///
    /// Should be called periodically during sync and before shutdown.
    /// Returns the number of entries flushed, or 0 if cache is not enabled.
    pub fn flush_utxo_cache(&self) -> Result<usize, StorageError> {
        if let Some(ref cache) = self.utxo_cache {
            cache.flush(&self.db)
        } else {
            Ok(0)
        }
    }

    /// Iterate all UTXOs and calculate statistics
    pub fn get_utxo_stats(&self) -> Result<UtxoStats, StorageError> {
        use sha2::{Digest, Sha256};

        let cf = self.db.cf_handle(CF_UTXO).unwrap();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        let mut stats = UtxoStats {
            transactions: 0,
            txouts: 0,
            total_amount: 0,
            bytes_serialized: 0,
            hash_serialized: [0u8; 32],
        };

        let mut last_txid: Option<Hash256> = None;
        let mut hasher = Sha256::new();

        for item in iter {
            let (_key, value) = item?;
            stats.txouts += 1;
            stats.bytes_serialized += value.len() as u64;

            let utxo = Utxo::from_bytes(&value)?;
            stats.total_amount += utxo.value.as_sat() as u64;

            let outpoint = outpoint_from_key(&_key).map_err(StorageError::Deserialization)?;
            if last_txid.as_ref() != Some(&outpoint.txid) {
                stats.transactions += 1;
                last_txid = Some(outpoint.txid);
            }

            // Feed UTXO data into SHA256 hasher (matching C++ gettxoutsetinfo format):
            // txid (32 bytes) | vout (u32 LE) | height (u32 LE) | is_coinbase (1 byte) | amount (i64 LE) | scriptPubKey (varint len + bytes)
            hasher.update(outpoint.txid.as_bytes());
            hasher.update(outpoint.vout.to_le_bytes());
            hasher.update(utxo.height.to_le_bytes());
            hasher.update([utxo.is_coinbase as u8]);
            hasher.update(utxo.value.as_sat().to_le_bytes());
            let script_bytes = utxo.script_pubkey.as_bytes();
            hasher.update((script_bytes.len() as u32).to_le_bytes());
            hasher.update(script_bytes);
        }

        stats.hash_serialized = hasher.finalize().into();

        Ok(stats)
    }

    // ========== Chain State ==========

    /// Get the best block hash
    pub fn get_best_block(&self) -> Result<Option<Hash256>, StorageError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        match self.db.get_cf(cf, KEY_BEST_BLOCK)? {
            Some(data) => {
                if data.len() != 32 {
                    return Err(StorageError::Deserialization(
                        "invalid best block hash".into(),
                    ));
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&data);
                Ok(Some(Hash256::from_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    /// Set the best block hash
    pub fn set_best_block(&self, hash: &Hash256) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        self.db.put_cf(cf, KEY_BEST_BLOCK, hash.as_bytes())?;
        Ok(())
    }

    /// Get the chain height
    pub fn get_chain_height(&self) -> Result<Option<u32>, StorageError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        match self.db.get_cf(cf, KEY_CHAIN_HEIGHT)? {
            Some(data) => {
                if data.len() != 4 {
                    return Err(StorageError::Deserialization("invalid height".into()));
                }
                let height = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Ok(Some(height))
            }
            None => Ok(None),
        }
    }

    /// Set the chain height
    pub fn set_chain_height(&self, height: u32) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_METADATA).unwrap();
        self.db.put_cf(cf, KEY_CHAIN_HEIGHT, height.to_le_bytes())?;
        Ok(())
    }

    // ========== Undo Data (CBlockUndo equivalent) ==========

    /// Store undo data for a block, keyed by block hash.
    /// Undo data contains the previous UTXO state for every input spent in the block,
    /// enabling deterministic disconnect without searching block data.
    pub fn store_undo_data(&self, block_hash: &Hash256, data: &[u8]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).unwrap();
        self.db.put_cf(cf, block_hash.as_bytes(), data)?;
        Ok(())
    }

    /// Get undo data for a block
    pub fn get_undo_data(&self, block_hash: &Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).unwrap();
        Ok(self.db.get_cf(cf, block_hash.as_bytes())?)
    }

    /// Delete undo data for a block (after it's deep enough to never be disconnected)
    pub fn delete_undo_data(&self, block_hash: &Hash256) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).unwrap();
        self.db.delete_cf(cf, block_hash.as_bytes())?;
        Ok(())
    }

    /// Atomically flush UTXO changes + undo data + tip update in a single WriteBatch.
    /// This is the C++ pattern: all state changes for a connected block are atomic.
    pub fn atomic_connect_block(
        &self,
        utxo_batch: &BatchedUtxoWriter,
        undo_data: &[u8],
        block_hash: &Hash256,
        block_index: &BlockIndex,
    ) -> Result<(), StorageError> {
        let removed_set: std::collections::HashSet<&OutPoint> = utxo_batch.removes.iter().collect();
        let added_set: std::collections::HashSet<&OutPoint> =
            utxo_batch.adds.iter().map(|(op, _)| op).collect();

        let cf_utxo = self.db.cf_handle(CF_UTXO).unwrap();
        let cf_undo = self.db.cf_handle(CF_UNDO).unwrap();
        let cf_metadata = self.db.cf_handle(CF_METADATA).unwrap();
        let cf_block_index = self.db.cf_handle(CF_BLOCK_INDEX).unwrap();

        let mut wb = WriteBatch::default();

        // UTXO removes (skip intra-block spends)
        for outpoint in &utxo_batch.removes {
            if !added_set.contains(outpoint) {
                wb.delete_cf(&cf_utxo, utxo_key(outpoint));
            }
        }

        // UTXO adds (skip intra-block spends)
        for (outpoint, utxo) in &utxo_batch.adds {
            if !removed_set.contains(outpoint) {
                wb.put_cf(&cf_utxo, utxo_key(outpoint), utxo.to_bytes());
            }
        }

        // Undo data
        wb.put_cf(&cf_undo, block_hash.as_bytes(), undo_data);

        // Tip update: best_block + chain_height + block_index + height mapping
        wb.put_cf(&cf_metadata, KEY_BEST_BLOCK, block_hash.as_bytes());
        wb.put_cf(
            &cf_metadata,
            KEY_CHAIN_HEIGHT,
            block_index.height.to_le_bytes(),
        );
        wb.put_cf(
            &cf_block_index,
            block_index_key(&block_index.hash),
            block_index.to_bytes(),
        );
        wb.put_cf(
            &cf_block_index,
            height_key(block_index.height),
            block_index.hash.as_bytes(),
        );

        // Single atomic write
        self.db.write(wb)?;

        // Update in-memory caches
        if let Some(ref cache) = self.utxo_cache {
            for outpoint in &utxo_batch.removes {
                if !added_set.contains(outpoint) {
                    cache.remove(*outpoint);
                }
            }
            for (outpoint, utxo) in &utxo_batch.adds {
                if !removed_set.contains(outpoint) {
                    cache.insert(*outpoint, utxo.clone());
                }
            }
        }

        // Update block index caches
        self.block_index_cache
            .insert(block_index.hash, block_index.clone());
        self.height_to_hash_cache
            .insert(block_index.height, block_index.hash);

        Ok(())
    }

    // ========== Batch Operations ==========

    /// Create a write batch for atomic operations
    pub fn batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Execute a write batch
    pub fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
        self.db.write(batch)?;
        Ok(())
    }

    /// Flush all pending writes
    pub fn flush(&self) -> Result<(), StorageError> {
        self.db.flush()?;
        Ok(())
    }

    /// Get reference to the underlying RocksDB instance
    /// Used by modules that need direct column family access (e.g., spent_index)
    pub fn inner_db(&self) -> &DB {
        &self.db
    }

    /// Get Arc to the underlying RocksDB instance
    /// Used by modules that need shared ownership (e.g., MasternodeManager)
    pub fn db_arc(&self) -> Arc<DB> {
        Arc::clone(&self.db)
    }

    /// Flush a batch of UTXO operations atomically
    ///
    /// If UTXO cache is enabled, operations go to the cache (deferred write).
    /// Otherwise, they are written directly to the database.
    pub fn flush_utxo_batch(&self, batch: &BatchedUtxoWriter) -> Result<(), StorageError> {
        // Build a set of removed outpoints so we can detect intra-block spends
        // (UTXOs created and spent within the same block should be a no-op)
        let removed_set: std::collections::HashSet<&OutPoint> = batch.removes.iter().collect();

        let cf = self.db.cf_handle(CF_UTXO).unwrap();
        let mut wb = WriteBatch::default();

        // Only remove UTXOs that were NOT also created in this batch
        // (those are pre-existing UTXOs that are being spent)
        let added_set: std::collections::HashSet<&OutPoint> =
            batch.adds.iter().map(|(op, _)| op).collect();
        for outpoint in &batch.removes {
            if !added_set.contains(outpoint) {
                wb.delete_cf(&cf, utxo_key(outpoint));
            }
        }

        // Only add UTXOs that were NOT also removed in this batch
        // (those survived the block and are unspent)
        for (outpoint, utxo) in &batch.adds {
            if !removed_set.contains(outpoint) {
                wb.put_cf(&cf, utxo_key(outpoint), utxo.to_bytes());
            }
        }

        self.db.write(wb)?;

        // Also update cache for fast reads (same deduplication logic)
        if let Some(ref cache) = self.utxo_cache {
            for outpoint in &batch.removes {
                if !added_set.contains(outpoint) {
                    cache.remove(*outpoint);
                }
            }
            for (outpoint, utxo) in &batch.adds {
                if !removed_set.contains(outpoint) {
                    cache.insert(*outpoint, utxo.clone());
                }
            }
        }

        Ok(())
    }
}

/// Batched UTXO writer for collecting multiple operations into a single atomic write
///
/// This reduces write amplification by batching all UTXO changes within a block
/// into a single RocksDB WriteBatch operation.
pub struct BatchedUtxoWriter {
    pub(crate) adds: Vec<(OutPoint, Utxo)>,
    pub(crate) removes: Vec<OutPoint>,
}

impl BatchedUtxoWriter {
    /// Create a new empty batch
    pub fn new() -> Self {
        Self {
            adds: Vec::new(),
            removes: Vec::new(),
        }
    }

    /// Create a batch with pre-allocated capacity
    pub fn with_capacity(add_capacity: usize, remove_capacity: usize) -> Self {
        Self {
            adds: Vec::with_capacity(add_capacity),
            removes: Vec::with_capacity(remove_capacity),
        }
    }

    /// Add a UTXO to the batch
    pub fn add(&mut self, outpoint: OutPoint, utxo: Utxo) {
        self.adds.push((outpoint, utxo));
    }

    /// Remove a UTXO from the batch
    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    /// Get the number of adds in this batch
    pub fn add_count(&self) -> usize {
        self.adds.len()
    }

    /// Get the number of removes in this batch
    pub fn remove_count(&self) -> usize {
        self.removes.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.removes.is_empty()
    }

    /// Clear the batch
    pub fn clear(&mut self) {
        self.adds.clear();
        self.removes.clear();
    }
}

impl Default for BatchedUtxoWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::amount::Amount;
    use divi_primitives::script::Script;
    use tempfile::tempdir;

    fn create_test_db() -> (ChainDatabase, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db = ChainDatabase::open(dir.path()).unwrap();
        (db, dir)
    }

    fn make_block_index(hash_byte: u8, height: u32) -> crate::block_index::BlockIndex {
        use crate::block_index::{BlockIndex, BlockStatus};
        use divi_primitives::lottery::LotteryWinners;
        BlockIndex {
            hash: Hash256::from_bytes([hash_byte; 32]),
            prev_hash: Hash256::zero(),
            height,
            version: 4,
            merkle_root: Hash256::zero(),
            time: 1_700_000_000 + height,
            bits: 0x1e0fffff,
            nonce: 0,
            accumulator: None,
            n_tx: 1,
            chain_work: [0u8; 32],
            status: BlockStatus::empty(),
            file_num: -1,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: LotteryWinners::new(height),
            is_proof_of_stake: false,
        }
    }

    fn make_utxo(sat: i64) -> (OutPoint, Utxo) {
        let outpoint = OutPoint::new(Hash256::from_bytes([sat as u8; 32]), 0);
        let utxo = Utxo::new(
            Amount::from_sat(sat),
            Script::new_p2pkh(&[0u8; 20]),
            100,
            false,
            false,
        );
        (outpoint, utxo)
    }

    #[test]
    fn test_block_storage() {
        let (db, _dir) = create_test_db();

        let block = Block::default();
        let hash = Hash256::from_bytes([1u8; 32]);

        // Store and retrieve
        db.store_block(&hash, &block).unwrap();
        assert!(db.has_block(&hash).unwrap());

        let retrieved = db.get_block(&hash).unwrap().unwrap();
        assert_eq!(retrieved.header.version, block.header.version);
    }

    #[test]
    fn test_block_index_storage() {
        use divi_primitives::lottery::LotteryWinners;
        let (db, _dir) = create_test_db();

        let index = BlockIndex {
            hash: Hash256::from_bytes([1u8; 32]),
            prev_hash: Hash256::zero(),
            height: 100,
            version: 4,
            merkle_root: Hash256::from_bytes([2u8; 32]),
            time: 1638000000,
            bits: 0x1d00ffff,
            nonce: 0,
            accumulator: None,
            n_tx: 1,
            chain_work: [0u8; 32],
            status: crate::block_index::BlockStatus::from_bits(0x17),
            file_num: 0,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: LotteryWinners::new(100),
            is_proof_of_stake: false,
        };

        db.store_block_index(&index).unwrap();

        // Retrieve by hash
        let by_hash = db.get_block_index(&index.hash).unwrap().unwrap();
        assert_eq!(by_hash.height, 100);

        // Retrieve by height
        let by_height = db.get_block_index_by_height(100).unwrap().unwrap();
        assert_eq!(by_height.hash, index.hash);
    }

    #[test]
    fn test_utxo_storage() {
        let (db, _dir) = create_test_db();

        let outpoint = OutPoint::new(Hash256::from_bytes([1u8; 32]), 0);
        let utxo = Utxo::new(
            Amount::from_sat(1000000),
            Script::new_p2pkh(&[0u8; 20]),
            100,
            false,
            false,
        );

        // Add and retrieve
        db.add_utxo(&outpoint, &utxo).unwrap();
        assert!(db.has_utxo(&outpoint).unwrap());

        let retrieved = db.get_utxo(&outpoint).unwrap().unwrap();
        assert_eq!(retrieved.value, utxo.value);
        assert_eq!(retrieved.height, 100);

        // Remove
        db.remove_utxo(&outpoint).unwrap();
        assert!(!db.has_utxo(&outpoint).unwrap());
    }

    #[test]
    fn test_chain_state() {
        let (db, _dir) = create_test_db();

        // Initially empty
        assert!(db.get_best_block().unwrap().is_none());
        assert!(db.get_chain_height().unwrap().is_none());

        // Set values
        let hash = Hash256::from_bytes([1u8; 32]);
        db.set_best_block(&hash).unwrap();
        db.set_chain_height(1000).unwrap();

        // Retrieve
        assert_eq!(db.get_best_block().unwrap().unwrap(), hash);
        assert_eq!(db.get_chain_height().unwrap().unwrap(), 1000);
    }

    #[test]
    fn test_get_utxo_stats() {
        let (db, _dir) = create_test_db();

        // Empty UTXO set
        let stats = db.get_utxo_stats().unwrap();
        assert_eq!(stats.transactions, 0);
        assert_eq!(stats.txouts, 0);
        assert_eq!(stats.total_amount, 0);
        assert_eq!(stats.bytes_serialized, 0);

        // Add UTXOs from the same transaction (txid1)
        let txid1 = Hash256::from_bytes([0x01; 32]);
        let utxo1 = Utxo::new(
            Amount::from_sat(100_000_000), // 1 DIVI
            Script::new_p2pkh(&[0x11; 20]),
            100,
            false,
            false,
        );
        let utxo2 = Utxo::new(
            Amount::from_sat(200_000_000), // 2 DIVI
            Script::new_p2pkh(&[0x12; 20]),
            100,
            false,
            false,
        );
        db.add_utxo(&OutPoint::new(txid1, 0), &utxo1).unwrap();
        db.add_utxo(&OutPoint::new(txid1, 1), &utxo2).unwrap();

        // Add UTXO from a different transaction (txid2)
        let txid2 = Hash256::from_bytes([0x02; 32]);
        let utxo3 = Utxo::new(
            Amount::from_sat(300_000_000), // 3 DIVI
            Script::new_p2pkh(&[0x13; 20]),
            101,
            false,
            false,
        );
        db.add_utxo(&OutPoint::new(txid2, 0), &utxo3).unwrap();

        // Get stats
        let stats = db.get_utxo_stats().unwrap();

        // Should have 2 unique transactions
        assert_eq!(stats.transactions, 2, "Expected 2 transactions");

        // Should have 3 total UTXOs
        assert_eq!(stats.txouts, 3, "Expected 3 transaction outputs");

        // Total amount should be 6 DIVI (600M satoshis)
        assert_eq!(stats.total_amount, 600_000_000, "Expected 600M satoshis");

        // Should have serialized bytes
        assert!(
            stats.bytes_serialized > 0,
            "Expected non-zero serialized bytes"
        );

        // Verify bytes_serialized is reasonable (3 UTXOs with P2PKH scripts)
        // Each UTXO: 8 (value) + 4 (script_len) + 25 (P2PKH script) + 4 (height) + 1 (flags) = 42 bytes
        assert_eq!(
            stats.bytes_serialized,
            42 * 3,
            "Expected 126 bytes (42 per UTXO)"
        );
    }

    #[test]
    fn test_get_utxo_stats_with_removal() {
        let (db, _dir) = create_test_db();

        // Add 3 UTXOs
        let txid1 = Hash256::from_bytes([0x01; 32]);
        let utxo1 = Utxo::new(
            Amount::from_sat(100_000_000),
            Script::new_p2pkh(&[0x11; 20]),
            100,
            false,
            false,
        );
        db.add_utxo(&OutPoint::new(txid1, 0), &utxo1).unwrap();
        db.add_utxo(&OutPoint::new(txid1, 1), &utxo1).unwrap();
        db.add_utxo(&OutPoint::new(txid1, 2), &utxo1).unwrap();

        // Remove one
        db.remove_utxo(&OutPoint::new(txid1, 1)).unwrap();

        // Stats should only count remaining UTXOs
        let stats = db.get_utxo_stats().unwrap();
        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.txouts, 2, "Should have 2 UTXOs after removal");
        assert_eq!(stats.total_amount, 200_000_000, "Total should be 2 DIVI");
    }

    #[test]
    fn test_get_utxo_stats_coinbase_and_coinstake() {
        let (db, _dir) = create_test_db();

        // Add coinbase UTXO
        let coinbase = Utxo::new(
            Amount::from_sat(500_000_000),
            Script::new_p2pkh(&[0x01; 20]),
            1,
            true,
            false,
        );
        db.add_utxo(
            &OutPoint::new(Hash256::from_bytes([0x01; 32]), 0),
            &coinbase,
        )
        .unwrap();

        // Add coinstake UTXO
        let coinstake = Utxo::new(
            Amount::from_sat(1_000_000_000),
            Script::new_p2pkh(&[0x02; 20]),
            2,
            false,
            true,
        );
        db.add_utxo(
            &OutPoint::new(Hash256::from_bytes([0x02; 32]), 0),
            &coinstake,
        )
        .unwrap();

        let stats = db.get_utxo_stats().unwrap();
        assert_eq!(stats.transactions, 2);
        assert_eq!(stats.txouts, 2);
        assert_eq!(stats.total_amount, 1_500_000_000); // 15 DIVI
    }

    // ================================================================
    // has_block / has_block_index
    // ================================================================

    #[test]
    fn test_has_block_missing() {
        let (db, _dir) = create_test_db();
        let hash = Hash256::from_bytes([0xaa; 32]);
        assert!(!db.has_block(&hash).unwrap());
    }

    #[test]
    fn test_has_block_index_missing() {
        let (db, _dir) = create_test_db();
        let hash = Hash256::from_bytes([0xbb; 32]);
        assert!(!db.has_block_index(&hash).unwrap());
    }

    #[test]
    fn test_has_block_index_stored() {
        let (db, _dir) = create_test_db();
        let idx = make_block_index(0x10, 500);
        db.store_block_index(&idx).unwrap();
        assert!(db.has_block_index(&idx.hash).unwrap());
        assert!(!db
            .has_block_index(&Hash256::from_bytes([0xff; 32]))
            .unwrap());
    }

    // ================================================================
    // Block index by height - missing returns None
    // ================================================================

    #[test]
    fn test_block_index_by_height_missing() {
        let (db, _dir) = create_test_db();
        let result = db.get_block_index_by_height(9999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_block_index_by_height_multiple() {
        let (db, _dir) = create_test_db();
        let idx0 = make_block_index(0x01, 0);
        let idx1 = make_block_index(0x02, 1);
        let idx2 = make_block_index(0x03, 2);
        db.store_block_index(&idx0).unwrap();
        db.store_block_index(&idx1).unwrap();
        db.store_block_index(&idx2).unwrap();

        // Retrieve each by height
        let r0 = db.get_block_index_by_height(0).unwrap().unwrap();
        let r1 = db.get_block_index_by_height(1).unwrap().unwrap();
        let r2 = db.get_block_index_by_height(2).unwrap().unwrap();

        assert_eq!(r0.hash, idx0.hash);
        assert_eq!(r1.hash, idx1.hash);
        assert_eq!(r2.hash, idx2.hash);
    }

    // ================================================================
    // Chain state: persistence across reopen
    // ================================================================

    #[test]
    fn test_chain_state_persistence_across_reopen() {
        let dir = tempdir().unwrap();
        let hash = Hash256::from_bytes([0x42; 32]);

        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            db.set_best_block(&hash).unwrap();
            db.set_chain_height(12345).unwrap();
        }

        // Reopen
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            assert_eq!(db.get_best_block().unwrap().unwrap(), hash);
            assert_eq!(db.get_chain_height().unwrap().unwrap(), 12345);
        }
    }

    #[test]
    fn test_chain_state_update() {
        let (db, _dir) = create_test_db();
        let hash1 = Hash256::from_bytes([0x11; 32]);
        let hash2 = Hash256::from_bytes([0x22; 32]);

        db.set_best_block(&hash1).unwrap();
        db.set_chain_height(100).unwrap();
        assert_eq!(db.get_best_block().unwrap().unwrap(), hash1);
        assert_eq!(db.get_chain_height().unwrap().unwrap(), 100);

        // Update values
        db.set_best_block(&hash2).unwrap();
        db.set_chain_height(200).unwrap();
        assert_eq!(db.get_best_block().unwrap().unwrap(), hash2);
        assert_eq!(db.get_chain_height().unwrap().unwrap(), 200);
    }

    // ================================================================
    // UTXO write-through cache: CRITICAL regression prevention
    //
    // Requirement: add_utxo writes immediately to RocksDB even when
    // the UTXO cache is enabled. Restarting the node must not lose UTXOs.
    // ================================================================

    #[test]
    fn test_utxo_write_through_cache_persistence() {
        let dir = tempdir().unwrap();
        let outpoint = OutPoint::new(Hash256::from_bytes([0x55; 32]), 0);
        let utxo = Utxo::new(
            Amount::from_sat(500_000_000),
            Script::new_p2pkh(&[0xAB; 20]),
            1000,
            false,
            false,
        );

        // Write with cache enabled
        {
            let db = ChainDatabase::open_with_utxo_cache(dir.path(), 1000).unwrap();
            assert!(db.has_utxo_cache());
            db.add_utxo(&outpoint, &utxo).unwrap();
            // Do NOT call flush - write-through should have persisted immediately
        }

        // Reopen WITHOUT cache and verify UTXO is there
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            assert!(!db.has_utxo_cache());
            let retrieved = db.get_utxo(&outpoint).unwrap();
            assert!(
                retrieved.is_some(),
                "UTXO must survive restart even without explicit flush"
            );
            assert_eq!(retrieved.unwrap().value, utxo.value);
        }
    }

    #[test]
    fn test_utxo_remove_write_through_persistence() {
        let dir = tempdir().unwrap();
        let (outpoint, utxo) = make_utxo(1_000_000);

        // Add UTXO, then remove it (both with cache)
        {
            let db = ChainDatabase::open_with_utxo_cache(dir.path(), 1000).unwrap();
            db.add_utxo(&outpoint, &utxo).unwrap();
            db.remove_utxo(&outpoint).unwrap();
        }

        // After restart, UTXO must be gone
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            assert!(
                !db.has_utxo(&outpoint).unwrap(),
                "Removed UTXO must not reappear after restart"
            );
        }
    }

    #[test]
    fn test_utxo_with_cache_get_returns_correct_value() {
        let dir = tempdir().unwrap();
        let db = ChainDatabase::open_with_utxo_cache(dir.path(), 1000).unwrap();

        let (op1, u1) = make_utxo(100_000);
        let (op2, u2) = make_utxo(200_000);

        db.add_utxo(&op1, &u1).unwrap();
        db.add_utxo(&op2, &u2).unwrap();

        // Both should be readable from cache
        let r1 = db.get_utxo(&op1).unwrap().unwrap();
        let r2 = db.get_utxo(&op2).unwrap().unwrap();
        assert_eq!(r1.value.as_sat(), 100_000);
        assert_eq!(r2.value.as_sat(), 200_000);

        // has_utxo also works
        assert!(db.has_utxo(&op1).unwrap());
        assert!(db.has_utxo(&op2).unwrap());

        // remove_utxo with cache
        db.remove_utxo(&op1).unwrap();
        assert!(!db.has_utxo(&op1).unwrap());
        assert!(db.has_utxo(&op2).unwrap());
    }

    #[test]
    fn test_open_with_utxo_cache_properties() {
        let dir = tempdir().unwrap();
        let db = ChainDatabase::open_with_utxo_cache(dir.path(), 5000).unwrap();
        assert!(db.has_utxo_cache());

        let stats = db.utxo_cache_stats().unwrap();
        assert_eq!(stats.max_entries, 5000);
    }

    #[test]
    fn test_no_cache_properties() {
        let (db, _dir) = create_test_db();
        assert!(!db.has_utxo_cache());
        assert!(db.utxo_cache_stats().is_none());
    }

    #[test]
    fn test_enable_utxo_cache_after_open() {
        let (mut db, _dir) = create_test_db();
        assert!(!db.has_utxo_cache());

        db.enable_utxo_cache(2000);
        assert!(db.has_utxo_cache());

        let stats = db.utxo_cache_stats().unwrap();
        assert_eq!(stats.max_entries, 2000);
    }

    // ================================================================
    // BatchedUtxoWriter
    // ================================================================

    #[test]
    fn test_batched_utxo_writer_basic() {
        let (db, _dir) = create_test_db();

        let mut batch = BatchedUtxoWriter::new();
        assert!(batch.is_empty());

        let (op1, u1) = make_utxo(1_000);
        let (op2, u2) = make_utxo(2_000);
        let (op3, _u3) = make_utxo(3_000);

        batch.add(op1, u1.clone());
        batch.add(op2, u2.clone());
        batch.remove(op3);

        assert_eq!(batch.add_count(), 2);
        assert_eq!(batch.remove_count(), 1);
        assert!(!batch.is_empty());

        // Flush batch
        db.flush_utxo_batch(&batch).unwrap();

        // Both adds should be stored
        assert!(db.has_utxo(&op1).unwrap());
        assert!(db.has_utxo(&op2).unwrap());
        assert_eq!(db.get_utxo(&op1).unwrap().unwrap().value.as_sat(), 1_000);

        // op3 was removed (was not present, so delete is no-op - just shouldn't error)
        assert!(!db.has_utxo(&op3).unwrap());
    }

    #[test]
    fn test_batched_utxo_writer_add_then_remove_in_batch() {
        let (db, _dir) = create_test_db();

        // First add a UTXO
        let (op, u) = make_utxo(5_000);
        db.add_utxo(&op, &u).unwrap();
        assert!(db.has_utxo(&op).unwrap());

        // Then remove it via batch
        let mut batch = BatchedUtxoWriter::new();
        batch.remove(op);
        db.flush_utxo_batch(&batch).unwrap();

        assert!(!db.has_utxo(&op).unwrap());
    }

    #[test]
    fn test_batched_utxo_writer_with_capacity() {
        let batch = BatchedUtxoWriter::with_capacity(10, 5);
        assert!(batch.is_empty());
        assert_eq!(batch.add_count(), 0);
        assert_eq!(batch.remove_count(), 0);
    }

    #[test]
    fn test_batched_utxo_writer_clear() {
        let mut batch = BatchedUtxoWriter::new();
        let (op, u) = make_utxo(1_000);
        batch.add(op, u);
        assert_eq!(batch.add_count(), 1);

        batch.clear();
        assert!(batch.is_empty());
        assert_eq!(batch.add_count(), 0);
    }

    #[test]
    fn test_batched_utxo_writer_with_cache() {
        let dir = tempdir().unwrap();
        let db = ChainDatabase::open_with_utxo_cache(dir.path(), 1000).unwrap();

        let mut batch = BatchedUtxoWriter::new();
        let (op1, u1) = make_utxo(10_000);
        let (op2, u2) = make_utxo(20_000);
        batch.add(op1, u1);
        batch.add(op2, u2);

        db.flush_utxo_batch(&batch).unwrap();

        // Both readable via cache-aware get
        assert_eq!(db.get_utxo(&op1).unwrap().unwrap().value.as_sat(), 10_000);
        assert_eq!(db.get_utxo(&op2).unwrap().unwrap().value.as_sat(), 20_000);
    }

    // ================================================================
    // flush_utxo_cache
    // ================================================================

    #[test]
    fn test_flush_utxo_cache_no_cache_returns_zero() {
        let (db, _dir) = create_test_db();
        let flushed = db.flush_utxo_cache().unwrap();
        assert_eq!(flushed, 0);
    }

    #[test]
    fn test_flush_utxo_cache_with_cache() {
        let dir = tempdir().unwrap();
        let db = ChainDatabase::open_with_utxo_cache(dir.path(), 1000).unwrap();

        // add_utxo writes to both DB and cache directly; flush should return 0
        // (no separately dirty entries since add_utxo bypasses cache's dirty tracking
        // by writing directly to RocksDB and then calling cache.insert which marks dirty)
        let (op, u) = make_utxo(1_000);
        db.add_utxo(&op, &u).unwrap();

        // flush_utxo_cache flushes any dirty cache entries (may be 1 since insert marks dirty)
        let _flushed = db.flush_utxo_cache().unwrap();
        // Just verify it doesn't error; flushed count depends on internal dirty state
    }

    // ================================================================
    // UTXO get with cache miss (cache enabled, value not in cache)
    // ================================================================

    #[test]
    fn test_utxo_cache_miss_falls_through_to_db() {
        let dir = tempdir().unwrap();

        // Write directly without cache
        let (op, u) = make_utxo(77_777);
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            db.add_utxo(&op, &u).unwrap();
        }

        // Reopen with cache (empty cache) - get should fall through to DB
        {
            let db = ChainDatabase::open_with_utxo_cache(dir.path(), 1000).unwrap();
            let result = db.get_utxo(&op).unwrap();
            assert!(result.is_some());
            assert_eq!(result.unwrap().value.as_sat(), 77_777);

            // Second call should hit cache
            let result2 = db.get_utxo(&op).unwrap();
            assert!(result2.is_some());
        }
    }

    #[test]
    fn test_has_utxo_cache_miss_falls_through_to_db() {
        let dir = tempdir().unwrap();
        let (op, u) = make_utxo(88_888);

        // Write without cache
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            db.add_utxo(&op, &u).unwrap();
        }

        // Reopen with cache - has_utxo should find it in DB
        {
            let db = ChainDatabase::open_with_utxo_cache(dir.path(), 1000).unwrap();
            assert!(db.has_utxo(&op).unwrap());
        }
    }

    // ================================================================
    // flush() method
    // ================================================================

    #[test]
    fn test_flush_db() {
        let (db, _dir) = create_test_db();
        // Just verify it doesn't error
        db.flush().unwrap();
    }

    // ================================================================
    // write_batch
    // ================================================================

    #[test]
    fn test_write_batch_empty() {
        let (db, _dir) = create_test_db();
        let batch = db.batch();
        db.write_batch(batch).unwrap();
    }
}
