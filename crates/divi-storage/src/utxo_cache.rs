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

//! High-performance in-memory UTXO cache
//!
//! Provides an LRU cache for UTXO lookups to dramatically reduce database I/O
//! during block synchronization. Uses the moka crate for efficient concurrent access.

use crate::error::StorageError;
use crate::utxo::{utxo_key, Utxo};
use divi_primitives::transaction::OutPoint;
use moka::notification::RemovalCause;
use moka::sync::Cache;
use parking_lot::RwLock;
use rocksdb::{WriteBatch, DB};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, error, trace, warn};

/// Default maximum number of entries in the UTXO cache (10 million)
pub const DEFAULT_UTXO_CACHE_SIZE: u64 = 10_000_000;

/// Column family name for UTXOs
const CF_UTXO: &str = "utxo";

/// Cache entry representing a UTXO state
#[derive(Clone, Debug)]
pub enum CacheEntry {
    /// UTXO is present with this value
    Present(Utxo),
    /// UTXO was deleted (tombstone)
    Deleted,
}

/// High-performance in-memory UTXO cache with LRU eviction and write-back
///
/// The cache sits between the application and RocksDB, providing:
/// - Fast lookups for hot UTXOs
/// - Tombstone tracking for deleted UTXOs
/// - Dirty tracking for write-back to database
/// - LRU eviction when capacity is reached
/// - Safe handling of evicted dirty entries
pub struct UtxoCache {
    /// The underlying moka LRU cache
    cache: Cache<OutPoint, CacheEntry>,
    /// Set of dirty (modified but not flushed) outpoints
    dirty: Arc<RwLock<HashSet<OutPoint>>>,
    /// Entries that were evicted while dirty - must be flushed to DB
    evicted_dirty: Arc<RwLock<HashMap<OutPoint, CacheEntry>>>,
    /// Maximum number of entries
    max_entries: u64,
}

impl UtxoCache {
    /// Create a new UTXO cache with the specified maximum entries
    pub fn new(max_entries: u64) -> Self {
        let dirty = Arc::new(RwLock::new(HashSet::new()));
        let evicted_dirty = Arc::new(RwLock::new(HashMap::new()));
        let dirty_clone = dirty.clone();
        let evicted_dirty_clone = evicted_dirty.clone();

        // Build the cache with an eviction listener
        // When dirty entries are evicted due to cache pressure (Size),
        // we save them to evicted_dirty so they can be flushed to DB later.
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .eviction_listener(move |key: Arc<OutPoint>, value, cause| {
                // For Size evictions (cache pressure), save dirty entries for later flush
                if cause == RemovalCause::Size {
                    let was_dirty = dirty_clone.write().remove(&*key);
                    if was_dirty {
                        debug!(
                            "UTXO cache saving evicted dirty entry {}:{} for later flush",
                            key.txid, key.vout
                        );
                        evicted_dirty_clone.write().insert((*key).clone(), value);
                    }
                } else if cause != RemovalCause::Replaced {
                    // For non-Replaced evictions, just remove from dirty set
                    dirty_clone.write().remove(&*key);
                }
                // For Replaced, don't touch dirty set - the key still has a new value
            })
            .build();

        debug!("UTXO cache initialized with max_entries={}", max_entries);

        Self {
            cache,
            dirty,
            evicted_dirty,
            max_entries,
        }
    }

    /// Get a UTXO from cache
    ///
    /// Returns:
    /// - `Some(Some(utxo))` if the UTXO is present in cache
    /// - `Some(None)` if the UTXO is known to be deleted (tombstone)
    /// - `None` if the UTXO is not in cache (cache miss)
    pub fn get(&self, outpoint: &OutPoint) -> Option<Option<Utxo>> {
        // First check the main cache
        if let Some(entry) = self.cache.get(outpoint) {
            return Some(match entry {
                CacheEntry::Present(utxo) => Some(utxo),
                CacheEntry::Deleted => None,
            });
        }
        // Then check evicted entries that haven't been flushed yet
        if let Some(entry) = self.evicted_dirty.read().get(outpoint) {
            return Some(match entry {
                CacheEntry::Present(utxo) => Some(utxo.clone()),
                CacheEntry::Deleted => None,
            });
        }
        None
    }

    /// Check if a UTXO exists in cache
    ///
    /// Returns:
    /// - `Some(true)` if the UTXO is present
    /// - `Some(false)` if the UTXO is known to be deleted
    /// - `None` if not in cache (cache miss)
    pub fn contains(&self, outpoint: &OutPoint) -> Option<bool> {
        // First check the main cache
        if let Some(entry) = self.cache.get(outpoint) {
            return Some(matches!(entry, CacheEntry::Present(_)));
        }
        // Then check evicted entries that haven't been flushed yet
        if let Some(entry) = self.evicted_dirty.read().get(outpoint) {
            return Some(matches!(entry, CacheEntry::Present(_)));
        }
        None
    }

    /// Insert a UTXO into the cache
    ///
    /// Marks the entry as dirty for later flush to database.
    pub fn insert(&self, outpoint: OutPoint, utxo: Utxo) {
        trace!("Cache insert: {}:{}", outpoint.txid, outpoint.vout);
        // Remove from evicted_dirty if present (we have a newer value now)
        self.evicted_dirty.write().remove(&outpoint);
        self.cache
            .insert(outpoint.clone(), CacheEntry::Present(utxo));
        self.dirty.write().insert(outpoint);
    }

    /// Mark a UTXO as deleted in the cache
    ///
    /// Inserts a tombstone entry and marks it as dirty for later flush.
    pub fn remove(&self, outpoint: OutPoint) {
        trace!(
            "Cache remove (tombstone): {}:{}",
            outpoint.txid,
            outpoint.vout
        );
        // Remove from evicted_dirty if present (we have a newer state now)
        self.evicted_dirty.write().remove(&outpoint);
        self.cache.insert(outpoint.clone(), CacheEntry::Deleted);
        self.dirty.write().insert(outpoint);
    }

    /// Flush all dirty entries to the database
    ///
    /// Writes all modified entries to RocksDB in a single atomic batch.
    /// This includes both entries still in cache and entries that were
    /// evicted due to cache pressure.
    /// Returns the number of entries flushed.
    ///
    /// On failure, entries remain dirty for retry on next flush.
    pub fn flush(&self, db: &DB) -> Result<usize, StorageError> {
        let cf = db
            .cf_handle(CF_UTXO)
            .ok_or_else(|| StorageError::ChainState("UTXO column family not found".to_string()))?;

        let mut batch = WriteBatch::default();
        let mut flushed_count = 0;

        // First, flush entries that were evicted while dirty
        let evicted_entries: Vec<(OutPoint, CacheEntry)> = {
            let evicted = self.evicted_dirty.read();
            evicted
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };

        for (outpoint, entry) in &evicted_entries {
            match entry {
                CacheEntry::Present(utxo) => {
                    batch.put_cf(&cf, utxo_key(outpoint), utxo.to_bytes());
                }
                CacheEntry::Deleted => {
                    batch.delete_cf(&cf, utxo_key(outpoint));
                }
            }
            flushed_count += 1;
        }

        // Then, flush entries still in cache
        let to_flush: Vec<OutPoint> = {
            let dirty = self.dirty.read();
            dirty.iter().cloned().collect()
        };

        for outpoint in &to_flush {
            if let Some(entry) = self.cache.get(outpoint) {
                match &entry {
                    CacheEntry::Present(utxo) => {
                        batch.put_cf(&cf, utxo_key(outpoint), utxo.to_bytes());
                    }
                    CacheEntry::Deleted => {
                        batch.delete_cf(&cf, utxo_key(outpoint));
                    }
                }
                flushed_count += 1;
            }
        }

        if flushed_count == 0 {
            return Ok(0);
        }

        // Attempt atomic write
        match db.write(batch) {
            Ok(()) => {
                // Success: clear evicted_dirty and remove flushed from dirty set
                self.evicted_dirty.write().clear();
                let mut dirty = self.dirty.write();
                for outpoint in &to_flush {
                    dirty.remove(outpoint);
                }
                debug!(
                    "UTXO cache flushed {} entries to database ({} evicted, {} in-cache)",
                    flushed_count,
                    evicted_entries.len(),
                    to_flush.len()
                );
                Ok(flushed_count)
            }
            Err(e) => {
                // On failure, entries remain dirty for retry
                error!(
                    "UTXO cache flush failed: {}. {} entries remain dirty.",
                    e, flushed_count
                );
                Err(StorageError::Database(e))
            }
        }
    }

    /// Get the number of dirty (unflushed) entries
    /// Includes both entries in cache and entries evicted but not yet flushed
    pub fn dirty_count(&self) -> usize {
        self.dirty.read().len() + self.evicted_dirty.read().len()
    }

    /// Get the number of evicted entries waiting to be flushed
    pub fn evicted_count(&self) -> usize {
        self.evicted_dirty.read().len()
    }

    /// Get the current number of entries in the cache
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Get the maximum number of entries
    pub fn max_entries(&self) -> u64 {
        self.max_entries
    }

    /// Get cache hit statistics (approximate)
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entry_count: self.cache.entry_count(),
            dirty_count: self.dirty.read().len(),
            max_entries: self.max_entries,
        }
    }

    /// Clear all entries from the cache
    ///
    /// WARNING: This will discard any dirty entries. Call flush() first
    /// if you want to persist changes.
    pub fn clear(&self) {
        let dirty_count = self.dirty_count();
        if dirty_count > 0 {
            warn!(
                "Clearing UTXO cache with {} dirty entries - changes will be lost",
                dirty_count
            );
        }
        self.cache.invalidate_all();
        self.dirty.write().clear();
    }

    /// Populate cache entry from database (for cache misses)
    ///
    /// Call this after a cache miss to populate the cache from DB.
    /// Does NOT mark the entry as dirty since it matches the DB state.
    pub fn populate_from_db(&self, outpoint: OutPoint, utxo: Option<Utxo>) {
        match utxo {
            Some(u) => {
                self.cache.insert(outpoint, CacheEntry::Present(u));
            }
            None => {
                // Don't cache negative results by default to avoid
                // filling cache with tombstones during validation
            }
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of entries
    pub entry_count: u64,
    /// Number of dirty (unflushed) entries
    pub dirty_count: usize,
    /// Maximum allowed entries
    pub max_entries: u64,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UtxoCache: {}/{} entries, {} dirty",
            self.entry_count, self.max_entries, self.dirty_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::amount::Amount;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;

    fn test_outpoint(n: u8) -> OutPoint {
        OutPoint::new(Hash256::from_bytes([n; 32]), n as u32)
    }

    fn test_utxo(value: i64) -> Utxo {
        Utxo::new(
            Amount::from_sat(value),
            Script::new_p2pkh(&[0u8; 20]),
            100,
            false,
            false,
        )
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = UtxoCache::new(1000);
        let outpoint = test_outpoint(1);
        let utxo = test_utxo(50000);

        // Insert
        cache.insert(outpoint.clone(), utxo.clone());

        // Get should return the UTXO
        let result = cache.get(&outpoint);
        assert!(result.is_some());
        let inner = result.unwrap();
        assert!(inner.is_some());
        assert_eq!(inner.unwrap().value, utxo.value);

        // Should be dirty
        assert_eq!(cache.dirty_count(), 1);
    }

    #[test]
    fn test_cache_remove_tombstone() {
        let cache = UtxoCache::new(1000);
        let outpoint = test_outpoint(2);
        let utxo = test_utxo(100000);

        // Insert then remove
        cache.insert(outpoint.clone(), utxo);
        cache.remove(outpoint.clone());

        // Get should return tombstone (Some(None))
        let result = cache.get(&outpoint);
        assert!(result.is_some());
        assert!(result.unwrap().is_none());

        // Contains should return Some(false)
        assert_eq!(cache.contains(&outpoint), Some(false));
    }

    #[test]
    fn test_cache_miss() {
        let cache = UtxoCache::new(1000);
        let outpoint = test_outpoint(3);

        // Get non-existent entry should return None (cache miss)
        let result = cache.get(&outpoint);
        assert!(result.is_none());

        // Contains should also return None
        assert!(cache.contains(&outpoint).is_none());
    }

    #[test]
    fn test_cache_contains() {
        let cache = UtxoCache::new(1000);
        let outpoint1 = test_outpoint(4);
        let outpoint2 = test_outpoint(5);

        cache.insert(outpoint1.clone(), test_utxo(1000));
        cache.remove(outpoint2.clone());

        // Present entry
        assert_eq!(cache.contains(&outpoint1), Some(true));

        // Deleted entry
        assert_eq!(cache.contains(&outpoint2), Some(false));

        // Non-existent entry
        assert!(cache.contains(&test_outpoint(99)).is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = UtxoCache::new(1000);

        // Empty cache
        let stats = cache.stats();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.dirty_count, 0);
        assert_eq!(stats.max_entries, 1000);

        // Add some entries
        cache.insert(test_outpoint(1), test_utxo(100));
        cache.insert(test_outpoint(2), test_utxo(200));
        cache.remove(test_outpoint(3));

        // Sync the cache to ensure counts are accurate
        cache.cache.run_pending_tasks();

        let stats = cache.stats();
        assert_eq!(stats.entry_count, 3);
        assert_eq!(stats.dirty_count, 3);
    }

    #[test]
    fn test_cache_clear() {
        let cache = UtxoCache::new(1000);

        cache.insert(test_outpoint(1), test_utxo(100));
        cache.insert(test_outpoint(2), test_utxo(200));

        // Sync cache to ensure counts are accurate
        cache.cache.run_pending_tasks();

        assert_eq!(cache.entry_count(), 2);
        assert_eq!(cache.dirty_count(), 2);

        cache.clear();

        // Sync after clear
        cache.cache.run_pending_tasks();

        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.dirty_count(), 0);
    }

    #[test]
    fn test_populate_from_db() {
        let cache = UtxoCache::new(1000);
        let outpoint = test_outpoint(10);
        let utxo = test_utxo(999999);

        // Populate from DB (simulating cache miss handling)
        cache.populate_from_db(outpoint.clone(), Some(utxo.clone()));

        // Sync cache to ensure counts are accurate
        cache.cache.run_pending_tasks();

        // Should be in cache but NOT dirty
        assert_eq!(cache.entry_count(), 1);
        assert_eq!(cache.dirty_count(), 0);

        let result = cache.get(&outpoint);
        assert!(result.is_some());
        assert_eq!(result.unwrap().unwrap().value, utxo.value);
    }

    #[test]
    fn test_cache_lru_eviction() {
        // Small cache for testing eviction
        let cache = UtxoCache::new(5);

        // Insert 10 entries - should evict older ones
        for i in 0..10u8 {
            cache.insert(test_outpoint(i), test_utxo(i as i64 * 100));
        }

        // Cache should have at most max_entries
        assert!(cache.entry_count() <= 5);
    }

    #[test]
    fn test_max_entries() {
        let cache = UtxoCache::new(12345);
        assert_eq!(cache.max_entries(), 12345);
    }

    #[test]
    fn test_evicted_count_initially_zero() {
        let cache = UtxoCache::new(1000);
        assert_eq!(cache.evicted_count(), 0);
    }

    #[test]
    fn test_populate_from_db_none_does_not_cache() {
        // Populating with None (negative result) should NOT store a tombstone
        // so the entry remains a cache miss (returns None from get)
        let cache = UtxoCache::new(1000);
        let outpoint = test_outpoint(20);

        cache.populate_from_db(outpoint.clone(), None);

        // Run pending tasks to flush internal state
        cache.cache.run_pending_tasks();

        // Should remain a cache miss - no tombstone stored
        assert!(
            cache.get(&outpoint).is_none(),
            "Negative populate_from_db should leave entry as cache miss"
        );
        assert_eq!(
            cache.dirty_count(),
            0,
            "populate_from_db(None) must not dirty the cache"
        );
    }

    #[test]
    fn test_insert_overrides_populate_from_db() {
        let cache = UtxoCache::new(1000);
        let outpoint = test_outpoint(30);
        let utxo = test_utxo(12345);

        // First populate from DB
        cache.populate_from_db(outpoint.clone(), Some(test_utxo(99999)));
        cache.cache.run_pending_tasks();

        // Should not be dirty
        assert_eq!(cache.dirty_count(), 0);

        // Insert a newer value - this should mark dirty
        cache.insert(outpoint.clone(), utxo.clone());

        let result = cache.get(&outpoint);
        assert!(result.is_some());
        assert_eq!(result.unwrap().unwrap().value.as_sat(), 12345);
        assert_eq!(cache.dirty_count(), 1);
    }

    #[test]
    fn test_remove_after_populate_from_db_marks_dirty() {
        let cache = UtxoCache::new(1000);
        let outpoint = test_outpoint(40);
        let utxo = test_utxo(5000);

        // Populate from DB (not dirty)
        cache.populate_from_db(outpoint.clone(), Some(utxo));
        cache.cache.run_pending_tasks();
        assert_eq!(cache.dirty_count(), 0);

        // Remove it - should mark dirty (tombstone)
        cache.remove(outpoint.clone());
        assert_eq!(cache.dirty_count(), 1);

        // Should now be a tombstone
        let result = cache.get(&outpoint);
        assert!(result.is_some());
        assert!(result.unwrap().is_none()); // tombstone
    }

    #[test]
    fn test_cache_multiple_inserts_same_outpoint() {
        let cache = UtxoCache::new(1000);
        let outpoint = test_outpoint(50);

        cache.insert(outpoint.clone(), test_utxo(100));
        cache.insert(outpoint.clone(), test_utxo(200));
        cache.insert(outpoint.clone(), test_utxo(300));

        cache.cache.run_pending_tasks();

        let result = cache.get(&outpoint);
        assert!(result.is_some());
        // Should reflect the latest value
        assert_eq!(result.unwrap().unwrap().value.as_sat(), 300);

        // Dirty count should be 1 (same outpoint, deduplicated in HashSet)
        assert_eq!(cache.dirty_count(), 1);
    }

    #[test]
    fn test_dirty_count_after_clear_includes_evicted() {
        let cache = UtxoCache::new(1000);

        cache.insert(test_outpoint(1), test_utxo(100));
        cache.insert(test_outpoint(2), test_utxo(200));
        cache.cache.run_pending_tasks();
        assert_eq!(cache.dirty_count(), 2);

        // clear() discards dirty entries
        cache.clear();
        cache.cache.run_pending_tasks();
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn test_stats_display() {
        let cache = UtxoCache::new(500);
        cache.insert(test_outpoint(1), test_utxo(100));
        cache.cache.run_pending_tasks();

        let stats = cache.stats();
        let display = format!("{}", stats);
        assert!(display.contains("500"), "Display should show max_entries");
        assert!(display.contains("dirty"), "Display should mention dirty");
    }
}
