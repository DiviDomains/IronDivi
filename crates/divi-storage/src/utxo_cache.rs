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

//! High-performance in-memory UTXO cache
//!
//! Provides an LRU cache for UTXO lookups to dramatically reduce database I/O
//! during block synchronization. Uses the moka crate for efficient concurrent access.
//!
//! # Ownership and coherence (C3)
//!
//! RocksDB owns the durable UTXO set. The cache holds two kinds of entry:
//!
//! * **Clean** entries, equal to what RocksDB holds. They are put there by a
//!   *write-through* ([`UtxoCache::write_through`]: the database write and the
//!   cache update happen as one serialized step) or by a *validated fill*
//!   ([`UtxoCache::fill_ticket`] + [`UtxoCache::fill`]) after a cache miss.
//!   `ChainDatabase` only ever creates clean entries.
//! * **Dirty** entries ([`UtxoCache::insert`] / [`UtxoCache::remove`], the
//!   standalone write-back use), newer than RocksDB until [`UtxoCache::flush`]
//!   writes them. They live in their own map, outside the LRU, so eviction can
//!   never drop or reorder unflushed data.
//!
//! Every mutation (write-through, write-back, flush, clear) holds `gate`, so
//! the order in which the database is written is the order in which the cache
//! changes, and a flush can never interleave with a write-through and put an
//! older value back over a newer one. Each mutation also moves `seq` to an odd
//! value before it touches the database and back to even when it is done. A
//! fill records `seq` before its database read and is accepted only if, under
//! `fill_lock` (which a mutation holds while it changes cache contents), `seq`
//! is still that same even value: no mutation began, was in flight, or ended
//! between the read and the fill, so the value read is the current one. A
//! stale read can therefore never be cached, whatever the interleaving with
//! writers, flushes or eviction.

use crate::error::StorageError;
use crate::utxo::{utxo_key, Utxo};
use divi_primitives::transaction::OutPoint;
use moka::sync::Cache;
use parking_lot::{Mutex, RwLock};
use rocksdb::{WriteBatch, DB};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
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

impl CacheEntry {
    fn from_option(utxo: Option<Utxo>) -> Self {
        match utxo {
            Some(u) => CacheEntry::Present(u),
            None => CacheEntry::Deleted,
        }
    }

    fn into_option(self) -> Option<Utxo> {
        match self {
            CacheEntry::Present(u) => Some(u),
            CacheEntry::Deleted => None,
        }
    }
}

/// The mutation sequence number observed before a cache-miss database read.
/// Pass it to [`UtxoCache::fill`] with the value read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FillTicket(u64);

#[cfg(test)]
pub(crate) type SchedHook = Arc<dyn Fn() + Send + Sync>;

/// High-performance in-memory UTXO cache with LRU eviction
///
/// See the module documentation for the ownership and coherence rules.
pub struct UtxoCache {
    /// The underlying moka LRU cache (clean entries and copies of dirty ones)
    cache: Cache<OutPoint, CacheEntry>,
    /// Write-back entries not yet written to the database. Never evicted.
    /// Changed only while `gate` is held.
    dirty: RwLock<HashMap<OutPoint, CacheEntry>>,
    /// Serializes every mutation of the cache and every database write made
    /// through it
    gate: Mutex<()>,
    /// Held by a mutation while it changes cache contents and by a fill while
    /// it validates its ticket and inserts
    fill_lock: Mutex<()>,
    /// Even: no mutation in flight. Odd: a mutation is in flight. Bumped twice
    /// by every mutation.
    seq: AtomicU64,
    /// Maximum number of entries
    max_entries: u64,
    /// Test-only scheduling points (see `sched_point`)
    #[cfg(test)]
    hooks: Mutex<HashMap<&'static str, SchedHook>>,
}

/// One mutation in flight: `seq` is odd while it lives. Dropping it makes
/// `seq` even again; if the mutation did not settle (it unwound), the touched
/// outpoints are dropped from memory so the database is read again.
struct Mutation<'a> {
    owner: &'a UtxoCache,
    keys: Vec<OutPoint>,
    settled: bool,
}

impl Drop for Mutation<'_> {
    fn drop(&mut self) {
        if !self.settled {
            let _fill = self.owner.fill_lock.lock();
            let mut dirty = self.owner.dirty.write();
            for key in &self.keys {
                self.owner.cache.invalidate(key);
                dirty.remove(key);
            }
        }
        self.owner.seq.fetch_add(1, Ordering::SeqCst);
    }
}

impl UtxoCache {
    /// Create a new UTXO cache with the specified maximum entries
    pub fn new(max_entries: u64) -> Self {
        let cache = Cache::builder().max_capacity(max_entries).build();

        debug!("UTXO cache initialized with max_entries={}", max_entries);

        Self {
            cache,
            dirty: RwLock::new(HashMap::new()),
            gate: Mutex::new(()),
            fill_lock: Mutex::new(()),
            seq: AtomicU64::new(0),
            max_entries,
            #[cfg(test)]
            hooks: Mutex::new(HashMap::new()),
        }
    }

    /// Start a mutation. The caller must hold `gate`, and must declare the
    /// gate guard before the returned value so the mutation ends first.
    fn begin(&self, keys: Vec<OutPoint>) -> Mutation<'_> {
        self.seq.fetch_add(1, Ordering::SeqCst);
        Mutation {
            owner: self,
            keys,
            settled: false,
        }
    }

    /// Get a UTXO from cache
    ///
    /// Returns:
    /// - `Some(Some(utxo))` if the UTXO is present in cache
    /// - `Some(None)` if the UTXO is known to be deleted (tombstone)
    /// - `None` if the UTXO is not in cache (cache miss)
    pub fn get(&self, outpoint: &OutPoint) -> Option<Option<Utxo>> {
        if let Some(entry) = self.cache.get(outpoint) {
            return Some(entry.into_option());
        }
        // A dirty entry the LRU evicted is still here until flushed
        if let Some(entry) = self.dirty.read().get(outpoint) {
            return Some(entry.clone().into_option());
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
        self.get(outpoint).map(|u| u.is_some())
    }

    /// Write `changes` (`Some` = present with that value, `None` = deleted) to
    /// the database with `db_write` and update the cache to match, as one step
    /// ordered against every other mutation of this cache.
    ///
    /// `db_write` must perform the whole durable write (one RocksDB write or
    /// `WriteBatch`); it runs with the mutation gate held, so it must not call
    /// back into this cache's writers. If it fails the database is unchanged
    /// and so is the cache. If it panics the touched outpoints are dropped
    /// from the cache. A write-through overlapping pending write-back entries is rejected before
    /// invoking the closure. Flush those entries before mixing write modes.
    pub fn write_through<R>(
        &self,
        changes: Vec<(OutPoint, Option<Utxo>)>,
        db_write: impl FnOnce() -> Result<R, StorageError>,
    ) -> Result<R, StorageError> {
        let _gate = self.gate.lock();
        // Do not discard pending work if an arbitrary writer unwinds with an
        // unknown commit outcome. Refuse mixed ownership before invoking it.
        if changes.iter().any(|(key, _)| self.dirty.read().contains_key(key)) {
            return Err(StorageError::ChainState(
                "flush pending UTXO write-back entries before write-through".into(),
            ));
        }
        let mut mutation = self.begin(changes.iter().map(|(k, _)| *k).collect());
        let result = db_write();
        if result.is_ok() {
            self.sched_point("utxo write-through applied");
            let _fill = self.fill_lock.lock();
            let mut dirty = self.dirty.write();
            for (outpoint, utxo) in changes {
                dirty.remove(&outpoint);
                self.cache.insert(outpoint, CacheEntry::from_option(utxo));
            }
        }
        mutation.settled = true;
        result
    }

    /// Record the mutation sequence before a cache-miss database read
    pub fn fill_ticket(&self) -> FillTicket {
        FillTicket(self.seq.load(Ordering::SeqCst))
    }

    /// Cache `utxo`, read from the database after `ticket` was taken, unless
    /// any mutation was in flight when the ticket was taken or has begun since
    /// (the value may then be stale). Negative results are not cached.
    /// Returns whether the value was cached.
    pub fn fill(&self, ticket: FillTicket, outpoint: OutPoint, utxo: Option<Utxo>) -> bool {
        let Some(utxo) = utxo else {
            return false;
        };
        if ticket.0 & 1 == 1 {
            return false;
        }
        let _fill = self.fill_lock.lock();
        if self.seq.load(Ordering::SeqCst) != ticket.0 {
            return false;
        }
        if self.dirty.read().contains_key(&outpoint) {
            return false;
        }
        self.cache.insert(outpoint, CacheEntry::Present(utxo));
        true
    }

    /// Insert a UTXO into the cache (write-back)
    ///
    /// Marks the entry as dirty for later flush to database.
    pub fn insert(&self, outpoint: OutPoint, utxo: Utxo) {
        trace!("Cache insert: {}:{}", outpoint.txid, outpoint.vout);
        self.write_back(outpoint, CacheEntry::Present(utxo));
    }

    /// Mark a UTXO as deleted in the cache (write-back)
    ///
    /// Inserts a tombstone entry and marks it as dirty for later flush.
    pub fn remove(&self, outpoint: OutPoint) {
        trace!(
            "Cache remove (tombstone): {}:{}",
            outpoint.txid,
            outpoint.vout
        );
        self.write_back(outpoint, CacheEntry::Deleted);
    }

    fn write_back(&self, outpoint: OutPoint, entry: CacheEntry) {
        let _gate = self.gate.lock();
        let mut mutation = self.begin(Vec::new());
        {
            let _fill = self.fill_lock.lock();
            self.dirty.write().insert(outpoint, entry.clone());
            self.cache.insert(outpoint, entry);
        }
        mutation.settled = true;
    }

    /// Flush all dirty entries to the database
    ///
    /// Writes every dirty entry to RocksDB in a single atomic batch. The gate
    /// is held from the snapshot of the dirty entries until they are cleared,
    /// so no write can land in between: what is written is the newest value of
    /// each outpoint, and only what was written is cleared.
    /// Returns the number of entries flushed.
    ///
    /// On failure, entries remain dirty for retry on next flush.
    pub fn flush(&self, db: &DB) -> Result<usize, StorageError> {
        let cf = db
            .cf_handle(CF_UTXO)
            .ok_or_else(|| StorageError::ChainState("UTXO column family not found".to_string()))?;

        let _gate = self.gate.lock();
        let entries: Vec<(OutPoint, CacheEntry)> = self
            .dirty
            .read()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        if entries.is_empty() {
            return Ok(0);
        }
        let mut mutation = self.begin(Vec::new());
        // The cache contents do not change; nothing to undo on any exit
        mutation.settled = true;

        let mut batch = WriteBatch::default();
        for (outpoint, entry) in &entries {
            match entry {
                CacheEntry::Present(utxo) => {
                    batch.put_cf(&cf, utxo_key(outpoint), utxo.to_bytes());
                }
                CacheEntry::Deleted => {
                    batch.delete_cf(&cf, utxo_key(outpoint));
                }
            }
        }

        self.sched_point("utxo flush");
        // A test can stop here, as if the write failed after the batch was
        // built; every entry stays dirty for the retry. Nothing outside test
        // builds (see `fault`).
        stop_point!("utxo flush");

        match db.write(batch) {
            Ok(()) => {
                // The gate was held throughout: the dirty map is exactly the
                // snapshot just written
                self.dirty.write().clear();
                debug!("UTXO cache flushed {} entries to database", entries.len());
                Ok(entries.len())
            }
            Err(e) => {
                error!(
                    "UTXO cache flush failed: {}. {} entries remain dirty.",
                    e,
                    entries.len()
                );
                Err(StorageError::Database(e))
            }
        }
    }

    /// Get the number of dirty (unflushed) entries
    pub fn dirty_count(&self) -> usize {
        self.dirty.read().len()
    }

    /// Get the number of dirty entries the LRU has evicted, still waiting to
    /// be flushed
    pub fn evicted_count(&self) -> usize {
        self.dirty
            .read()
            .keys()
            .filter(|k| !self.cache.contains_key(*k))
            .count()
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
            dirty_count: self.dirty_count(),
            max_entries: self.max_entries,
        }
    }

    /// Clear all entries from the cache
    ///
    /// WARNING: This will discard any dirty entries. Call flush() first
    /// if you want to persist changes.
    pub fn clear(&self) {
        let _gate = self.gate.lock();
        let dirty_count = self.dirty_count();
        if dirty_count > 0 {
            warn!(
                "Clearing UTXO cache with {} dirty entries - changes will be lost",
                dirty_count
            );
        }
        let mut mutation = self.begin(Vec::new());
        {
            let _fill = self.fill_lock.lock();
            self.cache.invalidate_all();
            self.dirty.write().clear();
        }
        mutation.settled = true;
    }

    /// A point where a test can run code (for example, block until another
    /// thread has acted) to force one interleaving; nothing outside tests
    #[inline]
    pub(crate) fn sched_point(&self, point: &'static str) {
        #[cfg(test)]
        {
            let hook = self.hooks.lock().get(point).cloned();
            if let Some(hook) = hook {
                hook();
            }
        }
        let _ = point;
    }

    /// Run `hook` whenever `point` is reached (None removes it)
    #[cfg(test)]
    pub(crate) fn set_sched_hook(&self, point: &'static str, hook: Option<SchedHook>) {
        let mut hooks = self.hooks.lock();
        match hook {
            Some(h) => {
                hooks.insert(point, h);
            }
            None => {
                hooks.remove(point);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks();
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
mod tests;
