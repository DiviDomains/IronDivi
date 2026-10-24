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

//! Transaction mempool
//!
//! Manages unconfirmed transactions waiting to be included in blocks.

use crate::config::MempoolConfig;
use crate::error::{reject, NodeError};
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::{OutPoint, Transaction};
use parking_lot::RwLock;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Transaction entry in the mempool
#[derive(Clone)]
pub struct MempoolEntry {
    /// The transaction
    pub tx: Transaction,

    /// Transaction ID
    pub txid: Hash256,

    /// Time added to mempool
    pub time: Instant,

    /// Fee in satoshis
    pub fee: Amount,

    /// Transaction size in bytes
    pub size: usize,

    /// Fee rate (satoshis per byte)
    pub fee_rate: f64,

    /// Ancestors (transactions this depends on)
    pub ancestors: HashSet<Hash256>,

    /// Descendants (transactions that depend on this)
    pub descendants: HashSet<Hash256>,

    /// Chain tip height when the transaction entered the pool
    pub height: u32,

    /// Coin age of the inputs per byte when it entered (Divi Core's
    /// `initialCoinAgePerByteOfInputs`, MemPoolEntry.cpp:43)
    pub starting_priority: f64,

    /// Size counted for priority (Divi Core `CalculateModifiedSize`)
    pub mod_size: usize,
}

impl MempoolEntry {
    /// Create a new mempool entry
    pub fn new(tx: Transaction, fee: Amount) -> Self {
        let txid = tx.txid();
        let size = tx.size();
        let fee_rate = fee.as_sat() as f64 / size as f64;

        let mod_size = modified_size(&tx, size);
        MempoolEntry {
            tx,
            txid,
            time: Instant::now(),
            fee,
            size,
            fee_rate,
            ancestors: HashSet::new(),
            descendants: HashSet::new(),
            height: 0,
            starting_priority: 0.0,
            mod_size,
        }
    }

    /// The entry as Divi Core makes it (MempoolConsensus.cpp:384-386): the tip
    /// height and the coin age of the inputs there (`ComputeInputCoinAge`)
    pub fn with_coin_age(mut self, height: u32, coin_age: f64) -> Self {
        self.height = height;
        self.starting_priority = if self.mod_size > 0 {
            coin_age / self.mod_size as f64
        } else {
            0.0
        };
        self
    }

    /// Divi Core `ComputeInputCoinAgePerByte` (MemPoolEntry.cpp:52-57): the
    /// starting priority plus the value in aged by the blocks since entry.
    /// Core subtracts unsigned heights, which wraps below the entry height
    /// after a reorganisation; here that counts as no blocks since entry.
    pub fn priority_at(&self, height: u32) -> f64 {
        if self.mod_size == 0 {
            return self.starting_priority;
        }
        let value_out: i64 = self.tx.vout.iter().map(|o| o.value.as_sat()).sum();
        let value_in = value_out + self.fee.as_sat();
        self.starting_priority
            + height.saturating_sub(self.height) as f64 * value_in as f64 / self.mod_size as f64
    }

    /// Get age of the entry
    pub fn age(&self) -> Duration {
        self.time.elapsed()
    }
}

/// A pool transaction as block assembly weighs it (Divi Core
/// BlockMemoryPoolTransactionCollector.cpp:122-147)
#[derive(Debug, Clone)]
pub struct BlockCandidate {
    pub tx: Transaction,
    pub txid: Hash256,
    pub size: usize,
    /// Fee the transaction pays
    pub fee: Amount,
    /// Coin age per byte at the block's height, plus the prioritisetransaction
    /// priority delta (`ComputeInputCoinAgePerByte`, `ApplyDeltas`)
    pub priority: f64,
    /// The fee plus the fee delta per 1,000 bytes, truncated as `CFeeRate`
    /// keeps it (FeeRate.cpp:27-33)
    pub fee_rate_per_kb: i64,
    /// Given a delta with prioritisetransaction
    /// (`CTxMemPool::IsPrioritizedTransaction`, txmempool.cpp:330-336)
    pub prioritised: bool,
    /// Pool transactions it spends, which must be in the block before it
    pub parents: Vec<Hash256>,
}

/// Entry for priority queue ordering by fee rate
struct PriorityEntry {
    _txid: Hash256,
    fee_rate: f64,
}

impl PartialEq for PriorityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.fee_rate == other.fee_rate
    }
}

impl Eq for PriorityEntry {}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher fee rate = higher priority
        self.fee_rate
            .partial_cmp(&other.fee_rate)
            .unwrap_or(Ordering::Equal)
    }
}

/// Listener notified when a transaction enters or leaves the mempool
pub type MempoolListener = Arc<dyn Fn(&Transaction) + Send + Sync>;

/// Returns the current chain tip height
pub type TipHeightProvider = Arc<dyn Fn() -> u32 + Send + Sync>;

/// Divi Core `IsFinalTx` as used by the mempool (MempoolConsensus.cpp): a height
/// lock is compared with the next block's height and a time lock with the
/// current time.
pub fn is_final_for_next_block(tx: &Transaction, tip_height: u32, now: u32) -> bool {
    tx.is_final(tip_height.saturating_add(1), now)
}

fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Checks a transaction against the chain before it may enter the mempool and
/// returns its fee; see [`Mempool::set_validator`]. The flag is Core's
/// `fLimitFree`: true for a transaction a peer relayed.
pub type MempoolValidator =
    Arc<dyn Fn(&Mempool, &Transaction, bool) -> Result<Admission, NodeError> + Send + Sync>;

/// What the checks found for a transaction entering the pool: its fee, the
/// chain tip height and the coin age of its inputs there (Divi Core
/// `CCoinsViewCache::ComputeInputCoinAge`)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Admission {
    pub fee: Amount,
    pub height: u32,
    pub coin_age: f64,
}

/// Divi Core `DEFAULT_BLOCK_PRIORITY_SIZE` (defaultValues.h:50)
pub const DEFAULT_BLOCK_PRIORITY_SIZE: usize = 50_000;

/// Divi Core `-limitfreerelay` default (MempoolConsensus.cpp:228), thousands of
/// bytes per minute
const LIMIT_FREE_RELAY: f64 = 30.0;

/// Divi Core `CTxMemPoolEntry::AllowFreeThreshold` (MemPoolEntry.h:18-21)
const ALLOW_FREE_THRESHOLD: f64 = (100_000_000i64 * 1440 / 250) as f64;

/// Divi Core `CTxMemPoolEntry::AllowFree` (MemPoolEntry.h:35-40): inputs old and
/// large enough for the transaction to go without the relay fee
pub fn allow_free(coin_age_per_byte: f64) -> bool {
    coin_age_per_byte > ALLOW_FREE_THRESHOLD
}

/// Divi Core `CalculateModifiedSize` (MemPoolEntry.cpp:8-22): the size used for
/// priority, without each input's overhead and up to 110 bytes of its scriptSig
pub fn modified_size(tx: &Transaction, size: usize) -> usize {
    let mut size = size;
    for input in &tx.vin {
        let offset = 41 + input.script_sig.len().min(110);
        if size > offset {
            size -= offset;
        }
    }
    size
}

/// Transaction mempool
pub struct Mempool {
    /// Configuration
    config: MempoolConfig,

    /// All transactions indexed by txid
    txs: RwLock<HashMap<Hash256, MempoolEntry>>,

    /// Transactions ordered by fee rate
    priority_queue: RwLock<BinaryHeap<PriorityEntry>>,

    /// Outpoint to spending transaction
    spenders: RwLock<HashMap<(Hash256, u32), Hash256>>,

    /// Total size of all transactions
    total_size: RwLock<usize>,

    /// Priority deltas for transactions (txid -> (priority_delta, fee_delta))
    priority_deltas: RwLock<HashMap<Hash256, (f64, i64)>>,

    /// Called after a transaction is inserted (outside any mempool lock)
    on_added: RwLock<Vec<MempoolListener>>,

    /// Called after a transaction is removed for any reason (outside any mempool lock)
    on_removed: RwLock<Option<MempoolListener>>,

    /// Chain tip height, for the finality of height-locked transactions
    tip_height: RwLock<Option<TipHeightProvider>>,
    /// Input and script checks every transaction must pass to be added
    validator: RwLock<Option<MempoolValidator>>,

    /// Divi Core's free-transaction rate limiter: decayed byte count and the
    /// time it was last updated
    free_limiter: parking_lot::Mutex<(f64, i64)>,
}

impl Mempool {
    /// Create a new mempool
    pub fn new(config: MempoolConfig) -> Self {
        Mempool {
            config,
            txs: RwLock::new(HashMap::new()),
            priority_queue: RwLock::new(BinaryHeap::new()),
            spenders: RwLock::new(HashMap::new()),
            total_size: RwLock::new(0),
            priority_deltas: RwLock::new(HashMap::new()),
            on_added: RwLock::new(Vec::new()),
            on_removed: RwLock::new(None),
            tip_height: RwLock::new(None),
            validator: RwLock::new(None),
            free_limiter: parking_lot::Mutex::new((0.0, 0)),
        }
    }

    /// The relay floor in DIVI/kB, the unit the fee RPCs report. Nothing below it
    /// is accepted, so no fee estimate may go below it (C++ `minRelayTxFee`).
    fn relay_floor_divi_per_kb(&self) -> f64 {
        self.min_relay_fee_per_kb() as f64 / 100_000_000.0
    }

    /// Register the chain tip height source used for finality checks
    pub fn set_tip_height_provider(&self, provider: TipHeightProvider) {
        *self.tip_height.write() = Some(provider);
    }

    /// Height of the chain tip. Without a provider every height lock counts as
    /// not yet reached.
    fn tip_height(&self) -> u32 {
        match self.tip_height.read().as_ref() {
            Some(provider) => provider(),
            None => 0,
        }
    }

    /// Add a listener for transactions entering the mempool
    pub fn add_added_listener(&self, listener: MempoolListener) {
        self.on_added.write().push(listener);
    }

    /// Install the checks every added transaction must pass. The node sets
    /// this once at start (Divi Core's AcceptToMemoryPool, in Core's order), so
    /// every path into the mempool is covered: RPC sends, relay, wallet
    /// resubmission and transactions re-added after a reorg. With a validator
    /// the fee is the one it computes from the inputs; the caller's is ignored.
    pub fn set_validator(&self, validator: MempoolValidator) {
        *self.validator.write() = Some(validator);
    }

    /// Register a listener for transactions leaving the mempool
    /// (confirmed, evicted, expired or explicitly removed)
    pub fn set_removed_listener(&self, listener: MempoolListener) {
        *self.on_removed.write() = Some(listener);
    }

    /// Check if a transaction is in the mempool
    pub fn contains(&self, txid: &Hash256) -> bool {
        self.txs.read().contains_key(txid)
    }

    /// Get a transaction from the mempool
    pub fn get(&self, txid: &Hash256) -> Option<MempoolEntry> {
        self.txs.read().get(txid).cloned()
    }

    /// Get all transaction IDs in the mempool
    pub fn get_txids(&self) -> Vec<Hash256> {
        self.txs.read().keys().cloned().collect()
    }

    /// Get transaction count
    pub fn size(&self) -> usize {
        self.txs.read().len()
    }

    /// Get total bytes of all transactions
    pub fn bytes(&self) -> usize {
        *self.total_size.read()
    }

    /// Add a transaction submitted locally (RPC, wallet, reorg): Divi Core's
    /// AcceptToMemoryPool with `fLimitFree` false. Policy refusals are
    /// `NodeError::TxRejected` with Divi Core's reject code and reason.
    pub fn add(&self, tx: Transaction, fee: Amount) -> Result<Hash256, NodeError> {
        self.add_with(tx, fee, false)
    }

    /// Add a transaction a peer relayed: AcceptToMemoryPool with `fLimitFree`
    /// true, so a free transaction must be small and is rate limited
    pub fn add_relayed(&self, tx: Transaction, fee: Amount) -> Result<Hash256, NodeError> {
        self.add_with(tx, fee, true)
    }

    fn add_with(
        &self,
        tx: Transaction,
        fee: Amount,
        limit_free: bool,
    ) -> Result<Hash256, NodeError> {
        let txid = tx.txid();

        // Check if already exists
        if self.contains(&txid) {
            return Ok(txid);
        }

        // Every check, in Divi Core's order (called without holding any
        // mempool lock: the validator looks up parent transactions here)
        let validator = self.validator.read().clone();
        let admission = match validator {
            Some(validator) => validator(self, &tx, limit_free)?,
            None => {
                self.check_without_chain(&tx, fee)?;
                // No chain to look the inputs up in: no coin age
                Admission {
                    fee,
                    height: self.tip_height(),
                    coin_age: 0.0,
                }
            }
        };
        let fee = admission.fee;
        let entry =
            MempoolEntry::new(tx.clone(), fee).with_coin_age(admission.height, admission.coin_age);

        // Check size limits
        let new_size = *self.total_size.read() + entry.size;
        if new_size > self.config.max_size {
            // Need to evict transactions
            self.evict_for_space(entry.size)?;
        }

        // Add to mempool
        {
            let mut txs = self.txs.write();
            let mut spenders = self.spenders.write();
            let mut total_size = self.total_size.write();

            // A conflicting transaction may have been added while the checks ran
            if txs.contains_key(&txid) {
                return Ok(txid);
            }
            if let Some(existing) = tx
                .vin
                .iter()
                .find_map(|input| spenders.get(&(input.prevout.txid, input.prevout.vout)))
            {
                return Err(conflict(existing));
            }

            // Track which outputs this transaction spends
            for input in &tx.vin {
                let outpoint = (input.prevout.txid, input.prevout.vout);
                spenders.insert(outpoint, txid);
            }

            *total_size += entry.size;
            txs.insert(txid, entry.clone());
        }

        // Add to priority queue
        self.priority_queue.write().push(PriorityEntry {
            _txid: txid,
            fee_rate: entry.fee_rate,
        });

        tracing::debug!(
            "Added tx {} to mempool (fee: {}, size: {})",
            txid,
            fee.as_sat(),
            entry.size
        );

        let listeners = self.on_added.read().clone();
        for listener in &listeners {
            listener(&entry.tx);
        }

        Ok(txid)
    }

    /// The checks made without a chain (no validator installed): finality,
    /// block-reward transactions, relay fee, dust and conflicts
    fn check_without_chain(&self, tx: &Transaction, fee: Amount) -> Result<(), NodeError> {
        if !is_final_for_next_block(tx, self.tip_height(), unix_now()) {
            return Err(NodeError::NonFinal);
        }
        if tx.is_coinbase() {
            return Err(rejected(reject::INVALID, "coinbase"));
        }
        if tx.is_coinstake() {
            return Err(rejected(reject::INVALID, "coinstake"));
        }
        if (fee.as_sat() as i128) * 1000
            < (self.min_relay_fee_per_kb() as i128) * (tx.size() as i128)
        {
            return Err(rejected(reject::INSUFFICIENT_FEE, "insufficient fee"));
        }
        let relay_fee_per_kb = self.min_relay_fee_per_kb();
        if tx.vout.iter().any(|out| out.is_dust_at(relay_fee_per_kb)) {
            return Err(rejected(reject::NONSTANDARD, "dust"));
        }
        self.check_conflicts(tx)
    }

    /// The minimum relay fee in satoshis per 1000 bytes (Core's
    /// `minimumRelayTransactionFee`)
    pub fn min_relay_fee_per_kb(&self) -> i64 {
        self.config.min_relay_fee_per_kb
    }

    /// Divi Core `CFeeRate::GetFee` (FeeRate.cpp:35-43) of the relay fee
    pub fn min_relay_fee_for(&self, size: usize) -> i64 {
        let per_kb = self.min_relay_fee_per_kb();
        let fee = per_kb * size as i64 / 1000;
        if fee == 0 && per_kb > 0 {
            per_kb
        } else {
            fee
        }
    }

    /// Divi Core AcceptToMemoryPool's conflict check: no replacement, so a
    /// transaction spending an output a mempool transaction spends is refused
    pub fn check_conflicts(&self, tx: &Transaction) -> Result<(), NodeError> {
        let spenders = self.spenders.read();
        for input in &tx.vin {
            if let Some(existing) = spenders.get(&(input.prevout.txid, input.prevout.vout)) {
                return Err(conflict(existing));
            }
        }
        Ok(())
    }

    /// Divi Core `CheckFeesPaidAreAcceptable` (MempoolConsensus.cpp:236-266) with
    /// `-relaypriority` on: below the relay fee a transaction needs enough coin
    /// age per byte (`priority`, Core's `ComputeInputCoinAgePerByte` at the next
    /// height); a relayed one (`limit_free`) must also be under 49,000 bytes
    /// unless prioritised, and free relay is rate limited.
    pub fn check_fees_paid(
        &self,
        txid: &Hash256,
        size: usize,
        fee: i64,
        priority: f64,
        limit_free: bool,
    ) -> Result<(), NodeError> {
        let min_fee = self.min_relay_fee_for(size);
        if fee >= min_fee {
            return Ok(());
        }
        let prioritised = self
            .get_priority_delta(txid)
            .is_some_and(|(priority_delta, fee_delta)| priority_delta > 0.0 || fee_delta > 0);
        if limit_free && !prioritised && size >= DEFAULT_BLOCK_PRIORITY_SIZE - 1000 {
            return Err(rejected(reject::INSUFFICIENT_FEE, "insufficient fee"));
        }
        if !allow_free(priority) {
            return Err(rejected(reject::INSUFFICIENT_FEE, "insufficient priority"));
        }
        if limit_free && !self.free_relay_allows(size) {
            return Err(rejected(
                reject::INSUFFICIENT_FEE,
                "rate limited free transaction",
            ));
        }
        Ok(())
    }

    /// Divi Core `RateLimiterAllowsFreeTransaction` (MempoolConsensus.cpp:211-234):
    /// an exponentially decaying ~10-minute window of free bytes
    fn free_relay_allows(&self, size: usize) -> bool {
        let now = unix_now() as i64;
        let mut limiter = self.free_limiter.lock();
        let (count, last) = &mut *limiter;
        *count *= (1.0 - 1.0 / 600.0f64).powf((now - *last) as f64);
        *last = now;
        if *count >= LIMIT_FREE_RELAY * 10.0 * 1000.0 {
            return false;
        }
        *count += size as f64;
        true
    }

    /// Remove a transaction from the mempool
    pub fn remove(&self, txid: &Hash256) -> Option<MempoolEntry> {
        let entry = self.txs.write().remove(txid)?;

        // Remove from spenders
        {
            let mut spenders = self.spenders.write();
            for input in &entry.tx.vin {
                let outpoint = (input.prevout.txid, input.prevout.vout);
                spenders.remove(&outpoint);
            }
        }

        // Update total size
        *self.total_size.write() -= entry.size;

        tracing::debug!("Removed tx {} from mempool", txid);

        let listener = self.on_removed.read().clone();
        if let Some(listener) = listener {
            listener(&entry.tx);
        }

        Some(entry)
    }

    /// Remove transactions that are now confirmed in a block, then any that
    /// can no longer be mined in the next block (after a reorg to a lower tip)
    pub fn remove_for_block(&self, txids: &[Hash256]) {
        for txid in txids {
            self.remove(txid);
        }
        self.remove_non_final();
    }

    /// Remove transactions that are not final for the next block, together
    /// with the mempool transactions that spend their outputs
    pub fn remove_non_final(&self) -> usize {
        let tip_height = self.tip_height();
        let now = unix_now();
        let mut to_remove: Vec<Hash256> = self
            .txs
            .read()
            .values()
            .filter(|entry| !is_final_for_next_block(&entry.tx, tip_height, now))
            .map(|entry| entry.txid)
            .collect();

        let mut removed = 0;
        while let Some(txid) = to_remove.pop() {
            if let Some(entry) = self.remove(&txid) {
                removed += 1;
                let spenders = self.spenders.read();
                for vout in 0..entry.tx.vout.len() as u32 {
                    if let Some(child) = spenders.get(&(txid, vout)) {
                        to_remove.push(*child);
                    }
                }
            }
        }

        if removed > 0 {
            tracing::info!("Removed {} non-final transaction(s) from mempool", removed);
        }
        removed
    }

    /// Remove every transaction with an input that is neither spendable on chain
    /// (`on_chain`) nor an output of another transaction still in the mempool,
    /// until none is left, so descendants follow their parents. After the chain
    /// changed branch this drops what the new chain confirmed (its inputs are
    /// spent there, while its children stay, their inputs now on chain), what
    /// conflicts with the new chain, and what spends a coin the new chain does
    /// not have or has not matured. Returns how many were removed.
    pub fn remove_unspendable(&self, on_chain: impl Fn(&OutPoint) -> bool) -> usize {
        let mut removed = 0;
        loop {
            let doomed: Vec<Hash256> = {
                let txs = self.txs.read();
                txs.values()
                    .filter(|entry| {
                        entry.tx.vin.iter().any(|input| {
                            let from_pool = txs.get(&input.prevout.txid).is_some_and(|parent| {
                                (input.prevout.vout as usize) < parent.tx.vout.len()
                            });
                            !from_pool && !on_chain(&input.prevout)
                        })
                    })
                    .map(|entry| entry.txid)
                    .collect()
            };
            if doomed.is_empty() {
                break;
            }
            for txid in doomed {
                if self.remove(&txid).is_some() {
                    removed += 1;
                    tracing::info!(
                        "Removed tx {} from mempool: inputs no longer spendable",
                        txid
                    );
                }
            }
        }
        removed
    }

    /// Remove transactions that spend a coin also spent by one of a connected
    /// block's transactions, together with their descendants. They can never
    /// confirm; left in place they kept a double spend in the local mempool
    /// (and the wallet's pending view) forever. Returns how many were removed.
    /// The transactions `remove_conflicts` would remove for `block_txs`, in
    /// the order Divi Core's removeConflicts lists them: for each block
    /// transaction and input in turn, the mempool transaction spending the
    /// same coin and then its descendants breadth first
    /// (txmempool.cpp:91-178)
    pub fn conflicts_with(&self, block_txs: &[Transaction]) -> Vec<Transaction> {
        let txs = self.txs.read();
        let spenders = self.spenders.read();
        let mut listed = HashSet::new();
        let mut out = Vec::new();
        for tx in block_txs {
            let txid = tx.txid();
            for input in &tx.vin {
                let Some(first) = spenders.get(&(input.prevout.txid, input.prevout.vout)) else {
                    continue;
                };
                if *first == txid {
                    continue;
                }
                let mut queue = std::collections::VecDeque::from([*first]);
                while let Some(id) = queue.pop_front() {
                    let Some(entry) = txs.get(&id) else { continue };
                    if !listed.insert(id) {
                        continue;
                    }
                    for vout in 0..entry.tx.vout.len() as u32 {
                        if let Some(child) = spenders.get(&(id, vout)) {
                            queue.push_back(*child);
                        }
                    }
                    out.push(entry.tx.clone());
                }
            }
        }
        out
    }

    pub fn remove_conflicts(&self, block_txs: &[Transaction]) -> usize {
        let mut doomed: Vec<Hash256> = {
            let spenders = self.spenders.read();
            block_txs
                .iter()
                .flat_map(|tx| {
                    let txid = tx.txid();
                    tx.vin
                        .iter()
                        .filter_map(|input| {
                            spenders
                                .get(&(input.prevout.txid, input.prevout.vout))
                                .copied()
                        })
                        .filter(move |spender| *spender != txid)
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let mut removed = 0;
        while let Some(txid) = doomed.pop() {
            if let Some(entry) = self.remove(&txid) {
                removed += 1;
                tracing::info!("Removed tx {} from mempool: conflicts with a block", txid);
                let spenders = self.spenders.read();
                for vout in 0..entry.tx.vout.len() as u32 {
                    if let Some(child) = spenders.get(&(txid, vout)) {
                        doomed.push(*child);
                    }
                }
            }
        }
        removed
    }

    /// Get transactions for a new block, sorted by fee rate
    pub fn get_block_txs(&self, max_size: usize) -> Vec<Transaction> {
        let txs = self.txs.read();
        let mut result = Vec::new();
        let mut total_size = 0;

        // Get entries sorted by fee rate (descending)
        let mut entries: Vec<_> = txs.values().collect();
        entries.sort_by(|a, b| {
            b.fee_rate
                .partial_cmp(&a.fee_rate)
                .unwrap_or(Ordering::Equal)
        });

        for entry in entries {
            if total_size + entry.size > max_size {
                continue; // Skip this one, might fit smaller txs
            }
            total_size += entry.size;
            result.push(entry.tx.clone());
        }

        result
    }

    /// Every pool transaction weighed for a block at `height`, in no order
    pub fn block_candidates(&self, height: u32) -> Vec<BlockCandidate> {
        let txs = self.txs.read();
        let deltas = self.priority_deltas.read();
        txs.values()
            .map(|e| {
                let delta = deltas.get(&e.txid).copied();
                let (priority_delta, fee_delta) = delta.unwrap_or((0.0, 0));
                let nominal_fee = e.fee.as_sat() + fee_delta;
                let mut parents: Vec<Hash256> =
                    e.tx.vin
                        .iter()
                        .map(|i| i.prevout.txid)
                        .filter(|p| txs.contains_key(p))
                        .collect();
                parents.sort();
                parents.dedup();
                BlockCandidate {
                    tx: e.tx.clone(),
                    txid: e.txid,
                    size: e.size,
                    fee: e.fee,
                    priority: e.priority_at(height) + priority_delta,
                    fee_rate_per_kb: if e.size > 0 {
                        nominal_fee * 1000 / e.size as i64
                    } else {
                        0
                    },
                    prioritised: delta.is_some(),
                    parents,
                }
            })
            .collect()
    }

    /// Check if an outpoint is spent by a mempool transaction
    pub fn is_spent(&self, txid: &Hash256, vout: u32) -> bool {
        self.spenders.read().contains_key(&(*txid, vout))
    }

    /// Get the transaction that spends an outpoint
    pub fn get_spender(&self, txid: &Hash256, vout: u32) -> Option<Hash256> {
        self.spenders.read().get(&(*txid, vout)).copied()
    }

    /// Remove expired transactions
    pub fn expire_old(&self) -> usize {
        let expiry = Duration::from_secs(self.config.expiry_time);
        let mut to_remove = Vec::new();

        for (txid, entry) in self.txs.read().iter() {
            if entry.age() > expiry {
                to_remove.push(*txid);
            }
        }

        let count = to_remove.len();
        for txid in to_remove {
            self.remove(&txid);
        }

        if count > 0 {
            tracing::info!("Expired {} old transactions from mempool", count);
        }

        count
    }

    /// Evict transactions to make room for new ones
    fn evict_for_space(&self, needed: usize) -> Result<(), NodeError> {
        let mut freed = 0;
        let mut to_remove = Vec::new();

        // Remove lowest fee rate transactions first
        let txs = self.txs.read();
        let mut entries: Vec<_> = txs.values().collect();
        entries.sort_by(|a, b| {
            a.fee_rate
                .partial_cmp(&b.fee_rate)
                .unwrap_or(Ordering::Equal)
        });

        for entry in entries {
            if freed >= needed {
                break;
            }
            to_remove.push(entry.txid);
            freed += entry.size;
        }

        drop(txs);

        for txid in to_remove {
            self.remove(&txid);
        }

        if freed < needed {
            return Err(NodeError::TransactionValidation(
                "Mempool full, cannot accept transaction".into(),
            ));
        }

        Ok(())
    }

    /// Get mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let txs = self.txs.read();
        let total_fee: i64 = txs.values().map(|e| e.fee.as_sat()).sum();

        MempoolStats {
            tx_count: txs.len(),
            total_bytes: *self.total_size.read(),
            total_fee: Amount::from_sat(total_fee),
            max_size: self.config.max_size,
        }
    }

    /// Divi Core `CTxMemPool::PrioritiseTransaction` (txmempool.cpp:318-328):
    /// the fee delta is added to the fee and, as a number, to the priority;
    /// the priority delta argument is not used (rpcmining.cpp:270-275)
    pub fn prioritise_transaction(
        &self,
        txid: &Hash256,
        _priority_delta: f64,
        fee_delta: i64,
    ) -> bool {
        let mut deltas = self.priority_deltas.write();

        let entry = deltas.entry(*txid).or_insert((0.0, 0));
        entry.0 += fee_delta as f64;
        entry.1 += fee_delta;

        true
    }

    pub fn get_priority_delta(&self, txid: &Hash256) -> Option<(f64, i64)> {
        self.priority_deltas.read().get(txid).copied()
    }

    /// Clear all transactions from mempool
    pub fn clear(&self) {
        let removed: Vec<MempoolEntry> = self.txs.write().drain().map(|(_, e)| e).collect();
        self.spenders.write().clear();
        self.priority_queue.write().clear();
        *self.total_size.write() = 0;
        self.priority_deltas.write().clear();
        tracing::info!("Mempool cleared");

        let listener = self.on_removed.read().clone();
        if let Some(listener) = listener {
            for entry in &removed {
                listener(&entry.tx);
            }
        }
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    /// Number of transactions
    pub tx_count: usize,

    /// Total bytes
    pub total_bytes: usize,

    /// Total fees
    pub total_fee: Amount,

    /// Maximum allowed size
    pub max_size: usize,
}

impl divi_rpc::blockchain::MempoolProvider for Mempool {
    fn get_txids(&self) -> Vec<Hash256> {
        self.get_txids()
    }

    fn get_transaction(&self, txid: &Hash256) -> Option<Transaction> {
        self.get(txid).map(|entry| entry.tx)
    }

    fn prioritise_transaction(&self, txid: &Hash256, priority_delta: f64, fee_delta: i64) -> bool {
        self.prioritise_transaction(txid, priority_delta, fee_delta)
    }

    fn is_spent(&self, outpoint: &divi_primitives::transaction::OutPoint) -> bool {
        self.is_spent(&outpoint.txid, outpoint.vout)
    }

    fn get_tx_infos(&self) -> Vec<divi_rpc::blockchain::MempoolTxInfo> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let tip_height = self.tip_height();
        let txs = self.txs.read();
        txs.values()
            .map(|e| divi_rpc::blockchain::MempoolTxInfo {
                txid: e.txid,
                size: e.size,
                fee_sat: e.fee.as_sat(),
                time: now - e.time.elapsed().as_secs() as i64,
                // Inputs from pool transactions, each once in hex order, as
                // Divi Core's std::set<string> (rpcblockchain.cpp:130-136)
                depends: {
                    let mut parents: Vec<Hash256> =
                        e.tx.vin
                            .iter()
                            .map(|i| i.prevout.txid)
                            .filter(|p| txs.contains_key(p))
                            .collect();
                    parents.sort_by_key(|p| p.to_string());
                    parents.dedup();
                    parents
                },
                height: e.height,
                starting_priority: e.priority_at(e.height),
                current_priority: e.priority_at(tip_height),
            })
            .collect()
    }

    fn get_stats(&self) -> divi_rpc::blockchain::MempoolStats {
        divi_rpc::blockchain::MempoolStats {
            size: self.size(),
            bytes: self.bytes(),
            usage: self.bytes() + self.size() * 200, // Estimate overhead per entry
            max_mempool: self.config.max_size,
            min_fee: self.relay_floor_divi_per_kb(),
        }
    }

    fn estimate_fee(&self, conf_target: u32) -> f64 {
        // Use mempool-based fee estimation
        // Look at fee rates in current mempool
        let txs = self.txs.read();
        if txs.is_empty() {
            return self.relay_floor_divi_per_kb();
        }

        // Collect all fee rates
        let mut fee_rates: Vec<f64> = txs.values().map(|e| e.fee_rate).collect();
        fee_rates.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        // For lower confirmation targets, use higher fee rates
        // conf_target of 1-2 = top 10%, 3-6 = top 50%, 7+ = median
        let percentile_idx = if conf_target <= 2 {
            fee_rates.len() / 10
        } else if conf_target <= 6 {
            fee_rates.len() / 2
        } else {
            fee_rates.len() * 3 / 4
        };

        let idx = percentile_idx.min(fee_rates.len().saturating_sub(1));
        let fee_per_byte = fee_rates.get(idx).copied().unwrap_or(1.0);

        // Convert from sat/byte to DIVI/kB
        let fee_per_kb = fee_per_byte * 1000.0;
        let fee_divi = fee_per_kb / 100_000_000.0;

        fee_divi.max(self.relay_floor_divi_per_kb())
    }

    fn estimate_smart_fee(&self, conf_target: u32) -> divi_rpc::blockchain::FeeEstimate {
        let fee_rate = self.estimate_fee(conf_target);
        let blocks = conf_target.min(25); // Cap at 25 blocks for estimation

        divi_rpc::blockchain::FeeEstimate { fee_rate, blocks }
    }
}

fn rejected(code: u8, reason: &str) -> NodeError {
    NodeError::rejected(code, reason)
}

fn conflict(existing: &Hash256) -> NodeError {
    NodeError::MempoolConflict(*existing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::constants::SEQUENCE_FINAL;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::{OutPoint, TxIn, TxOut};

    fn test_config() -> MempoolConfig {
        MempoolConfig {
            min_relay_fee_per_kb: 1000, // Very low for testing
            ..MempoolConfig::default()
        }
    }

    fn create_test_tx(prevout_txid: [u8; 32], value: i64) -> Transaction {
        Transaction {
            version: 2,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes(prevout_txid), 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(
                Amount::from_divi(value),
                Script::new_p2pkh(&[0u8; 20]),
            )],
            lock_time: 0,
        }
    }

    fn locked_tx(prevout_txid: [u8; 32], lock_time: u32, sequence: u32) -> Transaction {
        let mut tx = create_test_tx(prevout_txid, 1);
        tx.lock_time = lock_time;
        tx.vin[0].sequence = sequence;
        tx
    }

    fn mempool_at_height(height: Arc<std::sync::atomic::AtomicU32>) -> Mempool {
        let mempool = Mempool::new(test_config());
        mempool.set_tip_height_provider(Arc::new(move || {
            height.load(std::sync::atomic::Ordering::SeqCst)
        }));
        mempool
    }

    #[test]
    fn test_non_final_time_locked_tx_rejected() {
        // a tx time-locked far in the future with a non-final input
        // must not enter the mempool (Divi Core: -26 "64: non-final").
        let mempool = Mempool::new(test_config());
        let tx = locked_tx([7u8; 32], 4_000_000_000, 0);
        let result = mempool.add(tx, Amount::from_sat(10000));
        let err = result.expect_err("non-final tx was accepted").to_string();
        assert_eq!(err, "64: non-final");
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn test_locked_tx_with_final_sequences_accepted() {
        // All inputs final means the lock time is ignored
        let mempool = Mempool::new(test_config());
        let tx = locked_tx([8u8; 32], 4_000_000_000, SEQUENCE_FINAL);
        assert!(mempool.add(tx, Amount::from_sat(10000)).is_ok());
    }

    #[test]
    fn test_past_time_lock_accepted() {
        let mempool = Mempool::new(test_config());
        let tx = locked_tx([9u8; 32], 600_000_000, 0);
        assert!(mempool.add(tx, Amount::from_sat(10000)).is_ok());
    }

    #[test]
    fn test_height_locked_tx_waits_for_next_block() {
        let height = Arc::new(std::sync::atomic::AtomicU32::new(199));
        let mempool = mempool_at_height(Arc::clone(&height));
        let tx = locked_tx([10u8; 32], 200, 0);

        // Next block is 200: lock 200 is not below it yet
        assert!(matches!(
            mempool.add(tx.clone(), Amount::from_sat(10000)),
            Err(NodeError::NonFinal)
        ));

        height.store(200, std::sync::atomic::Ordering::SeqCst);
        assert!(mempool.add(tx, Amount::from_sat(10000)).is_ok());
    }

    #[test]
    fn test_reorg_evicts_non_final_tx_and_its_spender() {
        let height = Arc::new(std::sync::atomic::AtomicU32::new(300));
        let mempool = mempool_at_height(Arc::clone(&height));
        let parent = locked_tx([11u8; 32], 250, 0);
        let parent_txid = mempool.add(parent, Amount::from_sat(10000)).unwrap();
        let child = create_test_tx(*parent_txid.as_bytes(), 1);
        mempool.add(child, Amount::from_sat(10000)).unwrap();
        let unrelated = mempool
            .add(create_test_tx([12u8; 32], 1), Amount::from_sat(10000))
            .unwrap();
        assert_eq!(mempool.size(), 3);

        // Reorg to a chain whose tip is below the lock height
        height.store(240, std::sync::atomic::Ordering::SeqCst);
        mempool.remove_for_block(&[]);

        assert_eq!(mempool.size(), 1);
        assert!(mempool.contains(&unrelated));
        assert!(!mempool.contains(&parent_txid));
    }

    #[test]
    fn test_mempool_refuses_dust_output() {
        // Default relay fee (10 sat/byte): Divi Core's dust limit is 5460 sat for P2PKH
        let mempool = Mempool::new(MempoolConfig::default());
        let mut tx = create_test_tx([9u8; 32], 1);
        tx.vout.push(TxOut::new(
            Amount::from_sat(5459),
            Script::new_p2pkh(&[1u8; 20]),
        ));
        assert!(matches!(
            mempool.add(tx.clone(), Amount::from_sat(100_000)),
            Err(NodeError::TxRejected { code: 0x40, ref reason, .. }) if reason == "dust"
        ));
        assert_eq!(mempool.size(), 0);

        tx.vout[1].value = Amount::from_sat(5460);
        assert!(mempool.add(tx, Amount::from_sat(100_000)).is_ok());
    }

    #[test]
    fn test_mempool_rejects_with_divi_core_codes() {
        let mempool = Mempool::new(MempoolConfig::default());
        // 1 sat for ~85 bytes is below 10 sat/byte
        let tx = create_test_tx([8u8; 32], 1);
        assert!(matches!(
            mempool.add(tx, Amount::from_sat(1)),
            Err(NodeError::TxRejected { code: 0x42, ref reason, .. }) if reason == "insufficient fee"
        ));
        // A coinstake is only valid in a block
        let mut stake = create_test_tx([7u8; 32], 1);
        stake.vout.insert(0, TxOut::empty());
        assert!(stake.is_coinstake());
        assert!(matches!(
            mempool.add(stake, Amount::from_sat(100_000)),
            Err(NodeError::TxRejected { code: 0x10, ref reason, .. }) if reason == "coinstake"
        ));
    }

    #[test]
    fn test_mempool_new() {
        let mempool = Mempool::new(test_config());
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.bytes(), 0);
    }

    #[test]
    fn test_mempool_add_remove() {
        let mempool = Mempool::new(test_config());

        let tx = create_test_tx([1u8; 32], 50);
        let txid = tx.txid();
        let fee = Amount::from_sat(10000);

        mempool.add(tx, fee).unwrap();
        assert_eq!(mempool.size(), 1);
        assert!(mempool.contains(&txid));

        let entry = mempool.remove(&txid).unwrap();
        assert_eq!(entry.fee, fee);
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn test_mempool_conflict_detection() {
        let mempool = Mempool::new(test_config());

        // Add first tx
        let tx1 = create_test_tx([1u8; 32], 50);
        mempool.add(tx1, Amount::from_sat(10000)).unwrap();

        // Try to add conflicting tx (same input)
        let tx2 = create_test_tx([1u8; 32], 40);
        let result = mempool.add(tx2, Amount::from_sat(10000));
        assert!(result.is_err());
    }

    /// Block assembly sees a delta as Divi Core applies it: the fee delta adds
    /// to the fee rate and, as a number, to the priority; the priority delta
    /// argument is not used (txmempool.cpp:318-348, rpcmining.cpp:270-275).
    /// The fee the block collects stays the fee paid.
    #[test]
    fn block_candidates_carry_prioritisetransaction_deltas() {
        let mempool = Mempool::new(MempoolConfig::default());
        let tx = create_test_tx([1; 32], 1);
        let txid = tx.txid();
        let size = tx.size() as i64;
        mempool.add(tx, Amount::from_sat(10_000)).unwrap();

        // At the entry height (no tip provider: 0) there is no coin age yet
        let c = &mempool.block_candidates(0)[0];
        assert!(!c.prioritised);
        assert_eq!(c.fee_rate_per_kb, 10_000 * 1000 / size);

        mempool.prioritise_transaction(&txid, 999.0, 50_000);
        let c = &mempool.block_candidates(0)[0];
        assert!(c.prioritised);
        assert_eq!(c.fee_rate_per_kb, 60_000 * 1000 / size);
        assert_eq!(c.priority, 50_000.0);
        assert_eq!(c.fee, Amount::from_sat(10_000));

        // Any delta, even zero, marks the transaction as prioritised
        let other = create_test_tx([2; 32], 1);
        let other_id = other.txid();
        mempool.add(other, Amount::from_sat(10_000)).unwrap();
        mempool.prioritise_transaction(&other_id, 0.0, 0);
        let c = mempool
            .block_candidates(0)
            .into_iter()
            .find(|c| c.txid == other_id)
            .unwrap();
        assert!(c.prioritised);
    }

    #[test]
    fn test_mempool_get_block_txs() {
        let mempool = Mempool::new(test_config());

        // Add transactions with different fee rates
        for i in 0..5 {
            let tx = create_test_tx([i + 1; 32], 10);
            let fee = Amount::from_sat((i as i64 + 1) * 1000);
            mempool.add(tx, fee).unwrap();
        }

        let block_txs = mempool.get_block_txs(1_000_000);
        assert_eq!(block_txs.len(), 5);
    }

    #[test]
    fn test_mempool_is_spent() {
        let mempool = Mempool::new(test_config());

        let prev_txid = Hash256::from_bytes([1u8; 32]);
        let tx = create_test_tx([1u8; 32], 50);
        mempool.add(tx, Amount::from_sat(10000)).unwrap();

        assert!(mempool.is_spent(&prev_txid, 0));
        assert!(!mempool.is_spent(&prev_txid, 1));
    }

    #[test]
    fn test_mempool_stats() {
        let mempool = Mempool::new(test_config());

        let tx = create_test_tx([1u8; 32], 50);
        let fee = Amount::from_sat(10000);
        mempool.add(tx, fee).unwrap();

        let stats = mempool.stats();
        assert_eq!(stats.tx_count, 1);
        assert_eq!(stats.total_fee.as_sat(), 10000);
        assert!(stats.total_bytes > 0);
    }

    #[test]
    fn test_mempool_clear() {
        let mempool = Mempool::new(test_config());

        for i in 0..3 {
            let tx = create_test_tx([i + 1; 32], 50);
            mempool.add(tx, Amount::from_sat(10000)).unwrap();
        }

        assert_eq!(mempool.size(), 3);
        mempool.clear();
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.bytes(), 0);
    }

    #[test]
    fn test_low_fee_rejection() {
        let config = MempoolConfig {
            min_relay_fee_per_kb: 100_000_000, // High minimum
            ..MempoolConfig::default()
        };
        let mempool = Mempool::new(config);

        let tx = create_test_tx([1u8; 32], 50);
        let result = mempool.add(tx, Amount::from_sat(1)); // Very low fee
        assert!(result.is_err());
    }

    #[test]
    fn test_fee_estimate_never_below_relay_floor() {
        use divi_rpc::blockchain::MempoolProvider;

        // Default relay fee is C++ Divi's 10000 sat/kB. BasicSwap prices swap
        // transactions with estimatesmartfee and refuses a rate below relayfee.
        let mempool = Mempool::new(MempoolConfig::default());
        assert_eq!(mempool.min_relay_fee_per_kb(), 10_000);
        assert_eq!(MempoolProvider::estimate_fee(&mempool, 2), 0.0001);
        assert_eq!(
            MempoolProvider::estimate_smart_fee(&mempool, 2).fee_rate,
            0.0001
        );
        assert_eq!(MempoolProvider::get_stats(&mempool).min_fee, 0.0001);
    }

    // ============================================================
    // COMPREHENSIVE MEMPOOL TESTS
    // Added 2026-01-19 for test pyramid completeness
    // ============================================================

    #[test]
    fn test_mempool_reject_duplicate_add() {
        let mempool = Mempool::new(test_config());
        let tx = create_test_tx([1u8; 32], 50);
        let fee = Amount::from_sat(10000);

        // Add once - should succeed
        let txid1 = mempool.add(tx.clone(), fee).unwrap();
        assert_eq!(mempool.size(), 1);

        // Add again - should return same txid (idempotent)
        let txid2 = mempool.add(tx, fee).unwrap();
        assert_eq!(txid1, txid2);
        assert_eq!(mempool.size(), 1); // Still only 1 tx
    }

    #[test]
    fn test_mempool_remove_nonexistent() {
        let mempool = Mempool::new(test_config());
        let fake_txid = Hash256::from_bytes([0xff; 32]);

        let result = mempool.remove(&fake_txid);
        assert!(result.is_none());
    }

    #[test]
    fn test_mempool_fee_rate_calculation() {
        let mempool = Mempool::new(test_config());
        let tx = create_test_tx([1u8; 32], 50);
        let fee = Amount::from_sat(10000);

        mempool.add(tx.clone(), fee).unwrap();
        let entry = mempool.get(&tx.txid()).unwrap();

        // Fee rate should be fee / size
        let expected_rate = 10000.0 / (entry.size as f64);
        assert!((entry.fee_rate - expected_rate).abs() < 0.01);
    }

    #[test]
    fn test_mempool_priority_ordering() {
        let mempool = Mempool::new(test_config());

        // Add txs with different fee rates
        let tx1 = create_test_tx([1u8; 32], 50);
        let tx2 = create_test_tx([2u8; 32], 50);
        let tx3 = create_test_tx([3u8; 32], 50);

        mempool.add(tx1, Amount::from_sat(1000)).unwrap(); // Low fee
        mempool.add(tx2, Amount::from_sat(10000)).unwrap(); // High fee
        mempool.add(tx3, Amount::from_sat(5000)).unwrap(); // Medium fee

        // get_block_txs should return in high-to-low fee order
        let block_txs = mempool.get_block_txs(1_000_000);
        assert_eq!(block_txs.len(), 3);

        // Verify fee order (highest first)
        let entry1 = mempool.get(&block_txs[0].txid()).unwrap();
        let entry2 = mempool.get(&block_txs[1].txid()).unwrap();
        let entry3 = mempool.get(&block_txs[2].txid()).unwrap();

        assert!(entry1.fee_rate >= entry2.fee_rate);
        assert!(entry2.fee_rate >= entry3.fee_rate);
    }

    #[test]
    fn test_mempool_size_limit_eviction() {
        let mut config = test_config();
        config.max_size = 1000; // Very small mempool
        let mempool = Mempool::new(config);

        // Add multiple transactions
        for i in 0..10 {
            let tx = create_test_tx([i + 1; 32], 10);
            let _ = mempool.add(tx, Amount::from_sat((i as i64 + 1) * 1000));
        }

        // Mempool should have evicted some transactions
        assert!(mempool.bytes() <= 1000);
    }

    #[test]
    fn test_mempool_block_tx_size_limit() {
        let mempool = Mempool::new(test_config());

        // Add many transactions
        for i in 0..20 {
            let tx = create_test_tx([i + 1; 32], 10);
            mempool.add(tx, Amount::from_sat(10000)).unwrap();
        }

        // Request with very small size limit
        let block_txs = mempool.get_block_txs(500);

        // Should return fewer than all txs
        assert!(block_txs.len() < 20);

        // Total size should be <= limit
        let total_size: usize = block_txs.iter().map(|tx| tx.size()).sum();
        assert!(total_size <= 500);
    }

    #[test]
    fn test_mempool_spender_tracking() {
        let mempool = Mempool::new(test_config());

        let prev_txid = Hash256::from_bytes([1u8; 32]);
        let tx = create_test_tx([1u8; 32], 50);
        let txid = tx.txid();

        mempool.add(tx, Amount::from_sat(10000)).unwrap();

        // Check spender is tracked
        let spender = mempool.get_spender(&prev_txid, 0);
        assert_eq!(spender, Some(txid));

        // Remove tx
        mempool.remove(&txid);

        // Spender should be cleared
        let spender_after = mempool.get_spender(&prev_txid, 0);
        assert_eq!(spender_after, None);
    }

    #[test]
    fn test_mempool_remove_for_block() {
        let mempool = Mempool::new(test_config());

        let tx1 = create_test_tx([1u8; 32], 50);
        let tx2 = create_test_tx([2u8; 32], 50);
        let tx3 = create_test_tx([3u8; 32], 50);

        let txid1 = tx1.txid();
        let txid2 = tx2.txid();
        let txid3 = tx3.txid();

        mempool.add(tx1, Amount::from_sat(10000)).unwrap();
        mempool.add(tx2, Amount::from_sat(10000)).unwrap();
        mempool.add(tx3, Amount::from_sat(10000)).unwrap();

        assert_eq!(mempool.size(), 3);

        // Remove tx1 and tx2 (as if they were in a block)
        mempool.remove_for_block(&[txid1, txid2]);

        assert_eq!(mempool.size(), 1);
        assert!(!mempool.contains(&txid1));
        assert!(!mempool.contains(&txid2));
        assert!(mempool.contains(&txid3));
    }

    #[test]
    fn remove_conflicts_drops_double_spends_of_block_inputs() {
        let mempool = Mempool::new(test_config());

        // `stale` spends coin [1; 32] in the mempool, `child` spends `stale`;
        // `other` spends an unrelated coin
        let stale = create_test_tx([1u8; 32], 50);
        let child = create_test_tx(stale.txid().as_bytes().to_owned(), 40);
        let other = create_test_tx([2u8; 32], 50);
        mempool.add(stale.clone(), Amount::from_sat(10000)).unwrap();
        mempool.add(child.clone(), Amount::from_sat(10000)).unwrap();
        mempool.add(other.clone(), Amount::from_sat(10000)).unwrap();

        // A block spends coin [1; 32] with a different tx (e.g. a coinstake)
        let winner = create_test_tx([1u8; 32], 49);
        mempool.remove_for_block(&[winner.txid()]);
        assert_eq!(mempool.remove_conflicts(&[winner]), 2);

        assert!(!mempool.contains(&stale.txid()));
        assert!(!mempool.contains(&child.txid()));
        assert!(mempool.contains(&other.txid()));
        assert!(!mempool.is_spent(&Hash256::from_bytes([1u8; 32]), 0));
    }

    #[test]
    fn test_mempool_double_spend_rejection() {
        let mempool = Mempool::new(test_config());

        // Add first transaction
        let tx1 = create_test_tx([1u8; 32], 50);
        mempool.add(tx1.clone(), Amount::from_sat(10000)).unwrap();

        // Create second transaction spending same input
        let tx2 = create_test_tx([1u8; 32], 40); // Same prevout!
        let result = mempool.add(tx2, Amount::from_sat(15000));

        // Should be rejected
        assert!(result.is_err());
        assert!(
            matches!(result, Err(NodeError::MempoolConflict(_))),
            "{result:?}"
        );
    }

    #[test]
    fn test_mempool_get_nonexistent() {
        let mempool = Mempool::new(test_config());
        let fake_txid = Hash256::from_bytes([0xaa; 32]);

        assert!(!mempool.contains(&fake_txid));
        assert!(mempool.get(&fake_txid).is_none());
    }

    #[test]
    fn test_mempool_stats_accumulation() {
        let mempool = Mempool::new(test_config());

        let initial_stats = mempool.stats();
        assert_eq!(initial_stats.tx_count, 0);
        assert_eq!(initial_stats.total_fee.as_sat(), 0);
        assert_eq!(initial_stats.total_bytes, 0);

        // Add transactions
        for i in 0..5 {
            let tx = create_test_tx([i + 1; 32], 10);
            mempool
                .add(tx, Amount::from_sat((i as i64 + 1) * 1000))
                .unwrap();
        }

        let stats = mempool.stats();
        assert_eq!(stats.tx_count, 5);
        assert_eq!(stats.total_fee.as_sat(), 15000); // 1+2+3+4+5 = 15
        assert!(stats.total_bytes > 0);
    }

    #[test]
    fn test_mempool_age_tracking() {
        let mempool = Mempool::new(test_config());
        let tx = create_test_tx([1u8; 32], 50);
        let txid = tx.txid();

        mempool.add(tx, Amount::from_sat(10000)).unwrap();

        // Age should be very small (just added)
        let entry = mempool.get(&txid).unwrap();
        assert!(entry.age().as_secs() < 1);

        // Sleep would make age grow, but we don't want to slow down tests
        // Just verify age() works without panicking
        let _ = entry.age();
    }

    #[test]
    fn test_mempool_eviction_lowest_fee_first() {
        let mut config = test_config();
        config.max_size = 2000;
        let mempool = Mempool::new(config);

        // Add low fee tx
        let tx_low = create_test_tx([1u8; 32], 10);
        let txid_low = tx_low.txid();
        mempool.add(tx_low, Amount::from_sat(100)).unwrap();

        // Add many high fee txs to trigger eviction
        for i in 0..50 {
            let tx = create_test_tx([i + 10; 32], 10);
            let _ = mempool.add(tx, Amount::from_sat(100000));
        }

        // Low fee tx should have been evicted
        assert!(!mempool.contains(&txid_low));
    }

    #[test]
    fn test_mempool_clear_removes_all() {
        let mempool = Mempool::new(test_config());

        // Add multiple transactions
        for i in 0..10 {
            let tx = create_test_tx([i + 1; 32], 10);
            mempool.add(tx, Amount::from_sat(10000)).unwrap();
        }

        assert_eq!(mempool.size(), 10);
        assert!(mempool.bytes() > 0);

        mempool.clear();

        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.bytes(), 0);

        // All spenders should be cleared too
        let prev_txid = Hash256::from_bytes([1u8; 32]);
        assert!(!mempool.is_spent(&prev_txid, 0));
    }

    #[test]
    fn test_mempool_multiple_inputs_same_tx() {
        let mempool = Mempool::new(test_config());

        // Create tx with multiple inputs
        let tx = Transaction {
            version: 2,
            vin: vec![
                TxIn::new(
                    OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                    Script::new(),
                    SEQUENCE_FINAL,
                ),
                TxIn::new(
                    OutPoint::new(Hash256::from_bytes([2u8; 32]), 1),
                    Script::new(),
                    SEQUENCE_FINAL,
                ),
            ],
            vout: vec![TxOut::new(
                Amount::from_divi(50),
                Script::new_p2pkh(&[0u8; 20]),
            )],
            lock_time: 0,
        };

        mempool.add(tx.clone(), Amount::from_sat(10000)).unwrap();

        // Both inputs should be marked as spent
        assert!(mempool.is_spent(&Hash256::from_bytes([1u8; 32]), 0));
        assert!(mempool.is_spent(&Hash256::from_bytes([2u8; 32]), 1));

        // Different outputs should not be spent
        assert!(!mempool.is_spent(&Hash256::from_bytes([1u8; 32]), 1));
        assert!(!mempool.is_spent(&Hash256::from_bytes([2u8; 32]), 0));
    }

    #[test]
    fn test_mempool_empty_operations() {
        let mempool = Mempool::new(test_config());

        // Operations on empty mempool
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.bytes(), 0);

        let block_txs = mempool.get_block_txs(1_000_000);
        assert!(block_txs.is_empty());

        mempool.remove_for_block(&[]);
        assert_eq!(mempool.size(), 0);

        let expired = mempool.expire_old();
        assert_eq!(expired, 0);

        mempool.clear(); // Should not panic
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn test_mempool_fee_rate_extremes() {
        let mempool = Mempool::new(test_config());

        // Very high fee
        let tx_high = create_test_tx([1u8; 32], 10);
        mempool
            .add(tx_high.clone(), Amount::from_sat(100_000_000))
            .unwrap();
        let entry_high = mempool.get(&tx_high.txid()).unwrap();
        assert!(entry_high.fee_rate > 10000.0);

        // Low fee (but still above minimum relay of 1 sat/byte)
        let tx_low = create_test_tx([2u8; 32], 10);
        let tx_size = tx_low.size();
        mempool
            .add(tx_low.clone(), Amount::from_sat(tx_size as i64 + 1))
            .unwrap();
        let entry_low = mempool.get(&tx_low.txid()).unwrap();
        assert!(entry_low.fee_rate >= 1.0);
        assert!(entry_low.fee_rate < 2.0);
    }
}
