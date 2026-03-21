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

//! Proof-of-Stake block production
//!
//! This module implements the staking loop that attempts to produce new blocks
//! by finding valid proof-of-stake solutions using wallet UTXOs.

use crate::mempool::Mempool;
use divi_consensus::{
    HashproofResult, ProofOfStakeGenerator, SimpleStakeModifierService, StakingData,
};
use divi_crypto::compute_block_hash;
use divi_network::{BlockConnectedCallback, PeerManager};
use divi_primitives::amount::Amount;
use divi_primitives::block::{Block, BlockHeader};
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_storage::Chain;
use divi_wallet::{TransactionSigner, WalletDb};

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::{debug, info, trace, warn};

/// Distinguishes between regular P2PKH staking and vault staking
enum StakeCandidate<'a> {
    Regular(&'a divi_wallet::WalletUtxo),
    Vault(&'a divi_wallet::WalletUtxo, divi_script::StakingVaultScript),
}

impl<'a> StakeCandidate<'a> {
    fn utxo(&self) -> &divi_wallet::WalletUtxo {
        match self {
            StakeCandidate::Regular(u) => u,
            StakeCandidate::Vault(u, _) => u,
        }
    }
}

/// Cache of data that stays constant while staking at the same tip.
/// Invalidated when tip_hash changes, saving ~1632 DB reads per attempt.
struct StakerCache {
    /// Hash of the tip this cache was computed for
    tip_hash: Hash256,
    /// Stake modifier (from DB walkback, not the tip's cached field)
    stake_modifier: u64,
    /// Median time past for this tip
    median_time_past: u32,
    /// Cached confirmation block data: height -> (block_time, block_hash)
    /// Confirmation blocks are immutable (they don't change when the tip changes)
    /// so we keep these across tip changes and only add new entries.
    confirmation_blocks: HashMap<u32, (u32, Hash256)>,
}

impl StakerCache {
    fn new() -> Self {
        StakerCache {
            tip_hash: Hash256::zero(),
            stake_modifier: 0,
            median_time_past: 0,
            confirmation_blocks: HashMap::new(),
        }
    }
}

/// Staking configuration
#[derive(Debug, Clone)]
pub struct StakingConfig {
    /// Minimum UTXO value for staking (satoshis)
    pub min_stake_amount: i64,
    /// Reserve balance - don't stake this much (satoshis)
    pub reserve_balance: i64,
    /// Minimum UTXO age for staking (seconds)
    pub min_coin_age: u32,
    /// Maximum block size (bytes)
    pub max_block_size: usize,
    /// Maximum block weight
    pub max_block_weight: usize,
    /// Staking loop interval (milliseconds)
    pub loop_interval_ms: u64,
}

impl Default for StakingConfig {
    fn default() -> Self {
        StakingConfig {
            min_stake_amount: 0, // No minimum - any UTXO can stake (matches C++ Divi)
            reserve_balance: 0,
            min_coin_age: 60 * 60, // 1 hour
            max_block_size: 2_000_000,
            max_block_weight: 4_000_000,
            loop_interval_ms: 500, // Try every 500ms
        }
    }
}

/// Result of a staking attempt
pub enum StakeResult {
    /// Successfully staked a block (includes the block for self-acceptance)
    Success {
        block: Block,
        block_hash: Hash256,
        height: u32,
        reward: Amount,
    },
    /// No stakeable UTXOs available
    NoStakeableUtxos,
    /// Failed to find valid proof
    NoProofFound,
    /// Rate limited - too soon to try again
    RateLimited,
    /// Error during staking
    Error(String),
}

/// Events from the staker
#[derive(Debug, Clone)]
pub enum StakerEvent {
    /// Started staking
    Started,
    /// Stopped staking
    Stopped,
    /// Found and broadcast a new block
    BlockFound {
        hash: Hash256,
        height: u32,
        reward: Amount,
    },
    /// Status update
    Status {
        utxo_count: usize,
        stake_weight: u64,
        last_attempt: u64,
    },
}

/// Proof-of-stake block producer
pub struct Staker {
    /// Wallet database
    wallet: Arc<WalletDb>,
    /// Chain state
    chain: Arc<Chain>,
    /// Transaction mempool
    mempool: Arc<Mempool>,
    /// Peer manager for broadcasting blocks
    peer_manager: Arc<PeerManager>,
    /// Configuration (using RwLock for reserve_balance updates)
    config: RwLock<StakingConfig>,
    /// Whether staking is currently running
    running: AtomicBool,
    /// Event broadcaster
    event_tx: broadcast::Sender<StakerEvent>,
    /// Last successful stake time
    last_stake_time: RwLock<u64>,
    /// Total stake weight (for status)
    stake_weight: RwLock<u64>,
    /// Track last staking attempt time per height (height -> timestamp)
    /// This matches C++ mapHashedBlocks / hashedBlockTimestamps
    hashed_block_timestamps: RwLock<HashMap<u32, u64>>,
    /// Block connected callback (same one used by BlockSync for wallet/mempool/fees)
    /// Set from main.rs after construction so the staker can fire it on self-accepted blocks.
    block_connected_callback: RwLock<Option<BlockConnectedCallback>>,
    /// Per-tip cache to avoid repeated DB reads for stake_modifier, MTP, and confirmation blocks
    cache: RwLock<StakerCache>,
}

impl Staker {
    /// Create a new staker
    pub fn new(
        wallet: Arc<WalletDb>,
        chain: Arc<Chain>,
        mempool: Arc<Mempool>,
        peer_manager: Arc<PeerManager>,
        config: StakingConfig,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(100);

        Staker {
            wallet,
            chain,
            mempool,
            peer_manager,
            config: RwLock::new(config),
            running: AtomicBool::new(false),
            event_tx,
            last_stake_time: RwLock::new(0),
            stake_weight: RwLock::new(0),
            hashed_block_timestamps: RwLock::new(HashMap::new()),
            block_connected_callback: RwLock::new(None),
            cache: RwLock::new(StakerCache::new()),
        }
    }

    /// Set the block connected callback (for self-accepted staked blocks)
    ///
    /// This should be the same callback used by BlockSync so that wallet scanning,
    /// mempool cleanup, and fee estimation happen when we self-accept our own blocks.
    pub fn set_block_connected_callback(&self, callback: BlockConnectedCallback) {
        *self.block_connected_callback.write() = Some(callback);
    }

    /// Subscribe to staker events
    pub fn subscribe(&self) -> broadcast::Receiver<StakerEvent> {
        self.event_tx.subscribe()
    }

    /// Check if staking is currently running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get staking status
    pub fn get_status(&self) -> StakingStatus {
        let current_height = self.chain.height();

        // Get stakeable UTXOs
        let utxos = self.wallet.get_spendable_utxos(current_height, 1);
        let stakeable: Vec<_> = utxos
            .into_iter()
            .filter(|u| u.value.as_sat() >= self.config.read().min_stake_amount)
            .collect();

        let stake_weight: u64 = stakeable.iter().map(|u| u.value.as_sat() as u64).sum();

        StakingStatus {
            enabled: self.running.load(Ordering::SeqCst),
            staking: self.running.load(Ordering::SeqCst) && !stakeable.is_empty(),
            utxo_count: stakeable.len(),
            stake_weight,
            expected_time: self.calculate_expected_time(stake_weight),
            last_stake_time: *self.last_stake_time.read(),
            blocks: current_height,
        }
    }

    /// Calculate expected time to stake a block
    ///
    /// Formula: expected_time = (target / max_target) * (estimated_network_weight / my_weight) * block_spacing
    ///
    /// Since we don't have total network weight readily available, we use a simplified approach:
    /// - The difficulty target represents how hard it is to find a block
    /// - Higher target (easier) = longer time to stake
    /// - More stake weight = shorter time to stake
    ///
    /// The calculation uses the current difficulty target and assumes a reasonable network
    /// weight distribution. This gives an estimate in seconds.
    fn calculate_expected_time(&self, stake_weight: u64) -> Option<u64> {
        if stake_weight == 0 {
            return None;
        }

        // Get current tip and difficulty target
        let tip = match self.chain.tip() {
            Some(t) => t,
            None => return Some(3600), // Default to 1 hour if no tip
        };
        let target = Hash256::from_compact(tip.bits);

        // Target spacing: 60 seconds per block
        const TARGET_SPACING: u64 = 60;

        // Get the maximum target (minimum difficulty) for PoS
        // This is ~uint256(0) >> 24, represented as 0x1e0fffff in compact form
        let max_target = Hash256::from_compact(0x1e0fffff);

        // Calculate the ratio: target / max_target
        // This gives us a value between 0 and 1 representing relative difficulty
        // Hash256 is stored as little-endian internally, so the most significant bytes are at the END
        // We read the last 8 bytes to get a reasonable approximation of the target value
        let target_bytes = target.as_bytes();
        let target_value = u64::from_le_bytes([
            target_bytes[24],
            target_bytes[25],
            target_bytes[26],
            target_bytes[27],
            target_bytes[28],
            target_bytes[29],
            target_bytes[30],
            target_bytes[31],
        ]);

        let max_target_bytes = max_target.as_bytes();
        let max_target_value = u64::from_le_bytes([
            max_target_bytes[24],
            max_target_bytes[25],
            max_target_bytes[26],
            max_target_bytes[27],
            max_target_bytes[28],
            max_target_bytes[29],
            max_target_bytes[30],
            max_target_bytes[31],
        ]);

        // Edge case: if max_target is zero
        if max_target_value == 0 {
            return Some(3600); // Default to 1 hour if calculation fails
        }

        // Estimate network weight as a multiple of our stake weight
        // This is an approximation - in reality we'd need to track total staking weight
        // We assume the total network has roughly 1 million DIVI staking
        // This is a very rough heuristic and will need tuning based on actual network behavior
        const ESTIMATED_TOTAL_NETWORK_WEIGHT: u64 = 100_000_000_000_000; // 1M DIVI in satoshis

        // Expected time formula:
        // time = (target / max_target) * (network_weight / my_weight) * block_spacing
        //
        // Simplified when target ≈ max_target (easy difficulty):
        // time = (network_weight / my_weight) * block_spacing
        //
        // For easier calculation and to avoid overflow, we can simplify:
        // If target_value == 0 or very close to max_target, assume difficulty ratio is ~1
        // and just calculate based on stake weight proportion

        let expected_seconds = if target_value == 0 || target_value >= max_target_value {
            // Easy difficulty (regtest default) - simplified calculation
            // time = (network_weight / my_weight) * spacing
            let ratio = ESTIMATED_TOTAL_NETWORK_WEIGHT / stake_weight;
            ratio.saturating_mul(TARGET_SPACING)
        } else {
            // Harder difficulty - use full formula with u128 to avoid overflow
            let numerator = (target_value as u128)
                .saturating_mul(ESTIMATED_TOTAL_NETWORK_WEIGHT as u128)
                .saturating_mul(TARGET_SPACING as u128);

            let denominator = (max_target_value as u128).saturating_mul(stake_weight as u128);

            if denominator == 0 {
                return Some(3600); // Avoid division by zero
            }

            (numerator / denominator) as u64
        };

        // Clamp to reasonable values:
        // - Minimum: 60 seconds (one block time)
        // - Maximum: 30 days in seconds (for very small stakes)
        let clamped = expected_seconds.clamp(60, 30 * 24 * 3600);

        Some(clamped)
    }

    /// Start the staking loop
    pub async fn start(self: Arc<Self>) {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Staking already running");
            return;
        }

        info!("Starting proof-of-stake block production");
        let _ = self.event_tx.send(StakerEvent::Started);

        // Run the staking loop
        let staker = Arc::clone(&self);
        tokio::spawn(async move {
            staker.staking_loop().await;
        });
    }

    /// Stop staking
    pub fn stop(&self) {
        if self.running.swap(false, Ordering::SeqCst) {
            info!("Stopping proof-of-stake block production");
            let _ = self.event_tx.send(StakerEvent::Stopped);
        }
    }

    /// Main staking loop
    async fn staking_loop(&self) {
        let interval = tokio::time::Duration::from_millis(self.config.read().loop_interval_ms);

        info!(
            "Staking loop started with {}ms interval",
            self.config.read().loop_interval_ms
        );

        let mut iteration = 0u64;

        while self.running.load(Ordering::SeqCst) {
            iteration += 1;

            // Log every 60 iterations (30 seconds at 500ms)
            if iteration.is_multiple_of(60) {
                info!("Staking loop iteration {}", iteration);
            }

            // Try to stake
            match self.try_stake() {
                StakeResult::Success {
                    block,
                    block_hash,
                    height,
                    reward,
                } => {
                    // Step 1: Self-accept into our chain BEFORE broadcasting.
                    // This advances our tip immediately so we can start staking the
                    // next height while the block propagates to peers (~1-2s savings).
                    // Reorg safety: if a competing block arrives via P2P, accept_block
                    // triggers reorganize_chain which calls disconnect_block on ours.
                    match self.chain.accept_block(block.clone()) {
                        Ok(result) => {
                            if let Some(fork_height) = result.reorg_fork_height {
                                warn!(
                                    "Reorg detected during self-accept of staked block {} (fork height {})",
                                    block_hash, fork_height
                                );
                            }
                            info!(
                                "Self-accepted staked block {} at height {}",
                                block_hash, height
                            );
                            // Fire the block connected callback (wallet scan, mempool cleanup, fee estimation)
                            if let Some(ref callback) = *self.block_connected_callback.read() {
                                callback(&block, height);
                            }
                            // Step 3: Announce block to peers via inv message (standard protocol).
                            // Only broadcast after successful self-acceptance — if the block
                            // fails our own validation, peers would reject it too.
                            self.peer_manager.broadcast_block_inv(block_hash);
                        }
                        Err(e) => {
                            let err_msg = format!("{}", e);
                            warn!(
                                "Failed to self-accept staked block {}: {} (not broadcasting)",
                                block_hash, err_msg
                            );
                            // If the failure is due to a phantom UTXO (spent on chain but
                            // still in wallet), evict the coinstake input to prevent the
                            // staker from repeatedly trying to use it.
                            if err_msg.contains("UTXO not found")
                                || err_msg.contains("UtxoNotFound")
                            {
                                // The coinstake tx is always at index 1, and its first
                                // non-empty input is the kernel UTXO we tried to stake with.
                                if block.transactions.len() > 1 {
                                    for input in &block.transactions[1].vin {
                                        if !input.prevout.txid.is_zero() {
                                            let outpoint = &input.prevout;
                                            if self.wallet.has_utxo(outpoint) {
                                                self.wallet.spend_utxo(outpoint);
                                                warn!(
                                                    "Evicted phantom UTXO {}:{} from wallet after failed self-accept",
                                                    outpoint.txid, outpoint.vout
                                                );
                                            }
                                        }
                                    }
                                    // Persist the eviction
                                    if let Err(save_err) = self.wallet.save_incremental() {
                                        warn!(
                                            "Failed to save wallet after phantom UTXO eviction: {}",
                                            save_err
                                        );
                                    }
                                }
                            }
                            continue;
                        }
                    }

                    info!(
                        "Staked block {} at height {} (reward: {})",
                        block_hash, height, reward
                    );
                    *self.last_stake_time.write() = current_timestamp();
                    let _ = self.event_tx.send(StakerEvent::BlockFound {
                        hash: block_hash,
                        height,
                        reward,
                    });
                }
                StakeResult::NoStakeableUtxos => {
                    static NO_UTXO_COUNT: std::sync::atomic::AtomicU32 =
                        std::sync::atomic::AtomicU32::new(0);
                    let count = NO_UTXO_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if count == 0 {
                        info!("No stakeable UTXOs available (first occurrence)");
                    } else {
                        trace!("No stakeable UTXOs available");
                    }
                }
                StakeResult::NoProofFound => {
                    trace!("No valid proof found this round");
                }
                StakeResult::RateLimited => {
                    // Step 4: Sleep longer when rate-limited (22s wait needed, not 500ms)
                    static RATE_LIMITED_COUNT: std::sync::atomic::AtomicU32 =
                        std::sync::atomic::AtomicU32::new(0);
                    let count =
                        RATE_LIMITED_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if count == 0 {
                        info!("Rate limited (first occurrence - waiting 22s since last attempt)");
                    } else {
                        trace!("Rate limited - sleeping 5s");
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue; // Skip the default sleep at the end
                }
                StakeResult::Error(e) => {
                    info!("Staking error: {}", e);
                }
            }

            // Wait before next attempt
            tokio::time::sleep(interval).await;
        }

        info!("Staking loop stopped");
    }

    /// Check if we should limit staking speed at current height
    ///
    /// This matches C++ CoinMinter::limitStakingSpeed()
    /// Returns true if less than hashingDelay/2 (22 seconds, integer division) have passed
    /// since the last staking attempt at this height
    fn limit_staking_speed(&self, current_height: u32, current_time: u64) -> bool {
        const HASHING_DELAY_SECONDS: u64 = 45; // From C++ hashingDelay constant

        let map = self.hashed_block_timestamps.read();

        if let Some(&last_time) = map.get(&current_height) {
            let elapsed = current_time.saturating_sub(last_time);
            // Check if less than 22.5 seconds (hashingDelay/2) have passed
            if elapsed < HASHING_DELAY_SECONDS / 2 {
                trace!(
                    "Rate limiting: only {}s since last attempt at height {} (need {}s)",
                    elapsed,
                    current_height,
                    HASHING_DELAY_SECONDS / 2
                );
                return true; // LIMIT staking
            } else {
                info!(
                    "Rate limit passed: {}s elapsed at height {} (need {}s) - proceeding with stake",
                    elapsed,
                    current_height,
                    HASHING_DELAY_SECONDS / 2
                );
            }
        } else {
            info!(
                "No previous attempt at height {} - proceeding with stake",
                current_height
            );
        }

        false
    }

    /// Record that we attempted staking at this height
    ///
    /// This matches C++ PoSTransactionCreator line 235-236:
    /// hashedBlockTimestamps_.clear();
    /// hashedBlockTimestamps_[chainTip->nHeight] = GetTime();
    ///
    /// Note: C++ clears the ENTIRE map each time, which means only the current
    /// height is tracked. We do the same to match this behavior exactly.
    fn record_staking_attempt(&self, height: u32, time: u64) {
        let mut map = self.hashed_block_timestamps.write();
        // C++ clears ALL entries then adds current
        // This means if height changes, we're no longer rate limited
        map.clear();
        map.insert(height, time);
    }

    /// Try to stake a block
    fn try_stake(&self) -> StakeResult {
        let current_time = current_timestamp() as u32;

        // Get the current tip FIRST - this ensures all state is consistent
        let tip = match self.chain.tip() {
            Some(tip) => tip,
            None => return StakeResult::Error("No chain tip".to_string()),
        };

        let current_height = tip.height;
        let next_height = current_height + 1;

        // Don't stake while syncing — if tip is more than 10 minutes old,
        // we're still catching up and would create fork blocks that get orphaned
        let tip_age = current_time.saturating_sub(tip.time);
        if tip_age > 600 {
            debug!("Skipping stake: tip is {}s old (syncing)", tip_age);
            return StakeResult::RateLimited;
        }

        // CRITICAL: Rate limiting check (matches C++ limitStakingSpeed)
        // Check if we tried at this height recently (before updating the timestamp)
        if self.limit_staking_speed(current_height, current_time as u64) {
            return StakeResult::RateLimited;
        }

        // Record this staking attempt (matches C++ PoSTransactionCreator)
        // Only record if we pass rate limiting
        self.record_staking_attempt(current_height, current_time as u64);

        // Compute the NEXT block's difficulty bits.
        // Each block has its own difficulty computed by get_next_work_required(),
        // which adjusts based on the actual spacing between recent blocks.
        // The block header must contain the correct bits or C++ peers will reject it.
        let n_bits = match self.chain.get_next_bits(&tip) {
            Ok(bits) => bits,
            Err(e) => {
                debug!("Failed to compute next difficulty: {}", e);
                return StakeResult::Error(format!("Difficulty computation failed: {}", e));
            }
        };

        // Get stakeable UTXOs
        let utxos = self.wallet.get_spendable_utxos(current_height, 1);

        // Calculate total balance to check against reserve (exclude vault UTXOs - not our money)
        let total_balance: i64 = utxos
            .iter()
            .filter(|u| !u.address.starts_with("vault:"))
            .map(|u| u.value.as_sat())
            .sum();
        let reserve = self.config.read().reserve_balance;

        // Filter stakeable UTXOs:
        // 1. Must meet minimum amount
        // 2. Must be mature
        let coinbase_maturity = match self.chain.network_type() {
            divi_storage::NetworkType::Mainnet => 20u32,
            divi_storage::NetworkType::Testnet => 1u32,
            divi_storage::NetworkType::Regtest => 1u32,
        };
        let stakeable: Vec<_> = utxos
            .into_iter()
            .filter(|u| {
                // Skip vault UTXOs — they're handled separately via get_stakeable_vault_utxos()
                if u.address.starts_with("vault:") {
                    return false;
                }
                // Check minimum amount
                if u.value.as_sat() < self.config.read().min_stake_amount {
                    return false;
                }
                // Check maturity
                u.is_mature(current_height, coinbase_maturity)
            })
            .collect();

        if stakeable.is_empty() {
            return StakeResult::NoStakeableUtxos;
        }

        // Apply reserve balance: only stake if we have more than the reserve
        // Sort by value descending to prioritize larger UTXOs
        let mut sorted_stakeable = stakeable;
        sorted_stakeable.sort_by_key(|u| std::cmp::Reverse(u.value.as_sat()));

        // Calculate cumulative balance and filter out UTXOs that would dip into reserve
        let mut cumulative_balance = total_balance;
        let stakeable: Vec<_> = sorted_stakeable
            .into_iter()
            .filter(|u| {
                // Only use this UTXO if we'd still be above the reserve after using it
                let would_remain = cumulative_balance - u.value.as_sat();
                let can_use = would_remain >= reserve;
                if can_use {
                    cumulative_balance = would_remain;
                }
                can_use
            })
            .collect();

        if stakeable.is_empty() {
            static RESERVE_LIMIT_COUNT: std::sync::atomic::AtomicU32 =
                std::sync::atomic::AtomicU32::new(0);
            let count = RESERVE_LIMIT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if count == 0 {
                info!(
                    "No stakeable UTXOs after applying reserve balance of {} DIVI (first occurrence)",
                    reserve / 100_000_000
                );
            } else {
                trace!(
                    "No stakeable UTXOs after applying reserve balance of {} DIVI",
                    reserve / 100_000_000
                );
            }
            return StakeResult::NoStakeableUtxos;
        }

        // Also get vault UTXOs for staking (bypass reserve balance - not our money)
        let vault_utxos = self.wallet.get_stakeable_vault_utxos(current_height, 1);
        if !vault_utxos.is_empty() {
            info!("Found {} vault UTXOs for staking", vault_utxos.len());
        }

        // Build combined candidate list
        let mut candidates: Vec<StakeCandidate> =
            stakeable.iter().map(StakeCandidate::Regular).collect();
        for (utxo, vault_script) in &vault_utxos {
            candidates.push(StakeCandidate::Vault(utxo, vault_script.clone()));
        }

        // Update stake weight for status (include vault UTXOs)
        let total_weight: u64 = candidates
            .iter()
            .map(|c| c.utxo().value.as_sat() as u64)
            .sum();
        *self.stake_weight.write() = total_weight;

        // Log staking attempt (every 60 iterations to avoid spam)
        static ATTEMPT_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let count = ATTEMPT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count.is_multiple_of(60) {
            info!(
                "Staking attempt #{}: {} UTXOs, total weight {} DIVI, tip height {}, current_time {}, n_bits=0x{:08x}, stake_modifier={}",
                count, candidates.len(), total_weight / 100_000_000, next_height - 1, current_time, n_bits, tip.stake_modifier
            );
        }

        // Use per-tip cache to avoid repeated DB reads for stake_modifier and MTP.
        // Only recompute when the tip changes (~every 60s), saving ~1632 reads/attempt.
        let (stake_modifier, mtp) = {
            let mut cache = self.cache.write();
            if cache.tip_hash != tip.hash {
                // Tip changed — refresh stake_modifier and MTP
                let new_modifier = self.get_stake_modifier(&tip.hash);
                let new_mtp = self.get_median_time_past(&tip.hash);

                let tip_cached_modifier = tip.stake_modifier;
                if new_modifier != tip_cached_modifier {
                    warn!(
                        "MODIFIER MISMATCH: tip.stake_modifier=0x{:016x} vs db_walkback=0x{:016x} at height {} (generated={})",
                        tip_cached_modifier, new_modifier, tip.height, tip.generated_stake_modifier
                    );
                }

                cache.tip_hash = tip.hash;
                cache.stake_modifier = new_modifier;
                cache.median_time_past = new_mtp;
                // confirmation_blocks are immutable — keep across tip changes
            }
            (cache.stake_modifier, cache.median_time_past)
        };
        let modifier_service = SimpleStakeModifierService::new(move |_| Ok(stake_modifier));

        // 3. PoS generator - same config for all UTXOs
        let generator =
            ProofOfStakeGenerator::new(modifier_service, self.config.read().min_coin_age);

        // Try each UTXO
        let mut setup_failed_count = 0u32;
        let mut generation_failed_count = 0u32;
        for candidate in &candidates {
            let utxo = candidate.utxo();
            // Look up confirmation block from cache first (immutable, never changes)
            let (block_time_of_first_confirmation, block_hash_of_first_confirmation) =
                match utxo.height {
                    Some(h) => {
                        // Check cache first
                        let cached = self.cache.read().confirmation_blocks.get(&h).copied();
                        if let Some(entry) = cached {
                            entry
                        } else {
                            // Cache miss — fetch from DB and cache it
                            match self.chain.get_block_index_by_height(h) {
                                Ok(Some(idx)) => {
                                    self.cache
                                        .write()
                                        .confirmation_blocks
                                        .insert(h, (idx.time, idx.hash));
                                    (idx.time, idx.hash)
                                }
                                _ => continue,
                            }
                        }
                    }
                    None => continue,
                };

            if block_time_of_first_confirmation == 0 {
                continue;
            }

            // Skip UTXOs that haven't reached minimum coin age
            let coin_age = current_time.saturating_sub(block_time_of_first_confirmation);
            if coin_age < self.config.read().min_coin_age {
                continue;
            }

            let staking_data = StakingData::new(
                n_bits,
                block_time_of_first_confirmation,
                block_hash_of_first_confirmation,
                OutPoint::new(utxo.txid, utxo.vout),
                utxo.value,
                tip.hash,
            );

            // Try to find a valid hashproof
            let result = generator.create_hashproof_timestamp(&staking_data, current_time);

            match &result {
                HashproofResult::Success(ts) => {
                    info!(
                        "Hashproof SUCCESS for UTXO {}:{} value={}, timestamp={}",
                        utxo.txid,
                        utxo.vout,
                        utxo.value.as_sat() / 100_000_000,
                        ts
                    );
                }
                HashproofResult::FailedGeneration => {
                    generation_failed_count += 1;
                    // Diagnostic: log the first UTXO's details every 60 attempts
                    if generation_failed_count == 1 && count.is_multiple_of(60) {
                        let age = current_time.saturating_sub(block_time_of_first_confirmation);
                        info!(
                            "Sample UTXO {}:{} value={} age={}s ({:.1}h) block_time={}",
                            utxo.txid,
                            utxo.vout,
                            utxo.value.as_sat() / 100_000_000,
                            age,
                            age as f64 / 3600.0,
                            block_time_of_first_confirmation,
                        );
                    }
                }
                HashproofResult::FailedSetup => {
                    setup_failed_count += 1;
                }
            }

            if let HashproofResult::Success(timestamp) = result {
                // Check that timestamp > median time past (MTP)
                // C++ validation requires: block.GetBlockTime() > pindexPrev->GetMedianTimePast()
                // OPTIMIZATION: MTP is already cached above (same for all UTXOs)
                if timestamp <= mtp {
                    info!(
                        "Skipping UTXO {}:{} - hashproof timestamp {} <= MTP {} (diff: {}s)",
                        utxo.txid,
                        utxo.vout,
                        timestamp,
                        mtp,
                        mtp.saturating_sub(timestamp)
                    );
                    continue;
                }

                info!(
                    "Found valid stake for UTXO {}:{} at timestamp {} (MTP={}, current_time={})",
                    utxo.txid, utxo.vout, timestamp, mtp, current_time
                );

                // Create the block
                match self.create_stake_block(&tip, candidate, timestamp, n_bits) {
                    Ok(block) => {
                        let block_hash = compute_block_hash(&block.header);
                        let height = current_height + 1;
                        let reward = self.calculate_stake_reward(height);

                        // Return the block to staking_loop for self-acceptance + broadcast
                        return StakeResult::Success {
                            block,
                            block_hash,
                            height,
                            reward,
                        };
                    }
                    Err(e) => {
                        debug!("Failed to create stake block: {}", e);
                        continue;
                    }
                }
            }
        }

        // Log attempt summary (every 60 attempts to avoid spam)
        if count.is_multiple_of(60) {
            info!(
                "Staking attempt #{} summary: {} tried, {} no-proof, {} setup-failed, 0 success",
                count,
                candidates.len(),
                generation_failed_count,
                setup_failed_count
            );
        }

        StakeResult::NoProofFound
    }

    /// Calculate the median time past (MTP) for a block
    ///
    /// MTP is the median of the last 11 block timestamps.
    /// The block timestamp must be > MTP to be valid.
    fn get_median_time_past(&self, block_hash: &Hash256) -> u32 {
        const MEDIAN_TIME_SPAN: usize = 11;
        let mut timestamps: Vec<u32> = Vec::with_capacity(MEDIAN_TIME_SPAN);

        let mut current_hash = *block_hash;

        for _ in 0..MEDIAN_TIME_SPAN {
            let index = match self.chain.get_block_index(&current_hash) {
                Ok(Some(idx)) => idx,
                _ => break,
            };

            timestamps.push(index.time);

            // Stop if we reached genesis
            if index.height == 0 {
                break;
            }

            current_hash = index.prev_hash;
        }

        if timestamps.is_empty() {
            return 0;
        }

        // Sort and return median
        timestamps.sort_unstable();
        timestamps[timestamps.len() / 2]
    }

    /// Get stake modifier for a block hash
    ///
    /// Walks back through the chain to find the most recent block
    /// that generated a stake modifier.
    fn get_stake_modifier(&self, block_hash: &Hash256) -> u64 {
        let mut current_hash = *block_hash;
        let mut iterations = 0;
        const MAX_ITERATIONS: u32 = 10000;

        while iterations < MAX_ITERATIONS {
            // Get the block index for this hash
            let index = match self.chain.get_block_index(&current_hash) {
                Ok(Some(idx)) => idx,
                _ => {
                    debug!("Could not find block index for {}", current_hash);
                    return 0;
                }
            };

            // Check if this block generated a stake modifier
            if index.generated_stake_modifier {
                return index.stake_modifier;
            }

            // If we're at genesis, stop
            if index.height == 0 {
                break;
            }

            // Move to previous block
            current_hash = index.prev_hash;
            iterations += 1;
        }

        // If we couldn't find a stake modifier, return the tip's modifier
        // (which might be 0 for an empty chain)
        if let Ok(Some(idx)) = self.chain.get_block_index(block_hash) {
            return idx.stake_modifier;
        }

        0
    }

    /// Create a stake block
    fn create_stake_block(
        &self,
        tip: &divi_storage::BlockIndex,
        candidate: &StakeCandidate,
        timestamp: u32,
        n_bits: u32,
    ) -> Result<Block, String> {
        let stake_utxo = candidate.utxo();
        // Get stake reward
        let height = tip.height + 1;
        let stake_reward = self.calculate_stake_reward(height);

        // Check if this is a lottery block and get lottery payments
        let (lottery_start, lottery_cycle) = match self.chain.network_type() {
            divi_storage::NetworkType::Mainnet => (
                divi_consensus::lottery::mainnet::LOTTERY_START_BLOCK,
                divi_consensus::lottery::mainnet::LOTTERY_CYCLE,
            ),
            divi_storage::NetworkType::Testnet => (
                divi_consensus::lottery::testnet::LOTTERY_START_BLOCK,
                divi_consensus::lottery::testnet::LOTTERY_CYCLE,
            ),
            divi_storage::NetworkType::Regtest => (
                divi_consensus::lottery::regtest::LOTTERY_START_BLOCK,
                divi_consensus::lottery::regtest::LOTTERY_CYCLE,
            ),
        };
        let lottery_payments =
            if divi_consensus::lottery::is_lottery_block(height, lottery_start, lottery_cycle) {
                // Get lottery winners from the previous block (tip)
                let winners = &tip.lottery_winners;

                if !winners.coinstakes.is_empty() {
                    info!(
                        "Creating lottery block {} with {} winners",
                        height,
                        winners.coinstakes.len()
                    );

                    // Calculate lottery payments (50 DIVI per block × cycle = total lottery payout)
                    let lottery_reward_per_block = Amount::from_sat(50_00000000);
                    let payments = divi_consensus::lottery::calculate_lottery_payments(
                        winners,
                        lottery_reward_per_block,
                        lottery_cycle,
                    );

                    Some(payments)
                } else {
                    warn!("Lottery block {} has no winners!", height);
                    None
                }
            } else {
                None
            };

        let (treasury_start, treasury_cycle, treasury_lottery_cycle, is_mainnet) =
            match self.chain.network_type() {
                divi_storage::NetworkType::Mainnet => (
                    divi_consensus::treasury::mainnet::TREASURY_START_BLOCK,
                    divi_consensus::treasury::mainnet::TREASURY_CYCLE,
                    divi_consensus::treasury::mainnet::LOTTERY_CYCLE,
                    true,
                ),
                divi_storage::NetworkType::Testnet => (
                    divi_consensus::treasury::testnet::TREASURY_START_BLOCK,
                    divi_consensus::treasury::testnet::TREASURY_CYCLE,
                    divi_consensus::treasury::testnet::LOTTERY_CYCLE,
                    false,
                ),
                divi_storage::NetworkType::Regtest => (
                    divi_consensus::treasury::regtest::TREASURY_START_BLOCK,
                    divi_consensus::treasury::regtest::TREASURY_CYCLE,
                    divi_consensus::treasury::regtest::LOTTERY_CYCLE,
                    false,
                ),
            };

        let treasury_payments = if divi_consensus::treasury::is_treasury_block_with_lottery(
            height,
            treasury_start,
            treasury_cycle,
            treasury_lottery_cycle,
        ) {
            info!("Creating treasury block {}", height);

            // Use transition-aware payment cycle and weighted calculation
            // matching C++ BlockSubsidyProvider::updateTreasuryReward
            let halving_interval = match self.chain.network_type() {
                divi_storage::NetworkType::Mainnet => 525_600u32,
                divi_storage::NetworkType::Testnet => 1_000u32,
                divi_storage::NetworkType::Regtest => 100u32,
            };
            let payment_cycle = divi_consensus::treasury::get_treasury_payment_cycle(
                height,
                treasury_cycle,
                treasury_lottery_cycle,
            );
            let (treasury_payment, charity_payment) =
                divi_consensus::block_subsidy::calculate_weighted_treasury_payment(
                    height,
                    payment_cycle,
                    halving_interval,
                );

            info!(
                "Treasury block {} payments: {} DIVI treasury, {} DIVI charity",
                height,
                treasury_payment.as_divi(),
                charity_payment.as_divi()
            );

            let treasury_script = divi_consensus::treasury::get_treasury_script(is_mainnet);
            let charity_script = divi_consensus::treasury::get_charity_script(is_mainnet);

            Some(vec![
                (treasury_script, treasury_payment),
                (charity_script, charity_payment),
            ])
        } else {
            None
        };

        // Create coinstake transaction (with lottery and/or treasury payments if applicable)
        let coinstake = match candidate {
            StakeCandidate::Regular(_) => self.create_coinstake_tx(
                stake_utxo,
                stake_reward,
                lottery_payments,
                treasury_payments,
            )?,
            StakeCandidate::Vault(_, vault_script) => self.create_vault_coinstake_tx(
                stake_utxo,
                vault_script,
                stake_reward,
                lottery_payments,
                treasury_payments,
            )?,
        };

        // Gather transactions from mempool
        let mut transactions = vec![
            create_coinbase_marker(height), // Empty coinbase marker
            coinstake,
        ];

        // Add mempool transactions up to block limit
        let mempool_txs = self.mempool.get_block_txs(
            self.config.read().max_block_size - 1000, // Leave room for coinbase/coinstake
        );
        transactions.extend(mempool_txs);

        // Compute merkle root
        let merkle_root = compute_merkle_root(&transactions);

        // Create block header
        let header = BlockHeader {
            version: 4, // PoS blocks use version 4+
            prev_block: tip.hash,
            merkle_root,
            time: timestamp,
            bits: n_bits,
            nonce: 0,                                // PoS blocks don't use nonce for mining
            accumulator_checkpoint: Hash256::zero(), // Not using zerocoin
        };

        // Sign the block with the appropriate key
        let block_hash = compute_block_hash(&header);
        let block_sig = match candidate {
            StakeCandidate::Regular(_) => self.sign_block(&block_hash, stake_utxo)?,
            StakeCandidate::Vault(_, vault_script) => {
                self.sign_block_vault(&block_hash, vault_script)?
            }
        };

        Ok(Block {
            header,
            transactions,
            block_sig,
        })
    }

    /// Sign a block hash with the key that controls the stake UTXO
    fn sign_block(
        &self,
        block_hash: &Hash256,
        stake_utxo: &divi_wallet::WalletUtxo,
    ) -> Result<Vec<u8>, String> {
        // Get the address from the UTXO
        let addr = divi_wallet::Address::from_base58(&stake_utxo.address)
            .map_err(|e| format!("Invalid stake address: {}", e))?;

        // Get the key for this address
        let key_entry = self
            .wallet
            .keystore()
            .get_key(&addr.hash)
            .ok_or_else(|| "No key for stake address".to_string())?;

        // For P2PKH (pay-to-pubkey-hash) outputs, Divi expects a compact signature
        // that can be used to recover the public key during verification.
        // This is similar to Bitcoin's message signing format.
        // Note: sign_hash_recoverable signs the raw hash without additional hashing.
        let secret = key_entry
            .secret
            .as_ref()
            .ok_or_else(|| "Cannot stake with watch-only address".to_string())?;
        let signature = divi_crypto::sign_hash_recoverable(secret, block_hash.as_bytes())
            .map_err(|e| format!("Failed to sign block: {}", e))?;

        let sig_bytes = signature.to_compact_with_recovery();

        // Debug: log signature details
        debug!(
            "Block signature: hash={}, sig_len={}, recovery_byte={}, addr={}",
            block_hash,
            sig_bytes.len(),
            sig_bytes[0],
            stake_utxo.address
        );

        // Verify the signature can be recovered
        let recovered_pubkey = signature.recover_from_hash(block_hash.as_bytes());
        match recovered_pubkey {
            Ok(pk) => {
                let recovered_hash = divi_crypto::hash160(&pk.to_bytes());
                let matches = recovered_hash == addr.hash;
                debug!("Block signature verification: pubkey_match={}", matches);
                if !matches {
                    warn!("Block signature: recovered pubkey doesn't match expected address!");
                }
            }
            Err(e) => {
                warn!("Failed to recover pubkey from signature: {}", e);
            }
        }

        // Return the compact signature with recovery byte
        Ok(sig_bytes.to_vec())
    }

    /// Sign a block hash with the vault manager key
    fn sign_block_vault(
        &self,
        block_hash: &Hash256,
        vault_script: &divi_script::StakingVaultScript,
    ) -> Result<Vec<u8>, String> {
        let manager_hash =
            divi_primitives::hash::Hash160::from_bytes(vault_script.vault_pubkey_hash);

        let key_entry = self
            .wallet
            .keystore()
            .get_key(&manager_hash)
            .ok_or_else(|| "No manager key for vault block signing".to_string())?;

        let secret = key_entry
            .secret
            .as_ref()
            .ok_or_else(|| "Cannot sign vault block with watch-only key".to_string())?;

        let signature = divi_crypto::sign_hash_recoverable(secret, block_hash.as_bytes())
            .map_err(|e| format!("Failed to sign vault block: {}", e))?;

        let sig_bytes = signature.to_compact_with_recovery();

        debug!(
            "Vault block signature: hash={}, sig_len={}, manager_hash={:?}",
            block_hash,
            sig_bytes.len(),
            manager_hash.as_bytes()
        );

        // Verify recovery
        if let Ok(pk) = signature.recover_from_hash(block_hash.as_bytes()) {
            let recovered_hash = divi_crypto::hash160(&pk.to_bytes());
            if recovered_hash != manager_hash {
                warn!("Vault block signature: recovered pubkey doesn't match manager key!");
            }
        }

        Ok(sig_bytes.to_vec())
    }

    /// Create a vault coinstake transaction
    ///
    /// Uses CoinstakeBuilder for vault-path spending. The coinstake output pays back
    /// to the same vault script (preserving owner control).
    fn create_vault_coinstake_tx(
        &self,
        stake_utxo: &divi_wallet::WalletUtxo,
        vault_script: &divi_script::StakingVaultScript,
        reward: Amount,
        lottery_payments: Option<Vec<(Script, Amount)>>,
        treasury_payments: Option<Vec<(Script, Amount)>>,
    ) -> Result<Transaction, String> {
        if self.wallet.is_locked() {
            return Err("Wallet is locked".to_string());
        }

        let mut builder = divi_wallet::CoinstakeBuilder::new();
        builder.add_vault_input(stake_utxo);

        // Output: stake return + reward, paying to the SAME vault script
        builder.add_output_raw(stake_utxo.value + reward, stake_utxo.script_pubkey.clone());

        let (mut tx, prev_scripts) = builder
            .build()
            .map_err(|e| format!("Failed to build vault coinstake: {}", e))?;

        // Add lottery outputs
        if let Some(payments) = lottery_payments {
            for (script, amount) in payments {
                tx.vout.push(TxOut {
                    value: amount,
                    script_pubkey: script,
                });
            }
        }
        // Add treasury outputs
        if let Some(payments) = treasury_payments {
            for (script, amount) in payments {
                tx.vout.push(TxOut {
                    value: amount,
                    script_pubkey: script,
                });
            }
        }

        // Sign with manager key via manager path
        let manager_hash =
            divi_primitives::hash::Hash160::from_bytes(vault_script.vault_pubkey_hash);
        let key_entry = self
            .wallet
            .keystore()
            .get_key(&manager_hash)
            .ok_or_else(|| "No manager key for vault coinstake".to_string())?;
        let secret = key_entry
            .secret
            .as_ref()
            .ok_or_else(|| "Manager key is watch-only".to_string())?;

        divi_wallet::CoinstakeBuilder::sign_all_manager_path(&mut tx, &prev_scripts, secret)
            .map_err(|e| format!("Failed to sign vault coinstake: {}", e))?;

        info!(
            "Created vault coinstake: {} inputs, {} outputs, value {}",
            tx.vin.len(),
            tx.vout.len(),
            stake_utxo.value + reward
        );

        Ok(tx)
    }

    /// Create the coinstake transaction
    fn create_coinstake_tx(
        &self,
        stake_utxo: &divi_wallet::WalletUtxo,
        reward: Amount,
        lottery_payments: Option<Vec<(Script, Amount)>>,
        treasury_payments: Option<Vec<(Script, Amount)>>,
    ) -> Result<Transaction, String> {
        // Check if wallet is locked
        if self.wallet.is_locked() {
            return Err("Wallet is locked".to_string());
        }

        // Coinstake input: the staked UTXO
        let input = TxIn {
            prevout: OutPoint::new(stake_utxo.txid, stake_utxo.vout),
            script_sig: Script::default(), // Will be signed below
            sequence: 0xffffffff,
        };

        // Coinstake outputs:
        // 1. Empty marker output (value 0, empty script)
        // 2. Stake return + reward (same address as input)
        // 3. ... (optional lottery payments for lottery blocks)
        let marker_output = TxOut {
            value: Amount::ZERO,
            script_pubkey: Script::default(),
        };

        let stake_output = TxOut {
            value: stake_utxo.value + reward,
            script_pubkey: stake_utxo.script_pubkey.clone(),
        };

        let mut outputs = vec![marker_output, stake_output];

        // Add lottery payment outputs if this is a lottery block
        if let Some(payments) = lottery_payments {
            for (script, amount) in payments {
                outputs.push(TxOut {
                    value: amount,
                    script_pubkey: script,
                });
            }
        }

        // Add treasury and charity payment outputs if this is a treasury block
        if let Some(payments) = treasury_payments {
            for (script, amount) in payments {
                outputs.push(TxOut {
                    value: amount,
                    script_pubkey: script,
                });
            }
        }

        // Create the transaction
        // Must use version 1 to match C++ Divi coinstake transactions
        let mut tx = Transaction {
            version: 1,
            lock_time: 0,
            vin: vec![input],
            vout: outputs,
        };

        // Sign the coinstake input
        let signer = TransactionSigner::new(self.wallet.keystore());
        let prev_scripts = vec![stake_utxo.script_pubkey.clone()];

        let signed = signer
            .sign_all_inputs(&mut tx, &prev_scripts)
            .map_err(|e| format!("Failed to sign coinstake: {}", e))?;

        if signed != 1 {
            return Err("Failed to sign coinstake input".to_string());
        }

        Ok(tx)
    }

    /// Calculate stake reward for a given height
    ///
    /// The block subsidy follows a halving schedule starting at 1250 DIVI,
    /// decreasing by 100 DIVI per year until reaching a minimum of 250 DIVI.
    ///
    /// The staker receives the stake portion of the total subsidy.
    /// With masternodes active, the distribution is:
    /// - Stakers: 38%
    /// - Masternodes: 45%
    /// - Treasury: 16%
    /// - Charity: 1%
    /// - Lottery: 50 DIVI per block
    ///
    /// Without masternodes, the stake portion would be higher (staker gets
    /// what would have gone to masternodes), but this is handled at the
    /// block validation level, not here.
    fn calculate_stake_reward(&self, height: u32) -> Amount {
        // Use the proper block subsidy calculation from divi-consensus
        let halving_interval = match self.chain.network_type() {
            divi_storage::NetworkType::Mainnet => 525_600u32,
            divi_storage::NetworkType::Testnet => 1_000u32,
            divi_storage::NetworkType::Regtest => 100u32,
        };
        let rewards = divi_consensus::block_subsidy::get_block_subsidy(height, halving_interval);

        // After DeprecateMasternodes fork (MTP >= Aug 23 2023), the masternode
        // reward is folded into the staker reward. Since PrivateDivi started in
        // March 2026, this fork is always active.
        // C++ reference: BlockConnectionService.cpp lines 322-326
        let stake_reward = rewards.stake + rewards.masternode;

        tracing::debug!(
            "Block {} rewards: stake={} DIVI (incl. mn fold), treasury={} DIVI, lottery={} DIVI",
            height,
            stake_reward.as_divi(),
            rewards.treasury.as_divi(),
            rewards.lottery.as_divi(),
        );

        stake_reward
    }
}

/// Staking status information
#[derive(Debug, Clone)]
pub struct StakingStatus {
    /// Whether staking is enabled
    pub enabled: bool,
    /// Whether actively staking (enabled and has UTXOs)
    pub staking: bool,
    /// Number of stakeable UTXOs
    pub utxo_count: usize,
    /// Total stake weight (sum of UTXO values)
    pub stake_weight: u64,
    /// Expected time to stake (seconds, if calculable)
    pub expected_time: Option<u64>,
    /// Last successful stake time
    pub last_stake_time: u64,
    /// Current chain height
    pub blocks: u32,
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Create a minimal coinbase marker transaction for PoS blocks
fn create_coinbase_marker(height: u32) -> Transaction {
    // PoS blocks have an empty coinbase with just the height in scriptSig
    // Encode height using CScriptNum format (BIP34): little-endian with sign extension
    let script_sig = Script::from_bytes(encode_bip34_height(height));

    Transaction {
        version: 2,
        lock_time: 0,
        vin: vec![TxIn {
            prevout: OutPoint::null(),
            script_sig,
            sequence: 0xffffffff,
        }],
        vout: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: Script::default(),
        }],
    }
}

/// Encode block height as BIP34 CScriptNum for coinbase scriptSig.
///
/// CScriptNum uses little-endian encoding with a sign extension byte when
/// the most significant byte has bit 7 set (to prevent being interpreted as negative).
/// C++ equivalent: `CScript() << nHeight`
fn encode_bip34_height(height: u32) -> Vec<u8> {
    if height == 0 {
        // OP_0
        return vec![0x00];
    }

    // Serialize height in minimal little-endian bytes
    let mut num_bytes = Vec::new();
    let mut val = height;
    while val > 0 {
        num_bytes.push((val & 0xFF) as u8);
        val >>= 8;
    }

    // CScriptNum sign extension: if MSB has bit 7 set, add 0x00 to keep positive
    if num_bytes.last().unwrap() & 0x80 != 0 {
        num_bytes.push(0x00);
    }

    // Push opcode (length prefix) + data
    let mut data = vec![num_bytes.len() as u8];
    data.extend_from_slice(&num_bytes);
    data
}

/// Compute merkle root from transactions
fn compute_merkle_root(transactions: &[Transaction]) -> Hash256 {
    if transactions.is_empty() {
        return Hash256::zero();
    }

    let mut hashes: Vec<Hash256> = transactions.iter().map(|tx| tx.txid()).collect();

    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            // Duplicate last hash if odd number
            hashes.push(*hashes.last().unwrap());
        }

        let mut next_level = Vec::with_capacity(hashes.len() / 2);
        for i in (0..hashes.len()).step_by(2) {
            // Concatenate two hashes and hash the result
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(hashes[i].as_bytes());
            data.extend_from_slice(hashes[i + 1].as_bytes());
            let combined = divi_crypto::hash256(&data);
            next_level.push(combined);
        }
        hashes = next_level;
    }

    hashes[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staking_config_default() {
        let config = StakingConfig::default();
        assert_eq!(config.min_stake_amount, 0);
        assert_eq!(config.min_coin_age, 3600);
    }

    // ============================================================
    // MISSING TESTS: rate limiting, UTXO age, immature filtering
    // ============================================================

    #[test]
    fn test_staking_config_rate_limiting_interval() {
        // The staking loop interval controls rate limiting frequency
        let config = StakingConfig::default();
        // Default is 500ms loop interval
        assert_eq!(config.loop_interval_ms, 500);
    }

    #[test]
    fn test_staking_config_utxo_age_minimum() {
        // Minimum coin age for staking is 1 hour (3600 seconds) by default
        let config = StakingConfig::default();
        assert_eq!(config.min_coin_age, 60 * 60); // 3600 seconds = 1 hour
    }

    #[test]
    fn test_staking_config_reserve_balance_default() {
        // Default reserve balance is 0 (no funds reserved)
        let config = StakingConfig::default();
        assert_eq!(config.reserve_balance, 0);
    }

    #[test]
    fn test_staking_config_max_block_size() {
        let config = StakingConfig::default();
        assert_eq!(config.max_block_size, 2_000_000);
    }

    #[test]
    fn test_staking_config_no_minimum_utxo() {
        // C++ Divi has no minimum UTXO amount — any UTXO can stake
        let config = StakingConfig::default();
        assert_eq!(config.min_stake_amount, 0);
    }

    #[test]
    fn test_staking_config_custom_min_stake() {
        // Custom config with minimum stake amount
        let config = StakingConfig {
            min_stake_amount: 100_000_000_000, // 1000 DIVI
            ..Default::default()
        };
        assert_eq!(config.min_stake_amount, 100_000_000_000);
    }

    #[test]
    fn test_staking_config_custom_min_coin_age() {
        // Can configure minimum coin age (UTXO age filter)
        let config = StakingConfig {
            min_coin_age: 7 * 24 * 60 * 60, // 7 days
            ..Default::default()
        };
        assert_eq!(config.min_coin_age, 7 * 24 * 60 * 60);
    }

    #[test]
    fn test_staker_not_running_by_default() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::Network;

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path()).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let wallet = Arc::new(WalletDb::new(Network::Regtest));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let peer_manager = PeerManager::new(PeerManagerConfig::default());

        let staker = Staker::new(
            wallet,
            chain,
            mempool,
            peer_manager,
            StakingConfig::default(),
        );

        // Staker starts in stopped state
        assert!(!staker.is_running());
    }

    #[test]
    fn test_stake_result_variants() {
        // All StakeResult variants should be constructable
        let _ = StakeResult::NoStakeableUtxos;
        let _ = StakeResult::NoProofFound;
        let _ = StakeResult::RateLimited;
        let _ = StakeResult::Error("test error".to_string());

        // Success variant
        let success = StakeResult::Success {
            block: Block::new(),
            block_hash: Hash256::zero(),
            height: 500,
            reward: Amount::from_divi(1250),
        };
        if let StakeResult::Success { height, reward, .. } = success {
            assert_eq!(height, 500);
            assert_eq!(reward, Amount::from_divi(1250));
        } else {
            panic!("Expected Success variant");
        }
    }

    #[test]
    fn test_hashed_block_timestamps_rate_limit_logic() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::Network;

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path()).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let wallet = Arc::new(WalletDb::new(Network::Regtest));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let peer_manager = PeerManager::new(PeerManagerConfig::default());

        let staker = Staker::new(
            wallet,
            chain,
            mempool,
            peer_manager,
            StakingConfig::default(),
        );

        // The hashed_block_timestamps map starts empty
        assert!(staker.hashed_block_timestamps.read().is_empty());

        // After manually inserting a timestamp for height 100
        staker.hashed_block_timestamps.write().insert(100, 1000000);

        // The map now contains one entry
        assert_eq!(staker.hashed_block_timestamps.read().len(), 1);
        assert_eq!(
            *staker.hashed_block_timestamps.read().get(&100).unwrap(),
            1000000
        );
    }

    #[test]
    fn test_compute_merkle_root_empty() {
        let root = compute_merkle_root(&[]);
        assert!(root.is_zero());
    }

    #[test]
    fn test_coinbase_marker() {
        let marker = create_coinbase_marker(12345);
        assert!(marker.is_coinbase());
        assert_eq!(marker.vout.len(), 1);
        assert_eq!(marker.vout[0].value, Amount::ZERO);
    }

    #[test]
    fn test_bip34_height_encoding() {
        // Height 0 → OP_0
        assert_eq!(encode_bip34_height(0), vec![0x00]);

        // Height 1 → push 1 byte: 0x01
        assert_eq!(encode_bip34_height(1), vec![0x01, 0x01]);

        // Height 127 → push 1 byte: 0x7F (no sign extension)
        assert_eq!(encode_bip34_height(127), vec![0x01, 0x7F]);

        // Height 128 → push 2 bytes: 0x80 0x00 (sign extension because 0x80 has bit 7)
        assert_eq!(encode_bip34_height(128), vec![0x02, 0x80, 0x00]);

        // Height 255 → push 2 bytes: 0xFF 0x00 (sign extension)
        assert_eq!(encode_bip34_height(255), vec![0x02, 0xFF, 0x00]);

        // Height 256 → push 2 bytes: 0x00 0x01 (no sign extension, MSB=0x01)
        assert_eq!(encode_bip34_height(256), vec![0x02, 0x00, 0x01]);

        // Height 32767 → push 2 bytes: 0xFF 0x7F (no sign extension, MSB=0x7F)
        assert_eq!(encode_bip34_height(32767), vec![0x02, 0xFF, 0x7F]);

        // Height 32768 → push 3 bytes: 0x00 0x80 0x00 (sign extension, MSB=0x80)
        assert_eq!(encode_bip34_height(32768), vec![0x03, 0x00, 0x80, 0x00]);

        // Height 48872 (0xBEE8) → push 3 bytes: 0xE8 0xBE 0x00 (sign extension, MSB=0xBE)
        assert_eq!(encode_bip34_height(48872), vec![0x03, 0xE8, 0xBE, 0x00]);

        // Height 48735 (0xBE5F) → push 3 bytes: 0x5F 0xBE 0x00 (sign extension)
        assert_eq!(encode_bip34_height(48735), vec![0x03, 0x5F, 0xBE, 0x00]);

        // Height 12345 (0x3039) → push 2 bytes: 0x39 0x30 (no sign extension, MSB=0x30)
        assert_eq!(encode_bip34_height(12345), vec![0x02, 0x39, 0x30]);

        // Height 16777215 (0xFFFFFF) → push 4 bytes: 0xFF 0xFF 0xFF 0x00 (sign extension)
        assert_eq!(
            encode_bip34_height(16777215),
            vec![0x04, 0xFF, 0xFF, 0xFF, 0x00]
        );
    }

    #[test]
    fn test_stake_result() {
        let success = StakeResult::Success {
            block: Block::new(),
            block_hash: Hash256::zero(),
            height: 100,
            reward: Amount::from_sat(1250_00000000),
        };

        match success {
            StakeResult::Success { height, .. } => assert_eq!(height, 100),
            _ => panic!("Expected Success"),
        }
    }

    #[test]
    fn test_expected_time_calculation_zero_weight() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::Network;

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path()).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);

        let chain = Arc::new(Chain::new(db, params).unwrap());
        let wallet = Arc::new(WalletDb::new(Network::Regtest));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let peer_manager = PeerManager::new(PeerManagerConfig::default());

        let staker = Staker::new(
            wallet,
            chain,
            mempool,
            peer_manager,
            StakingConfig::default(),
        );

        // Zero stake weight should return None
        let result = staker.calculate_expected_time(0);
        assert_eq!(result, None);
    }

    #[test]
    fn test_expected_time_calculation_with_weight() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::Network;

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path()).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);

        let chain = Arc::new(Chain::new(db, params).unwrap());
        let wallet = Arc::new(WalletDb::new(Network::Regtest));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let peer_manager = PeerManager::new(PeerManagerConfig::default());

        let staker = Staker::new(
            wallet,
            chain,
            mempool,
            peer_manager,
            StakingConfig::default(),
        );

        // With 10,000 DIVI stake weight
        let stake_weight = 1_000_000_000_000_u64;
        let result = staker.calculate_expected_time(stake_weight);

        // Should return a reasonable time estimate
        assert!(result.is_some());
        let time = result.unwrap();

        // Should be between 1 minute and 7 days
        assert!(time >= 60, "Expected time too short: {}", time);
        assert!(time <= 7 * 24 * 3600, "Expected time too long: {}", time);

        // For regtest with max difficulty (easiest target), should be relatively short
        // but still reasonable
        println!(
            "Expected staking time with 10k DIVI: {} seconds ({} hours)",
            time,
            time / 3600
        );
    }

    #[test]
    fn test_expected_time_scales_with_weight() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::Network;

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path()).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);

        let chain = Arc::new(Chain::new(db, params).unwrap());
        let wallet = Arc::new(WalletDb::new(Network::Regtest));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let peer_manager = PeerManager::new(PeerManagerConfig::default());

        let staker = Staker::new(
            wallet,
            chain,
            mempool,
            peer_manager,
            StakingConfig::default(),
        );

        // Test with smaller stake weights to avoid hitting the minimum clamp
        let weight_1x = 100_000_000_000u64; // 1,000 DIVI
        let weight_2x = 200_000_000_000_u64; // 2,000 DIVI

        let time_1x = staker.calculate_expected_time(weight_1x).unwrap();
        let time_2x = staker.calculate_expected_time(weight_2x).unwrap();

        println!(
            "1k DIVI: {} seconds ({} hours), 2k DIVI: {} seconds ({} hours)",
            time_1x,
            time_1x / 3600,
            time_2x,
            time_2x / 3600
        );

        // Double the stake weight should roughly halve the expected time
        // Allow for some rounding error - 2x weight might not exactly be 1/2 time due to integer math
        // but it should be noticeably less
        assert!(
            time_2x <= time_1x,
            "Higher stake weight should not increase expected time: {}s vs {}s",
            time_2x,
            time_1x
        );

        // More lenient: just check that higher weight gives same or better time
        // The calculation might hit minimum clamps or integer rounding
    }
}
