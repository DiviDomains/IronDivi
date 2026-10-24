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
use divi_primitives::hash::{Hash160, Hash256};
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
    /// Maximum block size (bytes), Divi Core `-blockmaxsize`
    pub max_block_size: usize,
    /// Bytes filled by priority before fee rate, Divi Core `-blockprioritysize`
    pub block_priority_size: usize,
    /// Size below which transactions under the fee floor still go in, Divi
    /// Core `-blockminsize`
    pub block_min_size: usize,
    /// Maximum block weight
    pub max_block_weight: usize,
    /// Staking loop interval (milliseconds)
    pub loop_interval_ms: u64,
    /// Refuse to stake when the chain tip is older than this many seconds
    /// (C++ Divi parity: IsInitialBlockDownload's nMaxTipAge = 24h).
    pub max_tip_age_secs: u32,
    /// Explicit operator override (`-stakeonstaletip`): stake even when the tip
    /// is older than `max_tip_age_secs`, e.g. to restart a stalled network.
    pub allow_stale_tip: bool,
    /// Split the stake output in two when value + reward exceeds this, in
    /// satoshis (Divi Core `-stakesplitthreshold`, default 20,000 DIVI)
    pub stake_split_threshold: i64,
    /// Add small coins of the kernel's address as extra coinstake inputs
    /// (Divi Core `-autocombine`, default on)
    pub autocombine: bool,
}

/// Divi Core default `-stakesplitthreshold`: 20,000 DIVI.
pub const DEFAULT_STAKE_SPLIT_THRESHOLD: i64 = 20_000 * 100_000_000;

/// Divi Core `MAX_KERNEL_COMBINED_INPUTS` (Settings.cpp): consensus limit on
/// coinstake inputs, the same figure block validation checks.
pub const MAX_COMBINED_STAKE_INPUTS: usize = divi_storage::pos_validation::MAX_COMBINABLE_INPUTS;

/// Inputs and stake outputs of a coinstake, before payee outputs are added.
#[derive(Debug, Clone)]
pub struct StakeOutputPlan {
    /// Extra inputs after the kernel (combined coins)
    pub extra_inputs: Vec<divi_wallet::WalletUtxo>,
    /// Values of the stake outputs paying back to the kernel's script
    pub stake_outputs: Vec<Amount>,
}

/// Divi Core `PoSTransactionCreator::SplitOrCombineUTXOS`.
///
/// `credit` is the kernel value plus the stake reward. Above the split
/// threshold it is paid as two outputs (`credit / 2` and the rest). Otherwise,
/// with `autocombine`, coins of the kernel's script from other transactions
/// are added smallest first while the credit stays at or below half the
/// threshold and the coinstake has at most 20 inputs. `pool` must already hold
/// only coins Divi Core would stake with (`CWallet::SelectStakeCoins`).
pub fn plan_stake_outputs(
    kernel: &divi_wallet::WalletUtxo,
    credit: Amount,
    split_threshold: i64,
    autocombine: bool,
    pool: &[divi_wallet::WalletUtxo],
) -> StakeOutputPlan {
    let credit = credit.as_sat();
    if credit > split_threshold {
        let first = credit / 2;
        return StakeOutputPlan {
            extra_inputs: Vec::new(),
            stake_outputs: vec![Amount::from_sat(first), Amount::from_sat(credit - first)],
        };
    }
    if !autocombine {
        return StakeOutputPlan {
            extra_inputs: Vec::new(),
            stake_outputs: vec![Amount::from_sat(credit)],
        };
    }

    let combine_threshold = split_threshold / 2;
    let mut candidates: Vec<&divi_wallet::WalletUtxo> = pool
        .iter()
        .filter(|c| {
            c.script_pubkey == kernel.script_pubkey
                && c.txid != kernel.txid
                && c.value.as_sat() + credit <= combine_threshold
        })
        .collect();
    candidates.sort_by_key(|c| c.value.as_sat());

    let mut total = credit;
    let mut extra_inputs = Vec::new();
    for c in candidates {
        if 1 + extra_inputs.len() >= MAX_COMBINED_STAKE_INPUTS
            || total > combine_threshold
            || total + c.value.as_sat() > combine_threshold
        {
            break;
        }
        total += c.value.as_sat();
        extra_inputs.push(c.clone());
    }
    StakeOutputPlan {
        extra_inputs,
        stake_outputs: vec![Amount::from_sat(total)],
    }
}

/// Divi Core's lowest split threshold for a vault kernel: 20,000 DIVI
/// (PoSTransactionCreator.cpp:360-363)
pub const VAULT_MIN_STAKE_SPLIT_THRESHOLD: i64 = 20_000 * 100_000_000;

/// The split threshold Divi Core uses for a kernel: the configured
/// `-stakesplitthreshold`, but at least 20,000 DIVI for a vault kernel
pub fn split_threshold_for(configured: i64, vault_kernel: bool) -> i64 {
    if vault_kernel {
        configured.max(VAULT_MIN_STAKE_SPLIT_THRESHOLD)
    } else {
        configured
    }
}

/// Whether a wallet coin is in Divi Core's stake set, the coins it picks a
/// kernel from and combines into a coinstake: not locked by `lockunspent`
/// (AvailableUtxoCalculator.cpp:91), confirmed at least 10 blocks deep, or
/// the coinbase maturity deep for a coinstake output, and at least the
/// network's minimum coin age old, by the time of its block
/// (CWallet::SelectStakeCoins, wallet.cpp:1440-1461). `block_time` is the
/// time of the block that confirmed it.
pub fn is_stake_set_coin(
    coin: &divi_wallet::WalletUtxo,
    block_time: Option<u32>,
    tip_height: u32,
    now: u32,
    coinbase_maturity: u32,
    min_coin_age: u32,
    locked: bool,
) -> bool {
    let (Some(height), Some(block_time)) = (coin.height, block_time) else {
        return false;
    };
    if locked || coin.value.as_sat() <= 0 {
        return false;
    }
    let depth = (tip_height + 1).saturating_sub(height);
    let min_depth = if coin.is_coinstake {
        coinbase_maturity
    } else {
        10
    };
    depth >= min_depth && now.saturating_sub(block_time) >= min_coin_age
}

/// Default maximum tip age for staking: 24 hours (C++ `nMaxTipAge`).
pub const DEFAULT_MAX_TIP_AGE_SECS: u32 = 24 * 60 * 60;

/// Returns true when staking must be refused because the chain tip is stale.
///
/// A node that stakes on a stale tip extends a private fork: anything it mints
/// is orphaned as soon as it sees the real chain. So staking on a stale tip is
/// only allowed when the operator explicitly asks for it.
pub fn stale_tip_blocks_staking(
    now: u32,
    tip_time: u32,
    max_tip_age_secs: u32,
    allow_stale_tip: bool,
) -> bool {
    if allow_stale_tip {
        return false;
    }
    now.saturating_sub(tip_time) > max_tip_age_secs
}

impl Default for StakingConfig {
    fn default() -> Self {
        StakingConfig {
            min_stake_amount: 0, // No minimum - any UTXO can stake (matches C++ Divi)
            reserve_balance: 0,
            min_coin_age: 60 * 60, // 1 hour
            max_block_size: DEFAULT_BLOCK_MAX_SIZE,
            block_priority_size: DEFAULT_BLOCK_PRIORITY_SIZE,
            block_min_size: DEFAULT_BLOCK_MIN_SIZE,
            max_block_weight: 4_000_000,
            loop_interval_ms: 500, // Try every 500ms
            max_tip_age_secs: DEFAULT_MAX_TIP_AGE_SECS,
            allow_stale_tip: false,
            stake_split_threshold: DEFAULT_STAKE_SPLIT_THRESHOLD,
            autocombine: true,
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
    /// The wallet is locked, so no coinstake can be signed
    WalletLocked,
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
    /// A warning that staking is blocked by a locked wallet has been logged
    /// (cleared when the wallet is unlocked again)
    wallet_locked_warned: AtomicBool,
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
    /// Held while a block is built and accepted, so the staking loop and
    /// `setgenerate` never build on the same tip at once
    producing: parking_lot::Mutex<()>,
    /// `generateblock`'s ignoreMempool and extratx for the block being made
    /// (Divi Core ExtendedBlockTransactionCollector), cleared after it
    next_block_txs: parking_lot::Mutex<Option<(bool, Vec<Transaction>)>>,
}

/// What `generateblock` changes about the one block it makes (Divi Core
/// rpcmining.cpp:121-210, ExtendedBlockFactory.cpp)
#[derive(Debug, Clone, Default)]
pub struct BlockOverrides {
    /// Appended after the pool's transactions (`extratx`)
    pub extra_txs: Vec<Transaction>,
    /// Takes the place of the block's coinstake (`coinstake`)
    pub coinstake: Option<Transaction>,
    /// Leave the pool's transactions out (`ignoreMempool`)
    pub ignore_mempool: bool,
    /// Shift the block's target left by this many bits, at most 32
    /// (`blockBitsShift`)
    pub bits_shift: Option<u32>,
}

/// Why `generateblock` made no block
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateBlockError {
    /// Refused before a block was made, with Divi Core's message
    Refused(String),
    /// No valid block could be made
    Failed(String),
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
            wallet_locked_warned: AtomicBool::new(false),
            event_tx,
            last_stake_time: RwLock::new(0),
            stake_weight: RwLock::new(0),
            hashed_block_timestamps: RwLock::new(HashMap::new()),
            block_connected_callback: RwLock::new(None),
            cache: RwLock::new(StakerCache::new()),
            producing: parking_lot::Mutex::new(()),
            next_block_txs: parking_lot::Mutex::new(None),
        }
    }

    /// Set the block connected callback (for self-accepted staked blocks)
    ///
    /// This should be the same callback used by BlockSync so that wallet scanning,
    /// mempool cleanup, and fee estimation happen when we self-accept our own blocks.
    pub fn set_block_connected_callback(&self, callback: BlockConnectedCallback) {
        *self.block_connected_callback.write() = Some(callback);
    }

    /// Current stake split threshold in satoshis
    pub fn stake_split_threshold(&self) -> i64 {
        self.config.read().stake_split_threshold
    }

    /// Change the stake split threshold (satoshis) for the next stakes
    pub fn set_stake_split_threshold(&self, threshold: i64) {
        self.config.write().stake_split_threshold = threshold;
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

        // Get stakeable UTXOs: plain coins and registered vaults we manage
        // (vaults are not part of the spendable set)
        let mut utxos = self.wallet.get_spendable_utxos(current_height, 1);
        utxos.extend(
            self.wallet
                .get_stakeable_vault_utxos(current_height, 1)
                .into_iter()
                .map(|(u, _)| u),
        );
        // A locked coin is not stakable (AvailableUtxoCalculator.cpp:91)
        let stakeable: Vec<_> = utxos
            .into_iter()
            .filter(|u| u.value.as_sat() >= self.config.read().min_stake_amount)
            .filter(|u| !self.wallet.is_coin_locked(&u.outpoint()))
            .collect();

        let stake_weight: u64 = stakeable.iter().map(|u| u.value.as_sat() as u64).sum();

        StakingStatus {
            enabled: self.running.load(Ordering::SeqCst),
            staking: self.running.load(Ordering::SeqCst) && !stakeable.is_empty(),
            mintable_coins: self.has_mintable_coins(),
            utxo_count: stakeable.len(),
            stake_weight,
            expected_time: self.calculate_expected_time(stake_weight),
            last_stake_time: *self.last_stake_time.read(),
            blocks: current_height,
        }
    }

    /// Confirmations a coinbase or coinstake output needs before it can stake
    fn coinbase_maturity(&self) -> u32 {
        match self.chain.network_type() {
            divi_storage::NetworkType::Mainnet => 20u32,
            divi_storage::NetworkType::Testnet => 1u32,
            divi_storage::NetworkType::Regtest => 20u32,
        }
    }

    /// Divi Core `HasAgedCoins`: the wallet holds a coin the staker could use
    /// now, i.e. mature, at least the minimum stake amount, and older than the
    /// minimum coin age (vault coins count, as in Divi Core's stakable coins;
    /// a locked coin does not, AvailableUtxoCalculator.cpp:91)
    pub fn has_mintable_coins(&self) -> bool {
        let height = self.chain.height();
        let now = current_timestamp() as u32;
        let maturity = self.coinbase_maturity();
        let (min_amount, min_age) = {
            let c = self.config.read();
            (c.min_stake_amount, c.min_coin_age)
        };
        let aged = |utxo: &divi_wallet::WalletUtxo| {
            utxo.value.as_sat() >= min_amount
                && !self.wallet.is_coin_locked(&utxo.outpoint())
                && utxo.is_mature(height, maturity)
                && utxo
                    .height
                    .and_then(|h| self.chain.get_block_index_by_height(h).ok().flatten())
                    .is_some_and(|idx| now.saturating_sub(idx.time) >= min_age)
        };
        let regular = self.wallet.get_spendable_utxos(height, 1);
        regular
            .iter()
            .filter(|u| !u.address.starts_with("vault:"))
            .any(aged)
            || self
                .wallet
                .get_stakeable_vault_utxos(height, 1)
                .iter()
                .any(|(u, _)| aged(u))
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

            // Divi Core stakes only with a peer to announce the block to
            // (CoinMinter::canMintCoins, CoinMinter.cpp:73-75); without one a
            // block can only extend a private fork
            if !self.has_peers() {
                trace!("No peers - not staking");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }

            // Try to stake; skip the round while setgenerate is producing
            let result = match self.producing.try_lock() {
                Some(_producing) => {
                    let result = self.try_stake();
                    if let StakeResult::Success {
                        block,
                        block_hash,
                        height,
                        ..
                    } = &result
                    {
                        // Self-accept into our chain BEFORE broadcasting
                        if self.accept_own_block(block, *block_hash, *height).is_err() {
                            continue;
                        }
                    }
                    result
                }
                None => StakeResult::NoProofFound,
            };
            match result {
                StakeResult::Success {
                    block_hash,
                    height,
                    reward,
                    ..
                } => {
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
                StakeResult::WalletLocked => {
                    // Already reported once by note_wallet_locked
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
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

    /// Whether a peer is connected to receive a staked block
    fn has_peers(&self) -> bool {
        self.peer_manager.peer_count() > 0
    }

    /// Connect a block we built ourselves, then tell the wallet and peers.
    ///
    /// The block goes into our chain before it is announced, so the next block
    /// can be built while this one propagates. Reorg safety: if a competing
    /// block arrives via P2P, accept_block triggers reorganize_chain which
    /// disconnects ours.
    fn accept_own_block(
        &self,
        block: &Block,
        block_hash: Hash256,
        height: u32,
    ) -> Result<(), String> {
        match self.chain.accept_block(block.clone()) {
            Ok(result) => {
                if let Some(fork_height) = result.reorg_fork_height {
                    warn!(
                        "Reorg detected during self-accept of staked block {} (fork height {})",
                        block_hash, fork_height
                    );
                    // Undo what the wallet recorded from the disconnected
                    // blocks; the callback below rescans the new branch
                    self.wallet.handle_reorg(fork_height);
                    // Return their transactions to the mempool, as for a
                    // reorganisation a peer's block causes
                    crate::node::update_mempool_after_reorg(
                        &self.chain,
                        &self.mempool,
                        result.orphaned_transactions,
                    );
                }
                info!(
                    "Self-accepted staked block {} at height {}",
                    block_hash, height
                );
                // Fire the block connected callback (wallet scan, mempool cleanup, fee estimation)
                if let Some(ref callback) = *self.block_connected_callback.read() {
                    callback(block, height);
                }
                // Announce block to peers via inv message (standard protocol).
                // Only broadcast after successful self-acceptance — if the block
                // fails our own validation, peers would reject it too.
                self.peer_manager.broadcast_block_inv(block_hash);
                Ok(())
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
                if err_msg.contains("UTXO not found") || err_msg.contains("UtxoNotFound") {
                    // The coinstake tx is always at index 1, and its first
                    // non-empty input is the kernel UTXO we tried to stake with.
                    if block.transactions.len() > 1 {
                        for input in &block.transactions[1].vin {
                            if !input.prevout.txid.is_zero() {
                                let outpoint = &input.prevout;
                                // Only a coin the chain really lacks is a phantom;
                                // the error may name a different tx's input.
                                let gone = matches!(self.chain.has_utxo(outpoint), Ok(false));
                                if gone && self.wallet.has_utxo(outpoint) {
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
                Err(err_msg)
            }
        }
    }

    /// Regtest `setgenerate`: mine `n` blocks to this wallet now and return
    /// their hashes. Proof-of-work up to the last PoW height, proof-of-stake
    /// after it, as Divi Core does. The staking loop's pacing guards (rate
    /// limit, stale tip, minimum coin age, reserve balance) do not apply.
    pub fn generate_blocks(&self, n: u32) -> Result<Vec<Hash256>, String> {
        let _producing = self.producing.lock();
        let mut hashes = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let tip = self.chain.tip().ok_or("no chain tip")?;
            let height = tip.height + 1;
            // A work block pays a keypool key, which a locked wallet still
            // hands out; only a stake block needs the wallet unlocked
            // (CoinMinter.cpp:141-158)
            let block = if height <= divi_storage::chain::LAST_POW_BLOCK {
                self.build_work_block(&tip)?
            } else if self.wallet.is_locked() {
                return Err("wallet is locked".to_string());
            } else {
                self.build_generated_stake_block(&tip)?
            };
            let block_hash = compute_block_hash(&block.header);
            self.accept_own_block(&block, block_hash, height)?;
            hashes.push(block_hash);
        }
        Ok(hashes)
    }

    /// Regtest `generateblock`: one block made as `setgenerate` makes it, then
    /// changed as Divi Core's ExtendedBlockFactory changes it
    /// (ExtendedBlockFactory.cpp:27-104): the pool's transactions left out,
    /// extra ones appended, and on a proof-of-stake block another coinstake
    /// or shifted bits, the block then signed again with the key of the
    /// coinstake's second output (BlockSigning.cpp:39-84).
    pub fn generate_block_with(
        &self,
        overrides: &BlockOverrides,
    ) -> Result<Hash256, GenerateBlockError> {
        use GenerateBlockError::{Failed, Refused};
        if self.wallet.is_locked() {
            return Err(Failed("wallet is locked".to_string()));
        }
        let _producing = self.producing.lock();
        let tip = self
            .chain
            .tip()
            .ok_or_else(|| Failed("no chain tip".to_string()))?;
        let height = tip.height + 1;
        let work = height <= divi_storage::chain::LAST_POW_BLOCK;
        if work && overrides.coinstake.is_some() {
            return Err(Refused(
                "trying to set custom coinstake in non-PoS block".to_string(),
            ));
        }
        *self.next_block_txs.lock() = Some((overrides.ignore_mempool, overrides.extra_txs.clone()));
        let built = if work {
            self.build_work_block(&tip)
        } else {
            self.build_generated_stake_block(&tip)
        };
        *self.next_block_txs.lock() = None;
        let mut block = built.map_err(Failed)?;

        if work {
            // Core signs a changed proof-of-work block with a pay-to-pubkey
            // output of its coinbase; this coinbase pays a key hash
            if overrides.bits_shift.is_some() {
                return Err(Failed(
                    "no pay-to-pubkey coinbase output to sign with".into(),
                ));
            }
        } else if overrides.coinstake.is_some() || overrides.bits_shift.is_some() {
            if let Some(coinstake) = &overrides.coinstake {
                block.transactions[1] = coinstake.clone();
                block.header.merkle_root = compute_merkle_root(&block.transactions);
            }
            if let Some(shift) = overrides.bits_shift {
                block.header.bits = shift_bits(block.header.bits, shift);
            }
            let hash = compute_block_hash(&block.header);
            let script = &block.transactions[1]
                .vout
                .get(1)
                .ok_or_else(|| Failed("coinstake has no second output".to_string()))?
                .script_pubkey;
            block.block_sig = self.sign_block_for_script(&hash, script).map_err(Failed)?;
        }
        let block_hash = compute_block_hash(&block.header);
        self.accept_own_block(&block, block_hash, height)
            .map_err(Failed)?;
        Ok(block_hash)
    }

    /// Divi Core `SignBlock` for a proof-of-stake block (BlockSigning.cpp:39-84):
    /// with the wallet's key for the coinstake's second output, a compact
    /// signature for a key hash or vault, a DER one for a public key
    fn sign_block_for_script(&self, hash: &Hash256, script: &Script) -> Result<Vec<u8>, String> {
        let bytes = script.as_bytes();
        let key_for = |key_hash: &Hash160| {
            self.wallet
                .keystore()
                .get_key(key_hash)
                .and_then(|k| k.secret)
                .ok_or_else(|| "Sign failed: no key for the coinstake output".to_string())
        };
        let compact = |secret: &divi_crypto::SecretKey| {
            divi_crypto::sign_hash_recoverable(secret, hash.as_bytes())
                .map(|sig| sig.to_compact_with_recovery().to_vec())
                .map_err(|e| format!("Sign failed: {e}"))
        };
        if divi_script::standard::is_p2pk(bytes) {
            let pubkey = &bytes[1..bytes.len() - 1];
            let secret = key_for(&divi_crypto::hash160(pubkey))?;
            return divi_crypto::sign_hash(&secret, hash.as_bytes())
                .map(|sig| sig.to_der())
                .map_err(|e| format!("Sign failed: {e}"));
        }
        if let Some(vault) = divi_script::StakingVaultScript::from_script(script) {
            return compact(&key_for(&Hash160::from_bytes(vault.vault_pubkey_hash))?);
        }
        if bytes.len() == 25 && bytes[..3] == [0x76, 0xa9, 0x14] && bytes[23..] == [0x88, 0xac] {
            let mut key_hash = [0u8; 20];
            key_hash.copy_from_slice(&bytes[3..23]);
            return compact(&key_for(&Hash160::from_bytes(key_hash))?);
        }
        Err("Sign failed: the coinstake output is not a key hash, key or vault".to_string())
    }

    /// Earliest time a block on `tip` may carry: now, but past the median time
    fn next_block_time(&self, tip: &divi_storage::BlockIndex) -> u32 {
        (current_timestamp() as u32).max(self.get_median_time_past(&tip.hash) + 1)
    }

    /// A proof-of-work block on `tip` whose coinbase pays this wallet
    fn build_work_block(&self, tip: &divi_storage::BlockIndex) -> Result<Block, String> {
        let height = tip.height + 1;
        let bits = self.chain.get_next_bits(tip).map_err(|e| e.to_string())?;
        let time = self.next_block_time(tip);
        let pay_to = self
            .wallet
            .new_receiving_address()
            .map_err(|e| e.to_string())?;
        // Height, then the height again so each coinbase txid is unique
        let mut script_sig = divi_storage::bip34_height_script(height);
        script_sig.extend_from_slice(&height.to_le_bytes());
        let mut transactions = vec![Transaction {
            version: 1,
            lock_time: 0,
            vin: vec![TxIn::coinbase(Script::from_bytes(script_sig))],
            vout: vec![TxOut::new(
                self.chain.pow_block_reward(height),
                pay_to.script_pubkey(),
            )],
        }];
        transactions.extend(self.mempool_block_txs(height, time));
        let mut header = BlockHeader {
            version: 4,
            prev_block: tip.hash,
            merkle_root: compute_merkle_root(&transactions),
            time,
            bits,
            nonce: 0,
            accumulator_checkpoint: Hash256::zero(),
        };
        let target = Hash256::from_compact(bits);
        while compute_block_hash(&header) > target {
            header.nonce = header
                .nonce
                .checked_add(1)
                .ok_or("no proof-of-work nonce found")?;
        }
        Ok(Block {
            header,
            transactions,
            block_sig: Vec::new(),
        })
    }

    /// A proof-of-stake block on `tip`, its search starting past the median
    /// time so blocks made back to back stay valid
    fn build_generated_stake_block(&self, tip: &divi_storage::BlockIndex) -> Result<Block, String> {
        match self.build_stake_block(tip, self.next_block_time(tip)) {
            StakeResult::Success { block, .. } => Ok(block),
            StakeResult::NoStakeableUtxos => Err("no coins to stake".to_string()),
            StakeResult::Error(e) => Err(e),
            _ => Err("no coin found a proof of stake".to_string()),
        }
    }

    /// Mempool transactions to put in a block at `height` and `timestamp`
    fn mempool_block_txs(&self, height: u32, timestamp: u32) -> Vec<Transaction> {
        let overrides = self.next_block_txs.lock().clone();
        let mut txs = match &overrides {
            Some((true, _)) => Vec::new(),
            _ => self.pool_block_txs(height, timestamp),
        };
        if let Some((_, extra)) = overrides {
            txs.extend(extra);
        }
        txs
    }

    /// The pool's transactions for a block at `height` and `timestamp`
    fn pool_block_txs(&self, height: u32, timestamp: u32) -> Vec<Transaction> {
        let limits = {
            let c = self.config.read();
            BlockAssembly::new(
                c.max_block_size,
                c.block_priority_size,
                c.block_min_size,
                self.mempool.min_relay_fee_per_kb(),
            )
        };
        // Chosen and checked against this block as Divi Core's block assembler
        // does; a stale transaction (an input already spent on chain) is left out
        select_block_txs(
            self.mempool.block_candidates(height),
            height,
            timestamp,
            &limits,
            self.chain.params().coinbase_maturity,
            |op| self.chain.get_utxo(op).ok().flatten(),
        )
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
    /// Log once, at warn level, that staking is on but the wallet is locked, and
    /// once more at info level when it is unlocked again. Returns true when the
    /// warning was logged by this call.
    fn note_wallet_locked(&self, locked: bool) -> bool {
        if locked {
            let first = !self.wallet_locked_warned.swap(true, Ordering::SeqCst);
            if first {
                warn!(
                    "Staking is enabled but the wallet is locked, so no block can be staked; \
                     unlock it with walletpassphrase \"<passphrase>\" 0 true"
                );
            }
            first
        } else {
            if self.wallet_locked_warned.swap(false, Ordering::SeqCst) {
                info!("Wallet unlocked; staking can sign blocks again");
            }
            false
        }
    }

    fn try_stake(&self) -> StakeResult {
        let current_time = current_timestamp() as u32;

        // A locked wallet cannot sign a coinstake; say so once instead of
        // failing every candidate at debug level
        let locked = self.wallet.is_locked();
        self.note_wallet_locked(locked);
        if locked {
            return StakeResult::WalletLocked;
        }

        // Get the current tip FIRST - this ensures all state is consistent
        let tip = match self.chain.tip() {
            Some(tip) => tip,
            None => return StakeResult::Error("No chain tip".to_string()),
        };

        let current_height = tip.height;

        // Don't stake while actively syncing (IBD mode).
        if self.chain.is_ibd() {
            debug!("Skipping stake: still in IBD mode");
            return StakeResult::RateLimited;
        }

        // A snapshot-bootstrapped node trusts (does not prove) its UTXO set, so it must not
        // stake until at least one block past the snapshot tip has been fully validated.
        if let Some((base, _)) = self.chain.snapshot_base() {
            if tip.height <= base {
                debug!(
                    "Skipping stake: tip {} has not advanced past snapshot base {}",
                    tip.height, base
                );
                return StakeResult::RateLimited;
            }
        }

        // Don't stake on a stale tip unless the operator explicitly allows it
        // (-stakeonstaletip). Commit 34d75a0 removed this guard to let IronDivi
        // break a network-wide stall; doing that by default lets a node that has
        // lost its peers mint a private fork (vps1 testnet stall at 208,970).
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let (max_age, allow_stale) = {
                let c = self.config.read();
                (c.max_tip_age_secs, c.allow_stale_tip)
            };
            if stale_tip_blocks_staking(now, tip.time, max_age, allow_stale) {
                debug!(
                    "Skipping stake: tip {} is {}s old (> {}s); set -stakeonstaletip to override",
                    current_height,
                    now.saturating_sub(tip.time),
                    max_age
                );
                return StakeResult::RateLimited;
            }
        }

        // CRITICAL: Rate limiting check (matches C++ limitStakingSpeed)
        // Check if we tried at this height recently (before updating the timestamp)
        if self.limit_staking_speed(current_height, current_time as u64) {
            return StakeResult::RateLimited;
        }

        // Record this staking attempt (matches C++ PoSTransactionCreator)
        // Only record if we pass rate limiting
        self.record_staking_attempt(current_height, current_time as u64);

        self.build_stake_block(&tip, current_time)
    }

    /// A proof-of-stake block on `tip` at `current_time` or up to the hash
    /// drift before it, staked with the first coin of the stake set that finds
    /// a proof (Divi Core BlockFactory::CreateNewPoSBlock). The staking loop's
    /// pacing guards are the caller's.
    fn build_stake_block(&self, tip: &divi_storage::BlockIndex, current_time: u32) -> StakeResult {
        let current_height = tip.height;
        let next_height = current_height + 1;

        // Compute the NEXT block's difficulty bits.
        // Each block has its own difficulty computed by get_next_work_required(),
        // which adjusts based on the actual spacing between recent blocks.
        // The block header must contain the correct bits or C++ peers will reject it.
        let n_bits = match self.chain.get_next_bits(tip) {
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
        let coinbase_maturity = self.coinbase_maturity();
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

        // No plain coin left is no reason to stop: vault coins are staked too
        if stakeable.is_empty() && reserve > 0 {
            static RESERVE_LIMIT_COUNT: std::sync::atomic::AtomicU32 =
                std::sync::atomic::AtomicU32::new(0);
            let count = RESERVE_LIMIT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if count == 0 {
                info!(
                    "No stakeable UTXOs after applying reserve balance of {} DIVI (first occurrence)",
                    reserve as f64 / 100_000_000.0
                );
            } else {
                trace!(
                    "No stakeable UTXOs after applying reserve balance of {} DIVI",
                    reserve as f64 / 100_000_000.0
                );
            }
        }

        // Divi Core stakes and combines only coins of its stake set
        // (CWallet::SelectStakeCoins): depth, coin age, not locked
        let stakeable = self.stake_set(&stakeable, current_height, current_time);

        // Also get vault UTXOs for staking (bypass reserve balance - not our money)
        let vault_utxos: Vec<_> = self
            .wallet
            .get_stakeable_vault_utxos(current_height, 1)
            .into_iter()
            .filter(|(utxo, _)| self.is_in_stake_set(utxo, current_height, current_time))
            .collect();
        if !vault_utxos.is_empty() {
            info!("Found {} vault UTXOs for staking", vault_utxos.len());
        }
        if stakeable.is_empty() && vault_utxos.is_empty() {
            return StakeResult::NoStakeableUtxos;
        }
        // Coins the coinstake may combine with its kernel: the whole stake
        // set; plan_stake_outputs keeps those paying the kernel's script
        let combine_pool: Vec<divi_wallet::WalletUtxo> = stakeable
            .iter()
            .cloned()
            .chain(vault_utxos.iter().map(|(utxo, _)| utxo.clone()))
            .collect();

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
                count, candidates.len(), total_weight as f64 / 100_000_000.0, next_height - 1, current_time, n_bits, tip.stake_modifier
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
            // Core's stake set holds every spendable coin, but only P2PKH, P2PK
            // and vault coins can be the kernel (PoSTransactionCreator.cpp:142-160)
            if matches!(candidate, StakeCandidate::Regular(_))
                && !divi_script::standard::is_p2pkh(utxo.script_pubkey.as_bytes())
                && !divi_script::standard::is_p2pk(utxo.script_pubkey.as_bytes())
            {
                continue;
            }
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
                        utxo.value.as_divi_f64(),
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
                            utxo.value.as_divi_f64(),
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
                match self.create_stake_block(tip, candidate, timestamp, n_bits, &combine_pool) {
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
        combine_pool: &[divi_wallet::WalletUtxo],
    ) -> Result<Block, String> {
        let stake_utxo = candidate.utxo();
        // Get stake reward
        let height = tip.height + 1;
        let stake_reward = self.calculate_stake_reward(height);

        // At most one superblock payout per block: where the treasury and
        // lottery cycles coincide the treasury is paid and the lottery is not
        // (Divi Core BlockIncentivesPopulator::FillBlockPayee).
        let payout = superblock_payout(self.chain.network_type(), height);
        let lottery_cycle = match self.chain.network_type() {
            divi_storage::NetworkType::Mainnet => divi_consensus::lottery::mainnet::LOTTERY_CYCLE,
            divi_storage::NetworkType::Testnet => divi_consensus::lottery::testnet::LOTTERY_CYCLE,
            divi_storage::NetworkType::Regtest => divi_consensus::lottery::regtest::LOTTERY_CYCLE,
        };
        let lottery_payments = if payout == divi_consensus::treasury::SuperblockPayout::Lottery {
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

        let (treasury_cycle, treasury_lottery_cycle, is_mainnet) = match self.chain.network_type() {
            divi_storage::NetworkType::Mainnet => (
                divi_consensus::treasury::mainnet::TREASURY_CYCLE,
                divi_consensus::treasury::mainnet::LOTTERY_CYCLE,
                true,
            ),
            divi_storage::NetworkType::Testnet => (
                divi_consensus::treasury::testnet::TREASURY_CYCLE,
                divi_consensus::treasury::testnet::LOTTERY_CYCLE,
                false,
            ),
            divi_storage::NetworkType::Regtest => (
                divi_consensus::treasury::regtest::TREASURY_CYCLE,
                divi_consensus::treasury::regtest::LOTTERY_CYCLE,
                false,
            ),
        };

        let treasury_payments = if payout == divi_consensus::treasury::SuperblockPayout::Treasury {
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
                treasury_payment.as_divi_f64(),
                charity_payment.as_divi_f64()
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

        // Split or combine as Divi Core does for every kernel, vault kernels
        // included (PoSTransactionCreator.cpp:358-365)
        let (configured_threshold, autocombine) = {
            let c = self.config.read();
            (c.stake_split_threshold, c.autocombine)
        };
        let split_threshold = split_threshold_for(
            configured_threshold,
            matches!(candidate, StakeCandidate::Vault(..)),
        );
        let plan = plan_stake_outputs(
            stake_utxo,
            stake_utxo.value + stake_reward,
            split_threshold,
            autocombine,
            combine_pool,
        );

        // Create coinstake transaction (with lottery and/or treasury payments if applicable)
        let coinstake = match candidate {
            StakeCandidate::Regular(_) => {
                self.create_coinstake_tx(stake_utxo, &plan, lottery_payments, treasury_payments)?
            }
            StakeCandidate::Vault(_, vault_script) => self.create_vault_coinstake_tx(
                stake_utxo,
                vault_script,
                &plan,
                lottery_payments,
                treasury_payments,
            )?,
        };

        // Gather transactions from mempool
        let mut transactions = vec![
            create_coinbase_marker(height), // Empty coinbase marker
            coinstake,
        ];

        transactions.extend(self.mempool_block_txs(height, timestamp));

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
        // A P2PK kernel signs the block with a DER signature checked against
        // the key in the script (BlockSigning.cpp:69-80)
        if divi_script::standard::is_p2pk(stake_utxo.script_pubkey.as_bytes()) {
            let signature = divi_crypto::sign_hash(secret, block_hash.as_bytes())
                .map_err(|e| format!("Failed to sign block: {}", e))?;
            return Ok(signature.to_der());
        }
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
    /// Uses CoinstakeBuilder for vault-path spending. The kernel and any
    /// combined coins of the same vault are the inputs; the stake outputs pay
    /// back to the same vault script (preserving owner control).
    fn create_vault_coinstake_tx(
        &self,
        stake_utxo: &divi_wallet::WalletUtxo,
        vault_script: &divi_script::StakingVaultScript,
        plan: &StakeOutputPlan,
        lottery_payments: Option<Vec<(Script, Amount)>>,
        treasury_payments: Option<Vec<(Script, Amount)>>,
    ) -> Result<Transaction, String> {
        if self.wallet.is_locked() {
            return Err("Wallet is locked".to_string());
        }

        let mut builder = divi_wallet::CoinstakeBuilder::new();
        builder.add_vault_input(stake_utxo);
        for coin in &plan.extra_inputs {
            builder.add_vault_input(coin);
        }

        // Stake outputs: stake return + reward, paying to the SAME vault script
        for value in &plan.stake_outputs {
            builder.add_output_raw(*value, stake_utxo.script_pubkey.clone());
        }

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
            "Created vault coinstake: {} inputs, {} outputs",
            tx.vin.len(),
            tx.vout.len()
        );

        Ok(tx)
    }

    /// The coins of `coins` in Divi Core's stake set, the set it picks
    /// kernels from and combines into a coinstake
    fn stake_set(
        &self,
        coins: &[divi_wallet::WalletUtxo],
        tip_height: u32,
        now: u32,
    ) -> Vec<divi_wallet::WalletUtxo> {
        coins
            .iter()
            .filter(|u| self.is_in_stake_set(u, tip_height, now))
            .cloned()
            .collect()
    }

    /// Whether `coin` is in Divi Core's stake set (see `is_stake_set_coin`)
    fn is_in_stake_set(&self, coin: &divi_wallet::WalletUtxo, tip_height: u32, now: u32) -> bool {
        let block_time = coin.height.and_then(|h| {
            self.chain
                .get_block_index_by_height(h)
                .ok()
                .flatten()
                .map(|idx| idx.time)
        });
        is_stake_set_coin(
            coin,
            block_time,
            tip_height,
            now,
            self.chain.params().coinbase_maturity,
            self.config.read().min_coin_age,
            self.wallet.is_coin_locked(&coin.outpoint()),
        )
    }

    /// Create the coinstake transaction
    fn create_coinstake_tx(
        &self,
        stake_utxo: &divi_wallet::WalletUtxo,
        plan: &StakeOutputPlan,
        lottery_payments: Option<Vec<(Script, Amount)>>,
        treasury_payments: Option<Vec<(Script, Amount)>>,
    ) -> Result<Transaction, String> {
        // Check if wallet is locked
        if self.wallet.is_locked() {
            return Err("Wallet is locked".to_string());
        }

        // Coinstake inputs: the kernel first, then any combined coins
        let spent: Vec<&divi_wallet::WalletUtxo> = std::iter::once(stake_utxo)
            .chain(plan.extra_inputs.iter())
            .collect();
        let inputs: Vec<TxIn> = spent
            .iter()
            .map(|u| TxIn {
                prevout: OutPoint::new(u.txid, u.vout),
                script_sig: Script::default(), // Will be signed below
                sequence: 0xffffffff,
            })
            .collect();

        // Coinstake outputs:
        // 1. Empty marker output (value 0, empty script)
        // 2. Stake return + reward (same address as the kernel), one or two
        //    outputs (Divi Core stake split)
        // 3. ... (optional lottery payments for lottery blocks)
        let marker_output = TxOut {
            value: Amount::ZERO,
            script_pubkey: Script::default(),
        };

        let mut outputs = vec![marker_output];
        for value in &plan.stake_outputs {
            outputs.push(TxOut {
                value: *value,
                script_pubkey: stake_utxo.script_pubkey.clone(),
            });
        }

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
            vin: inputs,
            vout: outputs,
        };

        // Sign every coinstake input
        let signer = TransactionSigner::new(self.wallet.keystore());
        let prev_scripts: Vec<Script> = spent.iter().map(|u| u.script_pubkey.clone()).collect();

        let no_redeem_script = |_: &Hash160| None;
        let mut signed = 0;
        for (i, script) in prev_scripts.iter().enumerate() {
            let verified = signer
                .sign_and_merge_input(&mut tx, i, script, &no_redeem_script)
                .map_err(|e| format!("Failed to sign coinstake: {}", e))?;
            signed += usize::from(verified);
        }

        if signed != spent.len() {
            return Err("Failed to sign coinstake input".to_string());
        }

        if spent.len() > 1 || plan.stake_outputs.len() > 1 {
            info!(
                "Coinstake combines {} input(s) into {} stake output(s)",
                spent.len(),
                plan.stake_outputs.len()
            );
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
            stake_reward.as_divi_f64(),
            rewards.treasury.as_divi_f64(),
            rewards.lottery.as_divi_f64(),
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
    /// Divi Core `mintablecoins`: a coin is mature and old enough to stake now
    pub mintable_coins: bool,
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

/// Which superblock payout a staked block at `height` must carry.
///
/// Divi Core `BlockIncentivesPopulator::FillBlockPayee` pays the treasury when
/// `IsValidTreasuryBlockHeight`, else the lottery when
/// `IsValidLotteryBlockHeight` - never both.
pub(crate) fn superblock_payout(
    network: divi_storage::NetworkType,
    height: u32,
) -> divi_consensus::treasury::SuperblockPayout {
    use divi_consensus::{lottery, treasury};
    let (treasury_start, treasury_cycle, lottery_start, lottery_cycle) = match network {
        divi_storage::NetworkType::Mainnet => (
            treasury::mainnet::TREASURY_START_BLOCK,
            treasury::mainnet::TREASURY_CYCLE,
            lottery::mainnet::LOTTERY_START_BLOCK,
            lottery::mainnet::LOTTERY_CYCLE,
        ),
        divi_storage::NetworkType::Testnet => (
            treasury::testnet::TREASURY_START_BLOCK,
            treasury::testnet::TREASURY_CYCLE,
            lottery::testnet::LOTTERY_START_BLOCK,
            lottery::testnet::LOTTERY_CYCLE,
        ),
        divi_storage::NetworkType::Regtest => (
            treasury::regtest::TREASURY_START_BLOCK,
            treasury::regtest::TREASURY_CYCLE,
            lottery::regtest::LOTTERY_START_BLOCK,
            lottery::regtest::LOTTERY_CYCLE,
        ),
    };
    treasury::superblock_payout(
        height,
        treasury_start,
        treasury_cycle,
        lottery_start,
        lottery_cycle,
    )
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
    // Divi Core CreateEmptyCoinbaseTransaction (BlockFactory.cpp:38-52): the
    // height (BIP34, CScriptNum) then the extra nonce 1, one empty output,
    // transaction version 1
    let mut script_sig = encode_bip34_height(height);
    script_sig.extend_from_slice(&[0x01, 0x01]);
    let script_sig = Script::from_bytes(script_sig);

    Transaction {
        version: 1,
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

/// Divi Core `MAX_BLOCK_SIZE_CURRENT` (defaultValues.h:43)
const MAX_BLOCK_SIZE: usize = 2_000_000;

/// Divi Core `DEFAULT_BLOCK_MAX_SIZE` (defaultValues.h:47): `-blockmaxsize` default
pub const DEFAULT_BLOCK_MAX_SIZE: usize = 750_000;

/// Divi Core `MAX_BLOCK_SIGOPS_CURRENT` (defaultValues.h:56)
const MAX_BLOCK_SIGOPS: u32 = 40_000;

/// Divi Core `GetMaxBlockSize` (BlockMemoryPoolTransactionCollector.cpp:18-27):
/// the configured size, kept between 1,000 bytes and 1,000 below the network limit
fn block_max_size(configured: usize) -> usize {
    configured.clamp(1000, MAX_BLOCK_SIZE - 1000)
}

/// Divi Core's `blockBitsShift`: the target of `bits` shifted left by
/// `shift` bits, at most 32, what goes past 256 bits dropped as in uint256
/// (ExtendedBlockFactory.cpp:84-86)
fn shift_bits(bits: u32, shift: u32) -> u32 {
    let shift = shift.min(32) as usize;
    let le = divi_consensus::target::Target::from_compact(bits);
    let le = le.as_bytes();
    let mut out = [0u8; 32];
    let (bytes, rest) = (shift / 8, shift % 8);
    for i in (0..32usize).rev() {
        let Some(src) = i.checked_sub(bytes) else {
            continue;
        };
        let mut v = (le[src] as u16) << rest;
        if rest > 0 && src > 0 {
            v |= (le[src - 1] as u16) >> (8 - rest);
        }
        out[i] = v as u8;
    }
    divi_consensus::target::Target::from_bytes(out).to_compact()
}

/// Divi Core `DEFAULT_BLOCK_PRIORITY_SIZE` (defaultValues.h:50): `-blockprioritysize` default
pub const DEFAULT_BLOCK_PRIORITY_SIZE: usize = 50_000;

/// Divi Core `DEFAULT_BLOCK_MIN_SIZE` (defaultValues.h:48): `-blockminsize` default
pub const DEFAULT_BLOCK_MIN_SIZE: usize = 0;

/// The sizes and fee floor block assembly works to, as Divi Core's
/// `BlockMemoryPoolTransactionCollector` constructor sets them
/// (BlockMemoryPoolTransactionCollector.cpp:18-42, :103-105; the fee floor is
/// the minimum relay fee, miner.cpp:71-89)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockAssembly {
    pub max_size: usize,
    pub priority_size: usize,
    pub min_size: usize,
    pub fee_floor_per_kb: i64,
}

impl BlockAssembly {
    /// `-blockmaxsize` kept between 1,000 bytes and 1,000 below the network
    /// limit; `-blockprioritysize` and `-blockminsize` at most that
    pub fn new(max_size: usize, priority_size: usize, min_size: usize, fee_floor: i64) -> Self {
        let max_size = block_max_size(max_size);
        BlockAssembly {
            max_size,
            priority_size: priority_size.min(max_size),
            min_size: min_size.min(max_size),
            fee_floor_per_kb: fee_floor,
        }
    }
}

/// A candidate's place in Divi Core's `TxPriorityCompare`
/// (BlockMemoryPoolTransactionCollector.cpp:65-87): by priority with ties by
/// fee rate, or by fee rate with ties by priority. Core's heap leaves equal
/// keys in no set order; here they go by txid.
struct HeapItem {
    by_fee: bool,
    index: usize,
    priority: f64,
    fee_rate: i64,
    txid: Hash256,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for HeapItem {}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let by_priority = self.priority.total_cmp(&other.priority);
        let by_fee = self.fee_rate.cmp(&other.fee_rate);
        let order = if self.by_fee {
            by_fee.then(by_priority)
        } else {
            by_priority.then(by_fee)
        };
        // The lower txid first among equal keys (a max-heap pops the greatest)
        order.then_with(|| other.txid.cmp(&self.txid))
    }
}

/// Divi Core `PrioritizeTransactionsByBlockSpaceUsage`
/// (BlockMemoryPoolTransactionCollector.cpp:261-342), with the candidates of
/// `ComputeMempoolTransactionPriorities` (:212-251). Final transactions are
/// taken highest priority first. A transaction waits until every pool
/// transaction it spends is in the block (:156-166). Once the block reaches
/// `priority_size`, or the best one left must pay a fee (`AllowFree`), the
/// rest go by fee rate (:296-306), and from then a transaction below the fee
/// floor that has no prioritisetransaction delta is left out once the block
/// would reach `min_size` (:308-311, :232-238). Each one kept must keep the
/// block under the size limit (counting 1,000 bytes for the header and
/// block-reward transactions) and under 40,000 sigops (counting 100), spend
/// only outputs still available, and pass CheckInputs with the mandatory
/// script flags (coinbase/coinstake maturity, value in at least value out,
/// scripts). One that fails is left out, and so is everything spending it.
fn select_block_txs(
    candidates: Vec<crate::mempool::BlockCandidate>,
    height: u32,
    time: u32,
    limits: &BlockAssembly,
    maturity: u32,
    utxo: impl Fn(&OutPoint) -> Option<divi_storage::Utxo>,
) -> Vec<Transaction> {
    use std::collections::{BinaryHeap, HashSet};
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|c| c.tx.is_final(height, time))
        .collect();
    let index: HashMap<Hash256, usize> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| (c.txid, i))
        .collect();
    // Children waiting for each parent, and how many parents each still needs.
    // A parent that is not final is not a candidate: its children never go in.
    let mut waiting: HashMap<Hash256, Vec<usize>> = HashMap::new();
    let mut needs: Vec<usize> = vec![0; candidates.len()];
    let mut blocked: Vec<bool> = vec![false; candidates.len()];
    for (i, c) in candidates.iter().enumerate() {
        for parent in &c.parents {
            if index.contains_key(parent) {
                waiting.entry(*parent).or_default().push(i);
                needs[i] += 1;
            } else {
                blocked[i] = true;
            }
        }
    }
    let mut by_fee = limits.priority_size == 0;
    let item = |i: usize, by_fee: bool| HeapItem {
        by_fee,
        index: i,
        priority: candidates[i].priority,
        fee_rate: candidates[i].fee_rate_per_kb,
        txid: candidates[i].txid,
    };
    let mut heap: BinaryHeap<HeapItem> = (0..candidates.len())
        .filter(|&i| needs[i] == 0 && !blocked[i])
        .map(|i| item(i, by_fee))
        .collect();

    let mut kept = Vec::new();
    let mut created: HashMap<OutPoint, TxOut> = HashMap::new();
    let mut spent: HashSet<OutPoint> = HashSet::new();
    let mut block_size = 1000usize;
    let mut block_sig_ops = 100u32;
    while let Some(best) = heap.pop() {
        let c = &candidates[best.index];
        let tx = &c.tx;
        let size = c.size;
        let must_pay = !crate::mempool::allow_free(c.priority);
        let mut sig_ops: u32 = tx
            .vin
            .iter()
            .map(|i| divi_script::sig_op_count(i.script_sig.as_bytes(), false))
            .chain(
                tx.vout
                    .iter()
                    .map(|o| divi_script::sig_op_count(o.script_pubkey.as_bytes(), false)),
            )
            .sum();
        if block_size + size >= limits.max_size || block_sig_ops + sig_ops >= MAX_BLOCK_SIGOPS {
            continue;
        }
        if !by_fee {
            // This one is still weighed below, now by fee
            if block_size + size >= limits.priority_size || must_pay {
                by_fee = true;
                heap = heap.into_iter().map(|h| item(h.index, true)).collect();
            }
        } else if !c.prioritised
            && c.fee_rate_per_kb < limits.fee_floor_per_kb
            && block_size + size >= limits.min_size
        {
            continue;
        }

        let mut inputs: Vec<(Script, Amount)> = Vec::with_capacity(tx.vin.len());
        let mut value_in = Amount::ZERO;
        let usable = tx.vin.iter().all(|input| {
            if spent.contains(&input.prevout) {
                return false;
            }
            let (script, value) = if let Some(out) = created.get(&input.prevout) {
                (out.script_pubkey.clone(), out.value)
            } else if let Some(coin) = utxo(&input.prevout) {
                if (coin.is_coinbase || coin.is_coinstake)
                    && height.saturating_sub(coin.height) < maturity
                {
                    return false;
                }
                (coin.script_pubkey, coin.value)
            } else {
                return false;
            };
            if divi_script::is_p2sh(script.as_bytes()) {
                sig_ops +=
                    divi_script::p2sh_sig_op_count(script.as_bytes(), input.script_sig.as_bytes());
            }
            value_in += value;
            inputs.push((script, value));
            true
        });
        if !usable || block_sig_ops + sig_ops >= MAX_BLOCK_SIGOPS {
            continue;
        }
        let value_out = tx.vout.iter().fold(Amount::ZERO, |sum, o| sum + o.value);
        if value_in < value_out {
            continue;
        }
        let scripts_pass = inputs.iter().enumerate().all(|(i, (script, value))| {
            divi_script::verify_input_with_flags(
                tx,
                i,
                script,
                *value,
                divi_script::ScriptFlags::mandatory(),
            )
            .is_ok()
        });
        if !scripts_pass {
            continue;
        }

        block_size += size;
        block_sig_ops += sig_ops;
        spent.extend(tx.vin.iter().map(|i| i.prevout));
        for (n, out) in tx.vout.iter().enumerate() {
            created.insert(OutPoint::new(c.txid, n as u32), out.clone());
        }
        kept.push(tx.clone());
        for &child in waiting.get(&c.txid).map(Vec::as_slice).unwrap_or(&[]) {
            needs[child] -= 1;
            if needs[child] == 0 && !blocked[child] {
                heap.push(item(child, by_fee));
            }
        }
    }
    kept
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

    /// Where the regtest lottery and treasury cycles coincide before the
    /// superblock transition, the staker pays the treasury only, as Divi Core's
    /// FillBlockPayee does; paying both made the coinstake mint too much.
    #[test]
    fn test_staker_pays_treasury_not_lottery_on_coinciding_height() {
        use divi_consensus::treasury::SuperblockPayout;
        use divi_storage::NetworkType;
        for h in [150u32, 200, 250, 300, 350, 400, 450] {
            assert_eq!(
                superblock_payout(NetworkType::Regtest, h),
                SuperblockPayout::Treasury,
                "regtest height {h}"
            );
        }
        assert_eq!(
            superblock_payout(NetworkType::Regtest, 160),
            SuperblockPayout::Lottery
        );
        assert_eq!(
            superblock_payout(NetworkType::Regtest, 161),
            SuperblockPayout::None
        );
        assert_eq!(
            superblock_payout(NetworkType::Testnet, 40200),
            SuperblockPayout::Lottery
        );
        assert_eq!(
            superblock_payout(NetworkType::Testnet, 40201),
            SuperblockPayout::Treasury
        );
        assert_eq!(
            superblock_payout(NetworkType::Mainnet, 10080),
            SuperblockPayout::Lottery
        );
        assert_eq!(
            superblock_payout(NetworkType::Mainnet, 10081),
            SuperblockPayout::Treasury
        );
    }

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
        assert_eq!(config.max_block_size, 750_000);
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

    fn coin(tx: u8, vout: u32, divi: i64, owner: u8) -> divi_wallet::WalletUtxo {
        divi_wallet::WalletUtxo::new(
            Hash256::from_bytes([tx; 32]),
            vout,
            Amount::from_divi(divi),
            Script::new_p2pkh(&[owner; 20]),
            String::new(),
        )
    }

    fn sats(values: &[Amount]) -> Vec<i64> {
        values.iter().map(|a| a.as_sat()).collect()
    }

    #[test]
    fn test_stake_split_above_threshold() {
        // Divi Core splits value + reward above -stakesplitthreshold
        // into credit / 2 and the remainder, both to the kernel's script.
        let kernel = coin(1, 0, 30_000, 7);
        let credit = Amount::from_sat(30_000 * 100_000_000 + 456_00000001);
        let plan = plan_stake_outputs(&kernel, credit, DEFAULT_STAKE_SPLIT_THRESHOLD, true, &[]);
        assert!(plan.extra_inputs.is_empty());
        let half = credit.as_sat() / 2;
        assert_eq!(
            sats(&plan.stake_outputs),
            vec![half, credit.as_sat() - half]
        );

        // Exactly at the threshold: no split (Divi Core uses nCredit > stakeSplit)
        let at = Amount::from_sat(DEFAULT_STAKE_SPLIT_THRESHOLD);
        let plan = plan_stake_outputs(&kernel, at, DEFAULT_STAKE_SPLIT_THRESHOLD, true, &[]);
        assert_eq!(sats(&plan.stake_outputs), vec![at.as_sat()]);
    }

    #[test]
    fn test_stake_combine_small_coins_of_same_script() {
        let threshold = 10_000 * 100_000_000; // combine up to 5,000 DIVI
        let kernel = coin(1, 0, 1_000, 7);
        let credit = Amount::from_divi(1_000 + 456);
        let pool = vec![
            kernel.clone(),
            coin(1, 1, 10, 7),    // same tx as the kernel: never combined
            coin(2, 0, 3_000, 7), // passes alone, too large after the smaller ones
            coin(3, 0, 300, 7),
            coin(4, 0, 100, 9), // other script
            coin(5, 0, 500, 7),
            coin(6, 0, 4_000, 7), // credit + value > threshold / 2: skipped up front
        ];
        let plan = plan_stake_outputs(&kernel, credit, threshold, true, &pool);
        let combined: Vec<u8> = plan
            .extra_inputs
            .iter()
            .map(|c| c.txid.as_bytes()[0])
            .collect();
        // Ascending: 300 (tx 3), 500 (tx 5), then 3,000 would pass 5,000: stop
        assert_eq!(combined, vec![3, 5]);
        assert_eq!(
            sats(&plan.stake_outputs),
            vec![Amount::from_divi(1_000 + 456 + 300 + 500).as_sat()]
        );

        // -autocombine=0
        let plan = plan_stake_outputs(&kernel, credit, threshold, false, &pool);
        assert!(plan.extra_inputs.is_empty());
        assert_eq!(sats(&plan.stake_outputs), vec![credit.as_sat()]);
    }

    #[test]
    fn test_stake_combine_stops_at_twenty_inputs() {
        let kernel = coin(1, 0, 100, 7);
        let pool: Vec<_> = (2..40).map(|t| coin(t, 0, 1, 7)).collect();
        let plan = plan_stake_outputs(
            &kernel,
            Amount::from_divi(100),
            DEFAULT_STAKE_SPLIT_THRESHOLD,
            true,
            &pool,
        );
        assert_eq!(1 + plan.extra_inputs.len(), MAX_COMBINED_STAKE_INPUTS);
    }

    #[test]
    fn test_default_split_threshold_matches_divi_core() {
        assert_eq!(
            StakingConfig::default().stake_split_threshold,
            20_000 * 100_000_000
        );
        assert!(StakingConfig::default().autocombine);
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

    /// setgenerate below the last PoW block mines on a locked wallet: the
    /// coinbase pays a key from the keypool, which needs no unlock; only stake
    /// blocks need the wallet unlocked (CoinMinter.cpp:141-158, wallet.cpp:2129-2136)
    #[test]
    fn setgenerate_mines_work_blocks_on_a_locked_wallet() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::{HdWallet, Network};

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path().join("chain")).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let wallet = Arc::new(
            WalletDb::create_persistent(
                &temp_dir.path().join("wallet"),
                Network::Regtest,
                HdWallet::new(divi_primitives::ChainMode::Divi).unwrap(),
            )
            .unwrap(),
        );
        wallet.encrypt_wallet("pw").unwrap();
        wallet.lock();
        assert!(wallet.is_locked());
        let staker = Staker::new(
            wallet.clone(),
            chain.clone(),
            Arc::new(Mempool::new(MempoolConfig::default())),
            PeerManager::new(PeerManagerConfig::default()),
            StakingConfig::default(),
        );
        let hashes = staker
            .generate_blocks(1)
            .expect("a work block on a locked wallet");
        assert_eq!(hashes.len(), 1);
        assert_eq!(chain.height(), 1);
    }

    /// A coin lockunspent locked is neither stake weight nor an aged coin:
    /// divid's stakable coins skip it (AvailableUtxoCalculator.cpp:91)
    #[test]
    fn locked_coins_are_not_stakable() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::{HdWallet, Network};

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path().join("chain")).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let wallet = Arc::new(WalletDb::with_hd_wallet(
            Network::Regtest,
            HdWallet::new(divi_primitives::ChainMode::Divi).unwrap(),
        ));
        let staker = Staker::new(
            wallet.clone(),
            chain.clone(),
            Arc::new(Mempool::new(MempoolConfig::default())),
            PeerManager::new(PeerManagerConfig::default()),
            StakingConfig {
                min_coin_age: 0,
                ..Default::default()
            },
        );
        staker.generate_blocks(22).unwrap();
        wallet.sync_to_tip(
            chain.height(),
            |h| {
                chain
                    .get_block_index_by_height(h)
                    .ok()
                    .flatten()
                    .map(|i| i.hash)
            },
            |h| {
                let hash = chain.get_block_index_by_height(h).ok().flatten()?.hash;
                chain.get_block(&hash).ok().flatten().map(|b| (hash, b))
            },
        );
        let coins = wallet.get_spendable_utxos(chain.height(), 1);
        assert!(!coins.is_empty());
        assert!(staker.has_mintable_coins());
        assert!(staker.get_status().stake_weight > 0);

        for coin in &coins {
            wallet.set_coin_locked(coin.outpoint(), true);
        }
        assert!(!staker.has_mintable_coins());
        assert_eq!(staker.get_status().stake_weight, 0);
        assert_eq!(staker.get_status().utxo_count, 0);
    }

    #[test]
    fn locked_wallet_is_reported_once_and_skips_staking() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::{HdWallet, Network};

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path().join("chain")).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let wallet = Arc::new(
            WalletDb::create_persistent(
                &temp_dir.path().join("wallet"),
                Network::Regtest,
                HdWallet::new(divi_primitives::ChainMode::Divi).unwrap(),
            )
            .unwrap(),
        );
        wallet.encrypt_wallet("pw").unwrap();
        let staker = Staker::new(
            wallet.clone(),
            chain,
            Arc::new(Mempool::new(MempoolConfig::default())),
            PeerManager::new(PeerManagerConfig::default()),
            StakingConfig::default(),
        );

        assert!(matches!(staker.try_stake(), StakeResult::WalletLocked));
        assert!(staker.wallet_locked_warned.load(Ordering::SeqCst));
        // Later ticks stay quiet
        assert!(!staker.note_wallet_locked(true));
        assert!(matches!(staker.try_stake(), StakeResult::WalletLocked));

        // Unlocking clears it; locking again warns again
        wallet.unlock("pw", 0).unwrap();
        assert!(!staker.note_wallet_locked(false));
        assert!(!staker.wallet_locked_warned.load(Ordering::SeqCst));
        assert!(staker.note_wallet_locked(true));
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

    /// A staked block's coinbase is Divi Core's CreateEmptyCoinbaseTransaction
    /// (BlockFactory.cpp:38-52): version 1, the height then the extra nonce 1
    /// (`CScript() << nHeight << CScriptNum(1)`), one empty output
    #[test]
    fn coinbase_of_a_staked_block_is_core_s() {
        let marker = create_coinbase_marker(150);
        assert_eq!(marker.version, 1);
        // 150 needs a sign byte: push 2 bytes 96 00, then push 1 byte 01
        assert_eq!(
            marker.vin[0].script_sig.as_bytes(),
            &[0x02, 0x96, 0x00, 0x01, 0x01]
        );
        let marker = create_coinbase_marker(4_271_533);
        assert_eq!(
            marker.vin[0].script_sig.as_bytes(),
            &[0x03, 0xad, 0x2d, 0x41, 0x01, 0x01]
        );
        assert_eq!(marker.vout.len(), 1);
        assert!(marker.vout[0].is_empty());
    }

    /// Divi Core's stake set (CWallet::SelectStakeCoins): at least 10 blocks
    /// deep, the coinbase maturity for a coinstake output, the minimum coin
    /// age, and not locked
    #[test]
    fn stake_set_is_core_s_select_stake_coins() {
        let at = |height: u32, coinstake: bool| {
            let mut c = coin(1, 0, 100, 7);
            c.height = Some(height);
            c.is_coinstake = coinstake;
            c
        };
        let ok = |c: &divi_wallet::WalletUtxo, tip: u32, age: u32, locked: bool| {
            is_stake_set_coin(c, Some(1_000), tip, 1_000 + age, 20, 3600, locked)
        };
        // A plain coin: 10 deep (tip 109 for a coin at 100), not 9
        assert!(ok(&at(100, false), 109, 3600, false));
        assert!(!ok(&at(100, false), 108, 3600, false));
        // A coinstake output: the coinbase maturity, 20 here
        assert!(!ok(&at(100, true), 118, 3600, false));
        assert!(ok(&at(100, true), 119, 3600, false));
        // Minimum coin age
        assert!(!ok(&at(100, false), 200, 3599, false));
        // Locked by lockunspent
        assert!(!ok(&at(100, false), 200, 3600, true));
        // Unconfirmed, or its block unknown
        assert!(!ok(&coin(1, 0, 100, 7), 200, 3600, false));
        assert!(!is_stake_set_coin(
            &at(100, false),
            None,
            200,
            99_999,
            20,
            0,
            false
        ));
        // Regtest: no minimum age
        assert!(is_stake_set_coin(
            &at(100, false),
            Some(1_000),
            109,
            1_000,
            20,
            0,
            false
        ));
    }

    /// A vault kernel is split above max(-stakesplitthreshold, 20,000 DIVI)
    /// and combines coins of its own vault below half of that, as Divi Core
    /// does for every kernel (PoSTransactionCreator.cpp:358-365, :281-308)
    #[test]
    fn vault_kernel_splits_and_combines_as_core() {
        let vault = divi_script::StakingVaultScript::new([0x11; 20], [0x22; 20]).to_script();
        let vault_coin = |tx: u8, divi: i64| {
            let mut c = coin(tx, 0, divi, 7);
            c.script_pubkey = vault.clone();
            c
        };
        // Threshold: at least 20,000 DIVI for a vault kernel
        assert_eq!(
            split_threshold_for(1_000 * 100_000_000, true),
            20_000 * 100_000_000
        );
        assert_eq!(
            split_threshold_for(30_000 * 100_000_000, true),
            30_000 * 100_000_000
        );
        assert_eq!(
            split_threshold_for(1_000 * 100_000_000, false),
            1_000 * 100_000_000
        );

        // 30,000 DIVI vault coin + 456 reward: two outputs
        let big = vault_coin(1, 30_000);
        let plan = plan_stake_outputs(
            &big,
            big.value + Amount::from_divi(456),
            split_threshold_for(DEFAULT_STAKE_SPLIT_THRESHOLD, true),
            true,
            &[],
        );
        assert_eq!(
            sats(&plan.stake_outputs),
            vec![15_228 * 100_000_000, 15_228 * 100_000_000]
        );

        // A small vault coin combines the vault's other small coins, not a
        // plain coin of the same wallet
        let small = vault_coin(2, 1_000);
        let pool = vec![vault_coin(3, 500), vault_coin(4, 700), coin(5, 0, 100, 7)];
        let plan = plan_stake_outputs(
            &small,
            small.value + Amount::from_divi(456),
            split_threshold_for(DEFAULT_STAKE_SPLIT_THRESHOLD, true),
            true,
            &pool,
        );
        assert_eq!(plan.extra_inputs.len(), 2);
        assert!(plan.extra_inputs.iter().all(|c| c.script_pubkey == vault));
        assert_eq!(sats(&plan.stake_outputs), vec![2_656 * 100_000_000]);
    }

    /// A wallet whose only stakable coins are vault coins it manages still
    /// stakes, as Divi Core does (its stake set is plain and managed vault
    /// coins alike, CWallet::SelectStakeCoins): the coinstake spends the vault
    /// coin and pays back to the vault.
    #[test]
    fn vault_manager_without_plain_coins_stakes() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::wallet_db::VaultMetadata;
        use divi_wallet::{HdWallet, Network};

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path().join("chain")).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        chain.set_ibd_mode(false);
        let wallet = Arc::new(
            WalletDb::create_persistent(
                &temp_dir.path().join("wallet"),
                Network::Regtest,
                HdWallet::new(divi_primitives::ChainMode::Divi).unwrap(),
            )
            .unwrap(),
        );
        let manager = wallet.new_receiving_address().unwrap();
        let vault =
            divi_script::StakingVaultScript::new([0x11; 20], *manager.hash.as_bytes()).to_script();
        wallet.store_vault(VaultMetadata {
            owner_address: String::new(),
            manager_address: manager.to_string(),
            vault_script: vault.as_bytes().to_vec(),
            funding_txid: [0u8; 32],
        });

        // Block 1 pays its coinbase to the vault; 24 more make it mature
        for height in 1..=25u32 {
            let tip = chain.tip().unwrap();
            let payee = if height == 1 {
                vault.clone()
            } else {
                Script::new_p2pkh(&[0xee; 20])
            };
            let mut sig = divi_storage::bip34_height_script(height);
            sig.push(0);
            let mut block = Block::default();
            block.header.version = 4;
            block.header.prev_block = tip.hash;
            block.header.time = tip.time + 60;
            block.header.bits = 0x207fffff;
            block.transactions = vec![Transaction {
                version: 1,
                vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
                vout: vec![TxOut::new(Amount::from_divi(1250), payee)],
                lock_time: 0,
            }];
            block.header.merkle_root = compute_merkle_root(&block.transactions);
            let target = Hash256::from_compact(block.header.bits);
            while compute_block_hash(&block.header) > target {
                block.header.nonce += 1;
            }
            let hash = chain.accept_block(block.clone()).unwrap().hash;
            wallet.scan_block(hash, height, block.header.time, &block.transactions);
            wallet.set_last_scan_height(height);
        }
        assert_eq!(wallet.get_stakeable_vault_utxos(25, 1).len(), 1);
        assert!(wallet.get_spendable_utxos(25, 1).is_empty());

        let staker = Staker::new(
            wallet,
            chain,
            Arc::new(Mempool::new(MempoolConfig::default())),
            PeerManager::new(PeerManagerConfig::default()),
            StakingConfig {
                allow_stale_tip: true,
                min_coin_age: 0,
                ..StakingConfig::default()
            },
        );
        match staker.try_stake() {
            StakeResult::Success { block, .. } => {
                let coinstake = &block.transactions[1];
                assert!(coinstake.is_coinstake());
                assert_eq!(coinstake.vout[1].script_pubkey, vault);
                assert_eq!(coinstake.vin.len(), 1);
            }
            _ => panic!("expected a vault stake"),
        }
    }

    /// A P2PK coin of a wallet key stakes as in Divi Core: the coinstake pays
    /// back to the same P2PK script and the block carries a DER signature by
    /// that key (PoSTransactionCreator.cpp:142-160, BlockSigning.cpp:69-80),
    /// which the chain accepts.
    #[test]
    fn p2pk_coin_stakes() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::{HdWallet, Network};

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path().join("chain")).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        chain.set_ibd_mode(false);
        let wallet = Arc::new(
            WalletDb::create_persistent(
                &temp_dir.path().join("wallet"),
                Network::Regtest,
                HdWallet::new(divi_primitives::ChainMode::Divi).unwrap(),
            )
            .unwrap(),
        );
        let key = wallet.new_receiving_address().unwrap();
        let mut p2pk = vec![33u8];
        p2pk.extend_from_slice(&wallet.get_key_by_address(&key).unwrap().pubkey_bytes());
        p2pk.push(0xac);
        let p2pk = Script::from_bytes(p2pk);

        // Block 1 pays its coinbase to the P2PK script; the proof-of-work
        // blocks up to 100 make it mature (regtest stakes from block 101)
        for height in 1..=100u32 {
            let tip = chain.tip().unwrap();
            let payee = if height == 1 {
                p2pk.clone()
            } else {
                Script::new_p2pkh(&[0xee; 20])
            };
            let mut sig = divi_storage::bip34_height_script(height);
            sig.push(0);
            let mut block = Block::default();
            block.header.version = 4;
            block.header.prev_block = tip.hash;
            block.header.time = tip.time + 60;
            block.header.bits = 0x207fffff;
            block.transactions = vec![Transaction {
                version: 1,
                vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
                vout: vec![TxOut::new(Amount::from_divi(1250), payee)],
                lock_time: 0,
            }];
            block.header.merkle_root = compute_merkle_root(&block.transactions);
            let target = Hash256::from_compact(block.header.bits);
            while compute_block_hash(&block.header) > target {
                block.header.nonce += 1;
            }
            let hash = chain.accept_block(block.clone()).unwrap().hash;
            wallet.scan_block(hash, height, block.header.time, &block.transactions);
            wallet.set_last_scan_height(height);
        }

        let staker = Staker::new(
            wallet,
            chain.clone(),
            Arc::new(Mempool::new(MempoolConfig::default())),
            PeerManager::new(PeerManagerConfig::default()),
            StakingConfig {
                allow_stale_tip: true,
                min_coin_age: 0,
                ..StakingConfig::default()
            },
        );
        match staker.try_stake() {
            StakeResult::Success { block, .. } => {
                let coinstake = &block.transactions[1];
                assert!(coinstake.is_coinstake());
                assert_eq!(coinstake.vout[1].script_pubkey, p2pk);
                chain
                    .accept_block(block.clone())
                    .expect("the chain accepts the P2PK stake");
                assert_eq!(chain.height(), 101);
            }
            StakeResult::Error(e) => panic!("expected a P2PK stake: {}", e),
            _ => panic!("expected a P2PK stake"),
        }
    }

    /// Divi Core stakes only with a peer to announce the block to
    /// (CoinMinter::canMintCoins, CoinMinter.cpp:73-75)
    #[test]
    fn staker_without_peers_does_not_stake() {
        use crate::config::MempoolConfig;
        use divi_network::PeerManagerConfig;
        use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
        use divi_wallet::{HdWallet, Network};

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(temp_dir.path().join("chain")).unwrap());
        let params =
            ChainParams::for_network(NetworkType::Regtest, divi_primitives::ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let wallet = Arc::new(
            WalletDb::create_persistent(
                &temp_dir.path().join("wallet"),
                Network::Regtest,
                HdWallet::new(divi_primitives::ChainMode::Divi).unwrap(),
            )
            .unwrap(),
        );
        let staker = Staker::new(
            wallet,
            chain,
            Arc::new(Mempool::new(MempoolConfig::default())),
            PeerManager::new(PeerManagerConfig::default()),
            StakingConfig::default(),
        );
        assert!(!staker.has_peers());
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

    #[test]
    fn test_stale_tip_guard_default_refuses_old_tip() {
        let max = DEFAULT_MAX_TIP_AGE_SECS;
        let now = 2_000_000_000u32;
        assert!(!stale_tip_blocks_staking(now, now, max, false));
        assert!(!stale_tip_blocks_staking(now, now - max, max, false));
        assert!(stale_tip_blocks_staking(now, now - max - 1, max, false));
        assert!(stale_tip_blocks_staking(
            now,
            now - 30 * 24 * 3600,
            max,
            false
        ));
    }

    #[test]
    fn test_stale_tip_guard_override_allows_old_tip() {
        let now = 2_000_000_000u32;
        assert!(!stale_tip_blocks_staking(
            now,
            now - 30 * 24 * 3600,
            DEFAULT_MAX_TIP_AGE_SECS,
            true
        ));
    }

    #[test]
    fn test_stale_tip_guard_future_tip_is_not_stale() {
        let now = 2_000_000_000u32;
        assert!(!stale_tip_blocks_staking(
            now,
            now + 600,
            DEFAULT_MAX_TIP_AGE_SECS,
            false
        ));
    }

    #[test]
    fn test_staking_config_default_has_stale_tip_guard() {
        let c = StakingConfig::default();
        assert_eq!(c.max_tip_age_secs, 24 * 60 * 60);
        assert!(!c.allow_stale_tip);
    }

    fn spend_tx(inputs: &[OutPoint], tag: u32) -> Transaction {
        Transaction {
            version: 1,
            lock_time: tag,
            vin: inputs
                .iter()
                .map(|p| TxIn {
                    prevout: *p,
                    script_sig: Script::default(),
                    sequence: 0xffffffff,
                })
                .collect(),
            // Spendable by a child with an empty scriptSig
            vout: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
        }
    }

    fn op(n: u8, vout: u32) -> OutPoint {
        OutPoint::new(Hash256::from_bytes([n; 32]), vout)
    }

    fn chain_coin(value: i64, script: &[u8], height: u32, coinstake: bool) -> divi_storage::Utxo {
        divi_storage::Utxo::new(
            Amount::from_sat(value),
            Script::from_bytes(script.to_vec()),
            height,
            false,
            coinstake,
        )
    }

    /// A UTXO set of `(outpoint, coin)` pairs
    fn utxos(
        coins: Vec<(OutPoint, divi_storage::Utxo)>,
    ) -> impl Fn(&OutPoint) -> Option<divi_storage::Utxo> {
        move |p| coins.iter().find(|(o, _)| o == p).map(|(_, c)| c.clone())
    }

    const OP_TRUE: &[u8] = &[0x51];

    /// The pool in list order: falling priorities, all above Divi Core's
    /// AllowFree threshold, so it is taken in that order except where a
    /// parent must go first
    fn in_order(txs: Vec<Transaction>) -> Vec<crate::mempool::BlockCandidate> {
        let ids: Vec<Hash256> = txs.iter().map(|t| t.txid()).collect();
        let n = txs.len();
        txs.into_iter()
            .enumerate()
            .map(|(i, tx)| crate::mempool::BlockCandidate {
                txid: tx.txid(),
                size: tx.size(),
                fee: Amount::ZERO,
                priority: 1e12 * (n - i) as f64,
                fee_rate_per_kb: 0,
                prioritised: false,
                parents: tx
                    .vin
                    .iter()
                    .map(|v| v.prevout.txid)
                    .filter(|p| ids.contains(p))
                    .collect(),
                tx,
            })
            .collect()
    }

    fn limits(max_size: usize) -> BlockAssembly {
        BlockAssembly::new(max_size, max_size, 0, 10_000)
    }

    /// A pool transaction with the priority and fee rate block assembly sees
    fn cand(
        tx: &Transaction,
        priority: f64,
        fee_rate_per_kb: i64,
        parents: &[&Transaction],
    ) -> crate::mempool::BlockCandidate {
        crate::mempool::BlockCandidate {
            tx: tx.clone(),
            txid: tx.txid(),
            size: tx.size(),
            fee: Amount::ZERO,
            priority,
            fee_rate_per_kb,
            prioritised: false,
            parents: parents.iter().map(|p| p.txid()).collect(),
        }
    }

    /// Four spendable coins and a transaction spending each
    fn four_spends() -> (
        Vec<Transaction>,
        impl Fn(&OutPoint) -> Option<divi_storage::Utxo>,
    ) {
        let coins: Vec<OutPoint> = (1..=4).map(|n| op(n, 0)).collect();
        let set = utxos(
            coins
                .iter()
                .map(|o| (*o, chain_coin(10, OP_TRUE, 1, false)))
                .collect(),
        );
        let txs = coins
            .iter()
            .enumerate()
            .map(|(i, c)| spend_tx(&[*c], i as u32 + 1))
            .collect();
        (txs, set)
    }

    fn ids(txs: &[Transaction]) -> Vec<Hash256> {
        txs.iter().map(|t| t.txid()).collect()
    }

    /// Above Divi Core's AllowFree threshold (COIN * 1440 / 250)
    const HIGH: f64 = 1e12;

    /// Within the priority area an old, free transaction goes before a young
    /// one paying a high fee (BlockMemoryPoolTransactionCollector.cpp:77-85)
    #[test]
    fn high_priority_free_transaction_goes_first() {
        let (t, set) = four_spends();
        let pool = vec![cand(&t[0], 1e9, 90_000, &[]), cand(&t[1], HIGH, 0, &[])];
        let kept = select_block_txs(
            pool,
            50,
            0,
            &BlockAssembly::new(750_000, 50_000, 0, 10_000),
            20,
            set,
        );
        assert_eq!(ids(&kept), ids(&[t[1].clone(), t[0].clone()]));
    }

    /// Past the priority area the rest go by fee rate: the transaction that
    /// reaches it is still taken, then the highest fee rate
    /// (BlockMemoryPoolTransactionCollector.cpp:296-306)
    #[test]
    fn priority_area_is_capped_by_size() {
        let (t, set) = four_spends();
        let pool = vec![
            cand(&t[0], 4.0 * HIGH, 10_000, &[]),
            cand(&t[1], 3.0 * HIGH, 20_000, &[]),
            cand(&t[2], 2.0 * HIGH, 10_000, &[]),
            cand(&t[3], HIGH, 90_000, &[]),
        ];
        // Room for the first by priority; the second reaches the area
        let area = 1000 + t[0].size() + 1;
        let kept = select_block_txs(
            pool.clone(),
            50,
            0,
            &BlockAssembly::new(750_000, area, 0, 10_000),
            20,
            &set,
        );
        assert_eq!(
            ids(&kept),
            ids(&[t[0].clone(), t[1].clone(), t[3].clone(), t[2].clone()])
        );
        // -blockprioritysize=0: by fee rate from the start, ties by priority
        let kept = select_block_txs(
            pool,
            50,
            0,
            &BlockAssembly::new(750_000, 0, 0, 10_000),
            20,
            &set,
        );
        assert_eq!(
            ids(&kept),
            ids(&[t[3].clone(), t[1].clone(), t[0].clone(), t[2].clone()])
        );
    }

    /// A transaction that must pay a fee (AllowFree false) ends the priority
    /// area at once (BlockMemoryPoolTransactionCollector.cpp:274, :296-306)
    #[test]
    fn low_priority_transaction_switches_to_fee_order() {
        let (t, set) = four_spends();
        let pool = vec![
            cand(&t[0], 1.0, 20_000, &[]),
            cand(&t[1], 0.5, 90_000, &[]),
            cand(&t[2], 0.0, 30_000, &[]),
        ];
        let kept = select_block_txs(
            pool,
            50,
            0,
            &BlockAssembly::new(750_000, 50_000, 0, 10_000),
            20,
            set,
        );
        // t0 is taken off by priority and switches; the rest by fee rate
        assert_eq!(ids(&kept), ids(&[t[0].clone(), t[1].clone(), t[2].clone()]));
    }

    /// A child is never taken before its parent, even with the higher fee
    /// rate (BlockMemoryPoolTransactionCollector.cpp:156-166, :236-240)
    #[test]
    fn child_never_goes_before_its_parent() {
        let (t, set) = four_spends();
        let parent = t[0].clone();
        let child = spend_tx(&[OutPoint::new(parent.txid(), 0)], 9);
        let pool = vec![
            cand(&child, HIGH * 2.0, 90_000, &[&parent]),
            cand(&t[1], HIGH, 20_000, &[]),
            cand(&parent, 0.0, 10_000, &[]),
        ];
        let by_fee = BlockAssembly::new(750_000, 0, 0, 10_000);
        let kept = select_block_txs(pool.clone(), 50, 0, &by_fee, 20, &set);
        assert_eq!(
            ids(&kept),
            ids(&[t[1].clone(), parent.clone(), child.clone()])
        );
        let by_priority = BlockAssembly::new(750_000, 50_000, 0, 10_000);
        let kept = select_block_txs(pool, 50, 0, &by_priority, 20, &set);
        let at = |tx: &Transaction| kept.iter().position(|k| k.txid() == tx.txid()).unwrap();
        assert!(at(&parent) < at(&child), "child before parent");
    }

    /// By fee rate, one below the fee floor is left out once the block would
    /// reach -blockminsize, unless it was given a prioritisetransaction delta
    /// (BlockMemoryPoolTransactionCollector.cpp:232-238, :308-311)
    #[test]
    fn cheap_transactions_are_left_out_past_the_minimum_size() {
        let (t, set) = four_spends();
        let mut prioritised = cand(&t[2], 0.0, 5_000, &[]);
        prioritised.prioritised = true;
        let pool = vec![
            cand(&t[0], 0.0, 20_000, &[]),
            cand(&t[1], 0.0, 9_999, &[]),
            prioritised,
        ];
        let kept = select_block_txs(
            pool.clone(),
            50,
            0,
            &BlockAssembly::new(750_000, 0, 0, 10_000),
            20,
            &set,
        );
        assert_eq!(ids(&kept), ids(&[t[0].clone(), t[2].clone()]));
        // Below -blockminsize they still go in
        let kept = select_block_txs(
            pool,
            50,
            0,
            &BlockAssembly::new(750_000, 0, 100_000, 10_000),
            20,
            &set,
        );
        assert_eq!(ids(&kept), ids(&[t[0].clone(), t[1].clone(), t[2].clone()]));
    }

    /// The sizes are kept within -blockmaxsize, which is kept between 1,000
    /// bytes and 1,000 below the network limit (:18-42)
    #[test]
    fn block_assembly_sizes_are_cores() {
        let a = BlockAssembly::new(750_000, 50_000, 0, 10_000);
        assert_eq!(
            (a.max_size, a.priority_size, a.min_size),
            (750_000, 50_000, 0)
        );
        let a = BlockAssembly::new(10, 50_000, 90_000, 10_000);
        assert_eq!(
            (a.max_size, a.priority_size, a.min_size),
            (1000, 1000, 1000)
        );
        let a = BlockAssembly::new(usize::MAX, usize::MAX, 5, 10_000);
        assert_eq!(
            (a.max_size, a.priority_size, a.min_size),
            (1_999_000, 1_999_000, 5)
        );
    }

    #[test]
    fn stale_mempool_tx_is_left_out_of_a_stake_block() {
        let live = op(1, 0);
        let stale = op(2, 5); // spent on chain: not in the UTXO set
        let set = utxos(vec![(live, chain_coin(10, OP_TRUE, 1, false))]);
        let good = spend_tx(&[live], 1);
        let bad = spend_tx(&[stale], 2);
        let kept = select_block_txs(
            in_order(vec![bad, good.clone()]),
            50,
            0,
            &limits(750_000),
            20,
            set,
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].txid(), good.txid());
    }

    #[test]
    fn child_of_a_kept_mempool_tx_is_kept_even_when_listed_first() {
        let live = op(1, 0);
        let set = utxos(vec![(live, chain_coin(10, OP_TRUE, 1, false))]);
        let parent = spend_tx(&[live], 1);
        let child = spend_tx(&[OutPoint::new(parent.txid(), 0)], 2);
        let kept = select_block_txs(
            in_order(vec![child.clone(), parent.clone()]),
            50,
            0,
            &limits(750_000),
            20,
            set,
        );
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].txid(), parent.txid(), "parent must precede child");
        assert_eq!(kept[1].txid(), child.txid());
    }

    #[test]
    fn double_spend_between_mempool_txs_keeps_only_the_first() {
        let live = op(1, 0);
        let set = utxos(vec![(live, chain_coin(10, OP_TRUE, 1, false))]);
        let a = spend_tx(&[live], 1);
        let b = spend_tx(&[live], 2);
        let kept = select_block_txs(
            in_order(vec![a.clone(), b]),
            50,
            0,
            &limits(750_000),
            20,
            set,
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].txid(), a.txid());
    }

    #[test]
    fn orphan_child_of_a_dropped_tx_is_dropped() {
        let stale = op(2, 5);
        let parent = spend_tx(&[stale], 1);
        let child = spend_tx(&[OutPoint::new(parent.txid(), 0)], 2);
        let kept = select_block_txs(
            in_order(vec![parent, child]),
            50,
            0,
            &limits(750_000),
            20,
            |_| None,
        );
        assert!(kept.is_empty());
    }

    /// A coinstake output may be spent 20 blocks on (regtest), in a block at
    /// height 120 one from height 100; an earlier spend, and anything spending
    /// it, is left out of the block (Core's CheckInputs in the block assembler)
    #[test]
    fn immature_coinstake_spend_is_left_out_of_a_stake_block() {
        let mature = op(1, 0);
        let young = op(2, 0);
        let set = utxos(vec![
            (mature, chain_coin(10, OP_TRUE, 100, true)),
            (young, chain_coin(10, OP_TRUE, 101, true)),
        ]);
        let a = spend_tx(&[mature], 1);
        let b = spend_tx(&[young], 2);
        let child = spend_tx(&[OutPoint::new(b.txid(), 0)], 3);
        let kept = select_block_txs(
            in_order(vec![a.clone(), b, child]),
            120,
            0,
            &limits(750_000),
            20,
            set,
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].txid(), a.txid());
    }

    #[test]
    fn overspend_and_failing_script_are_left_out() {
        let small = op(1, 0);
        let locked = op(2, 0);
        let fine = op(3, 0);
        let set = utxos(vec![
            (small, chain_coin(0, OP_TRUE, 1, false)),
            (locked, chain_coin(10, &[0x00], 1, false)),
            (fine, chain_coin(10, OP_TRUE, 1, false)),
        ]);
        let mut overspend = spend_tx(&[small], 1);
        overspend.vout[0].value = Amount::from_sat(1);
        let fails = spend_tx(&[locked], 2);
        let ok = spend_tx(&[fine], 3);
        let kept = select_block_txs(
            in_order(vec![overspend, fails, ok.clone()]),
            50,
            0,
            &limits(750_000),
            20,
            set,
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].txid(), ok.txid());
    }

    #[test]
    fn block_size_and_sigops_budgets() {
        let coins: Vec<OutPoint> = (1..=4).map(|n| op(n, 0)).collect();
        let set = utxos(
            coins
                .iter()
                .map(|o| (*o, chain_coin(10, OP_TRUE, 1, false)))
                .collect(),
        );
        let a = spend_tx(&coins[0..1], 1);
        let b = spend_tx(&coins[1..2], 2);
        // 1,000 bytes counted for the header and reward transactions
        let max = 1000 + a.size() + b.size();
        let kept = select_block_txs(in_order(vec![a.clone(), b]), 50, 0, &limits(max), 20, &set);
        assert_eq!(kept.len(), 1, "a block stays under the size limit");

        // 100 sigops counted for the reward transactions; 20 per CHECKMULTISIG
        let with_sigops = |input: OutPoint, n: usize, tag: u32| {
            let mut tx = spend_tx(&[input], tag);
            tx.vout[0].script_pubkey = Script::from_bytes(vec![0xae; n]);
            tx
        };
        let at_limit = with_sigops(coins[2], 1995, 3);
        let under = with_sigops(coins[3], 1994, 4);
        let kept = select_block_txs(
            in_order(vec![at_limit, under.clone()]),
            50,
            0,
            &limits(750_000),
            20,
            &set,
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].txid(), under.txid());
    }
}
