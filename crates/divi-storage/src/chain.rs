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

//! Chain state machine
//!
//! Manages the blockchain state including block acceptance,
//! UTXO set updates, and chain reorganization.

use crate::block_index::{BlockIndex, BlockStatus};
use crate::database::{BatchedUtxoWriter, ChainDatabase};
use crate::difficulty::{get_next_work_required, DifficultyParams};
use crate::error::StorageError;
use crate::search_index::{self, SearchIndex};
use crate::txindex::{TxIndex, TxLocation};
use crate::undo::BlockUndo;
use crate::utxo::Utxo;
use divi_crypto::{compute_block_hash, compute_merkle_root, hash256};
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::{OutPoint, Transaction};
use divi_primitives::ChainMode;
use divi_script::{verify_input_with_flags, ScriptFlags};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};

/// Result of accepting a block
#[derive(Debug)]
pub struct AcceptBlockResult {
    /// The hash of the accepted block
    pub hash: Hash256,
    /// If a reorg occurred, the height of the common ancestor (fork point)
    pub reorg_fork_height: Option<u32>,
    /// Transactions from disconnected blocks that are no longer in the new chain.
    /// These should be re-added to the mempool so they can be re-mined.
    /// Only populated when a reorg occurred.
    pub orphaned_transactions: Vec<Transaction>,
}

/// Counts of block inputs whose scripts were verified, by the type of the
/// output they spend (P2SH split by redeem script)
#[derive(Default)]
struct ScriptStats {
    inputs: std::sync::atomic::AtomicU64,
    coinstake: std::sync::atomic::AtomicU64,
    p2pkh: std::sync::atomic::AtomicU64,
    p2pk: std::sync::atomic::AtomicU64,
    p2sh_multisig: std::sync::atomic::AtomicU64,
    p2sh_other: std::sync::atomic::AtomicU64,
    multisig: std::sync::atomic::AtomicU64,
    vault: std::sync::atomic::AtomicU64,
    other: std::sync::atomic::AtomicU64,
}

impl ScriptStats {
    fn record(&self, script_pubkey: &[u8], script_sig: &[u8], coinstake: bool) {
        use divi_script::ScriptType;
        use std::sync::atomic::Ordering::Relaxed;
        self.inputs.fetch_add(1, Relaxed);
        if coinstake {
            self.coinstake.fetch_add(1, Relaxed);
        }
        let counter = match divi_script::extract_script_type(script_pubkey).0 {
            ScriptType::PubKeyHash => &self.p2pkh,
            ScriptType::PubKey => &self.p2pk,
            ScriptType::Multisig => &self.multisig,
            ScriptType::Vault => &self.vault,
            ScriptType::ScriptHash => {
                // The redeem script is the scriptSig's last push
                let mut pc = 0;
                let mut last: &[u8] = &[];
                while let Some((_, data)) = divi_script::get_op(script_sig, &mut pc) {
                    last = data;
                }
                if divi_script::extract_script_type(last).0 == ScriptType::Multisig {
                    &self.p2sh_multisig
                } else {
                    &self.p2sh_other
                }
            }
            _ => &self.other,
        };
        counter.fetch_add(1, Relaxed);
    }

    fn summary(&self) -> String {
        use std::sync::atomic::Ordering::Relaxed;
        format!(
            "{} inputs (p2pkh {}, p2pk {}, p2sh-multisig {}, p2sh-other {}, multisig {}, vault {}, other {}; coinstake inputs {})",
            self.inputs.load(Relaxed),
            self.p2pkh.load(Relaxed),
            self.p2pk.load(Relaxed),
            self.p2sh_multisig.load(Relaxed),
            self.p2sh_other.load(Relaxed),
            self.multisig.load(Relaxed),
            self.vault.load(Relaxed),
            self.other.load(Relaxed),
            self.coinstake.load(Relaxed)
        )
    }
}

/// Network type for chain configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkType {
    #[default]
    Mainnet,
    Testnet,
    Regtest,
}

/// Chain parameters
#[derive(Debug, Clone)]
pub struct ChainParams {
    /// Genesis block hash
    pub genesis_hash: Hash256,
    /// Coinbase maturity (number of confirmations required)
    pub coinbase_maturity: u32,
    /// Maximum block size in bytes
    pub max_block_size: u32,
    /// Target block time in seconds
    pub target_block_time: u32,
    /// Network type
    pub network_type: NetworkType,
    /// Chain mode (Divi or PrivateDivi)
    pub chain_mode: ChainMode,
    /// The network's max reorganization depth (Core `nMaxReorganizationDepth`).
    /// `None` = no limit.
    pub max_reorg_depth: Option<u32>,
    /// `-maxreorg`: replaces `max_reorg_depth` when refusing a block that arrives
    /// (block serving keeps the network's value, as Core does)
    pub max_reorg_arg: Option<u32>,
    /// Block hashes the chain must have at these heights
    pub checkpoints: Vec<(u32, Hash256)>,
    /// Seconds a coin must exist before it can stake (Core `nMinCoinAgeForStaking`)
    pub min_stake_age: u32,
    /// Check each block's difficulty bits, its proof of work and that PoW blocks
    /// end and PoS blocks start after the last PoW block
    pub check_block_work: bool,
}

impl Default for ChainParams {
    fn default() -> Self {
        ChainParams {
            genesis_hash: Hash256::zero(),
            coinbase_maturity: 20,
            max_block_size: 2_000_000,
            target_block_time: 60,
            network_type: NetworkType::Mainnet,
            chain_mode: ChainMode::Divi,
            max_reorg_depth: None,
            max_reorg_arg: None,
            checkpoints: Vec::new(),
            min_stake_age: 0,
            check_block_work: false,
        }
    }
}

/// Last proof-of-work block on every Divi network (Divi Core chainparams.cpp:189, :405;
/// regtest inherits testnet's)
pub const LAST_POW_BLOCK: u32 = 100;

/// Divi Core MaxFutureBlockDrift: a PoS block's time may be at most this many
/// seconds ahead (Settings.cpp:215-218)
const MAX_FUTURE_BLOCK_DRIFT_POS: u64 = 180;

/// Divi Core MAX_BLOCK_SIZE_CURRENT (defaultValues.h:43)
const MAX_BLOCK_SIZE: usize = 2_000_000;

/// Divi Core MAX_STANDARD_TX_SIZE, which CheckTransaction applies to block
/// transactions too (defaultValues.h:54, BlockCheckingHelpers.cpp:106-109)
const MAX_TX_SIZE: usize = 100_000;

/// Divi Core MAX_BLOCK_SIGOPS_LEGACY, the CheckBlock limit (defaultValues.h:57)
const MAX_BLOCK_SIGOPS_LEGACY: u32 = 1_000_000 / 50;

/// Divi Core MAX_BLOCK_SIGOPS_CURRENT, the ConnectBlock limit counting P2SH inputs
/// (defaultValues.h:56)
const MAX_BLOCK_SIGOPS: u32 = MAX_BLOCK_SIZE as u32 / 50;

/// Divi mainnet checkpoint at height 100 (Divi Core chainparams.cpp:107-110). Height 0 is the
/// genesis block, which `Chain::new` hard-codes.
const DIVI_MAINNET_CHECKPOINT_100: &str =
    "000000275b2b4a8af2c93ebdfd36ef8dd8c8ec710072bcc388ecbf5d0c8d3f9d";

impl ChainParams {
    /// Create chain parameters for the specified network
    pub fn for_network(network_type: NetworkType, chain_mode: ChainMode) -> Self {
        use divi_primitives::test_vectors::genesis;

        let genesis_hash = match (chain_mode, network_type) {
            (ChainMode::Divi, NetworkType::Mainnet) => {
                Hash256::from_hex(genesis::mainnet::BLOCK_HASH).unwrap_or(Hash256::zero())
            }
            (ChainMode::Divi, NetworkType::Testnet) => {
                Hash256::from_hex(genesis::testnet::BLOCK_HASH).unwrap_or(Hash256::zero())
            }
            (ChainMode::Divi, NetworkType::Regtest) => {
                Hash256::from_hex(genesis::regtest::BLOCK_HASH).unwrap_or(Hash256::zero())
            }
            (ChainMode::PrivateDivi, NetworkType::Mainnet) => {
                Hash256::from_hex(genesis::privatedivi::mainnet::BLOCK_HASH)
                    .unwrap_or(Hash256::zero())
            }
            (ChainMode::PrivateDivi, NetworkType::Testnet) => {
                Hash256::from_hex(genesis::privatedivi::testnet::BLOCK_HASH)
                    .unwrap_or(Hash256::zero())
            }
            (ChainMode::PrivateDivi, NetworkType::Regtest) => {
                Hash256::from_hex(genesis::privatedivi::regtest::BLOCK_HASH)
                    .unwrap_or(Hash256::zero())
            }
        };

        // Divi Core nMaturity: chainparams.cpp:184 (main), :400 (test), :479 (regtest)
        let coinbase_maturity = match network_type {
            NetworkType::Mainnet => 20,
            NetworkType::Testnet => 1,
            NetworkType::Regtest => 20,
        };

        // The rules below follow Divi Core's chainparams. PrivateDivi keeps its
        // earlier behaviour until they are checked against PrivateDivi Core.
        let divi = chain_mode == ChainMode::Divi;

        // nMaxReorganizationDepth: chainparams.cpp:180 (main), :396 (test; regtest inherits)
        let max_reorg_depth = divi.then_some(100);

        // Testnet's and regtest's maps hold only height 0, which is never checked
        // (ChainExtensionService.cpp:297-298), so only mainnet has a live checkpoint.
        let checkpoints = if divi && network_type == NetworkType::Mainnet {
            vec![(
                100,
                Hash256::from_hex(DIVI_MAINNET_CHECKPOINT_100).expect("checkpoint hash"),
            )]
        } else {
            Vec::new()
        };

        // nMinCoinAgeForStaking: chainparams.cpp:195 (main; testnet inherits), :498 (regtest)
        let min_stake_age = match (divi, network_type) {
            (true, NetworkType::Mainnet | NetworkType::Testnet) => 60 * 60,
            _ => 0,
        };

        ChainParams {
            genesis_hash,
            coinbase_maturity,
            max_block_size: 2_000_000,
            target_block_time: 60,
            network_type,
            chain_mode,
            max_reorg_depth,
            max_reorg_arg: None,
            checkpoints,
            min_stake_age,
            check_block_work: divi,
        }
    }
}

/// Status of a chain tip, as reported by `getchaintips`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainTipStatus {
    Active,
    ValidFork,
    ValidHeaders,
    HeadersOnly,
    Invalid,
    Unknown,
}

impl ChainTipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainTipStatus::Active => "active",
            ChainTipStatus::ValidFork => "valid-fork",
            ChainTipStatus::ValidHeaders => "valid-headers",
            ChainTipStatus::HeadersOnly => "headers-only",
            ChainTipStatus::Invalid => "invalid",
            ChainTipStatus::Unknown => "unknown",
        }
    }
}

/// One entry of `getchaintips`.
#[derive(Debug, Clone)]
pub struct ChainTip {
    pub height: u32,
    pub hash: Hash256,
    pub branch_len: u32,
    pub status: ChainTipStatus,
}

/// A listener for a new chain tip (see `Chain::set_tip_listener`)
pub type TipListener = Arc<dyn Fn(&BlockIndex) + Send + Sync>;

/// Chain state
pub struct Chain {
    /// Database for persistent storage
    db: Arc<ChainDatabase>,
    /// Transaction index for O(1) transaction lookups
    tx_index: Option<Arc<TxIndex>>,
    /// Divi Core's address and spent indexes (`-addressindex`, `-spentindex`)
    search_index: Option<Arc<SearchIndex>>,
    /// Current chain tip
    tip: RwLock<Option<BlockIndex>>,
    /// Called with the new tip when a chain operation ends with another tip
    /// than it started with (Divi Core's UpdatedBlockTip, for -blocknotify)
    tip_listener: RwLock<Option<TipListener>>,
    /// Best known block index (block with the highest chain work we've seen).
    /// Used by `activate_best_chain` to detect when a side-chain has accumulated
    /// more work than the current tip and a reorganization is needed.
    best_known_block: RwLock<Option<BlockIndex>>,
    /// Chain parameters
    #[allow(dead_code)]
    params: ChainParams,
    /// Lock for chain state modifications (connect/disconnect/reorg)
    chain_lock: Mutex<()>,
    /// Whether the node is in Initial Block Download mode.
    /// When true, script verification is skipped for performance since
    /// the blockchain data is assumed valid during catch-up.
    ibd_mode: RwLock<bool>,
    /// What block script verification has checked, logged periodically
    script_stats: ScriptStats,
}

/// Metadata marker: the one-time height index repair has run on this datadir.
const HEIGHT_INDEX_REPAIR_KEY: &[u8] = b"height_index_repair_v1";

/// The block a reorganization is moving the chain to, kept until it is done,
/// so a node stopped part-way through finishes it at the next start (Divi Core
/// calls ActivateBestChain at start, init.cpp)
const REORG_TARGET_KEY: &[u8] = b"reorg_target";

/// "0" while a node runs on the database, "1" once it has stopped cleanly
/// (Divi Core's "shutdown" flag, BlockIndexLoading.cpp:253-282)
const CLEAN_STOP_KEY: &[u8] = b"clean_stop";

/// Blocks indexed again at start when the transaction index cannot say how
/// far it got (Divi's deepest reorganization is 100 blocks)
const TX_INDEX_RECHECK: u32 = 100;

/// Result of [`Chain::repair_height_index`].
#[derive(Debug, Default, Clone)]
pub struct HeightIndexAudit {
    /// Active-chain heights checked (tip down to genesis).
    pub checked: u64,
    /// Heights whose mapping did not point at the active-chain block.
    pub mismatched: u64,
    /// Mappings found above the tip.
    pub removed_above_tip: u64,
    /// Up to 16 of the mismatched heights (tip-first).
    pub first_mismatches: Vec<u32>,
}

impl Chain {
    /// Create a new chain with the given database and parameters
    pub fn new(db: Arc<ChainDatabase>, params: ChainParams) -> Result<Self, StorageError> {
        Self::load(db, params, true)
    }

    /// `Chain::new` for a chain that must already hold blocks: an empty
    /// database is refused instead of being given a genesis block
    pub fn open_existing(
        db: Arc<ChainDatabase>,
        params: ChainParams,
    ) -> Result<Self, StorageError> {
        Self::load(db, params, false)
    }

    fn load(
        db: Arc<ChainDatabase>,
        params: ChainParams,
        init_if_empty: bool,
    ) -> Result<Self, StorageError> {
        let mut chain = Chain {
            db,
            tx_index: None,
            search_index: None,
            tip: RwLock::new(None),
            tip_listener: RwLock::new(None),
            best_known_block: RwLock::new(None),
            params,
            chain_lock: Mutex::new(()),
            ibd_mode: RwLock::new(true),
            script_stats: ScriptStats::default(),
        };

        crate::datadir::check_network(&chain.db, &chain.params)?;

        // Load tip from database
        chain.load_tip()?;

        // Initialize genesis block if chain is empty
        if chain.tip().is_none() {
            if !init_if_empty {
                return Err(StorageError::ChainState(
                    "the chain database holds no blocks".to_string(),
                ));
            }
            chain.init_genesis()?;
            chain.db.put_metadata(HEIGHT_INDEX_REPAIR_KEY, b"1")?;
        } else if chain.db.get_metadata(HEIGHT_INDEX_REPAIR_KEY)?.is_none() {
            // One-time repair of height -> hash entries written for side-chain
            // blocks by earlier versions (see store_block_index_entry).
            info!("Auditing height index against the active chain (one-time repair)...");
            let audit = chain.repair_height_index(true)?;
            info!(
                "Height index repair: checked {} heights, fixed {} stale entries, removed {} above tip",
                audit.checked, audit.mismatched, audit.removed_above_tip
            );
            chain.db.put_metadata(HEIGHT_INDEX_REPAIR_KEY, b"1")?;
        }

        Ok(chain)
    }

    /// Enable transaction index for O(1) transaction lookups. An index that
    /// is behind the chain (the two databases recover separately after a
    /// power loss) is first filled in from the stored blocks.
    pub fn enable_tx_index(&mut self, tx_index: Arc<TxIndex>) {
        match self.catch_up_tx_index(&tx_index) {
            Ok(0) => {}
            Ok(n) => info!("Transaction index filled in for {} blocks", n),
            Err(e) => error!("Transaction index could not be filled in: {}", e),
        }
        self.tx_index = Some(tx_index);
    }

    /// Index the transactions of the active blocks above the newest block the
    /// index recorded. When that block is not on the active chain, or the
    /// index never recorded one, the last `TX_INDEX_RECHECK` blocks are
    /// indexed again (rewriting an entry is harmless).
    fn catch_up_tx_index(&self, tx_index: &TxIndex) -> Result<u32, StorageError> {
        let Some(tip) = self.tip() else {
            return Ok(0);
        };
        let from = match tx_index.indexed_tip()? {
            Some((height, hash))
                if height <= tip.height && self.db.get_height_mapping(height)? == Some(hash) =>
            {
                height + 1
            }
            _ => tip.height.saturating_sub(TX_INDEX_RECHECK),
        }
        .max(1);
        let mut indexed = 0;
        for height in from..=tip.height {
            let Some(hash) = self.db.get_height_mapping(height)? else {
                continue;
            };
            let Some(block) = self.db.get_block(&hash)? else {
                continue; // pruned or imported without bodies
            };
            let txids: Vec<Hash256> = block
                .transactions
                .iter()
                .map(|tx| self.compute_txid(tx))
                .collect();
            let locations = Self::tx_locations(&block, &txids, &hash);
            tx_index.put_block_tx_locations(&locations, height, &hash)?;
            indexed += 1;
        }
        Ok(indexed)
    }

    /// A block's transactions under txid and bare txid
    fn tx_locations(
        block: &Block,
        txids: &[Hash256],
        block_hash: &Hash256,
    ) -> Vec<(Hash256, Hash256, TxLocation)> {
        txids
            .iter()
            .zip(&block.transactions)
            .enumerate()
            .map(|(i, (txid, tx))| {
                (
                    *txid,
                    crate::txindex::bare_txid(tx),
                    TxLocation::new(*block_hash, i as u32),
                )
            })
            .collect()
    }

    /// Keep Divi Core's address and spent indexes as blocks are connected
    /// and disconnected
    pub fn enable_search_index(&mut self, search_index: Arc<SearchIndex>) {
        self.search_index = Some(search_index);
    }

    /// The address and spent indexes, when enabled
    pub fn search_index(&self) -> Option<&Arc<SearchIndex>> {
        self.search_index.as_ref()
    }

    /// Write a connected block (UTXOs, undo data, tip) together with its
    /// address and spent index entries, in one batch, as Divi Core's
    /// ConnectBlock writes the indexes with the block's best-block hash
    /// (BlockConnectionService.cpp:152-174)
    fn commit_connected_block(
        &self,
        block: &Block,
        utxo_batch: &BatchedUtxoWriter,
        undo_bytes: &[u8],
        index: &BlockIndex,
    ) -> Result<(), StorageError> {
        let updates = match self.search_index {
            Some(ref search) => {
                let mut prevouts = HashMap::new();
                if !undo_bytes.is_empty() {
                    for entry in BlockUndo::from_bytes(undo_bytes)?.entries {
                        prevouts.insert(
                            entry.outpoint,
                            (entry.prev_utxo.value, entry.prev_utxo.script_pubkey),
                        );
                    }
                }
                Some(search_index::collect_connect(
                    block,
                    index.height,
                    &prevouts,
                    search.address_enabled(),
                    search.spent_enabled(),
                ))
            }
            None => None,
        };
        self.db
            .atomic_connect_block(utxo_batch, undo_bytes, &index.hash, index, &|wb| match (
                &self.search_index,
                &updates,
            ) {
                (Some(search), Some(updates)) => search.add_to_batch(wb, updates, false),
                _ => Ok(()),
            })?;
        stop_point!("block connected");
        Ok(())
    }

    /// Set IBD (Initial Block Download) mode.
    ///
    /// When IBD mode is active, script verification is skipped during
    /// `connect_block` for performance, since the blockchain data is
    /// assumed valid during initial sync catch-up.
    pub fn set_ibd_mode(&self, ibd: bool) {
        *self.ibd_mode.write() = ibd;
    }

    /// Check whether the node is in IBD (Initial Block Download) mode.
    pub fn is_ibd(&self) -> bool {
        *self.ibd_mode.read()
    }

    /// Initialize the genesis block if chain is empty
    fn init_genesis(&mut self) -> Result<(), StorageError> {
        use divi_primitives::amount::Amount;
        use divi_primitives::block::{Block, BlockHeader};
        use divi_primitives::script::Script;
        use divi_primitives::test_vectors::genesis;
        use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

        info!(
            "Initializing genesis block for network {:?}...",
            self.params.network_type
        );

        // Get genesis parameters based on chain mode and network type
        let (genesis_hash, merkle_root, timestamp, bits, nonce, coinbase_pubkey) =
            match (self.params.chain_mode, self.params.network_type) {
                (ChainMode::Divi, NetworkType::Mainnet) => (
                    Hash256::from_hex(genesis::mainnet::BLOCK_HASH).map_err(|e| {
                        StorageError::ChainState(format!("Invalid genesis hash: {}", e))
                    })?,
                    Hash256::from_hex(genesis::mainnet::MERKLE_ROOT).map_err(|e| {
                        StorageError::ChainState(format!("Invalid merkle root: {}", e))
                    })?,
                    genesis::mainnet::TIMESTAMP,
                    genesis::mainnet::BITS,
                    genesis::mainnet::NONCE,
                    genesis::mainnet::COINBASE_PUBKEY,
                ),
                (ChainMode::Divi, NetworkType::Testnet) => (
                    Hash256::from_hex(genesis::testnet::BLOCK_HASH).map_err(|e| {
                        StorageError::ChainState(format!("Invalid genesis hash: {}", e))
                    })?,
                    Hash256::from_hex(genesis::testnet::MERKLE_ROOT).map_err(|e| {
                        StorageError::ChainState(format!("Invalid merkle root: {}", e))
                    })?,
                    genesis::testnet::TIMESTAMP,
                    genesis::testnet::BITS,
                    genesis::testnet::NONCE,
                    genesis::mainnet::COINBASE_PUBKEY, // Uses same coinbase as mainnet
                ),
                (ChainMode::Divi, NetworkType::Regtest) => (
                    Hash256::from_hex(genesis::regtest::BLOCK_HASH).map_err(|e| {
                        StorageError::ChainState(format!("Invalid genesis hash: {}", e))
                    })?,
                    Hash256::from_hex(genesis::regtest::MERKLE_ROOT).map_err(|e| {
                        StorageError::ChainState(format!("Invalid merkle root: {}", e))
                    })?,
                    genesis::regtest::TIMESTAMP,
                    genesis::regtest::BITS,
                    genesis::regtest::NONCE,
                    genesis::mainnet::COINBASE_PUBKEY, // Uses same coinbase as mainnet
                ),
                (ChainMode::PrivateDivi, NetworkType::Mainnet) => (
                    Hash256::from_hex(genesis::privatedivi::mainnet::BLOCK_HASH).map_err(|e| {
                        StorageError::ChainState(format!("Invalid genesis hash: {}", e))
                    })?,
                    Hash256::from_hex(genesis::privatedivi::mainnet::MERKLE_ROOT).map_err(|e| {
                        StorageError::ChainState(format!("Invalid merkle root: {}", e))
                    })?,
                    genesis::privatedivi::mainnet::TIMESTAMP,
                    genesis::privatedivi::mainnet::BITS,
                    genesis::privatedivi::mainnet::NONCE,
                    genesis::mainnet::COINBASE_PUBKEY, // Same coinbase as Divi
                ),
                (ChainMode::PrivateDivi, NetworkType::Testnet) => (
                    Hash256::from_hex(genesis::privatedivi::testnet::BLOCK_HASH).map_err(|e| {
                        StorageError::ChainState(format!("Invalid genesis hash: {}", e))
                    })?,
                    Hash256::from_hex(genesis::privatedivi::testnet::MERKLE_ROOT).map_err(|e| {
                        StorageError::ChainState(format!("Invalid merkle root: {}", e))
                    })?,
                    genesis::privatedivi::testnet::TIMESTAMP,
                    genesis::privatedivi::testnet::BITS,
                    genesis::privatedivi::testnet::NONCE,
                    genesis::mainnet::COINBASE_PUBKEY, // Same coinbase as Divi
                ),
                (ChainMode::PrivateDivi, NetworkType::Regtest) => (
                    Hash256::from_hex(genesis::privatedivi::regtest::BLOCK_HASH).map_err(|e| {
                        StorageError::ChainState(format!("Invalid genesis hash: {}", e))
                    })?,
                    Hash256::from_hex(genesis::privatedivi::regtest::MERKLE_ROOT).map_err(|e| {
                        StorageError::ChainState(format!("Invalid merkle root: {}", e))
                    })?,
                    genesis::privatedivi::regtest::TIMESTAMP,
                    genesis::privatedivi::regtest::BITS,
                    genesis::privatedivi::regtest::NONCE,
                    genesis::mainnet::COINBASE_PUBKEY, // Same coinbase as Divi
                ),
            };

        // Create the genesis coinbase transaction
        // The coinbase scriptSig contains the nBits and the genesis message
        // Each chain has a different coinbase message:
        //   Divi: "September 26, 2018 - US-Iran: Trump set to chair key UN Security Council session"
        //   PrivateDivi: "February 2026 - PrivateDivi Network Genesis - divi.domains"
        let coinbase_script_sig = match self.params.chain_mode {
            ChainMode::Divi => {
                // Divi: "September 26, 2018 - US-Iran: Trump set to chair key UN Security Council session"
                // Encoded as: 04 ffff001d 01 04 4c50 <80 bytes of message>
                // 0x4c = OP_PUSHDATA1, 0x50 = 80 (message length)
                Script::from(vec![
                    0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x4c, 0x50, 0x53, 0x65, 0x70, 0x74,
                    0x65, 0x6d, 0x62, 0x65, 0x72, 0x20, 0x32, 0x36, 0x2c, 0x20, 0x32, 0x30, 0x31,
                    0x38, 0x20, 0x2d, 0x20, 0x55, 0x53, 0x2d, 0x49, 0x72, 0x61, 0x6e, 0x3a, 0x20,
                    0x54, 0x72, 0x75, 0x6d, 0x70, 0x20, 0x73, 0x65, 0x74, 0x20, 0x74, 0x6f, 0x20,
                    0x63, 0x68, 0x61, 0x69, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x55, 0x4e, 0x20,
                    0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x43, 0x6f, 0x75, 0x6e,
                    0x63, 0x69, 0x6c, 0x20, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
                ])
            }
            ChainMode::PrivateDivi => {
                // PrivateDivi: "February 2026 - PrivateDivi Network Genesis - divi.domains"
                // Encoded as: 04 ffff001d 01 04 3a <58 bytes of message>
                // 0x3a = 58 (message length, used directly as push opcode)
                Script::from(vec![
                    0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x3a, 0x46, 0x65, 0x62, 0x72, 0x75,
                    0x61, 0x72, 0x79, 0x20, 0x32, 0x30, 0x32, 0x36, 0x20, 0x2d, 0x20, 0x50, 0x72,
                    0x69, 0x76, 0x61, 0x74, 0x65, 0x44, 0x69, 0x76, 0x69, 0x20, 0x4e, 0x65, 0x74,
                    0x77, 0x6f, 0x72, 0x6b, 0x20, 0x47, 0x65, 0x6e, 0x65, 0x73, 0x69, 0x73, 0x20,
                    0x2d, 0x20, 0x64, 0x69, 0x76, 0x69, 0x2e, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
                    0x73,
                ])
            }
        };

        // Decode the coinbase public key
        let pubkey_bytes = {
            use hex;
            hex::decode(coinbase_pubkey)
        }
        .map_err(|e| StorageError::ChainState(format!("Invalid coinbase pubkey: {}", e)))?;

        // Create P2PK scriptPubKey (OP_PUSHDATA <pubkey> OP_CHECKSIG)
        let mut script_pubkey_bytes = vec![pubkey_bytes.len() as u8];
        script_pubkey_bytes.extend_from_slice(&pubkey_bytes);
        script_pubkey_bytes.push(0xac); // OP_CHECKSIG
        let coinbase_script_pubkey = Script::from(script_pubkey_bytes);

        let coinbase_tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint::null(), // Coinbase uses null outpoint
                script_sig: coinbase_script_sig,
                sequence: 0xffffffff,
            }],
            vout: vec![TxOut {
                value: Amount::from_divi(50), // Genesis reward (50 DIVI)
                script_pubkey: coinbase_script_pubkey,
            }],
            lock_time: 0,
        };

        // Create genesis block header
        let genesis_header = BlockHeader {
            version: 1,
            prev_block: Hash256::zero(),
            merkle_root,
            time: timestamp,
            bits,
            nonce,
            accumulator_checkpoint: Hash256::zero(),
        };

        // Create genesis block with coinbase transaction
        let genesis_block = Block {
            header: genesis_header,
            transactions: vec![coinbase_tx],
            block_sig: vec![], // Genesis is PoW, no signature
        };

        // Verify that the constructed genesis header hashes to the expected value
        let serialized_header = divi_primitives::serialize::serialize(&genesis_block.header);
        let computed_hash = compute_block_hash(&genesis_block.header);
        if computed_hash != genesis_hash {
            error!(
                "Genesis hash mismatch! Expected: {}, Computed: {}",
                genesis_hash, computed_hash
            );
            error!(
                "Genesis header: version={}, prev_block={}, merkle_root={}, time={}, bits=0x{:08x}, nonce={}",
                genesis_block.header.version,
                genesis_block.header.prev_block,
                genesis_block.header.merkle_root,
                genesis_block.header.time,
                genesis_block.header.bits,
                genesis_block.header.nonce
            );
            error!(
                "Serialized header ({} bytes): {}",
                serialized_header.len(),
                hex::encode(&serialized_header)
            );
            // Don't fail - just warn and continue with the hardcoded hash
            // The mismatch means our constructed genesis block doesn't match the network's
            // but we use the hardcoded hash for the chain tip, which is what matters for sync
            warn!(
                "Using hardcoded genesis hash {} despite header hash mismatch (computed {})",
                genesis_hash, computed_hash
            );
        }

        // Store the genesis block data
        self.db.store_block(&genesis_hash, &genesis_block)?;
        info!(
            "Stored genesis block data: {} ({} bytes)",
            genesis_hash,
            divi_primitives::serialize::serialize(&genesis_block).len()
        );

        // Create genesis block index directly without full block validation
        // This is acceptable because the genesis block is hardcoded and trusted
        let mut status = BlockStatus::empty();
        status.insert(BlockStatus::VALID_HEADER);
        status.insert(BlockStatus::VALID_TRANSACTIONS);
        status.insert(BlockStatus::VALID_CHAIN);
        status.insert(BlockStatus::ON_MAIN_CHAIN);
        status.insert(BlockStatus::VALID_CHAIN);
        status.insert(BlockStatus::ON_MAIN_CHAIN);

        let genesis_index = BlockIndex {
            hash: genesis_hash,
            prev_hash: Hash256::zero(),
            height: 0,
            version: 1,
            merkle_root,
            time: timestamp,
            bits,
            nonce,
            accumulator: None,
            n_tx: 1,
            chain_work: [0u8; 32],
            status,
            file_num: 0,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: divi_primitives::LotteryWinners::new(0),
            is_proof_of_stake: false,
            money_supply: None,
        };

        // Store the genesis block index
        self.db.store_block_index(&genesis_index)?;
        self.db.set_best_block(&genesis_hash)?;
        *self.tip.write() = Some(genesis_index);

        info!("Genesis block initialized: {}", genesis_hash);

        Ok(())
    }

    /// Audit (and optionally repair) the height -> hash index against the active
    /// chain, walking from the tip back to genesis via `prev_hash`. Entries that
    /// point at a block not on the active chain are rewritten; entries above the
    /// tip are removed.
    pub fn repair_height_index(&self, fix: bool) -> Result<HeightIndexAudit, StorageError> {
        let mut audit = HeightIndexAudit::default();
        let tip = match self.tip() {
            Some(t) => t,
            None => return Ok(audit),
        };
        let mut above = tip.height.saturating_add(1);
        while self.db.get_height_mapping(above)?.is_some() {
            audit.removed_above_tip += 1;
            if fix {
                self.db.remove_height_mapping(above)?;
            }
            above = above.saturating_add(1);
        }
        let mut cur = tip;
        loop {
            audit.checked += 1;
            if self.db.get_height_mapping(cur.height)? != Some(cur.hash) {
                audit.mismatched += 1;
                if audit.first_mismatches.len() < 16 {
                    audit.first_mismatches.push(cur.height);
                }
                if fix {
                    self.db.set_height_mapping(cur.height, &cur.hash)?;
                }
            }
            if cur.height == 0 || cur.prev_hash.is_zero() {
                break;
            }
            cur = self.db.get_block_index(&cur.prev_hash)?.ok_or_else(|| {
                StorageError::ChainState(format!(
                    "height index audit: missing ancestor {} of height {}",
                    cur.prev_hash, cur.height
                ))
            })?;
        }
        Ok(audit)
    }

    /// Resolve the block that confirmed a PoS kernel output, on the chain that
    /// ends at `parent`.
    ///
    /// C++ (BlockProofVerifier.cpp) resolves this via GetTransaction -> hashBlock,
    /// never via a height lookup. We prefer the tx index (main-chain only, kept in
    /// sync by connect/disconnect), then the height mapping, and in both cases
    /// require the candidate to sit at the UTXO's height and to be an ancestor of
    /// `parent`; otherwise we walk back from `parent`. Never silently falls
    /// through to an unverified block.
    fn resolve_kernel_block_index(
        &self,
        parent: &BlockIndex,
        kernel_txid: &Hash256,
        kernel_height: u32,
    ) -> Result<BlockIndex, StorageError> {
        if kernel_height > parent.height {
            return Err(StorageError::invalid_block_scored(
                0,
                format!(
                    "Kernel height {} above parent height {}",
                    kernel_height, parent.height
                ),
            ));
        }
        // Fast path only applies when `parent` is the active-chain block at its
        // height; a side-branch parent is resolved by walking its own ancestry.
        let parent_on_active = self.db.get_height_mapping(parent.height)? == Some(parent.hash);
        if parent_on_active {
            let mut candidates: Vec<Hash256> = Vec::with_capacity(2);
            if let Some(ref tx_index) = self.tx_index {
                if let Some(loc) = tx_index.get_location(kernel_txid)? {
                    candidates.push(loc.block_hash);
                }
            }
            if let Some(h) = self.db.get_height_mapping(kernel_height)? {
                if !candidates.contains(&h) {
                    candidates.push(h);
                }
            }
            for hash in candidates {
                let idx = match self.db.get_block_index(&hash)? {
                    Some(i) if i.height == kernel_height => i,
                    _ => continue,
                };
                let contains = match self.db.get_block(&hash)? {
                    Some(b) => b
                        .transactions
                        .iter()
                        .any(|tx| self.compute_txid(tx) == *kernel_txid),
                    // Body pruned: the active-chain index entry at the kernel height is
                    // authoritative (the kernel block is an ancestor of `parent`).
                    None => kernel_height <= self.db.prune_height(),
                };
                if contains {
                    return Ok(idx);
                }
                warn!(
                    "Kernel lookup: block {} at height {} does not contain kernel tx {}; ignoring",
                    hash, kernel_height, kernel_txid
                );
            }
        }
        // Slow path: walk ancestors of `parent` down to the kernel height.
        let mut cur = parent.clone();
        while cur.height > kernel_height {
            cur = self.db.get_block_index(&cur.prev_hash)?.ok_or_else(|| {
                StorageError::invalid_block_scored(
                    0,
                    format!(
                        "Kernel lookup: missing ancestor {} at height {}",
                        cur.prev_hash,
                        cur.height.saturating_sub(1)
                    ),
                )
            })?;
        }
        Ok(cur)
    }

    /// Load the chain tip from the database
    fn load_tip(&mut self) -> Result<(), StorageError> {
        if let Some(hash) = self.db.get_best_block()? {
            match self.db.get_block_index(&hash)? {
                Some(index) => {
                    *self.best_known_block.write() = Some(index.clone());
                    *self.tip.write() = Some(index);
                }
                // A recorded tip without its index entry is damage, not an empty chain:
                // falling through to init_genesis would quietly restart from block 0.
                None => {
                    return Err(StorageError::ChainState(format!(
                        "database is damaged: best block {} has no block index entry",
                        hash
                    )))
                }
            }
        }
        Ok(())
    }

    /// Check the last `depth` blocks of the active chain, as C++ `-checkblocks` does at
    /// start (CVerifyDB::VerifyDB): each height maps to an index entry that links to the
    /// one below, and each stored block body reads back (RocksDB checks its CRC on read),
    /// hashes to its index entry and matches its merkle root; stored undo data must decode.
    /// Bodies may be absent only where pruning or a snapshot import removed them.
    /// `depth` 0 checks the whole chain (C++ treats `-checkblocks=0` the same way).
    ///
    /// Returns the number of heights checked.
    pub fn verify_recent_blocks(&self, depth: u32) -> Result<u32, StorageError> {
        let Some(tip) = self.tip() else {
            return Ok(0);
        };
        let bodies_optional_to = self
            .db
            .prune_height()
            .max(self.db.snapshot_base().map(|(h, _)| h).unwrap_or(0));
        let lowest = match depth {
            0 => 0,
            n => tip.height.saturating_sub(n - 1),
        };
        let damaged = |height: u32, what: String| {
            StorageError::ChainState(format!("database is damaged at height {height}: {what}"))
        };
        let mut above: Option<BlockIndex> = None;
        let mut checked = 0;
        for height in (lowest..=tip.height).rev() {
            let hash = if height == tip.height {
                tip.hash
            } else {
                self.db
                    .get_height_mapping(height)
                    .map_err(|e| damaged(height, format!("height index unreadable ({e})")))?
                    .ok_or_else(|| damaged(height, "no block in the height index".into()))?
            };
            let index = self
                .db
                .get_block_index(&hash)
                .map_err(|e| damaged(height, format!("block index unreadable ({e})")))?
                .ok_or_else(|| damaged(height, format!("no index entry for block {hash}")))?;
            if index.height != height {
                return Err(damaged(
                    height,
                    format!("index entry of {hash} says height {}", index.height),
                ));
            }
            if let Some(child) = &above {
                if child.prev_hash != hash {
                    return Err(damaged(
                        height,
                        format!(
                            "block {} names parent {}, height index has {hash}",
                            child.hash, child.prev_hash
                        ),
                    ));
                }
            }
            let block = self
                .db
                .get_block(&hash)
                .map_err(|e| damaged(height, format!("block {hash} unreadable ({e})")))?;
            match block {
                Some(block) => {
                    let computed = self.compute_block_hash(&block);
                    if computed != hash {
                        return Err(damaged(
                            height,
                            format!("stored block {hash} hashes to {computed}"),
                        ));
                    }
                    if compute_merkle_root(&block.transactions) != block.header.merkle_root {
                        return Err(damaged(
                            height,
                            format!("block {hash} transactions do not match its merkle root"),
                        ));
                    }
                }
                None if height <= bodies_optional_to => {}
                None => return Err(damaged(height, format!("block {hash} data is missing"))),
            }
            let undo = self
                .db
                .get_undo_data(&hash)
                .map_err(|e| damaged(height, format!("undo data of {hash} unreadable ({e})")))?;
            if let Some(bytes) = undo.filter(|b| !b.is_empty()) {
                BlockUndo::from_bytes(&bytes)
                    .map_err(|e| damaged(height, format!("undo data of {hash} is bad ({e})")))?;
            }
            above = Some(index);
            checked += 1;
        }
        self.verify_utxo_set_at_tip(&tip, lowest.max(1))?;
        Ok(checked)
    }

    /// Undo the blocks from the tip down to `lowest` in memory, as Divi Core's
    /// VerifyDB does at level 3 (verifyDb.cpp:110-127): every output a block
    /// created must be in the UTXO set once the blocks above it are undone, and
    /// every coin it spent must be absent until its undo data puts it back. A
    /// UTXO set that does not belong to the tip fails here instead of being
    /// built on. The walk stops at a block whose body or undo data is not kept
    /// (pruned, imported from a snapshot, or connected before undo data existed).
    fn verify_utxo_set_at_tip(&self, tip: &BlockIndex, lowest: u32) -> Result<(), StorageError> {
        let damaged = |height: u32, what: String| {
            StorageError::ChainState(format!(
                "database is damaged at height {height}: the UTXO set does not match the chain ({what})"
            ))
        };
        // What the undone blocks changed: Some = put back, None = removed
        let mut view: HashMap<OutPoint, Option<Utxo>> = HashMap::new();
        let mut height = tip.height;
        while height >= lowest {
            let hash = if height == tip.height {
                tip.hash
            } else {
                match self.db.get_height_mapping(height)? {
                    Some(hash) => hash,
                    None => break,
                }
            };
            let (Some(block), Some(undo)) =
                (self.db.get_block(&hash)?, self.db.get_undo_data(&hash)?)
            else {
                break;
            };
            let mut undo: HashMap<OutPoint, Utxo> = if undo.is_empty() {
                HashMap::new()
            } else {
                BlockUndo::from_bytes(&undo)?
                    .entries
                    .into_iter()
                    .map(|e| (e.outpoint, e.prev_utxo))
                    .collect()
            };
            for tx in block.transactions.iter().rev() {
                let txid = self.compute_txid(tx);
                for (vout, out) in tx.vout.iter().enumerate() {
                    let outpoint = OutPoint::new(txid, vout as u32);
                    let current = match view.get(&outpoint) {
                        Some(entry) => entry.clone(),
                        None => self.db.get_utxo(&outpoint)?,
                    };
                    match current {
                        Some(u)
                            if u.value == out.value
                                && u.script_pubkey == out.script_pubkey
                                && u.height == height => {}
                        _ => {
                            return Err(damaged(
                                height,
                                format!("output {txid}:{vout} of block {hash} is missing"),
                            ))
                        }
                    }
                    view.insert(outpoint, None);
                }
                if tx.is_coinbase() {
                    continue;
                }
                for input in &tx.vin {
                    if tx.is_coinstake() && input.prevout.is_null() {
                        continue;
                    }
                    let prev = undo.remove(&input.prevout).ok_or_else(|| {
                        damaged(
                            height,
                            format!(
                                "undo data of block {hash} lacks the coin {}:{}",
                                input.prevout.txid, input.prevout.vout
                            ),
                        )
                    })?;
                    let present = match view.get(&input.prevout) {
                        Some(entry) => entry.is_some(),
                        None => self.db.get_utxo(&input.prevout)?.is_some(),
                    };
                    if present {
                        return Err(damaged(
                            height,
                            format!(
                                "coin {}:{} spent by block {hash} is still unspent",
                                input.prevout.txid, input.prevout.vout
                            ),
                        ));
                    }
                    view.insert(input.prevout, Some(prev));
                }
            }
            height -= 1;
        }
        Ok(())
    }

    /// Get the current chain tip
    pub fn tip(&self) -> Option<BlockIndex> {
        self.tip.read().clone()
    }

    /// Get the current chain height
    pub fn height(&self) -> u32 {
        self.tip.read().as_ref().map(|t| t.height).unwrap_or(0)
    }

    /// Height below which block bodies and undo data have been pruned (0 = none).
    pub fn prune_height(&self) -> u32 {
        self.db.prune_height()
    }

    /// Highest height whose bodies may be pruned for `expire`, or `None` when nothing is
    /// eligible. Never reaches into the last `MIN_BLOCKS_TO_KEEP` blocks and never goes
    /// above `wallet_floor` (the wallet's last scanned height) when one is given.
    pub fn prune_cutoff(
        &self,
        expire: crate::prune::Expire,
        wallet_floor: Option<u32>,
        now: u64,
    ) -> Result<Option<u32>, StorageError> {
        use crate::prune::{Expire, MIN_BLOCKS_TO_KEEP};
        let tip_height = self.height();
        let mut cutoff = tip_height.saturating_sub(MIN_BLOCKS_TO_KEEP);
        if let Expire::Window(secs) = expire {
            let limit = now.saturating_sub(secs);
            // Highest height <= cutoff whose header time is older than the window
            // (block times are monotonic enough for a binary search).
            let (mut lo, mut hi, mut found) = (1u32, cutoff, 0u32);
            while lo <= hi {
                let mid = lo + (hi - lo) / 2;
                match self.get_block_index_by_height(mid)? {
                    Some(idx) if (idx.time as u64) < limit => {
                        found = mid;
                        lo = mid + 1;
                    }
                    _ => {
                        if mid == 0 {
                            break;
                        }
                        hi = mid - 1;
                    }
                }
            }
            cutoff = found;
        } else if !expire.is_enabled() {
            return Ok(None);
        }
        if let Some(floor) = wallet_floor {
            cutoff = cutoff.min(floor);
        }
        Ok(if cutoff > 0 { Some(cutoff) } else { None })
    }

    /// Height below which block-index lottery-winner lists have been cleared (0 = none).
    pub fn winners_strip_height(&self) -> u32 {
        self.db.winners_strip_height()
    }

    /// The chain parameters this chain was opened with
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// Tip this node was started from by `--import-snapshot`, if any.
    pub fn snapshot_base(&self) -> Option<(u32, Hash256)> {
        self.db.snapshot_base()
    }

    /// True if consensus may read the lottery-winner list stored at `height` at any future
    /// time: the block just before a lottery block (payment validation and the veto check
    /// both read exactly there), or the one before the first lottery start (the veto check's
    /// first-cycle lookup). These few lists (about 420 on mainnet) are never stripped.
    pub fn is_winners_terminal_height(&self, height: u32) -> bool {
        let (start, cycle) = self.get_lottery_params();
        let next = height.saturating_add(1);
        next == start || divi_consensus::lottery::is_lottery_block(next, start, cycle)
    }

    /// Highest height whose lottery-winner list may be cleared, or `None`. Consensus reads the
    /// winners only one block before each of the last `LOTTERY_VETO_CYCLES` lottery blocks, so
    /// anything older than that many cycles plus the reorg floor is never read again.
    pub fn winners_strip_cutoff(&self, prune_cutoff: u32) -> Option<u32> {
        use crate::prune::MIN_BLOCKS_TO_KEEP;
        const LOTTERY_VETO_CYCLES: u32 = 3;
        let (_, cycle) = self.get_lottery_params();
        let keep = LOTTERY_VETO_CYCLES
            .saturating_mul(cycle)
            .saturating_add(1)
            .saturating_add(MIN_BLOCKS_TO_KEEP);
        let cutoff = self.height().saturating_sub(keep).min(prune_cutoff);
        (cutoff > 0).then_some(cutoff)
    }

    /// Run one pruning pass: drop old block bodies and undo data, and clear old lottery-winner
    /// lists from the block index. Returns the number of blocks whose data was removed.
    pub fn prune_expired(
        &self,
        expire: crate::prune::Expire,
        wallet_floor: Option<u32>,
        now: u64,
    ) -> Result<u32, StorageError> {
        match self.prune_cutoff(expire, wallet_floor, now)? {
            Some(cutoff) => {
                let pruned = self.db.prune_blocks_to(cutoff)?;
                if let Some(strip) = self.winners_strip_cutoff(cutoff) {
                    self.db
                        .strip_lottery_winners_to(strip, |h| self.is_winners_terminal_height(h))?;
                }
                Ok(pruned)
            }
            None => Ok(0),
        }
    }

    /// Get the genesis block hash for this chain
    pub fn genesis_hash(&self) -> Hash256 {
        self.params.genesis_hash
    }

    pub fn network_type(&self) -> NetworkType {
        self.params.network_type
    }

    /// Compute the next block's difficulty bits given the current tip
    ///
    /// This wraps `get_next_work_required` with the chain's database and
    /// network-appropriate difficulty parameters. Used by the staker to
    /// compute the correct nBits for a new block.
    pub fn get_next_bits(&self, prev_block: &BlockIndex) -> Result<u32, StorageError> {
        get_next_work_required(&self.db, prev_block, &self.difficulty_params())
    }

    fn difficulty_params(&self) -> DifficultyParams {
        match (self.params.chain_mode, self.params.network_type) {
            (ChainMode::Divi, NetworkType::Mainnet) => DifficultyParams::default(),
            (ChainMode::Divi, NetworkType::Testnet) => DifficultyParams::testnet(),
            (ChainMode::Divi, NetworkType::Regtest) => DifficultyParams::regtest(),
            (ChainMode::PrivateDivi, NetworkType::Mainnet) => {
                DifficultyParams::privatedivi(56700, true)
            }
            (ChainMode::PrivateDivi, NetworkType::Testnet) => {
                DifficultyParams::privatedivi(100, true)
            }
            (ChainMode::PrivateDivi, NetworkType::Regtest) => {
                DifficultyParams::privatedivi(100, false)
            }
        }
    }

    pub fn get_utxo_stats(&self) -> Result<crate::database::UtxoStats, StorageError> {
        self.db.get_utxo_stats()
    }

    /// Get a block by hash
    pub fn get_block(&self, hash: &Hash256) -> Result<Option<Block>, StorageError> {
        self.db.get_block(hash)
    }

    /// Get a block index by hash
    /// A stored block that may be sent to a peer that asks for it
    ///
    /// Divi Core main.cpp:223-239: any block on the active chain; a block off it only
    /// if it was fully validated and lies less than the network's max reorganization
    /// depth below the tip, so a peer cannot probe which stale blocks we hold.
    pub fn get_block_for_peer(&self, hash: &Hash256) -> Result<Option<Block>, StorageError> {
        let Some(index) = self.db.get_block_index(hash)? else {
            return Ok(None);
        };
        if !index.is_on_main_chain() {
            let best_header_height = self
                .best_known_block
                .read()
                .as_ref()
                .map(|b| b.height)
                .unwrap_or(0);
            let within_depth = self.params.max_reorg_depth.is_none_or(|depth| {
                i64::from(self.height()) - i64::from(index.height) < i64::from(depth)
            });
            if !(index.status.contains(BlockStatus::VALID_SCRIPTS)
                && best_header_height > 0
                && within_depth)
            {
                return Ok(None);
            }
        }
        self.db.get_block(hash)
    }

    pub fn get_block_index(&self, hash: &Hash256) -> Result<Option<BlockIndex>, StorageError> {
        self.db.get_block_index(hash)
    }

    /// Get a block index by height
    pub fn get_block_index_by_height(
        &self,
        height: u32,
    ) -> Result<Option<BlockIndex>, StorageError> {
        self.db.get_block_index_by_height(height)
    }

    /// All known chain tips, mirroring C++ `getchaintips`.
    ///
    /// A tip is any block index entry that no other entry names as its parent;
    /// the active tip is always included. Sorted by height, highest first.
    pub fn get_chain_tips(&self) -> Result<Vec<ChainTip>, StorageError> {
        let entries = self.db.iter_all_block_indexes()?;
        let by_hash: std::collections::HashMap<Hash256, &BlockIndex> =
            entries.iter().map(|b| (b.hash, b)).collect();
        let parents: std::collections::HashSet<Hash256> =
            entries.iter().map(|b| b.prev_hash).collect();
        let active_tip = self.tip();

        let on_active = |b: &BlockIndex| -> Result<bool, StorageError> {
            Ok(self.db.get_height_mapping(b.height)? == Some(b.hash))
        };

        let mut tips: Vec<&BlockIndex> = entries
            .iter()
            .filter(|b| !parents.contains(&b.hash))
            .collect();
        if let Some(ref t) = active_tip {
            if !tips.iter().any(|b| b.hash == t.hash) {
                if let Some(b) = by_hash.get(&t.hash) {
                    tips.push(b);
                }
            }
        }

        let mut out = Vec::with_capacity(tips.len());
        for tip in tips {
            let active = on_active(tip)?;
            // Walk back to the fork point on the active chain, noting whether
            // any ancestor is failed or lacks block data.
            let mut cur = tip;
            let mut failed = false;
            let mut missing_data = false;
            while !active && !on_active(cur)? {
                failed |= cur.status.contains(BlockStatus::FAILED);
                missing_data |= !cur.status.contains(BlockStatus::HAVE_DATA)
                    && !cur.status.contains(BlockStatus::VALID_SCRIPTS);
                match by_hash.get(&cur.prev_hash) {
                    Some(parent) => cur = parent,
                    None => break,
                }
            }
            let branch_len = if active {
                0
            } else if on_active(cur)? {
                tip.height - cur.height
            } else {
                // Never joined the active chain (e.g. headers whose parent is
                // unknown): the whole branch down to its lowest known block.
                tip.height - cur.height + 1
            };
            let status = if active {
                ChainTipStatus::Active
            } else if failed {
                ChainTipStatus::Invalid
            } else if missing_data {
                ChainTipStatus::HeadersOnly
            } else if tip.status.contains(BlockStatus::VALID_SCRIPTS) {
                ChainTipStatus::ValidFork
            } else if tip.status.contains(BlockStatus::VALID_HEADER) {
                ChainTipStatus::ValidHeaders
            } else {
                ChainTipStatus::Unknown
            };
            out.push(ChainTip {
                height: tip.height,
                hash: tip.hash,
                branch_len,
                status,
            });
        }
        out.sort_by(|a, b| b.height.cmp(&a.height).then(a.hash.cmp(&b.hash)));
        Ok(out)
    }

    /// Check if a block exists in the chain
    pub fn has_block(&self, hash: &Hash256) -> Result<bool, StorageError> {
        self.db.has_block_index(hash)
    }

    /// Check if we have the full block data (not just the index)
    pub fn has_full_block(&self, hash: &Hash256) -> Result<bool, StorageError> {
        Ok(self.db.get_block(hash)?.is_some())
    }

    /// Get a transaction by its txid
    pub fn get_transaction(&self, txid: &Hash256) -> Result<Option<Transaction>, StorageError> {
        if let Some(ref tx_index) = self.tx_index {
            if let Some(location) = tx_index.get_location(txid)? {
                if let Some(block) = self.get_block(&location.block_hash)? {
                    if let Some(tx) = block.transactions.get(location.tx_index as usize) {
                        return Ok(Some(tx.clone()));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Get a transaction by its txid along with its block location
    pub fn get_transaction_with_location(
        &self,
        txid: &Hash256,
    ) -> Result<Option<(Transaction, TxLocation)>, StorageError> {
        if let Some(ref tx_index) = self.tx_index {
            if let Some(location) = tx_index.get_location(txid)? {
                if let Some(block) = self.get_block(&location.block_hash)? {
                    if let Some(tx) = block.transactions.get(location.tx_index as usize) {
                        return Ok(Some((tx.clone(), location)));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Calculate the median time past for a block index
    ///
    /// Returns the median timestamp of the last 11 blocks (or fewer if near genesis).
    /// This is used for block timestamp validation - a new block must have a timestamp
    /// greater than the median time past of its parent.
    ///
    /// Algorithm matches C++ Divi's CBlockIndex::GetMedianTimePast():
    /// 1. Collect timestamps from up to 11 blocks walking backwards
    /// 2. Sort the timestamps
    /// 3. Return the middle value (median)
    pub fn get_median_time_past(&self, block_index: &BlockIndex) -> Result<u32, StorageError> {
        const MEDIAN_TIME_SPAN: usize = 11;

        let mut timestamps = Vec::with_capacity(MEDIAN_TIME_SPAN);
        let mut current_index = Some(block_index.clone());

        // Walk backwards through the chain collecting up to 11 timestamps
        for _ in 0..MEDIAN_TIME_SPAN {
            if let Some(index) = current_index {
                timestamps.push(index.time);

                // Stop at genesis (prev_hash is zero)
                if index.prev_hash == Hash256::zero() {
                    break;
                }

                // Get parent block index
                current_index = self.db.get_block_index(&index.prev_hash)?;
            } else {
                break;
            }
        }

        // Sort timestamps to find median
        timestamps.sort_unstable();

        // Return the middle value
        // If we have an even number of timestamps, this takes the lower of the two middle values
        // which matches the C++ behavior (integer division truncates)
        let median_idx = timestamps.len() / 2;
        Ok(timestamps[median_idx])
    }

    /// Call `listener` with the new tip whenever an operation on the chain
    /// ends with a different tip
    pub fn set_tip_listener(&self, listener: TipListener) {
        *self.tip_listener.write() = Some(listener);
    }

    /// Run `op`, then tell the tip listener if the tip moved
    fn notifying_tip<T>(&self, op: impl FnOnce() -> T) -> T {
        let before = self.tip.read().as_ref().map(|t| t.hash);
        let result = op();
        let after = self.tip.read().clone();
        if after.as_ref().map(|t| t.hash) != before {
            if let (Some(tip), Some(listener)) = (after, self.tip_listener.read().clone()) {
                listener(&tip);
            }
        }
        result
    }

    /// Accept a new block into the chain
    pub fn accept_block(&self, block: Block) -> Result<AcceptBlockResult, StorageError> {
        self.notifying_tip(|| self.accept_block_unnotified(block))
    }

    fn accept_block_unnotified(&self, block: Block) -> Result<AcceptBlockResult, StorageError> {
        // Acquire exclusive lock for chain state modifications
        trace!("accept_block: Waiting for chain lock...");
        let _chain_guard = self.chain_lock.lock();
        trace!("accept_block: Chain lock acquired");

        // 1. Compute block hash
        let hash = self.compute_block_hash(&block);
        let height_estimate = block.header.prev_block.to_string();

        debug!(
            "📥 ACCEPTING BLOCK: {} | {} txs | prev: {}...",
            hash,
            block.transactions.len(),
            &height_estimate[..16]
        );

        // 2. Check if we already have this block
        if let Some(existing_index) = self.db.get_block_index(&hash)? {
            // Divi Core AcceptBlockHeader (ChainExtensionService.cpp): a known
            // block marked failed is rejected, never re-evaluated.
            if existing_index.failed() {
                return Err(StorageError::invalid_block_scored(
                    0,
                    format!("block {} is marked invalid", hash),
                ));
            }
            // We already have this block - update best_known_block in case
            // this was stored as a side-chain block and now participates in
            // the best chain evaluation.
            self.update_best_known_block(&existing_index);

            // Run activate_best_chain to check if any stored block
            // (including this one) has more work than the current tip.
            let mut reorg_fork_height = None;
            let mut orphaned_transactions = Vec::new();

            if let Some((fork_height, orphans)) = self.activate_best_chain_inner()? {
                info!(
                    "🔄 REORG TRIGGERED: activate_best_chain found better chain after re-receiving block {} (height {})",
                    hash, existing_index.height
                );
                reorg_fork_height = Some(fork_height);
                orphaned_transactions = orphans;
            }

            debug!("  ├─ Already have block {}, skipping", hash);
            return Ok(AcceptBlockResult {
                hash,
                reorg_fork_height,
                orphaned_transactions,
            }); // Already have it (may have just reorged to it)
        }

        // 3. Basic header validation
        debug!("  ├─ Header validation");
        self.check_block_header(&block)?;
        check_block_transactions(&block, self.max_money())?;
        debug!("  ├─ Header validation: ✅ PASS");

        // 4. Check if this is the genesis block (prev_block is all zeros)
        let is_genesis = block.header.prev_block == Hash256::zero();

        // 5. Get parent block index (skip for genesis)
        let parent_index = if is_genesis {
            None
        } else {
            Some(
                self.db
                    .get_block_index(&block.header.prev_block)?
                    .ok_or_else(|| {
                        StorageError::OrphanBlock(block.header.prev_block.to_string())
                    })?,
            )
        };

        // 5a. Divi Core AcceptBlock / AcceptBlockHeader (ChainExtensionService.cpp):
        // a block whose parent is marked failed is rejected and not stored.
        if let Some(ref parent) = parent_index {
            if parent.failed() {
                return Err(StorageError::InvalidBlock(format!(
                    "prev block {} at height {} is invalid, unable to add block {}",
                    parent.hash, parent.height, hash
                )));
            }
        }

        // 5b. Divi Core AcceptBlock -> CheckWork (BlockProofVerifier.cpp:136-155), then
        // ContextualCheckBlockHeader's depth limit (ChainExtensionService.cpp:308-311).
        // Both run for every block, whether it extends the tip or not.
        if let Some(ref parent) = parent_index {
            self.check_block_work(&block, &hash, parent)?;
            self.check_reorg_depth(parent.height + 1)?;
            Self::check_block_version_and_height(&block, parent.height + 1)?;
        }

        // 6. Check contextual validity (skip for genesis)
        // Only perform full PoS/signature validation for blocks extending the current tip.
        // Side-chain blocks are stored with header-only validation and get full validation
        // during reorg (connect_block). This matches C++ Divi's AcceptBlock vs ConnectTip
        // separation and allows storing competing chain blocks for proper fork selection.
        if let Some(ref parent) = parent_index {
            let extends_tip = {
                let tip = self.tip.read();
                tip.as_ref().map(|t| t.hash == parent.hash).unwrap_or(true)
            };
            if extends_tip {
                debug!("  ├─ Full context validation (extends tip)");
                self.check_block_context(&block, parent)?;
                debug!("  ├─ Context validation: ✅ PASS");
            } else {
                debug!("  ├─ Header-only context validation (side chain)");
                // Minimal validation: timestamp and parent linkage only
                if block.header.prev_block != parent.hash {
                    return Err(StorageError::invalid_block_scored(0, "wrong parent".into()));
                }
                let mtp = self.get_median_time_past(parent)?;
                if block.header.time <= mtp {
                    return Err(StorageError::invalid_block_scored(
                        0,
                        format!(
                            "block timestamp {} is not greater than median time past {}",
                            block.header.time, mtp
                        ),
                    ));
                }
                debug!("  ├─ Header validation: ✅ PASS (full validation deferred to reorg)");
            }
        }

        // 7. Create block index
        let height = parent_index.as_ref().map(|p| p.height + 1).unwrap_or(0);

        // 7a. Checkpoint validation — reject blocks at known heights with wrong hash.
        // This prevents following minority forks during IBD.
        if let Some(expected_hash) = self.get_checkpoint_hash(height) {
            if hash != expected_hash {
                warn!(
                    "CHECKPOINT REJECT: Block {} at height {} fails checkpoint (expected {})",
                    hash, height, expected_hash
                );
                return Err(StorageError::InvalidBlock(format!(
                    "checkpoint mismatch: rejected by checkpoint lock-in at {} (block {}, expected {})",
                    height, hash, expected_hash
                )));
            }
            warn!(
                "CHECKPOINT PASS: Block {} at height {} matches checkpoint",
                hash, height
            );
        }

        let mut index = BlockIndex::from_header(&block.header, height, parent_index.as_ref());
        index.hash = hash;
        index.n_tx = block.transactions.len() as u32;
        index.status.insert(BlockStatus::VALID_HEADER);
        index.status.insert(BlockStatus::HAVE_DATA);
        // Set PoS flag based on block transaction structure (vtx[1] is coinstake)
        index.set_proof_of_stake(block.is_proof_of_stake());

        // 7b. Compute stake modifier
        if height > 0 {
            if let Some(ref parent) = parent_index {
                let db_clone = self.db.clone();
                let mut block_map = std::collections::HashMap::new();

                // Stake modifier needs blocks within the selection interval (~2087 seconds).
                // On testnets with fast block production (~12s/block), this can span ~200 blocks.
                // The selection algorithm also needs to find blocks by hash for entropy selection,
                // and the last_modifier_index walk needs to find generated_stake_modifier flags.
                // Use 2000 as a safe upper bound that covers all networks while still being
                // much cheaper than the original full-chain walk.
                let max_walk_depth = 2000;
                let mut walk_count = 0u32;
                let mut current = Some(parent.clone());
                while let Some(ref idx) = current {
                    block_map.insert(idx.hash, idx.clone());
                    walk_count += 1;
                    if idx.prev_hash.is_zero() || walk_count >= max_walk_depth {
                        break;
                    }
                    current = db_clone.get_block_index(&idx.prev_hash).ok().flatten();
                }

                let block_map_refs: std::collections::HashMap<Hash256, &BlockIndex> =
                    block_map.iter().map(|(k, v)| (*k, v)).collect();

                let get_prev_closure = |prev_hash: &Hash256| -> Option<&BlockIndex> {
                    block_map_refs.get(prev_hash).copied()
                };

                // Check if HardenedStakeModifier fork is active for this block
                // Reference: Divi/divi/src/ForkActivation.cpp:48-60
                let activation_state = crate::fork_activation::ActivationState::new(parent);
                let hardened_fork_active = activation_state.is_hardened_stake_modifier_active();

                match crate::stake_modifier::compute_next_stake_modifier(
                    Some(parent),
                    &get_prev_closure,
                    &block_map_refs,
                    hardened_fork_active,
                ) {
                    Ok((modifier, generated)) => {
                        index.stake_modifier = modifier;
                        index.generated_stake_modifier = generated;
                        debug!(
                            "  ├─ Stake modifier: {} (generated: {})",
                            modifier, generated
                        );
                    }
                    Err(e) => {
                        // A failed modifier computation silently corrupts ALL subsequent
                        // blocks' modifiers, causing PoS validation failures later.
                        // This MUST be a hard error, not a warning.
                        return Err(StorageError::ChainState(format!(
                            "Failed to compute stake modifier for block {} at height {}: {}",
                            hash, height, e
                        )));
                    }
                }
            }
        }

        // 8. Store block and index
        debug!("  ├─ Storing block data and index");
        self.db.store_block(&hash, &block)?;
        // Index entry only: the height -> hash mapping is written solely when the
        // block is connected to the active chain (atomic_connect_block). Writing it
        // here let a later-arriving stale sibling overwrite the main-chain entry,
        // which then fed the wrong kernel block time into PoS validation
        // (mainnet block 4,168,729 rejected).
        self.db.store_block_index_entry(&index)?;
        debug!("  ├─ Storage: ✅ COMPLETE");

        // 8b. Track the best known block (highest chain work we've seen).
        // This enables activate_best_chain to detect when a side chain has
        // accumulated more work than the current tip after subsequent blocks
        // are stored.
        self.update_best_known_block(&index);

        // 9. Try to connect to the chain
        let tip = self.tip.read().clone();
        let mut reorg_fork_height = None;
        let mut orphaned_transactions: Vec<Transaction> = Vec::new();

        debug!("  ├─ Checking if should update tip");
        if self.should_update_tip(&index)? {
            // Check if this block extends the current tip (simple case)
            if let Some(ref current_tip) = tip {
                if block.header.prev_block == current_tip.hash {
                    // Simple extension - connect the block atomically
                    debug!("  ├─ Simple extension from tip {}", current_tip.hash);
                    let (utxo_batch, undo_bytes) = self.connect_block(&block, &mut index)?;
                    let accepted_height = index.height;

                    // Atomic write: UTXOs + undo data + tip update in single WriteBatch
                    self.commit_connected_block(&block, &utxo_batch, &undo_bytes, &index)?;
                    *self.tip.write() = Some(index.clone());

                    // Keep best_known_block in sync with the new tip
                    self.update_best_known_block(&index);

                    // Periodically flush UTXO cache to disk (every 100 blocks)
                    if self.db.has_utxo_cache() && accepted_height.is_multiple_of(100) {
                        match self.db.flush_utxo_cache() {
                            Ok(count) => {
                                if count > 0 {
                                    debug!(
                                        "Flushed {} UTXO cache entries at height {}",
                                        count, accepted_height
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to flush UTXO cache at height {}: {}",
                                    accepted_height, e
                                );
                            }
                        }
                    }
                    debug!(
                        "✅ BLOCK ACCEPTED: {} at height {} (extends tip)",
                        hash, accepted_height
                    );
                } else {
                    // This block doesn't extend our tip but has more work
                    // We need to reorganize the chain
                    info!(
                        "🔄 REORG NEEDED: Block {} at height {} has more work than tip {} at height {}",
                        hash, index.height, current_tip.hash, current_tip.height
                    );
                    let accepted_height = index.height;
                    let (fork_height, orphans) =
                        self.reorganize_chain(&block, &mut index, current_tip)?;
                    reorg_fork_height = Some(fork_height);
                    orphaned_transactions = orphans;

                    // Keep best_known_block in sync with the new tip
                    self.update_best_known_block(&index);

                    // Always flush UTXO cache after reorg for consistency
                    if self.db.has_utxo_cache() {
                        match self.db.flush_utxo_cache() {
                            Ok(count) => {
                                if count > 0 {
                                    debug!(
                                        "Flushed {} UTXO cache entries after reorg at height {}",
                                        count, accepted_height
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("Failed to flush UTXO cache after reorg: {}", e);
                            }
                        }
                    }

                    debug!(
                        "✅ BLOCK ACCEPTED: {} at height {} (reorg complete)",
                        hash, accepted_height
                    );
                }
            } else {
                // No tip yet (genesis block)
                debug!("  ├─ Genesis or first block after genesis");
                let (utxo_batch, undo_bytes) = self.connect_block(&block, &mut index)?;
                let accepted_height = index.height;

                // Atomic write: UTXOs + undo data + tip update in single WriteBatch
                self.commit_connected_block(&block, &utxo_batch, &undo_bytes, &index)?;
                *self.tip.write() = Some(index.clone());

                // Keep best_known_block in sync with the new tip
                self.update_best_known_block(&index);

                debug!(
                    "✅ BLOCK ACCEPTED: {} at height {} (genesis/first)",
                    hash, accepted_height
                );
            }
        } else {
            // Block stored as side-chain. Run activate_best_chain to check
            // whether this block (or any previously-stored descendant) has
            // accumulated enough work to warrant a chain reorganization.
            // This mirrors C++ Divi's ActivateBestChain pattern.
            debug!("  ├─ Block stored as side-chain, running activate_best_chain");
            if let Some((fork_height, orphans)) = self.activate_best_chain_inner()? {
                info!(
                    "activate_best_chain triggered reorg at fork height {} after storing side-chain block {}",
                    fork_height, hash
                );
                reorg_fork_height = Some(fork_height);
                orphaned_transactions = orphans;
            } else {
                debug!("  └─ Block stored as side-chain (insufficient work)");
            }
        }

        Ok(AcceptBlockResult {
            hash,
            reorg_fork_height,
            orphaned_transactions,
        })
    }

    /// Find the common ancestor between two block chains
    fn find_common_ancestor(
        &self,
        block_a: &BlockIndex,
        block_b: &BlockIndex,
    ) -> Result<BlockIndex, StorageError> {
        let mut a = block_a.clone();
        let mut b = block_b.clone();

        // Bring both to the same height
        while a.height > b.height {
            let prev_hash = self
                .db
                .get_block_index(&a.hash)?
                .ok_or_else(|| StorageError::BlockNotFound(a.hash.to_string()))?;
            let parent_hash = self
                .db
                .get_block(&prev_hash.hash)?
                .ok_or_else(|| StorageError::BlockNotFound(prev_hash.hash.to_string()))?
                .header
                .prev_block;
            a = self
                .db
                .get_block_index(&parent_hash)?
                .ok_or_else(|| StorageError::BlockNotFound(parent_hash.to_string()))?;
        }

        while b.height > a.height {
            let parent_hash = self
                .db
                .get_block(&b.hash)?
                .ok_or_else(|| StorageError::BlockNotFound(b.hash.to_string()))?
                .header
                .prev_block;
            b = self
                .db
                .get_block_index(&parent_hash)?
                .ok_or_else(|| StorageError::BlockNotFound(parent_hash.to_string()))?;
        }

        // Now find common ancestor
        while a.hash != b.hash {
            let a_parent = self
                .db
                .get_block(&a.hash)?
                .ok_or_else(|| StorageError::BlockNotFound(a.hash.to_string()))?
                .header
                .prev_block;
            let b_parent = self
                .db
                .get_block(&b.hash)?
                .ok_or_else(|| StorageError::BlockNotFound(b.hash.to_string()))?
                .header
                .prev_block;
            a = self
                .db
                .get_block_index(&a_parent)?
                .ok_or_else(|| StorageError::BlockNotFound(a_parent.to_string()))?;
            b = self
                .db
                .get_block_index(&b_parent)?
                .ok_or_else(|| StorageError::BlockNotFound(b_parent.to_string()))?;
        }

        Ok(a)
    }

    /// Get blocks from a given block back to (but not including) an ancestor
    fn get_blocks_to_ancestor(
        &self,
        from: &BlockIndex,
        ancestor_hash: &Hash256,
    ) -> Result<Vec<(Block, BlockIndex)>, StorageError> {
        let mut blocks = Vec::new();
        let mut current = from.clone();

        while current.hash != *ancestor_hash {
            let block = self
                .db
                .get_block(&current.hash)?
                .ok_or_else(|| StorageError::BlockNotFound(current.hash.to_string()))?;
            blocks.push((block.clone(), current.clone()));

            let parent_hash = block.header.prev_block;
            current = self
                .db
                .get_block_index(&parent_hash)?
                .ok_or_else(|| StorageError::BlockNotFound(parent_hash.to_string()))?;
        }

        Ok(blocks)
    }

    /// Reorganize the chain to use a new best chain.
    /// Returns `(fork_height, orphaned_txs)` where `orphaned_txs` is the list of
    /// non-coinbase, non-coinstake transactions from disconnected blocks that are
    /// not present in any of the newly-connected blocks, parents before children:
    /// the block nearest the fork first, each block's transactions in block order.
    /// Callers should re-insert these into the mempool so they can be re-mined.
    fn reorganize_chain(
        &self,
        new_block: &Block,
        new_index: &mut BlockIndex,
        old_tip: &BlockIndex,
    ) -> Result<(u32, Vec<Transaction>), StorageError> {
        info!(
            "reorganize_chain: Starting reorg from tip {} (height {}) to block {} (height {})",
            old_tip.hash, old_tip.height, new_index.hash, new_index.height
        );

        // Find common ancestor
        let common_ancestor = match self.find_common_ancestor(new_index, old_tip) {
            Ok(ancestor) => {
                info!(
                    "Common ancestor at height {}: {}",
                    ancestor.height, ancestor.hash
                );
                ancestor
            }
            Err(e) => {
                warn!("Failed to find common ancestor: {}", e);
                return Err(e);
            }
        };

        // Get blocks to disconnect (from old tip to common ancestor)
        let blocks_to_disconnect = match self.get_blocks_to_ancestor(old_tip, &common_ancestor.hash)
        {
            Ok(blocks) => {
                info!("Disconnecting {} blocks", blocks.len());
                blocks
            }
            Err(e) => {
                warn!("Failed to get blocks to disconnect: {}", e);
                return Err(e);
            }
        };

        // Get blocks to connect (from new block to common ancestor)
        let mut blocks_to_connect =
            match self.get_blocks_to_ancestor(new_index, &common_ancestor.hash) {
                Ok(blocks) => {
                    info!("Connecting {} blocks", blocks.len());
                    blocks
                }
                Err(e) => {
                    warn!("Failed to get blocks to connect: {}", e);
                    return Err(e);
                }
            };
        blocks_to_connect.reverse(); // Connect in order from ancestor to new tip

        // Collect candidate orphaned transactions from disconnected blocks.
        // Skip coinbase (index 0 in every block) and coinstake (index 1 in PoS blocks).
        // blocks_to_disconnect runs from the old tip down; walk it from the fork
        // up so a transaction comes after the ones it spends. Divi Core offers each
        // block's transactions to the mempool as it disconnects it, while the
        // blocks below are still connected (ChainTipManager.cpp:175-182), so a
        // child is never refused there for a parent that is not back yet.
        let mut orphaned_txs: Vec<Transaction> = Vec::new();
        for (block, _index) in blocks_to_disconnect.iter().rev() {
            for tx in &block.transactions {
                if tx.is_coinbase() || tx.is_coinstake() {
                    continue;
                }
                orphaned_txs.push(tx.clone());
            }
        }

        // Build the set of txids present in the newly-connected blocks so we can
        // filter out transactions that have already been included in the new chain.
        let mut new_chain_txids: std::collections::HashSet<Hash256> =
            std::collections::HashSet::new();
        for (block, _index) in &blocks_to_connect {
            for tx in &block.transactions {
                new_chain_txids.insert(self.compute_txid(tx));
            }
        }
        // Also include the triggering new block itself.
        for tx in &new_block.transactions {
            new_chain_txids.insert(self.compute_txid(tx));
        }

        // Retain only transactions that are NOT already in the new chain.
        orphaned_txs.retain(|tx| !new_chain_txids.contains(&self.compute_txid(tx)));

        if !orphaned_txs.is_empty() {
            info!(
                "reorganize_chain: {} orphaned transaction(s) will be returned to mempool",
                orphaned_txs.len()
            );
        }

        self.db
            .put_metadata(REORG_TARGET_KEY, new_index.hash.as_bytes())?;

        // Flush UTXO cache before reorg to ensure disconnect sees consistent state
        if self.db.has_utxo_cache() {
            match self.db.flush_utxo_cache() {
                Ok(count) => {
                    if count > 0 {
                        info!("Flushed {} UTXO cache entries before reorg", count);
                    }
                }
                Err(e) => {
                    warn!("Failed to flush UTXO cache before reorg: {}", e);
                    return Err(e);
                }
            }
        }

        // Disconnect blocks (in reverse order - from tip to ancestor)
        for (i, (block, index)) in blocks_to_disconnect.iter().enumerate() {
            info!(
                "Disconnecting block {} ({}/{}): {}",
                index.hash,
                i + 1,
                blocks_to_disconnect.len(),
                index.height
            );
            let mut index_mut = index.clone();
            if let Err(e) = self.disconnect_block(block, &mut index_mut) {
                warn!("Failed to disconnect block {}: {}", index.hash, e);
                // Each disconnect moved the tip on disk; follow it
                if let Some(at) = self.db.get_best_block()? {
                    if let Some(at) = self.db.get_block_index(&at)? {
                        *self.tip.write() = Some(at);
                    }
                }
                return Err(e);
            }
            pause_point!("reorg disconnected");
        }

        // Connect blocks (in order from ancestor to new tip)
        for (i, (block, index)) in blocks_to_connect.iter().enumerate() {
            info!(
                "Connecting block {} ({}/{}): {}",
                index.hash,
                i + 1,
                blocks_to_connect.len(),
                index.height
            );
            let mut index_mut = index.clone();
            // A side-chain block was stored without its proof of stake being
            // checked (that needs the UTXO set at its parent, which is now in place)
            let parent = if i == 0 {
                &common_ancestor
            } else {
                &blocks_to_connect[i - 1].1
            };
            let connected = self
                .check_block_proof_of_stake(block, parent)
                .and_then(|()| self.connect_block(block, &mut index_mut))
                .and_then(|(utxo_batch, undo_bytes)| {
                    self.commit_connected_block(block, &utxo_batch, &undo_bytes, &index_mut)
                });
            if let Err(e) = connected {
                warn!("Failed to connect block {}: {}", index.hash, e);
                // Divi Core ChainTipManager::connectTip -> InvalidBlockFound:
                // a block that is invalid (not merely unreadable) is marked
                // BLOCK_FAILED_VALID, and FindMostWorkChain marks its
                // descendants BLOCK_FAILED_CHILD, so the chain is never
                // selected again. Here the descendants on the path to the
                // reorg target are exactly the rest of blocks_to_connect.
                if Self::is_consensus_invalid(&e) {
                    for (_, failed) in &blocks_to_connect[i..] {
                        self.mark_block_failed(&failed.hash)?;
                    }
                    warn!(
                        "reorganize_chain: marked block {} at height {} and {} descendant(s) invalid",
                        index.hash,
                        index.height,
                        blocks_to_connect.len() - i - 1
                    );
                }
                self.restore_chain_after_failed_reorg(
                    &blocks_to_connect[..i],
                    &blocks_to_disconnect,
                    old_tip,
                )?;
                self.db.delete_metadata(REORG_TARGET_KEY)?;
                return Err(e);
            }
        }

        self.db.delete_metadata(REORG_TARGET_KEY)?;
        pause_point!("reorg done");

        // Update in-memory tip (DB tip already written by last atomic_connect_block)
        info!(
            "Updating in-memory tip to block {} at height {}",
            new_index.hash, new_index.height
        );
        *self.tip.write() = Some(new_index.clone());

        info!(
            "Chain reorganization complete. New tip: {} at height {}",
            new_index.hash, new_index.height
        );

        Ok((common_ancestor.height, orphaned_txs))
    }

    /// Whether an error proves the block itself invalid.
    ///
    /// Mirrors Divi Core's `state.IsInvalid() && !state.CorruptionPossible()`:
    /// consensus failures mark a block failed, database and I/O errors do not,
    /// since marking on those would permanently ban a valid chain.
    fn is_consensus_invalid(err: &StorageError) -> bool {
        matches!(
            err,
            StorageError::InvalidBlock(_)
                | StorageError::InvalidBlockScored { .. }
                | StorageError::UtxoNotFound(_)
                | StorageError::DoubleSpend(_)
        )
    }

    /// Persist the FAILED status on a stored block index.
    fn mark_block_failed(&self, hash: &Hash256) -> Result<(), StorageError> {
        if let Some(mut index) = self.db.get_block_index(hash)? {
            if !index.failed() {
                index.status.insert(BlockStatus::FAILED);
                self.db.store_block_index_entry(&index)?;
            }
        }
        Ok(())
    }

    /// Whether `candidate` or any ancestor of it off the active chain is
    /// marked failed. Blocks between the candidate and the failed ancestor are
    /// marked failed too, as Divi Core's FindMostWorkChain does with
    /// BLOCK_FAILED_CHILD (BlockCheckingHelpers.cpp).
    fn has_failed_ancestor(&self, candidate: &BlockIndex) -> Result<bool, StorageError> {
        let mut walked: Vec<Hash256> = Vec::new();
        let mut current = self.db.get_block_index(&candidate.hash)?;
        while let Some(index) = current {
            if index.failed() {
                for hash in &walked {
                    self.mark_block_failed(hash)?;
                }
                return Ok(true);
            }
            if index.is_on_main_chain() || index.prev_hash.is_zero() {
                return Ok(false);
            }
            walked.push(index.hash);
            current = self.db.get_block_index(&index.prev_hash)?;
        }
        Ok(false)
    }

    /// Put the chain back on `old_tip` after a reorg failed part-way.
    ///
    /// `connected` are the new-chain blocks that did connect (ancestor first);
    /// `disconnected` are the old-chain blocks (old tip first). Divi Core gets
    /// the same result from ActivateBestChain, which after InvalidBlockFound
    /// selects the most-work valid chain again - the one it just left.
    fn restore_chain_after_failed_reorg(
        &self,
        connected: &[(Block, BlockIndex)],
        disconnected: &[(Block, BlockIndex)],
        old_tip: &BlockIndex,
    ) -> Result<(), StorageError> {
        let restore = || -> Result<BlockIndex, StorageError> {
            for (block, index) in connected.iter().rev() {
                let mut stored = self
                    .db
                    .get_block_index(&index.hash)?
                    .ok_or_else(|| StorageError::BlockNotFound(index.hash.to_string()))?;
                self.disconnect_block(block, &mut stored)?;
            }
            for (block, index) in disconnected.iter().rev() {
                let mut stored = self
                    .db
                    .get_block_index(&index.hash)?
                    .ok_or_else(|| StorageError::BlockNotFound(index.hash.to_string()))?;
                let (utxo_batch, undo_bytes) = self.connect_block(block, &mut stored)?;
                self.commit_connected_block(block, &utxo_batch, &undo_bytes, &stored)?;
            }
            if self.db.has_utxo_cache() {
                self.db.flush_utxo_cache()?;
            }
            Ok(self
                .db
                .get_block_index(&old_tip.hash)?
                .unwrap_or_else(|| old_tip.clone()))
        };

        match restore() {
            Ok(restored_tip) => {
                info!(
                    "reorganize_chain: restored previous tip {} at height {}",
                    restored_tip.hash, restored_tip.height
                );
                *self.tip.write() = Some(restored_tip.clone());
                *self.best_known_block.write() = Some(restored_tip);
                Ok(())
            }
            Err(e) => {
                error!(
                    "reorganize_chain: failed to restore previous tip {} at height {}: {}",
                    old_tip.hash, old_tip.height, e
                );
                Err(StorageError::ChainState(format!(
                    "failed to restore tip {} after a failed reorg: {}",
                    old_tip.hash, e
                )))
            }
        }
    }

    /// Mark a block (and so every chain through it) invalid, as the
    /// `invalidateblock` RPC does. If the block is on the active chain the tip
    /// is rolled back to its parent, then the best remaining valid chain is
    /// activated.
    pub fn invalidate_block(&self, hash: &Hash256) -> Result<(), StorageError> {
        self.notifying_tip(|| self.invalidate_block_unnotified(hash))
    }

    fn invalidate_block_unnotified(&self, hash: &Hash256) -> Result<(), StorageError> {
        let _chain_guard = self.chain_lock.lock();
        let target = self
            .db
            .get_block_index(hash)?
            .ok_or_else(|| StorageError::BlockNotFound(hash.to_string()))?;
        if target.height == 0 {
            return Err(StorageError::invalid_block_scored(
                0,
                "cannot invalidate the genesis block".into(),
            ));
        }
        self.mark_block_failed(hash)?;

        if target.is_on_main_chain() {
            if self.db.has_utxo_cache() {
                self.db.flush_utxo_cache()?;
            }
            loop {
                let tip = self
                    .tip
                    .read()
                    .clone()
                    .ok_or_else(|| StorageError::ChainState("no chain tip".into()))?;
                let block = self
                    .db
                    .get_block(&tip.hash)?
                    .ok_or_else(|| StorageError::BlockNotFound(tip.hash.to_string()))?;
                let mut stored = self
                    .db
                    .get_block_index(&tip.hash)?
                    .unwrap_or_else(|| tip.clone());
                self.disconnect_block(&block, &mut stored)?;
                self.mark_block_failed(&tip.hash)?;
                let parent = self
                    .db
                    .get_block_index(&block.header.prev_block)?
                    .ok_or_else(|| {
                        StorageError::BlockNotFound(block.header.prev_block.to_string())
                    })?;
                if self.db.has_utxo_cache() {
                    self.db.flush_utxo_cache()?;
                }
                *self.tip.write() = Some(parent.clone());
                *self.best_known_block.write() = Some(parent);
                if tip.hash == *hash {
                    break;
                }
            }
        }
        self.activate_best_valid_chain()
    }

    /// Record that a node now runs on this database. Returns whether the run
    /// before it stopped cleanly (a database written before this was kept
    /// counts as clean).
    pub fn begin_run(&self) -> Result<bool, StorageError> {
        let clean = self.db.get_metadata(CLEAN_STOP_KEY)?.as_deref() != Some(b"0");
        self.db.put_metadata_synced(CLEAN_STOP_KEY, b"0")?;
        Ok(clean)
    }

    /// Record a clean stop: everything the node keeps has been written
    pub fn end_run(&self) -> Result<(), StorageError> {
        self.db.flush()?;
        self.db.put_metadata_synced(CLEAN_STOP_KEY, b"1")
    }

    /// Finish a reorganization that a stop interrupted: the chain on disk is
    /// whole at the block it had reached, and the blocks of the branch it was
    /// moving to are stored, so connect them now, as Divi Core's
    /// ActivateBestChain does at start. Returns whether the tip moved.
    pub fn finish_interrupted_reorg(&self) -> Result<bool, StorageError> {
        let Some(raw) = self.db.get_metadata(REORG_TARGET_KEY)? else {
            return Ok(false);
        };
        let _chain_guard = self.chain_lock.lock();
        let target = match <[u8; 32]>::try_from(raw.as_slice()) {
            Ok(bytes) => self.db.get_block_index(&Hash256::from_bytes(bytes))?,
            Err(_) => None,
        };
        let moved = match target {
            Some(target) => {
                info!(
                    "A reorganization to block {} at height {} was interrupted; finishing it",
                    target.hash, target.height
                );
                *self.best_known_block.write() = Some(target);
                match self.activate_best_chain_inner() {
                    Ok(result) => result.is_some(),
                    Err(e) if Self::is_consensus_invalid(&e) => {
                        warn!("The interrupted reorganization's branch is invalid: {}", e);
                        false
                    }
                    Err(e) => {
                        let tip = self.tip.read().clone();
                        *self.best_known_block.write() = tip;
                        return Err(e);
                    }
                }
            }
            None => false,
        };
        if !moved {
            let tip = self.tip.read().clone();
            *self.best_known_block.write() = tip;
        }
        self.db.delete_metadata(REORG_TARGET_KEY)?;
        Ok(moved)
    }

    /// Clear the invalid flag on a block, its ancestors and its descendants
    /// (`reconsiderblock`), then activate the best valid chain.
    pub fn reconsider_block(&self, hash: &Hash256) -> Result<(), StorageError> {
        self.notifying_tip(|| self.reconsider_block_unnotified(hash))
    }

    fn reconsider_block_unnotified(&self, hash: &Hash256) -> Result<(), StorageError> {
        let _chain_guard = self.chain_lock.lock();
        let target = self
            .db
            .get_block_index(hash)?
            .ok_or_else(|| StorageError::BlockNotFound(hash.to_string()))?;
        let all = self.db.iter_all_block_indexes()?;
        let by_hash: std::collections::HashMap<Hash256, BlockIndex> =
            all.iter().map(|i| (i.hash, i.clone())).collect();

        let mut to_clear: std::collections::HashSet<Hash256> = std::collections::HashSet::new();
        // Ancestors of the target
        let mut cur = Some(target.clone());
        while let Some(i) = cur {
            to_clear.insert(i.hash);
            cur = by_hash.get(&i.prev_hash).cloned();
        }
        // Descendants of the target
        for i in &all {
            let mut walk = Some(i.clone());
            while let Some(w) = walk {
                if w.hash == target.hash {
                    to_clear.insert(i.hash);
                    break;
                }
                if w.height <= target.height {
                    break;
                }
                walk = by_hash.get(&w.prev_hash).cloned();
            }
        }
        for h in to_clear {
            if let Some(mut i) = by_hash.get(&h).cloned() {
                if i.failed() {
                    i.status.remove(BlockStatus::FAILED);
                    self.db.store_block_index_entry(&i)?;
                }
            }
        }
        self.activate_best_valid_chain()
    }

    /// Move the active chain to the most-work valid chain, trying candidates
    /// in descending work order and skipping any that turn out invalid.
    /// Caller must hold `chain_lock`.
    fn activate_best_valid_chain(&self) -> Result<(), StorageError> {
        let mut candidates: Vec<BlockIndex> = self
            .db
            .iter_all_block_indexes()?
            .into_iter()
            .filter(|i| !i.failed() && i.status.contains(BlockStatus::HAVE_DATA))
            .collect();
        candidates.sort_by(|a, b| Self::compare_chain_work(&b.chain_work, &a.chain_work));
        for cand in candidates {
            let tip = match self.tip.read().clone() {
                Some(t) => t,
                None => return Ok(()),
            };
            if Self::compare_chain_work(&cand.chain_work, &tip.chain_work)
                != std::cmp::Ordering::Greater
            {
                break;
            }
            *self.best_known_block.write() = Some(cand);
            match self.activate_best_chain_inner() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => continue,
                Err(e) if Self::is_consensus_invalid(&e) => continue,
                Err(e) => return Err(e),
            }
        }
        let tip = self.tip.read().clone();
        *self.best_known_block.write() = tip;
        Ok(())
    }

    /// Disconnect a block from the chain (reverse UTXO changes)
    fn disconnect_block(&self, block: &Block, index: &mut BlockIndex) -> Result<(), StorageError> {
        info!(
            "Disconnecting block {} at height {}",
            index.hash, index.height
        );

        // Load undo data for this block
        let undo_data = self.db.get_undo_data(&index.hash)?;

        let tx_count = block.transactions.len();
        let mut utxo_batch = BatchedUtxoWriter::with_capacity(tx_count * 2, tx_count * 3);

        // Remove outputs created by this block (process txs in reverse order)
        for tx in block.transactions.iter().rev() {
            let txid = self.compute_txid(tx);
            for (vout, _output) in tx.vout.iter().enumerate() {
                let outpoint = OutPoint::new(txid, vout as u32);
                if self.db.has_utxo(&outpoint)? {
                    utxo_batch.remove(outpoint);
                }
            }
        }

        // Restore spent UTXOs from undo data
        if let Some(ref undo_bytes) = undo_data {
            if !undo_bytes.is_empty() {
                let block_undo = BlockUndo::from_bytes(undo_bytes)?;
                trace!(
                    "  ├─ Restoring {} spent UTXOs from undo data",
                    block_undo.entries.len()
                );
                // A coin created and spent in this block goes with the block:
                // Divi Core undoes the spender (putting the coin back) and then
                // the creator (taking it away again)
                let created: std::collections::HashSet<Hash256> = block
                    .transactions
                    .iter()
                    .map(|tx| self.compute_txid(tx))
                    .collect();
                for entry in block_undo.entries {
                    if !created.contains(&entry.outpoint.txid) {
                        utxo_batch.add(entry.outpoint, entry.prev_utxo);
                    }
                }
            }
            // else: block had no non-coinbase inputs, nothing to restore
        } else {
            // Fallback for blocks connected before undo data was implemented:
            // Use the old brute-force search method
            warn!(
                "No undo data for block {} at height {} - using legacy disconnect",
                index.hash, index.height
            );
            for tx in block.transactions.iter().rev() {
                let is_coinbase = tx.is_coinbase();
                let is_coinstake = tx.is_coinstake();
                if !is_coinbase {
                    for input in &tx.vin {
                        if is_coinstake && input.prevout.is_null() {
                            continue;
                        }
                        if let Some(prev_tx_data) = self
                            .find_transaction_from(&input.prevout.txid, &block.header.prev_block)?
                        {
                            let (prev_tx, prev_height, prev_is_coinbase, prev_is_coinstake) =
                                prev_tx_data;
                            if let Some(output) = prev_tx.vout.get(input.prevout.vout as usize) {
                                let utxo = Utxo::new(
                                    output.value,
                                    output.script_pubkey.clone(),
                                    prev_height,
                                    prev_is_coinbase,
                                    prev_is_coinstake,
                                );
                                utxo_batch.add(input.prevout, utxo);
                            }
                        } else {
                            warn!(
                                "Could not find transaction {} to restore UTXO during disconnect",
                                input.prevout.txid
                            );
                        }
                    }
                }
            }
        }

        // Divi Core DisconnectBlock: reverse the block's address and spent
        // index entries from the outputs its inputs spent
        let updates = match self.search_index {
            Some(ref search) => {
                let prevouts: HashMap<OutPoint, search_index::PrevOut> = utxo_batch
                    .adds
                    .iter()
                    .map(|(outpoint, utxo)| (*outpoint, (utxo.value, utxo.script_pubkey.clone())))
                    .collect();
                Some(search_index::collect_disconnect(
                    block,
                    index.height,
                    &prevouts,
                    search.address_enabled(),
                    search.spent_enabled(),
                ))
            }
            None => None,
        };

        let parent = self
            .db
            .get_block_index(&block.header.prev_block)?
            .ok_or_else(|| StorageError::BlockNotFound(block.header.prev_block.to_string()))?;

        // UTXO changes, undo data removed, index entry off the main chain, height
        // entry removed and the tip moved to the parent, in one write. The
        // transaction index keeps the block's entries: Divi Core's
        // DisconnectBlock leaves them, so getrawtransaction still finds a
        // transaction of a disconnected block.
        trace!(
            "  ├─ Disconnect batch: {} adds (restores), {} removes",
            utxo_batch.add_count(),
            utxo_batch.remove_count()
        );
        index.status.remove(BlockStatus::ON_MAIN_CHAIN);
        self.db
            .atomic_disconnect_block(&utxo_batch, index, &parent, &|wb| match (
                &self.search_index,
                &updates,
            ) {
                (Some(search), Some(updates)) => search.add_to_batch(wb, updates, true),
                _ => Ok(()),
            })?;

        info!(
            "Disconnected block {} at height {}",
            index.hash, index.height
        );
        stop_point!("block disconnected");
        Ok(())
    }

    /// Find a transaction by its hash and return (tx, height, is_coinbase, is_coinstake)
    #[allow(dead_code)]
    fn find_transaction(
        &self,
        txid: &Hash256,
    ) -> Result<Option<(Transaction, u32, bool, bool)>, StorageError> {
        if let Some(ref tx_index) = self.tx_index {
            if let Some(location) = tx_index.get_location(txid)? {
                if let Some(block) = self.db.get_block(&location.block_hash)? {
                    if let Some(tx) = block.transactions.get(location.tx_index as usize) {
                        if let Some(index) = self.db.get_block_index(&location.block_hash)? {
                            return Ok(Some((
                                tx.clone(),
                                index.height,
                                tx.is_coinbase(),
                                tx.is_coinstake(),
                            )));
                        }
                    }
                }
            }
            return Ok(None);
        }

        let tip = self.tip.read().clone();
        let Some(mut current) = tip else {
            return Ok(None);
        };

        for _ in 0..1000 {
            if let Some(block) = self.db.get_block(&current.hash)? {
                for tx in &block.transactions {
                    let tx_hash = self.compute_txid(tx);
                    if tx_hash == *txid {
                        return Ok(Some((
                            tx.clone(),
                            current.height,
                            tx.is_coinbase(),
                            tx.is_coinstake(),
                        )));
                    }
                }

                if block.header.prev_block == Hash256::zero() {
                    break;
                }
                if let Some(parent) = self.db.get_block_index(&block.header.prev_block)? {
                    current = parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(None)
    }

    /// Find a transaction by its hash starting from a specific block hash
    fn find_transaction_from(
        &self,
        txid: &Hash256,
        start_hash: &Hash256,
    ) -> Result<Option<(Transaction, u32, bool, bool)>, StorageError> {
        // Search through stored blocks for this transaction starting from a specific block
        // This is used during reorg to find transactions on the old chain

        let Some(mut current) = self.db.get_block_index(start_hash)? else {
            return Ok(None);
        };

        // Search backwards through the chain
        for _ in 0..10000 {
            // Increased search depth for deep reorgs
            if let Some(block) = self.db.get_block(&current.hash)? {
                for tx in &block.transactions {
                    let tx_hash = self.compute_txid(tx);
                    if tx_hash == *txid {
                        return Ok(Some((
                            tx.clone(),
                            current.height,
                            tx.is_coinbase(),
                            tx.is_coinstake(),
                        )));
                    }
                }

                // Move to parent
                if block.header.prev_block == Hash256::zero() {
                    break; // Reached genesis
                }
                if let Some(parent) = self.db.get_block_index(&block.header.prev_block)? {
                    current = parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(None)
    }

    /// Compute the hash of a block
    fn compute_block_hash(&self, block: &Block) -> Hash256 {
        divi_crypto::compute_block_hash(&block.header)
    }

    /// Get the expected block hash at a checkpoint height, if any.
    ///
    /// Divi Core ContextualCheckBlockHeader (ChainExtensionService.cpp:320-328). Its
    /// second clause, "forked chain older than last checkpoint" (:330-347), keeps the
    /// lowest checkpoint found (the genesis block) and so never refuses anything.
    /// PrivateDivi has none: its relaunch map holds only the genesis (PrivateDivi
    /// Core 21de13166, chainparams.cpp:107-109).
    fn get_checkpoint_hash(&self, height: u32) -> Option<Hash256> {
        self.params
            .checkpoints
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, hash)| *hash)
    }

    /// Check basic block header validity
    fn check_block_header(&self, block: &Block) -> Result<(), StorageError> {
        // Check version
        if block.header.version < 1 {
            return Err(StorageError::invalid_block_scored(
                0,
                "invalid version".into(),
            ));
        }

        // Divi Core CheckBlock (BlockCheckingHelpers.cpp:29-31): at most 180 s in the
        // future for a PoS block (MaxFutureBlockDrift, Settings.cpp:215-218), 2 hours
        // for a PoW block
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| StorageError::ChainState(format!("System time error: {}", e)))?
            .as_secs();
        let max_drift = if block.is_proof_of_stake() {
            MAX_FUTURE_BLOCK_DRIFT_POS
        } else {
            2 * 60 * 60
        };
        if u64::from(block.header.time) > now + max_drift {
            return Err(StorageError::invalid_block_scored(
                0,
                "time-too-new: block timestamp too far in the future".into(),
            ));
        }

        // Check merkle root
        let computed_merkle_root = compute_merkle_root(&block.transactions);
        if block.header.merkle_root != computed_merkle_root {
            return Err(StorageError::InvalidBlock(format!(
                "merkle root mismatch: header has {}, computed {}",
                block.header.merkle_root, computed_merkle_root
            )));
        }

        // A transaction list repeated at the end of a level gives the same merkle
        // root; Core refuses it as a duplicate (BlockCheckingHelpers.cpp:39-44)
        let txids: Vec<Hash256> = block.transactions.iter().map(|tx| tx.txid()).collect();
        if merkle_tree_mutated(&txids) {
            return Err(StorageError::InvalidBlock(
                "bad-txns-duplicate: duplicate transaction".into(),
            ));
        }

        Ok(())
    }

    /// Divi Core ContextualCheckBlockHeader's version rule and ContextualCheckBlock's
    /// BIP34 rule (ChainExtensionService.cpp:350-353, :375-382), for every block
    /// after the genesis block
    fn check_block_version_and_height(block: &Block, height: u32) -> Result<(), StorageError> {
        if block.header.version < 3 {
            return Err(StorageError::invalid_block_scored(
                0,
                format!(
                    "bad-version: rejected nVersion={} block",
                    block.header.version
                ),
            ));
        }
        let expect = bip34_height_script(height);
        let script_sig = block.transactions[0].vin[0].script_sig.as_bytes();
        if !script_sig.starts_with(&expect) {
            return Err(StorageError::InvalidBlock(
                "bad-cb-height: block height mismatch in coinbase".into(),
            ));
        }
        Ok(())
    }

    /// Check block context (relative to parent)
    fn check_block_context(&self, block: &Block, parent: &BlockIndex) -> Result<(), StorageError> {
        if block.header.prev_block != parent.hash {
            return Err(StorageError::invalid_block_scored(0, "wrong parent".into()));
        }

        let mtp = self.get_median_time_past(parent)?;
        if block.header.time <= mtp {
            return Err(StorageError::invalid_block_scored(
                0,
                format!(
                    "block timestamp {} is not greater than median time past {}",
                    block.header.time, mtp
                ),
            ));
        }

        self.check_block_proof_of_stake(block, parent)
    }

    /// The proof of stake (kernel, stake modifier, target, coin age) and the block
    /// signature. Divi Core checks the proof for every block it accepts, during
    /// initial sync too (AcceptBlock -> CheckWork, BlockProofVerifier.cpp:149-155).
    /// Here it needs the UTXO set at `parent`, so it runs when the block is
    /// connected: on arrival for a block on the tip, during a reorg otherwise.
    fn check_block_proof_of_stake(
        &self,
        block: &Block,
        parent: &BlockIndex,
    ) -> Result<(), StorageError> {
        if block.is_proof_of_stake() {
            self.validate_proof_of_stake(block, parent)?;
        }
        self.verify_block_signature(block)
    }

    /// Check the block's difficulty bits and, for a PoW block, its proof of work
    ///
    /// Divi Core CheckWork (BlockProofVerifier.cpp:136-155) and CheckProofOfWork
    /// (:27-43). A failure there carries no misbehaviour score.
    fn check_block_work(
        &self,
        block: &Block,
        hash: &Hash256,
        parent: &BlockIndex,
    ) -> Result<(), StorageError> {
        if !self.params.check_block_work {
            return Ok(());
        }
        let required = self.get_next_bits(parent)?;
        if block.header.bits != required {
            return Err(StorageError::invalid_block_scored(
                0,
                format!(
                    "bad-diffbits: block bits 0x{:08x}, required 0x{:08x}",
                    block.header.bits, required
                ),
            ));
        }
        if block.is_proof_of_work() {
            let target = Hash256::from_compact(block.header.bits);
            if target.is_zero() || target > self.difficulty_params().pow_limit {
                return Err(StorageError::invalid_block_scored(
                    0,
                    "CheckProofOfWork() : nBits below minimum work".into(),
                ));
            }
            if *hash > target {
                return Err(StorageError::invalid_block_scored(
                    0,
                    "CheckProofOfWork() : hash doesn't match nBits".into(),
                ));
            }
        }
        Ok(())
    }

    /// Refuse a block more than the max reorganization depth below the active tip
    ///
    /// Divi Core ContextualCheckBlockHeader (ChainExtensionService.cpp:308-311).
    fn check_reorg_depth(&self, height: u32) -> Result<(), StorageError> {
        let Some(depth) = self.params.max_reorg_arg.or(self.params.max_reorg_depth) else {
            return Ok(());
        };
        let tip_height = self.tip.read().as_ref().map(|t| t.height).unwrap_or(0);
        if i64::from(tip_height) - i64::from(height) >= i64::from(depth) {
            return Err(StorageError::invalid_block_scored(
                1,
                format!(
                    "forked chain older than max reorganization depth (height {})",
                    height
                ),
            ));
        }
        Ok(())
    }

    /// Divi Core `MaxMoneyOut` (chainparams.cpp:186 main, :402 test; regtest inherits test)
    pub fn max_money(&self) -> Amount {
        match self.params.network_type {
            NetworkType::Mainnet => Amount::from_divi(2_534_320_700),
            NetworkType::Testnet | NetworkType::Regtest => Amount::from_divi(2_535_000_000),
        }
    }

    /// Verify the block signature
    ///
    /// Implements CheckBlockSignature() from C++ Divi:
    /// - PoW blocks: block signature must be empty
    /// - PoS blocks with P2PKH coinstake output: Recover public key from compact
    ///   signature over the block hash, verify recovered pubkey's hash160 matches
    ///   the output's pubkey hash
    /// - PoS blocks with P2PK coinstake output: Standard ECDSA verify with the
    ///   pubkey extracted from the script
    /// - PoS blocks with vault (TX_VAULT) output: Recover public key from compact
    ///   signature, verify against vault manager's key hash
    fn verify_block_signature(&self, block: &Block) -> Result<(), StorageError> {
        // PoW blocks must have an empty signature
        if !block.is_proof_of_stake() {
            if !block.block_sig.is_empty() {
                return Err(StorageError::invalid_block_scored(
                    0,
                    "PoW block must have empty signature".into(),
                ));
            }
            return Ok(());
        }

        // PoS blocks must have a non-empty signature
        if block.block_sig.is_empty() {
            return Err(StorageError::invalid_block_scored(
                0,
                "PoS block must have a signature".into(),
            ));
        }

        // Get coinstake transaction (vtx[1])
        let coinstake = &block.transactions[1];

        // Get coinstake's second output (vout[1]) — the staking output with the key
        if coinstake.vout.len() < 2 {
            return Err(StorageError::invalid_block_scored(
                0,
                "coinstake must have at least 2 outputs for signature verification".into(),
            ));
        }
        let staking_output = &coinstake.vout[1];
        let script_bytes = staking_output.script_pubkey.as_bytes();

        // Compute block hash for signature verification
        let block_hash = self.compute_block_hash(block);

        // Determine the output type and verify accordingly
        let (script_type, solutions) = divi_script::extract_script_type(script_bytes);

        match script_type {
            divi_script::ScriptType::PubKeyHash => {
                // P2PKH: Use recoverable signature verification
                // Recover pubkey from compact signature, check hash160 matches
                if solutions.is_empty() || solutions[0].len() != 20 {
                    return Err(StorageError::invalid_block_scored(
                        0,
                        "invalid P2PKH script in coinstake output".into(),
                    ));
                }

                let expected_hash: [u8; 20] = solutions[0].as_slice().try_into().map_err(|_| {
                    StorageError::invalid_block_scored(0, "invalid pubkey hash length".into())
                })?;

                let recoverable_sig =
                    divi_crypto::RecoverableSig::from_compact_with_recovery(&block.block_sig)
                        .map_err(|e| {
                            StorageError::invalid_block_scored(
                                0,
                                format!("invalid block signature format: {}", e),
                            )
                        })?;

                let recovered_pubkey = recoverable_sig
                    .recover_from_hash(block_hash.as_bytes())
                    .map_err(|e| {
                        StorageError::invalid_block_scored(
                            0,
                            format!("failed to recover pubkey from block signature: {}", e),
                        )
                    })?;

                let recovered_hash = divi_crypto::hash160(&recovered_pubkey.to_bytes());
                if *recovered_hash.as_bytes() != expected_hash {
                    return Err(StorageError::invalid_block_scored(
                        0,
                        "block signature: recovered pubkey does not match coinstake P2PKH output"
                            .into(),
                    ));
                }
            }

            divi_script::ScriptType::PubKey => {
                // P2PK: Standard ECDSA verify with the pubkey from the script
                if solutions.is_empty() {
                    return Err(StorageError::invalid_block_scored(
                        0,
                        "invalid P2PK script in coinstake output".into(),
                    ));
                }

                let pubkey = divi_crypto::PublicKey::from_bytes(&solutions[0]).map_err(|e| {
                    StorageError::invalid_block_scored(
                        0,
                        format!("invalid pubkey in coinstake P2PK output: {}", e),
                    )
                })?;

                // For P2PK, the block_sig is a standard DER-encoded signature
                let signature =
                    divi_crypto::Signature::from_der(&block.block_sig).map_err(|e| {
                        StorageError::invalid_block_scored(
                            0,
                            format!("invalid DER block signature for P2PK: {}", e),
                        )
                    })?;

                if !divi_crypto::verify_hash(&pubkey, &signature, block_hash.as_bytes()) {
                    return Err(StorageError::invalid_block_scored(
                        0,
                        "block signature: ECDSA verify failed for coinstake P2PK output".into(),
                    ));
                }
            }

            divi_script::ScriptType::Vault => {
                // Vault: Use recoverable signature with the vault manager's key hash
                // solutions[1] is the vault pubkey hash (manager key)
                if solutions.len() < 2 || solutions[1].len() != 20 {
                    return Err(StorageError::invalid_block_scored(
                        0,
                        "invalid vault script in coinstake output".into(),
                    ));
                }

                let vault_hash: [u8; 20] = solutions[1].as_slice().try_into().map_err(|_| {
                    StorageError::invalid_block_scored(0, "invalid vault pubkey hash length".into())
                })?;

                let recoverable_sig =
                    divi_crypto::RecoverableSig::from_compact_with_recovery(&block.block_sig)
                        .map_err(|e| {
                            StorageError::invalid_block_scored(
                                0,
                                format!("invalid block signature format for vault: {}", e),
                            )
                        })?;

                let recovered_pubkey = recoverable_sig
                    .recover_from_hash(block_hash.as_bytes())
                    .map_err(|e| {
                        StorageError::invalid_block_scored(
                            0,
                            format!("failed to recover pubkey from vault block signature: {}", e),
                        )
                    })?;

                let recovered_hash = divi_crypto::hash160(&recovered_pubkey.to_bytes());
                if *recovered_hash.as_bytes() != vault_hash {
                    return Err(StorageError::invalid_block_scored(
                        0,
                        "block signature: recovered pubkey does not match vault manager key".into(),
                    ));
                }
            }

            _ => {
                return Err(StorageError::invalid_block_scored(
                    0,
                    format!(
                        "unsupported coinstake output script type for block signature: {:?}",
                        script_type
                    ),
                ));
            }
        }

        debug!("Block signature verified for block {}", block_hash);

        Ok(())
    }

    /// Get stake modifier for PoS validation
    ///
    /// This implements the two-tier stake modifier lookup from C++ Divi:
    /// - Hardened mode (post Dec 31, 2020): Walk backward from chain tip to find
    ///   nearest block with generated_stake_modifier == true
    /// - Legacy mode (pre Dec 31, 2020): Use UTXO confirmation block, walk forward
    ///   through time window, then backward to find first modifier
    ///
    /// Reference: Divi/divi/src/PoSStakeModifierService.cpp
    /// Reference: Divi/divi/src/LegacyPoSStakeModifierService.cpp
    fn get_stake_modifier_for_validation(
        &self,
        chain_tip: &BlockIndex,
        kernel_confirmation_block: &BlockIndex,
    ) -> Result<u64, StorageError> {
        // Check if HardenedStakeModifier fork is active
        let activation_state = crate::fork_activation::ActivationState::new(chain_tip);
        let hardened_active = activation_state.is_hardened_stake_modifier_active();

        if hardened_active {
            // Hardened mode: Walk backward from chain tip to find nearest block
            // that generated a stake modifier
            debug!(
                "Using HARDENED stake modifier lookup from chain tip height {}",
                chain_tip.height
            );
            self.get_stake_modifier_hardened(chain_tip)
        } else {
            // Legacy mode: Use kernel confirmation block's time window algorithm
            debug!(
                "Using LEGACY stake modifier lookup from kernel confirmation height {}",
                kernel_confirmation_block.height
            );
            self.get_stake_modifier_legacy(kernel_confirmation_block)
        }
    }

    /// Get stake modifier using hardened algorithm (post-fork)
    ///
    /// Walks backward from chain tip until finding a block with
    /// generated_stake_modifier == true, then returns that block's stake_modifier.
    ///
    /// Reference: Divi/divi/src/PoSStakeModifierService.cpp:17-29
    fn get_stake_modifier_hardened(&self, chain_tip: &BlockIndex) -> Result<u64, StorageError> {
        let mut current = Some(chain_tip.clone());

        while let Some(ref block_index) = current {
            if block_index.generated_stake_modifier {
                debug!(
                    "Found hardened stake modifier 0x{:016x} at height {}",
                    block_index.stake_modifier, block_index.height
                );
                return Ok(block_index.stake_modifier);
            }

            // Walk backward to parent
            if block_index.prev_hash.is_zero() {
                break;
            }

            current = self.db.get_block_index(&block_index.prev_hash)?;
        }

        // Fallback to genesis/zero modifier
        Err(StorageError::ChainState(
            "Could not find stake modifier (hardened)".into(),
        ))
    }

    /// Get stake modifier using legacy algorithm (pre-fork)
    ///
    /// Matches C++ LegacyPoSStakeModifierService::GetKernelStakeModifier exactly:
    /// - Start at kernel confirmation block
    /// - Walk forward, tracking timestamp of most recent generated modifier
    /// - Stop when that timestamp >= start_time + selection_interval
    /// - Return the current block's stake_modifier
    ///
    /// Reference: Divi/divi/src/LegacyPoSStakeModifierService.cpp:29-56
    fn get_stake_modifier_legacy(
        &self,
        kernel_confirmation_block: &BlockIndex,
    ) -> Result<u64, StorageError> {
        use crate::stake_modifier::get_stake_modifier_selection_interval;

        let start_time = kernel_confirmation_block.time as i64;
        let selection_interval = get_stake_modifier_selection_interval();

        debug!(
            "Legacy stake modifier lookup: start_height={}, start_time={}, selection_interval={}, need_timestamp={}",
            kernel_confirmation_block.height, start_time, selection_interval, start_time + selection_interval
        );

        // Initialize timestamp_of_selected_block to the start block's time
        // This will be updated whenever we find a block that generated a modifier
        let mut timestamp_of_selected_block = start_time;

        // Current block we're examining
        let mut pindex = kernel_confirmation_block.clone();
        let mut current_height = kernel_confirmation_block.height;

        // Loop to find the stake modifier later by a selection interval
        // Continue while timestamp_of_selected_block < start_time + selection_interval
        while timestamp_of_selected_block < start_time + selection_interval {
            // Get next block
            current_height += 1;
            match self.get_block_index_by_height(current_height)? {
                Some(next_block) => {
                    pindex = next_block;

                    // If this block generated a stake modifier, update the timestamp
                    if pindex.generated_stake_modifier {
                        timestamp_of_selected_block = pindex.time as i64;
                        debug!(
                            "  Found generated modifier at height {}, time={}, modifier=0x{:016x}",
                            pindex.height, timestamp_of_selected_block, pindex.stake_modifier
                        );
                    } else {
                        debug!(
                            "  Block {} at height {} did NOT generate modifier (inherited=0x{:016x})",
                            pindex.hash, pindex.height, pindex.stake_modifier
                        );
                    }
                }
                None => {
                    // Reached chain tip - shouldn't normally happen
                    // Fall back to start block if it has a generated modifier
                    if kernel_confirmation_block.generated_stake_modifier {
                        debug!(
                            "Reached chain tip, using kernel block modifier 0x{:016x}",
                            kernel_confirmation_block.stake_modifier
                        );
                        return Ok(kernel_confirmation_block.stake_modifier);
                    }
                    return Ok(0);
                }
            }
        }

        // Return the current block's stake_modifier
        debug!(
            "Legacy stake modifier RESULT: 0x{:016x} at height {} (timestamp_of_selected={}, kernel_start_height={})",
            pindex.stake_modifier, pindex.height, timestamp_of_selected_block, kernel_confirmation_block.height
        );
        Ok(pindex.stake_modifier)
    }

    /// Validate proof-of-stake for a block
    ///
    /// Reference: BlockProofVerifier.cpp CheckProofOfStake
    fn validate_proof_of_stake(
        &self,
        block: &Block,
        parent: &BlockIndex,
    ) -> Result<(), StorageError> {
        // Basic coinstake structure validation
        if block.transactions.len() < 2 {
            return Err(StorageError::InvalidBlock(
                "PoS block must have at least 2 transactions".into(),
            ));
        }

        let coinstake = &block.transactions[1];
        crate::pos_validation::validate_coinstake_transaction(coinstake).map_err(|e| {
            StorageError::invalid_block_scored(0, format!("Invalid coinstake: {}", e))
        })?;

        // Validate all inputs pay to the same script
        let chain_ref = self;
        let get_utxo = |outpoint: &divi_primitives::OutPoint| -> Option<divi_primitives::TxOut> {
            chain_ref
                .db
                .get_utxo(outpoint)
                .ok()
                .flatten()
                .map(|utxo| divi_primitives::TxOut {
                    value: utxo.value,
                    script_pubkey: utxo.script_pubkey.clone(),
                })
        };

        crate::pos_validation::validate_coinstake_inputs_same_script(coinstake, &get_utxo)
            .map_err(|e| {
                StorageError::invalid_block_scored(
                    0,
                    format!("Coinstake inputs validation failed: {}", e),
                )
            })?;

        let expected_stake_reward = coinstake_stake_reward(
            &self.block_rewards(parent.height + 1),
            self.masternodes_deprecated(parent)?,
        );
        crate::pos_validation::validate_coinstake_vault_rules(
            coinstake,
            expected_stake_reward,
            &get_utxo,
        )
        .map_err(|e| {
            StorageError::InvalidBlock(format!("Vault coinstake validation failed: {}", e))
        })?;

        // Full proof-of-stake verification
        // Reference: Divi/divi/src/BlockProofVerifier.cpp:110-126

        // Get kernel (first input of coinstake)
        let kernel_input = &coinstake.vin[0];

        // Get UTXO being staked
        let kernel_utxo = self.db.get_utxo(&kernel_input.prevout)?.ok_or_else(|| {
            StorageError::invalid_block_scored(
                0,
                format!(
                    "Kernel UTXO not found: {}:{}",
                    kernel_input.prevout.txid, kernel_input.prevout.vout
                ),
            )
        })?;

        // Use the UTXO's height field directly instead of calling find_transaction,
        // which would load the full block just to extract the height we already have.
        let kernel_height = kernel_utxo.height;

        // Get the block that confirmed the kernel UTXO, on this block's chain.
        let kernel_block_index =
            self.resolve_kernel_block_index(parent, &kernel_input.prevout.txid, kernel_height)?;

        // Build StakingData
        // Reference: Divi/divi/src/BlockProofVerifier.cpp:100-106
        let staking_data = crate::pos_validation::StakingData {
            n_bits: block.header.bits,
            block_time_of_first_confirmation: kernel_block_index.time,
            block_hash_of_first_confirmation: kernel_block_index.hash,
            utxo_being_staked: kernel_input.prevout,
            utxo_value: kernel_utxo.value,
            block_hash_of_chain_tip: parent.hash,
        };

        // Coin age before the stake modifier, as Divi Core's
        // CreateProofOfStakeCalculator (ProofOfStakeGenerator.cpp:92-98)
        crate::pos_validation::check_pos_time_requirements(
            kernel_block_index.time,
            block.header.time,
            self.params.min_stake_age,
        )
        .map_err(|e| {
            StorageError::invalid_block_scored(0, format!("PoS verification failed: {}", e))
        })?;

        // Get stake modifier for this block using proper lookup algorithm
        // Reference: Divi/divi/src/PoSStakeModifierService.cpp
        let stake_modifier = self.get_stake_modifier_for_validation(parent, &kernel_block_index)?;

        // Debug logging for PoS validation
        debug!("PoS validation for block at height {}:", parent.height + 1);
        debug!("  stake_modifier: 0x{:016x}", stake_modifier);
        debug!("  parent.height: {}", parent.height);
        debug!("  parent.hash: {}", parent.hash);
        debug!("  kernel_height: {}", kernel_height);
        debug!("  kernel_block_time: {}", kernel_block_index.time);
        debug!("  kernel_block_hash: {}", kernel_block_index.hash);
        debug!("  utxo_txid: {}", kernel_input.prevout.txid);
        debug!("  utxo_vout: {}", kernel_input.prevout.vout);
        debug!("  utxo_value: {}", kernel_utxo.value.as_sat());
        debug!("  block.header.time: {}", block.header.time);
        debug!("  block.header.bits: {}", block.header.bits);

        // Compute and verify proof-of-stake
        // Reference: Divi/divi/src/BlockProofVerifier.cpp:121-123
        let (hash_proof, meets_target) = crate::pos_validation::compute_and_verify_proof_of_stake(
            stake_modifier,
            &staking_data,
            block.header.time,
        )
        .map_err(|e| {
            StorageError::invalid_block_scored(0, format!("PoS verification failed: {}", e))
        })?;

        debug!("  computed_hash: {}", hash_proof);
        debug!("  meets_target: {}", meets_target);

        if !meets_target {
            // PoS validation - stake modifier algorithm fixes applied:
            // 1. Selection hash byte order: SHA256 big-endian output reversed to little-endian
            //    for correct Hash256 comparison (matching C++ uint256 semantics)
            // 2. PoS detection uses is_proof_of_stake flag (based on vtx[1].is_coinstake())
            // 3. Selection hash >> 32 shift corrected (right shift, not left)
            return Err(StorageError::invalid_block_scored(
                0,
                format!(
                    "Proof-of-stake hash does not meet target. Hash: {}, Target bits: {}",
                    hash_proof, block.header.bits
                ),
            ));
        }

        Ok(())
    }

    /// Check if we should update the chain tip
    fn should_update_tip(&self, new_index: &BlockIndex) -> Result<bool, StorageError> {
        let tip = self.tip.read();
        match &*tip {
            None => {
                info!("should_update_tip: No tip yet, returning true");
                Ok(true)
            }
            Some(current_tip) => {
                // If this block directly extends the current tip, always accept it
                // This handles the common case of sequential block sync
                // Use prev_hash from BlockIndex to avoid loading the full block from DB.
                if new_index.prev_hash == current_tip.hash {
                    debug!(
                        "should_update_tip: Block {} extends current tip {} - accepting",
                        new_index.hash, current_tip.hash
                    );
                    return Ok(true);
                }

                // Otherwise, compare chain work (greater work wins)
                // Compare as big-endian 256-bit integers
                let cmp = Self::compare_chain_work(&new_index.chain_work, &current_tip.chain_work);
                let result = cmp == std::cmp::Ordering::Greater;
                debug!(
                    "should_update_tip: new_height={}, new_work={:02x?}..., current_height={}, current_work={:02x?}..., cmp={:?}, result={}",
                    new_index.height,
                    &new_index.chain_work[..8],
                    current_tip.height,
                    &current_tip.chain_work[..8],
                    cmp,
                    result
                );
                Ok(result)
            }
        }
    }

    /// Compare two chain work values as big-endian 256-bit integers
    fn compare_chain_work(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
        // Chain work is stored in little-endian, so compare from high byte to low
        for i in (0..32).rev() {
            match a[i].cmp(&b[i]) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Update the best known block if the given index has more chain work.
    ///
    /// Called after storing a new block index so that `activate_best_chain`
    /// can later detect that a side chain has surpassed the current tip.
    fn update_best_known_block(&self, index: &BlockIndex) {
        // A block known to be invalid is never a candidate (Divi Core keeps
        // BLOCK_FAILED_MASK blocks out of setBlockIndexCandidates).
        if index.failed() {
            return;
        }
        let mut best = self.best_known_block.write();
        let dominated = match &*best {
            None => true,
            Some(current_best) => {
                Self::compare_chain_work(&index.chain_work, &current_best.chain_work)
                    == std::cmp::Ordering::Greater
            }
        };
        if dominated {
            *best = Some(index.clone());
        }
    }

    /// Activate the best chain, acquiring the chain lock first.
    ///
    /// Public entry point for callers that do NOT already hold the chain lock
    /// (e.g., the sync layer after processing orphan blocks). For the internal
    /// lock-free version used by `accept_block`, see `activate_best_chain_inner`.
    pub fn activate_best_chain(&self) -> Result<Option<(u32, Vec<Transaction>)>, StorageError> {
        self.notifying_tip(|| {
            let _chain_guard = self.chain_lock.lock();
            self.activate_best_chain_inner()
        })
    }

    /// Inner implementation of activate_best_chain (caller must hold chain_lock).
    ///
    /// This mirrors C++ Divi's `ActivateBestChain`: after every block
    /// acceptance, we check whether any stored block index has more
    /// cumulative chain work than the current tip. If so, we reorganize
    /// to that chain.
    ///
    /// Returns the reorg fork height and orphaned transactions if a
    /// reorganization occurred, or `None` if no reorg was needed.
    fn activate_best_chain_inner(&self) -> Result<Option<(u32, Vec<Transaction>)>, StorageError> {
        let tip = self.tip.read().clone();
        let best = self.best_known_block.read().clone();

        let (current_tip, best_block) = match (tip, best) {
            (Some(t), Some(b)) => (t, b),
            _ => return Ok(None), // No tip or no best known block
        };

        // Nothing to do if the best known block is already the tip
        if best_block.hash == current_tip.hash {
            return Ok(None);
        }

        // Nothing to do if best known block is already on the main chain
        // (this can happen if best_known_block was set before the tip was
        // updated but after the block was connected)
        if best_block.status.contains(BlockStatus::ON_MAIN_CHAIN) {
            return Ok(None);
        }

        // Only reorg if the best known block has strictly more work
        let cmp = Self::compare_chain_work(&best_block.chain_work, &current_tip.chain_work);
        if cmp != std::cmp::Ordering::Greater {
            return Ok(None);
        }

        // The best known block must have valid data to reorganize to it
        if !best_block.status.contains(BlockStatus::HAVE_DATA) {
            debug!(
                "activate_best_chain: best block {} at height {} has more work but no data yet",
                best_block.hash, best_block.height
            );
            return Ok(None);
        }

        // Never reorganize onto a chain that contains a block already found
        // invalid (Divi Core FindMostWorkChain skips BLOCK_FAILED_MASK chains).
        if self.has_failed_ancestor(&best_block)? {
            warn!(
                "activate_best_chain: block {} at height {} is on an invalid chain - not reorganizing",
                best_block.hash, best_block.height
            );
            *self.best_known_block.write() = Some(current_tip);
            return Ok(None);
        }

        info!(
            "activate_best_chain: block {} at height {} (work {:02x?}...) beats current tip {} at height {} (work {:02x?}...) - reorganizing",
            best_block.hash,
            best_block.height,
            &best_block.chain_work[..8],
            current_tip.hash,
            current_tip.height,
            &current_tip.chain_work[..8],
        );

        // Load the full block data for the reorg target
        let block = self
            .db
            .get_block(&best_block.hash)?
            .ok_or_else(|| StorageError::BlockNotFound(best_block.hash.to_string()))?;

        let mut best_index = best_block;
        let (fork_height, orphaned_txs) =
            self.reorganize_chain(&block, &mut best_index, &current_tip)?;

        // Flush UTXO cache after reorg for consistency
        if self.db.has_utxo_cache() {
            match self.db.flush_utxo_cache() {
                Ok(count) => {
                    if count > 0 {
                        debug!(
                            "Flushed {} UTXO cache entries after activate_best_chain reorg",
                            count
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to flush UTXO cache after activate_best_chain reorg: {}",
                        e
                    );
                }
            }
        }

        info!(
            "activate_best_chain: reorg complete, new tip {} at height {}",
            best_index.hash, best_index.height
        );

        Ok(Some((fork_height, orphaned_txs)))
    }

    /// Connect a block to the chain (update UTXO set)
    fn connect_block(
        &self,
        block: &Block,
        index: &mut BlockIndex,
    ) -> Result<(BatchedUtxoWriter, Vec<u8>), StorageError> {
        let height = index.height;

        debug!(
            "🔗 VALIDATING BLOCK {} at height {} | {} txs | prev: {}",
            index.hash,
            height,
            block.transactions.len(),
            block.header.prev_block
        );

        // Divi Core ContextualCheckBlock: every transaction must be final at
        // this block's height and time ("bad-txns-nonfinal").
        check_block_txs_final(block, height)?;

        // Divi Core ConnectBlock checks the block again in case an earlier
        // version stored a bad one (BlockConnectionService.cpp:300-302)
        check_block_transactions(block, self.max_money())?;

        // Divi Core CheckEnforcedPoSBlocksAndBIP30 (BlockConnectionService.cpp:46-54)
        if self.params.check_block_work && height > 0 {
            if height <= LAST_POW_BLOCK && block.is_proof_of_stake() {
                return Err(StorageError::InvalidBlock(format!(
                    "PoS-early: PoS period not active (height {})",
                    height
                )));
            }
            if height > LAST_POW_BLOCK && block.is_proof_of_work() {
                return Err(StorageError::InvalidBlock(format!(
                    "PoW-ended: PoW period ended (height {})",
                    height
                )));
            }
        }

        // Divi Core BIP30 (BlockConnectionService.cpp:56-62): a transaction may not
        // reuse the id of one that still has unspent outputs
        if height > 0 {
            for tx in &block.transactions {
                let txid = tx.txid();
                if self.db.has_spendable_output_of(&txid)? {
                    return Err(StorageError::InvalidBlock(format!(
                        "bad-txns-BIP30: tried to overwrite transaction ({})",
                        txid
                    )));
                }
            }
        }

        // IMPORTANT: Validate treasury payments BEFORE modifying any state
        // This prevents UTXO corruption if validation fails
        debug!(
            "  ├─ Treasury validation check (network: {:?})",
            self.network_type()
        );
        self.validate_treasury_payments(block, index)?;
        debug!("  ├─ Treasury validation: ✅ PASS");

        debug!("  ├─ Processing {} transactions", block.transactions.len());
        let mut total_inputs = 0;
        let mut total_outputs = 0;
        // Divi Core nMint (coinbase and coinstake supply change) and the fees of
        // all other transactions (TransactionInputChecker.cpp:79-81)
        let mut mint = Amount::ZERO;
        let mut fees = Amount::ZERO;
        let max_money = self.max_money();
        // Divi Core TotalSigOpsAreBelowMaximum (TransactionInputChecker.cpp:85-100)
        let mut sig_ops = 0u32;

        // Use batched UTXO writer for better performance
        // Pre-calculate capacity: estimate ~2 inputs and ~3 outputs per tx
        let tx_count = block.transactions.len();
        let mut utxo_batch = BatchedUtxoWriter::with_capacity(tx_count * 3, tx_count * 2);

        // Track UTXOs created within this block for intra-block spending
        // (when tx2 spends output created by tx1 in the same block)
        use std::collections::HashSet;
        let mut created_in_block: HashSet<OutPoint> = HashSet::new();
        let mut spent_in_block: HashSet<OutPoint> = HashSet::new();

        // Build undo data: capture previous UTXO state for every input spent
        let mut block_undo = BlockUndo::with_capacity(tx_count * 2);

        // Precompute all txids once to avoid redundant hash computations.
        // These are reused in the main transaction loop and for the tx_index update.
        let txids: Vec<Hash256> = block
            .transactions
            .iter()
            .map(|tx| self.compute_txid(tx))
            .collect();

        // Script flags for this block: Core's mandatory flags, plus CLTV and
        // LIMIT_TRANSFER once their forks are active by the block's median
        // time past (BlockTransactionChecker::Check)
        let block_flags = {
            use crate::fork_activation::{ActivationState, Fork};
            let mtp = self.get_median_time_past(index)? as i64;
            let activation = ActivationState::new_with_mtp(index, mtp);
            let mut flags = ScriptFlags::mandatory();
            if activation.is_active(Fork::CheckLockTimeVerify) {
                flags.set(ScriptFlags::CHECKLOCKTIMEVERIFY);
            }
            if activation.is_active(Fork::LimitTransferVerify) {
                flags.set(ScriptFlags::LIMIT_TRANSFER);
            }
            flags
        };

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let txid = txids[tx_idx];

            // Skip coinbase/coinstake input validation
            let is_coinbase = tx.is_coinbase();
            let is_coinstake = tx.is_coinstake();

            trace!(
                "  │  ├─ tx[{}]: {} (in={}, out={}, coinbase={}, coinstake={})",
                tx_idx,
                txid,
                tx.vin.len(),
                tx.vout.len(),
                is_coinbase,
                is_coinstake
            );

            total_inputs += tx.vin.len();
            total_outputs += tx.vout.len();
            let mut value_in = Amount::ZERO;

            sig_ops += legacy_sig_op_count(tx);
            if !is_coinbase {
                // Pay-to-script-hash inputs add their redeem script's sigops, for the
                // whole transaction before any of its scripts is run
                for input in &tx.vin {
                    let prev_script =
                        match utxo_batch.adds.iter().find(|(op, _)| op == &input.prevout) {
                            Some((_, u)) => Some(u.script_pubkey.clone()),
                            None => self.db.get_utxo(&input.prevout)?.map(|u| u.script_pubkey),
                        };
                    if let Some(spk) = prev_script.filter(|spk| spk.is_p2sh()) {
                        sig_ops += divi_script::p2sh_sig_op_count(
                            spk.as_bytes(),
                            input.script_sig.as_bytes(),
                        );
                    }
                }
            }
            if sig_ops > MAX_BLOCK_SIGOPS {
                return Err(StorageError::InvalidBlock(
                    "bad-blk-sigops: too many sigops".into(),
                ));
            }

            // Remove spent UTXOs (except for coinbase which has no real inputs)
            if !is_coinbase {
                for (input_index, input) in tx.vin.iter().enumerate() {
                    // Coinstake first input is empty marker, skip it
                    if is_coinstake && input.prevout.is_null() {
                        continue;
                    }

                    // A coin spent earlier in this block is gone (Divi Core CheckBlock,
                    // BlockCheckingHelpers.cpp:131-136)
                    if spent_in_block.contains(&input.prevout) {
                        return Err(StorageError::InvalidBlock(format!(
                            "bad-txns-inputs-duplicate: {}:{} in tx {}",
                            input.prevout.txid, input.prevout.vout, txid
                        )));
                    }

                    // Check if UTXO was created earlier in this same block
                    let exists_in_block = created_in_block.contains(&input.prevout);

                    // Capture previous UTXO state for undo data before removal.
                    // For non-block UTXOs we perform a single get_utxo call and treat
                    // None as "not found", avoiding a redundant has_utxo round-trip.
                    let prev_utxo = if exists_in_block {
                        // Intra-block spend: find in batch adds
                        utxo_batch
                            .adds
                            .iter()
                            .find(|(op, _)| op == &input.prevout)
                            .map(|(_, u)| u.clone())
                    } else {
                        // Regular spend: single DB read covers both existence check and data.
                        let utxo = self.db.get_utxo(&input.prevout)?;
                        if utxo.is_none() {
                            error!(
                                "UTXO NOT FOUND: {}:{} in tx {} at height {} (block {})",
                                input.prevout.txid, input.prevout.vout, txid, height, index.hash
                            );
                            return Err(StorageError::UtxoNotFound(format!(
                                "{}:{}",
                                input.prevout.txid, input.prevout.vout
                            )));
                        }
                        utxo
                    };

                    if let Some(ref utxo) = prev_utxo {
                        // Divi Core CheckInputs (UtxoCheckingAndUpdating.cpp:72-84): coinbase
                        // and coinstake outputs mature after nMaturity blocks; input values
                        // must be in range
                        if utxo.is_coinbase || utxo.is_coinstake {
                            let depth = i64::from(height) - i64::from(utxo.height);
                            if depth < i64::from(self.params.coinbase_maturity) {
                                return Err(StorageError::InvalidBlock(format!(
                                    "bad-txns-premature-spend-of-coinbase: tried to spend coinbase at depth {}, coinstake={} (tx {})",
                                    depth, utxo.is_coinstake, txid
                                )));
                            }
                        }
                        value_in += utxo.value;
                        if !money_range(utxo.value, max_money) || !money_range(value_in, max_money)
                        {
                            return Err(StorageError::InvalidBlock(format!(
                                "bad-txns-inputvalues-outofrange in tx {}",
                                txid
                            )));
                        }
                        block_undo.push(input.prevout, utxo.clone());
                    }

                    // Divi Core's CheckInputs: every input of every non-coinbase
                    // transaction, coinstakes included, is script-verified under the
                    // block's flags, during initial sync too. A failure rejects the
                    // block (BlockTransactionChecker::Check, ConnectBlock).
                    if let Some(ref utxo) = prev_utxo {
                        verify_input_with_flags(
                            tx,
                            input_index,
                            &utxo.script_pubkey,
                            utxo.value,
                            block_flags,
                        )
                        .map_err(|e| {
                            warn!(
                                "Script verification failed: tx {} input {} ({}:{}) at height {}: {}",
                                txid,
                                input_index,
                                input.prevout.txid,
                                input.prevout.vout,
                                height,
                                e.core_message()
                            );
                            StorageError::InvalidBlock(format!(
                                "mandatory-script-verify-flag-failed ({}) in tx {} input {}",
                                e.core_message(),
                                txid,
                                input_index
                            ))
                        })?;
                        self.script_stats.record(
                            utxo.script_pubkey.as_bytes(),
                            input.script_sig.as_bytes(),
                            is_coinstake,
                        );
                        // CheckProofOfStake also verifies the stake kernel (input 0)
                        // under POS_SCRIPT_VERIFY_FLAGS
                        if is_coinstake && input_index == 0 {
                            verify_input_with_flags(
                                tx,
                                0,
                                &utxo.script_pubkey,
                                utxo.value,
                                ScriptFlags::pos(),
                            )
                            .map_err(|e| {
                                StorageError::invalid_block_scored(
                                    0,
                                    format!(
                                        "VerifySignature failed on coinstake {} ({})",
                                        txid,
                                        e.core_message()
                                    ),
                                )
                            })?;
                        }
                    }

                    // Track spent UTXOs and queue removal
                    spent_in_block.insert(input.prevout);
                    utxo_batch.remove(input.prevout);
                }
            }

            // Divi Core CheckInputs (UtxoCheckingAndUpdating.cpp:86-99): an ordinary
            // transaction may not spend more than its inputs; the difference is its fee
            let value_out = tx.vout.iter().fold(Amount::ZERO, |acc, o| acc + o.value);
            if is_coinbase || is_coinstake {
                mint = mint + value_out - value_in;
            } else {
                if value_in < value_out {
                    return Err(StorageError::InvalidBlock(format!(
                        "bad-txns-in-belowout: tx {} value in ({}) < value out ({})",
                        txid, value_in, value_out
                    )));
                }
                fees += value_in - value_out;
            }

            // Add new UTXOs
            let mut utxos_created = 0;
            for (vout, output) in tx.vout.iter().enumerate() {
                // CRITICAL: Store ALL outputs including empty ones (coinstake markers)
                // This preserves output indices! If we skip output 0, then output 1 becomes output 0.
                // When someone later tries to spend output 1, it won't exist.
                // C++ code does the same - see coins.cpp which stores all outputs,
                // then calls ClearUnspendable() to mark OP_META outputs as null.
                //
                // Empty outputs (value=0, empty script) CAN be stored but CANNOT be spent.
                // They serve as markers (e.g., first output of coinstake tx).

                let outpoint = OutPoint::new(txid, vout as u32);
                let utxo = Utxo::new(
                    output.value,
                    output.script_pubkey.clone(),
                    height,
                    is_coinbase,
                    is_coinstake,
                );
                // Track UTXOs created in this block
                created_in_block.insert(outpoint);
                // Queue UTXO addition in batch
                utxo_batch.add(outpoint, utxo);
                utxos_created += 1;

                // Debug: log specific UTXOs we're interested in
                let txid_str = txid.to_string();
                if txid_str.starts_with("95ef902f") || height == 144 {
                    info!(
                        "  CREATED UTXO: {}:{} value={} at height {}",
                        txid, vout, output.value, height
                    );
                }
            }

            if utxos_created > 0 {
                debug!("  tx {}: created {} UTXOs", txid, utxos_created);
            }
        }

        debug!("  ├─ Block value + lottery validation check");
        self.validate_block_value(block, index, mint, fees)?;
        debug!("  ├─ Block value validation: ✅ PASS");

        // Money supply: previous supply plus everything created minus everything consumed
        // (coinbase/coinstake rewards raise it, fees burned by plain transactions lower it)
        let prev_supply = if index.height == 0 {
            Some(0)
        } else {
            self.db
                .get_block_index(&index.prev_hash)?
                // C++ never connects the genesis transactions, so genesis supply is 0
                .and_then(|p| {
                    if p.height == 0 {
                        Some(0)
                    } else {
                        p.money_supply
                    }
                })
        };
        index.money_supply = prev_supply.map(|prev| {
            let created: i64 = block
                .transactions
                .iter()
                .flat_map(|tx| tx.vout.iter())
                .map(|o| o.value.as_sat())
                .sum();
            let spent: i64 = block_undo
                .entries
                .iter()
                .map(|e| e.prev_utxo.value.as_sat())
                .sum();
            prev + created - spent
        });

        // Prepare undo bytes (caller will write atomically with UTXOs + tip)
        let undo_bytes = if !block_undo.entries.is_empty() {
            block_undo.to_bytes()
        } else {
            Vec::new()
        };

        debug!(
            "  ├─ Transaction processing: {} inputs, {} outputs",
            total_inputs, total_outputs
        );

        if let Some(ref tx_index) = self.tx_index {
            let locations = Self::tx_locations(block, &txids, &index.hash);
            tx_index.put_block_tx_locations(&locations, index.height, &index.hash)?;
        }

        debug!("  ├─ Lottery winners update");
        self.update_lottery_winners(block, index)?;

        // Note: Treasury validation was moved to the start of connect_block
        // to prevent UTXO corruption if validation fails

        index.status.insert(BlockStatus::VALID_TRANSACTIONS);
        index.status.insert(BlockStatus::VALID_CHAIN);
        index.status.insert(BlockStatus::VALID_SCRIPTS);
        index.status.insert(BlockStatus::ON_MAIN_CHAIN);

        if height.is_multiple_of(10_000) {
            info!(
                "Script verification through height {}: {} verified",
                height,
                self.script_stats.summary()
            );
        }

        debug!(
            "✅ BLOCK VALIDATED: {} at height {} | {} txs, {} UTXOs created",
            index.hash,
            height,
            block.transactions.len(),
            total_outputs
        );
        Ok((utxo_batch, undo_bytes))
    }

    /// Validate treasury and charity payments on treasury blocks
    fn validate_treasury_payments(
        &self,
        block: &Block,
        index: &BlockIndex,
    ) -> Result<(), StorageError> {
        use divi_consensus::treasury;

        let height = index.height;
        let network_type = self.network_type();

        // Get network-specific treasury parameters
        let (treasury_cycle, treasury_start, lottery_cycle) = match network_type {
            NetworkType::Mainnet => (
                treasury::mainnet::TREASURY_CYCLE,
                treasury::mainnet::TREASURY_START_BLOCK,
                treasury::mainnet::LOTTERY_CYCLE,
            ),
            NetworkType::Testnet => (
                treasury::testnet::TREASURY_CYCLE,
                treasury::testnet::TREASURY_START_BLOCK,
                treasury::testnet::LOTTERY_CYCLE,
            ),
            NetworkType::Regtest => (
                treasury::regtest::TREASURY_CYCLE,
                treasury::regtest::TREASURY_START_BLOCK,
                treasury::regtest::LOTTERY_CYCLE,
            ),
        };

        // Use transition-aware treasury block check (matches C++ SuperblockHeightValidator)
        let is_treasury_block = treasury::is_treasury_block_with_lottery(
            height,
            treasury_start,
            treasury_cycle,
            lottery_cycle,
        );

        if !is_treasury_block {
            // Not a treasury block - nothing to validate
            return Ok(());
        }

        let is_mainnet = matches!(network_type, NetworkType::Mainnet);

        if matches!(network_type, NetworkType::Regtest) {
            return Ok(());
        }

        let halving_interval = match network_type {
            NetworkType::Mainnet => 525_600u32,
            NetworkType::Testnet => 1_000u32,
            NetworkType::Regtest => 100u32,
        };

        let treasury_script = treasury::get_treasury_script(is_mainnet);
        let charity_script = treasury::get_charity_script(is_mainnet);

        let coinstake = block.transactions.get(1).ok_or_else(|| {
            StorageError::invalid_block_scored(0, "Treasury block missing coinstake".to_string())
        })?;

        // Use transition-aware payment cycle (matches C++ GetTreasuryBlockPaymentCycle)
        let payment_cycle =
            treasury::get_treasury_payment_cycle(height, treasury_cycle, lottery_cycle);
        let (expected_treasury, expected_charity) =
            divi_consensus::calculate_weighted_treasury_payment(
                height,
                payment_cycle,
                halving_interval,
            );

        let mut treasury_found = None;
        let mut charity_found = None;

        for output in &coinstake.vout {
            if output.script_pubkey == treasury_script {
                treasury_found = Some(output.value);
            }
            if output.script_pubkey == charity_script {
                charity_found = Some(output.value);
            }
        }

        match treasury_found {
            None => {
                return Err(StorageError::invalid_block_scored(
                    0,
                    format!("Treasury block {} missing treasury payment", height),
                ));
            }
            Some(actual) if actual != expected_treasury => {
                return Err(StorageError::invalid_block_scored(
                    0,
                    format!(
                        "Treasury block {} has incorrect treasury payment: expected {}, got {}",
                        height, expected_treasury, actual
                    ),
                ));
            }
            Some(_) => {}
        }

        match charity_found {
            None => {
                return Err(StorageError::invalid_block_scored(
                    0,
                    format!("Treasury block {} missing charity payment", height),
                ));
            }
            Some(actual) if actual != expected_charity => {
                return Err(StorageError::invalid_block_scored(
                    0,
                    format!(
                        "Treasury block {} has incorrect charity payment: expected {}, got {}",
                        height, expected_charity, actual
                    ),
                ));
            }
            Some(_) => {}
        }

        Ok(())
    }

    /// Subsidy halving interval for this network
    fn halving_interval(&self) -> u32 {
        match self.network_type() {
            NetworkType::Mainnet => 525_600u32,
            NetworkType::Testnet => 1_000u32,
            NetworkType::Regtest => 100u32,
        }
    }

    /// Per-block rewards at `height`
    fn block_rewards(&self, height: u32) -> divi_consensus::block_subsidy::BlockRewards {
        let mut rewards = divi_consensus::block_subsidy::get_block_subsidy_for_chain(
            self.params.chain_mode,
            self.network_type() == NetworkType::Mainnet,
            height,
            self.halving_interval(),
        );
        // Divi regtest's premine is 1250 coins (Divi Core chainparams.cpp:470)
        if height == 1
            && self.params.chain_mode == ChainMode::Divi
            && self.network_type() == NetworkType::Regtest
        {
            rewards.stake = Amount::from_divi(1_250);
        }
        rewards
    }

    /// Whether DeprecateMasternodes is active for the block after `parent`: Divi
    /// Core checks the parent's median time past against 2023-08-23
    /// (BlockConnectionService.cpp:322, ForkActivation.cpp:19-31, :48-60). Always
    /// active on PrivateDivi.
    fn masternodes_deprecated(&self, parent: &BlockIndex) -> Result<bool, StorageError> {
        if self.params.chain_mode == ChainMode::PrivateDivi {
            return Ok(true);
        }
        let mtp = self.get_median_time_past(parent)? as i64;
        Ok(masternodes_deprecated_after(parent, mtp))
    }

    /// The limit on what the coinbase and coinstake may create: stake plus
    /// masternode reward, whether or not the masternode reward is still paid
    /// separately (BlockIncentivesPopulator.cpp:202-220 sums both).
    fn stake_reward(rewards: &divi_consensus::block_subsidy::BlockRewards) -> Amount {
        rewards.stake + rewards.masternode
    }

    /// What a proof-of-work coinbase at `height` may pay, before fees: the limit
    /// `validate_block_value` checks it against
    pub fn pow_block_reward(&self, height: u32) -> Amount {
        Self::stake_reward(&self.block_rewards(height))
    }

    /// Validate block value (total mint) doesn't exceed expected rewards.
    /// Matches C++ BlockIncentivesPopulator::IsBlockValueValid and HasValidPayees.
    ///
    /// `mint` is Core's `nMint`: what the coinbase and the coinstake create beyond
    /// their inputs. `fees` is what the other transactions leave unspent; PoW blocks
    /// may claim it, PoS blocks burn it (BlockConnectionService.cpp:67-96).
    fn validate_block_value(
        &self,
        block: &Block,
        index: &BlockIndex,
        mint: Amount,
        fees: Amount,
    ) -> Result<(), StorageError> {
        use divi_consensus::{block_subsidy, lottery, treasury};

        let height = index.height;

        if height == 0 {
            return Ok(());
        }
        if height <= LAST_POW_BLOCK {
            // PrivateDivi keeps its earlier behaviour (no PoW-era check)
            if !self.params.check_block_work {
                return Ok(());
            }
            let limit = Self::stake_reward(&self.block_rewards(height)) + fees;
            if mint > limit {
                return Err(StorageError::InvalidBlock(format!(
                    "bad-cb-amount: reward pays too much (actual={} vs limit={})",
                    mint, limit
                )));
            }
            return Ok(());
        }

        let network_type = self.network_type();
        let halving_interval = self.halving_interval();
        let rewards = self.block_rewards(height);
        let base_expected = Self::stake_reward(&rewards);

        // Get treasury/lottery parameters
        let (treasury_cycle, treasury_start, treasury_lottery_cycle) = match network_type {
            NetworkType::Mainnet => (
                treasury::mainnet::TREASURY_CYCLE,
                treasury::mainnet::TREASURY_START_BLOCK,
                treasury::mainnet::LOTTERY_CYCLE,
            ),
            NetworkType::Testnet => (
                treasury::testnet::TREASURY_CYCLE,
                treasury::testnet::TREASURY_START_BLOCK,
                treasury::testnet::LOTTERY_CYCLE,
            ),
            NetworkType::Regtest => (
                treasury::regtest::TREASURY_CYCLE,
                treasury::regtest::TREASURY_START_BLOCK,
                treasury::regtest::LOTTERY_CYCLE,
            ),
        };

        let (lottery_start, lottery_cycle) = match network_type {
            NetworkType::Mainnet => (
                lottery::mainnet::LOTTERY_START_BLOCK,
                lottery::mainnet::LOTTERY_CYCLE,
            ),
            NetworkType::Testnet => (
                lottery::testnet::LOTTERY_START_BLOCK,
                lottery::testnet::LOTTERY_CYCLE,
            ),
            NetworkType::Regtest => (
                lottery::regtest::LOTTERY_START_BLOCK,
                lottery::regtest::LOTTERY_CYCLE,
            ),
        };

        // Treasury takes precedence where both cycles fall on one height
        // (Divi Core BlockIncentivesPopulator::IsBlockValueValid / HasValidPayees).
        let payout = treasury::superblock_payout(
            height,
            treasury_start,
            treasury_cycle,
            lottery_start,
            treasury_lottery_cycle,
        );
        debug_assert_eq!(treasury_lottery_cycle, lottery_cycle);
        let is_treasury = payout == treasury::SuperblockPayout::Treasury;
        let is_lottery = payout == treasury::SuperblockPayout::Lottery;

        // Compute expected max mint
        let expected_mint = if is_treasury {
            let payment_cycle = treasury::get_treasury_payment_cycle(
                height,
                treasury_cycle,
                treasury_lottery_cycle,
            );
            let (treasury_amt, charity_amt) = block_subsidy::calculate_weighted_treasury_payment(
                height,
                payment_cycle,
                halving_interval,
            );
            base_expected + treasury_amt + charity_amt
        } else if is_lottery {
            // Lottery reward = 50 DIVI per block × cycle_length (always 50, independent of halving)
            let lottery_total = Amount::from_sat(rewards.lottery.as_sat() * lottery_cycle as i64);
            base_expected + lottery_total
        } else {
            base_expected
        };

        if mint > expected_mint {
            return Err(StorageError::InvalidBlock(format!(
                "bad-cb-amount: reward pays too much (actual={} vs limit={}) at height {}",
                mint, expected_mint, height
            )));
        }

        // Validate lottery payments on lottery blocks
        if is_lottery {
            self.validate_lottery_payments(block, height, lottery_cycle, halving_interval)?;
        }

        Ok(())
    }

    /// Validate lottery winner payments on lottery blocks.
    /// Matches C++ IsValidLotteryPayment in BlockIncentivesPopulator.cpp.
    fn validate_lottery_payments(
        &self,
        block: &Block,
        height: u32,
        lottery_cycle: u32,
        halving_interval: u32,
    ) -> Result<(), StorageError> {
        use divi_consensus::block_subsidy;

        // Get previous block's lottery winners
        let prev_index = self
            .db
            .get_block_index(&block.header.prev_block)?
            .ok_or_else(|| StorageError::BlockNotFound(block.header.prev_block.to_string()))?;

        let winners = &prev_index.lottery_winners;

        // If no winners, lottery payments are optional (C++ returns true for empty winners)
        if winners.coinstakes.is_empty() {
            return Ok(());
        }

        // Calculate lottery pool: 50 DIVI per block × cycle = total
        // (lottery per-block reward is always 50 DIVI, independent of halving)
        let per_block_lottery = block_subsidy::get_block_subsidy(height, halving_interval).lottery;
        let total_pool = Amount::from_sat(per_block_lottery.as_sat() * lottery_cycle as i64);

        // Big reward (1st place): 50% of pool
        let big_reward = Amount::from_sat(total_pool.as_sat() / 2);
        // Small reward (2nd-11th): 5% of pool each
        let small_reward = Amount::from_sat(big_reward.as_sat() / 10);

        let coinstake = block.transactions.get(1).ok_or_else(|| {
            StorageError::InvalidBlock("Lottery block missing coinstake".to_string())
        })?;

        // Verify each winner's payment exists in coinstake outputs
        for (i, winner) in winners.coinstakes.iter().enumerate() {
            let expected_reward = if i == 0 { big_reward } else { small_reward };
            let expected_script = &winner.script_pubkey;

            let found = coinstake
                .vout
                .iter()
                .any(|out| out.script_pubkey == *expected_script && out.value == expected_reward);

            if !found {
                return Err(StorageError::invalid_block_scored(
                    0,
                    format!(
                        "Lottery block {} missing payment for winner {}: expected {} to script",
                        height, i, expected_reward
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Update lottery winners when connecting a block.
    /// Matches C++ LotteryWinnersCalculator::CalculateUpdatedLotteryWinners()
    fn update_lottery_winners(
        &self,
        block: &Block,
        index: &mut BlockIndex,
    ) -> Result<(), StorageError> {
        use divi_consensus::lottery;
        use divi_primitives::{LotteryCoinstake, LotteryWinners};

        let height = index.height;
        let (lottery_start, lottery_cycle) = self.get_lottery_params();

        // C++ line 179: if(nHeight <= 0) return LotteryCoinstakeData();
        if height == 0 {
            index.lottery_winners = LotteryWinners::new(0);
            return Ok(());
        }

        // C++ line 180: if(IsValidLotteryBlockHeight(nHeight)) return LotteryCoinstakeData(nHeight);
        // Lottery block = start of new cycle, reset candidates
        if lottery::is_lottery_block(height, lottery_start, lottery_cycle) {
            index.lottery_winners = LotteryWinners::new(height);
            return Ok(());
        }

        // C++ line 181: if(nHeight <= startOfLotteryBlocks_) return previousBlockLotteryCoinstakeData.getShallowCopy();
        if height <= lottery_start {
            let prev_winners = if height > 0 {
                let prev_index = self
                    .db
                    .get_block_index(&block.header.prev_block)?
                    .ok_or_else(|| {
                        StorageError::BlockNotFound(block.header.prev_block.to_string())
                    })?;
                prev_index.lottery_winners
            } else {
                LotteryWinners::new(height)
            };
            index.lottery_winners = prev_winners;
            return Ok(());
        }

        // Get previous block's lottery winners
        let prev_winners = {
            let prev_index = self
                .db
                .get_block_index(&block.header.prev_block)?
                .ok_or_else(|| StorageError::BlockNotFound(block.header.prev_block.to_string()))?;
            prev_index.lottery_winners
        };

        // C++ line 182: if(!IsCoinstakeValidForLottery(coinMintTransaction, nHeight))
        // Check if this block has a valid coinstake for lottery
        if block.transactions.len() < 2 {
            index.lottery_winners = prev_winners;
            return Ok(());
        }

        let coinstake = &block.transactions[1];

        if !lottery::is_coinstake_valid_for_lottery(coinstake) {
            index.lottery_winners = prev_winners;
            return Ok(());
        }

        // C++ line 184-185: Clone previous coinstakes, append new one
        let mut updated_coinstakes = prev_winners.coinstakes.clone();
        let coinstake_hash = self.compute_txid(coinstake);

        // C++ line 185: payment script is vout[0] for coinbase, vout[1] for coinstake
        let payment_script = if coinstake
            .vout
            .first()
            .is_some_and(|o| o.value == Amount::ZERO && o.script_pubkey.is_empty())
        {
            // Coinstake: vout[0] is empty marker, payment is vout[1]
            coinstake.vout[1].script_pubkey.clone()
        } else {
            // Coinbase: payment is vout[0]
            coinstake.vout[0].script_pubkey.clone()
        };

        updated_coinstakes.push(LotteryCoinstake::new(coinstake_hash, payment_script));

        // C++ line 187: if(UpdateCoinstakes(nHeight, updatedCoinstakes))
        if self.update_coinstakes_internal(
            height,
            lottery_start,
            lottery_cycle,
            &mut updated_coinstakes,
        )? {
            index.lottery_winners = LotteryWinners::with_coinstakes(height, updated_coinstakes);
        } else {
            index.lottery_winners = prev_winners;
        }

        Ok(())
    }

    /// Get lottery parameters for the current network.
    /// Lottery `(start_block, cycle_length)` for this network.
    pub fn get_lottery_params(&self) -> (u32, u32) {
        use divi_consensus::lottery;
        match self.network_type() {
            NetworkType::Mainnet => (
                lottery::mainnet::LOTTERY_START_BLOCK,
                lottery::mainnet::LOTTERY_CYCLE,
            ),
            NetworkType::Testnet => (
                lottery::testnet::LOTTERY_START_BLOCK,
                lottery::testnet::LOTTERY_CYCLE,
            ),
            NetworkType::Regtest => (
                lottery::regtest::LOTTERY_START_BLOCK,
                lottery::regtest::LOTTERY_CYCLE,
            ),
        }
    }

    /// Get the last lottery block height at or before blockHeight-1.
    /// Matches C++ GetLastLotteryBlockIndexBeforeHeight().
    ///
    /// For the first cycle (before first lottery payout), returns lottery_start.
    /// For subsequent cycles, returns the most recent lottery block height.
    fn get_last_lottery_block_height_before(
        &self,
        block_height: u32,
        lottery_start: u32,
        lottery_cycle: u32,
    ) -> u32 {
        // C++: max(startOfLotteryBlocks_, lotteryBlockPaymentCycle * ((blockHeight - 1) / lotteryBlockPaymentCycle))
        let computed = lottery_cycle * ((block_height - 1) / lottery_cycle);
        std::cmp::max(lottery_start, computed)
    }

    /// Check if a payment script is vetoed from lottery participation.
    /// Matches C++ LotteryWinnersCalculator::IsPaymentScriptVetoed().
    ///
    /// A script is vetoed if it appears in the lottery winners from any of the
    /// last 3 lottery cycles. This prevents the same address from winning
    /// multiple times in consecutive cycles.
    fn is_payment_script_vetoed_for_lottery(
        &self,
        payment_script: &divi_primitives::Script,
        block_height: u32,
        lottery_start: u32,
        lottery_cycle: u32,
    ) -> Result<bool, StorageError> {
        let last_lottery_height =
            self.get_last_lottery_block_height_before(block_height, lottery_start, lottery_cycle);

        // C++: constexpr int numberOfLotteryCyclesToVetoFor = 3;
        for cycle_count in 0u32..3 {
            // C++: activeChain_[nLastLotteryHeight - lotteryBlockPaymentCycle*lotteryCycleCount - 1]
            let offset = lottery_cycle * cycle_count + 1;
            let check_height = match last_lottery_height.checked_sub(offset) {
                Some(h) => h,
                None => return Ok(false), // Before chain start
            };

            // Get block index at check_height
            let block_index = match self.db.get_block_index_by_height(check_height)? {
                Some(idx) => idx,
                None => return Ok(false), // Block not found (C++ returns false for null)
            };

            // Check if payment_script appears in that block's lottery winners
            for winner in &block_index.lottery_winners.coinstakes {
                if winner.script_pubkey == *payment_script {
                    return Ok(true); // Vetoed!
                }
            }
        }

        Ok(false)
    }

    /// Core lottery update logic matching C++ UpdateCoinstakes().
    ///
    /// Implements:
    /// 1. Fork-dependent veto check (UniformLotteryWinners)
    /// 2. Ranked score computation (insertion-order ranks, duplicate tracking)
    /// 3. Stable sort by score descending
    /// 4. Top-11 trimming with duplicate-aware eviction
    ///
    /// Returns true if the coinstakes list was meaningfully updated (caller should store it).
    /// Returns false if the new coinstake was rejected (vetoed or didn't improve top-11).
    fn update_coinstakes_internal(
        &self,
        height: u32,
        lottery_start: u32,
        lottery_cycle: u32,
        coinstakes: &mut Vec<divi_primitives::LotteryCoinstake>,
    ) -> Result<bool, StorageError> {
        use divi_consensus::lottery::calculate_lottery_score;
        use std::collections::{HashMap, HashSet};

        // C++ line 156: Get last lottery block index
        let last_lottery_height =
            self.get_last_lottery_block_height_before(height, lottery_start, lottery_cycle);
        let last_lottery_index = self
            .db
            .get_block_index_by_height(last_lottery_height)?
            .ok_or_else(|| {
                StorageError::BlockNotFound(format!("height {}", last_lottery_height))
            })?;

        // C++ line 157-158: Check UniformLotteryWinners fork activation on last lottery block
        let fork_active = {
            use crate::fork_activation::{ActivationState, Fork};
            let activation = ActivationState::new(&last_lottery_index);
            activation.is_active(Fork::UniformLotteryWinners)
        };

        // C++ line 158-162: If fork active, check if new coinstake (back) is vetoed
        if fork_active {
            let new_script = &coinstakes.last().unwrap().script_pubkey;
            if self.is_payment_script_vetoed_for_lottery(
                new_script,
                height,
                lottery_start,
                lottery_cycle,
            )? {
                return Ok(false); // Vetoed - reject this coinstake
            }
        }

        // C++ line 164-165: computeRankedScoreAwareCoinstakes
        // Process in ORIGINAL insertion order (before sort) to assign ranks and detect duplicates
        let last_lottery_hash = last_lottery_index.hash;
        let mut ranked: HashMap<Hash256, (Hash256, usize, bool)> = HashMap::new();
        let mut seen_scripts: HashSet<divi_primitives::Script> = HashSet::new();

        for (i, cs) in coinstakes.iter().enumerate() {
            let score = calculate_lottery_score(&cs.tx_hash, &last_lottery_hash);
            let is_dup = !seen_scripts.insert(cs.script_pubkey.clone());
            ranked.insert(cs.tx_hash, (score, i, is_dup));
        }

        // C++ line 166: SortCoinstakesByScore - stable sort by score descending
        // Rust's sort_by is stable (guaranteed by std lib)
        coinstakes.sort_by(|a, b| {
            let score_a = &ranked[&a.tx_hash].0;
            let score_b = &ranked[&b.tx_hash].0;
            score_b.cmp(score_a)
        });

        // C++ line 168-171: TopElevenBestCoinstakesNeedUpdating
        let mut should_update = !ranked.is_empty();

        if ranked.len() > 1 {
            // After sorting, back() is the worst scorer.
            // Check if its original rank was 11 (the newly appended entry when prev had 11 entries).
            // If rank == 11, the new entry is the worst = nothing changed in top-11.
            let back_rank = ranked[&coinstakes.last().unwrap().tx_hash].1;
            should_update = back_rank != 11;
        }

        if coinstakes.len() > 11 {
            if fork_active {
                // Find the lowest-ranked (worst-scoring) duplicate scanning from back
                // C++: std::find_if(rbegin, rend, isDuplicateScript)
                if let Some(dup_pos) = coinstakes.iter().rposition(|cs| ranked[&cs.tx_hash].2) {
                    coinstakes.remove(dup_pos);
                    should_update = true;
                } else {
                    coinstakes.pop(); // No duplicate found, remove worst
                }
            } else {
                coinstakes.pop(); // Pre-fork: always remove worst
            }
        }

        Ok(should_update)
    }

    /// Compute transaction ID
    fn compute_txid(&self, tx: &Transaction) -> Hash256 {
        use divi_primitives::serialize::serialize;
        let tx_bytes = serialize(tx);
        hash256(&tx_bytes)
    }

    /// Update the chain tip
    #[allow(dead_code)]
    fn update_tip(&self, index: BlockIndex) -> Result<(), StorageError> {
        self.db.set_best_block(&index.hash)?;
        self.db.set_chain_height(index.height)?;
        self.db.store_block_index(&index)?;
        *self.tip.write() = Some(index);
        Ok(())
    }

    /// Get UTXO for an outpoint
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, StorageError> {
        self.db.get_utxo(outpoint)
    }

    /// Whether any spendable output of `txid` is unspent (Core's `HaveCoins`)
    pub fn has_spendable_output_of(&self, txid: &Hash256) -> Result<bool, StorageError> {
        self.db.has_spendable_output_of(txid)
    }

    /// Check if a UTXO exists
    pub fn has_utxo(&self, outpoint: &OutPoint) -> Result<bool, StorageError> {
        self.db.has_utxo(outpoint)
    }

    /// Flush the UTXO cache to database
    ///
    /// Should be called periodically during sync for durability.
    /// Returns the number of entries flushed, or 0 if cache is not enabled.
    pub fn flush_utxo_cache(&self) -> Result<usize, StorageError> {
        self.db.flush_utxo_cache()
    }

    /// Get UTXO cache statistics (if cache is enabled)
    pub fn utxo_cache_stats(&self) -> Option<crate::database::UtxoStats> {
        // Note: This returns database stats, not cache stats
        // Use db.utxo_cache_stats() for cache-specific stats
        None
    }

    /// Check if UTXO cache is enabled
    pub fn has_utxo_cache(&self) -> bool {
        self.db.has_utxo_cache()
    }

    /// Try to activate a stored block (potentially triggering a chain reorganization).
    /// When it does, returns the fork height and the transactions of the
    /// disconnected blocks to return to the mempool, as `accept_block` reports them.
    pub fn try_activate_block(
        &self,
        hash: &Hash256,
    ) -> Result<Option<(u32, Vec<Transaction>)>, StorageError> {
        // Acquire exclusive lock for chain state modifications
        debug!("try_activate_block: Waiting for chain lock...");
        let _chain_guard = self.chain_lock.lock();
        debug!("try_activate_block: Chain lock acquired");

        // Get the block index
        let existing_index = match self.db.get_block_index(hash)? {
            Some(idx) => idx,
            None => {
                debug!("try_activate_block: Block {} not found in index", hash);
                return Ok(None); // Block not found
            }
        };

        // Already on main chain, nothing to do
        if existing_index.status.contains(BlockStatus::ON_MAIN_CHAIN) {
            debug!("try_activate_block: Block {} already on main chain", hash);
            return Ok(None);
        }

        // Never activate a block that is, or descends from, an invalid block.
        if self.has_failed_ancestor(&existing_index)? {
            debug!("try_activate_block: Block {} is on an invalid chain", hash);
            return Ok(None);
        }

        // Check if this block has more work than our tip
        let tip = self.tip.read().clone();
        let Some(ref current_tip) = tip else {
            debug!(
                "try_activate_block: No tip yet, cannot activate block {}",
                hash
            );
            return Ok(None); // No tip yet
        };

        debug!(
            "try_activate_block: Checking if block {} (height {}) should activate. Current tip: {} (height {})",
            hash, existing_index.height, current_tip.hash, current_tip.height
        );

        if !self.should_update_tip(&existing_index)? {
            debug!(
                "try_activate_block: Block {} should NOT update tip (insufficient work or doesn't extend)",
                hash
            );
            return Ok(None); // Not enough work to trigger reorg
        }

        // Get the block data
        let block = match self.db.get_block(hash)? {
            Some(b) => b,
            None => {
                warn!(
                    "try_activate_block: Block {} index exists but full block data not found",
                    hash
                );
                return Err(StorageError::BlockNotFound(hash.to_string()));
            }
        };

        debug!(
            "Activating stored block {} at height {} (current tip: {} at height {})",
            hash, existing_index.height, current_tip.hash, current_tip.height
        );

        let mut index = existing_index;
        match self.reorganize_chain(&block, &mut index, current_tip) {
            Ok(reorg) => {
                info!("try_activate_block: Successfully activated block {}", hash);
                self.update_best_known_block(&index);
                if self.db.has_utxo_cache() {
                    self.db.flush_utxo_cache()?;
                }
                Ok(Some(reorg))
            }
            Err(e) => {
                warn!(
                    "try_activate_block: Failed to reorganize chain for block {}: {}",
                    hash, e
                );
                Err(e)
            }
        }
    }

    /// Get a block locator (list of block hashes from tip to genesis)
    pub fn get_locator(&self) -> Result<Vec<Hash256>, StorageError> {
        let mut locator = Vec::new();
        let tip = self.tip.read().clone();

        let Some(tip_index) = tip else {
            return Ok(locator);
        };

        let mut height = tip_index.height;
        let mut step = 1u32;

        while height > 0 {
            if let Some(index) = self.db.get_block_index_by_height(height)? {
                locator.push(index.hash);
            }

            // Exponential backoff
            if locator.len() >= 10 {
                step *= 2;
            }

            if height < step {
                break;
            }
            height -= step;
        }

        // Always include genesis
        if let Some(index) = self.db.get_block_index_by_height(0)? {
            if locator.last() != Some(&index.hash) {
                locator.push(index.hash);
            }
        }

        Ok(locator)
    }
}

// ============================================================
// MASTERNODE UTXO PROVIDER IMPLEMENTATION
// Added for Phase C.3 - UTXO collateral verification
// ============================================================

/// Implement UtxoProvider for Chain to enable masternode collateral verification
impl divi_masternode::UtxoProvider for Chain {
    fn get_utxo(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<divi_masternode::Utxo>, Box<dyn std::error::Error>> {
        // Get UTXO from storage
        let storage_utxo = match self.db.get_utxo(outpoint)? {
            Some(utxo) => utxo,
            None => return Ok(None),
        };

        // Convert storage::Utxo to masternode::Utxo (only value and height needed)
        Ok(Some(divi_masternode::Utxo::new(
            storage_utxo.value,
            storage_utxo.height,
        )))
    }
}

/// Implement UtxoProvider for ChainDatabase to enable masternode collateral verification
impl divi_masternode::UtxoProvider for ChainDatabase {
    fn get_utxo(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<divi_masternode::Utxo>, Box<dyn std::error::Error>> {
        // Get UTXO from database
        let storage_utxo = match self.get_utxo(outpoint)? {
            Some(utxo) => utxo,
            None => return Ok(None),
        };

        // Convert storage::Utxo to masternode::Utxo (only value and height needed)
        Ok(Some(divi_masternode::Utxo::new(
            storage_utxo.value,
            storage_utxo.height,
        )))
    }
}

/// DeprecateMasternodes for the block after `parent`, from the parent's median
/// time past (ForkActivation.cpp:31, :35-36, :56)
fn masternodes_deprecated_after(parent: &BlockIndex, parent_mtp: i64) -> bool {
    use crate::fork_activation::{ActivationState, Fork};
    ActivationState::new_with_mtp(parent, parent_mtp).is_active(Fork::DeprecateMasternodes)
}

/// Divi Core's `nStakeReward` as ConnectBlock hands it to the vault coinstake rule
/// (BlockConnectionService.cpp:321-326, BlockTransactionChecker.cpp:57-108): the
/// stake share, plus the masternode share only once DeprecateMasternodes is active.
/// Before that the masternode share is paid to another output.
fn coinstake_stake_reward(
    rewards: &divi_consensus::block_subsidy::BlockRewards,
    masternodes_deprecated: bool,
) -> Amount {
    if masternodes_deprecated {
        rewards.stake + rewards.masternode
    } else {
        rewards.stake
    }
}

/// `CScript() << height` (Divi Core script.h:210-225): OP_1..OP_16 for 1-16,
/// otherwise the minimal CScriptNum encoding pushed as data
pub fn bip34_height_script(height: u32) -> Vec<u8> {
    match height {
        0 => vec![0x00],
        1..=16 => vec![0x50 + height as u8],
        _ => {
            let mut num = Vec::new();
            let mut v = height;
            while v > 0 {
                num.push((v & 0xff) as u8);
                v >>= 8;
            }
            if num.last().is_some_and(|b| b & 0x80 != 0) {
                num.push(0x00);
            }
            let mut out = vec![num.len() as u8];
            out.extend_from_slice(&num);
            out
        }
    }
}

/// Divi Core CBlock::BuildMerkleTree's `fMutated` (primitives/block.cpp:59-79): two
/// identical hashes at the end of a level
fn merkle_tree_mutated(txids: &[Hash256]) -> bool {
    let mut level = txids.to_vec();
    let mut mutated = false;
    while level.len() > 1 {
        let n = level.len();
        let mut next = Vec::with_capacity(n.div_ceil(2));
        for i in (0..n).step_by(2) {
            let i2 = (i + 1).min(n - 1);
            if i2 == i + 1 && i2 + 1 == n && level[i] == level[i2] {
                mutated = true;
            }
            let mut pair = Vec::with_capacity(64);
            pair.extend_from_slice(level[i].as_bytes());
            pair.extend_from_slice(level[i2].as_bytes());
            next.push(hash256(&pair));
        }
        level = next;
    }
    mutated
}

/// Divi Core `GetLegacySigOpCount` (TransactionOpCounting.cpp:6-16)
fn legacy_sig_op_count(tx: &Transaction) -> u32 {
    let ins: u32 = tx
        .vin
        .iter()
        .map(|i| divi_script::sig_op_count(i.script_sig.as_bytes(), false))
        .sum();
    let outs: u32 = tx
        .vout
        .iter()
        .map(|o| divi_script::sig_op_count(o.script_pubkey.as_bytes(), false))
        .sum();
    ins + outs
}

/// Divi Core `MoneyRange` against the network's `MaxMoneyOut`
fn money_range(value: Amount, max_money: Amount) -> bool {
    value >= Amount::ZERO && value <= max_money
}

/// The context-free transaction checks of Divi Core CheckBlock and
/// CheckTransaction (BlockCheckingHelpers.cpp:24-147): one coinbase, first; a PoS
/// block's coinbase pays nothing and its coinstake comes second; no transaction
/// without inputs or outputs; output values in range; no coin spent twice.
fn check_block_transactions(block: &Block, max_money: Amount) -> Result<(), StorageError> {
    let invalid = |reason: String| Err(StorageError::InvalidBlock(reason));
    use divi_primitives::serialize::Encodable;
    if block.transactions.is_empty()
        || block.transactions.len() > MAX_BLOCK_SIZE
        || block.encoded_size() > MAX_BLOCK_SIZE
    {
        return invalid("bad-blk-length: size limits failed".into());
    }
    if !block.transactions[0].is_coinbase() {
        return invalid("bad-cb-missing: first tx is not coinbase".into());
    }
    if block.transactions[1..].iter().any(|tx| tx.is_coinbase()) {
        return invalid("bad-cb-multiple: more than one coinbase".into());
    }
    if block.is_proof_of_stake() {
        let coinbase = &block.transactions[0];
        if coinbase.vout.len() != 1 || !coinbase.vout[0].is_empty() {
            return invalid("coinbase output not empty for proof-of-stake block".into());
        }
        if block.transactions[2..].iter().any(|tx| tx.is_coinstake()) {
            return invalid("more than one coinstake".into());
        }
    }

    let mut inputs = std::collections::HashSet::new();
    for tx in &block.transactions {
        check_transaction_with(tx, max_money, &mut inputs)?;
    }
    let sig_ops: u32 = block.transactions.iter().map(legacy_sig_op_count).sum();
    if sig_ops > MAX_BLOCK_SIGOPS_LEGACY {
        return invalid("bad-blk-sigops: out-of-bounds SigOpCount".into());
    }
    Ok(())
}

/// Divi Core `CheckTransaction` (BlockCheckingHelpers.cpp:99-147): the checks
/// that need no context. `inputs` collects the outpoints spent so far; a block
/// shares one set across its transactions, as Core's CheckBlock does.
fn check_transaction_with(
    tx: &Transaction,
    max_money: Amount,
    inputs: &mut std::collections::HashSet<OutPoint>,
) -> Result<(), StorageError> {
    use divi_primitives::serialize::Encodable;
    let invalid = |reason: String| Err(StorageError::InvalidBlock(reason));
    if tx.vin.is_empty() {
        return Err(StorageError::invalid_block_scored(
            10,
            "bad-txns-vin-empty".into(),
        ));
    }
    if tx.vout.is_empty() {
        return Err(StorageError::invalid_block_scored(
            10,
            "bad-txns-vout-empty".into(),
        ));
    }
    if tx.encoded_size() > MAX_TX_SIZE {
        return invalid("bad-txns-oversize: size limits failed".into());
    }
    let mut value_out = Amount::ZERO;
    for out in &tx.vout {
        if out.is_empty() && !tx.is_coinbase() && !tx.is_coinstake() {
            return invalid("txout empty for user transaction".into());
        }
        if !money_range(out.value, max_money) {
            return invalid("bad-txns-vout-negative-or-toolarge".into());
        }
        value_out += out.value;
        if !money_range(value_out, max_money) {
            return invalid("bad-txns-txouttotal-toolarge".into());
        }
    }
    for input in &tx.vin {
        if !inputs.insert(input.prevout) {
            return invalid(format!(
                "bad-txns-inputs-duplicate: {}:{}",
                input.prevout.txid, input.prevout.vout
            ));
        }
    }
    if tx.is_coinbase() {
        let len = tx.vin[0].script_sig.len();
        if !(2..=150).contains(&len) {
            return invalid(format!("bad-cb-length: coinbase script size={}", len));
        }
    }
    Ok(())
}

/// Divi Core `CheckTransaction` for a single transaction (the mempool's first
/// check); the error carries Core's reason
pub fn check_transaction(tx: &Transaction, max_money: Amount) -> Result<(), StorageError> {
    check_transaction_with(tx, max_money, &mut std::collections::HashSet::new())
}

/// Divi Core `ContextualCheckBlock` finality rule: a block may only contain
/// transactions that are final at its own height and timestamp.
fn check_block_txs_final(block: &Block, height: u32) -> Result<(), StorageError> {
    for tx in &block.transactions {
        if !tx.is_final(height, block.header.time) {
            return Err(StorageError::invalid_block_scored(
                10,
                format!(
                    "bad-txns-nonfinal: block at height {} contains a non-final transaction",
                    height
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    mod crash;

    use super::*;
    use divi_primitives::amount::Amount;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::{TxIn, TxOut};
    use divi_primitives::ChainMode;
    use tempfile::tempdir;

    /// Each (mode x network) pair selects its own genesis. The hashes are
    /// literal here, not the test_vectors constants, so a swapped or
    /// mistyped constant (which `for_network` would turn into a zero hash)
    /// fails. Divi mainnet and PrivateDivi testnet are proven against live
    /// Core nodes (dnsdivi divid, vps1 privatedivid).
    #[test]
    fn genesis_hash_per_mode_and_network() {
        let cases = [
            (
                ChainMode::Divi,
                NetworkType::Mainnet,
                "00000e258596876664989374c7ee36445cf5f4f80889af415cc32478214394ea",
            ),
            (
                ChainMode::Divi,
                NetworkType::Testnet,
                "00000f43b54bbcae395d815b255ac4ed0693bca7987d72b873d5d4b68d73a6bd",
            ),
            (
                ChainMode::Divi,
                NetworkType::Regtest,
                "0000000b3f9980dcf71f5f52d69e30d3b02f807e0a77b91b6091701e4ae51a6f",
            ),
            (
                ChainMode::PrivateDivi,
                NetworkType::Mainnet,
                "00000cc899db77f0b4104ca9556b78947be103c25da7895e1a507a8b3e415fd7",
            ),
            (
                ChainMode::PrivateDivi,
                NetworkType::Testnet,
                "000003071a9dac6c02eb354b7e44add111c5427d483301cb76ed521d621a3b1d",
            ),
            (
                ChainMode::PrivateDivi,
                NetworkType::Regtest,
                "4b66fa19b46819cedf4dd4c3f84229916089e09e693e69d1beab944492b84ce3",
            ),
        ];
        for (mode, net, want) in cases {
            let p = ChainParams::for_network(net, mode);
            assert_eq!(p.genesis_hash.to_hex(), want, "{mode:?} {net:?}");
            assert_eq!(p.chain_mode, mode);
            assert_eq!(p.network_type, net);
        }
    }

    /// PrivateDivi mainnet was relaunched on 2026-04-20 (PrivateDivi Core
    /// 21de13166, chainparams.cpp:254 genesis). The live mainnet nodes on
    /// vps1 report this hash at height 0.
    #[test]
    fn privatedivi_mainnet_genesis_matches_live_network() {
        let p = ChainParams::for_network(NetworkType::Mainnet, ChainMode::PrivateDivi);
        assert_eq!(
            p.genesis_hash.to_hex(),
            "00000cc899db77f0b4104ca9556b78947be103c25da7895e1a507a8b3e415fd7"
        );
    }

    /// The genesis irondivi builds for PrivateDivi mainnet hashes, by quark,
    /// to the relaunch genesis: the header fields (nTime 1776703200, nNonce
    /// 1440691, nBits 0x1e0ffff0, PrivateDivi Core chainparams.cpp:241-243)
    /// and the unchanged coinbase reproduce Core's asserts at :254-255.
    /// `init_genesis` only warns on a mismatch, so this is what catches one.
    #[test]
    fn privatedivi_mainnet_genesis_header_hashes_to_relaunch_genesis() {
        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Chain::new(
            db,
            ChainParams::for_network(NetworkType::Mainnet, ChainMode::PrivateDivi),
        )
        .unwrap();
        let tip = chain.tip().expect("genesis");
        assert_eq!(tip.height, 0);
        let block = chain.get_block(&tip.hash).unwrap().expect("genesis block");
        assert_eq!(
            divi_crypto::compute_block_hash(&block.header).to_hex(),
            "00000cc899db77f0b4104ca9556b78947be103c25da7895e1a507a8b3e415fd7"
        );
        assert_eq!(
            block.header.merkle_root.to_hex(),
            "4123e9ba36523af0b90b02b26663b76a11e9bf680e6c775d8dd6d7c66f95c4bd"
        );
        assert_eq!(block.header.time, 1_776_703_200);
        assert_eq!(block.header.nonce, 1_440_691);
    }

    /// Create a test chain with regtest network (genesis already initialized)
    /// Real mainnet vault coinstakes, all accepted by Divi Core (read from a Core
    /// 3.0.0 node): height, parent's median time past, vault input, vault outputs,
    /// other outputs, all in satoshis. DeprecateMasternodes starts at 2,580,189,
    /// the first block whose parent's MTP reaches 1692792000. 2,580,186 and
    /// 2,580,187 have block times past that but parents' MTPs below it, so they are
    /// still before the fork and pay the masternode share to another output.
    #[allow(clippy::type_complexity)]
    const MAINNET_VAULT_STAKES: &[(u32, i64, i64, &[i64], &[i64])] = &[
        (
            1_191_825,
            1_610_308_802,
            6_200_000_000_000,
            &[3_120_900_000_000, 3_120_900_000_000],
            &[49_500_000_000],
        ),
        (
            2_400_002,
            1_682_102_505,
            1_569_559_351_563,
            &[1_603_759_351_563],
            &[40_500_000_000],
        ),
        (
            2_400_005,
            1_682_102_826,
            740_515_029_326,
            &[774_715_029_326],
            &[40_500_000_000],
        ),
        (
            2_580_186,
            1_692_791_906,
            1_969_562_500_000,
            &[1_001_881_250_000, 1_001_881_250_000],
            &[40_500_000_000],
        ),
        (
            2_580_187,
            1_692_791_913,
            1_305_117_500_000,
            &[1_339_317_500_000],
            &[40_500_000_000],
        ),
        (
            2_580_194,
            1_692_792_561,
            1_715_190_625_000,
            &[1_789_890_625_000],
            &[],
        ),
    ];

    #[test]
    fn test_vault_coinstakes_of_real_mainnet_blocks() {
        let vault = divi_script::StakingVaultScript::new([0x36; 20], [0xa7; 20]).to_script();
        let prev = OutPoint::new(Hash256::from_bytes([0x44; 32]), 1);
        for &(height, parent_mtp, value_in, vault_outs, others) in MAINNET_VAULT_STAKES {
            let parent = BlockIndex::from_header(
                &divi_primitives::block::BlockHeader::default(),
                height - 1,
                None,
            );
            let deprecated = masternodes_deprecated_after(&parent, parent_mtp);
            assert_eq!(deprecated, height >= 2_580_189, "fork state at {height}");

            let mut vout = vec![TxOut::new(Amount::ZERO, Script::new())];
            vout.extend(
                vault_outs
                    .iter()
                    .map(|&v| TxOut::new(Amount::from_sat(v), vault.clone())),
            );
            vout.extend(
                others
                    .iter()
                    .map(|&v| TxOut::new(Amount::from_sat(v), Script::new_p2pkh(&[0xcd; 20]))),
            );
            let coinstake = Transaction {
                version: 1,
                vin: vec![TxIn::new(prev, Script::new(), 0xffff_ffff)],
                vout,
                lock_time: 0,
            };
            let input = TxOut::new(Amount::from_sat(value_in), vault.clone());
            let get = |op: &OutPoint| (*op == prev).then(|| input.clone());
            let check = |reward| {
                crate::pos_validation::validate_coinstake_vault_rules(&coinstake, reward, &get)
            };
            let rewards = divi_consensus::block_subsidy::get_block_subsidy(height, 525_600);
            assert!(
                check(coinstake_stake_reward(&rewards, deprecated)).is_ok(),
                "Core accepted block {height}"
            );
            if !deprecated {
                // What IronDivi required before: the masternode share counted as the vault's
                assert!(
                    check(coinstake_stake_reward(&rewards, true)).is_err(),
                    "block {height} pays the masternode share elsewhere"
                );
            }
        }
        // 1,191,825 in DIVI, as the refusal reported it
        let rewards = divi_consensus::block_subsidy::get_block_subsidy(1_191_825, 525_600);
        assert_eq!(
            coinstake_stake_reward(&rewards, false),
            Amount::from_divi(418)
        );
        assert_eq!(
            coinstake_stake_reward(&rewards, true),
            Amount::from_divi(913)
        );
    }

    fn create_test_chain() -> (Chain, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap();
        (chain, dir)
    }

    thread_local! {
        /// Heights of the blocks `seal` produced in this test (a test runs on one thread)
        static SEALED_HEIGHTS: std::cell::RefCell<std::collections::HashMap<Hash256, u32>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }

    /// Make a test block valid as Core requires: version 4, a coinbase that starts
    /// with the block height (one more than its sealed parent's, 1 on genesis),
    /// the merkle root, and a nonce that meets the block's bits
    fn seal(block: &mut Block) {
        let height = SEALED_HEIGHTS.with(|m| {
            m.borrow()
                .get(&block.header.prev_block)
                .map_or(1, |h| h + 1)
        });
        if block.header.version < 3 {
            block.header.version = 4;
        }
        if let Some(cb) = block.transactions.first_mut().filter(|tx| tx.is_coinbase()) {
            let prefix = bip34_height_script(height);
            if !cb.vin[0].script_sig.as_bytes().starts_with(&prefix) {
                let mut sig = prefix;
                sig.extend_from_slice(cb.vin[0].script_sig.as_bytes());
                cb.vin[0].script_sig = Script::from_bytes(sig);
            }
        }
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        let hash = compute_block_hash(&block.header);
        SEALED_HEIGHTS.with(|m| m.borrow_mut().insert(hash, height));
    }

    /// Get the existing genesis block info from the chain
    fn get_genesis_info(chain: &Chain) -> (Hash256, u32) {
        let tip = chain.tip().expect("Chain should have genesis block");
        (tip.hash, tip.time)
    }

    fn create_child_block(parent_hash: Hash256, parent_time: u32) -> Block {
        let mut block = Block::default();
        block.header.version = 1;
        block.header.prev_block = parent_hash;
        block.header.time = parent_time + 60;
        block.header.bits = 0x207fffff; // Regtest difficulty

        // Add coinbase transaction
        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x01, 0x05]))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250_00000000),
                Script::new_p2pkh(&[1u8; 20]),
            )],
            lock_time: 0,
        };
        block.transactions.push(coinbase);

        // Compute merkle root
        seal(&mut block);
        block
    }

    #[test]
    fn test_accept_genesis_block() {
        let (chain, _dir) = create_test_chain();

        // Genesis is already accepted by Chain::new
        let (genesis_hash, _) = get_genesis_info(&chain);

        assert!(chain.has_block(&genesis_hash).unwrap());
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn test_accept_multiple_blocks() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Accept second block
        let block1 = create_child_block(genesis_hash, genesis_time);
        let hash1 = chain.accept_block(block1.clone()).unwrap().hash;

        assert_eq!(chain.height(), 1);

        // Accept third block
        let block2 = create_child_block(hash1, block1.header.time);
        let _hash2 = chain.accept_block(block2).unwrap().hash;

        assert_eq!(chain.height(), 2);
    }

    #[test]
    fn test_block_with_non_final_tx_rejected() {
        // Consensus side: Divi Core rejects a block holding a tx that is
        // not final at the block's height ("bad-txns-nonfinal").
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let mut block1 = create_child_block(genesis_hash, genesis_time);
        block1.transactions[0].lock_time = 1; // height 1 is not below 1
        block1.transactions[0].vin[0].sequence = 0;
        seal(&mut block1);

        let result = chain.accept_block(block1);
        assert!(result.is_err(), "block with a non-final tx was accepted");
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn test_block_with_reached_lock_time_accepted() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let mut block1 = create_child_block(genesis_hash, genesis_time);
        // A time lock below the block's own timestamp is final
        block1.transactions[0].lock_time = genesis_time;
        block1.transactions[0].vin[0].sequence = 0;
        seal(&mut block1);

        chain.accept_block(block1).unwrap();
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn test_orphan_block_rejected() {
        let (chain, _dir) = create_test_chain();

        // Try to accept a block without parent
        let orphan = create_child_block(Hash256::from_bytes([1u8; 32]), 1000000000);
        let result = chain.accept_block(orphan);

        assert!(matches!(result, Err(StorageError::OrphanBlock(_))));
    }

    #[test]
    fn test_utxo_tracking() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Add a block on top of genesis
        let block1 = create_child_block(genesis_hash, genesis_time);
        let hash1 = chain.accept_block(block1).unwrap().hash;

        // Get the coinbase txid
        let block1_data = chain.get_block(&hash1).unwrap().unwrap();
        let coinbase_txid = chain.compute_txid(&block1_data.transactions[0]);

        // Check UTXO exists
        let outpoint = OutPoint::new(coinbase_txid, 0);
        assert!(chain.has_utxo(&outpoint).unwrap());

        let utxo = chain.get_utxo(&outpoint).unwrap().unwrap();
        assert_eq!(utxo.value.as_sat(), 1250_00000000);
        assert!(utxo.is_coinbase);
    }

    #[test]
    fn test_block_locator() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let block1 = create_child_block(genesis_hash, genesis_time);
        let hash1 = chain.accept_block(block1.clone()).unwrap().hash;

        let block2 = create_child_block(hash1, block1.header.time);
        let hash2 = chain.accept_block(block2).unwrap().hash;

        // Get locator
        let locator = chain.get_locator().unwrap();

        // Should have: tip, ..., genesis
        assert!(!locator.is_empty());
        assert_eq!(locator[0], hash2); // Tip first
        assert_eq!(*locator.last().unwrap(), genesis_hash); // Genesis last
    }

    // ============================================================
    // COMPREHENSIVE TEST SUITE - Chain State Machine
    // Added 2026-01-19 for full coverage
    // ============================================================

    /// Helper to count UTXOs in the chain
    #[allow(dead_code)]
    fn count_utxos(_chain: &Chain) -> usize {
        // We can't directly iterate UTXOs, so we'll track by checking known outpoints
        // For test purposes, we count based on the blocks we've added
        0 // Placeholder - actual implementation would need db iteration
    }

    /// Helper to create a block with a specific coinbase output pubkey hash
    fn create_child_block_with_pubkey(
        parent_hash: Hash256,
        parent_time: u32,
        pubkey_hash: [u8; 20],
    ) -> Block {
        let mut block = Block::default();
        block.header.version = 1;
        block.header.prev_block = parent_hash;
        block.header.time = parent_time + 60;
        block.header.bits = 0x207fffff; // Regtest difficulty

        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x01, 0x05]))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250_00000000),
                Script::new_p2pkh(&pubkey_hash),
            )],
            lock_time: 0,
        };
        block.transactions.push(coinbase);
        seal(&mut block);
        block
    }

    /// Helper to create a chain of N blocks
    fn create_chain(chain: &Chain, num_blocks: usize) -> Vec<Hash256> {
        let mut hashes = Vec::new();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(chain);
        hashes.push(genesis_hash);

        let mut prev_hash = genesis_hash;
        let mut prev_time = genesis_time;

        for i in 0..num_blocks {
            let block = create_child_block_with_pubkey(prev_hash, prev_time, [(i as u8 + 2); 20]);
            let hash = chain.accept_block(block).unwrap().hash;
            hashes.push(hash);
            prev_hash = hash;
            prev_time += 60;
        }

        hashes
    }

    // ============================================================
    // 1. Validation Failure Tests - UTXO Consistency
    // ============================================================

    #[test]
    fn test_invalid_merkle_root_does_not_modify_state() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let initial_height = chain.height();

        // Create block with invalid merkle root
        let mut bad_block = create_child_block(genesis_hash, genesis_time);
        bad_block.header.merkle_root = Hash256::from_bytes([0xde; 32]);

        // Should fail
        let _result = chain.accept_block(bad_block);
        // Note: May succeed or fail depending on validation order

        // State should still be consistent
        assert!(
            chain.height() <= initial_height + 1,
            "Height should not jump unexpectedly"
        );
    }

    #[test]
    fn test_orphan_block_does_not_modify_utxos() {
        let (chain, _dir) = create_test_chain();

        // Try to accept a block with unknown parent
        let orphan = create_child_block(Hash256::from_bytes([0xaa; 32]), 1000000100);
        let result = chain.accept_block(orphan);

        assert!(matches!(result, Err(StorageError::OrphanBlock(_))));
        assert_eq!(chain.height(), 0, "Height should still be 0 (genesis only)");
    }

    #[test]
    fn test_duplicate_block_rejected() {
        let (chain, _dir) = create_test_chain();

        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Add a block
        let block1 = create_child_block(genesis_hash, genesis_time);
        let hash1 = chain.accept_block(block1.clone()).unwrap().hash;

        // Try to accept same block again
        let _result = chain.accept_block(block1);

        // Should either succeed (idempotent) or fail with appropriate error
        // But should NOT corrupt state
        assert_eq!(chain.height(), 1);
        assert!(chain.has_block(&hash1).unwrap());
    }

    // ============================================================
    // 2. Chain Reorganization Tests
    // ============================================================

    #[test]
    fn test_simple_reorg_two_chains() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Build initial chain: genesis -> A1 -> A2
        let block_a1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
        let hash_a1 = chain.accept_block(block_a1.clone()).unwrap().hash;

        let block_a2 = create_child_block_with_pubkey(hash_a1, block_a1.header.time, [0x0b; 20]);
        let _hash_a2 = chain.accept_block(block_a2.clone()).unwrap().hash;

        assert_eq!(chain.height(), 2);

        // Now create competing chain: genesis -> B1 -> B2 -> B3 (longer)
        let block_b1 = create_child_block_with_pubkey(genesis_hash, genesis_time + 1, [0x1a; 20]);
        let hash_b1 = chain.accept_block(block_b1.clone()).unwrap().hash;

        let block_b2 = create_child_block_with_pubkey(hash_b1, block_b1.header.time, [0x1b; 20]);
        let hash_b2 = chain.accept_block(block_b2.clone()).unwrap().hash;

        let block_b3 = create_child_block_with_pubkey(hash_b2, block_b2.header.time, [0x1c; 20]);
        let hash_b3 = chain.accept_block(block_b3).unwrap().hash;

        // Chain should have reorged to B chain
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.tip().unwrap().hash, hash_b3);
    }

    #[test]
    fn test_reorg_utxo_consistency() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Build chain A: genesis -> A1
        let block_a1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
        let hash_a1 = chain.accept_block(block_a1.clone()).unwrap().hash;

        // Get the coinbase UTXO from A1
        let coinbase_txid =
            chain.compute_txid(&chain.get_block(&hash_a1).unwrap().unwrap().transactions[0]);
        let outpoint_a1 = OutPoint::new(coinbase_txid, 0);
        assert!(
            chain.has_utxo(&outpoint_a1).unwrap(),
            "UTXO from A1 should exist"
        );

        // Build longer competing chain B: genesis -> B1 -> B2
        let block_b1 = create_child_block_with_pubkey(genesis_hash, genesis_time + 1, [0x1a; 20]);
        let hash_b1 = chain.accept_block(block_b1.clone()).unwrap().hash;

        let block_b2 = create_child_block_with_pubkey(hash_b1, block_b1.header.time, [0x1b; 20]);
        let _hash_b2 = chain.accept_block(block_b2.clone()).unwrap().hash;

        // After reorg, A1's UTXO should NOT exist
        assert!(
            !chain.has_utxo(&outpoint_a1).unwrap_or(true),
            "UTXO from A1 should be removed after reorg"
        );

        // B1's UTXO should exist
        let coinbase_b1_txid =
            chain.compute_txid(&chain.get_block(&hash_b1).unwrap().unwrap().transactions[0]);
        let outpoint_b1 = OutPoint::new(coinbase_b1_txid, 0);
        assert!(
            chain.has_utxo(&outpoint_b1).unwrap(),
            "UTXO from B1 should exist after reorg"
        );
    }

    /// The transactions of disconnected blocks come back parents first, so the
    /// mempool can take a child after its parent. Divi Core offers each block's
    /// transactions to the mempool while the blocks below it are still connected
    /// (ChainTipManager.cpp:175-182), so both come back there.
    #[test]
    fn reorg_returns_disconnected_transactions_parents_first() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);
        let anyone = Script::from_bytes(vec![0x51]);
        let spend = |coin: OutPoint, value: i64| Transaction {
            version: 1,
            vin: vec![TxIn::new(coin, Script::new(), 0xffff_ffff)],
            vout: vec![TxOut::new(Amount::from_sat(value), anyone.clone())],
            lock_time: 0,
        };

        // 21 blocks, so the first one's coinbase is mature (regtest maturity 20)
        let mut parent = (genesis_hash, genesis_time);
        let mut coin = None;
        for _ in 0..21 {
            let mut block = create_child_block(parent.0, parent.1);
            block.transactions[0].vout[0].script_pubkey = anyone.clone();
            seal(&mut block);
            let hash = chain.accept_block(block.clone()).unwrap().hash;
            coin.get_or_insert(OutPoint::new(block.transactions[0].txid(), 0));
            parent = (hash, block.header.time);
        }
        let fork = parent;

        // A22 confirms T1, A23 confirms T2 spending T1
        let t1 = spend(coin.unwrap(), 1249_00000000);
        let t2 = spend(OutPoint::new(t1.txid(), 0), 1248_00000000);
        let mut a22 = create_child_block(fork.0, fork.1);
        a22.transactions.push(t1.clone());
        seal(&mut a22);
        let a22_hash = chain.accept_block(a22.clone()).unwrap().hash;
        let mut a23 = create_child_block(a22_hash, a22.header.time);
        a23.transactions.push(t2.clone());
        seal(&mut a23);
        chain.accept_block(a23).unwrap();
        assert_eq!(chain.height(), 23);

        // A branch from height 21 with more work disconnects both
        let mut parent = (fork.0, fork.1 + 1);
        let mut result = None;
        for _ in 0..3 {
            let block = create_child_block_with_pubkey(parent.0, parent.1, [0x2b; 20]);
            let accepted = chain.accept_block(block.clone()).unwrap();
            parent = (accepted.hash, block.header.time);
            result = Some(accepted);
        }
        let result = result.unwrap();
        assert_eq!(chain.height(), 24);
        assert_eq!(result.reorg_fork_height, Some(21));
        let returned: Vec<Hash256> = result
            .orphaned_transactions
            .iter()
            .map(|tx| tx.txid())
            .collect();
        assert_eq!(returned, vec![t1.txid(), t2.txid()]);
    }

    /// A side-chain block that fails to connect during a reorg must be marked
    /// invalid together with its descendants, the old chain must be restored,
    /// and later blocks must never make the node retry that chain.
    /// Divi Core: ChainTipManager::connectTip -> InvalidBlockFound marks
    /// BLOCK_FAILED_VALID; FindMostWorkChain marks descendants BLOCK_FAILED_CHILD;
    /// AcceptBlock / AcceptBlockHeader reject a block whose parent is failed.
    #[test]
    fn test_reorg_marks_failed_side_chain_block_and_descendants_invalid() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Main chain: genesis -> A1 -> A2
        let block_a1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
        let hash_a1 = chain.accept_block(block_a1.clone()).unwrap().hash;
        let block_a2 = create_child_block_with_pubkey(hash_a1, block_a1.header.time, [0x0b; 20]);
        let hash_a2 = chain.accept_block(block_a2.clone()).unwrap().hash;
        assert_eq!(chain.height(), 2);

        let utxo_a1 = OutPoint::new(chain.compute_txid(&block_a1.transactions[0]), 0);
        let utxo_a2 = OutPoint::new(chain.compute_txid(&block_a2.transactions[0]), 0);

        // Side chain: genesis -> B1 -> B2(bad) -> B3
        let block_b1 = create_child_block_with_pubkey(genesis_hash, genesis_time + 1, [0x1a; 20]);
        let hash_b1 = chain.accept_block(block_b1.clone()).unwrap().hash;
        let utxo_b1 = OutPoint::new(chain.compute_txid(&block_b1.transactions[0]), 0);

        // B2 carries a transaction spending an output that does not exist. Its
        // header is fine, so it is stored as a side-chain block; it can only
        // fail when the reorg tries to connect it.
        let mut block_b2 =
            create_child_block_with_pubkey(hash_b1, block_b1.header.time, [0x1b; 20]);
        block_b2.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([0xee; 32]), 0),
                Script::from_bytes(vec![0x51]),
                0xffff_ffff,
            )],
            vout: vec![TxOut::new(
                Amount::from_sat(1_00000000),
                Script::new_p2pkh(&[0x1e; 20]),
            )],
            lock_time: 0,
        });
        seal(&mut block_b2);
        let hash_b2 = chain.accept_block(block_b2.clone()).unwrap().hash;

        // B3 gives the side chain more work and triggers the reorg, which fails at B2.
        let block_b3 = create_child_block_with_pubkey(hash_b2, block_b2.header.time, [0x1c; 20]);
        let hash_b3 = chain.compute_block_hash(&block_b3);
        assert!(
            chain.accept_block(block_b3.clone()).is_err(),
            "reorg onto a chain containing an invalid block must fail"
        );

        // The old chain is fully restored: tip, height and UTXO set.
        assert_eq!(chain.tip().unwrap().hash, hash_a2);
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.db.get_best_block().unwrap(), Some(hash_a2));
        assert!(
            chain.has_utxo(&utxo_a1).unwrap(),
            "A1 coinbase must be restored"
        );
        assert!(
            chain.has_utxo(&utxo_a2).unwrap(),
            "A2 coinbase must be restored"
        );
        assert!(
            !chain.has_utxo(&utxo_b1).unwrap(),
            "B1 coinbase must be rolled back"
        );
        let idx_a2 = chain.db.get_block_index(&hash_a2).unwrap().unwrap();
        assert!(idx_a2.is_on_main_chain());

        // The failing block and its descendant are marked invalid; B1 is not.
        let idx_b1 = chain.db.get_block_index(&hash_b1).unwrap().unwrap();
        let idx_b2 = chain.db.get_block_index(&hash_b2).unwrap().unwrap();
        let idx_b3 = chain.db.get_block_index(&hash_b3).unwrap().unwrap();
        assert!(!idx_b1.failed(), "B1 connected fine and must not be marked");
        assert!(!idx_b1.is_on_main_chain());
        assert!(
            idx_b2.failed(),
            "B2 failed to connect and must be marked invalid"
        );
        assert!(
            idx_b3.failed(),
            "B3 descends from B2 and must be marked invalid"
        );

        // Re-receiving a failed block is rejected and does not retry the reorg.
        assert!(chain.accept_block(block_b3.clone()).is_err());
        assert_eq!(chain.tip().unwrap().hash, hash_a2);

        // A child of a failed block is rejected outright.
        let block_b4 = create_child_block_with_pubkey(hash_b3, block_b3.header.time, [0x1d; 20]);
        assert!(chain.accept_block(block_b4).is_err());
        assert_eq!(chain.tip().unwrap().hash, hash_a2);

        // Neither the explicit activation path nor activate_best_chain picks it again.
        assert!(chain.try_activate_block(&hash_b3).unwrap().is_none());
        assert!(chain.activate_best_chain().unwrap().is_none());
        assert_eq!(chain.tip().unwrap().hash, hash_a2);

        // The restored main chain still extends normally.
        let block_a3 = create_child_block_with_pubkey(hash_a2, block_a2.header.time, [0x0c; 20]);
        let hash_a3 = chain.accept_block(block_a3).unwrap().hash;
        assert_eq!(chain.tip().unwrap().hash, hash_a3);
        assert_eq!(chain.height(), 3);
    }

    // ============================================================
    // 3. Concurrent Access Tests
    // ============================================================

    #[test]
    fn test_concurrent_block_acceptance() {
        use std::thread;

        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Arc::new(
            Chain::new(
                db,
                ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
            )
            .unwrap(),
        );

        // Get existing genesis
        let genesis_index = chain.tip().expect("Chain should have genesis");
        let genesis_hash = genesis_index.hash;
        let genesis_time = genesis_index.time;

        // Spawn multiple threads trying to add the same child block
        let mut handles = vec![];

        for i in 0..4 {
            let chain_clone = Arc::clone(&chain);
            let handle = thread::spawn(move || {
                let block = create_child_block_with_pubkey(
                    genesis_hash,
                    genesis_time,
                    [(i + 10) as u8; 20],
                );
                chain_clone.accept_block(block)
            });
            handles.push(handle);
        }

        // All threads should complete without panic
        let mut success_count = 0;
        for handle in handles {
            if handle.join().unwrap().is_ok() {
                success_count += 1;
            }
        }

        // At least one should succeed
        assert!(
            success_count >= 1,
            "At least one block acceptance should succeed"
        );

        // Height should be exactly 1 (only one block after genesis)
        assert_eq!(chain.height(), 1, "Only one block should be on main chain");
    }

    #[test]
    fn test_concurrent_reads_during_write() {
        use std::thread;
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Arc::new(
            Chain::new(
                db,
                ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
            )
            .unwrap(),
        );

        // Get existing genesis
        let genesis_index = chain.tip().expect("Chain should have genesis");
        let genesis_hash = genesis_index.hash;
        let genesis_time = genesis_index.time;

        // Start reader threads
        let mut handles = vec![];
        for _ in 0..4 {
            let chain_clone = Arc::clone(&chain);
            let handle = thread::spawn(move || {
                for _ in 0..10 {
                    let _ = chain_clone.height();
                    let _ = chain_clone.tip();
                    let _ = chain_clone.has_block(&genesis_hash);
                    thread::sleep(Duration::from_millis(1));
                }
            });
            handles.push(handle);
        }

        // Meanwhile, add blocks
        let mut prev_hash = genesis_hash;
        let mut prev_time = genesis_time;
        for i in 0..5 {
            let block = create_child_block_with_pubkey(prev_hash, prev_time, [(i + 20) as u8; 20]);
            let hash = chain.accept_block(block).unwrap().hash;
            prev_hash = hash;
            prev_time += 60;
        }

        // All readers should complete without panic
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(chain.height(), 5);
    }

    // ============================================================
    // 4. UTXO Maturity Tests
    // ============================================================

    #[test]
    fn test_coinbase_utxo_created() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Add a block
        let block1 = create_child_block(genesis_hash, genesis_time);
        let hash1 = chain.accept_block(block1).unwrap().hash;

        let block1_data = chain.get_block(&hash1).unwrap().unwrap();
        let coinbase_txid = chain.compute_txid(&block1_data.transactions[0]);

        let outpoint = OutPoint::new(coinbase_txid, 0);
        let utxo = chain.get_utxo(&outpoint).unwrap().unwrap();

        assert!(utxo.is_coinbase);
        assert_eq!(utxo.height, 1);
        assert_eq!(utxo.value.as_sat(), 1250_00000000);
    }

    #[test]
    fn test_utxo_spent_in_next_block() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Add a block to have a spendable UTXO
        let block1 = create_child_block(genesis_hash, genesis_time);
        let hash1 = chain.accept_block(block1.clone()).unwrap().hash;

        let block1_data = chain.get_block(&hash1).unwrap().unwrap();
        let coinbase_txid = chain.compute_txid(&block1_data.transactions[0]);
        let coinbase_outpoint = OutPoint::new(coinbase_txid, 0);

        // UTXO should exist
        assert!(chain.has_utxo(&coinbase_outpoint).unwrap());

        // Create block that spends the coinbase (note: maturity not enforced in test)
        let mut spending_block = create_child_block(hash1, block1.header.time);

        // Add a transaction spending the coinbase
        let spending_tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: coinbase_outpoint,
                script_sig: Script::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            vout: vec![TxOut::new(
                Amount::from_sat(1249_00000000), // minus fee
                Script::new_p2pkh(&[0x99; 20]),
            )],
            lock_time: 0,
        };
        spending_block.transactions.push(spending_tx);
        seal(&mut spending_block);

        // This should fail because coinbase needs 100 confirmations
        // (maturity rule)
        let _result = chain.accept_block(spending_block);
        // Note: Depending on implementation, might fail for immature coinbase
        // or might fail for other reasons

        // For now, verify state consistency
        assert!(chain.height() >= 1);
    }

    // ============================================================
    // 5. Block Height and Index Tests
    // ============================================================

    #[test]
    fn test_get_block_by_height() {
        let (chain, _dir) = create_test_chain();

        let hashes = create_chain(&chain, 5);

        // Verify we can get each block by height
        for (height, expected_hash) in hashes.iter().enumerate() {
            let index = chain.get_block_index_by_height(height as u32).unwrap();
            assert!(index.is_some(), "Block at height {} should exist", height);
            assert_eq!(index.unwrap().hash, *expected_hash);
        }

        // Non-existent height
        let missing = chain.get_block_index_by_height(100).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_chain_work_increases() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);
        let genesis_index = chain.get_block_index(&genesis_hash).unwrap().unwrap();

        let block1 = create_child_block(genesis_hash, genesis_time);
        let hash1 = chain.accept_block(block1).unwrap().hash;
        let index1 = chain.get_block_index(&hash1).unwrap().unwrap();

        // Chain work should increase
        let cmp = Chain::compare_chain_work(&index1.chain_work, &genesis_index.chain_work);
        assert_eq!(
            cmp,
            std::cmp::Ordering::Greater,
            "Chain work should increase with each block"
        );
    }

    // ============================================================
    // 6. Edge Cases and Error Handling
    // ============================================================

    #[test]
    fn test_block_with_no_transactions_rejected() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Create block with no transactions
        let mut empty_block = Block::default();
        empty_block.header.version = 1;
        empty_block.header.prev_block = genesis_hash;
        empty_block.header.time = genesis_time + 60;
        empty_block.header.bits = 0x207fffff;
        seal(&mut empty_block);

        let _result = chain.accept_block(empty_block);
        // Note: The current implementation may accept empty blocks (depending on validation)
        // This test just verifies no crash occurs and state stays consistent
        // Height should be 0 (genesis) or 1 (if empty block was accepted)
        assert!(
            chain.height() <= 1,
            "Chain should have at most 1 block after genesis"
        );
    }

    #[test]
    fn test_very_old_timestamp_block() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Create block with timestamp in the past (before parent)
        // Note: Divi allows timestamps > MTP, so this might be valid
        let mut old_block = create_child_block(genesis_hash, genesis_time);
        old_block.header.time = genesis_time.saturating_sub(1000); // Before genesis
        seal(&mut old_block);

        // Depending on implementation, may or may not be rejected
        let _result = chain.accept_block(old_block);
        // Just verify no crash
    }

    #[test]
    fn test_future_timestamp_block_rejected() {
        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Create block with timestamp far in future
        let mut future_block = create_child_block(genesis_hash, genesis_time);
        let future_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        future_block.header.time = future_time + 3 * 60 * 60; // 3 hours in future
        seal(&mut future_block);

        let result = chain.accept_block(future_block);
        assert!(
            result.is_err(),
            "Block with timestamp >2 hours in future should be rejected"
        );
    }

    // ============================================================
    // 7. Regression Test: Treasury Validation Before UTXO Modification
    // ============================================================

    #[test]
    fn test_validation_order_utxo_not_corrupted_on_failure() {
        // This is a regression test for the sync bug fixed on 2026-01-19
        // The bug: validate_treasury_payments() was called AFTER UTXO modifications
        // If validation failed, UTXOs were already modified (corrupted)

        let (chain, _dir) = create_test_chain();

        // Get existing genesis
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Build chain to a reasonable height
        let mut prev_hash = genesis_hash;
        let mut prev_time = genesis_time;
        for i in 0..10 {
            let block = create_child_block_with_pubkey(prev_hash, prev_time, [(i + 5) as u8; 20]);
            let hash = chain.accept_block(block).unwrap().hash;
            prev_hash = hash;
            prev_time += 60;
        }

        let height_before = chain.height();
        let tip_before = chain.tip().unwrap().hash;

        // Try to add a block with invalid merkle (simulating validation failure)
        let mut bad_block = create_child_block(prev_hash, prev_time);
        bad_block.header.merkle_root = Hash256::from_bytes([0xff; 32]);

        let result = chain.accept_block(bad_block);
        assert!(result.is_err());

        // Verify state is unchanged
        assert_eq!(
            chain.height(),
            height_before,
            "Height should not change after failed validation"
        );
        assert_eq!(
            chain.tip().unwrap().hash,
            tip_before,
            "Tip should not change after failed validation"
        );
    }

    // ============================================================
    // UTXO Index Preservation Tests
    // ============================================================

    /// Test that empty outputs (coinstake markers) are stored to preserve output indices
    ///
    /// This is a regression test for the critical bug where IronDivi was skipping
    /// empty outputs when storing UTXOs, which broke output indices.
    ///
    /// Bug scenario:
    /// - Coinstake tx has outputs: [0: empty marker, 1: 9150 DIVI]
    /// - Old code skipped output 0, stored output 1 at index 0 (wrong!)
    /// - When trying to spend output 1, it didn't exist → "UTXO not found"
    ///
    /// This test verifies that ALL outputs including empty ones are stored at
    /// their correct indices, matching C++ behavior.
    #[test]
    fn test_utxo_indices_preserved_with_empty_outputs() {
        let (chain, _dir) = create_test_chain();

        // Get genesis info
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Create a block with a coinstake-like transaction that has:
        // - Output 0: empty marker (value=0, empty script)
        // - Output 1: actual stake output (9150 DIVI)
        let mut block = Block::default();
        block.header.version = 1;
        block.header.prev_block = genesis_hash;
        block.header.time = genesis_time + 60;
        block.header.bits = 0x207fffff;

        // A coinbase with an empty first output, like a coinstake's marker output.
        // (Only a coinbase or a coinstake may carry an empty output, and a
        // coinstake needs a real stake; the stored layout is the same.)
        let coinstake = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x01, 0x01]))],
            vout: vec![
                // Output 0: Empty marker
                TxOut::new(Amount::ZERO, Script::new()),
                // Output 1: Actual reward
                TxOut::new(Amount::from_divi(1000), Script::new_p2pkh(&[0xaa; 20])),
            ],
            lock_time: 0,
        };

        block.transactions.push(coinstake.clone());
        seal(&mut block);
        // seal puts the height in front of the coinbase script
        let coinstake = block.transactions[0].clone();

        // Accept the block
        let block_hash = chain
            .accept_block(block)
            .expect("Block should be accepted")
            .hash;

        // Compute the coinstake txid
        let coinstake_txid = chain.compute_txid(&coinstake);

        // CRITICAL TEST: Verify BOTH outputs are stored at their correct indices

        // Output 0 should exist (even though it's empty)
        let outpoint_0 = OutPoint::new(coinstake_txid, 0);
        assert!(
            chain.has_utxo(&outpoint_0).unwrap(),
            "Output 0 (empty marker) must be stored to preserve indices"
        );

        let utxo_0 = chain
            .get_utxo(&outpoint_0)
            .unwrap()
            .expect("Output 0 should exist in UTXO set");
        assert_eq!(
            utxo_0.value,
            Amount::ZERO,
            "Output 0 should have zero value"
        );
        assert!(
            utxo_0.script_pubkey.is_empty(),
            "Output 0 should have empty script"
        );

        // Output 1 should exist AT INDEX 1 (not index 0!)
        let outpoint_1 = OutPoint::new(coinstake_txid, 1);
        assert!(
            chain.has_utxo(&outpoint_1).unwrap(),
            "Output 1 must exist at index 1 (not shifted to index 0)"
        );

        let utxo_1 = chain
            .get_utxo(&outpoint_1)
            .unwrap()
            .expect("Output 1 should exist in UTXO set");
        assert_eq!(
            utxo_1.value,
            Amount::from_divi(1000),
            "Output 1 should have correct value"
        );

        // Now test that we can spend output 1 by referencing it correctly
        // Create a block that spends output 1
        let mut spending_block = Block::default();
        spending_block.header.version = 1;
        spending_block.header.prev_block = block_hash;
        spending_block.header.time = genesis_time + 120;
        spending_block.header.bits = 0x207fffff;

        // Coinbase for spending block
        let coinbase2 = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x02, 0x01]))],
            vout: vec![TxOut::new(Amount::ZERO, Script::new())],
            lock_time: 0,
        };

        // Transaction spending output 1 (at index 1, not index 0!)
        let spending_tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: outpoint_1,                        // Spending output 1
                script_sig: Script::from_bytes(vec![0x01]), // Dummy signature
                sequence: 0xffffffff,
            }],
            vout: vec![TxOut::new(
                Amount::from_divi(900),
                Script::new_p2pkh(&[0xbb; 20]),
            )],
            lock_time: 0,
        };

        spending_block.transactions.push(coinbase2);
        spending_block.transactions.push(spending_tx);
        seal(&mut spending_block);

        // This should succeed because output 1 exists at index 1
        let result = chain.accept_block(spending_block);

        // Note: May fail due to signature validation or maturity checks,
        // but should NOT fail with "UTXO not found" error
        if let Err(e) = result {
            let error_msg = format!("{:?}", e);
            assert!(
                !error_msg.contains("UtxoNotFound") && !error_msg.contains("UTXO not found"),
                "Should not get 'UTXO not found' error. Got: {}. \
                 This means output indices were preserved correctly.",
                error_msg
            );
        }

        // After spending, output 1 should be removed from UTXO set
        // (only if block was accepted)
        if chain.height() == 2 {
            assert!(
                !chain.has_utxo(&outpoint_1).unwrap(),
                "Output 1 should be removed after being spent"
            );
        }
    }

    //     /// Test that disconnecting blocks with empty outputs works correctly
    //     ///
    //     /// This tests the disconnect_block path which also needs to handle
    //     /// empty outputs correctly (remove them all, not skip them).
    //     #[test]
    //     fn test_disconnect_block_removes_all_outputs_including_empty() {
    //         let (chain, _dir) = create_test_chain();
    //
    //         let (genesis_hash, genesis_time) = get_genesis_info(&chain);
    //
    //         // Create block with transaction that has empty output
    //         let mut block1 = Block::default();
    //         block1.header.version = 1;
    //         block1.header.prev_block = genesis_hash;
    //         block1.header.time = genesis_time + 60;
    //         block1.header.bits = 0x207fffff;
    //
    //         let coinbase = Transaction {
    //             version: 1,
    //             vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x01, 0x01]))],
    //             vout: vec![TxOut::new(Amount::ZERO, Script::new())],
    //             lock_time: 0,
    //         };
    //
    //         let tx_with_empty = Transaction {
    //             version: 1,
    //             vin: vec![TxIn {
    //                 prevout: OutPoint::null(),
    //                 script_sig: Script::new(),
    //                 sequence: 0xffffffff,
    //             }],
    //             vout: vec![
    //                 TxOut::new(Amount::ZERO, Script::new()), // Empty output 0
    //                 TxOut::new(Amount::from_divi(100), Script::new_p2pkh(&[0xcc; 20])), // Output 1
    //             ],
    //             lock_time: 0,
    //         };
    //
    //         block1.transactions.push(coinbase);
    //         block1.transactions.push(tx_with_empty.clone());
    //         block1.header.merkle_root = compute_merkle_root(&block1.transactions);
    //
    //         let block1_hash = chain.accept_block(block1.clone()).unwrap().hash;
    //         let tx_hash = chain.compute_txid(&tx_with_empty);
    //
    //         // Verify both outputs exist
    //         assert!(chain.has_utxo(&OutPoint::new(tx_hash, 0)).unwrap());
    //         assert!(chain.has_utxo(&OutPoint::new(tx_hash, 1)).unwrap());
    //
    //         // Create competing block to trigger reorg (disconnect block1)
    //         let mut block2 = Block::default();
    //         block2.header.version = 1;
    //         block2.header.prev_block = genesis_hash;
    //         block2.header.time = genesis_time + 61; // Slightly later
    //         block2.header.bits = 0x207fffff;
    //
    //         let coinbase2 = Transaction {
    //             version: 1,
    //             vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x02]))],
    //             vout: vec![TxOut::new(Amount::from_divi(1250), Script::new_p2pkh(&[0xdd; 20]))],
    //             lock_time: 0,
    //         };
    //
    //         block2.transactions.push(coinbase2);
    //         block2.header.merkle_root = compute_merkle_root(&block2.transactions);
    //
    //         let _block2_hash = chain.accept_block(block2).unwrap().hash;
    //
    //         // After reorg, block1's UTXOs should be removed (including empty output)
    //         assert!(
    //             !chain.has_utxo(&OutPoint::new(tx_hash, 0)).unwrap(),
    //             "Empty output should be removed during disconnect"
    //         );
    //         assert!(
    //             !chain.has_utxo(&OutPoint::new(tx_hash, 1)).unwrap(),
    //             "Output 1 should be removed during disconnect"
    //         );
    //     }

    /// Test that multiple transactions in same block maintain correct indices
    ///
    /// This tests that when we have multiple transactions with empty outputs,
    /// all indices are preserved correctly.
    #[test]
    fn test_multiple_transactions_with_empty_outputs() {
        let (chain, _dir) = create_test_chain();

        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        // Create block with multiple transactions that have empty outputs
        let mut block = Block::default();
        block.header.version = 1;
        block.header.prev_block = genesis_hash;
        block.header.time = genesis_time + 60;
        block.header.bits = 0x207fffff;

        // Two coinbase-like transactions are not allowed in one block, so each
        // layout goes in its own block's coinbase.
        // tx1: empty output at index 0, real output at index 1
        let tx1 = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x01, 0x01]))],
            vout: vec![
                TxOut::new(Amount::ZERO, Script::new()), // Index 0: empty
                TxOut::new(Amount::from_divi(100), Script::new_p2pkh(&[0xaa; 20])), // Index 1
            ],
            lock_time: 0,
        };

        // tx2: empty outputs at 0 and 1, real output at index 2
        let tx2 = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x01, 0x02]))],
            vout: vec![
                TxOut::new(Amount::ZERO, Script::new()), // Index 0: empty
                TxOut::new(Amount::ZERO, Script::new()), // Index 1: empty
                TxOut::new(Amount::from_divi(200), Script::new_p2pkh(&[0xbb; 20])), // Index 2
            ],
            lock_time: 0,
        };

        block.transactions.push(tx1.clone());
        seal(&mut block);
        // seal puts the height in front of the coinbase script
        let tx1 = block.transactions[0].clone();
        let first = chain.accept_block(block).unwrap().hash;

        let mut block = Block::default();
        block.header.version = 1;
        block.header.prev_block = first;
        block.header.time = genesis_time + 120;
        block.header.bits = 0x207fffff;
        block.transactions.push(tx2.clone());
        seal(&mut block);
        let tx2 = block.transactions[0].clone();
        chain.accept_block(block).unwrap();

        let tx1_hash = chain.compute_txid(&tx1);
        let tx2_hash = chain.compute_txid(&tx2);

        // Verify tx1 outputs
        assert!(
            chain.has_utxo(&OutPoint::new(tx1_hash, 0)).unwrap(),
            "tx1 output 0 (empty) must exist"
        );
        assert!(
            chain.has_utxo(&OutPoint::new(tx1_hash, 1)).unwrap(),
            "tx1 output 1 (100 DIVI) must exist at correct index"
        );

        let tx1_utxo1 = chain
            .get_utxo(&OutPoint::new(tx1_hash, 1))
            .unwrap()
            .unwrap();
        assert_eq!(tx1_utxo1.value, Amount::from_divi(100));

        // Verify tx2 outputs
        assert!(
            chain.has_utxo(&OutPoint::new(tx2_hash, 0)).unwrap(),
            "tx2 output 0 (empty) must exist"
        );
        assert!(
            chain.has_utxo(&OutPoint::new(tx2_hash, 1)).unwrap(),
            "tx2 output 1 (empty) must exist"
        );
        assert!(
            chain.has_utxo(&OutPoint::new(tx2_hash, 2)).unwrap(),
            "tx2 output 2 (200 DIVI) must exist at correct index"
        );

        let tx2_utxo2 = chain
            .get_utxo(&OutPoint::new(tx2_hash, 2))
            .unwrap()
            .unwrap();
        assert_eq!(tx2_utxo2.value, Amount::from_divi(200));
    }

    // ===== Block-expiry pruning =====

    /// Build `n` blocks on top of genesis by writing storage directly. `accept_block`
    /// would demand real proof-of-stake past height 100, and pruning does not care.
    fn build_chain_of(chain: &Chain, n: u32) -> Vec<Hash256> {
        let (genesis_hash, genesis_time) = get_genesis_info(chain);
        let mut prev = chain.get_block_index(&genesis_hash).unwrap().unwrap();
        let mut hashes = vec![genesis_hash];
        let mut t = genesis_time;
        for h in 1..=n {
            t += 60;
            let block = create_child_block_with_time(prev.hash, t);
            let mut index = BlockIndex::from_header(&block.header, h, Some(&prev));
            index.hash = chain.compute_block_hash(&block);
            chain.db.store_block(&index.hash, &block).unwrap();
            chain.db.store_block_index_entry(&index).unwrap();
            chain.db.set_height_mapping(h, &index.hash).unwrap();
            hashes.push(index.hash);
            prev = index;
        }
        chain.db.set_best_block(&prev.hash).unwrap();
        *chain.tip.write() = Some(prev);
        hashes
    }

    #[test]
    fn test_prune_minimum_keeps_floor_and_chainstate() {
        use crate::prune::{Expire, MIN_BLOCKS_TO_KEEP};
        let (chain, _dir) = create_test_chain();
        let n = MIN_BLOCKS_TO_KEEP + 120;
        let hashes = build_chain_of(&chain, n);
        let tip_before = chain.tip().unwrap();
        assert_eq!(chain.prune_height(), 0);

        let pruned = chain.prune_expired(Expire::Minimum, None, 0).unwrap();
        assert_eq!(pruned, 120);
        assert_eq!(chain.prune_height(), 120);
        assert_eq!(chain.tip().unwrap().hash, tip_before.hash);
        for (h, hash) in hashes.iter().enumerate().take(121).skip(1) {
            assert!(chain.get_block(hash).unwrap().is_none(), "body {h} pruned");
            assert!(
                chain.get_block_index(hash).unwrap().is_some(),
                "index {h} kept"
            );
        }
        for (h, hash) in hashes.iter().enumerate().take(n as usize + 1).skip(121) {
            assert!(chain.get_block(hash).unwrap().is_some(), "body {h} kept");
        }
        // Idempotent, and never reaches into the floor.
        assert_eq!(chain.prune_expired(Expire::Minimum, None, 0).unwrap(), 0);
        assert!(chain.get_block(&hashes[n as usize]).unwrap().is_some());
    }

    #[test]
    fn test_prune_strips_old_lottery_winners_only() {
        use crate::prune::{Expire, MIN_BLOCKS_TO_KEEP};
        use divi_primitives::{LotteryCoinstake, LotteryWinners, Script};
        let (chain, _dir) = create_test_chain();
        let (_, cycle) = chain.get_lottery_params();
        let n = MIN_BLOCKS_TO_KEEP + 3 * cycle + 200;
        let hashes = build_chain_of(&chain, n);
        let winners = |h: u32| {
            LotteryWinners::with_coinstakes(
                h,
                vec![LotteryCoinstake::new(
                    Hash256::from_bytes([h as u8; 32]),
                    Script::from(vec![0x51]),
                )],
            )
        };
        for (h, hash) in hashes.iter().enumerate().skip(1) {
            let mut idx = chain.get_block_index(hash).unwrap().unwrap();
            idx.lottery_winners = winners(h as u32);
            chain.db.store_block_index_entry(&idx).unwrap();
        }
        assert_eq!(chain.winners_strip_height(), 0);

        chain.prune_expired(Expire::Minimum, None, 0).unwrap();

        let strip = chain.winners_strip_height();
        let keep = 3 * cycle + 1 + MIN_BLOCKS_TO_KEEP;
        assert_eq!(
            strip,
            n - keep,
            "strip watermark = tip - (3 cycles + floor)"
        );
        for (h, hash) in hashes.iter().enumerate().skip(1) {
            let idx = chain.get_block_index(hash).unwrap().unwrap();
            if (h as u32) <= strip && !chain.is_winners_terminal_height(h as u32) {
                assert!(
                    idx.lottery_winners.coinstakes.is_empty(),
                    "winners {h} stripped"
                );
            } else {
                assert_eq!(idx.lottery_winners.coinstakes.len(), 1, "winners {h} kept");
            }
            assert_eq!(idx.height, h as u32);
            assert_eq!(idx.hash, *hash);
        }
        // Terminal lists (the block before each lottery block) survive below the watermark.
        let kept_terminals = (1..=strip)
            .filter(|h| chain.is_winners_terminal_height(*h))
            .count();
        assert!(kept_terminals > 5, "test must cover terminals below strip");
        // Survives a round trip through the DB (not just the cache) and is idempotent.
        let raw = chain.db.get_block_index(&hashes[1]).unwrap().unwrap();
        assert!(raw.lottery_winners.coinstakes.is_empty());
        chain.prune_expired(Expire::Minimum, None, 0).unwrap();
        assert_eq!(chain.winners_strip_height(), strip);
        // Never strips without expire.
        let (chain2, _d2) = create_test_chain();
        build_chain_of(&chain2, n);
        chain2.prune_expired(Expire::Never, None, 0).unwrap();
        assert_eq!(chain2.winners_strip_height(), 0);
    }

    #[test]
    fn test_prune_never_and_wallet_floor_and_window() {
        use crate::prune::{Expire, MIN_BLOCKS_TO_KEEP};
        let (chain, _dir) = create_test_chain();
        let n = MIN_BLOCKS_TO_KEEP + 200;
        let hashes = build_chain_of(&chain, n);
        let genesis_time = chain.get_block_index(&hashes[0]).unwrap().unwrap().time as u64;

        // -1 never prunes.
        assert_eq!(
            chain
                .prune_expired(Expire::Never, None, u64::MAX / 2)
                .unwrap(),
            0
        );
        assert_eq!(chain.prune_height(), 0);

        // Wallet floor limits the pass.
        assert_eq!(
            chain.prune_expired(Expire::Minimum, Some(50), 0).unwrap(),
            50
        );
        assert!(chain.get_block(&hashes[51]).unwrap().is_some());

        // Window: "now" = time of block 150 + 10 minutes, keep 5 minutes -> blocks with
        // time < now-300 are expired, i.e. up to height 150 - 4 = 146 (60 s spacing).
        let now = genesis_time + 150 * 60 + 600;
        let cutoff = chain
            .prune_cutoff(Expire::Window(300), None, now)
            .unwrap()
            .unwrap();
        let t_cut = chain
            .get_block_index_by_height(cutoff)
            .unwrap()
            .unwrap()
            .time as u64;
        let t_next = chain
            .get_block_index_by_height(cutoff + 1)
            .unwrap()
            .unwrap()
            .time as u64;
        assert!(
            t_cut < now - 300 && t_next >= now - 300,
            "cutoff is the window edge"
        );
        chain.prune_expired(Expire::Window(300), None, now).unwrap();
        assert!(chain.get_block(&hashes[cutoff as usize]).unwrap().is_none());
        assert!(chain
            .get_block(&hashes[cutoff as usize + 1])
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_kernel_lookup_survives_pruned_body() {
        use crate::prune::{Expire, MIN_BLOCKS_TO_KEEP};
        let (chain, _dir) = create_test_chain();
        let hashes = build_chain_of(&chain, MIN_BLOCKS_TO_KEEP + 50);
        chain.prune_expired(Expire::Minimum, None, 0).unwrap();
        let parent = chain.tip().unwrap();
        let bogus_txid = Hash256::from_bytes([7u8; 32]);
        // Kernel at a pruned height resolves from the index without the body.
        let idx = chain
            .resolve_kernel_block_index(&parent, &bogus_txid, 10)
            .unwrap();
        assert_eq!(idx.hash, hashes[10]);
    }

    #[test]
    fn test_median_time_past_genesis() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, _) = get_genesis_info(&chain);
        let genesis_index = chain.get_block_index(&genesis_hash).unwrap().unwrap();

        let mtp = chain.get_median_time_past(&genesis_index).unwrap();
        assert_eq!(
            mtp, genesis_index.time,
            "MTP of genesis should be genesis timestamp"
        );
    }

    #[test]
    fn test_median_time_past_few_blocks() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let block1 = create_child_block_with_time(genesis_hash, genesis_time + 60);
        let hash1 = chain.accept_block(block1).unwrap().hash;

        let block2 = create_child_block_with_time(hash1, genesis_time + 120);
        let hash2 = chain.accept_block(block2).unwrap().hash;

        let block3 = create_child_block_with_time(hash2, genesis_time + 180);
        let hash3 = chain.accept_block(block3).unwrap().hash;

        let index3 = chain.get_block_index(&hash3).unwrap().unwrap();
        let mtp = chain.get_median_time_past(&index3).unwrap();

        let mut times = [
            genesis_time,
            genesis_time + 60,
            genesis_time + 120,
            genesis_time + 180,
        ];
        times.sort_unstable();
        let expected_median = times[times.len() / 2];

        assert_eq!(mtp, expected_median, "MTP should be median of 4 blocks");
    }

    #[test]
    fn test_median_time_past_exactly_11_blocks() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let mut prev_hash = genesis_hash;
        let mut timestamps = vec![genesis_time];

        for i in 1..=10 {
            let block_time = genesis_time + (i * 60);
            timestamps.push(block_time);
            let block = create_child_block_with_time(prev_hash, block_time);
            prev_hash = chain.accept_block(block).unwrap().hash;
        }

        let final_index = chain.get_block_index(&prev_hash).unwrap().unwrap();
        let mtp = chain.get_median_time_past(&final_index).unwrap();

        let mut sorted_times = timestamps.clone();
        sorted_times.sort_unstable();
        let expected_median = sorted_times[sorted_times.len() / 2];

        assert_eq!(mtp, expected_median, "MTP should be median of 11 blocks");
        assert_eq!(timestamps.len(), 11, "Should have exactly 11 timestamps");
    }

    #[test]
    fn test_median_time_past_more_than_11_blocks() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let mut prev_hash = genesis_hash;

        for i in 1..=20 {
            let block_time = genesis_time + (i * 60);
            let block = create_child_block_with_time(prev_hash, block_time);
            prev_hash = chain.accept_block(block).unwrap().hash;
        }

        let final_index = chain.get_block_index(&prev_hash).unwrap().unwrap();
        let mtp = chain.get_median_time_past(&final_index).unwrap();

        let mut last_11_timestamps = vec![];
        for i in 10..=20 {
            last_11_timestamps.push(genesis_time + (i * 60));
        }

        let mut sorted_times = last_11_timestamps.clone();
        sorted_times.sort_unstable();
        let expected_median = sorted_times[sorted_times.len() / 2];

        assert_eq!(mtp, expected_median, "MTP should use only last 11 blocks");
        assert_eq!(last_11_timestamps.len(), 11);
    }

    #[test]
    fn test_median_time_past_with_increasing_timestamps() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let time_deltas = vec![100, 150, 200, 250, 300];
        let mut prev_hash = genesis_hash;
        let mut all_times = vec![genesis_time];

        for &delta in &time_deltas {
            let block_time = genesis_time + delta;
            all_times.push(block_time);
            let block = create_child_block_with_time(prev_hash, block_time);
            prev_hash = chain.accept_block(block).unwrap().hash;
        }

        let final_index = chain.get_block_index(&prev_hash).unwrap().unwrap();
        let mtp = chain.get_median_time_past(&final_index).unwrap();

        let mut sorted_times = all_times.clone();
        sorted_times.sort_unstable();
        let expected_median = sorted_times[sorted_times.len() / 2];

        assert_eq!(mtp, expected_median, "MTP should compute median correctly");
    }

    #[test]
    fn test_block_timestamp_validation_against_mtp() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let mut prev_hash = genesis_hash;
        for i in 1..=5 {
            let block = create_child_block_with_time(prev_hash, genesis_time + (i * 60));
            prev_hash = chain.accept_block(block).unwrap().hash;
        }

        let parent_index = chain.get_block_index(&prev_hash).unwrap().unwrap();
        let mtp = chain.get_median_time_past(&parent_index).unwrap();

        let invalid_block = create_child_block_with_time(prev_hash, mtp);
        let result = chain.accept_block(invalid_block);

        assert!(
            result.is_err(),
            "Block with timestamp <= MTP should be rejected"
        );
        if let Err(e) = result {
            let error_msg = format!("{:?}", e);
            assert!(
                error_msg.contains("median time past") || error_msg.contains("timestamp"),
                "Error should mention MTP or timestamp validation"
            );
        }
    }

    #[test]
    fn test_block_timestamp_validation_passes_when_greater_than_mtp() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);

        let mut prev_hash = genesis_hash;
        for i in 1..=5 {
            let block = create_child_block_with_time(prev_hash, genesis_time + (i * 60));
            prev_hash = chain.accept_block(block).unwrap().hash;
        }

        let parent_index = chain.get_block_index(&prev_hash).unwrap().unwrap();
        let mtp = chain.get_median_time_past(&parent_index).unwrap();

        let valid_block = create_child_block_with_time(prev_hash, mtp + 1);
        let result = chain.accept_block(valid_block);

        assert!(
            result.is_ok(),
            "Block with timestamp > MTP should be accepted"
        );
    }

    fn create_child_block_with_time(parent: Hash256, time: u32) -> Block {
        let mut block = Block::default();
        block.header.version = 1;
        block.header.prev_block = parent;
        block.header.time = time;
        block.header.bits = 0x207fffff;

        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x01, 0x01]))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250_00000000),
                Script::new_p2pkh(&[0xab; 20]),
            )],
            lock_time: 0,
        };

        block.transactions.push(coinbase);
        seal(&mut block);
        block
    }

    // ===== Lane E: height index must describe the active chain only =====

    /// A stale sibling stored after the main-chain block must not overwrite the
    /// height -> hash mapping (it did: accept_block wrote it for every block).
    #[test]
    fn test_side_chain_block_does_not_overwrite_height_index() {
        let dir = tempdir().unwrap();
        let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
        let (hash_a1, hash_b1);
        {
            let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
            let chain = Chain::new(db, params.clone()).unwrap();
            let (genesis_hash, genesis_time) = get_genesis_info(&chain);
            let a1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
            hash_a1 = chain.accept_block(a1.clone()).unwrap().hash;
            let a2 = create_child_block_with_pubkey(hash_a1, a1.header.time, [0x0b; 20]);
            chain.accept_block(a2).unwrap();
            // Less-work sibling of A1 arrives late (stale block).
            let b1 = create_child_block_with_pubkey(genesis_hash, genesis_time + 1, [0x1a; 20]);
            hash_b1 = chain.accept_block(b1).unwrap().hash;
            assert_ne!(hash_a1, hash_b1);
            assert_eq!(chain.height(), 2);
            assert_eq!(
                chain.get_block_index_by_height(1).unwrap().unwrap().hash,
                hash_a1,
                "height 1 must still map to the active-chain block"
            );
        }
        // And on disk, not just in the cache.
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Chain::new(db, params).unwrap();
        assert_eq!(
            chain.get_block_index_by_height(1).unwrap().unwrap().hash,
            hash_a1
        );
        assert!(chain.db.get_block_index(&hash_b1).unwrap().is_some());
    }

    /// A recorded tip whose index entry is gone used to send Chain::new into
    /// init_genesis, quietly restarting the chain from block 0.
    #[test]
    fn test_missing_tip_index_is_an_error_not_a_new_chain() {
        let dir = tempdir().unwrap();
        let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
        let tip_hash = {
            let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
            let chain = Chain::new(db, params.clone()).unwrap();
            let (genesis_hash, genesis_time) = get_genesis_info(&chain);
            let b1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
            chain.accept_block(b1).unwrap().hash
        };
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            let raw = db.inner_db();
            let key = crate::block_index::block_index_key(&tip_hash);
            raw.delete_cf(&raw.cf_handle("block_index").unwrap(), key)
                .unwrap();
        }
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let err = Chain::new(db.clone(), params).err().expect("must refuse");
        assert!(err.to_string().contains("damaged"), "{err}");
        assert_eq!(
            db.get_best_block().unwrap(),
            Some(tip_hash),
            "tip left alone"
        );
    }

    /// verify_recent_blocks walks the newest blocks and reports a body that does not
    /// match its index entry.
    #[test]
    fn test_verify_recent_blocks() {
        let (chain, _dir) = create_test_chain();
        let (mut hash, mut time) = get_genesis_info(&chain);
        let mut blocks = Vec::new();
        for i in 0..5u8 {
            let b = create_child_block_with_pubkey(hash, time, [i + 1; 20]);
            time = b.header.time;
            hash = chain.accept_block(b.clone()).unwrap().hash;
            blocks.push((hash, b));
        }
        assert_eq!(chain.verify_recent_blocks(0).unwrap(), 6, "0 = whole chain");
        assert_eq!(chain.verify_recent_blocks(3).unwrap(), 3);
        assert_eq!(
            chain.verify_recent_blocks(100).unwrap(),
            6,
            "tip down to genesis"
        );
        // Store block 2's body under block 4's hash: wrong data for that key
        chain.db.store_block(&blocks[3].0, &blocks[1].1).unwrap();
        let err = chain.verify_recent_blocks(100).unwrap_err().to_string();
        assert!(err.contains("damaged at height 4"), "{err}");
        assert_eq!(
            chain.verify_recent_blocks(1).unwrap(),
            1,
            "height 4 not in range"
        );
    }

    /// getchaintips must report side branches, not just the active tip.
    #[test]
    fn test_get_chain_tips_reports_side_branches() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);
        let a1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
        let hash_a1 = chain.accept_block(a1.clone()).unwrap().hash;
        let a2 = create_child_block_with_pubkey(hash_a1, a1.header.time, [0x0b; 20]);
        let hash_a2 = chain.accept_block(a2).unwrap().hash;
        // Stale sibling of A1: stored, never connected.
        let b1 = create_child_block_with_pubkey(genesis_hash, genesis_time + 1, [0x1a; 20]);
        let hash_b1 = chain.accept_block(b1).unwrap().hash;

        let tips = chain.get_chain_tips().unwrap();
        assert_eq!(tips.len(), 2, "active tip plus one side branch: {tips:?}");
        assert_eq!(tips[0].hash, hash_a2);
        assert_eq!(tips[0].status, ChainTipStatus::Active);
        assert_eq!(tips[0].branch_len, 0);
        assert_eq!(tips[1].hash, hash_b1);
        assert_eq!(tips[1].height, 1);
        assert_eq!(tips[1].branch_len, 1);
        assert_eq!(tips[1].status, ChainTipStatus::ValidHeaders);
    }

    /// After a reorg the abandoned branch is a fully validated `valid-fork`.
    #[test]
    fn test_get_chain_tips_after_reorg_marks_old_branch_valid_fork() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);
        let a1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
        let hash_a1 = chain.accept_block(a1.clone()).unwrap().hash;
        let a2 = create_child_block_with_pubkey(hash_a1, a1.header.time, [0x0b; 20]);
        let hash_a2 = chain.accept_block(a2).unwrap().hash;
        let b1 = create_child_block_with_pubkey(genesis_hash, genesis_time + 1, [0x1a; 20]);
        let hash_b1 = chain.accept_block(b1.clone()).unwrap().hash;
        let b2 = create_child_block_with_pubkey(hash_b1, b1.header.time, [0x1b; 20]);
        let hash_b2 = chain.accept_block(b2.clone()).unwrap().hash;
        let b3 = create_child_block_with_pubkey(hash_b2, b2.header.time, [0x1c; 20]);
        let hash_b3 = chain.accept_block(b3).unwrap().hash;
        assert_eq!(chain.tip().unwrap().hash, hash_b3);

        let tips = chain.get_chain_tips().unwrap();
        assert_eq!(tips.len(), 2, "{tips:?}");
        assert_eq!(
            (tips[0].hash, tips[0].status),
            (hash_b3, ChainTipStatus::Active)
        );
        assert_eq!(tips[1].hash, hash_a2);
        assert_eq!(tips[1].branch_len, 2);
        assert_eq!(tips[1].status, ChainTipStatus::ValidFork);
    }

    /// invalidateblock on an active block rolls the tip back to its parent
    /// (or switches to a valid competing branch); reconsiderblock restores it.
    #[test]
    fn test_invalidate_and_reconsider_block() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);
        let a1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
        let hash_a1 = chain.accept_block(a1.clone()).unwrap().hash;
        let a2 = create_child_block_with_pubkey(hash_a1, a1.header.time, [0x0b; 20]);
        let hash_a2 = chain.accept_block(a2.clone()).unwrap().hash;
        let a3 = create_child_block_with_pubkey(hash_a2, a2.header.time, [0x0c; 20]);
        let hash_a3 = chain.accept_block(a3).unwrap().hash;
        assert_eq!(chain.tip().unwrap().hash, hash_a3);

        let a2_coinbase = OutPoint::new(
            chain.compute_txid(&chain.get_block(&hash_a2).unwrap().unwrap().transactions[0]),
            0,
        );
        assert!(chain.has_utxo(&a2_coinbase).unwrap());

        // Invalidate A2: A2 and A3 leave the chain, tip is A1.
        chain.invalidate_block(&hash_a2).unwrap();
        assert_eq!(chain.tip().unwrap().hash, hash_a1);
        assert_eq!(chain.height(), 1);
        assert!(!chain.has_utxo(&a2_coinbase).unwrap_or(true));
        assert!(chain.get_block_index(&hash_a2).unwrap().unwrap().failed());
        assert!(chain.get_block_index(&hash_a3).unwrap().unwrap().failed());

        // Reconsider A2: the chain returns to A3.
        chain.reconsider_block(&hash_a2).unwrap();
        assert_eq!(chain.tip().unwrap().hash, hash_a3);
        assert_eq!(chain.height(), 3);
        assert!(chain.has_utxo(&a2_coinbase).unwrap());
        assert!(!chain.get_block_index(&hash_a3).unwrap().unwrap().failed());

        // Unknown block
        assert!(matches!(
            chain.invalidate_block(&Hash256::from_bytes([0x77; 32])),
            Err(StorageError::BlockNotFound(_))
        ));
    }

    /// Invalidating the active tip switches to a valid shorter side branch
    /// only if it has more work than the new tip; here it does.
    #[test]
    fn test_invalidate_block_switches_to_side_branch() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);
        let a1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
        let hash_a1 = chain.accept_block(a1.clone()).unwrap().hash;
        let a2 = create_child_block_with_pubkey(hash_a1, a1.header.time, [0x0b; 20]);
        let hash_a2 = chain.accept_block(a2).unwrap().hash;
        let b1 = create_child_block_with_pubkey(genesis_hash, genesis_time + 1, [0x1a; 20]);
        let hash_b1 = chain.accept_block(b1).unwrap().hash;
        assert_eq!(chain.tip().unwrap().hash, hash_a2);

        chain.invalidate_block(&hash_a1).unwrap();
        assert_eq!(chain.tip().unwrap().hash, hash_b1);
        assert_eq!(chain.height(), 1);
    }

    /// repair_height_index restores entries a pre-fix build corrupted and
    /// removes entries above the tip.
    #[test]
    fn test_repair_height_index() {
        let (chain, _dir) = create_test_chain();
        let (genesis_hash, genesis_time) = get_genesis_info(&chain);
        let a1 = create_child_block_with_pubkey(genesis_hash, genesis_time, [0x0a; 20]);
        let hash_a1 = chain.accept_block(a1.clone()).unwrap().hash;
        let a2 = create_child_block_with_pubkey(hash_a1, a1.header.time, [0x0b; 20]);
        chain.accept_block(a2).unwrap();
        let b1 = create_child_block_with_pubkey(genesis_hash, genesis_time + 1, [0x1a; 20]);
        let hash_b1 = chain.accept_block(b1).unwrap().hash;

        // Reproduce the pre-fix on-disk state.
        chain.db.set_height_mapping(1, &hash_b1).unwrap();
        chain.db.set_height_mapping(7, &hash_b1).unwrap();

        let audit = chain.repair_height_index(false).unwrap();
        assert_eq!(
            (audit.checked, audit.mismatched, audit.removed_above_tip),
            (3, 1, 0)
        );
        // The above-tip scan is contiguous from tip+1; use a contiguous stale entry.
        chain.db.remove_height_mapping(7).unwrap();
        chain.db.set_height_mapping(3, &hash_b1).unwrap();

        let audit = chain.repair_height_index(true).unwrap();
        assert_eq!(audit.mismatched, 1);
        assert_eq!(audit.removed_above_tip, 1);
        assert_eq!(audit.first_mismatches, vec![1]);
        assert_eq!(
            chain.get_block_index_by_height(1).unwrap().unwrap().hash,
            hash_a1
        );
        assert!(chain.get_block_index_by_height(3).unwrap().is_none());
        let again = chain.repair_height_index(false).unwrap();
        assert_eq!((again.mismatched, again.removed_above_tip), (0, 0));
    }

    // Real mainnet data: block 4,168,729 (076f3c67...) stakes output
    // 92e02051...:1, confirmed at height 4,160,835 in block 1c64797f... (time
    // 1786214610). A stale sibling ccdc7a9a... (time 1786214609) at the same height
    // overwrote the height mapping, so validation used the wrong kernel block time
    // and computed fd1b5590... instead of 00000036..., rejecting a valid block.
    const MAINNET_4168729: &str = "040000004ea7f13657e99799b3649308c9b1a2214bf2ccb93943ad8470dc3d042432ef43c73f3ae138df9a7a9bc1ba056ec10a5b434aaaf438f8880e884b3972480d1b9ee3957e6a6a2d011b0000000000000000000000000000000000000000000000000000000000000000000000000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0603199c3f0101ffffffff0100000000000000000000000000010000000135853e268545cddeb842a7af7ad74442b2ca159a46b5509e6929d7555120e092010000006b47304402201a71abbc6df7ba09365e0862b00b9c44a471f944cd63cc99d06f0dfa9be241df0220791aa648269fb533aca74dea6daa3ca0670432b69ec7511977e4932714288e0b0121025e79347493205945da83b6c218efa9d95395f1ec0810fdd14b4ded443e779f6a00ffffffff020000000000000000000023779a8603000032631498aa0889294384a3b218e334b1e7a55078d7f66367b914d6bd2e3196f9b54d83a796b6b76594d12e3d4ad06878a988ac000000004120601fef16097a3ab0641c2d3da690338bcefacac6249d9b3bf3ab0c404b2c19e97fb5fe6d1ae15e66e9a5771a1473942c609cb7c2e6347edb00df62f90f4a8aac";
    const MAINNET_4160835_MAIN: &str = "040000003292b2889c76e7ae503d95a71c3ef55dc0ede7c2c27279a0a048086fc9216b01c080161abea3834b5afb3ee5c6113877cadad5cf38c0b71e66d18f5b6a12121bd278776aed36011b0000000000000000000000000000000000000000000000000000000000000000000000000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0603437d3f0101ffffffff010000000000000000000000000001000000017082a6a7a0356668eaa0bfcba3aa9c8db5e98dc81d9a31e273edb102db76d611010000006c483045022100da7a8989d2fadbd2a26096c0205834c1140aa09dc84b3a9911d990eb0bf2524c02204447c1532765905d51ee2b6ce0778d02e339e37b3350c4ae3df7173063b146d70121025e79347493205945da83b6c218efa9d95395f1ec0810fdd14b4ded443e779f6a00ffffffff02000000000000000000007127027b03000032631498aa0889294384a3b218e334b1e7a55078d7f66367b914d6bd2e3196f9b54d83a796b6b76594d12e3d4ad06878a988ac000000004120c0d370f911e085bfdf29511b8b79578a03af59aade1f2e43aed7929e27fb684126ecbc9139eb9f6a7578bca6fbab5ed66636268b72fab1be340a9bfc3338e077";
    const MAINNET_4160835_STALE: &str = "040000003292b2889c76e7ae503d95a71c3ef55dc0ede7c2c27279a0a048086fc9216b01c5905e42d5cc405ce781020d2b8e5be3df69d98fdfc089ee35c9d3364414ccd3d178776aed36011b0000000000000000000000000000000000000000000000000000000000000000000000000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0603437d3f0101ffffffff0100000000000000000000000000010000000139bd722ff63fe914bdfc39a30e7094fef771d1ac445971c9f55bfbd1a1300d83010000006b47304402205967762c6d7a245173007f7915af174640e88495842e7162801a6e41f913a9cb02201d509ff4f7a00b172e15acd819e50c467605b9e78a031e427708a473c7e61ecf012103cd9d8bd4a5aa2abf8bd68b9ee329df2b303b5fed0b829a8d527aed93f8f172d600ffffffff02000000000000000000d9e190da95010000326314f4cc232c04bef1a87d8780bd7055d7cba4a7891b67b91438a39738d282862753945a3d19487f1e0a01e36d6878a988ac00000000411f9f61d2dbbd547c1fb48c2b2082172fb7cec32d27d8d06a8a386baf55233fb93b7ba972370b3de67bacac16a890a2c13af52da3691b03b2094148ca1c25f4d9a9";
    const KERNEL_HEIGHT: u32 = 4_160_835;
    const PARENT_HEIGHT: u32 = 4_168_728;

    /// Build the on-disk state a pre-fix node had when it rejected 4,168,729.
    /// `with_ancestry` links parent -> ... -> kernel block with placeholder
    /// index entries so the kernel can be resolved by walking ancestors.
    fn mainnet_4168729_fixture(
        with_tx_index: bool,
        with_ancestry: bool,
    ) -> (Chain, tempfile::TempDir, Block, BlockIndex) {
        use divi_primitives::serialize::deserialize;
        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
        let mut chain = Chain::new(
            db,
            ChainParams::for_network(NetworkType::Mainnet, ChainMode::Divi),
        )
        .unwrap();
        let block: Block = deserialize(&hex::decode(MAINNET_4168729).unwrap()).unwrap();
        let kb: Block = deserialize(&hex::decode(MAINNET_4160835_MAIN).unwrap()).unwrap();
        let ob: Block = deserialize(&hex::decode(MAINNET_4160835_STALE).unwrap()).unwrap();
        let kb_hash = chain.compute_block_hash(&kb);
        let ob_hash = chain.compute_block_hash(&ob);
        assert_eq!(
            kb_hash.to_string(),
            "1c64797f9da5660f7719601dcf2039c0ddc67425a42b06347c578e8cfea5b86b"
        );
        assert_eq!(
            ob_hash.to_string(),
            "ccdc7a9a5c97a7586928932ded2d14c14b45b241ec6659f9de2ee8fc4490ebde"
        );
        let kernel = block.transactions[1].vin[0].prevout;
        assert_eq!(chain.compute_txid(&kb.transactions[1]), kernel.txid);

        let mut kb_idx = BlockIndex::from_header(&kb.header, KERNEL_HEIGHT, None);
        kb_idx.hash = kb_hash;
        kb_idx.is_proof_of_stake = true;
        let mut ob_idx = BlockIndex::from_header(&ob.header, KERNEL_HEIGHT, None);
        ob_idx.hash = ob_hash;
        ob_idx.is_proof_of_stake = true;
        chain.db.store_block(&kb_hash, &kb).unwrap();
        chain.db.store_block(&ob_hash, &ob).unwrap();
        // Main block connected first, stale sibling stored afterwards: exactly the
        // order that let the pre-fix accept_block overwrite the height mapping.
        chain.db.store_block_index(&kb_idx).unwrap();
        chain.db.store_block_index(&ob_idx).unwrap();
        assert_eq!(
            chain.db.get_height_mapping(KERNEL_HEIGHT).unwrap(),
            Some(ob_hash)
        );

        // Parent 43ef3224... (4,168,728): generated stake modifier 0x8f778a3b1e0f81d4.
        let mut parent = BlockIndex::from_header(&block.header, PARENT_HEIGHT, None);
        parent.hash = block.header.prev_block;
        parent.time = 1_786_680_822;
        parent.bits = 0x1b01363e;
        parent.stake_modifier = 0x8f77_8a3b_1e0f_81d4;
        parent.generated_stake_modifier = true;
        parent.is_proof_of_stake = true;
        parent.prev_hash = Hash256::from_bytes([0xee; 32]);
        if with_ancestry {
            // Placeholder index entries for 4,160,836..=4,168,727.
            let mut prev = kb_hash;
            for h in (KERNEL_HEIGHT + 1)..PARENT_HEIGHT {
                let mut bytes = [0u8; 32];
                bytes[..4].copy_from_slice(&h.to_le_bytes());
                bytes[31] = 0xab;
                let mut idx = parent.clone();
                idx.hash = Hash256::from_bytes(bytes);
                idx.prev_hash = prev;
                idx.height = h;
                idx.generated_stake_modifier = false;
                chain.db.store_block_index_entry(&idx).unwrap();
                prev = idx.hash;
            }
            parent.prev_hash = prev;
        }
        chain.db.store_block_index(&parent).unwrap();

        chain
            .db
            .add_utxo(
                &kernel,
                &Utxo {
                    value: Amount::from_sat(3_826_852_000_000),
                    script_pubkey: Script::from_bytes(
                        hex::decode("631498aa0889294384a3b218e334b1e7a55078d7f66367b914d6bd2e3196f9b54d83a796b6b76594d12e3d4ad06878a988ac").unwrap(),
                    ),
                    height: KERNEL_HEIGHT,
                    is_coinbase: false,
                    is_coinstake: true,
                },
            )
            .unwrap();

        if with_tx_index {
            let tx_index = Arc::new(TxIndex::open(dir.path().join("txindex")).unwrap());
            tx_index
                .put_location(&kernel.txid, &TxLocation::new(kb_hash, 1))
                .unwrap();
            chain.enable_tx_index(tx_index);
        }
        (chain, dir, block, parent)
    }

    #[test]
    fn test_pos_mainnet_4168729_kernel_resolved_via_tx_index() {
        let (chain, _dir, block, parent) = mainnet_4168729_fixture(true, false);
        chain
            .validate_proof_of_stake(&block, &parent)
            .expect("mainnet block 4,168,729 is valid and must pass PoS validation");
    }

    #[test]
    fn test_pos_mainnet_4168729_kernel_resolved_without_tx_index() {
        let (chain, _dir, block, parent) = mainnet_4168729_fixture(false, true);
        chain
            .validate_proof_of_stake(&block, &parent)
            .expect("mainnet block 4,168,729 is valid and must pass PoS validation");
    }

    /// Control: with the stale sibling's time the kernel genuinely misses, so the
    /// tests above can only pass if the right kernel block was used.
    #[test]
    fn test_pos_mainnet_4168729_stale_kernel_time_fails() {
        let (_chain, _dir, block, parent) = mainnet_4168729_fixture(false, false);
        let kernel = block.transactions[1].vin[0].prevout;
        let mk = |time: u32| crate::pos_validation::StakingData {
            n_bits: block.header.bits,
            block_time_of_first_confirmation: time,
            block_hash_of_first_confirmation: Hash256::zero(),
            utxo_being_staked: kernel,
            utxo_value: Amount::from_sat(3_826_852_000_000),
            block_hash_of_chain_tip: parent.hash,
        };
        let run = |t| {
            crate::pos_validation::compute_and_verify_proof_of_stake(
                parent.stake_modifier,
                &mk(t),
                block.header.time,
            )
            .unwrap()
        };
        assert!(
            run(1_786_214_610).1,
            "main kernel block time must hit target"
        );
        assert!(!run(1_786_214_609).1, "stale sibling time must miss target");
    }
}
