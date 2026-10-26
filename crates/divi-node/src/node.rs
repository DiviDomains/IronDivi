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

//! Full node implementation
//!
//! Orchestrates all node components: storage, networking, RPC, and wallet.

use crate::block_import::ImportResult;
use crate::config::NodeConfig;
use crate::error::NodeError;
use crate::fee_estimator::FeeEstimator;
use crate::mempool::Mempool;
use divi_consensus::bits_to_difficulty;
use divi_crypto::compute_block_hash;
use divi_masternode::MasternodeManager;
use divi_network::constants::MAX_INV_SIZE;
use divi_network::{
    BlockSync, NetworkMessage, PeerEvent, PeerManager, PeerManagerConfig, SporkManager, SyncState,
    TxRelay,
};
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::{OutPoint, Transaction};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType as StorageNetworkType};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Most block hashes in one answer to `getblocks` (Divi Core main.cpp)
pub const GETBLOCKS_LIMIT: usize = 500;

/// Divi Core's answer to `getblocks`: the main-chain blocks after the first
/// locator hash we have on it (genesis if none), up to `limit` or the stop
/// hash. When the limit is reached, the last hash is returned too: when the
/// peer asks for that block, our tip is announced so it asks for the next batch.
pub fn getblocks_reply(
    chain: &Chain,
    msg: &divi_network::GetBlocksMessage,
    limit: usize,
) -> (Vec<divi_network::InvItem>, Option<Hash256>) {
    let start_height = msg.locator_hashes.iter().find_map(|hash| {
        chain
            .get_block_index(hash)
            .ok()
            .flatten()
            .filter(|idx| idx.is_on_main_chain())
            .map(|idx| idx.height)
    });
    let mut items = Vec::new();
    let mut height = start_height.unwrap_or(0) + 1;
    while height <= chain.height() {
        let Ok(Some(idx)) = chain.get_block_index_by_height(height) else {
            break;
        };
        items.push(divi_network::InvItem::new(
            divi_network::InvType::Block,
            idx.hash,
        ));
        if items.len() >= limit {
            return (items, Some(idx.hash));
        }
        if idx.hash == msg.stop_hash {
            break;
        }
        height += 1;
    }
    (items, None)
}

/// What getdata items are served from
pub struct GetDataStores<'a> {
    pub chain: &'a Chain,
    pub tx_relay: &'a TxRelay,
    pub mempool: &'a Mempool,
    pub spork_manager: &'a SporkManager,
    pub masternode_list: &'a divi_rpc::mn_list::MasternodeList,
    pub masternode_votes: &'a divi_rpc::mn_votes::MasternodeVotes,
}

/// Answer a peer's waiting getdata as Divi Core's ProcessGetData
/// (main.cpp:283-347), in the order asked, while the bytes queued for the
/// peer are under -maxsendbuffer (main.cpp:291-293); what is left waits for
/// the next pass, so a peer that does not read holds up no other.
///
/// A block is sent only if the node has it and may send it
/// (GetBlockIndexOfRequestedBlock, main.cpp:213-247), else nothing; after the
/// last block of a full getblocks answer an inv of the tip follows, so the peer
/// asks for more. A transaction comes from what was relayed in the last 15
/// minutes, then the mempool (main.cpp:324), else it is named in a notfound,
/// which goes out after the next block, or at the end of the pass. A spork,
/// masternode broadcast, ping or vote held is sent, else named in the same
/// notfound (main.cpp:187-198, :337-346).
pub fn serve_getdata(
    stores: &GetDataStores<'_>,
    peer_manager: &PeerManager,
    hash_continue: &mut HashMap<divi_network::PeerId, Hash256>,
    queue: &mut std::collections::VecDeque<divi_network::InvItem>,
    peer_id: divi_network::PeerId,
) {
    use divi_network::TrySend;
    let GetDataStores {
        chain,
        tx_relay,
        mempool,
        spork_manager,
        masternode_list,
        masternode_votes,
    } = stores;
    let mut not_found = Vec::new();
    while let Some(item) = queue.front().cloned() {
        match peer_manager.send_queued(peer_id) {
            None => return queue.clear(),
            Some(queued) if queued >= divi_network::buffers::max_send_buffer() => break,
            Some(_) => {}
        }
        match item.inv_type {
            // A filtered block is found and followed as a block is
            // (main.cpp:300-318), sent as a merkleblock under the peer's
            // filter (which matching updates), then each matched transaction
            // the peer is not known to have (main.cpp:249-278); served whatever
            // -peerbloomfilters says, as every peer has a filter (Node.cpp:556)
            divi_network::InvType::Block | divi_network::InvType::FilteredBlock => {
                match chain.get_block_for_peer(&item.hash) {
                    Ok(Some(block)) => {
                        let messages = if item.inv_type == divi_network::InvType::Block {
                            vec![NetworkMessage::Block(block)]
                        } else {
                            let Some(stats) = peer_manager.peer_stats(peer_id) else {
                                return queue.clear();
                            };
                            let (payload, matched) = {
                                let mut filter = stats.bloom.filter();
                                divi_network::bloom::merkle_block(&block, &mut filter)
                            };
                            let mut messages = vec![NetworkMessage::MerkleBlock(payload)];
                            for (i, txid) in matched {
                                if !tx_relay.peer_knows(peer_id, &txid) {
                                    messages
                                        .push(NetworkMessage::Tx(block.transactions[i].clone()));
                                }
                            }
                            messages
                        };
                        // A full queue keeps the item for the next pass; the
                        // transactions after a merkleblock follow it at once,
                        // as divid pushes them together
                        let mut messages = messages.into_iter();
                        if let Some(first) = messages.next() {
                            match peer_manager.try_send_to_peer(peer_id, first) {
                                TrySend::Sent => {}
                                TrySend::Full => break,
                                TrySend::Gone => return queue.clear(),
                            }
                        }
                        for msg in messages {
                            if let TrySend::Gone = peer_manager.try_send_to_peer(peer_id, msg) {
                                return queue.clear();
                            }
                        }
                        tracing::debug!("Served block {} to peer {} (getdata)", item.hash, peer_id);
                        if hash_continue.get(&peer_id) == Some(&item.hash) {
                            hash_continue.remove(&peer_id);
                            if let Some(tip) = chain.tip() {
                                let inv = NetworkMessage::Inv(vec![divi_network::InvItem::new(
                                    divi_network::InvType::Block,
                                    tip.hash,
                                )]);
                                let _ = peer_manager.try_send_to_peer(peer_id, inv);
                            }
                        }
                    }
                    Ok(None) => tracing::debug!(
                        "Block {} not found for getdata from peer {}",
                        item.hash,
                        peer_id
                    ),
                    Err(e) => tracing::warn!(
                        "Error looking up block {} for peer {}: {}",
                        item.hash,
                        peer_id,
                        e
                    ),
                }
                queue.pop_front();
                // The pass's notfound goes out after the block
                if !not_found.is_empty() {
                    let msg = NetworkMessage::NotFound(std::mem::take(&mut not_found));
                    let _ = peer_manager.try_send_to_peer(peer_id, msg);
                }
            }
            divi_network::InvType::Tx => {
                match tx_relay
                    .relayed_tx(&item.hash)
                    .or_else(|| mempool.get(&item.hash).map(|e| e.tx))
                {
                    Some(tx) => {
                        match peer_manager.try_send_to_peer(peer_id, NetworkMessage::Tx(tx)) {
                            TrySend::Sent => {}
                            TrySend::Full => break,
                            TrySend::Gone => return queue.clear(),
                        }
                    }
                    None => not_found.push(item),
                }
                queue.pop_front();
            }
            divi_network::InvType::Spork
            | divi_network::InvType::MasternodeAnnounce
            | divi_network::InvType::MasternodePing
            | divi_network::InvType::MasternodeWinner => {
                let hash = item.hash.as_bytes();
                let held = match item.inv_type {
                    divi_network::InvType::Spork => spork_manager
                        .spork_by_hash(&item.hash)
                        .map(NetworkMessage::Spork),
                    divi_network::InvType::MasternodeAnnounce => masternode_list
                        .seen_broadcast(hash)
                        .map(NetworkMessage::MasternodeBroadcast),
                    divi_network::InvType::MasternodePing => masternode_list
                        .seen_ping(hash)
                        .map(NetworkMessage::MasternodePing),
                    _ => masternode_votes
                        .winner_bytes(hash)
                        .map(NetworkMessage::MasternodeWinner),
                };
                match held {
                    Some(msg) => match peer_manager.try_send_to_peer(peer_id, msg) {
                        TrySend::Sent => {}
                        TrySend::Full => break,
                        TrySend::Gone => return queue.clear(),
                    },
                    None => not_found.push(item),
                }
                queue.pop_front();
            }
            // A type outside 1..15 is not known and gets nothing (main.cpp:321,
            // protocol.cpp:146-149)
            divi_network::InvType::Unknown => {
                queue.pop_front();
            }
            // The other known types: Divi Core holds nothing to send for them,
            // neither in its relay map nor in PushKnownInventory, so they are
            // not found (main.cpp:168-211, :321-327, net.cpp:1565-1575)
            _ => {
                not_found.push(item);
                queue.pop_front();
            }
        }
    }
    if !not_found.is_empty() {
        let _ = peer_manager.try_send_to_peer(peer_id, NetworkMessage::NotFound(not_found));
    }
}

/// A peer's message the node is handling, marked taken when dropped
struct Taken<'a> {
    peer_manager: &'a PeerManager,
    peer_id: divi_network::PeerId,
    size: u64,
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        self.peer_manager.message_taken(self.peer_id, self.size);
    }
}

/// Node status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    /// Node is starting up
    Starting,
    /// Node is synchronizing with the network
    Syncing,
    /// Node is fully synchronized and running
    Running,
    /// Node is shutting down
    Stopping,
    /// Node is stopped
    Stopped,
}

/// Events emitted by the node
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// Node started
    Started,
    /// Node stopped
    Stopped,
    /// New block accepted
    BlockAccepted(Hash256),
    /// New transaction accepted to mempool
    TransactionAccepted(Hash256),
    /// Peer connected
    PeerConnected(String),
    /// Peer disconnected
    PeerDisconnected(String),
    /// Sync progress update
    SyncProgress { current: u32, total: u32 },
}

/// Full Divi node
pub struct Node {
    /// Node configuration
    config: NodeConfig,

    /// The thread importing bootstrap.dat and -loadblock files, and the flag
    /// that stops it
    import_thread: parking_lot::Mutex<Option<std::thread::JoinHandle<ImportResult>>>,
    /// A -reindex's index builds, carried out first on the import thread
    reindex_plan: parking_lot::Mutex<Option<ReindexPlan>>,
    /// Set by `hold_import`: the import thread waits for `release_import`
    import_held: Arc<std::sync::atomic::AtomicBool>,
    import_stop: Arc<std::sync::atomic::AtomicBool>,

    /// Current status
    status: RwLock<NodeStatus>,

    /// Chain state
    chain: Arc<Chain>,

    /// Transaction mempool
    mempool: Arc<Mempool>,

    /// Fee estimator
    fee_estimator: Arc<FeeEstimator>,

    /// Chain parameters
    chain_params: ChainParams,

    /// P2P peer manager
    peer_manager: Arc<PeerManager>,

    /// Block synchronization manager
    block_sync: Arc<BlockSync>,

    /// Fetches pruned blocks from full-history peers
    history: Arc<crate::history_fetch::HistoryFetcher>,

    /// Transaction relay manager
    tx_relay: Arc<TxRelay>,

    /// Relayed transactions waiting for a parent (Divi Core mapOrphanTransactions)
    orphans: Arc<crate::orphans::OrphanPool>,

    /// Spork synchronization manager
    spork_manager: Arc<SporkManager>,

    /// Masternode manager
    masternode_manager: Arc<MasternodeManager>,

    /// The masternodes the network announced, as Divi Core keeps them
    masternode_list: Arc<divi_rpc::mn_list::MasternodeList>,

    /// The masternodes' payment votes (mnw)
    masternode_votes: Arc<divi_rpc::mn_votes::MasternodeVotes>,

    /// Divi Core's masternode sync and IsBlockchainSynced
    masternode_sync: divi_masternode::mnsync::SharedMasternodeSync,

    /// Event broadcaster
    event_tx: broadcast::Sender<NodeEvent>,

    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,

    /// The loops `start` runs (peer events, sync, relay, peer upkeep):
    /// stopped by `stop` before it flushes, so nothing writes after it
    tasks: parking_lot::Mutex<Vec<tokio::task::JoinHandle<()>>>,

    /// The -upnp port mapping: its stop signal and task, which removes the
    /// mapping once told to stop
    upnp: parking_lot::Mutex<Option<(broadcast::Sender<()>, tokio::task::JoinHandle<()>)>>,
}

/// How long `Node::stop` waits for the node's loops once told to stop
const STOP_TASKS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long stop waits for the peer tasks: past the connect timeout
/// (-timeout, 5 s by default), so a dial under way ends on its own
const PEER_TASKS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Log one shutdown step and how long it took
pub fn shutdown_stage(what: &str, started: std::time::Instant) {
    tracing::info!("Shutdown: {} in {} ms", what, started.elapsed().as_millis());
}

/// Abort `tasks` and wait for them, for `timeout` in all; how many did not
/// finish (a task stops at its next await, so one inside a blocking call
/// keeps running until the call returns)
async fn stop_tasks(
    tasks: Vec<tokio::task::JoinHandle<()>>,
    timeout: std::time::Duration,
) -> usize {
    for task in &tasks {
        task.abort();
    }
    let deadline = tokio::time::Instant::now() + timeout;
    let mut stalled = 0;
    for task in tasks {
        if tokio::time::timeout_at(deadline, task).await.is_err() {
            stalled += 1;
        }
    }
    stalled
}

/// Chain database metadata present while a -reindex is under way (Divi Core's
/// DB_REINDEXINGFLAG, txdb.cpp:192-204)
const REINDEXING_KEY: &[u8] = b"reindexing";

/// What a -reindex has left to do once the node runs: fill in the indexes
/// `Node::new` cleared and attached, then store their flags and erase the
/// reindexing mark. Divi Core reindexes in its import thread, after init has
/// loaded the wallet and while RPC answers (init.cpp:686-690, :1580, :1639).
struct ReindexPlan {
    db: Arc<ChainDatabase>,
    tx_index: Option<Arc<divi_storage::TxIndex>>,
    search: Option<Arc<divi_storage::SearchIndex>>,
    /// The height when the indexes were attached: the blocks above it wrote
    /// their own address and spent entries as they connected
    height: u32,
    flags: divi_storage::search_index::IndexFlags,
}

impl ReindexPlan {
    /// Carry the reindex out on the import thread; false if `stop` ended it
    /// first, which leaves the reindexing mark for the next start
    fn carry_out(self, chain: &Chain, stop: &std::sync::atomic::AtomicBool) -> bool {
        let stopped = || {
            tracing::info!("The -reindex was stopped; it is carried out again at the next start");
            false
        };
        if let Some(tx_index) = &self.tx_index {
            tracing::info!("Building the transaction index from the stored blocks");
            let started = std::time::Instant::now();
            match chain.build_tx_index(tx_index, stop) {
                Ok(Some(blocks)) => tracing::info!(
                    "Transaction index built for {} blocks in {} ms",
                    blocks,
                    started.elapsed().as_millis()
                ),
                Ok(None) => return stopped(),
                Err(e) => {
                    tracing::error!("Failed to build the transaction index: {}", e);
                    return true;
                }
            }
        }
        if let Some(search) = &self.search {
            tracing::info!("Building the address and spent indexes from the stored blocks");
            let started = std::time::Instant::now();
            match chain.build_search_index(search, self.height, stop) {
                Ok(Some(blocks)) => tracing::info!(
                    "Address and spent indexes built for {} blocks in {} ms",
                    blocks,
                    started.elapsed().as_millis()
                ),
                Ok(None) => return stopped(),
                Err(e) => {
                    tracing::error!("Failed to build the address and spent indexes: {}", e);
                    return true;
                }
            }
        }
        // The flags change only once the indexes they name are complete
        if let Err(e) = self.flags.store(&self.db) {
            tracing::error!("Could not store the index settings: {}", e);
            return true;
        }
        if let Err(e) = self.db.delete_metadata(REINDEXING_KEY) {
            tracing::error!("Could not record the end of the -reindex: {}", e);
            return true;
        }
        // divid's line once its -reindex is done (init.cpp:681)
        tracing::info!("Reindexing finished");
        true
    }
}

impl Node {
    /// Create a new node with the given configuration
    pub fn new(config: NodeConfig) -> Result<Self, NodeError> {
        // Determine chain parameters based on network type
        let storage_network_type = match config.network.network_type {
            crate::config::NetworkType::Mainnet => StorageNetworkType::Mainnet,
            crate::config::NetworkType::Testnet => StorageNetworkType::Testnet,
            crate::config::NetworkType::Regtest => StorageNetworkType::Regtest,
        };
        let mut chain_params =
            ChainParams::for_network(storage_network_type, config.network.chain_mode);
        chain_params.max_reorg_arg = config.max_reorg;

        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| NodeError::Init(format!("Failed to create data directory: {}", e)))?;
        if config.resync {
            clear_folders_for_resync(&config);
        }

        // Initialize database, optionally with UTXO cache
        let db = Arc::new(if let Some(block_cache) = config.block_cache_size {
            // -dbcache: divid's split of it (init.cpp:1046-1056)
            tracing::info!(
                "Cache configuration: block cache {} MiB, UTXO cache {} entries",
                block_cache >> 20,
                config.utxo_cache_size
            );
            ChainDatabase::open_with_caches(
                config.chainstate_path(),
                block_cache,
                config.utxo_cache_size,
            )
            .map_err(|e| NodeError::Init(format!("Failed to open chain database: {}", e)))?
        } else if config.utxo_cache_size > 0 {
            tracing::info!("UTXO cache enabled: {} entries", config.utxo_cache_size);
            ChainDatabase::open_with_utxo_cache(config.chainstate_path(), config.utxo_cache_size)
                .map_err(|e| NodeError::Init(format!("Failed to open chain database: {}", e)))?
        } else {
            tracing::info!("UTXO cache disabled (direct RocksDB reads)");
            ChainDatabase::open(config.chainstate_path())
                .map_err(|e| NodeError::Init(format!("Failed to open chain database: {}", e)))?
        });

        // Initialize chain state
        let damaged = |e: divi_storage::StorageError| {
            // Not damage: the database belongs to another network
            if let divi_storage::StorageError::WrongNetwork(_) = e {
                return NodeError::Init(format!(
                    "Chain database {}: {}",
                    config.chainstate_path().display(),
                    e
                ));
            }
            NodeError::Init(format!(
                "Chain database {} cannot be used: {}. Stopping instead of building on it. \
                 To recover, stop irondivid, move that directory aside and start again to \
                 resync (or use --import-snapshot).",
                config.chainstate_path().display(),
                e
            ))
        };
        let mut chain = Chain::new(db.clone(), chain_params.clone()).map_err(damaged)?;

        // C++ checks the newest blocks at every start (-checkblocks); a damaged
        // database otherwise goes unnoticed until the bad record is read.
        let started = std::time::Instant::now();
        // A failed check stops the start with Divi Core's InitError text
        // (init.cpp:1116-1119) on the first line; what was found, and how to
        // recover, after it and in the log
        let checked = chain
            .verify_db(i64::from(config.check_blocks))
            .map_err(|e| {
                tracing::error!("VerifyDB() : *** {}", e);
                match damaged(e) {
                    NodeError::Init(detail) => {
                        NodeError::Init(format!("Corrupted block database detected\n{detail}"))
                    }
                    other => other,
                }
            })?;
        tracing::info!(
            "Verified the last {} blocks in {} ms",
            checked,
            started.elapsed().as_millis()
        );

        // Divi Core keeps the index flags with the chain database: a changed
        // -txindex refuses to start, and -addressindex/-spentindex take effect
        // only on a new chain database or with -reindex, which builds every
        // index again (init.cpp:1103-1106, txdb.cpp:498-523,
        // ChainExtensionService.cpp:703-707)
        // As Divi Core, a -reindex is recorded in the chain database before it
        // starts and erased only once it is done, so one that was stopped
        // (kill, power loss) is carried out again at the next start
        // (init.cpp:1072-1073, :679; BlockIndexLoading.cpp:287-290;
        // txdb.cpp:192-204)
        let interrupted = db.get_metadata(REINDEXING_KEY).map_err(damaged)?.is_some();
        if interrupted && !config.index.reindex {
            tracing::warn!(
                "A -reindex was stopped before it finished; the indexes are built again now"
            );
        }
        let reindex = config.index.reindex || interrupted;
        if reindex {
            db.put_metadata_synced(REINDEXING_KEY, b"1")
                .map_err(damaged)?;
        }
        let requested = divi_storage::search_index::IndexFlags {
            txindex: config.index.txindex,
            addressindex: config.index.addressindex,
            spentindex: config.index.spentindex,
        };
        // A database with blocks but no stored flags (made before they were
        // kept, or installed from a snapshot) has a transaction index of
        // unknown extent. Divi Core always has the flags (written at genesis),
        // so its "txindex on" means every block is indexed: here the flag is
        // first stored as off, and set on only once the index is known to
        // cover the chain.
        let unflagged = chain.height() > 0
            && divi_storage::search_index::IndexFlags::load(&db)
                .map_err(damaged)?
                .is_none();
        let snapshot_base = chain.snapshot_base().map(|(height, _)| height);
        // A -reindex clears the indexes here and fills them in on the import
        // thread once the node runs, as Divi Core reindexes in its import
        // thread (init.cpp:686-690, :1580). A snapshot database cannot be
        // reindexed in full: its refusal comes here, before the start.
        let defer = reindex && snapshot_base.is_none();
        let mut plan_tx_index = None;
        let mut plan_search = None;
        let mut flags = divi_storage::search_index::IndexFlags::load_or_init(
            &db,
            chain.height(),
            divi_storage::search_index::IndexFlags {
                txindex: requested.txindex && !unflagged,
                ..requested
            },
        )
        .map_err(damaged)?;
        let mut check_unflagged_index = false;
        // The address and spent indexes of such a database are stored as off
        // (load_or_init); asked for, they are built from the blocks below
        let mut build_unflagged_search = false;
        if unflagged && (requested.addressindex || requested.spentindex) {
            match snapshot_base {
                Some(base) => tracing::warn!(
                    "This chain database was installed from a snapshot and has no blocks \
                     below height {}, so it cannot have full address and spent indexes: \
                     they are off",
                    base
                ),
                None => {
                    flags.addressindex = requested.addressindex;
                    flags.spentindex = requested.spentindex;
                    build_unflagged_search = true;
                }
            }
        }
        if unflagged && requested.txindex {
            match snapshot_base {
                Some(base) => tracing::warn!(
                    "This chain database was installed from a snapshot and has no blocks \
                     below height {}, so it cannot have a full transaction index: the \
                     transaction index is off",
                    base
                ),
                None => {
                    flags.txindex = true;
                    check_unflagged_index = true;
                }
            }
        }
        // -reindex builds the transaction index again with the -txindex now
        // given, as Divi Core's -reindex writes the flags anew
        // (ChainExtensionService.cpp:703-707). Here the index is built from
        // the stored blocks; the chain state is kept.
        let rebuild_tx_index = reindex && requested.txindex;
        if reindex && flags.txindex != requested.txindex {
            flags.txindex = requested.txindex;
        }
        // and the address and spent indexes with the options now given
        if reindex {
            flags.addressindex = requested.addressindex;
            flags.spentindex = requested.spentindex;
        }
        // A snapshot database cannot build a full index; it runs without one
        if snapshot_base.is_some() && !flags.txindex && requested.txindex {
            if !unflagged {
                tracing::warn!(
                    "Transaction index off: this chain database was installed from a \
                     snapshot and has no blocks below height {}",
                    snapshot_base.unwrap_or_default()
                );
            }
        } else if flags.txindex != requested.txindex {
            return Err(NodeError::Init(
                "You need to rebuild the database using -reindex to change -txindex".into(),
            ));
        }
        if requested.addressindex != flags.addressindex || requested.spentindex != flags.spentindex
        {
            tracing::warn!(
                "Address index {} and spent index {} as kept by this chain database; \
                 -addressindex and -spentindex apply only to a new one",
                if flags.addressindex { "on" } else { "off" },
                if flags.spentindex { "on" } else { "off" },
            );
        }

        let txindex_path = config.data_dir.join("txindex");
        if reindex && txindex_path.exists() {
            // Entries of an earlier index may name blocks no longer active
            std::fs::remove_dir_all(&txindex_path).map_err(|e| {
                NodeError::Init(format!(
                    "Failed to remove the old transaction index {:?}: {}",
                    txindex_path, e
                ))
            })?;
        }
        if flags.txindex {
            let tx_index = divi_storage::TxIndex::open(&txindex_path).map_err(|e| {
                tracing::error!("Failed to open transaction index: {}", e);
                NodeError::Init(format!("Failed to open transaction index: {}", e))
            })?;
            let tx_index = Arc::new(tx_index);
            if defer {
                chain.attach_tx_index(Arc::clone(&tx_index));
                plan_tx_index = Some(tx_index);
            } else {
                let build = rebuild_tx_index
                    || (check_unflagged_index
                        && !chain
                            .tx_index_covers_chain(&tx_index, 16)
                            .map_err(damaged)?);
                if check_unflagged_index && !rebuild_tx_index {
                    tracing::info!(
                        "No index settings were stored with this chain database; {}",
                        if build {
                            "the transaction index does not cover it and is built now"
                        } else {
                            "the transaction index covers it"
                        }
                    );
                }
                if build {
                    tracing::info!("Building the transaction index from the stored blocks");
                    let started = std::time::Instant::now();
                    let blocks = chain.rebuild_tx_index(tx_index).map_err(|e| {
                        NodeError::Init(format!("Failed to build the transaction index: {}", e))
                    })?;
                    tracing::info!(
                        "Transaction index built for {} blocks in {} ms",
                        blocks,
                        started.elapsed().as_millis()
                    );
                } else {
                    chain.enable_tx_index(tx_index);
                }
            }
            tracing::info!("Transaction index enabled at {:?}", txindex_path);
        }
        let build_search = reindex || build_unflagged_search;
        if build_search && !(flags.addressindex || flags.spentindex) {
            // Switched off: remove the entries an earlier index left
            divi_storage::SearchIndex::new(db.clone(), false, false)
                .clear()
                .map_err(damaged)?;
        }
        if flags.addressindex || flags.spentindex {
            let search = Arc::new(divi_storage::SearchIndex::new(
                db.clone(),
                flags.addressindex,
                flags.spentindex,
            ));
            if defer {
                search.clear().map_err(damaged)?;
                chain.enable_search_index(Arc::clone(&search));
                plan_search = Some(search);
            } else if build_search {
                tracing::info!("Building the address and spent indexes from the stored blocks");
                let started = std::time::Instant::now();
                match chain.rebuild_search_index(search) {
                    Ok(blocks) => tracing::info!(
                        "Address and spent indexes built for {} blocks in {} ms",
                        blocks,
                        started.elapsed().as_millis()
                    ),
                    Err(e) if reindex => {
                        return Err(NodeError::Init(format!(
                            "Failed to build the address and spent indexes: {}",
                            e
                        )))
                    }
                    Err(e) => {
                        tracing::warn!(
                            "No index settings were stored with this chain database and the \
                             address and spent indexes cannot be built ({}): they are off",
                            e
                        );
                        flags.addressindex = false;
                        flags.spentindex = false;
                    }
                }
            } else {
                chain.enable_search_index(search);
            }
            tracing::info!(
                "Address index {}, spent index {}",
                if flags.addressindex { "on" } else { "off" },
                if flags.spentindex { "on" } else { "off" },
            );
        }

        // The flags change only once the indexes they name are complete
        let reindex_plan = defer.then(|| ReindexPlan {
            db: db.clone(),
            tx_index: plan_tx_index,
            search: plan_search,
            height: chain.height(),
            flags,
        });
        if !defer && (reindex || check_unflagged_index || build_unflagged_search) {
            flags.store(&db).map_err(damaged)?;
        }
        if reindex && !defer {
            db.delete_metadata(REINDEXING_KEY).map_err(damaged)?;
            // divid's line once its -reindex is done (init.cpp:681)
            tracing::info!("Reindexing finished");
        }

        // Divi Core notes an unclean stop at start and brings the chain to the
        // best block it knows; here every chain write is whole, so what is left
        // is a reorganization the stop interrupted
        if !chain.begin_run().map_err(damaged)? {
            tracing::warn!("irondivid did not stop cleanly last time");
        }
        if chain.finish_interrupted_reorg().map_err(damaged)? {
            tracing::info!(
                "Finished the interrupted reorganization; tip {} at height {}",
                chain.tip().map(|t| t.hash.to_string()).unwrap_or_default(),
                chain.height()
            );
        }

        // Initialize mempool
        let mempool = Arc::new(Mempool::new(config.mempool.clone()));

        // Initialize fee estimator
        let fee_estimator = Arc::new(FeeEstimator::new());

        // Create peer manager based on network type
        let peer_sources = config.peer_sources();
        if !config.p2p.connect.is_empty() {
            tracing::info!(
                "connect-only: peers={:?}, dns seeds off, listen={}",
                peer_sources.static_peers,
                peer_sources.listen
            );
        }
        let proxy = config
            .p2p
            .proxy_addr()
            .map_err(NodeError::Init)?
            .map(|addr| divi_network::socks5::Proxy {
                addr,
                randomize_credentials: config.p2p.proxy_randomize,
            });
        if let Some(proxy) = proxy.map(|p| p.addr) {
            tracing::info!("Outbound P2P connections go through SOCKS5 proxy {}", proxy);
        }
        // The onion network: -onion's proxy, else -proxy's; reachable with
        // either, not with -onion=0 (net.cpp:1774-1800)
        let (tor_proxy, tor_reachable) =
            match config.p2p.onion_setting().map_err(NodeError::Init)? {
                crate::config::OnionSetting::Unset => (proxy, proxy.is_some()),
                crate::config::OnionSetting::Off => (proxy, false),
                crate::config::OnionSetting::Proxy(addr) => (
                    Some(divi_network::socks5::Proxy {
                        addr,
                        randomize_credentials: config.p2p.proxy_randomize,
                    }),
                    true,
                ),
            };
        // -timeout for outbound connections
        divi_network::set_connect_timeout_ms(config.p2p.connect_timeout_ms);
        // -connect and -addnode host names that go to the proxy by name
        let mut named_peers: Vec<(String, u16)> = Vec::new();
        let peer_manager_config = PeerManagerConfig {
            max_outbound: config.p2p.max_outbound,
            max_inbound: config.p2p.max_inbound,
            magic: config.network.magic,
            dns_seeds: peer_sources.dns_seeds.clone(),
            static_peers: peer_sources
                .static_peers
                .iter()
                .filter_map(|s| {
                    // First try to parse as SocketAddr (IP:port), then as an
                    // onion name, which no DNS lookup reads
                    if let Ok(addr) = s.parse() {
                        return Some(addr);
                    }
                    if let Some(addr) =
                        divi_network::local::onion_service(s, config.network.default_p2p_port())
                    {
                        return Some(addr);
                    }
                    // A host name: given to the proxy, which resolves it, when
                    // one is set; resolved here only with -dns
                    // (ConnectSocketByName, netbase.cpp:631-660)
                    if proxy.is_some() {
                        named_peers.push(host_and_port(s, config.network.default_p2p_port()));
                        return None;
                    }
                    if !config.p2p.name_lookup {
                        tracing::info!("Peer {} is a host name and -dns=0: not resolved", s);
                        return None;
                    }
                    use std::net::ToSocketAddrs;
                    match s.to_socket_addrs() {
                        Ok(mut addrs) => {
                            let addr = addrs.next();
                            if addr.is_some() {
                                tracing::info!("Resolved peer {} to {:?}", s, addr);
                            }
                            addr
                        }
                        Err(e) => {
                            tracing::warn!("Failed to resolve peer {}: {}", s, e);
                            None
                        }
                    }
                })
                .collect(),
            listen_addr: if peer_sources.listen && config.p2p.listen_on_addr {
                Some(config.p2p.socket_addr())
            } else {
                None
            },
            default_port: config.network.default_p2p_port(),
            proxy,
            tor_proxy,
            tor_reachable,
            named_peers,
            connect_only: !config.p2p.connect.is_empty(),
            whitelist: config
                .p2p
                .whitelist
                .iter()
                .filter_map(|n| divi_network::Subnet::parse(n))
                .collect(),
            white_listen: if peer_sources.listen {
                config.p2p.white_bind.clone()
            } else {
                Vec::new()
            },
            more_listen: if peer_sources.listen {
                config.p2p.more_bind.clone()
            } else {
                Vec::new()
            },
            // A -seednode host name is looked up only with -dns, as a
            // -connect one (ProcessOneShot, net.cpp:1071-1084, dials it by
            // name: ConnectSocketByName, netbase.cpp:631-660)
            seed_nodes: config
                .p2p
                .seednode
                .iter()
                .filter(|s| {
                    let numeric = s.parse::<std::net::SocketAddr>().is_ok()
                        || s.trim_matches(['[', ']'])
                            .parse::<std::net::IpAddr>()
                            .is_ok();
                    if !numeric && proxy.is_none() && !config.p2p.name_lookup {
                        tracing::info!("Peer {} is a host name and -dns=0: not resolved", s);
                        return false;
                    }
                    true
                })
                .cloned()
                .collect(),
            dns_seed: config.p2p.dns_seed.unwrap_or(config.p2p.connect.is_empty()),
            force_dns_seed: config.p2p.force_dns_seed,
        };
        let peer_manager = PeerManager::new(peer_manager_config);
        // The -addnode values are the first added nodes (net.cpp:1218)
        for node in &config.p2p.addnode {
            let addr = node
                .parse::<std::net::SocketAddr>()
                .ok()
                .or_else(|| {
                    node.parse::<std::net::IpAddr>()
                        .ok()
                        .map(|ip| std::net::SocketAddr::new(ip, config.network.default_p2p_port()))
                })
                .or_else(|| {
                    divi_network::local::onion_service(node, config.network.default_p2p_port())
                });
            match addr {
                Some(addr) => {
                    peer_manager.add_node(addr);
                }
                None => {
                    tracing::debug!("-addnode {} is not an address; dialled by name only", node)
                }
            }
        }
        // The addresses learnt before the last stop (Divi Core peers.dat, net.cpp:1431-1438)
        peer_manager.address_book().open(&config.data_dir);
        // Divi Core -banscore / -bantime
        peer_manager.scoring().set_ban_policy(
            config.p2p.ban_score.min(i32::MAX as u32) as i32,
            std::time::Duration::from_secs(config.p2p.ban_time),
        );

        // Create chain Arc for sharing
        let chain = Arc::new(chain);

        // Height locks are checked against the chain tip on every path into the mempool
        let chain_for_mempool = Arc::clone(&chain);
        mempool.set_tip_height_provider(Arc::new(move || chain_for_mempool.height()));

        // Every transaction entering the mempool is checked against the chain:
        // inputs, then scripts, as Divi Core's AcceptToMemoryPool does
        {
            let chain_for_scripts = Arc::clone(&chain);
            mempool.set_validator(Arc::new(
                move |pool: &Mempool, tx: &Transaction, origin: crate::mempool::Origin| {
                    check_mempool_transaction(&chain_for_scripts, pool, tx, origin)
                },
            ));
        }

        // Create block sync manager
        let block_sync = BlockSync::new(Arc::clone(&chain), Arc::clone(&peer_manager));

        // Create transaction relay manager
        let tx_relay = TxRelay::new(Arc::clone(&peer_manager));
        let orphans = Arc::new(crate::orphans::OrphanPool::new());
        {
            let (mempool, orphans) = (Arc::clone(&mempool), Arc::clone(&orphans));
            tx_relay.set_have_check(Arc::new(move |txid| {
                (mempool.contains(txid), orphans.contains(txid))
            }));
        }
        let mempool_for_filters = Arc::clone(&mempool);
        tx_relay.set_tx_source(Arc::new(move |txid| {
            mempool_for_filters.get(txid).map(|entry| entry.tx.clone())
        }));

        // Create spork synchronization manager; sporks are kept in the chain
        // database across restarts, as Divi Core keeps them in its spork database
        let spork_manager = SporkManager::with_chain(
            Arc::clone(&peer_manager),
            Arc::clone(&db),
            chain.consensus_sporks(),
        );

        // A spork 14 entry sets the relay fee and the highest fee the mempool uses
        {
            let (chain, mempool) = (Arc::clone(&chain), Arc::clone(&mempool));
            spork_manager.on_tx_fee_spork(Arc::new(move || {
                if let Some(fee) = chain.tx_fee_spork_at_tip() {
                    mempool.set_spork_fees(fee.min_fee_per_kb as i64, fee.max_fee as i64);
                }
            }));
        }

        // Initialize masternode manager with database persistence
        let masternode_manager = match MasternodeManager::with_db(db.db_arc()) {
            Ok(manager) => {
                let count = manager.count();
                if count > 0 {
                    tracing::info!("Loaded {} masternodes from database", count);
                }
                Arc::new(manager)
            }
            Err(e) => {
                tracing::warn!("Failed to initialize masternode manager with database: {}, using in-memory only", e);
                Arc::new(MasternodeManager::new())
            }
        };

        // The network's masternodes, kept in the datadir as Divi Core keeps
        // mncache.dat, and their payment votes
        let masternode_list = Arc::new(divi_rpc::mn_list::MasternodeList::new());
        masternode_list.set_path(config.data_dir.join("masternodes.list"));
        let masternode_votes = Arc::new(divi_rpc::mn_votes::MasternodeVotes::new());
        // The masternode sync, with the requests kept from the last run
        let masternode_sync = divi_masternode::mnsync::shared(
            divi_primitives::clock::now(),
            chain.network_type() == divi_storage::chain::NetworkType::Mainnet,
        );
        crate::masternode_sync::load(&masternode_sync, &config.data_dir);
        // Votes are checked against the sync's stage (masternode-payments.cpp:241-245, :320)
        masternode_votes.follow_sync(Arc::clone(&masternode_sync));
        // The payment votes of the last run, read when there are masternodes,
        // as LoadMasternodeDataFromDisk does (MasternodeModule.cpp:269-280); a
        // file that is not a votes file of this network stops the start
        if !masternode_list.entries().is_empty() {
            use divi_rpc::mn_votes::{PaymentsFile, PAYMENTS_FILE};
            let path = config.data_dir.join(PAYMENTS_FILE);
            match masternode_votes.load(&path, config.network.magic, chain.height() as i64) {
                PaymentsFile::Loaded(n) => {
                    tracing::info!("Loaded {} masternode payment votes from {}", n, PAYMENTS_FILE)
                }
                PaymentsFile::Missing => {
                    tracing::info!("Missing file {}, will try to recreate", PAYMENTS_FILE)
                }
                PaymentsFile::BadFormat => tracing::warn!(
                    "Error reading {}: Magic is ok but data has invalid format, will try to recreate",
                    PAYMENTS_FILE
                ),
                PaymentsFile::Invalid(why) => {
                    tracing::error!("Error reading {}: {}", PAYMENTS_FILE, why);
                    return Err(NodeError::Init(format!(
                        "Failed to load masternode payments cache from\n{}",
                        config.data_dir.display()
                    )));
                }
            }
        }

        // NOTE: block_connected_callback is set in main.rs where it can include
        // both node-level processing (mempool cleanup, fee estimation) and wallet scanning.
        // Do NOT set it here — main.rs sets a single unified callback.

        // Create event broadcaster
        let (event_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Node {
            config,
            import_thread: parking_lot::Mutex::new(None),
            reindex_plan: parking_lot::Mutex::new(reindex_plan),
            import_held: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            import_stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            status: RwLock::new(NodeStatus::Stopped),
            chain,
            mempool,
            fee_estimator,
            chain_params,
            history: crate::history_fetch::HistoryFetcher::new(Arc::clone(&peer_manager)),
            peer_manager,
            block_sync,
            tx_relay,
            orphans,
            spork_manager,
            masternode_manager,
            masternode_list,
            masternode_votes,
            masternode_sync,
            event_tx,
            shutdown_tx,
            tasks: parking_lot::Mutex::new(Vec::new()),
            upnp: parking_lot::Mutex::new(None),
        })
    }

    /// Keep a loop `start` runs, for `stop`
    fn keep(&self, task: tokio::task::JoinHandle<()>) {
        self.tasks.lock().push(task);
    }

    /// Get node configuration
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Get current node status
    pub fn status(&self) -> NodeStatus {
        *self.status.read()
    }

    /// Get chain state
    pub fn chain(&self) -> &Arc<Chain> {
        &self.chain
    }

    /// Get mempool
    pub fn mempool(&self) -> &Arc<Mempool> {
        &self.mempool
    }

    /// Get the spork manager
    pub fn spork_manager(&self) -> &Arc<SporkManager> {
        &self.spork_manager
    }

    /// Get fee estimator
    pub fn fee_estimator(&self) -> &Arc<FeeEstimator> {
        &self.fee_estimator
    }

    /// Get chain parameters
    pub fn chain_params(&self) -> &ChainParams {
        &self.chain_params
    }

    /// Fetcher for blocks this node has pruned (asks full-history peers, verifies the answer).
    pub fn history_fetcher(&self) -> Arc<crate::history_fetch::HistoryFetcher> {
        Arc::clone(&self.history)
    }

    /// Subscribe to node events
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.event_tx.subscribe()
    }

    /// Get a shutdown signal receiver
    pub fn shutdown_signal(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Start the node
    /// Carry out a -reindex, then import bootstrap.dat and the -loadblock
    /// files, on a thread of their own while the node starts and runs, as
    /// Divi Core does (init.cpp:686-728, :1580); until it is done blocks from
    /// peers are neither asked for nor taken
    pub fn spawn_import(&self) {
        let mut slot = self.import_thread.lock();
        if slot.is_some() {
            return;
        }
        let chain = Arc::clone(&self.chain);
        let stop = Arc::clone(&self.import_stop);
        let bootstrap_dir = self
            .config
            .bootstrap_dir
            .clone()
            .unwrap_or_else(|| self.config.data_dir.clone());
        let load_block = self.config.load_block.clone();
        let magic = self.config.network.magic;
        let reindex = self.reindex_plan.lock().take();
        let held = Arc::clone(&self.import_held);
        chain.set_importing(true);
        let spawned = std::thread::Builder::new()
            .name("divi-loadblk".into())
            .spawn(move || {
                while held.load(std::sync::atomic::Ordering::SeqCst)
                    && !stop.load(std::sync::atomic::Ordering::SeqCst)
                {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                // A stopped reindex ends the thread, as Divi Core's
                // interruption point ends its import thread (init.cpp:575)
                let result = if reindex.is_none_or(|plan| plan.carry_out(&chain, &stop)) {
                    crate::block_import::import_at_start(
                        &chain,
                        &bootstrap_dir,
                        &load_block,
                        magic,
                        &stop,
                    )
                } else {
                    ImportResult::default()
                };
                chain.set_importing(false);
                result
            });
        match spawned {
            Ok(handle) => *slot = Some(handle),
            Err(e) => {
                self.chain.set_importing(false);
                tracing::error!("Could not start the block import: {}", e);
            }
        }
    }

    /// Have the import thread `start` spawns wait, blocks from peers still
    /// refused, until `release_import`: Divi Core starts its import thread
    /// once the wallet is loaded (init.cpp:1580), which irondivid loads after
    /// the node starts
    pub fn hold_import(&self) {
        self.import_held
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Let the import thread go on (see `hold_import`)
    pub fn release_import(&self) {
        self.import_held
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Wait for the block import to finish; None if none was started
    pub fn wait_for_import(&self) -> Option<ImportResult> {
        let handle = self.import_thread.lock().take()?;
        handle.join().ok()
    }

    pub async fn start(&self) -> Result<(), NodeError> {
        let current_status = *self.status.read();
        if current_status != NodeStatus::Stopped {
            return Err(NodeError::AlreadyRunning);
        }
        // As Divi Core, do not start without the listening socket
        self.peer_manager
            .bind_listeners()
            .await
            .map_err(NodeError::Init)?;
        self.spawn_import();

        tracing::info!("Starting Divi node...");
        *self.status.write() = NodeStatus::Starting;

        // Initialize components
        tracing::info!("Chain height: {}", self.chain.height());

        // Set peer manager height
        self.peer_manager.set_height(self.chain.height());
        // An inbound peer is told the active spork count after its version
        let sporks_for_count = Arc::clone(&self.spork_manager);
        self.peer_manager
            .set_spork_count_source(Arc::new(move || sporks_for_count.spork_count() as u32));
        // Version messages name the height at the time they are sent
        let chain_for_height = Arc::clone(&self.chain);
        self.peer_manager
            .set_height_source(Arc::new(move || chain_for_height.height()));

        // A pruning node must not advertise NODE_NETWORK (full history). Key it off the
        // database too, so a node that pruned earlier stays honest if expire is later off.
        let prunes = self.config.expire.is_enabled() || self.chain.prune_height() > 0;
        // NODE_BLOOM while bloom filters are served (Divi Core EnableBloomFilters,
        // net.cpp:1722-1723, NetworkLocalAddressHelpers.cpp:224-227)
        let bloom = if self.config.p2p.peer_bloom_filters {
            divi_network::constants::services::NODE_BLOOM
        } else {
            0
        };
        self.peer_manager
            .set_services(divi_network::constants::advertised_services(prunes) | bloom);
        divi_network::constants::set_protocol_version(self.config.network.protocol_version as i32);
        self.peer_manager
            .set_local_addresses(self.local_addresses());
        divi_network::buffers::set_max_receive_buffer(self.config.p2p.max_receive_buffer);
        divi_network::buffers::set_max_send_buffer(self.config.p2p.max_send_buffer);
        // -listenonion: the Tor controller, for the life of the node
        // (init.cpp:1621-1622)
        if self.config.p2p.listen_onion {
            self.keep(divi_network::torcontrol::spawn(
                divi_network::torcontrol::TorControl {
                    target: self.config.p2p.tor_control.clone(),
                    password: self.config.p2p.tor_password.clone(),
                    private_key_file: self.config.data_dir.join("onion_private_key"),
                    set_onion_proxy: self.config.p2p.onion.as_deref().unwrap_or("").is_empty(),
                },
                Arc::clone(&self.peer_manager),
            ));
        }
        // -upnp: map the listen port until shutdown (net.cpp:1454, :1477)
        if self.config.p2p.upnp {
            let local = self.peer_manager.local_addresses();
            let (stop, shutdown) = broadcast::channel(1);
            let discover = self.config.p2p.discover;
            let task = tokio::spawn(async move {
                let igd = divi_network::upnp::Igd::discover().await;
                let description = format!("DIVI v{}", env!("CARGO_PKG_VERSION"));
                divi_network::upnp::map_port(igd, local, discover, description, shutdown).await;
            });
            *self.upnp.lock() = Some((stop, task));
        }

        // Start peer event handler
        let event_tx = self.event_tx.clone();
        let block_sync = Arc::clone(&self.block_sync);
        let history = Arc::clone(&self.history);
        let tx_relay = Arc::clone(&self.tx_relay);
        let orphans = Arc::clone(&self.orphans);
        let spork_manager = Arc::clone(&self.spork_manager);
        let chain = Arc::clone(&self.chain);
        let mempool = Arc::clone(&self.mempool);
        let masternode_list = Arc::clone(&self.masternode_list);
        let masternode_votes = Arc::clone(&self.masternode_votes);
        let peer_manager = Arc::clone(&self.peer_manager);
        let mut peer_events = self.peer_manager.subscribe();
        // Divi Core checks every masternode once a minute (MasternodeModule.cpp:524-529)
        {
            let list = Arc::clone(&self.masternode_list);
            let chain = Arc::clone(&self.chain);
            let mut shutdown = self.shutdown_tx.subscribe();
            self.keep(tokio::spawn(async move {
                let mut every = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    tokio::select! {
                        _ = every.tick() => list.check_collateral(&chain),
                        _ = shutdown.recv() => break,
                    }
                }
            }));
        }
        // The masternode sync thread: a step a second, the request cache
        // cleared of expired entries and kept on disk once a minute
        // (MasternodeModule.cpp:472-531)
        {
            let sync = Arc::clone(&self.masternode_sync);
            let chain = Arc::clone(&self.chain);
            let peers = Arc::clone(&self.peer_manager);
            let sporks = Arc::clone(&self.spork_manager);
            let data_dir = self.config.data_dir.clone();
            let mut shutdown = self.shutdown_tx.subscribe();
            self.keep(tokio::spawn(async move {
                let mut every = tokio::time::interval(std::time::Duration::from_secs(1));
                let mut last_cleanup = divi_primitives::clock::now();
                loop {
                    tokio::select! {
                        _ = every.tick() => {}
                        _ = shutdown.recv() => break,
                    }
                    let now = divi_primitives::clock::now();
                    if !crate::masternode_sync::tick(&sync, &chain, &peers, &sporks, now).await {
                        continue;
                    }
                    if now >= last_cleanup + 60 {
                        last_cleanup = now;
                        sync.lock().sync.requests.check_and_remove(now);
                        crate::masternode_sync::save(&sync, &data_dir);
                    }
                }
            }));
        }
        let masternode_sync = Arc::clone(&self.masternode_sync);
        // With -alerts=0 an alert message is not read at all (main.cpp:870)
        let alert_key = divi_network::alert::alert_key(&self.config.network.magic)
            .filter(|_| self.config.p2p.alerts);
        let peer_bloom_filters = self.config.p2p.peer_bloom_filters;
        self.keep(tokio::spawn(async move {
            // Per peer: the last hash of a full getblocks answer (Divi Core
            // hashContinue) and the alerts already accepted from it
            let mut hash_continue: HashMap<u64, Hash256> = HashMap::new();
            let mut alerts_known: HashMap<u64, HashSet<[u8; 32]>> = HashMap::new();
            // Masternode broadcasts and pings already asked for (Divi Core's
            // AlreadyHave for MSG_MASTERNODE_ANNOUNCE / _PING)
            let mut masternode_items_asked: HashSet<Hash256> = HashSet::new();
            // Transaction lock requests and votes already asked for
            let mut lock_items_asked: HashSet<Hash256> = HashSet::new();
            // The peers known to have each masternode item: it came from them
            // in an inv, or went to them in one (CNode::setInventoryKnown)
            let mut masternode_items_known: HashMap<[u8; 32], HashSet<u64>> = HashMap::new();
            // Per peer: block getdata not answered yet (its send buffer was
            // full), answered again when a peer's buffer has room, or on the
            // `resume` tick
            let mut pending_getdata: HashMap<u64, std::collections::VecDeque<divi_network::InvItem>> =
                HashMap::new();
            let stores = GetDataStores {
                chain: &chain,
                tx_relay: &tx_relay,
                mempool: &mempool,
                spork_manager: &spork_manager,
                masternode_list: &masternode_list,
                masternode_votes: &masternode_votes,
            };
            let mut resume = tokio::time::interval(std::time::Duration::from_millis(50));
            resume.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                // A message is taken off the queue here; falling behind the
                // queue drops messages, and the loop goes on
                let received = tokio::select! {
                    received = peer_events.recv() => received,
                    _ = divi_network::buffers::send_space().notified(), if !pending_getdata.is_empty() => {
                        pending_getdata.retain(|peer_id, queue| {
                            serve_getdata(&stores, &peer_manager, &mut hash_continue, queue, *peer_id);
                            !queue.is_empty()
                        });
                        continue;
                    }
                    _ = resume.tick(), if !pending_getdata.is_empty() => {
                        pending_getdata.retain(|peer_id, queue| {
                            serve_getdata(&stores, &peer_manager, &mut hash_continue, queue, *peer_id);
                            !queue.is_empty()
                        });
                        continue;
                    }
                };
                let event = match received {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::warn!("Peer messages came faster than they were handled: {} missed", missed);
                        peer_manager.clear_receive_queues();
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                // Taken once handled, at the end of this turn of the loop: until
                // then it counts against the peer's receive limits, and the
                // connection's own answers to later messages wait for it (Divi
                // Core erases a message from vRecvMsg after ProcessMessage,
                // main.cpp:1072-1077)
                let _taken = match &event {
                    PeerEvent::Message { peer_id, size, .. } => Some(Taken {
                        peer_manager: &peer_manager,
                        peer_id: *peer_id,
                        size: *size,
                    }),
                    _ => None,
                };
                match event {
                    PeerEvent::Connected {
                        peer_id,
                        addr,
                        version,
                    } => {
                        tracing::info!(
                            "Peer connected: {}",
                            divi_network::peer_log::peer(peer_id, addr)
                        );
                        let _ = event_tx.send(NodeEvent::PeerConnected(addr.to_string()));

                        // Update sync with peer's height
                        block_sync.update_peer_height(peer_id, version.start_height.max(0) as u32);
                        block_sync
                            .begin_syncing_with_peer(
                                peer_id,
                                divi_network::SyncPeer {
                                    services: version.services,
                                    inbound: peer_manager.is_inbound(peer_id),
                                    whitelisted: peer_manager.is_whitelisted(peer_id),
                                    one_shot: peer_manager.is_one_shot(peer_id),
                                },
                            )
                            .await;

                        peer_manager
                            .gossip()
                            .connected(peer_id, peer_manager.is_one_shot(peer_id));
                        if peer_manager.is_inbound(peer_id) {
                            spork_manager.inbound_peer_connected(peer_id).await;
                        } else {
                            // An outbound peer was asked for addresses with its
                            // verack (main.cpp:438-442), and counts as good
                            // (addrman Good, main.cpp:443)
                            peer_manager.gossip().asked(peer_id);
                            peer_manager.address_book().good(addr);
                        }
                    }
                    PeerEvent::Disconnected { peer_id, reason } => {
                        tracing::warn!("Peer {} disconnected: {}", peer_id, reason);
                        pending_getdata.remove(&peer_id);
                        block_sync.remove_peer(peer_id);
                        // The peers kept waiting while it was there are asked
                        // for blocks now if it was the last one preferred
                        block_sync.ask_peers_to_sync().await;
                        tx_relay.remove_peer(peer_id);
                        // Divi Core FinalizeNode: EraseOrphansFor (NodeState.cpp:41)
                        orphans.erase_for_peer(peer_id);
                        spork_manager.remove_peer(peer_id);
                        hash_continue.remove(&peer_id);
                        alerts_known.remove(&peer_id);
                        peer_manager.gossip().disconnected(peer_id);
                    }
                    PeerEvent::Message {
                        peer_id, message, ..
                    } => {
                        // Log all message types at INFO for debugging sync issues
                        let cmd = message.command();
                        if cmd == "block" || cmd == "notfound" {
                            tracing::info!(
                                "Received P2P message from peer {}: {} (size: {} bytes)",
                                peer_id,
                                cmd,
                                match &message {
                                    NetworkMessage::Block(b) => b.transactions.len() * 200, // rough estimate
                                    _ => 0,
                                }
                            );
                        } else {
                            tracing::debug!("Received P2P message from peer {}: {}", peer_id, cmd);
                        }

                        match message {
                            // Divi Core reads a headers message only with
                            // headers-first syncing, which no network has, so it
                            // never acts on one or answers it (main.cpp:669,
                            // chainparams.cpp:251, :360, :440); nor does any node
                            // send one, as getheaders is answered with an inv
                            NetworkMessage::Headers(headers) => {
                                tracing::debug!(
                                    "headers ({} entries) from peer {} not read",
                                    headers.len(),
                                    peer_id
                                );
                            }
                            NetworkMessage::Block(block) => {
                                if history.deliver(
                                    peer_id,
                                    compute_block_hash(&block.header),
                                    &block,
                                ) {
                                    continue;
                                }
                                tracing::debug!(
                                    "Block message received from peer {}: {} with {} txs",
                                    peer_id,
                                    compute_block_hash(&block.header),
                                    block.transactions.len()
                                );
                                // First try to connect via sync manager
                                block_sync.handle_block(peer_id, block.clone()).await;

                                // Also emit event
                                let hash = compute_block_hash(&block.header);
                                if chain.has_block(&hash).unwrap_or(false) {
                                    let _ = event_tx.send(NodeEvent::BlockAccepted(hash));
                                }
                            }
                            NetworkMessage::Inv(items) => {
                                if items.len() > MAX_INV_SIZE {
                                    peer_manager.report_misbehavior_score(
                                        peer_id,
                                        20,
                                        "Asked for too large an inventory of data items",
                                    );
                                    continue;
                                }
                                // Split into block and tx inv items
                                let block_items: Vec<_> = items
                                    .iter()
                                    .filter(|i| i.inv_type == divi_network::message::InvType::Block)
                                    .cloned()
                                    .collect();
                                let tx_items: Vec<_> = items
                                    .iter()
                                    .filter(|i| i.inv_type == divi_network::message::InvType::Tx)
                                    .cloned()
                                    .collect();

                                if !block_items.is_empty() {
                                    block_sync.handle_inv(peer_id, block_items).await;
                                }
                                if !tx_items.is_empty() {
                                    tx_relay.handle_inv(peer_id, tx_items).await;
                                }
                                // Masternode broadcasts and pings are announced
                                // by inv and fetched with getdata, as divid
                                // relays them (CMasternodeBroadcast::Relay,
                                // CMasternodePing::Relay)
                                if masternode_items_asked.len() > 100_000 {
                                    masternode_items_asked.clear();
                                }
                                // Announced items the node has count for the
                                // sync's list and winner stages (MasternodeIsKnown,
                                // MasternodeWinnerIsKnown, MasternodeModule.cpp:346-370)
                                for i in items.iter() {
                                    use divi_network::message::InvType;
                                    let now = divi_primitives::clock::now();
                                    match i.inv_type {
                                        InvType::MasternodeAnnounce
                                            if masternode_list
                                                .has(divi_rpc::mn_list::INV_BROADCAST, &i.hash.0) =>
                                        {
                                            masternode_sync.lock().sync.record_list_update(i.hash.0, true, now)
                                        }
                                        InvType::MasternodeWinner if masternode_votes.is_known(&i.hash.0) => {
                                            masternode_sync.lock().sync.record_winner_update(i.hash.0, true, now)
                                        }
                                        _ => {}
                                    }
                                }
                                let masternode_items: Vec<_> = items
                                    .iter()
                                    .filter(|i| masternode_inv_kind(i.inv_type).is_some())
                                    .filter(|i| {
                                        masternode_items_known
                                            .entry(*i.hash.as_bytes())
                                            .or_default()
                                            .insert(peer_id);
                                        let kind = masternode_inv_kind(i.inv_type).unwrap();
                                        !masternode_list.has(kind, i.hash.as_bytes())
                                            && !masternode_votes.is_known(i.hash.as_bytes())
                                    })
                                    .filter(|i| masternode_items_asked.insert(i.hash))
                                    .cloned()
                                    .collect();
                                if !masternode_items.is_empty() {
                                    let _ = peer_manager
                                        .send_to_peer(peer_id, NetworkMessage::GetData(masternode_items))
                                        .await;
                                }
                                // Divi Core never has a transaction lock request or
                                // vote (AlreadyHave, main.cpp:143-146), so it asks for
                                // each one announced (AskFor, main.cpp:580-581); what
                                // comes back is not read (main.cpp:963-966)
                                if lock_items_asked.len() > 100_000 {
                                    lock_items_asked.clear();
                                }
                                let lock_items: Vec<_> = items
                                    .iter()
                                    .filter(|i| {
                                        matches!(
                                            i.inv_type,
                                            divi_network::message::InvType::TxLockRequest
                                                | divi_network::message::InvType::TxLockVote
                                        )
                                    })
                                    .filter(|i| lock_items_asked.insert(i.hash))
                                    .cloned()
                                    .collect();
                                if !lock_items.is_empty() {
                                    let _ = peer_manager
                                        .send_to_peer(peer_id, NetworkMessage::GetData(lock_items))
                                        .await;
                                }
                                // Sporks are announced by inv as well
                                spork_manager.handle_inv(peer_id, &items).await;
                            }
                            NetworkMessage::NotFound(items) => {
                                let items: Vec<_> = items
                                    .into_iter()
                                    .filter(|i| !history.not_found(peer_id, i.hash))
                                    .collect();
                                // Fail block requests over to another peer now
                                // instead of after the download timeout
                                block_sync.handle_notfound(peer_id, items).await;
                            }
                            NetworkMessage::Tx(tx) => {
                                tx_relay.handle_tx(peer_id, tx).await;
                            }
                            NetworkMessage::GetData(items) => {
                                if items.len() > MAX_INV_SIZE {
                                    peer_manager.report_misbehavior_score(
                                        peer_id,
                                        20,
                                        "Getdata request too large",
                                    );
                                    continue;
                                }
                                // Queued for the peer, answered in order as its
                                // send buffer allows
                                if !items.is_empty() {
                                    let queue = pending_getdata.entry(peer_id).or_default();
                                    queue.extend(items);
                                    serve_getdata(
                                        &stores,
                                        &peer_manager,
                                        &mut hash_continue,
                                        queue,
                                        peer_id,
                                    );
                                    if queue.is_empty() {
                                        pending_getdata.remove(&peer_id);
                                    }
                                }
                            }
                            // Handle getblocks: respond with inv for blocks after locator.
                            // Divi Core answers getheaders the same way (main.cpp:624):
                            // its headers answer is built only for a "headers" request
                            // with headers-first syncing on, which no network has
                            // (main.cpp:680-702, chainparams.cpp:251, :360, :440)
                            NetworkMessage::GetBlocks(msg) | NetworkMessage::GetHeaders(msg) => {
                                let (inv_items, continue_at) =
                                    getblocks_reply(&chain, &msg, GETBLOCKS_LIMIT);
                                if let Some(hash) = continue_at {
                                    hash_continue.insert(peer_id, hash);
                                }
                                if !inv_items.is_empty() {
                                    let count = inv_items.len();
                                    let inv_msg = NetworkMessage::Inv(inv_items);
                                    if let Err(e) =
                                        peer_manager.send_to_peer(peer_id, inv_msg).await
                                    {
                                        tracing::warn!("Failed to send inv response to getblocks from peer {}: {}", peer_id, e);
                                    } else {
                                        tracing::debug!("Sent {} inv items in response to getblocks from peer {}", count, peer_id);
                                    }
                                }
                            }
                            // Spork messages - required for Divi protocol
                            NetworkMessage::SporkCount(count) => {
                                spork_manager.handle_sporkcount(peer_id, count).await;
                                block_sync.ask_peers_to_sync().await;
                                peer_manager.release_held(peer_id);
                            }
                            NetworkMessage::GetSporks => {
                                spork_manager.handle_getsporks(peer_id).await;
                            }
                            NetworkMessage::Spork(spork) => {
                                spork_manager.handle_spork(peer_id, spork).await;
                                block_sync.ask_peers_to_sync().await;
                                peer_manager.release_held(peer_id);
                            }
                            // Masternode sync messages
                            // A peer's count for what the masternode sync asked
                            NetworkMessage::SyncStatusCount { item_id, count } => {
                                tracing::debug!(
                                    "Sync status count from peer {}: item_id={}, count={}",
                                    peer_id,
                                    item_id,
                                    count
                                );
                                crate::masternode_sync::sync_status_count(
                                    &masternode_sync,
                                    &chain,
                                    peer_manager.peer_addr(peer_id),
                                    item_id,
                                    count,
                                    divi_primitives::clock::now(),
                                );
                            }
                            NetworkMessage::GetSyncStatus => {
                                tracing::debug!("Received govsync request from peer {}", peer_id);
                            }
                            // Masternode P2P messages: a peer's masternode
                            // sync asks for the list and the winners
                            NetworkMessage::RequestMasternodeList(payload) => {
                                crate::masternode_sync::answer_list_request(
                                    &masternode_sync,
                                    &chain,
                                    &masternode_list,
                                    &peer_manager,
                                    peer_id,
                                    &payload,
                                    divi_primitives::clock::now(),
                                )
                                .await;
                            }
                            NetworkMessage::MasternodeWinnersRequest(count) => {
                                crate::masternode_sync::answer_winners_request(
                                    &masternode_sync,
                                    &chain,
                                    &masternode_votes,
                                    &peer_manager,
                                    peer_id,
                                    count,
                                    divi_primitives::clock::now(),
                                )
                                .await;
                            }
                            // Masternode messages are read once the chain is
                            // synced (ProcessMasternodeMessages,
                            // MasternodeModule.cpp:371-382)
                            NetworkMessage::MasternodeBroadcast(_)
                            | NetworkMessage::MasternodePing(_)
                            | NetworkMessage::MasternodeWinner(_)
                                if !crate::masternode_sync::blockchain_synced(
                                    &masternode_sync,
                                    &chain,
                                    divi_primitives::clock::now(),
                                ) =>
                            {
                                tracing::debug!(
                                    "Masternode message from peer {} not read: the chain is not synced",
                                    peer_id
                                );
                            }
                            // Broadcasts and pings in Divi Core's wire format, kept
                            // when they pass its checks (mn_list)
                            NetworkMessage::MasternodeBroadcast(payload) => {
                                // A broadcast seen again or newly taken counts for
                                // the sync's list stage (masternodeman.cpp:416-419, :474)
                                let hash = divi_masternode::cpp_wire::CppBroadcast::decode(&payload)
                                    .ok()
                                    .map(|b| b.hash());
                                let known = hash.is_some_and(|h| {
                                    masternode_list.has(divi_rpc::mn_list::INV_BROADCAST, &h)
                                });
                                let result = masternode_list.accept_broadcast(&chain, &payload);
                                if let (Some(hash), true) = (hash, known || result.is_ok()) {
                                    masternode_sync.lock().sync.record_list_update(
                                        hash,
                                        known,
                                        divi_primitives::clock::now(),
                                    );
                                }
                                match result {
                                    Ok(true) => tracing::info!(
                                        "Masternode entry from peer {} added to the list",
                                        peer_id
                                    ),
                                    Ok(false) => {}
                                    Err(e) => {
                                        tracing::debug!(
                                            "Masternode broadcast from peer {} not taken: {}",
                                            peer_id,
                                            e
                                        );
                                        if e.dos > 0 {
                                            peer_manager.report_misbehavior_score(peer_id, e.dos, e.cause);
                                        }
                                    }
                                }
                                relay_masternode_items(
                                    &peer_manager,
                                    &mut masternode_items_known,
                                    masternode_list.take_relays(),
                                )
                                .await;
                            }
                            NetworkMessage::MasternodePing(payload) => {
                                if let Err(e) = masternode_list.accept_ping(&chain, &payload) {
                                    tracing::debug!(
                                        "Masternode ping from peer {} not taken: {}",
                                        peer_id,
                                        e
                                    );
                                    if e.dos > 0 {
                                        peer_manager.report_misbehavior_score(peer_id, e.dos, e.cause);
                                    }
                                    if let Some(vin) = e.ask {
                                        let _ = peer_manager
                                            .send_to_peer(peer_id, NetworkMessage::RequestMasternodeList(vin))
                                            .await;
                                    }
                                }
                                relay_masternode_items(
                                    &peer_manager,
                                    &mut masternode_items_known,
                                    masternode_list.take_relays(),
                                )
                                .await;
                            }
                            // A payment vote, counted when it passes Divi Core's
                            // checks and then announced, as ProcessMasternodeWinners
                            // relays it (masternode-payments.cpp:250-267)
                            NetworkMessage::MasternodeWinner(payload) => {
                                // A vote seen again or newly taken counts for the
                                // sync's winner stage (masternode-payments.cpp:205-209, :262-265)
                                let hash = divi_masternode::cpp_wire::CppWinner::decode(&payload)
                                    .ok()
                                    .map(|w| w.hash());
                                let known = hash.is_some_and(|h| masternode_votes.is_known(&h));
                                let result = masternode_votes.accept(&chain, &masternode_list, &payload);
                                if let (Some(hash), true) = (hash, known || matches!(result, Ok(true))) {
                                    masternode_sync.lock().sync.record_winner_update(
                                        hash,
                                        true,
                                        divi_primitives::clock::now(),
                                    );
                                }
                                match result {
                                    Ok(true) => {
                                        if let Some(hash) = hash {
                                            relay_masternode_items(
                                                &peer_manager,
                                                &mut masternode_items_known,
                                                vec![(divi_rpc::mn_list::INV_WINNER, hash)],
                                            )
                                            .await;
                                        }
                                    }
                                    Ok(false) => {}
                                    Err(e) => {
                                        tracing::debug!(
                                            "Masternode winner from peer {} not taken: {}",
                                            peer_id,
                                            e
                                        );
                                        if e.dos > 0 {
                                            peer_manager.report_misbehavior_score(peer_id, e.dos, e.cause);
                                        }
                                        if let Some(vin) = e.ask {
                                            let _ = peer_manager
                                                .send_to_peer(
                                                    peer_id,
                                                    NetworkMessage::RequestMasternodeList(vin),
                                                )
                                                .await;
                                        }
                                    }
                                }
                            }
                            // Divi Core reads no transaction from a dstx
                            // (main.cpp:705-718) and checks an empty one, which
                            // fails CheckTransaction (DoS 10,
                            // BlockCheckingHelpers.cpp:101-103) and then bad-tx
                            // (DoS 100, MempoolConsensus.cpp:276-277): a reject
                            // and a score of 110 (main.cpp:803-812)
                            NetworkMessage::Unknown(cmd, _) if cmd == "dstx" => {
                                if let Err(e) =
                                    peer_manager.send_to_peer(peer_id, dstx_reject()).await
                                {
                                    tracing::debug!("Failed to send reject to peer {}: {}", peer_id, e);
                                }
                                peer_manager.report_misbehavior_score(
                                    peer_id,
                                    DSTX_SCORE,
                                    "Transaction from peer rejected by memory pool",
                                );
                            }
                            NetworkMessage::Unknown(cmd, payload) => {
                                // Unknown messages are logged with payload details for debugging
                                tracing::info!(
                                    "Unknown message type '{}' ({} bytes): {:02x?}",
                                    cmd,
                                    payload.len(),
                                    &payload[..std::cmp::min(64, payload.len())]
                                );
                            }
                            NetworkMessage::Addr(addrs) => {
                                // Kept in the address book, as Divi Core's addrman
                                // keeps them, and a short fresh one relayed
                                // (main.cpp:521-558)
                                if addrs.len() > divi_network::gossip::MAX_ADDR_MESSAGE {
                                    peer_manager.report_misbehavior_score(
                                        peer_id,
                                        20,
                                        "Requested too many addresses",
                                    );
                                } else {
                                    // Addresses are dated on the network-adjusted
                                    // clock (main.cpp:536), the day's peers picked
                                    // on the node's own (net.cpp:1508)
                                    let now = divi_primitives::clock::adjusted_now().max(0) as u32;
                                    let day_now = divi_primitives::clock::now().max(0) as u32;
                                    let got = peer_manager.gossip().received(
                                        peer_id,
                                        &addrs,
                                        &peer_manager.connected_peers(),
                                        now,
                                        day_now,
                                    );
                                    if let Some(from) = peer_manager.peer_addr(peer_id) {
                                        peer_manager.address_book().add(&got.keep, from.ip());
                                    }
                                    for (to, relayed) in got.relay {
                                        if let Err(e) = peer_manager
                                            .send_to_peer(to, NetworkMessage::Addr(relayed))
                                            .await
                                        {
                                            tracing::debug!("Failed to relay addr to peer {}: {}", to, e);
                                        }
                                    }
                                    // A -seednode peer goes once it has answered (main.cpp:556-557)
                                    if got.disconnect {
                                        peer_manager.disconnect(peer_id);
                                    }
                                }
                            }
                            // An inbound peer asking for addresses gets a share of
                            // the book it does not have yet, at most 1000
                            // (main.cpp:863-869, :1087-1104)
                            NetworkMessage::GetAddr if peer_manager.is_inbound(peer_id) => {
                                let sample = peer_manager.address_book().sample();
                                let answer = peer_manager.gossip().answer(peer_id, sample);
                                if !answer.is_empty() {
                                    if let Err(e) = peer_manager
                                        .send_to_peer(peer_id, NetworkMessage::Addr(answer))
                                        .await
                                    {
                                        tracing::debug!("Failed to send addr to peer {}: {}", peer_id, e);
                                    }
                                }
                            }
                            // With -peerbloomfilters=0 Divi Core bans a peer that
                            // sends these (main.cpp:892-899)
                            NetworkMessage::FilterLoad(_)
                            | NetworkMessage::FilterAdd(_)
                            | NetworkMessage::FilterClear
                                if !peer_bloom_filters =>
                            {
                                peer_manager.report_misbehavior_score(
                                    peer_id,
                                    100,
                                    "Sent bloom filter msg but they are disabled",
                                );
                            }
                            // filterload, filteradd and filterclear as Divi Core
                            // takes them (main.cpp:900-939)
                            NetworkMessage::FilterLoad(payload) => {
                                let Some(stats) = peer_manager.peer_stats(peer_id) else {
                                    continue;
                                };
                                // A payload that does not read is dropped, as
                                // Core's deserialization throws
                                let Some(mut filter) =
                                    divi_network::bloom::BloomFilter::deserialize(&payload)
                                else {
                                    continue;
                                };
                                if filter.is_within_size_constraints() {
                                    filter.update_empty_full();
                                    stats.bloom.set_filter(filter);
                                } else {
                                    peer_manager.report_misbehavior_score(
                                        peer_id,
                                        100,
                                        "Sent too large a bloom filter message",
                                    );
                                }
                                stats.bloom.set_relay(true);
                            }
                            NetworkMessage::FilterAdd(payload) => {
                                let Some(stats) = peer_manager.peer_stats(peer_id) else {
                                    continue;
                                };
                                let Some(item) = divi_network::bloom::read_bytes(&payload) else {
                                    continue;
                                };
                                // Every peer has a filter from the start (Node.cpp:556),
                                // so Core's "before enabling it" (main.cpp:930) is not met
                                if item.len() > divi_network::bloom::MAX_FILTERADD_SIZE {
                                    peer_manager.report_misbehavior_score(
                                        peer_id,
                                        100,
                                        "Exceeded maximum size of script element to be added to filter",
                                    );
                                } else {
                                    stats.bloom.filter().insert(item);
                                }
                            }
                            NetworkMessage::FilterClear => {
                                if let Some(stats) = peer_manager.peer_stats(peer_id) {
                                    stats
                                        .bloom
                                        .set_filter(divi_network::bloom::BloomFilter::default());
                                    stats.bloom.set_relay(true);
                                }
                            }
                            NetworkMessage::Alert(payload) => {
                                let (Some(key), Ok(alert)) =
                                    (&alert_key, divi_network::alert::Alert::parse(&payload))
                                else {
                                    continue;
                                };
                                let known = alerts_known.entry(peer_id).or_default();
                                if known.contains(&alert.hash()) {
                                    continue;
                                }
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |d| d.as_secs() as i64);
                                if alert.is_acceptable(key, now) {
                                    known.insert(alert.hash());
                                } else {
                                    peer_manager.report_misbehavior_score(
                                        peer_id,
                                        divi_network::alert::BAD_ALERT_SCORE,
                                        "Unable to process alert message",
                                    );
                                }
                            }
                            NetworkMessage::Reject(reject) => {
                                let hash_hex = if reject.data.len() >= 32 {
                                    let mut hash = [0u8; 32];
                                    hash.copy_from_slice(&reject.data[..32]);
                                    Hash256::from_bytes(hash).to_string()
                                } else {
                                    format!("{:02x?}", reject.data)
                                };
                                tracing::warn!(
                                    "Peer {} rejected {}: code={} reason='{}' hash={}",
                                    peer_id,
                                    reject.message,
                                    reject.code,
                                    reject.reason,
                                    hash_hex
                                );
                            }
                            _ => {
                                // Other known messages handled elsewhere
                            }
                        }
                    }
                    // Scores found by the connection itself (handshake, framing)
                    PeerEvent::Misbehavior {
                        peer_id,
                        score,
                        reason,
                    } => {
                        peer_manager.report_misbehavior_score(peer_id, score, &reason);
                    }
                }
            }
        }));

        // Start peer manager (non-blocking for regtest with no peers)
        let peer_manager = Arc::clone(&self.peer_manager);
        self.keep(tokio::spawn(async move {
            if let Err(e) = peer_manager.start().await {
                tracing::error!("Peer manager error: {}", e);
            }
        }));

        // peers.dat every 15 minutes, as Divi Core's dumpaddr thread (net.cpp:83, :1060-1068)
        let book = Arc::clone(self.peer_manager.address_book());
        self.keep(tokio::spawn(async move {
            let mut every = tokio::time::interval(divi_network::addrbook::DUMP_INTERVAL);
            every.tick().await;
            loop {
                every.tick().await;
                if let Err(e) = book.save() {
                    tracing::warn!("Failed to write peers.dat: {}", e);
                }
            }
        }));

        // Spawn peer maintenance loop (reconnects if peers drop)
        let pm_for_maintenance = Arc::clone(&self.peer_manager);
        self.keep(tokio::spawn(async move {
            pm_for_maintenance.run_maintenance().await;
        }));
        // -connect peers are dialled again every few seconds, as Divi Core does
        let pm_for_connect = Arc::clone(&self.peer_manager);
        self.keep(tokio::spawn(async move {
            pm_for_connect.run_connect_loop().await;
        }));

        // Start sync progress tracker
        let sync = Arc::clone(&self.block_sync);
        let event_sender = self.event_tx.clone();
        let mut sync_progress = sync.subscribe();
        self.keep(tokio::spawn(async move {
            while let Ok(progress) = sync_progress.recv().await {
                let _ = event_sender.send(NodeEvent::SyncProgress {
                    current: progress.current_height,
                    total: progress.target_height,
                });
            }
        }));

        // Start sync timeout checker
        let sync_for_timeout = Arc::clone(&self.block_sync);
        self.keep(tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                sync_for_timeout.check_timeouts().await;
            }
        }));

        // Start transaction relay event handler (adds received txs to mempool)
        let tx_relay_for_mempool = Arc::clone(&self.tx_relay);
        let mempool_for_relay = Arc::clone(&self.mempool);
        let event_tx_for_relay = self.event_tx.clone();
        let peers_for_relay = Arc::clone(&self.peer_manager);
        let orphans_for_relay = Arc::clone(&self.orphans);
        let max_orphans = self.config.mempool.max_orphan_txs;
        let mut tx_events = tx_relay_for_mempool.subscribe();
        self.keep(tokio::spawn(async move {
            while let Ok(event) = tx_events.recv().await {
                let result = mempool_for_relay
                    .add_relayed(event.tx.clone(), divi_primitives::amount::Amount::ZERO);
                // The reject goes out before the peer is scored, so a peer
                // the refusal bans still gets it (main.cpp:803-811)
                if let Err(e) = &result {
                    if let Some(msg) = relay_reject(e, &event.txid) {
                        let _ = peers_for_relay.send_to_peer(event.from_peer, msg).await;
                    }
                    score_relayed_refusal(&peers_for_relay, &event, e);
                }
                match result {
                    Ok(txid) => {
                        tracing::debug!("Added relayed tx {} to mempool", txid);
                        // Relayed once the mempool took it, and so is each
                        // orphan it lets in (Divi Core main.cpp:734, :763)
                        tx_relay_for_mempool.keep_relayed(event.tx.clone());
                        tx_relay_for_mempool
                            .relay_accepted(txid, Some(event.from_peer))
                            .await;
                        let _ = event_tx_for_relay.send(NodeEvent::TransactionAccepted(txid));
                        for txid in accept_orphans(
                            &mempool_for_relay,
                            &peers_for_relay,
                            &orphans_for_relay,
                            txid,
                        ) {
                            if let Some(entry) = mempool_for_relay.get(&txid) {
                                tx_relay_for_mempool.keep_relayed(entry.tx);
                            }
                            tx_relay_for_mempool.relay_accepted(txid, None).await;
                            let _ = event_tx_for_relay.send(NodeEvent::TransactionAccepted(txid));
                        }
                    }
                    Err(NodeError::MissingInputs) => {
                        // Kept until a parent comes; at most -maxorphantx
                        // (main.cpp:785-792)
                        orphans_for_relay.add(event.tx.clone(), event.from_peer);
                        let evicted = orphans_for_relay.limit(max_orphans);
                        if evicted > 0 {
                            tracing::debug!("mapOrphan overflow, removed {} tx", evicted);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Rejected relayed tx {}: {}", event.txid, e);
                    }
                }
            }
        }));

        // Rebroadcast some mempool transactions at a random time within 30
        // minutes when the tip has moved since the last time, as Divi Core's
        // SendMessages does (PeriodicallyRebroadcastMempoolTxs, main.cpp:1280-1294)
        let tx_relay_for_rebroadcast = Arc::clone(&self.tx_relay);
        let mempool_for_rebroadcast = Arc::clone(&self.mempool);
        let chain_for_rebroadcast = Arc::clone(&self.chain);
        self.keep(tokio::spawn(async move {
            use crate::rebroadcast::{rebroadcast_candidates, RebroadcastTimer, MAX_WAIT_SECS};
            use rand::Rng;
            let mut timer = RebroadcastTimer::new();
            let mut tip = chain_for_rebroadcast.tip().map(|t| t.hash);
            let mut last_tip_update = 0i64;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let current = chain_for_rebroadcast.tip().map(|t| t.hash);
                if current != tip {
                    tip = current;
                    last_tip_update = now;
                }
                if timer.due(now, last_tip_update, || {
                    rand::thread_rng().gen_range(0..MAX_WAIT_SECS)
                }) {
                    let txids = rebroadcast_candidates(&mempool_for_rebroadcast);
                    if !txids.is_empty() {
                        tracing::info!("Rebroadcasting {} mempool transaction(s)", txids.len());
                        tx_relay_for_rebroadcast.rebroadcast(&txids).await;
                    }
                }
            }
        }));

        // Start transaction relay timeout checker
        let tx_relay_for_timeout = Arc::clone(&self.tx_relay);
        self.keep(tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                tx_relay_for_timeout.check_timeouts().await;
            }
        }));

        // Start block sync (wait for sporks to sync first, as required by Divi protocol)
        let sync_to_start = Arc::clone(&self.block_sync);
        let spork_for_sync = Arc::clone(&self.spork_manager);
        self.keep(tokio::spawn(async move {
            // Wait for initial peer connections
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // Wait for spork sync before starting block sync
            // Divi nodes won't serve blocks until sporks are synced
            let mut attempts = 0;
            while !spork_for_sync.is_synced() && attempts < 60 {
                if attempts == 0 {
                    tracing::info!("Waiting for spork synchronization...");
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                attempts += 1;
            }

            if spork_for_sync.is_synced() {
                tracing::info!(
                    "Sporks synced ({} sporks), starting block sync",
                    spork_for_sync.spork_count()
                );
            } else {
                tracing::warn!("Spork sync timed out, attempting block sync anyway");
            }

            sync_to_start.start().await;
        }));

        // Move to syncing state initially, then running when synced
        *self.status.write() = NodeStatus::Syncing;
        let _ = self.event_tx.send(NodeEvent::Started);

        tracing::info!("Node started successfully");
        Ok(())
    }

    /// Stop the node
    pub async fn stop(&self) -> Result<(), NodeError> {
        let current_status = *self.status.read();
        if current_status == NodeStatus::Stopped {
            return Err(NodeError::NotRunning);
        }

        tracing::info!("Stopping Divi node...");
        *self.status.write() = NodeStatus::Stopping;

        // The network first, as Divi Core's shutdown interrupts and joins its
        // net threads before anything else (divid.cpp:42-53): no peer is
        // accepted, dialled or looked up once stop has begun
        self.peer_manager.stop_network();
        // And waits for them, as its join_all returns only when every net
        // thread has ended: a connection or dial under way is done before the
        // rest of the stop
        let started = std::time::Instant::now();
        let left = self.peer_manager.join_tasks(PEER_TASKS_TIMEOUT).await;
        if !left.is_empty() {
            tracing::warn!(
                "{} peer task(s) had not ended within {} s; not waiting for them: {}",
                left.len(),
                PEER_TASKS_TIMEOUT.as_secs(),
                left.join(", ")
            );
        }
        shutdown_stage("peer tasks ended", started);

        // Stop the block import between two records and wait for it, for a
        // minute at most (a read can block where the flag is not seen)
        let started = std::time::Instant::now();
        self.import_stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let handle = self.import_thread.lock().take();
        if let Some(handle) = handle {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while !handle.is_finished() && std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                tracing::warn!("The block import did not stop within a minute; not waiting for it");
            }
            shutdown_stage("block import stopped", started);
        }

        // Stop the node's own loops (sync, relay, peer upkeep), so no block
        // or transaction is taken and no peer dialled while the state below
        // is written, as Divi Core's StopNode joins its threads before the
        // flush (init.cpp Shutdown)
        // -upnp: remove the port mapping (MapPort(false), net.cpp:1477)
        let upnp = self.upnp.lock().take();
        if let Some((stop, mut task)) = upnp {
            let _ = stop.send(());
            if tokio::time::timeout(std::time::Duration::from_secs(10), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }

        let started = std::time::Instant::now();
        let tasks = std::mem::take(&mut *self.tasks.lock());
        let stalled = stop_tasks(tasks, STOP_TASKS_TIMEOUT).await;
        if stalled > 0 {
            tracing::warn!(
                "{} node task(s) did not stop within {} s; not waiting for them",
                stalled,
                STOP_TASKS_TIMEOUT.as_secs()
            );
        }
        shutdown_stage("node loops stopped", started);

        // netfulfilled.dat once the loops that change it have stopped, as
        // Divi Core's SaveMasternodeDataToDisk follows StopNode
        // (init.cpp:372, :376; MasternodeModule.cpp:284-297)
        let started = std::time::Instant::now();
        crate::masternode_sync::save(&self.masternode_sync, &self.config.data_dir);
        shutdown_stage("netfulfilled.dat written", started);

        // The payment votes beside it, as SaveMasternodeDataToDisk writes
        // mnpayments.dat (MasternodeModule.cpp:284-297)
        let started = std::time::Instant::now();
        let path = self.config.data_dir.join(divi_rpc::mn_votes::PAYMENTS_FILE);
        match self.masternode_votes.save(&path, self.config.network.magic) {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                "Error reading {}: File format is unknown or invalid, please fix it manually",
                divi_rpc::mn_votes::PAYMENTS_FILE
            ),
            Err(e) => tracing::error!(
                "Failed to write {}: {}",
                divi_rpc::mn_votes::PAYMENTS_FILE,
                e
            ),
        }
        shutdown_stage("mnpayments.dat written", started);

        // The addresses learnt, for the next start (Divi Core DumpAddresses at stop)
        let started = std::time::Instant::now();
        if let Err(e) = self.peer_manager.address_book().save() {
            tracing::error!("Failed to write peers.dat: {}", e);
        }
        shutdown_stage("peers.dat written", started);

        // Persist masternode state before shutdown
        let started = std::time::Instant::now();
        if let Err(e) = self.masternode_manager.save() {
            tracing::error!("Failed to persist masternode state on shutdown: {}", e);
        } else {
            tracing::info!("Masternode state persisted successfully");
        }
        shutdown_stage("masternode state saved", started);

        // Flush UTXO cache to database before shutdown
        let started = std::time::Instant::now();
        match self.chain.flush_utxo_cache() {
            Ok(count) => {
                if count > 0 {
                    tracing::info!("Flushed {} dirty UTXO cache entries to database", count);
                }
            }
            Err(e) => {
                tracing::error!("Failed to flush UTXO cache on shutdown: {}", e);
            }
        }
        shutdown_stage("UTXO cache flushed", started);

        // The connections close last, after the chain state is flushed, as
        // Divi Core's CleanupP2PConnections ends its shutdown (init.cpp:417);
        // peers.dat was written above, while they were open (StopNode,
        // net.cpp:1474-1485)
        let started = std::time::Instant::now();
        self.peer_manager.disconnect_all();
        shutdown_stage("peers disconnected", started);

        // Send shutdown signal
        let _ = self.shutdown_tx.send(());

        // Clean up
        *self.status.write() = NodeStatus::Stopped;
        let _ = self.event_tx.send(NodeEvent::Stopped);

        tracing::info!("Node stopped");
        Ok(())
    }

    /// Accept a new block
    pub fn accept_block(&self, block: Block) -> Result<(), NodeError> {
        let hash = compute_block_hash(&block.header);

        // Validate and add to chain
        let result = self
            .chain
            .accept_block(block.clone())
            .map_err(|e| NodeError::BlockValidation(e.to_string()))?;

        // A block on the active chain confirms its transactions and makes double
        // spends of its inputs unminable; one stored on a side chain does neither
        let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
        let active = self
            .chain
            .get_block_index_by_height(self.chain.height())
            .ok()
            .flatten()
            .is_some_and(|tip| tip.hash == hash);
        if active {
            self.mempool.remove_for_block(&txids);
            self.mempool.remove_conflicts(&block.transactions);
        }
        if let Some(fork_height) = result.reorg_fork_height {
            tracing::info!(
                "Block {} reorganised the chain at height {}",
                hash,
                fork_height
            );
            update_mempool_after_reorg(&self.chain, &self.mempool, result.orphaned_transactions);
        }
        for txid in &txids {
            self.tx_relay.mark_seen(*txid);
        }

        let _ = self.event_tx.send(NodeEvent::BlockAccepted(hash));

        tracing::info!("Accepted block {} at height {}", hash, self.chain.height());
        Ok(())
    }

    /// Validate a transaction against the UTXO set
    ///
    /// Checks:
    /// 1. All inputs exist in the UTXO set (or in mempool for chained transactions)
    /// 2. Input amounts >= output amounts (fee is the difference)
    /// 3. Basic transaction structure validation
    ///
    /// Note: Full signature verification is performed during block connection.
    /// For mempool acceptance, we validate that inputs exist and amounts are correct.
    pub fn validate_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<divi_primitives::amount::Amount, NodeError> {
        use divi_primitives::amount::Amount;

        let txid = tx.txid();

        // Coinbase transactions are not allowed in the mempool
        if tx.is_coinbase() {
            return Err(NodeError::TransactionValidation(
                "Coinbase transactions cannot be in mempool".into(),
            ));
        }

        // Must have at least one input and one output
        if tx.vin.is_empty() {
            return Err(NodeError::TransactionValidation(
                "Transaction has no inputs".into(),
            ));
        }
        if tx.vout.is_empty() {
            return Err(NodeError::TransactionValidation(
                "Transaction has no outputs".into(),
            ));
        }

        // Check for duplicate inputs
        let mut seen_inputs = std::collections::HashSet::new();
        for input in &tx.vin {
            let outpoint = (input.prevout.txid, input.prevout.vout);
            if !seen_inputs.insert(outpoint) {
                return Err(NodeError::TransactionValidation(format!(
                    "Duplicate input: {}:{}",
                    input.prevout.txid, input.prevout.vout
                )));
            }
        }

        // Sum up input values from UTXO set
        let mut total_input = Amount::from_sat(0);
        for input in &tx.vin {
            // First check if the input is in the UTXO set
            match self.chain.get_utxo(&input.prevout) {
                Ok(Some(utxo)) => {
                    // Check coinbase maturity (the chain's nMaturity: mainnet 20,
                    // testnet 1, regtest 20)
                    if utxo.is_coinbase || utxo.is_coinstake {
                        // Spent in the next block, as Core's CheckInputs counts it
                        let spend_height = self.chain.height() + 1;
                        let confirmations = spend_height.saturating_sub(utxo.height);
                        let coinbase_maturity = self.chain.params().coinbase_maturity;
                        if confirmations < coinbase_maturity {
                            return Err(NodeError::TransactionValidation(format!(
                                "Input {}:{} is immature ({} confirmations, need {})",
                                input.prevout.txid,
                                input.prevout.vout,
                                confirmations,
                                coinbase_maturity
                            )));
                        }
                    }
                    total_input += utxo.value;
                }
                Ok(None) => {
                    // Not in UTXO set, check if it's an output of a mempool transaction
                    if let Some(mempool_entry) = self.mempool.get(&input.prevout.txid) {
                        if (input.prevout.vout as usize) < mempool_entry.tx.vout.len() {
                            total_input += mempool_entry.tx.vout[input.prevout.vout as usize].value;
                        } else {
                            return Err(NodeError::MissingInputs);
                        }
                    } else {
                        return Err(NodeError::MissingInputs);
                    }
                }
                Err(e) => {
                    return Err(NodeError::TransactionValidation(format!(
                        "Failed to lookup UTXO {}:{}: {}",
                        input.prevout.txid, input.prevout.vout, e
                    )));
                }
            }
        }

        // Sum up output values
        let mut total_output = Amount::from_sat(0);
        for output in &tx.vout {
            // Check for negative values (should be caught by Amount, but be safe)
            if output.value.as_sat() < 0 {
                return Err(NodeError::rejected(
                    crate::error::reject::INVALID,
                    "bad-txns-vout-negative",
                ));
            }
            total_output += output.value;
        }

        // Input must be >= output (difference is the fee)
        if total_input.as_sat() < total_output.as_sat() {
            return Err(NodeError::rejected(
                crate::error::reject::INVALID,
                "bad-txns-in-belowout",
            ));
        }

        // Calculate and return fee
        let fee = Amount::from_sat(total_input.as_sat() - total_output.as_sat());

        // Check minimum fee (1 satoshi per byte minimum)
        let tx_size = tx.size();
        let min_fee = Amount::from_sat(tx_size as i64);
        if fee.as_sat() < min_fee.as_sat() {
            return Err(NodeError::TransactionValidation(format!(
                "Fee {} is below minimum {} (1 sat/byte for {} bytes)",
                fee.as_sat(),
                min_fee.as_sat(),
                tx_size
            )));
        }

        tracing::debug!(
            "Transaction {} validated: {} inputs, {} outputs, {} fee",
            txid,
            tx.vin.len(),
            tx.vout.len(),
            fee.as_sat()
        );

        Ok(fee)
    }

    /// Calculate transaction fee from UTXO lookups (inputs from the chain or the
    /// mempool, minus outputs). A static helper usable from spawned tasks and
    /// from the RPC submit path.
    pub fn calculate_transaction_fee(
        tx: &Transaction,
        chain: &Arc<Chain>,
        mempool: &Arc<Mempool>,
    ) -> Result<divi_primitives::amount::Amount, NodeError> {
        use divi_primitives::amount::Amount;

        // Sum up input values from UTXO set
        let mut total_input = Amount::from_sat(0);
        for input in &tx.vin {
            match chain.get_utxo(&input.prevout) {
                Ok(Some(utxo)) => {
                    total_input += utxo.value;
                }
                Ok(None) => {
                    // Not in UTXO set, check if it's an output of a mempool transaction
                    if let Some(mempool_entry) = mempool.get(&input.prevout.txid) {
                        if (input.prevout.vout as usize) < mempool_entry.tx.vout.len() {
                            total_input += mempool_entry.tx.vout[input.prevout.vout as usize].value;
                        } else {
                            return Err(NodeError::MissingInputs);
                        }
                    } else {
                        return Err(NodeError::MissingInputs);
                    }
                }
                Err(e) => {
                    return Err(NodeError::TransactionValidation(format!(
                        "Failed to lookup UTXO {}:{}: {}",
                        input.prevout.txid, input.prevout.vout, e
                    )));
                }
            }
        }

        // Sum up output values
        let mut total_output = Amount::from_sat(0);
        for output in &tx.vout {
            if output.value.as_sat() < 0 {
                return Err(NodeError::rejected(
                    crate::error::reject::INVALID,
                    "bad-txns-vout-negative",
                ));
            }
            total_output += output.value;
        }

        // Input must be >= output (difference is the fee)
        if total_input.as_sat() < total_output.as_sat() {
            return Err(NodeError::rejected(
                crate::error::reject::INVALID,
                "bad-txns-in-belowout",
            ));
        }

        Ok(Amount::from_sat(
            total_input.as_sat() - total_output.as_sat(),
        ))
    }

    /// Accept a new transaction into mempool
    pub fn accept_transaction(
        &self,
        tx: Transaction,
        fee: divi_primitives::amount::Amount,
    ) -> Result<Hash256, NodeError> {
        // Validate transaction against UTXO set
        let calculated_fee = self.validate_transaction(&tx)?;

        // Use the calculated fee if provided fee is zero
        let actual_fee = if fee.as_sat() == 0 {
            calculated_fee
        } else {
            fee
        };

        let relayed = tx.clone();
        let txid = self.mempool.add(tx, actual_fee)?;
        let _ = self.event_tx.send(NodeEvent::TransactionAccepted(txid));

        // Mark as seen and announce to peers, and keep it for their getdata
        self.tx_relay.mark_seen(txid);
        self.tx_relay.keep_relayed(relayed);
        let relay = Arc::clone(&self.tx_relay);
        tokio::spawn(async move {
            relay.announce_tx(txid).await;
        });

        tracing::debug!("Accepted transaction {} to mempool", txid);
        Ok(txid)
    }

    /// Get transaction relay manager
    pub fn tx_relay(&self) -> &Arc<TxRelay> {
        &self.tx_relay
    }

    /// Get blockchain info
    pub fn get_blockchain_info(&self) -> BlockchainInfo {
        let tip = self.chain.tip();
        let tip_hash = tip.as_ref().map(|t| t.hash).unwrap_or_else(Hash256::zero);
        let height = self.chain.height();
        let difficulty = tip
            .as_ref()
            .map(|t| bits_to_difficulty(t.bits))
            .unwrap_or(1.0);

        let sync_progress = self.block_sync.progress();
        let sync_state = sync_progress.state;
        let headers = sync_progress.headers_downloaded.max(height);
        let target_height = sync_progress.target_height.max(height);

        let verification_progress = if target_height > 0 {
            height as f64 / target_height as f64
        } else {
            1.0
        };

        let initial_block_download =
            sync_state != SyncState::Synced && target_height > height + 144;

        BlockchainInfo {
            chain: match self.config.network.network_type {
                crate::config::NetworkType::Mainnet => "main".to_string(),
                crate::config::NetworkType::Testnet => "test".to_string(),
                crate::config::NetworkType::Regtest => "regtest".to_string(),
            },
            blocks: height,
            headers,
            best_block_hash: tip_hash.to_string(),
            difficulty,
            verification_progress,
            initial_block_download,
        }
    }

    /// Get network info
    /// The node's own addresses, learned as Divi Core learns them: a routable
    /// bound address (net.cpp:1379-1380), -externalip (net.cpp:1834-1839),
    /// then the interfaces (net.cpp:1385-1425)
    fn local_addresses(&self) -> divi_network::local::LocalAddresses {
        use divi_network::local::{LocalAddresses, LOCAL_BIND, LOCAL_IF, LOCAL_MANUAL};
        let p2p = &self.config.p2p;
        let listen = self.config.peer_sources().listen;
        let local = LocalAddresses::new(listen, p2p.discover, p2p.port);
        // -onlynet first: an address of a left-out network is not ours
        // (AddLocal, NetworkLocalAddressHelpers.cpp:90)
        let only: Vec<_> = p2p
            .only_nets
            .iter()
            .filter_map(|n| divi_network::local::Network::parse(n))
            .collect();
        local.limit_to(&only);
        let bound = p2p
            .listen_addr
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>();
        if let (true, Ok(ip)) = (listen, bound) {
            local.add(std::net::SocketAddr::new(ip, p2p.port), LOCAL_BIND);
        }
        for addr in &p2p.external_ips {
            local.add(*addr, LOCAL_MANUAL);
        }
        for ip in &p2p.interface_ips {
            local.add(std::net::SocketAddr::new(*ip, p2p.port), LOCAL_IF);
        }
        for a in local.list() {
            tracing::info!(
                "Local address {} port {} score {}",
                a.address,
                a.port,
                a.score
            );
        }
        local
    }

    pub fn get_network_info(&self) -> NetworkInfo {
        NetworkInfo {
            version: self.config.network.protocol_version,
            subversion: self.config.p2p.user_agent.clone(),
            protocol_version: self.config.network.protocol_version,
            connections: self.peer_manager.peer_count(),
            networks: vec!["ipv4".to_string(), "ipv6".to_string()],
            relay_fee: self.mempool.min_relay_fee_per_kb() as f64 / 100_000_000.0,
        }
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peer_manager.peer_count()
    }

    /// Get connected peer addresses
    pub fn peer_addresses(&self) -> Vec<SocketAddr> {
        self.peer_manager.peer_addresses()
    }

    /// Get peer manager
    pub fn peer_manager(&self) -> &Arc<PeerManager> {
        &self.peer_manager
    }

    /// Get block sync manager
    pub fn block_sync(&self) -> &Arc<BlockSync> {
        &self.block_sync
    }

    /// Get sync state
    pub fn sync_state(&self) -> SyncState {
        self.block_sync.state()
    }

    /// Get mempool info
    pub fn get_mempool_info(&self) -> MempoolInfo {
        let stats = self.mempool.stats();
        MempoolInfo {
            size: stats.tx_count,
            bytes: stats.total_bytes,
            usage: stats.total_bytes,
            max_size: stats.max_size,
            total_fee: stats.total_fee.as_divi_f64(),
        }
    }

    /// Get masternode manager
    pub fn masternode_manager(&self) -> &Arc<MasternodeManager> {
        &self.masternode_manager
    }

    /// The masternodes the network announced (listmasternodes)
    pub fn masternode_list(&self) -> &Arc<divi_rpc::mn_list::MasternodeList> {
        &self.masternode_list
    }

    /// The masternodes' payment votes (getmasternodewinners)
    pub fn masternode_votes(&self) -> &Arc<divi_rpc::mn_votes::MasternodeVotes> {
        &self.masternode_votes
    }

    /// The masternode sync (mnsync, getstakingstatus)
    pub fn masternode_sync(&self) -> &divi_masternode::mnsync::SharedMasternodeSync {
        &self.masternode_sync
    }
}

/// Blockchain information
#[derive(Debug, Clone)]
pub struct BlockchainInfo {
    /// Chain name
    pub chain: String,
    /// Block height
    pub blocks: u32,
    /// Header height
    pub headers: u32,
    /// Best block hash
    pub best_block_hash: String,
    /// Current difficulty
    pub difficulty: f64,
    /// Verification progress
    pub verification_progress: f64,
    /// Is in initial block download
    pub initial_block_download: bool,
}

/// Network information
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    /// Node version
    pub version: u32,
    /// User agent
    pub subversion: String,
    /// Protocol version
    pub protocol_version: u32,
    /// Number of connections
    pub connections: usize,
    /// Active networks
    pub networks: Vec<String>,
    /// Minimum relay fee
    pub relay_fee: f64,
}

/// Mempool information
#[derive(Debug, Clone)]
pub struct MempoolInfo {
    /// Number of transactions
    pub size: usize,
    /// Total size in bytes
    pub bytes: usize,
    /// Memory usage
    pub usage: usize,
    /// Maximum size
    pub max_size: usize,
    /// Total fees
    pub total_fee: f64,
}

/// A transaction relayed by a peer: offer it to the mempool (which works out
/// its fee). As Divi Core's ProcessMessage, a refusal costs the peer the
/// refusal's misbehaviour score (Core's DoS value: 100 for most invalid
/// transactions, 0 for policy refusals, immature spends and missing inputs);
/// enough of it bans the peer.
pub fn accept_relayed_transaction(
    _chain: &Arc<Chain>,
    mempool: &Arc<Mempool>,
    peers: &PeerManager,
    event: &divi_network::TxRelayEvent,
) -> Result<Hash256, NodeError> {
    let result = mempool.add_relayed(event.tx.clone(), divi_primitives::amount::Amount::ZERO);
    match &result {
        Ok(txid) => tracing::debug!("Added relayed tx {} to mempool", txid),
        Err(e) => score_relayed_refusal(peers, event, e),
    }
    result
}

/// The masternode inv kinds (mn_list's INV_*) of an inv type
fn masternode_inv_kind(inv_type: divi_network::InvType) -> Option<u32> {
    match inv_type {
        divi_network::InvType::MasternodeWinner => Some(divi_rpc::mn_list::INV_WINNER),
        divi_network::InvType::MasternodeAnnounce => Some(divi_rpc::mn_list::INV_BROADCAST),
        divi_network::InvType::MasternodePing => Some(divi_rpc::mn_list::INV_PING),
        _ => None,
    }
}

/// Announce masternode items as RelayInv does: an inv to every peer that does
/// not know the item yet, the peer that sent it included unless it announced
/// it (net.cpp:1617-1624, CNode::PushInventory)
async fn relay_masternode_items(
    peers: &PeerManager,
    known: &mut HashMap<[u8; 32], HashSet<u64>>,
    items: Vec<(u32, [u8; 32])>,
) {
    if known.len() > 100_000 {
        known.clear();
    }
    for (kind, hash) in items {
        let inv_type = match kind {
            divi_rpc::mn_list::INV_WINNER => divi_network::InvType::MasternodeWinner,
            divi_rpc::mn_list::INV_BROADCAST => divi_network::InvType::MasternodeAnnounce,
            _ => divi_network::InvType::MasternodePing,
        };
        let knows = known.entry(hash).or_default();
        for peer in peers.connected_peers() {
            if knows.insert(peer) {
                let inv =
                    NetworkMessage::Inv(vec![divi_network::InvItem::new(inv_type, Hash256(hash))]);
                let _ = peers.send_to_peer(peer, inv).await;
            }
        }
    }
}

/// The misbehaviour score of a refused relayed transaction, charged to the
/// peer that sent it
fn score_relayed_refusal(peers: &PeerManager, event: &divi_network::TxRelayEvent, e: &NodeError) {
    peers.report_misbehavior_score(
        event.from_peer,
        e.misbehaviour_score(),
        &format!("tx {} rejected by the mempool: {}", event.txid, e),
    );
}

/// Divi Core's -resync (ClearFoldersForResync, init.cpp:901-930): the chain's
/// folders are deleted before it is loaded, one by one so a missing one does not
/// stop the rest, and a failure is logged, not fatal. irondivid's chain database
/// holds its blocks, undo data, sporks and the address and spent indexes; the
/// transaction index has its own folder. The wallet, the configuration and the
/// peer and masternode files stay.
fn clear_folders_for_resync(config: &NodeConfig) {
    tracing::info!("Deleting blockchain folders blocks, chainstate and sporks");
    for dir in [
        config.blocks_path(),
        config.chainstate_path(),
        config.data_dir.join("txindex"),
    ] {
        if !dir.exists() {
            continue;
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => tracing::info!("-resync: folder deleted: {}", dir.display()),
            Err(e) => tracing::warn!("Failed to delete blockchain folders {}", e),
        }
    }
}

/// The score a `dstx` costs its sender: Divi Core checks the empty
/// transaction it never read, 10 for CheckTransaction and 100 for bad-tx
/// (BlockCheckingHelpers.cpp:101-103, MempoolConsensus.cpp:276-277)
pub const DSTX_SCORE: u32 = 110;

/// The `reject` Divi Core sends for a `dstx` (main.cpp:803-809): bad-tx, with
/// the hash of the empty transaction, which is all zeros since a transaction
/// that was never read has no hash computed
pub fn dstx_reject() -> divi_network::NetworkMessage {
    divi_network::NetworkMessage::Reject(divi_network::RejectMessage {
        message: "dstx".to_string(),
        code: crate::error::reject::INVALID,
        reason: "bad-tx".to_string(),
        data: vec![0u8; 32],
    })
}

/// The `reject` Divi Core sends the peer that relayed a transaction its
/// mempool refused (main.cpp:803-809): only for a refusal with a reject
/// state, with its code, its reason cut to MAX_REJECT_MESSAGE_LENGTH (111,
/// defaultValues.h:94) and the txid. A missing input (an orphan), a coin a
/// mempool transaction already spends and non-standard inputs leave no
/// reject state (MempoolConsensus.cpp:296-313, :363-364), so no reject.
pub fn relay_reject(e: &NodeError, txid: &Hash256) -> Option<divi_network::NetworkMessage> {
    let (code, reason) = match e {
        NodeError::TxRejected { reason, .. } if reason == "bad-txns-nonstandard-inputs" => {
            return None
        }
        NodeError::TxRejected { code, reason, .. } => (*code, reason.as_str()),
        NodeError::NonFinal => (crate::error::reject::NONSTANDARD, "non-final"),
        _ => return None,
    };
    let mut cut = reason.len().min(111);
    while !reason.is_char_boundary(cut) {
        cut -= 1;
    }
    Some(divi_network::NetworkMessage::Reject(
        divi_network::RejectMessage {
            message: "tx".to_string(),
            code,
            reason: reason[..cut].to_string(),
            data: txid.as_bytes().to_vec(),
        },
    ))
}

/// Divi Core's orphan resolution after `txid` entered the mempool
/// (main.cpp:743-782): each orphan spending from an accepted transaction is
/// offered to the mempool in turn. One accepted joins the work queue; one
/// still missing inputs stays; any other refusal drops it, and a refusal
/// with a misbehaviour score costs the peer that sent it, once. Returns the
/// orphans accepted.
pub fn accept_orphans(
    mempool: &Arc<Mempool>,
    peers: &PeerManager,
    orphans: &crate::orphans::OrphanPool,
    txid: Hash256,
) -> Vec<Hash256> {
    let mut work = vec![txid];
    let mut accepted = Vec::new();
    let mut erase = Vec::new();
    let mut misbehaving = HashSet::new();
    let mut i = 0;
    while i < work.len() {
        for orphan_id in orphans.spending(&work[i]) {
            let Some((tx, from_peer)) = orphans.get(&orphan_id) else {
                continue;
            };
            if misbehaving.contains(&from_peer) {
                continue;
            }
            match mempool.add_relayed(tx, divi_primitives::amount::Amount::ZERO) {
                Ok(_) => {
                    tracing::debug!("   accepted orphan tx {}", orphan_id);
                    work.push(orphan_id);
                    accepted.push(orphan_id);
                    erase.push(orphan_id);
                }
                Err(NodeError::MissingInputs) => {}
                Err(e) => {
                    let score = e.misbehaviour_score();
                    if score > 0 {
                        peers.report_misbehavior_score(
                            from_peer,
                            score,
                            "Invalid orphan transaction required by mempool transaction",
                        );
                        misbehaving.insert(from_peer);
                        tracing::debug!("   invalid orphan tx {}", orphan_id);
                    }
                    tracing::debug!("   removed orphan tx {}", orphan_id);
                    erase.push(orphan_id);
                }
            }
        }
        i += 1;
    }
    for txid in erase {
        orphans.erase(&txid);
    }
    accepted
}

/// Whether a chain coin can be spent by a transaction in the next block: it
/// is unspent and, if a coinbase or coinstake output, mature at that height
/// (Divi Core CheckInputs, UtxoCheckingAndUpdating.cpp:61-78, which the
/// mempool runs with the tip as the spending block's parent).
fn spendable_in_next_block(chain: &Chain, outpoint: &OutPoint) -> Result<bool, NodeError> {
    let next_height = chain.height() + 1;
    let maturity = chain.params().coinbase_maturity;
    Ok(chain
        .get_utxo(outpoint)?
        .is_some_and(|utxo| utxo.is_mature_with(next_height, maturity)))
}

/// Bring the mempool in line with the active chain after a reorganisation.
///
/// Divi Core does this block by block. disconnectTip offers every transaction
/// of a disconnected block to AcceptToMemoryPool, then drops the mempool
/// transactions spending a coinbase or coinstake output that is gone or no
/// longer mature (removeCoinbaseSpends); connectTip removes the transactions
/// each connected block confirms and those conflicting with it
/// (ChainTipManager.cpp:139-141, :175-183). Here the chain has already moved:
/// `disconnected` (parents before children, as `Chain::accept_block` returns
/// them) is offered first, through `Mempool::add_from_disconnected_block`,
/// which works out the fee and applies Core's AcceptToMemoryPool with
/// `fLimitFree` false and the height lock checked at the transaction's block,
/// as disconnectTip does; then every transaction the new chain made
/// unspendable goes, with its descendants.
pub fn update_mempool_after_reorg(
    chain: &Arc<Chain>,
    mempool: &Arc<Mempool>,
    disconnected: Vec<Transaction>,
) {
    let offered = disconnected.len();
    let mut returned = 0;
    for tx in disconnected {
        let txid = tx.txid();
        match mempool.add_from_disconnected_block(tx) {
            Ok(_) => returned += 1,
            Err(e) => tracing::debug!(
                "Transaction {} of a disconnected block not returned to the mempool: {}",
                txid,
                e
            ),
        }
    }
    // A transaction a lower tip makes non-final stays, as in Core: only the
    // staker waits for its lock
    let dropped = mempool
        .remove_unspendable(|outpoint| spendable_in_next_block(chain, outpoint).unwrap_or(true));
    tracing::info!(
        "Reorg: returned {} of {} transaction(s) of disconnected blocks to the mempool, removed {} the new chain spends or lacks",
        returned,
        offered,
        dropped
    );
}

/// A `host[:port]` peer as its host and port, `default_port` when none is
/// given (SplitHostPort)
fn host_and_port(text: &str, default_port: u16) -> (String, u16) {
    match text.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => match port.parse() {
            Ok(port) => (host.to_string(), port),
            Err(_) => (text.to_string(), default_port),
        },
        _ => (text.to_string(), default_port),
    }
}

/// Divi Core `MAX_STANDARD_TX_SIZE` (defaultValues.h:54)
const MAX_STANDARD_TX_SIZE: usize = 100_000;

/// Divi Core `MAX_TX_SIGOPS_CURRENT` (defaultValues.h:61): 40,000 / 5
const MAX_TX_SIGOPS: u32 = 8_000;

/// Divi Core `MempoolConsensus::IsStandardTx` (MempoolConsensus.cpp:29-121): the
/// reason a transaction is not relayed, if it is not. Applies on every network,
/// as `-acceptnonstandard` is off by default. Without `permit_bare_multisig`
/// (`-permitbaremultisig=0`) a bare multisig output is not standard; an OP_META
/// output script is standard up to `max_datacarrier_bytes` (`-datacarriersize`,
/// 603 by default; 0 with `-datacarrier=0`).
pub fn check_standard_tx(
    tx: &Transaction,
    tip_height: u32,
    now: u32,
    relay_fee_per_kb: i64,
    permit_bare_multisig: bool,
    max_datacarrier_bytes: usize,
) -> Result<(), NodeError> {
    use crate::error::reject;
    use divi_script::policy::standard_output_type;
    use divi_script::ScriptType;

    let nonstandard = |reason: &str| Err(NodeError::rejected(reject::NONSTANDARD, reason));
    // CTransaction::CURRENT_VERSION is 1
    if tx.version != 1 {
        return nonstandard("version");
    }
    if !crate::mempool::is_final_for_next_block(tx, tip_height, now) {
        return Err(NodeError::NonFinal);
    }
    if tx.size() >= MAX_STANDARD_TX_SIZE {
        return nonstandard("tx-size");
    }
    for input in &tx.vin {
        if input.script_sig.len() > 1650 {
            return nonstandard("scriptsig-size");
        }
        if !divi_script::is_push_only(input.script_sig.as_bytes()) {
            return nonstandard("scriptsig-not-pushonly");
        }
    }
    let mut data_outputs = 0;
    for out in &tx.vout {
        match standard_output_type(out.script_pubkey.as_bytes(), max_datacarrier_bytes) {
            None => return nonstandard("scriptpubkey"),
            Some(ScriptType::NullData) => data_outputs += 1,
            Some(ScriptType::Multisig) if !permit_bare_multisig => {
                return nonstandard("bare-multisig");
            }
            Some(_) => {
                if out.value < out.min_non_dust_value(relay_fee_per_kb) {
                    return nonstandard("dust");
                }
            }
        }
    }
    // Only one OP_META output
    if data_outputs > 1 {
        return nonstandard("multi-op-meta");
    }
    Ok(())
}

/// Divi Core's `MempoolConsensus::AcceptToMemoryPool` (MempoolConsensus.cpp:268-422)
/// against the chain, in Core's order: CheckTransaction, no coinbase or
/// coinstake, IsStandardTx, no conflict, inputs known and unspent, standard
/// inputs, at most 8,000 sigops, the relay fee or enough priority, then
/// CheckInputs (maturity, input values, value in at least value out) and every
/// input script under the standard flags (and, to pick the reject reason, the
/// mandatory ones). Returns the fee. Each refusal carries Core's reject code,
/// reason and misbehaviour score. `origin` gives Core's `fLimitFree` (true for
/// relayed transactions) and the tip a height lock is checked against.
pub fn check_mempool_transaction(
    chain: &Chain,
    mempool: &Mempool,
    tx: &Transaction,
    origin: crate::mempool::Origin,
) -> Result<crate::mempool::Admission, NodeError> {
    let limit_free = origin.limit_free();
    use crate::error::reject;
    use divi_primitives::amount::Amount;
    use divi_primitives::script::Script;
    use divi_script::{verify_input_with_flags, ScriptFlags};

    let lookup_failed = |e: divi_storage::StorageError| {
        NodeError::TransactionValidation(format!("Failed to look up the chain: {}", e))
    };

    let max_money = chain.max_money();
    // Divi Core's AcceptToMemoryPool records its own 100 on top of what
    // CheckTransaction recorded (CValidationState::DoS adds them up,
    // ValidationState.cpp:41; MempoolConsensus.cpp:276-277): 110 for a
    // transaction without inputs or outputs, 200 for the other failures
    if let Err(e) = divi_storage::check_transaction(tx, max_money) {
        return Err(NodeError::rejected_scored(
            reject::INVALID,
            "bad-tx",
            e.misbehaviour_score() + 100,
        ));
    }
    if tx.is_coinbase() {
        return Err(NodeError::rejected(reject::INVALID, "coinbase"));
    }
    if tx.is_coinstake() {
        return Err(NodeError::rejected(reject::INVALID, "coinstake"));
    }
    let tip_height = chain.height();
    // IsStandardTx reads a time lock on GetAdjustedTime: the node's clock
    // (setmocktime sets it) plus the network time offset
    // (MempoolConsensus.cpp:61, TransactionFinalityHelpers.cpp:16-17)
    let now = divi_primitives::clock::adjusted_now().max(0) as u32;
    // Divi Core checks IsStandardTx and AreInputsStandard only without
    // -acceptnonstandard (MempoolConsensus.cpp:274, :291, :363)
    let require_standard = mempool.requires_standard();
    if require_standard {
        check_standard_tx(
            tx,
            origin.lock_tip(tip_height),
            now,
            mempool.min_relay_fee_per_kb(),
            mempool.permits_bare_multisig(),
            mempool.max_datacarrier_bytes(),
        )?;
    }
    mempool.check_conflicts(tx)?;

    // The transaction's own outputs must not exist yet
    let txid = tx.txid();
    if chain
        .has_spendable_output_of(&txid)
        .map_err(lookup_failed)?
    {
        return Err(NodeError::TransactionValidation(
            "transaction outputs already exist".into(),
        ));
    }

    // Each input: (script, value, height and coinbase/coinstake if confirmed)
    struct Spent {
        script: Script,
        value: Amount,
        confirmed: Option<(u32, bool)>,
    }
    let mut spent: Vec<Spent> = Vec::with_capacity(tx.vin.len());
    let mut any_unknown = false;
    let mut any_spent = false;
    for input in &tx.vin {
        if let Some(utxo) = chain.get_utxo(&input.prevout).map_err(lookup_failed)? {
            spent.push(Spent {
                script: utxo.script_pubkey,
                value: utxo.value,
                confirmed: Some((utxo.height, utxo.is_coinbase || utxo.is_coinstake)),
            });
            continue;
        }
        match mempool.get(&input.prevout.txid) {
            Some(parent) => match parent.tx.vout.get(input.prevout.vout as usize) {
                Some(out) => spent.push(Spent {
                    script: out.script_pubkey.clone(),
                    value: out.value,
                    confirmed: None,
                }),
                None => any_spent = true,
            },
            None => {
                // Core's HaveCoins: the transaction still has unspent outputs,
                // so this one is spent; otherwise it is unknown (an orphan)
                if chain
                    .has_spendable_output_of(&input.prevout.txid)
                    .map_err(lookup_failed)?
                {
                    any_spent = true;
                } else {
                    any_unknown = true;
                }
            }
        }
    }
    if any_unknown {
        return Err(NodeError::MissingInputs);
    }
    if any_spent {
        return Err(NodeError::rejected_scored(
            reject::DUPLICATE,
            "bad-txns-inputs-spent",
            0,
        ));
    }

    // AreInputsStandard: refused without a reject reason in Core
    for (input, prev) in tx.vin.iter().zip(&spent).filter(|_| require_standard) {
        if !divi_script::policy::is_input_standard(
            prev.script.as_bytes(),
            input.script_sig.as_bytes(),
        ) {
            return Err(NodeError::rejected(
                reject::NONSTANDARD,
                "bad-txns-nonstandard-inputs",
            ));
        }
    }

    // GetLegacySigOpCount + GetP2SHSigOpCount
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
    for (input, prev) in tx.vin.iter().zip(&spent) {
        if divi_script::is_p2sh(prev.script.as_bytes()) {
            sig_ops +=
                divi_script::p2sh_sig_op_count(prev.script.as_bytes(), input.script_sig.as_bytes());
        }
    }
    if sig_ops > MAX_TX_SIGOPS {
        return Err(NodeError::rejected(
            reject::NONSTANDARD,
            "bad-txns-too-many-sigops",
        ));
    }

    // Fee (may be negative here; CheckInputs refuses that below) and priority:
    // Core's ComputeInputCoinAge at the tip, then ComputeInputCoinAgePerByte at
    // the next height, which adds the value in once more
    let value_in: i64 = spent.iter().map(|p| p.value.as_sat()).sum();
    let value_out: i64 = tx.vout.iter().map(|o| o.value.as_sat()).sum();
    let fee = value_in.wrapping_sub(value_out);
    let coin_age: f64 = spent
        .iter()
        .filter_map(|p| p.confirmed.map(|(height, _)| (height, p.value)))
        .filter(|(height, _)| *height < tip_height)
        .map(|(height, value)| value.as_sat() as f64 * (tip_height - height) as f64)
        .sum();
    let size = tx.size();
    let mod_size = crate::mempool::modified_size(tx, size);
    let priority = if mod_size > 0 {
        coin_age / mod_size as f64 + value_in as f64 / mod_size as f64
    } else {
        0.0
    };
    mempool.check_fees_paid(&txid, size, fee, priority, limit_free)?;

    // CheckInputs (UtxoCheckingAndUpdating.cpp:66-103)
    let spend_height = tip_height + 1;
    let maturity = chain.params().coinbase_maturity;
    let mut total_in = Amount::ZERO;
    for prev in &spent {
        if let Some((height, true)) = prev.confirmed {
            if spend_height.saturating_sub(height) < maturity {
                return Err(NodeError::rejected_scored(
                    reject::INVALID,
                    "bad-txns-premature-spend-of-coinbase",
                    0,
                ));
            }
        }
        total_in += prev.value;
        if !money_range(prev.value, max_money) || !money_range(total_in, max_money) {
            return Err(NodeError::rejected(
                reject::INVALID,
                "bad-txns-inputvalues-outofrange",
            ));
        }
    }
    if value_in < value_out {
        return Err(NodeError::rejected(reject::INVALID, "bad-txns-in-belowout"));
    }

    for (i, prev) in spent.iter().enumerate() {
        if let Err(e) =
            verify_input_with_flags(tx, i, &prev.script, prev.value, ScriptFlags::policy())
        {
            // As Core's CheckInputs: if the mandatory flags alone pass, only
            // policy failed
            return Err(
                match verify_input_with_flags(
                    tx,
                    i,
                    &prev.script,
                    prev.value,
                    ScriptFlags::mandatory(),
                ) {
                    Ok(()) => NodeError::rejected(
                        reject::NONSTANDARD,
                        format!("non-mandatory-script-verify-flag ({})", e.core_message()),
                    ),
                    Err(e) => NodeError::rejected(
                        reject::INVALID,
                        format!("mandatory-script-verify-flag-failed ({})", e.core_message()),
                    ),
                },
            );
        }
    }
    Ok(crate::mempool::Admission {
        fee: Amount::from_sat(fee),
        height: tip_height,
        coin_age,
    })
}

fn money_range(
    value: divi_primitives::amount::Amount,
    max_money: divi_primitives::amount::Amount,
) -> bool {
    value >= divi_primitives::amount::Amount::ZERO && value <= max_money
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::ChainMode;
    use tempfile::tempdir;

    fn test_config() -> NodeConfig {
        let temp_dir = tempdir().unwrap();
        let mut config = NodeConfig::testnet(ChainMode::Divi);
        config.data_dir = temp_dir.keep();
        // A port of its own: a node that cannot listen does not start
        config.p2p.listen_addr = "127.0.0.1".into();
        config.p2p.port = 0;
        // No DNS seeding: a test node looks nothing up and dials no one off
        // the host. The seed lookup and its dials run in tasks of their own,
        // which on a slow resolver kept the peer manager past
        // stop_ends_the_node_loops' deadline
        config.p2p.dns_seed = Some(false);
        config
    }

    /// Write `n` regtest blocks to the node's chain database and flush the block bodies
    /// to their own table file; returns the path of that file.
    fn regtest_chain_on_disk(config: &NodeConfig, n: u32) -> std::path::PathBuf {
        use divi_primitives::amount::Amount;
        use divi_primitives::block::Block;
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{Transaction, TxIn, TxOut};
        let db = Arc::new(ChainDatabase::open(config.chainstate_path()).unwrap());
        let chain = Chain::new(
            db.clone(),
            ChainParams::for_network(StorageNetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap();
        let mut parent = chain.tip().unwrap();
        for i in 0..n {
            let mut block = Block::default();
            block.header.version = 4;
            block.header.prev_block = parent.hash;
            block.header.time = parent.time + 60;
            block.header.bits = 0x207fffff;
            block.transactions.push(Transaction {
                version: 1,
                vin: vec![TxIn::coinbase(Script::from_bytes(
                    [
                        divi_storage::bip34_height_script(i + 1),
                        vec![0x01, i as u8],
                    ]
                    .concat(),
                ))],
                vout: vec![TxOut::new(
                    Amount::from_sat(1250_00000000),
                    Script::new_p2pkh(&[i as u8 + 1; 20]),
                )],
                lock_time: 0,
            });
            block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
            // Proof of work for the block's bits
            let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
            while divi_crypto::compute_block_hash(&block.header) > target {
                block.header.nonce += 1;
            }
            chain.accept_block(block).unwrap();
            parent = chain.tip().unwrap();
        }
        assert_eq!(chain.height(), n);
        let raw = db.inner_db();
        for cf in ["blocks", "block_index", "metadata", "undo", "utxo"] {
            raw.flush_cf(&raw.cf_handle(cf).unwrap()).unwrap();
        }
        let file = raw
            .live_files()
            .unwrap()
            .into_iter()
            .find(|f| f.column_family_name == "blocks")
            .expect("block bodies flushed to a table file");
        config
            .chainstate_path()
            .join(file.name.trim_start_matches('/'))
    }

    /// A damaged block table must stop the node at start with a clear error, as C++
    /// -checkblocks does. It used to start and run on (testnet: 8 KB overwritten in a
    /// chainstate file, no error). --checkblocks=0 checks every block, as in C++.
    #[test]
    fn test_damaged_block_data_is_caught_at_start() {
        let dir = tempdir().unwrap();
        let mut config = NodeConfig::regtest(ChainMode::Divi);
        config.data_dir = dir.path().to_path_buf();
        let table = regtest_chain_on_disk(&config, 10);
        drop(Node::new(config.clone()).expect("healthy database starts"));

        // Overwrite bytes inside the first data block (the bodies of all 10 blocks)
        let mut bytes = std::fs::read(&table).unwrap();
        for b in &mut bytes[16..48] {
            *b ^= 0x5a;
        }
        std::fs::write(&table, bytes).unwrap();

        let err = match Node::new(config.clone()) {
            Ok(_) => panic!("node started on a damaged chain database"),
            Err(NodeError::Init(reason)) => reason,
            Err(e) => panic!("not a start refusal: {e}"),
        };
        // Divi Core's InitError text first (init.cpp:1116-1119), then the detail
        assert_eq!(
            err.lines().next(),
            Some("Corrupted block database detected"),
            "{err}"
        );
        assert!(err.contains("damaged at height"), "{err}");
        assert!(err.contains("move that directory aside"), "{err}");

        config.check_blocks = 0;
        assert!(Node::new(config).is_err());
    }

    #[test]
    fn test_node_creation() {
        let config = test_config();
        let node = Node::new(config).unwrap();
        assert_eq!(node.status(), NodeStatus::Stopped);
    }

    #[tokio::test]
    async fn test_node_start_stop() {
        let config = test_config();
        let node = Node::new(config).unwrap();

        node.start().await.unwrap();
        // Node starts in Syncing state (transitions to Running when synced)
        assert_eq!(node.status(), NodeStatus::Syncing);

        node.stop().await.unwrap();
        assert_eq!(node.status(), NodeStatus::Stopped);
    }

    /// stop ends the loops start runs: none still holds the node's parts
    #[tokio::test]
    async fn stop_ends_the_node_loops() {
        let node = Node::new(test_config()).unwrap();
        let idle = (
            Arc::strong_count(&node.block_sync),
            Arc::strong_count(&node.tx_relay),
            Arc::strong_count(&node.peer_manager),
        );
        node.start().await.unwrap();
        assert_ne!(Arc::strong_count(&node.block_sync), idle.0);
        node.stop().await.unwrap();
        // An aborted task lets go of what it holds once it has stopped
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let counts = || {
            (
                Arc::strong_count(&node.block_sync),
                Arc::strong_count(&node.tx_relay),
                Arc::strong_count(&node.peer_manager),
            )
        };
        while counts() != idle && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(counts(), idle, "loops still running after stop");
    }

    /// A task inside a blocking call cannot be stopped; stop_tasks gives up on
    /// it after its timeout
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_tasks_gives_up_after_the_timeout() {
        let waiting = tokio::spawn(std::future::pending::<()>());
        let blocked = tokio::spawn(async {
            std::thread::sleep(std::time::Duration::from_secs(3));
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let started = std::time::Instant::now();
        let stalled = stop_tasks(
            vec![waiting, blocked],
            std::time::Duration::from_millis(200),
        )
        .await;
        assert_eq!(stalled, 1);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[tokio::test]
    async fn test_double_start() {
        let config = test_config();
        let node = Node::new(config).unwrap();

        node.start().await.unwrap();
        let result = node.start().await;
        assert!(matches!(result, Err(NodeError::AlreadyRunning)));

        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_stop_not_running() {
        let config = test_config();
        let node = Node::new(config).unwrap();

        let result = node.stop().await;
        assert!(matches!(result, Err(NodeError::NotRunning)));
    }

    #[test]
    fn test_blockchain_info() {
        let config = test_config();
        let node = Node::new(config).unwrap();

        let info = node.get_blockchain_info();
        assert_eq!(info.chain, "test");
        assert_eq!(info.blocks, 0);
    }

    /// As Divi Core ("Unable to bind to ... on this computer", net.cpp:1355-1365;
    /// "Failed to listen on any port", net.cpp:1829-1831), a node whose P2P
    /// port is taken does not start
    #[tokio::test]
    async fn node_does_not_start_when_its_port_is_taken() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = test_config();
        config.p2p.port = taken.local_addr().unwrap().port();
        let node = Node::new(config).unwrap();
        let err = node.start().await.expect_err("the port is taken");
        let text = err.to_string();
        assert!(text.contains("Unable to bind to 127.0.0.1:"), "{text}");
        assert!(text.contains("Failed to listen on any port"), "{text}");

        // With its own port the same node starts and listens
        let mut config = test_config();
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        config.p2p.port = free.local_addr().unwrap().port();
        drop(free);
        let port = config.p2p.port;
        let node = Node::new(config).unwrap();
        node.start().await.unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            assert!(std::time::Instant::now() < deadline, "listening");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        node.stop().await.ok();
    }

    #[test]
    fn test_network_info() {
        let config = test_config();
        let node = Node::new(config).unwrap();

        let info = node.get_network_info();
        // Divi Core 3.0.0's PROTOCOL_VERSION (version.h:21)
        assert_eq!(info.protocol_version, 70915);
    }

    #[test]
    fn test_mempool_info() {
        let config = test_config();
        let node = Node::new(config).unwrap();

        let info = node.get_mempool_info();
        assert_eq!(info.size, 0);
        assert_eq!(info.bytes, 0);
    }

    #[test]
    fn test_event_subscription() {
        let config = test_config();
        let node = Node::new(config).unwrap();

        let _rx = node.subscribe();
        // Just verify we can create a subscription
    }

    #[test]
    fn test_validate_transaction_no_inputs() {
        use divi_primitives::amount::Amount;
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{Transaction, TxOut};

        let config = test_config();
        let node = Node::new(config).unwrap();

        // Create a transaction with no inputs
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![TxOut::new(Amount::from_sat(1000), Script::new())],
            lock_time: 0,
        };

        let result = node.validate_transaction(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no inputs"));
    }

    #[test]
    fn test_validate_transaction_no_outputs() {
        use divi_primitives::hash::Hash256;
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{OutPoint, Transaction, TxIn};

        let config = test_config();
        let node = Node::new(config).unwrap();

        // Create a transaction with no outputs
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: Hash256::zero(),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
            }],
            vout: vec![],
            lock_time: 0,
        };

        let result = node.validate_transaction(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no outputs"));
    }

    #[test]
    fn test_validate_transaction_coinbase_rejected() {
        use divi_primitives::amount::Amount;
        use divi_primitives::hash::Hash256;
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

        let config = test_config();
        let node = Node::new(config).unwrap();

        // Create a coinbase transaction (input txid is all zeros, vout is 0xffffffff)
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: Hash256::zero(),
                    vout: 0xffffffff,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
            }],
            vout: vec![TxOut::new(Amount::from_sat(1000), Script::new())],
            lock_time: 0,
        };

        let result = node.validate_transaction(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Coinbase"));
    }

    #[test]
    fn test_validate_transaction_duplicate_inputs() {
        use divi_primitives::amount::Amount;
        use divi_primitives::hash::Hash256;
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

        let config = test_config();
        let node = Node::new(config).unwrap();

        let dummy_txid = Hash256::from_bytes([1u8; 32]);

        // Create a transaction with duplicate inputs
        let tx = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: OutPoint {
                        txid: dummy_txid,
                        vout: 0,
                    },
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                },
                TxIn {
                    prevout: OutPoint {
                        txid: dummy_txid,
                        vout: 0,
                    },
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                },
            ],
            vout: vec![TxOut::new(Amount::from_sat(1000), Script::new())],
            lock_time: 0,
        };

        let result = node.validate_transaction(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate input"));
    }

    #[test]
    fn test_validate_transaction_missing_utxo() {
        use divi_primitives::amount::Amount;
        use divi_primitives::hash::Hash256;
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

        let config = test_config();
        let node = Node::new(config).unwrap();

        // Create a transaction spending a non-existent UTXO
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: Hash256::from_bytes([0xab; 32]),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
            }],
            vout: vec![TxOut::new(Amount::from_sat(1000), Script::new())],
            lock_time: 0,
        };

        let result = node.validate_transaction(&tx);
        assert!(matches!(result, Err(NodeError::MissingInputs)));
    }
}
