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

use crate::config::NodeConfig;
use crate::error::NodeError;
use crate::fee_estimator::FeeEstimator;
use crate::mempool::Mempool;
use divi_consensus::bits_to_difficulty;
use divi_crypto::compute_block_hash;
use divi_masternode::MasternodeManager;
use divi_network::constants::MAX_INV_SIZE;
use divi_network::{
    BlockSync, MasternodeHandler, NetworkMessage, PeerEvent, PeerManager, PeerManagerConfig,
    SporkManager, SyncState, TxRelay,
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

    /// Spork synchronization manager
    spork_manager: Arc<SporkManager>,

    /// Masternode manager
    masternode_manager: Arc<MasternodeManager>,

    /// Masternode P2P message handler
    masternode_handler: Arc<MasternodeHandler>,

    /// Event broadcaster
    event_tx: broadcast::Sender<NodeEvent>,

    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
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

        // Initialize database, optionally with UTXO cache
        let db = Arc::new(if config.utxo_cache_size > 0 {
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
        let checked = chain
            .verify_recent_blocks(config.check_blocks)
            .map_err(damaged)?;
        tracing::info!(
            "Verified the last {} blocks in {} ms",
            checked,
            started.elapsed().as_millis()
        );

        // Divi Core keeps the index flags with the chain database: a changed
        // -txindex refuses to start, and -addressindex/-spentindex take effect
        // only on a new chain database (init.cpp:1103-1106, txdb.cpp:498-523)
        let requested = divi_storage::search_index::IndexFlags {
            txindex: config.index.txindex,
            addressindex: config.index.addressindex,
            spentindex: config.index.spentindex,
        };
        let flags =
            divi_storage::search_index::IndexFlags::load_or_init(&db, chain.height(), requested)
                .map_err(damaged)?;
        if flags.txindex != requested.txindex {
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

        if flags.txindex {
            let txindex_path = config.data_dir.join("txindex");
            let tx_index = divi_storage::TxIndex::open(&txindex_path).map_err(|e| {
                tracing::error!("Failed to open transaction index: {}", e);
                NodeError::Init(format!("Failed to open transaction index: {}", e))
            })?;
            chain.enable_tx_index(Arc::new(tx_index));
            tracing::info!("Transaction index enabled at {:?}", txindex_path);
        }

        if flags.addressindex || flags.spentindex {
            chain.enable_search_index(Arc::new(divi_storage::SearchIndex::new(
                db.clone(),
                flags.addressindex,
                flags.spentindex,
            )));
            tracing::info!(
                "Address index {}, spent index {}",
                if flags.addressindex { "on" } else { "off" },
                if flags.spentindex { "on" } else { "off" },
            );
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
            .map_err(|e| NodeError::Init(format!("-proxy: {}", e)))?;
        if let Some(proxy) = proxy {
            tracing::info!("Outbound P2P connections go through SOCKS5 proxy {}", proxy);
        }
        // -timeout for outbound connections
        divi_network::set_connect_timeout_ms(config.p2p.connect_timeout_ms);
        let peer_manager_config = PeerManagerConfig {
            max_outbound: config.p2p.max_outbound,
            max_inbound: config.p2p.max_inbound,
            magic: config.network.magic,
            dns_seeds: peer_sources.dns_seeds.clone(),
            static_peers: peer_sources
                .static_peers
                .iter()
                .filter_map(|s| {
                    // First try to parse as SocketAddr (IP:port)
                    if let Ok(addr) = s.parse() {
                        return Some(addr);
                    }
                    // If that fails, try to resolve as hostname:port
                    if proxy.is_some() {
                        tracing::warn!(
                            "Resolving peer {} with local DNS, outside the proxy; give an IP address to avoid this",
                            s
                        );
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
            listen_addr: if peer_sources.listen {
                Some(config.p2p.socket_addr())
            } else {
                None
            },
            default_port: config.network.default_p2p_port(),
            proxy,
        };
        let peer_manager = PeerManager::new(peer_manager_config);
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
                move |pool: &Mempool, tx: &Transaction, limit_free: bool| {
                    check_mempool_transaction(&chain_for_scripts, pool, tx, limit_free)
                },
            ));
        }

        // Create block sync manager
        let block_sync = BlockSync::new(Arc::clone(&chain), Arc::clone(&peer_manager));

        // Create transaction relay manager
        let tx_relay = TxRelay::new(Arc::clone(&peer_manager));

        // Create spork synchronization manager
        let spork_manager = SporkManager::new(Arc::clone(&peer_manager));

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

        // Create masternode P2P handler
        let masternode_handler = Arc::new(MasternodeHandler::new(Arc::clone(&masternode_manager)));

        // NOTE: block_connected_callback is set in main.rs where it can include
        // both node-level processing (mempool cleanup, fee estimation) and wallet scanning.
        // Do NOT set it here — main.rs sets a single unified callback.

        // Create event broadcaster
        let (event_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Node {
            config,
            status: RwLock::new(NodeStatus::Stopped),
            chain,
            mempool,
            fee_estimator,
            chain_params,
            history: crate::history_fetch::HistoryFetcher::new(Arc::clone(&peer_manager)),
            peer_manager,
            block_sync,
            tx_relay,
            spork_manager,
            masternode_manager,
            masternode_handler,
            event_tx,
            shutdown_tx,
        })
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
    pub async fn start(&self) -> Result<(), NodeError> {
        let current_status = *self.status.read();
        if current_status != NodeStatus::Stopped {
            return Err(NodeError::AlreadyRunning);
        }

        tracing::info!("Starting Divi node...");
        *self.status.write() = NodeStatus::Starting;

        // Initialize components
        tracing::info!("Chain height: {}", self.chain.height());

        // Set peer manager height
        self.peer_manager.set_height(self.chain.height());

        // A pruning node must not advertise NODE_NETWORK (full history). Key it off the
        // database too, so a node that pruned earlier stays honest if expire is later off.
        let prunes = self.config.expire.is_enabled() || self.chain.prune_height() > 0;
        self.peer_manager
            .set_services(divi_network::constants::advertised_services(prunes));

        // Start peer event handler
        let event_tx = self.event_tx.clone();
        let block_sync = Arc::clone(&self.block_sync);
        let history = Arc::clone(&self.history);
        let tx_relay = Arc::clone(&self.tx_relay);
        let spork_manager = Arc::clone(&self.spork_manager);
        let chain = Arc::clone(&self.chain);
        let mempool = Arc::clone(&self.mempool);
        let masternode_handler = Arc::clone(&self.masternode_handler);
        let peer_manager = Arc::clone(&self.peer_manager);
        let mut peer_events = self.peer_manager.subscribe();
        let alert_key = divi_network::alert::alert_key(&self.config.network.magic);
        tokio::spawn(async move {
            // Per peer: the last hash of a full getblocks answer (Divi Core
            // hashContinue) and the alerts already accepted from it
            let mut hash_continue: HashMap<u64, Hash256> = HashMap::new();
            let mut alerts_known: HashMap<u64, HashSet<[u8; 32]>> = HashMap::new();
            while let Ok(event) = peer_events.recv().await {
                match event {
                    PeerEvent::Connected {
                        peer_id,
                        addr,
                        version,
                    } => {
                        tracing::info!("Peer connected: {}", addr);
                        let _ = event_tx.send(NodeEvent::PeerConnected(addr.to_string()));

                        // Update sync with peer's height
                        block_sync.update_peer_height(peer_id, version.start_height.max(0) as u32);
                    }
                    PeerEvent::Disconnected { peer_id, reason } => {
                        tracing::warn!("Peer {} disconnected: {}", peer_id, reason);
                        block_sync.remove_peer(peer_id);
                        tx_relay.remove_peer(peer_id);
                        spork_manager.remove_peer(peer_id);
                        hash_continue.remove(&peer_id);
                        alerts_known.remove(&peer_id);
                    }
                    PeerEvent::Message { peer_id, message } => {
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
                            NetworkMessage::Headers(headers) => {
                                block_sync.handle_headers(peer_id, headers).await;
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
                                // Split block and tx getdata items
                                let block_items: Vec<_> = items
                                    .iter()
                                    .filter(|i| i.inv_type == divi_network::InvType::Block)
                                    .cloned()
                                    .collect();
                                let tx_items: Vec<_> = items
                                    .iter()
                                    .filter(|i| i.inv_type == divi_network::InvType::Tx)
                                    .cloned()
                                    .collect();

                                // Handle block getdata: serve blocks from our chain
                                for item in block_items {
                                    match chain.get_block_for_peer(&item.hash) {
                                        Ok(Some(block)) => {
                                            let msg = NetworkMessage::Block(block);
                                            if let Err(e) =
                                                peer_manager.send_block_to_peer(peer_id, msg).await
                                            {
                                                tracing::warn!(
                                                    "Failed to send block {} to peer {}: {}",
                                                    item.hash,
                                                    peer_id,
                                                    e
                                                );
                                            } else {
                                                tracing::debug!(
                                                    "Served block {} to peer {} (getdata)",
                                                    item.hash,
                                                    peer_id
                                                );
                                                // The last block of a full getblocks
                                                // answer: announce our tip so the peer
                                                // asks for the next batch
                                                if hash_continue.get(&peer_id) == Some(&item.hash) {
                                                    hash_continue.remove(&peer_id);
                                                    if let Some(tip) = chain.tip() {
                                                        let inv = NetworkMessage::Inv(vec![
                                                            divi_network::InvItem::new(
                                                                divi_network::InvType::Block,
                                                                tip.hash,
                                                            ),
                                                        ]);
                                                        let _ = peer_manager
                                                            .send_block_to_peer(peer_id, inv)
                                                            .await;
                                                    }
                                                }
                                            }
                                        }
                                        Ok(None) => {
                                            tracing::debug!(
                                                "Block {} not found for getdata from peer {}",
                                                item.hash,
                                                peer_id
                                            );
                                            // Tell the peer so it can ask elsewhere (pruned or unknown).
                                            let msg = NetworkMessage::NotFound(vec![item.clone()]);
                                            if let Err(e) =
                                                peer_manager.send_block_to_peer(peer_id, msg).await
                                            {
                                                tracing::debug!(
                                                    "Failed to send notfound for {} to peer {}: {}",
                                                    item.hash,
                                                    peer_id,
                                                    e
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "Error looking up block {} for peer {}: {}",
                                                item.hash,
                                                peer_id,
                                                e
                                            );
                                        }
                                    }
                                }

                                // Handle tx getdata requests
                                if !tx_items.is_empty() {
                                    let mempool_ref = &mempool;
                                    tx_relay
                                        .handle_getdata(peer_id, tx_items, |txid| {
                                            mempool_ref.get(txid).map(|e| e.tx)
                                        })
                                        .await;
                                }
                            }
                            // Handle getblocks: respond with inv for blocks after locator
                            NetworkMessage::GetBlocks(msg) => {
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
                            }
                            NetworkMessage::GetSporks => {
                                spork_manager.handle_getsporks(peer_id).await;
                            }
                            NetworkMessage::Spork(spork) => {
                                spork_manager.handle_spork(peer_id, spork).await;
                            }
                            // Masternode sync messages
                            NetworkMessage::SyncStatusCount { item_id, count } => {
                                tracing::info!(
                                    "Received sync status count from peer {}: item_id={}, count={}",
                                    peer_id,
                                    item_id,
                                    count
                                );
                            }
                            NetworkMessage::GetSyncStatus => {
                                tracing::debug!("Received govsync request from peer {}", peer_id);
                            }
                            // Masternode P2P messages
                            // Not answered: IronDivi cannot vouch for masternode
                            // entries as Divi Core does (see MasternodeHandler)
                            NetworkMessage::RequestMasternodeList(_) => {
                                tracing::debug!("dseg from peer {} not answered", peer_id);
                            }
                            NetworkMessage::MasternodeBroadcast(payload) => {
                                if let Err(e) =
                                    masternode_handler.handle_broadcast(peer_id, &payload)
                                {
                                    tracing::warn!(
                                        "Failed to handle masternode broadcast from peer {}: {}",
                                        peer_id,
                                        e
                                    );
                                }
                            }
                            NetworkMessage::MasternodePing(payload) => {
                                if let Err(e) = masternode_handler.handle_ping(peer_id, &payload) {
                                    tracing::warn!(
                                        "Failed to handle masternode ping from peer {}: {}",
                                        peer_id,
                                        e
                                    );
                                }
                            }
                            NetworkMessage::MasternodeWinner(payload) => {
                                if let Err(e) = masternode_handler.handle_winner(peer_id, &payload)
                                {
                                    tracing::warn!(
                                        "Failed to handle masternode winner from peer {}: {}",
                                        peer_id,
                                        e
                                    );
                                }
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
                                // IronDivi keeps no address book; only Divi Core's limit applies
                                if addrs.len() > 1000 {
                                    peer_manager.report_misbehavior_score(
                                        peer_id,
                                        20,
                                        "Requested too many addresses",
                                    );
                                }
                            }
                            // IronDivi does not offer NODE_BLOOM, and Divi Core without
                            // bloom filters bans a peer that sends these
                            NetworkMessage::FilterLoad(_)
                            | NetworkMessage::FilterAdd(_)
                            | NetworkMessage::FilterClear => {
                                peer_manager.report_misbehavior_score(
                                    peer_id,
                                    100,
                                    "Sent bloom filter msg but they are disabled",
                                );
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
        });

        // Start peer manager (non-blocking for regtest with no peers)
        let peer_manager = Arc::clone(&self.peer_manager);
        tokio::spawn(async move {
            if let Err(e) = peer_manager.start().await {
                tracing::error!("Peer manager error: {}", e);
            }
        });

        // Spawn peer maintenance loop (reconnects if peers drop)
        let pm_for_maintenance = Arc::clone(&self.peer_manager);
        tokio::spawn(async move {
            pm_for_maintenance.run_maintenance().await;
        });

        // Start sync progress tracker
        let sync = Arc::clone(&self.block_sync);
        let event_sender = self.event_tx.clone();
        let mut sync_progress = sync.subscribe();
        tokio::spawn(async move {
            while let Ok(progress) = sync_progress.recv().await {
                let _ = event_sender.send(NodeEvent::SyncProgress {
                    current: progress.current_height,
                    total: progress.target_height,
                });
            }
        });

        // Start sync timeout checker
        let sync_for_timeout = Arc::clone(&self.block_sync);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                sync_for_timeout.check_timeouts().await;
            }
        });

        // Start transaction relay event handler (adds received txs to mempool)
        let tx_relay_for_mempool = Arc::clone(&self.tx_relay);
        let mempool_for_relay = Arc::clone(&self.mempool);
        let chain_for_relay = Arc::clone(&self.chain);
        let event_tx_for_relay = self.event_tx.clone();
        let peers_for_relay = Arc::clone(&self.peer_manager);
        let mut tx_events = tx_relay_for_mempool.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = tx_events.recv().await {
                match accept_relayed_transaction(
                    &chain_for_relay,
                    &mempool_for_relay,
                    &peers_for_relay,
                    &event,
                ) {
                    Ok(txid) => {
                        let _ = event_tx_for_relay.send(NodeEvent::TransactionAccepted(txid));
                    }
                    Err(e) => {
                        tracing::debug!("Rejected relayed tx {}: {}", event.txid, e);
                    }
                }
            }
        });

        // Start transaction relay timeout checker
        let tx_relay_for_timeout = Arc::clone(&self.tx_relay);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                tx_relay_for_timeout.check_timeouts().await;
            }
        });

        // Start block sync (wait for sporks to sync first, as required by Divi protocol)
        let sync_to_start = Arc::clone(&self.block_sync);
        let spork_for_sync = Arc::clone(&self.spork_manager);
        tokio::spawn(async move {
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
        });

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

        // Disconnect all peers
        self.peer_manager.disconnect_all();

        // Persist masternode state before shutdown
        if let Err(e) = self.masternode_manager.save() {
            tracing::error!("Failed to persist masternode state on shutdown: {}", e);
        } else {
            tracing::info!("Masternode state persisted successfully");
        }

        // Flush UTXO cache to database before shutdown
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

        let txid = self.mempool.add(tx, actual_fee)?;
        let _ = self.event_tx.send(NodeEvent::TransactionAccepted(txid));

        // Mark as seen and announce to peers
        self.tx_relay.mark_seen(txid);
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
    pub fn get_network_info(&self) -> NetworkInfo {
        NetworkInfo {
            version: self.config.network.protocol_version,
            subversion: self.config.p2p.user_agent.clone(),
            protocol_version: self.config.network.protocol_version,
            connections: self.peer_manager.peer_count(),
            networks: vec!["ipv4".to_string(), "ipv6".to_string()],
            relay_fee: (self.config.mempool.min_relay_fee as f64 * 1000.0) / 100_000_000.0,
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
        Err(e) => {
            peers.report_misbehavior_score(
                event.from_peer,
                e.misbehaviour_score(),
                &format!("tx {} rejected by the mempool: {}", event.txid, e),
            );
        }
    }
    result
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
/// them) is offered first, through `Mempool::add`, which works out the fee and
/// applies Core's AcceptToMemoryPool with `fLimitFree` false as disconnectTip
/// does; then every transaction the new chain made unspendable goes, with its
/// descendants.
pub fn update_mempool_after_reorg(
    chain: &Arc<Chain>,
    mempool: &Arc<Mempool>,
    disconnected: Vec<Transaction>,
) {
    let offered = disconnected.len();
    let mut returned = 0;
    for tx in disconnected {
        let txid = tx.txid();
        match mempool.add(tx, divi_primitives::amount::Amount::ZERO) {
            Ok(_) => returned += 1,
            Err(e) => tracing::debug!(
                "Transaction {} of a disconnected block not returned to the mempool: {}",
                txid,
                e
            ),
        }
    }
    let dropped = mempool
        .remove_unspendable(|outpoint| spendable_in_next_block(chain, outpoint).unwrap_or(true));
    // The tip may now be lower: drop what can no longer be mined
    mempool.remove_non_final();
    tracing::info!(
        "Reorg: returned {} of {} transaction(s) of disconnected blocks to the mempool, removed {} the new chain spends or lacks",
        returned,
        offered,
        dropped
    );
}

/// Divi Core `MAX_STANDARD_TX_SIZE` (defaultValues.h:54)
const MAX_STANDARD_TX_SIZE: usize = 100_000;

/// Divi Core `MAX_TX_SIGOPS_CURRENT` (defaultValues.h:61): 40,000 / 5
const MAX_TX_SIGOPS: u32 = 8_000;

/// Divi Core `MempoolConsensus::IsStandardTx` (MempoolConsensus.cpp:29-121) with
/// its defaults (`-permitbaremultisig` on, `-datacarriersize` 603): the reason
/// a transaction is not relayed, if it is not. Applies on every network, as
/// `-acceptnonstandard` is off by default.
pub fn check_standard_tx(
    tx: &Transaction,
    tip_height: u32,
    now: u32,
    relay_fee_per_kb: i64,
) -> Result<(), NodeError> {
    use crate::error::reject;
    use divi_script::policy::{standard_output_type, MAX_OP_META_RELAY};
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
        match standard_output_type(out.script_pubkey.as_bytes(), MAX_OP_META_RELAY) {
            None => return nonstandard("scriptpubkey"),
            Some(ScriptType::NullData) => data_outputs += 1,
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
/// reason and misbehaviour score. `limit_free` is Core's `fLimitFree` (true for
/// relayed transactions).
pub fn check_mempool_transaction(
    chain: &Chain,
    mempool: &Mempool,
    tx: &Transaction,
    limit_free: bool,
) -> Result<divi_primitives::amount::Amount, NodeError> {
    use crate::error::reject;
    use divi_primitives::amount::Amount;
    use divi_primitives::script::Script;
    use divi_script::{verify_input_with_flags, ScriptFlags};

    let lookup_failed = |e: divi_storage::StorageError| {
        NodeError::TransactionValidation(format!("Failed to look up the chain: {}", e))
    };

    let max_money = chain.max_money();
    if divi_storage::check_transaction(tx, max_money).is_err() {
        return Err(NodeError::rejected(reject::INVALID, "bad-tx"));
    }
    if tx.is_coinbase() {
        return Err(NodeError::rejected(reject::INVALID, "coinbase"));
    }
    if tx.is_coinstake() {
        return Err(NodeError::rejected(reject::INVALID, "coinstake"));
    }
    let tip_height = chain.height();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    check_standard_tx(tx, tip_height, now, mempool.min_relay_fee_per_kb())?;
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
    for (input, prev) in tx.vin.iter().zip(&spent) {
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
    Ok(Amount::from_sat(fee))
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
            Err(e) => e.to_string(),
        };
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

    #[test]
    fn test_network_info() {
        let config = test_config();
        let node = Node::new(config).unwrap();

        let info = node.get_network_info();
        assert_eq!(info.protocol_version, 70920);
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
