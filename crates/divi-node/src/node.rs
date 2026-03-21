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
use divi_network::{
    BlockSync, MasternodeHandler, NetworkMessage, PeerEvent, PeerManager, PeerManagerConfig,
    SporkManager, SyncState, TxRelay,
};
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::Transaction;
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType as StorageNetworkType};
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

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
        let chain_params =
            ChainParams::for_network(storage_network_type, config.network.chain_mode);

        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| NodeError::Init(format!("Failed to create data directory: {}", e)))?;

        // Initialize database, optionally with UTXO cache
        let db = Arc::new(if config.utxo_cache_size > 0 {
            tracing::info!("UTXO cache enabled: {} entries", config.utxo_cache_size);
            ChainDatabase::open_with_utxo_cache(&config.chainstate_path(), config.utxo_cache_size)
                .map_err(|e| NodeError::Init(format!("Failed to open chain database: {}", e)))?
        } else {
            tracing::info!("UTXO cache disabled (direct RocksDB reads)");
            ChainDatabase::open(&config.chainstate_path())
                .map_err(|e| NodeError::Init(format!("Failed to open chain database: {}", e)))?
        });

        // Initialize chain state
        let mut chain = Chain::new(db.clone(), chain_params.clone())
            .map_err(|e| NodeError::Init(format!("Failed to initialize chain state: {}", e)))?;

        if config.index.txindex {
            let txindex_path = config.data_dir.join("txindex");
            let tx_index = divi_storage::TxIndex::open(&txindex_path).map_err(|e| {
                tracing::error!("Failed to open transaction index: {}", e);
                NodeError::Init(format!("Failed to open transaction index: {}", e))
            })?;
            chain.enable_tx_index(Arc::new(tx_index));
            tracing::info!("Transaction index enabled at {:?}", txindex_path);
        }

        if config.index.spentindex {
            let spent_index = divi_storage::SpentIndex::new(db.clone());
            chain.enable_spent_index(Arc::new(spent_index));
            tracing::info!("Spent index enabled");
        }

        // Initialize mempool
        let mempool = Arc::new(Mempool::new(config.mempool.clone()));

        // Initialize fee estimator
        let fee_estimator = Arc::new(FeeEstimator::new());

        // Create peer manager based on network type
        let peer_manager_config = PeerManagerConfig {
            max_outbound: config.p2p.max_outbound,
            max_inbound: config.p2p.max_inbound,
            magic: config.network.magic,
            dns_seeds: config.network.dns_seeds.clone(),
            static_peers: config
                .network
                .static_peers
                .iter()
                .filter_map(|s| {
                    // First try to parse as SocketAddr (IP:port)
                    if let Ok(addr) = s.parse() {
                        return Some(addr);
                    }
                    // If that fails, try to resolve as hostname:port
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
            listen_addr: Some(config.p2p.socket_addr()),
            default_port: config.p2p.port,
        };
        let peer_manager = PeerManager::new(peer_manager_config);

        // Create chain Arc for sharing
        let chain = Arc::new(chain);

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

        // Set up relay callback for masternode handler
        let pm_for_relay = Arc::clone(&peer_manager);
        masternode_handler.set_relay_callback(move |msg, exclude_peer| {
            // Broadcast to all peers except the one who sent it
            pm_for_relay.broadcast_except(msg, exclude_peer);
        });

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

    /// Get fee estimator
    pub fn fee_estimator(&self) -> &Arc<FeeEstimator> {
        &self.fee_estimator
    }

    /// Get chain parameters
    pub fn chain_params(&self) -> &ChainParams {
        &self.chain_params
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

        // Start peer event handler
        let event_tx = self.event_tx.clone();
        let block_sync = Arc::clone(&self.block_sync);
        let tx_relay = Arc::clone(&self.tx_relay);
        let spork_manager = Arc::clone(&self.spork_manager);
        let chain = Arc::clone(&self.chain);
        let mempool = Arc::clone(&self.mempool);
        let masternode_handler = Arc::clone(&self.masternode_handler);
        let peer_manager = Arc::clone(&self.peer_manager);
        let mut peer_events = self.peer_manager.subscribe();
        tokio::spawn(async move {
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
                            NetworkMessage::Tx(tx) => {
                                tx_relay.handle_tx(peer_id, tx).await;
                            }
                            NetworkMessage::GetData(items) => {
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
                                    match chain.get_block(&item.hash) {
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
                                            }
                                        }
                                        Ok(None) => {
                                            tracing::debug!(
                                                "Block {} not found for getdata from peer {}",
                                                item.hash,
                                                peer_id
                                            );
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
                                // Find the first locator hash we have on our main chain
                                let mut start_height = None;
                                for locator_hash in &msg.locator_hashes {
                                    if let Ok(Some(idx)) = chain.get_block_index(locator_hash) {
                                        if idx.is_on_main_chain() {
                                            start_height = Some(idx.height);
                                            break;
                                        }
                                    }
                                }
                                // If no locator found, start from genesis
                                let start = start_height.unwrap_or(0) + 1;
                                let tip_height = chain.height();
                                // Send up to 500 block inv items (standard Bitcoin protocol limit)
                                let end = std::cmp::min(start + 500, tip_height + 1);
                                let mut inv_items = Vec::new();
                                for h in start..end {
                                    if let Ok(Some(idx)) = chain.get_block_index_by_height(h) {
                                        inv_items.push(divi_network::InvItem::new(
                                            divi_network::InvType::Block,
                                            idx.hash,
                                        ));
                                        if idx.hash == msg.stop_hash {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
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
                            NetworkMessage::RequestMasternodeList(payload) => {
                                let handler = Arc::clone(&masternode_handler);
                                let pm = Arc::clone(&peer_manager);
                                tokio::spawn(async move {
                                    match handler.handle_list_request(peer_id, &payload) {
                                        Ok(responses) => {
                                            // Send responses back to the requesting peer
                                            for response in responses {
                                                if let Err(e) =
                                                    pm.send_to_peer(peer_id, response).await
                                                {
                                                    tracing::warn!(
                                                        "Failed to send masternode response to peer {}: {}",
                                                        peer_id, e
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to handle masternode list request from peer {}: {}",
                                                peer_id, e
                                            );
                                        }
                                    }
                                });
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
                    PeerEvent::Misbehavior {
                        peer_id,
                        score,
                        reason,
                    } => {
                        tracing::warn!("Peer {} misbehaved (score {}): {}", peer_id, score, reason);
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
        let mut tx_events = tx_relay_for_mempool.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = tx_events.recv().await {
                // Calculate fee from actual UTXO values
                let fee = match Self::calculate_transaction_fee(
                    &event.tx,
                    &chain_for_relay,
                    &mempool_for_relay,
                ) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::debug!(
                            "Failed to calculate fee for relayed tx {}: {}",
                            event.txid,
                            e
                        );
                        continue;
                    }
                };

                match mempool_for_relay.add(event.tx.clone(), fee) {
                    Ok(txid) => {
                        tracing::debug!(
                            "Added relayed tx {} to mempool with fee {}",
                            txid,
                            fee.as_sat()
                        );
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
        let _result = self
            .chain
            .accept_block(block.clone())
            .map_err(|e| NodeError::BlockValidation(e.to_string()))?;

        // Remove confirmed transactions from mempool and mark as seen in relay
        let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
        self.mempool.remove_for_block(&txids);
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
                    // Check coinbase maturity (network-specific: mainnet=20, testnet/regtest=1)
                    if utxo.is_coinbase || utxo.is_coinstake {
                        let current_height = self.chain.height();
                        let confirmations = current_height.saturating_sub(utxo.height);
                        let coinbase_maturity = match self.chain.network_type() {
                            StorageNetworkType::Mainnet => 20,
                            StorageNetworkType::Testnet => 1,
                            StorageNetworkType::Regtest => 1,
                        };
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
                    total_input = total_input + utxo.value;
                }
                Ok(None) => {
                    // Not in UTXO set, check if it's an output of a mempool transaction
                    if let Some(mempool_entry) = self.mempool.get(&input.prevout.txid) {
                        if (input.prevout.vout as usize) < mempool_entry.tx.vout.len() {
                            total_input = total_input
                                + mempool_entry.tx.vout[input.prevout.vout as usize].value;
                        } else {
                            return Err(NodeError::TransactionValidation(format!(
                                "Input {}:{} output index out of bounds",
                                input.prevout.txid, input.prevout.vout
                            )));
                        }
                    } else {
                        return Err(NodeError::TransactionValidation(format!(
                            "Input {}:{} not found in UTXO set",
                            input.prevout.txid, input.prevout.vout
                        )));
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
                return Err(NodeError::TransactionValidation(
                    "Negative output value".into(),
                ));
            }
            total_output = total_output + output.value;
        }

        // Input must be >= output (difference is the fee)
        if total_input.as_sat() < total_output.as_sat() {
            return Err(NodeError::TransactionValidation(format!(
                "Inputs ({}) less than outputs ({})",
                total_input.as_sat(),
                total_output.as_sat()
            )));
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

    /// Calculate transaction fee from UTXO lookups
    /// This is a static helper that can be called from spawned tasks
    fn calculate_transaction_fee(
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
                    total_input = total_input + utxo.value;
                }
                Ok(None) => {
                    // Not in UTXO set, check if it's an output of a mempool transaction
                    if let Some(mempool_entry) = mempool.get(&input.prevout.txid) {
                        if (input.prevout.vout as usize) < mempool_entry.tx.vout.len() {
                            total_input = total_input
                                + mempool_entry.tx.vout[input.prevout.vout as usize].value;
                        } else {
                            return Err(NodeError::TransactionValidation(format!(
                                "Input {}:{} output index out of bounds",
                                input.prevout.txid, input.prevout.vout
                            )));
                        }
                    } else {
                        return Err(NodeError::TransactionValidation(format!(
                            "Input {}:{} not found in UTXO set",
                            input.prevout.txid, input.prevout.vout
                        )));
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
                return Err(NodeError::TransactionValidation(
                    "Negative output value".into(),
                ));
            }
            total_output = total_output + output.value;
        }

        // Input must be >= output (difference is the fee)
        if total_input.as_sat() < total_output.as_sat() {
            return Err(NodeError::TransactionValidation(format!(
                "Inputs ({}) less than outputs ({})",
                total_input.as_sat(),
                total_output.as_sat()
            )));
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
            total_fee: stats.total_fee.as_divi() as f64 / 100_000_000.0,
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

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::ChainMode;
    use tempfile::tempdir;

    fn test_config() -> NodeConfig {
        let temp_dir = tempdir().unwrap();
        let mut config = NodeConfig::testnet(ChainMode::Divi);
        config.data_dir = temp_dir.into_path();
        config
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
        use divi_primitives::amount::Amount;
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
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not found in UTXO set"));
    }
}
