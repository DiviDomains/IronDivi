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

//! Peer manager for handling multiple peer connections
//!
//! Manages peer discovery, connection limits, and message routing.

use crate::connection::Connection;
use crate::constants::Magic;
use crate::error::NetworkError;
use crate::message::{InvItem, InvType};
use crate::peer::{PeerEvent, PeerHandle, PeerId};
use crate::scoring::{Misbehavior, MisbehaviourOutcome, PeerScoring};
use crate::NetworkMessage;
use divi_primitives::hash::Hash256;

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Configuration for the peer manager
#[derive(Debug, Clone)]
pub struct PeerManagerConfig {
    /// Maximum number of outbound connections
    pub max_outbound: usize,
    /// Maximum number of inbound connections
    pub max_inbound: usize,
    /// Network magic bytes
    pub magic: Magic,
    /// DNS seeds for peer discovery
    pub dns_seeds: Vec<String>,
    /// Static peers to connect to
    pub static_peers: Vec<SocketAddr>,
    /// Listen address for inbound connections
    pub listen_addr: Option<SocketAddr>,
    /// Default P2P port for DNS seed resolution
    pub default_port: u16,
    /// SOCKS5 proxy for every outbound connection (C++ `-proxy`). When set, no
    /// outbound connection is made directly and DNS seeds are not resolved locally.
    pub proxy: Option<SocketAddr>,
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        PeerManagerConfig {
            max_outbound: 8,
            max_inbound: 125,
            magic: crate::MAINNET_MAGIC,
            dns_seeds: vec!["autoseeds.diviseed.diviproject.org".to_string()],
            static_peers: vec![
                "178.62.195.16:51472".parse().unwrap(),
                "178.62.221.33:51472".parse().unwrap(),
                "178.128.251.20:51472".parse().unwrap(),
            ],
            listen_addr: None,
            default_port: 51472, // Mainnet P2P port
            proxy: None,
        }
    }
}

/// Added node entry (manually added via RPC)
#[derive(Debug, Clone)]
pub struct AddedNode {
    /// Address of the node
    pub addr: SocketAddr,
    /// Whether we're currently connected to this node
    pub connected: bool,
    /// Whether connection attempt is in progress
    pub connecting: bool,
}

/// Manages connections to multiple peers
pub struct PeerManager {
    /// Configuration
    config: PeerManagerConfig,
    /// Connected peers
    peers: RwLock<HashMap<PeerId, PeerHandle>>,
    /// Our best block height
    our_height: RwLock<u32>,
    /// Service bits advertised in our version message
    our_services: AtomicU64,
    /// Event channel sender
    event_tx: broadcast::Sender<PeerEvent>,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// Peer scoring and ban management
    scoring: PeerScoring,
    /// Nonces of our version messages on open connections (self-connection check)
    local_nonces: crate::connection::LocalNonces,
    /// Manually added nodes (via addnode RPC)
    added_nodes: RwLock<HashSet<SocketAddr>>,
    /// Addresses currently being connected to (connection attempt in progress)
    connecting_addrs: RwLock<HashSet<SocketAddr>>,
    /// Total bytes sent across all peers (cumulative since node start)
    total_bytes_sent: Arc<AtomicU64>,
    /// Total bytes received across all peers (cumulative since node start)
    total_bytes_recv: Arc<AtomicU64>,
    /// Per-address backoff state for static peer reconnection attempts.
    ///
    /// Tracks (consecutive_failures, last_attempt_time) so that repeatedly-failing
    /// peers are skipped for exponentially longer periods (up to 30 minutes).
    static_peer_backoff: RwLock<HashMap<SocketAddr, (u32, Instant)>>,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new(config: PeerManagerConfig) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, _) = broadcast::channel(1);

        Arc::new(PeerManager {
            config,
            peers: RwLock::new(HashMap::new()),
            our_height: RwLock::new(0),
            our_services: AtomicU64::new(crate::constants::services::NODE_NETWORK),
            event_tx,
            shutdown_tx,
            scoring: PeerScoring::new(),
            local_nonces: Default::default(),
            added_nodes: RwLock::new(HashSet::new()),
            connecting_addrs: RwLock::new(HashSet::new()),
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_bytes_recv: Arc::new(AtomicU64::new(0)),
            static_peer_backoff: RwLock::new(HashMap::new()),
        })
    }

    /// Get a reference to peer scoring
    pub fn scoring(&self) -> &PeerScoring {
        &self.scoring
    }

    /// Report misbehavior for a peer
    pub fn report_misbehavior(&self, peer_id: PeerId, reason: Misbehavior) {
        if self.scoring.record_misbehavior(peer_id, reason) {
            // Peer was banned, disconnect them
            self.disconnect(peer_id);
        }
    }

    /// Divi Core's `Misbehaving`: add a misbehaviour score to a peer (0 does
    /// nothing); a peer reaching the ban threshold is disconnected and,
    /// unless local, banned for the ban time
    pub fn report_misbehavior_score(
        &self,
        peer_id: PeerId,
        score: u32,
        cause: &str,
    ) -> MisbehaviourOutcome {
        let ip = self.scoring.get_stats(peer_id).map(|s| s.ip);
        let outcome = self.scoring.record_misbehavior_score(
            peer_id,
            score.min(i32::MAX as u32) as i32,
            cause,
        );
        match (outcome, ip) {
            // Every connection from the banned address goes
            (MisbehaviourOutcome::Banned, Some(ip)) => self.disconnect_ip(ip),
            (MisbehaviourOutcome::Scored, _) => {}
            _ => self.disconnect(peer_id),
        }
        outcome
    }

    /// Divi Core bans a peer whose protocol version is too old
    /// (`PeerBanningService::Ban` after `DisconnectOldProtocol`), local or not
    fn ban_obsolete(&self, ip: std::net::IpAddr, error: &NetworkError) {
        if let NetworkError::VersionMismatch { peer, required } = error {
            let (_, duration) = self.scoring.ban_policy();
            self.ban_ip(
                ip,
                duration,
                format!("obsolete version {} (need {})", peer, required),
            );
        }
    }

    /// Check if an IP is banned
    pub fn is_banned(&self, ip: &std::net::IpAddr) -> bool {
        self.scoring.is_banned(ip)
    }

    /// Ban an IP address
    pub fn ban_ip(&self, ip: std::net::IpAddr, duration: Duration, reason: impl Into<String>) {
        self.scoring.ban_ip(ip, duration, reason);
        self.disconnect_ip(ip);
    }

    /// Disconnect every peer connected from `ip`
    fn disconnect_ip(&self, ip: std::net::IpAddr) {
        let peers_to_disconnect: Vec<_> = self
            .peers
            .read()
            .iter()
            .filter(|(_, handle)| {
                if let std::net::SocketAddr::V4(addr) = handle.addr {
                    std::net::IpAddr::V4(*addr.ip()) == ip
                } else if let std::net::SocketAddr::V6(addr) = handle.addr {
                    std::net::IpAddr::V6(*addr.ip()) == ip
                } else {
                    false
                }
            })
            .map(|(id, _)| *id)
            .collect();

        for peer_id in peers_to_disconnect {
            self.disconnect(peer_id);
        }
    }

    /// Unban an IP address
    pub fn unban_ip(&self, ip: &std::net::IpAddr) -> bool {
        self.scoring.unban_ip(ip)
    }

    /// Get retry delay for connecting to an address
    pub fn retry_delay(&self, addr: SocketAddr) -> Duration {
        self.scoring.retry_delay(addr.ip())
    }

    /// Subscribe to peer events
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.event_tx.subscribe()
    }

    /// Get shutdown signal receiver
    pub fn shutdown_signal(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Update our best block height
    pub fn set_height(&self, height: u32) {
        *self.our_height.write() = height;
    }

    /// Set the service bits we advertise to peers. A node that has pruned
    /// block bodies must clear `NODE_NETWORK` and set `NODE_NETWORK_LIMITED`.
    pub fn set_services(&self, services: u64) {
        self.our_services.store(services, Ordering::Relaxed);
    }

    /// Service bits we currently advertise
    pub fn services(&self) -> u64 {
        self.our_services.load(Ordering::Relaxed)
    }

    /// Connected peers that advertise `NODE_NETWORK`, i.e. keep every block
    pub fn full_history_peers(&self) -> Vec<PeerId> {
        self.peers
            .read()
            .iter()
            .filter(|(_, p)| {
                p.stats.services.load(Ordering::Relaxed) & crate::constants::services::NODE_NETWORK
                    != 0
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get current peer count
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Get list of connected peer addresses
    pub fn peer_addresses(&self) -> Vec<SocketAddr> {
        self.peers.read().values().map(|p| p.addr).collect()
    }

    /// Get list of connected peer IDs
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peers.read().keys().copied().collect()
    }

    /// Peer IDs of all connected peers whose remote IP equals `ip` (any port)
    pub fn peer_ids_for_ip(&self, ip: std::net::IpAddr) -> Vec<PeerId> {
        self.peers
            .read()
            .iter()
            .filter(|(_, p)| p.addr.ip() == ip)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Peer ID of the connected peer with exactly this socket address
    pub fn peer_id_for_addr(&self, addr: &SocketAddr) -> Option<PeerId> {
        self.peers
            .read()
            .iter()
            .find(|(_, p)| &p.addr == addr)
            .map(|(id, _)| *id)
    }

    /// Check if a specific peer is currently connected
    pub fn is_peer_connected(&self, peer_id: PeerId) -> bool {
        self.peers.read().contains_key(&peer_id)
    }

    /// Get peer info for RPC (address and inbound status)
    pub fn get_peer_info(&self) -> Vec<(SocketAddr, bool)> {
        self.peers
            .read()
            .values()
            .map(|p| (p.addr, p.inbound))
            .collect()
    }

    /// Get detailed peer info for RPC: (id, addr, inbound, live stats, ban score)
    pub fn get_peer_details(
        &self,
    ) -> Vec<(
        PeerId,
        SocketAddr,
        bool,
        Arc<crate::peer::LivePeerStats>,
        i64,
    )> {
        self.peers
            .read()
            .values()
            .map(|p| {
                let ban = self
                    .scoring
                    .get_stats(p.id)
                    .map(|s| s.misbehavior_score as i64)
                    .unwrap_or(0);
                (p.id, p.addr, p.inbound, p.stats.clone(), ban)
            })
            .collect()
    }

    /// Check if we have room for more outbound connections
    pub fn can_connect_outbound(&self) -> bool {
        let outbound_count = self.peers.read().values().filter(|p| !p.inbound).count();
        outbound_count < self.config.max_outbound
    }

    /// Get count of inbound connections
    pub fn inbound_count(&self) -> usize {
        self.peers.read().values().filter(|p| p.inbound).count()
    }

    /// Get count of outbound connections
    pub fn outbound_count(&self) -> usize {
        self.peers.read().values().filter(|p| !p.inbound).count()
    }

    /// Add a node manually (via RPC addnode command)
    ///
    /// This adds the node to the list of nodes we should try to stay connected to.
    pub fn add_node(&self, addr: SocketAddr) -> bool {
        let mut added = self.added_nodes.write();
        if added.contains(&addr) {
            return false; // Already added
        }
        added.insert(addr);
        info!("Added node: {}", addr);
        true
    }

    /// Remove a manually added node
    pub fn remove_added_node(&self, addr: &SocketAddr) -> bool {
        let removed = self.added_nodes.write().remove(addr);
        if removed {
            info!("Removed node: {}", addr);
        }
        removed
    }

    /// Get info about added nodes
    pub fn get_added_node_info(&self) -> Vec<AddedNode> {
        let added = self.added_nodes.read();
        let peers = self.peers.read();
        let connecting = self.connecting_addrs.read();

        let connected_addrs: HashSet<_> = peers.values().map(|p| p.addr).collect();

        added
            .iter()
            .map(|addr| AddedNode {
                addr: *addr,
                connected: connected_addrs.contains(addr),
                connecting: connecting.contains(addr),
            })
            .collect()
    }

    /// Check if an address is a manually added node
    pub fn is_added_node(&self, addr: &SocketAddr) -> bool {
        self.added_nodes.read().contains(addr)
    }

    /// Start the peer manager
    pub async fn start(self: Arc<Self>) -> Result<(), NetworkError> {
        info!("Starting peer manager");

        // Start listener for inbound connections
        let listener_handle = if let Some(listen_addr) = self.config.listen_addr {
            let self_clone = Arc::clone(&self);
            Some(tokio::spawn(async move {
                if let Err(e) = self_clone.run_listener(listen_addr).await {
                    error!("Listener error: {}", e);
                }
            }))
        } else {
            None
        };

        // Connect to static peers first (they report accurate heights)
        let static_handles: Vec<_> = self
            .config
            .static_peers
            .clone()
            .into_iter()
            .filter(|_| self.can_connect_outbound())
            .map(|addr| {
                let self_clone = Arc::clone(&self);
                tokio::spawn(async move {
                    if let Err(e) = self_clone.connect_to_peer(addr).await {
                        warn!("Failed to connect to static peer {}: {}", addr, e);
                    }
                })
            })
            .collect();

        // Wait for static peer connections to complete before DNS discovery
        for handle in static_handles {
            let _ = handle.await;
        }

        // Fill remaining slots from DNS seeds
        Arc::clone(&self).discover_peers().await;

        // Wait for listener (if started)
        if let Some(handle) = listener_handle {
            let _ = handle.await;
        }

        Ok(())
    }

    /// SOCKS5 proxy used for outbound connections, if any
    pub fn proxy(&self) -> Option<SocketAddr> {
        self.config.proxy
    }

    /// Discover peers from DNS seeds
    async fn discover_peers(self: Arc<Self>) {
        if self.config.dns_seeds.is_empty() {
            debug!("No DNS seeds configured; skipping DNS peer discovery");
            return;
        }
        if let Some(proxy) = self.config.proxy {
            // A local lookup would reveal the node outside the proxy
            info!(
                "Proxy {} set: not resolving DNS seeds locally; using configured peers only",
                proxy
            );
            return;
        }
        info!(
            "Discovering peers from DNS seeds ({} configured)",
            self.config.dns_seeds.len()
        );

        for seed in &self.config.dns_seeds {
            debug!("Resolving DNS seed: {}", seed);

            match tokio::net::lookup_host(format!("{}:{}", seed, self.config.default_port)).await {
                Ok(addrs) => {
                    for addr in addrs {
                        if self.can_connect_outbound() {
                            info!("Discovered peer: {}", addr);
                            let self_clone = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(e) = self_clone.connect_to_peer(addr).await {
                                    debug!("Failed to connect to discovered peer {}: {}", addr, e);
                                }
                            });
                        } else {
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to resolve DNS seed {}: {}", seed, e);
                }
            }
        }
    }

    /// Run the inbound connection listener
    async fn run_listener(self: Arc<Self>, addr: SocketAddr) -> Result<(), NetworkError> {
        let listener = TcpListener::bind(addr).await?;
        info!("Listening for connections on {}", addr);

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Listener shutting down");
                    break;
                }

                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            info!("Accepted connection from {}", peer_addr);

                            // Check connection limit
                            if self.peers.read().len() >= self.config.max_inbound + self.config.max_outbound {
                                warn!("Connection limit reached, rejecting {}", peer_addr);
                                continue;
                            }

                            let self_clone = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(e) = self_clone.handle_inbound(stream).await {
                                    debug!("Inbound connection error from {}: {}", peer_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Connect to a specific peer
    pub async fn connect_to_peer(
        self: Arc<Self>,
        addr: SocketAddr,
    ) -> Result<PeerId, NetworkError> {
        // Check if IP is banned
        if self.is_banned(&addr.ip()) {
            return Err(NetworkError::ConnectionRefused(format!(
                "{} is banned",
                addr.ip()
            )));
        }

        // Mark address as connecting
        self.connecting_addrs.write().insert(addr);

        let our_height = *self.our_height.read();

        let result = Connection::connect(
            addr,
            self.config.proxy,
            self.config.magic,
            our_height,
            self.services(),
            self.event_tx.clone(),
            self.shutdown_tx.subscribe(),
            self.bytes_sent_counter(),
            self.bytes_recv_counter(),
            Arc::clone(&self.local_nonces),
        )
        .await;

        // Remove from connecting set regardless of result
        self.connecting_addrs.write().remove(&addr);

        let (conn, handle) = result?;

        let peer_id = handle.id;

        // Register with scoring system
        self.scoring.register_peer(peer_id, addr.ip());
        self.scoring.reset_connection_failures(peer_id);

        // Store the handle
        self.peers.write().insert(peer_id, handle);

        // Run the connection handler
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            if let Err(e) = conn.run().await {
                debug!("Connection to {} ended: {}", addr, e);
                self_clone.ban_obsolete(addr.ip(), &e);
            }
            // Remove peer on disconnect
            self_clone.peers.write().remove(&peer_id);
            self_clone.scoring.unregister_peer(peer_id);
        });

        Ok(peer_id)
    }

    /// Handle an inbound connection
    async fn handle_inbound(
        self: Arc<Self>,
        stream: tokio::net::TcpStream,
    ) -> Result<PeerId, NetworkError> {
        // Get peer address and check if banned
        let peer_addr = stream.peer_addr()?;
        if self.is_banned(&peer_addr.ip()) {
            warn!("Rejecting connection from banned IP {}", peer_addr.ip());
            return Err(NetworkError::ConnectionRefused(format!(
                "{} is banned",
                peer_addr.ip()
            )));
        }

        let our_height = *self.our_height.read();

        let (conn, handle) = Connection::accept(
            stream,
            self.config.magic,
            our_height,
            self.services(),
            self.event_tx.clone(),
            self.shutdown_tx.subscribe(),
            self.bytes_sent_counter(),
            self.bytes_recv_counter(),
            Arc::clone(&self.local_nonces),
        )
        .await?;

        let peer_id = handle.id;
        let addr = handle.addr;

        // Register with scoring system
        self.scoring.register_peer(peer_id, addr.ip());

        // Store the handle
        self.peers.write().insert(peer_id, handle);

        // Run the connection handler
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            if let Err(e) = conn.run().await {
                debug!("Inbound connection ended: {}", e);
                self_clone.ban_obsolete(addr.ip(), &e);
            }
            // Remove peer on disconnect
            self_clone.peers.write().remove(&peer_id);
            self_clone.scoring.unregister_peer(peer_id);
        });

        Ok(peer_id)
    }

    /// Register a peer handle directly (tests capture its outbound messages).
    #[cfg(test)]
    pub(crate) fn insert_test_peer(&self, handle: PeerHandle) {
        self.peers.write().insert(handle.id, handle);
    }

    /// Send a message to a specific peer
    pub async fn send_to_peer(
        &self,
        peer_id: PeerId,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        let handle = self.peers.read().get(&peer_id).cloned();

        if let Some(handle) = handle {
            handle
                .send(msg)
                .await
                .map_err(|_| NetworkError::Disconnected)?;
            Ok(())
        } else {
            Err(NetworkError::PeerNotFound(peer_id))
        }
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast(&self, msg: NetworkMessage) {
        let peers = self.peers.read();
        for (peer_id, handle) in peers.iter() {
            if let Err(e) = handle.try_send(msg.clone()) {
                debug!("Failed to broadcast to peer {}: {}", peer_id, e);
            }
        }
    }

    /// Queue a timed ping to every connected peer (the `ping` RPC); each pong updates
    /// that peer's pingtime
    pub fn ping_all(&self) {
        self.broadcast(NetworkMessage::Ping(0));
    }

    /// Relay a raw C++-format masternode broadcast (`mnb`) to all connected peers
    pub fn broadcast_masternode_broadcast(&self, bytes: Vec<u8>) {
        self.broadcast(NetworkMessage::MasternodeBroadcast(bytes));
    }

    /// Broadcast a block inv to all connected peers (standard Bitcoin inv/getdata protocol).
    ///
    /// Instead of pushing full block data, we announce the block hash via an `inv` message.
    /// Peers that don't have the block will respond with `getdata`, and we serve the full
    /// block in response. This matches the standard Bitcoin/Divi block announcement protocol.
    pub fn broadcast_block_inv(&self, block_hash: Hash256) {
        let inv_item = InvItem::new(InvType::Block, block_hash);
        let msg = NetworkMessage::Inv(vec![inv_item]);
        let peers = self.peers.read();
        let peer_count = peers.len();
        for (peer_id, handle) in peers.iter() {
            if let Err(e) = handle.try_send(msg.clone()) {
                debug!("Failed to send block inv to peer {}: {}", peer_id, e);
            }
        }
        info!("Broadcast block inv {} to {} peers", block_hash, peer_count);
    }

    /// Broadcast a block inv to all connected peers except the one specified.
    ///
    /// Used when relaying a block received from a peer to all other peers.
    pub fn broadcast_block_inv_except(&self, block_hash: Hash256, exclude: PeerId) {
        let inv_item = InvItem::new(InvType::Block, block_hash);
        let msg = NetworkMessage::Inv(vec![inv_item]);
        let peers = self.peers.read();
        let mut sent_count = 0;
        for (peer_id, handle) in peers.iter() {
            if *peer_id != exclude {
                if let Err(e) = handle.try_send(msg.clone()) {
                    debug!("Failed to send block inv to peer {}: {}", peer_id, e);
                } else {
                    sent_count += 1;
                }
            }
        }
        debug!(
            "Relayed block inv {} to {} peers (excluding {})",
            block_hash, sent_count, exclude
        );
    }

    /// Send a full block to a specific peer (in response to a getdata request).
    ///
    /// Uses async `send` with a timeout for reliable delivery.
    pub async fn send_block_to_peer(
        &self,
        peer_id: PeerId,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        let handle = self.peers.read().get(&peer_id).cloned();

        if let Some(handle) = handle {
            match tokio::time::timeout(Duration::from_secs(10), handle.send(msg)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => {
                    warn!("Failed to send block to peer {}: {}", peer_id, e);
                    Err(NetworkError::Disconnected)
                }
                Err(_) => {
                    warn!("Timeout sending block to peer {}", peer_id);
                    Err(NetworkError::Timeout)
                }
            }
        } else {
            Err(NetworkError::PeerNotFound(peer_id))
        }
    }

    /// Broadcast a message to all peers except one
    pub fn broadcast_except(&self, msg: NetworkMessage, exclude: PeerId) {
        let peers = self.peers.read();
        for (peer_id, handle) in peers.iter() {
            if *peer_id != exclude {
                if let Err(e) = handle.try_send(msg.clone()) {
                    debug!("Failed to broadcast to peer {}: {}", peer_id, e);
                }
            }
        }
    }

    /// Disconnect a peer
    pub fn disconnect(&self, peer_id: PeerId) {
        if self.peers.write().remove(&peer_id).is_some() {
            debug!("Disconnected peer {}", peer_id);
        }
    }

    /// Disconnect all peers
    pub fn disconnect_all(&self) {
        let _ = self.shutdown_tx.send(());
        self.peers.write().clear();
    }

    /// Get network traffic totals across all peers
    ///
    /// Returns (total_bytes_sent, total_bytes_received)
    pub fn get_net_totals(&self) -> (u64, u64) {
        let sent = self.total_bytes_sent.load(Ordering::Relaxed);
        let recv = self.total_bytes_recv.load(Ordering::Relaxed);
        (sent, recv)
    }

    /// Get reference to total bytes sent counter (for Connection to update)
    pub(crate) fn bytes_sent_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.total_bytes_sent)
    }

    /// Get reference to total bytes received counter (for Connection to update)
    pub(crate) fn bytes_recv_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.total_bytes_recv)
    }

    /// Get set of currently connected peer addresses
    pub fn connected_addresses(&self) -> HashSet<SocketAddr> {
        self.peers.read().values().map(|p| p.addr).collect()
    }

    /// Compute exponential backoff duration for a given consecutive failure count.
    ///
    /// Starts at 30 seconds, doubles each failure, capped at 30 minutes.
    /// Peers that have failed 5+ times will be skipped for at least 16 minutes.
    fn backoff_duration(failures: u32) -> Duration {
        // base = 30s, cap = 30 min
        let base_secs = 30u64;
        let max_secs = 30 * 60u64; // 30 minutes
        let multiplier = 2u64.saturating_pow(failures.saturating_sub(1).min(10));
        Duration::from_secs((base_secs.saturating_mul(multiplier)).min(max_secs))
    }

    /// Check whether a static peer is ready to retry based on its backoff state.
    ///
    /// Returns `true` if we should attempt a connection (i.e., enough time has passed).
    fn peer_backoff_ready(&self, addr: SocketAddr) -> bool {
        let backoff = self.static_peer_backoff.read();
        match backoff.get(&addr) {
            None => true, // Never attempted — go ahead
            Some((failures, last_attempt)) => {
                if *failures == 0 {
                    return true;
                }
                last_attempt.elapsed() >= Self::backoff_duration(*failures)
            }
        }
    }

    /// Record a static-peer connection failure, incrementing its backoff counter.
    fn record_static_peer_failure(&self, addr: SocketAddr) {
        let mut backoff = self.static_peer_backoff.write();
        let entry = backoff.entry(addr).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
        let delay = Self::backoff_duration(entry.0);
        debug!(
            "Static peer {} failure #{} — next retry in {:.0}s",
            addr,
            entry.0,
            delay.as_secs_f64()
        );
    }

    /// Record a successful connection to a static peer, resetting its backoff.
    fn record_static_peer_success(&self, addr: SocketAddr) {
        self.static_peer_backoff.write().remove(&addr);
    }

    /// Periodic maintenance loop that ensures we maintain target outbound peer count.
    ///
    /// Runs every 30 seconds and reconnects to peers if we've dropped below
    /// `max_outbound`. Tries added nodes first, then static peers (with exponential
    /// backoff for repeatedly-failing peers), then DNS seeds.
    ///
    /// Backoff schedule for static peers (consecutive failures → min wait before retry):
    ///   1 failure  → 30 s
    ///   2 failures → 1 min
    ///   3 failures → 2 min
    ///   4 failures → 4 min
    ///   5 failures → 8 min
    ///   6 failures → 16 min
    ///   7+ failures → 30 min (cap)
    pub async fn run_maintenance(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            let outbound = self.outbound_count();
            let target = self.config.max_outbound;

            if outbound >= target {
                continue;
            }

            info!(
                "Peer maintenance: {}/{} outbound peers, attempting reconnection",
                outbound, target
            );

            // Snapshot connected + connecting addresses to avoid duplicates
            let connected = self.connected_addresses();

            // 1. Try added nodes first (manually added via RPC)
            let added: Vec<SocketAddr> = self.added_nodes.read().iter().copied().collect();
            for addr in added {
                if !self.can_connect_outbound() {
                    break;
                }
                if connected.contains(&addr) || self.connecting_addrs.read().contains(&addr) {
                    continue;
                }
                if self.is_banned(&addr.ip()) {
                    continue;
                }
                // Added nodes also respect backoff if they keep failing
                if !self.peer_backoff_ready(addr) {
                    debug!("Skipping added node {} (in backoff)", addr);
                    continue;
                }
                info!("Reconnecting to added node: {}", addr);
                let self_clone = Arc::clone(&self);
                tokio::spawn(async move {
                    let self_for_record = Arc::clone(&self_clone);
                    match self_clone.connect_to_peer(addr).await {
                        Ok(_) => {
                            self_for_record.record_static_peer_success(addr);
                        }
                        Err(e) => {
                            debug!("Failed to reconnect to added node {}: {}", addr, e);
                            self_for_record.record_static_peer_failure(addr);
                        }
                    }
                });
            }

            // 2. Try static peers (with exponential backoff for known-failing peers)
            if self.can_connect_outbound() {
                let static_peers = self.config.static_peers.clone();
                for addr in static_peers {
                    if !self.can_connect_outbound() {
                        break;
                    }
                    if connected.contains(&addr) || self.connecting_addrs.read().contains(&addr) {
                        continue;
                    }
                    if self.is_banned(&addr.ip()) {
                        continue;
                    }
                    if !self.peer_backoff_ready(addr) {
                        debug!("Skipping static peer {} (in backoff)", addr);
                        continue;
                    }
                    info!("Reconnecting to static peer: {}", addr);
                    let self_clone = Arc::clone(&self);
                    tokio::spawn(async move {
                        let self_for_record = Arc::clone(&self_clone);
                        match self_clone.connect_to_peer(addr).await {
                            Ok(_) => {
                                self_for_record.record_static_peer_success(addr);
                            }
                            Err(e) => {
                                debug!("Failed to reconnect to static peer {}: {}", addr, e);
                                self_for_record.record_static_peer_failure(addr);
                            }
                        }
                    });
                }
            }

            // 3. Re-query DNS seeds as last resort
            if self.can_connect_outbound() && !self.config.dns_seeds.is_empty() {
                info!("Re-querying DNS seeds for peers");
                Arc::clone(&self).discover_peers().await;
            }
        }
    }
}

/// Create a peer manager with mainnet configuration
pub fn mainnet_peer_manager(listen_addr: Option<SocketAddr>) -> Arc<PeerManager> {
    let config = PeerManagerConfig {
        magic: crate::MAINNET_MAGIC,
        dns_seeds: vec!["autoseeds.diviseed.diviproject.org".to_string()],
        static_peers: vec![
            "178.62.195.16:51472".parse().unwrap(),
            "178.62.221.33:51472".parse().unwrap(),
            "178.128.251.20:51472".parse().unwrap(),
        ],
        listen_addr,
        ..Default::default()
    };
    PeerManager::new(config)
}

/// Create a peer manager with testnet configuration
pub fn testnet_peer_manager(listen_addr: Option<SocketAddr>) -> Arc<PeerManager> {
    let config = PeerManagerConfig {
        magic: crate::TESTNET_MAGIC,
        dns_seeds: vec!["autoseeds.tiviseed.diviproject.org".to_string()],
        listen_addr,
        default_port: 51474, // Testnet P2P port
        ..Default::default()
    };
    PeerManager::new(config)
}

/// Create a peer manager with regtest configuration
pub fn regtest_peer_manager(listen_addr: Option<SocketAddr>) -> Arc<PeerManager> {
    let config = PeerManagerConfig {
        magic: crate::REGTEST_MAGIC,
        dns_seeds: vec![],
        listen_addr,
        ..Default::default()
    };
    PeerManager::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager_creation() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert_eq!(pm.peer_count(), 0);
    }

    #[test]
    fn test_mainnet_config() {
        let pm = mainnet_peer_manager(None);
        assert_eq!(pm.config.magic, crate::MAINNET_MAGIC);
    }

    #[test]
    fn test_testnet_config() {
        let pm = testnet_peer_manager(None);
        assert_eq!(pm.config.magic, crate::TESTNET_MAGIC);
    }

    /// Log sink for `tracing` output in one test.
    #[derive(Clone, Default)]
    struct LogBuf(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_no_dns_discovery_log_when_seed_list_empty() {
        let buf = LogBuf::default();
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        // current-thread runtime: the default subscriber covers the awaited call
        let _guard = tracing::subscriber::set_default(subscriber);

        let pm = regtest_peer_manager(None);
        assert!(pm.config.dns_seeds.is_empty());
        Arc::clone(&pm).discover_peers().await;
        tracing::info!("log capture marker");

        let logs = String::from_utf8(buf.0.lock().clone()).unwrap();
        assert!(
            logs.contains("log capture marker"),
            "capture not working: {:?}",
            logs
        );
        assert!(
            !logs.contains("Discovering peers from DNS seeds"),
            "empty seed list still logged discovery: {:?}",
            logs
        );
    }

    #[test]
    fn test_regtest_config() {
        let pm = regtest_peer_manager(None);
        assert_eq!(pm.config.magic, crate::REGTEST_MAGIC);
        assert!(pm.config.dns_seeds.is_empty());
    }

    #[test]
    fn test_height_update() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        pm.set_height(12345);
        assert_eq!(*pm.our_height.read(), 12345);
    }

    #[test]
    fn test_added_nodes() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let addr: SocketAddr = "192.168.1.100:51472".parse().unwrap();

        // Initially no added nodes
        assert!(pm.get_added_node_info().is_empty());
        assert!(!pm.is_added_node(&addr));

        // Add a node
        assert!(pm.add_node(addr));
        assert!(pm.is_added_node(&addr));
        assert_eq!(pm.get_added_node_info().len(), 1);

        // Adding same node again returns false
        assert!(!pm.add_node(addr));
        assert_eq!(pm.get_added_node_info().len(), 1);

        // Remove the node
        assert!(pm.remove_added_node(&addr));
        assert!(!pm.is_added_node(&addr));
        assert!(pm.get_added_node_info().is_empty());

        // Removing non-existent node returns false
        assert!(!pm.remove_added_node(&addr));
    }

    #[test]
    fn test_connecting_status() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let addr: SocketAddr = "192.168.1.100:51472".parse().unwrap();

        // Add a node
        pm.add_node(addr);

        // Initially not connecting (no connection attempt started)
        let info = pm.get_added_node_info();
        assert_eq!(info.len(), 1);
        assert!(!info[0].connected);
        assert!(!info[0].connecting);

        // Manually add to connecting_addrs to simulate connection in progress
        pm.connecting_addrs.write().insert(addr);

        // Now should show as connecting
        let info = pm.get_added_node_info();
        assert!(!info[0].connected);
        assert!(info[0].connecting);

        // Remove from connecting
        pm.connecting_addrs.write().remove(&addr);

        // Back to not connecting
        let info = pm.get_added_node_info();
        assert!(!info[0].connected);
        assert!(!info[0].connecting);
    }

    // ============================================================
    // MISSING TESTS: ban, score, peer counts, PrivateDivi configs
    // ============================================================

    #[test]
    fn test_ban_ip_and_check() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();

        // Initially not banned
        assert!(!pm.is_banned(&ip));

        // Ban the IP
        pm.ban_ip(ip, std::time::Duration::from_secs(3600), "test ban");

        // Now it should be banned
        assert!(pm.is_banned(&ip));
    }

    #[test]
    fn test_unban_ip() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let ip: std::net::IpAddr = "10.0.0.6".parse().unwrap();

        pm.ban_ip(ip, std::time::Duration::from_secs(3600), "test");
        assert!(pm.is_banned(&ip));

        pm.unban_ip(&ip);
        assert!(!pm.is_banned(&ip));
    }

    #[test]
    fn test_banned_ip_not_connected_peers() {
        // Banning an IP should not cause panic when no peers are connected
        let pm = PeerManager::new(PeerManagerConfig::default());
        let ip: std::net::IpAddr = "10.0.0.7".parse().unwrap();

        // Ban with no peers — should not panic
        pm.ban_ip(ip, std::time::Duration::from_secs(3600), "test");
        assert!(pm.is_banned(&ip));
        assert_eq!(pm.peer_count(), 0);
    }

    #[test]
    fn test_peer_count_starts_at_zero() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert_eq!(pm.peer_count(), 0);
        assert_eq!(pm.inbound_count(), 0);
        assert_eq!(pm.outbound_count(), 0);
    }

    #[test]
    fn test_can_connect_outbound_when_empty() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert!(pm.can_connect_outbound());
    }

    #[test]
    fn test_peer_addresses_empty() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert!(pm.peer_addresses().is_empty());
    }

    #[test]
    fn test_connected_peers_empty() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert!(pm.connected_peers().is_empty());
    }

    #[test]
    fn test_get_peer_info_empty() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert!(pm.get_peer_info().is_empty());
    }

    #[test]
    fn test_privatedivi_mainnet_peer_manager() {
        use crate::constants::PRIVATEDIVI_MAINNET_MAGIC;
        let config = PeerManagerConfig {
            magic: PRIVATEDIVI_MAINNET_MAGIC,
            ..Default::default()
        };
        let pm = PeerManager::new(config);
        assert_eq!(pm.config.magic, PRIVATEDIVI_MAINNET_MAGIC);
        assert_eq!(pm.config.magic, [0x70, 0xd2, 0x76, 0x11]);
    }

    #[test]
    fn test_privatedivi_testnet_peer_manager() {
        use crate::constants::PRIVATEDIVI_TESTNET_MAGIC;
        let config = PeerManagerConfig {
            magic: PRIVATEDIVI_TESTNET_MAGIC,
            default_port: 52474,
            ..Default::default()
        };
        let pm = PeerManager::new(config);
        assert_eq!(pm.config.magic, PRIVATEDIVI_TESTNET_MAGIC);
        assert_eq!(pm.config.magic, [0x70, 0xd1, 0x76, 0x12]);
        assert_eq!(pm.config.default_port, 52474);
    }

    #[test]
    fn test_add_multiple_nodes() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:51472".parse().unwrap(),
            "10.0.0.2:51472".parse().unwrap(),
            "10.0.0.3:51472".parse().unwrap(),
        ];

        for addr in &addrs {
            assert!(pm.add_node(*addr));
        }

        assert_eq!(pm.get_added_node_info().len(), 3);

        // All should be registered
        for addr in &addrs {
            assert!(pm.is_added_node(addr));
        }
    }

    fn local_only(listen_addr: Option<SocketAddr>, proxy: Option<SocketAddr>) -> PeerManagerConfig {
        PeerManagerConfig {
            magic: crate::REGTEST_MAGIC,
            dns_seeds: vec![],
            static_peers: vec![],
            listen_addr,
            proxy,
            ..Default::default()
        }
    }

    /// With a proxy set, the outbound P2P connection goes through it (SOCKS5 CONNECT
    /// to the peer) and completes the handshake end to end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_outbound_connection_goes_through_socks5_proxy() {
        let listen: SocketAddr = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let server = PeerManager::new(local_only(Some(listen), None));
        tokio::spawn(Arc::clone(&server).start());
        let (proxy, seen) = crate::socks5::stub::start().await;
        let client = PeerManager::new(local_only(None, Some(proxy)));
        assert_eq!(client.proxy(), Some(proxy));

        let mut connected = false;
        for _ in 0..50 {
            if Arc::clone(&client).connect_to_peer(listen).await.is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(connected, "could not connect through the proxy");
        // Handshake done over the proxied stream: the server sees one inbound peer
        let mut inbound = 0;
        for _ in 0..50 {
            inbound = server.inbound_count();
            if inbound == 1 && client.outbound_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(inbound, 1);
        assert_eq!(client.outbound_count(), 1);
        assert!(!seen.lock().is_empty() && seen.lock().iter().all(|t| *t == listen));
        client.disconnect_all();
        server.disconnect_all();
    }

    /// A dead proxy must fail the connection, never fall back to connecting directly.
    #[tokio::test]
    async fn test_dead_proxy_does_not_fall_back_to_direct() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let dead_proxy = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let client = PeerManager::new(local_only(None, Some(dead_proxy)));
        let err = Arc::clone(&client).connect_to_peer(target_addr).await;
        assert!(err.is_err());
        let direct = tokio::time::timeout(Duration::from_millis(300), target.accept()).await;
        assert!(direct.is_err(), "connected to the peer directly");
    }

    #[test]
    fn test_net_totals_start_at_zero() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let (sent, recv) = pm.get_net_totals();
        assert_eq!(sent, 0);
        assert_eq!(recv, 0);
    }

    #[test]
    fn test_scoring_register_unregister() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let peer_id: crate::peer::PeerId = 999;
        let ip: std::net::IpAddr = "192.168.5.5".parse().unwrap();

        pm.scoring().register_peer(peer_id, ip);
        assert!(pm.scoring().get_stats(peer_id).is_some());

        pm.scoring().unregister_peer(peer_id);
        assert!(pm.scoring().get_stats(peer_id).is_none());
    }

    #[test]
    fn test_misbehavior_reporting_no_panic_without_peer() {
        // Reporting misbehavior for a non-registered peer should not panic
        let pm = PeerManager::new(PeerManagerConfig::default());
        let peer_id: crate::peer::PeerId = 42;
        pm.report_misbehavior(peer_id, crate::scoring::Misbehavior::InvalidMessage);
        // No panic = success
    }

    #[test]
    fn test_disconnect_nonexistent_peer_no_panic() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        // Disconnecting a non-existent peer should not panic
        pm.disconnect(9999);
    }

    #[test]
    fn test_retry_delay_fresh_ip() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let addr: SocketAddr = "10.0.0.9:51472".parse().unwrap();
        // Retry delay for a fresh IP should be 1 second (no failures)
        let delay = pm.retry_delay(addr);
        assert_eq!(delay, std::time::Duration::from_secs(1));
    }
}
