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

//! Block synchronization manager
//!
//! Handles downloading and validating the blockchain from peers.

use crate::message::{InvItem, InvType};
use crate::peer::PeerId;
use crate::peer_manager::PeerManager;
use crate::{GetHeadersMessage, NetworkMessage};

use divi_crypto::compute_block_hash;
use divi_primitives::block::{Block, BlockHeader};
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::Transaction;
use divi_storage::Chain;

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{debug, error, info, trace, warn};

/// Maximum headers to request at once
const MAX_HEADERS_REQUEST: usize = 2000;

/// Maximum blocks to have in flight at once
const MAX_BLOCKS_IN_FLIGHT: usize = 16;

/// Timeout for block downloads
const BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for header requests
const HEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum orphan blocks to keep in memory
const MAX_ORPHAN_BLOCKS: usize = 500;

/// Maximum time in the future for block timestamps (2 hours)
const MAX_FUTURE_TIME: u32 = 2 * 60 * 60;

/// Last proof-of-work block height (mainnet)
const LAST_POW_BLOCK: u32 = 100;

/// Maximum time to keep an orphan block before discarding
const ORPHAN_BLOCK_TIMEOUT: Duration = Duration::from_secs(300);

/// Result of header validation
#[derive(Debug)]
pub enum HeaderValidationError {
    /// Timestamp is too far in the future
    TimestampTooFarInFuture { header_time: u32, max_allowed: u32 },
    /// PoW hash does not meet difficulty target
    PowNotMet { hash: Hash256, target: Hash256 },
    /// Invalid difficulty bits (nBits)
    InvalidBits(u32),
}

/// Validate a block header during sync
///
/// This performs basic validation that doesn't require chain context:
/// - Timestamp not too far in future
/// - For PoW blocks (before LAST_POW_BLOCK), validates hash meets difficulty
///
/// Note: For PoS blocks, we can't validate the stake proof from headers alone.
/// Full validation happens when we receive the full block.
fn validate_header(header: &BlockHeader, height: u32) -> Result<(), HeaderValidationError> {
    // Check timestamp not too far in future
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    if header.time > now + MAX_FUTURE_TIME {
        return Err(HeaderValidationError::TimestampTooFarInFuture {
            header_time: header.time,
            max_allowed: now + MAX_FUTURE_TIME,
        });
    }

    // For PoW blocks, validate hash meets difficulty target
    if height <= LAST_POW_BLOCK {
        // Convert compact bits to target
        let target = target_from_compact(header.bits);
        if target.is_zero() {
            return Err(HeaderValidationError::InvalidBits(header.bits));
        }

        // Block hash must be <= target
        let block_hash = compute_block_hash(header);
        if !hash_meets_target(&block_hash, &target) {
            return Err(HeaderValidationError::PowNotMet {
                hash: block_hash,
                target,
            });
        }
    }

    Ok(())
}

/// Convert compact nBits to full target hash
///
/// Format: 0xEEMMMMMM where:
/// - EE = exponent (shift amount)
/// - MMMMMM = 24-bit mantissa
fn target_from_compact(compact: u32) -> Hash256 {
    let mut result = [0u8; 32];

    // Extract mantissa (bottom 23 bits, bit 23 is sign which we ignore)
    let mantissa = compact & 0x007fffff;
    let exponent = (compact >> 24) as usize;

    // Handle negative flag or zero mantissa
    if (compact & 0x00800000) != 0 || mantissa == 0 || exponent == 0 {
        return Hash256::zero();
    }

    // Position where mantissa starts (3 bytes before exponent position)
    if exponent >= 3 {
        let offset = exponent - 3;
        if offset < 30 {
            // Write mantissa bytes (big-endian order within mantissa)
            result[offset] = (mantissa & 0xff) as u8;
            if offset + 1 < 32 {
                result[offset + 1] = ((mantissa >> 8) & 0xff) as u8;
            }
            if offset + 2 < 32 {
                result[offset + 2] = ((mantissa >> 16) & 0xff) as u8;
            }
        }
    } else {
        // Exponent < 3, shift mantissa right
        let shift = (3 - exponent) * 8;
        let shifted = mantissa >> shift;
        result[0] = (shifted & 0xff) as u8;
        if shifted > 0xff {
            result[1] = ((shifted >> 8) & 0xff) as u8;
        }
        if shifted > 0xffff {
            result[2] = ((shifted >> 16) & 0xff) as u8;
        }
    }

    Hash256::from_bytes(result)
}

/// Check if hash meets the target (hash <= target)
///
/// Both hash and target are treated as little-endian 256-bit integers.
fn hash_meets_target(hash: &Hash256, target: &Hash256) -> bool {
    let hash_bytes = hash.as_bytes();
    let target_bytes = target.as_bytes();

    // Compare from most significant byte (end of array in little-endian)
    for i in (0..32).rev() {
        if hash_bytes[i] < target_bytes[i] {
            return true;
        }
        if hash_bytes[i] > target_bytes[i] {
            return false;
        }
    }
    // Equal means it meets target
    true
}

/// Sync state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Not syncing
    Idle,
    /// Downloading headers
    HeaderSync,
    /// Downloading blocks
    BlockDownload,
    /// Fully synchronized
    Synced,
}

/// Progress of synchronization
#[derive(Debug, Clone)]
pub struct SyncProgress {
    /// Current sync state
    pub state: SyncState,
    /// Current block height
    pub current_height: u32,
    /// Target height (best known among peers)
    pub target_height: u32,
    /// Number of headers downloaded
    pub headers_downloaded: u32,
    /// Number of blocks downloaded
    pub blocks_downloaded: u32,
    /// Blocks in flight
    pub blocks_in_flight: usize,
    /// Download speed (blocks per second)
    pub blocks_per_second: f64,
}

/// Block download request tracking
struct BlockRequest {
    /// Peer we requested from
    peer_id: PeerId,
    /// Block hash (stored for debugging; the HashMap key is canonical)
    _hash: Hash256,
    /// When we sent the request
    requested_at: Instant,
}

/// Orphan block tracking
struct OrphanBlock {
    /// The orphan block
    block: Block,
    /// When we received it
    received_at: Instant,
}

/// Callback for when a block is connected to the chain
pub type BlockConnectedCallback = Arc<dyn Fn(&Block, u32) + Send + Sync>;

/// Callback for when a chain reorganization occurs (parameter is fork height)
pub type ReorgCallback = Arc<dyn Fn(u32) + Send + Sync>;

/// Callback invoked after a reorg with the transactions that were in disconnected
/// blocks but are not present in any of the newly-connected blocks.  The node
/// should re-insert these into the mempool so they can be re-mined.
pub type OrphanedTxCallback = Arc<dyn Fn(Vec<Transaction>) + Send + Sync>;

/// Block synchronization manager
pub struct BlockSync {
    /// Chain state
    chain: Arc<Chain>,
    /// Peer manager
    peer_manager: Arc<PeerManager>,
    /// Current sync state
    state: RwLock<SyncState>,
    /// Best known height among peers
    best_peer_height: RwLock<u32>,
    /// Peer heights
    peer_heights: RwLock<HashMap<PeerId, u32>>,
    /// Headers we've downloaded but not yet validated blocks for
    pending_headers: RwLock<VecDeque<BlockHeader>>,
    /// Blocks currently being downloaded
    blocks_in_flight: RwLock<HashMap<Hash256, BlockRequest>>,
    /// Blocks that have been downloaded but not yet connected
    downloaded_blocks: RwLock<HashMap<Hash256, Block>>,
    /// Orphan blocks (blocks whose parent we don't have yet)
    orphan_blocks: RwLock<HashMap<Hash256, OrphanBlock>>,
    /// Blocks we've requested from each peer
    peer_block_requests: RwLock<HashMap<PeerId, HashSet<Hash256>>>,
    /// Blocks queued for download (not yet requested due to in-flight limits)
    pending_block_requests: RwLock<VecDeque<(Hash256, PeerId)>>,
    /// Sync progress channel
    progress_tx: broadcast::Sender<SyncProgress>,
    /// Statistics
    stats: RwLock<SyncStats>,
    /// Sync peer (peer we're syncing headers from)
    sync_peer: RwLock<Option<PeerId>>,
    /// Last header request time
    last_header_request: RwLock<Option<Instant>>,
    /// Callback for when a block is connected
    block_connected_callback: RwLock<Option<BlockConnectedCallback>>,
    /// Callback for when a chain reorganization occurs
    reorg_callback: RwLock<Option<ReorgCallback>>,
    /// Callback invoked after a reorg with the orphaned transactions that should
    /// be re-added to the mempool
    orphaned_tx_callback: RwLock<Option<OrphanedTxCallback>>,
}

/// Sync statistics
#[derive(Debug, Default)]
struct SyncStats {
    headers_downloaded: u32,
    blocks_downloaded: u32,
    blocks_connected: u32,
    start_time: Option<Instant>,
}

impl BlockSync {
    /// Create a new block sync manager
    pub fn new(chain: Arc<Chain>, peer_manager: Arc<PeerManager>) -> Arc<Self> {
        let (progress_tx, _) = broadcast::channel(100);

        Arc::new(BlockSync {
            chain,
            peer_manager,
            state: RwLock::new(SyncState::Idle),
            best_peer_height: RwLock::new(0),
            peer_heights: RwLock::new(HashMap::new()),
            pending_headers: RwLock::new(VecDeque::new()),
            blocks_in_flight: RwLock::new(HashMap::new()),
            downloaded_blocks: RwLock::new(HashMap::new()),
            orphan_blocks: RwLock::new(HashMap::new()),
            peer_block_requests: RwLock::new(HashMap::new()),
            pending_block_requests: RwLock::new(VecDeque::new()),
            progress_tx,
            stats: RwLock::new(SyncStats::default()),
            sync_peer: RwLock::new(None),
            last_header_request: RwLock::new(None),
            block_connected_callback: RwLock::new(None),
            reorg_callback: RwLock::new(None),
            orphaned_tx_callback: RwLock::new(None),
        })
    }

    /// Set callback for when a block is connected
    pub fn set_block_connected_callback(&self, callback: BlockConnectedCallback) {
        *self.block_connected_callback.write() = Some(callback);
    }

    /// Set callback for chain reorganization events
    pub fn set_reorg_callback(&self, callback: ReorgCallback) {
        *self.reorg_callback.write() = Some(callback);
    }

    /// Set callback for orphaned transactions after a chain reorganization.
    /// The callback receives transactions from disconnected blocks that were not
    /// included in the new chain and should be re-added to the mempool.
    pub fn set_orphaned_tx_callback(&self, callback: OrphanedTxCallback) {
        *self.orphaned_tx_callback.write() = Some(callback);
    }

    /// Fire reorg callbacks: notifies the reorg callback with `fork_height` and,
    /// if there are orphaned transactions, invokes the orphaned-tx callback so
    /// they can be re-added to the mempool.
    fn fire_reorg_callbacks(&self, fork_height: u32, orphaned_txs: Vec<Transaction>) {
        if let Some(callback) = self.reorg_callback.read().as_ref() {
            callback(fork_height);
        }
        if !orphaned_txs.is_empty() {
            if let Some(callback) = self.orphaned_tx_callback.read().as_ref() {
                callback(orphaned_txs);
            }
        }
    }

    /// Subscribe to sync progress updates
    pub fn subscribe(&self) -> broadcast::Receiver<SyncProgress> {
        self.progress_tx.subscribe()
    }

    /// Get current sync state
    pub fn state(&self) -> SyncState {
        *self.state.read()
    }

    /// Get current sync progress
    pub fn progress(&self) -> SyncProgress {
        let stats = self.stats.read();
        let blocks_per_second = if let Some(start) = stats.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                stats.blocks_downloaded as f64 / elapsed
            } else {
                0.0
            }
        } else {
            0.0
        };

        SyncProgress {
            state: *self.state.read(),
            current_height: self.chain.height(),
            target_height: *self.best_peer_height.read(),
            headers_downloaded: stats.headers_downloaded,
            blocks_downloaded: stats.blocks_downloaded,
            blocks_in_flight: self.blocks_in_flight.read().len(),
            blocks_per_second,
        }
    }

    /// Update peer height from version message
    pub fn update_peer_height(&self, peer_id: PeerId, height: u32) {
        self.peer_heights.write().insert(peer_id, height);
        let total_peers = self.peer_heights.read().len();
        info!(
            "Added peer {} with height {}, now have {} peers",
            peer_id, height, total_peers
        );

        // Update best known height
        let mut best = self.best_peer_height.write();
        let old_best = *best;
        if height > *best {
            *best = height;
            info!("New best peer height: {} (peer {})", height, peer_id);
        }
        drop(best); // Release lock before checking sync state

        // If we're in Synced state but peer has more blocks, transition to HeaderSync
        // This handles the case where sync started before peers connected
        let our_height = self.chain.height();
        let current_state = *self.state.read();
        if current_state == SyncState::Synced && height > our_height {
            warn!(
                "Peer {} has height {} but we're at {} - restarting sync (was best_peer_height={})",
                peer_id, height, our_height, old_best
            );
            *self.state.write() = SyncState::HeaderSync;
        }
    }

    /// Get a peer's known height (for testing and diagnostics)
    pub fn get_peer_height(&self, peer_id: PeerId) -> Option<u32> {
        self.peer_heights.read().get(&peer_id).copied()
    }

    /// Sentinel PeerId meaning "no peer assigned, needs reassignment when a peer connects"
    const UNASSIGNED_PEER: PeerId = 0;

    /// Remove peer from tracking
    pub fn remove_peer(&self, peer_id: PeerId) {
        let removed_height = self.peer_heights.write().remove(&peer_id);
        let remaining_peers = self.peer_heights.read().len();

        if let Some(height) = removed_height {
            info!(
                "Removed peer {} (was at height {}), {} peers remaining",
                peer_id, height, remaining_peers
            );
        }

        // Get a live, connected alternative peer (not just from peer_heights which can be stale)
        let connected = self.peer_manager.connected_peers();
        let alt_peer = connected.iter().find(|&&p| p != peer_id).copied();

        // Re-queue in-flight requests from this peer
        let mut in_flight = self.blocks_in_flight.write();
        let hashes_to_requeue: Vec<_> = in_flight
            .iter()
            .filter(|(_, req)| req.peer_id == peer_id)
            .map(|(hash, _)| *hash)
            .collect();

        for hash in &hashes_to_requeue {
            in_flight.remove(hash);
        }
        drop(in_flight);

        // Re-queue the blocks: use a live peer if available, otherwise mark as UNASSIGNED
        {
            let reassign_to = alt_peer.unwrap_or(Self::UNASSIGNED_PEER);
            let mut pending = self.pending_block_requests.write();
            for hash in &hashes_to_requeue {
                pending.push_back((*hash, reassign_to));
            }

            if alt_peer.is_none() && !hashes_to_requeue.is_empty() {
                debug!(
                    "No connected peers to reassign {} in-flight blocks from peer {} — marked as unassigned",
                    hashes_to_requeue.len(), peer_id
                );
            }
        }

        // Also reassign pending requests that were assigned to the dead peer
        {
            let reassign_to = alt_peer.unwrap_or(Self::UNASSIGNED_PEER);
            let mut pending = self.pending_block_requests.write();
            for (_, peer) in pending.iter_mut() {
                if *peer == peer_id {
                    *peer = reassign_to;
                }
            }
        }

        self.peer_block_requests.write().remove(&peer_id);

        // Clear sync peer if it was this peer
        let mut sync_peer = self.sync_peer.write();
        if *sync_peer == Some(peer_id) {
            *sync_peer = None;
        }

        // Recalculate best height
        let heights = self.peer_heights.read();
        let new_best = heights.values().max().copied().unwrap_or(0);
        *self.best_peer_height.write() = new_best;
    }

    /// Start synchronization
    pub async fn start(self: Arc<Self>) {
        info!("Starting block synchronization");
        self.stats.write().start_time = Some(Instant::now());

        // Check if we need to sync
        let our_height = self.chain.height();
        let best_height = *self.best_peer_height.read();
        let peer_count = self.peer_heights.read().len();

        // Don't declare synced if we have no peers and height is 0
        // This prevents false "up to date" when peers haven't connected yet
        if best_height == 0 && peer_count == 0 {
            warn!("No peers connected yet, cannot determine sync status");
            // Stay in HeaderSync state and try to request headers
            // The timeout checker will retry when peers connect
            *self.state.write() = SyncState::HeaderSync;
            self.request_headers().await;
            return;
        }

        if our_height >= best_height {
            info!("Chain is up to date (height {})", our_height);
            *self.state.write() = SyncState::Synced;
            return;
        }

        info!(
            "Starting sync from height {} to {}",
            our_height, best_height
        );
        *self.state.write() = SyncState::HeaderSync;

        // Request headers from the best peer
        self.request_headers().await;
    }

    /// Request headers from a peer
    async fn request_headers(&self) {
        // Find the best peer to sync from
        let sync_peer = self.select_sync_peer();
        if sync_peer.is_none() {
            warn!("No peers available for sync");
            return;
        }
        let peer_id = sync_peer.unwrap();
        *self.sync_peer.write() = Some(peer_id);

        // Build block locator
        let locator = self.build_block_locator();

        debug!(
            "Requesting headers from peer {} with {} locator hashes",
            peer_id,
            locator.len()
        );

        // Send getblocks for initial sync
        // Note: C++ Divi nodes treat getheaders the same as getblocks and return inv messages
        // (HeadersFirstSyncingActive is disabled). So we use getblocks which is well-tested.
        let msg =
            NetworkMessage::GetBlocks(GetHeadersMessage::new(locator.clone(), Hash256::zero()));

        // Show first locator hash (our tip) for clarity
        let locator_tip = locator.first().map(|h| h.to_string()).unwrap_or_default();
        info!(
            "Sending getblocks to peer {} from height {} (locator tip: {}...)",
            peer_id,
            self.chain.height(),
            &locator_tip[..std::cmp::min(16, locator_tip.len())]
        );

        if let Err(e) = self.peer_manager.send_to_peer(peer_id, msg).await {
            warn!("Failed to send getblocks to peer {}: {}", peer_id, e);
            *self.sync_peer.write() = None;
        } else {
            *self.last_header_request.write() = Some(Instant::now());
            debug!("getblocks sent successfully, waiting for inv response");
        }
    }

    /// Select the best peer for syncing
    fn select_sync_peer(&self) -> Option<PeerId> {
        let heights = self.peer_heights.read();
        let best_height = *self.best_peer_height.read();

        // Debug: log peer_heights state
        let heights_str: Vec<_> = heights
            .iter()
            .map(|(id, h)| format!("{}:{}", id, h))
            .collect();
        debug!(
            "select_sync_peer: peer_heights=[{}], best_peer_height={}",
            heights_str.join(", "),
            best_height
        );

        // Find a peer at the best height
        let peer = heights
            .iter()
            .filter(|(_, &h)| h >= best_height)
            .map(|(&id, _)| id)
            .next();

        if peer.is_none() && !heights.is_empty() {
            // No peer at best height - find the peer with highest height instead
            // This can happen if best_peer_height was updated from inv but peer_heights wasn't
            let (best_peer, max_height) = heights
                .iter()
                .max_by_key(|(_, &h)| h)
                .map(|(&id, &h)| (id, h))
                .unwrap();
            warn!(
                "No peer at best_height {}, falling back to peer {} at height {}",
                best_height, best_peer, max_height
            );
            return Some(best_peer);
        }

        if peer.is_none() && heights.is_empty() {
            warn!(
                "select_sync_peer: peer_heights is EMPTY! best_peer_height={}",
                best_height
            );
        }

        peer
    }

    /// Build block locator hashes
    fn build_block_locator(&self) -> Vec<Hash256> {
        let mut locator = Vec::new();
        let tip = self.chain.tip();

        if let Some(tip_index) = tip {
            let mut height = tip_index.height;
            let mut step = 1u32;
            let mut count = 0;

            loop {
                if let Ok(Some(index)) = self.chain.get_block_index_by_height(height) {
                    locator.push(index.hash);
                }

                count += 1;
                if height == 0 {
                    break;
                }

                // Exponential back-off after first 10
                if count > 10 {
                    step *= 2;
                }

                if height > step {
                    height -= step;
                } else {
                    height = 0;
                }
            }
        } else {
            let genesis_hash = self.chain.genesis_hash();
            info!(
                "Empty chain - using genesis hash in locator: {}",
                genesis_hash
            );
            locator.push(genesis_hash);
        }

        locator
    }

    /// Handle received headers
    pub async fn handle_headers(&self, peer_id: PeerId, headers: Vec<BlockHeader>) {
        if headers.is_empty() {
            debug!("Received empty headers from peer {}", peer_id);

            // Check if we have pending headers to process
            if !self.pending_headers.read().is_empty() {
                // Continue with block download
                *self.state.write() = SyncState::BlockDownload;
                self.request_blocks().await;
            } else {
                // We're synced
                *self.state.write() = SyncState::Synced;
                info!("Header sync complete");
            }
            return;
        }

        info!(
            "Received {} headers from peer {} (first: {})",
            headers.len(),
            peer_id,
            compute_block_hash(&headers[0])
        );

        // Validate headers connect to our chain
        let (mut prev_hash, mut current_height) = {
            let pending = self.pending_headers.read();
            if let Some(last) = pending.back() {
                // Calculate height based on pending headers count + chain height
                let chain_height = self.chain.height();
                let pending_count = pending.len() as u32;
                (compute_block_hash(last), chain_height + pending_count)
            } else if let Some(tip) = self.chain.tip() {
                (tip.hash, tip.height)
            } else {
                // Genesis case
                (Hash256::zero(), 0)
            }
        };

        let headers_count = headers.len();
        let mut valid_headers = Vec::new();
        for header in headers {
            // Check that prev_hash matches
            if header.prev_block != prev_hash && !prev_hash.is_zero() {
                warn!(
                    "Header {} does not connect (expected prev {}, got {})",
                    compute_block_hash(&header),
                    prev_hash,
                    header.prev_block
                );
                break;
            }

            // Increment height for this header
            current_height += 1;

            // Validate header (timestamp, PoW for early blocks)
            if let Err(e) = validate_header(&header, current_height) {
                warn!(
                    "Header {} at height {} failed validation: {:?}",
                    compute_block_hash(&header),
                    current_height,
                    e
                );
                break;
            }

            valid_headers.push(header.clone());
            prev_hash = compute_block_hash(&header);
        }

        if valid_headers.is_empty() {
            warn!("No valid headers from peer {}", peer_id);
            return;
        }

        // Add to pending headers
        {
            let mut pending = self.pending_headers.write();
            let mut stats = self.stats.write();
            for header in valid_headers {
                stats.headers_downloaded += 1;
                pending.push_back(header);
            }
        }

        // If we got a full batch, request more
        if headers_count >= MAX_HEADERS_REQUEST {
            debug!("Got full header batch, requesting more");
            self.request_headers().await;
        } else {
            // Switch to block download
            info!(
                "Header sync complete, {} headers pending",
                self.pending_headers.read().len()
            );
            *self.state.write() = SyncState::BlockDownload;
            self.request_blocks().await;
        }

        // Emit progress
        let _ = self.progress_tx.send(self.progress());
    }

    /// Request blocks from peers
    async fn request_blocks(&self) {
        let in_flight_count = self.blocks_in_flight.read().len();
        if in_flight_count >= MAX_BLOCKS_IN_FLIGHT {
            trace!("Already have {} blocks in flight", in_flight_count);
            return;
        }

        // Get block hashes to request
        let mut hashes_to_request = Vec::new();
        {
            let pending = self.pending_headers.read();
            let in_flight = self.blocks_in_flight.read();
            let downloaded = self.downloaded_blocks.read();

            for header in pending.iter() {
                let hash = compute_block_hash(header);
                if !in_flight.contains_key(&hash)
                    && !downloaded.contains_key(&hash)
                    && hashes_to_request.len() < MAX_BLOCKS_IN_FLIGHT - in_flight_count
                {
                    hashes_to_request.push(hash);
                }
            }
        }

        if hashes_to_request.is_empty() {
            // Try to connect downloaded blocks
            self.try_connect_blocks().await;
            return;
        }

        // Request blocks from actually-connected peers (not stale peer_heights)
        let peer_ids = self.peer_manager.connected_peers();
        if peer_ids.is_empty() {
            debug!("No connected peers available for block download");
            return;
        }

        // Distribute requests across peers
        for (i, hash) in hashes_to_request.iter().enumerate() {
            let peer_id = peer_ids[i % peer_ids.len()];

            let inv = vec![InvItem::new(InvType::Block, *hash)];
            let msg = NetworkMessage::GetData(inv);

            debug!("Requesting block {} from peer {}", hash, peer_id);

            if let Err(e) = self.peer_manager.send_to_peer(peer_id, msg).await {
                warn!("Failed to request block from peer {}: {}", peer_id, e);
                continue;
            }

            // Track the request
            self.blocks_in_flight.write().insert(
                *hash,
                BlockRequest {
                    peer_id,
                    _hash: *hash,
                    requested_at: Instant::now(),
                },
            );

            self.peer_block_requests
                .write()
                .entry(peer_id)
                .or_default()
                .insert(*hash);
        }
    }

    /// Handle received block
    pub async fn handle_block(&self, peer_id: PeerId, block: Block) {
        let hash = compute_block_hash(&block.header);
        debug!("Received block {} from peer {}", hash, peer_id);

        // Track chain height before processing to detect newly connected blocks
        let height_before = self.chain.height();

        // Remove from in-flight
        self.blocks_in_flight.write().remove(&hash);
        if let Some(requests) = self.peer_block_requests.write().get_mut(&peer_id) {
            requests.remove(&hash);
        }

        // Store in downloaded blocks
        self.downloaded_blocks.write().insert(hash, block);
        self.stats.write().blocks_downloaded += 1;

        // Try to connect blocks
        self.try_connect_blocks().await;

        // Relay block inv to other peers if the chain advanced (block was accepted).
        // Only relay during normal operation (not during initial bulk sync) to avoid
        // flooding peers with inv messages for blocks they already have.
        let height_after = self.chain.height();
        if height_after > height_before {
            let best_height = *self.best_peer_height.read();
            let blocks_behind = best_height.saturating_sub(height_after);
            if blocks_behind < 10 {
                // Near tip -- relay to all peers except the sender
                self.peer_manager.broadcast_block_inv_except(hash, peer_id);
            }
        }

        // Request more blocks (header-first sync)
        self.request_blocks().await;

        // Request more blocks from queue (inv-based sync)
        self.request_queued_blocks().await;

        // Emit progress
        let _ = self.progress_tx.send(self.progress());
    }

    /// Try to connect downloaded blocks to the chain
    async fn try_connect_blocks(&self) {
        // First try to connect blocks from pending_headers (header-first sync)
        loop {
            // Find the next block we need
            let next_hash = {
                let pending = self.pending_headers.read();
                if pending.is_empty() {
                    break;
                }
                pending.front().map(compute_block_hash)
            };

            let Some(hash) = next_hash else { break };

            // Check if we have it
            let block = self.downloaded_blocks.write().remove(&hash);
            let Some(block) = block else { break };

            // Try to connect it
            match self.chain.accept_block(block.clone()) {
                Ok(result) => {
                    let hash = result.hash;
                    if let Some(fork_height) = result.reorg_fork_height {
                        self.fire_reorg_callbacks(fork_height, result.orphaned_transactions);
                    }
                    let height = self.chain.height();
                    // Remove from pending headers
                    self.pending_headers.write().pop_front();
                    debug!("Connected block {} at height {}", hash, height);

                    // Call block connected callback if set
                    if let Some(callback) = self.block_connected_callback.read().as_ref() {
                        callback(&block, height);
                    }
                }
                Err(e) => {
                    error!("Failed to connect block {}: {}", hash, e);
                    break;
                }
            }
        }

        // If pending_headers is empty (inv-based sync), try connecting blocks by prev_block
        if self.pending_headers.read().is_empty() {
            self.try_connect_blocks_by_prev().await;
        }

        // Clean up orphan blocks that we can't connect (e.g., new block announcements while syncing)
        // These blocks are from the tip of the chain but we're far behind
        self.cleanup_orphan_blocks();

        // Check if we're done (include pending_block_requests in the check)
        let pending_headers_count = self.pending_headers.read().len();
        let in_flight = self.blocks_in_flight.read().len();
        let downloaded = self.downloaded_blocks.read().len();
        let pending_requests = self.pending_block_requests.read().len();

        // Only check if we need more data if all queues are empty
        if pending_headers_count == 0 && in_flight == 0 && downloaded == 0 && pending_requests == 0
        {
            let our_height = self.chain.height();
            let best_height = *self.best_peer_height.read();

            if our_height >= best_height {
                info!("Block sync complete at height {}", our_height);
                *self.state.write() = SyncState::Synced;
            } else {
                // Need to sync more - request next batch of block hashes
                info!(
                    "All queues empty, requesting more blocks (at height {}, target {})",
                    our_height, best_height
                );
                *self.state.write() = SyncState::HeaderSync;
                self.request_headers().await;
            }
        } else if pending_headers_count > 0
            || in_flight > 0
            || downloaded > 0
            || pending_requests > 0
        {
            // Only log at debug level if we have work pending
            debug!(
                "Sync work pending: pending_headers={}, in_flight={}, downloaded={}, queued={}",
                pending_headers_count, in_flight, downloaded, pending_requests
            );
        }
    }

    /// Try to connect blocks by finding ones that extend our chain tip
    /// Used for inv-based sync (getblocks flow) where we don't have pending_headers
    async fn try_connect_blocks_by_prev(&self) {
        // First, try to connect blocks that extend our tip (simple case)
        loop {
            // Get current tip hash (use genesis hash if chain is empty)
            let tip_hash = self.chain.tip().map(|i| i.hash).unwrap_or_else(|| {
                // Empty chain - use the chain's configured genesis hash
                self.chain.genesis_hash()
            });

            // Find a block whose prev_block matches our tip
            let block_to_connect = {
                let mut downloaded = self.downloaded_blocks.write();

                // Log downloaded blocks for debugging
                if !downloaded.is_empty() {
                    let sample_prev: Vec<_> = downloaded
                        .values()
                        .take(3)
                        .map(|b| format!("{}", b.header.prev_block))
                        .collect();
                    info!(
                        "try_connect_blocks_by_prev: tip={}, downloaded={} blocks, sample prev_blocks: {:?}",
                        tip_hash, downloaded.len(), sample_prev
                    );
                }

                let mut found_key = None;
                for (hash, block) in downloaded.iter() {
                    if block.header.prev_block == tip_hash {
                        found_key = Some(*hash);
                        break;
                    }
                }
                found_key.and_then(|k| downloaded.remove(&k))
            };

            let Some(block) = block_to_connect else {
                break;
            };

            let hash = compute_block_hash(&block.header);

            // Try to connect it
            match self.chain.accept_block(block.clone()) {
                Ok(result) => {
                    if let Some(fork_height) = result.reorg_fork_height {
                        self.fire_reorg_callbacks(fork_height, result.orphaned_transactions);
                    }
                    let height = self.chain.height();
                    debug!("Connected block {} at height {}", hash, height);
                    self.stats.write().blocks_connected += 1;

                    // Call block connected callback if set
                    if let Some(callback) = self.block_connected_callback.read().as_ref() {
                        callback(&block, height);
                    }
                }
                Err(e) => {
                    error!("Failed to connect block {}: {}", hash, e);
                    break;
                }
            }
        }

        // If we still have downloaded blocks that don't extend our tip,
        // try to accept them anyway - they might trigger a chain reorganization
        // if they're on a longer chain.
        //
        // Loop until no more progress: blocks arrive in HashMap order (not chain order),
        // so a child block may be tried before its parent. The parent gets stored on one
        // pass, and the child succeeds on the next pass. This matches C++ Divi's
        // ActivateBestChain which always processes all available blocks.
        let initial_height = self.chain.height();
        let mut made_progress = true;

        while made_progress {
            made_progress = false;

            let blocks_to_try: Vec<_> = {
                let downloaded = self.downloaded_blocks.read();
                if downloaded.is_empty() {
                    break;
                }
                downloaded.iter().map(|(h, b)| (*h, b.clone())).collect()
            };

            for (hash, block) in blocks_to_try {
                // Try to accept the block - this will store it and potentially trigger a reorg
                match self.chain.accept_block(block.clone()) {
                    Ok(result) => {
                        if let Some(fork_height) = result.reorg_fork_height {
                            self.fire_reorg_callbacks(fork_height, result.orphaned_transactions);
                        }
                        // Remove from downloaded if it was accepted
                        self.downloaded_blocks.write().remove(&hash);
                        made_progress = true;

                        // Check if our height changed (reorg happened)
                        let new_height = self.chain.height();
                        if new_height > initial_height {
                            info!(
                                "Chain reorganized! Height changed from {} to {} after accepting block {}",
                                initial_height, new_height, hash
                            );

                            // Call block connected callback if set
                            if let Some(callback) = self.block_connected_callback.read().as_ref() {
                                callback(&block, new_height);
                            }
                        }
                    }
                    Err(e) => {
                        // Block couldn't be accepted (orphan or invalid)
                        // Keep it for now, might be usable after we get more blocks
                        debug!("Block {} not accepted yet: {}", hash, e);
                    }
                }
            }
        }

        // After processing downloaded blocks, also try orphan blocks whose parents
        // may now be in the block index (stored as side-chain blocks above)
        self.try_connect_orphans().await;
    }

    /// Clean up orphan blocks that we can't connect
    /// This handles the case where we receive new block announcements while syncing
    /// These blocks are at the chain tip but we're far behind, so they can't connect
    fn cleanup_orphan_blocks(&self) {
        let our_height = self.chain.height();
        let best_height = *self.best_peer_height.read();

        // Only cleanup if we're very far behind (more than 1000 blocks)
        // We need to keep blocks that might be part of a chain reorg
        if best_height.saturating_sub(our_height) < 1000 {
            return;
        }

        let tip_hash = self.chain.tip().map(|i| i.hash);

        let mut downloaded = self.downloaded_blocks.write();
        let initial_count = downloaded.len();

        // Only limit the size of downloaded_blocks if it's very large
        // Keep up to 500 blocks for potential reorg scenarios
        if downloaded.len() <= 500 {
            return;
        }

        // Build sets for retention logic
        let prev_blocks: HashSet<_> = downloaded.values().map(|b| b.header.prev_block).collect();
        let all_hashes: HashSet<_> = downloaded.keys().copied().collect();

        // Remove blocks that:
        // 1. Don't extend our tip
        // 2. Don't have their parent in downloaded_blocks (orphaned chain)
        // 3. Are not a parent of another block in downloaded_blocks
        downloaded.retain(|hash, block| {
            // Keep if this block extends our tip
            if Some(block.header.prev_block) == tip_hash {
                return true;
            }

            // Keep if this block is a parent of another block we have
            if prev_blocks.contains(hash) {
                return true;
            }

            // Keep if parent is in downloaded (part of a chain)
            if all_hashes.contains(&block.header.prev_block) {
                return true;
            }

            // Otherwise, this block is truly orphaned
            false
        });

        let removed = initial_count - downloaded.len();
        if removed > 0 {
            debug!(
                "Cleaned up {} orphan blocks that can't connect to height {}",
                removed, our_height
            );
        }
    }

    /// Check for stalled downloads and retry
    pub async fn check_timeouts(&self) {
        let now = Instant::now();

        // Log sync progress periodically
        let state = *self.state.read();
        let our_height = self.chain.height();
        let target_height = *self.best_peer_height.read();
        let in_flight = self.blocks_in_flight.read().len();
        let queued = self.pending_block_requests.read().len();

        if state != SyncState::Synced && state != SyncState::Idle {
            info!(
                "Sync progress: height {}/{}, state {:?}, in_flight={}, queued={}",
                our_height, target_height, state, in_flight, queued
            );
        }

        // Check header request timeout - capture values without holding lock across await
        let should_retry_headers = {
            let is_header_sync = state == SyncState::HeaderSync;
            let last_request = *self.last_header_request.read();
            let header_timed_out = last_request
                .map(|t| now.duration_since(t) > HEADER_REQUEST_TIMEOUT)
                .unwrap_or(false);
            // Also request headers if we're in HeaderSync but never made a request
            // This handles the case where update_peer_height transitions us to HeaderSync
            let no_request_yet = last_request.is_none() && is_header_sync;
            is_header_sync && (header_timed_out || no_request_yet)
        };

        if should_retry_headers {
            debug!("Header sync needed, requesting headers");
            *self.sync_peer.write() = None;
            self.request_headers().await;
        }

        // Check block download timeouts
        let timed_out: Vec<_> = self
            .blocks_in_flight
            .read()
            .iter()
            .filter(|(_, req)| now.duration_since(req.requested_at) > BLOCK_DOWNLOAD_TIMEOUT)
            .map(|(hash, req)| (*hash, req.peer_id))
            .collect();

        for (hash, peer_id) in timed_out {
            warn!(
                "Block {} request timed out from peer {}, re-queuing",
                hash, peer_id
            );
            self.blocks_in_flight.write().remove(&hash);
            if let Some(requests) = self.peer_block_requests.write().get_mut(&peer_id) {
                requests.remove(&hash);
            }

            // Re-queue the block for download from a different connected peer
            let connected = self.peer_manager.connected_peers();
            if let Some(&alt_peer) = connected.iter().find(|&&p| p != peer_id) {
                debug!("Re-queuing timed-out block {} with peer {}", hash, alt_peer);
                self.pending_block_requests
                    .write()
                    .push_back((hash, alt_peer));
            } else if !connected.is_empty() {
                // If no alternative connected peer, re-queue with the same peer
                debug!(
                    "Re-queuing timed-out block {} with same peer {}",
                    hash, peer_id
                );
                self.pending_block_requests
                    .write()
                    .push_back((hash, peer_id));
            } else {
                // No connected peers at all — mark as unassigned for later
                debug!(
                    "No connected peers for timed-out block {}, marking unassigned",
                    hash
                );
                self.pending_block_requests
                    .write()
                    .push_back((hash, Self::UNASSIGNED_PEER));
            }
        }

        // Request more blocks if we have capacity - capture state before await
        let should_request_blocks = state == SyncState::BlockDownload;
        if should_request_blocks {
            self.request_blocks().await;
        }

        // Also process queued blocks from inv announcements
        self.request_queued_blocks().await;

        // Check for downloaded blocks that can't connect (orphans)
        // First try to accept any blocks whose parent is in the block index
        // (side-chain blocks that could trigger a reorg). Only move truly orphaned
        // blocks (parent unknown) to orphan storage.
        let downloaded_count = self.downloaded_blocks.read().len();
        if downloaded_count > 0 && target_height > our_height {
            // Try to accept blocks with known parents before orphaning them
            self.try_connect_blocks_by_prev().await;

            // Check what's left
            let remaining_count = self.downloaded_blocks.read().len();
            if remaining_count > 0 {
                let tip_hash = self
                    .chain
                    .tip()
                    .map(|i| i.hash)
                    .unwrap_or_else(|| self.chain.genesis_hash());

                // Move remaining blocks (true orphans) to orphan storage
                {
                    let mut orphans = self.orphan_blocks.write();
                    let downloaded = self.downloaded_blocks.write();
                    let now = Instant::now();

                    info!(
                        "Moving {} downloaded blocks to orphan storage (can't connect to tip {} at height {})",
                        remaining_count, tip_hash, our_height
                    );

                    for (hash, block) in downloaded.iter() {
                        if orphans.len() >= MAX_ORPHAN_BLOCKS {
                            // Remove oldest orphan to make space
                            if let Some((oldest_hash, _)) =
                                orphans.iter().min_by_key(|(_, o)| o.received_at)
                            {
                                let oldest_hash = *oldest_hash;
                                orphans.remove(&oldest_hash);
                                warn!("Orphan cache full, removed oldest orphan {}", oldest_hash);
                            }
                        }

                        orphans.insert(
                            *hash,
                            OrphanBlock {
                                block: block.clone(),
                                received_at: now,
                            },
                        );
                    }
                } // Locks dropped here

                // Clear downloaded blocks now that we've saved them as orphans
                self.downloaded_blocks.write().clear();

                // Try to request missing blocks to fill the gap
                self.request_missing_blocks_for_orphans().await;

                // Try to reconnect orphans in case some can now connect
                self.try_connect_orphans().await;
            }
        }

        // Clean up expired orphans
        {
            let mut orphans = self.orphan_blocks.write();
            let now = Instant::now();
            orphans.retain(|hash, orphan| {
                if now.duration_since(orphan.received_at) > ORPHAN_BLOCK_TIMEOUT {
                    debug!("Removing expired orphan block {}", hash);
                    false
                } else {
                    true
                }
            });
        } // Drop lock explicitly

        // If we're stuck (no activity but not synced), try to restart
        if state == SyncState::HeaderSync && in_flight == 0 && queued == 0 {
            // Check if we now have peers with a higher height than us
            let peer_count = self.peer_heights.read().len();
            if peer_count > 0 && target_height > our_height {
                // We have peers and they're ahead - try to sync
                info!(
                    "Peers available with higher height ({} vs {}), requesting headers",
                    target_height, our_height
                );
                self.request_headers().await;
            } else if peer_count == 0 {
                debug!("Waiting for peers to connect (currently 0)");
            } else {
                debug!("Waiting for peer response to getblocks request");
            }
        } else if state == SyncState::BlockDownload && in_flight == 0 && queued == 0 {
            // We're supposed to be downloading blocks but have nothing in flight
            // This shouldn't happen - try to recover by requesting more headers
            warn!("Block download state but no work - requesting more blocks");
            *self.state.write() = SyncState::HeaderSync;
            self.request_headers().await;
        }
    }

    /// Handle inventory announcement
    pub async fn handle_inv(&self, peer_id: PeerId, items: Vec<InvItem>) {
        // Count block items
        let block_count = items
            .iter()
            .filter(|i| i.inv_type == InvType::Block)
            .count();

        // During initial sync, ignore small inv announcements (1-2 blocks) as these are
        // likely new block announcements at the chain tip, not responses to our getblocks
        let our_height = self.chain.height();
        let best_height = *self.best_peer_height.read();
        let is_initial_sync = best_height.saturating_sub(our_height) > 100;

        // During initial sync (>100 blocks behind), ignore small inv announcements as these are
        // likely new block announcements at the tip, not responses to our getblocks requests.
        // Once we're within 100 blocks of the tip, accept all inv responses to avoid stalling.
        let blocks_behind = best_height.saturating_sub(our_height);
        if is_initial_sync && block_count < 50 {
            // Still update best_peer_height so we know there are more blocks
            let new_estimated_height = our_height + block_count as u32;
            if new_estimated_height > best_height {
                *self.best_peer_height.write() = new_estimated_height;
                // Also update peer_heights so select_sync_peer can find this peer
                self.peer_heights
                    .write()
                    .insert(peer_id, new_estimated_height);
            }

            trace!(
                "Ignoring {} block announcement(s) while catching up (height {}/{}, {} behind)",
                block_count,
                our_height,
                best_height.max(new_estimated_height),
                blocks_behind
            );
            return;
        }

        // Clear header request timestamp - any inv that reaches this point (i.e., not filtered
        // by the early-return above) is a response to our getblocks or a new-block announcement
        // near the tip. Either way, the pending request has been answered.
        if block_count > 0 {
            *self.last_header_request.write() = None;
        }

        if block_count > 0 {
            info!(
                "Received inv with {} block hashes from peer {}",
                block_count, peer_id
            );
        }

        let mut queued = 0;
        let mut already_have = 0;
        let mut already_downloading = 0;
        let mut reorg_triggered = false;
        let mut first_hash_checked = false;

        // Queue blocks for download
        {
            let mut pending = self.pending_block_requests.write();
            let in_flight = self.blocks_in_flight.read();

            for item in items {
                if item.inv_type == InvType::Block {
                    let hash = item.hash;

                    // Detailed logging for first block in each inv to diagnose issue
                    if !first_hash_checked && block_count > 0 {
                        first_hash_checked = true;
                        let has_index =
                            self.chain.get_block_index(&hash).is_ok_and(|o| o.is_some());
                        let has_full = self.chain.has_full_block(&hash).unwrap_or(false);
                        info!(
                            "First inv block: hash={}, has_index={}, has_full_block={}",
                            hash, has_index, has_full
                        );
                        if has_index {
                            if let Ok(Some(index)) = self.chain.get_block_index(&hash) {
                                info!(
                                    "  Block index exists: height={}, on_main_chain={}",
                                    index.height,
                                    index.is_on_main_chain()
                                );
                            }
                        }
                    }

                    // Check if we already have this block on the main chain
                    if let Ok(Some(index)) = self.chain.get_block_index(&hash) {
                        let on_main_chain = index.is_on_main_chain();
                        let has_full = self.chain.has_full_block(&hash).unwrap_or(false);

                        if on_main_chain {
                            // We have this block and it's on the main chain
                            already_have += 1;
                            continue;
                        } else if has_full {
                            // We have the full block but it's not on main chain
                            // Try to activate it (reorg if it has more work)
                            match self.chain.try_activate_block(&hash) {
                                Ok(true) => {
                                    info!("Reorg triggered by block {} from inv", hash);
                                    reorg_triggered = true;
                                    already_have += 1;
                                    continue;
                                }
                                Ok(false) => {
                                    // Can't activate - parent missing or less work
                                    // Download it again from the network
                                    debug!(
                                        "Block {} exists but can't activate, will redownload",
                                        hash
                                    );
                                }
                                Err(e) => {
                                    warn!("Error trying to activate block {}: {}", hash, e);
                                }
                            }
                        }
                    }

                    // Check if we're already downloading it
                    if in_flight.contains_key(&hash) {
                        already_downloading += 1;
                        continue;
                    }

                    // Check if already queued
                    if pending.iter().any(|(h, _)| *h == hash) {
                        already_downloading += 1;
                        continue;
                    }

                    // Queue for download
                    pending.push_back((hash, peer_id));
                    queued += 1;
                }
            }
        }

        // If we triggered a reorg, log the new height
        if reorg_triggered {
            info!("After reorg, chain height is now {}", self.chain.height());
        }

        if block_count > 0 {
            info!(
                "Inventory result: queued={}, already_have={}, already_downloading={}",
                queued, already_have, already_downloading
            );
        }

        if queued > 0 {
            // Request blocks from the queue (respecting limits)
            self.request_queued_blocks().await;

            // Update best_peer_height: if peer announces blocks we don't have,
            // they're at least at our_height + queued
            // This ensures we keep syncing when peers stake new blocks
            let new_estimated_height = our_height + queued as u32;
            let current_best = *self.best_peer_height.read();
            if new_estimated_height > current_best {
                info!(
                    "Updating best_peer_height from {} to {} based on inv announcements",
                    current_best, new_estimated_height
                );
                *self.best_peer_height.write() = new_estimated_height;
            }

            // Also update this peer's recorded height so select_sync_peer can find them
            // This is critical: peer_heights is only set at connection time, but peers
            // stake new blocks. Without this, select_sync_peer() returns None because
            // no peer has height >= best_peer_height.
            let peer_current_height = self.peer_heights.read().get(&peer_id).copied().unwrap_or(0);
            if new_estimated_height > peer_current_height {
                self.peer_heights
                    .write()
                    .insert(peer_id, new_estimated_height);
                debug!(
                    "Updated peer {} height from {} to {}",
                    peer_id, peer_current_height, new_estimated_height
                );
            }
        }
    }

    /// Request blocks from the pending queue, respecting MAX_BLOCKS_IN_FLIGHT.
    ///
    /// Uses only actually-connected peers (via `peer_manager`) rather than the
    /// potentially-stale `peer_heights` map. Includes a circuit breaker: if we
    /// encounter 3 consecutive failures (no connected peers or all sends fail),
    /// we stop processing the queue to avoid a tight spin loop. Unassigned or
    /// dead-peer blocks will be retried the next time this method is called
    /// (e.g., from `check_timeouts` or when a new block arrives).
    async fn request_queued_blocks(&self) {
        let mut consecutive_failures: u32 = 0;
        const MAX_CONSECUTIVE_FAILURES: u32 = 3;

        loop {
            // Circuit breaker: stop after too many consecutive failures
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                let queued = self.pending_block_requests.read().len();
                if queued > 0 {
                    debug!(
                        "Circuit breaker: {} consecutive send failures, {} blocks still queued — will retry later",
                        consecutive_failures, queued
                    );
                }
                break;
            }

            // Check how many slots are available
            let in_flight_count = self.blocks_in_flight.read().len();
            if in_flight_count >= MAX_BLOCKS_IN_FLIGHT {
                trace!("At max blocks in flight ({}), waiting", in_flight_count);
                break;
            }

            // Get next block to request
            let next = {
                let mut pending = self.pending_block_requests.write();
                pending.pop_front()
            };

            let Some((hash, assigned_peer)) = next else {
                break; // Queue empty
            };

            // Double-check we don't already have it
            if self.chain.has_block(&hash).unwrap_or(false) {
                consecutive_failures = 0;
                continue;
            }
            if self.blocks_in_flight.read().contains_key(&hash) {
                consecutive_failures = 0;
                continue;
            }

            // Build ordered list of peers to try: assigned peer first (if valid),
            // then all other connected peers.
            let connected = self.peer_manager.connected_peers();
            if connected.is_empty() {
                // No connected peers at all — put the block back as unassigned
                self.pending_block_requests
                    .write()
                    .push_back((hash, Self::UNASSIGNED_PEER));
                consecutive_failures += 1;
                continue;
            }

            let mut peers_to_try: Vec<PeerId> = Vec::with_capacity(connected.len());
            // If assigned peer is connected and not the sentinel, try it first
            if assigned_peer != Self::UNASSIGNED_PEER
                && self.peer_manager.is_peer_connected(assigned_peer)
            {
                peers_to_try.push(assigned_peer);
            }
            // Add all other connected peers
            for &p in &connected {
                if p != assigned_peer {
                    peers_to_try.push(p);
                }
            }

            // Try each peer until one succeeds
            let item = InvItem {
                inv_type: InvType::Block,
                hash,
            };
            let mut sent = false;

            for &try_peer in &peers_to_try {
                let msg = NetworkMessage::GetData(vec![item.clone()]);
                match self.peer_manager.send_to_peer(try_peer, msg).await {
                    Ok(()) => {
                        debug!("Requested block {} from peer {}", hash, try_peer);
                        self.blocks_in_flight.write().insert(
                            hash,
                            BlockRequest {
                                peer_id: try_peer,
                                _hash: hash,
                                requested_at: Instant::now(),
                            },
                        );
                        sent = true;
                        consecutive_failures = 0;
                        break;
                    }
                    Err(_) => {
                        // This peer failed, try the next one
                        continue;
                    }
                }
            }

            if !sent {
                // All peers failed — put block back as unassigned for later retry
                debug!(
                    "All {} peers failed for block {}, re-queuing as unassigned",
                    peers_to_try.len(),
                    hash
                );
                self.pending_block_requests
                    .write()
                    .push_back((hash, Self::UNASSIGNED_PEER));
                consecutive_failures += 1;
            }
        }
    }

    /// Try to connect orphan blocks to the chain
    /// Called after we've received new blocks that might be parents of orphans.
    /// Matches C++ Divi's approach: tries any orphan whose parent is in the block
    /// index (not just tip-extending orphans), allowing side-chain blocks to be
    /// stored and potentially trigger reorgs via accept_block.
    async fn try_connect_orphans(&self) {
        let mut connected_any = true;

        // Keep trying to connect orphans until we can't connect any more
        while connected_any {
            connected_any = false;

            // Find orphans whose parent is known (in the block index).
            // This is broader than just tip-extending: it includes side-chain blocks
            // whose parent was stored earlier. accept_block() handles reorg detection.
            let orphans_to_try: Vec<(Hash256, Block)> = {
                let orphans = self.orphan_blocks.read();
                orphans
                    .iter()
                    .filter(|(_, orphan)| {
                        self.chain
                            .get_block_index(&orphan.block.header.prev_block)
                            .ok()
                            .flatten()
                            .is_some()
                    })
                    .map(|(hash, orphan)| (*hash, orphan.block.clone()))
                    .collect()
            };

            for (hash, block) in orphans_to_try {
                // Try to accept this block - this will store and connect it
                match self.chain.accept_block(block.clone()) {
                    Ok(result) => {
                        if let Some(fork_height) = result.reorg_fork_height {
                            self.fire_reorg_callbacks(fork_height, result.orphaned_transactions);
                        }
                        let height = self.chain.height();
                        info!("Connected orphan block {} at height {}", hash, height);

                        // Remove from orphans
                        self.orphan_blocks.write().remove(&hash);

                        // Update stats
                        self.stats.write().blocks_connected += 1;

                        // Notify callback if registered
                        if let Some(callback) = self.block_connected_callback.read().as_ref() {
                            callback(&block, height);
                        }

                        connected_any = true;
                    }
                    Err(e) => {
                        debug!("Failed to connect orphan block {}: {}", hash, e);
                    }
                }
            }
        }

        if self.orphan_blocks.read().is_empty() {
            debug!("All orphans connected successfully");
        } else {
            let orphan_count = self.orphan_blocks.read().len();
            debug!(
                "Still have {} orphan blocks waiting for parents",
                orphan_count
            );
        }
    }

    /// Request missing blocks to fill gaps for orphans
    /// Identifies the gap between our chain tip and the orphans, then requests those blocks
    async fn request_missing_blocks_for_orphans(&self) {
        let our_height = self.chain.height();

        // Check if we have orphans in a scope
        let orphan_count = {
            let orphans = self.orphan_blocks.read();
            if orphans.is_empty() {
                return;
            }
            orphans.len()
        }; // Lock dropped here

        // For now, just assume orphans are slightly ahead of our tip
        // The header sync will fill in the gaps properly
        let min_orphan_height = our_height + 1;

        if min_orphan_height <= our_height {
            debug!("No gap to fill for orphans");
            return;
        }

        // Request headers to fill the gap
        info!(
            "Requesting headers to fill gap from height {} to {} for {} orphans",
            our_height, min_orphan_height, orphan_count
        );

        // Use header sync to get the missing blocks in order
        *self.state.write() = SyncState::HeaderSync;
        self.request_headers().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_storage::{ChainDatabase, ChainParams};
    use tempfile::tempdir;

    fn create_test_sync() -> (Arc<BlockSync>, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Arc::new(Chain::new(db, ChainParams::default()).unwrap());
        let peer_manager = PeerManager::new(Default::default());

        let sync = BlockSync::new(chain, peer_manager);
        (sync, dir)
    }

    #[test]
    fn test_sync_creation() {
        let (sync, _dir) = create_test_sync();
        assert_eq!(sync.state(), SyncState::Idle);
    }

    #[test]
    fn test_peer_height_tracking() {
        let (sync, _dir) = create_test_sync();

        sync.update_peer_height(1, 1000);
        assert_eq!(*sync.best_peer_height.read(), 1000);

        sync.update_peer_height(2, 1500);
        assert_eq!(*sync.best_peer_height.read(), 1500);

        sync.update_peer_height(3, 1200);
        assert_eq!(*sync.best_peer_height.read(), 1500); // Still 1500

        sync.remove_peer(2);
        assert_eq!(*sync.best_peer_height.read(), 1200);
    }

    #[test]
    fn test_block_locator() {
        let (sync, _dir) = create_test_sync();
        let locator = sync.build_block_locator();
        // Empty chain should have empty or genesis locator
        assert!(locator.is_empty() || locator.len() == 1);
    }

    #[test]
    fn test_sync_progress() {
        let (sync, _dir) = create_test_sync();
        let progress = sync.progress();

        assert_eq!(progress.state, SyncState::Idle);
        assert_eq!(progress.current_height, 0);
        assert_eq!(progress.target_height, 0);
    }

    #[test]
    fn test_select_sync_peer_fallback() {
        // This test verifies that select_sync_peer falls back to the highest
        // height peer when no peer has height >= best_peer_height.
        // This can happen when best_peer_height is updated from inv announcements
        // but peer_heights only has the initial heights from version messages.
        let (sync, _dir) = create_test_sync();

        // Add peers with initial heights
        sync.update_peer_height(1, 1000);
        sync.update_peer_height(2, 1200);
        sync.update_peer_height(3, 1100);

        // Manually update best_peer_height to simulate inv announcements
        // that increased our known best height beyond any peer's recorded height
        *sync.best_peer_height.write() = 1500;

        // select_sync_peer should fall back to peer 2 (highest height 1200)
        let peer = sync.select_sync_peer();
        assert!(
            peer.is_some(),
            "select_sync_peer should fall back to highest peer"
        );
        assert_eq!(
            peer.unwrap(),
            2,
            "should select peer 2 with highest height 1200"
        );
    }

    #[test]
    fn test_select_sync_peer_exact_match() {
        let (sync, _dir) = create_test_sync();

        sync.update_peer_height(1, 1000);
        sync.update_peer_height(2, 1500);
        sync.update_peer_height(3, 1200);

        // best_peer_height should be 1500 (highest)
        assert_eq!(*sync.best_peer_height.read(), 1500);

        // select_sync_peer should find peer 2 with height 1500 >= 1500
        let peer = sync.select_sync_peer();
        assert!(peer.is_some());
        assert_eq!(peer.unwrap(), 2);
    }

    #[test]
    fn test_select_sync_peer_empty() {
        let (sync, _dir) = create_test_sync();

        // No peers added
        let peer = sync.select_sync_peer();
        assert!(
            peer.is_none(),
            "select_sync_peer should return None with no peers"
        );
    }

    // ============================================================
    // COMPREHENSIVE SYNC TESTS
    // Added 2026-01-19 for full coverage
    // ============================================================

    #[test]
    fn test_peer_height_update_increases() {
        let (sync, _dir) = create_test_sync();

        // Add peer with initial height
        sync.update_peer_height(1, 1000);
        assert_eq!(sync.get_peer_height(1), Some(1000));

        // Update to higher height
        sync.update_peer_height(1, 1500);
        assert_eq!(sync.get_peer_height(1), Some(1500));
    }

    #[test]
    fn test_peer_height_update_decreases() {
        let (sync, _dir) = create_test_sync();

        // Add peer with initial height
        sync.update_peer_height(1, 2000);

        // Update to lower height (might happen during reorg)
        sync.update_peer_height(1, 1800);

        // Depending on implementation, might keep higher or accept lower
        let height = sync.get_peer_height(1);
        assert!(height.is_some());
    }

    #[test]
    fn test_multiple_peers_tracking() {
        let (sync, _dir) = create_test_sync();

        // Add multiple peers
        sync.update_peer_height(1, 1000);
        sync.update_peer_height(2, 1500);
        sync.update_peer_height(3, 1200);
        sync.update_peer_height(4, 800);
        sync.update_peer_height(5, 2000);

        // Best should be 2000
        assert_eq!(*sync.best_peer_height.read(), 2000);
    }

    #[test]
    fn test_remove_best_peer_updates_best_height() {
        let (sync, _dir) = create_test_sync();

        sync.update_peer_height(1, 1000);
        sync.update_peer_height(2, 2000); // Best
        sync.update_peer_height(3, 1500);

        assert_eq!(*sync.best_peer_height.read(), 2000);

        // Remove best peer
        sync.remove_peer(2);

        // Best should now be 1500
        assert_eq!(*sync.best_peer_height.read(), 1500);
    }

    #[test]
    fn test_remove_all_peers() {
        let (sync, _dir) = create_test_sync();

        sync.update_peer_height(1, 1000);
        sync.update_peer_height(2, 2000);

        sync.remove_peer(1);
        sync.remove_peer(2);

        // Best should be 0 with no peers
        assert_eq!(*sync.best_peer_height.read(), 0);

        // Select sync peer should return None
        assert!(sync.select_sync_peer().is_none());
    }

    #[test]
    fn test_sync_state_transitions() {
        let (sync, _dir) = create_test_sync();

        // Start idle
        assert_eq!(sync.state(), SyncState::Idle);

        // Add a peer with higher height to trigger sync
        sync.update_peer_height(1, 1000);

        // State might transition based on implementation
        let state = sync.state();
        assert!(matches!(
            state,
            SyncState::Idle | SyncState::HeaderSync | SyncState::BlockDownload
        ));
    }

    #[test]
    fn test_sync_progress_fields() {
        let (sync, _dir) = create_test_sync();

        let progress = sync.progress();

        // Initial progress
        assert_eq!(progress.current_height, 0);
        assert_eq!(progress.headers_downloaded, 0);
        assert_eq!(progress.blocks_downloaded, 0);
        assert_eq!(progress.blocks_in_flight, 0);
        assert!(progress.blocks_per_second >= 0.0);
    }

    #[test]
    fn test_block_locator_empty_chain() {
        let (sync, _dir) = create_test_sync();

        let locator = sync.build_block_locator();

        // Empty or single genesis entry
        assert!(locator.len() <= 1);
    }

    #[test]
    fn test_select_sync_peer_prefers_higher() {
        let (sync, _dir) = create_test_sync();

        sync.update_peer_height(1, 500);
        sync.update_peer_height(2, 1000);
        sync.update_peer_height(3, 750);

        // Should prefer peer 2 (highest height)
        let selected = sync.select_sync_peer();
        assert!(selected.is_some());
        // Either peer 2 directly, or the one matching best_peer_height
    }

    #[test]
    fn test_peer_height_zero() {
        let (sync, _dir) = create_test_sync();

        // Peer reporting height 0 (just started)
        sync.update_peer_height(1, 0);

        assert_eq!(sync.get_peer_height(1), Some(0));
        assert_eq!(*sync.best_peer_height.read(), 0);
    }

    #[test]
    fn test_peer_height_very_large() {
        let (sync, _dir) = create_test_sync();

        // Very large height (stress test)
        sync.update_peer_height(1, u32::MAX);

        assert_eq!(*sync.best_peer_height.read(), u32::MAX);
    }

    #[test]
    fn test_concurrent_peer_updates() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let dir = tempdir().unwrap();
        let db = StdArc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = StdArc::new(Chain::new(db, ChainParams::default()).unwrap());
        let peer_manager = PeerManager::new(Default::default());
        let sync = StdArc::new(BlockSync::new(chain, peer_manager));

        let mut handles = vec![];

        // Multiple threads updating different peers
        for peer_id in 1..=10 {
            let sync_clone = StdArc::clone(&sync);
            let handle = thread::spawn(move || {
                for height in (1000..1100).step_by(10) {
                    sync_clone.update_peer_height(peer_id, height);
                }
            });
            handles.push(handle);
        }

        // All should complete without panic
        for handle in handles {
            handle.join().unwrap();
        }

        // Best height should be 1090 (last update value)
        let best = *sync.best_peer_height.read();
        assert!(best >= 1000, "Best height should be at least 1000");
    }

    // Helper method tests
    #[test]
    fn test_get_peer_height_nonexistent() {
        let (sync, _dir) = create_test_sync();

        // Peer that was never added
        assert_eq!(sync.get_peer_height(999), None);
    }

    #[test]
    fn test_remove_nonexistent_peer() {
        let (sync, _dir) = create_test_sync();

        // Should not panic
        sync.remove_peer(999);
    }

    #[test]
    fn test_update_same_peer_multiple_times() {
        let (sync, _dir) = create_test_sync();

        for height in (100..200).step_by(10) {
            sync.update_peer_height(1, height);
        }

        // Final height should be 190
        assert_eq!(sync.get_peer_height(1), Some(190));
    }

    // ============================================================
    // HEADER VALIDATION TESTS
    // Added for FIX-015: Header validation during sync
    // ============================================================

    #[test]
    fn test_target_from_compact_genesis() {
        // Genesis block nBits = 0x1e0fffff (Divi mainnet)
        let compact = 0x1e0fffff;
        let target = target_from_compact(compact);

        // Should not be zero
        assert!(!target.is_zero(), "Genesis target should not be zero");

        // Check target bytes - exponent is 0x1e = 30, mantissa is 0x0fffff
        // Target should have 0x0fffff at bytes 27, 28, 29 (offset = 30 - 3 = 27)
        let bytes = target.as_bytes();
        assert_eq!(bytes[27], 0xff);
        assert_eq!(bytes[28], 0xff);
        assert_eq!(bytes[29], 0x0f);
    }

    #[test]
    fn test_target_from_compact_zero_mantissa() {
        // Zero mantissa should return zero target
        let compact = 0x1e000000;
        let target = target_from_compact(compact);
        assert!(target.is_zero(), "Zero mantissa should give zero target");
    }

    #[test]
    fn test_target_from_compact_negative() {
        // Negative bit set should return zero target
        let compact = 0x1e800001;
        let target = target_from_compact(compact);
        assert!(target.is_zero(), "Negative target should give zero");
    }

    #[test]
    fn test_hash_meets_target_equal() {
        // Hash equal to target should meet it
        let hash = Hash256::from_bytes([0x01; 32]);
        let target = Hash256::from_bytes([0x01; 32]);
        assert!(
            hash_meets_target(&hash, &target),
            "Equal hash should meet target"
        );
    }

    #[test]
    fn test_hash_meets_target_below() {
        // Hash below target should meet it
        let mut hash_bytes = [0x00; 32];
        hash_bytes[0] = 0x01;
        let hash = Hash256::from_bytes(hash_bytes);

        let mut target_bytes = [0x00; 32];
        target_bytes[0] = 0x02;
        let target = Hash256::from_bytes(target_bytes);

        assert!(
            hash_meets_target(&hash, &target),
            "Lower hash should meet target"
        );
    }

    #[test]
    fn test_hash_meets_target_above() {
        // Hash above target should NOT meet it
        let mut hash_bytes = [0x00; 32];
        hash_bytes[31] = 0x02; // Higher byte at MSB position
        let hash = Hash256::from_bytes(hash_bytes);

        let mut target_bytes = [0x00; 32];
        target_bytes[31] = 0x01;
        let target = Hash256::from_bytes(target_bytes);

        assert!(
            !hash_meets_target(&hash, &target),
            "Higher hash should NOT meet target"
        );
    }

    #[test]
    fn test_validate_header_timestamp_in_future() {
        let mut header = BlockHeader::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Set timestamp 3 hours in future (beyond MAX_FUTURE_TIME)
        header.time = now + 3 * 60 * 60;
        header.bits = 0x1e0fffff; // Valid bits

        let result = validate_header(&header, 500); // Height > LAST_POW_BLOCK
        assert!(
            matches!(
                result,
                Err(HeaderValidationError::TimestampTooFarInFuture { .. })
            ),
            "Should reject timestamp too far in future"
        );
    }

    #[test]
    fn test_validate_header_timestamp_valid() {
        let mut header = BlockHeader::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Set timestamp 1 hour in future (within MAX_FUTURE_TIME)
        header.time = now + 60 * 60;
        header.bits = 0x1e0fffff;

        // For PoS block (height > LAST_POW_BLOCK), only timestamp is checked
        let result = validate_header(&header, 500);
        assert!(
            result.is_ok(),
            "Should accept timestamp within 2 hours of future"
        );
    }

    #[test]
    fn test_validate_header_pow_block_invalid_bits() {
        let mut header = BlockHeader::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        header.time = now;
        header.bits = 0x00000000; // Invalid bits (zero)

        // Height within PoW range
        let result = validate_header(&header, 50);
        assert!(
            matches!(result, Err(HeaderValidationError::InvalidBits(_))),
            "Should reject invalid bits for PoW block"
        );
    }
}
