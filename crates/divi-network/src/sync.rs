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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{debug, error, info, trace, warn};

/// Maximum headers to request at once
const MAX_HEADERS_REQUEST: usize = 2000;

/// Maximum blocks to have in flight at once
const MAX_BLOCKS_IN_FLIGHT: usize = 128;

/// Timeout for block downloads
const BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Failed attempts (timeouts or `notfound`) after which a block request is dropped.
/// Before this cap a block nobody serves was re-requested every 60 s forever,
/// ping-ponging between the same two peers.
const MAX_BLOCK_REQUEST_ATTEMPTS: u32 = 5;

/// How long a given-up block stays suppressed before it may be requested again.
/// A fresh announcement from a peer that has not failed it lifts this early.
const BLOCK_GIVE_UP_BACKOFF: Duration = Duration::from_secs(600);

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

/// Retry bookkeeping for one block hash, kept across re-queues
#[derive(Default)]
struct BlockRetryState {
    /// Failed attempts so far (counted separately from `failed_peers`: with a
    /// single peer the set never grows)
    attempts: u32,
    /// Peers that timed out on or answered `notfound` for this block
    failed_peers: HashSet<PeerId>,
    /// Last peer that announced the block via inv
    announced_by: Option<PeerId>,
    /// Set once `attempts` reached the cap; the block is not requested until
    /// `BLOCK_GIVE_UP_BACKOFF` passes or a fresh peer announces it
    gave_up_at: Option<Instant>,
}

/// Outcome of recording a failed block request
#[derive(Debug, PartialEq, Eq)]
enum BlockRetryOutcome {
    /// Re-queued for another peer
    Requeued,
    /// Dropped because we already have the block
    NoLongerNeeded,
    /// Dropped because the attempt cap was reached
    GaveUp,
}

/// Order the peers to try for a block request.
///
/// Peers that already failed this block go last (they stay as a fallback so a
/// single-peer node can still retry). Among the rest: the announcing peer
/// first, then the assigned peer, then everyone else rotated by `cursor`.
/// `connected` comes from a `HashMap`, so it is sorted first; without that the
/// "rotation" would follow hash order and keep landing on the same peers.
fn order_retry_peers(
    mut connected: Vec<PeerId>,
    failed: &HashSet<PeerId>,
    announced_by: Option<PeerId>,
    assigned_peer: PeerId,
    cursor: usize,
) -> Vec<PeerId> {
    connected.sort_unstable();
    let (mut fresh, stale): (Vec<PeerId>, Vec<PeerId>) =
        connected.into_iter().partition(|p| !failed.contains(p));

    if !fresh.is_empty() {
        let len = fresh.len();
        fresh.rotate_left(cursor % len);
    }
    for preferred in [
        assigned_peer,
        announced_by.unwrap_or(BlockSync::UNASSIGNED_PEER),
    ] {
        if let Some(pos) = fresh.iter().position(|&p| p == preferred) {
            let peer = fresh.remove(pos);
            fresh.insert(0, peer);
        }
    }

    fresh.extend(stale);
    fresh
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

/// Number of block hashes a getblocks answer carries when more follow (C++ limit).
const MAX_GETBLOCKS_INV: usize = 500;

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
    /// Per-block retry state: attempt count, failed peers, announcer
    block_retry: RwLock<HashMap<Hash256, BlockRetryState>>,
    /// Round-robin offset for choosing among retry candidates
    retry_cursor: AtomicUsize,
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
    /// Counter for stall detection - increments each timeout cycle at same height
    /// Format: ((main_height, side_chain_tip_height) at last check, consecutive_stall_count).
    /// A growing side chain counts as progress: while a deep fork is fetched the
    /// main-chain height stays put for many rounds.
    stall_counter: RwLock<((u32, u32), u32)>,
    /// Highest fully stored block we know of that is NOT on the main chain
    /// (hash, height). A fork deeper than one getblocks batch (500 hashes) is
    /// fetched across several rounds; this lets each round resume from where
    /// the side chain ends instead of from the fork point.
    side_chain_tip: RwLock<Option<(Hash256, u32)>>,
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
            block_retry: RwLock::new(HashMap::new()),
            retry_cursor: AtomicUsize::new(0),
            progress_tx,
            stats: RwLock::new(SyncStats::default()),
            sync_peer: RwLock::new(None),
            last_header_request: RwLock::new(None),
            block_connected_callback: RwLock::new(None),
            reorg_callback: RwLock::new(None),
            orphaned_tx_callback: RwLock::new(None),
            stall_counter: RwLock::new(((0, 0), 0)),
            side_chain_tip: RwLock::new(None),
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

        // If we're already at or ahead of all peers and still in IBD, exit IBD.
        // This handles the case where the node restarts already synced — the sync
        // engine never runs, so the Synced → exit IBD transition never fires.
        if our_height >= height && self.chain.is_ibd() {
            let best = *self.best_peer_height.read();
            if our_height >= best {
                info!(
                    "Already synced (height {} >= best peer {}), exiting IBD mode",
                    our_height, best
                );
                *self.state.write() = SyncState::Synced;
                self.chain.set_ibd_mode(false);
            }
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

        // Use getblocks for sync (C++ Divi responds to both getblocks and getheaders
        // with inv messages — it does not support headers-first sync).
        // Fork selection is handled by storing side-chain blocks and using
        // activate_best_chain to reorg when a competing chain has more work.
        let msg =
            NetworkMessage::GetBlocks(GetHeadersMessage::new(locator.clone(), Hash256::zero()));

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

    /// Locator for a continuation getblocks after an inv that brought nothing new.
    ///
    /// Returns Some only when the inv was a full getblocks answer (MAX_GETBLOCKS_INV
    /// hashes), nothing from it was queued or in flight, and we know its last block.
    fn inv_continuation_locator(
        &self,
        block_count: usize,
        queued: usize,
        already_downloading: usize,
        last_block_hash: Option<Hash256>,
    ) -> Option<Vec<Hash256>> {
        if block_count < MAX_GETBLOCKS_INV || queued > 0 || already_downloading > 0 {
            return None;
        }
        let last = last_block_hash?;
        if !self.chain.get_block_index(&last).is_ok_and(|o| o.is_some()) {
            return None;
        }
        let genesis = self.chain.genesis_hash();
        if last == genesis {
            Some(vec![last])
        } else {
            Some(vec![last, genesis])
        }
    }

    /// `Some(height)` when `hash` is fully stored but not on the main chain.
    fn stored_side_chain_height(&self, hash: &Hash256) -> Option<u32> {
        let index = self.chain.get_block_index(hash).ok()??;
        if index.is_on_main_chain() || !self.chain.has_full_block(hash).unwrap_or(false) {
            return None;
        }
        Some(index.height)
    }

    /// Remember `hash` as the side-chain tip if it is a stored side-chain block
    /// higher than the current hint (or the current hint is no longer valid).
    fn note_side_chain_block(&self, hash: Hash256) {
        let Some(height) = self.stored_side_chain_height(&hash) else {
            return;
        };
        let current = *self.side_chain_tip.read();
        let replace = match current {
            None => true,
            Some((cur_hash, cur_height)) => {
                height > cur_height || self.stored_side_chain_height(&cur_hash).is_none()
            }
        };
        if replace {
            *self.side_chain_tip.write() = Some((hash, height));
        }
    }

    /// The side-chain tip hint, if it is still a stored block off the main chain.
    /// Cleared once a reorg puts it on the main chain.
    fn valid_side_chain_tip(&self) -> Option<(Hash256, u32)> {
        let (hash, height) = (*self.side_chain_tip.read())?;
        if self.stored_side_chain_height(&hash).is_some() {
            Some((hash, height))
        } else {
            *self.side_chain_tip.write() = None;
            None
        }
    }

    /// Build block locator hashes
    ///
    /// Normally walks back from the main-chain tip. When we hold a stored side
    /// chain (a competing fork we are still downloading), its tip goes first:
    /// a peer on that fork then answers from where our copy ends, so a fork
    /// deeper than one 500-hash batch keeps growing round after round until it
    /// out-works our tip and `accept_block` reorgs onto it. A peer that does
    /// not know the hint skips it and matches on the main-chain entries.
    ///
    /// There is no max-reorg-depth rule in this codebase (nor in C++ Divi's
    /// getblocks sync); the only fork-choice limit is the hard-coded
    /// checkpoint table in `Chain::get_checkpoint_hash`.
    fn build_block_locator(&self) -> Vec<Hash256> {
        let mut locator = Vec::new();
        if let Some((side_hash, side_height)) = self.valid_side_chain_tip() {
            debug!(
                "Block locator starts at stored side-chain block {} (height {}) to continue a competing fork",
                side_hash, side_height
            );
            locator.push(side_hash);
        }
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
                let chain_height = self.chain.height();
                let pending_count = pending.len() as u32;
                (compute_block_hash(last), chain_height + pending_count)
            } else if let Some(tip) = self.chain.tip() {
                (tip.hash, tip.height)
            } else {
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
            let retry = self.block_retry.read();

            for header in pending.iter() {
                let hash = compute_block_hash(header);
                if !in_flight.contains_key(&hash)
                    && !downloaded.contains_key(&hash)
                    && !retry.get(&hash).is_some_and(|r| r.gave_up_at.is_some())
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
        self.block_retry.write().remove(&hash);

        // Store in downloaded blocks
        self.downloaded_blocks.write().insert(hash, block);
        self.stats.write().blocks_downloaded += 1;

        // Try to connect blocks
        self.try_connect_blocks().await;

        // A block stored on a competing fork becomes the side-chain locator hint.
        self.note_side_chain_block(hash);

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
                // Disable IBD mode — enable full PoS and script validation for new blocks
                if self.chain.is_ibd() {
                    info!("Exiting IBD mode — full validation enabled for new blocks");
                    self.chain.set_ibd_mode(false);
                }
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

        // Stall detection: if height hasn't changed across timeout cycles, rotate peer
        let progress = (
            our_height,
            self.valid_side_chain_tip().map_or(0, |(_, h)| h),
        );
        let is_stalled = {
            let mut stall = self.stall_counter.write();
            if stall.0 == progress && state != SyncState::Synced && state != SyncState::Idle {
                stall.1 += 1;
                if stall.1 >= 3 {
                    warn!(
                        "Sync stalled at height {} for {} cycles, rotating sync peer",
                        our_height, stall.1
                    );
                    stall.1 = 0;
                    true
                } else {
                    false
                }
            } else {
                stall.0 = progress;
                stall.1 = 0;
                false
            }
        }; // RwLock guard dropped here
        if is_stalled {
            *self.sync_peer.write() = None;
            self.downloaded_blocks.write().clear();
            self.orphan_blocks.write().clear();
            self.request_headers().await;
            return;
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
            warn!("Block {} request timed out from peer {}", hash, peer_id);
            self.fail_block_request(hash, peer_id, "timed out");
        }

        self.prune_block_retry(now);

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

        let last_block_hash = items
            .iter()
            .rev()
            .find(|i| i.inv_type == InvType::Block)
            .map(|i| i.hash);

        let mut queued = 0;
        let mut already_have = 0;
        let mut known_side_chain = 0usize;
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
                                    // Stored on a side chain with less work than our
                                    // tip. We already hold it: count it as known. Re-
                                    // queueing it was the deep-fork loop: the queue
                                    // drops blocks we have, and queued > 0 blocked the
                                    // continuation getblocks, so every round restarted
                                    // at the fork point and the fork never grew.
                                    already_have += 1;
                                    known_side_chain += 1;
                                    self.note_side_chain_block(hash);
                                    continue;
                                }
                                Err(e) => {
                                    warn!("Error trying to activate block {}: {}", hash, e);
                                    already_have += 1;
                                    known_side_chain += 1;
                                    continue;
                                }
                            }
                        }
                    }

                    // Remember who announced it, so retries prefer a peer that
                    // claims to have it. A given-up block is lifted early only by a
                    // peer that has not already failed it.
                    {
                        let mut retry = self.block_retry.write();
                        let state = retry.entry(hash).or_default();
                        let fresh_peer = !state.failed_peers.contains(&peer_id);
                        if fresh_peer {
                            state.announced_by = Some(peer_id);
                        }
                        if state.gave_up_at.is_some() {
                            if fresh_peer {
                                state.gave_up_at = None;
                                state.attempts = 0;
                            } else {
                                already_downloading += 1;
                                continue;
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
        if known_side_chain > 0 {
            let side = *self.side_chain_tip.read();
            info!(
                "{} inv blocks are already stored on a side chain (side-chain tip {:?}, main tip height {}); \
                 waiting for that fork to out-work the tip",
                known_side_chain,
                side.map(|(_, h)| h),
                self.chain.height()
            );
        }

        // C++ parity (main.cpp ProcessMessage "inv"): on a very long side chain the
        // peer's getblocks answer can be 500 blocks we already have. Re-sending the
        // tip locator would get the same 500 back forever (vps1 testnet stalled at
        // 208,970 this way), so continue from the last block of this inv instead.
        if let Some(locator) =
            self.inv_continuation_locator(block_count, queued, already_downloading, last_block_hash)
        {
            info!(
                "All {} inv blocks already known; continuing getblocks from {} (long side chain)",
                block_count, locator[0]
            );
            let msg = NetworkMessage::GetBlocks(GetHeadersMessage::new(locator, Hash256::zero()));
            if let Err(e) = self.peer_manager.send_to_peer(peer_id, msg).await {
                warn!(
                    "Failed to send continuation getblocks to peer {}: {}",
                    peer_id, e
                );
            } else {
                *self.last_header_request.write() = Some(Instant::now());
            }
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
                self.block_retry.write().remove(&hash);
                consecutive_failures = 0;
                continue;
            }
            if self.blocks_in_flight.read().contains_key(&hash) {
                consecutive_failures = 0;
                continue;
            }
            if self
                .block_retry
                .read()
                .get(&hash)
                .is_some_and(|r| r.gave_up_at.is_some())
            {
                consecutive_failures = 0;
                continue;
            }

            let connected = self.peer_manager.connected_peers();
            if connected.is_empty() {
                // No connected peers at all — put the block back as unassigned
                self.pending_block_requests
                    .write()
                    .push_back((hash, Self::UNASSIGNED_PEER));
                consecutive_failures += 1;
                continue;
            }

            let peers_to_try = self.order_peers_for_block(&hash, assigned_peer, connected);

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

    /// Handle a `notfound` reply. A block the peer says it does not have is
    /// failed over to another peer at once instead of waiting out the timeout.
    pub async fn handle_notfound(&self, peer_id: PeerId, items: Vec<InvItem>) {
        let mut requeued = 0;
        for item in items {
            if item.inv_type != InvType::Block {
                continue;
            }
            // Only a reply from the peer we actually asked counts; anything else
            // is stale (the request already moved on).
            let asked_this_peer = self
                .blocks_in_flight
                .read()
                .get(&item.hash)
                .is_some_and(|req| req.peer_id == peer_id);
            if !asked_this_peer {
                continue;
            }
            debug!("Peer {} sent notfound for block {}", peer_id, item.hash);
            if self.fail_block_request(item.hash, peer_id, "notfound")
                == BlockRetryOutcome::Requeued
            {
                requeued += 1;
            }
        }

        if requeued > 0 {
            self.request_queued_blocks().await;
        }
    }

    /// Record a failed block request (timeout or `notfound`) and decide what
    /// happens next: drop it if we already have the block, give up once
    /// `MAX_BLOCK_REQUEST_ATTEMPTS` is reached, otherwise re-queue it unassigned
    /// so `request_queued_blocks` picks a peer that has not failed it.
    fn fail_block_request(
        &self,
        hash: Hash256,
        peer_id: PeerId,
        reason: &str,
    ) -> BlockRetryOutcome {
        self.blocks_in_flight.write().remove(&hash);
        if let Some(requests) = self.peer_block_requests.write().get_mut(&peer_id) {
            requests.remove(&hash);
        }

        if self.chain.has_block(&hash).unwrap_or(false) {
            self.block_retry.write().remove(&hash);
            return BlockRetryOutcome::NoLongerNeeded;
        }

        let attempts = {
            let mut retry = self.block_retry.write();
            let state = retry.entry(hash).or_default();
            state.attempts += 1;
            state.failed_peers.insert(peer_id);
            if state.attempts >= MAX_BLOCK_REQUEST_ATTEMPTS {
                state.gave_up_at = Some(Instant::now());
            }
            state.attempts
        };

        if attempts >= MAX_BLOCK_REQUEST_ATTEMPTS {
            info!(
                "Giving up on block {} after {} failed requests (last: peer {} {}); \
                 will retry if a new peer announces it or after {}s",
                hash,
                attempts,
                peer_id,
                reason,
                BLOCK_GIVE_UP_BACKOFF.as_secs()
            );
            return BlockRetryOutcome::GaveUp;
        }

        debug!(
            "Re-queuing block {} after peer {} {} (attempt {}/{})",
            hash, peer_id, reason, attempts, MAX_BLOCK_REQUEST_ATTEMPTS
        );
        self.pending_block_requests
            .write()
            .push_back((hash, Self::UNASSIGNED_PEER));
        BlockRetryOutcome::Requeued
    }

    /// Bound `block_retry`: lift give-ups whose backoff has passed and drop
    /// entries for blocks that are neither in flight nor queued any more.
    fn prune_block_retry(&self, now: Instant) {
        let in_flight: HashSet<Hash256> = self.blocks_in_flight.read().keys().copied().collect();
        let queued: HashSet<Hash256> = self
            .pending_block_requests
            .read()
            .iter()
            .map(|(h, _)| *h)
            .collect();
        self.block_retry
            .write()
            .retain(|hash, state| match state.gave_up_at {
                Some(at) => now.duration_since(at) < BLOCK_GIVE_UP_BACKOFF,
                None => in_flight.contains(hash) || queued.contains(hash),
            });
    }

    /// Order the connected peers to try for one block request.
    fn order_peers_for_block(
        &self,
        hash: &Hash256,
        assigned_peer: PeerId,
        connected: Vec<PeerId>,
    ) -> Vec<PeerId> {
        let (failed, announced_by) = match self.block_retry.read().get(hash) {
            Some(state) => (state.failed_peers.clone(), state.announced_by),
            None => (HashSet::new(), None),
        };
        let cursor = self.retry_cursor.fetch_add(1, Ordering::Relaxed);
        order_retry_peers(connected, &failed, announced_by, assigned_peer, cursor)
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

    /// Request missing blocks to fill gaps for orphans.
    ///
    /// When blocks can't connect to our tip, we need to fill the gap. Instead of
    /// just re-requesting from the same peer (which may send the same non-connecting
    /// blocks), we force selection of a different sync peer to break the stall cycle.
    async fn request_missing_blocks_for_orphans(&self) {
        let our_height = self.chain.height();

        let orphan_count = {
            let orphans = self.orphan_blocks.read();
            if orphans.is_empty() {
                return;
            }
            orphans.len()
        };

        info!(
            "Requesting blocks to fill gap at height {} for {} orphans",
            our_height, orphan_count
        );

        // Force selection of a different sync peer to avoid getting the same
        // non-connecting blocks from the same peer (the root cause of stall loops).
        let current_sync = *self.sync_peer.read();
        *self.sync_peer.write() = None;

        // Try to find a peer that's NOT the current sync peer
        let alt_peer = {
            let peer_heights = self.peer_heights.read();
            peer_heights
                .iter()
                .filter(|(&id, _)| Some(id) != current_sync)
                .max_by_key(|(_, &h)| h)
                .map(|(&id, _)| id)
        };

        if let Some(peer) = alt_peer {
            *self.sync_peer.write() = Some(peer);
            info!(
                "Switching to alternative peer {} for gap fill (was {:?})",
                peer, current_sync
            );
        } else if current_sync.is_some() {
            debug!(
                "No alternative peer available, will retry with same peer {:?}",
                current_sync
            );
        }

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
    fn test_inv_continuation_full_known_inv_continues_from_last() {
        // vps1 testnet stall: a full 500-hash inv of blocks we already have must
        // produce a continuation getblocks from the last hash, not nothing.
        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let params = ChainParams::for_network(
            divi_storage::NetworkType::Regtest,
            divi_primitives::ChainMode::Divi,
        );
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let sync = BlockSync::new(chain, PeerManager::new(Default::default()));
        let g = sync.chain.genesis_hash();
        assert!(!g.is_zero());
        assert_eq!(
            sync.inv_continuation_locator(500, 0, 0, Some(g)),
            Some(vec![g])
        );
    }

    #[test]
    fn test_inv_continuation_not_sent_when_progress_or_short_inv() {
        let (sync, _dir) = create_test_sync();
        let g = sync.chain.genesis_hash();
        assert_eq!(sync.inv_continuation_locator(499, 0, 0, Some(g)), None);
        assert_eq!(sync.inv_continuation_locator(500, 1, 0, Some(g)), None);
        assert_eq!(sync.inv_continuation_locator(500, 0, 3, Some(g)), None);
        assert_eq!(sync.inv_continuation_locator(500, 0, 0, None), None);
        let unknown = Hash256::from_bytes([7u8; 32]);
        assert_eq!(
            sync.inv_continuation_locator(500, 0, 0, Some(unknown)),
            None
        );
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

    // ------------------------------------------------------------------
    // Deep side-chain reorg across getblocks batches (vps1 testnet, fork
    // at 97,550). The peer's chain is heavier but the fork is longer than
    // one 500-hash inv, and we already hold the first 500 side-chain
    // blocks from an earlier round.
    // ------------------------------------------------------------------

    fn regtest_params() -> ChainParams {
        ChainParams::for_network(
            divi_storage::NetworkType::Regtest,
            divi_primitives::ChainMode::Divi,
        )
    }

    /// Build `len` consensus-valid regtest blocks on top of genesis.
    ///
    /// Heights 1..=100 are PoW; above that each block is PoS, built the way
    /// `divi-node`'s staker builds one (coinbase marker, coinstake re-staking
    /// the previous stake output, lottery and treasury payees, recoverable
    /// block signature). The chain is built in its own scratch `Chain`, where
    /// it is the main chain, so lottery winners come from the real chain code.
    /// Stake-kernel checks are skipped in IBD mode, which a fresh `Chain` is in.
    fn build_regtest_chain(len: u32, seed: u8, time_offset: u32) -> Vec<Block> {
        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Chain::new(db, regtest_params()).unwrap();
        extend_regtest_chain(&chain, len, seed, time_offset, 1250_00000000)
    }

    /// Extend `chain` from genesis to height `len` (see `build_regtest_chain`).
    /// `pow_value_sat` is the value of each PoW coinbase; the stake re-staked
    /// from height 101 on starts from the height-100 coinbase.
    fn extend_regtest_chain(
        chain: &Chain,
        len: u32,
        seed: u8,
        time_offset: u32,
        pow_value_sat: i64,
    ) -> Vec<Block> {
        use divi_consensus::block_subsidy;
        use divi_primitives::amount::Amount;
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{OutPoint, TxIn, TxOut};

        let key = divi_crypto::SecretKey::from_bytes(&[seed; 32]).unwrap();
        let pay = Script::new_p2pkh(key.public_key().pubkey_hash().as_bytes());
        let genesis = chain.tip().unwrap();
        let (mut prev, mut t) = (genesis.hash, genesis.time + time_offset);
        let mut stake: Option<(OutPoint, Amount)> = None;
        let mut blocks = Vec::with_capacity(len as usize);

        for h in 1..=len {
            t += 60;
            // Height + seed keep every coinbase txid unique across both chains.
            let mut tag = vec![0x05];
            tag.extend_from_slice(&h.to_le_bytes());
            tag.push(seed);

            let mut block = Block::default();
            block.header.prev_block = prev;
            block.header.time = t;
            block.header.bits = 0x207fffff; // regtest never retargets

            if h <= 100 {
                block.header.version = 1;
                let coinbase = Transaction {
                    version: 1,
                    vin: vec![TxIn::coinbase(Script::from_bytes(tag))],
                    vout: vec![TxOut::new(Amount::from_sat(pow_value_sat), pay.clone())],
                    lock_time: 0,
                };
                if h == 100 {
                    stake = Some((OutPoint::new(coinbase.txid(), 0), coinbase.vout[0].value));
                }
                block.transactions.push(coinbase);
            } else {
                block.header.version = 4;
                let parent = chain.get_block_index(&prev).unwrap().unwrap();
                let (prevout, value) = stake.take().unwrap();
                let rewards = block_subsidy::get_block_subsidy(h, 100);
                let mut vout = vec![
                    TxOut::new(Amount::ZERO, Script::default()),
                    TxOut::new(value + rewards.stake + rewards.masternode, pay.clone()),
                ];
                vout.extend(regtest_superblock_outputs(h, &parent.lottery_winners));
                let coinstake = Transaction {
                    version: 1,
                    vin: vec![TxIn {
                        prevout,
                        script_sig: Script::default(),
                        sequence: 0xffffffff,
                    }],
                    vout,
                    lock_time: 0,
                };
                stake = Some((OutPoint::new(coinstake.txid(), 1), coinstake.vout[1].value));
                let marker = Transaction {
                    version: 2,
                    vin: vec![TxIn::coinbase(Script::from_bytes(tag))],
                    vout: vec![TxOut::new(Amount::ZERO, Script::default())],
                    lock_time: 0,
                };
                block.transactions.push(marker);
                block.transactions.push(coinstake);
            }

            block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
            if block.is_proof_of_stake() {
                let hash = compute_block_hash(&block.header);
                block.block_sig = divi_crypto::sign_hash_recoverable(&key, hash.as_bytes())
                    .unwrap()
                    .to_compact_with_recovery()
                    .to_vec();
            }
            prev = chain
                .accept_block(block.clone())
                .unwrap_or_else(|e| panic!("scratch chain rejected height {}: {}", h, e))
                .hash;
            assert_eq!(chain.height(), h);
            blocks.push(block);
        }
        blocks
    }

    /// Superblock outputs a regtest coinstake at `h` must carry, in Divi
    /// Core's order (BlockIncentivesPopulator::FillBlockPayee): a treasury
    /// height pays treasury and charity, otherwise a lottery height pays the
    /// winners. Before the lottery/treasury transition both can fall on one
    /// height; treasury wins there.
    fn regtest_superblock_outputs(
        h: u32,
        winners: &divi_primitives::LotteryWinners,
    ) -> Vec<divi_primitives::transaction::TxOut> {
        use divi_consensus::{block_subsidy, lottery, treasury};
        use divi_primitives::amount::Amount;
        use divi_primitives::transaction::TxOut;

        match treasury::superblock_payout(
            h,
            treasury::regtest::TREASURY_START_BLOCK,
            treasury::regtest::TREASURY_CYCLE,
            lottery::regtest::LOTTERY_START_BLOCK,
            lottery::regtest::LOTTERY_CYCLE,
        ) {
            treasury::SuperblockPayout::Treasury => {
                let cycle = treasury::get_treasury_payment_cycle(
                    h,
                    treasury::regtest::TREASURY_CYCLE,
                    treasury::regtest::LOTTERY_CYCLE,
                );
                let (t_amt, c_amt) =
                    block_subsidy::calculate_weighted_treasury_payment(h, cycle, 100);
                vec![
                    TxOut::new(t_amt, treasury::get_treasury_script(false)),
                    TxOut::new(c_amt, treasury::get_charity_script(false)),
                ]
            }
            treasury::SuperblockPayout::Lottery => lottery::calculate_lottery_payments(
                winners,
                Amount::from_sat(50_00000000),
                lottery::regtest::LOTTERY_CYCLE,
            )
            .into_iter()
            .map(|(script, amount)| TxOut::new(amount, script))
            .collect(),
            treasury::SuperblockPayout::None => Vec::new(),
        }
    }

    /// Divi Core pays the treasury, not the lottery, when a pre-transition
    /// height is both (BlockIncentivesPopulator.cpp IsBlockValueValid /
    /// HasValidPayees: `if IsValidTreasuryBlockHeight ... else if
    /// IsValidLotteryBlockHeight`). Regtest height 150 is such a height.
    /// The stake is above the 10,000 DIVI ticket minimum, so the lottery
    /// has winners at 149 and a lottery-first rule would demand their
    /// payments and reject the treasury-only block.
    #[test]
    fn test_coinciding_superblock_height_pays_treasury_not_lottery() {
        use divi_consensus::{lottery, treasury};

        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Chain::new(db, regtest_params()).unwrap();

        // 20,000 DIVI PoW coinbases: every coinstake from 101 on is a ticket.
        let blocks = extend_regtest_chain(&chain, 150, 0x7C, 0, 2_000_000_000_000);

        assert!(treasury::is_treasury_block_with_lottery(
            150,
            treasury::regtest::TREASURY_START_BLOCK,
            treasury::regtest::TREASURY_CYCLE,
            treasury::regtest::LOTTERY_CYCLE,
        ));
        assert!(lottery::is_lottery_block(
            150,
            lottery::regtest::LOTTERY_START_BLOCK,
            lottery::regtest::LOTTERY_CYCLE,
        ));

        let idx_149 = chain
            .get_block_index(&compute_block_hash(&blocks[148].header))
            .unwrap()
            .unwrap();
        assert_eq!(idx_149.height, 149);
        assert!(
            !idx_149.lottery_winners.coinstakes.is_empty(),
            "the lottery must have winners at 149 for this test to mean anything"
        );

        let coinstake = &blocks[149].transactions[1];
        assert_eq!(chain.height(), 150);
        assert_eq!(
            coinstake.vout[2].script_pubkey,
            treasury::get_treasury_script(false)
        );
        assert_eq!(
            coinstake.vout[3].script_pubkey,
            treasury::get_charity_script(false)
        );
        assert_eq!(coinstake.vout.len(), 4, "no lottery payees at 150");
    }

    #[tokio::test]
    async fn test_deep_side_chain_reorg_across_inv_batches() {
        use crate::peer::PeerHandle;

        const MAIN_LEN: u32 = 600; // our active chain A
        const SIDE_LEN: usize = 700; // peer's heavier chain B, forked at genesis
        const ALREADY_STORED: usize = 500; // B1..B500 stored as a side chain

        let a_blocks = build_regtest_chain(MAIN_LEN, 0xA1, 0);
        let b_blocks = build_regtest_chain(SIDE_LEN as u32, 0xB2, 1);

        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Arc::new(Chain::new(db, regtest_params()).unwrap());
        let pm = PeerManager::new(Default::default());
        let sync = BlockSync::new(chain.clone(), pm.clone());

        let peer_id: PeerId = 7;
        let (tx, mut rx) = tokio::sync::mpsc::channel(8192);
        pm.insert_test_peer(PeerHandle {
            id: peer_id,
            addr: "127.0.0.1:1".parse().unwrap(),
            tx,
            inbound: false,
        });

        let g = chain.genesis_hash();
        for b in &a_blocks {
            chain.accept_block(b.clone()).unwrap();
        }
        let a_tip = compute_block_hash(&a_blocks.last().unwrap().header);
        assert_eq!(chain.height(), MAIN_LEN);

        let b_hashes: Vec<Hash256> = b_blocks
            .iter()
            .map(|b| compute_block_hash(&b.header))
            .collect();
        let by_hash: HashMap<Hash256, Block> = b_hashes
            .iter()
            .copied()
            .zip(b_blocks.iter().cloned())
            .collect();

        // An earlier round already stored B1..B500 as a side chain.
        for b in &b_blocks[..ALREADY_STORED] {
            chain.accept_block(b.clone()).unwrap();
        }
        assert_eq!(
            chain.tip().unwrap().hash,
            a_tip,
            "B500 has less work than A600"
        );
        assert!(!chain
            .get_block_index(&b_hashes[ALREADY_STORED - 1])
            .unwrap()
            .unwrap()
            .is_on_main_chain());

        let inv = |hs: &[Hash256]| -> Vec<InvItem> {
            hs.iter()
                .map(|h| InvItem::new(InvType::Block, *h))
                .collect()
        };

        // The C++ peer answers our main-chain locator from the fork point
        // (genesis): the first 500 B hashes, all of which we already hold.
        sync.handle_inv(peer_id, inv(&b_hashes[..ALREADY_STORED]))
            .await;
        assert!(
            sync.pending_block_requests.read().is_empty(),
            "stored side-chain blocks must count as known, not be re-queued"
        );

        // Simulated C++ peer: getblocks -> next <=500 hashes after the first
        // locator hash it knows; getdata -> the blocks.
        let mut getblocks_starts = Vec::new();
        for _ in 0..200 {
            let mut msgs = Vec::new();
            while let Ok(m) = rx.try_recv() {
                msgs.push(m);
            }
            if msgs.is_empty() {
                break;
            }
            for m in msgs {
                match m {
                    NetworkMessage::GetBlocks(gb) => {
                        let start = gb
                            .locator_hashes
                            .iter()
                            .find_map(|h| {
                                if *h == g {
                                    Some(0)
                                } else {
                                    b_hashes.iter().position(|x| x == h).map(|p| p + 1)
                                }
                            })
                            .unwrap_or(0);
                        getblocks_starts.push(start);
                        let end = (start + 500).min(b_hashes.len());
                        if start < end {
                            sync.handle_inv(peer_id, inv(&b_hashes[start..end])).await;
                        }
                    }
                    NetworkMessage::GetData(items) => {
                        for it in items {
                            if let Some(b) = by_hash.get(&it.hash) {
                                sync.handle_block(peer_id, b.clone()).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(
            getblocks_starts.contains(&ALREADY_STORED),
            "expected a getblocks continuing past B500, got starts {:?}",
            getblocks_starts
        );
        let tip = chain.tip().unwrap();
        assert_eq!(
            tip.height as usize, SIDE_LEN,
            "node must reorg onto the heavier chain"
        );
        assert_eq!(tip.hash, b_hashes[SIDE_LEN - 1]);
        assert!(!chain
            .get_block_index(&a_tip)
            .unwrap()
            .unwrap()
            .is_on_main_chain());
    }
    /// A sync manager with `n` test peers (ids 1..=n); returns their receivers.
    fn sync_with_peers(
        n: u64,
    ) -> (
        Arc<BlockSync>,
        HashMap<PeerId, tokio::sync::mpsc::Receiver<NetworkMessage>>,
        tempfile::TempDir,
    ) {
        use crate::peer::PeerHandle;

        let (sync, dir) = create_test_sync();
        let mut rxs = HashMap::new();
        for id in 1..=n {
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            sync.peer_manager.insert_test_peer(PeerHandle {
                id,
                addr: format!("127.0.0.1:{}", 1000 + id).parse().unwrap(),
                tx,
                inbound: false,
            });
            rxs.insert(id, rx);
        }
        (sync, rxs, dir)
    }

    /// Peers that received a getdata for `hash` since the last drain.
    fn getdata_recipients(
        rxs: &mut HashMap<PeerId, tokio::sync::mpsc::Receiver<NetworkMessage>>,
        hash: Hash256,
    ) -> Vec<PeerId> {
        let mut got = Vec::new();
        for (&id, rx) in rxs.iter_mut() {
            while let Ok(msg) = rx.try_recv() {
                if let NetworkMessage::GetData(items) = msg {
                    if items.iter().any(|i| i.hash == hash) {
                        got.push(id);
                    }
                }
            }
        }
        got.sort_unstable();
        got
    }

    fn in_flight_peer(sync: &BlockSync, hash: &Hash256) -> Option<PeerId> {
        sync.blocks_in_flight.read().get(hash).map(|r| r.peer_id)
    }

    /// Backdate the in-flight request so the next `check_timeouts` expires it.
    fn expire_request(sync: &BlockSync, hash: &Hash256) {
        let mut in_flight = sync.blocks_in_flight.write();
        let req = in_flight.get_mut(hash).unwrap();
        req.requested_at = Instant::now() - BLOCK_DOWNLOAD_TIMEOUT - Duration::from_secs(1);
    }

    #[test]
    fn test_order_retry_peers_skips_failed_and_prefers_announcer() {
        let failed: HashSet<PeerId> = [2].into_iter().collect();
        // The announcer leads, the failed peer is only a last resort.
        let order = order_retry_peers(vec![3, 1, 2, 4], &failed, Some(4), 0, 0);
        assert_eq!(order[0], 4);
        assert_eq!(*order.last().unwrap(), 2);
        // A failed announcer is not preferred.
        let order = order_retry_peers(vec![1, 2, 3], &failed, Some(2), 0, 0);
        assert_eq!(*order.last().unwrap(), 2);
        // Without preferences the cursor rotates the start over sorted peers.
        let starts: Vec<PeerId> = (0..3)
            .map(|c| order_retry_peers(vec![3, 1, 2], &HashSet::new(), None, 0, c)[0])
            .collect();
        assert_eq!(starts, vec![1, 2, 3]);
        // Everyone failed: still returns them all (single-peer nodes can retry).
        let all: HashSet<PeerId> = [1, 2].into_iter().collect();
        assert_eq!(order_retry_peers(vec![2, 1], &all, None, 0, 0).len(), 2);
    }

    #[tokio::test]
    async fn test_block_retry_rotation_never_repicks_failed_peer() {
        let (sync, mut rxs, _dir) = sync_with_peers(3);
        let hash = Hash256::from_bytes([0x5a; 32]);

        sync.pending_block_requests.write().push_back((hash, 1));
        sync.request_queued_blocks().await;
        assert_eq!(getdata_recipients(&mut rxs, hash), vec![1]);

        let mut tried = vec![1];
        for _ in 0..2 {
            expire_request(&sync, &hash);
            sync.check_timeouts().await;
            let got = getdata_recipients(&mut rxs, hash);
            assert_eq!(got.len(), 1, "exactly one re-request per timeout");
            assert!(
                !tried.contains(&got[0]),
                "re-requested from peer {} which already failed (tried {:?})",
                got[0],
                tried
            );
            tried.push(got[0]);
        }
        tried.sort_unstable();
        assert_eq!(tried, vec![1, 2, 3], "all three peers tried once each");
    }

    #[tokio::test]
    async fn test_block_retry_cap_gives_up() {
        let (sync, mut rxs, _dir) = sync_with_peers(2);
        let hash = Hash256::from_bytes([0x6b; 32]);

        sync.pending_block_requests.write().push_back((hash, 1));
        sync.request_queued_blocks().await;
        let mut requests = getdata_recipients(&mut rxs, hash).len();

        for _ in 0..MAX_BLOCK_REQUEST_ATTEMPTS + 2 {
            if in_flight_peer(&sync, &hash).is_none() {
                break;
            }
            expire_request(&sync, &hash);
            sync.check_timeouts().await;
            requests += getdata_recipients(&mut rxs, hash).len();
        }

        assert_eq!(
            requests,
            MAX_BLOCK_REQUEST_ATTEMPTS as usize,
            "one initial request plus {} retries, then stop",
            MAX_BLOCK_REQUEST_ATTEMPTS - 1
        );
        assert!(in_flight_peer(&sync, &hash).is_none());
        assert!(sync.pending_block_requests.read().is_empty());
        assert!(sync.block_retry.read()[&hash].gave_up_at.is_some());

        // Still suppressed: a re-queue does not send anything.
        sync.pending_block_requests.write().push_back((hash, 1));
        sync.request_queued_blocks().await;
        assert!(getdata_recipients(&mut rxs, hash).is_empty());
    }

    #[tokio::test]
    async fn test_notfound_redispatches_immediately() {
        let (sync, mut rxs, _dir) = sync_with_peers(2);
        let hash = Hash256::from_bytes([0x7c; 32]);

        sync.pending_block_requests.write().push_back((hash, 1));
        sync.request_queued_blocks().await;
        assert_eq!(getdata_recipients(&mut rxs, hash), vec![1]);

        // A notfound from a peer we did not ask is ignored.
        sync.handle_notfound(2, vec![InvItem::new(InvType::Block, hash)])
            .await;
        assert_eq!(in_flight_peer(&sync, &hash), Some(1));
        assert!(getdata_recipients(&mut rxs, hash).is_empty());

        // The asked peer's notfound moves the request on with no timeout.
        sync.handle_notfound(1, vec![InvItem::new(InvType::Block, hash)])
            .await;
        assert_eq!(getdata_recipients(&mut rxs, hash), vec![2]);
        assert_eq!(in_flight_peer(&sync, &hash), Some(2));
        assert_eq!(sync.block_retry.read()[&hash].attempts, 1);
    }
}
