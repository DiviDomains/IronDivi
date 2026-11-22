// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Transaction relay manager
//!
//! Handles transaction propagation over the P2P network.

use crate::message::{InvItem, InvType};
use crate::peer::PeerId;
use crate::peer_manager::PeerManager;
use crate::NetworkMessage;

use divi_primitives::amount::Amount;
use divi_primitives::counted::{self, Site};
use divi_primitives::hash::Hash256;
use divi_primitives::redact::WalletTxid;
use divi_primitives::transaction::Transaction;

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::warn;

/// Maximum transactions to track per peer
const MAX_TX_PER_PEER: usize = 5000;
const MAX_PENDING: usize = 4096;
const MAX_PENDING_PER_PEER: usize = 256;
const MAX_FLIGHT_PER_PEER: usize = 32;

/// Recent inventory hints, never an authoritative record of accepted objects.
/// Dropping a hint can cause a redundant announcement, not a validation decision.
pub struct PeerInventory {
    peers: HashMap<PeerId, RecentInventory>,
    per_peer: usize,
    max_peers: usize,
    ttl: Duration,
}

#[derive(Default)]
struct RecentInventory {
    order: VecDeque<(Instant, Hash256)>,
    items: HashMap<Hash256, Instant>,
}

impl PeerInventory {
    /// Bound both the number of peers retained across churn and each peer's hints.
    pub fn new(per_peer: usize, max_peers: usize, ttl: Duration) -> Self {
        assert!(per_peer > 0 && max_peers > 0);
        Self {
            peers: HashMap::new(),
            per_peer,
            max_peers,
            ttl,
        }
    }

    pub fn note(&mut self, peer: PeerId, hash: Hash256, now: Instant) {
        if self.peers.len() == self.max_peers && !self.peers.contains_key(&peer) {
            if let Some(oldest) = self
                .peers
                .iter()
                .min_by_key(|(id, inv)| (inv.order.back().map(|e| e.0), **id))
                .map(|(id, _)| *id)
            {
                self.peers.remove(&oldest);
            }
        }
        let inv = self.peers.entry(peer).or_default();
        inv.expire(now, self.ttl);
        if inv.items.contains_key(&hash) {
            return;
        }
        if inv.order.len() == self.per_peer {
            let (_, old) = inv.order.pop_front().unwrap();
            inv.items.remove(&old);
        }
        inv.items.insert(hash, now);
        inv.order.push_back((now, hash));
    }

    pub fn knows(&self, peer: PeerId, hash: &Hash256, now: Instant) -> bool {
        self.peers
            .get(&peer)
            .and_then(|inv| inv.items.get(hash))
            .is_some_and(|at| now.saturating_duration_since(*at) < self.ttl)
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.remove(&peer);
    }

    pub fn expire(&mut self, now: Instant) {
        self.peers.retain(|_, inv| {
            inv.expire(now, self.ttl);
            !inv.order.is_empty()
        });
    }

    fn alternate(&self, hash: &Hash256, except: PeerId, now: Instant) -> Option<PeerId> {
        self.peers
            .keys()
            .copied()
            .filter(|id| *id != except && self.knows(*id, hash, now))
            .min_by_key(|id| (*id < except, *id))
    }
}

impl RecentInventory {
    fn expire(&mut self, now: Instant, ttl: Duration) {
        while self
            .order
            .front()
            .is_some_and(|entry| now.saturating_duration_since(entry.0) >= ttl)
        {
            let (_, old) = self.order.pop_front().unwrap();
            self.items.remove(&old);
        }
    }
}

#[derive(Default)]
struct Requests {
    queued: HashMap<PeerId, VecDeque<Hash256>>,
    queued_ids: HashMap<Hash256, PeerId>,
    ready: VecDeque<PeerId>,
    flight: HashMap<Hash256, TxRequest>,
}

impl Requests {
    fn enqueue(&mut self, hash: Hash256, peer: PeerId) {
        if self.queued_ids.len() == MAX_PENDING
            || self.flight.contains_key(&hash)
            || self.queued_ids.contains_key(&hash)
        {
            return;
        }
        let q = self.queued.entry(peer).or_default();
        if q.len() == MAX_PENDING_PER_PEER {
            return;
        }
        if q.is_empty() {
            self.ready.push_back(peer);
        }
        q.push_back(hash);
        self.queued_ids.insert(hash, peer);
    }
}

/// Maximum transactions to have in flight
const MAX_TX_IN_FLIGHT: usize = 100;

/// Timeout for transaction requests
const TX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Minimum fee rate for relay (satoshis per byte)
/// TODO: Use this when implementing fee-based relay filtering
const _MIN_RELAY_FEE_RATE: f64 = 1.0;

/// Event emitted when a transaction is received
#[derive(Debug, Clone)]
pub struct TxRelayEvent {
    /// Transaction ID
    pub txid: Hash256,
    /// The transaction
    pub tx: Transaction,
    /// Fee (if known)
    pub fee: Option<Amount>,
    /// Peer that sent it
    pub from_peer: PeerId,
}

/// Transaction request tracking
struct TxRequest {
    /// Peer we requested from
    peer_id: PeerId,
    /// When we sent the request
    requested_at: Instant,
}

/// How long a relayed transaction is kept to answer getdata (Divi Core's
/// 15 minutes, net.cpp:1588)
const RELAYED_KEEP_SECS: i64 = 15 * 60;

/// Transaction relay manager
pub struct TxRelay {
    /// Peer manager for sending messages
    peer_manager: Arc<PeerManager>,

    /// Transactions we know each peer has (peer -> set of txids)
    peer_inventory: RwLock<PeerInventory>,

    /// Transactions we've already seen/processed
    seen_txs: RwLock<HashSet<Hash256>>,

    /// Transactions currently being requested
    requests: RwLock<Requests>,

    /// Recently announced transactions (to avoid re-announcing)
    recently_announced: RwLock<HashMap<Hash256, Instant>>,

    /// Event channel for received transactions
    event_tx: broadcast::Sender<TxRelayEvent>,

    /// Transactions announced to peers, kept until the Unix time given so a
    /// getdata is answered from here, in a block by then or not (Divi Core
    /// mapRelay, net.cpp:1565-1590)
    relayed: RwLock<HashMap<Hash256, (Transaction, i64)>>,

    /// Whether a transaction is in the node's mempool and whether it is a
    /// held orphan; without it, the transactions seen here count as had
    have: RwLock<Option<HaveTx>>,

    /// The mempool's transaction by txid, so an announcement can be held to
    /// each peer's bloom filter
    tx_source: RwLock<Option<TxSource>>,
}

/// The node's view of a transaction: (in the mempool, a held orphan)
pub type HaveTx = Arc<dyn Fn(&Hash256) -> (bool, bool) + Send + Sync>;

/// Looks a transaction up by txid (the node's mempool)
pub type TxSource = Arc<dyn Fn(&Hash256) -> Option<Transaction> + Send + Sync>;

impl TxRelay {
    /// Create a new transaction relay manager
    pub fn new(peer_manager: Arc<PeerManager>) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(1000);

        Arc::new(TxRelay {
            peer_manager,
            peer_inventory: RwLock::new(PeerInventory::new(
                MAX_TX_PER_PEER,
                256,
                Duration::from_secs(900),
            )),
            seen_txs: RwLock::new(HashSet::new()),
            requests: RwLock::new(Requests::default()),
            recently_announced: RwLock::new(HashMap::new()),
            event_tx,
            relayed: RwLock::new(HashMap::new()),
            have: RwLock::new(None),
            tx_source: RwLock::new(None),
        })
    }

    /// Where announcements find the transaction to test peers' filters with
    pub fn set_tx_source(&self, source: TxSource) {
        *self.tx_source.write() = Some(source);
    }

    /// Subscribe to transaction events
    pub fn subscribe(&self) -> broadcast::Receiver<TxRelayEvent> {
        self.event_tx.subscribe()
    }

    /// Check if we've seen a transaction
    pub fn has_seen(&self, txid: &Hash256) -> bool {
        self.seen_txs.read().contains(txid)
    }

    /// Divi Core's AlreadyHave for a transaction (main.cpp:140-144): in the
    /// mempool or a held orphan. A transaction refused before, or one in a
    /// block, is asked for again.
    pub fn set_have_check(&self, have: HaveTx) {
        *self.have.write() = Some(have);
    }

    fn already_have(&self, txid: &Hash256) -> bool {
        match &*self.have.read() {
            Some(have) => {
                let (in_mempool, orphan) = have(txid);
                in_mempool || orphan
            }
            None => self.seen_txs.read().contains(txid),
        }
    }

    fn in_mempool(&self, txid: &Hash256) -> bool {
        match &*self.have.read() {
            Some(have) => have(txid).0,
            None => self.seen_txs.read().contains(txid),
        }
    }

    /// Mark a transaction as seen (e.g., from mempool or block)
    pub fn mark_seen(&self, txid: Hash256) {
        self.seen_txs.write().insert(txid);
    }

    /// Remove a peer from tracking
    pub fn remove_peer(&self, peer_id: PeerId) {
        let now = self.peer_manager.clock().now();
        let mut inv = self.peer_inventory.write();
        inv.remove_peer(peer_id);
        let mut req = self.requests.write();
        let mut retry = Vec::new();
        req.flight.retain(|hash, r| {
            if r.peer_id == peer_id {
                retry.push(*hash);
            }
            r.peer_id != peer_id
        });
        if let Some(q) = req.queued.remove(&peer_id) {
            req.ready.retain(|p| *p != peer_id);
            retry.extend(q);
        }
        for hash in retry {
            req.queued_ids.remove(&hash);
            if let Some(other) = inv.alternate(&hash, peer_id, now) {
                req.enqueue(hash, other);
            }
        }
    }

    /// Handle inventory announcement from a peer
    pub async fn handle_inv(&self, peer_id: PeerId, items: Vec<InvItem>) {
        let tx_items: Vec<_> = items
            .into_iter()
            .filter(|item| item.inv_type == InvType::Tx)
            .collect();

        if tx_items.is_empty() {
            return;
        }

        counted::hit(Site::RelayInv);

        {
            let mut inv = self.peer_inventory.write();
            let now = self.peer_manager.clock().now();
            let mut req = self.requests.write();
            for item in tx_items {
                let txid = item.hash;
                inv.note(peer_id, txid, now);
                if !self.already_have(&txid) {
                    req.enqueue(txid, peer_id);
                }
            }
        }
        self.process_request_queue();
    }

    /// Process the request queue
    fn process_request_queue(&self) {
        let mut req = self.requests.write();
        if req.queued.is_empty() {
            return;
        }
        let mut by_peer = HashMap::<PeerId, usize>::new();
        for r in req.flight.values() {
            *by_peer.entry(r.peer_id).or_default() += 1;
        }
        let mut blocked = 0;
        while req.flight.len() < MAX_TX_IN_FLIGHT && blocked < req.ready.len() {
            let peer = req.ready.pop_front().unwrap();
            if by_peer.get(&peer).copied().unwrap_or(0) >= MAX_FLIGHT_PER_PEER {
                req.ready.push_back(peer);
                blocked += 1;
                continue;
            }
            blocked = 0;
            let q = req.queued.get_mut(&peer).unwrap();
            let hash = q.pop_front().unwrap();
            if q.is_empty() {
                req.queued.remove(&peer);
            } else {
                req.ready.push_back(peer);
            }
            req.queued_ids.remove(&hash);
            if self.already_have(&hash) {
                continue;
            }
            let msg = NetworkMessage::GetData(vec![InvItem::new(InvType::Tx, hash)]);
            if let Err(e) = self.peer_manager.send_required(peer, msg) {
                tracing::debug!("Did not request tx from peer {}: {}", peer, e);
                continue;
            }
            counted::hit(Site::RelayRequested);
            req.flight.insert(
                hash,
                TxRequest {
                    peer_id: peer,
                    requested_at: self.peer_manager.clock().now(),
                },
            );
            *by_peer.entry(peer).or_default() += 1;
        }
    }

    /// Handle received transaction
    pub async fn handle_tx(&self, peer_id: PeerId, tx: Transaction) {
        let txid = tx.txid();

        // Remove from in-flight
        let released = {
            let mut req = self.requests.write();
            let released = req.flight.remove(&txid).is_some();
            if let Some(peer) = req.queued_ids.remove(&txid) {
                let q = req.queued.get_mut(&peer).unwrap();
                q.retain(|hash| *hash != txid);
                if q.is_empty() {
                    req.queued.remove(&peer);
                    req.ready.retain(|p| *p != peer);
                }
            }
            released
        };
        if released {
            self.process_request_queue();
        }

        // The peer has it (Divi Core AddInventoryKnown, main.cpp:720)
        self.peer_inventory
            .write()
            .note(peer_id, txid, self.peer_manager.clock().now());

        // One already in the mempool changes nothing there; one held as an
        // orphan is offered again, as its parent may have come in a block
        // (Divi Core checks AlreadyHave for an inv only, main.cpp:140-144).
        // One a whitelisted peer sends is relayed again, so the node serves
        // as a gateway for nodes behind it (Divi Core main.cpp:794-799)
        if self.in_mempool(&txid) {
            counted::hit(Site::RelayAlreadyHave);
            if self.peer_manager.is_whitelisted(peer_id) {
                self.relay_tx(txid, Some(peer_id)).await;
            }
            return;
        }

        // No per-tx line here or in relay_tx: a "Received" line exists only
        // for a peer's tx, so a "Relaying" line without one names a tx this
        // node sent itself.

        self.seen_txs.write().insert(txid);

        // Emit event for mempool processing
        let event = TxRelayEvent {
            txid,
            tx: tx.clone(),
            fee: None, // Fee calculated by mempool
            from_peer: peer_id,
        };

        // The mempool decides; it is relayed once accepted (relay_accepted),
        // as Divi Core relays a transaction only after AcceptToMemoryPool took
        // it (main.cpp:732-734), so a transaction it cannot take yet, such as
        // a child whose parent has not come, is not announced
        let _ = self.event_tx.send(event);
    }

    /// Keep a transaction that is announced for 15 minutes, as Divi Core keeps
    /// what it relays in mapRelay (net.cpp:1580-1590); older ones go
    pub fn keep_relayed(&self, tx: Transaction) {
        let now = divi_primitives::clock::now();
        let mut relayed = self.relayed.write();
        relayed.retain(|_, (_, until)| *until > now);
        relayed.insert(tx.txid(), (tx, now + RELAYED_KEEP_SECS));
    }

    /// A transaction announced in the last 15 minutes (RepeatRelayedInventory,
    /// net.cpp:1565-1574)
    pub fn relayed_tx(&self, txid: &Hash256) -> Option<Transaction> {
        let now = divi_primitives::clock::now();
        self.relayed
            .read()
            .get(txid)
            .filter(|(_, until)| *until > now)
            .map(|(tx, _)| tx.clone())
    }

    /// Whether `peer_id` is known to have `txid` (it announced or was told of
    /// it): Divi Core's setInventoryKnown
    pub fn peer_knows(&self, peer_id: PeerId, txid: &Hash256) -> bool {
        self.peer_inventory
            .read()
            .knows(peer_id, txid, self.peer_manager.clock().now())
    }

    /// Relay a transaction the mempool took, to every peer but the one it came
    /// from (Divi Core RelayTransactionToAllPeers after AcceptToMemoryPool,
    /// main.cpp:734, and for an orphan accepted once its parent came, :763)
    pub async fn relay_accepted(&self, txid: Hash256, from_peer: Option<PeerId>) {
        self.relay_tx(txid, from_peer).await;
    }

    /// Handle getdata request for transactions
    pub async fn handle_getdata(
        &self,
        peer_id: PeerId,
        items: Vec<InvItem>,
        get_tx: impl Fn(&Hash256) -> Option<Transaction>,
    ) {
        for item in items {
            if item.inv_type != InvType::Tx {
                counted::hit(Site::RelayGetdataNotTx);
                continue;
            }

            if let Some(tx) = get_tx(&item.hash) {
                let msg = NetworkMessage::Tx(tx);
                if let Err(e) = self.peer_manager.send_to_peer(peer_id, msg).await {
                    warn!(
                        "Failed to send tx {} to peer {}: {}",
                        WalletTxid(item.hash),
                        peer_id,
                        e
                    );
                }
            } else {
                counted::hit(Site::RelayGetdataMissing);
            }
        }
    }

    /// Announce a new transaction to peers
    pub async fn announce_tx(&self, txid: Hash256) {
        // Check if recently announced
        {
            let mut recently = self.recently_announced.write();
            if let Some(time) = recently.get(&txid) {
                if time.elapsed() < Duration::from_secs(30) {
                    return; // Already announced recently
                }
            }
            recently.insert(txid, Instant::now());
        }

        self.relay_tx(txid, None).await;
    }

    /// Announce mempool transactions again to every peer not known to have
    /// them, as Divi Core's RebroadcastSomeMempoolTxs relays each to all peers
    /// (main.cpp:1269-1271)
    pub async fn rebroadcast(&self, txids: &[Hash256]) {
        for txid in txids {
            self.relay_tx(*txid, None).await;
        }
    }

    /// Relay a transaction to peers that don't have it: only to a peer that
    /// wants transactions, and that one's bloom filter matches (which the match
    /// updates), as Divi Core's RelayTransaction (net.cpp:1593-1606)
    async fn relay_tx(&self, txid: Hash256, exclude_peer: Option<PeerId>) {
        let source = self.tx_source.read().clone();
        // The mempool's copy, else the one kept since it was announced
        let tx = source
            .and_then(|lookup| lookup(&txid))
            .or_else(|| self.relayed_tx(&txid));
        let peers_to_notify: Vec<PeerId> = {
            let peer_inventory = self.peer_inventory.read();
            let all_peers = self.peer_manager.connected_peers();

            all_peers
                .into_iter()
                .filter(|&peer_id| {
                    // Exclude the source peer
                    if exclude_peer == Some(peer_id) {
                        return false;
                    }

                    // Check if peer already has this tx
                    if peer_inventory.knows(peer_id, &txid, self.peer_manager.clock().now()) {
                        return false;
                    }

                    let Some(stats) = self.peer_manager.peer_stats(peer_id) else {
                        return true;
                    };
                    if !stats.bloom.relays_txs() {
                        return false;
                    }
                    match &tx {
                        Some(tx) => stats.bloom.filter().is_relevant_and_update(tx),
                        None => true,
                    }
                })
                .collect()
        };

        if peers_to_notify.is_empty() {
            return;
        }

        let inv = vec![InvItem::new(InvType::Tx, txid)];
        let msg = NetworkMessage::Inv(inv);

        for peer_id in peers_to_notify {
            if self.peer_manager.send_gossip(peer_id, msg.clone()).is_err() {
                counted::hit(Site::RelayInvSendFailed);
            }
        }
    }

    /// Check for timed out requests and retry
    pub async fn check_timeouts(&self) {
        {
            let mut inv = self.peer_inventory.write();
            let mut requests = self.requests.write();
            let now = self.peer_manager.clock().now();
            inv.expire(now);
            let mut retry = Vec::new();
            requests.flight.retain(|hash, r| {
                if now.saturating_duration_since(r.requested_at) < TX_REQUEST_TIMEOUT {
                    return true;
                }
                if let Some(other) = inv.alternate(hash, r.peer_id, now) {
                    retry.push((*hash, other));
                }
                false
            });
            for (hash, peer) in retry {
                requests.enqueue(hash, peer);
            }
        }
        self.process_request_queue();

        // Clean up old entries from recently_announced
        {
            let mut recently = self.recently_announced.write();
            recently.retain(|_, time| time.elapsed() < Duration::from_secs(300));
        }

        // Clean up old entries from seen_txs (keep last 10000)
        {
            let mut seen = self.seen_txs.write();
            if seen.len() > 10000 {
                // Just clear oldest half
                let to_keep: HashSet<_> = seen.iter().take(5000).copied().collect();
                *seen = to_keep;
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> TxRelayStats {
        let tracked_peers = self.peer_inventory.read().peers.len();
        let requests = self.requests.read();
        TxRelayStats {
            seen_count: self.seen_txs.read().len(),
            in_flight_count: requests.flight.len(),
            queue_size: requests.queued_ids.len(),
            tracked_peers,
        }
    }
}

/// Transaction relay statistics
#[derive(Debug, Clone)]
pub struct TxRelayStats {
    /// Number of seen transactions
    pub seen_count: usize,
    /// Number of transactions in flight
    pub in_flight_count: usize,
    /// Request queue size
    pub queue_size: usize,
    /// Number of tracked peers
    pub tracked_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::PeerManagerConfig;

    fn create_test_relay() -> Arc<TxRelay> {
        let config = PeerManagerConfig::default();
        let peer_manager = PeerManager::new(config);
        TxRelay::new(peer_manager)
    }

    #[test]
    fn test_relay_creation() {
        let relay = create_test_relay();
        let stats = relay.stats();
        assert_eq!(stats.seen_count, 0);
        assert_eq!(stats.in_flight_count, 0);
    }

    #[test]
    fn test_mark_seen() {
        let relay = create_test_relay();
        let txid = Hash256::from_bytes([1u8; 32]);

        assert!(!relay.has_seen(&txid));
        relay.mark_seen(txid);
        assert!(relay.has_seen(&txid));
    }

    #[test]
    fn test_peer_removal() {
        let relay = create_test_relay();
        let peer_id = 1;
        let txid = Hash256::from_bytes([1u8; 32]);

        // Add to peer inventory
        relay
            .peer_inventory
            .write()
            .note(peer_id, txid, Instant::now());
        assert!(relay.peer_knows(peer_id, &txid));

        relay.remove_peer(peer_id);

        assert!(!relay.peer_knows(peer_id, &txid));
    }

    #[test]
    fn d4_inventory_expires_and_evicts_without_losing_recent_hints() {
        let ttl = Duration::from_secs(10);
        let t = Instant::now();
        let mut inv = PeerInventory::new(2, 2, ttl);
        let [a, b, c] = [1, 2, 3].map(|n| Hash256([n; 32]));
        inv.note(1, a, t);
        inv.note(1, b, t);
        inv.note(1, c, t);
        assert!(!inv.knows(1, &a, t));
        assert!(inv.knows(1, &b, t));
        inv.note(2, c, t + Duration::from_secs(1));
        inv.note(3, c, t + Duration::from_secs(2));
        assert!(!inv.knows(1, &c, t));
        assert_eq!(inv.alternate(&c, 3, t + ttl), Some(2));
        assert_eq!(inv.alternate(&c, 3, t + ttl + Duration::from_secs(1)), None);
        inv.note(2, a, t + ttl + Duration::from_secs(1));
        assert_eq!(inv.peers[&2].items.len(), 1);
        inv.expire(t + ttl * 3);
        assert!(inv.peers.is_empty());
    }

    #[tokio::test]
    async fn d4_duplicate_inv_and_disconnect_transfer_one_request() {
        let relay = create_test_relay();
        let mut first = test_peer(&relay, 1);
        let mut second = test_peer(&relay, 2);
        let a = Hash256([7; 32]);
        let item = InvItem::new(InvType::Tx, a);
        relay.handle_inv(1, vec![item.clone(), item.clone()]).await;
        relay.handle_inv(2, vec![item]).await;
        assert!(matches!(first.try_recv(), Ok(NetworkMessage::GetData(_))));
        assert!(first.try_recv().is_err() && second.try_recv().is_err());
        relay.remove_peer(1);
        relay.check_timeouts().await;
        assert!(
            matches!(second.try_recv(),Ok(NetworkMessage::GetData(items)) if items.len()==1 && items[0].hash==a)
        );
        assert_eq!(relay.stats().in_flight_count, 1);
    }

    #[tokio::test]
    async fn d4_timeout_rotates_and_leaves_room_for_another_peer() {
        let clock = crate::peer_clock::PeerClock::skippable(Duration::from_secs(1));
        let relay = TxRelay::new(PeerManager::with_clock(Default::default(), clock.clone()));
        let mut first = test_peer(&relay, 1);
        let mut second = test_peer(&relay, 2);
        let mut third = test_peer(&relay, 3);
        for n in 0..MAX_FLIGHT_PER_PEER {
            let hash = Hash256([n as u8; 32]);
            relay
                .handle_inv(1, vec![InvItem::new(InvType::Tx, hash)])
                .await;
            assert!(matches!(first.try_recv(), Ok(NetworkMessage::GetData(_))));
        }
        let next = InvItem::new(InvType::Tx, Hash256([241; 32]));
        relay.handle_inv(1, vec![next.clone()]).await;
        assert!(first.try_recv().is_err());
        let independent = InvItem::new(InvType::Tx, Hash256([242; 32]));
        relay.handle_inv(2, vec![independent]).await;
        assert!(matches!(second.try_recv(), Ok(NetworkMessage::GetData(_))));
        let retry = InvItem::new(InvType::Tx, Hash256([0; 32]));
        relay.handle_inv(2, vec![retry.clone()]).await;
        relay.handle_inv(3, vec![retry.clone()]).await;
        clock.skip(TX_REQUEST_TIMEOUT);
        relay.check_timeouts().await;
        assert!(
            matches!(first.try_recv(), Ok(NetworkMessage::GetData(items)) if items == vec![next])
        );
        assert!(
            matches!(second.try_recv(), Ok(NetworkMessage::GetData(items)) if items == vec![retry.clone()])
        );
        clock.skip(TX_REQUEST_TIMEOUT);
        relay.check_timeouts().await;
        assert!(
            matches!(third.try_recv(), Ok(NetworkMessage::GetData(items)) if items == vec![retry])
        );
        assert_eq!(relay.stats().queue_size, 0);
    }

    /// A peer and the receiver of the messages sent to it
    fn test_peer(relay: &TxRelay, id: PeerId) -> tokio::sync::mpsc::Receiver<NetworkMessage> {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        relay
            .peer_manager
            .insert_test_peer(crate::peer::PeerHandle {
                id,
                addr: format!("127.0.0.1:{}", 2000 + id).parse().unwrap(),
                tx,
                inbound: false,
                stats: Default::default(),
            });
        rx
    }

    fn invs(rx: &mut tokio::sync::mpsc::Receiver<NetworkMessage>) -> Vec<Hash256> {
        let mut got = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let NetworkMessage::Inv(items) = msg {
                got.extend(items.iter().map(|i| i.hash));
            }
        }
        got
    }

    /// A received transaction is announced to the other peers only once the
    /// mempool took it (Divi Core main.cpp:732-734): a child that came before
    /// its parent is not announced while it waits, then is when accepted
    /// (:763)
    #[tokio::test]
    async fn a_received_transaction_is_announced_only_once_accepted() {
        let relay = create_test_relay();
        let _from = test_peer(&relay, 1);
        let mut other = test_peer(&relay, 2);
        let mut events = relay.subscribe();
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![],
            lock_time: 7,
        };
        let txid = tx.txid();

        relay.handle_tx(1, tx).await;
        assert_eq!(events.try_recv().map(|e| e.txid).ok(), Some(txid));
        assert!(
            invs(&mut other).is_empty(),
            "announced before the mempool took it"
        );

        relay.relay_accepted(txid, Some(1)).await;
        assert_eq!(invs(&mut other), vec![txid]);
    }

    #[test]
    fn test_stats() {
        let relay = create_test_relay();

        // Mark some txs as seen
        for i in 0..10 {
            relay.mark_seen(Hash256::from_bytes([i; 32]));
        }

        let stats = relay.stats();
        assert_eq!(stats.seen_count, 10);
    }

    fn test_tx(n: u8) -> Transaction {
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{OutPoint, TxIn, TxOut};
        Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([n; 32]), 0),
                Script::new(),
                u32::MAX,
            )],
            vout: vec![TxOut::new(Amount::from_sat(1000), Script::new())],
            lock_time: 0,
        }
    }

    /// AlreadyHave (main.cpp:140-144): an inv is asked for unless the
    /// transaction is in the mempool or a held orphan; one seen and refused
    /// before is asked for again
    #[tokio::test]
    async fn an_inv_is_asked_for_unless_the_node_holds_the_transaction() {
        let relay = create_test_relay();
        let (in_pool, orphan, refused) = (
            Hash256::from_bytes([3; 32]),
            Hash256::from_bytes([4; 32]),
            Hash256::from_bytes([5; 32]),
        );
        relay.set_have_check(Arc::new(move |t| (*t == in_pool, *t == orphan)));
        relay.mark_seen(refused);
        let mut rx = test_peer(&relay, 1);
        let peer = 1;
        let items = [in_pool, orphan, refused]
            .iter()
            .map(|h| InvItem::new(InvType::Tx, *h))
            .collect();
        relay.handle_inv(peer, items).await;
        let mut asked = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let NetworkMessage::GetData(items) = msg {
                asked.extend(items.into_iter().map(|i| i.hash));
            }
        }
        assert_eq!(asked, vec![refused]);
    }

    /// A transaction message goes to the mempool unless the transaction is in
    /// it already: a held orphan sent again is offered again, since its parent
    /// may have come in a block
    #[tokio::test]
    async fn a_held_orphan_sent_again_is_offered_to_the_mempool() {
        let relay = create_test_relay();
        let (orphan, pooled) = (test_tx(6), test_tx(7));
        let (orphan_id, pooled_id) = (orphan.txid(), pooled.txid());
        relay.set_have_check(Arc::new(move |t| (*t == pooled_id, *t == orphan_id)));
        let mut events = relay.subscribe();
        let _rx = test_peer(&relay, 1);
        let peer = 1;
        relay.handle_tx(peer, orphan).await;
        relay.handle_tx(peer, pooled).await;
        assert_eq!(events.try_recv().map(|e| e.txid).ok(), Some(orphan_id));
        assert!(
            events.try_recv().is_err(),
            "the one in the mempool is not offered"
        );
    }

    /// A transaction announced is kept 15 minutes to answer getdata, in a
    /// block by then or not; an older one is gone (Divi Core mapRelay,
    /// net.cpp:1565-1590)
    #[test]
    fn a_relayed_transaction_is_kept_for_getdata() {
        let relay = create_test_relay();
        let tx = test_tx(8);
        relay.keep_relayed(tx.clone());
        assert_eq!(relay.relayed_tx(&tx.txid()), Some(tx.clone()));
        let old = test_tx(9);
        relay
            .relayed
            .write()
            .insert(old.txid(), (old.clone(), divi_primitives::clock::now() - 1));
        assert_eq!(relay.relayed_tx(&old.txid()), None, "past its 15 minutes");
        relay.keep_relayed(test_tx(10));
        assert!(
            !relay.relayed.read().contains_key(&old.txid()),
            "dropped when the map is next written"
        );
    }
}
