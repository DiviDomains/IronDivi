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

//! Transaction relay manager
//!
//! Handles transaction propagation over the P2P network.

use crate::message::{InvItem, InvType};
use crate::peer::PeerId;
use crate::peer_manager::PeerManager;
use crate::NetworkMessage;

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::Transaction;

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{debug, trace, warn};

/// Maximum transactions to track per peer
const MAX_TX_PER_PEER: usize = 5000;

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

/// Transaction relay manager
pub struct TxRelay {
    /// Peer manager for sending messages
    peer_manager: Arc<PeerManager>,

    /// Transactions we know each peer has (peer -> set of txids)
    peer_inventory: RwLock<HashMap<PeerId, HashSet<Hash256>>>,

    /// Peers that have each transaction (txid -> set of peers)
    tx_sources: RwLock<HashMap<Hash256, HashSet<PeerId>>>,

    /// Transactions we've already seen/processed
    seen_txs: RwLock<HashSet<Hash256>>,

    /// Transactions currently being requested
    txs_in_flight: RwLock<HashMap<Hash256, TxRequest>>,

    /// Queue of transactions to request
    request_queue: RwLock<VecDeque<(Hash256, PeerId)>>,

    /// Recently announced transactions (to avoid re-announcing)
    recently_announced: RwLock<HashMap<Hash256, Instant>>,

    /// Event channel for received transactions
    event_tx: broadcast::Sender<TxRelayEvent>,

    /// Whether a transaction is in the node's mempool and whether it is a
    /// held orphan; without it, the transactions seen here count as had
    have: RwLock<Option<HaveTx>>,
}

/// The node's view of a transaction: (in the mempool, a held orphan)
pub type HaveTx = Arc<dyn Fn(&Hash256) -> (bool, bool) + Send + Sync>;

impl TxRelay {
    /// Create a new transaction relay manager
    pub fn new(peer_manager: Arc<PeerManager>) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(1000);

        Arc::new(TxRelay {
            peer_manager,
            peer_inventory: RwLock::new(HashMap::new()),
            tx_sources: RwLock::new(HashMap::new()),
            seen_txs: RwLock::new(HashSet::new()),
            txs_in_flight: RwLock::new(HashMap::new()),
            request_queue: RwLock::new(VecDeque::new()),
            recently_announced: RwLock::new(HashMap::new()),
            event_tx,
            have: RwLock::new(None),
        })
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
        self.peer_inventory.write().remove(&peer_id);

        // Remove peer from tx_sources
        let mut tx_sources = self.tx_sources.write();
        for peers in tx_sources.values_mut() {
            peers.remove(&peer_id);
        }

        // Cancel in-flight requests from this peer
        let mut in_flight = self.txs_in_flight.write();
        let to_remove: Vec<_> = in_flight
            .iter()
            .filter(|(_, req)| req.peer_id == peer_id)
            .map(|(txid, _)| *txid)
            .collect();

        for txid in to_remove {
            in_flight.remove(&txid);
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

        trace!(
            "Received {} tx inv items from peer {}",
            tx_items.len(),
            peer_id
        );

        let mut new_txs = Vec::new();

        {
            let in_flight = self.txs_in_flight.read();

            // Track peer inventory
            let mut peer_inv = self.peer_inventory.write();
            let inv = peer_inv.entry(peer_id).or_default();

            // Limit inventory size per peer
            if inv.len() > MAX_TX_PER_PEER {
                // Remove oldest entries (just clear and start fresh)
                inv.clear();
            }

            let mut tx_sources = self.tx_sources.write();

            for item in tx_items {
                let txid = item.hash;

                // Track that this peer has this tx
                inv.insert(txid);
                tx_sources.entry(txid).or_default().insert(peer_id);

                // Check if we need to request it
                if !self.already_have(&txid) && !in_flight.contains_key(&txid) {
                    new_txs.push((txid, peer_id));
                }
            }
        }

        // Queue new transactions for request
        if !new_txs.is_empty() {
            debug!(
                "Queuing {} new transactions to request from peer {}",
                new_txs.len(),
                peer_id
            );

            let mut queue = self.request_queue.write();
            for (txid, peer) in new_txs {
                queue.push_back((txid, peer));
            }
        }

        // Process request queue
        self.process_request_queue().await;
    }

    /// Process the request queue
    async fn process_request_queue(&self) {
        let in_flight_count = self.txs_in_flight.read().len();
        if in_flight_count >= MAX_TX_IN_FLIGHT {
            return;
        }

        let to_request: Vec<_> = {
            let mut queue = self.request_queue.write();
            let mut requests = Vec::new();
            let in_flight = self.txs_in_flight.read();

            while requests.len() < MAX_TX_IN_FLIGHT - in_flight_count {
                match queue.pop_front() {
                    Some((txid, peer_id)) => {
                        // Skip if we already have it or it's in flight
                        if self.already_have(&txid) || in_flight.contains_key(&txid) {
                            continue;
                        }
                        requests.push((txid, peer_id));
                    }
                    None => break,
                }
            }
            requests
        };

        // Request transactions
        for (txid, peer_id) in to_request {
            self.request_tx(txid, peer_id).await;
        }
    }

    /// Request a transaction from a peer
    async fn request_tx(&self, txid: Hash256, peer_id: PeerId) {
        let inv = vec![InvItem::new(InvType::Tx, txid)];
        let msg = NetworkMessage::GetData(inv);

        if let Err(e) = self.peer_manager.send_to_peer(peer_id, msg).await {
            warn!("Failed to request tx {} from peer {}: {}", txid, peer_id, e);
            return;
        }

        trace!("Requested tx {} from peer {}", txid, peer_id);

        self.txs_in_flight.write().insert(
            txid,
            TxRequest {
                peer_id,
                requested_at: Instant::now(),
            },
        );
    }

    /// Handle received transaction
    pub async fn handle_tx(&self, peer_id: PeerId, tx: Transaction) {
        let txid = tx.txid();

        // Remove from in-flight
        self.txs_in_flight.write().remove(&txid);

        // The peer has it (Divi Core AddInventoryKnown, main.cpp:720)
        self.peer_inventory
            .write()
            .entry(peer_id)
            .or_default()
            .insert(txid);

        // One already in the mempool changes nothing there; one held as an
        // orphan is offered again, as its parent may have come in a block
        // (Divi Core checks AlreadyHave for an inv only, main.cpp:140-144).
        // One a whitelisted peer sends is relayed again, so the node serves
        // as a gateway for nodes behind it (Divi Core main.cpp:794-799)
        if self.in_mempool(&txid) {
            trace!("Already have tx {}", txid);
            if self.peer_manager.is_whitelisted(peer_id) {
                self.relay_tx(txid, Some(peer_id)).await;
            }
            return;
        }

        debug!("Received tx {} from peer {}", txid, peer_id);

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
                debug!(
                    "getdata item type {:?} (not tx), skipping hash {}",
                    item.inv_type, item.hash
                );
                continue;
            }

            if let Some(tx) = get_tx(&item.hash) {
                let tx_version = tx.version;
                let tx_vin = tx.vin.len();
                let tx_vout = tx.vout.len();
                let msg = NetworkMessage::Tx(tx);
                if let Err(e) = self.peer_manager.send_to_peer(peer_id, msg).await {
                    warn!("Failed to send tx {} to peer {}: {}", item.hash, peer_id, e);
                } else {
                    debug!(
                        "Sent tx {} to peer {} (version={}, vin={}, vout={})",
                        item.hash, peer_id, tx_version, tx_vin, tx_vout
                    );
                }
            } else {
                debug!(
                    "getdata: tx {} not found in mempool for peer {}",
                    item.hash, peer_id
                );
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

    /// Relay a transaction to peers that don't have it
    async fn relay_tx(&self, txid: Hash256, exclude_peer: Option<PeerId>) {
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
                    if let Some(inv) = peer_inventory.get(&peer_id) {
                        if inv.contains(&txid) {
                            return false;
                        }
                    }

                    true
                })
                .collect()
        };

        if peers_to_notify.is_empty() {
            return;
        }

        debug!("Relaying tx {} to {} peers", txid, peers_to_notify.len());

        let inv = vec![InvItem::new(InvType::Tx, txid)];
        let msg = NetworkMessage::Inv(inv);

        for peer_id in peers_to_notify {
            if let Err(e) = self.peer_manager.send_to_peer(peer_id, msg.clone()).await {
                trace!("Failed to relay tx inv to peer {}: {}", peer_id, e);
            }
        }
    }

    /// Check for timed out requests and retry
    pub async fn check_timeouts(&self) {
        let now = Instant::now();

        let timed_out: Vec<(Hash256, PeerId)> = {
            self.txs_in_flight
                .read()
                .iter()
                .filter(|(_, req)| now.duration_since(req.requested_at) > TX_REQUEST_TIMEOUT)
                .map(|(txid, req)| (*txid, req.peer_id))
                .collect()
        };

        for (txid, peer_id) in timed_out {
            warn!("Tx {} request timed out from peer {}", txid, peer_id);
            self.txs_in_flight.write().remove(&txid);

            // Try to get from another peer
            let alternate_peer = {
                let tx_sources = self.tx_sources.read();
                tx_sources
                    .get(&txid)
                    .and_then(|peers| peers.iter().find(|&&p| p != peer_id).copied())
            };

            if let Some(other_peer) = alternate_peer {
                debug!("Retrying tx {} from peer {}", txid, other_peer);
                self.request_tx(txid, other_peer).await;
            }
        }

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
        TxRelayStats {
            seen_count: self.seen_txs.read().len(),
            in_flight_count: self.txs_in_flight.read().len(),
            queue_size: self.request_queue.read().len(),
            tracked_peers: self.peer_inventory.read().len(),
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
            .entry(peer_id)
            .or_default()
            .insert(txid);

        // Add to tx_sources
        relay
            .tx_sources
            .write()
            .entry(txid)
            .or_default()
            .insert(peer_id);

        assert!(relay.peer_inventory.read().contains_key(&peer_id));

        relay.remove_peer(peer_id);

        assert!(!relay.peer_inventory.read().contains_key(&peer_id));
        assert!(!relay
            .tx_sources
            .read()
            .get(&txid)
            .map(|s| s.contains(&peer_id))
            .unwrap_or(false));
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
}
