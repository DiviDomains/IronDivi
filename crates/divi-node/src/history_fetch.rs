// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Fetch a block this node has pruned from a full-history peer, and verify it.
//!
//! The block hash and merkle root come from our own block index, so a peer can withhold a
//! block or send garbage, but cannot make us accept a different block. If no full-history
//! peer returns a verified block, the fetch fails; callers must refuse and never guess.

use divi_crypto::{compute_block_hash, compute_merkle_root};
use divi_network::message::{InvItem, InvType};
use divi_network::peer::PeerId;
use divi_network::{NetworkMessage, PeerManager};
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// Why a fetch gave up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// No connected peer advertises `NODE_NETWORK`.
    NoFullPeers,
    /// Every full-history peer timed out, said `notfound`, or sent a block that failed checks.
    NotAvailable,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::NoFullPeers => write!(f, "no full-history peer connected"),
            FetchError::NotAvailable => {
                write!(f, "no full-history peer returned a verified block")
            }
        }
    }
}

impl std::error::Error for FetchError {}

/// True if `block` is the block with `hash` and its transactions match `merkle_root`.
pub fn verify_block(block: &Block, hash: &Hash256, merkle_root: &Hash256) -> bool {
    compute_block_hash(&block.header) == *hash
        && block.header.merkle_root == *merkle_root
        && compute_merkle_root(&block.transactions) == *merkle_root
}

enum Reply {
    Block(Box<Block>),
    NotFound,
}

/// Requests old blocks from full-history peers. The node's message loop must pass every
/// `Block` and `NotFound` through [`HistoryFetcher::deliver`] / [`HistoryFetcher::not_found`]
/// first and skip its normal handling when they return true.
pub struct HistoryFetcher {
    peer_manager: Arc<PeerManager>,
    pending: Mutex<HashMap<(PeerId, Hash256), oneshot::Sender<Reply>>>,
    timeout: Duration,
    last_result: Mutex<Option<String>>,
}

impl HistoryFetcher {
    pub fn new(peer_manager: Arc<PeerManager>) -> Arc<Self> {
        Arc::new(Self {
            peer_manager,
            pending: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(20),
            last_result: Mutex::new(None),
        })
    }

    /// Number of connected peers that keep every block.
    pub fn full_peer_count(&self) -> usize {
        self.peer_manager.full_history_peers().len()
    }

    /// Outcome of the most recent fetch, if any.
    pub fn last_result(&self) -> Option<String> {
        self.last_result.lock().clone()
    }

    /// A block arrived from `peer`. Returns true if a fetch was waiting for it.
    pub fn deliver(&self, peer: PeerId, hash: Hash256, block: &Block) -> bool {
        match self.pending.lock().remove(&(peer, hash)) {
            Some(tx) => {
                let _ = tx.send(Reply::Block(Box::new(block.clone())));
                true
            }
            None => false,
        }
    }

    /// `peer` said it does not have `hash`. Returns true if a fetch was waiting for it.
    pub fn not_found(&self, peer: PeerId, hash: Hash256) -> bool {
        match self.pending.lock().remove(&(peer, hash)) {
            Some(tx) => {
                let _ = tx.send(Reply::NotFound);
                true
            }
            None => false,
        }
    }

    /// Ask full-history peers in turn for the block `hash`, whose merkle root we know from our
    /// own index. Returns only a block that passed [`verify_block`].
    pub async fn fetch_block(
        &self,
        hash: Hash256,
        merkle_root: Hash256,
    ) -> Result<Block, FetchError> {
        let result = self.fetch_inner(hash, merkle_root).await;
        *self.last_result.lock() = Some(match &result {
            Ok(_) => format!("ok {hash}"),
            Err(e) => {
                tracing::warn!("history fetch of {} failed: {}", hash, e);
                format!("failed {hash}: {e}")
            }
        });
        result
    }

    async fn fetch_inner(&self, hash: Hash256, merkle_root: Hash256) -> Result<Block, FetchError> {
        let peers = self.peer_manager.full_history_peers();
        if peers.is_empty() {
            return Err(FetchError::NoFullPeers);
        }
        for peer in peers {
            let (tx, rx) = oneshot::channel();
            self.pending.lock().insert((peer, hash), tx);
            let msg = NetworkMessage::GetData(vec![InvItem {
                inv_type: InvType::Block,
                hash,
            }]);
            if self.peer_manager.send_to_peer(peer, msg).await.is_err() {
                self.pending.lock().remove(&(peer, hash));
                continue;
            }
            let reply = tokio::time::timeout(self.timeout, rx).await;
            self.pending.lock().remove(&(peer, hash));
            if let Ok(Ok(Reply::Block(block))) = reply {
                if verify_block(&block, &hash, &merkle_root) {
                    return Ok(*block);
                }
                tracing::warn!("peer {} sent a block that failed verification", peer);
            }
        }
        Err(FetchError::NotAvailable)
    }
}

impl divi_rpc::BlockFetcher for HistoryFetcher {
    fn full_peer_count(&self) -> usize {
        HistoryFetcher::full_peer_count(self)
    }

    fn last_result(&self) -> Option<String> {
        HistoryFetcher::last_result(self)
    }

    /// Synchronous bridge for RPC handlers, which run on the multi-threaded runtime.
    fn fetch_block(&self, hash: Hash256, merkle_root: Hash256) -> Option<Block> {
        let handle = tokio::runtime::Handle::try_current().ok()?;
        tokio::task::block_in_place(|| {
            handle.block_on(HistoryFetcher::fetch_block(self, hash, merkle_root))
        })
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::transaction::{Transaction, TxIn, TxOut};

    fn sample_block() -> Block {
        let mut b = Block::default();
        b.header.version = 1;
        b.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::default()],
            vout: vec![TxOut::default()],
            lock_time: 0,
        });
        b.header.merkle_root = compute_merkle_root(&b.transactions);
        b
    }

    #[test]
    fn verify_accepts_matching_block() {
        let b = sample_block();
        let h = compute_block_hash(&b.header);
        assert!(verify_block(&b, &h, &b.header.merkle_root));
    }

    #[test]
    fn verify_rejects_wrong_hash_wrong_merkle_and_tampered_txs() {
        let b = sample_block();
        let h = compute_block_hash(&b.header);
        assert!(!verify_block(&b, &Hash256::zero(), &b.header.merkle_root));
        assert!(!verify_block(&b, &h, &Hash256::zero()));
        let mut t = b.clone();
        t.transactions[0].lock_time = 7;
        assert!(!verify_block(&t, &h, &b.header.merkle_root));
    }

    #[test]
    fn deliver_without_pending_request_is_not_claimed() {
        let pm = PeerManager::new(divi_network::PeerManagerConfig::default());
        let f = HistoryFetcher::new(pm);
        let b = sample_block();
        assert!(!f.deliver(1, compute_block_hash(&b.header), &b));
        assert!(!f.not_found(1, Hash256::zero()));
    }

    #[tokio::test]
    async fn fetch_with_no_full_peers_refuses() {
        let pm = PeerManager::new(divi_network::PeerManagerConfig::default());
        let f = HistoryFetcher::new(pm);
        assert_eq!(
            f.fetch_block(Hash256::zero(), Hash256::zero()).await,
            Err(FetchError::NoFullPeers)
        );
    }
}
