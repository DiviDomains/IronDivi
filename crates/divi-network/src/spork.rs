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

//! Spork synchronization manager
//!
//! Divi requires spork synchronization before regular block sync can proceed.
//! After the version/verack handshake, the peer sends a `sporkcount` message
//! indicating how many sporks it has. We respond with `getsporks` to request
//! them all, then receive individual `spork` messages.

use crate::messages::SporkMessage;
use crate::peer::PeerId;
use crate::peer_manager::PeerManager;
use crate::NetworkMessage;
use divi_primitives::hash::Hash256;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Spork synchronization state per peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SporkSyncState {
    /// Haven't received sporkcount yet
    Pending,
    /// Received sporkcount, waiting for sporks
    Syncing { expected: u32, received: u32 },
    /// All sporks received from this peer
    Synced,
}

/// Spork sync progress event
#[derive(Debug, Clone)]
pub struct SporkSyncProgress {
    /// Number of peers with synced sporks
    pub synced_peers: usize,
    /// Total number of peers
    pub total_peers: usize,
    /// Number of unique sporks received
    pub spork_count: usize,
}

/// Spork synchronization manager
pub struct SporkManager {
    /// Peer manager for sending messages
    peer_manager: Arc<PeerManager>,

    /// Sync state per peer
    peer_states: RwLock<HashMap<PeerId, SporkSyncState>>,

    /// Received sporks (keyed by hash)
    sporks: RwLock<HashMap<Hash256, SporkMessage>>,

    /// Active sporks by ID (most recent per spork_id)
    active_sporks: RwLock<HashMap<i32, SporkMessage>>,

    /// Progress event broadcaster
    progress_tx: broadcast::Sender<SporkSyncProgress>,
}

impl SporkManager {
    /// Create a new spork manager
    pub fn new(peer_manager: Arc<PeerManager>) -> Arc<Self> {
        let (progress_tx, _) = broadcast::channel(16);
        Arc::new(SporkManager {
            peer_manager,
            peer_states: RwLock::new(HashMap::new()),
            sporks: RwLock::new(HashMap::new()),
            active_sporks: RwLock::new(HashMap::new()),
            progress_tx,
        })
    }

    /// Subscribe to progress events
    pub fn subscribe(&self) -> broadcast::Receiver<SporkSyncProgress> {
        self.progress_tx.subscribe()
    }

    /// Check if sporks are synced from at least one peer
    pub fn is_synced(&self) -> bool {
        let states = self.peer_states.read();
        states.values().any(|s| *s == SporkSyncState::Synced)
    }

    /// Check if a specific peer has synced sporks
    pub fn is_peer_synced(&self, peer_id: PeerId) -> bool {
        let states = self.peer_states.read();
        states
            .get(&peer_id)
            .map(|s| *s == SporkSyncState::Synced)
            .unwrap_or(false)
    }

    /// Get the sync state for a peer
    pub fn peer_state(&self, peer_id: PeerId) -> SporkSyncState {
        self.peer_states
            .read()
            .get(&peer_id)
            .copied()
            .unwrap_or(SporkSyncState::Pending)
    }

    /// Handle sporkcount message from a peer
    pub async fn handle_sporkcount(&self, peer_id: PeerId, count: u32) {
        tracing::info!("Peer {} has {} sporks", peer_id, count);

        // Update peer state
        {
            let mut states = self.peer_states.write();
            if count == 0 {
                states.insert(peer_id, SporkSyncState::Synced);
            } else {
                states.insert(
                    peer_id,
                    SporkSyncState::Syncing {
                        expected: count,
                        received: 0,
                    },
                );
            }
        }

        // If peer has sporks, request them
        if count > 0 {
            tracing::debug!("Requesting sporks from peer {}", peer_id);
            let _ = self
                .peer_manager
                .send_to_peer(peer_id, NetworkMessage::GetSporks)
                .await;
        }

        self.emit_progress();
    }

    /// Handle spork message from a peer
    pub async fn handle_spork(&self, peer_id: PeerId, spork: SporkMessage) {
        let hash = spork.hash();
        tracing::debug!(
            "Received spork {} (id={}, value={}) from peer {}",
            hash,
            spork.spork_id,
            spork.value,
            peer_id
        );

        // Store the spork
        {
            let mut sporks = self.sporks.write();
            sporks.insert(hash, spork.clone());
        }

        // Update active spork (keep most recent by time_signed)
        {
            let mut active = self.active_sporks.write();
            let should_update = active
                .get(&spork.spork_id)
                .map(|existing| spork.time_signed > existing.time_signed)
                .unwrap_or(true);
            if should_update {
                active.insert(spork.spork_id, spork);
            }
        }

        // Update peer state
        {
            let mut states = self.peer_states.write();
            if let Some(SporkSyncState::Syncing { expected, received }) =
                states.get(&peer_id).copied()
            {
                let new_received = received + 1;
                if new_received >= expected {
                    tracing::info!(
                        "Spork sync complete from peer {} ({} sporks)",
                        peer_id,
                        new_received
                    );
                    states.insert(peer_id, SporkSyncState::Synced);
                } else {
                    states.insert(
                        peer_id,
                        SporkSyncState::Syncing {
                            expected,
                            received: new_received,
                        },
                    );
                }
            }
        }

        self.emit_progress();
    }

    /// Handle getsporks request (respond with our sporks)
    pub async fn handle_getsporks(&self, peer_id: PeerId) {
        // Collect sporks while holding the lock, then release before awaiting
        let sporks: Vec<SporkMessage> = {
            let active = self.active_sporks.read();
            tracing::debug!("Sending {} sporks to peer {}", active.len(), peer_id);
            active.values().cloned().collect()
        };

        for spork in sporks {
            let _ = self
                .peer_manager
                .send_to_peer(peer_id, NetworkMessage::Spork(spork))
                .await;
        }
    }

    /// Remove a peer's state when disconnected
    pub fn remove_peer(&self, peer_id: PeerId) {
        self.peer_states.write().remove(&peer_id);
        self.emit_progress();
    }

    /// Get the number of active sporks
    pub fn spork_count(&self) -> usize {
        self.active_sporks.read().len()
    }

    /// Get an active spork value by ID
    pub fn get_spork(&self, spork_id: i32) -> Option<SporkMessage> {
        self.active_sporks.read().get(&spork_id).cloned()
    }

    /// Get all active spork IDs
    pub fn active_spork_ids(&self) -> Vec<i32> {
        self.active_sporks.read().keys().copied().collect()
    }

    /// Emit progress event
    fn emit_progress(&self) {
        let states = self.peer_states.read();
        let synced_peers = states
            .values()
            .filter(|s| **s == SporkSyncState::Synced)
            .count();
        let total_peers = states.len();
        let spork_count = self.active_sporks.read().len();

        let _ = self.progress_tx.send(SporkSyncProgress {
            synced_peers,
            total_peers,
            spork_count,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests require mocking PeerManager
    // This tests the basic state machine logic

    #[test]
    fn test_spork_sync_state() {
        assert_eq!(SporkSyncState::Pending, SporkSyncState::Pending);
        assert_ne!(SporkSyncState::Pending, SporkSyncState::Synced);
    }
}
