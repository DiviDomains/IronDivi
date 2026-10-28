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
use divi_storage::ChainDatabase;
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
/// Divi Core `strSporkKey` (chainparams.cpp); regtest uses the testnet key
const MAINNET_SPORK_KEY: &str =
    "02c1ed5eadcf6793fa22840febfbd667fabbabc48ddd75c2d228662d65e292eb00";
const TESTNET_SPORK_KEY: &str =
    "034ffa41e5cffdd009f3b34a3e1482ec82b514bb218b7648948b5858cc5c035adb";

/// Points Divi Core adds for a spork with a bad signature (spork.cpp)
pub const BAD_SPORK_SCORE: u32 = 100;

/// The spork key of a Divi network, by its magic (None for other chains)
pub fn spork_key(magic: &crate::constants::Magic) -> Option<Vec<u8>> {
    use crate::constants::{MAINNET_MAGIC, REGTEST_MAGIC, TESTNET_MAGIC};
    let key = if magic == &MAINNET_MAGIC {
        MAINNET_SPORK_KEY
    } else if magic == &TESTNET_MAGIC || magic == &REGTEST_MAGIC {
        TESTNET_SPORK_KEY
    } else {
        return None;
    };
    hex::decode(key).ok()
}

/// Divi Core `SPORK_START` and `SPORK_END` (spork.h): the ids it loads at start
const SPORK_IDS: std::ops::RangeInclusive<i32> = 10001..=10015;

/// Where a spork id is kept in the chain database's metadata
fn db_key(spork_id: i32) -> Vec<u8> {
    format!("spork_{spork_id}").into_bytes()
}

/// Divi Core `IsMultiValueSpork`: sporks 13 to 16 keep a list of values
fn is_multi_value(spork_id: i32) -> bool {
    use crate::messages::spork_ids::*;
    matches!(
        spork_id,
        SPORK_13_BLOCK_PAYMENTS
            | SPORK_14_TX_FEE
            | SPORK_15_BLOCK_VALUE
            | SPORK_16_LOTTERY_TICKET_MIN_VALUE
    )
}

impl SporkMessage {
    /// Divi Core `CSporkMessage::CheckSignature`: a compact signature over
    /// id + value + time (as decimal text, with the signed-message magic)
    /// that recovers to the compressed spork key
    pub fn signature_is_valid(&self, key: &[u8]) -> bool {
        let message = format!("{}{}{}", self.spork_id, self.value, self.time_signed);
        self.signature.len() == 65
            && (31..=34).contains(&self.signature[0])
            && divi_masternode::cpp_wire::verify_message(key, &self.signature, message.as_bytes())
    }
}

pub struct SporkManager {
    /// Peer manager for sending messages
    peer_manager: Arc<PeerManager>,

    /// Key that signs sporks on this network (None: not checked)
    spork_key: Option<Vec<u8>>,

    /// Sync state per peer
    peer_states: RwLock<HashMap<PeerId, SporkSyncState>>,

    /// Received sporks (keyed by hash)
    sporks: RwLock<HashMap<Hash256, SporkMessage>>,

    /// Active sporks by ID, as Divi Core's `mapSporksActive`: the newest one
    /// for a single-value spork, every signed entry in time order for a
    /// multi-value spork
    active_sporks: RwLock<HashMap<i32, Vec<SporkMessage>>>,

    /// Keeps the last spork added per id across restarts (Core's spork
    /// database); None keeps sporks in memory only
    db: Option<Arc<ChainDatabase>>,

    /// Progress event broadcaster
    progress_tx: broadcast::Sender<SporkSyncProgress>,
}

impl SporkManager {
    /// Create a new spork manager that keeps sporks in memory only
    pub fn new(peer_manager: Arc<PeerManager>) -> Arc<Self> {
        let key = spork_key(&peer_manager.magic());
        Self::with_key(peer_manager, key, None)
    }

    /// Create a spork manager that keeps sporks in `db` and loads the ones a
    /// previous run stored (Divi Core `LoadSporksFromDB`)
    pub fn with_db(peer_manager: Arc<PeerManager>, db: Arc<ChainDatabase>) -> Arc<Self> {
        let key = spork_key(&peer_manager.magic());
        Self::with_key(peer_manager, key, Some(db))
    }

    /// Create a spork manager that checks sporks against `spork_key` (None:
    /// not checked), optionally kept in `db`
    pub fn with_key(
        peer_manager: Arc<PeerManager>,
        spork_key: Option<Vec<u8>>,
        db: Option<Arc<ChainDatabase>>,
    ) -> Arc<Self> {
        let (progress_tx, _) = broadcast::channel(16);
        let manager = SporkManager {
            spork_key,
            peer_manager,
            peer_states: RwLock::new(HashMap::new()),
            sporks: RwLock::new(HashMap::new()),
            active_sporks: RwLock::new(HashMap::new()),
            db,
            progress_tx,
        };
        manager.load_stored();
        Arc::new(manager)
    }

    /// Divi Core `LoadSporksFromDB`: one stored spork per known id
    fn load_stored(&self) {
        let Some(db) = &self.db else {
            return;
        };
        for id in SPORK_IDS {
            let stored = match db.get_metadata(&db_key(id)) {
                Ok(Some(bytes)) => SporkMessage::deserialize(&bytes),
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!("Could not read spork {} from the database: {}", id, e);
                    continue;
                }
            };
            match stored {
                Ok(spork) => {
                    tracing::debug!("Loaded spork {} with value {}", id, spork.value);
                    self.sporks.write().insert(spork.hash(), spork.clone());
                    self.add_active(spork);
                }
                Err(e) => tracing::warn!("Stored spork {} does not decode: {}", id, e),
            }
        }
    }

    /// Divi Core `AddActiveSpork`: a multi-value spork joins its list unless
    /// that entry is already held; any other spork replaces the active one.
    /// True when the spork was added.
    fn add_active(&self, spork: SporkMessage) -> bool {
        let mut active = self.active_sporks.write();
        let list = active.entry(spork.spork_id).or_default();
        if is_multi_value(spork.spork_id) {
            let hash = spork.hash();
            if list.iter().any(|held| held.hash() == hash) {
                return false;
            }
            list.push(spork);
            list.sort_by_key(|held| held.time_signed);
        } else {
            *list = vec![spork];
        }
        true
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
        tracing::debug!("Peer {} has {} sporks", peer_id, count);

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

        // Divi Core ProcessSpork: a spork no newer than the active one is
        // only counted (unless it is a multi-value spork); otherwise its
        // signature must check out, or the peer gets Misbehaving(100)
        let newer = self
            .active_sporks
            .read()
            .get(&spork.spork_id)
            .and_then(|list| list.last())
            .is_none_or(|active| spork.time_signed > active.time_signed);
        if !newer && !is_multi_value(spork.spork_id) {
            self.count_received(peer_id);
            self.emit_progress();
            return;
        }
        if let Some(key) = &self.spork_key {
            if !spork.signature_is_valid(key) {
                tracing::warn!("Spork {} from peer {}: invalid signature", hash, peer_id);
                self.peer_manager.report_misbehavior_score(
                    peer_id,
                    BAD_SPORK_SCORE,
                    "Invalid spork signature",
                );
                return;
            }
        }

        self.count_received(peer_id);
        self.sporks.write().insert(hash, spork.clone());

        // Divi Core writes the spork to its database when it was added
        if self.add_active(spork.clone()) {
            if let Some(db) = &self.db {
                if let Err(e) = db.put_metadata(&db_key(spork.spork_id), &spork.serialize()) {
                    tracing::warn!("Could not store spork {}: {}", spork.spork_id, e);
                }
            }
        }

        self.emit_progress();
    }

    /// Count a spork received from a peer towards its sync
    fn count_received(&self, peer_id: PeerId) {
        {
            let mut states = self.peer_states.write();
            if let Some(SporkSyncState::Syncing { expected, received }) =
                states.get(&peer_id).copied()
            {
                let new_received = received + 1;
                if new_received >= expected {
                    tracing::debug!(
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
    }

    /// Handle getsporks request (respond with our sporks)
    pub async fn handle_getsporks(&self, peer_id: PeerId) {
        let sporks = self.active_sporks();
        tracing::debug!("Sending {} sporks to peer {}", sporks.len(), peer_id);

        for spork in sporks {
            let _ = self
                .peer_manager
                .send_to_peer(peer_id, NetworkMessage::Spork(spork))
                .await;
        }
    }

    /// A peer that dialled us. Divi Core tells it how many sporks it holds
    /// (main.cpp SetPeerVersionAndServices) and waits for no sporks from it
    /// (Node.cpp CanSendMessagesToPeer, net.cpp GetSporkSyncedOrInboundNodes);
    /// the peer itself sends nothing else to us until it has that many sporks,
    /// so the count must match what `getsporks` serves.
    pub async fn inbound_peer_connected(&self, peer_id: PeerId) {
        self.peer_states
            .write()
            .entry(peer_id)
            .or_insert(SporkSyncState::Synced);
        let count = self.spork_count() as u32;
        let _ = self
            .peer_manager
            .send_to_peer(peer_id, NetworkMessage::SporkCount(count))
            .await;
        self.emit_progress();
    }

    /// Remove a peer's state when disconnected
    pub fn remove_peer(&self, peer_id: PeerId) {
        self.peer_states.write().remove(&peer_id);
        self.emit_progress();
    }

    /// The number of active sporks, every entry of a multi-value spork
    /// counted (Divi Core `GetActiveSporkCount`)
    pub fn spork_count(&self) -> usize {
        self.active_sporks.read().values().map(Vec::len).sum()
    }

    /// Every active spork, as `getsporks` serves them
    pub fn active_sporks(&self) -> Vec<SporkMessage> {
        self.active_sporks
            .read()
            .values()
            .flat_map(|list| list.iter().cloned())
            .collect()
    }

    /// The newest active spork with this ID
    pub fn get_spork(&self, spork_id: i32) -> Option<SporkMessage> {
        self.active_sporks
            .read()
            .get(&spork_id)
            .and_then(|list| list.last())
            .cloned()
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
        let spork_count = self.spork_count();

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

    fn signed(kp: &divi_crypto::KeyPair, id: i32, value: &str, time: i64) -> SporkMessage {
        let message = format!("{}{}{}", id, value, time);
        let signature =
            divi_masternode::cpp_wire::sign_message(kp.secret_key(), message.as_bytes()).unwrap();
        SporkMessage {
            spork_id: id,
            value: value.into(),
            time_signed: time,
            signature,
        }
    }

    #[test]
    fn spork_signature_is_checked_against_the_key() {
        let kp = divi_crypto::KeyPair::new_random();
        let key = kp.public_key().to_bytes();
        let spork = signed(&kp, 10007, "1", 1_700_000_000);
        assert!(spork.signature_is_valid(&key));

        let mut changed = spork.clone();
        changed.value = "0".into();
        assert!(!changed.signature_is_valid(&key));

        let other = divi_crypto::KeyPair::new_random();
        assert!(!spork.signature_is_valid(&other.public_key().to_bytes()));

        // Divi Core compares key ids: the recovery byte must say compressed
        let mut uncompressed = spork.clone();
        uncompressed.signature[0] -= 4;
        assert!(!uncompressed.signature_is_valid(&key));
    }

    fn quiet_peers() -> Arc<PeerManager> {
        PeerManager::new(crate::PeerManagerConfig {
            dns_seeds: vec![],
            static_peers: vec![],
            listen_addr: None,
            ..Default::default()
        })
    }

    /// Divi Core AddActiveSpork and GetActiveSporkCount (spork.cpp:144-168,
    /// :351-356): every signed entry of a multi-value spork is kept in time
    /// order, served and counted; a single-value spork keeps the newest only
    #[tokio::test]
    async fn multi_value_spork_keeps_every_signed_entry() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let key = kp.public_key().to_bytes();
        let sporks = SporkManager::with_key(quiet_peers(), Some(key), None);

        let lottery = SPORK_16_LOTTERY_TICKET_MIN_VALUE;
        sporks
            .handle_spork(1, signed(&kp, lottery, "5000;100", 1000))
            .await;
        sporks
            .handle_spork(1, signed(&kp, lottery, "6000;200", 2000))
            .await;
        // an older entry still joins the list, in time order
        sporks
            .handle_spork(1, signed(&kp, lottery, "5500;150", 1500))
            .await;
        // the same entry again is not a new one
        sporks
            .handle_spork(2, signed(&kp, lottery, "5000;100", 1000))
            .await;
        // a single-value spork keeps the newest only
        let enforcement = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
        sporks
            .handle_spork(1, signed(&kp, enforcement, "1", 1000))
            .await;
        sporks
            .handle_spork(1, signed(&kp, enforcement, "2", 2000))
            .await;
        sporks
            .handle_spork(1, signed(&kp, enforcement, "3", 1500))
            .await;

        assert_eq!(sporks.spork_count(), 4);
        let mut served: Vec<(i32, String)> = sporks
            .active_sporks()
            .into_iter()
            .map(|s| (s.spork_id, s.value))
            .collect();
        served.sort();
        assert_eq!(
            served,
            vec![
                (enforcement, "2".to_string()),
                (lottery, "5000;100".to_string()),
                (lottery, "5500;150".to_string()),
                (lottery, "6000;200".to_string()),
            ]
        );
        assert_eq!(sporks.get_spork(lottery).unwrap().value, "6000;200");
        assert_eq!(sporks.get_spork(enforcement).unwrap().value, "2");

        // an unsigned multi-value entry is not kept
        let mut unsigned = signed(&kp, lottery, "1;1", 3000);
        unsigned.signature = vec![0x1f; 65];
        sporks.handle_spork(3, unsigned).await;
        assert_eq!(sporks.spork_count(), 4);
    }

    /// Divi Core writes each spork it adds to its spork database and loads one
    /// per id at start (spork.cpp:192-211, :255)
    #[tokio::test]
    async fn stored_sporks_are_loaded_after_a_restart() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let key = kp.public_key().to_bytes();
        let dir = tempfile::tempdir().unwrap();
        let lottery = SPORK_16_LOTTERY_TICKET_MIN_VALUE;
        let enforcement = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
        {
            let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
            let sporks = SporkManager::with_key(quiet_peers(), Some(key.clone()), Some(db));
            sporks
                .handle_spork(1, signed(&kp, enforcement, "1", 1000))
                .await;
            sporks
                .handle_spork(1, signed(&kp, lottery, "5000;100", 1000))
                .await;
            sporks
                .handle_spork(1, signed(&kp, lottery, "6000;200", 2000))
                .await;
        }
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let sporks = SporkManager::with_key(quiet_peers(), Some(key), Some(db));
        assert_eq!(sporks.get_spork(enforcement).unwrap().value, "1");
        assert_eq!(sporks.get_spork(lottery).unwrap().value, "6000;200");
        assert_eq!(sporks.spork_count(), 2);
    }

    #[test]
    fn spork_keys_by_network() {
        use crate::constants::*;
        assert_eq!(spork_key(&MAINNET_MAGIC).unwrap()[0], 0x02);
        assert_eq!(spork_key(&REGTEST_MAGIC), spork_key(&TESTNET_MAGIC));
        assert!(spork_key(&PRIVATEDIVI_MAINNET_MAGIC).is_none());
    }
}
