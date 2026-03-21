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

//! Masternode P2P message handler
//!
//! This module handles masternode-related P2P messages and bridges them
//! to the masternode manager.

use crate::error::NetworkError;
use crate::peer::PeerId;
use crate::NetworkMessage;
use divi_masternode::{
    MasternodeBroadcast, MasternodeManager, MasternodePaymentWinner, MasternodePing,
    MessageValidator, RelayManager, RequestMasternodeList, SyncStatus,
};
use divi_primitives::serialize::{deserialize, Decodable};
use parking_lot::RwLock;
use std::io::Cursor;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Handler for masternode P2P messages
pub struct MasternodeHandler {
    manager: Arc<MasternodeManager>,
    relay: Arc<RelayManager>,
    /// Masternode sync status tracker
    sync_status: Arc<RwLock<SyncStatus>>,
    /// Callback for relaying messages to other peers
    relay_callback: Arc<RwLock<Option<Box<dyn Fn(NetworkMessage, PeerId) + Send + Sync>>>>,
}

impl MasternodeHandler {
    /// Create a new masternode handler
    pub fn new(manager: Arc<MasternodeManager>) -> Self {
        MasternodeHandler {
            manager,
            relay: Arc::new(RelayManager::new()),
            sync_status: Arc::new(RwLock::new(SyncStatus::new())),
            relay_callback: Arc::new(RwLock::new(None)),
        }
    }

    /// Get the current sync status
    pub fn get_sync_status(&self) -> SyncStatus {
        self.sync_status.read().clone()
    }

    /// Process sync tick (should be called periodically, e.g. every 5 seconds)
    pub fn process_sync_tick(&self) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let masternode_count = self.manager.count();
        let winner_count = 0; // TODO: Track payment winner count

        let action = {
            let mut status = self.sync_status.write();
            status.process_tick(current_time, masternode_count, winner_count)
        };

        if let Some(sync_action) = action {
            match sync_action {
                divi_masternode::SyncAction::RequestSporks => {
                    debug!("Masternode sync: Requesting sporks");
                }
                divi_masternode::SyncAction::RequestMasternodeList => {
                    debug!("Masternode sync: Requesting masternode list");
                }
                divi_masternode::SyncAction::RequestWinners => {
                    debug!("Masternode sync: Requesting payment winners");
                }
                divi_masternode::SyncAction::SyncComplete => {
                    info!("Masternode sync complete!");
                }
            }
        }
    }

    /// Set the relay callback for broadcasting messages to other peers
    pub fn set_relay_callback<F>(&self, callback: F)
    where
        F: Fn(NetworkMessage, PeerId) + Send + Sync + 'static,
    {
        *self.relay_callback.write() = Some(Box::new(callback));
    }

    /// Handle a masternode list request (dseg)
    pub fn handle_list_request(
        &self,
        peer_id: PeerId,
        payload: &[u8],
    ) -> Result<Vec<NetworkMessage>, NetworkError> {
        debug!("Received masternode list request from peer {}", peer_id);

        // Parse the request
        let mut cursor = Cursor::new(payload);
        let request = RequestMasternodeList::decode(&mut cursor)
            .map_err(|e| NetworkError::Deserialization(e.to_string()))?;

        let consumed = cursor.position() as usize;
        if consumed != payload.len() {
            warn!(
                "dseg deserialization consumed {} bytes but payload has {} bytes ({} unconsumed)",
                consumed,
                payload.len(),
                payload.len() - consumed
            );
        }

        // Get masternodes from manager
        let masternodes = if request.is_full_list() {
            self.manager.get_all()
        } else if let Some(vin) = request.vin {
            // Request for specific masternode
            self.manager.get(vin).map(|mn| vec![mn]).unwrap_or_default()
        } else {
            vec![]
        };

        info!(
            "Sending {} masternodes to peer {} in response to list request",
            masternodes.len(),
            peer_id
        );

        // Convert masternodes to broadcast messages
        let mut responses = Vec::new();
        for mn in masternodes {
            let mnb = MasternodeBroadcast::new(
                mn.vin,
                mn.addr,
                mn.pubkey_collateral.clone(),
                mn.pubkey_masternode.clone(),
                mn.tier,
                mn.protocol_version,
                mn.sig_time,
            );

            let payload = divi_primitives::serialize::serialize(&mnb);
            responses.push(NetworkMessage::MasternodeBroadcast(payload));
        }

        Ok(responses)
    }

    /// Handle a masternode broadcast (mnb)
    pub fn handle_broadcast(&self, peer_id: PeerId, payload: &[u8]) -> Result<(), NetworkError> {
        debug!("Received masternode broadcast from peer {}", peer_id);

        // Deserialize the broadcast
        let mnb: MasternodeBroadcast =
            deserialize(payload).map_err(|e| NetworkError::Deserialization(e.to_string()))?;

        // Validate the broadcast
        if let Err(e) = MessageValidator::validate_broadcast(&mnb) {
            warn!(
                "Invalid masternode broadcast from peer {}: {:?}",
                peer_id, e
            );
            return Err(NetworkError::InvalidMessage(format!(
                "Invalid masternode broadcast: {:?}",
                e
            )));
        }

        // Check if we should relay
        let should_relay = self.relay.should_relay_broadcast(&mnb);

        // Add to manager
        let is_new = if let Err(e) = self.manager.add(mnb.clone()) {
            // AlreadyExists is not an error, just means we already have it
            if !matches!(e, divi_masternode::MasternodeError::AlreadyExists(_)) {
                warn!("Failed to add masternode from broadcast: {}", e);
                return Err(NetworkError::InvalidMessage(format!(
                    "Failed to add masternode: {}",
                    e
                )));
            }
            false
        } else {
            info!(
                "Added masternode from broadcast: {} (tier: {:?})",
                mnb.vin, mnb.tier
            );
            true
        };

        // If we received a new masternode during LIST sync stage, check sync progress
        if is_new {
            use divi_masternode::SyncStage;
            let sync_status = self.sync_status.read();
            if sync_status.current_stage() == SyncStage::List {
                debug!("Masternode count now: {}", self.manager.count());
            }
        }

        // Mark as seen and relay if needed
        self.relay.mark_broadcast_seen(&mnb);
        if should_relay {
            if let Some(ref callback) = *self.relay_callback.read() {
                let payload = divi_primitives::serialize::serialize(&mnb);
                callback(NetworkMessage::MasternodeBroadcast(payload), peer_id);
            }
        }

        Ok(())
    }

    /// Handle a masternode ping (mnp)
    pub fn handle_ping(&self, peer_id: PeerId, payload: &[u8]) -> Result<(), NetworkError> {
        debug!("Received masternode ping from peer {}", peer_id);

        // Deserialize the ping
        let ping: MasternodePing =
            deserialize(payload).map_err(|e| NetworkError::Deserialization(e.to_string()))?;

        // Validate the ping
        if let Err(e) = MessageValidator::validate_ping(&ping) {
            warn!("Invalid masternode ping from peer {}: {:?}", peer_id, e);
            return Err(NetworkError::InvalidMessage(format!(
                "Invalid masternode ping: {:?}",
                e
            )));
        }

        // Update last seen time for this masternode
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if let Err(e) = self.manager.update_last_seen(ping.vin, current_time) {
            debug!("Could not update last seen time for masternode: {}", e);
            // This is not a critical error - masternode might not exist yet
        }

        // Check if we should relay
        let should_relay = self.relay.should_relay_ping(&ping);

        // Mark as seen and relay if needed
        self.relay.mark_ping_seen(&ping);
        if should_relay {
            if let Some(ref callback) = *self.relay_callback.read() {
                let payload = divi_primitives::serialize::serialize(&ping);
                callback(NetworkMessage::MasternodePing(payload), peer_id);
            }
        }

        Ok(())
    }

    /// Handle a masternode payment winner (mnw)
    pub fn handle_winner(&self, peer_id: PeerId, payload: &[u8]) -> Result<(), NetworkError> {
        debug!("Received masternode winner from peer {}", peer_id);

        // Deserialize the winner
        let winner: MasternodePaymentWinner =
            deserialize(payload).map_err(|e| NetworkError::Deserialization(e.to_string()))?;

        // Validate the winner
        if let Err(e) = MessageValidator::validate_payment_vote(&winner) {
            warn!("Invalid masternode winner from peer {}: {:?}", peer_id, e);
            return Err(NetworkError::InvalidMessage(format!(
                "Invalid masternode winner: {:?}",
                e
            )));
        }

        info!(
            "Received masternode payment winner for height {} from peer {}",
            winner.block_height, peer_id
        );

        // Check if we should relay
        let should_relay = self.relay.should_relay_payment_vote(&winner);

        // Mark as seen and relay if needed
        self.relay.mark_payment_vote_seen(&winner);
        if should_relay {
            if let Some(ref callback) = *self.relay_callback.read() {
                let payload = divi_primitives::serialize::serialize(&winner);
                callback(NetworkMessage::MasternodeWinner(payload), peer_id);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_masternode::SyncStage;

    #[test]
    fn test_handler_creation() {
        let manager = Arc::new(MasternodeManager::new());
        let handler = MasternodeHandler::new(manager);
        assert!(handler.relay_callback.read().is_none());

        // Verify initial sync state
        let sync_status = handler.get_sync_status();
        assert_eq!(sync_status.current_stage(), SyncStage::Initial);
        assert!(!sync_status.is_synced());
    }

    #[test]
    fn test_sync_status_tracking() {
        let manager = Arc::new(MasternodeManager::new());
        let handler = MasternodeHandler::new(manager);

        // Initial state
        assert_eq!(
            handler.get_sync_status().current_stage(),
            SyncStage::Initial
        );

        // Process tick should advance to Sporks stage
        handler.process_sync_tick();
        assert_eq!(handler.get_sync_status().current_stage(), SyncStage::Sporks);
    }
}
