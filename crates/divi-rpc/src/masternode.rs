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

use crate::error::{Error, RpcError};
use crate::protocol::Params;
use divi_masternode::{MasternodeManager, MasternodeRpc as MasternodeRpcImpl, PaymentVoteTracker};
use parking_lot::RwLock;
use serde_json::{json, Value};
use std::sync::Arc;

pub struct MasternodeRpc {
    manager: Arc<RwLock<Option<MasternodeManager>>>,
    vote_tracker: Arc<RwLock<PaymentVoteTracker>>,
}

impl MasternodeRpc {
    pub fn new() -> Self {
        Self {
            manager: Arc::new(RwLock::new(None)),
            vote_tracker: Arc::new(RwLock::new(PaymentVoteTracker::new(10, 3))),
        }
    }

    pub fn set_manager(&self, manager: MasternodeManager) {
        *self.manager.write() = Some(manager);
    }

    fn get_rpc(&self) -> Result<MasternodeRpcImpl, Error> {
        let manager_lock = self.manager.read();
        if let Some(ref manager) = *manager_lock {
            Ok(MasternodeRpcImpl::new(manager.clone()))
        } else {
            Err(RpcError::new(
                -32603,
                "Masternode subsystem not initialized. This node is running in lite mode without masternode support."
            ).into())
        }
    }

    // Stub error message for commands that need additional work
    fn masternode_not_implemented(&self) -> Error {
        RpcError::new(
            -32603,
            "Masternode functionality requires the full masternode subsystem including P2P protocol support, masternode broadcast mechanisms, and collateral verification. This feature will be implemented in a future release. For masternode operations, please use the C++ Divi client."
        ).into()
    }

    /// Get masternode count values
    pub fn get_masternode_count(&self, _params: &Params) -> Result<Value, Error> {
        let rpc = self.get_rpc()?;
        let count = rpc.count();
        Ok(serde_json::to_value(count)?)
    }

    /// Print masternode status
    pub fn get_masternode_status(&self, _params: &Params) -> Result<Value, Error> {
        // This requires the node to be running as a masternode
        // For now, return error indicating not running as masternode
        Err(RpcError::new(-32603, "This node is not configured as a masternode").into())
    }

    /// Print the masternode winners for the last n blocks
    pub fn get_masternode_winners(&self, params: &Params) -> Result<Value, Error> {
        let rpc = self.get_rpc()?;
        let blocks = params.get_i64(0).unwrap_or(10) as usize;
        let _filter = params.get_str(1); // TODO: Apply filter

        // Get current height from somewhere - for now use a placeholder
        let current_height: i32 = 0; // TODO: Get from chain
        let start_height = current_height.saturating_sub(blocks as i32);

        let tracker = self.vote_tracker.read();
        let winners = rpc.get_winners(&tracker, start_height, blocks);
        Ok(serde_json::to_value(winners)?)
    }

    /// Get a ranked list of masternodes
    pub fn list_masternodes(&self, params: &Params) -> Result<Value, Error> {
        let rpc = self.get_rpc()?;
        let mode = params.get_str(0).map(|s| s.to_string());
        let list = rpc.list(mode);
        Ok(serde_json::to_value(list)?)
    }

    /// Setup masternode configuration
    pub fn setup_masternode(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters even though not used (for signature validation)
        let _alias = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: alias"))?;
        let _txhash = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: txhash"))?;
        let _output_index = params
            .get_str(2)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: outputIndex"))?;
        let _collateral_pubkey = params.get_str(3).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: collateralPubKey")
        })?;
        let _ip_address = params
            .get_str(4)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: ip_address"))?;
        Err(self.masternode_not_implemented())
    }

    /// Start masternode
    pub fn start_masternode(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters even though not used (for signature validation)
        let _alias = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: alias"))?;
        let _defer_relay = params.get_bool(1);
        Err(self.masternode_not_implemented())
    }

    /// Broadcast masternode start message
    pub fn broadcast_start_masternode(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters even though not used (for signature validation)
        let _broadcast_hex = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: broadcast_hex"))?;
        let _append_broadcast_signature = params.get_str(1);
        Err(self.masternode_not_implemented())
    }

    /// Sign masternode broadcast message
    pub fn sign_mn_broadcast(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters even though not used (for signature validation)
        let _mnhex = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: mnhex"))?;
        Err(self.masternode_not_implemented())
    }

    /// Import signed masternode broadcast
    pub fn import_mn_broadcast(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters even though not used (for signature validation)
        let _broadcast_hex = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: broadcast_hex"))?;
        Err(self.masternode_not_implemented())
    }

    /// List pending masternode broadcasts
    pub fn list_mn_broadcasts(&self, _params: &Params) -> Result<Value, Error> {
        Err(self.masternode_not_implemented())
    }

    /// Verify masternode is correctly configured
    pub fn verify_masternode_setup(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters even though not used (for signature validation)
        let _ip_address = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: ip_address"))?;
        let _sigtime = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: sigtime"))?;
        let _collateral_pubkey = params.get_str(2).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: collateralPubKey")
        })?;
        let _masternode_pubkey = params.get_str(3).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: masternodePubKey")
        })?;
        Err(self.masternode_not_implemented())
    }

    /// Masternode sync control
    pub fn mnsync(&self, params: &Params) -> Result<Value, Error> {
        let command = params.get_str(0).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: command (status|reset)")
        })?;

        match command.to_lowercase().as_str() {
            "status" => {
                // Return basic sync status
                Ok(json!({
                    "IsBlockchainSynced": true,
                    "timestampOfLastMasternodeListUpdate": 0,
                    "timestampOfLastMasternodeWinnerUpdate": 0,
                    "currentMasternodeSyncStatus": 999
                }))
            }
            "reset" | "next" => {
                Err(RpcError::new(
                    -32603,
                    "Masternode sync control requires full masternode subsystem. mnsync manages the synchronization of masternode lists, winners, and governance data across the P2P network. For masternode sync operations, please use the C++ Divi client."
                ).into())
            }
            _ => Err(RpcError::invalid_params("Command must be 'status', 'reset', or 'next'").into()),
        }
    }
}

impl Default for MasternodeRpc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Params;

    #[test]
    fn test_masternode_rpc_without_manager() {
        let rpc = MasternodeRpc::new();

        // Should return error when manager is not set
        let result = rpc.get_masternode_count(&Params::None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not initialized"));
    }

    #[test]
    fn test_masternode_rpc_with_manager() {
        let rpc = MasternodeRpc::new();
        let manager = divi_masternode::MasternodeManager::new();
        rpc.set_manager(manager);

        // Should now work and return empty counts
        let result = rpc.get_masternode_count(&Params::None);
        assert!(result.is_ok());

        let value = result.unwrap();
        assert_eq!(value["total"], 0);
        assert_eq!(value["enabled"], 0);
    }

    #[test]
    fn test_list_masternodes_empty() {
        let rpc = MasternodeRpc::new();
        let manager = divi_masternode::MasternodeManager::new();
        rpc.set_manager(manager);

        // Should return empty list
        let result = rpc.list_masternodes(&Params::None);
        assert!(result.is_ok());

        let value = result.unwrap();
        assert!(value["masternodes"].is_object());
        assert_eq!(value["masternodes"].as_object().unwrap().len(), 0);
    }

    #[test]
    fn test_mnsync_status() {
        let rpc = MasternodeRpc::new();

        // mnsync status should work without manager
        let result = rpc.mnsync(&Params::Array(vec![serde_json::json!("status")]));
        assert!(result.is_ok());

        let value = result.unwrap();
        assert!(value["IsBlockchainSynced"].is_boolean());
    }
}
