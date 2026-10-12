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

use crate::error::{codes, Error, RpcError};
use crate::protocol::Params;
use divi_masternode::{MasternodeManager, MasternodeRpc as MasternodeRpcImpl, PaymentVoteTracker};
use parking_lot::RwLock;
use serde_json::{json, Value};
use std::sync::Arc;

pub struct MasternodeRpc {
    manager: Arc<RwLock<Option<MasternodeManager>>>,
    /// Reserved for network payment votes (not wired yet; see get_masternode_winners)
    #[allow(dead_code)]
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
                codes::MISC_ERROR,
                "Masternode subsystem not initialized. This node is running in lite mode without masternode support."
            ).into())
        }
    }

    // Stub error message for commands that need additional work
    fn masternode_not_implemented(&self) -> Error {
        RpcError::new(
            codes::MISC_ERROR,
            "Masternode functionality requires the full masternode subsystem including P2P protocol support, masternode broadcast mechanisms, and collateral verification. This feature will be implemented in a future release. For masternode operations, please use the C++ Divi client."
        ).into()
    }

    /// Get masternode count values
    pub fn get_masternode_count(&self, _params: &Params) -> Result<Value, Error> {
        let rpc = self.get_rpc()?;
        let mut value = serde_json::to_value(rpc.count())?;
        // Fields C++ always reports; the Rust manager does not track network types yet
        if let Some(obj) = value.as_object_mut() {
            for key in ["inqueue", "ipv4", "ipv6", "onion", "obfcompat", "stable"] {
                obj.entry(key).or_insert(json!(0));
            }
        }
        Ok(value)
    }

    /// Print masternode status
    pub fn get_masternode_status(&self, _params: &Params) -> Result<Value, Error> {
        // This requires the node to be running as a masternode
        // For now, return error indicating not running as masternode
        Err(RpcError::new(
            codes::MISC_ERROR,
            "This node is not configured as a masternode",
        )
        .into())
    }

    /// Print the masternode winners for the last n blocks.
    ///
    /// Payment votes are not yet received over the network, so every height reports the C++
    /// "Unknown" winner with zero votes; the shape matches C++ (`nHeight` / `winner`).
    pub fn get_masternode_winners(&self, params: &Params, tip_height: i32) -> Result<Value, Error> {
        self.get_rpc()?;
        let blocks = match params.get(0) {
            Some(Value::String(s)) => s.parse::<i32>().unwrap_or(0),
            Some(v) => v.as_i64().unwrap_or(10) as i32,
            None => 10,
        };
        let filter = params.get_str(1).unwrap_or("");
        if !filter.is_empty() && !"Unknown".contains(filter) {
            return Ok(json!([]));
        }
        let winners: Vec<Value> = (tip_height - blocks..tip_height + 20)
            .map(|h| json!({"nHeight": h, "winner": {"address": "Unknown", "nVotes": 0}}))
            .collect();
        Ok(Value::Array(winners))
    }

    /// Get a ranked list of masternodes
    pub fn list_masternodes(&self, params: &Params) -> Result<Value, Error> {
        let rpc = self.get_rpc()?;
        let mode = params.get_str(0).map(|s| s.to_string());
        let list = serde_json::to_value(rpc.list(mode))?;
        // C++ listmasternodes returns a bare array of entries
        Ok(match list.get("masternodes") {
            Some(Value::Object(m)) => Value::Array(m.values().cloned().collect()),
            Some(Value::Array(a)) => Value::Array(a.clone()),
            _ => list,
        })
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

    /// List stored pre-signed masternode broadcasts (none are stored yet)
    pub fn list_mn_broadcasts(&self, _params: &Params) -> Result<Value, Error> {
        Ok(json!([]))
    }

    /// Show the message a masternode broadcast must be signed over.
    ///
    /// Mirrors C++ `CMasternodeBroadcast::getMessageToSign`: `addr.ToString() + sigTime +
    /// collateral pubkey bytes + masternode pubkey bytes + protocolVersion`. C++ builds the two
    /// pubkeys from the characters of the argument strings, which never form a valid `CPubKey`,
    /// so both contribute nothing; that quirk is reproduced so the output matches byte for byte.
    pub fn verify_masternode_setup(
        &self,
        params: &Params,
        default_port: u16,
    ) -> Result<Value, Error> {
        let bad = || -> Error {
            RpcError::new(
                codes::INVALID_PARAMETER,
                "Error parsing input arguments\n".to_string(),
            )
            .into()
        };
        if params.len() != 4 {
            return Err(RpcError::new(
                codes::MISC_ERROR,
                "verifymasternodesetup ip_address sigtime collateralPubKey masternodePubKey",
            )
            .into());
        }
        let ip = params.get_str(0).ok_or_else(bad)?;
        let sigtime: i64 = params
            .get_str(1)
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(bad)?;
        params.get_str(2).ok_or_else(bad)?;
        params.get_str(3).ok_or_else(bad)?;
        let addr: std::net::IpAddr = ip.parse().map_err(|_| bad())?;
        let addr_str = match addr {
            std::net::IpAddr::V4(a) => format!("{}:{}", a, default_port),
            std::net::IpAddr::V6(a) => format!("[{}]:{}", a, default_port),
        };
        let message = format!(
            "{}{}{}",
            addr_str,
            sigtime,
            divi_network::constants::PROTOCOL_VERSION
        );
        Ok(json!({ "expected_message_to_sign": hex::encode(message.as_bytes()) }))
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
                    "currentMasternodeSyncStatus": 999,
                    "countOfFailedSyncAttempts": 0,
                    "totalSuccessivePeerSyncRequests": 0,
                    "timestampOfLastFailedSync": 0,
                    "fulfilledMasternodeListSyncRequests": 0,
                    "fulfilledMasternodeWinnerSyncRequests": 0,
                    "nominalNumberOfMasternodeBroadcastsReceived": 0,
                    "nominalNumberOfMasternodeWinnersReceived": 0
                }))
            }
            "reset" | "next" => {
                Err(RpcError::new(
                    codes::MISC_ERROR,
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
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 0);
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

    #[test]
    fn test_verifymasternodesetup_message() {
        let rpc = MasternodeRpc::new();
        let p = |v: &[&str]| Params::Array(v.iter().map(|s| serde_json::json!(s)).collect());
        let v = rpc
            .verify_masternode_setup(&p(&["1.2.3.4", "1700000000", "aa", "bb"]), 51474)
            .unwrap();
        let msg = String::from_utf8(
            hex::decode(v["expected_message_to_sign"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            msg,
            format!(
                "1.2.3.4:514741700000000{}",
                divi_network::constants::PROTOCOL_VERSION
            )
        );
        assert!(rpc
            .verify_masternode_setup(&p(&["nope", "1", "a", "b"]), 51474)
            .is_err());
        assert_eq!(
            rpc.list_mn_broadcasts(&Params::None).unwrap(),
            serde_json::json!([])
        );
    }
}
