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
use crate::mn_broadcast::{self, BroadcastRelay, BroadcastStore, MnContext};
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
    /// Pre-signed broadcasts (`importmnbroadcast` / `listmnbroadcasts`)
    stored: BroadcastStore,
    /// Datadir holding `masternode.conf`
    datadir: RwLock<Option<std::path::PathBuf>>,
    /// Sends raw broadcast bytes to the P2P layer
    relay: RwLock<Option<BroadcastRelay>>,
}

impl MasternodeRpc {
    pub fn new() -> Self {
        Self {
            manager: Arc::new(RwLock::new(None)),
            vote_tracker: Arc::new(RwLock::new(PaymentVoteTracker::new(10, 3))),
            stored: BroadcastStore::default(),
            datadir: RwLock::new(None),
            relay: RwLock::new(None),
        }
    }

    /// Set the datadir: broadcasts persist to `mnbroadcasts.json`, config is `masternode.conf`
    pub fn set_datadir(&self, dir: std::path::PathBuf) {
        self.stored.set_path(dir.join("mnbroadcasts.json"));
        *self.datadir.write() = Some(dir);
    }

    pub fn set_broadcast_relay(&self, relay: BroadcastRelay) {
        *self.relay.write() = Some(relay);
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
        // irondivid never runs as a masternode: Divi Core's reply for a node
        // that is not one (RpcMasternodeFeatures.cpp:219)
        Err(RpcError::new(codes::MISC_ERROR, "This is not a masternode").into())
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

    /// Usage error like C++ `runtime_error(help)` (code -1)
    fn usage(msg: &str) -> Error {
        RpcError::new(codes::MISC_ERROR, msg.to_string()).into()
    }

    /// `setupmasternode alias txhash outputIndex collateralPubKey ip_address`
    pub fn setup_masternode(
        &self,
        params: &Params,
        ctx: &MnContext,
        default_port: u16,
    ) -> Result<Value, Error> {
        if params.len() < 5 || params.len() > 6 {
            return Err(Self::usage(
                "setupmasternode alias txhash outputIndex collateralPubKey ip_address",
            ));
        }
        let arg = |i: usize| -> Result<&str, Error> {
            params
                .get_str(i)
                .ok_or_else(|| RpcError::new(codes::TYPE_ERROR, "Expected string").into())
        };
        mn_broadcast::setup_masternode(
            ctx,
            arg(0)?,
            arg(1)?,
            arg(2)?,
            arg(3)?,
            arg(4)?,
            default_port,
        )
    }

    /// `startmasternode alias ( deferRelay )`
    pub fn start_masternode(&self, params: &Params, ctx: &MnContext) -> Result<Value, Error> {
        if params.is_empty() || params.len() > 2 {
            return Err(Self::usage("startmasternode alias"));
        }
        let alias = params
            .get_str(0)
            .ok_or_else(|| RpcError::new(codes::TYPE_ERROR, "Expected string"))?;
        match &ctx.wallet {
            Some(w) if !w.is_fully_unlocked() => {
                return Err(RpcError::new(
                    codes::WALLET_UNLOCK_NEEDED,
                    "Error: Please enter the wallet passphrase with walletpassphrase first.",
                )
                .into())
            }
            None => return Err(RpcError::new(codes::WALLET_ERROR, "Wallet disabled!").into()),
            _ => {}
        }
        let conf = self
            .datadir
            .read()
            .as_ref()
            .map(|d| mn_broadcast::read_conf(&d.join("masternode.conf")))
            .unwrap_or_default();
        // This node never runs as the masternode itself, as on a C++ controller wallet
        Ok(mn_broadcast::start_masternode(
            &conf,
            alias,
            &self.stored,
            false,
        ))
    }

    /// `broadcaststartmasternode hex ( sig )`
    pub fn broadcast_start_masternode(
        &self,
        params: &Params,
        ctx: &MnContext,
    ) -> Result<Value, Error> {
        if params.is_empty() || params.len() > 2 {
            return Err(Self::usage("broadcaststartmasternode hex sig"));
        }
        let hex_in = params
            .get_str(0)
            .ok_or_else(|| RpcError::new(codes::TYPE_ERROR, "Expected string"))?;
        let sig = match params.get_str(1) {
            Some("update_ping") | None => None,
            Some(s) => Some(s),
        };
        let relay = self.relay.read().clone();
        mn_broadcast::relay_broadcast(ctx, relay.as_ref(), hex_in, sig)
    }

    /// `signmnbroadcast mnhex`
    pub fn sign_mn_broadcast(&self, params: &Params, ctx: &MnContext) -> Result<Value, Error> {
        if params.len() != 1 {
            return Err(Self::usage("signmnbroadcast mnhex"));
        }
        let hex_in = params
            .get_str(0)
            .ok_or_else(|| RpcError::new(codes::TYPE_ERROR, "Expected string"))?;
        mn_broadcast::sign_broadcast(ctx, hex_in)
    }

    /// `importmnbroadcast hex`
    pub fn import_mn_broadcast(&self, params: &Params) -> Result<Value, Error> {
        if params.len() != 1 {
            return Err(Self::usage("importmnbroadcast \"broadcast_hex\""));
        }
        let hex_in = params
            .get_str(0)
            .ok_or_else(|| RpcError::new(codes::TYPE_ERROR, "Expected string"))?;
        mn_broadcast::import_broadcast(&self.stored, hex_in)
    }

    /// `listmnbroadcasts`: the stored pre-signed broadcasts
    pub fn list_mn_broadcasts(&self, params: &Params) -> Result<Value, Error> {
        if !params.is_empty() {
            return Err(Self::usage("listmnbroadcasts"));
        }
        Ok(mn_broadcast::list_broadcasts(&self.stored))
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
        // Divi Core takes exactly one mode, "status" or "reset" as written, and
        // answers anything else with its help (rpcmisc.cpp:160-197)
        let command = match (params.len(), params.get_str(0)) {
            (1, Some(c)) if c == "status" || c == "reset" => c,
            _ => return Err(RpcError::new(codes::MISC_ERROR, MNSYNC_USAGE).into()),
        };

        match command {
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
            "reset" => {
                Err(RpcError::new(
                    codes::MISC_ERROR,
                    "Masternode sync control requires full masternode subsystem. mnsync manages the synchronization of masternode lists, winners, and governance data across the P2P network. For masternode sync operations, please use the C++ Divi client."
                ).into())
            }
            _ => unreachable!("mode checked above"),
        }
    }
}

/// Divi Core's mnsync help, the error for a call it cannot take
const MNSYNC_USAGE: &str = "mnsync \"status|reset\"\n\nReturns the sync status or resets sync.\n\nArguments:\n1. \"mode\"    (string, required) either 'status' or 'reset'\n\nResult ('status' mode):\n{\n  \"IsBlockchainSynced\": true|false,    (boolean) 'true' if blockchain is synced\n  \"timestampOfLastMasternodeListUpdate\": xxxx,        (numeric) Timestamp of last MN list message\n  \"timestampOfLastMasternodeWinnerUpdate\": xxxx,      (numeric) Timestamp of last MN winner message\n  \"lastBudgetItem\": xxxx,            (numeric) Timestamp of last MN budget message\n  \"timestampOfLastFailedSync\": xxxx,           (numeric) Timestamp of last failed sync\n  \"countOfFailedSyncAttempts\": n,           (numeric) Number of failed syncs (total)\n  \"nominalNumberOfMasternodeBroadcastsReceived\": n,        (numeric) Number of MN list messages (total)\n  \"nominalNumberOfMasternodeWinnersReceived\": n,      (numeric) Number of MN winner messages (total)\n  \"sumBudgetItemProp\": n,        (numeric) Number of MN budget messages (total)\n  \"sumBudgetItemFin\": n,         (numeric) Number of MN budget finalization messages (total)\n  \"fulfilledMasternodeListSyncRequests\": n,      (numeric) Number of MN list messages (local)\n  \"fulfilledMasternodeWinnerSyncRequests\": n,    (numeric) Number of MN winner messages (local)\n  \"countBudgetItemProp\": n,      (numeric) Number of MN budget messages (local)\n  \"countBudgetItemFin\": n,       (numeric) Number of MN budget finalization messages (local)\n  \"currentMasternodeSyncStatus\": n, (numeric) Status code of last sync phase\n  \"totalSuccessivePeerSyncRequests\": n, (numeric) Status code of last sync attempt\n}\n\nResult ('reset' mode):\n\"status\"     (string) 'success'\n\nExamples:\n> divi-cli mnsync \"status\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"mnsync\", \"params\": [\"status\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n";

impl Default for MasternodeRpc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Params;

    fn rpc_err(r: Result<Value, Error>) -> (i32, String) {
        match r {
            Err(Error::Rpc(e)) => (e.code, e.message),
            other => panic!("expected an RPC error, got {other:?}"),
        }
    }

    /// Divi Core's reply on a node that is not a masternode
    /// (RpcMasternodeFeatures.cpp:219)
    #[test]
    fn getmasternodestatus_on_a_node_that_is_not_a_masternode() {
        assert_eq!(
            rpc_err(MasternodeRpc::new().get_masternode_status(&Params::None)),
            (-1, "This is not a masternode".to_string())
        );
    }

    /// mnsync takes one mode, "status" or "reset" as written; anything else is
    /// Divi Core's help (rpcmisc.cpp:160-197)
    #[test]
    fn mnsync_answers_a_call_it_cannot_take_with_divid_s_help() {
        let rpc = MasternodeRpc::new();
        let call = |args: &[&str]| {
            rpc.mnsync(&Params::Array(
                args.iter().map(|a| serde_json::json!(a)).collect(),
            ))
        };
        assert!(call(&["status"]).is_ok());
        for bad in [&[][..], &["bad"], &["next"], &["Status"], &["status", "x"]] {
            let (code, message) = rpc_err(call(bad));
            assert_eq!(code, -1, "{bad:?}");
            assert!(
                message.starts_with("mnsync \"status|reset\"\n\nReturns the sync status")
                    && message.ends_with("\"params\": [\"status\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n"),
                "{bad:?}: {message}"
            );
        }
    }

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
