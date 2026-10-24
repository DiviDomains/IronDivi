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

/// `params[i].get_str()` as Divi Core's json_spirit does it: None when there is
/// no such argument, a -1 "value is type X, expected str" error when it is not a
/// string
pub(crate) fn str_arg(params: &Params, i: usize) -> Result<Option<&str>, Error> {
    match params.get(i) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(v) => Err(RpcError::new(
            codes::MISC_ERROR,
            format!(
                "value is type {}, expected str",
                crate::wallet::json_spirit_type(v)
            ),
        )
        .into()),
    }
}

/// C `atoi`, as getmasternodewinners reads its block count: leading spaces, a
/// sign and digits, 0 when there are none
fn atoi(s: &str) -> i32 {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0i64, |n, d| {
            (n * 10 + i64::from(d - b'0')).min(i64::from(i32::MAX) + 1)
        });
    let n = if neg { -n } else { n };
    n.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

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
    pub fn get_masternode_count(&self, params: &Params) -> Result<Value, Error> {
        // No arguments: anything else gets the help (rpcmasternode.cpp:329)
        if !params.is_empty() {
            return Err(Self::usage(GETMASTERNODECOUNT_USAGE));
        }
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
    pub fn get_masternode_status(&self, params: &Params) -> Result<Value, Error> {
        // No arguments: anything else gets the help (rpcmasternode.cpp:429)
        if !params.is_empty() {
            return Err(Self::usage(GETMASTERNODESTATUS_USAGE));
        }
        // irondivid never runs as a masternode: Divi Core's reply for a node
        // that is not one (RpcMasternodeFeatures.cpp:219)
        Err(RpcError::new(codes::MISC_ERROR, "This is not a masternode").into())
    }

    /// Print the masternode winners for the last n blocks.
    ///
    /// Payment votes are not yet received over the network, so every height reports the C++
    /// "Unknown" winner with zero votes; the shape matches C++ (`nHeight` / `winner`).
    ///
    /// As Divi Core (rpcmasternode.cpp:489-593): at most three arguments; the
    /// block count is a string read with `atoi`; the filter is read only when
    /// exactly two are given; height h is listed only when the block it is scored
    /// with, at h - 101, is on the chain (GetBlockHashForScoring,
    /// MasternodeHelpers.cpp:75-86).
    pub fn get_masternode_winners(&self, params: &Params, tip_height: i32) -> Result<Value, Error> {
        if params.len() > 3 {
            return Err(Self::usage(GETMASTERNODEWINNERS_USAGE));
        }
        self.get_rpc()?;
        let blocks = str_arg(params, 0)?.map(atoi).unwrap_or(10);
        let filter = if params.len() == 2 {
            str_arg(params, 1)?.unwrap_or("")
        } else {
            ""
        };
        if !filter.is_empty() && !"Unknown".contains(filter) {
            return Ok(json!([]));
        }
        let first = tip_height.saturating_sub(blocks);
        let winners: Vec<Value> = (first..tip_height.saturating_add(20))
            .filter(|h| (0..=tip_height).contains(&h.saturating_sub(101)))
            .map(|h| json!({"nHeight": h, "winner": {"address": "Unknown", "nVotes": 0}}))
            .collect();
        Ok(Value::Array(winners))
    }

    /// Get a ranked list of masternodes
    pub fn list_masternodes(&self, params: &Params) -> Result<Value, Error> {
        // One string filter at most (rpcmasternode.cpp:263-275)
        let filter = str_arg(params, 0)?;
        if params.len() > 1 {
            return Err(Self::usage(LISTMASTERNODES_USAGE));
        }
        let rpc = self.get_rpc()?;
        let mode = filter.map(|s| s.to_string());
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
        // params[1].get_bool(): json_spirit takes only a boolean (rpcmasternode.cpp:407)
        if let Some(v) = params.get(1) {
            if !v.is_boolean() {
                return Err(RpcError::new(
                    codes::MISC_ERROR,
                    format!(
                        "value is type {}, expected bool",
                        crate::wallet::json_spirit_type(v)
                    ),
                )
                .into());
            }
        }
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
            // RPC_INVALID_PARAMS (rpcmasternode.cpp:156)
            RpcError::new(
                codes::INVALID_PARAMS,
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
            // Divi Core restarts its masternode sync and answers "success"
            // (rpcmisc.cpp:217-220); irondivid keeps no sync stages to restart
            "reset" => Ok(json!("success")),
            _ => unreachable!("mode checked above"),
        }
    }
}

/// The help Divi Core answers a call with arguments it does not take (the first
/// line is what the comparison scripts look at)
const GETMASTERNODECOUNT_USAGE: &str = "getmasternodecount\n\nGet masternode count values\n";
const GETMASTERNODESTATUS_USAGE: &str = "getmasternodestatus\n\nPrint masternode status\n";
const GETMASTERNODEWINNERS_USAGE: &str = "getmasternodewinners ( blocks \"filter\" )\n\nPrint the masternode winners for the last n blocks\n";
const LISTMASTERNODES_USAGE: &str =
    "listmasternodes ( \"filter\" )\n\nGet a ranked list of masternodes\n";

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

    fn with_manager() -> MasternodeRpc {
        let rpc = MasternodeRpc::new();
        rpc.set_manager(divi_masternode::MasternodeManager::new());
        rpc
    }

    fn args(values: &[Value]) -> Params {
        Params::Array(values.to_vec())
    }

    fn first_line((code, message): (i32, String)) -> (i32, String) {
        (code, message.lines().next().unwrap_or("").to_string())
    }

    /// Argument counts and types as Divi Core checks them: more arguments than
    /// a call takes is its help (-1), and a parameter read with get_str/get_bool
    /// that is another JSON type is json_spirit's -1 type error
    /// (rpcmasternode.cpp:263-275, :327-331, :393-407, :427-431, :489-494)
    #[test]
    fn masternode_calls_check_argument_counts_and_types_as_divid() {
        let rpc = with_manager();
        let s = |v: &str| json!(v);
        let help = |r| first_line(rpc_err(r));
        assert_eq!(
            help(rpc.get_masternode_count(&args(&[s("x")]))),
            (-1, "getmasternodecount".into())
        );
        assert_eq!(
            help(rpc.get_masternode_status(&args(&[s("x")]))),
            (-1, "getmasternodestatus".into())
        );
        assert_eq!(
            help(rpc.list_masternodes(&args(&[s("a"), s("b")]))),
            (-1, "listmasternodes ( \"filter\" )".into())
        );
        assert_eq!(
            help(rpc.list_masternodes(&args(&[json!(5)]))),
            (-1, "value is type int, expected str".into())
        );
        assert_eq!(
            help(rpc.get_masternode_winners(&args(&[s("5"), s("a"), s("b"), s("c")]), 200)),
            (-1, "getmasternodewinners ( blocks \"filter\" )".into())
        );
        assert_eq!(
            help(rpc.get_masternode_winners(&args(&[json!(5)]), 200)),
            (-1, "value is type int, expected str".into())
        );
        // Three arguments are taken; the filter is read only when there are two
        let three = rpc
            .get_masternode_winners(&args(&[s("5"), s("nomatch"), s("x")]), 200)
            .unwrap();
        assert_eq!(three.as_array().unwrap().len(), 25);
    }

    /// The block count is read with atoi, and height h is listed only when the
    /// block it is scored with, h - 101, is on the chain (rpcmasternode.cpp:543-590,
    /// MasternodeHelpers.cpp:75-86)
    #[test]
    fn masternode_winners_list_only_heights_with_a_scoring_block() {
        let rpc = with_manager();
        let heights = |a: &[&str], tip: i32| -> Vec<i64> {
            rpc.get_masternode_winners(&args(&a.iter().map(|v| json!(v)).collect::<Vec<_>>()), tip)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|w| w["nHeight"].as_i64().unwrap())
                .collect()
        };
        assert!(heights(&[], 32).is_empty());
        assert_eq!(heights(&[], 90), (101..110).collect::<Vec<_>>());
        assert_eq!(heights(&[], 200), (190..220).collect::<Vec<_>>());
        assert_eq!(heights(&["5blocks"], 200), (195..220).collect::<Vec<_>>());
        assert_eq!(heights(&["abc"], 200), (200..220).collect::<Vec<_>>());
        assert_eq!(heights(&["-3"], 200), (203..220).collect::<Vec<_>>());
    }

    #[test]
    fn atoi_reads_a_number_as_c_does() {
        assert_eq!(atoi("  +12x"), 12);
        assert_eq!(atoi("-7"), -7);
        assert_eq!(atoi("x1"), 0);
        assert_eq!(atoi("99999999999"), i32::MAX);
    }

    /// startmasternode reads its second argument with get_bool (rpcmasternode.cpp:407)
    #[test]
    fn startmasternode_defer_relay_must_be_a_boolean() {
        let rpc = MasternodeRpc::new();
        let dir = tempfile::tempdir().unwrap();
        let db = divi_storage::ChainDatabase::open(dir.path()).unwrap();
        let chain = std::sync::Arc::new(
            divi_storage::Chain::new(
                std::sync::Arc::new(db),
                divi_storage::ChainParams::for_network(
                    divi_storage::chain::NetworkType::Regtest,
                    divi_primitives::ChainMode::Divi,
                ),
            )
            .unwrap(),
        );
        let ctx = MnContext {
            chain: &chain,
            wallet: None,
        };
        assert_eq!(
            rpc_err(rpc.start_masternode(&args(&[json!("mn1"), json!("yes")]), &ctx)),
            (-1, "value is type str, expected bool".to_string())
        );
    }

    /// mnsync reset answers "success" as Divi Core (rpcmisc.cpp:217-220)
    #[test]
    fn mnsync_reset_answers_success() {
        assert_eq!(
            MasternodeRpc::new()
                .mnsync(&args(&[json!("reset")]))
                .unwrap(),
            json!("success")
        );
    }

    /// A sigtime that is not a number is RPC_INVALID_PARAMS (rpcmasternode.cpp:156)
    #[test]
    fn verifymasternodesetup_bad_input_is_invalid_params() {
        assert_eq!(
            rpc_err(MasternodeRpc::new().verify_masternode_setup(
                &args(&[json!("127.0.0.1"), json!("abc"), json!("02"), json!("03")]),
                51476
            )),
            (-32602, "Error parsing input arguments\n".to_string())
        );
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
