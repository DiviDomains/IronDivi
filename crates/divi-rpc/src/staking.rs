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

//! Staking RPC methods
//!
//! JSON-RPC methods for proof-of-stake operations including
//! staking status and control.

use crate::error::{codes, Error, RpcError};
use crate::protocol::Params;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::info;

/// Staking status information (matches Divi RPC format)
#[derive(Debug, Clone)]
pub struct StakingInfo {
    pub enabled: bool,
    pub staking: bool,
    pub errors: Option<String>,
    pub current_block_size: u32,
    pub current_block_tx: u32,
    pub pooled_tx: u32,
    pub difficulty: f64,
    pub search_interval: u32,
    pub weight: u64,
    pub netstakeweight: u64,
    pub expected_time: Option<u64>,
    // Additional fields for getstakingstatus (C++ Divi format)
    pub staking_balance: f64,
    pub wallet_unlocked: bool,
    pub have_connections: bool,
    pub valid_time: bool,
    pub mintable_coins: bool,
    pub enough_coins: bool,
    pub mnsync: bool,
    /// Current chain height
    pub blocks: u32,
    /// Stake split threshold in DIVI (`-stakesplitthreshold`)
    pub stake_split_threshold: f64,
}

/// Callback for getting staking status
pub type StakingStatusCallback = Arc<dyn Fn() -> StakingInfo + Send + Sync>;

/// Callback for enabling/disabling staking
pub type SetStakingCallback = Arc<dyn Fn(bool) -> Result<(), String> + Send + Sync>;

/// Callback for the stake split threshold in satoshis: sets it when given a
/// value, and returns the current one
pub type SplitThresholdCallback = Arc<dyn Fn(Option<i64>) -> i64 + Send + Sync>;

/// Callback that mines blocks to the wallet at once (regtest setgenerate) and
/// returns their hashes
pub type GenerateCallback = Arc<dyn Fn(u32) -> Result<Vec<String>, String> + Send + Sync>;

/// What `generateblock` asks of the one block it makes (rpcmining.cpp:121-210)
#[derive(Debug, Clone, Default)]
pub struct GenerateBlockOptions {
    /// `extratx`: appended after the pool's transactions
    pub extra_txs: Vec<divi_primitives::transaction::Transaction>,
    /// `coinstake`: takes the place of the block's coinstake
    pub coinstake: Option<divi_primitives::transaction::Transaction>,
    /// `ignoreMempool`: leave the pool's transactions out
    pub ignore_mempool: bool,
    /// `blockBitsShift`: shift the block's target left by this many bits
    pub bits_shift: Option<u32>,
}

/// Why `generateblock` made no block
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateBlockFailure {
    /// Refused with Divi Core's message, answered as -1
    Refused(String),
    /// No valid block, answered as -25 "failed to generate a valid block"
    Failed(String),
}

/// Makes one block for `generateblock` and gives its hash
pub type GenerateBlockCallback =
    Arc<dyn Fn(GenerateBlockOptions) -> Result<String, GenerateBlockFailure> + Send + Sync>;

const COIN: i64 = 100_000_000;

pub struct StakingRpc {
    status_callback: RwLock<Option<StakingStatusCallback>>,
    set_staking_callback: RwLock<Option<SetStakingCallback>>,
    split_threshold_callback: RwLock<Option<SplitThresholdCallback>>,
    generate_callback: RwLock<Option<GenerateCallback>>,
    generate_block_callback: RwLock<Option<GenerateBlockCallback>>,
    reserve_balance: RwLock<f64>,
}

impl StakingRpc {
    pub fn new() -> Self {
        StakingRpc {
            status_callback: RwLock::new(None),
            set_staking_callback: RwLock::new(None),
            split_threshold_callback: RwLock::new(None),
            generate_callback: RwLock::new(None),
            generate_block_callback: RwLock::new(None),
            reserve_balance: RwLock::new(0.0),
        }
    }

    /// Set the staking status callback
    pub fn set_status_callback(&self, callback: StakingStatusCallback) {
        *self.status_callback.write() = Some(callback);
    }

    /// Set the staking control callback
    pub fn set_staking_control(&self, callback: SetStakingCallback) {
        *self.set_staking_callback.write() = Some(callback);
    }

    /// Set the stake split threshold callback
    pub fn set_split_threshold_control(&self, callback: SplitThresholdCallback) {
        *self.split_threshold_callback.write() = Some(callback);
    }

    /// Set the block generation callback
    pub fn set_generate_control(&self, callback: GenerateCallback) {
        *self.generate_callback.write() = Some(callback);
    }

    pub fn set_generate_block_control(&self, callback: GenerateBlockCallback) {
        *self.generate_block_callback.write() = Some(callback);
    }

    fn split_threshold(&self, new_sats: Option<i64>) -> Result<i64, Error> {
        let callback = self.split_threshold_callback.read();
        let callback = callback
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Staking control not available"))?;
        Ok(callback(new_sats))
    }

    /// getstakesplitthreshold - the stake split threshold in whole DIVI
    /// (startup value from -stakesplitthreshold)
    pub fn get_stake_split_threshold(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        Ok(serde_json::json!(self.split_threshold(None)? / COIN))
    }

    /// setstakesplitthreshold <DIVI> - change the stake split threshold for
    /// the running node: a stake whose value plus reward exceeds it is paid
    /// back as two outputs; smaller coins of the same address are combined up
    /// to half of it (Divi Core -stakesplitthreshold, whole DIVI)
    pub fn set_stake_split_threshold(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let divi = params
            .get(0)
            .and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .ok_or_else(|| {
                RpcError::invalid_params(
                    "setstakesplitthreshold value\n\nvalue: threshold in whole DIVI (integer >= 0)",
                )
            })?;
        let sats = divi
            .checked_mul(COIN)
            .filter(|_| divi >= 0)
            .ok_or_else(|| RpcError::new(codes::INVALID_PARAMETER, "Threshold out of range"))?;
        let threshold = self.split_threshold(Some(sats))? / COIN;
        info!("Stake split threshold set to {} DIVI", threshold);
        Ok(serde_json::json!({ "threshold": threshold }))
    }

    /// getstakingstatus - Get staking status (C++ Divi format)
    pub fn get_staking_status(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let callback = self.status_callback.read();
        let callback = callback
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Staking not available"))?;

        let info = callback();
        // The threshold in force now, as getstakesplitthreshold reports it
        // (setstakesplitthreshold can change it after start-up)
        let split_threshold = self
            .split_threshold(None)
            .map(|sats| sats as f64 / COIN as f64)
            .unwrap_or(info.stake_split_threshold);

        let staking_status_text = if info.staking && info.enabled {
            "Staking Active"
        } else if info.enabled {
            "Staking Not Active"
        } else {
            "Staking Disabled"
        };

        Ok(serde_json::json!({
            "validtime": info.valid_time,
            "haveconnections": info.have_connections,
            "walletunlocked": info.wallet_unlocked,
            "mintablecoins": info.mintable_coins,
            "staking_balance": info.staking_balance,
            "enoughcoins": info.enough_coins,
            "mnsync": info.mnsync,
            "staking status": info.staking && info.enabled,
            "staking status text": staking_status_text,
            "stake split threshold": split_threshold,
        }))
    }

    /// getmintinginfo - Get detailed minting/staking info (Divi format)
    pub fn get_minting_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let callback = self.status_callback.read();
        let callback = callback
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Staking not available"))?;

        let info = callback();

        Ok(serde_json::json!({
            "blocks": info.blocks,
            "currentblocksize": info.current_block_size,
            "currentblocktx": info.current_block_tx,
            "difficulty": info.difficulty,
            "errors": info.errors.unwrap_or_default(),
            "generate": info.enabled,
            "genproclimit": 1,
            "pooledtx": info.pooled_tx,
            "stakeweight": {
                "minimum": 0,
                "maximum": 0,
                "combined": info.weight,
            },
            "netstakeweight": info.netstakeweight,
            "expectedtime": info.expected_time.unwrap_or(0),
            "searchinterval": info.search_interval,
        }))
    }

    /// setstaking - Enable or disable staking
    pub fn set_staking(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let enable = params
            .get_bool(0)
            .ok_or_else(|| RpcError::invalid_params("Boolean parameter required (true/false)"))?;

        let callback = self.set_staking_callback.read();
        let callback = callback
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Staking control not available"))?;

        callback(enable).map_err(|e| RpcError::new(codes::MISC_ERROR, e))?;

        info!("Staking {}", if enable { "enabled" } else { "disabled" });

        Ok(serde_json::json!({
            "staking": enable
        }))
    }

    /// setgenerate - mine blocks to the wallet at once, as Divi Core does on
    /// regtest: `setgenerate N` returns the hashes of the N new blocks, null
    /// for N < 1. The caller checks the argument count and the network.
    pub fn set_generate(&self, params: &Params) -> Result<serde_json::Value, Error> {
        // json_spirit's get_int
        let value = params.get(0).cloned().unwrap_or(serde_json::Value::Null);
        let count = value.as_i64().filter(|_| !value.is_f64()).ok_or_else(|| {
            let type_name = match &value {
                serde_json::Value::Object(_) => "obj",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::String(_) => "str",
                serde_json::Value::Bool(_) => "bool",
                serde_json::Value::Number(n) if n.is_f64() => "real",
                serde_json::Value::Number(_) => "int",
                serde_json::Value::Null => "null",
            };
            RpcError::new(
                codes::MISC_ERROR,
                format!("value is type {}, expected int", type_name),
            )
        })?;
        if count < 1 {
            return Ok(serde_json::Value::Null);
        }
        let count = u32::try_from(count)
            .map_err(|_| RpcError::invalid_params("numberofblocks is too large"))?;

        let callback = self.generate_callback.read().clone();
        let callback = callback.ok_or_else(|| {
            RpcError::new(codes::MISC_ERROR, "setgenerate needs a wallet to mine to")
        })?;
        let hashes = callback(count).map_err(|e| {
            info!("setgenerate failed: {}", e);
            RpcError::new(codes::VERIFY_ERROR, "failed to generate a valid block")
        })?;
        Ok(serde_json::json!(hashes))
    }

    /// generateblock as Divi Core (rpcmining.cpp:121-210): the options are
    /// type-checked in name order, each extratx and the coinstake decoded,
    /// then one block is made with them. The argument count and the type of
    /// `options` are checked by the server first.
    pub fn generate_block(&self, params: &Params) -> Result<serde_json::Value, Error> {
        use divi_primitives::serialize::deserialize;
        use divi_primitives::transaction::Transaction;
        use serde_json::Value;

        let empty = serde_json::Map::new();
        let options = match params.get(0) {
            Some(Value::Object(o)) => o,
            _ => &empty,
        };
        // RPCTypeCheck(options, map_list_of(...), true): a std::map, so in
        // name order (rpcserver.cpp:214-229)
        for (key, want) in [
            ("blockBitsShift", "int"),
            ("coinstake", "str"),
            ("extratx", "array"),
            ("ignoreMempool", "bool"),
        ] {
            if let Some(value) = options.get(key).filter(|v| !v.is_null()) {
                let got = crate::wallet::json_spirit_type(value);
                if got != want {
                    return Err(RpcError::new(
                        codes::TYPE_ERROR,
                        format!("Expected type {want} for {key}, got {got}"),
                    )
                    .into());
                }
            }
        }
        // DecodeHexTx (core_io.cpp:99-113)
        let decode = |hex_str: &str| -> Result<Transaction, Error> {
            hex::decode(hex_str)
                .ok()
                .filter(|b| !b.is_empty())
                .and_then(|b| deserialize::<Transaction>(&b).ok())
                .ok_or_else(|| {
                    RpcError::new(codes::DESERIALIZATION_ERROR, "TX decode failed").into()
                })
        };
        let mut wanted = GenerateBlockOptions::default();
        if let Some(Value::Array(txs)) = options.get("extratx") {
            for value in txs {
                let Value::String(hex_str) = value else {
                    return Err(RpcError::new(
                        codes::MISC_ERROR,
                        format!(
                            "value is type {}, expected str",
                            crate::wallet::json_spirit_type(value)
                        ),
                    )
                    .into());
                };
                wanted.extra_txs.push(decode(hex_str)?);
            }
        }
        if let Some(Value::String(hex_str)) = options.get("coinstake") {
            let tx = decode(hex_str)?;
            if !tx.is_coinstake() {
                return Err(
                    RpcError::new(codes::INVALID_PARAMETER, "TX is not a coinstake").into(),
                );
            }
            wanted.coinstake = Some(tx);
        }
        if let Some(Value::Bool(ignore)) = options.get("ignoreMempool") {
            wanted.ignore_mempool = *ignore;
        }
        if let Some(Value::Number(n)) = options.get("blockBitsShift") {
            // get_int(), then taken as unsigned (ExtendedBlockFactory.cpp:160-163)
            wanted.bits_shift = Some(n.as_i64().unwrap_or_default() as i32 as u32);
        }

        let callback = self.generate_block_callback.read().clone();
        let callback = callback.ok_or_else(|| {
            RpcError::new(codes::MISC_ERROR, "generateblock needs a wallet to mine to")
        })?;
        match callback(wanted) {
            Ok(hash) => Ok(serde_json::json!(hash)),
            Err(GenerateBlockFailure::Refused(message)) => {
                Err(RpcError::new(codes::MISC_ERROR, message).into())
            }
            Err(GenerateBlockFailure::Failed(why)) => {
                info!("generateblock failed: {}", why);
                Err(RpcError::new(codes::VERIFY_ERROR, "failed to generate a valid block").into())
            }
        }
    }

    pub fn reserve_balance(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let show = params.get_bool(0).unwrap_or(true);

        if show {
            let reserve = *self.reserve_balance.read();
            Ok(serde_json::json!({
                "reserve": reserve,
                "amount": reserve
            }))
        } else {
            let amount = params
                .get(1)
                .and_then(|v| v.as_f64())
                .ok_or_else(|| RpcError::invalid_params("Amount required"))?;

            if amount < 0.0 {
                return Err(RpcError::invalid_params("Amount must be non-negative").into());
            }

            *self.reserve_balance.write() = amount;

            Ok(serde_json::json!({
                "reserve": amount,
                "amount": amount
            }))
        }
    }
}

impl Default for StakingRpc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staking_rpc_creation() {
        let rpc = StakingRpc::new();
        // Without callback, should return error
        let result = rpc.get_staking_status(&Params::None);
        assert!(result.is_err());
    }

    #[test]
    fn test_stake_split_threshold_rpc() {
        let rpc = StakingRpc::new();
        let value = Arc::new(parking_lot::Mutex::new(20_000 * COIN));
        let v = Arc::clone(&value);
        rpc.set_split_threshold_control(Arc::new(move |new| {
            let mut cur = v.lock();
            if let Some(n) = new {
                *cur = n;
            }
            *cur
        }));
        assert_eq!(
            rpc.get_stake_split_threshold(&Params::None).unwrap(),
            serde_json::json!(20_000)
        );
        let set = rpc
            .set_stake_split_threshold(&Params::Array(vec![serde_json::json!(5000)]))
            .unwrap();
        assert_eq!(set, serde_json::json!({"threshold": 5000}));
        assert_eq!(*value.lock(), 5000 * COIN);
        assert!(rpc
            .set_stake_split_threshold(&Params::Array(vec![serde_json::json!(-1)]))
            .is_err());
        assert!(rpc.set_stake_split_threshold(&Params::None).is_err());
    }

    #[test]
    fn getstakingstatus_reports_the_current_split_threshold() {
        let rpc = StakingRpc::new();
        rpc.set_status_callback(Arc::new(|| StakingInfo {
            enabled: true,
            staking: false,
            errors: None,
            current_block_size: 0,
            current_block_tx: 0,
            pooled_tx: 0,
            difficulty: 0.0,
            search_interval: 0,
            weight: 0,
            netstakeweight: 0,
            expected_time: None,
            staking_balance: 0.0,
            wallet_unlocked: true,
            have_connections: true,
            valid_time: true,
            mintable_coins: false,
            enough_coins: false,
            mnsync: true,
            blocks: 0,
            // the value irondivid passes from its start-up config
            stake_split_threshold: 20000.0,
        }));
        let value = Arc::new(parking_lot::Mutex::new(20_000 * COIN));
        let v = Arc::clone(&value);
        rpc.set_split_threshold_control(Arc::new(move |new| {
            let mut cur = v.lock();
            if let Some(n) = new {
                *cur = n;
            }
            *cur
        }));
        rpc.set_stake_split_threshold(&Params::Array(vec![serde_json::json!(5000)]))
            .unwrap();
        let status = rpc.get_staking_status(&Params::None).unwrap();
        assert_eq!(status["stake split threshold"], 5000.0);
        assert_eq!(
            rpc.get_stake_split_threshold(&Params::None).unwrap(),
            serde_json::json!(5000)
        );
    }

    #[test]
    fn test_staking_rpc_with_callback() {
        let rpc = StakingRpc::new();

        rpc.set_status_callback(Arc::new(|| StakingInfo {
            enabled: true,
            staking: true,
            errors: None,
            current_block_size: 1000,
            current_block_tx: 5,
            pooled_tx: 10,
            difficulty: 1234.5,
            search_interval: 500,
            weight: 1000000,
            netstakeweight: 50000000,
            expected_time: Some(3600),
            staking_balance: 10000.0,
            wallet_unlocked: true,
            have_connections: true,
            valid_time: true,
            mintable_coins: true,
            enough_coins: true,
            mnsync: true,
            blocks: 12345,
            stake_split_threshold: 20000.0,
        }));

        let result = rpc.get_staking_status(&Params::None).unwrap();
        assert_eq!(result["staking status"], true);
        assert_eq!(result["staking status text"], "Staking Active");
        assert_eq!(result["stake split threshold"], 20000.0);
        assert_eq!(result["walletunlocked"], true);
        assert_eq!(result["staking_balance"], 10000.0);
    }
}
