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
}

/// Callback for getting staking status
pub type StakingStatusCallback = Arc<dyn Fn() -> StakingInfo + Send + Sync>;

/// Callback for enabling/disabling staking
pub type SetStakingCallback = Arc<dyn Fn(bool) -> Result<(), String> + Send + Sync>;

pub struct StakingRpc {
    status_callback: RwLock<Option<StakingStatusCallback>>,
    set_staking_callback: RwLock<Option<SetStakingCallback>>,
    reserve_balance: RwLock<f64>,
}

impl StakingRpc {
    pub fn new() -> Self {
        StakingRpc {
            status_callback: RwLock::new(None),
            set_staking_callback: RwLock::new(None),
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

    /// getstakingstatus - Get staking status (C++ Divi format)
    pub fn get_staking_status(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let callback = self.status_callback.read();
        let callback = callback
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Staking not available"))?;

        let info = callback();

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
            "staking status": staking_status_text,
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
        }));

        let result = rpc.get_staking_status(&Params::None).unwrap();
        assert_eq!(result["staking status"], "Staking Active");
        assert_eq!(result["walletunlocked"], true);
        assert_eq!(result["staking_balance"], 10000.0);
    }
}
