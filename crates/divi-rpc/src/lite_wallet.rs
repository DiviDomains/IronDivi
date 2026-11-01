// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Lite Wallet RPC methods
//!
//! Provides RPC methods for lite wallet services - external address queries
//! without requiring a local wallet. These services can be incentivized
//! through the network reward system.

use crate::blockchain::MempoolProvider;
use crate::error::{codes, Error, RpcError};
use crate::protocol::Params;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_storage::{AddressIndex, Chain, NetworkType};
use std::sync::Arc;

/// Most entries one getaddressutxos or getaddresshistory call returns, and
/// most addresses one validateaddresses call takes
pub const MAX_PAGE: usize = 1000;

/// Lite wallet RPC handler
pub struct LiteWalletRpc {
    /// Chain reference for height queries
    chain: Option<Arc<Chain>>,
    /// Address index for external lookups
    address_index: Option<Arc<AddressIndex>>,
    /// Mempool provider for fee estimation and mempool stats
    mempool: Option<Arc<dyn MempoolProvider>>,
}

impl LiteWalletRpc {
    /// Create a new lite wallet RPC handler
    pub fn new() -> Self {
        LiteWalletRpc {
            chain: None,
            address_index: None,
            mempool: None,
        }
    }

    /// Create with a chain reference, so addresses are checked against its network
    pub fn for_chain(chain: Arc<Chain>) -> Self {
        LiteWalletRpc {
            chain: Some(chain),
            address_index: None,
            mempool: None,
        }
    }

    /// Create with chain and address index
    pub fn with_index(chain: Arc<Chain>, address_index: Arc<AddressIndex>) -> Self {
        LiteWalletRpc {
            chain: Some(chain),
            address_index: Some(address_index),
            mempool: None,
        }
    }

    /// Set the chain reference
    pub fn set_chain(&mut self, chain: Arc<Chain>) {
        self.chain = Some(chain);
    }

    /// Set the address index
    pub fn set_address_index(&mut self, index: Arc<AddressIndex>) {
        self.address_index = Some(index);
    }

    /// Set the mempool provider for fee estimation
    pub fn set_mempool(&mut self, mempool: Arc<dyn MempoolProvider>) {
        self.mempool = Some(mempool);
    }

    /// Get the current chain height
    fn get_height(&self) -> u32 {
        self.chain.as_ref().map(|c| c.height()).unwrap_or(0)
    }

    /// Decode an address; once the chain is known, an address of another network is invalid
    fn decode_address(&self, addr_str: &str) -> Option<divi_wallet::address::Address> {
        use divi_wallet::address::{Address, Network};

        match self.chain.as_ref().map(|c| c.network_type()) {
            Some(network_type) => {
                let network = match network_type {
                    NetworkType::Mainnet => Network::Mainnet,
                    NetworkType::Testnet => Network::Testnet,
                    NetworkType::Regtest => Network::Regtest,
                };
                Address::from_base58_for_network(addr_str, network).ok()
            }
            None => Address::from_base58(addr_str).ok(),
        }
    }

    /// Parse an address string to a script
    fn parse_address(&self, addr_str: &str) -> Result<Script, Error> {
        use divi_wallet::address::AddressType;

        let address = self
            .decode_address(addr_str)
            .ok_or_else(|| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        // Convert address to script_pubkey
        match address.addr_type {
            AddressType::P2PKH => Ok(Script::new_p2pkh(address.hash.as_bytes())),
            AddressType::P2SH => Ok(Script::new_p2sh(address.hash.as_bytes())),
        }
    }

    // ========== RPC Methods ==========

    /// Get balance for an external address
    /// getaddressbalance "address" ( minconf )
    pub fn get_address_balance(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let index = self
            .address_index
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Address index not available"))?;

        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let min_conf = params.get_u64(1).unwrap_or(1) as u32;
        let height = self.get_height();

        let script = self.parse_address(addr_str)?;
        let coinbase_maturity = self
            .chain
            .as_ref()
            .map(|c| c.params().coinbase_maturity)
            .unwrap_or(20);
        let balance = index
            .get_balance(&script, min_conf, height, coinbase_maturity)
            .map_err(|e| RpcError::new(codes::MISC_ERROR, e.to_string()))?;

        Ok(serde_json::json!({
            "balance": balance.as_sat(),
            "balance_divi": balance.as_divi_f64(),
            "confirmed": true,
        }))
    }

    /// Get UTXOs for an external address, a page at a time
    /// getaddressutxos "address" ( minconf maxconf skip limit )
    pub fn get_address_utxos(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let index = self
            .address_index
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Address index not available"))?;

        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let min_conf = params.get_u64(1).unwrap_or(1) as u32;
        let max_conf = params.get_u64(2).unwrap_or(9999999) as u32;
        let skip = params.get_u64(3).unwrap_or(0) as usize;
        let limit = params
            .get_u64(4)
            .map_or(MAX_PAGE, |l| (l as usize).min(MAX_PAGE));
        let height = self.get_height();

        let script = self.parse_address(addr_str)?;
        let utxos = index
            .get_utxos_for_address(&script)
            .map_err(|e| RpcError::new(codes::MISC_ERROR, e.to_string()))?;

        let result: Vec<serde_json::Value> = utxos
            .iter()
            .filter_map(|utxo| {
                let confirmations = if height >= utxo.height {
                    height - utxo.height + 1
                } else {
                    0
                };

                if confirmations >= min_conf && confirmations <= max_conf {
                    Some(serde_json::json!({
                        "txid": utxo.outpoint.txid.to_string(),
                        "vout": utxo.outpoint.vout,
                        "address": addr_str,
                        "amount": utxo.value.as_divi_f64(),
                        "satoshis": utxo.value.as_sat(),
                        "height": utxo.height,
                        "confirmations": confirmations,
                    }))
                } else {
                    None
                }
            })
            .skip(skip)
            .take(limit)
            .collect();

        Ok(serde_json::json!(result))
    }

    /// Get transaction history for an address
    /// getaddresshistory "address" ( skip limit )
    pub fn get_address_history(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let index = self
            .address_index
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Address index not available"))?;

        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let skip = params.get_u64(1).unwrap_or(0) as usize;
        let limit = params.get_u64(2).unwrap_or(100) as usize;
        let limit = std::cmp::min(limit, MAX_PAGE);

        let script = self.parse_address(addr_str)?;
        let history = index
            .get_history(&script, skip, limit)
            .map_err(|e| RpcError::new(codes::MISC_ERROR, e.to_string()))?;

        let result: Vec<serde_json::Value> = history
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "txid": entry.txid.to_string(),
                    "block_hash": entry.block_hash.to_string(),
                    "height": entry.height,
                    "timestamp": entry.timestamp,
                    "value_change": entry.value_change,
                    "value_change_divi": entry.value_change as f64 / 100_000_000.0,
                    "confirmed": entry.is_confirmed,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "address": addr_str,
            "history": result,
            "count": result.len(),
        }))
    }

    /// Get transaction by txid
    /// gettxindex "txid"
    pub fn get_tx_index(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let index = self
            .address_index
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Address index not available"))?;

        let txid_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Transaction ID required"))?;

        let txid = Hash256::from_hex(txid_str)
            .map_err(|_| RpcError::invalid_params(format!("Invalid txid: {}", txid_str)))?;

        match index.get_tx_index(&txid) {
            Ok(Some(entry)) => Ok(serde_json::json!({
                "txid": txid_str,
                "block_hash": entry.block_hash.to_string(),
                "block_height": entry.block_height,
                "tx_index": entry.tx_index,
            })),
            Ok(None) => Err(RpcError::new(codes::MISC_ERROR, "Transaction not found").into()),
            Err(e) => Err(RpcError::new(codes::MISC_ERROR, e.to_string()).into()),
        }
    }

    /// Estimate fee for transaction
    /// estimatefee ( nblocks )
    pub fn estimate_fee(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let conf_target = params.get_u64(0).unwrap_or(6) as u32;

        let fee_rate = if let Some(ref mempool) = self.mempool {
            mempool.estimate_fee(conf_target)
        } else {
            0.0001 // Divi Core's default relay floor, 10000 sat/kB
        };

        Ok(serde_json::json!(fee_rate))
    }

    /// Estimate smart fee with more details
    /// estimatesmartfee ( nblocks )
    pub fn estimate_smart_fee(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let conf_target = params.get_u64(0).unwrap_or(6) as u32;

        if let Some(ref mempool) = self.mempool {
            let estimate = mempool.estimate_smart_fee(conf_target);
            Ok(serde_json::json!({
                "feerate": estimate.fee_rate,
                "blocks": estimate.blocks,
            }))
        } else {
            Ok(serde_json::json!({
                "feerate": 0.0001,
                "blocks": conf_target,
            }))
        }
    }

    pub fn estimate_priority(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        // Not in Divi Core 3.0.0 (docs/divid-differences.md R1); "-1" as text
        Ok(serde_json::Value::String("-1".to_string()))
    }

    /// Get mempool info for fee estimation
    /// getmempoolinfo
    pub fn get_mempool_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        if let Some(ref mempool) = self.mempool {
            let stats = mempool.get_stats();
            Ok(serde_json::json!({
                "size": stats.size,
                "bytes": stats.bytes,
                "usage": stats.usage,
                "maxmempool": stats.max_mempool,
                "mempoolminfee": stats.min_fee,
            }))
        } else {
            Ok(serde_json::json!({
                "size": 0,
                "bytes": 0,
                "usage": 0,
                "maxmempool": 300000000,
                "mempoolminfee": 0.0001,
            }))
        }
    }

    /// Validate multiple addresses
    /// validateaddresses ["address1", "address2", ...]
    pub fn validate_addresses(&self, params: &Params) -> Result<serde_json::Value, Error> {
        // Get first parameter and check if it's an array
        let addresses = params
            .get(0)
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::invalid_params("Array of addresses required"))?;
        if addresses.len() > MAX_PAGE {
            return Err(RpcError::invalid_params(format!(
                "At most {MAX_PAGE} addresses at once, got {}",
                addresses.len()
            ))
            .into());
        }

        let results: Vec<serde_json::Value> = addresses
            .iter()
            .filter_map(|v| v.as_str())
            .map(|addr_str| {
                let valid = self.decode_address(addr_str).is_some();
                serde_json::json!({
                    "address": addr_str,
                    "valid": valid,
                })
            })
            .collect();

        Ok(serde_json::json!(results))
    }

    /// Get info about lite wallet service
    /// getlitewalletinfo
    pub fn get_lite_wallet_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let has_index = self.address_index.is_some();
        let height = self.get_height();

        Ok(serde_json::json!({
            "enabled": has_index,
            "indexed_height": height,
            "services": [
                "getaddressbalance",
                "getaddressutxos",
                "getaddresshistory",
                "gettxindex",
                "estimatefee",
                "estimatesmartfee",
                "validateaddresses",
            ],
        }))
    }
}

impl Default for LiteWalletRpc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lite_wallet_rpc_creation() {
        let rpc = LiteWalletRpc::new();
        assert!(rpc.chain.is_none());
        assert!(rpc.address_index.is_none());
    }

    #[test]
    fn test_estimate_fee() {
        let rpc = LiteWalletRpc::new();
        let result = rpc.estimate_fee(&Params::None).unwrap();
        assert!(result.as_f64().unwrap() > 0.0);
    }

    #[test]
    fn test_estimate_smart_fee() {
        let rpc = LiteWalletRpc::new();
        let result = rpc.estimate_smart_fee(&Params::None).unwrap();
        assert!(result["feerate"].as_f64().unwrap() > 0.0);
        assert!(result["blocks"].as_u64().is_some());
    }

    #[test]
    fn test_get_mempool_info() {
        let rpc = LiteWalletRpc::new();
        let result = rpc.get_mempool_info(&Params::None).unwrap();
        assert!(result["maxmempool"].as_u64().is_some());
    }

    #[test]
    fn test_get_lite_wallet_info() {
        let rpc = LiteWalletRpc::new();
        let result = rpc.get_lite_wallet_info(&Params::None).unwrap();
        assert!(!result["enabled"].as_bool().unwrap());
        assert!(result["services"].as_array().is_some());
    }

    #[test]
    fn node13_validateaddresses_caps_its_array() {
        let rpc = LiteWalletRpc::new();
        let addresses = |n| Params::Array(vec![serde_json::json!(vec!["x"; n])]);
        let result = rpc.validate_addresses(&addresses(MAX_PAGE)).unwrap();
        assert_eq!(result.as_array().map(Vec::len), Some(MAX_PAGE));
        let err = rpc
            .validate_addresses(&addresses(MAX_PAGE + 1))
            .unwrap_err();
        assert!(err.to_string().contains("At most 1000"), "{err}");
    }
}
