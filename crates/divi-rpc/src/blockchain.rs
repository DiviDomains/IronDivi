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

//! Blockchain RPC methods
//!
//! Methods for querying blockchain state: blocks, transactions, chain info.

use crate::error::{codes, Error, RpcError};
use crate::protocol::Params;
use divi_consensus::bits_to_difficulty;
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::serialize;
use divi_storage::chain::NetworkType;
use divi_storage::Chain;
use parking_lot::RwLock;
use serde_json::{json, Value};
use std::sync::Arc;

/// Blockchain RPC handler
pub struct BlockchainRpc {
    chain: Arc<Chain>,
    mempool: RwLock<Option<Arc<dyn MempoolProvider>>>,
}

/// Mempool statistics for RPC responses
#[derive(Debug, Clone, Default)]
pub struct MempoolStats {
    /// Number of transactions in mempool
    pub size: usize,
    /// Total bytes of all transactions
    pub bytes: usize,
    /// Memory usage (bytes + overhead)
    pub usage: usize,
    /// Maximum mempool size in bytes
    pub max_mempool: usize,
    /// Minimum fee rate to get into mempool (DIVI/kB)
    pub min_fee: f64,
}

/// Fee estimation result
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    /// Fee rate in DIVI per kilobyte
    pub fee_rate: f64,
    /// Number of blocks used for estimation
    pub blocks: u32,
}

/// Trait for mempool access (to avoid circular dependency)
pub trait MempoolProvider: Send + Sync {
    fn get_txids(&self) -> Vec<Hash256>;
    fn prioritise_transaction(&self, txid: &Hash256, priority_delta: f64, fee_delta: i64) -> bool;

    /// Get mempool statistics
    fn get_stats(&self) -> MempoolStats {
        MempoolStats::default()
    }

    /// Estimate fee for confirmation within target blocks
    fn estimate_fee(&self, _conf_target: u32) -> f64 {
        0.00001 // Default minimum fee
    }

    /// Estimate smart fee with block count used
    fn estimate_smart_fee(&self, conf_target: u32) -> FeeEstimate {
        FeeEstimate {
            fee_rate: self.estimate_fee(conf_target),
            blocks: conf_target,
        }
    }
}

/// Convert chain_work from little-endian storage to big-endian hex for RPC display.
/// C++ Bitcoin/Divi stores and displays chainwork as big-endian hex.
fn chainwork_to_hex(chain_work: &[u8; 32]) -> String {
    let mut be = *chain_work;
    be.reverse();
    hex::encode(be)
}

impl BlockchainRpc {
    /// Create new blockchain RPC handler
    pub fn new(chain: Arc<Chain>) -> Self {
        BlockchainRpc {
            chain,
            mempool: RwLock::new(None),
        }
    }

    /// Get a reference to the chain
    pub fn chain(&self) -> &Arc<Chain> {
        &self.chain
    }

    /// Set the mempool provider
    pub fn set_mempool(&self, mempool: Arc<dyn MempoolProvider>) {
        *self.mempool.write() = Some(mempool);
    }

    /// Get current block count (height)
    pub fn get_block_count(&self, _params: &Params) -> Result<Value, Error> {
        let height = self.chain.height();
        Ok(json!(height))
    }

    /// Get best block hash
    pub fn get_best_block_hash(&self, _params: &Params) -> Result<Value, Error> {
        match self.chain.tip() {
            Some(tip) => Ok(json!(tip.hash.to_string())),
            None => Err(RpcError::internal_error("No blocks in chain").into()),
        }
    }

    /// Get block hash by height
    pub fn get_block_hash(&self, params: &Params) -> Result<Value, Error> {
        let height = params
            .get_i64(0)
            .ok_or_else(|| RpcError::invalid_params("Missing height parameter"))?;

        let height = height as u32;
        match self.chain.get_block_index_by_height(height)? {
            Some(index) => Ok(json!(index.hash.to_string())),
            None => Err(RpcError::invalid_params(format!(
                "Block height {} not in main chain",
                height
            ))
            .into()),
        }
    }

    /// Get block by hash
    ///
    /// Parameters:
    /// - blockhash: Block hash (hex string)
    /// - verbosity: 0 = raw hex, 1 = json object, 2 = json with tx details (default: 1)
    pub fn get_block(&self, params: &Params) -> Result<Value, Error> {
        let hash_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing blockhash parameter"))?;

        let hash = parse_hash(hash_str)?;

        let verbose = params.get_bool(1).unwrap_or(true);

        let block = self
            .chain
            .get_block(&hash)?
            .ok_or_else(|| RpcError::block_not_found(hash_str))?;

        let index = self
            .chain
            .get_block_index(&hash)?
            .ok_or_else(|| RpcError::block_not_found(hash_str))?;

        if !verbose {
            // Return raw hex
            let raw = serialize(&block);
            Ok(json!(hex::encode(raw)))
        } else {
            // Return JSON object
            let txids: Vec<String> = block
                .transactions
                .iter()
                .map(|tx| {
                    let tx_bytes = serialize(tx);
                    let txid = divi_crypto::hash256(&tx_bytes);
                    txid.to_string()
                })
                .collect();

            let mut result = json!({
                "hash": hash.to_string(),
                "confirmations": self.get_confirmations(&index),
                "size": serialize(&block).len(),
                "height": index.height,
                "version": index.version,
                "merkleroot": index.merkle_root.to_string(),
                "tx": txids,
                "time": index.time,
                "mediantime": self.get_median_time(&index),
                "nonce": index.nonce,
                "bits": format!("{:08x}", index.bits),
                "difficulty": bits_to_difficulty(index.bits),
                "chainwork": chainwork_to_hex(&index.chain_work),
                "nTx": block.transactions.len(),
                "previousblockhash": if index.height > 0 {
                    Some(index.prev_hash.to_string())
                } else {
                    None
                },
            });

            // Add nextblockhash if not tip
            if let Some(tip) = self.chain.tip() {
                if index.height < tip.height {
                    if let Ok(Some(next)) = self.chain.get_block_index_by_height(index.height + 1) {
                        result["nextblockhash"] = json!(next.hash.to_string());
                    }
                }
            }

            Ok(result)
        }
    }

    /// Get block header
    pub fn get_block_header(&self, params: &Params) -> Result<Value, Error> {
        let hash_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing blockhash parameter"))?;

        let hash = parse_hash(hash_str)?;
        let verbose = params.get_bool(1).unwrap_or(true);

        let block = self
            .chain
            .get_block(&hash)?
            .ok_or_else(|| RpcError::block_not_found(hash_str))?;

        let index = self
            .chain
            .get_block_index(&hash)?
            .ok_or_else(|| RpcError::block_not_found(hash_str))?;

        if !verbose {
            // Return raw hex
            let raw = serialize(&block.header);
            Ok(json!(hex::encode(raw)))
        } else {
            let mut result = json!({
                "hash": hash.to_string(),
                "confirmations": self.get_confirmations(&index),
                "height": index.height,
                "version": index.version,
                "merkleroot": index.merkle_root.to_string(),
                "time": index.time,
                "mediantime": self.get_median_time(&index),
                "nonce": index.nonce,
                "bits": format!("{:08x}", index.bits),
                "difficulty": bits_to_difficulty(index.bits),
                "chainwork": chainwork_to_hex(&index.chain_work),
                "nTx": index.n_tx,
                "previousblockhash": if index.height > 0 {
                    Some(index.prev_hash.to_string())
                } else {
                    None
                },
            });

            // Add nextblockhash if not tip
            if let Some(tip) = self.chain.tip() {
                if index.height < tip.height {
                    if let Ok(Some(next)) = self.chain.get_block_index_by_height(index.height + 1) {
                        result["nextblockhash"] = json!(next.hash.to_string());
                    }
                }
            }

            Ok(result)
        }
    }

    /// Get blockchain info
    pub fn get_blockchain_info(&self, _params: &Params) -> Result<Value, Error> {
        let tip = self.chain.tip();
        let (height, best_hash, chain_work, mediantime, difficulty) = match &tip {
            Some(t) => (
                t.height,
                t.hash.to_string(),
                chainwork_to_hex(&t.chain_work),
                self.get_median_time(&t),
                bits_to_difficulty(t.bits),
            ),
            None => (
                0,
                Hash256::zero().to_string(),
                hex::encode([0u8; 32]),
                0,
                1.0,
            ),
        };

        Ok(json!({
            "chain": match self.chain.network_type() {
                NetworkType::Mainnet => "main",
                NetworkType::Testnet => "test",
                NetworkType::Regtest => "regtest",
            },
            "blocks": height,
            "headers": height,
            "bestblockhash": best_hash,
            "difficulty": difficulty,
            "mediantime": mediantime,
            "verificationprogress": 1.0,
            "chainwork": chain_work,
            "pruned": false,
            "warnings": ""
        }))
    }

    /// Get general info (deprecated, replaced by getblockchaininfo/getnetworkinfo/getwalletinfo)
    pub fn get_info(&self, _params: &Params) -> Result<Value, Error> {
        let tip = self.chain.tip();
        let (height, difficulty) = match &tip {
            Some(t) => (t.height, bits_to_difficulty(t.bits)),
            None => (0, 1.0),
        };

        Ok(json!({
            "version": 2000000,
            "protocolversion": 70020,
            "blocks": height,
            "timeoffset": 0,
            "connections": 0,
            "proxy": "",
            "difficulty": difficulty,
            "testnet": matches!(self.chain.network_type(), NetworkType::Testnet),
            "moneysupply": 0,
            "keypoololdest": 0,
            "keypoolsize": 0,
            "paytxfee": 0.0,
            "relayfee": 0.00001,
            "staking status": "Staking Not Active",
            "errors": ""
        }))
    }

    /// Get chain tips
    pub fn get_chain_tips(&self, _params: &Params) -> Result<Value, Error> {
        let tip = self.chain.tip();
        match tip {
            Some(t) => Ok(json!([{
                "height": t.height,
                "hash": t.hash.to_string(),
                "branchlen": 0,
                "status": "active"
            }])),
            None => Ok(json!([])),
        }
    }

    /// Get difficulty
    pub fn get_difficulty(&self, _params: &Params) -> Result<Value, Error> {
        let tip = self.chain.tip();
        let difficulty = match tip {
            Some(t) => bits_to_difficulty(t.bits),
            None => 1.0,
        };
        Ok(json!(difficulty))
    }

    /// Get TXOUT set info
    pub fn get_txout_set_info(&self, _params: &Params) -> Result<Value, Error> {
        let tip = self.chain.tip();
        let (height, best_hash) = match tip {
            Some(t) => (t.height, t.hash.to_string()),
            None => (0, Hash256::zero().to_string()),
        };

        let stats = self.chain.get_utxo_stats().map_err(|e| {
            RpcError::new(
                codes::INTERNAL_ERROR,
                &format!("Failed to get UTXO stats: {}", e),
            )
        })?;

        let total_amount_divi = stats.total_amount as f64 / 100_000_000.0;

        let hash_serialized = hex::encode(stats.hash_serialized);

        Ok(json!({
            "height": height,
            "bestblock": best_hash,
            "transactions": stats.transactions,
            "txouts": stats.txouts,
            "bogosize": stats.bytes_serialized,
            "hash_serialized": hash_serialized,
            "total_amount": total_amount_divi
        }))
    }

    // Helper methods

    fn get_confirmations(&self, index: &divi_storage::BlockIndex) -> i64 {
        match self.chain.tip() {
            Some(tip) => (tip.height as i64) - (index.height as i64) + 1,
            None => 0,
        }
    }

    /// Calculate the median time of the past 11 blocks (or fewer if not available)
    fn get_median_time(&self, index: &divi_storage::BlockIndex) -> u32 {
        const MEDIAN_TIME_SPAN: u32 = 11;

        let mut timestamps = Vec::with_capacity(MEDIAN_TIME_SPAN as usize);
        timestamps.push(index.time);

        // Collect timestamps from previous blocks
        let mut current_height = index.height;
        let mut prev_hash = index.prev_hash;

        while timestamps.len() < MEDIAN_TIME_SPAN as usize && current_height > 0 {
            if let Ok(Some(prev_index)) = self.chain.get_block_index(&prev_hash) {
                timestamps.push(prev_index.time);
                prev_hash = prev_index.prev_hash;
                current_height = prev_index.height;
            } else {
                break;
            }
        }

        // Sort and find median
        timestamps.sort_unstable();
        timestamps[timestamps.len() / 2]
    }

    fn tx_to_json(&self, tx: &divi_primitives::transaction::Transaction) -> Value {
        let tx_bytes = serialize(tx);
        let txid = divi_crypto::hash256(&tx_bytes);

        let vin: Vec<Value> = tx
            .vin
            .iter()
            .map(|input| {
                if input.prevout.is_null() {
                    json!({
                        "coinbase": hex::encode(&input.script_sig.as_bytes()),
                        "sequence": input.sequence
                    })
                } else {
                    json!({
                        "txid": input.prevout.txid.to_string(),
                        "vout": input.prevout.vout,
                        "scriptSig": {
                            "hex": hex::encode(&input.script_sig.as_bytes())
                        },
                        "sequence": input.sequence
                    })
                }
            })
            .collect();

        let vout: Vec<Value> = tx
            .vout
            .iter()
            .enumerate()
            .map(|(n, output)| {
                json!({
                    "value": output.value.as_sat() as f64 / 100_000_000.0,
                    "n": n,
                    "scriptPubKey": {
                        "hex": hex::encode(&output.script_pubkey.as_bytes())
                    }
                })
            })
            .collect();

        json!({
            "txid": txid.to_string(),
            "version": tx.version,
            "locktime": tx.lock_time,
            "vin": vin,
            "vout": vout
        })
    }

    pub fn get_raw_mempool(&self, _params: &Params) -> Result<Value, Error> {
        let mempool_guard = self.mempool.read();
        let Some(ref mempool) = *mempool_guard else {
            return Ok(json!([]));
        };

        let txids: Vec<String> = mempool
            .get_txids()
            .iter()
            .map(|txid| txid.to_string())
            .collect();

        Ok(json!(txids))
    }

    pub fn prioritise_transaction(&self, params: &Params) -> Result<Value, Error> {
        let txid_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing txid parameter"))?;

        let priority_delta = match params.get(1) {
            Some(value) => value
                .as_f64()
                .ok_or_else(|| RpcError::invalid_params("Priority delta must be a number"))?,
            None => return Err(RpcError::invalid_params("Missing priority delta parameter").into()),
        };

        let fee_delta = params
            .get_i64(2)
            .ok_or_else(|| RpcError::invalid_params("Missing fee delta parameter"))?;

        let txid = parse_hash(txid_str)?;

        let mempool_guard = self.mempool.read();
        let Some(ref mempool) = *mempool_guard else {
            return Err(RpcError::new(codes::INTERNAL_ERROR, "Mempool not available").into());
        };

        let success = mempool.prioritise_transaction(&txid, priority_delta, fee_delta);
        Ok(json!(success))
    }

    pub fn get_tx_out(&self, params: &Params) -> Result<Value, Error> {
        use divi_primitives::hash::Hash160;
        use divi_primitives::transaction::OutPoint;
        use divi_wallet::address::{Address, AddressType, Network};

        let txid_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing txid parameter"))?;

        let vout = params
            .get_i64(1)
            .ok_or_else(|| RpcError::invalid_params("Missing vout parameter"))?;

        let txid = parse_hash(txid_str)?;

        if vout < 0 {
            return Err(RpcError::invalid_params("vout must be non-negative").into());
        }
        let vout = vout as u32;

        let _include_mempool = params.get_bool(2).unwrap_or(true);

        let outpoint = OutPoint::new(txid, vout);
        match self.chain.get_utxo(&outpoint)? {
            Some(utxo) => {
                let current_height = self.chain.height();
                let confirmations = current_height.saturating_sub(utxo.height) + 1;

                let best_block_hash = match self.chain.tip() {
                    Some(tip) => tip.hash.to_string(),
                    None => Hash256::zero().to_string(),
                };

                let address = if let Some(pkh) = utxo.script_pubkey.extract_p2pkh_hash() {
                    Some(
                        Address::from_pubkey_hash(Hash160::from_bytes(pkh), Network::Mainnet)
                            .to_base58(),
                    )
                } else if let Some(sh) = utxo.script_pubkey.extract_p2sh_hash() {
                    Some(Address::p2sh(Hash160::from_bytes(sh), Network::Mainnet).to_base58())
                } else {
                    None
                };

                let script_type = if utxo.script_pubkey.is_p2pkh() {
                    "pubkeyhash"
                } else if utxo.script_pubkey.is_p2sh() {
                    "scripthash"
                } else {
                    "nonstandard"
                };

                let mut script_obj = json!({
                    "hex": hex::encode(utxo.script_pubkey.as_bytes()),
                    "type": script_type,
                });

                if let Some(addr) = address {
                    script_obj["addresses"] = json!([addr]);
                }

                Ok(json!({
                    "bestblock": best_block_hash,
                    "confirmations": confirmations,
                    "value": utxo.value.as_divi_f64(),
                    "scriptPubKey": script_obj,
                    "coinbase": utxo.is_coinbase,
                    "coinstake": utxo.is_coinstake,
                }))
            }
            None => Ok(json!(null)),
        }
    }

    pub fn generate_block(&self, _params: &Params) -> Result<Value, Error> {
        Err(RpcError::new(
            codes::INTERNAL_ERROR,
            "generateblock is not yet implemented - requires full mining subsystem",
        )
        .into())
    }

    pub fn set_generate(&self, _params: &Params) -> Result<Value, Error> {
        Err(RpcError::new(
            codes::INTERNAL_ERROR,
            "setgenerate is not yet implemented - requires full mining subsystem",
        )
        .into())
    }

    pub fn decode_script(&self, params: &Params) -> Result<Value, Error> {
        use divi_crypto::hash160;
        use divi_primitives::hash::Hash160;
        use divi_primitives::script::Script;
        use divi_script::{
            extract_destinations, extract_script_type, get_script_type_name, to_asm,
        };
        use divi_wallet::address::{Address, AddressType, Network};

        let hex_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing hex parameter"))?;

        let script_bytes =
            hex::decode(hex_str).map_err(|_| RpcError::invalid_params("Invalid script hex"))?;

        let (script_type, _solutions) = extract_script_type(&script_bytes);

        let asm = to_asm(&script_bytes);
        let type_name = get_script_type_name(script_type);

        let mut result = json!({
            "asm": asm,
            "hex": hex_str,
            "type": type_name,
        });

        if let Some((stype, destinations, req_sigs)) = extract_destinations(&script_bytes) {
            result["reqSigs"] = json!(req_sigs);

            let addresses: Vec<String> = destinations
                .iter()
                .filter_map(|dest| match dest {
                    divi_script::Destination::PubKeyHash(pkh) => {
                        let mut bytes = [0u8; 20];
                        bytes.copy_from_slice(pkh);
                        let addr =
                            Address::from_pubkey_hash(Hash160::from_bytes(bytes), Network::Mainnet);
                        Some(addr.to_base58())
                    }
                    divi_script::Destination::ScriptHash(sh) => {
                        let mut bytes = [0u8; 20];
                        bytes.copy_from_slice(sh);
                        let addr = Address::p2sh(Hash160::from_bytes(bytes), Network::Mainnet);
                        Some(addr.to_base58())
                    }
                })
                .collect();

            if !addresses.is_empty() {
                result["addresses"] = json!(addresses);
            }

            if type_name != "scripthash" {
                let script_hash = hash160(&script_bytes);
                let mut bytes = [0u8; 20];
                bytes.copy_from_slice(script_hash.as_ref());
                let p2sh_addr = Address::p2sh(Hash160::from_bytes(bytes), Network::Mainnet);
                result["p2sh"] = json!(p2sh_addr.to_base58());
            }
        }

        Ok(result)
    }

    // Address Index Commands

    /// Get address deltas
    pub fn get_address_deltas(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters to validate structure
        let _addresses = self.parse_address_index_params(params, "getaddressdeltas")?;

        // Return address index not enabled error
        Err(self.address_index_not_enabled())
    }

    /// Get address transaction IDs
    pub fn get_address_txids(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters to validate structure
        let _addresses = self.parse_address_index_params(params, "getaddresstxids")?;

        // Return address index not enabled error
        Err(self.address_index_not_enabled())
    }

    /// Get spent info for a transaction output
    pub fn get_spent_info(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters - expect object with txid and index
        let param = params
            .get(0)
            .ok_or_else(|| RpcError::invalid_params("Missing parameter"))?;

        if let Some(obj) = param.as_object() {
            // Validate txid field
            let txid_str = obj
                .get("txid")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RpcError::invalid_params("Missing or invalid 'txid' field"))?;

            // Validate it's a valid hash
            let _txid = parse_hash(txid_str)?;

            // Validate index field
            let _index = obj
                .get("index")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| RpcError::invalid_params("Missing or invalid 'index' field"))?;
        } else {
            return Err(RpcError::invalid_params(
                "Parameter must be an object with 'txid' and 'index' fields",
            )
            .into());
        }

        // Return address index not enabled error
        Err(self.address_index_not_enabled())
    }

    // Helper methods for address index

    fn address_index_not_enabled(&self) -> Error {
        RpcError::new(
            -5,
            "Address index not enabled. To use address index features, you must:\n\
             1. Stop IronDivi\n\
             2. Add -addressindex=1 to your configuration\n\
             3. Add -reindex=1 for the next startup (one time only)\n\
             4. Restart IronDivi and wait for full blockchain reindex\n\
             \n\
             Warning: Reindexing can take 40-60 hours depending on blockchain size.\n\
             The address index allows querying transaction history and balances for any address.",
        )
        .into()
    }

    fn parse_address_index_params(
        &self,
        params: &Params,
        method: &str,
    ) -> Result<Vec<String>, Error> {
        let param = params
            .get(0)
            .ok_or_else(|| RpcError::invalid_params("Missing address parameter"))?;

        // Handle single address string
        if let Some(addr) = param.as_str() {
            return Ok(vec![addr.to_string()]);
        }

        // Handle object with addresses array
        if let Some(obj) = param.as_object() {
            if let Some(addresses) = obj.get("addresses") {
                if let Some(arr) = addresses.as_array() {
                    let addrs: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();

                    if addrs.is_empty() {
                        return Err(RpcError::invalid_params(
                            "'addresses' array is empty or invalid",
                        )
                        .into());
                    }

                    // Validate optional fields if present
                    if let Some(start) = obj.get("start") {
                        if !start.is_i64() {
                            return Err(
                                RpcError::invalid_params("'start' must be an integer").into()
                            );
                        }
                    }

                    if let Some(end) = obj.get("end") {
                        if !end.is_i64() {
                            return Err(RpcError::invalid_params("'end' must be an integer").into());
                        }
                    }

                    if method == "getaddressdeltas" {
                        if let Some(chain_info) = obj.get("chainInfo") {
                            if !chain_info.is_boolean() {
                                return Err(RpcError::invalid_params(
                                    "'chainInfo' must be a boolean",
                                )
                                .into());
                            }
                        }
                    }

                    return Ok(addrs);
                } else {
                    return Err(RpcError::invalid_params("'addresses' must be an array").into());
                }
            } else {
                return Err(
                    RpcError::invalid_params("Object must contain 'addresses' field").into(),
                );
            }
        }

        Err(RpcError::invalid_params(
            "Parameter must be a string address or object with 'addresses' field",
        )
        .into())
    }

    /// Verify blockchain database
    /// verifychain ( numblocks )
    pub fn verifychain(&self, params: &Params) -> Result<Value, Error> {
        // Parse optional numblocks parameter (default 288)
        let numblocks = params.get_i64(0).unwrap_or(288).max(0) as u64;

        let best_height = self.chain.height() as u64;

        // Verify last N blocks
        let start_height = best_height.saturating_sub(numblocks);

        for height in start_height..=best_height {
            // Check that block index exists
            let index = match self.chain.get_block_index_by_height(height as u32)? {
                Some(idx) => idx,
                None => return Ok(json!(false)),
            };

            // Verify block data exists
            if self.chain.get_block(&index.hash)?.is_none() {
                return Ok(json!(false));
            }
        }

        Ok(json!(true))
    }

    /// Get mining information
    /// getmininginfo
    pub fn getmininginfo(&self, _params: &Params) -> Result<Value, Error> {
        let tip = self.chain.tip();
        let (blocks, difficulty) = match &tip {
            Some(t) => (t.height, bits_to_difficulty(t.bits)),
            None => (0, 1.0),
        };

        // Get mempool size
        let pooled_tx = {
            let mempool_guard = self.mempool.read();
            if let Some(ref mempool) = *mempool_guard {
                mempool.get_txids().len()
            } else {
                0
            }
        };

        Ok(json!({
            "blocks": blocks,
            "currentblocksize": 0,
            "currentblocktx": 0,
            "difficulty": difficulty,
            "errors": "",
            "pooledtx": pooled_tx,
            "testnet": matches!(self.chain.network_type(), NetworkType::Testnet),
            "chain": match self.chain.network_type() {
                NetworkType::Mainnet => "main",
                NetworkType::Testnet => "test",
                NetworkType::Regtest => "regtest",
            },
        }))
    }
}

/// Parse a hash from hex string
fn parse_hash(s: &str) -> Result<Hash256, Error> {
    Hash256::from_hex(s)
        .map_err(|e| RpcError::invalid_params(format!("Invalid hash: {} - {}", s, e)).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash() {
        let hash_str = "0000000000000000000000000000000000000000000000000000000000000000";
        let hash = parse_hash(hash_str).unwrap();
        assert_eq!(hash, Hash256::zero());
    }

    #[test]
    fn test_parse_hash_invalid() {
        assert!(parse_hash("not_hex").is_err());
        assert!(parse_hash("0000").is_err()); // Too short
    }
}
