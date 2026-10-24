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
use divi_primitives::hash::{Hash160, Hash256};
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
    /// Money supply cached against the tip hash it was computed for
    money_supply_cache: RwLock<Option<(Hash256, f64)>>,
    /// Fetches blocks this node has pruned from full-history peers
    block_fetcher: RwLock<Option<Arc<dyn BlockFetcher>>>,
}

/// Source for block bodies this node no longer stores (to avoid a dependency on divi-node).
///
/// Implementations must return only a block that matches `hash` and `merkle_root`.
pub trait BlockFetcher: Send + Sync {
    fn fetch_block(
        &self,
        hash: Hash256,
        merkle_root: Hash256,
    ) -> Option<divi_primitives::block::Block>;

    /// Connected peers that keep every block
    fn full_peer_count(&self) -> usize;

    /// Outcome of the most recent fetch
    fn last_result(&self) -> Option<String>;
}

/// Load a block body, asking `fetcher` for it if it is pruned locally. `None` if unobtainable.
pub fn load_block_or_fetch(
    chain: &Chain,
    fetcher: Option<&Arc<dyn BlockFetcher>>,
    index: &divi_storage::block_index::BlockIndex,
) -> Result<Option<divi_primitives::block::Block>, divi_storage::StorageError> {
    if let Some(block) = chain.get_block(&index.hash)? {
        return Ok(Some(block));
    }
    if index.height <= chain.prune_height() {
        return Ok(fetcher.and_then(|f| f.fetch_block(index.hash, index.merkle_root)));
    }
    Ok(None)
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

/// Per-transaction mempool details for `getrawmempool true`
#[derive(Debug, Clone)]
pub struct MempoolTxInfo {
    pub txid: Hash256,
    pub size: usize,
    /// Fee in satoshis
    pub fee_sat: i64,
    /// Unix time the transaction entered the pool
    pub time: i64,
    /// Unconfirmed in-pool parents
    pub depends: Vec<Hash256>,
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

    /// Details for every pool transaction (verbose getrawmempool)
    fn get_tx_infos(&self) -> Vec<MempoolTxInfo> {
        Vec::new()
    }

    fn prioritise_transaction(&self, txid: &Hash256, priority_delta: f64, fee_delta: i64) -> bool;

    /// Whether a pool transaction spends this outpoint
    fn is_spent(&self, _outpoint: &divi_primitives::transaction::OutPoint) -> bool {
        false
    }

    /// The pool's copy of a transaction, if it holds `txid`
    fn get_transaction(
        &self,
        _txid: &Hash256,
    ) -> Option<divi_primitives::transaction::Transaction> {
        None
    }

    /// The pool transaction whose bare txid is `bare` (Divi Core
    /// `CTxMemPool::lookupBareTxid`)
    fn get_transaction_by_bare_txid(
        &self,
        bare: &Hash256,
    ) -> Option<divi_primitives::transaction::Transaction> {
        self.get_txids()
            .iter()
            .filter_map(|txid| self.get_transaction(txid))
            .find(|tx| divi_storage::bare_txid(tx) == *bare)
    }

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
    /// Current chain tip height
    pub fn tip_height(&self) -> i32 {
        self.chain.height() as i32
    }

    /// Create new blockchain RPC handler
    pub fn new(chain: Arc<Chain>) -> Self {
        BlockchainRpc {
            chain,
            mempool: RwLock::new(None),
            money_supply_cache: RwLock::new(None),
            block_fetcher: RwLock::new(None),
        }
    }

    /// Total money supply in DIVI (equals the UTXO set total, as C++ `nMoneySupply` does).
    ///
    /// A full UTXO scan is costly, so the result is cached per tip hash.
    /// Address-encoding network matching the chain this node runs on
    fn address_network(&self) -> divi_wallet::address::Network {
        use divi_wallet::address::Network;
        match self.chain.network_type() {
            NetworkType::Mainnet => Network::Mainnet,
            NetworkType::Testnet => Network::Testnet,
            NetworkType::Regtest => Network::Regtest,
        }
    }

    /// getlotteryblockwinners [block_height]
    ///
    /// Candidates recorded in the block index at `block_height` (default and
    /// maximum: the tip), ranked against the last lottery block before it.
    pub fn get_lottery_block_winners(&self, params: &Params) -> Result<Value, Error> {
        use divi_script::extract_destinations;
        use divi_wallet::address::Address;

        if params.len() > 1 {
            return Err(
                RpcError::new(codes::MISC_ERROR, "getlotteryblockwinners [block_height]").into(),
            );
        }
        let tip = self.chain.tip().ok_or_else(|| {
            RpcError::new(codes::MISC_ERROR, "Could not acquire lock on chain tip.")
        })?;
        let height = match params.get_i64(0) {
            Some(h) => h.clamp(0, tip.height as i64) as u32,
            None => tip.height,
        };
        let index = self
            .chain
            .get_block_index_by_height(height)?
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Block not in main chain"))?;

        let (start, cycle) = self.chain.get_lottery_params();
        let last_lottery_height = start.max(cycle * (height.saturating_sub(1) / cycle));
        let last_lottery = self
            .chain
            .get_block_index_by_height(last_lottery_height)?
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Last lottery block not found"))?;

        let coinstakes = &index.lottery_winners.coinstakes;
        // C++ computeRankedScoreAwareCoinstakes: rank by score, highest first
        let mut ranked: Vec<(Hash256, Hash256)> = coinstakes
            .iter()
            .map(|c| {
                (
                    c.tx_hash,
                    divi_consensus::lottery::calculate_lottery_score(
                        &c.tx_hash,
                        &last_lottery.hash,
                    ),
                )
            })
            .collect();
        ranked.sort_by_key(|(_, score)| std::cmp::Reverse(*score));
        let network = self.address_network();

        let candidates: Vec<Value> = coinstakes
            .iter()
            .map(|cs| {
                let addresses = extract_destinations(cs.script_pubkey.as_bytes())
                    .map(|(_, dests, _)| dests)
                    .unwrap_or_default()
                    .iter()
                    .map(|d| match d {
                        divi_script::Destination::PubKeyHash(h) => {
                            let mut b = [0u8; 20];
                            b.copy_from_slice(h);
                            Address::from_pubkey_hash(Hash160::from_bytes(b), network).to_base58()
                        }
                        divi_script::Destination::ScriptHash(h) => {
                            let mut b = [0u8; 20];
                            b.copy_from_slice(h);
                            Address::p2sh(Hash160::from_bytes(b), network).to_base58()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(":");
                let (rank, score) = ranked
                    .iter()
                    .position(|(h, _)| *h == cs.tx_hash)
                    .map(|r| (r, ranked[r].1.to_string()))
                    .unwrap_or((0, String::new()));
                json!({
                    "Address": addresses,
                    "Rank": rank,
                    "Score": score.chars().take(8).collect::<String>(),
                })
            })
            .collect();

        Ok(json!({
            "Is Lottery Block": divi_consensus::lottery::is_lottery_block(height, start, cycle),
            "Block Height": height,
            "Block Hash ": index.hash.to_string(),
            "Lottery Candidates": candidates,
        }))
    }

    pub fn money_supply(&self) -> f64 {
        let Some(tip) = self.chain.tip() else {
            return 0.0;
        };
        if let Some((hash, supply)) = *self.money_supply_cache.read() {
            if hash == tip.hash {
                return supply;
            }
        }
        match self.chain.get_utxo_stats() {
            Ok(stats) => {
                let supply = stats.total_amount as f64 / 100_000_000.0;
                *self.money_supply_cache.write() = Some((tip.hash, supply));
                supply
            }
            Err(_) => 0.0,
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

    pub fn set_block_fetcher(&self, fetcher: Arc<dyn BlockFetcher>) {
        *self.block_fetcher.write() = Some(fetcher);
    }

    /// Load a block body, asking a full-history peer if it is pruned locally.
    fn load_block(
        &self,
        _hash: &Hash256,
        index: &divi_storage::block_index::BlockIndex,
        hash_str: &str,
    ) -> Result<divi_primitives::block::Block, Error> {
        let fetcher = self.block_fetcher.read().clone();
        if let Some(block) = load_block_or_fetch(&self.chain, fetcher.as_ref(), index)? {
            return Ok(block);
        }
        Err(self.missing_block_error(index, hash_str))
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

    /// Error for a block whose body is not stored: pruned vs. genuinely unknown.
    fn missing_block_error(
        &self,
        index: &divi_storage::block_index::BlockIndex,
        hash_str: &str,
    ) -> Error {
        if index.height <= self.chain.prune_height() {
            RpcError::new(
                crate::error::codes::INVALID_ADDRESS_OR_KEY,
                format!(
                    "Block not available (pruned data): {} at height {} (prune height {})",
                    hash_str,
                    index.height,
                    self.chain.prune_height()
                ),
            )
            .into()
        } else {
            RpcError::block_not_found(hash_str).into()
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

        // 0/false = hex, 1/true = JSON with txids, 2 = JSON with decoded transactions
        let verbosity = match params.get(1) {
            None | Some(Value::Null) => 1,
            Some(Value::Bool(b)) => i64::from(*b),
            Some(_) => params.get_i64(1).ok_or_else(|| {
                RpcError::invalid_params("verbosity must be 0, 1, 2, true or false")
            })?,
        };

        let index = self
            .chain
            .get_block_index(&hash)?
            .ok_or_else(|| RpcError::block_not_found(hash_str))?;

        let block = self.load_block(&hash, &index, hash_str)?;

        if verbosity <= 0 {
            // Return raw hex
            let raw = serialize(&block);
            Ok(json!(hex::encode(raw)))
        } else {
            // Return JSON object
            let confirmations = self.get_confirmations(&index);
            let txs: Vec<Value> = block
                .transactions
                .iter()
                .map(|tx| {
                    if verbosity >= 2 {
                        // Same shape as `getrawtransaction <txid> 1`
                        let mut obj = crate::wallet::tx_to_json(tx, self.address_network());
                        obj["blockhash"] = json!(hash.to_string());
                        obj["confirmations"] = json!(confirmations);
                        obj["time"] = json!(index.time);
                        obj["blocktime"] = json!(index.time);
                        obj["height"] = json!(index.height);
                        obj
                    } else {
                        json!(tx.txid().to_string())
                    }
                })
                .collect();

            let mut result = json!({
                "hash": hash.to_string(),
                "confirmations": confirmations,
                "size": serialize(&block).len(),
                "height": index.height,
                "version": index.version,
                "merkleroot": index.merkle_root.to_string(),
                "tx": txs,
                "time": index.time,
                "mediantime": self.get_median_time(&index),
                "nonce": index.nonce,
                "bits": format!("{:08x}", index.bits),
                "difficulty": bits_to_difficulty(index.bits),
                "chainwork": chainwork_to_hex(&index.chain_work),
                "acc_checkpoint": block.header.accumulator_checkpoint.to_string(),
                "nTx": block.transactions.len(),
                "previousblockhash": if index.height > 0 {
                    Some(index.prev_hash.to_string())
                } else {
                    None
                },
            });

            // Per-block supply is only known for blocks connected since the
            // field was added to the block index; omit it otherwise.
            if let Some(supply) = index.money_supply {
                result["moneysupply"] = json!(supply as f64 / 100_000_000.0);
            }

            // Add nextblockhash if on the active chain and not the tip
            if let Some(tip) = self.chain.tip().filter(|_| index.is_on_main_chain()) {
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

        let index = self
            .chain
            .get_block_index(&hash)?
            .ok_or_else(|| RpcError::block_not_found(hash_str))?;

        if !verbose {
            // Rebuild the header from the block index so pruned blocks still work; the
            // hash check guards against an index whose fields do not round-trip.
            let mut header = divi_primitives::block::BlockHeader::new();
            header.version = index.version;
            header.prev_block = index.prev_hash;
            header.merkle_root = index.merkle_root;
            header.time = index.time;
            header.bits = index.bits;
            header.nonce = index.nonce;
            if let Some(acc) = index.accumulator {
                header.accumulator_checkpoint = acc;
            }
            if divi_crypto::compute_block_hash(&header) != hash {
                let block = self
                    .chain
                    .get_block(&hash)?
                    .ok_or_else(|| self.missing_block_error(&index, hash_str))?;
                header = block.header;
            }
            let raw = serialize(&header);
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

            // Add nextblockhash if on the active chain and not the tip
            if let Some(tip) = self.chain.tip().filter(|_| index.is_on_main_chain()) {
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
        let fetcher = self.block_fetcher.read().clone();
        let tip = self.chain.tip();
        let (height, best_hash, chain_work, mediantime, difficulty) = match &tip {
            Some(t) => (
                t.height,
                t.hash.to_string(),
                chainwork_to_hex(&t.chain_work),
                self.get_median_time(t),
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
            "pruned": self.chain.prune_height() > 0,
            "pruneheight": self.chain.prune_height(),
            "winnersstripheight": self.chain.winners_strip_height(),
            "fullhistorypeers": fetcher.as_ref().map(|f| f.full_peer_count()),
            "lastblockfetch": fetcher.as_ref().and_then(|f| f.last_result()),
            // History below a snapshot base was checked only against a state this release
            // knows, not validated block by block on this node
            "snapshotbase": self.chain.snapshot_base().map(|(h, hash)| serde_json::json!({
                "height": h,
                "hash": hash.to_string(),
                "historyvalidated": false
            })),
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

    /// Get chain tips (active chain plus every known side branch)
    pub fn get_chain_tips(&self, _params: &Params) -> Result<Value, Error> {
        let tips = self
            .chain
            .get_chain_tips()
            .map_err(|e| RpcError::internal_error(e.to_string()))?;
        Ok(Value::Array(
            tips.into_iter()
                .map(|t| {
                    json!({
                        "height": t.height,
                        "hash": t.hash.to_string(),
                        "branchlen": t.branch_len,
                        "status": t.status.as_str(),
                    })
                })
                .collect(),
        ))
    }

    /// invalidateblock / reconsiderblock / reverseblocktransactions
    pub fn invalidate_block_family(&self, method: &str, params: &Params) -> Result<Value, Error> {
        let usage = || RpcError::invalid_params(format!("{} \"hash\"", method));
        if params.len() != 1 {
            return Err(usage().into());
        }
        let hash_str = params.get_str(0).ok_or_else(usage)?;
        // C++ uint256S: an unparseable hash becomes the zero hash, which is never found
        let hash = Hash256::from_hex(hash_str).unwrap_or_else(|_| Hash256::zero());
        let map_err = |e: divi_storage::StorageError| -> Error {
            match e {
                divi_storage::StorageError::BlockNotFound(_) => {
                    RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Block not found").into()
                }
                other => RpcError::database_error(other.to_string()).into(),
            }
        };
        match method {
            "invalidateblock" => self.chain.invalidate_block(&hash).map_err(map_err)?,
            "reconsiderblock" => self.chain.reconsider_block(&hash).map_err(map_err)?,
            _ => {
                // C++ reverseblocktransactions invalidates (reversing the block's
                // transactions in the coin DB) then reconsiders; the net effect on a
                // sound database is a roll-back and re-connect of the block.
                self.chain.invalidate_block(&hash).map_err(map_err)?;
                self.chain.reconsider_block(&hash).map_err(map_err)?;
            }
        }
        Ok(Value::Null)
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
                codes::MISC_ERROR,
                format!("Failed to get UTXO stats: {}", e),
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
            "bytes_serialized": stats.bytes_serialized,
            "hash_serialized": hash_serialized,
            "total_amount": total_amount_divi
        }))
    }

    // Helper methods

    /// Confirmations as C++ Divi reports them: -1 for a block that is not on
    /// the active chain (a stored side-chain block), else tip - height + 1.
    fn get_confirmations(&self, index: &divi_storage::BlockIndex) -> i64 {
        if !index.is_on_main_chain() {
            return -1;
        }
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

    fn _tx_to_json(&self, tx: &divi_primitives::transaction::Transaction) -> Value {
        let tx_bytes = serialize(tx);
        let txid = divi_crypto::hash256(&tx_bytes);

        let vin: Vec<Value> = tx
            .vin
            .iter()
            .map(|input| {
                if input.prevout.is_null() {
                    json!({
                        "coinbase": hex::encode(input.script_sig.as_bytes()),
                        "sequence": input.sequence
                    })
                } else {
                    json!({
                        "txid": input.prevout.txid.to_string(),
                        "vout": input.prevout.vout,
                        "scriptSig": {
                            "hex": hex::encode(input.script_sig.as_bytes())
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
                        "hex": hex::encode(output.script_pubkey.as_bytes())
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

    pub fn get_raw_mempool(&self, params: &Params) -> Result<Value, Error> {
        let verbose = params.get(0).and_then(|v| v.as_bool()).unwrap_or(false);
        let mempool_guard = self.mempool.read();
        let Some(ref mempool) = *mempool_guard else {
            return Ok(if verbose { json!({}) } else { json!([]) });
        };

        if verbose {
            let height = self.chain.height();
            let mut out = serde_json::Map::new();
            for info in mempool.get_tx_infos() {
                out.insert(
                    info.txid.to_string(),
                    json!({
                        "size": info.size,
                        "fee": info.fee_sat as f64 / 100_000_000.0,
                        "time": info.time,
                        "height": height,
                        "startingpriority": 0.0,
                        "currentpriority": 0.0,
                        "depends": info.depends.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
                    }),
                );
            }
            return Ok(Value::Object(out));
        }

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
            return Err(RpcError::new(codes::MISC_ERROR, "Mempool not available").into());
        };

        let success = mempool.prioritise_transaction(&txid, priority_delta, fee_delta);
        Ok(json!(success))
    }

    pub fn get_tx_out(&self, params: &Params) -> Result<Value, Error> {
        use divi_primitives::hash::Hash160;
        use divi_primitives::transaction::OutPoint;
        use divi_wallet::address::Address;
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
                        Address::from_pubkey_hash(Hash160::from_bytes(pkh), self.address_network())
                            .to_base58(),
                    )
                } else {
                    utxo.script_pubkey.extract_p2sh_hash().map(|sh| {
                        Address::p2sh(Hash160::from_bytes(sh), self.address_network()).to_base58()
                    })
                };

                let script_type = if utxo.script_pubkey.is_p2pkh() {
                    "pubkeyhash"
                } else if utxo.script_pubkey.is_p2sh() {
                    "scripthash"
                } else {
                    "nonstandard"
                };

                let mut script_obj = json!({
                    "asm": divi_script::to_asm(utxo.script_pubkey.as_bytes()),
                    "hex": hex::encode(utxo.script_pubkey.as_bytes()),
                    "type": script_type,
                });

                if let Some(addr) = address {
                    script_obj["addresses"] = json!([addr]);
                }

                Ok(json!({
                    "bestblock": best_block_hash,
                    "confirmations": confirmations,
                    "version": 1,
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
            codes::MISC_ERROR,
            "generateblock is not yet implemented - requires full mining subsystem",
        )
        .into())
    }

    pub fn set_generate(&self, _params: &Params) -> Result<Value, Error> {
        Err(RpcError::new(
            codes::MISC_ERROR,
            "setgenerate is not yet implemented - requires full mining subsystem",
        )
        .into())
    }

    pub fn decode_script(&self, params: &Params) -> Result<Value, Error> {
        use divi_crypto::hash160;
        use divi_primitives::hash::Hash160;

        use divi_script::{
            extract_destinations, extract_script_type, get_script_type_name, to_asm,
        };
        use divi_wallet::address::Address;

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

        if let Some((_stype, destinations, req_sigs)) = extract_destinations(&script_bytes) {
            result["reqSigs"] = json!(req_sigs);

            let addresses: Vec<String> = destinations
                .iter()
                .map(|dest| match dest {
                    divi_script::Destination::PubKeyHash(pkh) => {
                        let mut bytes = [0u8; 20];
                        bytes.copy_from_slice(pkh);
                        let addr = Address::from_pubkey_hash(
                            Hash160::from_bytes(bytes),
                            self.address_network(),
                        );
                        addr.to_base58()
                    }
                    divi_script::Destination::ScriptHash(sh) => {
                        let mut bytes = [0u8; 20];
                        bytes.copy_from_slice(sh);
                        let addr =
                            Address::p2sh(Hash160::from_bytes(bytes), self.address_network());
                        addr.to_base58()
                    }
                })
                .collect();

            if !addresses.is_empty() {
                result["addresses"] = json!(addresses);
            }
        }

        if type_name != "scripthash" {
            let script_hash = hash160(&script_bytes);
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(script_hash.as_ref());
            let p2sh_addr = Address::p2sh(Hash160::from_bytes(bytes), self.address_network());
            result["p2sh"] = json!(p2sh_addr.to_base58());
        }

        Ok(result)
    }

    // Address Index Commands

    /// getaddressdeltas: an address's receives and spends from the address
    /// index (Divi Core rpcmisc.cpp getaddressdeltas)
    pub fn get_address_deltas(&self, params: &Params) -> Result<Value, Error> {
        let (start, end, include_chain_info) = match params.get(0).and_then(|p| p.as_object()) {
            Some(obj) => {
                let chain_info = obj
                    .get("chainInfo")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                match (
                    obj.get("start").and_then(|v| v.as_i64()),
                    obj.get("end").and_then(|v| v.as_i64()),
                ) {
                    (Some(start), Some(end)) => {
                        if start <= 0 || end <= 0 {
                            return Err(RpcError::new(
                                codes::INVALID_ADDRESS_OR_KEY,
                                "Start and end is expected to be greater than zero",
                            )
                            .into());
                        }
                        if end < start {
                            return Err(RpcError::new(
                                codes::INVALID_ADDRESS_OR_KEY,
                                "End value is expected to be greater than start",
                            )
                            .into());
                        }
                        (start, end, chain_info)
                    }
                    _ => (0, 0, chain_info),
                }
            }
            None => (0, 0, false),
        };
        let keys = self.index_keys(params, "getaddressdeltas")?;
        let index = self.address_index()?;
        let mut deltas = Vec::new();
        for (address_type, hash) in &keys {
            for (key, satoshis) in
                index.read_deltas(*address_type, hash, start as u32, end as u32)?
            {
                deltas.push(json!({
                    "satoshis": satoshis,
                    "txid": key.txid.to_string(),
                    "index": key.index,
                    "blockindex": key.tx_index,
                    "height": key.height,
                    "address": self.index_address(key.address_type, &key.hash),
                }));
            }
        }
        if include_chain_info && start > 0 && end > 0 {
            let height = i64::from(self.chain.height());
            if start > height || end > height {
                return Err(RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    "Start or end is outside chain range",
                )
                .into());
            }
            let hash_at = |h: i64| -> Result<String, Error> {
                Ok(self
                    .chain
                    .get_block_index_by_height(h as u32)?
                    .map(|i| i.hash.to_string())
                    .unwrap_or_default())
            };
            return Ok(json!({
                "deltas": deltas,
                "start": {"hash": hash_at(start)?, "height": start},
                "end": {"hash": hash_at(end)?, "height": end},
            }));
        }
        Ok(json!(deltas))
    }

    /// getaddresstxids: the txids touching the addresses, one per (height,
    /// txid); for several addresses ordered by height then txid (Divi Core
    /// rpcmisc.cpp getaddresstxids)
    pub fn get_address_txids(&self, params: &Params) -> Result<Value, Error> {
        let keys = self.index_keys(params, "getaddresstxids")?;
        let (start, end) = params
            .get(0)
            .and_then(|p| p.as_object())
            .and_then(|obj| Some((obj.get("start")?.as_i64()?, obj.get("end")?.as_i64()?)))
            .filter(|(start, end)| *start > 0 && *end > 0)
            .unwrap_or((0, 0));
        let index = self.address_index()?;
        let mut seen = std::collections::BTreeSet::new();
        let mut result = Vec::new();
        for (address_type, hash) in &keys {
            for (key, _) in index.read_deltas(*address_type, hash, start as u32, end as u32)? {
                let txid = key.txid.to_string();
                if seen.insert((key.height, txid.clone())) && keys.len() == 1 {
                    result.push(txid);
                }
            }
        }
        if keys.len() > 1 {
            result = seen.into_iter().map(|(_, txid)| txid).collect();
        }
        Ok(json!(result))
    }

    /// getaddressbalance: the sum of the addresses' deltas, and of the
    /// receives alone (Divi Core rpcmisc.cpp getaddressbalance)
    pub fn get_address_balance(&self, params: &Params) -> Result<Value, Error> {
        let keys = self.index_keys(params, "getaddressbalance")?;
        let index = self.address_index()?;
        let (mut balance, mut received) = (0i64, 0i64);
        for (address_type, hash) in &keys {
            for (_, satoshis) in index.read_deltas(*address_type, hash, 0, 0)? {
                if satoshis > 0 {
                    received += satoshis;
                }
                balance += satoshis;
            }
        }
        Ok(json!({"balance": balance, "received": received}))
    }

    /// getaddressutxos: the addresses' unspent outputs by height (Divi Core
    /// rpcmisc.cpp getaddressutxos)
    pub fn get_address_utxos(&self, params: &Params) -> Result<Value, Error> {
        let include_chain_info = params
            .get(0)
            .and_then(|p| p.as_object())
            .and_then(|obj| obj.get("chainInfo"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let keys = self.index_keys(params, "getaddressutxos")?;
        let index = self.address_index()?;
        let mut unspent = Vec::new();
        for (address_type, hash) in &keys {
            unspent.extend(index.read_unspent(*address_type, hash)?);
        }
        unspent.sort_by_key(|(_, value)| value.height);
        let utxos: Vec<Value> = unspent
            .iter()
            .map(|(key, value)| {
                json!({
                    "address": self.index_address(key.address_type, &key.hash),
                    "txid": key.txid.to_string(),
                    "outputIndex": key.index,
                    "script": hex::encode(value.script.as_bytes()),
                    "satoshis": value.satoshis,
                    "height": value.height,
                })
            })
            .collect();
        if include_chain_info {
            let tip = self.chain.tip();
            return Ok(json!({
                "utxos": utxos,
                "hash": tip.as_ref().map(|t| t.hash.to_string()).unwrap_or_default(),
                "height": self.chain.height(),
            }));
        }
        Ok(json!(utxos))
    }

    /// getspentinfo: the input that spent an output, from the spent index
    /// (Divi Core rpcmisc.cpp getspentinfo)
    pub fn get_spent_info(&self, params: &Params) -> Result<Value, Error> {
        // Parse parameters - expect object with txid and index
        let param = params
            .get(0)
            .ok_or_else(|| RpcError::invalid_params("Missing parameter"))?;

        let Some(obj) = param.as_object() else {
            return Err(RpcError::invalid_params(
                "Parameter must be an object with 'txid' and 'index' fields",
            )
            .into());
        };
        let txid_str = obj
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::invalid_params("Missing or invalid 'txid' field"))?;
        let txid = parse_hash(txid_str)?;
        let index = obj
            .get("index")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| RpcError::invalid_params("Missing or invalid 'index' field"))?;

        let search = match self.chain.search_index() {
            Some(search) if search.spent_enabled() => search,
            _ => return Err(self.address_index_not_enabled()),
        };
        match search.read_spent(&divi_storage::SpentIndexKey::new(txid, index as u32))? {
            Some(value) => Ok(json!({
                "txid": value.spending_txid.to_string(),
                "index": value.input_index,
                "height": value.block_height,
            })),
            None => {
                Err(RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Unable to get spent info").into())
            }
        }
    }

    /// The address index, or the error for a node without it
    fn address_index(&self) -> Result<&Arc<divi_storage::SearchIndex>, Error> {
        match self.chain.search_index() {
            Some(search) if search.address_enabled() => Ok(search),
            _ => Err(self.address_index_not_enabled()),
        }
    }

    /// Divi Core getAddressesFromParams/GetIndexKey: the address type and hash
    /// each address is indexed under. With the second parameter (only vaults)
    /// true, a key-hash address names the vaults it owns (type 3) and a
    /// script-hash address is refused.
    fn index_keys(&self, params: &Params, method: &str) -> Result<Vec<(u8, [u8; 20])>, Error> {
        use divi_wallet::address::{Address, AddressType};
        let addresses = self.parse_address_index_params(params, method)?;
        self.check_index_addresses(&addresses)?;
        let only_vaults =
            params.len() == 2 && params.get(1).and_then(|v| v.as_bool()) == Some(true);
        addresses
            .iter()
            .map(|a| {
                let address = Address::from_base58_for_network(a, self.address_network())
                    .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;
                let hash = *address.hash.as_bytes();
                match (address.addr_type, only_vaults) {
                    (AddressType::P2SH, true) => {
                        Err(RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address").into())
                    }
                    (_, true) => Ok((3, hash)),
                    (AddressType::P2PKH, false) => Ok((1, hash)),
                    (AddressType::P2SH, false) => Ok((2, hash)),
                }
            })
            .collect()
    }

    /// Divi Core getAddressFromIndex: the address of an index entry
    fn index_address(&self, address_type: u8, hash: &[u8; 20]) -> String {
        use divi_wallet::address::Address;
        let hash = Hash160::from_bytes(*hash);
        if address_type == 2 {
            Address::p2sh(hash, self.address_network()).to_base58()
        } else {
            Address::from_pubkey_hash(hash, self.address_network()).to_base58()
        }
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

    /// Divi Core getAddressesFromParams: every address must decode for this
    /// node's network, else -5 "Invalid address"
    fn check_index_addresses(&self, addresses: &[String]) -> Result<(), Error> {
        use divi_wallet::address::Address;
        for a in addresses {
            Address::from_base58_for_network(a, self.address_network())
                .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;
        }
        Ok(())
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

                    // An empty array names no address and gets an empty
                    // reply (Divi Core rpcmisc.cpp:580-589)
                    if addrs.len() != arr.len() {
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

    /// `len` regtest PoW blocks on genesis (heights <= 100 are PoW on regtest).
    fn pow_chain(
        chain: &Chain,
        len: u32,
        seed: u8,
        time_offset: u32,
    ) -> Vec<divi_primitives::block::Block> {
        use divi_primitives::amount::Amount;
        use divi_primitives::block::Block;
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{Transaction, TxIn, TxOut};
        let genesis = chain.tip().unwrap();
        let (mut prev, mut t) = (genesis.hash, genesis.time + time_offset);
        let mut out = Vec::new();
        for h in 1..=len {
            t += 60;
            // BIP34 height, then height and seed
            let mut tag = divi_storage::bip34_height_script(h);
            tag.push(0x05);
            tag.extend_from_slice(&h.to_le_bytes());
            tag.push(seed);
            let mut block = Block::default();
            block.header.version = 4;
            block.header.prev_block = prev;
            block.header.time = t;
            block.header.bits = 0x207fffff;
            block.transactions.push(Transaction {
                version: 1,
                vin: vec![TxIn::coinbase(Script::from_bytes(tag))],
                vout: vec![TxOut::new(
                    Amount::from_sat(1250_00000000),
                    Script::default(),
                )],
                lock_time: 0,
            });
            block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
            // Proof of work for the block's bits
            let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
            while divi_crypto::compute_block_hash(&block.header) > target {
                block.header.nonce += 1;
            }
            prev = divi_crypto::compute_block_hash(&block.header);
            out.push(block);
        }
        out
    }

    fn header_of(rpc: &BlockchainRpc, hash: Hash256) -> Value {
        rpc.get_block_header(&Params::Array(vec![json!(hash.to_string())]))
            .unwrap()
    }

    #[test]
    fn test_invalidate_reconsider_rpc() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(divi_storage::ChainDatabase::open(dir.path()).unwrap());
        let params = divi_storage::ChainParams::for_network(
            NetworkType::Regtest,
            divi_primitives::ChainMode::Divi,
        );
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let a = pow_chain(&chain, 3, 0xA1, 0);
        for blk in &a {
            chain.accept_block(blk.clone()).unwrap();
        }
        let rpc = BlockchainRpc::new(chain.clone());
        let h2 = divi_crypto::compute_block_hash(&a[1].header).to_string();
        let p = |s: &str| Params::Array(vec![json!(s)]);

        assert_eq!(
            rpc.invalidate_block_family("invalidateblock", &p(&h2))
                .unwrap(),
            Value::Null
        );
        assert_eq!(chain.height(), 1);
        assert_eq!(
            rpc.invalidate_block_family("reconsiderblock", &p(&h2))
                .unwrap(),
            Value::Null
        );
        assert_eq!(chain.height(), 3);
        assert_eq!(
            rpc.invalidate_block_family("reverseblocktransactions", &p(&h2))
                .unwrap(),
            Value::Null
        );
        assert_eq!(chain.height(), 3);

        let missing = "aa".repeat(32);
        let err = rpc
            .invalidate_block_family("invalidateblock", &p(&missing))
            .unwrap_err();
        assert!(err.to_string().contains("Block not found"));
        assert!(rpc
            .invalidate_block_family("invalidateblock", &Params::None)
            .is_err());
    }

    #[test]
    fn test_getblockheader_confirmations_minus_one_off_main_chain() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(divi_storage::ChainDatabase::open(dir.path()).unwrap());
        let params = divi_storage::ChainParams::for_network(
            NetworkType::Regtest,
            divi_primitives::ChainMode::Divi,
        );
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let a = pow_chain(&chain, 3, 0xA1, 0);
        let b = pow_chain(&chain, 4, 0xB2, 1);
        let hash =
            |blk: &divi_primitives::block::Block| divi_crypto::compute_block_hash(&blk.header);
        for blk in a.iter().chain(b[..2].iter()) {
            chain.accept_block(blk.clone()).unwrap();
        }
        let rpc = BlockchainRpc::new(chain.clone());
        assert_eq!(chain.height(), 3);

        // Active chain A: tip has 1 confirmation, A1 has 3.
        assert_eq!(header_of(&rpc, hash(&a[2]))["confirmations"], json!(1));
        assert_eq!(header_of(&rpc, hash(&a[0]))["confirmations"], json!(3));
        assert_eq!(
            header_of(&rpc, hash(&a[0]))["nextblockhash"],
            json!(hash(&a[1]).to_string())
        );
        // Side chain B (stored, not active): -1, and no nextblockhash.
        let b1 = header_of(&rpc, hash(&b[0]));
        assert_eq!(b1["confirmations"], json!(-1));
        assert!(
            b1.get("nextblockhash").is_none(),
            "side-chain block got {}",
            b1
        );
        assert_eq!(header_of(&rpc, hash(&b[1]))["confirmations"], json!(-1));
        assert_eq!(
            rpc.get_block(&Params::Array(vec![json!(hash(&b[0]).to_string())]))
                .unwrap()["confirmations"],
            json!(-1)
        );

        // B out-works A: the roles flip.
        chain.accept_block(b[2].clone()).unwrap();
        chain.accept_block(b[3].clone()).unwrap();
        assert_eq!(chain.height(), 4);
        assert_eq!(header_of(&rpc, hash(&b[0]))["confirmations"], json!(4));
        assert_eq!(header_of(&rpc, hash(&a[0]))["confirmations"], json!(-1));
    }
}
