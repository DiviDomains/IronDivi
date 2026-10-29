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

//! Blockchain RPC methods
//!
//! Methods for querying blockchain state: blocks, transactions, chain info.

use crate::error::{codes, Error, RpcError};
use crate::lite_wallet::MAX_PAGE;
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
    /// The mempool's side of invalidateblock and its family
    reorg_hook: RwLock<Option<ReorgHook>>,
    /// Money supply cached against the tip hash it was computed for
    money_supply_cache: RwLock<Option<(Hash256, f64)>>,
    /// Fetches blocks this node has pruned from full-history peers
    block_fetcher: RwLock<Option<Arc<dyn BlockFetcher>>>,
    block_sync: RwLock<Option<Arc<divi_network::BlockSync>>>,
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
    /// Chain height when the transaction entered the pool
    pub height: u32,
    /// Coin-age priority when it entered, and at the current height
    pub starting_priority: f64,
    pub current_priority: f64,
}

/// Fee estimation result
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    /// Fee rate in DIVI per kilobyte
    pub fee_rate: f64,
    /// Number of blocks used for estimation
    pub blocks: u32,
}

/// Takes the transactions of blocks `invalidateblock` or
/// `reverseblocktransactions` disconnected back into the mempool and drops
/// what the chain now spends (called with none after `reconsiderblock`)
pub type ReorgHook = Arc<dyn Fn(Vec<divi_primitives::transaction::Transaction>) + Send + Sync>;

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

    /// The highest fee sendrawtransaction takes without allowhighfees
    /// (-maxtxfee; Divi Core's DEFAULT_TRANSACTION_MAXFEE, defaultValues.h:34)
    fn max_tx_fee(&self) -> divi_primitives::amount::Amount {
        divi_primitives::amount::Amount::from_sat(100 * 100_000_000)
    }

    /// Estimate fee for confirmation within target blocks
    fn estimate_fee(&self, _conf_target: u32) -> f64 {
        0.0001 // Divi Core's default relay floor, 10000 sat/kB
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
///
/// The stored genesis index has no work of its own, so every stored value is
/// one genesis proof short of Divi Core's nChainWork (which counts the genesis
/// block); `genesis_bits` adds it back for display only.
fn chainwork_to_hex(chain_work: &[u8; 32], genesis_bits: u32) -> String {
    let genesis = divi_consensus::get_block_proof(genesis_bits);
    let mut sum = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = chain_work[i] as u16 + genesis[i] as u16 + carry;
        sum[i] = v as u8;
        carry = v >> 8;
    }
    sum.reverse();
    hex::encode(sum)
}

impl BlockchainRpc {
    /// Divi Core's chainwork for a stored block index
    fn chainwork(&self, index: &divi_storage::BlockIndex) -> String {
        let genesis_bits = self
            .chain
            .get_block_index_by_height(0)
            .ok()
            .flatten()
            .map_or(index.bits, |g| g.bits);
        chainwork_to_hex(&index.chain_work, genesis_bits)
    }

    /// Current chain tip height
    pub fn tip_height(&self) -> i32 {
        self.chain.height() as i32
    }

    /// Create new blockchain RPC handler
    pub fn new(chain: Arc<Chain>) -> Self {
        BlockchainRpc {
            chain,
            mempool: RwLock::new(None),
            reorg_hook: RwLock::new(None),
            money_supply_cache: RwLock::new(None),
            block_fetcher: RwLock::new(None),
            block_sync: RwLock::new(None),
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
        // params[0].get_int(): json_spirit takes only an integer
        // (rpclottery.cpp:47); divid has no answer for a height below 0 (it
        // reads a null block), irondivid gives genesis's
        let height = match params.get(0) {
            Some(Value::Number(n)) if n.is_i64() || n.is_u64() => {
                n.as_i64().unwrap_or(i64::MAX).clamp(0, tip.height as i64) as u32
            }
            Some(v) => return Err(json_spirit_type_error(Some(v), "int").into()),
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

    /// The tip's money supply, as Divi Core's getinfo reports it
    /// (`chain.Tip()->nMoneySupply`, rpcmisc.cpp:152). A tip without a
    /// recorded supply (the chain opened before it was filled in) gets it from
    /// the UTXO set, which holds the same value.
    pub fn money_supply(&self) -> f64 {
        let Some(tip) = self.chain.tip() else {
            return 0.0;
        };
        if let Some(supply) = tip.money_supply.or((tip.height == 0).then_some(0)) {
            return supply as f64 / 100_000_000.0;
        }
        if let Some((hash, supply)) = *self.money_supply_cache.read() {
            if hash == tip.hash {
                return supply;
            }
        }
        match self.chain.utxo_value_total() {
            Ok(total) => {
                let supply = total as f64 / 100_000_000.0;
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

    /// Set what invalidateblock, reconsiderblock and reverseblocktransactions
    /// do to the mempool
    pub fn set_reorg_hook(&self, hook: ReorgHook) {
        *self.reorg_hook.write() = Some(hook);
    }

    /// The minimum relay fee in DIVI/kB that getinfo and getnetworkinfo
    /// report (Divi Core's getMinimumRelayFeeRate, -minrelaytxfee)
    pub fn relay_fee(&self) -> f64 {
        match self.mempool.read().as_ref() {
            Some(mempool) => mempool.get_stats().min_fee,
            None => 0.0001,
        }
    }

    pub fn set_block_fetcher(&self, fetcher: Arc<dyn BlockFetcher>) {
        *self.block_fetcher.write() = Some(fetcher);
    }

    /// Let `getblockchaininfo` report the headers the sync holds
    pub fn set_block_sync(&self, sync: Arc<divi_network::BlockSync>) {
        *self.block_sync.write() = Some(sync);
    }

    /// Divi Core's GetBestHeaderBlockHeight: the best header's height, never
    /// below the tip
    fn best_header_height(&self, height: u32) -> u32 {
        match self.block_sync.read().as_ref() {
            Some(sync) => sync.best_header_height().max(height),
            None => height,
        }
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
        // params[0].get_int(): json_spirit takes only an integer
        let height = match params.get(0) {
            Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.as_i64().unwrap_or(i64::MAX),
            Some(v) => {
                return Err(RpcError::new(
                    crate::error::codes::MISC_ERROR,
                    format!(
                        "value is type {}, expected int",
                        crate::wallet::json_spirit_type(v)
                    ),
                )
                .into())
            }
            None => return Err(RpcError::invalid_params("Missing height parameter").into()),
        };

        // Divi Core: a height below 0 or above the tip is out of range
        // (rpcblockchain.cpp:168-170)
        let out_of_range =
            || RpcError::new(codes::INVALID_PARAMETER, "Block height out of range").into();
        if height < 0 || height > i64::from(self.chain.height()) {
            return Err(out_of_range());
        }
        match self.chain.get_block_index_by_height(height as u32)? {
            Some(index) => Ok(json!(index.hash.to_string())),
            None => Err(out_of_range()),
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

        let hash = block_hash_like_core(hash_str)?;

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
                "chainwork": self.chainwork(&index),
                "acc_checkpoint": block.header.accumulator_checkpoint.to_string(),
                "nTx": block.transactions.len(),
            });
            // The genesis block has no previousblockhash key (JsonBlockHelpers.cpp:68)
            if index.height > 0 {
                result["previousblockhash"] = json!(index.prev_hash.to_string());
            }

            // Per-block supply is only known for blocks connected since the
            // field was added to the block index; omit it otherwise. The
            // genesis block's supply is 0.
            let supply = index.money_supply.or((index.height == 0).then_some(0));
            if let Some(supply) = supply {
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

        let hash = block_hash_like_core(hash_str)?;
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
                "chainwork": self.chainwork(&index),
                "nTx": index.n_tx,
            });
            if index.height > 0 {
                result["previousblockhash"] = json!(index.prev_hash.to_string());
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

    /// Get blockchain info
    pub fn get_blockchain_info(&self, _params: &Params) -> Result<Value, Error> {
        let fetcher = self.block_fetcher.read().clone();
        let tip = self.chain.tip();
        let (height, best_hash, chain_work, mediantime, difficulty) = match &tip {
            Some(t) => (
                t.height,
                t.hash.to_string(),
                self.chainwork(t),
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

        let headers = self.best_header_height(height);

        Ok(json!({
            "chain": match self.chain.network_type() {
                NetworkType::Mainnet => "main",
                NetworkType::Testnet => "test",
                NetworkType::Regtest => "regtest",
            },
            "blocks": height,
            "headers": headers,
            "bestblockhash": best_hash,
            "difficulty": difficulty,
            "mediantime": mediantime,
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
            "protocolversion": divi_network::constants::protocol_version(),
            "blocks": height,
            "timeoffset": 0,
            "connections": 0,
            "proxy": "",
            "difficulty": difficulty,
            "testnet": matches!(self.chain.network_type(), NetworkType::Testnet),
            "moneysupply": self.money_supply(),
            "keypoololdest": 0,
            "keypoolsize": 0,
            "paytxfee": 0.0,
            "relayfee": self.relay_fee(),
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
        // As Divi Core reads it, uint256(strHash) or uint256S: leading space
        // and "0x" skipped, a short hash read as a number, text without
        // digits the zero hash, which is never found (rpcblockchain.cpp:589,
        // :625, :663)
        let hash = crate::wallet::uint256_set_hex(hash_str);
        let map_err = |e: divi_storage::StorageError| -> Error {
            match e {
                divi_storage::StorageError::BlockNotFound(_) => {
                    RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Block not found").into()
                }
                other => RpcError::database_error(other.to_string()).into(),
            }
        };
        // The disconnected blocks' transactions go back to the mempool, as
        // Divi Core's disconnectTip puts them back; after a reconsider the
        // mempool drops what the chain now holds
        let returned = match method {
            "invalidateblock" => self.chain.invalidate_block(&hash).map_err(map_err)?,
            "reconsiderblock" => {
                self.chain.reconsider_block(&hash).map_err(map_err)?;
                Vec::new()
            }
            // C++ reverseblocktransactions invalidates (reversing the block's
            // transactions in the coin DB) then clears the invalid mark
            // without moving the tip, which stays at the block's parent
            // until another block comes (rpcblockchain.cpp:577-603)
            _ => self
                .chain
                .reverse_block_transactions(&hash)
                .map_err(map_err)?,
        };
        if let Some(hook) = self.reorg_hook.read().clone() {
            hook(returned);
        }
        Ok(Value::Null)
    }

    /// getinvalid ( "all" ): Divi Core 3.0.0 builds its summary from empty
    /// maps, so it is always empty (rpcblockchain.cpp:687-725); at most one
    /// argument, a string
    pub fn get_invalid(&self, params: &Params) -> Result<Value, Error> {
        crate::core_help::check_arguments("getinvalid", params, (0, 1), 1)?;
        Ok(json!([{
            "addresses_with_invalid": {},
            "total_unspent": "0.00",
            "total_minted": "0.00",
            "total_valid_used": "0.00",
        }]))
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
    ///
    /// Divi Core rpcblockchain.cpp:293-327: height, best block and every value
    /// from one view of the UTXO set; bytes_serialized and hash_serialized over
    /// Core's coin records (txdb.cpp:105-157). bogosize (irondivid only) is the
    /// size of irondivid's own records.
    pub fn get_txout_set_info(&self, _params: &Params) -> Result<Value, Error> {
        let stats = self.chain.get_utxo_stats().map_err(|e| {
            RpcError::new(
                codes::MISC_ERROR,
                format!("Failed to get UTXO stats: {}", e),
            )
        })?;

        let total_amount_divi = stats.total_amount as f64 / 100_000_000.0;

        Ok(json!({
            "height": stats.height,
            "bestblock": stats.best_block.to_string(),
            "transactions": stats.transactions,
            "txouts": stats.txouts,
            "bogosize": stats.bogosize,
            "bytes_serialized": stats.bytes_serialized,
            "hash_serialized": stats.hash_serialized.to_string(),
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
        // params[0].get_bool(): json_spirit takes only a boolean
        // (rpcblockchain.cpp:110-112)
        let verbose = match params.get(0) {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(v) => {
                return Err(RpcError::new(
                    crate::error::codes::MISC_ERROR,
                    format!(
                        "value is type {}, expected bool",
                        crate::wallet::json_spirit_type(v)
                    ),
                )
                .into())
            }
        };
        let mempool_guard = self.mempool.read();
        let Some(ref mempool) = *mempool_guard else {
            return Ok(if verbose { json!({}) } else { json!([]) });
        };

        if verbose {
            // Divi Core rpcblockchain.cpp:122-128
            let mut out = serde_json::Map::new();
            for info in mempool.get_tx_infos() {
                out.insert(
                    info.txid.to_string(),
                    json!({
                        "size": info.size,
                        "fee": info.fee_sat as f64 / 100_000_000.0,
                        "time": info.time,
                        "height": info.height,
                        "startingpriority": info.starting_priority,
                        "currentpriority": info.current_priority,
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

    /// prioritisetransaction as Divi Core (rpcmining.cpp:251-276): the txid
    /// through ParseHashStr, the fee delta as an integer; the priority delta
    /// is not read, and the answer is always true
    pub fn prioritise_transaction(&self, params: &Params) -> Result<Value, Error> {
        let txid = match params.get(0) {
            Some(Value::String(s)) => core_parse_hash_str(s, "txid")?,
            v => return Err(json_spirit_type_error(v, "str").into()),
        };
        let fee_delta = match params.get(2) {
            Some(Value::Number(n)) if n.is_i64() => n.as_i64().unwrap_or_default(),
            v => return Err(json_spirit_type_error(v, "int").into()),
        };

        let mempool_guard = self.mempool.read();
        let Some(ref mempool) = *mempool_guard else {
            return Err(RpcError::new(codes::MISC_ERROR, "Mempool not available").into());
        };

        // Core's PrioritiseTransaction takes the fee delta only (txmempool.cpp:318-328)
        mempool.prioritise_transaction(&txid, 0.0, fee_delta);
        Ok(json!(true))
    }

    /// gettxout as Divi Core (rpcblockchain.cpp:330-402): null for an output
    /// that is spent or unknown; with includemempool (default) an output spent
    /// in the mempool is null and a mempool transaction's output has 0
    /// confirmations
    pub fn get_tx_out(&self, params: &Params) -> Result<Value, Error> {
        use divi_primitives::transaction::OutPoint;
        // params[0].get_str(), params[1].get_int() and params[2].get_bool():
        // json_spirit takes only a string, an integer and a boolean
        // (rpcblockchain.cpp:366-371)
        let type_error = |v: &Value, want: &str| -> Error {
            RpcError::new(
                codes::MISC_ERROR,
                format!(
                    "value is type {}, expected {want}",
                    crate::wallet::json_spirit_type(v)
                ),
            )
            .into()
        };
        let txid_str = match params.get(0) {
            Some(Value::String(t)) => t.as_str(),
            Some(v) => return Err(type_error(v, "str")),
            None => return Err(RpcError::invalid_params("Missing txid parameter").into()),
        };
        let vout = match params.get(1) {
            Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.as_i64().unwrap_or(i64::MAX),
            Some(v) => return Err(type_error(v, "int")),
            None => return Err(RpcError::invalid_params("Missing vout parameter").into()),
        };
        let include_mempool = match params.get(2) {
            None => true,
            Some(Value::Bool(b)) => *b,
            Some(v) => return Err(type_error(v, "bool")),
        };

        // `uint256 hash(strHash)`: text that is not a hash names no transaction
        let Ok(txid) = Hash256::from_hex(txid_str) else {
            return Ok(Value::Null);
        };
        if vout < 0 || vout > u32::MAX as i64 {
            return Ok(Value::Null);
        }
        let outpoint = OutPoint::new(txid, vout as u32);
        let mempool = self.mempool.read().clone().filter(|_| include_mempool);

        if mempool.as_ref().is_some_and(|m| m.is_spent(&outpoint)) {
            return Ok(Value::Null);
        }
        let best_block_hash = match self.chain.tip() {
            Some(tip) => tip.hash.to_string(),
            None => Hash256::zero().to_string(),
        };
        let network = self.address_network();
        // Divi Core keeps no OP_META output in its coins (CCoins::ClearUnspendable,
        // coins.cpp:54-61), from a block or from the mempool, so gettxout gives null
        if let Some(utxo) = self.chain.get_utxo(&outpoint)? {
            if utxo.script_pubkey.is_op_return() {
                return Ok(Value::Null);
            }
            let confirmations = self.chain.height().saturating_sub(utxo.height) + 1;
            return Ok(json!({
                "bestblock": best_block_hash,
                "confirmations": confirmations,
                "value": utxo.value.as_divi_f64(),
                "scriptPubKey": crate::wallet::script_pubkey_to_json(utxo.script_pubkey.as_bytes(), network, true),
                "version": utxo.version,
                "coinbase": utxo.is_coinbase,
                "coinstake": utxo.is_coinstake,
            }));
        }
        let in_pool = mempool.and_then(|m| m.get_transaction(&txid));
        if let Some(tx) = in_pool {
            if let Some(out) = tx
                .vout
                .get(outpoint.vout as usize)
                .filter(|o| !o.script_pubkey.is_op_return())
            {
                return Ok(json!({
                    "bestblock": best_block_hash,
                    "confirmations": 0,
                    "value": out.value.as_divi_f64(),
                    "scriptPubKey": crate::wallet::script_pubkey_to_json(out.script_pubkey.as_bytes(), network, true),
                    "version": tx.version,
                    "coinbase": false,
                    "coinstake": false,
                }));
            }
        }
        Ok(Value::Null)
    }

    /// decodescript as Divi Core (rpcrawtransaction.cpp:527-564): the script
    /// fields of ScriptPubKeyToJSON without hex, then the script's P2SH address
    pub fn decode_script(&self, params: &Params) -> Result<Value, Error> {
        use divi_crypto::hash160;
        use divi_primitives::hash::Hash160;
        use divi_wallet::address::Address;

        let hex_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing hex parameter"))?;

        // Empty scripts are valid; anything else must be hex (ParseHexV "argument")
        let script_bytes = if hex_str.is_empty() {
            Vec::new()
        } else {
            crate::wallet::parse_hex_v(hex_str, "argument")?
        };

        let mut result =
            crate::wallet::script_pubkey_to_json(&script_bytes, self.address_network(), false);
        // IronDivi also echoes the script hex
        result["hex"] = json!(hex_str);
        let script_hash = hash160(&script_bytes);
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(script_hash.as_ref());
        let p2sh_addr = Address::p2sh(Hash160::from_bytes(bytes), self.address_network());
        result["p2sh"] = json!(p2sh_addr.to_base58());

        Ok(result)
    }

    // Address Index Commands

    /// getaddressdeltas: an address's receives and spends from the address
    /// index (Divi Core rpcmisc.cpp getaddressdeltas)
    pub fn get_address_deltas(&self, params: &Params) -> Result<Value, Error> {
        Self::address_call_arity(params, "getaddressdeltas")?;
        let (start, end, include_chain_info) = match params.get(0).and_then(|p| p.as_object()) {
            Some(obj) => {
                let chain_info = obj
                    .get("chainInfo")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                match (
                    obj.get("start").and_then(json_spirit_int),
                    obj.get("end").and_then(json_spirit_int),
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
        let keys = self.index_keys(params)?;
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
        Self::address_call_arity(params, "getaddresstxids")?;
        let keys = self.index_keys(params)?;
        let (start, end) = params
            .get(0)
            .and_then(|p| p.as_object())
            .and_then(|obj| {
                Some((
                    json_spirit_int(obj.get("start")?)?,
                    json_spirit_int(obj.get("end")?)?,
                ))
            })
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
        Self::address_call_arity(params, "getaddressbalance")?;
        let keys = self.index_keys(params)?;
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
        Self::address_call_arity(params, "getaddressutxos")?;
        let include_chain_info = params
            .get(0)
            .and_then(|p| p.as_object())
            .and_then(|obj| obj.get("chainInfo"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // A page of the outputs, oldest first: "skip" and "limit" in the
        // object form, at most MAX_PAGE (the default) per call
        let page = |key: &str| {
            params
                .get(0)
                .and_then(|p| p.as_object())
                .and_then(|obj| obj.get(key))
                .and_then(json_spirit_int)
                .map(|n| n.max(0) as usize)
        };
        let skip = page("skip").unwrap_or(0);
        let limit = page("limit").map_or(MAX_PAGE, |l| l.min(MAX_PAGE));
        let keys = self.index_keys(params)?;
        let index = self.address_index()?;
        let mut unspent = Vec::new();
        for (address_type, hash) in &keys {
            unspent.extend(index.read_unspent(*address_type, hash)?);
        }
        unspent.sort_by_key(|(_, value)| value.height);
        let utxos: Vec<Value> = unspent
            .iter()
            .skip(skip)
            .take(limit)
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
    /// (Divi Core rpcmisc.cpp:878-926): one object argument, else -1 with the
    /// help text; a string txid and an integer index, else -5 "Invalid txid or
    /// index"; the txid read as ParseHashV reads it; an output the spent index
    /// has no entry for, or a node without the index, -5 "Unable to get spent
    /// info"
    pub fn get_spent_info(&self, params: &Params) -> Result<Value, Error> {
        let obj = match (params.len(), params.get(0)) {
            (1, Some(Value::Object(obj))) => obj,
            _ => return Err(RpcError::invalid_params("getspentinfo {txid:,index:}").into()),
        };
        let (txid, index) = match (obj.get("txid"), obj.get("index").and_then(json_spirit_int)) {
            (Some(Value::String(txid)), Some(index)) => (txid.as_str(), index),
            _ => {
                return Err(
                    RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid txid or index").into(),
                )
            }
        };
        // ParseHashV (JsonParseHelpers.cpp:5-15): ParseHashStr's reading, -8
        let txid = core_parse_hash_str(txid, "txid")
            .map_err(|e| RpcError::new(codes::INVALID_PARAMETER, e.message))?;
        let not_found = || -> Error {
            RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Unable to get spent info").into()
        };
        // GetSpentIndex failing without the index (TransactionSearchIndexes.cpp:43-44)
        let search = match self.chain.search_index() {
            Some(search) if search.spent_enabled() => search,
            _ => return Err(not_found()),
        };
        // The index is an int, kept as the key's unsigned 32 bits
        match search.read_spent(&divi_storage::SpentIndexKey::new(txid, index as u32))? {
            Some(value) => Ok(json!({
                "txid": value.spending_txid.to_string(),
                "index": value.input_index,
                "height": value.block_height,
            })),
            None => Err(not_found()),
        }
    }

    /// The address index, or the error for a node without it
    fn address_index(&self) -> Result<&Arc<divi_storage::SearchIndex>, Error> {
        match self.chain.search_index() {
            Some(search) if search.address_enabled() => Ok(search),
            _ => Err(self.address_index_not_enabled()),
        }
    }

    /// Divi Core getAddressesFromParams (rpcmisc.cpp:563-595): the index key of
    /// each address. `only_vaults` is read first, with json_spirit's type check;
    /// then one address, or an object whose "addresses" must be a list of
    /// strings; an address that does not decode for this network (or a P2SH one
    /// with only_vaults) is -5 "Invalid address", as is any other first argument
    fn index_keys(&self, params: &Params) -> Result<Vec<(u8, [u8; 20])>, Error> {
        let only_vaults = match (params.len(), params.get(1)) {
            (2, Some(Value::Bool(b))) => *b,
            (2, v) => return Err(json_spirit_type_error(v, "bool").into()),
            _ => false,
        };
        let invalid =
            || -> Error { RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address").into() };
        let addresses: Vec<&str> = match params.get(0) {
            Some(Value::String(a)) => vec![a.as_str()],
            Some(Value::Object(obj)) => match obj.get("addresses") {
                Some(Value::Array(list)) => {
                    let mut out = Vec::with_capacity(list.len());
                    for v in list {
                        match v {
                            Value::String(a) => out.push(a.as_str()),
                            other => return Err(json_spirit_type_error(Some(other), "str").into()),
                        }
                    }
                    out
                }
                _ => {
                    return Err(RpcError::new(
                        codes::INVALID_ADDRESS_OR_KEY,
                        "Addresses is expected to be an array",
                    )
                    .into())
                }
            },
            _ => return Err(invalid()),
        };
        addresses
            .iter()
            .map(|a| self.index_key(a, only_vaults).ok_or_else(invalid))
            .collect()
    }

    /// Divi Core GetIndexKey (rpcmisc.cpp:543-561): an address's type (1 P2PKH,
    /// 2 P2SH, 3 for a vault search) and hash, or None
    fn index_key(&self, address: &str, only_vaults: bool) -> Option<(u8, [u8; 20])> {
        use divi_wallet::address::{Address, AddressType};
        let address = Address::from_base58_for_network(address, self.address_network()).ok()?;
        let hash = *address.hash.as_bytes();
        match (address.addr_type, only_vaults) {
            (AddressType::P2SH, true) => None,
            (_, true) => Some((3, hash)),
            (AddressType::P2PKH, false) => Some((1, hash)),
            (AddressType::P2SH, false) => Some((2, hash)),
        }
    }

    /// Divi Core's argument count check of the address index calls: one or two
    /// arguments, else -1 with the call's help text, before anything else
    fn address_call_arity(params: &Params, method: &str) -> Result<(), Error> {
        if params.is_empty() || params.len() > 2 {
            return Err(RpcError::invalid_params(format!(
                "{method} <address>|<addresses> (only_vaults)"
            ))
            .into());
        }
        Ok(())
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
        // GetAddressIndex / GetAddressUnspent failing (rpcmisc.cpp:658, :760, :851, :976)
        RpcError::new(
            codes::INVALID_ADDRESS_OR_KEY,
            "No information available for address",
        )
        .into()
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
    pub fn getmininginfo(&self, params: &Params) -> Result<Value, Error> {
        // Divi Core sends these seven members (rpcmining.cpp:220-247)
        crate::core_help::check_arguments("getmininginfo", params, (0, 0), 0)?;
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

        // Divi Core's members (rpcmining.cpp:229-236)
        Ok(json!({
            "blocks": blocks,
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
/// A block hash argument as Divi Core reads it (`uint256 hash(strHash)` then a
/// block map lookup): text that is not a hash names no block, -5 "Block not found"
fn block_hash_like_core(s: &str) -> Result<Hash256, Error> {
    Hash256::from_hex(s).map_err(|_| {
        RpcError::new(
            crate::error::codes::INVALID_ADDRESS_OR_KEY,
            "Block not found",
        )
        .into()
    })
}

/// json_spirit's error for a value read as the wrong type
fn json_spirit_type_error(value: Option<&Value>, want: &str) -> RpcError {
    let got = value.map_or("null", crate::wallet::json_spirit_type);
    RpcError::new(
        crate::error::codes::MISC_ERROR,
        format!("value is type {got}, expected {want}"),
    )
}

/// Divi Core ParseHashStr (core_io.cpp:139-147): a non-empty, even-length hex
/// string, else -1 "<name> must be hexadecimal string (not '<value>')", read as
/// uint256::SetHex reads it (uint256.cpp:186-212): its last 64 digits, a
/// shorter one with leading zeros
fn core_parse_hash_str(s: &str, name: &str) -> Result<Hash256, RpcError> {
    let is_hex =
        !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit());
    let not_hex = || {
        RpcError::new(
            crate::error::codes::MISC_ERROR,
            format!("{name} must be hexadecimal string (not '{s}')"),
        )
    };
    if !is_hex {
        return Err(not_hex());
    }
    let tail = &s[s.len().saturating_sub(64)..];
    Hash256::from_hex(&format!("{tail:0>64}")).map_err(|_| not_hex())
}

/// json_spirit's `get_int()` of an integer: its 64 bits cut to a C++ `int`
/// (json_spirit_value.h, `static_cast<int>`), so 2^32 + 5 reads as 5; None for
/// anything but an integer
fn json_spirit_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) if n.is_i64() || n.is_u64() => {
            let wide = n
                .as_i64()
                .unwrap_or_else(|| n.as_u64().unwrap_or_default() as i64);
            Some(i64::from(wide as i32))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A regtest chain of two blocks, with the address and spent indexes
    /// when `indexes`
    fn index_rpc(indexes: bool) -> (BlockchainRpc, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(divi_storage::ChainDatabase::open(dir.path()).unwrap());
        let params = divi_storage::ChainParams::for_network(
            NetworkType::Regtest,
            divi_primitives::ChainMode::Divi,
        );
        let mut chain = Chain::new(Arc::clone(&db), params).unwrap();
        if indexes {
            chain.enable_search_index(Arc::new(divi_storage::SearchIndex::new(db, true, true)));
        }
        let chain = Arc::new(chain);
        for blk in pow_chain(&chain, 2, 0xB7, 0) {
            chain.accept_block(blk).unwrap();
        }
        (BlockchainRpc::new(chain), dir)
    }

    fn refusal(reply: Result<Value, Error>) -> (i32, String) {
        match reply {
            Err(Error::Rpc(e)) => (e.code, e.message),
            other => panic!("not refused: {other:?}"),
        }
    }

    /// The address index calls check their arguments as Divi Core does
    /// (rpcmisc.cpp:563-595 getAddressesFromParams, and each call's count check)
    #[test]
    fn address_calls_check_arguments_as_divid() {
        let (rpc, _dir) = index_rpc(true);
        let address = divi_wallet::address::Address::from_pubkey_hash(
            Hash160::from_bytes([7u8; 20]),
            rpc.address_network(),
        )
        .to_base58();
        type Call = fn(&BlockchainRpc, &Params) -> Result<Value, Error>;
        let calls: [(&str, Call); 4] = [
            ("getaddressbalance", BlockchainRpc::get_address_balance),
            ("getaddressdeltas", BlockchainRpc::get_address_deltas),
            ("getaddresstxids", BlockchainRpc::get_address_txids),
            ("getaddressutxos", BlockchainRpc::get_address_utxos),
        ];
        for (method, call) in calls {
            let at = |args: Vec<Value>| call(&rpc, &Params::Array(args));
            for args in [vec![], vec![json!(address), json!(false), json!(1)]] {
                let (code, message) = refusal(at(args));
                assert_eq!(code, codes::MISC_ERROR, "{method}");
                assert!(
                    message.starts_with(&format!("{method} ")),
                    "{method}: {message}"
                );
            }
            for (args, code, message) in [
                (
                    vec![json!(address), json!("yes")],
                    -1,
                    "value is type str, expected bool",
                ),
                (vec![json!(7)], -5, "Invalid address"),
                (vec![json!("notanaddress")], -5, "Invalid address"),
                (
                    vec![json!({"addresses": address})],
                    -5,
                    "Addresses is expected to be an array",
                ),
                (vec![json!({})], -5, "Addresses is expected to be an array"),
                (
                    vec![json!({"addresses": [7]})],
                    -1,
                    "value is type int, expected str",
                ),
                (
                    vec![json!({"addresses": [address, "notanaddress"]})],
                    -5,
                    "Invalid address",
                ),
            ] {
                assert_eq!(
                    refusal(at(args.clone())),
                    (code, message.to_string()),
                    "{method} {args:?}"
                );
            }
            // An empty list names no address: an empty answer
            assert!(at(vec![json!({"addresses": []})]).is_ok(), "{method} []");
            assert!(
                at(vec![json!(address), json!(true)]).is_ok(),
                "{method} only_vaults"
            );
        }
    }

    /// getspentinfo checks its argument and answers a missing entry, with or
    /// without the spent index, as Divi Core does (rpcmisc.cpp:878-926)
    #[test]
    fn getspentinfo_checks_arguments_as_divid() {
        let txid = "11".repeat(32);
        for indexes in [true, false] {
            let (rpc, _dir) = index_rpc(indexes);
            let at = |args: Vec<Value>| rpc.get_spent_info(&Params::Array(args));
            for args in [
                vec![],
                vec![json!({"txid": txid, "index": 0}), json!(1)],
                vec![json!(txid)],
            ] {
                let (code, message) = refusal(at(args));
                assert_eq!(code, -1);
                assert!(message.starts_with("getspentinfo "), "{message}");
            }
            for (arg, code, message) in [
                (
                    json!({"txid": txid, "index": 0}),
                    -5,
                    "Unable to get spent info".to_string(),
                ),
                (
                    json!({"txid": "abab", "index": 0}),
                    -5,
                    "Unable to get spent info".into(),
                ),
                (json!({"txid": txid}), -5, "Invalid txid or index".into()),
                (
                    json!({"txid": txid, "index": "0"}),
                    -5,
                    "Invalid txid or index".into(),
                ),
                (
                    json!({"txid": 5, "index": 0}),
                    -5,
                    "Invalid txid or index".into(),
                ),
                (
                    json!({"txid": "zz", "index": 0}),
                    -8,
                    "txid must be hexadecimal string (not 'zz')".into(),
                ),
            ] {
                assert_eq!(
                    refusal(at(vec![arg.clone()])),
                    (code, message),
                    "{indexes} {arg}"
                );
            }
        }
    }

    /// getlotteryblockwinners reads its height with json_spirit's get_int
    /// (rpclottery.cpp:47)
    #[test]
    fn getlotteryblockwinners_height_must_be_an_integer() {
        let (rpc, _dir) = index_rpc(false);
        let at = |args: Vec<Value>| rpc.get_lottery_block_winners(&Params::Array(args));
        for (arg, message) in [
            (json!("abc"), "value is type str, expected int"),
            (json!(1.5), "value is type real, expected int"),
            (json!(null), "value is type null, expected int"),
        ] {
            assert_eq!(refusal(at(vec![arg])), (-1, message.to_string()));
        }
    }

    /// reverseblocktransactions leaves the tip at the block's parent, and the
    /// block is not left invalid: a child of it connects (Divi Core
    /// rpcblockchain.cpp:577-603, ChainExtensionService.cpp:662-689)
    #[test]
    fn reverseblocktransactions_leaves_the_tip_at_the_parent() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(divi_storage::ChainDatabase::open(dir.path()).unwrap());
        let params = divi_storage::ChainParams::for_network(
            NetworkType::Regtest,
            divi_primitives::ChainMode::Divi,
        );
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let blocks = pow_chain(&chain, 4, 0xC3, 0);
        for blk in &blocks[..3] {
            chain.accept_block(blk.clone()).unwrap();
        }
        let rpc = BlockchainRpc::new(chain.clone());
        let third = divi_crypto::compute_block_hash(&blocks[2].header);
        let second = divi_crypto::compute_block_hash(&blocks[1].header);
        rpc.invalidate_block_family(
            "reverseblocktransactions",
            &Params::Array(vec![json!(third.to_string())]),
        )
        .unwrap();
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.tip().unwrap().hash, second);
        chain.accept_block(blocks[3].clone()).unwrap();
        assert_eq!(chain.height(), 4, "the reversed block stayed invalid");
    }

    fn header_of(rpc: &BlockchainRpc, hash: Hash256) -> Value {
        rpc.get_block_header(&Params::Array(vec![json!(hash.to_string())]))
            .unwrap()
    }

    /// getblockhash answers a height outside the active chain as Divi Core
    /// does: RPC_INVALID_PARAMETER "Block height out of range"
    #[test]
    fn getblockhash_out_of_range_is_divid_s_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(divi_storage::ChainDatabase::open(dir.path()).unwrap());
        let params = divi_storage::ChainParams::for_network(
            NetworkType::Regtest,
            divi_primitives::ChainMode::Divi,
        );
        let chain = Arc::new(Chain::new(db, params).unwrap());
        for blk in pow_chain(&chain, 2, 0xA1, 0) {
            chain.accept_block(blk).unwrap();
        }
        let rpc = BlockchainRpc::new(chain);
        let at = |h: i64| rpc.get_block_hash(&Params::Array(vec![json!(h)]));
        assert!(at(0).is_ok());
        assert!(at(2).is_ok());
        for height in [3, 99_999, -1] {
            match at(height) {
                Err(Error::Rpc(e)) => {
                    assert_eq!(e.code, codes::INVALID_PARAMETER, "{height}");
                    assert_eq!(e.message, "Block height out of range", "{height}");
                }
                other => panic!("{height}: {other:?}"),
            }
        }
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
        // As divid: the tip stays at the reversed block's parent until another
        // block comes (rpcblockchain.cpp:577-603)
        assert_eq!(chain.height(), 1);

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
