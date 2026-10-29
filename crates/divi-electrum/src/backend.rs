// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The chain and mempool queries behind each Electrum method. Every call
//! blocks on RocksDB, so sessions run them on the blocking pool.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use divi_crypto::hash::{double_sha256, sha256};
use divi_primitives::block::BlockHeader;
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction};
use divi_rpc::blockchain::MempoolProvider;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::search_index::script_hash;
use divi_storage::{BlockIndex, Chain};
use serde_json::{json, Value};

/// Every header is sent this long; see docs/electrum-server.md
pub const HEADER_SIZE: usize = 112;
/// Most headers one `blockchain.block.headers` reply carries
pub const MAX_HEADERS: u32 = 2016;

/// An Electrum error: the code and message of the reply's `error` object
#[derive(Debug, Clone, PartialEq)]
pub struct ElectrumError {
    pub code: i64,
    pub message: String,
}

impl ElectrumError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        ElectrumError {
            code: 1,
            message: message.into(),
        }
    }

    pub fn daemon(message: impl Into<String>) -> Self {
        ElectrumError {
            code: 2,
            message: message.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, ElectrumError>;

fn storage<E: std::fmt::Display>(e: E) -> ElectrumError {
    ElectrumError::daemon(format!("database error: {e}"))
}

/// One `get_history` entry. Unconfirmed transactions have height 0, or -1
/// when they spend an unconfirmed output.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEntry {
    pub txid: Hash256,
    pub height: i64,
    pub fee: Option<i64>,
}

/// One `listunspent` entry
#[derive(Debug, Clone, PartialEq)]
pub struct Unspent {
    pub txid: Hash256,
    pub vout: u32,
    pub height: i64,
    pub value: i64,
}

/// A header as the server sends it: serialized as Divi does, then padded
/// with zeros to `HEADER_SIZE`
pub fn header_bytes(index: &BlockIndex) -> Vec<u8> {
    let header = BlockHeader {
        version: index.version,
        prev_block: index.prev_hash,
        merkle_root: index.merkle_root,
        time: index.time,
        bits: index.bits,
        nonce: index.nonce,
        accumulator_checkpoint: index.accumulator.unwrap_or_else(Hash256::zero),
    };
    pad_header(serialize(&header))
}

/// Pads a serialized header to `HEADER_SIZE`
pub fn pad_header(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.resize(HEADER_SIZE, 0);
    bytes
}

/// The block hash of a padded header: sha256d over 80 bytes when the
/// version is 3 or less, else over all 112. This is what a client computes.
pub fn padded_header_hash(header: &[u8]) -> Option<Hash256> {
    if header.len() != HEADER_SIZE {
        return None;
    }
    let version = i32::from_le_bytes(header[..4].try_into().ok()?);
    let len = if version > 3 { HEADER_SIZE } else { 80 };
    Some(Hash256::from_bytes(double_sha256(&header[..len])))
}

/// The raw script hash an Electrum scripthash names. Electrum shows
/// sha256(script) byte-reversed.
pub fn parse_scripthash(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ElectrumError::bad_request(format!("invalid scripthash {hex_str}")))?;
    let mut out: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ElectrumError::bad_request(format!("invalid scripthash {hex_str}")))?;
    out.reverse();
    Ok(out)
}

/// The Electrum status of a history: sha256 over `txid:height:` for each
/// entry, or None when there is none
pub fn status_hash(history: &[HistoryEntry]) -> Option<String> {
    if history.is_empty() {
        return None;
    }
    let mut text = String::new();
    for entry in history {
        text.push_str(&entry.txid.to_hex());
        text.push(':');
        text.push_str(&entry.height.to_string());
        text.push(':');
    }
    Some(hex::encode(sha256(text.as_bytes())))
}

/// The merkle branch of the transaction at `pos` among `txids`, each hash
/// in internal byte order
pub fn merkle_branch(txids: &[Hash256], mut pos: usize) -> Vec<Hash256> {
    let mut level: Vec<[u8; 32]> = txids.iter().map(|t| *t.as_bytes()).collect();
    let mut branch = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        branch.push(Hash256::from_bytes(level[pos ^ 1]));
        level = level
            .chunks(2)
            .map(|pair| {
                let mut joined = [0u8; 64];
                joined[..32].copy_from_slice(&pair[0]);
                joined[32..].copy_from_slice(&pair[1]);
                double_sha256(&joined)
            })
            .collect();
        pos /= 2;
    }
    branch
}

/// The mempool as one scripthash sees it
struct MempoolView {
    /// Pool transactions that pay to or spend from the script
    history: Vec<HistoryEntry>,
    /// Pool outputs to the script, with their value
    outputs: Vec<(OutPoint, i64, i64)>,
    /// Outpoints of the script that pool transactions spend
    spent: HashSet<OutPoint>,
}

pub struct Backend {
    chain: Arc<Chain>,
    mempool: Arc<dyn MempoolProvider>,
    rpc: Arc<RpcServer>,
}

impl Backend {
    pub fn new(chain: Arc<Chain>, mempool: Arc<dyn MempoolProvider>, rpc: Arc<RpcServer>) -> Self {
        Backend {
            chain,
            mempool,
            rpc,
        }
    }

    pub fn genesis_hash(&self) -> Hash256 {
        self.chain.genesis_hash()
    }

    /// A fingerprint of the tip and the mempool; sessions recompute
    /// statuses only when it changes
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut data = Vec::new();
        if let Some(tip) = self.chain.tip() {
            data.extend_from_slice(tip.hash.as_bytes());
        }
        let mut txids = self.mempool.get_txids();
        txids.sort();
        for txid in txids {
            data.extend_from_slice(txid.as_bytes());
        }
        sha256(&data)
    }

    /// The tip as `blockchain.headers.subscribe` reports it
    pub fn tip(&self) -> Result<Value> {
        let tip = self
            .chain
            .tip()
            .ok_or_else(|| ElectrumError::daemon("no chain tip"))?;
        Ok(json!({ "hex": hex::encode(header_bytes(&tip)), "height": tip.height }))
    }

    pub fn tip_hash(&self) -> Option<Hash256> {
        self.chain.tip().map(|t| t.hash)
    }

    fn index_at(&self, height: u32) -> Result<BlockIndex> {
        let tip = self.chain.height();
        if height > tip {
            return Err(ElectrumError::bad_request(format!(
                "height {height} out of range"
            )));
        }
        self.chain
            .get_block_index_by_height(height)
            .map_err(storage)?
            .ok_or_else(|| ElectrumError::bad_request(format!("no header at height {height}")))
    }

    pub fn header(&self, height: u32) -> Result<String> {
        Ok(hex::encode(header_bytes(&self.index_at(height)?)))
    }

    pub fn headers(&self, start: u32, count: u32) -> Result<Value> {
        let count = count.min(MAX_HEADERS);
        let tip = self.chain.height();
        let mut hex_out = String::new();
        let mut got = 0u32;
        let mut height = start;
        while got < count && height <= tip {
            hex_out.push_str(&hex::encode(header_bytes(&self.index_at(height)?)));
            got += 1;
            height += 1;
        }
        Ok(json!({ "hex": hex_out, "count": got, "max": MAX_HEADERS }))
    }

    /// The confirmed unspent outputs of a script, from the address index
    fn confirmed_unspent(&self, sh: &[u8; 32]) -> Result<Vec<Unspent>> {
        let index = self.search_index()?;
        let Some((address_type, hash)) = index.lookup_script_hash(sh).map_err(storage)? else {
            return Ok(Vec::new());
        };
        Ok(index
            .read_unspent(address_type, &hash)
            .map_err(storage)?
            .into_iter()
            .filter(|(_, value)| script_hash(value.script.as_bytes()) == *sh)
            .map(|(key, value)| Unspent {
                txid: key.txid,
                vout: key.index,
                height: value.height as i64,
                value: value.satoshis,
            })
            .collect())
    }

    fn search_index(&self) -> Result<&Arc<divi_storage::SearchIndex>> {
        self.chain
            .search_index()
            .filter(|index| index.address_enabled())
            .ok_or_else(|| ElectrumError::daemon("the address index is off"))
    }

    /// The confirmed history of a script, in block order
    fn confirmed_history(&self, sh: &[u8; 32]) -> Result<Vec<HistoryEntry>> {
        let index = self.search_index()?;
        let Some((address_type, hash)) = index.lookup_script_hash(sh).map_err(storage)? else {
            return Ok(Vec::new());
        };
        let mut seen: BTreeMap<(u32, u32), Hash256> = BTreeMap::new();
        for (key, _) in index
            .read_deltas(address_type, &hash, 0, 0)
            .map_err(storage)?
        {
            seen.insert((key.height, key.tx_index), key.txid);
        }
        Ok(seen
            .into_iter()
            .map(|((height, _), txid)| HistoryEntry {
                txid,
                height: height as i64,
                fee: None,
            })
            .collect())
    }

    fn mempool_view(&self, sh: &[u8; 32], confirmed: &[Unspent]) -> MempoolView {
        let infos = self.mempool.get_tx_infos();
        let mut txs: Vec<(Hash256, i64, bool, Transaction)> = Vec::new();
        for info in infos {
            if let Some(tx) = self.mempool.get_transaction(&info.txid) {
                txs.push((info.txid, info.fee_sat, !info.depends.is_empty(), tx));
            }
        }
        let mut values: HashMap<OutPoint, i64> = confirmed
            .iter()
            .map(|u| (OutPoint::new(u.txid, u.vout), u.value))
            .collect();
        let mut outputs = Vec::new();
        let mut paying: HashSet<Hash256> = HashSet::new();
        for (txid, _, depends, tx) in &txs {
            for (k, out) in tx.vout.iter().enumerate() {
                if script_hash(out.script_pubkey.as_bytes()) == *sh {
                    let outpoint = OutPoint::new(*txid, k as u32);
                    let value = out.value.as_sat();
                    values.insert(outpoint, value);
                    outputs.push((outpoint, value, if *depends { -1 } else { 0 }));
                    paying.insert(*txid);
                }
            }
        }
        let mut spent = HashSet::new();
        let mut history = Vec::new();
        for (txid, fee, depends, tx) in &txs {
            let mut relevant = paying.contains(txid);
            for input in &tx.vin {
                if values.contains_key(&input.prevout) {
                    spent.insert(input.prevout);
                    relevant = true;
                }
            }
            if relevant {
                history.push(HistoryEntry {
                    txid: *txid,
                    height: if *depends { -1 } else { 0 },
                    fee: Some(*fee),
                });
            }
        }
        history.sort_by(|a, b| {
            b.height
                .cmp(&a.height)
                .then_with(|| a.txid.to_hex().cmp(&b.txid.to_hex()))
        });
        MempoolView {
            history,
            outputs,
            spent,
        }
    }

    pub fn history(&self, sh: &[u8; 32]) -> Result<Vec<HistoryEntry>> {
        let mut history = self.confirmed_history(sh)?;
        let confirmed = self.confirmed_unspent(sh)?;
        history.extend(self.mempool_view(sh, &confirmed).history);
        Ok(history)
    }

    pub fn mempool_history(&self, sh: &[u8; 32]) -> Result<Vec<HistoryEntry>> {
        let confirmed = self.confirmed_unspent(sh)?;
        Ok(self.mempool_view(sh, &confirmed).history)
    }

    pub fn status(&self, sh: &[u8; 32]) -> Result<Option<String>> {
        Ok(status_hash(&self.history(sh)?))
    }

    /// (confirmed, unconfirmed) balance in satoshis
    pub fn balance(&self, sh: &[u8; 32]) -> Result<(i64, i64)> {
        let confirmed = self.confirmed_unspent(sh)?;
        let view = self.mempool_view(sh, &confirmed);
        let confirmed_sum: i64 = confirmed.iter().map(|u| u.value).sum();
        let incoming: i64 = view.outputs.iter().map(|(_, value, _)| value).sum();
        let mut values: HashMap<OutPoint, i64> = confirmed
            .iter()
            .map(|u| (OutPoint::new(u.txid, u.vout), u.value))
            .collect();
        for (outpoint, value, _) in &view.outputs {
            values.insert(*outpoint, *value);
        }
        let outgoing: i64 = view.spent.iter().filter_map(|o| values.get(o)).sum();
        Ok((confirmed_sum, incoming - outgoing))
    }

    pub fn listunspent(&self, sh: &[u8; 32]) -> Result<Vec<Unspent>> {
        let confirmed = self.confirmed_unspent(sh)?;
        let view = self.mempool_view(sh, &confirmed);
        let mut out: Vec<Unspent> = confirmed
            .into_iter()
            .filter(|u| !view.spent.contains(&OutPoint::new(u.txid, u.vout)))
            .collect();
        for (outpoint, value, height) in view.outputs {
            if !view.spent.contains(&outpoint) {
                out.push(Unspent {
                    txid: outpoint.txid,
                    vout: outpoint.vout,
                    height,
                    value,
                });
            }
        }
        Ok(out)
    }

    /// A transaction's raw bytes, from the mempool or the transaction index
    pub fn raw_transaction(&self, txid: &Hash256) -> Result<Vec<u8>> {
        if let Some(tx) = self.mempool.get_transaction(txid) {
            return Ok(serialize(&tx));
        }
        self.chain
            .get_transaction(txid)
            .map_err(storage)?
            .map(|tx| serialize(&tx))
            .ok_or_else(|| ElectrumError::bad_request(format!("no transaction {}", txid.to_hex())))
    }

    /// `{merkle, block_height, pos}` for a transaction in the block at `height`
    pub fn merkle(&self, txid: &Hash256, height: u32) -> Result<Value> {
        let index = self.index_at(height)?;
        let block = self
            .chain
            .get_block(&index.hash)
            .map_err(storage)?
            .ok_or_else(|| ElectrumError::daemon(format!("block {height} not stored")))?;
        let txids: Vec<Hash256> = block.transactions.iter().map(|tx| tx.txid()).collect();
        let pos = txids.iter().position(|t| t == txid).ok_or_else(|| {
            ElectrumError::bad_request(format!(
                "transaction {} not in block {height}",
                txid.to_hex()
            ))
        })?;
        let branch: Vec<String> = merkle_branch(&txids, pos)
            .iter()
            .map(|h| h.to_hex())
            .collect();
        Ok(json!({ "merkle": branch, "block_height": height, "pos": pos }))
    }

    /// Calls a node RPC method and returns its result
    pub fn rpc(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let response = self.rpc.handle_request(Request {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: method.into(),
            params: Params::Array(params),
        });
        if let Some(error) = response.error {
            return Err(ElectrumError::bad_request(error.message));
        }
        Ok(response.result.unwrap_or(Value::Null))
    }

    /// The minimum relay fee in DIVI per kB
    pub fn relay_fee(&self) -> f64 {
        self.rpc("getnetworkinfo", vec![])
            .ok()
            .and_then(|info| info.get("relayfee").and_then(Value::as_f64))
            .unwrap_or(0.0001)
    }

    /// The fee estimate in DIVI per kB for confirmation within `blocks`,
    /// the relay fee when the node has none
    pub fn estimate_fee(&self, blocks: u32) -> f64 {
        match self
            .rpc("estimatefee", vec![json!(blocks)])
            .ok()
            .and_then(|v| v.as_f64())
        {
            Some(fee) if fee > 0.0 => fee,
            _ => self.relay_fee(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txid(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    #[test]
    fn old_headers_hash_their_first_80_bytes() {
        let header = BlockHeader {
            version: 3,
            prev_block: txid(1),
            merkle_root: txid(2),
            time: 1_600_000_000,
            bits: 0x207fffff,
            nonce: 7,
            accumulator_checkpoint: Hash256::zero(),
        };
        let raw = serialize(&header);
        assert_eq!(raw.len(), 80);
        let padded = pad_header(raw.clone());
        assert_eq!(padded.len(), HEADER_SIZE);
        assert_eq!(
            padded_header_hash(&padded),
            Some(Hash256::from_bytes(double_sha256(&raw)))
        );
    }

    #[test]
    fn new_headers_hash_all_112_bytes() {
        let header = BlockHeader {
            version: 4,
            prev_block: txid(1),
            merkle_root: txid(2),
            time: 1_600_000_000,
            bits: 0x207fffff,
            nonce: 7,
            accumulator_checkpoint: txid(9),
        };
        let raw = serialize(&header);
        assert_eq!(raw.len(), HEADER_SIZE);
        assert_eq!(pad_header(raw.clone()), raw);
        assert_eq!(
            padded_header_hash(&raw),
            Some(Hash256::from_bytes(double_sha256(&raw)))
        );
    }

    #[test]
    fn scripthash_is_reversed_hex() {
        let sh = script_hash(&[0x51]);
        let mut shown = sh;
        shown.reverse();
        assert_eq!(parse_scripthash(&hex::encode(shown)).unwrap(), sh);
        assert!(parse_scripthash("zz").is_err());
        assert!(parse_scripthash("00").is_err());
    }

    #[test]
    fn status_hash_matches_electrum() {
        assert_eq!(status_hash(&[]), None);
        let history = vec![
            HistoryEntry {
                txid: txid(1),
                height: 5,
                fee: None,
            },
            HistoryEntry {
                txid: txid(2),
                height: 0,
                fee: Some(100),
            },
        ];
        let text = format!("{}:5:{}:0:", txid(1).to_hex(), txid(2).to_hex());
        assert_eq!(
            status_hash(&history),
            Some(hex::encode(sha256(text.as_bytes())))
        );
    }

    fn merkle_root(txids: &[Hash256]) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = txids.iter().map(|t| *t.as_bytes()).collect();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            level = level
                .chunks(2)
                .map(|p| double_sha256(&[p[0], p[1]].concat()))
                .collect();
        }
        level[0]
    }

    #[test]
    fn merkle_branches_lead_to_the_root() {
        for n in 1..=7u8 {
            let txids: Vec<Hash256> = (0..n).map(txid).collect();
            let root = merkle_root(&txids);
            for pos in 0..n as usize {
                let mut hash = *txids[pos].as_bytes();
                let mut index = pos;
                for sibling in merkle_branch(&txids, pos) {
                    let pair = if index % 2 == 0 {
                        [hash, *sibling.as_bytes()].concat()
                    } else {
                        [*sibling.as_bytes(), hash].concat()
                    };
                    hash = double_sha256(&pair);
                    index /= 2;
                }
                assert_eq!(hash, root, "n={n} pos={pos}");
            }
        }
    }
}
