// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Minimal JSON-RPC client for the services.divi.domains proxy, with retry and error
//! classification. No auth: the proxy allow-lists read methods plus `sendrawtransaction`.

use std::sync::Arc;
use std::time::Duration;

use divi_swap::SwapError;
use parking_lot::Mutex;
use serde_json::{json, Value};

/// Blocks whose header times give the median time past (BIP113, `CBlockIndex::GetMedianTimePast`).
const MTP_BLOCKS: usize = 11;

/// How transient failures are retried.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total attempts per call (>= 1).
    pub attempts: u32,
    /// Delay before the 2nd attempt; doubles each time.
    pub base_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            attempts: 4,
            base_delay: Duration::from_millis(500),
        }
    }
}

/// A failed call: either the node answered with an error, or we never got an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// The node returned a JSON-RPC error object.
    Node {
        /// JSON-RPC error code.
        code: i64,
        /// Node's message.
        message: String,
    },
    /// Transport or HTTP-level failure, already classified.
    Swap(SwapError),
}

impl From<RpcError> for SwapError {
    fn from(e: RpcError) -> Self {
        match e {
            RpcError::Node { code, message } => SwapError::Other(format!("rpc {code}: {message}")),
            RpcError::Swap(e) => e,
        }
    }
}

/// JSON-RPC over HTTP.
#[derive(Debug, Clone)]
pub struct RpcClient {
    http: reqwest::Client,
    url: String,
    retry: RetryPolicy,
    /// The last median time past read, keyed by the best block it was read from
    /// ([`RpcClient::median_time_past`]). Shared by every clone of this client.
    mtp: Arc<Mutex<Option<(String, u32)>>>,
}

impl RpcClient {
    /// New client for `url`.
    pub fn new(url: &str, retry: RetryPolicy) -> Self {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(Duration::from_secs(30));
        let http = builder.build().unwrap_or_default();
        RpcClient {
            http,
            url: url.to_string(),
            retry,
            mtp: Arc::default(),
        }
    }

    /// Median time past of the best block: the median of the header times of it and up to
    /// ten ancestors (the node reports `mediantime: null`, so it is computed here).
    ///
    /// The walk starts from `getbestblockhash`, so every block read is an ancestor of the one
    /// tip named (no `getblockcount` / `getblockhash` pair a new block can land between). A
    /// block hash commits to its header time and to its parent, so the eleven times are a
    /// function of the tip hash alone: the answer is kept with that hash and, while the best
    /// block is unchanged, one `getbestblockhash` answers instead of twelve calls. A new tip,
    /// including a different block at the same height after a reorg, names another hash and
    /// is read afresh. An error is never kept, and neither is an answer whose blocks did not
    /// prove themselves (a block that is not the one asked for, or a walk that ended short of
    /// eleven blocks above genesis); those are returned as before, but read again next time.
    pub async fn median_time_past(&self) -> Result<u32, SwapError> {
        let tip = self.call_ok("getbestblockhash", json!([])).await?;
        let tip = tip
            .as_str()
            .ok_or_else(|| SwapError::Transient("getbestblockhash: not a string".into()))?;
        let tip = divi_swap::backend::normalize_block_hash(tip)?;
        if let Some((hash, mtp)) = self.mtp.lock().as_ref() {
            if *hash == tip {
                return Ok(*mtp);
            }
        }
        let (mtp, proven) = self.median_time_past_from(&tip).await?;
        if proven {
            *self.mtp.lock() = Some((tip, mtp));
        }
        Ok(mtp)
    }

    /// Median time past of the block `tip`, uncached, and whether every block read was the
    /// one asked for and the walk reached eleven blocks or genesis.
    async fn median_time_past_from(&self, tip: &str) -> Result<(u32, bool), SwapError> {
        let mut hash = Value::String(tip.to_owned());
        let mut times = Vec::with_capacity(MTP_BLOCKS);
        let mut proven = true;
        let mut reached_genesis = false;
        for _ in 0..MTP_BLOCKS {
            let block = self.call_ok("getblock", json!([hash, true])).await?;
            times.push(block["time"].as_u64().ok_or_else(|| {
                // A real block always has a time; its absence means a proxy-fronted
                // node behind the one that reported this hash hasn't indexed it yet.
                SwapError::Transient("block without time (still indexing?)".into())
            })?);
            let asked = hash
                .as_str()
                .and_then(|h| divi_swap::backend::normalize_block_hash(h).ok());
            let named = block["hash"]
                .as_str()
                .and_then(|h| divi_swap::backend::normalize_block_hash(h).ok());
            proven &= asked.is_some() && asked == named;
            match block.get("previousblockhash").filter(|p| p.is_string()) {
                Some(prev) => hash = prev.clone(),
                None => {
                    reached_genesis = block["height"].as_u64() == Some(0);
                    break;
                }
            }
        }
        proven &= times.len() == MTP_BLOCKS || reached_genesis;
        times.sort_unstable();
        Ok((times[times.len() / 2] as u32, proven))
    }

    /// Call `method`; transient failures are retried with exponential backoff.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let attempts = self.retry.attempts.max(1);
        let mut delay = self.retry.base_delay;
        let mut last = RpcError::Swap(SwapError::Transient("no attempt made".into()));
        for attempt in 0..attempts {
            if attempt > 0 {
                divi_swap::rt::sleep(delay).await;
                delay *= 2;
            }
            match self.once(method, &params).await {
                Err(RpcError::Swap(SwapError::Transient(m))) => {
                    tracing::warn!(method, attempt, "transient rpc failure: {m}");
                    last = RpcError::Swap(SwapError::Transient(m));
                }
                other => return other,
            }
        }
        Err(last)
    }

    /// Like [`call`](Self::call) but node errors become `SwapError::Other`.
    pub async fn call_ok(&self, method: &str, params: Value) -> Result<Value, SwapError> {
        self.call(method, params).await.map_err(Into::into)
    }

    async fn once(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params});
        let resp = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RpcError::Swap(SwapError::Transient(format!("{method}: {e}"))))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| RpcError::Swap(SwapError::Transient(format!("{method}: {e}"))))?;
        // bitcoind-style nodes answer RPC errors with HTTP 4xx/5xx and a JSON body: prefer it.
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
                let code = err["code"].as_i64().unwrap_or(0);
                let message = err["message"].as_str().unwrap_or("").to_string();
                // -28 is bitcoind's (and DIVI's) node-warmup code ("Loading block
                // index...", "Verifying blocks..."); -5 is reused for both "Block not
                // found" (a load-balanced proxy serving a block a different backend
                // already reported as the tip, the exact DIVI analog of the esplora
                // "Block not found" 404 bug) and "No such mempool or blockchain
                // transaction" (not this case — that one is handled by message text).
                // Both are transient: routing them through `RpcError::Swap` gets them
                // retried by this method's own backoff loop, not just correctly labeled
                // after it gives up.
                if code == -28 || (code == -5 && message.contains("Block not found")) {
                    return Err(RpcError::Swap(SwapError::Transient(format!(
                        "rpc {code}: {message}"
                    ))));
                }
                return Err(RpcError::Node { code, message });
            }
            if status.is_success() {
                return Ok(v.get("result").cloned().unwrap_or(Value::Null));
            }
        }
        let snippet: String = text.chars().take(200).collect();
        if status.as_u16() == 429 || status.is_server_error() {
            Err(RpcError::Swap(SwapError::Transient(format!(
                "{method}: HTTP {status}: {snippet}"
            ))))
        } else if status.is_success() {
            Err(RpcError::Swap(SwapError::Transient(format!(
                "{method}: unparseable response: {snippet}"
            ))))
        } else {
            Err(RpcError::Swap(SwapError::Other(format!(
                "{method}: HTTP {status}: {snippet}"
            ))))
        }
    }
}

/// What a `sendrawtransaction` error message means.
#[derive(Debug, PartialEq, Eq)]
pub enum BroadcastClass {
    /// The chain already has the transaction.
    AlreadyKnown,
    /// A timelock has not matured.
    Premature,
    /// Refused for another reason.
    Rejected,
}

/// Classify a `sendrawtransaction` error message.
pub fn classify_broadcast_error(message: &str) -> BroadcastClass {
    let m = message.to_ascii_lowercase();
    if m.contains("already in block chain")
        || m.contains("already in the block chain")
        || m.contains("txn-already-known")
        || m.contains("txn-already-in-mempool")
        || m.contains("outputs already in utxo set")
    {
        BroadcastClass::AlreadyKnown
    } else if m.contains("non-final") || m.contains("locktime requirement not satisfied") {
        BroadcastClass::Premature
    } else {
        BroadcastClass::Rejected
    }
}
