// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Read-only DIVI [`Observer`]s for [`divi_swap::TwoSource`]: the RPC proxy, and
//! chainz.cryptoid.info as a source the proxy's operator does not run.
//!
//! cryptoid serves mainnet only (no `divi-test`), so testnet stays single-source. Its
//! terms: free, "please do not abuse"; the Query API (`api.dws`) at most one call per 10 s,
//! which [`CryptoidObserver`] enforces. The explorer endpoints (`*.raw.dws`) send no CORS
//! header, so a browser extension needs host permission for the site.

use std::time::Duration;

use async_trait::async_trait;
use divi_swap::htlc::HtlcParams;
use divi_swap::observer::{ObservedLock, ObservedTx, Observer};
use divi_swap::{Amount, Outpoint, Result, SwapError, Txid};
use parking_lot::Mutex;
use serde_json::{json, Value};

use crate::htlc_script_pubkey;
use crate::rpc::{RetryPolicy, RpcClient, RpcError};

/// chainz.cryptoid.info, the default second DIVI source.
pub const CRYPTOID: &str = "https://chainz.cryptoid.info";

/// Seconds between two Query API calls (cryptoid asks for at most one per 10 s).
const QUERY_GAP_SECS: u64 = 11;
/// How long a cryptoid median time past is reused. Staler only lowers it, and
/// `TwoSource` takes the later of its two sources.
const MTP_TTL_SECS: u64 = 60;

/// A verbose transaction (`getrawtransaction … 1`, or cryptoid's `tx.raw.dws`, which has
/// the same shape) as an [`ObservedTx`].
pub(crate) fn observed_tx(tx: &Value) -> ObservedTx {
    ObservedTx {
        confirmations: tx["confirmations"].as_u64().unwrap_or(0) as u32,
        block_hash: tx["blockhash"].as_str().map(String::from),
    }
}

/// Output `vout` of a verbose transaction, if it pays exactly `htlc`'s P2SH script.
pub(crate) fn observed_lock(
    tx: &Value,
    htlc: &HtlcParams,
    vout: u32,
) -> Result<Option<ObservedLock>> {
    let Some(out) = tx["vout"]
        .as_array()
        .and_then(|a| a.iter().find(|o| o["n"].as_u64() == Some(vout as u64)))
    else {
        return Ok(None);
    };
    if out["scriptPubKey"]["hex"].as_str() != Some(htlc_script_pubkey(htlc).to_hex().as_str()) {
        return Ok(None);
    }
    let sat = out["valueSat"]
        .as_u64()
        .or_else(|| out["value"].as_f64().map(|v| (v * 1e8).round() as u64))
        .ok_or_else(|| SwapError::Other("output without value".into()))?;
    Ok(Some(ObservedLock {
        amount: Amount(sat),
        tx: observed_tx(tx),
    }))
}

/// Median of up to 11 block times.
fn median(mut times: Vec<u64>) -> Result<u32> {
    if times.is_empty() {
        return Err(SwapError::Transient("no block times".into()));
    }
    times.sort_unstable();
    Ok(times[times.len() / 2] as u32)
}

fn block_time(block: &Value) -> Result<u64> {
    // A real block always has a time; its absence means a source behind the one that
    // reported the tip hasn't indexed it yet.
    block["time"]
        .as_u64()
        .ok_or_else(|| SwapError::Transient("block without time (still indexing?)".into()))
}

/// Median time past over the JSON-RPC proxy (the node reports `mediantime: null`).
pub(crate) async fn rpc_median_time_past(rpc: &RpcClient) -> Result<u32> {
    let tip = rpc.call_ok("getblockcount", json!([])).await?;
    let tip = tip
        .as_u64()
        .ok_or_else(|| SwapError::Transient(format!("getblockcount: not a number: {tip}")))?;
    let mut hash = rpc.call_ok("getblockhash", json!([tip])).await?;
    let mut times = Vec::with_capacity(11);
    for _ in 0..11 {
        let block = rpc.call_ok("getblock", json!([hash, true])).await?;
        times.push(block_time(&block)?);
        match block.get("previousblockhash").filter(|p| p.is_string()) {
            Some(prev) => hash = prev.clone(),
            None => break,
        }
    }
    median(times)
}

/// The JSON-RPC proxy as an observer.
#[derive(Debug, Clone)]
pub struct RpcObserver {
    rpc: RpcClient,
}

impl RpcObserver {
    /// Observer over the proxy at `url`.
    pub fn new(url: &str, retry: RetryPolicy) -> Self {
        RpcObserver {
            rpc: RpcClient::new(url, retry),
        }
    }

    pub(crate) fn from_client(rpc: RpcClient) -> Self {
        RpcObserver { rpc }
    }

    async fn get_tx(&self, txid: &Txid) -> Result<Option<Value>> {
        match self
            .rpc
            .call("getrawtransaction", json!([txid.to_rpc_hex(), 1]))
            .await
        {
            Ok(v) => Ok(Some(v)),
            Err(RpcError::Node { code: -5, .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Observer for RpcObserver {
    fn name(&self) -> &str {
        "rpc"
    }

    async fn median_time_past(&self) -> Result<u32> {
        rpc_median_time_past(&self.rpc).await
    }

    async fn tx(&self, txid: &Txid) -> Result<Option<ObservedTx>> {
        Ok(self.get_tx(txid).await?.as_ref().map(observed_tx))
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<ObservedLock>> {
        match self.get_tx(&at.txid).await? {
            Some(tx) => observed_lock(&tx, htlc, at.vout),
            None => Ok(None),
        }
    }
}

/// chainz.cryptoid.info as an observer (mainnet `divi` only).
#[derive(Debug)]
pub struct CryptoidObserver {
    http: reqwest::Client,
    base: String,
    coin: String,
    /// Earliest unix second the next Query API call may go out.
    next_query: Mutex<u64>,
    /// (fetched at, MTP).
    mtp: Mutex<Option<(u64, u32)>>,
}

impl CryptoidObserver {
    /// Observer for mainnet DIVI at [`CRYPTOID`].
    pub fn mainnet() -> Self {
        Self::new(CRYPTOID, "divi")
    }

    /// Observer for `coin` at `base` (tests point this at a mock).
    pub fn new(base: &str, coin: &str) -> Self {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(Duration::from_secs(30));
        CryptoidObserver {
            http: builder.build().unwrap_or_default(),
            base: base.trim_end_matches('/').to_string(),
            coin: coin.to_string(),
            next_query: Mutex::new(0),
            mtp: Mutex::new(None),
        }
    }

    /// GET `path` as JSON. 5xx, 429 and 412 ("block number out of range", a tip race) are
    /// transient; any other non-2xx is not.
    async fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{}/{path}", self.base);
        let what = path.split('?').next().unwrap_or(path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| SwapError::Transient(format!("cryptoid {what}: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| SwapError::Transient(format!("cryptoid {what}: {e}")))?;
        let short: String = text.chars().take(120).collect();
        if status.is_server_error() || matches!(status.as_u16(), 412 | 429) {
            return Err(SwapError::Transient(format!(
                "cryptoid {what}: HTTP {status}: {short}"
            )));
        }
        if !status.is_success() {
            return Err(SwapError::Other(format!(
                "cryptoid {what}: HTTP {status}: {short}"
            )));
        }
        serde_json::from_str(&text)
            .map_err(|e| SwapError::Transient(format!("cryptoid {what}: not JSON ({e}): {short}")))
    }

    /// A Query API call, spaced at least [`QUERY_GAP_SECS`] from the previous one.
    async fn query(&self, q: &str) -> Result<Value> {
        loop {
            let wait = {
                let mut next = self.next_query.lock();
                let now = divi_swap::rt::unix_now();
                if now >= *next {
                    *next = now + QUERY_GAP_SECS;
                    0
                } else {
                    *next - now
                }
            };
            if wait == 0 {
                break;
            }
            divi_swap::rt::sleep(Duration::from_secs(wait)).await;
        }
        self.get(&format!("{}/api.dws?q={q}", self.coin)).await
    }

    async fn get_tx(&self, txid: &Txid) -> Result<Option<Value>> {
        let tx = self
            .get(&format!(
                "explorer/tx.raw.dws?coin={}&id={}",
                self.coin,
                txid.to_rpc_hex()
            ))
            .await?;
        // An unknown txid is HTTP 200 with the JSON string "unknown".
        Ok(tx.is_object().then_some(tx))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Observer for CryptoidObserver {
    fn name(&self) -> &str {
        "cryptoid"
    }

    async fn median_time_past(&self) -> Result<u32> {
        let now = divi_swap::rt::unix_now();
        if let Some((at, mtp)) = *self.mtp.lock() {
            if now < at + MTP_TTL_SECS {
                return Ok(mtp);
            }
        }
        let tip = self.query("getblockcount").await?;
        let tip = tip
            .as_u64()
            .or_else(|| tip.as_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| SwapError::Transient(format!("cryptoid getblockcount: {tip}")))?;
        let mut times = Vec::with_capacity(11);
        for h in (tip.saturating_sub(10)..=tip).rev() {
            let block = self
                .get(&format!(
                    "explorer/block.raw.dws?coin={}&height={h}",
                    self.coin
                ))
                .await?;
            times.push(block_time(&block)?);
        }
        let mtp = median(times)?;
        *self.mtp.lock() = Some((now, mtp));
        Ok(mtp)
    }

    async fn tx(&self, txid: &Txid) -> Result<Option<ObservedTx>> {
        Ok(self.get_tx(txid).await?.as_ref().map(observed_tx))
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<ObservedLock>> {
        match self.get_tx(&at.txid).await? {
            Some(tx) => observed_lock(&tx, htlc, at.vout),
            None => Ok(None),
        }
    }
}
