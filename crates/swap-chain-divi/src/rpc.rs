// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Minimal JSON-RPC client for the services.divi.domains proxy, with retry and error
//! classification. No auth: the proxy allow-lists read methods plus `sendrawtransaction`.

use std::time::Duration;

use divi_swap::SwapError;
use serde_json::{json, Value};

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
}

impl RpcClient {
    /// New client for `url`.
    pub fn new(url: &str, retry: RetryPolicy) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        RpcClient {
            http,
            url: url.to_string(),
            retry,
        }
    }

    /// Call `method`; transient failures are retried with exponential backoff.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let attempts = self.retry.attempts.max(1);
        let mut delay = self.retry.base_delay;
        let mut last = RpcError::Swap(SwapError::Transient("no attempt made".into()));
        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::time::sleep(delay).await;
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
                return Err(RpcError::Node {
                    code: err["code"].as_i64().unwrap_or(0),
                    message: err["message"].as_str().unwrap_or("").to_string(),
                });
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
