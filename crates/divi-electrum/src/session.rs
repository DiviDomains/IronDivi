// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! One client connection: JSON-RPC requests in, replies and subscription
//! notifications out. Over TCP and TLS a message is a line; over WebSocket it
//! is a text frame. The session logic is the same for both.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use divi_primitives::hash::Hash256;
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};

use crate::backend::{parse_scripthash, Backend, ElectrumError, HistoryEntry, Result};

/// Longest request line accepted
const MAX_LINE: usize = 4 * 1024 * 1024;
/// Most scripthashes one connection may subscribe to
const MAX_SUBSCRIPTIONS: usize = 20_000;
/// Protocol version spoken
pub const PROTOCOL_VERSION: &str = "1.4";

pub fn server_version() -> String {
    format!("IronDivi {}", env!("CARGO_PKG_VERSION"))
}

struct Session {
    backend: Arc<Backend>,
    banner: Arc<String>,
    /// The tip hash last sent, once the client subscribed to headers
    headers: Option<Option<Hash256>>,
    /// Subscribed scripthashes (as shown) with the status last sent
    scripthashes: HashMap<String, ([u8; 32], Option<String>)>,
    fingerprint: Option<[u8; 32]>,
}

async fn blocking<T, F>(backend: &Arc<Backend>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Backend) -> Result<T> + Send + 'static,
{
    let backend = backend.clone();
    tokio::task::spawn_blocking(move || f(&backend))
        .await
        .map_err(|e| ElectrumError::daemon(format!("task failed: {e}")))?
}

/// Positional argument `i`, or the named one when the params are an object
fn arg<'a>(params: &'a Value, i: usize, name: &str) -> Option<&'a Value> {
    match params {
        Value::Array(items) => items.get(i),
        Value::Object(map) => map.get(name),
        _ => None,
    }
    .filter(|v| !v.is_null())
}

fn str_arg<'a>(params: &'a Value, i: usize, name: &str) -> Result<&'a str> {
    arg(params, i, name)
        .and_then(Value::as_str)
        .ok_or_else(|| ElectrumError::bad_request(format!("missing or invalid {name}")))
}

fn u32_arg(params: &Value, i: usize, name: &str) -> Result<u32> {
    arg(params, i, name)
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| ElectrumError::bad_request(format!("missing or invalid {name}")))
}

fn opt_u32_arg(params: &Value, i: usize, name: &str) -> Result<u32> {
    match arg(params, i, name) {
        None => Ok(0),
        Some(_) => u32_arg(params, i, name),
    }
}

fn txid_arg(params: &Value, i: usize) -> Result<Hash256> {
    let s = str_arg(params, i, "tx_hash")?;
    Hash256::from_hex(s).map_err(|_| ElectrumError::bad_request(format!("invalid tx_hash {s}")))
}

fn no_checkpoint(params: &Value, i: usize) -> Result<()> {
    if opt_u32_arg(params, i, "cp_height")? != 0 {
        return Err(ElectrumError::bad_request("cp_height is not supported"));
    }
    Ok(())
}

fn history_json(history: &[HistoryEntry]) -> Value {
    Value::Array(
        history
            .iter()
            .map(|h| match h.fee {
                Some(fee) => json!({ "tx_hash": h.txid.to_hex(), "height": h.height, "fee": fee }),
                None => json!({ "tx_hash": h.txid.to_hex(), "height": h.height }),
            })
            .collect(),
    )
}

impl Session {
    async fn call(&mut self, method: &str, params: &Value) -> Result<Value> {
        match method {
            "server.version" => Ok(json!([server_version(), PROTOCOL_VERSION])),
            "server.ping" => Ok(Value::Null),
            "server.banner" => Ok(json!(self.banner.as_str())),
            "server.donation_address" => Ok(json!("")),
            "server.peers.subscribe" => Ok(json!([])),
            "server.features" => {
                let genesis = blocking(&self.backend, |b| Ok(b.genesis_hash())).await?;
                Ok(json!({
                    "genesis_hash": genesis.to_hex(),
                    "hosts": {},
                    "protocol_min": PROTOCOL_VERSION,
                    "protocol_max": PROTOCOL_VERSION,
                    "pruning": null,
                    "server_version": server_version(),
                    "hash_function": "sha256",
                }))
            }
            "mempool.get_fee_histogram" => Ok(json!([])),
            "blockchain.headers.subscribe" => {
                let (tip, hash) = blocking(&self.backend, |b| Ok((b.tip()?, b.tip_hash()))).await?;
                self.headers = Some(hash);
                Ok(tip)
            }
            "blockchain.block.header" => {
                let height = u32_arg(params, 0, "height")?;
                no_checkpoint(params, 1)?;
                Ok(json!(
                    blocking(&self.backend, move |b| b.header(height)).await?
                ))
            }
            "blockchain.block.headers" => {
                let start = u32_arg(params, 0, "start_height")?;
                let count = u32_arg(params, 1, "count")?;
                no_checkpoint(params, 2)?;
                blocking(&self.backend, move |b| b.headers(start, count)).await
            }
            "blockchain.scripthash.get_balance" => {
                let sh = parse_scripthash(str_arg(params, 0, "scripthash")?)?;
                let (confirmed, unconfirmed) =
                    blocking(&self.backend, move |b| b.balance(&sh)).await?;
                Ok(json!({ "confirmed": confirmed, "unconfirmed": unconfirmed }))
            }
            "blockchain.scripthash.get_history" => {
                let sh = parse_scripthash(str_arg(params, 0, "scripthash")?)?;
                let history = blocking(&self.backend, move |b| b.history(&sh)).await?;
                Ok(history_json(&history))
            }
            "blockchain.scripthash.get_mempool" => {
                let sh = parse_scripthash(str_arg(params, 0, "scripthash")?)?;
                let history = blocking(&self.backend, move |b| b.mempool_history(&sh)).await?;
                Ok(history_json(&history))
            }
            "blockchain.scripthash.listunspent" => {
                let sh = parse_scripthash(str_arg(params, 0, "scripthash")?)?;
                let unspent = blocking(&self.backend, move |b| b.listunspent(&sh)).await?;
                Ok(Value::Array(
                    unspent
                        .iter()
                        .map(|u| {
                            json!({
                                "tx_hash": u.txid.to_hex(),
                                "tx_pos": u.vout,
                                "height": u.height,
                                "value": u.value,
                            })
                        })
                        .collect(),
                ))
            }
            "blockchain.scripthash.subscribe" => {
                let shown = str_arg(params, 0, "scripthash")?.to_ascii_lowercase();
                let sh = parse_scripthash(&shown)?;
                if !self.scripthashes.contains_key(&shown)
                    && self.scripthashes.len() >= MAX_SUBSCRIPTIONS
                {
                    return Err(ElectrumError::bad_request("too many subscriptions"));
                }
                let status = blocking(&self.backend, move |b| b.status(&sh)).await?;
                self.scripthashes.insert(shown, (sh, status.clone()));
                Ok(json!(status))
            }
            "blockchain.scripthash.unsubscribe" => {
                let shown = str_arg(params, 0, "scripthash")?.to_ascii_lowercase();
                Ok(json!(self.scripthashes.remove(&shown).is_some()))
            }
            "blockchain.transaction.get" => {
                let txid = txid_arg(params, 0)?;
                let verbose = arg(params, 1, "verbose")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if verbose {
                    blocking(&self.backend, move |b| {
                        b.rpc("getrawtransaction", vec![json!(txid.to_hex()), json!(1)])
                    })
                    .await
                } else {
                    let raw = blocking(&self.backend, move |b| b.raw_transaction(&txid)).await?;
                    Ok(json!(hex::encode(raw)))
                }
            }
            "blockchain.transaction.broadcast" => {
                let raw = str_arg(params, 0, "raw_tx")?.to_string();
                blocking(&self.backend, move |b| {
                    b.rpc("sendrawtransaction", vec![json!(raw)])
                })
                .await
            }
            "blockchain.transaction.get_merkle" => {
                let txid = txid_arg(params, 0)?;
                let height = u32_arg(params, 1, "height")?;
                blocking(&self.backend, move |b| b.merkle(&txid, height)).await
            }
            "blockchain.estimatefee" => {
                let blocks = u32_arg(params, 0, "number")?;
                Ok(json!(
                    blocking(&self.backend, move |b| Ok(b.estimate_fee(blocks))).await?
                ))
            }
            "blockchain.relayfee" => {
                Ok(json!(blocking(&self.backend, |b| Ok(b.relay_fee())).await?))
            }
            _ => Err(ElectrumError {
                code: -32601,
                message: format!("unknown method {method}"),
            }),
        }
    }

    /// The reply to one request object, or None for a notification
    async fn reply(&mut self, request: &Value) -> Option<Value> {
        let Some(object) = request.as_object() else {
            return Some(error_reply(Value::Null, -32600, "invalid request"));
        };
        let id = object.get("id").cloned();
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Some(error_reply(
                id.unwrap_or(Value::Null),
                -32600,
                "invalid request",
            ));
        };
        let params = object.get("params").cloned().unwrap_or(json!([]));
        let result = self.call(method, &params).await;
        let id = id?;
        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => error_reply(id, e.code, &e.message),
        })
    }

    async fn handle_line(&mut self, line: &str) -> Option<Value> {
        let request: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Some(error_reply(Value::Null, -32700, "parse error")),
        };
        match request {
            Value::Array(batch) => {
                if batch.is_empty() {
                    return Some(error_reply(Value::Null, -32600, "empty batch"));
                }
                let mut replies = Vec::new();
                for item in &batch {
                    if let Some(reply) = self.reply(item).await {
                        replies.push(reply);
                    }
                }
                (!replies.is_empty()).then_some(Value::Array(replies))
            }
            other => self.reply(&other).await,
        }
    }

    /// Notifications for whatever changed since the last tick
    async fn tick(&mut self) -> Result<Vec<Value>> {
        if self.headers.is_none() && self.scripthashes.is_empty() {
            return Ok(Vec::new());
        }
        let fingerprint = blocking(&self.backend, |b| Ok(b.fingerprint())).await?;
        if self.fingerprint == Some(fingerprint) {
            return Ok(Vec::new());
        }
        self.fingerprint = Some(fingerprint);
        let mut out = Vec::new();
        if let Some(last) = self.headers {
            let (tip, hash) = blocking(&self.backend, |b| Ok((b.tip()?, b.tip_hash()))).await?;
            if hash != last {
                self.headers = Some(hash);
                out.push(notification("blockchain.headers.subscribe", json!([tip])));
            }
        }
        let subscribed: Vec<(String, [u8; 32], Option<String>)> = self
            .scripthashes
            .iter()
            .map(|(shown, (sh, status))| (shown.clone(), *sh, status.clone()))
            .collect();
        let statuses = blocking(&self.backend, move |b| {
            subscribed
                .into_iter()
                .map(|(shown, sh, last)| Ok((shown, b.status(&sh)?, last)))
                .collect::<Result<Vec<_>>>()
        })
        .await?;
        for (shown, status, last) in statuses {
            if status != last {
                if let Some(entry) = self.scripthashes.get_mut(&shown) {
                    entry.1 = status.clone();
                }
                out.push(notification(
                    "blockchain.scripthash.subscribe",
                    json!([shown, status]),
                ));
            }
        }
        Ok(out)
    }
}

fn error_reply(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn notification(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": method, "params": params })
}

/// Longest request accepted, over any transport
pub const MAX_MESSAGE: usize = MAX_LINE;

/// Serves one newline-delimited connection until the client leaves or it errors
pub async fn run<S>(stream: S, backend: Arc<Backend>, banner: Arc<String>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (reader, writer) = tokio::io::split(stream);
    let lines = FramedRead::new(reader, LinesCodec::new_with_max_length(MAX_LINE));
    let out = FramedWrite::new(writer, LinesCodec::new());
    run_messages(lines, out, backend, banner).await
}

/// Serves one connection whose requests arrive as `incoming` messages and
/// whose replies go to `outgoing`, until either side ends or errors
pub async fn run_messages<I, E, O>(
    mut incoming: I,
    mut outgoing: O,
    backend: Arc<Backend>,
    banner: Arc<String>,
) where
    I: Stream<Item = std::result::Result<String, E>> + Unpin,
    E: std::fmt::Display,
    O: Sink<String> + Unpin,
{
    let mut session = Session {
        backend,
        banner,
        headers: None,
        scripthashes: HashMap::new(),
        fingerprint: None,
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            line = incoming.next() => {
                let line = match line {
                    Some(Ok(line)) => line,
                    Some(Err(e)) => {
                        tracing::debug!("electrum: closing connection: {e}");
                        return;
                    }
                    None => return,
                };
                if line.trim().is_empty() {
                    continue;
                }
                if let Some(reply) = session.handle_line(&line).await {
                    if outgoing.send(reply.to_string()).await.is_err() {
                        return;
                    }
                }
            }
            _ = ticker.tick() => {
                match session.tick().await {
                    Ok(notifications) => {
                        for n in notifications {
                            if outgoing.send(n.to_string()).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => tracing::debug!("electrum: notification check failed: {}", e.message),
                }
            }
        }
    }
}
