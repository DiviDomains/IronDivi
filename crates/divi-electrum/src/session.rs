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

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use divi_primitives::hash::Hash256;
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};

use crate::backend::{parse_scripthash, Backend, ElectrumError, HistoryEntry, Result};
use crate::limits::{
    self, Budget, IdleClock, TickPacer, Verdict, MAX_BATCH_ITEMS, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES, MAX_SESSION_SUBSCRIPTIONS, REQUEST_TIMEOUT, TICK_CHUNK, WRITE_TIMEOUT,
};

/// Reconcile statuses even when the tip and mempool returned to a prior state.
const STATUS_RECHECK: Duration = Duration::from_secs(120);

/// Longest request line accepted
const MAX_LINE: usize = MAX_REQUEST_BYTES;
/// Protocol version spoken
pub const PROTOCOL_VERSION: &str = "1.4";

pub fn server_version() -> String {
    format!("IronDivi {}", env!("CARGO_PKG_VERSION"))
}

tokio::task_local! {
    /// The connection's peer address, for `rpc-methods.log` (diag A15)
    pub(crate) static PEER: std::net::IpAddr;
}

struct Session {
    backend: Arc<Backend>,
    banner: Arc<String>,
    /// The tip hash last sent, once the client subscribed to headers
    headers: Option<Option<Hash256>>,
    /// Subscribed scripthashes (as shown) with the status last sent
    scripthashes: BTreeMap<String, ([u8; 32], Option<String>)>,
    /// Last key checked during an unfinished fingerprint pass.
    cursor: Option<String>,
    /// The tip and mempool the statuses were last computed for
    fingerprint: Option<[u8; 32]>,
    reconcile_at: Duration,
    started: tokio::time::Instant,
    budget: Budget,
    idle: IdleClock,
    pacer: TickPacer,
    /// Set once the session has run up its hard limit: it ends after the
    /// reply under way
    closing: bool,
}

impl Session {
    fn new(backend: Arc<Backend>, banner: Arc<String>) -> Self {
        Session {
            backend,
            banner,
            headers: None,
            scripthashes: BTreeMap::new(),
            cursor: None,
            fingerprint: None,
            reconcile_at: Duration::ZERO,
            started: tokio::time::Instant::now(),
            budget: Budget::new(Duration::ZERO),
            idle: IdleClock::new(Duration::ZERO),
            pacer: TickPacer::default(),
            closing: false,
        }
    }

    /// Time since the session began, the clock of the limits
    fn now(&self) -> Duration {
        self.started.elapsed()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.backend.subscriptions().give(self.scripthashes.len());
    }
}

/// Runs `f` on the blocking pool, once one of the server's few permits for
/// such calls is free. The permit goes back when the call ends, not when the
/// session stops waiting for it, so abandoned calls still count.
async fn blocking<T, F>(backend: &Arc<Backend>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Backend) -> Result<T> + Send + 'static,
{
    let permit = backend
        .work()
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ElectrumError::daemon("the server is stopping"))?;
    run_blocking(backend, permit, f).await
}

async fn run_blocking<T, F>(backend: &Arc<Backend>, permit: impl Send + 'static, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Backend) -> Result<T> + Send + 'static,
{
    let backend = backend.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f(&backend)
    })
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
            "server.banner" if self.banner.len() > MAX_RESPONSE_BYTES => {
                Err(ElectrumError::bad_request("response too large"))
            }
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
                let (tip, hash) = blocking(&self.backend, Backend::header_snapshot).await?;
                self.headers = Some(Some(hash));
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
                let new = !self.scripthashes.contains_key(&shown);
                if new {
                    if self.scripthashes.len() >= MAX_SESSION_SUBSCRIPTIONS {
                        return Err(ElectrumError::bad_request("too many subscriptions"));
                    }
                    if self.backend.subscriptions().full() {
                        return Err(ElectrumError::bad_request(
                            "the server has too many subscriptions",
                        ));
                    }
                }
                let status = blocking(&self.backend, move |b| b.status(&sh)).await?;
                // taken after the work, so that a request given up on in
                // between holds none
                if new && !self.backend.subscriptions().take() {
                    return Err(ElectrumError::bad_request(
                        "the server has too many subscriptions",
                    ));
                }
                self.scripthashes.insert(shown, (sh, status.clone()));
                let now = self.now();
                self.budget.set_subscriptions(now, self.scripthashes.len());
                Ok(json!(status))
            }
            "blockchain.scripthash.unsubscribe" => {
                let shown = str_arg(params, 0, "scripthash")?.to_ascii_lowercase();
                let removed = self.scripthashes.remove(&shown).is_some();
                if removed {
                    self.backend.subscriptions().give(1);
                    let now = self.now();
                    self.budget.set_subscriptions(now, self.scripthashes.len());
                }
                Ok(json!(removed))
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
                    if raw.len() > MAX_RESPONSE_BYTES / 2 {
                        return Err(ElectrumError::bad_request("response too large"));
                    }
                    Ok(json!(hex::encode(raw)))
                }
            }
            "blockchain.transaction.broadcast" => {
                let raw = str_arg(params, 0, "raw_tx")?.to_string();
                // diag A15: only a loopback client's broadcast is the user's
                let local = PEER.try_with(|ip| ip.is_loopback()).unwrap_or(true);
                blocking(&self.backend, move |b| {
                    let send = || b.rpc("sendrawtransaction", vec![json!(raw)]);
                    if local {
                        send()
                    } else {
                        divi_primitives::diag_rpc::as_remote(send)
                    }
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

    /// The reply to one request object, serialized, or None for a
    /// notification. Its cost is charged first, so a session past its limit
    /// is slowed or ended before the request runs.
    async fn reply(&mut self, request: &Value) -> Option<String> {
        let Some(object) = request.as_object() else {
            return Some(encode_reply(
                error_reply(Value::Null, -32600, "invalid request"),
                MAX_RESPONSE_BYTES,
            ));
        };
        let id = object.get("id").cloned();
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Some(encode_reply(
                error_reply(id.unwrap_or(Value::Null), -32600, "invalid request"),
                MAX_RESPONSE_BYTES,
            ));
        };
        let now = self.now();
        match self.budget.charge(now, limits::method_cost(method)) {
            Verdict::Proceed => {}
            Verdict::Delay(wait) => tokio::time::sleep(wait).await,
            Verdict::Disconnect => {
                self.closing = true;
                return Some(encode_reply(
                    error_reply(
                        id.unwrap_or(Value::Null),
                        1,
                        "excessive resource usage: disconnecting",
                    ),
                    MAX_RESPONSE_BYTES,
                ));
            }
        }
        let params = object.get("params").cloned().unwrap_or(json!([]));
        let transport = divi_primitives::diag_rpc::Transport::Electrum;
        let call = divi_primitives::diag_rpc::begin(method, transport);
        let result = match tokio::time::timeout(REQUEST_TIMEOUT, self.call(method, &params)).await {
            Ok(result) => result,
            Err(_) => Err(ElectrumError::daemon(
                "request timed out: the server is busy",
            )),
        };
        call.finish(
            method,
            transport,
            PEER.try_with(|ip| *ip).ok(),
            false,
            result.as_ref().err().map(|e| (e.code, e.message.as_str())),
        );
        let id = id?;
        let value = match result {
            Ok(result) => {
                let mut reply = json!({ "jsonrpc": "2.0", "id": id });
                reply["result"] = result;
                reply
            }
            Err(e) => error_reply(id, e.code, &e.message),
        };
        let text = encode_reply(value, MAX_RESPONSE_BYTES);
        if limits::counts_bandwidth(method) {
            let now = self.now();
            if self.budget.charge_bytes(now, text.len()) == Verdict::Disconnect {
                self.closing = true;
            }
        }
        Some(text)
    }

    /// The serialized reply to one line: a request, or a batch of them
    async fn handle_line(&mut self, line: &str) -> Option<String> {
        let now = self.now();
        if self.budget.charge_bytes(now, line.len()) == Verdict::Disconnect {
            self.closing = true;
        }
        let request: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                if self.budget.charge(now, 1.0) == Verdict::Disconnect {
                    self.closing = true;
                }
                return Some(encode_reply(
                    error_reply(Value::Null, -32700, "parse error"),
                    MAX_RESPONSE_BYTES,
                ));
            }
        };
        match request {
            Value::Array(batch) => {
                if batch.is_empty() {
                    return Some(encode_reply(
                        error_reply(Value::Null, -32600, "empty batch"),
                        MAX_RESPONSE_BYTES,
                    ));
                }
                if batch.len() > MAX_BATCH_ITEMS {
                    return Some(encode_reply(
                        error_reply(
                            Value::Null,
                            -32600,
                            &format!("batch too large: at most {MAX_BATCH_ITEMS} requests"),
                        ),
                        MAX_RESPONSE_BYTES,
                    ));
                }
                let mut replies = String::from("[");
                for (i, item) in batch.iter().enumerate() {
                    if self.closing {
                        break;
                    }
                    let Some(reply) = self.reply(item).await else {
                        continue;
                    };
                    if !append_batch(
                        &mut replies,
                        &reply,
                        i + 1 < batch.len(),
                        MAX_RESPONSE_BYTES,
                    ) {
                        break;
                    }
                }
                (replies.len() > 1).then(|| {
                    replies.push(']');
                    replies
                })
            }
            other => self.reply(&other).await,
        }
    }

    /// Flush a changed header before starting any status work.
    async fn check_header<O: Sink<String> + Unpin>(
        &mut self,
        out: &mut O,
        permit: &Arc<tokio::sync::OwnedSemaphorePermit>,
    ) -> Result<()> {
        let Some(last) = self.headers else {
            return Ok(());
        };
        let change = run_blocking(&self.backend, permit.clone(), move |b| {
            let hash = b.tip_hash();
            if hash == last {
                Ok(None)
            } else {
                b.header_snapshot().map(Some)
            }
        })
        .await?;
        if let Some((tip, hash)) = change {
            send_notification(
                out,
                notification("blockchain.headers.subscribe", json!([tip])),
            )
            .await?;
            self.headers = Some(Some(hash));
        }
        Ok(())
    }

    /// Flush at most one chunk. Only successful, unfinished work earns
    /// another turn; in particular, a saved cursor alone is not enough.
    async fn check_chunk<O: Sink<String> + Unpin>(
        &mut self,
        out: &mut O,
        permit: &Arc<tokio::sync::OwnedSemaphorePermit>,
    ) -> Result<bool> {
        if self.scripthashes.is_empty() {
            self.cursor = None;
            return Ok(false);
        }
        let pass = if self.cursor.is_none() {
            if !self.pacer.ready(self.now()) {
                return Ok(false);
            }
            let fingerprint =
                run_blocking(&self.backend, permit.clone(), |b| Ok(b.fingerprint())).await?;
            if self.fingerprint == Some(fingerprint) && self.now() < self.reconcile_at {
                return Ok(false);
            }
            Some(fingerprint)
        } else {
            None
        };
        let (chunk, next) = status_chunk(&self.scripthashes, self.cursor.as_ref(), TICK_CHUNK);
        let statuses = run_blocking(&self.backend, permit.clone(), move |b| {
            check_statuses(chunk, |sh| b.status(sh))
        })
        .await?;
        // Keep the starting fingerprint through the pass, even if the chain
        // changes between chunks; the following pass will pick up that change.
        if let Some(start) = pass {
            self.fingerprint = Some(start);
        }
        self.cursor = next;
        if self.cursor.is_none() {
            self.reconcile_at = self.now() + STATUS_RECHECK;
            self.pacer.ran(self.now(), self.scripthashes.len());
        }
        for (shown, status) in statuses {
            let entry = self
                .scripthashes
                .get_mut(&shown)
                .expect("subscribed during tick");
            if status != entry.1 {
                entry.1 = status.clone();
                send_notification(
                    out,
                    notification("blockchain.scripthash.subscribe", json!([shown, status])),
                )
                .await?;
            }
        }
        Ok(self.cursor.is_some())
    }
}

type ScriptChunk = Vec<(String, [u8; 32])>;

fn status_chunk<T>(
    scripts: &BTreeMap<String, ([u8; 32], T)>,
    cursor: Option<&String>,
    limit: usize,
) -> (ScriptChunk, Option<String>) {
    let mut iter = scripts.range::<String, _>((cursor.map_or(Unbounded, Excluded), Unbounded));
    let chunk: ScriptChunk = iter
        .by_ref()
        .take(limit)
        .map(|(key, (sh, _))| (key.clone(), *sh))
        .collect();
    let next = iter
        .next()
        .and_then(|_| chunk.last().map(|(key, _)| key.clone()));
    (chunk, next)
}

fn check_statuses(
    chunk: ScriptChunk,
    mut status: impl FnMut(&[u8; 32]) -> Result<Option<String>>,
) -> Result<Vec<(String, Option<String>)>> {
    chunk
        .into_iter()
        .map(|(key, sh)| Ok((key, status(&sh)?)))
        .collect()
}

const TOO_LARGE: &str =
    r#"{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"response too large"}}"#;
const BATCH_STOP: &str = r#"{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"response too large: batch stopped"}}"#;
const _: () =
    assert!(MAX_RESPONSE_BYTES >= BATCH_STOP.len() + 2 && MAX_RESPONSE_BYTES >= TOO_LARGE.len());

fn append_batch(batch: &mut String, item: &str, more: bool, limit: usize) -> bool {
    if batch.len() > 1 {
        batch.push(',');
    }
    let reserve = 1 + if more { 1 + BATCH_STOP.len() } else { 0 };
    if item.len() > limit.saturating_sub(batch.len() + reserve) {
        batch.push_str(BATCH_STOP);
        return false;
    }
    batch.push_str(item);
    true
}

struct CappedJson {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for CappedJson {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.limit - self.bytes.len() {
            return Err(io::Error::other("JSON size limit"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode(value: &Value, limit: usize) -> Option<String> {
    let mut out = CappedJson {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut out, value).ok()?;
    Some(String::from_utf8(out.bytes).expect("JSON is UTF-8"))
}

fn encode_reply(mut value: Value, limit: usize) -> String {
    assert!(limit >= TOO_LARGE.len());
    encode(&value, limit).unwrap_or_else(|| {
        let id = value["id"].take();
        encode(&error_reply(id, 1, "response too large"), limit).unwrap_or_else(|| TOO_LARGE.into())
    })
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
    incoming: I,
    outgoing: O,
    backend: Arc<Backend>,
    banner: Arc<String>,
) where
    I: Stream<Item = std::result::Result<String, E>> + Unpin,
    E: std::fmt::Display,
    O: Sink<String> + Unpin,
{
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    session_loop(Session::new(backend, banner), incoming, outgoing, |cx| {
        ticker.poll_tick(cx).map(|_| ())
    })
    .await;
}

enum Turn<T> {
    Read(Option<T>),
    IdleTick,
    Expired,
    Notify(Arc<tokio::sync::OwnedSemaphorePermit>),
}

async fn session_loop<I, E, O>(
    mut session: Session,
    mut incoming: I,
    mut outgoing: O,
    mut poll_tick: impl FnMut(&mut Context<'_>) -> Poll<()>,
) where
    I: Stream<Item = std::result::Result<String, E>> + Unpin,
    E: std::fmt::Display,
    O: Sink<String> + Unpin,
{
    // Keep the FIFO waiter across reads. A request can use its own pool even
    // when the notification slot is assigned while handle_line is suspended.
    let mut admission = None;
    let mut header_due = false;
    let mut remaining = 0;
    let mut read_first = false;
    loop {
        // Next borrows the stream: partial lines/frames remain in the
        // codec when a notification turn wins. No competing reader task.
        let work = futures::future::poll_fn(|cx| {
            let ticked = poll_tick(cx).is_ready();
            if ticked {
                if session.idle.expired(session.now()) {
                    return Poll::Ready(Turn::Expired);
                }
                remaining = limits::TICK_BURST_CHUNKS;
                header_due = true;
            }
            if remaining == 0 {
                return Poll::Pending;
            }
            if session.headers.is_none() && session.scripthashes.is_empty() {
                remaining = 0;
                admission = None;
                return Poll::Ready(Turn::IdleTick);
            }
            let waiter = admission.get_or_insert_with(|| {
                Box::pin(session.backend.notifications.clone().acquire_owned())
            });
            use std::future::Future;
            match waiter.as_mut().poll(cx) {
                // Poll the interval again to register for the next idle check.
                Poll::Pending if ticked => Poll::Ready(Turn::IdleTick),
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    admission = None;
                    Poll::Ready(match result {
                        Ok(permit) => Turn::Notify(Arc::new(permit)),
                        Err(_) => Turn::Expired,
                    })
                }
            }
        });
        let turn = if read_first {
            tokio::select! {
                biased;
                line = incoming.next() => Turn::Read(line),
                turn = work => turn,
            }
        } else {
            tokio::select! {
                biased;
                turn = work => turn,
                line = incoming.next() => Turn::Read(line),
            }
        };
        match turn {
            Turn::Read(line) => {
                read_first = false;
                let line = match line {
                    Some(Ok(line)) => line,
                    Some(Err(e)) => {
                        tracing::debug!("electrum: closing connection: {e}");
                        return;
                    }
                    None => return,
                };
                // any message, control frames included, shows the client is there
                let now = session.now();
                session.idle.touch(now);
                if line.trim().is_empty() {
                    if session.budget.charge(now, limits::KEEPALIVE_COST) == Verdict::Disconnect {
                        return;
                    }
                    continue;
                }
                if let Some(reply) = session.handle_line(&line).await {
                    if !send(&mut outgoing, reply).await {
                        return;
                    }
                }
                if session.closing {
                    return;
                }
            }
            Turn::IdleTick => read_first = true,
            Turn::Expired => return,
            Turn::Notify(permit) => {
                read_first = true;
                let real_tick = std::mem::take(&mut header_due);
                let check = async {
                    if real_tick {
                        session.check_header(&mut outgoing, &permit).await?;
                    }
                    session.check_chunk(&mut outgoing, &permit).await
                };
                match check.await {
                    Ok(true) => remaining -= 1,
                    Ok(false) => remaining = 0,
                    Err(e) => {
                        tracing::debug!(
                            "electrum: notification check failed; closing connection: {}",
                            e.message
                        );
                        return;
                    }
                }
            }
        }
    }
}

async fn send_notification<O: Sink<String> + Unpin>(out: &mut O, value: Value) -> Result<()> {
    let message = encode(&value, MAX_RESPONSE_BYTES)
        .ok_or_else(|| ElectrumError::daemon("oversized notification"))?;
    if !send(out, message).await {
        return Err(ElectrumError::daemon("notification write failed"));
    }
    Ok(())
}

/// Sends one message; false when the client is gone or too slow to read it
async fn send<O: Sink<String> + Unpin>(outgoing: &mut O, message: String) -> bool {
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, outgoing.send(message)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_encoding_includes_escapes_envelope_and_error_id() {
        let value = json!({"jsonrpc":"2.0","id":7,"result":"\n".repeat(80)});
        let exact = value.to_string();
        assert_eq!(encode_reply(value.clone(), exact.len()), exact);
        let error: Value = serde_json::from_str(&encode_reply(value, exact.len() - 1)).unwrap();
        assert_eq!(error["id"], 7);
        assert_eq!(error["error"]["message"], "response too large");
        let oversized_id = error_reply(json!("x".repeat(96)), -32600, "invalid request");
        assert_eq!(encode_reply(oversized_id, TOO_LARGE.len()), TOO_LARGE);
    }

    #[test]
    fn batch_reserves_the_comma_error_and_closing_bracket() {
        let limit = 2 + 4 + 1 + BATCH_STOP.len();
        let mut batch = String::from("[");
        assert!(append_batch(&mut batch, "null", true, limit));
        assert!(!append_batch(
            &mut batch,
            &"1".repeat(BATCH_STOP.len() + 1),
            false,
            limit
        ));
        batch.push(']');
        assert_eq!(batch.len(), limit);
        let parsed: Vec<Value> = serde_json::from_str(&batch).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed[1]["error"].is_object());
        let mut single = String::from("[");
        assert!(append_batch(&mut single, "null", false, 6));
        assert_eq!(single + "]", "[null]");
    }

    #[test]
    fn tick_cursor_survives_unsubscribe_and_reports_failed_status() {
        let mut scripts = BTreeMap::from([
            ("a".into(), ([1; 32], ())),
            ("b".into(), ([2; 32], ())),
            ("c".into(), ([3; 32], ())),
        ]);
        let (first, cursor) = status_chunk(&scripts, None, 2);
        assert_eq!(first.len(), 2);
        assert_eq!(cursor.as_deref(), Some("b"));
        scripts.remove("b");
        let (last, end) = status_chunk(&scripts, cursor.as_ref(), 2);
        assert_eq!(last, vec![("c".to_owned(), [3; 32])]);
        assert!(end.is_none());
        let failure = ElectrumError::bad_request("history too large");
        assert_eq!(check_statuses(last, |_| Err(failure.clone())), Err(failure));
    }

    #[derive(Default)]
    struct EmptyMempool(std::sync::atomic::AtomicUsize);

    impl divi_rpc::blockchain::MempoolProvider for EmptyMempool {
        fn get_txids(&self) -> Vec<Hash256> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            vec![]
        }

        fn prioritise_transaction(&self, _: &Hash256, _: f64, _: i64) -> bool {
            false
        }
    }

    fn subscribed(n: usize) -> (tempfile::TempDir, Session, Arc<EmptyMempool>) {
        use divi_storage::{Chain, ChainDatabase, ChainParams, SearchIndex};

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let mut chain = Chain::new(db.clone(), ChainParams::default()).unwrap();
        chain.enable_search_index(Arc::new(SearchIndex::new(db, true, false)));
        let chain = Arc::new(chain);
        let rpc = Arc::new(divi_rpc::RpcServer::new(chain.clone()));
        let pool = Arc::new(EmptyMempool::default());
        let backend = Arc::new(Backend::new(chain, pool.clone(), rpc));
        let mut session = Session::new(backend, Arc::default());
        session.headers = Some(None);
        for i in 0..n {
            let shown = format!("{i:064x}");
            let sh = parse_scripthash(&shown).unwrap();
            assert!(session.backend.subscriptions().take());
            session
                .scripthashes
                .insert(shown, (sh, Some("stale".into())));
        }
        (dir, session, pool)
    }

    fn ping(id: usize) -> std::result::Result<String, std::convert::Infallible> {
        Ok(json!({"jsonrpc":"2.0","id":id,"method":"server.ping"}).to_string())
    }

    #[tokio::test]
    async fn stable_fingerprint_eventually_corrects_transient_status() {
        let (_dir, mut session, _) = subscribed(1);
        session.fingerprint = Some(session.backend.fingerprint());
        let mut out = futures::sink::drain();
        // The stored status was observed between two identical fingerprints.
        let permit = Arc::new(
            session
                .backend
                .notifications
                .clone()
                .acquire_owned()
                .await
                .unwrap(),
        );
        assert!(!session.check_chunk(&mut out, &permit).await.unwrap());
        assert!(session
            .scripthashes
            .values()
            .all(|(_, status)| status.is_none()));
    }

    #[tokio::test]
    async fn a_full_wallet_finishes_in_79_uncontended_ticks() {
        let (_dir, session, _) = subscribed(MAX_SESSION_SUBSCRIPTIONS);
        let statuses = std::cell::Cell::new(0usize);
        let ticks = std::cell::Cell::new(0usize);
        let per_tick = limits::TICK_BURST_CHUNKS * TICK_CHUNK;
        let incoming = futures::stream::poll_fn(|_| {
            if statuses.get() == MAX_SESSION_SUBSCRIPTIONS || ticks.get() > 79 {
                Poll::Ready(None::<std::result::Result<String, std::convert::Infallible>>)
            } else {
                Poll::Pending
            }
        });
        let out = futures::sink::drain().with(|line: String| {
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["method"] == "blockchain.scripthash.subscribe" {
                assert_eq!(message["params"][0], format!("{:064x}", statuses.get()));
                statuses.set(statuses.get() + 1);
            }
            futures::future::ready(Ok::<(), futures::never::Never>(()))
        });
        // On each real tick, require
        // the previous burst to have finished every script it was allowed.
        let mut polls = 0;
        session_loop(session, incoming, out, |_| {
            let tick = polls % limits::TICK_BURST_CHUNKS == 0;
            polls += 1;
            if tick {
                assert_eq!(statuses.get(), ticks.get() * per_tick);
                ticks.set(ticks.get() + 1);
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        assert_eq!(
            (ticks.get(), statuses.get()),
            (79, MAX_SESSION_SUBSCRIPTIONS)
        );
    }

    #[tokio::test]
    async fn a_request_flood_and_a_status_pass_take_turns_within_one_tick() {
        let chunks = limits::TICK_BURST_CHUNKS;
        let (_dir, session, pool) = subscribed((chunks + 1) * TICK_CHUNK);
        let lines = futures::stream::iter((0..chunks + 3).map(ping));
        let mut replies = 0;
        let mut statuses = 0;
        let mut headers = 0;
        let out = futures::sink::drain().with(|line: String| {
            let msg: Value = serde_json::from_str(&line).unwrap();
            match msg["method"].as_str() {
                Some("blockchain.headers.subscribe") => {
                    // Already on the wire before even the fingerprint read.
                    assert_eq!(pool.0.load(std::sync::atomic::Ordering::Relaxed), 0);
                    headers += 1;
                }
                Some("blockchain.scripthash.subscribe") => {
                    assert_eq!(headers, 1);
                    assert_eq!(replies, statuses / TICK_CHUNK);
                    assert_eq!(msg["params"][0], format!("{statuses:064x}"));
                    statuses += 1;
                }
                None => {
                    assert_eq!(msg["id"], replies);
                    assert_eq!(statuses, (replies + 1).min(chunks) * TICK_CHUNK);
                    replies += 1;
                }
                other => panic!("unexpected notification: {other:?}"),
            }
            futures::future::ready(Ok::<(), futures::never::Never>(()))
        });
        let mut tick = Some(());
        session_loop(session, lines, out, |_| {
            tick.take().map_or(Poll::Pending, Poll::Ready)
        })
        .await;
        assert_eq!(
            (headers, statuses, replies),
            (1, chunks * TICK_CHUNK, chunks + 3)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn status_chunks_progress_during_continuous_request_handoffs() {
        let (_dir, session, _) = subscribed(3 * TICK_CHUNK);
        let backend = session.backend.clone();
        let work = backend.work().clone();
        let _occupied = work
            .clone()
            .acquire_many_owned((work.available_permits() - 1) as u32)
            .await
            .unwrap();
        let mut active = Some(work.clone().acquire_owned().await.unwrap());
        let mut replies = 0;
        let mut statuses = 0;
        let out = futures::sink::drain().with(|line: String| {
            let msg: Value = serde_json::from_str(&line).unwrap();
            if msg["method"] == "blockchain.scripthash.subscribe" {
                statuses += 1;
            } else if msg["id"].is_number() {
                // Queue the next request before completing the active one.
                let mut next = Box::pin(work.clone().acquire_owned());
                use futures::FutureExt;
                assert!(next.as_mut().now_or_never().is_none());
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(run_blocking(&backend, active.take().unwrap(), |b| {
                            Ok(b.genesis_hash())
                        }))
                        .unwrap();
                });
                active = Some(next.now_or_never().unwrap().unwrap());
                replies += 1;
                assert_eq!(statuses, replies.min(3) * TICK_CHUNK);
            }
            futures::future::ready(Ok::<(), futures::never::Never>(()))
        });
        let mut tick = Some(());
        session_loop(
            session,
            futures::stream::iter((0..4).map(ping)),
            out,
            |_| tick.take().map_or(Poll::Pending, Poll::Ready),
        )
        .await;
        assert_eq!((statuses, replies), (3 * TICK_CHUNK, 4));
    }

    #[tokio::test]
    async fn a_busy_continuation_serves_requests_and_resumes_in_fifo_order() {
        let (_dir, session, _) = subscribed(3 * TICK_CHUNK);
        let work = session.backend.notifications.clone();
        let permits = work.available_permits() as u32;
        use futures::FutureExt;
        let mut competitor = None;
        let mut held = None;
        let tick = std::cell::Cell::new(true);
        let lines = futures::stream::iter((0..5).map(ping));
        let mut replies = 0;
        let mut statuses = 0;
        let out = futures::sink::drain().with(|line: String| {
            let msg: Value = serde_json::from_str(&line).unwrap();
            if msg["method"] == "blockchain.scripthash.subscribe" {
                assert_eq!(msg["params"][0], format!("{statuses:064x}"));
                statuses += 1;
            } else if msg["id"].is_number() {
                assert_eq!(msg["id"], replies);
                match replies {
                    0 => held = Some(work.clone().try_acquire_many_owned(permits).unwrap()),
                    1 => {
                        // This session is already queued. The later waiter must
                        // remain behind it even though a read won the select.
                        let mut later = Box::pin(work.clone().acquire_owned());
                        assert!(later.as_mut().now_or_never().is_none());
                        drop(held.take());
                        assert!(later.as_mut().now_or_never().is_none());
                        competitor = Some(later);
                    }
                    2 => drop(competitor.take().unwrap().now_or_never().unwrap().unwrap()),

                    _ => (),
                }
                assert_eq!(statuses, [1, 1, 2, 3, 3][replies] * TICK_CHUNK);
                replies += 1;
            }
            futures::future::ready(Ok::<(), futures::never::Never>(()))
        });
        session_loop(session, lines, out, |_| {
            if tick.replace(false) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        assert_eq!((replies, statuses), (5, 3 * TICK_CHUNK));
    }
}
