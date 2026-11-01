// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A hand-written client for lightwalletd's `CompactTxStreamer` gRPC service — step 0's
//! chosen primary testnet API (see `- decisions:` in `docs/plans/swap-poc/status/zec.md`).
//!
//! No `build.rs`/`protoc`: the handful of request/response messages we use are implemented
//! directly with `#[derive(prost::Message)]` against the field numbers in
//! <https://github.com/zcash/lightwalletd/blob/master/lightwallet-protocol/walletrpc/{service,compact_formats}.proto>,
//! and the unary/streaming calls are made through `tonic::client::Grpc` without
//! `tonic-build`-generated stubs.

use std::future::Future;
use std::time::Duration;

use tonic::transport::{Channel, ClientTlsConfig};
use tonic::Status;

use divi_swap::SwapError;

// ---- Wire messages (CompactTxStreamer) ---------------------------------------------------

/// `cash.z.wallet.sdk.rpc.ChainSpec`
#[derive(Clone, PartialEq, prost::Message)]
pub struct ChainSpec {}

/// `cash.z.wallet.sdk.rpc.Empty`
#[derive(Clone, PartialEq, prost::Message)]
pub struct Empty {}

/// `cash.z.wallet.sdk.rpc.BlockID`
#[derive(Clone, PartialEq, prost::Message)]
pub struct BlockId {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: Vec<u8>,
}

/// `cash.z.wallet.sdk.rpc.BlockRange`
#[derive(Clone, PartialEq, prost::Message)]
pub struct BlockRange {
    #[prost(message, optional, tag = "1")]
    pub start: Option<BlockId>,
    #[prost(message, optional, tag = "2")]
    pub end: Option<BlockId>,
    /// `repeated PoolType poolTypes`. Empty means Sapling + Orchard only (lightwalletd's
    /// backward-compatible default), which strips every `CompactTx.vin` — so a transparent
    /// HTLC spend is invisible unless this asks for [`POOL_TYPE_TRANSPARENT`].
    #[prost(int32, repeated, tag = "3")]
    pub pool_types: Vec<i32>,
}

/// `cash.z.wallet.sdk.rpc.PoolType.TRANSPARENT`.
pub const POOL_TYPE_TRANSPARENT: i32 = 1;

/// The `GetBlockRange` request for `start..=end`, asking for transparent data only:
/// `find_spend` reads `CompactTx.vin`, nothing here reads shielded data.
fn block_range_request(start: u64, end: u64) -> BlockRange {
    BlockRange {
        start: Some(BlockId {
            height: start,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: end,
            hash: vec![],
        }),
        pool_types: vec![POOL_TYPE_TRANSPARENT],
    }
}

/// `cash.z.wallet.sdk.rpc.TxFilter`
#[derive(Clone, PartialEq, prost::Message)]
pub struct TxFilter {
    #[prost(message, optional, tag = "1")]
    pub block: Option<BlockId>,
    #[prost(uint64, tag = "2")]
    pub index: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub hash: Vec<u8>,
}

/// `cash.z.wallet.sdk.rpc.RawTransaction`
#[derive(Clone, PartialEq, prost::Message)]
pub struct RawTransaction {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub height: u64,
}

/// `cash.z.wallet.sdk.rpc.SendResponse`
#[derive(Clone, PartialEq, prost::Message)]
pub struct SendResponse {
    #[prost(int32, tag = "1")]
    pub error_code: i32,
    #[prost(string, tag = "2")]
    pub error_message: String,
}

/// `cash.z.wallet.sdk.rpc.LightdInfo` (fields we use; the rest are omitted, which is valid
/// proto3 — absent fields decode to their zero value).
#[derive(Clone, PartialEq, prost::Message)]
pub struct LightdInfo {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "4")]
    pub chain_name: String,
    #[prost(string, tag = "6")]
    pub consensus_branch_id: String,
    #[prost(uint64, tag = "7")]
    pub block_height: u64,
}

/// `cash.z.wallet.sdk.rpc.GetAddressUtxosArg`
#[derive(Clone, PartialEq, prost::Message)]
pub struct GetAddressUtxosArg {
    #[prost(string, repeated, tag = "1")]
    pub addresses: Vec<String>,
    #[prost(uint64, tag = "2")]
    pub start_height: u64,
    #[prost(uint32, tag = "3")]
    pub max_entries: u32,
}

/// `cash.z.wallet.sdk.rpc.GetAddressUtxosReply`
#[derive(Clone, PartialEq, prost::Message)]
pub struct GetAddressUtxosReply {
    #[prost(bytes = "vec", tag = "1")]
    pub txid: Vec<u8>,
    #[prost(int32, tag = "2")]
    pub index: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub script: Vec<u8>,
    #[prost(int64, tag = "4")]
    pub value_zat: i64,
    #[prost(uint64, tag = "5")]
    pub height: u64,
    #[prost(string, tag = "6")]
    pub address: String,
}

/// `cash.z.wallet.sdk.rpc.GetAddressUtxosReplyList`
#[derive(Clone, PartialEq, prost::Message)]
pub struct GetAddressUtxosReplyList {
    #[prost(message, repeated, tag = "1")]
    pub address_utxos: Vec<GetAddressUtxosReply>,
}

/// `cash.z.wallet.sdk.rpc.CompactTxIn` (just enough to find a spend of an outpoint).
#[derive(Clone, PartialEq, prost::Message)]
pub struct CompactTxIn {
    #[prost(bytes = "vec", tag = "1")]
    pub prevout_txid: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prevout_index: u32,
}

/// `cash.z.wallet.sdk.rpc.CompactTx` (fields we use).
#[derive(Clone, PartialEq, prost::Message)]
pub struct CompactTx {
    #[prost(uint64, tag = "1")]
    pub index: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub txid: Vec<u8>,
    #[prost(message, repeated, tag = "7")]
    pub vin: Vec<CompactTxIn>,
}

/// `cash.z.wallet.sdk.rpc.CompactBlock` (fields we use).
#[derive(Clone, PartialEq, prost::Message)]
pub struct CompactBlock {
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(uint32, tag = "5")]
    pub time: u32,
    #[prost(message, repeated, tag = "7")]
    pub vtx: Vec<CompactTx>,
}

// ---- Retry / fallback -----------------------------------------------------------------

/// Retry / backoff settings.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Attempts per endpoint (>= 1).
    pub attempts: u32,
    /// First backoff; doubles each retry.
    pub base_delay: Duration,
    /// Upper bound on any single wait.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 4,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        }
    }
}

/// Outcome of a call that reached (or failed to reach) a lightwalletd endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The server understood and refused: not worth retrying or falling back for.
    Rejected(String),
    /// Connect failure, timeout, or a transient gRPC status (`UNAVAILABLE`, `DEADLINE_EXCEEDED`,
    /// etc.) — worth retrying, including against the next endpoint.
    Transient(String),
}

impl From<ClientError> for SwapError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Rejected(m) => SwapError::Other(format!("lightwalletd: {m}")),
            ClientError::Transient(m) => SwapError::Transient(m),
        }
    }
}

impl From<Status> for ClientError {
    fn from(s: Status) -> Self {
        use tonic::Code;
        match s.code() {
            Code::Unavailable
            | Code::DeadlineExceeded
            | Code::ResourceExhausted
            | Code::Aborted => ClientError::Transient(s.to_string()),
            // This client has no `server` feature compiled in (see Cargo.toml), so
            // tonic's own `Status::from_error` never reaches its h2-reason-specific
            // mapping (that table is `#[cfg(feature = "server")]`); any transport-level
            // failure it can't otherwise explain — a dropped connection mid-stream, a
            // proxy returning a garbled/non-gRPC body — falls through to its generic
            // `Code::Unknown` fallback, and a client-side timeout/cancel surfaces as
            // `Code::Cancelled`. Neither is lightwalletd rejecting anything: both are
            // transient. (`Code::NotFound`/`Code::Internal` stay out of this arm — those
            // carry real lightwalletd signals, e.g. `is_tx_not_found` below depends on a
            // genuine "unknown tx" answer arriving as `Rejected` so it can inspect the
            // message.)
            Code::Unknown | Code::Cancelled => ClientError::Transient(s.to_string()),
            _ => ClientError::Rejected(s.to_string()),
        }
    }
}

/// Whether a rejected `GetTransaction` call's message means "the chain doesn't know this
/// txid" (zcashd's classic `getrawtransaction` wording, or a gRPC `NotFound`) rather than
/// some other failure.
pub(crate) fn is_tx_not_found(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("notfound")
        || m.contains("not found")
        || m.contains("no such mempool or blockchain transaction")
        || m.contains("no information available about transaction")
}

/// Try `attempt` against each of `endpoints` in order; within an endpoint, retry up to
/// `retry.attempts` times (with exponential backoff) on [`ClientError::Transient`], then move
/// on to the next endpoint. [`ClientError::Rejected`] is never retried.
///
/// `attempt` takes an owned endpoint `String` (rather than `&str`) so its returned future's
/// type doesn't need to borrow from this function's loop variable — avoids a higher-ranked
/// lifetime that `FnMut(&str) -> Fut` can't express without boxing.
pub(crate) async fn retry_fallback<T, F, Fut>(
    endpoints: &[String],
    retry: &RetryPolicy,
    mut attempt: F,
) -> Result<T, ClientError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<T, ClientError>>,
{
    let mut last = String::from("no endpoint configured");
    for (i, endpoint) in endpoints.iter().enumerate() {
        let mut delay = retry.base_delay;
        for a in 1..=retry.attempts.max(1) {
            match attempt(endpoint.clone()).await {
                Ok(v) => return Ok(v),
                Err(ClientError::Rejected(m)) => return Err(ClientError::Rejected(m)),
                Err(ClientError::Transient(m)) => {
                    last = format!("{endpoint}: {m}");
                    if a < retry.attempts.max(1) {
                        tracing::debug!(%last, attempt = a, "lightwalletd retry");
                        tokio::time::sleep(delay.min(retry.max_delay)).await;
                        delay = (delay * 2).min(retry.max_delay);
                    }
                }
            }
        }
        if i + 1 < endpoints.len() {
            tracing::warn!(%last, "lightwalletd endpoint exhausted, falling back");
        }
    }
    Err(ClientError::Transient(last))
}

// ---- The client -------------------------------------------------------------------------

/// `cash.z.wallet.sdk.rpc.CompactTxStreamer` client over an ordered list of endpoints
/// (primary first), connecting fresh per call (swaps are infrequent; simplicity over
/// connection pooling).
#[derive(Debug, Clone)]
pub struct LightwalletdClient {
    endpoints: Vec<String>,
    retry: RetryPolicy,
}

const PATH_GET_LATEST_BLOCK: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock";
const PATH_GET_BLOCK_RANGE: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange";
const PATH_GET_TRANSACTION: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction";
const PATH_SEND_TRANSACTION: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction";
const PATH_GET_ADDRESS_UTXOS: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetAddressUtxos";
const PATH_GET_LIGHTD_INFO: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo";

impl LightwalletdClient {
    /// `endpoints`: `https://host:port` base URIs, primary first.
    pub fn new(endpoints: Vec<String>, retry: RetryPolicy) -> Result<Self, SwapError> {
        if endpoints.is_empty() {
            return Err(SwapError::InvalidParams("no lightwalletd endpoints".into()));
        }
        Ok(Self { endpoints, retry })
    }

    async fn connect(endpoint: String) -> Result<Channel, ClientError> {
        let tls = ClientTlsConfig::new().with_webpki_roots();
        let endpoint = Channel::from_shared(endpoint)
            .map_err(|e| ClientError::Rejected(format!("bad endpoint: {e}")))?
            .tls_config(tls)
            .map_err(|e| ClientError::Rejected(format!("tls config: {e}")))?
            .timeout(Duration::from_secs(20));
        endpoint
            .connect()
            .await
            .map_err(|e| ClientError::Transient(format!("connect: {e}")))
    }

    async fn unary<Req, Resp>(
        endpoint: String,
        path: &'static str,
        req: Req,
    ) -> Result<Resp, ClientError>
    where
        Req: prost::Message + Clone + 'static,
        Resp: prost::Message + Default + 'static,
    {
        let channel = Self::connect(endpoint).await?;
        let mut client = tonic::client::Grpc::new(channel);
        client
            .ready()
            .await
            .map_err(|e| ClientError::Transient(format!("not ready: {e}")))?;
        let codec = tonic_prost::ProstCodec::default();
        let path = http::uri::PathAndQuery::try_from(path)
            .map_err(|e| ClientError::Rejected(format!("bad rpc path: {e}")))?;
        let resp = client
            .unary(tonic::Request::new(req), path, codec)
            .await
            .map_err(ClientError::from)?;
        Ok(resp.into_inner())
    }

    async fn server_streaming<Req, Resp>(
        endpoint: String,
        path: &'static str,
        req: Req,
    ) -> Result<Vec<Resp>, ClientError>
    where
        Req: prost::Message + Clone + 'static,
        Resp: prost::Message + Default + 'static,
    {
        let channel = Self::connect(endpoint).await?;
        let mut client = tonic::client::Grpc::new(channel);
        client
            .ready()
            .await
            .map_err(|e| ClientError::Transient(format!("not ready: {e}")))?;
        let codec = tonic_prost::ProstCodec::default();
        let path = http::uri::PathAndQuery::try_from(path)
            .map_err(|e| ClientError::Rejected(format!("bad rpc path: {e}")))?;
        let resp = client
            .server_streaming(tonic::Request::new(req), path, codec)
            .await
            .map_err(ClientError::from)?;
        let mut stream = resp.into_inner();
        let mut out = Vec::new();
        loop {
            match stream.message().await {
                Ok(Some(m)) => out.push(m),
                Ok(None) => break,
                Err(status) => return Err(ClientError::from(status)),
            }
        }
        Ok(out)
    }

    /// `GetLatestBlock`: the tip height.
    pub async fn latest_block(&self) -> Result<BlockId, ClientError> {
        retry_fallback(&self.endpoints, &self.retry, |ep| {
            Self::unary(ep, PATH_GET_LATEST_BLOCK, ChainSpec {})
        })
        .await
    }

    /// `GetBlockRange(start..=end)`, inclusive, increasing height order.
    pub async fn block_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<CompactBlock>, ClientError> {
        let req = block_range_request(start, end);
        retry_fallback(&self.endpoints, &self.retry, |ep| {
            Self::server_streaming(ep, PATH_GET_BLOCK_RANGE, req.clone())
        })
        .await
    }

    /// `GetTransaction` by txid (internal byte order — callers reverse RPC-order hex first).
    pub async fn get_transaction(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<RawTransaction>, ClientError> {
        let req = TxFilter {
            block: None,
            index: 0,
            hash: txid.to_vec(),
        };
        let result = retry_fallback(&self.endpoints, &self.retry, |ep| {
            Self::unary(ep, PATH_GET_TRANSACTION, req.clone())
        })
        .await;
        match result {
            Ok(tx) => Ok(Some(tx)),
            Err(ClientError::Rejected(m)) if is_tx_not_found(&m) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `SendTransaction`.
    pub async fn send_transaction(&self, raw: &[u8]) -> Result<SendResponse, ClientError> {
        let req = RawTransaction {
            data: raw.to_vec(),
            height: 0,
        };
        retry_fallback(&self.endpoints, &self.retry, |ep| {
            Self::unary(ep, PATH_SEND_TRANSACTION, req.clone())
        })
        .await
    }

    /// `GetAddressUtxos` for a single t-address.
    pub async fn address_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<GetAddressUtxosReply>, ClientError> {
        let req = GetAddressUtxosArg {
            addresses: vec![address.to_string()],
            start_height: 0,
            max_entries: 0,
        };
        let list: GetAddressUtxosReplyList = retry_fallback(&self.endpoints, &self.retry, |ep| {
            Self::unary(ep, PATH_GET_ADDRESS_UTXOS, req.clone())
        })
        .await?;
        Ok(list.address_utxos)
    }

    /// `GetLightdInfo`.
    pub async fn lightd_info(&self) -> Result<LightdInfo, ClientError> {
        retry_fallback(&self.endpoints, &self.retry, |ep| {
            Self::unary(ep, PATH_GET_LIGHTD_INFO, Empty {})
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    /// `Code::Unknown` is tonic's generic fallback for a transport-level failure this
    /// client build can't otherwise explain (no `server` feature → no h2-reason table);
    /// `Code::Cancelled` is a benign client-side timeout/cancel. Neither is lightwalletd
    /// rejecting anything — both must retry, not end the swap.
    #[test]
    fn unknown_and_cancelled_status_are_transient() {
        assert!(matches!(
            ClientError::from(Status::new(tonic::Code::Unknown, "stream reset")),
            ClientError::Transient(_)
        ));
        assert!(matches!(
            ClientError::from(Status::new(tonic::Code::Cancelled, "client cancelled")),
            ClientError::Transient(_)
        ));
    }

    /// `Code::NotFound` stays `Rejected` (not folded into the transient set above):
    /// `is_tx_not_found` depends on a genuine "unknown tx" answer arriving this way so it
    /// can inspect the message and turn it into `Ok(None)`, not a hard error.
    #[test]
    fn not_found_status_stays_rejected_for_is_tx_not_found() {
        assert!(matches!(
            ClientError::from(Status::new(tonic::Code::NotFound, "No such transaction")),
            ClientError::Rejected(_)
        ));
    }

    #[test]
    fn is_tx_not_found_recognizes_every_known_wording() {
        for m in [
            "NotFound",
            "transaction not found",
            "No such mempool or blockchain transaction",
            "No information available about transaction",
        ] {
            assert!(is_tx_not_found(m), "{m}");
        }
        assert!(!is_tx_not_found("mandatory-script-verify-flag-failed"));
    }

    /// Without `poolTypes = [TRANSPARENT]` lightwalletd returns every `CompactTx.vin`
    /// empty, so the maker never saw a taker's ZEC claim (live reverse swap, 2026-10-12).
    #[test]
    fn block_range_asks_for_transparent_inputs() {
        use prost::Message;
        let req = block_range_request(10, 20);
        assert_eq!(req.pool_types, vec![POOL_TYPE_TRANSPARENT]);
        let bytes = req.encode_to_vec();
        // Field 3, packed repeated int32: tag 0x1a, length 1, value 1.
        assert!(bytes.ends_with(&[0x1a, 0x01, 0x01]), "{bytes:02x?}");
    }

    fn fast() -> RetryPolicy {
        RetryPolicy {
            attempts: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
        }
    }

    #[tokio::test]
    async fn client_retries_and_falls_back() {
        let endpoints = vec!["primary".to_string(), "secondary".to_string()];
        let retry = fast();
        let calls = AtomicUsize::new(0);

        // The primary is transient-broken for every attempt; the secondary succeeds.
        let result: Result<u32, ClientError> = retry_fallback(&endpoints, &retry, |ep| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if ep == "primary" {
                    Err(ClientError::Transient(format!("call {n} failed")))
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(result, Ok(42));
        // 3 attempts against the primary, then 1 against the secondary.
        assert_eq!(calls.load(Ordering::SeqCst), 4);

        // Every endpoint transient-failing exhausts to a `Transient` error, not a panic/hang.
        let calls2 = AtomicUsize::new(0);
        let result2: Result<u32, ClientError> = retry_fallback(&endpoints, &retry, |_ep| {
            calls2.fetch_add(1, Ordering::SeqCst);
            async move { Err(ClientError::Transient("down".into())) }
        })
        .await;
        assert!(matches!(result2, Err(ClientError::Transient(_))));
        assert_eq!(calls2.load(Ordering::SeqCst), 6); // 3 attempts * 2 endpoints

        // A `Rejected` error short-circuits immediately: no retry, no fallback.
        let calls3 = AtomicUsize::new(0);
        let result3: Result<u32, ClientError> = retry_fallback(&endpoints, &retry, |_ep| {
            calls3.fetch_add(1, Ordering::SeqCst);
            async move { Err(ClientError::Rejected("bad request".into())) }
        })
        .await;
        assert!(matches!(result3, Err(ClientError::Rejected(_))));
        assert_eq!(calls3.load(Ordering::SeqCst), 1);
    }
}
