// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! An in-process lightwalletd for tests: a tonic server on 127.0.0.1 (ephemeral port)
//! answering `GetLatestBlock`, `GetBlock`, `GetBlockRange` and `GetTransaction` of
//! `cash.z.wallet.sdk.rpc.CompactTxStreamer` from a scripted chain, with the crate's own
//! [`grpc`](crate::grpc) wire messages. [`ZecBackend`]'s `tip_header`, `in_best_chain` and
//! the expiry sweep run over real gRPC against it.

use std::convert::Infallible;
use std::future::{ready, Ready};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use secp256k1::SecretKey;
use tonic::body::Body;
use tonic::codegen::{tokio_stream, BoxFuture, Service};
use tonic::server::{Grpc, NamedService, ServerStreamingService, UnaryService};
use tonic::transport::server::TcpIncoming;
use tonic::Status;
use tonic_prost::ProstCodec;

use crate::grpc::{BlockId, BlockRange, ChainSpec, CompactBlock, RawTransaction, TxFilter};
use crate::{FeePolicy, RetryPolicy, ZecBackend};

/// Block time of height 0; each later block is [`SPACING`] s after the one before.
const GENESIS_TIME: u32 = 1_790_000_000;
/// Zcash's post-Blossom target spacing.
const SPACING: u32 = 75;

/// A change to the chain applied right after the next `GetLatestBlock` answer.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Move {
    /// A new block on top.
    Mine,
    /// The tip block replaced by another at the same height.
    ReorgTip,
}

#[derive(Default)]
struct Chain {
    /// The main chain by height: (wire-order hash, time).
    blocks: Vec<([u8; 32], u32)>,
    /// Bumped by each reorg, so replacement blocks get new hashes.
    branch: u8,
    after_latest: Option<Move>,
    /// Method names in call order.
    calls: Vec<&'static str>,
}

impl Chain {
    fn mine(&mut self, n: u64) {
        for _ in 0..n {
            let height = self.blocks.len() as u64;
            let mut hash = [0x5a; 32];
            hash[0] = self.branch;
            hash[24..].copy_from_slice(&height.to_be_bytes());
            self.blocks
                .push((hash, GENESIS_TIME + SPACING * height as u32));
        }
    }

    fn reorg(&mut self, depth: u64) {
        self.branch += 1;
        self.blocks.truncate(self.blocks.len() - depth as usize);
        self.mine(depth);
    }

    fn tip(&self) -> u64 {
        self.blocks.len() as u64 - 1
    }

    fn compact(&self, height: u64) -> Option<CompactBlock> {
        let (hash, time) = *self.blocks.get(height as usize)?;
        Some(CompactBlock {
            height,
            hash: hash.to_vec(),
            time,
            vtx: Vec::new(),
        })
    }
}

/// The running stub; the server stops with the test's runtime.
pub(crate) struct Lightwalletd {
    chain: Arc<Mutex<Chain>>,
    endpoint: String,
}

impl Lightwalletd {
    /// A chain of blocks 0..=`height`, served on a fresh 127.0.0.1 port.
    pub(crate) fn start(height: u64) -> Self {
        let incoming = TcpIncoming::bind(([127, 0, 0, 1], 0).into()).unwrap();
        let addr = incoming.local_addr().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        chain.lock().unwrap().mine(height + 1);
        tokio::spawn(
            tonic::transport::Server::builder().serve_with_incoming(Stub(chain.clone()), incoming),
        );
        Self {
            chain,
            endpoint: format!("http://{addr}"),
        }
    }

    /// A backend on this stub only, one attempt per call.
    pub(crate) fn backend(&self) -> ZecBackend {
        ZecBackend::new(
            vec![self.endpoint.clone()],
            SecretKey::from_slice(&[0x33; 32]).unwrap(),
            FeePolicy::default(),
            RetryPolicy {
                attempts: 1,
                base_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
        )
        .unwrap()
    }

    pub(crate) fn mine(&self, n: u64) {
        self.chain.lock().unwrap().mine(n);
    }

    /// Replace the top `depth` blocks with blocks of new hashes; the height is unchanged.
    pub(crate) fn reorg(&self, depth: u64) {
        self.chain.lock().unwrap().reorg(depth);
    }

    pub(crate) fn after_latest(&self, m: Move) {
        self.chain.lock().unwrap().after_latest = Some(m);
    }

    pub(crate) fn tip_height(&self) -> u64 {
        self.chain.lock().unwrap().tip()
    }

    pub(crate) fn tip_time(&self) -> u32 {
        let c = self.chain.lock().unwrap();
        c.blocks[c.tip() as usize].1
    }

    pub(crate) fn time_at(&self, height: u64) -> u32 {
        self.chain.lock().unwrap().blocks[height as usize].1
    }

    /// The block hash at `height` in explorer (display) order, as `in_best_chain` takes it.
    pub(crate) fn hash_at(&self, height: u64) -> String {
        let mut hash = self.chain.lock().unwrap().blocks[height as usize].0;
        hash.reverse();
        hex::encode(hash)
    }

    /// Give the block at `height` another hash on this stub only (a lying operator).
    pub(crate) fn tamper(&self, height: u64) {
        self.chain.lock().unwrap().blocks[height as usize].0[1] ^= 0xff;
    }

    /// This stub's gRPC base URI.
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn take_calls(&self) -> Vec<&'static str> {
        std::mem::take(&mut self.chain.lock().unwrap().calls)
    }
}

#[derive(Clone)]
struct Stub(Arc<Mutex<Chain>>);

impl NamedService for Stub {
    const NAME: &'static str = "cash.z.wallet.sdk.rpc.CompactTxStreamer";
}

impl Service<http::Request<Body>> for Stub {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let chain = self.0.clone();
        Box::pin(async move {
            let path = req.uri().path().to_string();
            Ok(match path.as_str() {
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock" => {
                    let mut grpc = Grpc::new(ProstCodec::default());
                    grpc.unary(Unary(chain, get_latest_block), req).await
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlock" => {
                    let mut grpc = Grpc::new(ProstCodec::default());
                    grpc.unary(Unary(chain, get_block), req).await
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction" => {
                    let mut grpc = Grpc::new(ProstCodec::default());
                    grpc.unary(Unary(chain, get_transaction), req).await
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange" => {
                    let mut grpc = Grpc::new(ProstCodec::default());
                    grpc.server_streaming(BlockRangeSvc(chain), req).await
                }
                other => Status::unimplemented(other.to_string()).into_http(),
            })
        })
    }
}

/// A unary method answered by `F` under the chain's lock.
struct Unary<F>(Arc<Mutex<Chain>>, F);

impl<Req, Resp, F> UnaryService<Req> for Unary<F>
where
    F: FnMut(&mut Chain, Req) -> Result<Resp, Status>,
{
    type Response = Resp;
    type Future = Ready<Result<tonic::Response<Resp>, Status>>;

    fn call(&mut self, request: tonic::Request<Req>) -> Self::Future {
        let mut chain = self.0.lock().unwrap();
        ready((self.1)(&mut chain, request.into_inner()).map(tonic::Response::new))
    }
}

fn get_latest_block(c: &mut Chain, _: ChainSpec) -> Result<BlockId, Status> {
    c.calls.push("GetLatestBlock");
    let height = c.tip();
    let id = BlockId {
        height,
        hash: c.blocks[height as usize].0.to_vec(),
    };
    match c.after_latest.take() {
        Some(Move::Mine) => c.mine(1),
        Some(Move::ReorgTip) => c.reorg(1),
        None => {}
    }
    Ok(id)
}

/// By height only, like lightwalletd (`frontend/service.go`).
fn get_block(c: &mut Chain, id: BlockId) -> Result<CompactBlock, Status> {
    c.calls.push("GetBlock");
    if !id.hash.is_empty() {
        return Err(Status::invalid_argument(
            "GetBlock: Block hash specifier is not yet implemented",
        ));
    }
    c.compact(id.height)
        .ok_or_else(|| Status::invalid_argument(format!("no block at height {}", id.height)))
}

/// Every transaction is unknown: the locks under test have dropped out.
fn get_transaction(c: &mut Chain, _: TxFilter) -> Result<RawTransaction, Status> {
    c.calls.push("GetTransaction");
    Err(Status::not_found(
        "No such mempool or blockchain transaction",
    ))
}

struct BlockRangeSvc(Arc<Mutex<Chain>>);

impl ServerStreamingService<BlockRange> for BlockRangeSvc {
    type Response = CompactBlock;
    type ResponseStream = tokio_stream::Iter<std::vec::IntoIter<Result<CompactBlock, Status>>>;
    type Future = Ready<Result<tonic::Response<Self::ResponseStream>, Status>>;

    fn call(&mut self, request: tonic::Request<BlockRange>) -> Self::Future {
        let mut c = self.0.lock().unwrap();
        c.calls.push("GetBlockRange");
        let r = request.into_inner();
        let start = r.start.map_or(0, |b| b.height);
        let end = r.end.map_or(0, |b| b.height);
        let blocks: Vec<_> = (start..=end).filter_map(|h| c.compact(h)).map(Ok).collect();
        ready(Ok(tonic::Response::new(tokio_stream::iter(blocks))))
    }
}

mod tests {
    use divi_swap::backend::TipHeader;
    use divi_swap::reservation::EXPIRY_MAX_TIP_LEAD_SECS;
    use divi_swap::{Chain, ChainBackend, InputReservations, Outpoint, SwapError, Txid};

    use super::*;

    const LOCK: Txid = Txid([0x77; 32]);

    /// A reservation held by [`LOCK`], due since long before the stub's genesis.
    fn reserved_lock() -> (InputReservations, [(Txid, u32); 1]) {
        let r = InputReservations::in_memory().unwrap();
        let input = Outpoint {
            txid: Txid([0x66; 32]),
            vout: 0,
        };
        r.reserve(Chain::Zec, &LOCK, &[input]).unwrap();
        (r, [(LOCK, 1_000)])
    }

    #[tokio::test]
    async fn tip_header_over_grpc_takes_height_hash_and_time_from_one_block() {
        let lwd = Lightwalletd::start(100);
        let b = lwd.backend();
        // A block lands between GetLatestBlock and GetBlock.
        lwd.after_latest(Move::Mine);
        let header = b.tip_header().await.unwrap();
        assert_eq!(lwd.tip_height(), 101);
        assert_eq!(
            header,
            TipHeader {
                height: 100,
                hash: lwd.hash_at(100),
                time: lwd.time_at(100),
            }
        );
        assert_eq!(lwd.take_calls(), ["GetLatestBlock", "GetBlock"]);
    }

    #[tokio::test]
    async fn tip_header_over_grpc_refuses_a_tip_reorged_between_the_two_reads() {
        let lwd = Lightwalletd::start(100);
        let b = lwd.backend();
        let before = lwd.hash_at(100);
        // The tip block is replaced between GetLatestBlock and GetBlock.
        lwd.after_latest(Move::ReorgTip);
        let err = b.tip_header().await.unwrap_err();
        assert!(
            matches!(&err, SwapError::Transient(m) if m.contains("moved between reads")),
            "{err:?}"
        );
        let header = b.tip_header().await.unwrap();
        assert_ne!(header.hash, before);
        assert_eq!(
            header,
            TipHeader {
                height: 100,
                hash: lwd.hash_at(100),
                time: lwd.time_at(100),
            }
        );
    }

    #[tokio::test]
    async fn in_best_chain_over_grpc_compares_the_hash_at_that_height() {
        let lwd = Lightwalletd::start(100);
        let b = lwd.backend();
        let old = lwd.hash_at(95);
        assert!(b.in_best_chain(95, &old).await.unwrap());
        assert!(b
            .in_best_chain(95, &old.to_ascii_uppercase())
            .await
            .unwrap());
        lwd.reorg(6);
        assert!(!b.in_best_chain(95, &old).await.unwrap());
        assert!(b.in_best_chain(95, &lwd.hash_at(95)).await.unwrap());
        assert_eq!(
            lwd.take_calls(),
            ["GetBlock", "GetBlock", "GetBlock", "GetBlock"]
        );
        assert!(b.in_best_chain(101, &old).await.is_err());
    }

    #[tokio::test]
    async fn a_zec_tip_past_the_consensus_future_limit_releases_nothing_over_grpc() {
        let lwd = Lightwalletd::start(100);
        let b = lwd.backend();
        let (r, locks) = reserved_lock();

        // The wall clock is one second more than 7200 s behind the tip's time: stale.
        let now = lwd.tip_time() - EXPIRY_MAX_TIP_LEAD_SECS - 1;
        assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
        assert_eq!(r.first_absent_block(Chain::Zec, &LOCK).unwrap(), None);
        assert_eq!(lwd.take_calls(), ["GetLatestBlock", "GetBlock"]);

        // Exactly 7200 s ahead is fresh: the first check records the tip block.
        let now = lwd.tip_time() - EXPIRY_MAX_TIP_LEAD_SECS;
        assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
        assert_eq!(
            r.first_absent_block(Chain::Zec, &LOCK).unwrap(),
            Some((100, Some(lwd.hash_at(100))))
        );

        lwd.mine(6);
        let now = lwd.tip_time() - EXPIRY_MAX_TIP_LEAD_SECS - 1;
        assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
        assert_eq!(r.reserved(Chain::Zec).unwrap().len(), 1);
        assert_eq!(
            r.release_expired(&b, &locks, lwd.tip_time()).await.unwrap(),
            1
        );
        assert!(r.reserved(Chain::Zec).unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_zec_reorg_of_the_first_absent_block_restarts_the_count_over_grpc() {
        let lwd = Lightwalletd::start(100);
        let b = lwd.backend();
        let (r, locks) = reserved_lock();
        assert_eq!(
            r.release_expired(&b, &locks, lwd.tip_time()).await.unwrap(),
            0
        );
        assert_eq!(
            r.first_absent_block(Chain::Zec, &LOCK).unwrap(),
            Some((100, Some(lwd.hash_at(100))))
        );

        // Block 100 is replaced at the same height: the record is off the main chain.
        lwd.reorg(3);
        assert_eq!(
            r.release_expired(&b, &locks, lwd.tip_time()).await.unwrap(),
            0
        );
        assert_eq!(
            r.first_absent_block(Chain::Zec, &LOCK).unwrap(),
            Some((100, Some(lwd.hash_at(100))))
        );

        lwd.mine(5);
        assert_eq!(
            r.release_expired(&b, &locks, lwd.tip_time()).await.unwrap(),
            0
        );
        lwd.mine(1);
        assert_eq!(
            r.release_expired(&b, &locks, lwd.tip_time()).await.unwrap(),
            1
        );
        assert!(r.reserved(Chain::Zec).unwrap().is_empty());
    }

    fn spend_args(b: &ZecBackend) -> (divi_swap::HtlcParams, Outpoint, divi_swap::Amount) {
        let htlc = divi_swap::HtlcParams {
            hash: [0x11; 32],
            claim_pubkey: b.pubkey(),
            refund_pubkey: b.pubkey(),
            locktime: 1_900_000_000,
            script_version: Default::default(),
        };
        let at = Outpoint {
            txid: Txid([0x44; 32]),
            vout: 0,
        };
        (htlc, at, divi_swap::Amount::from_sat(100_000))
    }

    /// The error of a claim and of a refund built on `b` (the stub has no `GetLightdInfo`,
    /// so neither can succeed: what matters is whether the cross-check stopped it first).
    async fn claim_and_refund_errors(b: &ZecBackend) -> [SwapError; 2] {
        let (htlc, at, amount) = spend_args(b);
        [
            b.build_claim(&htlc, &at, amount, &[0x22; 32])
                .await
                .unwrap_err(),
            b.build_refund(&htlc, &at, amount).await.unwrap_err(),
        ]
    }

    fn is_crosscheck_hold(e: &SwapError) -> bool {
        matches!(e, SwapError::Transient(m) if m.contains("cross-check"))
    }

    #[tokio::test]
    async fn no_crosscheck_url_makes_no_extra_request() {
        let lwd = Lightwalletd::start(40);
        let b = lwd.backend().with_crosscheck(None).unwrap();
        b.crosscheck().await.unwrap();
        for e in claim_and_refund_errors(&b).await {
            assert!(!is_crosscheck_hold(&e), "{e:?}");
        }
        assert!(lwd.take_calls().is_empty());
    }

    #[tokio::test]
    async fn an_agreeing_second_operator_lets_claim_and_refund_through() {
        let (lwd, other) = (Lightwalletd::start(40), Lightwalletd::start(40));
        let b = lwd
            .backend()
            .with_crosscheck(Some(other.endpoint().to_string()))
            .unwrap();
        b.crosscheck().await.unwrap();
        for e in claim_and_refund_errors(&b).await {
            assert!(!is_crosscheck_hold(&e), "{e:?}");
        }
        assert!(other.take_calls().contains(&"GetLatestBlock"));
    }

    #[tokio::test]
    async fn a_disagreeing_second_operator_holds_claim_and_refund_and_fails_startup() {
        let (lwd, other) = (Lightwalletd::start(40), Lightwalletd::start(40));
        other.tamper(40);
        let b = lwd
            .backend()
            .with_crosscheck(Some(other.endpoint().to_string()))
            .unwrap();
        assert!(matches!(b.crosscheck().await, Err(SwapError::Transient(_))));
        for e in claim_and_refund_errors(&b).await {
            assert!(is_crosscheck_hold(&e), "{e:?}");
        }
    }

    #[tokio::test]
    async fn an_unreachable_second_operator_holds_claim_and_refund_but_not_startup() {
        let lwd = Lightwalletd::start(40);
        let b = lwd
            .backend()
            .with_crosscheck(Some("http://127.0.0.1:1".into()))
            .unwrap();
        b.crosscheck().await.expect("startup only warns");
        for e in claim_and_refund_errors(&b).await {
            assert!(is_crosscheck_hold(&e), "{e:?}");
        }
    }
}
