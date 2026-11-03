// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `Maker::accept` is atomic: one quote, and one hash, is accepted once, even when two accepts
//! overlap across the median-time-past read.

use async_trait::async_trait;
use divi_swap::api::{AcceptRequest, Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, LockedOutput, Maker, Outpoint, Profile,
    Result, SignedTx, SpendInfo, Store, SwapConfig, Taker, Txid,
};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const T0: u32 = 1_800_000_000;
const BTC_SATS: u64 = 1_000_000;

/// A mock backend whose `median_time_past` really suspends (for the shared number of
/// milliseconds), so an `accept` that checks, awaits and then writes without a gate lets a second
/// `accept` run in the middle, and a stalled node can be simulated.
struct SlowMtp(MockBackend, Arc<AtomicU64>);

#[async_trait]
impl ChainBackend for SlowMtp {
    fn chain(&self) -> Chain {
        self.0.chain()
    }
    fn pubkey(&self) -> [u8; 33] {
        self.0.pubkey()
    }
    async fn tip_height(&self) -> Result<u64> {
        self.0.tip_height().await
    }
    async fn tip_hash(&self) -> Result<String> {
        self.0.tip_hash().await
    }
    async fn median_time_past(&self) -> Result<u32> {
        tokio::time::sleep(Duration::from_millis(self.1.load(Ordering::SeqCst))).await;
        self.0.median_time_past().await
    }
    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        self.0.build_funding(htlc, amount).await
    }
    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx> {
        self.0.build_claim(htlc, at, amount, preimage).await
    }
    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        self.0.build_refund(htlc, at, amount).await
    }
    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        self.0.broadcast(tx).await
    }
    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        self.0.confirmations(txid).await
    }
    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        self.0.htlc_output(htlc, at).await
    }
    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        self.0.find_spend(outpoint, from_height).await
    }
}

struct W {
    maker: Maker,
    taker: Taker,
    store: Store,
    mtp_ms: Arc<AtomicU64>,
    _dir: tempfile::TempDir,
}

fn world() -> W {
    let btc = MockChain::new(Chain::Btc, T0, 600);
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let mdivi = divi.backend(1, Amount(2_000_000_000));
    let mbtc = btc.backend(2, Amount(0));
    let tdivi = divi.backend(3, Amount(0));
    let tbtc = btc.backend(4, Amount(10_000_000));
    let mtp_ms = Arc::new(AtomicU64::new(50));
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("swap.db")).unwrap();
    let offer = Offer {
        id: "o1".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    };
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(SlowMtp(mdivi, mtp_ms.clone())),
        Arc::new(SlowMtp(mbtc, mtp_ms.clone())),
        store.clone(),
        vec![offer],
    )
    .unwrap()
    .with_gate_bound(Duration::from_millis(500))
    .with_clock(Arc::new(|| T0 as u64));
    let taker = Taker::new(Arc::new(tdivi), Arc::new(tbtc), store.clone());
    W {
        maker,
        taker,
        store,
        mtp_ms,
        _dir: dir,
    }
}

async fn request(w: &W) -> AcceptRequest {
    let q = w.maker.quote("o1", BTC_SATS).await.unwrap();
    w.taker.prepare(&q).await.unwrap().1
}

fn is_err_with(r: &Result<divi_swap::api::SwapView>, msg: &str) -> bool {
    r.as_ref()
        .err()
        .is_some_and(|e| e.to_string().contains(msg))
}

#[tokio::test]
async fn concurrent_accepts_of_one_quote_succeed_once() {
    let w = world();
    let req = request(&w).await;
    let (a, b) = tokio::join!(w.maker.accept(req.clone()), w.maker.accept(req.clone()));
    assert_eq!(
        a.is_ok() as u8 + b.is_ok() as u8,
        1,
        "exactly one accept wins"
    );
    let loser = if a.is_ok() { &b } else { &a };
    assert!(is_err_with(loser, "quote already used"), "{loser:?}");
    assert_eq!(w.store.list_maker_swaps().unwrap().len(), 1, "one record");
}

#[tokio::test]
async fn many_concurrent_accepts_of_one_quote_succeed_once() {
    let w = world();
    let req = request(&w).await;
    let results = futures_join(&w, &req, 8).await;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(w.store.list_maker_swaps().unwrap().len(), 1);
}

async fn futures_join(
    w: &W,
    req: &AcceptRequest,
    n: usize,
) -> Vec<Result<divi_swap::api::SwapView>> {
    let maker = &w.maker;
    // All futures are polled from this one task (the maker is borrowed, so no spawn).
    let mut futs: Vec<_> = (0..n)
        .map(|_| Box::pin(maker.accept(req.clone())))
        .collect();
    let mut out = Vec::new();
    std::future::poll_fn(|cx| {
        let mut i = 0;
        while i < futs.len() {
            match futs[i].as_mut().poll(cx) {
                std::task::Poll::Ready(r) => {
                    out.push(r);
                    drop(futs.swap_remove(i));
                }
                std::task::Poll::Pending => i += 1,
            }
        }
        if futs.is_empty() {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    out
}

#[tokio::test]
async fn concurrent_accepts_of_one_hash_on_two_quotes_succeed_once() {
    let w = world();
    let req1 = request(&w).await;
    let q2 = w.maker.quote("o1", BTC_SATS).await.unwrap();
    let mut req2 = req1.clone();
    req2.quote_id = q2.id.clone();
    assert_ne!(req1.quote_id, req2.quote_id);
    assert_eq!(req1.hash, req2.hash);
    let (a, b) = tokio::join!(w.maker.accept(req1), w.maker.accept(req2));
    assert_eq!(
        a.is_ok() as u8 + b.is_ok() as u8,
        1,
        "exactly one accept wins"
    );
    let loser = if a.is_ok() { &b } else { &a };
    assert!(is_err_with(loser, "hash already in use"), "{loser:?}");
    assert_eq!(w.store.list_maker_swaps().unwrap().len(), 1, "one record");
}

#[tokio::test]
async fn sequential_reuse_of_a_quote_and_of_a_hash_is_still_refused() {
    let w = world();
    let req = request(&w).await;
    w.maker.accept(req.clone()).await.unwrap();
    let again = w.maker.accept(req.clone()).await;
    assert!(is_err_with(&again, "quote already used"), "{again:?}");

    let q2 = w.maker.quote("o1", BTC_SATS).await.unwrap();
    let mut req2 = req.clone();
    req2.quote_id = q2.id;
    let dup = w.maker.accept(req2).await;
    assert!(is_err_with(&dup, "hash already in use"), "{dup:?}");
    assert_eq!(w.store.list_maker_swaps().unwrap().len(), 1);
}

#[tokio::test]
async fn distinct_quotes_and_hashes_accepted_concurrently_both_succeed() {
    let w = world();
    let r1 = request(&w).await;
    let r2 = request(&w).await;
    assert_ne!(r1.hash, r2.hash);
    let (a, b) = tokio::join!(w.maker.accept(r1), w.maker.accept(r2));
    a.unwrap();
    b.unwrap();
    assert_eq!(w.store.list_maker_swaps().unwrap().len(), 2);
}

#[tokio::test]
async fn stalled_mtp_read_fails_accept_within_the_bound_without_a_write() {
    let w = world();
    let req = request(&w).await;
    w.mtp_ms.store(3_000, Ordering::SeqCst); // the node stalls, far past the 500 ms bound
    let t = Instant::now();
    let r = w.maker.accept(req.clone()).await;
    let took = t.elapsed();
    assert!(
        matches!(r, Err(divi_swap::SwapError::Transient(_))),
        "{r:?} after {took:?}"
    );
    assert!(took < Duration::from_millis(1_500), "took {took:?}");
    assert!(
        w.store.list_maker_swaps().unwrap().is_empty(),
        "no swap row"
    );
    assert!(
        !w.store.get_quote(&req.quote_id).unwrap().unwrap().used,
        "quote stays unused"
    );

    // The gate was released and the quote is intact: a healthy node accepts the same request.
    w.mtp_ms.store(50, Ordering::SeqCst);
    w.maker.accept(req).await.unwrap();
    assert_eq!(w.store.list_maker_swaps().unwrap().len(), 1);
}

#[tokio::test]
async fn accept_queued_behind_a_stalled_accept_fails_within_its_own_bound() {
    let w = world();
    let (r1, r2) = (request(&w).await, request(&w).await);
    w.mtp_ms.store(3_000, Ordering::SeqCst);
    let t = Instant::now();
    let (a, b) = tokio::join!(w.maker.accept(r1), w.maker.accept(r2));
    // The first holds the gate for its 500 ms read bound; the second then takes the gate and
    // stalls on its own read. Neither waits out the 3 s stall, neither writes.
    assert!(a.is_err() && b.is_err(), "{a:?} {b:?}");
    assert!(
        t.elapsed() < Duration::from_millis(2_500),
        "{:?}",
        t.elapsed()
    );
    assert!(w.store.list_maker_swaps().unwrap().is_empty());
}
