// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The engine's own checks of a counterparty lock against the agreed terms, at the two
//! acting points: the maker funds its leg only against a taker lock whose script matches
//! (`htlc_output` returns it) and whose value covers the taker-leg amount; the taker reveals
//! the preimage only against a maker lock with our hash, our claim key, the quote's maker
//! refund key, a matching script and the full maker-leg amount. A lock read that fails
//! (`Transient`, as a cross-checked backend answers when its sources disagree) is a wait at
//! both points, never an act. Both directions, LTC as the counter chain.

use async_trait::async_trait;
use divi_swap::api::{Direction, Offer, SwapView};
use divi_swap::backend::TipHeader;
use divi_swap::mock::{MockBackend, MockChain, TxKind};
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimSizes, FeeBump, Funding, HtlcParams, LockedOutput, Maker,
    Outpoint, Profile, Result, SignedTx, SpendInfo, Store, SwapConfig, SwapError, SwapState, Taker,
    TakerState, Txid,
};
use std::sync::{Arc, Mutex};

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;

/// What a lock read shows, whatever the chain holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lie {
    Honest,
    /// The output's script is not the agreed HTLC's: a backend returns `None`.
    OtherScript,
    /// The agreed script, one satoshi short of what the chain holds.
    Short,
    /// The read fails (a cross-checked backend whose sources disagree, or are down).
    Transient,
}

/// A [`MockBackend`] whose `htlc_output` answers per [`Lie`]; everything else delegates.
#[derive(Clone)]
struct Reader(MockBackend, Arc<Mutex<Lie>>);

impl Reader {
    fn new(b: MockBackend) -> Self {
        Reader(b, Arc::new(Mutex::new(Lie::Honest)))
    }
    fn lie(&self, l: Lie) {
        *self.1.lock().unwrap() = l;
    }
}

#[async_trait]
impl ChainBackend for Reader {
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
        self.0.median_time_past().await
    }
    fn refund_final(&self, mtp: u32, locktime: u32) -> bool {
        self.0.refund_final(mtp, locktime)
    }
    async fn tip_header(&self) -> Result<TipHeader> {
        self.0.tip_header().await
    }
    async fn in_best_chain(&self, height: u64, hash: &str) -> Result<bool> {
        self.0.in_best_chain(height, hash).await
    }
    fn target_block_secs(&self) -> Option<u32> {
        self.0.target_block_secs()
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
        let lie = *self.1.lock().unwrap();
        let real = self.0.htlc_output(htlc, at).await?;
        match lie {
            Lie::Honest => Ok(real),
            Lie::OtherScript => Ok(None),
            Lie::Short => Ok(real.map(|lo| LockedOutput {
                amount: Amount(lo.amount.0 - 1),
                ..lo
            })),
            Lie::Transient => Err(SwapError::Transient(
                "ltc lock cross-check FAILED (test)".into(),
            )),
        }
    }
    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        self.0.find_spend(outpoint, from_height).await
    }
    async fn release_dead_lock(&self, lock: &SignedTx) -> Result<bool> {
        self.0.release_dead_lock(lock).await
    }
    async fn spendable(&self) -> Result<Option<Amount>> {
        self.0.spendable().await
    }
    fn fee_bump(&self) -> FeeBump {
        self.0.fee_bump()
    }
    async fn claim_feerate(&self) -> Result<Option<u64>> {
        self.0.claim_feerate().await
    }
    fn claim_sizes(&self, htlc: &HtlcParams) -> Option<ClaimSizes> {
        self.0.claim_sizes(htlc)
    }
    async fn build_claim_at(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
        feerate: u64,
    ) -> Result<SignedTx> {
        self.0
            .build_claim_at(htlc, at, amount, preimage, feerate)
            .await
    }
    async fn build_cpfp(
        &self,
        package: &[SignedTx],
        htlc_amount: Amount,
        feerate: u64,
    ) -> Result<SignedTx> {
        self.0.build_cpfp(package, htlc_amount, feerate).await
    }
    async fn build_claim_replacement(
        &self,
        prev: &SignedTx,
        feerate: u64,
        price_bump_pct: u64,
    ) -> Result<Option<SignedTx>> {
        self.0
            .build_claim_replacement(prev, feerate, price_bump_pct)
            .await
    }
}

struct World {
    divi: MockChain,
    ltc: MockChain,
    mdivi: Reader,
    mltc: Reader,
    tdivi: Reader,
    tltc: Reader,
    dir: Direction,
    store: Store,
    maker: Maker,
    taker: Taker,
}

impl World {
    fn new(dir: Direction) -> World {
        let divi = MockChain::new(Chain::Divi, T0, 60);
        let ltc = MockChain::new(Chain::Ltc, T0, 150);
        let mdivi = Reader::new(divi.backend(1, Amount(FUNDS)));
        let mltc = Reader::new(ltc.backend(2, Amount(FUNDS)));
        let tdivi = Reader::new(divi.backend(3, Amount(FUNDS)));
        let tltc = Reader::new(ltc.backend(4, Amount(FUNDS)));
        let store = Store::in_memory().unwrap();
        let maker = Maker::new(
            SwapConfig::profile(Profile::Testnet),
            Arc::new(mdivi.clone()),
            Arc::new(mltc.clone()),
            store.clone(),
            vec![Offer {
                id: "o".into(),
                direction: dir,
                counter_chain: Chain::Ltc,
                divi_sats_per_btc: 50_000_000_000,
                min_btc_sats: 10_000,
                max_btc_sats: 5_000_000,
            }],
        )
        .unwrap();
        let taker = Taker::new(
            Arc::new(tdivi.clone()),
            Arc::new(tltc.clone()),
            store.clone(),
        );
        World {
            divi,
            ltc,
            mdivi,
            mltc,
            tdivi,
            tltc,
            dir,
            store,
            maker,
            taker,
        }
    }

    /// The maker-leg chain.
    fn maker_chain(&self) -> &MockChain {
        match self.dir {
            Direction::TakerPaysBtc => &self.divi,
            Direction::TakerPaysDivi => &self.ltc,
        }
    }

    /// The maker's backend on the maker-leg chain (where it funds).
    fn maker_funder(&self) -> &Reader {
        match self.dir {
            Direction::TakerPaysBtc => &self.mdivi,
            Direction::TakerPaysDivi => &self.mltc,
        }
    }

    /// The maker's backend on the taker-leg chain (where it reads the taker's lock).
    fn maker_reader(&self) -> &Reader {
        match self.dir {
            Direction::TakerPaysBtc => &self.mltc,
            Direction::TakerPaysDivi => &self.mdivi,
        }
    }

    /// The taker's backend on the maker-leg chain (where it reads the maker's lock).
    fn taker_reader(&self) -> &Reader {
        match self.dir {
            Direction::TakerPaysBtc => &self.tdivi,
            Direction::TakerPaysDivi => &self.tltc,
        }
    }

    /// Quote, accept and lock the taker leg; returns (taker swap id, maker swap id).
    async fn through_taker_lock(&self) -> (String, String) {
        let q = self.maker.quote("o", 1_000_000).await.unwrap();
        let (tid, req) = self.taker.prepare(&q).await.unwrap();
        let v = self.maker.accept(req).await.unwrap();
        self.taker.accepted(&tid, &v).await.unwrap();
        let notice = self.taker.lock(&tid).await.unwrap();
        let mid = self.maker.notify_lock(&v.id, notice).await.unwrap().id;
        (tid, mid)
    }

    /// Mine and step both sides `rounds` times; the taker sees the maker's view through
    /// `tamper`.
    async fn run(&self, tid: &str, mid: &str, rounds: usize, tamper: impl Fn(&mut SwapView)) {
        for _ in 0..rounds {
            self.divi.mine(1);
            self.ltc.mine(1);
            let _ = self.maker.tick().await;
            let mut v = self.maker.view(mid).unwrap();
            if let Some(v) = v.as_mut() {
                tamper(v);
            }
            let _ = self.taker.step(tid, v.as_ref()).await;
        }
    }

    fn maker_state(&self, mid: &str) -> (SwapState, Option<String>) {
        let r = self.store.get_maker_swap(mid).unwrap().unwrap();
        (r.state, r.last_error)
    }

    fn taker_claims(&self) -> usize {
        self.maker_chain().attempts(TxKind::Claim)
    }
}

const BOTH: [Direction; 2] = [Direction::TakerPaysBtc, Direction::TakerPaysDivi];

/// Control: the wrapper is transparent; an honest swap completes both ways.
#[tokio::test]
async fn honest_locks_complete_in_both_directions() {
    for dir in BOTH {
        let w = World::new(dir);
        let (tid, mid) = w.through_taker_lock().await;
        w.run(&tid, &mid, 60, |_| {}).await;
        assert_eq!(w.maker_state(&mid).0, SwapState::Done, "{dir:?}");
        let t = w.store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(t.state, TakerState::Done, "{dir:?}");
    }
}

/// Maker, funding path: a confirmed taker lock whose script is not the agreed HTLC's is
/// refused before any coin is selected.
#[tokio::test]
async fn maker_does_not_fund_against_a_taker_lock_with_another_script() {
    for dir in BOTH {
        let w = World::new(dir);
        w.maker_reader().lie(Lie::OtherScript);
        let (tid, mid) = w.through_taker_lock().await;
        w.run(&tid, &mid, 20, |_| {}).await;
        let (state, why) = w.maker_state(&mid);
        assert_eq!(state, SwapState::Aborted, "{dir:?}");
        assert!(why.unwrap().contains("does not match the HTLC"), "{dir:?}");
        assert_eq!(w.maker_funder().0.funding_calls(), 0, "{dir:?}");
    }
}

/// Maker, funding path: a taker lock one satoshi short of the taker-leg amount is refused.
#[tokio::test]
async fn maker_does_not_fund_against_a_short_taker_lock() {
    for dir in BOTH {
        let w = World::new(dir);
        w.maker_reader().lie(Lie::Short);
        let (tid, mid) = w.through_taker_lock().await;
        w.run(&tid, &mid, 20, |_| {}).await;
        let (state, why) = w.maker_state(&mid);
        assert_eq!(state, SwapState::Aborted, "{dir:?}");
        assert!(why.unwrap().contains("underfunded"), "{dir:?}");
        assert_eq!(w.maker_funder().0.funding_calls(), 0, "{dir:?}");
    }
}

/// Maker, funding path: a lock read that fails is a wait, at every state before funding.
#[tokio::test]
async fn maker_does_not_fund_while_the_taker_lock_read_fails() {
    for dir in BOTH {
        let w = World::new(dir);
        w.maker_reader().lie(Lie::Transient);
        let (tid, mid) = w.through_taker_lock().await;
        w.run(&tid, &mid, 20, |_| {}).await;
        let (state, why) = w.maker_state(&mid);
        assert_eq!(state, SwapState::Accepted, "{dir:?}");
        assert!(why.unwrap().contains("cross-check FAILED"), "{dir:?}");
        assert_eq!(w.maker_funder().0.funding_calls(), 0, "{dir:?}");
    }
}

/// Maker, funding path: the read failing after the lock was seen holds the maker in
/// `TakerLockSeen` (or `TakerLockConfirmed`), unfunded.
#[tokio::test]
async fn maker_does_not_fund_when_the_read_fails_after_the_lock_was_seen() {
    for dir in BOTH {
        let w = World::new(dir);
        let (tid, mid) = w.through_taker_lock().await;
        let _ = w.maker.tick().await;
        assert_eq!(w.maker_state(&mid).0, SwapState::TakerLockSeen, "{dir:?}");
        w.maker_reader().lie(Lie::Transient);
        w.run(&tid, &mid, 20, |_| {}).await;
        let (state, _) = w.maker_state(&mid);
        assert!(
            matches!(
                state,
                SwapState::TakerLockSeen | SwapState::TakerLockConfirmed
            ),
            "{dir:?}: {state:?}"
        );
        assert_eq!(w.maker_funder().0.funding_calls(), 0, "{dir:?}");
    }
}

/// Taker, claim path: a maker lock with another script is never claimed (the preimage stays
/// secret).
#[tokio::test]
async fn taker_does_not_claim_a_maker_lock_with_another_script() {
    for dir in BOTH {
        let w = World::new(dir);
        w.taker_reader().lie(Lie::OtherScript);
        let (tid, mid) = w.through_taker_lock().await;
        w.run(&tid, &mid, 30, |_| {}).await;
        assert_eq!(w.taker_claims(), 0, "{dir:?}");
        let t = w.store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(t.maker_leg_htlc.is_none() && t.maker_leg_claim.is_none());
    }
}

/// Taker, claim path: a maker lock short of the maker-leg amount is refused as underfunded.
#[tokio::test]
async fn taker_does_not_claim_a_short_maker_lock() {
    for dir in BOTH {
        let w = World::new(dir);
        w.taker_reader().lie(Lie::Short);
        let (tid, mid) = w.through_taker_lock().await;
        w.run(&tid, &mid, 30, |_| {}).await;
        assert_eq!(w.taker_claims(), 0, "{dir:?}");
        let t = w.store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(t.maker_leg_claim.is_none(), "{dir:?}");
        assert!(
            t.last_error
                .as_deref()
                .unwrap_or("")
                .contains("underfunded")
                || t.state == TakerState::Refunded,
            "{dir:?}: {:?} {:?}",
            t.state,
            t.last_error
        );
    }
}

/// Taker, claim path: a lock read that fails is a wait; the preimage is not revealed.
#[tokio::test]
async fn taker_does_not_claim_while_the_maker_lock_read_fails() {
    for dir in BOTH {
        let w = World::new(dir);
        w.taker_reader().lie(Lie::Transient);
        let (tid, mid) = w.through_taker_lock().await;
        w.run(&tid, &mid, 30, |_| {}).await;
        assert_eq!(w.taker_claims(), 0, "{dir:?}");
        let t = w.store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(t.maker_leg_claim.is_none(), "{dir:?}");
    }
}

/// Taker, claim path: the maker's stated HTLC must carry our hash, our claim key and the
/// quote's maker refund key, whatever the chain shows (the locktime floor is
/// `taker_maker_leg_floor.rs` / `taker_maker_leg_exact.rs`).
#[tokio::test]
async fn taker_does_not_claim_a_maker_lock_with_another_hash_or_keys() {
    type Tamper = fn(&mut SwapView);
    let cases: [(&str, Tamper); 3] = [
        ("wrong hash", |v| {
            if let Some(l) = v.maker_leg.as_mut() {
                l.htlc.hash[0] ^= 1;
            }
        }),
        ("claim key is not ours", |v| {
            if let Some(l) = v.maker_leg.as_mut() {
                l.htlc.claim_pubkey[1] ^= 1;
            }
        }),
        ("refund key is not the quote's maker key", |v| {
            if let Some(l) = v.maker_leg.as_mut() {
                l.htlc.refund_pubkey[1] ^= 1;
            }
        }),
    ];
    for dir in BOTH {
        for (want, tamper) in cases {
            let w = World::new(dir);
            let (tid, mid) = w.through_taker_lock().await;
            w.run(&tid, &mid, 30, tamper).await;
            assert_eq!(w.taker_claims(), 0, "{dir:?} {want}");
            let t = w.store.get_taker_swap(&tid).unwrap().unwrap();
            assert!(t.maker_leg_claim.is_none(), "{dir:?} {want}");
            let err = t.last_error.unwrap_or_default();
            assert!(
                err.contains(want) || t.state == TakerState::Refunded,
                "{dir:?} {want}: {:?} {err}",
                t.state
            );
        }
    }
}
