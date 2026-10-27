// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The lock's terms from both lightwalletd operators (ET). With `[zec].crosscheck_url` set,
//! [`ZecBackend`]'s `htlc_output` (the maker about to fund against the taker's ZEC lock, the
//! taker about to reveal the preimage against the maker's) must see the agreed HTLC script
//! and the same value at the outpoint on the second operator too, and fails closed
//! (`Transient`) otherwise. Off, it reads the primary alone, request for request as before.
//!
//! The backend tests read a lock from two [`Lightwalletd`] stubs; the engine tests run a
//! [`Maker`] and a [`Taker`] on [`MockChain`]s whose ZEC lock reads go through a real
//! cross-checked [`ZecBackend`] (the stubs serve what the mock chain holds, and the second
//! operator what the test makes it say).

use divi_swap::{Amount, ChainBackend, HtlcParams, LockedOutput, Outpoint, SwapError, Txid};

use crate::address::{htlc_script_pubkey, TransparentAddress};
use crate::lwd_stub::{raw_tx, Lightwalletd};
use crate::ZecBackend;

/// The stubs' tip in the backend tests.
const TIP: u64 = 40;
const LOCK: Txid = Txid([0x5e; 32]);
const ZAT: u64 = 250_000;
/// The value of the output in front of the lock.
const FILLER: u64 = 1_000;

fn htlc() -> HtlcParams {
    HtlcParams {
        hash: [0x24; 32],
        claim_pubkey: pk(0x02),
        refund_pubkey: pk(0x03),
        locktime: 1_800_000_000,
        script_version: Default::default(),
    }
}

fn pk(n: u8) -> [u8; 33] {
    let sk = secp256k1::SecretKey::from_slice(&[n; 32]).unwrap();
    sk.public_key(&secp256k1::Secp256k1::new()).serialize()
}

fn at() -> Outpoint {
    Outpoint {
        txid: LOCK,
        vout: 1,
    }
}

fn agreed_spk(h: &HtlcParams) -> Vec<u8> {
    htlc_script_pubkey(&h.redeem_script())
}

fn other_spk() -> Vec<u8> {
    TransparentAddress::p2pkh(&pk(0x09)).script_pubkey()
}

/// A lock transaction: a filler output, then `(value, spk)` at vout 1.
fn lock_tx(value: u64, spk: Vec<u8>) -> Vec<u8> {
    raw_tx(&[(FILLER, other_spk()), (value, spk)])
}

/// Both operators at [`TIP`]; `primary` holds the agreed lock at `height`.
fn pair(height: u64) -> (Lightwalletd, Lightwalletd) {
    let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
    p.put_tx(LOCK.0, lock_tx(ZAT, agreed_spk(&htlc())), height);
    (p, o)
}

fn checked(p: &Lightwalletd, o: &Lightwalletd) -> ZecBackend {
    p.backend()
        .with_crosscheck(Some(o.endpoint().to_string()))
        .unwrap()
}

/// `htlc_output` refused the lock as `Transient`, naming both operators and no secret.
async fn refused(p: &Lightwalletd, o: &Lightwalletd, case: &str) -> String {
    let b = checked(p, o);
    let got = b.htlc_output(&htlc(), &at()).await;
    let Err(SwapError::Transient(m)) = &got else {
        panic!("{case}: the lock was not refused: {got:?}");
    };
    for needle in [p.endpoint(), o.endpoint()] {
        assert!(m.contains(needle), "{case}: {m} lacks {needle}");
    }
    // The stub backend's key ([0x33; 32]) appears in no message.
    assert!(!m.contains(&hex::encode([0x33u8; 32])), "{case}: {m}");
    m.clone()
}

/// Off: the primary alone, `GetTransaction` then (when mined) `GetLatestBlock`, as before;
/// a second operator that is not configured is never asked.
#[tokio::test]
async fn off_reads_the_primary_alone_request_for_request() {
    for (height, confs, calls) in [
        (TIP - 2, 3, &["GetTransaction", "GetLatestBlock"][..]),
        (0, 0, &["GetTransaction"][..]),
    ] {
        let (p, o) = pair(height);
        o.put_tx(LOCK.0, lock_tx(ZAT, other_spk()), height);
        let b = p.backend().with_crosscheck(None).unwrap();
        let got = b.htlc_output(&htlc(), &at()).await.unwrap();
        assert_eq!(
            got,
            Some(LockedOutput {
                amount: Amount::from_sat(ZAT),
                confirmations: confs
            }),
            "{height}"
        );
        assert_eq!(p.take_calls(), calls, "{height}");
        assert!(o.take_calls().is_empty(), "{height}");
        // Another script at the outpoint is still `None` on the primary alone.
        p.put_tx(LOCK.0, lock_tx(ZAT, other_spk()), height);
        assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), None);
    }
}

/// Wrong script: the primary shows the agreed HTLC and the full value, the second operator
/// another scriptPubKey at the outpoint.
#[tokio::test]
async fn a_second_operator_showing_another_script_refuses_the_lock() {
    let (p, o) = pair(TIP - 2);
    o.put_tx(LOCK.0, lock_tx(ZAT, other_spk()), TIP - 2);
    let m = refused(&p, &o, "other script").await;
    assert!(m.contains(&hex::encode(other_spk())), "{m}");
}

/// Short value (and, as values must be equal, a larger one): the agreed script on both.
#[tokio::test]
async fn a_second_operator_showing_another_value_refuses_the_lock() {
    for value in [ZAT - 1, ZAT / 2, ZAT + 1] {
        let (p, o) = pair(TIP - 2);
        o.put_tx(LOCK.0, lock_tx(value, agreed_spk(&htlc())), TIP - 2);
        let m = refused(&p, &o, &format!("value {value}")).await;
        assert!(m.contains(&value.to_string()), "{m}");
    }
}

/// Missing at the second: no such transaction, or no output at the lock's index.
#[tokio::test]
async fn a_lock_the_second_operator_does_not_have_is_refused() {
    let (p, o) = pair(TIP - 2);
    refused(&p, &o, "no such tx").await;
    o.put_tx(LOCK.0, raw_tx(&[(ZAT, agreed_spk(&htlc()))]), TIP - 2);
    refused(&p, &o, "no such vout").await;
}

/// Second operator down: refused (nothing is at risk while the maker waits before funding
/// or the taker before revealing).
#[tokio::test]
async fn an_unreachable_second_operator_refuses_the_lock() {
    let (p, o) = pair(TIP - 2);
    o.put_tx(LOCK.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    o.set_down(true);
    refused(&p, &o, "down").await;
}

/// Both agree: the lock, at the lower of the two confirmation counts.
#[tokio::test]
async fn both_operators_agreeing_give_the_lower_confirmations() {
    for (p_height, o_height, confs) in [
        (TIP - 5, TIP - 2, 3),
        (TIP - 2, TIP - 5, 3),
        (TIP - 5, 0, 0),
        (0, TIP - 5, 0),
    ] {
        let (p, o) = pair(p_height);
        o.put_tx(LOCK.0, lock_tx(ZAT, agreed_spk(&htlc())), o_height);
        let got = checked(&p, &o).htlc_output(&htlc(), &at()).await.unwrap();
        assert_eq!(
            got,
            Some(LockedOutput {
                amount: Amount::from_sat(ZAT),
                confirmations: confs
            }),
            "{p_height}/{o_height}"
        );
        assert!(
            o.take_calls().contains(&"GetTransaction"),
            "{p_height}/{o_height}: the second operator was not asked"
        );
    }
}

/// Nothing to agree when the primary shows no matching lock: no side acts on `None`, and
/// the second operator is not asked.
#[tokio::test]
async fn no_lock_on_the_primary_asks_nothing_of_the_second() {
    let (p, o) = pair(TIP - 2);
    o.put_tx(LOCK.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    p.put_tx(LOCK.0, lock_tx(ZAT, other_spk()), TIP - 2);
    let b = checked(&p, &o);
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), None);
    p.drop_tx(LOCK.0);
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), None);
    assert!(o.take_calls().is_empty());
}

// ---- The engine at both acting points -----------------------------------------------------

/// `#[cfg(test)]` again (the module is test-only already) so the source scan in
/// `divi-swap`'s `taker_floor_entry_points` reads the `Taker::new` below as test code.
#[cfg(test)]
mod engine {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use divi_swap::api::{Direction, Offer};
    use divi_swap::backend::TipHeader;
    use divi_swap::mock::{MockBackend, MockChain, TxKind};
    use divi_swap::{
        Chain, ClaimSizes, FeeBump, Funding, Maker, Profile, Result, SignedTx, SpendInfo, Store,
        SwapConfig, SwapState, Taker, TakerState,
    };

    use super::*;

    const T0: u32 = 1_800_000_000;
    const FUNDS: u64 = 2_000_000_000;
    /// The stubs' tip in the engine tests: above any confirmation count a run reaches.
    const STUB_TIP: u64 = 10_000;

    /// What the second operator shows of a lock the mock chain (and the primary) holds.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Second {
        Honest,
        OtherScript,
        Short,
        NoTx,
        NoVout,
        Down,
    }

    const LIES: [Second; 5] = [
        Second::OtherScript,
        Second::Short,
        Second::NoTx,
        Second::NoVout,
        Second::Down,
    ];

    /// A ZEC [`MockBackend`] whose `htlc_output` is a cross-checked [`ZecBackend`]'s, over two
    /// stubs that serve the mock chain's lock (the primary as it is, the second per [`Second`]).
    #[derive(Clone)]
    struct CrossRead {
        mock: MockBackend,
        zec: Arc<ZecBackend>,
        primary: Arc<Lightwalletd>,
        second: Arc<Lightwalletd>,
        shows: Arc<Mutex<Second>>,
    }

    impl CrossRead {
        fn new(mock: MockBackend) -> Self {
            let (primary, second) = (Lightwalletd::start(STUB_TIP), Lightwalletd::start(STUB_TIP));
            let zec = checked(&primary, &second);
            CrossRead {
                mock,
                zec: Arc::new(zec),
                primary: Arc::new(primary),
                second: Arc::new(second),
                shows: Arc::new(Mutex::new(Second::Honest)),
            }
        }

        fn shows(&self, s: Second) {
            *self.shows.lock().unwrap() = s;
            self.second.set_down(s == Second::Down);
        }

        /// Serve the mock chain's view of `at` on both stubs.
        fn serve(&self, htlc: &HtlcParams, at: &Outpoint, real: Option<LockedOutput>) {
            let Some(lo) = real else {
                self.primary.drop_tx(at.txid.0);
                self.second.drop_tx(at.txid.0);
                return;
            };
            let height = match lo.confirmations {
                0 => 0,
                c => STUB_TIP + 1 - u64::from(c),
            };
            let outputs = |value: u64, spk: Vec<u8>| {
                let mut v = vec![(FILLER, other_spk()); at.vout as usize];
                v.push((value, spk));
                raw_tx(&v)
            };
            let (zat, spk) = (lo.amount.to_sat(), agreed_spk(htlc));
            self.primary
                .put_tx(at.txid.0, outputs(zat, spk.clone()), height);
            match *self.shows.lock().unwrap() {
                Second::Honest | Second::Down => {
                    self.second.put_tx(at.txid.0, outputs(zat, spk), height)
                }
                Second::OtherScript => {
                    self.second
                        .put_tx(at.txid.0, outputs(zat, other_spk()), height)
                }
                Second::Short => self.second.put_tx(at.txid.0, outputs(zat - 1, spk), height),
                Second::NoTx => self.second.drop_tx(at.txid.0),
                Second::NoVout => {
                    let v = vec![(FILLER, other_spk()); at.vout as usize];
                    self.second.put_tx(at.txid.0, raw_tx(&v), height)
                }
            }
        }
    }

    #[async_trait]
    impl ChainBackend for CrossRead {
        fn chain(&self) -> Chain {
            self.mock.chain()
        }
        fn pubkey(&self) -> [u8; 33] {
            self.mock.pubkey()
        }
        async fn tip_height(&self) -> Result<u64> {
            self.mock.tip_height().await
        }
        async fn tip_hash(&self) -> Result<String> {
            self.mock.tip_hash().await
        }
        async fn median_time_past(&self) -> Result<u32> {
            self.mock.median_time_past().await
        }
        fn refund_final(&self, mtp: u32, locktime: u32) -> bool {
            self.mock.refund_final(mtp, locktime)
        }
        async fn tip_header(&self) -> Result<TipHeader> {
            self.mock.tip_header().await
        }
        async fn in_best_chain(&self, height: u64, hash: &str) -> Result<bool> {
            self.mock.in_best_chain(height, hash).await
        }
        fn target_block_secs(&self) -> Option<u32> {
            self.mock.target_block_secs()
        }
        async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
            self.mock.build_funding(htlc, amount).await
        }
        async fn build_claim(
            &self,
            htlc: &HtlcParams,
            at: &Outpoint,
            amount: Amount,
            preimage: &[u8; 32],
        ) -> Result<SignedTx> {
            self.mock.build_claim(htlc, at, amount, preimage).await
        }
        async fn build_refund(
            &self,
            htlc: &HtlcParams,
            at: &Outpoint,
            amount: Amount,
        ) -> Result<SignedTx> {
            self.mock.build_refund(htlc, at, amount).await
        }
        async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
            self.mock.broadcast(tx).await
        }
        async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
            self.mock.confirmations(txid).await
        }
        async fn htlc_output(
            &self,
            htlc: &HtlcParams,
            at: &Outpoint,
        ) -> Result<Option<LockedOutput>> {
            let real = self.mock.htlc_output(htlc, at).await?;
            self.serve(htlc, at, real);
            self.zec.htlc_output(htlc, at).await
        }
        async fn find_spend(
            &self,
            outpoint: &Outpoint,
            from_height: u64,
        ) -> Result<Option<SpendInfo>> {
            self.mock.find_spend(outpoint, from_height).await
        }
        async fn release_dead_lock(&self, lock: &SignedTx) -> Result<bool> {
            self.mock.release_dead_lock(lock).await
        }
        async fn spendable(&self) -> Result<Option<Amount>> {
            self.mock.spendable().await
        }
        fn fee_bump(&self) -> FeeBump {
            self.mock.fee_bump()
        }
        async fn claim_feerate(&self) -> Result<Option<u64>> {
            self.mock.claim_feerate().await
        }
        fn claim_sizes(&self, htlc: &HtlcParams) -> Option<ClaimSizes> {
            self.mock.claim_sizes(htlc)
        }
        fn primary_only(&self) -> Option<Arc<dyn ChainBackend>> {
            self.mock.primary_only()
        }
    }

    struct World {
        divi: MockChain,
        zec: MockChain,
        mdivi: MockBackend,
        mzec: CrossRead,
        tzec: CrossRead,
        store: Store,
        maker: Maker,
        taker: Taker,
    }

    impl World {
        fn new(dir: Direction) -> World {
            let divi = MockChain::new(Chain::Divi, T0, 60);
            let zec = MockChain::new(Chain::Zec, T0, 75);
            let mdivi = divi.backend(1, Amount(FUNDS));
            let mzec = CrossRead::new(zec.backend(2, Amount(FUNDS)));
            let tdivi = divi.backend(3, Amount(FUNDS));
            let tzec = CrossRead::new(zec.backend(4, Amount(FUNDS)));
            let store = Store::in_memory().unwrap();
            let maker = Maker::new(
                SwapConfig::profile(Profile::Testnet),
                Arc::new(mdivi.clone()),
                Arc::new(mzec.clone()),
                store.clone(),
                vec![Offer {
                    id: "o".into(),
                    direction: dir,
                    counter_chain: Chain::Zec,
                    divi_sats_per_btc: 50_000_000_000,
                    min_btc_sats: 10_000,
                    max_btc_sats: 5_000_000,
                }],
            )
            .unwrap();
            let taker = Taker::new(Arc::new(tdivi), Arc::new(tzec.clone()), store.clone());
            World {
                divi,
                zec,
                mdivi,
                mzec,
                tzec,
                store,
                maker,
                taker,
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

        async fn run(&self, tid: &str, mid: &str, rounds: usize) {
            for _ in 0..rounds {
                self.divi.mine(1);
                self.zec.mine(1);
                let _ = self.maker.tick().await;
                let v = self.maker.view(mid).unwrap();
                let _ = self.taker.step(tid, v.as_ref()).await;
            }
        }

        fn maker_state(&self, mid: &str) -> (SwapState, Option<String>) {
            let r = self.store.get_maker_swap(mid).unwrap().unwrap();
            (r.state, r.last_error)
        }
    }

    /// Control: with the cross-check on and the second operator honest, a swap completes in
    /// both directions (ZEC as the taker leg, then as the maker leg).
    #[tokio::test]
    async fn agreeing_operators_complete_the_swap_both_ways() {
        for dir in [Direction::TakerPaysBtc, Direction::TakerPaysDivi] {
            let w = World::new(dir);
            let (tid, mid) = w.through_taker_lock().await;
            w.run(&tid, &mid, 80).await;
            assert_eq!(w.maker_state(&mid).0, SwapState::Done, "{dir:?}");
            let t = w.store.get_taker_swap(&tid).unwrap().unwrap();
            assert_eq!(t.state, TakerState::Done, "{dir:?}");
        }
    }

    /// Maker, funding point (ZEC is the taker leg): a taker lock the second operator does not
    /// show as agreed is never funded against; the maker waits, naming the refusal.
    #[tokio::test]
    async fn the_maker_does_not_fund_against_a_lock_the_second_operator_disputes() {
        for lie in LIES {
            let w = World::new(Direction::TakerPaysBtc);
            w.mzec.shows(lie);
            let (tid, mid) = w.through_taker_lock().await;
            w.run(&tid, &mid, 30).await;
            let (state, why) = w.maker_state(&mid);
            assert_eq!(w.mdivi.funding_calls(), 0, "{lie:?}: the maker funded");
            assert!(
                matches!(state, SwapState::Accepted | SwapState::TakerLockSeen),
                "{lie:?}: {state:?}"
            );
            let why = why.unwrap_or_default();
            assert!(
                why.contains("zec lock cross-check FAILED"),
                "{lie:?}: {why}"
            );
        }
    }

    /// Taker, claim point (ZEC is the maker leg): a maker lock the second operator does not show
    /// as agreed is never claimed, so the preimage stays secret.
    #[tokio::test]
    async fn the_taker_does_not_claim_a_lock_the_second_operator_disputes() {
        for lie in LIES {
            let w = World::new(Direction::TakerPaysDivi);
            w.tzec.shows(lie);
            let (tid, mid) = w.through_taker_lock().await;
            w.run(&tid, &mid, 40).await;
            assert_eq!(
                w.zec.attempts(TxKind::Claim),
                0,
                "{lie:?}: the taker claimed"
            );
            let t = w.store.get_taker_swap(&tid).unwrap().unwrap();
            assert!(t.maker_leg_claim.is_none(), "{lie:?}");
            let why = t.last_error.unwrap_or_default();
            assert!(
                why.contains("zec lock cross-check FAILED"),
                "{lie:?}: {why}"
            );
        }
    }
}
