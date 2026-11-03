// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! In-flight V0 swaps finish on V0 (claim and refund), a V1 swap in the same store stays V1,
//! and an old binary (one that ignores `script_version`) cannot see a V1 output.
//!
//! A swap "written before `aa0d50b`" is made by accepting a swap, then rewriting the maker
//! record's taker-leg HTLC to V0: a V0 HTLC serializes without the field, so the stored JSON is
//! the pre-F3 shape (checked key by key against the committed pre-F3 fixture). Everything after
//! that (the taker's lock, the maker's lock, the claims, the refunds) is the real engine code on
//! the mock chain, which keys every output, claim and refund on the full `HtlcParams`.

use divi_swap::api::{Direction, LockNotice, Offer};
use divi_swap::htlc::{script_num, ScriptVersion};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, HtlcParams, Maker, Profile, SignedTx, Store, SwapConfig,
    SwapState, Taker, TakerState,
};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const BTC_SATS: u64 = 1_000_000;
const FWD: Direction = Direction::TakerPaysBtc;
const REV: Direction = Direction::TakerPaysDivi;
const MAKER_FILE: &str = include_str!("fixtures/maker-forward-done-happy.json");

struct W {
    dir: Direction,
    btc: MockChain,
    divi: MockChain,
    mdivi: MockBackend,
    mbtc: MockBackend,
    tdivi: MockBackend,
    tbtc: MockBackend,
    clock: Arc<AtomicU64>,
    path: PathBuf,
    _tmp: tempfile::TempDir,
    store: Store,
    maker: Maker,
    taker: Taker,
}

struct Sw {
    mid: String,
    tid: String,
}

fn offer(dir: Direction) -> Offer {
    Offer {
        id: "o1".into(),
        direction: dir,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    }
}

impl W {
    fn new(dir: Direction) -> W {
        let btc = MockChain::new(Chain::Btc, T0, 600);
        let divi = MockChain::new(Chain::Divi, T0, 60);
        // Two swaps share one maker, so each side is funded for two legs.
        let (md, mb, td, tb) = match dir {
            Direction::TakerPaysBtc => (4_000_000_000, 0, 0, 20_000_000),
            Direction::TakerPaysDivi => (0, 20_000_000, 4_000_000_000, 0),
        };
        let mdivi = divi.backend(1, Amount(md));
        let mbtc = btc.backend(2, Amount(mb));
        let tdivi = divi.backend(3, Amount(td));
        let tbtc = btc.backend(4, Amount(tb));
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("swap.db");
        let store = Store::open(&path).unwrap();
        let clock = Arc::new(AtomicU64::new(T0 as u64));
        let (maker, taker) = engines(dir, &mdivi, &mbtc, &tdivi, &tbtc, &store, &clock);
        W {
            dir,
            btc,
            divi,
            mdivi,
            mbtc,
            tdivi,
            tbtc,
            clock,
            path,
            _tmp: tmp,
            store,
            maker,
            taker,
        }
    }

    /// Drop both engines and reopen the database file, as after a process restart.
    fn restart(&mut self) {
        self.store = Store::open(&self.path).unwrap();
        let (m, t) = engines(
            self.dir,
            &self.mdivi,
            &self.mbtc,
            &self.tdivi,
            &self.tbtc,
            &self.store,
            &self.clock,
        );
        self.maker = m;
        self.taker = t;
    }

    fn mine(&self) {
        self.btc.mine(1);
        self.divi.mine(1);
    }

    fn chain_of(&self, c: Chain) -> &MockChain {
        if c == Chain::Divi {
            &self.divi
        } else {
            &self.btc
        }
    }

    /// Open a swap. `v0` makes it an in-flight swap from before `aa0d50b`.
    async fn open(&self, v0: bool) -> Sw {
        let quote = self.maker.quote("o1", BTC_SATS).await.unwrap();
        let (tid, req) = self.taker.prepare(&quote).await.unwrap();
        let mut view = self.maker.accept(req).await.unwrap();
        let mid = view.id.clone();
        if v0 {
            let mut rec = self.store.get_maker_swap(&mid).unwrap().unwrap();
            assert_eq!(rec.taker_leg_htlc.script_version, ScriptVersion::V1);
            rec.taker_leg_htlc.script_version = ScriptVersion::V0;
            self.store.put_maker_swap(&rec).unwrap();
            view = self.maker.view(&mid).unwrap().unwrap();
            assert_eq!(view.taker_leg.htlc.script_version, ScriptVersion::V0);
        }
        self.taker.accepted(&tid, &view).await.unwrap();
        let n: LockNotice = self.taker.lock(&tid).await.unwrap();
        self.maker.notify_lock(&mid, n).await.unwrap();
        Sw { mid, tid }
    }

    fn mstate(&self, s: &Sw) -> SwapState {
        self.store.get_maker_swap(&s.mid).unwrap().unwrap().state
    }
    fn tstate(&self, s: &Sw) -> TakerState {
        self.store.get_taker_swap(&s.tid).unwrap().unwrap().state
    }

    /// One scheduler round: maker tick, then each taker (if `taker_acts`), then a block.
    async fn round(&self, sws: &[&Sw], taker_acts: bool) {
        let _ = self.maker.tick().await;
        if taker_acts {
            for s in sws {
                let view = self.maker.view(&s.mid).unwrap();
                let _ = self.taker.step(&s.tid, view.as_ref()).await;
            }
        }
        self.mine();
    }

    /// Run until every maker leg is locked and confirmed, restart the process there, then
    /// either let the takers claim, or let both timeouts pass and refund.
    async fn finish(&mut self, sws: &[&Sw], refund: bool) {
        for _ in 0..60 {
            if sws
                .iter()
                .all(|s| self.mstate(s) == SwapState::MakerLockConfirmed)
            {
                break;
            }
            self.round(sws, !refund).await;
        }
        for s in sws {
            assert_eq!(self.mstate(s), SwapState::MakerLockConfirmed);
        }
        self.restart();
        if refund {
            self.tl_expire();
        }
        for _ in 0..80 {
            if sws
                .iter()
                .all(|s| self.mstate(s).is_terminal() && self.tstate(s) == TakerState::Done)
            {
                return;
            }
            self.round(sws, true).await;
        }
        panic!("did not finish");
    }

    fn tl_expire(&self) {
        self.chain_of(self.dir.taker_chain()).advance_time(22_000);
        self.chain_of(self.dir.maker_chain()).advance_time(12_000);
    }

    fn balance(&self, chain: Chain, who: &MockBackend) -> u64 {
        self.chain_of(chain).balance(&who.pubkey()).0
    }
}

fn engines(
    dir: Direction,
    mdivi: &MockBackend,
    mbtc: &MockBackend,
    tdivi: &MockBackend,
    tbtc: &MockBackend,
    store: &Store,
    clock: &Arc<AtomicU64>,
) -> (Maker, Taker) {
    let c = clock.clone();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(mdivi.clone()),
        Arc::new(mbtc.clone()),
        store.clone(),
        vec![offer(dir)],
    )
    .unwrap()
    .with_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    let taker = Taker::new(
        Arc::new(tdivi.clone()),
        Arc::new(tbtc.clone()),
        store.clone(),
    );
    (maker, taker)
}

/// OP_IF OP_SHA256 <h> OP_EQUALVERIFY <claim> OP_ELSE <lt> CLTV OP_DROP <refund> OP_ENDIF CHECKSIG,
/// built from the HTLC's own fields, independently of `redeem_script`.
fn v0_script_by_hand(h: &HtlcParams) -> Vec<u8> {
    let lt = script_num(h.locktime as i64);
    hex::decode(format!(
        "63a820{}8821{}67{:02x}{}b17521{}68ac",
        hex::encode(h.hash),
        hex::encode(h.claim_pubkey),
        lt.len(),
        hex::encode(&lt),
        hex::encode(h.refund_pubkey)
    ))
    .unwrap()
}

fn check_htlc(h: &HtlcParams, want: ScriptVersion, what: &str) {
    assert_eq!(h.script_version, want, "{what}");
    let other = if want == ScriptVersion::V0 {
        ScriptVersion::V1
    } else {
        ScriptVersion::V0
    };
    assert_eq!(h.redeem_script(), h.redeem_script_v(want), "{what}");
    assert_ne!(h.redeem_script(), h.redeem_script_v(other), "{what}");
    assert_eq!(h.script_sha256(), h.script_sha256_v(want), "{what}");
    assert_ne!(h.script_sha256(), h.script_sha256_v(other), "{what}");
    if want == ScriptVersion::V0 {
        assert_eq!(h.redeem_script(), v0_script_by_hand(h), "{what}");
    }
}

/// Every `*_htlc` object anywhere in `v`.
fn htlc_objects<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k.ends_with("_htlc") && x.is_object() {
                    out.push(x);
                } else {
                    htlc_objects(x, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| htlc_objects(x, out)),
        _ => {}
    }
}

/// The HTLC a mock transaction (fund, claim or refund) was built against.
fn tx_htlc(tx: &SignedTx) -> HtlcParams {
    let v: Value = serde_json::from_slice(&tx.raw).unwrap();
    let (_, body) = v.as_object().unwrap().iter().next().unwrap();
    serde_json::from_value(body["htlc"].clone()).unwrap()
}

/// Both records of `s` carry `want` on BOTH legs, the stored JSON has the right shape, and every
/// transaction either side built is against that script.
fn assert_swap_version(w: &W, s: &Sw, want: ScriptVersion, txs_expected: usize) {
    let m = w.store.get_maker_swap(&s.mid).unwrap().unwrap();
    let t = w.store.get_taker_swap(&s.tid).unwrap().unwrap();
    let ml = m.maker_leg_htlc.expect("maker leg");
    let ttl = t.taker_leg_htlc.unwrap();
    // A taker that never saw the maker lock (the refund path) has no maker-leg HTLC to compare.
    let tml = t.maker_leg_htlc;
    check_htlc(&m.taker_leg_htlc, want, "maker record, taker leg");
    check_htlc(&ml, want, "maker record, maker leg");
    check_htlc(&ttl, want, "taker record, taker leg");
    if let Some(tml) = &tml {
        check_htlc(tml, want, "taker record, maker leg");
        assert_eq!(&ml, tml, "both records agree on the maker leg");
    }
    assert_eq!(m.taker_leg_htlc, ttl, "both records agree on the taker leg");

    // Stored JSON: V0 has no `script_version` and the pre-F3 key set; V1 names its version.
    let fixture: Value = serde_json::from_str(MAKER_FILE).unwrap();
    let old_keys: Vec<&String> = fixture["btc_htlc"].as_object().unwrap().keys().collect();
    for rec in [
        serde_json::to_value(&m).unwrap(),
        serde_json::to_value(&t).unwrap(),
    ] {
        let mut found = Vec::new();
        htlc_objects(&rec, &mut found);
        assert!(!found.is_empty(), "found {} htlc objects", found.len());
        for j in found {
            if want == ScriptVersion::V0 {
                let mut keys: Vec<&String> = j.as_object().unwrap().keys().collect();
                keys.sort();
                let mut old = old_keys.clone();
                old.sort();
                assert_eq!(keys, old, "V0 JSON must be the pre-F3 shape");
            } else {
                assert_eq!(j["script_version"], "V1");
            }
        }
    }

    // Every transaction recorded on either side.
    let mut txs: Vec<&SignedTx> = Vec::new();
    txs.extend(m.maker_leg_funding.as_ref().map(|f| &f.tx));
    txs.extend(t.taker_leg_funding.as_ref().map(|f| &f.tx));
    txs.extend(m.taker_leg_claim.as_ref());
    txs.extend(m.maker_leg_refund.as_ref());
    txs.extend(t.maker_leg_claim.as_ref());
    txs.extend(t.taker_leg_refund.as_ref());
    assert_eq!(txs.len(), txs_expected);
    for tx in txs {
        assert_eq!(tx_htlc(tx).script_version, want);
    }
}

async fn v0_claim(dir: Direction) {
    let mut w = W::new(dir);
    let s = w.open(true).await;
    w.finish(&[&s], false).await;
    // funding x2, and a claim on each leg
    assert_swap_version(&w, &s, ScriptVersion::V0, 4);
    let m = w.store.get_maker_swap(&s.mid).unwrap().unwrap();
    assert!(m.taker_leg_claim.is_some() && m.maker_leg_refund.is_none());
    assert_eq!(m.state, SwapState::Done);
    let t = w.store.get_taker_swap(&s.tid).unwrap().unwrap();
    assert!(t.maker_leg_claim.is_some() && t.taker_leg_refund.is_none());
    let (tc, mc) = (dir.taker_chain(), dir.maker_chain());
    let (m_tl, t_ml) = (w.m_on(tc), w.t_on(mc));
    assert!(w.balance(tc, m_tl) > 0, "maker was paid on the taker leg");
    assert!(w.balance(mc, t_ml) > 0, "taker was paid on the maker leg");
}

async fn v0_refund(dir: Direction) {
    let mut w = W::new(dir);
    let s = w.open(true).await;
    w.finish(&[&s], true).await;
    // funding x2, and a refund on each leg
    assert_swap_version(&w, &s, ScriptVersion::V0, 4);
    let m = w.store.get_maker_swap(&s.mid).unwrap().unwrap();
    assert!(m.maker_leg_refund.is_some() && m.taker_leg_claim.is_none());
    let t = w.store.get_taker_swap(&s.tid).unwrap().unwrap();
    assert!(t.taker_leg_refund.is_some() && t.maker_leg_claim.is_none());
    let (tc, mc) = (dir.taker_chain(), dir.maker_chain());
    assert_eq!(w.balance(tc, w.m_on(tc)), 0, "maker received nothing");
    assert_eq!(w.balance(mc, w.t_on(mc)), 0, "taker received nothing");
}

async fn mixed(dir: Direction, refund: bool) {
    let mut w = W::new(dir);
    let old = w.open(true).await;
    let new = w.open(false).await;
    w.finish(&[&old, &new], refund).await;
    assert_swap_version(&w, &old, ScriptVersion::V0, 4);
    assert_swap_version(&w, &new, ScriptVersion::V1, 4);
    // The two swaps never share a script.
    let a = w.store.get_maker_swap(&old.mid).unwrap().unwrap();
    let b = w.store.get_maker_swap(&new.mid).unwrap().unwrap();
    assert_ne!(
        a.taker_leg_htlc.script_sha256(),
        b.taker_leg_htlc.script_sha256()
    );
}

impl W {
    fn m_on(&self, c: Chain) -> &MockBackend {
        if c == Chain::Divi {
            &self.mdivi
        } else {
            &self.mbtc
        }
    }
    fn t_on(&self, c: Chain) -> &MockBackend {
        if c == Chain::Divi {
            &self.tdivi
        } else {
            &self.tbtc
        }
    }
}

macro_rules! both {
    ($fwd:ident, $rev:ident, $body:ident $(, $arg:expr)?) => {
        #[tokio::test]
        async fn $fwd() {
            $body(FWD $(, $arg)?).await
        }
        #[tokio::test]
        async fn $rev() {
            $body(REV $(, $arg)?).await
        }
    };
}

both!(
    v0_inflight_swap_claims_on_v0,
    rev_v0_inflight_swap_claims_on_v0,
    v0_claim
);
both!(
    v0_inflight_swap_refunds_on_v0,
    rev_v0_inflight_swap_refunds_on_v0,
    v0_refund
);
both!(
    v0_and_v1_swaps_in_one_store_both_claim,
    rev_v0_and_v1_swaps_in_one_store_both_claim,
    mixed,
    false
);
both!(
    v0_and_v1_swaps_in_one_store_both_refund,
    rev_v0_and_v1_swaps_in_one_store_both_refund,
    mixed,
    true
);

/// The old-binary hazard, shown on the mock chain: a binary from before `aa0d50b` ignores
/// `script_version`, so it rebuilds V0 for a V1 record. Its script, its script hash (so its
/// address) and its output lookup all differ from what is on chain, so it can neither see the
/// lock nor build a spend that the chain would accept.
#[tokio::test]
async fn old_binary_cannot_see_a_v1_output() {
    let w = W::new(FWD);
    let s = w.open(false).await;
    let m = w.store.get_maker_swap(&s.mid).unwrap().unwrap();
    let v1 = m.taker_leg_htlc;
    assert_eq!(v1.script_version, ScriptVersion::V1);
    // What an old binary makes of the stored JSON: the field is unknown to it and dropped.
    let mut j = serde_json::to_value(v1).unwrap();
    j.as_object_mut()
        .unwrap()
        .shift_remove("script_version")
        .unwrap();
    let old_view: HtlcParams = serde_json::from_value(j).unwrap();
    assert_eq!(old_view.script_version, ScriptVersion::V0);
    assert_ne!(old_view.redeem_script(), v1.redeem_script());
    assert_ne!(old_view.script_sha256(), v1.script_sha256());
    let op = m.taker_leg_outpoint.expect("taker lock noticed");
    let tk = w.t_on(FWD.taker_chain());
    assert!(tk.htlc_output(&v1, &op).await.unwrap().is_some());
    assert!(
        tk.htlc_output(&old_view, &op).await.unwrap().is_none(),
        "an old binary's lookup must not find the V1 output"
    );
}
