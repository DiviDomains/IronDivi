// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A maker lock that was sent and confirmed once (its reservation row released on that
//! confirmation), then reorged out and dropped by the node while still short of the
//! maker-leg confirmations, and whose coin another holder on the same reservation table
//! then takes. Its bytes reached the network and can still be mined, so the maker must keep
//! that funding and never build a second lock beside it. Run with the maker leg on DIVI and
//! on BTC (both at three confirmations, so one confirmation is short of them).

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain, TxKind};
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, InputReservations, Maker, Outpoint, Profile,
    SignedTx, Store, SwapConfig, SwapState, Taker, Txid,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;
/// The maker-leg confirmations: one confirmation is short of them on both chains.
const CONFS: u32 = 3;
/// The maker's wallet coins, in selection order.
const COINS: [Outpoint; 2] = [coin(0xc1), coin(0xc2)];

const fn coin(n: u8) -> Outpoint {
    Outpoint {
        txid: Txid([n; 32]),
        vout: 0,
    }
}

struct World {
    divi: MockChain,
    btc: MockChain,
    /// The maker's swap database's reservation table, shared by every daemon on it.
    res: InputReservations,
    /// The maker-leg backend of the maker under test.
    mk: MockBackend,
    store: Store,
    maker: Maker,
    mid: String,
    dir: Direction,
}

impl World {
    /// The maker-leg chain.
    fn ml(&self) -> &MockChain {
        match self.dir {
            Direction::TakerPaysBtc => &self.divi,
            Direction::TakerPaysDivi => &self.btc,
        }
    }

    fn chain(&self) -> Chain {
        match self.dir {
            Direction::TakerPaysBtc => Chain::Divi,
            Direction::TakerPaysDivi => Chain::Btc,
        }
    }

    fn mine(&self) {
        self.divi.mine(1);
        self.btc.mine(1);
    }

    fn rec(&self) -> divi_swap::store::MakerRecord {
        self.store.get_maker_swap(&self.mid).unwrap().unwrap()
    }

    fn funding(&self) -> Funding {
        self.rec().maker_leg_funding.expect("a persisted funding")
    }

    /// Rows of the shared table on the maker-leg chain, as (input, reserving tx).
    fn rows(&self) -> Vec<(Outpoint, Txid)> {
        self.res
            .list_all()
            .unwrap()
            .into_iter()
            .filter(|r| r.chain == self.chain())
            .map(|r| (r.input, r.reserved_by))
            .collect()
    }
}

/// The maker sent its lock and it confirmed once (short of [`CONFS`]): its row is released.
async fn locked_confirmed_once(dir: Direction) -> World {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let btc = MockChain::new(Chain::Btc, T0, 600);
    let res = InputReservations::in_memory().unwrap();
    let (mdivi, mbtc) = (
        divi.backend(1, Amount(FUNDS)),
        btc.backend(1, Amount(FUNDS)),
    );
    let (mdivi, mbtc, mk) = match dir {
        Direction::TakerPaysBtc => {
            let m = mdivi.with_input_reservations(res.clone(), &COINS);
            (m.clone(), mbtc, m)
        }
        Direction::TakerPaysDivi => {
            let m = mbtc.with_input_reservations(res.clone(), &COINS);
            (mdivi, m.clone(), m)
        }
    };
    let mut cfg = SwapConfig::profile(Profile::Testnet);
    cfg.btc_confirmations = CONFS;
    cfg.divi_confirmations = CONFS;
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        cfg,
        Arc::new(mdivi),
        Arc::new(mbtc),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: dir,
            counter_chain: Chain::Btc,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap();
    let taker = Taker::new(
        Arc::new(divi.backend(3, Amount(FUNDS))),
        Arc::new(btc.backend(4, Amount(FUNDS))),
        store.clone(),
    );
    let q = maker.quote("o", 1_000_000).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    let w = World {
        divi,
        btc,
        res,
        mk,
        store,
        maker,
        mid,
        dir,
    };
    w.maker.halt_after(Some(SwapState::MakerLocked));
    for _ in 0..30 {
        w.mine();
        let _ = w.maker.step(&w.mid).await;
        if w.rec().state == SwapState::MakerLocked {
            break;
        }
    }
    w.maker.halt_after(None);
    assert_eq!(w.rec().state, SwapState::MakerLocked);
    let f = w.funding();
    assert_eq!(inputs_of(&f.tx), vec![COINS[0]]);

    // Sent, then one confirmation, which releases its row.
    w.maker.tick().await.unwrap();
    assert!(w.ml().contains(&f.tx.txid), "sent");
    w.mine();
    w.maker.tick().await.unwrap();
    let r = w.rec();
    assert_eq!(r.state, SwapState::MakerLocked, "{:?}", r.last_error);
    assert_eq!(w.mk.confirmations(&f.tx.txid).await.unwrap(), Some(1));
    assert!(
        w.rows().is_empty(),
        "the first confirmation released its row"
    );
    assert_eq!(w.mk.funding_calls(), 1);
    assert!(r.maker_lock_sent, "the send is on the record");
    w
}

/// The coins a mock funding spends.
fn inputs_of(tx: &SignedTx) -> Vec<Outpoint> {
    let v: serde_json::Value = serde_json::from_slice(&tx.raw).unwrap();
    serde_json::from_value(v["Fund"]["inputs"].clone()).unwrap_or_default()
}

/// The reorg drops the lock's block and the node forgets the lock.
fn reorg_out(w: &World, lock: &Funding) {
    w.ml().rewind(1);
    w.ml().forget(&lock.tx.txid);
    assert!(
        !w.ml().contains(&lock.tx.txid),
        "the node no longer knows it"
    );
}

/// Further ticks keep the persisted funding: no second selection, no second lock sent.
async fn keeps_the_lock(w: &World, persisted: &Funding) {
    let funds_sent = w.ml().attempts(TxKind::Fund);
    for _ in 0..3 {
        let _ = w.maker.tick().await;
        let r = w.rec();
        assert_eq!(r.state, SwapState::MakerLocked, "{:?}", r.last_error);
        assert_eq!(r.maker_leg_funding.as_ref(), Some(persisted), "kept");
        w.mine();
    }
    assert_eq!(w.mk.funding_calls(), 1, "never re-selected");
    assert_eq!(
        w.ml().attempts(TxKind::Fund),
        funds_sent,
        "no second lock reached the chain"
    );
}

async fn a_reorged_lock_whose_coin_is_reserved_is_not_reselected(dir: Direction) {
    let w = locked_confirmed_once(dir).await;
    let persisted = w.funding();
    reorg_out(&w, &persisted);
    // Another holder on the same table reserves the coin (its lock not sent yet).
    w.res
        .reserve(w.chain(), &Txid([0x77; 32]), &[COINS[0]])
        .unwrap();
    keeps_the_lock(&w, &persisted).await;
}

async fn a_reorged_lock_whose_coin_another_lock_spends_is_not_reselected(dir: Direction) {
    let w = locked_confirmed_once(dir).await;
    let persisted = w.funding();
    reorg_out(&w, &persisted);
    // A second daemon on the same table and wallet selects the coin and sends its own lock.
    let have = w.ml().balance(&w.mk.pubkey());
    let other_backend = w
        .ml()
        .backend(1, have)
        .with_input_reservations(w.res.clone(), &COINS);
    let mut htlc: HtlcParams = w.rec().maker_leg_htlc.unwrap();
    htlc.hash = [0x99; 32];
    let other = other_backend
        .build_funding(&htlc, Amount(1_000_000))
        .await
        .unwrap();
    assert_eq!(inputs_of(&other.tx), vec![COINS[0]]);
    other_backend.broadcast(&other.tx).await.unwrap();
    keeps_the_lock(&w, &persisted).await;
}

/// The kept bytes are mined after all (a miner still held them): the maker tracks that one
/// lock to `MakerLockConfirmed`, although the table still gives the coin to another holder.
async fn a_kept_reorged_lock_mined_later_is_the_one_tracked(dir: Direction) {
    let w = locked_confirmed_once(dir).await;
    let persisted = w.funding();
    reorg_out(&w, &persisted);
    w.res
        .reserve(w.chain(), &Txid([0x77; 32]), &[COINS[0]])
        .unwrap();
    keeps_the_lock(&w, &persisted).await;
    // Another node on the network sends the old bytes again; no table in between.
    let have = w.ml().balance(&w.mk.pubkey());
    w.ml()
        .backend(1, have)
        .broadcast(&persisted.tx)
        .await
        .unwrap();
    for _ in 0..10 {
        w.mine();
        let _ = w.maker.tick().await;
        if w.rec().state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    let r = w.rec();
    assert_eq!(r.state, SwapState::MakerLockConfirmed, "{:?}", r.last_error);
    assert_eq!(
        r.maker_leg_funding.as_ref(),
        Some(&persisted),
        "the same lock"
    );
    assert_eq!(w.mk.funding_calls(), 1, "never re-selected");
}

macro_rules! on_both_chains {
    ($divi:ident, $btc:ident, $body:ident) => {
        #[tokio::test]
        async fn $divi() {
            $body(Direction::TakerPaysBtc).await;
        }
        #[tokio::test]
        async fn $btc() {
            $body(Direction::TakerPaysDivi).await;
        }
    };
}

on_both_chains!(
    divi_a_reorged_lock_whose_coin_is_reserved_is_not_reselected,
    btc_a_reorged_lock_whose_coin_is_reserved_is_not_reselected,
    a_reorged_lock_whose_coin_is_reserved_is_not_reselected
);
on_both_chains!(
    divi_a_reorged_lock_whose_coin_another_lock_spends_is_not_reselected,
    btc_a_reorged_lock_whose_coin_another_lock_spends_is_not_reselected,
    a_reorged_lock_whose_coin_another_lock_spends_is_not_reselected
);
on_both_chains!(
    divi_a_kept_reorged_lock_mined_later_is_the_one_tracked,
    btc_a_kept_reorged_lock_mined_later_is_the_one_tracked,
    a_kept_reorged_lock_mined_later_is_the_one_tracked
);
