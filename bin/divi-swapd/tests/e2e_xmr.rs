// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! The DIVI<->XMR adaptor swap through the daemon over real HTTP (`divi-xmr-stagenet`): the
//! hashlock maker serves the offer and quotes (the xmr engine is registered with it), the
//! `/xmr/swaps` routes carry the protocol, the scheduler ticks both; the taker CLI's
//! `xmr_flow` drives the other side. Chains are the `divi_swap_xmr` mocks (real DIVI
//! transactions and script checks), shared by both parties in-process.

use std::sync::Arc;
use std::time::{Duration, Instant};

use divi_swap::mock::MockChain;
use divi_swap::{Amount, Chain, Maker, Profile, Store, SwapConfig};
use divi_swap_cli::{xmr_flow, MakerClient, RunOpts, Sessions};
use divi_swap_xmr::mock::{
    MockDiviChain, MockDiviWallet, MockMoneroChain, MockMoneroWallet, MOCK_DIVI_FEE, MOCK_XMR_FEE,
};
use divi_swap_xmr::{XmrConfig, XmrMaker, XmrMakerState, XmrTaker, XmrTakerState};
use divi_swapd::{mock_xmr_offers, router_with_xmr, spawn_scheduler, AppState, ScanStatus};
use tokio::task::JoinHandle;

const T0: u32 = 1_700_000_000;
const XMR_UNITS: u64 = 1_000_000; // 0.01 XMR
const MAKER_DIVI: u64 = 1_000_000 * 100_000_000;
const TAKER_XMR: u64 = 1_000_000_000_000;
/// Upper bound for polling loops: wall clock, not an iteration count, so a busy build
/// host (hp2 runs many lanes at once) slows them down instead of failing them.
const LOADED_HOST_WAIT: Duration = Duration::from_secs(180);
const TICK: Duration = Duration::from_millis(15);

fn cfg() -> XmrConfig {
    XmrConfig {
        xmr_confirmations: 3,
        divi_fee_sats: 10_000,
        ..XmrConfig::testnet()
    }
}

struct World {
    divi: MockDiviChain,
    xmr: MockMoneroChain,
    maker_divi: MockDiviWallet,
    taker_divi: MockDiviWallet,
    maker_xmr: MockMoneroWallet,
    taker_xmr: MockMoneroWallet,
}

impl World {
    fn new() -> Self {
        let divi = MockDiviChain::new(T0, 60);
        let xmr = MockMoneroChain::new();
        let maker_divi = divi.wallet(1);
        maker_divi.fund(MAKER_DIVI);
        World {
            maker_divi,
            taker_divi: divi.wallet(2),
            maker_xmr: xmr.wallet("maker", 0),
            taker_xmr: xmr.wallet("taker", TAKER_XMR),
            divi,
            xmr,
        }
    }

    fn mine(&self) {
        self.divi.mine(1);
        self.xmr.mine(1);
    }

    fn taker(&self, db: &std::path::Path) -> XmrTaker {
        XmrTaker::new(
            cfg(),
            Arc::new(self.taker_divi.clone()),
            Arc::new(self.taker_xmr.clone()),
            Store::open(db).unwrap(),
        )
        .unwrap()
    }
}

struct Daemon {
    base: String,
    xmr: Arc<XmrMaker>,
    tasks: [JoinHandle<()>; 2],
}

impl Drop for Daemon {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// A BTC hashlock maker (serving nothing) with the xmr engine registered, under `/swap`.
async fn serve(w: &World, db: &std::path::Path) -> Daemon {
    let store = Store::open(db).unwrap();
    let xmr = Arc::new(
        XmrMaker::new(
            cfg(),
            Arc::new(w.maker_divi.clone()),
            Arc::new(w.maker_xmr.clone()),
            store.clone(),
            mock_xmr_offers(),
        )
        .unwrap(),
    );
    let hl_divi = MockChain::new(Chain::Divi, T0, 60).backend(1, Amount(0));
    let hl_btc = MockChain::new(Chain::Btc, T0, 600).backend(2, Amount(0));
    let maker = Arc::new(
        Maker::new(
            SwapConfig::profile(Profile::Testnet),
            Arc::new(hl_divi.clone()),
            Arc::new(hl_btc.clone()),
            store,
            vec![],
        )
        .unwrap()
        .with_engine(xmr.clone())
        .unwrap(),
    );
    let state = AppState {
        maker: maker.clone(),
        divi: Arc::new(hl_divi),
        btc: Arc::new(hl_btc),
        scan: ScanStatus::done(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/swap", listener.local_addr().unwrap());
    let app = router_with_xmr(state, Some(xmr.clone()), "/swap");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Daemon {
        base,
        xmr,
        tasks: [server, spawn_scheduler(maker, TICK)],
    }
}

fn quoted_divi() -> u64 {
    mock_xmr_offers()[0].divi_for(XMR_UNITS).0
}

#[tokio::test]
async fn e2e_mock_xmr_happy() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let tdb = tmp.path().join("t.db");
    let taker = w.taker(&tdb);
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);

    // The offer is served and quoted through the ordinary routes.
    let offers = client.offers().await.unwrap();
    let o = offers.iter().find(|o| o.id == "divi-xmr-stagenet").unwrap();
    assert_eq!(o.counter_chain, Chain::Xmr);
    let q = client.quote("divi-xmr-stagenet", XMR_UNITS).await.unwrap();
    assert_eq!(q.counter_chain, Chain::Xmr);

    let opts = RunOpts {
        timeout: Duration::from_secs(180), // hp2 runs many lanes at once
        poll: TICK,
    };
    let (local, outcome) = xmr_flow::run(
        &taker,
        &client,
        &sessions,
        "divi-xmr-stagenet",
        XMR_UNITS,
        &opts,
        &mut || w.mine(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, "redeemed");
    let id = sessions.get(&local).unwrap().maker_swap_id;
    let deadline = Instant::now() + LOADED_HOST_WAIT;

    while Instant::now() < deadline {
        w.mine();
        if client.xmr_swap(&id).await.unwrap().state == XmrMakerState::Done {
            break;
        }
        tokio::time::sleep(TICK).await;
    }
    assert_eq!(
        client.xmr_swap(&id).await.unwrap().state,
        XmrMakerState::Done
    );
    assert_eq!(w.taker_divi.balance(), quoted_divi());
    let xmr = XMR_UNITS * divi_swap_xmr::PICONERO_PER_COUNTER_SAT;
    assert_eq!(w.maker_xmr.balance(), xmr - MOCK_XMR_FEE);
    assert_eq!(w.taker_xmr.balance(), TAKER_XMR - xmr - MOCK_XMR_FEE);
    assert_eq!(
        w.maker_divi.balance(),
        MAKER_DIVI - quoted_divi() - cfg().divi_fee_sats - MOCK_DIVI_FEE
    );
    drop(d);
}

/// The taker locks XMR, then walks away before redeeming: past `t_cancel` the maker cancels
/// and refunds (revealing `s_m`), and the taker sweeps her XMR back.
#[tokio::test]
async fn e2e_mock_xmr_refund() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let tdb = tmp.path().join("t.db");
    let taker = w.taker(&tdb);
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);

    let local = xmr_flow::begin(&taker, &client, &sessions, "divi-xmr-stagenet", XMR_UNITS)
        .await
        .unwrap();
    let deadline = Instant::now() + LOADED_HOST_WAIT;

    while Instant::now() < deadline {
        w.mine();
        let s = xmr_flow::step(&taker, &client, &sessions, &local)
            .await
            .unwrap();
        if s == XmrTakerState::XmrLocked {
            break;
        }
        tokio::time::sleep(TICK).await;
    }
    assert_eq!(
        taker.record(&local).unwrap().unwrap().state,
        XmrTakerState::XmrLocked
    );
    // One more step reports the lock to the maker; then the taker goes silent.
    xmr_flow::step(&taker, &client, &sessions, &local)
        .await
        .unwrap();
    let id = sessions.get(&local).unwrap().maker_swap_id;
    assert!(client.xmr_swap(&id).await.unwrap().xmr_lock_txid.is_some());

    w.divi.advance_time(cfg().cancel_after_secs);
    let deadline = Instant::now() + LOADED_HOST_WAIT;

    while Instant::now() < deadline {
        w.mine();
        if client.xmr_swap(&id).await.unwrap().state == XmrMakerState::Done {
            break;
        }
        tokio::time::sleep(TICK).await;
    }
    let v = client.xmr_swap(&id).await.unwrap();
    assert_eq!(v.state, XmrMakerState::Done);
    assert!(v.cancel_txid.is_some() && v.refund_txid.is_some());

    let mut state = XmrTakerState::XmrLocked;
    let deadline = Instant::now() + LOADED_HOST_WAIT;

    while Instant::now() < deadline {
        w.mine();
        state = xmr_flow::step(&taker, &client, &sessions, &local)
            .await
            .unwrap();
        if state == XmrTakerState::Done {
            break;
        }
        tokio::time::sleep(TICK).await;
    }
    assert_eq!(state, XmrTakerState::Done);
    let rec = taker.record(&local).unwrap().unwrap();
    assert_eq!(rec.outcome.as_deref(), Some("refunded"));
    assert_eq!(w.taker_xmr.balance(), TAKER_XMR - 2 * MOCK_XMR_FEE);
    assert_eq!(w.taker_divi.balance(), 0);
    assert_eq!(w.maker_xmr.balance(), 0);
    assert_eq!(
        w.maker_divi.balance(),
        MAKER_DIVI - 2 * cfg().divi_fee_sats - MOCK_DIVI_FEE
    );
    assert_eq!(d.xmr.list().unwrap().len(), 1);
}

/// A hashlock take (`POST /swaps`) of an xmr quote is refused and creates nothing; the xmr
/// setup route refuses a hashlock quote.
#[tokio::test]
async fn xmr_and_hashlock_routes_do_not_cross() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let client = MakerClient::new(&d.base);
    let q = client.quote("divi-xmr-stagenet", XMR_UNITS).await.unwrap();
    let body = serde_json::json!({
        "quote_id": q.id, "hash": "00".repeat(32), "counter_chain": "xmr",
        "taker_btc_pubkey": "02".to_string() + &"11".repeat(32),
        "taker_divi_pubkey": "02".to_string() + &"22".repeat(32),
    });
    let r = reqwest::Client::new()
        .post(format!("{}/swaps", d.base))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let all: serde_json::Value = reqwest::get(format!("{}/swaps", d.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(all.as_array().unwrap().len(), 0);
    assert!(d.xmr.list().unwrap().is_empty());
    // An unknown xmr swap is a 404.
    let r = reqwest::get(format!("{}/xmr/swaps/nope", d.base))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}
