// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
use divi_swap_xmr::api::{JRoundRequest, SigsRequest, XmrLockNotice};
use divi_swap_xmr::mock::{
    MockDiviChain, MockDiviWallet, MockMoneroChain, MockMoneroWallet, MOCK_DIVI_FEE, MOCK_XMR_FEE,
};
use divi_swap_xmr::taker::JNext;
use divi_swap_xmr::{XmrConfig, XmrMaker, XmrMakerState, XmrTaker, XmrTakerState};
use divi_swapd::{
    mock_xmr_offers, router_with_auth, spawn_scheduler, AppState, HashlockAuth, ScanStatus,
};
use tokio::task::JoinHandle;

const OPERATOR_TOKEN: &str = "test-operator-token";

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
    serve_with(w, db, false).await
}

async fn serve_with(w: &World, db: &std::path::Path, trust_proxy_headers: bool) -> Daemon {
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
    let auth = HashlockAuth::new(Store::in_memory().unwrap())
        .with_operator_token(Some(OPERATOR_TOKEN.into()));
    let app = router_with_auth(state, Some(xmr.clone()), "/swap", trust_proxy_headers, auth);
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
    let session = sessions.get(&local).unwrap();
    let (id, token) = (session.maker_swap_id, session.swap_token);
    let deadline = Instant::now() + LOADED_HOST_WAIT;

    while Instant::now() < deadline {
        w.mine();
        if client.xmr_swap(&id, &token).await.unwrap().state == XmrMakerState::Done {
            break;
        }
        tokio::time::sleep(TICK).await;
    }
    assert_eq!(
        client.xmr_swap(&id, &token).await.unwrap().state,
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
    let session = sessions.get(&local).unwrap();
    let (id, token) = (session.maker_swap_id, session.swap_token);
    assert!(client
        .xmr_swap(&id, &token)
        .await
        .unwrap()
        .xmr_lock_txid
        .is_some());

    w.divi.advance_time(cfg().cancel_after_secs);
    let deadline = Instant::now() + LOADED_HOST_WAIT;

    while Instant::now() < deadline {
        w.mine();
        if client.xmr_swap(&id, &token).await.unwrap().state == XmrMakerState::Done {
            break;
        }
        tokio::time::sleep(TICK).await;
    }
    let v = client.xmr_swap(&id, &token).await.unwrap();
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
        .header("x-swap-token-support", "1")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let all: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/swaps", d.base))
        .header("x-operator-token", OPERATOR_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(all.as_array().unwrap().len(), 0);
    assert!(d.xmr.list().unwrap().is_empty());
    // There is no listing route at all.
    let r = reqwest::get(format!("{}/xmr/swaps", d.base)).await.unwrap();
    assert_eq!(r.status().as_u16(), 405);
    // An unknown xmr swap is a 404.
    let r = reqwest::get(format!("{}/xmr/swaps/nope", d.base))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}

/// C3d/C6a: every route of one XMR swap needs its `X-Swap-Token`; a wrong or missing token is
/// the same 404 an unknown id gets, and there is no unauthenticated listing.
#[tokio::test]
async fn xmr_swap_routes_need_the_swap_token() {
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
    let session = sessions.get(&local).unwrap();
    let (id, token) = (session.maker_swap_id, session.swap_token);
    assert_eq!(token.len(), 64);

    let http = reqwest::Client::new();
    let url = format!("{}/xmr/swaps/{id}", d.base);
    let status = |r: reqwest::Response| r.status().as_u16();
    assert_eq!(
        status(http.get(&url).send().await.unwrap()),
        404,
        "no token"
    );
    let wrong = "0".repeat(64);
    let r = http.get(&url).header("X-Swap-Token", &wrong).send().await;
    assert_eq!(status(r.unwrap()), 404, "wrong token");
    let r = http.get(&url).header("X-Swap-Token", &token).send().await;
    assert_eq!(status(r.unwrap()), 200, "right token");
    // A mutating route refuses a wrong token too, before looking at the body.
    let notice = serde_json::json!({ "xmr_txid": "00" });
    for tail in ["xmr-lock", "sigs", "j"] {
        let r = http
            .post(format!("{url}/{tail}"))
            .header("X-Swap-Token", &wrong)
            .json(&notice)
            .send()
            .await
            .unwrap();
        assert_eq!(status(r), 404, "{tail} with a wrong token");
    }
    // Another swap's id with this swap's token: nothing.
    let r = http
        .get(format!("{}/xmr/swaps/nope", d.base))
        .header("X-Swap-Token", &token)
        .send()
        .await;
    assert_eq!(status(r.unwrap()), 404);
}

/// C3c: past the per-IP limit the setup route answers 429 (a body that fails to parse is
/// still counted: the limiter runs first).
#[tokio::test]
async fn xmr_setup_is_rate_limited_per_ip() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let http = reqwest::Client::new();
    let url = format!("{}/xmr/swaps", d.base);
    let mut limited = None;
    for n in 1..=divi_swapd::RATE_LIMIT_PER_WINDOW + 1 {
        let r = http.post(&url).json(&serde_json::json!({})).send().await;
        let code = r.unwrap().status().as_u16();
        if code == 429 {
            limited = Some(n);
            break;
        }
        assert_eq!(
            code, 422,
            "request {n} is parsed (and refused), not limited"
        );
    }
    assert_eq!(limited, Some(divi_swapd::RATE_LIMIT_PER_WINDOW + 1));
}

/// Posts `n` unparseable setups, each with the given `X-Forwarded-For` (or none), and returns
/// the status codes. Served without `ConnectInfo`, so every socket peer is one bucket.
async fn setup_posts(d: &Daemon, xff: impl Fn(u32) -> Option<String>, n: u32) -> Vec<u16> {
    let http = reqwest::Client::new();
    let url = format!("{}/xmr/swaps", d.base);
    let mut codes = Vec::new();
    for i in 0..n {
        let mut req = http.post(&url).json(&serde_json::json!({}));
        if let Some(v) = xff(i) {
            req = req.header("x-forwarded-for", v);
        }
        codes.push(req.send().await.unwrap().status().as_u16());
    }
    codes
}

/// Gate C left-over: with `trust_proxy_headers` off (the default) a client cannot pick its
/// own bucket by sending `X-Forwarded-For`.
#[tokio::test]
async fn spoofed_forwarded_for_is_ignored_by_default() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let n = divi_swapd::RATE_LIMIT_PER_WINDOW + 1;
    let codes = setup_posts(&d, |i| Some(format!("203.0.113.{}", i + 1)), n).await;
    assert_eq!(
        codes.last(),
        Some(&429),
        "a fresh header every time is still one bucket"
    );
}

/// With it on, two `X-Forwarded-For` values are two buckets.
#[tokio::test]
async fn forwarded_for_selects_the_bucket_when_trusted() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve_with(&w, &tmp.path().join("m.db"), true).await;
    let max = divi_swapd::RATE_LIMIT_PER_WINDOW;
    let a = setup_posts(&d, |_| Some("203.0.113.1".into()), max + 1).await;
    assert_eq!(a.last(), Some(&429), "client A is over its limit");
    let b = setup_posts(&d, |_| Some("203.0.113.2".into()), 1).await;
    assert_eq!(b, vec![422], "client B has its own bucket");
}

/// With it on, a header that is not an address falls back to the socket address's bucket.
#[tokio::test]
async fn garbage_forwarded_for_falls_back_to_the_socket() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve_with(&w, &tmp.path().join("m.db"), true).await;
    let n = divi_swapd::RATE_LIMIT_PER_WINDOW + 1;
    let codes = setup_posts(&d, |i| Some(format!("not-an-ip-{i}")), n).await;
    assert_eq!(codes.last(), Some(&429), "garbage shares the socket bucket");
}

/// One honest swap's setup (`begin`: the `/j` exchanges and `/sigs`), then a status read with
/// its own token per request: a swap's right-token requests on the XMR `:id` routes share one
/// per-swap bucket, and the setup leaves most of it. Fails on 7361ae6 (no limit: never 429).
#[tokio::test]
async fn xmr_swap_routes_share_a_per_swap_bucket() {
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
    let session = sessions.get(&local).unwrap();
    let url = format!("{}/xmr/swaps/{}", d.base, session.maker_swap_id);
    let http = reqwest::Client::new();
    let limit = divi_swapd::XMR_SWAP_LIMIT_PER_WINDOW;
    let mut ok = 0;
    let first_429 = loop {
        let r = http
            .get(&url)
            .header("X-Swap-Token", &session.swap_token)
            .send()
            .await
            .unwrap();
        match r.status().as_u16() {
            200 => ok += 1,
            429 => break ok + 1,
            other => panic!("status {other}"),
        }
        assert!(ok <= limit, "no 429 after {ok} reads");
    };
    // `begin` used some of the bucket (about ten `/j` and one `/sigs`); reads use the rest.
    let used_by_setup = limit + 1 - first_429;
    assert!(
        (2..=66).contains(&used_by_setup),
        "setup used {used_by_setup} of {limit}"
    );
}

/// Token guesses: past `XMR_TOKEN_MISS_LIMIT_PER_WINDOW` misses an IP gets 429 on every XMR
/// `:id` route without the right token, while the right token still passes (so a prober on a
/// shared address cannot lock its taker out). Fails on 7361ae6 (every guess a 404).
#[tokio::test]
async fn xmr_token_guesses_are_throttled() {
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
    let session = sessions.get(&local).unwrap();
    let url = format!("{}/xmr/swaps/{}", d.base, session.maker_swap_id);
    let http = reqwest::Client::new();
    let get = |token: String| {
        let r = http.get(&url).header("X-Swap-Token", token).send();
        async move { r.await.unwrap().status().as_u16() }
    };
    assert_eq!(get(session.swap_token.clone()).await, 200, "no miss yet");
    let misses = divi_swapd::XMR_TOKEN_MISS_LIMIT_PER_WINDOW;
    for i in 0..misses {
        assert_eq!(get(format!("{i:064x}")).await, 404, "guess {i}");
    }
    assert_eq!(get(format!("{misses:064x}")).await, 429, "the next guess");
    assert_eq!(
        get(session.swap_token.clone()).await,
        200,
        "the right token still passes"
    );
    let r = http
        .post(format!("{url}/sigs"))
        .header("X-Swap-Token", "0".repeat(64))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 429, "every :id route");
    // One miss budget per address: the hashlock `:id` routes are locked out too.
    let r = reqwest::get(format!("{}/swaps/nope", d.base))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 429, "hashlock misses share the budget");
}

/// One miss budget per address across the hashlock and XMR `:id` routes: a prober mixing them
/// gets [`divi_swapd::XMR_TOKEN_MISS_LIMIT_PER_WINDOW`] misses in all, not twice that. Fails
/// on 4310796 (two budgets: the 21st miss is a 404).
#[tokio::test]
async fn hashlock_and_xmr_misses_share_one_budget() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let http = reqwest::Client::new();
    let hashlock = format!("{}/swaps/nope", d.base);
    let xmr = format!("{}/xmr/swaps/nope", d.base);
    let get = |url: &str| {
        let r = http.get(url).header("X-Swap-Token", "0".repeat(64)).send();
        async move { r.await.unwrap().status().as_u16() }
    };
    let misses = divi_swapd::XMR_TOKEN_MISS_LIMIT_PER_WINDOW;
    for i in 0..misses {
        let url = if i % 2 == 0 { &hashlock } else { &xmr };
        assert_eq!(get(url).await, 404, "miss {i} on {url}");
    }
    assert_eq!(get(&xmr).await, 429, "the next miss, on the XMR route");
    assert_eq!(get(&hashlock).await, 429, "and on the hashlock route");
}

/// The XMR `:id` routes have no per-address bucket: right-token traffic counts only in its
/// swap's bucket, never per address, so after its swap's whole bucket the address still has
/// every miss, and the next one is the 429. Passes on 4310796 as well: the per-address bucket
/// there (as large as the swap's) counted only misses, so the miss limit always bound first.
#[tokio::test]
async fn xmr_right_tokens_are_not_counted_per_address() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let (id, token) = begun(&w, tmp.path(), &d.base).await;
    let url = format!("{}/xmr/swaps/{id}", d.base);
    let http = reqwest::Client::new();
    let get = |token: &str| {
        let r = http.get(&url).header("X-Swap-Token", token).send();
        async move { r.await.unwrap().status().as_u16() }
    };
    // Spend the swap's whole bucket (`begin` already used some of it).
    let mut ok = 0;
    loop {
        match get(&token).await {
            200 => ok += 1,
            429 => break,
            other => panic!("status {other}"),
        }
        assert!(
            ok <= divi_swapd::XMR_SWAP_LIMIT_PER_WINDOW,
            "no 429 after {ok}"
        );
    }
    let misses = divi_swapd::XMR_TOKEN_MISS_LIMIT_PER_WINDOW;
    for i in 0..misses {
        assert_eq!(get(&format!("{i:064x}")).await, 404, "miss {i}");
    }
    assert_eq!(get(&format!("{misses:064x}")).await, 429, "the next miss");
}

/// With `trust_proxy_headers`, a prober rotating the first `X-Forwarded-For` entry keeps the
/// miss count of the last one.
#[tokio::test]
async fn spoofed_forwarded_for_cannot_reset_token_misses() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve_with(&w, &tmp.path().join("m.db"), true).await;
    let http = reqwest::Client::new();
    let url = format!("{}/xmr/swaps/nope", d.base);
    let misses = divi_swapd::XMR_TOKEN_MISS_LIMIT_PER_WINDOW;
    let mut codes = Vec::new();
    for i in 0..=misses {
        let r = http
            .get(&url)
            .header("x-forwarded-for", format!("203.0.113.{i}, 198.51.100.9"))
            .header("X-Swap-Token", "0".repeat(64))
            .send()
            .await
            .unwrap();
        codes.push(r.status().as_u16());
    }
    assert!(
        codes[..misses as usize].iter().all(|c| *c == 404),
        "{codes:?}"
    );
    assert_eq!(codes.last(), Some(&429), "{codes:?}");
    let r = http
        .get(&url)
        .header("x-forwarded-for", "198.51.100.10")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404, "another client is not throttled");
}

/// Starts a swap on `w`'s daemon at `base` and returns its `(maker id, token)`.
async fn begun(w: &World, tmp: &std::path::Path, base: &str) -> (String, String) {
    let tdb = tmp.join("t.db");
    let taker = w.taker(&tdb);
    let client = MakerClient::new(base);
    let sessions = Sessions::beside(&tdb);
    let local = xmr_flow::begin(&taker, &client, &sessions, "divi-xmr-stagenet", XMR_UNITS)
        .await
        .unwrap();
    let session = sessions.get(&local).unwrap();
    (session.maker_swap_id, session.swap_token)
}

/// The shared-bucket DoS: with `trust_proxy_headers` off every client behind a proxy is one
/// address, so a prober there spends the token misses and floods the XMR `:id` routes. A
/// client holding the right token on that same address still reaches every `:id` route.
/// Fails on 747ec44 (the prober's misses lock the whole address out: 429).
#[tokio::test]
async fn a_prober_cannot_lock_a_valid_token_client_out() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let (id, token) = begun(&w, tmp.path(), &d.base).await;
    let url = format!("{}/xmr/swaps/{id}", d.base);
    let http = reqwest::Client::new();
    let limit = divi_swapd::XMR_SWAP_LIMIT_PER_WINDOW;
    let misses = divi_swapd::XMR_TOKEN_MISS_LIMIT_PER_WINDOW;
    for i in 0..misses + 5 {
        http.get(&url)
            .header("X-Swap-Token", format!("{i:064x}"))
            .send()
            .await
            .unwrap();
    }
    for _ in 0..limit + 20 {
        http.get(&url).send().await.unwrap();
        http.get(format!("{}/xmr/swaps/nope", d.base))
            .send()
            .await
            .unwrap();
    }
    let r = http.get(&url).header("X-Swap-Token", &token).send().await;
    assert_eq!(
        r.unwrap().status().as_u16(),
        200,
        "GET with the right token"
    );
    for tail in ["j", "sigs", "xmr-lock"] {
        let r = http
            .post(format!("{url}/{tail}"))
            .header("X-Swap-Token", &token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        let code = r.status().as_u16();
        // A junk body: the handler answers it (4xx/5xx), but the gate let it through.
        assert!(
            code != 429 && code != 404,
            "{tail} with the right token: {code}"
        );
    }
}

/// The prober's own guesses are still throttled: past `XMR_TOKEN_MISS_LIMIT_PER_WINDOW`
/// wrong tokens on a real id, every wrong-token request from that address is a 429 on every
/// XMR `:id` route.
#[tokio::test]
async fn wrong_tokens_to_a_real_id_still_hit_the_miss_limit() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let (id, _token) = begun(&w, tmp.path(), &d.base).await;
    let url = format!("{}/xmr/swaps/{id}", d.base);
    let http = reqwest::Client::new();
    let misses = divi_swapd::XMR_TOKEN_MISS_LIMIT_PER_WINDOW;
    for i in 0..misses {
        let r = http
            .get(&url)
            .header("X-Swap-Token", format!("{i:064x}"))
            .send()
            .await;
        assert_eq!(r.unwrap().status().as_u16(), 404, "guess {i}");
    }
    let r = http
        .get(&url)
        .header("X-Swap-Token", format!("{misses:064x}"))
        .send()
        .await;
    assert_eq!(r.unwrap().status().as_u16(), 429, "the next guess");
    for tail in ["j", "sigs", "xmr-lock"] {
        let r = http
            .post(format!("{url}/{tail}"))
            .header("X-Swap-Token", "f".repeat(64))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "{tail} with a wrong token");
    }
    let r = http.get(format!("{}/xmr/swaps/nope", d.base)).send().await;
    assert_eq!(r.unwrap().status().as_u16(), 429, "no token, unknown id");
}

/// A wrong token for an id that exists counts against the address's misses, never against
/// that swap's bucket: after twice the swap limit of wrong-token requests to the real id, its
/// taker still has the whole bucket less what the setup used. Fails on 747ec44 (429 at once).
#[tokio::test]
async fn wrong_tokens_never_spend_the_swaps_bucket() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let (id, token) = begun(&w, tmp.path(), &d.base).await;
    let url = format!("{}/xmr/swaps/{id}", d.base);
    let http = reqwest::Client::new();
    let limit = divi_swapd::XMR_SWAP_LIMIT_PER_WINDOW;
    for i in 0..2 * limit {
        http.get(&url)
            .header("X-Swap-Token", format!("{i:064x}"))
            .send()
            .await
            .unwrap();
    }
    let mut ok = 0;
    loop {
        let r = http.get(&url).header("X-Swap-Token", &token).send().await;
        match r.unwrap().status().as_u16() {
            200 => ok += 1,
            429 => break,
            other => panic!("status {other}"),
        }
        assert!(ok <= limit, "no 429 after {ok} reads");
    }
    // `begin` used about ten `/j` and one `/sigs` of the bucket (at most 66).
    assert!(ok >= limit - 66, "the taker got {ok} of {limit}");
}

/// A swap on `w`'s daemon at `base`, keyed up to its last `/j` exchange; `/sigs` not sent.
struct Keyed {
    taker: XmrTaker,
    local: String,
    id: String,
    token: String,
    /// The last `/j` request: the maker answers a replay with its cached reply (200).
    last_j: JRoundRequest,
    sigs: SigsRequest,
    /// Right-token requests made so far on the `:id` routes (each counts in the swap's bucket).
    spent: u32,
}

async fn keyed(w: &World, tmp: &std::path::Path, base: &str) -> Keyed {
    let taker = w.taker(&tmp.join("t.db"));
    let client = MakerClient::new(base);
    client.wait_ready().await.unwrap();
    taker.warm_primes().await.unwrap();
    let quote = client
        .quote_retrying("divi-xmr-stagenet", XMR_UNITS)
        .await
        .unwrap();
    let (local, req) = taker.prepare(&quote).await.unwrap();
    let mut reply = client.xmr_setup(&req).await.unwrap();
    let (id, token) = (reply.swap_id.clone(), reply.swap_token.clone());
    let (mut last_j, mut spent) = (None, 0);
    let sigs = loop {
        match taker.j_step(&local, reply).await.unwrap() {
            JNext::Sigs(s) => break s,
            JNext::Send(req) => {
                reply = client.xmr_j(&id, &token, &req).await.unwrap();
                spent += 1;
                last_j = Some(req);
            }
        }
    };
    Keyed {
        taker,
        local,
        id,
        token,
        last_j: last_j.expect("at least one /j exchange"),
        sigs,
        spent,
    }
}

/// Sends `/sigs`, then steps the taker (one right-token `GET` per step) until it has locked
/// its XMR; returns the lock notice, not yet sent.
async fn to_xmr_lock(w: &World, k: &mut Keyed, base: &str) -> XmrLockNotice {
    let client = MakerClient::new(base);
    client.xmr_sigs(&k.id, &k.token, &k.sigs).await.unwrap();
    k.spent += 1;
    let deadline = Instant::now() + LOADED_HOST_WAIT;
    loop {
        w.mine();
        let view = client.xmr_swap(&k.id, &k.token).await.unwrap();
        k.spent += 1;
        k.taker.step(&k.local, Some(&view)).await.unwrap();
        if let Some(n) = k.taker.lock_notice(&k.local).unwrap() {
            return n;
        }
        assert!(Instant::now() < deadline, "the taker never locked its XMR");
        // Long enough for the scheduler to act on each block: every step spends a request.
        tokio::time::sleep(TICK * 10).await;
    }
}

async fn post(http: &reqwest::Client, url: &str, token: &str, body: &impl serde::Serialize) -> u16 {
    let r = http.post(url).header("X-Swap-Token", token).json(body);
    r.send().await.unwrap().status().as_u16()
}

/// The POST `:id` routes' limits, each route on a daemon of its own: wrong-token requests
/// to the real id are 404 up to `XMR_TOKEN_MISS_LIMIT_PER_WINDOW`, then 429 through request
/// `XMR_SWAP_LIMIT_PER_WINDOW + 1` (the miss lockout binds before the per-IP bucket of 300
/// could), and the right token with a valid body is still a 200. Passes on 5a35a3e: a guard.
#[tokio::test]
async fn xmr_posts_without_the_token_lock_out_at_the_miss_limit() {
    let limit = divi_swapd::XMR_SWAP_LIMIT_PER_WINDOW;
    let misses = divi_swapd::XMR_TOKEN_MISS_LIMIT_PER_WINDOW as usize;
    for tail in ["j", "sigs", "xmr-lock"] {
        let w = World::new();
        let tmp = tempfile::tempdir().unwrap();
        let d = serve(&w, &tmp.path().join("m.db")).await;
        let mut k = keyed(&w, tmp.path(), &d.base).await;
        let body = match tail {
            "j" => serde_json::to_value(&k.last_j).unwrap(),
            "sigs" => serde_json::to_value(&k.sigs).unwrap(),
            _ => serde_json::to_value(to_xmr_lock(&w, &mut k, &d.base).await).unwrap(),
        };
        let url = format!("{}/xmr/swaps/{}/{tail}", d.base, k.id);
        let http = reqwest::Client::new();
        let mut codes = Vec::new();
        for i in 0..=limit {
            codes.push(post(&http, &url, &format!("{i:064x}"), &body).await);
        }
        assert!(
            codes[..misses].iter().all(|c| *c == 404),
            "{tail}: {codes:?}"
        );
        assert!(
            codes[misses..].iter().all(|c| *c == 429),
            "{tail}: {codes:?}"
        );
        assert_eq!(codes[limit as usize], 429, "{tail}: request {}", limit + 1);
        assert_eq!(
            post(&http, &url, &k.token, &body).await,
            200,
            "{tail} with the token"
        );
    }
}

/// A prober on the taker's address floods every POST `:id` route with wrong and missing
/// tokens, twice the swap limit. The taker still gets a 200 on each with a valid body, and
/// its right-token requests before and after add up to exactly the swap's bucket: none of
/// the prober's were counted in it. Passes on 5a35a3e (c282392's per-swap buckets): a guard.
#[tokio::test]
async fn a_prober_cannot_drain_a_swaps_bucket_on_the_post_routes() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let mut k = keyed(&w, tmp.path(), &d.base).await;
    let url = format!("{}/xmr/swaps/{}", d.base, k.id);
    let http = reqwest::Client::new();
    let limit = divi_swapd::XMR_SWAP_LIMIT_PER_WINDOW;
    let junk = serde_json::json!({});
    for i in 0..2 * limit {
        let tail = ["j", "sigs", "xmr-lock"][i as usize % 3];
        let token = if i % 2 == 0 {
            format!("{i:064x}")
        } else {
            String::new()
        };
        post(&http, &format!("{url}/{tail}"), &token, &junk).await;
    }
    assert_eq!(
        post(&http, &format!("{url}/j"), &k.token, &k.last_j).await,
        200,
        "/j"
    );
    k.spent += 1;
    let notice = to_xmr_lock(&w, &mut k, &d.base).await; // sends `/sigs`: a 200 or it panics
    assert_eq!(
        post(&http, &format!("{url}/sigs"), &k.token, &k.sigs).await,
        200,
        "/sigs"
    );
    k.spent += 1;
    let lock = format!("{url}/xmr-lock");
    let mut ok = 0;
    loop {
        match post(&http, &lock, &k.token, &notice).await {
            200 => ok += 1,
            429 => break,
            other => panic!("/xmr-lock: status {other}"),
        }
        assert!(ok <= limit, "no 429 after {ok}");
    }
    assert!(ok > 0, "/xmr-lock with the token");
    assert_eq!(
        k.spent + ok,
        limit,
        "the taker's requests fill the bucket exactly"
    );
}
