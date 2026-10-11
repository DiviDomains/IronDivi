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

//! Daemon + taker CLI flow over simulated DIVI and LTC chains, talking real HTTP: the
//! mock `divi-ltc-testnet` / `ltc-divi-testnet` offers, claimed and refunded.

use std::sync::Arc;
use std::time::Duration;

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain, MOCK_FEE};
use divi_swap::{
    Amount, Chain, ChainBackend, Maker, Profile, Store, SwapConfig, SwapState, Taker, TakerState,
};
use divi_swap_cli::{flow, run_swap, MakerClient, RunOpts, Sessions};
use divi_swapd::{mock_counter_offers, router, spawn_scheduler, AppState, ScanStatus};
use tokio::task::JoinHandle;

const T0: u32 = 1_700_000_000;
const LTC_SATS: u64 = 1_000_000;
const TICK: Duration = Duration::from_millis(15);
/// A BTC offer beside the LTC ones, for the old-client checks.
const BTC_OFFER: &str = "divi-btc-testnet";

/// DIVI and LTC chains; the maker also holds an (idle) BTC backend, as the daemon does.
struct World {
    divi: MockChain,
    ltc: MockChain,
    maker_divi: MockBackend,
    maker_ltc: MockBackend,
    maker_btc: MockBackend,
    taker_divi: MockBackend,
    taker_ltc: MockBackend,
}

impl World {
    fn new() -> Self {
        let divi = MockChain::new(Chain::Divi, T0, 60);
        let ltc = MockChain::new(Chain::Ltc, T0, 150);
        let btc = MockChain::new(Chain::Btc, T0, 600);
        let fund = Amount(1_000 * Amount::COIN);
        World {
            maker_divi: divi.backend(1, fund),
            maker_ltc: ltc.backend(2, fund),
            maker_btc: btc.backend(3, fund),
            taker_divi: divi.backend(4, fund),
            taker_ltc: ltc.backend(5, fund),
            divi,
            ltc,
        }
    }

    fn mine(&self) {
        self.divi.mine(1);
        self.ltc.mine(1);
    }

    /// The mock daemon's LTC offer in `dir`.
    fn offer(dir: Direction) -> Offer {
        mock_counter_offers()
            .into_iter()
            .find(|o| o.counter_chain == Chain::Ltc && o.direction == dir)
            .expect("mock LTC offer")
    }

    /// The chain and the maker's / taker's backend of each leg.
    fn legs(&self, dir: Direction) -> Legs<'_> {
        match dir {
            Direction::TakerPaysBtc => Legs {
                taker_chain: &self.ltc,
                maker_chain: &self.divi,
                taker_on_taker_leg: &self.taker_ltc,
                maker_on_taker_leg: &self.maker_ltc,
                taker_on_maker_leg: &self.taker_divi,
                maker_on_maker_leg: &self.maker_divi,
            },
            Direction::TakerPaysDivi => Legs {
                taker_chain: &self.divi,
                maker_chain: &self.ltc,
                taker_on_taker_leg: &self.taker_divi,
                maker_on_taker_leg: &self.maker_divi,
                taker_on_maker_leg: &self.taker_ltc,
                maker_on_maker_leg: &self.maker_ltc,
            },
        }
    }
}

struct Legs<'a> {
    taker_chain: &'a MockChain,
    maker_chain: &'a MockChain,
    taker_on_taker_leg: &'a MockBackend,
    maker_on_taker_leg: &'a MockBackend,
    taker_on_maker_leg: &'a MockBackend,
    maker_on_maker_leg: &'a MockBackend,
}

fn bal(chain: &MockChain, b: &MockBackend) -> u64 {
    chain.balance(&b.pubkey()).0
}

struct Daemon {
    base: String,
    tasks: [JoinHandle<()>; 2],
}

impl Drop for Daemon {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// A maker trading DIVI against BTC and LTC with the mock LTC offers, under `/swap`.
async fn serve(w: &World, db: &std::path::Path) -> Daemon {
    let counters: Vec<Arc<dyn ChainBackend>> =
        vec![Arc::new(w.maker_btc.clone()), Arc::new(w.maker_ltc.clone())];
    let mut offers = [Direction::TakerPaysBtc, Direction::TakerPaysDivi]
        .map(World::offer)
        .to_vec();
    offers.push(Offer {
        id: BTC_OFFER.into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: 300_000 * Amount::COIN,
        min_btc_sats: 5_000,
        max_btc_sats: 50_000,
    });
    let maker = Arc::new(
        Maker::with_counters(
            SwapConfig::profile(Profile::Testnet),
            Arc::new(w.maker_divi.clone()),
            counters,
            Store::open(db).unwrap(),
            offers,
        )
        .unwrap(),
    );
    let state = AppState {
        maker: maker.clone(),
        divi: Arc::new(w.maker_divi.clone()),
        btc: Arc::new(w.maker_btc.clone()),
        scan: ScanStatus::done(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/swap", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state, "/swap")).await.unwrap();
    });
    Daemon {
        base,
        tasks: [server, spawn_scheduler(maker, TICK)],
    }
}

/// The taker CLI's engine with `--counter-chain ltc`.
fn taker(w: &World, db: &std::path::Path) -> Taker {
    Taker::new(
        Arc::new(w.taker_divi.clone()),
        Arc::new(w.taker_ltc.clone()),
        Store::open(db).unwrap(),
    )
}

async fn wait_state(client: &MakerClient, id: &str, want: SwapState, w: &World) {
    let mut state = SwapState::Quoted;
    for _ in 0..600 {
        w.mine();
        state = client.swap(id).await.unwrap().state;
        if state == want {
            return;
        }
        tokio::time::sleep(TICK).await;
    }
    panic!("never reached {want:?}; stuck in {state:?}");
}

async fn happy(dir: Direction) {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let tdb = tmp.path().join("t.db");
    let taker = taker(&w, &tdb);
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);
    let l = w.legs(dir);
    let offer = World::offer(dir);
    let divi_sats = offer.divi_for(LTC_SATS).0;
    let (taker_amt, maker_amt) = match dir {
        Direction::TakerPaysBtc => (LTC_SATS, divi_sats),
        Direction::TakerPaysDivi => (divi_sats, LTC_SATS),
    };
    let maker_got_before = bal(l.taker_chain, l.maker_on_taker_leg);
    let taker_got_before = bal(l.maker_chain, l.taker_on_maker_leg);

    let opts = RunOpts {
        timeout: Duration::from_secs(60),
        poll: TICK,
    };
    let (local, state) = run_swap(
        &taker,
        &client,
        &sessions,
        &offer.id,
        LTC_SATS,
        &opts,
        &mut || w.mine(),
    )
    .await
    .unwrap();
    assert_eq!(state, TakerState::Done);
    let id = sessions.get(&local).unwrap().maker_swap_id;
    wait_state(&client, &id, SwapState::Done, &w).await;
    let view = client.swap(&id).await.unwrap();
    assert!(view.preimage.is_some(), "claim revealed the preimage");
    assert_eq!(view.quote.counter_chain, Chain::Ltc);
    assert_eq!(view.quote.direction, dir);
    assert_eq!(view.quote.maker_btc_pubkey, w.maker_ltc.pubkey());

    // Each side received the other's leg, less one claim fee, on the right chain.
    assert_eq!(
        bal(l.taker_chain, l.maker_on_taker_leg) - maker_got_before,
        taker_amt - MOCK_FEE.0
    );
    assert_eq!(
        bal(l.maker_chain, l.taker_on_maker_leg) - taker_got_before,
        maker_amt - MOCK_FEE.0
    );
    assert_eq!(l.maker_on_maker_leg.funding_calls(), 1);
    assert_eq!(l.maker_on_taker_leg.funding_calls(), 0);
    assert_eq!(w.maker_btc.funding_calls(), 0, "BTC untouched");
}

/// Case C: both lock, the taker never claims; both sides refund after their timeouts.
async fn refund(dir: Direction) {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let tdb = tmp.path().join("t.db");
    let taker = taker(&w, &tdb);
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);
    let l = w.legs(dir);
    let offer = World::offer(dir);
    let taker_before = bal(l.taker_chain, l.taker_on_taker_leg);
    let maker_before = bal(l.maker_chain, l.maker_on_maker_leg);

    let local = flow::begin(&taker, &client, &sessions, &offer.id, LTC_SATS)
        .await
        .unwrap();
    flow::lock(&taker, &client, &sessions, &local)
        .await
        .unwrap();
    let id = sessions.get(&local).unwrap().maker_swap_id;
    wait_state(&client, &id, SwapState::MakerLockConfirmed, &w).await;
    assert!(bal(l.maker_chain, l.maker_on_maker_leg) < maker_before);

    // Past the maker timeout (3 h) the maker refunds its leg.
    l.maker_chain.advance_time(4 * 3600);
    wait_state(&client, &id, SwapState::Done, &w).await;
    assert!(client.swap(&id).await.unwrap().preimage.is_none());
    assert!(bal(l.maker_chain, l.maker_on_maker_leg) >= maker_before - 2 * MOCK_FEE.0);

    // Past the taker timeout (6 h) the taker refunds its leg.
    l.taker_chain.advance_time(7 * 3600);
    let mut state = TakerState::Locked;
    for _ in 0..200 {
        w.mine();
        state = flow::step(&taker, &client, &sessions, &local)
            .await
            .unwrap();
        if state == TakerState::Done {
            break;
        }
        tokio::time::sleep(TICK).await;
    }
    assert_eq!(state, TakerState::Done);
    assert!(bal(l.taker_chain, l.taker_on_taker_leg) >= taker_before - 2 * MOCK_FEE.0);
    // Nobody got the other's coins.
    let tr = Store::open(&tdb).unwrap().get_taker_swap(&local).unwrap();
    let tr = tr.unwrap();
    assert!(tr.maker_leg_claim.is_none() && tr.taker_leg_refund.is_some());
}

#[tokio::test]
async fn e2e_mock_ltc_forward_happy() {
    happy(Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn e2e_mock_ltc_reverse_happy() {
    happy(Direction::TakerPaysDivi).await;
}

#[tokio::test]
async fn e2e_mock_ltc_forward_refund() {
    refund(Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn e2e_mock_ltc_reverse_refund() {
    refund(Direction::TakerPaysDivi).await;
}

/// `POST /swaps` with a body shaped like a v0.2.5 taker's (no `counter_chain`), or a current
/// one's (`echo = Some(..)`), for a fresh quote on `offer`. Returns the status and body.
async fn raw_take(
    w: &World,
    base: &str,
    offer: &str,
    sats: u64,
    echo: Option<&str>,
) -> (u16, serde_json::Value) {
    let q: serde_json::Value = reqwest::get(format!("{base}/offers/{offer}/quote?btc_sats={sats}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut body = serde_json::json!({
        "quote_id": q["id"],
        "hash": hex::encode(rand::random::<[u8; 32]>()),
        "taker_btc_pubkey": hex::encode(w.taker_ltc.pubkey()),
        "taker_divi_pubkey": hex::encode(w.taker_divi.pubkey()),
    });
    if let Some(c) = echo {
        body["counter_chain"] = c.into();
    }
    let r = reqwest::Client::new()
        .post(format!("{base}/swaps"))
        .json(&body)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

async fn swap_count(base: &str) -> usize {
    let all: serde_json::Value = reqwest::get(format!("{base}/swaps"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    all.as_array().unwrap().len()
}

/// Wave-4 safety: a v0.2.5 taker CLI (which ignores `counter_chain` and would lock BTC) is
/// refused on both LTC offers with a 400 that says what to do, before any swap exists.
#[tokio::test]
async fn old_client_take_of_ltc_offer_is_rejected() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    for dir in [Direction::TakerPaysBtc, Direction::TakerPaysDivi] {
        let offer = World::offer(dir);
        let (code, body) = raw_take(&w, &d.base, &offer.id, LTC_SATS, None).await;
        assert_eq!(code, 400, "{body}");
        let msg = body["error"].as_str().unwrap();
        assert!(msg.contains("does not name a counter chain"), "{msg}");
        assert!(msg.contains("--counter-chain ltc"), "{msg}");
        // Naming the wrong chain is refused too.
        let (code, _) = raw_take(&w, &d.base, &offer.id, LTC_SATS, Some("btc")).await;
        assert_eq!(code, 400);
    }
    assert_eq!(swap_count(&d.base).await, 0, "nothing accepted");
    assert_eq!(
        w.maker_ltc.funding_calls() + w.maker_divi.funding_calls(),
        0
    );
}

/// The v0.2.5 wire stays valid for BTC offers.
#[tokio::test]
async fn old_client_take_of_btc_offer_is_accepted() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let (code, body) = raw_take(&w, &d.base, BTC_OFFER, 10_000, None).await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["state"], "Accepted");
    assert_eq!(body["quote"]["counter_chain"], "btc");
}

/// A current client names the chain and is accepted, over raw HTTP and through the CLI flow.
#[tokio::test]
async fn new_client_take_of_ltc_offer_is_accepted() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let offer = World::offer(Direction::TakerPaysBtc);
    let (code, body) = raw_take(&w, &d.base, &offer.id, LTC_SATS, Some("ltc")).await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["quote"]["counter_chain"], "ltc");

    let tdb = tmp.path().join("t.db");
    let taker = taker(&w, &tdb);
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);
    let local = flow::begin(&taker, &client, &sessions, &offer.id, LTC_SATS)
        .await
        .unwrap();
    let id = sessions.get(&local).unwrap().maker_swap_id;
    assert_eq!(client.swap(&id).await.unwrap().state, SwapState::Accepted);
    assert_eq!(swap_count(&d.base).await, 2);
}

/// A taker CLI left on its default `--counter-chain btc` is told what to pass, and nothing
/// reaches the maker.
#[tokio::test]
async fn btc_taker_on_ltc_offer_is_told_to_pass_counter_chain() {
    let w = World::new();
    let tmp = tempfile::tempdir().unwrap();
    let d = serve(&w, &tmp.path().join("m.db")).await;
    let tdb = tmp.path().join("t.db");
    let btc_taker = Taker::new(
        Arc::new(w.taker_divi.clone()),
        Arc::new(w.maker_btc.clone()),
        Store::open(&tdb).unwrap(),
    );
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);
    let offer = World::offer(Direction::TakerPaysBtc);
    let err = flow::begin(&btc_taker, &client, &sessions, &offer.id, LTC_SATS)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("--counter-chain ltc"), "{err}");
    assert_eq!(swap_count(&d.base).await, 0);
    assert!(Store::open(&tdb)
        .unwrap()
        .list_taker_swaps()
        .unwrap()
        .is_empty());
}
