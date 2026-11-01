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

//! One daemon serving BTC, LTC and ZEC offers over HTTP; the taker flow swaps on each.

use std::sync::Arc;
use std::time::Duration;

use divi_swap::api::Offer;
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, Maker, Profile, Store, SwapConfig, Taker, TakerState,
};
use divi_swap_cli::{run_swap, MakerClient, RunOpts, Sessions};
use divi_swapd::{mock_counter_offers, router, spawn_scheduler, AppState, ScanStatus};

const T0: u32 = 1_700_000_000;

struct Net {
    chains: Vec<MockChain>,
    maker: Vec<MockBackend>,
    taker: Vec<MockBackend>,
}

impl Net {
    /// DIVI first, then BTC, LTC, ZEC.
    fn new() -> Self {
        let chains: Vec<MockChain> = [
            (Chain::Divi, 60),
            (Chain::Btc, 600),
            (Chain::Ltc, 150),
            (Chain::Zec, 75),
        ]
        .into_iter()
        .map(|(c, s)| MockChain::new(c, T0, s))
        .collect();
        let fund = Amount(1_000 * Amount::COIN);
        Net {
            maker: chains.iter().map(|c| c.backend(1, fund)).collect(),
            taker: chains.iter().map(|c| c.backend(2, fund)).collect(),
            chains,
        }
    }

    fn mine(&self) {
        for c in &self.chains {
            c.mine(1);
        }
    }

    fn counters(backends: &[MockBackend]) -> Vec<Arc<dyn ChainBackend>> {
        backends[1..]
            .iter()
            .map(|b| Arc::new(b.clone()) as Arc<dyn ChainBackend>)
            .collect()
    }
}

async fn get_json(url: &str) -> serde_json::Value {
    reqwest::get(url).await.unwrap().json().await.unwrap()
}

#[tokio::test]
async fn daemon_swaps_ltc_and_zec_both_ways() {
    let net = Net::new();
    let dir = tempfile::tempdir().unwrap();
    let offers: Vec<Offer> = mock_counter_offers();
    let maker = Arc::new(
        Maker::with_counters(
            SwapConfig::profile(Profile::Testnet),
            Arc::new(net.maker[0].clone()),
            Net::counters(&net.maker),
            Store::open(&dir.path().join("m.db")).unwrap(),
            offers.clone(),
        )
        .unwrap(),
    );
    let state = AppState {
        maker: maker.clone(),
        divi: Arc::new(net.maker[0].clone()),
        btc: Arc::new(net.maker[1].clone()),
        scan: ScanStatus::done(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/swap", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state, "/swap")).await.unwrap();
    });
    let scheduler = spawn_scheduler(maker.clone(), Duration::from_millis(15));

    let listed = get_json(&format!("{base}/offers")).await;
    let ids: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    for want in [
        "divi-ltc-testnet",
        "ltc-divi-testnet",
        "divi-zec-testnet",
        "zec-divi-testnet",
    ] {
        assert!(ids.contains(&want), "{want} missing from {ids:?}");
    }
    let health = get_json(&format!("{base}/healthz")).await;
    assert_eq!(health["ok"], true);
    assert!(health["counters"]["ltc"]["tip"].is_u64());
    assert!(health["counters"]["zec"]["tip"].is_u64());

    let tdb = dir.path().join("t.db");
    let taker = Taker::with_counters(
        Arc::new(net.taker[0].clone()),
        Net::counters(&net.taker),
        Store::open(&tdb).unwrap(),
    );
    let client = MakerClient::new(&base);
    let sessions = Sessions::beside(&tdb);
    let opts = RunOpts {
        timeout: Duration::from_secs(180), // hp2 runs many lanes at once
        poll: Duration::from_millis(15),
    };
    for o in &offers {
        let (local, state) = run_swap(
            &taker,
            &client,
            &sessions,
            &o.id,
            o.min_btc_sats,
            &opts,
            &mut || net.mine(),
        )
        .await
        .unwrap();
        assert_eq!(state, TakerState::Done, "{}", o.id);
        let rec = Store::open(&tdb).unwrap().get_taker_swap(&local).unwrap();
        assert_eq!(rec.unwrap().quote.counter_chain, o.counter_chain);
    }
    scheduler.abort();
    server.abort();
}
