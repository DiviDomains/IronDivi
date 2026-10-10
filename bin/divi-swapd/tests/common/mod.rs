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

//! Shared test world: two simulated chains, a maker daemon on an ephemeral port.

#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use divi_swap::api::Offer;
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{Amount, Chain, ChainBackend, Maker, Profile, Store, SwapConfig, Taker};
use divi_swapd::{router, spawn_scheduler, AppState, ScanStatus};
use tokio::task::JoinHandle;

pub const OFFER_ID: &str = "o1";
pub const BTC_SATS: u64 = 100_000;
pub const T0: u32 = 1_700_000_000;

pub struct World {
    pub divi: MockChain,
    pub btc: MockChain,
    pub maker_divi: MockBackend,
    pub maker_btc: MockBackend,
    pub taker_divi: MockBackend,
    pub taker_btc: MockBackend,
}

impl World {
    pub fn new() -> Self {
        let divi = MockChain::new(Chain::Divi, T0, 60);
        let btc = MockChain::new(Chain::Btc, T0, 600);
        World {
            maker_divi: divi.backend(1, Amount(1_000_000 * Amount::COIN)),
            maker_btc: btc.backend(2, Amount(0)),
            taker_divi: divi.backend(3, Amount(0)),
            taker_btc: btc.backend(4, Amount(10 * Amount::COIN)),
            divi,
            btc,
        }
    }

    pub fn offers() -> Vec<Offer> {
        vec![Offer {
            id: OFFER_ID.into(),
            divi_sats_per_btc: 1_000 * Amount::COIN,
            min_btc_sats: 1_000,
            max_btc_sats: 10_000_000,
        }]
    }

    pub fn maker(&self, store: Store) -> Arc<Maker> {
        Arc::new(
            Maker::new(
                SwapConfig::profile(Profile::Testnet),
                Arc::new(self.maker_divi.clone()),
                Arc::new(self.maker_btc.clone()),
                store,
                Self::offers(),
            )
            .expect("maker"),
        )
    }

    pub fn taker(&self, db: &Path) -> Taker {
        Taker::new(
            Arc::new(self.taker_divi.clone()),
            Arc::new(self.taker_btc.clone()),
            Store::open(db).expect("taker store"),
        )
    }

    pub fn maker_btc_pub(&self) -> [u8; 33] {
        self.maker_btc.pubkey()
    }
    pub fn maker_divi_pub(&self) -> [u8; 33] {
        self.maker_divi.pubkey()
    }
    pub fn taker_btc_pub(&self) -> [u8; 33] {
        self.taker_btc.pubkey()
    }
    pub fn taker_divi_pub(&self) -> [u8; 33] {
        self.taker_divi.pubkey()
    }

    pub fn mine_both(&self) {
        self.divi.mine(1);
        self.btc.mine(1);
    }
}

pub struct Daemon {
    pub base: String,
    pub maker: Arc<Maker>,
    server: JoinHandle<()>,
    scheduler: Option<JoinHandle<()>>,
}

impl Daemon {
    pub fn stop(self) {
        self.server.abort();
        if let Some(s) = self.scheduler {
            s.abort();
        }
    }
}

/// Serve `maker` under `/swap` on an ephemeral port; optionally run the scheduler.
pub async fn serve(world: &World, maker: Arc<Maker>, tick: Option<Duration>) -> Daemon {
    let state = AppState {
        maker: maker.clone(),
        divi: Arc::new(world.maker_divi.clone()),
        btc: Arc::new(world.maker_btc.clone()),
        scan: ScanStatus::done(),
    };
    let app = router(state, "/swap");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Daemon {
        base: format!("http://{addr}/swap"),
        scheduler: tick.map(|t| spawn_scheduler(maker.clone(), t)),
        maker,
        server,
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
