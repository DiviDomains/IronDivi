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

//! Daemon + taker engine over two simulated chains, talking real HTTP.

mod common;

use std::time::Duration;

use common::*;
use divi_swap::api::Direction;
use divi_swap::mock::MOCK_FEE;
use divi_swap::{Store, SwapState, TakerState};
use divi_swap_cli::{flow, run_swap, MakerClient, RunOpts, Sessions};

const TICK: Duration = Duration::from_millis(15);

fn fast() -> RunOpts {
    RunOpts {
        timeout: Duration::from_secs(60),
        poll: Duration::from_millis(15),
    }
}

async fn wait_state(
    client: &MakerClient,
    id: &str,
    want: &[SwapState],
    mut each: impl FnMut(),
) -> SwapState {
    let mut state = SwapState::Quoted;
    for _ in 0..600 {
        each();
        state = client.swap(id).await.unwrap().state;
        if want.contains(&state) {
            return state;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    panic!("never reached {want:?}; stuck in {state:?}");
}

#[tokio::test]
async fn e2e_mock_happy_path() {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap();
    let d = serve(
        &w,
        w.maker(Store::open(&dir.path().join("m.db")).unwrap()),
        Some(TICK),
    )
    .await;
    let tdb = dir.path().join("t.db");
    let taker = w.taker(&tdb);
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);

    let (local, state) = run_swap(
        &taker,
        &client,
        &sessions,
        OFFER_ID,
        BTC_SATS,
        &fast(),
        &mut || w.mine_both(),
    )
    .await
    .unwrap();
    assert_eq!(state, TakerState::Done);

    let id = sessions.get(&local).unwrap().maker_swap_id;
    let end = wait_state(&client, &id, &[SwapState::Done], || w.mine_both()).await;
    assert_eq!(end, SwapState::Done);
    let view = client.swap(&id).await.unwrap();
    assert!(view.preimage.is_some(), "claim revealed the preimage");

    // Maker got the BTC, taker got the DIVI.
    assert!(w.btc.balance(&w.maker_btc_pub()).0 >= BTC_SATS - 2 * MOCK_FEE.0);
    assert!(w.divi.balance(&w.taker_divi_pub()).0 > 0);
    d.stop();
}

#[tokio::test]
async fn e2e_mock_refund() {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap();
    let d = serve(
        &w,
        w.maker(Store::open(&dir.path().join("m.db")).unwrap()),
        Some(TICK),
    )
    .await;
    let tdb = dir.path().join("t.db");
    let taker = w.taker(&tdb);
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);
    let btc_before = w.btc.balance(&w.taker_btc_pub());
    let divi_before = w.divi.balance(&w.maker_divi_pub());

    // Taker locks, the maker locks, and the taker then goes silent (case C).
    let local = flow::begin(&taker, &client, &sessions, OFFER_ID, BTC_SATS)
        .await
        .unwrap();
    flow::lock(&taker, &client, &sessions, &local)
        .await
        .unwrap();
    let id = sessions.get(&local).unwrap().maker_swap_id;
    wait_state(&client, &id, &[SwapState::MakerLockConfirmed], || {
        w.mine_both()
    })
    .await;
    assert!(
        w.divi.balance(&w.maker_divi_pub()).0 < divi_before.0,
        "maker DIVI is locked"
    );

    // Past the maker timeout the maker refunds its DIVI.
    w.divi.advance_time(4 * 3600);
    let end = wait_state(&client, &id, &[SwapState::Done], || w.mine_both()).await;
    assert_eq!(end, SwapState::Done);
    assert!(
        w.divi.balance(&w.maker_divi_pub()).0 >= divi_before.0 - 2 * MOCK_FEE.0,
        "maker DIVI came back"
    );
    assert!(client.swap(&id).await.unwrap().preimage.is_none());

    // Past the taker timeout the taker refunds its BTC.
    w.btc.advance_time(7 * 3600);
    w.btc.mine(1);
    let mut state = TakerState::Locked;
    for _ in 0..200 {
        state = flow::step(&taker, &client, &sessions, &local)
            .await
            .unwrap();
        if state == TakerState::Done {
            break;
        }
        w.mine_both();
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert_eq!(state, TakerState::Done);
    assert!(
        w.btc.balance(&w.taker_btc_pub()).0 >= btc_before.0 - 2 * MOCK_FEE.0,
        "taker BTC came back"
    );
    d.stop();
}

#[tokio::test]
async fn e2e_mock_rev_happy_path() {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap();
    let d = serve(
        &w,
        w.maker(Store::open(&dir.path().join("m.db")).unwrap()),
        Some(TICK),
    )
    .await;
    let tdb = dir.path().join("t.db");
    let taker = w.taker(&tdb);
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);
    let btc_before = w.btc.balance(&w.taker_btc_pub());
    let divi_before = w.divi.balance(&w.maker_divi_pub());

    let (local, state) = run_swap(
        &taker,
        &client,
        &sessions,
        REV_OFFER_ID,
        BTC_SATS,
        &fast(),
        &mut || w.mine_both(),
    )
    .await
    .unwrap();
    assert_eq!(state, TakerState::Done);

    let id = sessions.get(&local).unwrap().maker_swap_id;
    let end = wait_state(&client, &id, &[SwapState::Done], || w.mine_both()).await;
    assert_eq!(end, SwapState::Done);
    let view = client.swap(&id).await.unwrap();
    assert!(view.preimage.is_some(), "claim revealed the preimage");
    assert_eq!(view.quote.direction, Direction::TakerPaysDivi);

    // The taker sold DIVI and received the BTC; the maker has the DIVI.
    assert!(w.btc.balance(&w.taker_btc_pub()).0 >= btc_before.0 + BTC_SATS - 2 * MOCK_FEE.0);
    assert!(w.divi.balance(&w.maker_divi_pub()).0 > divi_before.0);
    d.stop();
}

#[tokio::test]
async fn e2e_mock_rev_refund() {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap();
    let d = serve(
        &w,
        w.maker(Store::open(&dir.path().join("m.db")).unwrap()),
        Some(TICK),
    )
    .await;
    let tdb = dir.path().join("t.db");
    let taker = w.taker(&tdb);
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&tdb);
    let divi_before = w.divi.balance(&w.taker_divi_pub());
    let btc_before = w.btc.balance(&w.maker_btc_pub());

    // Taker locks DIVI, the maker locks BTC, and the taker then goes silent (case C).
    let local = flow::begin(&taker, &client, &sessions, REV_OFFER_ID, BTC_SATS)
        .await
        .unwrap();
    flow::lock(&taker, &client, &sessions, &local)
        .await
        .unwrap();
    let id = sessions.get(&local).unwrap().maker_swap_id;
    wait_state(&client, &id, &[SwapState::MakerLockConfirmed], || {
        w.mine_both()
    })
    .await;
    assert!(
        w.btc.balance(&w.maker_btc_pub()).0 < btc_before.0,
        "maker BTC is locked"
    );

    // Past the maker timeout the maker refunds its BTC.
    w.btc.advance_time(4 * 3600);
    let end = wait_state(&client, &id, &[SwapState::Done], || w.mine_both()).await;
    assert_eq!(end, SwapState::Done);
    assert!(
        w.btc.balance(&w.maker_btc_pub()).0 >= btc_before.0 - 2 * MOCK_FEE.0,
        "maker BTC came back"
    );
    assert!(client.swap(&id).await.unwrap().preimage.is_none());

    // Past the taker timeout the taker refunds its DIVI.
    w.divi.advance_time(7 * 3600);
    w.divi.mine(1);
    let mut state = TakerState::Locked;
    for _ in 0..200 {
        state = flow::step(&taker, &client, &sessions, &local)
            .await
            .unwrap();
        if state == TakerState::Done {
            break;
        }
        w.mine_both();
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert_eq!(state, TakerState::Done);
    assert!(
        w.divi.balance(&w.taker_divi_pub()).0 >= divi_before.0 - 2 * MOCK_FEE.0,
        "taker DIVI came back"
    );
    d.stop();
}
