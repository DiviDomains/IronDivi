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

//! The end-to-end claim policies (case C never-claim, case D late claim) over simulated chains.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use divi_swap::{Store, SwapState, TakerState};
use divi_swap_cli::{flow, ClaimGate, ClaimPolicy, MakerClient, RunOpts, Sessions};

const TICK: Duration = Duration::from_millis(15);

fn fast() -> RunOpts {
    RunOpts {
        timeout: Duration::from_secs(120),
        poll: Duration::from_millis(15),
    }
}

#[test]
fn late_claim_lead_must_exceed_the_safety_margin() {
    let p = |n| ClaimPolicy::NotBefore {
        secs_before_timeout: n,
    };
    assert!(p(1800).validate().is_err());
    assert!(p(2400).validate().is_ok());
    assert!(ClaimPolicy::Never.validate().is_ok());
}

/// Case D: the claim is held until the DIVI MTP is `lead` seconds before the maker's
/// locktime, then goes through; the maker still claims the BTC.
#[tokio::test]
async fn late_claim_waits_then_both_sides_finish() {
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
    let lead = 2400;
    let gate = ClaimGate {
        policy: ClaimPolicy::NotBefore {
            secs_before_timeout: lead,
        },
        store: Store::open(&tdb).unwrap(),
        divi: Arc::new(w.taker_divi.clone()),
        btc: Arc::new(w.taker_btc.clone()),
    };
    let mut polls = 0u32;
    let (local, state) = flow::run_swap_gated(
        &taker,
        &client,
        &sessions,
        OFFER_ID,
        BTC_SATS,
        &fast(),
        &mut || {
            polls += 1;
            w.divi.mine(1);
            w.divi.advance_time(120);
            w.btc.mine(1); // 600 s a block: stays well inside the 6 h BTC timelock
        },
        Some(&gate),
    )
    .await
    .unwrap();
    assert_eq!(state, TakerState::Done);
    assert!(polls > 30, "the claim was not held back ({polls} polls)");

    // The claim landed in the window [lead - one poll, lead).
    let rec = Store::open(&tdb)
        .unwrap()
        .get_taker_swap(&local)
        .unwrap()
        .unwrap();
    let locktime = rec.divi_htlc.unwrap().locktime;
    let left = locktime.saturating_sub(w.divi.mtp());
    assert!((1800..=lead).contains(&left), "{left}s before timeout");

    let id = sessions.get(&local).unwrap().maker_swap_id;
    let mut end = SwapState::Quoted;
    for _ in 0..600 {
        w.btc.mine(1);
        end = client.swap(&id).await.unwrap().state;
        if end == SwapState::Done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert_eq!(end, SwapState::Done);
    assert!(client.swap(&id).await.unwrap().preimage.is_some());
    d.stop();
}

/// Case C through the gated runner: the taker verifies the maker's lock, never claims,
/// and ends refunded after both timeouts.
#[tokio::test]
async fn never_claim_ends_in_refunds() {
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
    let gate = ClaimGate {
        policy: ClaimPolicy::Never,
        store: Store::open(&tdb).unwrap(),
        divi: Arc::new(w.taker_divi.clone()),
        btc: Arc::new(w.taker_btc.clone()),
    };
    let (local, state) = flow::run_swap_gated(
        &taker,
        &client,
        &sessions,
        OFFER_ID,
        BTC_SATS,
        &fast(),
        &mut || {
            w.divi.mine(1);
            w.divi.advance_time(300);
            w.btc.mine(1);
            w.btc.advance_time(300);
        },
        Some(&gate),
    )
    .await
    .unwrap();
    assert_eq!(state, TakerState::Done);
    let id = sessions.get(&local).unwrap().maker_swap_id;
    let view = client.swap(&id).await.unwrap();
    assert!(view.preimage.is_none(), "nothing was ever claimed");
    let rec = Store::open(&tdb)
        .unwrap()
        .get_taker_swap(&local)
        .unwrap()
        .unwrap();
    assert!(rec.divi_claim.is_none());
    assert!(rec.btc_refund.is_some());
    d.stop();
}
