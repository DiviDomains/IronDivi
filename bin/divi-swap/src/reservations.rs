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

//! The taker's lock-input reservations: the `input_reservation` table in the `--db` swap
//! database, the same table `divi-swapd --reservations` lists and `--release-reservation`
//! edits. A live BTC, LTC or ZEC taker reserves the inputs of its funding tx before the
//! broadcast, so a second taker on the same wallet (another `divi-swap` process on the same
//! `--db`) never selects them. The backend releases them once it sees that tx confirmed;
//! the taker never asks for its own lock's confirmations, so [`release_finished`] releases
//! the lock of every finished taker swap instead.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use divi_swap::{InputReservations, Store};

/// Open the swap database at `db` and its reservation table. The store opens first, so a
/// new file is created at mode 0600 before SQLite touches it (it holds the preimages).
pub fn open(db: &Path) -> Result<(Store, InputReservations)> {
    let store =
        Store::open(db).with_context(|| format!("opening swap database {}", db.display()))?;
    let res = InputReservations::open(db).context("opening input reservations")?;
    Ok((store, res))
}

/// Release the reservations held by the taker-leg funding tx of every terminal
/// ([`divi_swap::TakerState::is_terminal`]) taker swap in `store`; returns how many inputs
/// were released. A finished swap's lock is on chain (its refund or the maker's claim spent
/// it), so its inputs can never be selected again anyway. Only rows still held are touched:
/// running it again, or after a restart, releases nothing twice, and a swap that is not
/// finished keeps its reservation however often it runs.
pub fn release_finished(store: &Store, res: &InputReservations) -> Result<usize> {
    let held: HashSet<_> = res
        .list_all()?
        .into_iter()
        .map(|r| (r.chain, r.reserved_by))
        .collect();
    if held.is_empty() {
        return Ok(0);
    }
    let mut released = 0;
    for s in store.list_taker_swaps()? {
        let Some(f) = s.taker_leg_funding.as_ref() else {
            continue;
        };
        let lock = (s.quote.taker_chain(), f.tx.txid);
        if s.state.is_terminal() && held.contains(&lock) {
            released += res.release_tx(lock.0, &lock.1)?;
        }
    }
    Ok(released)
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_swap::api::{Direction, Quote};
    use divi_swap::store::TakerRecord;
    use divi_swap::{Amount, Chain, Funding, HtlcParams, Outpoint, SignedTx, TakerState, Txid};

    fn op(n: u8) -> Outpoint {
        Outpoint {
            txid: Txid([n; 32]),
            vout: 0,
        }
    }

    /// A taker swap in `state` whose taker-leg lock on `chain` is the tx `[lock; 32]`.
    fn swap(id: &str, state: TakerState, chain: Chain, lock: u8) -> TakerRecord {
        let htlc = HtlcParams {
            hash: [1; 32],
            claim_pubkey: [2; 33],
            refund_pubkey: [3; 33],
            locktime: 1_800_000_000,
            script_version: Default::default(),
        };
        TakerRecord {
            id: id.into(),
            state,
            quote: Quote {
                id: format!("q-{id}"),
                offer_id: "o".into(),
                direction: Direction::TakerPaysBtc,
                counter_chain: chain,
                btc_amount: Amount(1),
                divi_amount: Amount(2),
                expires_at: 3,
                maker_btc_pubkey: [2; 33],
                maker_divi_pubkey: [3; 33],
                taker_timeout_secs: 4,
                maker_timeout_secs: 5,
                btc_confirmations: 1,
                divi_confirmations: 1,
            },
            preimage: [9; 32],
            hash: [lock; 32],
            maker_swap_id: None,
            taker_leg_htlc: Some(htlc),
            taker_leg_funding: Some(Funding {
                tx: SignedTx {
                    txid: Txid([lock; 32]),
                    raw: vec![],
                },
                outpoint: op(lock),
                amount: Amount(1),
            }),
            maker_leg_htlc: None,
            maker_leg_outpoint: None,
            maker_leg_amount: None,
            maker_leg_claim: None,
            taker_leg_refund: None,
            claim_declined: None,
            claim_base_feerate: None,
            claim_feerate: None,
            claim_replaced: Vec::new(),
            claim_children: Vec::new(),
            last_error: None,
        }
    }

    /// Completed (claimed then done) 0x11 and refunded-then-done 0x12 on BTC, done 0x13 on
    /// LTC, plus live swaps: `Locked` 0x21, `Claimed` 0x22, `Refunded` 0x23, and an orphan
    /// lock 0x31 no swap names. Each lock reserves input `[lock+0x40; 32]:0`.
    fn db(dir: &Path) -> std::path::PathBuf {
        let db = dir.join("swaps.db");
        let (store, res) = open(&db).unwrap();
        let mut refunded = swap("refunded", TakerState::Done, Chain::Btc, 0x12);
        refunded.taker_leg_refund = Some(SignedTx {
            txid: Txid([0x52; 32]),
            raw: vec![],
        });
        for s in [
            swap("claimed", TakerState::Done, Chain::Btc, 0x11),
            refunded,
            swap("ltc", TakerState::Done, Chain::Ltc, 0x13),
            swap("locked", TakerState::Locked, Chain::Btc, 0x21),
            swap("claiming", TakerState::Claimed, Chain::Btc, 0x22),
            swap("refunding", TakerState::Refunded, Chain::Btc, 0x23),
        ] {
            store.put_taker_swap(&s).unwrap();
        }
        for (chain, lock) in [
            (Chain::Btc, 0x11),
            (Chain::Btc, 0x12),
            (Chain::Ltc, 0x13),
            (Chain::Btc, 0x21),
            (Chain::Btc, 0x22),
            (Chain::Btc, 0x23),
            (Chain::Btc, 0x31),
        ] {
            res.reserve(chain, &Txid([lock; 32]), &[op(lock + 0x40)])
                .unwrap();
        }
        db
    }

    fn held(db: &Path) -> HashSet<u8> {
        InputReservations::open_read_only(db)
            .unwrap()
            .list_all()
            .unwrap()
            .into_iter()
            .map(|r| r.reserved_by.0[0])
            .collect()
    }

    #[test]
    fn finished_swaps_release_their_lock_inputs_and_live_ones_keep_them() {
        let dir = tempfile::tempdir().unwrap();
        let db = db(dir.path());
        let (store, res) = open(&db).unwrap();
        assert_eq!(release_finished(&store, &res).unwrap(), 3);
        assert_eq!(held(&db), HashSet::from([0x21, 0x22, 0x23, 0x31]));
        // The released inputs can be taken by a new lock.
        res.reserve(Chain::Btc, &Txid([0x77; 32]), &[op(0x51)])
            .unwrap();
    }

    #[test]
    fn a_second_run_and_a_restart_release_nothing_twice() {
        let dir = tempfile::tempdir().unwrap();
        let db = db(dir.path());
        let (store, res) = open(&db).unwrap();
        assert_eq!(release_finished(&store, &res).unwrap(), 3);
        assert_eq!(release_finished(&store, &res).unwrap(), 0);
        // A new lock takes a released input: a repeat run must leave it reserved.
        res.reserve(Chain::Btc, &Txid([0x77; 32]), &[op(0x51)])
            .unwrap();
        drop((store, res));

        // New process on the same file.
        let (store, res) = open(&db).unwrap();
        assert_eq!(release_finished(&store, &res).unwrap(), 0);
        assert_eq!(held(&db), HashSet::from([0x21, 0x22, 0x23, 0x31, 0x77]));
    }

    #[test]
    fn a_swap_that_finishes_after_a_restart_is_released_then() {
        let dir = tempfile::tempdir().unwrap();
        let db = db(dir.path());
        {
            let (store, res) = open(&db).unwrap();
            release_finished(&store, &res).unwrap();
        }
        let (store, res) = open(&db).unwrap();
        let mut s = store.get_taker_swap("refunding").unwrap().unwrap();
        s.state = TakerState::Done;
        store.put_taker_swap(&s).unwrap();
        assert_eq!(release_finished(&store, &res).unwrap(), 1);
        assert_eq!(held(&db), HashSet::from([0x21, 0x22, 0x31]));
    }

    #[test]
    fn nothing_held_is_a_no_op_and_open_creates_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("fresh.db");
        let (store, res) = open(&db).unwrap();
        assert_eq!(release_finished(&store, &res).unwrap(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&db).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
