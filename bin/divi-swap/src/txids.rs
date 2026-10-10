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

//! `divi-swap txids` output: `key=value` lines whose names depend on the swap's direction.
//!
//! Forward (`taker_pays_btc`): `btc_lock divi_lock divi_claim_by_taker btc_claim_by_maker
//! divi_spend_by_maker btc_refund_by_taker`. Reverse (`taker_pays_divi`): `divi_lock btc_lock
//! btc_claim_by_taker divi_claim_by_maker btc_spend_by_maker divi_refund_by_taker`.
//! `tools/swap-poc/e2e.sh` reads these, so the forward keys must not change.

use divi_swap::api::{Direction, SwapView};
use divi_swap::store::TakerRecord;

/// The `key=value` lines for one swap, in print order.
pub fn lines(rec: &TakerRecord, view: &SwapView) -> Vec<String> {
    let direction = match rec.quote.direction {
        Direction::TakerPaysBtc => "taker_pays_btc",
        Direction::TakerPaysDivi => "taker_pays_divi",
    };
    let mut out = vec![
        format!("direction={direction}"),
        format!("taker_state={:?}", rec.state),
        format!("maker_state={:?}", view.state),
    ];
    let mut line = |k: &str, v: Option<String>| {
        if let Some(v) = v {
            out.push(format!("{k}={v}"));
        }
    };
    let funding = rec.btc_funding.as_ref().map(|f| f.tx.txid.to_string());
    let claim = rec.divi_claim.as_ref().map(|t| t.txid.to_string());
    let refund = rec.btc_refund.as_ref().map(|t| t.txid.to_string());
    let maker_lock = view
        .maker_leg
        .as_ref()
        .and_then(|l| l.outpoint)
        .map(|o| o.txid.to_string());
    let taker_leg_spend = view.taker_leg.spend_txid.map(|t| t.to_string());
    let maker_leg_spend = view
        .maker_leg
        .as_ref()
        .and_then(|l| l.spend_txid)
        .map(|t| t.to_string());
    match rec.quote.direction {
        Direction::TakerPaysBtc => {
            line("btc_lock", funding);
            line("divi_lock", maker_lock);
            line("divi_claim_by_taker", claim);
            line("btc_claim_by_maker", taker_leg_spend);
            line("divi_spend_by_maker", maker_leg_spend);
            line("btc_refund_by_taker", refund);
        }
        Direction::TakerPaysDivi => {
            // A leg's spend is either the counterparty's claim or its owner's refund; keep the
            // view's spend out of a key when it is the taker's own transaction.
            let other = |spend: Option<String>, own: &[&Option<String>]| {
                spend.filter(|s| !own.iter().any(|o| o.as_deref() == Some(s)))
            };
            line("divi_lock", funding);
            line("btc_lock", maker_lock);
            line("btc_claim_by_taker", claim.clone());
            line("divi_claim_by_maker", other(taker_leg_spend, &[&refund]));
            line("btc_spend_by_maker", other(maker_leg_spend, &[&claim]));
            line("divi_refund_by_taker", refund);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id(n: u8) -> String {
        hex::encode([n; 32])
    }
    fn htlc() -> serde_json::Value {
        let k = hex::encode([2u8; 33]);
        json!({"hash": id(1), "claim_pubkey": k, "refund_pubkey": k, "locktime": 1_700_000_000u32})
    }
    fn quote(direction: &str) -> serde_json::Value {
        let k = hex::encode([2u8; 33]);
        json!({
            "id": "q", "offer_id": "o", "direction": direction, "btc_amount": 1000,
            "divi_amount": 5000, "expires_at": 1, "maker_btc_pubkey": k,
            "maker_divi_pubkey": k, "taker_timeout_secs": 21600, "maker_timeout_secs": 10800,
            "btc_confirmations": 1, "divi_confirmations": 1
        })
    }
    fn tx(n: u8) -> serde_json::Value {
        json!({"txid": id(n), "raw": "00"})
    }
    fn outpoint(n: u8) -> serde_json::Value {
        json!({"txid": id(n), "vout": 0})
    }
    fn leg(lock: Option<u8>, spend: Option<u8>) -> serde_json::Value {
        json!({"htlc": htlc(), "amount": 1000, "outpoint": lock.map(outpoint), "spend_txid": spend.map(id)})
    }
    fn view(
        state: &str,
        direction: &str,
        taker_spend: Option<u8>,
        maker_spend: Option<u8>,
    ) -> SwapView {
        serde_json::from_value(json!({
            "id": "m", "state": state, "quote": quote(direction),
            "taker_leg": leg(Some(10), taker_spend),
            "maker_leg": leg(Some(20), maker_spend),
            "preimage": null, "last_error": null
        }))
        .unwrap()
    }
    fn record(direction: &str, state: &str, claim: Option<u8>, refund: Option<u8>) -> TakerRecord {
        serde_json::from_value(json!({
            "id": "t", "state": state, "quote": quote(direction),
            "preimage": vec![9u8; 32], "hash": vec![1u8; 32], "maker_swap_id": "m",
            "btc_htlc": htlc(),
            "btc_funding": {"tx": tx(10), "outpoint": outpoint(10), "amount": 1000},
            "divi_htlc": htlc(), "divi_outpoint": outpoint(20), "divi_amount": 1000,
            "divi_claim": claim.map(tx), "btc_refund": refund.map(tx), "last_error": null
        }))
        .unwrap()
    }
    fn keys(lines: &[String]) -> Vec<&str> {
        lines.iter().map(|l| l.split('=').next().unwrap()).collect()
    }

    #[test]
    fn txids_forward_keys_unchanged() {
        let l = lines(
            &record("taker_pays_btc", "done", Some(30), None),
            &view("Done", "taker_pays_btc", Some(40), Some(30)),
        );
        assert_eq!(
            keys(&l),
            [
                "direction",
                "taker_state",
                "maker_state",
                "btc_lock",
                "divi_lock",
                "divi_claim_by_taker",
                "btc_claim_by_maker",
                "divi_spend_by_maker",
            ]
        );
        assert_eq!(l[0], "direction=taker_pays_btc");
        assert!(l.contains(&format!("btc_lock={}", id(10))));
        assert!(l.contains(&format!("divi_lock={}", id(20))));
    }

    #[test]
    fn txids_reverse_keys() {
        // Happy path: the taker claimed the BTC (30); the maker claimed the DIVI (40).
        let l = lines(
            &record("taker_pays_divi", "done", Some(30), None),
            &view("Done", "taker_pays_divi", Some(40), Some(30)),
        );
        assert_eq!(
            keys(&l),
            [
                "direction",
                "taker_state",
                "maker_state",
                "divi_lock",
                "btc_lock",
                "btc_claim_by_taker",
                "divi_claim_by_maker",
            ]
        );
        assert_eq!(l[0], "direction=taker_pays_divi");
        assert!(l.contains(&format!("divi_lock={}", id(10))));
        assert!(l.contains(&format!("btc_lock={}", id(20))));
        assert!(l.contains(&format!("btc_claim_by_taker={}", id(30))));
        assert!(l.contains(&format!("divi_claim_by_maker={}", id(40))));

        // Case C: nobody claimed; the maker refunded its BTC (50), the taker its DIVI (60).
        let l = lines(
            &record("taker_pays_divi", "done", None, Some(60)),
            &view("Done", "taker_pays_divi", Some(60), Some(50)),
        );
        assert_eq!(
            keys(&l),
            [
                "direction",
                "taker_state",
                "maker_state",
                "divi_lock",
                "btc_lock",
                "btc_spend_by_maker",
                "divi_refund_by_taker",
            ]
        );
        assert!(l.contains(&format!("btc_spend_by_maker={}", id(50))));
        assert!(l.contains(&format!("divi_refund_by_taker={}", id(60))));
    }
}
