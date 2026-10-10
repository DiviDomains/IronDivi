// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Wire types between taker and maker (the `divi-swapd` HTTP API) and the persisted swap
//! record. **Frozen contract** — the engine and daemon lanes both build against these.
//!
//! Protocol. The offer's [`Direction`] says which coin the taker pays; the *taker leg* is on
//! that chain and the *maker leg* on the other. The taker always generates the preimage,
//! locks first, and gets the longer timeout. For [`Direction::TakerPaysBtc`] (maker sells
//! DIVI) the taker leg is BTC; for [`Direction::TakerPaysDivi`] (maker buys DIVI) it is DIVI.
//! 1. `GET /offers` → [`Offer`]s. `GET /offers/:id/quote?btc_sats=N` → [`Quote`] (60 s).
//!    Both directions are sized in BTC sats; the price is always DIVI per BTC.
//! 2. `POST /swaps` with [`AcceptRequest`] → [`SwapView`] in `accepted`, carrying the
//!    taker-leg HTLC the taker must fund (claim = maker key, refund = taker key, both on the
//!    taker-leg chain; locktime = that chain's MTP + taker timeout).
//! 3. Taker funds it and `POST /swaps/:id/lock` with [`LockNotice`]. Maker verifies with
//!    `htlc_output`, waits for confirmations, and only then selects coins and funds the
//!    maker-leg HTLC (claim = taker key, refund = maker key, on the maker-leg chain;
//!    locktime = that chain's MTP + maker timeout). `GET /swaps/:id` shows it.
//! 4. Taker verifies the maker leg, waits for confirmations, claims it (revealing the
//!    preimage). Maker's `find_spend` on the maker leg sees it and claims the taker leg.

use serde::{Deserialize, Serialize};

use crate::htlc::HtlcParams;
use crate::state::SwapState;
use crate::types::{Amount, Chain, Outpoint, Txid};

/// Which coin the taker pays (and so which chain each leg is on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Maker sells DIVI: the taker locks BTC, the maker locks DIVI. Records and offers
    /// written before directions existed are this.
    #[default]
    TakerPaysBtc,
    /// Maker buys DIVI: the taker locks DIVI, the maker locks BTC.
    TakerPaysDivi,
}

impl Direction {
    /// Chain of the taker leg (funded first, by the taker, with the longer timeout).
    pub fn taker_chain(self) -> Chain {
        match self {
            Direction::TakerPaysBtc => Chain::Btc,
            Direction::TakerPaysDivi => Chain::Divi,
        }
    }

    /// Chain of the maker leg (funded by the maker after the taker leg confirms).
    pub fn maker_chain(self) -> Chain {
        match self {
            Direction::TakerPaysBtc => Chain::Divi,
            Direction::TakerPaysDivi => Chain::Btc,
        }
    }
}

/// A standing offer to swap DIVI and BTC in one [`Direction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// Offer id.
    pub id: String,
    /// Which coin the taker pays.
    #[serde(default)]
    pub direction: Direction,
    /// Price: DIVI sats paid per 1 BTC (1e8 BTC sats).
    pub divi_sats_per_btc: u64,
    /// Smallest swap, BTC sats.
    pub min_btc_sats: u64,
    /// Largest swap, BTC sats.
    pub max_btc_sats: u64,
}

impl Offer {
    /// DIVI sats for `btc_sats`, rounded down.
    pub fn divi_for(&self, btc_sats: u64) -> Amount {
        Amount(((btc_sats as u128 * self.divi_sats_per_btc as u128) / 100_000_000) as u64)
    }
}

/// A firm price for one swap, valid until `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    /// Quote id.
    pub id: String,
    /// Offer it was made from.
    pub offer_id: String,
    /// Which coin the taker pays.
    #[serde(default)]
    pub direction: Direction,
    /// BTC locked (by the taker for `TakerPaysBtc`, by the maker for `TakerPaysDivi`).
    pub btc_amount: Amount,
    /// DIVI locked (by the maker for `TakerPaysBtc`, by the taker for `TakerPaysDivi`).
    pub divi_amount: Amount,
    /// Unix seconds (wall clock).
    pub expires_at: u64,
    /// Maker's BTC pubkey — claim key of a BTC taker leg, refund key of a BTC maker leg.
    #[serde(with = "hex33")]
    pub maker_btc_pubkey: [u8; 33],
    /// Maker's DIVI pubkey — refund key of a DIVI maker leg, claim key of a DIVI taker leg.
    #[serde(with = "hex33")]
    pub maker_divi_pubkey: [u8; 33],
    /// Taker-leg HTLC lifetime (seconds after the taker-leg chain's MTP).
    pub taker_timeout_secs: u32,
    /// Maker-leg HTLC lifetime (seconds after the maker-leg chain's MTP).
    pub maker_timeout_secs: u32,
    /// Confirmations required on any BTC lock (the maker's check of a BTC taker leg, the
    /// taker's check of a BTC maker leg).
    pub btc_confirmations: u32,
    /// Confirmations required on any DIVI lock.
    pub divi_confirmations: u32,
}

/// `POST /swaps` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptRequest {
    /// The quote being accepted.
    pub quote_id: String,
    /// SHA256 of the taker's preimage.
    #[serde(with = "hex32")]
    pub hash: [u8; 32],
    /// Taker's BTC pubkey — refund key of a BTC taker leg, claim key of a BTC maker leg.
    #[serde(with = "hex33")]
    pub taker_btc_pubkey: [u8; 33],
    /// Taker's DIVI pubkey — claim key of a DIVI maker leg, refund key of a DIVI taker leg.
    #[serde(with = "hex33")]
    pub taker_divi_pubkey: [u8; 33],
}

/// `POST /swaps/:id/lock` body: where the taker funded the taker-leg HTLC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockNotice {
    /// The BTC HTLC output.
    pub outpoint: Outpoint,
}

/// One side's HTLC as it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegView {
    /// Script parameters.
    pub htlc: HtlcParams,
    /// Value locked.
    pub amount: Amount,
    /// Funding output, once known.
    pub outpoint: Option<Outpoint>,
    /// Claim or refund txid, once broadcast.
    pub spend_txid: Option<Txid>,
}

/// `GET /swaps/:id` — what either party may see. Never contains a key; contains the
/// preimage only after the taker has revealed it on chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapView {
    /// Swap id.
    pub id: String,
    /// Maker-side state.
    pub state: SwapState,
    /// The quote this swap executes (`quote.direction` says which chain each leg is on).
    pub quote: Quote,
    /// The taker's HTLC (known from `accepted`). Was `btc` before directions existed.
    #[serde(alias = "btc")]
    pub taker_leg: LegView,
    /// The maker's HTLC (known from `maker_locked`). Was `divi` before directions existed.
    #[serde(alias = "divi")]
    pub maker_leg: Option<LegView>,
    /// Revealed preimage (hex), after `taker_claimed`.
    pub preimage: Option<String>,
    /// Last error the scheduler hit on this swap, for operators.
    pub last_error: Option<String>,
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        hex::decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex33 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        hex::decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divi_for_rounds_down() {
        let o = Offer {
            id: "o".into(),
            direction: Direction::TakerPaysBtc,
            divi_sats_per_btc: 3_000_000 * 100_000_000,
            min_btc_sats: 1,
            max_btc_sats: 1_000_000,
        };
        assert_eq!(o.divi_for(100_000).0, 3_000 * 100_000_000);
    }

    #[test]
    fn direction_defaults_for_pre_direction_json() {
        let o: Offer = serde_json::from_str(
            r#"{"id":"o","divi_sats_per_btc":1,"min_btc_sats":1,"max_btc_sats":2}"#,
        )
        .unwrap();
        assert_eq!(o.direction, Direction::TakerPaysBtc);
        assert_eq!(o.direction.taker_chain(), Chain::Btc);
        assert_eq!(Direction::TakerPaysDivi.taker_chain(), Chain::Divi);
        assert_eq!(Direction::TakerPaysDivi.maker_chain(), Chain::Btc);
        let j = serde_json::to_value(Direction::TakerPaysDivi).unwrap();
        assert_eq!(j, "taker_pays_divi");
    }
}
