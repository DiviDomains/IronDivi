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
//! Protocol (maker sells DIVI for BTC; the taker holds BTC and generates the preimage):
//! 1. `GET /offers` → [`Offer`]s. `GET /offers/:id/quote?btc_sats=N` → [`Quote`] (60 s).
//! 2. `POST /swaps` with [`AcceptRequest`] → [`SwapView`] in `accepted`, carrying the BTC
//!    HTLC the taker must fund (claim = maker BTC key, refund = taker BTC key,
//!    locktime = BTC MTP + taker timeout).
//! 3. Taker funds it and `POST /swaps/:id/lock` with [`LockNotice`]. Maker verifies with
//!    `htlc_output`, waits for confirmations, and only then selects coins and funds the DIVI
//!    HTLC (claim = taker DIVI key, refund = maker DIVI key, locktime = DIVI MTP + maker
//!    timeout). `GET /swaps/:id` shows it.
//! 4. Taker verifies the DIVI lock, waits for confirmations, claims DIVI (revealing the
//!    preimage). Maker's `find_spend` sees it and claims the BTC.

use serde::{Deserialize, Serialize};

use crate::htlc::HtlcParams;
use crate::state::SwapState;
use crate::types::{Amount, Outpoint, Txid};

/// A standing offer to sell DIVI for BTC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// Offer id.
    pub id: String,
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
    /// BTC the taker locks.
    pub btc_amount: Amount,
    /// DIVI the maker locks.
    pub divi_amount: Amount,
    /// Unix seconds (wall clock).
    pub expires_at: u64,
    /// Maker's BTC pubkey — `claim_pubkey` of the BTC HTLC.
    #[serde(with = "hex33")]
    pub maker_btc_pubkey: [u8; 33],
    /// Maker's DIVI pubkey — `refund_pubkey` of the DIVI HTLC.
    #[serde(with = "hex33")]
    pub maker_divi_pubkey: [u8; 33],
    /// Taker's BTC HTLC lifetime (seconds after BTC MTP).
    pub taker_timeout_secs: u32,
    /// Maker's DIVI HTLC lifetime (seconds after DIVI MTP).
    pub maker_timeout_secs: u32,
    /// Confirmations the maker requires on the BTC lock.
    pub btc_confirmations: u32,
    /// Confirmations the taker should require on the DIVI lock.
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
    /// Taker's BTC pubkey — `refund_pubkey` of the BTC HTLC.
    #[serde(with = "hex33")]
    pub taker_btc_pubkey: [u8; 33],
    /// Taker's DIVI pubkey — `claim_pubkey` of the DIVI HTLC.
    #[serde(with = "hex33")]
    pub taker_divi_pubkey: [u8; 33],
}

/// `POST /swaps/:id/lock` body: where the taker funded the BTC HTLC.
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
    /// The quote this swap executes.
    pub quote: Quote,
    /// Taker's BTC HTLC (known from `accepted`).
    pub btc: LegView,
    /// Maker's DIVI HTLC (known from `maker_locked`).
    pub divi: Option<LegView>,
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
            divi_sats_per_btc: 3_000_000 * 100_000_000,
            min_btc_sats: 1,
            max_btc_sats: 1_000_000,
        };
        assert_eq!(o.divi_for(100_000).0, 3_000 * 100_000_000);
    }
}
