// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Immutable offer selections: the exact terms a UI showed, pinned under a token.
//!
//! Every [`Engine::offers`](crate::Engine::offers) call is a new *listing*. Each offer in it
//! gets a selection token that is a keyed digest of its full terms (id, direction, counter
//! chain, price and range), so a token can never name different terms: a later listing, from
//! another extension view or a refresh, adds tokens and never rewrites one. A caller begins a
//! swap with the token *and* the terms it displayed, as decimal strings ([`SelectionSpec`]);
//! both must agree with what the engine recorded.
//!
//! Refused rather than guessed:
//! * an id the maker listed more than once (in the selection's listing or the latest one),
//!   since the maker's quote endpoint is keyed by id alone;
//! * a token this engine never issued (e.g. after a service-worker restart or a lock) or
//!   evicted, and one older than [`SELECTION_TTL_SECS`]: the user must look at the offers
//!   again.
//!
//! Selections are memory only. Swaps already begun live in the sealed store and are locked,
//! ticked and refunded by id whatever happens here.

use std::collections::{HashMap, HashSet};

use divi_swap::api::{Direction, Offer};
use divi_swap::{Chain, QuoteIntent, Result, SwapError};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::engine::exact_u64;

/// How long after issuance a selection may still begin a swap.
pub const SELECTION_TTL_SECS: u64 = 15 * 60;

/// Most selections remembered; the least recently listed go first.
pub const MAX_SELECTIONS: usize = 256;

const DOMAIN: &[u8] = b"irondivi/swap-wasm/offer-selection/v1";

struct Shown {
    offer: Offer,
    listed_at: u64,
}

/// The selections one engine has issued.
pub struct Selections {
    key: [u8; 32],
    listing: u64,
    by_token: HashMap<String, Shown>,
    /// Ids listed more than once in the latest listing.
    ambiguous: HashSet<String>,
}

fn invalid(m: String) -> SwapError {
    SwapError::InvalidParams(m)
}

impl Selections {
    /// Selections under `key`, which makes tokens specific to this engine instance.
    pub fn new(key: [u8; 32]) -> Self {
        Selections {
            key,
            listing: 0,
            by_token: HashMap::new(),
            ambiguous: HashSet::new(),
        }
    }

    /// Selections under a fresh random key.
    pub fn random() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key)
            .map_err(|e| SwapError::Other(format!("no entropy for offer selections: {e}")))?;
        Ok(Self::new(key))
    }

    /// The token for exactly `offer`'s terms.
    fn token(&self, offer: &Offer) -> String {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(self.key);
        h.update(self.listing.to_be_bytes());
        h.update((offer.id.len() as u64).to_be_bytes());
        h.update(offer.id.as_bytes());
        h.update([match offer.direction {
            Direction::TakerPaysBtc => 0u8,
            Direction::TakerPaysDivi => 1u8,
        }]);
        let chain = offer.counter_chain.as_str();
        h.update((chain.len() as u64).to_be_bytes());
        h.update(chain.as_bytes());
        h.update(offer.divi_sats_per_btc.to_be_bytes());
        h.update(offer.min_btc_sats.to_be_bytes());
        h.update(offer.max_btc_sats.to_be_bytes());
        hex::encode(h.finalize())
    }

    /// Record a listing at `now`. `maker_ids` are the ids of every offer the maker returned
    /// (before filtering); `shown` the offers the UI will display. Returns, for each of
    /// `shown`, its token, or `None` when its id is ambiguous (or it could not be kept).
    pub fn record<'a>(
        &mut self,
        maker_ids: impl IntoIterator<Item = &'a str>,
        shown: &[Offer],
        now: u64,
    ) -> Result<Vec<Option<String>>> {
        self.listing = self.listing.checked_add(1).ok_or_else(|| {
            invalid("offer listing sequence exhausted; reopen the wallet session".into())
        })?;
        let mut seen = HashSet::new();
        let mut ambiguous = HashSet::new();
        for id in maker_ids {
            if !seen.insert(id) {
                ambiguous.insert(id.to_string());
            }
        }
        self.ambiguous = ambiguous;
        let mut tokens = Vec::with_capacity(shown.len());
        for o in shown {
            if self.ambiguous.contains(&o.id) {
                tokens.push(None);
                continue;
            }
            let t = self.token(o);
            self.by_token.insert(
                t.clone(),
                Shown {
                    offer: o.clone(),
                    listed_at: now,
                },
            );
            tokens.push(Some(t));
        }
        self.prune(now);
        Ok(tokens
            .into_iter()
            .map(|t| t.filter(|t| self.by_token.contains_key(t)))
            .collect())
    }

    fn prune(&mut self, now: u64) {
        self.by_token
            .retain(|_, s| now.saturating_sub(s.listed_at) <= SELECTION_TTL_SECS);
        if self.by_token.len() > MAX_SELECTIONS {
            let mut by_age: Vec<(u64, String)> = self
                .by_token
                .iter()
                .map(|(t, s)| (s.listed_at, t.clone()))
                .collect();
            by_age.sort();
            let excess = self.by_token.len() - MAX_SELECTIONS;
            for (_, t) in by_age.into_iter().take(excess) {
                self.by_token.remove(&t);
            }
        }
    }

    /// The offer `token` selected, if it is still current at `now` and unambiguous.
    pub fn get(&self, token: &str, now: u64) -> Result<Offer> {
        let shown = self.by_token.get(token).ok_or_else(|| {
            invalid(
                "offer selection missing: this wallet session did not list it (or no longer \
                 remembers it); list offers and select again"
                    .into(),
            )
        })?;
        if now.saturating_sub(shown.listed_at) > SELECTION_TTL_SECS {
            return Err(invalid(format!(
                "offer selection is stale (listed over {SELECTION_TTL_SECS} s ago); list \
                 offers and select again"
            )));
        }
        if self.ambiguous.contains(&shown.offer.id) {
            return Err(invalid(format!(
                "offer id {} is ambiguous: the maker lists it more than once",
                shown.offer.id
            )));
        }
        Ok(shown.offer.clone())
    }

    /// Age every selection by `secs` (tests only).
    #[cfg(test)]
    pub(crate) fn age(&mut self, secs: u64) {
        for s in self.by_token.values_mut() {
            s.listed_at = s.listed_at.saturating_sub(secs);
        }
    }
}

/// What a UI sends to begin a swap on a selected offer: the token, every term it displayed
/// and the amount, each u64 as a canonical decimal string. Unknown keys are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionSpec {
    pub selection: String,
    pub offer_id: String,
    pub direction: Direction,
    pub counter_chain: Chain,
    pub divi_sats_per_btc: String,
    pub min_btc_sats: String,
    pub max_btc_sats: String,
    pub btc_sats: String,
    #[serde(default)]
    pub min_remaining_secs: Option<serde_json::Value>,
    #[serde(default)]
    pub max_taker_timeout_secs: Option<u32>,
}

/// A u64 as a canonical decimal string: digits only, no sign, no leading zero.
pub fn decimal(name: &str, s: &str) -> Result<u64> {
    let bad = || invalid(format!("{name}: not a decimal amount: {s:?}"));
    let canonical = !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if !canonical {
        return Err(bad());
    }
    s.parse().map_err(|_| bad())
}

impl SelectionSpec {
    pub fn parse(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| invalid(format!("bad selection: {e}")))
    }

    /// The intent for `shown` (the offer [`Self::selection`] names), refused unless every
    /// displayed term matches it exactly.
    pub fn intent(&self, shown: &Offer) -> Result<QuoteIntent> {
        let mismatch = |what: &str| {
            Err(invalid(format!(
                "offer selection does not match the terms shown: {what} differs; list offers \
                 and select again"
            )))
        };
        if self.offer_id != shown.id {
            return mismatch("offer id");
        }
        if self.direction != shown.direction {
            return mismatch("direction");
        }
        if self.counter_chain != shown.counter_chain {
            return mismatch("counter chain");
        }
        if decimal("divi_sats_per_btc", &self.divi_sats_per_btc)? != shown.divi_sats_per_btc {
            return mismatch("price");
        }
        if decimal("min_btc_sats", &self.min_btc_sats)? != shown.min_btc_sats {
            return mismatch("minimum");
        }
        if decimal("max_btc_sats", &self.max_btc_sats)? != shown.max_btc_sats {
            return mismatch("maximum");
        }
        let btc_sats = decimal("btc_sats", &self.btc_sats)?;
        let mut intent = QuoteIntent::for_offer(shown, btc_sats)?
            .with_max_taker_timeout_secs(self.max_taker_timeout_secs);
        if let Some(v) = &self.min_remaining_secs {
            intent = intent.with_min_remaining_secs(exact_u64("min_remaining_secs", v)?);
        }
        Ok(intent)
    }
}
