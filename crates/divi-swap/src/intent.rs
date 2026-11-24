// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! What the taker agreed to, and the check that a maker's [`Quote`] honours it.
//!
//! The maker is the untrusted party, and so is anything it serves: an offer page or
//! `GET /offers` can change between the moment the user read it and the moment the taker
//! asks for a quote. A [`QuoteIntent`] therefore always pins the offer id, the amount, the
//! counter chain, the direction and an exact DIVI amount bound. It comes from one of two
//! places only:
//!
//! * [`QuoteIntent::for_offer`]: the offer terms the user was actually shown and selected
//!   (the extension caches the offers it displayed). The bound is exactly what the maker
//!   must quote for those terms ([`Offer::checked_divi_for`]).
//! * [`QuoteIntent::with_limit`]: explicit limits typed by the user, for a caller that has no
//!   trusted terms (the CLI, unattended runs).
//!
//! [`QuoteIntent::stricter_price`] can only tighten either. [`QuoteIntent::check_quote`] is
//! chain-agnostic (the XMR adaptor flow uses it too); [`QuoteIntent::check_htlc_terms`] and
//! [`check_funding_window`] are the hashlock timing checks, kept apart from the quote's
//! wall-clock expiry: quote expiry bounds when the taker may *commit* (`POST /swaps`), the
//! HTLC terms bound whether, once committed and funded, the swap can still complete. Pure
//! functions over the wire types; nothing here touches a chain or the network.

use crate::api::{Direction, Offer, Quote};
use crate::config::{
    check_terms_against_profile, ClaimDeadline, OfferedTerms, Profile, SwapConfig,
};
use crate::error::{Result, SwapError};
use crate::taker::LOCKTIME_TOLERANCE_SECS;
use crate::types::{Amount, Chain};

/// Seconds of quote validity the taker requires left when it commits (accepts) by default.
/// The maker's quotes live 60 s ([`crate::SwapConfig::profile`]).
pub const DEFAULT_MIN_REMAINING_SECS: u64 = 15;

/// The furthest ahead a quote may expire. A maker quotes for 60 s; an expiry beyond this is
/// a broken or hostile maker (or a badly skewed clock) and is refused.
pub const MAX_QUOTE_TTL_SECS: u64 = 3600;

/// Without an explicit [`QuoteIntent::max_taker_timeout_secs`], the longest taker timeout
/// accepted is this multiple of the taker profile's own taker timeout (testnet 12 h, mainnet
/// 48 h): how long the taker's coins may be stranded if the maker vanishes.
pub const DEFAULT_TAKER_TIMEOUT_CEILING_FACTOR: u32 = 2;

/// Longest offer or quote id accepted (ids end up in URL paths and on disk).
pub const MAX_ID_LEN: usize = 128;

/// What the user agreed to when taking an offer. Every field is required: there is no
/// "any chain", "any direction" or "any price".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteIntent {
    /// Offer id.
    pub offer_id: String,
    /// Counter-chain amount (BTC, LTC, …, or 1e-8 XMR) in its smallest unit.
    pub btc_sats: u64,
    /// The counter chain the quote must be on.
    pub counter_chain: Chain,
    /// The direction the quote must have.
    pub direction: Direction,
    /// Exact DIVI amount bound: the least DIVI received when the taker buys DIVI
    /// ([`Direction::TakerPaysBtc`]), the most DIVI paid when it sells
    /// ([`Direction::TakerPaysDivi`]).
    pub divi_bound: Amount,
    /// Seconds of quote validity required left at commitment.
    pub min_remaining_secs: u64,
    /// Longest taker-leg timeout accepted (`None`: [`DEFAULT_TAKER_TIMEOUT_CEILING_FACTOR`]
    /// times the taker profile's). Hashlock flows only.
    pub max_taker_timeout_secs: Option<u32>,
}

/// `floor(btc_sats × divi_sats_per_btc / 1e8)`: the maker's own rounding
/// ([`Offer::checked_divi_for`]), `None` past `u64`.
fn divi_at(btc_sats: u64, divi_sats_per_btc: u64) -> Option<Amount> {
    let divi = u128::from(btc_sats) * u128::from(divi_sats_per_btc) / u128::from(Amount::COIN);
    u64::try_from(divi).ok().map(Amount)
}

fn invalid(m: String) -> SwapError {
    SwapError::InvalidParams(m)
}

impl QuoteIntent {
    /// Bind to `offer` as the user was shown it: its id, chain, direction, and exactly the
    /// DIVI amount it promises for `btc_sats` (the maker's rounding, so an honest quote
    /// matches to the sat). `offer` must be the copy the user selected, never one re-fetched
    /// from the maker just before quoting.
    pub fn for_offer(offer: &Offer, btc_sats: u64) -> Result<Self> {
        check_id("offer id", &offer.id).map_err(invalid)?;
        let c = offer.counter_chain;
        if !c.is_counter() {
            return Err(invalid(format!("{c} cannot be the counter chain")));
        }
        if btc_sats == 0 || btc_sats < offer.min_btc_sats || btc_sats > offer.max_btc_sats {
            return Err(invalid(format!(
                "{btc_sats} counter sats is outside offer {} range {}..={}",
                offer.id, offer.min_btc_sats, offer.max_btc_sats
            )));
        }
        let divi = offer.checked_divi_for(btc_sats).ok_or_else(|| {
            invalid(format!(
                "{btc_sats} counter sats on offer {} is more DIVI than an amount can hold",
                offer.id
            ))
        })?;
        if divi.0 == 0 {
            return Err(invalid(format!(
                "{btc_sats} counter sats on offer {} is worth no DIVI",
                offer.id
            )));
        }
        Ok(QuoteIntent {
            offer_id: offer.id.clone(),
            btc_sats,
            counter_chain: c,
            direction: offer.direction,
            divi_bound: divi,
            min_remaining_secs: DEFAULT_MIN_REMAINING_SECS,
            max_taker_timeout_secs: None,
        })
    }

    /// Explicit limits, for a caller with no trusted offer terms: `btc_sats` on `offer_id`,
    /// on `counter_chain`, in `direction`, at a worst price of `limit_divi_sats_per_btc`
    /// (DIVI sats per counter coin, a floor when buying DIVI and a ceiling when selling),
    /// turned into an exact DIVI amount bound with the maker's rounding.
    pub fn with_limit(
        offer_id: &str,
        btc_sats: u64,
        counter_chain: Chain,
        direction: Direction,
        limit_divi_sats_per_btc: u64,
    ) -> Result<Self> {
        check_id("offer id", offer_id).map_err(invalid)?;
        if btc_sats == 0 {
            return Err(invalid("the counter-chain amount must be positive".into()));
        }
        if !counter_chain.is_counter() {
            return Err(invalid(format!(
                "{counter_chain} cannot be the counter chain"
            )));
        }
        let bound = divi_at(btc_sats, limit_divi_sats_per_btc).ok_or_else(|| {
            invalid(format!(
                "the price limit {limit_divi_sats_per_btc} for {btc_sats} counter sats is more \
                 DIVI than an amount can hold"
            ))
        })?;
        if bound.0 == 0 {
            return Err(invalid(format!(
                "the price limit {limit_divi_sats_per_btc} for {btc_sats} counter sats rounds \
                 to no DIVI"
            )));
        }
        Ok(QuoteIntent {
            offer_id: offer_id.to_string(),
            btc_sats,
            counter_chain,
            direction,
            divi_bound: bound,
            min_remaining_secs: DEFAULT_MIN_REMAINING_SECS,
            max_taker_timeout_secs: None,
        })
    }

    /// Tighten the bound to a worst price of `limit_divi_sats_per_btc`; never loosens it.
    pub fn stricter_price(mut self, limit_divi_sats_per_btc: u64) -> Result<Self> {
        let at = divi_at(self.btc_sats, limit_divi_sats_per_btc);
        self.divi_bound = match (self.direction, at) {
            (Direction::TakerPaysBtc, Some(b)) => self.divi_bound.max(b),
            (Direction::TakerPaysBtc, None) => {
                return Err(invalid(format!(
                    "the price limit {limit_divi_sats_per_btc} for {} counter sats is more \
                     DIVI than an amount can hold",
                    self.btc_sats
                )))
            }
            (Direction::TakerPaysDivi, Some(b)) => self.divi_bound.min(b),
            // A ceiling above every amount tightens nothing.
            (Direction::TakerPaysDivi, None) => self.divi_bound,
        };
        if self.divi_bound.0 == 0 {
            return Err(invalid(format!(
                "the price limit {limit_divi_sats_per_btc} rounds to no DIVI"
            )));
        }
        Ok(self)
    }

    /// Require `secs` of quote validity left at commitment.
    pub fn with_min_remaining_secs(mut self, secs: u64) -> Self {
        self.min_remaining_secs = secs;
        self
    }

    /// Accept taker timeouts up to `secs` (`None`: the profile default).
    pub fn with_max_taker_timeout_secs(mut self, secs: Option<u32>) -> Self {
        self.max_taker_timeout_secs = secs;
        self
    }

    /// Refuse an intent that is malformed on its own, before any request is made.
    pub fn validate(&self) -> Result<()> {
        check_id("offer id", &self.offer_id).map_err(invalid)?;
        if self.btc_sats == 0 {
            return Err(invalid("the counter-chain amount must be positive".into()));
        }
        if !self.counter_chain.is_counter() {
            return Err(invalid(format!(
                "{} cannot be the counter chain",
                self.counter_chain
            )));
        }
        if self.divi_bound.0 == 0 {
            return Err(invalid("the DIVI amount bound must be positive".into()));
        }
        if self.min_remaining_secs >= MAX_QUOTE_TTL_SECS {
            return Err(invalid(format!(
                "min_remaining_secs {} must be below {MAX_QUOTE_TTL_SECS}",
                self.min_remaining_secs
            )));
        }
        if self.max_taker_timeout_secs == Some(0) {
            return Err(invalid("max_taker_timeout_secs must be positive".into()));
        }
        if self.counter_chain == Chain::Xmr && self.max_taker_timeout_secs.is_some() {
            return Err(invalid(
                "max_taker_timeout_secs is not supported for XMR adaptor swaps".into(),
            ));
        }
        Ok(())
    }

    /// Refuse `quote` unless it is exactly what this intent agreed to: offer, counter chain,
    /// direction, amount, a DIVI amount within the bound, structurally sound terms, and
    /// [`min_remaining_secs`](Self::min_remaining_secs) of validity left at `now` (unix
    /// seconds). Chain-agnostic: no HTLC timing here ([`Self::check_htlc_terms`]).
    pub fn check_quote(&self, quote: &Quote, now: u64) -> Result<()> {
        self.validate()?;
        let bad = |m: String| Err(SwapError::Rejected(format!("maker's quote: {m}")));
        check_id("quote id", &quote.id).or_else(bad)?;
        if quote.offer_id != self.offer_id {
            return bad(format!(
                "for offer {:?}, not {:?}",
                quote.offer_id, self.offer_id
            ));
        }
        let c = quote.counter_chain;
        if c != self.counter_chain {
            return bad(format!("on {c}, not {}", self.counter_chain));
        }
        if quote.direction != self.direction {
            return bad(format!(
                "direction {:?}, not {:?}",
                quote.direction, self.direction
            ));
        }
        if quote.btc_amount != Amount(self.btc_sats) {
            return bad(format!(
                "{} counter sats, not the {} asked for",
                quote.btc_amount.0, self.btc_sats
            ));
        }
        let (divi, bound) = (quote.divi_amount.0, self.divi_bound.0);
        if divi == 0 {
            return bad("worth no DIVI".into());
        }
        match self.direction {
            Direction::TakerPaysBtc if divi < bound => {
                return bad(format!(
                    "{divi} DIVI sats received is below the {bound} agreed for {} counter sats",
                    self.btc_sats
                ));
            }
            Direction::TakerPaysDivi if divi > bound => {
                return bad(format!(
                    "{divi} DIVI sats paid is above the {bound} agreed for {} counter sats",
                    self.btc_sats
                ));
            }
            _ => {}
        }
        check_terms(quote).or_else(bad)?;
        self.check_deadline(quote, now)
    }

    /// Refuse `quote` unless it expires no sooner than [`min_remaining_secs`](Self::min_remaining_secs)
    /// after `now`, and no later than [`MAX_QUOTE_TTL_SECS`]. Callers re-run this right
    /// before committing (`POST /swaps`), after any slow local work. Wall clock only: the
    /// HTLC timing is [`Self::check_htlc_terms`] and [`check_funding_window`].
    pub fn check_deadline(&self, quote: &Quote, now: u64) -> Result<()> {
        if quote.expires_at <= now {
            return Err(SwapError::Rejected("the quote has already expired".into()));
        }
        let left = quote.expires_at - now;
        if left < self.min_remaining_secs {
            return Err(SwapError::Rejected(format!(
                "the quote expires in {left}s, less than the {}s margin required to commit",
                self.min_remaining_secs
            )));
        }
        if left > MAX_QUOTE_TTL_SECS {
            return Err(SwapError::Rejected(format!(
                "the quote expires in {left}s, beyond the {MAX_QUOTE_TTL_SECS}s any maker quotes \
                 for (check the clocks)"
            )));
        }
        Ok(())
    }

    /// Hashlock timing of `quote` under the taker's `profile`, before `prepare`.
    /// `deadline(chain)` is the taker's [`ClaimDeadline`] for a maker leg on that chain
    /// (`Taker::claim_deadline`; its `block_secs` is also used for the taker-leg chain).
    ///
    /// * the profile floors ([`check_terms_against_profile`]);
    /// * a taker timeout no longer than [`max_taker_timeout_secs`](Self::max_taker_timeout_secs)
    ///   (default: [`DEFAULT_TAKER_TIMEOUT_CEILING_FACTOR`] × the profile's);
    /// * taker leg: the maker refuses to lock once less than `maker_timeout + claim_margin`
    ///   is left of the taker-leg locktime against the taker chain's MTP
    ///   (`Maker::on_taker_lock_confirmed`, `taker_window_too_short`). The locktime is set at
    ///   accept from that same MTP, and both ends are MTP readings on one chain, so the MTP lag
    ///   cancels; what is spent is the confirmations' expected time plus the locktime
    ///   tolerance `Taker::accepted` allows. Needs `taker_timeout ≥ maker_timeout +
    ///   claim_margin + confirmations(taker chain) × block_secs + LOCKTIME_TOLERANCE_SECS`.
    ///   The maker's own claim margin is unknown; the profile's stands in for it.
    /// * maker leg: the taker claims only after the maker lock's confirmations and only while
    ///   the chain's claim deadline is left: `maker_timeout ≥ confirmations(maker chain) ×
    ///   block_secs + deadline(maker chain).margin_secs()`.
    ///
    /// Expected block times, not guarantees: this refuses terms that cannot work even on
    /// schedule; [`check_funding_window`] re-checks the real locktime before funding, and the
    /// taker-leg refund covers a maker that still refuses.
    pub fn check_htlc_terms(
        &self,
        quote: &Quote,
        profile: Profile,
        deadline: &dyn Fn(Chain) -> ClaimDeadline,
    ) -> Result<()> {
        let (tc, mc) = (quote.taker_chain(), quote.maker_chain());
        check_terms_against_profile(profile, (tc, mc), &OfferedTerms::from(quote))
            .map_err(SwapError::Rejected)?;
        let bad = |m: String| Err(SwapError::Rejected(format!("maker's quote: {m}")));
        let floor = SwapConfig::profile(profile);
        let ceiling = self.max_taker_timeout_secs.unwrap_or_else(|| {
            floor
                .taker_timeout_secs
                .saturating_mul(DEFAULT_TAKER_TIMEOUT_CEILING_FACTOR)
        });
        if quote.taker_timeout_secs > ceiling {
            return bad(format!(
                "taker_timeout_secs {} exceeds this taker's {ceiling}s ceiling (--profile \
                 {profile}): the taker's coins would be locked that long if the maker vanished",
                quote.taker_timeout_secs
            ));
        }
        let confs_wait = |c: Chain| {
            u64::from(quote.confirmations_on(c)) * u64::from(deadline(c).block_secs.max(1))
        };
        let taker_wait = confs_wait(tc);
        let need = u64::from(quote.maker_timeout_secs)
            + u64::from(floor.claim_margin_secs)
            + taker_wait
            + u64::from(LOCKTIME_TOLERANCE_SECS);
        if u64::from(quote.taker_timeout_secs) < need {
            return bad(format!(
                "taker_timeout_secs {} is short of maker_timeout_secs {} + the {}s claim margin \
                 + {} {tc} confirmations (~{taker_wait}s) + the {LOCKTIME_TOLERANCE_SECS}s \
                 locktime tolerance = {need}s: the maker would refuse to lock after the taker \
                 funds",
                quote.taker_timeout_secs,
                quote.maker_timeout_secs,
                floor.claim_margin_secs,
                quote.confirmations_on(tc)
            ));
        }
        let d = deadline(mc);
        let maker_wait = confs_wait(mc);
        let need = maker_wait + u64::from(d.margin_secs());
        if u64::from(quote.maker_timeout_secs) < need {
            return bad(format!(
                "maker_timeout_secs {} is short of {} {mc} confirmations (~{maker_wait}s) + the \
                 {}s {mc} claim deadline = {need}s: the taker could never claim the maker leg",
                quote.maker_timeout_secs,
                quote.confirmations_on(mc),
                d.margin_secs()
            ));
        }
        Ok(())
    }
}

/// Right before the taker funds its leg (hashlock): refuse unless the taker-leg `locktime`
/// still leaves, against the taker chain's `mtp`, the time the maker requires to lock
/// (`maker_timeout + claim_margin`, `taker_window_too_short`) plus the expected time of the
/// lock's own confirmations (`confirmations × taker_block_secs`). A taker that sat on an
/// accepted swap must not fund into a window the maker will refuse.
pub fn check_funding_window(
    quote: &Quote,
    profile: Profile,
    taker_block_secs: u32,
    locktime: u32,
    mtp: u32,
) -> std::result::Result<(), String> {
    let tc = quote.taker_chain();
    let margin = SwapConfig::profile(profile).claim_margin_secs;
    let wait = u64::from(quote.confirmations_on(tc)) * u64::from(taker_block_secs.max(1));
    let need = u64::from(quote.maker_timeout_secs) + u64::from(margin) + wait;
    let left = i64::from(locktime) - i64::from(mtp);
    if left < 0 || (left as u64) < need {
        return Err(format!(
            "taker-leg locktime {locktime} is {left}s after the {tc} MTP {mtp}, short of the \
             {need}s the maker needs (maker_timeout_secs {} + the {margin}s claim margin + {} \
             confirmations, ~{wait}s); not funding",
            quote.maker_timeout_secs,
            quote.confirmations_on(tc)
        ));
    }
    Ok(())
}

/// Ids go into URL paths: non-empty, at most [`MAX_ID_LEN`], `[A-Za-z0-9_-]` only.
fn check_id(what: &str, id: &str) -> std::result::Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(format!("bad {what} {id:?}"))
    }
}

/// Shape every quote must have, hashlock or adaptor. Ceilings are profile-relative and
/// hashlock-only ([`QuoteIntent::check_htlc_terms`]).
fn check_terms(q: &Quote) -> std::result::Result<(), String> {
    if q.maker_timeout_secs == 0 {
        return Err("maker_timeout_secs is 0".into());
    }
    if q.taker_timeout_secs <= q.maker_timeout_secs {
        return Err(format!(
            "taker_timeout_secs {} does not exceed maker_timeout_secs {}",
            q.taker_timeout_secs, q.maker_timeout_secs
        ));
    }
    for (term, n) in [
        ("btc_confirmations", q.btc_confirmations),
        ("divi_confirmations", q.divi_confirmations),
    ] {
        if n == 0 {
            return Err(format!("{term} 0"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An edit that makes a case out of a valid offer or quote
    type OfferEdit = fn(&mut Offer);
    type QuoteEdit = fn(&mut Quote);

    const NOW: u64 = 1_800_000_000;
    /// 1e5 DIVI per BTC.
    const PRICE: u64 = 10_000_000_000_000;

    fn offer() -> Offer {
        Offer {
            id: "divi-btc-testnet".into(),
            direction: Direction::TakerPaysBtc,
            counter_chain: Chain::Btc,
            divi_sats_per_btc: PRICE,
            min_btc_sats: 1_000,
            max_btc_sats: 1_000_000,
        }
    }

    fn quote() -> Quote {
        Quote {
            id: "q-1".into(),
            offer_id: "divi-btc-testnet".into(),
            direction: Direction::TakerPaysBtc,
            counter_chain: Chain::Btc,
            btc_amount: Amount(10_000),
            // 10_000 sats at PRICE.
            divi_amount: Amount(1_000_000_000),
            expires_at: NOW + 60,
            maker_btc_pubkey: [2; 33],
            maker_divi_pubkey: [3; 33],
            taker_timeout_secs: 6 * 3600,
            maker_timeout_secs: 3 * 3600,
            btc_confirmations: 1,
            divi_confirmations: 3,
        }
    }

    fn intent() -> QuoteIntent {
        QuoteIntent::for_offer(&offer(), 10_000).unwrap()
    }

    fn rejected(i: &QuoteIntent, q: &Quote) -> String {
        i.check_quote(q, NOW).unwrap_err().to_string()
    }

    fn htlc(q: &Quote, p: Profile) -> Result<()> {
        intent().check_htlc_terms(q, p, &ClaimDeadline::builtin)
    }

    #[test]
    fn selected_offer_terms_pin_everything() {
        let i = intent();
        assert_eq!(i.counter_chain, Chain::Btc);
        assert_eq!(i.direction, Direction::TakerPaysBtc);
        assert_eq!(i.divi_bound, Amount(1_000_000_000));
        assert!(i.check_quote(&quote(), NOW).is_ok());
    }

    #[test]
    fn the_bound_uses_the_makers_rounding() {
        // 333 sats at 1e5 DIVI/BTC is 33_300_000 DIVI sats exactly; at a price that does not
        // divide evenly the honest quote is rounded down and must still pass.
        let mut o = offer();
        o.divi_sats_per_btc = 10_000_000_000_003;
        o.min_btc_sats = 1;
        let i = QuoteIntent::for_offer(&o, 333).unwrap();
        let mut q = quote();
        q.btc_amount = Amount(333);
        q.divi_amount = o.checked_divi_for(333).unwrap();
        assert!(
            i.check_quote(&q, NOW).is_ok(),
            "an honest floor-rounded quote"
        );
        q.divi_amount = Amount(q.divi_amount.0 - 1);
        assert!(rejected(&i, &q).contains("below the"));

        let j = QuoteIntent::with_limit(
            "o",
            333,
            Chain::Btc,
            Direction::TakerPaysBtc,
            o.divi_sats_per_btc,
        )
        .unwrap();
        assert_eq!(
            j.divi_bound, i.divi_bound,
            "an explicit limit at the offer price"
        );
    }

    #[test]
    fn selected_terms_are_validated() {
        let cases: [(OfferEdit, u64, &str); 6] = [
            (|_| {}, 999, "outside offer"),
            (|_| {}, 1_000_001, "outside offer"),
            (
                |o| o.counter_chain = Chain::Divi,
                10_000,
                "cannot be the counter chain",
            ),
            (|o| o.id = "../swaps".into(), 10_000, "bad offer id"),
            (|o| o.divi_sats_per_btc = 1, 10_000, "worth no DIVI"),
            (
                |o| {
                    o.divi_sats_per_btc = u64::MAX;
                    o.max_btc_sats = u64::MAX;
                },
                u64::MAX,
                "more DIVI",
            ),
        ];
        for (edit, sats, want) in cases {
            let mut o = offer();
            edit(&mut o);
            let e = QuoteIntent::for_offer(&o, sats).unwrap_err().to_string();
            assert!(e.contains(want), "{want}: {e}");
        }
    }

    #[test]
    fn explicit_limits_are_validated() {
        let w = |id: &str, sats, chain, price| {
            QuoteIntent::with_limit(id, sats, chain, Direction::TakerPaysBtc, price)
                .unwrap_err()
                .to_string()
        };
        assert!(w("", 1, Chain::Btc, PRICE).contains("bad offer id"));
        assert!(w(&"a".repeat(MAX_ID_LEN + 1), 1, Chain::Btc, PRICE).contains("bad offer id"));
        assert!(w("o", 0, Chain::Btc, PRICE).contains("must be positive"));
        assert!(w("o", 1, Chain::Divi, PRICE).contains("cannot be the counter chain"));
        assert!(w("o", 1, Chain::Btc, 0).contains("rounds to no DIVI"));
        assert!(w("o", 1, Chain::Btc, 99_999_999).contains("rounds to no DIVI"));
        assert!(w("o", u64::MAX, Chain::Btc, u64::MAX).contains("more DIVI"));
        let i = intent().with_min_remaining_secs(MAX_QUOTE_TTL_SECS);
        assert!(i
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must be below"));
        let i = intent().with_max_taker_timeout_secs(Some(0));
        assert!(i.validate().is_err());
        let xmr = QuoteIntent {
            counter_chain: Chain::Xmr,
            ..intent()
        };
        assert!(xmr.validate().is_ok());
        assert!(xmr
            .with_max_taker_timeout_secs(Some(30_000))
            .validate()
            .is_err());
    }

    #[test]
    fn quote_must_match_offer_chain_direction_and_amount() {
        let i = intent();
        let mut q = quote();
        q.offer_id = "divi-ltc-testnet".into();
        assert!(rejected(&i, &q).contains("for offer"));

        let mut q = quote();
        q.id = "q/../1".into();
        assert!(rejected(&i, &q).contains("bad quote id"));

        let mut q = quote();
        q.counter_chain = Chain::Ltc;
        assert!(rejected(&i, &q).contains("on ltc, not btc"));

        let mut q = quote();
        q.direction = Direction::TakerPaysDivi;
        assert!(rejected(&i, &q).contains("direction"));

        let mut q = quote();
        q.btc_amount = Amount(10_001);
        assert!(rejected(&i, &q).contains("not the 10000 asked for"));

        let mut q = quote();
        q.divi_amount = Amount(0);
        assert!(rejected(&i, &q).contains("worth no DIVI"));
    }

    #[test]
    fn the_bound_is_a_floor_when_buying_and_a_ceiling_when_selling() {
        let buy = intent();
        let mut q = quote();
        q.divi_amount = Amount(999_999_999);
        assert!(rejected(&buy, &q).contains("below the 1000000000 agreed"));
        q.divi_amount = Amount(1_000_000_001);
        assert!(
            buy.check_quote(&q, NOW).is_ok(),
            "more DIVI received is fine"
        );

        let mut o = offer();
        o.direction = Direction::TakerPaysDivi;
        let sell = QuoteIntent::for_offer(&o, 10_000).unwrap();
        let mut q = quote();
        q.direction = Direction::TakerPaysDivi;
        q.divi_amount = Amount(1_000_000_001);
        assert!(rejected(&sell, &q).contains("above the 1000000000 agreed"));
        q.divi_amount = Amount(999_999_999);
        assert!(sell.check_quote(&q, NOW).is_ok(), "less DIVI paid is fine");
    }

    #[test]
    fn a_stricter_price_only_tightens() {
        let i = intent();
        assert_eq!(
            i.clone().stricter_price(PRICE / 2).unwrap().divi_bound,
            i.divi_bound,
            "a lower floor when buying changes nothing"
        );
        assert_eq!(
            i.clone().stricter_price(PRICE * 2).unwrap().divi_bound,
            Amount(2_000_000_000)
        );
        assert!(i.clone().stricter_price(u64::MAX).is_ok());

        let mut o = offer();
        o.direction = Direction::TakerPaysDivi;
        let s = QuoteIntent::for_offer(&o, 10_000).unwrap();
        assert_eq!(
            s.clone().stricter_price(PRICE * 2).unwrap().divi_bound,
            s.divi_bound,
            "a higher ceiling when selling changes nothing"
        );
        assert_eq!(
            s.clone().stricter_price(PRICE / 2).unwrap().divi_bound,
            Amount(500_000_000)
        );
        assert!(s
            .stricter_price(1)
            .unwrap_err()
            .to_string()
            .contains("no DIVI"));
    }

    #[test]
    fn deadline_needs_the_margin_left_and_a_plausible_expiry() {
        let i = intent();
        let mut q = quote();
        q.expires_at = NOW;
        assert!(rejected(&i, &q).contains("already expired"));
        q.expires_at = NOW + DEFAULT_MIN_REMAINING_SECS - 1;
        assert!(rejected(&i, &q).contains("margin required to commit"));
        q.expires_at = NOW + DEFAULT_MIN_REMAINING_SECS;
        assert!(i.check_quote(&q, NOW).is_ok());
        q.expires_at = NOW + MAX_QUOTE_TTL_SECS;
        assert!(i.check_quote(&q, NOW).is_ok());
        q.expires_at = NOW + MAX_QUOTE_TTL_SECS + 1;
        assert!(rejected(&i, &q).contains("check the clocks"));
        q.expires_at = u64::MAX;
        assert!(rejected(&i, &q).contains("check the clocks"));

        // The re-check at commitment sees time passing.
        let q = quote();
        assert!(i.check_deadline(&q, NOW).is_ok());
        assert!(i.check_deadline(&q, NOW + 50).is_err());
    }

    #[test]
    fn terms_have_a_sound_shape() {
        let cases: [(QuoteEdit, &str); 4] = [
            (|q| q.maker_timeout_secs = 0, "maker_timeout_secs is 0"),
            (
                |q| q.taker_timeout_secs = q.maker_timeout_secs,
                "does not exceed",
            ),
            (|q| q.btc_confirmations = 0, "btc_confirmations 0"),
            (|q| q.divi_confirmations = 0, "divi_confirmations 0"),
        ];
        for (edit, want) in cases {
            let mut q = quote();
            edit(&mut q);
            let e = rejected(&intent(), &q);
            assert!(e.contains(want), "{e}");
        }
    }

    #[test]
    fn each_profiles_own_honest_quote_passes_the_htlc_terms() {
        for p in [Profile::Testnet, Profile::Mainnet] {
            let cfg = SwapConfig::profile(p);
            for dir in [Direction::TakerPaysBtc, Direction::TakerPaysDivi] {
                for c in [Chain::Btc, Chain::Ltc, Chain::Zec] {
                    let mut q = quote();
                    q.direction = dir;
                    q.counter_chain = c;
                    q.taker_timeout_secs = cfg.taker_timeout_secs;
                    q.maker_timeout_secs = cfg.maker_timeout_secs;
                    q.btc_confirmations = cfg.confirmations(c);
                    q.divi_confirmations = cfg.confirmations(Chain::Divi);
                    htlc(&q, p).unwrap_or_else(|e| panic!("{p} {dir:?} {c}: {e}"));
                }
            }
        }
    }

    #[test]
    fn htlc_terms_keep_the_profile_floor() {
        // Testnet terms under a mainnet taker: the floor is not weakened.
        let e = htlc(&quote(), Profile::Mainnet).unwrap_err().to_string();
        assert!(e.contains("floor"), "{e}");
    }

    #[test]
    fn the_taker_timeout_ceiling_is_the_profiles_unless_set() {
        let mut q = quote();
        q.taker_timeout_secs = 12 * 3600;
        assert!(htlc(&q, Profile::Testnet).is_ok(), "2 × the testnet 6 h");
        q.taker_timeout_secs = 12 * 3600 + 1;
        let e = htlc(&q, Profile::Testnet).unwrap_err().to_string();
        assert!(e.contains("43200s ceiling"), "{e}");
        let wider = intent().with_max_taker_timeout_secs(Some(24 * 3600));
        assert!(wider
            .check_htlc_terms(&q, Profile::Testnet, &ClaimDeadline::builtin)
            .is_ok());
        let narrower = intent().with_max_taker_timeout_secs(Some(6 * 3600 - 1));
        assert!(narrower
            .check_htlc_terms(&quote(), Profile::Testnet, &ClaimDeadline::builtin)
            .is_err());
    }

    #[test]
    fn confirmations_must_fit_inside_the_timeouts() {
        // Testnet BTC taker leg: 21600 ≥ 10800 + 1800 + n × 600 + 1800 holds up to n = 12.
        let mut q = quote();
        q.btc_confirmations = 12;
        assert!(htlc(&q, Profile::Testnet).is_ok());
        q.btc_confirmations = 13;
        let e = htlc(&q, Profile::Testnet).unwrap_err().to_string();
        assert!(e.contains("maker would refuse to lock"), "{e}");

        // DIVI maker leg: 10800 ≥ n × 60 + 1800 holds up to n = 150.
        let mut q = quote();
        q.divi_confirmations = 150;
        assert!(htlc(&q, Profile::Testnet).is_ok());
        q.divi_confirmations = 151;
        let e = htlc(&q, Profile::Testnet).unwrap_err().to_string();
        assert!(e.contains("never claim the maker leg"), "{e}");
    }

    #[test]
    fn the_funding_window_is_mtp_based_and_counts_the_confirmations() {
        let q = quote(); // testnet: maker 10800, claim margin 1800, 1 BTC conf at 600 s
        let need = 10_800 + 1_800 + 600;
        let mtp = 1_700_000_000;
        assert!(check_funding_window(&q, Profile::Testnet, 600, mtp + need, mtp).is_ok());
        let e = check_funding_window(&q, Profile::Testnet, 600, mtp + need - 1, mtp).unwrap_err();
        assert!(e.contains("not funding"), "{e}");
        assert!(check_funding_window(&q, Profile::Testnet, 600, mtp - 1, mtp).is_err());
        // Mainnet's larger claim margin makes the same window too short.
        assert!(check_funding_window(&q, Profile::Mainnet, 600, mtp + need, mtp).is_err());
    }
}
