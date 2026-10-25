// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The taker engine (used by the `divi-swap` CLI). **Lane engine** owns the bodies; the
//! public signatures are frozen (the CLI builds against them).
//!
//! Legs are role-based: the taker leg (we fund first, longer timeout) is on
//! `quote.taker_chain()`, the maker leg (we claim) on `quote.maker_chain()` — DIVI and the
//! quote's counter chain, in the order the direction says.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::api::{AcceptRequest, LockNotice, Quote, SwapView};
use crate::backend::{ChainBackend, FeeBump};
use crate::config::{
    check_maker_leg_locktime, check_maker_leg_locktime_exact, check_terms_against_profile,
    ClaimDeadline, FeeEscalation, OfferedTerms, Profile,
};
use crate::error::{Result, SwapError};
use crate::htlc::{new_preimage, HtlcParams};
use crate::store::{Store, TakerRecord};
use crate::types::{Amount, Chain, Outpoint, SignedTx, SpendInfo};

/// The least margin, on any chain, that the taker keeps before the maker's locktime when it
/// broadcasts its first claim: a claim that confirms after the maker refunds would lose the
/// maker leg while revealing the preimage. Each chain's own margin
/// ([`ClaimDeadline::builtin`]) is at least this, and higher where blocks are slow.
pub const TAKER_SAFETY_MARGIN_SECS: u32 = 1800;

/// How far the taker-leg locktime may drift from `taker_chain_mtp + taker_timeout` (clock skew
/// between `accept` and our own view of the chain).
const LOCKTIME_TOLERANCE_SECS: u32 = 1800;

/// Taker-side state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TakerState {
    /// Preimage generated and persisted; accept request built.
    Prepared,
    /// Maker accepted; taker-leg HTLC fixed.
    Accepted,
    /// Taker-leg HTLC funding tx persisted (broadcast follows).
    Locked,
    /// Maker's lock verified (amount, script) and confirmed. The first claim is sent from
    /// here only while the chain's [`crate::ClaimDeadline`] margin is left before the
    /// maker-leg locktime; below it the taker records `claim_declined`, never reveals the
    /// preimage and waits for its taker-leg refund (`Refunded`).
    MakerLockConfirmed,
    /// Maker-leg claim broadcast (preimage revealed). Resent every step until it confirms;
    /// where the backend can bump it ([`crate::FeeBump`]) its fee climbs towards the
    /// [`crate::FeeEscalation`] cap as the maker-leg locktime nears, by replacement (BTC,
    /// earlier versions kept in `claim_replaced`) or by CPFP children (LTC,
    /// `claim_children`). An evicted or refused claim is re-signed at a higher feerate.
    Claimed,
    /// Taker leg refunded after the taker timeout.
    Refunded,
    /// Finished.
    Done,
    /// Both legs went to the maker: our maker-leg claim revealed the preimage but never
    /// confirmed (e.g. evicted from the mempool), the maker refunded the maker leg and then
    /// claimed the taker leg with the preimage. Nothing is left to spend; logged at error
    /// level with both outpoints. The claim-deadline margin and fee escalation make this
    /// unreachable in the mock's fee markets on BTC and LTC (`tests/claim_race.rs`); DIVI
    /// and ZEC cannot bump and rely on the margin alone.
    Lost,
}

impl TakerState {
    /// Whether the swap can never move again and never needs another broadcast, so a
    /// reservation held for its taker-leg funding tx may be released by an operator.
    ///
    /// Only the state that no transition leaves qualifies; every variant is decided here:
    /// - `Prepared`: not terminal. `accepted` moves it to `Accepted`.
    /// - `Accepted`: not terminal. `lock` funds the taker leg (`Locked`).
    /// - `Locked`: not terminal. The funding tx may still be rebroadcast; it moves to
    ///   `MakerLockConfirmed` or `Refunded`.
    /// - `MakerLockConfirmed`: not terminal. Moves to `Claimed` or `Refunded`.
    /// - `Claimed`: not terminal. The maker-leg claim is still being broadcast until it
    ///   confirms (`Done`), unless the maker refunded its leg first (`Refunded`).
    /// - `Refunded`: not terminal. The refund is only built and broadcast from here, and
    ///   still owed until it confirms (`Done`); the taker leg stays funded and spendable
    ///   by the refund, unless the maker claimed it with a leaked preimage (`Lost`).
    /// - `Done`: terminal. Reached from `Claimed` or `Refunded` once the claim or refund
    ///   confirmed; `step` and `refund` return at once and nothing else leaves it.
    /// - `Lost`: terminal. Reached from `Refunded` once a claim of the taker leg that
    ///   carries our preimage is buried as deep as the quote's confirmations on that
    ///   chain: the refund can never confirm, so it is not re-signed or sent again;
    ///   `step` and `refund` return at once and nothing else leaves it.
    ///
    /// The `match` is exhaustive on purpose: a new variant must be decided here.
    pub fn is_terminal(self) -> bool {
        match self {
            TakerState::Done | TakerState::Lost => true,
            TakerState::Prepared
            | TakerState::Accepted
            | TakerState::Locked
            | TakerState::MakerLockConfirmed
            | TakerState::Claimed
            | TakerState::Refunded => false,
        }
    }
}

/// Taker engine. `divi` holds the taker's DIVI key, each counter backend the taker's key on
/// that chain.
pub struct Taker {
    divi: Arc<dyn ChainBackend>,
    /// Counter-chain backends, by `chain()`.
    counters: BTreeMap<Chain, Arc<dyn ChainBackend>>,
    store: Store,
    /// Profile whose floors every quote's terms must meet (`None`: terms are taken as offered).
    profile_floor: Option<Profile>,
    /// Per-chain claim deadlines replacing [`ClaimDeadline::builtin`].
    claim_deadlines: BTreeMap<Chain, ClaimDeadline>,
    /// Per-chain fee escalations replacing [`FeeEscalation::builtin`] (`None`: off).
    fee_escalations: BTreeMap<Chain, Option<FeeEscalation>>,
    halt_after: Mutex<Option<TakerState>>,
    gate: tokio::sync::Mutex<()>,
}

impl Taker {
    /// New taker engine with one counter-chain backend (`btc` — any chain but DIVI; the
    /// name predates counter chains).
    pub fn new(divi: Arc<dyn ChainBackend>, btc: Arc<dyn ChainBackend>, store: Store) -> Self {
        Self::with_counters(divi, vec![btc], store)
    }

    /// New taker engine trading DIVI against every chain in `counters`, keyed by
    /// [`ChainBackend::chain`] (a later backend for the same chain replaces an earlier one).
    pub fn with_counters(
        divi: Arc<dyn ChainBackend>,
        counters: Vec<Arc<dyn ChainBackend>>,
        store: Store,
    ) -> Self {
        Taker {
            divi,
            counters: counters.into_iter().map(|b| (b.chain(), b)).collect(),
            store,
            profile_floor: None,
            claim_deadlines: BTreeMap::new(),
            fee_escalations: BTreeMap::new(),
            halt_after: Mutex::new(None),
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Refuse, in [`Taker::prepare`] and so before anything is signed or funded, any quote
    /// whose confirmation depths or timeouts are weaker than `profile`'s own
    /// ([`check_terms_against_profile`]). Without it the taker takes the maker's terms as
    /// offered.
    pub fn with_profile_floor(mut self, profile: Profile) -> Self {
        self.profile_floor = Some(profile);
        self
    }

    /// Use `deadline` instead of [`ClaimDeadline::builtin`] for maker legs on `chain`.
    pub fn with_claim_deadline(mut self, chain: Chain, deadline: ClaimDeadline) -> Self {
        self.claim_deadlines.insert(chain, deadline);
        self
    }

    /// The claim deadline this taker applies to a maker leg on `chain`.
    pub fn claim_deadline(&self, chain: Chain) -> ClaimDeadline {
        self.claim_deadlines
            .get(&chain)
            .copied()
            .unwrap_or_else(|| ClaimDeadline::builtin(chain))
    }

    /// Use `escalation` instead of [`FeeEscalation::builtin`] for claims of maker legs on
    /// `chain`; `None` never bumps them.
    pub fn with_fee_escalation(mut self, chain: Chain, escalation: Option<FeeEscalation>) -> Self {
        self.fee_escalations.insert(chain, escalation);
        self
    }

    /// The fee escalation this taker applies to claims of maker legs on `chain`.
    pub fn fee_escalation(&self, chain: Chain) -> Option<FeeEscalation> {
        self.fee_escalations
            .get(&chain)
            .copied()
            .unwrap_or_else(|| FeeEscalation::builtin(chain))
    }

    /// The counter chains this taker holds a key on.
    pub fn counter_chains(&self) -> Vec<Chain> {
        self.counters.keys().copied().collect()
    }

    /// Test hook: behave as if the process died right after persisting the transition
    /// into `state` — [`Taker::step`] returns before that state's side effect runs.
    #[doc(hidden)]
    pub fn halt_after(&self, state: Option<TakerState>) {
        *self.halt_after.lock() = state;
    }

    /// Generate + persist a preimage for `quote`; returns a local swap id and the request
    /// to `POST /swaps`.
    pub async fn prepare(&self, quote: &Quote) -> Result<(String, AcceptRequest)> {
        if let Some(p) = self.profile_floor {
            check_terms_against_profile(
                p,
                (quote.taker_chain(), quote.maker_chain()),
                &OfferedTerms::from(quote),
            )
            .map_err(SwapError::InvalidParams)?;
        }
        let (preimage, hash) = new_preimage();
        let req = AcceptRequest {
            quote_id: quote.id.clone(),
            hash,
            taker_btc_pubkey: self.chain(quote.counter_chain)?.pubkey(),
            taker_divi_pubkey: self.divi.pubkey(),
            counter_chain: Some(quote.counter_chain),
        };
        let id = uuid::Uuid::new_v4().to_string();
        self.store.put_taker_swap(&TakerRecord {
            id: id.clone(),
            state: TakerState::Prepared,
            quote: quote.clone(),
            preimage,
            hash,
            maker_swap_id: None,
            taker_leg_htlc: None,
            taker_leg_funding: None,
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
            claim_underpriced: 0,
            last_error: None,
        })?;
        Ok((id, req))
    }

    /// Record the maker's reply to `POST /swaps`, checking its taker-leg HTLC is the one we
    /// expect (our refund key, our hash, a locktime matching the quote's taker timeout).
    pub async fn accepted(&self, local_id: &str, maker: &SwapView) -> Result<()> {
        let _g = self.gate.lock().await;
        let mut r = self.load(local_id)?;
        if r.state != TakerState::Prepared {
            return Err(SwapError::InvalidParams(format!(
                "swap is {:?}, not awaiting acceptance",
                r.state
            )));
        }
        let h = maker.taker_leg.htlc;
        h.validate()?;
        let bad = |what: &str| SwapError::InvalidParams(format!("maker's taker-leg HTLC: {what}"));
        let tc = r.quote.taker_chain();
        let tb = self.chain(tc)?;
        if h.hash != r.hash {
            return Err(bad("wrong hash"));
        }
        if h.refund_pubkey != tb.pubkey() {
            return Err(bad("refund key is not ours"));
        }
        if h.claim_pubkey != r.quote.maker_pubkey(tc) {
            return Err(bad("claim key is not the quote's maker key"));
        }
        if maker.quote.id != r.quote.id
            || maker.quote.btc_amount != r.quote.btc_amount
            || maker.quote.divi_amount != r.quote.divi_amount
            || maker.quote.direction != r.quote.direction
            || maker.quote.counter_chain != r.quote.counter_chain
        {
            return Err(bad("reply is for a different quote"));
        }
        let expect = tb.median_time_past().await? as u64 + r.quote.taker_timeout_secs as u64;
        if (h.locktime as u64).abs_diff(expect) > LOCKTIME_TOLERANCE_SECS as u64 {
            return Err(bad("locktime does not match the quote's taker timeout"));
        }
        r.taker_leg_htlc = Some(h);
        r.maker_swap_id = Some(maker.id.clone());
        self.enter(&mut r, TakerState::Accepted)?;
        Ok(())
    }

    /// Fund the taker-leg HTLC (write-ahead); returns the notice to `POST /swaps/:id/lock`.
    pub async fn lock(&self, local_id: &str) -> Result<LockNotice> {
        let _g = self.gate.lock().await;
        let mut r = self.load(local_id)?;
        match r.state {
            TakerState::Accepted => {
                let htlc = self.taker_leg_htlc(&r)?;
                let funding = self
                    .tk(&r)?
                    .build_funding(&htlc, r.quote.taker_leg_amount())
                    .await?;
                r.taker_leg_funding = Some(funding);
                // Persist the signed tx before it can reach the network.
                if matches!(self.enter(&mut r, TakerState::Locked)?, Flow::Halted) {
                    return Err(SwapError::Other("halted after Locked".into()));
                }
            }
            TakerState::Locked => {}
            s => {
                return Err(SwapError::InvalidParams(format!(
                    "swap is {s:?}, cannot lock"
                )))
            }
        }
        let funding = r
            .taker_leg_funding
            .clone()
            .ok_or_else(|| SwapError::Other("Locked without a funding tx".into()))?;
        self.tk(&r)?.broadcast(&funding.tx).await?;
        Ok(LockNotice {
            outpoint: funding.outpoint,
        })
    }

    /// Advance using the maker's latest view (`None` if the maker is unreachable): claim the
    /// maker leg once the maker's lock is verified and confirmed, refund the taker leg after
    /// timeout.
    pub async fn step(&self, local_id: &str, maker: Option<&SwapView>) -> Result<TakerState> {
        let _g = self.gate.lock().await;
        let mut r = self.load(local_id)?;
        if r.state.is_terminal() {
            return Ok(r.state);
        }
        let had_error = r.last_error.take().is_some();
        for _ in 0..16 {
            match self.advance(&mut r, maker).await {
                Ok(Flow::Moved) => {}
                Ok(Flow::Idle | Flow::Halted) => break,
                Err(e) => {
                    r.last_error = Some(e.to_string());
                    self.store.put_taker_swap(&r)?;
                    return Err(e);
                }
            }
        }
        if had_error && r.last_error.is_none() {
            self.store.put_taker_swap(&r)?;
        }
        Ok(r.state)
    }

    /// Refund the taker leg once its own timeout has passed — unlike [`Taker::step`], this
    /// never claims the maker leg, even if that would still be safe. For an operator who
    /// has decided to abandon the swap (or is testing the refund path) and explicitly asked
    /// to refund, not for `step`'s normal "claim if still safe, else refund" judgment call.
    pub async fn refund(&self, local_id: &str) -> Result<TakerState> {
        let _g = self.gate.lock().await;
        let mut r = self.load(local_id)?;
        if r.state.is_terminal() {
            return Ok(r.state);
        }
        let had_error = r.last_error.take().is_some();
        for _ in 0..16 {
            match self.advance_refund_only(&mut r).await {
                Ok(Flow::Moved) => {}
                Ok(Flow::Idle | Flow::Halted) => break,
                Err(e) => {
                    r.last_error = Some(e.to_string());
                    self.store.put_taker_swap(&r)?;
                    return Err(e);
                }
            }
        }
        if had_error && r.last_error.is_none() {
            self.store.put_taker_swap(&r)?;
        }
        Ok(r.state)
    }

    /// [`Taker::refund`]'s state machine: `Locked`/`MakerLockConfirmed` only ever move to
    /// `Refunded` (never `Claimed`), and only once the taker leg is actually refundable;
    /// `Refunded` drives the refund to `Done` (or `Lost`) the same way [`Taker::advance`] does;
    /// `Claimed` moves to `Refunded` only once the maker has refunded its leg (nothing is
    /// left to claim); every other state is left exactly as it is.
    async fn advance_refund_only(&self, r: &mut TakerRecord) -> Result<Flow> {
        match r.state {
            TakerState::Locked | TakerState::MakerLockConfirmed => {
                if self.taker_leg_refundable(r).await? {
                    self.enter(r, TakerState::Refunded)
                } else {
                    Ok(Flow::Idle)
                }
            }
            TakerState::Claimed if self.maker_leg_refunded(r).await? => {
                r.maker_leg_claim = None;
                self.enter(r, TakerState::Refunded)
            }
            TakerState::Refunded => self.on_refunded(r).await,
            TakerState::Prepared
            | TakerState::Accepted
            | TakerState::Claimed
            | TakerState::Done
            | TakerState::Lost => Ok(Flow::Idle),
        }
    }

    fn load(&self, id: &str) -> Result<TakerRecord> {
        self.store
            .get_taker_swap(id)?
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown swap {id:?}")))
    }

    /// Backend for `c`: DIVI, or one of the counter chains.
    fn chain(&self, c: Chain) -> Result<&Arc<dyn ChainBackend>> {
        if c == Chain::Divi {
            return Ok(&self.divi);
        }
        self.counters
            .get(&c)
            .ok_or_else(|| SwapError::InvalidParams(format!("no {c} backend")))
    }

    /// Backend of the taker leg (where we lock).
    fn tk(&self, r: &TakerRecord) -> Result<&Arc<dyn ChainBackend>> {
        self.chain(r.quote.taker_chain())
    }

    /// Backend of the maker leg (where we claim).
    fn mk(&self, r: &TakerRecord) -> Result<&Arc<dyn ChainBackend>> {
        self.chain(r.quote.maker_chain())
    }

    fn taker_leg_htlc(&self, r: &TakerRecord) -> Result<HtlcParams> {
        r.taker_leg_htlc
            .ok_or_else(|| SwapError::Other("taker-leg HTLC not fixed yet".into()))
    }

    /// Persist the transition, then honour the crash hook.
    fn enter(&self, r: &mut TakerRecord, next: TakerState) -> Result<Flow> {
        r.state = next;
        self.store.put_taker_swap(r)?;
        if *self.halt_after.lock() == Some(next) {
            return Ok(Flow::Halted);
        }
        Ok(Flow::Moved)
    }

    async fn advance(&self, r: &mut TakerRecord, maker: Option<&SwapView>) -> Result<Flow> {
        match r.state {
            TakerState::Prepared | TakerState::Accepted | TakerState::Done | TakerState::Lost => {
                Ok(Flow::Idle)
            }
            TakerState::Locked => self.on_locked(r, maker).await,
            TakerState::MakerLockConfirmed => self.on_maker_lock_confirmed(r).await,
            TakerState::Claimed => self.on_claimed(r).await,
            TakerState::Refunded => self.on_refunded(r).await,
        }
    }

    /// Whether a block holds a spend of the maker-leg lock that carries no preimage: the
    /// maker's refund won, because we were down or offline from signing our claim until
    /// past its locktime. Nothing is left to claim and the preimage never went out with a
    /// spend of it, so our own leg comes back by refund.
    async fn maker_leg_refunded(&self, r: &TakerRecord) -> Result<bool> {
        let Some(op) = r.maker_leg_outpoint else {
            return Ok(false);
        };
        let mb = self.mk(r)?;
        // No spend predates the lock's own block.
        let Some(confs) = mb.confirmations(&op.txid).await?.filter(|&c| c >= 1) else {
            return Ok(false);
        };
        let from = (mb.tip_height().await? + 1).saturating_sub(confs as u64);
        let Some(spend) = mb.find_spend(&op, from).await? else {
            return Ok(false);
        };
        Ok(spend.height.is_some() && spend.extract_preimage(&r.hash).is_none())
    }

    /// The maker's claim of the taker leg, if one that carries our preimage is buried at
    /// least as deep as the quote asks on that chain. Our refund can then never confirm: the
    /// preimage went out with a maker-leg claim of ours that never confirmed, and the maker
    /// spent both legs.
    async fn taker_leg_lost(&self, r: &TakerRecord) -> Result<Option<SpendInfo>> {
        let Some(f) = &r.taker_leg_funding else {
            return Ok(None);
        };
        let tb = self.tk(r)?;
        let Some(confs) = tb
            .confirmations(&f.outpoint.txid)
            .await?
            .filter(|&c| c >= 1)
        else {
            return Ok(None);
        };
        let tip = tb.tip_height().await?;
        let Some(spend) = tb
            .find_spend(&f.outpoint, (tip + 1).saturating_sub(confs as u64))
            .await?
        else {
            return Ok(None);
        };
        let deep = spend
            .height
            .is_some_and(|h| tip + 1 - h >= r.quote.confirmations_on(r.quote.taker_chain()) as u64);
        Ok((deep && spend.extract_preimage(&r.hash).is_some()).then_some(spend))
    }

    async fn taker_leg_refundable(&self, r: &TakerRecord) -> Result<bool> {
        let tk = self.tk(r)?;
        Ok(tk.refund_final(
            tk.median_time_past().await?,
            self.taker_leg_htlc(r)?.locktime,
        ))
    }

    async fn on_locked(&self, r: &mut TakerRecord, maker: Option<&SwapView>) -> Result<Flow> {
        if let Some(f) = &r.taker_leg_funding {
            self.tk(r)?.broadcast(&f.tx).await?; // idempotent; recovers a crash before broadcast
        }
        if self.taker_leg_refundable(r).await? {
            return self.enter(r, TakerState::Refunded);
        }
        if r.claim_declined.is_some() {
            // Decided for good: never claim, just wait for the refund above to mature.
            return Ok(Flow::Idle);
        }
        let Some(leg) = maker.and_then(|m| m.maker_leg.as_ref()) else {
            return Ok(Flow::Idle);
        };
        let Some(op) = leg.outpoint else {
            return Ok(Flow::Idle);
        };
        let htlc = leg.htlc;
        htlc.validate()?;
        let bad = |what: &str| SwapError::Other(format!("maker's lock: {what}"));
        let mb = self.mk(r)?.clone();
        if htlc.hash != r.hash {
            return Err(bad("wrong hash"));
        }
        if htlc.claim_pubkey != mb.pubkey() {
            return Err(bad("claim key is not ours"));
        }
        if htlc.refund_pubkey != r.quote.maker_pubkey(r.quote.maker_chain()) {
            return Err(bad("refund key is not the quote's maker key"));
        }
        // Trust the chain, not the maker's view, for amount and confirmations.
        let Some(lo) = mb.htlc_output(&htlc, &op).await? else {
            return Ok(Flow::Idle);
        };
        if lo.amount < r.quote.maker_leg_amount() {
            return Err(bad("underfunded"));
        }
        if lo.confirmations < r.quote.confirmations_on(r.quote.maker_chain()) {
            return Ok(Flow::Idle);
        }
        let mtp = mb.median_time_past().await?;
        let chain = r.quote.maker_chain();
        if let Err(reason) = self.claim_deadline(chain).check(chain, mtp, htlc.locktime) {
            // Not an error to retry: a claim now could confirm after the maker refunds, losing
            // the maker leg while revealing the preimage. Decide once, persist, and let the
            // taker-leg refund run its course.
            tracing::warn!(swap = %r.id, %reason, "declining to claim the maker leg");
            r.claim_declined = Some(reason);
            self.store.put_taker_swap(r)?;
            return Ok(Flow::Idle);
        }
        if let Some(p) = self.profile_floor {
            // Same decided-once outcome for a maker that quoted strong terms but locked short.
            if let Err(reason) = check_maker_leg_locktime(
                p,
                (r.quote.taker_chain(), r.quote.maker_chain()),
                &OfferedTerms::from(&r.quote),
                self.taker_leg_htlc(r)?.locktime,
                htlc.locktime,
                LOCKTIME_TOLERANCE_SECS,
            ) {
                tracing::warn!(swap = %r.id, %reason, "declining to claim the maker leg");
                r.claim_declined = Some(format!("{reason}; waiting for the taker-leg refund"));
                self.store.put_taker_swap(r)?;
                return Ok(Flow::Idle);
            }
            // The maker stated the MTP it locked at: the floor is then exact, not tolerant.
            if let Some(stated) = maker.and_then(|m| m.maker_mtp_at_lock) {
                if let Err(reason) = check_maker_leg_locktime_exact(
                    p,
                    (r.quote.taker_chain(), r.quote.maker_chain()),
                    &OfferedTerms::from(&r.quote),
                    self.taker_leg_htlc(r)?.locktime,
                    htlc.locktime,
                    stated,
                    mtp,
                    LOCKTIME_TOLERANCE_SECS,
                ) {
                    tracing::warn!(swap = %r.id, %reason, "declining to claim the maker leg");
                    r.claim_declined = Some(format!("{reason}; waiting for the taker-leg refund"));
                    self.store.put_taker_swap(r)?;
                    return Ok(Flow::Idle);
                }
            }
        }
        r.maker_leg_htlc = Some(htlc);
        r.maker_leg_outpoint = Some(op);
        r.maker_leg_amount = Some(lo.amount);
        self.enter(r, TakerState::MakerLockConfirmed)
    }

    async fn on_maker_lock_confirmed(&self, r: &mut TakerRecord) -> Result<Flow> {
        let htlc = r
            .maker_leg_htlc
            .ok_or_else(|| SwapError::Other("no verified maker lock".into()))?;
        let mtp = self.mk(r)?.median_time_past().await?;
        let chain = r.quote.maker_chain();
        let deadline = match r.claim_declined {
            Some(_) => Ok(()), // decided below on an earlier pass
            None => match self.claim_deadline(chain).check(chain, mtp, htlc.locktime) {
                Ok(()) => self.claim_fee_check(r, &htlc).await?,
                late => late,
            },
        };
        if r.claim_declined.is_none() && deadline.is_ok() {
            let op = r.maker_leg_outpoint.expect("set with maker_leg_htlc");
            let amount = r.maker_leg_amount.expect("set with maker_leg_htlc");
            self.sign_first_claim(r, &htlc, &op, amount).await?;
            // Persist the signed claim (which reveals the preimage) before broadcasting it.
            return self.enter(r, TakerState::Claimed);
        }
        // Too late or too dear to claim safely: decide for good, record why, and wait out
        // our own taker-leg timelock. Nothing has been revealed, so both legs refund.
        if let Err(reason) = deadline {
            tracing::warn!(swap = %r.id, %reason, "declining to claim the maker leg");
            r.claim_declined = Some(reason);
            self.store.put_taker_swap(r)?;
        }
        if self.taker_leg_refundable(r).await? {
            return self.enter(r, TakerState::Refunded);
        }
        Ok(Flow::Idle)
    }

    async fn on_claimed(&self, r: &mut TakerRecord) -> Result<Flow> {
        let claim = match r.maker_leg_claim.clone() {
            Some(tx) => tx,
            None => {
                let htlc = r
                    .maker_leg_htlc
                    .ok_or_else(|| SwapError::Other("Claimed without a maker-leg lock".into()))?;
                let op = r.maker_leg_outpoint.expect("set with maker_leg_htlc");
                let amount = r.maker_leg_amount.expect("set with maker_leg_htlc");
                let tx = self.sign_first_claim(r, &htlc, &op, amount).await?;
                self.store.put_taker_swap(r)?; // write-ahead
                tx
            }
        };
        // A version an RBF bump replaced may be the one that got mined.
        for (old, _) in &r.claim_replaced {
            if self
                .mk(r)?
                .confirmations(&old.txid)
                .await?
                .is_some_and(|c| c >= 1)
            {
                return self.enter(r, TakerState::Done);
            }
        }
        if let Err(e) = self.mk(r)?.broadcast(&claim).await {
            if matches!(e, SwapError::Rejected(_)) {
                return self.claim_refused(r, &claim, e).await;
            }
            return Err(e);
        }
        for (i, child) in r.claim_children.clone().iter().enumerate() {
            if let Err(e) = self.mk(r)?.broadcast(child).await {
                if matches!(e, SwapError::Rejected(_)) {
                    // Drop it and every child built on it; the next bump builds afresh.
                    tracing::warn!(swap = %r.id, refused = %child.txid, error = %e,
                        "claim CPFP child refused; dropping it");
                    r.claim_children.truncate(i);
                    r.claim_feerate = r.claim_base_feerate;
                    self.store.put_taker_swap(r)?;
                }
                return Err(e);
            }
        }
        if self
            .mk(r)?
            .confirmations(&claim.txid)
            .await?
            .is_some_and(|c| c >= 1)
        {
            return self.enter(r, TakerState::Done);
        }
        self.escalate_claim_fee(r, &claim).await?;
        Ok(Flow::Idle)
    }

    /// The node refused `claim`, the current version of the maker-leg claim, for good.
    ///
    /// - The chain holds it after all, or holds a version it replaced: keep the newest version
    ///   it holds (the refusal is not about the claim), dropping newer ones it never took.
    ///   Re-signing at the first claim's feerate would only conflict with it.
    /// - The maker refunded its leg: `Refunded`.
    /// - Nothing is held (evicted below the mempool's minimum feerate, say) and the claim can
    ///   be bumped: re-sign it at the escalation target, at least one unit per vbyte above
    ///   what it paid and at least the current estimate, within the cap; send it now.
    /// - Otherwise forget it so the next step re-signs from the persisted preimage (e.g.
    ///   signed by an older, buggy build), as the other claim/refund paths do.
    async fn claim_refused(
        &self,
        r: &mut TakerRecord,
        claim: &SignedTx,
        e: SwapError,
    ) -> Result<Flow> {
        let mk = self.mk(r)?;
        if mk.confirmations(&claim.txid).await?.is_some() {
            tracing::warn!(swap = %r.id, txid = %claim.txid, error = %e,
                "claim rebroadcast refused but the chain holds it; keeping it");
            return Err(e);
        }
        for i in (0..r.claim_replaced.len()).rev() {
            let (prev, feerate) = r.claim_replaced[i].clone();
            if mk.confirmations(&prev.txid).await?.is_some() {
                tracing::warn!(swap = %r.id, refused = %claim.txid, back_to = %prev.txid,
                    error = %e, "claim replacement refused; back to the claim the chain holds");
                // The node wants a bigger step than the configured price bump: counted, so
                // the next replacement outbids it (`FeeEscalation::underpriced_target`).
                if mk.fee_bump() == FeeBump::SameNonce
                    && e.to_string().to_ascii_lowercase().contains("underpriced")
                {
                    r.claim_underpriced = r.claim_underpriced.saturating_add(1);
                    tracing::warn!(swap = %r.id, chain = %r.quote.maker_chain(),
                        refusals = r.claim_underpriced, feerate = feerate,
                        "claim replacement refused as underpriced");
                }
                r.claim_replaced.truncate(i);
                r.maker_leg_claim = Some(prev);
                r.claim_feerate = Some(feerate);
                r.claim_children.clear();
                self.store.put_taker_swap(r)?;
                return Err(e);
            }
        }
        if self.maker_leg_refunded(r).await? {
            r.maker_leg_claim = None;
            r.claim_children.clear();
            return self.enter(r, TakerState::Refunded);
        }
        let chain = r.quote.maker_chain();
        // Under `SameNonce` nothing at the claim's nonce is held here, so it is free (or a
        // different transaction took it): `build_claim_at` signs at the next free nonce.
        if let (
            Some(esc),
            Some(base),
            Some(current),
            FeeBump::Rbf | FeeBump::Cpfp | FeeBump::SameNonce,
        ) = (
            self.fee_escalation(chain),
            r.claim_base_feerate,
            r.claim_feerate,
            mk.fee_bump(),
        ) {
            let htlc = r.maker_leg_htlc.expect("Claimed has a maker-leg lock");
            let op = r.maker_leg_outpoint.expect("set with maker_leg_htlc");
            let amount = r.maker_leg_amount.expect("set with maker_leg_htlc");
            let left = i64::from(htlc.locktime) - i64::from(mk.median_time_past().await?);
            let estimate = mk.claim_feerate().await?.unwrap_or(0);
            let (target, cap) = match self.claim_ceiling(r, &htlc, amount, left, 0)? {
                Some(ceiling) => (esc.target_after_leak(base, left, ceiling), ceiling),
                None => (esc.target(base, left), esc.cap(base)),
            };
            // Refused at the fixed cap or above: the mempool wants more than the cap, so
            // step up by a bump's worth rather than one unit per vbyte.
            let step = if current >= esc.cap(base) {
                (current / 4).max(1)
            } else {
                1
            };
            let feerate = target
                .max(estimate)
                .max(current.saturating_add(step))
                .min(cap);
            if feerate <= current {
                tracing::warn!(swap = %r.id, txid = %claim.txid, feerate = current, error = %e,
                    "claim refused at the fee cap; resending it unchanged");
                return Err(e);
            }
            let tx = mk
                .build_claim_at(&htlc, &op, amount, &r.preimage, feerate)
                .await?;
            r.claim_replaced.push((claim.clone(), current));
            r.maker_leg_claim = Some(tx.clone());
            r.claim_feerate = Some(feerate);
            r.claim_children.clear();
            r.claim_underpriced = 0; // a fresh claim, not a replacement
            self.store.put_taker_swap(r)?; // write-ahead
            tracing::info!(swap = %r.id, %chain, old_feerate = current, new_feerate = feerate,
                txid = %tx.txid, claim = %claim.txid, secs_left = left, error = %e,
                "claim refused and not held; re-signed at a higher feerate");
            mk.broadcast(&tx).await?;
            return Ok(Flow::Idle);
        }
        r.maker_leg_claim = None;
        r.claim_children.clear();
        self.store.put_taker_swap(r)?;
        Err(e)
    }

    /// `Err(reason)` if a claim at the feerate the backend reports now would pay more than
    /// half the maker leg, the post-leak ceiling's first share
    /// ([`FeeEscalation::ceiling_fee`]). Checked before the first claim reveals the
    /// preimage, while declining still refunds both legs; past that point the leg is won or
    /// lost on fees. `Ok` where the backend reports no feerate or no sizes.
    async fn claim_fee_check(
        &self,
        r: &TakerRecord,
        htlc: &HtlcParams,
    ) -> Result<std::result::Result<(), String>> {
        let mk = self.mk(r)?;
        let chain = r.quote.maker_chain();
        let amount = r.maker_leg_amount.expect("set with maker_leg_htlc");
        let (Some(sizes), Some(feerate)) = (mk.claim_sizes(htlc), mk.claim_feerate().await?) else {
            return Ok(Ok(()));
        };
        let fee = feerate.saturating_mul(sizes.claim_vsize);
        let share = amount.0 / 2;
        if fee > share {
            return Ok(Err(format!(
                "a {chain} claim at the current {feerate}/vB pays {fee}, more than half the \
                 maker leg ({share} of {}); not claiming, waiting for the taker-leg refund",
                amount.0
            )));
        }
        Ok(Ok(()))
    }

    /// The post-leak fee ceiling ([`FeeEscalation::ceiling_fee`]) for the maker-leg claim
    /// with `left` seconds before the locktime, as a feerate over the package the next
    /// version makes: the claim and `children` CPFP children (the new one included), so a
    /// CPFP ceiling covers the fee of parent and children together. `None` where the backend
    /// reports no sizes: the fixed cap then holds.
    fn claim_ceiling(
        &self,
        r: &TakerRecord,
        htlc: &HtlcParams,
        amount: Amount,
        left: i64,
        children: u64,
    ) -> Result<Option<u64>> {
        let Some(sizes) = self.mk(r)?.claim_sizes(htlc) else {
            return Ok(None);
        };
        let vsize = sizes
            .claim_vsize
            .saturating_add(sizes.child_vsize.saturating_mul(children))
            .max(1);
        let window = self.claim_deadline(r.quote.maker_chain()).margin_secs();
        let fee = FeeEscalation::ceiling_fee(amount.0, sizes.dust, vsize, left, window);
        Ok(Some(fee / vsize))
    }

    /// Sign the first maker-leg claim. Where the backend can bump it, at the feerate it
    /// reports now, recorded as the base the escalation climbs from.
    async fn sign_first_claim(
        &self,
        r: &mut TakerRecord,
        htlc: &HtlcParams,
        op: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        let mk = self.mk(r)?;
        let feerate = match (mk.fee_bump(), self.fee_escalation(r.quote.maker_chain())) {
            (FeeBump::None, _) | (_, None) => None,
            _ => mk.claim_feerate().await?,
        };
        let tx = match feerate {
            Some(f) => mk.build_claim_at(htlc, op, amount, &r.preimage, f).await?,
            None => mk.build_claim(htlc, op, amount, &r.preimage).await?,
        };
        r.maker_leg_claim = Some(tx.clone());
        r.claim_base_feerate = feerate;
        r.claim_feerate = feerate;
        r.claim_replaced.clear();
        r.claim_children.clear();
        r.claim_underpriced = 0;
        Ok(tx)
    }

    /// Raise the fee of the unconfirmed `claim` along the chain's [`FeeEscalation`] as the
    /// maker-leg locktime nears: replace it (RBF, or at its nonce on EVM), or bump it
    /// through a CPFP child, persisting the new transaction before broadcasting it and
    /// logging every bump. A no-op where the backend cannot bump, escalation is off, or the
    /// target is not yet worth a new transaction.
    ///
    /// A CPFP bump replaces the newest child, so the package stays the claim and one child
    /// (the child signals BIP125). A node that refuses that (Litecoin Core's default,
    /// `-mempoolreplacement=0`) gets the old child back and a new one on top instead, which
    /// [`FeeEscalation::should_add_child`] keeps to about ten in all, inside the
    /// 25-transaction ancestor limit.
    async fn escalate_claim_fee(&self, r: &mut TakerRecord, claim: &SignedTx) -> Result<()> {
        let chain = r.quote.maker_chain();
        let mk = self.mk(r)?;
        let (Some(esc), Some(base), Some(current)) = (
            self.fee_escalation(chain),
            r.claim_base_feerate,
            r.claim_feerate,
        ) else {
            return Ok(());
        };
        let kind = mk.fee_bump();
        if kind == FeeBump::None {
            return Ok(());
        }
        let (Some(htlc), Some(op), Some(amount)) =
            (r.maker_leg_htlc, r.maker_leg_outpoint, r.maker_leg_amount)
        else {
            return Ok(());
        };
        let left = i64::from(htlc.locktime) - i64::from(mk.median_time_past().await?);
        if kind == FeeBump::Cpfp {
            return self
                .bump_claim_child(r, claim, &esc, base, current, left)
                .await;
        }
        let (target, bump) = match self.claim_ceiling(r, &htlc, amount, left, 0)? {
            Some(c) => {
                let t = esc.target_after_leak(base, left, c);
                (t, esc.should_bump(base, current, t))
            }
            None => {
                let t = esc.target(base, left);
                (t, esc.should_bump(base, current, t))
            }
        };
        if !bump {
            return Ok(());
        }
        // Refused as underpriced at least twice since the node last took a version: it holds
        // a stricter price bump than the chain's configured one. Double the step every second
        // refusal, within the cap.
        let target = match kind {
            FeeBump::SameNonce if r.claim_underpriced >= 2 => {
                let raised = esc.underpriced_target(base, current, target, r.claim_underpriced);
                tracing::warn!(
                    swap = %r.id,
                    %chain,
                    refusals = r.claim_underpriced,
                    price_bump_pct = esc.price_bump_pct,
                    old_feerate = current,
                    step_feerate = target,
                    new_feerate = raised,
                    cap = esc.cap(base),
                    "claim replacements refused as underpriced; doubling the step"
                );
                raised
            }
            _ => target,
        };
        let tx = match kind {
            FeeBump::Rbf => {
                let tx = mk
                    .build_claim_at(&htlc, &op, amount, &r.preimage, target)
                    .await?;
                r.claim_replaced.push((claim.clone(), current));
                r.maker_leg_claim = Some(tx.clone());
                tx
            }
            FeeBump::SameNonce => {
                // `None`: the node's replacement minimum is above the target; keep the claim.
                let Some(tx) = mk
                    .build_claim_replacement(claim, target, esc.price_bump_pct)
                    .await?
                else {
                    return Ok(());
                };
                r.claim_replaced.push((claim.clone(), current));
                r.maker_leg_claim = Some(tx.clone());
                tx
            }
            FeeBump::Cpfp | FeeBump::None => unreachable!("returned above"),
        };
        r.claim_feerate = Some(target);
        self.store.put_taker_swap(r)?; // write-ahead
        tracing::info!(
            swap = %r.id,
            %chain,
            bump = ?kind,
            old_feerate = current,
            new_feerate = target,
            txid = %tx.txid,
            claim = %claim.txid,
            secs_left = left,
            "claim fee bumped"
        );
        match mk.broadcast(&tx).await {
            Ok(_) if r.claim_underpriced > 0 => {
                // The node took a version: the next step starts from the configured bump.
                r.claim_underpriced = 0;
                self.store.put_taker_swap(r)?;
            }
            Ok(_) => {}
            // Kept: the next step resends it and, if refused for good, falls back.
            Err(e) => {
                tracing::warn!(swap = %r.id, txid = %tx.txid, error = %e,
                    "fee bump broadcast failed");
            }
        }
        Ok(())
    }

    /// The CPFP target for the package of `claim` and `children` CPFP children (the new one
    /// included), with `left` seconds before the locktime, and whether it is worth a bump
    /// from `current`. Past the cap point the ceiling is the one at the start of the
    /// current step ([`FeeEscalation::cpfp_step`]), so the step's target holds through it.
    fn cpfp_target(
        &self,
        r: &TakerRecord,
        esc: &FeeEscalation,
        base: u64,
        current: u64,
        left: i64,
        children: u64,
    ) -> Result<(u64, bool)> {
        let (Some(htlc), Some(amount)) = (r.maker_leg_htlc, r.maker_leg_amount) else {
            return Ok((current, false));
        };
        let at = esc.cpfp_step(left).map_or(left, |(_, start)| start);
        let target = match self.claim_ceiling(r, &htlc, amount, at, children)? {
            Some(c) => esc.cpfp_target_after_leak(base, left, c),
            None => esc.target(base, left),
        };
        Ok((target, esc.should_add_child(base, left, current, target)))
    }

    /// [`Taker::escalate_claim_fee`] for a CPFP claim: add a child on top of the newest
    /// child of `claim` (or the first). With [`FeeEscalation::replace_cpfp_child`], replace
    /// the newest child instead, and where the node refuses the replacement, keep the old
    /// child and add one on top of it.
    async fn bump_claim_child(
        &self,
        r: &mut TakerRecord,
        claim: &SignedTx,
        esc: &FeeEscalation,
        base: u64,
        current: u64,
        left: i64,
    ) -> Result<()> {
        let mk = self.mk(r)?;
        let amount = r.maker_leg_amount.expect("checked by the caller");
        let held = r.claim_children.len() as u64;
        let replace = esc.replace_cpfp_child && held > 0;
        let children = if replace { held } else { held + 1 };
        let (target, bump) = self.cpfp_target(r, esc, base, current, left, children)?;
        if !bump {
            return Ok(());
        }
        let old = if replace {
            r.claim_children.pop()
        } else {
            None
        };
        let mut package = vec![claim.clone()];
        package.extend(r.claim_children.iter().cloned());
        let tx = match mk.build_cpfp(&package, amount, target).await {
            Ok(tx) => tx,
            Err(e) => {
                r.claim_children.extend(old);
                return Err(e);
            }
        };
        r.claim_children.push(tx.clone());
        r.claim_feerate = Some(target);
        self.store.put_taker_swap(r)?; // write-ahead
        self.log_child_bump(r, claim, &tx, current, target, left, old.is_some());
        let refused = match mk.broadcast(&tx).await {
            Ok(_) => return Ok(()),
            Err(SwapError::Rejected(e)) if old.is_some() => e,
            Err(e) => {
                // Kept: the next step resends it and, if refused for good, drops it.
                tracing::warn!(swap = %r.id, txid = %tx.txid, error = %e,
                    "fee bump broadcast failed");
                return Ok(());
            }
        };
        // The node keeps the old child (no child replacement): put it back, then chain a
        // new child onto the whole package, which is one child bigger.
        tracing::info!(swap = %r.id, refused = %tx.txid, error = %refused,
            "claim CPFP child replacement refused; adding a child instead");
        r.claim_children.pop();
        r.claim_children.extend(old);
        r.claim_feerate = Some(current);
        let (target, bump) = self.cpfp_target(r, esc, base, current, left, held + 1)?;
        if !bump {
            self.store.put_taker_swap(r)?;
            return Ok(());
        }
        let mut package = vec![claim.clone()];
        package.extend(r.claim_children.iter().cloned());
        let tx = match mk.build_cpfp(&package, amount, target).await {
            Ok(tx) => tx,
            Err(e) => {
                self.store.put_taker_swap(r)?;
                return Err(e);
            }
        };
        r.claim_children.push(tx.clone());
        r.claim_feerate = Some(target);
        self.store.put_taker_swap(r)?; // write-ahead
        self.log_child_bump(r, claim, &tx, current, target, left, false);
        if let Err(e) = mk.broadcast(&tx).await {
            tracing::warn!(swap = %r.id, txid = %tx.txid, error = %e, "fee bump broadcast failed");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn log_child_bump(
        &self,
        r: &TakerRecord,
        claim: &SignedTx,
        tx: &SignedTx,
        current: u64,
        target: u64,
        left: i64,
        replaces: bool,
    ) {
        tracing::info!(
            swap = %r.id,
            chain = %r.quote.maker_chain(),
            bump = ?FeeBump::Cpfp,
            replaces,
            children = r.claim_children.len(),
            old_feerate = current,
            new_feerate = target,
            txid = %tx.txid,
            claim = %claim.txid,
            secs_left = left,
            "claim fee bumped"
        );
    }

    async fn on_refunded(&self, r: &mut TakerRecord) -> Result<Flow> {
        if let Some(spend) = self.taker_leg_lost(r).await? {
            // Without this the refund is refused for good on every step and re-signed
            // forever.
            tracing::error!(
                swap = %r.id,
                taker_leg = ?r.taker_leg_funding.as_ref().map(|f| f.outpoint),
                maker_leg = ?r.maker_leg_outpoint,
                maker_claim = %spend.txid,
                "swap lost: the maker claimed the taker leg with our preimage and our \
                 maker-leg claim never confirmed; nothing is left to refund or claim"
            );
            r.taker_leg_refund = None;
            r.last_error = Some(format!(
                "lost: the taker leg was claimed by {} with our preimage",
                spend.txid
            ));
            return self.enter(r, TakerState::Lost);
        }
        let refund = match r.taker_leg_refund.clone() {
            Some(tx) => tx,
            None => {
                let htlc = self.taker_leg_htlc(r)?;
                let f = r
                    .taker_leg_funding
                    .clone()
                    .ok_or_else(|| SwapError::Other("Refunded without a funding tx".into()))?;
                let tx = self
                    .tk(r)?
                    .build_refund(&htlc, &f.outpoint, f.amount)
                    .await?;
                r.taker_leg_refund = Some(tx.clone());
                self.store.put_taker_swap(r)?; // write-ahead
                tx
            }
        };
        match self.tk(r)?.broadcast(&refund).await {
            Ok(_) => {}
            Err(SwapError::Premature(_)) => return Ok(Flow::Idle),
            Err(e @ SwapError::Rejected(_)) => {
                // Refused for good: re-sign on the next step rather than resend dead bytes.
                r.taker_leg_refund = None;
                self.store.put_taker_swap(r)?;
                return Err(e);
            }
            Err(e) => return Err(e),
        }
        if self
            .tk(r)?
            .confirmations(&refund.txid)
            .await?
            .is_some_and(|c| c >= 1)
        {
            return self.enter(r, TakerState::Done);
        }
        Ok(Flow::Idle)
    }
}

enum Flow {
    Idle,
    Moved,
    Halted,
}

#[cfg(test)]
mod terminal_tests {
    use super::TakerState;

    /// Every variant with its verdict. The match makes a new variant a compile error here
    /// as well as in `is_terminal`, so it cannot be added without a decision.
    fn verdict(s: TakerState) -> bool {
        match s {
            TakerState::Prepared
            | TakerState::Accepted
            | TakerState::Locked
            | TakerState::MakerLockConfirmed
            | TakerState::Claimed
            | TakerState::Refunded => false,
            TakerState::Done | TakerState::Lost => true,
        }
    }

    #[test]
    fn is_terminal_matches_the_table_for_every_variant() {
        let all = [
            TakerState::Prepared,
            TakerState::Accepted,
            TakerState::Locked,
            TakerState::MakerLockConfirmed,
            TakerState::Claimed,
            TakerState::Refunded,
            TakerState::Done,
            TakerState::Lost,
        ];
        for s in all {
            assert_eq!(s.is_terminal(), verdict(s), "{s:?}");
        }
        // Refunded still owes its refund broadcast, so only Done and Lost are terminal.
        assert_eq!(all.iter().filter(|s| s.is_terminal()).count(), 2);
    }
}
