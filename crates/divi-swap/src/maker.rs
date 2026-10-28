// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The maker engine: quotes, accepts, and drives each swap through [`SwapState`].
//! **Lane engine** owns the bodies; the public signatures are frozen (the daemon builds
//! against them).
//!
//! Rules (plan §3.2): persist every transition and every signed tx **before** broadcasting;
//! every `step` is idempotent and safe to re-run after a crash; `build_funding` on the
//! maker-leg backend is called only on the `TakerLockConfirmed → MakerLocked` edge (and on
//! neither backend before it).
//!
//! Chains. Every swap is DIVI against the offer's counter chain; the offer's [`Direction`]
//! fixes which chain each leg is on: the taker leg on `quote.taker_chain()`, the maker leg on
//! `quote.maker_chain()`. Everything below is written in those roles, so a new UTXO counter
//! chain needs only a [`ChainBackend`], no engine change.

use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::{AcceptRequest, LegView, LockNotice, Offer, Quote, SwapView};
use crate::backend::ChainBackend;
use crate::claim_fee::ClaimCtx;
use crate::config::{ClaimDeadline, FeeEscalation, SwapConfig};
use crate::error::{Result, SwapError};
use crate::hold;
use crate::htlc::{HtlcParams, ScriptVersion};
use crate::state::SwapState;
use crate::store::{MakerRecord, QuoteRecord, Store};
use crate::types::{Amount, Chain, Funding, Outpoint, SignedTx, SpendInfo};

/// Default wall-clock time the maker waits for the taker's lock after `accept`.
pub const DEFAULT_LOCK_WAIT_SECS: u64 = 1800;

/// Bound, in seconds, on each wait `accept` (and `notify_lock`) makes around the gate: acquiring
/// it, and (for `accept`) the taker-chain median-time-past read held under it.
///
/// A healthy MTP read is 2 calls (BTC/LTC) or 13 (DIVI) and takes seconds. Per-request timeouts
/// alone allow ~27 min on DIVI (13 calls x 4 attempts x 30 s) and ~3 min on BTC/LTC, with the
/// gate held. 20 s per wait keeps `accept` under 40 s in the worst case, inside the default 60 s
/// quote expiry, and fails with a retryable error the taker can answer with a new quote.
pub const GATE_BOUND_SECS: u64 = 20;

/// Upper bound on transitions one `step` call performs (a swap has far fewer).
const MAX_TRANSITIONS_PER_STEP: usize = 32;

/// Reported once when the maker lock was reorged out and cannot be re-sent.
const MAKER_LOCK_DROPPED: &str = "maker lock dropped by a reorg and its inputs were spent";
/// `last_error` of a sent maker lock the node dropped whose coin the reservation table now
/// gives to another lock: kept, never replaced.
const MAKER_LOCK_HELD: &str =
    "maker lock dropped by a reorg and its inputs are held by another lock";

/// What one pass of the state machine did.
enum Flow {
    /// Nothing to do until something changes on chain or the clock moves.
    Idle,
    /// Entered a new state (already persisted).
    Moved,
    /// Entered the state named by the test crash hook; stop as if the process died.
    Halted,
}

/// Maker engine: serves quotes and drives each accepted swap through the state machine.
///
/// Another swap engine sharing this maker's offer list, quote route and scheduler — the
/// DIVI<->XMR adaptor engine (`divi-swap-xmr`), which cannot be a [`ChainBackend`]. Its own
/// swap routes live beside the hashlock ones; only offers, quotes and ticking go through here.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait OfferEngine: Send + Sync {
    /// The offers it serves (ids must not clash with this maker's).
    fn offers(&self) -> Vec<Offer>;
    /// Quote one of them.
    async fn quote(&self, offer_id: &str, btc_sats: u64) -> Result<Quote>;
    /// Advance its swaps (called on every [`Maker::tick`]).
    async fn tick(&self) -> Result<()>;
}

/// Every transition — and every signed transaction — is persisted before the side effect it
/// precedes (write-ahead), so [`Maker::step`] can be re-run after a crash at any point.
pub struct Maker {
    cfg: SwapConfig,
    divi: Arc<dyn ChainBackend>,
    /// Counter-chain backends, by `chain()`.
    counters: BTreeMap<Chain, Arc<dyn ChainBackend>>,
    store: Store,
    offers: Vec<Offer>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    lock_wait_secs: u64,
    halt_after: Mutex<Option<SwapState>>,
    gate: tokio::sync::Mutex<()>,
    gate_bound: Duration,
    engines: Vec<Arc<dyn OfferEngine>>,
    /// Per-chain fee escalations of taker-leg claims replacing
    /// [`FeeEscalation::builtin`] (`None`: off).
    fee_escalations: BTreeMap<Chain, Option<FeeEscalation>>,
}

impl Maker {
    /// New engine with one counter-chain backend (`btc` — any chain but DIVI; the name
    /// predates counter chains). Fails if `cfg` violates the timeout invariant or an offer's
    /// counter chain has no backend.
    pub fn new(
        cfg: SwapConfig,
        divi: Arc<dyn ChainBackend>,
        btc: Arc<dyn ChainBackend>,
        store: Store,
        offers: Vec<Offer>,
    ) -> Result<Self> {
        Self::with_counters(cfg, divi, vec![btc], store, offers)
    }

    /// New engine trading DIVI against every chain in `counters` (one backend per chain,
    /// keyed by [`ChainBackend::chain`]). Fails like [`Maker::new`], or on two backends for
    /// one chain.
    pub fn with_counters(
        cfg: SwapConfig,
        divi: Arc<dyn ChainBackend>,
        counters: Vec<Arc<dyn ChainBackend>>,
        store: Store,
        offers: Vec<Offer>,
    ) -> Result<Self> {
        cfg.validate()?;
        let mut by_chain = BTreeMap::new();
        for b in counters {
            let c = b.chain();
            if by_chain.insert(c, b).is_some() {
                return Err(SwapError::InvalidParams(format!(
                    "two counter backends for {c}"
                )));
            }
        }
        for o in &offers {
            if o.counter_chain.is_adaptor() {
                return Err(SwapError::InvalidParams(format!(
                    "offer {}: {} swaps use the adaptor-signature engine, not the hashlock maker",
                    o.id, o.counter_chain
                )));
            }
            if !o.counter_chain.is_counter() || !by_chain.contains_key(&o.counter_chain) {
                return Err(SwapError::InvalidParams(format!(
                    "offer {}: no {} backend",
                    o.id, o.counter_chain
                )));
            }
        }
        Ok(Maker {
            cfg,
            divi,
            counters: by_chain,
            store,
            offers,
            clock: Arc::new(unix_now),
            lock_wait_secs: DEFAULT_LOCK_WAIT_SECS,
            halt_after: Mutex::new(None),
            gate: tokio::sync::Mutex::new(()),
            gate_bound: Duration::from_secs(GATE_BOUND_SECS),
            engines: Vec::new(),
            fee_escalations: BTreeMap::new(),
        })
    }

    /// Use `escalation` instead of [`FeeEscalation::builtin`] for claims of taker legs on
    /// `chain`; `None` never bumps them.
    pub fn with_fee_escalation(mut self, chain: Chain, escalation: Option<FeeEscalation>) -> Self {
        self.fee_escalations.insert(chain, escalation);
        self
    }

    /// The fee escalation this maker applies to claims of taker legs on `chain`.
    pub fn fee_escalation(&self, chain: Chain) -> Option<FeeEscalation> {
        self.fee_escalations
            .get(&chain)
            .copied()
            .unwrap_or_else(|| FeeEscalation::builtin(chain))
    }

    /// Replace the bound on each gate wait and gate-held chain read ([`GATE_BOUND_SECS`]).
    pub fn with_gate_bound(mut self, bound: Duration) -> Self {
        self.gate_bound = bound;
        self
    }

    /// Take the gate, or fail with a retryable error after `gate_bound` (nothing was written).
    async fn gate_bounded(&self, what: &str) -> Result<tokio::sync::MutexGuard<'_, ()>> {
        tokio::time::timeout(self.gate_bound, self.gate.lock())
            .await
            .map_err(|_| {
                SwapError::Transient(format!(
                    "{what}: engine busy (waited {:?} for a swap step); retry",
                    self.gate_bound
                ))
            })
    }

    /// Replace the wall clock (unix seconds). Quote expiry and the lock wait use it.
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// How long to wait for the taker's lock before aborting an accepted swap.
    pub fn with_lock_wait_secs(mut self, secs: u64) -> Self {
        self.lock_wait_secs = secs;
        self
    }

    /// Test hook: behave as if the process died right after persisting the transition
    /// into `state` — [`Maker::step`] returns before that state's side effect runs.
    #[doc(hidden)]
    pub fn halt_after(&self, state: Option<SwapState>) {
        *self.halt_after.lock() = state;
    }

    /// Serve another engine's offers through this maker's offer list, quotes and ticks.
    /// Fails if one of its offer ids is already taken.
    pub fn with_engine(mut self, engine: Arc<dyn OfferEngine>) -> Result<Self> {
        let taken = self.offers();
        if let Some(o) = engine
            .offers()
            .iter()
            .find(|o| taken.iter().any(|t| t.id == o.id))
        {
            return Err(SwapError::InvalidParams(format!(
                "offer id {} served twice",
                o.id
            )));
        }
        self.engines.push(engine);
        Ok(self)
    }

    /// Standing offers (this maker's, then each engine's).
    pub fn offers(&self) -> Vec<Offer> {
        let mut all = self.offers.clone();
        for e in &self.engines {
            all.extend(e.offers());
        }
        all
    }

    /// The counter chains this maker has a backend for.
    pub fn counter_chains(&self) -> Vec<Chain> {
        self.counters.keys().copied().collect()
    }

    /// The backend for `chain` (DIVI or a counter chain), if this maker has one.
    pub fn backend(&self, chain: Chain) -> Option<Arc<dyn ChainBackend>> {
        self.chain(chain).ok().cloned()
    }

    /// Issue a quote for `btc_sats` counter-chain sats, valid for `cfg.quote_expiry_secs`.
    /// No coins are reserved.
    pub async fn quote(&self, offer_id: &str, btc_sats: u64) -> Result<Quote> {
        if !self.offers.iter().any(|o| o.id == offer_id) {
            for e in &self.engines {
                if e.offers().iter().any(|o| o.id == offer_id) {
                    return e.quote(offer_id, btc_sats).await;
                }
            }
        }
        let offer = self
            .offers
            .iter()
            .find(|o| o.id == offer_id)
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown offer {offer_id:?}")))?;
        if btc_sats < offer.min_btc_sats || btc_sats > offer.max_btc_sats {
            return Err(SwapError::InvalidParams(format!(
                "{btc_sats} sats outside offer range {}..={}",
                offer.min_btc_sats, offer.max_btc_sats
            )));
        }
        let divi_amount = offer.checked_divi_for(btc_sats).ok_or_else(|| {
            SwapError::InvalidParams(format!(
                "{btc_sats} sats at {} DIVI sats per BTC is more DIVI than an amount can hold",
                offer.divi_sats_per_btc
            ))
        })?;
        if divi_amount.0 == 0 {
            return Err(SwapError::InvalidParams("swap is worth no DIVI".into()));
        }
        let counter = offer.counter_chain;
        let quote = Quote {
            id: uuid::Uuid::new_v4().to_string(),
            offer_id: offer.id.clone(),
            direction: offer.direction,
            counter_chain: counter,
            btc_amount: Amount(btc_sats),
            divi_amount,
            expires_at: (self.clock)() + self.cfg.quote_expiry_secs as u64,
            maker_btc_pubkey: self.chain(counter)?.pubkey(),
            maker_divi_pubkey: self.divi.pubkey(),
            taker_timeout_secs: self.cfg.taker_timeout_secs,
            maker_timeout_secs: self.cfg.maker_timeout_secs,
            btc_confirmations: self.cfg.confirmations(counter),
            divi_confirmations: self.cfg.confirmations(Chain::Divi),
        };
        self.store.put_quote(&QuoteRecord {
            quote: quote.clone(),
            used: false,
        })?;
        Ok(quote)
    }

    /// Accept an unexpired quote: fixes the taker-leg HTLC the taker must fund.
    ///
    /// Holds `gate` from the used-quote and hash checks through the writes, across the one
    /// `median_time_past` read: two accepts of one quote, or of one hash on two quotes, cannot
    /// both pass the checks.
    ///
    /// Both the wait for `gate` and each chain read are bounded by `gate_bound`; on timeout the
    /// accept fails with [`SwapError::Transient`] (HTTP 503, retryable) before any write, so the
    /// quote stays unused and no swap row exists.
    ///
    /// A maker that cannot fund its own leg refuses with [`SwapError::InsufficientFunds`]
    /// (HTTP 409), also before any write: it reads [`ChainBackend::spendable`] on the maker-leg
    /// chain, less what accepted swaps on that chain still have to lock. No coin is selected or
    /// reserved here; that still waits for `TakerLockConfirmed`.
    pub async fn accept(&self, req: AcceptRequest) -> Result<SwapView> {
        let _g = self.gate_bounded("accept").await?;
        let mut qr = self
            .store
            .get_quote(&req.quote_id)?
            .ok_or_else(|| SwapError::InvalidParams("unknown quote".into()))?;
        if qr.used {
            return Err(SwapError::InvalidParams("quote already used".into()));
        }
        // Before anything else touches the quote: an old client on a non-BTC offer must
        // not get a taker-leg HTLC it would fund on the wrong chain.
        req.check_counter_chain(&qr.quote)?;
        let now = (self.clock)();
        if now > qr.quote.expires_at {
            return Err(SwapError::InvalidParams("quote expired".into()));
        }
        let swaps = self.store.list_maker_swaps()?;
        if swaps.iter().any(|s| s.hash == req.hash) {
            return Err(SwapError::InvalidParams("hash already in use".into()));
        }
        let (tc, mc) = (qr.quote.taker_chain(), qr.quote.maker_chain());
        let tmtp = tokio::time::timeout(self.gate_bound, self.chain(tc)?.median_time_past())
            .await
            .map_err(|_| {
                SwapError::Transient(format!(
                    "accept: {tc} median time past not read within {:?}; retry",
                    self.gate_bound
                ))
            })??;
        let locktime = tmtp
            .checked_add(qr.quote.taker_timeout_secs)
            .ok_or_else(|| SwapError::InvalidParams("locktime overflow".into()))?;
        let taker_leg_htlc = HtlcParams {
            hash: req.hash,
            claim_pubkey: qr.quote.maker_pubkey(tc),
            refund_pubkey: req.taker_pubkey(tc),
            locktime,
            script_version: ScriptVersion::V1,
        };
        taker_leg_htlc.validate()?;
        // The maker leg is built later, on its own chain's clock; check the keys now.
        HtlcParams {
            hash: req.hash,
            claim_pubkey: req.taker_pubkey(mc),
            refund_pubkey: qr.quote.maker_pubkey(mc),
            locktime,
            script_version: ScriptVersion::V1,
        }
        .validate()?;
        // Otherwise the taker locks and then waits out its whole timeout for a refund.
        let need = qr.quote.maker_leg_amount();
        let have = tokio::time::timeout(self.gate_bound, self.chain(mc)?.spendable())
            .await
            .map_err(|_| {
                SwapError::Transient(format!(
                    "accept: {mc} balance not read within {:?}; retry",
                    self.gate_bound
                ))
            })??;
        // Swaps already accepted on this chain whose maker leg is not funded yet draw on the
        // same coins. One whose taker never locks stops counting when it aborts (lock wait).
        // Summed in u128: legs near `u64::MAX` must not wrap, nor saturate into a pass.
        let promised: u128 = swaps
            .iter()
            .filter(|s| {
                matches!(
                    s.state,
                    SwapState::Accepted | SwapState::TakerLockSeen | SwapState::TakerLockConfirmed
                ) && s.maker_leg_funding.is_none()
                    && s.quote.maker_chain() == mc
            })
            .map(|s| u128::from(s.quote.maker_leg_amount().0))
            .sum();
        if let Some(have) = have {
            if u128::from(have.0) < u128::from(need.0) + promised {
                return Err(SwapError::InsufficientFunds(format!(
                    "maker has {have} spendable on {mc}, this swap needs {need}, \
                     accepted swaps not yet funded need {}",
                    Amount(u64::try_from(promised).unwrap_or(u64::MAX))
                )));
            }
        }

        let rec = MakerRecord {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: now,
            state: SwapState::Accepted,
            quote: qr.quote.clone(),
            hash: req.hash,
            taker_maker_leg_pubkey: req.taker_pubkey(mc),
            taker_leg_htlc,
            taker_leg_outpoint: None,
            taker_leg_locked: None,
            maker_leg_htlc: None,
            maker_leg_funding: None,
            maker_leg_scan_from: 0,
            maker_mtp_at_lock: None,
            maker_leg_refund: None,
            preimage: None,
            taker_leg_claim: None,
            last_error: None,
            maker_lock_dropped: false,
            maker_lock_sent: false,
            claim_fees: Default::default(),
        };
        qr.used = true;
        self.store.put_quote(&qr)?;
        self.store.put_maker_swap(&rec)?;
        Ok(view_of(&rec))
    }

    /// The taker says it funded the taker-leg HTLC at `lock.outpoint`.
    pub async fn notify_lock(&self, swap_id: &str, lock: LockNotice) -> Result<SwapView> {
        {
            let _g = self.gate_bounded("notify_lock").await?;
            let mut rec = self.load(swap_id)?;
            match rec.taker_leg_outpoint {
                Some(op) if op == lock.outpoint => {}
                Some(_) => {
                    return Err(SwapError::InvalidParams(
                        "a different lock was already reported".into(),
                    ))
                }
                None if rec.state == SwapState::Accepted => {
                    self.refuse_downgraded_lock(&rec, &lock.outpoint).await?;
                    rec.taker_leg_outpoint = Some(lock.outpoint);
                    self.store.put_maker_swap(&rec)?;
                }
                None => {
                    return Err(SwapError::InvalidParams(format!(
                        "swap is {}, not accepting a lock",
                        rec.state
                    )))
                }
            }
        }
        // Verification errors are recorded on the swap; the scheduler retries them. If a
        // step already holds the gate, the lock is persisted and the scheduler picks it up:
        // do not make the caller wait out another swap's chain calls.
        if let Ok(g) = self.gate_bounded("notify_lock").await {
            drop(g);
            let _ = self.step(swap_id).await;
        }
        self.view(swap_id)?
            .ok_or_else(|| SwapError::Other("swap vanished".into()))
    }

    /// F3: a new swap's taker leg is the V1 script. A taker (an old client, or a hostile one)
    /// that locked the V0 script for the same parameters is refused here, before anything is
    /// written: the V0 leg accepts a non-32-byte preimage that we could never claim with.
    /// A chain read that fails or times out is not a refusal; the step re-checks the real script.
    async fn refuse_downgraded_lock(&self, rec: &MakerRecord, op: &Outpoint) -> Result<()> {
        if rec.taker_leg_htlc.script_version == ScriptVersion::V0 {
            return Ok(());
        }
        let v0 = HtlcParams {
            script_version: ScriptVersion::V0,
            ..rec.taker_leg_htlc
        };
        let probe = async { self.tk(rec)?.htlc_output(&v0, op).await };
        if let Ok(Ok(Some(_))) = tokio::time::timeout(self.gate_bound, probe).await {
            return Err(SwapError::InvalidParams(
                "taker lock uses the V0 HTLC script; this swap requires the size-checked V1 script"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Current view of one swap.
    pub fn view(&self, swap_id: &str) -> Result<Option<SwapView>> {
        Ok(self.store.get_maker_swap(swap_id)?.as_ref().map(view_of))
    }

    /// All swaps, newest first.
    pub fn list(&self) -> Result<Vec<SwapView>> {
        Ok(self.store.list_maker_swaps()?.iter().map(view_of).collect())
    }

    /// Advance one swap as far as it can go right now. Idempotent; safe after restart.
    pub async fn step(&self, swap_id: &str) -> Result<SwapState> {
        let _g = self.gate.lock().await;
        let mut rec = self.load(swap_id)?;
        if rec.state.is_terminal() {
            return Ok(rec.state);
        }
        let had_error = rec.last_error.take().is_some();
        for _ in 0..MAX_TRANSITIONS_PER_STEP {
            match self.advance(&mut rec).await {
                Ok(Flow::Moved) => {}
                Ok(Flow::Idle | Flow::Halted) => break,
                Err(e) => {
                    rec.last_error = Some(e.to_string());
                    self.store.put_maker_swap(&rec)?;
                    return Err(e);
                }
            }
        }
        if had_error && rec.last_error.is_none() {
            self.store.put_maker_swap(&rec)?;
        }
        Ok(rec.state)
    }

    /// `step` every non-terminal swap; errors are recorded on the swap, not returned.
    /// The daemon's scheduler calls this every few seconds and once at startup.
    pub async fn tick(&self) -> Result<()> {
        for rec in self.store.list_maker_swaps()? {
            if !rec.state.is_terminal() {
                let _ = self.step(&rec.id).await;
            }
        }
        for e in &self.engines {
            let _ = e.tick().await; // errors are recorded on that engine's swaps
        }
        Ok(())
    }

    fn load(&self, swap_id: &str) -> Result<MakerRecord> {
        self.store
            .get_maker_swap(swap_id)?
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown swap {swap_id:?}")))
    }

    /// Persist the transition (and everything else changed on `r`), then honour the
    /// crash hook.
    fn enter(&self, r: &mut MakerRecord, next: SwapState) -> Result<Flow> {
        if !r.state.can_transition_to(next) {
            return Err(SwapError::Other(format!(
                "illegal transition {} -> {next}",
                r.state
            )));
        }
        r.state = next;
        self.store.put_maker_swap(r)?;
        if *self.halt_after.lock() == Some(next) {
            return Ok(Flow::Halted);
        }
        Ok(Flow::Moved)
    }

    fn abort(&self, r: &mut MakerRecord, reason: &str) -> Result<Flow> {
        r.last_error = Some(format!("aborted: {reason}"));
        self.enter(r, SwapState::Aborted)
    }

    async fn advance(&self, r: &mut MakerRecord) -> Result<Flow> {
        match r.state {
            SwapState::Accepted => self.on_accepted(r).await,
            SwapState::TakerLockSeen => self.on_taker_lock_seen(r).await,
            SwapState::TakerLockConfirmed => self.on_taker_lock_confirmed(r).await,
            SwapState::MakerLocked => self.on_maker_locked(r).await,
            SwapState::MakerLockConfirmed => self.on_maker_lock_confirmed(r).await,
            SwapState::MakerRefundable => self.on_maker_refundable(r).await,
            SwapState::TakerClaimed => self.on_taker_claimed(r).await,
            SwapState::MakerClaimed => self.on_maker_claimed(r).await,
            SwapState::MakerRefunded => self.enter(r, SwapState::Done),
            SwapState::Quoted | SwapState::Aborted | SwapState::Done | SwapState::Lost => {
                Ok(Flow::Idle)
            }
        }
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

    /// Backend of the taker leg.
    fn tk(&self, r: &MakerRecord) -> Result<&Arc<dyn ChainBackend>> {
        self.chain(r.quote.taker_chain())
    }

    /// Backend of the maker leg.
    fn mk(&self, r: &MakerRecord) -> Result<&Arc<dyn ChainBackend>> {
        self.chain(r.quote.maker_chain())
    }

    /// Confirmations the taker leg needs before we lock.
    fn taker_leg_confs(&self, r: &MakerRecord) -> u32 {
        self.cfg.confirmations(r.quote.taker_chain())
    }

    /// Confirmations the maker leg needs before we treat it as locked.
    fn maker_leg_confs(&self, r: &MakerRecord) -> u32 {
        self.cfg.confirmations(r.quote.maker_chain())
    }

    /// True when waiting for the taker's lock is pointless: the wall-clock wait is over,
    /// or the taker-leg window left could no longer cover our lock plus the claim margin.
    ///
    /// Decision: the margin here is `maker_timeout + claim_margin`, not the full
    /// `SwapConfig::validate` gap — that gap already budgets taker-leg MTP lag, which
    /// `taker_locktime − taker_chain_mtp_now` (both on the taker-leg clock) measures
    /// directly. Using the full gap would abort every swap that waits even one block for a
    /// confirmation.
    async fn lock_window_gone(&self, r: &MakerRecord) -> Result<bool> {
        if (self.clock)() > r.created_at + self.lock_wait_secs {
            return Ok(true);
        }
        self.taker_window_too_short(r).await
    }

    async fn taker_window_too_short(&self, r: &MakerRecord) -> Result<bool> {
        let mtp = self.tk(r)?.median_time_past().await?;
        let remaining = r.taker_leg_htlc.locktime.saturating_sub(mtp) as u64;
        let needed = r.quote.maker_timeout_secs as u64 + self.cfg.claim_margin_secs as u64;
        Ok(remaining < needed)
    }

    async fn on_accepted(&self, r: &mut MakerRecord) -> Result<Flow> {
        let taker_amount = r.quote.taker_leg_amount();
        let Some(op) = r.taker_leg_outpoint else {
            if self.lock_window_gone(r).await? {
                return self.abort(r, "taker never locked");
            }
            return Ok(Flow::Idle);
        };
        match self.tk(r)?.htlc_output(&r.taker_leg_htlc, &op).await? {
            Some(lo) if lo.amount < taker_amount => self.abort(r, "taker lock underfunded"),
            Some(lo) => {
                r.taker_leg_locked = Some(lo.amount);
                self.enter(r, SwapState::TakerLockSeen)
            }
            None => {
                // Only a confirmed tx is conclusive: Esplora behind a load balancer can know a
                // mempool tx on `/status` while `/tx` still 404s on another backend.
                if self.tk(r)?.confirmations(&op.txid).await?.unwrap_or(0) > 0 {
                    return self.abort(r, "taker lock does not match the HTLC");
                }
                if self.lock_window_gone(r).await? {
                    return self.abort(r, "taker lock never appeared");
                }
                Ok(Flow::Idle)
            }
        }
    }

    async fn on_taker_lock_seen(&self, r: &mut MakerRecord) -> Result<Flow> {
        let taker_amount = r.quote.taker_leg_amount();
        let op = self.taker_leg_outpoint(r)?;
        match self.tk(r)?.htlc_output(&r.taker_leg_htlc, &op).await? {
            Some(lo) if lo.amount < taker_amount => self.abort(r, "taker lock underfunded"),
            Some(lo) if lo.confirmations >= self.taker_leg_confs(r) => {
                r.taker_leg_locked = Some(lo.amount);
                self.enter(r, SwapState::TakerLockConfirmed)
            }
            Some(_) => {
                if self.taker_window_too_short(r).await? {
                    return self.abort(r, "taker-leg window ran out while confirming");
                }
                Ok(Flow::Idle)
            }
            None => {
                // Only a confirmed tx is conclusive: Esplora behind a load balancer can know a
                // mempool tx on `/status` while `/tx` still 404s on another backend.
                if self.tk(r)?.confirmations(&op.txid).await?.unwrap_or(0) > 0 {
                    return self.abort(r, "taker lock does not match the HTLC");
                }
                if self.taker_window_too_short(r).await? {
                    return self.abort(r, "taker lock disappeared and window ran out");
                }
                Ok(Flow::Idle)
            }
        }
    }

    /// The staking edge: the only place the maker selects coins (on the maker-leg chain).
    async fn on_taker_lock_confirmed(&self, r: &mut MakerRecord) -> Result<Flow> {
        let taker_amount = r.quote.taker_leg_amount();
        let op = self.taker_leg_outpoint(r)?;
        match self.tk(r)?.htlc_output(&r.taker_leg_htlc, &op).await? {
            Some(lo)
                if lo.amount >= taker_amount && lo.confirmations >= self.taker_leg_confs(r) => {}
            Some(lo) if lo.amount < taker_amount => return self.abort(r, "taker lock underfunded"),
            Some(_) => return Ok(Flow::Idle), // confirmations dropped (reorg): wait
            None => return self.abort(r, "taker lock vanished"),
        }
        if self.taker_window_too_short(r).await? {
            return self.abort(r, "taker-leg window too short to lock safely");
        }
        let mb = self.mk(r)?.clone();
        let mtp = mb.median_time_past().await?;
        let htlc = HtlcParams {
            hash: r.hash,
            claim_pubkey: r.taker_maker_leg_pubkey,
            refund_pubkey: mb.pubkey(),
            locktime: mtp
                .checked_add(r.quote.maker_timeout_secs)
                .ok_or_else(|| SwapError::InvalidParams("locktime overflow".into()))?,
            // Same script as the taker leg: V1 for a swap accepted now, V0 for one in flight.
            script_version: r.taker_leg_htlc.script_version,
        };
        htlc.validate()?;
        let scan_from = mb.tip_height().await?;
        let funding = mb.build_funding(&htlc, r.quote.maker_leg_amount()).await?;
        r.maker_leg_htlc = Some(htlc);
        r.maker_leg_funding = Some(funding);
        r.maker_leg_scan_from = scan_from;
        r.maker_mtp_at_lock = Some(mtp);
        self.enter(r, SwapState::MakerLocked)
    }

    async fn on_maker_locked(&self, r: &mut MakerRecord) -> Result<Flow> {
        let funding = r
            .maker_leg_funding
            .clone()
            .ok_or_else(|| SwapError::Other("MakerLocked without a funding tx".into()))?;
        // Idempotent: a tx the chain already has is Ok.
        match self.mk(r)?.broadcast(&funding.tx).await {
            Ok(_) => {}
            Err(SwapError::InputsHeld(why)) => {
                if let Some(flow) = self.lost_coin_race(r, &funding, &why).await? {
                    return Ok(flow);
                }
            }
            Err(e) => return Err(e),
        }
        self.mark_lock_sent(r)?;
        let at = self.maker_refund_read(r)?;
        let what = "refund: maker-lock confirmation read";
        let confs = hold::confirmations(self.mk(r)?.as_ref(), &funding.tx.txid, &at, what)
            .await?
            .unwrap_or(0);
        let spent_already = confs >= 1 && self.revealed_preimage(r).await?.is_some();
        if confs >= self.maker_leg_confs(r) || spent_already {
            return self.enter(r, SwapState::MakerLockConfirmed);
        }
        if self.maker_leg_timed_out(r).await? {
            return self.enter(r, SwapState::MakerRefundable);
        }
        Ok(Flow::Idle)
    }

    /// Persist `maker_lock_sent` the first time the funding is known to have left: a
    /// broadcast returned Ok or the node reported the tx.
    fn mark_lock_sent(&self, r: &mut MakerRecord) -> Result<()> {
        if !r.maker_lock_sent {
            r.maker_lock_sent = true;
            self.store.put_maker_swap(r)?;
        }
        Ok(())
    }

    /// The reservation table refused the persisted funding before it was sent: another lock
    /// (a second daemon on the same database) took one of its coins first. When the chain
    /// knows these bytes (sent earlier, before their row went) nothing needs sending: `None`,
    /// and the caller goes on to its confirmation checks. Bytes that were ever sent
    /// (`maker_lock_sent`: e.g. confirmed once, row released, then reorged out and dropped)
    /// can still be mined, so they are kept and never replaced: the lock is reported dropped,
    /// and past its locktime the swap goes to `MakerRefundable`. Otherwise drop the funding
    /// and go back to `TakerLockConfirmed`, whose checks build a new one from other coins
    /// or, past the lock window, abort. The backend has already given the coins back to its
    /// wallet.
    async fn lost_coin_race(
        &self,
        r: &mut MakerRecord,
        funding: &Funding,
        why: &str,
    ) -> Result<Option<Flow>> {
        if self.mk(r)?.confirmations(&funding.tx.txid).await?.is_some() {
            return Ok(None);
        }
        if r.maker_lock_sent {
            if self.maker_leg_timed_out(r).await? {
                return self.enter(r, SwapState::MakerRefundable).map(Some);
            }
            // `step` clears the error each pass; keep reporting it without a new write.
            r.last_error = Some(format!("{MAKER_LOCK_HELD}: {why}"));
            return Ok(Some(Flow::Idle));
        }
        tracing::warn!(swap = %r.id, txid = %funding.tx.txid, "maker lock lost the coin race, unsent: {why}");
        r.maker_leg_htlc = None;
        r.maker_leg_funding = None;
        r.maker_mtp_at_lock = None;
        self.enter(r, SwapState::TakerLockConfirmed).map(Some)
    }

    async fn on_maker_lock_confirmed(&self, r: &mut MakerRecord) -> Result<Flow> {
        if let Some(p) = self.revealed_preimage(r).await? {
            r.preimage = Some(p);
            return self.enter(r, SwapState::TakerClaimed);
        }
        if self.maker_leg_timed_out(r).await? {
            return self.enter(r, SwapState::MakerRefundable);
        }
        self.watch_maker_lock(r).await
    }

    /// F2: a reorg can drop the confirmed maker lock. While it is not `maker_leg_confs` deep,
    /// re-send the persisted signed bytes (never re-sign: the txid is the outpoint the taker
    /// watches). A late lock the taker would refuse to claim is not worth waiting for: go
    /// to `MakerRefundable` early. Runs after the preimage and locktime checks.
    async fn watch_maker_lock(&self, r: &mut MakerRecord) -> Result<Flow> {
        let (htlc, funding) = self.maker_leg(r)?;
        let mk = self.mk(r)?.clone();
        let confs = mk.confirmations(&funding.tx.txid).await?;
        // The node sees the lock again (mempool or chain): it is no longer dropped, so a later
        // drop gets a fresh re-send instead of the stale flag.
        if confs.is_some() && r.maker_lock_dropped {
            r.maker_lock_dropped = false;
            r.last_error = None;
            self.store.put_maker_swap(r)?;
        }
        if confs.is_some_and(|c| c >= self.maker_leg_confs(r)) {
            return Ok(Flow::Idle);
        }
        let remaining = htlc.locktime.saturating_sub(mk.median_time_past().await?);
        if remaining < self.cfg.claim_margin_secs {
            return self.enter(r, SwapState::MakerRefundable);
        }
        if r.maker_lock_dropped {
            // `step` clears the error each pass; keep reporting it without a new write.
            r.last_error = Some(MAKER_LOCK_DROPPED.into());
            return Ok(Flow::Idle);
        }
        match mk.broadcast(&funding.tx).await {
            Ok(_) => {}
            Err(SwapError::Rejected(why) | SwapError::InputsHeld(why)) => {
                r.maker_lock_dropped = true;
                r.last_error = Some(format!("{MAKER_LOCK_DROPPED}: {why}"));
                self.store.put_maker_swap(r)?;
            }
            Err(e) => return Err(e),
        }
        Ok(Flow::Idle)
    }

    async fn on_maker_refundable(&self, r: &mut MakerRecord) -> Result<Flow> {
        // A late claim still wins until our refund is on chain.
        if let Some(p) = self.revealed_preimage(r).await? {
            r.preimage = Some(p);
            return self.enter(r, SwapState::TakerClaimed);
        }
        // Entered early (a late lock, `watch_maker_lock`) or not: never send a refund the
        // node must refuse as non-final.
        if !self.maker_leg_timed_out(r).await? {
            return Ok(Flow::Idle);
        }
        let (htlc, funding) = self.maker_leg(r)?;
        let refund = match r.maker_leg_refund.clone() {
            Some(tx) => tx,
            None => {
                let mk = self.mk(r)?.clone();
                let margin = ClaimDeadline::builtin(mk.chain()).margin_secs();
                let tx = hold::build_refund(
                    mk.as_ref(),
                    &htlc,
                    &funding.outpoint,
                    funding.amount,
                    margin,
                    &r.id,
                    &mut r.last_error,
                )
                .await?;
                r.maker_leg_refund = Some(tx.clone());
                self.store.put_maker_swap(r)?; // write-ahead
                tx
            }
        };
        match self.mk(r)?.broadcast(&refund).await {
            Ok(_) => {}
            Err(SwapError::Premature(_)) => return Ok(Flow::Idle),
            Err(e @ SwapError::Rejected(_)) => {
                // Refused for good: re-sign on the next step rather than resend dead bytes.
                r.maker_leg_refund = None;
                self.store.put_maker_swap(r)?;
                // The refund spends the lock, so the chain refusing it while it does not know
                // the lock at all means the lock is gone: hand its wallet bookkeeping back.
                // Never on a mere "not seen" refund error; the backend still wants its own proof.
                self.release_dead_lock(r, &funding.tx).await;
                return Err(e);
            }
            Err(e) => return Err(e),
        }
        let at = self.maker_refund_read(r)?;
        let mk = self.mk(r)?;
        let confs =
            hold::confirmations(mk.as_ref(), &refund.txid, &at, "refund: confirmation read")
                .await?;
        if confs.is_some_and(|c| c >= 1) {
            return self.enter(r, SwapState::MakerRefunded);
        }
        Ok(Flow::Idle)
    }

    /// Best effort: a lock the node does not know after a refund rejection is released from
    /// the maker's wallet bookkeeping (no-op on chains without it). Any failure is logged and
    /// leaves everything held.
    async fn release_dead_lock(&self, r: &MakerRecord, lock: &SignedTx) {
        let Ok(mk) = self.mk(r) else { return };
        if !matches!(mk.confirmations(&lock.txid).await, Ok(None)) {
            return;
        }
        match mk.release_dead_lock(lock).await {
            Ok(true) => {
                tracing::warn!(txid = %lock.txid, "released the wallet booking of a lost maker lock")
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(txid = %lock.txid, "lost maker lock not released: {e}"),
        }
    }

    /// The taker-leg claim, for the shared escalation ([`crate::claim_fee`]).
    fn claim_ctx(&self, r: &MakerRecord) -> Result<ClaimCtx<'_>> {
        let chain = r.quote.taker_chain();
        let preimage = r
            .preimage
            .ok_or_else(|| SwapError::Other("claiming without a preimage".into()))?;
        let amount = r
            .taker_leg_locked
            .ok_or_else(|| SwapError::Other("no verified taker-leg amount".into()))?;
        Ok(ClaimCtx {
            chain,
            backend: self.tk(r)?.as_ref(),
            escalation: self.fee_escalation(chain),
            window: ClaimDeadline::builtin(chain).margin_secs(),
            htlc: r.taker_leg_htlc,
            op: self.taker_leg_outpoint(r)?,
            amount,
            preimage,
            store: &self.store,
        })
    }

    async fn on_taker_claimed(&self, r: &mut MakerRecord) -> Result<Flow> {
        let ctx = self.claim_ctx(r)?;
        let claim = match r.taker_leg_claim.clone() {
            Some(tx) => tx,
            None => {
                // The taker's claim revealed the preimage: a hold ends at the margin.
                let tx = ctx.sign_public(r).await?;
                self.store.put_maker_swap(r)?; // write-ahead
                tx
            }
        };
        if let Err(e) = ctx.backend.broadcast(&claim).await {
            if matches!(e, SwapError::Rejected(_)) {
                match self.claim_refused(&ctx, r, &claim, &e).await? {
                    Refused::Resent => return self.enter(r, SwapState::MakerClaimed),
                    Refused::Lost => return self.enter(r, SwapState::Lost),
                    Refused::NotResent => {}
                }
            }
            return Err(e);
        }
        self.enter(r, SwapState::MakerClaimed)
    }

    /// Until the taker-leg claim confirms: resend it (and its CPFP children), and raise its
    /// fee along the chain's [`FeeEscalation`] as the taker-leg locktime nears. The taker
    /// revealed the preimage as late as its own claim deadline allowed, so the claim may
    /// have little more than `claim_margin_secs` to confirm before the taker's refund can
    /// take the leg back, with the maker leg already gone.
    async fn on_maker_claimed(&self, r: &mut MakerRecord) -> Result<Flow> {
        let ctx = self.claim_ctx(r)?;
        let claim = match r.taker_leg_claim.clone() {
            Some(tx) => tx,
            None => {
                // Forgotten after a refusal: re-sign from the persisted preimage.
                let tx = ctx.sign_public(r).await?;
                self.store.put_maker_swap(r)?; // write-ahead
                tx
            }
        };
        if ctx
            .backend
            .confirmations(&claim.txid)
            .await?
            .is_some_and(|c| c >= 1)
            || ctx.replaced_confirmed(r).await?
        {
            return self.enter(r, SwapState::Done);
        }
        if let Err(e) = ctx.backend.broadcast(&claim).await {
            if matches!(e, SwapError::Rejected(_)) {
                match self.claim_refused(&ctx, r, &claim, &e).await? {
                    Refused::Resent => return Ok(Flow::Idle),
                    Refused::Lost => return self.enter(r, SwapState::Lost),
                    Refused::NotResent => {}
                }
            }
            return Err(e);
        }
        ctx.resend_children(r).await?;
        ctx.escalate(r, &claim).await?;
        Ok(Flow::Idle)
    }

    /// The node refused `claim`, the newest taker-leg claim, for good. `Resent` if it was
    /// re-signed higher and sent ([`ClaimCtx::resign_after_refusal`]). Nothing is re-signed
    /// while the chain holds it or a version it replaced (`NotResent`), or once the taker's
    /// refund of the taker leg has confirmed: that leg is gone. A refund with fewer
    /// confirmations than the quote asks for on that chain is an error on every step (a
    /// reorg may still drop it); once it is that deep the loss is recorded on the swap
    /// (`Lost`, with `last_error` naming the refund) and the claim is forgotten.
    async fn claim_refused(
        &self,
        ctx: &ClaimCtx<'_>,
        r: &mut MakerRecord,
        claim: &SignedTx,
        e: &SwapError,
    ) -> Result<Refused> {
        if ctx.held_after_refusal(r, claim, e).await? {
            return Ok(Refused::NotResent);
        }
        if let Some((refund, deep)) = self.taker_leg_refund(r).await? {
            if !deep {
                tracing::error!(swap = %r.id, chain = %ctx.chain, refund = %refund.txid,
                    error = %e, "the taker refunded the taker leg before the claim confirmed");
                return Err(SwapError::Other(format!(
                    "taker leg refunded by {} before the claim confirmed ({e}); the leg is lost",
                    refund.txid
                )));
            }
            tracing::error!(
                swap = %r.id,
                chain = %ctx.chain,
                taker_leg = ?r.taker_leg_outpoint,
                maker_leg = ?r.maker_leg_funding.as_ref().map(|f| f.outpoint),
                refund = %refund.txid,
                claim = %claim.txid,
                error = %e,
                "swap lost: the taker refunded the taker leg before our claim confirmed and \
                 already has the maker leg; nothing is left to claim"
            );
            r.last_error = Some(format!(
                "lost: the taker leg was refunded by {} before our claim {} confirmed ({e})",
                refund.txid, claim.txid
            ));
            r.taker_leg_claim = None;
            return Ok(Refused::Lost);
        }
        Ok(if ctx.resign_after_refusal(r, claim, e).await? {
            Refused::Resent
        } else {
            Refused::NotResent
        })
    }

    /// A confirmed spend of the taker-leg lock that carries no preimage (the taker's
    /// refund), and whether it is as deep as the quote's confirmations on that chain.
    async fn taker_leg_refund(&self, r: &MakerRecord) -> Result<Option<(SpendInfo, bool)>> {
        let Some(op) = r.taker_leg_outpoint else {
            return Ok(None);
        };
        let tb = self.tk(r)?;
        // No spend predates the lock's own block.
        let Some(confs) = tb.confirmations(&op.txid).await?.filter(|&c| c >= 1) else {
            return Ok(None);
        };
        let tip = tb.tip_height().await?;
        let Some(spend) = tb
            .find_spend(&op, (tip + 1).saturating_sub(confs as u64))
            .await?
        else {
            return Ok(None);
        };
        let Some(height) = spend.height else {
            return Ok(None);
        };
        if spend.extract_preimage(&r.hash).is_some() {
            return Ok(None);
        }
        let need = r.quote.confirmations_on(r.quote.taker_chain()) as u64;
        let deep = (tip + 1).saturating_sub(height) >= need;
        Ok(Some((spend, deep)))
    }

    fn taker_leg_outpoint(&self, r: &MakerRecord) -> Result<Outpoint> {
        r.taker_leg_outpoint
            .ok_or_else(|| SwapError::Other("no taker lock reported".into()))
    }

    fn maker_leg(&self, r: &MakerRecord) -> Result<(HtlcParams, crate::types::Funding)> {
        match (&r.maker_leg_htlc, &r.maker_leg_funding) {
            (Some(h), Some(f)) => Ok((*h, f.clone())),
            _ => Err(SwapError::Other("maker lock not built".into())),
        }
    }

    async fn maker_leg_timed_out(&self, r: &MakerRecord) -> Result<bool> {
        let (htlc, _) = self.maker_leg(r)?;
        let mk = self.mk(r)?;
        let at = self.maker_refund_read(r)?;
        let mtp = hold::median_time_past(mk.as_ref(), &at, "refund: maker-leg MTP read").await?;
        Ok(mk.refund_final(mtp, htlc.locktime))
    }

    /// The deadline of a read in front of the maker-leg refund: a hold for the second
    /// source ends one claim margin after the maker-leg locktime.
    fn maker_refund_read<'a>(&self, r: &'a MakerRecord) -> Result<hold::RefundRead<'a>> {
        let (htlc, _) = self.maker_leg(r)?;
        let margin = ClaimDeadline::builtin(self.mk(r)?.chain()).margin_secs();
        Ok(hold::RefundRead {
            deadline: hold::refund_deadline(htlc.locktime, margin),
            locktime: htlc.locktime,
            swap: &r.id,
        })
    }

    /// The preimage, if a transaction other than our own refund spent the maker-leg lock. Our
    /// refund waits on this read, so a read held by the second source is read on the primary
    /// alone one claim margin after the locktime ([`hold::find_spend`]).
    async fn revealed_preimage(&self, r: &mut MakerRecord) -> Result<Option<[u8; 32]>> {
        let (htlc, funding) = self.maker_leg(r)?;
        let mk = self.mk(r)?.clone();
        let margin = ClaimDeadline::builtin(mk.chain()).margin_secs();
        let Some(spend) = hold::find_spend(
            mk.as_ref(),
            &funding.outpoint,
            r.maker_leg_scan_from,
            htlc.locktime,
            margin,
            &r.id,
            &mut r.last_error,
        )
        .await?
        else {
            return Ok(None);
        };
        if r.maker_leg_refund
            .as_ref()
            .is_some_and(|t| t.txid == spend.txid)
        {
            return Ok(None);
        }
        Ok(spend.extract_preimage(&r.hash))
    }
}

/// What became of a taker-leg claim the node refused for good ([`Maker::claim_refused`]).
enum Refused {
    /// Re-signed at a higher fee and sent.
    Resent,
    /// Not re-signed: the chain holds it or a version it replaced, or it cannot be bumped.
    NotResent,
    /// The taker's refund of the taker leg is buried: the swap is lost.
    Lost,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn view_of(r: &MakerRecord) -> SwapView {
    SwapView {
        id: r.id.clone(),
        state: r.state,
        quote: r.quote.clone(),
        taker_leg: LegView {
            htlc: r.taker_leg_htlc,
            amount: r.quote.taker_leg_amount(),
            outpoint: r.taker_leg_outpoint,
            spend_txid: r.taker_leg_claim.as_ref().map(|t| t.txid),
        },
        maker_leg: match (&r.maker_leg_htlc, &r.maker_leg_funding) {
            (Some(h), Some(f)) => Some(LegView {
                htlc: *h,
                amount: f.amount,
                outpoint: Some(f.outpoint),
                spend_txid: r.maker_leg_refund.as_ref().map(|t| t.txid),
            }),
            _ => None,
        },
        preimage: r.preimage.map(hex::encode),
        last_error: r.last_error.clone(),
        maker_mtp_at_lock: r.maker_mtp_at_lock,
    }
}
