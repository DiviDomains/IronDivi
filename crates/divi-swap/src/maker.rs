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
//! Direction. The offer's [`Direction`] fixes which chain each leg is on: the taker leg on
//! `taker_chain()`, the maker leg on `maker_chain()`. Everything below is written in those
//! roles; the forward direction (taker pays BTC) is just one assignment.

use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::{AcceptRequest, LegView, LockNotice, Offer, Quote, SwapView};
use crate::backend::ChainBackend;
use crate::config::SwapConfig;
use crate::error::{Result, SwapError};
use crate::htlc::HtlcParams;
use crate::state::SwapState;
use crate::store::{MakerRecord, QuoteRecord, Store};
use crate::types::{Amount, Chain, Outpoint};

/// Default wall-clock time the maker waits for the taker's BTC lock after `accept`.
pub const DEFAULT_LOCK_WAIT_SECS: u64 = 1800;

/// Upper bound on transitions one `step` call performs (a swap has far fewer).
const MAX_TRANSITIONS_PER_STEP: usize = 32;

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
/// Every transition — and every signed transaction — is persisted before the side effect it
/// precedes (write-ahead), so [`Maker::step`] can be re-run after a crash at any point.
pub struct Maker {
    cfg: SwapConfig,
    divi: Arc<dyn ChainBackend>,
    btc: Arc<dyn ChainBackend>,
    store: Store,
    offers: Vec<Offer>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    lock_wait_secs: u64,
    halt_after: Mutex<Option<SwapState>>,
    gate: tokio::sync::Mutex<()>,
}

impl Maker {
    /// New engine. Fails if `cfg` violates the timeout invariant.
    pub fn new(
        cfg: SwapConfig,
        divi: Arc<dyn ChainBackend>,
        btc: Arc<dyn ChainBackend>,
        store: Store,
        offers: Vec<Offer>,
    ) -> Result<Self> {
        cfg.validate()?;
        Ok(Maker {
            cfg,
            divi,
            btc,
            store,
            offers,
            clock: Arc::new(unix_now),
            lock_wait_secs: DEFAULT_LOCK_WAIT_SECS,
            halt_after: Mutex::new(None),
            gate: tokio::sync::Mutex::new(()),
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

    /// Standing offers.
    pub fn offers(&self) -> Vec<Offer> {
        self.offers.clone()
    }

    /// Issue a quote valid for `cfg.quote_expiry_secs`. No coins are reserved.
    pub async fn quote(&self, offer_id: &str, btc_sats: u64) -> Result<Quote> {
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
        let divi_amount = offer.divi_for(btc_sats);
        if divi_amount.0 == 0 {
            return Err(SwapError::InvalidParams("swap is worth no DIVI".into()));
        }
        let quote = Quote {
            id: uuid::Uuid::new_v4().to_string(),
            offer_id: offer.id.clone(),
            direction: offer.direction,
            btc_amount: crate::types::Amount(btc_sats),
            divi_amount,
            expires_at: (self.clock)() + self.cfg.quote_expiry_secs as u64,
            maker_btc_pubkey: self.btc.pubkey(),
            maker_divi_pubkey: self.divi.pubkey(),
            taker_timeout_secs: self.cfg.taker_timeout_secs,
            maker_timeout_secs: self.cfg.maker_timeout_secs,
            btc_confirmations: self.cfg.btc_confirmations,
            divi_confirmations: self.cfg.divi_confirmations,
        };
        self.store.put_quote(&QuoteRecord {
            quote: quote.clone(),
            used: false,
        })?;
        Ok(quote)
    }

    /// Accept an unexpired quote: fixes the taker-leg HTLC the taker must fund.
    pub async fn accept(&self, req: AcceptRequest) -> Result<SwapView> {
        let mut qr = self
            .store
            .get_quote(&req.quote_id)?
            .ok_or_else(|| SwapError::InvalidParams("unknown quote".into()))?;
        if qr.used {
            return Err(SwapError::InvalidParams("quote already used".into()));
        }
        let now = (self.clock)();
        if now > qr.quote.expires_at {
            return Err(SwapError::InvalidParams("quote expired".into()));
        }
        if self
            .store
            .list_maker_swaps()?
            .iter()
            .any(|s| s.hash == req.hash)
        {
            return Err(SwapError::InvalidParams("hash already in use".into()));
        }
        let dir = qr.quote.direction;
        let (tc, mc) = (dir.taker_chain(), dir.maker_chain());
        let tmtp = self.chain(tc).median_time_past().await?;
        let locktime = tmtp
            .checked_add(qr.quote.taker_timeout_secs)
            .ok_or_else(|| SwapError::InvalidParams("locktime overflow".into()))?;
        let taker_leg_htlc = HtlcParams {
            hash: req.hash,
            claim_pubkey: maker_key(&qr.quote, tc),
            refund_pubkey: taker_key(&req, tc),
            locktime,
        };
        taker_leg_htlc.validate()?;
        // The maker leg is built later, on its own chain's clock; check the keys now.
        HtlcParams {
            hash: req.hash,
            claim_pubkey: taker_key(&req, mc),
            refund_pubkey: maker_key(&qr.quote, mc),
            locktime,
        }
        .validate()?;

        let rec = MakerRecord {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: now,
            state: SwapState::Accepted,
            quote: qr.quote.clone(),
            hash: req.hash,
            taker_maker_leg_pubkey: taker_key(&req, mc),
            taker_leg_htlc,
            taker_leg_outpoint: None,
            taker_leg_locked: None,
            maker_leg_htlc: None,
            maker_leg_funding: None,
            maker_leg_scan_from: 0,
            maker_leg_refund: None,
            preimage: None,
            taker_leg_claim: None,
            last_error: None,
        };
        qr.used = true;
        self.store.put_quote(&qr)?;
        self.store.put_maker_swap(&rec)?;
        Ok(view_of(&rec))
    }

    /// The taker says it funded the taker-leg HTLC at `lock.outpoint`.
    pub async fn notify_lock(&self, swap_id: &str, lock: LockNotice) -> Result<SwapView> {
        {
            let _g = self.gate.lock().await;
            let mut rec = self.load(swap_id)?;
            match rec.taker_leg_outpoint {
                Some(op) if op == lock.outpoint => {}
                Some(_) => {
                    return Err(SwapError::InvalidParams(
                        "a different lock was already reported".into(),
                    ))
                }
                None if rec.state == SwapState::Accepted => {
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
        // Verification errors are recorded on the swap; the scheduler retries them.
        let _ = self.step(swap_id).await;
        self.view(swap_id)?
            .ok_or_else(|| SwapError::Other("swap vanished".into()))
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
            SwapState::Quoted | SwapState::Aborted | SwapState::Done => Ok(Flow::Idle),
        }
    }

    /// Backend for `c`.
    fn chain(&self, c: Chain) -> &Arc<dyn ChainBackend> {
        match c {
            Chain::Btc => &self.btc,
            Chain::Divi => &self.divi,
        }
    }

    /// Backend of the taker leg.
    fn tk(&self, r: &MakerRecord) -> &Arc<dyn ChainBackend> {
        self.chain(r.quote.direction.taker_chain())
    }

    /// Backend of the maker leg.
    fn mk(&self, r: &MakerRecord) -> &Arc<dyn ChainBackend> {
        self.chain(r.quote.direction.maker_chain())
    }

    /// Confirmations the taker leg needs before we lock.
    fn taker_leg_confs(&self, r: &MakerRecord) -> u32 {
        match r.quote.direction.taker_chain() {
            Chain::Btc => self.cfg.btc_confirmations,
            Chain::Divi => self.cfg.divi_confirmations,
        }
    }

    /// Confirmations the maker leg needs before we treat it as locked.
    fn maker_leg_confs(&self, r: &MakerRecord) -> u32 {
        match r.quote.direction.maker_chain() {
            Chain::Btc => self.cfg.btc_confirmations,
            Chain::Divi => self.cfg.divi_confirmations,
        }
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
        let mtp = self.tk(r).median_time_past().await?;
        let remaining = r.taker_leg_htlc.locktime.saturating_sub(mtp) as u64;
        let needed = r.quote.maker_timeout_secs as u64 + self.cfg.claim_margin_secs as u64;
        Ok(remaining < needed)
    }

    async fn on_accepted(&self, r: &mut MakerRecord) -> Result<Flow> {
        let taker_amount = taker_leg_amount(&r.quote);
        let Some(op) = r.taker_leg_outpoint else {
            if self.lock_window_gone(r).await? {
                return self.abort(r, "taker never locked");
            }
            return Ok(Flow::Idle);
        };
        match self.tk(r).htlc_output(&r.taker_leg_htlc, &op).await? {
            Some(lo) if lo.amount < taker_amount => self.abort(r, "taker lock underfunded"),
            Some(lo) => {
                r.taker_leg_locked = Some(lo.amount);
                self.enter(r, SwapState::TakerLockSeen)
            }
            None => {
                // Only a confirmed tx is conclusive: Esplora behind a load balancer can know a
                // mempool tx on `/status` while `/tx` still 404s on another backend.
                if self.tk(r).confirmations(&op.txid).await?.unwrap_or(0) > 0 {
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
        let taker_amount = taker_leg_amount(&r.quote);
        let op = self.taker_leg_outpoint(r)?;
        match self.tk(r).htlc_output(&r.taker_leg_htlc, &op).await? {
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
                if self.tk(r).confirmations(&op.txid).await?.unwrap_or(0) > 0 {
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
        let taker_amount = taker_leg_amount(&r.quote);
        let op = self.taker_leg_outpoint(r)?;
        match self.tk(r).htlc_output(&r.taker_leg_htlc, &op).await? {
            Some(lo)
                if lo.amount >= taker_amount && lo.confirmations >= self.taker_leg_confs(r) => {}
            Some(lo) if lo.amount < taker_amount => return self.abort(r, "taker lock underfunded"),
            Some(_) => return Ok(Flow::Idle), // confirmations dropped (reorg): wait
            None => return self.abort(r, "taker lock vanished"),
        }
        if self.taker_window_too_short(r).await? {
            return self.abort(r, "taker-leg window too short to lock safely");
        }
        let mb = self.mk(r).clone();
        let mtp = mb.median_time_past().await?;
        let htlc = HtlcParams {
            hash: r.hash,
            claim_pubkey: r.taker_maker_leg_pubkey,
            refund_pubkey: mb.pubkey(),
            locktime: mtp
                .checked_add(r.quote.maker_timeout_secs)
                .ok_or_else(|| SwapError::InvalidParams("locktime overflow".into()))?,
        };
        htlc.validate()?;
        let scan_from = mb.tip_height().await?;
        let funding = mb.build_funding(&htlc, maker_leg_amount(&r.quote)).await?;
        r.maker_leg_htlc = Some(htlc);
        r.maker_leg_funding = Some(funding);
        r.maker_leg_scan_from = scan_from;
        self.enter(r, SwapState::MakerLocked)
    }

    async fn on_maker_locked(&self, r: &mut MakerRecord) -> Result<Flow> {
        let funding = r
            .maker_leg_funding
            .clone()
            .ok_or_else(|| SwapError::Other("MakerLocked without a funding tx".into()))?;
        // Idempotent: a tx the chain already has is Ok.
        self.mk(r).broadcast(&funding.tx).await?;
        let confs = self
            .mk(r)
            .confirmations(&funding.tx.txid)
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

    async fn on_maker_lock_confirmed(&self, r: &mut MakerRecord) -> Result<Flow> {
        if let Some(p) = self.revealed_preimage(r).await? {
            r.preimage = Some(p);
            return self.enter(r, SwapState::TakerClaimed);
        }
        if self.maker_leg_timed_out(r).await? {
            return self.enter(r, SwapState::MakerRefundable);
        }
        Ok(Flow::Idle)
    }

    async fn on_maker_refundable(&self, r: &mut MakerRecord) -> Result<Flow> {
        // A late claim still wins until our refund is on chain.
        if let Some(p) = self.revealed_preimage(r).await? {
            r.preimage = Some(p);
            return self.enter(r, SwapState::TakerClaimed);
        }
        let (htlc, funding) = self.maker_leg(r)?;
        let refund = match r.maker_leg_refund.clone() {
            Some(tx) => tx,
            None => {
                let tx = self
                    .mk(r)
                    .build_refund(&htlc, &funding.outpoint, funding.amount)
                    .await?;
                r.maker_leg_refund = Some(tx.clone());
                self.store.put_maker_swap(r)?; // write-ahead
                tx
            }
        };
        match self.mk(r).broadcast(&refund).await {
            Ok(_) => {}
            Err(SwapError::Premature(_)) => return Ok(Flow::Idle),
            Err(e) => return Err(e),
        }
        if self
            .mk(r)
            .confirmations(&refund.txid)
            .await?
            .is_some_and(|c| c >= 1)
        {
            return self.enter(r, SwapState::MakerRefunded);
        }
        Ok(Flow::Idle)
    }

    async fn on_taker_claimed(&self, r: &mut MakerRecord) -> Result<Flow> {
        let preimage = r
            .preimage
            .ok_or_else(|| SwapError::Other("TakerClaimed without a preimage".into()))?;
        let claim = match r.taker_leg_claim.clone() {
            Some(tx) => tx,
            None => {
                let op = self.taker_leg_outpoint(r)?;
                let amount = r
                    .taker_leg_locked
                    .ok_or_else(|| SwapError::Other("no verified taker-leg amount".into()))?;
                let tx = self
                    .tk(r)
                    .build_claim(&r.taker_leg_htlc, &op, amount, &preimage)
                    .await?;
                r.taker_leg_claim = Some(tx.clone());
                self.store.put_maker_swap(r)?; // write-ahead
                tx
            }
        };
        self.tk(r).broadcast(&claim).await?;
        self.enter(r, SwapState::MakerClaimed)
    }

    async fn on_maker_claimed(&self, r: &mut MakerRecord) -> Result<Flow> {
        let claim = r
            .taker_leg_claim
            .clone()
            .ok_or_else(|| SwapError::Other("MakerClaimed without a claim tx".into()))?;
        match self.tk(r).confirmations(&claim.txid).await? {
            Some(c) if c >= 1 => self.enter(r, SwapState::Done),
            _ => {
                // Dropped from the mempool? Rebroadcasting identical bytes is harmless.
                self.tk(r).broadcast(&claim).await?;
                Ok(Flow::Idle)
            }
        }
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
        Ok(self.mk(r).median_time_past().await? >= htlc.locktime)
    }

    /// The preimage, if a transaction other than our own refund spent the maker-leg lock.
    async fn revealed_preimage(&self, r: &MakerRecord) -> Result<Option<[u8; 32]>> {
        let (_, funding) = self.maker_leg(r)?;
        let Some(spend) = self
            .mk(r)
            .find_spend(&funding.outpoint, r.maker_leg_scan_from)
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Value the taker locks.
fn taker_leg_amount(q: &Quote) -> Amount {
    match q.direction.taker_chain() {
        Chain::Btc => q.btc_amount,
        Chain::Divi => q.divi_amount,
    }
}

/// Value the maker locks.
fn maker_leg_amount(q: &Quote) -> Amount {
    match q.direction.maker_chain() {
        Chain::Btc => q.btc_amount,
        Chain::Divi => q.divi_amount,
    }
}

fn maker_key(q: &Quote, c: Chain) -> [u8; 33] {
    match c {
        Chain::Btc => q.maker_btc_pubkey,
        Chain::Divi => q.maker_divi_pubkey,
    }
}

fn taker_key(req: &AcceptRequest, c: Chain) -> [u8; 33] {
    match c {
        Chain::Btc => req.taker_btc_pubkey,
        Chain::Divi => req.taker_divi_pubkey,
    }
}

fn view_of(r: &MakerRecord) -> SwapView {
    SwapView {
        id: r.id.clone(),
        state: r.state,
        quote: r.quote.clone(),
        taker_leg: LegView {
            htlc: r.taker_leg_htlc,
            amount: taker_leg_amount(&r.quote),
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
    }
}
