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
//! `quote.direction.taker_chain()`, the maker leg (we claim) on `maker_chain()`.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::{AcceptRequest, LockNotice, Quote, SwapView};
use crate::backend::ChainBackend;
use crate::error::{Result, SwapError};
use crate::htlc::{new_preimage, HtlcParams};
use crate::store::{Store, TakerRecord};
use crate::types::{Amount, Chain};

/// The taker stops claiming the maker leg this many seconds before the maker's locktime: a claim
/// that confirms after the maker refunds would lose the DIVI while revealing the preimage.
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
    /// Maker's lock verified (amount, script) and confirmed.
    MakerLockConfirmed,
    /// Maker-leg claim broadcast (preimage revealed).
    Claimed,
    /// Taker leg refunded after the taker timeout.
    Refunded,
    /// Finished.
    Done,
}

/// Taker engine. `divi` holds the taker's DIVI key, `btc` the taker's BTC key.
pub struct Taker {
    divi: Arc<dyn ChainBackend>,
    btc: Arc<dyn ChainBackend>,
    store: Store,
    halt_after: Mutex<Option<TakerState>>,
    gate: tokio::sync::Mutex<()>,
}

impl Taker {
    /// New taker engine.
    pub fn new(divi: Arc<dyn ChainBackend>, btc: Arc<dyn ChainBackend>, store: Store) -> Self {
        Taker {
            divi,
            btc,
            store,
            halt_after: Mutex::new(None),
            gate: tokio::sync::Mutex::new(()),
        }
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
        let (preimage, hash) = new_preimage();
        let req = AcceptRequest {
            quote_id: quote.id.clone(),
            hash,
            taker_btc_pubkey: self.btc.pubkey(),
            taker_divi_pubkey: self.divi.pubkey(),
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
        let dir = r.quote.direction;
        let tb = self.chain(dir.taker_chain());
        if h.hash != r.hash {
            return Err(bad("wrong hash"));
        }
        if h.refund_pubkey != tb.pubkey() {
            return Err(bad("refund key is not ours"));
        }
        if h.claim_pubkey != maker_key(&r.quote, dir.taker_chain()) {
            return Err(bad("claim key is not the quote's maker key"));
        }
        if maker.quote.id != r.quote.id
            || maker.quote.btc_amount != r.quote.btc_amount
            || maker.quote.divi_amount != r.quote.divi_amount
            || maker.quote.direction != dir
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
                    .tk(&r)
                    .build_funding(&htlc, taker_leg_amount(&r.quote))
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
        self.tk(&r).broadcast(&funding.tx).await?;
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
        if r.state == TakerState::Done {
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

    fn load(&self, id: &str) -> Result<TakerRecord> {
        self.store
            .get_taker_swap(id)?
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown swap {id:?}")))
    }

    fn chain(&self, c: Chain) -> &Arc<dyn ChainBackend> {
        match c {
            Chain::Btc => &self.btc,
            Chain::Divi => &self.divi,
        }
    }

    /// Backend of the taker leg (where we lock).
    fn tk(&self, r: &TakerRecord) -> &Arc<dyn ChainBackend> {
        self.chain(r.quote.direction.taker_chain())
    }

    /// Backend of the maker leg (where we claim).
    fn mk(&self, r: &TakerRecord) -> &Arc<dyn ChainBackend> {
        self.chain(r.quote.direction.maker_chain())
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
            TakerState::Prepared | TakerState::Accepted | TakerState::Done => Ok(Flow::Idle),
            TakerState::Locked => self.on_locked(r, maker).await,
            TakerState::MakerLockConfirmed => self.on_maker_lock_confirmed(r).await,
            TakerState::Claimed => self.on_claimed(r).await,
            TakerState::Refunded => self.on_refunded(r).await,
        }
    }

    async fn taker_leg_refundable(&self, r: &TakerRecord) -> Result<bool> {
        Ok(self.tk(r).median_time_past().await? >= self.taker_leg_htlc(r)?.locktime)
    }

    async fn on_locked(&self, r: &mut TakerRecord, maker: Option<&SwapView>) -> Result<Flow> {
        if let Some(f) = &r.taker_leg_funding {
            self.tk(r).broadcast(&f.tx).await?; // idempotent; recovers a crash before broadcast
        }
        if self.taker_leg_refundable(r).await? {
            return self.enter(r, TakerState::Refunded);
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
        let dir = r.quote.direction;
        let mb = self.mk(r).clone();
        if htlc.hash != r.hash {
            return Err(bad("wrong hash"));
        }
        if htlc.claim_pubkey != mb.pubkey() {
            return Err(bad("claim key is not ours"));
        }
        if htlc.refund_pubkey != maker_key(&r.quote, dir.maker_chain()) {
            return Err(bad("refund key is not the quote's maker key"));
        }
        // Trust the chain, not the maker's view, for amount and confirmations.
        let Some(lo) = mb.htlc_output(&htlc, &op).await? else {
            return Ok(Flow::Idle);
        };
        if lo.amount < maker_leg_amount(&r.quote) {
            return Err(bad("underfunded"));
        }
        if lo.confirmations < maker_leg_confs(&r.quote) {
            return Ok(Flow::Idle);
        }
        let mtp = mb.median_time_past().await?;
        if (htlc.locktime as u64) < mtp as u64 + TAKER_SAFETY_MARGIN_SECS as u64 {
            return Err(bad("locktime too close to claim safely"));
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
        let mtp = self.mk(r).median_time_past().await?;
        if (mtp as u64) + TAKER_SAFETY_MARGIN_SECS as u64 <= htlc.locktime as u64 {
            let op = r.maker_leg_outpoint.expect("set with maker_leg_htlc");
            let amount = r.maker_leg_amount.expect("set with maker_leg_htlc");
            let claim = self
                .mk(r)
                .build_claim(&htlc, &op, amount, &r.preimage)
                .await?;
            r.maker_leg_claim = Some(claim);
            // Persist the signed claim (which reveals the preimage) before broadcasting it.
            return self.enter(r, TakerState::Claimed);
        }
        // Too late to claim safely: wait out our own taker-leg timelock.
        if self.taker_leg_refundable(r).await? {
            return self.enter(r, TakerState::Refunded);
        }
        Ok(Flow::Idle)
    }

    async fn on_claimed(&self, r: &mut TakerRecord) -> Result<Flow> {
        let claim = r
            .maker_leg_claim
            .clone()
            .ok_or_else(|| SwapError::Other("Claimed without a claim tx".into()))?;
        self.mk(r).broadcast(&claim).await?;
        if self
            .mk(r)
            .confirmations(&claim.txid)
            .await?
            .is_some_and(|c| c >= 1)
        {
            return self.enter(r, TakerState::Done);
        }
        Ok(Flow::Idle)
    }

    async fn on_refunded(&self, r: &mut TakerRecord) -> Result<Flow> {
        let refund = match r.taker_leg_refund.clone() {
            Some(tx) => tx,
            None => {
                let htlc = self.taker_leg_htlc(r)?;
                let f = r
                    .taker_leg_funding
                    .clone()
                    .ok_or_else(|| SwapError::Other("Refunded without a funding tx".into()))?;
                let tx = self
                    .tk(r)
                    .build_refund(&htlc, &f.outpoint, f.amount)
                    .await?;
                r.taker_leg_refund = Some(tx.clone());
                self.store.put_taker_swap(r)?; // write-ahead
                tx
            }
        };
        match self.tk(r).broadcast(&refund).await {
            Ok(_) => {}
            Err(SwapError::Premature(_)) => return Ok(Flow::Idle),
            Err(e) => return Err(e),
        }
        if self
            .tk(r)
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

fn maker_key(q: &Quote, c: Chain) -> [u8; 33] {
    match c {
        Chain::Btc => q.maker_btc_pubkey,
        Chain::Divi => q.maker_divi_pubkey,
    }
}

fn taker_leg_amount(q: &Quote) -> Amount {
    match q.direction.taker_chain() {
        Chain::Btc => q.btc_amount,
        Chain::Divi => q.divi_amount,
    }
}

fn maker_leg_amount(q: &Quote) -> Amount {
    match q.direction.maker_chain() {
        Chain::Btc => q.btc_amount,
        Chain::Divi => q.divi_amount,
    }
}

fn maker_leg_confs(q: &Quote) -> u32 {
    match q.direction.maker_chain() {
        Chain::Btc => q.btc_confirmations,
        Chain::Divi => q.divi_confirmations,
    }
}
