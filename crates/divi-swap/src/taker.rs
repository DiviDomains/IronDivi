// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The taker engine (used by the `divi-swap` CLI). **Lane engine** owns the bodies; the
//! public signatures are frozen (the CLI builds against them).

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::{AcceptRequest, LockNotice, Quote, SwapView};
use crate::backend::ChainBackend;
use crate::error::{Result, SwapError};
use crate::htlc::{new_preimage, HtlcParams};
use crate::store::{Store, TakerRecord};

/// The taker stops claiming DIVI this many seconds before the maker's locktime: a claim
/// that confirms after the maker refunds would lose the DIVI while revealing the preimage.
pub const TAKER_SAFETY_MARGIN_SECS: u32 = 1800;

/// How far the maker's BTC locktime may drift from `btc_mtp + taker_timeout` (clock skew
/// between `accept` and our own view of the chain).
const LOCKTIME_TOLERANCE_SECS: u32 = 1800;

/// Taker-side state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TakerState {
    /// Preimage generated and persisted; accept request built.
    Prepared,
    /// Maker accepted; BTC HTLC fixed.
    Accepted,
    /// BTC HTLC funding tx persisted (broadcast follows).
    Locked,
    /// Maker's DIVI lock verified (amount, script) and confirmed.
    MakerLockConfirmed,
    /// DIVI claim broadcast (preimage revealed).
    Claimed,
    /// BTC refunded after the taker timeout.
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
            btc_htlc: None,
            btc_funding: None,
            divi_htlc: None,
            divi_outpoint: None,
            divi_amount: None,
            divi_claim: None,
            btc_refund: None,
            last_error: None,
        })?;
        Ok((id, req))
    }

    /// Record the maker's reply to `POST /swaps`, checking its BTC HTLC is the one we
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
        let bad = |what: &str| SwapError::InvalidParams(format!("maker's BTC HTLC: {what}"));
        if h.hash != r.hash {
            return Err(bad("wrong hash"));
        }
        if h.refund_pubkey != self.btc.pubkey() {
            return Err(bad("refund key is not ours"));
        }
        if h.claim_pubkey != r.quote.maker_btc_pubkey {
            return Err(bad("claim key is not the quote's maker key"));
        }
        if maker.quote.id != r.quote.id || maker.quote.btc_amount != r.quote.btc_amount {
            return Err(bad("reply is for a different quote"));
        }
        let expect = self.btc.median_time_past().await? as u64 + r.quote.taker_timeout_secs as u64;
        if (h.locktime as u64).abs_diff(expect) > LOCKTIME_TOLERANCE_SECS as u64 {
            return Err(bad("locktime does not match the quote's taker timeout"));
        }
        r.btc_htlc = Some(h);
        r.maker_swap_id = Some(maker.id.clone());
        self.enter(&mut r, TakerState::Accepted)?;
        Ok(())
    }

    /// Fund the BTC HTLC (write-ahead); returns the notice to `POST /swaps/:id/lock`.
    pub async fn lock(&self, local_id: &str) -> Result<LockNotice> {
        let _g = self.gate.lock().await;
        let mut r = self.load(local_id)?;
        match r.state {
            TakerState::Accepted => {
                let htlc = self.btc_htlc(&r)?;
                let funding = self.btc.build_funding(&htlc, r.quote.btc_amount).await?;
                r.btc_funding = Some(funding);
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
            .btc_funding
            .clone()
            .ok_or_else(|| SwapError::Other("Locked without a funding tx".into()))?;
        self.btc.broadcast(&funding.tx).await?;
        Ok(LockNotice {
            outpoint: funding.outpoint,
        })
    }

    /// Advance using the maker's latest view (`None` if the maker is unreachable): claim the
    /// DIVI once the maker's lock is verified and confirmed, refund the BTC after timeout.
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

    fn btc_htlc(&self, r: &TakerRecord) -> Result<HtlcParams> {
        r.btc_htlc
            .ok_or_else(|| SwapError::Other("BTC HTLC not fixed yet".into()))
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

    async fn btc_refundable(&self, r: &TakerRecord) -> Result<bool> {
        Ok(self.btc.median_time_past().await? >= self.btc_htlc(r)?.locktime)
    }

    async fn on_locked(&self, r: &mut TakerRecord, maker: Option<&SwapView>) -> Result<Flow> {
        if let Some(f) = &r.btc_funding {
            self.btc.broadcast(&f.tx).await?; // idempotent; recovers a crash before broadcast
        }
        if self.btc_refundable(r).await? {
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
        let bad = |what: &str| SwapError::Other(format!("maker's DIVI lock: {what}"));
        if htlc.hash != r.hash {
            return Err(bad("wrong hash"));
        }
        if htlc.claim_pubkey != self.divi.pubkey() {
            return Err(bad("claim key is not ours"));
        }
        if htlc.refund_pubkey != r.quote.maker_divi_pubkey {
            return Err(bad("refund key is not the quote's maker key"));
        }
        // Trust the chain, not the maker's view, for amount and confirmations.
        let Some(lo) = self.divi.htlc_output(&htlc, &op).await? else {
            return Ok(Flow::Idle);
        };
        if lo.amount < r.quote.divi_amount {
            return Err(bad("underfunded"));
        }
        if lo.confirmations < r.quote.divi_confirmations {
            return Ok(Flow::Idle);
        }
        let mtp = self.divi.median_time_past().await?;
        if (htlc.locktime as u64) < mtp as u64 + TAKER_SAFETY_MARGIN_SECS as u64 {
            return Err(bad("locktime too close to claim safely"));
        }
        r.divi_htlc = Some(htlc);
        r.divi_outpoint = Some(op);
        r.divi_amount = Some(lo.amount);
        self.enter(r, TakerState::MakerLockConfirmed)
    }

    async fn on_maker_lock_confirmed(&self, r: &mut TakerRecord) -> Result<Flow> {
        let htlc = r
            .divi_htlc
            .ok_or_else(|| SwapError::Other("no verified DIVI lock".into()))?;
        let mtp = self.divi.median_time_past().await?;
        if (mtp as u64) + TAKER_SAFETY_MARGIN_SECS as u64 <= htlc.locktime as u64 {
            let op = r.divi_outpoint.expect("set with divi_htlc");
            let amount = r.divi_amount.expect("set with divi_htlc");
            let claim = self
                .divi
                .build_claim(&htlc, &op, amount, &r.preimage)
                .await?;
            r.divi_claim = Some(claim);
            // Persist the signed claim (which reveals the preimage) before broadcasting it.
            return self.enter(r, TakerState::Claimed);
        }
        // Too late to claim safely: wait out our own BTC timelock.
        if self.btc_refundable(r).await? {
            return self.enter(r, TakerState::Refunded);
        }
        Ok(Flow::Idle)
    }

    async fn on_claimed(&self, r: &mut TakerRecord) -> Result<Flow> {
        let claim = r
            .divi_claim
            .clone()
            .ok_or_else(|| SwapError::Other("Claimed without a claim tx".into()))?;
        self.divi.broadcast(&claim).await?;
        if self
            .divi
            .confirmations(&claim.txid)
            .await?
            .is_some_and(|c| c >= 1)
        {
            return self.enter(r, TakerState::Done);
        }
        Ok(Flow::Idle)
    }

    async fn on_refunded(&self, r: &mut TakerRecord) -> Result<Flow> {
        let refund = match r.btc_refund.clone() {
            Some(tx) => tx,
            None => {
                let htlc = self.btc_htlc(r)?;
                let f = r
                    .btc_funding
                    .clone()
                    .ok_or_else(|| SwapError::Other("Refunded without a funding tx".into()))?;
                let tx = self.btc.build_refund(&htlc, &f.outpoint, f.amount).await?;
                r.btc_refund = Some(tx.clone());
                self.store.put_taker_swap(r)?; // write-ahead
                tx
            }
        };
        match self.btc.broadcast(&refund).await {
            Ok(_) => {}
            Err(SwapError::Premature(_)) => return Ok(Flow::Idle),
            Err(e) => return Err(e),
        }
        if self
            .btc
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
