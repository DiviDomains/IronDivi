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
//! every `step` is idempotent and safe to re-run after a crash; `build_funding` on the DIVI
//! backend is called only on the `TakerLockConfirmed → MakerLocked` edge.

use std::sync::Arc;

use crate::api::{AcceptRequest, LockNotice, Offer, Quote, SwapView};
use crate::backend::ChainBackend;
use crate::config::SwapConfig;
use crate::error::Result;
use crate::state::SwapState;
use crate::store::Store;

/// Maker engine. `divi` holds the maker's DIVI key, `btc` the maker's BTC key.
#[allow(dead_code)] // filled in by lane engine
pub struct Maker {
    cfg: SwapConfig,
    divi: Arc<dyn ChainBackend>,
    btc: Arc<dyn ChainBackend>,
    store: Store,
    offers: Vec<Offer>,
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
        })
    }

    /// Standing offers.
    pub fn offers(&self) -> Vec<Offer> {
        self.offers.clone()
    }

    /// Issue a quote valid for `cfg.quote_expiry_secs`. No coins are reserved.
    pub async fn quote(&self, offer_id: &str, btc_sats: u64) -> Result<Quote> {
        let _ = (offer_id, btc_sats);
        todo!("lane engine: Maker::quote")
    }

    /// Accept an unexpired quote: fixes the BTC HTLC the taker must fund.
    pub async fn accept(&self, req: AcceptRequest) -> Result<SwapView> {
        let _ = req;
        todo!("lane engine: Maker::accept")
    }

    /// The taker says it funded the BTC HTLC at `lock.outpoint`.
    pub async fn notify_lock(&self, swap_id: &str, lock: LockNotice) -> Result<SwapView> {
        let _ = (swap_id, lock);
        todo!("lane engine: Maker::notify_lock")
    }

    /// Current view of one swap.
    pub fn view(&self, swap_id: &str) -> Result<Option<SwapView>> {
        let _ = swap_id;
        todo!("lane engine: Maker::view")
    }

    /// All swaps, newest first.
    pub fn list(&self) -> Result<Vec<SwapView>> {
        todo!("lane engine: Maker::list")
    }

    /// Advance one swap as far as it can go right now. Idempotent; safe after restart.
    pub async fn step(&self, swap_id: &str) -> Result<SwapState> {
        let _ = swap_id;
        todo!("lane engine: Maker::step")
    }

    /// `step` every non-terminal swap; errors are recorded on the swap, not returned.
    /// The daemon's scheduler calls this every few seconds and once at startup.
    pub async fn tick(&self) -> Result<()> {
        todo!("lane engine: Maker::tick")
    }
}
