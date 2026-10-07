// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The taker engine (used by the `divi-swap` CLI). **Lane engine** owns the bodies; the
//! public signatures are frozen (the CLI builds against them).

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::{AcceptRequest, LockNotice, Quote, SwapView};
use crate::backend::ChainBackend;
use crate::error::Result;
use crate::store::Store;

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
#[allow(dead_code)] // filled in by lane engine
pub struct Taker {
    divi: Arc<dyn ChainBackend>,
    btc: Arc<dyn ChainBackend>,
    store: Store,
}

impl Taker {
    /// New taker engine.
    pub fn new(divi: Arc<dyn ChainBackend>, btc: Arc<dyn ChainBackend>, store: Store) -> Self {
        Taker { divi, btc, store }
    }

    /// Generate + persist a preimage for `quote`; returns a local swap id and the request
    /// to `POST /swaps`.
    pub async fn prepare(&self, quote: &Quote) -> Result<(String, AcceptRequest)> {
        let _ = quote;
        todo!("lane engine: Taker::prepare")
    }

    /// Record the maker's reply to `POST /swaps`, checking its BTC HTLC is the one we
    /// expect (our refund key, our hash, a locktime matching the quote's taker timeout).
    pub async fn accepted(&self, local_id: &str, maker: &SwapView) -> Result<()> {
        let _ = (local_id, maker);
        todo!("lane engine: Taker::accepted")
    }

    /// Fund the BTC HTLC (write-ahead); returns the notice to `POST /swaps/:id/lock`.
    pub async fn lock(&self, local_id: &str) -> Result<LockNotice> {
        let _ = local_id;
        todo!("lane engine: Taker::lock")
    }

    /// Advance using the maker's latest view (`None` if the maker is unreachable): claim the
    /// DIVI once the maker's lock is verified and confirmed, refund the BTC after timeout.
    pub async fn step(&self, local_id: &str, maker: Option<&SwapView>) -> Result<TakerState> {
        let _ = (local_id, maker);
        todo!("lane engine: Taker::step")
    }
}
