// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Atomic swap engine for DIVI ↔ BTC (HTLC, SHA256 hashlock, CLTV refunds).
//!
//! Plan: `docs/plans/atomic-swap-poc.md`. The modules [`types`], [`htlc`], [`backend`],
//! [`state`], [`config`], [`error`] and [`api`] — plus the public signatures in [`maker`],
//! [`taker`] and [`store`] — are the **frozen contract** (plan §3.1): lanes build
//! against them and never change them alone — a needed change goes to the orchestrator.

pub mod api;
pub mod backend;
pub mod config;
pub mod error;
pub mod htlc;
pub mod maker;
pub mod mock;
pub mod secrets;
pub mod state;
pub mod store;
pub mod taker;
pub mod types;

pub use api::Direction;
pub use backend::ChainBackend;
pub use config::{Profile, SwapConfig};
pub use error::{Result, SwapError};
pub use htlc::HtlcParams;
pub use maker::Maker;
pub use state::SwapState;
pub use store::Store;
pub use taker::{Taker, TakerState};
pub use types::{Amount, Chain, Funding, LockedOutput, Outpoint, SignedTx, SpendInfo, Txid};
