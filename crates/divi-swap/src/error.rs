// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Error type shared by the engine and every [`crate::ChainBackend`].

use thiserror::Error;

/// Result alias used across the swap engine.
pub type Result<T> = std::result::Result<T, SwapError>;

/// Errors a backend or the engine can return.
///
/// The variant tells the engine what to do next, so backends must classify carefully:
/// `Transient` and `Held` are retried, `Premature` is retried later, everything else is
/// surfaced.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SwapError {
    /// Network failure, timeout, HTTP 429/5xx — safe to retry the same call.
    #[error("transient backend error: {0}")]
    Transient(String),
    /// The backend refused to build a claim or refund because its second source (an opt-in
    /// cross-check) is unavailable or disagrees with the primary: retried like `Transient`
    /// until the engine's deadline for that spend, past which it builds the spend on the
    /// primary alone ([`crate::ChainBackend::primary_only`]). The message names both sources.
    #[error("held for a second source: {0}")]
    Held(String),
    /// The chain refused a transaction because a timelock has not matured yet
    /// (`non-final`, `Locktime requirement not satisfied`). Retry after more blocks.
    #[error("transaction premature: {0}")]
    Premature(String),
    /// The chain refused a transaction for any other reason.
    #[error("transaction rejected: {0}")]
    Rejected(String),
    /// The input-reservation table ([`crate::InputReservations`]) refused a transaction
    /// before it was sent: another transaction holds one of its inputs. Nothing reached the
    /// node. Never returned for anything a node said.
    #[error("transaction not sent: {0}")]
    InputsHeld(String),
    /// The backend's wallet cannot cover the requested amount plus fee.
    #[error("insufficient funds: {0}")]
    InsufficientFunds(String),
    /// Caller supplied parameters that violate the contract.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    /// Persistence (SQLite) failure.
    #[error("storage error: {0}")]
    Storage(String),
    /// The swap database was written by a newer binary than this one. Opening it would let
    /// this binary silently drop fields it does not know (a V1 script read back as V0).
    #[error(
        "swap database schema version {found} is newer than this binary supports ({supported}): \
         run the newer divi-swap/divi-swapd binary that wrote it; refusing to open"
    )]
    StoreTooNew { found: u32, supported: u32 },
    /// A secret could not be resolved. Never contains the secret itself.
    #[error("secret unavailable: {0}")]
    Secret(String),
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl SwapError {
    /// True when retrying the identical call later may succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            SwapError::Transient(_) | SwapError::Premature(_) | SwapError::Held(_)
        )
    }
}
