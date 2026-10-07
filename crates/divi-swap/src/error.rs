// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
/// `Transient` is retried, `Premature` is retried later, everything else is surfaced.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SwapError {
    /// Network failure, timeout, HTTP 429/5xx — safe to retry the same call.
    #[error("transient backend error: {0}")]
    Transient(String),
    /// The chain refused a transaction because a timelock has not matured yet
    /// (`non-final`, `Locktime requirement not satisfied`). Retry after more blocks.
    #[error("transaction premature: {0}")]
    Premature(String),
    /// The chain refused a transaction for any other reason.
    #[error("transaction rejected: {0}")]
    Rejected(String),
    /// The backend's wallet cannot cover the requested amount plus fee.
    #[error("insufficient funds: {0}")]
    InsufficientFunds(String),
    /// Caller supplied parameters that violate the contract.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    /// Persistence (SQLite) failure.
    #[error("storage error: {0}")]
    Storage(String),
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
        matches!(self, SwapError::Transient(_) | SwapError::Premature(_))
    }
}
