// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The two chain traits of the adaptor swap (`xmr-design.md` Option B: "two backend-shaped
//! traits, not one"). Each party holds one of each: a DIVI wallet (its own key — funding,
//! payouts) and a Monero wallet. The per-swap 2-of-2 keys are not the backends': the engines
//! generate them per swap and sign with them directly.

use async_trait::async_trait;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use divi_swap::Result;

/// One party's DIVI wallet plus read access to the DIVI chain.
// clippy >= 1.99 flags the `#[must_use]` that `async_trait` adds to the boxed futures.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait DiviChain: Send + Sync {
    /// Where this wallet receives (the taker's `Tx_redeem`/`Tx_punish` payout, the maker's
    /// `Tx_refund` payout).
    fn payout_script(&self) -> Script;

    /// Current best height.
    async fn tip_height(&self) -> Result<u64>;

    /// Median time past of the tip (what `nLockTime` unix times are compared against).
    async fn median_time_past(&self) -> Result<u32>;

    /// Select this wallet's coins and sign a transaction paying `amount` sats to
    /// `script_pubkey`, change back to the wallet. **Does not broadcast.** The maker calls it
    /// once per swap to build `Tx_lock`.
    async fn build_funding(&self, script_pubkey: &Script, amount: u64) -> Result<Transaction>;

    /// Broadcast. Idempotent: a transaction the chain already has returns `Ok`. One that is
    /// not final yet (`nLockTime` in the future) returns `SwapError::Premature`; one whose
    /// input another transaction already spent returns `SwapError::Rejected`.
    async fn broadcast(&self, tx: &Transaction) -> Result<()>;

    /// Confirmations of `txid`: `Some(0)` in mempool, `None` if unknown.
    async fn confirmations(&self, txid: &Hash256) -> Result<Option<u32>>;

    /// The output at `at` and its transaction's confirmations, if the chain knows it.
    async fn output(&self, at: &OutPoint) -> Result<Option<(TxOut, u32)>>;

    /// The transaction spending `at` (mempool or block), if any.
    async fn find_spend(&self, at: &OutPoint) -> Result<Option<Transaction>>;
}

/// A Monero output paying the swap's shared 2-of-2 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmrOutput {
    /// Transaction id (hex).
    pub txid: String,
    /// Amount, piconero.
    pub amount: u64,
    /// Confirmations (0 = in the pool).
    pub confirmations: u32,
}

/// One party's Monero wallet plus read access to the Monero chain.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait MoneroChain: Send + Sync {
    /// Send `amount` piconero from this wallet to the address with public spend key
    /// `spend_pub` and private view key `view_secret` (the swap's 2-of-2). Returns the txid.
    /// Not idempotent: callers persist their intent first and check [`MoneroChain::find_lock`]
    /// before retrying.
    async fn lock(
        &self,
        spend_pub: &[u8; 32],
        view_secret: &[u8; 32],
        amount: u64,
    ) -> Result<String>;

    /// The output paying `spend_pub` (scanned with `view_secret`), if any.
    async fn find_lock(
        &self,
        spend_pub: &[u8; 32],
        view_secret: &[u8; 32],
    ) -> Result<Option<XmrOutput>>;

    /// Spend `lock` (all of it, less the fee) to this wallet with the full spend secret
    /// `spend_secret` (`s_m + s_t`, little-endian scalar bytes). Returns the txid. Idempotent
    /// for an output this wallet already swept.
    async fn sweep(
        &self,
        lock: &XmrOutput,
        spend_secret: &[u8; 32],
        view_secret: &[u8; 32],
    ) -> Result<String>;

    /// Confirmations of `txid`, `None` if unknown.
    async fn confirmations(&self, txid: &str) -> Result<Option<u32>>;
}
