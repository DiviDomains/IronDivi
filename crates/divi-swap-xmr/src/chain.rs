// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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

    /// The network the DIVI node is on, as `getblockchaininfo` names it (`main`, `test`,
    /// `regtest`). Every timelock trusts this node's median time past, so the engines check
    /// it against the configured network at startup ([`check_divi_chain`]).
    async fn chain_name(&self) -> Result<String>;

    /// Current best height.
    async fn tip_height(&self) -> Result<u64>;

    /// Median time past of the tip (what `nLockTime` unix times are compared against).
    async fn median_time_past(&self) -> Result<u32>;

    /// Select this wallet's coins and sign a transaction paying `amount` sats to
    /// `script_pubkey`, change back to the wallet. **Does not broadcast.** The maker calls it
    /// once per swap to build `Tx_lock`.
    async fn build_funding(&self, script_pubkey: &Script, amount: u64) -> Result<Transaction>;

    /// Give back the coins [`DiviChain::build_funding`] reserved for `tx`, which will never be
    /// broadcast (the swap was aborted or never reached the lock stage). Idempotent: a
    /// transaction with nothing reserved is `Ok`. Never call it for a transaction that was
    /// broadcast.
    async fn release_funding(&self, tx: &Transaction) -> Result<()>;

    /// Release every reservation whose funding transaction is not in `keep` and return their
    /// txids. The maker calls it once after a restart with the `Tx_lock` of every persisted
    /// swap: a reservation outlives the process (the wallet file keeps it), so one made just
    /// before a crash, with no record to refer to it, would otherwise lock those coins forever.
    async fn release_orphan_funding(&self, keep: &[Hash256]) -> Result<Vec<Hash256>>;

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

/// Refuse a DIVI node that is not on the `expected` chain (`main` / `test` / `regtest`): a
/// mainnet swap over a testnet node (or the reverse) would run every timelock off the wrong
/// chain's clock.
pub async fn check_divi_chain(divi: &dyn DiviChain, expected: &str) -> Result<()> {
    let got = divi.chain_name().await?;
    if got != expected {
        return Err(divi_swap::SwapError::InvalidParams(format!(
            "the DIVI RPC is on chain {got:?}, but the configured network needs {expected:?}"
        )));
    }
    Ok(())
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

    /// The first output paying `spend_pub` (scanned with `view_secret`) worth at least
    /// `min_amount` piconero, if any. Smaller outputs to that address are dust someone sent
    /// to hide the real lock and are ignored.
    async fn find_lock(
        &self,
        spend_pub: &[u8; 32],
        view_secret: &[u8; 32],
        min_amount: u64,
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
