// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The `ChainBackend` trait — the frozen contract between the engine and each chain.
//!
//! Differences from the sketch in plan §3.1, decided in Wave 0 (see
//! `docs/plans/swap-poc/DECISIONS.md` #3): building and broadcasting are separate so the
//! engine can persist a signed transaction **before** it is broadcast (write-ahead) and
//! rebroadcast the identical bytes after a crash; the backend exposes its own pubkey; and
//! `htlc_output` lets each side verify the counterparty's lock.

use async_trait::async_trait;

use crate::error::Result;
use crate::htlc::HtlcParams;
use crate::types::{Amount, Chain, Funding, LockedOutput, Outpoint, SignedTx, SpendInfo, Txid};

/// One chain, one engine key. A backend owns exactly one secp256k1 key (resolved from
/// 1Password at startup): it funds HTLCs from that key's coins, and claims / refunds to it.
#[async_trait]
pub trait ChainBackend: Send + Sync {
    /// Which chain this is.
    fn chain(&self) -> Chain;

    /// Compressed pubkey of this backend's key — the `claim_pubkey` or `refund_pubkey`
    /// to put in an HTLC this side may spend.
    fn pubkey(&self) -> [u8; 33];

    /// Current best block height.
    async fn tip_height(&self) -> Result<u64>;

    /// Median time past of the tip (what CLTV unix-time locktimes are compared against).
    async fn median_time_past(&self) -> Result<u32>;

    /// Select coins and build + sign a transaction paying `amount` to the HTLC (P2SH on
    /// DIVI, P2WSH on BTC), change back to this key. **Does not broadcast.**
    ///
    /// This is the only method that performs coin selection. On the maker side the engine
    /// calls it only on entering `MakerLocked` (the staking promise, plan §3.2).
    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding>;

    /// Build + sign the claim spend of `at` (value `amount`) using `preimage`, paying
    /// `amount − fee` to this key. **Does not broadcast.**
    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx>;

    /// Build + sign the refund spend of `at` (value `amount`) with
    /// `nLockTime = htlc.locktime`, paying `amount − fee` to this key. **Does not broadcast.**
    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx>;

    /// Broadcast. Idempotent: a transaction the chain already has (mempool or block)
    /// returns `Ok(txid)`. Timelock-immature refusals return `SwapError::Premature`.
    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid>;

    /// Confirmations of `txid`: `Some(0)` in mempool, `None` if the chain does not know it.
    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>>;

    /// If `at` exists and pays exactly the HTLC script for `htlc`, its value and
    /// confirmations; `None` if the tx is unknown or the output does not match.
    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>>;

    /// Find a transaction spending `outpoint`, scanning blocks from `from_height` to the
    /// tip and then the mempool where the backend can. Must not rely on address or spent
    /// indexes (plan §2: missing on the DIVI testnet proxy).
    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>>;
}
