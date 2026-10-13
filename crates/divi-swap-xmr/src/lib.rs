// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! DIVI<->XMR adaptor-signature swap engine: `docs/plans/swap-poc/xmr-design.md`'s
//! **Option B** — a dedicated maker/taker pair beside `divi-swap`'s hashlock engine, not a
//! `ChainBackend`. The cryptography is the xmr lane's (`swap-adaptor`, `swap-chain-xmr`),
//! used only through their public API; this crate is the two-party protocol around it:
//! messages, per-party state machines, persistence (in `divi_swap::Store`'s document table)
//! and the two chain traits ([`chain::DiviChain`], [`chain::MoneroChain`]) a backend must
//! implement, with in-process mocks ([`mock`]).
//!
//! Roles (`xmr-design.md` `## Protocol`): the **maker** holds DIVI and buys XMR; the
//! **taker** holds XMR and buys DIVI (offer `divi-xmr-stagenet`, `taker_pays_btc` on
//! `counter_chain = "xmr"`). Message order — note step 5, which is where this differs from
//! the design doc's happy-path list (see [`maker`]'s docs):
//!
//! 1. Taker → maker `POST /xmr/swaps` ([`api::SetupRequest`]): her DIVI multisig pubkey `b`,
//!    payout script, adaptor point `X = s_t·G` with her Monero share `S_t` and the DLEQ
//!    proof binding them.
//! 2. Maker → taker ([`api::SetupReply`]): `a`, `Y = s_m·G`, `S_m`, his DLEQ proof, the
//!    shared Monero view key, his built-but-unbroadcast `Tx_lock`'s outpoint, unsigned
//!    `Tx_cancel`/`Tx_refund`/`Tx_punish`, and his plain signatures on `Tx_cancel` and
//!    `Tx_punish`.
//! 3. Taker → maker `POST /xmr/swaps/:id/sigs` ([`api::SigsRequest`]): her plain `Tx_cancel`
//!    signature and her `Tx_refund` signature adaptor-encrypted under `Y`. The maker verifies
//!    both, then (and only then) broadcasts `Tx_lock`.
//! 4. Taker sees `Tx_lock` confirmed, locks XMR to `S = S_m + S_t`, and reports it
//!    (`POST /xmr/swaps/:id/xmr-lock`, [`api::XmrLockNotice`]).
//! 5. Maker sees that lock with enough Monero confirmations and only then publishes his
//!    `Tx_redeem` signature adaptor-encrypted under `X` ([`api::RedeemOffer`] in the view).
//! 6. Taker completes it with `s_t` and broadcasts `Tx_redeem` (the DIVI is hers); the maker
//!    reads `s_t` back out of that transaction and sweeps the XMR with `s_m + s_t`.
//!
//! Abort: past `t_cancel` either side broadcasts `Tx_cancel`; the maker then completes
//! `Tx_refund` with `s_m` (DIVI back to him), which reveals `s_m` to the taker, who sweeps
//! her XMR back. If the maker stalls until `t_punish`, the taker broadcasts `Tx_punish` and
//! takes the DIVI.

pub mod api;
pub mod chain;
pub mod crypto;
pub mod maker;
pub mod mock;
pub mod nums;
pub mod taker;
pub mod wire;

pub use api::{SetupReply, SetupRequest, SigsRequest, XmrLockNotice, XmrSwapView};
pub use chain::{DiviChain, MoneroChain, XmrOutput};
pub use maker::{XmrMaker, XmrMakerState};
pub use taker::{XmrTaker, XmrTakerState};

/// Piconero per "counter sat" (1e-8 XMR): quotes keep the engine-wide convention that the
/// counter amount is in 1e-8 units of the coin, Monero itself counts 1e-12.
pub const PICONERO_PER_COUNTER_SAT: u64 = 10_000;

/// Timing and confirmations of the adaptor swap. All times in seconds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct XmrConfig {
    /// `Tx_cancel`'s `nLockTime` = DIVI median time past at setup + this. The taker must
    /// redeem before it; after it either side may cancel. (`Tx_refund` shares it.)
    pub cancel_after_secs: u32,
    /// `Tx_punish`'s `nLockTime` = `t_cancel` + this: the maker's window to refund.
    pub punish_after_secs: u32,
    /// Margin before `t_cancel` within which neither side starts the redeem path any more
    /// (the maker stops offering his `Tx_redeem` signature, the taker stops redeeming).
    pub redeem_margin_secs: u32,
    /// Confirmations of `Tx_lock` the taker waits for before locking XMR.
    pub divi_confirmations: u32,
    /// Confirmations of the taker's XMR lock the maker waits for before offering redeem.
    pub xmr_confirmations: u32,
    /// DIVI fee per presigned transaction (sats).
    pub divi_fee_sats: u64,
    /// How long the maker keeps an accepted swap open waiting for the taker's signatures
    /// before forgetting it (no coins are locked until then).
    pub sigs_wait_secs: u64,
    /// Quote validity.
    pub quote_expiry_secs: u32,
}

impl XmrConfig {
    /// Testnet/stagenet defaults: 6 h to `t_cancel` (Monero's 10 confirmations alone take
    /// ~20 min), 3 h more to `t_punish`, 1 h redeem margin.
    pub fn testnet() -> Self {
        XmrConfig {
            cancel_after_secs: 6 * 3600,
            punish_after_secs: 3 * 3600,
            redeem_margin_secs: 3600,
            divi_confirmations: 3,
            xmr_confirmations: 10,
            divi_fee_sats: 100_000,
            sigs_wait_secs: 1800,
            quote_expiry_secs: 60,
        }
    }

    /// Reject configs that leave no room to redeem or to refund.
    pub fn validate(&self) -> divi_swap::Result<()> {
        if self.redeem_margin_secs >= self.cancel_after_secs {
            return Err(divi_swap::SwapError::InvalidParams(
                "redeem margin must be shorter than the cancel timelock".into(),
            ));
        }
        if self.punish_after_secs < self.redeem_margin_secs {
            return Err(divi_swap::SwapError::InvalidParams(
                "the maker's refund window (punish_after_secs) is shorter than the redeem margin"
                    .into(),
            ));
        }
        if self.divi_confirmations == 0 || self.xmr_confirmations == 0 {
            return Err(divi_swap::SwapError::InvalidParams(
                "confirmations must be at least 1".into(),
            ));
        }
        Ok(())
    }
}
