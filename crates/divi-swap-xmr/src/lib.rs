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
//! implement, with in-process mocks ([`mock`]) and live backends over the xmr lane's chains
//! ([`live`]).
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
pub mod jsig;
pub mod live;
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

/// What the timelock minimums of [`XmrConfig::validate_for`] are derived from: block times,
/// how much slower than nominal blocks may run, the DIVI median-time-past drift, and how long
/// a party takes to notice a chain event and act on it. All times in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTiming {
    /// DIVI target block interval.
    pub divi_block_secs: u32,
    /// Monero target block interval.
    pub xmr_block_secs: u32,
    /// Waits for `n` confirmations are budgeted at this many times `n` nominal blocks
    /// (block arrival is random; a run of slow blocks must not cost a side its funds).
    pub slow_block_factor: u32,
    /// Every deadline is a DIVI MTP, every wait is wall clock: between two MTP readings the
    /// wall clock can run this much less than the MTPs say (the lag at the first reading
    /// minus the lag at the second), so each window gives this up.
    pub divi_mtp_lag_secs: u32,
    /// One party noticing a chain event and acting on it: a scheduler tick, a client poll,
    /// a `find_lock` scan on a remote monerod, a broadcast.
    pub reaction_secs: u32,
}

impl ChainTiming {
    /// The live chains: DIVI 60 s blocks and the shared engine's DIVI MTP lag
    /// (`divi_swap::ChainParams`), Monero 120 s blocks, waits budgeted at 3× nominal, 5 min
    /// per reaction (the daemon ticks every 5 s; a remote `find_lock` scan takes minutes).
    pub fn live() -> Self {
        ChainTiming {
            divi_block_secs: swap_chain_xmr::timelocks::DIVI_BLOCK_SECS,
            xmr_block_secs: 120,
            slow_block_factor: 3,
            divi_mtp_lag_secs: divi_swap::ChainParams::builtin(
                divi_swap::Chain::Divi,
                divi_swap::Profile::Mainnet,
            )
            .mtp_lag_secs,
            reaction_secs: 300,
        }
    }

    /// Budget for `n` DIVI confirmations.
    pub fn divi_wait(&self, n: u32) -> u64 {
        self.slow_block_factor as u64 * self.divi_block_secs as u64 * n as u64
    }

    /// Budget for `n` Monero confirmations.
    pub fn xmr_wait(&self, n: u32) -> u64 {
        self.slow_block_factor as u64 * self.xmr_block_secs as u64 * n as u64
    }
}

impl XmrConfig {
    /// Testnet/stagenet defaults: 6 h to `t_cancel` (Monero's 10 confirmations alone take
    /// ~20 min), 3 h more to `t_punish`, 1 h redeem margin. Derived minimums under
    /// [`ChainTiming::live`]: cancel 12 240 s, punish 3 600 s, margin 2 640 s.
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

    /// Mainnet profile. Never selected while the mainnet refusals stand
    /// (`xmr-mainnet-plan.md` phase D). DIVI depth is the shared engine's mainnet DIVI
    /// depth, XMR depth Monero's spendable age; timelocks mirror the shared mainnet profile
    /// (`t_cancel` = its 12 h maker timeout, `t_punish` = its 24 h taker timeout) with a 2 h
    /// redeem margin. Derived minimums under [`ChainTiming::live`]: cancel 20 400 s, punish
    /// 7 200 s, margin 3 900 s. The presigned transactions cannot be fee-bumped, so their fee
    /// is the DIVI wallet's 0.01 DIVI/kB rate on a full kB, about 3× a 2-of-2 spend's size.
    pub fn mainnet() -> Self {
        XmrConfig {
            cancel_after_secs: 12 * 3600,
            punish_after_secs: 12 * 3600,
            redeem_margin_secs: 2 * 3600,
            divi_confirmations: divi_swap::SwapConfig::profile(divi_swap::Profile::Mainnet)
                .divi_confirmations,
            xmr_confirmations: swap_chain_xmr::live_rpc::SPENDABLE_AGE as u32,
            divi_fee_sats: 1_000_000,
            sigs_wait_secs: 1800,
            quote_expiry_secs: 60,
        }
    }

    /// Smallest `redeem_margin_secs` under `t`: the taker completes `Tx_redeem` while
    /// `t_cancel` is more than the margin away, and it must be `divi_confirmations` deep
    /// before `Tx_cancel` becomes valid (a `Tx_cancel` mined first would let the maker refund
    /// his DIVI *and* sweep the XMR with the `s_t` the broadcast `Tx_redeem` revealed).
    pub fn min_redeem_margin_secs(&self, t: &ChainTiming) -> u64 {
        t.divi_mtp_lag_secs as u64 + t.reaction_secs as u64 + t.divi_wait(self.divi_confirmations)
    }

    /// Smallest `cancel_after_secs` under `t` (it counts from the DIVI MTP at setup,
    /// `maker.rs` `setup`). The taker's happy path must fit before the maker stops offering
    /// redeem at `t_cancel − redeem_margin`: her signatures may come up to `sigs_wait_secs`
    /// after setup, the maker broadcasts `Tx_lock` (a reaction), it gets
    /// `divi_confirmations`, she locks XMR (a reaction), it gets `xmr_confirmations`, the
    /// maker's scan sees it (a reaction) and offers redeem. She also only starts locking
    /// while `t_cancel` is more than twice the margin away (`taker.rs`), so the lock must be
    /// reachable before that too. A taker who locks later than this schedule but before her
    /// own cutoff may miss the offer; the swap then aborts through `Tx_cancel`/`Tx_refund`,
    /// which returns both sides' coins.
    pub fn min_cancel_after_secs(&self, t: &ChainTiming) -> u64 {
        let reaction = t.reaction_secs as u64;
        let margin = self.redeem_margin_secs as u64;
        let to_xmr_lock = t.divi_mtp_lag_secs as u64
            + self.sigs_wait_secs
            + 2 * reaction
            + t.divi_wait(self.divi_confirmations);
        let after_lock = (reaction + t.xmr_wait(self.xmr_confirmations) + margin).max(2 * margin);
        to_xmr_lock + after_lock
    }

    /// Smallest `punish_after_secs` under `t`: from `t_cancel` the maker notices (a
    /// reaction), `Tx_cancel` is mined, `Tx_refund` goes out (a reaction) and must be
    /// `divi_confirmations` deep before `Tx_punish` becomes valid (a `Tx_punish` mined after
    /// the broadcast `Tx_refund` revealed `s_m` would give the taker the DIVI *and* her XMR
    /// back). `Tx_refund` buried `n` deep buries `Tx_cancel` too, so `Tx_cancel` counts one
    /// block. Never below the margin: the taker refuses a shorter window at setup.
    pub fn min_punish_after_secs(&self, t: &ChainTiming) -> u64 {
        let maker = t.divi_mtp_lag_secs as u64
            + 2 * t.reaction_secs as u64
            + t.divi_wait(self.divi_confirmations + 1);
        maker.max(self.redeem_margin_secs as u64)
    }

    /// [`XmrConfig::validate_for`] the live chains.
    pub fn validate(&self) -> divi_swap::Result<()> {
        self.validate_for(&ChainTiming::live())
    }

    /// Reject configs that leave either side less time than its path needs under `t` (the
    /// `min_*_secs` above). Mock chains, whose blocks come on demand, pass their own timing.
    pub fn validate_for(&self, t: &ChainTiming) -> divi_swap::Result<()> {
        let bad = |s: String| Err(divi_swap::SwapError::InvalidParams(s));
        if self.divi_confirmations == 0 || self.xmr_confirmations == 0 {
            return bad("confirmations must be at least 1".into());
        }
        let checks = [
            (
                "redeem_margin_secs",
                self.redeem_margin_secs,
                self.min_redeem_margin_secs(t),
                "Tx_redeem to confirm before t_cancel",
            ),
            (
                "cancel_after_secs",
                self.cancel_after_secs,
                self.min_cancel_after_secs(t),
                "Tx_lock and the XMR lock to confirm before the redeem margin",
            ),
            (
                "punish_after_secs",
                self.punish_after_secs,
                self.min_punish_after_secs(t),
                "Tx_cancel and Tx_refund to confirm before t_punish",
            ),
        ];
        for (field, have, need, what) in checks {
            if (have as u64) < need {
                return bad(format!(
                    "{field} = {have}s is below the {need}s needed for {what} \
                     ({} DIVI / {} XMR confirmations at {}s / {}s blocks, ×{} for slow blocks)",
                    self.divi_confirmations,
                    self.xmr_confirmations,
                    t.divi_block_secs,
                    t.xmr_block_secs,
                    t.slow_block_factor,
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_profile_pinned() {
        let m = XmrConfig::mainnet();
        assert_eq!(
            m,
            XmrConfig {
                cancel_after_secs: 43_200,
                punish_after_secs: 43_200,
                redeem_margin_secs: 7_200,
                divi_confirmations: 10,
                xmr_confirmations: 10,
                divi_fee_sats: 1_000_000,
                sigs_wait_secs: 1800,
                quote_expiry_secs: 60,
            }
        );
        // Tied to their sources, not just equal to them today.
        let shared = divi_swap::SwapConfig::profile(divi_swap::Profile::Mainnet);
        assert_eq!(m.divi_confirmations, shared.divi_confirmations);
        assert_eq!(
            m.xmr_confirmations as u64,
            swap_chain_xmr::live_rpc::SPENDABLE_AGE
        );
        assert_eq!(m.cancel_after_secs, shared.maker_timeout_secs);
        assert_eq!(
            m.cancel_after_secs + m.punish_after_secs,
            shared.taker_timeout_secs
        );
        m.validate().unwrap();
        let t = ChainTiming::live();
        assert_eq!(
            (
                m.min_cancel_after_secs(&t),
                m.min_punish_after_secs(&t),
                m.min_redeem_margin_secs(&t)
            ),
            (20_400, 7_200, 3_900)
        );
    }

    #[test]
    fn testnet_profile_clears_the_derived_minimums() {
        let c = XmrConfig::testnet();
        c.validate().unwrap();
        let t = ChainTiming::live();
        assert_eq!(
            t,
            ChainTiming {
                divi_block_secs: 60,
                xmr_block_secs: 120,
                slow_block_factor: 3,
                divi_mtp_lag_secs: 1800,
                reaction_secs: 300,
            }
        );
        assert_eq!(
            (
                c.min_cancel_after_secs(&t),
                c.min_punish_after_secs(&t),
                c.min_redeem_margin_secs(&t)
            ),
            (12_240, 3_600, 2_640)
        );
    }

    /// Each minimum is the boundary: one second less fails, naming the field.
    #[test]
    fn each_minimum_is_enforced() {
        let t = ChainTiming::live();
        let base = XmrConfig::mainnet();
        let mut c = base.clone();
        c.redeem_margin_secs = c.min_redeem_margin_secs(&t) as u32;
        c.validate().unwrap();
        c.redeem_margin_secs -= 1;
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("redeem_margin_secs"), "{e}");

        let mut c = base.clone();
        c.cancel_after_secs = c.min_cancel_after_secs(&t) as u32;
        c.validate().unwrap();
        c.cancel_after_secs -= 1;
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("cancel_after_secs"), "{e}");

        let mut c = base;
        c.redeem_margin_secs = 3900; // below the maker's own refund need of 4 380 s
        c.punish_after_secs = c.min_punish_after_secs(&t) as u32;
        assert_eq!(c.punish_after_secs, 4380);
        c.validate().unwrap();
        c.punish_after_secs -= 1;
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("punish_after_secs"), "{e}");

        let mut c = XmrConfig::testnet();
        c.xmr_confirmations = 0;
        assert!(c.validate().is_err());
    }

    /// Short mock-chain schedules fail the live check but pass against their own timing.
    #[test]
    fn mock_timing_opts_out_without_weakening_validate() {
        let fast = ChainTiming {
            divi_block_secs: 1,
            xmr_block_secs: 1,
            slow_block_factor: 1,
            divi_mtp_lag_secs: 0,
            reaction_secs: 1,
        };
        let c = XmrConfig {
            cancel_after_secs: 600,
            punish_after_secs: 300,
            redeem_margin_secs: 100,
            sigs_wait_secs: 60,
            ..XmrConfig::testnet()
        };
        c.validate_for(&fast).unwrap();
        assert!(c.validate().is_err());
    }
}
