// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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
//! 1. Taker → maker `POST /xmr/swaps` ([`api::SetupRequest`]): her DIVI key `b`, payout
//!    script, adaptor point `X = s_t·G` with her Monero share `S_t` and the DLEQ proof binding
//!    them, and the opening messages of a 2P-ECDSA session ([`jsig`]) for the joint cancel
//!    key `J`.
//! 2. `J` exchanges (`POST /xmr/swaps/:id/j`, [`api::JRoundReply`]) until `J` exists. The
//!    maker then builds `Tx_lock` ([`swap_chain_xmr::lock_scripts::LockScript`]: redeem by
//!    `a`+`b`, cancel by `J` alone after `t_cancel`, the maker's late escape after `t_late`)
//!    and `Tx_cancel`, sends [`api::SetupReply`], and both sides jointly produce `σ_J`, the
//!    one signature `Tx_cancel` needs. Neither side alone can sign for `J`, and nothing else
//!    can spend the cancel branch, so no single key can take the lock to a `Tx_cancel` the
//!    other side has no `Tx_refund` for (C1).
//! 3. Taker → maker `POST /xmr/swaps/:id/sigs` ([`api::SigsRequest`]): `σ_J` and her
//!    `Tx_refund` signature adaptor-encrypted under `Y`, once per consensus-valid encoding
//!    of the signed `Tx_cancel`. The maker verifies all, then (and only then) broadcasts
//!    `Tx_lock`.
//! 4. Taker sees `Tx_lock` confirmed, locks XMR to `S = S_m + S_t`, and reports it
//!    (`POST /xmr/swaps/:id/xmr-lock`, [`api::XmrLockNotice`]).
//! 5. Maker sees that lock with enough Monero confirmations and only then publishes his
//!    `Tx_redeem` signature adaptor-encrypted under `X` ([`api::RedeemOffer`] in the view).
//! 6. Taker completes it with `s_t` and broadcasts `Tx_redeem` (the DIVI is hers); the maker
//!    reads `s_t` back out of that transaction and sweeps the XMR with `s_m + s_t`.
//!
//! Abort: past `t_cancel` either side broadcasts `Tx_cancel`; the maker then completes
//! `Tx_refund` with `s_m` (DIVI back to him), which reveals `s_m` to the taker, who sweeps
//! her XMR back. If the maker stalls until `t_punish`, the taker alone signs `Tx_punish` and
//! takes the DIVI. If `Tx_lock` is still unspent at `t_late` (the taker never cancelled), the
//! maker alone takes it back.

pub mod api;
pub mod chain;
pub mod crypto;
pub mod jsig;
pub mod live;
pub mod maker;
pub mod mock;
pub mod nums;
mod redact;
pub mod taker;
pub mod wire;

pub use api::{
    JRoundReply, JRoundRequest, RefundEncsig, SetupReply, SetupRequest, SigsRequest, XmrLockNotice,
    XmrSwapView,
};
pub use chain::{check_divi_chain, DiviChain, MoneroChain, XmrOutput};
pub use maker::{XmrMaker, XmrMakerState};
pub use taker::{XmrTaker, XmrTakerState};

/// Piconero per "counter sat" (1e-8 XMR): quotes keep the engine-wide convention that the
/// counter amount is in 1e-8 units of the coin, Monero itself counts 1e-12.
pub const PICONERO_PER_COUNTER_SAT: u64 = 10_000;

/// Largest `t_cancel − mtp` the taker accepts from a maker's setup: 24 h, the longest
/// `cancel_after_secs` `tests/schedule.rs` still considers (the mainnet profile uses 12 h).
/// Without an upper bound a maker could hold her XMR for years.
pub const MAX_CANCEL_AFTER_SECS: u32 = 24 * 3600;

/// Largest `t_punish − t_cancel` the taker accepts: 12 h, the longest `punish_after_secs`
/// `tests/schedule.rs` considers (the mainnet profile uses 12 h).
pub const MAX_PUNISH_AFTER_SECS: u32 = 12 * 3600;

/// Timing and confirmations of the adaptor swap. All times in seconds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct XmrConfig {
    /// `Tx_cancel`'s `nLockTime` = DIVI median time past at setup + this. The taker must
    /// redeem before it; after it either side may cancel. (`Tx_refund` shares it.)
    pub cancel_after_secs: u32,
    /// `Tx_punish`'s `nLockTime` = `t_cancel` + this: the maker's window to refund.
    pub punish_after_secs: u32,
    /// `Tx_lock`'s late branch opens at `t_late` = `t_punish` + this: the maker alone may then
    /// spend a lock that is still unspent (a malleated `Tx_lock` none of the presigned cancel
    /// variants spend, or a taker who never cancelled). The taker cancels from `t_cancel` on,
    /// so she has the whole punish window plus this to get `Tx_cancel` buried first.
    pub late_after_secs: u32,
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
    /// How far behind the taker's own DIVI MTP (read in `prepare`, before the request) the
    /// maker's `t_cancel` clock may be: the setup floor on `t_cancel` is that MTP minus this,
    /// plus `cancel_after_secs` (`docs/plans/swap-poc/xmr-design.md`, "Maker MTP bound"). It
    /// bounds a maker that lies about, or omits, `maker_mtp`. Mainnet sets 900 s, derived from
    /// DIVI mainnet data (p99.9 of `MTP(h) − MTP(h−4)` = 831 s, plus 60 s; Human chose it
    /// 2026-10-23, `xmr-design.md` "L from mainnet data"). Testnet block timing was never
    /// measured, so it keeps `sigs_wait_secs`, which makes the floor never stricter than the
    /// one without it.
    pub maker_mtp_trail_secs: u64,
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
    /// [`ChainTiming::live`]: cancel 12 240 s, punish and late 3 600 s, margin 2 640 s.
    pub fn testnet() -> Self {
        XmrConfig {
            cancel_after_secs: 6 * 3600,
            punish_after_secs: 3 * 3600,
            late_after_secs: 3 * 3600,
            redeem_margin_secs: 3600,
            divi_confirmations: 3,
            xmr_confirmations: 10,
            divi_fee_sats: 100_000,
            sigs_wait_secs: 1800,
            maker_mtp_trail_secs: 1800,
            quote_expiry_secs: 60,
        }
    }

    /// Mainnet profile. Never selected while the mainnet refusals stand
    /// (`xmr-mainnet-plan.md` phase D). DIVI depth is the shared engine's mainnet DIVI
    /// depth, XMR depth Monero's spendable age; timelocks mirror the shared mainnet profile
    /// (`t_cancel` = its 12 h maker timeout, `t_punish` = its 24 h taker timeout) with a 2 h
    /// redeem margin. Derived minimums under [`ChainTiming::live`]: cancel 21 660 s, punish
    /// and late 7 200 s, margin 5 160 s. The presigned transactions cannot be fee-bumped, so their fee
    /// is the DIVI wallet's 0.01 DIVI/kB rate on a full kB, about 3× a 2-of-2 spend's size.
    pub fn mainnet() -> Self {
        XmrConfig {
            cancel_after_secs: 12 * 3600,
            punish_after_secs: 12 * 3600,
            late_after_secs: 12 * 3600,
            redeem_margin_secs: 2 * 3600,
            divi_confirmations: divi_swap::SwapConfig::profile(divi_swap::Profile::Mainnet)
                .divi_confirmations,
            xmr_confirmations: swap_chain_xmr::live_rpc::SPENDABLE_AGE as u32,
            divi_fee_sats: 1_000_000,
            sigs_wait_secs: 1800,
            maker_mtp_trail_secs: 900,
            quote_expiry_secs: 60,
        }
    }

    /// The engine profile for a swap [`divi_swap::Profile`]: [`XmrConfig::testnet`] or
    /// [`XmrConfig::mainnet`]. Selecting the mainnet numbers does not lift the runtime
    /// mainnet refusal (`live::profile_for`, `xmr-mainnet-plan.md` phase D).
    pub fn for_profile(profile: divi_swap::Profile) -> Self {
        match profile {
            divi_swap::Profile::Mainnet => Self::mainnet(),
            _ => Self::testnet(),
        }
    }

    /// Refuse a maker's quote whose terms are weaker than `self` (the taker's own floor):
    /// the maker's quote carries `maker_timeout_secs = cancel_after_secs`,
    /// `taker_timeout_secs = cancel_after_secs + punish_after_secs`, `btc_confirmations =
    /// xmr_confirmations` and `divi_confirmations` (`maker.rs` `quote`). `Err` names the
    /// term, the offered value and the floor.
    pub fn check_quote_terms(&self, q: &divi_swap::api::Quote) -> std::result::Result<(), String> {
        let refuse = |term: &str, offered: u64, min: u64| {
            Err(format!(
                "maker's {term} is {offered}, below the {min} floor of this taker's profile; \
                 refusing the offer"
            ))
        };
        let terms = [
            (
                "divi_confirmations",
                q.divi_confirmations as u64,
                self.divi_confirmations as u64,
            ),
            (
                "btc_confirmations (xmr lock)",
                q.btc_confirmations as u64,
                self.xmr_confirmations as u64,
            ),
            (
                "maker_timeout_secs (cancel_after_secs)",
                q.maker_timeout_secs as u64,
                self.cancel_after_secs as u64,
            ),
            (
                "taker_timeout_secs (cancel_after_secs + punish_after_secs)",
                q.taker_timeout_secs as u64,
                self.cancel_after_secs as u64 + self.punish_after_secs as u64,
            ),
        ];
        for (term, offered, min) in terms {
            if offered < min {
                return refuse(term, offered, min);
            }
        }
        Ok(())
    }

    /// Refuse a maker's setup timelocks weaker than `self` (the taker's own floor), given the
    /// DIVI median time past `mtp` the taker reads now. The maker set `t_cancel = mtp_setup +
    /// cancel_after_secs`.
    ///
    /// Without `maker_mtp` (an older maker) the taker cannot tell a short `t_cancel` from an
    /// older reading: it reads `mtp` after the `J` rounds, so `t_cancel` may have lost up to
    /// `sigs_wait_secs` (the longest a setup is kept open) of that span, and the floor
    /// tolerates it. With `maker_mtp` (the MTP the maker says it used) the floor is exact,
    /// `t_cancel − maker_mtp ≥ cancel_after_secs`, provided the stated MTP is not ahead of
    /// `mtp` and not older than `sigs_wait_secs` (the same staleness bound). The punish and
    /// late windows are exact differences either way.
    ///
    /// `prepare_mtp` is the taker's own MTP from before she sent the request (`None` on a
    /// record that predates it): when present, `t_cancel` must also be at least
    /// `prepare_mtp − maker_mtp_trail_secs + cancel_after_secs`, whether or not the maker
    /// states `maker_mtp`.
    pub fn check_setup_timelocks(
        &self,
        mtp: u32,
        prepare_mtp: Option<u32>,
        maker_mtp: Option<u32>,
        t_cancel: u32,
        t_punish: u32,
        t_late: u32,
    ) -> std::result::Result<(), String> {
        let slack = self.sigs_wait_secs.min(u32::MAX as u64) as u32;
        let cancel_min = match maker_mtp {
            None => mtp
                .saturating_add(self.cancel_after_secs)
                .saturating_sub(slack),
            Some(m) => {
                if m > mtp {
                    return Err(format!(
                        "maker states a DIVI MTP of {m}, {}s ahead of this taker's {mtp}; \
                         refusing the setup",
                        m - mtp
                    ));
                }
                if mtp - m > slack {
                    return Err(format!(
                        "maker states a DIVI MTP of {m}, {}s behind this taker's {mtp}, \
                         beyond the {slack}s a setup may take; refusing the setup",
                        mtp - m
                    ));
                }
                m.saturating_add(self.cancel_after_secs)
            }
        };
        let prepare_min = prepare_mtp.map(|p| {
            p.saturating_sub(self.maker_mtp_trail_secs.min(u32::MAX as u64) as u32)
                .saturating_add(self.cancel_after_secs)
        });
        let punish_min = t_cancel.saturating_add(self.punish_after_secs);
        let late_min = t_punish.saturating_add(self.late_after_secs);
        let refuse = |term: &str, offered: String, min: String| {
            Err(format!(
                "maker's {term} is {offered}, below the {min} floor of this taker's profile"
            ))
        };
        if let Some(pm) = prepare_min {
            if t_cancel < pm && t_cancel >= cancel_min {
                return Err(format!(
                    "maker's t_cancel is {}s short of the floor from this taker's own DIVI MTP \
                     before the request ({}s trail allowed); refusing the setup",
                    pm - t_cancel,
                    self.maker_mtp_trail_secs
                ));
            }
        }
        if t_cancel < cancel_min {
            return match maker_mtp {
                Some(m) => refuse(
                    "t_cancel",
                    format!(
                        "{}s after the maker's stated MTP",
                        t_cancel.saturating_sub(m)
                    ),
                    format!("{}s", self.cancel_after_secs),
                ),
                None => refuse(
                    "t_cancel",
                    format!("{}s after the DIVI MTP", t_cancel.saturating_sub(mtp)),
                    format!(
                        "{}s",
                        self.cancel_after_secs as u64 - slack.min(self.cancel_after_secs) as u64
                    ),
                ),
            };
        }
        if t_punish < punish_min {
            return refuse(
                "t_punish − t_cancel",
                format!("{}s", t_punish.saturating_sub(t_cancel)),
                format!("{}s", self.punish_after_secs),
            );
        }
        if t_late < late_min {
            return refuse(
                "t_late − t_punish",
                format!("{}s", t_late.saturating_sub(t_punish)),
                format!("{}s", self.late_after_secs),
            );
        }
        Ok(())
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

    /// Smallest `late_after_secs` under `t`: the taker's `Tx_cancel` (broadcast from
    /// `t_cancel`, a reaction) must be `divi_confirmations` deep before the late branch opens,
    /// else the maker could take the DIVI through it while her XMR stays locked. She already
    /// has the punish window for that; this window alone must cover it again, so a slow
    /// punish window never eats into it. Never below the margin.
    pub fn min_late_after_secs(&self, t: &ChainTiming) -> u64 {
        let taker = t.divi_mtp_lag_secs as u64
            + 2 * t.reaction_secs as u64
            + t.divi_wait(self.divi_confirmations + 1);
        taker.max(self.redeem_margin_secs as u64)
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
            (
                "late_after_secs",
                self.late_after_secs,
                self.min_late_after_secs(t),
                "Tx_cancel to confirm before the late branch opens",
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

    fn quote_at(c: &XmrConfig) -> divi_swap::api::Quote {
        divi_swap::api::Quote {
            id: "q".into(),
            offer_id: "o".into(),
            direction: divi_swap::api::Direction::TakerPaysBtc,
            counter_chain: divi_swap::Chain::Xmr,
            btc_amount: divi_swap::Amount(1),
            divi_amount: divi_swap::Amount(1),
            expires_at: 0,
            maker_btc_pubkey: [2; 33],
            maker_divi_pubkey: [2; 33],
            taker_timeout_secs: c.cancel_after_secs + c.punish_after_secs,
            maker_timeout_secs: c.cancel_after_secs,
            btc_confirmations: c.xmr_confirmations,
            divi_confirmations: c.divi_confirmations,
        }
    }

    const PROFILES: [divi_swap::Profile; 2] =
        [divi_swap::Profile::Testnet, divi_swap::Profile::Mainnet];

    #[test]
    fn for_profile_selects_the_two_configs() {
        assert_eq!(
            XmrConfig::for_profile(divi_swap::Profile::Testnet),
            XmrConfig::testnet()
        );
        assert_eq!(
            XmrConfig::for_profile(divi_swap::Profile::Mainnet),
            XmrConfig::mainnet()
        );
    }

    #[test]
    fn quote_terms_at_the_floor_or_stronger_are_accepted() {
        for p in PROFILES {
            let f = XmrConfig::for_profile(p);
            let mut q = quote_at(&f);
            f.check_quote_terms(&q).unwrap();
            q.divi_confirmations += 1;
            q.btc_confirmations += 1;
            q.maker_timeout_secs += 60;
            q.taker_timeout_secs += 60;
            f.check_quote_terms(&q).unwrap();
        }
        // A testnet taker takes the stronger mainnet maker.
        XmrConfig::testnet()
            .check_quote_terms(&quote_at(&XmrConfig::mainnet()))
            .unwrap();
    }

    #[test]
    fn each_quote_term_below_the_floor_is_refused_per_profile() {
        for p in PROFILES {
            let f = XmrConfig::for_profile(p);
            type Weaken = fn(&mut divi_swap::api::Quote);
            let cases: [(&str, Weaken); 4] = [
                ("divi_confirmations", |q| q.divi_confirmations -= 1),
                ("btc_confirmations (xmr lock)", |q| q.btc_confirmations -= 1),
                ("maker_timeout_secs", |q| q.maker_timeout_secs -= 1),
                ("taker_timeout_secs", |q| q.taker_timeout_secs -= 1),
            ];
            for (term, weaken) in cases {
                let mut q = quote_at(&f);
                weaken(&mut q);
                let e = f.check_quote_terms(&q).unwrap_err();
                assert!(e.contains(term) && e.contains("below the"), "{p}: {e}");
            }
        }
    }

    #[test]
    fn a_testnet_maker_is_refused_by_a_mainnet_floor() {
        let e = XmrConfig::mainnet()
            .check_quote_terms(&quote_at(&XmrConfig::testnet()))
            .unwrap_err();
        assert!(e.contains("below the"), "{e}");
    }

    #[test]
    fn setup_timelocks_at_the_floor_or_stronger_are_accepted() {
        for p in PROFILES {
            let f = XmrConfig::for_profile(p);
            let mtp = 1_800_000_000;
            let (c, pu) = (
                mtp + f.cancel_after_secs,
                mtp + f.cancel_after_secs + f.punish_after_secs,
            );
            f.check_setup_timelocks(mtp, None, None, c, pu, pu + f.late_after_secs)
                .unwrap();
            f.check_setup_timelocks(
                mtp,
                None,
                None,
                c + 1,
                pu + 2,
                pu + 2 + f.late_after_secs + 1,
            )
            .unwrap();
            // The taker read its MTP up to sigs_wait_secs after the maker set t_cancel.
            let later = mtp + f.sigs_wait_secs as u32;
            f.check_setup_timelocks(later, None, None, c, pu, pu + f.late_after_secs)
                .unwrap();
        }
    }

    #[test]
    fn t_cancel_is_floored_exactly_against_the_makers_stated_mtp() {
        for p in PROFILES {
            let f = XmrConfig::for_profile(p);
            let mtp = 1_800_000_000u32;
            // The maker read its MTP up to sigs_wait_secs before the taker read hers.
            for lag in [0, 1, f.sigs_wait_secs as u32] {
                let m = mtp - lag;
                let c = m + f.cancel_after_secs;
                let pu = c + f.punish_after_secs;
                let late = pu + f.late_after_secs;
                f.check_setup_timelocks(mtp, None, Some(m), c, pu, late)
                    .unwrap();
                f.check_setup_timelocks(mtp, None, Some(m), c + 1, pu + 1, late + 1)
                    .unwrap();
                // One second under the exact floor: refused, naming the term, however
                // much of the tolerant slack is left.
                let e = f
                    .check_setup_timelocks(mtp, None, Some(m), c - 1, pu, late)
                    .unwrap_err();
                assert!(
                    e.contains("t_cancel") && e.contains("maker's stated MTP"),
                    "{p}: {e}"
                );
            }
        }
    }

    #[test]
    fn a_stated_mtp_ahead_of_the_takers_or_too_stale_is_refused() {
        for p in PROFILES {
            let f = XmrConfig::for_profile(p);
            let mtp = 1_800_000_000u32;
            let ok = |m: u32| {
                let c = m + f.cancel_after_secs;
                let pu = c + f.punish_after_secs;
                f.check_setup_timelocks(mtp, None, Some(m), c, pu, pu + f.late_after_secs)
            };
            ok(mtp).unwrap();
            let e = ok(mtp + 1).unwrap_err();
            assert!(e.contains("ahead"), "{p}: {e}");
            ok(mtp - f.sigs_wait_secs as u32).unwrap();
            let e = ok(mtp - f.sigs_wait_secs as u32 - 1).unwrap_err();
            assert!(e.contains("behind") && e.contains("MTP"), "{p}: {e}");
        }
    }

    #[test]
    fn without_a_stated_mtp_the_tolerant_floor_is_kept() {
        let f = XmrConfig::testnet();
        let mtp = 1_800_000_000u32;
        let slack = f.sigs_wait_secs as u32;
        let c = mtp + f.cancel_after_secs - slack;
        let pu = c + f.punish_after_secs;
        f.check_setup_timelocks(mtp, None, None, c, pu, pu + f.late_after_secs)
            .unwrap();
        assert!(f
            .check_setup_timelocks(mtp, None, None, c - 1, pu, pu + f.late_after_secs)
            .is_err());
    }

    /// The taker reads `p` in `prepare`, the maker states `m`, the taker reads `mtp` at
    /// verification (`p ≤ mtp`). All the cases set the tolerance explicitly.
    fn trail_case(
        l: u64,
        p: u32,
        mtp: u32,
        m: Option<u32>,
        t_cancel_from: u32,
    ) -> Result<(), String> {
        let f = XmrConfig {
            maker_mtp_trail_secs: l,
            ..XmrConfig::testnet()
        };
        let c = t_cancel_from + f.cancel_after_secs;
        let pu = c + f.punish_after_secs;
        f.check_setup_timelocks(mtp, Some(p), m, c, pu, pu + f.late_after_secs)
    }

    #[test]
    fn a_maker_stating_an_old_mtp_is_refused_against_the_prepare_mtp() {
        let (p, mtp, l) = (1_800_000_000u32, 1_800_000_060u32, 360u64);
        // Oldest the staleness check accepts: mtp − sigs_wait_secs.
        let old = mtp - XmrConfig::testnet().sigs_wait_secs as u32;
        let e = trail_case(l, p, mtp, Some(old), old).unwrap_err();
        assert!(e.contains("own DIVI MTP before the request"), "{e}");
    }

    #[test]
    fn a_maker_omitting_its_mtp_is_refused_against_the_prepare_mtp() {
        let (p, mtp, l) = (1_800_000_000u32, 1_800_000_060u32, 360u64);
        // The tolerant floor alone would take mtp − sigs_wait_secs.
        let lying = mtp - XmrConfig::testnet().sigs_wait_secs as u32;
        assert!(trail_case(l, p, mtp, None, lying).is_err());
        // Honest and trailing by less than L, omitting the field: accepted.
        trail_case(l, p, mtp, None, p - 300).unwrap();
    }

    #[test]
    fn an_honest_maker_trailing_by_less_than_the_tolerance_is_accepted_and_beyond_refused() {
        let (p, mtp, l) = (1_800_000_000u32, 1_800_000_060u32, 360u64);
        for m in [mtp, p, p - 1, p - 300, p - l as u32] {
            trail_case(l, p, mtp, Some(m), m).unwrap();
        }
        for m in [p - l as u32 - 1, p - 1000] {
            assert!(trail_case(l, p, mtp, Some(m), m).is_err(), "m = {m}");
        }
        // L = 0 refuses any maker behind the taker's reading.
        trail_case(0, p, mtp, Some(p), p).unwrap();
        assert!(trail_case(0, p, mtp, Some(p - 1), p - 1).is_err());
    }

    #[test]
    fn a_record_without_a_prepare_mtp_keeps_todays_floor() {
        for p in PROFILES {
            let f = XmrConfig::for_profile(p);
            let mtp = 1_800_000_000u32;
            let slack = f.sigs_wait_secs as u32;
            for m in [None, Some(mtp), Some(mtp - slack)] {
                let from = m.unwrap_or(mtp - slack);
                let c = from + f.cancel_after_secs;
                let pu = c + f.punish_after_secs;
                let late = pu + f.late_after_secs;
                f.check_setup_timelocks(mtp, None, m, c, pu, late).unwrap();
                assert!(f
                    .check_setup_timelocks(mtp, None, m, c - 1, pu, late)
                    .is_err());
            }
        }
    }

    #[test]
    fn the_testnet_tolerance_is_sigs_wait_secs_and_changes_nothing() {
        // Testnet block timing was never measured, so it keeps `sigs_wait_secs`.
        for p in [divi_swap::Profile::Testnet] {
            let f = XmrConfig::for_profile(p);
            assert_eq!(f.maker_mtp_trail_secs, f.sigs_wait_secs, "{p:?}");
            assert_eq!(f.maker_mtp_trail_secs, 1800, "{p:?}");
            // With the default, a prepare MTP at or behind the verification MTP never
            // tightens the floor: same verdict at every t_cancel around it.
            let (prep, mtp) = (1_800_000_000u32, 1_800_000_060u32);
            for m in [None, Some(mtp), Some(mtp - f.sigs_wait_secs as u32)] {
                let edge = m.unwrap_or(mtp - f.sigs_wait_secs as u32) + f.cancel_after_secs;
                for c in [edge - 1, edge, edge + 1] {
                    let pu = c + f.punish_after_secs;
                    let late = pu + f.late_after_secs;
                    assert_eq!(
                        f.check_setup_timelocks(mtp, Some(prep), m, c, pu, late),
                        f.check_setup_timelocks(mtp, None, m, c, pu, late),
                        "{p:?} m={m:?} c={c}"
                    );
                }
            }
        }
    }

    /// Mainnet L, measured on DIVI mainnet (`xmr-design.md`, "L from mainnet data").
    const MAINNET_L: u32 = 900;

    fn mainnet_case(p: u32, mtp: u32, m: Option<u32>, t_cancel_from: u32) -> Result<(), String> {
        let f = XmrConfig::mainnet();
        let c = t_cancel_from + f.cancel_after_secs;
        let pu = c + f.punish_after_secs;
        f.check_setup_timelocks(mtp, Some(p), m, c, pu, pu + f.late_after_secs)
    }

    #[test]
    fn the_mainnet_trail_is_900_secs_from_mainnet_data() {
        assert_eq!(XmrConfig::mainnet().maker_mtp_trail_secs, MAINNET_L as u64);
    }

    #[test]
    fn on_mainnet_a_maker_trailing_by_900_secs_is_accepted_and_by_901_refused() {
        // Boundary in the code: `t_cancel ≥ prepare_mtp − L + cancel_after`, so a maker
        // whose stated MTP is exactly L behind the prepare MTP passes, one second more fails.
        let (p, mtp) = (1_800_000_000u32, 1_800_000_060u32);
        mainnet_case(p, mtp, Some(p - MAINNET_L), p - MAINNET_L).unwrap();
        let m = p - MAINNET_L - 1;
        let e = mainnet_case(p, mtp, Some(m), m).unwrap_err();
        assert!(e.contains("own DIVI MTP before the request"), "{e}");
        assert!(e.contains("900s trail"), "{e}");
    }

    #[test]
    fn on_mainnet_a_maker_omitting_its_mtp_gets_the_prepare_floor_with_l_900() {
        let (p, mtp) = (1_800_000_000u32, 1_800_000_060u32);
        // floor = prepare_mtp − 900 + cancel_after_secs
        mainnet_case(p, mtp, None, p - MAINNET_L).unwrap();
        assert!(mainnet_case(p, mtp, None, p - MAINNET_L - 1).is_err());
    }

    #[test]
    fn mainnet_with_l_900_still_validates_under_the_live_chain_timing() {
        XmrConfig::mainnet()
            .validate_for(&ChainTiming::live())
            .unwrap();
    }

    #[test]
    fn each_setup_timelock_below_the_floor_is_refused_per_profile() {
        for p in PROFILES {
            let f = XmrConfig::for_profile(p);
            let mtp = 1_800_000_000u32;
            let c = mtp + f.cancel_after_secs;
            let pu = c + f.punish_after_secs;
            let late = pu + f.late_after_secs;
            let slack = f.sigs_wait_secs as u32;
            // t_cancel just below mtp + cancel_after − slack
            let e = f
                .check_setup_timelocks(mtp, None, None, c - slack - 1, pu, late)
                .unwrap_err();
            assert!(e.contains("t_cancel"), "{p}: {e}");
            let e = f
                .check_setup_timelocks(mtp, None, None, c, pu - 1, late)
                .unwrap_err();
            assert!(e.contains("t_punish"), "{p}: {e}");
            let e = f
                .check_setup_timelocks(mtp, None, None, c, pu, late - 1)
                .unwrap_err();
            assert!(e.contains("t_late"), "{p}: {e}");
        }
    }

    #[test]
    fn the_numbers_are_the_existing_ones() {
        // This lane enforces the profiles' values; it must not move them.
        assert_eq!(XmrConfig::testnet().cancel_after_secs, 6 * 3600);
        assert_eq!(XmrConfig::testnet().punish_after_secs, 3 * 3600);
        assert_eq!(XmrConfig::mainnet().cancel_after_secs, 43_200);
    }

    #[test]
    fn mainnet_profile_pinned() {
        let m = XmrConfig::mainnet();
        assert_eq!(
            m,
            XmrConfig {
                cancel_after_secs: 43_200,
                punish_after_secs: 43_200,
                late_after_secs: 43_200,
                redeem_margin_secs: 7_200,
                divi_confirmations: 17,
                xmr_confirmations: 10,
                divi_fee_sats: 1_000_000,
                sigs_wait_secs: 1800,
                maker_mtp_trail_secs: 900,
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
                m.min_late_after_secs(&t),
                m.min_redeem_margin_secs(&t)
            ),
            (21_660, 7_200, 7_200, 5_160)
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
                c.min_late_after_secs(&t),
                c.min_redeem_margin_secs(&t)
            ),
            (12_240, 3_600, 3_600, 2_640)
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

        let mut c = base.clone();
        c.redeem_margin_secs = 5160; // below the maker's own refund need of 5 640 s
        c.punish_after_secs = c.min_punish_after_secs(&t) as u32;
        assert_eq!(c.punish_after_secs, 5640);
        c.validate().unwrap();
        c.punish_after_secs -= 1;
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("punish_after_secs"), "{e}");

        let mut c = base.clone();
        c.redeem_margin_secs = 5160;
        c.late_after_secs = c.min_late_after_secs(&t) as u32;
        assert_eq!(c.late_after_secs, 5640);
        c.validate().unwrap();
        c.late_after_secs -= 1;
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("late_after_secs"), "{e}");

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
            late_after_secs: 300,
            redeem_margin_secs: 100,
            sigs_wait_secs: 60,
            maker_mtp_trail_secs: 60,
            ..XmrConfig::testnet()
        };
        c.validate_for(&fast).unwrap();
        assert!(c.validate().is_err());
    }
}
