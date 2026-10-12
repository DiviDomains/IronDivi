// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Build-plan step 7's `t_cancel < t_refund < t_punish` ordering (`xmr-design.md`'s
//! `## Protocol` table) has, until now, had no mainnet-safe schedule anywhere in this
//! crate -- every template builder in [`crate::swap_templates`]/[`crate::multisig`]
//! takes `lock_time` as a plain parameter, by design (this crate doesn't own offer
//! negotiation or network profiles; see `xmr-design.md`'s `## Build plan`/
//! `## Recommendation`). Found via the mainnet-readiness review: "no built-in schedule
//! anywhere... no mainnet-safe margin scheme exists to review." This module is that
//! scheme: a built-in safe default for `t_refund`/`t_punish` given a caller-supplied
//! `t_cancel`, plus [`validate_schedule`] to catch an unsafe ordering before it's ever
//! burned into presigned transactions (DIVI has no CSV backstop if the ordering is
//! wrong -- see `xmr-design.md`'s `## Risks`).
//!
//! `t_cancel` itself stays a caller parameter, not defaulted here: picking it well
//! depends on things this crate doesn't track (how deep the DIVI *and* Monero locks
//! need to confirm, which is [`crate::live_rpc::DIVI_CONFIRMATIONS_MAINNET`] plus
//! Monero's mainnet depth -- `xmr-design.md`'s `## Risks` already flags Monero's
//! confirmation depth as "~20 min minimum on stagenet, worse on mainnet"). What *is*
//! safe to default, independent of all that: the margins between the three deadlines
//! once `t_cancel` is picked.

/// DIVI's own block interval, matching `crates/divi-swap/src/config.rs`'s comment
/// next to `Chain::Divi`'s confirmation depth ("1-minute blocks") -- used only to turn
/// this module's margins into block counts, not drift-tested the way
/// [`crate::live_rpc::DIVI_CONFIRMATIONS_MAINNET`] is, since `config.rs` doesn't
/// expose it as a literal field value (just that comment) and a wrong guess here only
/// makes the built-in default's real-world margin bigger or smaller, not unsafe --
/// [`validate_schedule`] is what actually enforces safety, independent of this number.
pub const DIVI_BLOCK_SECS: u32 = 60;

/// Built-in default margin between `t_cancel` and `t_refund`: zero. `Tx_refund` spends
/// `Tx_cancel`'s own output (`xmr-design.md`'s `## Protocol` table), so it cannot be
/// mined before `Tx_cancel` is anyway -- delaying its `nLockTime` further than
/// `t_cancel` buys nothing. This is the design doc's own documented simplification,
/// not a new choice made here.
pub const DEFAULT_REFUND_MARGIN_BLOCKS: u32 = 0;

/// Built-in default margin between `t_refund` and `t_punish`: 3 hours' worth of DIVI
/// blocks at [`DIVI_BLOCK_SECS`]. Generous on purpose (`xmr-design.md`'s `## Risks`:
/// "mitigate the same way the existing BTC/DIVI HTLC lane does: generous margins") --
/// this is the window an honestly slow (not stalling) Maker has to notice `t_refund`
/// matured, build, sign, and broadcast `Tx_refund` before Taker could punish him for
/// it instead; too thin here turns ordinary network/operational latency into a false
/// "Maker went silent" punish. Same proportion the multichain lane already chose for
/// `divi-swap-xmr::XmrConfig::testnet` (`t_cancel = MTP+6h`, `t_punish = +3h` -- half
/// the cancel window), adopted here as this crate's one network-profile-free default
/// since (unlike `DIVI_CONFIRMATIONS_MAINNET`) there is no single shared-engine field
/// to mirror: this swap's 3-deadline shape has no analog in [`SwapConfig`]'s 2-deadline
/// one (`taker_timeout_secs`/`maker_timeout_secs`).
pub const DEFAULT_PUNISH_MARGIN_BLOCKS: u32 = 3 * 3600 / DIVI_BLOCK_SECS;

/// `t_refund`/`t_punish` fail [`validate_schedule`]'s ordering/margin invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScheduleError {
    /// `t_refund` is before `t_cancel` -- `Tx_refund` would be minable before the
    /// output it spends (`Tx_cancel`) could even exist yet.
    #[error("t_refund ({t_refund}) must be >= t_cancel ({t_cancel})")]
    RefundBeforeCancel { t_cancel: u32, t_refund: u32 },
    /// `t_punish` isn't strictly after `t_refund` -- no window in which Maker can
    /// still act (broadcast `Tx_refund`) before Taker's punish becomes valid, so the
    /// "stalling" the punish path is supposed to deter can't be distinguished from
    /// ordinary confirmation latency.
    #[error("t_punish ({t_punish}) must be strictly > t_refund ({t_refund})")]
    PunishNotAfterRefund { t_refund: u32, t_punish: u32 },
}

/// The built-in safe default: `t_refund`/`t_punish` derived from a caller-supplied
/// `t_cancel` using [`DEFAULT_REFUND_MARGIN_BLOCKS`]/[`DEFAULT_PUNISH_MARGIN_BLOCKS`].
/// Always passes [`validate_schedule`] (exercised by this module's own tests) --
/// callers who need a different margin (e.g. a live example's deliberately short,
/// explicitly-flagged-as-unsafe testnet timelocks) should build their own schedule and
/// still run it through [`validate_schedule`] rather than skip the check.
pub fn default_schedule(t_cancel: u32) -> (u32, u32) {
    let t_refund = t_cancel + DEFAULT_REFUND_MARGIN_BLOCKS;
    let t_punish = t_refund + DEFAULT_PUNISH_MARGIN_BLOCKS;
    (t_refund, t_punish)
}

/// Rejects any `t_cancel < t_refund < t_punish` ordering `xmr-design.md`'s `## Protocol`
/// table doesn't allow (`t_refund >= t_cancel`, `t_punish > t_refund` strictly) --
/// independent of margin size, so it also catches a schedule that's merely *backwards*,
/// not just one that's too tight.
pub fn validate_schedule(t_cancel: u32, t_refund: u32, t_punish: u32) -> Result<(), ScheduleError> {
    if t_refund < t_cancel {
        return Err(ScheduleError::RefundBeforeCancel { t_cancel, t_refund });
    }
    if t_punish <= t_refund {
        return Err(ScheduleError::PunishNotAfterRefund { t_refund, t_punish });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_schedule_is_always_valid() {
        let t_cancel = 500_000;
        let (t_refund, t_punish) = default_schedule(t_cancel);
        assert_eq!(t_refund, t_cancel, "default refund margin is zero");
        assert_eq!(t_punish, t_refund + DEFAULT_PUNISH_MARGIN_BLOCKS);
        validate_schedule(t_cancel, t_refund, t_punish).unwrap();
    }

    #[test]
    fn equal_cancel_and_refund_is_allowed() {
        // The design doc's documented simplification -- t_refund == t_cancel is not
        // itself an unsafe ordering, unlike t_refund < t_cancel.
        validate_schedule(1000, 1000, 1181).unwrap();
    }

    #[test]
    fn refund_before_cancel_is_rejected() {
        let err = validate_schedule(1000, 999, 2000).unwrap_err();
        assert_eq!(
            err,
            ScheduleError::RefundBeforeCancel {
                t_cancel: 1000,
                t_refund: 999
            }
        );
    }

    #[test]
    fn punish_equal_to_refund_is_rejected() {
        // No gap at all -- Taker could punish in the very block Maker's Tx_refund
        // first becomes valid, leaving him no real window to act first.
        let err = validate_schedule(1000, 1200, 1200).unwrap_err();
        assert_eq!(
            err,
            ScheduleError::PunishNotAfterRefund {
                t_refund: 1200,
                t_punish: 1200
            }
        );
    }

    #[test]
    fn punish_before_refund_is_rejected() {
        let err = validate_schedule(1000, 1200, 1100).unwrap_err();
        assert_eq!(
            err,
            ScheduleError::PunishNotAfterRefund {
                t_refund: 1200,
                t_punish: 1100
            }
        );
    }

    #[test]
    fn punish_one_block_after_refund_is_accepted() {
        // validate_schedule enforces ordering, not a minimum margin size -- a razor-
        // thin but strictly-positive gap is "unsafe" in the sense of being a bad
        // operational choice, not in the sense this function exists to catch (that's
        // why default_schedule's own margin is generous, not minimal).
        validate_schedule(1000, 1200, 1201).unwrap();
    }
}
