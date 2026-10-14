// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Property over a grid of chain timings and schedules: every `XmrConfig` that passes
//! `validate_for` leaves each side the time its path needs. The paths are written out here as
//! worst-case wall-clock timelines, step by step, independently of `XmrConfig::min_*_secs`.

use divi_swap_xmr::{ChainTiming, XmrConfig};

/// Seconds each side is short of (negative) or ahead of its deadline, worst case.
struct Slack {
    /// Taker: XMR lock started before her own cutoff (`t_cancel − 2·margin`).
    taker_lock: i64,
    /// Taker: redeem offered before the maker stops offering (`t_cancel − margin`).
    taker_offer: i64,
    /// Taker: `Tx_redeem` buried before `Tx_cancel` is valid.
    taker_redeem: i64,
    /// Maker: `Tx_refund` buried before `Tx_punish` is valid.
    maker_refund: i64,
}

/// Worst-case timeline. Wall clock 0 is setup; a deadline set as MTP + d is reached, in wall
/// clock, up to `lag` early (the MTP lagged by `lag` when read, by 0 when the deadline hits).
fn timeline(c: &XmrConfig, t: &ChainTiming) -> Slack {
    let lag = t.divi_mtp_lag_secs as i64;
    let react = t.reaction_secs as i64;
    let blocks = |secs: u32, n: u32| (t.slow_block_factor * secs) as i64 * n as i64;
    let (cancel, margin, punish) = (
        c.cancel_after_secs as i64,
        c.redeem_margin_secs as i64,
        c.punish_after_secs as i64,
    );

    // Happy path, from setup.
    let mut now = c.sigs_wait_secs as i64; // her signatures, as late as the maker accepts
    now += react; // the maker broadcasts Tx_lock
    now += blocks(t.divi_block_secs, c.divi_confirmations); // it confirms
    now += react; // she sees it and locks XMR
    let taker_lock = (cancel - 2 * margin - lag) - now;
    now += blocks(t.xmr_block_secs, c.xmr_confirmations); // the XMR lock confirms
    now += react; // the maker's scan finds it and he offers redeem
    let taker_offer = (cancel - margin - lag) - now;

    // Redeem as late as she is allowed: MTP just short of t_cancel − margin.
    let need = react + blocks(t.divi_block_secs, c.divi_confirmations);
    let taker_redeem = (margin - lag) - need;

    // Refund, from the moment Tx_cancel becomes valid.
    let need = react // the maker notices t_cancel, broadcasts Tx_cancel
        + blocks(t.divi_block_secs, 1) // it is mined
        + react // Tx_refund goes out
        + blocks(t.divi_block_secs, c.divi_confirmations); // and is buried
    let maker_refund = (punish - lag) - need;

    Slack {
        taker_lock,
        taker_offer,
        taker_redeem,
        maker_refund,
    }
}

#[test]
fn validated_schedules_leave_every_side_its_time() {
    let mut passed = 0u64;
    let mut failed = 0u64;
    for divi_block_secs in [30, 60, 120] {
        for xmr_block_secs in [60, 120, 240] {
            for slow_block_factor in [1, 2, 3, 4] {
                for reaction_secs in [0, 300, 900] {
                    for divi_mtp_lag_secs in [0, 1800] {
                        let t = ChainTiming {
                            divi_block_secs,
                            xmr_block_secs,
                            slow_block_factor,
                            divi_mtp_lag_secs,
                            reaction_secs,
                        };
                        for divi_confirmations in [1, 3, 10, 20] {
                            for xmr_confirmations in [1, 3, 10, 20] {
                                let base = XmrConfig {
                                    divi_confirmations,
                                    xmr_confirmations,
                                    ..XmrConfig::testnet()
                                };
                                for c in schedules(&base) {
                                    if c.validate_for(&t).is_err() {
                                        failed += 1;
                                        continue;
                                    }
                                    passed += 1;
                                    let s = timeline(&c, &t);
                                    let ctx = || format!("{c:?} {t:?}");
                                    assert!(s.taker_lock >= 0, "taker lock late: {}", ctx());
                                    assert!(s.taker_offer >= 0, "redeem offer late: {}", ctx());
                                    assert!(s.taker_redeem >= 0, "redeem unburied: {}", ctx());
                                    assert!(s.maker_refund >= 0, "refund unburied: {}", ctx());
                                    assert!(c.punish_after_secs >= c.redeem_margin_secs);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // The grid exercises both sides of the check.
    assert!(
        passed > 1000 && failed > 1000,
        "{passed} passed, {failed} failed"
    );
}

/// Timelock combinations around the interesting range, on `base`'s confirmations.
fn schedules(base: &XmrConfig) -> Vec<XmrConfig> {
    let mut out = Vec::new();
    for margin_h in [1, 2, 3, 4, 6] {
        for cancel_h in [3, 6, 9, 12, 18, 24] {
            for punish_h in [1, 2, 3, 6, 12] {
                out.push(XmrConfig {
                    redeem_margin_secs: margin_h * 1800,
                    cancel_after_secs: cancel_h * 3600,
                    punish_after_secs: punish_h * 3600,
                    ..base.clone()
                });
            }
        }
    }
    out
}

/// And the derived minimums are tight: a config sitting exactly on them leaves zero slack
/// somewhere, so the check is not merely conservative by accident.
#[test]
fn minimal_schedule_is_tight() {
    let t = ChainTiming::live();
    for divi_confirmations in [1, 3, 10] {
        for xmr_confirmations in [1, 3, 10] {
            let mut c = XmrConfig {
                divi_confirmations,
                xmr_confirmations,
                ..XmrConfig::testnet()
            };
            c.redeem_margin_secs = c.min_redeem_margin_secs(&t) as u32;
            c.cancel_after_secs = c.min_cancel_after_secs(&t) as u32;
            c.punish_after_secs = c.min_punish_after_secs(&t) as u32;
            c.validate_for(&t).unwrap();
            let s = timeline(&c, &t);
            assert_eq!(s.taker_redeem, 0);
            assert_eq!(s.taker_lock.min(s.taker_offer), 0);
            assert!(s.maker_refund >= 0);
        }
    }
}
