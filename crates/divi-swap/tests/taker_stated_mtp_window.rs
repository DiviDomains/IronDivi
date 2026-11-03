// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Reviewer question 2: a maker cannot shorten the taker's claim window with a self-stated
//! `maker_mtp_at_lock`. For every hashlock chain pair under the mainnet profile, drive
//! `check_maker_leg_locktime_exact` with the extreme in-window stated values and find the
//! shortest maker-leg locktime it still accepts; the taker's remaining window
//! (`locktime - observed maker-chain MTP`) must stay at or above the claim margin, and must
//! never be shorter than what the tolerant floor alone (no stated MTP) allows.

use divi_swap::config::{
    check_maker_leg_locktime, check_maker_leg_locktime_exact, OfferedTerms, SwapConfig,
};
use divi_swap::taker::TAKER_SAFETY_MARGIN_SECS;
use divi_swap::{Chain, Profile};

const TOL: u32 = 1800; // taker.rs LOCKTIME_TOLERANCE_SECS
const NOW: u32 = 1_800_000_000;
const CHAINS: [Chain; 4] = [Chain::Divi, Chain::Btc, Chain::Ltc, Chain::Zec];

fn lag(p: Profile, c: Chain) -> u32 {
    SwapConfig::profile(p).chain_params(c).mtp_lag_secs
}

/// Smallest maker-leg locktime the tolerant floor accepts.
fn min_tolerant(p: Profile, ch: (Chain, Chain), t: &OfferedTerms, tl: u32) -> u32 {
    let (mut lo, mut hi) = (0u32, u32::MAX / 2);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if check_maker_leg_locktime(p, ch, t, tl, mid, TOL).is_ok() {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

/// Smallest maker-leg locktime tolerant + exact floors accept for a stated MTP, if any.
fn min_exact(
    p: Profile,
    ch: (Chain, Chain),
    t: &OfferedTerms,
    tl: u32,
    stated: u32,
    obs: u32,
) -> Option<u32> {
    let ok = |l: u32| {
        check_maker_leg_locktime(p, ch, t, tl, l, TOL).is_ok()
            && check_maker_leg_locktime_exact(p, ch, t, tl, l, stated, obs, TOL).is_ok()
    };
    let hi = u32::MAX / 2;
    if !ok(hi) {
        return None;
    }
    let (mut lo, mut hi) = (0u32, hi);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if ok(mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Some(lo)
}

#[test]
fn a_stated_mtp_never_leaves_the_taker_less_than_the_claim_margin_on_any_mainnet_pair() {
    let p = Profile::Mainnet;
    let cfg = SwapConfig::profile(p);
    let mut worst = u32::MAX;
    for tc in CHAINS {
        for mc in CHAINS {
            if tc == mc {
                continue;
            }
            let ch = (tc, mc);
            let l = lag(p, tc).max(lag(p, mc));
            // The profile floor's own timeouts, and the narrowest gap the profile admits.
            let gap_min = SwapConfig::MIN_TIMEOUT_GAP_SECS.max(2 * l + cfg.claim_margin_secs);
            for (tt, mt) in [
                (cfg.taker_timeout_secs, cfg.maker_timeout_secs),
                (cfg.taker_timeout_secs, cfg.taker_timeout_secs - gap_min),
            ] {
                let terms = OfferedTerms {
                    taker_timeout_secs: tt,
                    maker_timeout_secs: mt,
                    counter_confirmations: 2,
                    divi_confirmations: 10,
                };
                // Worst skew: taker chain MTP lags true time by its lag, maker chain MTP is current.
                let tk_mtp = NOW - lag(p, tc);
                for drift in [-(TOL as i64), 0, TOL as i64] {
                    let tl = (tk_mtp as i64 + tt as i64 + drift) as u32;
                    let obs = NOW; // taker's own read of the maker chain
                    let base = min_tolerant(p, ch, &terms, tl);
                    let lowest = (tl as i64 - tt as i64 - TOL as i64 - l as i64) as u32;
                    let highest = obs + l;
                    for stated in [lowest, lowest + 1, obs - 3600, obs, highest - 1, highest] {
                        let m = min_exact(p, ch, &terms, tl, stated, obs).unwrap_or_else(|| {
                            panic!("{tc}/{mc}: in-window stated {stated} refused outright")
                        });
                        assert!(
                            m >= base,
                            "{tc}/{mc}: stated {stated} loosened the floor {m} < {base}"
                        );
                        let window = m as i64 - obs as i64;
                        assert!(
                            window >= TAKER_SAFETY_MARGIN_SECS as i64
                                && window >= cfg.claim_margin_secs as i64,
                            "{tc}/{mc} stated {stated}: window {window}s"
                        );
                        worst = worst.min(window as u32);
                    }
                    // Just outside the window on either side is refused.
                    assert!(check_maker_leg_locktime_exact(
                        p,
                        ch,
                        &terms,
                        tl,
                        u32::MAX / 2,
                        lowest - 1,
                        obs,
                        TOL
                    )
                    .is_err());
                    assert!(check_maker_leg_locktime_exact(
                        p,
                        ch,
                        &terms,
                        tl,
                        u32::MAX / 2,
                        highest + 1,
                        obs,
                        TOL
                    )
                    .is_err());
                }
            }
        }
    }
    // Pin the worst case: maker_timeout - 2*tolerance - 2*lag on the narrowest gap's pair.
    println!("worst remaining claim window across mainnet pairs: {worst}s");
    assert!(worst >= TAKER_SAFETY_MARGIN_SECS);
}
