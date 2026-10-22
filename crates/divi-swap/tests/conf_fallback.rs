// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! F6 (`docs/plans/swap-poc/engine-review-brief.md`): a chain absent from
//! `SwapConfig::chains` takes the *mainnet* built-in, so the fallback is never less
//! conservative than any profile. Pinned here per `Chain` variant.
//!
//! Safety fields of `ChainParams` and which direction is "stricter":
//! * `confirmations`: higher is stricter (a deeper lock before the engine acts on it).
//! * `mtp_lag_secs`: higher is stricter (`SwapConfig::required_gap_secs` is
//!   `2 × max lag + claim margin`, so a larger lag demands a larger timeout gap).

use divi_swap::{Chain, ChainParams, Profile, SwapConfig};

const PROFILES: [Profile; 2] = [Profile::Mainnet, Profile::Testnet];

/// Number of `Chain` variants. Bump together with `ordinal` when a variant is added.
const CHAIN_COUNT: usize = 6;

/// Exhaustive on purpose (no wildcard arm): a new `Chain` variant fails to compile here
/// until it is classified, and `every_chain_is_listed_in_all` then fails until it is in
/// `Chain::ALL`, so the per-chain loops below cannot silently skip it.
fn ordinal(c: Chain) -> usize {
    match c {
        Chain::Divi => 0,
        Chain::Btc => 1,
        Chain::Ltc => 2,
        Chain::Zec => 3,
        Chain::Usdc => 4,
        Chain::Xmr => 5,
    }
}

/// Whether `chain_params` reads dedicated `SwapConfig` fields for `c` (never `chains`).
/// Exhaustive for the same reason as `ordinal`.
fn has_dedicated_fields(c: Chain) -> bool {
    match c {
        Chain::Divi | Chain::Btc => true,
        Chain::Ltc | Chain::Zec | Chain::Usdc | Chain::Xmr => false,
    }
}

/// Chains that resolve through `chains` with the mainnet built-in as the fallback.
fn fallback_chains() -> impl Iterator<Item = Chain> {
    Chain::ALL.into_iter().filter(|c| !has_dedicated_fields(*c))
}

#[test]
fn every_chain_is_listed_in_all() {
    let mut seen: Vec<usize> = Chain::ALL.into_iter().map(ordinal).collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..CHAIN_COUNT).collect::<Vec<_>>());
}

#[test]
fn mainnet_builtin_is_at_least_as_strict_as_testnet_on_every_safety_field() {
    for c in Chain::ALL {
        let m = ChainParams::builtin(c, Profile::Mainnet);
        let t = ChainParams::builtin(c, Profile::Testnet);
        assert!(
            m.confirmations >= t.confirmations,
            "{c}: mainnet confirmations {} < testnet {}",
            m.confirmations,
            t.confirmations
        );
        assert!(
            m.mtp_lag_secs >= t.mtp_lag_secs,
            "{c}: mainnet mtp_lag_secs {} < testnet {}",
            m.mtp_lag_secs,
            t.mtp_lag_secs
        );
        assert!(
            m.confirmations >= 1,
            "{c}: mainnet needs at least 1 confirmation"
        );
    }
}

#[test]
fn mainnet_profile_is_at_least_as_strict_as_testnet_on_the_swap_wide_fields() {
    let m = SwapConfig::profile(Profile::Mainnet);
    let t = SwapConfig::profile(Profile::Testnet);
    assert!(m.taker_timeout_secs >= t.taker_timeout_secs);
    assert!(m.maker_timeout_secs >= t.maker_timeout_secs);
    assert!(m.claim_margin_secs >= t.claim_margin_secs);
    assert!(m.btc_confirmations >= t.btc_confirmations);
    assert!(m.divi_confirmations >= t.divi_confirmations);
    assert!(m.btc_mtp_lag_secs >= t.btc_mtp_lag_secs);
    for c in Chain::ALL {
        assert!(
            m.confirmations(c) >= t.confirmations(c),
            "{c}: mainnet profile confirmations below testnet profile"
        );
        assert!(m.chain_params(c).mtp_lag_secs >= t.chain_params(c).mtp_lag_secs);
    }
}

#[test]
fn profile_chains_map_is_the_builtin_of_that_profile() {
    for p in PROFILES {
        let cfg = SwapConfig::profile(p);
        for c in fallback_chains() {
            assert_eq!(
                cfg.chains.get(&c),
                Some(&ChainParams::builtin(c, p)),
                "{c} under {p}"
            );
        }
        for c in Chain::ALL.into_iter().filter(|c| has_dedicated_fields(*c)) {
            assert!(!cfg.chains.contains_key(&c), "{c} has dedicated fields");
        }
    }
}

#[test]
fn a_chain_omitted_from_chains_takes_the_mainnet_builtin_under_both_profiles() {
    for p in PROFILES {
        let mut cfg = SwapConfig::profile(p);
        cfg.chains.clear();
        for c in fallback_chains() {
            let want = ChainParams::builtin(c, Profile::Mainnet);
            assert_eq!(cfg.chain_params(c), want, "{c} under {p}");
            assert_eq!(cfg.confirmations(c), want.confirmations, "{c} under {p}");
            // Never weaker than the profile's own built-in, on either field.
            let own = ChainParams::builtin(c, p);
            assert!(want.confirmations >= own.confirmations, "{c} under {p}");
            assert!(want.mtp_lag_secs >= own.mtp_lag_secs, "{c} under {p}");
        }
    }
}

#[test]
fn omitting_one_chain_does_not_disturb_the_others() {
    for p in PROFILES {
        for omitted in fallback_chains() {
            let mut cfg = SwapConfig::profile(p);
            cfg.chains.remove(&omitted);
            for c in fallback_chains() {
                let want = if c == omitted {
                    ChainParams::builtin(c, Profile::Mainnet)
                } else {
                    ChainParams::builtin(c, p)
                };
                assert_eq!(cfg.chain_params(c), want, "{c}, {omitted} omitted, {p}");
            }
        }
    }
}

#[test]
fn an_explicit_chains_entry_is_used_as_given() {
    for p in PROFILES {
        for c in fallback_chains() {
            // Distinct from both built-ins so a fallback or clamp would show.
            let explicit = ChainParams {
                confirmations: 77,
                mtp_lag_secs: 7777,
            };
            assert_ne!(explicit, ChainParams::builtin(c, Profile::Mainnet));
            assert_ne!(explicit, ChainParams::builtin(c, Profile::Testnet));
            let mut cfg = SwapConfig::profile(p);
            cfg.chains.insert(c, explicit);
            assert_eq!(cfg.chain_params(c), explicit, "{c} under {p}");
            assert_eq!(cfg.confirmations(c), 77, "{c} under {p}");

            // An explicit entry weaker than the mainnet built-in is honoured too: the
            // fallback applies only to an absent chain and never overrides an operator.
            let weaker = ChainParams {
                confirmations: 1,
                mtp_lag_secs: 1,
            };
            cfg.chains.insert(c, weaker);
            assert_eq!(cfg.chain_params(c), weaker, "{c} under {p}");
        }
    }
}

#[test]
fn btc_and_divi_ignore_chains_and_read_their_dedicated_fields() {
    for p in PROFILES {
        let base = SwapConfig::profile(p);
        let mut cfg = base.clone();
        let bogus = ChainParams {
            confirmations: 99,
            mtp_lag_secs: 9999,
        };
        cfg.chains.insert(Chain::Btc, bogus);
        cfg.chains.insert(Chain::Divi, bogus);
        assert_eq!(cfg.chain_params(Chain::Btc), base.chain_params(Chain::Btc));
        assert_eq!(
            cfg.chain_params(Chain::Divi),
            base.chain_params(Chain::Divi)
        );
        assert_eq!(cfg.confirmations(Chain::Btc), base.btc_confirmations);
        assert_eq!(cfg.confirmations(Chain::Divi), base.divi_confirmations);
        assert_eq!(
            cfg.chain_params(Chain::Divi).mtp_lag_secs,
            ChainParams::builtin(Chain::Divi, Profile::Mainnet).mtp_lag_secs
        );
        assert_eq!(
            cfg.chain_params(Chain::Btc).mtp_lag_secs,
            base.btc_mtp_lag_secs
        );
    }
}
