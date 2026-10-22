// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Timeout and confirmation profiles (plan §3.1). Config, not constants.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::{Result, SwapError};
use crate::types::Chain;

/// Named profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Production timeouts.
    Mainnet,
    /// Public testnets (DIVI testnet, BTC signet).
    Testnet,
}

/// Settings of one counter chain other than BTC (BTC and DIVI keep their own fields in
/// [`SwapConfig`], which old configs already carry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainParams {
    /// Confirmations required on a lock on this chain.
    pub confirmations: u32,
    /// How far this chain's median time past lags wall clock.
    pub mtp_lag_secs: u32,
}

impl ChainParams {
    /// Built-in settings for `chain` under `profile`. MTP is the median of the last 11
    /// blocks, so it lags by about six block intervals; the lags below round that up.
    pub fn builtin(chain: Chain, profile: Profile) -> Self {
        let mainnet = profile == Profile::Mainnet;
        let (confirmations, mtp_lag_secs) = match chain {
            // 10-minute blocks.
            Chain::Btc => (if mainnet { 2 } else { 1 }, 3600),
            // 2.5-minute blocks: same wall-clock depth as BTC needs ~4× the blocks.
            Chain::Ltc => (if mainnet { 6 } else { 2 }, 1800),
            // ~25-second blocks (NU7, measured live; testnet confirmations raised from 3 to
            // 9 to keep the same ~225s finality depth this chain always intended — the
            // figure was set assuming 75s blocks before the real NU7 rate was measured).
            Chain::Zec => (if mainnet { 10 } else { 9 }, 1800),
            // 1-minute blocks.
            Chain::Divi => (if mainnet { 10 } else { 3 }, 1800),
            // ~12-second blocks; 12 confirmations is the common safe-finality heuristic for
            // Ethereum mainnet. No MTP smoothing on EVM (the contract itself compares against
            // the latest block's timestamp), so the lag only needs to cover block-time jitter.
            Chain::Usdc => (if mainnet { 12 } else { 3 }, if mainnet { 180 } else { 60 }),
            // 2-minute blocks; 10 confirmations on any network is what xmr-btc-swap ships with.
            // No CLTV on Monero: the lag only enters the shared timeout-gap bound.
            Chain::Xmr => (10, 1800),
        };
        ChainParams {
            confirmations,
            mtp_lag_secs,
        }
    }
}

/// Swap timing and confirmation requirements. All durations in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapConfig {
    /// Taker-leg HTLC: refund locktime = lock time + this.
    pub taker_timeout_secs: u32,
    /// Maker-leg HTLC: refund locktime = lock time + this.
    pub maker_timeout_secs: u32,
    /// Confirmations required on a BTC lock.
    pub btc_confirmations: u32,
    /// Confirmations required on a DIVI lock.
    pub divi_confirmations: u32,
    /// How far BTC median time past lags wall clock (≈ 1 h).
    pub btc_mtp_lag_secs: u32,
    /// Time the maker needs to get its taker-leg claim confirmed after learning the preimage.
    pub claim_margin_secs: u32,
    /// Quote validity.
    pub quote_expiry_secs: u32,
    /// Counter chains other than BTC. A chain missing here uses
    /// [`ChainParams::builtin`] with the mainnet profile (the stricter one), so configs
    /// written before counter chains existed stay safe.
    #[serde(default)]
    pub chains: BTreeMap<Chain, ChainParams>,
}

impl SwapConfig {
    /// Minimum gap between the two timeouts regardless of the other parameters.
    pub const MIN_TIMEOUT_GAP_SECS: u32 = 3 * 3600;

    /// The built-in profile.
    pub fn profile(p: Profile) -> Self {
        match p {
            Profile::Mainnet => SwapConfig {
                taker_timeout_secs: 24 * 3600,
                maker_timeout_secs: 12 * 3600,
                btc_confirmations: 2,
                divi_confirmations: 10,
                btc_mtp_lag_secs: 3600,
                claim_margin_secs: 3600,
                quote_expiry_secs: 60,
                chains: Self::builtin_chains(p),
            },
            Profile::Testnet => SwapConfig {
                taker_timeout_secs: 6 * 3600,
                maker_timeout_secs: 3 * 3600,
                btc_confirmations: 1,
                divi_confirmations: 3,
                btc_mtp_lag_secs: 3600,
                claim_margin_secs: 1800,
                quote_expiry_secs: 60,
                chains: Self::builtin_chains(p),
            },
        }
    }

    fn builtin_chains(p: Profile) -> BTreeMap<Chain, ChainParams> {
        Chain::ALL
            .into_iter()
            .filter(|c| !matches!(c, Chain::Divi | Chain::Btc))
            .map(|c| (c, ChainParams::builtin(c, p)))
            .collect()
    }

    /// Settings of `chain`: the dedicated fields for DIVI and BTC, `chains` (or the
    /// mainnet built-in) for the others.
    pub fn chain_params(&self, chain: Chain) -> ChainParams {
        match chain {
            Chain::Divi => ChainParams {
                confirmations: self.divi_confirmations,
                mtp_lag_secs: ChainParams::builtin(Chain::Divi, Profile::Mainnet).mtp_lag_secs,
            },
            Chain::Btc => ChainParams {
                confirmations: self.btc_confirmations,
                mtp_lag_secs: self.btc_mtp_lag_secs,
            },
            c => self
                .chains
                .get(&c)
                .copied()
                .unwrap_or_else(|| ChainParams::builtin(c, Profile::Mainnet)),
        }
    }

    /// Confirmations required on a lock on `chain`.
    pub fn confirmations(&self, chain: Chain) -> u32 {
        self.chain_params(chain).confirmations
    }

    /// Largest MTP lag of any chain a swap can lock on.
    pub fn max_mtp_lag_secs(&self) -> u32 {
        Chain::ALL
            .into_iter()
            .map(|c| self.chain_params(c).mtp_lag_secs)
            .max()
            .unwrap_or(self.btc_mtp_lag_secs)
    }

    /// Required minimum of `taker_timeout − maker_timeout`.
    pub fn required_gap_secs(&self) -> u32 {
        Self::MIN_TIMEOUT_GAP_SECS.max(2 * self.max_mtp_lag_secs() + self.claim_margin_secs)
    }

    /// Enforce `taker_timeout − maker_timeout ≥ max(3 h, 2 × max MTP lag + claim margin)`
    /// (the maximum over every chain, BTC's hour by default).
    ///
    /// ```
    /// use divi_swap::{Profile, SwapConfig};
    /// assert!(SwapConfig::profile(Profile::Testnet).validate().is_ok());
    /// let mut c = SwapConfig::profile(Profile::Testnet);
    /// c.maker_timeout_secs = 4 * 3600;
    /// assert!(c.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        let gap = self
            .taker_timeout_secs
            .checked_sub(self.maker_timeout_secs)
            .ok_or_else(|| {
                SwapError::InvalidParams("taker timeout must exceed maker timeout".into())
            })?;
        if gap < self.required_gap_secs() {
            return Err(SwapError::InvalidParams(format!(
                "timeout gap {gap}s < required {}s",
                self.required_gap_secs()
            )));
        }
        if Chain::ALL.into_iter().any(|c| self.confirmations(c) == 0) {
            return Err(SwapError::InvalidParams(
                "confirmations must be at least 1".into(),
            ));
        }
        Ok(())
    }
}

/// Whether `network` is `chain`'s mainnet. Every coin spells it `"mainnet"`; USDC's EVM
/// networks (`swap_chain_evm::UsdcNetwork`, which this crate cannot depend on) are only
/// `sepolia` and `base-sepolia` today, so its mainnet names are matched here by variant
/// name (`ethereum`, `base`) until the usdc lane adds them.
fn is_mainnet_network(chain: Chain, network: &str) -> bool {
    network == "mainnet" || (chain == Chain::Usdc && matches!(network, "ethereum" | "base"))
}

/// One configured coin: its chain, its `network` string, and its `allow_mainnet` flag
/// (`None` where the section has no such flag, e.g. USDC).
pub type ConfiguredNetwork<'a> = (Chain, &'a str, Option<bool>);

/// Refuse a swap profile that disagrees with the networks of the coins in use. Shared by
/// `divi-swapd` (at config load) and `divi-swap` (before any network call).
///
/// * `Profile::Mainnet`: every coin must be on its mainnet and, where it has the flag,
///   `allow_mainnet = true`.
/// * `Profile::Testnet`: no coin may be on a mainnet (real funds under testnet timeouts).
///
/// ```
/// use divi_swap::config::check_profile_networks;
/// use divi_swap::{Chain, Profile};
/// assert!(check_profile_networks(Profile::Testnet, &[(Chain::Btc, "signet", Some(false))]).is_ok());
/// assert!(check_profile_networks(Profile::Mainnet, &[(Chain::Btc, "signet", Some(false))]).is_err());
/// ```
pub fn check_profile_networks(
    profile: Profile,
    coins: &[ConfiguredNetwork<'_>],
) -> std::result::Result<(), String> {
    for &(chain, network, allow_mainnet) in coins {
        let mainnet = is_mainnet_network(chain, network);
        match profile {
            Profile::Mainnet if !mainnet => {
                return Err(format!(
                    "profile = \"mainnet\" but [{chain}].network = \"{network}\" — a mainnet \
                     profile with a test network is refused"
                ));
            }
            Profile::Mainnet if allow_mainnet == Some(false) => {
                return Err(format!(
                    "profile = \"mainnet\" but [{chain}].allow_mainnet is not set — mainnet \
                     moves real money and needs the explicit opt-in"
                ));
            }
            Profile::Testnet if mainnet => {
                return Err(format!(
                    "profile = \"testnet\" but [{chain}].network = \"{network}\" — real funds \
                     under testnet timeouts are refused; set profile = \"mainnet\""
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_profiles_valid() {
        SwapConfig::profile(Profile::Mainnet).validate().unwrap();
        SwapConfig::profile(Profile::Testnet).validate().unwrap();
    }

    #[test]
    fn lag_dominates_gap() {
        let mut c = SwapConfig::profile(Profile::Testnet);
        c.btc_mtp_lag_secs = 2 * 3600;
        assert_eq!(c.required_gap_secs(), 4 * 3600 + 1800);
        assert!(c.validate().is_err());
    }

    #[test]
    fn btc_and_divi_values_unchanged() {
        let c = SwapConfig::profile(Profile::Testnet);
        assert_eq!(c.confirmations(Chain::Btc), 1);
        assert_eq!(c.confirmations(Chain::Divi), 3);
        assert_eq!(c.chain_params(Chain::Btc).mtp_lag_secs, 3600);
        assert_eq!(c.required_gap_secs(), SwapConfig::MIN_TIMEOUT_GAP_SECS);
        let m = SwapConfig::profile(Profile::Mainnet);
        assert_eq!(
            (m.confirmations(Chain::Btc), m.confirmations(Chain::Divi)),
            (2, 10)
        );
        assert_eq!(c.confirmations(Chain::Ltc), 2);
        assert_eq!(m.confirmations(Chain::Zec), 10);
    }

    #[test]
    fn per_chain_settings_apply() {
        let mut c = SwapConfig::profile(Profile::Testnet);
        c.chains.insert(
            Chain::Ltc,
            ChainParams {
                confirmations: 4,
                mtp_lag_secs: 7200,
            },
        );
        assert_eq!(c.confirmations(Chain::Ltc), 4);
        // LTC's lag now dominates the gap.
        assert_eq!(c.required_gap_secs(), 2 * 7200 + 1800);
        assert!(c.validate().is_err());
        c.chains.get_mut(&Chain::Ltc).unwrap().mtp_lag_secs = 1800;
        c.validate().unwrap();
        c.chains.get_mut(&Chain::Ltc).unwrap().confirmations = 0;
        assert!(c.validate().is_err());
    }

    /// A `SwapConfig` written before per-chain settings existed (no `chains`) still parses,
    /// keeps its BTC/DIVI values, and gets the strict built-ins for the new chains.
    #[test]
    fn old_config_toml_parses() {
        const OLD: &str = r#"
taker_timeout_secs = 21600
maker_timeout_secs = 10800
btc_confirmations = 1
divi_confirmations = 3
btc_mtp_lag_secs = 3600
claim_margin_secs = 1800
quote_expiry_secs = 60
"#;
        let c: SwapConfig = toml::from_str(OLD).unwrap();
        c.validate().unwrap();
        assert!(c.chains.is_empty());
        let t = SwapConfig::profile(Profile::Testnet);
        assert_eq!(
            (
                c.taker_timeout_secs,
                c.maker_timeout_secs,
                c.claim_margin_secs
            ),
            (
                t.taker_timeout_secs,
                t.maker_timeout_secs,
                t.claim_margin_secs
            )
        );
        assert_eq!(c.confirmations(Chain::Btc), 1);
        assert_eq!(c.confirmations(Chain::Divi), 3);
        assert_eq!(c.required_gap_secs(), t.required_gap_secs());
        assert_eq!(
            c.chain_params(Chain::Ltc),
            ChainParams::builtin(Chain::Ltc, Profile::Mainnet)
        );
        // And the new shape round-trips.
        let text = toml::to_string(&t).unwrap();
        assert_eq!(toml::from_str::<SwapConfig>(&text).unwrap(), t);
    }

    const ALL_TEST: [ConfiguredNetwork<'static>; 5] = [
        (Chain::Btc, "signet", Some(false)),
        (Chain::Ltc, "testnet", Some(false)),
        (Chain::Zec, "testnet", Some(false)),
        (Chain::Xmr, "stagenet", Some(false)),
        (Chain::Usdc, "sepolia", None),
    ];
    const ALL_MAIN: [ConfiguredNetwork<'static>; 5] = [
        (Chain::Btc, "mainnet", Some(true)),
        (Chain::Ltc, "mainnet", Some(true)),
        (Chain::Zec, "mainnet", Some(true)),
        (Chain::Xmr, "mainnet", Some(true)),
        (Chain::Usdc, "ethereum", None),
    ];

    #[test]
    fn profile_network_all_agree_is_ok() {
        assert!(check_profile_networks(Profile::Testnet, &ALL_TEST).is_ok());
        assert!(check_profile_networks(Profile::Mainnet, &ALL_MAIN).is_ok());
        assert!(check_profile_networks(Profile::Mainnet, &[]).is_ok());
        assert!(check_profile_networks(Profile::Testnet, &[]).is_ok());
    }

    #[test]
    fn mainnet_profile_refuses_a_test_network_for_every_coin() {
        for (i, coin) in ALL_TEST.iter().enumerate() {
            let mut set = ALL_MAIN;
            set[i] = (coin.0, coin.1, ALL_MAIN[i].2);
            let e = check_profile_networks(Profile::Mainnet, &set).unwrap_err();
            assert!(
                e.contains(&format!("[{}].network = \"{}\"", coin.0, coin.1))
                    && e.contains("mainnet profile with a test network is refused"),
                "{e}"
            );
        }
    }

    #[test]
    fn testnet_profile_refuses_a_mainnet_network_for_every_coin() {
        for (i, coin) in ALL_MAIN.iter().enumerate() {
            let mut set = ALL_TEST;
            set[i] = (coin.0, coin.1, ALL_TEST[i].2);
            let e = check_profile_networks(Profile::Testnet, &set).unwrap_err();
            assert!(
                e.contains(&format!("[{}].network = \"{}\"", coin.0, coin.1))
                    && e.contains("real funds under testnet timeouts are refused")
                    && e.contains("set profile = \"mainnet\""),
                "{e}"
            );
        }
        let e =
            check_profile_networks(Profile::Testnet, &[(Chain::Usdc, "base", None)]).unwrap_err();
        assert!(e.contains("[usdc].network = \"base\""), "{e}");
    }

    #[test]
    fn mainnet_profile_without_allow_mainnet_is_refused() {
        for i in 0..4 {
            let mut set = ALL_MAIN;
            set[i].2 = Some(false);
            let e = check_profile_networks(Profile::Mainnet, &set).unwrap_err();
            assert!(
                e.contains(&format!("[{}].allow_mainnet is not set", set[i].0)),
                "{e}"
            );
        }
    }
}
