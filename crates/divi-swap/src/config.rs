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

use crate::api::Quote;
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

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Profile::Mainnet => "mainnet",
            Profile::Testnet => "testnet",
        })
    }
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
            // 1-minute blocks; mainnet 17 = lock-reversal risk below 0.1 % against 25 % of stake
            // (docs/plans/swap-poc/divi-confirmations.md, Bert chose 17 on 2026-10-23).
            Chain::Divi => (if mainnet { 17 } else { 3 }, 1800),
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

/// How much time must be left before the maker-leg locktime for the taker to broadcast its
/// **first** maker-leg claim ([`ClaimDeadline::builtin`]; `Taker::with_claim_deadline`
/// overrides one chain).
///
/// Once that claim is out the preimage is public, and the maker may claim the taker leg with
/// it at any time before the taker-leg locktime. The taker only keeps the maker leg if its
/// claim confirms before the maker can refund (MTP reaching the maker-leg locktime), so it
/// needs enough blocks to get mined in, not just enough seconds. Below the margin the taker
/// declines for good and waits for its taker-leg refund: nothing has been revealed yet, so
/// both sides get their coins back. A claim already broadcast is never abandoned.
///
/// The margin is `max(min_secs, min_blocks × block_secs)`: both must be met.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimDeadline {
    /// Target block interval of the chain, in seconds.
    pub block_secs: u32,
    /// Blocks that must still be due before the locktime.
    pub min_blocks: u32,
    /// Seconds of MTP that must be left before the locktime.
    pub min_secs: u32,
}

impl ClaimDeadline {
    /// Built-in margin for a maker leg on `chain`, the same on every profile (it is about how
    /// fast the chain mines, not about how much the counterparty is trusted). Never below the
    /// 1800 s every chain had before margins were per chain
    /// (`taker::TAKER_SAFETY_MARGIN_SECS`).
    pub fn builtin(chain: Chain) -> Self {
        let (block_secs, min_blocks, min_secs) = match chain {
            // 10-minute blocks. Six blocks: the chance of no block at all in an hour is
            // e^-6 ≈ 0.25 %, against e^-3 ≈ 5 % for the three blocks 1800 s used to give,
            // and every block in between is a fee-bump (RBF) step.
            Chain::Btc => (600, 6, 3600),
            // 2.5-minute blocks: 1800 s is twelve blocks (no block in 30 min: e^-12, about
            // 6 in a million), and each one is a CPFP step.
            Chain::Ltc => (150, 12, 1800),
            // 75 s is the protocol target (ZIP-208); it is counted at the target, not the
            // ~25 s measured on NU7, so the block arm never reads more blocks than mainnet
            // mines. 24 blocks = 1800 s. Neither replacement nor CPFP helps on ZEC
            // (docs/plans/swap-poc/status/engine.md, DJ round), so the claim is resent at its
            // first fee and this margin is the whole defence.
            Chain::Zec => (75, 24, 1800),
            // 1-minute blocks; 30 blocks = 1800 s. DIVI Core relays no replacement and its
            // miner ignores CPFP (engine.md, DJ round); it has no mempool size limit to evict
            // from, so the claim is resent unchanged and thirty blocks is ample.
            Chain::Divi => (60, 30, 1800),
            // ~12-second blocks: 1800 s is 150 of them, far over the 180 s timestamp lag;
            // the seconds floor binds, not the block count.
            Chain::Usdc => (12, 150, 1800),
            // 2-minute blocks. Monero has no CLTV, so no HTLC claim ever runs against it;
            // the value only keeps every chain covered.
            Chain::Xmr => (120, 15, 1800),
        };
        ClaimDeadline {
            block_secs,
            min_blocks,
            min_secs,
        }
    }

    /// Seconds that must be left before the locktime: `max(min_secs, min_blocks ×
    /// block_secs)`, saturating.
    pub fn margin_secs(&self) -> u32 {
        self.min_secs
            .max(self.min_blocks.saturating_mul(self.block_secs))
    }

    /// `Ok` if a first claim may still go out with the chain at `mtp` and the maker-leg
    /// locktime at `locktime`; otherwise why not.
    pub fn check(&self, chain: Chain, mtp: u32, locktime: u32) -> std::result::Result<(), String> {
        let left = i64::from(locktime) - i64::from(mtp);
        let blocks = left.max(0) / i64::from(self.block_secs.max(1));
        if left < i64::from(self.min_secs) || blocks < i64::from(self.min_blocks) {
            return Err(format!(
                "maker-leg locktime {locktime} is {left}s (~{blocks} {chain} blocks) after its \
                 chain's MTP {mtp}, short of the claim deadline (at least {}s and {} blocks); not \
                 claiming, waiting for the taker-leg refund",
                self.min_secs, self.min_blocks
            ));
        }
        Ok(())
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
                divi_confirmations: 17,
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

    /// Required minimum of `taker_timeout − maker_timeout`, saturating at `u32::MAX`.
    pub fn required_gap_secs(&self) -> u32 {
        u32::try_from(self.required_gap()).unwrap_or(u32::MAX)
    }

    /// `max(3 h, 2 × max MTP lag + claim margin)`, exact: lag and margin come from config.
    fn required_gap(&self) -> u64 {
        let need = 2 * u64::from(self.max_mtp_lag_secs()) + u64::from(self.claim_margin_secs);
        need.max(u64::from(Self::MIN_TIMEOUT_GAP_SECS))
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
        if u64::from(gap) < self.required_gap() {
            return Err(SwapError::InvalidParams(format!(
                "timeout gap {gap}s < required {}s",
                self.required_gap()
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

/// The terms a maker puts in a quote that bind the taker's money: how long each leg is
/// locked and how deep each lock must be before the other side acts. All durations in
/// seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferedTerms {
    /// Taker-leg HTLC lifetime.
    pub taker_timeout_secs: u32,
    /// Maker-leg HTLC lifetime.
    pub maker_timeout_secs: u32,
    /// Confirmations required on a lock on the counter chain.
    pub counter_confirmations: u32,
    /// Confirmations required on a DIVI lock.
    pub divi_confirmations: u32,
}

impl From<&Quote> for OfferedTerms {
    fn from(q: &Quote) -> Self {
        OfferedTerms {
            taker_timeout_secs: q.taker_timeout_secs,
            maker_timeout_secs: q.maker_timeout_secs,
            counter_confirmations: q.btc_confirmations,
            divi_confirmations: q.divi_confirmations,
        }
    }
}

/// Refuse maker terms weaker than the taker's own `profile`. The maker is the untrusted
/// party, so a taker started under `--profile mainnet` must not accept testnet-short
/// timeouts or shallow confirmation depths. `chains` is the (taker-leg chain, maker-leg
/// chain) pair of the swap; the floors are [`SwapConfig::profile`] and
/// [`ChainParams::builtin`] values, never new numbers.
///
/// Refused, naming the term, the offered value and the floor:
/// * a confirmation depth below the profile's for either leg's chain;
/// * a taker-leg or maker-leg timeout shorter than the profile's;
/// * a taker timeout that does not exceed the maker timeout by at least the profile's gap
///   for this pair (`max(3 h, 2 × the larger MTP lag + claim margin)`).
///
/// ```
/// use divi_swap::config::{check_terms_against_profile, OfferedTerms};
/// use divi_swap::{Chain, Profile};
/// let t = OfferedTerms {
///     taker_timeout_secs: 6 * 3600,
///     maker_timeout_secs: 3 * 3600,
///     counter_confirmations: 1,
///     divi_confirmations: 3,
/// };
/// let pair = (Chain::Btc, Chain::Divi);
/// assert!(check_terms_against_profile(Profile::Testnet, pair, &t).is_ok());
/// assert!(check_terms_against_profile(Profile::Mainnet, pair, &t).is_err());
/// ```
pub fn check_terms_against_profile(
    profile: Profile,
    chains: (Chain, Chain),
    terms: &OfferedTerms,
) -> std::result::Result<(), String> {
    let floor = SwapConfig::profile(profile);
    let (taker_chain, maker_chain) = chains;
    let refuse = |term: &str, offered: u32, min: u32, unit: &str| {
        Err(format!(
            "maker's {term} is {offered}{unit}, below the {min}{unit} floor of this taker's \
             --profile {profile}; refusing the offer"
        ))
    };
    for chain in [taker_chain, maker_chain] {
        let (term, offered) = if chain == Chain::Divi {
            ("divi_confirmations", terms.divi_confirmations)
        } else {
            ("btc_confirmations", terms.counter_confirmations)
        };
        let min = floor.confirmations(chain);
        if offered < min {
            return refuse(&format!("{term} ({chain} lock)"), offered, min, "");
        }
    }
    if terms.taker_timeout_secs < floor.taker_timeout_secs {
        return refuse(
            "taker_timeout_secs",
            terms.taker_timeout_secs,
            floor.taker_timeout_secs,
            "s",
        );
    }
    if terms.maker_timeout_secs < floor.maker_timeout_secs {
        return refuse(
            "maker_timeout_secs",
            terms.maker_timeout_secs,
            floor.maker_timeout_secs,
            "s",
        );
    }
    let lag = floor
        .chain_params(taker_chain)
        .mtp_lag_secs
        .max(floor.chain_params(maker_chain).mtp_lag_secs);
    let need = SwapConfig::MIN_TIMEOUT_GAP_SECS.max(2 * lag + floor.claim_margin_secs);
    let gap = terms
        .taker_timeout_secs
        .saturating_sub(terms.maker_timeout_secs);
    if gap < need {
        return Err(format!(
            "maker's timeouts leave a gap (taker_timeout_secs {} − maker_timeout_secs {}) of \
             {gap}s, below the {need}s floor of this taker's --profile {profile} for \
             {taker_chain}/{maker_chain}; refusing the offer",
            terms.taker_timeout_secs, terms.maker_timeout_secs
        ));
    }
    Ok(())
}

/// Refuse a maker-leg HTLC whose real on-chain locktime is below the floor the quote implies.
///
/// What the taker knows when it first sees the maker's lock: its own leg's locktime
/// (`taker_leg_locktime`, already checked against `quote.taker_timeout_secs` in
/// `Taker::accepted`) and the quote's two timeouts. An honest maker locks at
/// `maker_chain_mtp_at_lock + maker_timeout_secs`, and it locks after the taker's accept, so
/// its locktime is at least `taker_leg_locktime - (taker_timeout_secs - maker_timeout_secs)`
/// less the slack between the two chains' clocks. The floor is therefore
///
/// `maker_leg_locktime >= taker_leg_locktime - (taker_timeout_secs - maker_timeout_secs)
///                        - accept_tolerance_secs - max(MTP lag of the two chains)`
///
/// where `accept_tolerance_secs` is the drift `Taker::accepted` already allows on the taker
/// leg and the lag is the profile's own per-chain value. Because `terms` passed the profile
/// check in `Taker::prepare`, this also floors the maker timeout at the profile's. No new
/// numbers: every term is an existing quote, profile or taker constant.
pub fn check_maker_leg_locktime(
    profile: Profile,
    chains: (Chain, Chain),
    terms: &OfferedTerms,
    taker_leg_locktime: u32,
    maker_leg_locktime: u32,
    accept_tolerance_secs: u32,
) -> std::result::Result<(), String> {
    let floor = SwapConfig::profile(profile);
    let (taker_chain, maker_chain) = chains;
    let lag = floor
        .chain_params(taker_chain)
        .mtp_lag_secs
        .max(floor.chain_params(maker_chain).mtp_lag_secs);
    let gap = terms.taker_timeout_secs as i64 - terms.maker_timeout_secs as i64;
    let min = taker_leg_locktime as i64 - gap - accept_tolerance_secs as i64 - lag as i64;
    if (maker_leg_locktime as i64) < min {
        return Err(format!(
            "maker-leg locktime is {maker_leg_locktime}, below the {min} floor (taker-leg \
             locktime {taker_leg_locktime} - quoted gap {gap}s [taker_timeout_secs {} - \
             maker_timeout_secs {}] - {accept_tolerance_secs}s accept tolerance - {lag}s MTP \
             lag) of this taker's --profile {profile}; not claiming",
            terms.taker_timeout_secs, terms.maker_timeout_secs
        ));
    }
    Ok(())
}

/// Exact maker-leg floor when the maker states the MTP it locked at (`SwapView::maker_mtp_at_lock`).
///
/// An honest maker sets `locktime = mtp_at_lock + maker_timeout_secs`, so the exact check is
/// `maker_leg_locktime >= stated_mtp + maker_timeout_secs`. The stated MTP is the maker's
/// word, so it is first bounded by what the taker can see itself (no new numbers, the same
/// tolerance and profile MTP lag as [`check_maker_leg_locktime`]):
///
/// * from below: the maker locks after the taker's accept, so
///   `stated_mtp >= taker_leg_locktime - taker_timeout_secs - accept_tolerance_secs - lag`;
///   a smaller one would let a short lock pass the exact check by understating the MTP;
/// * from above: MTP never runs ahead of the chain, so `stated_mtp <= observed_maker_mtp + lag`
///   where `observed_maker_mtp` is the taker's own read of the maker chain just now.
///
/// Additive to [`check_maker_leg_locktime`]: a maker that also understates its MTP down to the
/// lower bound is still bounded only by that tolerant floor.
#[allow(clippy::too_many_arguments)]
pub fn check_maker_leg_locktime_exact(
    profile: Profile,
    chains: (Chain, Chain),
    terms: &OfferedTerms,
    taker_leg_locktime: u32,
    maker_leg_locktime: u32,
    stated_mtp: u32,
    observed_maker_mtp: u32,
    accept_tolerance_secs: u32,
) -> std::result::Result<(), String> {
    let floor = SwapConfig::profile(profile);
    let (taker_chain, maker_chain) = chains;
    let lag = floor
        .chain_params(taker_chain)
        .mtp_lag_secs
        .max(floor.chain_params(maker_chain).mtp_lag_secs) as i64;
    let lowest = taker_leg_locktime as i64
        - terms.taker_timeout_secs as i64
        - accept_tolerance_secs as i64
        - lag;
    if (stated_mtp as i64) < lowest {
        return Err(format!(
            "maker's stated MTP-at-lock {stated_mtp} is implausibly low, below {lowest} \
             (taker-leg locktime {taker_leg_locktime} - taker_timeout_secs {} - \
             {accept_tolerance_secs}s accept tolerance - {lag}s MTP lag) of this taker's \
             --profile {profile}; not claiming",
            terms.taker_timeout_secs
        ));
    }
    let highest = observed_maker_mtp as i64 + lag;
    if (stated_mtp as i64) > highest {
        return Err(format!(
            "maker's stated MTP-at-lock {stated_mtp} is implausibly high, above {highest} \
             (the maker chain's MTP {observed_maker_mtp} + {lag}s MTP lag) of this taker's \
             --profile {profile}; not claiming"
        ));
    }
    let exact = stated_mtp as i64 + terms.maker_timeout_secs as i64;
    if (maker_leg_locktime as i64) < exact {
        return Err(format!(
            "maker-leg locktime is {maker_leg_locktime}, below the exact {exact} floor (maker's \
             stated MTP-at-lock {stated_mtp} + maker_timeout_secs {}) of the quote; not claiming",
            terms.maker_timeout_secs
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Direction;
    use crate::types::Amount;

    /// A lag near `u32::MAX` (divi-swapd takes `mtp_lag_secs` from the config file) does not
    /// overflow the required gap: it is computed exactly, so no gap a `u32` holds satisfies it.
    #[test]
    fn huge_mtp_lag_does_not_overflow_the_gap() {
        let mut c = SwapConfig::profile(Profile::Testnet);
        c.taker_timeout_secs = u32::MAX;
        c.maker_timeout_secs = 0;
        c.btc_mtp_lag_secs = u32::MAX / 2;
        c.claim_margin_secs = 2;
        assert_eq!(c.required_gap_secs(), u32::MAX);
        assert!(c.validate().is_err());
        c.btc_mtp_lag_secs = u32::MAX;
        assert!(c.validate().is_err());
    }

    /// Every chain's claim deadline keeps at least the old 1800 s, and fits inside the
    /// mainnet maker leg's worst case: the maker timeout less the locktime tolerance taken on
    /// both legs (2 × 1800 s) and the MTP lag on both (2 × the largest lag).
    #[test]
    fn claim_deadlines_hold_the_floor_and_fit_the_mainnet_window() {
        let c = SwapConfig::profile(Profile::Mainnet);
        let window = c.maker_timeout_secs - 2 * 1800 - 2 * c.max_mtp_lag_secs();
        for chain in Chain::ALL {
            let d = ClaimDeadline::builtin(chain);
            assert!(
                d.margin_secs() >= crate::taker::TAKER_SAFETY_MARGIN_SECS,
                "{chain}"
            );
            assert!(d.margin_secs() >= d.min_blocks * d.block_secs, "{chain}");
            assert!(
                d.margin_secs() <= window,
                "{chain}: {} > {window}",
                d.margin_secs()
            );
        }
    }

    #[test]
    fn claim_deadline_check_needs_both_seconds_and_blocks() {
        let d = ClaimDeadline {
            block_secs: 600,
            min_blocks: 6,
            min_secs: 600,
        };
        assert_eq!(d.margin_secs(), 3600);
        assert!(d.check(Chain::Btc, 0, 3600).is_ok());
        assert!(d.check(Chain::Btc, 0, 3599).is_err(), "five blocks");
        assert!(d.check(Chain::Btc, 100, 50).is_err(), "past the locktime");
        let d = ClaimDeadline {
            min_secs: 4000,
            ..d
        };
        assert!(
            d.check(Chain::Btc, 0, 3999).is_err(),
            "six blocks, too few seconds"
        );
        assert!(d.check(Chain::Btc, 0, 4000).is_ok());
    }

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
            (2, 17)
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

    fn terms_of(p: Profile, counter: Chain) -> OfferedTerms {
        let c = SwapConfig::profile(p);
        OfferedTerms {
            taker_timeout_secs: c.taker_timeout_secs,
            maker_timeout_secs: c.maker_timeout_secs,
            counter_confirmations: c.confirmations(counter),
            divi_confirmations: c.divi_confirmations,
        }
    }

    const COUNTERS: [Chain; 4] = [Chain::Btc, Chain::Ltc, Chain::Zec, Chain::Usdc];

    fn pairs(counter: Chain) -> [(Chain, Chain); 2] {
        [(counter, Chain::Divi), (Chain::Divi, counter)]
    }

    #[test]
    fn terms_exactly_at_the_profile_floor_are_accepted() {
        for p in [Profile::Testnet, Profile::Mainnet] {
            for c in COUNTERS {
                for pair in pairs(c) {
                    check_terms_against_profile(p, pair, &terms_of(p, c)).unwrap();
                }
            }
        }
    }

    #[test]
    fn stronger_terms_than_the_floor_are_accepted() {
        for p in [Profile::Testnet, Profile::Mainnet] {
            let mut t = terms_of(p, Chain::Btc);
            t.taker_timeout_secs += 3600;
            t.maker_timeout_secs += 600;
            t.counter_confirmations += 1;
            t.divi_confirmations += 1;
            check_terms_against_profile(p, (Chain::Btc, Chain::Divi), &t).unwrap();
        }
    }

    #[test]
    fn a_testnet_maker_is_refused_by_a_mainnet_taker_naming_the_term() {
        let t = terms_of(Profile::Testnet, Chain::Btc);
        let e = check_terms_against_profile(Profile::Mainnet, (Chain::Btc, Chain::Divi), &t)
            .unwrap_err();
        // Confirmations are checked first: BTC 1 < 2.
        assert!(
            e.contains("btc_confirmations (btc lock) is 1, below the 2 floor"),
            "{e}"
        );
        assert!(e.contains("--profile mainnet"), "{e}");
    }

    #[test]
    fn each_confirmation_depth_below_the_floor_is_refused_per_profile() {
        for p in [Profile::Testnet, Profile::Mainnet] {
            for c in COUNTERS {
                for pair in pairs(c) {
                    let ok = terms_of(p, c);
                    let floor = SwapConfig::profile(p);

                    let mut t = ok;
                    t.counter_confirmations -= 1;
                    let e = check_terms_against_profile(p, pair, &t).unwrap_err();
                    let want = format!(
                        "btc_confirmations ({c} lock) is {}, below the {} floor",
                        t.counter_confirmations,
                        floor.confirmations(c)
                    );
                    assert!(e.contains(&want), "{e} / {want}");

                    let mut t = ok;
                    t.divi_confirmations -= 1;
                    let e = check_terms_against_profile(p, pair, &t).unwrap_err();
                    let want = format!(
                        "divi_confirmations (divi lock) is {}, below the {} floor",
                        t.divi_confirmations, floor.divi_confirmations
                    );
                    assert!(e.contains(&want), "{e} / {want}");
                }
            }
        }
    }

    #[test]
    fn a_shorter_timeout_than_the_floor_is_refused_per_profile() {
        for p in [Profile::Testnet, Profile::Mainnet] {
            let floor = SwapConfig::profile(p);
            let ok = terms_of(p, Chain::Btc);
            let pair = (Chain::Btc, Chain::Divi);

            let mut t = ok;
            t.taker_timeout_secs -= 1;
            let e = check_terms_against_profile(p, pair, &t).unwrap_err();
            assert!(
                e.contains(&format!(
                    "taker_timeout_secs is {}s, below the {}s floor",
                    t.taker_timeout_secs, floor.taker_timeout_secs
                )),
                "{e}"
            );

            let mut t = ok;
            t.maker_timeout_secs -= 1;
            let e = check_terms_against_profile(p, pair, &t).unwrap_err();
            assert!(
                e.contains(&format!(
                    "maker_timeout_secs is {}s, below the {}s floor",
                    t.maker_timeout_secs, floor.maker_timeout_secs
                )),
                "{e}"
            );
        }
    }

    #[test]
    fn a_timeout_gap_below_the_floor_is_refused_per_profile() {
        for p in [Profile::Testnet, Profile::Mainnet] {
            for c in COUNTERS {
                for pair in pairs(c) {
                    // Both timeouts at or above their floors, but too close together.
                    let ok = terms_of(p, c);
                    let mut t = ok;
                    t.maker_timeout_secs = t.taker_timeout_secs - 1;
                    let e = check_terms_against_profile(p, pair, &t).unwrap_err();
                    assert!(e.contains("gap") && e.contains("floor"), "{e}");
                    assert!(e.contains("1s, below the"), "{e}");
                    // Exactly the needed gap passes.
                    let lag = SwapConfig::profile(p)
                        .chain_params(pair.0)
                        .mtp_lag_secs
                        .max(SwapConfig::profile(p).chain_params(pair.1).mtp_lag_secs);
                    let need = SwapConfig::MIN_TIMEOUT_GAP_SECS
                        .max(2 * lag + SwapConfig::profile(p).claim_margin_secs);
                    t.maker_timeout_secs = t.taker_timeout_secs - need;
                    if t.maker_timeout_secs >= ok.maker_timeout_secs {
                        check_terms_against_profile(p, pair, &t).unwrap();
                    }
                    t.maker_timeout_secs += 1;
                    if t.maker_timeout_secs >= ok.maker_timeout_secs {
                        assert!(check_terms_against_profile(p, pair, &t).is_err());
                    }
                }
            }
        }
    }

    #[test]
    fn a_taker_timeout_below_the_maker_timeout_is_refused_not_wrapped() {
        let mut t = terms_of(Profile::Testnet, Chain::Btc);
        t.taker_timeout_secs = t.maker_timeout_secs - 1;
        assert!(
            check_terms_against_profile(Profile::Testnet, (Chain::Btc, Chain::Divi), &t).is_err()
        );
    }

    #[test]
    fn a_mainnet_floor_is_the_unchanged_btc_two_confirmations() {
        let t = terms_of(Profile::Mainnet, Chain::Btc);
        assert_eq!(t.counter_confirmations, 2);
        check_terms_against_profile(Profile::Mainnet, (Chain::Btc, Chain::Divi), &t).unwrap();
    }

    #[test]
    fn mainnet_divi_confirmations_are_17_and_testnet_stays_3() {
        assert_eq!(SwapConfig::profile(Profile::Mainnet).divi_confirmations, 17);
        assert_eq!(
            ChainParams::builtin(Chain::Divi, Profile::Mainnet).confirmations,
            17
        );
        assert_eq!(SwapConfig::profile(Profile::Testnet).divi_confirmations, 3);
        assert_eq!(
            ChainParams::builtin(Chain::Divi, Profile::Testnet).confirmations,
            3
        );
    }

    #[test]
    fn a_mainnet_taker_refuses_16_divi_confirmations_and_accepts_17() {
        let mut t = terms_of(Profile::Mainnet, Chain::Btc);
        t.divi_confirmations = 16;
        let e = check_terms_against_profile(Profile::Mainnet, (Chain::Btc, Chain::Divi), &t)
            .unwrap_err();
        assert!(
            e.contains("divi_confirmations (divi lock) is 16, below the 17 floor"),
            "{e}"
        );
        t.divi_confirmations = 17;
        check_terms_against_profile(Profile::Mainnet, (Chain::Btc, Chain::Divi), &t).unwrap();
    }

    #[test]
    fn quote_converts_to_offered_terms() {
        let q = Quote {
            id: "q".into(),
            offer_id: "o".into(),
            direction: Direction::TakerPaysBtc,
            counter_chain: Chain::Ltc,
            btc_amount: Amount(1),
            divi_amount: Amount(1),
            expires_at: 0,
            maker_btc_pubkey: [2; 33],
            maker_divi_pubkey: [2; 33],
            taker_timeout_secs: 7,
            maker_timeout_secs: 5,
            btc_confirmations: 3,
            divi_confirmations: 4,
        };
        assert_eq!(
            OfferedTerms::from(&q),
            OfferedTerms {
                taker_timeout_secs: 7,
                maker_timeout_secs: 5,
                counter_confirmations: 3,
                divi_confirmations: 4,
            }
        );
    }

    #[test]
    fn maker_leg_locktime_floor_per_profile() {
        for p in [Profile::Testnet, Profile::Mainnet] {
            for c in [Chain::Btc, Chain::Ltc, Chain::Zec] {
                let pair = (c, Chain::Divi);
                let f = SwapConfig::profile(p);
                let t = OfferedTerms {
                    taker_timeout_secs: f.taker_timeout_secs,
                    maker_timeout_secs: f.maker_timeout_secs,
                    counter_confirmations: f.confirmations(c),
                    divi_confirmations: f.confirmations(Chain::Divi),
                };
                let lag = f
                    .chain_params(c)
                    .mtp_lag_secs
                    .max(f.chain_params(Chain::Divi).mtp_lag_secs);
                let tol = 1800;
                let tl = 2_000_000_000u32;
                let floor = tl - (t.taker_timeout_secs - t.maker_timeout_secs) - tol - lag;
                // at the floor, and stronger: accepted
                check_maker_leg_locktime(p, pair, &t, tl, floor, tol).unwrap();
                check_maker_leg_locktime(p, pair, &t, tl, floor + 1, tol).unwrap();
                check_maker_leg_locktime(p, pair, &t, tl, tl, tol).unwrap();
                // one below: refused, naming the term and both values
                let e = check_maker_leg_locktime(p, pair, &t, tl, floor - 1, tol).unwrap_err();
                assert!(e.contains("maker-leg locktime"), "{e}");
                assert!(e.contains(&(floor - 1).to_string()), "{e}");
                assert!(e.contains(&floor.to_string()), "{e}");
                assert!(e.contains(&format!("--profile {p}")), "{e}");
            }
        }
    }

    fn exact_case(p: Profile, c: Chain) -> (OfferedTerms, u32, u32, u32, u32) {
        let f = SwapConfig::profile(p);
        let t = OfferedTerms {
            taker_timeout_secs: f.taker_timeout_secs,
            maker_timeout_secs: f.maker_timeout_secs,
            counter_confirmations: f.confirmations(c),
            divi_confirmations: f.confirmations(Chain::Divi),
        };
        let lag = f
            .chain_params(c)
            .mtp_lag_secs
            .max(f.chain_params(Chain::Divi).mtp_lag_secs);
        // taker leg locked at maker-chain time `now`, maker reads its MTP a little later
        let now = 2_000_000_000u32;
        (t, now + t.taker_timeout_secs, now, now + 100, lag)
    }

    #[test]
    fn maker_leg_locktime_exact_floor_at_below_above_per_profile_and_direction() {
        for p in [Profile::Testnet, Profile::Mainnet] {
            for c in [Chain::Btc, Chain::Ltc, Chain::Zec] {
                // both directions: (taker chain, maker chain)
                for pair in [(c, Chain::Divi), (Chain::Divi, c)] {
                    let (t, tl, _, stated, _) = exact_case(p, c);
                    let exact = stated + t.maker_timeout_secs;
                    let chk = |ml| {
                        check_maker_leg_locktime_exact(p, pair, &t, tl, ml, stated, stated, 1800)
                    };
                    chk(exact).unwrap();
                    chk(exact + 1).unwrap();
                    chk(exact + 10_000).unwrap();
                    let e = chk(exact - 1).unwrap_err();
                    assert!(e.contains("exact"), "{e}");
                    assert!(e.contains(&(exact - 1).to_string()), "{e}");
                    assert!(e.contains(&exact.to_string()), "{e}");
                    // inside AA's tolerance, still refused when the MTP is stated
                    assert!(chk(exact - 600).is_err());
                }
            }
        }
    }

    #[test]
    fn maker_leg_locktime_exact_refuses_an_implausible_stated_mtp() {
        for p in [Profile::Testnet, Profile::Mainnet] {
            for c in [Chain::Btc, Chain::Ltc, Chain::Zec] {
                for pair in [(c, Chain::Divi), (Chain::Divi, c)] {
                    let (t, tl, _, stated, lag) = exact_case(p, c);
                    let lowest = tl - t.taker_timeout_secs - 1800 - lag;
                    // lower edge accepted, one below refused as implausibly low
                    check_maker_leg_locktime_exact(
                        p,
                        pair,
                        &t,
                        tl,
                        lowest + t.maker_timeout_secs,
                        lowest,
                        stated,
                        1800,
                    )
                    .unwrap();
                    let e = check_maker_leg_locktime_exact(
                        p,
                        pair,
                        &t,
                        tl,
                        u32::MAX,
                        lowest - 1,
                        stated,
                        1800,
                    )
                    .unwrap_err();
                    assert!(e.contains("implausibly low"), "{e}");
                    assert!(e.contains(&(lowest - 1).to_string()), "{e}");
                    // upper edge accepted, one above refused as implausibly high
                    let highest = stated + lag;
                    check_maker_leg_locktime_exact(
                        p,
                        pair,
                        &t,
                        tl,
                        highest + t.maker_timeout_secs,
                        highest,
                        stated,
                        1800,
                    )
                    .unwrap();
                    let e = check_maker_leg_locktime_exact(
                        p,
                        pair,
                        &t,
                        tl,
                        u32::MAX,
                        highest + 1,
                        stated,
                        1800,
                    )
                    .unwrap_err();
                    assert!(e.contains("implausibly high"), "{e}");
                    assert!(e.contains(&(highest + 1).to_string()), "{e}");
                }
            }
        }
    }
}
