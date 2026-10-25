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

/// How a claim that has not confirmed has its fee raised as the claimed leg's locktime nears
/// ([`FeeEscalation::builtin`]): the taker's claim of the maker leg, and the maker's claim of
/// the taker leg, which the taker's refund takes back at the taker-leg locktime
/// (`Taker::with_fee_escalation` and `Maker::with_fee_escalation` override or turn it off
/// for one chain). Applied only where the backend can bump (`FeeBump::Rbf`, `Cpfp` or
/// `SameNonce`). The schedule is written in terms of the maker leg; for the maker read
/// "taker leg" throughout.
///
/// The feerate stays at what the first claim paid until `start_secs_left` seconds are left,
/// then climbs geometrically to the cap, reached with `cap_secs_left` left. The cap is the
/// lower of `cap_feerate` and `max_multiple` times the first claim's feerate: the claim is
/// worth the maker leg, so overpaying beats losing it, but not without bound (a fee estimate
/// gone wrong must not hand the leg to the miners).
///
/// The cap only bounds what is paid while it is enough. Every claim is sent after its
/// preimage is out (the first one reveals it), and from then on the maker leg is lost unless
/// the claim confirms, so where the backend reports its sizes the fee is bounded by
/// [`FeeEscalation::ceiling_fee`], a share of the leg, instead
/// ([`FeeEscalation::target_after_leak`]). Before the preimage is out the taker declines a
/// claim whose current feerate alone would cost more than half the leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeEscalation {
    /// Seconds left before the maker-leg locktime when bumping starts.
    pub start_secs_left: u32,
    /// Seconds left when the cap is reached.
    pub cap_secs_left: u32,
    /// Highest feerate ever paid, base unit per vbyte (on EVM, wei per gas).
    pub cap_feerate: u64,
    /// Highest multiple of the first claim's feerate ever paid.
    pub max_multiple: u64,
    /// The replacement price bump, percent, of the node a same-nonce (`FeeBump::SameNonce`,
    /// EVM) claim is sent to: a replacement raises both `maxFeePerGas` and
    /// `maxPriorityFeePerGas` at least this much over the version it replaces. go-ethereum's
    /// default is 10 (`--txpool.pricebump`, `legacypool.DefaultConfig.PriceBump`; checked in
    /// `list.Add`, `core/txpool/legacypool/list.go`); set it to the node's own where that is
    /// stricter. Absent from a config written before it existed: 10. Unused by RBF and CPFP.
    #[serde(default = "default_price_bump_pct")]
    pub price_bump_pct: u64,
    /// Under `FeeBump::Cpfp`, bump by replacing the newest CPFP child (falling back to a
    /// new child where the node refuses that) rather than by adding a child on top of it.
    /// Off in every built-in schedule: Litecoin Core 0.21.4 relays no replacement
    /// (`DEFAULT_ENABLE_REPLACEMENT=false`) and the LTC backend refuses to spend an input
    /// an unmined child already spends before it reaches the node, so the replacement is
    /// only ever refused. Off, a crash between a bump's write-ahead and its broadcast
    /// leaves a child on top of the one the node holds, which the next step resends.
    #[serde(default)]
    pub replace_cpfp_child: bool,
}

/// go-ethereum's default replacement price bump, percent ([`FeeEscalation::price_bump_pct`]).
pub const GETH_PRICE_BUMP_PCT: u64 = 10;

fn default_price_bump_pct() -> u64 {
    GETH_PRICE_BUMP_PCT
}

impl FeeEscalation {
    /// Built-in schedule for a maker leg on `chain`, or `None` where no backend can bump
    /// (DIVI and ZEC relay no replacement and ignore CPFP; XMR has no HTLC). Bumping starts at twice the claim deadline
    /// ([`ClaimDeadline::builtin`]) and caps out at half of it, so a claim sent at the
    /// deadline is at the cap with three BTC blocks (six LTC blocks) still to come.
    pub fn builtin(chain: Chain) -> Option<Self> {
        let cap_feerate = match chain {
            // sat/vB. Above every sustained mainnet peak so far (a few hundred sat/vB);
            // 1000 sat/vB on a ~150 vB claim is 150 000 sat.
            Chain::Btc => 1000,
            // litoshi/vB. LTC fees sit near the relay floor; 500 is far above any backlog
            // it has had, and its blocks are four times as frequent.
            Chain::Ltc => 500,
            // wei per gas (`maxFeePerGas`; the claim is replaced at its nonce,
            // `FeeBump::SameNonce`). 500 gwei is above every sustained mainnet base fee
            // since EIP-1559; on a claim of under 100 000 gas it is at most 0.05 ETH.
            Chain::Usdc => 500_000_000_000,
            Chain::Zec | Chain::Divi | Chain::Xmr => return None,
        };
        let m = ClaimDeadline::builtin(chain).margin_secs();
        Some(FeeEscalation {
            start_secs_left: m.saturating_mul(2),
            cap_secs_left: m / 2,
            cap_feerate,
            max_multiple: 50,
            price_bump_pct: GETH_PRICE_BUMP_PCT,
            replace_cpfp_child: false,
        })
    }

    /// This schedule with `cap_feerate` instead (the chain's configured cap).
    pub fn with_cap_feerate(self, cap_feerate: u64) -> Self {
        FeeEscalation {
            cap_feerate,
            ..self
        }
    }

    /// This schedule with `price_bump_pct` instead (the node's replacement price bump).
    pub fn with_price_bump(self, price_bump_pct: u64) -> Self {
        FeeEscalation {
            price_bump_pct,
            ..self
        }
    }

    /// The feerate for a same-nonce replacement of a claim paying `current` (first version
    /// `base`) towards `target`, after `refusals` "replacement transaction underpriced"
    /// refusals at this step: the step from `current` to `target` doubles after every second
    /// refusal, so a node with a stricter bump than configured is outbid within a few tries
    /// instead of refusing the same step forever. Never below `target`, never above the cap
    /// (or `target`, where a post-leak target is already above the cap).
    pub fn underpriced_target(&self, base: u64, current: u64, target: u64, refusals: u32) -> u64 {
        self.underpriced_target_within(current, target, refusals, self.cap(base))
    }

    /// [`FeeEscalation::underpriced_target`] under the cap `cap` instead of the fixed one
    /// (after the leak, [`FeeEscalation::cap_after_leak`]).
    pub fn underpriced_target_within(
        &self,
        current: u64,
        target: u64,
        refusals: u32,
        cap: u64,
    ) -> u64 {
        let step = u128::from(target.saturating_sub(current));
        let doubled = step << (refusals / 2).min(64);
        let raised = (u128::from(current) + doubled).min(u128::from(u64::MAX)) as u64;
        raised.min(cap.max(target)).max(target)
    }

    /// The feerate to pay with `left` seconds before the locktime, the first claim having paid
    /// `base`. Never below `base` and never above the cap.
    pub fn target(&self, base: u64, left: i64) -> u64 {
        let base = base.max(1);
        let cap = self.cap(base);
        let (start, end) = (
            i64::from(self.start_secs_left),
            i64::from(self.cap_secs_left),
        );
        if left >= start {
            return base;
        }
        if left <= end || start <= end {
            return cap;
        }
        let t = (start - left) as f64 / (start - end) as f64;
        let rate = base as f64 * (cap as f64 / base as f64).powf(t);
        (rate.ceil() as u64).clamp(base, cap)
    }

    /// Whether paying `target` instead of `current` is worth a new transaction: at least a
    /// quarter more, and at least one unit per vbyte more (BIP125's incremental relay fee, so
    /// a replacement is never refused for paying too little extra). A quarter keeps a climb
    /// to 50x within 18 bumps, so a CPFP chain stays inside the 25-transaction ancestor limit.
    pub fn worth_bumping(current: u64, target: u64) -> bool {
        target >= current.saturating_add((current / 4).max(1))
    }

    /// The highest feerate a claim whose first version paid `base` ever pays.
    pub fn cap(&self, base: u64) -> u64 {
        let base = base.max(1);
        self.cap_feerate
            .min(base.saturating_mul(self.max_multiple))
            .max(base)
    }

    /// The highest feerate a claim whose fee is not paid out of the leg pays with `left`
    /// seconds before the locktime, the first claim having paid `base`: on EVM (USDC) gas is
    /// paid in ETH, so there is no share of the leg to bound it
    /// ([`FeeEscalation::ceiling_fee`]). Until `cap_secs_left` it is the fixed cap. From
    /// there the claim is unconfirmed with blocks running out and the preimage out, the
    /// multiple of the first feerate no longer binds, and `cap_feerate` does: a claim first
    /// priced low can still outbid a floor that rose after the leak.
    pub fn cap_after_leak(&self, base: u64, left: i64) -> u64 {
        let end = i64::from(self.cap_secs_left);
        if left >= end || end <= 0 {
            return self.cap(base);
        }
        self.cap_feerate.max(base.max(1))
    }

    /// The feerate for a same-nonce claim with no post-leak ceiling (EVM), with `left`
    /// seconds before the locktime, the first claim having paid `base`. Until
    /// `cap_secs_left` it is [`FeeEscalation::target`]. From there it climbs on
    /// geometrically from the fixed cap to [`FeeEscalation::cap_after_leak`] at the
    /// locktime, as [`FeeEscalation::target_after_leak`] does to the ceiling. Either way
    /// [`FeeEscalation::reach_cap`] applies.
    pub fn same_nonce_target(&self, base: u64, left: i64) -> u64 {
        let cap = self.cap_after_leak(base, left);
        self.reach_cap(self.target_after_leak(base, left, cap), cap)
    }

    /// A same-nonce `target` under `cap`, or `cap` itself where one more price bump
    /// (`price_bump_pct`) over `target` would pass it: a version there could never be
    /// replaced again within the cap (DM2 (c)), and would hold the claim short of the cap,
    /// under a floor the cap still clears.
    pub fn reach_cap(&self, target: u64, cap: u64) -> u64 {
        let next = u128::from(target) * u128::from(100 + self.price_bump_pct) / 100;
        if target < cap && next > u128::from(cap) {
            cap
        } else {
            target
        }
    }

    /// The most a maker-leg claim (with every CPFP child of it) pays in fees once its
    /// preimage is out, in base units: half the leg `amount` while `left ≥ window`, then
    /// rising linearly to `amount − dust − step` at the locktime (`left ≤ 0`), never below
    /// half. `window` is the chain's claim-deadline margin
    /// ([`ClaimDeadline::margin_secs`]), `dust` the smallest output the chain relays and
    /// `step` one minimal fee bump (one base unit per vbyte of the package), so the last
    /// version still leaves a relayable output and room to replace it.
    ///
    /// Half is what the taker may still lose and call the swap worth doing; it is also the
    /// share the taker declines above before revealing anything. The rise is there because
    /// at the locktime the maker's refund takes the whole leg: any fee short of the whole
    /// leg is better than that, and it costs the hostile maker its refund.
    pub fn ceiling_fee(amount: u64, dust: u64, step: u64, left: i64, window: u32) -> u64 {
        let half = amount / 2;
        let top = amount.saturating_sub(dust).saturating_sub(step).max(half);
        let window = i64::from(window);
        if left >= window || window <= 0 {
            return half;
        }
        let gone = (window - left.max(0)) as u128;
        half + (u128::from(top - half) * gone / window as u128) as u64
    }

    /// The feerate to pay with `left` seconds before the locktime once the preimage is out,
    /// the first claim having paid `base`, with the post-leak ceiling
    /// ([`FeeEscalation::ceiling_fee`]) at `ceiling` per vbyte. Until `cap_secs_left` it is
    /// [`FeeEscalation::target`], never above `ceiling` (a small leg's ceiling can be under
    /// the fixed cap). From there the claim is unconfirmed at the fixed cap with blocks
    /// running out, which is evidence the cap is not enough, so it climbs on geometrically
    /// from the cap to `ceiling` at the locktime.
    pub fn target_after_leak(&self, base: u64, left: i64, ceiling: u64) -> u64 {
        let ceiling = ceiling.max(1);
        let cap = self.cap(base);
        let end = i64::from(self.cap_secs_left);
        if left >= end || end <= 0 || ceiling <= cap {
            return self.target(base, left).min(ceiling);
        }
        let t = (end - left.max(0)) as f64 / end as f64;
        let rate = cap as f64 * (ceiling as f64 / cap as f64).powf(t);
        (rate.ceil() as u64).clamp(cap, ceiling)
    }

    /// Past `cap_secs_left`, which quarter of the stretch to the locktime `left` falls in (1
    /// to 4, the last one running on past the locktime) and the seconds left at its start;
    /// `None` before. A CPFP claim climbs one step per quarter
    /// ([`FeeEscalation::cpfp_target_after_leak`]).
    pub fn cpfp_step(&self, left: i64) -> Option<(u32, i64)> {
        let end = i64::from(self.cap_secs_left);
        if left >= end || end <= 0 {
            return None;
        }
        let gone = end - left.max(0);
        let k = ((4 * gone + end - 1) / end).clamp(1, 4);
        Some((k as u32, end - (k - 1) * end / 4))
    }

    /// [`FeeEscalation::target_after_leak`] for a CPFP claim. Until `cap_secs_left` it is
    /// [`FeeEscalation::target`], never above `ceiling`. Past it the climb goes on from the
    /// cap towards the ceiling in at most four steps, one per quarter `k` of what is left
    /// ([`FeeEscalation::cpfp_step`]): `cap · (ceiling / cap)^(k/4)`, where `ceiling` is the
    /// post-leak ceiling at the start of that quarter. Each step replaces the child (or, on a
    /// node that refuses that, adds one), and a package must pay its whole size at the new
    /// feerate, so a few large steps keep it small, where a geometric climb in small steps
    /// would grow it at each and price it out.
    pub fn cpfp_target_after_leak(&self, base: u64, left: i64, ceiling: u64) -> u64 {
        let ceiling = ceiling.max(1);
        let cap = self.cap(base);
        match self.cpfp_step(left) {
            Some((k, _)) if ceiling > cap => {
                let t = f64::from(k) / 4.0;
                let rate = cap as f64 * (ceiling as f64 / cap as f64).powf(t);
                (rate.ceil() as u64).clamp(cap, ceiling)
            }
            _ => self.target(base, left).min(ceiling),
        }
    }

    /// [`FeeEscalation::should_bump`] for a CPFP claim (first version `base`) whose package
    /// pays `current`, with `left` seconds before the locktime. Until `cap_secs_left`, only
    /// when `target` at least doubles `current` or reaches the fixed cap; past it, whenever
    /// `target` is higher, which [`FeeEscalation::cpfp_target_after_leak`] makes at most
    /// four times. Fewer, larger steps keep the package, and with it the fee of every later
    /// step, small: about six bumps to the cap and four past it.
    pub fn should_add_child(&self, base: u64, left: i64, current: u64, target: u64) -> bool {
        if self.cpfp_step(left).is_some() {
            return target > current;
        }
        target > current && (target >= current.saturating_mul(2) || target == self.cap(base))
    }

    /// Whether to bump a claim paying `current` (first version `base`) to `target`: when
    /// [`FeeEscalation::worth_bumping`], or to finish the climb to the cap, which a quarter
    /// step could otherwise leave just short of (one more transaction at most).
    pub fn should_bump(&self, base: u64, current: u64, target: u64) -> bool {
        Self::should_bump_within(current, target, self.cap(base))
    }

    /// [`FeeEscalation::should_bump`] finishing the climb to `cap` instead of the fixed cap
    /// (after the leak, [`FeeEscalation::cap_after_leak`]).
    pub fn should_bump_within(current: u64, target: u64, cap: u64) -> bool {
        target > current && (Self::worth_bumping(current, target) || target == cap)
    }
}

/// `CHAIN=N`, the value of the per-chain claim fee flags (`--claim-fee-cap`,
/// `--claim-price-bump`) of the `divi-swap` and `divi-swapd` binaries.
pub fn parse_chain_value(s: &str) -> std::result::Result<(Chain, u64), String> {
    let (chain, value) = s
        .split_once('=')
        .ok_or_else(|| format!("expected CHAIN=N, got {s:?}"))?;
    let chain = chain.parse::<Chain>().map_err(|e| e.to_string())?;
    let value = value
        .parse::<u64>()
        .map_err(|e| format!("{chain}: {e} in {s:?}"))?;
    Ok((chain, value))
}

/// The fee escalations the claim fee flags set: each named chain's
/// [`FeeEscalation::builtin`] with `caps` ([`FeeEscalation::with_cap_feerate`]) and `bumps`
/// ([`FeeEscalation::with_price_bump`]) applied, one entry per chain. Fails on a chain whose
/// claims cannot be bumped (DIVI, ZEC, XMR).
pub fn claim_fee_escalations(
    caps: &[(Chain, u64)],
    bumps: &[(Chain, u64)],
) -> Result<Vec<(Chain, FeeEscalation)>> {
    let mut out: Vec<(Chain, FeeEscalation)> = Vec::new();
    let mut set = |chain: Chain, f: &dyn Fn(FeeEscalation) -> FeeEscalation| -> Result<()> {
        let i = match out.iter().position(|(c, _)| *c == chain) {
            Some(i) => i,
            None => {
                let builtin = FeeEscalation::builtin(chain).ok_or_else(|| {
                    SwapError::InvalidParams(format!(
                        "{chain} claims have no fee escalation to configure"
                    ))
                })?;
                out.push((chain, builtin));
                out.len() - 1
            }
        };
        out[i].1 = f(out[i].1);
        Ok(())
    };
    for &(chain, cap) in caps {
        set(chain, &|e| e.with_cap_feerate(cap))?;
    }
    for &(chain, pct) in bumps {
        set(chain, &|e| e.with_price_bump(pct))?;
    }
    Ok(out)
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
    /// The taker's own margin before the maker-leg locktime is per chain, in
    /// [`ClaimDeadline`], not this value.
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
    fn fee_escalation_climbs_from_base_to_the_cap() {
        let e = FeeEscalation::builtin(Chain::Btc).unwrap();
        assert_eq!((e.start_secs_left, e.cap_secs_left), (7200, 1800));
        assert_eq!(
            e.target(10, 9000),
            10,
            "before the start: the first claim's rate"
        );
        assert_eq!(e.target(10, 7200), 10);
        assert_eq!(e.target(10, 1800), 500, "cap: 50 x base, under 1000 sat/vB");
        assert_eq!(e.target(10, -60), 500, "past the locktime: still the cap");
        assert_eq!(e.target(100, 0), 1000, "cap: the absolute 1000 sat/vB");
        let mid = e.target(10, 4500);
        assert!(mid > 10 && mid < 500, "{mid}");
        let mut last = 0;
        for left in (0..=9000).rev().step_by(60) {
            let t = e.target(10, left);
            assert!(t >= last, "never falls as the locktime nears");
            last = t;
        }
        assert!(FeeEscalation::worth_bumping(10, 12) && !FeeEscalation::worth_bumping(10, 11));
        assert!(!FeeEscalation::worth_bumping(100, 124));
        assert!(FeeEscalation::worth_bumping(1, 2) && !FeeEscalation::worth_bumping(1, 1));
        let btc = FeeEscalation::builtin(Chain::Btc).unwrap();
        assert_eq!((btc.cap(10), btc.cap(100)), (500, 1000));
        assert!(
            btc.should_bump(10, 450, 500),
            "finishes the climb to the cap"
        );
        assert!(
            !btc.should_bump(10, 450, 480),
            "short of the cap: a quarter step"
        );
        assert!(!btc.should_bump(10, 500, 500));
        for chain in [Chain::Divi, Chain::Zec, Chain::Xmr] {
            assert!(FeeEscalation::builtin(chain).is_none(), "{chain}");
        }
        assert!(FeeEscalation::builtin(Chain::Ltc).is_some());
        // USDC: same-nonce replacement, feerate in wei per gas (maxFeePerGas).
        let usdc = FeeEscalation::builtin(Chain::Usdc).expect("EVM claims escalate");
        assert_eq!(usdc.cap_feerate, 500_000_000_000, "500 gwei");
        assert_eq!((usdc.start_secs_left, usdc.cap_secs_left), (3600, 900));
    }

    /// The cap and the node's replacement price bump are per-chain settings: the builtin
    /// USDC cap stays 500 gwei and the bump geth's default 10%, a config written before the
    /// bump existed reads as 10, and the `with_` helpers change one field only.
    #[test]
    fn fee_escalation_cap_and_price_bump_are_per_chain_settings() {
        let usdc = FeeEscalation::builtin(Chain::Usdc).unwrap();
        assert_eq!(usdc.price_bump_pct, 10, "geth's default PriceBump");
        assert_eq!(usdc.cap_feerate, 500_000_000_000);
        let old: FeeEscalation = serde_json::from_str(
            r#"{"start_secs_left":3600,"cap_secs_left":900,"cap_feerate":7,"max_multiple":50}"#,
        )
        .unwrap();
        assert_eq!(old.price_bump_pct, 10);
        let tight = usdc.with_cap_feerate(40_000_000_000).with_price_bump(30);
        assert_eq!(tight.cap_feerate, 40_000_000_000);
        assert_eq!(tight.price_bump_pct, 30);
        assert_eq!(
            (
                tight.start_secs_left,
                tight.cap_secs_left,
                tight.max_multiple
            ),
            (usdc.start_secs_left, usdc.cap_secs_left, usdc.max_multiple)
        );
        assert_eq!(tight.cap(1_000_000_000), 40_000_000_000);
        let back: FeeEscalation =
            serde_json::from_str(&serde_json::to_string(&tight).unwrap()).unwrap();
        assert_eq!(back, tight);
    }

    /// After every second "replacement underpriced" refusal at a step, the step from the
    /// claim's feerate to the target doubles, never past the cap.
    #[test]
    fn an_underpriced_step_doubles_every_second_refusal_within_the_cap() {
        let esc = FeeEscalation::builtin(Chain::Usdc)
            .unwrap()
            .with_cap_feerate(500);
        let steps: Vec<u64> = (0..6)
            .map(|n| esc.underpriced_target(10, 10, 12, n))
            .collect();
        assert_eq!(steps, [12, 12, 14, 14, 18, 18]);
        assert_eq!(esc.underpriced_target(10, 10, 12, 200), 500, "the cap");
        assert_eq!(esc.underpriced_target(10, 490, 500, 2), 500);
        assert_eq!(esc.underpriced_target(10, 400, 480, 2), 500, "560 capped");
        assert_eq!(
            esc.underpriced_target(10, 10, 10, 4),
            10,
            "no step to double"
        );
    }

    proptest::proptest! {
        /// Whatever the refusals, the doubled step never lowers the target nor passes the
        /// cap (or the target, where a post-leak target is already above it).
        #[test]
        fn an_underpriced_step_stays_between_the_target_and_the_cap(
            base in 1u64..1_000_000_000_000,
            current_over in 0u64..1_000_000_000_000,
            step in 0u64..1_000_000_000_000,
            refusals in 0u32..200,
            cap in 1u64..1_000_000_000_000,
        ) {
            let esc = FeeEscalation::builtin(Chain::Usdc).unwrap().with_cap_feerate(cap);
            let current = base.saturating_add(current_over);
            let target = current.saturating_add(step);
            let got = esc.underpriced_target(base, current, target, refusals);
            proptest::prop_assert!(got >= target);
            proptest::prop_assert!(got <= esc.cap(base).max(target));
            if refusals < 2 {
                proptest::prop_assert_eq!(got, target);
            }
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

    #[test]
    fn the_post_leak_ceiling_is_half_the_leg_then_rises_to_all_but_dust_and_a_step() {
        let w = ClaimDeadline::builtin(Chain::Btc).margin_secs();
        let c = |left| FeeEscalation::ceiling_fee(1_000_000, 294, 150, left, w);
        assert_eq!(c(i64::from(w) * 3), 500_000);
        assert_eq!(c(i64::from(w)), 500_000);
        assert_eq!(
            c(i64::from(w) / 2),
            500_000 + (1_000_000 - 294 - 150 - 500_000) / 2
        );
        assert_eq!(c(0), 1_000_000 - 294 - 150);
        assert_eq!(c(-600), 1_000_000 - 294 - 150);
        let mut prev = 0;
        for left in (-60..=i64::from(w) + 60).rev() {
            assert!(c(left) >= prev, "falls at {left}");
            prev = c(left);
        }
        // A leg too small for dust and a step stays at half.
        assert_eq!(FeeEscalation::ceiling_fee(400, 294, 150, 0, w), 200);
    }

    #[test]
    fn after_the_leak_the_target_passes_the_fixed_cap_only_late_and_never_the_ceiling() {
        let e = FeeEscalation::builtin(Chain::Btc).unwrap();
        let end = i64::from(e.cap_secs_left);
        // Before the cap point: the fixed schedule.
        for left in [7200, 5000, 3600, end] {
            assert_eq!(e.target_after_leak(10, left, 5000), e.target(10, left));
        }
        // After it: above the cap (500), up to the ceiling at the locktime.
        assert!(e.target_after_leak(10, end - 600, 5000) > 500);
        assert_eq!(e.target_after_leak(10, 0, 5000), 5000);
        assert_eq!(e.target_after_leak(10, -60, 5000), 5000);
        // A ceiling under the fixed cap (a small leg) holds throughout.
        for left in [7200, 2000, end, 600, 0] {
            assert!(e.target_after_leak(10, left, 50) <= 50);
        }
    }

    /// The geometric climb past the cap point holds the ceiling: for any first feerate,
    /// ceiling and time left, a replaced claim never pays above the ceiling.
    #[test]
    fn after_the_leak_a_replaced_claim_never_passes_the_ceiling() {
        let e = FeeEscalation::builtin(Chain::Btc).unwrap();
        let start = i64::from(e.start_secs_left);
        for base in [0, 1, 2, 3, 7, 10, 19, 20, 37, 100, 999, 1000, 1001, 50_000] {
            for ceiling in [
                0,
                1,
                2,
                5,
                19,
                20,
                21,
                499,
                500,
                501,
                999,
                1000,
                1001,
                7919,
                1 << 40,
            ] {
                for left in (-700..=start + 700).step_by(13) {
                    let t = e.target_after_leak(base, left, ceiling);
                    assert!(
                        t <= ceiling.max(1),
                        "base {base} ceiling {ceiling} left {left}: {t}"
                    );
                }
            }
        }
    }

    /// USDC (no post-leak ceiling: gas is paid in ETH): before the cap point the cap is the
    /// fixed `min(cap_feerate, 50 x base)`; past it `cap_feerate` binds, whatever the first
    /// feerate. BTC and LTC keep their fixed cap (their post-leak ceiling governs instead).
    #[test]
    fn after_the_leak_the_usdc_cap_is_cap_feerate_and_before_it_the_fixed_cap() {
        let e = FeeEscalation::builtin(Chain::Usdc).unwrap();
        let (gwei, end) = (1_000_000_000u64, i64::from(e.cap_secs_left));
        for base in [1, gwei, 2 * gwei, 5 * gwei, 10 * gwei, 20 * gwei] {
            let fixed = e.cap_feerate.min(50 * base);
            assert_eq!(e.cap(base), fixed);
            for left in [7200, 3600, 1800, end] {
                assert_eq!(e.cap_after_leak(base, left), fixed, "{base} at {left}");
            }
            for left in [end - 1, 600, 1, 0, -60] {
                assert_eq!(
                    e.cap_after_leak(base, left),
                    e.cap_feerate,
                    "{base} at {left}"
                );
            }
        }
        assert_eq!(e.cap(2 * gwei), 100 * gwei, "the clamp note 2 found");
        // A first feerate above the cap is never undercut.
        assert_eq!(e.cap_after_leak(600 * gwei, 0), 600 * gwei);
        for chain in [Chain::Btc, Chain::Ltc] {
            let e = FeeEscalation::builtin(chain).unwrap();
            assert_eq!(e.cap(2), 100, "{chain}");
        }
    }

    /// The USDC target: the fixed schedule before the cap point; past it a geometric climb
    /// from the fixed cap to `cap_feerate`, never above it, never falling. Either way it is
    /// the cap once one more 10% price bump would pass it, so the last version is the cap.
    #[test]
    fn after_the_leak_the_usdc_target_climbs_to_cap_feerate_and_ends_on_it() {
        let e = FeeEscalation::builtin(Chain::Usdc).unwrap();
        let (gwei, start, end) = (
            1_000_000_000u64,
            i64::from(e.start_secs_left),
            i64::from(e.cap_secs_left),
        );
        for base in [1, gwei, 2 * gwei, 10 * gwei] {
            // Before the cap point: the fixed schedule, ending on the fixed cap.
            let fixed = e.cap(base);
            for left in (end..=start + 600).step_by(7) {
                let (t, plain) = (e.same_nonce_target(base, left), e.target(base, left));
                if plain * 110 / 100 > fixed {
                    assert_eq!(t, fixed, "{base} at {left}");
                } else {
                    assert_eq!(t, plain, "{base} at {left}");
                }
            }
            let mut last = e.cap(base);
            for left in (-60..end).rev() {
                let t = e.same_nonce_target(base, left);
                assert!(t >= last && t <= e.cap_feerate, "{base} at {left}: {t}");
                assert!(
                    t == e.cap_feerate || t * 110 / 100 <= e.cap_feerate,
                    "{base} at {left}: {t} is stuck under the cap"
                );
                last = t;
            }
            assert_eq!(e.same_nonce_target(base, 0), e.cap_feerate);
        }
        let t = e.same_nonce_target(2 * gwei, end - 1);
        assert!(t > 100 * gwei && t < 110 * gwei, "{t}");
        // The stalls `claim_race` and `maker_claim_race` found at 5000 cases (mock scale,
        // cap 500): 456 and 487 could never be replaced under 500 at a 10% bump.
        let mock = e.with_cap_feerate(500);
        for (t, want) in [
            (454, 454),
            (455, 455),
            (456, 500),
            (487, 500),
            (499, 500),
            (500, 500),
        ] {
            assert_eq!(mock.reach_cap(t, 500), want, "{t}");
        }
        assert_eq!(mock.with_price_bump(30).reach_cap(390, 500), 500);
        // A node with a stricter bump ends on the cap from further away.
        let strict = e.with_price_bump(30);
        let left = (0..end)
            .rev()
            .find(|&l| strict.same_nonce_target(2 * gwei, l) == e.cap_feerate)
            .unwrap();
        let before = strict.target_after_leak(2 * gwei, left, e.cap_feerate);
        assert!(before * 130 / 100 > e.cap_feerate && before * 110 / 100 <= e.cap_feerate);
        assert!(
            FeeEscalation::should_bump_within(before, e.cap_feerate, e.cap_feerate),
            "the last step to the cap is always sent"
        );
    }

    #[test]
    fn a_cpfp_claim_steps_to_the_ceiling_past_the_cap_point_in_four_bumps() {
        let e = FeeEscalation::builtin(Chain::Ltc).unwrap();
        let end = i64::from(e.cap_secs_left);
        // Before the cap point: the fixed schedule, in doublings.
        assert_eq!(e.cpfp_step(end), None);
        assert_eq!(
            e.cpfp_target_after_leak(10, end + 60, 900),
            e.target(10, end + 60)
        );
        assert!(!e.should_add_child(10, end, 10, 19));
        assert!(e.should_add_child(10, end, 10, 20));
        assert!(e.should_add_child(10, end, 320, e.cap(10)));
        assert!(!e.should_add_child(10, end, e.cap(10), e.cap(10)));
        // Past it: four quarters, the last one running on past the locktime.
        assert_eq!(e.cpfp_step(end - 1), Some((1, end)));
        assert_eq!(e.cpfp_step(end * 3 / 4), Some((1, end)));
        assert_eq!(e.cpfp_step(end * 3 / 4 - 1), Some((2, end - end / 4)));
        assert_eq!(e.cpfp_step(1), Some((4, end - 3 * end / 4)));
        assert_eq!(e.cpfp_step(-600), Some((4, end - 3 * end / 4)));
        // One step per quarter, from the cap (500) to the ceiling: 500 · (8000/500)^(k/4).
        let steps: Vec<u64> = (1..=4)
            .map(|k| e.cpfp_target_after_leak(10, end - (k - 1) * end / 4 - 1, 8000))
            .collect();
        assert_eq!(steps, vec![1000, 2000, 4000, 8000]);
        // Every time left gives one of those, so at most four bumps, each one higher.
        let mut current = e.cap(10);
        let mut bumps = 0;
        for left in (-300..end).rev() {
            let t = e.cpfp_target_after_leak(10, left, 8000);
            assert!(steps.contains(&t), "{t} at {left}");
            if e.should_add_child(10, left, current, t) {
                bumps += 1;
                current = t;
            }
        }
        assert_eq!((bumps, current), (4, 8000));
        // The ceiling holds, and a ceiling under the cap holds throughout.
        for left in (-300..=i64::from(e.start_secs_left)).step_by(7) {
            for ceiling in [0, 1, 50, 499, 500, 501, 8000] {
                assert!(e.cpfp_target_after_leak(10, left, ceiling) <= ceiling.max(1));
            }
        }
        assert_eq!(e.cpfp_target_after_leak(10, 0, 50), 50);
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
