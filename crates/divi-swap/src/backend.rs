// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The `ChainBackend` trait — the frozen contract between the engine and each chain.
//!
//! Differences from the sketch in plan §3.1, decided in Wave 0 (see
//! `docs/plans/swap-poc/DECISIONS.md` #3): building and broadcasting are separate so the
//! engine can persist a signed transaction **before** it is broadcast (write-ahead) and
//! rebroadcast the identical bytes after a crash; the backend exposes its own pubkey; and
//! `htlc_output` lets each side verify the counterparty's lock.

use async_trait::async_trait;

use crate::error::{Result, SwapError};
use crate::htlc::HtlcParams;
use crate::types::{Amount, Chain, Funding, LockedOutput, Outpoint, SignedTx, SpendInfo, Txid};

/// The best block as one backend sees it: every field is read from the same block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipHeader {
    /// Its height.
    pub height: u64,
    /// Its hash: 64 lowercase hex characters in display byte order ([`normalize_block_hash`]).
    pub hash: String,
    /// Its header time (unix seconds).
    pub time: u32,
}

/// Normalise a block hash a backend reported to 64 lowercase hex characters, or a
/// `Transient` error (an empty or malformed hash is a node glitch, not a chain state).
pub fn normalize_block_hash(raw: &str) -> Result<String> {
    let h = raw.trim().to_ascii_lowercase();
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(h)
    } else {
        Err(crate::error::SwapError::Transient(format!(
            "malformed tip block hash {raw:?}"
        )))
    }
}

/// How a claim stuck in a chain's mempool can be made to pay more ([`ChainBackend::fee_bump`]).
/// Which one a chain has was read from its node source, not assumed:
/// `docs/plans/swap-poc/status/engine.md`, DJ round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FeeBump {
    /// Neither works: the chain's mempool refuses any spend that conflicts with one it holds,
    /// and its miner scores each transaction on its own fee, so a child cannot pull a parent
    /// in. The claim is resent unchanged (DIVI, ZEC).
    #[default]
    None,
    /// Replace the claim with a re-signed one paying a higher feerate (BIP125 rules: more
    /// absolute fee and a higher feerate). The node relays replacements (BTC).
    Rbf,
    /// Leave the claim, and spend its output in a child paying enough for the pair: the
    /// miner selects by package feerate though replacements are not relayed (LTC).
    Cpfp,
    /// Re-sign the identical call at the claim's own nonce with higher EIP-1559 fees
    /// ([`ChainBackend::build_claim_replacement`]); the feerate is `maxFeePerGas` in wei. The
    /// node takes it only if *both* `maxFeePerGas` and `maxPriorityFeePerGas` rise by its
    /// price bump, at least 1 wei each (go-ethereum `core/txpool/legacypool/list.go`,
    /// `list.Add`; `PriceBump` defaults to 10 in `legacypool.go`), else it answers
    /// `replacement transaction underpriced` (`core/txpool/errors.go`). Not [`Self::Rbf`]:
    /// the conflict is the nonce, which only the previous signed transaction carries, so a
    /// fresh signing at a feerate would take a new nonce behind the stuck claim (USDC).
    SameNonce,
}

/// Sizes of a maker-leg claim on one chain ([`ChainBackend::claim_sizes`]), so the taker can
/// turn a fee ceiling in base units (a share of the maker leg) into a feerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimSizes {
    /// Virtual size of the claim, vbytes.
    pub claim_vsize: u64,
    /// Virtual size of one CPFP child of it, vbytes (0 where the chain takes none).
    pub child_vsize: u64,
    /// Smallest output value the chain relays, base units.
    pub dust: u64,
}

/// One chain, one engine key. A backend owns exactly one secp256k1 key (resolved from
/// 1Password at startup): it funds HTLCs from that key's coins, and claims / refunds to it.
// clippy >= 1.99 flags the `#[must_use]` that `async_trait` adds to the boxed futures.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait ChainBackend: Send + Sync {
    /// Which chain this is.
    fn chain(&self) -> Chain;

    /// Compressed pubkey of this backend's key — the `claim_pubkey` or `refund_pubkey`
    /// to put in an HTLC this side may spend.
    fn pubkey(&self) -> [u8; 33];

    /// Current best block height.
    async fn tip_height(&self) -> Result<u64>;

    /// Hash of the current best block: 64 lowercase hex characters in display byte order
    /// (what block explorers show; no `0x` prefix, on EVM too), so a height can be
    /// cross-checked against an independent explorer. Read-only; no swap path calls it.
    async fn tip_hash(&self) -> Result<String>;

    /// Median time past of the tip (what CLTV unix-time locktimes are compared against).
    async fn median_time_past(&self) -> Result<u32>;

    /// Whether a refund whose absolute locktime is `locktime` is final at a tip with median
    /// time past `mtp`, by this chain's own rule: the engines' refund gate, so neither side
    /// broadcasts a refund the node must refuse.
    ///
    /// Default: Bitcoin Core's `IsFinalTx` for a unix-time nLockTime (BIP113), which needs
    /// `nLockTime < MTP(tip)`: final only once the tip's MTP is *past* the locktime. Every
    /// HTLC locktime is a unix time (`HtlcParams::validate`), and the refund's nSequence
    /// disables BIP68, so this is the only lock a refund has. (A height nLockTime `H` would
    /// instead be final at `tip_height >= H`.)
    fn refund_final(&self, mtp: u32, locktime: u32) -> bool {
        mtp > locktime
    }

    /// Height, hash and header time of the current best block, all read from that one block
    /// (not from separate tip queries that may straddle a new block or land on different
    /// endpoints), so a caller can tell a backend that has stopped following the chain. A
    /// backend that cannot report it fails with `Transient` (the default), and a caller that
    /// needs a fresh view acts on nothing.
    async fn tip_header(&self) -> Result<TipHeader> {
        Err(crate::error::SwapError::Transient(format!(
            "the {} backend does not report its tip header",
            self.chain()
        )))
    }

    /// Whether the block `hash` (as [`TipHeader::hash`]) at `height` is on this backend's
    /// main chain. `Ok(false)` means it was reorged out; a backend that cannot tell (the
    /// default, or a height it has not reached) fails with `Transient`.
    async fn in_best_chain(&self, height: u64, hash: &str) -> Result<bool> {
        let _ = (height, hash);
        Err(crate::error::SwapError::Transient(format!(
            "the {} backend cannot check a block against its main chain",
            self.chain()
        )))
    }

    /// The chain's target block spacing in seconds, from its consensus parameters; `None`
    /// (the default) if this backend does not say.
    fn target_block_secs(&self) -> Option<u32> {
        None
    }

    /// Select coins and build + sign a transaction paying `amount` to the HTLC (P2SH on
    /// DIVI, P2WSH on BTC), change back to this key. **Does not broadcast.**
    ///
    /// This is the only method that performs coin selection. On the maker side the engine
    /// calls it only on entering `MakerLocked` (the staking promise, plan §3.2).
    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding>;

    /// Build + sign the claim spend of `at` (value `amount`) using `preimage`, paying
    /// `amount − fee` to this key. **Does not broadcast.**
    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx>;

    /// Build + sign the refund spend of `at` (value `amount`) with
    /// `nLockTime = htlc.locktime`, paying `amount − fee` to this key. **Does not broadcast.**
    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx>;

    /// Broadcast. Idempotent: a transaction the chain already has (mempool or block)
    /// returns `Ok(txid)`. Timelock-immature refusals return `SwapError::Premature`.
    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid>;

    /// Confirmations of `txid`: `Some(0)` in mempool, `None` if the chain does not know it.
    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>>;

    /// If `at` exists and pays exactly the HTLC script for `htlc`, its value and
    /// confirmations; `None` if the tx is unknown or the output does not match.
    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>>;

    /// Find a transaction spending `outpoint`, scanning blocks from `from_height` to the
    /// tip and then the mempool where the backend can. Must not rely on address or spent
    /// indexes (plan §2: missing on the DIVI testnet proxy).
    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>>;

    /// `lock` (a funding transaction this backend built and broadcast) can never confirm:
    /// give back what the wallet booked for it. Returns `true` if anything was released.
    ///
    /// Only the DIVI backend overrides this: its wallet tombstones the inputs and books the
    /// change as a coin the moment `broadcast` succeeds, so a lock that is gone for good
    /// leaves a phantom change coin and inputs that stay locked. Chains whose wallet
    /// re-reads live coins have nothing to release (the default). The caller must have
    /// shown that the chain does not know `lock`; the backend must still fail closed
    /// (`Ok(false)` or an error, no release) unless it can prove the lock's inputs are
    /// unspent.
    async fn release_dead_lock(&self, _lock: &SignedTx) -> Result<bool> {
        Ok(false)
    }

    /// What this key could put into a funding transaction now: the sum of the coins
    /// [`build_funding`](Self::build_funding) selects from, less inputs an unconfirmed lock
    /// holds, with **no** fee taken off. `spendable >= amount` is therefore necessary for a lock
    /// of `amount`, not sufficient. Read-only: no coin is selected or reserved.
    ///
    /// `None` means this backend cannot tell cheaply; a caller must not refuse on it.
    async fn spendable(&self) -> Result<Option<Amount>> {
        Ok(None)
    }

    /// How this backend can raise the fee of a claim it built ([`FeeBump::None`] unless it
    /// implements [`build_claim_at`](Self::build_claim_at) or
    /// [`build_cpfp`](Self::build_cpfp)).
    fn fee_bump(&self) -> FeeBump {
        FeeBump::None
    }

    /// Feerate, in the chain's base unit per virtual byte, that
    /// [`build_claim`](Self::build_claim) would pay now. `None`: fixed or not known, and so
    /// nothing to escalate from.
    async fn claim_feerate(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    /// Sizes of a claim of `htlc` as [`build_claim_at`](Self::build_claim_at) and
    /// [`build_cpfp`](Self::build_cpfp) build it. `None`: not known, and the taker keeps the
    /// fixed [`FeeEscalation`](crate::FeeEscalation) cap and never declines on the fee.
    fn claim_sizes(&self, _htlc: &HtlcParams) -> Option<ClaimSizes> {
        None
    }

    /// [`build_claim`](Self::build_claim) paying `feerate` (base unit per vbyte) instead of
    /// the backend's own rate. An [`FeeBump::Rbf`] backend signals replacement (BIP125
    /// sequence) so that it can replace an earlier claim of the same outpoint; a
    /// [`FeeBump::Cpfp`] backend implements it too, for the first claim only.
    async fn build_claim_at(
        &self,
        _htlc: &HtlcParams,
        _at: &Outpoint,
        _amount: Amount,
        _preimage: &[u8; 32],
        _feerate: u64,
    ) -> Result<SignedTx> {
        Err(SwapError::Other(format!(
            "{} backend cannot re-sign a claim at a new feerate",
            self.chain()
        )))
    }

    /// Build + sign a child spending output 0 of the last transaction in `package` back to
    /// this key, paying enough that the package and the child together pay `feerate` (base
    /// unit per vbyte). `package` is a claim this backend built of an HTLC worth
    /// `htlc_amount`, then any children built on it, each spending its predecessor's only
    /// output. **Does not broadcast.** Only for [`FeeBump::Cpfp`] backends.
    async fn build_cpfp(
        &self,
        _package: &[SignedTx],
        _htlc_amount: Amount,
        _feerate: u64,
    ) -> Result<SignedTx> {
        Err(SwapError::Other(format!(
            "{} backend cannot build a CPFP child",
            self.chain()
        )))
    }

    /// Re-sign `prev`, a claim this backend built, as its replacement: the same call at the
    /// same nonce, with `maxFeePerGas` at most `feerate` and both fees past the node's
    /// replacement minimum, `price_bump_pct` percent over `prev`'s
    /// ([`crate::FeeEscalation::price_bump_pct`]; [`FeeBump::SameNonce`]). `Ok(None)` when no
    /// replacement the node would take fits under `feerate`: the caller keeps `prev`.
    /// **Does not broadcast.** Only for [`FeeBump::SameNonce`] backends.
    async fn build_claim_replacement(
        &self,
        _prev: &SignedTx,
        _feerate: u64,
        _price_bump_pct: u64,
    ) -> Result<Option<SignedTx>> {
        Err(SwapError::Other(format!(
            "{} backend cannot replace a claim at its nonce",
            self.chain()
        )))
    }

    /// The same key and primary endpoints with the second source off: builds that would
    /// return [`SwapError::Held`] here are built on the primary alone. The engine asks for it
    /// only past the deadline of a claim whose preimage is already public, or of a refund
    /// (`docs/plans/swap-poc/status/engine.md`, EM round); never for a first claim that
    /// would reveal the preimage. Reads (EV): a two-source read that returns `Held` is made
    /// on it past the deadline of the refund it sits in front of, or of a claim already
    /// broadcast (its fee escalation). `None` (the default): this backend never holds.
    fn primary_only(&self) -> Option<std::sync::Arc<dyn ChainBackend>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockChain;

    /// The default gate is Core's: at MTP == locktime the refund is still non-final.
    #[test]
    fn refund_final_default_is_core_time_lock() {
        let b = MockChain::new(Chain::Btc, 0, 600).backend(1, Amount(0));
        let l = 1_800_000_000;
        assert!(!b.refund_final(l - 1, l));
        assert!(!b.refund_final(l, l));
        assert!(b.refund_final(l + 1, l));
    }
}
