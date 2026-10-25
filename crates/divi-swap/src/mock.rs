// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! In-memory chain for engine and daemon tests.
//!
//! One [`MockChain`] is one chain; any number of [`MockBackend`]s (one per key) share it.
//! It enforces the HTLC rules that matter to the engine — hashlock, CLTV against median
//! time past, double spends — and counts coin selections so tests can assert the staking
//! invariant (no `build_funding` before `TakerLockConfirmed`).

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::backend::{ChainBackend, ClaimSizes, FeeBump};
use crate::error::{Result, SwapError};
use crate::htlc::HtlcParams;
use crate::types::{Amount, Chain, Funding, LockedOutput, Outpoint, SignedTx, SpendInfo, Txid};

/// Flat fee every mock funding and refund pays, and a claim at [`MOCK_FEERATE`].
pub const MOCK_FEE: Amount = Amount(1_000);

/// Virtual size of every mock claim, refund and CPFP child.
pub const MOCK_VSIZE: u64 = 100;

/// Feerate of a claim built by [`ChainBackend::build_claim`]: [`MOCK_FEE`] over
/// [`MOCK_VSIZE`].
pub const MOCK_FEERATE: u64 = MOCK_FEE.0 / MOCK_VSIZE;

fn default_feerate() -> u64 {
    MOCK_FEERATE
}

fn is_default_feerate(f: &u64) -> bool {
    *f == MOCK_FEERATE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum MockTx {
    Fund {
        from: String,
        htlc: HtlcParams,
        amount: Amount,
        nonce: u64,
    },
    Claim {
        to: String,
        htlc: HtlcParams,
        at: Outpoint,
        amount: Amount,
        preimage: [u8; 32],
        /// Left out at the default so that claims built before it existed keep their txids.
        #[serde(
            default = "default_feerate",
            skip_serializing_if = "is_default_feerate"
        )]
        feerate: u64,
    },
    /// A CPFP child: spends output 0 of `parent` (worth `value_in`, owned by `to`) back to
    /// `to`.
    Child {
        to: String,
        parent: Txid,
        value_in: u64,
        value_out: u64,
    },
    Refund {
        to: String,
        htlc: HtlcParams,
        at: Outpoint,
        amount: Amount,
        /// Left out at the default so that refunds built before it existed keep their txids.
        #[serde(
            default = "default_feerate",
            skip_serializing_if = "is_default_feerate"
        )]
        feerate: u64,
    },
}

#[derive(Debug, Default)]
struct ChainState {
    height: u64,
    mtp: u32,
    balances: HashMap<String, u64>,
    /// txid → (tx, height when mined)
    txs: HashMap<Txid, (MockTx, Option<u64>)>,
    /// outpoint → spending txid
    spends: HashMap<Outpoint, Txid>,
    offline: bool,
    /// One-shot: the next `broadcast()` call fails with `SwapError::Rejected` instead of
    /// whatever it would otherwise do, then clears itself.
    reject_next_broadcast: bool,
    /// One-shot: the next `broadcast()` of a transaction the chain does not hold yet fails
    /// with `SwapError::Transient` and relays nothing, then clears itself.
    lose_next_new_broadcast: bool,
    /// Txids the node cannot look up (no txindex): `confirmations`/`htlc_output` say `None`
    /// although the tx stays in the chain and `broadcast` still answers already-known.
    blind: HashSet<Txid>,
    /// Every distinct claim/refund ever handed to `broadcast`, accepted or not.
    spend_attempts: HashMap<Txid, MockTx>,
    /// How this chain's backends bump a claim, and what its relay accepts as a bump.
    fee_bump: FeeBump,
    /// Feerate backends report through `claim_feerate` (`None`: [`MOCK_FEERATE`]).
    fee_estimate: Option<u64>,
    /// Feerate of every refund built on this chain (`None`: [`MOCK_FEERATE`]).
    refund_feerate: Option<u64>,
    /// `mine` leaves unmined spends whose effective feerate is below this in the mempool.
    block_floor: u64,
    /// The mempool's minimum feerate: spends below it are refused and evicted.
    mempool_floor: u64,
    /// Under [`FeeBump::Cpfp`], whether a CPFP child replaces an unmined child of the same
    /// parent (a Litecoin node run with `-mempoolreplacement=1`) instead of being refused as
    /// a double spend (the default, as Litecoin Core's).
    child_replacement: bool,
    /// The most unconfirmed transactions any accepted tx has had in its chain, itself
    /// included.
    longest_chain: u64,
}

/// Unconfirmed ancestors, and unconfirmed descendants of each ancestor, a node takes for a
/// tx, both counts including the tx (Litecoin Core v0.21's `DEFAULT_ANCESTOR_LIMIT` and
/// `DEFAULT_DESCENDANT_LIMIT`, `src/validation.h:58,62`; Bitcoin Core's are the same).
pub const MOCK_CHAIN_LIMIT: u64 = 25;

impl MockTx {
    /// Fee and output 0's value of a claim, refund or child (`None` for a funding).
    fn fee_and_out(&self) -> Option<(u64, u64)> {
        match self {
            MockTx::Fund { .. } => None,
            MockTx::Claim {
                amount, feerate, ..
            } => {
                let fee = feerate.saturating_mul(MOCK_VSIZE).min(amount.0);
                Some((fee, amount.0 - fee))
            }
            MockTx::Refund {
                amount, feerate, ..
            } => {
                let fee = feerate.saturating_mul(MOCK_VSIZE).min(amount.0);
                Some((fee, amount.0 - fee))
            }
            MockTx::Child {
                value_in,
                value_out,
                ..
            } => Some((value_in.saturating_sub(*value_out), *value_out)),
        }
    }

    fn feerate(&self) -> u64 {
        self.fee_and_out().map_or(0, |(fee, _)| fee / MOCK_VSIZE)
    }

    /// The outpoint a claim, refund or child spends (`None` for a funding).
    fn spends(&self) -> Option<Outpoint> {
        match self {
            MockTx::Fund { .. } => None,
            MockTx::Claim { at, .. } | MockTx::Refund { at, .. } => Some(*at),
            MockTx::Child { parent, .. } => Some(Outpoint {
                txid: *parent,
                vout: 0,
            }),
        }
    }
}

/// What one HTLC outpoint has seen on a [`MockChain`] ([`MockChain::tx_counts`]).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TxCounts {
    /// Funding txs the chain holds for the outpoint (0 or 1).
    pub fundings: u32,
    /// Claims / refunds of the outpoint the chain accepted (mempool or mined).
    pub claims: u32,
    pub refunds: u32,
    /// Distinct claim / refund txids broadcast for the outpoint, accepted or refused.
    pub claim_attempts: u32,
    pub refund_attempts: u32,
}

/// A simulated chain shared by several backends.
#[derive(Debug, Clone)]
pub struct MockChain {
    chain: Chain,
    block_secs: u32,
    state: Arc<Mutex<ChainState>>,
}

impl MockChain {
    /// New chain at height 0 whose MTP starts at `mtp` and advances `block_secs` per block.
    pub fn new(chain: Chain, mtp: u32, block_secs: u32) -> Self {
        let state = ChainState {
            mtp,
            ..ChainState::default()
        };
        MockChain {
            chain,
            block_secs,
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Mine `n` blocks: confirms everything in the mempool, advances height and MTP.
    ///
    /// Above a block floor ([`MockChain::set_block_floor`]) a spend is mined only if its
    /// effective feerate reaches the floor: its own, or under [`FeeBump::Cpfp`] that of the
    /// package it heads (itself and every unmined descendant), which is then mined together.
    pub fn mine(&self, n: u64) {
        let mut s = self.state.lock();
        for _ in 0..n {
            s.height += 1;
            s.mtp += self.block_secs;
            let h = s.height;
            let floor = s.block_floor;
            let mut take: Vec<Txid> = Vec::new();
            for (id, (tx, mined)) in &s.txs {
                if mined.is_some() {
                    continue;
                }
                let parent_mined = match tx {
                    MockTx::Child { parent, .. } => {
                        matches!(s.txs.get(parent), Some((_, Some(_))))
                    }
                    _ => true,
                };
                if parent_mined && (floor == 0 || Self::effective_feerate(&s, *id) >= floor) {
                    take.push(*id);
                }
            }
            while let Some(id) = take.pop() {
                let Some((_, mined)) = s.txs.get_mut(&id) else {
                    continue;
                };
                if mined.is_some() {
                    continue;
                }
                *mined = Some(h);
                if s.fee_bump == FeeBump::Cpfp {
                    take.extend(Self::spenders_of(&s, id));
                }
            }
        }
    }

    /// From now on `mine` includes only spends paying at least `feerate` (0: everything, the
    /// default). Fundings are always mined.
    pub fn set_block_floor(&self, feerate: u64) {
        self.state.lock().block_floor = feerate;
    }

    /// The mempool's minimum feerate from now on: unmined spends below it (by effective
    /// feerate) are evicted with what spends them, giving back what they booked, and new
    /// ones below it are refused (`SwapError::Rejected`, "mempool min fee not met").
    pub fn set_mempool_floor(&self, feerate: u64) {
        let mut s = self.state.lock();
        s.mempool_floor = feerate;
        let low: Vec<Txid> = s
            .txs
            .iter()
            .filter(|(id, (tx, mined))| {
                mined.is_none()
                    && !matches!(tx, MockTx::Fund { .. })
                    && Self::effective_feerate(&s, **id) < feerate
            })
            .map(|(id, _)| *id)
            .collect();
        for id in low {
            Self::evict(&mut s, id);
        }
    }

    /// Feerate of every refund built on this chain from now on (a maker outbidding the
    /// taker's claim once its refund is valid).
    pub fn set_refund_feerate(&self, feerate: u64) {
        self.state.lock().refund_feerate = Some(feerate);
    }

    /// Unmined `id`'s own feerate, or under [`FeeBump::Cpfp`] its package's (with every
    /// unmined descendant) if higher.
    fn effective_feerate(s: &ChainState, id: Txid) -> u64 {
        let own = s.txs.get(&id).map_or(0, |(tx, _)| tx.feerate());
        if s.fee_bump != FeeBump::Cpfp {
            return own;
        }
        let (fee, n) = Self::package_with_descendants(s, id);
        own.max(fee / (n.max(1) * MOCK_VSIZE))
    }

    fn spenders_of(s: &ChainState, id: Txid) -> Vec<Txid> {
        s.spends
            .iter()
            .filter(|(at, _)| at.txid == id)
            .map(|(_, spender)| *spender)
            .collect()
    }

    /// The unmined txs `tx` spends from, directly or through others, nearest first.
    fn unconfirmed_ancestors(s: &ChainState, tx: &MockTx) -> Vec<Txid> {
        let mut out = Vec::new();
        let mut at = tx.spends();
        while let Some(Outpoint { txid, .. }) = at {
            let Some((parent, None)) = s.txs.get(&txid) else {
                break;
            };
            out.push(txid);
            at = parent.spends();
        }
        out
    }

    /// Refuse `new` ("too-long-mempool-chain") if it would have more than
    /// [`MOCK_CHAIN_LIMIT`] unconfirmed ancestors, or give one of them more than that many
    /// unconfirmed descendants, itself included. A tx `new` replaces does not count.
    fn check_chain_limits(s: &ChainState, new: &MockTx) -> Result<()> {
        let ancestors = Self::unconfirmed_ancestors(s, new);
        let replaced = new
            .spends()
            .and_then(|at| s.spends.get(&at))
            .filter(|old| matches!(s.txs.get(old), Some((_, None))))
            .map_or(0, |old| Self::package_with_descendants(s, *old).1);
        let too_long = ancestors.len() as u64 + 1 > MOCK_CHAIN_LIMIT
            || ancestors
                .iter()
                .any(|a| Self::package_with_descendants(s, *a).1 - replaced + 1 > MOCK_CHAIN_LIMIT);
        if too_long {
            return Err(SwapError::Rejected(format!(
                "too-long-mempool-chain: {} unconfirmed ancestors, limit {MOCK_CHAIN_LIMIT}",
                ancestors.len()
            )));
        }
        Ok(())
    }

    /// Fee and count of unmined `id` and every unmined tx spending it.
    fn package_with_descendants(s: &ChainState, id: Txid) -> (u64, u64) {
        let (mut fee, mut n) = (0, 0);
        let mut queue = vec![id];
        while let Some(id) = queue.pop() {
            if let Some((tx, None)) = s.txs.get(&id) {
                fee += tx.fee_and_out().map_or(0, |(f, _)| f);
                n += 1;
            }
            queue.extend(Self::spenders_of(s, id));
        }
        (fee, n)
    }

    /// Reorg: `txid` (and every mined tx that spends its outputs) goes back to the mempool.
    /// Test-only; unknown ids are ignored.
    pub fn unconfirm(&self, txid: &Txid) {
        let mut s = self.state.lock();
        let ids = Self::with_dependents(&s, txid);
        for id in ids {
            if let Some((_, mined)) = s.txs.get_mut(&id) {
                *mined = None;
            }
        }
    }

    /// Reorg: `txid` (and every tx that spends its outputs) is gone from chain and mempool,
    /// and a dropped funding tx gives its inputs back, so rebroadcasting it works again.
    /// Test-only; unknown ids are ignored.
    pub fn forget(&self, txid: &Txid) {
        let mut s = self.state.lock();
        for id in Self::with_dependents(&s, txid) {
            let Some((tx, _)) = s.txs.remove(&id) else {
                continue;
            };
            s.spends.retain(|_, spender| *spender != id);
            if let MockTx::Fund { from, amount, .. } = tx {
                *s.balances.entry(from).or_default() += amount.0 + MOCK_FEE.0;
            }
        }
    }

    /// The node cannot look `txid` up (a backend without txindex), though it is in the chain.
    /// Test-only.
    pub fn blind(&self, txid: &Txid) {
        self.state.lock().blind.insert(*txid);
    }

    fn with_dependents(s: &ChainState, txid: &Txid) -> Vec<Txid> {
        let mut ids = vec![*txid];
        ids.extend(
            s.spends
                .iter()
                .filter(|(at, _)| at.txid == *txid)
                .map(|(_, spender)| *spender),
        );
        ids
    }

    /// Move MTP forward without mining (models a slow chain).
    pub fn advance_time(&self, secs: u32) {
        self.state.lock().mtp += secs;
    }

    /// While offline every backend call fails with `SwapError::Transient`.
    pub fn set_offline(&self, offline: bool) {
        self.state.lock().offline = offline;
    }

    /// The next `broadcast()` on this chain (by any backend) fails with
    /// `SwapError::Rejected`, as if a node refused the signed bytes for good (e.g. a stale
    /// or buggy signature) — before touching any balance/spend state. One-shot: it clears
    /// itself after firing, so a re-signed retry goes through normally. For tests of the
    /// "a rejected claim/refund is forgotten and re-signed on the next step" paths.
    pub fn reject_next_broadcast(&self) {
        self.state.lock().reject_next_broadcast = true;
    }

    /// The next `broadcast()` on this chain of a transaction it does not hold yet fails
    /// with `SwapError::Transient` and relays nothing; rebroadcasts of transactions it holds
    /// still answer already-known. One-shot. As if the process died between persisting a
    /// transaction and sending it: the record has it, the chain never saw it.
    pub fn lose_next_new_broadcast(&self) {
        self.state.lock().lose_next_new_broadcast = true;
    }

    /// How backends on this chain bump a claim ([`ChainBackend::fee_bump`]) and what the
    /// relay accepts: under [`FeeBump::Rbf`] a spend of an outpoint an unmined claim or
    /// refund already spends replaces it if it pays at least that one's fee plus one unit
    /// per vbyte (BIP125 rules 3 and 4, incremental relay feerate 1); otherwise it is a
    /// double spend. Default [`FeeBump::None`]: backends report no feerate and nothing is
    /// ever replaced, as before.
    pub fn set_fee_bump(&self, bump: FeeBump) {
        self.state.lock().fee_bump = bump;
    }

    /// Under [`FeeBump::Cpfp`], from now on a CPFP child spending the output an unmined
    /// child already spends replaces it if it pays at least that one's fee (with its
    /// descendants') plus one unit per vbyte, at a higher feerate: a Litecoin node run with
    /// `-mempoolreplacement=1`, the child signalling BIP125. Off (the default, as Litecoin
    /// Core's `DEFAULT_ENABLE_REPLACEMENT`): it is refused as a double spend.
    pub fn set_child_replacement(&self, on: bool) {
        self.state.lock().child_replacement = on;
    }

    /// The most unconfirmed transactions in one chain (ancestors of a tx, itself included)
    /// the chain has accepted so far. Test-only observation of how deep a CPFP package got.
    pub fn longest_unconfirmed_chain(&self) -> u64 {
        self.state.lock().longest_chain
    }

    /// The feerate backends report through `claim_feerate` from now on.
    pub fn set_fee_estimate(&self, feerate: u64) {
        self.state.lock().fee_estimate = Some(feerate);
    }

    /// Feerate of `txid` (a claim, refund or CPFP child) if the chain holds it.
    pub fn feerate_of(&self, txid: &Txid) -> Option<u64> {
        self.state.lock().txs.get(txid).map(|(tx, _)| tx.feerate())
    }

    /// The txid spending `at`, mined or not.
    pub fn spender(&self, at: &Outpoint) -> Option<Txid> {
        self.state.lock().spends.get(at).copied()
    }

    /// Drop unmined `id` and everything spending it, giving back what each booked
    /// (a replacement evicting the losers).
    fn evict(s: &mut ChainState, id: Txid) {
        let mut queue = vec![id];
        while let Some(id) = queue.pop() {
            queue.extend(
                s.spends
                    .iter()
                    .filter(|(at, _)| at.txid == id)
                    .map(|(_, spender)| *spender),
            );
            if !matches!(s.txs.get(&id), Some((_, None))) {
                continue;
            }
            let (tx, _) = s.txs.remove(&id).expect("checked above");
            s.spends.retain(|_, spender| *spender != id);
            match tx {
                MockTx::Fund { from, amount, .. } => {
                    *s.balances.entry(from).or_default() += amount.0 + MOCK_FEE.0;
                }
                MockTx::Claim { ref to, .. } | MockTx::Refund { ref to, .. } => {
                    let (_, out) = tx.fee_and_out().expect("a spend");
                    let bal = s.balances.entry(to.clone()).or_default();
                    *bal = bal.saturating_sub(out);
                }
                MockTx::Child {
                    to,
                    value_in,
                    value_out,
                    ..
                } => {
                    let bal = s.balances.entry(to).or_default();
                    *bal = bal.saturating_sub(value_out) + value_in;
                }
            }
        }
    }

    /// Make room for `new` spending `at`, or refuse it as a double spend: an unmined
    /// claim or refund there is replaced if the relay takes replacements and `new` pays
    /// enough more ([`MockChain::set_fee_bump`]), and so is an unmined CPFP child where the
    /// relay takes child replacements ([`MockChain::set_child_replacement`]).
    fn replace_spend(s: &mut ChainState, at: &Outpoint, new: &MockTx) -> Result<()> {
        let Some(&old) = s.spends.get(at) else {
            return Ok(());
        };
        let replaceable = match (s.txs.get(&old), new) {
            (Some((MockTx::Claim { .. } | MockTx::Refund { .. }, None)), _) => {
                s.fee_bump == FeeBump::Rbf
            }
            (Some((MockTx::Child { .. }, None)), MockTx::Child { .. }) => {
                s.fee_bump == FeeBump::Cpfp && s.child_replacement
            }
            _ => false,
        };
        if !replaceable {
            return Err(SwapError::Rejected("double spend".into()));
        }
        let (new_fee, _) = new.fee_and_out().expect("a spend");
        let need = Self::package_with_descendants(s, old).0 + MOCK_VSIZE;
        if new_fee < need || new.feerate() <= s.txs[&old].0.feerate() {
            return Err(SwapError::Rejected(format!(
                "insufficient fee: replacement pays {new_fee}, needs {need}"
            )));
        }
        Self::evict(s, old);
        Ok(())
    }

    /// Funding, accepted spends and spend attempts of `at`. Test-only observation, e.g.
    /// to check that no outpoint is ever claimed twice or both claimed and refunded.
    pub fn tx_counts(&self, at: &Outpoint) -> TxCounts {
        let s = self.state.lock();
        let mut c = TxCounts {
            fundings: s.txs.contains_key(&at.txid) as u32,
            ..TxCounts::default()
        };
        for (tx, _) in s.txs.values() {
            match tx {
                MockTx::Claim { at: a, .. } if a == at => c.claims += 1,
                MockTx::Refund { at: a, .. } if a == at => c.refunds += 1,
                _ => {}
            }
        }
        for tx in s.spend_attempts.values() {
            match tx {
                MockTx::Claim { at: a, .. } if a == at => c.claim_attempts += 1,
                MockTx::Refund { at: a, .. } if a == at => c.refund_attempts += 1,
                _ => {}
            }
        }
        c
    }

    /// Current MTP.
    pub fn mtp(&self) -> u32 {
        self.state.lock().mtp
    }

    /// Deterministic fake hash of the tip block: the chain index and height, zero-padded
    /// to 64 hex characters (distinct per height and per chain).
    pub fn tip_hash(&self) -> String {
        format!("{:02x}{:062x}", self.chain as u8, self.height())
    }

    /// Current height.
    pub fn height(&self) -> u64 {
        self.state.lock().height
    }

    /// Spendable balance of a backend's key.
    pub fn balance(&self, pubkey: &[u8; 33]) -> Amount {
        Amount(
            *self
                .state
                .lock()
                .balances
                .get(&hex::encode(pubkey))
                .unwrap_or(&0),
        )
    }

    /// A backend on this chain with a deterministic key derived from `seed` and `balance`.
    pub fn backend(&self, seed: u8, balance: Amount) -> MockBackend {
        let mut pubkey = [seed; 33];
        pubkey[0] = 0x02;
        self.state
            .lock()
            .balances
            .insert(hex::encode(pubkey), balance.0);
        MockBackend {
            chain: self.clone(),
            pubkey,
            funding_calls: Arc::new(AtomicU64::new(0)),
            released: Arc::default(),
            nonce: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// A [`ChainBackend`] over a [`MockChain`].
#[derive(Debug, Clone)]
pub struct MockBackend {
    chain: MockChain,
    pubkey: [u8; 33],
    funding_calls: Arc<AtomicU64>,
    nonce: Arc<AtomicU64>,
    released: Arc<Mutex<Vec<Txid>>>,
}

impl MockBackend {
    /// How many times `build_funding` (coin selection) has been called.
    pub fn funding_calls(&self) -> u64 {
        self.funding_calls.load(Ordering::SeqCst)
    }

    /// Locks the engine asked this backend to release as lost (`release_dead_lock`), in order.
    pub fn released_locks(&self) -> Vec<Txid> {
        self.released.lock().clone()
    }

    /// The underlying chain.
    pub fn mock_chain(&self) -> &MockChain {
        &self.chain
    }

    fn owner(&self) -> String {
        hex::encode(self.pubkey)
    }

    fn check_online(&self) -> Result<()> {
        if self.chain.state.lock().offline {
            Err(SwapError::Transient("mock chain offline".into()))
        } else {
            Ok(())
        }
    }

    fn sign(tx: &MockTx) -> SignedTx {
        let raw = serde_json::to_vec(tx).expect("mock tx serializes");
        SignedTx {
            txid: Txid(Sha256::digest(&raw).into()),
            raw,
        }
    }
}

fn htlc_amount(s: &ChainState, htlc: &HtlcParams, at: &Outpoint) -> Option<Amount> {
    match s.txs.get(&at.txid) {
        Some((
            MockTx::Fund {
                htlc: h, amount, ..
            },
            _,
        )) if h == htlc && at.vout == 0 => Some(*amount),
        _ => None,
    }
}

#[async_trait]
impl ChainBackend for MockBackend {
    fn chain(&self) -> Chain {
        self.chain.chain
    }

    fn pubkey(&self) -> [u8; 33] {
        self.pubkey
    }

    async fn tip_height(&self) -> Result<u64> {
        self.check_online()?;
        Ok(self.chain.height())
    }

    async fn tip_hash(&self) -> Result<String> {
        self.check_online()?;
        Ok(self.chain.tip_hash())
    }

    async fn median_time_past(&self) -> Result<u32> {
        self.check_online()?;
        Ok(self.chain.mtp())
    }

    async fn spendable(&self) -> Result<Option<Amount>> {
        self.check_online()?;
        Ok(Some(self.chain.balance(&self.pubkey)))
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        self.check_online()?;
        htlc.validate()?;
        self.funding_calls.fetch_add(1, Ordering::SeqCst);
        let have = self.chain.balance(&self.pubkey);
        if have.0 < amount.0 + MOCK_FEE.0 {
            return Err(SwapError::InsufficientFunds(format!(
                "have {have}, need {amount} + fee"
            )));
        }
        let tx = Self::sign(&MockTx::Fund {
            from: self.owner(),
            htlc: *htlc,
            amount,
            nonce: self.nonce.fetch_add(1, Ordering::SeqCst),
        });
        Ok(Funding {
            outpoint: Outpoint {
                txid: tx.txid,
                vout: 0,
            },
            tx,
            amount,
        })
    }

    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx> {
        self.check_online()?;
        Ok(Self::sign(&MockTx::Claim {
            to: self.owner(),
            htlc: *htlc,
            at: *at,
            amount,
            preimage: *preimage,
            feerate: MOCK_FEERATE,
        }))
    }

    fn fee_bump(&self) -> FeeBump {
        self.chain.state.lock().fee_bump
    }

    async fn claim_feerate(&self) -> Result<Option<u64>> {
        self.check_online()?;
        let s = self.chain.state.lock();
        Ok((s.fee_bump != FeeBump::None).then(|| s.fee_estimate.unwrap_or(MOCK_FEERATE)))
    }

    /// Every mock claim and child is [`MOCK_VSIZE`]; the mock has no dust limit.
    fn claim_sizes(&self, _htlc: &HtlcParams) -> Option<ClaimSizes> {
        (self.fee_bump() != FeeBump::None).then_some(ClaimSizes {
            claim_vsize: MOCK_VSIZE,
            child_vsize: MOCK_VSIZE,
            dust: 0,
        })
    }

    async fn build_claim_at(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
        feerate: u64,
    ) -> Result<SignedTx> {
        self.check_online()?;
        if self.fee_bump() == FeeBump::None {
            return Err(SwapError::Other("mock chain takes no fee bumps".into()));
        }
        Ok(Self::sign(&MockTx::Claim {
            to: self.owner(),
            htlc: *htlc,
            at: *at,
            amount,
            preimage: *preimage,
            feerate: feerate.max(1),
        }))
    }

    async fn build_cpfp(
        &self,
        package: &[SignedTx],
        htlc_amount: Amount,
        feerate: u64,
    ) -> Result<SignedTx> {
        self.check_online()?;
        if self.fee_bump() != FeeBump::Cpfp {
            return Err(SwapError::Other("mock chain takes no CPFP".into()));
        }
        let last = package
            .last()
            .ok_or_else(|| SwapError::InvalidParams("empty CPFP package".into()))?;
        let parsed: MockTx = serde_json::from_slice(&last.raw)
            .map_err(|e| SwapError::Other(format!("decode: {e}")))?;
        let (_, value_in) = parsed
            .fee_and_out()
            .ok_or_else(|| SwapError::InvalidParams("CPFP parent is a funding".into()))?;
        let package_fee = htlc_amount.0.saturating_sub(value_in);
        let want = feerate
            .max(1)
            .saturating_mul(MOCK_VSIZE * (package.len() as u64 + 1));
        let fee = want.saturating_sub(package_fee).max(MOCK_VSIZE);
        let value_out = value_in.checked_sub(fee).ok_or_else(|| {
            SwapError::InsufficientFunds(format!("claim output {value_in} < fee {fee}"))
        })?;
        Ok(Self::sign(&MockTx::Child {
            to: self.owner(),
            parent: last.txid,
            value_in,
            value_out,
        }))
    }

    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        self.check_online()?;
        let feerate = self
            .chain
            .state
            .lock()
            .refund_feerate
            .unwrap_or(MOCK_FEERATE);
        Ok(Self::sign(&MockTx::Refund {
            to: self.owner(),
            htlc: *htlc,
            at: *at,
            amount,
            feerate,
        }))
    }

    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        self.check_online()?;
        let parsed: MockTx = serde_json::from_slice(&tx.raw)
            .map_err(|e| SwapError::Rejected(format!("decode: {e}")))?;
        let mut s = self.chain.state.lock();
        if !matches!(parsed, MockTx::Fund { .. }) {
            s.spend_attempts.insert(tx.txid, parsed.clone());
        }
        if s.reject_next_broadcast {
            s.reject_next_broadcast = false;
            return Err(SwapError::Rejected("mock: forced rejection (test)".into()));
        }
        if s.txs.contains_key(&tx.txid) {
            return Ok(tx.txid);
        }
        if s.lose_next_new_broadcast {
            s.lose_next_new_broadcast = false;
            return Err(SwapError::Transient(
                "mock: lost before broadcast (test)".into(),
            ));
        }
        if !matches!(parsed, MockTx::Fund { .. }) && parsed.feerate() < s.mempool_floor {
            return Err(SwapError::Rejected(format!(
                "mempool min fee not met: {} < {}",
                parsed.feerate(),
                s.mempool_floor
            )));
        }
        MockChain::check_chain_limits(&s, &parsed)?;
        match &parsed {
            MockTx::Fund { from, amount, .. } => {
                let bal = s.balances.entry(from.clone()).or_default();
                if *bal < amount.0 + MOCK_FEE.0 {
                    return Err(SwapError::Rejected("insufficient funds".into()));
                }
                *bal -= amount.0 + MOCK_FEE.0;
            }
            MockTx::Claim {
                to,
                htlc,
                at,
                amount,
                preimage,
                ..
            } => {
                let locked = htlc_amount(&s, htlc, at)
                    .ok_or_else(|| SwapError::Rejected("missing inputs".into()))?;
                if locked != *amount {
                    return Err(SwapError::Rejected("amount mismatch".into()));
                }
                if <[u8; 32]>::from(Sha256::digest(preimage)) != htlc.hash {
                    return Err(SwapError::Rejected("hashlock: wrong preimage".into()));
                }
                MockChain::replace_spend(&mut s, at, &parsed)?;
                s.spends.insert(*at, tx.txid);
                let (_, out) = parsed.fee_and_out().expect("a spend");
                *s.balances.entry(to.clone()).or_default() += out;
            }
            MockTx::Child {
                to,
                parent,
                value_in,
                ..
            } => {
                let at = Outpoint {
                    txid: *parent,
                    vout: 0,
                };
                let (_, parent_out) = s
                    .txs
                    .get(parent)
                    .and_then(|(p, _)| p.fee_and_out())
                    .ok_or_else(|| SwapError::Rejected("missing inputs".into()))?;
                if parent_out != *value_in {
                    return Err(SwapError::Rejected("amount mismatch".into()));
                }
                MockChain::replace_spend(&mut s, &at, &parsed)?;
                s.spends.insert(at, tx.txid);
                let (_, out) = parsed.fee_and_out().expect("a spend");
                let bal = s.balances.entry(to.clone()).or_default();
                *bal = bal.saturating_sub(*value_in) + out;
            }
            MockTx::Refund {
                to,
                htlc,
                at,
                amount,
                ..
            } => {
                let locked = htlc_amount(&s, htlc, at)
                    .ok_or_else(|| SwapError::Rejected("missing inputs".into()))?;
                if locked != *amount {
                    return Err(SwapError::Rejected("amount mismatch".into()));
                }
                if s.mtp < htlc.locktime {
                    return Err(SwapError::Premature(format!(
                        "non-final: mtp {} < locktime {}",
                        s.mtp, htlc.locktime
                    )));
                }
                MockChain::replace_spend(&mut s, at, &parsed)?;
                s.spends.insert(*at, tx.txid);
                let (_, out) = parsed.fee_and_out().expect("a spend");
                *s.balances.entry(to.clone()).or_default() += out;
            }
        }
        let depth = MockChain::unconfirmed_ancestors(&s, &parsed).len() as u64 + 1;
        s.longest_chain = s.longest_chain.max(depth);
        s.txs.insert(tx.txid, (parsed, None));
        Ok(tx.txid)
    }

    async fn release_dead_lock(&self, lock: &SignedTx) -> Result<bool> {
        self.released.lock().push(lock.txid);
        Ok(true)
    }

    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        self.check_online()?;
        let s = self.chain.state.lock();
        if s.blind.contains(txid) {
            return Ok(None);
        }
        Ok(s.txs.get(txid).map(|(_, mined)| match mined {
            Some(h) => (s.height - h + 1) as u32,
            None => 0,
        }))
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        self.check_online()?;
        let s = self.chain.state.lock();
        if s.blind.contains(&at.txid) {
            return Ok(None);
        }
        Ok(htlc_amount(&s, htlc, at).map(|amount| {
            let mined = s.txs[&at.txid].1;
            LockedOutput {
                amount,
                confirmations: mined.map_or(0, |h| (s.height - h + 1) as u32),
            }
        }))
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        self.check_online()?;
        let s = self.chain.state.lock();
        let Some(spender) = s.spends.get(outpoint) else {
            return Ok(None);
        };
        let (tx, mined) = &s.txs[spender];
        if mined.is_some_and(|h| h < from_height) {
            return Ok(None);
        }
        let witness = match tx {
            MockTx::Claim { preimage, .. } => vec![vec![0x30; 71], preimage.to_vec(), vec![1]],
            _ => vec![vec![0x30; 71], vec![]],
        };
        Ok(Some(SpendInfo {
            txid: *spender,
            input_index: 0,
            height: *mined,
            script_sig: Vec::new(),
            witness,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc::new_preimage;

    fn htlc(claim: [u8; 33], refund: [u8; 33], hash: [u8; 32], locktime: u32) -> HtlcParams {
        HtlcParams {
            hash,
            claim_pubkey: claim,
            refund_pubkey: refund,
            locktime,
            script_version: Default::default(),
        }
    }

    #[tokio::test]
    async fn tip_hash_tracks_height_and_goes_offline() {
        let chain = MockChain::new(Chain::Divi, 1_800_000_000, 60);
        let b = chain.backend(1, Amount(0));
        let h0 = b.tip_hash().await.unwrap();
        assert_eq!(h0.len(), 64);
        assert!(h0
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        chain.mine(1);
        assert_ne!(b.tip_hash().await.unwrap(), h0);
        chain.set_offline(true);
        assert!(b.tip_hash().await.is_err());
    }

    #[tokio::test]
    async fn fund_claim_and_extract() {
        let chain = MockChain::new(Chain::Divi, 1_800_000_000, 60);
        let maker = chain.backend(1, Amount(10_000_000));
        let taker = chain.backend(2, Amount(0));
        let (pre, hash) = new_preimage();
        let h = htlc(taker.pubkey(), maker.pubkey(), hash, 1_800_003_600);
        let f = maker.build_funding(&h, Amount(5_000_000)).await.unwrap();
        maker.broadcast(&f.tx).await.unwrap();
        maker.broadcast(&f.tx).await.unwrap(); // idempotent
        chain.mine(1);
        assert_eq!(maker.confirmations(&f.tx.txid).await.unwrap(), Some(1));
        let wrong = taker
            .build_claim(&h, &f.outpoint, f.amount, &[0; 32])
            .await
            .unwrap();
        assert!(taker.broadcast(&wrong).await.is_err());
        let c = taker
            .build_claim(&h, &f.outpoint, f.amount, &pre)
            .await
            .unwrap();
        taker.broadcast(&c).await.unwrap();
        taker.broadcast(&c).await.unwrap(); // idempotent
        let r = maker.build_refund(&h, &f.outpoint, f.amount).await.unwrap();
        assert!(maker.broadcast(&r).await.is_err()); // premature, and spent anyway
        let counts = chain.tx_counts(&f.outpoint);
        assert_eq!(
            counts,
            TxCounts {
                fundings: 1,
                claims: 1,
                refunds: 0,
                claim_attempts: 2,
                refund_attempts: 1,
            }
        );
        let spend = maker.find_spend(&f.outpoint, 0).await.unwrap().unwrap();
        assert_eq!(spend.extract_preimage(&hash), Some(pre));
        assert_eq!(chain.balance(&taker.pubkey()), Amount(5_000_000 - 1_000));
    }

    #[tokio::test]
    async fn refund_waits_for_mtp() {
        let chain = MockChain::new(Chain::Btc, 1_800_000_000, 600);
        let taker = chain.backend(3, Amount(1_000_000));
        let (_, hash) = new_preimage();
        let h = htlc([2; 33], taker.pubkey(), hash, 1_800_001_200);
        let f = taker.build_funding(&h, Amount(100_000)).await.unwrap();
        taker.broadcast(&f.tx).await.unwrap();
        let r = taker.build_refund(&h, &f.outpoint, f.amount).await.unwrap();
        assert!(matches!(
            taker.broadcast(&r).await,
            Err(SwapError::Premature(_))
        ));
        chain.mine(2);
        taker.broadcast(&r).await.unwrap();
        let spend = taker.find_spend(&f.outpoint, 0).await.unwrap().unwrap();
        assert_eq!(spend.extract_preimage(&hash), None);
    }

    /// A claim with a mined funding and `children` CPFP children chained on it, the last
    /// paying for the whole package at `feerate`; returns the package, claim first.
    async fn claim_chain(
        chain: &MockChain,
        children: usize,
        feerate: u64,
    ) -> (MockBackend, Amount, Vec<SignedTx>) {
        chain.set_fee_bump(FeeBump::Cpfp);
        let maker = chain.backend(1, Amount(10_000_000));
        let taker = chain.backend(2, Amount(0));
        let (pre, hash) = new_preimage();
        let h = htlc(taker.pubkey(), maker.pubkey(), hash, 1_800_003_600);
        let f = maker.build_funding(&h, Amount(5_000_000)).await.unwrap();
        maker.broadcast(&f.tx).await.unwrap();
        chain.mine(1);
        let claim = taker
            .build_claim_at(&h, &f.outpoint, f.amount, &pre, 1)
            .await
            .unwrap();
        taker.broadcast(&claim).await.unwrap();
        let mut package = vec![claim];
        for _ in 0..children {
            let child = taker.build_cpfp(&package, f.amount, feerate).await.unwrap();
            taker.broadcast(&child).await.unwrap();
            package.push(child);
        }
        (taker, f.amount, package)
    }

    #[tokio::test]
    async fn an_unconfirmed_chain_stops_at_the_25_transaction_limit() {
        // Litecoin Core (and Bitcoin Core) refuse a tx with more than 25 unconfirmed
        // ancestors, itself included, or one that would give an ancestor more than 25
        // unconfirmed descendants, itself included ("too-long-mempool-chain").
        let chain = MockChain::new(Chain::Ltc, 1_800_000_000, 150);
        let (taker, amount, package) = claim_chain(&chain, 24, 2).await;
        let child = taker.build_cpfp(&package, amount, 2).await.unwrap();
        let refused = taker.broadcast(&child).await;
        assert!(
            matches!(&refused, Err(SwapError::Rejected(m)) if m.contains("too-long-mempool-chain")),
            "{refused:?}"
        );
        assert_eq!(chain.feerate_of(&child.txid), None);
        // Once the package is mined the child fits.
        chain.mine(1);
        taker.broadcast(&child).await.unwrap();
    }

    #[tokio::test]
    async fn a_cpfp_child_replaces_its_sibling_only_where_the_relay_takes_it() {
        let chain = MockChain::new(Chain::Ltc, 1_800_000_000, 150);
        let (taker, amount, package) = claim_chain(&chain, 1, 20).await;
        let (claim, first) = (&package[0], &package[1]);
        let higher = taker
            .build_cpfp(std::slice::from_ref(claim), amount, 30)
            .await
            .unwrap();
        // Litecoin Core's default: a second spend of the claim's output is a conflict.
        let refused = taker.broadcast(&higher).await;
        assert!(
            matches!(&refused, Err(SwapError::Rejected(m)) if m.contains("double spend")),
            "{refused:?}"
        );

        chain.set_child_replacement(true);
        taker.broadcast(&higher).await.unwrap();
        let at = Outpoint {
            txid: claim.txid,
            vout: 0,
        };
        assert_eq!(chain.spender(&at), Some(higher.txid));
        assert_eq!(
            chain.feerate_of(&first.txid),
            None,
            "the sibling is evicted"
        );
        // The evicted sibling pays less, so it cannot come back.
        let refused = taker.broadcast(first).await;
        assert!(
            matches!(&refused, Err(SwapError::Rejected(m)) if m.contains("insufficient fee")),
            "{refused:?}"
        );
        assert_eq!(chain.longest_unconfirmed_chain(), 2);
        chain.mine(1);
        assert_eq!(taker.confirmations(&higher.txid).await.unwrap(), Some(1));
    }
}
