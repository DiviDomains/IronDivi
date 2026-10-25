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
//! It enforces the HTLC rules that matter to the engine — hashlock, double spends and a
//! refund's timelocks as a Bitcoin Core node checks them (see [`refund_premature`]) — and
//! counts coin selections so tests can assert the staking invariant (no `build_funding`
//! before `TakerLockConfirmed`).

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::backend::ChainBackend;
use crate::error::{Result, SwapError};
use crate::htlc::{HtlcParams, LOCKTIME_THRESHOLD, REFUND_SEQUENCE};
use crate::types::{Amount, Chain, Funding, LockedOutput, Outpoint, SignedTx, SpendInfo, Txid};

/// Flat fee every mock transaction pays.
pub const MOCK_FEE: Amount = Amount(1_000);

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
    },
    /// Spends the HTLC through its `OP_CHECKLOCKTIMEVERIFY` branch; a version-2 tx with
    /// one input, so `lock_time` and `sequence` are the tx's nLockTime and the input's
    /// nSequence.
    Refund {
        to: String,
        htlc: HtlcParams,
        at: Outpoint,
        amount: Amount,
        lock_time: u32,
        sequence: u32,
    },
}

/// nSequence that makes an input final: no nLockTime, no CLTV, no BIP68.
const SEQUENCE_FINAL: u32 = 0xffff_ffff;
/// BIP68: set, the input has no relative lock.
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// BIP68: set, the relative lock counts 512-second units of MTP, else blocks.
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;
const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;

#[derive(Debug, Default)]
struct ChainState {
    height: u64,
    mtp: u32,
    /// MTP of the block at each height (the tip's entry moves with `advance_time`).
    mtp_hist: Vec<u32>,
    balances: HashMap<String, u64>,
    /// txid → (tx, height when mined)
    txs: HashMap<Txid, (MockTx, Option<u64>)>,
    /// outpoint → spending txid
    spends: HashMap<Outpoint, Txid>,
    offline: bool,
    /// One-shot: the next `broadcast()` call fails with `SwapError::Rejected` instead of
    /// whatever it would otherwise do, then clears itself.
    reject_next_broadcast: bool,
    /// Txids the node cannot look up (no txindex): `confirmations`/`htlc_output` say `None`
    /// although the tx stays in the chain and `broadcast` still answers already-known.
    blind: HashSet<Txid>,
    /// While set, every backend call fails with this error (an erroring node).
    fail: Option<SwapError>,
    /// While set, every `broadcast()` fails with this error; reads still work.
    fail_broadcasts: Option<SwapError>,
    /// Every txid this chain ever accepted, kept when the tx later leaves the mempool.
    accepted: HashMap<Txid, TxKind>,
    /// Every `broadcast()` call that reached the node, by kind, whatever its answer
    /// (accepted, already known, premature or rejected).
    attempts: HashMap<TxKind, usize>,
}

/// The kind of a mock transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxKind {
    Fund,
    Claim,
    Refund,
}

impl MockTx {
    fn kind(&self) -> TxKind {
        match self {
            MockTx::Fund { .. } => TxKind::Fund,
            MockTx::Claim { .. } => TxKind::Claim,
            MockTx::Refund { .. } => TxKind::Refund,
        }
    }
}

/// How many funding, claim and refund txs a [`MockChain`] has accepted (mempool or mined).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxCounts {
    pub funds: u64,
    pub claims: u64,
    pub refunds: u64,
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
            mtp_hist: vec![mtp],
            ..ChainState::default()
        };
        MockChain {
            chain,
            block_secs,
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Mine `n` blocks: confirms everything in the mempool, advances height and MTP.
    pub fn mine(&self, n: u64) {
        let mut s = self.state.lock();
        for _ in 0..n {
            s.height += 1;
            s.mtp += self.block_secs;
            let mtp = s.mtp;
            s.mtp_hist.push(mtp);
            let h = s.height;
            for (_, mined) in s.txs.values_mut() {
                if mined.is_none() {
                    *mined = Some(h);
                }
            }
        }
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

    /// Mempool eviction: an unconfirmed `txid` (and every unconfirmed tx spending it) is
    /// gone as if it was never sent: a funding gives its inputs back and a claim or refund
    /// takes its credit back, so rebroadcasting the same bytes is accepted again. Returns
    /// false (and changes nothing) for a mined or unknown txid. Test-only.
    pub fn drop_from_mempool(&self, txid: &Txid) -> bool {
        let mut s = self.state.lock();
        if !matches!(s.txs.get(txid), Some((_, None))) {
            return false;
        }
        for id in Self::with_dependents(&s, txid) {
            if !matches!(s.txs.get(&id), Some((_, None))) {
                continue;
            }
            let Some((tx, _)) = s.txs.remove(&id) else {
                continue;
            };
            s.spends.retain(|_, spender| *spender != id);
            match tx {
                MockTx::Fund { from, amount, .. } => {
                    *s.balances.entry(from).or_default() += amount.0 + MOCK_FEE.0;
                }
                MockTx::Claim { to, amount, .. } | MockTx::Refund { to, amount, .. } => {
                    let bal = s.balances.entry(to).or_default();
                    *bal = bal
                        .checked_sub(amount.0 - MOCK_FEE.0)
                        .expect("dropped spend's credit is still there");
                }
            }
        }
        true
    }

    /// Unconfirmed txs, by kind.
    pub fn mempool(&self) -> Vec<(Txid, TxKind)> {
        let s = self.state.lock();
        s.txs
            .iter()
            .filter(|(_, (_, mined))| mined.is_none())
            .map(|(id, (tx, _))| (*id, tx.kind()))
            .collect()
    }

    /// Every txid this chain ever accepted, by kind, including ones since dropped.
    pub fn accepted(&self) -> Vec<(Txid, TxKind)> {
        let s = self.state.lock();
        s.accepted.iter().map(|(id, k)| (*id, *k)).collect()
    }

    /// How many `broadcast()` calls of `kind` reached this chain's node (online), whatever
    /// the node answered: a premature refund the node refused counts too.
    pub fn attempts(&self, kind: TxKind) -> usize {
        self.state.lock().attempts.get(&kind).copied().unwrap_or(0)
    }

    /// The chain has `txid`, in the mempool or mined.
    pub fn contains(&self, txid: &Txid) -> bool {
        self.state.lock().txs.contains_key(txid)
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
        let mut s = self.state.lock();
        s.mtp += secs;
        let mtp = s.mtp;
        *s.mtp_hist.last_mut().expect("genesis entry") = mtp;
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

    /// While `Some`, every backend call on this chain fails with `err`: a node that is up
    /// but erroring, or down (`Transient`). `None` heals it.
    pub fn fail_with(&self, err: Option<SwapError>) {
        self.state.lock().fail = err;
    }

    /// While `Some`, every `broadcast()` on this chain fails with `err` before touching
    /// any state; reads still answer. `None` heals it.
    pub fn fail_broadcasts_with(&self, err: Option<SwapError>) {
        self.state.lock().fail_broadcasts = err;
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

    /// Every tx this chain has ever accepted, by kind, including one since dropped from the
    /// mempool. A rebroadcast of the same txid is not counted twice, so a second funding,
    /// a re-signed spend or a claim plus a refund shows up here.
    pub fn tx_counts(&self) -> TxCounts {
        let mut c = TxCounts::default();
        for kind in self.state.lock().accepted.values() {
            match kind {
                TxKind::Fund => c.funds += 1,
                TxKind::Claim => c.claims += 1,
                TxKind::Refund => c.refunds += 1,
            }
        }
        c
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
        let s = self.chain.state.lock();
        if s.offline {
            Err(SwapError::Transient("mock chain offline".into()))
        } else if let Some(e) = &s.fail {
            Err(e.clone())
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

/// Bitcoin Core's `IsFinalTx` for a one-input tx mined into the block after a tip at
/// `tip_height` with median time past `tip_mtp` (BIP113): a height nLockTime is final once
/// it is below the next block's height, a time nLockTime once it is below the tip's MTP; a
/// zero nLockTime or a final input always is.
fn is_final_tx(lock_time: u32, sequence: u32, tip_height: u64, tip_mtp: u32) -> bool {
    if lock_time == 0 || sequence == SEQUENCE_FINAL {
        return true;
    }
    let cutoff = if lock_time < LOCKTIME_THRESHOLD {
        tip_height as i64 + 1
    } else {
        tip_mtp as i64
    };
    (lock_time as i64) < cutoff
}

/// Bitcoin Core's `CalculateSequenceLocks` + `EvaluateSequenceLocks` (BIP68) for the input
/// of a version-2 tx spending a coin mined at `coin_height` (a mempool coin counts as the
/// next block's), into the block after the tip at `tip_height`. `mtp_of(h)` is the MTP of
/// the block at height `h`. A relative lock of `n` blocks gives
/// `min_height = coin_height + n - 1`; of `n` 512 s units gives
/// `min_time = MTP(block before the coin's) + n * 512 - 1`. Final when
/// `min_height < tip_height + 1` and `min_time < MTP(tip)`; the disable bit turns it off.
fn sequence_lock_final(
    sequence: u32,
    coin_height: u64,
    tip_height: u64,
    mtp_of: impl Fn(u64) -> u32,
) -> bool {
    if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        return true;
    }
    let n = (sequence & SEQUENCE_LOCKTIME_MASK) as i64;
    let mut min_height: i64 = -1;
    let mut min_time: i64 = -1;
    if sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
        let coin_time = mtp_of(coin_height.saturating_sub(1)) as i64;
        min_time = min_time.max(coin_time + (n << SEQUENCE_LOCKTIME_GRANULARITY) - 1);
    } else {
        min_height = min_height.max(coin_height as i64 + n - 1);
    }
    let next_height = tip_height as i64 + 1;
    !(min_height >= next_height || min_time >= mtp_of(tip_height) as i64)
}

/// Why a node refuses `tx` spending the HTLC at `at` into the next block, if it does: the
/// checks and reject strings of Bitcoin Core's mempool, in its order. [`is_final_tx`]
/// (BIP113), then BIP68 relative locks ([`sequence_lock_final`]; a mempool parent counts
/// as mined in the next block), then the script's `OP_CHECKLOCKTIMEVERIFY` (nLockTime of
/// the HTLC's type and at least its locktime, input not final). The BTC backend maps all
/// three to `SwapError::Premature` (`classify_broadcast_error`), and so does the mock.
fn refund_premature(
    s: &ChainState,
    htlc: &HtlcParams,
    at: &Outpoint,
    lock_time: u32,
    sequence: u32,
) -> Option<String> {
    let next = s.height + 1;
    if !is_final_tx(lock_time, sequence, s.height, s.mtp) {
        return Some(format!(
            "non-final (nLockTime {lock_time}, tip mtp {}, next height {next})",
            s.mtp
        ));
    }
    let parent = s.txs.get(&at.txid).and_then(|(_, h)| *h).unwrap_or(next);
    if !sequence_lock_final(sequence, parent, s.height, |h| s.mtp_hist[h as usize]) {
        return Some(format!(
            "non-BIP68-final (sequence {sequence:#x}, parent height {parent})"
        ));
    }
    let same_type = (lock_time < LOCKTIME_THRESHOLD) == (htlc.locktime < LOCKTIME_THRESHOLD);
    if sequence == SEQUENCE_FINAL || !same_type || lock_time < htlc.locktime {
        return Some(format!(
            "mandatory-script-verify-flag-failed (Locktime requirement not satisfied) \
             (nLockTime {lock_time}, CLTV {}, sequence {sequence:#x})",
            htlc.locktime
        ));
    }
    None
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
        }))
    }

    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        self.check_online()?;
        Ok(Self::sign(&MockTx::Refund {
            to: self.owner(),
            htlc: *htlc,
            at: *at,
            amount,
            lock_time: htlc.locktime,
            sequence: REFUND_SEQUENCE,
        }))
    }

    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        self.check_online()?;
        let parsed: MockTx = serde_json::from_slice(&tx.raw)
            .map_err(|e| SwapError::Rejected(format!("decode: {e}")))?;
        let mut s = self.chain.state.lock();
        *s.attempts.entry(parsed.kind()).or_default() += 1;
        if let Some(e) = &s.fail_broadcasts {
            return Err(e.clone());
        }
        if s.reject_next_broadcast {
            s.reject_next_broadcast = false;
            return Err(SwapError::Rejected("mock: forced rejection (test)".into()));
        }
        if s.txs.contains_key(&tx.txid) {
            return Ok(tx.txid);
        }
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
            } => {
                let locked = htlc_amount(&s, htlc, at)
                    .ok_or_else(|| SwapError::Rejected("missing inputs".into()))?;
                if locked != *amount {
                    return Err(SwapError::Rejected("amount mismatch".into()));
                }
                if <[u8; 32]>::from(Sha256::digest(preimage)) != htlc.hash {
                    return Err(SwapError::Rejected("hashlock: wrong preimage".into()));
                }
                if s.spends.contains_key(at) {
                    return Err(SwapError::Rejected("double spend".into()));
                }
                s.spends.insert(*at, tx.txid);
                *s.balances.entry(to.clone()).or_default() += amount.0 - MOCK_FEE.0;
            }
            MockTx::Refund {
                to,
                htlc,
                at,
                amount,
                lock_time,
                sequence,
            } => {
                let locked = htlc_amount(&s, htlc, at)
                    .ok_or_else(|| SwapError::Rejected("missing inputs".into()))?;
                if locked != *amount {
                    return Err(SwapError::Rejected("amount mismatch".into()));
                }
                if let Some(why) = refund_premature(&s, htlc, at, *lock_time, *sequence) {
                    return Err(SwapError::Premature(why));
                }
                if s.spends.contains_key(at) {
                    return Err(SwapError::Rejected("double spend".into()));
                }
                s.spends.insert(*at, tx.txid);
                *s.balances.entry(to.clone()).or_default() += amount.0 - MOCK_FEE.0;
            }
        }
        s.accepted.insert(tx.txid, parsed.kind());
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
        let spend = maker.find_spend(&f.outpoint, 0).await.unwrap().unwrap();
        assert_eq!(spend.extract_preimage(&hash), Some(pre));
        assert_eq!(chain.balance(&taker.pubkey()), Amount(5_000_000 - 1_000));
    }

    fn premature(r: Result<Txid>) -> String {
        match r {
            Err(SwapError::Premature(m)) => m,
            other => panic!("want Premature, got {other:?}"),
        }
    }

    /// A refund of the HTLC at `f` with any nLockTime and nSequence (the engine's builder
    /// always uses the HTLC's locktime and `REFUND_SEQUENCE`).
    fn refund_with(
        b: &MockBackend,
        h: &HtlcParams,
        f: &Funding,
        lock_time: u32,
        seq: u32,
    ) -> SignedTx {
        MockBackend::sign(&MockTx::Refund {
            to: b.owner(),
            htlc: *h,
            at: f.outpoint,
            amount: f.amount,
            lock_time,
            sequence: seq,
        })
    }

    /// BIP113 as Bitcoin Core applies it: the refund (nLockTime = locktime L) is non-final
    /// while the tip's MTP is L-1 and still at MTP == L, and accepted from L+1 on.
    #[tokio::test]
    async fn refund_waits_for_mtp() {
        let chain = MockChain::new(Chain::Btc, 1_800_000_000, 600);
        let taker = chain.backend(3, Amount(1_000_000));
        let (_, hash) = new_preimage();
        let h = htlc([2; 33], taker.pubkey(), hash, 1_800_001_200);
        let f = taker.build_funding(&h, Amount(100_000)).await.unwrap();
        taker.broadcast(&f.tx).await.unwrap();
        let r = taker.build_refund(&h, &f.outpoint, f.amount).await.unwrap();
        assert!(premature(taker.broadcast(&r).await).starts_with("non-final"));
        chain.mine(1);
        chain.advance_time(599); // MTP = L-1
        assert!(premature(taker.broadcast(&r).await).starts_with("non-final"));
        chain.advance_time(1); // MTP = L
        assert!(premature(taker.broadcast(&r).await).starts_with("non-final"));
        assert!(!chain.contains(&r.txid));
        chain.advance_time(1); // MTP = L+1
        taker.broadcast(&r).await.unwrap();
        let spend = taker.find_spend(&f.outpoint, 0).await.unwrap().unwrap();
        assert_eq!(spend.extract_preimage(&hash), None);
    }

    /// Core's finality on all four lock kinds, each at edge-1, at the edge (both not final)
    /// and at the first final point. Only the absolute time lock is an HTLC refund's; the
    /// other three are pinned here so the mock cannot drift from Core on them.
    #[test]
    fn core_finality_edges_all_four_kinds() {
        // Absolute time L (BIP113): final once MTP(tip) > L.
        let l = 1_800_000_000;
        for (mtp, fin) in [(l - 1, false), (l, false), (l + 1, true)] {
            assert_eq!(
                is_final_tx(l, REFUND_SEQUENCE, 7, mtp),
                fin,
                "time, mtp {mtp}"
            );
        }
        // Absolute height H: final once H < tip_height + 1, i.e. tip_height >= H.
        let hl = 500u32;
        for (tip, fin) in [(498, false), (499, false), (500, true)] {
            assert_eq!(
                is_final_tx(hl, REFUND_SEQUENCE, tip, 0),
                fin,
                "height, tip {tip}"
            );
        }
        // A final input or a zero nLockTime is final whatever the tip.
        assert!(is_final_tx(l, SEQUENCE_FINAL, 0, 0));
        assert!(is_final_tx(0, REFUND_SEQUENCE, 0, 0));
        // Relative height n on a coin at height c: min_height = c + n - 1 < tip + 1.
        let (c, n) = (10u64, 3u32);
        let flat = |_: u64| 0u32;
        for (tip, fin) in [(10, false), (11, false), (12, true)] {
            assert_eq!(
                sequence_lock_final(n, c, tip, flat),
                fin,
                "csv height, tip {tip}"
            );
        }
        // Relative time n units: min_time = MTP(block c-1) + n*512 - 1 < MTP(tip). The
        // coin's own block time does not count: MTP(c) is far above MTP(c-1) here.
        let base = 1_800_000_000u32;
        let seq = SEQUENCE_LOCKTIME_TYPE_FLAG | n;
        let edge = base + n * 512 - 1;
        for (tip_mtp, fin) in [(edge - 1, false), (edge, false), (edge + 1, true)] {
            let mtp_of = |h: u64| match h {
                9 => base,
                10 => base + 1_000_000,
                _ => tip_mtp,
            };
            assert_eq!(
                sequence_lock_final(seq, c, 20, mtp_of),
                fin,
                "csv time, tip mtp {tip_mtp}"
            );
        }
        // The disable bit turns either relative lock off.
        assert!(sequence_lock_final(
            SEQUENCE_LOCKTIME_DISABLE_FLAG | n,
            c,
            0,
            flat
        ));
        assert!(sequence_lock_final(REFUND_SEQUENCE, c, 0, flat));
    }

    /// `attempts` counts every broadcast that reached the node, a refused premature refund
    /// and an already-known resend included; `tx_counts` only the accepted txids.
    #[tokio::test]
    async fn attempts_count_refused_and_repeated_broadcasts() {
        let chain = MockChain::new(Chain::Btc, 1_800_000_000, 600);
        let taker = chain.backend(3, Amount(1_000_000));
        let (_, hash) = new_preimage();
        let h = htlc([2; 33], taker.pubkey(), hash, 1_800_000_600);
        let f = taker.build_funding(&h, Amount(100_000)).await.unwrap();
        taker.broadcast(&f.tx).await.unwrap();
        let r = taker.build_refund(&h, &f.outpoint, f.amount).await.unwrap();
        premature(taker.broadcast(&r).await);
        assert_eq!(chain.attempts(TxKind::Refund), 1);
        assert_eq!(chain.tx_counts().refunds, 0);
        chain.mine(1);
        chain.advance_time(1); // MTP = L+1
        taker.broadcast(&r).await.unwrap();
        taker.broadcast(&r).await.unwrap(); // already known
        assert_eq!(chain.attempts(TxKind::Refund), 3);
        assert_eq!(chain.attempts(TxKind::Fund), 1);
        assert_eq!(chain.tx_counts().refunds, 1);
    }

    /// The script's CLTV: an nLockTime below the HTLC's, of the other type, or a final
    /// input fails it however late, with the node's script error.
    #[tokio::test]
    async fn refund_cltv_needs_locktime_and_non_final_input() {
        let chain = MockChain::new(Chain::Btc, 1_800_000_000, 600);
        let taker = chain.backend(3, Amount(1_000_000));
        let (_, hash) = new_preimage();
        let l = 1_800_001_200;
        let h = htlc([2; 33], taker.pubkey(), hash, l);
        let f = taker.build_funding(&h, Amount(100_000)).await.unwrap();
        taker.broadcast(&f.tx).await.unwrap();
        chain.mine(1);
        chain.advance_time(10 * 3600);
        let cltv = "mandatory-script-verify-flag-failed (Locktime requirement not satisfied)";
        let m = premature(
            taker
                .broadcast(&refund_with(&taker, &h, &f, l - 1, REFUND_SEQUENCE))
                .await,
        );
        assert!(m.starts_with(cltv), "{m}");
        // A final input skips the nLockTime check but fails CLTV.
        let m = premature(
            taker
                .broadcast(&refund_with(&taker, &h, &f, l, SEQUENCE_FINAL))
                .await,
        );
        assert!(m.starts_with(cltv), "{m}");
        // A height nLockTime is final against the next height, then fails the time CLTV.
        let m = premature(
            taker
                .broadcast(&refund_with(&taker, &h, &f, 3, REFUND_SEQUENCE))
                .await,
        );
        assert!(m.starts_with("non-final"), "{m}");
        chain.mine(2);
        let m = premature(
            taker
                .broadcast(&refund_with(&taker, &h, &f, 3, REFUND_SEQUENCE))
                .await,
        );
        assert!(m.starts_with(cltv), "{m}");
        assert!(chain.mempool().iter().all(|(_, k)| *k != TxKind::Refund));
        taker
            .broadcast(&refund_with(&taker, &h, &f, l + 7, REFUND_SEQUENCE))
            .await
            .unwrap();
    }

    /// BIP68 (CSV): with the disable bit clear the input's sequence is a relative lock on
    /// its parent, in blocks or in 512 s of MTP since the block before the parent's.
    #[tokio::test]
    async fn refund_bip68_relative_locks() {
        let chain = MockChain::new(Chain::Btc, 1_800_000_000, 600);
        let taker = chain.backend(3, Amount(1_000_000));
        let (_, hash) = new_preimage();
        let l = 1_800_000_000;
        let h = htlc([2; 33], taker.pubkey(), hash, l);
        // Blocks: 3 confirmations of the parent.
        let f = taker.build_funding(&h, Amount(100_000)).await.unwrap();
        taker.broadcast(&f.tx).await.unwrap();
        let r = refund_with(&taker, &h, &f, l, 3);
        chain.mine(1); // parent at height 1, MTP > L
        assert!(premature(taker.broadcast(&r).await).starts_with("non-BIP68-final"));
        chain.mine(1);
        assert!(premature(taker.broadcast(&r).await).starts_with("non-BIP68-final"));
        chain.mine(1); // the parent has 3 confirmations
        taker.broadcast(&r).await.unwrap();
        // Time: 2 units = 1024 s of MTP since the block before the parent's.
        let g = taker.build_funding(&h, Amount(100_000)).await.unwrap();
        taker.broadcast(&g.tx).await.unwrap();
        let r = refund_with(&taker, &h, &g, l, SEQUENCE_LOCKTIME_TYPE_FLAG | 2);
        assert!(premature(taker.broadcast(&r).await).starts_with("non-BIP68-final"));
        chain.mine(1); // parent's block; the block before it had MTP base
        let base = chain.mtp() - 600;
        chain.advance_time(base + 1023 - chain.mtp());
        assert!(premature(taker.broadcast(&r).await).starts_with("non-BIP68-final"));
        chain.advance_time(1);
        taker.broadcast(&r).await.unwrap();
        // The disable bit turns the lock off.
        let k = taker.build_funding(&h, Amount(100_000)).await.unwrap();
        taker.broadcast(&k.tx).await.unwrap();
        let r = refund_with(
            &taker,
            &h,
            &k,
            l + 1,
            SEQUENCE_LOCKTIME_DISABLE_FLAG | 0xffff,
        );
        taker.broadcast(&r).await.unwrap();
    }
}
