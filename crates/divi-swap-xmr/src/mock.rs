// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! In-process chains for the adaptor swap.
//!
//! [`MockDiviChain`] carries **real** DIVI transactions: every input is checked with
//! `divi_script::verify_input` against the output it spends, `nLockTime` is enforced with
//! `Transaction::is_final` against the chain's median time past, and double spends are
//! refused. So a wrong signature, a premature `Tx_cancel`/`Tx_refund`/`Tx_punish`, or a
//! redeem racing a cancel fails here as it would on the real chain. Wallet coins are
//! P2PKH outputs minted by [`MockDiviChain::fund`] (a transaction with no inputs).
//!
//! [`MockMoneroChain`] keeps outputs by public spend key: a sweep must present the scalar
//! `s` with `s·G = S`, so only a party that really holds both shares can spend the 2-of-2.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek_ng::edwards::CompressedEdwardsY;
use divi_crypto::hash::hash160;
use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::SigHashType;
use divi_wallet::signer::{create_p2pkh_script_sig, sign_input};
use parking_lot::Mutex;
use swap_adaptor::dleq::ScalarQ;

use crate::chain::{DiviChain, MoneroChain, XmrOutput};
use divi_swap::{Result, SwapError};

/// Fee the mock DIVI wallet pays for a funding transaction, sats.
pub const MOCK_DIVI_FEE: u64 = 1_000;
/// Fee the mock Monero wallet pays per transaction, piconero.
pub const MOCK_XMR_FEE: u64 = 10_000_000;

fn transient() -> SwapError {
    SwapError::Transient("mock chain offline".into())
}

#[derive(Default)]
struct DiviState {
    height: u64,
    mtp: u32,
    /// txid → (tx, height when mined)
    txs: HashMap<Hash256, (Transaction, Option<u64>)>,
    /// outpoint → spending txid
    spends: HashMap<OutPoint, Hash256>,
    offline: bool,
    minted: u64,
}

/// A simulated DIVI chain shared by several wallets.
#[derive(Clone)]
pub struct MockDiviChain {
    block_secs: u32,
    st: Arc<Mutex<DiviState>>,
}

impl MockDiviChain {
    /// New chain at height 0 whose MTP starts at `mtp` and advances `block_secs` per block.
    pub fn new(mtp: u32, block_secs: u32) -> Self {
        MockDiviChain {
            block_secs,
            st: Arc::new(Mutex::new(DiviState {
                mtp,
                ..DiviState::default()
            })),
        }
    }

    /// Mine `n` blocks: confirms the mempool, advances height and MTP.
    pub fn mine(&self, n: u64) {
        let mut s = self.st.lock();
        for _ in 0..n {
            s.height += 1;
            s.mtp += self.block_secs;
            let h = s.height;
            for (_, mined) in s.txs.values_mut() {
                mined.get_or_insert(h);
            }
        }
    }

    /// Move MTP forward without mining.
    pub fn advance_time(&self, secs: u32) {
        self.st.lock().mtp += secs;
    }

    /// Current MTP.
    pub fn mtp(&self) -> u32 {
        self.st.lock().mtp
    }

    /// While offline every call fails with `SwapError::Transient`.
    pub fn set_offline(&self, offline: bool) {
        self.st.lock().offline = offline;
    }

    /// Mint a confirmed coin of `amount` sats paying `script_pubkey`.
    pub fn fund(&self, script_pubkey: &Script, amount: u64) -> OutPoint {
        let mut s = self.st.lock();
        s.minted += 1;
        // A unique, input-less transaction: the lock_time makes each mint's txid distinct.
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![TxOut::new(
                Amount::from_sat(amount as i64),
                script_pubkey.clone(),
            )],
            lock_time: s.minted as u32,
        };
        let txid = tx.txid();
        let h = s.height;
        s.txs.insert(txid, (tx, Some(h)));
        OutPoint::new(txid, 0)
    }

    /// A wallet with a deterministic key derived from `seed`.
    pub fn wallet(&self, seed: u8) -> MockDiviWallet {
        let mut b = [seed; 32];
        b[0] = 0x01;
        MockDiviWallet {
            chain: self.clone(),
            key: SecretKey::from_bytes(&b).expect("valid test key"),
        }
    }

    /// Sum of unspent outputs paying `script_pubkey` (mempool included).
    pub fn balance(&self, script_pubkey: &Script) -> u64 {
        let s = self.st.lock();
        s.txs
            .iter()
            .flat_map(|(txid, (tx, _))| {
                tx.vout
                    .iter()
                    .enumerate()
                    .map(move |(i, o)| (OutPoint::new(*txid, i as u32), o))
            })
            .filter(|(op, o)| &o.script_pubkey == script_pubkey && !s.spends.contains_key(op))
            .map(|(_, o)| o.value.as_sat() as u64)
            .sum()
    }

    /// The transaction with `txid`, if known.
    pub fn tx(&self, txid: &Hash256) -> Option<Transaction> {
        self.st.lock().txs.get(txid).map(|(t, _)| t.clone())
    }

    fn unspent_paying(&self, script_pubkey: &Script) -> Vec<(OutPoint, TxOut)> {
        let s = self.st.lock();
        let mut v: Vec<_> = s
            .txs
            .iter()
            .flat_map(|(txid, (tx, _))| {
                tx.vout
                    .iter()
                    .enumerate()
                    .map(move |(i, o)| (OutPoint::new(*txid, i as u32), o.clone()))
            })
            .filter(|(op, o)| &o.script_pubkey == script_pubkey && !s.spends.contains_key(op))
            .collect();
        v.sort_by_key(|(op, _)| (op.txid.to_hex(), op.vout));
        v
    }

    fn broadcast_tx(&self, tx: &Transaction) -> Result<()> {
        let mut s = self.st.lock();
        if s.offline {
            return Err(transient());
        }
        let txid = tx.txid();
        if s.txs.contains_key(&txid) {
            return Ok(());
        }
        if !tx.is_final(s.height as u32 + 1, s.mtp) {
            return Err(SwapError::Premature(format!(
                "nLockTime {} not reached (mtp {})",
                tx.lock_time, s.mtp
            )));
        }
        let mut value_in = 0i64;
        for (i, input) in tx.vin.iter().enumerate() {
            let prev = s
                .txs
                .get(&input.prevout.txid)
                .and_then(|(t, _)| t.vout.get(input.prevout.vout as usize))
                .ok_or_else(|| SwapError::Rejected(format!("input {i}: unknown output")))?
                .clone();
            if let Some(other) = s.spends.get(&input.prevout) {
                return Err(SwapError::Rejected(format!(
                    "input {i}: already spent by {}",
                    other.to_hex()
                )));
            }
            divi_script::verify_input(tx, i, &prev.script_pubkey, prev.value)
                .map_err(|e| SwapError::Rejected(format!("input {i}: script: {e}")))?;
            value_in += prev.value.as_sat();
        }
        let value_out: i64 = tx.vout.iter().map(|o| o.value.as_sat()).sum();
        if value_out > value_in {
            return Err(SwapError::Rejected("outputs exceed inputs".into()));
        }
        for input in &tx.vin {
            s.spends.insert(input.prevout, txid);
        }
        s.txs.insert(txid, (tx.clone(), None));
        Ok(())
    }
}

/// A wallet on a [`MockDiviChain`]: one P2PKH key.
#[derive(Clone)]
pub struct MockDiviWallet {
    chain: MockDiviChain,
    key: SecretKey,
}

impl MockDiviWallet {
    /// The wallet's P2PKH scriptPubKey.
    pub fn script(&self) -> Script {
        let pk = self.key.public_key().serialize_compressed();
        Script::new_p2pkh(hash160(&pk).as_bytes())
    }

    /// Mint `amount` sats to this wallet.
    pub fn fund(&self, amount: u64) {
        self.chain.fund(&self.script(), amount);
    }

    /// Spendable balance.
    pub fn balance(&self) -> u64 {
        self.chain.balance(&self.script())
    }

    /// The chain.
    pub fn chain(&self) -> &MockDiviChain {
        &self.chain
    }
}

#[async_trait]
impl DiviChain for MockDiviWallet {
    fn payout_script(&self) -> Script {
        self.script()
    }

    async fn tip_height(&self) -> Result<u64> {
        let s = self.chain.st.lock();
        if s.offline {
            return Err(transient());
        }
        Ok(s.height)
    }

    async fn median_time_past(&self) -> Result<u32> {
        let s = self.chain.st.lock();
        if s.offline {
            return Err(transient());
        }
        Ok(s.mtp)
    }

    async fn build_funding(&self, script_pubkey: &Script, amount: u64) -> Result<Transaction> {
        let mine = self.script();
        let mut picked = Vec::new();
        let mut total = 0u64;
        for (op, out) in self.chain.unspent_paying(&mine) {
            if total >= amount + MOCK_DIVI_FEE {
                break;
            }
            total += out.value.as_sat() as u64;
            picked.push((op, out));
        }
        if total < amount + MOCK_DIVI_FEE {
            return Err(SwapError::InsufficientFunds(format!(
                "have {total} sats, need {}",
                amount + MOCK_DIVI_FEE
            )));
        }
        let mut vout = vec![TxOut::new(
            Amount::from_sat(amount as i64),
            script_pubkey.clone(),
        )];
        let change = total - amount - MOCK_DIVI_FEE;
        if change > 0 {
            vout.push(TxOut::new(Amount::from_sat(change as i64), mine.clone()));
        }
        let mut tx = Transaction {
            version: 1,
            vin: picked
                .iter()
                .map(|(op, _)| TxIn::new(*op, Script::new(), 0xffff_ffff))
                .collect(),
            vout,
            lock_time: 0,
        };
        let pubkey = self.key.public_key();
        let mut sigs = Vec::new();
        for (i, (_, out)) in picked.iter().enumerate() {
            let sig = sign_input(&tx, i, &out.script_pubkey, &self.key, SigHashType::All)
                .map_err(|e| SwapError::Other(format!("sign: {e}")))?;
            sigs.push(sig);
        }
        for (i, sig) in sigs.iter().enumerate() {
            tx.vin[i].script_sig = create_p2pkh_script_sig(sig, &pubkey);
        }
        Ok(tx)
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<()> {
        self.chain.broadcast_tx(tx)
    }

    async fn confirmations(&self, txid: &Hash256) -> Result<Option<u32>> {
        let s = self.chain.st.lock();
        if s.offline {
            return Err(transient());
        }
        Ok(s.txs.get(txid).map(|(_, h)| match h {
            Some(h) => (s.height - h + 1) as u32,
            None => 0,
        }))
    }

    async fn output(&self, at: &OutPoint) -> Result<Option<(TxOut, u32)>> {
        let s = self.chain.st.lock();
        if s.offline {
            return Err(transient());
        }
        Ok(s.txs.get(&at.txid).and_then(|(tx, h)| {
            let confs = h.map_or(0, |h| (s.height - h + 1) as u32);
            tx.vout.get(at.vout as usize).map(|o| (o.clone(), confs))
        }))
    }

    async fn find_spend(&self, at: &OutPoint) -> Result<Option<Transaction>> {
        let s = self.chain.st.lock();
        if s.offline {
            return Err(transient());
        }
        Ok(s.spends
            .get(at)
            .and_then(|txid| s.txs.get(txid))
            .map(|(t, _)| t.clone()))
    }
}

struct XmrOut {
    txid: String,
    spend_pub: [u8; 32],
    view: [u8; 32],
    amount: u64,
    /// (sweep txid, wallet that swept)
    swept: Option<(String, String)>,
}

#[derive(Default)]
struct XmrState {
    height: u64,
    outputs: Vec<XmrOut>,
    /// txid → height when mined
    txs: HashMap<String, Option<u64>>,
    wallets: HashMap<String, u64>,
    nonce: u64,
    offline: bool,
}

/// A simulated Monero chain shared by several wallets.
#[derive(Clone, Default)]
pub struct MockMoneroChain {
    st: Arc<Mutex<XmrState>>,
}

impl MockMoneroChain {
    /// Empty chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// A wallet called `name` holding `balance` piconero.
    pub fn wallet(&self, name: &str, balance: u64) -> MockMoneroWallet {
        self.st.lock().wallets.insert(name.into(), balance);
        MockMoneroWallet {
            chain: self.clone(),
            name: name.into(),
        }
    }

    /// Mine `n` blocks.
    pub fn mine(&self, n: u64) {
        let mut s = self.st.lock();
        for _ in 0..n {
            s.height += 1;
            let h = s.height;
            for mined in s.txs.values_mut() {
                mined.get_or_insert(h);
            }
        }
    }

    /// While offline every call fails with `SwapError::Transient`.
    pub fn set_offline(&self, offline: bool) {
        self.st.lock().offline = offline;
    }

    /// Balance of wallet `name`.
    pub fn balance(&self, name: &str) -> u64 {
        *self.st.lock().wallets.get(name).unwrap_or(&0)
    }

    /// Number of 2-of-2 outputs ever locked to `spend_pub`.
    pub fn locks_to(&self, spend_pub: &[u8; 32]) -> usize {
        self.st
            .lock()
            .outputs
            .iter()
            .filter(|o| &o.spend_pub == spend_pub)
            .count()
    }
}

/// A wallet on a [`MockMoneroChain`].
#[derive(Clone)]
pub struct MockMoneroWallet {
    chain: MockMoneroChain,
    name: String,
}

impl MockMoneroWallet {
    /// This wallet's balance.
    pub fn balance(&self) -> u64 {
        self.chain.balance(&self.name)
    }
}

fn confs(s: &XmrState, txid: &str) -> Option<u32> {
    s.txs
        .get(txid)
        .map(|h| h.map_or(0, |h| (s.height - h + 1) as u32))
}

#[async_trait]
impl MoneroChain for MockMoneroWallet {
    async fn lock(
        &self,
        spend_pub: &[u8; 32],
        view_secret: &[u8; 32],
        amount: u64,
    ) -> Result<String> {
        let mut s = self.chain.st.lock();
        if s.offline {
            return Err(transient());
        }
        let bal = *s.wallets.get(&self.name).unwrap_or(&0);
        if bal < amount + MOCK_XMR_FEE {
            return Err(SwapError::InsufficientFunds(format!(
                "{} holds {bal} piconero, needs {}",
                self.name,
                amount + MOCK_XMR_FEE
            )));
        }
        s.wallets
            .insert(self.name.clone(), bal - amount - MOCK_XMR_FEE);
        s.nonce += 1;
        let txid = format!("xmr-lock-{:04}", s.nonce);
        s.outputs.push(XmrOut {
            txid: txid.clone(),
            spend_pub: *spend_pub,
            view: *view_secret,
            amount,
            swept: None,
        });
        s.txs.insert(txid.clone(), None);
        Ok(txid)
    }

    async fn find_lock(
        &self,
        spend_pub: &[u8; 32],
        view_secret: &[u8; 32],
    ) -> Result<Option<XmrOutput>> {
        let s = self.chain.st.lock();
        if s.offline {
            return Err(transient());
        }
        Ok(s.outputs
            .iter()
            .find(|o| &o.spend_pub == spend_pub && &o.view == view_secret)
            .map(|o| XmrOutput {
                txid: o.txid.clone(),
                amount: o.amount,
                confirmations: confs(&s, &o.txid).unwrap_or(0),
            }))
    }

    async fn sweep(
        &self,
        lock: &XmrOutput,
        spend_secret: &[u8; 32],
        view_secret: &[u8; 32],
    ) -> Result<String> {
        let mut s = self.chain.st.lock();
        if s.offline {
            return Err(transient());
        }
        let confirmed = confs(&s, &lock.txid).unwrap_or(0) >= 1;
        let idx = s
            .outputs
            .iter()
            .position(|o| o.txid == lock.txid && &o.view == view_secret)
            .ok_or_else(|| SwapError::Rejected("unknown 2-of-2 output".into()))?;
        if let Some((txid, by)) = &s.outputs[idx].swept {
            return if by == &self.name {
                Ok(txid.clone())
            } else {
                Err(SwapError::Rejected("output already spent".into()))
            };
        }
        let secret = ScalarQ::from_canonical_bytes(*spend_secret)
            .ok_or_else(|| SwapError::Rejected("not a scalar".into()))?;
        let expected = CompressedEdwardsY(s.outputs[idx].spend_pub).decompress();
        if expected != Some(&secret * &ED25519_BASEPOINT_TABLE) {
            return Err(SwapError::Rejected(
                "spend secret does not open the 2-of-2 key".into(),
            ));
        }
        if !confirmed {
            return Err(SwapError::Premature("lock not confirmed yet".into()));
        }
        let amount = s.outputs[idx].amount;
        s.nonce += 1;
        let txid = format!("xmr-sweep-{:04}", s.nonce);
        s.outputs[idx].swept = Some((txid.clone(), self.name.clone()));
        *s.wallets.entry(self.name.clone()).or_default() += amount - MOCK_XMR_FEE;
        s.txs.insert(txid.clone(), None);
        Ok(txid)
    }

    async fn confirmations(&self, txid: &str) -> Result<Option<u32>> {
        let s = self.chain.st.lock();
        if s.offline {
            return Err(transient());
        }
        Ok(confs(&s, txid))
    }
}
