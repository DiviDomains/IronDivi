// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! DIVI `ChainBackend` over the services.divi.domains JSON-RPC proxy.
//!
//! Lane **divi** (docs/plans/swap-poc/lanes/divi.md) owns this crate. The Wave 0 live
//! proof (`examples/*_cltv_proof.rs`) shows the transaction shapes that the chain accepts.

mod rpc;
mod second_source;
mod wallet;

pub use rpc::{classify_broadcast_error, BroadcastClass, RetryPolicy, RpcClient, RpcError};
pub use second_source::{CONFIRMATION_TOLERANCE, MTP_TOLERANCE_SECS, TIP_TOLERANCE_BLOCKS};
pub use wallet::{Utxo, Wallet};

use std::time::Duration;

use async_trait::async_trait;
use divi_crypto::keys::SecretKey;
use divi_crypto::signature::sign_hash;
use divi_primitives::amount::Amount as DiviAmount;
use divi_primitives::constants::SEQUENCE_FINAL;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::{verify_input, SigHashType};
use divi_swap::htlc::{
    claim_script_sig, push_data, refund_script_sig, HtlcParams, REFUND_SEQUENCE,
};
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, InputReservations, LockedOutput, Outpoint, Result,
    SignedTx, SpendInfo, SwapError, Txid,
};
use divi_wallet::address::{Address, Network};
use divi_wallet::signer::sighash;
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Public RPC proxy for Divi testnet.
pub const TESTNET_RPC: &str = "https://services.divi.domains/api/testnet/rpc/";

/// Public RPC proxy for Divi mainnet. Note the path has no `/mainnet/` segment
/// (`/api/mainnet/rpc/` is a 404); `getblockchaininfo` answers `chain = "main"`.
pub const MAINNET_RPC: &str = "https://services.divi.domains/api/rpc/";

/// The default public RPC proxy for `network` (regtest has none; it uses the testnet one).
pub fn default_rpc(network: Network) -> &'static str {
    match network {
        Network::Mainnet => MAINNET_RPC,
        Network::Testnet | Network::Regtest => TESTNET_RPC,
    }
}

/// Outputs below this are not worth creating; the remainder goes to fees instead.
const DUST: u64 = 10_000;
/// Size of a DER signature + sighash byte used while estimating fees.
const SIG_LEN_EST: usize = 72;

/// DIVI Core's default relay minimum, satoshis per 1000 bytes (ab3bf31
/// `divi/src/defaultValues.h:38` `DEFAULT_TX_RELAY_FEE_PER_KILOBYTE`). A mempool admits a
/// transaction paying less only on coin-age priority (`MempoolConsensus.cpp:236-266`
/// `CheckFeesPaidAreAcceptable`).
pub const RELAY_FEE_PER_KB: u64 = 10_000;
/// A maker-leg claim pays at least this many times [`RELAY_FEE_PER_KB`] for its size,
/// whatever the [`FeePolicy`]. DIVI cannot bump a claim (replacement is disabled and block
/// assembly ignores packages, ab3bf31 `MempoolConsensus.cpp:303-313`,
/// `BlockMemoryPoolTransactionCollector.cpp:66-83,110-119`), so the first claim must clear
/// a node whose operator raised `-minimumRelayTransactionFee` and still sort ahead of
/// transactions paying the minimum. 10 leaves an order of magnitude for both; the default
/// policy pays about 100.
pub const CLAIM_FEE_FACTOR: u64 = 10;

/// Fee policy: `max(min_fee, rate * size / 1000)`, in satoshis.
#[derive(Debug, Clone, Copy)]
pub struct FeePolicy {
    /// Satoshis per 1000 bytes.
    pub sat_per_kb: u64,
    /// Floor per transaction.
    pub min_fee: u64,
}

impl Default for FeePolicy {
    fn default() -> Self {
        FeePolicy {
            sat_per_kb: 1_000_000, // 0.01 DIVI / kB
            min_fee: 100_000,
        }
    }
}

impl FeePolicy {
    fn fee(&self, size: usize) -> u64 {
        (self.sat_per_kb * size as u64)
            .div_ceil(1000)
            .max(self.min_fee)
    }
}

/// `ChainBackend` for DIVI over the JSON-RPC proxy, holding one engine key.
pub struct DiviBackend {
    rpc: RpcClient,
    /// Optional second endpoint (`[divi].fallback_rpc_url`). When set, every swap-relevant
    /// read is made on both and a disagreement is `Transient`; see [`second_source`].
    fallback: Option<RpcClient>,
    retry: RetryPolicy,
    key: SecretKey,
    pubkey: [u8; 33],
    spk: Script,
    network: Network,
    fee: FeePolicy,
    wallet: Mutex<Wallet>,
    reservations: Option<InputReservations>,
}

fn to_hash(txid: &Txid) -> Hash256 {
    Hash256::from_hex(&txid.to_rpc_hex()).expect("txid hex is 64 chars")
}

fn from_hash(h: &Hash256) -> Txid {
    Txid::from_rpc_hex(&h.to_hex()).expect("hash hex is 64 chars")
}

fn script_err(what: &str, e: impl std::fmt::Debug) -> SwapError {
    SwapError::Rejected(format!("{what} failed local script verification: {e:?}"))
}

/// P2SH scriptPubKey of an HTLC.
pub fn htlc_script_pubkey(htlc: &HtlcParams) -> Script {
    htlc_script_pubkey_v(htlc, htlc.script_version)
}

/// P2SH scriptPubKey of an HTLC redeem script of the given version.
pub fn htlc_script_pubkey_v(htlc: &HtlcParams, version: divi_swap::htlc::ScriptVersion) -> Script {
    Script::new_p2sh(divi_crypto::hash::hash160(&htlc.redeem_script_v(version)).as_bytes())
}

impl DiviBackend {
    /// New backend. `wallet_path` persists the known-coin set (public data only); `None`
    /// keeps it in memory.
    pub fn new(
        rpc_url: &str,
        key: SecretKey,
        network: Network,
        fee: FeePolicy,
        wallet_path: Option<PathBuf>,
    ) -> Result<Self> {
        Self::with_retry(
            rpc_url,
            key,
            network,
            fee,
            wallet_path,
            RetryPolicy::default(),
        )
    }

    /// As [`new`](Self::new) with an explicit retry policy.
    pub fn with_retry(
        rpc_url: &str,
        key: SecretKey,
        network: Network,
        fee: FeePolicy,
        wallet_path: Option<PathBuf>,
        retry: RetryPolicy,
    ) -> Result<Self> {
        let pk = key.public_key();
        Ok(DiviBackend {
            rpc: RpcClient::new(rpc_url, retry),
            fallback: None,
            retry,
            pubkey: pk.serialize_compressed(),
            spk: Script::new_p2pkh(pk.pubkey_hash().as_bytes()),
            key,
            network,
            fee,
            wallet: Mutex::new(Wallet::open(wallet_path)?),
            reservations: None,
        })
    }

    /// Share lock-input reservations with every other process on the same swap database.
    pub fn with_input_reservations(mut self, reservations: InputReservations) -> Self {
        self.reservations = Some(reservations);
        self
    }

    /// Add a second, independent endpoint. Every swap-relevant read (confirmations, HTLC
    /// output, find-spend, MTP, tip height and hash, and the wallet scan reads) is then made on both and any disagreement is
    /// `SwapError::Transient`; a broadcast goes to both. An empty `url` leaves the backend
    /// single-source.
    pub fn with_fallback_rpc(mut self, url: &str) -> Self {
        let url = url.trim();
        if !url.is_empty() {
            self.fallback = Some(RpcClient::new(url, self.retry));
        }
        self
    }

    /// Whether a second endpoint is configured.
    pub fn has_fallback(&self) -> bool {
        self.fallback.is_some()
    }

    /// The key's P2PKH address.
    pub fn address(&self) -> String {
        Address::p2pkh(&self.key.public_key(), self.network).to_string()
    }

    /// Coins currently spendable.
    pub fn balance(&self) -> u64 {
        self.wallet.lock().balance()
    }

    /// Never spend outputs of `txid`.
    pub fn exclude_txid(&self, txid: Txid) -> Result<()> {
        self.wallet.lock().exclude_txid(txid)
    }

    /// Learn the coins a known transaction (e.g. the faucet send) pays to this key.
    /// Returns how many new coins were added.
    pub async fn add_funding_tx(&self, txid: &Txid) -> Result<usize> {
        let tx = self.get_tx(&txid.to_rpc_hex()).await?;
        self.wallet.lock().apply_tx(&tx, &self.spk.to_hex())
    }

    /// Next block height a scan should start at, as persisted with the wallet.
    pub fn scanned_height(&self) -> Option<u64> {
        self.wallet.lock().scanned_height
    }

    /// Scan blocks `from_height..=tip` for coins paying this key and spends of known coins.
    /// Returns the next height to scan from. Not called implicitly.
    pub async fn scan_blocks(&self, from_height: u64) -> Result<u64> {
        let tip = self.tip_height().await?;
        self.scan_range(from_height, tip).await
    }

    /// Scan blocks `from_height..=to_height` and persist the cursor (`to_height + 1`) with the
    /// wallet, so a later run can resume there. Returns the next height to scan from.
    pub async fn scan_range(&self, from_height: u64, to_height: u64) -> Result<u64> {
        let spk = self.spk.to_hex();
        for h in from_height..=to_height {
            for txid in self.block_txids(h).await? {
                let tx = self.get_tx(&txid).await?;
                self.wallet.lock().apply_tx(&tx, &spk)?;
            }
        }
        let mut w = self.wallet.lock();
        w.scanned_height = Some(to_height + 1);
        w.record_broadcast(&[], &[])?;
        Ok(to_height + 1)
    }

    /// The transactions of block `height`. With a fallback both endpoints must list the same
    /// ones: a primary that hides a block's transactions would hide a coin or a spend from the
    /// wallet for good, because the scan cursor moves past the block.
    async fn block_txids(&self, height: u64) -> Result<Vec<String>> {
        let Some(fb) = &self.fallback else {
            return block_txids_on(&self.rpc, height).await;
        };
        let (a, b) = tokio::join!(
            block_txids_on(&self.rpc, height),
            block_txids_on(fb, height)
        );
        let (a, b) = second_source::pair("block_txids", a, b)?;
        second_source::agree_block_txids(a, b)
    }

    /// A transaction as the wallet will learn it. With a fallback both endpoints must give the
    /// same txid, spent outpoints and outputs; the wallet derives coins and spends from them,
    /// and coin selection (which UTXO is spent, for how much) follows from the coins.
    async fn get_tx(&self, txid: &str) -> Result<Value> {
        let Some(fb) = &self.fallback else {
            return get_tx_on(&self.rpc, txid).await;
        };
        let (a, b) = tokio::join!(get_tx_on(&self.rpc, txid), get_tx_on(fb, txid));
        let (a, b) = second_source::pair("wallet_tx", a, b)?;
        second_source::agree_wallet_tx(a, b)
    }

    /// Like `get_tx` but `None` for "No such mempool or blockchain transaction" (-5).
    #[cfg(test)]
    async fn get_tx_opt(&self, txid: &Txid) -> Result<Option<Value>> {
        get_tx_opt_on(&self.rpc, txid).await
    }

    fn sign_input(&self, tx: &Transaction, idx: usize, script_code: &Script) -> Result<Vec<u8>> {
        let h = sighash(tx, idx, script_code, SigHashType::All, false)
            .map_err(|e| SwapError::Other(format!("sighash: {e}")))?;
        let mut sig = sign_hash(&self.key, h.as_bytes())
            .map_err(|e| SwapError::Other(format!("sign: {e}")))?
            .to_der();
        sig.push(SigHashType::All as u8);
        Ok(sig)
    }

    fn signed(tx: &Transaction) -> SignedTx {
        SignedTx {
            txid: from_hash(&tx.txid()),
            raw: serialize(tx),
        }
    }

    /// Build the one-input, one-output spend of an HTLC. `claim_with` selects the branch.
    fn build_spend(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        claim_with: Option<&[u8; 32]>,
    ) -> Result<SignedTx> {
        htlc.validate()?;
        let redeem = htlc.redeem_script();
        let redeem_script = Script::from_bytes(redeem.clone());
        let spk = htlc_script_pubkey(htlc);
        let script_sig = |sig: &[u8]| match claim_with {
            Some(pre) => claim_script_sig(sig, pre, &redeem),
            None => refund_script_sig(sig, &redeem),
        };
        let mut tx = Transaction::new();
        tx.vin.push(TxIn::new(
            OutPoint::new(to_hash(&at.txid), at.vout),
            Script::new(),
            if claim_with.is_some() {
                SEQUENCE_FINAL
            } else {
                REFUND_SEQUENCE
            },
        ));
        if claim_with.is_none() {
            tx.lock_time = htlc.locktime;
        }
        tx.vout
            .push(TxOut::new(DiviAmount::from_sat(0), self.spk.clone()));
        // Fee from the real size with a placeholder signature.
        tx.vin[0].script_sig = Script::from_bytes(script_sig(&[0u8; SIG_LEN_EST]));
        let mut fee = self.fee.fee(tx.size());
        if claim_with.is_some() {
            fee = fee.max(CLAIM_FEE_FACTOR * (RELAY_FEE_PER_KB * tx.size() as u64).div_ceil(1000));
        }
        let value = amount
            .to_sat()
            .checked_sub(fee)
            .filter(|v| *v >= DUST)
            .ok_or_else(|| {
                SwapError::InsufficientFunds(format!(
                    "HTLC value {amount} does not cover fee {fee}"
                ))
            })?;
        tx.vout[0].value = DiviAmount::from_sat(value as i64);
        let sig = self.sign_input(&tx, 0, &redeem_script)?;
        tx.vin[0].script_sig = Script::from_bytes(script_sig(&sig));
        verify_input(&tx, 0, &spk, DiviAmount::from_sat(amount.to_sat() as i64)).map_err(|e| {
            script_err(
                if claim_with.is_some() {
                    "claim"
                } else {
                    "refund"
                },
                e,
            )
        })?;
        Ok(Self::signed(&tx))
    }
}

#[async_trait]
impl ChainBackend for DiviBackend {
    fn chain(&self) -> Chain {
        Chain::Divi
    }

    fn pubkey(&self) -> [u8; 33] {
        self.pubkey
    }

    async fn tip_height(&self) -> Result<u64> {
        let Some(fb) = &self.fallback else {
            return tip_height_on(&self.rpc).await;
        };
        let (a, b) = tokio::join!(tip_height_on(&self.rpc), tip_height_on(fb));
        let (a, b) = second_source::pair("tip_height", a, b)?;
        second_source::agree_tip_height(a, b)
    }

    async fn tip_hash(&self) -> Result<String> {
        let Some(fb) = &self.fallback else {
            return tip_hash_on(&self.rpc).await;
        };
        let (a, b) = tokio::join!(tip_hash_on(&self.rpc), tip_hash_on(fb));
        let (a, b) = second_source::pair("tip_hash", a, b)?;
        second_source::agree_tip_hash(a, b)
    }

    async fn median_time_past(&self) -> Result<u32> {
        let Some(fb) = &self.fallback else {
            return median_time_past_on(&self.rpc).await;
        };
        let (a, b) = tokio::join!(median_time_past_on(&self.rpc), median_time_past_on(fb));
        let (a, b) = second_source::pair("median_time_past", a, b)?;
        second_source::agree_mtp(a, b)
    }

    async fn spendable(&self) -> Result<Option<Amount>> {
        Ok(Some(Amount(self.balance())))
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        htlc.validate()?;
        let target = amount.to_sat();
        let htlc_spk = htlc_script_pubkey(htlc);
        let mut wallet = self.wallet.lock();
        let mut coins = wallet.available();
        coins.sort_by_key(|c| c.value);
        // Prefer the smallest single coin that covers the amount, else take largest first.
        let est_fee = |n: usize| self.fee.fee(10 + n * 148 + 2 * 34);
        let picked: Vec<Utxo> = match coins.iter().find(|c| c.value >= target + est_fee(1)) {
            Some(c) => vec![*c],
            None => {
                let mut acc = Vec::new();
                let mut sum = 0u64;
                for c in coins.iter().rev() {
                    acc.push(*c);
                    sum += c.value;
                    if sum >= target + est_fee(acc.len()) {
                        break;
                    }
                }
                if sum < target + est_fee(acc.len()) {
                    return Err(SwapError::InsufficientFunds(format!(
                        "need {} + fee, have {}",
                        amount,
                        Amount(sum)
                    )));
                }
                acc
            }
        };
        let input_total: u64 = picked.iter().map(|c| c.value).sum();
        let fee = est_fee(picked.len());
        let change = input_total - target - fee;

        let mut tx = Transaction::new();
        for c in &picked {
            tx.vin.push(TxIn::new(
                OutPoint::new(to_hash(&c.outpoint.txid), c.outpoint.vout),
                Script::new(),
                SEQUENCE_FINAL,
            ));
        }
        tx.vout
            .push(TxOut::new(DiviAmount::from_sat(target as i64), htlc_spk));
        let change_index = (change >= DUST).then(|| {
            tx.vout.push(TxOut::new(
                DiviAmount::from_sat(change as i64),
                self.spk.clone(),
            ));
            1u32
        });
        // All inputs are our P2PKH coins: script code is our scriptPubKey.
        let mut sigs = Vec::new();
        for i in 0..picked.len() {
            sigs.push(self.sign_input(&tx, i, &self.spk)?);
        }
        for (i, sig) in sigs.iter().enumerate() {
            let mut ss = Vec::new();
            push_data(&mut ss, sig);
            push_data(&mut ss, &self.pubkey);
            tx.vin[i].script_sig = Script::from_bytes(ss);
            verify_input(
                &tx,
                i,
                &self.spk,
                DiviAmount::from_sat(picked[i].value as i64),
            )
            .map_err(|e| script_err("funding input", e))?;
        }
        let signed = Self::signed(&tx);
        wallet.reserve(&picked, signed.txid)?;
        Ok(Funding {
            outpoint: Outpoint {
                txid: signed.txid,
                vout: 0,
            },
            amount,
            tx: signed,
        })
        .inspect(|_| {
            tracing::debug!(change_index = ?change_index, "built DIVI funding tx");
        })
    }

    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx> {
        if <[u8; 32]>::from(Sha256::digest(preimage)) != htlc.hash {
            return Err(SwapError::InvalidParams(
                "preimage does not hash to the HTLC hash".into(),
            ));
        }
        self.build_spend(htlc, at, amount, Some(preimage))
    }

    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        self.build_spend(htlc, at, amount, None)
    }

    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        let parsed: Transaction = divi_primitives::serialize::deserialize(&tx.raw)
            .map_err(|e| SwapError::InvalidParams(format!("undecodable transaction: {e}")))?;
        let raw_hex = hex::encode(&tx.raw);
        match &self.fallback {
            None => send_raw_on(&self.rpc, &raw_hex, &tx.txid).await?,
            Some(fb) => {
                // Broadcast goes to both endpoints: a transaction either one accepts is on
                // the network, so one endpoint dropping or hiding it cannot stall a claim
                // or a refund.
                let (p, f) = tokio::join!(
                    send_raw_on(&self.rpc, &raw_hex, &tx.txid),
                    send_raw_on(fb, &raw_hex, &tx.txid)
                );
                match (p, f) {
                    (Ok(()), Ok(())) => {}
                    (Ok(()), Err(e)) => {
                        tracing::warn!(txid = %tx.txid, "fallback endpoint did not take the broadcast: {e}");
                    }
                    (Err(e), Ok(())) => {
                        tracing::warn!(txid = %tx.txid, "primary endpoint did not take the broadcast: {e}");
                    }
                    (Err(e), Err(_)) => return Err(e),
                }
            }
        }
        let own: Vec<Utxo> = parsed
            .vout
            .iter()
            .enumerate()
            .filter(|(_, o)| o.script_pubkey == self.spk)
            .map(|(n, o)| Utxo {
                outpoint: Outpoint {
                    txid: tx.txid,
                    vout: n as u32,
                },
                value: o.value.as_sat() as u64,
            })
            .collect();
        let inputs: Vec<Outpoint> = parsed
            .vin
            .iter()
            .map(|i| Outpoint {
                txid: from_hash(&i.prevout.txid),
                vout: i.prevout.vout,
            })
            .collect();
        self.wallet.lock().record_broadcast(&inputs, &own)?;
        Ok(tx.txid)
    }

    async fn release_dead_lock(&self, lock: &SignedTx) -> Result<bool> {
        let parsed: Transaction = divi_primitives::serialize::deserialize(&lock.raw)
            .map_err(|e| SwapError::InvalidParams(format!("undecodable transaction: {e}")))?;
        // Proof the lock is not in the chain: every input is still an unspent output paying
        // our key. `gettxout` needs no index; a node that refuses it is an error here, so
        // there is no release without the proof.
        let mut coins = Vec::new();
        for i in &parsed.vin {
            let op = Outpoint {
                txid: from_hash(&i.prevout.txid),
                vout: i.prevout.vout,
            };
            let mut views = vec![txout_on(&self.rpc, &op, &self.spk).await?];
            if let Some(fb) = &self.fallback {
                views.push(txout_on(fb, &op, &self.spk).await?);
            }
            match views.as_slice() {
                [Some(value)] => coins.push(Utxo {
                    outpoint: op,
                    value: *value,
                }),
                [Some(a), Some(b)] if a == b => coins.push(Utxo {
                    outpoint: op,
                    value: *a,
                }),
                // Spent (by the lock or a rival), unknown, not ours, or the endpoints disagree.
                _ => return Ok(false),
            }
        }
        self.wallet.lock().release_dead_tx(lock.txid, &coins)
    }

    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        let Some(fb) = &self.fallback else {
            return confirmations_on(&self.rpc, txid).await;
        };
        let (a, b) = tokio::join!(
            confirmations_on(&self.rpc, txid),
            confirmations_on(fb, txid)
        );
        let (a, b) = second_source::pair("confirmations", a, b)?;
        second_source::agree_confirmations(a, b)
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        let Some(fb) = &self.fallback else {
            return htlc_output_on(&self.rpc, htlc, at).await;
        };
        let (a, b) = tokio::join!(
            htlc_output_on(&self.rpc, htlc, at),
            htlc_output_on(fb, htlc, at)
        );
        let (a, b) = second_source::pair("htlc_output", a, b)?;
        second_source::agree_htlc_output(a, b)
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        let Some(fb) = &self.fallback else {
            return find_spend_on(&self.rpc, outpoint, from_height).await;
        };
        let (a, b) = tokio::join!(
            find_spend_on(&self.rpc, outpoint, from_height),
            find_spend_on(fb, outpoint, from_height)
        );
        let (a, b) = second_source::pair("find_spend", a, b)?;
        second_source::agree_spend(a, b)
    }
}

async fn block_txids_on(rpc: &RpcClient, height: u64) -> Result<Vec<String>> {
    let hash = rpc.call_ok("getblockhash", json!([height])).await?;
    let block = rpc.call_ok("getblock", json!([hash, true])).await?;
    Ok(block["tx"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default())
}

async fn get_tx_on(rpc: &RpcClient, txid: &str) -> Result<Value> {
    rpc.call_ok("getrawtransaction", json!([txid, 1])).await
}

async fn get_tx_opt_on(rpc: &RpcClient, txid: &Txid) -> Result<Option<Value>> {
    match rpc
        .call("getrawtransaction", json!([txid.to_rpc_hex(), 1]))
        .await
    {
        Ok(v) => Ok(Some(v)),
        Err(RpcError::Node { code: -5, .. }) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Value in satoshis of `op` if it is unspent (`gettxout`, mempool included) and pays
/// `spk`; `None` if it is spent, unknown or pays something else.
async fn txout_on(rpc: &RpcClient, op: &Outpoint, spk: &Script) -> Result<Option<u64>> {
    let v = rpc
        .call_ok("gettxout", json!([op.txid.to_rpc_hex(), op.vout, true]))
        .await?;
    if v.is_null()
        || v["scriptPubKey"]["hex"].as_str() != Some(hex::encode(spk.as_bytes()).as_str())
    {
        return Ok(None);
    }
    let sat = v["valueSat"]
        .as_u64()
        .or_else(|| v["value"].as_f64().map(|x| (x * 1e8).round() as u64))
        .ok_or_else(|| SwapError::Transient("gettxout: output without value".into()))?;
    Ok(Some(sat))
}

async fn tip_hash_on(rpc: &RpcClient) -> Result<String> {
    let v = rpc.call_ok("getbestblockhash", json!([])).await?;
    let s = v
        .as_str()
        .ok_or_else(|| SwapError::Transient("getbestblockhash: not a string".into()))?;
    divi_swap::backend::normalize_block_hash(s)
}

async fn tip_height_on(rpc: &RpcClient) -> Result<u64> {
    rpc.call_ok("getblockcount", json!([]))
        .await?
        .as_u64()
        .ok_or_else(|| {
            // A proxy returning a null/non-numeric block count is a glitch, not a real
            // "the chain has no height" condition.
            SwapError::Transient("getblockcount: not a number".into())
        })
}

async fn median_time_past_on(rpc: &RpcClient) -> Result<u32> {
    // The node reports `mediantime: null`, so take the median of the last 11 block times.
    let tip = tip_height_on(rpc).await?;
    let mut hash = rpc.call_ok("getblockhash", json!([tip])).await?;
    let mut times = Vec::with_capacity(11);
    for _ in 0..11 {
        let block = rpc.call_ok("getblock", json!([hash, true])).await?;
        times.push(block["time"].as_u64().ok_or_else(|| {
            // A real block always has a time; its absence means a proxy-fronted
            // node behind the one that reported this hash hasn't indexed it yet.
            SwapError::Transient("block without time (still indexing?)".into())
        })?);
        match block.get("previousblockhash").filter(|p| p.is_string()) {
            Some(prev) => hash = prev.clone(),
            None => break,
        }
    }
    times.sort_unstable();
    Ok(times[times.len() / 2] as u32)
}

async fn confirmations_on(rpc: &RpcClient, txid: &Txid) -> Result<Option<u32>> {
    Ok(get_tx_opt_on(rpc, txid)
        .await?
        .map(|v| v["confirmations"].as_u64().unwrap_or(0) as u32))
}

async fn htlc_output_on(
    rpc: &RpcClient,
    htlc: &HtlcParams,
    at: &Outpoint,
) -> Result<Option<LockedOutput>> {
    let Some(tx) = get_tx_opt_on(rpc, &at.txid).await? else {
        return Ok(None);
    };
    let Some(out) = tx["vout"]
        .as_array()
        .and_then(|a| a.iter().find(|o| o["n"].as_u64() == Some(at.vout as u64)))
    else {
        return Ok(None);
    };
    if out["scriptPubKey"]["hex"].as_str() != Some(htlc_script_pubkey(htlc).to_hex().as_str()) {
        return Ok(None);
    }
    let sat = out["valueSat"]
        .as_u64()
        .or_else(|| out["value"].as_f64().map(|v| (v * 1e8).round() as u64))
        .ok_or_else(|| SwapError::Other("output without value".into()))?;
    Ok(Some(LockedOutput {
        amount: Amount(sat),
        confirmations: tx["confirmations"].as_u64().unwrap_or(0) as u32,
    }))
}

async fn find_spend_on(
    rpc: &RpcClient,
    outpoint: &Outpoint,
    from_height: u64,
) -> Result<Option<SpendInfo>> {
    let want_txid = outpoint.txid.to_rpc_hex();
    let tip = tip_height_on(rpc).await?;
    for h in from_height..=tip {
        for txid in block_txids_on(rpc, h).await? {
            let tx = get_tx_on(rpc, &txid).await?;
            if let Some(s) = spend_in(&tx, &want_txid, outpoint.vout, Some(h))? {
                return Ok(Some(s));
            }
        }
    }
    let pool = rpc.call_ok("getrawmempool", json!([])).await?;
    for txid in pool
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let tx = match get_tx_opt_on(rpc, &txid.parse()?).await? {
            Some(tx) => tx,
            None => continue, // left the mempool meanwhile; a block scan will see it
        };
        if let Some(s) = spend_in(&tx, &want_txid, outpoint.vout, None)? {
            return Ok(Some(s));
        }
    }
    Ok(None)
}

/// One endpoint's `sendrawtransaction`, with the "already known" / premature / recheck
/// classification the single-source backend always had.
async fn send_raw_on(rpc: &RpcClient, raw_hex: &str, txid: &Txid) -> Result<()> {
    match rpc.call("sendrawtransaction", json!([raw_hex])).await {
        Ok(_) => Ok(()),
        Err(RpcError::Node { message, .. }) => match classify_broadcast_error(&message) {
            BroadcastClass::AlreadyKnown => Ok(()),
            BroadcastClass::Premature => Err(SwapError::Premature(message)),
            BroadcastClass::Rejected => {
                // A rejection of a tx the chain already has (e.g. its inputs are now
                // spent by itself) is still success. A single `None` here is not
                // proof of absence, though: a proxy fronting more than one node can
                // reject against one backend while another already has the tx (the
                // same lagging-backend race as the esplora "Block not found" bug) —
                // so double-check a couple of times, with a short delay, before
                // concluding the rejection is real.
                let mut known = get_tx_opt_on(rpc, txid).await?.is_some();
                for _ in 0..2 {
                    if known {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    known = get_tx_opt_on(rpc, txid).await?.is_some();
                }
                if known {
                    Ok(())
                } else {
                    Err(SwapError::Rejected(message))
                }
            }
        },
        Err(e) => Err(e.into()),
    }
}

/// If `tx` (verbose JSON) has an input spending `txid:vout`, describe it.
fn spend_in(tx: &Value, txid: &str, vout: u32, height: Option<u64>) -> Result<Option<SpendInfo>> {
    for (i, input) in tx["vin"].as_array().into_iter().flatten().enumerate() {
        if input["txid"].as_str() == Some(txid) && input["vout"].as_u64() == Some(vout as u64) {
            let script_sig = hex::decode(input["scriptSig"]["hex"].as_str().unwrap_or(""))
                .map_err(|e| SwapError::Other(format!("scriptSig hex: {e}")))?;
            return Ok(Some(SpendInfo {
                txid: tx["txid"]
                    .as_str()
                    .ok_or_else(|| SwapError::Other("tx without txid".into()))?
                    .parse()?,
                input_index: i as u32,
                height,
                script_sig,
                witness: vec![],
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
