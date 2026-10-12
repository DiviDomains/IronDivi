// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live DIVI-side primitives for the other half of the multichain lane's `- needs:`
//! (`docs/plans/swap-poc/status/multichain.md`: "a live `DiviChain`: `build_funding`
//! to an arbitrary scriptPubKey + raw-tx broadcast + `find_spend`"). Their
//! `divi-swap-xmr::chain::DiviChain` trait (read directly, not guessed):
//!
//! ```text
//! trait DiviChain {
//!     fn payout_script(&self) -> Script;
//!     async fn tip_height(&self) -> Result<u64>;
//!     async fn median_time_past(&self) -> Result<u32>;
//!     async fn build_funding(&self, script_pubkey: &Script, amount: u64) -> Result<Transaction>;
//!     async fn broadcast(&self, tx: &Transaction) -> Result<()>;
//!     async fn confirmations(&self, txid: &Hash256) -> Result<Option<u32>>;
//!     async fn output(&self, at: &OutPoint) -> Result<Option<(TxOut, u32)>>;
//!     async fn find_spend(&self, at: &OutPoint) -> Result<Option<Transaction>>;
//! }
//! ```
//!
//! [`LiveDiviChain`] below provides every one of these as an inherent method with the
//! identical signature (same `divi_primitives` types, same `divi_swap::Result`) --
//! not a trait impl (no dependency on `divi-swap-xmr`, which this lane doesn't own),
//! but a drop-in body for whoever writes one. **Reuses, rather than reimplements, the
//! existing DIVI HTLC client's machinery**: `swap-chain-divi`'s `Wallet`/`Utxo` (the
//! coin-tracking set backing its own `ChainBackend::build_funding`), `FeePolicy`,
//! `RpcClient`, and `classify_broadcast_error` are all already public exports of that
//! crate (lane **divi**'s, already a dependency here) -- this module is the same
//! coin-selection/fee/broadcast-idempotency logic `DiviBackend` already has, just
//! generalized from "pay an HTLC script" to "pay an arbitrary script" (the one thing
//! `ChainBackend::build_funding` can't do, per the `- needs:`), without editing that
//! crate at all.
//!
//! One signature difference from their trait, flagged rather than silently diverged:
//! [`LiveDiviChain::find_spend`] takes an extra `from_height: u64` the trait method
//! doesn't. A blind, unbounded scan from genesis isn't practical (same reasoning as
//! [`crate::monero_chain::find_lock`]'s height window) -- and isn't actually new here
//! either: `divi_swap::ChainBackend::find_spend` (the existing hashlock engine's own
//! trait, `DiviBackend`'s real implementation below) already takes this same
//! parameter. Whoever wires the live `DiviChain` impl should pass the height the
//! relevant lock was negotiated/broadcast at, same as the hashlock engine's callers do.

use std::path::PathBuf;
use std::sync::Mutex;

use divi_crypto::keys::SecretKey;
use divi_crypto::signature::sign_hash;
use divi_primitives::amount::Amount as DiviAmount;
use divi_primitives::constants::SEQUENCE_FINAL;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::{verify_input, SigHashType};
use divi_swap::htlc::push_data;
use divi_swap::{Outpoint, Result, SwapError, Txid};
use divi_wallet::signer::sighash;
use serde_json::{json, Value};
use swap_chain_divi::{
    classify_broadcast_error, BroadcastClass, FeePolicy, RetryPolicy, RpcClient, RpcError, Utxo,
    Wallet,
};

/// Outputs below this are not worth creating; the remainder goes to fees instead.
/// Same value `swap-chain-divi`'s own `DiviBackend` uses.
const DUST: u64 = 10_000;

fn to_txid(h: Hash256) -> Txid {
    // Both types store the same internal (hashed, non-display-reversed) byte order --
    // `Hash256::to_hex`/`Txid::to_rpc_hex` each reverse independently for display, so
    // this is a plain field copy, not a hex round trip.
    Txid(*h.as_bytes())
}

fn from_txid(t: Txid) -> Hash256 {
    Hash256::from_bytes(t.0)
}

fn to_outpoint(o: &OutPoint) -> Outpoint {
    Outpoint {
        txid: to_txid(o.txid),
        vout: o.vout,
    }
}

/// A live `DiviChain`, holding one engine key -- same shape as `swap-chain-divi`'s
/// `DiviBackend`, minus the HTLC-specific pieces this doesn't need.
pub struct LiveDiviChain {
    rpc: RpcClient,
    key: SecretKey,
    pubkey: [u8; 33],
    spk: Script,
    fee: FeePolicy,
    wallet: Mutex<Wallet>,
}

impl LiveDiviChain {
    /// New chain, over `rpc_url` (e.g. `swap_chain_divi::TESTNET_RPC`). `wallet_path`
    /// persists the known-coin set (public data only, same as `DiviBackend::new`);
    /// `None` keeps it in memory.
    pub fn new(
        rpc_url: &str,
        key: SecretKey,
        fee: FeePolicy,
        wallet_path: Option<PathBuf>,
    ) -> Result<Self> {
        Self::with_retry(rpc_url, key, fee, wallet_path, RetryPolicy::default())
    }

    /// Like [`LiveDiviChain::new`] with an explicit [`RetryPolicy`].
    pub fn with_retry(
        rpc_url: &str,
        key: SecretKey,
        fee: FeePolicy,
        wallet_path: Option<PathBuf>,
        retry: RetryPolicy,
    ) -> Result<Self> {
        let pubkey = key.public_key().serialize_compressed();
        let spk = Script::new_p2pkh(divi_crypto::hash::hash160(&pubkey).as_bytes());
        Ok(LiveDiviChain {
            rpc: RpcClient::new(rpc_url, retry),
            key,
            pubkey,
            spk,
            fee,
            wallet: Mutex::new(Wallet::open(wallet_path)?),
        })
    }

    /// Tell the wallet about a coin it doesn't know about yet (e.g. a previous round's
    /// reclaimed output) -- `swap_chain_divi::Wallet::apply_tx` needs the verbose
    /// `getrawtransaction` JSON and this wallet's own scriptPubKey hex.
    pub async fn learn_utxo(&self, txid: &str) -> Result<usize> {
        let tx = self.get_tx(txid).await?;
        self.wallet
            .lock()
            .unwrap()
            .apply_tx(&tx, &self.spk.to_hex())
    }

    /// `payout_script` -- where this wallet receives (change, swap payouts).
    pub fn payout_script(&self) -> Script {
        self.spk.clone()
    }

    /// `tip_height`.
    pub async fn tip_height(&self) -> Result<u64> {
        self.rpc
            .call_ok("getblockcount", json!([]))
            .await?
            .as_u64()
            .ok_or_else(|| SwapError::Transient("getblockcount: not a number".into()))
    }

    /// `median_time_past` -- the node reports `mediantime: null` on this proxy, so
    /// this takes the median of the last 11 block times itself, same as
    /// `DiviBackend::median_time_past`.
    pub async fn median_time_past(&self) -> Result<u32> {
        let tip = self.tip_height().await?;
        let mut hash = self.rpc.call_ok("getblockhash", json!([tip])).await?;
        let mut times = Vec::with_capacity(11);
        for _ in 0..11 {
            let block = self.rpc.call_ok("getblock", json!([hash, true])).await?;
            times.push(block["time"].as_u64().ok_or_else(|| {
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

    /// `build_funding`, generalized to an arbitrary `script_pubkey` (the piece
    /// `ChainBackend::build_funding`, which only takes `HtlcParams`, can't do) --
    /// same coin-selection algorithm `DiviBackend::build_funding` uses (prefer the
    /// smallest single coin that covers it, else accumulate largest-first), signed
    /// and locally script-verified before returning. **Not broadcast.**
    pub async fn build_funding(
        &self,
        script_pubkey: &Script,
        amount_sat: u64,
    ) -> Result<Transaction> {
        let target = amount_sat;
        let mut wallet = self.wallet.lock().unwrap();
        let mut coins = wallet.available();
        coins.sort_by_key(|c| c.value);
        // FeePolicy::fee's own formula (its method is private to swap-chain-divi;
        // `sat_per_kb`/`min_fee` are its public fields, same values DiviBackend uses).
        let est_fee = |n: usize| {
            let size = (10 + n * 148 + 2 * 34) as u64;
            (self.fee.sat_per_kb * size)
                .div_ceil(1000)
                .max(self.fee.min_fee)
        };
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
                        "need {target} + fee, have {sum}"
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
                OutPoint::new(from_txid(c.outpoint.txid), c.outpoint.vout),
                Script::new(),
                SEQUENCE_FINAL,
            ));
        }
        tx.vout.push(TxOut::new(
            DiviAmount::from_sat(target as i64),
            script_pubkey.clone(),
        ));
        if change >= DUST {
            tx.vout.push(TxOut::new(
                DiviAmount::from_sat(change as i64),
                self.spk.clone(),
            ));
        }
        // Not a clean iterator rewrite: sign_p2pkh needs an immutable &tx while this
        // loop also mutates tx.vin[i] in lockstep with picked[i] (both indexed by the
        // same input position) -- the same shape DiviBackend::build_funding's own
        // signing loop has.
        #[allow(clippy::needless_range_loop)]
        for i in 0..picked.len() {
            let sig = self.sign_p2pkh(&tx, i)?;
            let mut script_sig = Vec::new();
            push_data(&mut script_sig, &sig);
            push_data(&mut script_sig, &self.pubkey);
            tx.vin[i].script_sig = Script::from_bytes(script_sig);
            verify_input(
                &tx,
                i,
                &self.spk,
                DiviAmount::from_sat(picked[i].value as i64),
            )
            .map_err(|e| {
                SwapError::Rejected(format!(
                    "funding input failed local script verification: {e:?}"
                ))
            })?;
        }
        wallet.reserve(&picked, to_txid(tx.txid()))?;
        Ok(tx)
    }

    /// `broadcast` -- idempotent: already-known is success, a premature or genuinely
    /// rejected broadcast returns the matching `SwapError` variant, same semantics
    /// (and same `classify_broadcast_error` call) as `DiviBackend::broadcast`.
    pub async fn broadcast(&self, tx: &Transaction) -> Result<()> {
        let raw = hex::encode(divi_primitives::serialize::serialize(tx));
        match self.rpc.call("sendrawtransaction", json!([raw])).await {
            Ok(_) => {}
            Err(RpcError::Node { message, .. }) => match classify_broadcast_error(&message) {
                BroadcastClass::AlreadyKnown => {}
                BroadcastClass::Premature => return Err(SwapError::Premature(message)),
                BroadcastClass::Rejected => {
                    // Same double-check as DiviBackend::broadcast: a proxy fronting
                    // more than one backend node can reject against one while another
                    // already has the tx.
                    let txid = to_txid(tx.txid());
                    let mut known = self.get_tx_opt(&txid).await?.is_some();
                    for _ in 0..2 {
                        if known {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        known = self.get_tx_opt(&txid).await?.is_some();
                    }
                    if !known {
                        return Err(SwapError::Rejected(message));
                    }
                }
            },
            Err(e) => return Err(e.into()),
        }
        let own: Vec<Utxo> = tx
            .vout
            .iter()
            .enumerate()
            .filter(|(_, o)| o.script_pubkey == self.spk)
            .map(|(n, o)| Utxo {
                outpoint: to_outpoint(&OutPoint::new(tx.txid(), n as u32)),
                value: o.value.as_sat() as u64,
            })
            .collect();
        let inputs: Vec<Outpoint> = tx.vin.iter().map(|i| to_outpoint(&i.prevout)).collect();
        self.wallet
            .lock()
            .unwrap()
            .record_broadcast(&inputs, &own)?;
        Ok(())
    }

    /// `confirmations`.
    pub async fn confirmations(&self, txid: &Hash256) -> Result<Option<u32>> {
        Ok(self
            .get_tx_opt(&to_txid(*txid))
            .await?
            .map(|v| v["confirmations"].as_u64().unwrap_or(0) as u32))
    }

    /// `output` -- whatever is at `at`, regardless of which script it pays (the
    /// hashlock engine's own `htlc_output` filters by a specific HTLC's scriptPubKey;
    /// this doesn't, since the `DiviChain` trait's `output` takes no script to match).
    pub async fn output(&self, at: &OutPoint) -> Result<Option<(TxOut, u32)>> {
        let Some(tx) = self.get_tx_opt(&to_txid(at.txid)).await? else {
            return Ok(None);
        };
        let Some(out) = tx["vout"]
            .as_array()
            .and_then(|a| a.iter().find(|o| o["n"].as_u64() == Some(at.vout as u64)))
        else {
            return Ok(None);
        };
        let script_pubkey = Script::from_hex(
            out["scriptPubKey"]["hex"]
                .as_str()
                .ok_or_else(|| SwapError::Other("output without scriptPubKey hex".into()))?,
        )
        .map_err(|e| SwapError::Other(format!("scriptPubKey hex: {e:?}")))?;
        let sat = out["valueSat"]
            .as_u64()
            .or_else(|| out["value"].as_f64().map(|v| (v * 1e8).round() as u64))
            .ok_or_else(|| SwapError::Other("output without value".into()))?;
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
        Ok(Some((
            TxOut::new(DiviAmount::from_sat(sat as i64), script_pubkey),
            confirmations,
        )))
    }

    /// `find_spend` (plus `from_height`, see the module docs) -- scans blocks
    /// `from_height..=tip`, then the mempool, for a transaction spending `at`;
    /// returns its full decoded [`Transaction`] (the `DiviChain` trait's own return
    /// type), not just a description of the spend.
    pub async fn find_spend(&self, at: &OutPoint, from_height: u64) -> Result<Option<Transaction>> {
        let want_txid = at.txid.to_hex();
        let tip = self.tip_height().await?;
        for h in from_height..=tip {
            for txid in self.block_txids(h).await? {
                if self.spends(&txid, &want_txid, at.vout).await? {
                    return Ok(Some(self.get_full_tx(&txid).await?));
                }
            }
        }
        let pool = self.rpc.call_ok("getrawmempool", json!([])).await?;
        for txid in pool
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if self.spends(txid, &want_txid, at.vout).await? {
                return Ok(Some(self.get_full_tx(txid).await?));
            }
        }
        Ok(None)
    }

    async fn spends(&self, txid: &str, want_txid: &str, want_vout: u32) -> Result<bool> {
        let Some(tx) = self.get_tx_opt(&txid.parse()?).await? else {
            return Ok(false);
        };
        Ok(tx["vin"].as_array().into_iter().flatten().any(|input| {
            input["txid"].as_str() == Some(want_txid)
                && input["vout"].as_u64() == Some(want_vout as u64)
        }))
    }

    async fn get_full_tx(&self, txid: &str) -> Result<Transaction> {
        let hex_str = self
            .rpc
            .call_ok("getrawtransaction", json!([txid, 0]))
            .await?;
        let hex_str = hex_str.as_str().ok_or_else(|| {
            SwapError::Other("getrawtransaction(verbosity=0): not a string".into())
        })?;
        divi_primitives::serialize::deserialize(
            &hex::decode(hex_str).map_err(|e| SwapError::Other(format!("tx hex: {e}")))?,
        )
        .map_err(|e| SwapError::Other(format!("undecodable transaction: {e:?}")))
    }

    async fn block_txids(&self, height: u64) -> Result<Vec<String>> {
        let hash = self.rpc.call_ok("getblockhash", json!([height])).await?;
        let block = self.rpc.call_ok("getblock", json!([hash, true])).await?;
        Ok(block["tx"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn get_tx(&self, txid: &str) -> Result<Value> {
        self.rpc
            .call_ok("getrawtransaction", json!([txid, 1]))
            .await
    }

    /// Like [`LiveDiviChain::get_tx`] but `None` for "no such transaction" (-5)
    /// instead of an error -- same distinction `DiviBackend::get_tx_opt` makes.
    async fn get_tx_opt(&self, txid: &Txid) -> Result<Option<Value>> {
        match self
            .rpc
            .call("getrawtransaction", json!([txid.to_rpc_hex(), 1]))
            .await
        {
            Ok(v) => Ok(Some(v)),
            Err(RpcError::Node { code: -5, .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn sign_p2pkh(&self, tx: &Transaction, input_index: usize) -> Result<Vec<u8>> {
        let hash = sighash(tx, input_index, &self.spk, SigHashType::All, false)
            .map_err(|e| SwapError::Other(format!("sighash: {e}")))?;
        let signature = sign_hash(&self.key, hash.as_bytes())
            .map_err(|e| SwapError::Other(format!("sign: {e}")))?;
        let mut sig_bytes = signature.to_der();
        sig_bytes.push(SigHashType::All as u8);
        Ok(sig_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_key() -> SecretKey {
        SecretKey::from_bytes(&[0x42; 32]).unwrap()
    }

    fn chain_against(rpc_url: &str) -> LiveDiviChain {
        LiveDiviChain::with_retry(
            rpc_url,
            test_key(),
            FeePolicy::default(),
            None,
            RetryPolicy {
                attempts: 1,
                base_delay: std::time::Duration::from_millis(1),
            },
        )
        .unwrap()
    }

    async fn mock_rpc(server: &MockServer, result: Value) {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": result, "error": null, "id": 1
            })))
            .mount(server)
            .await;
    }

    #[test]
    fn payout_script_is_the_wallets_own_p2pkh() {
        let chain = chain_against("http://unused");
        let pubkey = test_key().public_key().serialize_compressed();
        let expected = Script::new_p2pkh(divi_crypto::hash::hash160(&pubkey).as_bytes());
        assert_eq!(chain.payout_script(), expected);
    }

    #[tokio::test]
    async fn tip_height_reads_getblockcount() {
        let server = MockServer::start().await;
        mock_rpc(&server, json!(123_456)).await;
        let chain = chain_against(&server.uri());
        assert_eq!(chain.tip_height().await.unwrap(), 123_456);
    }

    #[tokio::test]
    async fn build_funding_rejects_insufficient_funds_with_no_coins_known() {
        let chain = chain_against("http://unused");
        let err = chain
            .build_funding(&Script::new(), 1_000_000)
            .await
            .unwrap_err();
        assert!(matches!(err, SwapError::InsufficientFunds(_)));
    }

    #[tokio::test]
    async fn build_funding_selects_the_learned_coin_and_pays_the_requested_script() {
        let server = MockServer::start().await;
        let chain = chain_against(&server.uri());
        let pubkey = test_key().public_key().serialize_compressed();
        let spk_hex = Script::new_p2pkh(divi_crypto::hash::hash160(&pubkey).as_bytes()).to_hex();
        let learn_tx = json!({
            "txid": "a".repeat(64),
            "vin": [],
            "vout": [{"n": 0, "scriptPubKey": {"hex": spk_hex}, "valueSat": 100_000_000}]
        });
        mock_rpc(&server, learn_tx).await;
        chain.learn_utxo(&"a".repeat(64)).await.unwrap();

        let destination = Script::new_p2pkh(&[7u8; 20]);
        let tx = chain.build_funding(&destination, 50_000_000).await.unwrap();
        assert_eq!(tx.vout[0].script_pubkey, destination);
        assert_eq!(tx.vout[0].value, DiviAmount::from_sat(50_000_000));
        // A change output comes back to this wallet's own script.
        assert_eq!(tx.vout[1].script_pubkey, chain.spk);
        verify_input(&tx, 0, &chain.spk, DiviAmount::from_sat(100_000_000))
            .expect("build_funding must leave a script-valid signature on its own input");
    }

    #[tokio::test]
    async fn broadcast_treats_already_known_as_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": null,
                "error": {"code": -27, "message": "transaction already in block chain"},
                "id": 1
            })))
            .mount(&server)
            .await;
        let chain = chain_against(&server.uri());
        let tx = Transaction::new();
        chain.broadcast(&tx).await.unwrap();
    }

    #[tokio::test]
    async fn broadcast_surfaces_a_premature_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": null,
                "error": {"code": -26, "message": "non-final"},
                "id": 1
            })))
            .mount(&server)
            .await;
        let chain = chain_against(&server.uri());
        let tx = Transaction::new();
        let err = chain.broadcast(&tx).await.unwrap_err();
        assert!(matches!(err, SwapError::Premature(_)));
    }

    #[tokio::test]
    async fn confirmations_is_none_for_an_unknown_txid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": null,
                "error": {"code": -5, "message": "No such mempool or blockchain transaction"},
                "id": 1
            })))
            .mount(&server)
            .await;
        let chain = chain_against(&server.uri());
        let result = chain
            .confirmations(&Hash256::from_bytes([9u8; 32]))
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn output_returns_the_txout_and_confirmations() {
        let server = MockServer::start().await;
        let spk = Script::new_p2pkh(&[3u8; 20]);
        mock_rpc(
            &server,
            json!({
                "confirmations": 6,
                "vout": [{"n": 0, "scriptPubKey": {"hex": spk.to_hex()}, "valueSat": 42}]
            }),
        )
        .await;
        let chain = chain_against(&server.uri());
        let at = OutPoint::new(Hash256::from_bytes([1u8; 32]), 0);
        let (txout, confirmations) = chain.output(&at).await.unwrap().unwrap();
        assert_eq!(confirmations, 6);
        assert_eq!(txout.value, DiviAmount::from_sat(42));
        assert_eq!(txout.script_pubkey, spk);
    }

    #[tokio::test]
    async fn output_is_none_when_the_vout_index_does_not_exist() {
        let server = MockServer::start().await;
        mock_rpc(&server, json!({"confirmations": 1, "vout": []})).await;
        let chain = chain_against(&server.uri());
        let at = OutPoint::new(Hash256::from_bytes([1u8; 32]), 0);
        assert_eq!(chain.output(&at).await.unwrap(), None);
    }
}

// Needs the real public DIVI testnet RPC proxy -- not run by default, same
// `--features live` convention as every other real-network test in this crate.
// Read-only (`tip_height`/`median_time_past`/`output` against a known-real outpoint):
// proves the RPC call shapes against the actual proxy, not just mocked JSON, without
// broadcasting anything.
#[cfg(all(test, feature = "live"))]
mod live {
    use super::*;
    use divi_crypto::keys::SecretKey;
    use swap_chain_divi::{RetryPolicy, TESTNET_RPC};

    fn chain() -> LiveDiviChain {
        LiveDiviChain::with_retry(
            TESTNET_RPC,
            SecretKey::from_bytes(&[0x42; 32]).unwrap(),
            FeePolicy::default(),
            None,
            RetryPolicy::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn tip_height_and_median_time_past_are_real() {
        let chain = chain();
        let tip = chain
            .tip_height()
            .await
            .expect("real testnet proxy reachable");
        assert!(tip > 300_000, "DIVI testnet is well past height 300,000");
        let mtp = chain.median_time_past().await.expect("mtp reachable");
        assert!(mtp > 1_700_000_000, "mtp must be a real, recent unix time");
    }

    #[tokio::test]
    async fn output_reads_a_known_real_outpoint() {
        // The role-swap round's real Tx_redeem output (docs/plans/swap-poc/status
        // /xmr.md): 95,900,000 sat to a known P2PKH script, confirmed on-chain.
        let chain = chain();
        let at = OutPoint::new(
            Hash256::from_hex("0de8a0c6d5c117bf1aefa0bfd6d3c4790e7c9a52c5ee27c569858818e934307c")
                .unwrap(),
            0,
        );
        let (txout, confirmations) = chain
            .output(&at)
            .await
            .expect("real proxy reachable")
            .expect("this outpoint is real and confirmed");
        assert_eq!(txout.value, DiviAmount::from_sat(95_900_000));
        assert!(confirmations > 0);
    }
}
