// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Litecoin testnet `ChainBackend` over Esplora HTTP (`litecoinspace.org`).
//!
//! Lane **ltc** (docs/plans/swap-poc/lanes/ltc.md) owns this crate. Litecoin uses the same
//! script and SegWit v0 rules as Bitcoin, so transaction building (`tx.rs`) is modeled
//! directly on `swap-chain-btc`; only address *string* encoding (`address.rs`) differs,
//! since Litecoin's bech32 HRP (`tltc`/`ltc`) is not one of `bitcoin::Address`'s known
//! `Network` variants.

mod address;
mod client;
mod send;
mod tx;

pub use address::{decode_segwit_v0, encode_segwit_v0, LTC_HRP, TLTC_HRP};
pub use client::{ClientError, EsploraClient, RetryPolicy};
pub use send::build_send_tx;
pub use tx::{
    build_funding_tx, build_spend_tx, htlc_script_pubkey, verify_htlc_spend, Coin, Spend,
};

use std::collections::HashSet;
use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{CompressedPublicKey, OutPoint};
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, LockedOutput, Outpoint, SignedTx, SpendInfo,
    SwapError, Txid,
};
use serde_json::Value;

type Result<T> = std::result::Result<T, SwapError>;

/// Default (and, so far, only known) Litecoin testnet Esplora endpoint. No independent
/// secondary mirror of this API shape was found publicly as of 2026-10-11 (recorded under
/// `- decisions:` in the lane status file); `esplora_falls_back_to_secondary` exercises the
/// fallback logic itself against synthetic servers.
pub const LITECOINSPACE_TESTNET: &str = "https://litecoinspace.org/testnet/api";

/// Default Esplora endpoints (primary first) for a test network name: currently only
/// `testnet`.
pub fn esplora_endpoints(network: &str) -> Result<Vec<String>> {
    match network {
        "testnet" => Ok(vec![LITECOINSPACE_TESTNET.into()]),
        other => Err(SwapError::InvalidParams(format!(
            "ltc network {other:?} unsupported: testnet"
        ))),
    }
}

/// How the sat/vB (litoshi/vB) rate is chosen.
#[derive(Debug, Clone, Copy)]
pub enum FeePolicy {
    /// Always this rate.
    Fixed(u64),
    /// `/v1/fees/recommended` half-hour rate, never below `floor`.
    Recommended {
        /// Minimum sat/vB.
        floor: u64,
    },
}

impl Default for FeePolicy {
    fn default() -> Self {
        // Litecoin fees are sat/vB; floor 1 (brief).
        FeePolicy::Recommended { floor: 1 }
    }
}

/// Blocks scanned per `find_spend` call when falling back to block scanning.
const MAX_SCAN_BLOCKS: u64 = 200;

/// Litecoin testnet [`ChainBackend`].
pub struct LtcBackend {
    esplora: EsploraClient,
    secp: Secp256k1<All>,
    key: SecretKey,
    pubkey: CompressedPublicKey,
    address: String,
    fees: FeePolicy,
    /// Coins spent by transactions built here; see [`Self::with_free_coins`].
    spent_by_built: parking_lot::Mutex<HashSet<OutPoint>>,
}

impl std::fmt::Debug for LtcBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LtcBackend")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl LtcBackend {
    /// `endpoints`: Esplora base URLs, primary first. `key` is resolved by the caller.
    pub fn new(
        endpoints: Vec<String>,
        key: SecretKey,
        fees: FeePolicy,
        retry: RetryPolicy,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let pubkey = CompressedPublicKey(key.public_key(&secp));
        let address = encode_segwit_v0(TLTC_HRP, pubkey.wpubkey_hash().as_byte_array())?;
        Ok(Self {
            esplora: EsploraClient::new(endpoints, retry)?,
            secp,
            key,
            pubkey,
            address,
            fees,
            spent_by_built: Default::default(),
        })
    }

    /// Default endpoints for `testnet` (see [`esplora_endpoints`]).
    pub fn for_network(network: &str, key: SecretKey, fees: FeePolicy) -> Result<Self> {
        Self::new(
            esplora_endpoints(network)?,
            key,
            fees,
            RetryPolicy::default(),
        )
    }

    /// The key's P2WPKH `tltc` address string (where funding coins live and spends land).
    pub fn address(&self) -> &str {
        &self.address
    }

    async fn sat_per_vb(&self) -> u64 {
        match self.fees {
            FeePolicy::Fixed(r) => r.max(1),
            FeePolicy::Recommended { floor } => {
                let rate = async {
                    let body = self.esplora.get("/v1/fees/recommended").await.ok()?;
                    let v: Value = serde_json::from_str(&body).ok()?;
                    v["halfHourFee"].as_u64()
                }
                .await;
                if rate.is_none() {
                    tracing::warn!(floor, "fee estimate unavailable, using floor");
                }
                rate.unwrap_or(floor).max(floor).max(1)
            }
        }
    }

    async fn get_json(&self, path: &str) -> Result<Value> {
        let body = self.esplora.get(path).await?;
        parse_json(&body)
    }

    async fn get_json_opt(&self, path: &str) -> Result<Option<Value>> {
        match self.esplora.get_opt(path).await? {
            Some(b) => Ok(Some(parse_json(&b)?)),
            None => Ok(None),
        }
    }

    /// This backend's own UTXOs, from the Esplora address endpoint.
    async fn my_utxos(&self) -> Result<Vec<Coin>> {
        let utxos = self
            .get_json(&format!("/address/{}/utxo", self.address))
            .await?;
        utxos
            .as_array()
            .ok_or_else(|| {
                SwapError::Transient("utxo response is not an array (malformed?)".into())
            })?
            .iter()
            .map(|u| {
                Ok(Coin {
                    outpoint: OutPoint::new(
                        bitcoin::Txid::from_str(u["txid"].as_str().unwrap_or(""))
                            .map_err(|e| SwapError::Other(format!("utxo txid: {e}")))?,
                        u["vout"].as_u64().unwrap_or(u64::MAX) as u32,
                    ),
                    value: u["value"].as_u64().unwrap_or(0),
                    confirmed: u["status"]["confirmed"].as_bool().unwrap_or(false),
                })
            })
            .collect()
    }

    /// Build, sign and consensus-verify a plain P2WPKH send of `sats` to `to` (any bech32
    /// segwit v0 address with a 20-byte program — a P2WPKH destination), change back to
    /// this backend's own address. **Does not broadcast** — call [`ChainBackend::broadcast`]
    /// on the result.
    ///
    /// Not part of [`ChainBackend`] (that trait only funds/claims/refunds HTLCs); for
    /// moving funds directly between wallets, e.g. to unblock a swap direction without a
    /// faucet (`docs/plans/swap-poc/funding.md`).
    pub async fn build_send(&self, to: &str, sats: u64) -> Result<SignedTx> {
        let (_, program) = decode_segwit_v0(to)?;
        let to_program: [u8; 20] = program.try_into().map_err(|p: Vec<u8>| {
            SwapError::InvalidParams(format!(
                "destination is not a P2WPKH (20-byte) address: {} bytes",
                p.len()
            ))
        })?;
        let fee_rate = self.sat_per_vb().await;
        let coins = self.my_utxos().await?;
        let tx = self.with_free_coins(
            coins,
            |coins| build_send_tx(&self.secp, &self.key, coins, to_program, sats, fee_rate),
            |tx| tx,
        )?;
        Ok(Self::to_signed(&tx))
    }

    /// `build` from `coins` less those a transaction this backend built already spends,
    /// then mark the new transaction's inputs as spent. Two swaps locking at once both see
    /// the same coins from Esplora — a funding is persisted before it is broadcast, so the
    /// first is not in the mempool yet when the second is built — and without this both
    /// would pick the same coin and the second broadcast would be rejected as a double
    /// spend. Filter, build and mark run under one lock with no await, so builds serialise.
    /// A mark lasts until its coin leaves the address's UTXO list (spent in the mempool or
    /// a block). A transaction never broadcast holds its coins until the process restarts:
    /// that fails closed, as insufficient funds, never as a double spend.
    fn with_free_coins<T>(
        &self,
        coins: Vec<Coin>,
        build: impl FnOnce(&[Coin]) -> Result<T>,
        tx: impl FnOnce(&T) -> &bitcoin::Transaction,
    ) -> Result<T> {
        let mut spent = self.spent_by_built.lock();
        spent.retain(|op| coins.iter().any(|c| c.outpoint == *op));
        let free: Vec<Coin> = coins
            .into_iter()
            .filter(|c| !spent.contains(&c.outpoint))
            .collect();
        let built = build(&free)?;
        spent.extend(tx(&built).input.iter().map(|i| i.previous_output));
        Ok(built)
    }

    fn to_signed(tx: &bitcoin::Transaction) -> SignedTx {
        SignedTx {
            txid: Txid(tx.compute_txid().to_byte_array()),
            raw: serialize(tx),
        }
    }

    /// Confirmations from an Esplora `status` object, given the tip height.
    fn confs_from_status(status: &Value, tip: u64) -> u32 {
        match (
            status["confirmed"].as_bool(),
            status["block_height"].as_u64(),
        ) {
            (Some(true), Some(h)) if tip >= h => (tip - h + 1) as u32,
            _ => 0,
        }
    }

    /// Scan blocks `from_height..=tip` for a transaction spending `outpoint`.
    async fn scan_blocks(
        &self,
        outpoint: &Outpoint,
        from_height: u64,
    ) -> Result<Option<SpendInfo>> {
        let tip = self.tip_height().await?;
        let want_txid = outpoint.txid.to_rpc_hex();
        let last = tip.min(from_height.saturating_add(MAX_SCAN_BLOCKS - 1));
        for height in from_height..=last {
            let hash = self
                .esplora
                .get(&format!("/block-height/{height}"))
                .await?
                .trim()
                .to_string();
            let mut start = 0u32;
            loop {
                let txs = self.get_json(&format!("/block/{hash}/txs/{start}")).await?;
                let txs = txs.as_array().cloned().unwrap_or_default();
                if txs.is_empty() {
                    break;
                }
                for t in &txs {
                    if let Some(info) = spend_from_tx(t, &want_txid, outpoint.vout, Some(height))? {
                        return Ok(Some(info));
                    }
                }
                start += txs.len() as u32;
            }
        }
        Ok(None)
    }
}

fn parse_json(body: &str) -> Result<Value> {
    // A non-error (2xx) response that fails to parse as JSON is a transport/proxy artifact
    // (a truncated or HTML body), not a deliberate answer from the chain: real Esplora
    // error bodies are plain text and never reach this function (see `ClientError::Http`).
    serde_json::from_str(body).map_err(|e| SwapError::Transient(format!("bad Esplora JSON: {e}")))
}

fn hex_items(v: &Value) -> Result<Vec<Vec<u8>>> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|s| {
                    hex::decode(s.as_str().unwrap_or(""))
                        .map_err(|e| SwapError::Other(format!("bad witness hex: {e}")))
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(vec![]))
}

/// If Esplora tx JSON `t` has an input spending `prev_txid:vout`, describe it.
fn spend_from_tx(
    t: &Value,
    prev_txid: &str,
    vout: u32,
    height: Option<u64>,
) -> Result<Option<SpendInfo>> {
    let Some(vins) = t["vin"].as_array() else {
        return Ok(None);
    };
    for (i, vin) in vins.iter().enumerate() {
        if vin["txid"].as_str() == Some(prev_txid) && vin["vout"].as_u64() == Some(vout as u64) {
            let txid = Txid::from_rpc_hex(t["txid"].as_str().unwrap_or(""))?;
            return Ok(Some(SpendInfo {
                txid,
                input_index: i as u32,
                height,
                script_sig: hex::decode(vin["scriptsig"].as_str().unwrap_or(""))
                    .map_err(|e| SwapError::Other(format!("bad scriptsig hex: {e}")))?,
                witness: hex_items(&vin["witness"])?,
            }));
        }
    }
    Ok(None)
}

/// Map a node reject reason (Esplora puts it in the 400 body) to the engine's taxonomy.
fn classify_broadcast_error(body: &str) -> SwapError {
    let b = body.to_ascii_lowercase();
    if b.contains("non-final")
        || b.contains("locktime requirement not satisfied")
        || b.contains("non-mandatory-script-verify-flag (locktime")
    {
        SwapError::Premature(body.trim().to_string())
    } else {
        SwapError::Rejected(body.trim().to_string())
    }
}

fn is_already_known(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    b.contains("already in block chain")
        || b.contains("already in the block chain")
        || b.contains("txn-already-in-mempool")
        || b.contains("txn-already-known")
        // Bitcoin Core >= 0.21 wording (Litecoin Core tracks it) for an already-confirmed tx.
        || b.contains("outputs already in utxo set")
}

fn ltc_outpoint(o: &Outpoint) -> OutPoint {
    OutPoint::new(bitcoin::Txid::from_byte_array(o.txid.0), o.vout)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ChainBackend for LtcBackend {
    fn chain(&self) -> Chain {
        Chain::Ltc
    }

    fn pubkey(&self) -> [u8; 33] {
        self.pubkey.to_bytes()
    }

    async fn tip_height(&self) -> Result<u64> {
        let body = self.esplora.get("/blocks/tip/height").await?;
        let trimmed = body.trim();
        if trimmed.is_empty() {
            // A load-balanced backend occasionally answers 200 with an empty body
            // mid-reindex; a real tip height is never empty.
            return Err(SwapError::Transient("empty tip height response".into()));
        }
        trimmed
            .parse()
            .map_err(|_| SwapError::Transient(format!("unparseable tip height {body:?}")))
    }

    async fn median_time_past(&self) -> Result<u32> {
        let hash = self.esplora.get("/blocks/tip/hash").await?;
        let block = self.get_json(&format!("/block/{}", hash.trim())).await?;
        block["mediantime"]
            .as_u64()
            .map(|t| t as u32)
            .ok_or_else(|| {
                // Esplora always sets mediantime on a real block; its absence means we read a
                // block from a backend that has not finished indexing it yet.
                SwapError::Transient("block JSON lacks mediantime (still indexing?)".into())
            })
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        let fee_rate = self.sat_per_vb().await;
        let coins = self.my_utxos().await?;
        let built = self.with_free_coins(
            coins,
            |coins| {
                build_funding_tx(
                    &self.secp,
                    &self.key,
                    coins,
                    htlc,
                    amount.to_sat(),
                    fee_rate,
                )
            },
            |built| &built.tx,
        )?;
        let signed = Self::to_signed(&built.tx);
        Ok(Funding {
            outpoint: Outpoint {
                txid: signed.txid,
                vout: built.htlc_vout,
            },
            tx: signed,
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
        let tx = build_spend_tx(
            &self.secp,
            &self.key,
            htlc,
            ltc_outpoint(at),
            amount.to_sat(),
            Spend::Claim(preimage),
            self.sat_per_vb().await,
        )?;
        Ok(Self::to_signed(&tx))
    }

    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        let tx = build_spend_tx(
            &self.secp,
            &self.key,
            htlc,
            ltc_outpoint(at),
            amount.to_sat(),
            Spend::Refund,
            self.sat_per_vb().await,
        )?;
        Ok(Self::to_signed(&tx))
    }

    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        match self.esplora.post("/tx", hex::encode(&tx.raw)).await {
            Ok(_) => Ok(tx.txid),
            Err(ClientError::Http(f)) => {
                if is_already_known(&f.body) {
                    return Ok(tx.txid);
                }
                let err = classify_broadcast_error(&f.body);
                // Inputs gone + the tx itself known (e.g. confirmed while we were down).
                if f.body.to_ascii_lowercase().contains("missingorspent")
                    && self.confirmations(&tx.txid).await?.is_some()
                {
                    return Ok(tx.txid);
                }
                Err(err)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        let Some(status) = self
            .get_json_opt(&format!("/tx/{}/status", txid.to_rpc_hex()))
            .await?
        else {
            return Ok(None);
        };
        if status["confirmed"].as_bool() != Some(true) {
            return Ok(Some(0));
        }
        let tip = self.tip_height().await?;
        Ok(Some(Self::confs_from_status(&status, tip)))
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        let Some(t) = self
            .get_json_opt(&format!("/tx/{}", at.txid.to_rpc_hex()))
            .await?
        else {
            return Ok(None);
        };
        let Some(out) = t["vout"].as_array().and_then(|v| v.get(at.vout as usize)) else {
            return Ok(None);
        };
        let want = hex::encode(htlc_script_pubkey(htlc).as_bytes());
        if out["scriptpubkey"].as_str() != Some(want.as_str()) {
            return Ok(None);
        }
        let value = out["value"]
            .as_u64()
            .ok_or_else(|| SwapError::Other("vout lacks value".into()))?;
        let confirmations = if t["status"]["confirmed"].as_bool() == Some(true) {
            Self::confs_from_status(&t["status"], self.tip_height().await?)
        } else {
            0
        };
        Ok(Some(LockedOutput {
            amount: Amount::from_sat(value),
            confirmations,
        }))
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        let prev = outpoint.txid.to_rpc_hex();
        let path = format!("/tx/{prev}/outspend/{}", outpoint.vout);
        let outspend = match self.esplora.get_opt(&path).await {
            Ok(Some(b)) => parse_json(&b)?,
            Ok(None) => return Ok(None),
            // Endpoint without outspend support: fall back to scanning blocks.
            Err(ClientError::Http(f)) if f.status == 400 || f.status == 501 => {
                return self.scan_blocks(outpoint, from_height).await;
            }
            Err(e) => return Err(e.into()),
        };
        if outspend["spent"].as_bool() != Some(true) {
            return Ok(None);
        }
        let spender = outspend["txid"]
            .as_str()
            .ok_or_else(|| SwapError::Other("outspend lacks txid".into()))?;
        // A load-balanced backend can report the outspend before another replica has
        // indexed the spending tx itself; treat that race as "not found yet" (the caller
        // polls find_spend again), not a permanent error.
        let Some(t) = self.get_json_opt(&format!("/tx/{spender}")).await? else {
            return Ok(None);
        };
        let height = outspend["status"]["block_height"].as_u64();
        spend_from_tx(&t, &prev, outpoint.vout, height)
    }
}

#[cfg(test)]
mod tests;
