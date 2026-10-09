// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! BTC `ChainBackend` over Esplora HTTP (mempool.space signet, blockstream fallback).
//!
//! Lane **btc** (docs/plans/swap-poc/lanes/btc.md) owns this crate. The Wave 0 live
//! proof (`examples/*_cltv_proof.rs`) shows the transaction shapes that signet accepts.

mod client;
mod tx;

pub use client::{ClientError, EsploraClient, RetryPolicy};
pub use tx::{
    build_funding_tx, build_spend_tx, htlc_script_pubkey, verify_htlc_spend, Coin, Spend,
};

use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, OutPoint};
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, LockedOutput, Outpoint, SignedTx, SpendInfo,
    SwapError, Txid,
};
use serde_json::Value;

type Result<T> = std::result::Result<T, SwapError>;

/// Default primary Esplora endpoint.
pub const MEMPOOL_SIGNET: &str = "https://mempool.space/signet/api";
/// Default secondary Esplora endpoint.
pub const BLOCKSTREAM_SIGNET: &str = "https://blockstream.info/signet/api";
/// Testnet3 primary Esplora endpoint.
pub const MEMPOOL_TESTNET: &str = "https://mempool.space/testnet/api";
/// Testnet3 secondary Esplora endpoint.
pub const BLOCKSTREAM_TESTNET: &str = "https://blockstream.info/testnet/api";

/// Default Esplora endpoints (primary first) for a test network name: `signet` or `testnet`
/// (testnet3). Both use `tb1` addresses, so only the endpoints differ.
pub fn esplora_endpoints(network: &str) -> Result<Vec<String>> {
    match network {
        "signet" => Ok(vec![MEMPOOL_SIGNET.into(), BLOCKSTREAM_SIGNET.into()]),
        "testnet" => Ok(vec![MEMPOOL_TESTNET.into(), BLOCKSTREAM_TESTNET.into()]),
        other => Err(SwapError::InvalidParams(format!(
            "btc network {other:?} unsupported: signet or testnet"
        ))),
    }
}

/// How the sat/vB rate is chosen.
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
        FeePolicy::Recommended { floor: 2 }
    }
}

/// Blocks scanned per `find_spend` call when falling back to block scanning.
const MAX_SCAN_BLOCKS: u64 = 200;

/// Bitcoin signet [`ChainBackend`].
pub struct BtcBackend {
    esplora: EsploraClient,
    secp: Secp256k1<All>,
    key: SecretKey,
    pubkey: CompressedPublicKey,
    address: Address,
    fees: FeePolicy,
}

impl std::fmt::Debug for BtcBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtcBackend")
            .field("address", &self.address.to_string())
            .finish_non_exhaustive()
    }
}

impl BtcBackend {
    /// `endpoints`: Esplora base URLs, primary first. `key` is resolved by the caller.
    pub fn new(
        endpoints: Vec<String>,
        key: SecretKey,
        fees: FeePolicy,
        retry: RetryPolicy,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let pubkey = CompressedPublicKey(key.public_key(&secp));
        let address = Address::p2wpkh(&pubkey, Network::Signet);
        Ok(Self {
            esplora: EsploraClient::new(endpoints, retry)?,
            secp,
            key,
            pubkey,
            address,
            fees,
        })
    }

    /// Mempool.space with blockstream as secondary.
    pub fn signet(key: SecretKey, fees: FeePolicy) -> Result<Self> {
        Self::for_network("signet", key, fees)
    }

    /// Default endpoints for `signet` or `testnet` (see [`esplora_endpoints`]).
    pub fn for_network(network: &str, key: SecretKey, fees: FeePolicy) -> Result<Self> {
        Self::new(
            esplora_endpoints(network)?,
            key,
            fees,
            RetryPolicy::default(),
        )
    }

    /// The key's P2WPKH `tb1` address (same string on signet and testnet3; where funding coins live and spends land).
    pub fn address(&self) -> &Address {
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
    serde_json::from_str(body).map_err(|e| SwapError::Other(format!("bad Esplora JSON: {e}")))
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
}

fn btc_outpoint(o: &Outpoint) -> OutPoint {
    OutPoint::new(bitcoin::Txid::from_byte_array(o.txid.0), o.vout)
}

#[async_trait]
impl ChainBackend for BtcBackend {
    fn chain(&self) -> Chain {
        Chain::Btc
    }

    fn pubkey(&self) -> [u8; 33] {
        self.pubkey.to_bytes()
    }

    async fn tip_height(&self) -> Result<u64> {
        let body = self.esplora.get("/blocks/tip/height").await?;
        body.trim()
            .parse()
            .map_err(|e| SwapError::Other(format!("bad tip height {body:?}: {e}")))
    }

    async fn median_time_past(&self) -> Result<u32> {
        let hash = self.esplora.get("/blocks/tip/hash").await?;
        let block = self.get_json(&format!("/block/{}", hash.trim())).await?;
        block["mediantime"]
            .as_u64()
            .map(|t| t as u32)
            .ok_or_else(|| SwapError::Other("block JSON lacks mediantime".into()))
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        let utxos = self
            .get_json(&format!("/address/{}/utxo", self.address))
            .await?;
        let coins = utxos
            .as_array()
            .ok_or_else(|| SwapError::Other("utxo response is not an array".into()))?
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
            .collect::<Result<Vec<_>>>()?;
        let built = build_funding_tx(
            &self.secp,
            &self.key,
            &coins,
            htlc,
            amount.to_sat(),
            self.sat_per_vb().await,
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
            btc_outpoint(at),
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
            btc_outpoint(at),
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
        let t = self.get_json(&format!("/tx/{spender}")).await?;
        let height = outspend["status"]["block_height"].as_u64();
        spend_from_tx(&t, &prev, outpoint.vout, height)
    }
}

#[cfg(test)]
mod tests;
