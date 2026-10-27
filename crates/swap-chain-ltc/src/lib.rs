// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
mod crosscheck;
mod send;
mod tx;

pub use address::{decode_segwit_v0, encode_segwit_v0, LTC_HRP, TLTC_HRP};
pub use client::{ClientError, EsploraClient, RetryPolicy};
pub use crosscheck::{
    enforce as enforce_tip_crosscheck, tip_crosscheck, CrossCheckOutcome, CrossCheckSource,
    BLOCKBOOK_MAINNET, BLOCKCYPHER_MAINNET, CROSSCHECK_DEPTH,
};
pub use send::build_send_tx;
pub use tx::{
    build_cpfp_tx, build_funding_tx, build_spend_tx, claim_vsize, cpfp_child_vsize,
    htlc_script_pubkey, verify_htlc_spend, Coin, Spend, DUST_SATS,
};

use std::collections::HashMap;
use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{CompressedPublicKey, OutPoint};
use crosscheck::{
    agree_find_spend, agree_lock, claim_crosscheck, enforce, lock_view, ClaimCheck, LockView,
    SpendCheck,
};
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimSizes, FeeBump, Funding, HtlcParams, InputReservations,
    LockedOutput, Outpoint, SignedTx, SpendInfo, SwapError, Txid,
};
use serde_json::Value;

type Result<T> = std::result::Result<T, SwapError>;

/// Default (and, so far, only known) Litecoin testnet Esplora endpoint. No independent
/// secondary mirror of this API shape was found publicly as of 2026-10-11 (recorded under
/// `- decisions:` in the lane status file); `esplora_falls_back_to_secondary` exercises the
/// fallback logic itself against synthetic servers.
pub const LITECOINSPACE_TESTNET: &str = "https://litecoinspace.org/testnet/api";

/// Litecoin mainnet Esplora endpoint (same operator as the testnet one; no independent
/// mainnet mirror is listed).
pub const LITECOINSPACE_MAINNET: &str = "https://litecoinspace.org/api";

/// The bech32 HRP for a network name: `ltc` on `mainnet`, `tltc` on `testnet`.
pub fn hrp_for(network: &str) -> Result<&'static str> {
    match network {
        "mainnet" => Ok(LTC_HRP),
        "testnet" => Ok(TLTC_HRP),
        other => Err(SwapError::InvalidParams(format!(
            "ltc network {other:?} unsupported: mainnet or testnet"
        ))),
    }
}

/// Default Esplora endpoints (primary first) for a network name: `mainnet` or `testnet`.
/// Callers gate `mainnet` behind an explicit opt-in (`allow_mainnet`).
pub fn esplora_endpoints(network: &str) -> Result<Vec<String>> {
    match network {
        "mainnet" => Ok(vec![LITECOINSPACE_MAINNET.into()]),
        "testnet" => Ok(vec![LITECOINSPACE_TESTNET.into()]),
        other => Err(SwapError::InvalidParams(format!(
            "ltc network {other:?} unsupported: mainnet or testnet"
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

/// Litecoin's target block spacing in seconds, the same on mainnet and testnet: Litecoin
/// Core's `consensus.nPowTargetSpacing = 2.5 * 60` in `src/kernel/chainparams.cpp`.
pub const TARGET_BLOCK_SECS: u32 = 150;

/// Litecoin [`ChainBackend`] (testnet by default; see [`LtcBackend::new_on`]).
pub struct LtcBackend {
    esplora: EsploraClient,
    secp: Secp256k1<All>,
    key: SecretKey,
    pubkey: CompressedPublicKey,
    address: String,
    hrp: &'static str,
    fees: FeePolicy,
    reservations: Option<InputReservations>,
    retry: RetryPolicy,
    claim_check: Option<ClaimCrossCheck>,
}

/// The opt-in claim-time tip cross-check (see [`LtcBackend::with_claim_crosscheck`]).
struct ClaimCrossCheck {
    source: CrossCheckSource,
    base: String,
    /// The last outcome, the primary tip hash it was taken at and the outpoint it checked. A
    /// claim retried every engine tick reuses it until the primary's tip moves, so the
    /// (rate-limited) source is asked at most once per primary block per comparison.
    last: parking_lot::Mutex<Option<(String, Outpoint, ClaimCheck)>>,
    /// The source's view of each lock read (EL), with the primary's answer it was taken
    /// against. A lock polled every engine tick reuses it until the primary's answer changes
    /// (a new confirmation, so about once per LTC block), keeping a rate-limited source's
    /// quota for the reads that matter.
    locks: parking_lot::Mutex<LockCache>,
    /// The agreed view of each `find_spend` (EN), with the primary's answer it was taken
    /// against and when. A spend polled every engine tick (5 s) reuses it while the primary's
    /// answer is unchanged, for at most [`SPEND_RECHECK`], so a rate-limited source (BlockCypher
    /// keyless: 100 requests an hour) is asked about once per LTC block per watched lock.
    spends: parking_lot::Mutex<SpendCache>,
}

/// Per outpoint: the primary's answer and the source's view (or why it could not be read)
/// taken against it.
type LockCache = HashMap<Outpoint, (LockedOutput, std::result::Result<LockView, String>)>;

/// Spend reads cached by [`ClaimCrossCheck::spends`]: the primary's answer, when it was
/// agreed, and the outcome.
type SpendCache = HashMap<
    Outpoint,
    (
        Option<SpendInfo>,
        std::time::Instant,
        std::result::Result<Option<SpendInfo>, SpendCheck>,
    ),
>;

/// How long an agreed `find_spend` is reused while the primary's answer stands: one LTC
/// block time. A reuse window only; no timeout, margin or confirmation count reads it.
const SPEND_RECHECK: std::time::Duration = std::time::Duration::from_secs(TARGET_BLOCK_SECS as u64);

/// Cached lock reads kept before the cache is emptied; far more than the swaps in flight.
const LOCK_CACHE_MAX: usize = 256;

impl std::fmt::Debug for LtcBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LtcBackend")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl LtcBackend {
    /// Keep the inputs of broadcast wallet transactions out of coin selection until they
    /// confirm (see [`InputReservations`]). Without it selection reads the live address
    /// query only, so a lock that dropped out of the mempool can lose its inputs to a second
    /// swap. The handle is the daemon's swap database; tests and one-shot tools omit it.
    pub fn with_input_reservations(mut self, reservations: InputReservations) -> Self {
        self.reservations = Some(reservations);
        self
    }

    /// Opt-in (`[ltc].crosscheck_before_claim`): before every claim is built, compare the
    /// primary's hash at `tip - CROSSCHECK_DEPTH` with `source` at its default mainnet base,
    /// as the startup [`LtcBackend::crosscheck`] does, then its hash at
    /// `tip - CLAIM_NEAR_DEPTH` and its spend of the claimed output. `Disagree` refuses the claim as
    /// [`SwapError::Transient`] (the engine retries); `Unavailable` logs one warning per claim
    /// and builds it anyway. The result is reused until the primary's tip hash changes.
    /// It also cross-checks every lock read (`htlc_output`, EL): the source must show the
    /// agreed script and the primary's value at the outpoint, and the lower confirmation
    /// count is used; a disagreeing or unreadable source is `Transient` (fail closed, since
    /// neither caller has revealed or paid anything yet).
    /// And it cross-checks every `find_spend` (EN): the source's spender, input, scriptSig and
    /// witness must match the primary's, else `Transient`; the fewer confirmations are used; a
    /// source that cannot be read logs a warning and leaves the primary's answer (as today), so
    /// a down explorer never holds the maker's refund or preimage watch. One more request per
    /// read while unspent, two once spent, reused for one LTC block time while the primary's
    /// answer stands.
    /// `None` (the default) is off: no extra request. Mainnet only; the daemon's config
    /// enforces that.
    pub fn with_claim_crosscheck(self, source: Option<CrossCheckSource>) -> Self {
        match source {
            Some(s) => self.with_claim_crosscheck_at(s, s.default_base()),
            None => Self {
                claim_check: None,
                ..self
            },
        }
    }

    /// [`LtcBackend::with_claim_crosscheck`] asking `source` at `base` instead of its default
    /// mainnet API (a self-hosted explorer, or a test mock).
    pub fn with_claim_crosscheck_at(
        mut self,
        source: CrossCheckSource,
        base: impl Into<String>,
    ) -> Self {
        self.claim_check = Some(ClaimCrossCheck {
            source,
            base: base.into(),
            last: parking_lot::Mutex::new(None),
            locks: parking_lot::Mutex::new(HashMap::new()),
            spends: parking_lot::Mutex::new(HashMap::new()),
        });
        self
    }

    /// Stub (EO test commit): no behaviour yet; the fix posts to both endpoints.
    pub fn with_dual_broadcast(self, _on: bool) -> Result<Self> {
        Ok(self)
    }

    /// The claim-time cross-check for a claim of `at`; `Ok` when off.
    async fn check_before_claim(&self, at: &Outpoint) -> Result<()> {
        let Some(cc) = &self.claim_check else {
            return Ok(());
        };
        let source = cc.source.as_str();
        let outcome = match self.tip_hash_raw().await {
            Err(e) => {
                ClaimCheck::Unavailable(format!("{}: tip hash: {e}", self.esplora.primary_url()))
            }
            Ok(tip) => {
                let tip = tip.trim().to_ascii_lowercase();
                let cached = cc
                    .last
                    .lock()
                    .as_ref()
                    .filter(|(t, o, _)| *t == tip && o == at)
                    .map(|(_, _, c)| c.clone());
                match cached {
                    Some(c) => c,
                    None => {
                        // One attempt: a rate-limited source must not hold the claim up in
                        // backoff; the next primary block asks again.
                        let once = RetryPolicy {
                            attempts: 1,
                            ..self.retry
                        };
                        let c =
                            claim_crosscheck(&self.esplora, cc.source, &cc.base, once, at).await;
                        *cc.last.lock() = Some((tip, *at, c.clone()));
                        c
                    }
                }
            }
        };
        match outcome {
            ClaimCheck::Agree => {
                tracing::debug!(source, outpoint = %at, "ltc claim cross-check agrees");
                Ok(())
            }
            ClaimCheck::Unavailable(reason) => {
                // Warn and continue: the claim must not stall past the counterparty's refund
                // timeout because a second explorer is down. One line per claim built
                // unchecked, for audit.
                tracing::warn!(
                    source,
                    source_url = %cc.base,
                    %reason,
                    outpoint = %at,
                    "ltc claim cross-check unavailable; building the claim unchecked"
                );
                Ok(())
            }
            ClaimCheck::Disagree(m) => {
                Err(SwapError::Transient(format!("{m}; claim of {at} held")))
            }
        }
    }

    /// The primary's lock read: the output at `at` if its scriptPubKey is `htlc`'s.
    async fn htlc_output_primary(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
    ) -> Result<Option<LockedOutput>> {
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

    /// With `[ltc].crosscheck_before_claim` on: `mine` (the primary's read of a matching lock)
    /// agreed with the cross-check source's script, value and confirmations at `at`. One
    /// attempt, no backoff; the answer is reused while the primary's is unchanged. Fails
    /// closed: a disagreeing or unreadable source is `Transient`, so the maker does not fund
    /// and the taker does not reveal until both agree.
    async fn agree_lock_with_source(
        &self,
        cc: &ClaimCrossCheck,
        htlc: &HtlcParams,
        at: &Outpoint,
        mine: LockedOutput,
    ) -> Result<LockedOutput> {
        let cached = cc
            .locks
            .lock()
            .get(at)
            .filter(|(p, _)| *p == mine)
            .map(|(_, v)| v.clone());
        let theirs = match cached {
            Some(v) => v,
            None => {
                let once = RetryPolicy {
                    attempts: 1,
                    ..self.retry
                };
                let v = lock_view(cc.source, &cc.base, once, at).await;
                let mut m = cc.locks.lock();
                if m.len() >= LOCK_CACHE_MAX {
                    m.clear();
                }
                m.insert(*at, (mine, v.clone()));
                v
            }
        };
        let txid = at.txid.to_rpc_hex();
        let want = hex::encode(htlc_script_pubkey(htlc).as_bytes());
        let primary_url = format!("{}/tx/{txid}", self.esplora.primary_url());
        let source_url = format!(
            "{}{}",
            cc.base.trim_end_matches('/'),
            cc.source.tx_path(&txid)
        );
        agree_lock(at, &want, mine, &primary_url, &theirs, &source_url)
    }

    /// With `[ltc].crosscheck_before_claim` on: `mine` (the primary's `find_spend`) agreed with
    /// the cross-check source's view of the spend of `at` ([`agree_find_spend`]). One attempt,
    /// no backoff. `Disagree` is `Transient` (the engine reads again); `Unavailable` warns once
    /// per fresh read and returns `mine`, the LTC claim-time rule: failing closed would hold
    /// the maker's refund, which reads `find_spend` first, behind a third-party explorer.
    async fn agree_spend_with_source(
        &self,
        cc: &ClaimCrossCheck,
        at: &Outpoint,
        mine: Option<SpendInfo>,
    ) -> Result<Option<SpendInfo>> {
        let cached = cc
            .spends
            .lock()
            .get(at)
            .filter(|(p, when, _)| *p == mine && when.elapsed() < SPEND_RECHECK)
            .map(|(_, _, v)| v.clone());
        let fresh = cached.is_none();
        let outcome = match cached {
            Some(v) => v,
            None => {
                let once = RetryPolicy {
                    attempts: 1,
                    ..self.retry
                };
                let v = agree_find_spend(
                    self.esplora.primary_url(),
                    cc.source,
                    &cc.base,
                    once,
                    at,
                    &mine,
                )
                .await;
                let mut m = cc.spends.lock();
                if m.len() >= LOCK_CACHE_MAX {
                    m.clear();
                }
                m.insert(*at, (mine.clone(), std::time::Instant::now(), v.clone()));
                v
            }
        };
        let source = cc.source.as_str();
        match outcome {
            Ok(agreed) => Ok(agreed),
            Err(SpendCheck::Disagree(m)) => {
                if fresh {
                    tracing::warn!(source, outpoint = %at, "{m}");
                }
                Err(SwapError::Transient(m))
            }
            Err(SpendCheck::Unavailable(reason)) => {
                if fresh {
                    tracing::warn!(
                        source,
                        source_url = %cc.base,
                        %reason,
                        outpoint = %at,
                        "ltc find_spend cross-check unavailable; using the primary's answer"
                    );
                }
                Ok(mine)
            }
        }
    }

    /// The primary's `find_spend`: outspend then the spender, or a block scan where the
    /// endpoint has no outspend.
    async fn find_spend_primary(
        &self,
        outpoint: &Outpoint,
        from_height: u64,
    ) -> Result<Option<SpendInfo>> {
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

    /// `coins` without those reserved by a broadcast transaction that has not confirmed.
    fn unreserved(&self, coins: Vec<Coin>) -> Result<Vec<Coin>> {
        let Some(res) = &self.reservations else {
            return Ok(coins);
        };
        let held = res.reserved(Chain::Ltc)?;
        Ok(coins
            .into_iter()
            .filter(|c| {
                !held.contains(&Outpoint {
                    txid: Txid(c.outpoint.txid.to_byte_array()),
                    vout: c.outpoint.vout,
                })
            })
            .collect())
    }

    /// Before `tx` is posted: reserve the wallet inputs it spends. Only a transaction whose
    /// inputs are all this key's P2WPKH coins (a lock funding, a plain send) is reserved; a
    /// claim or refund spends an HTLC output, never in the address UTXO list, so it is left
    /// alone and a store fault cannot hold up a refund. An error blocks the broadcast.
    fn reserve_inputs(&self, tx: &SignedTx) -> Result<()> {
        let Some(res) = &self.reservations else {
            return Ok(());
        };
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&tx.raw).map_err(|e| {
                SwapError::Other(format!("cannot read own transaction to reserve: {e}"))
            })?;
        let ours = self.pubkey.to_bytes();
        let own_p2wpkh =
            |i: &bitcoin::TxIn| i.witness.len() == 2 && i.witness.last() == Some(ours.as_slice());
        if parsed.input.is_empty() || !parsed.input.iter().all(own_p2wpkh) {
            return Ok(());
        }
        let inputs: Vec<Outpoint> = parsed
            .input
            .iter()
            .map(|i| Outpoint {
                txid: Txid(i.previous_output.txid.to_byte_array()),
                vout: i.previous_output.vout,
            })
            .collect();
        res.reserve(Chain::Ltc, &tx.txid, &inputs)
    }

    /// The transaction is on chain: its inputs are spent, so the reservation has done its
    /// job. A store fault here is only logged; the next poll releases again.
    fn release_confirmed(&self, txid: &Txid, confs: u32) {
        if confs == 0 {
            return;
        }
        if let Some(res) = &self.reservations {
            if let Err(e) = res.release_tx(Chain::Ltc, txid) {
                tracing::warn!(%txid, error = %e, "could not release confirmed input reservation");
            }
        }
    }

    /// The raw `/blocks/tip/hash` body, shared by `tip_hash` and `median_time_past`.
    async fn tip_hash_raw(&self) -> Result<String> {
        Ok(self.esplora.get("/blocks/tip/hash").await?)
    }

    /// Testnet backend on explicit `endpoints`: Esplora base URLs, primary first. `key` is
    /// resolved by the caller. Other networks: [`LtcBackend::new_on`].
    pub fn new(
        endpoints: Vec<String>,
        key: SecretKey,
        fees: FeePolicy,
        retry: RetryPolicy,
    ) -> Result<Self> {
        Self::new_on("testnet", endpoints, key, fees, retry)
    }

    /// Like [`LtcBackend::new`] for the named `network` (`mainnet`, `testnet`): the network
    /// picks the address HRP (`ltc` vs `tltc`). Not gated here — the daemon and CLI refuse
    /// `mainnet` unless explicitly allowed.
    pub fn new_on(
        network: &str,
        endpoints: Vec<String>,
        key: SecretKey,
        fees: FeePolicy,
        retry: RetryPolicy,
    ) -> Result<Self> {
        let hrp = hrp_for(network)?;
        let secp = Secp256k1::new();
        let pubkey = CompressedPublicKey(key.public_key(&secp));
        let address = encode_segwit_v0(hrp, pubkey.wpubkey_hash().as_byte_array())?;
        Ok(Self {
            esplora: EsploraClient::new(endpoints, retry)?,
            secp,
            key,
            pubkey,
            address,
            hrp,
            fees,
            reservations: None,
            retry,
            claim_check: None,
        })
    }

    /// Default endpoints for `mainnet` or `testnet` (see [`esplora_endpoints`]).
    pub fn for_network(network: &str, key: SecretKey, fees: FeePolicy) -> Result<Self> {
        Self::new_on(
            network,
            esplora_endpoints(network)?,
            key,
            fees,
            RetryPolicy::default(),
        )
    }

    /// The key's P2WPKH address string (`ltc1…` on mainnet, `tltc1…` on testnet) (where funding coins live and spends land).
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Opt-in mainnet tip-hash cross-check of this backend's Esplora against an independent
    /// source (see [`enforce_tip_crosscheck`]): `Disagree` is an error, `Unavailable` warns.
    /// `None` (`off`) makes no request.
    pub async fn crosscheck(&self, source: Option<CrossCheckSource>) -> Result<()> {
        if source.is_some() && self.hrp != LTC_HRP {
            return Err(SwapError::InvalidParams(
                "ltc crosscheck is mainnet-only: no testnet source is verified".into(),
            ));
        }
        enforce(&self.esplora, source, None, RetryPolicy::default()).await
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

    /// This backend's own UTXOs, from the Esplora address endpoint, less those reserved.
    async fn my_utxos(&self) -> Result<Vec<Coin>> {
        let utxos = self
            .get_json(&format!("/address/{}/utxo", self.address))
            .await?;
        let coins: Vec<Coin> = utxos
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
            .collect::<Result<_>>()?;
        self.unreserved(coins)
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
        let (hrp, program) = decode_segwit_v0(to)?;
        if hrp != self.hrp {
            return Err(SwapError::InvalidParams(format!(
                "destination HRP {hrp:?} does not match this backend's network ({:?})",
                self.hrp
            )));
        }
        let to_program: [u8; 20] = program.try_into().map_err(|p: Vec<u8>| {
            SwapError::InvalidParams(format!(
                "destination is not a P2WPKH (20-byte) address: {} bytes",
                p.len()
            ))
        })?;
        let coins = self.my_utxos().await?;
        let tx = build_send_tx(
            &self.secp,
            &self.key,
            &coins,
            to_program,
            sats,
            self.sat_per_vb().await,
        )?;
        Ok(Self::to_signed(&tx))
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

#[async_trait]
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

    async fn tip_hash(&self) -> Result<String> {
        divi_swap::backend::normalize_block_hash(&self.tip_hash_raw().await?)
    }

    /// Esplora `GET /blocks/tip/hash` ("the hash of the last block"), then `GET /block/:hash`
    /// for that block's `height`, `timestamp` and `id` (Blockstream esplora `API.md`). Height
    /// and time come from the one block whose hash was read, so a tip that moves between
    /// the two requests cannot mix two blocks; a block whose `id` is not the hash asked for
    /// is a transient error.
    async fn tip_header(&self) -> Result<divi_swap::backend::TipHeader> {
        let hash = divi_swap::backend::normalize_block_hash(&self.tip_hash_raw().await?)?;
        let block = self.get_json(&format!("/block/{hash}")).await?;
        let id = block["id"]
            .as_str()
            .ok_or_else(|| SwapError::Transient("block JSON lacks id (still indexing?)".into()))
            .and_then(divi_swap::backend::normalize_block_hash)?;
        if id != hash {
            return Err(SwapError::Transient(format!(
                "asked for block {hash}, got {id}"
            )));
        }
        let field = |name: &str| {
            block[name].as_u64().ok_or_else(|| {
                SwapError::Transient(format!("block JSON lacks {name} (still indexing?)"))
            })
        };
        Ok(divi_swap::backend::TipHeader {
            height: field("height")?,
            hash,
            time: field("timestamp")? as u32,
        })
    }

    /// Esplora `GET /block/:hash/status`: `in_best_chain` is "false for orphaned blocks"
    /// (Blockstream esplora `API.md`). A status whose `height` is not `height` is a transient
    /// error, as is one without `in_best_chain`. Esplora may also answer `false` (or 404, an
    /// error here) for a hash it never saw; the expiry sweep only asks about a block at or
    /// below a tip it has already accepted from this chain.
    async fn in_best_chain(&self, height: u64, hash: &str) -> Result<bool> {
        let hash = divi_swap::backend::normalize_block_hash(hash)?;
        let status = self.get_json(&format!("/block/{hash}/status")).await?;
        let best = status["in_best_chain"]
            .as_bool()
            .ok_or_else(|| SwapError::Transient("block status JSON lacks in_best_chain".into()))?;
        if best && status["height"].as_u64() != Some(height) {
            return Err(SwapError::Transient(format!(
                "block {hash} is in the best chain at {}, not {height}",
                status["height"]
            )));
        }
        Ok(best)
    }

    fn target_block_secs(&self) -> Option<u32> {
        Some(TARGET_BLOCK_SECS)
    }

    async fn median_time_past(&self) -> Result<u32> {
        let hash = self.tip_hash_raw().await?;
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

    async fn spendable(&self) -> Result<Option<Amount>> {
        Ok(Some(Amount(
            self.my_utxos().await?.iter().map(|c| c.value).sum(),
        )))
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        let coins = self.my_utxos().await?;
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
        self.check_before_claim(at).await?;
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

    /// Litecoin Core does not relay replacements by default (`DEFAULT_ENABLE_REPLACEMENT`
    /// is false, `src/validation.h:80`), but its miner selects by ancestor package
    /// (`addPackageTxs`, `src/miner.cpp:351`), so a child paying for the claim works.
    fn fee_bump(&self) -> FeeBump {
        FeeBump::Cpfp
    }

    async fn claim_feerate(&self) -> Result<Option<u64>> {
        Ok(Some(self.sat_per_vb().await))
    }

    fn claim_sizes(&self, htlc: &HtlcParams) -> Option<ClaimSizes> {
        Some(ClaimSizes {
            claim_vsize: claim_vsize(htlc),
            child_vsize: cpfp_child_vsize(),
            dust: DUST_SATS,
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
        self.check_before_claim(at).await?;
        let tx = build_spend_tx(
            &self.secp,
            &self.key,
            htlc,
            ltc_outpoint(at),
            amount.to_sat(),
            Spend::Claim(preimage),
            feerate.max(1),
        )?;
        Ok(Self::to_signed(&tx))
    }

    async fn build_cpfp(
        &self,
        package: &[SignedTx],
        htlc_amount: Amount,
        feerate: u64,
    ) -> Result<SignedTx> {
        let txs = package
            .iter()
            .map(|t| bitcoin::consensus::deserialize::<bitcoin::Transaction>(&t.raw))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| SwapError::Other(format!("cannot read own claim package: {e}")))?;
        let last = txs
            .last()
            .ok_or_else(|| SwapError::InvalidParams("empty CPFP package".into()))?;
        let parent_value = last
            .output
            .first()
            .ok_or_else(|| SwapError::InvalidParams("CPFP parent has no output".into()))?
            .value
            .to_sat();
        let package_vsize = txs.iter().map(|t| t.vsize() as u64).sum();
        let package_fee = htlc_amount.to_sat().saturating_sub(parent_value);
        let tx = build_cpfp_tx(
            &self.secp,
            &self.key,
            last,
            parent_value,
            package_vsize,
            package_fee,
            feerate,
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
        self.reserve_inputs(tx)?;
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
        let confs = Self::confs_from_status(&status, tip);
        self.release_confirmed(txid, confs);
        Ok(Some(confs))
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        let mine = self.htlc_output_primary(htlc, at).await?;
        match (&self.claim_check, mine) {
            // Nothing to agree when the primary shows no matching lock: no side acts on `None`.
            (Some(cc), Some(lo)) => self
                .agree_lock_with_source(cc, htlc, at, lo)
                .await
                .map(Some),
            (_, mine) => Ok(mine),
        }
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        let mine = self.find_spend_primary(outpoint, from_height).await?;
        match &self.claim_check {
            Some(cc) => self.agree_spend_with_source(cc, outpoint, mine).await,
            None => Ok(mine),
        }
    }
}

#[cfg(test)]
mod tests;
