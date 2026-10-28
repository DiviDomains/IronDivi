// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Zcash testnet transparent-HTLC `ChainBackend` for the DIVI swap engine.
//!
//! Wired onto `lightwalletd`'s `CompactTxStreamer` gRPC service ([`grpc`]) — step 0's chosen
//! primary API (see `- decisions:` in `docs/plans/swap-poc/status/zec.md`). Transaction
//! building, the ZIP-244 signature digest and script self-verification live in [`tx`];
//! t-address encoding lives in [`address`].

pub mod address;
pub mod crosscheck;
pub mod grpc;
pub mod tx;

#[cfg(test)]
mod lock_terms;
#[cfg(test)]
mod lwd_stub;
#[cfg(test)]
mod txid_binding;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use secp256k1::{All, Secp256k1, SecretKey};

use divi_swap::backend::TipHeader;
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, InputReservations, LockedOutput, Outpoint,
    SignedTx, SpendInfo, SwapError, Txid,
};

use address::TransparentAddress;
use grpc::{BlockId, ClientError, CompactBlock, LightwalletdClient};

pub use crosscheck::{CrossCheckOutcome, CROSSCHECK_DEPTH};
pub use grpc::RetryPolicy;

type Result<T> = std::result::Result<T, SwapError>;

/// The only public testnet lightwalletd endpoint confirmed reachable from hp2 as of step 0
/// (TLS + ALPN h2 handshake succeeds; used by default by Zecwallet-lite's testnet preset).
///
/// No second working plain-HTTPS endpoint has been found despite a real search (see
/// `- decisions:` in `docs/plans/swap-poc/status/zec.md` for the evidence): every other
/// candidate tried either doesn't resolve, fails TLS, or 521s at its origin, and the one
/// actively-maintained project that curates a real multi-operator Zcash testnet server list
/// (`logos-co/logos-zcash-node-module`) itself only has one non-Tor testnet entry — its
/// second operator is Tor-onion-only, which this crate doesn't attempt (a new system
/// dependency, out of scope here). [`lightwalletd_endpoints`] is still written to take a
/// list, not a single URL, and [`LIGHTWALLETD_EXTRA_ENV`] lets a second endpoint be wired in
/// the moment one turns up, without a code change.
pub const TESTNET_LIGHTWALLETD: &str = "https://testnet.zec.rocks:443";

/// Env var (comma-separated `https://host:port` entries) appended, in order, after the
/// built-in default(s) in [`lightwalletd_endpoints`] — the configurable half of the fallback
/// list this crate can't yet populate with a second known-good public endpoint itself.
pub const LIGHTWALLETD_EXTRA_ENV: &str = "SWAP_ZEC_LIGHTWALLETD_EXTRA";

/// Public mainnet lightwalletd endpoints, primary first. Each answered a TLS handshake that
/// negotiated ALPN `h2` with a verified certificate on 2026-10-21 (`openssl s_client -alpn h2`
/// from hp2); `lwd1.zcash-infra.com:9067`, `mainnet.lightwalletd.com:9067` and
/// `lightwalletd.electriccoin.co:9067` gave no handshake and are deliberately left out. See
/// `- decisions:` in `docs/plans/swap-poc/status/zec.md`. Reachability is not a statement
/// about operator trust: all three are one operator's, so a mainnet daemon compares their tip
/// with a second operator's lightwalletd ([`crosscheck`], `[zec].crosscheck_url`).
pub const MAINNET_LIGHTWALLETD: [&str; 3] = [
    "https://zec.rocks:443",
    "https://na.zec.rocks:443",
    "https://eu.zec.rocks:443",
];

/// Built-in lightwalletd endpoints (primary first) for a network name: `mainnet`
/// ([`MAINNET_LIGHTWALLETD`]) or `testnet` (only [`TESTNET_LIGHTWALLETD`] — see its docs for
/// why there's no second entry).
fn default_endpoints(network: &str) -> Result<Vec<String>> {
    match network {
        "mainnet" => Ok(MAINNET_LIGHTWALLETD.iter().map(|s| s.to_string()).collect()),
        "testnet" => Ok(vec![TESTNET_LIGHTWALLETD.to_string()]),
        other => Err(SwapError::InvalidParams(format!(
            "zec network {other:?} unsupported: mainnet, testnet"
        ))),
    }
}

/// Appends endpoints parsed from a comma-separated list (as read from
/// [`LIGHTWALLETD_EXTRA_ENV`]) after `endpoints`, in order — pure, no env access, so it's
/// testable without mutating process-global state. Blank/whitespace-only entries (a trailing
/// comma, an unset-but-present env var) are dropped rather than becoming a bogus endpoint
/// that only fails at call time.
fn with_extra_endpoints(mut endpoints: Vec<String>, extra: Option<&str>) -> Vec<String> {
    if let Some(extra) = extra {
        endpoints.extend(
            extra
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from),
        );
    }
    endpoints
}

/// Default lightwalletd endpoints (primary first) for a network name — [`default_endpoints`]
/// plus whatever [`LIGHTWALLETD_EXTRA_ENV`] adds, mirroring the btc/ltc lanes'
/// `esplora_endpoints(network)` shape (same ordered-list-of-fallback-URLs convention the
/// `ChainBackend`s' shared `grpc`/`client` retry-then-fall-back-to-next-endpoint logic — see
/// [`grpc::retry_fallback`] — is built around).
pub fn lightwalletd_endpoints(network: &str) -> Result<Vec<String>> {
    let extra = std::env::var(LIGHTWALLETD_EXTRA_ENV).ok();
    Ok(with_extra_endpoints(
        default_endpoints(network)?,
        extra.as_deref(),
    ))
}

/// Blocks scanned per `find_spend` call (mirrors the BTC lane's `MAX_SCAN_BLOCKS`): we have
/// no "find the spend of this outpoint" index on this API, only block scanning.
const MAX_SCAN_BLOCKS: u64 = 200;

/// Zcash's target block spacing in seconds since Blossom (ZIP 208), on mainnet and
/// testnet: zcashd's `POST_BLOSSOM_POW_TARGET_SPACING = 75` in `src/consensus/params.h`.
pub const TARGET_BLOCK_SECS: u32 = 75;

/// How the zat/byte rate is chosen.
#[derive(Debug, Clone, Copy)]
pub enum FeePolicy {
    /// Always this rate.
    Fixed(u64),
}

impl Default for FeePolicy {
    fn default() -> Self {
        FeePolicy::Fixed(2)
    }
}

impl FeePolicy {
    fn zats_per_byte(&self) -> u64 {
        match self {
            FeePolicy::Fixed(r) => (*r).max(1),
        }
    }
}

/// The most agreed locks one backend keeps (FB): past it the oldest is dropped.
pub(crate) const LOCK_CACHE_CAP: usize = 64;

/// Zcash testnet transparent [`ChainBackend`].
pub struct ZecBackend {
    client: LightwalletdClient,
    secp: Secp256k1<All>,
    key: SecretKey,
    pubkey: [u8; 33],
    address: TransparentAddress,
    fees: FeePolicy,
    reservations: Option<InputReservations>,
    /// `"mainnet"` or `"testnet"`: selects address prefixes and the v5/v6 activation height.
    network: String,
    /// The second lightwalletd operator ([`ZecBackend::with_crosscheck`]); `None` is off.
    second: Option<LightwalletdClient>,
    /// The longest one lock read from the second operator may take
    /// ([`crosscheck::LOCK_READ_BUDGET`]; tests shorten it).
    second_budget: Duration,
    /// Since when the second operator has refused each lock it has not agreed yet (EX), for
    /// the refusal's "failing for". In memory only; an agreement clears the entry.
    lock_failing: Mutex<HashMap<Outpoint, Instant>>,
    /// Shared with this backend's [`ChainBackend::primary_only`] views.
    hold: Arc<HoldState>,
}

/// What a cross-checked backend and its primary-only views share.
#[derive(Debug, Default)]
struct HoldState {
    /// The second operator, kept by the primary-only views too: a spend they build after a
    /// `Disagree` is also sent to it (best effort; the primary may be the liar).
    relay_to: Option<LightwalletdClient>,
    /// The last spend cross-check disagreed (not merely unavailable).
    disagreed: AtomicBool,
    /// Spends built on the primary alone after a `Disagree`: every broadcast of them also
    /// goes to `relay_to`. In memory only; after a restart the primary alone resends them.
    relay: Mutex<HashSet<Txid>>,
}

impl std::fmt::Debug for ZecBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZecBackend")
            .field("address", &self.encoded_address())
            .finish_non_exhaustive()
    }
}

impl ZecBackend {
    /// `endpoints`: lightwalletd gRPC base URIs (`https://host:port`), primary first.
    pub fn new(
        endpoints: Vec<String>,
        key: SecretKey,
        fees: FeePolicy,
        retry: RetryPolicy,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let pubkey = key.public_key(&secp).serialize();
        let address = TransparentAddress::p2pkh(&pubkey);
        Ok(Self {
            client: LightwalletdClient::new(endpoints, retry)?,
            secp,
            key,
            pubkey,
            address,
            fees,
            reservations: None,
            network: "testnet".to_string(),
            second: None,
            second_budget: crosscheck::LOCK_READ_BUDGET,
            lock_failing: Mutex::default(),
            hold: Arc::default(),
        })
    }

    /// Keep the inputs of broadcast wallet transactions out of coin selection until they
    /// confirm (see [`InputReservations`]). Without it selection reads `GetAddressUtxos`
    /// only, so a lock that dropped out of the mempool can lose its inputs to a second swap.
    /// The handle is the daemon's swap database; tests and one-shot tools omit it.
    pub fn with_input_reservations(mut self, reservations: InputReservations) -> Self {
        self.reservations = Some(reservations);
        self
    }

    /// Opt-in (`[zec].crosscheck_url`): a lightwalletd run by a second operator, asked at
    /// startup ([`ZecBackend::crosscheck`]), before every claim and refund is built, and for
    /// the lock output at every `htlc_output` (see [`crosscheck`]). `None` (the default) is
    /// off: no extra request. The URL is checked by
    /// the caller against the primaries ([`crosscheck::check_second_operator`]).
    pub fn with_crosscheck(mut self, url: Option<String>) -> Result<Self> {
        self.second = match url {
            Some(url) => Some(LightwalletdClient::new(vec![url], self.client.retry())?),
            None => None,
        };
        self.hold = Arc::new(HoldState {
            relay_to: self.second.clone(),
            ..HoldState::default()
        });
        Ok(self)
    }

    /// Bound each lock read from the second operator by `budget` instead of
    /// [`crosscheck::LOCK_READ_BUDGET`] (tests).
    #[cfg(test)]
    pub(crate) fn with_second_budget(mut self, budget: Duration) -> Self {
        self.second_budget = budget;
        self
    }

    /// How many agreed locks this backend keeps (FB; tests).
    #[cfg(test)]
    pub(crate) fn agreed_locks(&self) -> usize {
        0
    }

    /// The startup cross-check: `Disagree` is an error, `Unavailable` warns; `Ok` when off.
    pub async fn crosscheck(&self) -> Result<()> {
        match &self.second {
            Some(second) => crosscheck::enforce_at_startup(&self.client, second).await,
            None => Ok(()),
        }
    }

    /// Before a claim or refund (`what`) of `at` is built: hold it on anything but
    /// agreement ([`crosscheck::spend_hold`], [`SwapError::Held`]); `Ok` when off and in a
    /// primary-only view.
    async fn check_before_spend(&self, what: &str, at: &Outpoint) -> Result<()> {
        let Some(second) = &self.second else {
            return Ok(());
        };
        let hold = crosscheck::spend_hold(&self.client, second, what, at).await;
        self.hold
            .disagreed
            .store(hold.as_ref().is_some_and(|h| h.disagree), Ordering::SeqCst);
        match hold {
            None => Ok(()),
            Some(h) => Err(h.error),
        }
    }

    /// A lock refusal by [`crosscheck::agree_lock`], completed with how long the second
    /// operator has been failing this lock (since its first refusal in this process; EX).
    /// The engine retries it until its own deadline for the step.
    fn failing_for(&self, at: &Outpoint, agreed: Result<LockedOutput>) -> Result<LockedOutput> {
        let mut failing = self.lock_failing.lock().expect("lock_failing map");
        match agreed {
            Ok(lo) => {
                failing.remove(at);
                Ok(lo)
            }
            Err(SwapError::Transient(m)) => {
                let since = *failing.entry(*at).or_insert_with(Instant::now);
                Err(SwapError::Transient(format!(
                    "{m}; the second operator has been failing this lock for {} s",
                    since.elapsed().as_secs()
                )))
            }
            Err(e) => Err(e),
        }
    }

    /// The primary's lock read: the output at `at` if its scriptPubKey is `htlc`'s, with its
    /// value and confirmations ([`ChainBackend::htlc_output`] adds the second operator).
    async fn htlc_output_primary(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
    ) -> Result<Option<LockedOutput>> {
        let Some(raw) = self
            .client
            .get_transaction(&at.txid.0)
            .await
            .map_err(SwapError::from)?
        else {
            return Ok(None);
        };
        let parsed = tx::ParsedTx::parse(&raw.data)?;
        self.requested(&parsed, &at.txid.0)?;
        let Some(out) = parsed.vout.get(at.vout as usize) else {
            return Ok(None);
        };
        let want = address::htlc_script_pubkey(&htlc.redeem_script());
        if out.script_pubkey != want {
            return Ok(None);
        }
        let confirmations = if raw.height == 0 || raw.height == u64::MAX {
            0
        } else {
            let tip = self.tip_height().await?;
            (tip.saturating_sub(raw.height) + 1) as u32
        };
        Ok(Some(LockedOutput {
            amount: Amount::from_sat(out.value),
            confirmations,
        }))
    }

    /// `Ok` when `parsed`, the primary's answer to `GetTransaction(want)`, is that transaction;
    /// else [`SwapError::Transient`] naming the primary endpoints ([`not_requested`]).
    fn requested(&self, parsed: &tx::ParsedTx, want: &[u8; 32]) -> Result<()> {
        match not_requested(parsed, want) {
            None => Ok(()),
            Some(why) => Err(self.refuse_answer(&why)),
        }
    }

    /// The refusal of an answer of the primary's: `why` completes "zec lightwalletd <urls> …".
    fn refuse_answer(&self, why: &str) -> SwapError {
        SwapError::Transient(format!(
            "zec lightwalletd {} {why}; not acting on it",
            self.client.endpoints().join(", ")
        ))
    }

    /// A spend this backend built: in a primary-only view after a `Disagree`, also sent to
    /// the second operator from now on.
    fn built_spend(&self, tx: SignedTx) -> SignedTx {
        if self.second.is_none()
            && self.hold.relay_to.is_some()
            && self.hold.disagreed.load(Ordering::SeqCst)
        {
            self.hold.relay.lock().expect("relay set").insert(tx.txid);
        }
        tx
    }

    /// Best effort: send `tx` to the second operator if it was built on the primary alone
    /// after a `Disagree`. A failure is only logged; the primary's answer stands.
    async fn relay(&self, tx: &SignedTx) {
        let Some(second) = &self.hold.relay_to else {
            return;
        };
        if !self
            .hold
            .relay
            .lock()
            .expect("relay set")
            .contains(&tx.txid)
        {
            return;
        }
        match second.send_transaction(&tx.raw).await {
            Ok(resp) if resp.error_code == 0 || is_already_known(&resp.error_message) => {
                tracing::warn!(txid = %tx.txid, second_operator = %second.endpoints().join(", "),
                    "zec spend built on the primary alone also sent to the second operator");
            }
            Ok(resp) => tracing::warn!(txid = %tx.txid,
                second_operator = %second.endpoints().join(", "),
                error = %resp.error_message, "second operator refused the zec spend"),
            Err(e) => tracing::warn!(txid = %tx.txid,
                second_operator = %second.endpoints().join(", "),
                error = ?e, "zec spend not sent to the second operator"),
        }
    }

    /// Send to the primary endpoints (failover order), reserving a funding's inputs first.
    async fn broadcast_primary(&self, signed_tx: &SignedTx) -> Result<Txid> {
        self.reserve_inputs(signed_tx)?;
        match self.client.send_transaction(&signed_tx.raw).await {
            Ok(resp) if resp.error_code == 0 => Ok(signed_tx.txid),
            Ok(resp) => {
                if is_already_known(&resp.error_message) {
                    return Ok(signed_tx.txid);
                }
                Err(classify_broadcast_error(&resp.error_message))
            }
            Err(ClientError::Rejected(m)) => {
                if is_already_known(&m) {
                    return Ok(signed_tx.txid);
                }
                Err(classify_broadcast_error(&m))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// `coins` without those reserved by a broadcast transaction that has not confirmed.
    fn unreserved(&self, coins: Vec<tx::Coin>) -> Result<Vec<tx::Coin>> {
        let Some(res) = &self.reservations else {
            return Ok(coins);
        };
        let held = res.reserved(Chain::Zec)?;
        Ok(coins
            .into_iter()
            .filter(|c| {
                !held.contains(&Outpoint {
                    txid: Txid(c.outpoint.txid),
                    vout: c.outpoint.n,
                })
            })
            .collect())
    }

    /// Before `signed_tx` is sent: reserve the wallet inputs it spends. Only a transaction
    /// whose inputs are all this key's P2PKH coins (a lock funding) is reserved; a claim or
    /// refund spends an HTLC output, never in the address UTXO list, so it is left alone and
    /// a store fault cannot hold up a refund. An error blocks the broadcast.
    fn reserve_inputs(&self, signed_tx: &SignedTx) -> Result<()> {
        let Some(res) = &self.reservations else {
            return Ok(());
        };
        let parsed = tx::ParsedTx::parse(&signed_tx.raw)?;
        // P2PKH scriptSig: <sig> <33-byte pubkey>. An HTLC spend ends in its redeem script.
        let own_p2pkh = |i: &tx::TxIn| {
            let s = &i.script_sig;
            s.len() > 34 && s[s.len() - 34] == 0x21 && s[s.len() - 33..] == self.pubkey
        };
        if parsed.vin.is_empty() || !parsed.vin.iter().all(own_p2pkh) {
            return Ok(());
        }
        let inputs: Vec<Outpoint> = parsed
            .vin
            .iter()
            .map(|i| Outpoint {
                txid: Txid(i.prevout.txid),
                vout: i.prevout.n,
            })
            .collect();
        res.reserve(Chain::Zec, &signed_tx.txid, &inputs)
    }

    /// The transaction is on chain: its inputs are spent, so the reservation has done its
    /// job. A store fault here is only logged; the next poll releases again.
    fn release_confirmed(&self, txid: &Txid, confs: u32) {
        if confs == 0 {
            return;
        }
        if let Some(res) = &self.reservations {
            if let Err(e) = res.release_tx(Chain::Zec, txid) {
                tracing::warn!(%txid, error = %e, "could not release confirmed input reservation");
            }
        }
    }

    /// Select the network (`"mainnet"` / `"testnet"`) this backend addresses and builds for.
    /// [`Self::new`] defaults to testnet; [`Self::for_network`] calls this.
    pub fn with_network(mut self, network: &str) -> Result<Self> {
        address::prefixes_for(network)?;
        self.network = network.to_string();
        Ok(self)
    }

    /// Base58Check address for this backend's network (`t1…` mainnet, `tm…` testnet).
    pub fn encoded_address(&self) -> String {
        self.address
            .encode_for(&self.network)
            .expect("network validated by with_network")
    }

    /// Default endpoints for `network` (see [`lightwalletd_endpoints`]): `"mainnet"` or
    /// `"testnet"`.
    pub fn for_network(network: &str, key: SecretKey, fees: FeePolicy) -> Result<Self> {
        Self::new(
            lightwalletd_endpoints(network)?,
            key,
            fees,
            RetryPolicy::default(),
        )?
        .with_network(network)
    }

    /// [`TESTNET_LIGHTWALLETD`] (plus any [`LIGHTWALLETD_EXTRA_ENV`] fallback), the step-0
    /// default.
    pub fn testnet(key: SecretKey, fees: FeePolicy) -> Result<Self> {
        Self::for_network("testnet", key, fees)
    }

    /// The key's P2PKH address (`tm…` on testnet, `t1…` on mainnet; encode with
    /// [`TransparentAddress::encode_for`]) (where funding coins live and spends land).
    pub fn address(&self) -> &TransparentAddress {
        &self.address
    }

    /// This key's coins from `GetAddressUtxos`, less those [`Self::unreserved`] holds back:
    /// what funding selects from.
    async fn my_coins(&self) -> Result<Vec<tx::Coin>> {
        let utxos = self
            .client
            .address_utxos(&self.encoded_address())
            .await
            .map_err(SwapError::from)?;
        let coins = utxos
            .into_iter()
            .map(|u| {
                Ok(tx::Coin {
                    outpoint: tx::OutPoint {
                        txid: Self::txid32(&u.txid, "GetAddressUtxosReply.txid")?,
                        n: u.index as u32,
                    },
                    value: u.value_zat as u64,
                    script_pubkey: u.script,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.unreserved(coins)
    }

    /// Confirmed balance (sum of `GetAddressUtxos`) in zatoshi.
    pub async fn balance_zatoshi(&self) -> Result<u64> {
        let utxos = self
            .client
            .address_utxos(&self.encoded_address())
            .await
            .map_err(SwapError::from)?;
        Ok(utxos.iter().map(|u| u.value_zat as u64).sum())
    }

    /// Read fresh from `GetLightdInfo` every call — never hard-coded, per the brief (a
    /// network upgrade changes it without warning).
    async fn consensus_branch_id(&self) -> Result<u32> {
        let info = self.client.lightd_info().await.map_err(SwapError::from)?;
        u32::from_str_radix(info.consensus_branch_id.trim(), 16).map_err(|e| {
            SwapError::Other(format!(
                "bad consensusBranchId {:?}: {e}",
                info.consensus_branch_id
            ))
        })
    }

    /// v5 or v6 for the next block, by NU6.3 activation height ([`tx::tx_version_for`]).
    async fn tx_version(&self) -> Result<u32> {
        let next = self.tip_height().await? + 1;
        let next = u32::try_from(next)
            .map_err(|_| SwapError::Other(format!("tip height {next} overflows u32")))?;
        tx::tx_version_for(&self.network, next)
    }

    fn to_signed(built: &tx::ZecTx) -> SignedTx {
        SignedTx {
            txid: Txid(built.txid()),
            raw: built.serialize(),
        }
    }

    fn txid32(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
        <[u8; 32]>::try_from(bytes)
            .map_err(|_| SwapError::Other(format!("{what} is {} bytes, want 32", bytes.len())))
    }
}

/// `Some(why)` when `parsed`, a lightwalletd's answer to `GetTransaction(want)`, is another
/// transaction: its txid ([`tx::ParsedTx::txid`], ZIP-244 for v5, ZIP-229 for v6) is not
/// `want` (both in internal byte order, as `get_transaction` takes it). Every read by txid
/// checks this before it uses any field of the answer (EW): without it an operator could
/// answer any transaction whose output at the index carries the agreed script and value.
/// `why` completes "<operator> …".
pub(crate) fn not_requested(parsed: &tx::ParsedTx, want: &[u8; 32]) -> Option<String> {
    let got = parsed.txid();
    (got != *want).then(|| {
        format!(
            "answered GetTransaction({}) with transaction {}, not the one asked for",
            Txid(*want),
            Txid(got)
        )
    })
}

/// Map a lightwalletd/zcashd reject reason to the engine's taxonomy (zcashd shares its
/// script/mempool rejection wording with DIVI and Bitcoin Core).
fn classify_broadcast_error(message: &str) -> SwapError {
    let m = message.to_ascii_lowercase();
    if m.contains("non-final")
        || m.contains("locktime requirement not satisfied")
        || m.contains("non-mandatory-script-verify-flag (locktime")
        // Zebra's own wording (not zcashd's) for a refund whose nLockTime hasn't matured
        // yet: `TransactionError::LockedUntilAfterBlockHeight`/`...BlockTime` in
        // zebra-consensus/src/error.rs are both "transaction is locked until after block
        // height/time {..}" — our htlc locktimes are always the time variant (values well
        // above ZIP-203's 500,000,000 height/time threshold), but matching the shared
        // "locked until after block" stem covers both just in case.
        || m.contains("locked until after block")
    {
        SwapError::Premature(message.trim().to_string())
    } else {
        SwapError::Rejected(message.trim().to_string())
    }
}

/// Whether a reject reason means "the chain already has this exact transaction" — i.e. a
/// rebroadcast of a tx `broadcast()` itself already sent is not a failure. There's nothing
/// to cross-check the error against a different txid with (unlike e.g. an EVM nonce
/// collision): we only ever submit the one `signed_tx.raw` we just built, so a node telling
/// us it already has "the transaction" can only mean that same tx.
fn is_already_known(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("already in block chain")
        || m.contains("already in the block chain")
        || m.contains("txn-already-in-mempool")
        || m.contains("txn-already-known")
        || m.contains("outputs already in utxo set")
        // Zebra's wording (not zcashd's) for a tx it already holds in its mempool or has
        // mined: a live happy-forward run's taker rebroadcast its own already-mined ZEC
        // lock and got "already exists in mempool" back, which the CLI treated as fatal
        // before this fix; "committed to the best chain" is the equivalent once it's mined.
        || m.contains("already exists in mempool")
        || m.contains("transaction was committed to the best chain")
        // Zebra's mempool `InState` error: the tx (matched by its id) is already mined. Seen
        // live when a case-C forward taker rebroadcast its confirmed ZEC lock.
        || m.contains("transaction is already in state")
}

/// The median of a set of block times (`median_time_past`'s definition). An empty input
/// means `block_range` answered with nothing for heights up to a tip we were just given —
/// `tip_height` and `block_range` can land on different lightwalletd backends, so that is
/// "this one hasn't indexed that far yet," not "the chain truly has no blocks."
fn median_of_block_times(times: impl Iterator<Item = u32>) -> Result<u32> {
    let mut times: Vec<u32> = times.collect();
    if times.is_empty() {
        return Err(SwapError::Transient(
            "lightwalletd returned no blocks for median-time-past (tip not indexed yet?)".into(),
        ));
    }
    times.sort_unstable();
    Ok(times[times.len() / 2])
}

/// If `block` has a `CompactTx` spending `want_txid:want_vout`, (spender txid, input index).
fn spend_in_block(
    block: &CompactBlock,
    want_txid: &[u8; 32],
    want_vout: u32,
) -> Option<([u8; 32], u32)> {
    for t in &block.vtx {
        for (i, vin) in t.vin.iter().enumerate() {
            if vin.prevout_txid == want_txid && vin.prevout_index == want_vout {
                let txid = ZecBackend::txid32(&t.txid, "CompactTx.txid").ok()?;
                return Some((txid, i as u32));
            }
        }
    }
    None
}

#[allow(clippy::double_must_use)]
#[async_trait]
impl ChainBackend for ZecBackend {
    fn chain(&self) -> Chain {
        Chain::Zec
    }

    fn pubkey(&self) -> [u8; 33] {
        self.pubkey
    }

    async fn tip_height(&self) -> Result<u64> {
        Ok(self
            .client
            .latest_block()
            .await
            .map_err(SwapError::from)?
            .height)
    }

    async fn tip_hash(&self) -> Result<String> {
        let tip = self.client.latest_block().await.map_err(SwapError::from)?;
        display_block_hash(&tip.hash)
    }

    /// lightwalletd `GetLatestBlock` (the tip's height and hash), then `GetBlock` at that
    /// height for its time ([`tip_header_from`]). `GetBlock` takes a height only.
    async fn tip_header(&self) -> Result<TipHeader> {
        let latest = self.client.latest_block().await.map_err(SwapError::from)?;
        let block = self
            .client
            .block(latest.height)
            .await
            .map_err(SwapError::from)?;
        tip_header_from(&latest, &block)
    }

    /// lightwalletd `GetBlock` at `height`: `hash` is on the main chain of the endpoint
    /// that answered iff that block's hash is `hash`. A block without a hash is an error,
    /// never "not on the main chain".
    async fn in_best_chain(&self, height: u64, hash: &str) -> Result<bool> {
        let block = self.client.block(height).await.map_err(SwapError::from)?;
        if block.height != height {
            return Err(SwapError::Transient(format!(
                "lightwalletd GetBlock({height}) answered block {}",
                block.height
            )));
        }
        Ok(display_block_hash(&block.hash)? == hash.trim().to_ascii_lowercase())
    }

    fn target_block_secs(&self) -> Option<u32> {
        Some(TARGET_BLOCK_SECS)
    }

    async fn median_time_past(&self) -> Result<u32> {
        let tip = self.tip_height().await?;
        let start = tip.saturating_sub(10);
        let blocks = self
            .client
            .block_range(start, tip)
            .await
            .map_err(SwapError::from)?;
        median_of_block_times(blocks.iter().map(|b| b.time))
    }

    async fn spendable(&self) -> Result<Option<Amount>> {
        Ok(Some(Amount(
            self.my_coins().await?.iter().map(|c| c.value).sum(),
        )))
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        let branch_id = self.consensus_branch_id().await?;
        let version = self.tx_version().await?;
        let coins = self.my_coins().await?;
        let built = tx::build_funding_tx(
            &self.secp,
            &self.key,
            &self.pubkey,
            &coins,
            htlc,
            amount.to_sat(),
            version,
            branch_id,
            self.fees.zats_per_byte(),
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
        self.check_before_spend("claim", at).await?;
        let branch_id = self.consensus_branch_id().await?;
        let version = self.tx_version().await?;
        let outpoint = tx::OutPoint {
            txid: at.txid.0,
            n: at.vout,
        };
        let built = tx::build_spend_tx(
            &self.secp,
            &self.key,
            &self.pubkey,
            htlc,
            outpoint,
            amount.to_sat(),
            tx::Spend::Claim(preimage),
            version,
            branch_id,
            self.fees.zats_per_byte(),
        )?;
        Ok(self.built_spend(Self::to_signed(&built)))
    }

    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        self.check_before_spend("refund", at).await?;
        let branch_id = self.consensus_branch_id().await?;
        let version = self.tx_version().await?;
        let outpoint = tx::OutPoint {
            txid: at.txid.0,
            n: at.vout,
        };
        let built = tx::build_spend_tx(
            &self.secp,
            &self.key,
            &self.pubkey,
            htlc,
            outpoint,
            amount.to_sat(),
            tx::Spend::Refund,
            version,
            branch_id,
            self.fees.zats_per_byte(),
        )?;
        Ok(self.built_spend(Self::to_signed(&built)))
    }

    async fn broadcast(&self, signed_tx: &SignedTx) -> Result<Txid> {
        let sent = self.broadcast_primary(signed_tx).await;
        self.relay(signed_tx).await;
        sent
    }

    /// With the cross-check on: the same key and primary endpoints, no second-operator check
    /// before a spend. A spend it builds after a `Disagree` is also sent to the second operator
    /// whenever it is broadcast ([`HoldState::relay`]).
    fn primary_only(&self) -> Option<Arc<dyn ChainBackend>> {
        self.second.as_ref()?;
        Some(Arc::new(ZecBackend {
            client: self.client.clone(),
            secp: self.secp.clone(),
            key: self.key,
            pubkey: self.pubkey,
            address: self.address,
            fees: self.fees,
            reservations: self.reservations.clone(),
            network: self.network.clone(),
            second: None,
            second_budget: self.second_budget,
            lock_failing: Mutex::default(),
            hold: self.hold.clone(),
        }))
    }

    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        let Some(raw) = self
            .client
            .get_transaction(&txid.0)
            .await
            .map_err(SwapError::from)?
        else {
            return Ok(None);
        };
        // The answer counts only as `txid`'s: a transaction that does not parse cannot show it.
        let parsed = tx::ParsedTx::parse(&raw.data).map_err(|e| {
            self.refuse_answer(&format!(
                "answered GetTransaction({txid}) with a transaction that does not parse ({e})"
            ))
        })?;
        self.requested(&parsed, &txid.0)?;
        // height 0 = mempool; u64::MAX = mined on a fork that isn't the main chain (lightwalletd
        // `RawTransaction.height` doc). Neither is a main-chain confirmation yet.
        if raw.height == 0 || raw.height == u64::MAX {
            return Ok(Some(0));
        }
        let tip = self.tip_height().await?;
        let confs = (tip.saturating_sub(raw.height) + 1) as u32;
        self.release_confirmed(txid, confs);
        Ok(Some(confs))
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        let mine = self.htlc_output_primary(htlc, at).await?;
        match (&self.second, mine) {
            // Nothing to agree when the primary shows no matching lock: no side acts on `None`.
            (Some(second), Some(lo)) => {
                let want = address::htlc_script_pubkey(&htlc.redeem_script());
                // EX: a second operator that never answers fails the read at the budget.
                let budget = self.second_budget;
                let theirs = tokio::time::timeout(budget, crosscheck::lock_view(second, at))
                    .await
                    .unwrap_or_else(|_| Err(format!("did not answer within {budget:?}")));
                let agreed = crosscheck::agree_lock(at, &want, lo, &self.client, theirs, second);
                self.failing_for(at, agreed).map(Some)
            }
            (_, mine) => Ok(mine),
        }
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        let tip = self.tip_height().await?;
        if from_height > tip {
            return Ok(None);
        }
        let last = tip.min(from_height.saturating_add(MAX_SCAN_BLOCKS - 1));
        let blocks = self
            .client
            .block_range(from_height, last)
            .await
            .map_err(SwapError::from)?;
        for block in &blocks {
            let Some((spender_txid, input_index)) =
                spend_in_block(block, &outpoint.txid.0, outpoint.vout)
            else {
                continue;
            };
            let Some(full) = self
                .client
                .get_transaction(&spender_txid)
                .await
                .map_err(SwapError::from)?
            else {
                continue; // compact block saw it, full tx vanished (reorg); caller retries.
            };
            let parsed = tx::ParsedTx::parse(&full.data)?;
            self.requested(&parsed, &spender_txid)?;
            let Some(input) = parsed.vin.get(input_index as usize) else {
                continue;
            };
            // The txid commits to the prevouts: the compact block's claim is now checkable.
            if input.prevout.txid != outpoint.txid.0 || input.prevout.n != outpoint.vout {
                return Err(self.refuse_answer(&format!(
                    "named {} input {input_index} as the spend of {outpoint}, but that input \
                     spends {}:{}",
                    Txid(spender_txid),
                    Txid(input.prevout.txid),
                    input.prevout.n
                )));
            }
            let height = if full.height == 0 || full.height == u64::MAX {
                None
            } else {
                Some(full.height)
            };
            return Ok(Some(SpendInfo {
                txid: Txid(spender_txid),
                input_index,
                height,
                script_sig: input.script_sig.clone(),
                witness: vec![],
            }));
        }
        Ok(None)
    }
}

/// The tip header from `GetLatestBlock`'s `latest` and `GetBlock(latest.height)`'s `block`.
/// Both name the block by height and by little-endian hash (lightwalletd's
/// `GetLatestBlock` reverses zcashd's `getbestblockhash` hex, and `CompactBlock.hash` is
/// the block's wire-order hash), so a `block` whose height or hash differs means the tip
/// moved, or another endpoint answered with another chain, between the two reads: a
/// transient error, never a header mixing two blocks.
fn tip_header_from(latest: &BlockId, block: &CompactBlock) -> Result<TipHeader> {
    if block.height != latest.height || block.hash != latest.hash {
        return Err(SwapError::Transient(format!(
            "lightwalletd tip moved between reads: GetLatestBlock said {} {}, GetBlock answered {} {}",
            latest.height,
            hex::encode(&latest.hash),
            block.height,
            hex::encode(&block.hash)
        )));
    }
    Ok(TipHeader {
        height: block.height,
        hash: display_block_hash(&block.hash)?,
        time: block.time,
    })
}

/// `BlockID.hash` from lightwalletd is the 32-byte hash in internal (wire) order; explorers
/// show it byte-reversed. Returns the explorer form: 64 lowercase hex characters.
fn display_block_hash(wire: &[u8]) -> Result<String> {
    if wire.len() != 32 {
        return Err(SwapError::Transient(format!(
            "GetLatestBlock hash is {} bytes, expected 32",
            wire.len()
        )));
    }
    let mut rev = wire.to_vec();
    rev.reverse();
    Ok(hex::encode(rev))
}

#[cfg(test)]
mod tests {
    use divi_swap::htlc::new_preimage;

    use super::*;
    use crate::grpc::{CompactTx, CompactTxIn};
    use crate::tx::OutPoint;

    #[test]
    fn lightwalletd_endpoints_default_is_testnet_primary_only() {
        assert_eq!(
            default_endpoints("testnet").unwrap(),
            vec![TESTNET_LIGHTWALLETD.to_string()]
        );
        let err = default_endpoints("regtest").unwrap_err();
        assert!(matches!(err, SwapError::InvalidParams(_)), "{err:?}");
    }

    #[test]
    fn mainnet_default_endpoints_are_nonempty_https_and_primary_first() {
        let eps = default_endpoints("mainnet").unwrap();
        assert!(!eps.is_empty());
        assert_eq!(eps[0], MAINNET_LIGHTWALLETD[0]);
        assert!(eps.iter().all(|e| e.starts_with("https://")), "{eps:?}");
        assert!(!eps.contains(&TESTNET_LIGHTWALLETD.to_string()));
    }

    #[test]
    fn with_network_rejects_unknown_and_selects_address_prefix() {
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let b = ZecBackend::for_network("mainnet", key, FeePolicy::default()).unwrap();
        assert!(b.encoded_address().starts_with("t1"));
        // `address().encode()` is testnet-only; callers (CLI/daemon) must use `encoded_address()`.
        assert!(b.address().encode().starts_with("tm"));
        assert_ne!(b.encoded_address(), b.address().encode());
        let t = ZecBackend::for_network("testnet", key, FeePolicy::default()).unwrap();
        assert!(t.encoded_address().starts_with("tm"));
        assert!(ZecBackend::for_network("regtest", key, FeePolicy::default()).is_err());
    }

    /// The configurable half of the fallback list (`LIGHTWALLETD_EXTRA_ENV`'s parsing):
    /// appended in order after the built-in default(s), blanks/whitespace dropped, `None`
    /// (unset) left as a no-op — pure, so this doesn't need to touch the real process env
    /// (and risk racing other tests that might).
    #[test]
    fn extra_endpoints_append_in_order_and_drop_blanks() {
        let base = vec!["https://primary:443".to_string()];
        assert_eq!(with_extra_endpoints(base.clone(), None), base);
        assert_eq!(with_extra_endpoints(base.clone(), Some("")), base);
        assert_eq!(
            with_extra_endpoints(base.clone(), Some("https://second:443")),
            vec!["https://primary:443", "https://second:443"]
        );
        // Ordered (second before third), and a stray blank entry (trailing comma, or
        // whitespace-only) is dropped rather than becoming a bogus endpoint that would
        // only ever fail at call time.
        assert_eq!(
            with_extra_endpoints(base, Some(" https://second:443 , , https://third:443,")),
            vec![
                "https://primary:443",
                "https://second:443",
                "https://third:443"
            ]
        );
    }

    #[test]
    fn refund_rejected_before_locktime() {
        let err = classify_broadcast_error(
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"64: non-final\"}",
        );
        assert!(matches!(err, SwapError::Premature(_)), "{err:?}");
        assert!(err.is_retryable());

        let err2 = classify_broadcast_error("Locktime requirement not satisfied");
        assert!(matches!(err2, SwapError::Premature(_)), "{err2:?}");

        // Zebra's own wording (zebra-consensus/src/error.rs, TransactionError::
        // LockedUntilAfterBlock{Height,Time}'s Display) — a case-c refund attempted before
        // its locktime matures must be retried, not treated as a fatal rejection.
        let err4 = classify_broadcast_error(
            "transaction rejected: transaction is locked until after block time 2026-10-12 12:00:00 UTC",
        );
        assert!(matches!(err4, SwapError::Premature(_)), "{err4:?}");
        assert!(err4.is_retryable());
        let err5 = classify_broadcast_error(
            "transaction rejected: transaction is locked until after block height Height(4500000)",
        );
        assert!(matches!(err5, SwapError::Premature(_)), "{err5:?}");

        // Other node refusals are not retryable.
        let err3 = classify_broadcast_error("bad-txns-in-belowout");
        assert!(matches!(err3, SwapError::Rejected(_)), "{err3:?}");
        assert!(!err3.is_retryable());

        assert!(is_already_known(
            "sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction already in block chain\"}"
        ));
        assert!(is_already_known(
            "transaction rejected: transaction already exists in mempool"
        ));
        assert!(is_already_known(
            "transaction rejected: any transaction with the same effects will be rejected \
             from the mempool until a chain reset: transaction was committed to the best chain"
        ));
    }

    /// Zcash mainnet genesis: lightwalletd's wire bytes are the reverse of the explorer hash.
    #[test]
    fn display_block_hash_reverses_wire_bytes() {
        let explorer = "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08";
        let mut wire = hex::decode(explorer).unwrap();
        wire.reverse();
        assert_eq!(display_block_hash(&wire).unwrap(), explorer);
    }

    /// GetLatestBlock named block 100 (hash A); by the GetBlock read the tip moved to 101.
    /// GetBlock(100) still answers block 100, so its time is block 100's. A different block
    /// at that height (another endpoint, a reorg) is refused.
    #[test]
    fn tip_header_takes_its_time_from_the_block_get_latest_block_named() {
        let a = vec![0xaa; 32];
        let latest = BlockId {
            height: 100,
            hash: a.clone(),
        };
        let block = |height, hash: &[u8], time| CompactBlock {
            height,
            hash: hash.to_vec(),
            time,
            vtx: Vec::new(),
        };
        assert_eq!(
            tip_header_from(&latest, &block(100, &a, 1_790_000_000)).unwrap(),
            TipHeader {
                height: 100,
                hash: "aa".repeat(32),
                time: 1_790_000_000,
            }
        );
        for bad in [block(100, &[0xbb; 32], 1), block(101, &a, 1)] {
            let err = tip_header_from(&latest, &bad).unwrap_err();
            assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
        }
    }

    #[test]
    fn display_block_hash_rejects_wrong_length() {
        for bad in [&[][..], &[0u8; 31][..], &[0u8; 33][..]] {
            let err = display_block_hash(bad).unwrap_err();
            assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
        }
    }

    #[test]
    fn median_of_block_times_computes_and_rejects_empty() {
        assert_eq!(median_of_block_times([3u32, 1, 2].into_iter()).unwrap(), 2);
        // `tip_height` and `block_range` landing on different lightwalletd backends can
        // answer with no blocks at all for a tip we were just given — transient, not "the
        // chain has no blocks."
        let err = median_of_block_times(std::iter::empty()).unwrap_err();
        assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
    }

    /// `broadcast()` must treat a rebroadcast of a tx the chain already has as success, not
    /// a fatal error — the exact live failure: a taker's ZEC lock was accepted and mined,
    /// the taker then rebroadcast it (e.g. after a retry/restart) and Zebra's rejection was
    /// treated as fatal, killing the CLI with real coins already moved.
    #[test]
    fn broadcast_idempotent_already_known_errors() {
        // The exact live message (Zebra's NU7 mempool wording), and the equivalent once
        // the same tx has already been mined rather than just sitting in the mempool.
        assert!(is_already_known(
            "transaction rejected: transaction already exists in mempool"
        ));
        assert!(is_already_known(
            "transaction rejected: any transaction with the same effects will be rejected \
             from the mempool until a chain reset: transaction was committed to the best chain"
        ));
        // Case-insensitive, and with a gRPC Status's Display wrapper around the real text
        // (`ClientError::Rejected` stores `tonic::Status::to_string()`, not the bare
        // message).
        assert!(is_already_known(
            "status: InvalidArgument, message: \"Transaction already exists in mempool\", details: [], metadata: MetadataMap { headers: {} }"
        ));
        // zcashd/bitcoind-style reject reasons (legacy JSON-RPC, still possible from a
        // zcashd-era node or a stale test vector).
        assert!(is_already_known("txn-already-known"));
        assert!(is_already_known("txn-already-in-mempool"));
        assert!(is_already_known(
            "sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction already in block chain\"}"
        ));
        assert!(is_already_known("outputs already in utxo set"));
        assert!(is_already_known(
            "transaction rejected: failed to validate tx: WtxId(\"private\"), error: \
             transaction is already in state"
        ));

        // A genuine rejection (not already-known) must not be swallowed as success.
        assert!(!is_already_known("bad-txns-in-belowout"));
        assert!(!is_already_known(
            "transaction rejected: ... Unpaid actions is higher than the limit"
        ));
    }

    #[test]
    fn find_spend_reads_scriptsig() {
        const BRANCH_ID: u32 = 0xc2d6_d0b4;
        let (preimage, hash) = new_preimage();
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
        let pk = sk.public_key(&secp).serialize();
        let htlc = HtlcParams {
            hash,
            claim_pubkey: pk,
            refund_pubkey: pk,
            locktime: 1_900_000_000,
            script_version: Default::default(),
        };
        let fund_outpoint = OutPoint {
            txid: [7; 32],
            n: 1,
        };

        // Build a real claim spend so its scriptSig is genuine.
        let spend = tx::build_spend_tx(
            &secp,
            &sk,
            &pk,
            &htlc,
            fund_outpoint,
            60_000,
            tx::Spend::Claim(&preimage),
            6,
            BRANCH_ID,
            2,
        )
        .unwrap();
        let spender_txid = spend.txid();

        // The compact block only carries prevout/index, as the real API would.
        let block = CompactBlock {
            height: 500,
            hash: vec![0x55; 32],
            time: 1_900_000_100,
            vtx: vec![CompactTx {
                index: 1,
                txid: spender_txid.to_vec(),
                vin: vec![CompactTxIn {
                    prevout_txid: fund_outpoint.txid.to_vec(),
                    prevout_index: fund_outpoint.n,
                }],
            }],
        };
        let found = spend_in_block(&block, &fund_outpoint.txid, fund_outpoint.n);
        assert_eq!(found, Some((spender_txid, 0)));

        // The full tx (as `GetTransaction` would return it) is what supplies the scriptSig.
        let raw = spend.serialize();
        let parsed = tx::ParsedTx::parse(&raw).unwrap();
        let script_sig = parsed.vin[0].script_sig.clone();
        let info = SpendInfo {
            txid: Txid(spender_txid),
            input_index: 0,
            height: Some(500),
            script_sig,
            witness: vec![],
        };
        assert_eq!(info.extract_preimage(&hash), Some(preimage));

        // An outpoint this spend doesn't touch is not found.
        let other = OutPoint {
            txid: [8; 32],
            n: 0,
        };
        assert_eq!(spend_in_block(&block, &other.txid, other.n), None);
    }

    /// Read-only smoke: prints `SMOKE ZEC <net> <height_before> <tip_hash> <height_after>`
    /// for comparison with an independent explorer. Broadcasts nothing.
    #[tokio::test]
    #[ignore = "hits live lightwalletd (read-only)"]
    async fn tip_hash_live_smoke() {
        for net in ["testnet", "mainnet"] {
            let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
            let b = ZecBackend::for_network(net, sk, FeePolicy::default()).unwrap();
            let before = b.tip_height().await.unwrap();
            let hash = b.tip_hash().await.unwrap();
            let after = b.tip_height().await.unwrap();
            assert_eq!(hash.len(), 64, "{hash}");
            println!("SMOKE ZEC {net} {before} {hash} {after}");
        }
    }

    /// Read-only, against the live testnet API.
    #[tokio::test]
    #[ignore = "needs network access to testnet.zec.rocks"]
    async fn testnet_api_reachable() {
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let backend = ZecBackend::testnet(sk, FeePolicy::default()).unwrap();
        let tip = backend.tip_height().await.unwrap();
        assert!(tip > 0, "tip height {tip}");
        let mtp = backend.median_time_past().await.unwrap();
        assert!(mtp > 1_700_000_000, "median time past {mtp}");
        let info = backend.consensus_branch_id().await.unwrap();
        assert!(info > 0, "consensus branch id {info:#x}");
        println!("testnet.zec.rocks: tip={tip} mtp={mtp} consensus_branch_id={info:#010x}");
    }

    /// Read-only chain-tip fact (no funds, no key material spent): proves NU6.3 (mainnet
    /// activation height 3428143, `tx::NU6_3_MAINNET_ACTIVATION_HEIGHT`) is live on mainnet,
    /// closing `docs/plans/swap-poc/mainnet-readiness.md`'s "could not verify (no tip query
    /// run)" row.
    #[tokio::test]
    #[ignore = "needs network access to zec.rocks (mainnet)"]
    async fn mainnet_tip_reachable() {
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let backend = ZecBackend::for_network("mainnet", sk, FeePolicy::default()).unwrap();
        let tip = backend.tip_height().await.unwrap();
        assert!(
            tip >= tx::NU6_3_MAINNET_ACTIVATION_HEIGHT as u64,
            "mainnet tip {tip} is below the NU6.3 activation height \
             {}",
            tx::NU6_3_MAINNET_ACTIVATION_HEIGHT
        );
        println!(
            "{}: mainnet tip={tip} (NU6.3 active: {})",
            MAINNET_LIGHTWALLETD[0],
            tip >= tx::NU6_3_MAINNET_ACTIVATION_HEIGHT as u64
        );
    }

    /// Diagnostic only (not part of the acceptance surface): what transaction version is
    /// actually on-chain right now, post-NU6.3? (Historical: this backend once built only v5;
    /// had the network required v6 for everything, not just transactions touching the new
    /// Ironwood pool, those would have been rejected.)
    #[tokio::test]
    #[ignore = "diagnostic: needs network access to testnet.zec.rocks"]
    async fn probe_live_tx_version() {
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let backend = ZecBackend::testnet(sk, FeePolicy::default()).unwrap();
        let tip = backend.client.latest_block().await.unwrap().height;
        let blocks = backend
            .client
            .block_range(tip.saturating_sub(2000), tip)
            .await
            .unwrap();
        let mut seen = 0;
        for b in &blocks {
            for t in &b.vtx {
                let txid: [u8; 32] = t.txid.clone().try_into().unwrap();
                if let Some(raw) = backend.client.get_transaction(&txid).await.unwrap() {
                    let version_bytes = u32::from_le_bytes(raw.data[0..4].try_into().unwrap());
                    println!(
                        "height={} index={} txid={} version_bytes={version_bytes:#010x} (version {}) len={} vin_in_compact={} raw_head={}",
                        b.height,
                        t.index,
                        hex::encode(&t.txid),
                        version_bytes & 0x7fff_ffff,
                        raw.data.len(),
                        t.vin.len(),
                        hex::encode(&raw.data[..raw.data.len().min(80)])
                    );
                    seen += 1;
                    if seen > 30 {
                        return;
                    }
                }
            }
        }
        println!("total txs seen across scanned range: {seen}");
    }

    #[cfg(feature = "live")]
    mod live {
        use std::time::Duration;

        use divi_swap::htlc::new_preimage;
        use divi_swap::{Amount, ChainBackend, HtlcParams, SignedTx, SwapError, Txid};

        use crate::{FeePolicy, ZecBackend};

        // Covers a claim's CLAIM_ZIP317_FACTOR x conventional fee (40,000) plus dust.
        const HTLC_ZATOSHI: u64 = 60_000;
        const REFUND_AHEAD_OF_MTP: u32 = 2 * 3600;

        fn key_from_env() -> secp256k1::SecretKey {
            let hex = std::env::var("SWAP_ZEC_TEST_KEY_HEX")
                .expect("SWAP_ZEC_TEST_KEY_HEX must hold a 32-byte hex secp256k1 key");
            secp256k1::SecretKey::from_slice(&hex::decode(hex.trim()).unwrap()).unwrap()
        }

        async fn wait_confirmed(b: &ZecBackend, txid: &Txid, what: &str) {
            for _ in 0..240 {
                if matches!(b.confirmations(txid).await, Ok(Some(c)) if c >= 1) {
                    println!("{what} confirmed: {}", txid.to_rpc_hex());
                    return;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            panic!("{what} {} not confirmed after 2h", txid.to_rpc_hex());
        }

        async fn broadcast(b: &ZecBackend, tx: &SignedTx, what: &str) {
            let id = b.broadcast(tx).await.unwrap();
            assert_eq!(id, tx.txid);
            println!("{what} broadcast: {}", id.to_rpc_hex());
        }

        /// Fund two HTLCs on Zcash testnet with the taker-zec key, claim one, refund the
        /// other once MTP passes a locktime 2h ahead of the MTP at start. Takes about 3h.
        #[tokio::test]
        #[ignore = "needs a funded testnet t-address (SWAP_ZEC_TEST_KEY_HEX) and ~3 h"]
        async fn live_fund_claim_refund() {
            let key = key_from_env();
            let b = ZecBackend::testnet(key, FeePolicy::default()).unwrap();
            println!("address {} on testnet", b.address().encode());

            let locktime = b.median_time_past().await.unwrap() + REFUND_AHEAD_OF_MTP;
            let mk = |hash: [u8; 32]| HtlcParams {
                hash,
                claim_pubkey: b.pubkey(),
                refund_pubkey: b.pubkey(),
                locktime,
                script_version: Default::default(),
            };
            let (pre_claim, hash_claim) = new_preimage();
            let (_, hash_refund) = new_preimage();
            let h_claim = mk(hash_claim);
            let h_refund = mk(hash_refund);
            let amount = Amount::from_sat(HTLC_ZATOSHI);

            let f1 = b.build_funding(&h_claim, amount).await.unwrap();
            broadcast(&b, &f1.tx, "fund(claim)").await;
            wait_confirmed(&b, &f1.tx.txid, "fund(claim)").await;
            let f2 = b.build_funding(&h_refund, amount).await.unwrap();
            broadcast(&b, &f2.tx, "fund(refund)").await;
            wait_confirmed(&b, &f2.tx.txid, "fund(refund)").await;
            println!("live_fund_txid: {}", f1.tx.txid.to_rpc_hex());
            println!("live_fund2_txid: {}", f2.tx.txid.to_rpc_hex());

            let locked = b
                .htlc_output(&h_claim, &f1.outpoint)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(locked.amount, amount);

            let claim = b
                .build_claim(&h_claim, &f1.outpoint, amount, &pre_claim)
                .await
                .unwrap();
            broadcast(&b, &claim, "claim").await;
            wait_confirmed(&b, &claim.txid, "claim").await;
            println!("live_claim_txid: {}", claim.txid.to_rpc_hex());
            let spend = b.find_spend(&f1.outpoint, 0).await.unwrap().unwrap();
            assert_eq!(spend.txid, claim.txid);
            assert_eq!(spend.extract_preimage(&h_claim.hash), Some(pre_claim));

            let refund = b
                .build_refund(&h_refund, &f2.outpoint, amount)
                .await
                .unwrap();
            loop {
                match b.broadcast(&refund).await {
                    Ok(id) => {
                        println!("refund broadcast: {}", id.to_rpc_hex());
                        break;
                    }
                    Err(SwapError::Premature(_)) | Err(SwapError::Transient(_)) => {
                        tokio::time::sleep(Duration::from_secs(120)).await;
                    }
                    Err(e) => panic!("refund rejected: {e}"),
                }
            }
            wait_confirmed(&b, &refund.txid, "refund").await;
            println!("live_refund_txid: {}", refund.txid.to_rpc_hex());
        }
    }

    // ---- input reservations (a dropped lock's inputs are not handed to the next swap) ----

    const RES_MAKER_KEY: [u8; 32] = [0x11; 32];
    const RES_TAKER_KEY: [u8; 32] = [0x22; 32];
    const RES_BRANCH_ID: u32 = 0xc2d6_d0b4;

    fn res_db(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "swap-chain-zec-{tag}-{}-{nanos}.db",
            std::process::id()
        ))
    }

    fn rm_db(path: &std::path::Path) {
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
    }

    /// A backend whose endpoint is unreachable: nothing here may need the network.
    fn res_backend(key: [u8; 32]) -> ZecBackend {
        ZecBackend::new(
            vec!["http://127.0.0.1:1".to_string()],
            SecretKey::from_slice(&key).unwrap(),
            FeePolicy::default(),
            RetryPolicy::default(),
        )
        .unwrap()
    }

    fn res_htlc(b: &ZecBackend) -> HtlcParams {
        let (_, hash) = new_preimage();
        HtlcParams {
            hash,
            claim_pubkey: b.pubkey(),
            refund_pubkey: b.pubkey(),
            locktime: 1_900_000_000,
            script_version: Default::default(),
        }
    }

    fn res_coin(b: &ZecBackend, n: u8, value: u64) -> tx::Coin {
        tx::Coin {
            outpoint: tx::OutPoint {
                txid: [n; 32],
                n: 0,
            },
            value,
            script_pubkey: crate::address::TransparentAddress::p2pkh(&b.pubkey()).script_pubkey(),
        }
    }

    /// What `build_funding` does after the UTXO query, minus the network: filter, then build.
    fn fund(b: &ZecBackend, coins: &[tx::Coin], htlc: &HtlcParams) -> (SignedTx, Vec<[u8; 32]>) {
        let coins = b.unreserved(coins.to_vec()).unwrap();
        let built = tx::build_funding_tx(
            &b.secp,
            &b.key,
            &b.pubkey,
            &coins,
            htlc,
            5_000,
            6,
            RES_BRANCH_ID,
            2,
        )
        .unwrap();
        let spent = built.tx.vin.iter().map(|i| i.prevout.txid).collect();
        (ZecBackend::to_signed(&built.tx), spent)
    }

    #[test]
    fn a_dropped_locks_inputs_are_skipped_until_the_lock_confirms() {
        let res = InputReservations::in_memory().unwrap();
        let b = res_backend(RES_MAKER_KEY).with_input_reservations(res.clone());
        let coins = [res_coin(&b, 1, 200_000), res_coin(&b, 2, 150_000)];
        let h = res_htlc(&b);

        let (lock1, spent1) = fund(&b, &coins, &h);
        assert_eq!(spent1, vec![[1u8; 32]], "largest coin first");
        b.reserve_inputs(&lock1).unwrap();

        // The lock dropped from the mempool; the UTXO query still lists both coins.
        let (_, spent2) = fund(&b, &coins, &h);
        assert_eq!(
            spent2,
            vec![[2u8; 32]],
            "coin 1 is reserved by the dropped lock"
        );
        // "Not seen" (0 confirmations is mempool; absence is never reported here) never releases.
        b.release_confirmed(&lock1.txid, 0);
        let (_, spent3) = fund(&b, &coins, &h);
        assert_eq!(spent3, vec![[2u8; 32]]);

        b.release_confirmed(&lock1.txid, 1);
        assert!(res.reserved(Chain::Zec).unwrap().is_empty());
        let (_, spent4) = fund(&b, &coins, &h);
        assert_eq!(spent4, vec![[1u8; 32]]);
    }

    #[test]
    fn reserved_inputs_survive_a_restart() {
        let db = res_db("restart");
        let b = res_backend(RES_MAKER_KEY)
            .with_input_reservations(InputReservations::open(&db).unwrap());
        let coins = [res_coin(&b, 1, 200_000), res_coin(&b, 2, 150_000)];
        let h = res_htlc(&b);
        let (lock, _) = fund(&b, &coins, &h);
        b.reserve_inputs(&lock).unwrap();
        drop(b);

        let b2 = res_backend(RES_MAKER_KEY)
            .with_input_reservations(InputReservations::open(&db).unwrap());
        let (_, spent) = fund(&b2, &coins, &h);
        assert_eq!(spent, vec![[2u8; 32]]);
        drop(b2);
        rm_db(&db);
    }

    #[tokio::test]
    async fn a_failed_reservation_write_blocks_the_lock_broadcast() {
        let db = res_db("failclosed");
        InputReservations::open(&db).unwrap();
        let b = res_backend(RES_MAKER_KEY)
            .with_input_reservations(InputReservations::open_read_only(&db).unwrap());
        let coins = [res_coin(&b, 1, 200_000)];
        let (lock, _) = fund(&b, &coins, &res_htlc(&b));
        // The endpoint is unreachable, so a Storage error proves we stopped before the network.
        let err = b.broadcast(&lock).await.unwrap_err();
        assert!(matches!(err, SwapError::Storage(_)), "{err:?}");
        rm_db(&db);
    }

    #[test]
    fn claims_and_refunds_are_never_reserved() {
        let res = InputReservations::in_memory().unwrap();
        let b = res_backend(RES_TAKER_KEY).with_input_reservations(res.clone());
        let (pre, hash) = new_preimage();
        let h = HtlcParams {
            hash,
            ..res_htlc(&b)
        };
        for spend in [tx::Spend::Claim(&pre), tx::Spend::Refund] {
            let built = tx::build_spend_tx(
                &b.secp,
                &b.key,
                &b.pubkey,
                &h,
                tx::OutPoint {
                    txid: [9; 32],
                    n: 1,
                },
                50_000,
                spend,
                6,
                RES_BRANCH_ID,
                2,
            )
            .unwrap();
            b.reserve_inputs(&ZecBackend::to_signed(&built)).unwrap();
        }
        assert!(res.reserved(Chain::Zec).unwrap().is_empty());
    }
}
