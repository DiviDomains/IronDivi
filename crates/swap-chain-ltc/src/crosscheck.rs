// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Opt-in LTC **mainnet** tip-hash cross-check against a source that is not Esplora.
//!
//! The primary (`litecoinspace.org/api`) is the only mainnet Esplora API we know of, so a
//! lying or forked primary would go unnoticed. This asks one independent explorer (Blockbook
//! or BlockCypher) for the hash of the block [`CROSSCHECK_DEPTH`] below the primary's tip and
//! compares it with the primary's hash at that height. It is a sanity check, not a UTXO
//! source, and it changes no confirmation count, lag or timeout.
//!
//! `H - 6` (not the tip) is used so that ordinary one-to-few-block reorgs and the few
//! seconds by which one explorer leads another cannot cause a false `Disagree`.
//!
//! The claim-time check (`[ltc].crosscheck_before_claim`, [`claim_crosscheck`]) also compares
//! the block at `H - 1` ([`CLAIM_NEAR_DEPTH`]: a source one block behind or ahead still has
//! it, so one block of lag is not a disagreement) and the spend of the output being claimed.
//! With it on, every lock read (`htlc_output`: the maker about to fund against the taker's
//! lock, the taker about to claim the maker's) also compares the output's script and value
//! with the source ([`lock_view`], [`agree_lock`]) and fails closed. Every `find_spend` (EN)
//! is agreed with the source's view of the spend ([`agree_find_spend`]): two answers that
//! differ are `Transient`, a source that cannot be read leaves the primary's answer.

use std::str::FromStr;

use bitcoin::hashes::Hash;
use divi_swap::{LockedOutput, Outpoint, SpendInfo, Txid};
use serde_json::Value;

use crate::client::{ClientError, EsploraClient, RetryPolicy};

/// How far below the primary's tip the compared block sits. A comparison depth only — it is
/// **not** a confirmation count and nothing else reads it.
pub const CROSSCHECK_DEPTH: u64 = 6;

/// The claim-time check's second comparison sits this far below the primary's tip. Like
/// [`CROSSCHECK_DEPTH`], a comparison depth only.
pub const CLAIM_NEAR_DEPTH: u64 = 1;

/// Blockbook mainnet API base (keyless).
pub const BLOCKBOOK_MAINNET: &str = "https://litecoinblockexplorer.net/api/v2";

/// BlockCypher LTC mainnet API base (keyless, rate limited).
pub const BLOCKCYPHER_MAINNET: &str = "https://api.blockcypher.com/v1/ltc/main";

/// Which independent source to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossCheckSource {
    /// `GET {base}/block-index/{height}` → `{"blockHash":"…"}`.
    Blockbook,
    /// `GET {base}/blocks/{height}` → `{"hash":"…", …}`.
    BlockCypher,
}

impl CrossCheckSource {
    /// Default mainnet API base for this source.
    pub fn default_base(self) -> &'static str {
        match self {
            Self::Blockbook => BLOCKBOOK_MAINNET,
            Self::BlockCypher => BLOCKCYPHER_MAINNET,
        }
    }

    /// Config / CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blockbook => "blockbook",
            Self::BlockCypher => "blockcypher",
        }
    }

    /// Parse the config / CLI value. `off` is `Ok(None)`; anything unknown is an error.
    pub fn parse_opt(s: &str) -> Result<Option<Self>, String> {
        match s {
            "off" => Ok(None),
            other => other.parse().map(Some),
        }
    }

    fn path(self, height: u64) -> String {
        match self {
            Self::Blockbook => format!("/block-index/{height}"),
            Self::BlockCypher => format!("/blocks/{height}"),
        }
    }

    /// The transaction whose outputs carry their spenders: Blockbook `GET /api/v2/tx/{txid}`
    /// (`vout[].spent`, `vout[].spentTxId`; trezor/blockbook `api/types.go`), BlockCypher
    /// `GET /txs/{txid}` (`outputs[].spent_by`, "only returned for outputs that have been
    /// spent"; BlockCypher API docs, TXOutput).
    pub(crate) fn tx_path(self, txid: &str) -> String {
        match self {
            Self::Blockbook => format!("/tx/{txid}"),
            Self::BlockCypher => format!("/txs/{txid}"),
        }
    }

    /// How this source's transaction body shows output `vout` spent.
    fn spend_from(self, body: &str, vout: u32) -> Result<SpendView, String> {
        let v: Value = serde_json::from_str(body).map_err(|e| format!("not JSON: {e}"))?;
        match self {
            Self::Blockbook => {
                let out = v["vout"]
                    .as_array()
                    .and_then(|a| a.iter().find(|o| o["n"].as_u64() == Some(vout as u64)))
                    .ok_or_else(|| format!("no output {vout} in response"))?;
                // `spent` and `spentTxId` are omitted when empty (`omitempty`).
                if out["spent"].as_bool() != Some(true) {
                    return Ok(SpendView::Unspent);
                }
                Ok(match out["spentTxId"].as_str().filter(|t| !t.is_empty()) {
                    Some(t) => SpendView::SpentBy(normalize_txid(t)?),
                    None => SpendView::SpentUnnamed,
                })
            }
            Self::BlockCypher => {
                // BlockCypher lists 20 outputs by default; an HTLC output is never that far in.
                let out = v["outputs"]
                    .as_array()
                    .and_then(|a| a.get(vout as usize))
                    .ok_or_else(|| format!("no output {vout} in response"))?;
                Ok(match out["spent_by"].as_str().filter(|t| !t.is_empty()) {
                    Some(t) => SpendView::SpentBy(normalize_txid(t)?),
                    None => SpendView::Unspent,
                })
            }
        }
    }

    /// Pull the block hash out of this source's response body.
    fn hash_from(self, body: &str) -> Result<String, String> {
        let v: Value = serde_json::from_str(body).map_err(|e| format!("not JSON: {e}"))?;
        let key = match self {
            Self::Blockbook => "blockHash",
            Self::BlockCypher => "hash",
        };
        // Blockbook answers 200 with an empty hash for a height it has not indexed yet.
        let h = v[key]
            .as_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| format!("no {key:?} in response"))?;
        normalize_hash(h)
    }
}

impl FromStr for CrossCheckSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "blockbook" => Ok(Self::Blockbook),
            "blockcypher" => Ok(Self::BlockCypher),
            other => Err(format!(
                "ltc crosscheck {other:?} unsupported: blockbook, blockcypher or off"
            )),
        }
    }
}

/// Lower-case a 64-hex block hash; anything else is rejected.
fn normalize_hash(h: &str) -> Result<String, String> {
    let h = h.trim().to_ascii_lowercase();
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(h)
    } else {
        Err(format!("not a 64-hex block hash: {h:?}"))
    }
}

fn normalize_txid(t: &str) -> Result<String, String> {
    normalize_hash(t).map_err(|_| format!("not a 64-hex txid: {t:?}"))
}

/// An output's spend as one source shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SpendView {
    Unspent,
    SpentBy(String),
    /// Spent, but the source did not name the spender (Blockbook without `spentTxId`).
    SpentUnnamed,
}

impl std::fmt::Display for SpendView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspent => f.write_str("unspent"),
            Self::SpentBy(t) => write!(f, "spent by {t}"),
            Self::SpentUnnamed => f.write_str("spent (spender not named)"),
        }
    }
}

/// Result of one cross-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCheckOutcome {
    /// Both sources report the same hash at `height`.
    Agree { height: u64, hash: String },
    /// They report different hashes at `height`: refuse to proceed.
    Disagree {
        height: u64,
        primary_hash: String,
        primary_url: String,
        other_hash: String,
        other_url: String,
    },
    /// Could not compare (network error, rate limit, malformed body, source behind).
    Unavailable { reason: String },
}

impl CrossCheckOutcome {
    /// The refusal text for a `Disagree`, naming both hashes and both URLs.
    pub fn disagree_message(&self) -> Option<String> {
        match self {
            Self::Disagree {
                height,
                primary_hash,
                primary_url,
                other_hash,
                other_url,
            } => Some(format!(
                "ltc tip cross-check FAILED at height {height}: primary {primary_url} says \
                 {primary_hash}, independent source {other_url} says {other_hash}; refusing"
            )),
            _ => None,
        }
    }
}

/// Compare `primary`'s hash at `tip - CROSSCHECK_DEPTH` with `source`'s, asking `source` at
/// `source_base` (use [`CrossCheckSource::default_base`]). Never returns an error: every
/// failure is [`CrossCheckOutcome::Unavailable`] so the caller decides (warn and continue).
pub async fn tip_crosscheck(
    primary: &EsploraClient,
    source: CrossCheckSource,
    source_base: &str,
    retry: RetryPolicy,
) -> CrossCheckOutcome {
    let unavailable = |reason: String| CrossCheckOutcome::Unavailable { reason };
    let other = match EsploraClient::new(vec![source_base.to_string()], retry) {
        Ok(c) => c,
        Err(e) => return unavailable(format!("{} client: {e}", source.as_str())),
    };
    let primary_base = primary.primary_url().to_string();

    let tip: u64 = match primary.get("/blocks/tip/height").await {
        Ok(b) => match b.trim().parse() {
            Ok(h) => h,
            Err(_) => return unavailable(format!("{primary_base}: tip height not a number")),
        },
        Err(e) => return unavailable(format!("{primary_base}: tip height: {e:?}")),
    };
    let height = match tip.checked_sub(CROSSCHECK_DEPTH) {
        Some(h) => h,
        None => return unavailable(format!("{primary_base}: tip {tip} below depth")),
    };
    compare_at(primary, &other, source, source_base, height).await
}

/// Compare `primary`'s hash at `height` with `source`'s (asked through `other`, at
/// `source_base`).
async fn compare_at(
    primary: &EsploraClient,
    other: &EsploraClient,
    source: CrossCheckSource,
    source_base: &str,
    height: u64,
) -> CrossCheckOutcome {
    let unavailable = |reason: String| CrossCheckOutcome::Unavailable { reason };
    let primary_base = primary.primary_url().to_string();
    let primary_hash = match primary.get(&format!("/block-height/{height}")).await {
        Ok(b) => match normalize_hash(&b) {
            Ok(h) => h,
            Err(e) => return unavailable(format!("{primary_base}: {e}")),
        },
        Err(e) => return unavailable(format!("{primary_base}: hash at {height}: {e:?}")),
    };

    let other_path = source.path(height);
    let other_url = format!("{}{other_path}", source_base.trim_end_matches('/'));
    let other_hash = match other.get(&other_path).await {
        Ok(body) => match source.hash_from(&body) {
            Ok(h) => h,
            Err(e) => return unavailable(format!("{other_url}: {e}")),
        },
        Err(e) => return unavailable(format!("{other_url}: {e:?}")),
    };

    if other_hash == primary_hash {
        CrossCheckOutcome::Agree {
            height,
            hash: primary_hash,
        }
    } else {
        CrossCheckOutcome::Disagree {
            height,
            primary_hash,
            primary_url: format!("{primary_base}/block-height/{height}"),
            other_hash,
            other_url,
        }
    }
}

/// Result of the claim-time check ([`claim_crosscheck`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClaimCheck {
    /// Every comparison was made and agrees.
    Agree,
    /// A comparison disagrees: the refusal text, naming both answers and both URLs.
    Disagree(String),
    /// Nothing disagrees, but at least one comparison could not be made: why.
    Unavailable(String),
}

/// The claim-time check of a claim of `at`: `primary`'s hashes at `tip - CROSSCHECK_DEPTH`
/// and `tip - CLAIM_NEAR_DEPTH` and its spend of `at` (Esplora `GET /tx/:txid/outspend/:vout`,
/// as `find_spend` reads it), each against `source`. The first disagreement ends the check;
/// a comparison that cannot be made is noted and the others still run.
pub(crate) async fn claim_crosscheck(
    primary: &EsploraClient,
    source: CrossCheckSource,
    source_base: &str,
    retry: RetryPolicy,
    at: &Outpoint,
) -> ClaimCheck {
    let other = match EsploraClient::new(vec![source_base.to_string()], retry) {
        Ok(c) => c,
        Err(e) => return ClaimCheck::Unavailable(format!("{} client: {e}", source.as_str())),
    };
    let primary_base = primary.primary_url().to_string();
    let tip: u64 = match primary.get("/blocks/tip/height").await {
        Ok(b) => match b.trim().parse() {
            Ok(h) => h,
            Err(_) => {
                return ClaimCheck::Unavailable(format!("{primary_base}: tip height not a number"))
            }
        },
        Err(e) => return ClaimCheck::Unavailable(format!("{primary_base}: tip height: {e:?}")),
    };
    let mut unavailable = Vec::new();
    for depth in [CROSSCHECK_DEPTH, CLAIM_NEAR_DEPTH] {
        let Some(height) = tip.checked_sub(depth) else {
            unavailable.push(format!("{primary_base}: tip {tip} below depth {depth}"));
            continue;
        };
        match compare_at(primary, &other, source, source_base, height).await {
            CrossCheckOutcome::Agree { .. } => {}
            CrossCheckOutcome::Unavailable { reason } => unavailable.push(reason),
            d @ CrossCheckOutcome::Disagree { .. } => {
                return ClaimCheck::Disagree(d.disagree_message().expect("disagree"))
            }
        }
    }
    match compare_spend(primary, &other, source, source_base, at).await {
        Ok(()) => {}
        Err(SpendCheck::Unavailable(r)) => unavailable.push(r),
        Err(SpendCheck::Disagree(m)) => return ClaimCheck::Disagree(m),
    }
    if unavailable.is_empty() {
        ClaimCheck::Agree
    } else {
        ClaimCheck::Unavailable(unavailable.join("; "))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpendCheck {
    Unavailable(String),
    Disagree(String),
}

/// `primary`'s and `source`'s view of the spend of `at`. Both unspent, or spent by the same
/// transaction, agree; so does a spend the source shows without naming its spender. A spend
/// one shows and the other does not, or two different spenders, disagree.
async fn compare_spend(
    primary: &EsploraClient,
    other: &EsploraClient,
    source: CrossCheckSource,
    source_base: &str,
    at: &Outpoint,
) -> Result<(), SpendCheck> {
    let txid = at.txid.to_rpc_hex();
    let primary_path = format!("/tx/{txid}/outspend/{}", at.vout);
    let primary_url = format!("{}{primary_path}", primary.primary_url());
    let mine = match primary.get_opt(&primary_path).await {
        // Not found reads as unspent, as `find_spend` reads it.
        Ok(None) => SpendView::Unspent,
        Ok(Some(b)) => {
            let v: Value = serde_json::from_str(&b)
                .map_err(|e| SpendCheck::Unavailable(format!("{primary_url}: not JSON: {e}")))?;
            if v["spent"].as_bool() == Some(true) {
                let t = v["txid"].as_str().ok_or_else(|| {
                    SpendCheck::Unavailable(format!("{primary_url}: outspend lacks txid"))
                })?;
                SpendView::SpentBy(
                    normalize_txid(t)
                        .map_err(|e| SpendCheck::Unavailable(format!("{primary_url}: {e}")))?,
                )
            } else {
                SpendView::Unspent
            }
        }
        Err(e) => return Err(SpendCheck::Unavailable(format!("{primary_url}: {e:?}"))),
    };
    let other_path = source.tx_path(&txid);
    let other_url = format!("{}{other_path}", source_base.trim_end_matches('/'));
    let theirs = match other.get(&other_path).await {
        Ok(body) => source
            .spend_from(&body, at.vout)
            .map_err(|e| SpendCheck::Unavailable(format!("{other_url}: {e}")))?,
        Err(e) => return Err(SpendCheck::Unavailable(format!("{other_url}: {e:?}"))),
    };
    let agree = match (&mine, &theirs) {
        (SpendView::Unspent, SpendView::Unspent) => true,
        (SpendView::SpentBy(a), SpendView::SpentBy(b)) => a == b,
        (SpendView::SpentBy(_), SpendView::SpentUnnamed) => true,
        _ => false,
    };
    if agree {
        return Ok(());
    }
    Err(SpendCheck::Disagree(format!(
        "ltc claim cross-check FAILED on the spend of {at}: primary {primary_url} says {mine}, \
         independent source {other_url} says {theirs}; refusing"
    )))
}

/// `find_spend` with the cross-check on (EN): the primary's answer `mine` agreed with
/// `source`'s, as `swap-chain-btc`'s `quorum::agree_spend` agrees two Esplora endpoints.
/// The source's lock transaction names the spender ([`CrossCheckSource::tx_path`]); the
/// spender itself is read as raw hex ([`source_spender`]) so the spending input, its scriptSig
/// and its witness (the preimage) are compared byte for byte. Both unspent agree; a spend one
/// shows and the other does not, two spenders, or one spender with another input or witness
/// are `Disagree`. On agreement the spend is returned with the fewer confirmations: the later
/// block, or the mempool if either has it there. A source that cannot be read (transport,
/// 5xx, 429, a body that does not parse) is `Unavailable`.
pub(crate) async fn agree_find_spend(
    primary_base: &str,
    source: CrossCheckSource,
    source_base: &str,
    retry: RetryPolicy,
    at: &Outpoint,
    mine: &Option<SpendInfo>,
) -> Result<Option<SpendInfo>, SpendCheck> {
    let other = EsploraClient::new(vec![source_base.to_string()], retry)
        .map_err(|e| SpendCheck::Unavailable(format!("{} client: {e}", source.as_str())))?;
    let base = source_base.trim_end_matches('/');
    let lock_txid = at.txid.to_rpc_hex();
    let primary_url = format!("{primary_base}/tx/{lock_txid}/outspend/{}", at.vout);
    let view_url = format!("{base}{}", source.tx_path(&lock_txid));
    let view = match other.get(&source.tx_path(&lock_txid)).await {
        Ok(body) => source
            .spend_from(&body, at.vout)
            .map_err(|e| SpendCheck::Unavailable(format!("{view_url}: {e}")))?,
        Err(e) => return Err(SpendCheck::Unavailable(format!("{view_url}: {e:?}"))),
    };
    let refuse = |mine: String, theirs: String| {
        SpendCheck::Disagree(format!(
            "ltc find_spend cross-check FAILED on the spend of {at}: primary {primary_url} \
             says {mine}, independent source {theirs}; not acting on it"
        ))
    };
    let Some(x) = mine else {
        return match view {
            SpendView::Unspent => Ok(None),
            v => Err(refuse("unspent".into(), format!("{view_url} says {v}"))),
        };
    };
    let x_txid = x.txid.to_rpc_hex();
    let says_x = format!("spent by {x_txid} input {}", x.input_index);
    if let SpendView::SpentBy(y) = &view {
        if *y != x_txid {
            return Err(refuse(says_x, format!("{view_url} says spent by {y}")));
        }
    }
    let spender_url = format!("{base}{}", source.tx_path(&x_txid));
    let Some((tx, height)) = source_spender(&other, source, base, &x_txid).await? else {
        return Err(refuse(
            says_x,
            format!("{view_url} says {view} and {spender_url} does not know {x_txid}"),
        ));
    };
    let want = bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array(at.txid.0), at.vout);
    let Some((i, input)) = tx
        .input
        .iter()
        .enumerate()
        .find(|(_, i)| i.previous_output == want)
    else {
        return Err(refuse(
            says_x,
            format!("{spender_url} shows {x_txid} spending no such output"),
        ));
    };
    let theirs = SpendInfo {
        txid: x.txid,
        input_index: i as u32,
        height,
        script_sig: input.script_sig.to_bytes(),
        witness: input.witness.to_vec(),
    };
    if theirs.input_index != x.input_index
        || theirs.script_sig != x.script_sig
        || theirs.witness != x.witness
    {
        return Err(refuse(
            says_x,
            format!(
                "{spender_url} shows the same spender with input {}, but the input, scriptSig \
                 or witness differs",
                theirs.input_index
            ),
        ));
    }
    // The fewer confirmations: a single liar can lower a spend's depth, never raise it.
    let height = match (x.height, height) {
        (Some(a), Some(b)) => Some(a.max(b)),
        _ => None,
    };
    Ok(Some(SpendInfo {
        height,
        ..x.clone()
    }))
}

/// `source`'s copy of transaction `txid` and its block height (`None` in the mempool), from
/// raw hex: Blockbook `GET /tx/{txid}` (`hex`, `blockHeight`, -1 for unconfirmed; `hex` is
/// documented for confirmed transactions, so without it `GET /tx-specific/{txid}`, the
/// backend's own JSON, gives `hex`), BlockCypher `GET /txs/{txid}?includeHex=true` (`hex`,
/// `block_height`, -1 when unconfirmed). `Ok(None)`: the source refused the txid (a 4xx
/// other than 429; Blockbook answers 400 for an unknown txid), so it does not know it.
async fn source_spender(
    other: &EsploraClient,
    source: CrossCheckSource,
    base: &str,
    txid: &str,
) -> Result<Option<(bitcoin::Transaction, Option<u64>)>, SpendCheck> {
    let (path, height_key) = match source {
        CrossCheckSource::Blockbook => (source.tx_path(txid), "blockHeight"),
        CrossCheckSource::BlockCypher => (
            format!("{}?includeHex=true", source.tx_path(txid)),
            "block_height",
        ),
    };
    let url = format!("{base}{path}");
    let unavailable = |e: String| SpendCheck::Unavailable(format!("{url}: {e}"));
    let body = match other.get(&path).await {
        Ok(b) => b,
        Err(ClientError::Http(_)) => return Ok(None),
        Err(e) => return Err(unavailable(format!("{e:?}"))),
    };
    let v: Value =
        serde_json::from_str(&body).map_err(|e| unavailable(format!("not JSON: {e}")))?;
    let height = v[height_key]
        .as_i64()
        .ok_or_else(|| unavailable(format!("no {height_key:?} in response")))?;
    let height = u64::try_from(height).ok();
    let hex = match (v["hex"].as_str().filter(|h| !h.is_empty()), source) {
        (Some(h), _) => h.to_string(),
        (None, CrossCheckSource::Blockbook) => {
            let path = format!("/tx-specific/{txid}");
            let url = format!("{base}{path}");
            let body = other
                .get(&path)
                .await
                .map_err(|e| SpendCheck::Unavailable(format!("{url}: {e:?}")))?;
            let v: Value = serde_json::from_str(&body)
                .map_err(|e| SpendCheck::Unavailable(format!("{url}: not JSON: {e}")))?;
            v["hex"]
                .as_str()
                .ok_or_else(|| SpendCheck::Unavailable(format!("{url}: no \"hex\" in response")))?
                .to_string()
        }
        (None, CrossCheckSource::BlockCypher) => {
            return Err(unavailable("no \"hex\" in response".into()))
        }
    };
    let raw = hex::decode(hex.trim()).map_err(|e| unavailable(format!("bad hex: {e}")))?;
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw)
        .map_err(|e| unavailable(format!("not a transaction: {e}")))?;
    if Txid(tx.compute_txid().to_byte_array()).to_rpc_hex() != txid {
        return Err(unavailable(format!("hex is not transaction {txid}")));
    }
    Ok(Some((tx, height)))
}

/// A lock output as the cross-check source shows it (EL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockView {
    /// scriptPubKey, lower-case hex.
    script: String,
    value: u64,
    confirmations: u32,
}

/// `source`'s view of output `at` (the same transaction read as the spend check: Blockbook
/// `GET /api/v2/tx/{txid}`, `vout[n].hex` / `vout[n].value` (decimal string of satoshis) /
/// `confirmations`; BlockCypher `GET /txs/{txid}`, `outputs[n].script` / `outputs[n].value` /
/// `confirmations`). An error is the reason, naming the URL asked.
pub(crate) async fn lock_view(
    source: CrossCheckSource,
    source_base: &str,
    retry: RetryPolicy,
    at: &Outpoint,
) -> Result<LockView, String> {
    let other = EsploraClient::new(vec![source_base.to_string()], retry)
        .map_err(|e| format!("{} client: {e}", source.as_str()))?;
    let path = source.tx_path(&at.txid.to_rpc_hex());
    let url = format!("{}{path}", source_base.trim_end_matches('/'));
    let body = other
        .get(&path)
        .await
        .map_err(|e| format!("{url}: {e:?}"))?;
    source
        .lock_from(&body, at.vout)
        .map_err(|e| format!("{url}: {e}"))
}

impl CrossCheckSource {
    fn lock_from(self, body: &str, vout: u32) -> Result<LockView, String> {
        let v: Value = serde_json::from_str(body).map_err(|e| format!("not JSON: {e}"))?;
        let (out, script_key) = match self {
            Self::Blockbook => (
                v["vout"]
                    .as_array()
                    .and_then(|a| a.iter().find(|o| o["n"].as_u64() == Some(vout as u64))),
                "hex",
            ),
            Self::BlockCypher => (
                v["outputs"].as_array().and_then(|a| a.get(vout as usize)),
                "script",
            ),
        };
        let out = out.ok_or_else(|| format!("no output {vout} in response"))?;
        let script = out[script_key]
            .as_str()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| format!("output {vout} lacks {script_key:?}"))?;
        // Blockbook serialises satoshi amounts as decimal strings; BlockCypher as numbers.
        let value = match &out["value"] {
            Value::String(s) => s.parse().ok(),
            n => n.as_u64(),
        }
        .ok_or_else(|| format!("output {vout} lacks \"value\""))?;
        let confirmations = v["confirmations"]
            .as_u64()
            .ok_or_else(|| "no \"confirmations\" in response".to_string())?;
        Ok(LockView {
            script,
            value,
            confirmations: u32::try_from(confirmations).unwrap_or(u32::MAX),
        })
    }
}

/// Agree the primary's lock read (`mine`, at `primary_url`, already matched against the
/// agreed script `want`) with the source's (`theirs`, from `source_url`), as
/// `swap-chain-btc`'s `quorum::agree_htlc_output` does: the script must be the agreed one on
/// both, the values equal, and the lower confirmation count is returned. Anything else,
/// including a source that could not be read, is `Transient`: the caller (the maker about to
/// fund, the taker about to reveal) waits and reads again.
pub(crate) fn agree_lock(
    at: &Outpoint,
    want: &str,
    mine: LockedOutput,
    primary_url: &str,
    theirs: &Result<LockView, String>,
    source_url: &str,
) -> Result<LockedOutput, divi_swap::SwapError> {
    let sats = mine.amount.to_sat();
    let refuse = |what: String| {
        divi_swap::SwapError::Transient(format!(
            "ltc lock cross-check FAILED for {at}: primary {primary_url} shows the agreed HTLC \
             script with {sats} sat, {what}; not acting on the lock"
        ))
    };
    match theirs {
        Err(reason) => Err(refuse(format!(
            "independent source could not be read ({reason})"
        ))),
        Ok(v) if v.script != want => Err(refuse(format!(
            "independent source {source_url} shows scriptPubKey {} there",
            v.script
        ))),
        Ok(v) if v.value != sats => Err(refuse(format!(
            "independent source {source_url} shows {} sat there",
            v.value
        ))),
        Ok(v) => Ok(LockedOutput {
            amount: mine.amount,
            confirmations: mine.confirmations.min(v.confirmations),
        }),
    }
}

/// Run the check for a mainnet backend and apply the policy: `Disagree` is an error naming
/// both hashes and URLs, `Unavailable` logs a warning and continues. `source = None` (`off`)
/// makes no request.
pub async fn enforce(
    primary: &EsploraClient,
    source: Option<CrossCheckSource>,
    source_base: Option<&str>,
    retry: RetryPolicy,
) -> Result<(), divi_swap::SwapError> {
    let Some(source) = source else {
        return Ok(());
    };
    let base = source_base.unwrap_or_else(|| source.default_base());
    match tip_crosscheck(primary, source, base, retry).await {
        CrossCheckOutcome::Agree { height, hash } => {
            tracing::info!(height, %hash, source = source.as_str(), "ltc tip cross-check agrees");
            Ok(())
        }
        CrossCheckOutcome::Unavailable { reason } => {
            tracing::warn!(%reason, source = source.as_str(), "ltc tip cross-check unavailable; continuing");
            Ok(())
        }
        d @ CrossCheckOutcome::Disagree { .. } => Err(divi_swap::SwapError::Other(
            d.disagree_message().expect("disagree"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const H_A: &str = "bb06e9077c1907d25a1d986ac281b6d119228b8eae984c21b59fcfdb4af66b11";
    const H_B: &str = "ac6f27fa7cfdc204f13f93fcd48ce5f57a4a858b950b4de8ac89979b3b5f0b43";
    const TIP: u64 = 3_199_583;
    const AT: u64 = TIP - CROSSCHECK_DEPTH;

    fn fast() -> RetryPolicy {
        RetryPolicy {
            attempts: 1,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
        }
    }

    async fn primary(hash: &str) -> (MockServer, EsploraClient) {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string(TIP.to_string()))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/block-height/{AT}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(hash))
            .mount(&s)
            .await;
        let c = EsploraClient::new(vec![s.uri()], fast()).unwrap();
        (s, c)
    }

    async fn source(kind: CrossCheckSource, resp: ResponseTemplate) -> MockServer {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(kind.path(AT)))
            .respond_with(resp)
            .mount(&s)
            .await;
        s
    }

    fn bb(hash: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(format!(r#"{{"blockHash":"{hash}"}}"#))
    }

    fn bc(hash: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"height":{AT},"hash":"{hash}","prev_block":"x"}}"#
        ))
    }

    #[tokio::test]
    async fn agree_on_both_source_shapes() {
        for (kind, resp) in [
            (CrossCheckSource::Blockbook, bb(H_A)),
            (CrossCheckSource::BlockCypher, bc(&H_A.to_uppercase())),
        ] {
            let (_p, pc) = primary(H_A).await;
            let s = source(kind, resp).await;
            let out = tip_crosscheck(&pc, kind, &s.uri(), fast()).await;
            assert_eq!(
                out,
                CrossCheckOutcome::Agree {
                    height: AT,
                    hash: H_A.into()
                },
                "{kind:?}"
            );
        }
    }

    #[tokio::test]
    async fn disagree_names_both_hashes_and_both_urls() {
        for (kind, resp) in [
            (CrossCheckSource::Blockbook, bb(H_B)),
            (CrossCheckSource::BlockCypher, bc(H_B)),
        ] {
            let (p, pc) = primary(H_A).await;
            let s = source(kind, resp).await;
            let out = tip_crosscheck(&pc, kind, &s.uri(), fast()).await;
            let msg = out.disagree_message().expect("disagree");
            for needle in [H_A, H_B, &p.uri(), &s.uri()] {
                assert!(msg.contains(needle), "{msg} lacks {needle}");
            }
            let err = enforce(&pc, Some(kind), Some(&s.uri()), fast())
                .await
                .unwrap_err();
            assert!(err.to_string().contains(H_B), "{err}");
        }
    }

    #[tokio::test]
    async fn source_unavailable_continues() {
        for kind in [CrossCheckSource::Blockbook, CrossCheckSource::BlockCypher] {
            for status in [404, 429, 500] {
                let (_p, pc) = primary(H_A).await;
                let s = source(kind, ResponseTemplate::new(status)).await;
                let out = tip_crosscheck(&pc, kind, &s.uri(), fast()).await;
                assert!(
                    matches!(out, CrossCheckOutcome::Unavailable { .. }),
                    "{kind:?} {status}: {out:?}"
                );
                enforce(&pc, Some(kind), Some(&s.uri()), fast())
                    .await
                    .expect("unavailable must not refuse");
            }
        }
    }

    #[tokio::test]
    async fn source_unreachable_is_unavailable() {
        let (_p, pc) = primary(H_A).await;
        // Port 1 on loopback refuses. A dropped `MockServer` is not dead: wiremock returns it
        // to a pool, and a concurrent test can mount a matching route on it.
        let base = "http://127.0.0.1:1".to_string();
        let out = tip_crosscheck(&pc, CrossCheckSource::Blockbook, &base, fast()).await;
        assert!(
            matches!(out, CrossCheckOutcome::Unavailable { .. }),
            "{out:?}"
        );
    }

    #[tokio::test]
    async fn malformed_bodies_are_unavailable_not_agree_or_disagree() {
        let bad = [
            ResponseTemplate::new(200).set_body_string("<html>oops</html>"),
            ResponseTemplate::new(200).set_body_string("{}"),
            // Blockbook's answer for a height it has not indexed.
            ResponseTemplate::new(200).set_body_string(r#"{"blockHash":""}"#),
            ResponseTemplate::new(200).set_body_string(r#"{"blockHash":"zz","hash":"12"}"#),
        ];
        for kind in [CrossCheckSource::Blockbook, CrossCheckSource::BlockCypher] {
            for resp in &bad {
                let (_p, pc) = primary(H_A).await;
                let s = source(kind, resp.clone()).await;
                let out = tip_crosscheck(&pc, kind, &s.uri(), fast()).await;
                assert!(
                    matches!(out, CrossCheckOutcome::Unavailable { .. }),
                    "{kind:?}: {out:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn malformed_primary_is_unavailable() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-a-number"))
            .mount(&s)
            .await;
        let pc = EsploraClient::new(vec![s.uri()], fast()).unwrap();
        let out = tip_crosscheck(
            &pc,
            CrossCheckSource::Blockbook,
            "http://127.0.0.1:1",
            fast(),
        )
        .await;
        assert!(
            matches!(out, CrossCheckOutcome::Unavailable { .. }),
            "{out:?}"
        );
    }

    #[tokio::test]
    async fn off_makes_no_request() {
        let (p, pc) = primary(H_A).await;
        enforce(&pc, None, None, fast()).await.unwrap();
        assert!(p.received_requests().await.unwrap().is_empty());
    }

    /// Read-only smoke against live Litecoin mainnet (GET only, no keys):
    /// `cargo test -p swap-chain-ltc --features live -- --ignored live_mainnet_agrees --nocapture`.
    #[cfg(feature = "live")]
    #[tokio::test]
    #[ignore = "network"]
    async fn live_mainnet_agrees() {
        let pc = EsploraClient::new(
            vec![crate::LITECOINSPACE_MAINNET.to_string()],
            RetryPolicy::default(),
        )
        .unwrap();
        for kind in [CrossCheckSource::Blockbook, CrossCheckSource::BlockCypher] {
            let out = tip_crosscheck(&pc, kind, kind.default_base(), RetryPolicy::default()).await;
            println!("{}: {out:?}", kind.as_str());
            assert!(
                !matches!(out, CrossCheckOutcome::Disagree { .. }),
                "{out:?}"
            );
        }
    }

    #[test]
    fn parse_values() {
        assert_eq!(CrossCheckSource::parse_opt("off"), Ok(None));
        assert_eq!(
            CrossCheckSource::parse_opt("blockbook"),
            Ok(Some(CrossCheckSource::Blockbook))
        );
        assert_eq!(
            CrossCheckSource::parse_opt("blockcypher"),
            Ok(Some(CrossCheckSource::BlockCypher))
        );
        assert!(CrossCheckSource::parse_opt("esplora").is_err());
    }
}
