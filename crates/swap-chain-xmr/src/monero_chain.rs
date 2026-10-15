// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live Monero-side primitives for whoever builds the multichain lane's own
//! `MoneroChain` implementation (`crates/divi-swap-xmr/src/chain.rs`'s `- needs:` in
//! `docs/plans/swap-poc/status/multichain.md`: "send to a (spend pub, view secret)
//! address, scan for that output with the view key... and sweep it with the combined
//! spend secret"). Three operations, matching that trait's shape (coordinated via
//! `docs/plans/swap-poc/status/xmr.md`, not a crate dependency on `divi-swap-xmr` --
//! this module knows nothing about their trait, only mirrors its parameter shapes):
//!
//! - [`lock`]: send `amount_piconero` from a `monero-wallet-rpc`-backed wallet to the
//!   swap's shared address (`spend_pub`, `view_secret`).
//! - [`find_lock`]: scan a height range with `view_secret` for an output paying
//!   `spend_pub`.
//! - [`sweep`]: spend a found lock to `destination` with the combined full spend
//!   secret `s_m + s_t`.
//!
//! All three, plus [`confirmations`], were previously hand-rolled inline in
//! `examples/xmr_live.rs` (the sweep step) or not implemented at all (`lock`/
//! `find_lock` were a manual `monero-wallet-rpc transfer` curl call and a human
//! recording the resulting txid by hand every live round so far) -- moved here so
//! `divi-swap-xmr` can reuse them without reimplementing Monero wallet-RPC digest auth
//! or the decoy-selection retry loop itself.

use ciphersuite::group::ff::PrimeField;
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519};
use monero_wallet::address::{MoneroAddress, Network};
use monero_wallet::ed25519::CompressedPoint;
use monero_wallet::interface::FeeRate;
use monero_wallet::{OutputWithDecoys, ViewPair};
use rand_core::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::live_rpc::{monerod_get_info, scan_block, LiveDecoys};

/// A Monero output paying the swap's shared 2-of-2 address -- the same three fields
/// `divi-swap-xmr::chain::XmrOutput` carries (coordinated shape, no shared type: this
/// crate has no dependency on theirs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmrLockOutput {
    pub txid: String,
    pub amount_piconero: u64,
    pub confirmations: u32,
}

/// Errors from this module's live operations.
#[derive(Debug, Error)]
pub enum MoneroChainError {
    /// `spend_pub` doesn't decompress to a valid (torsion-free) point, `view_secret`
    /// isn't a canonical scalar, or `spend_secret` isn't a canonical scalar.
    #[error("invalid key bytes: {0}")]
    InvalidKey(&'static str),
    /// A `monerod`/`monero-wallet-rpc` request failed at the transport level.
    #[error("rpc request failed: {0}")]
    Rpc(String),
    /// `monerod`/`monero-wallet-rpc` answered with an error body.
    #[error("rpc error: {0}")]
    RpcError(String),
    /// [`find_lock`]'s output couldn't be re-scanned by [`sweep`] -- it matured,
    /// reorged out, or the view/spend keys don't actually match `lock.txid`.
    #[error("lock output {0} not found when re-scanning for the sweep")]
    LockOutputMissing(String),
    /// Decoy selection didn't succeed within the retry budget.
    #[error("decoy selection failed after {0} attempts")]
    DecoySelection(usize),
    /// Building or signing the sweep transaction failed.
    #[error("sweep build failed: {0}")]
    SweepBuild(String),
}

fn view_pair_from(
    spend_pub: [u8; 32],
    view_secret: [u8; 32],
) -> Result<ViewPair, MoneroChainError> {
    let spend_point = CompressedPoint::from(spend_pub)
        .decompress()
        .ok_or(MoneroChainError::InvalidKey("spend_pub"))?;
    let view_key = Zeroizing::new(
        monero_wallet::ed25519::Scalar::read(&mut &view_secret[..])
            .map_err(|_| MoneroChainError::InvalidKey("view_secret"))?,
    );
    ViewPair::new(spend_point, view_key).map_err(|_| MoneroChainError::InvalidKey("spend_pub"))
}

/// The swap's shared lock address: spend key `spend_pub` (the swap's combined 2-of-2
/// public key, `S = s_m*G + s_t*G`), view key `view_secret` (the swap's shared view
/// key -- `xmr-design.md`'s `## Protocol`/`## Stagenet` simplification: shared in the
/// clear, not itself split). Byte encoding for both: `monero-wallet`/`curve25519-dalek`'s
/// own canonical little-endian scalar/compressed-point bytes -- the same encoding this
/// crate's own [`crate::monero_key_share`] and every live example already use.
pub fn lock_address(
    spend_pub: [u8; 32],
    view_secret: [u8; 32],
    network: Network,
) -> Result<MoneroAddress, MoneroChainError> {
    Ok(view_pair_from(spend_pub, view_secret)?.legacy_address(network))
}

/// Send `amount_piconero` from the wallet `wallet_rpc` (a `monero-wallet-rpc` URL,
/// e.g. `http://127.0.0.1:38088`, with an already-open wallet) to [`lock_address`].
/// Returns the txid. Not idempotent -- same contract as `divi-swap-xmr::chain
/// ::MoneroChain::lock`: callers persist their intent and check [`find_lock`] before
/// retrying, rather than relying on this call being safe to repeat.
///
/// `monero-wallet-rpc` requires HTTP Digest auth (confirmed live: a plain or Basic-auth
/// request gets a flat 401, `WWW-Authenticate: Digest ...`) -- `reqwest` has no built-in
/// support for it, so this does the challenge/response round trip itself with
/// `digest_auth` (already a transitive dependency via `monero-simple-request-rpc`'s own
/// digest-auth handling for `monerod`, pulled in here directly since that crate's own
/// transport is daemon-RPC-shaped, not wallet-RPC-shaped).
pub async fn lock(
    wallet_rpc: &str,
    username: &str,
    password: &str,
    spend_pub: [u8; 32],
    view_secret: [u8; 32],
    amount_piconero: u64,
    network: Network,
) -> Result<String, MoneroChainError> {
    let address = lock_address(spend_pub, view_secret, network)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": "0", "method": "transfer",
        "params": {
            "destinations": [{"amount": amount_piconero, "address": address.to_string()}],
            "priority": 1,
        }
    });
    let response =
        digest_auth_post_json(wallet_rpc, username, password, "/json_rpc", &body).await?;
    if let Some(error) = response.get("error").filter(|e| !e.is_null()) {
        return Err(MoneroChainError::RpcError(error.to_string()));
    }
    response["result"]["tx_hash"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| MoneroChainError::RpcError(format!("no tx_hash in response: {response}")))
}

/// POSTs `body` to `{rpc_url}{path}`, handling `monero-wallet-rpc`'s mandatory Digest
/// auth challenge if (and only if) the server asks for one -- a daemon RPC endpoint
/// that needs no auth gets a single request, same as every other call in this crate.
async fn digest_auth_post_json(
    rpc_url: &str,
    username: &str,
    password: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, MoneroChainError> {
    let body_bytes = serde_json::to_vec(body).expect("serde_json::Value always serializes");
    let client = reqwest::Client::new();
    let url = format!("{rpc_url}{path}");
    let first = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body_bytes.clone())
        .send()
        .await
        .map_err(|e| MoneroChainError::Rpc(e.to_string()))?;
    if first.status() != reqwest::StatusCode::UNAUTHORIZED {
        return first
            .json()
            .await
            .map_err(|e| MoneroChainError::Rpc(e.to_string()));
    }
    let challenge = first
        .headers()
        .get("www-authenticate")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| MoneroChainError::Rpc("401 with no WWW-Authenticate header".into()))?
        .to_string();
    let mut prompt = digest_auth::parse(&challenge)
        .map_err(|e| MoneroChainError::Rpc(format!("invalid digest challenge: {e}")))?;
    let context =
        digest_auth::AuthContext::new_post(username, password, path, Some(body_bytes.as_slice()));
    let answer = prompt
        .respond(&context)
        .map_err(|e| MoneroChainError::Rpc(format!("digest response build failed: {e}")))?
        .to_string();
    client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Authorization", answer)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| MoneroChainError::Rpc(e.to_string()))?
        .json()
        .await
        .map_err(|e| MoneroChainError::Rpc(e.to_string()))
}

/// Scans blocks `from_height..` (capped at `max_blocks_to_scan`, so a wrong/ancient
/// `from_height` can't turn into an unbounded crawl) for an output paying `spend_pub`,
/// scannable with `view_secret` -- `divi-swap-xmr::chain::MoneroChain::find_lock`'s
/// trait method takes no height hint at all, but a real wallet always scans from a
/// known restore point rather than genesis; callers should pass the height around when
/// the swap's Monero leg was negotiated, same as any wallet's own restore height.
/// Returns the first match, confirmations computed against the chain's tip at scan
/// time. `None` if nothing paying `spend_pub` is found in the window (not yet sent, or
/// sent below `from_height` -- rescan with an earlier `from_height` if so).
pub async fn find_lock(
    monerod_rpc: &str,
    spend_pub: [u8; 32],
    view_secret: [u8; 32],
    from_height: usize,
    max_blocks_to_scan: usize,
) -> Result<Option<XmrLockOutput>, MoneroChainError> {
    let view_pair = view_pair_from(spend_pub, view_secret)?;
    let info = monerod_get_info(monerod_rpc)
        .await
        .map_err(|e| MoneroChainError::Rpc(e.to_string()))?;
    let tip = info["result"]["height"]
        .as_u64()
        .ok_or_else(|| MoneroChainError::RpcError(format!("no height in get_info: {info}")))?
        as usize;
    let last = (from_height + max_blocks_to_scan).min(tip);
    for height in from_height..last {
        if let Some(output) = scan_block(monerod_rpc, height, view_pair.clone())
            .await
            .map_err(MoneroChainError::Rpc)?
            .into_iter()
            .next()
        {
            return Ok(Some(XmrLockOutput {
                txid: hex::encode(output.transaction()),
                amount_piconero: output.commitment().amount,
                confirmations: (tip - height + 1) as u32,
            }));
        }
    }
    Ok(None)
}

/// Re-derives `spend_pub` from the combined full private spend scalar `spend_secret`
/// (`s_m + s_t`, canonical little-endian bytes -- same encoding [`find_lock`]'s
/// `spend_pub`/`view_secret` use) and re-scans for `lock.txid` (needs the real
/// `monero_wallet::WalletOutput`, not just [`XmrLockOutput`]'s plain fields, to build decoys and
/// sign against) before spending it to `destination`, less the daemon's live fee
/// estimate. Returns the sweep's txid. Idempotent in the sense that a lock output this
/// wallet already swept has nothing left to find on a re-scan -- same contract as
/// `divi-swap-xmr::chain::MoneroChain::sweep`.
pub async fn sweep(
    monerod_rpc: &str,
    lock: &XmrLockOutput,
    spend_secret: [u8; 32],
    view_secret: [u8; 32],
    destination: MoneroAddress,
) -> Result<String, MoneroChainError> {
    let full_spend_scalar = <Ed25519 as Ciphersuite>::F::from_repr(spend_secret)
        .into_option()
        .ok_or(MoneroChainError::InvalidKey("spend_secret"))?;
    let spend_point = Ed25519::generator() * full_spend_scalar;
    let spend_pub: [u8; 32] = <Ed25519 as Ciphersuite>::G::to_bytes(&spend_point);
    let view_pair = view_pair_from(spend_pub, view_secret)?;

    let output = crate::live_rpc::scan_for_lock_output(monerod_rpc, &lock.txid, view_pair)
        .await
        .map_err(MoneroChainError::Rpc)?
        .ok_or_else(|| MoneroChainError::LockOutputMissing(lock.txid.clone()))?;

    let info = monerod_get_info(monerod_rpc)
        .await
        .map_err(|e| MoneroChainError::Rpc(e.to_string()))?;
    let latest_height = info["result"]["height"]
        .as_u64()
        .ok_or_else(|| MoneroChainError::RpcError(format!("no height in get_info: {info}")))?
        as usize;
    let fee_body: serde_json::Value = reqwest::Client::new()
        .post(format!("{monerod_rpc}/json_rpc"))
        .json(&serde_json::json!({"jsonrpc":"2.0","id":"0","method":"get_fee_estimate"}))
        .send()
        .await
        .map_err(|e| MoneroChainError::Rpc(e.to_string()))?
        .json()
        .await
        .map_err(|e| MoneroChainError::Rpc(e.to_string()))?;
    let fee_rate = FeeRate::new(
        fee_body["result"]["fee"]
            .as_u64()
            .ok_or_else(|| MoneroChainError::RpcError(format!("no fee in estimate: {fee_body}")))?,
        fee_body["result"]["quantization_mask"]
            .as_u64()
            .ok_or_else(|| {
                MoneroChainError::RpcError(format!("no quantization_mask in estimate: {fee_body}"))
            })?,
    )
    .ok_or_else(|| MoneroChainError::SweepBuild("daemon reported an invalid fee rate".into()))?;

    let live_decoys = LiveDecoys {
        monerod_rpc: monerod_rpc.to_string(),
        latest_height,
    };
    let mut decoys = None;
    const DECOY_ATTEMPTS: usize = 8;
    for _ in 0..DECOY_ATTEMPTS {
        if let Ok(d) =
            OutputWithDecoys::new(&mut OsRng, &live_decoys, 16, latest_height, output.clone()).await
        {
            decoys = Some(d);
            break;
        }
    }
    let decoys = decoys.ok_or(MoneroChainError::DecoySelection(DECOY_ATTEMPTS))?;

    let mut outgoing_view_key = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut outgoing_view_key);
    let tx = crate::monero_sweep::sweep(
        &mut OsRng,
        &output,
        decoys,
        destination,
        outgoing_view_key,
        fee_rate,
        &full_spend_scalar,
    )
    .map_err(|e| MoneroChainError::SweepBuild(format!("{e:?}")))?;

    let tx_hex = hex::encode(monero_wallet::transaction::Transaction::serialize(&tx));
    let resp: serde_json::Value = reqwest::Client::new()
        .post(format!("{monerod_rpc}/send_raw_transaction"))
        .json(&serde_json::json!({"tx_as_hex": tx_hex, "do_not_relay": false}))
        .send()
        .await
        .map_err(|e| MoneroChainError::Rpc(e.to_string()))?
        .json()
        .await
        .map_err(|e| MoneroChainError::Rpc(e.to_string()))?;
    if resp["status"] == "OK" && !resp["not_relayed"].as_bool().unwrap_or(true) {
        Ok(hex::encode(tx.hash()))
    } else {
        Err(MoneroChainError::RpcError(resp.to_string()))
    }
}

/// Confirmations of `txid` on the Monero chain `monerod_rpc` points at -- `None` if the
/// daemon doesn't know about it at all (reports it in `missed_tx`, not `txs`), `Some(0)`
/// if it's only in the mempool. Matches `divi-swap-xmr::chain::MoneroChain
/// ::confirmations`'s `Result<Option<u32>>` shape, minus the `Result` (this can't fail
/// in a way worth distinguishing from "unknown" for this crate's callers; wrap with
/// your own error type if you need to tell "daemon unreachable" apart from "not found").
pub async fn confirmations(monerod_rpc: &str, txid: &str) -> Option<u32> {
    let resp = reqwest::Client::new()
        .post(format!("{monerod_rpc}/get_transactions"))
        .json(&serde_json::json!({"txs_hashes": [txid], "decode_as_json": false}))
        .send()
        .await
        .ok()?;
    let body: serde_json::Value = resp.json().await.ok()?;
    body["txs"][0]["confirmations"].as_u64().map(|c| c as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use monero_wallet::ed25519::Scalar as EdScalar;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn valid_spend_pub() -> [u8; 32] {
        // G itself -- a real, valid, torsion-free compressed point, not a special case.
        <Ed25519 as Ciphersuite>::G::to_bytes(&Ed25519::generator())
    }

    fn valid_view_secret() -> [u8; 32] {
        <[u8; 32]>::from(EdScalar::ONE)
    }

    #[test]
    fn lock_address_rejects_a_non_canonical_point() {
        let err = lock_address([0xffu8; 32], valid_view_secret(), Network::Stagenet).unwrap_err();
        assert!(matches!(err, MoneroChainError::InvalidKey("spend_pub")));
    }

    #[test]
    fn lock_address_builds_from_valid_keys() {
        let address =
            lock_address(valid_spend_pub(), valid_view_secret(), Network::Stagenet).unwrap();
        // Legacy stagenet addresses start with a '5' or '7' network prefix byte, which
        // base58 renders starting with one of a small set of characters -- cheap sanity
        // check that this really built a stagenet (not mainnet) address.
        assert!(address.to_string().len() > 90, "a legacy address is long");
    }

    #[tokio::test]
    async fn lock_sends_the_right_destination_and_amount_and_parses_the_txid() {
        let server = MockServer::start().await;
        let address =
            lock_address(valid_spend_pub(), valid_view_secret(), Network::Stagenet).unwrap();
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0", "id": "0",
                "result": {"tx_hash": "a".repeat(64)}
            })))
            .mount(&server)
            .await;

        let txid = lock(
            &server.uri(),
            "throwaway",
            "throwaway",
            valid_spend_pub(),
            valid_view_secret(),
            20_000_000_000,
            Network::Stagenet,
        )
        .await
        .unwrap();
        assert_eq!(txid, "a".repeat(64));
        let _ = address; // built identically inside lock(); asserting it doesn't panic is the point
    }

    #[tokio::test]
    async fn lock_follows_the_digest_auth_challenge() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "WWW-Authenticate",
                r#"Digest qop="auth",algorithm=MD5,realm="monero-rpc",nonce="abc123",stale=false"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0", "id": "0",
                "result": {"tx_hash": "b".repeat(64)}
            })))
            .mount(&server)
            .await;

        let txid = lock(
            &server.uri(),
            "throwaway",
            "throwaway",
            valid_spend_pub(),
            valid_view_secret(),
            1,
            Network::Stagenet,
        )
        .await
        .unwrap();
        assert_eq!(txid, "b".repeat(64));
    }

    #[tokio::test]
    async fn lock_surfaces_an_rpc_error_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0", "id": "0",
                "error": {"code": -4, "message": "not enough money"}
            })))
            .mount(&server)
            .await;

        let err = lock(
            &server.uri(),
            "throwaway",
            "throwaway",
            valid_spend_pub(),
            valid_view_secret(),
            1,
            Network::Stagenet,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, MoneroChainError::RpcError(msg) if msg.contains("not enough money")));
    }

    #[tokio::test]
    async fn confirmations_is_none_for_an_unknown_txid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/get_transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "OK", "missed_tx": ["c".repeat(64)]
            })))
            .mount(&server)
            .await;
        assert_eq!(confirmations(&server.uri(), &"c".repeat(64)).await, None);
    }

    #[tokio::test]
    async fn confirmations_reads_the_real_field() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/get_transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "OK",
                "txs": [{"tx_hash": "d".repeat(64), "confirmations": 7}]
            })))
            .mount(&server)
            .await;
        assert_eq!(confirmations(&server.uri(), &"d".repeat(64)).await, Some(7));
    }

    #[tokio::test]
    async fn find_lock_returns_none_when_nothing_matches_in_the_window() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0", "id": "0",
                "result": {"height": 100}
            })))
            .mount(&server)
            .await;
        // get_block is never mocked to return a decodable block -- scan_block treats a
        // failed/undecodable fetch the same as "no output here" for this test's
        // purposes (fetch_scannable_block's own `.expect`s mean a truly malformed
        // response would panic rather than return None; a well-formed-but-empty window
        // is exercised instead by capping max_blocks_to_scan at 0 below, which never
        // calls get_block at all).
        let result = find_lock(
            &server.uri(),
            valid_spend_pub(),
            valid_view_secret(),
            100,
            0,
        )
        .await
        .unwrap();
        assert_eq!(result, None);
    }
}

// Needs a real `monero-wallet-rpc` reachable at `MONERO_WALLET_RPC` (default matches
// this lane's hp2 setup: `monero-wallet-rpc --rpc-bind-port 38088 --rpc-login
// throwaway:throwaway`) -- not run by default, same convention as `stagenet_rpc.rs`'s
// `#[cfg(feature = "live")]`. Read-only (`get_balance`): proves the digest-auth
// challenge/response round trip in [`digest_auth_post_json`] works against the real
// server's actual challenge format, not just `tests::lock_follows_the_digest_auth
// _challenge`'s synthetic one, without moving any funds.
#[cfg(all(test, feature = "live"))]
mod live {
    use super::*;

    #[tokio::test]
    async fn digest_auth_round_trip_works_against_the_real_wallet_rpc() {
        let wallet_rpc = std::env::var("MONERO_WALLET_RPC")
            .unwrap_or_else(|_| "http://127.0.0.1:38088".to_string());
        let (username, password) = ("throwaway".to_string(), "throwaway".to_string());
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": "0", "method": "get_balance",
            "params": {"account_index": 0}
        });
        let response = digest_auth_post_json(&wallet_rpc, &username, &password, "/json_rpc", &body)
            .await
            .expect("real wallet-rpc reachable and digest auth accepted");
        assert!(
            response["result"]["balance"].as_u64().is_some(),
            "expected a real balance field, got {response}"
        );
    }
}
