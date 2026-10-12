// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Shared live-RPC glue for every live example (`examples/xmr_live.rs`,
//! `examples/xmr_live_refund.rs`): talking to a public, **restricted** Monero
//! stagenet node (`monero-daemon-rpc` 0.2.0 ships no `ProvidesDecoys` or
//! scannable-block implementation for a live daemon -- checked its source directly;
//! every RPC call below is hand-rolled and was verified live against
//! `node.monerodevs.org:38089` before being written, not guessed) and the DIVI
//! testnet RPC proxy. Pulled out of `xmr_live.rs` once a second live example needed
//! the exact same machinery, so the three real bugs already found and fixed here
//! (DIVI tx version policy lives in the examples, not here, but the Monero-side
//! fixes below do) don't get a chance to silently diverge between two copies.

use monero_wallet::block::Block;
use monero_wallet::ed25519::Point;
use monero_wallet::interface::{
    EvaluateUnlocked, InterfaceError, ProvidesBlockchainMeta, ProvidesUnvalidatedDecoys,
    ScannableBlock, TransactionsError,
};
use monero_wallet::{Scanner, ViewPair, WalletOutput};
use swap_chain_divi::RpcClient;

/// A public, restricted stagenet node -- no local monerod on hp2 (the hp2-local sync
/// crawled at ~75 blocks/min, months to finish; self-mining happens against public
/// nodes via `get_block_template`/`submit_block`, outside this binary). Talked to only
/// through the ordinary restricted RPC surface (`get_info`, `get_transactions`,
/// `get_output_distribution`, `get_outs`, `get_block`, `send_raw_transaction`) -- no
/// `start_mining`, no other local-only/trusted-only methods.
pub const MONEROD_RPC_DEFAULT: &str = "http://node.monerodevs.org:38089";
// Fallback if the primary node above is unreachable: override via MONEROD_RPC=http://stagenet.xmr-tw.org:38081.

/// `get_info` over `/json_rpc` -- available on restricted public nodes exactly like
/// trusted/local ones (checked live against `node.monerodevs.org:38089` and
/// `stagenet.xmr-tw.org:38081`, both `"restricted": true` and both answer it fine).
pub async fn monerod_get_info(monerod_rpc: &str) -> reqwest::Result<serde_json::Value> {
    reqwest::Client::new()
        .post(format!("{monerod_rpc}/json_rpc"))
        .json(&serde_json::json!({"jsonrpc":"2.0","id":"0","method":"get_info"}))
        .send()
        .await?
        .json()
        .await
}

/// Whether a DIVI testnet transaction has at least one confirmation
/// (`getrawtransaction` against the testnet RPC proxy).
pub async fn check_divi_confirmed(rpc: &RpcClient, txid: &str) -> bool {
    match rpc
        .call_ok("getrawtransaction", serde_json::json!([txid, 1]))
        .await
    {
        Ok(v) => v.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0) >= 1,
        Err(_) => false,
    }
}

/// Monero's real `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`: an ordinary (non-coinbase)
/// output needs this many confirmations before it's actually usable as a transaction
/// *input* -- a stricter bar than merely being confirmed at all. Found live: a sweep
/// broadcast against a lock output with only 1 confirmation was rejected
/// (`"invalid_input": true`) by the daemon; [`check_xmr_confirmed`]'s default
/// single-confirmation check is correct for "did the funding tx land" but not for
/// "is this output spendable yet" -- use [`check_xmr_spendable`] for the latter.
pub const SPENDABLE_AGE: u64 = 10;

/// Whether `txid` has at least `min_confirmations`, via the restricted-node-safe
/// `get_transactions` RPC (confirmed live against `node.monerodevs.org:38089`:
/// reachable, returns a real `confirmations` field per tx, not blocked by the node's
/// restricted mode -- same posture as [`check_divi_confirmed`]'s `getrawtransaction`
/// on the DIVI side). Scanning for the actual *output* (not just confirming the
/// funding tx exists) is [`scan_for_lock_output`]'s job.
pub async fn check_xmr_confirmed_n(monerod_rpc: &str, txid: &str, min_confirmations: u64) -> bool {
    let resp = reqwest::Client::new()
        .post(format!("{monerod_rpc}/get_transactions"))
        .json(&serde_json::json!({"txs_hashes": [txid], "decode_as_json": false}))
        .send()
        .await;
    match resp {
        Ok(r) => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            body["txs"][0]["confirmations"].as_u64().unwrap_or(0) >= min_confirmations
        }
        Err(e) => {
            println!("Monero: daemon unreachable ({e}) -- is {monerod_rpc} up?");
            false
        }
    }
}

/// Whether `txid` has landed at all (at least one confirmation) -- "did the funding
/// transaction land", not "is its output spendable yet" (see [`check_xmr_spendable`]
/// for the latter, stricter check).
pub async fn check_xmr_confirmed(monerod_rpc: &str, txid: &str) -> bool {
    check_xmr_confirmed_n(monerod_rpc, txid, 1).await
}

/// Whether `txid`'s output has matured past [`SPENDABLE_AGE`] confirmations -- the
/// real bar for using it as a transaction input, not just "it landed".
pub async fn check_xmr_spendable(monerod_rpc: &str, txid: &str) -> bool {
    check_xmr_confirmed_n(monerod_rpc, txid, SPENDABLE_AGE).await
}

/// Real decoy source for `monero_wallet::OutputWithDecoys::new`, backed by the
/// daemon's ordinary (non-trusted) RPC surface -- `get_output_distribution` and
/// `get_outs`, the same calls any Monero wallet uses against a remote node it doesn't
/// control. Confirmed live against `node.monerodevs.org:38089`: both reachable and
/// return real, directly-usable data on a *restricted* node.
pub struct LiveDecoys {
    pub monerod_rpc: String,
    pub latest_height: usize,
}

impl ProvidesBlockchainMeta for LiveDecoys {
    fn latest_block_number(
        &self,
    ) -> impl Send + std::future::Future<Output = Result<usize, InterfaceError>> {
        async move { Ok(self.latest_height) }
    }
}

impl ProvidesUnvalidatedDecoys for LiveDecoys {
    fn ringct_output_distribution(
        &self,
        _range: impl Send + std::ops::RangeBounds<usize>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u64>, InterfaceError>> {
        let monerod_rpc = self.monerod_rpc.clone();
        // Bounded to the last 100,000 blocks rather than the full chain: the full
        // distribution is ~17MB on stagenet's current height and unreliable to fetch
        // in one request (seen live: intermittent "error decoding response body"/
        // connection drops); `select_n`'s algorithm only uses relative position within
        // whatever's returned, so a bounded recent window -- still >>
        // DEFAULT_LOCK_WINDOW -- works identically, just smaller and reliable.
        let from_height = self.latest_height.saturating_sub(100_000);
        async move {
            let body: serde_json::Value = reqwest::Client::new()
                .post(format!("{monerod_rpc}/json_rpc"))
                .json(&serde_json::json!({
                    "jsonrpc": "2.0", "id": "0", "method": "get_output_distribution",
                    "params": {"amounts": [0], "cumulative": true, "binary": false, "from_height": from_height}
                }))
                .send()
                .await
                .map_err(|e| InterfaceError::InterfaceError(e.to_string()))?
                .json()
                .await
                .map_err(|e| InterfaceError::InterfaceError(e.to_string()))?;
            body["result"]["distributions"][0]["distribution"]
                .as_array()
                .ok_or_else(|| InterfaceError::InvalidInterface("missing distribution".into()))?
                .iter()
                .map(|v| {
                    v.as_u64()
                        .ok_or_else(|| InterfaceError::InvalidInterface("non-u64 entry".into()))
                })
                .collect()
        }
    }

    fn unlocked_ringct_outputs(
        &self,
        indexes: &[u64],
        _evaluate_unlocked: EvaluateUnlocked,
    ) -> impl Send + std::future::Future<Output = Result<Vec<Option<[Point; 2]>>, TransactionsError>>
    {
        let monerod_rpc = self.monerod_rpc.clone();
        let outputs: Vec<_> = indexes
            .iter()
            .map(|i| serde_json::json!({"amount": 0, "index": i}))
            .collect();
        async move {
            let body: serde_json::Value = reqwest::Client::new()
                .post(format!("{monerod_rpc}/get_outs"))
                .json(&serde_json::json!({"outputs": outputs, "get_txid": false}))
                .send()
                .await
                .map_err(|e| InterfaceError::InterfaceError(e.to_string()))?
                .json()
                .await
                .map_err(|e| InterfaceError::InterfaceError(e.to_string()))?;
            let outs = body["outs"]
                .as_array()
                .ok_or_else(|| InterfaceError::InvalidInterface("missing outs".into()))?;
            Ok(outs
                .iter()
                .map(|o| {
                    if !o["unlocked"].as_bool().unwrap_or(false) {
                        return None;
                    }
                    let key = decode_point(o["key"].as_str()?)?;
                    let commitment = decode_point(o["mask"].as_str()?)?;
                    Some([key, commitment])
                })
                .collect())
        }
    }
}

/// A compressed Ed25519 point from hex, decompressed -- `None` on any malformed or
/// off-curve input (treated as an unusable candidate, same as `select_n`'s own
/// torsion/identity filtering does for its other failure modes).
pub fn decode_point(hex_str: &str) -> Option<Point> {
    let bytes: [u8; 32] = hex::decode(hex_str).ok()?.try_into().ok()?;
    monero_wallet::ed25519::CompressedPoint::from(bytes).decompress()
}

/// Fetches block `height` and wraps it as a `ScannableBlock` -- the block's own blob
/// (decoded directly into a `Block`, including its miner transaction) plus the full
/// bytes of every other transaction in it, plus the global output index of the first
/// RingCT output in the block (taken from the miner transaction's own
/// `output_indices`, which `get_transactions` reports directly -- stagenet's current
/// height is long past the point where every miner transaction is V2/RingCT, so this
/// skips the more general "scan forward for the first V2 tx" case
/// `monero_wallet::interface::ExpandToScannableBlock` handles, since it isn't needed
/// here).
pub async fn fetch_scannable_block(monerod_rpc: &str, height: usize) -> ScannableBlock {
    let client = reqwest::Client::new();
    let block_body: serde_json::Value = client
        .post(format!("{monerod_rpc}/json_rpc"))
        .json(&serde_json::json!({"jsonrpc":"2.0","id":"0","method":"get_block","params":{"height":height}}))
        .send()
        .await
        .expect("get_block reachable")
        .json()
        .await
        .expect("get_block returns JSON");
    let blob = block_body["result"]["blob"]
        .as_str()
        .expect("block has a blob");
    let block = Block::read(&mut hex::decode(blob).expect("blob is hex").as_slice())
        .expect("blob is a valid block");
    let miner_tx_hash = block_body["result"]["miner_tx_hash"]
        .as_str()
        .expect("get_block reports miner_tx_hash")
        .to_string();

    let mut hashes = vec![miner_tx_hash.clone()];
    hashes.extend(block.transactions.iter().map(hex::encode));
    let txs_body: serde_json::Value = client
        .post(format!("{monerod_rpc}/get_transactions"))
        .json(&serde_json::json!({"txs_hashes": hashes, "decode_as_json": false, "prune": false}))
        .send()
        .await
        .expect("get_transactions reachable")
        .json()
        .await
        .expect("get_transactions returns JSON");
    let txs = txs_body["txs"].as_array().expect("txs array present");
    assert_eq!(
        txs.len(),
        hashes.len(),
        "get_transactions returned a different tx count"
    );

    let output_index_for_first_ringct_output = txs[0]["output_indices"][0]
        .as_u64()
        .expect("miner tx has a first output index");
    // `pruned_as_hex` is empty for ordinary (non-coinbase) transactions on this node --
    // only coinbase transactions have no prunable signature data, making their pruned
    // and full forms identical, which is why that field happens to work for the miner
    // transaction above but not here. `as_hex` (requested in full via `"prune": false`)
    // is reliably populated instead; read it as `NotPruned` and convert, same as any
    // other full transaction.
    let transactions = txs[1..]
        .iter()
        .map(|t| {
            let hex_str = t["as_hex"].as_str().expect("as_hex present");
            monero_wallet::transaction::Transaction::<monero_wallet::transaction::NotPruned>::read(
                &mut hex::decode(hex_str).expect("tx hex valid").as_slice(),
            )
            .expect("valid transaction")
            .into()
        })
        .collect();

    ScannableBlock {
        block,
        transactions,
        output_index_for_first_ringct_output: Some(output_index_for_first_ringct_output),
    }
}

/// Scans the block containing `txid` with `view_pair`, returning the one output in it
/// that belongs to us -- `None` if `txid` isn't confirmed yet or doesn't contain an
/// output we can see.
pub async fn scan_for_lock_output(
    monerod_rpc: &str,
    txid: &str,
    view_pair: ViewPair,
) -> Option<WalletOutput> {
    let tx_body: serde_json::Value = reqwest::Client::new()
        .post(format!("{monerod_rpc}/get_transactions"))
        .json(&serde_json::json!({"txs_hashes": [txid], "decode_as_json": false}))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let height = tx_body["txs"][0]["block_height"].as_u64()? as usize;
    let block = fetch_scannable_block(monerod_rpc, height).await;
    let mut scanner = Scanner::new(view_pair);
    let outputs = scanner.scan(block).ok()?.not_additionally_locked();
    let txid_bytes: [u8; 32] = hex::decode(txid).ok()?.try_into().ok()?;
    outputs.into_iter().find(|o| o.transaction() == txid_bytes)
}

// Gated behind the `live` feature, same convention as `stagenet_rpc.rs`'s
// `#[cfg(feature = "live")] mod live` -- these hit the real network, so the feature
// gate alone (no `#[ignore]` needed) keeps them out of a plain `cargo test`.
#[cfg(all(test, feature = "live"))]
mod tests {
    //! Validates the live-RPC scanning/decoy machinery against the real public node,
    //! independent of any particular swap's own funds -- run with
    //! `cargo test -p swap-chain-xmr --features live live_rpc`.

    use super::*;

    #[tokio::test]
    async fn fetch_scannable_block_decodes_a_real_block() {
        let info = monerod_get_info(MONEROD_RPC_DEFAULT)
            .await
            .expect("get_info reachable");
        let height = info["result"]["height"].as_u64().expect("height present") as usize - 5;
        let block = fetch_scannable_block(MONEROD_RPC_DEFAULT, height).await;
        assert_eq!(block.block.number(), height);
        assert!(block.output_index_for_first_ringct_output.is_some());
    }

    /// A block containing only a coinbase (no ordinary transactions) doesn't exercise
    /// the non-miner decode path at all -- which is exactly how an earlier version of
    /// `fetch_scannable_block` shipped with a real bug (it read `pruned_as_hex`, which
    /// this node leaves empty for ordinary transactions -- only coinbase transactions
    /// have no prunable signature data, making their pruned and full forms identical,
    /// which is why the bug didn't show up until a transaction actually needed it) and
    /// this test's predecessor still passed, since its randomly-chosen recent block
    /// happened to have zero ordinary transactions. Block 2,227,378 is a real, fixed
    /// stagenet block containing a real transaction (this lane's own 0.1 XMR transfer
    /// into the forward swap's 2-of-2 lock address) specifically to exercise that path.
    #[tokio::test]
    async fn fetch_scannable_block_decodes_a_block_with_a_real_transaction() {
        let block = fetch_scannable_block(MONEROD_RPC_DEFAULT, 2_227_378).await;
        assert_eq!(block.block.number(), 2_227_378);
        assert_eq!(
            block.transactions.len(),
            1,
            "this block has exactly one ordinary tx"
        );
    }

    #[tokio::test]
    async fn live_decoys_distribution_and_outs_are_real() {
        let info = monerod_get_info(MONEROD_RPC_DEFAULT)
            .await
            .expect("get_info reachable");
        let latest_height = info["result"]["height"].as_u64().expect("height present") as usize;
        let live = LiveDecoys {
            monerod_rpc: MONEROD_RPC_DEFAULT.to_string(),
            latest_height,
        };

        let distribution = live
            .ringct_output_distribution(..)
            .await
            .expect("distribution fetch");
        assert!(
            distribution.len() > 1000,
            "expected a real, large distribution"
        );
        assert!(distribution.is_sorted(), "distribution must be monotonic");

        // A known-real, known-unlocked (deep enough) output index, confirmed live via
        // get_outs before writing this test.
        let known_index = distribution[distribution.len() / 2];
        let outs = live
            .unlocked_ringct_outputs(&[known_index], EvaluateUnlocked::Normal)
            .await
            .expect("get_outs fetch");
        assert_eq!(outs.len(), 1);
        assert!(
            outs[0].is_some(),
            "a deep, real output index should be unlocked"
        );
    }
}
