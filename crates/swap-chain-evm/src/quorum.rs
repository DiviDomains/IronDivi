// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Reconciling a USDC read made on two EVM nodes ([`crate::UsdcBackend::with_quorum_rpc`]).
//!
//! Rule (docs/plans/swap-poc/single-source-design.md, USDC/EVM; the DIVI shape in
//! `swap-chain-divi/src/second_source.rs`): two nodes that disagree on a read a claim or
//! refund rests on are never a decision. The answer is `SwapError::Held`, which the engine
//! retries like `Transient` and, in front of a refund, reads on the primary alone once the
//! refund's deadline passes (`divi_swap` `hold.rs`, EV).
//!
//! - Existence: `Some` on one node and `None` on the other is a disagreement.
//! - A lock (`htlc_output`): each node checks the `Locked` log's parties, token, hashlock and
//!   timelock against the swap itself, so a node whose log differs answers `None` and the
//!   pair disagrees on existence; the amounts must then be equal. Confirmations: the smaller.
//! - A spend (`find_spend`): the same spending txid, block height and witness (the preimage).
//! - `confirmations`: two counts are the smaller one (nodes a block apart are ordinary lag).
//! - `median_time_past`: the smaller latest-block timestamp, never a disagreement, so a refund
//!   is never early on one node's word.
//! - A second node that fails to answer is `Held` (fail closed: one view is not enough).
//!   A primary that fails returns its own error, as with no second node; the second node is
//!   then not asked.

use divi_swap::{LockedOutput, SpendInfo, SwapError};

type Result<T> = std::result::Result<T, SwapError>;

/// The engine logs a `Held` read and retries it, so the message names both answers.
fn disagree(op: &str, detail: String) -> SwapError {
    SwapError::Held(format!("{op}: USDC nodes disagree: {detail}"))
}

/// The second node's answer, or `Held` if it gave none.
pub(crate) fn second<T>(op: &str, answer: Result<T>) -> Result<T> {
    answer.map_err(|e| disagree(op, format!("second node failed: {e}")))
}

pub(crate) fn agree_confirmations(a: Option<u32>, b: Option<u32>) -> Result<Option<u32>> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) => Ok(Some(a.min(b))),
        (a, b) => Err(disagree(
            "confirmations",
            format!("primary {a:?}, second {b:?}"),
        )),
    }
}

pub(crate) fn agree_htlc_output(
    a: Option<LockedOutput>,
    b: Option<LockedOutput>,
) -> Result<Option<LockedOutput>> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) if a.amount == b.amount => Ok(Some(LockedOutput {
            amount: a.amount,
            confirmations: a.confirmations.min(b.confirmations),
        })),
        (a, b) => Err(disagree(
            "htlc_output",
            format!(
                "primary {}, second {}",
                describe_lock(a.as_ref()),
                describe_lock(b.as_ref())
            ),
        )),
    }
}

fn describe_lock(l: Option<&LockedOutput>) -> String {
    l.map_or_else(
        || "no matching lock".into(),
        |l| format!("a lock of {}", l.amount),
    )
}

pub(crate) fn agree_spend(a: Option<SpendInfo>, b: Option<SpendInfo>) -> Result<Option<SpendInfo>> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(a), Some(b))
            if a.txid == b.txid && a.height == b.height && a.witness == b.witness =>
        {
            Ok(Some(a))
        }
        (a, b) => Err(disagree(
            "find_spend",
            format!(
                "primary {}, second {}",
                describe_spend(a.as_ref()),
                describe_spend(b.as_ref())
            ),
        )),
    }
}

fn describe_spend(s: Option<&SpendInfo>) -> String {
    s.map_or_else(
        || "no spend".into(),
        |s| {
            let kind = if s.witness.is_empty() {
                "refund"
            } else {
                "claim"
            };
            format!("{kind} {} at {:?}", s.txid, s.height)
        },
    )
}

/// The smaller of two latest-block timestamps.
pub(crate) fn agree_mtp(a: u32, b: u32) -> u32 {
    a.min(b)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use alloy::primitives::{Address, LogData, B256, U256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::sol_types::SolEvent;
    use divi_swap::{ChainBackend, HtlcParams, Outpoint, SwapError, Txid};
    use serde_json::{json, Value};

    use crate::client::swap_id;
    use crate::contract::IErc20Htlc;
    use crate::UsdcBackend;

    const HTLC: Address = Address::repeat_byte(0x11);
    const TOKEN: Address = Address::repeat_byte(0x22);
    const LOCKTIME: u32 = 1_800_000_000;
    const UNITS: u64 = 25_000_000; // 25 USDC
    const LOCK_TX: B256 = B256::repeat_byte(0xa1);
    const CLAIM_TX: B256 = B256::repeat_byte(0xc1);
    const PREIMAGE: B256 = B256::repeat_byte(0x5e);

    /// A read-only JSON-RPC node: a tip, the latest block's timestamp, receipts by hash and
    /// logs answered to `eth_getLogs` by event signature. Counts every request it gets.
    #[derive(Clone)]
    struct ChainNode {
        tip: u64,
        timestamp: u64,
        receipts: HashMap<B256, Value>,
        logs: Vec<Value>,
        requests: Arc<AtomicU64>,
    }

    impl ChainNode {
        fn new(tip: u64) -> Self {
            Self {
                tip,
                timestamp: u64::from(LOCKTIME) - 3600,
                receipts: HashMap::new(),
                logs: Vec::new(),
                requests: Arc::default(),
            }
        }

        fn requests(&self) -> u64 {
            self.requests.load(Ordering::SeqCst)
        }
    }

    fn hex_u64(n: u64) -> Value {
        json!(format!("0x{n:x}"))
    }

    fn rpc_log(data: &LogData, tx: B256, block: u64) -> Value {
        json!({
            "address": HTLC,
            "topics": data.topics(),
            "data": data.data,
            "blockHash": B256::repeat_byte(0xbb),
            "blockNumber": hex_u64(block),
            "transactionHash": tx,
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false,
        })
    }

    fn receipt(tx: B256, block: u64, logs: Vec<Value>) -> Value {
        json!({
            "transactionHash": tx,
            "transactionIndex": "0x0",
            "blockHash": B256::repeat_byte(0xbb),
            "blockNumber": hex_u64(block),
            "from": Address::repeat_byte(0x33),
            "to": HTLC,
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3b9aca00",
            "contractAddress": null,
            "logs": logs,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "status": "0x1",
            "type": "0x2",
        })
    }

    fn latest_block(n: &ChainNode) -> Value {
        let zero32 = B256::ZERO;
        json!({
            "hash": B256::repeat_byte(0xbc),
            "parentHash": zero32,
            "sha3Uncles": zero32,
            "miner": Address::ZERO,
            "stateRoot": zero32,
            "transactionsRoot": zero32,
            "receiptsRoot": zero32,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "difficulty": "0x0",
            "number": hex_u64(n.tip),
            "gasLimit": "0x1c9c380",
            "gasUsed": "0x0",
            "timestamp": hex_u64(n.timestamp),
            "extraData": "0x",
            "mixHash": zero32,
            "nonce": "0x0000000000000000",
            "baseFeePerGas": "0x3b9aca00",
            "uncles": [],
            "transactions": [],
        })
    }

    impl wiremock::Respond for ChainNode {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            self.requests.fetch_add(1, Ordering::SeqCst);
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let result = match body["method"].as_str().unwrap_or("") {
                "eth_blockNumber" => hex_u64(self.tip),
                "eth_getBlockByNumber" => latest_block(self),
                "eth_getTransactionReceipt" | "eth_getTransactionByHash" => {
                    let hash: B256 = serde_json::from_value(body["params"][0].clone()).unwrap();
                    match body["method"].as_str() {
                        Some("eth_getTransactionReceipt") => {
                            self.receipts.get(&hash).cloned().unwrap_or(Value::Null)
                        }
                        _ => Value::Null, // nothing pending
                    }
                }
                "eth_getLogs" => {
                    let want = &body["params"][0]["topics"][0];
                    Value::Array(
                        self.logs
                            .iter()
                            .filter(|l| &l["topics"][0] == want)
                            .cloned()
                            .collect(),
                    )
                }
                other => {
                    return wiremock::ResponseTemplate::new(200).set_body_json(json!({
                        "jsonrpc": "2.0", "id": body["id"],
                        "error": {"code": -32601, "message": format!("unmocked {other}")},
                    }))
                }
            };
            wiremock::ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
        }
    }

    async fn serve(node: &ChainNode) -> wiremock::MockServer {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(node.clone())
            .mount(&server)
            .await;
        server
    }

    fn key(byte: u8) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn pubkey(byte: u8) -> [u8; 33] {
        key(byte)
            .public_key(&secp256k1::Secp256k1::new())
            .serialize()
    }

    fn address(byte: u8) -> Address {
        PrivateKeySigner::from_slice(&[byte; 32]).unwrap().address()
    }

    /// The swap: sender (refund key) 7, receiver (claim key) 8.
    fn htlc() -> HtlcParams {
        HtlcParams {
            hash: [0xab; 32],
            claim_pubkey: pubkey(8),
            refund_pubkey: pubkey(7),
            locktime: LOCKTIME,
            script_version: Default::default(),
        }
    }

    fn lock_outpoint() -> Outpoint {
        Outpoint {
            txid: Txid(LOCK_TX.0),
            vout: 0,
        }
    }

    fn swap_id_of(units: u64) -> B256 {
        swap_id(
            address(7),
            address(8),
            TOKEN,
            U256::from(units),
            B256::from([0xab; 32]),
            U256::from(LOCKTIME),
        )
    }

    /// The `Locked` log of [`htlc`] at `units`, in [`LOCK_TX`].
    fn lock_receipt(units: u64, block: u64) -> Value {
        let data = IErc20Htlc::Locked {
            id: swap_id_of(units),
            sender: address(7),
            receiver: address(8),
            token: TOKEN,
            amount: U256::from(units),
            hashlock: B256::from([0xab; 32]),
            timelock: U256::from(LOCKTIME),
        }
        .encode_log_data();
        receipt(LOCK_TX, block, vec![rpc_log(&data, LOCK_TX, block)])
    }

    /// A node that holds the lock at block 100 (tip `tip`).
    fn with_lock(tip: u64) -> ChainNode {
        let mut n = ChainNode::new(tip);
        n.receipts.insert(LOCK_TX, lock_receipt(UNITS, 100));
        n
    }

    /// Adds the receiver's claim of the lock, in [`CLAIM_TX`] at block 105.
    fn claimed(mut n: ChainNode) -> ChainNode {
        let data = IErc20Htlc::Claimed {
            id: swap_id_of(UNITS),
            preimage: PREIMAGE,
        }
        .encode_log_data();
        n.logs.push(rpc_log(&data, CLAIM_TX, 105));
        n.receipts
            .insert(CLAIM_TX, receipt(CLAIM_TX, 105, Vec::new()));
        n
    }

    fn single(primary: &wiremock::MockServer) -> UsdcBackend {
        UsdcBackend::new(&primary.uri(), PrivateKeySigner::random(), HTLC, TOKEN).unwrap()
    }

    fn quorum(primary: &wiremock::MockServer, second: &str) -> UsdcBackend {
        single(primary).with_quorum_rpc(second).unwrap()
    }

    /// Both nodes served, the backend reading both.
    async fn pair(
        primary: &ChainNode,
        second: &ChainNode,
    ) -> (wiremock::MockServer, wiremock::MockServer, UsdcBackend) {
        let (p, s) = (serve(primary).await, serve(second).await);
        let backend = quorum(&p, &s.uri());
        (p, s, backend)
    }

    /// The primary hides the taker's claim; the second node has it. One node's silence must
    /// not read as "unspent" (the maker would wait out its own lock's timelock while the
    /// taker holds the preimage).
    #[tokio::test]
    async fn find_spend_hidden_by_the_primary_is_held() {
        let (_p, _s, backend) = pair(&with_lock(110), &claimed(with_lock(110))).await;
        assert_held(
            backend.find_spend(&lock_outpoint(), 100).await,
            "claim only on second",
        );
        let (_p, _s, backend) = pair(&claimed(with_lock(110)), &with_lock(110)).await;
        assert_held(
            backend.find_spend(&lock_outpoint(), 100).await,
            "claim only on primary",
        );
    }

    /// Two nodes that both show the claim agree: the claim, with its preimage.
    #[tokio::test]
    async fn find_spend_seen_by_both_is_the_claim() {
        let (_p, _s, backend) = pair(&claimed(with_lock(110)), &claimed(with_lock(111))).await;
        let spend = backend
            .find_spend(&lock_outpoint(), 100)
            .await
            .unwrap()
            .expect("claim");
        assert_eq!(spend.txid, Txid(CLAIM_TX.0));
        assert_eq!(spend.height, Some(105));
        assert_eq!(spend.witness, vec![PREIMAGE.to_vec()]);
        let (_p, _s, backend) = pair(&with_lock(110), &with_lock(110)).await;
        assert_eq!(
            backend.find_spend(&lock_outpoint(), 100).await.unwrap(),
            None
        );
    }

    /// The primary says the lock was refunded, the second node that it was claimed: two
    /// spending txids. The message names both answers.
    #[tokio::test]
    async fn find_spend_with_two_spending_txids_is_held_and_names_both() {
        const REFUND_TX: B256 = B256::repeat_byte(0xd1);
        let mut refunded = with_lock(110);
        let data = IErc20Htlc::Refunded {
            id: swap_id_of(UNITS),
        }
        .encode_log_data();
        refunded.logs.push(rpc_log(&data, REFUND_TX, 106));
        let (_p, _s, backend) = pair(&refunded, &claimed(with_lock(110))).await;
        match backend.find_spend(&lock_outpoint(), 100).await {
            Err(SwapError::Held(msg)) => {
                assert!(msg.contains("disagree"), "{msg}");
                assert!(
                    msg.contains(&Txid(REFUND_TX.0).to_string()),
                    "refund txid missing: {msg}"
                );
                assert!(
                    msg.contains(&Txid(CLAIM_TX.0).to_string()),
                    "claim txid missing: {msg}"
                );
            }
            other => panic!("expected Held, got {other:?}"),
        }
    }

    /// The primary reports a lock the second node does not have, or has at another amount.
    #[tokio::test]
    async fn htlc_output_seen_by_one_node_or_at_two_amounts_is_held() {
        let (_p, _s, backend) = pair(&with_lock(110), &ChainNode::new(110)).await;
        assert_held(
            backend.htlc_output(&htlc(), &lock_outpoint()).await,
            "lock only on primary",
        );
        let mut other_amount = ChainNode::new(110);
        other_amount
            .receipts
            .insert(LOCK_TX, lock_receipt(UNITS / 2, 100));
        let (_p, _s, backend) = pair(&with_lock(110), &other_amount).await;
        assert_held(
            backend.htlc_output(&htlc(), &lock_outpoint()).await,
            "lock at another amount",
        );
        let (_p, _s, backend) = pair(&ChainNode::new(110), &with_lock(110)).await;
        assert_held(
            backend.htlc_output(&htlc(), &lock_outpoint()).await,
            "lock only on second",
        );
    }

    /// Both nodes show the same lock; one is a block behind. The lower count is used.
    #[tokio::test]
    async fn htlc_output_seen_by_both_takes_the_lower_confirmation_count() {
        let (_p, _s, backend) = pair(&with_lock(110), &with_lock(109)).await;
        let out = backend
            .htlc_output(&htlc(), &lock_outpoint())
            .await
            .unwrap()
            .expect("lock");
        assert_eq!(out.amount.to_sat(), UNITS * 100);
        assert_eq!(out.confirmations, 10);
    }

    /// The primary's latest block is past the timelock, the second node's well before it: a
    /// refund is never early on one node's word, so the smaller timestamp is the answer.
    #[tokio::test]
    async fn median_time_past_is_the_smaller_of_the_two() {
        let mut ahead = ChainNode::new(110);
        ahead.timestamp = u64::from(LOCKTIME) + 3600;
        let mut behind = ChainNode::new(110);
        behind.timestamp = u64::from(LOCKTIME) - 3600;
        let (_p, _s, backend) = pair(&ahead, &behind).await;
        let mtp = backend.median_time_past().await.unwrap();
        assert_eq!(mtp, LOCKTIME - 3600);
        assert!(!backend.refund_final(mtp, LOCKTIME));
        let (_p, _s, backend) = pair(&behind, &ahead).await;
        assert_eq!(backend.median_time_past().await.unwrap(), LOCKTIME - 3600);
    }

    /// The primary has a receipt for a transaction the second node does not know.
    #[tokio::test]
    async fn confirmations_known_to_one_node_is_held() {
        let (_p, _s, backend) = pair(&with_lock(110), &ChainNode::new(110)).await;
        assert_held(
            backend.confirmations(&Txid(LOCK_TX.0)).await,
            "primary only",
        );
        let (_p, _s, backend) = pair(&ChainNode::new(110), &with_lock(110)).await;
        assert_held(backend.confirmations(&Txid(LOCK_TX.0)).await, "second only");
    }

    /// Two counts a block apart are lag, not a disagreement: the smaller is used. Unknown to
    /// both is `None`.
    #[tokio::test]
    async fn confirmations_known_to_both_takes_the_smaller() {
        let (_p, _s, backend) = pair(&with_lock(110), &with_lock(109)).await;
        assert_eq!(
            backend.confirmations(&Txid(LOCK_TX.0)).await.unwrap(),
            Some(10)
        );
        let (_p, _s, backend) = pair(&with_lock(109), &with_lock(110)).await;
        assert_eq!(
            backend.confirmations(&Txid(LOCK_TX.0)).await.unwrap(),
            Some(10)
        );
        let (_p, _s, backend) = pair(&ChainNode::new(110), &ChainNode::new(110)).await;
        assert_eq!(
            backend.confirmations(&Txid(CLAIM_TX.0)).await.unwrap(),
            None
        );
    }

    /// A second node that does not answer fails the read closed: `Held`, never the
    /// primary's answer alone.
    #[tokio::test]
    async fn an_unreachable_second_node_is_held() {
        let p = serve(&claimed(with_lock(110))).await;
        let backend = quorum(&p, "http://127.0.0.1:1");
        assert_held(
            backend.find_spend(&lock_outpoint(), 100).await,
            "find_spend",
        );
        assert_held(
            backend.htlc_output(&htlc(), &lock_outpoint()).await,
            "htlc_output",
        );
        assert_held(
            backend.confirmations(&Txid(LOCK_TX.0)).await,
            "confirmations",
        );
        assert_held(backend.median_time_past().await, "median_time_past");
    }

    /// Quorum off (the default): every read is the primary's, with the requests it made on
    /// 95699a5, and the second node is never asked.
    #[tokio::test]
    async fn without_the_quorum_reads_are_unchanged_and_the_second_node_is_never_asked() {
        let primary = with_lock(110);
        let second = claimed(with_lock(110));
        let (p, _s) = (serve(&primary).await, serve(&second).await);
        let backend = single(&p);
        let mut before = 0;
        let mut step = |want: u64, what: &str| {
            let now = primary.requests();
            assert_eq!(now - before, want, "{what}: requests to the primary");
            before = now;
        };
        assert_eq!(
            backend.find_spend(&lock_outpoint(), 100).await.unwrap(),
            None
        );
        step(3, "find_spend (receipt, Claimed logs, Refunded logs)");
        let out = backend
            .htlc_output(&htlc(), &lock_outpoint())
            .await
            .unwrap()
            .expect("lock");
        assert_eq!(out.confirmations, 11);
        step(2, "htlc_output (receipt, tip)");
        assert_eq!(
            backend.confirmations(&Txid(LOCK_TX.0)).await.unwrap(),
            Some(11)
        );
        step(2, "confirmations (receipt, tip)");
        assert_eq!(
            backend.confirmations(&Txid(CLAIM_TX.0)).await.unwrap(),
            None
        );
        step(2, "confirmations of an unknown tx (receipt, by hash)");
        assert_eq!(backend.median_time_past().await.unwrap(), LOCKTIME - 3600);
        step(1, "median_time_past (latest block)");
        assert_eq!(second.requests(), 0, "the second node was asked");
    }

    /// Quorum on: the second node gets the same reads as the primary, and nothing else.
    #[tokio::test]
    async fn with_the_quorum_the_second_node_gets_the_same_reads() {
        let (primary, second) = (with_lock(110), with_lock(110));
        let (_p, _s, backend) = pair(&primary, &second).await;
        backend.find_spend(&lock_outpoint(), 100).await.unwrap();
        backend
            .htlc_output(&htlc(), &lock_outpoint())
            .await
            .unwrap();
        backend.confirmations(&Txid(LOCK_TX.0)).await.unwrap();
        backend.median_time_past().await.unwrap();
        assert_eq!(primary.requests(), 8);
        assert_eq!(second.requests(), 8);
        backend.tip_height().await.unwrap();
        backend.tip_hash().await.unwrap();
        assert_eq!(second.requests(), 8, "tip reads stay single-source");
    }

    // ---- bounded read hold (EV): `Held` and the primary-only view ----

    fn assert_held<T: std::fmt::Debug>(r: Result<T, SwapError>, what: &str) {
        match r {
            Err(SwapError::Held(msg)) => assert!(msg.contains("disagree"), "{what}: {msg}"),
            other => panic!("{what}: expected Held, got {other:?}"),
        }
    }

    /// A second node that disagrees or does not answer holds the read for the engine's
    /// deadline (`SwapError::Held`).
    #[tokio::test]
    async fn a_disagreeing_or_unreachable_second_node_holds_the_read() {
        let (_p, _s, backend) = pair(&with_lock(110), &claimed(with_lock(110))).await;
        assert_held(
            backend.find_spend(&lock_outpoint(), 100).await,
            "claim only on second",
        );
        let p = serve(&claimed(with_lock(110))).await;
        let backend = quorum(&p, "http://127.0.0.1:1");
        assert_held(
            backend.find_spend(&lock_outpoint(), 100).await,
            "find_spend",
        );
        assert_held(
            backend.confirmations(&Txid(LOCK_TX.0)).await,
            "confirmations",
        );
        assert_held(backend.median_time_past().await, "median_time_past");
    }

    /// The primary-only view reads the primary alone; the second node is not asked. Without
    /// the quorum there is no view.
    #[tokio::test]
    async fn the_primary_only_view_reads_the_primary_alone() {
        let (primary, second) = (claimed(with_lock(110)), with_lock(110));
        let (_p, _s, backend) = pair(&primary, &second).await;
        assert_held(
            backend.find_spend(&lock_outpoint(), 100).await,
            "find_spend",
        );
        let asked = second.requests();
        let view = backend
            .primary_only()
            .expect("the quorum has a primary-only view");
        assert_eq!(view.pubkey(), backend.pubkey());
        assert!(view.primary_only().is_none());
        assert!(view
            .find_spend(&lock_outpoint(), 100)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            view.confirmations(&Txid(LOCK_TX.0)).await.unwrap(),
            Some(11)
        );
        assert_eq!(view.median_time_past().await.unwrap(), LOCKTIME - 3600);
        assert_eq!(second.requests(), asked, "the view asked the second node");

        let p = serve(&with_lock(110)).await;
        assert!(single(&p).primary_only().is_none());
    }
}
