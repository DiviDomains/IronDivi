// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

use std::time::Duration;

use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::SecretKey;
use divi_swap::htlc::{new_preimage, REFUND_SEQUENCE};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

const MAKER_KEY: [u8; 32] = [0x11; 32];
const TAKER_KEY: [u8; 32] = [0x22; 32];
const LOCKTIME: u32 = 1_900_000_000;

/// Genesis block hash of Litecoin testnet4, as served by `litecoinspace.org/testnet/api`
/// (verified live 2026-10-11): `GET /block-height/0`.
const LTC_TESTNET_GENESIS_HASH: &str =
    "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0";

fn fast() -> RetryPolicy {
    RetryPolicy {
        attempts: 3,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
    }
}

fn backend(urls: Vec<String>, key: [u8; 32]) -> LtcBackend {
    LtcBackend::new(
        urls,
        SecretKey::from_slice(&key).unwrap(),
        FeePolicy::Fixed(1),
        fast(),
    )
    .unwrap()
}

/// HTLC where the taker key claims and the maker key refunds.
fn htlc(hash: [u8; 32]) -> HtlcParams {
    let secp = Secp256k1::new();
    let pk = |k: &[u8; 32]| {
        SecretKey::from_slice(k)
            .unwrap()
            .public_key(&secp)
            .serialize()
    };
    HtlcParams {
        hash,
        claim_pubkey: pk(&TAKER_KEY),
        refund_pubkey: pk(&MAKER_KEY),
        locktime: LOCKTIME,
        script_version: Default::default(),
    }
}

fn outpoint() -> Outpoint {
    Outpoint {
        txid: Txid([9; 32]),
        vout: 1,
    }
}

fn dead_url() -> String {
    "http://127.0.0.1:1".to_string()
}

#[tokio::test]
async fn claim_verifies_with_consensus() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let b = backend(vec![dead_url()], TAKER_KEY);
    let signed = b
        .build_claim(&h, &outpoint(), Amount::from_sat(20_000), &pre)
        .await
        .unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&signed.raw).unwrap();
    verify_htlc_spend(&tx, &h, 20_000).unwrap();
    assert_eq!(tx.lock_time, LockTime::ZERO);
    assert_eq!(tx.input[0].witness.len(), 4);
    assert_eq!(tx.input[0].witness.nth(1).unwrap(), pre);
    assert_eq!(signed.txid.0, tx.compute_txid().to_byte_array());
    assert!(tx.output[0].value.to_sat() < 20_000);
    // The claim cannot be verified against a different amount (BIP 143: the sighash commits
    // to it), so a primary-only spend cannot be made to pay away more than it was told.
    assert!(verify_htlc_spend(&tx, &h, 19_999).is_err());
    assert!(verify_htlc_spend(&tx, &h, 20_001).is_err());
}

#[tokio::test]
async fn claim_sizes_are_the_vsizes_a_claim_and_its_child_are_charged_for() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let b = backend(vec![dead_url()], TAKER_KEY);
    let sizes = b.claim_sizes(&h).unwrap();
    assert_eq!(sizes.dust, DUST_SATS);
    let amount = Amount::from_sat(1_000_000);
    let claim = b
        .build_claim_at(&h, &outpoint(), amount, &pre, 10)
        .await
        .unwrap();
    let parent: bitcoin::Transaction = bitcoin::consensus::deserialize(&claim.raw).unwrap();
    let parent_value = parent.output[0].value.to_sat();
    // The claim's fee is computed on the same 72-byte-signature size the ceiling divides by.
    assert_eq!(1_000_000 - parent_value, 10 * sizes.claim_vsize);
    let child = b.build_cpfp(&[claim], amount, 100).await.unwrap();
    let child: bitcoin::Transaction = bitcoin::consensus::deserialize(&child.raw).unwrap();
    let actual = child.vsize() as u64;
    assert!(actual <= sizes.child_vsize && actual + 1 >= sizes.child_vsize);
    // The package (claim and child) pays about 100/vB over both sizes.
    let fee = 1_000_000 - child.output[0].value.to_sat();
    let want = 100 * (sizes.claim_vsize + sizes.child_vsize);
    assert!(fee <= want && fee + 200 >= want, "{fee} for {want}");
}

#[tokio::test]
async fn a_cpfp_child_signals_replacement_and_a_richer_sibling_outbids_it() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let b = backend(vec![dead_url()], TAKER_KEY);
    let amount = Amount::from_sat(1_000_000);
    let claim = b
        .build_claim_at(&h, &outpoint(), amount, &pre, 10)
        .await
        .unwrap();
    let read = |t: &divi_swap::SignedTx| -> bitcoin::Transaction {
        bitcoin::consensus::deserialize(&t.raw).unwrap()
    };
    let child = read(
        &b.build_cpfp(std::slice::from_ref(&claim), amount, 100)
            .await
            .unwrap(),
    );
    assert!(child.is_explicitly_rbf(), "BIP125 signal");
    // The next bump replaces it: same input, and its extra fee pays for its own size ten
    // times over (BIP125 rule 4 asks the incremental relay feerate on it).
    let sibling = read(&b.build_cpfp(&[claim], amount, 200).await.unwrap());
    assert!(sibling.is_explicitly_rbf());
    assert_eq!(
        sibling.input[0].previous_output,
        child.input[0].previous_output
    );
    let extra = child.output[0].value.to_sat() - sibling.output[0].value.to_sat();
    assert!(extra >= 10 * sibling.vsize() as u64, "{extra}");
}

#[tokio::test]
async fn refund_verifies_with_consensus() {
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let b = backend(vec![dead_url()], MAKER_KEY);
    let signed = b
        .build_refund(&h, &outpoint(), Amount::from_sat(20_000))
        .await
        .unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&signed.raw).unwrap();
    verify_htlc_spend(&tx, &h, 20_000).unwrap();
    assert_eq!(tx.lock_time, LockTime::from_time(LOCKTIME).unwrap());
    assert_eq!(tx.input[0].sequence.0, REFUND_SEQUENCE);
    assert_eq!(tx.input[0].witness.len(), 3);
    assert!(tx.input[0].witness.nth(1).unwrap().is_empty());
    // BIP 143: the refund's signature commits to the spent amount too.
    assert!(verify_htlc_spend(&tx, &h, 19_999).is_err());
    assert!(verify_htlc_spend(&tx, &h, 20_001).is_err());
}

#[tokio::test]
async fn refund_rejected_before_locktime() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"non-final\"}",
        ))
        .mount(&server)
        .await;
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let b = backend(vec![server.uri()], MAKER_KEY);
    let signed = b
        .build_refund(&h, &outpoint(), Amount::from_sat(20_000))
        .await
        .unwrap();
    let err = b.broadcast(&signed).await.unwrap_err();
    assert!(matches!(err, SwapError::Premature(_)), "{err:?}");
    assert!(err.is_retryable());

    // Other node refusals are not retryable.
    assert!(matches!(
        classify_broadcast_error("bad-txns-in-belowout"),
        SwapError::Rejected(_)
    ));
    assert!(matches!(
        classify_broadcast_error("Locktime requirement not satisfied"),
        SwapError::Premature(_)
    ));
}

#[test]
fn already_confirmed_is_already_known() {
    // Every wording this backend relies on classify_broadcast_error/is_already_known to
    // recognize, so a retried broadcast after the chain already has the tx counts as
    // success instead of aborting the swap (the zec lane hit this with Zebra's distinct
    // wording, 7c932f9 — Litecoin Core's wording is Bitcoin Core's, all covered here).
    for body in [
        "sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction already in block chain\"}",
        "sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction outputs already in utxo set\"}",
        "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"txn-already-in-mempool\"}",
        "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"txn-already-known\"}",
    ] {
        assert!(is_already_known(body), "{body}");
    }
}

#[tokio::test]
async fn broadcast_is_idempotent_when_already_known() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction already in block chain\"}"),
        )
        .mount(&server)
        .await;
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let b = backend(vec![server.uri()], TAKER_KEY);
    let signed = b
        .build_claim(&h, &outpoint(), Amount::from_sat(20_000), &pre)
        .await
        .unwrap();
    assert_eq!(b.broadcast(&signed).await.unwrap(), signed.txid);
}

/// A refund broadcast retried after the chain already accepted it (e.g. the first
/// response timed out) hits Esplora's "txn-already-in-mempool" instead of a real
/// rejection — case C has both sides refund, so this must count as success, not abort the
/// swap. Same bug class as the zec lane's Zebra "already exists in mempool" case, 7c932f9.
#[tokio::test]
async fn broadcast_is_idempotent_on_mempool_duplicate() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"txn-already-in-mempool\"}",
        ))
        .mount(&server)
        .await;
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let b = backend(vec![server.uri()], MAKER_KEY);
    let signed = b
        .build_refund(&h, &outpoint(), Amount::from_sat(20_000))
        .await
        .unwrap();
    assert_eq!(b.broadcast(&signed).await.unwrap(), signed.txid);
}

#[tokio::test]
async fn wrong_preimage_rejected() {
    let (_, hash) = new_preimage();
    let (wrong, _) = new_preimage();
    let h = htlc(hash);
    let b = backend(vec![dead_url()], TAKER_KEY);
    let err = b
        .build_claim(&h, &outpoint(), Amount::from_sat(20_000), &wrong)
        .await
        .unwrap_err();
    assert!(matches!(err, SwapError::InvalidParams(_)), "{err:?}");

    // Even if the early check were bypassed, consensus rejects a wrong preimage: build a
    // claim for a matching HTLC, then verify it against an HTLC with a different hash.
    let (pre, good_hash) = new_preimage();
    let good = htlc(good_hash);
    let signed = b
        .build_claim(&good, &outpoint(), Amount::from_sat(20_000), &pre)
        .await
        .unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&signed.raw).unwrap();
    let other = htlc(hash);
    assert!(verify_htlc_spend(&tx, &other, 20_000).is_err());
}

#[tokio::test]
async fn wrong_key_rejected() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    // Maker key is the refund key, not the claim key.
    let b = backend(vec![dead_url()], MAKER_KEY);
    let err = b
        .build_claim(&h, &outpoint(), Amount::from_sat(20_000), &pre)
        .await
        .unwrap_err();
    assert!(matches!(err, SwapError::InvalidParams(_)), "{err:?}");
}

#[tokio::test]
async fn esplora_retries_on_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("3105405"))
        .expect(1)
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], TAKER_KEY);
    assert_eq!(b.tip_height().await.unwrap(), 3_105_405);
}

#[tokio::test]
async fn esplora_gives_up_as_transient() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], TAKER_KEY);
    let err = b.tip_height().await.unwrap_err();
    assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
}

#[tokio::test]
async fn esplora_falls_back_to_secondary() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .expect(3)
        .mount(&primary)
        .await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("42"))
        .expect(1)
        .mount(&secondary)
        .await;
    let b = backend(vec![primary.uri(), secondary.uri()], TAKER_KEY);
    assert_eq!(b.tip_height().await.unwrap(), 42);
}

#[tokio::test]
async fn find_spend_reads_witness() {
    let server = MockServer::start().await;
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let fund = outpoint();
    let spender = "ab".repeat(32);
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}/outspend/1", fund.txid)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spent": true, "txid": spender, "vin": 1,
            "status": {"confirmed": true, "block_height": 777}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/tx/{spender}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "txid": spender,
            "vin": [
                {"txid": "00".repeat(32), "vout": 0, "scriptsig": "", "witness": []},
                {"txid": fund.txid.to_rpc_hex(), "vout": 1, "scriptsig": "",
                 "witness": [hex::encode([0x30u8; 71]), hex::encode(pre), "01",
                             hex::encode(h.redeem_script())]}
            ]
        })))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    let spend = b.find_spend(&fund, 700).await.unwrap().expect("spent");
    assert_eq!(spend.txid, Txid::from_rpc_hex(&spender).unwrap());
    assert_eq!(spend.input_index, 1);
    assert_eq!(spend.height, Some(777));
    assert_eq!(spend.extract_preimage(&hash), Some(pre));
}

#[tokio::test]
async fn find_spend_unspent_and_unknown() {
    let server = MockServer::start().await;
    let fund = outpoint();
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}/outspend/1", fund.txid)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"spent": false})))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    assert!(b.find_spend(&fund, 0).await.unwrap().is_none());
    let unknown = Outpoint {
        txid: Txid([1; 32]),
        vout: 0,
    };
    assert!(b.find_spend(&unknown, 0).await.unwrap().is_none()); // wiremock 404
}

/// A load-balanced backend can report an outpoint spent before another replica has
/// indexed the spending tx itself (the same lagging-backend class as the "Block not
/// found" bug, `d371a22`, just one hop later: the outspend lookup and the spender tx
/// lookup can land on different replicas). `find_spend` must treat that as "not found
/// yet" (the caller polls again), not a permanent error.
#[tokio::test]
async fn find_spend_treats_a_lagging_spender_lookup_as_not_found_yet() {
    let server = MockServer::start().await;
    let fund = outpoint();
    let spender = "ab".repeat(32);
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}/outspend/1", fund.txid)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spent": true, "txid": spender, "vin": 1,
            "status": {"confirmed": true, "block_height": 777}
        })))
        .mount(&server)
        .await;
    // No mock for GET /tx/{spender}: wiremock answers 404, exactly what a replica that
    // has not indexed the spender yet would return.
    let b = backend(vec![server.uri()], MAKER_KEY);
    assert!(b.find_spend(&fund, 700).await.unwrap().is_none());
}

#[tokio::test]
async fn find_spend_scans_blocks_without_outspend() {
    let server = MockServer::start().await;
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let fund = outpoint();
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}/outspend/1", fund.txid)))
        .respond_with(ResponseTemplate::new(501))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("11"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block-height/10"))
        .respond_with(ResponseTemplate::new(200).set_body_string("blockhash10"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block-height/11"))
        .respond_with(ResponseTemplate::new(200).set_body_string("blockhash11"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block/blockhash10/txs/0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"txid": "cd".repeat(32), "vin": [{"txid": "00".repeat(32), "vout": 0, "scriptsig": "", "witness": []}]}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block/blockhash10/txs/1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block/blockhash11/txs/0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"txid": "ef".repeat(32), "vin": [{"txid": fund.txid.to_rpc_hex(), "vout": 1, "scriptsig": "",
              "witness": [hex::encode([0x30u8; 71]), hex::encode(pre), "01", hex::encode(h.redeem_script())]}]}
        ])))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    let spend = b
        .find_spend(&fund, 10)
        .await
        .unwrap()
        .expect("found by scan");
    assert_eq!(spend.height, Some(11));
    assert_eq!(spend.extract_preimage(&hash), Some(pre));
}

#[tokio::test]
async fn confirmations_and_htlc_output() {
    let server = MockServer::start().await;
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let fund = outpoint();
    let spk = hex::encode(htlc_script_pubkey(&h).as_bytes());
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("110"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}/status", fund.txid)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"confirmed": true, "block_height": 109})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}", fund.txid)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "txid": fund.txid.to_rpc_hex(),
            "vout": [{"scriptpubkey": "00", "value": 5}, {"scriptpubkey": spk, "value": 20000}],
            "status": {"confirmed": true, "block_height": 109}
        })))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    assert_eq!(b.confirmations(&fund.txid).await.unwrap(), Some(2));
    assert_eq!(b.confirmations(&Txid([5; 32])).await.unwrap(), None);
    let locked = b.htlc_output(&h, &fund).await.unwrap().unwrap();
    assert_eq!(locked.amount, Amount::from_sat(20_000));
    assert_eq!(locked.confirmations, 2);
    // Output 0 does not pay this HTLC.
    let wrong = Outpoint { vout: 0, ..fund };
    assert!(b.htlc_output(&h, &wrong).await.unwrap().is_none());
    // A different HTLC at the same outpoint does not match.
    let (_, other_hash) = new_preimage();
    assert!(b
        .htlc_output(&htlc(other_hash), &fund)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn median_time_past_reads_tip_block() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(200).set_body_string("tiphash"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block/tiphash"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"mediantime": 1_790_000_000u64, "timestamp": 1_790_003_600u64}),
            ),
        )
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    assert_eq!(b.median_time_past().await.unwrap(), 1_790_000_000);
}

/// A block that a backend handed us as "the tip" but has not finished indexing can come
/// back without `mediantime` — a transient, not a permanent, condition.
#[tokio::test]
async fn median_time_past_missing_field_is_transient() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(200).set_body_string("tiphash"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block/tiphash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"timestamp": 1})))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    let err = b.median_time_past().await.unwrap_err();
    assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
}

/// An Esplora `/blocks/tip/height` never legitimately answers 200 with an empty body; a
/// backend caught mid-restart might. Transient, not permanent.
#[tokio::test]
async fn tip_height_empty_body_is_transient() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    let err = b.tip_height().await.unwrap_err();
    assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
}

/// Same as above for a garbled (non-numeric) body instead of an empty one.
#[tokio::test]
async fn tip_height_unparseable_body_is_transient() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>502</html>"))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    let err = b.tip_height().await.unwrap_err();
    assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
}

/// A 2xx response that fails to parse as JSON (a truncated body, or an HTML page from a
/// misbehaving proxy in front of Esplora) is a transport artifact, not Esplora's answer —
/// real Esplora error bodies are plain text and carry a non-2xx status.
#[tokio::test]
async fn malformed_json_body_is_transient() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(200).set_body_string("tiphash"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block/tiphash"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>not json</html>"))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    let err = b.median_time_past().await.unwrap_err();
    assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
}

/// A UTXO response that is not a JSON array (e.g. a proxy error object, or a truncated
/// body) is a backend/transport glitch, not a reason to give up on funding permanently.
#[tokio::test]
async fn funding_transient_on_malformed_utxo_response() {
    let server = MockServer::start().await;
    let b = backend(vec![server.uri()], TAKER_KEY);
    let addr = b.address().to_string();
    Mock::given(method("GET"))
        .and(path(format!("/address/{addr}/utxo")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"error": "not ready"})))
        .mount(&server)
        .await;
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let err = b
        .build_funding(&h, Amount::from_sat(20_000))
        .await
        .unwrap_err();
    assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
}

#[tokio::test]
async fn funding_selects_coins_and_change() {
    let server = MockServer::start().await;
    let b = backend(vec![server.uri()], TAKER_KEY);
    let addr = b.address().to_string();
    let t = |n: u8| hex::encode([n; 32]);
    Mock::given(method("GET"))
        .and(path(format!("/address/{addr}/utxo")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"txid": t(1), "vout": 0, "value": 10_000, "status": {"confirmed": true}},
            {"txid": t(2), "vout": 3, "value": 15_000, "status": {"confirmed": true}},
            {"txid": t(3), "vout": 0, "value": 900_000, "status": {"confirmed": false}}
        ])))
        .mount(&server)
        .await;
    let (_, hash) = new_preimage();
    let h = htlc(hash);

    // 20,000 needs both confirmed coins (largest first); the unconfirmed one is not used.
    let f = b.build_funding(&h, Amount::from_sat(20_000)).await.unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.input[0].previous_output.vout, 3);
    assert_eq!(f.outpoint.vout, 0);
    assert_eq!(f.outpoint.txid.0, tx.compute_txid().to_byte_array());
    assert_eq!(tx.output.len(), 2);
    assert_eq!(tx.output[0].value.to_sat(), 20_000);
    assert_eq!(tx.output[0].script_pubkey, htlc_script_pubkey(&h));
    let (_, my_program) = decode_segwit_v0(&addr).unwrap();
    assert_eq!(
        tx.output[1].script_pubkey,
        bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_slice(&my_program).unwrap())
    );
    let fee = 25_000 - 20_000 - tx.output[1].value.to_sat();
    // Estimating with dummy 72-byte signatures never undershoots the real size; real DER
    // signatures are 71-72 bytes, so it overshoots by under 1 vB per input.
    let real = tx.vsize() as u64;
    assert!(
        fee >= real && fee <= real + 2 * tx.input.len() as u64,
        "fee {fee} is 1 sat/vB of the signed size {real}"
    );

    // 5,000 fits in the largest confirmed coin alone, with change.
    let f = b.build_funding(&h, Amount::from_sat(5_000)).await.unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);

    // A remainder below dust is folded into the fee instead of a change output.
    let f = b.build_funding(&h, Amount::from_sat(14_700)).await.unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1, "no dust change");

    // More than the confirmed coins hold pulls in the unconfirmed one.
    let f = b
        .build_funding(&h, Amount::from_sat(500_000))
        .await
        .unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
    assert!(tx.input.len() >= 3);

    // Insufficient funds is reported as such.
    let err = b
        .build_funding(&h, Amount::from_sat(5_000_000))
        .await
        .unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
}

/// A freshly generated, never-funded address (zero UTXOs, not just too few sats) reports
/// `InsufficientFunds` instead of panicking: the live dry run (`examples/ltc_live_dry_run.rs`)
/// hit this against a real throwaway key before the fix.
#[tokio::test]
async fn funding_fails_cleanly_with_no_utxos_at_all() {
    let server = MockServer::start().await;
    let b = backend(vec![server.uri()], TAKER_KEY);
    let addr = b.address().to_string();
    Mock::given(method("GET"))
        .and(path(format!("/address/{addr}/utxo")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let err = b
        .build_funding(&h, Amount::from_sat(100_000))
        .await
        .unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
}

/// `LtcBackend::build_send` (plain P2WPKH send, no HTLC — used to move funds between
/// wallets directly, e.g. `examples/ltc_send.rs`): selects coins, pays the destination,
/// change back to self, and never broadcasts.
#[tokio::test]
async fn backend_send_selects_coins_and_change() {
    let server = MockServer::start().await;
    let from = backend(vec![server.uri()], TAKER_KEY);
    let to = backend(vec![server.uri()], MAKER_KEY);
    let from_addr = from.address().to_string();
    let to_addr = to.address().to_string();
    let t = |n: u8| hex::encode([n; 32]);
    Mock::given(method("GET"))
        .and(path(format!("/address/{from_addr}/utxo")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"txid": t(1), "vout": 0, "value": 50_000, "status": {"confirmed": true}}
        ])))
        .mount(&server)
        .await;

    let signed = from.build_send(&to_addr, 20_000).await.unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&signed.raw).unwrap();
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2, "change expected");
    assert_eq!(tx.output[0].value.to_sat(), 20_000);
    let (_, to_program) = decode_segwit_v0(&to_addr).unwrap();
    assert_eq!(
        tx.output[0].script_pubkey,
        bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_slice(&to_program).unwrap())
    );
    assert_eq!(signed.txid.0, tx.compute_txid().to_byte_array());

    // Sending to its own address is rejected without even looking at coins.
    let err = from.build_send(&from_addr, 20_000).await.unwrap_err();
    assert!(matches!(err, SwapError::InvalidParams(_)), "{err:?}");

    // A P2WSH destination (32-byte program) is rejected: build_send is P2WPKH-only.
    let p2wsh_addr = encode_segwit_v0(TLTC_HRP, &[0x11u8; 32]).unwrap();
    let err = from.build_send(&p2wsh_addr, 20_000).await.unwrap_err();
    assert!(matches!(err, SwapError::InvalidParams(_)), "{err:?}");
}

/// `#[ignore]`, read-only: hits the real Litecoin testnet Esplora API for the tip height
/// and a known block (the genesis hash at height 0).
#[tokio::test]
#[ignore = "hits the real Litecoin testnet Esplora API (read-only)"]
async fn testnet_api_reachable() {
    let b = LtcBackend::for_network(
        "testnet",
        SecretKey::from_slice(&TAKER_KEY).unwrap(),
        FeePolicy::Fixed(1),
    )
    .unwrap();
    let tip = b.tip_height().await.unwrap();
    assert!(tip > 4_000_000, "tip height {tip} looks implausibly low");
    let genesis = reqwest::get(format!("{LITECOINSPACE_TESTNET}/block-height/0"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(genesis.trim(), LTC_TESTNET_GENESIS_HASH);
}

#[cfg(feature = "live")]
mod live {
    use std::time::Duration;

    use divi_swap::htlc::new_preimage;
    use divi_swap::{Amount, ChainBackend, HtlcParams, SignedTx, SwapError, Txid};

    use crate::{FeePolicy, LtcBackend};

    const HTLC_SATS: u64 = 100_000; // 0.001 tLTC
    const REFUND_AHEAD_OF_MTP: u32 = 2 * 3600;

    fn key_from_env() -> bitcoin::secp256k1::SecretKey {
        let hex = std::env::var("SWAP_LTC_TEST_KEY_HEX")
            .expect("SWAP_LTC_TEST_KEY_HEX must be set for the live test");
        bitcoin::secp256k1::SecretKey::from_slice(&hex::decode(hex.trim()).unwrap()).unwrap()
    }

    async fn wait_confirmed(b: &LtcBackend, txid: &Txid, what: &str) {
        for _ in 0..240 {
            if matches!(b.confirmations(txid).await, Ok(Some(c)) if c >= 1) {
                println!("{what} confirmed: {}", txid.to_rpc_hex());
                return;
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        panic!("{what} {} not confirmed after 2h", txid.to_rpc_hex());
    }

    async fn broadcast(b: &LtcBackend, tx: &SignedTx, what: &str) {
        let id = b.broadcast(tx).await.unwrap();
        assert_eq!(id, tx.txid);
        println!("{what} broadcast: {}", id.to_rpc_hex());
    }

    /// Fund two HTLCs on Litecoin testnet with the funded test key, claim one, refund the
    /// other once MTP passes a locktime 2 h ahead of the MTP at start. Takes about 3 h.
    #[tokio::test]
    #[ignore = "needs a funded Litecoin testnet address (env SWAP_LTC_TEST_KEY_HEX) and ~3 h"]
    async fn live_fund_claim_refund() {
        let key = key_from_env();
        let b = LtcBackend::for_network("testnet", key, FeePolicy::default()).unwrap();
        println!("address {}", b.address());

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
        let amount = Amount::from_sat(HTLC_SATS);

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

// ---- explicit network selection (mainnet wiring) ----

#[test]
fn mainnet_endpoint_list_is_non_empty_and_testnet_unchanged() {
    assert_eq!(
        crate::esplora_endpoints("mainnet").unwrap(),
        vec!["https://litecoinspace.org/api".to_string()]
    );
    assert_eq!(
        crate::esplora_endpoints("testnet").unwrap(),
        vec!["https://litecoinspace.org/testnet/api".to_string()]
    );
}

#[test]
fn unknown_ltc_network_is_rejected() {
    let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    assert!(crate::esplora_endpoints("signet").is_err());
    assert!(LtcBackend::for_network("signet", key, FeePolicy::default()).is_err());
}

#[test]
fn mainnet_address_is_ltc1q_and_testnet_stays_tltc1q() {
    let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let main = LtcBackend::for_network("mainnet", key, FeePolicy::default()).unwrap();
    assert!(main.address().starts_with("ltc1q"), "{}", main.address());
    let test = LtcBackend::for_network("testnet", key, FeePolicy::default()).unwrap();
    assert!(test.address().starts_with("tltc1q"), "{}", test.address());
    assert_eq!(
        backend(vec!["http://127.0.0.1:1".into()], [7u8; 32]).address(),
        test.address()
    );
}

#[tokio::test]
async fn build_send_rejects_a_destination_on_the_other_network() {
    let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let main = LtcBackend::for_network("mainnet", key, FeePolicy::default()).unwrap();
    let test_addr = encode_segwit_v0(TLTC_HRP, &[0x11u8; 20]).unwrap();
    let err = main.build_send(&test_addr, 20_000).await.unwrap_err();
    assert!(err.to_string().contains("does not match"), "{err}");
}

/// Bitcoin genesis, as explorers show it: leading zeros, lowercase. Esplora may answer with
/// uppercase or a trailing newline; `tip_hash` normalises both.
const GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

#[tokio::test]
async fn tip_hash_reads_tip_hash_endpoint_in_display_order() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!("{}\n", GENESIS_HASH.to_uppercase())),
        )
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    assert_eq!(b.tip_hash().await.unwrap(), GENESIS_HASH);
}

#[tokio::test]
async fn tip_hash_rejects_malformed_body_as_transient() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(200).set_body_string("tiphash"))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    let err = b.tip_hash().await.unwrap_err();
    assert!(matches!(err, SwapError::Transient(_)), "{err:?}");
}

#[tokio::test]
async fn tip_hash_failing_endpoint_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    assert!(b.tip_hash().await.is_err());
}

/// Read-only smoke against the live LTC APIs: prints `SMOKE <chain> <net> <height_before>
/// <tip_hash> <height_after>` for comparison with an independent explorer. Broadcasts nothing.
#[tokio::test]
#[ignore = "hits live LTC APIs (read-only GETs)"]
async fn tip_hash_live_smoke() {
    for net in ["testnet", "mainnet"] {
        let b = LtcBackend::for_network(
            net,
            SecretKey::from_slice(&TAKER_KEY).unwrap(),
            FeePolicy::Fixed(1),
        )
        .unwrap();
        let before = b.tip_height().await.unwrap();
        let hash = b.tip_hash().await.unwrap();
        let after = b.tip_height().await.unwrap();
        assert_eq!(hash.len(), 64, "{hash}");
        println!("SMOKE LTC {net} {before} {hash} {after}");
    }
}

#[test]
fn v1_script_pubkey_wraps_the_size_checked_script() {
    use divi_swap::htlc::ScriptVersion;
    let h = htlc([7; 32]);
    // V0 is the in-flight script, untouched.
    assert_eq!(
        tx::htlc_script_pubkey(&h),
        tx::htlc_script_pubkey_v(&h, ScriptVersion::V0)
    );
    let v1 = tx::htlc_script_pubkey_v(&h, ScriptVersion::V1);
    assert_ne!(v1, tx::htlc_script_pubkey(&h));
    let want = bitcoin::ScriptBuf::new_p2wsh(
        &bitcoin::ScriptBuf::from_bytes(h.redeem_script_v(ScriptVersion::V1)).wscript_hash(),
    );
    assert_eq!(v1, want);
    assert_eq!(h.redeem_script_v(ScriptVersion::V1).len(), 118);
}

#[test]
fn script_pubkey_follows_the_params_version() {
    use divi_swap::htlc::ScriptVersion;
    let v0 = htlc([7; 32]);
    let v1 = HtlcParams {
        script_version: ScriptVersion::V1,
        ..v0
    };
    assert_eq!(
        tx::htlc_script_pubkey(&v0),
        tx::htlc_script_pubkey_v(&v0, ScriptVersion::V0)
    );
    assert_eq!(
        tx::htlc_script_pubkey(&v1),
        tx::htlc_script_pubkey_v(&v1, ScriptVersion::V1)
    );
    assert_ne!(tx::htlc_script_pubkey(&v0), tx::htlc_script_pubkey(&v1));
}

// ---- input reservations (a dropped lock's inputs are not handed to the next swap) ----

fn reservation_db(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "swap-chain-ltc-{tag}-{}-{nanos}.db",
        std::process::id()
    ))
}

fn rm_db(path: &std::path::Path) {
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}

/// The wallet owns coin A (20,000) and coin B (15,000); the address query keeps listing both,
/// as it does once a broadcast lock has dropped out of the mempool.
async fn two_coin_wallet(key: [u8; 32]) -> (MockServer, LtcBackend, [u8; 32], [u8; 32]) {
    let server = MockServer::start().await;
    let b = backend(vec![server.uri()], key);
    let (a, c) = ([1u8; 32], [2u8; 32]);
    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", b.address())))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"txid": hex::encode(a), "vout": 0, "value": 20_000, "status": {"confirmed": true}},
            {"txid": hex::encode(c), "vout": 0, "value": 15_000, "status": {"confirmed": true}}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    (server, b, a, c)
}

fn spent_txids(f: &Funding) -> Vec<[u8; 32]> {
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
    tx.input
        .iter()
        .map(|i| i.previous_output.txid.to_byte_array())
        .collect()
}

fn posts(reqs: &[wiremock::Request]) -> usize {
    reqs.iter().filter(|r| r.method.as_str() == "POST").count()
}

async fn mock_confirmed(server: &MockServer, txid: &Txid) {
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("110"))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}/status", txid.to_rpc_hex())))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"confirmed": true, "block_height": 109})),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_dropped_locks_inputs_are_skipped_until_the_lock_confirms() {
    let (server, b, a, c) = two_coin_wallet(MAKER_KEY).await;
    let res = InputReservations::in_memory().unwrap();
    let b = b.with_input_reservations(res.clone());
    let (_, hash) = new_preimage();
    let h = htlc(hash);

    let lock1 = b.build_funding(&h, Amount::from_sat(5_000)).await.unwrap();
    assert_eq!(spent_txids(&lock1), vec![a], "largest coin first");
    b.broadcast(&lock1.tx).await.unwrap();

    // The lock is not on the node (dropped): a second swap must not take coin A.
    assert_eq!(b.confirmations(&lock1.tx.txid).await.unwrap(), None);
    let lock2 = b.build_funding(&h, Amount::from_sat(5_000)).await.unwrap();
    assert_eq!(
        spent_txids(&lock2),
        vec![c],
        "A is reserved by the dropped lock"
    );
    // Still not seen: still reserved, a "not seen" never releases.
    let lock3 = b.build_funding(&h, Amount::from_sat(5_000)).await.unwrap();
    assert_eq!(spent_txids(&lock3), vec![c]);

    // Seen confirmed: released (the inputs are spent on chain anyway).
    mock_confirmed(&server, &lock1.tx.txid).await;
    assert_eq!(b.confirmations(&lock1.tx.txid).await.unwrap(), Some(2));
    assert!(res.reserved(Chain::Ltc).unwrap().is_empty());
    let lock4 = b.build_funding(&h, Amount::from_sat(5_000)).await.unwrap();
    assert_eq!(spent_txids(&lock4), vec![a]);
}

#[tokio::test]
async fn a_rebroadcast_of_the_same_lock_keeps_its_one_reservation() {
    let (_server, b, a, _) = two_coin_wallet(MAKER_KEY).await;
    let res = InputReservations::in_memory().unwrap();
    let b = b.with_input_reservations(res.clone());
    let (_, hash) = new_preimage();
    let lock = b
        .build_funding(&htlc(hash), Amount::from_sat(5_000))
        .await
        .unwrap();
    b.broadcast(&lock.tx).await.unwrap();
    b.broadcast(&lock.tx).await.unwrap();
    let held = res.reserved(Chain::Ltc).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held.iter().next().unwrap().txid.0, a);
}

#[tokio::test]
async fn reserved_inputs_survive_a_restart() {
    let db = reservation_db("restart");
    let (_server, b, a, c) = two_coin_wallet(MAKER_KEY).await;
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let b = b.with_input_reservations(InputReservations::open(&db).unwrap());
    let lock = b.build_funding(&h, Amount::from_sat(5_000)).await.unwrap();
    assert_eq!(spent_txids(&lock), vec![a]);
    b.broadcast(&lock.tx).await.unwrap();
    drop(b);

    // New process: fresh backend, reservations reopened from the file.
    let (_server2, b2, _, _) = two_coin_wallet(MAKER_KEY).await;
    let b2 = b2.with_input_reservations(InputReservations::open(&db).unwrap());
    let lock2 = b2.build_funding(&h, Amount::from_sat(5_000)).await.unwrap();
    assert_eq!(spent_txids(&lock2), vec![c]);
    drop(b2);
    rm_db(&db);
}

#[tokio::test]
async fn a_failed_reservation_write_blocks_the_lock_broadcast() {
    let db = reservation_db("failclosed");
    InputReservations::open(&db).unwrap();
    let (server, b, _, _) = two_coin_wallet(MAKER_KEY).await;
    let b = b.with_input_reservations(InputReservations::open_read_only(&db).unwrap());
    let (_, hash) = new_preimage();
    let lock = b
        .build_funding(&htlc(hash), Amount::from_sat(5_000))
        .await
        .unwrap();
    let err = b.broadcast(&lock.tx).await.unwrap_err();
    assert!(matches!(err, SwapError::Storage(_)), "{err:?}");
    assert_eq!(posts(&server.received_requests().await.unwrap()), 0);
    rm_db(&db);
}

#[tokio::test]
async fn claims_and_refunds_are_never_reserved_or_blocked_by_the_store() {
    let db = reservation_db("spends");
    InputReservations::open(&db).unwrap();
    let (server, b, _, _) = two_coin_wallet(TAKER_KEY).await;
    let b = b.with_input_reservations(InputReservations::open_read_only(&db).unwrap());
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = b
        .build_claim(&h, &outpoint(), Amount::from_sat(20_000), &pre)
        .await
        .unwrap();
    // A read-only store would fail any write; the claim still goes out.
    assert_eq!(b.broadcast(&claim).await.unwrap(), claim.txid);
    assert_eq!(posts(&server.received_requests().await.unwrap()), 1);
    rm_db(&db);
}

const TIP_A: &str = "00000000000000000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TIP_B: &str = "00000000000000000001bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The tip moves between the reads: `/blocks/tip/height` already says 101, while the hash
/// read first names block 100. Height and time both come from block 100.
#[tokio::test]
async fn tip_header_takes_height_and_time_from_the_block_whose_hash_it_read() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("101"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(200).set_body_string(TIP_A.to_uppercase()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/block/{TIP_A}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": TIP_A, "height": 100, "timestamp": 1_790_000_000u64,
            "mediantime": 1_789_998_000u64
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/block/{TIP_B}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": TIP_B, "height": 101, "timestamp": 1_790_000_600u64,
            "mediantime": 1_789_998_600u64
        })))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    assert_eq!(b.tip_height().await.unwrap(), 101);
    assert_eq!(
        b.tip_header().await.unwrap(),
        divi_swap::backend::TipHeader {
            height: 100,
            hash: TIP_A.into(),
            time: 1_790_000_000,
        }
    );
}

/// A block answer for some other hash (a confused proxy) is not the tip's header.
#[tokio::test]
async fn tip_header_refuses_a_block_whose_id_is_not_the_tip_hash() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(200).set_body_string(TIP_A))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/block/{TIP_A}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": TIP_B, "height": 101, "timestamp": 1_790_000_600u64
        })))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    assert!(matches!(
        b.tip_header().await.unwrap_err(),
        SwapError::Transient(_)
    ));
}

#[tokio::test]
async fn in_best_chain_reads_the_block_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/block/{TIP_A}/status")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "in_best_chain": true, "height": 100, "next_best": TIP_B
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/block/{TIP_B}/status")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"in_best_chain": false})))
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    assert!(b.in_best_chain(100, TIP_A).await.unwrap());
    assert!(!b.in_best_chain(101, TIP_B).await.unwrap(), "orphaned");
    assert!(
        b.in_best_chain(99, TIP_A).await.is_err(),
        "on the best chain at another height"
    );
}

// --- Claim-time tip cross-check (opt-in, `with_claim_crosscheck`) ---

const CC_TIP: u64 = 3_199_583;
const CC_AT: u64 = CC_TIP - CROSSCHECK_DEPTH;
const CC_HASH_A: &str = "bb06e9077c1907d25a1d986ac281b6d119228b8eae984c21b59fcfdb4af66b11";
const CC_HASH_B: &str = "ac6f27fa7cfdc204f13f93fcd48ce5f57a4a858b950b4de8ac89979b3b5f0b43";

/// A mainnet primary Esplora whose tip is `tip_hash` at [`CC_TIP`] and whose block at
/// [`CC_AT`] is `hash_at`.
async fn cc_primary(tip_hash: &str, hash_at: &str) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tip_hash))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string(CC_TIP.to_string()))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/block-height/{CC_AT}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(hash_at))
        .mount(&s)
        .await;
    s
}

/// A Blockbook that answers `resp` for the block at [`CC_AT`].
async fn cc_blockbook(resp: ResponseTemplate) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/block-index/{CC_AT}")))
        .respond_with(resp)
        .mount(&s)
        .await;
    s
}

fn cc_bb(hash: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string(format!(r#"{{"blockHash":"{hash}"}}"#))
}

fn cc_mainnet(primary: &MockServer) -> LtcBackend {
    LtcBackend::new_on(
        "mainnet",
        vec![primary.uri()],
        SecretKey::from_slice(&TAKER_KEY).unwrap(),
        FeePolicy::Fixed(1),
        fast(),
    )
    .unwrap()
}

async fn requests_to(s: &MockServer) -> usize {
    s.received_requests().await.map_or(0, |r| r.len())
}

/// A disagreeing source holds the claim as `Held` (EU), so the engine bounds it: the message
/// names both hashes and both sources (URLs only, no secret).
#[tokio::test]
async fn claim_crosscheck_disagree_holds_the_claim_naming_both_hashes_and_both_sources() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let p = cc_primary(TIP_A, CC_HASH_A).await;
    let bb = cc_blockbook(cc_bb(CC_HASH_B)).await;
    let b = cc_mainnet(&p).with_claim_crosscheck_at(CrossCheckSource::Blockbook, bb.uri());
    let amount = Amount::from_sat(20_000);
    for e in [
        b.build_claim(&h, &outpoint(), amount, &pre)
            .await
            .unwrap_err(),
        b.build_claim_at(&h, &outpoint(), amount, &pre, 10)
            .await
            .unwrap_err(),
    ] {
        let SwapError::Held(msg) = e else {
            panic!("want Held, got {e:?}");
        };
        assert!(msg.contains(CC_HASH_A) && msg.contains(CC_HASH_B), "{msg}");
        assert!(msg.contains(&p.uri()) && msg.contains(&bb.uri()), "{msg}");
        assert!(!msg.contains(&hex::encode(pre)), "{msg}");
    }
}

#[tokio::test]
async fn claim_crosscheck_agree_builds_the_claim_and_asks_once_per_primary_tip() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let p = cc_primary_full(CC_HASH_B, None).await;
    let bb = cc_source(
        CrossCheckSource::Blockbook,
        CC_HASH_B,
        cc_tx(CrossCheckSource::Blockbook, None),
    )
    .await;
    let b = cc_mainnet(&p).with_claim_crosscheck_at(CrossCheckSource::Blockbook, bb.uri());
    let amount = Amount::from_sat(20_000);
    let signed = b.build_claim(&h, &outpoint(), amount, &pre).await.unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&signed.raw).unwrap();
    verify_htlc_spend(&tx, &h, 20_000).unwrap();
    b.build_claim_at(&h, &outpoint(), amount, &pre, 10)
        .await
        .unwrap();
    // Same primary tip on the retry: the cached result is reused, the source is asked once
    // per comparison (`tip - 6`, `tip - 1`, the spend; EI).
    assert_eq!(requests_to(&bb).await, 3);
}

#[tokio::test]
async fn claim_crosscheck_asks_again_when_the_primary_tip_moves() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let p = cc_primary_full(CC_HASH_B, None).await;
    let bb = cc_source(
        CrossCheckSource::Blockbook,
        CC_HASH_B,
        cc_tx(CrossCheckSource::Blockbook, None),
    )
    .await;
    let b = cc_mainnet(&p).with_claim_crosscheck_at(CrossCheckSource::Blockbook, bb.uri());
    let amount = Amount::from_sat(20_000);
    b.build_claim(&h, &outpoint(), amount, &pre).await.unwrap();
    p.reset().await;
    let p2_tip = Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(200).set_body_string(TIP_B));
    p2_tip.mount(&p).await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string(CC_TIP.to_string()))
        .mount(&p)
        .await;
    // The primary now forks off: the block at the compared height differs.
    Mock::given(method("GET"))
        .and(path(format!("/block-height/{CC_AT}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(CC_HASH_B))
        .mount(&p)
        .await;
    let e = b
        .build_claim(&h, &outpoint(), amount, &pre)
        .await
        .unwrap_err();
    assert!(matches!(e, SwapError::Transient(_)), "{e:?}");
    // Three on the first tip; one on the second, where `tip - 6` already disagrees (EI).
    assert_eq!(requests_to(&bb).await, 4);
}

/// Collects formatted `tracing` output for the current thread.
#[derive(Clone, Default)]
struct LogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[tokio::test]
async fn claim_crosscheck_unavailable_source_warns_and_builds_the_claim() {
    let buf = LogBuf::default();
    let w = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || w.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);

    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let p = cc_primary(TIP_A, CC_HASH_A).await;
    let bb = cc_blockbook(ResponseTemplate::new(429)).await;
    let b = cc_mainnet(&p).with_claim_crosscheck_at(CrossCheckSource::Blockbook, bb.uri());
    let amount = Amount::from_sat(20_000);
    b.build_claim(&h, &outpoint(), amount, &pre).await.unwrap();
    b.build_claim_at(&h, &outpoint(), amount, &pre, 10)
        .await
        .unwrap();
    // Rate-limited source: not asked again for the same primary tip.
    let first = requests_to(&bb).await;
    assert!(first >= 1);
    b.build_claim(&h, &outpoint(), amount, &pre).await.unwrap();
    assert_eq!(requests_to(&bb).await, first);

    // One audit line per claim built without a comparison: source URL, reason, outpoint.
    let log = buf.text();
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("claim cross-check"))
        .collect();
    assert_eq!(lines.len(), 3, "{log}");
    for l in lines {
        assert!(l.contains(&bb.uri()), "source URL: {l}");
        assert!(l.contains("429"), "reason: {l}");
        assert!(l.contains(&outpoint().to_string()), "outpoint: {l}");
    }
}

#[tokio::test]
async fn claim_crosscheck_off_sends_nothing_to_the_source_or_the_primary() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let p = cc_primary(TIP_A, CC_HASH_A).await;
    let bb = cc_blockbook(cc_bb(CC_HASH_B)).await;
    let amount = Amount::from_sat(20_000);
    for b in [cc_mainnet(&p), cc_mainnet(&p).with_claim_crosscheck(None)] {
        b.build_claim(&h, &outpoint(), amount, &pre).await.unwrap();
        b.build_claim_at(&h, &outpoint(), amount, &pre, 10)
            .await
            .unwrap();
    }
    assert_eq!(requests_to(&bb).await, 0);
    // Off is today's request count exactly: a Fixed fee policy claim asks the primary nothing.
    assert_eq!(requests_to(&p).await, 0);
}

// --- Claim-time cross-check at `tip - 1` and of the claimed output's spend (EI) ---

const CC_AT1: u64 = CC_TIP - 1;
const SPENDER_X: &str = "abababababababababababababababababababababababababababababababab";
const SPENDER_Y: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

/// [`cc_primary`] plus its block at `tip - 1` (`hash_at1`) and the outspend of
/// [`outpoint`]: `spender` or unspent.
async fn cc_primary_full(hash_at1: &str, spender: Option<&str>) -> MockServer {
    let s = cc_primary(TIP_A, CC_HASH_A).await;
    Mock::given(method("GET"))
        .and(path(format!("/block-height/{CC_AT1}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(hash_at1))
        .mount(&s)
        .await;
    let o = outpoint();
    let body = match spender {
        Some(t) => json!({"spent": true, "txid": t, "vin": 0, "status": {"confirmed": false}}),
        None => json!({"spent": false}),
    };
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}/outspend/{}", o.txid, o.vout)))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&s)
        .await;
    s
}

/// A source of `kind` that has [`CC_HASH_A`] at [`CC_AT`], `hash_at1` at [`CC_AT1`] and
/// answers `tx` for the funding transaction of [`outpoint`].
async fn cc_source(kind: CrossCheckSource, hash_at1: &str, tx: ResponseTemplate) -> MockServer {
    let s = MockServer::start().await;
    let (block, txp) = match kind {
        CrossCheckSource::Blockbook => ("/block-index", "/tx"),
        CrossCheckSource::BlockCypher => ("/blocks", "/txs"),
    };
    for (h, hash) in [(CC_AT, CC_HASH_A), (CC_AT1, hash_at1)] {
        let body = match kind {
            CrossCheckSource::Blockbook => json!({"blockHash": hash}),
            CrossCheckSource::BlockCypher => json!({"height": h, "hash": hash}),
        };
        Mock::given(method("GET"))
            .and(path(format!("{block}/{h}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&s)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("{txp}/{}", outpoint().txid)))
        .respond_with(tx)
        .mount(&s)
        .await;
    s
}

/// The funding transaction as `kind` shows it: output 0 unspent, output 1 (the HTLC of
/// [`outpoint`]) spent by `spender` or unspent.
fn cc_tx(kind: CrossCheckSource, spender: Option<&str>) -> ResponseTemplate {
    let txid = outpoint().txid.to_string();
    let body = match (kind, spender) {
        (CrossCheckSource::Blockbook, Some(t)) => json!({"txid": txid, "vout": [
            {"n": 0, "value": "5"},
            {"n": 1, "value": "20000", "spent": true, "spentTxId": t, "spentIndex": 0}]}),
        (CrossCheckSource::Blockbook, None) => json!({"txid": txid, "vout": [
            {"n": 0, "value": "5"}, {"n": 1, "value": "20000"}]}),
        (CrossCheckSource::BlockCypher, Some(t)) => json!({"hash": txid, "outputs": [
            {"value": 5}, {"value": 20000, "spent_by": t}]}),
        (CrossCheckSource::BlockCypher, None) => json!({"hash": txid, "outputs": [
            {"value": 5}, {"value": 20000}]}),
    };
    ResponseTemplate::new(200).set_body_json(body)
}

const BOTH_SOURCES: [CrossCheckSource; 2] =
    [CrossCheckSource::Blockbook, CrossCheckSource::BlockCypher];

async fn cc_claim(b: &LtcBackend) -> Result<SignedTx> {
    let (pre, hash) = new_preimage();
    b.build_claim(&htlc(hash), &outpoint(), Amount::from_sat(20_000), &pre)
        .await
}

fn cc_held(r: Result<SignedTx>) -> String {
    match r {
        Err(SwapError::Held(m)) => m,
        other => panic!("want Held, got {other:?}"),
    }
}

/// Agreement at `tip - 6`, at `tip - 1` and on the spend (unspent, or the same spender):
/// the claim is built, and the source is asked once per comparison per primary tip.
#[tokio::test]
async fn claim_crosscheck_agrees_at_tip_minus_one_and_on_the_spend() {
    for kind in BOTH_SOURCES {
        for spender in [None, Some(SPENDER_X)] {
            let p = cc_primary_full(CC_HASH_B, spender).await;
            let s = cc_source(kind, CC_HASH_B, cc_tx(kind, spender)).await;
            let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
            cc_claim(&b).await.unwrap();
            cc_claim(&b).await.unwrap();
            assert_eq!(requests_to(&s).await, 3, "{kind:?} {spender:?}");
        }
    }
}

/// `tip - 6` agrees, `tip - 1` does not: the claim is held, naming both hashes.
#[tokio::test]
async fn claim_crosscheck_tip_minus_one_disagree_holds_the_claim() {
    for kind in BOTH_SOURCES {
        let p = cc_primary_full(CC_HASH_B, None).await;
        let s = cc_source(kind, TIP_B, cc_tx(kind, None)).await;
        let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
        let m = cc_held(cc_claim(&b).await);
        assert!(m.contains(CC_HASH_B) && m.contains(TIP_B), "{kind:?}: {m}");
        assert!(m.contains(&CC_AT1.to_string()), "{m}");
    }
}

/// A spend of the claimed output that only the source shows (the primary hides it), or only
/// the primary shows, holds the claim.
#[tokio::test]
async fn claim_crosscheck_spend_one_source_shows_holds_the_claim() {
    for kind in BOTH_SOURCES {
        for (primary, other) in [(None, Some(SPENDER_X)), (Some(SPENDER_X), None)] {
            let p = cc_primary_full(CC_HASH_B, primary).await;
            let s = cc_source(kind, CC_HASH_B, cc_tx(kind, other)).await;
            let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
            let m = cc_held(cc_claim(&b).await);
            assert!(
                m.contains(SPENDER_X) && m.contains("unspent"),
                "{kind:?}: {m}"
            );
            assert!(m.contains(&outpoint().to_string()), "{m}");
        }
    }
}

#[tokio::test]
async fn claim_crosscheck_two_different_spenders_holds_the_claim() {
    for kind in BOTH_SOURCES {
        let p = cc_primary_full(CC_HASH_B, Some(SPENDER_X)).await;
        let s = cc_source(kind, CC_HASH_B, cc_tx(kind, Some(SPENDER_Y))).await;
        let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
        let m = cc_held(cc_claim(&b).await);
        assert!(
            m.contains(SPENDER_X) && m.contains(SPENDER_Y),
            "{kind:?}: {m}"
        );
    }
}

/// ED's rule for an unreachable source holds for the new comparisons: the source failing on
/// the spend read (or not having `tip - 1`) warns, naming the source URL, and the claim
/// goes ahead.
#[tokio::test]
async fn claim_crosscheck_source_down_on_the_new_reads_warns_and_builds_the_claim() {
    let buf = LogBuf::default();
    let w = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || w.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    for kind in BOTH_SOURCES {
        let p = cc_primary_full(CC_HASH_B, None).await;
        let s = cc_source(kind, CC_HASH_B, ResponseTemplate::new(500)).await;
        let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
        cc_claim(&b).await.unwrap();
        // A source that has not indexed `tip - 1` yet (Blockbook: an empty hash).
        let p = cc_primary_full(CC_HASH_B, None).await;
        let s = cc_source(kind, "", cc_tx(kind, None)).await;
        let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
        cc_claim(&b).await.unwrap();
    }
    let log = buf.text();
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("claim cross-check"))
        .collect();
    assert_eq!(lines.len(), 4, "{log}");
    assert!(lines[0].contains("500"), "{}", lines[0]);
}

/// The startup check (`[ltc].crosscheck`) is unchanged: one comparison at `tip - 6`, no
/// `tip - 1` and no spend read.
#[tokio::test]
async fn startup_crosscheck_still_compares_tip_minus_six_only() {
    let p = cc_primary_full(CC_HASH_B, None).await;
    let s = cc_source(
        CrossCheckSource::Blockbook,
        CC_HASH_B,
        cc_tx(CrossCheckSource::Blockbook, None),
    )
    .await;
    let pc = EsploraClient::new(vec![p.uri()], fast()).unwrap();
    let out = tip_crosscheck(&pc, CrossCheckSource::Blockbook, &s.uri(), fast()).await;
    assert!(
        matches!(out, CrossCheckOutcome::Agree { height: CC_AT, .. }),
        "{out:?}"
    );
    assert_eq!(requests_to(&s).await, 1);
    assert_eq!(requests_to(&p).await, 2);
}

// --- The lock's script and value, read from the cross-check source too (EL) ---
//
// Source shapes: Blockbook `GET /api/v2/tx/{txid}` (`confirmations`, `vout[].n`,
// `vout[].value` as a decimal string of satoshis, `vout[].hex` the scriptPubKey; trezor/blockbook
// `api/types.go`) and BlockCypher `GET /txs/{txid}` (`confirmations`, `outputs[].value` in
// satoshis, `outputs[].script` the scriptPubKey hex; BlockCypher API docs, TX and TXOutput).

const LOCK_SATS: u64 = 20_000;

/// The primary shows the agreed HTLC script and `LOCK_SATS` at `outpoint()`, confirmed at
/// height 109 under a tip of 110 (two confirmations).
async fn lock_primary(spk: &str) -> MockServer {
    let s = MockServer::start().await;
    mount_lock_primary(&s, spk, 110).await;
    s
}

async fn mount_lock_primary(s: &MockServer, spk: &str, tip: u64) {
    let fund = outpoint();
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tip.to_string()))
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}", fund.txid)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "txid": fund.txid.to_rpc_hex(),
            "vout": [{"scriptpubkey": "00", "value": 5}, {"scriptpubkey": spk, "value": LOCK_SATS}],
            "status": {"confirmed": true, "block_height": 109}
        })))
        .mount(s)
        .await;
}

/// `kind`'s transaction body for `outpoint()`: output 1 pays `value` to `spk`.
fn lock_tx(kind: CrossCheckSource, spk: &str, value: u64, confs: u32) -> ResponseTemplate {
    let txid = outpoint().txid.to_rpc_hex();
    let body = match kind {
        CrossCheckSource::Blockbook => json!({"txid": txid, "confirmations": confs,
            "blockHeight": 109, "vout": [
            {"n": 0, "value": "5", "hex": "00"},
            {"n": 1, "value": value.to_string(), "hex": spk}]}),
        CrossCheckSource::BlockCypher => json!({"hash": txid, "confirmations": confs,
            "block_height": 109, "outputs": [
            {"value": 5, "script": "00"}, {"value": value, "script": spk}]}),
    };
    ResponseTemplate::new(200).set_body_json(body)
}

fn lock_tx_path(kind: CrossCheckSource) -> String {
    let txid = outpoint().txid.to_rpc_hex();
    match kind {
        CrossCheckSource::Blockbook => format!("/tx/{txid}"),
        CrossCheckSource::BlockCypher => format!("/txs/{txid}"),
    }
}

async fn lock_source(kind: CrossCheckSource, resp: ResponseTemplate) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(lock_tx_path(kind)))
        .respond_with(resp)
        .mount(&s)
        .await;
    s
}

fn spk_of(h: &HtlcParams) -> String {
    hex::encode(htlc_script_pubkey(h).as_bytes())
}

/// A lock read with the cross-check on that must fail closed: `Transient`, naming both
/// sources, carrying no key material.
fn lock_held(r: Result<Option<LockedOutput>>, p: &MockServer, s: &MockServer) -> String {
    let m = match r {
        Err(SwapError::Transient(m)) => m,
        other => panic!("want Transient, got {other:?}"),
    };
    assert!(m.contains(&p.uri()), "primary named: {m}");
    assert!(m.contains(&s.uri()), "source named: {m}");
    assert!(!m.contains(&hex::encode(TAKER_KEY)), "no key: {m}");
    m
}

/// Fail-first 1: the primary shows the agreed script and the full value; the cross-check
/// source shows another scriptPubKey at that outpoint. Neither side may act on it.
#[tokio::test]
async fn lock_crosscheck_wrong_script_on_the_source_is_transient() {
    for kind in BOTH_SOURCES {
        let (_, hash) = new_preimage();
        let h = htlc(hash);
        let (_, other) = new_preimage();
        let p = lock_primary(&spk_of(&h)).await;
        let s = lock_source(kind, lock_tx(kind, &spk_of(&htlc(other)), LOCK_SATS, 2)).await;
        let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
        let m = lock_held(b.htlc_output(&h, &outpoint()).await, &p, &s);
        assert!(m.contains("script"), "{kind:?}: {m}");
    }
}

/// Fail-first 2: the source shows the agreed script but a value below the agreed amount
/// (and below the primary's).
#[tokio::test]
async fn lock_crosscheck_short_value_on_the_source_is_transient() {
    for kind in BOTH_SOURCES {
        let (_, hash) = new_preimage();
        let h = htlc(hash);
        let p = lock_primary(&spk_of(&h)).await;
        let s = lock_source(kind, lock_tx(kind, &spk_of(&h), LOCK_SATS - 1_000, 2)).await;
        let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
        let m = lock_held(b.htlc_output(&h, &outpoint()).await, &p, &s);
        assert!(
            m.contains(&(LOCK_SATS - 1_000).to_string()),
            "{kind:?}: {m}"
        );
        assert!(m.contains(&LOCK_SATS.to_string()), "{kind:?}: {m}");
    }
}

/// Both sources show the same script and value: the lock is returned with the lower of the
/// two confirmation counts.
#[tokio::test]
async fn lock_crosscheck_agree_returns_the_lock_with_the_lower_confirmations() {
    for kind in BOTH_SOURCES {
        for (theirs, want) in [(1, 1), (0, 0), (5, 2)] {
            let (_, hash) = new_preimage();
            let h = htlc(hash);
            let p = lock_primary(&spk_of(&h)).await;
            let s = lock_source(
                kind,
                lock_tx(kind, &spk_of(&h).to_uppercase(), LOCK_SATS, theirs),
            )
            .await;
            let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
            let lo = b.htlc_output(&h, &outpoint()).await.unwrap();
            assert_eq!(
                lo,
                Some(LockedOutput {
                    amount: Amount::from_sat(LOCK_SATS),
                    confirmations: want,
                }),
                "{kind:?} source confs {theirs}"
            );
        }
    }
}

/// The source down, rate-limited, without the transaction or malformed: the lock read fails
/// closed (nothing is at risk while the maker waits to fund or the taker waits to reveal).
#[tokio::test]
async fn lock_crosscheck_source_down_fails_closed() {
    for kind in BOTH_SOURCES {
        for resp in [
            ResponseTemplate::new(404),
            ResponseTemplate::new(429),
            ResponseTemplate::new(500),
            ResponseTemplate::new(200).set_body_string("<html>oops</html>"),
            ResponseTemplate::new(200).set_body_string("{}"),
        ] {
            let (_, hash) = new_preimage();
            let h = htlc(hash);
            let p = lock_primary(&spk_of(&h)).await;
            let s = lock_source(kind, resp).await;
            let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
            lock_held(b.htlc_output(&h, &outpoint()).await, &p, &s);
        }
        let (_, hash) = new_preimage();
        let h = htlc(hash);
        let p = lock_primary(&spk_of(&h)).await;
        let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, dead_url());
        match b.htlc_output(&h, &outpoint()).await {
            Err(SwapError::Transient(m)) => assert!(m.contains(&dead_url()), "{m}"),
            other => panic!("{kind:?}: want Transient, got {other:?}"),
        }
    }
}

/// The source is asked once per primary answer: a lock polled every engine tick does not
/// spend a rate-limited source's quota, and a new primary block asks again.
#[tokio::test]
async fn lock_crosscheck_asks_the_source_once_per_primary_answer() {
    let kind = CrossCheckSource::Blockbook;
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let p = lock_primary(&spk_of(&h)).await;
    let s = lock_source(kind, lock_tx(kind, &spk_of(&h), LOCK_SATS, 2)).await;
    let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
    for _ in 0..3 {
        assert!(b.htlc_output(&h, &outpoint()).await.unwrap().is_some());
    }
    assert_eq!(requests_to(&s).await, 1);
    p.reset().await;
    mount_lock_primary(&p, &spk_of(&h), 111).await;
    let lo = b.htlc_output(&h, &outpoint()).await.unwrap().unwrap();
    assert_eq!(requests_to(&s).await, 2);
    // Primary 3, source (as mocked) 2.
    assert_eq!(lo.confirmations, 2);
}

/// Off (the default, and `with_claim_crosscheck(None)`): today's request sequence to the
/// primary exactly, nothing to the source, and today's answer.
#[tokio::test]
async fn lock_crosscheck_off_is_todays_lock_read() {
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let s = lock_source(
        CrossCheckSource::Blockbook,
        lock_tx(CrossCheckSource::Blockbook, "00", 1, 0),
    )
    .await;
    for explicit in [false, true] {
        let p = lock_primary(&spk_of(&h)).await;
        let b = if explicit {
            cc_mainnet(&p).with_claim_crosscheck(None)
        } else {
            cc_mainnet(&p)
        };
        let lo = b.htlc_output(&h, &outpoint()).await.unwrap();
        assert_eq!(
            lo,
            Some(LockedOutput {
                amount: Amount::from_sat(LOCK_SATS),
                confirmations: 2,
            })
        );
        let seen: Vec<String> = p
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect();
        assert_eq!(
            seen,
            [
                format!("GET /tx/{}", outpoint().txid),
                "GET /blocks/tip/height".to_string()
            ]
        );
    }
    assert_eq!(requests_to(&s).await, 0);
}

/// The primary shows no matching lock: nothing to agree, no source request (no side acts on
/// `None`), as today.
#[tokio::test]
async fn lock_crosscheck_primary_none_asks_nothing_more() {
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let (_, other) = new_preimage();
    let p = lock_primary(&spk_of(&htlc(other))).await;
    let s = lock_source(
        CrossCheckSource::Blockbook,
        lock_tx(CrossCheckSource::Blockbook, &spk_of(&h), LOCK_SATS, 2),
    )
    .await;
    let b = cc_mainnet(&p).with_claim_crosscheck_at(CrossCheckSource::Blockbook, s.uri());
    assert_eq!(b.htlc_output(&h, &outpoint()).await.unwrap(), None);
    assert_eq!(requests_to(&s).await, 0);
}

// --- find_spend from two sources (EN, T32-2) ---
//
// With `[ltc].crosscheck_before_claim` on, `find_spend` also asks the cross-check source and
// agrees the two answers as `swap-chain-btc`'s `quorum::agree_spend` does. The source's
// shapes (single-source-design.FACTS.md): the lock transaction's output `n` shows its
// spender (Blockbook `GET /tx/{txid}` `vout[].spent` / `vout[].spentTxId`; BlockCypher
// `GET /txs/{txid}` `outputs[].spent_by`); the spender itself is read as raw hex (Blockbook
// `GET /tx/{txid}` `hex` and `blockHeight`, -1 in the mempool, falling back to
// `GET /tx-specific/{txid}` `hex` when `hex` is absent; BlockCypher
// `GET /txs/{txid}?includeHex=true` `hex` and `block_height`, -1 when unconfirmed), so the
// spending input's scriptSig and witness (the preimage) are compared byte for byte.

const FS_HEIGHT: u64 = 777;

/// A claim's witness for `h`: signature, preimage, the claim branch selector, the script.
fn fs_claim_witness(h: &HtlcParams, pre: &[u8; 32]) -> Vec<Vec<u8>> {
    vec![vec![0x30; 71], pre.to_vec(), vec![1], h.redeem_script()]
}

/// A refund's witness for `h`: signature, the empty refund branch selector, the script.
fn fs_refund_witness(h: &HtlcParams) -> Vec<Vec<u8>> {
    vec![vec![0x30; 71], vec![], h.redeem_script()]
}

/// A transaction spending [`outpoint`] at input 1 with `witness`. Its txid commits to
/// neither witness, so a claim and a refund with the same other fields share a txid.
fn fs_spender(witness: &[Vec<u8>], fee_tag: u64) -> bitcoin::Transaction {
    use bitcoin::{ScriptBuf, Sequence, TxIn, TxOut, Witness};
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([7; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![0x02; 33]]),
            },
            TxIn {
                previous_output: ltc_outpoint(&outpoint()),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(witness),
            },
        ],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(19_000 - fee_tag),
            script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0x11]),
        }],
    }
}

fn fs_txid(t: &bitcoin::Transaction) -> String {
    t.compute_txid().to_string()
}

/// A mainnet primary Esplora that shows [`outpoint`] spent by `spender` at `height` (`None`:
/// in the mempool), or unspent.
async fn fs_primary(spender: Option<(&bitcoin::Transaction, Option<u64>)>) -> MockServer {
    let s = MockServer::start().await;
    let o = outpoint();
    let outspend = match spender {
        None => json!({"spent": false}),
        Some((t, h)) => {
            let status = match h {
                Some(h) => json!({"confirmed": true, "block_height": h}),
                None => json!({"confirmed": false}),
            };
            json!({"spent": true, "txid": fs_txid(t), "vin": 1, "status": status})
        }
    };
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}/outspend/{}", o.txid, o.vout)))
        .respond_with(ResponseTemplate::new(200).set_body_json(outspend))
        .mount(&s)
        .await;
    if let Some((t, _)) = spender {
        let vin: Vec<Value> = t
            .input
            .iter()
            .map(|i| {
                json!({
                    "txid": i.previous_output.txid.to_string(),
                    "vout": i.previous_output.vout,
                    "scriptsig": hex::encode(i.script_sig.as_bytes()),
                    "witness": i.witness.iter().map(hex::encode).collect::<Vec<_>>(),
                })
            })
            .collect();
        Mock::given(method("GET"))
            .and(path(format!("/tx/{}", fs_txid(t))))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"txid": fs_txid(t), "vin": vin})),
            )
            .mount(&s)
            .await;
    }
    s
}

/// `kind`'s body for the spending transaction `t` at `height` (`None`: mempool).
fn fs_source_tx(kind: CrossCheckSource, t: &bitcoin::Transaction, height: Option<u64>) -> Value {
    let raw = hex::encode(serialize(t));
    let h = height.map_or(-1, |h| h as i64);
    match kind {
        CrossCheckSource::Blockbook => json!({"txid": fs_txid(t), "blockHeight": h,
            "confirmations": if height.is_some() { 3 } else { 0 }, "hex": raw}),
        CrossCheckSource::BlockCypher => json!({"hash": fs_txid(t), "block_height": h,
            "confirmations": if height.is_some() { 3 } else { 0 }, "hex": raw}),
    }
}

fn fs_source_tx_path(kind: CrossCheckSource, txid: &str) -> String {
    match kind {
        CrossCheckSource::Blockbook => format!("/tx/{txid}"),
        CrossCheckSource::BlockCypher => format!("/txs/{txid}"),
    }
}

/// A cross-check source of `kind` whose lock transaction shows output 1 spent by
/// `spent_by` (or unspent), and that knows the transactions in `knows` at their heights.
async fn fs_source(
    kind: CrossCheckSource,
    spent_by: Option<&str>,
    knows: &[(&bitcoin::Transaction, Option<u64>)],
) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(lock_tx_path(kind)))
        .respond_with(cc_tx(kind, spent_by))
        .mount(&s)
        .await;
    for (t, h) in knows {
        Mock::given(method("GET"))
            .and(path(fs_source_tx_path(kind, &fs_txid(t))))
            .respond_with(ResponseTemplate::new(200).set_body_json(fs_source_tx(kind, t, *h)))
            .mount(&s)
            .await;
    }
    s
}

fn fs_backend(p: &MockServer, kind: CrossCheckSource, s: &MockServer) -> LtcBackend {
    cc_mainnet(p).with_claim_crosscheck_at(kind, s.uri())
}

/// A `find_spend` the two sources disagree on: `Held` (the engine retries, and reads on the
/// primary alone once a refund waiting on it is one margin past its locktime, EU), naming
/// both sources.
fn fs_held(r: Result<Option<SpendInfo>>, p: &MockServer, s: &MockServer) -> String {
    let m = match r {
        Err(SwapError::Held(m)) => m,
        other => panic!("want Held, got {other:?}"),
    };
    assert!(m.contains(&p.uri()), "primary named: {m}");
    assert!(m.contains(&s.uri()), "source named: {m}");
    m
}

/// Fail-first 1, hidden spend: the source shows the lock spent by a claim, the primary says
/// unspent. `None` would read as "not spent" (the maker never learns the preimage while the
/// taker's refund locktime runs out); it must be held (`Held`, EU; `Transient` before).
#[tokio::test]
async fn find_spend_hidden_by_the_primary_is_held() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    for kind in BOTH_SOURCES {
        let p = fs_primary(None).await;
        let s = fs_source(kind, Some(&fs_txid(&claim)), &[(&claim, Some(FS_HEIGHT))]).await;
        let b = fs_backend(&p, kind, &s);
        let m = fs_held(b.find_spend(&outpoint(), 700).await, &p, &s);
        assert!(m.contains("unspent"), "{m}");
        assert!(m.contains(&fs_txid(&claim)), "{m}");
    }
}

/// Fail-first 2, different spender: both say spent, by different transactions (the primary
/// shows a refund, the source a claim). Today the primary's answer is returned.
#[tokio::test]
async fn find_spend_two_different_spenders_is_held() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    let refund = fs_spender(&fs_refund_witness(&h), 1);
    assert_ne!(fs_txid(&claim), fs_txid(&refund));
    for kind in BOTH_SOURCES {
        let p = fs_primary(Some((&refund, Some(FS_HEIGHT)))).await;
        let s = fs_source(kind, Some(&fs_txid(&claim)), &[(&claim, Some(FS_HEIGHT))]).await;
        let b = fs_backend(&p, kind, &s);
        let m = fs_held(b.find_spend(&outpoint(), 700).await, &p, &s);
        assert!(
            m.contains(&fs_txid(&claim)) && m.contains(&fs_txid(&refund)),
            "{m}"
        );
    }
}

/// Fail-first 2b, same txid with a different witness: a txid does not commit to the
/// witness, so the primary can show the real spender with another preimage (or a refund's
/// empty branch). Today the primary's witness is returned.
#[tokio::test]
async fn find_spend_same_spender_with_a_different_witness_is_held() {
    let (pre, hash) = new_preimage();
    let (wrong, _) = new_preimage();
    let h = htlc(hash);
    let real = fs_spender(&fs_claim_witness(&h, &pre), 0);
    for lie in [
        fs_spender(&fs_claim_witness(&h, &wrong), 0),
        fs_spender(&fs_refund_witness(&h), 0),
    ] {
        assert_eq!(fs_txid(&lie), fs_txid(&real));
        for kind in BOTH_SOURCES {
            let p = fs_primary(Some((&lie, Some(FS_HEIGHT)))).await;
            let s = fs_source(kind, Some(&fs_txid(&real)), &[(&real, Some(FS_HEIGHT))]).await;
            let b = fs_backend(&p, kind, &s);
            let m = fs_held(b.find_spend(&outpoint(), 700).await, &p, &s);
            assert!(m.contains("witness"), "{m}");
        }
    }
}

/// Fail-first 3, invented spend: the primary shows a spend the source does not know (the
/// lock unspent there, and no such transaction). Today it is returned.
#[tokio::test]
async fn find_spend_invented_by_the_primary_is_held() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    for kind in BOTH_SOURCES {
        let p = fs_primary(Some((&claim, Some(FS_HEIGHT)))).await;
        // No mock for the spender: wiremock answers 404 (Blockbook answers 400 for an
        // unknown txid; both are a refusal, not an outage).
        let s = fs_source(kind, None, &[]).await;
        let b = fs_backend(&p, kind, &s);
        let m = fs_held(b.find_spend(&outpoint(), 700).await, &p, &s);
        assert!(m.contains(&fs_txid(&claim)), "{m}");
    }
    // Blockbook's own answer for an unknown txid.
    let p = fs_primary(Some((&claim, Some(FS_HEIGHT)))).await;
    let s = fs_source(CrossCheckSource::Blockbook, None, &[]).await;
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}", fs_txid(&claim))))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            json!({"error": format!("Transaction '{}' not found", fs_txid(&claim))}),
        ))
        .mount(&s)
        .await;
    let b = fs_backend(&p, CrossCheckSource::Blockbook, &s);
    fs_held(b.find_spend(&outpoint(), 700).await, &p, &s);
}

/// Both agree: the spend is returned with the preimage. Where the two place it differently
/// the lower confirmation count wins (the later block; the mempool over a block), so a
/// lying primary cannot make a spend look deeper than the source has it.
#[tokio::test]
async fn find_spend_both_agree_returns_it_with_the_fewer_confirmations() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    let cases = [
        (Some(FS_HEIGHT), Some(FS_HEIGHT), Some(FS_HEIGHT)),
        (Some(FS_HEIGHT), Some(FS_HEIGHT + 1), Some(FS_HEIGHT + 1)),
        (Some(FS_HEIGHT + 1), Some(FS_HEIGHT), Some(FS_HEIGHT + 1)),
        (Some(FS_HEIGHT), None, None),
        (None, Some(FS_HEIGHT), None),
        (None, None, None),
    ];
    for kind in BOTH_SOURCES {
        for (mine, theirs, want) in cases {
            let p = fs_primary(Some((&claim, mine))).await;
            let s = fs_source(kind, Some(&fs_txid(&claim)), &[(&claim, theirs)]).await;
            let b = fs_backend(&p, kind, &s);
            let spend = b
                .find_spend(&outpoint(), 700)
                .await
                .unwrap()
                .expect("spent");
            assert_eq!(spend.txid, Txid::from_rpc_hex(&fs_txid(&claim)).unwrap());
            assert_eq!(spend.input_index, 1);
            assert_eq!(
                spend.height, want,
                "{kind:?} primary {mine:?} source {theirs:?}"
            );
            assert_eq!(spend.extract_preimage(&hash), Some(pre));
        }
        // Both unspent.
        let p = fs_primary(None).await;
        let s = fs_source(kind, None, &[]).await;
        assert_eq!(
            fs_backend(&p, kind, &s)
                .find_spend(&outpoint(), 700)
                .await
                .unwrap(),
            None
        );
    }
}

/// The source has the spender in its index before its lock view marks the output spent
/// (or, on Blockbook, marks it spent without naming the spender): the spender is still
/// read and agreed.
#[tokio::test]
async fn find_spend_agrees_when_the_source_names_no_spender_but_knows_it() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    for kind in BOTH_SOURCES {
        let p = fs_primary(Some((&claim, None))).await;
        let s = fs_source(kind, None, &[(&claim, None)]).await;
        let spend = fs_backend(&p, kind, &s)
            .find_spend(&outpoint(), 700)
            .await
            .unwrap()
            .expect("spent");
        assert_eq!(spend.extract_preimage(&hash), Some(pre));
    }
    let p = fs_primary(Some((&claim, Some(FS_HEIGHT)))).await;
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(lock_tx_path(CrossCheckSource::Blockbook)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"vout": [
            {"n": 0, "value": "5"}, {"n": 1, "value": "20000", "spent": true}]})))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}", fs_txid(&claim))))
        .respond_with(ResponseTemplate::new(200).set_body_json(fs_source_tx(
            CrossCheckSource::Blockbook,
            &claim,
            Some(FS_HEIGHT),
        )))
        .mount(&s)
        .await;
    let spend = fs_backend(&p, CrossCheckSource::Blockbook, &s)
        .find_spend(&outpoint(), 700)
        .await
        .unwrap()
        .expect("spent");
    assert_eq!(spend.height, Some(FS_HEIGHT));
}

/// Blockbook's normalized transaction carries `hex` for confirmed transactions; for a
/// mempool spender without it, the backend-native `GET /tx-specific/{txid}` `hex` is read.
#[tokio::test]
async fn find_spend_blockbook_mempool_spender_without_hex_reads_tx_specific() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    let p = fs_primary(Some((&claim, None))).await;
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(lock_tx_path(CrossCheckSource::Blockbook)))
        .respond_with(cc_tx(CrossCheckSource::Blockbook, Some(&fs_txid(&claim))))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/tx/{}", fs_txid(&claim))))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"txid": fs_txid(&claim), "blockHeight": -1, "confirmations": 0}),
            ),
        )
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/tx-specific/{}", fs_txid(&claim))))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"txid": fs_txid(&claim), "hex": hex::encode(serialize(&claim))}),
            ),
        )
        .mount(&s)
        .await;
    let spend = fs_backend(&p, CrossCheckSource::Blockbook, &s)
        .find_spend(&outpoint(), 700)
        .await
        .unwrap()
        .expect("spent");
    assert_eq!(spend.height, None);
    assert_eq!(spend.extract_preimage(&hash), Some(pre));
}

/// Source down (429, 5xx, unreachable, malformed): the LTC claim-time rule, not the lock
/// rule. One warning naming the source and the outpoint, then the primary's answer, as
/// today: failing closed here would hold the maker's refund (`on_maker_refundable` reads
/// `find_spend` first) and its preimage watch behind a rate-limited third-party explorer.
#[tokio::test]
async fn find_spend_source_down_warns_and_returns_the_primarys_answer() {
    let buf = LogBuf::default();
    let w = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || w.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);

    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    let mut warned = 0;
    for resp in [
        ResponseTemplate::new(429),
        ResponseTemplate::new(503),
        ResponseTemplate::new(200).set_body_string("<html>"),
    ] {
        for mine in [None, Some((&claim, Some(FS_HEIGHT)))] {
            let p = fs_primary(mine).await;
            let s = lock_source(CrossCheckSource::Blockbook, resp.clone()).await;
            let b = fs_backend(&p, CrossCheckSource::Blockbook, &s);
            let got = b.find_spend(&outpoint(), 700).await.unwrap();
            assert_eq!(
                got.map(|s| s.txid),
                mine.map(|(t, _)| Txid::from_rpc_hex(&fs_txid(t)).unwrap())
            );
            warned += 1;
        }
    }
    // A primary spend the source knows nothing reliable about (its spender read is down).
    let p = fs_primary(Some((&claim, Some(FS_HEIGHT)))).await;
    let s = fs_source(CrossCheckSource::BlockCypher, None, &[]).await;
    Mock::given(method("GET"))
        .and(path(format!("/txs/{}", fs_txid(&claim))))
        .respond_with(ResponseTemplate::new(503))
        .mount(&s)
        .await;
    let b = fs_backend(&p, CrossCheckSource::BlockCypher, &s);
    assert!(b.find_spend(&outpoint(), 700).await.unwrap().is_some());
    warned += 1;
    // Unreachable.
    let p = fs_primary(None).await;
    let b = cc_mainnet(&p).with_claim_crosscheck_at(CrossCheckSource::Blockbook, dead_url());
    assert_eq!(b.find_spend(&outpoint(), 700).await.unwrap(), None);
    warned += 1;

    let log = buf.text();
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("find_spend cross-check unavailable"))
        .collect();
    assert_eq!(lines.len(), warned, "{log}");
    for l in lines {
        assert!(l.contains(&outpoint().to_string()), "outpoint: {l}");
    }
}

/// The source is asked once per primary answer while that answer stands (within one LTC
/// block time): the engine polls every 5 s and BlockCypher's keyless quota is 100/hour.
#[tokio::test]
async fn find_spend_asks_the_source_once_per_primary_answer() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    for kind in BOTH_SOURCES {
        let p = fs_primary(Some((&claim, Some(FS_HEIGHT)))).await;
        let s = fs_source(kind, Some(&fs_txid(&claim)), &[(&claim, Some(FS_HEIGHT))]).await;
        let b = fs_backend(&p, kind, &s);
        for _ in 0..3 {
            assert!(b.find_spend(&outpoint(), 700).await.unwrap().is_some());
        }
        assert_eq!(
            requests_to(&s).await,
            2,
            "{kind:?}: lock view and spender, once"
        );
        // A disagreement is reused the same way, and stays a disagreement.
        let p = fs_primary(None).await;
        let s = fs_source(kind, Some(&fs_txid(&claim)), &[(&claim, Some(FS_HEIGHT))]).await;
        let b = fs_backend(&p, kind, &s);
        for _ in 0..3 {
            fs_held(b.find_spend(&outpoint(), 700).await, &p, &s);
        }
        assert_eq!(requests_to(&s).await, 1, "{kind:?}: lock view once");
    }
}

/// Opt-in off: today's read exactly, the primary's answer and requests, nothing to the
/// source, even where the source would disagree.
#[tokio::test]
async fn find_spend_crosscheck_off_is_todays_read() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    let s = fs_source(CrossCheckSource::Blockbook, None, &[]).await;
    for (mine, want_reqs) in [(None, 1), (Some((&claim, Some(FS_HEIGHT))), 2)] {
        let p = fs_primary(mine).await;
        for b in [cc_mainnet(&p), cc_mainnet(&p).with_claim_crosscheck(None)] {
            let got = b.find_spend(&outpoint(), 700).await.unwrap();
            assert_eq!(got.as_ref().map(|s| s.height), mine.map(|(_, h)| h));
        }
        let seen: Vec<String> = p
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect();
        let o = outpoint();
        let mut want = vec![format!("GET /tx/{}/outspend/{}", o.txid, o.vout)];
        if mine.is_some() {
            want.push(format!("GET /tx/{}", fs_txid(&claim)));
        }
        let want: Vec<String> = want.iter().chain(want.iter()).cloned().collect();
        assert_eq!(seen.len(), 2 * want_reqs);
        assert_eq!(seen, want);
    }
    assert_eq!(requests_to(&s).await, 0);
}

// ---- the bounded hold (EU): `Held` and the primary-only view ---------------------------

/// Opt-in off: nothing is ever held, so there is no primary-only view.
#[tokio::test]
async fn crosscheck_off_has_no_primary_only_view() {
    let p = MockServer::start().await;
    assert!(cc_mainnet(&p).primary_only().is_none());
    assert!(cc_mainnet(&p)
        .with_claim_crosscheck(None)
        .primary_only()
        .is_none());
    assert!(backend(vec![dead_url()], TAKER_KEY)
        .primary_only()
        .is_none());
    assert_eq!(requests_to(&p).await, 0);
}

/// The primary-only view of a backend whose source disagrees on the claim: the same key and
/// primary, the claim cross-check off. It builds the claim the backend would build with the
/// opt-in off, byte for byte, and asks the source nothing.
#[tokio::test]
async fn the_primary_only_view_builds_a_claim_without_asking_the_source() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let amount = Amount::from_sat(20_000);
    for kind in BOTH_SOURCES {
        let p = cc_primary_full(CC_HASH_B, None).await;
        let s = cc_source(kind, TIP_B, cc_tx(kind, None)).await;
        let b = cc_mainnet(&p).with_claim_crosscheck_at(kind, s.uri());
        cc_held(b.build_claim(&h, &outpoint(), amount, &pre).await);
        let asked = requests_to(&s).await;
        let view = b.primary_only().expect("a view with the cross-check on");
        let plain = cc_mainnet(&p);
        assert_eq!(
            view.build_claim(&h, &outpoint(), amount, &pre)
                .await
                .unwrap(),
            plain
                .build_claim(&h, &outpoint(), amount, &pre)
                .await
                .unwrap()
        );
        assert_eq!(
            view.build_claim_at(&h, &outpoint(), amount, &pre, 7)
                .await
                .unwrap(),
            plain
                .build_claim_at(&h, &outpoint(), amount, &pre, 7)
                .await
                .unwrap()
        );
        assert_eq!(
            requests_to(&s).await,
            asked,
            "{kind:?}: the view asked the source"
        );
    }
}

/// The view's refund is the opt-in-off refund, byte for byte, and verifies.
#[tokio::test]
async fn the_primary_only_view_builds_the_refund_of_the_same_key() {
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let amount = Amount::from_sat(20_000);
    let p = MockServer::start().await;
    let s = MockServer::start().await;
    let maker = |c: Option<&MockServer>| {
        let b = LtcBackend::new_on(
            "mainnet",
            vec![p.uri()],
            SecretKey::from_slice(&MAKER_KEY).unwrap(),
            FeePolicy::Fixed(1),
            fast(),
        )
        .unwrap();
        match c {
            Some(c) => b.with_claim_crosscheck_at(CrossCheckSource::Blockbook, c.uri()),
            None => b,
        }
    };
    let view = maker(Some(&s)).primary_only().unwrap();
    let refund = view.build_refund(&h, &outpoint(), amount).await.unwrap();
    assert_eq!(
        refund,
        maker(None)
            .build_refund(&h, &outpoint(), amount)
            .await
            .unwrap()
    );
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&refund.raw).unwrap();
    verify_htlc_spend(&tx, &h, 20_000).unwrap();
    assert_eq!(requests_to(&s).await, 0);
}

/// The view's `find_spend` is the primary's answer where the source disagrees (EN's
/// agreement off), asking the source nothing.
#[tokio::test]
async fn the_primary_only_view_reads_the_primarys_spend_without_asking_the_source() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let claim = fs_spender(&fs_claim_witness(&h, &pre), 0);
    for kind in BOTH_SOURCES {
        let p = fs_primary(Some((&claim, Some(FS_HEIGHT)))).await;
        let s = fs_source(kind, None, &[]).await;
        let b = fs_backend(&p, kind, &s);
        fs_held(b.find_spend(&outpoint(), 700).await, &p, &s);
        let asked = requests_to(&s).await;
        let got = b
            .primary_only()
            .unwrap()
            .find_spend(&outpoint(), 700)
            .await
            .unwrap()
            .expect("the primary's spend");
        assert_eq!(got.txid.to_rpc_hex(), fs_txid(&claim));
        assert_eq!(got.extract_preimage(&hash), Some(pre));
        assert_eq!(
            requests_to(&s).await,
            asked,
            "{kind:?}: the view asked the source"
        );
    }
}

// ---- dual broadcast (EO, `[ltc].dual_broadcast`): every POST goes to the primary and the
// secondary Esplora. Esplora `POST /tx` answers the txid on success
// (single-source-design.FACTS.md, Esplora `POST /tx`).

fn dual(primary: &MockServer, secondary: &MockServer) -> LtcBackend {
    backend(vec![primary.uri(), secondary.uri()], TAKER_KEY)
        .with_dual_broadcast(true)
        .unwrap()
}

/// A claim of `outpoint()` signed by the taker key (no request: the fee is fixed).
async fn a_claim() -> SignedTx {
    let (pre, hash) = new_preimage();
    backend(vec![dead_url()], TAKER_KEY)
        .build_claim(&htlc(hash), &outpoint(), Amount::from_sat(20_000), &pre)
        .await
        .unwrap()
}

async fn mock_post(server: &MockServer, resp: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(resp)
        .mount(server)
        .await;
}

fn accepts(tx: &SignedTx) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string(tx.txid.to_rpc_hex())
}

fn refuses(reason: &str) -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_string(format!(
        "sendrawtransaction RPC error: {{\"code\":-26,\"message\":\"{reason}\"}}"
    ))
}

/// The raw hex bodies `server` was POSTed at `/tx`.
async fn posted(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/tx")
        .map(|r| String::from_utf8(r.body.clone()).unwrap())
        .collect()
}

/// A primary that refuses the claim, or accepts it and then drops it, cannot keep it off the
/// network: the secondary is given the same claim.
#[tokio::test]
async fn dual_broadcast_claim_dropped_by_the_primary_reaches_the_secondary() {
    let claim = a_claim().await;
    for primary_says in [refuses("min relay fee not met"), accepts(&claim)] {
        let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
        mock_post(&primary, primary_says).await;
        mock_post(&secondary, accepts(&claim)).await;
        assert_eq!(
            dual(&primary, &secondary).broadcast(&claim).await.unwrap(),
            claim.txid
        );
        assert_eq!(posted(&secondary).await, [hex::encode(&claim.raw)]);
        assert_eq!(posted(&primary).await, [hex::encode(&claim.raw)]);
    }
}

/// One endpoint accepting (or reporting already-known) is a broadcast; both accepting is one
/// txid and one POST each.
#[tokio::test]
async fn dual_broadcast_one_accepting_is_enough_and_both_post_once() {
    let claim = a_claim().await;
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_post(&primary, accepts(&claim)).await;
    mock_post(&secondary, accepts(&claim)).await;
    assert_eq!(
        dual(&primary, &secondary).broadcast(&claim).await.unwrap(),
        claim.txid
    );
    assert_eq!(posted(&primary).await.len(), 1);
    assert_eq!(posted(&secondary).await.len(), 1);

    let b = backend(vec![primary.uri(), dead_url()], TAKER_KEY)
        .with_dual_broadcast(true)
        .unwrap();
    assert_eq!(b.broadcast(&claim).await.unwrap(), claim.txid);

    let (p2, s2) = (MockServer::start().await, MockServer::start().await);
    mock_post(&p2, refuses("bad-txns-inputs-duplicate")).await;
    mock_post(
        &s2,
        ResponseTemplate::new(400).set_body_string(
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"txn-already-in-mempool\"}",
        ),
    )
    .await;
    assert_eq!(dual(&p2, &s2).broadcast(&claim).await.unwrap(), claim.txid);
}

/// An endpoint that answers 200 with another txid has not taken our transaction: with nothing
/// else accepting it, the broadcast fails naming that endpoint and both txids.
#[tokio::test]
async fn dual_broadcast_another_txid_is_an_error_naming_the_endpoint() {
    let claim = a_claim().await;
    let other = "ab".repeat(32);
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_post(&primary, ResponseTemplate::new(200).set_body_string(&other)).await;
    mock_post(&secondary, refuses("mempool full")).await;
    let e = dual(&primary, &secondary)
        .broadcast(&claim)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        e.contains(&primary.uri()) && e.contains(&other) && e.contains(&claim.txid.to_rpc_hex()),
        "{e}"
    );
}

/// Both refusing is today's error (a refund before its locktime stays `Premature`).
#[tokio::test]
async fn dual_broadcast_both_refusing_is_todays_error() {
    let claim = a_claim().await;
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_post(&primary, refuses("non-final")).await;
    mock_post(&secondary, refuses("non-final")).await;
    let r = dual(&primary, &secondary).broadcast(&claim).await;
    assert!(matches!(r, Err(SwapError::Premature(_))), "{r:?}");
    let b = backend(vec![dead_url(), secondary.uri()], TAKER_KEY)
        .with_dual_broadcast(true)
        .unwrap();
    let r = b.broadcast(&claim).await;
    assert!(matches!(r, Err(SwapError::Premature(_))), "{r:?}");
}

/// Off (the default): one POST to the primary, its body ignored, nothing to the secondary.
#[tokio::test]
async fn dual_broadcast_off_is_unchanged() {
    let claim = a_claim().await;
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_post(
        &primary,
        ResponseTemplate::new(200).set_body_string("not a txid"),
    )
    .await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&secondary)
        .await;
    for on in [None, Some(false)] {
        let b = backend(vec![primary.uri(), secondary.uri()], TAKER_KEY);
        let b = match on {
            Some(on) => b.with_dual_broadcast(on).unwrap(),
            None => b,
        };
        assert_eq!(b.broadcast(&claim).await.unwrap(), claim.txid);
    }
    assert_eq!(posted(&primary).await.len(), 2);
    assert_eq!(primary.received_requests().await.unwrap().len(), 2);
    assert!(secondary.received_requests().await.unwrap().is_empty());
}

#[test]
fn dual_broadcast_needs_two_endpoints() {
    let one = backend(vec![dead_url()], TAKER_KEY);
    assert!(matches!(
        one.with_dual_broadcast(true),
        Err(SwapError::InvalidParams(_))
    ));
    let one = backend(vec![dead_url()], TAKER_KEY);
    assert!(one.with_dual_broadcast(false).is_ok());
}
