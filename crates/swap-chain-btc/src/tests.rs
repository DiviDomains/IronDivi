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

fn fast() -> RetryPolicy {
    RetryPolicy {
        attempts: 3,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
    }
}

fn backend(urls: Vec<String>, key: [u8; 32]) -> BtcBackend {
    BtcBackend::new(
        urls,
        SecretKey::from_slice(&key).unwrap(),
        FeePolicy::Fixed(2),
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
    // The claim cannot be verified against a different amount (sighash commits to it).
    assert!(verify_htlc_spend(&tx, &h, 19_999).is_err());
}

#[tokio::test]
async fn claim_sizes_are_the_vsize_a_claim_is_charged_for() {
    let (pre, hash) = new_preimage();
    let h = htlc(hash);
    let b = backend(vec![dead_url()], TAKER_KEY);
    let sizes = b.claim_sizes(&h).unwrap();
    assert_eq!((sizes.child_vsize, sizes.dust), (0, DUST_SATS));
    let signed = b
        .build_claim_at(&h, &outpoint(), Amount::from_sat(1_000_000), &pre, 10)
        .await
        .unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&signed.raw).unwrap();
    // The fee is computed on the same 72-byte-signature size the ceiling divides by.
    assert_eq!(
        1_000_000 - tx.output[0].value.to_sat(),
        10 * sizes.claim_vsize
    );
    let actual = tx.vsize() as u64;
    assert!(actual <= sizes.claim_vsize && actual + 1 >= sizes.claim_vsize);
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
    // Bitcoin Core >= 0.21 rejects a re-broadcast of a confirmed tx with this -27 message.
    assert!(is_already_known(
        "sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction outputs already in utxo set\"}"
    ));
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
        .respond_with(ResponseTemplate::new(200).set_body_string("325405"))
        .expect(1)
        .mount(&server)
        .await;
    let b = backend(vec![server.uri()], TAKER_KEY);
    assert_eq!(b.tip_height().await.unwrap(), 325_405);
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
    assert_eq!(tx.output[1].script_pubkey, b.address().script_pubkey());
    let fee = 25_000 - 20_000 - tx.output[1].value.to_sat();
    // Estimating with dummy 72-byte signatures never undershoots the real size; real DER
    // signatures are 71-72 bytes, so it overshoots by under 1 vB per input.
    let real = 2 * tx.vsize() as u64;
    assert!(
        fee >= real && fee <= real + 2 * tx.input.len() as u64,
        "fee {fee} is 2 sat/vB of the signed size {real}"
    );

    // 5,000 fits in the largest confirmed coin alone, with change.
    let f = b.build_funding(&h, Amount::from_sat(5_000)).await.unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);

    // A remainder below dust is folded into the fee instead of a change output.
    let f = b.build_funding(&h, Amount::from_sat(14_650)).await.unwrap();
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

#[tokio::test]
async fn funding_from_empty_wallet_is_insufficient_funds() {
    // An Esplora on the wrong network returns `[]` for the address; that used to panic with a
    // subtract overflow in coin selection instead of reporting insufficient funds.
    let server = MockServer::start().await;
    let b = backend(vec![server.uri()], MAKER_KEY);
    let addr = b.address().to_string();
    Mock::given(method("GET"))
        .and(path(format!("/address/{addr}/utxo")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    let (_, hash) = new_preimage();
    let err = b
        .build_funding(&htlc(hash), Amount::from_sat(20_000))
        .await
        .unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
}

#[cfg(feature = "live")]
mod live {
    use std::time::Duration;

    use crate::{BtcBackend, FeePolicy};
    use divi_swap::htlc::new_preimage;
    use divi_swap::secrets::SecretRef;
    use divi_swap::{Amount, ChainBackend, HtlcParams, SignedTx, SwapError, Txid};

    const KEY_REF: &str = "op://global_secret_store/IronDivi Swap POC - taker-btc/password";
    const HTLC_SATS: u64 = 20_000;
    const REFUND_AHEAD_OF_MTP: u32 = 2 * 3600;

    async fn wait_confirmed(b: &BtcBackend, txid: &Txid, what: &str) {
        for _ in 0..240 {
            if matches!(b.confirmations(txid).await, Ok(Some(c)) if c >= 1) {
                println!("{what} confirmed: {}", txid.to_rpc_hex());
                return;
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        panic!("{what} {} not confirmed after 2h", txid.to_rpc_hex());
    }

    async fn broadcast(b: &BtcBackend, tx: &SignedTx, what: &str) {
        let id = b.broadcast(tx).await.unwrap();
        assert_eq!(id, tx.txid);
        println!("{what} broadcast: {}", id.to_rpc_hex());
    }

    /// Fund two HTLCs on signet (or `SWAP_BTC_NETWORK`) with the taker-btc key, claim one, refund the other once
    /// MTP passes a locktime 2 h ahead of the MTP at start. Takes about 3 h.
    #[tokio::test]
    #[ignore = "needs a funded taker-btc address (signet, or SWAP_BTC_NETWORK) and ~3 h"]
    async fn live_fund_claim_refund() {
        let hex = SecretRef::parse(KEY_REF).unwrap().resolve().unwrap();
        let key =
            bitcoin::secp256k1::SecretKey::from_slice(&hex::decode(hex.trim()).unwrap()).unwrap();
        // SWAP_BTC_NETWORK=testnet runs it on testnet3 (DECISIONS #8).
        let net = std::env::var("SWAP_BTC_NETWORK").unwrap_or_else(|_| "signet".into());
        let b = BtcBackend::for_network(&net, key, FeePolicy::Recommended { floor: 2 }).unwrap();
        println!("address {} on {net}", b.address());

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
fn mainnet_endpoints_are_non_empty_with_mempool_first() {
    let eps = crate::esplora_endpoints("mainnet").unwrap();
    assert_eq!(
        eps,
        vec![
            "https://mempool.space/api".to_string(),
            "https://blockstream.info/api".to_string()
        ]
    );
}

#[test]
fn test_network_endpoints_are_unchanged() {
    assert_eq!(
        crate::esplora_endpoints("signet").unwrap(),
        vec![
            "https://mempool.space/signet/api".to_string(),
            "https://blockstream.info/signet/api".to_string()
        ]
    );
    assert_eq!(
        crate::esplora_endpoints("testnet").unwrap(),
        vec![
            "https://mempool.space/testnet/api".to_string(),
            "https://blockstream.info/testnet/api".to_string()
        ]
    );
}

#[test]
fn unknown_btc_network_is_rejected() {
    let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    assert!(crate::esplora_endpoints("regtest").is_err());
    assert!(BtcBackend::for_network("regtest", key, FeePolicy::Fixed(2)).is_err());
}

#[test]
fn mainnet_address_is_bc1q_and_test_networks_stay_tb1q() {
    let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let main = BtcBackend::for_network("mainnet", key, FeePolicy::Fixed(2)).unwrap();
    assert!(
        main.address().to_string().starts_with("bc1q"),
        "{}",
        main.address()
    );
    let sig = BtcBackend::for_network("signet", key, FeePolicy::Fixed(2)).unwrap();
    let tst = BtcBackend::for_network("testnet", key, FeePolicy::Fixed(2)).unwrap();
    assert!(sig.address().to_string().starts_with("tb1q"));
    // Same key, same witness program: signet and testnet3 give the identical string, as before.
    assert_eq!(sig.address().to_string(), tst.address().to_string());
    // `new` keeps its signet behaviour.
    assert_eq!(
        backend(vec!["http://127.0.0.1:1".into()], [7u8; 32])
            .address()
            .to_string(),
        sig.address().to_string()
    );
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

/// Read-only smoke against the live BTC APIs: prints `SMOKE <chain> <net> <height_before>
/// <tip_hash> <height_after>` for comparison with an independent explorer. Broadcasts nothing.
#[tokio::test]
#[ignore = "hits live BTC APIs (read-only GETs)"]
async fn tip_hash_live_smoke() {
    for net in ["testnet", "mainnet"] {
        let b = BtcBackend::for_network(
            net,
            SecretKey::from_slice(&MAKER_KEY).unwrap(),
            FeePolicy::Fixed(1),
        )
        .unwrap();
        let before = b.tip_height().await.unwrap();
        let hash = b.tip_hash().await.unwrap();
        let after = b.tip_height().await.unwrap();
        assert_eq!(hash.len(), 64, "{hash}");
        println!("SMOKE BTC {net} {before} {hash} {after}");
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
    assert_eq!(v1.redeem_script().len(), 118);
}

// ---- input reservations (a dropped lock's inputs are not handed to the next swap) ----

fn reservation_db(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "swap-chain-btc-{tag}-{}-{nanos}.db",
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
async fn two_coin_wallet(key: [u8; 32]) -> (MockServer, BtcBackend, [u8; 32], [u8; 32]) {
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
    assert!(res.reserved(Chain::Btc).unwrap().is_empty());
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
    let held = res.reserved(Chain::Btc).unwrap();
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

// ---- quorum reads (single-source-design.md section 5, BTC row) ----

fn quorum(primary: &MockServer, secondary: &MockServer) -> BtcBackend {
    backend(vec![primary.uri(), secondary.uri()], MAKER_KEY)
        .with_quorum_reads(true)
        .unwrap()
}

fn transient<T: std::fmt::Debug>(r: Result<T>) -> String {
    match r {
        Err(SwapError::Transient(m)) => m,
        other => panic!("expected Transient, got {other:?}"),
    }
}

async fn mock_json(server: &MockServer, p: String, body: Value) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn mock_tip(server: &MockServer, height: u64) {
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string(height.to_string()))
        .mount(server)
        .await;
}

async fn mock_unspent(server: &MockServer, fund: &Outpoint) {
    mock_json(
        server,
        format!("/tx/{}/outspend/{}", fund.txid, fund.vout),
        json!({"spent": false}),
    )
    .await;
}

/// `spender` spends `fund` (input 0) with a claim witness, confirmed at `height` if any.
async fn mock_spend(server: &MockServer, fund: &Outpoint, spender: &str, height: Option<u64>) {
    let status = match height {
        Some(h) => json!({"confirmed": true, "block_height": h}),
        None => json!({"confirmed": false}),
    };
    mock_json(
        server,
        format!("/tx/{}/outspend/{}", fund.txid, fund.vout),
        json!({"spent": true, "txid": spender, "vin": 0, "status": status}),
    )
    .await;
    mock_json(
        server,
        format!("/tx/{spender}"),
        json!({
            "txid": spender,
            "vin": [{"txid": fund.txid.to_rpc_hex(), "vout": fund.vout, "scriptsig": "",
                     "witness": [hex::encode([0x30u8; 71]), "11".repeat(32), "01"]}]
        }),
    )
    .await;
}

/// `fund.txid` pays `value` to `spk` at `fund.vout`, confirmed at `height`.
async fn mock_lock(server: &MockServer, fund: &Outpoint, spk: &str, value: u64, height: u64) {
    let status = json!({"confirmed": true, "block_height": height});
    mock_json(
        server,
        format!("/tx/{}", fund.txid),
        json!({
            "txid": fund.txid.to_rpc_hex(),
            "vout": [{"scriptpubkey": "00", "value": 5}, {"scriptpubkey": spk, "value": value}],
            "status": status
        }),
    )
    .await;
    mock_json(server, format!("/tx/{}/status", fund.txid), status).await;
}

#[tokio::test]
async fn quorum_find_spend_a_claim_the_primary_hides_is_held() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let fund = outpoint();
    mock_unspent(&primary, &fund).await;
    mock_spend(&secondary, &fund, &"ab".repeat(32), Some(777)).await;
    let m = held(quorum(&primary, &secondary).find_spend(&fund, 700).await);
    assert!(m.contains("unspent") && m.contains(&"ab".repeat(32)), "{m}");
}

#[tokio::test]
async fn quorum_find_spend_a_spend_only_the_primary_reports_is_held() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let fund = outpoint();
    mock_spend(&primary, &fund, &"ab".repeat(32), Some(777)).await;
    mock_unspent(&secondary, &fund).await;
    held(quorum(&primary, &secondary).find_spend(&fund, 700).await);
}

#[tokio::test]
async fn quorum_find_spend_two_different_spenders_is_held() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let fund = outpoint();
    mock_spend(&primary, &fund, &"ab".repeat(32), Some(777)).await;
    mock_spend(&secondary, &fund, &"cd".repeat(32), Some(777)).await;
    let m = held(quorum(&primary, &secondary).find_spend(&fund, 700).await);
    assert!(
        m.contains(&"ab".repeat(32)) && m.contains(&"cd".repeat(32)),
        "{m}"
    );
}

#[tokio::test]
async fn quorum_htlc_output_the_secondary_does_not_have_is_held() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let fund = outpoint();
    let spk = hex::encode(htlc_script_pubkey(&h).as_bytes());
    for s in [&primary, &secondary] {
        mock_tip(s, 110).await;
    }
    mock_lock(&primary, &fund, &spk, 20_000, 109).await;
    // The secondary does not know the transaction (wiremock 404).
    held(quorum(&primary, &secondary).htlc_output(&h, &fund).await);
}

#[tokio::test]
async fn quorum_htlc_output_with_another_value_is_held() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let fund = outpoint();
    let spk = hex::encode(htlc_script_pubkey(&h).as_bytes());
    for s in [&primary, &secondary] {
        mock_tip(s, 110).await;
    }
    mock_lock(&primary, &fund, &spk, 20_000, 109).await;
    mock_lock(&secondary, &fund, &spk, 2_000, 109).await;
    let m = held(quorum(&primary, &secondary).htlc_output(&h, &fund).await);
    assert!(m.contains("20000") && m.contains("2000"), "{m}");
}

#[tokio::test]
async fn quorum_htlc_output_with_another_script_is_held() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let (_, hash) = new_preimage();
    let (_, other) = new_preimage();
    let h = htlc(hash);
    let fund = outpoint();
    for s in [&primary, &secondary] {
        mock_tip(s, 110).await;
    }
    let spk = hex::encode(htlc_script_pubkey(&h).as_bytes());
    let other_spk = hex::encode(htlc_script_pubkey(&htlc(other)).as_bytes());
    mock_lock(&primary, &fund, &spk, 20_000, 109).await;
    mock_lock(&secondary, &fund, &other_spk, 20_000, 109).await;
    held(quorum(&primary, &secondary).htlc_output(&h, &fund).await);
}

#[tokio::test]
async fn quorum_confirmations_the_secondary_does_not_know_is_held() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let fund = outpoint();
    for s in [&primary, &secondary] {
        mock_tip(s, 110).await;
    }
    mock_json(
        &primary,
        format!("/tx/{}/status", fund.txid),
        json!({"confirmed": true, "block_height": 109}),
    )
    .await;
    held(quorum(&primary, &secondary).confirmations(&fund.txid).await);
}

/// Agreement: the lower confirmation count wins (a block apart is lag, not a lie), and a
/// spend one endpoint still has in the mempool is reported with the other's block height.
#[tokio::test]
async fn quorum_agreeing_reads_take_the_lower_count() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let fund = outpoint();
    let spk = hex::encode(htlc_script_pubkey(&h).as_bytes());
    mock_tip(&primary, 111).await;
    mock_tip(&secondary, 110).await;
    for s in [&primary, &secondary] {
        mock_lock(s, &fund, &spk, 20_000, 109).await;
    }
    let b = quorum(&primary, &secondary);
    assert_eq!(b.confirmations(&fund.txid).await.unwrap(), Some(2));
    let locked = b.htlc_output(&h, &fund).await.unwrap().unwrap();
    assert_eq!(
        (locked.amount, locked.confirmations),
        (Amount::from_sat(20_000), 2)
    );
    let unknown = Txid([5; 32]);
    assert_eq!(b.confirmations(&unknown).await.unwrap(), None);

    let spent = Outpoint {
        txid: Txid([7; 32]),
        vout: 0,
    };
    mock_spend(&primary, &spent, &"ab".repeat(32), None).await;
    mock_spend(&secondary, &spent, &"ab".repeat(32), Some(109)).await;
    let spend = b.find_spend(&spent, 100).await.unwrap().expect("spent");
    assert_eq!(spend.txid, Txid::from_rpc_hex(&"ab".repeat(32)).unwrap());
    assert_eq!(spend.height, Some(109));
    let unspent = Outpoint {
        txid: Txid([8; 32]),
        vout: 0,
    };
    for s in [&primary, &secondary] {
        mock_unspent(s, &unspent).await;
    }
    assert!(b.find_spend(&unspent, 100).await.unwrap().is_none());
}

/// Quorum mode fails closed: a secondary that cannot be reached holds every quorum read
/// (`Held`), however healthy the primary's answer looks.
#[tokio::test]
async fn quorum_unreachable_secondary_is_held() {
    let primary = MockServer::start().await;
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let fund = outpoint();
    let spk = hex::encode(htlc_script_pubkey(&h).as_bytes());
    mock_tip(&primary, 110).await;
    mock_lock(&primary, &fund, &spk, 20_000, 109).await;
    mock_unspent(&primary, &fund).await;
    let b = backend(vec![primary.uri(), dead_url()], MAKER_KEY)
        .with_quorum_reads(true)
        .unwrap();
    held(b.confirmations(&fund.txid).await);
    held(b.htlc_output(&h, &fund).await);
    held(b.find_spend(&fund, 100).await);
}

/// Off (the default): the three reads go to the primary alone, exactly as before; the
/// secondary is not asked anything while the primary answers.
#[tokio::test]
async fn quorum_off_never_asks_the_secondary() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let (_, hash) = new_preimage();
    let h = htlc(hash);
    let fund = outpoint();
    let spk = hex::encode(htlc_script_pubkey(&h).as_bytes());
    mock_tip(&primary, 110).await;
    mock_lock(&primary, &fund, &spk, 20_000, 109).await;
    mock_spend(&primary, &fund, &"ab".repeat(32), Some(110)).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .expect(0)
        .mount(&secondary)
        .await;
    for on in [None, Some(false)] {
        let b = backend(vec![primary.uri(), secondary.uri()], MAKER_KEY);
        let b = match on {
            Some(on) => b.with_quorum_reads(on).unwrap(),
            None => b,
        };
        assert_eq!(b.confirmations(&fund.txid).await.unwrap(), Some(2));
        assert!(b.htlc_output(&h, &fund).await.unwrap().is_some());
        assert!(b.find_spend(&fund, 100).await.unwrap().is_some());
    }
    // The primary saw each read's requests once per pass: status + tip, tx + tip,
    // outspend + spender.
    assert_eq!(primary.received_requests().await.unwrap().len(), 12);
    assert!(secondary.received_requests().await.unwrap().is_empty());
}

#[test]
fn quorum_reads_need_two_endpoints() {
    let one = backend(vec![dead_url()], MAKER_KEY);
    assert!(matches!(
        one.with_quorum_reads(true),
        Err(SwapError::InvalidParams(_))
    ));
    let one = backend(vec![dead_url()], MAKER_KEY);
    assert!(one.with_quorum_reads(false).is_ok());
}

// ---- quorum tip reads (EI): tip, header, median time and block status ----

const TIP_C: &str = "00000000000000000001cccccccccccccccccccccccccccccccccccccccccccc";

/// `server`'s tip is block `hash` at `height`, with time `1_790_000_000 + height` and median
/// time `mtp`; `prev` is its parent, served at `/block-height/{height - 1}`.
async fn mock_chain_tip(server: &MockServer, height: u64, hash: &str, prev: &str, mtp: u64) {
    mock_tip(server, height).await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/hash"))
        .respond_with(ResponseTemplate::new(200).set_body_string(hash))
        .mount(server)
        .await;
    mock_json(
        server,
        format!("/block/{hash}"),
        json!({"id": hash, "height": height, "timestamp": 1_790_000_000 + height,
               "mediantime": mtp, "previousblockhash": prev}),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/block-height/{height}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(hash))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/block-height/{}", height - 1)))
        .respond_with(ResponseTemplate::new(200).set_body_string(prev))
        .mount(server)
        .await;
}

async fn mock_best(server: &MockServer, hash: &str, height: u64, best: bool) {
    mock_json(
        server,
        format!("/block/{hash}/status"),
        json!({"in_best_chain": best, "height": height}),
    )
    .await;
}

/// Agreement, a block apart: the lower tip, its hash and header, and the lower median time.
/// The endpoint a block ahead names the lower tip as its block at that height.
#[tokio::test]
async fn quorum_tip_reads_agree_on_the_lower_tip() {
    for primary_ahead in [true, false] {
        let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
        let (ahead, behind) = match primary_ahead {
            true => (&primary, &secondary),
            false => (&secondary, &primary),
        };
        mock_chain_tip(ahead, 101, TIP_B, TIP_A, 1_789_998_600).await;
        mock_chain_tip(behind, 100, TIP_A, TIP_C, 1_789_998_000).await;
        let b = quorum(&primary, &secondary);
        assert_eq!(b.tip_height().await.unwrap(), 100, "ahead={primary_ahead}");
        assert_eq!(b.tip_hash().await.unwrap(), TIP_A);
        assert_eq!(
            b.tip_header().await.unwrap(),
            divi_swap::backend::TipHeader {
                height: 100,
                hash: TIP_A.into(),
                time: 1_790_000_100,
            }
        );
        assert_eq!(b.median_time_past().await.unwrap(), 1_789_998_000);
    }
    // Same height, same block.
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    for s in [&primary, &secondary] {
        mock_chain_tip(s, 100, TIP_A, TIP_C, 1_789_998_000).await;
    }
    let b = quorum(&primary, &secondary);
    assert_eq!(b.tip_hash().await.unwrap(), TIP_A);
    assert_eq!(b.tip_header().await.unwrap().height, 100);
}

/// Two different blocks at one height are a disagreement: at the shared tip height, and at
/// the lower tip's height when one endpoint is a block ahead on another branch.
#[tokio::test]
async fn quorum_tip_hash_two_blocks_at_one_height_is_held() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_chain_tip(&primary, 100, TIP_A, TIP_C, 1_789_998_000).await;
    mock_chain_tip(&secondary, 100, TIP_B, TIP_C, 1_789_998_000).await;
    let b = quorum(&primary, &secondary);
    let m = held(b.tip_hash().await);
    assert!(m.contains(TIP_A) && m.contains(TIP_B), "{m}");
    held(b.tip_header().await);

    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    // The primary is a block ahead, but its block 100 is TIP_C, not the secondary's TIP_A.
    mock_chain_tip(&primary, 101, TIP_B, TIP_C, 1_789_998_600).await;
    mock_chain_tip(&secondary, 100, TIP_A, TIP_C, 1_789_998_000).await;
    let b = quorum(&primary, &secondary);
    let m = held(b.tip_hash().await);
    assert!(m.contains(TIP_A) && m.contains(TIP_C), "{m}");
    held(b.tip_header().await);
}

#[tokio::test]
async fn quorum_in_best_chain_needs_both_endpoints() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    for s in [&primary, &secondary] {
        mock_best(s, TIP_A, 100, true).await;
        mock_best(s, TIP_C, 100, false).await;
    }
    mock_best(&primary, TIP_B, 101, true).await;
    mock_best(&secondary, TIP_B, 101, false).await;
    let b = quorum(&primary, &secondary);
    assert!(b.in_best_chain(100, TIP_A).await.unwrap());
    assert!(
        !b.in_best_chain(100, TIP_C).await.unwrap(),
        "orphaned on both"
    );
    let m = held(b.in_best_chain(101, TIP_B).await);
    assert!(m.contains(TIP_B), "{m}");
}

/// Fail closed on the tip reads too: with either endpoint unreachable, all five fail, however
/// healthy the other's answer looks (`Held` with the secondary down, `Transient` with the
/// primary down).
#[tokio::test]
async fn quorum_tip_reads_with_one_endpoint_down_are_held() {
    let up = MockServer::start().await;
    mock_chain_tip(&up, 100, TIP_A, TIP_C, 1_789_998_000).await;
    mock_best(&up, TIP_A, 100, true).await;
    for urls in [vec![up.uri(), dead_url()], vec![dead_url(), up.uri()]] {
        let down = urls[0] == dead_url();
        let b = backend(urls, MAKER_KEY).with_quorum_reads(true).unwrap();
        one_down(down, b.tip_height().await);
        one_down(down, b.tip_hash().await);
        one_down(down, b.tip_header().await);
        one_down(down, b.median_time_past().await);
        one_down(down, b.in_best_chain(100, TIP_A).await);
    }
}

/// Off (the default): the five tip reads go to the primary alone, with today's requests
/// (height 1, hash 1, header 2, median time 2, block status 1); the secondary is not asked.
#[tokio::test]
async fn quorum_off_tip_reads_are_unchanged() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_chain_tip(&primary, 101, TIP_B, TIP_A, 1_789_998_600).await;
    mock_best(&primary, TIP_B, 101, true).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .expect(0)
        .mount(&secondary)
        .await;
    for on in [None, Some(false)] {
        let b = backend(vec![primary.uri(), secondary.uri()], MAKER_KEY);
        let b = match on {
            Some(on) => b.with_quorum_reads(on).unwrap(),
            None => b,
        };
        assert_eq!(b.tip_height().await.unwrap(), 101);
        assert_eq!(b.tip_hash().await.unwrap(), TIP_B);
        assert_eq!(b.tip_header().await.unwrap().height, 101);
        assert_eq!(b.median_time_past().await.unwrap(), 1_789_998_600);
        assert!(b.in_best_chain(101, TIP_B).await.unwrap());
    }
    let paths: Vec<String> = primary
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    let block = format!("/block/{TIP_B}");
    let status = format!("/block/{TIP_B}/status");
    let once = [
        "/blocks/tip/height",
        "/blocks/tip/hash",
        "/blocks/tip/hash",
        &block,
        "/blocks/tip/hash",
        &block,
        &status,
    ];
    let want: Vec<String> = once
        .iter()
        .chain(once.iter())
        .map(|s| s.to_string())
        .collect();
    assert_eq!(paths, want);
    assert!(secondary.received_requests().await.unwrap().is_empty());
}

// ---- quorum broadcast and funding reads (EO): both endpoints get every POST, funding uses
// only coins both endpoints list. Esplora `POST /tx` answers the txid on success
// (single-source-design.FACTS.md, Esplora `POST /tx`).

fn quorum_as(primary: &MockServer, secondary: &MockServer, key: [u8; 32]) -> BtcBackend {
    backend(vec![primary.uri(), secondary.uri()], key)
        .with_quorum_reads(true)
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
async fn quorum_broadcast_claim_dropped_by_the_primary_reaches_the_secondary() {
    let claim = a_claim().await;
    for primary_says in [refuses("min relay fee not met"), accepts(&claim)] {
        let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
        mock_post(&primary, primary_says).await;
        mock_post(&secondary, accepts(&claim)).await;
        let b = quorum_as(&primary, &secondary, TAKER_KEY);
        assert_eq!(b.broadcast(&claim).await.unwrap(), claim.txid);
        assert_eq!(posted(&secondary).await, [hex::encode(&claim.raw)]);
        assert_eq!(posted(&primary).await, [hex::encode(&claim.raw)]);
    }
}

/// The secondary refusing, or down, while the primary accepts is still a broadcast.
#[tokio::test]
async fn quorum_broadcast_one_endpoint_accepting_is_enough() {
    let claim = a_claim().await;
    let primary = MockServer::start().await;
    mock_post(&primary, accepts(&claim)).await;
    let secondary = MockServer::start().await;
    mock_post(&secondary, refuses("mempool full")).await;
    let b = quorum_as(&primary, &secondary, TAKER_KEY);
    assert_eq!(b.broadcast(&claim).await.unwrap(), claim.txid);
    let b = backend(vec![primary.uri(), dead_url()], TAKER_KEY)
        .with_quorum_reads(true)
        .unwrap();
    assert_eq!(b.broadcast(&claim).await.unwrap(), claim.txid);
    // An already-known answer counts as accepted.
    let (p2, s2) = (MockServer::start().await, MockServer::start().await);
    mock_post(&p2, refuses("bad-txns-inputs-duplicate")).await;
    mock_post(
        &s2,
        ResponseTemplate::new(400).set_body_string(
            "sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction already in block chain\"}",
        ),
    )
    .await;
    assert_eq!(
        quorum_as(&p2, &s2, TAKER_KEY)
            .broadcast(&claim)
            .await
            .unwrap(),
        claim.txid
    );
}

/// Both accepting: one txid, one POST each.
#[tokio::test]
async fn quorum_broadcast_both_accept_once_each() {
    let claim = a_claim().await;
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_post(&primary, accepts(&claim)).await;
    mock_post(&secondary, accepts(&claim)).await;
    let b = quorum_as(&primary, &secondary, TAKER_KEY);
    assert_eq!(b.broadcast(&claim).await.unwrap(), claim.txid);
    assert_eq!(posted(&primary).await.len(), 1);
    assert_eq!(posted(&secondary).await.len(), 1);
}

/// An endpoint that answers 200 with another txid has not taken our transaction: with nothing
/// else accepting it, the broadcast fails naming that endpoint and both txids.
#[tokio::test]
async fn quorum_broadcast_another_txid_is_an_error_naming_the_endpoint() {
    let claim = a_claim().await;
    let other = "ab".repeat(32);
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_post(&primary, ResponseTemplate::new(200).set_body_string(&other)).await;
    mock_post(&secondary, refuses("mempool full")).await;
    let b = quorum_as(&primary, &secondary, TAKER_KEY);
    let e = b.broadcast(&claim).await.unwrap_err().to_string();
    assert!(
        e.contains(&primary.uri()) && e.contains(&other) && e.contains(&claim.txid.to_rpc_hex()),
        "{e}"
    );
}

/// Both refusing is today's error: a refund before its locktime is still `Premature`, also
/// when the other endpoint cannot be reached.
#[tokio::test]
async fn quorum_broadcast_both_refusing_is_todays_error() {
    let claim = a_claim().await;
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_post(&primary, refuses("non-final")).await;
    mock_post(&secondary, refuses("non-final")).await;
    let r = quorum_as(&primary, &secondary, TAKER_KEY)
        .broadcast(&claim)
        .await;
    assert!(matches!(r, Err(SwapError::Premature(_))), "{r:?}");
    for urls in [
        vec![dead_url(), secondary.uri()],
        vec![primary.uri(), dead_url()],
    ] {
        let b = backend(urls, TAKER_KEY).with_quorum_reads(true).unwrap();
        let r = b.broadcast(&claim).await;
        assert!(matches!(r, Err(SwapError::Premature(_))), "{r:?}");
    }
}

/// Off (the default): one POST to the primary, its body ignored, nothing to the secondary.
#[tokio::test]
async fn quorum_off_broadcast_and_funding_are_unchanged() {
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
    let t = |n: u8| hex::encode([n; 32]);
    for on in [None, Some(false)] {
        let b = backend(vec![primary.uri(), secondary.uri()], TAKER_KEY);
        let b = match on {
            Some(on) => b.with_quorum_reads(on).unwrap(),
            None => b,
        };
        mock_json(
            &primary,
            format!("/address/{}/utxo", b.address()),
            json!([{"txid": t(1), "vout": 0, "value": 900_000, "status": {"confirmed": true}}]),
        )
        .await;
        assert_eq!(b.broadcast(&claim).await.unwrap(), claim.txid);
        let (_, hash) = new_preimage();
        b.build_funding(&htlc(hash), Amount::from_sat(20_000))
            .await
            .unwrap();
    }
    let paths: Vec<String> = primary
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect();
    let utxo = format!(
        "GET /address/{}/utxo",
        backend(vec![dead_url()], TAKER_KEY).address()
    );
    assert_eq!(
        paths,
        ["POST /tx", utxo.as_str(), "POST /tx", utxo.as_str()]
    );
    assert!(secondary.received_requests().await.unwrap().is_empty());
}

/// The wallet as each endpoint lists it: `(txid byte, value, confirmed)`.
async fn mock_wallet(server: &MockServer, b: &BtcBackend, coins: &[(u8, u64, bool)]) {
    let list: Vec<Value> = coins
        .iter()
        .map(|(t, v, c)| {
            json!({"txid": hex::encode([*t; 32]), "vout": 0, "value": v, "status": {"confirmed": c}})
        })
        .collect();
    mock_json(
        server,
        format!("/address/{}/utxo", b.address()),
        json!(list),
    )
    .await;
}

/// A primary that lists a coin the secondary does not (spent, or never there), or at another
/// value, cannot get it into a funding transaction or the spendable balance.
#[tokio::test]
async fn quorum_funding_uses_only_coins_both_endpoints_list() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let b = quorum_as(&primary, &secondary, MAKER_KEY);
    // 1: phantom on the primary; 2: on both; 3: another value on the primary.
    mock_wallet(
        &primary,
        &b,
        &[(1, 900_000, true), (2, 30_000, true), (3, 500_000, true)],
    )
    .await;
    mock_wallet(&secondary, &b, &[(2, 30_000, true), (3, 5_000, true)]).await;
    let (_, hash) = new_preimage();
    let f = b
        .build_funding(&htlc(hash), Amount::from_sat(20_000))
        .await
        .unwrap();
    assert_eq!(spent_txids(&f), [[2u8; 32]]);
    assert_eq!(b.spendable().await.unwrap(), Some(Amount::from_sat(30_000)));
    let err = b
        .build_funding(&htlc(hash), Amount::from_sat(100_000))
        .await
        .unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
}

/// A coin is confirmed only if both endpoints say so (selection prefers confirmed coins).
#[tokio::test]
async fn quorum_funding_a_coin_is_confirmed_only_on_both_words() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let b = quorum_as(&primary, &secondary, MAKER_KEY);
    mock_wallet(&primary, &b, &[(1, 900_000, true), (2, 30_000, true)]).await;
    mock_wallet(&secondary, &b, &[(1, 900_000, false), (2, 30_000, true)]).await;
    let (_, hash) = new_preimage();
    let f = b
        .build_funding(&htlc(hash), Amount::from_sat(20_000))
        .await
        .unwrap();
    assert_eq!(spent_txids(&f), [[2u8; 32]]);
}

/// The UTXO list failing on either endpoint fails funding, as every quorum read (`Held` with
/// the secondary down, `Transient` with the primary down).
#[tokio::test]
async fn quorum_funding_with_one_endpoint_down_fails_closed() {
    let primary = MockServer::start().await;
    let probe = backend(vec![dead_url()], MAKER_KEY);
    mock_wallet(&primary, &probe, &[(1, 900_000, true)]).await;
    for urls in [
        vec![primary.uri(), dead_url()],
        vec![dead_url(), primary.uri()],
    ] {
        let down = urls[0] == dead_url();
        let b = backend(urls, MAKER_KEY).with_quorum_reads(true).unwrap();
        let (_, hash) = new_preimage();
        one_down(
            down,
            b.build_funding(&htlc(hash), Amount::from_sat(20_000)).await,
        );
        one_down(down, b.spendable().await);
    }
}

async fn mock_fees(server: &MockServer, half_hour: u64) {
    mock_json(
        server,
        "/v1/fees/recommended".into(),
        json!({"fastestFee": half_hour + 1, "halfHourFee": half_hour, "hourFee": 1}),
    )
    .await;
}

fn recommended(urls: Vec<String>, quorum: bool) -> BtcBackend {
    BtcBackend::new(
        urls,
        SecretKey::from_slice(&MAKER_KEY).unwrap(),
        FeePolicy::Recommended { floor: 2 },
        fast(),
    )
    .unwrap()
    .with_quorum_reads(quorum)
    .unwrap()
}

/// A primary that quotes a low fee cannot leave a lock, claim or refund stuck: the higher of
/// the two endpoints' rates is used. One endpoint down falls back to the other's rate (a fee
/// read never stalls a claim); both down is the floor, as today.
#[tokio::test]
async fn quorum_fee_rate_is_the_higher_of_the_two() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    mock_fees(&primary, 3).await;
    mock_fees(&secondary, 40).await;
    let b = recommended(vec![primary.uri(), secondary.uri()], true);
    assert_eq!(b.claim_feerate().await.unwrap(), Some(40));
    let b = recommended(vec![secondary.uri(), primary.uri()], true);
    assert_eq!(b.claim_feerate().await.unwrap(), Some(40));
    let b = recommended(vec![dead_url(), primary.uri()], true);
    assert_eq!(b.claim_feerate().await.unwrap(), Some(3));
    let b = recommended(vec![dead_url(), "http://127.0.0.1:2".into()], true);
    assert_eq!(b.claim_feerate().await.unwrap(), Some(2));
    // Off: the primary's rate, as today.
    let b = recommended(vec![primary.uri(), secondary.uri()], false);
    assert_eq!(b.claim_feerate().await.unwrap(), Some(3));
}

// ---- bounded read hold (EV): `Held` and the primary-only view ----

/// The secondary down holds a quorum read (`Held`); the primary down is `Transient`.
fn one_down<T: std::fmt::Debug>(primary_down: bool, r: Result<T>) -> String {
    if primary_down {
        transient(r)
    } else {
        held(r)
    }
}

fn held<T: std::fmt::Debug>(r: Result<T>) -> String {
    match r {
        Err(SwapError::Held(m)) => m,
        other => panic!("expected Held, got {other:?}"),
    }
}

/// With quorum reads, a secondary that disagrees or cannot be reached holds the read for the
/// engine's deadline (`SwapError::Held`); a primary that cannot be reached stays `Transient`
/// (nothing the primary alone could answer).
#[tokio::test]
async fn quorum_a_disagreeing_or_unreachable_secondary_holds_the_read() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let fund = outpoint();
    mock_unspent(&primary, &fund).await;
    mock_spend(&secondary, &fund, &"ab".repeat(32), Some(777)).await;
    let m = held(quorum(&primary, &secondary).find_spend(&fund, 700).await);
    assert!(m.contains("unspent") && m.contains(&"ab".repeat(32)), "{m}");

    let up = MockServer::start().await;
    mock_chain_tip(&up, 110, TIP_A, TIP_C, 1_789_998_000).await;
    mock_json(
        &up,
        format!("/tx/{}/status", fund.txid),
        json!({"confirmed": true, "block_height": 109}),
    )
    .await;
    mock_unspent(&up, &fund).await;
    let b = backend(vec![up.uri(), dead_url()], MAKER_KEY)
        .with_quorum_reads(true)
        .unwrap();
    held(b.confirmations(&fund.txid).await);
    held(b.find_spend(&fund, 100).await);
    held(b.tip_height().await);
    held(b.median_time_past().await);

    let b = backend(vec![dead_url(), up.uri()], MAKER_KEY)
        .with_quorum_reads(true)
        .unwrap();
    transient(b.find_spend(&fund, 100).await);
    transient(b.median_time_past().await);
}

/// The primary-only view reads the primary alone: the secondary that holds the quorum read
/// (down, or answering otherwise) is not asked.
#[tokio::test]
async fn quorum_primary_only_view_reads_the_primary_alone() {
    let (primary, secondary) = (MockServer::start().await, MockServer::start().await);
    let fund = outpoint();
    mock_chain_tip(&primary, 110, TIP_A, TIP_C, 1_789_998_000).await;
    mock_json(
        &primary,
        format!("/tx/{}/status", fund.txid),
        json!({"confirmed": true, "block_height": 109}),
    )
    .await;
    mock_unspent(&primary, &fund).await;
    mock_spend(&secondary, &fund, &"ab".repeat(32), Some(777)).await;
    let b = quorum(&primary, &secondary);
    held(b.find_spend(&fund, 100).await);
    let asked = secondary.received_requests().await.unwrap().len();

    let view = b
        .primary_only()
        .expect("quorum reads have a primary-only view");
    assert!(view.find_spend(&fund, 100).await.unwrap().is_none());
    assert_eq!(view.confirmations(&fund.txid).await.unwrap(), Some(2));
    assert_eq!(view.tip_height().await.unwrap(), 110);
    assert_eq!(view.median_time_past().await.unwrap(), 1_789_998_000);
    assert_eq!(view.pubkey(), b.pubkey());
    assert!(
        view.primary_only().is_none(),
        "the view has no second source"
    );
    assert_eq!(
        secondary.received_requests().await.unwrap().len(),
        asked,
        "the view asked the secondary"
    );

    let b = backend(vec![primary.uri(), dead_url()], MAKER_KEY)
        .with_quorum_reads(true)
        .unwrap();
    let view = b.primary_only().unwrap();
    assert!(view.find_spend(&fund, 100).await.unwrap().is_none());
}

/// Off (the default): no view, so nothing is ever read on the primary alone by the engine.
#[test]
fn quorum_off_has_no_primary_only_view() {
    let b = backend(vec![dead_url(), dead_url()], MAKER_KEY);
    assert!(b.primary_only().is_none());
    assert!(b.with_quorum_reads(false).unwrap().primary_only().is_none());
}
