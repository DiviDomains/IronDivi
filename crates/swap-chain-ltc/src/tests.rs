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
    #[cfg(feature = "consensus")]
    assert!(verify_htlc_spend(&tx, &h, 19_999).is_err());
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
    #[cfg(feature = "consensus")]
    {
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
    // Every case starts from the same coins, and a backend never reuses a coin a
    // transaction it built spends, so each case after the first gets a fresh one.
    let fresh = || backend(vec![server.uri()], TAKER_KEY);

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
    let f = fresh()
        .build_funding(&h, Amount::from_sat(5_000))
        .await
        .unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);

    // A remainder below dust is folded into the fee instead of a change output.
    let f = fresh()
        .build_funding(&h, Amount::from_sat(14_700))
        .await
        .unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1, "no dust change");

    // More than the confirmed coins hold pulls in the unconfirmed one.
    let f = fresh()
        .build_funding(&h, Amount::from_sat(500_000))
        .await
        .unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
    assert!(tx.input.len() >= 3);

    // Insufficient funds is reported as such.
    let err = fresh()
        .build_funding(&h, Amount::from_sat(5_000_000))
        .await
        .unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
}

/// A freshly generated, never-funded address (zero UTXOs, not just too few sats) reports
/// `InsufficientFunds` instead of panicking: the live dry run (`examples/ltc_live_dry_run.rs`)
/// hit this against a real throwaway key before the fix.
/// Two swaps locking at once: the second build must not reuse the coin the first spends,
/// though Esplora still lists it (the first is built but not yet broadcast).
#[tokio::test]
async fn concurrent_builds_never_share_a_coin() {
    let server = MockServer::start().await;
    let b = backend(vec![server.uri()], TAKER_KEY);
    let addr = b.address().to_string();
    let to = backend(vec![server.uri()], MAKER_KEY).address().to_string();
    let t = |n: u8| hex::encode([n; 32]);
    let coin =
        |n: u8| json!({"txid": t(n), "vout": 0, "value": 50_000, "status": {"confirmed": true}});
    let input = |f: &Funding| {
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&f.tx.raw).unwrap();
        assert_eq!(tx.input.len(), 1);
        tx.input[0].previous_output
    };
    Mock::given(method("GET"))
        .and(path(format!("/address/{addr}/utxo")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([coin(1), coin(2)])))
        .mount(&server)
        .await;
    let (_, h1) = new_preimage();
    let (_, h2) = new_preimage();
    let (h1, h2) = (htlc(h1), htlc(h2));
    let amount = Amount::from_sat(20_000);

    // Esplora lists both coins to both builds; selection alone would pick the same one twice.
    let (f1, f2) = tokio::join!(b.build_funding(&h1, amount), b.build_funding(&h2, amount));
    let (a, c) = (input(&f1.unwrap()), input(&f2.unwrap()));
    assert_ne!(a, c, "two fundings spend the same coin");

    // Both coins are taken: a third funding, or a plain send, finds none.
    let err = b.build_funding(&h1, amount).await.unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
    let err = b.build_send(&to, 10_000).await.unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");

    // The first funding was broadcast (its coin left the list) and a new coin came in:
    // the new coin is free, the second funding's coin is still taken.
    server.reset().await;
    let listed = if a.txid.to_byte_array() == [1; 32] {
        2
    } else {
        1
    };
    Mock::given(method("GET"))
        .and(path(format!("/address/{addr}/utxo")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([coin(listed), coin(3)])))
        .mount(&server)
        .await;
    let f3 = b.build_funding(&h1, amount).await.unwrap();
    assert_eq!(input(&f3).txid.to_byte_array(), [3; 32]);
}

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
