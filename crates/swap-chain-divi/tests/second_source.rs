// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `[divi].fallback_rpc_url`: with a second endpoint, a swap-relevant read the two disagree on is
//! `Transient`, never a decision. No network: two wiremock "nodes". Each lie test also runs the
//! same lie against a single-source backend and shows it is trusted (the behavior before this
//! lane, and still the behavior with the key unset).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use divi_crypto::keys::SecretKey;
use divi_swap::htlc::HtlcParams;
use divi_swap::{Amount, ChainBackend, Outpoint, SignedTx, SwapError, Txid};
use divi_wallet::address::Network;
use parking_lot::Mutex;
use serde_json::{json, Value};
use swap_chain_divi::{htlc_script_pubkey, DiviBackend, FeePolicy, RetryPolicy};
use wiremock::{matchers::method, Mock, MockServer, Request, Respond, ResponseTemplate};

const TIP: u64 = 100;
const BASE_TIME: u64 = 1_800_000_000;
const SATS: u64 = 5_000_000_000;

/// A scripted chain: what one endpoint believes.
#[derive(Default)]
struct Chain {
    tip: u64,
    /// Added to every block time (a lying or skewed endpoint shifts MTP).
    skew: u64,
    txs: HashMap<String, Value>,
    blocks: HashMap<u64, Vec<String>>,
    mempool: Vec<String>,
    /// `sendrawtransaction` answer: `None` = accept, `Some(message)` = node error.
    send_error: Option<String>,
    sent: u32,
}

#[derive(Clone)]
struct Node(Arc<Mutex<Chain>>);

fn block_hash(h: u64) -> String {
    format!("{:064x}", h + 1)
}

impl Respond for Node {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let p = &body["params"];
        let mut c = self.0.lock();
        let ok = |v: Value| {
            ResponseTemplate::new(200).set_body_json(json!({"result": v, "error": null, "id": 1}))
        };
        let err = |code: i64, m: &str| {
            ResponseTemplate::new(500).set_body_json(
                json!({"result": null, "error": {"code": code, "message": m}, "id": 1}),
            )
        };
        match body["method"].as_str().unwrap_or("") {
            "getblockcount" => ok(json!(c.tip)),
            "getblockhash" => ok(json!(block_hash(p[0].as_u64().unwrap()))),
            "getblock" => {
                let h = u64::from_str_radix(p[0].as_str().unwrap(), 16).unwrap() - 1;
                let mut b = json!({
                    "time": BASE_TIME + h * 60 + c.skew,
                    "tx": c.blocks.get(&h).cloned().unwrap_or_default(),
                });
                if h > 0 {
                    b["previousblockhash"] = json!(block_hash(h - 1));
                }
                ok(b)
            }
            "getrawtransaction" => match c.txs.get(p[0].as_str().unwrap()) {
                Some(t) => ok(t.clone()),
                None => err(-5, "No such mempool or blockchain transaction"),
            },
            "getrawmempool" => ok(json!(c.mempool)),
            "sendrawtransaction" => {
                c.sent += 1;
                match &c.send_error {
                    None => ok(json!("00")),
                    Some(m) => err(-26, m),
                }
            }
            _ => err(-32601, "Method not found"),
        }
    }
}

async fn node() -> (MockServer, Arc<Mutex<Chain>>) {
    let server = MockServer::start().await;
    let chain = Arc::new(Mutex::new(Chain {
        tip: TIP,
        ..Chain::default()
    }));
    Mock::given(method("POST"))
        .respond_with(Node(chain.clone()))
        .mount(&server)
        .await;
    (server, chain)
}

fn key() -> SecretKey {
    SecretKey::from_hex(&"11".repeat(32)).unwrap()
}

fn retry() -> RetryPolicy {
    RetryPolicy {
        attempts: 1,
        base_delay: Duration::from_millis(1),
    }
}

fn single(url: &str) -> DiviBackend {
    DiviBackend::with_retry(
        url,
        key(),
        Network::Testnet,
        FeePolicy::default(),
        None,
        retry(),
    )
    .unwrap()
}

fn dual(primary: &str, fallback: &str) -> DiviBackend {
    single(primary).with_fallback_rpc(fallback)
}

fn htlc(b: &DiviBackend) -> HtlcParams {
    HtlcParams {
        hash: [7; 32],
        claim_pubkey: b.pubkey(),
        refund_pubkey: b.pubkey(),
        locktime: 1_900_000_000,
        script_version: Default::default(),
    }
}

fn lock_outpoint() -> Outpoint {
    Outpoint {
        txid: Txid([0xaa; 32]),
        vout: 0,
    }
}

fn spend_txid() -> Txid {
    Txid([0xbb; 32])
}

/// A read held for the second source (EV: `Held`, the engine's bounded hold).
fn is_held<T: std::fmt::Debug>(r: &Result<T, SwapError>) -> bool {
    matches!(r, Err(SwapError::Held(m)) if m.contains("disagree"))
}

/// A read the primary could not answer: `Transient`, not a hold.
fn is_primary_down<T: std::fmt::Debug>(r: &Result<T, SwapError>) -> bool {
    matches!(r, Err(SwapError::Transient(m)) if m.contains("primary endpoint failed"))
}

/// Give `chain` the HTLC funding tx (`confs` confirmations, `sat` value) and, if `spent`, a
/// block-100 spend of it.
fn populate(chain: &Arc<Mutex<Chain>>, b: &DiviBackend, confs: u32, sat: u64, spent: bool) {
    let mut c = chain.lock();
    let o = lock_outpoint();
    let spk = htlc_script_pubkey(&htlc(b)).to_hex();
    c.txs.insert(
        o.txid.to_rpc_hex(),
        json!({
            "txid": o.txid.to_rpc_hex(),
            "confirmations": confs,
            "vin": [],
            "vout": [{"n": 0, "valueSat": sat, "value": sat as f64 / 1e8, "scriptPubKey": {"hex": spk}}],
        }),
    );
    if spent {
        let s = spend_txid();
        c.txs.insert(
            s.to_rpc_hex(),
            json!({
                "txid": s.to_rpc_hex(),
                "confirmations": 1,
                "vin": [{"txid": o.txid.to_rpc_hex(), "vout": 0, "scriptSig": {"hex": "aabbcc"}}],
                "vout": [],
            }),
        );
        c.blocks.insert(TIP, vec![s.to_rpc_hex()]);
    }
}

async fn pair_lie(
    lie: impl Fn(&mut Chain, &DiviBackend),
    state: (u32, u64, bool),
) -> (
    MockServer,
    MockServer,
    DiviBackend,
    DiviBackend,
    DiviBackend,
    DiviBackend,
) {
    let (hs, hc) = node().await;
    let (ls, lc) = node().await;
    let probe = single(&hs.uri());
    populate(&hc, &probe, state.0, state.1, state.2);
    populate(&lc, &probe, state.0, state.1, state.2);
    lie(&mut lc.lock(), &probe);
    let liar_alone = single(&ls.uri());
    let honest_alone = single(&hs.uri());
    let liar_primary = dual(&ls.uri(), &hs.uri());
    let liar_fallback = dual(&hs.uri(), &ls.uri());
    (
        hs,
        ls,
        liar_alone,
        honest_alone,
        liar_primary,
        liar_fallback,
    )
}

#[tokio::test]
async fn two_agreeing_endpoints_answer_exactly_like_one() {
    let (a, ac) = node().await;
    let (b, bc) = node().await;
    let probe = single(&a.uri());
    populate(&ac, &probe, 8, SATS, true);
    populate(&bc, &probe, 8, SATS, true);
    let one = single(&a.uri());
    let two = dual(&a.uri(), &b.uri());
    let h = htlc(&one);
    assert!(!one.has_fallback() && two.has_fallback());
    let o = lock_outpoint();
    assert_eq!(
        format!("{:?}", one.confirmations(&o.txid).await),
        format!("{:?}", two.confirmations(&o.txid).await)
    );
    assert_eq!(two.confirmations(&o.txid).await.unwrap(), Some(8));
    assert_eq!(
        format!("{:?}", one.htlc_output(&h, &o).await),
        format!("{:?}", two.htlc_output(&h, &o).await)
    );
    assert_eq!(
        two.htlc_output(&h, &o).await.unwrap().unwrap().amount,
        Amount(SATS)
    );
    assert_eq!(
        format!("{:?}", one.find_spend(&o, TIP - 2).await),
        format!("{:?}", two.find_spend(&o, TIP - 2).await)
    );
    assert_eq!(
        two.find_spend(&o, TIP - 2).await.unwrap().unwrap().txid,
        spend_txid()
    );
    assert_eq!(
        one.median_time_past().await.unwrap(),
        two.median_time_past().await.unwrap()
    );
    // Unknown output: both None.
    let none = Outpoint {
        txid: Txid([0xcc; 32]),
        vout: 0,
    };
    assert_eq!(two.confirmations(&none.txid).await.unwrap(), None);
    assert!(two.htlc_output(&h, &none).await.unwrap().is_none());
}

#[tokio::test]
async fn inflated_confirmations_on_one_endpoint_are_transient() {
    let (_h, _l, liar_alone, _honest_alone, liar_primary, liar_fallback) = pair_lie(
        |c, _| {
            c.txs
                .values_mut()
                .for_each(|t| t["confirmations"] = json!(100));
        },
        (1, SATS, false),
    )
    .await;
    let o = lock_outpoint();
    // The single-source backend trusts the liar.
    assert_eq!(liar_alone.confirmations(&o.txid).await.unwrap(), Some(100));
    assert!(is_held(&liar_primary.confirmations(&o.txid).await));
    assert!(is_held(&liar_fallback.confirmations(&o.txid).await));
    let h = htlc(&liar_alone);
    assert_eq!(
        liar_alone
            .htlc_output(&h, &o)
            .await
            .unwrap()
            .unwrap()
            .confirmations,
        100
    );
    assert!(is_held(&liar_primary.htlc_output(&h, &o).await));
    assert!(is_held(&liar_fallback.htlc_output(&h, &o).await));
}

#[tokio::test]
async fn one_block_of_tip_lag_is_tolerated_and_the_lower_count_wins() {
    let (a, ac) = node().await;
    let (b, bc) = node().await;
    let probe = single(&a.uri());
    populate(&ac, &probe, 6, SATS, false);
    populate(&bc, &probe, 5, SATS, false);
    for d in [dual(&a.uri(), &b.uri()), dual(&b.uri(), &a.uri())] {
        assert_eq!(
            d.confirmations(&lock_outpoint().txid).await.unwrap(),
            Some(5)
        );
        let out = d
            .htlc_output(&htlc(&d), &lock_outpoint())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out.confirmations, 5);
    }
}

#[tokio::test]
async fn a_spend_hidden_by_one_endpoint_is_held() {
    // The honest endpoint has the spend; the liar hides it (state passed has spent = true, then
    // the lie removes it).
    let (_h, _l, liar_alone, honest_alone, liar_primary, liar_fallback) = pair_lie(
        |c, _| {
            c.blocks.clear();
            c.mempool.clear();
        },
        (8, SATS, true),
    )
    .await;
    let o = lock_outpoint();
    assert!(honest_alone
        .find_spend(&o, TIP - 2)
        .await
        .unwrap()
        .is_some());
    // The single-source backend on the liar sees no spend and would act on that.
    assert!(liar_alone.find_spend(&o, TIP - 2).await.unwrap().is_none());
    assert!(is_held(&liar_primary.find_spend(&o, TIP - 2).await));
    assert!(is_held(&liar_fallback.find_spend(&o, TIP - 2).await));
}

#[tokio::test]
async fn a_spend_with_a_different_preimage_is_held() {
    let (_h, _l, _la, _ha, liar_primary, liar_fallback) = pair_lie(
        |c, _| {
            let s = spend_txid().to_rpc_hex();
            c.txs.get_mut(&s).unwrap()["vin"][0]["scriptSig"]["hex"] = json!("ddeeff");
        },
        (8, SATS, true),
    )
    .await;
    let o = lock_outpoint();
    assert!(is_held(&liar_primary.find_spend(&o, TIP - 2).await));
    assert!(is_held(&liar_fallback.find_spend(&o, TIP - 2).await));
}

#[tokio::test]
async fn a_spend_in_a_block_on_one_and_the_mempool_on_the_other_is_the_same_spend() {
    let (a, ac) = node().await;
    let (b, bc) = node().await;
    let probe = single(&a.uri());
    populate(&ac, &probe, 8, SATS, true);
    populate(&bc, &probe, 8, SATS, true);
    {
        let mut c = bc.lock();
        c.blocks.clear();
        c.mempool = vec![spend_txid().to_rpc_hex()];
    }
    for d in [dual(&a.uri(), &b.uri()), dual(&b.uri(), &a.uri())] {
        let s = d
            .find_spend(&lock_outpoint(), TIP - 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(s.txid, spend_txid());
        assert_eq!(s.height, Some(TIP));
    }
}

#[tokio::test]
async fn a_shifted_median_time_is_held() {
    let (_h, _l, liar_alone, honest_alone, liar_primary, liar_fallback) =
        pair_lie(|c, _| c.skew = 3 * 3600, (8, SATS, false)).await;
    let honest = honest_alone.median_time_past().await.unwrap();
    // Single source: the liar moves the timelock clock by three hours, unnoticed.
    assert_eq!(
        liar_alone.median_time_past().await.unwrap(),
        honest + 3 * 3600
    );
    assert!(is_held(&liar_primary.median_time_past().await));
    assert!(is_held(&liar_fallback.median_time_past().await));
}

#[tokio::test]
async fn a_small_median_time_skew_is_tolerated_and_the_lower_value_wins() {
    let (_h, _l, _la, honest_alone, liar_primary, liar_fallback) = pair_lie(
        |c, _| c.skew = swap_chain_divi::MTP_TOLERANCE_SECS as u64,
        (8, SATS, false),
    )
    .await;
    let honest = honest_alone.median_time_past().await.unwrap();
    assert_eq!(liar_primary.median_time_past().await.unwrap(), honest);
    assert_eq!(liar_fallback.median_time_past().await.unwrap(), honest);
}

#[tokio::test]
async fn a_wrong_amount_on_one_endpoint_is_held() {
    let (_h, _l, liar_alone, _ha, liar_primary, liar_fallback) = pair_lie(
        |c, probe| populate_amount(c, probe, SATS * 2),
        (8, SATS, false),
    )
    .await;
    let o = lock_outpoint();
    let h = htlc(&liar_alone);
    assert_eq!(
        liar_alone
            .htlc_output(&h, &o)
            .await
            .unwrap()
            .unwrap()
            .amount,
        Amount(SATS * 2)
    );
    assert!(is_held(&liar_primary.htlc_output(&h, &o).await));
    assert!(is_held(&liar_fallback.htlc_output(&h, &o).await));
}

fn populate_amount(c: &mut Chain, probe: &DiviBackend, sat: u64) {
    let spk = htlc_script_pubkey(&htlc(probe)).to_hex();
    let t = c.txs.get_mut(&lock_outpoint().txid.to_rpc_hex()).unwrap();
    t["vout"] =
        json!([{"n": 0, "valueSat": sat, "value": sat as f64 / 1e8, "scriptPubKey": {"hex": spk}}]);
}

#[tokio::test]
async fn an_output_one_endpoint_does_not_know_is_held() {
    let (a, ac) = node().await;
    let (b, _bc) = node().await;
    let probe = single(&a.uri());
    populate(&ac, &probe, 8, SATS, false);
    // `b` has never heard of the funding tx.
    let o = lock_outpoint();
    for d in [dual(&a.uri(), &b.uri()), dual(&b.uri(), &a.uri())] {
        assert!(is_held(&d.confirmations(&o.txid).await));
        assert!(is_held(&d.htlc_output(&htlc(&d), &o).await));
    }
}

#[tokio::test]
async fn one_endpoint_down_fails_every_read_closed() {
    let (a, ac) = node().await;
    let probe = single(&a.uri());
    populate(&ac, &probe, 8, SATS, true);
    let dead = "http://127.0.0.1:1";
    let o = lock_outpoint();
    // Single source on the live endpoint answers; paired with a dead one it must not.
    assert_eq!(
        single(&a.uri()).confirmations(&o.txid).await.unwrap(),
        Some(8)
    );
    // The fallback down holds every read (`Held`); the primary down is `Transient`.
    for (d, down) in [(dual(&a.uri(), dead), false), (dual(dead, &a.uri()), true)] {
        let closed = |r: &Result<_, SwapError>| match down {
            true => is_primary_down(r),
            false => is_held(r),
        };
        assert!(closed(&d.confirmations(&o.txid).await.map(|_| ())));
        assert!(closed(&d.htlc_output(&htlc(&d), &o).await.map(|_| ())));
        assert!(closed(&d.find_spend(&o, TIP - 2).await.map(|_| ())));
        assert!(closed(&d.median_time_past().await.map(|_| ())));
    }
}

#[tokio::test]
async fn both_endpoints_down_is_still_transient() {
    let d = dual("http://127.0.0.1:1", "http://127.0.0.1:2");
    assert!(matches!(
        d.confirmations(&lock_outpoint().txid).await,
        Err(SwapError::Transient(_))
    ));
}

#[tokio::test]
async fn broadcast_goes_to_both_endpoints() {
    let (a, ac) = node().await;
    let (b, bc) = node().await;
    let d = dual(&a.uri(), &b.uri());
    let tx = sample_tx(&d).await;
    let txid = d.broadcast(&tx).await.unwrap();
    assert_eq!(txid, tx.txid);
    assert_eq!((ac.lock().sent, bc.lock().sent), (1, 1));
}

#[tokio::test]
async fn broadcast_succeeds_if_either_endpoint_takes_it() {
    let (a, ac) = node().await;
    let (b, bc) = node().await;
    bc.lock().send_error = Some("bad-txns-inputs-spent".into());
    let tx = sample_tx(&dual(&a.uri(), &b.uri())).await;
    // The refusing endpoint hides nothing from the network: the accepting one took it.
    assert!(dual(&a.uri(), &b.uri()).broadcast(&tx).await.is_ok());
    assert!(dual(&b.uri(), &a.uri()).broadcast(&tx).await.is_ok());
    // A dead second endpoint does not stop a claim or a refund either.
    assert!(dual(&a.uri(), "http://127.0.0.1:1")
        .broadcast(&tx)
        .await
        .is_ok());
    assert!(dual("http://127.0.0.1:1", &a.uri())
        .broadcast(&tx)
        .await
        .is_ok());
    assert!(ac.lock().sent >= 4);
}

#[tokio::test]
async fn broadcast_fails_when_both_endpoints_refuse() {
    let (a, ac) = node().await;
    let (b, bc) = node().await;
    for c in [&ac, &bc] {
        c.lock().send_error = Some("bad-txns-inputs-spent".into());
    }
    let tx = sample_tx(&dual(&a.uri(), &b.uri())).await;
    assert!(matches!(
        dual(&a.uri(), &b.uri()).broadcast(&tx).await,
        Err(SwapError::Rejected(_))
    ));
}

#[tokio::test]
async fn a_blank_fallback_url_leaves_the_backend_single_source() {
    let (a, _ac) = node().await;
    assert!(!single(&a.uri()).with_fallback_rpc("  ").has_fallback());
}

/// A real (unsigned-input) transaction the backend can decode.
async fn sample_tx(b: &DiviBackend) -> SignedTx {
    use divi_primitives::amount::Amount as A;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;
    use divi_primitives::serialize::serialize;
    use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    let mut tx = Transaction::new();
    tx.vin.push(TxIn::new(
        OutPoint::new(Hash256::from_bytes([9; 32]), 0),
        Script::new(),
        0xffff_ffff,
    ));
    tx.vout.push(TxOut::new(
        A::from_sat(1_000_000),
        Script::new_p2pkh(&[1; 20]),
    ));
    let _ = b;
    SignedTx {
        txid: Txid::from_rpc_hex(&tx.txid().to_hex()).unwrap(),
        raw: serialize(&tx),
    }
}

// ---- bounded read hold (EV): `Held` and the primary-only view ----

/// A fallback that disagrees or is down holds the read for the engine's deadline
/// (`SwapError::Held`); a primary that is down stays `Transient`.
#[tokio::test]
async fn a_disagreeing_or_unreachable_fallback_holds_the_read() {
    let (_h, _l, _liar_alone, _honest_alone, _liar_primary, liar_fallback) =
        pair_lie(|c, _| c.skew = 3 * 3600, (8, SATS, false)).await;
    assert!(is_held(&liar_fallback.median_time_past().await));

    let (a, ac) = node().await;
    let probe = single(&a.uri());
    populate(&ac, &probe, 8, SATS, true);
    let dead = "http://127.0.0.1:1";
    let o = lock_outpoint();
    let d = dual(&a.uri(), dead);
    assert!(is_held(&d.confirmations(&o.txid).await));
    assert!(is_held(&d.find_spend(&o, TIP - 2).await));
    assert!(is_held(&d.median_time_past().await));
    assert!(is_held(&d.tip_height().await));
    let d = dual(dead, &a.uri());
    assert!(matches!(
        d.find_spend(&o, TIP - 2).await,
        Err(SwapError::Transient(_))
    ));
    assert!(matches!(
        d.median_time_past().await,
        Err(SwapError::Transient(_))
    ));
}

/// The primary-only view reads the primary alone, with the same key; the fallback is not
/// asked. Without a fallback there is no view.
#[tokio::test]
async fn the_primary_only_view_reads_the_primary_alone() {
    let (a, ac) = node().await;
    let (f, fc) = node().await;
    let probe = single(&a.uri());
    populate(&ac, &probe, 8, SATS, true);
    populate(&fc, &probe, 8, SATS, false);
    fc.lock().skew = 3 * 3600;
    let d = dual(&a.uri(), &f.uri());
    let o = lock_outpoint();
    assert!(is_held(&d.find_spend(&o, TIP - 2).await));
    let asked = f.received_requests().await.unwrap().len();

    let view = d
        .primary_only()
        .expect("a fallback has a primary-only view");
    assert_eq!(view.pubkey(), d.pubkey());
    assert!(view.primary_only().is_none());
    let spend = view.find_spend(&o, TIP - 2).await.unwrap().expect("spent");
    assert_eq!(spend.txid, spend_txid());
    assert_eq!(view.confirmations(&o.txid).await.unwrap(), Some(8));
    assert_eq!(
        view.median_time_past().await.unwrap(),
        probe.median_time_past().await.unwrap()
    );
    assert_eq!(view.tip_height().await.unwrap(), TIP);
    assert_eq!(f.received_requests().await.unwrap().len(), asked);

    assert!(single(&a.uri()).primary_only().is_none());
    assert!(single(&a.uri())
        .with_fallback_rpc("  ")
        .primary_only()
        .is_none());
}
