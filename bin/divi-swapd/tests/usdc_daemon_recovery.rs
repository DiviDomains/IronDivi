// SPDX-License-Identifier: AGPL-3.0-only
use divi_swap::api::{Direction, Offer};
use divi_swap::mock::MockChain;
use divi_swap::{
    Amount, Chain, ChainBackend, HtlcParams, InputReservations, Maker, Profile, Store, SwapConfig,
    SwapState, Taker, Txid,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[tokio::test]
async fn disabled_usdc_offer_recovers_local_funding_on_daemon_restart() {
    recovery(None).await;
}

#[tokio::test]
async fn changed_usdc_endpoint_permits_only_local_recovery() {
    recovery(Some("0x1")).await;
}

#[tokio::test]
async fn unavailable_usdc_endpoint_permits_only_local_recovery() {
    recovery(Some("down")).await;
}

async fn recovery(counter_reply: Option<&'static str>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("swaps.db");
    let wallet = dir.path().join("wallet.json");
    let store = Store::open(&db).unwrap();
    let node = MockServer::start().await;
    let url = node.uri();
    let seen = Arc::new(Mutex::new(HashMap::<String, u32>::new()));
    let inputs = Arc::new(Mutex::new(HashMap::<String, Value>::new()));
    let sends = Arc::new(Mutex::new(Vec::<String>::new()));
    let phase = Arc::new(AtomicUsize::new(0));
    let chain_time = Arc::new(AtomicUsize::new(1799999900));
    let secondary = MockServer::start().await;
    let secondary_url = secondary.uri();
    let reads = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    for (i, server) in [&node, &secondary].into_iter().enumerate() {
        let clock = chain_time.clone();
        let observations = reads.clone();
        let mode = phase.clone();
        let confirmations = seen.clone();
        let sent = sends.clone();
        let inputs = inputs.clone();
        let respond = move |req: &Request| {
            let body: Value = req.body_json().unwrap();
            let mined = confirmations.lock().unwrap().clone();
            let tip = if mined.len() > 1 {
                10
            } else if clock.load(Ordering::SeqCst) >= 1800000000 {
                9
            } else {
                3
            };
            let hash = |height: u32| format!("{:064x}", height + 1);
            let coinbase = |height: u32| format!("{:064x}", height + 1000);
            let result = match body["method"].as_str().unwrap() {
                "getblockcount" => json!(tip),
                "getbestblockhash" => json!(hash(tip)),
                "getblockhash" => json!(hash(body["params"][0].as_u64().unwrap() as u32)),
                "getblock" => {
                    let h = (0..=tip).find(|h| hash(*h) == body["params"][0]).unwrap();
                    let mut tx = vec![coinbase(h)];
                    tx.extend(
                        mined
                            .iter()
                            .filter(|(_, height)| **height == h)
                            .map(|(id, _)| id.clone()),
                    );
                    let block_time = if h <= 3 { 1799999900 } else { 1800000360 };
                    let mut block = json!({"height":h,"hash":hash(h),"time":block_time,"tx":tx});
                    if h > 0 {
                        block["previousblockhash"] = hash(h - 1).into();
                    }
                    block
                }
                "getrawmempool" => json!([]),
                "sendrawtransaction" => {
                    let raw = body["params"][0].as_str().unwrap();
                    let tx: divi_primitives::transaction::Transaction =
                        divi_primitives::serialize::deserialize(&hex::decode(raw).unwrap())
                            .unwrap();
                    let id = tx.txid().to_string();
                    let vin: Vec<_> = tx.vin.iter().map(|v|json!({"txid":v.prevout.txid.to_string(),"vout":v.prevout.vout,"scriptSig":{"hex":v.script_sig.to_hex()}})).collect();
                    inputs.lock().unwrap().insert(id.clone(), json!(vin));
                    sent.lock().unwrap().push(raw.to_owned());
                    json!(id)
                }
                "getrawtransaction" => {
                    let id = body["params"][0].as_str().unwrap();
                    if let Some(h) = (0..=tip).find(|h| coinbase(*h) == id) {
                        return ResponseTemplate::new(200).set_body_json(json!({"id":1,"error":null,"result":{"txid":id,"vin":[{"coinbase":"00"}],"confirmations":tip-h+1}}));
                    }
                    observations[i].fetch_add(1, Ordering::SeqCst);
                    let unknown = || {
                        ResponseTemplate::new(500).set_body_json(json!({"id":1,"result":null,"error":{"code":-5,"message":"No such transaction"}}))
                    };
                    match (mode.load(Ordering::SeqCst), i) {
                    (0,_) | (2,1) => return unknown(),
                    (1,1) => return ResponseTemplate::new(200).set_body_json(json!({"id":1,"result":null,"error":{"code":-32601,"message":"unavailable"}})),
                    _ => {}
                }
                    match mined.get(id) {
                    Some(h) => json!({"txid":id,"vin":inputs.lock().unwrap()[id],"confirmations":tip-h+1}),
                    None => return ResponseTemplate::new(500).set_body_json(json!({"id":1,"result":null,"error":{"code":-5,"message":"No such transaction"}})),
                }
                }
                _ => return ResponseTemplate::new(500),
            };
            ResponseTemplate::new(200).set_body_json(json!({"id":1,"result":result,"error":null}))
        };
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(respond)
            .mount(server)
            .await;
    }
    let divi = MockChain::new(Chain::Divi, 1800000000, 60);
    let usdc = MockChain::new(Chain::Usdc, 1800000000, 60);
    let backend = Arc::new(divi.backend(1, Amount(2000000000)));
    let counter = Arc::new(usdc.backend(2, Amount(2000000000)));
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        backend,
        counter,
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: Direction::TakerPaysBtc,
            counter_chain: Chain::Usdc,
            divi_sats_per_btc: 50000000000,
            min_btc_sats: 10000,
            max_btc_sats: 5000000,
        }],
    )
    .unwrap();
    let taker = Taker::new(
        Arc::new(divi.backend(3, Amount(2000000000))),
        Arc::new(usdc.backend(4, Amount(2000000000))),
        store.clone(),
    );
    let mut ids = Vec::new();
    for _ in 0..2 {
        let quote = maker.quote("o", 1000000).await.unwrap();
        let (_, req) = taker.prepare(&quote).await.unwrap();
        ids.push(maker.accept(req).await.unwrap().id);
    }
    let key = divi_crypto::keys::SecretKey::from_bytes(&[0x44; 32]).unwrap();
    let input = Txid([1; 32]).to_rpc_hex();
    fs::write(&wallet, json!({"utxos":[{"outpoint":{"txid":input,"vout":0},"value":600000000}],"reserved":[],"spent":[],"excluded":[],"scanned_height":1}).to_string()).unwrap();
    let res = InputReservations::open(&db).unwrap();
    let live = swap_chain_divi::DiviBackend::new(
        &url,
        key,
        divi_wallet::address::Network::Testnet,
        Default::default(),
        Some(wallet.clone()),
    )
    .unwrap()
    .with_input_reservations(res.clone());
    let mut record = store.get_maker_swap(&ids[0]).unwrap().unwrap();
    let binding = divi_swap::backend::UsdcAdmission::EvmContracts {
        chain_id: 11155111,
        token: [0x22; 20],
        htlc: [0x11; 20],
    };
    record.usdc_admission = Some(binding);
    let mut unfunded = store.get_maker_swap(&ids[1]).unwrap().unwrap();
    unfunded.usdc_admission = Some(binding);
    store.put_maker_swap(&unfunded).unwrap();
    let htlc = HtlcParams {
        hash: record.hash,
        claim_pubkey: record.taker_maker_leg_pubkey,
        refund_pubkey: live.pubkey(),
        locktime: 1800000000,
        script_version: Default::default(),
    };
    let funding = live
        .build_funding(&htlc, record.quote.divi_amount)
        .await
        .unwrap();
    live.broadcast(&funding.tx).await.unwrap();
    seen.lock().unwrap().insert(funding.tx.txid.to_rpc_hex(), 1);
    record.maker_leg_htlc = Some(htlc);
    record.maker_leg_funding = Some(funding.clone());
    record.state = SwapState::MakerLocked;
    store.put_maker_swap(&record).unwrap();
    assert_eq!(res.list_all().unwrap().len(), 1);
    drop(live);
    drop(maker);
    drop(taker);
    drop(store);
    let cfg = dir.path().join("daemon.toml");
    fs::write(dir.path().join("key"), "44".repeat(32)).unwrap();
    fs::write(
        &cfg,
        format!(
            r#"db_path = "{}"
listen = "127.0.0.1:0"
tick_secs = 1
[[offers]]
id = "o"
enabled = false
counter_chain = "usdc"
divi_sats_per_btc = 50000000000
min_btc_sats = 10000
max_btc_sats = 5000000
[divi]
key = "credential:key"
rpc_url = "{url}"
fallback_rpc_url = "{secondary_url}"
wallet_path = "{}"
[btc]
key = "credential:key"
esplora_url = "{url}"
"#,
            db.display(),
            wallet.display()
        ),
    )
    .unwrap();
    let counter_node = MockServer::start().await;
    if let Some(reply) = counter_reply {
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(move |req: &Request| {
                let msg: Value = req.body_json().unwrap();
                assert_eq!(msg["method"], "eth_chainId");
                let mut out = json!({"jsonrpc":"2.0", "id":msg["id"]});
                if reply == "down" {
                    out["error"] = json!({"code":-32000,"message":"unavailable"});
                } else {
                    out["result"] = json!(reply);
                }
                ResponseTemplate::new(200).set_body_json(out)
            })
            .mount(&counter_node)
            .await;
        use std::io::Write;
        writeln!(
            fs::OpenOptions::new().append(true).open(&cfg).unwrap(),
            r#"[usdc]
network = "sepolia"
rpc_url = "{}"
htlc = "0x1111111111111111111111111111111111111111"
key = "credential:key"
"#,
            counter_node.uri()
        )
        .unwrap();
    }
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_divi-swapd"))
        .arg("--config")
        .arg(cfg)
        .env("CREDENTIALS_DIRECTORY", dir.path())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let store = Store::open_read_only(&db).unwrap();
    // Exercise real dual-source reads before allowing the sent marker to advance.
    for stage in 0..3 {
        phase.store(stage, Ordering::SeqCst);
        let before = reads.each_ref().map(|count| count.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(30), async {
            while (0..2).any(|i| reads[i].load(Ordering::SeqCst) < before[i] + 2) {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "daemon exited at startup"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("daemon must recheck both sources");
        let pending = store.get_maker_swap(&ids[0]).unwrap().unwrap();
        assert_eq!(pending.state, SwapState::MakerLocked);
        assert_eq!(pending.maker_leg_funding.as_ref(), Some(&funding));
        assert!(!pending.maker_lock_sent);
        assert_eq!(res.list_all().unwrap().len(), 1);
        assert_eq!(
            sends.lock().unwrap().len(),
            1,
            "only the pre-restart lock send"
        );
    }
    phase.store(3, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "daemon exited at startup"
            );
            let funded = store.get_maker_swap(&ids[0]).unwrap().unwrap();
            if funded.state == SwapState::MakerLockConfirmed {
                assert!(funded.maker_lock_sent);
                chain_time.store(1800000360, Ordering::SeqCst);
            }
            if let Some(refund) = funded.maker_leg_refund {
                let raw = hex::encode(&refund.raw);
                let sent = sends.lock().unwrap();
                if sent.contains(&raw) {
                    seen.lock().unwrap().insert(refund.txid.to_rpc_hex(), 10);
                }
                if funded.state.is_terminal() && res.list_all().unwrap().is_empty() {
                    assert!(funded.maker_lock_sent);
                    assert!(matches!(
                        funded.state,
                        SwapState::Done | SwapState::MakerRefunded
                    ));
                    let unfunded = store.get_maker_swap(&ids[1]).unwrap().unwrap();
                    assert_eq!(unfunded.state, SwapState::Aborted);
                    assert!(unfunded.maker_leg_funding.is_none());
                    assert!(!unfunded.maker_lock_sent);
                    assert!(sent.contains(&raw));
                    assert_eq!(chain_time.load(Ordering::SeqCst), 1800000360);
                    let lock = hex::encode(&funding.tx.raw);
                    assert!(sent.iter().all(|tx| tx == &lock || tx == &raw));
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("refund confirmation and release");
    child.kill().await.unwrap();
    if counter_reply.is_some() {
        assert!(!counter_node.received_requests().await.unwrap().is_empty());
    }
}
