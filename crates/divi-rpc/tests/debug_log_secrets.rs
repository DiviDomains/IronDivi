// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! What the debug log keeps of an RPC call. Divi Core 3.0.0 logs only the
//! method's name, "ThreadRPCServer method=<name>" in the rpc category
//! (rpcserver.cpp:893-894), never the params nor the reply: a passphrase,
//! private key or seed sent to or answered by the node stays out of the log.
//! These calls go over HTTP with every log level on.

use divi_primitives::ChainMode;
use divi_rpc::{create_router_with_auth, RpcConfig, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::io::Write;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const USER: &str = "u";
const PASS: &str = "p";

/// Every log line of this test binary, from every thread
static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Capture;

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Capture the log at its most verbose, as irondivid -debug (or RUST_LOG=trace)
fn capture() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing_subscriber::filter::LevelFilter::TRACE)
            .with_writer(|| Capture)
            .init();
    });
}

fn log_text() -> String {
    String::from_utf8_lossy(&LOG.lock().unwrap()).into_owned()
}

/// A value no other call or test sends
fn secret() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

struct Node {
    addr: std::net::SocketAddr,
    _dir: tempfile::TempDir,
}

/// A regtest node with a wallet, its RPC served over HTTP
async fn start_node() -> Node {
    capture();
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(
        WalletDb::create_persistent(
            &dir.path().join("wallet"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    let server = Arc::new(RpcServer::with_wallet(chain, wallet));
    let config = RpcConfig {
        username: Some(USER.into()),
        password: Some(PASS.into()),
        ..RpcConfig::default()
    };
    let router = create_router_with_auth(server, &config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });
    Node { addr, _dir: dir }
}

impl Node {
    /// POST `body` to "/" and return the reply body
    async fn post(&self, body: &str) -> String {
        use base64::Engine;
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASS}"));
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Authorization: Basic {auth}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            body.len()
        );
        let exchange = async {
            let mut stream = tokio::net::TcpStream::connect(self.addr).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        };
        let response = tokio::time::timeout(Duration::from_secs(20), exchange)
            .await
            .expect("RPC reply within 20 s");
        response
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default()
    }

    /// One call; its reply object
    async fn call(&self, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params});
        serde_json::from_str(&self.post(&body.to_string()).await).unwrap()
    }

    /// One call that must succeed; its result
    async fn ok(&self, method: &str, params: Value) -> Value {
        let reply = self.call(method, params).await;
        assert!(reply["error"].is_null(), "{method}: {reply}");
        reply["result"].clone()
    }

    /// A private key of a new address, as dumpprivkey answers it
    async fn new_key(&self) -> (String, String) {
        let address = self.ok("getnewaddress", json!([])).await;
        let wif = self.ok("dumpprivkey", json!([address])).await;
        (
            address.as_str().unwrap().to_string(),
            wif.as_str().unwrap().to_string(),
        )
    }
}

/// The values in `secrets` that the log holds, by name
fn in_log(secrets: &[(&str, &str)]) -> Vec<String> {
    let log = log_text();
    secrets
        .iter()
        .filter(|(_, value)| !value.is_empty() && log.contains(*value))
        .map(|(name, _)| name.to_string())
        .collect()
}

/// encryptwallet, walletpassphrase (right and wrong), walletpassphrasechange,
/// malformed calls, an unparsable body and a batch: no passphrase in the log
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passphrases_stay_out_of_the_debug_log() {
    let node = start_node().await;
    let (first, wrong, second, bad_type, too_many, unparsable, third) = (
        secret(),
        secret(),
        secret(),
        secret(),
        secret(),
        secret(),
        secret(),
    );
    node.ok("encryptwallet", json!([first])).await;
    let reply = node.call("walletpassphrase", json!([wrong, 60])).await;
    assert_eq!(reply["error"]["code"], -14, "{reply}");
    node.ok("walletpassphrase", json!([first, 60])).await;
    node.ok("walletpassphrasechange", json!([first, second]))
        .await;
    let reply = node
        .call("walletpassphrase", json!([bad_type, "notanumber"]))
        .await;
    assert!(!reply["error"].is_null(), "{reply}");
    let reply = node
        .call("walletpassphrase", json!([too_many, 60, true, "x", "y"]))
        .await;
    assert!(!reply["error"].is_null(), "{reply}");
    let reply = node
        .post(&format!(
            r#"{{"jsonrpc":"1.0","id":1,"method":"walletpassphrase","params":["{unparsable}",60"#
        ))
        .await;
    assert!(reply.contains("-32700"), "{reply}");
    let batch = json!([
        {"id": 1, "method": "walletlock", "params": []},
        {"id": 2, "method": "walletpassphrasechange", "params": [second, third]},
        {"id": 3, "method": "walletpassphrase", "params": [third, 60]},
    ]);
    let replies: Value = serde_json::from_str(&node.post(&batch.to_string()).await).unwrap();
    assert!(
        replies
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["error"].is_null()),
        "{replies}"
    );
    let leaked = in_log(&[
        ("encryptwallet passphrase", &first),
        ("wrong walletpassphrase passphrase", &wrong),
        ("walletpassphrasechange new passphrase", &second),
        ("walletpassphrase of a wrong type call", &bad_type),
        (
            "walletpassphrase of a call with too many arguments",
            &too_many,
        ),
        ("passphrase in an unparsable request", &unparsable),
        ("passphrase in a batch", &third),
    ]);
    assert!(leaked.is_empty(), "in the debug log: {leaked:?}");
}

/// Private keys and seeds, sent (importprivkey, signrawtransaction) or
/// answered (dumpprivkey, dumphdinfo), and the bip38 passphrases: none in the log
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keys_and_seeds_stay_out_of_the_debug_log() {
    let node = start_node().await;
    let other = start_node().await;
    let (address, dumped) = node.new_key().await;
    let (_, imported) = other.new_key().await;
    let (_, signing) = other.new_key().await;
    node.ok("importprivkey", json!([imported, "", false])).await;
    let hd = node.ok("dumphdinfo", json!([])).await;
    let seed = hd["hdseed"].as_str().unwrap().to_string();
    let mnemonic = hd["mnemonic"].as_str().unwrap_or_default().to_string();
    assert!(!seed.is_empty(), "{hd}");
    let txid = format!("{}{}", secret(), secret());
    let script = node.ok("validateaddress", json!([address])).await["scriptPubKey"].clone();
    let raw = node
        .ok(
            "createrawtransaction",
            json!([[{"txid": txid, "vout": 0}], {address.clone(): 1}]),
        )
        .await;
    node.ok(
        "signrawtransaction",
        json!([raw, [{"txid": txid, "vout": 0, "scriptPubKey": script}], [signing]]),
    )
    .await;
    let (paper, encrypting) = (secret(), secret());
    node.ok("bip38paperwallet", json!([paper])).await;
    let encrypted = node.ok("bip38encrypt", json!([address, encrypting])).await;
    // decrypted where the key is not held yet
    other
        .ok("bip38decrypt", json!([encrypted, encrypting]))
        .await;
    let leaked = in_log(&[
        ("dumpprivkey reply", &dumped),
        ("importprivkey key", &imported),
        ("signrawtransaction private key", &signing),
        ("dumphdinfo seed", &seed),
        ("dumphdinfo mnemonic", &mnemonic),
        ("bip38paperwallet passphrase", &paper),
        ("bip38encrypt/bip38decrypt passphrase", &encrypting),
    ]);
    assert!(leaked.is_empty(), "in the debug log: {leaked:?}");
}

/// The log keeps the method's name, as divid's "ThreadRPCServer method=" line
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_debug_log_names_the_method() {
    let node = start_node().await;
    let reply = node.call("walletpassphrase", json!([secret(), 60])).await;
    assert!(!reply["error"].is_null(), "{reply}");
    assert!(
        log_text().contains("ThreadRPCServer method=walletpassphrase"),
        "no \"ThreadRPCServer method=walletpassphrase\" line in the log"
    );
}
