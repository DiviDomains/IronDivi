// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `-electrum` and `-electrumtls` serve the Electrum protocol from a regtest
//! node: headers padded to 112 bytes, a script hash's history, balance and
//! coins through the mempool and into a block, notifications, transactions
//! and their merkle proofs, and broadcasting. The TLS certificate in
//! tests/fixtures/electrum is a test-only one, signed by the test CA there.

#![cfg(unix)]

use divi_test_support::{free_port, start_node};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tungstenite::client::IntoClientRequest;
use tungstenite::{Message, WebSocket};

/// One JSON-RPC call; None while the server is not up.
/// "dGVzdDp0ZXN0" is base64 of test:test
fn try_rpc(port: u16, method: &str, params: &Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let start = response.find("\r\n\r\n")? + 4;
    serde_json::from_str(&response[start..]).ok()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/electrum")
        .join(name)
}

struct Node {
    child: Child,
    port: u16,
    electrum: u16,
    electrum_tls: u16,
    electrum_ws: u16,
    electrum_wss: u16,
}

impl Node {
    fn start(datadir: &std::path::Path) -> Node {
        let (mut electrum, mut electrum_tls, mut electrum_ws, mut electrum_wss) = (0, 0, 0, 0);
        let (child, port, _) = start_node(
            datadir,
            |rpc_port, p2p_port| {
                (electrum, electrum_tls, electrum_ws, electrum_wss) =
                    (free_port(), free_port(), free_port(), free_port());
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
                cmd.arg("--regtest")
                    .arg("--datadir")
                    .arg(datadir)
                    .args(["--rpcport", &rpc_port.to_string()])
                    .args(["--port", &p2p_port.to_string()])
                    .args(["--bind", "127.0.0.1", "--staking=false"])
                    .args(["--connect", "127.0.0.1:1"])
                    .args(["--rpcuser", "test", "--rpcpassword", "test"])
                    .args(["--txindex", "--addressindex"])
                    .arg(format!("--electrum=127.0.0.1:{electrum}"))
                    .arg(format!("--electrumtls=127.0.0.1:{electrum_tls}"))
                    .arg(format!("--electrumws=127.0.0.1:{electrum_ws}"))
                    .arg(format!("--electrumwss=127.0.0.1:{electrum_wss}"))
                    .arg(format!("--electrumcert={}", fixture("cert.pem").display()))
                    .arg(format!("--electrumkey={}", fixture("key.pem").display()))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                cmd
            },
            |rpc_port| try_rpc(rpc_port, "getblockcount", &json!([])).is_some(),
        );
        Node {
            child,
            port,
            electrum,
            electrum_tls,
            electrum_ws,
            electrum_wss,
        }
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply =
            try_rpc(self.port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"));
        assert!(reply["error"].is_null(), "{method} {params}: {reply}");
        reply["result"].clone()
    }

    /// A connection to the plain TCP port, once the server listens
    fn connect(&self) -> Client<Lines<TcpStream>> {
        Client::new(self.open(self.electrum))
    }

    /// A plain WebSocket connection, once the server listens
    fn connect_ws(&self) -> Client<WebSocket<TcpStream>> {
        let stream = self.open(self.electrum_ws);
        // A browser sends its page's Origin; the server must accept any
        let mut request = "ws://127.0.0.1/".into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Origin", "https://wallet.example".parse().unwrap());
        let (socket, _) = tungstenite::client(request, stream).unwrap();
        Client::with(socket)
    }

    /// A WebSocket-over-TLS connection
    fn connect_wss(
        &self,
    ) -> Client<WebSocket<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>> {
        let tls = tls_stream(self.open(self.electrum_wss));
        let (socket, _) = tungstenite::client("wss://localhost/", tls).unwrap();
        Client::with(socket)
    }

    fn open(&self, port: u16) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                return stream;
            }
            assert!(Instant::now() < deadline, "the electrum port never opened");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The TLS client side over `tcp`, trusting the test CA
fn tls_stream(tcp: TcpStream) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    let ca = std::fs::read(fixture("ca.pem")).unwrap();
    use rustls::pki_types::pem::PemObject;
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&ca) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connection =
        rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    rustls::StreamOwned::new(connection, tcp)
}

/// How a client reads and writes whole JSON-RPC messages: a line over TCP,
/// a text frame over WebSocket
trait Transport {
    fn read_text(&mut self) -> String;
    fn write_text(&mut self, message: &str);
}

struct Lines<S: Read + Write>(BufReader<S>);

impl<S: Read + Write> Transport for Lines<S> {
    fn read_text(&mut self) -> String {
        let mut line = String::new();
        let n = self.0.read_line(&mut line).unwrap();
        assert!(n > 0, "the server closed the connection");
        line
    }

    fn write_text(&mut self, message: &str) {
        let stream = self.0.get_mut();
        stream.write_all(format!("{message}\n").as_bytes()).unwrap();
        stream.flush().unwrap();
    }
}

impl<S: Read + Write> Transport for WebSocket<S> {
    fn read_text(&mut self) -> String {
        loop {
            match self.read().expect("the server closed the connection") {
                Message::Text(text) => {
                    // One message per frame, no line framing
                    assert!(!text.ends_with('\n'), "{text:?}");
                    return text;
                }
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("unexpected frame {other:?}"),
            }
        }
    }

    fn write_text(&mut self, message: &str) {
        self.send(Message::Text(message.to_string())).unwrap();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = try_rpc(self.port, "stop", &json!([]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An Electrum client: one JSON line per request, notifications kept aside
struct Client<T: Transport> {
    transport: T,
    next_id: u64,
    notifications: Vec<Value>,
}

impl<S: Read + Write> Client<Lines<S>> {
    fn new(stream: S) -> Self {
        Client::with(Lines(BufReader::new(stream)))
    }
}

impl<T: Transport> Client<T> {
    fn with(transport: T) -> Self {
        Client {
            transport,
            next_id: 0,
            notifications: Vec::new(),
        }
    }

    fn read(&mut self) -> Value {
        serde_json::from_str(&self.transport.read_text()).unwrap()
    }

    /// The whole reply to a request
    fn reply(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.transport.write_text(&line.to_string());
        loop {
            let message = self.read();
            if message["id"] == json!(id) {
                return message;
            }
            assert!(message.get("id").is_none(), "{message}");
            self.notifications.push(message);
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let reply = self.reply(method, params.clone());
        assert!(reply["error"].is_null(), "{method} {params}: {reply}");
        reply["result"].clone()
    }

    /// The next notification of `method`, kept or still to come
    fn notification(&mut self, method: &str) -> Value {
        if let Some(i) = self
            .notifications
            .iter()
            .position(|n| n["method"] == method)
        {
            return self.notifications.remove(i)["params"].clone();
        }
        loop {
            let message = self.read();
            if message["method"] == method {
                return message["params"].clone();
            }
            self.notifications.push(message);
        }
    }
}

/// Electrum's script hash: sha256 of the script, byte-reversed, in hex
fn scripthash(script_hex: &str) -> String {
    let mut hash = Sha256::digest(hex::decode(script_hex).unwrap()).to_vec();
    hash.reverse();
    hex::encode(hash)
}

/// A header as the server sends it: Divi's header padded to 112 bytes
/// A hash in RPC display order, as internal (little-endian) bytes
fn hex_le(hash: &Value) -> Vec<u8> {
    let mut bytes = hex::decode(hash.as_str().unwrap()).unwrap();
    bytes.reverse();
    bytes
}

fn sha256d(data: &[u8]) -> Vec<u8> {
    Sha256::digest(Sha256::digest(data)).to_vec()
}

fn padded(raw: &str) -> String {
    format!("{raw:0<224}")
}

#[test]
fn electrum_serves_a_regtest_node() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(dir.path());
    node.rpc("setgenerate", json!([110]));
    let mut c = node.connect();
    session_suite(&node, &mut c);

    // TLS: the same server behind the test certificate
    let mut tls = Client::new(tls_stream(node.open(node.electrum_tls)));
    assert_eq!(tls.call("server.version", json!(["test", "1.4"]))[1], "1.4");
    assert_eq!(
        tls.call("blockchain.headers.subscribe", json!([]))["height"],
        111
    );
}

/// The same session tests over WebSocket: a text frame per message, a header
/// push and a scripthash push, from a page on another Origin
#[test]
fn electrum_serves_a_regtest_node_over_websocket() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(dir.path());
    node.rpc("setgenerate", json!([110]));
    let mut c = node.connect_ws();
    session_suite(&node, &mut c);

    // Secure WebSocket: the same server behind the test certificate
    let mut wss = node.connect_wss();
    assert_eq!(wss.call("server.version", json!(["test", "1.4"]))[1], "1.4");
    assert_eq!(
        wss.call("blockchain.headers.subscribe", json!([]))["height"],
        111
    );
    // A frame with several requests is a JSON-RPC batch
    wss.transport.write_text(
        &json!([
            {"jsonrpc": "2.0", "id": 1, "method": "server.ping", "params": []},
            {"jsonrpc": "2.0", "id": 2, "method": "blockchain.relayfee", "params": []},
        ])
        .to_string(),
    );
    assert_eq!(wss.read().as_array().unwrap().len(), 2);
}

/// A client that
/// talks plain TCP at a WebSocket port is dropped, and the port keeps serving
#[test]
fn electrum_websocket_port_rejects_non_websocket_clients() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(dir.path());
    let mut stream = node.open(node.electrum_ws);
    stream
        .write_all(b"{\"id\":1,\"method\":\"server.ping\",\"params\":[]}\n\r\n\r\n")
        .unwrap();
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    assert!(!reply.contains("result"), "{reply}");
    // And the node still serves a real one
    assert_eq!(
        node.connect_ws().call("server.ping", json!([])),
        Value::Null
    );
}

/// The whole conversation, over whichever transport `c` speaks; expects a
/// fresh regtest node at height 110
fn session_suite<T: Transport>(node: &Node, c: &mut Client<T>) {
    c.notifications.clear();
    let version = c.call("server.version", json!(["test", "1.4"]));
    assert_eq!(version[1], "1.4");
    assert!(version[0].as_str().unwrap().starts_with("IronDivi"));
    assert_eq!(c.call("server.ping", json!([])), Value::Null);

    // Headers: the tip, one by height and a run of them, all 112 bytes
    let tip = c.call("blockchain.headers.subscribe", json!([]));
    assert_eq!(tip["height"], 110);
    let tip_hash = node.rpc("getblockhash", json!([110]));
    let raw = node.rpc("getblockheader", json!([tip_hash, false]));
    assert_eq!(tip["hex"], padded(raw.as_str().unwrap()));
    let header = c.call("blockchain.block.header", json!([5]));
    let raw = node.rpc(
        "getblockheader",
        json!([node.rpc("getblockhash", json!([5])), false]),
    );
    assert_eq!(header, padded(raw.as_str().unwrap()));
    let headers = c.call("blockchain.block.headers", json!([0, 5]));
    assert_eq!(headers["count"], 5);
    assert_eq!(headers["hex"].as_str().unwrap().len(), 5 * 224);
    assert_eq!(
        &headers["hex"].as_str().unwrap()[5 * 224 - 224..],
        c.call("blockchain.block.header", json!([4]))
            .as_str()
            .unwrap()
    );
    assert!(!c.reply("blockchain.block.header", json!([1000]))["error"].is_null());

    // A fresh address: no history, then a payment in the mempool
    let address = node.rpc("getnewaddress", json!([]));
    let script = node.rpc("validateaddress", json!([address]))["scriptPubKey"].clone();
    let sh = scripthash(script.as_str().unwrap());
    assert_eq!(
        c.call("blockchain.scripthash.subscribe", json!([sh])),
        Value::Null
    );
    assert_eq!(
        c.call("blockchain.scripthash.get_history", json!([sh])),
        json!([])
    );

    let txid = node.rpc("sendtoaddress", json!([address, 10]));
    let pushed = c.notification("blockchain.scripthash.subscribe");
    assert_eq!(pushed[0], sh);
    assert!(pushed[1].is_string());
    assert_eq!(
        c.call("blockchain.scripthash.get_balance", json!([sh])),
        json!({"confirmed": 0, "unconfirmed": 1_000_000_000})
    );
    let mempool = c.call("blockchain.scripthash.get_mempool", json!([sh]));
    assert_eq!(mempool[0]["tx_hash"], txid);
    assert_eq!(mempool[0]["height"], 0);
    assert!(mempool[0]["fee"].as_i64().unwrap() > 0);
    let unspent = c.call("blockchain.scripthash.listunspent", json!([sh]));
    assert_eq!(unspent[0]["height"], 0);
    assert_eq!(unspent[0]["value"], 1_000_000_000);

    // Into a block: confirmed, a new tip pushed, a merkle proof
    node.rpc("setgenerate", json!([1]));
    let tip = c.notification("blockchain.headers.subscribe");
    assert_eq!(tip[0]["height"], 111);
    let status = c.notification("blockchain.scripthash.subscribe")[1].clone();
    assert_ne!(status, pushed[1]);
    assert_eq!(
        c.call("blockchain.scripthash.get_history", json!([sh])),
        json!([{"tx_hash": txid, "height": 111}])
    );
    assert_eq!(
        c.call("blockchain.scripthash.get_balance", json!([sh])),
        json!({"confirmed": 1_000_000_000, "unconfirmed": 0})
    );
    let unspent = c.call("blockchain.scripthash.listunspent", json!([sh]));
    assert_eq!(unspent.as_array().unwrap().len(), 1);
    assert_eq!(unspent[0]["height"], 111);
    assert_eq!(unspent[0]["tx_hash"], txid);
    assert_eq!(
        c.call("blockchain.scripthash.subscribe", json!([sh])),
        status
    );

    let raw_tx = node.rpc("getrawtransaction", json!([txid]));
    assert_eq!(c.call("blockchain.transaction.get", json!([txid])), raw_tx);
    let verbose = c.call("blockchain.transaction.get", json!([txid, true]));
    assert_eq!(verbose["txid"], txid);
    let block = node.rpc("getblock", json!([node.rpc("getblockhash", json!([111]))]));
    let pos = block["tx"]
        .as_array()
        .unwrap()
        .iter()
        .position(|t| *t == txid)
        .unwrap();
    let merkle = c.call("blockchain.transaction.get_merkle", json!([txid, 111]));
    assert_eq!(merkle["block_height"], 111);
    assert_eq!(merkle["pos"], pos);
    let mut node_hash = hex_le(&txid);
    let mut index = pos;
    for sibling in merkle["merkle"].as_array().unwrap() {
        let sibling = hex_le(sibling);
        node_hash = if index % 2 == 0 {
            sha256d(&[node_hash, sibling].concat())
        } else {
            sha256d(&[sibling, node_hash].concat())
        };
        index /= 2;
    }
    assert_eq!(node_hash, hex_le(&block["merkleroot"]));

    // Broadcasting the coin back to the wallet
    let to = node.rpc("getnewaddress", json!([]));
    let raw = node.rpc(
        "createrawtransaction",
        json!([[{"txid": txid, "vout": unspent[0]["tx_pos"]}], {to.as_str().unwrap(): 9.999}]),
    );
    let signed = node.rpc("signrawtransaction", json!([raw]))["hex"].clone();
    let sent = c.call("blockchain.transaction.broadcast", json!([signed]));
    assert_eq!(node.rpc("getrawmempool", json!([])), json!([sent]));
    assert!(!c.reply("blockchain.transaction.broadcast", json!(["00"]))["error"].is_null());
    let balance = c.call("blockchain.scripthash.get_balance", json!([sh]));
    assert_eq!(
        balance,
        json!({"confirmed": 1_000_000_000, "unconfirmed": -1_000_000_000})
    );
    assert_eq!(
        c.call("blockchain.scripthash.listunspent", json!([sh])),
        json!([])
    );

    assert!(
        c.call("blockchain.estimatefee", json!([2]))
            .as_f64()
            .unwrap()
            > 0.0
    );
    assert!(c.call("blockchain.relayfee", json!([])).as_f64().unwrap() > 0.0);
    assert_eq!(
        c.reply("no.such.method", json!([]))["error"]["code"],
        -32601
    );
}

#[test]
fn electrum_needs_the_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(dir.path())
        .arg(format!("--electrum=127.0.0.1:{}", free_port()))
        .args(["--txindex=0", "--addressindex=0"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("-electrum needs -txindex=1 and -addressindex=1"),
        "{stderr}"
    );
}
