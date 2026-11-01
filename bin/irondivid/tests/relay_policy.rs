// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The relay-policy options Divi Core's mempool reads (MempoolConsensus.cpp):
//! -permitbaremultisig, -datacarrier and -datacarriersize, -limitfreerelay and
//! -relaypriority, each taken as divid takes it.

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// POST one JSON-RPC call; None while the server is not up.
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

struct Node {
    child: Child,
    port: u16,
    p2p_port: u16,
}

impl Node {
    /// A regtest node with `extra` options and 101 blocks: a mature coinbase
    fn funded(datadir: &std::path::Path, extra: &[&str]) -> Node {
        let (child, port, p2p_port) = start_node(
            datadir,
            |rpc_port, p2p_port| {
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
                cmd.arg("--regtest")
                    .arg("--datadir")
                    .arg(datadir)
                    .args(["--rpcport", &rpc_port.to_string()])
                    .args(["--port", &p2p_port.to_string()])
                    .args(["--bind", "127.0.0.1", "--staking=false"])
                    .args(["--connect", "127.0.0.1:1"])
                    .args(["--rpcuser", "test", "--rpcpassword", "test"])
                    .args(extra)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                cmd
            },
            |rpc_port| try_rpc(rpc_port, "getblockcount", &json!([])).is_some(),
        );
        let node = Node {
            child,
            port,
            p2p_port,
        };
        node.rpc("setgenerate", json!([101]));
        node
    }

    fn call(&self, method: &str, params: Value) -> Value {
        try_rpc(self.port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"))
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply = self.call(method, params.clone());
        assert!(reply["error"].is_null(), "{method} {params}: {reply}");
        reply["result"].clone()
    }

    /// An unspent coin of the wallet of at least `min` satoshis, with
    /// `confirmations`: (txid, vout, satoshis)
    fn coin(&self, min: i64, confirmations: Option<u64>) -> (String, u32, i64) {
        let coins = self.rpc("listunspent", json!([]));
        let c = coins
            .as_array()
            .unwrap()
            .iter()
            .find(|c| {
                (c["amount"].as_f64().unwrap() * 1e8).round() as i64 >= min
                    && confirmations.is_none_or(|n| c["confirmations"].as_u64() == Some(n))
            })
            .unwrap_or_else(|| panic!("no coin of {min} sat: {coins}"));
        (
            c["txid"].as_str().unwrap().to_string(),
            c["vout"].as_u64().unwrap() as u32,
            (c["amount"].as_f64().unwrap() * 1e8).round() as i64,
        )
    }

    /// The script of a new address of the wallet
    fn script(&self) -> Vec<u8> {
        let address = self.rpc("getnewaddress", json!([]));
        hex(
            self.rpc("validateaddress", json!([address]))["scriptPubKey"]
                .as_str()
                .unwrap(),
        )
    }

    /// A spend of `coin` to `outputs` (satoshis, script), signed by the wallet
    fn signed(&self, coin: &(String, u32, i64), outputs: &[(i64, Vec<u8>)]) -> String {
        let signed = self.rpc("signrawtransaction", json!([serialize(coin, outputs)]));
        assert_eq!(signed["complete"], true, "{signed}");
        signed["hex"].as_str().unwrap().to_string()
    }

    /// sendrawtransaction: Ok(txid) or Err((code, message))
    fn send(&self, hex: &str) -> Result<String, (i64, String)> {
        let reply = self.call("sendrawtransaction", json!([hex]));
        match reply["error"].as_object() {
            Some(e) => Err((
                e["code"].as_i64().unwrap(),
                e["message"].as_str().unwrap().to_string(),
            )),
            None => Ok(reply["result"].as_str().unwrap().to_string()),
        }
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

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A version-1 transaction spending `coin` with an empty scriptSig
fn serialize(coin: &(String, u32, i64), outputs: &[(i64, Vec<u8>)]) -> String {
    let mut b = 1i32.to_le_bytes().to_vec();
    b.push(1);
    let mut txid = hex(&coin.0);
    txid.reverse();
    b.extend(txid);
    b.extend(coin.1.to_le_bytes());
    b.push(0);
    b.extend(0xffff_ffffu32.to_le_bytes());
    b.push(outputs.len() as u8);
    for (value, script) in outputs {
        b.extend(value.to_le_bytes());
        if script.len() < 0xfd {
            b.push(script.len() as u8);
        } else {
            b.push(0xfd);
            b.extend((script.len() as u16).to_le_bytes());
        }
        b.extend(script);
    }
    b.extend(0u32.to_le_bytes());
    to_hex(&b)
}

/// A bare 1-of-1 CHECKMULTISIG script of the secp256k1 generator, no one's key
fn bare_multisig() -> Vec<u8> {
    let mut s = vec![0x51, 33];
    s.extend(hex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ));
    s.extend([0x51, 0xae]);
    s
}

const FEE: i64 = 100_000;
const COIN: i64 = 100_000_000;

/// -permitbaremultisig=0 makes a bare multisig output not standard
/// (MempoolConsensus.cpp:31, :107-109); by default it is standard
#[test]
fn permitbaremultisig_off_refuses_bare_multisig() {
    for (option, refused) in [(None, false), (Some("-permitbaremultisig=0"), true)] {
        let dir = tempfile::tempdir().unwrap();
        let extra: Vec<&str> = option.into_iter().collect();
        let node = Node::funded(dir.path(), &extra);
        let coin = node.coin(1000 * COIN, None);
        let tx = node.signed(
            &coin,
            &[
                (coin.2 - FEE - COIN, node.script()),
                (COIN, bare_multisig()),
            ],
        );
        let got = node.send(&tx);
        if refused {
            assert_eq!(
                got,
                Err((-26, "64: bare-multisig".to_string())),
                "{option:?}"
            );
        } else {
            assert!(got.is_ok(), "{option:?}: {got:?}");
        }
    }
}

/// An OP_META output script of `size` bytes: OP_META and one push
fn op_meta(size: usize) -> Vec<u8> {
    let mut s = vec![0x6a];
    match size {
        1 => {}
        2..=77 => s.push((size - 2) as u8),
        78..=258 => s.extend([0x4c, (size - 3) as u8]),
        _ => {
            s.push(0x4d);
            s.extend(((size - 4) as u16).to_le_bytes());
        }
    }
    s.resize(size, 0xab);
    s
}

/// The largest standard OP_META output is -datacarriersize bytes, and with
/// -datacarrier=0 there is none (MempoolConsensus.cpp:32-33, script/standard.cpp:249)
#[test]
fn datacarrier_options_set_the_largest_op_meta() {
    for (options, taken, refused) in [
        (vec!["-datacarriersize=40"], 40, 41),
        (vec!["-datacarriersize=1000"], 1000, 1001),
        (vec!["-datacarrier=0", "-datacarriersize=1000"], 0, 1),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::funded(dir.path(), &options);
        for (size, ok) in [(taken, true), (refused, false)] {
            if size == 0 {
                continue;
            }
            let coin = node.coin(1000 * COIN, None);
            let tx = node.signed(&coin, &[(coin.2 - FEE, node.script()), (0, op_meta(size))]);
            let got = node.send(&tx);
            if ok {
                assert!(got.is_ok(), "{options:?} {size}: {got:?}");
            } else {
                assert_eq!(
                    got,
                    Err((-26, "64: scriptpubkey".to_string())),
                    "{options:?} {size}"
                );
            }
        }
    }
}

/// A free spend of a young 1 DIVI coin has too little priority: refused with
/// 66 "insufficient priority" unless -relaypriority=0 (MempoolConsensus.cpp:254-259)
#[test]
fn relaypriority_off_takes_a_free_low_priority_spend() {
    for (option, taken) in [(None, false), (Some("-relaypriority=0"), true)] {
        let dir = tempfile::tempdir().unwrap();
        let extra: Vec<&str> = option.into_iter().collect();
        let node = Node::funded(dir.path(), &extra);
        let to = node.rpc("getnewaddress", json!([]));
        node.rpc("sendtoaddress", json!([to, 1]));
        node.rpc("setgenerate", json!([1]));
        let coins = node.rpc("listunspent", json!([1, 1, [to]]));
        let c = &coins[0];
        let coin = (
            c["txid"].as_str().unwrap().to_string(),
            c["vout"].as_u64().unwrap() as u32,
            COIN,
        );
        let tx = node.signed(&coin, &[(COIN, node.script())]);
        let got = node.send(&tx);
        if taken {
            assert!(got.is_ok(), "{option:?}: {got:?}");
        } else {
            assert_eq!(
                got,
                Err((-26, "66: insufficient priority".to_string())),
                "{option:?}"
            );
        }
    }
}

/// One p2p message: regtest magic, command, length, checksum, payload
fn message(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = vec![0xa1, 0xcf, 0x7e, 0xac];
    let mut name = command.as_bytes().to_vec();
    name.resize(12, 0);
    m.extend(name);
    m.extend((payload.len() as u32).to_le_bytes());
    m.extend(&divi_crypto::double_sha256(payload)[..4]);
    m.extend(payload);
    m
}

fn read_message(stream: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let mut head = [0u8; 24];
    stream.read_exact(&mut head)?;
    let command = String::from_utf8_lossy(&head[4..16])
        .trim_end_matches('\0')
        .to_string();
    let len = u32::from_le_bytes(head[16..20].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((command, payload))
}

fn net_address(port: u16) -> Vec<u8> {
    let mut a = 1u64.to_le_bytes().to_vec();
    a.extend([0u8; 10]);
    a.extend([0xff, 0xff, 127, 0, 0, 1]);
    a.extend(port.to_be_bytes());
    a
}

/// Relay `hex` from a raw peer: the node's `reject` for it (code, reason), if
/// it sends one within 5 seconds
fn relay(port: u16, hex_tx: &str) -> Option<(u8, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut version = 70920i32.to_le_bytes().to_vec();
    version.extend(1u64.to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    version.extend(now.to_le_bytes());
    version.extend(net_address(port));
    version.extend(net_address(0));
    version.extend(0x5eed_u64.to_le_bytes());
    version.push(4);
    version.extend(b"/rp/");
    version.extend(0i32.to_le_bytes());
    version.push(1);
    stream.write_all(&message("version", &version)).unwrap();
    let (mut got_version, mut got_verack) = (false, false);
    while !(got_version && got_verack) {
        let (command, _) = read_message(&mut stream).expect("handshake");
        if command == "version" {
            got_version = true;
            stream.write_all(&message("verack", &[])).unwrap();
        } else if command == "verack" {
            got_verack = true;
        }
    }
    stream.write_all(&message("tx", &hex(hex_tx))).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match read_message(&mut stream) {
            Ok((command, payload)) if command == "reject" => {
                let n = payload[0] as usize;
                let code = payload[1 + n];
                let m = payload[2 + n] as usize;
                let reason = String::from_utf8_lossy(&payload[3 + n..3 + n + m]).to_string();
                return Some((code, reason));
            }
            Ok((command, payload)) if command == "ping" => {
                stream.write_all(&message("pong", &payload)).unwrap();
            }
            _ => {}
        }
    }
    None
}

/// A free transaction from a peer counts against -limitfreerelay thousand
/// bytes a minute; at 0 none is taken: 66 "rate limited free transaction"
/// (MempoolConsensus.cpp:211-234, :260-263). By default (30) it is taken.
#[test]
fn limitfreerelay_zero_refuses_free_transactions_from_peers() {
    for (option, limited) in [(None, false), (Some("-limitfreerelay=0"), true)] {
        let dir = tempfile::tempdir().unwrap();
        let mut extra = vec!["-listen=1"];
        extra.extend(option);
        let node = Node::funded(dir.path(), &extra);
        // A coinbase of 1250 DIVI, about 100 blocks old: priority to spare
        let coin = node.coin(1000 * COIN, None);
        let tx = node.signed(&coin, &[(coin.2, node.script())]);
        let reject = relay(node.p2p_port, &tx);
        std::thread::sleep(Duration::from_millis(500));
        let pool = node.rpc("getrawmempool", json!([]));
        let in_pool = pool.as_array().unwrap().iter().any(|t| {
            let mut id = divi_crypto::double_sha256(&hex(&tx)).to_vec();
            id.reverse();
            t == &json!(to_hex(&id))
        });
        if limited {
            assert_eq!(
                reject,
                Some((66, "rate limited free transaction".to_string())),
                "{option:?}"
            );
            assert!(!in_pool, "{option:?}");
        } else {
            assert_eq!(reject, None, "{option:?}");
            assert!(in_pool, "{option:?}: {pool}");
        }
    }
}
