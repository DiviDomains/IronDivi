// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
}

impl Node {
    /// A regtest node with `extra` options and 101 blocks: a mature coinbase
    fn funded(datadir: &std::path::Path, extra: &[&str]) -> Node {
        let (child, port, _) = start_node(
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
        let node = Node { child, port };
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
        assert!(script.len() < 0xfd);
        b.push(script.len() as u8);
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
