// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A block takes the pool's transactions as Divi Core's block assembler does
//! (BlockMemoryPoolTransactionCollector.cpp:261-342): by coin-age priority up
//! to -blockprioritysize, then by fee rate, with prioritisetransaction deltas
//! applied and a child after its parent.

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
    fn start(datadir: &std::path::Path, extra: &[&str]) -> Node {
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
        Node { child, port }
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply =
            try_rpc(self.port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"));
        assert!(reply["error"].is_null(), "{method} {params}: {reply}");
        reply["result"].clone()
    }

    /// Spend `coin` (txid, vout, amount in DIVI) back to the wallet, paying
    /// `fee` satoshis
    fn spend(&self, coin: &(String, u64, i64), fee: i64) -> String {
        let to = self.rpc("getnewaddress", json!([]));
        let out = format!("{:.8}", (coin.2 - fee) as f64 / 1e8);
        let raw = self.rpc(
            "createrawtransaction",
            json!([[{"txid": coin.0, "vout": coin.1}], {to.as_str().unwrap(): out.parse::<f64>().unwrap()}]),
        );
        let signed = self.rpc("signrawtransaction", json!([raw]));
        assert_eq!(signed["complete"], true, "{signed}");
        self.rpc("sendrawtransaction", json!([signed["hex"]]))
            .as_str()
            .unwrap()
            .to_string()
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

/// Six pool transactions, one block, `-blockprioritysize=1300`:
/// - C has a prioritisetransaction delta that puts it first;
/// - A spends the oldest coin, so it is next by priority, though its fee is
///   among the lowest; with C it reaches the priority area, so the rest go by
///   fee rate: B (a large fee), D, then P;
/// - K pays the largest fee but spends P's output, so it waits for P.
///
/// Fee order alone would give K, B, D, then the others.
#[test]
fn block_is_filled_by_priority_then_fee_as_divid() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(dir.path(), &["-blockprioritysize=1300"]);
    node.rpc("setgenerate", json!([30]));

    // The coinbase of height h has 31 - h confirmations at tip 30
    let unspent = node.rpc("listunspent", json!([]));
    let coin_at = |height: i64| -> (String, u64, i64) {
        let u = unspent
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["confirmations"] == 31 - height)
            .unwrap_or_else(|| panic!("no coin from height {height}: {unspent}"));
        (
            u["txid"].as_str().unwrap().to_string(),
            u["vout"].as_u64().unwrap(),
            (u["amount"].as_f64().unwrap() * 1e8).round() as i64,
        )
    };

    let a = node.spend(&coin_at(1), 3_000);
    let d = node.spend(&coin_at(2), 4_000);
    let p = node.spend(&coin_at(7), 3_000);
    let c = node.spend(&coin_at(8), 3_000);
    let b = node.spend(&coin_at(9), 1_000_000);
    let p_out = node.rpc("getrawtransaction", json!([p, 1]));
    let k = node.spend(
        &(
            p.clone(),
            0,
            (p_out["vout"][0]["value"].as_f64().unwrap() * 1e8).round() as i64,
        ),
        50_000_000,
    );
    assert_eq!(
        node.rpc(
            "prioritisetransaction",
            json!([c, 0.0, 100_000_000_000_000i64])
        ),
        true
    );

    let hash = &node.rpc("setgenerate", json!([1]))[0];
    let block = node.rpc("getblock", json!([hash]));
    let txs: Vec<&str> = block["tx"].as_array().unwrap()[1..]
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    let name = |t: &str| {
        [
            ("A", &a),
            ("B", &b),
            ("C", &c),
            ("D", &d),
            ("K", &k),
            ("P", &p),
        ]
        .iter()
        .find(|(_, id)| id.as_str() == t)
        .map(|(n, _)| *n)
        .unwrap_or("?")
    };
    let order: Vec<&str> = txs.iter().map(|t| name(t)).collect();
    assert_eq!(order, ["C", "A", "B", "D", "P", "K"]);
}
