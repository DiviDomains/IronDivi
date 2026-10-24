// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Regtest `generateblock` makes one block as Divi Core's does
//! (rpcmining.cpp:121-210, ExtendedBlockFactory.cpp): with or without the
//! pool's transactions, with extra ones, and with a custom coinstake or
//! shifted bits only where Core makes a block of them.

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A coinstake (vin[0] not null, vout[0] empty, two outputs) paying OP_TRUE,
/// for which no key signs a block
const COINSTAKE: &str = concat!(
    "01000000",
    "01",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "00000000",
    "00",
    "ffffffff",
    "02",
    "0000000000000000",
    "00",
    "00e1f50500000000",
    "01",
    "51",
    "00000000"
);

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

struct Node {
    child: Child,
    port: u16,
}

impl Node {
    fn start(datadir: &std::path::Path) -> Node {
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
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                cmd
            },
            |rpc_port| try_rpc(rpc_port, "getblockcount", &json!([])).is_some(),
        );
        Node { child, port }
    }

    fn call(&self, method: &str, params: Value) -> Value {
        try_rpc(self.port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"))
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply = self.call(method, params.clone());
        assert!(reply["error"].is_null(), "{method} {params}: {reply}");
        reply["result"].clone()
    }

    /// The (code, message) of a refused call
    fn refused(&self, method: &str, params: Value) -> (i64, String) {
        let reply = self.call(method, params.clone());
        let e = &reply["error"];
        assert!(!e.is_null(), "{method} {params}: {reply}");
        (
            e["code"].as_i64().unwrap(),
            e["message"].as_str().unwrap().to_string(),
        )
    }

    fn height(&self) -> u64 {
        self.rpc("getblockcount", json!([])).as_u64().unwrap()
    }

    /// The txids of a block after the block-reward transactions
    fn block_txs(&self, hash: &Value, skip: usize) -> Vec<String> {
        let block = self.rpc("getblock", json!([hash]));
        block["tx"].as_array().unwrap()[skip..]
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect()
    }

    /// A signed transaction of the wallet spending its oldest coin
    fn signed_tx(&self, skip: usize) -> String {
        let mut coins = self
            .rpc("listunspent", json!([]))
            .as_array()
            .unwrap()
            .clone();
        coins.sort_by_key(|c| std::cmp::Reverse(c["confirmations"].as_u64().unwrap()));
        let coin = &coins[skip];
        let to = self.rpc("getnewaddress", json!([]));
        let amount = coin["amount"].as_f64().unwrap() - 0.001;
        let raw = self.rpc(
            "createrawtransaction",
            json!([[{"txid": coin["txid"], "vout": coin["vout"]}], {to.as_str().unwrap(): (amount * 1e8).round() / 1e8}]),
        );
        let signed = self.rpc("signrawtransaction", json!([raw]));
        signed["hex"].as_str().unwrap().to_string()
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

#[test]
fn generateblock_makes_one_block_as_divid() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(dir.path());
    node.rpc("setgenerate", json!([25]));

    // Proof of work: the pool's transaction left out, an extra one taken
    let pooled = node.rpc("sendrawtransaction", json!([node.signed_tx(0)]));
    let extra = node.signed_tx(1);
    let extra_id = node.rpc("decoderawtransaction", json!([extra]))["txid"].clone();
    let hash = node.rpc(
        "generateblock",
        json!([{"ignoreMempool": true, "extratx": [extra]}]),
    );
    assert_eq!(node.height(), 26);
    assert_eq!(node.block_txs(&hash, 1), vec![extra_id.as_str().unwrap()]);
    assert_eq!(node.rpc("getrawmempool", json!([])), json!([pooled]));
    // With no options, as setgenerate
    let hash = node.rpc("generateblock", json!([]));
    assert_eq!(node.block_txs(&hash, 1), vec![pooled.as_str().unwrap()]);

    // A custom coinstake on a proof-of-work block is refused with Core's
    // message; shifted bits make no block there (Core's SignBlock finds no
    // pay-to-pubkey coinbase output)
    assert_eq!(
        node.refused("generateblock", json!([{"coinstake": COINSTAKE}])),
        (
            -1,
            "trying to set custom coinstake in non-PoS block".to_string()
        )
    );
    assert_eq!(
        node.refused("generateblock", json!([{"blockBitsShift": 0}])),
        (-25, "failed to generate a valid block".to_string())
    );
    assert_eq!(node.height(), 27);

    // Proof of stake after block 100
    node.rpc("setgenerate", json!([100 - 27 + 1]));
    assert_eq!(node.height(), 101);
    node.rpc("generateblock", json!([]));
    node.rpc("generateblock", json!([{"ignoreMempool": true}]));
    // Bits shifted by 0 are the same bits: the block, signed again, is valid
    node.rpc("generateblock", json!([{"blockBitsShift": 0}]));
    assert_eq!(node.height(), 104);
    assert_eq!(
        node.refused("generateblock", json!([{"blockBitsShift": 1}])),
        (-25, "failed to generate a valid block".to_string())
    );
    // No key signs for this coinstake's second output (divid's process stops
    // here instead, docs/divid-differences.md R14)
    assert_eq!(
        node.refused("generateblock", json!([{"coinstake": COINSTAKE}])),
        (-25, "failed to generate a valid block".to_string())
    );
    assert_eq!(node.height(), 104);
}
