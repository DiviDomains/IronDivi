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

//! Number arguments read as divid reads them: json_spirit's get_int() cuts an
//! integer to a C++ int (json_spirit_value.h:385-390), so 2^32 + 50 is 50 and
//! 2^31 is negative, and a null given by position is read, and refused, as any
//! other type.

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const TWO_32: i64 = 1 << 32;

/// POST one JSON-RPC call: the result, or the error's code and message; None
/// while the server is not up yet
fn rpc(port: u16, method: &str, params: Value) -> Option<Result<Value, (i64, String)>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
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
    let reply: Value = serde_json::from_str(&response[start..]).ok()?;
    Some(match &reply["error"] {
        Value::Null => Ok(reply["result"].clone()),
        e => Err((
            e["code"].as_i64().unwrap_or_default(),
            e["message"].as_str().unwrap_or_default().to_string(),
        )),
    })
}

struct Node {
    child: Child,
    port: u16,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    /// A regtest node with a wallet and `blocks` blocks mined to it
    fn mined(dir: &Path, blocks: u32) -> Node {
        let (child, port, _) = start_node(
            dir,
            |rpc_port, p2p_port| {
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
                cmd.arg("--regtest")
                    .arg("--datadir")
                    .arg(dir)
                    .args(["--rpcport", &rpc_port.to_string()])
                    .args(["--port", &p2p_port.to_string()])
                    .args(["--bind", "127.0.0.1", "--staking=false"])
                    .args(["--connect=127.0.0.1:1", "--dnsseed=0"])
                    .args(["--rpcuser", "test", "--rpcpassword", "test"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                cmd
            },
            |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
        );
        let node = Node { child, port };
        node.ok("setgenerate", json!([blocks]));
        node
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        rpc(self.port, method, params).unwrap_or_else(|| panic!("{method}: no reply"))
    }

    fn ok(&self, method: &str, params: Value) -> Value {
        self.call(method, params.clone())
            .unwrap_or_else(|e| panic!("{method} {params}: {e:?}"))
    }

    /// A confirmed coin of the wallet: txid, output index, scriptPubKey, address
    fn coin(&self) -> (String, i64, String, String) {
        let unspent = self.ok("listunspent", json!([]));
        let u = &unspent[0];
        (
            u["txid"].as_str().unwrap().to_string(),
            u["vout"].as_i64().unwrap(),
            u["scriptPubKey"].as_str().unwrap().to_string(),
            u["address"].as_str().unwrap().to_string(),
        )
    }
}

fn null_refused() -> Result<Value, (i64, String)> {
    Err((-1, "value is type null, expected int".to_string()))
}

/// getblockhash, getlotteryblockwinners, gettxout, getrawtransaction and
/// verifychain (rpcblockchain.cpp:168, :369, :418-420; rpclottery.cpp:50;
/// rpcrawtransaction.cpp:206-207)
#[test]
fn chain_calls_cut_heights_and_indexes_to_an_int() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::mined(dir.path(), 106);

    assert_eq!(
        node.call("getblockhash", json!([TWO_32 + 50])),
        node.call("getblockhash", json!([50]))
    );
    assert_eq!(
        node.call("getlotteryblockwinners", json!([TWO_32 + 105])),
        node.call("getlotteryblockwinners", json!([105]))
    );
    let (txid, vout, _, _) = node.coin();
    assert_eq!(
        node.call("gettxout", json!([txid, TWO_32 + vout])),
        node.call("gettxout", json!([txid, vout]))
    );
    // verbose 2^32 is 0: the hex
    assert!(node
        .ok("getrawtransaction", json!([txid, TWO_32]))
        .is_string());
    // A null is read too
    assert_eq!(
        node.call("getrawtransaction", json!([txid, null])),
        null_refused()
    );
    // verifychain reads its second argument whenever it has one
    assert_eq!(node.call("verifychain", json!([4, null])), null_refused());
    assert_eq!(node.ok("verifychain", json!([4, 1])), json!(true));
}
