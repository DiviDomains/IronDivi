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
const TWO_31: i64 = 1 << 31;

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

/// createrawtransaction and signrawtransaction vouts, signtransactionwithaddresskey's
/// input index and createmultisig's nrequired (rpcrawtransaction.cpp:420-426, :572,
/// :726-728; rpcmisc.cpp:390)
#[test]
fn raw_transaction_calls_cut_indexes_to_an_int() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::mined(dir.path(), 25);
    let (txid, vout, script, address) = node.coin();

    // 2^31 is negative
    assert_eq!(
        node.call(
            "createrawtransaction",
            json!([[{"txid": txid, "vout": TWO_31}], {address.clone(): 1}])
        ),
        Err((-8, "Invalid parameter, vout must be positive".to_string()))
    );
    // 2^32 + vout is vout
    assert_eq!(
        node.call(
            "createrawtransaction",
            json!([[{"txid": txid, "vout": TWO_32 + vout}], {address.clone(): 1}])
        ),
        node.call(
            "createrawtransaction",
            json!([[{"txid": txid, "vout": vout}], {address.clone(): 1}])
        )
    );
    let raw = node.ok(
        "createrawtransaction",
        json!([[{"txid": txid, "vout": vout}], {address.clone(): 1}]),
    );
    assert_eq!(
        node.call(
            "signrawtransaction",
            json!([raw, [{"txid": txid, "vout": TWO_31, "scriptPubKey": script}]])
        ),
        Err((-22, "vout must be positive".to_string()))
    );
    assert_eq!(
        node.call(
            "signtransactionwithaddresskey",
            json!([raw, address.clone(), null])
        ),
        null_refused()
    );
    let pubkey = node.ok("validateaddress", json!([address]))["pubkey"].clone();
    assert_eq!(
        node.call("createmultisig", json!([TWO_32 + 1, [pubkey.clone()]])),
        node.call("createmultisig", json!([1, [pubkey]]))
    );
}

/// The wallet calls' minconf, count, from and target, lockunspent's vout,
/// getbalance "*" and sendmany's repeated outputs (rpcwallet.cpp:1576-1584,
/// :1668-1675, :2276-2279, :2343, :2420-2422, :2801-2803;
/// rpcrawtransaction.cpp:288-294, :318)
#[test]
fn wallet_calls_cut_counts_and_depths_to_an_int() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::mined(dir.path(), 25);
    let (txid, _, _, address) = node.coin();

    // maxconf -1: no depth is at most -1; minconf 2^32 is 0
    assert_eq!(node.ok("listunspent", json!([1, -1])), json!([]));
    assert_eq!(
        node.call("listunspent", json!([TWO_32])),
        node.call("listunspent", json!([0]))
    );
    let three = node.ok("listtransactions", json!(["*", TWO_32 + 3]));
    assert_eq!(three.as_array().unwrap().len(), 3, "{three}");
    assert_eq!(
        node.call("listtransactions", json!(["*", TWO_31])),
        Err((-8, "Negative count".to_string()))
    );
    let genesis = node.ok("getblockhash", json!([0]));
    assert_eq!(
        node.call("listsinceblock", json!([genesis, TWO_32])),
        Err((-8, "Invalid parameter".to_string()))
    );
    assert_eq!(node.call("listaccounts", json!([null])), null_refused());
    // For "*" divid answers before it reads minconf; for an account it reads it
    assert_eq!(
        node.call("getbalance", json!(["*", 1.5])),
        node.call("getbalance", json!([]))
    );
    assert_eq!(node.call("getbalance", json!(["", null])), null_refused());
    assert_eq!(
        node.call(
            "lockunspent",
            json!([false, [{"txid": txid, "vout": TWO_31}]])
        ),
        Err((-8, "Invalid parameter, vout must be positive".to_string()))
    );
    // A repeated output's amount must be a real; -2^32 + 2 repetitions is 2
    assert_eq!(
        node.call(
            "sendmany",
            json!(["", {address.clone(): {"amount": 1, "repetitions": 1}}])
        ),
        Err((-3, "Expected type real for amount, got int".to_string()))
    );
    let sent = node.ok(
        "sendmany",
        json!(["", {address.clone(): {"amount": 1.5, "repetitions": 2 - TWO_32}}]),
    );
    let tx = node.ok("getrawtransaction", json!([sent, 1]));
    let to_address = tx["vout"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["scriptPubKey"]["addresses"] == json!([address]))
        .count();
    assert_eq!(to_address, 2, "{tx}");
}

/// setgenerate's number of blocks (rpcmining.cpp:79-81)
#[test]
fn setgenerate_cuts_the_number_of_blocks_to_an_int() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::mined(dir.path(), 3);
    let mined = node.ok("setgenerate", json!([TWO_32 + 1]));
    assert_eq!(mined.as_array().map(Vec::len), Some(1), "{mined}");
    // 2^32 + 2^31 is negative: none
    assert_eq!(
        node.ok("setgenerate", json!([TWO_32 + TWO_31])),
        json!(null)
    );
    assert_eq!(node.ok("getblockcount", json!([])), json!(4));
}
