// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A wallet transaction's `time` and `timereceived` are set when the wallet
//! first hears of it and stay: a send seen in the mempool keeps them when it is
//! mined later, after a restart and after -rescan (Divi Core: nTimeReceived set
//! once, SpentOutputTracker.cpp:39-48; nTimeSmart once, wallet.cpp:1253-1256;
//! rpcwallet.cpp:267-268).

#![cfg(unix)]

use divi_test_support::{free_port, start_on};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// POST one JSON-RPC call; None while the server is not up
fn try_rpc(port: u16, method: &str, params: &Value, timeout: Duration) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    // "dGVzdDp0ZXN0" is base64 of test:test
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

fn ok(port: u16, method: &str, params: Value) -> Value {
    let reply = try_rpc(port, method, &params, Duration::from_secs(120))
        .unwrap_or_else(|| panic!("{method}: no reply"));
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(datadir: &Path, rpc_port: &mut u16, p2p_port: &mut u16, extra: &[&str]) -> Node {
    Node(start_on(
        datadir,
        rpc_port,
        p2p_port,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("--regtest")
                .arg("--datadir")
                .arg(datadir)
                .args(["--rpcport", &rpc_port.to_string()])
                .args(["--port", &p2p_port.to_string()])
                .args(["--bind", "127.0.0.1", "--staking=false", "--listen=false"])
                .args(["--rpcuser", "test", "--rpcpassword", "test"])
                .args(extra)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| {
            try_rpc(
                rpc_port,
                "getblockcount",
                &json!([]),
                Duration::from_secs(10),
            )
            .is_some()
        },
    ))
}

fn times(port: u16, txid: &Value) -> (Value, Value) {
    let tx = ok(port, "gettransaction", json!([txid]));
    (tx["time"].clone(), tx["timereceived"].clone())
}

fn listed_time(port: u16, txid: &Value) -> Value {
    let list = ok(port, "listtransactions", json!(["*", 100]));
    list.as_array()
        .unwrap()
        .iter()
        .find(|e| &e["txid"] == txid)
        .map(|e| e["time"].clone())
        .unwrap_or(Value::Null)
}

#[test]
fn transaction_times_are_kept_from_the_first_sight() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc_port, mut p2p_port) = (free_port(), free_port());
    let node = start(dir.path(), &mut rpc_port, &mut p2p_port, &[]);
    ok(rpc_port, "setgenerate", json!([101]));
    let address = ok(rpc_port, "getnewaddress", json!([]));
    let txid = ok(rpc_port, "sendtoaddress", json!([address, 1]));
    let first = times(rpc_port, &txid);
    assert_eq!(
        first.0, first.1,
        "an unconfirmed transaction: time is the received time"
    );

    // Mined a few seconds later: the times stay those of the first sight
    std::thread::sleep(Duration::from_millis(3100));
    ok(rpc_port, "setgenerate", json!([1]));
    let mined = ok(rpc_port, "gettransaction", json!([txid]));
    assert!(mined["blocktime"].as_u64().unwrap() >= first.0.as_u64().unwrap() + 3);
    assert_eq!(times(rpc_port, &txid), first, "mined later");
    assert_eq!(listed_time(rpc_port, &txid), first.0);
    drop(node);

    // A restart with -rescan keeps them too
    let _node = start(dir.path(), &mut rpc_port, &mut p2p_port, &["--rescan"]);
    assert_eq!(times(rpc_port, &txid), first, "after -rescan");
    assert_eq!(listed_time(rpc_port, &txid), first.0);
}
