// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The wallet's unconfirmed sends go back into the mempool at start without
//! being announced to peers, as Divi Core's
//! SubmitUnconfirmedWalletTransactionsToMempool only runs AcceptToMemoryPool
//! (init.cpp:1262-1275, txmempool.cpp:408-415); peers hear of them from the
//! periodic mempool rebroadcast.

#![cfg(unix)]

use divi_test_support::{free_port, log_tail};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

struct Node {
    child: Child,
    rpc: u16,
}

impl Node {
    fn stop(mut self) {
        let _ = try_rpc(self.rpc, "stop", &json!([]), Duration::from_secs(30));
        let _ = self.child.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(datadir: &Path, rpc: u16, p2p: u16, extra: &[String]) -> Node {
    let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &rpc.to_string()])
        .args(["--port", &p2p.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=0"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn irondivid");
    let mut node = Node { child, rpc };
    let deadline = Instant::now() + Duration::from_secs(120);
    while try_rpc(rpc, "getblockcount", &json!([]), Duration::from_secs(10)).is_none() {
        if let Ok(Some(status)) = node.child.try_wait() {
            panic!("irondivid exited at start: {status}\n{}", log_tail(datadir));
        }
        assert!(
            Instant::now() < deadline,
            "irondivid did not answer within 120 s"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    node
}

fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        assert!(Instant::now() < deadline, "{what} within {secs} s");
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn in_pool(port: u16, txid: &Value) -> bool {
    ok(port, "getrawmempool", json!([]))
        .as_array()
        .unwrap()
        .contains(txid)
}

#[test]
fn a_resubmitted_send_is_not_announced_at_start() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (rpc_a, p2p_a, rpc_b, p2p_b) = (free_port(), free_port(), free_port(), free_port());
    // A dials B, which listens
    let to_b = vec![format!("--connect=127.0.0.1:{p2p_b}"), "--listen=0".into()];
    let b_args = vec!["--listen=1".to_string()];

    let b = start(dir_b.path(), rpc_b, p2p_b, &b_args);
    let a = start(dir_a.path(), rpc_a, p2p_a, &to_b);
    ok(rpc_a, "setgenerate", json!([101]));
    wait_until("B follows A", 60, || {
        ok(rpc_b, "getblockcount", json!([])) == json!(101)
    });

    // The send is made while B is down, so only A's wallet has it
    b.stop();
    let txid = ok(
        rpc_a,
        "sendtoaddress",
        json!([ok(rpc_a, "getnewaddress", json!([])), 1]),
    );
    a.stop();

    let _b = start(dir_b.path(), rpc_b, p2p_b, &b_args);
    let _a = start(dir_a.path(), rpc_a, p2p_a, &to_b);
    assert!(in_pool(rpc_a, &txid), "the send is back in A's mempool");
    wait_until("A and B connected", 30, || {
        ok(rpc_b, "getconnectioncount", json!([])).as_u64() >= Some(1)
    });
    // Not announced: B does not get it
    let quiet_until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < quiet_until {
        assert!(
            !in_pool(rpc_b, &txid),
            "A announced its resubmitted send at start"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
