// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Account names, comments and messages of any text, as divid keeps them

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

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(datadir: &Path, rpc_port: u16, p2p_port: u16, extra: &[&str]) -> Node {
    let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false", "--listen=false"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn irondivid");
    let mut node = Node(child);
    let deadline = Instant::now() + Duration::from_secs(120);
    while try_rpc(
        rpc_port,
        "getblockcount",
        &json!([]),
        Duration::from_secs(10),
    )
    .is_none()
    {
        if let Ok(Some(status)) = node.0.try_wait() {
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

/// Stop the node with the RPC stop and wait (bounded) until it exits
fn stop(mut node: Node, rpc_port: u16) {
    let _ = try_rpc(rpc_port, "stop", &json!([]), Duration::from_secs(30));
    let deadline = Instant::now() + Duration::from_secs(60);
    while node.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Text no script uses: non-ASCII, quotes, a tab, a newline and NUL
const ODD: &str = "caf\u{e9} \u{4e2d}\u{6587} \u{1f4b0} \"q\" \t\n\u{0}x";

/// sendfrom and sendmany keep the account they spent from with the send
/// (wtx.strFromAccount, wallet.cpp:1918-1921), and their send entries carry it:
/// gettransaction's details and listtransactions of that account
/// (rpcwallet.cpp:2162-2167), also after a restart
#[test]
fn sends_list_under_the_account_they_came_from() {
    // An address of another wallet to pay
    let other = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let n = start(other.path(), rpc_port, p2p_port, &[]);
    let payee = ok(rpc_port, "getnewaddress", json!([]));
    stop(n, rpc_port);

    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), rpc_port, p2p_port, &[]);
    ok(rpc_port, "setgenerate", json!([101]));
    let own = ok(rpc_port, "getnewaddress", json!([ODD]));
    for _ in 0..2 {
        ok(rpc_port, "sendtoaddress", json!([own, 10]));
    }
    ok(rpc_port, "setgenerate", json!([1]));
    let sends = [
        ok(rpc_port, "sendfrom", json!([ODD, payee, 1, "c", "t"])),
        ok(
            rpc_port,
            "sendmany",
            json!([ODD, {payee.as_str().unwrap(): 1}, "c"]),
        ),
    ];
    let plain = ok(rpc_port, "sendtoaddress", json!([payee, 1]));
    let check = |when: &str| {
        let listed = ok(rpc_port, "listtransactions", json!([ODD, 100]));
        for txid in &sends {
            let tx = ok(rpc_port, "gettransaction", json!([txid]));
            let sent: Vec<&Value> = tx["details"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|d| d["category"] == "send")
                .collect();
            assert!(!sent.is_empty(), "{when}: {tx}");
            for d in sent {
                assert_eq!(d["account"], json!(ODD), "{when}: {tx}");
            }
            assert!(
                listed.as_array().unwrap().iter().any(|e| e["txid"] == *txid
                    && e["category"] == "send"
                    && e["account"] == json!(ODD)),
                "{when}: the send {txid} under its account: {listed}"
            );
        }
        // A send of the default account stays under ""
        let tx = ok(rpc_port, "gettransaction", json!([plain]));
        for d in tx["details"].as_array().unwrap() {
            assert_eq!(d["account"], json!(""), "{when}: {tx}");
        }
    };
    check("before a restart");
    stop(n, rpc_port);
    let n = start(dir.path(), rpc_port, p2p_port, &[]);
    check("after a restart");
    stop(n, rpc_port);
}

/// sendfrom and sendmany take no minconf: a comment that reads as a number
/// is a comment (rpcwallet.cpp:1631-1642, :1716-1723), and the send spends
/// coins with one confirmation
#[test]
fn a_comment_that_reads_as_a_number_is_a_comment() {
    let other = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let n = start(other.path(), rpc_port, p2p_port, &[]);
    let payee = ok(rpc_port, "getnewaddress", json!([]));
    stop(n, rpc_port);

    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), rpc_port, p2p_port, &[]);
    ok(rpc_port, "setgenerate", json!([101]));
    let own = ok(rpc_port, "getnewaddress", json!(["acct"]));
    for _ in 0..2 {
        ok(rpc_port, "sendtoaddress", json!([own, 10]));
    }
    // One confirmation
    ok(rpc_port, "setgenerate", json!([1]));
    let from = ok(
        rpc_port,
        "sendfrom",
        json!(["acct", payee, 1, "123", "456"]),
    );
    let many = ok(
        rpc_port,
        "sendmany",
        json!(["acct", {payee.as_str().unwrap(): 1}, "7"]),
    );
    let tx = ok(rpc_port, "gettransaction", json!([from]));
    assert_eq!((&tx["comment"], &tx["to"]), (&json!("123"), &json!("456")));
    let tx = ok(rpc_port, "gettransaction", json!([many]));
    assert_eq!(tx["comment"], json!("7"));
    stop(n, rpc_port);
}
