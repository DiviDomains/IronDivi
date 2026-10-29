// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! getstakingstatus `staking status` is true, and getinfo says "Staking
//! Active", once the node has tried to stake at the tip in the last minutes,
//! by setgenerate as by the staking loop (Divi Core
//! HasRecentlyAttemptedToGenerateProofOfStake, init.cpp:155-175;
//! rpcmisc.cpp:154-155, :1071-1072).

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

fn start(datadir: &Path, rpc_port: u16, p2p_port: u16) -> Node {
    let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false", "--listen=false"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
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

fn staking_status(port: u16) -> (Value, Value) {
    (
        ok(port, "getstakingstatus", json!([]))["staking status"].clone(),
        ok(port, "getinfo", json!([]))["staking status"].clone(),
    )
}

#[test]
fn staking_status_follows_a_recent_stake_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let _node = start(dir.path(), rpc_port, p2p_port);
    // Proof-of-work blocks hash no stake kernel
    ok(rpc_port, "setgenerate", json!([100]));
    assert_eq!(
        staking_status(rpc_port),
        (json!(false), json!("Staking Not Active"))
    );
    // A proof-of-stake block from setgenerate: a kernel was hashed at the tip
    ok(rpc_port, "setgenerate", json!([1]));
    assert_eq!(ok(rpc_port, "getblockcount", json!([])), json!(101));
    assert_eq!(
        staking_status(rpc_port),
        (json!(true), json!("Staking Active"))
    );
}
