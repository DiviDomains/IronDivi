// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The masternode sync stages as Divi Core walks them (masternode-sync.cpp,
//! rpcmisc.cpp:200-221): INITIAL until the chain is synced, then SPORKS, where
//! a node with fewer than three peers stays; `mnsync reset` goes back to
//! INITIAL.

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
    start_with(datadir, rpc_port, p2p_port, &["--listen=false"])
}

fn start_with(datadir: &Path, rpc_port: u16, p2p_port: u16, extra: &[&str]) -> Node {
    let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false"])
        .args(extra)
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

fn status(port: u16) -> Value {
    ok(port, "mnsync", json!(["status"]))
}

/// Polls `mnsync status` until `done` holds, for `secs` at most
fn wait_status(port: u16, secs: u64, done: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let s = status(port);
        if done(&s) || Instant::now() >= deadline {
            return s;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn mnsync_stages_follow_the_chain_and_reset() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let _node = start(dir.path(), rpc_port, p2p_port);
    // The genesis block is old: the chain is not synced, the sync not begun
    let s = status(rpc_port);
    assert_eq!(s["IsBlockchainSynced"], json!(false), "{s}");
    assert_eq!(s["currentMasternodeSyncStatus"], json!(0), "{s}");
    // A new block: synced; the sync thread's first step starts its clock and
    // the next, five seconds on, moves to SPORKS, where a node with no peers
    // stays
    ok(rpc_port, "setgenerate", json!([1]));
    let s = wait_status(rpc_port, 15, |s| {
        s["currentMasternodeSyncStatus"] == json!(1)
    });
    assert_eq!(s["currentMasternodeSyncStatus"], json!(1), "{s}");
    assert_eq!(s["IsBlockchainSynced"], json!(true), "{s}");
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(status(rpc_port)["currentMasternodeSyncStatus"], json!(1));
    // Reset: INITIAL, then SPORKS again at the next step
    assert_eq!(ok(rpc_port, "mnsync", json!(["reset"])), json!("success"));
    assert_eq!(status(rpc_port)["currentMasternodeSyncStatus"], json!(0));
    let s = wait_status(rpc_port, 10, |s| {
        s["currentMasternodeSyncStatus"] == json!(1)
    });
    assert_eq!(s["currentMasternodeSyncStatus"], json!(1), "{s}");
}

/// getstakingstatus `mnsync` is IsSynced, the sync finished (rpcmisc.cpp:1069):
/// false at SPORKS on a node that followed a peer's chain, though that chain
/// is synced
#[test]
fn getstakingstatus_mnsync_is_the_finished_sync() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (rpc_a, p2p_a, rpc_b, p2p_b) = (free_port(), free_port(), free_port(), free_port());
    let _a = start_with(dir_a.path(), rpc_a, p2p_a, &["--listen=1"]);
    let connect = format!("-connect=127.0.0.1:{p2p_a}");
    let _b = start_with(dir_b.path(), rpc_b, p2p_b, &["--listen=false", &connect]);
    ok(rpc_a, "setgenerate", json!([3]));
    let deadline = Instant::now() + Duration::from_secs(60);
    while ok(rpc_b, "getblockcount", json!([])) != json!(3) {
        assert!(
            Instant::now() < deadline,
            "the follower did not reach the tip"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let s = wait_status(rpc_b, 15, |s| s["currentMasternodeSyncStatus"] == json!(1));
    assert_eq!(s["IsBlockchainSynced"], json!(true), "{s}");
    assert_eq!(
        ok(rpc_b, "getstakingstatus", json!([]))["mnsync"],
        json!(false),
        "{s}"
    );
    assert_eq!(s["currentMasternodeSyncStatus"], json!(1), "{s}");
}
