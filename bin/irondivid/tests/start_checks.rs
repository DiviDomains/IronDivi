// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! -resync, as Divi Core's ClearFoldersForResync (init.cpp:901-930,
//! :1480-1483): the chain's folders are removed before the chain loads, so the
//! node starts again from genesis; the wallet and the configuration stay.

#![cfg(unix)]

use divi_test_support::{free_port, log_tail, start_on};
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

fn start(datadir: &Path, rpc_port: &mut u16, p2p_port: &mut u16) -> Node {
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

fn stop(port: u16, mut node: Node) {
    let _ = try_rpc(port, "stop", &json!([]), Duration::from_secs(30));
    let deadline = Instant::now() + Duration::from_secs(60);
    while node.0.try_wait().ok().flatten().is_none() {
        assert!(Instant::now() < deadline, "irondivid did not stop");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn resync_starts_the_chain_again_and_keeps_the_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc_port, mut p2p_port) = (free_port(), free_port());
    let node = start(dir.path(), &mut rpc_port, &mut p2p_port);
    ok(rpc_port, "setgenerate", json!([10]));
    let address = ok(rpc_port, "getnewaddress", json!([]));
    stop(rpc_port, node);
    assert!(dir.path().join("txindex").exists());

    std::fs::write(dir.path().join("divi.conf"), "resync=1\n").unwrap();
    let node = start(dir.path(), &mut rpc_port, &mut p2p_port);
    assert_eq!(
        ok(rpc_port, "getblockcount", json!([])),
        json!(0),
        "the chain starts again"
    );
    assert_eq!(
        ok(rpc_port, "validateaddress", json!([address]))["ismine"],
        json!(true),
        "the wallet is kept"
    );
    assert!(dir.path().join("divi.conf").exists());
    stop(rpc_port, node);
    let log = std::fs::read_to_string(dir.path().join("debug.log")).unwrap();
    assert!(
        log.contains("-resync: folder deleted:"),
        "{}",
        log_tail(dir.path())
    );
}
