// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A restart leaves the keypool as it was, as divid's does: divid tops the
//! pool up only before it takes a key (wallet.cpp:2122-2131), not when it
//! loads the wallet.

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    // "dGVzdDp0ZXN0" is base64 of test:test
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let (_, body) = response.split_once("\r\n\r\n")?;
    serde_json::from_str(body).ok()
}

fn ok(port: u16, method: &str, params: Value) -> Value {
    let reply = rpc(port, method, params).unwrap_or_else(|| panic!("{method}: no reply"));
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        unsafe { libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A regtest node on `dir` and its RPC port
fn start(dir: &Path) -> (Node, u16) {
    let (child, rpc_port, _) = start_node(
        dir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("-regtest")
                .arg(format!("-datadir={}", dir.display()))
                .arg(format!("-rpcport={rpc_port}"))
                .arg(format!("-port={p2p_port}"))
                .args([
                    "-bind=127.0.0.1",
                    "-rpcuser=test",
                    "-rpcpassword=test",
                    "-staking=0",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    (Node(child), rpc_port)
}

#[test]
fn restart_keeps_the_keypool_size() {
    let dir = tempfile::tempdir().unwrap();
    let (node, rpc_port) = start(dir.path());
    // Taking a key leaves the pool one short until the next take
    ok(rpc_port, "getnewaddress", json!([]));
    let before = ok(rpc_port, "getwalletinfo", json!([]))["keypoolsize"].clone();
    ok(rpc_port, "stop", json!([]));
    drop(node);

    let (_node, rpc_port) = start(dir.path());
    let after = ok(rpc_port, "getwalletinfo", json!([]))["keypoolsize"].clone();
    assert_eq!(after, before, "the restart changed the keypool");
}
