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

//! The start and RPC options divid acts on: -forcestart, -sysperms,
//! -rpcthreads, -alerts and -alertnotify.

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One JSON-RPC call with test:test; None until the server is up
fn rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    // "dGVzdDp0ZXN0" is base64 of test:test
    let request = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let (_, body) = response.split_once("\r\n\r\n")?;
    serde_json::from_str(body).ok()
}

fn result(port: u16, method: &str, params: Value) -> Value {
    let reply = rpc(port, method, params).unwrap_or_else(|| panic!("{method}: no reply"));
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

struct Node {
    child: Child,
    rpc_port: u16,
}

impl Node {
    fn stop(mut self) {
        let _ = rpc(self.rpc_port, "stop", json!([]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// divid's form of the options for a regtest node, then `extra`
fn command(datadir: &Path, rpc_port: u16, p2p_port: u16, extra: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg("-regtest")
        .arg(format!("-datadir={}", datadir.display()))
        .arg(format!("-rpcport={rpc_port}"))
        .arg(format!("-port={p2p_port}"))
        .args(["-bind=127.0.0.1", "-listen=1", "-staking=0"])
        .args(["-connect=127.0.0.1:1", "-dnsseed=0"])
        .args(["-rpcuser=test", "-rpcpassword=test"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

fn start(datadir: &Path, extra: &[&str]) -> Node {
    let (child, rpc_port, _) = start_node(
        datadir,
        |rpc_port, p2p_port| command(datadir, rpc_port, p2p_port, extra),
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    Node { child, rpc_port }
}

fn debug_log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("regtest").join("debug.log"))
        .or_else(|_| std::fs::read_to_string(datadir.join("debug.log")))
        .unwrap_or_default()
}

/// -forcestart: divid skips its block and coin database checks after a stop
/// that was not prepared (BlockIndexLoading.cpp:267-285). irondivid has no
/// such check to skip: after a kill it starts at its last whole block, and
/// takes the option without calling it unsupported.
#[test]
fn forcestart_is_taken_and_a_killed_node_starts_at_its_last_block() {
    let dir = tempfile::tempdir().unwrap();
    let node = start(dir.path(), &[]);
    result(node.rpc_port, "setgenerate", json!([12]));
    node.kill();
    let node = start(dir.path(), &["-forcestart"]);
    assert_eq!(result(node.rpc_port, "getblockcount", json!([])), json!(12));
    node.stop();
    let log = debug_log(dir.path());
    assert!(
        !log.contains("Option -forcestart is not supported"),
        "-forcestart called unsupported"
    );
}
