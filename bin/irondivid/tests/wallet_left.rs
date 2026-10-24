// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The wallet's sends pay the -minrelaytxfee rate, as Divi Core's wallet
//! does (rpcwallet.cpp:470-473, :510-513).

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
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

#[test]
fn wallet_send_fee_follows_minrelaytxfee() {
    let dir = tempfile::tempdir().unwrap();
    let (child, rpc_port, _) = start_node(
        dir.path(),
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("-regtest")
                .arg(format!("-datadir={}", dir.path().display()))
                .arg(format!("-rpcport={rpc_port}"))
                .arg(format!("-port={p2p_port}"))
                .args(["-bind=127.0.0.1", "-rpcuser=test", "-rpcpassword=test"])
                .args(["-staking=0", "-minrelaytxfee=0.0005"])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    let _node = Node(child);

    // Mature coins: regtest coinbase maturity is 20
    ok(rpc_port, "setgenerate", json!([25]));
    let to = ok(rpc_port, "getnewaddress", json!([]));
    let txid = ok(rpc_port, "sendtoaddress", json!([to, 1]));
    let tx = ok(rpc_port, "gettransaction", json!([txid]));
    let size = tx["hex"].as_str().expect("hex").len() as f64 / 2.0;
    let fee_sat = (tx["fee"].as_f64().expect("fee").abs() * 1e8).round();
    assert!(
        fee_sat >= 50_000.0 * size / 1000.0,
        "fee {fee_sat} sat for {size} bytes is below the -minrelaytxfee rate"
    );
}
