// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A send on an unlocked wallet leaves the keypool full, change or not, as
//! Divi Core reserves a change key for every send without a change address of
//! its own (wallet.cpp:1786, :1909-1910), which tops the keypool up
//! (wallet.cpp:2129-2130), and returns it when no change is needed
//! (wallet.cpp:1813-1816).

use divi_test_support::start_node;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::Value;

/// POST one JSON-RPC call; None while the server is not up yet.
fn rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .ok()?;
    let body = serde_json::json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
        .to_string();
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

/// The result of a call that must succeed.
fn ok(port: u16, method: &str, params: Value) -> Value {
    let reply = rpc(port, method, params).unwrap_or_else(|| panic!("{method}: no reply"));
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_send_without_change_tops_the_keypool_up() {
    let dir = tempfile::tempdir().unwrap();
    let (child, port, _) = start_node(
        dir.path(),
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("--regtest")
                .arg("--datadir")
                .arg(dir.path())
                .args(["--rpcport", &rpc_port.to_string()])
                .args(["--port", &p2p_port.to_string()])
                .args(["--bind", "127.0.0.1", "--staking=0", "--keypool=3"])
                // RPC always requires credentials; "dGVzdDp0ZXN0" is base64 of test:test
                .args(["--rpcuser", "test", "--rpcpassword", "test"])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", serde_json::json!([])).is_some(),
    );
    let _node = KillOnDrop(child);
    let keypool = |port| ok(port, "getwalletinfo", serde_json::json!([]))["keypoolsize"].clone();

    ok(port, "setgenerate", serde_json::json!([30]));
    // A call that takes a key tops the keypool up first, so it is left one
    // short: 3 + 3 keys less the one taken
    let to = ok(port, "getnewaddress", serde_json::json!([]));
    assert_eq!(keypool(port), 5);

    // The whole balance sent: no change output, the reserved key goes back
    let balance = ok(port, "getbalance", serde_json::json!(["*", 1]));
    ok(
        port,
        "sendtoaddress",
        serde_json::json!([to, balance, "sweep_funds"]),
    );
    assert_eq!(keypool(port), 6, "the send topped the keypool up");
}
