// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `setgenerate N` on regtest mines N blocks to the wallet: proof of work up
//! to the last PoW block, proof of stake after it (BasicSwap's test setup).

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
fn setgenerate_mines_pow_then_pos() {
    let dir = tempfile::tempdir().unwrap();
    let (child, rpc_port, _) = start_node(
        dir.path(),
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("--regtest")
                .arg("--datadir")
                .arg(dir.path())
                .args(["--rpcport", &rpc_port.to_string()])
                .args(["--port", &p2p_port.to_string()])
                // BasicSwap starts the node with staking off and mines with setgenerate
                .args(["--bind", "127.0.0.1", "--staking=false"])
                // RPC always requires credentials; "dGVzdDp0ZXN0" is base64 of test:test
                .args(["--rpcuser", "test", "--rpcpassword", "test"])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", serde_json::json!([])).is_some(),
    );
    let _node = KillOnDrop(child);

    assert!(ok(rpc_port, "setgenerate", serde_json::json!([0])).is_null());

    // Core takes exactly one integer (rpcmining.cpp:54, json_spirit get_int)
    for params in [
        serde_json::json!([]),
        serde_json::json!([true, 1]),
        serde_json::json!(["1"]),
    ] {
        let reply = rpc(rpc_port, "setgenerate", params.clone()).expect("reply");
        assert_eq!(reply["error"]["code"], -1, "{params}: {reply}");
    }
    assert_eq!(ok(rpc_port, "getblockcount", serde_json::json!([])), 0);

    // Proof of work through the last PoW block
    let hashes = ok(rpc_port, "setgenerate", serde_json::json!([101]));
    let hashes = hashes.as_array().expect("setgenerate returns hashes");
    assert_eq!(hashes.len(), 101);
    assert_eq!(ok(rpc_port, "getblockcount", serde_json::json!([])), 101);
    assert_eq!(
        ok(rpc_port, "getblockhash", serde_json::json!([101])),
        hashes[100]
    );

    // Proof of stake after it, from the coins mined above
    let hashes = ok(rpc_port, "setgenerate", serde_json::json!([5]));
    assert_eq!(hashes.as_array().map(Vec::len), Some(5));
    assert_eq!(ok(rpc_port, "getblockcount", serde_json::json!([])), 106);
    let tip = ok(rpc_port, "getblock", serde_json::json!([hashes[4]]));
    assert_eq!(tip["height"], 106);
    assert!(
        ok(rpc_port, "getbalance", serde_json::json!([]))
            .as_f64()
            .unwrap()
            > 0.0
    );
}
