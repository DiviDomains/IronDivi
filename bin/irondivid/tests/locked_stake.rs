// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Mining on a locked wallet, as Divi Core does it: a stake block is searched
//! for, and signing its coinstake with a key of the encrypted HD seed fails in
//! CWallet::GetKey (wallet.cpp:536-545, PoSTransactionCreator.cpp:368-371),
//! which the RPC server answers as -1 with that text (rpcserver.cpp:1107-1108).

use divi_test_support::{log_tail, start_node};
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

/// A node with `blocks` work blocks and an encrypted wallet, locked
fn locked_node(dir: &std::path::Path, blocks: u32) -> (KillOnDrop, u16) {
    let (child, rpc_port, _) = start_node(
        dir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("--regtest")
                .arg("--datadir")
                .arg(dir)
                .args(["--rpcport", &rpc_port.to_string()])
                .args(["--port", &p2p_port.to_string()])
                .args(["--bind", "127.0.0.1", "--staking=0"])
                // RPC always requires credentials; "dGVzdDp0ZXN0" is base64 of test:test
                .args(["--rpcuser", "test", "--rpcpassword", "test"])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", serde_json::json!([])).is_some(),
    );
    let node = KillOnDrop(child);
    ok(rpc_port, "setgenerate", serde_json::json!([blocks]));
    ok(
        rpc_port,
        "encryptwallet",
        serde_json::json!(["throwaway test passphrase"]),
    );
    let info = ok(rpc_port, "getwalletinfo", serde_json::json!([]));
    assert_eq!(info["encryption_status"], "locked", "{info}");
    (node, rpc_port)
}

/// The error of a call that must fail
fn error(port: u16, method: &str, params: Value) -> Value {
    let reply = rpc(port, method, params).unwrap_or_else(|| panic!("{method}: no reply"));
    assert!(reply["result"].is_null(), "{method} should fail: {reply}");
    reply["error"].clone()
}

#[test]
fn setgenerate_on_a_locked_wallet_fails_in_getkey_for_a_stake() {
    let dir = tempfile::tempdir().unwrap();
    let (_node, port) = locked_node(dir.path(), 100);

    let err = error(port, "setgenerate", serde_json::json!([1]));
    assert_eq!(err["code"], -1, "{err}\n{}", log_tail(dir.path()));
    assert_eq!(err["message"], "GetKey: DecryptHDChainSeed failed", "{err}");
    assert_eq!(ok(port, "getblockcount", serde_json::json!([])), 100);

    // Unlocked for staking only, the key is there and the block is made
    ok(
        port,
        "walletpassphrase",
        serde_json::json!(["throwaway test passphrase", 300, true]),
    );
    ok(port, "setgenerate", serde_json::json!([1]));
    assert_eq!(ok(port, "getblockcount", serde_json::json!([])), 101);
}

/// generateblock makes its block as setgenerate does (rpcmining.cpp:200-208,
/// minter.createNewBlock): on a locked wallet a work block pays a keypool key,
/// and a stake block fails in GetKey
#[test]
fn generateblock_on_a_locked_wallet_mines_as_setgenerate() {
    let dir = tempfile::tempdir().unwrap();
    let (_node, port) = locked_node(dir.path(), 99);

    ok(port, "generateblock", serde_json::json!([{}]));
    assert_eq!(ok(port, "getblockcount", serde_json::json!([])), 100);

    let err = error(port, "generateblock", serde_json::json!([{}]));
    assert_eq!(err["code"], -1, "{err}\n{}", log_tail(dir.path()));
    assert_eq!(err["message"], "GetKey: DecryptHDChainSeed failed", "{err}");
    assert_eq!(ok(port, "getblockcount", serde_json::json!([])), 100);
}
