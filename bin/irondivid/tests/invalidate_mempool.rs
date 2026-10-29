// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! invalidateblock gives the transactions of the blocks it disconnects back
//! to the mempool, as Divi Core's disconnectTip does ("Resurrect mempool
//! transactions from the disconnected block", ChainTipManager.cpp), and
//! reconsiderblock takes them out again once the block is back on the chain.

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

fn pool(port: u16) -> (u64, u64) {
    let info = ok(port, "getmempoolinfo", json!([]));
    (
        info["size"].as_u64().unwrap(),
        info["bytes"].as_u64().unwrap(),
    )
}

#[test]
fn invalidateblock_returns_the_block_transactions_to_the_mempool() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let _node = start(dir.path(), rpc_port, p2p_port);
    ok(rpc_port, "setgenerate", json!([101]));
    let address = ok(rpc_port, "getnewaddress", json!([]));
    let txid = ok(rpc_port, "sendtoaddress", json!([address, 1]));
    let size = ok(rpc_port, "getrawtransaction", json!([txid]))
        .as_str()
        .unwrap()
        .len() as u64
        / 2;
    assert_eq!(pool(rpc_port), (1, size));
    ok(rpc_port, "setgenerate", json!([1]));
    assert_eq!(pool(rpc_port), (0, 0), "confirmed");

    let tip = ok(rpc_port, "getbestblockhash", json!([]));
    ok(rpc_port, "invalidateblock", json!([tip]));
    assert_eq!(pool(rpc_port), (1, size), "back in the mempool");
    let pending = ok(rpc_port, "getrawmempool", json!([]));
    assert_eq!(pending, json!([txid]));

    ok(rpc_port, "reconsiderblock", json!([tip]));
    assert_eq!(ok(rpc_port, "getbestblockhash", json!([])), tip);
    assert_eq!(pool(rpc_port), (0, 0), "confirmed again");
}

/// The wallet follows invalidateblock and reconsiderblock as divid's does: it
/// hears of the disconnected block (SyncTransactions BLOCK_DISCONNECT,
/// ChainTipManager.cpp:189), so its send is unconfirmed again and its balance
/// is what it was before the block; the block's return confirms it again
#[test]
fn the_wallet_follows_invalidateblock_and_reconsiderblock() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let _node = start(dir.path(), rpc_port, p2p_port);
    ok(rpc_port, "setgenerate", json!([101]));
    let txid = ok(
        rpc_port,
        "sendtoaddress",
        json!([ok(rpc_port, "getnewaddress", json!([])), 1]),
    );
    let state = || {
        let tx = ok(rpc_port, "gettransaction", json!([txid]));
        (
            ok(rpc_port, "getbalance", json!([])),
            ok(rpc_port, "getunconfirmedbalance", json!([])),
            tx["confirmations"].clone(),
            ok(rpc_port, "listunspent", json!([0]))
                .as_array()
                .unwrap()
                .len(),
        )
    };
    let unconfirmed = state();
    ok(rpc_port, "setgenerate", json!([1]));
    let confirmed = state();
    assert_ne!(unconfirmed, confirmed);

    let tip = ok(rpc_port, "getbestblockhash", json!([]));
    ok(rpc_port, "invalidateblock", json!([tip]));
    assert_eq!(state(), unconfirmed, "after invalidateblock");
    ok(rpc_port, "reconsiderblock", json!([tip]));
    assert_eq!(state(), confirmed, "after reconsiderblock");

    ok(rpc_port, "reverseblocktransactions", json!([tip]));
    assert_eq!(state(), unconfirmed, "after reverseblocktransactions");
}
