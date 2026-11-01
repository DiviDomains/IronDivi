// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Divi Core's fork warning: an invalid chain with more than six blocks of
//! work over the best one shows in getinfo's and getmininginfo's "errors" and
//! puts the server in safe mode (ForkWarningHelpers.cpp:20-58, Warnings.cpp:41-47).

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WARNING: &str = "Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.";
const LOG_LINE: &str =
    "CheckForkWarningConditions: Warning: Found invalid chain at least ~6 blocks longer than our best chain.";

/// One JSON-RPC call on 127.0.0.1 with test:test; None until the server is up
fn rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok()?;
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
    let (_, body) = response.split_once("\r\n\r\n")?;
    serde_json::from_str(body).ok()
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

/// A regtest irondivid on `datadir` with no peers, once its RPC answers
fn start(datadir: &Path, extra: &[String]) -> (Node, u16) {
    let (child, rpc_port, _) = start_node(
        datadir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.args([
                "-regtest".to_string(),
                format!("-datadir={}", datadir.display()),
                "-bind=127.0.0.1".into(),
                "-rpcuser=test".into(),
                "-rpcpassword=test".into(),
                "-staking=0".into(),
                "-connect=127.0.0.1:1".into(),
                format!("-rpcport={rpc_port}"),
                format!("-port={p2p_port}"),
            ])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    (Node(child), rpc_port)
}

fn ok(port: u16, method: &str, params: Value) -> Value {
    let reply = rpc(port, method, params).unwrap();
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

fn errors(port: u16) -> (Value, Value) {
    (
        ok(port, "getinfo", json!([]))["errors"].clone(),
        ok(port, "getmininginfo", json!([]))["errors"].clone(),
    )
}

/// The node invalidates block 11 of 30: the invalid block it keeps then is
/// block 11, one block of work past its tip, so nothing shows. After a
/// restart it keeps block 30, the most work of the blocks marked failed
/// (BlockIndexLoading.cpp:67-68), and the next block it connects is
/// checked: block 30 is more than six blocks of work past it, so the warning
/// shows, the log has divid's line and calls not marked okSafeMode answer -2.
/// It goes once the tip is six blocks below block 30. -alertnotify is not run:
/// divid runs it only for a large valid fork (ForkWarningHelpers.cpp:36-41).
#[test]
fn an_invalid_chain_far_past_the_tip_shows_divids_warning() {
    let dir = tempfile::tempdir().unwrap();
    let notified = dir.path().join("alertnotify.txt");
    let extra = [format!("-alertnotify=echo %s >> {}", notified.display())];
    {
        let (_node, port) = start(dir.path(), &extra);
        ok(port, "setgenerate", json!([30]));
        let block_11 = ok(port, "getblockhash", json!([11]));
        ok(port, "invalidateblock", json!([block_11]));
        assert_eq!(ok(port, "getblockcount", json!([])), 10);
        assert_eq!(errors(port), (json!(""), json!("")));
    }
    let (node, port) = start(dir.path(), &extra);
    // Nothing is checked until a block is connected
    assert_eq!(errors(port), (json!(""), json!("")));
    ok(port, "setgenerate", json!([1]));
    assert_eq!(errors(port), (json!(WARNING), json!(WARNING)));
    let balance = rpc(port, "getbalance", json!([])).unwrap();
    assert_eq!(balance["error"]["code"], -2, "{balance}");
    assert_eq!(balance["error"]["message"], format!("Safe mode: {WARNING}"));
    // Tip 23: block 30 is seven blocks of work past it
    ok(port, "setgenerate", json!([12]));
    assert_eq!(errors(port).0, json!(WARNING));
    // Tip 24: six
    ok(port, "setgenerate", json!([1]));
    assert_eq!(errors(port), (json!(""), json!("")));
    assert!(rpc(port, "getbalance", json!([])).unwrap()["error"].is_null());
    drop(node);
    let log = std::fs::read_to_string(dir.path().join("debug.log")).unwrap();
    assert_eq!(log.matches(LOG_LINE).count(), 13, "a line at tips 11 to 23");
    assert!(!notified.exists(), "-alertnotify ran");
}

/// reconsiderblock of the first invalidated block forgets the invalid block
/// kept (ChainExtensionService.cpp:667-678); the node moves back to that chain
/// and the check that follows clears the warning
#[test]
fn reconsiderblock_clears_divids_warning() {
    let dir = tempfile::tempdir().unwrap();
    let block_11 = {
        let (_node, port) = start(dir.path(), &[]);
        ok(port, "setgenerate", json!([30]));
        let block_11 = ok(port, "getblockhash", json!([11]));
        ok(port, "invalidateblock", json!([block_11]));
        block_11
    };
    let (_node, port) = start(dir.path(), &[]);
    ok(port, "setgenerate", json!([1]));
    assert_eq!(errors(port).0, json!(WARNING));
    ok(port, "reconsiderblock", json!([block_11]));
    assert_eq!(ok(port, "getblockcount", json!([])), 30);
    assert_eq!(errors(port), (json!(""), json!("")));
}
