// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The A11 canary, reduced: a regtest node with a labelled address, mined
//! blocks, a payment of exactly 1.23456789 DIVI, an RPC error that names
//! the address, and failing `-walletnotify` / `-blocknotify` commands that
//! hold a canary string. Every log and diag file the node wrote is then
//! scanned for each canary; any hit fails.
//!
//! Not covered here (still owed by the full §10 item 5 canary): a stake,
//! a masternode collateral, rescan, lock and unlock, a panic in a
//! supervised task, a crash, and the diag package.

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const LABEL: &str = "CANARY-LABEL-7f3e";
const NOTIFY: &str = "CANARY-NOTIFY-5c1d";

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

fn start(dir: &Path) -> (Node, u16) {
    let (child, rpc_port, _) = start_node(
        dir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("-regtest")
                .arg(format!("-datadir={}", dir.display()))
                .arg(format!("-rpcport={rpc_port}"))
                .arg(format!("-port={p2p_port}"))
                .arg(format!("-walletnotify=false {NOTIFY}-w-%s"))
                .arg(format!("-blocknotify=false {NOTIFY}-b-%s"))
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

/// Every file the node writes as text: logs, `diag/`, start-up records.
/// A database directory (one holding RocksDB's `CURRENT`) is the wallet or
/// the chain itself, whose `*.log` files are its write-ahead logs, not text.
fn written(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        if d.join("CURRENT").is_file() {
            continue;
        }
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                todo.push(p);
                continue;
            }
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let in_diag = p
                .strip_prefix(dir)
                .unwrap()
                .components()
                .any(|c| c.as_os_str() == "diag");
            if in_diag || name.contains(".log") || name.ends_with(".txt") || name.ends_with(".tail")
            {
                out.push(p);
            }
        }
    }
    out
}

/// A txid as RPC shows it and in byte order
fn both_orders(hex: &str) -> [String; 2] {
    let bytes: Vec<&str> = (0..hex.len()).step_by(2).map(|i| &hex[i..i + 2]).collect();
    [hex.to_string(), bytes.into_iter().rev().collect()]
}

#[test]
fn no_wallet_value_or_notify_command_reaches_a_log() {
    let dir = tempfile::tempdir().unwrap();
    let (node, port) = start(dir.path());
    let addr = ok(port, "getnewaddress", json!([LABEL]));
    let addr = addr.as_str().unwrap().to_string();
    ok(port, "setgenerate", json!([101]));
    let txid = ok(port, "sendtoaddress", json!([addr, 1.23456789]));
    let txid = txid.as_str().unwrap().to_string();
    ok(port, "setgenerate", json!([1]));
    // An RPC error that names the address
    let reply = rpc(port, "sendtoaddress", json!([addr, 90_000_000_000.0])).unwrap();
    assert!(!reply["error"].is_null(), "{reply}");
    ok(port, "stop", json!([]));
    drop(node);

    let mut canaries = vec![
        LABEL.to_string(),
        NOTIFY.to_string(),
        addr.clone(),
        "1.23456789".to_string(),
        "123456789".to_string(),
    ];
    canaries.extend(both_orders(&txid));

    let files = written(dir.path());
    let mut notify_lines = 0;
    let mut hits = Vec::new();
    for f in &files {
        let text = String::from_utf8_lossy(&std::fs::read(f).unwrap()).into_owned();
        notify_lines += text.matches("runCommand error: walletnotify (").count();
        for c in &canaries {
            for line in text.lines().filter(|l| l.contains(c.as_str())) {
                hits.push(format!("{}: {c}: {line}", f.display()));
            }
        }
    }
    assert!(
        files.iter().any(|f| f.ends_with("debug.log")),
        "no debug.log among {files:?}"
    );
    // The failing command ran and was logged by its kind
    assert!(notify_lines > 0, "no walletnotify line in {files:?}");
    assert!(hits.is_empty(), "canaries found:\n{}", hits.join("\n"));
}
