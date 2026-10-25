// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Wallet options divid reads, and irondivid with them: -createwalletbackups,
//! -monthlybackups, -vault_min, and -txconfirmtarget / -sendfreetransactions
//! (which divid takes and does nothing with).

#![cfg(unix)]

use divi_test_support::{free_port, log_tail};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
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

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(datadir: &Path, rpc_port: u16, p2p_port: u16, extra: &[&str]) -> Node {
    let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false", "--listen=false"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .args(extra)
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

/// Stop the node with the RPC stop and wait (bounded) until it exits
fn stop(mut node: Node, rpc_port: u16) {
    let _ = try_rpc(rpc_port, "stop", &json!([]), Duration::from_secs(30));
    let deadline = Instant::now() + Duration::from_secs(60);
    while node.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The folder named `name` somewhere under `root`
fn find_dir(root: &Path, name: &str) -> Option<PathBuf> {
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == name) {
                    return Some(path);
                }
                dirs.push(path);
            }
        }
    }
    None
}

fn entries(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

/// -createwalletbackups=<n>: the backup at start keeps n in backups/
/// (init.cpp:938, WalletBackupCreator.cpp:85-121); 0 makes none and removes
/// none
#[test]
fn createwalletbackups_sets_the_count_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    // A start that makes the wallet, then three that back it up
    stop(start(dir.path(), rpc_port, p2p_port, &[]), rpc_port);
    for i in 0..3 {
        stop(
            start(dir.path(), rpc_port, p2p_port, &["-createwalletbackups=2"]),
            rpc_port,
        );
        // A backup is named by the minute and not made again under a name
        // already there, so the new one is renamed to leave the next start
        // its name
        let backups = find_dir(dir.path(), "backups").expect("backups/");
        for entry in std::fs::read_dir(&backups).unwrap().flatten() {
            let path = entry.path();
            if !path.to_string_lossy().ends_with("-kept") {
                let mut renamed = path.clone().into_os_string();
                renamed.push(format!("-{i}-kept"));
                std::fs::rename(&path, renamed).unwrap();
            }
        }
    }
    let backups = find_dir(dir.path(), "backups").expect("backups/");
    assert_eq!(entries(&backups), 2, "two kept");
    stop(
        start(dir.path(), rpc_port, p2p_port, &["-createwalletbackups=0"]),
        rpc_port,
    );
    assert_eq!(entries(&backups), 2, "none made, none removed");
}
