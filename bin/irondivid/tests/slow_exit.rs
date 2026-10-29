// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! After SIGINT irondivid exits as soon as it has recorded its clean stop,
//! without the destructors of its state (the databases' close among them),
//! and the next start finds a clean stop and the same chain.

#![cfg(unix)]

use divi_test_support::{free_port, log_tail};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// From SIGINT to exit, at most
const EXIT_LIMIT: Duration = Duration::from_secs(30);

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
        .args(["--txindex=1", "--addressindex=1", "--spentindex=1"])
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

/// The RocksDB LOG files of the databases under `datadir` (chainstate,
/// txindex): RocksDB writes "Shutdown: canceling all background work" there
/// when a database is closed
fn database_logs(datadir: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut dirs = vec![datadir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.file_name().is_some_and(|n| n == "LOG")
                && dir
                    .file_name()
                    .is_some_and(|d| d == "chainstate" || d == "txindex")
            {
                found.push(path);
            }
        }
    }
    found
}

fn debug_log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("debug.log"))
        .or_else(|_| std::fs::read_to_string(datadir.join("regtest").join("debug.log")))
        .unwrap_or_default()
}

#[test]
fn exits_without_closing_the_databases_after_the_clean_stop() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let mut node = start(dir.path(), rpc_port, p2p_port);
    ok(rpc_port, "setgenerate", json!([120]));
    let address = ok(rpc_port, "getnewaddress", json!([]));
    ok(rpc_port, "sendtoaddress", json!([address, 1]));
    ok(rpc_port, "setgenerate", json!([1]));
    let tip = ok(rpc_port, "getbestblockhash", json!([]));
    let logs = database_logs(dir.path());
    assert_eq!(logs.len(), 2, "chainstate and txindex: {logs:?}");

    let signalled = Instant::now();
    unsafe { libc::kill(node.0.id() as libc::pid_t, libc::SIGINT) };
    let exited = loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            break Some(status);
        }
        if signalled.elapsed() > EXIT_LIMIT * 2 {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = signalled.elapsed();
    let status = exited.unwrap_or_else(|| {
        panic!(
            "irondivid still running {} s after SIGINT\n{}",
            took.as_secs(),
            log_tail(dir.path())
        )
    });
    assert!(took < EXIT_LIMIT, "exit took {} s", took.as_secs_f32());
    assert!(status.success(), "{status}");
    // Closing the databases is left out: their logs were synced before the
    // clean stop was recorded, and the close can take minutes (it frees
    // every cache page, from swap if need be)
    for path in &logs {
        let text = std::fs::read_to_string(path).unwrap();
        assert!(
            !text.contains("Shutdown: canceling all background work"),
            "{} was closed at exit",
            path.display()
        );
    }
    let log = debug_log(dir.path());
    assert!(
        log.contains("Shutdown: databases synced and the clean stop recorded"),
        "{}",
        log_tail(dir.path())
    );
    drop(node);

    // The next start finds a clean stop and the same chain, and goes on
    let before = log.len();
    let node = start(dir.path(), rpc_port, p2p_port);
    assert_eq!(ok(rpc_port, "getbestblockhash", json!([])), tip);
    let log = debug_log(dir.path());
    let restart = log.get(before..).unwrap_or(&log);
    assert!(
        !restart.contains("did not stop cleanly"),
        "{}",
        log_tail(dir.path())
    );
    ok(rpc_port, "setgenerate", json!([1]));
    drop(node);
}
