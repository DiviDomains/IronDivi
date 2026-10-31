// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A lost console never changes how irondivid stops: a stop signal still
//! stops the node when stderr is gone (D1), and -version still exits 1 when
//! stdout is gone (D2). Before, the console write panicked: the signal task
//! died, or -version exited 101.

#![cfg(unix)]

use divi_test_support::{free_port, log_tail};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// From SIGTERM to exit, at most
const EXIT_LIMIT: Duration = Duration::from_secs(60);

/// POST one JSON-RPC call; None while the server is not up
fn try_rpc(port: u16, method: &str, timeout: Duration) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": []}).to_string();
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

fn debug_log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("debug.log"))
        .or_else(|_| std::fs::read_to_string(datadir.join("regtest").join("debug.log")))
        .unwrap_or_default()
}

#[test]
fn sigterm_stops_the_node_when_stderr_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(dir.path())
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false", "--listen=false"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irondivid");
    let mut node = Node(child);
    let deadline = Instant::now() + Duration::from_secs(120);
    while try_rpc(rpc_port, "getblockcount", Duration::from_secs(10)).is_none() {
        if let Ok(Some(status)) = node.0.try_wait() {
            panic!("irondivid exited at start: {status}\n{}", log_tail(dir.path()));
        }
        assert!(Instant::now() < deadline, "irondivid did not answer within 120 s");
        std::thread::sleep(Duration::from_millis(250));
    }
    // The terminal goes away: the next console line meets EPIPE
    drop(node.0.stderr.take());

    let signalled = Instant::now();
    unsafe { libc::kill(node.0.id() as libc::pid_t, libc::SIGTERM) };
    let status = loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            signalled.elapsed() < EXIT_LIMIT,
            "irondivid did not stop within {EXIT_LIMIT:?} of SIGTERM with stderr gone\n{}",
            log_tail(dir.path())
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let log = debug_log(dir.path());
    assert_eq!(status.code(), Some(0), "{status}\n{}", log_tail(dir.path()));
    assert!(
        log.contains("stderr lost:"),
        "the lost console is noted in debug.log\n{}",
        log_tail(dir.path())
    );
    assert!(log.contains("Received SIGTERM, initiating shutdown"), "{}", log_tail(dir.path()));
}

#[test]
fn version_exits_1_when_stdout_is_gone() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("-version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irondivid");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("wait for irondivid");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
