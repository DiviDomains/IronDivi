// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The divid options no other script compared, as divid takes them
//! (scripts/options-left).

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// One JSON-RPC call on 127.0.0.1 with test:test; None until the server is up
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

/// The arguments every node here starts with
fn base_args(datadir: &Path) -> Vec<String> {
    vec![
        "-regtest".to_string(),
        format!("-datadir={}", datadir.display()),
        "-bind=127.0.0.1".into(),
        "-rpcuser=test".into(),
        "-rpcpassword=test".into(),
        "-staking=0".into(),
        "-connect=127.0.0.1:1".into(),
    ]
}

/// A regtest irondivid on `datadir` with `extra`, once its RPC answers
fn start(datadir: &Path, extra: &[String]) -> (Node, u16) {
    let (child, rpc_port, _) = start_node(
        datadir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.args(base_args(datadir))
                .args([format!("-rpcport={rpc_port}"), format!("-port={p2p_port}")])
                .args(extra)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    (Node(child), rpc_port)
}

/// A start with `extra` that is expected to end by itself, within 120 s
fn run_to_exit(datadir: &Path, extra: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .args(base_args(datadir))
        .args(["-rpcport=1".to_string(), "-port=1".to_string()])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("irondivid did not exit within 120 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child.wait_with_output().unwrap()
}

/// The lines of stderr that report an error
fn errors(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.starts_with("Error"))
        .map(String::from)
        .collect()
}

/// -socks given at all, and a true -tor, stop the start with divid's error
/// (init.cpp:775-781); -tor=0 starts
#[test]
fn socks_and_a_true_tor_are_refused_as_divid_refuses_them() {
    let socks = "Error: Error: Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported.";
    let tor = "Error: Error: Unsupported argument -tor found, use -onion.";
    for (arg, line) in [
        ("-socks=5", socks),
        ("-socks=0", socks),
        ("-socks", socks),
        ("-tor", tor),
        ("-tor=1", tor),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let out = run_to_exit(dir.path(), &[arg.to_string()]);
        assert_eq!(errors(&out), [line], "{arg}");
        assert_eq!(out.status.code(), Some(1), "{arg}");
    }
    let dir = tempfile::tempdir().unwrap();
    let (_node, port) = start(dir.path(), &["-tor=0".into()]);
    assert!(rpc(port, "getblockcount", json!([])).is_some());
}
