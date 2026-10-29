// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Start-up behaviour where irondivid knowingly differs from Divi Core
//! 3.0.0's divid. Each test pins one row of docs/divid-differences.md.

#![cfg(unix)]

use divi_test_support::{free_port, start_node};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One JSON-RPC call on 127.0.0.1 with test:test; None until the server is up
fn rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
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

/// divid's form of the options for a regtest node on `rpc_port` and `p2p_port`
fn args(datadir: &Path, rpc_port: u16, p2p_port: u16) -> Vec<String> {
    vec![
        "-regtest".into(),
        format!("-datadir={}", datadir.display()),
        format!("-rpcport={rpc_port}"),
        format!("-port={p2p_port}"),
        "-bind=127.0.0.1".into(),
        "-rpcuser=test".into(),
        "-rpcpassword=test".into(),
    ]
}

fn debug_log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("regtest").join("debug.log"))
        .or_else(|_| std::fs::read_to_string(datadir.join("debug.log")))
        .unwrap_or_default()
}

/// divid keeps every option it does not know and says nothing
/// (Settings.cpp:130-150). irondivid starts too, but names the option in the
/// log; an option divid has and irondivid does not use is named as such.
#[test]
fn unknown_and_unsupported_options_start_with_a_log_line() {
    let dir = tempfile::tempdir().unwrap();
    let (child, _, _) = start_node(
        dir.path(),
        |rpc_port, p2p_port| {
            let mut a = args(dir.path(), rpc_port, p2p_port);
            a.push("-bogusflag=1".into());
            a.push("-dbcache=100".into());
            a.push("-alertnotify=echo %s".into());
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.args(&a).stdout(Stdio::null()).stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    let _node = Node(child);
    let log = debug_log(dir.path());
    assert!(
        log.contains("Unknown option -bogusflag; ignored"),
        "no line for the unknown option"
    );
    assert!(
        log.contains("Option -dbcache is not supported by irondivid; ignored"),
        "no line for the unsupported option"
    );
    assert!(
        log.contains("Option -alertnotify is not supported by irondivid; ignored"),
        "no line for -alertnotify"
    );
}

/// divid runs as the masternode named by -masternode=<alias> from
/// masternode.conf (MasternodeModule.cpp:163-190); irondivid does not run as
/// a masternode and refuses to start, naming the line to remove
#[test]
fn masternode_option_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let mut a = args(dir.path(), rpc_port, p2p_port);
    a.push("-masternode=mn1".into());
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .args(&a)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("irondivid kept running with -masternode");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(!status.success());
    let mut text = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    text.push_str(&debug_log(dir.path()));
    assert!(
        text.contains("irondivid does not run as a masternode"),
        "{text}"
    );
}

/// An unknown option given as `-no<name>` is named as it was written
#[test]
fn negated_unknown_option_is_named_as_written() {
    let dir = tempfile::tempdir().unwrap();
    let (child, _, _) = start_node(
        dir.path(),
        |rpc_port, p2p_port| {
            let mut a = args(dir.path(), rpc_port, p2p_port);
            a.push("-nobogusflag".into());
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.args(&a).stdout(Stdio::null()).stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    let _node = Node(child);
    let log = debug_log(dir.path());
    assert!(
        log.contains("Unknown option -nobogusflag; ignored"),
        "no line naming -nobogusflag"
    );
}
