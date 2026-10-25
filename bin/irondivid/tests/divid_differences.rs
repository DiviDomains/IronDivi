// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
    // -alertnotify is taken: irondivid runs it for its own warning
    // (start_rpc_options.rs), so it is not named as unsupported
}

/// Start irondivid with `extra` and masternode.conf `conf`; its exit status
/// and what it printed (stderr, stdout, log)
fn start_and_stop(extra: &[&str], conf: &str) -> (std::process::ExitStatus, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("masternode.conf"), conf).unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    let mut a = args(dir.path(), rpc_port, p2p_port);
    a.extend(extra.iter().map(|s| s.to_string()));
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
            panic!("irondivid kept running with {extra:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
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
    (status, text)
}

/// -masternode=<alias> goes through divid's checks first
/// (MasternodeModule.cpp:163-240): with no masternode.conf entry for the alias
/// irondivid stops with divid's text. With a valid entry divid runs as that
/// masternode; irondivid does not run as one and refuses to start, naming
/// the line to remove.
#[test]
fn masternode_option_is_refused() {
    let (status, text) = start_and_stop(&["-masternode=mn1"], "");
    assert!(!status.success());
    assert!(
        text.contains("Unknown masternode configuration for masternode=<alias>."),
        "{text}"
    );

    // A throwaway regtest key made for this test only (test fixture)
    let key = divi_crypto::keys::SecretKey::new_random();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(key.as_bytes());
    let wif = divi_wallet::encode_wif(&bytes, true, divi_wallet::Network::Regtest);
    let conf = format!("mn1 127.0.0.1:1 {wif} {} 0\n", "11".repeat(32));
    let (status, text) = start_and_stop(&["-masternode=mn1"], &conf);
    assert!(!status.success());
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
