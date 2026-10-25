// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The start options that load blocks or check the chain, as divid logs and
//! takes them (scripts/chain-load-options).

#![cfg(unix)]

use divi_test_support::start_node;
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

/// A regtest irondivid on `datadir` with `extra`, once its RPC answers
fn start(datadir: &Path, extra: &[String]) -> (Node, u16) {
    let (child, rpc_port, _) = start_node(
        datadir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.args([
                "-regtest".to_string(),
                format!("-datadir={}", datadir.display()),
                format!("-rpcport={rpc_port}"),
                format!("-port={p2p_port}"),
                "-bind=127.0.0.1".into(),
                "-rpcuser=test".into(),
                "-rpcpassword=test".into(),
                "-staking=0".into(),
                "-connect=127.0.0.1:1".into(),
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

fn debug_log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("debug.log"))
        .or_else(|_| std::fs::read_to_string(datadir.join("regtest").join("debug.log")))
        .unwrap_or_default()
}

/// Wait (bounded) until the log holds `text`
fn log_has(datadir: &Path, text: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if debug_log(datadir).contains(text) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// A -loadblock file that does not open is named in divid's warning and
/// never as being imported (init.cpp:715-722)
#[test]
fn a_loadblock_file_that_does_not_open_is_named_in_divid_s_warning() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such-file.dat");
    let (_node, _) = start(dir.path(), &[format!("-loadblock={}", missing.display())]);
    let line = format!("Warning: Could not open blocks file {}", missing.display());
    assert!(log_has(dir.path(), &line), "no line {line:?}");
    assert!(
        !debug_log(dir.path()).contains(&format!("Importing blocks file {}", missing.display())),
        "a missing file named as imported"
    );
}

/// The chain check at start and verifychain log divid's line, with divid's
/// depth: -checkblocks or the verifychain depth, 0 or below every block, more
/// than the height the height (verifyDb.cpp:73-78)
#[test]
fn the_chain_check_logs_divid_s_verifying_line() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (_node, port) = start(dir.path(), &[]);
        let mined = rpc(port, "setgenerate", json!([3])).expect("setgenerate");
        assert!(mined["error"].is_null(), "{mined}");
        assert_eq!(rpc(port, "getblockcount", json!([])).unwrap()["result"], 3);
    }
    for (depth, line) in [
        ("2", "Verifying last 2 blocks at level 4"),
        ("0", "Verifying last 3 blocks at level 4"),
    ] {
        std::fs::remove_file(dir.path().join("debug.log")).ok();
        let (_node, port) = start(dir.path(), &[format!("-checkblocks={depth}")]);
        assert!(
            log_has(dir.path(), line),
            "-checkblocks={depth}: no {line:?}"
        );
        if depth == "0" {
            let reply = rpc(port, "verifychain", json!([4, 1])).unwrap();
            assert_eq!(reply["result"], true, "{reply}");
            assert!(log_has(dir.path(), "Verifying last 1 blocks at level 4"));
            let reply = rpc(port, "verifychain", json!([4, 99])).unwrap();
            assert_eq!(reply["result"], true, "{reply}");
            assert_eq!(
                debug_log(dir.path())
                    .matches("Verifying last 3 blocks at level 4")
                    .count(),
                2
            );
        }
    }
}

/// -checkpoints is only in divid's help (LicenseAndInfo.cpp:165): taken
/// without a line, as divid takes it
#[test]
fn checkpoints_is_taken_without_a_line() {
    let dir = tempfile::tempdir().unwrap();
    let (_node, _) = start(
        dir.path(),
        &["-checkpoints=0".into(), "-bogusmarker=1".into()],
    );
    // the unknown option's line shows the warnings were written
    assert!(log_has(dir.path(), "Unknown option -bogusmarker; ignored"));
    assert!(
        !debug_log(dir.path()).contains("-checkpoints"),
        "a line for -checkpoints"
    );
}

/// -reindex ends with divid's line once the indexes are built again (init.cpp:681)
#[test]
fn reindex_logs_reindexing_finished() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (_node, _) = start(dir.path(), &[]);
    }
    let (_node, _) = start(dir.path(), &["-reindex".into()]);
    assert!(
        log_has(dir.path(), "Reindexing finished"),
        "no Reindexing finished"
    );
}
