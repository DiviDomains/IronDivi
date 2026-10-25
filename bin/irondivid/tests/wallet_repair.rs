// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A wallet with a record that cannot be read, and -salvagewallet, as Divi
//! Core 3.0.0 starts with them: a key stops the start, anything else is a
//! warning (and a transaction a rescan) unless -dbloadfailexit
//! (walletdb.cpp:495-511, init.cpp:1143-1177, :1296-1310, :763-766).
//! Every wait is bounded.

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

const WARNING: &str = "Warning: Warning: error reading wallet.dat! All keys read correctly, but transaction data or address book entries might be missing or incorrect.";

/// A regtest node's wallet folder
fn wallet_dir(datadir: &Path) -> std::path::PathBuf {
    datadir.join("wallet")
}

/// Write `value` under `key` in the column family `cf` of the stopped node's
/// wallet: a record its code cannot read
fn damage(datadir: &Path, cf: &str, key: &[u8], value: &[u8]) {
    let path = wallet_dir(datadir);
    let opts = rocksdb::Options::default();
    let cfs = rocksdb::DB::list_cf(&opts, &path).expect("column families");
    let db = rocksdb::DB::open_cf(&opts, &path, &cfs).expect("open the wallet");
    let handle = db.cf_handle(cf).expect("column family");
    db.put_cf(handle, key, value).expect("write");
}

/// The first key in `cf` of the stopped node's wallet whose length is `len`
fn some_key(datadir: &Path, cf: &str, len: usize) -> Vec<u8> {
    let path = wallet_dir(datadir);
    let opts = rocksdb::Options::default();
    let cfs = rocksdb::DB::list_cf(&opts, &path).expect("column families");
    let db = rocksdb::DB::open_cf(&opts, &path, &cfs).expect("open the wallet");
    let handle = db.cf_handle(cf).expect("column family");
    let found = db
        .iterator_cf(handle, rocksdb::IteratorMode::Start)
        .map(|item| item.unwrap().0.to_vec())
        .find(|k| k.len() == len);
    found.unwrap_or_else(|| panic!("no key of {len} bytes in {cf}"))
}

/// A node made and stopped, with `blocks` mined
fn made(datadir: &Path, rpc_port: u16, p2p_port: u16, blocks: u32) {
    let n = start(datadir, rpc_port, p2p_port, &[]);
    if blocks > 0 {
        ok(rpc_port, "setgenerate", json!([blocks]));
    }
    stop(n, rpc_port);
}

/// Run the node to its exit (bounded), as a refused start does: its exit code
/// and stderr
fn run_to_exit(
    datadir: &Path,
    rpc_port: u16,
    p2p_port: u16,
    extra: &[&str],
) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false", "--listen=false"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("irondivid did not exit within 120 s\n{}", log_tail(datadir));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The node's stderr while it runs, read after it stopped
fn start_with_stderr(
    datadir: &Path,
    rpc_port: u16,
    p2p_port: u16,
    extra: &[&str],
) -> (Child, std::path::PathBuf) {
    let err = datadir.join("stderr.txt");
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
        .stderr(std::fs::File::create(&err).unwrap())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(120);
    while try_rpc(
        rpc_port,
        "getblockcount",
        &json!([]),
        Duration::from_secs(10),
    )
    .is_none()
    {
        assert!(
            Instant::now() < deadline,
            "irondivid did not answer\n{}",
            log_tail(datadir)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    (child, err)
}

fn log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("debug.log")).unwrap_or_default()
}

/// A key record that cannot be read stops the start: exit 1 and Divi Core's
/// InitError (DB_CORRUPT, walletdb.cpp:499-500, init.cpp:1153-1156)
#[test]
fn an_unreadable_key_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    made(dir.path(), rpc_port, p2p_port, 0);
    damage(dir.path(), "wallet_keys", &[7u8; 20], &[0xff, 0x00, 0x01]);
    let (code, stderr) = run_to_exit(dir.path(), rpc_port, p2p_port, &[]);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("Error: Error loading wallet.dat: Wallet corrupted"),
        "stderr: {stderr}"
    );
}

/// An address-book record that cannot be read: a warning on stderr, and the
/// node starts (DB_NONCRITICAL_ERROR, init.cpp:1157-1162, :1307)
#[test]
fn an_unreadable_address_book_entry_is_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    made(dir.path(), rpc_port, p2p_port, 0);
    damage(dir.path(), "wallet_accounts", b"acc_damaged", b"{not json");
    let (child, err) = start_with_stderr(dir.path(), rpc_port, p2p_port, &[]);
    let node = Node(child);
    assert!(ok(rpc_port, "getwalletinfo", json!([])).is_object());
    stop(node, rpc_port);
    let stderr = std::fs::read_to_string(err).unwrap();
    assert!(stderr.contains(WARNING), "stderr: {stderr}");
    assert!(log(dir.path()).contains("Errors detected during wallet loading"));
}

/// A transaction record that cannot be read: the warning, and the chain is
/// scanned again so the transaction comes back (walletdb.cpp:505-508); not
/// with -rescan=0, which is given
#[test]
fn an_unreadable_transaction_is_found_again_by_a_rescan() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    made(dir.path(), rpc_port, p2p_port, 3);
    let txid = some_key(dir.path(), "wallet_transactions", 32);
    damage(dir.path(), "wallet_transactions", &txid, &[0xff; 5]);
    let from = log(dir.path()).len();
    let (child, err) = start_with_stderr(dir.path(), rpc_port, p2p_port, &[]);
    let node = Node(child);
    let deadline = Instant::now() + Duration::from_secs(60);
    while ok(rpc_port, "listtransactions", json!(["*", 100]))
        .as_array()
        .map_or(0, |l| l.len())
        < 3
    {
        assert!(
            Instant::now() < deadline,
            "the transaction did not come back"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    stop(node, rpc_port);
    assert!(std::fs::read_to_string(err).unwrap().contains(WARNING));
    assert!(
        log(dir.path())[from..].contains("Rescanning... from height 0"),
        "{}",
        log_tail(dir.path())
    );

    // With -rescan=0 given, no rescan
    let txid = some_key(dir.path(), "wallet_transactions", 32);
    damage(dir.path(), "wallet_transactions", &txid, &[0xff; 5]);
    let from = log(dir.path()).len();
    let node = start(dir.path(), rpc_port, p2p_port, &["-rescan=0"]);
    stop(node, rpc_port);
    assert!(!log(dir.path())[from..].contains("Rescanning... from height 0"));
}

/// -dbloadfailexit=1: a wallet that loads with the warning stops the start,
/// exit 1 and no error line (init.cpp:1307-1309)
#[test]
fn dbloadfailexit_stops_a_start_with_the_warning() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc_port, p2p_port) = (free_port(), free_port());
    made(dir.path(), rpc_port, p2p_port, 0);
    damage(dir.path(), "wallet_accounts", b"acc_damaged", b"{not json");
    let (code, stderr) = run_to_exit(dir.path(), rpc_port, p2p_port, &["-dbloadfailexit=1"]);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains(WARNING), "stderr: {stderr}");
    assert!(!stderr.contains("Error:"), "stderr: {stderr}");
}
