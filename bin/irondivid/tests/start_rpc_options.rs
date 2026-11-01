// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The start and RPC options divid acts on: -forcestart, -sysperms,
//! -rpcthreads, -alerts and -alertnotify.

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One JSON-RPC call with test:test; None until the server is up
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

fn result(port: u16, method: &str, params: Value) -> Value {
    let reply = rpc(port, method, params).unwrap_or_else(|| panic!("{method}: no reply"));
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

struct Node {
    child: Child,
    rpc_port: u16,
    p2p_port: u16,
}

impl Node {
    fn stop(mut self) {
        let _ = rpc(self.rpc_port, "stop", json!([]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// divid's form of the options for a regtest node, then `extra`
fn command(datadir: &Path, rpc_port: u16, p2p_port: u16, extra: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg("-regtest")
        .arg(format!("-datadir={}", datadir.display()))
        .arg(format!("-rpcport={rpc_port}"))
        .arg(format!("-port={p2p_port}"))
        .args(["-bind=127.0.0.1", "-listen=1", "-staking=0"])
        .args(["-connect=127.0.0.1:1", "-dnsseed=0"])
        .args(["-rpcuser=test", "-rpcpassword=test"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

fn start(datadir: &Path, extra: &[&str]) -> Node {
    let (child, rpc_port, p2p_port) = start_node(
        datadir,
        |rpc_port, p2p_port| command(datadir, rpc_port, p2p_port, extra),
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    Node {
        child,
        rpc_port,
        p2p_port,
    }
}

fn debug_log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("regtest").join("debug.log"))
        .or_else(|_| std::fs::read_to_string(datadir.join("debug.log")))
        .unwrap_or_default()
}

/// -forcestart: divid skips its block and coin database checks after a stop
/// that was not prepared (BlockIndexLoading.cpp:267-285). irondivid has no
/// such check to skip: after a kill it starts at its last whole block, and
/// takes the option without calling it unsupported.
#[test]
fn forcestart_is_taken_and_a_killed_node_starts_at_its_last_block() {
    let dir = tempfile::tempdir().unwrap();
    let node = start(dir.path(), &[]);
    result(node.rpc_port, "setgenerate", json!([12]));
    node.kill();
    let node = start(dir.path(), &["-forcestart"]);
    assert_eq!(result(node.rpc_port, "getblockcount", json!([])), json!(12));
    node.stop();
    let log = debug_log(dir.path());
    assert!(
        !log.contains("Option -forcestart is not supported"),
        "-forcestart called unsupported"
    );
}

/// The modes of the files and directories under `dir`
fn modes(dir: &Path) -> (Vec<u32>, Vec<u32>) {
    use std::os::unix::fs::PermissionsExt;
    let (mut files, mut dirs) = (Vec::new(), Vec::new());
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let meta = std::fs::symlink_metadata(entry.path()).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            if meta.is_dir() {
                dirs.push(mode);
                todo.push(entry.path());
            } else if meta.is_file() {
                files.push(mode);
            }
        }
    }
    files.sort();
    files.dedup();
    dirs.sort();
    dirs.dedup();
    (files, dirs)
}

/// Start under umask 022 with `extra`, stop, and give the modes made
fn modes_made(extra: &[&str]) -> (Vec<u32>, Vec<u32>) {
    use std::os::unix::process::CommandExt;
    let dir = tempfile::tempdir().unwrap();
    let (child, rpc_port, p2p_port) = start_node(
        dir.path(),
        |rpc_port, p2p_port| {
            let mut cmd = command(dir.path(), rpc_port, p2p_port, extra);
            // SAFETY: umask(2) in the child before exec
            unsafe {
                cmd.pre_exec(|| {
                    libc::umask(0o022);
                    Ok(())
                });
            }
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    Node {
        child,
        rpc_port,
        p2p_port,
    }
    .stop();
    modes(dir.path())
}

/// -sysperms: divid sets umask 077 unless it is given, and refuses it with
/// the wallet on (init.cpp:1378-1385)
#[test]
fn files_are_private_unless_sysperms_with_the_wallet_off() {
    assert_eq!(modes_made(&[]), (vec![0o600], vec![0o700]));
    assert_eq!(modes_made(&["-disablewallet"]), (vec![0o600], vec![0o700]));
    // -sysperms with the wallet off is taken, but irondivid makes its files
    // private whatever the umask (private_files), so they stay 0600/0700
    let (files, dirs) = modes_made(&["-sysperms", "-disablewallet"]);
    assert_eq!((files, dirs), (vec![0o600], vec![0o700]));

    let dir = tempfile::tempdir().unwrap();
    let out = command(dir.path(), 1, 1, &["-sysperms"])
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(
            "Error: Error: -sysperms is not allowed in combination with enabled wallet functionality"
        ),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A getblockcount on `stream`, kept alive: whether it is answered within `secs`
fn answered(stream: &mut TcpStream, secs: u64, send: bool) -> bool {
    if send {
        let body = r#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        if stream.write_all(request.as_bytes()).is_err() {
            return false;
        }
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(secs)))
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(&got).contains("\"result\"") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return false,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    true
}

/// -rpcthreads: divid serves each connection on one of its N threads to the
/// end, so connection N+1 waits until one closes, and with 0 none is served
/// (rpcserver.cpp:755-757, :1000-1010)
#[test]
fn rpcthreads_is_how_many_connections_are_served_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let node = start(dir.path(), &["-rpcthreads=2"]);
    let connect = || TcpStream::connect(("127.0.0.1", node.rpc_port)).unwrap();
    let (mut first, mut second, mut third) = (connect(), connect(), connect());
    assert!(answered(&mut first, 10, true));
    assert!(answered(&mut second, 10, true));
    assert!(!answered(&mut third, 3, true), "a third connection served");
    drop(first);
    assert!(
        answered(&mut third, 10, false),
        "not served once one closed"
    );
    drop((second, third));
    node.stop();

    // With 0 the node runs and serves no call
    let dir = tempfile::tempdir().unwrap();
    let port = divi_test_support::free_port();
    let mut child = command(
        dir.path(),
        port,
        divi_test_support::free_port(),
        &["-rpcthreads=0"],
    )
    .spawn()
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    while !debug_log(dir.path()).contains("Starting RPC server on") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_secs(2));
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert!(
        !answered(&mut stream, 3, true),
        "a call served with -rpcthreads=0"
    );
    assert!(child.try_wait().unwrap().is_none(), "the node stopped");
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

const REGTEST_MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];
const AGENT: &str = "/start-rpc-options-test:1/";

fn message(cmd: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = REGTEST_MAGIC.to_vec();
    let mut name = [0u8; 12];
    name[..cmd.len()].copy_from_slice(cmd.as_bytes());
    out.extend_from_slice(&name);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&divi_crypto::double_sha256(payload)[..4]);
    out.extend_from_slice(payload);
    out
}

fn net_addr(port: u16) -> Vec<u8> {
    let mut out = 1u64.to_le_bytes().to_vec();
    out.extend_from_slice(&[0u8; 10]);
    out.extend_from_slice(&[0xff, 0xff, 127, 0, 0, 1]);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A raw peer that has sent its version and verack
fn raw_peer(p2p_port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", p2p_port)).unwrap();
    let mut payload = Vec::new();
    payload.extend_from_slice(&70920i32.to_le_bytes());
    payload.extend_from_slice(&1u64.to_le_bytes());
    payload.extend_from_slice(&now().to_le_bytes());
    payload.extend_from_slice(&net_addr(p2p_port));
    payload.extend_from_slice(&net_addr(0));
    payload.extend_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
    payload.push(AGENT.len() as u8);
    payload.extend_from_slice(AGENT.as_bytes());
    payload.extend_from_slice(&0i32.to_le_bytes());
    payload.push(1);
    stream.write_all(&message("version", &payload)).unwrap();
    stream.write_all(&message("verack", &[])).unwrap();
    stream
}

/// An alert in effect for an hour, for every version, whose signature is not
/// the alert key's
fn bad_alert() -> Vec<u8> {
    let mut unsigned = Vec::new();
    unsigned.extend_from_slice(&1i32.to_le_bytes());
    unsigned.extend_from_slice(&(now() + 3600).to_le_bytes());
    unsigned.extend_from_slice(&(now() + 3600).to_le_bytes());
    unsigned.extend_from_slice(&1234i32.to_le_bytes());
    unsigned.extend_from_slice(&0i32.to_le_bytes());
    unsigned.push(0);
    unsigned.extend_from_slice(&0i32.to_le_bytes());
    unsigned.extend_from_slice(&999_999i32.to_le_bytes());
    unsigned.push(0);
    unsigned.extend_from_slice(&1i32.to_le_bytes());
    unsigned.extend_from_slice(&[0, 10]);
    unsigned.extend_from_slice(b"test alert");
    unsigned.push(0);
    let mut signature = vec![0x30, 0x44, 0x02, 0x20, 0x00];
    signature.extend_from_slice(&[0x11; 31]);
    signature.extend_from_slice(&[0x02, 0x20, 0x00]);
    signature.extend_from_slice(&[0x22; 31]);
    let mut out = vec![unsigned.len() as u8];
    out.extend_from_slice(&unsigned);
    out.push(signature.len() as u8);
    out.extend_from_slice(&signature);
    out
}

/// The ban score of the raw peer, once the node lists it
fn raw_peer_banscore(rpc_port: u16) -> Option<i64> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let peers = result(rpc_port, "getpeerinfo", json!([]));
        if let Some(p) = peers
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["subver"] == json!(AGENT))
        {
            return p["banscore"].as_i64();
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

/// -alerts: divid reads a peer's alert unless -alerts=0, and scores 10 for one
/// it cannot process, here a bad signature (main.cpp:870-890)
#[test]
fn a_bad_alert_scores_unless_alerts_are_off() {
    for (extra, score) in [(&[][..], 10), (&["-alerts=0"][..], 0)] {
        let dir = tempfile::tempdir().unwrap();
        let node = start(dir.path(), extra);
        let mut peer = raw_peer(node.p2p_port);
        assert_eq!(raw_peer_banscore(node.rpc_port), Some(0), "{extra:?}");
        peer.write_all(&message("alert", &bad_alert())).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(raw_peer_banscore(node.rpc_port), Some(score), "{extra:?}");
        drop(peer);
        node.stop();
    }
}

/// `count` proof-of-work blocks of `version` on genesis, each paying nothing
fn blocks_of_version(genesis: &str, count: u32, version: i32) -> Vec<Vec<u8>> {
    use divi_primitives::amount::Amount;
    use divi_primitives::block::Block;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::{Transaction, TxIn, TxOut};
    let mut prev = Hash256::from_hex(genesis).unwrap();
    let start = now() as u32 - count - 60;
    (1..=count)
        .map(|height| {
            let mut sig = divi_storage::bip34_height_script(height);
            sig.extend_from_slice(&[0, 0]);
            let coinbase = Transaction {
                version: 1,
                vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
                vout: vec![TxOut::new(
                    Amount::from_sat(0),
                    Script::from_bytes(vec![0x51]),
                )],
                lock_time: 0,
            };
            let mut block = Block::default();
            block.header.version = version;
            block.header.prev_block = prev;
            block.header.time = start + height;
            block.header.bits = 0x207fffff;
            block.transactions = vec![coinbase];
            block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
            let target = Hash256::from_compact(block.header.bits);
            while divi_crypto::compute_block_hash(&block.header) > target {
                block.header.nonce += 1;
            }
            prev = divi_crypto::compute_block_hash(&block.header);
            divi_primitives::serialize::serialize(&block)
        })
        .collect()
}

/// -alertnotify: more than 50 of the last 100 blocks above version 4 set
/// divid's warning "Warning: This version is obsolete, upgrade required!",
/// shown as getinfo's errors, and run the command with the text kept to safe
/// characters and quoted (ChainTipManager.cpp:43-60, alert.cpp:218-235)
#[test]
fn newer_blocks_raise_the_obsolete_version_warning_and_alertnotify() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("alert-marker");
    let notify = format!("-alertnotify=echo %s > {}", marker.display());
    let node = start(dir.path(), &[&notify]);
    let genesis = result(node.rpc_port, "getblockhash", json!([0]));
    let mut peer = raw_peer(node.p2p_port);
    for block in blocks_of_version(genesis.as_str().unwrap(), 52, 5) {
        peer.write_all(&message("block", &block)).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while result(node.rpc_port, "getblockcount", json!([])) != json!(52) {
        assert!(Instant::now() < deadline, "the blocks were not taken");
        std::thread::sleep(Duration::from_millis(200));
    }
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        std::fs::read_to_string(&marker).ok().as_deref(),
        Some("Warning: This version is obsolete, upgrade required\n")
    );
    assert_eq!(
        result(node.rpc_port, "getinfo", json!([]))["errors"],
        json!("Warning: This version is obsolete, upgrade required!")
    );
    drop(peer);
    node.stop();
}
