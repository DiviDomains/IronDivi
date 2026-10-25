// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The options that decide which peers a node talks to, as divid takes them
//! (net.cpp:757-762, :1214-1285, :1672-1716, :1803-1828). Every node and peer
//! here is on 127.0.0.x.

#![cfg(unix)]

use divi_test_support::free_port;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// POST one JSON-RPC call; None while the server is not up.
/// "dGVzdDp0ZXN0" is base64 of test:test
fn try_rpc(port: u16, method: &str, params: &Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
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

struct Node {
    child: Child,
    port: u16,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = try_rpc(self.port, "stop", &json!([]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start a regtest irondivid with only `extra` for its peers and listening
/// (each test binds 127.0.0.x itself or does not listen); Err(stderr) when it exits
fn start(datadir: &Path, extra: &[&str]) -> Result<Node, String> {
    let port = free_port();
    let stderr = datadir.join("stderr.txt");
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &port.to_string()])
        .args(["--staking=false", "-listenonion=0"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if child.try_wait().unwrap().is_some() {
            return Err(std::fs::read_to_string(&stderr).unwrap_or_default());
        }
        if try_rpc(port, "getblockcount", &json!([])).is_some() {
            return Ok(Node { child, port });
        }
        assert!(Instant::now() < deadline, "irondivid did not start");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn up(datadir: &Path, extra: &[&str]) -> Node {
    start(datadir, extra).unwrap_or_else(|e| panic!("{extra:?}: {e}"))
}

fn wait_until(mut done: impl FnMut() -> bool, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    done()
}

/// A listener on `ip` a node may dial, and its address
fn target(ip: &str) -> (TcpListener, String) {
    let listener = TcpListener::bind(format!("{ip}:0")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let at = format!("{ip}:{}", listener.local_addr().unwrap().port());
    (listener, at)
}

/// divid dials every added node, with -connect or not and whatever
/// -maxconnections says: its added-node thread takes no outbound slot since
/// Divi Core f8c0d2e67 (net.cpp:1214-1271, :1275-1285). Each target has its
/// own address, as divid dials one connection per IP
#[test]
fn added_nodes_are_dialled_whatever_maxconnections_says() {
    for setting in [
        vec!["-maxconnections=0"],
        vec!["-maxconnections=1", "-connect=127.0.0.1:1"],
    ] {
        let (first, first_at) = target("127.0.0.11");
        let (second, second_at) = target("127.0.0.12");
        let dir = tempfile::tempdir().unwrap();
        let p2p = format!("-bind=127.0.0.1:{}", free_port());
        let (a, b) = (
            format!("-addnode={first_at}"),
            format!("-addnode={second_at}"),
        );
        let mut args = vec![p2p.as_str(), "-discover=0", a.as_str(), b.as_str()];
        args.extend(setting.iter());
        let node = up(dir.path(), &args);
        let mut dialled = (false, false);
        wait_until(
            || {
                dialled.0 |= first.accept().is_ok();
                dialled.1 |= second.accept().is_ok();
                dialled == (true, true)
            },
            20,
        );
        drop(node);
        assert_eq!(dialled, (true, true), "{setting:?}");
    }
}
