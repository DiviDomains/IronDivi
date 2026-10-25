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
use std::net::{SocketAddr, TcpListener, TcpStream};
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
    log: std::path::PathBuf,
}

impl Node {
    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply =
            try_rpc(self.port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"));
        assert!(reply["error"].is_null(), "{method}: {reply}");
        reply["result"].clone()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
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
            return Ok(Node {
                child,
                port,
                log: datadir.join("debug.log"),
            });
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

/// A TCP connection from `src` to `to`, closed at once
fn knock(src: &str, to: SocketAddr) -> bool {
    let from: SocketAddr = format!("{src}:0").parse().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind(from).unwrap();
            tokio::time::timeout(Duration::from_secs(5), socket.connect(to))
                .await
                .is_ok_and(|r| r.is_ok())
        })
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

/// Every -bind is listened on, the second on its own port or the listen port;
/// one that is not an address stops the start (net.cpp:1809-1814)
#[test]
fn every_bind_is_listened_on() {
    let (p1, p2, p3) = (free_port(), free_port(), free_port());
    let dir = tempfile::tempdir().unwrap();
    let (b1, b2) = (
        format!("-bind=127.0.0.1:{p1}"),
        format!("-bind=127.0.0.2:{p2}"),
    );
    let port = format!("-port={p3}");
    let node = up(
        dir.path(),
        &[&b1, &b2, "-bind=127.0.0.3", &port, "-discover=0"],
    );
    for (ip, p) in [("127.0.0.1", p1), ("127.0.0.2", p2), ("127.0.0.3", p3)] {
        let at: SocketAddr = format!("{ip}:{p}").parse().unwrap();
        assert!(knock("127.0.0.9", at), "{at} does not listen");
    }
    drop(node);

    let dir = tempfile::tempdir().unwrap();
    let err = match start(dir.path(), &[&b1, "-bind=not-an-address"]) {
        Ok(_) => panic!("started with -bind=not-an-address"),
        Err(e) => e,
    };
    assert!(
        err.contains("Cannot resolve -bind address: 'not-an-address'"),
        "{err}"
    );
}

/// Each parameter interaction that sets an option not given is logged with
/// divid's text, and one that sets nothing is not (net.cpp:1672-1716)
#[test]
fn parameter_interactions_are_logged_as_divid_logs_them() {
    let line = |what: &str| format!("parameter interaction: {what}");
    let bind_listen = line("-bind or -whitebind set -> setting -listen=1");
    let connect_seed = line("-connect set -> setting -dnsseed=0");
    let connect_listen = line("-connect set -> setting -listen=0");
    let off_upnp = line("-listen=0 -> setting -upnp=0");
    let off_discover = line("-listen=0 -> setting -discover=0");

    // -bind wins over -connect for listening
    let dir = tempfile::tempdir().unwrap();
    let bind = format!("-bind=127.0.0.1:{}", free_port());
    let node = up(dir.path(), &[&bind, "-connect=127.0.0.1:1", "-discover=0"]);
    let log = node.log();
    assert!(log.contains(&bind_listen), "{log}");
    assert!(log.contains(&connect_seed), "{log}");
    assert!(!log.contains(&connect_listen), "{log}");
    assert!(!log.contains(&off_upnp), "{log}");
    drop(node);

    // -connect alone: no listening, so no UPnP and no discovery
    let dir = tempfile::tempdir().unwrap();
    let node = up(dir.path(), &["-connect=127.0.0.1:1"]);
    let log = node.log();
    for want in [&connect_seed, &connect_listen, &off_upnp, &off_discover] {
        assert!(log.contains(want.as_str()), "{want}: {log}");
    }
    assert!(!log.contains(&bind_listen), "{log}");
}

/// A peer turned away is logged with divid's text: "dropped (banned)" always,
/// "dropped (full)" only with -debug, divid's "net" category (net.cpp:757-762)
#[test]
fn refused_peers_are_logged_as_divid_logs_them() {
    for debug in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let p = free_port();
        let bind = format!("-bind=127.0.0.1:{p}");
        let mut args = vec![bind.as_str(), "-maxconnections=16", "-discover=0"];
        if debug {
            args.push("-debug=net");
        }
        let node = up(dir.path(), &args);
        let at: SocketAddr = format!("127.0.0.1:{p}").parse().unwrap();
        knock("127.0.0.5", at);
        let seen = wait_until(|| node.log().contains("dropped (full)"), 5);
        assert_eq!(seen, debug, "-debug: {debug}: {}", node.log());
        if debug {
            assert!(
                node.log().contains("connection from 127.0.0.5:"),
                "{}",
                node.log()
            );
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let p = free_port();
    let bind = format!("-bind=127.0.0.1:{p}");
    let node = up(dir.path(), &[&bind, "-discover=0"]);
    node.rpc("setban", json!(["127.0.0.6", "add"]));
    let at: SocketAddr = format!("127.0.0.1:{p}").parse().unwrap();
    knock("127.0.0.6", at);
    assert!(
        wait_until(
            || node.log().contains("connection from 127.0.0.6:")
                && node.log().contains("dropped (banned)"),
            10
        ),
        "{}",
        node.log()
    );
}
