// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The proxy, onion, Tor control, -dns and -upnp options as divid reads them
//! (net.cpp:1690-1800, init.cpp:1621, torcontrol.cpp): what irondivid does at
//! start and what getnetworkinfo then shows. Every node and stand-in here is on
//! 127.0.0.1.

#![cfg(unix)]

use divi_test_support::free_port;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
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

/// How a start ended: up (with the node, to call and stop), or an exit code
/// and stderr
enum Started {
    Up(Node),
    Exited(i32, String),
}

struct Node {
    child: Child,
    port: u16,
}

impl Node {
    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply =
            try_rpc(self.port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"));
        assert!(reply["error"].is_null(), "{method}: {reply}");
        reply["result"].clone()
    }

    /// getnetworkinfo's entry for `name` (ipv4, ipv6, onion)
    fn network(&self, name: &str) -> Value {
        let info = self.rpc("getnetworkinfo", json!([]));
        info["networks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no {name} in {info}"))
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

/// Start a regtest irondivid on 127.0.0.1 with `extra` options (no peers)
fn start(datadir: &Path, extra: &[&str]) -> Started {
    let (port, p2p_port) = (free_port(), free_port());
    let stderr = datadir.join("stderr.txt");
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args([
            "--bind",
            "127.0.0.1",
            "--staking=false",
            "-discover=0",
            "-listenonion=0",
        ])
        .args(["--connect", "127.0.0.1:1"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let text = std::fs::read_to_string(&stderr).unwrap_or_default();
            return Started::Exited(status.code().unwrap_or(-1), text);
        }
        if try_rpc(port, "getblockcount", &json!([])).is_some() {
            return Started::Up(Node { child, port });
        }
        assert!(Instant::now() < deadline, "irondivid did not start");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn up(datadir: &Path, extra: &[&str]) -> Node {
    match start(datadir, extra) {
        Started::Up(node) => node,
        Started::Exited(code, text) => panic!("{extra:?}: exit {code}: {text}"),
    }
}

/// With -proxy the IPv4 and IPv6 networks name it, with random credentials
/// unless -proxyrandomize=0 (net.cpp:1761-1779, rpcnet.cpp:326); -proxy=0 and
/// -noproxy set none
#[test]
fn proxy_and_proxyrandomize_in_getnetworkinfo() {
    for (options, proxy, randomize) in [
        (vec!["-proxy=127.0.0.1:9"], "127.0.0.1:9", true),
        (
            vec!["-proxy=127.0.0.1:9", "-proxyrandomize=0"],
            "127.0.0.1:9",
            false,
        ),
        (vec!["-proxy=0"], "", false),
        (vec!["-noproxy"], "", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let node = up(dir.path(), &options);
        for net in ["ipv4", "ipv6"] {
            let n = node.network(net);
            assert_eq!(n["proxy"], proxy, "{options:?} {n}");
            assert_eq!(
                n["proxy_randomize_credentials"], randomize,
                "{options:?} {n}"
            );
        }
    }
}
