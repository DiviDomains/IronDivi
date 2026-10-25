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

/// What a SOCKS5 stand-in on 127.0.0.1 was asked: per connection, the
/// methods offered and the CONNECT address type and destination
type Socks5Seen = std::sync::Arc<std::sync::Mutex<Vec<(Vec<u8>, u8, String)>>>;

fn read_n(c: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    c.read_exact(&mut b).map(|_| b)
}

/// One SOCKS5 exchange: take username/password when offered, record the
/// CONNECT, refuse it
fn socks5_serve(c: &mut TcpStream, record: &Socks5Seen) -> std::io::Result<()> {
    let head = read_n(c, 2)?;
    let methods = read_n(c, head[1] as usize)?;
    let auth = methods.contains(&2);
    c.write_all(&[5, if auth { 2 } else { 0 }])?;
    if auth {
        let user = read_n(c, 2)?;
        read_n(c, user[1] as usize)?;
        let len = read_n(c, 1)?;
        read_n(c, len[0] as usize)?;
        c.write_all(&[1, 0])?;
    }
    let req = read_n(c, 4)?;
    let dest = match req[3] {
        1 => {
            let b = read_n(c, 4)?;
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
        3 => {
            let len = read_n(c, 1)?;
            String::from_utf8_lossy(&read_n(c, len[0] as usize)?).into_owned()
        }
        _ => {
            let b: [u8; 16] = read_n(c, 16)?.try_into().unwrap();
            std::net::Ipv6Addr::from(b).to_string()
        }
    };
    read_n(c, 2)?;
    record.lock().unwrap().push((methods, req[3], dest));
    c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
}

/// A SOCKS5 stand-in on 127.0.0.1 that records each CONNECT and refuses it
fn socks5_stand_in() -> (u16, Socks5Seen) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Socks5Seen = Default::default();
    let record = seen.clone();
    std::thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let record = record.clone();
            std::thread::spawn(move || {
                let _ = socks5_serve(&mut c, &record);
            });
        }
    });
    (port, seen)
}

/// The destination goes to the proxy as a name, an onion address as its
/// .onion name (netbase.cpp:379-386, CNetAddr::ToStringIP); irondivid sent
/// the binary address. The onion target is never reachable off the proxy.
#[test]
fn proxy_destination_is_sent_as_a_name() {
    let (socks, seen) = socks5_stand_in();
    let dir = tempfile::tempdir().unwrap();
    let proxy = format!("-proxy=127.0.0.1:{socks}");
    // abcdefghij234567.onion as an OnionCat address
    let connect = "-connect=[fd87:d87e:eb43:44:3214:c742:75be:77df]:51476";
    let node = up(dir.path(), &[proxy.as_str(), connect]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while seen.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    drop(node);
    let seen = seen.lock().unwrap().clone();
    assert!(!seen.is_empty(), "nothing reached the proxy");
    for (_, atyp, dest) in &seen {
        assert_eq!(
            (*atyp, dest.as_str()),
            (3, "abcdefghij234567.onion"),
            "{seen:?}"
        );
    }
}
