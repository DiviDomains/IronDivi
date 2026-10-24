// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! getnetworkinfo's protocolversion and localaddresses, and the version
//! message, as Divi Core 3.0.0 gives them: protocol version 70915 unless
//! -protocolversion sets another, -externalip listed (port and score as
//! strings) and sent as our address, the score raised when an inbound peer
//! names that address, and an -externalip that is not a valid address
//! refused at start. Every wait is bounded.

#![cfg(unix)]

use divi_test_support::{free_port, start_node};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const REGTEST_MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];
const WAIT: Duration = Duration::from_secs(30);

/// One JSON-RPC call (test:test); None while the server is not up
fn try_rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).ok()?;
    let start = resp.find("\r\n\r\n")? + 4;
    let reply: Value = serde_json::from_str(&resp[start..]).ok()?;
    assert!(reply["error"].is_null(), "{method}: {}", reply["error"]);
    Some(reply["result"].clone())
}

struct Daemon {
    child: Child,
    rpc_port: u16,
    p2p_port: u16,
}

fn command(datadir: &Path, rpc_port: u16, p2p_port: u16, extra: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg("-regtest")
        .arg(format!("-datadir={}", datadir.display()))
        .arg(format!("-rpcport={rpc_port}"))
        .arg(format!("-port={p2p_port}"))
        .args([
            "-bind=127.0.0.1",
            "-rpcuser=test",
            "-rpcpassword=test",
            "-staking=0",
        ])
        .args(extra);
    cmd
}

impl Daemon {
    fn start(datadir: &Path, extra: &[&str]) -> Daemon {
        let (child, rpc_port, p2p_port) = start_node(
            datadir,
            |rpc_port, p2p_port| {
                let mut cmd = command(datadir, rpc_port, p2p_port, extra);
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                cmd
            },
            |rpc_port| try_rpc(rpc_port, "getblockcount", json!([])).is_some(),
        );
        Daemon {
            child,
            rpc_port,
            p2p_port,
        }
    }

    fn rpc(&self, method: &str) -> Value {
        try_rpc(self.rpc_port, method, json!([])).unwrap_or_else(|| panic!("{method}"))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = REGTEST_MAGIC.to_vec();
    let mut name = [0u8; 12];
    name[..command.len()].copy_from_slice(command.as_bytes());
    m.extend_from_slice(&name);
    m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    m.extend_from_slice(&divi_crypto::double_sha256(payload)[..4]);
    m.extend_from_slice(payload);
    m
}

/// A version message whose first address (where we reached the node) is `you`
fn version_payload(you: SocketAddr) -> Vec<u8> {
    let addr = |a: SocketAddr| {
        let mut v = 1u64.to_le_bytes().to_vec();
        let ip = match a.ip() {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            std::net::IpAddr::V6(v6) => v6.octets(),
        };
        v.extend_from_slice(&ip);
        v.extend_from_slice(&a.port().to_be_bytes());
        v
    };
    let mut v = 70915i32.to_le_bytes().to_vec();
    v.extend_from_slice(&1u64.to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    v.extend_from_slice(&now.to_le_bytes());
    v.extend_from_slice(&addr(you));
    v.extend_from_slice(&addr("0.0.0.0:0".parse().unwrap()));
    v.extend_from_slice(&rand_nonce().to_le_bytes());
    v.push(7);
    v.extend_from_slice(b"/raw:1/");
    v.extend_from_slice(&0i32.to_le_bytes());
    v.push(1);
    v
}

fn rand_nonce() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        ^ u64::from(std::process::id())
}

/// The payload of the next `command` message (others skipped), within WAIT
fn expect(s: &mut TcpStream, command: &str) -> Vec<u8> {
    s.set_read_timeout(Some(WAIT)).unwrap();
    loop {
        let mut header = [0u8; 24];
        s.read_exact(&mut header).expect("message header");
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).expect("message payload");
        let end = header[4..16].iter().position(|&b| b == 0).unwrap_or(12);
        if &header[4..4 + end] == command.as_bytes() {
            return payload;
        }
    }
}

/// (version, services, address names us at, address of the peer as the node sees it)
struct NodeVersion {
    version: i32,
    services: u64,
    addr_recv: (u64, SocketAddr),
    addr_from: (u64, SocketAddr),
}

fn parse_version(p: &[u8]) -> NodeVersion {
    let addr = |b: &[u8]| {
        let services = u64::from_le_bytes(b[..8].try_into().unwrap());
        let v6 = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap());
        let ip = v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(v6));
        let port = u16::from_be_bytes([b[24], b[25]]);
        (services, SocketAddr::new(ip, port))
    };
    NodeVersion {
        version: i32::from_le_bytes(p[..4].try_into().unwrap()),
        services: u64::from_le_bytes(p[4..12].try_into().unwrap()),
        addr_recv: addr(&p[20..46]),
        addr_from: addr(&p[46..72]),
    }
}

/// Connect from 127.0.0.2, send a version naming `you`, return the node's version
fn handshake(d: &Daemon, you: SocketAddr) -> (TcpStream, NodeVersion) {
    let socket =
        std::net::TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], d.p2p_port)), WAIT)
            .expect("connect");
    let mut s = socket;
    s.write_all(&frame("version", &version_payload(you)))
        .unwrap();
    let v = parse_version(&expect(&mut s, "version"));
    expect(&mut s, "verack");
    s.write_all(&frame("verack", &[])).unwrap();
    (s, v)
}

fn local_addresses(d: &Daemon) -> Value {
    d.rpc("getnetworkinfo")["localaddresses"].clone()
}

#[test]
fn getnetworkinfo_and_version_message_as_divid() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), &["-externalip=1.2.3.4"]);
    let port = d.p2p_port;
    let net = d.rpc("getnetworkinfo");
    // Divi Core 3.0.0's PROTOCOL_VERSION (version.h:21)
    assert_eq!(net["protocolversion"], 70915, "{net}");
    assert_eq!(d.rpc("getinfo")["protocolversion"], 70915);
    // irondivid serves no bloom filters: NODE_NETWORK, as divid with -peerbloomfilters=0
    assert_eq!(net["localservices"], "0000000000000001", "{net}");
    // -externalip at the listen port, LOCAL_MANUAL (4); port and score as strings
    assert_eq!(
        net["localaddresses"],
        json!([{"address": "1.2.3.4", "port": port.to_string(), "score": "4"}]),
        "{net}"
    );

    // Our version message: the protocol version, our services, our
    // -externalip address; the peer (loopback, not routable) as 0.0.0.0:0
    let me: SocketAddr = format!("1.2.3.4:{port}").parse().unwrap();
    let (_s, v) = handshake(&d, me);
    assert_eq!(v.version, 70915);
    assert_eq!(v.services, 1);
    assert_eq!(v.addr_from, (1, me), "our address");
    assert_eq!(v.addr_recv.1, "0.0.0.0:0".parse::<SocketAddr>().unwrap());
    // The inbound peer named our address: score 5 (Divi Core SeenLocal)
    let deadline = Instant::now() + WAIT;
    while local_addresses(&d)[0]["score"] != "5" {
        assert!(Instant::now() < deadline, "{}", local_addresses(&d));
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn without_a_local_address_the_version_names_the_listen_port() {
    let dir = tempfile::tempdir().unwrap();
    // -discover=0: no interface addresses, so nothing routable is known
    let d = Daemon::start(dir.path(), &["-discover=0"]);
    assert_eq!(local_addresses(&d), json!([]));
    let (_s, v) = handshake(&d, "0.0.0.0:0".parse().unwrap());
    let any: SocketAddr = format!("0.0.0.0:{}", d.p2p_port).parse().unwrap();
    assert_eq!(v.addr_from, (1, any), "0.0.0.0 with our listen port");
}

#[test]
fn protocolversion_option_sets_the_version() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), &["-protocolversion=70930", "-discover=0"]);
    assert_eq!(d.rpc("getnetworkinfo")["protocolversion"], 70930);
    assert_eq!(d.rpc("getinfo")["protocolversion"], 70930);
    let (_s, v) = handshake(&d, "0.0.0.0:0".parse().unwrap());
    assert_eq!(v.version, 70930);
}

fn output_within(cmd: &mut Command) -> Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("irondivid kept running");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn externalip_that_is_not_an_address_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    // A documentation address is not valid to Divi Core: "Cannot resolve"
    let out = output_within(&mut command(
        dir.path(),
        free_port(),
        free_port(),
        &["-externalip=[2001:db8::1]"],
    ));
    assert!(!out.status.success());
    let log = std::fs::read_to_string(dir.path().join("debug.log")).unwrap_or_default();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stderr), log);
    assert!(
        text.contains("Cannot resolve -externalip address: '[2001:db8::1]'"),
        "{text}"
    );
}
