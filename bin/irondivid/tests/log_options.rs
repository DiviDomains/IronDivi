// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! debug.log as Divi Core 3.0.0 writes it: -logips (default 0) names a peer
//! by its id only, and adds its address only when set (Node.cpp:577-580,
//! :1000-1003, main.cpp:456-461). Every wait is bounded.

#![cfg(unix)]

use divi_test_support::{read_log, start_node};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const REGTEST_MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];
const WAIT: Duration = Duration::from_secs(30);

/// One JSON-RPC call (test:test); None while the server is not up
fn try_rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(WAIT)).ok()?;
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
    Some(reply["result"].clone())
}

struct Daemon {
    child: Child,
    rpc_port: u16,
    p2p_port: u16,
}

impl Daemon {
    fn start(datadir: &Path, extra: &[&str]) -> Daemon {
        let (child, rpc_port, p2p_port) = start_node(
            datadir,
            |rpc_port, p2p_port| {
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
                        "-listen=1",
                    ])
                    .args(extra)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
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

    /// Stop by RPC and wait for the exit, so debug.log holds every line
    fn stop(mut self) {
        let _ = try_rpc(self.rpc_port, "stop", json!([]));
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("irondivid did not stop within {WAIT:?}");
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

fn version_payload() -> Vec<u8> {
    let addr = || {
        let mut v = 1u64.to_le_bytes().to_vec();
        v.extend_from_slice(&std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets());
        v.extend_from_slice(&0u16.to_be_bytes());
        v
    };
    let mut v = 70915i32.to_le_bytes().to_vec();
    v.extend_from_slice(&1u64.to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    v.extend_from_slice(&(now.as_secs() as i64).to_le_bytes());
    v.extend_from_slice(&addr());
    v.extend_from_slice(&addr());
    v.extend_from_slice(&(now.as_nanos() as u64).to_le_bytes());
    v.push(7);
    v.extend_from_slice(b"/raw:1/");
    v.extend_from_slice(&0i32.to_le_bytes());
    v.push(1);
    v
}

/// A raw peer that connects, sends its version and waits for the node's
/// verack; returns the peer's own address (as the node sees it)
fn raw_peer_handshake(port: u16) -> SocketAddr {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(WAIT)).unwrap();
    s.write_all(&frame("version", &version_payload())).unwrap();
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        let mut header = [0u8; 24];
        s.read_exact(&mut header).expect("message header");
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).expect("message payload");
        if &header[4..10] == b"verack" {
            s.write_all(&frame("verack", &[])).unwrap();
            std::thread::sleep(Duration::from_millis(500));
            return s.local_addr().unwrap();
        }
    }
    panic!("no verack within {WAIT:?}");
}

/// The log after a raw peer connected and the node stopped
fn log_with_a_peer(extra: &[&str]) -> (String, SocketAddr) {
    let dir = tempfile::tempdir().unwrap();
    let node = Daemon::start(dir.path(), extra);
    let peer = raw_peer_handshake(node.p2p_port);
    node.stop();
    (read_log(dir.path()), peer)
}

/// -logips=0 (the default): the peer's address is in no line. -logips=1: the
/// version line names it, `peeraddr=<address>`, as divid's does
#[test]
fn logips_decides_whether_peer_addresses_are_logged() {
    let (log, peer) = log_with_a_peer(&[]);
    let at = peer.to_string();
    assert!(log.contains("receive version message"), "{log}");
    assert!(!log.contains(&at), "{at} in a log without -logips:\n{log}");
    assert!(!log.contains("Option -logips"), "{log}");

    let (log, peer) = log_with_a_peer(&["-logips=1"]);
    let at = format!("peeraddr={peer}");
    assert!(
        log.lines()
            .any(|l| l.contains("receive version message") && l.contains(&at)),
        "no {at} in the version line under -logips:\n{log}"
    );
    assert!(!log.contains("Option -logips"), "{log}");
}

/// Whether a line starts as divid's do under -logtimestamps:
/// `YYYY-MM-DD HH:MM:SS ` (Logging.cpp:182)
fn timestamped(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() > 20
        && b[..19].iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b' ',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        })
        && b[19] == b' '
}

/// -logtimestamps (default 1): each line begins with the time, then the
/// message, as divid's do: no level or module name. -logtimestamps=0: no time
#[test]
fn logtimestamps_decides_the_line_prefix() {
    let (log, _) = log_with_a_peer(&[]);
    let lines: Vec<&str> = log.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(timestamped(line), "not divid's prefix: {line:?}");
        assert!(
            !line.contains(" INFO ") && !line.contains("irondivid:"),
            "{line:?}"
        );
    }
    assert!(!log.contains("Option -logtimestamps"), "{log}");

    let (log, _) = log_with_a_peer(&["-logtimestamps=0"]);
    let version = log
        .lines()
        .find(|l| l.contains("receive version message"))
        .unwrap_or_else(|| panic!("no version line:\n{log}"));
    assert!(
        version.starts_with("receive version message"),
        "{version:?}"
    );
    assert!(log.lines().all(|l| !timestamped(l)), "{log}");
    assert!(!log.contains("Option -logtimestamps"), "{log}");
}
