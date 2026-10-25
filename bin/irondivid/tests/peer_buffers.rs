// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A peer that floods the node with messages, as Divi Core 3.0.0 meets it:
//! the peer is read no faster than the node takes its messages
//! (-maxreceivebuffer, Node.cpp:23, :335-339), and other peers are still
//! served. Every wait is bounded.

#![cfg(unix)]

use divi_test_support::{read_log, start_node};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
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

/// The payload of a getdata for one block
fn getdata_block(hash: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(hash);
    v
}

/// The genesis block's hash, in wire order
fn genesis(node: &Daemon) -> [u8; 32] {
    let hex = try_rpc(node.rpc_port, "getblockhash", json!([0])).unwrap();
    let mut h: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex.as_str().unwrap()[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    h.reverse();
    h.try_into().unwrap()
}

/// A new peer asks for a block: whether it comes within `wait`
fn block_served(node: &Daemon, wait: Duration) -> bool {
    let mut s = TcpStream::connect(("127.0.0.1", node.p2p_port)).expect("connect");
    s.set_read_timeout(Some(wait)).unwrap();
    s.write_all(&frame("version", &version_payload())).unwrap();
    s.write_all(&frame("verack", &[])).unwrap();
    s.write_all(&frame("getdata", &getdata_block(&genesis(node))))
        .unwrap();
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        let mut header = [0u8; 24];
        if s.read_exact(&mut header).is_err() {
            return false;
        }
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        if s.read_exact(&mut payload).is_err() {
            return false;
        }
        if &header[4..10] == b"block\0" {
            return true;
        }
    }
    false
}

/// A peer that sends inv after inv for `secs`, reading nothing
fn flood_inv(node: &Daemon, secs: u64) -> std::thread::JoinHandle<()> {
    let port = node.p2p_port;
    std::thread::spawn(move || {
        let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
            return;
        };
        s.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        if s.write_all(&frame("version", &version_payload())).is_err()
            || s.write_all(&frame("verack", &[])).is_err()
        {
            return;
        }
        let mut batch = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut n = 0u64;
        while Instant::now() < deadline {
            batch.clear();
            for _ in 0..500 {
                n += 1;
                let mut inv = vec![1u8];
                inv.extend_from_slice(&1u32.to_le_bytes());
                inv.extend_from_slice(&divi_crypto::double_sha256(&n.to_le_bytes()));
                batch.extend_from_slice(&frame("inv", &inv));
            }
            // A write that stalls means the node stopped reading: go on trying
            let _ = s.write_all(&batch);
        }
    })
}

/// While a peer floods, and after, another peer is still served: the node
/// reads the flood only as it takes the messages, and its message loop goes on
#[test]
fn a_flooding_peer_does_not_stop_the_node_serving_others() {
    let dir = tempfile::tempdir().unwrap();
    let node = Daemon::start(dir.path(), &["-maxreceivebuffer=100"]);
    let flood = flood_inv(&node, 10);
    std::thread::sleep(Duration::from_secs(4));
    assert!(
        block_served(&node, Duration::from_secs(10)),
        "not served during the flood"
    );
    flood.join().unwrap();
    assert!(
        block_served(&node, Duration::from_secs(10)),
        "not served after the flood"
    );
    node.stop();
    let log = read_log(dir.path());
    assert!(!log.contains("Option -maxreceivebuffer"), "{log}");
}
