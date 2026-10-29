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

//! What irondivid keeps across a restart as divid does: addresses learnt from
//! an `addr` message, given back to a `getaddr` after a clean stop and start
//! (Divi Core's addrman and peers.dat: main.cpp:521-558, :863-869;
//! net.cpp:1060-1068, :1431-1438), and the masternode.conf divid makes in a
//! new data directory (masternodeconfig.cpp:53-64).

use divi_test_support::start_node;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const REGTEST_MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];

fn rpc(port: u16, method: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":[]}}"#);
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let start = response.find("\r\n\r\n")? + 4;
    Some(response[start..].to_string())
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A connect-only regtest node (it dials nothing it learns), listening on 127.0.0.1
fn start(dir: &Path) -> (KillOnDrop, u16, u16) {
    let (child, rpc_port, p2p_port) = start_node(
        dir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("--regtest")
                .arg("--datadir")
                .arg(dir)
                .args(["--rpcport", &rpc_port.to_string()])
                .args(["--port", &p2p_port.to_string()])
                .args(["--bind", "127.0.0.1", "--listen=1", "--staking=false"])
                .args(["--connect=127.0.0.1:1", "--dnsseed=0"])
                .args(["--rpcuser", "test", "--rpcpassword", "test"])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount").is_some(),
    );
    (KillOnDrop(child), rpc_port, p2p_port)
}

fn stop(node: &mut KillOnDrop, rpc_port: u16) {
    rpc(rpc_port, "stop").expect("stop reply");
    let deadline = Instant::now() + Duration::from_secs(60);
    while node.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "irondivid did not stop");
        std::thread::sleep(Duration::from_millis(100));
    }
}

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

fn net_addr(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut out = 1u64.to_le_bytes().to_vec();
    out.extend_from_slice(&[0u8; 10]);
    out.extend_from_slice(&[0xff, 0xff]);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

/// An inbound peer: version, then the messages the node sends
struct Peer {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Peer {
    fn connect(p2p_port: u16) -> Peer {
        let stream = TcpStream::connect(("127.0.0.1", p2p_port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&70915i32.to_le_bytes());
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&(now() as i64).to_le_bytes());
        payload.extend_from_slice(&net_addr([127, 0, 0, 1], p2p_port));
        payload.extend_from_slice(&net_addr([127, 0, 0, 1], 0));
        payload.extend_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.push(1);
        let mut peer = Peer {
            stream,
            buf: Vec::new(),
        };
        peer.send("version", &payload);
        assert!(peer.wait_for("verack", 20).is_some(), "no verack");
        peer
    }

    fn send(&mut self, cmd: &str, payload: &[u8]) {
        self.stream.write_all(&message(cmd, payload)).unwrap();
    }

    /// The payloads of `cmd` messages within `secs` (the first one ends it
    /// unless `all`)
    fn collect(&mut self, cmd: &str, secs: u64, all: bool) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut got = Vec::new();
        while Instant::now() < deadline {
            while self.buf.len() >= 24 {
                let len = u32::from_le_bytes(self.buf[16..20].try_into().unwrap()) as usize;
                if self.buf.len() < 24 + len {
                    break;
                }
                let name: Vec<u8> = self.buf[4..16]
                    .iter()
                    .copied()
                    .take_while(|&b| b != 0)
                    .collect();
                let payload = self.buf[24..24 + len].to_vec();
                self.buf.drain(..24 + len);
                match name.as_slice() {
                    b"version" => self.send("verack", &[]),
                    b"ping" => self.send("pong", &payload),
                    _ => {}
                }
                if name == cmd.as_bytes() {
                    got.push(payload);
                    if !all {
                        return got;
                    }
                }
            }
            let mut chunk = [0u8; 65536];
            match self.stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(_) => {}
            }
        }
        got
    }

    fn wait_for(&mut self, cmd: &str, secs: u64) -> Option<Vec<u8>> {
        self.collect(cmd, secs, false).pop()
    }
}

/// The 100 addresses: public, each in its own /16, on the regtest port
fn gossip() -> Vec<[u8; 4]> {
    (0..100u8)
        .map(|k| [20 + k, k.wrapping_mul(7), 3, 4])
        .collect()
}

/// The IPv4 addresses of the addr messages a getaddr brings
fn asked(p2p_port: u16) -> Vec<[u8; 4]> {
    let mut peer = Peer::connect(p2p_port);
    peer.send("getaddr", &[]);
    let mut out = Vec::new();
    for payload in peer.collect("addr", 6, true) {
        let (n, off) = match payload[0] {
            0xfd => (u16::from_le_bytes([payload[1], payload[2]]) as usize, 3),
            n => (n as usize, 1),
        };
        for k in 0..n {
            let e = &payload[off + 30 * k..off + 30 * (k + 1)];
            out.push(e[24..28].try_into().unwrap());
        }
    }
    out
}

#[test]
fn addresses_from_gossip_are_given_back_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, rpc_port, p2p_port) = start(dir.path());

    let mut peer = Peer::connect(p2p_port);
    let mut payload = vec![100u8];
    for ip in gossip() {
        payload.extend_from_slice(&(now() - 600).to_le_bytes());
        payload.extend_from_slice(&net_addr(ip, 51476));
    }
    peer.send("addr", &payload);
    std::thread::sleep(Duration::from_secs(2));
    drop(peer);

    // 23% of the 100 (ADDRMAN_GETADDR_MAX_PCT), all of them gossiped
    let before = asked(p2p_port);
    assert_eq!(before.len(), 23, "getaddr before the restart");
    assert!(before.iter().all(|a| gossip().contains(a)));

    stop(&mut node, rpc_port);
    assert!(
        dir.path().join("peers.dat").exists(),
        "peers.dat written at the stop"
    );
    let (mut node, rpc_port, p2p_port) = start(dir.path());
    let after = asked(p2p_port);
    assert_eq!(after.len(), 23, "getaddr after the restart");
    assert!(after.iter().all(|a| gossip().contains(a)));
    stop(&mut node, rpc_port);
}

#[test]
fn a_new_data_directory_gets_divid_s_masternode_conf() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, rpc_port, _) = start(dir.path());
    stop(&mut node, rpc_port);
    let conf = std::fs::read_to_string(dir.path().join("masternode.conf"))
        .expect("masternode.conf made at the start");
    assert!(conf.starts_with("# Masternode config file\n"), "{conf}");
}
