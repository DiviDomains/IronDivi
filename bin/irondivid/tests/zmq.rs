// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! -zmqpubhashblock, -zmqpubhashtx, -zmqpubrawblock and -zmqpubrawtx publish
//! as Divi Core 3.0.0 does: three frames (topic, body, 4-byte little-endian
//! sequence number), hashes in the order they are shown, notifiers with one
//! address on one socket, and no notifier at all when an address cannot be
//! bound (zmq/zmqpublishnotifier.cpp, zmq/zmqnotificationinterface.cpp).
//! A subscriber written here speaks ZMTP 3.0.

use divi_test_support::start_node;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

/// POST one JSON-RPC call; None while the server is not up yet.
fn rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
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

fn ok(port: u16, method: &str, params: Value) -> Value {
    let reply = rpc(port, method, params).unwrap_or_else(|| panic!("{method}: no reply"));
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port nothing listens on, below the ephemeral range outgoing
/// connections take theirs from
fn free_port() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let seed = std::collections::hash_map::RandomState::new();
    for i in 0u32..1000 {
        let mut h = seed.build_hasher();
        h.write_u32(i);
        let port = 20000 + (h.finish() % 12768) as u16;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port in 20000-32767");
}

/// irondivid on regtest with `zmq` options
fn node(dir: &Path, zmq: Vec<String>) -> (KillOnDrop, u16) {
    let (child, rpc_port, _) = start_node(
        dir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("--regtest")
                .arg("--datadir")
                .arg(dir)
                .args(["--rpcport", &rpc_port.to_string()])
                .args(["--port", &p2p_port.to_string()])
                .args(["--bind", "127.0.0.1", "--staking=false"])
                .args(["--rpcuser", "test", "--rpcpassword", "test"])
                .args(&zmq)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    (KillOnDrop(child), rpc_port)
}

fn frame(body: &[u8], command: bool) -> Vec<u8> {
    let mut out = vec![if command { 4 } else { 0 }, body.len() as u8];
    out.extend_from_slice(body);
    out
}

/// A ZMTP 3.0 SUB connection, subscribed to every topic
struct Subscriber(TcpStream);

impl Subscriber {
    fn connect(port: u16) -> Self {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("the ZMQ port listens");
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut greeting = [0u8; 64];
        greeting[0] = 0xff;
        greeting[9] = 0x7f;
        greeting[10] = 3;
        greeting[12..16].copy_from_slice(b"NULL");
        s.write_all(&greeting).unwrap();
        let mut peer = [0u8; 64];
        s.read_exact(&mut peer).unwrap();
        assert_eq!(
            (peer[0], peer[9], peer[10]),
            (0xff, 0x7f, 3),
            "a ZMTP 3 greeting"
        );
        assert_eq!(&peer[12..16], b"NULL");
        let mut ready = vec![5u8];
        ready.extend_from_slice(b"READY");
        ready.push(11);
        ready.extend_from_slice(b"Socket-Type");
        ready.extend_from_slice(&3u32.to_be_bytes());
        ready.extend_from_slice(b"SUB");
        s.write_all(&frame(&ready, true)).unwrap();
        let mut sub = Subscriber(s);
        let (command, _, body) = sub.read_frame();
        assert!(command && body[1..6] == *b"READY", "READY");
        // Subscribe to every topic
        sub.0.write_all(&frame(&[1], false)).unwrap();
        sub
    }

    fn read_frame(&mut self) -> (bool, bool, Vec<u8>) {
        let mut flags = [0u8; 1];
        self.0.read_exact(&mut flags).unwrap();
        let size = if flags[0] & 2 != 0 {
            let mut b = [0u8; 8];
            self.0.read_exact(&mut b).unwrap();
            u64::from_be_bytes(b) as usize
        } else {
            let mut b = [0u8; 1];
            self.0.read_exact(&mut b).unwrap();
            b[0] as usize
        };
        let mut body = vec![0u8; size];
        self.0.read_exact(&mut body).unwrap();
        (flags[0] & 4 != 0, flags[0] & 1 != 0, body)
    }

    /// The next message: (topic, body as hex, sequence number)
    fn message(&mut self) -> (String, String, u32) {
        let mut parts = Vec::new();
        loop {
            let (command, more, body) = self.read_frame();
            if command {
                continue;
            }
            parts.push(body);
            if !more {
                break;
            }
        }
        assert_eq!(parts.len(), 3, "topic, body and sequence number");
        let sequence = u32::from_le_bytes(parts[2].as_slice().try_into().expect("4 bytes"));
        (
            String::from_utf8(parts[0].clone()).unwrap(),
            hex::encode(&parts[1]),
            sequence,
        )
    }
}

#[test]
fn blocks_and_transactions_are_published_as_divid_publishes_them() {
    let dir = tempfile::tempdir().unwrap();
    let (hashes, rawblock, rawtx) = (free_port(), free_port(), free_port());
    let at = |p: u16| format!("tcp://127.0.0.1:{p}");
    let (_node, rpc_port) = node(
        dir.path(),
        vec![
            format!("--zmqpubhashblock={}", at(hashes)),
            format!("--zmqpubhashtx={}", at(hashes)),
            format!("--zmqpubrawblock={}", at(rawblock)),
            format!("--zmqpubrawtx={}", at(rawtx)),
        ],
    );
    let mut on_hashes = Subscriber::connect(hashes);
    let mut on_rawblock = Subscriber::connect(rawblock);
    let mut on_rawtx = Subscriber::connect(rawtx);
    // A subscription takes effect when the publisher has read it
    std::thread::sleep(Duration::from_millis(500));

    let mined = ok(rpc_port, "setgenerate", json!([1]));
    let block_hash = mined[0].as_str().unwrap().to_string();
    let block = ok(rpc_port, "getblock", json!([block_hash]));
    let coinbase = block["tx"][0].as_str().unwrap().to_string();
    let raw_block = ok(rpc_port, "getblock", json!([block_hash, false]));
    let raw_coinbase = ok(rpc_port, "getrawtransaction", json!([coinbase]));

    // The block's transaction, then the block, on the shared socket. The
    // transaction is the second: a new data directory sent the genesis
    // block's transaction with sequence number 0.
    assert_eq!(on_hashes.message(), ("hashtx".into(), coinbase.clone(), 1));
    assert_eq!(on_hashes.message(), ("hashblock".into(), block_hash, 0));
    assert_eq!(
        on_rawblock.message(),
        (
            "rawblock".into(),
            raw_block.as_str().unwrap().to_string(),
            0
        )
    );
    assert_eq!(
        on_rawtx.message(),
        (
            "rawtx".into(),
            raw_coinbase.as_str().unwrap().to_string(),
            1
        )
    );
}

#[test]
fn an_address_that_cannot_be_bound_leaves_no_notifier() {
    let dir = tempfile::tempdir().unwrap();
    let good = free_port();
    let (_node, rpc_port) = node(
        dir.path(),
        vec![
            format!("--zmqpubhashblock=tcp://127.0.0.1:{good}"),
            "--zmqpubrawtx=notanaddress".to_string(),
        ],
    );
    // The node runs; the address that was bound before the failure is closed again
    assert_eq!(ok(rpc_port, "getblockcount", json!([])), 0);
    assert!(TcpStream::connect(("127.0.0.1", good)).is_err());
}
