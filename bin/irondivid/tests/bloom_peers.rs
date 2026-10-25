// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Bloom filters as Divi Core serves them to light clients, seen by a peer
//! that speaks the wire protocol to a regtest irondivid: the NODE_BLOOM
//! service bit, the filter messages and their scores, filtered blocks, and
//! filtered transaction announcements; all behind -peerbloomfilters, on by
//! default (Divi Core defaultValues.h:100, net.cpp:1722-1723).

#![cfg(unix)]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const REGTEST_MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];
const NODE_BLOOM: u64 = 1 << 2;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A regtest irondivid with no peers of its own
struct Daemon {
    child: Child,
    rpc_port: u16,
    p2p_port: u16,
    _dir: tempfile::TempDir,
}

impl Daemon {
    fn start(extra: &[&str]) -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        let (rpc_port, p2p_port) = (free_port(), free_port());
        let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
            .arg("-regtest")
            .arg(format!("-datadir={}", dir.path().display()))
            .arg(format!("-rpcport={rpc_port}"))
            .arg(format!("-port={p2p_port}"))
            .args(["-bind=127.0.0.1", "-listen=1", "-dnsseed=0", "-staking=0"])
            .args(["-rpcuser=test", "-rpcpassword=test"])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn irondivid");
        let daemon = Daemon {
            child,
            rpc_port,
            p2p_port,
            _dir: dir,
        };
        let deadline = Instant::now() + Duration::from_secs(120);
        while daemon.try_rpc("getblockcount", json!([])).is_none() {
            assert!(Instant::now() < deadline, "RPC server did not come up");
            std::thread::sleep(Duration::from_millis(250));
        }
        daemon
    }

    fn try_rpc(&self, method: &str, params: Value) -> Option<Value> {
        let mut stream = TcpStream::connect(("127.0.0.1", self.rpc_port)).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .ok()?;
        let body =
            json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        // "dGVzdDp0ZXN0" is base64 of test:test
        let request = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).ok()?;
        let mut response = String::new();
        stream.read_to_string(&mut response).ok()?;
        let start = response.find("\r\n\r\n")? + 4;
        serde_json::from_str(&response[start..]).ok()
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply = self
            .try_rpc(method, params.clone())
            .unwrap_or_else(|| panic!("{method}: no reply"));
        assert!(reply["error"].is_null(), "{method} {params}: {reply}");
        reply["result"].clone()
    }

    /// Whether 127.0.0.1 is in the ban list
    fn banned(&self) -> bool {
        self.rpc("listbanned", json!([]))
            .to_string()
            .contains("127.0.0.1")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.try_rpc("stop", json!([]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn message(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = REGTEST_MAGIC.to_vec();
    let mut name = [0u8; 12];
    name[..command.len()].copy_from_slice(command.as_bytes());
    m.extend_from_slice(&name);
    m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    m.extend_from_slice(&divi_crypto::double_sha256(payload)[..4]);
    m.extend_from_slice(payload);
    m
}

fn net_addr(port: u16) -> Vec<u8> {
    let mut a = 1u64.to_le_bytes().to_vec();
    a.extend_from_slice(&[0u8; 10]);
    a.extend_from_slice(&[0xff, 0xff, 127, 0, 0, 1]);
    a.extend_from_slice(&port.to_be_bytes());
    a
}

/// A peer of this test's own: version (with or without transaction relay),
/// verack, then the messages each test sends and reads
struct Peer {
    stream: TcpStream,
    buf: Vec<u8>,
    /// The services irondivid named in its version
    services: u64,
    /// Whether irondivid closed the connection
    closed: bool,
}

impl Peer {
    fn connect(port: u16, relay: bool) -> Peer {
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut peer = Peer {
            stream,
            buf: Vec::new(),
            services: 0,
            closed: false,
        };
        let mut v = 70915i32.to_le_bytes().to_vec();
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(
            &(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64)
                .to_le_bytes(),
        );
        v.extend(net_addr(port));
        v.extend(net_addr(0));
        v.extend_from_slice(&rand_nonce().to_le_bytes());
        let ua = b"/bloom-test:1/";
        v.push(ua.len() as u8);
        v.extend_from_slice(ua);
        v.extend_from_slice(&0i32.to_le_bytes());
        v.push(relay as u8);
        peer.send("version", &v);
        let (mut got_version, mut got_verack) = (false, false);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !(got_version && got_verack) {
            assert!(Instant::now() < deadline, "no handshake");
            match peer.next(Duration::from_secs(1)) {
                Some((cmd, payload)) if cmd == "version" => {
                    peer.services = u64::from_le_bytes(payload[4..12].try_into().unwrap());
                    got_version = true;
                    peer.send("verack", &[]);
                }
                Some((cmd, _)) if cmd == "verack" => got_verack = true,
                _ => {}
            }
        }
        peer
    }

    fn send(&mut self, command: &str, payload: &[u8]) {
        let _ = self.stream.write_all(&message(command, payload));
    }

    /// The next message within `wait`, or None; a closed connection is None
    fn next(&mut self, wait: Duration) -> Option<(String, Vec<u8>)> {
        let deadline = Instant::now() + wait;
        loop {
            if self.buf.len() >= 24 {
                let len = u32::from_le_bytes(self.buf[16..20].try_into().unwrap()) as usize;
                if self.buf.len() >= 24 + len {
                    let cmd = String::from_utf8_lossy(&self.buf[4..16])
                        .trim_end_matches('\0')
                        .to_string();
                    let payload = self.buf[24..24 + len].to_vec();
                    self.buf.drain(..24 + len);
                    return Some((cmd, payload));
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            let mut chunk = [0u8; 65536];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    self.closed = true;
                    return None;
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => {
                    self.closed = true;
                    return None;
                }
            }
        }
    }

    /// Every message that comes within `wait`
    fn drain(&mut self, wait: Duration) -> Vec<(String, Vec<u8>)> {
        let deadline = Instant::now() + wait;
        let mut got = Vec::new();
        while Instant::now() < deadline && !self.closed {
            if let Some(m) = self.next(Duration::from_millis(200)) {
                got.push(m);
            }
        }
        got
    }
}

fn rand_nonce() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
        ^ std::process::id() as u64
}

/// Divi Core advertises NODE_BLOOM while -peerbloomfilters is on, as it is by
/// default (defaultValues.h:100, net.cpp:1722-1723), and not with it off
#[test]
fn node_bloom_is_advertised_while_peerbloomfilters_is_on() {
    let on = Daemon::start(&[]);
    assert_ne!(
        Peer::connect(on.p2p_port, true).services & NODE_BLOOM,
        0,
        "default"
    );
    let off = Daemon::start(&["-peerbloomfilters=0"]);
    assert_eq!(
        Peer::connect(off.p2p_port, true).services & NODE_BLOOM,
        0,
        "=0"
    );
}

/// A filterload payload: `bytes` of filter data all set to `fill`, five hash
/// functions, no tweak, BLOOM_UPDATE_ALL
fn filterload(bytes: usize, fill: u8) -> Vec<u8> {
    let mut p = Vec::new();
    if bytes < 0xfd {
        p.push(bytes as u8);
    } else {
        p.push(0xfd);
        p.extend_from_slice(&(bytes as u16).to_le_bytes());
    }
    p.extend(std::iter::repeat_n(fill, bytes));
    p.extend_from_slice(&5u32.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes());
    p.push(1);
    p
}

/// A filteradd payload of `bytes` bytes
fn filteradd(bytes: usize) -> Vec<u8> {
    let mut p = Vec::new();
    if bytes < 0xfd {
        p.push(bytes as u8);
    } else {
        p.push(0xfd);
        p.extend_from_slice(&(bytes as u16).to_le_bytes());
    }
    p.extend(std::iter::repeat_n(7u8, bytes));
    p
}

/// Send the messages on a fresh connection and say whether they scored 100.
/// The test's peer is local, which Divi Core disconnects at 100 but never
/// bans (main.cpp:1107-1125, "not banning local peer"); every bloom score is
/// 100 (main.cpp:892-939), so the disconnect is the score
fn scores_100(daemon: &Daemon, messages: &[(&str, Vec<u8>)]) -> bool {
    let mut peer = Peer::connect(daemon.p2p_port, true);
    for (command, payload) in messages {
        peer.send(command, payload);
    }
    peer.drain(Duration::from_secs(3));
    assert!(!daemon.banned(), "a local peer banned");
    peer.closed
}

/// The filter messages and their scores, as Divi Core takes them
/// (main.cpp:892-939): a filter within the limits, a filteradd (even before
/// any filterload: every peer starts with a filter, Node.cpp:556) and a
/// filterclear are taken; a filter over 36,000 bytes and a filteradd item
/// over 520 bytes score 100; with -peerbloomfilters=0 any filter message
/// scores 100
#[test]
fn filter_messages_are_taken_and_scored_as_divid() {
    let on = Daemon::start(&[]);
    assert!(
        !scores_100(&on, &[("filterload", filterload(10, 0))]),
        "filterload"
    );
    assert!(
        !scores_100(&on, &[("filteradd", filteradd(20))]),
        "filteradd first"
    );
    assert!(
        !scores_100(
            &on,
            &[
                ("filterload", filterload(10, 0)),
                ("filteradd", filteradd(520))
            ]
        ),
        "filteradd of 520 bytes"
    );
    assert!(!scores_100(&on, &[("filterclear", vec![])]), "filterclear");
    assert!(
        scores_100(&on, &[("filterload", filterload(36_001, 0))]),
        "oversize filter"
    );
    assert!(
        scores_100(&on, &[("filteradd", filteradd(521))]),
        "filteradd of 521 bytes"
    );

    let off = Daemon::start(&["-peerbloomfilters=0"]);
    assert!(
        scores_100(&off, &[("filterload", filterload(10, 0))]),
        "off: filterload"
    );
    assert!(
        scores_100(&off, &[("filterclear", vec![])]),
        "off: filterclear"
    );
}

/// A getdata of one block of inv type `kind` (3: a filtered block)
fn getdata(kind: u32, hash_hex: &str) -> Vec<u8> {
    let mut hash = hex::decode(hash_hex).unwrap();
    hash.reverse();
    let mut p = vec![1u8];
    p.extend_from_slice(&kind.to_le_bytes());
    p.extend_from_slice(&hash);
    p
}

/// The serialized header and first transaction of a block, from getblock
fn header_and_coinbase(daemon: &Daemon, hash: &str) -> (Vec<u8>, Vec<u8>) {
    let raw = hex::decode(
        daemon
            .rpc("getblock", json!([hash, false]))
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let version = i32::from_le_bytes(raw[..4].try_into().unwrap());
    let header_len = if version > 3 { 112 } else { 80 };
    let block = daemon.rpc("getblock", json!([hash]));
    let coinbase = block["tx"][0].as_str().unwrap().to_string();
    let tx = hex::decode(
        daemon
            .rpc("getrawtransaction", json!([coinbase]))
            .as_str()
            .unwrap(),
    )
    .unwrap();
    (raw[..header_len].to_vec(), tx)
}

/// A getdata of a filtered block is answered as Divi Core answers it
/// (main.cpp:249-278): a merkleblock of the block's header and partial merkle
/// tree, then each matched transaction; served whatever -peerbloomfilters
/// says, as every peer has a filter that matches all (Node.cpp:556)
#[test]
fn filtered_block_getdata_gets_a_merkleblock_and_the_matched_transactions() {
    for extra in [&[][..], &["-peerbloomfilters=0"][..]] {
        let daemon = Daemon::start(extra);
        daemon.rpc("setgenerate", json!([1]));
        let hash = daemon
            .rpc("getblockhash", json!([1]))
            .as_str()
            .unwrap()
            .to_string();
        let (header, coinbase) = header_and_coinbase(&daemon, &hash);

        let mut peer = Peer::connect(daemon.p2p_port, true);
        if extra.is_empty() {
            peer.send("filterload", &filterload(10, 0xff));
        }
        peer.send("getdata", &getdata(3, &hash));
        let got = peer.drain(Duration::from_secs(3));
        let merkle = got
            .iter()
            .find(|(c, _)| c == "merkleblock")
            .unwrap_or_else(|| {
                panic!(
                    "{extra:?}: no merkleblock in {:?}",
                    got.iter().map(|m| &m.0).collect::<Vec<_>>()
                )
            });
        assert_eq!(&merkle.1[..header.len()], &header[..], "{extra:?}: header");
        assert_eq!(
            u32::from_le_bytes(merkle.1[header.len()..header.len() + 4].try_into().unwrap()),
            1,
            "{extra:?}: one transaction"
        );
        assert!(
            got.iter().any(|(c, p)| c == "tx" && *p == coinbase),
            "{extra:?}: the matched coinbase was not sent"
        );

        if extra.is_empty() {
            // A filter that matches nothing: the merkleblock, and no transaction
            let mut peer = Peer::connect(daemon.p2p_port, true);
            peer.send("filterload", &filterload(10, 0));
            peer.send("getdata", &getdata(3, &hash));
            let got = peer.drain(Duration::from_secs(3));
            assert!(
                got.iter().any(|(c, _)| c == "merkleblock"),
                "empty filter: no merkleblock"
            );
            assert!(
                !got.iter().any(|(c, _)| c == "tx"),
                "empty filter: a tx was sent"
            );
        }
    }
}

/// Whether an inv of `txid` (display hex) came within the messages
fn inv_of(got: &[(String, Vec<u8>)], txid: &str) -> bool {
    let mut hash = hex::decode(txid).unwrap();
    hash.reverse();
    got.iter()
        .any(|(c, p)| c == "inv" && p.windows(32).any(|w| w == hash.as_slice()))
}

/// A new transaction is announced as Divi Core announces it
/// (net.cpp:1593-1606, main.cpp:388-391): not to a peer whose version asked
/// for no relay, nor to one whose filter does not match it; to a peer with no
/// filter message, and again after filterclear
#[test]
fn transactions_are_announced_by_each_peer_s_relay_flag_and_filter() {
    let daemon = Daemon::start(&[]);
    daemon.rpc("setgenerate", json!([101]));
    let mut quiet = Peer::connect(daemon.p2p_port, false);
    let mut plain = Peer::connect(daemon.p2p_port, true);
    let mut filtered = Peer::connect(daemon.p2p_port, true);
    filtered.send("filterload", &filterload(10, 0));
    std::thread::sleep(Duration::from_secs(1));

    let to = daemon.rpc("getnewaddress", json!([]));
    let txid = daemon.rpc("sendtoaddress", json!([to, 1]));
    let txid = txid.as_str().unwrap();
    assert!(
        inv_of(&plain.drain(Duration::from_secs(5)), txid),
        "no inv to a plain peer"
    );
    assert!(
        !inv_of(&quiet.drain(Duration::from_secs(1)), txid),
        "inv to a relay=0 peer"
    );
    assert!(
        !inv_of(&filtered.drain(Duration::from_secs(1)), txid),
        "inv past a filter"
    );

    filtered.send("filterclear", &[]);
    std::thread::sleep(Duration::from_secs(1));
    let second = daemon.rpc("sendtoaddress", json!([to, 1]));
    let second = second.as_str().unwrap();
    assert!(
        inv_of(&filtered.drain(Duration::from_secs(5)), second),
        "no inv after filterclear"
    );
}
