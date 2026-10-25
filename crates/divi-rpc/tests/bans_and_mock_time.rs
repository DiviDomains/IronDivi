// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Replies of the divid calls no other replies script makes, as Divi Core
//! 3.0.0's divid gives them: listlockunspent, getrawchangeaddress, loadwallet,
//! validateaddress of a change key, signtransactionwithaddresskey and

//! `ban outdated` against raw peers of a listening regtest PeerManager, and
//! setmocktime moving what divid reads from GetTime: a peer's conntime, a
//! ban's end, and the newest block time the chain takes. The clock is one for
//! the process, so the tests take a lock and set it back to 0.

use divi_network::{
    regtest_peer_manager, NetworkMessage, PeerManager, VersionMessage, REGTEST_MAGIC,
};
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

static CLOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn regtest_server() -> (RpcServer, Arc<Chain>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    (RpcServer::new(chain.clone()), chain, dir)
}

fn call(server: &RpcServer, method: &str, params: Vec<Value>) -> Result<Value, (i32, String)> {
    let r = server.handle_request(Request {
        jsonrpc: "1.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    });
    match r.error {
        Some(e) => Err((e.code, e.message)),
        None => Ok(r.result.unwrap_or(Value::Null)),
    }
}

/// A PeerManager listening on a free loopback port
async fn listening() -> (Arc<PeerManager>, SocketAddr) {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let pm = regtest_peer_manager(Some(addr));
    tokio::spawn(pm.clone().start());
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "the peer manager did not listen");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (pm, addr)
}

/// A raw peer with this sub-version, through the handshake
fn raw_peer(to: SocketAddr, subver: &str) -> TcpStream {
    let mut s = TcpStream::connect(to).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let version = VersionMessage {
        version: 70920,
        services: 1,
        timestamp: 0,
        addr_recv: divi_network::NetAddr::from_socket_addr(to, 1),
        addr_from: divi_network::NetAddr::from_socket_addr(s.local_addr().unwrap(), 1),
        nonce: rand::random(),
        user_agent: subver.to_string(),
        start_height: 0,
        relay: true,
    };
    s.write_all(
        &NetworkMessage::Version(version)
            .to_bytes(REGTEST_MAGIC)
            .unwrap(),
    )
    .unwrap();
    s.write_all(&NetworkMessage::Verack.to_bytes(REGTEST_MAGIC).unwrap())
        .unwrap();
    // Read until the node's verack
    loop {
        let mut head = [0u8; 24];
        s.read_exact(&mut head).unwrap();
        let size = u32::from_le_bytes(head[16..20].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; size];
        s.read_exact(&mut payload).unwrap();
        if head[4..16].starts_with(b"verack\0") {
            return s;
        }
    }
}

/// Whether the node has closed the connection within `secs`
fn closed(s: &mut TcpStream, secs: u64) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match s.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return true,
        }
    }
    false
}

async fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn subvers(server: &RpcServer) -> Vec<String> {
    let peers = call(server, "getpeerinfo", vec![]).unwrap();
    let mut out: Vec<String> = peers
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["subver"].as_str().unwrap_or("").to_string())
        .collect();
    out.sort();
    out
}

/// ban outdated bans each peer below Divi Core 3.0.0.0, as ip:port, and drops
/// it (net.cpp:357-393); a peer whose sub-version divid could not read is
/// left alone
#[tokio::test(flavor = "multi_thread")]
async fn ban_outdated_bans_the_peers_below_divi_core_3() {
    let (server, _chain, _dir) = regtest_server();
    let (pm, addr) = listening().await;
    server.set_peer_manager(pm.clone());
    assert_eq!(
        call(&server, "ban", vec![json!("outdated")]),
        Ok(json!({"Banned": []}))
    );

    let mut old = raw_peer(addr, "Divi Core: 2.4.0.0");
    let mut new = raw_peer(addr, "Divi Core: 3.0.0.0");
    let mut odd = raw_peer(addr, "/IronDivi:0.2.6/");
    wait_for("the three sub-versions", || {
        subvers(&server)
            == [
                "/IronDivi:0.2.6/",
                "Divi Core: 2.4.0.0",
                "Divi Core: 3.0.0.0",
            ]
    })
    .await;
    let old_addr = old.local_addr().unwrap().to_string();
    assert_eq!(
        call(&server, "ban", vec![json!("outdated")]),
        Ok(json!({ "Banned": [old_addr] }))
    );
    assert!(closed(&mut old, 10), "the outdated peer is dropped");
    assert!(
        !closed(&mut new, 1) && !closed(&mut odd, 1),
        "the others stay"
    );
    assert!(pm.is_banned(&"127.0.0.1".parse().unwrap()));
}

/// setmocktime sets the clock on regtest: a peer connecting then has that
/// conntime, a ban ends by that clock, and a block up to two hours past it is
/// not too new (Core GetTime, GetAdjustedTime; BlockCheckingHelpers.cpp:29-31)
#[tokio::test(flavor = "multi_thread")]
async fn setmocktime_moves_peer_times_and_ban_ends() {
    let _clock = CLOCK.lock().await;
    let (server, _chain, _dir) = regtest_server();
    let (pm, addr) = listening().await;
    server.set_peer_manager(pm.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mock = now + 86_400;
    assert_eq!(
        call(&server, "setmocktime", vec![json!(mock)]),
        Ok(Value::Null)
    );

    let _peer = raw_peer(addr, "Divi Core: 3.0.0.0");
    wait_for("the peer's conntime", || {
        call(&server, "getpeerinfo", vec![]).unwrap()[0]["conntime"] == json!(mock)
    })
    .await;

    pm.ban_ip(
        "192.0.2.7".parse().unwrap(),
        Duration::from_secs(60),
        "test",
    );
    let bans = call(&server, "listbanned", vec![]).unwrap();
    assert_eq!(bans[0]["banned_until"], json!(mock + 60));
    call(&server, "setmocktime", vec![json!(mock + 61)]).unwrap();
    assert_eq!(
        call(&server, "listbanned", vec![]),
        Ok(json!([])),
        "the ban ended"
    );

    assert_eq!(
        call(&server, "setmocktime", vec![json!(0)]),
        Ok(Value::Null)
    );
    let bans_again = {
        pm.ban_ip(
            "192.0.2.8".parse().unwrap(),
            Duration::from_secs(60),
            "test",
        );
        call(&server, "listbanned", vec![]).unwrap()
    };
    let until = bans_again[0]["banned_until"].as_i64().unwrap();
    assert!(
        (until - (now + 60)).abs() < 30,
        "back on the system clock: {until}"
    );
}

/// A work block at `time` on the tip, paying nobody
fn block_at(chain: &Chain, time: u32) -> divi_primitives::block::Block {
    use divi_primitives::{amount::Amount, block::Block, script::Script, transaction::*};
    let tip = chain.tip().unwrap();
    let height = tip.height + 1;
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = tip.hash;
    block.header.time = time;
    block.header.bits = 0x207fffff;
    let mut cb_sig = divi_storage::bip34_height_script(height);
    cb_sig.extend_from_slice(&height.to_le_bytes());
    block.transactions.push(Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(cb_sig))],
        vout: vec![TxOut::new(
            Amount::from_sat(0),
            Script::from_bytes(vec![0x6a]),
        )],
        lock_time: 0,
    });
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    block
}

/// A block a day ahead is too new on the system clock, and taken with the
/// clock set a day ahead (CheckBlock against GetAdjustedTime)
#[tokio::test]
async fn a_block_is_too_new_by_the_mocked_clock() {
    let _clock = CLOCK.lock().await;
    let (server, chain, _dir) = regtest_server();
    let ahead = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
        + 86_400;
    assert!(
        chain.accept_block(block_at(&chain, ahead)).is_err(),
        "too new on the system clock"
    );
    assert_eq!(
        call(&server, "setmocktime", vec![json!(ahead)]),
        Ok(Value::Null)
    );
    let taken = chain.accept_block(block_at(&chain, ahead));
    call(&server, "setmocktime", vec![json!(0)]).unwrap();
    taken.expect("taken with the clock a day ahead");
}
