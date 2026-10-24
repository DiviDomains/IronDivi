// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The spork count as Divi Core sends it (main.cpp SetPeerVersionAndServices):
//! after the handshake an inbound peer is told how many sporks we hold. A Divi
//! Core node that dialled us sends it nothing else (no block or tx inv, no
//! getblocks, no getdata) until it has that many sporks from us (Node.cpp
//! CanSendMessagesToPeer, spork.cpp ProcessSpork). A peer we dialled is not
//! sent the count. Divi Core waits for no sporks from a peer that dialled it
//! (net.cpp GetSporkSyncedOrInboundNodes) and such a peer sends it none, so
//! block sync from it starts at once.

mod common;
use common::raw_peer::*;
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_peer_is_sent_the_spork_count_it_can_sync() {
    let t = TestNode::start().await;
    let mut core = RawPeer::connect(&t, "127.0.0.2").await;
    core.handshake().await;

    let count = core
        .expect("sporkcount", WAIT)
        .await
        .expect("no sporkcount sent to an inbound peer");
    assert_eq!(count, 0i32.to_le_bytes());

    // getsporks serves as many sporks as the count said
    core.send("getsporks", &[]).await;
    assert_eq!(core.expect("spork", QUIET).await, None);
    assert!(core.alive().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_peer_is_not_sent_the_spork_count() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _t = TestNode::start_with(|c| {
        c.p2p.connect = vec![format!("127.0.0.1:{port}")];
    })
    .await;

    let (stream, addr) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .expect("node dials in time")
        .unwrap();
    let mut core = RawPeer {
        stream,
        ip: addr.ip(),
    };
    // Divi Core's inbound side: version, verack, sporkcount
    assert!(core.expect("version", WAIT).await.is_some(), "node version");
    core.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    core.send("verack", &[]).await;
    core.send("sporkcount", &0i32.to_le_bytes()).await;
    assert!(core.expect("verack", WAIT).await.is_some(), "node verack");

    assert_eq!(core.expect("sporkcount", QUIET).await, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn block_sync_from_an_inbound_peer_does_not_wait_for_sporks() {
    let t = TestNode::start().await;
    let mut core = RawPeer::connect(&t, "127.0.0.2").await;
    // Divi Core's outbound side at height 25: version, verack, no sporkcount
    let mut version = version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/");
    let at = version.len() - 5;
    version[at..at + 4].copy_from_slice(&25i32.to_le_bytes());
    core.send("version", &version).await;
    assert!(core.expect("verack", WAIT).await.is_some(), "node verack");
    core.send("verack", &[]).await;

    assert!(
        core.expect("getblocks", WAIT).await.is_some(),
        "no getblocks to an inbound peer that is ahead"
    );
}
