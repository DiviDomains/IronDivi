// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Which peers are dialled, as Divi Core decides it (net.cpp
//! OpenNetworkConnection, ThreadOpenAddedConnections, ThreadOpenConnections):
//! `-addnode` and `addnode … add` entries are skipped while any peer from the
//! same IP is connected, inbound or outbound; `-connect` entries are dialled
//! by address and port, so several on one IP are all dialled.

mod common;
use common::raw_peer::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// The node's maintenance pass that retries added peers runs every 30 s
const MAINTENANCE: Duration = Duration::from_secs(35);

/// A listener on `ip` that plays Divi Core's inbound side for every
/// connection it accepts and counts them
async fn core_listener(ip: &str) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, from)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut core = RawPeer {
                    stream,
                    ip: from.ip(),
                };
                if core.expect("version", WAIT).await.is_none() {
                    return;
                }
                core.send(
                    "version",
                    &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
                )
                .await;
                core.send("verack", &[]).await;
                core.send("sporkcount", &0i32.to_le_bytes()).await;
                // Hold the connection until the node drops it
                while !matches!(core.recv(WAIT).await, Recv::Closed) {}
            });
        }
    });
    (addr, accepted)
}

/// Wait until `pred` holds, at most `within`
async fn wait_until(within: Duration, pred: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    pred()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn addnode_entries_on_one_ip_are_dialled_once() {
    let (a, a_accepted) = core_listener("127.0.0.1").await;
    let (b, b_accepted) = core_listener("127.0.0.1").await;
    let t = TestNode::start_with(|c| {
        c.network.static_peers = vec![a.to_string(), b.to_string()];
    })
    .await;

    let total = || a_accepted.load(Ordering::SeqCst) + b_accepted.load(Ordering::SeqCst);
    assert!(
        wait_until(WAIT, || total() >= 1).await,
        "no addnode dialled"
    );
    // Give a second dial time to show up
    tokio::time::sleep(QUIET).await;
    assert_eq!(total(), 1, "both addnode entries on 127.0.0.1 were dialled");
    assert_eq!(t.node.peer_manager().outbound_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn added_node_is_not_dialled_while_a_peer_from_its_ip_is_connected() {
    let t = TestNode::start().await;
    let mut inbound = RawPeer::connect(&t, "127.0.0.3").await;
    inbound.handshake().await;

    let (busy, busy_accepted) = core_listener("127.0.0.3").await;
    let (free, free_accepted) = core_listener("127.0.0.4").await;
    let pm = t.node.peer_manager();
    assert!(pm.add_node(busy));
    assert!(pm.add_node(free));

    // The node dials the added peer on the free IP at its next pass...
    assert!(
        wait_until(MAINTENANCE, || free_accepted.load(Ordering::SeqCst) == 1).await,
        "the added node on a free IP was not dialled"
    );
    tokio::time::sleep(QUIET).await;
    // ...but not the one whose IP already has an (inbound) peer
    assert_eq!(
        busy_accepted.load(Ordering::SeqCst),
        0,
        "dialled an added node whose IP already has a peer"
    );
    assert!(inbound.alive().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_entries_on_one_ip_are_each_dialled() {
    let (a, a_accepted) = core_listener("127.0.0.1").await;
    let (b, b_accepted) = core_listener("127.0.0.1").await;
    let t = TestNode::start_with(|c| {
        c.p2p.connect = vec![a.to_string(), b.to_string()];
    })
    .await;

    assert!(
        wait_until(WAIT, || a_accepted.load(Ordering::SeqCst) == 1
            && b_accepted.load(Ordering::SeqCst) == 1)
        .await,
        "not every -connect entry was dialled"
    );
    // The listeners count a connection at accept, before the handshake that
    // registers the peer, so wait for both peers to be registered
    let pm = t.node.peer_manager();
    assert!(
        wait_until(WAIT, || pm.outbound_count() == 2).await,
        "-connect peers registered: {}",
        pm.outbound_count()
    );
}
