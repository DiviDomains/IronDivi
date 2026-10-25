// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A pong that ends the node's ping without timing it, as Divi Core reads
//! one (nonce 0, or under 8 bytes: Node.cpp:754-808).

mod common;
use common::raw_peer::*;
use std::sync::atomic::Ordering;

/// A peer past the handshake that has read the node's first ping and left it
/// unanswered; the ping's nonce
async fn peer_with_a_ping_unanswered(t: &TestNode) -> (RawPeer, u64) {
    let mut p = RawPeer::connect(t, "127.0.0.2").await;
    p.handshake().await;
    let ping = p.expect("ping", WAIT).await.expect("the node pings");
    let nonce = u64::from_le_bytes(ping[..8].try_into().unwrap());
    (p, nonce)
}

/// Whether the node still waits for its ping to the peer from `p` (getpeerinfo
/// pingwait), once that settles to `want` within WAIT
async fn ping_outstanding(t: &TestNode, p: &RawPeer, want: bool) -> bool {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let now = t
            .node
            .peer_manager()
            .get_peer_details()
            .into_iter()
            .find(|(_, addr, _, _, _)| addr.ip() == p.ip)
            .is_some_and(|(_, _, _, stats, _)| stats.ping_sent_us.load(Ordering::Relaxed) != 0);
        if now == want || tokio::time::Instant::now() >= deadline {
            return now;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pong_with_nonce_zero_ends_the_ping() {
    let t = TestNode::start().await;
    let (mut p, _) = peer_with_a_ping_unanswered(&t).await;
    assert!(ping_outstanding(&t, &p, true).await);

    p.send("pong", &0u64.to_le_bytes()).await;
    assert!(!ping_outstanding(&t, &p, false).await, "the ping is ended");
    assert!(p.alive().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_pong_ends_the_ping_without_a_reject() {
    let t = TestNode::start().await;
    let (mut p, nonce) = peer_with_a_ping_unanswered(&t).await;
    assert!(ping_outstanding(&t, &p, true).await);

    p.send("pong", &(nonce as u32).to_le_bytes()).await;
    assert!(!ping_outstanding(&t, &p, false).await, "the ping is ended");
    assert_eq!(p.expect("reject", QUIET).await, None, "no reject");
}

/// Pings may overlap, so a pong with another nonce leaves the ping waiting
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pong_with_another_nonce_leaves_the_ping() {
    let t = TestNode::start().await;
    let (mut p, nonce) = peer_with_a_ping_unanswered(&t).await;

    p.send("pong", &(nonce ^ 1).to_le_bytes()).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(ping_outstanding(&t, &p, true).await);
    p.send("pong", &nonce.to_le_bytes()).await;
    assert!(!ping_outstanding(&t, &p, false).await);
}
