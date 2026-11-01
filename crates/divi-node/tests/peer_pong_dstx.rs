// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Two messages a peer sends rarely, answered as Divi Core answers them: a
//! pong that ends the node's ping without timing it (nonce 0, or under 8
//! bytes: Node.cpp:754-808), and a dstx, which divid checks as an empty
//! transaction (main.cpp:705-812). And the order of the answers: a pong
//! comes after the answers to the messages before its ping.

mod common;
use common::raw_peer::*;
use std::sync::atomic::Ordering;
use std::time::Duration;

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

/// divid answers a dstx with reject bad-tx and the empty transaction's hash
/// (all zeros: never computed), and the score of 110 drops the peer
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dstx_is_rejected_and_drops_the_peer() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    p.send("dstx", &[]).await;
    let reject = p.expect("reject", WAIT).await.expect("reject");
    assert_eq!(
        parse_reject(&reject),
        ("dstx".into(), 0x10, "bad-tx".into())
    );
    // "dstx", the code, "bad-tx", then the hash
    assert_eq!(reject.len(), 1 + 4 + 1 + 1 + 6 + 32);
    assert_eq!(&reject[13..], &[0u8; 32]);
    assert!(p.closed_within(WAIT).await);
}

/// With -banscore 1000 the peer stays, and its score is 110
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dstx_scores_110() {
    let t = TestNode::start().await;
    t.node
        .peer_manager()
        .scoring()
        .set_ban_policy(1000, std::time::Duration::from_secs(60));
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    p.send("dstx", &[1, 2, 3]).await;
    assert_eq!(t.wait_score(p.ip, 110).await, Some(110));
    assert!(p.alive().await);
}

/// A peer's messages are answered in the order they came, the ones the
/// connection answers itself included: Divi Core handles them one at a time
/// (main.cpp:1023-1077), so the notfound of a getdata comes before the reject
/// of a malformed message sent after it, and that before the pong of a ping
/// sent last, even when all come in one write and the getdata takes long
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_come_in_the_order_of_the_messages() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.3").await;
    p.handshake().await;
    while let Recv::Message(..) = p.recv(Duration::from_secs(2)).await {}
    // The most items a getdata may name (MAX_INV_SZ), none of them known
    let mut items = compact(50_000);
    for n in 0..50_000u32 {
        items.extend_from_slice(&1u32.to_le_bytes());
        let mut hash = [0x5a; 32];
        hash[..4].copy_from_slice(&n.to_le_bytes());
        items.extend_from_slice(&hash);
    }
    let mut burst = frame("getdata", &items);
    // A spork that does not parse: answered by the connection itself
    burst.extend(frame("spork", &[1, 2]));
    let nonce = rand_nonce();
    burst.extend(frame("ping", &nonce.to_le_bytes()));
    p.send_raw(&burst).await;
    let mut got = Vec::new();
    loop {
        match p.recv(WAIT).await {
            Recv::Message(c, m) if c == "pong" && m == nonce.to_le_bytes() => break,
            Recv::Message(c, _) if c == "ping" || c == "pong" => {}
            Recv::Message(c, _) => got.push(c),
            other => panic!("no pong: {other:?} after {got:?}"),
        }
    }
    got.dedup();
    assert_eq!(got, vec!["notfound".to_string(), "reject".to_string()]);
}
