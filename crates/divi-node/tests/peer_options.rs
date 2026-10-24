// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Run-time peer options as Divi Core applies them: `-maxconnections` less
//! the 16 outbound slots is the number of inbound peers taken (net.cpp:757);
//! `-whitelist` and `-whitebind` peers are never punished and come in when
//! banned (net.cpp:742-766, main.cpp:1111-1114).

mod common;
use common::raw_peer::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_peers_stop_at_the_inbound_limit() {
    // -maxconnections=17: 16 outbound slots and one inbound
    let t = TestNode::start_with(|c| {
        c.p2p.max_outbound = 16;
        c.p2p.max_inbound = 1;
    })
    .await;
    let mut first = RawPeer::connect(&t, "127.0.0.2").await;
    first.handshake().await;

    let mut second = RawPeer::connect(&t, "127.0.0.3").await;
    second
        .send(
            "version",
            &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
        )
        .await;
    assert!(
        second.closed_within(WAIT).await,
        "a second inbound peer was taken with one inbound slot"
    );
    assert!(first.alive().await, "the first inbound peer was dropped");
}

fn addr_payload(count: usize) -> Vec<u8> {
    let mut v = compact(count as u64);
    for i in 0..count {
        v.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0]);
        v.extend_from_slice(&(i as u16).to_be_bytes());
        v.extend_from_slice(&51472u16.to_be_bytes());
    }
    v
}

/// A -whitelist peer that reaches the ban score is neither dropped nor
/// banned ("not punishing whitelisted peer", main.cpp:1111-1114); another
/// peer is dropped
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whitelisted_peer_is_kept_when_it_misbehaves() {
    let t = TestNode::start_with(|c| {
        c.p2p.whitelist = vec!["127.0.0.2".into()];
        c.p2p.ban_score = 40;
    })
    .await;
    let mut white = RawPeer::connect(&t, "127.0.0.2").await;
    white.handshake().await;
    let mut other = RawPeer::connect(&t, "127.0.0.3").await;
    other.handshake().await;
    for _ in 0..3 {
        white.send("addr", &addr_payload(1001)).await;
        other.send("addr", &addr_payload(1001)).await;
    }
    assert_eq!(t.wait_score(white.ip, 60).await, Some(60));
    assert!(white.alive().await, "the whitelisted peer was dropped");
    assert!(other.closed_within(WAIT).await, "the other peer was kept");
    let pm = t.node.peer_manager();
    let ids = pm.peer_ids_for_ip(white.ip);
    assert_eq!(ids.len(), 1);
    assert!(pm.is_whitelisted(ids[0]));
}

/// A whitelisted address comes in although it is banned (net.cpp:760)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whitelisted_peer_comes_in_though_banned() {
    let t = TestNode::start_with(|c| c.p2p.whitelist = vec!["127.0.0.0/30".into()]).await;
    let pm = t.node.peer_manager();
    for ip in ["127.0.0.2", "127.0.0.9"] {
        pm.ban_ip(
            ip.parse().unwrap(),
            std::time::Duration::from_secs(600),
            "test",
        );
    }
    let mut white = RawPeer::connect(&t, "127.0.0.2").await;
    white.handshake().await;
    assert!(white.alive().await);

    let mut banned = RawPeer::connect(&t, "127.0.0.9").await;
    banned
        .send(
            "version",
            &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
        )
        .await;
    assert!(banned.closed_within(WAIT).await, "a banned peer came in");
}

/// Peers coming in on a -whitebind address are whitelisted; those on the
/// listen address are not
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whitebind_peers_are_whitelisted() {
    let white_port = divi_test_support::free_port();
    let t = TestNode::start_with(|c| {
        c.p2p.white_bind = vec![std::net::SocketAddr::from(([127, 0, 0, 1], white_port))];
    })
    .await;
    // The -whitebind listener comes up on a task of its own
    let stream = tokio::time::timeout(divi_test_support::START_WAIT, async {
        loop {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.4:0".parse().unwrap()).unwrap();
            let to = std::net::SocketAddr::from(([127, 0, 0, 1], white_port));
            match socket.connect(to).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("the -whitebind address listens");
    let mut white = RawPeer {
        stream,
        ip: "127.0.0.4".parse().unwrap(),
    };
    white.handshake().await;
    let mut plain = RawPeer::connect(&t, "127.0.0.5").await;
    plain.handshake().await;

    let pm = t.node.peer_manager();
    let id = |ip: &str| pm.peer_ids_for_ip(ip.parse().unwrap())[0];
    assert!(pm.is_whitelisted(id("127.0.0.4")));
    assert!(!pm.is_whitelisted(id("127.0.0.5")));
}
