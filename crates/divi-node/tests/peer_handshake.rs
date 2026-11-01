// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The version handshake as Divi Core runs it (main.cpp SetPeerVersionAndServices
//! and ProcessMessage): a message before `version` costs 1, a second `version`
//! is rejected and costs 1, an obsolete protocol version is rejected,
//! disconnected and banned, and a connection to ourselves is dropped.

mod common;
use common::raw_peer::*;
use divi_network::PeerEvent;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn message_before_version_scores_one() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;

    p.send("ping", &7u64.to_le_bytes()).await;
    p.send("getaddr", &[]).await;
    assert_eq!(t.wait_score(p.ip, 2).await, Some(2));
    // The handshake still goes ahead
    p.handshake().await;
    assert!(p.alive().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_version_is_rejected_and_scores_one() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    p.send("version", &version_payload(PROTOCOL_VERSION, 5, b"/raw:1/"))
        .await;
    let reject = p.expect("reject", WAIT).await.expect("reject");
    assert_eq!(
        parse_reject(&reject),
        ("version".into(), 0x12, "Duplicate version message".into())
    );
    assert_eq!(t.wait_score(p.ip, 1).await, Some(1));
    assert!(p.alive().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn obsolete_version_is_rejected_and_banned() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.3").await;

    p.send("version", &version_payload(70914, 5, b"/old:1/"))
        .await;
    let reject = p.expect("reject", WAIT).await.expect("reject");
    assert_eq!(
        parse_reject(&reject),
        (
            "version".into(),
            0x11,
            "Version must be 70915 or greater".into()
        )
    );
    assert!(p.closed_within(WAIT).await);
    // Divi Core bans the address, even a local one
    let deadline = tokio::time::Instant::now() + WAIT;
    while !t.banned(p.ip) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(t.banned(p.ip));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_to_self_is_dropped() {
    let t = TestNode::build(|c| {
        c.p2p.connect = vec![format!("127.0.0.1:{}", c.p2p.port)];
    });
    let mut events = t.node.peer_manager().subscribe();
    t.run().await;

    let watch = async {
        let mut connected = 0;
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, events.recv()).await {
                // The harness's readiness probe counts as connected once its
                // version is read; only the node's own version is the self
                // connection
                Ok(Ok(PeerEvent::Connected { version, .. }))
                    if version.user_agent.starts_with("/IronDivi:") =>
                {
                    connected += 1
                }
                Ok(Ok(_)) => {}
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(_)) | Err(_) => return connected,
            }
        }
    };
    assert_eq!(watch.await, 0, "the node completed a handshake with itself");
}

/// The live stats getpeerinfo reads for the peer from `ip`, once it is listed
async fn peer_stats(t: &TestNode, ip: std::net::IpAddr) -> Arc<divi_network::LivePeerStats> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let found = t
            .node
            .peer_manager()
            .get_peer_details()
            .into_iter()
            .find(|(_, addr, _, _, _)| addr.ip() == ip);
        if let Some((_, _, _, stats, _)) = found {
            return stats;
        }
        assert!(tokio::time::Instant::now() < deadline, "peer listed");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Divi Core handles a message once the peer's version is in, before its
/// verack (main.cpp:484-514 checks only for the version): a ping between the
/// two is answered
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ping_between_version_and_verack_is_answered() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    assert!(p.expect("verack", WAIT).await.is_some(), "node verack");

    let nonce = 0x1122_3344_5566_7788u64.to_le_bytes();
    p.send("ping", &nonce).await;
    assert_eq!(p.expect("pong", WAIT).await, Some(nonce.to_vec()));
}

/// The other messages after the version are handled as they come, with no
/// verack from the peer: an inventory list over 50,000 items costs 20
/// (main.cpp:484-514 checks only for the version, :563-566)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn message_after_the_version_is_handled_without_a_verack() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    assert!(p.expect("verack", WAIT).await.is_some(), "node verack");

    p.send("inv", &inv_payload(1, 50_001)).await;
    assert_eq!(t.wait_score(p.ip, 20).await, Some(20));
    assert!(p.alive().await);
}

/// What goes out to an inbound peer once its version is handled comes before
/// its verack, which the node does not wait for: version, verack, sporkcount,
/// then a ping and getblocks (main.cpp:400-420, :454; net.cpp:871-893 sends
/// to any peer with a version, Node.cpp:1025-1036)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_peer_gets_sporkcount_ping_and_getblocks_before_its_verack() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + WAIT;
    while got.len() < 5 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match p.recv(left).await {
            Recv::Message(c, _) => got.push(c),
            Recv::Closed | Recv::Timeout => break,
        }
    }
    assert_eq!(
        got,
        ["version", "verack", "sporkcount", "ping", "getblocks"]
    );
}

/// getpeerinfo shows a peer's version, sub-version and start height as soon
/// as its version is read, before its verack (main.cpp:372-391 keeps them as
/// it reads them)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn getpeerinfo_shows_the_version_before_the_verack() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    assert!(p.expect("verack", WAIT).await.is_some(), "node verack");

    let stats = peer_stats(&t, p.ip).await;
    assert_eq!(
        stats.version.load(Ordering::Relaxed),
        PROTOCOL_VERSION as u64
    );
    assert_eq!(*stats.subver.lock(), "/raw:1/");
    assert_eq!(stats.start_height.load(Ordering::Relaxed), 0);
}

/// A peer that has sent no version yet shows start height -1, Divi Core's
/// nStartingHeight before a version names one (Node.cpp:561)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startingheight_is_minus_one_before_any_version() {
    let t = TestNode::start().await;
    let p = RawPeer::connect(&t, "127.0.0.2").await;

    let stats = peer_stats(&t, p.ip).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(stats.version.load(Ordering::Relaxed), 0);
    assert_eq!(stats.start_height.load(Ordering::Relaxed), -1);
}

/// What goes out to an outbound peer once its version is handled comes before
/// its verack, which the node does not wait for: after the node's version, a
/// verack and getaddr (main.cpp:415-442)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_peer_gets_verack_and_getaddr_before_its_verack() {
    let listener = tokio::net::TcpListener::bind("127.0.0.3:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _t = TestNode::start_with(|c| c.p2p.connect = vec![addr.to_string()]).await;
    let (stream, _) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .expect("the node dials")
        .unwrap();
    let mut p = RawPeer {
        stream,
        ip: addr.ip(),
    };
    assert!(p.expect("version", WAIT).await.is_some(), "node version");
    p.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + WAIT;
    while got.len() < 2 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match p.recv(left).await {
            Recv::Message(c, _) => got.push(c),
            Recv::Closed | Recv::Timeout => break,
        }
    }
    assert_eq!(got, ["verack", "getaddr"]);
}
