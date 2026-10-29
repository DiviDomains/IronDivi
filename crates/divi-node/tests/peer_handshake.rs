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
                Ok(Ok(PeerEvent::Connected { .. })) => connected += 1,
                Ok(Ok(_)) => {}
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(_)) | Err(_) => return connected,
            }
        }
    };
    assert_eq!(watch.await, 0, "the node completed a handshake with itself");
}
