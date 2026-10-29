// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Message framing as Divi Core applies it (main.cpp ProcessReceivedMessages,
//! Node.cpp readHeader / DeserializeNetworkMessageFromBuffer): a wrong magic or
//! an oversized payload ends the connection, a bad checksum skips the message,
//! and a payload that does not parse gets `reject` "error parsing message"
//! while the connection stays up.

mod common;
use common::raw_peer::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_checksum_skips_the_message_only() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    let mut bad = frame("ping", &7u64.to_le_bytes());
    bad[20] ^= 0xff;
    p.send_raw(&bad).await;
    assert!(p.alive().await, "the connection survives a bad checksum");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unparseable_payload_gets_a_reject_and_the_connection_stays() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    // A ping needs an 8-byte nonce
    p.send("ping", &[1, 2]).await;
    let reject = p.expect("reject", WAIT).await.expect("reject");
    assert_eq!(
        parse_reject(&reject),
        ("ping".into(), 0x01, "error parsing message".into())
    );
    assert!(p.alive().await);
    assert_eq!(t.score(p.ip), Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_inventory_types_are_ignored() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    p.send("inv", &inv_payload(99, 3)).await;
    p.send("getdata", &inv_payload(99, 3)).await;
    assert!(
        p.alive().await,
        "unknown inv types do not end the connection"
    );
    assert_eq!(t.score(p.ip), Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_version_gets_a_reject() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;

    // Version, services and time only: the receiver's address is missing
    p.send("version", &version_payload(PROTOCOL_VERSION, 1, b"")[..20])
        .await;
    let reject = p.expect("reject", WAIT).await.expect("reject");
    assert_eq!(parse_reject(&reject).1, 0x01);
    // The handshake can still go ahead
    p.handshake().await;
    assert!(p.alive().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn minimal_version_is_accepted() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;

    // Divi Core reads the fields after the receiver's address only if present
    p.send("version", &version_payload(PROTOCOL_VERSION, 1, b"")[..46])
        .await;
    assert!(p.expect("version", WAIT).await.is_some());
    assert!(p.expect("verack", WAIT).await.is_some());
    p.send("verack", &[]).await;
    assert!(p.alive().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_magic_ends_the_connection() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    let mut wrong = frame("ping", &7u64.to_le_bytes());
    wrong[0] ^= 0xff;
    p.send_raw(&wrong).await;
    p.send("ping", &8u64.to_le_bytes()).await;
    assert!(
        p.closed_within(WAIT).await,
        "a wrong magic ends the connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn payload_over_two_mib_ends_the_connection() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    let mut header = frame("block", &[]);
    header[16..20].copy_from_slice(&(2 * 1024 * 1024 + 1u32).to_le_bytes());
    p.send_raw(&header).await;
    assert!(
        p.closed_within(WAIT).await,
        "an oversized payload ends the connection"
    );
}
