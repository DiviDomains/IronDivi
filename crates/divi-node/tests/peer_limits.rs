// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Per-message limits and scores as Divi Core applies them (main.cpp
//! ProcessMessage): more than 1000 addresses or 50,000 inventory items cost
//! 20, bloom filter messages cost 100 when bloom filters are not offered, and
//! an alert that cannot be accepted costs 10.

mod common;
use common::raw_peer::*;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn more_than_1000_addresses_score_20() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    p.send("addr", &addr_payload(1000)).await;
    assert!(p.alive().await);
    assert_eq!(t.score(p.ip), Some(0));
    p.send("addr", &addr_payload(1001)).await;
    assert_eq!(t.wait_score(p.ip, 20).await, Some(20));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn more_than_50000_inventory_items_score_20() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    p.send("inv", &inv_payload(1, 50_001)).await;
    assert_eq!(t.wait_score(p.ip, 20).await, Some(20));
    p.send("getdata", &inv_payload(1, 50_001)).await;
    assert_eq!(t.wait_score(p.ip, 40).await, Some(40));
    // Nothing is asked for or served from an oversized list
    assert!(p.alive().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bloom_filter_messages_score_100() {
    for (command, payload) in [
        ("filterload", vec![1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ("filteradd", vec![1u8, 0]),
        ("filterclear", vec![]),
    ] {
        let t = TestNode::start().await;
        let mut p = RawPeer::connect(&t, "127.0.0.2").await;
        p.handshake().await;
        p.send(command, &payload).await;
        // A local peer is disconnected at the ban score (Divi Core does not ban it)
        assert!(
            p.closed_within(WAIT).await,
            "{} did not end the connection",
            command
        );
    }
}

fn alert_payload() -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&1i32.to_le_bytes());
    msg.extend_from_slice(&0i64.to_le_bytes());
    msg.extend_from_slice(&i64::MAX.to_le_bytes());
    msg.extend_from_slice(&7i32.to_le_bytes());
    msg.extend_from_slice(&0i32.to_le_bytes());
    msg.push(0);
    msg.extend_from_slice(&0i32.to_le_bytes());
    msg.extend_from_slice(&i32::MAX.to_le_bytes());
    msg.push(0);
    msg.extend_from_slice(&1i32.to_le_bytes());
    msg.extend_from_slice(&[0, 0, 0]);
    // Not signed by the alert key
    let sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    let mut v = compact(msg.len() as u64);
    v.extend_from_slice(&msg);
    v.extend_from_slice(&compact(sig.len() as u64));
    v.extend_from_slice(&sig);
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alert_that_cannot_be_accepted_scores_10() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    p.send("alert", &alert_payload()).await;
    assert_eq!(t.wait_score(p.ip, 10).await, Some(10));
    // Each one costs again: a refused alert is not remembered
    p.send("alert", &alert_payload()).await;
    assert_eq!(t.wait_score(p.ip, 20).await, Some(20));

    // An alert that does not parse is malformed
    p.send("alert", &[0xfd]).await;
    let reject = p.expect("reject", WAIT).await.expect("reject");
    assert_eq!(parse_reject(&reject).0, "alert");
    assert_eq!(t.score(p.ip), Some(20));
}
