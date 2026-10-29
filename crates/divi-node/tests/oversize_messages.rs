// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Oversize inv, getdata and addr messages are refused with a misbehaviour
//! score of 20, as Divi Core does (main.cpp:529-531 addr over 1000 entries,
//! :563-565 inv and :617-619 getdata over MAX_INV_SZ = 50000, Node.h:27).
//! One such message leaves the peer connected and below the ban score (100);
//! the limit itself is not refused; four leave it at 80; the fifth reaches
//! the ban score and the peer is disconnected (a local one is not banned).

mod common;

use common::raw_peer::*;
use std::time::Duration;

const MAX_INV_SZ: usize = 50_000;
const MAX_ADDR: usize = 1000;

/// An addr payload with `count` entries (time, services, IPv4-mapped address, port)
fn addr_payload(count: usize) -> Vec<u8> {
    let mut v = compact(count as u64);
    for i in 0..count {
        v.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..].copy_from_slice(&[1, 2, (i >> 8) as u8, i as u8]);
        v.extend_from_slice(&ip);
        v.extend_from_slice(&51476u16.to_be_bytes());
    }
    v
}

/// (command, payload over the limit, payload at the limit)
fn cases() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    vec![
        // MSG_TX items: a block inv at the limit would start a download
        (
            "inv",
            inv_payload(1, MAX_INV_SZ + 1),
            inv_payload(1, MAX_INV_SZ),
        ),
        (
            "getdata",
            inv_payload(1, MAX_INV_SZ + 1),
            inv_payload(1, MAX_INV_SZ),
        ),
        ("addr", addr_payload(MAX_ADDR + 1), addr_payload(MAX_ADDR)),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_oversize_message_scores_20_and_keeps_the_peer() {
    let t = TestNode::start().await;
    for (i, (command, over, _)) in cases().into_iter().enumerate() {
        let mut p = RawPeer::connect(&t, &format!("127.0.0.{}", 10 + i)).await;
        p.handshake().await;
        p.send(command, &over).await;
        assert_eq!(t.wait_score(p.ip, 20).await, Some(20), "{command}");
        assert!(p.alive().await, "{command}: the peer stays connected");
        assert!(!t.banned(p.ip), "{command}: not banned below 100");
        // and nothing more is scored for it
        tokio::time::sleep(QUIET).await;
        assert_eq!(t.score(p.ip), Some(20), "{command}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_at_the_limit_is_not_refused() {
    let t = TestNode::start().await;
    for (i, (command, _, at)) in cases().into_iter().enumerate() {
        let mut p = RawPeer::connect(&t, &format!("127.0.0.{}", 20 + i)).await;
        p.handshake().await;
        p.send(command, &at).await;
        assert!(p.alive().await, "{command}");
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(t.score(p.ip).unwrap_or(0), 0, "{command}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fifth_oversize_message_disconnects_the_peer() {
    let t = TestNode::start().await;
    for (i, (command, over, _)) in cases().into_iter().enumerate() {
        let mut p = RawPeer::connect(&t, &format!("127.0.0.{}", 30 + i)).await;
        p.handshake().await;
        for _ in 0..4 {
            p.send(command, &over).await;
        }
        assert_eq!(t.wait_score(p.ip, 80).await, Some(80), "{command}");
        assert!(p.alive().await, "{command}: still connected at 80");
        assert!(!t.banned(p.ip), "{command}");
        // The fifth brings it to the ban score: disconnected. The test peers
        // are on loopback, which Divi Core disconnects but does not ban
        // ("not banning local peer", main.cpp:1117-1121).
        p.send(command, &over).await;
        assert!(p.closed_within(WAIT).await, "{command}: disconnected");
        assert!(!t.banned(p.ip), "{command}: a local peer is not banned");
    }
}
