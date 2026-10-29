// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Sporks as Divi Core takes them (spork.cpp ProcessSpork): a new spork must be
//! signed by the network's spork key, or the peer gets Misbehaving(100) and the
//! spork is dropped, so it is never served to others.

mod common;
use common::raw_peer::*;

fn spork_payload(id: i32, value: &str, time: i64, sig: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&compact(value.len() as u64));
    v.extend_from_slice(value.as_bytes());
    v.extend_from_slice(&time.to_le_bytes());
    v.extend_from_slice(&compact(sig.len() as u64));
    v.extend_from_slice(sig);
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spork_with_a_bad_signature_scores_100_and_is_dropped() {
    let t = TestNode::start().await;
    let mut forger = RawPeer::connect(&t, "127.0.0.2").await;
    forger.handshake().await;

    let mut sig = vec![0x1f];
    sig.extend_from_slice(&[0x42; 64]);
    forger
        .send("spork", &spork_payload(10007, "0", 1_900_000_000, &sig))
        .await;
    // Local peers are disconnected at the ban score, not banned
    assert!(forger.closed_within(WAIT).await, "the peer was not dropped");

    // The spork is not served to anyone
    let mut other = RawPeer::connect(&t, "127.0.0.4").await;
    other.handshake().await;
    other.send("getsporks", &[]).await;
    assert_eq!(other.expect("spork", QUIET).await, None);
}
