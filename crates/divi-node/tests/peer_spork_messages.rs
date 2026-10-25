// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The spork messages as Divi Core answers them (spork.cpp ProcessSpork,
//! main.cpp inv and getdata): what a peer gets back for sporkcount, getsporks,
//! and the inventory of a spork.

mod common;
use common::raw_peer::*;

/// Read `n` inventory items from an `inv`, `getdata` or `notfound` payload
fn inv_items(payload: &[u8]) -> Vec<(u32, [u8; 32])> {
    let n = payload[0] as usize;
    (0..n)
        .map(|k| {
            let at = 1 + 36 * k;
            let kind = u32::from_le_bytes(payload[at..at + 4].try_into().unwrap());
            (kind, payload[at + 4..at + 36].try_into().unwrap())
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_sporkcount_is_answered_with_getsporks() {
    let t = TestNode::start().await;
    for (src, count) in [("127.0.0.2", 0i32), ("127.0.0.3", 5), ("127.0.0.4", -1)] {
        let mut peer = RawPeer::connect(&t, src).await;
        peer.handshake().await;
        peer.send("sporkcount", &count.to_le_bytes()).await;
        assert!(
            peer.expect("getsporks", WAIT).await.is_some(),
            "no getsporks after sporkcount {count}"
        );
    }
}
