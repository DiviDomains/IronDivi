// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Masternode broadcasts and pings are announced by inv and fetched with
//! getdata, as divid relays them (CMasternodeBroadcast::Relay,
//! CMasternodePing::Relay; MSG_MASTERNODE_ANNOUNCE 14, MSG_MASTERNODE_PING 15),
//! each item asked for once.

mod common;
use common::raw_peer::*;

fn inv(items: &[(u32, [u8; 32])]) -> Vec<u8> {
    let mut v = compact(items.len() as u64);
    for (kind, hash) in items {
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(hash);
    }
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn announced_masternode_items_are_fetched_once() {
    let t = TestNode::start().await;
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;
    let items = [(14u32, [0x11u8; 32]), (15u32, [0x22u8; 32])];
    peer.send("inv", &inv(&items)).await;
    let asked = peer.expect("getdata", WAIT).await;
    assert_eq!(
        asked,
        Some(inv(&items)),
        "the announced broadcast and ping are asked for"
    );
    // The same items again are not asked for a second time
    peer.send("inv", &inv(&items)).await;
    assert_eq!(peer.expect("getdata", QUIET).await, None);
}
