// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Masternode broadcasts and pings are announced by inv and fetched with
//! getdata, as divid relays them (CMasternodeBroadcast::Relay,
//! CMasternodePing::Relay, CMasternodePaymentWinner::Relay; MSG_MASTERNODE_ANNOUNCE
//! 14, MSG_MASTERNODE_PING 15, MSG_MASTERNODE_WINNER 7),
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
    let items = [
        (14u32, [0x11u8; 32]),
        (15u32, [0x22u8; 32]),
        (7u32, [0x33u8; 32]),
    ];
    peer.send("inv", &inv(&items)).await;
    let asked = peer.expect("getdata", WAIT).await;
    assert_eq!(
        asked,
        Some(inv(&items)),
        "the announced broadcast, ping and payment vote are asked for"
    );
    // The same items again are not asked for a second time
    peer.send("inv", &inv(&items)).await;
    assert_eq!(peer.expect("getdata", QUIET).await, None);
}

/// Masternode items the node does not have are answered with notfound, as
/// divid's ProcessGetData answers what PushKnownInventory cannot send
/// (main.cpp:165-212, :322-345)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_masternode_items_asked_for_are_not_found() {
    let t = TestNode::start().await;
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;
    let items = [
        (14u32, [0x44u8; 32]),
        (15u32, [0x55u8; 32]),
        (7u32, [0x66u8; 32]),
    ];
    peer.send("getdata", &inv(&items)).await;
    assert_eq!(peer.expect("notfound", WAIT).await, Some(inv(&items)));
}

/// Transaction lock requests and votes (MSG_TXLOCK_REQUEST 4, MSG_TXLOCK_VOTE
/// 5) are asked for when announced: Divi Core's AlreadyHave is false for them
/// (main.cpp:143-146, :580-581)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn announced_transaction_lock_items_are_asked_for() {
    let t = TestNode::start().await;
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;
    let items = [(4u32, [0x77u8; 32]), (5u32, [0x88u8; 32])];
    peer.send("inv", &inv(&items)).await;
    assert_eq!(peer.expect("getdata", WAIT).await, Some(inv(&items)));
}
