// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Masternode messages from peers are not passed on, and `dseg` is not
//! answered: Divi Core relays an entry, or announces it on `dseg`, only after
//! checking its signatures and collateral (masternodeman.cpp, masternode-sync.cpp),
//! which IronDivi does not do.

mod common;
use common::raw_peer::*;
use divi_masternode::{
    MasternodeBroadcast, MasternodePing, MasternodeTier, RequestMasternodeList, ServiceAddr,
};
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::OutPoint;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A broadcast with the right shape and no valid signature
fn forged_broadcast() -> Vec<u8> {
    let mnb = MasternodeBroadcast::new(
        OutPoint::new(Hash256::from_bytes([7; 32]), 0),
        ServiceAddr::new("[::ffff:10.1.2.3]:51472".parse().unwrap()),
        vec![2; 33],
        vec![3; 33],
        MasternodeTier::Gold,
        PROTOCOL_VERSION,
        now(),
    );
    serialize(&mnb)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn masternode_messages_from_peers_are_not_relayed() {
    let t = TestNode::start().await;
    let mut sender = RawPeer::connect(&t, "127.0.0.2").await;
    sender.handshake().await;
    let mut other = RawPeer::connect(&t, "127.0.0.4").await;
    other.handshake().await;

    sender.send("mnb", &forged_broadcast()).await;
    let ping = MasternodePing::new(
        OutPoint::new(Hash256::from_bytes([7; 32]), 0),
        Hash256::from_bytes([9; 32]),
        now(),
    );
    sender.send("mnp", &serialize(&ping)).await;

    let deadline = tokio::time::Instant::now() + QUIET;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match other.recv(left).await {
            Recv::Message(c, _) if c == "mnb" || c == "mnp" => {
                panic!("{} from a peer was passed on", c)
            }
            Recv::Message(..) => continue,
            Recv::Closed => panic!("connection closed"),
            Recv::Timeout => break,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dseg_is_not_answered_with_unchecked_entries() {
    let t = TestNode::start().await;
    let mut sender = RawPeer::connect(&t, "127.0.0.2").await;
    sender.handshake().await;
    sender.send("mnb", &forged_broadcast()).await;
    assert!(sender.alive().await);

    let mut asker = RawPeer::connect(&t, "127.0.0.4").await;
    asker.handshake().await;
    asker
        .send("dseg", &serialize(&RequestMasternodeList::new()))
        .await;
    assert_eq!(asker.expect("mnb", QUIET).await, None, "dseg answered");
}
