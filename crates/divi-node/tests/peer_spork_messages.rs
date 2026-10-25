// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The spork messages as Divi Core answers them (spork.cpp ProcessSpork,
//! main.cpp inv and getdata): what a peer gets back for sporkcount, getsporks,
//! and the inventory of a spork.

mod common;
use common::raw_peer::*;
use divi_network::SporkMessage;
use divi_node::config::NodeConfig;
use divi_storage::ChainDatabase;

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

/// A stored spork. Divi Core loads the sporks of its database without
/// checking them again, so the signature here is only bytes (spork.cpp
/// LoadSporksFromDB); a node can start with sporks no key here could sign.
fn stored(id: i32, value: &str, time: i64) -> SporkMessage {
    SporkMessage {
        spork_id: id,
        value: value.into(),
        time_signed: time,
        signature: vec![0x1f; 65],
    }
}

/// Put sporks in the database a node is about to open
fn seed(config: &mut NodeConfig, sporks: &[SporkMessage]) {
    std::fs::create_dir_all(config.chainstate_path()).unwrap();
    let db = ChainDatabase::open(config.chainstate_path()).unwrap();
    for spork in sporks {
        db.put_metadata(
            format!("spork_{}", spork.spork_id).as_bytes(),
            &spork.serialize(),
        )
        .unwrap();
    }
}

fn spork_id(payload: &[u8]) -> i32 {
    i32::from_le_bytes(payload[..4].try_into().unwrap())
}

/// Divi Core keeps its active sporks in a std::map and serves them in ID order
/// (spork.cpp:261-267)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn getsporks_serves_the_sporks_in_id_order() {
    let ids = [
        10015, 10001, 10012, 10007, 10013, 10002, 10011, 10009, 10004, 10008, 10014,
    ];
    let sporks: Vec<_> = ids.iter().map(|&id| stored(id, "1", 1000)).collect();
    let t = TestNode::start_with(|c| seed(c, &sporks)).await;
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;
    peer.send("getsporks", &[]).await;
    let mut served = Vec::new();
    for _ in ids {
        let payload = peer.expect("spork", WAIT).await.expect("a spork");
        served.push(spork_id(&payload));
    }
    let mut sorted = ids.to_vec();
    sorted.sort();
    assert_eq!(served, sorted);
}
