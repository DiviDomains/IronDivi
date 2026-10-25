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

/// Divi Core loads only the ids it has a name for (spork.cpp:196-197): a stored
/// spork of any other id is not active after a restart, is not counted and is
/// not served
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stored_sporks_of_unnamed_ids_are_not_loaded() {
    let sporks = [
        stored(10007, "1", 1000),
        stored(10003, "1", 1000),
        stored(10005, "1", 1000),
        stored(10010, "1", 1000),
        stored(10099, "1", 1000),
    ];
    let t = TestNode::start_with(|c| seed(c, &sporks)).await;
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;
    let count = peer.expect("sporkcount", WAIT).await.expect("sporkcount");
    assert_eq!(i32::from_le_bytes(count[..4].try_into().unwrap()), 1);
    peer.send("getsporks", &[]).await;
    let served = peer.expect("spork", WAIT).await.expect("a spork");
    assert_eq!(spork_id(&served), 10007);
    assert_eq!(peer.expect("spork", QUIET).await, None);
}

/// Divi Core serves a spork it holds to a peer that asks for it by its hash and
/// answers `notfound` for one it does not (main.cpp:187-189, :337-346)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn getdata_of_a_spork_is_served_or_not_found() {
    let held = stored(10007, "1537971708", 1000);
    let t = TestNode::start_with(|c| seed(c, std::slice::from_ref(&held))).await;
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;

    let mut ask = vec![1u8];
    ask.extend_from_slice(&6u32.to_le_bytes());
    ask.extend_from_slice(held.hash().as_bytes());
    peer.send("getdata", &ask).await;
    let served = peer.expect("spork", WAIT).await.expect("the spork");
    assert_eq!(served, held.serialize());

    let unknown = [0x42u8; 32];
    let mut ask = vec![2u8];
    ask.extend_from_slice(&6u32.to_le_bytes());
    ask.extend_from_slice(&unknown);
    ask.extend_from_slice(&6u32.to_le_bytes());
    ask.extend_from_slice(held.hash().as_bytes());
    peer.send("getdata", &ask).await;
    let first = peer.expect("spork", WAIT).await.expect("the spork again");
    assert_eq!(first, held.serialize());
    let missing = peer.expect("notfound", WAIT).await.expect("notfound");
    assert_eq!(inv_items(&missing), vec![(6, unknown)]);
}

/// Divi Core asks the peer that announced a spork it does not hold, once, and
/// not for one it holds (main.cpp:559-612)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inv_of_a_spork_not_held_is_asked_for_once() {
    let held = stored(10007, "1537971708", 1000);
    let t = TestNode::start_with(|c| seed(c, std::slice::from_ref(&held))).await;
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;

    let unknown = [0x42u8; 32];
    let announce = |hash: &[u8]| {
        let mut inv = vec![1u8];
        inv.extend_from_slice(&6u32.to_le_bytes());
        inv.extend_from_slice(hash);
        inv
    };
    peer.send("inv", &announce(&unknown)).await;
    let asked = peer.expect("getdata", WAIT).await.expect("getdata");
    assert_eq!(inv_items(&asked), vec![(6, unknown)]);

    // the same again, and one it holds: nothing more is asked
    peer.send("inv", &announce(&unknown)).await;
    peer.send("inv", &announce(held.hash().as_bytes())).await;
    assert_eq!(peer.expect("getdata", QUIET).await, None);
}
