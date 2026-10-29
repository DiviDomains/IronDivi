// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A version message names the node's current height, as Divi Core's
//! PushVersion does (Node.cpp:994-1005 reads the chain height each time), not
//! the height the node had when it started.

mod common;

use common::raw_peer::*;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{Transaction, TxIn, TxOut};

/// Add one proof-of-work regtest block to the node's chain
fn mine(t: &TestNode) {
    let chain = t.node.chain();
    let tip = chain.tip().unwrap();
    let mut tag = divi_storage::bip34_height_script(tip.height + 1);
    tag.extend_from_slice(&(tip.height + 1).to_le_bytes());
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = tip.hash;
    block.header.time = tip.time + 60;
    block.header.bits = 0x207fffff;
    block.transactions = vec![Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(tag))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250 * 100_000_000),
            Script::new_p2pkh(&[0xee; 20]),
        )],
        lock_time: 0,
    }];
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    chain.accept_block(block).unwrap();
}

/// The start height in a version payload
fn start_height(v: &[u8]) -> i32 {
    // version, services, time, two addresses, nonce, then the user agent
    let mut at = 4 + 8 + 8 + 26 + 26 + 8;
    let len = v[at] as usize;
    at += 1 + len;
    i32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn version_names_the_current_height() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    let v = p.expect("version", WAIT).await.expect("version");
    assert_eq!(start_height(&v), 0);

    for _ in 0..3 {
        mine(&t);
    }
    assert_eq!(t.node.chain().height(), 3);
    let mut q = RawPeer::connect(&t, "127.0.0.3").await;
    q.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    let v = q.expect("version", WAIT).await.expect("version");
    assert_eq!(start_height(&v), 3, "the height now, not at start");
}

/// The block locator of a getblocks payload: its first hash (the sender's tip)
fn locator_tip(p: &[u8]) -> [u8; 32] {
    // version, then the compact count of hashes (one byte below 253)
    p[5..37].try_into().unwrap()
}

/// A version payload without the start height (and relay) fields
fn version_without_height() -> Vec<u8> {
    let v = version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/");
    v[..v.len() - 5].to_vec()
}

/// Wait (bounded) until the node has one peer whose stats show a start
/// height, and return it as getpeerinfo would
async fn starting_height(t: &TestNode) -> Option<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let peers = t.node.peer_manager().get_peer_details();
        if let Some((_, _, _, st, _)) = peers.first() {
            if st.version.load(std::sync::atomic::Ordering::Relaxed) != 0 {
                return Some(serde_json::json!(st
                    .start_height
                    .load(std::sync::atomic::Ordering::Relaxed)));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Divi Core's BeginSyncingWithPeer (main.cpp:1130-1142) sends getblocks
/// from its tip to a full-node peer when the handshake is done, whatever height
/// the peer named: a peer that names 0 still gets asked
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_peer_naming_a_lower_height_is_asked_for_blocks() {
    let t = TestNode::start().await;
    for _ in 0..3 {
        mine(&t);
    }
    let tip = t.node.chain().tip().unwrap().hash;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;
    let getblocks = p
        .expect("getblocks", WAIT)
        .await
        .expect("getblocks after the handshake");
    assert_eq!(
        &locator_tip(&getblocks),
        tip.as_bytes(),
        "from the node's tip"
    );
}

/// A fresh -connect node asks the peer it dials for blocks at once, though
/// the peer names height 0 and announces no new block
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_node_asks_its_peer_for_blocks_without_a_new_block() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _t = TestNode::start_with(|c| {
        c.p2p.connect = vec![format!("127.0.0.1:{port}")];
    })
    .await;
    let (stream, addr) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .expect("node dials in time")
        .unwrap();
    let mut seed = RawPeer {
        stream,
        ip: addr.ip(),
    };
    assert!(seed.expect("version", WAIT).await.is_some(), "node version");
    seed.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    seed.send("verack", &[]).await;
    assert!(
        seed.expect("getblocks", WAIT).await.is_some(),
        "getblocks to the -connect peer"
    );
}

/// getpeerinfo startingheight is the height the peer named, -1 when its
/// version names none (Divi Core nStartingHeight(-1), Node.cpp:561;
/// rpcnet.cpp:135)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startingheight_is_minus_one_when_the_peer_names_none() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.send("version", &version_without_height()).await;
    assert!(p.expect("version", WAIT).await.is_some(), "node version");
    p.send("verack", &[]).await;
    assert_eq!(starting_height(&t).await, Some(serde_json::json!(-1)));
}

/// Two nodes: the fresh one dials one at height 3; each shows the other's
/// start height as divid does (3 and 0), and the fresh one syncs the three
/// blocks with no new block announced
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_node_syncs_from_its_connect_peer_and_both_show_start_heights() {
    let a = TestNode::start().await;
    for _ in 0..3 {
        mine(&a);
    }
    let port = a.port;
    let b = TestNode::start_with(|c| {
        c.p2p.connect = vec![format!("127.0.0.1:{port}")];
    })
    .await;
    assert_eq!(
        starting_height(&b).await,
        Some(serde_json::json!(3)),
        "b sees a's height"
    );
    assert_eq!(
        starting_height(&a).await,
        Some(serde_json::json!(0)),
        "a sees b's height"
    );
    let deadline = tokio::time::Instant::now() + WAIT * 3;
    while b.node.chain().height() < 3 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(b.node.chain().height(), 3);
}
