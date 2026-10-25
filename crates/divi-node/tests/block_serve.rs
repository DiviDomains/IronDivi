// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The spork count as Divi Core sends it (main.cpp SetPeerVersionAndServices):
//! after the handshake an inbound peer is told how many sporks we hold. A Divi
//! Core node that dialled us sends it nothing else (no block or tx inv, no
//! getblocks, no getdata) until it has that many sporks from us (Node.cpp
//! CanSendMessagesToPeer, spork.cpp ProcessSpork). A peer we dialled is not
//! sent the count. Divi Core waits for no sporks from a peer that dialled it
//! (net.cpp GetSporkSyncedOrInboundNodes) and such a peer sends it none, so
//! block sync from it starts at once.
//! What a node answers a peer that asks for blocks and data, as Divi Core's
//! ProcessMessage does (main.cpp:283-347, :613-668)

mod common;
use common::raw_peer::*;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{Transaction, TxIn, TxOut};
use std::time::Duration;

/// A work block on the node's tip, not given to the node
fn next_block(t: &TestNode) -> Block {
    let chain = t.node.chain();
    let tip = chain.tip().unwrap();
    let mut tag = divi_storage::bip34_height_script(tip.height + 1);
    tag.extend_from_slice(&(tip.height + 1).to_le_bytes());
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(tag))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250 * 100_000_000),
            Script::new_p2pkh(&[0xee; 20]),
        )],
        lock_time: 0,
    };
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = tip.hash;
    block.header.time = tip.time + 60;
    block.header.bits = 0x207fffff;
    block.transactions = vec![coinbase];
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    block
}

/// A work block on the node's tip; its hash
fn mine(t: &TestNode) -> Hash256 {
    let block = next_block(t);
    let hash = divi_crypto::compute_block_hash(&block.header);
    t.node.chain().accept_block(block).unwrap();
    hash
}

/// A peer past the handshake and the messages that follow it
async fn peer(t: &TestNode, src: &str) -> RawPeer {
    let mut p = RawPeer::connect(t, src).await;
    p.handshake().await;
    while let Recv::Message(..) = p.recv(Duration::from_secs(2)).await {}
    p
}

/// The messages that come within `quiet` of each other
async fn replies(p: &mut RawPeer) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    while let Recv::Message(c, m) = p.recv(Duration::from_secs(2)).await {
        if c != "ping" && c != "pong" {
            out.push((c, m));
        }
    }
    out
}

fn locator(hashes: &[Hash256], stop: Hash256) -> Vec<u8> {
    let mut b = PROTOCOL_VERSION.to_le_bytes().to_vec();
    b.extend(compact(hashes.len() as u64));
    for h in hashes {
        b.extend_from_slice(h.as_bytes());
    }
    b.extend_from_slice(stop.as_bytes());
    b
}

/// The (type, hash) items of an inv, getdata or notfound payload
fn items(p: &[u8]) -> Vec<(u32, Hash256)> {
    let n = p[0] as usize;
    (0..n)
        .map(|k| {
            let at = 1 + 36 * k;
            let kind = u32::from_le_bytes(p[at..at + 4].try_into().unwrap());
            let hash = Hash256::from_bytes(p[at + 4..at + 36].try_into().unwrap());
            (kind, hash)
        })
        .collect()
}

/// The items of a notfound; none for any other message
fn notfound_items(command: &str, p: &[u8]) -> Vec<(u32, Hash256)> {
    if command == "notfound" {
        items(p)
    } else {
        Vec::new()
    }
}

/// getheaders is answered as getblocks: an inv of the blocks after the
/// locator (main.cpp:624-668), not a headers message
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn getheaders_is_answered_with_an_inv_as_getblocks() {
    let t = TestNode::start().await;
    let genesis = t.node.chain().tip().unwrap().hash;
    let hashes: Vec<Hash256> = (0..5).map(|_| mine(&t)).collect();
    let mut p = peer(&t, "127.0.0.3").await;
    p.send("getheaders", &locator(&[genesis], Hash256::zero()))
        .await;
    let got = replies(&mut p).await;
    let invs: Vec<_> = got.iter().filter(|(c, _)| c == "inv").collect();
    assert_eq!(
        invs.len(),
        1,
        "{:?}",
        got.iter().map(|(c, _)| c).collect::<Vec<_>>()
    );
    assert_eq!(
        items(&invs[0].1),
        hashes.iter().map(|h| (2, *h)).collect::<Vec<_>>()
    );
    assert!(!got.iter().any(|(c, _)| c == "headers"));
}

fn getdata(list: &[(u32, Hash256)]) -> Vec<u8> {
    let mut b = compact(list.len() as u64);
    for (kind, hash) in list {
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(hash.as_bytes());
    }
    b
}

/// getdata is answered in the order asked, a pass ending after each block
/// item with the notfound of that pass; an unknown transaction is named in
/// a notfound, an unknown block is not answered (main.cpp:283-347)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn getdata_answers_in_order_and_names_only_missing_transactions() {
    let t = TestNode::start().await;
    let (b1, b2) = (mine(&t), mine(&t));
    let (tx1, tx2, nb) = (
        Hash256::from_bytes([1; 32]),
        Hash256::from_bytes([2; 32]),
        Hash256::from_bytes([3; 32]),
    );
    let mut p = peer(&t, "127.0.0.3").await;
    p.send(
        "getdata",
        &getdata(&[(1, tx1), (2, b1), (1, tx2), (2, nb), (2, b2)]),
    )
    .await;
    let got: Vec<String> = replies(&mut p)
        .await
        .iter()
        .map(|(c, m)| match c.as_str() {
            "block" => {
                let parent = Hash256::from_bytes(m[4..36].try_into().unwrap());
                let height = t
                    .node
                    .chain()
                    .get_block_index(&parent)
                    .unwrap()
                    .unwrap()
                    .height
                    + 1;
                format!("block {height}")
            }
            "notfound" => format!("notfound {:?}", items(m)),
            other => other.to_string(),
        })
        .collect();
    assert_eq!(
        got,
        vec![
            "block 1".to_string(),
            format!("notfound {:?}", vec![(1u32, tx1)]),
            format!("notfound {:?}", vec![(1u32, tx2)]),
            "block 2".to_string(),
        ]
    );
}

/// A getdata of the known types the node holds nothing for (tx lock, scan
/// error, budget, quorum) is answered with a notfound naming them, in order:
/// Divi Core finds them neither in its relay map nor in PushKnownInventory
/// (main.cpp:168-211, :321-327, :337-345)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn getdata_of_items_held_by_no_store_is_not_found() {
    let t = TestNode::start().await;
    let asked: Vec<(u32, Hash256)> = [4u32, 5, 8, 9, 10, 11, 12, 13]
        .iter()
        .map(|&k| (k, Hash256::from_bytes([k as u8; 32])))
        .collect();
    let mut p = peer(&t, "127.0.0.3").await;
    p.send("getdata", &getdata(&asked)).await;
    let got: Vec<(String, Vec<(u32, Hash256)>)> = replies(&mut p)
        .await
        .iter()
        .map(|(c, m)| (c.clone(), items(m)))
        .collect();
    assert_eq!(got, vec![("notfound".to_string(), asked)]);
}

/// A filtered block item ends a getdata pass as a block item does, so the
/// unknown transactions before and after it are named in two notfounds
/// (main.cpp:300-332), with the block's merkleblock, and any matched
/// transactions, sent between them
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filtered_block_item_ends_a_getdata_pass() {
    let t = TestNode::start().await;
    let b1 = mine(&t);
    let (tx1, tx2) = (Hash256::from_bytes([1; 32]), Hash256::from_bytes([2; 32]));
    let mut p = peer(&t, "127.0.0.3").await;
    p.send("getdata", &getdata(&[(1, tx1), (3, b1), (1, tx2)]))
        .await;
    let got: Vec<(String, Vec<(u32, Hash256)>)> = replies(&mut p)
        .await
        .iter()
        .map(|(c, m)| (c.clone(), notfound_items(c, m)))
        .collect();
    let commands: Vec<&str> = got.iter().map(|(c, _)| c.as_str()).collect();
    assert!(got.len() >= 3, "{commands:?}");
    assert_eq!(got[0], ("notfound".to_string(), vec![(1, tx1)]));
    assert_eq!(commands[1], "merkleblock", "{commands:?}");
    assert!(
        commands[2..got.len() - 1].iter().all(|&c| c == "tx"),
        "{commands:?}"
    );
    assert_eq!(got[got.len() - 1], ("notfound".to_string(), vec![(1, tx2)]));
}

/// A block that invalidateblock marked failed is not sent, though it was
/// fully validated: Divi Core's IsValid(BLOCK_VALID_SCRIPTS) is false for a
/// failed block (main.cpp:223-239, chain.h:313-319)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn getdata_of_an_invalidated_block_gets_nothing() {
    let t = TestNode::start().await;
    let _b1 = mine(&t);
    let b2 = mine(&t);
    t.node.chain().invalidate_block(&b2).unwrap();
    let mut p = peer(&t, "127.0.0.3").await;
    p.send("getdata", &getdata(&[(2, b2)])).await;
    let got: Vec<String> = replies(&mut p).await.into_iter().map(|(c, _)| c).collect();
    assert!(got.is_empty(), "{got:?}");
}

/// A headers message is not read: Divi Core reads one only with
/// headers-first syncing, which no network has (main.cpp:669,
/// chainparams.cpp:251, :360, :440), so a header of a block the node lacks
/// is not asked for, and an empty one is not answered either
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn headers_message_is_not_read() {
    let t = TestNode::start().await;
    mine(&t);
    let header = divi_primitives::serialize::serialize(&next_block(&t).header);
    let mut p = peer(&t, "127.0.0.3").await;
    let mut one = compact(1);
    one.extend_from_slice(&header);
    one.push(0);
    p.send("headers", &one).await;
    p.send("headers", &compact(0)).await;
    let got: Vec<String> = replies(&mut p).await.into_iter().map(|(c, _)| c).collect();
    assert!(got.is_empty(), "{got:?}");
}

/// A block whose parent is unknown is answered with a getblocks up to it,
/// and the same block again with one up to its parent: Divi Core asks the
/// peer that way for what it is missing (main.cpp:822-833)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn block_with_an_unknown_parent_is_answered_with_getblocks() {
    let t = TestNode::start().await;
    mine(&t);
    let mut block = next_block(&t);
    let parent = Hash256::from_bytes([0x6b; 32]);
    block.header.prev_block = parent;
    let hash = divi_crypto::compute_block_hash(&block.header);
    let bytes = divi_primitives::serialize::serialize(&block);
    let mut p = peer(&t, "127.0.0.3").await;
    let mut stops = Vec::new();
    for _ in 0..2 {
        p.send("block", &bytes).await;
        for (c, m) in replies(&mut p).await {
            if c == "getblocks" {
                stops.push(Hash256::from_bytes(m[m.len() - 32..].try_into().unwrap()));
            }
        }
    }
    assert_eq!(stops, vec![hash, parent]);
}
