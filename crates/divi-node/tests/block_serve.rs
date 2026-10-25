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

/// A work block on the node's tip; its hash
fn mine(t: &TestNode) -> Hash256 {
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
    let hash = divi_crypto::compute_block_hash(&block.header);
    chain.accept_block(block).unwrap();
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
