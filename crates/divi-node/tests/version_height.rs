// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
