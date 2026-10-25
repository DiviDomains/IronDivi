// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A peer's masternode sync is answered as Divi Core answers it
//! (masternode-sync.cpp ProcessSyncUpdate): `dseg` for the whole list with the
//! list's broadcasts and `ssc 2 <count>`, `mnget` with the winners and
//! `ssc 3 <count>`, once per request expiry (a second `mnget` scores 20).

mod common;
use common::raw_peer::*;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash256,
    script::Script,
    transaction::{Transaction, TxIn, TxOut},
};

/// A block at the present time, so the chain is synced (the sync messages
/// are taken only then)
fn mine_now(t: &TestNode) {
    let chain = t.node.chain();
    let tip = chain.tip().unwrap();
    let mut tag = divi_storage::bip34_height_script(tip.height + 1);
    tag.extend_from_slice(&(tip.height + 1).to_le_bytes());
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = tip.hash;
    block.header.time = divi_primitives::clock::now() as u32;
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

fn ssc(code: i32, count: i32) -> Vec<u8> {
    let mut v = code.to_le_bytes().to_vec();
    v.extend_from_slice(&count.to_le_bytes());
    v
}

fn empty_ctxin() -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v.extend_from_slice(&[0xff; 4]);
    v.push(0);
    v.extend_from_slice(&[0xff; 4]);
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dseg_and_mnget_are_answered_with_their_counts() {
    let t = TestNode::start().await;
    mine_now(&t);
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;

    // No masternodes: the count alone
    peer.send("dseg", &empty_ctxin()).await;
    assert_eq!(peer.expect("ssc", WAIT).await, Some(ssc(2, 0)));
    // A local peer may ask again
    peer.send("dseg", &empty_ctxin()).await;
    assert_eq!(peer.expect("ssc", WAIT).await, Some(ssc(2, 0)));

    peer.send("mnget", &200i32.to_le_bytes()).await;
    assert_eq!(peer.expect("ssc", WAIT).await, Some(ssc(3, 0)));
    assert_eq!(t.score(peer.ip), Some(0));
    // Asked again within the request's expiry: Misbehaving(20), no answer
    peer.send("mnget", &200i32.to_le_bytes()).await;
    assert_eq!(t.wait_score(peer.ip, 20).await, Some(20));
    assert_eq!(peer.expect("ssc", QUIET).await, None);
}
