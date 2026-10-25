// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The masternode sync asks its peers as Divi Core does (masternode-sync.cpp
//! Process, SyncMasternodeList): with three peers it may ask and a synced
//! chain, one peer a step for the whole list (`dseg` with an empty CTxIn), the
//! next peer only after the last one's step; a peer's `ssc` is its answer.

mod common;
use common::raw_peer::*;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash256,
    script::Script,
    transaction::{Transaction, TxIn, TxOut},
};
use std::time::Duration;

/// A block at the present time, so the chain is synced (IsBlockchainSynced)
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

fn empty_ctxin() -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v.extend_from_slice(&[0xff; 4]);
    v.push(0);
    v.extend_from_slice(&[0xff; 4]);
    v
}

fn ssc(code: i32, count: i32) -> Vec<u8> {
    let mut v = code.to_le_bytes().to_vec();
    v.extend_from_slice(&count.to_le_bytes());
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sync_asks_one_peer_a_step_for_the_masternode_list() {
    let t = TestNode::start().await;
    mine_now(&t);
    let mut peers = Vec::new();
    for src in ["127.0.0.2", "127.0.0.3", "127.0.0.4"] {
        let mut p = RawPeer::connect(&t, src).await;
        p.handshake().await;
        peers.push(p);
    }
    // The first step starts the clock, the next (5 s on) asks the first peer
    let step = Duration::from_secs(15);
    assert_eq!(peers[0].expect("dseg", step).await, Some(empty_ctxin()));
    peers[0].send("ssc", &ssc(2, 0)).await;
    // The next step asks the second peer, not the first again
    assert_eq!(peers[1].expect("dseg", step).await, Some(empty_ctxin()));
    peers[1].send("ssc", &ssc(2, 0)).await;
    assert_eq!(peers[2].expect("dseg", step).await, Some(empty_ctxin()));
    peers[2].send("ssc", &ssc(2, 0)).await;
    // Counted: ten seconds after the last count the winners stage asks the
    // first peer for the winners of 200 blocks (unanswered, the list stage
    // would fail instead)
    let winners = peers[0].expect("mnget", Duration::from_secs(25)).await;
    assert_eq!(winners, Some(200i32.to_le_bytes().to_vec()));
}
