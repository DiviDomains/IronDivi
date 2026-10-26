// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A broadcast the node already has, announced during the list stage, counts
//! as a list update (MasternodeIsKnown, RecordMasternodeListUpdate,
//! masternode-sync.cpp:227-239): with it the stage moves on to the winners
//! though no peer answered with ssc; without it the stage fails after 25 s.

mod common;
use common::raw_peer::*;
use divi_masternode::cpp_wire::{CppBroadcast, CppPing, CppTxIn};
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

/// A broadcast as the list keeps it, on a public address, pinged now
fn broadcast() -> CppBroadcast {
    let vin = CppTxIn::new([0x11; 32], 1);
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12..].copy_from_slice(&[8, 8, 4, 4]);
    let now = divi_primitives::clock::now();
    CppBroadcast {
        vin: vin.clone(),
        ip,
        port: 51476,
        pubkey_collateral: vec![2; 33],
        pubkey_masternode: vec![3; 33],
        signature: vec![0x1f; 65],
        sig_time: now - 100,
        protocol_version: 70920,
        last_ping: CppPing {
            vin,
            block_hash: [0x22; 32],
            sig_time: now - 10,
            signature: vec![0x1f; 65],
        },
        tier: 0,
    }
}

fn compact(n: usize) -> Vec<u8> {
    assert!(n < 0xfd);
    vec![n as u8]
}

/// CMasternodeBroadcast::GetHash: sigTime and the collateral key
fn broadcast_hash(b: &CppBroadcast) -> [u8; 32] {
    let mut d = b.sig_time.to_le_bytes().to_vec();
    d.extend_from_slice(&compact(b.pubkey_collateral.len()));
    d.extend_from_slice(&b.pubkey_collateral);
    sha256d(&d)
}

fn inv(inv_type: u32, hash: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&inv_type.to_le_bytes());
    v.extend_from_slice(hash);
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_known_broadcast_announced_in_the_list_stage_counts() {
    let mnb = broadcast();
    let t = TestNode::start_with(|c| {
        let file = common::mncache::mncache_with(&mnb, c.network.magic);
        std::fs::write(c.data_dir.join("mncache.dat"), file).unwrap();
    })
    .await;
    mine_now(&t);
    let mut peers = Vec::new();
    for src in ["127.0.0.2", "127.0.0.3", "127.0.0.4"] {
        let mut p = RawPeer::connect(&t, src).await;
        p.handshake().await;
        peers.push(p);
    }
    assert!(peers[0]
        .expect("dseg", Duration::from_secs(15))
        .await
        .is_some());
    // No ssc: the first peer announces the broadcast the node has
    peers[0].send("inv", &inv(14, &broadcast_hash(&mnb))).await;
    // Ten seconds after it, with two peers asked, the winners stage asks
    let winners = peers[0].expect("mnget", Duration::from_secs(30)).await;
    assert_eq!(winners, Some(200i32.to_le_bytes().to_vec()));
}
