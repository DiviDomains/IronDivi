// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Relayed transactions whose parent has not arrived are kept, at most
//! -maxorphantx of them, and enter the mempool when the parent does, as
//! Divi Core's orphan pool (main.cpp:743-792, OrphanTransactions.cpp).

mod common;
use common::raw_peer::*;
use divi_crypto::KeyPair;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::TransactionSignatureChecker;
use std::time::Duration;

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;
const COINBASE: i64 = 1250 * COIN;
const CHILD: i64 = 10 * COIN;

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes())
}

fn mine(t: &TestNode, payee: Script) -> OutPoint {
    let chain = t.node.chain();
    let tip = chain.tip().unwrap();
    let mut tag = divi_storage::bip34_height_script(tip.height + 1);
    tag.extend_from_slice(&(tip.height + 1).to_le_bytes());
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(tag))],
        vout: vec![TxOut::new(Amount::from_sat(COINBASE), payee)],
        lock_time: 0,
    };
    let outpoint = OutPoint::new(coinbase.txid(), 0);
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = tip.hash;
    block.header.time = tip.time + 60;
    block.header.bits = 0x207fffff;
    block.transactions = vec![coinbase];
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    chain.accept_block(block).unwrap();
    outpoint
}

fn signed(inputs: &[OutPoint], outputs: Vec<TxOut>, kp: &KeyPair, value: i64) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        vin: inputs
            .iter()
            .map(|op| TxIn::new(*op, Script::new(), 0xffffffff))
            .collect(),
        vout: outputs,
        lock_time: 0,
    };
    for i in 0..tx.vin.len() {
        let checker = TransactionSignatureChecker::new(&tx, i, Amount::from_sat(value));
        let sighash = checker.signature_hash(&p2pkh(kp), 1);
        let mut sig = divi_crypto::sign_hash(kp.secret_key(), &sighash)
            .unwrap()
            .to_der();
        sig.push(1);
        let pubkey = kp.public_key().to_bytes();
        let mut ss = vec![sig.len() as u8];
        ss.extend_from_slice(&sig);
        ss.push(pubkey.len() as u8);
        ss.extend_from_slice(&pubkey);
        tx.vin[i].script_sig = Script::from_bytes(ss);
    }
    tx
}

/// A started node with `max_orphans`, a parent paying `children` outputs of
/// 10 DIVI from a mature coin, and one child spending each output
async fn family(max_orphans: usize, children: usize) -> (TestNode, Transaction, Vec<Transaction>) {
    let t = TestNode::build(|c| c.mempool.max_orphan_txs = max_orphans);
    let owner = KeyPair::new_random();
    let coin = mine(&t, p2pkh(&owner));
    for _ in 0..20 {
        mine(&t, Script::new_p2pkh(&[0xee; 20]));
    }
    t.run().await;
    let mut outs: Vec<TxOut> = (0..children)
        .map(|_| TxOut::new(Amount::from_sat(CHILD), p2pkh(&owner)))
        .collect();
    let change = COINBASE - CHILD * children as i64 - FEE;
    outs.push(TxOut::new(Amount::from_sat(change), p2pkh(&owner)));
    let parent = signed(&[coin], outs, &owner, COINBASE);
    let kids = (0..children)
        .map(|n| {
            signed(
                &[OutPoint::new(parent.txid(), n as u32)],
                vec![TxOut::new(Amount::from_sat(CHILD - FEE), p2pkh(&owner))],
                &owner,
                CHILD,
            )
        })
        .collect();
    (t, parent, kids)
}

fn in_pool(t: &TestNode, tx: &Transaction) -> bool {
    t.node.mempool().get(&tx.txid()).is_some()
}

async fn wait_for(t: &TestNode, tx: &Transaction) -> bool {
    let deadline = tokio::time::Instant::now() + WAIT;
    while tokio::time::Instant::now() < deadline {
        if in_pool(t, tx) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Children sent first; how many are in the mempool once the parent is
async fn children_kept(max_orphans: usize) -> usize {
    let (t, parent, kids) = family(max_orphans, 4).await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;
    for kid in &kids {
        p.send("tx", &divi_primitives::serialize(kid)).await;
    }
    assert!(p.alive().await);
    assert!(
        kids.iter().all(|k| !in_pool(&t, k)),
        "a child without its parent"
    );
    p.send("tx", &divi_primitives::serialize(&parent)).await;
    assert!(wait_for(&t, &parent).await, "parent not accepted");
    // The orphans are offered right after the parent, on the same task
    tokio::time::sleep(QUIET).await;
    kids.iter().filter(|k| in_pool(&t, k)).count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn children_wait_for_their_parent() {
    assert_eq!(children_kept(100).await, 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn orphans_beyond_maxorphantx_are_dropped() {
    assert_eq!(children_kept(2).await, 2);
    assert_eq!(children_kept(0).await, 0);
}

/// Divi Core drops a peer's orphans when it disconnects (NodeState.cpp:41)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_s_orphans_go_when_it_disconnects() {
    let (t, parent, kids) = family(100, 1).await;
    let mut first = RawPeer::connect(&t, "127.0.0.2").await;
    first.handshake().await;
    first
        .send("tx", &divi_primitives::serialize(&kids[0]))
        .await;
    assert!(first.alive().await);
    drop(first);
    tokio::time::sleep(QUIET).await;

    let mut second = RawPeer::connect(&t, "127.0.0.3").await;
    second.handshake().await;
    second
        .send("tx", &divi_primitives::serialize(&parent))
        .await;
    assert!(wait_for(&t, &parent).await, "parent not accepted");
    tokio::time::sleep(QUIET).await;
    assert!(!in_pool(&t, &kids[0]), "the orphan of a gone peer was kept");
}
