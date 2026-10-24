// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A peer that relays a transaction the mempool refuses gets Divi Core's
//! `reject` (main.cpp:803-809): "tx", the refusal's code and reason, and the
//! txid. A transaction with a missing input (an orphan) or one spending a
//! coin a mempool transaction already spends gets none.

mod common;
use common::raw_peer::*;
use divi_crypto::KeyPair;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::TransactionSignatureChecker;

const COIN: i64 = 100_000_000;
const COINBASE: i64 = 1250 * COIN;

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
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    chain.accept_block(block).unwrap();
    outpoint
}

/// A spend of `coin` (a coinbase of `owner`) paying `outputs`, signed
fn signed(
    coin: OutPoint,
    outputs: Vec<TxOut>,
    kp: &KeyPair,
    lock_time: u32,
    seq: u32,
) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), seq)],
        vout: outputs,
        lock_time,
    };
    let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_sat(COINBASE));
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
    tx.vin[0].script_sig = Script::from_bytes(ss);
    tx
}

/// Core's `reject` payload: message, code, reason, the txid
fn reject_payload(code: u8, reason: &str, txid: &Hash256) -> Vec<u8> {
    let mut v = compact(2);
    v.extend_from_slice(b"tx");
    v.push(code);
    v.extend_from_slice(&compact(reason.len() as u64));
    v.extend_from_slice(reason.as_bytes());
    v.extend_from_slice(txid.as_bytes());
    v
}

#[tokio::test]
async fn refused_relayed_transactions_get_cores_reject() {
    let t = TestNode::build(|_| {});
    let owner = KeyPair::new_random();
    let coins: Vec<OutPoint> = (0..4).map(|_| mine(&t, p2pkh(&owner))).collect();
    for _ in 0..20 {
        mine(&t, Script::new_p2pkh(&[0xee; 20]));
    }
    t.run().await;
    let tip = t.node.chain().tip().unwrap().height;
    let pay = |v: i64| TxOut::new(Amount::from_sat(v), Script::new_p2pkh(&[0xaa; 20]));

    let mut peer = RawPeer::connect(&t, "127.0.0.1").await;
    peer.handshake().await;

    // An output under the dust threshold (5460 satoshis): 64 "dust"
    let dust = signed(
        coins[0],
        vec![pay(COINBASE - COIN), pay(5000)],
        &owner,
        0,
        0xffffffff,
    );
    peer.send("tx", &serialize(&dust)).await;
    assert_eq!(
        peer.expect("reject", WAIT).await,
        Some(reject_payload(0x40, "dust", &dust.txid()))
    );

    // A lock time past the next block: 64 "non-final"
    let late = signed(coins[1], vec![pay(COINBASE - COIN)], &owner, tip + 100, 0);
    peer.send("tx", &serialize(&late)).await;
    assert_eq!(
        peer.expect("reject", WAIT).await,
        Some(reject_payload(0x40, "non-final", &late.txid()))
    );

    // Taken, then a second spend of the same coin: no reject for either
    let first = signed(coins[2], vec![pay(COINBASE - COIN)], &owner, 0, 0xffffffff);
    let second = signed(
        coins[2],
        vec![pay(COINBASE - 2 * COIN)],
        &owner,
        0,
        0xffffffff,
    );
    peer.send("tx", &serialize(&first)).await;
    peer.send("tx", &serialize(&second)).await;
    // A missing input: kept as an orphan, no reject
    let orphan = signed(
        OutPoint::new(Hash256::from_bytes([0x11; 32]), 0),
        vec![pay(COIN)],
        &owner,
        0,
        0xffffffff,
    );
    peer.send("tx", &serialize(&orphan)).await;
    assert_eq!(peer.expect("reject", QUIET).await, None);
    assert!(t.node.mempool().contains(&first.txid()));
    assert!(!t.node.mempool().contains(&second.txid()));
    assert!(peer.alive().await);
}
