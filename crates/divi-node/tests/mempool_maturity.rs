// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A coinbase or coinstake output cannot be spent before it is mature: the
//! mempool refuses the spend as Divi Core's does.

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;

/// Regtest coinbase and coinstake maturity (Divi Core chainparams.cpp:479)
const MATURITY: u32 = 20;

/// Extend the active chain by one block paying its coinbase to anyone and
/// return that coin
fn mine(node: &Node) -> OutPoint {
    let chain = node.chain();
    let tip = chain.tip().unwrap();
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(
            [divi_storage::bip34_height_script(tip.height + 1), vec![0]].concat(),
        ))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250 * COIN),
            Script::from_bytes(vec![0x51]),
        )],
        lock_time: 0,
    };
    let coin = OutPoint::new(coinbase.txid(), 0);
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
    coin
}

fn spend(coin: OutPoint) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffffffff)],
        vout: vec![TxOut::new(
            Amount::from_sat(1250 * COIN - FEE),
            Script::from_bytes(vec![0x51]),
        )],
        lock_time: 0,
    }
}

/// Divi Core's mempool refuses the spend of an immature coinbase as invalid,
/// without scoring the peer that relayed it (CheckInputs,
/// UtxoCheckingAndUpdating.cpp:72-78, run with the tip as the spending
/// block's parent).
#[test]
fn immature_coinbase_spend_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    let node = Node::new(config).unwrap();

    let coin = mine(&node);
    for _ in 0..MATURITY - 2 {
        mine(&node);
    }
    // Spent in the next block the coin would have 19 confirmations
    let err = node
        .mempool()
        .add(spend(coin), Amount::from_sat(FEE))
        .unwrap_err();
    assert_eq!(err.to_string(), "16: bad-txns-premature-spend-of-coinbase");
    assert_eq!(err.misbehaviour_score(), 0);

    // One block later it is mature
    mine(&node);
    node.mempool()
        .add(spend(coin), Amount::from_sat(FEE))
        .unwrap();
}
