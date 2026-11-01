// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A mempool entry keeps the coin-age priority it entered with, and
//! `getrawmempool true` shows it with the entry height and the priority at the
//! current height, as Divi Core does (MemPoolEntry.cpp, rpcblockchain.cpp:122-128).

use divi_crypto::KeyPair;
use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_script::TransactionSignatureChecker;
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes())
}

/// Extend the active chain by one block paying its coinbase to `kp` and
/// return that coin
fn mine(node: &Node, kp: &KeyPair) -> OutPoint {
    let chain = node.chain();
    let tip = chain.tip().unwrap();
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(
            [divi_storage::bip34_height_script(tip.height + 1), vec![0]].concat(),
        ))],
        vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), p2pkh(kp))],
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

/// Spend `coin` (a 1250 DIVI coinbase) back to `kp`, signed
fn spend(kp: &KeyPair, coin: OutPoint) -> Transaction {
    spend_value(kp, coin, 1250 * COIN)
}

/// Spend a coin worth `value` back to `kp`, paying FEE, signed
fn spend_value(kp: &KeyPair, coin: OutPoint, value: i64) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffffffff)],
        vout: vec![TxOut::new(Amount::from_sat(value - FEE), p2pkh(kp))],
        lock_time: 0,
    };
    let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_sat(value));
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

/// Divi Core `CalculateModifiedSize` (MemPoolEntry.cpp:6-19), written out
/// here so the test does not lean on the code it checks
fn core_modified_size(tx: &Transaction) -> f64 {
    let mut size = tx.size();
    for input in &tx.vin {
        let offset = 41 + input.script_sig.as_bytes().len().min(110);
        if size > offset {
            size -= offset;
        }
    }
    size as f64
}

fn raw_mempool(server: &RpcServer) -> Value {
    let r = server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: "getrawmempool".to_string(),
        params: Params::Array(vec![json!(true)]),
    });
    assert!(r.error.is_none(), "{:?}", r.error);
    r.result.unwrap()
}

/// A coin from height 1 spent at tip 25: starting priority is Core's
/// ComputeInputCoinAge at the tip per modified byte; two blocks later the
/// current priority adds the value in for each of them
#[test]
fn raw_mempool_shows_entry_height_and_coin_age_priority() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    let node = Node::new(config).unwrap();
    let server = RpcServer::new(Arc::clone(node.chain()));
    server.set_mempool(node.mempool().clone());
    let key = KeyPair::new_random();

    let coin = mine(&node, &key);
    for _ in 0..24 {
        mine(&node, &key);
    }
    assert_eq!(node.chain().height(), 25);
    let tx = spend(&key, coin);
    let txid = tx.txid().to_string();
    let mod_size = core_modified_size(&tx);
    node.mempool().add(tx, Amount::from_sat(FEE)).unwrap();

    let value_in = 1250 * COIN;
    let starting = (value_in as f64 * 24.0) / mod_size;
    let entry = &raw_mempool(&server)[&txid];
    assert_eq!(entry["height"], 25, "{entry}");
    assert_eq!(
        entry["startingpriority"].as_f64(),
        Some(starting),
        "{entry}"
    );
    assert_eq!(entry["currentpriority"].as_f64(), Some(starting), "{entry}");

    mine(&node, &key);
    mine(&node, &key);
    let entry = &raw_mempool(&server)[&txid];
    assert_eq!(entry["height"], 25, "entry height kept: {entry}");
    assert_eq!(
        entry["startingpriority"].as_f64(),
        Some(starting),
        "{entry}"
    );
    assert_eq!(
        entry["currentpriority"].as_f64(),
        Some(starting + (2.0 * value_in as f64) / mod_size),
        "{entry}"
    );
}

/// A spend of an unconfirmed pool output depends on it and has no coin age
/// from that input
/// (Core counts only coins below the tip height, coins.cpp:367-380), and gains
/// priority as blocks pass
#[test]
fn spend_of_a_pool_output_starts_at_zero_priority() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    let node = Node::new(config).unwrap();
    let server = RpcServer::new(Arc::clone(node.chain()));
    server.set_mempool(node.mempool().clone());
    let key = KeyPair::new_random();

    let coin = mine(&node, &key);
    for _ in 0..24 {
        mine(&node, &key);
    }
    let parent = spend(&key, coin);
    let parent_out = OutPoint::new(parent.txid(), 0);
    node.mempool().add(parent, Amount::from_sat(FEE)).unwrap();
    let child = spend_value(&key, parent_out, 1250 * COIN - FEE);
    let txid = child.txid().to_string();
    let mod_size = core_modified_size(&child);
    node.mempool().add(child, Amount::from_sat(FEE)).unwrap();

    let entry = &raw_mempool(&server)[&txid];
    assert_eq!(entry["startingpriority"].as_f64(), Some(0.0), "{entry}");
    assert_eq!(
        entry["depends"],
        json!([parent_out.txid.to_string()]),
        "{entry}"
    );
    mine(&node, &key);
    let entry = &raw_mempool(&server)[&txid];
    let value_in = 1250 * COIN - FEE;
    assert_eq!(
        entry["currentpriority"].as_f64(),
        Some(value_in as f64 / mod_size),
        "{entry}"
    );
}
