// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A -reindex that stops before it is done is carried out again at the next
//! start, as Divi Core's is (init.cpp:1072-1073, :679;
//! BlockIndexLoading.cpp:287-290): the address and spent indexes are never
//! left half built while the node runs as if they were complete.
//!
//! The stop is made at a known block, not by timing a kill: the undo data of
//! a block that spends a coin is taken away, so building the indexes stops
//! there with the transaction index rebuilt and the address rows of the
//! blocks below written; it is put back before the next start.

use divi_crypto::KeyPair;
use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::RpcServer;
use divi_script::TransactionSignatureChecker;
use divi_storage::ChainDatabase;
use divi_wallet::{Address, Network};
use serde_json::{json, Value};
use std::path::Path;

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;
/// Regtest coinbase maturity (Divi Core chainparams.cpp:479)
const MATURITY: u32 = 20;

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes())
}

fn address(kp: &KeyPair) -> String {
    Address::from_pubkey_hash(
        Hash160::from_bytes(*divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes()),
        Network::Regtest,
    )
    .to_base58()
}

/// Spend `coin` (a 1250 DIVI coinbase of `kp`) to `to`, signed
fn spend(kp: &KeyPair, coin: OutPoint, to: &KeyPair) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffffffff)],
        vout: vec![TxOut::new(Amount::from_sat(1250 * COIN - FEE), p2pkh(to))],
        lock_time: 0,
    };
    let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_sat(1250 * COIN));
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

fn start(dir: &Path, reindex: bool) -> Result<Node, divi_node::NodeError> {
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.to_path_buf();
    config.index.txindex = true;
    config.index.addressindex = true;
    config.index.spentindex = true;
    config.index.reindex = reindex;
    Node::new(config)
}

/// Extend the active chain by one block paying its coinbase to `kp`, with
/// `txs`; the block
fn mine(node: &Node, kp: &KeyPair, txs: Vec<Transaction>) -> Block {
    let parent = node.chain().tip().unwrap();
    let height = parent.height + 1;
    let mut sig = divi_storage::bip34_height_script(height);
    sig.push(0);
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = parent.hash;
    block.header.time = parent.time + 60;
    block.header.bits = 0x207fffff;
    block.transactions = vec![Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
        vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), p2pkh(kp))],
        lock_time: 0,
    }];
    block.transactions.extend(txs);
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    node.chain().accept_block(block.clone()).unwrap();
    block
}

/// What the address and spent indexes answer for the two addresses and the
/// spent coin
fn indexes(node: &Node, miner: &KeyPair, payee: &KeyPair, coin: OutPoint) -> Value {
    let rpc = RpcServer::new(node.chain().clone());
    let call = |method: &str, params: Value| -> Value {
        let request = serde_json::from_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        }))
        .unwrap();
        let reply = serde_json::to_value(rpc.handle_request(request)).unwrap();
        if reply["error"].is_null() {
            reply["result"].clone()
        } else {
            reply["error"].clone()
        }
    };
    json!({
        "miner": call("getaddressbalance", json!([address(miner)])),
        "payee": call("getaddressbalance", json!([address(payee)])),
        "miner txids": call("getaddresstxids", json!([address(miner)])),
        "spent": call("getspentinfo", json!([{"txid": coin.txid.to_string(), "index": coin.vout}])),
    })
}

#[test]
fn reindex_stopped_while_building_the_indexes_is_done_again_at_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let (miner, payee) = (KeyPair::new_random(), KeyPair::new_random());

    // A chain with all three indexes: a coinbase spent at block 22, then
    // eight more blocks
    let node = start(dir.path(), false).unwrap();
    let first = mine(&node, &miner, vec![]);
    let coin = OutPoint::new(first.transactions[0].txid(), 0);
    for _ in 0..MATURITY {
        mine(&node, &miner, vec![]);
    }
    let spending = mine(&node, &miner, vec![spend(&miner, coin, &payee)]);
    for _ in 0..8 {
        mine(&node, &miner, vec![]);
    }
    let clean = indexes(&node, &miner, &payee, coin);
    assert_eq!(
        clean["miner txids"].as_array().map(Vec::len),
        Some(31),
        "{clean}"
    );
    drop(node);

    // -reindex stops at block 22 while it builds the address and spent indexes
    let spending_hash = divi_crypto::compute_block_hash(&spending.header);
    let undo = {
        let db = ChainDatabase::open(dir.path().join("chainstate")).unwrap();
        let undo = db.get_undo_data(&spending_hash).unwrap().unwrap();
        db.delete_undo_data(&spending_hash).unwrap();
        undo
    };
    let stopped = start(dir.path(), true);
    assert!(stopped.is_err(), "the reindex did not stop at block 22");
    drop(stopped);
    {
        let db = ChainDatabase::open(dir.path().join("chainstate")).unwrap();
        db.store_undo_data(&spending_hash, &undo).unwrap();
    }

    // The next start, without -reindex, builds the indexes again
    let node = start(dir.path(), false).unwrap();
    assert_eq!(node.chain().height(), 30);
    assert_eq!(indexes(&node, &miner, &payee, coin), clean);
    drop(node);

    // and the start after that keeps them, without building them again
    let node = start(dir.path(), false).unwrap();
    assert_eq!(indexes(&node, &miner, &payee, coin), clean);
}
