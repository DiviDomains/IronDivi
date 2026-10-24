// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! -txindex is changed for an existing chain database with -reindex, as in
//! Divi Core: without -reindex a changed -txindex refuses to start
//! (init.cpp:1103-1106); with it the node starts and the index covers every
//! block (init.cpp:663-680, ChainExtensionService.cpp:703-707), and later
//! starts keep it.

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::RpcServer;
use serde_json::{json, Value};
use std::path::Path;

fn start(dir: &Path, txindex: bool, reindex: bool) -> Result<Node, divi_node::NodeError> {
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.to_path_buf();
    config.index.txindex = txindex;
    config.index.reindex = reindex;
    Node::new(config)
}

/// Extend the active chain by one block paying its coinbase to a fixed script
fn mine(node: &Node) -> Hash256 {
    let parent = node.chain().tip().unwrap();
    let height = parent.height + 1;
    // Height, then a byte, so the coinbase script is at least two bytes
    let mut sig = divi_storage::bip34_height_script(height);
    sig.push(0);
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250 * 100_000_000),
            Script::new_p2pkh(&[7; 20]),
        )],
        lock_time: 0,
    };
    let txid = coinbase.txid();
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = parent.hash;
    block.header.time = parent.time + 60;
    block.header.bits = 0x207fffff;
    block.transactions = vec![coinbase];
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    node.chain().accept_block(block).unwrap();
    txid
}

/// getrawtransaction's result, or its error message
fn raw_tx(node: &Node, txid: &Hash256) -> Result<Value, String> {
    let rpc = RpcServer::new(node.chain().clone());
    let request = serde_json::from_value(json!({
        "jsonrpc": "2.0", "id": 1, "method": "getrawtransaction",
        "params": [txid.to_string()],
    }))
    .unwrap();
    let reply = serde_json::to_value(rpc.handle_request(request)).unwrap();
    match reply.get("error") {
        Some(e) if !e.is_null() => Err(e["message"].as_str().unwrap_or("").to_string()),
        _ => Ok(reply["result"].clone()),
    }
}

fn refused(result: Result<Node, divi_node::NodeError>) -> String {
    match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("the node started"),
    }
}

#[test]
fn reindex_turns_on_the_transaction_index_for_an_existing_chain() {
    let dir = tempfile::tempdir().unwrap();

    // A chain database made with -txindex=0
    let node = start(dir.path(), false, false).unwrap();
    let txids: Vec<Hash256> = (0..30).map(|_| mine(&node)).collect();
    let (early, late) = (txids[4], txids[28]); // blocks 5 and 29
    assert!(!node.chain().has_tx_index());
    // Without the index divid still finds a transaction through an unspent
    // output of it (TransactionDiskAccessor.cpp:88-96); these coinbases are unspent
    assert!(raw_tx(&node, &early).is_ok(), "not found through its coin");
    assert!(
        raw_tx(&node, &Hash256::from_bytes([3; 32])).is_err(),
        "an unknown txid was found"
    );
    drop(node);

    // -txindex=1 alone keeps refusing, with Core's message
    let e = refused(start(dir.path(), true, false));
    assert!(
        e.contains("You need to rebuild the database using -reindex to change -txindex"),
        "{e}"
    );

    // -txindex=1 -reindex starts, and every block's transactions are found
    let node = start(dir.path(), true, true).unwrap();
    assert_eq!(node.chain().height(), 30);
    for txid in [early, late] {
        let hex = raw_tx(&node, &txid).unwrap_or_else(|e| panic!("{txid}: {e}"));
        assert!(hex.as_str().is_some_and(|h| !h.is_empty()));
    }
    drop(node);

    // Later starts with -txindex=1 and no -reindex keep the index
    let node = start(dir.path(), true, false).unwrap();
    for txid in [early, late] {
        assert!(raw_tx(&node, &txid).is_ok(), "index lost after restart");
    }
    let newer = mine(&node);
    assert!(raw_tx(&node, &newer).is_ok(), "a new block is not indexed");
    drop(node);

    // -reindex with -txindex=0 turns it off again, as divid does
    let node = start(dir.path(), false, true).unwrap();
    assert!(!node.chain().has_tx_index(), "index still used");
    drop(node);
    assert!(start(dir.path(), false, false).is_ok());
    let e = refused(start(dir.path(), true, false));
    assert!(e.contains("-reindex to change -txindex"), "{e}");
}
