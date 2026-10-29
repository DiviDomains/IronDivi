// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! -txindex is changed for an existing chain database with -reindex, as in
//! Divi Core: without -reindex a changed -txindex refuses to start
//! (init.cpp:1103-1106); with it the node starts and the index covers every
//! block (init.cpp:663-680, ChainExtensionService.cpp:703-707), and later
//! starts keep it. Without the index, getrawtransaction still finds a
//! transaction that has an unspent output (TransactionDiskAccessor.cpp:88-110).

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
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

/// An output anyone can spend with an empty scriptSig (OP_TRUE)
fn anyone() -> Script {
    Script::from_bytes(vec![0x51])
}

/// Extend the active chain by one block paying its coinbase to OP_TRUE
fn mine(node: &Node) -> Hash256 {
    mine_with(node, vec![])
}

/// A transaction spending the whole first output of `txid` (an OP_TRUE
/// coinbase output) to OP_TRUE
fn spend(txid: Hash256) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(
            OutPoint { txid, vout: 0 },
            Script::new(),
            0xffff_ffff,
        )],
        vout: vec![TxOut::new(Amount::from_sat(1250 * 100_000_000), anyone())],
        lock_time: 0,
    }
}

/// Extend the active chain by one block with `txs` after its coinbase; the
/// coinbase's txid
fn mine_with(node: &Node, txs: Vec<Transaction>) -> Hash256 {
    let parent = node.chain().tip().unwrap();
    let height = parent.height + 1;
    // Height, then a byte, so the coinbase script is at least two bytes
    let mut sig = divi_storage::bip34_height_script(height);
    sig.push(0);
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
        vout: vec![TxOut::new(Amount::from_sat(1250 * 100_000_000), anyone())],
        lock_time: 0,
    };
    let txid = coinbase.txid();
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = parent.hash;
    block.header.time = parent.time + 60;
    block.header.bits = 0x207fffff;
    block.transactions = vec![coinbase];
    block.transactions.extend(txs);
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
                                               // Block 31 spends block 5's coinbase: without the index it is not found
    mine_with(&node, vec![spend(early)]);
    assert!(raw_tx(&node, &early).is_err(), "found without the index");
    drop(node);

    // -txindex=1 alone keeps refusing, with Core's message
    let e = refused(start(dir.path(), true, false));
    assert!(
        e.contains("You need to rebuild the database using -reindex to change -txindex"),
        "{e}"
    );

    // -txindex=1 -reindex starts, and every block's transactions are found
    let node = start(dir.path(), true, true).unwrap();
    assert_eq!(node.chain().height(), 31);
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
    assert!(raw_tx(&node, &early).is_err(), "index still used");
    drop(node);
    assert!(start(dir.path(), false, false).is_ok());
    let e = refused(start(dir.path(), true, false));
    assert!(e.contains("-reindex to change -txindex"), "{e}");
}

/// Divi Core's GetTransaction without the index reads the block at the height
/// an unspent output of the transaction records (TransactionDiskAccessor.cpp:
/// 88-110): a transaction with an unspent output is found, one whose outputs
/// are all spent is not, and the genesis block's are never found
#[test]
fn without_the_index_a_transaction_with_an_unspent_output_is_found() {
    let dir = tempfile::tempdir().unwrap();
    let node = start(dir.path(), false, false).unwrap();
    let coinbases: Vec<Hash256> = (0..25).map(|_| mine(&node)).collect();
    let t = spend(coinbases[0]);
    let block_26 = mine_with(&node, vec![t.clone()]);

    // Block 1's coinbase: its only output is spent by T
    assert_eq!(
        raw_tx(&node, &coinbases[0]),
        Err("No information available about transaction".to_string())
    );
    // T, in block 26, and block 2's coinbase still have their outputs
    assert_eq!(
        raw_tx(&node, &t.txid()),
        Ok(json!(serialize(&t)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()))
    );
    assert!(raw_tx(&node, &coinbases[1]).is_ok());
    assert!(raw_tx(&node, &block_26).is_ok());
    let genesis = node.chain().get_block_index_by_height(0).unwrap().unwrap();
    let genesis_tx = node
        .chain()
        .get_block(&genesis.hash)
        .unwrap()
        .unwrap()
        .transactions[0]
        .txid();
    assert!(raw_tx(&node, &genesis_tx).is_err());

    // Verbose: the block fields of the block it is in
    let rpc = RpcServer::new(node.chain().clone());
    let request = serde_json::from_value(json!({
        "jsonrpc": "2.0", "id": 1, "method": "getrawtransaction",
        "params": [t.txid().to_string(), 1],
    }))
    .unwrap();
    let reply = serde_json::to_value(rpc.handle_request(request)).unwrap();
    let tip = node.chain().tip().unwrap();
    assert_eq!(reply["result"]["blockhash"], json!(tip.hash.to_string()));
    assert_eq!(reply["result"]["height"], json!(26));
    assert_eq!(reply["result"]["confirmations"], json!(1));
}
