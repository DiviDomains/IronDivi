// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A -reindex is carried out on the import thread once the node runs, as
//! Divi Core reindexes in its import thread after init, with RPC answering
//! (init.cpp:686-690, :1580, :1639). One that was stopped before it finished
//! is carried out again at the next start (init.cpp:1072-1073;
//! BlockIndexLoading.cpp:287-290).

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use std::path::Path;

fn config(dir: &Path, reindex: bool) -> NodeConfig {
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.to_path_buf();
    config.index.txindex = true;
    config.index.reindex = reindex;
    config
}

/// `n` regtest proof-of-work blocks on the chain in `dir`; the txid of each
/// block's coinbase
fn mine(dir: &Path, n: usize) -> Vec<Hash256> {
    let node = Node::new(config(dir, false)).unwrap();
    let mut txids = Vec::new();
    for _ in 0..n {
        let parent = node.chain().tip().unwrap();
        let mut sig = divi_storage::bip34_height_script(parent.height + 1);
        sig.push(0);
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = parent.hash;
        block.header.time = parent.time + 60;
        block.header.bits = 0x207fffff;
        block.transactions = vec![Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250 * 100_000_000),
                Script::new_p2pkh(&[7; 20]),
            )],
            lock_time: 0,
        }];
        block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        txids.push(block.transactions[0].txid());
        node.chain().accept_block(block).unwrap();
    }
    txids
}

fn indexed(node: &Node, txids: &[Hash256]) -> usize {
    txids
        .iter()
        .filter(|txid| node.chain().get_transaction(txid).unwrap().is_some())
        .count()
}

/// The transaction index is built again on the import thread, not while the
/// node is made: until then a lookup misses and blocks from peers are not
/// taken
#[test]
fn reindex_runs_on_the_import_thread() {
    let dir = tempfile::tempdir().unwrap();
    let txids = mine(dir.path(), 30);

    let node = Node::new(config(dir.path(), true)).unwrap();
    assert_eq!(node.chain().height(), 30);
    assert_eq!(
        indexed(&node, &txids),
        0,
        "the index was built before the start"
    );
    node.spawn_import();
    node.wait_for_import();
    assert!(!node.chain().is_importing());
    assert_eq!(indexed(&node, &txids), 30);
    drop(node);

    // Done: the next start has nothing left to build
    let node = Node::new(config(dir.path(), false)).unwrap();
    assert_eq!(indexed(&node, &txids), 30);
}

/// A -reindex that did not finish (the node stopped before the import thread
/// was done) is carried out at the next start without -reindex, from the
/// start of the chain
#[test]
fn a_stopped_reindex_is_carried_out_at_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let txids = mine(dir.path(), 30);

    let node = Node::new(config(dir.path(), true)).unwrap();
    drop(node);

    let node = Node::new(config(dir.path(), false)).unwrap();
    assert_eq!(
        indexed(&node, &txids),
        0,
        "the reindex was not carried out again"
    );
    node.spawn_import();
    node.wait_for_import();
    assert_eq!(indexed(&node, &txids), 30);
    drop(node);

    let node = Node::new(config(dir.path(), false)).unwrap();
    assert_eq!(indexed(&node, &txids), 30);
}

/// A held import thread (irondivid holds it until its wallet is loaded, as
/// Divi Core starts its import thread then, init.cpp:1580) does nothing, and
/// blocks from peers stay refused, until it is released
#[test]
fn a_held_import_waits_for_its_release() {
    let dir = tempfile::tempdir().unwrap();
    let txids = mine(dir.path(), 10);

    let node = Node::new(config(dir.path(), true)).unwrap();
    node.hold_import();
    node.spawn_import();
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(node.chain().is_importing());
    assert_eq!(indexed(&node, &txids), 0, "the reindex ran while held");
    node.release_import();
    node.wait_for_import();
    assert!(!node.chain().is_importing());
    assert_eq!(indexed(&node, &txids), 10);
}
