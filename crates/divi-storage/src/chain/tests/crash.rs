// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! What the chain database holds when the process dies part-way through
//! connecting or disconnecting blocks. A stop point ends the operation where a
//! crash would; the database is then reopened as a restart would open it.

use super::*;
use crate::fault;
use crate::search_index::SearchIndex;
use std::path::Path;

fn open_chain(path: &Path, search: bool, txindex: bool) -> Chain {
    let db = Arc::new(ChainDatabase::open(path.join("chain")).unwrap());
    let mut chain = Chain::new(
        db.clone(),
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    if txindex {
        chain.enable_tx_index(Arc::new(TxIndex::open(path.join("txindex")).unwrap()));
    }
    if search {
        chain.enable_search_index(Arc::new(SearchIndex::new(db, true, true)));
    }
    chain
}

/// Every output of the tip block is unspent (nothing above the tip spends it)
fn tip_outputs_unspent(chain: &Chain) -> bool {
    let tip = chain.tip().unwrap();
    if tip.height == 0 {
        return true; // genesis outputs are never connected
    }
    let block = chain.get_block(&tip.hash).unwrap().unwrap();
    block.transactions.iter().all(|tx| {
        let txid = chain.compute_txid(tx);
        (0..tx.vout.len() as u32).all(|vout| chain.has_utxo(&OutPoint::new(txid, vout)).unwrap())
    })
}

fn accept(chain: &Chain, parent: (Hash256, u32), key: u8) -> (Hash256, u32, Block) {
    let block = create_child_block_with_pubkey(parent.0, parent.1, [key; 20]);
    let hash = chain.accept_block(block.clone()).unwrap().hash;
    (hash, block.header.time, block)
}

/// A: genesis-A1-A2 active; B: genesis-B1-B2 stored. Returns B2's (hash, time).
fn two_branches(chain: &Chain) -> ((Hash256, u32), Hash256) {
    let (g, gt) = get_genesis_info(chain);
    let (a1, a1t, _) = accept(chain, (g, gt), 0x0a);
    let (a2, _, _) = accept(chain, (a1, a1t), 0x0b);
    let (b1, b1t, _) = accept(chain, (g, gt + 1), 0x1a);
    let (b2, b2t, _) = accept(chain, (b1, b1t), 0x1b);
    assert_eq!(chain.tip().unwrap().hash, a2);
    ((b2, b2t), a2)
}

/// A crash between two disconnects of a reorg leaves a chain that starts:
/// every disconnect moves the tip with the UTXO changes, as Divi Core's
/// disconnectTip flushes both together
#[test]
fn stop_inside_two_block_reorg_leaves_a_chain_that_starts() {
    let dir = tempdir().unwrap();
    let chain = open_chain(dir.path(), true, false);
    let (b2, _) = two_branches(&chain);
    let b3 = create_child_block_with_pubkey(b2.0, b2.1, [0x1c; 20]);
    fault::arm("block disconnected", 1);
    assert!(chain.accept_block(b3).is_err());
    fault::disarm();
    drop(chain);

    let chain = open_chain(dir.path(), true, false);
    chain
        .verify_recent_blocks(100)
        .expect("the chain left by the stop must pass the start-up check");
    assert!(
        tip_outputs_unspent(&chain),
        "UTXO set does not match the tip"
    );
}

/// The same for a one-block reorg: the tip on disk must match the UTXO set
#[test]
fn stop_inside_one_block_reorg_keeps_utxo_set_and_tip_together() {
    let dir = tempdir().unwrap();
    let chain = open_chain(dir.path(), false, false);
    let (g, gt) = get_genesis_info(&chain);
    accept(&chain, (g, gt), 0x0a);
    let (b1, b1t, _) = accept(&chain, (g, gt + 1), 0x1a);
    let b2 = create_child_block_with_pubkey(b1, b1t, [0x1b; 20]);
    fault::arm("block disconnected", 0);
    assert!(chain.accept_block(b2).is_err());
    fault::disarm();
    drop(chain);

    let chain = open_chain(dir.path(), false, false);
    assert!(
        tip_outputs_unspent(&chain),
        "UTXO set does not match the tip"
    );
    chain.verify_recent_blocks(100).unwrap();
}

/// After such a stop the next start finishes the reorganization
#[test]
fn interrupted_reorg_is_finished_at_start() {
    let dir = tempdir().unwrap();
    let chain = open_chain(dir.path(), true, false);
    let (b2, _) = two_branches(&chain);
    let b3 = create_child_block_with_pubkey(b2.0, b2.1, [0x1c; 20]);
    let b3_hash = compute_block_hash(&b3.header);
    fault::arm("block disconnected", 1);
    assert!(chain.accept_block(b3).is_err());
    fault::disarm();
    drop(chain);

    let chain = open_chain(dir.path(), true, false);
    assert!(chain.finish_interrupted_reorg().unwrap());
    assert_eq!(chain.tip().unwrap().hash, b3_hash);
    assert_eq!(chain.height(), 3);
    chain.verify_recent_blocks(100).unwrap();
    assert!(tip_outputs_unspent(&chain));
    // Nothing left to finish at the next start
    drop(chain);
    let chain = open_chain(dir.path(), true, false);
    assert!(!chain.finish_interrupted_reorg().unwrap());
    assert_eq!(chain.tip().unwrap().hash, b3_hash);
}

/// The start-up check undoes the newest blocks in memory and refuses a UTXO
/// set that does not belong to the tip, as Divi Core's VerifyDB does
#[test]
fn start_up_check_refuses_utxo_set_that_does_not_match_tip() {
    let dir = tempdir().unwrap();
    let chain = open_chain(dir.path(), false, false);
    create_chain(&chain, 3);
    chain.verify_recent_blocks(100).unwrap();

    // An output of the tip is missing
    let tip = chain.tip().unwrap();
    let block = chain.get_block(&tip.hash).unwrap().unwrap();
    let coin = OutPoint::new(chain.compute_txid(&block.transactions[0]), 0);
    let saved = chain.get_utxo(&coin).unwrap().unwrap();
    let mut batch = BatchedUtxoWriter::new();
    batch.remove(coin);
    chain.db.flush_utxo_batch(&batch).unwrap();
    let err = chain.verify_recent_blocks(100).unwrap_err();
    assert!(err.to_string().contains("UTXO set"), "{err}");

    // Back in place it passes; a coin of a block below the tip missing fails
    let mut batch = BatchedUtxoWriter::new();
    batch.add(coin, saved);
    chain.db.flush_utxo_batch(&batch).unwrap();
    chain.verify_recent_blocks(100).unwrap();
    let below = chain.get_block(&tip.prev_hash).unwrap().unwrap();
    let mut batch = BatchedUtxoWriter::new();
    batch.remove(OutPoint::new(chain.compute_txid(&below.transactions[0]), 0));
    chain.db.flush_utxo_batch(&batch).unwrap();
    assert!(chain.verify_recent_blocks(100).is_err());
}

/// A block's address and spent index entries reach disk with the block
#[test]
fn stop_after_block_write_keeps_its_address_index_entries() {
    let dir = tempdir().unwrap();
    let chain = open_chain(dir.path(), true, false);
    let (g, gt) = get_genesis_info(&chain);
    let (h1, t1, _) = accept(&chain, (g, gt), 0x0a);
    let block = create_child_block_with_pubkey(h1, t1, [0x0b; 20]);
    let hash = compute_block_hash(&block.header);
    fault::arm("block connected", 0);
    assert!(chain.accept_block(block.clone()).is_err());
    fault::disarm();
    drop(chain);

    let chain = open_chain(dir.path(), true, false);
    assert_eq!(chain.tip().unwrap().hash, hash, "the block was written");
    let unspent = chain
        .search_index()
        .unwrap()
        .read_unspent(1, &[0x0b; 20])
        .unwrap();
    let txid = chain.compute_txid(&block.transactions[0]);
    assert!(
        unspent.iter().any(|(k, _)| k.txid == txid),
        "address index lacks the connected block's output"
    );
}

/// A reorg moves the address index with the chain: the old branch's entries
/// go, the new branch's come
#[test]
fn reorg_moves_address_index_with_the_chain() {
    let dir = tempdir().unwrap();
    let chain = open_chain(dir.path(), true, false);
    let (b2, _) = two_branches(&chain);
    accept(&chain, b2, 0x1c);
    assert_eq!(chain.height(), 3);
    let search = chain.search_index().unwrap();
    assert!(search.read_unspent(1, &[0x0a; 20]).unwrap().is_empty());
    assert!(search.read_unspent(1, &[0x0b; 20]).unwrap().is_empty());
    for key in [0x1a, 0x1b, 0x1c] {
        assert_eq!(search.read_unspent(1, &[key; 20]).unwrap().len(), 1);
    }
}

/// A coin created and spent in the same block leaves with the block when it is
/// disconnected (Divi Core undoes the spender, then the creator)
#[test]
fn disconnect_does_not_bring_back_coin_created_and_spent_in_block() {
    let dir = tempdir().unwrap();
    let chain = open_chain(dir.path(), false, false);
    let (g, gt) = get_genesis_info(&chain);
    let anyone = Script::from_bytes(vec![0x51]);
    let spend = |coin: OutPoint, value: i64| Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffff_ffff)],
        vout: vec![TxOut::new(Amount::from_sat(value), anyone.clone())],
        lock_time: 0,
    };
    let mut parent = (g, gt);
    let mut coin = None;
    for _ in 0..21 {
        let mut block = create_child_block(parent.0, parent.1);
        block.transactions[0].vout[0].script_pubkey = anyone.clone();
        seal(&mut block);
        let hash = chain.accept_block(block.clone()).unwrap().hash;
        coin.get_or_insert(OutPoint::new(block.transactions[0].txid(), 0));
        parent = (hash, block.header.time);
    }
    let fork = parent;
    let t1 = spend(coin.unwrap(), 1249_00000000);
    let t2 = spend(OutPoint::new(t1.txid(), 0), 1248_00000000);
    let mut a22 = create_child_block(fork.0, fork.1);
    a22.transactions.push(t1.clone());
    a22.transactions.push(t2.clone());
    seal(&mut a22);
    chain.accept_block(a22).unwrap();
    assert!(!chain.has_utxo(&OutPoint::new(t1.txid(), 0)).unwrap());

    let mut parent = (fork.0, fork.1 + 1);
    for _ in 0..2 {
        let (hash, time, _) = accept(&chain, parent, 0x2b);
        parent = (hash, time);
    }
    assert_eq!(chain.height(), 23);
    assert!(
        !chain.has_utxo(&OutPoint::new(t1.txid(), 0)).unwrap(),
        "a coin spent inside the disconnected block came back"
    );
    assert!(!chain.has_utxo(&OutPoint::new(t2.txid(), 0)).unwrap());
    assert!(chain.has_utxo(&coin.unwrap()).unwrap());
    chain.verify_recent_blocks(100).unwrap();
}

/// A transaction index that came back behind the chain (power loss: the two
/// databases recover to different points) is filled in at start
#[test]
fn tx_index_behind_the_chain_is_filled_in_at_start() {
    let dir = tempdir().unwrap();
    let chain = open_chain(dir.path(), false, true);
    create_chain(&chain, 2);
    let tip = chain.tip().unwrap();
    drop(chain);
    let saved = dir.path().join("txindex-saved");
    copy_dir(&dir.path().join("txindex"), &saved);

    let chain = open_chain(dir.path(), false, true);
    let (_, _, block) = accept(&chain, (tip.hash, tip.time), 0x33);
    let txid = chain.compute_txid(&block.transactions[0]);
    drop(chain);
    std::fs::remove_dir_all(dir.path().join("txindex")).unwrap();
    std::fs::rename(&saved, dir.path().join("txindex")).unwrap();

    let chain = open_chain(dir.path(), false, true);
    assert_eq!(chain.height(), 3);
    let tx_index = chain.tx_index.as_ref().unwrap();
    assert!(
        tx_index.get_location(&txid).unwrap().is_some(),
        "transaction of the block above the saved index is not indexed"
    );
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}
