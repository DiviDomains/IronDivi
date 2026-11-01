// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A reorganization a stop cut off is finished at the next start, and the
//! transactions of the blocks it then disconnects go to the mempool, as in
//! Divi Core: its start connects the best chain (init.cpp:1569), and each
//! disconnectTip on the way offers the block's transactions to the mempool
//! (ChainTipManager.cpp:175-182).
//!
//! The stop is made before the first disconnect, not by timing a kill: the
//! branch is stored with more work than the tip and the reorganization target
//! is recorded, as `reorganize_chain` records it before it disconnects.

use divi_crypto::KeyPair;
use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_script::TransactionSignatureChecker;
use divi_storage::ChainDatabase;
use std::path::Path;

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;

/// Regtest coinbase maturity (Divi Core chainparams.cpp:479)
const MATURITY: u32 = 20;

/// The chain database's record of a reorganization under way
/// (divi-storage chain.rs REORG_TARGET_KEY)
const REORG_TARGET_KEY: &[u8] = b"reorg_target";

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes())
}

/// Spend `coin`, worth `value` and paying `kp`, back to `kp`, less the fee
fn spend(kp: &KeyPair, coin: OutPoint, value: i64) -> Transaction {
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

fn start(dir: &Path) -> Node {
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.to_path_buf();
    Node::new(config).unwrap()
}

/// A block on `parent` paying its coinbase to `kp` (`tag` makes blocks of
/// different branches differ) and confirming `txs`
fn block_on(node: &Node, kp: &KeyPair, parent: Hash256, tag: u8, txs: &[Transaction]) -> Block {
    let parent = node.chain().get_block_index(&parent).unwrap().unwrap();
    let height = parent.height + 1;
    let mut sig = divi_storage::bip34_height_script(height);
    sig.push(tag);
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
        vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), p2pkh(kp))],
        lock_time: 0,
    };
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = parent.hash;
    block.header.time = parent.time + 60 + u32::from(tag);
    block.header.bits = 0x207fffff;
    block.transactions = vec![coinbase];
    block.transactions.extend_from_slice(txs);
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    block
}

/// Extend the chain on `parent` with `n` blocks of branch `tag`, the first
/// confirming `first_txs`; the last block's hash
fn extend(
    node: &Node,
    kp: &KeyPair,
    parent: Hash256,
    tag: u8,
    n: usize,
    first_txs: &[Transaction],
) -> Hash256 {
    let mut parent = parent;
    for i in 0..n {
        let txs = if i == 0 { first_txs } else { &[] };
        let block = block_on(node, kp, parent, tag, txs);
        parent = node.chain().accept_block(block).unwrap().hash;
    }
    parent
}

/// The datadir left by a stop at the start of a reorganization: the active
/// chain is the fork, then a block confirming `a1_txs` and one confirming
/// `a2_txs`; three blocks on the fork, the first confirming `b1_txs`, are
/// stored with more work, and the reorganization to them is recorded.
/// Returns the branch's last block.
fn interrupted_reorg(
    dir: &Path,
    kp: &KeyPair,
    fork: Hash256,
    a1_txs: &[Transaction],
    a2_txs: &[Transaction],
    b1_txs: &[Transaction],
) -> Hash256 {
    let node = start(dir);
    // The branch first, set aside again by reverseblocktransactions: stored,
    // valid, more work than the tip, not active
    let b3 = extend(&node, kp, fork, 1, 3, b1_txs);
    assert_eq!(node.chain().tip().unwrap().hash, b3);
    let b1 = node
        .chain()
        .get_block_index_by_height(node.chain().height() - 2);
    let b1 = b1.unwrap().unwrap().hash;
    node.chain().reverse_block_transactions(&b1).unwrap();
    assert_eq!(node.chain().tip().unwrap().hash, fork);
    let a1 = extend(&node, kp, fork, 0, 1, a1_txs);
    let a2 = extend(&node, kp, a1, 0, 1, a2_txs);
    assert_eq!(
        node.chain().tip().unwrap().hash,
        a2,
        "the shorter branch is the active chain"
    );
    drop(node);

    let db = ChainDatabase::open(dir.join("chainstate")).unwrap();
    db.put_metadata_synced(REORG_TARGET_KEY, b3.as_bytes())
        .unwrap();
    drop(db);
    b3
}

/// A fork with `n` mature coinbase coins of `kp` spendable on it
fn fork_with_coins(dir: &Path, kp: &KeyPair, n: usize) -> (Hash256, Vec<OutPoint>) {
    let node = start(dir);
    let mut tip = node.chain().tip().unwrap().hash;
    let mut coins = Vec::new();
    for _ in 0..n {
        let block = block_on(&node, kp, tip, 0, &[]);
        coins.push(OutPoint::new(block.transactions[0].txid(), 0));
        tip = node.chain().accept_block(block).unwrap().hash;
    }
    tip = extend(&node, kp, tip, 0, MATURITY as usize, &[]);
    (tip, coins)
}

/// A send and the send spending its change, confirmed in the two blocks the
/// finished reorganization disconnects, are in the mempool after the start
#[test]
fn transactions_of_blocks_an_interrupted_reorg_disconnects_return_to_the_mempool() {
    let dir = tempfile::tempdir().unwrap();
    let kp = KeyPair::new_random();
    let (fork, coins) = fork_with_coins(dir.path(), &kp, 1);
    let send = spend(&kp, coins[0], 1250 * COIN);
    let child = spend(&kp, OutPoint::new(send.txid(), 0), 1250 * COIN - FEE);
    let b3 = interrupted_reorg(
        dir.path(),
        &kp,
        fork,
        std::slice::from_ref(&send),
        std::slice::from_ref(&child),
        &[],
    );

    let node = start(dir.path());
    assert_eq!(
        node.chain().tip().unwrap().hash,
        b3,
        "the start finishes the reorganization"
    );
    assert!(
        node.mempool().contains(&send.txid()),
        "the send of a block the start disconnected is in the mempool"
    );
    assert!(
        node.mempool().contains(&child.txid()),
        "the send spending its change is in the mempool too"
    );
    assert_eq!(node.mempool().size(), 2);
}

/// A transaction the new branch confirms stays out of the mempool, and so
/// does one that spends a coin a transaction of the new branch spends; a
/// child of the confirmed one comes back
#[test]
fn interrupted_reorg_keeps_confirmed_and_conflicting_transactions_out_of_the_mempool() {
    let dir = tempfile::tempdir().unwrap();
    let kp = KeyPair::new_random();
    let (fork, coins) = fork_with_coins(dir.path(), &kp, 2);
    let send = spend(&kp, coins[0], 1250 * COIN);
    let child = spend(&kp, OutPoint::new(send.txid(), 0), 1250 * COIN - FEE);
    let lost = spend(&kp, coins[1], 1250 * COIN);
    // The same coin spent again, paying a larger fee: a different transaction
    let winner = spend(&kp, coins[1], 1250 * COIN - FEE);
    let b3 = interrupted_reorg(
        dir.path(),
        &kp,
        fork,
        &[send.clone(), lost.clone()],
        std::slice::from_ref(&child),
        &[send.clone(), winner],
    );

    let node = start(dir.path());
    assert_eq!(node.chain().tip().unwrap().hash, b3);
    assert!(
        !node.mempool().contains(&send.txid()),
        "the send the new branch confirms is not in the mempool"
    );
    assert!(
        !node.mempool().contains(&lost.txid()),
        "a send whose coin the new branch spends is not in the mempool"
    );
    assert!(
        node.mempool().contains(&child.txid()),
        "the child of the confirmed send, which the new branch lacks, is"
    );
    assert_eq!(node.mempool().size(), 1);
}
