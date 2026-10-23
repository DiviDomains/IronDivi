// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The mempool after a chain reorganisation holds what Divi Core's holds:
//! the transactions of the disconnected blocks that are still valid, parents
//! and children alike, and nothing the new chain confirmed, conflicts with or
//! no longer has.

use divi_node::config::NodeConfig;
use divi_node::{update_mempool_after_reorg, Node};
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

fn anyone() -> Script {
    Script::from_bytes(vec![0x51])
}

fn spend(coin: OutPoint, value: i64) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffffffff)],
        vout: vec![TxOut::new(Amount::from_sat(value - FEE), anyone())],
        lock_time: 0,
    }
}

struct TestNode {
    _dir: tempfile::TempDir,
    node: Node,
}

impl TestNode {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::regtest(ChainMode::Divi);
        config.data_dir = dir.path().to_path_buf();
        let node = Node::new(config).unwrap();
        TestNode { _dir: dir, node }
    }

    /// A block on `parent` paying its coinbase to anyone (`tag` makes
    /// blocks of different branches differ) and confirming `txs`
    fn block_on(&self, parent: Hash256, tag: u8, txs: &[Transaction]) -> Block {
        let parent = self.node.chain().get_block_index(&parent).unwrap().unwrap();
        let height = parent.height + 1;
        let mut sig = divi_storage::bip34_height_script(height);
        sig.push(tag);
        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), anyone())],
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

    fn tip(&self) -> Hash256 {
        self.node.chain().tip().unwrap().hash
    }

    /// Extend the active chain by one block and return its coinbase coin
    fn mine(&self, txs: &[Transaction]) -> OutPoint {
        let block = self.block_on(self.tip(), 0, txs);
        let coin = OutPoint::new(block.transactions[0].txid(), 0);
        self.node.chain().accept_block(block).unwrap();
        coin
    }

    /// Coinbase coins spendable in the next block
    fn mature_coins(&self, n: usize) -> Vec<OutPoint> {
        let coins: Vec<OutPoint> = (0..n).map(|_| self.mine(&[])).collect();
        for _ in 0..MATURITY {
            self.mine(&[]);
        }
        coins
    }

    /// Build `n` blocks on `fork` (the first confirming `first_txs`) and hand
    /// them to the chain; returns the disconnected transactions of the reorg
    /// they cause
    fn branch(&self, fork: Hash256, n: usize, first_txs: &[Transaction]) -> Vec<Transaction> {
        let mut parent = fork;
        let mut orphaned = None;
        for i in 0..n {
            let txs = if i == 0 { first_txs } else { &[] };
            let block = self.block_on(parent, 1, txs);
            let result = self.node.chain().accept_block(block).unwrap();
            parent = result.hash;
            if result.reorg_fork_height.is_some() {
                orphaned = Some(result.orphaned_transactions);
            }
        }
        assert_eq!(
            self.tip(),
            parent,
            "the branch must become the active chain"
        );
        orphaned.expect("the branch must cause a reorganisation")
    }

    fn add(&self, tx: &Transaction) {
        self.node
            .mempool()
            .add(tx.clone(), Amount::from_sat(FEE))
            .unwrap();
    }

    fn in_mempool(&self, tx: &Transaction) -> bool {
        self.node.mempool().contains(&tx.txid())
    }
}

/// A send and a send spending its change, confirmed in two blocks a
/// reorganisation disconnects, both come back to the mempool, as in Divi Core
/// (each block's transactions go back while the blocks below are connected).
#[test]
fn disconnected_send_and_its_child_both_return_to_the_mempool() {
    let t = TestNode::new();
    let coin = t.mature_coins(1)[0];
    let fork = t.tip();

    let send = spend(coin, 1250 * COIN);
    let child = spend(OutPoint::new(send.txid(), 0), 1250 * COIN - FEE);
    t.mine(std::slice::from_ref(&send));
    t.mine(std::slice::from_ref(&child));

    let orphaned = t.branch(fork, 3, &[]);
    update_mempool_after_reorg(t.node.chain(), t.node.mempool(), orphaned);

    assert!(t.in_mempool(&send), "the send is back in the mempool");
    assert!(
        t.in_mempool(&child),
        "the send spending its change is back too"
    );
    assert_eq!(
        t.node.mempool().get(&child.txid()).unwrap().fee,
        Amount::from_sat(FEE),
        "the child's fee counts its parent's output in the mempool"
    );
}

/// After a reorganisation the mempool drops what the new chain confirmed in
/// any of its blocks, not only the tip (its children stay), what conflicts
/// with the new chain, and what spends a coinbase the new chain does not have
/// (Divi Core connectTip removeConfirmedTransactions, disconnectTip
/// removeCoinbaseSpends).
#[test]
fn reorg_drops_what_the_new_chain_confirms_conflicts_with_or_lacks() {
    let t = TestNode::new();
    let coins = t.mature_coins(2);
    let fork = t.tip();
    // A coinbase only the old branch has, mature at its tip
    let old_branch_coin = t.mature_coins(1)[0];

    let confirmed = spend(coins[0], 1250 * COIN);
    let child_of_confirmed = spend(OutPoint::new(confirmed.txid(), 0), 1250 * COIN - FEE);
    let pending = spend(coins[1], 1250 * COIN);
    let mut double_spend = spend(coins[1], 1250 * COIN);
    double_spend.vout[0].value = Amount::from_sat(1250 * COIN - 2 * FEE);
    let spends_old_coin = spend(old_branch_coin, 1250 * COIN);
    for tx in [&confirmed, &child_of_confirmed, &pending, &spends_old_coin] {
        t.add(tx);
    }

    // The new branch confirms `confirmed` and the double spend in its first
    // block, well below its tip
    let orphaned = t.branch(
        fork,
        MATURITY as usize + 3,
        &[confirmed.clone(), double_spend],
    );
    update_mempool_after_reorg(t.node.chain(), t.node.mempool(), orphaned);

    assert!(!t.in_mempool(&confirmed), "confirmed by the new chain");
    assert!(
        t.in_mempool(&child_of_confirmed),
        "its child spends a coin the new chain has"
    );
    assert!(!t.in_mempool(&pending), "conflicts with the new chain");
    assert!(
        !t.in_mempool(&spends_old_coin),
        "spends a coinbase only the old branch had"
    );
    assert_eq!(t.node.mempool().size(), 1);
}

/// A block stored on a side chain confirms nothing: the mempool keeps the
/// transactions it carries (Divi Core changes the mempool only in connectTip
/// and disconnectTip).
#[test]
fn side_chain_block_leaves_the_mempool_alone() {
    let t = TestNode::new();
    let coin = t.mature_coins(1)[0];
    let pending = spend(coin, 1250 * COIN);
    t.add(&pending);

    // A sibling of the tip: same work, so it stays on a side chain
    let tip = t.node.chain().tip().unwrap();
    let side = t.block_on(tip.prev_hash, 1, std::slice::from_ref(&pending));
    t.node.accept_block(side).unwrap();
    assert_eq!(t.tip(), tip.hash, "the side block does not become the tip");

    assert!(
        t.in_mempool(&pending),
        "a side-chain block confirms nothing"
    );
}
