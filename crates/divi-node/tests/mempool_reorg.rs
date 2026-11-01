// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The mempool after a chain reorganisation holds what Divi Core's holds:
//! the transactions of the disconnected blocks that are still valid, parents
//! and children alike, and nothing the new chain confirmed, conflicts with or
//! no longer has.

use divi_crypto::KeyPair;
use divi_node::config::NodeConfig;
use divi_node::{update_mempool_after_reorg, Node};
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_script::TransactionSignatureChecker;

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;

/// Regtest coinbase and coinstake maturity (Divi Core chainparams.cpp:479)
const MATURITY: u32 = 20;

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes())
}

/// Spend `coin`, worth `value` and paying `kp`, back to `kp`, less `fee`
fn spend_with_fee(kp: &KeyPair, coin: OutPoint, value: i64, fee: i64) -> Transaction {
    spend_locked(kp, coin, value, fee, 0)
}

/// As `spend_with_fee`, with `lock_time` set and the input's sequence below
/// final, so the lock time applies
fn spend_locked(kp: &KeyPair, coin: OutPoint, value: i64, fee: i64, lock_time: u32) -> Transaction {
    let sequence = if lock_time == 0 {
        0xffffffff
    } else {
        0xfffffffe
    };
    let mut tx = Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), sequence)],
        vout: vec![TxOut::new(Amount::from_sat(value - fee), p2pkh(kp))],
        lock_time,
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

struct TestNode {
    _dir: tempfile::TempDir,
    node: Node,
    key: KeyPair,
}

impl TestNode {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::regtest(ChainMode::Divi);
        config.data_dir = dir.path().to_path_buf();
        let node = Node::new(config).unwrap();
        TestNode {
            _dir: dir,
            node,
            key: KeyPair::new_random(),
        }
    }

    /// A block on `parent` paying its coinbase to the node's key (`tag` makes
    /// blocks of different branches differ) and confirming `txs`
    fn block_on(&self, parent: Hash256, tag: u8, txs: &[Transaction]) -> Block {
        let parent = self.node.chain().get_block_index(&parent).unwrap().unwrap();
        let height = parent.height + 1;
        let mut sig = divi_storage::bip34_height_script(height);
        sig.push(tag);
        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), p2pkh(&self.key))],
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

    /// Spend `coin`, worth `value`, paying the node's key, less the fee
    fn spend(&self, coin: OutPoint, value: i64) -> Transaction {
        spend_with_fee(&self.key, coin, value, FEE)
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

    let send = t.spend(coin, 1250 * COIN);
    let child = t.spend(OutPoint::new(send.txid(), 0), 1250 * COIN - FEE);
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

    let confirmed = t.spend(coins[0], 1250 * COIN);
    let child_of_confirmed = t.spend(OutPoint::new(confirmed.txid(), 0), 1250 * COIN - FEE);
    let pending = t.spend(coins[1], 1250 * COIN);
    let double_spend = spend_with_fee(&t.key, coins[1], 1250 * COIN, 2 * FEE);
    let spends_old_coin = t.spend(old_branch_coin, 1250 * COIN);
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
    let pending = t.spend(coin, 1250 * COIN);
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

/// A send with a height lock, final for the next block, and a send spending
/// it stay in the mempool when invalidateblock lowers the tip below the lock:
/// Divi Core's disconnectTip only drops spends of coins that are gone or no
/// longer mature (removeCoinbaseSpends, ChainTipManager.cpp:175-183), and no
/// other path removes a non-final transaction from its mempool.
#[test]
fn a_send_a_lower_tip_makes_non_final_stays_in_the_mempool() {
    let t = TestNode::new();
    let coin = t.mature_coins(1)[0];
    let height = t.node.chain().height();

    // Final for the next block (height + 1), not for the one below it
    let locked = spend_locked(&t.key, coin, 1250 * COIN, FEE, height);
    let child = t.spend(OutPoint::new(locked.txid(), 0), 1250 * COIN - FEE);
    t.add(&locked);
    t.add(&child);

    let tip = t.tip();
    let disconnected = t.node.chain().invalidate_block(&tip).unwrap();
    assert_eq!(t.node.chain().height(), height - 1);
    update_mempool_after_reorg(t.node.chain(), t.node.mempool(), disconnected);

    assert!(t.in_mempool(&locked), "the locked send stays");
    assert!(t.in_mempool(&child), "its child stays");
}

/// A send with a height lock, confirmed in a block that invalidateblock
/// disconnects together with the block below it, comes back to the mempool
/// although the new tip is below its lock: Divi Core's disconnectTip offers a
/// block's transactions to AcceptToMemoryPool before it moves the tip
/// (ChainTipManager.cpp:175-185), so IsStandardTx checks the lock against the
/// block that held it (MempoolConsensus.cpp:61), where it passed.
#[test]
fn a_locked_send_of_a_disconnected_block_returns_to_the_mempool() {
    let t = TestNode::new();
    let coin = t.mature_coins(1)[0];
    t.mine(&[]);
    let lock_height = t.node.chain().height();
    let below = t.tip();

    // Final for the next block (lock_height + 1), which confirms it
    let locked = spend_locked(&t.key, coin, 1250 * COIN, FEE, lock_height);
    t.mine(std::slice::from_ref(&locked));

    // Both blocks off: the next height is lock_height, where the lock holds
    let disconnected = t.node.chain().invalidate_block(&below).unwrap();
    assert_eq!(t.node.chain().height(), lock_height - 1);
    update_mempool_after_reorg(t.node.chain(), t.node.mempool(), disconnected);

    assert!(
        t.in_mempool(&locked),
        "the locked send is back in the mempool"
    );
}

/// Make the next transaction checked for the mempool wait, after its checks
/// and before it is inserted, until `resume` is called or two seconds pass.
/// Returns once the checks are done, with the add still running on its own
/// thread, and the add's handle.
struct HeldAdd {
    resume: std::sync::mpsc::Sender<()>,
    add: std::thread::JoinHandle<Result<Hash256, divi_node::NodeError>>,
}

fn add_held_after_its_checks(t: &TestNode, tx: &Transaction) -> HeldAdd {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Mutex};
    let (checked, checks_done) = mpsc::channel();
    let (resume, resumed) = mpsc::channel::<()>();
    let resumed = Mutex::new(resumed);
    let armed = AtomicBool::new(true);
    let chain = t.node.chain().clone();
    t.node
        .mempool()
        .set_validator(std::sync::Arc::new(move |pool, tx, origin| {
            let result = divi_node::check_mempool_transaction(&chain, pool, tx, origin);
            if armed.swap(false, Ordering::SeqCst) {
                let _ = checked.send(());
                let _ = resumed
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(2));
            }
            result
        }));
    let mempool = t.node.mempool().clone();
    let tx = tx.clone();
    let add = std::thread::spawn(move || mempool.add(tx, Amount::from_sat(FEE)));
    checks_done.recv().unwrap();
    HeldAdd { resume, add }
}

impl HeldAdd {
    fn finish(self) {
        let _ = self.resume.send(());
        // Accepted or refused, as long as it does not stay with a spent input
        let _ = self.add.join().unwrap();
    }
}

/// A send checked against the chain just before a block spending the same
/// coin connects does not stay in the mempool once the block's transactions
/// are cleaned out of it. Divi Core checks a transaction and connects a block
/// under the same lock (cs_main: main.cpp:726, ChainTipManager.cpp:139-141),
/// so a send either sees the block (refused, inputs spent) or is in the
/// mempool when the block removes its conflicts.
#[test]
fn a_send_checked_before_a_block_spends_its_coin_does_not_stay() {
    let t = TestNode::new();
    let coin = t.mature_coins(1)[0];
    let send = t.spend(coin, 1250 * COIN);
    let double_spend = spend_with_fee(&t.key, coin, 1250 * COIN, 2 * FEE);

    let held = add_held_after_its_checks(&t, &send);
    // The block comes while the send is between its checks and its insert:
    // connected, then the mempool cleaned of what it confirms and conflicts with
    let block = t.block_on(t.tip(), 0, std::slice::from_ref(&double_spend));
    t.node.accept_block(block).unwrap();
    held.finish();

    assert!(
        !t.in_mempool(&send),
        "a send whose coin the chain spent is not in the mempool"
    );
    assert_eq!(t.node.mempool().size(), 0);
}

/// The same across a reorganisation: a send checked against the old branch,
/// added while the chain moves to a branch that spends its coin, does not
/// stay in the mempool after the reorganisation's cleanup.
#[test]
fn a_send_checked_before_a_reorg_spends_its_coin_does_not_stay() {
    let t = TestNode::new();
    let coin = t.mature_coins(1)[0];
    let fork = t.tip();
    t.mine(&[]);
    let send = t.spend(coin, 1250 * COIN);
    let double_spend = spend_with_fee(&t.key, coin, 1250 * COIN, 2 * FEE);

    let held = add_held_after_its_checks(&t, &send);
    let orphaned = t.branch(fork, 2, std::slice::from_ref(&double_spend));
    update_mempool_after_reorg(t.node.chain(), t.node.mempool(), orphaned);
    held.finish();

    assert!(
        !t.in_mempool(&send),
        "a send whose coin the new chain spent is not in the mempool"
    );
    assert_eq!(t.node.mempool().size(), 0);
}

impl TestNode {
    /// The blockchain RPC with the reorg hook irondivid gives it
    /// (bin/irondivid/src/main.rs mempool_reorg_hook, without a wallet)
    fn chain_rpc(&self) -> divi_rpc::blockchain::BlockchainRpc {
        let rpc = divi_rpc::blockchain::BlockchainRpc::new(self.node.chain().clone());
        let chain = self.node.chain().clone();
        let mempool = self.node.mempool().clone();
        rpc.set_reorg_hook(std::sync::Arc::new(move |disconnected| {
            update_mempool_after_reorg(&chain, &mempool, disconnected)
        }));
        rpc
    }

    fn block_rpc(&self, rpc: &divi_rpc::blockchain::BlockchainRpc, method: &str, hash: Hash256) {
        let params = divi_rpc::Params::Array(vec![serde_json::json!(hash.to_string())]);
        rpc.invalidate_block_family(method, &params).unwrap();
    }

    /// Store `n` blocks on `fork` as a side chain (`tag` sets them apart);
    /// returns their hashes, lowest first
    fn side_branch(&self, fork: Hash256, n: usize, tag: u8) -> Vec<Hash256> {
        let tip = self.tip();
        let mut hashes = Vec::new();
        let mut parent = fork;
        for _ in 0..n {
            let block = self.block_on(parent, tag, &[]);
            parent = self.node.chain().accept_block(block).unwrap().hash;
            hashes.push(parent);
        }
        assert_eq!(self.tip(), tip, "the side branch stays a side chain");
        hashes
    }
}

/// reconsiderblock that moves the node back to a branch with more work
/// returns the transactions of the blocks it disconnects to the mempool, a
/// send and the send spending its change: Divi Core's reconsiderblock
/// activates the best chain (rpcblockchain.cpp:676-678), which disconnects
/// each block through disconnectTip and offers its transactions to the mempool
/// (MostWorkChainTransitionMediator.cpp:33-38, ChainTipManager.cpp:175-182).
#[test]
fn reconsiderblock_that_switches_branches_returns_their_transactions() {
    let t = TestNode::new();
    let rpc = t.chain_rpc();
    let coin = t.mature_coins(1)[0];
    let fork = t.tip();

    // Branch A, two blocks: the send, then the send of its change
    let send = t.spend(coin, 1250 * COIN);
    let child = t.spend(OutPoint::new(send.txid(), 0), 1250 * COIN - FEE);
    t.mine(std::slice::from_ref(&send));
    t.mine(std::slice::from_ref(&child));
    let tip_a = t.tip();

    // Branch B, three blocks, takes over
    let b = t.side_branch(fork, 2, 1);
    let b3 = t.block_on(b[1], 1, &[]);
    let orphaned = t
        .node
        .chain()
        .accept_block(b3)
        .unwrap()
        .orphaned_transactions;
    update_mempool_after_reorg(t.node.chain(), t.node.mempool(), orphaned);
    let tip_b = t.tip();
    assert_ne!(tip_b, tip_a, "branch B is the active chain");

    // invalidateblock on B's first block: the node goes back to branch A,
    // which confirms both sends again
    t.block_rpc(&rpc, "invalidateblock", b[0]);
    assert_eq!(t.tip(), tip_a, "the node moved to branch A");
    assert!(!t.in_mempool(&send) && !t.in_mempool(&child));

    // reconsiderblock: B has more work again, so the node disconnects A
    t.block_rpc(&rpc, "reconsiderblock", b[0]);
    assert_eq!(t.tip(), tip_b, "the node moved back to branch B");
    assert!(t.in_mempool(&send), "the send is back in the mempool");
    assert!(t.in_mempool(&child), "the send of its change is back too");
}

/// invalidateblock whose tip the node then leaves for another branch returns
/// the transactions of every block it disconnects to the mempool, not only
/// those of the invalidated block and the blocks above it: Divi Core's
/// invalidateblock disconnects down to the block (BlockInvalidationHelpers.cpp
/// :129-143), then activates the best chain (rpcblockchain.cpp:638-640), which
/// disconnects the rest down to the fork the same way.
#[test]
fn invalidateblock_that_switches_branches_returns_every_disconnected_transaction() {
    let t = TestNode::new();
    let rpc = t.chain_rpc();
    let coin = t.mature_coins(1)[0];
    let fork = t.tip();

    // Branch B, active, three blocks: the send in the lowest
    let send = t.spend(coin, 1250 * COIN);
    t.mine(std::slice::from_ref(&send));
    t.mine(&[]);
    t.mine(&[]);
    let tip_b = t.tip();
    // Branch A, three blocks of the same work, stays on the side
    let a = t.side_branch(fork, 3, 1);

    // invalidateblock on B's tip: B's two lower blocks have less work than
    // A, so the node disconnects them too and moves to A
    t.block_rpc(&rpc, "invalidateblock", tip_b);
    assert_eq!(t.tip(), a[2], "the node moved to branch A");
    assert!(t.in_mempool(&send), "the send of B's lowest block is back");
}
