// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The mempool takes the transactions Divi Core's AcceptToMemoryPool takes and
//! refuses the ones it refuses, with Core's reject code, reason and peer score
//! (MempoolConsensus.cpp:268-422).

use divi_crypto::KeyPair;
use divi_network::TxRelayEvent;
use divi_node::config::NodeConfig;
use divi_node::{accept_relayed_transaction, Node};
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_script::TransactionSignatureChecker;
use std::net::IpAddr;

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;
const COINBASE: i64 = 1250 * COIN;

struct TestNode {
    _dir: tempfile::TempDir,
    node: Node,
}

impl TestNode {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::regtest(ChainMode::Divi);
        config.data_dir = dir.path().to_path_buf();
        TestNode {
            node: Node::new(config).unwrap(),
            _dir: dir,
        }
    }

    fn mine(&self, payee: Script) -> OutPoint {
        let chain = self.node.chain();
        let tip = chain.tip().unwrap();
        // BIP34: the coinbase starts with the height
        let mut tag = divi_storage::bip34_height_script(tip.height + 1);
        tag.extend_from_slice(&(tip.height + 1).to_le_bytes());
        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(tag))],
            vout: vec![TxOut::new(Amount::from_sat(COINBASE), payee)],
            lock_time: 0,
        };
        let outpoint = OutPoint::new(coinbase.txid(), 0);
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        block.transactions = vec![coinbase];
        block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
        // Proof of work for the block's bits
        let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        chain.accept_block(block).unwrap();
        outpoint
    }

    fn mine_empty(&self, n: u32) {
        for _ in 0..n {
            self.mine(Script::new_p2pkh(&[0xee; 20]));
        }
    }

    /// A coinbase paying `kp`, `depth` blocks deep
    fn coin_at_depth(&self, kp: &KeyPair, depth: u32) -> OutPoint {
        let coin = self.mine(p2pkh(kp));
        self.mine_empty(depth - 1);
        coin
    }

    /// A mature coinbase paying `kp` (regtest maturity is 20 blocks)
    fn fund(&self, kp: &KeyPair) -> OutPoint {
        self.coin_at_depth(kp, 21)
    }

    fn submit(&self, tx: Transaction, fee: i64) -> Result<(), String> {
        self.node
            .mempool()
            .add(tx, Amount::from_sat(fee))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn peer(&self, id: u64, ip: &str) -> (u64, IpAddr) {
        let ip: IpAddr = ip.parse().unwrap();
        self.node.peer_manager().scoring().register_peer(id, ip);
        (id, ip)
    }

    fn relay(&self, from_peer: u64, tx: Transaction) -> Result<(), String> {
        let event = TxRelayEvent {
            txid: tx.txid(),
            tx,
            fee: None,
            from_peer,
        };
        accept_relayed_transaction(
            self.node.chain(),
            self.node.mempool(),
            self.node.peer_manager(),
            &event,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    fn score(&self, peer: u64) -> i32 {
        self.node
            .peer_manager()
            .scoring()
            .get_stats(peer)
            .map_or(0, |s| s.misbehavior_score)
    }

    fn banned(&self, ip: &IpAddr) -> bool {
        self.node.peer_manager().is_banned(ip)
    }
}

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes())
}

fn tx(inputs: &[OutPoint], outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 1,
        vin: inputs
            .iter()
            .map(|op| TxIn::new(*op, Script::new(), 0xffffffff))
            .collect(),
        vout: outputs,
        lock_time: 0,
    }
}

fn pay(value: i64, to: &KeyPair) -> TxOut {
    TxOut::new(Amount::from_sat(value), p2pkh(to))
}

/// The scriptSig pushes (signature, pubkey) for input `i` spending `value` from `kp`
fn sig_and_key(tx: &Transaction, i: usize, kp: &KeyPair, value: i64) -> Vec<u8> {
    let checker = TransactionSignatureChecker::new(tx, i, Amount::from_sat(value));
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
    ss
}

/// Sign every input; all spend `value` from `kp`
fn sign_all(mut tx: Transaction, kp: &KeyPair, value: i64) -> Transaction {
    for i in 0..tx.vin.len() {
        let ss = sig_and_key(&tx, i, kp, value);
        tx.vin[i].script_sig = Script::from_bytes(ss);
    }
    tx
}

/// CheckTransaction failures are refused as "bad-tx": CheckTransaction's own
/// DoS 100 plus AcceptToMemoryPool's 100, which CValidationState adds up
/// (MempoolConsensus.cpp:276-277; BlockCheckingHelpers.cpp:99-147;
/// ValidationState.cpp:41)
#[test]
fn context_free_failures_are_refused_and_score_200() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();

    // The same coin spent twice in one transaction
    let coin = t.fund(&owner);
    let (peer, ip) = t.peer(1, "192.0.2.21");
    let twice = sign_all(
        tx(&[coin, coin], vec![pay(2 * COINBASE - FEE, &owner)]),
        &owner,
        COINBASE,
    );
    assert_eq!(t.relay(peer, twice).unwrap_err(), "16: bad-tx");
    assert_eq!(t.score(peer), 200);
    assert!(t.banned(&ip));

    // An empty output (no value, no script) in an ordinary transaction
    let (peer, ip) = t.peer(2, "192.0.2.22");
    let empty = sign_all(
        tx(
            &[coin],
            vec![
                pay(COINBASE - FEE, &owner),
                TxOut::new(Amount::ZERO, Script::new()),
            ],
        ),
        &owner,
        COINBASE,
    );
    assert_eq!(t.relay(peer, empty).unwrap_err(), "16: bad-tx");
    assert_eq!(t.score(peer), 200);
    assert!(t.banned(&ip));
    assert_eq!(t.node.mempool().size(), 0);
}

/// IsStandardTx (MempoolConsensus.cpp:29-121): version 1 only, under 100,000
/// bytes, push-only scriptSigs, standard output scripts, at most one OP_META
/// output of at most 603 bytes. Refused with code 64 and no score.
#[test]
fn nonstandard_transactions_are_refused() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let (peer, ip) = t.peer(3, "192.0.2.23");

    let coin = t.fund(&owner);
    let mut v2 = tx(&[coin], vec![pay(COINBASE - FEE, &owner)]);
    v2.version = 2;
    let v2 = sign_all(v2, &owner, COINBASE);
    assert_eq!(t.relay(peer, v2).unwrap_err(), "64: version");

    let bare = tx(
        &[coin],
        vec![
            pay(COINBASE - FEE - COIN, &owner),
            TxOut::new(Amount::from_sat(COIN), Script::from_bytes(vec![0x51])),
        ],
    );
    let bare = sign_all(bare, &owner, COINBASE);
    assert_eq!(t.relay(peer, bare).unwrap_err(), "64: scriptpubkey");

    let meta = |len: usize| {
        let mut s = vec![0x6a, 0x4d];
        s.extend_from_slice(&(len as u16).to_le_bytes());
        s.extend(std::iter::repeat_n(7u8, len));
        TxOut::new(Amount::ZERO, Script::from_bytes(s))
    };
    let two_meta = sign_all(
        tx(
            &[coin],
            vec![pay(COINBASE - FEE, &owner), meta(10), meta(10)],
        ),
        &owner,
        COINBASE,
    );
    assert_eq!(t.relay(peer, two_meta).unwrap_err(), "64: multi-op-meta");
    let big_meta = sign_all(
        tx(&[coin], vec![pay(COINBASE - FEE, &owner), meta(600)]),
        &owner,
        COINBASE,
    );
    assert_eq!(t.relay(peer, big_meta).unwrap_err(), "64: scriptpubkey");

    let mut not_push = tx(&[coin], vec![pay(COINBASE - FEE, &owner)]);
    let mut ss = sig_and_key(&not_push, 0, &owner, COINBASE);
    ss.push(0x61); // OP_NOP
    not_push.vin[0].script_sig = Script::from_bytes(ss);
    assert_eq!(
        t.relay(peer, not_push).unwrap_err(),
        "64: scriptsig-not-pushonly"
    );

    // Exactly 100,000 bytes: within CheckTransaction's limit but not standard.
    // An OP_META output takes up the slack. The signature length varies with
    // the content, so a pad window can miss 100,000; changing the first
    // amount keeps the size and gives a new signature, so retry with that.
    let build = |nudge: i64, pad: usize| {
        let mut outputs: Vec<TxOut> = (0..2925).map(|_| pay(COIN / 10, &owner)).collect();
        outputs[0] = pay(COIN / 10 - nudge, &owner);
        outputs.push(meta(pad));
        sign_all(tx(&[coin], outputs), &owner, COINBASE)
    };
    let estimate = 300 + 100_000 - build(0, 300).size();
    let exact = (0..64)
        .flat_map(|nudge| (estimate - 8..=estimate + 8).map(move |pad| (nudge, pad)))
        .map(|(nudge, pad)| build(nudge, pad))
        .find(|t| t.size() == 100_000)
        .expect("a pad length giving exactly 100,000 bytes");
    assert_eq!(t.relay(peer, exact).unwrap_err(), "64: tx-size");

    assert_eq!(t.score(peer), 0);
    assert!(!t.banned(&ip));
    assert_eq!(t.node.mempool().size(), 0);

    // The same coin in an ordinary send is accepted
    let good = sign_all(
        tx(&[coin], vec![pay(COINBASE - FEE, &owner), meta(80)]),
        &owner,
        COINBASE,
    );
    t.relay(peer, good).unwrap();
}

/// AreInputsStandard (MempoolConsensus.cpp:132-194): a scriptSig with more
/// items than the spent script needs is refused, with no reject reason and no
/// score in Core
#[test]
fn extra_scriptsig_items_are_refused() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let coin = t.fund(&owner);
    let (peer, ip) = t.peer(4, "192.0.2.24");

    let mut padded = tx(&[coin], vec![pay(COINBASE - FEE, &owner)]);
    let mut ss = sig_and_key(&padded, 0, &owner, COINBASE);
    ss.push(0x51); // OP_1 left on the stack
    padded.vin[0].script_sig = Script::from_bytes(ss);
    assert_eq!(
        t.relay(peer, padded).unwrap_err(),
        "64: bad-txns-nonstandard-inputs"
    );
    assert_eq!(t.score(peer), 0);
    assert!(!t.banned(&ip));
}

/// A transaction may carry at most 8,000 sigops, counting each bare
/// CHECKMULTISIG as 20 (MempoolConsensus.cpp:371-381, MAX_TX_SIGOPS_CURRENT)
#[test]
fn transaction_with_too_many_sigops_is_refused() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let coin = t.fund(&owner);
    let (peer, ip) = t.peer(5, "192.0.2.25");

    // 1-of-3 bare multisig: standard, 20 legacy sigops each
    let key = owner.public_key().to_bytes();
    let mut multisig = vec![0x51];
    for _ in 0..3 {
        multisig.push(key.len() as u8);
        multisig.extend_from_slice(&key);
    }
    multisig.extend_from_slice(&[0x53, 0xae]);
    let outputs = |n: usize| -> Vec<TxOut> {
        let mut outs: Vec<TxOut> = (0..n)
            .map(|_| TxOut::new(Amount::from_sat(COIN), Script::from_bytes(multisig.clone())))
            .collect();
        outs.push(pay(COINBASE - FEE - n as i64 * COIN, &owner));
        outs
    };
    // 401 outputs: 8,020 sigops
    let over = sign_all(tx(&[coin], outputs(401)), &owner, COINBASE);
    assert_eq!(
        t.relay(peer, over).unwrap_err(),
        "64: bad-txns-too-many-sigops"
    );
    assert_eq!(t.score(peer), 0);
    assert!(!t.banned(&ip));

    // 399 outputs: 7,980 sigops plus the change output's one
    let under = sign_all(tx(&[coin], outputs(399)), &owner, COINBASE);
    t.relay(peer, under).unwrap();
}

/// CheckInputs refuses a coinbase spent before it has 20 confirmations on
/// regtest, with REJECT_INVALID but no score (UtxoCheckingAndUpdating.cpp:72-79)
#[test]
fn immature_coinbase_spend_is_refused_without_score() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let (peer, ip) = t.peer(6, "192.0.2.26");

    // Spent in the next block it would be 19 blocks deep
    let young = t.coin_at_depth(&owner, 19);
    let spend = sign_all(
        tx(&[young], vec![pay(COINBASE - FEE, &owner)]),
        &owner,
        COINBASE,
    );
    assert_eq!(
        t.relay(peer, spend.clone()).unwrap_err(),
        "16: bad-txns-premature-spend-of-coinbase"
    );
    assert_eq!(
        t.submit(spend.clone(), FEE).unwrap_err(),
        "16: bad-txns-premature-spend-of-coinbase"
    );
    assert_eq!(t.score(peer), 0);
    assert!(!t.banned(&ip));
    assert_eq!(t.node.mempool().size(), 0);

    // One block later it may be spent in the next block
    t.mine_empty(1);
    t.relay(peer, spend).unwrap();
}

/// Below the relay fee Core asks for priority before it checks value in
/// against value out: spending a young, small output for more than it holds is
/// refused for priority with no score (MempoolConsensus.cpp:254-260)
#[test]
fn overspend_of_low_priority_inputs_is_refused_for_priority() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let coin = t.fund(&owner);
    let (peer, ip) = t.peer(7, "192.0.2.27");

    let parent = sign_all(
        tx(
            &[coin],
            vec![pay(COIN, &owner), pay(COINBASE - COIN - FEE, &owner)],
        ),
        &owner,
        COINBASE,
    );
    let small = OutPoint::new(parent.txid(), 0);
    t.submit(parent, FEE).unwrap();

    let overspend = sign_all(tx(&[small], vec![pay(2 * COIN, &owner)]), &owner, COIN);
    assert_eq!(
        t.relay(peer, overspend).unwrap_err(),
        "66: insufficient priority"
    );
    assert_eq!(t.score(peer), 0);
    assert!(!t.banned(&ip));
}

/// A transaction paying less than the relay fee is taken when its inputs have
/// enough coin age per byte (Core's AllowFree); a relayed one must also be
/// under 49,000 bytes (MempoolConsensus.cpp:197-266)
#[test]
fn free_transaction_needs_priority() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();

    // 1250 DIVI, 21 blocks old: high priority, no fee
    let coin = t.fund(&owner);
    let free = sign_all(tx(&[coin], vec![pay(COINBASE, &owner)]), &owner, COINBASE);
    let free_txid = free.txid();
    t.submit(free, 0).unwrap();
    assert!(t.node.mempool().contains(&free_txid));

    // Spending its 1250 DIVI output again, unconfirmed: the priority is the
    // value in per byte, still enough
    let child = sign_all(
        tx(&[OutPoint::new(free_txid, 0)], vec![pay(COINBASE, &owner)]),
        &owner,
        COINBASE,
    );
    let (peer, _) = t.peer(8, "192.0.2.28");
    t.relay(peer, child.clone()).unwrap();

    // 1 DIVI, unconfirmed: not enough priority
    let coin = t.fund(&owner);
    let parent = sign_all(
        tx(
            &[coin],
            vec![pay(COIN, &owner), pay(COINBASE - COIN - FEE, &owner)],
        ),
        &owner,
        COINBASE,
    );
    let small = OutPoint::new(parent.txid(), 0);
    t.submit(parent, FEE).unwrap();
    let cheap = sign_all(tx(&[small], vec![pay(COIN, &owner)]), &owner, COIN);
    assert_eq!(t.submit(cheap, 0).unwrap_err(), "66: insufficient priority");
}

/// A relayed transaction below the relay fee must be under 49,000 bytes unless
/// prioritised; a local one need not be (MempoolConsensus.cpp:205, :250-253)
#[test]
fn relayed_free_transaction_must_be_small() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let (peer, _) = t.peer(9, "192.0.2.29");

    // Ten coins about 50 blocks old: priority enough for a 49 KB transaction
    let coins: Vec<OutPoint> = (0..10).map(|_| t.mine(p2pkh(&owner))).collect();
    t.mine_empty(50);
    let mut outputs: Vec<TxOut> = (0..1400).map(|_| pay(COIN / 10, &owner)).collect();
    outputs.push(pay(10 * COINBASE - 140 * COIN, &owner));
    let big_free = sign_all(tx(&coins, outputs), &owner, COINBASE);
    assert!(big_free.size() >= 49_000 && big_free.size() < 100_000);
    assert_eq!(
        t.relay(peer, big_free.clone()).unwrap_err(),
        "66: insufficient fee"
    );
    assert_eq!(t.score(peer), 0);
    // Submitted locally it is taken (Core's fLimitFree is off for local sends)
    t.submit(big_free, 0).unwrap();
}

/// An input whose transaction still has other unspent outputs is spent, not
/// unknown: "bad-txns-inputs-spent" (REJECT_DUPLICATE), no score
/// (MempoolConsensus.cpp:336-351)
#[test]
fn spent_input_is_reported_as_spent() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let coin = t.fund(&owner);
    let split = sign_all(
        tx(
            &[coin],
            vec![
                pay(100 * COIN, &owner),
                pay(COINBASE - 100 * COIN - FEE, &owner),
            ],
        ),
        &owner,
        COINBASE,
    );
    let first = OutPoint::new(split.txid(), 0);

    // Confirm the split and the spend of its first output
    let spend_first = sign_all(
        tx(&[first], vec![pay(100 * COIN - FEE, &owner)]),
        &owner,
        100 * COIN,
    );
    let chain = t.node.chain();
    let tip = chain.tip().unwrap();
    let mut tag = divi_storage::bip34_height_script(tip.height + 1);
    tag.extend_from_slice(&[0xab]);
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(tag))],
        vout: vec![TxOut::new(
            Amount::from_sat(COINBASE + 2 * FEE),
            Script::new_p2pkh(&[0xee; 20]),
        )],
        lock_time: 0,
    };
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = tip.hash;
    block.header.time = tip.time + 60;
    block.header.bits = 0x207fffff;
    block.transactions = vec![coinbase, split, spend_first.clone()];
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    chain.accept_block(block).unwrap();

    let again = sign_all(
        tx(&[first], vec![pay(100 * COIN - 2 * FEE, &owner)]),
        &owner,
        100 * COIN,
    );
    assert_eq!(
        t.submit(again, 2 * FEE).unwrap_err(),
        "18: bad-txns-inputs-spent"
    );
}
