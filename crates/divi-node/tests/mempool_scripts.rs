// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The node's mempool refuses transactions whose input scripts fail, with
//! Divi Core's reject code and reason, and still accepts valid spends.

use divi_crypto::KeyPair;
use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_script::{StakingVaultScript, TransactionSignatureChecker};

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;

fn push(out: &mut Vec<u8>, data: &[u8]) {
    assert!(data.len() < 0x4c);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes())
}

fn sign(tx: &Transaction, script_code: &Script, value: i64, kp: &KeyPair) -> Vec<u8> {
    let checker = TransactionSignatureChecker::new(tx, 0, Amount::from_sat(value));
    let sighash = checker.signature_hash(script_code, 1);
    let mut sig = divi_crypto::sign_hash(kp.secret_key(), &sighash)
        .unwrap()
        .to_der();
    sig.push(1);
    sig
}

fn spend(coin: OutPoint, value: i64, to: Script) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffffffff)],
        vout: vec![TxOut::new(Amount::from_sat(value - FEE), to)],
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

    fn mine(&self, payee: Script) -> OutPoint {
        let chain = self.node.chain();
        let tip = chain.tip().unwrap();
        let height = tip.height + 1;
        // BIP34: the coinbase starts with the height
        let mut sig = divi_storage::bip34_height_script(height);
        sig.extend_from_slice(&height.to_le_bytes());
        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), payee)],
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

    /// A 1250 DIVI coin paying `script`, mature for the next block (regtest
    /// coinbase maturity 20, Divi Core chainparams.cpp:479)
    fn fund(&self, script: Script) -> (OutPoint, i64) {
        let coin = self.mine(script);
        for _ in 0..19 {
            self.mine(Script::new_p2pkh(&[0xee; 20]));
        }
        (coin, 1250 * COIN)
    }

    fn submit(&self, tx: Transaction) -> Result<(), String> {
        self.node
            .mempool()
            .add(tx, Amount::from_sat(FEE))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[test]
fn unsigned_spend_is_refused_as_core_refuses_it() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let (coin, value) = t.fund(p2pkh(&owner));
    let err = t
        .submit(spend(coin, value, p2pkh(&KeyPair::new_random())))
        .unwrap_err();
    assert_eq!(
        err,
        "16: mandatory-script-verify-flag-failed (Operation not valid with the current stack size)"
    );
    assert_eq!(t.node.mempool().size(), 0);
}

#[test]
fn wrong_key_spend_is_refused() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let stranger_key = KeyPair::new_random();
    let (coin, value) = t.fund(p2pkh(&owner));
    let mut tx = spend(coin, value, p2pkh(&stranger_key));
    let sig = sign(&tx, &p2pkh(&owner), value, &stranger_key);
    let mut ss = Vec::new();
    push(&mut ss, &sig);
    push(&mut ss, &stranger_key.public_key().to_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert_eq!(
        t.submit(tx).unwrap_err(),
        "16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );
}

#[test]
fn wrong_signature_for_right_key_is_refused() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let (coin, value) = t.fund(p2pkh(&owner));
    let mut tx = spend(coin, value, p2pkh(&owner));
    // Signed over a different scriptCode, so the signature does not verify
    let sig = sign(&tx, &Script::new_p2pkh(&[0x11; 20]), value, &owner);
    let mut ss = Vec::new();
    push(&mut ss, &sig);
    push(&mut ss, &owner.public_key().to_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert_eq!(
        t.submit(tx).unwrap_err(),
        "16: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)"
    );
}

/// 2-of-3 multisig redeem script and its P2SH output script
fn multisig(keys: &[KeyPair; 3]) -> (Script, Script) {
    let mut redeem = vec![0x52];
    for k in keys {
        push(&mut redeem, &k.public_key().to_bytes());
    }
    redeem.extend_from_slice(&[0x53, 0xae]);
    let hash = divi_crypto::hash160(&redeem);
    (
        Script::from_bytes(redeem),
        Script::new_p2sh(hash.as_bytes()),
    )
}

#[test]
fn wrong_redeem_script_is_refused() {
    let t = TestNode::new();
    let keys = [
        KeyPair::new_random(),
        KeyPair::new_random(),
        KeyPair::new_random(),
    ];
    let (_, p2sh) = multisig(&keys);
    let (coin, value) = t.fund(p2sh);
    let stranger_key = KeyPair::new_random();
    let mut other = vec![0x51];
    push(&mut other, &stranger_key.public_key().to_bytes());
    other.extend_from_slice(&[0x51, 0xae]);
    let mut tx = spend(coin, value, p2pkh(&stranger_key));
    let sig = sign(
        &tx,
        &Script::from_bytes(other.clone()),
        value,
        &stranger_key,
    );
    let mut ss = vec![0x00];
    push(&mut ss, &sig);
    push(&mut ss, &other);
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert_eq!(
        t.submit(tx).unwrap_err(),
        "16: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)"
    );
}

#[test]
fn policy_only_failure_is_non_mandatory() {
    // A valid signature pushed with OP_PUSHDATA1 breaks only MINIMALDATA
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let (coin, value) = t.fund(p2pkh(&owner));
    let mut tx = spend(coin, value, p2pkh(&owner));
    let sig = sign(&tx, &p2pkh(&owner), value, &owner);
    let mut ss = vec![0x4c, sig.len() as u8];
    ss.extend_from_slice(&sig);
    push(&mut ss, &owner.public_key().to_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert_eq!(
        t.submit(tx).unwrap_err(),
        "64: non-mandatory-script-verify-flag (Data push larger than necessary)"
    );
}

#[test]
fn valid_p2pkh_spend_is_accepted() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let (coin, value) = t.fund(p2pkh(&owner));
    let mut tx = spend(coin, value, p2pkh(&KeyPair::new_random()));
    let sig = sign(&tx, &p2pkh(&owner), value, &owner);
    let mut ss = Vec::new();
    push(&mut ss, &sig);
    push(&mut ss, &owner.public_key().to_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    t.submit(tx).unwrap();
    assert_eq!(t.node.mempool().size(), 1);
}

#[test]
fn valid_p2sh_multisig_spend_is_accepted() {
    let t = TestNode::new();
    let keys = [
        KeyPair::new_random(),
        KeyPair::new_random(),
        KeyPair::new_random(),
    ];
    let (redeem, p2sh) = multisig(&keys);
    let (coin, value) = t.fund(p2sh);
    let mut tx = spend(coin, value, p2pkh(&KeyPair::new_random()));
    let s1 = sign(&tx, &redeem, value, &keys[1]);
    let s2 = sign(&tx, &redeem, value, &keys[2]);
    let mut ss = vec![0x00];
    push(&mut ss, &s1);
    push(&mut ss, &s2);
    ss.extend_from_slice(&[0x4c, redeem.as_bytes().len() as u8]);
    ss.extend_from_slice(redeem.as_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    t.submit(tx).unwrap();
}

#[test]
fn vault_owner_reclaim_is_accepted_and_manager_spend_refused() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let manager = KeyPair::new_random();
    let h = |k: &KeyPair| *divi_crypto::hash160(&k.public_key().to_bytes()).as_bytes();
    let vault = StakingVaultScript::new(h(&owner), h(&manager)).to_script();
    let (coin, value) = t.fund(vault.clone());
    let script_sig = |sig: &[u8], kp: &KeyPair, owner_path: bool| {
        let mut ss = Vec::new();
        push(&mut ss, sig);
        push(&mut ss, &kp.public_key().to_bytes());
        ss.push(if owner_path { 0x51 } else { 0x00 });
        Script::from_bytes(ss)
    };

    // The manager may only move vault funds in a coinstake
    let mut tx = spend(coin, value, p2pkh(&manager));
    let sig = sign(&tx, &vault, value, &manager);
    tx.vin[0].script_sig = script_sig(&sig, &manager, false);
    assert_eq!(
        t.submit(tx).unwrap_err(),
        "16: mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)"
    );

    let mut tx = spend(coin, value, p2pkh(&owner));
    let sig = sign(&tx, &vault, value, &owner);
    tx.vin[0].script_sig = script_sig(&sig, &owner, true);
    t.submit(tx).unwrap();
}
