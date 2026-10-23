// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A peer that relays a transaction the mempool refuses is scored as Divi
//! Core scores it (Misbehaving with the refusal's DoS value) and banned at the
//! ban score; policy refusals and missing inputs cost nothing.

use divi_crypto::KeyPair;
use divi_network::TxRelayEvent;
use divi_node::config::NodeConfig;
use divi_node::{accept_relayed_transaction, Node};
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_script::TransactionSignatureChecker;
use std::net::IpAddr;

const COIN: i64 = 100_000_000;

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

    /// A mature 1250 DIVI coin paying `kp`
    fn fund(&self, kp: &KeyPair) -> OutPoint {
        let coin = self.mine(p2pkh(kp));
        self.mine(Script::new_p2pkh(&[0xee; 20]));
        coin
    }

    fn peer(&self, id: u64, ip: &str) -> (u64, IpAddr) {
        let ip: IpAddr = ip.parse().unwrap();
        self.node.peer_manager().scoring().register_peer(id, ip);
        (id, ip)
    }

    fn relay(&self, from_peer: u64, tx: Transaction) -> Result<Hash256, String> {
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

fn spend(coin: OutPoint, value: i64, to: Script) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffffffff)],
        vout: vec![TxOut::new(Amount::from_sat(value), to)],
        lock_time: 0,
    }
}

fn sign(tx: &mut Transaction, kp: &KeyPair) {
    let checker = TransactionSignatureChecker::new(tx, 0, Amount::from_sat(1250 * COIN));
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
}

#[test]
fn peer_relaying_an_unsigned_spend_is_banned() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let coin = t.fund(&owner);
    let (peer, ip) = t.peer(1, "192.0.2.10");

    let err = t
        .relay(peer, spend(coin, 1249 * COIN, p2pkh(&owner)))
        .unwrap_err();
    assert!(
        err.starts_with("16: mandatory-script-verify-flag-failed"),
        "{}",
        err
    );
    assert_eq!(t.score(peer), 100);
    assert!(t.banned(&ip));
}

#[test]
fn peer_relaying_outputs_above_inputs_is_banned() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let coin = t.fund(&owner);
    let (peer, ip) = t.peer(2, "192.0.2.11");
    let mut tx = spend(coin, 2000 * COIN, p2pkh(&owner));
    sign(&mut tx, &owner);

    assert_eq!(t.relay(peer, tx).unwrap_err(), "16: bad-txns-in-belowout");
    assert!(t.banned(&ip));
}

#[test]
fn missing_inputs_and_policy_refusals_do_not_score() {
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let coin = t.fund(&owner);
    let (peer, ip) = t.peer(3, "192.0.2.12");

    // Unknown input (Divi Core keeps it as an orphan, DoS 0)
    let orphan = spend(
        OutPoint::new(Hash256::from_bytes([4u8; 32]), 0),
        COIN,
        p2pkh(&owner),
    );
    assert_eq!(t.relay(peer, orphan).unwrap_err(), "missing inputs");

    // Dust output (IsStandard, DoS 0)
    let mut dust = spend(coin, 1, p2pkh(&owner));
    sign(&mut dust, &owner);
    assert_eq!(t.relay(peer, dust).unwrap_err(), "64: dust");

    assert_eq!(t.score(peer), 0);
    assert!(!t.banned(&ip));

    // A valid spend from the same peer is accepted
    let mut good = spend(coin, 1249 * COIN, p2pkh(&owner));
    sign(&mut good, &owner);
    t.relay(peer, good).unwrap();
}

#[test]
fn local_peer_is_scored_but_not_banned() {
    // Divi Core disconnects a local peer at the ban score but never bans it
    let t = TestNode::new();
    let owner = KeyPair::new_random();
    let coin = t.fund(&owner);
    let (peer, ip) = t.peer(4, "127.0.0.1");
    assert!(t
        .relay(peer, spend(coin, 1249 * COIN, p2pkh(&owner)))
        .is_err());
    assert_eq!(t.score(peer), 100);
    assert!(!t.banned(&ip));
}

#[test]
fn ban_score_setting_raises_the_threshold() {
    let t = TestNode::new();
    t.node
        .peer_manager()
        .scoring()
        .set_ban_policy(200, std::time::Duration::from_secs(60));
    let owner = KeyPair::new_random();
    let a = t.fund(&owner);
    let b = t.fund(&owner);
    let (peer, ip) = t.peer(5, "192.0.2.13");

    assert!(t.relay(peer, spend(a, 1249 * COIN, p2pkh(&owner))).is_err());
    assert!(!t.banned(&ip));
    assert!(t.relay(peer, spend(b, 1249 * COIN, p2pkh(&owner))).is_err());
    assert_eq!(t.score(peer), 200);
    assert!(t.banned(&ip));
    let ban = t.node.peer_manager().scoring().list_bans();
    assert_eq!(ban.len(), 1);
}
