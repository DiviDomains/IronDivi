// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A relayed transaction that fails Divi Core's CheckTransaction costs the
//! peer what it costs there: AcceptToMemoryPool records 100 on top of
//! CheckTransaction's own score (CValidationState::DoS adds them up).

use divi_network::TxRelayEvent;
use divi_node::config::NodeConfig;
use divi_node::{accept_relayed_transaction, Node};
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;

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

    fn relay(&self, from_peer: u64, ip: &str, tx: Transaction) -> i32 {
        let scoring = self.node.peer_manager().scoring();
        scoring.register_peer(from_peer, ip.parse().unwrap());
        let event = TxRelayEvent {
            txid: tx.txid(),
            tx,
            fee: None,
            from_peer,
        };
        assert!(accept_relayed_transaction(
            self.node.chain(),
            self.node.mempool(),
            self.node.peer_manager(),
            &event,
        )
        .is_err());
        scoring
            .get_stats(from_peer)
            .map_or(0, |s| s.misbehavior_score)
    }
}

fn input() -> TxIn {
    TxIn::new(
        OutPoint::new(Hash256::from_bytes([7; 32]), 0),
        Script::new(),
        0xffff_ffff,
    )
}

#[test]
fn transaction_without_outputs_scores_110() {
    let t = TestNode::new();
    let tx = Transaction {
        version: 1,
        vin: vec![input()],
        vout: vec![],
        lock_time: 0,
    };
    assert_eq!(t.relay(1, "10.1.0.1", tx), 110);
}

#[test]
fn transaction_with_negative_output_scores_200() {
    let t = TestNode::new();
    let tx = Transaction {
        version: 1,
        vin: vec![input()],
        vout: vec![TxOut::new(
            Amount::from_sat(-1),
            Script::new_p2pkh(&[1; 20]),
        )],
        lock_time: 0,
    };
    assert_eq!(t.relay(2, "10.1.0.2", tx), 200);
}
