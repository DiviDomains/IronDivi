// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Sporks survive a restart, as Divi Core's spork database keeps them
//! (spork.cpp LoadSporksFromDB): `spork show` after a restart gives the values
//! the network signed, not the defaults. On PrivateDivi networks a stored spork
//! must also verify against the network's authority, and with no authority a
//! stored spork holds the start instead of loading (docs/spork-authority.md).

use divi_network::constants::{PRIVATEDIVI_MAINNET_MAGIC, PRIVATEDIVI_TESTNET_MAGIC};
use divi_network::spork::{QuarantineReason, SporkStartError, SporkStoreHold, SPORK_HOLD_ACK_ENV};
use divi_network::{PeerManager, PeerManagerConfig, SporkManager, SporkMessage};
use divi_rpc::spork::SporkRpc;
use divi_rpc::Params;
use divi_storage::ChainDatabase;
use serde_json::{json, Value};
use std::sync::Arc;

fn peers() -> Arc<PeerManager> {
    PeerManager::new(PeerManagerConfig {
        dns_seeds: vec![],
        static_peers: vec![],
        listen_addr: None,
        ..Default::default()
    })
}

fn peers_on(magic: divi_network::constants::Magic) -> Arc<PeerManager> {
    PeerManager::new(PeerManagerConfig {
        magic,
        dns_seeds: vec![],
        static_peers: vec![],
        listen_addr: None,
        ..Default::default()
    })
}

/// A row as an earlier IronDivi stored it on a PrivateDivi network, where
/// sporks were taken unchecked
fn seed_unsigned(dir: &std::path::Path, id: i32, value: &str) -> Vec<u8> {
    let spork = SporkMessage {
        spork_id: id,
        value: value.into(),
        time_signed: 1000,
        signature: vec![0x1f; 65],
    };
    let db = ChainDatabase::open(dir).unwrap();
    db.put_metadata(format!("spork_{id}").as_bytes(), &spork.serialize())
        .unwrap();
    spork.serialize()
}

fn held(err: SporkStartError) -> SporkStoreHold {
    match err {
        SporkStartError::Held(hold) => hold,
        other => panic!("not a hold: {other}"),
    }
}

fn signed(kp: &divi_crypto::KeyPair, id: i32, value: &str, time: i64) -> SporkMessage {
    let message = format!("{}{}{}", id, value, time);
    SporkMessage {
        spork_id: id,
        value: value.into(),
        time_signed: time,
        signature: divi_masternode::cpp_wire::sign_message(kp.secret_key(), message.as_bytes())
            .unwrap(),
    }
}

fn spork_show(sporks: Arc<SporkManager>) -> Value {
    let rpc = SporkRpc::new();
    rpc.set_manager(sporks);
    rpc.spork(&Params::Array(vec![json!("show")])).unwrap()
}

#[tokio::test]
async fn spork_show_after_a_restart_gives_the_stored_values() {
    let kp = divi_crypto::KeyPair::new_random();
    let key = kp.public_key().to_bytes();
    let dir = tempfile::tempdir().unwrap();

    let before = {
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let sporks = SporkManager::with_key(peers(), Some(key.clone()), Some(db));
        let defaults = spork_show(Arc::clone(&sporks));
        assert_eq!(
            defaults["SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT"],
            "1537971708"
        );
        assert_eq!(defaults["SPORK_16_LOTTERY_TICKET_MIN_VALUE"], "");
        sporks
            .handle_spork(1, signed(&kp, 10007, "1600000000", 1000))
            .await;
        sporks
            .handle_spork(1, signed(&kp, 10015, "5000;100", 1000))
            .await;
        sporks
            .handle_spork(1, signed(&kp, 10015, "6000;200", 2000))
            .await;
        spork_show(sporks)
    };
    assert_eq!(
        before["SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT"],
        "1600000000"
    );
    assert_eq!(before["SPORK_16_LOTTERY_TICKET_MIN_VALUE"], "6000;200");

    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let after = spork_show(SporkManager::with_key(peers(), Some(key), Some(db)));
    assert_eq!(after, before);
}

/// PrivateDivi testnet checks stored rows against the key pinned from
/// PrivateDivi Core: an unchecked row from an earlier release is not loaded
/// after a restart, `spork show` gives the default, and the row is kept
#[tokio::test]
async fn privatedivi_testnet_restart_does_not_load_an_unverified_spork() {
    let dir = tempfile::tempdir().unwrap();
    let raw = seed_unsigned(dir.path(), 10007, "1600000000");

    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let sporks = SporkManager::with_db(peers_on(PRIVATEDIVI_TESTNET_MAGIC), Arc::clone(&db));
    assert_eq!(sporks.quarantined().len(), 1);
    assert!(matches!(
        sporks.quarantined()[0].reason,
        QuarantineReason::InvalidSignature(_)
    ));
    assert!(sporks.store_hold().is_none());
    let shown = spork_show(sporks);
    assert_eq!(
        shown["SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT"],
        "1537971708"
    );
    assert_eq!(db.get_metadata(b"spork_10007").unwrap(), Some(raw));
}

/// PrivateDivi mainnet has no confirmed authority: a stored row holds the
/// start, across restarts, until its fingerprint is acknowledged; it is never
/// loaded and never deleted
#[tokio::test]
async fn privatedivi_mainnet_restart_holds_on_stored_sporks() {
    let dir = tempfile::tempdir().unwrap();
    let raw = seed_unsigned(dir.path(), 10014, "2000;200");
    let start = |ack: Option<&str>| {
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let consensus = divi_storage::SharedSporks::default();
        let started = SporkManager::try_with_chain(
            peers_on(PRIVATEDIVI_MAINNET_MAGIC),
            db,
            consensus.clone(),
            ack,
        );
        assert!(consensus.read().entries(10014).is_empty());
        started
    };

    let hold = held(start(None).err().expect("held"));
    let again = held(start(None).err().expect("held after a restart"));
    assert_eq!(again.fingerprint, hold.fingerprint);

    let sporks = start(Some(hold.fingerprint.as_str())).expect("acknowledged");
    assert_eq!(sporks.spork_count(), 0);
    drop(sporks);

    let db = ChainDatabase::open(dir.path()).unwrap();
    assert_eq!(db.get_metadata(b"spork_10014").unwrap(), Some(raw));
}

/// The daemon start goes through the hold: a PrivateDivi mainnet data
/// directory with a stored spork row stops `Node::new` with the hold report,
/// and only that hold's fingerprint in IRONDIVI_SPORK_HOLD_ACK lets it start.
/// Synthetic row, temporary directory, no network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn privatedivi_mainnet_node_start_is_held_by_stored_sporks() {
    use divi_node::config::NodeConfig;
    use divi_node::{Node, NodeError};
    use divi_primitives::ChainMode;

    std::env::remove_var(SPORK_HOLD_ACK_ENV);
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::mainnet(ChainMode::PrivateDivi);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen = Some(false);
    config.p2p.enable_discovery = false;
    config.network.dns_seeds = vec![];
    config.network.static_peers = vec![];
    std::fs::create_dir_all(config.chainstate_path()).unwrap();
    seed_unsigned(&config.chainstate_path(), 10014, "2000;200");

    let fingerprint = {
        let db = Arc::new(ChainDatabase::open(config.chainstate_path()).unwrap());
        let hold = SporkManager::try_with_chain(
            peers_on(PRIVATEDIVI_MAINNET_MAGIC),
            db,
            Default::default(),
            None,
        )
        .err()
        .map(held)
        .expect("held");
        hold.fingerprint
    };

    match Node::new(config.clone()).err() {
        Some(NodeError::Init(report)) => {
            assert!(report.contains("spork store hold"), "{report}");
            assert!(report.contains(&fingerprint), "{report}");
            assert!(report.contains(SPORK_HOLD_ACK_ENV), "{report}");
        }
        other => panic!("node started or failed otherwise: {other:?}"),
    }

    std::env::set_var(SPORK_HOLD_ACK_ENV, "00");
    assert!(matches!(
        Node::new(config.clone()).err(),
        Some(NodeError::Init(report)) if report.contains("spork store hold")
    ));

    std::env::set_var(SPORK_HOLD_ACK_ENV, fingerprint);
    let started = Node::new(config).map(drop);
    std::env::remove_var(SPORK_HOLD_ACK_ENV);
    started.expect("acknowledged hold lets the node start");
}
