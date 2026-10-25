// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Sporks survive a restart, as Divi Core's spork database keeps them
//! (spork.cpp LoadSporksFromDB): `spork show` after a restart gives the values
//! the network signed, not the defaults.

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
