// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Spork 15 sets what a block is worth, as Divi Core reads it
//! (LegacyBlockSubsidies.cpp:30-42, spork.cpp:90-107). A node that
//! starts with it in its spork database, which is where a restart gets it
//! from, values the blocks above its height with it.

mod common;
use common::raw_peer::*;
use divi_network::SporkMessage;
use divi_node::config::NodeConfig;
use divi_primitives::Amount;
use divi_storage::ChainDatabase;

fn seed(config: &mut NodeConfig, sporks: &[SporkMessage]) {
    std::fs::create_dir_all(config.chainstate_path()).unwrap();
    let db = ChainDatabase::open(config.chainstate_path()).unwrap();
    for spork in sporks {
        db.put_metadata(
            format!("spork_{}", spork.spork_id).as_bytes(),
            &spork.serialize(),
        )
        .unwrap();
    }
}

fn stored(id: i32, value: &str) -> SporkMessage {
    SporkMessage {
        spork_id: id,
        value: value.into(),
        time_signed: 1000,
        signature: vec![0x1f; 65],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn block_value_follows_the_stored_spork() {
    let t = TestNode::start_with(|c| seed(c, &[stored(10014, "2000;200")])).await;
    let chain = t.node.chain();

    // below its height, the usual
    assert_eq!(chain.block_rewards(150).stake, Amount::from_divi(456));
    assert_eq!(chain.block_rewards(150).masternode, Amount::from_divi(540));

    // from 200 the value is 2000 DIVI: 50 for the lottery, the rest by 38/45/16/0/1
    let at_200 = chain.block_rewards(250);
    assert_eq!(at_200.stake, Amount::from_divi(741));
    assert_eq!(
        at_200.masternode,
        Amount::from_divi(877) + Amount::from_sat(50_000_000)
    );
    assert_eq!(at_200.treasury, Amount::from_divi(312));
    assert_eq!(at_200.lottery, Amount::from_divi(50));
}
