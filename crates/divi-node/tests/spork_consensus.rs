// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Sporks 13 and 15 set what a block is worth and how it is split, as Divi Core
//! reads them (LegacyBlockSubsidies.cpp:30-112, spork.cpp:90-125). A node that
//! starts with them in its spork database, which is where a restart gets them
//! from, values the blocks above their height with them.

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
async fn block_value_and_payments_follow_the_stored_sporks() {
    let t = TestNode::start_with(|c| {
        seed(
            c,
            &[stored(10014, "2000;200"), stored(10012, "50;30;10;5;5;300")],
        )
    })
    .await;
    let chain = t.node.chain();

    // below their heights, the usual
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

    // from 300 the split is 50/30/10/5/5 of that
    let at_300 = chain.block_rewards(350);
    assert_eq!(at_300.stake, Amount::from_divi(975));
    assert_eq!(at_300.masternode, Amount::from_divi(585));
    assert_eq!(at_300.treasury, Amount::from_divi(195));
    assert_eq!(
        at_300.proposals,
        Amount::from_divi(97) + Amount::from_sat(50_000_000)
    );
    assert_eq!(
        at_300.charity,
        Amount::from_divi(97) + Amount::from_sat(50_000_000)
    );
}
