// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The per-network values of the block rules (max reorganization depth and
//! `-maxreorg`, checkpoints, minimum stake age) and serving stale blocks to peers.

mod common;

use common::*;
use divi_crypto::compute_block_hash;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::ChainMode;
use divi_storage::{ChainParams, NetworkType};

/// `-maxreorg` replaces the network depth when refusing a block
#[test]
fn maxreorg_override_sets_the_depth() {
    let mut params = regtest();
    params.max_reorg_arg = Some(5);
    let t = TestChain::new(params);
    t.extend_pow(6);
    let one = t.chain.get_block_index_by_height(1).unwrap().unwrap();
    let two = t.chain.get_block_index_by_height(2).unwrap().unwrap();
    // Fork block at height 2: 6 - 2 = 4 < 5
    t.chain
        .accept_block(t.pow_block(&one, Amount::from_sat(1250 * COIN), vec![]))
        .unwrap();
    // Fork block at height 1: 6 - 1 = 5 >= 5
    let genesis = t.chain.get_block_index_by_height(0).unwrap().unwrap();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &genesis,
        Amount::from_sat(1250 * COIN),
        vec![],
    )));
    assert!(msg.contains("max reorganization depth (height 1)"), "{msg}");
    let _ = two;
}

/// Divi networks use depth 100; serving follows the network depth, not -maxreorg
#[test]
fn max_reorg_depth_per_network() {
    for net in [
        NetworkType::Mainnet,
        NetworkType::Testnet,
        NetworkType::Regtest,
    ] {
        let p = ChainParams::for_network(net, ChainMode::Divi);
        assert_eq!(p.max_reorg_depth, Some(100), "{net:?}");
        assert_eq!(p.max_reorg_arg, None);
    }
}

/// A block off the active chain is served only if it was fully validated and
/// lies less than the max reorganization depth below the tip (main.cpp:229-239)
#[test]
fn stale_blocks_are_served_only_when_validated_and_recent() {
    let t = TestChain::new(regtest());
    t.extend_pow(3);
    let two = t.chain.get_block_index_by_height(2).unwrap().unwrap();
    // A side block that was never connected
    let side = t.pow_block(&two, Amount::from_sat(1250 * COIN), vec![]);
    let side_hash = compute_block_hash(&side.header);
    t.chain.accept_block(side).unwrap();
    assert!(t.chain.get_block_for_peer(&side_hash).unwrap().is_none());
    // Main-chain blocks are served
    assert!(t.chain.get_block_for_peer(&two.hash).unwrap().is_some());

    // A block that was connected and then reorganized away is served while recent
    let three = t.tip();
    let side_index = t.index(&side_hash);
    let next = t.pow_block(&side_index, Amount::from_sat(1250 * COIN), vec![]);
    t.chain.accept_block(next).unwrap();
    assert_eq!(t.tip().height, 4);
    assert!(!t.index(&three.hash).is_on_main_chain());
    assert!(t.chain.get_block_for_peer(&three.hash).unwrap().is_some());
}

#[test]
fn checkpoints_per_network() {
    let main = ChainParams::for_network(NetworkType::Mainnet, ChainMode::Divi);
    assert_eq!(
        main.checkpoints,
        vec![(
            100,
            Hash256::from_hex("000000275b2b4a8af2c93ebdfd36ef8dd8c8ec710072bcc388ecbf5d0c8d3f9d")
                .unwrap()
        )]
    );
    // Testnet's and regtest's maps hold only height 0, which Core never checks
    for net in [NetworkType::Testnet, NetworkType::Regtest] {
        assert!(ChainParams::for_network(net, ChainMode::Divi)
            .checkpoints
            .is_empty());
    }
}

/// A block at a checkpoint height with another hash is refused, on the tip
/// and on a side chain
#[test]
fn block_missing_a_checkpoint_is_refused() {
    let base = TestChain::new(regtest());
    base.tag.set(1000);
    base.extend_pow(3);
    let pinned = base
        .chain
        .get_block_index_by_height(3)
        .unwrap()
        .unwrap()
        .hash;

    let mut params = regtest();
    params.checkpoints = vec![(3, pinned)];
    let t = TestChain::new(params);
    t.extend_pow(2);
    let two = t.tip();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &two,
        Amount::from_sat(1250 * COIN),
        vec![],
    )));
    assert!(msg.contains("checkpoint mismatch"), "{msg}");
    assert_eq!(t.tip().height, 2);

    // Same on a side chain at height 3
    let one = t.chain.get_block_index_by_height(1).unwrap().unwrap();
    let s2 = t.pow_block(&one, Amount::from_sat(1250 * COIN), vec![]);
    let s2h = compute_block_hash(&s2.header);
    t.chain.accept_block(s2).unwrap();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &t.index(&s2h),
        Amount::from_sat(1250 * COIN),
        vec![],
    )));
    assert!(msg.contains("checkpoint mismatch"), "{msg}");
}

#[test]
fn min_stake_age_per_network() {
    let a = |net| ChainParams::for_network(net, ChainMode::Divi).min_stake_age;
    assert_eq!(a(NetworkType::Mainnet), 3600);
    assert_eq!(a(NetworkType::Testnet), 3600);
    assert_eq!(a(NetworkType::Regtest), 0);
}

/// With a one-hour minimum, a kernel 59 minutes old is refused, one hour old accepted
#[test]
fn stake_younger_than_min_age_is_refused() {
    let mut params = regtest();
    params.min_stake_age = 3600;
    let t = TestChain::new(params);
    let coins = t.extend_pow(100);
    let tip = t.tip();
    // Kernel from height 80; its block time plus 3540 s
    let kernel_time = t.chain.get_block_index_by_height(80).unwrap().unwrap().time;
    assert!(kernel_time + 3540 > tip.time);
    let young = t.pos_block(&tip, kernel_time + 3540, coins[79], |_| {}, |_| {});
    let msg = err_text(t.chain.accept_block(young));
    assert!(msg.contains("min age violation"), "{msg}");
    let old = t.pos_block(&tip, kernel_time + 3600, coins[79], |_| {}, |_| {});
    t.chain.accept_block(old).unwrap();
    assert_eq!(t.tip().height, 101);
}
