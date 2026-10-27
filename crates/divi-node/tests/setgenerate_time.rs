// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Where setgenerate's stake blocks take their time on regtest, as divid's
//! PoSTransactionCreator::attachBlockProof (PoSTransactionCreator.cpp:331-341)
//! picks it: the kernel search starts at the network-adjusted time, but past
//! the median time past, and never past the future drift; it counts down from
//! there. The test sets the mock clock, so it runs alone in this binary.

use divi_network::{PeerManager, PeerManagerConfig};
use divi_node::config::MempoolConfig;
use divi_node::{Mempool, Staker, StakingConfig};
use divi_primitives::clock::set_mock_time;
use divi_primitives::ChainMode;
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use std::sync::Arc;

/// The median time past of the block `hash`: the median of its own and its
/// ten parents' times (Divi Core CBlockIndex::GetMedianTimePast)
fn median_time_past(chain: &Chain, hash: divi_primitives::hash::Hash256) -> u32 {
    let mut times = Vec::new();
    let mut index = chain.get_block_index(&hash).unwrap();
    while let Some(block) = index {
        times.push(block.time);
        if times.len() == 11 || block.height == 0 {
            break;
        }
        index = chain.get_block_index(&block.prev_hash).unwrap();
    }
    times.sort_unstable();
    times[times.len() / 2]
}

#[test]
fn setgenerate_stake_blocks_start_their_search_where_divid_does() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let config = StakingConfig {
        min_coin_age: chain.params().min_stake_age,
        ..StakingConfig::default()
    };
    let staker = Staker::new(
        wallet.clone(),
        chain.clone(),
        Arc::new(Mempool::new(MempoolConfig::default())),
        PeerManager::new(PeerManagerConfig::default()),
        config,
    );
    // The wallet learns of each block as irondivid's callback scans it
    let (scan_wallet, scan_chain) = (wallet.clone(), chain.clone());
    staker.set_block_connected_callback(Arc::new(move |_, _| {
        scan_wallet.sync_to_tip(
            scan_chain.height(),
            |h| {
                scan_chain
                    .get_block_index_by_height(h)
                    .ok()
                    .flatten()
                    .map(|i| i.hash)
            },
            |h| {
                let index = scan_chain.get_block_index_by_height(h).ok().flatten()?;
                let block = scan_chain.get_block(&index.hash).ok().flatten()?;
                Some((index.hash, block))
            },
        );
    }));

    // A clock that stands still, so the median time catches up with it
    let now = 1_750_000_000;
    set_mock_time(now);
    staker.generate_blocks(100).unwrap();
    assert_eq!(chain.height(), 100);

    for _ in 0..30 {
        let tip = chain.tip().unwrap();
        let mtp = median_time_past(&chain, tip.hash);
        // Regtest does not retarget, so no hash drift is added to the floor
        let start = now.max(i64::from(mtp) + 1) as u32;
        staker.generate_blocks(1).unwrap();
        let block = chain.tip().unwrap();
        assert_eq!(block.height, tip.height + 1);
        // At the start or up to the hash drift before it, past the median time
        assert!(
            block.time <= start,
            "{} after the start {start}",
            block.time
        );
        assert!(block.time + 45 > start, "{} before the drift", block.time);
        assert!(
            block.time > mtp,
            "{} not past the median time {mtp}",
            block.time
        );
    }
    // The stand-still clock fell behind the median time: blocks come at
    // the median time plus one
    let tip = chain.tip().unwrap();
    assert!(median_time_past(&chain, tip.hash) >= now as u32);

    // Clock taken back until the latest time divid stakes at, the adjusted
    // time plus 179, is the median time plus one: divid finds no time left
    // (`maximumTime <= minimumTime`, PoSTransactionCreator.cpp:337-340) and
    // setgenerate makes no block, though the median time plus one would pass
    // CheckBlock's 180 s
    let mtp = median_time_past(&chain, tip.hash);
    let behind = i64::from(mtp) + 1 - 179;
    set_mock_time(behind);
    assert!(staker.generate_blocks(1).is_err());
    assert_eq!(chain.height(), tip.height);
    // One second later there is a second to stake at, the median time plus one
    set_mock_time(behind + 1);
    staker.generate_blocks(1).unwrap();
    assert_eq!(chain.tip().unwrap().time, mtp + 1);
    set_mock_time(0);
}
