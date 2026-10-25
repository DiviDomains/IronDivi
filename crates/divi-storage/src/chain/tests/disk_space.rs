// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Under 50 MB free, Divi Core writes no block and no coins: it aborts with
//! "Disk space is low!" (BlockFileHelpers.cpp:132-142, FlushChainState.cpp:31-40).
//! The free space is set for the test's thread.

use super::*;
use crate::disk_space::{set_free_for_test, MIN_DISK_SPACE};

fn open_chain(path: &std::path::Path) -> Chain {
    let db = Arc::new(ChainDatabase::open(path.join("chain")).unwrap());
    Chain::new(
        db,
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap()
}

#[test]
fn no_block_is_written_with_under_50_mb_free() {
    let dir = tempdir().unwrap();
    let chain = open_chain(dir.path());
    let (g, gt) = get_genesis_info(&chain);
    let block = create_child_block_with_pubkey(g, gt, [0x0a; 20]);
    let hash = compute_block_hash(&block.header);

    set_free_for_test(Some(MIN_DISK_SPACE + 10));
    let refused = chain.accept_block(block.clone());
    set_free_for_test(None);
    let err = refused.expect_err("the block is refused");
    assert!(err.to_string().contains("Disk space is low!"), "{err}");
    assert!(crate::abort::aborted(), "the node aborts");
    assert_eq!(chain.height(), 0);
    assert!(
        !chain.has_block(&hash).unwrap(),
        "nothing of the block is stored"
    );

    // With room for it, the same block is taken
    set_free_for_test(Some(MIN_DISK_SPACE + 1_000_000));
    let taken = chain.accept_block(block);
    set_free_for_test(None);
    assert_eq!(taken.unwrap().hash, hash);
    assert_eq!(chain.height(), 1);
}
