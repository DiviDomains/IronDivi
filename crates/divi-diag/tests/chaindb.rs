// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.8 against a real chain database written by divi-storage: the record
//! layout diag parses matches `BlockIndex::to_bytes`, the secondary open
//! works while the primary is open, and the secondary folder is removed.
#![cfg(feature = "chaindb")]

use divi_diag::collectors::chain::{self, parse_index};
use divi_diag::frame::Out;
use divi_primitives::block::BlockHeader;
use divi_storage::{BlockIndex, BlockStatus, ChainDatabase};

fn chain_of(n: u32) -> Vec<BlockIndex> {
    let mut v: Vec<BlockIndex> = Vec::new();
    for h in 0..n {
        let mut hd = BlockHeader::default();
        hd.nonce = h + 1;
        if let Some(p) = v.last() {
            hd.prev_block = p.hash;
        }
        let mut ix = BlockIndex::from_header(&hd, h, v.last());
        ix.hash = hd.hash();
        ix.status.insert(BlockStatus::VALID_HEADER);
        ix.status.insert(BlockStatus::HAVE_DATA);
        ix.status.insert(BlockStatus::ON_MAIN_CHAIN);
        v.push(ix);
    }
    v
}

#[test]
fn layout_matches_divi_storage() {
    let c = chain_of(2);
    let b = c[1].to_bytes();
    let h = parse_index(&b).unwrap();
    assert_eq!(h.height, 1);
    assert_eq!(&h.hash, c[1].hash.as_bytes());
    assert_eq!(&h.prev, c[0].hash.as_bytes());
    assert_eq!(h.status, c[1].status.bits());
}

#[test]
fn secondary_open_reports() {
    let t = tempfile::tempdir().unwrap();
    let cs = t.path().join("chainstate");
    let db = ChainDatabase::open(&cs).unwrap();
    let c = chain_of(6);
    for ix in &c {
        db.store_block_index(ix).unwrap();
    }
    // a failed side block at height 4
    let mut hd = BlockHeader::default();
    hd.nonce = 999;
    hd.prev_block = c[3].hash;
    let mut bad = BlockIndex::from_header(&hd, 4, Some(&c[3]));
    bad.hash = hd.hash();
    bad.status.insert(BlockStatus::VALID_HEADER);
    bad.status.insert(BlockStatus::FAILED);
    db.store_block_index_entry(&bad).unwrap();
    db.put_metadata(b"chain_height", &5u32.to_le_bytes()).unwrap();
    db.set_best_block(&c[5].hash).unwrap();
    db.put_metadata(b"network", b"regtest").unwrap();

    // the primary stays open: B2.8 must work while the node runs
    let before = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("irondivi-diag-secondary-"))
        .count();
    let mut o = Out::capture();
    chain::open_and_report(&cs, &t.path().join("txindex"), &mut o).unwrap();
    let s = o.captured();
    assert!(s.contains("tip height: 5"), "{s}");
    assert!(s.contains(&format!("tip hash: blk:{}", c[5].hash.to_hex())), "{s}");
    assert!(s.contains("chain mode / network recorded: regtest"), "{s}");
    assert!(s.contains("failed-block entries: 1"), "{s}");
    assert!(s.contains(&format!("blk:{}", bad.hash.to_hex())), "{s}");
    assert!(s.contains("6 height records read, 0 problems"), "{s}");
    assert!(s.contains("header tip: height 5"), "{s}");
    let after = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("irondivi-diag-secondary-"))
        .count();
    assert!(after <= before, "secondary folder left behind");
    drop(db);
}
