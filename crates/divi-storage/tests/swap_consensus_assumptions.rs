// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Pins the Divi Core rules the swap confirmation math relies on
//! (`docs/plans/swap-poc/divi-confirmations.md`, "IronDivi enforcement of these rules").
//!
//! Every block here goes through `Chain::accept_block`, the entry point the sync layer
//! calls for a block that arrives from a peer. A test without `#[ignore]` pins a rule
//! IronDivi enforces; a test with `#[ignore = "NOT ENFORCED: ..."]` fails today and
//! passes once the rule is enforced.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash256,
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use std::sync::Arc;
use tempfile::{tempdir, TempDir};

fn new_chain(net: NetworkType) -> (Chain, TempDir) {
    let dir = tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Chain::new(db, ChainParams::for_network(net, ChainMode::Divi)).unwrap();
    (chain, dir)
}

/// A PoW-era (height <= 100) block: one coinbase, optional extra transactions.
fn block_on(parent: Hash256, time: u32, bits: u32, tag: u8, extra: Vec<Transaction>) -> Block {
    let mut block = Block::default();
    block.header.version = 1;
    block.header.prev_block = parent;
    block.header.time = time;
    block.header.bits = bits;
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(vec![
            0x05,
            tag,
            (time & 0xff) as u8,
        ]))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250_00000000),
            Script::new_p2pkh(&[tag; 20]),
        )],
        lock_time: 0,
    };
    block.transactions.push(coinbase);
    block.transactions.extend(extra);
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    block
}

const EASY_BITS: u32 = 0x207fffff;

fn tip_info(chain: &Chain) -> (Hash256, u32) {
    let t = chain.tip().expect("genesis");
    (t.hash, t.time)
}

fn err_text<T>(r: Result<T, divi_storage::StorageError>) -> String {
    match r {
        Ok(_) => String::from("<accepted>"),
        Err(e) => e.to_string(),
    }
}

/// Core `ChainExtensionService.cpp:314` `time-too-old`: a block whose time is not later than the
/// parent's median-time-past is rejected. IronDivi: `chain.rs:2125-2131` (extends the tip).
#[test]
fn block_not_later_than_parent_mtp_is_rejected_on_the_tip() {
    let (chain, _d) = new_chain(NetworkType::Regtest);
    let (mut parent, mut t) = tip_info(&chain);
    for i in 0..11u32 {
        t += 60;
        let b = block_on(parent, t, EASY_BITS, 1 + i as u8, vec![]);
        chain.accept_block(b).unwrap();
        parent = chain.tip().unwrap().hash;
    }
    let mtp = chain.get_median_time_past(&chain.tip().unwrap()).unwrap();
    let bad = block_on(parent, mtp, EASY_BITS, 0x77, vec![]);
    let msg = err_text(chain.accept_block(bad));
    assert!(msg.contains("not greater than median time past"), "{msg}");
    let ok = block_on(parent, mtp + 1, EASY_BITS, 0x78, vec![]);
    assert!(chain.accept_block(ok).is_ok());
}

/// Same rule on the side-chain path (`chain.rs:1073-1079`), which is where a competing fork is stored.
#[test]
fn block_not_later_than_parent_mtp_is_rejected_on_a_side_chain() {
    let (chain, _d) = new_chain(NetworkType::Regtest);
    let (genesis, gt) = tip_info(&chain);
    let mut parent = genesis;
    let mut t = gt;
    for i in 0..3u32 {
        t += 60;
        chain
            .accept_block(block_on(parent, t, EASY_BITS, 1 + i as u8, vec![]))
            .unwrap();
        parent = chain.tip().unwrap().hash;
    }
    // Fork off genesis: first fork block is fine, the second is not later than its parent's MTP.
    let f1 = block_on(genesis, gt + 30, EASY_BITS, 0x40, vec![]);
    let f1h = divi_crypto::compute_block_hash(&f1.header);
    chain.accept_block(f1).unwrap();
    let mtp = chain
        .get_median_time_past(&chain.get_block_index(&f1h).unwrap().unwrap())
        .unwrap();
    let bad = block_on(f1h, mtp, EASY_BITS, 0x41, vec![]);
    let msg = err_text(chain.accept_block(bad));
    assert!(msg.contains("not greater than median time past"), "{msg}");
}

/// Core `ChainExtensionService.cpp:309-311`: a fork is rejected when
/// `tip height - fork height >= 100` (mainnet). IronDivi has no such rule (`sync.rs:810-812`).
/// Main chain of 100 blocks; a heavier fork from genesis (depth 100) must be refused.
#[test]
#[ignore = "NOT ENFORCED: no max-reorg-depth rule; a 100-deep fork with more work reorganises the tip"]
fn fork_deeper_than_max_reorg_depth_is_rejected() {
    let (chain, _d) = new_chain(NetworkType::Mainnet);
    let (genesis, gt) = tip_info(&chain);
    let mut parent = genesis;
    for i in 1..=100u32 {
        let b = block_on(parent, gt + 60 * i, EASY_BITS, (i % 200) as u8 + 1, vec![]);
        chain.accept_block(b).unwrap();
        parent = chain.tip().unwrap().hash;
    }
    assert_eq!(chain.tip().unwrap().height, 100);
    let main_tip = chain.tip().unwrap().hash;
    // Heavier fork from genesis: harder bits => more work per block, so 99 blocks out-work 100.
    let mut p = genesis;
    let mut last = Ok(());
    for i in 1..=99u32 {
        let b = block_on(p, gt + 59 * i, 0x1f00ffff, (i % 200) as u8 + 1, vec![]);
        p = divi_crypto::compute_block_hash(&b.header);
        if let Err(e) = chain.accept_block(b) {
            last = Err(e);
            break;
        }
    }
    let _ = last;
    assert_eq!(
        chain.tip().unwrap().hash,
        main_tip,
        "tip must not move to a >=100-deep fork"
    );
}

/// Core `UtxoCheckingAndUpdating.cpp:75`: a coinbase output cannot be spent before 20 blocks.
/// IronDivi checks maturity only for mempool admission (`node.rs:947-967`), not in `connect_block`.
#[test]
#[ignore = "NOT ENFORCED: connect_block does not check coinbase/coinstake maturity"]
fn block_spending_an_immature_coinbase_is_rejected() {
    let (chain, _d) = new_chain(NetworkType::Mainnet);
    let (genesis, gt) = tip_info(&chain);
    let b1 = block_on(genesis, gt + 60, EASY_BITS, 1, vec![]);
    let cb_txid = b1.transactions[0].txid();
    let h1 = divi_crypto::compute_block_hash(&b1.header);
    chain.accept_block(b1).unwrap();
    let spend = Transaction {
        version: 1,
        vin: vec![TxIn::new(
            OutPoint::new(cb_txid, 0),
            Script::from_bytes(vec![0x51]),
            0xffff_ffff,
        )],
        vout: vec![TxOut::new(
            Amount::from_sat(1249_00000000),
            Script::new_p2pkh(&[9u8; 20]),
        )],
        lock_time: 0,
    };
    let b2 = block_on(h1, gt + 120, EASY_BITS, 2, vec![spend]);
    assert!(chain.accept_block(b2).is_err(), "1 confirmation < 20");
}
