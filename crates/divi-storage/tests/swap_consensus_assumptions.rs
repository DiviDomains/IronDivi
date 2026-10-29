// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Pins the Divi Core rules the swap confirmation math relies on
//! (`docs/plans/swap-poc/divi-confirmations.md`, "IronDivi enforcement of these rules").
//!
//! Every block here goes through `Chain::accept_block`, the entry point the sync layer
//! calls for a block that arrives from a peer. Blocks are regtest PoW blocks with a
//! proof of work for regtest's fixed bits, so they pass the difficulty check and the
//! test shows the rule it names.

mod common;

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

/// A PoW-era (height <= 100) block at `height`: one coinbase, optional extra transactions.
fn block_on(
    height: u32,
    parent: Hash256,
    time: u32,
    bits: u32,
    tag: u8,
    extra: Vec<Transaction>,
) -> Block {
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = parent;
    block.header.time = time;
    block.header.bits = bits;
    let coinbase = Transaction {
        version: 1,
        // BIP34 height, then a tag
        vin: vec![TxIn::coinbase(Script::from_bytes(
            [
                common::bip34_height(height),
                vec![2, tag, (time & 0xff) as u8],
            ]
            .concat(),
        ))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250_00000000),
            Script::new_p2pkh(&[tag; 20]),
        )],
        lock_time: 0,
    };
    block.transactions.push(coinbase);
    block.transactions.extend(extra);
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    let target = Hash256::from_compact(bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    block
}

/// Regtest's PoW limit (~uint256(0) >> 1), which regtest never retargets from
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
        let b = block_on(i + 1, parent, t, EASY_BITS, 1 + i as u8, vec![]);
        chain.accept_block(b).unwrap();
        parent = chain.tip().unwrap().hash;
    }
    let mtp = chain.get_median_time_past(&chain.tip().unwrap()).unwrap();
    let bad = block_on(12, parent, mtp, EASY_BITS, 0x77, vec![]);
    let msg = err_text(chain.accept_block(bad));
    assert!(msg.contains("not greater than median time past"), "{msg}");
    let ok = block_on(12, parent, mtp + 1, EASY_BITS, 0x78, vec![]);
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
            .accept_block(block_on(i + 1, parent, t, EASY_BITS, 1 + i as u8, vec![]))
            .unwrap();
        parent = chain.tip().unwrap().hash;
    }
    // Fork off genesis: first fork block is fine, the second is not later than its parent's MTP.
    let f1 = block_on(1, genesis, gt + 30, EASY_BITS, 0x40, vec![]);
    let f1h = divi_crypto::compute_block_hash(&f1.header);
    chain.accept_block(f1).unwrap();
    let mtp = chain
        .get_median_time_past(&chain.get_block_index(&f1h).unwrap().unwrap())
        .unwrap();
    let bad = block_on(2, f1h, mtp, EASY_BITS, 0x41, vec![]);
    let msg = err_text(chain.accept_block(bad));
    assert!(msg.contains("not greater than median time past"), "{msg}");
}

/// Core `ChainExtensionService.cpp:308-311`: a block is refused when
/// `tip height - block height >= 100` (`nMaxReorganizationDepth`, every Divi network).
/// Main chain of 101 blocks; a fork block at height 1 is 100 deep and refused, so a fork
/// from genesis can never grow to out-work the tip. (With a 100-block tip the height-1
/// fork block is only 99 deep, which Core accepts.)
#[test]
fn fork_deeper_than_max_reorg_depth_is_rejected() {
    // Heights 1-100 are PoW, 101 is PoS (no PoW block after the last PoW block)
    let t = common::TestChain::new(common::regtest());
    let coins = t.extend_pow(100);
    t.chain
        .accept_block(t.simple_pos(&t.tip(), coins[0]))
        .unwrap();
    let chain = &t.chain;
    let (genesis, gt) = (
        chain.get_block_index_by_height(0).unwrap().unwrap().hash,
        chain.get_block_index_by_height(0).unwrap().unwrap().time,
    );
    assert_eq!(chain.tip().unwrap().height, 101);
    let main_tip = chain.tip().unwrap().hash;
    let mut p = genesis;
    let mut refused = None;
    for i in 1..=102u32 {
        let b = block_on(i, p, gt + 59 * i, EASY_BITS, (i % 200) as u8 + 101, vec![]);
        p = divi_crypto::compute_block_hash(&b.header);
        if let Err(e) = chain.accept_block(b) {
            refused = Some((i, e.to_string()));
            break;
        }
    }
    let (at, msg) = refused.expect("a 100-deep fork block must be refused");
    assert_eq!(at, 1);
    assert!(msg.contains("max reorganization depth"), "{msg}");
    assert_eq!(
        chain.tip().unwrap().hash,
        main_tip,
        "tip must not move to a >=100-deep fork"
    );
}

/// Core `UtxoCheckingAndUpdating.cpp:75`: a coinbase output cannot be spent before 20 blocks
/// (`nMaturity` 20 on mainnet and regtest).
#[test]
fn block_spending_an_immature_coinbase_is_rejected() {
    let (chain, _d) = new_chain(NetworkType::Regtest);
    let (genesis, gt) = tip_info(&chain);
    let b1 = block_on(1, genesis, gt + 60, EASY_BITS, 1, vec![]);
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
    let b2 = block_on(2, h1, gt + 120, EASY_BITS, 2, vec![spend]);
    let msg = err_text(chain.accept_block(b2));
    assert!(
        msg.contains("bad-txns-premature-spend-of-coinbase"),
        "1 confirmation < 20: {msg}"
    );
}
