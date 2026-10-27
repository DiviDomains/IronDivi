// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Divi Core 3.0.0's finality rule for blocks (IsFinalTx in
//! ContextualCheckBlock, TransactionFinalityHelpers.cpp:8-25,
//! ChainExtensionService.cpp:357-385): a height lock below 500,000,000 is
//! compared with the block's height, a time lock with the block's own time
//! (not the median time past), and a transaction whose inputs all have the
//! final sequence is final whatever its lock. AcceptBlock runs it on every
//! block as it arrives, a block of a side chain too (:493), after the
//! header's time, checkpoint and version rules and before BIP34.

mod common;

use common::*;
use divi_crypto::compute_merkle_root;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::script::Script;
use divi_primitives::transaction::{Transaction, TxIn, TxOut};

const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// A transaction spending `coins` (ours) with `lock_time`, the inputs'
/// sequences from `sequences`
fn locked_spend(t: &TestChain, coins: &[Coin], lock_time: u32, sequences: &[u32]) -> Transaction {
    let total = coins.iter().fold(Amount::ZERO, |a, c| a + c.value);
    let mut tx = Transaction {
        version: 1,
        vin: coins
            .iter()
            .zip(sequences)
            .map(|(c, s)| TxIn::new(c.outpoint, Script::new(), *s))
            .collect(),
        vout: vec![TxOut::new(total - Amount::from_sat(COIN), t.pay.clone())],
        lock_time,
    };
    for (i, c) in coins.iter().enumerate() {
        sign_input(&mut tx, i, &t.pay, c.value, &t.key);
    }
    tx
}

fn reseal(block: &mut Block) {
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    mine(block);
}

/// A chain of 25 PoW blocks; the coinbases of blocks 1-5 are mature for a
/// block at 26
fn chain() -> (TestChain, Vec<Coin>) {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(25);
    (t, coins)
}

/// The block at 26 holding `tx`, its time `time` (default: the tip's + 60)
fn block_with(t: &TestChain, tx: Transaction, time: Option<u32>) -> Block {
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![tx]);
    if let Some(time) = time {
        b.header.time = time;
    }
    reseal(&mut b);
    b
}

fn accepted(t: &TestChain, b: Block) -> bool {
    let before = t.tip().height;
    match t.chain.accept_block(b) {
        Ok(_) => {
            assert_eq!(t.tip().height, before + 1);
            true
        }
        Err(e) => {
            assert!(e.to_string().contains("bad-txns-nonfinal"), "{e}");
            assert_eq!(t.tip().height, before);
            false
        }
    }
}

#[test]
fn a_height_lock_is_compared_with_the_blocks_height() {
    let (t, coins) = chain();
    // The block is at 26: a lock of 26 is not below it
    assert!(!accepted(
        &t,
        block_with(&t, locked_spend(&t, &coins[..1], 26, &[0]), None)
    ));
    assert!(!accepted(
        &t,
        block_with(&t, locked_spend(&t, &coins[..1], 27, &[0]), None)
    ));
    // 499,999,999 is still a height
    assert!(!accepted(
        &t,
        block_with(&t, locked_spend(&t, &coins[..1], 499_999_999, &[0]), None)
    ));
    assert!(accepted(
        &t,
        block_with(&t, locked_spend(&t, &coins[..1], 25, &[0]), None)
    ));
}

#[test]
fn a_time_lock_is_compared_with_the_blocks_own_time() {
    let (t, coins) = chain();
    let tip = t.tip();
    let time = tip.time + 60;
    let mtp = t.chain.get_median_time_past(&tip).unwrap();
    assert!(mtp < tip.time);
    assert!(!accepted(
        &t,
        block_with(&t, locked_spend(&t, &coins[..1], time, &[0]), Some(time))
    ));
    assert!(!accepted(
        &t,
        block_with(
            &t,
            locked_spend(&t, &coins[..1], time + 1, &[0]),
            Some(time)
        )
    ));
    // Past the median time past but not past the block's time: final, as
    // Divi Core compares a time lock with the block's time
    assert!(accepted(
        &t,
        block_with(
            &t,
            locked_spend(&t, &coins[..1], tip.time, &[0]),
            Some(time)
        )
    ));
    // 500,000,000 is a time, long past
    assert!(accepted(
        &t,
        block_with(&t, locked_spend(&t, &coins[1..2], 500_000_000, &[0]), None)
    ));
}

#[test]
fn final_sequences_make_any_lock_final() {
    let (t, coins) = chain();
    // Every input final: final whatever the lock
    let all_final = locked_spend(&t, &coins[..2], 1_000_000, &[SEQUENCE_FINAL; 2]);
    // One input not final is enough to keep the lock
    let one_open = locked_spend(&t, &coins[2..4], 1_000_000, &[SEQUENCE_FINAL, 0]);
    assert!(!accepted(&t, block_with(&t, one_open, None)));
    assert!(accepted(&t, block_with(&t, all_final, None)));
    // A coinbase is held to the same rule
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.transactions[0].lock_time = tip.height + 1;
    b.transactions[0].vin[0].sequence = 0;
    reseal(&mut b);
    assert!(!accepted(&t, b));
}

/// A block of a side chain holding a transaction that is not final is
/// refused as it arrives, with a score of 10: divid's AcceptBlock runs
/// ContextualCheckBlock before it writes the block
/// (ChainExtensionService.cpp:493-499), so the block never waits for a reorg.
/// Its header stays in the index, marked failed and without its data: the
/// block sent again is refused with a score of 0 and no reject, and a block
/// on it is refused as bad-prevblk with a score of 100 (:405-426)
#[test]
fn a_side_chain_block_with_a_non_final_transaction_is_refused_on_arrival() {
    let (t, coins) = chain();
    let parent = t.tip();
    let tip_block = t.pow_block(&parent, Amount::from_sat(1250 * COIN), vec![]);
    t.chain.accept_block(tip_block).unwrap();
    let tip = t.tip();
    assert_eq!(tip.height, 26);

    // A sibling of the tip block, at 26, holding a lock of 26
    let mut side = t.pow_block_raw(
        &parent,
        Amount::from_sat(1250 * COIN),
        vec![locked_spend(&t, &coins[..1], 26, &[0])],
    );
    side.header.time = tip.time + 1;
    reseal(&mut side);
    let side_hash = divi_crypto::compute_block_hash(&side.header);
    match t.chain.accept_block(side.clone()) {
        Err(e) => {
            assert!(e.to_string().contains("bad-txns-nonfinal"), "{e}");
            assert_eq!(e.misbehaviour_score(), 10, "{e}");
            assert_eq!(e.block_reject().map(|(code, _)| code), Some(0x10), "{e}");
        }
        Ok(_) => panic!("a side-chain block with a non-final transaction was taken"),
    }
    let kept = t
        .chain
        .get_block_index(&side_hash)
        .unwrap()
        .expect("the refused block's header is kept");
    assert!(kept.failed(), "the refused block is not marked failed");
    assert!(!kept.has_data(), "the refused block's data was kept");
    assert!(t.chain.get_block(&side_hash).unwrap().is_none());
    assert_eq!(t.tip().hash, tip.hash);

    // Sent again: known to be invalid, no score, no reject
    let e = t.chain.accept_block(side.clone()).unwrap_err();
    assert_eq!(e.misbehaviour_score(), 0, "{e}");
    assert_eq!(e.block_reject(), None, "{e}");

    // A block on it: bad-prevblk, score 100
    let child = t.pow_block(&kept, Amount::from_sat(1250 * COIN), vec![]);
    let child_hash = divi_crypto::compute_block_hash(&child.header);
    let e = t.chain.accept_block(child).unwrap_err();
    assert_eq!(e.misbehaviour_score(), 100, "{e}");
    assert_eq!(
        e.block_reject(),
        Some((0x10, "bad-prevblk".to_string())),
        "{e}"
    );
    assert!(t.chain.get_block_index(&child_hash).unwrap().is_none());
    assert_eq!(t.tip().hash, tip.hash);

    // The same sibling with a lock of 25 is final and kept as a side chain
    let mut side = t.pow_block_raw(
        &parent,
        Amount::from_sat(1250 * COIN),
        vec![locked_spend(&t, &coins[..1], 25, &[0])],
    );
    side.header.time = tip.time + 2;
    reseal(&mut side);
    let side_hash = divi_crypto::compute_block_hash(&side.header);
    t.chain.accept_block(side).unwrap();
    let held = t.chain.get_block_index(&side_hash).unwrap().unwrap();
    assert!(!held.failed() && held.has_data());
    assert_eq!(t.tip().hash, tip.hash);
}

/// The same for the other ContextualCheckBlock rule, BIP34: the header of a
/// block whose coinbase does not start with its height is kept as failed
#[test]
fn a_block_without_the_height_in_its_coinbase_is_kept_as_failed() {
    let (t, _) = chain();
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.transactions[0].vin[0].script_sig = Script::from_bytes(vec![0x02, 0xab, 0xcd]);
    reseal(&mut b);
    let hash = divi_crypto::compute_block_hash(&b.header);
    let e = t.chain.accept_block(b).unwrap_err();
    assert!(e.to_string().contains("bad-cb-height"), "{e}");
    let kept = t.chain.get_block_index(&hash).unwrap().unwrap();
    assert!(kept.failed() && !kept.has_data());
    let child = t.pow_block(&kept, Amount::from_sat(1250 * COIN), vec![]);
    let e = t.chain.accept_block(child).unwrap_err();
    assert_eq!(e.misbehaviour_score(), 100, "{e}");
    // A valid block at that height is still taken
    t.extend_pow(1);
    assert_eq!(t.tip().height, tip.height + 1);
}

/// A block refused by a header rule (here the version) leaves no header, as
/// Divi Core's AcceptBlockHeader returns before it adds one (:429-433)
#[test]
fn a_block_refused_by_a_header_rule_leaves_nothing() {
    let (t, _) = chain();
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.header.version = 2;
    reseal(&mut b);
    let hash = divi_crypto::compute_block_hash(&b.header);
    let e = t.chain.accept_block(b).unwrap_err();
    assert!(e.to_string().contains("bad-version"), "{e}");
    assert!(t.chain.get_block_index(&hash).unwrap().is_none());
}

/// Divi Core's order: the header's time rule before the finality rule, the
/// finality rule before BIP34 (ChainExtensionService.cpp:313-317, :362-368,
/// :375-382). A block that breaks two of them is refused for the first.
#[test]
fn the_finality_rule_comes_after_the_time_rule_and_before_bip34() {
    let (t, coins) = chain();
    let tip = t.tip();

    // Not final and a coinbase without the height: refused as not final
    let mut b = t.pow_block_raw(
        &tip,
        Amount::from_sat(1250 * COIN),
        vec![locked_spend(&t, &coins[..1], 26, &[0])],
    );
    b.transactions[0].vin[0].script_sig = Script::from_bytes(vec![0x02, 0xab, 0xcd]);
    reseal(&mut b);
    let e = t.chain.accept_block(b).unwrap_err();
    assert!(e.to_string().contains("bad-txns-nonfinal"), "{e}");
    assert_eq!(e.misbehaviour_score(), 10);

    // At the median time past and not final: refused for the time, score 0
    let mtp = t.chain.get_median_time_past(&tip).unwrap();
    let mut b = t.pow_block_raw(
        &tip,
        Amount::from_sat(1250 * COIN),
        vec![locked_spend(&t, &coins[..1], 26, &[0])],
    );
    b.header.time = mtp;
    reseal(&mut b);
    let e = t.chain.accept_block(b).unwrap_err();
    assert!(e.to_string().contains("time-too-old"), "{e}");
    assert_eq!(e.misbehaviour_score(), 0);

    // At the median time past and a coinbase without the height: the time
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.header.time = mtp;
    b.transactions[0].vin[0].script_sig = Script::from_bytes(vec![0x02, 0xab, 0xcd]);
    reseal(&mut b);
    let e = t.chain.accept_block(b).unwrap_err();
    assert!(e.to_string().contains("time-too-old"), "{e}");
    assert_eq!(e.misbehaviour_score(), 0);
    assert_eq!(t.tip().hash, tip.hash);
}
