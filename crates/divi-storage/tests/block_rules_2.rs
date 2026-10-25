// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! More block rules of Divi Core 3.0.0: the coinbase starts with the block
//! height (BIP34), block version 3 or later, a PoS block at most 180 s in the
//! future, the sigop limits, no reuse of a transaction id with unspent outputs
//! (BIP30) or a duplicated transaction list, and the block and transaction size
//! limits.

mod common;

use common::*;
use divi_crypto::compute_merkle_root;
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn reseal(block: &mut divi_primitives::block::Block) {
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    mine(block);
}

// --- a: BIP34 (ChainExtensionService.cpp:375-382) ---

/// A coinbase that does not start with the block's height is refused
#[test]
fn coinbase_without_the_height_is_refused() {
    let t = TestChain::new(regtest());
    t.extend_pow(20);
    let tip = t.tip();
    // No height at all
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.transactions[0].vin[0].script_sig = Script::from_bytes(vec![0x02, 0xab, 0xcd]);
    reseal(&mut b);
    let msg = err_text(t.chain.accept_block(b));
    assert!(msg.contains("bad-cb-height"), "{msg}");
    // The next height's number instead of this one's
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    let mut sig = bip34_height(tip.height + 2);
    sig.extend_from_slice(&[0x01, 0x77]);
    b.transactions[0].vin[0].script_sig = Script::from_bytes(sig);
    reseal(&mut b);
    let msg = err_text(t.chain.accept_block(b));
    assert!(msg.contains("bad-cb-height"), "{msg}");
    assert_eq!(t.tip().height, 20);
    // Heights 1-16 are OP_1..OP_16, as Core's CScript() << nHeight
    assert_eq!(bip34_height(1), vec![0x51]);
    assert_eq!(bip34_height(17), vec![0x01, 0x11]);
}

// --- b: block version (ChainExtensionService.cpp:350-353) ---

#[test]
fn block_version_below_3_is_refused() {
    let t = TestChain::new(regtest());
    t.extend_pow(2);
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.header.version = 2;
    reseal(&mut b);
    let msg = err_text(t.chain.accept_block(b));
    assert!(
        msg.contains("bad-version: rejected nVersion=2 block"),
        "{msg}"
    );
    // Version 3 is accepted
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.header.version = 3;
    reseal(&mut b);
    t.chain.accept_block(b).unwrap();
    assert_eq!(t.tip().height, 3);
}

// --- c: future drift (BlockCheckingHelpers.cpp:29-31) ---

/// A PoS block more than 180 s ahead is refused; a PoW block may be 2 hours ahead
#[test]
fn pos_block_more_than_180_seconds_ahead_is_refused() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(99);
    // PoW block 100 an hour ahead: within PoW's 2 hours
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.header.time = now() + 3600;
    reseal(&mut b);
    t.chain.accept_block(b).unwrap();
    let tip = t.tip();
    assert_eq!(tip.height, 100);

    let ahead = t.pos_block(&tip, now() + 600, coins[0], |_| {}, |_| {});
    let msg = err_text(t.chain.accept_block(ahead));
    assert!(msg.contains("time-too-new"), "{msg}");
    assert_eq!(t.tip().height, 100);
    // The PoS block must also be later than its parent (an hour ahead), so the
    // accepted case needs a parent within 180 s: checked in the unit below
    let close = t.pos_block(&tip, tip.time + 1, coins[1], |_| {}, |_| {});
    let msg = err_text(t.chain.accept_block(close));
    assert!(msg.contains("time-too-new"), "{msg}");
}

#[test]
fn pos_block_within_180_seconds_is_accepted() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(99);
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.header.time = now();
    reseal(&mut b);
    t.chain.accept_block(b).unwrap();
    let tip = t.tip();
    let b = t.pos_block(&tip, now() + 150, coins[0], |_| {}, |_| {});
    t.chain.accept_block(b).unwrap();
    assert_eq!(t.tip().height, 101);
}

// --- d: sigops (BlockCheckingHelpers.cpp:86-93, TransactionInputChecker.cpp:85-100) ---

/// More than 20,000 legacy sigops in a block are refused (CheckBlock)
#[test]
fn block_over_the_legacy_sigop_limit_is_refused() {
    let t = TestChain::new(regtest());
    t.extend_pow(1);
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    // 20,001 OP_CHECKSIG in a coinbase output
    b.transactions[0].vout.push(TxOut::new(
        Amount::ZERO,
        Script::from_bytes(vec![0xac; 20_001]),
    ));
    reseal(&mut b);
    let msg = err_text(t.chain.accept_block(b));
    assert!(msg.contains("bad-blk-sigops"), "{msg}");

    // 20,000 is the limit itself (19,999 here plus the P2PKH output's one)
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.transactions[0].vout.push(TxOut::new(
        Amount::ZERO,
        Script::from_bytes(vec![0xac; 19_999]),
    ));
    reseal(&mut b);
    t.chain.accept_block(b).unwrap();
}

/// P2SH inputs count their redeem script's sigops; over 40,000 in a block is
/// refused when the block is connected (ConnectBlock)
#[test]
fn block_over_the_p2sh_sigop_limit_is_refused() {
    let t = TestChain::new(regtest());
    let coin = t.extend_pow(1)[0];
    t.extend_pow(20);
    // Redeem script: 520 OP_CHECKSIG (the largest push), 520 accurate sigops
    let redeem = vec![0xacu8; 520];
    let p2sh = Script::new_p2sh(divi_crypto::hash160(&redeem).as_bytes());
    let fund = t.spend(
        coin,
        (0..80)
            .map(|_| TxOut::new(Amount::from_sat(10 * COIN), p2sh.clone()))
            .collect(),
    );
    let fund_txid = fund.txid();
    let tip = t.tip();
    t.chain
        .accept_block(t.pow_block(&tip, Amount::from_sat(1250 * COIN), vec![fund]))
        .unwrap();
    // 80 inputs x 520 = 41,600 > 40,000; the scriptSig is one push, so 0 legacy sigops
    let mut push = vec![0x4d, (520 & 0xff) as u8, (520 >> 8) as u8];
    push.extend_from_slice(&redeem);
    let spend = Transaction {
        version: 1,
        vin: (0..80)
            .map(|i| {
                TxIn::new(
                    OutPoint::new(fund_txid, i),
                    Script::from_bytes(push.clone()),
                    0xffff_ffff,
                )
            })
            .collect(),
        vout: vec![TxOut::new(Amount::from_sat(700 * COIN), t.pay.clone())],
        lock_time: 0,
    };
    let tip = t.tip();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &tip,
        Amount::from_sat(1250 * COIN),
        vec![spend],
    )));
    assert!(msg.contains("bad-blk-sigops"), "{msg}");
}

// --- e: BIP30 (BlockConnectionService.cpp:56-62) and duplicated transactions ---

/// A transaction whose id still has unspent outputs cannot appear again
#[test]
fn transaction_reusing_an_unspent_id_is_refused() {
    let t = TestChain::new(regtest());
    let coin = t.extend_pow(1)[0];
    t.extend_pow(20);
    let tx = t.spend(
        coin,
        vec![TxOut::new(
            coin.value - Amount::from_sat(COIN),
            t.pay.clone(),
        )],
    );
    let tip = t.tip();
    t.chain
        .accept_block(t.pow_block(&tip, Amount::from_sat(1250 * COIN), vec![tx.clone()]))
        .unwrap();
    let tip = t.tip();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &tip,
        Amount::from_sat(1250 * COIN),
        vec![tx],
    )));
    assert!(msg.contains("bad-txns-BIP30"), "{msg}");
}

/// A block whose transaction list repeats its last transactions (same merkle
/// root as without them) is refused as a duplicate
#[test]
fn block_with_a_duplicated_transaction_list_is_refused() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(2);
    t.extend_pow(20);
    let a = t.spend(
        coins[0],
        vec![TxOut::new(
            coins[0].value - Amount::from_sat(COIN),
            t.pay.clone(),
        )],
    );
    let b2 = t.spend(
        coins[1],
        vec![TxOut::new(
            coins[1].value - Amount::from_sat(COIN),
            t.pay.clone(),
        )],
    );
    // [coinbase, b2, a, a]: the last two hashes of the list are equal
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![b2, a.clone(), a]);
    reseal(&mut b);
    let msg = err_text(t.chain.accept_block(b));
    assert!(msg.contains("bad-txns-duplicate"), "{msg}");
}

// --- f: size limits (BlockCheckingHelpers.cpp:47-50, :106-109) ---

/// A transaction larger than 100,000 bytes is refused
#[test]
fn transaction_over_100000_bytes_is_refused() {
    let t = TestChain::new(regtest());
    let coin = t.extend_pow(1)[0];
    t.extend_pow(20);
    let tx = t.spend(coin, vec![big_output(100_000), change(&t, coin)]);
    let tip = t.tip();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &tip,
        Amount::from_sat(1250 * COIN),
        vec![tx],
    )));
    assert!(msg.contains("bad-txns-oversize"), "{msg}");
}

/// A block larger than 2,000,000 bytes is refused
#[test]
fn block_over_2000000_bytes_is_refused() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(21);
    t.extend_pow(20);
    let txs: Vec<Transaction> = coins
        .iter()
        .map(|c| t.spend(*c, vec![big_output(96_000), change(&t, *c)]))
        .collect();
    let tip = t.tip();
    let b = t.pow_block(&tip, Amount::from_sat(1250 * COIN), txs);
    use divi_primitives::serialize::Encodable;
    assert!(b.encoded_size() > 2_000_000);
    let msg = err_text(t.chain.accept_block(b));
    assert!(msg.contains("bad-blk-length"), "{msg}");
}

/// An OP_RETURN output carrying `len` bytes of data
fn big_output(len: usize) -> TxOut {
    let mut s = vec![0x6a, 0x4e];
    s.extend_from_slice(&(len as u32).to_le_bytes());
    s.extend(std::iter::repeat_n(0x42u8, len));
    TxOut::new(Amount::ZERO, Script::from_bytes(s))
}

fn change(t: &TestChain, coin: Coin) -> TxOut {
    TxOut::new(coin.value - Amount::from_sat(COIN), t.pay.clone())
}
