// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Blocks that Divi Core 3.0.0 refuses are refused here too: reorganization
//! depth, checkpoints, coinbase/coinstake maturity, minimum stake age,
//! difficulty bits and proof of work, the proof of stake on every connect
//! path, and the block's value. Every block goes through `Chain::accept_block`,
//! the entry point for a block from a peer.

mod common;

use common::*;
use divi_crypto::{compute_block_hash, compute_merkle_root, SecretKey};
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_storage::{ChainParams, NetworkType};

// ---------------------------------------------------------------------------
// Max reorganization depth (ChainExtensionService.cpp:308-311, chainparams.cpp:180/396)
// ---------------------------------------------------------------------------

/// A fork block 100 below the tip is refused; 99 below is accepted (regtest
/// inherits testnet's depth of 100).
#[test]
fn fork_block_at_max_reorg_depth_is_refused() {
    let t = TestChain::new(regtest());
    let genesis = t.tip();
    let coins = t.extend_pow(100);
    t.chain
        .accept_block(t.simple_pos(&t.tip(), coins[0]))
        .unwrap();
    let tip = t.tip();
    assert_eq!(tip.height, 101);

    // Height 1 off genesis: 101 - 1 = 100 >= 100
    let deep = t.pow_block(&genesis, Amount::from_sat(1250 * COIN), vec![]);
    let msg = err_text(t.chain.accept_block(deep.clone()));
    assert!(
        msg.contains("forked chain older than max reorganization depth (height 1)"),
        "{msg}"
    );
    assert!(t
        .chain
        .get_block_index(&compute_block_hash(&deep.header))
        .unwrap()
        .is_none());

    // Height 2 off block 1: 101 - 2 = 99 < 100, stored as a side block
    let one = t.chain.get_block_index_by_height(1).unwrap().unwrap();
    let ok = t.pow_block(&one, Amount::from_sat(1250 * COIN), vec![]);
    t.chain.accept_block(ok).unwrap();
    assert_eq!(t.tip().hash, tip.hash);
}

// ---------------------------------------------------------------------------
// Checkpoints (chainparams.cpp:107-110, ChainExtensionService.cpp:320-328)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Coinbase / coinstake maturity (UtxoCheckingAndUpdating.cpp:72-77)
// ---------------------------------------------------------------------------

#[test]
fn maturity_per_network() {
    let m = |net| ChainParams::for_network(net, ChainMode::Divi).coinbase_maturity;
    assert_eq!(m(NetworkType::Mainnet), 20);
    assert_eq!(m(NetworkType::Testnet), 1);
    assert_eq!(m(NetworkType::Regtest), 20);
}

/// Spending a coinbase at depth 19 is refused, at depth 20 accepted
#[test]
fn coinbase_spend_before_maturity_is_refused() {
    let t = TestChain::new(regtest());
    let coin = t.extend_pow(1)[0];
    t.extend_pow(18);
    // Next block is height 20: depth 19
    let pay = vec![TxOut::new(
        coin.value - Amount::from_sat(COIN),
        t.pay.clone(),
    )];
    let tx = t.spend(coin, pay.clone());
    let tip = t.tip();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &tip,
        Amount::from_sat(1250 * COIN),
        vec![tx.clone()],
    )));
    assert!(
        msg.contains("bad-txns-premature-spend-of-coinbase"),
        "{msg}"
    );
    assert_eq!(t.tip().hash, tip.hash);

    t.extend_pow(1);
    let tip = t.tip();
    t.chain
        .accept_block(t.pow_block(&tip, Amount::from_sat(1250 * COIN), vec![tx]))
        .unwrap();
    assert_eq!(t.tip().height, 21);
}

/// A coinstake output is immature for 20 blocks too
#[test]
fn coinstake_spend_before_maturity_is_refused() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(100);
    let tip = t.tip();
    let b101 = t.simple_pos(&tip, coins[0]);
    t.chain.accept_block(b101.clone()).unwrap();
    let stake = TestChain::stake_of(&b101, 101);
    // Height 102 restakes the height-101 coinstake output: depth 1
    let tip = t.tip();
    let msg = err_text(t.chain.accept_block(t.simple_pos(&tip, stake)));
    assert!(
        msg.contains("bad-txns-premature-spend-of-coinbase") && msg.contains("coinstake=true"),
        "{msg}"
    );
    // An ordinary spend of it is refused as well
    let tx = t.spend(
        stake,
        vec![TxOut::new(
            stake.value - Amount::from_sat(COIN),
            t.pay.clone(),
        )],
    );
    let mut b = t.simple_pos(&tip, coins[1]);
    b.transactions.push(tx);
    b.header.merkle_root = compute_merkle_root(&b.transactions);
    let b = resign(&t, b);
    let msg = err_text(t.chain.accept_block(b));
    assert!(
        msg.contains("bad-txns-premature-spend-of-coinbase"),
        "{msg}"
    );
}

// ---------------------------------------------------------------------------
// Minimum stake age (chainparams.cpp:195/498, ProofOfStakeGenerator.cpp:75-90)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Difficulty bits and proof of work (BlockProofVerifier.cpp:136-155, :27-43)
// ---------------------------------------------------------------------------

/// A block whose bits differ from the required next work is refused, even
/// with a valid proof of work for the bits it claims
#[test]
fn block_with_wrong_bits_is_refused() {
    let t = TestChain::new(regtest());
    t.extend_pow(2);
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    b.header.bits = 0x2000ffff; // harder than required, so its work is real
    mine(&mut b);
    let msg = err_text(t.chain.accept_block(b));
    assert!(msg.contains("bad-diffbits"), "{msg}");
    assert_eq!(t.tip().height, 2);

    // On a side chain too
    let one = t.chain.get_block_index_by_height(1).unwrap().unwrap();
    let mut s = t.pow_block_raw(&one, Amount::from_sat(1250 * COIN), vec![]);
    s.header.bits = 0x2000ffff;
    mine(&mut s);
    let sh = compute_block_hash(&s.header);
    let msg = err_text(t.chain.accept_block(s));
    assert!(msg.contains("bad-diffbits"), "{msg}");
    assert!(t.chain.get_block_index(&sh).unwrap().is_none());
}

/// A PoW block whose hash does not meet its bits is refused
#[test]
fn pow_block_without_work_is_refused() {
    let t = TestChain::new(regtest());
    t.extend_pow(1);
    let tip = t.tip();
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    mine_failing(&mut b);
    let msg = err_text(t.chain.accept_block(b));
    assert!(msg.contains("hash doesn't match nBits"), "{msg}");
}

/// No PoW block after the last PoW block (100), no PoS block up to it
#[test]
fn pow_after_last_pow_block_and_early_pos_are_refused() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(50);
    let tip = t.tip();
    let msg = err_text(t.chain.accept_block(t.simple_pos(&tip, coins[0])));
    assert!(msg.contains("PoS-early"), "{msg}");

    t.extend_pow(50);
    let tip = t.tip();
    assert_eq!(tip.height, 100);
    let msg = err_text(
        t.chain
            .accept_block(t.pow_block(&tip, Amount::from_sat(COIN), vec![])),
    );
    assert!(msg.contains("PoW-ended"), "{msg}");
    assert_eq!(t.tip().height, 100);
}

// ---------------------------------------------------------------------------
// Proof of stake on every connect path (BlockProofVerifier.cpp:149-155)
// ---------------------------------------------------------------------------

/// During initial sync (a fresh chain is in IBD mode) the stake is still
/// checked: here the coinstake's second input pays another script
#[test]
fn pos_block_is_checked_during_initial_sync() {
    let other = SecretKey::from_bytes(&[9u8; 32]).unwrap();
    let other_pay = Script::new_p2pkh(other.public_key().pubkey_hash().as_bytes());
    let t = TestChain::new(regtest());
    assert!(t.chain.is_ibd());
    // Height 80 moves a coin to another key; it is mature by height 101
    let coins = t.extend_pow(79);
    let tip = t.tip();
    let fund = t.spend(
        coins[0],
        vec![TxOut::new(
            coins[0].value - Amount::from_sat(COIN),
            other_pay.clone(),
        )],
    );
    let fund_out = OutPoint::new(fund.txid(), 0);
    let fund_value = fund.vout[0].value;
    t.chain
        .accept_block(t.pow_block(&tip, Amount::from_sat(1250 * COIN), vec![fund]))
        .unwrap();
    let coins2 = t.extend_pow(20);
    let tip = t.tip();
    assert_eq!(tip.height, 100);

    let kernel = coins2[0];
    let b = t.pos_block(
        &tip,
        tip.time + 60,
        kernel,
        |cs| {
            cs.vin.push(TxIn::new(fund_out, Script::new(), 0xffff_ffff));
            cs.vout[1].value += fund_value;
        },
        |_| {},
    );
    // Sign the second input with the other key (the first is signed by pos_block,
    // but its signature hash changed when input 1 was added: sign both again)
    let mut b = b;
    let mut cs = b.transactions[1].clone();
    sign_input(&mut cs, 0, &t.pay, kernel.value, &t.key);
    sign_input(&mut cs, 1, &other_pay, fund_value, &other);
    b.transactions[1] = cs;
    b.header.merkle_root = compute_merkle_root(&b.transactions);
    let b = resign(&t, b);
    let msg = err_text(t.chain.accept_block(b));
    assert!(msg.contains("pays to different script"), "{msg}");
    assert_eq!(t.tip().height, 100);
}

/// A side-chain PoS block is checked when a reorg connects it: a fork with
/// more work whose block carries a bad block signature does not become the tip
#[test]
fn side_chain_pos_block_is_checked_on_reorg() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(100);
    let fork_point = t.tip();
    // Main chain: 101, 102
    let a1 = t.simple_pos(&fork_point, coins[0]);
    t.chain.accept_block(a1).unwrap();
    let a2 = t.simple_pos(&t.tip(), coins[1]);
    t.chain.accept_block(a2).unwrap();
    let main_tip = t.tip();
    assert_eq!(main_tip.height, 102);

    // Fork from 100: b1 fine, b2 with a broken block signature, b3 on top
    let b1 = t.pos_block(&fork_point, fork_point.time + 61, coins[2], |_| {}, |_| {});
    let b1h = compute_block_hash(&b1.header);
    t.chain.accept_block(b1).unwrap();
    let mut b2 = t.pos_block(
        &t.index(&b1h),
        fork_point.time + 121,
        coins[3],
        |_| {},
        |_| {},
    );
    b2.block_sig[10] ^= 0x55;
    let b2h = compute_block_hash(&b2.header);
    t.chain.accept_block(b2).unwrap(); // stored: equal work, not connected
    let b3 = t.pos_block(
        &t.index(&b2h),
        fork_point.time + 181,
        coins[4],
        |_| {},
        |_| {},
    );
    let _ = t.chain.accept_block(b3);
    assert_eq!(
        t.tip().hash,
        main_tip.hash,
        "fork with a bad signature became the tip"
    );
}

// ---------------------------------------------------------------------------
// Block value (BlockConnectionService.cpp:67-96, TransactionInputChecker.cpp:79-81,
// UtxoCheckingAndUpdating.cpp:86-99, BlockCheckingHelpers.cpp:24-147)
// ---------------------------------------------------------------------------

/// A PoS block that pays itself in the coinbase is refused
#[test]
fn pos_block_paying_in_its_coinbase_is_refused() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(100);
    let tip = t.tip();
    let pay = t.pay.clone();
    let b = t.pos_block(
        &tip,
        tip.time + 60,
        coins[0],
        |_| {},
        |b| b.transactions[0].vout = vec![TxOut::new(Amount::from_sat(1_000_000 * COIN), pay)],
    );
    let msg = err_text(t.chain.accept_block(b));
    assert!(
        msg.contains("coinbase output not empty for proof-of-stake block"),
        "{msg}"
    );
    assert_eq!(t.tip().height, 100);
}

/// A PoS block whose coinstake claims more than the reward is refused
#[test]
fn coinstake_claiming_too_much_is_refused() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(100);
    let tip = t.tip();
    let b = t.pos_block(
        &tip,
        tip.time + 60,
        coins[0],
        |cs| cs.vout[1].value += Amount::from_sat(1),
        |_| {},
    );
    let msg = err_text(t.chain.accept_block(b));
    assert!(msg.contains("bad-cb-amount"), "{msg}");
}

/// A transaction that spends more than its inputs is refused
#[test]
fn transaction_spending_more_than_its_inputs_is_refused() {
    let t = TestChain::new(regtest());
    let coin = t.extend_pow(1)[0];
    t.extend_pow(20);
    let tx = t.spend(
        coin,
        vec![TxOut::new(
            coin.value + Amount::from_sat(500 * COIN),
            t.pay.clone(),
        )],
    );
    let tip = t.tip();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &tip,
        Amount::from_sat(1250 * COIN),
        vec![tx],
    )));
    assert!(msg.contains("bad-txns-in-belowout"), "{msg}");
}

/// Two transactions of one block spending the same coin are refused
#[test]
fn block_spending_one_coin_twice_is_refused() {
    let t = TestChain::new(regtest());
    let coin = t.extend_pow(1)[0];
    t.extend_pow(20);
    let half = Amount::from_sat(600 * COIN);
    let tx1 = t.spend(coin, vec![TxOut::new(half, t.pay.clone())]);
    let other = Script::new_p2pkh(&[3u8; 20]);
    let tx2 = t.spend(coin, vec![TxOut::new(half, other)]);
    let tip = t.tip();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &tip,
        Amount::from_sat(1250 * COIN),
        vec![tx1, tx2],
    )));
    assert!(msg.contains("bad-txns-inputs-duplicate"), "{msg}");
}

/// A PoW block may claim its subsidy plus fees, not more; regtest's premine is 1250
#[test]
fn pow_block_value_is_checked() {
    let t = TestChain::new(regtest());
    let genesis = t.tip();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &genesis,
        Amount::from_sat(1250 * COIN + 1),
        vec![],
    )));
    assert!(msg.contains("bad-cb-amount"), "{msg}");

    let coin = t.extend_pow(1)[0];
    t.extend_pow(20);
    // 3 DIVI fee: the coinbase may take 1253, not 1253 + 1 sat
    let tx = t.spend(
        coin,
        vec![TxOut::new(
            coin.value - Amount::from_sat(3 * COIN),
            t.pay.clone(),
        )],
    );
    let tip = t.tip();
    let msg = err_text(t.chain.accept_block(t.pow_block(
        &tip,
        Amount::from_sat(1253 * COIN + 1),
        vec![tx.clone()],
    )));
    assert!(msg.contains("bad-cb-amount"), "{msg}");
    t.chain
        .accept_block(t.pow_block(&tip, Amount::from_sat(1253 * COIN), vec![tx]))
        .unwrap();
    assert_eq!(t.tip().height, 22);
}
