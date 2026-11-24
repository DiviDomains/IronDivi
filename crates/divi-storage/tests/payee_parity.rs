// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Block value and special payees through `Chain::accept_block`, on one
//! regtest chain of signed PoS blocks, against Divi Core 3.0.0
//! (`CheckMintTotalsAndBlockPayees`, BlockConnectionService.cpp:77-98;
//! `IsBlockValueValid` / `HasValidPayees`, BlockIncentivesPopulator.cpp:156-197;
//! `BlockSubsidyProvider`, BlockSubsidyProvider.cpp:19-64):
//!
//! - a lottery block pays each of its parent's winners exactly (the first half
//!   of the cycle's pool, each other a tenth of that), with zero, one and
//!   several winners; with none the staker may keep the pool;
//! - a height that is both a treasury and a lottery block is a treasury block:
//!   exact treasury and charity outputs, no lottery outputs, no lottery pool in
//!   the mint limit;
//! - the mint limit follows the subsidy halving (regtest interval 100) on
//!   each side of the boundary, and a treasury block straddling it is paid
//!   from the earlier cycle's weights.
//!
//! The chain's blocks are timed in 2018, before DeprecateMasternodes, and no
//! masternode exists: Divi Core's `HasValidMasternodePayee` accepts these
//! blocks (no masternode sync, and no payee with 6 votes); irondivid has no
//! vote-based check (see docs/security-performance-remediation-ledger.md).

mod common;

use common::*;
use divi_crypto::{compute_block_hash, compute_merkle_root, SecretKey};
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_storage::BlockIndex;
use std::collections::VecDeque;

/// Divi Core's regtest constants (chainparams.cpp; SuperblockHeightValidator)
const LOTTERY_POOL: i64 = 50 * 10 * COIN;
const BIG: i64 = LOTTERY_POOL / 2;
const SMALL: i64 = BIG / 10;
const DEPRECATE_MASTERNODES_TIME: u32 = 1_692_792_000;

struct Staker {
    key: SecretKey,
    pay: Script,
    coin: Coin,
}

impl Staker {
    fn new(seed: u8) -> Self {
        let key = SecretKey::from_bytes(&[seed; 32]).unwrap();
        let pay = Script::new_p2pkh(key.public_key().pubkey_hash().as_bytes());
        let coin = Coin {
            outpoint: OutPoint::new(divi_primitives::hash::Hash256::zero(), 0),
            value: Amount::ZERO,
            height: 0,
        };
        Staker { key, pay, coin }
    }
}

/// A signed PoS block on `parent` staking `kernel` of `key`'s P2PKH script
fn pos_block_of(
    t: &TestChain,
    parent: &BlockIndex,
    kernel: Coin,
    key: &SecretKey,
    pay: &Script,
    edit: impl FnOnce(&mut Transaction),
) -> Block {
    let height = parent.height + 1;
    let mut coinstake = Transaction {
        version: 1,
        vin: vec![TxIn::new(kernel.outpoint, Script::new(), 0xffff_ffff)],
        vout: vec![
            TxOut::new(Amount::ZERO, Script::default()),
            TxOut::new(kernel.value + TestChain::stake_reward(height), pay.clone()),
        ],
        lock_time: 0,
    };
    edit(&mut coinstake);
    sign_input(&mut coinstake, 0, pay, kernel.value, key);
    let marker = t.coinbase(height, vec![TxOut::new(Amount::ZERO, Script::default())]);
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = parent.hash;
    block.header.time = parent.time + 60;
    block.header.bits = REGTEST_BITS;
    block.transactions = vec![marker, coinstake];
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    let hash = compute_block_hash(&block.header);
    block.block_sig = divi_crypto::sign_hash_recoverable(key, hash.as_bytes())
        .unwrap()
        .to_compact_with_recovery()
        .to_vec();
    block
}

struct Run {
    t: TestChain,
    /// Our own small coins, oldest first: none of them buys a lottery ticket
    pool: VecDeque<Coin>,
}

impl Run {
    /// A block of ours on the tip, from the oldest coin, with `edit` applied
    fn ours(&self, edit: impl FnOnce(&mut Transaction)) -> Block {
        let tip = self.t.tip();
        let kernel = *self.pool.front().expect("a coin to stake");
        pos_block_of(&self.t, &tip, kernel, &self.t.key, &self.t.pay, edit)
    }

    /// Accept one of our blocks; its stake goes to the back of the pool
    fn accept_ours(&mut self, block: Block) {
        let height = self.t.tip().height + 1;
        self.t.chain.accept_block(block.clone()).unwrap();
        assert_eq!(self.t.tip().height, height);
        self.pool.pop_front();
        self.pool.push_back(TestChain::stake_of(&block, height));
    }

    fn extend_ours(&mut self, to_height: u32) {
        while self.t.tip().height < to_height {
            let block = self.ours(|_| {});
            self.accept_ours(block);
        }
    }

    /// A block staked by `s` on the tip; `s.coin` becomes its stake
    fn accept_staker(&self, s: &mut Staker) {
        let tip = self.t.tip();
        let block = pos_block_of(&self.t, &tip, s.coin, &s.key, &s.pay, |_| {});
        self.t.chain.accept_block(block.clone()).unwrap();
        assert_eq!(self.t.tip().height, tip.height + 1);
        s.coin = TestChain::stake_of(&block, tip.height + 1);
    }

    /// The block is refused for `what`, with Divi Core's score, and the tip
    /// does not move
    fn refuse(&self, block: Block, what: &str, score: u32) {
        let height = self.t.tip().height;
        let err = self.t.chain.accept_block(block).expect_err(what);
        assert!(err.to_string().contains(what), "{what}: {err}");
        assert_eq!(err.misbehaviour_score(), score, "{what}: {err}");
        assert_eq!(self.t.tip().height, height);
    }

    /// The scripts of the tip's lottery winners, in payment order
    fn winners(&self) -> Vec<Script> {
        self.t
            .tip()
            .lottery_winners
            .coinstakes
            .iter()
            .map(|c| c.script_pubkey.clone())
            .collect()
    }
}

fn pay(script: &Script, sat: i64) -> TxOut {
    TxOut::new(Amount::from_sat(sat), script.clone())
}

fn lottery_outputs(winners: &[Script]) -> Vec<TxOut> {
    winners
        .iter()
        .enumerate()
        .map(|(i, w)| pay(w, if i == 0 { BIG } else { SMALL }))
        .collect()
}

#[test]
fn block_value_and_special_payees_match_divi_core_through_connection() {
    let t = TestChain::new(regtest());
    let mut stakers = [Staker::new(0x51), Staker::new(0x52), Staker::new(0x53)];
    let coins = t.extend_pow(59);

    // Height 60: three coins of 11,249 DIVI, one per staker, each worth a
    // lottery ticket (more than spork 16's default 10,000 DIVI)
    let tip = t.tip();
    let mut funding = Vec::new();
    for (n, s) in stakers.iter().enumerate() {
        let inputs = &coins[n * 9..n * 9 + 9];
        let total = inputs.iter().map(|c| c.value.as_sat()).sum::<i64>();
        let mut tx = Transaction {
            version: 1,
            vin: inputs
                .iter()
                .map(|c| TxIn::new(c.outpoint, Script::new(), 0xffff_ffff))
                .collect(),
            vout: vec![pay(&s.pay, total - COIN)],
            lock_time: 0,
        };
        for (i, c) in inputs.iter().enumerate() {
            sign_input(&mut tx, i, &t.pay, c.value, &t.key);
        }
        funding.push(tx);
    }
    let block = t.pow_block(&tip, Amount::from_sat(1250 * COIN), funding.clone());
    t.chain.accept_block(block).unwrap();
    for (s, tx) in stakers.iter_mut().zip(&funding) {
        s.coin = Coin {
            outpoint: OutPoint::new(tx.txid(), 0),
            value: tx.vout[0].value,
            height: 60,
        };
    }
    let mut pool: VecDeque<Coin> = coins[27..].iter().copied().collect();
    pool.extend(t.extend_pow(40));
    assert_eq!(t.tip().height, 100);
    let mut run = Run { t, pool };

    // ---- Lottery cycle 101-110: three winners ----
    run.extend_ours(101);
    for s in stakers.iter_mut() {
        run.accept_staker(s);
    }
    run.extend_ours(109);
    assert!(run.t.tip().time < DEPRECATE_MASTERNODES_TIME);
    let winners = run.winners();
    let mut expected: Vec<Script> = stakers.iter().map(|s| s.pay.clone()).collect();
    let mut sorted = winners.clone();
    sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    expected.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(sorted, expected, "each staker holds one ticket");

    // Block 110 (lottery): every winner, exactly; the pool counts in the limit
    run.refuse(run.ours(|_| {}), "missing payment for winner 0", 0);
    let mut short = lottery_outputs(&winners);
    short[2].value = Amount::from_sat(SMALL - 1);
    run.refuse(
        run.ours(|cs| cs.vout.extend(short)),
        "missing payment for winner 2",
        0,
    );
    let mut swapped = lottery_outputs(&winners);
    swapped[0].value = Amount::from_sat(SMALL);
    swapped[1].value = Amount::from_sat(BIG);
    run.refuse(
        run.ours(|cs| cs.vout.extend(swapped)),
        "missing payment for winner 0",
        0,
    );
    let block = run.ours(|cs| cs.vout.extend(lottery_outputs(&winners)));
    run.accept_ours(block);
    assert!(
        run.winners().is_empty(),
        "a lottery block starts a new cycle"
    );

    // ---- Cycle 111-120: no ticket, no winner ----
    run.extend_ours(119);
    assert!(run.winners().is_empty());
    // With no winner the staker may take the pool, as Core's limit allows
    // (IsValidLotteryPayment is true for no winners), but not a satoshi more
    let pool = Amount::from_sat(LOTTERY_POOL);
    run.refuse(
        run.ours(|cs| cs.vout[1].value += pool + Amount::from_sat(1)),
        "bad-cb-amount",
        100,
    );
    let block = run.ours(|cs| cs.vout[1].value += pool);
    run.accept_ours(block);

    // ---- Cycle 121-130: one winner ----
    run.extend_ours(121);
    run.accept_staker(&mut stakers[0]);
    run.extend_ours(129);
    let winners = run.winners();
    assert_eq!(winners, vec![stakers[0].pay.clone()]);
    run.refuse(run.ours(|_| {}), "missing payment for winner 0", 0);
    run.refuse(
        run.ours(|cs| cs.vout.push(pay(&winners[0], SMALL))),
        "missing payment for winner 0",
        0,
    );
    let block = run.ours(|cs| cs.vout.push(pay(&winners[0], BIG)));
    run.accept_ours(block);

    // ---- Block 150: treasury and lottery height, treasury takes precedence ----
    run.extend_ours(141);
    run.accept_staker(&mut stakers[1]);
    run.accept_staker(&mut stakers[2]);
    run.extend_ours(149);
    let winners = run.winners();
    assert_eq!(winners.len(), 2, "two tickets in cycle 141-149");
    let due = run
        .t
        .chain
        .treasury_payments_due(150)
        .expect("150 is a treasury block");
    // BlockSubsidyProvider: weight 0 for block 100's rewards, 50 for block 150's
    // (1250 - 50 lottery = 1200; 16% and 1% of it, for 50 blocks)
    assert_eq!(due.treasury.1, Amount::from_divi(9600));
    assert_eq!(due.charity.1, Amount::from_divi(600));
    let treasury = |cs: &mut Transaction, t_sat: i64, c_sat: i64| {
        cs.vout.push(pay(&due.treasury.0, t_sat));
        cs.vout.push(pay(&due.charity.0, c_sat));
    };
    let (t150, c150) = (due.treasury.1.as_sat(), due.charity.1.as_sat());
    run.refuse(
        run.ours(|cs| cs.vout.extend(lottery_outputs(&winners))),
        "does not pay the treasury",
        0,
    );
    run.refuse(
        run.ours(|cs| treasury(cs, t150 - 1, c150)),
        "does not pay the treasury",
        0,
    );
    run.refuse(
        run.ours(|cs| treasury(cs, t150, c150 + 1)),
        "bad-cb-amount",
        100,
    );
    // The lottery pool is not part of a treasury block's limit
    run.refuse(
        run.ours(|cs| {
            treasury(cs, t150, c150);
            cs.vout[1].value += pool;
        }),
        "bad-cb-amount",
        100,
    );
    let block = run.ours(|cs| treasury(cs, t150, c150));
    run.accept_ours(block);
    assert!(
        run.winners().is_empty(),
        "cycle 141-149's winners are not paid"
    );

    // ---- Halving boundary at 200 (regtest interval 100) ----
    let reward = |h| TestChain::stake_reward(h);
    assert_eq!(reward(199), Amount::from_divi(996));
    assert_eq!(reward(200), Amount::from_divi(913));
    run.extend_ours(198);
    run.refuse(
        run.ours(|cs| cs.vout[1].value += Amount::from_sat(1)),
        "bad-cb-amount",
        100,
    );
    let block = run.ours(|_| {});
    run.accept_ours(block);

    // 200 is a treasury block straddling the halving: Core weights block 150's
    // rewards by 2*100 - 150 = 50 and block 200's by 0, so it still pays 9600
    // and 600 DIVI, not 50 x the post-halving 176 and 11
    let due = run
        .t
        .chain
        .treasury_payments_due(200)
        .expect("200 is a treasury block");
    assert_eq!(due.treasury.1, Amount::from_divi(9600));
    assert_eq!(due.charity.1, Amount::from_divi(600));
    let (t200, c200) = (due.treasury.1.as_sat(), due.charity.1.as_sat());
    let treasury = |cs: &mut Transaction, t_sat: i64, c_sat: i64| {
        cs.vout.push(pay(&due.treasury.0, t_sat));
        cs.vout.push(pay(&due.charity.0, c_sat));
    };
    run.refuse(
        run.ours(|cs| treasury(cs, 8800 * COIN, 550 * COIN)),
        "does not pay the treasury",
        0,
    );
    run.refuse(
        run.ours(|cs| {
            treasury(cs, t200, c200);
            cs.vout[1].value += Amount::from_sat(1);
        }),
        "bad-cb-amount",
        100,
    );
    let block = run.ours(|cs| treasury(cs, t200, c200));
    run.accept_ours(block);

    // 201: the halved limit; the pre-halving claim is refused
    run.refuse(
        run.ours(|cs| cs.vout[1].value += reward(199) - reward(201)),
        "bad-cb-amount",
        100,
    );
    let block = run.ours(|_| {});
    run.accept_ours(block);
    assert_eq!(run.t.tip().height, 201);
    assert!(run.t.tip().time < DEPRECATE_MASTERNODES_TIME);
}
