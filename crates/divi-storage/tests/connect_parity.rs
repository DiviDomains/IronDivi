// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Connecting a block whose transactions spend each other's outputs: the coins
//! found, the undo data written, and which refusal comes first when a block
//! breaks more than one rule. Only the public API is used, so the same file
//! runs against any earlier version to show the results are unchanged.

mod common;

use common::*;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_storage::Utxo;

fn state(t: &TestChain) -> String {
    divi_storage::snapshot::compute_state_hash(&t.db, &t.chain, t.tip().height).unwrap()
}

fn coin_of(tx: &Transaction, vout: u32, height: u32) -> Coin {
    Coin {
        outpoint: OutPoint::new(tx.txid(), vout),
        value: tx.vout[vout as usize].value,
        height,
    }
}

fn utxo(t: &TestChain, outpoint: &OutPoint) -> Option<Utxo> {
    t.chain.get_utxo(outpoint).unwrap()
}

/// Pushes `data` as one script element
fn push(data: &[u8]) -> Vec<u8> {
    let mut out = match data.len() {
        n @ 0..=75 => vec![n as u8],
        n @ 76..=255 => vec![0x4c, n as u8],
        n => vec![0x4d, (n & 0xff) as u8, (n >> 8) as u8],
    };
    out.extend_from_slice(data);
    out
}

fn p2sh_of(redeem: &[u8]) -> Script {
    Script::new_p2sh(divi_crypto::hash160(redeem).as_bytes())
}

/// A block on the tip with `txs` after its coinbase, mined
fn block_with(t: &TestChain, txs: Vec<Transaction>) -> Block {
    t.pow_block(&t.tip(), Amount::from_sat(1250 * COIN), txs)
}

/// Chains of spends, fan-outs, inputs from this block and the UTXO set
/// together, and a P2SH output spent in the block that made it: the coins
/// connected are those a transaction-by-transaction walk expects, a
/// disconnect restores the UTXO set exactly, and a reconnect returns to the
/// same state
#[test]
fn intra_block_spends_connect_disconnect_and_reconnect_alike() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(3);
    t.extend_pow(20);
    let parent = t.tip();
    let before = state(&t);
    let h = parent.height + 1;
    let out = |sat: i64| TxOut::new(Amount::from_sat(sat), t.pay.clone());

    // Coin 0 fans out to 150 outputs; each output is spent again in this
    // block by a chain of one to four transactions
    let fan = t.spend(coins[0], (0..150).map(|_| out(8 * COIN)).collect());
    let mut txs = vec![fan.clone()];
    let mut spent = vec![coins[0].outpoint];
    let mut unspent: Vec<(OutPoint, Amount)> = Vec::new();
    for i in 0..150u32 {
        let mut prev = coin_of(&fan, i, h);
        for _ in 0..(1 + i % 4) {
            spent.push(prev.outpoint);
            let tx = t.spend(prev, vec![out(prev.value.as_sat() - 1_000)]);
            prev = coin_of(&tx, 0, h);
            txs.push(tx);
        }
        unspent.push((prev.outpoint, prev.value));
    }
    // An input from this block and one from the UTXO set in one transaction
    let (last, last_value) = unspent.pop().unwrap();
    spent.extend([last, coins[1].outpoint]);
    let mut mixed = Transaction {
        version: 1,
        vin: vec![
            TxIn::new(last, Script::new(), 0xffff_ffff),
            TxIn::new(coins[1].outpoint, Script::new(), 0xffff_ffff),
        ],
        vout: vec![
            out(last_value.as_sat()),
            TxOut::new(Amount::from_sat(1_000 * COIN), p2sh_of(&[0x51])),
        ],
        lock_time: 0,
    };
    sign_input(&mut mixed, 0, &t.pay, last_value, &t.key);
    sign_input(&mut mixed, 1, &t.pay, coins[1].value, &t.key);
    txs.push(mixed.clone());
    unspent.push((OutPoint::new(mixed.txid(), 0), last_value));
    // Its P2SH output (redeem script OP_1) is spent in the same block
    let redeem = Transaction {
        version: 1,
        vin: vec![TxIn::new(
            OutPoint::new(mixed.txid(), 1),
            Script::from_bytes(push(&[0x51])),
            0xffff_ffff,
        )],
        vout: vec![out(999 * COIN)],
        lock_time: 0,
    };
    spent.push(OutPoint::new(mixed.txid(), 1));
    unspent.push((
        OutPoint::new(redeem.txid(), 0),
        Amount::from_sat(999 * COIN),
    ));
    txs.push(redeem);
    let n_txs = txs.len();

    let block = block_with(&t, txs);
    let hash = t.chain.accept_block(block).unwrap().hash;
    assert_eq!(t.tip().hash, hash);
    assert_eq!(t.tip().n_tx as usize, n_txs + 1);
    let after = state(&t);
    for outpoint in &spent {
        assert_eq!(utxo(&t, outpoint), None, "{outpoint:?} still unspent");
    }
    for (outpoint, value) in &unspent {
        let coin = utxo(&t, outpoint).expect("created and unspent");
        assert_eq!((coin.value, coin.height), (*value, h));
        assert!(!coin.is_coinbase && !coin.is_coinstake);
        assert_eq!(coin.script_pubkey, t.pay);
    }
    println!(
        "PARITY connect txs={} block={hash} state={after}",
        n_txs + 1
    );

    // Disconnect: the undo data gives back exactly the coins spent
    t.chain.invalidate_block(&hash).unwrap();
    assert_eq!(t.tip().hash, parent.hash);
    assert_eq!(state(&t), before);
    for coin in &coins[..2] {
        let back = utxo(&t, &coin.outpoint).expect("restored");
        assert_eq!((back.value, back.height), (coin.value, coin.height));
        assert!(back.is_coinbase);
    }
    for (outpoint, _) in &unspent {
        assert_eq!(utxo(&t, outpoint), None);
    }

    // Reconnect
    t.chain.reconsider_block(&hash).unwrap();
    assert_eq!(t.tip().hash, hash);
    assert_eq!(state(&t), after);
}

/// A block that breaks several rules is refused for the one the base checked
/// first, with its exact text, and the tip and state do not move
#[test]
fn connect_refusals_come_in_the_same_order() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(4);
    t.extend_pow(20);
    let out = |sat: i64| TxOut::new(Amount::from_sat(sat), t.pay.clone());

    // 80 confirmed P2SH outputs whose redeem script has 520 sigops each:
    // spending all of them is 41,600 > 40,000 sigops
    let heavy_redeem = vec![0xacu8; 520];
    let heavy = p2sh_of(&heavy_redeem);
    let fund = t.spend(
        coins[0],
        (0..80)
            .map(|_| TxOut::new(Amount::from_sat(10 * COIN), heavy.clone()))
            .collect(),
    );
    let fund_txid = fund.txid();
    t.chain
        .accept_block(block_with(&t, vec![fund.clone()]))
        .unwrap();
    let tip = t.tip();
    let settled = state(&t);
    let h = tip.height + 1;

    let heavy_spend = |prevouts: Vec<OutPoint>| Transaction {
        version: 1,
        vin: prevouts
            .into_iter()
            .map(|op| TxIn::new(op, Script::from_bytes(push(&heavy_redeem)), 0xffff_ffff))
            .collect(),
        vout: vec![out(COIN)],
        lock_time: 0,
    };
    let all_heavy = |txid: Hash256| (0..80).map(|i| OutPoint::new(txid, i)).collect::<Vec<_>>();
    let missing = OutPoint::new(Hash256::from_bytes([0xee; 32]), 7);
    let missing_coin = Coin {
        outpoint: missing,
        value: Amount::from_sat(COIN),
        height: 1,
    };
    let refuse = |case: &str, txs: Vec<Transaction>| {
        let msg = err_text(t.chain.accept_block(block_with(&t, txs)));
        println!("PARITY {case}: {msg}");
        assert_eq!(t.tip().hash, tip.hash, "{case}");
        msg
    };
    let refuse_block = |case: &str, block: Block| {
        let msg = err_text(t.chain.accept_block(block));
        println!("PARITY {case}: {msg}");
        assert_eq!(t.tip().hash, tip.hash, "{case}");
        msg
    };
    let sigops = "invalid block: bad-blk-sigops: too many sigops";

    // The sigops of all of a transaction's inputs are counted before any of
    // them is looked for: a missing first input does not come first
    let mut ins = vec![missing];
    ins.extend(all_heavy(fund_txid));
    assert_eq!(
        refuse("sigops-before-missing", vec![heavy_spend(ins)]),
        sigops
    );

    // A missing input of an earlier transaction comes before a later
    // transaction's sigops
    let orphan = t.spend(missing_coin, vec![out(COIN / 2)]);
    assert_eq!(
        refuse(
            "missing-before-later-sigops",
            vec![orphan, heavy_spend(all_heavy(fund_txid))]
        ),
        format!("UTXO not found: {}:{}", missing.txid, missing.vout)
    );

    // Sigops of P2SH outputs made earlier in the same block count too
    let fund2 = t.spend(
        coins[1],
        (0..80)
            .map(|_| TxOut::new(Amount::from_sat(10 * COIN), heavy.clone()))
            .collect(),
    );
    let fund2_txid = fund2.txid();
    assert_eq!(
        refuse(
            "in-block-p2sh-sigops",
            vec![fund2, heavy_spend(all_heavy(fund2_txid))]
        ),
        sigops
    );

    // An output of a later transaction of the block is not there yet
    let later = t.spend(coins[2], vec![out(1_000 * COIN)]);
    let early = t.spend(coin_of(&later, 0, h), vec![out(999 * COIN)]);
    assert_eq!(
        refuse("spends-a-later-output", vec![early, later.clone()]),
        format!("UTXO not found: {}:0", later.txid())
    );

    // An output made in the block and spent twice in it: CheckBlock's
    // duplicate-input check refuses it before the block is connected
    let first = t.spend(coin_of(&later, 0, h), vec![out(999 * COIN)]);
    let second = t.spend(coin_of(&later, 0, h), vec![out(998 * COIN)]);
    assert_eq!(
        refuse("in-block-double-spend", vec![later.clone(), first, second]),
        format!(
            "invalid block: bad-txns-inputs-duplicate: {}:0",
            later.txid()
        )
    );

    // An output made in the block spent for more than it holds
    let greedy = t.spend(coin_of(&later, 0, h), vec![out(1_001 * COIN)]);
    let greedy_txid = greedy.txid();
    assert_eq!(
        refuse("in-block-value-below-out", vec![later.clone(), greedy]),
        format!(
            "invalid block: bad-txns-in-belowout: tx {} value in ({}) < value out ({})",
            greedy_txid,
            Amount::from_sat(1_000 * COIN),
            Amount::from_sat(1_001 * COIN)
        )
    );

    // The block's own coinbase is found in the block, and is immature
    let mut b = t.pow_block_raw(&tip, Amount::from_sat(1250 * COIN), vec![]);
    let cb = coin_of(&b.transactions[0], 0, h);
    let early_cb = t.spend(cb, vec![out(1_000 * COIN)]);
    let early_cb_txid = early_cb.txid();
    b.transactions.push(early_cb);
    b.header.merkle_root = divi_crypto::compute_merkle_root(&b.transactions);
    mine(&mut b);
    assert_eq!(
        refuse_block("in-block-coinbase-immature", b),
        format!(
            "invalid block: bad-txns-premature-spend-of-coinbase: tried to spend coinbase at depth 0, coinstake=false (tx {early_cb_txid})"
        )
    );

    // BIP30: a transaction whose id still has unspent outputs, here the
    // funding transaction again, before any of its inputs is looked at
    assert_eq!(
        refuse("bip30", vec![fund]),
        format!("invalid block: bad-txns-BIP30: tried to overwrite transaction ({fund_txid})")
    );

    // Nothing of the refused blocks stayed; a valid block still connects
    assert_eq!(state(&t), settled);
    let next = t.spend(coins[3], vec![out(1_249 * COIN)]);
    let ok = t.spend(coin_of(&next, 0, h), vec![out(1_248 * COIN)]);
    t.chain
        .accept_block(block_with(&t, vec![next, ok]))
        .unwrap();
    assert_eq!(t.tip().height, h);
}
