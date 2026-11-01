// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Every block's money supply, as Divi Core records it (`nMoneySupply`:
//! the previous block's plus every output minus every input spent,
//! TransactionInputChecker.cpp:79-80), also for a database whose blocks were
//! connected before the block index kept it.

mod common;

use common::*;
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::transaction::TxOut;
use divi_storage::Chain;
use std::sync::Arc;

#[test]
fn database_without_supplies_gets_them_back_at_the_tip() {
    let t = TestChain::new(regtest());
    let coins = t.extend_pow(25);
    // a spend paying a fee and 100 DIVI to an OP_META output, which stays in the supply
    let spend = t.spend(
        coins[0],
        vec![
            TxOut::new(Amount::from_sat(1000 * COIN), t.pay.clone()),
            TxOut::new(
                Amount::from_sat(100 * COIN),
                Script::from_bytes(vec![0x6a, 1, 1]),
            ),
        ],
    );
    let block = t.pow_block(&t.tip(), Amount::from_sat(1250 * COIN), vec![spend]);
    t.chain.accept_block(block).unwrap();
    t.extend_pow(2);

    let tip = t.tip();
    let supply_at = |h: u32| {
        t.index(&t.db.get_height_mapping(h).unwrap().unwrap())
            .money_supply
    };
    let recorded: Vec<Option<i64>> = (0..=tip.height).map(supply_at).collect();
    // 28 coinbases of 1250, less the 150 DIVI fee
    assert_eq!(recorded[28], Some((28 * 1250 - 150) * COIN));
    assert_eq!(t.db.utxo_value_total().unwrap(), recorded[28].unwrap());

    // the same database as a node that connected these blocks before the field existed
    for h in 1..=tip.height {
        let mut index = t.index(&t.db.get_height_mapping(h).unwrap().unwrap());
        index.money_supply = None;
        t.db.store_block_index_entry(&index).unwrap();
    }
    let reopened = Chain::new(Arc::clone(&t.db), regtest()).unwrap();
    assert_eq!(reopened.tip().unwrap().money_supply, recorded[28]);

    // disconnecting works each block's supply back to its parent
    // heights 28 and 27 (coinbase only), then 26 with the spend
    for h in (26..=28).rev() {
        let at = reopened.tip().unwrap();
        assert_eq!(at.height, h);
        reopened.invalidate_block(&at.hash).unwrap();
        let parent = reopened.tip().unwrap();
        assert_eq!(
            parent.money_supply,
            recorded[h as usize - 1],
            "height {}",
            h - 1
        );
        assert_eq!(
            reopened
                .get_block_index(&parent.hash)
                .unwrap()
                .unwrap()
                .money_supply,
            recorded[h as usize - 1]
        );
    }
}
