// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! What `getwalletinfo` counts after a reorganisation: Divi Core's `txcount` is
//! the size of its wallet map, which keeps a transaction whose block was
//! disconnected and that the new branch dropped (rpcwallet.cpp:2894-2906).

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::{Params, WalletRpc};
use divi_wallet::{HdWallet, Network, WalletDb};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

fn tx(prevouts: &[(Hash256, u32)], outputs: Vec<(i64, Script)>) -> Transaction {
    Transaction {
        version: 1,
        vin: prevouts
            .iter()
            .map(|(txid, vout)| TxIn {
                prevout: OutPoint {
                    txid: *txid,
                    vout: *vout,
                },
                script_sig: Script::default(),
                sequence: 0xffffffff,
            })
            .collect(),
        vout: outputs
            .into_iter()
            .map(|(v, script_pubkey)| TxOut {
                value: Amount::from_sat(v),
                script_pubkey,
            })
            .collect(),
        lock_time: 0,
    }
}

fn hash(height: u32, branch: u8) -> Hash256 {
    let mut b = [branch; 32];
    b[..4].copy_from_slice(&height.to_le_bytes());
    Hash256::from_bytes(b)
}

/// A payment whose block a reorganisation disconnects and that the new branch
/// does not mine again stays in the wallet, and in `txcount`
#[test]
fn txcount_keeps_a_payment_the_new_branch_dropped() {
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let address = wallet.new_receiving_address().unwrap();
    let pay = |tag: u8| {
        tx(
            &[(Hash256::from_bytes([tag; 32]), 0)],
            vec![(100 * COIN, Script::new_p2pkh(address.hash.as_bytes()))],
        )
    };
    let (kept, dropped) = (pay(1), pay(2));
    wallet.scan_block(hash(1, 0), 1, 1_001, std::slice::from_ref(&kept));
    wallet.scan_block(hash(2, 0), 2, 1_002, std::slice::from_ref(&dropped));
    let rpc = WalletRpc::with_wallet(wallet.clone());
    let count = |rpc: &WalletRpc| rpc.get_wallet_info(&Params::None).unwrap()["txcount"].clone();
    assert_eq!(count(&rpc), 2);

    wallet.handle_reorg(1);
    assert_eq!(
        count(&rpc),
        2,
        "the payment the new branch dropped is still held"
    );
}
