// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Regressions for send outputs and wallet unlock state.
//! Only APIs that older trees also have are used, so these run there too.

use divi_primitives::transaction::OutPoint;
use divi_primitives::{amount::Amount, hash::Hash160, hash::Hash256, script::Script};
use divi_wallet::{Address, Network, TransactionBuilder};

/// A payment to a P2SH address must use a P2SH script; a P2PKH script over the
/// script hash pays a key nobody has.
#[test]
fn p2sh_address_is_paid_with_p2sh_script() {
    let hash = Hash160::from_bytes([0x5a; 20]);
    for network in [Network::Mainnet, Network::Testnet] {
        let p2sh = Address::p2sh(hash, network);
        let p2pkh = Address::from_pubkey_hash(hash, network);
        let (tx, _) = TransactionBuilder::new()
            .add_input(
                OutPoint::new(Hash256::from_bytes([1; 32]), 0),
                Script::new(),
            )
            .add_output_to_address(Amount::from_sat(100_000), &p2sh)
            .add_output_to_address(Amount::from_sat(100_000), &p2pkh)
            .build();
        assert_eq!(tx.vout[0].script_pubkey, Script::new_p2sh(&[0x5a; 20]));
        assert_eq!(tx.vout[1].script_pubkey, Script::new_p2pkh(&[0x5a; 20]));
    }
}
