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

/// hdmasterkeyid and hdchainid are public; they must survive lock and a restart
/// of an encrypted (locked) wallet
#[test]
fn hd_ids_are_kept_while_locked_and_after_restart() {
    use divi_primitives::ChainMode;
    use divi_wallet::{HdWallet, WalletDb};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w");
    let (master_id, chain_id) = {
        let wallet = WalletDb::create_persistent(
            &path,
            Network::Testnet,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap();
        let ids = (wallet.hd_master_key_id(), wallet.get_hd_chain_id());
        assert_eq!(ids.0.len(), 40);
        assert!(ids.1.is_some());

        wallet.encrypt_wallet("pw").unwrap();
        assert!(wallet.is_locked());
        assert_eq!(wallet.hd_master_key_id(), ids.0, "empty while locked");
        assert_eq!(wallet.get_hd_chain_id(), ids.1);
        wallet.unlock("pw", 0).unwrap();
        wallet.lock();
        assert_eq!(wallet.hd_master_key_id(), ids.0, "empty after walletlock");
        ids
    };

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert!(wallet.is_locked());
    assert_eq!(wallet.hd_master_key_id(), master_id, "empty after restart");
    assert_eq!(wallet.get_hd_chain_id(), chain_id);
}
