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

//! getaddressdeltas / getaddresstxids check each address against the node's
//! network first, as Divi Core's getAddressesFromParams (rpcmisc.cpp).

use divi_primitives::{hash::Hash160, ChainMode};
use divi_rpc::{BlockchainRpc, Params};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, Network};
use serde_json::json;
use std::sync::Arc;

fn rpc() -> (tempfile::TempDir, BlockchainRpc) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Chain::new(
        db,
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    (dir, BlockchainRpc::new(Arc::new(chain)))
}

fn message(r: Result<serde_json::Value, divi_rpc::Error>) -> (i32, String) {
    match r {
        Err(divi_rpc::Error::Rpc(e)) => (e.code, e.message),
        other => panic!("expected an RPC error, got {:?}", other),
    }
}

#[test]
fn address_index_rpcs_refuse_other_network_addresses() {
    let (_dir, rpc) = rpc();
    let hash = Hash160::from_bytes([5; 20]);
    let mainnet = Address::from_pubkey_hash(hash, Network::Mainnet).to_base58();
    let testnet = Address::from_pubkey_hash(hash, Network::Regtest).to_base58();
    let invalid = (-5, "Invalid address".to_string());

    for params in [
        Params::Array(vec![json!(mainnet)]),
        Params::Array(vec![json!({ "addresses": [testnet, mainnet] })]),
        Params::Array(vec![json!("not an address")]),
    ] {
        assert_eq!(message(rpc.get_address_deltas(&params)), invalid);
        assert_eq!(message(rpc.get_address_txids(&params)), invalid);
    }

    // A valid address gets past the check to the index error
    let ok = Params::Array(vec![json!(testnet)]);
    assert_ne!(message(rpc.get_address_deltas(&ok)), invalid);
    assert_ne!(message(rpc.get_address_txids(&ok)), invalid);
}
