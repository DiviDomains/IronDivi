// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! signrawtransaction refuses text that is no transaction as Divi Core does
//! (rpcrawtransaction.cpp:651-661): -8 "Transaction hex data must be
//! hexadecimal string (not '...')" for text that is not hex (IsHex("") is
//! false), -22 "TX decode failed" for hex that is no transaction.

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::json;
use std::sync::Arc;

#[test]
fn signrawtransaction_refuses_what_is_no_transaction_as_divid() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain, wallet);
    let refused = |hex: &str| {
        let error = server
            .handle_request(Request {
                jsonrpc: "1.0".to_string(),
                id: RequestId::Number(1),
                method: "signrawtransaction".to_string(),
                params: Params::Array(vec![json!(hex)]),
            })
            .error
            .expect("refused");
        (error.code, error.message)
    };
    assert_eq!(
        refused("xyz"),
        (
            -8,
            "Transaction hex data must be hexadecimal string (not 'xyz')".to_string()
        )
    );
    assert_eq!(
        refused(""),
        (
            -8,
            "Transaction hex data must be hexadecimal string (not '')".to_string()
        )
    );
    assert_eq!(refused("0011"), (-22, "TX decode failed".to_string()));
}
