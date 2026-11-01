// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! sendrawtransaction of text that is no transaction: Divi Core's
//! DecodeHexTx fails and the reply is -22 "TX decode failed", nothing more
//! (rpcrawtransaction.cpp:850-852).

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::json;
use std::sync::Arc;

#[test]
fn sendrawtransaction_of_no_transaction_says_tx_decode_failed() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let server = RpcServer::new(chain);
    for hex in ["0011", "", "xyz", "0100000000"] {
        let error = server
            .handle_request(Request {
                jsonrpc: "1.0".to_string(),
                id: RequestId::Number(1),
                method: "sendrawtransaction".to_string(),
                params: Params::Array(vec![json!(hex)]),
            })
            .error
            .unwrap_or_else(|| panic!("{hex:?} was taken"));
        assert_eq!(
            (error.code, error.message.as_str()),
            (-22, "TX decode failed"),
            "{hex:?}"
        );
    }
}
