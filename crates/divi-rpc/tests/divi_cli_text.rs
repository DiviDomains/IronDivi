// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Non-ASCII text from Divi Core's divi-cli: it writes each byte of the text as
//! a `\u00XX` escape, and divid's json_spirit reads each escape back into that
//! byte (json_spirit_reader_template.h:71-82), so an account named in another
//! script stays the text it is.

use divi_primitives::ChainMode;
use divi_rpc::RpcServer;
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::Value;
use std::sync::Arc;

#[test]
fn divi_clis_escaped_text_is_read_as_divid_reads_it() {
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
    let result = |body: String| -> Value {
        let (_, reply) = server.handle_http_body(&body);
        serde_json::from_str::<Value>(&reply).unwrap()["result"].clone()
    };
    let address = result(r#"{"method":"getnewaddress","params":[],"id":1}"#.to_string());
    let address = address.as_str().unwrap();

    // "Z\u{fc}rich \u{2713}" as divi-cli sends it (divi-cli.cpp, json_spirit write_string)
    let escaped = r#"Z\u00C3\u00BCrich \u00E2\u009C\u0093"#;
    result(format!(
        r#"{{"method":"setaccount","params":["{address}","{escaped}"],"id":1}}"#
    ));
    assert_eq!(
        result(format!(
            r#"{{"method":"getaccount","params":["{address}"],"id":1}}"#
        )),
        Value::String("Z\u{fc}rich \u{2713}".to_string())
    );
    assert_eq!(
        result(format!(
            r#"{{"method":"getaddressesbyaccount","params":["{escaped}"],"id":1}}"#
        )),
        serde_json::json!([address])
    );
}
