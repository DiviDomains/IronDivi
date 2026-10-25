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

//! Wallet RPC cases found by scripts/wallet-gaps, against Divi Core 3.0.0
//! behaviour (rpcwallet.cpp, rpcserver.cpp).

use divi_primitives::ChainMode;
use divi_rpc::{Params, WalletRpc};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const PASS: &str = "correct horse battery staple";

fn p(v: Vec<Value>) -> Params {
    Params::Array(v)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn encrypted_rpc(path: &Path) -> WalletRpc {
    let db = Arc::new(
        WalletDb::create_persistent(
            path,
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    let rpc = WalletRpc::with_wallet(db);
    rpc.encrypt_wallet(&p(vec![json!(PASS)])).unwrap();
    rpc
}

fn unlocked_until(rpc: &WalletRpc) -> u64 {
    rpc.get_wallet_info(&Params::None).unwrap()["unlocked_until"]
        .as_u64()
        .unwrap()
}

/// As rpcserver.cpp ModifyWalletLockStateBriefly: an unlock with a timeout of 0
/// reports the time it was made (GetTime() + 0), and walletlock reports 0
#[test]
fn an_unlock_without_timeout_reports_its_time() {
    let dir = tempfile::tempdir().unwrap();
    let rpc = encrypted_rpc(&dir.path().join("w"));
    for staking_only in [false, true] {
        let before = now();
        rpc.wallet_passphrase(&p(vec![json!(PASS), json!(0), json!(staking_only)]))
            .unwrap();
        let until = unlocked_until(&rpc);
        assert!(
            until >= before && until <= now(),
            "staking_only {staking_only}: unlocked_until {until}, unlocked at {before}"
        );
        rpc.wallet_lock(&Params::None).unwrap();
        assert_eq!(unlocked_until(&rpc), 0);
    }
}
