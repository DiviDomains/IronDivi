// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! `backupwallet` at a place that is not a wallet backup: refused with
//! Divi Core's reply (rpcwallet.cpp:2538) and the place left as it was,
//! never mixed with the wallet's files.

use divi_primitives::ChainMode;
use divi_rpc::{Error, Params, WalletRpc};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

fn wallet_rpc(dir: &Path) -> WalletRpc {
    let wallet = WalletDb::create_persistent(
        &dir.join("wallet"),
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    )
    .unwrap();
    WalletRpc::with_wallet(Arc::new(wallet))
}

/// Every file under `dir` with its contents
fn listing(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                out.push((p.display().to_string(), Vec::new()));
                stack.push(p);
            } else {
                out.push((p.display().to_string(), std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

fn assert_cores_reply(result: Result<serde_json::Value, Error>) {
    match result {
        Err(Error::Rpc(e)) => {
            assert_eq!(e.code, -4, "{}", e.message);
            assert_eq!(e.message, "Error: Wallet backup failed!");
        }
        other => panic!("backupwallet was not refused: {other:?}"),
    }
}

/// A file given as the destination is refused and left as it was
#[test]
fn backup_onto_a_file_is_refused_and_the_file_kept() {
    let dir = tempfile::tempdir().unwrap();
    let rpc = wallet_rpc(dir.path());
    let file = dir.path().join("notes.txt");
    std::fs::write(&file, "keep me").unwrap();
    assert_cores_reply(rpc.backup_wallet(&Params::Array(vec![json!(file.to_string_lossy())])));
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
}

/// A folder whose `wallet` entry is something else than a backup is refused,
/// and nothing in the folder is changed or added
#[test]
fn backup_into_a_folder_holding_other_files_leaves_them_alone() {
    let dir = tempfile::tempdir().unwrap();
    let rpc = wallet_rpc(dir.path());
    let folder = dir.path().join("usb");
    std::fs::create_dir_all(folder.join("wallet")).unwrap();
    std::fs::write(folder.join("wallet/photo.jpg"), [9u8; 64]).unwrap();
    std::fs::write(folder.join("readme"), "other files").unwrap();
    let before = listing(&folder);
    assert_cores_reply(rpc.backup_wallet(&Params::Array(vec![json!(folder.to_string_lossy())])));
    assert!(listing(&folder) == before, "the folder was changed");
}
