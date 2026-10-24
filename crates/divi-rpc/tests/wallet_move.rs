// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! What a wallet carries when it moves: `backupwallet` copies, the HD path
//! `dumphdinfo` names, and a wallet made from a hex seed (Divi Core's
//! -hdseed), against Divi Core 3.0.0 (walletdb.cpp, rpcdump.cpp, wallet.cpp).

use divi_primitives::ChainMode;
use divi_rpc::{Params, WalletRpc};
use divi_wallet::{HdWallet, Network, WalletDatabase, WalletDb};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn p(v: Vec<Value>) -> Params {
    Params::Array(v)
}

/// BIP32 test vector 1; Divi Core 3.0.0 on regtest started with
/// `-hdseed=000102030405060708090a0b0c0d0e0f` gives this address at
/// m/44'/1'/0'/0/0
const SEED: &str = "000102030405060708090a0b0c0d0e0f";
const CORE_FIRST_ADDRESS: &str = "y7VQ7R3SDRxzNuUsUuFzuq2FT1uVtW8iBz";

/// A backup taken while the wallet is being written opens, every time
#[test]
fn backup_taken_while_wallet_writes_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = Arc::new(
        WalletDb::create_persistent(
            &path,
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    wallet.encrypt_wallet("one").unwrap();
    let rpc = WalletRpc::with_wallet(wallet.clone());

    // Writes that flush the database and replace its files, as a busy node's
    // do; `committed` is the scan height of the last save that returned
    let stop = Arc::new(AtomicBool::new(false));
    let committed = Arc::new(AtomicU32::new(0));
    let writer = {
        let wallet = wallet.clone();
        let stop = stop.clone();
        let committed = committed.clone();
        std::thread::spawn(move || {
            let mut height = 0u32;
            let (mut from, mut to) = ("one", "two");
            while !stop.load(Ordering::Relaxed) {
                height += 1;
                wallet.set_last_scan_height(height);
                wallet.save().unwrap();
                committed.store(height, Ordering::SeqCst);
                wallet.change_passphrase(from, to).unwrap();
                std::mem::swap(&mut from, &mut to);
            }
            height
        })
    };

    let started = Instant::now();
    let mut failures = Vec::new();
    for i in 0..400 {
        if started.elapsed() > Duration::from_secs(90) {
            break;
        }
        let target = dir.path().join(format!("backup-{i}"));
        let before = committed.load(Ordering::SeqCst);
        match rpc.backup_wallet(&p(vec![json!(target.to_string_lossy())])) {
            Ok(_) => match WalletDb::open(&target, Network::Regtest) {
                Ok(copy) => {
                    if copy.last_scan_height() < before {
                        failures.push(format!(
                            "backup {i}: scan height {} older than {before}, saved before the backup",
                            copy.last_scan_height()
                        ));
                    }
                    if copy.unlock("one", 0).is_err() && copy.unlock("two", 0).is_err() {
                        failures.push(format!("backup {i}: neither passphrase opens it"));
                    }
                }
                Err(e) => failures.push(format!("backup {i} does not open: {e}")),
            },
            Err(e) => failures.push(format!("backup {i} failed: {e:?}")),
        }
    }
    stop.store(true, Ordering::Relaxed);
    let last = writer.join().unwrap();
    assert!(last > 0);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `backupwallet` to a folder puts the copy inside it, as Core appends
/// wallet.dat to a directory; running it again replaces that copy
#[test]
fn backup_into_folder_and_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = Arc::new(
        WalletDb::create_persistent(
            &path,
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    let rpc = WalletRpc::with_wallet(wallet.clone());
    let folder = dir.path().join("usb");
    std::fs::create_dir_all(&folder).unwrap();
    let dest = json!(folder.to_string_lossy());
    rpc.backup_wallet(&p(vec![dest.clone()])).unwrap();
    wallet.set_last_scan_height(7);
    wallet.save().unwrap();
    rpc.backup_wallet(&p(vec![dest])).unwrap();
    let copy = WalletDb::open(&folder.join("wallet"), Network::Regtest).unwrap();
    assert_eq!(copy.last_scan_height(), 7);
    assert_eq!(copy.mnemonic(), wallet.mnemonic());
}

/// `dumphdinfo` names the account path, so a restore elsewhere can tell the
/// coin type: 1 on testnet, 301 for a testnet wallet stored before the coin
/// type followed the network
#[test]
fn dumphdinfo_names_the_account_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet");
    {
        WalletDb::create_persistent(
            &path,
            Network::Testnet,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap();
    }
    let rpc = WalletRpc::with_wallet(Arc::new(WalletDb::open(&path, Network::Testnet).unwrap()));
    let info = rpc.dump_hd_info(&Params::None).unwrap();
    assert_eq!(info["hdaccountpath"], "m/44'/1'/0'", "{info}");

    // The same wallet as an older one, stored without a coin type
    drop(rpc);
    {
        let db = WalletDatabase::open(&path).unwrap();
        let mut batch = db.create_batch();
        batch.delete_cf(db.cf_metadata(), b"hd_coin_type");
        db.write_batch(batch).unwrap();
    }
    let rpc = WalletRpc::with_wallet(Arc::new(WalletDb::open(&path, Network::Testnet).unwrap()));
    let info = rpc.dump_hd_info(&Params::None).unwrap();
    assert_eq!(info["hdaccountpath"], "m/44'/301'/0'", "{info}");
}

/// A wallet made from a hex seed derives Core's addresses, shows the seed and
/// an empty mnemonic in `dumphdinfo` as Core does, and keeps its seed across
/// a restart and through encryption
#[test]
fn hex_seed_wallet_matches_core_and_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet");
    let seed = hex::decode(SEED).unwrap();
    {
        let wallet = Arc::new(
            WalletDb::create_persistent(
                &path,
                Network::Regtest,
                HdWallet::from_seed(&seed, ChainMode::Divi).unwrap(),
            )
            .unwrap(),
        );
        wallet.refill_keypool(Some(5)).unwrap();
        let addresses: Vec<String> = wallet
            .get_addresses()
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert!(
            addresses.iter().any(|a| a == CORE_FIRST_ADDRESS),
            "{addresses:?}"
        );
        wallet.save().unwrap();
    }

    let wallet = Arc::new(WalletDb::open(&path, Network::Regtest).unwrap());
    let rpc = WalletRpc::with_wallet(wallet.clone());
    let info = rpc.dump_hd_info(&Params::None).unwrap();
    assert_eq!(info["hdseed"], SEED);
    assert_eq!(info["mnemonic"], "");
    assert_eq!(info["mnemonicpassphrase"], "");

    wallet.encrypt_wallet("pass").unwrap();
    drop(rpc);
    drop(wallet);
    let wallet = Arc::new(WalletDb::open(&path, Network::Regtest).unwrap());
    wallet.unlock("pass", 0).unwrap();
    let rpc = WalletRpc::with_wallet(wallet.clone());
    let info = rpc.dump_hd_info(&Params::None).unwrap();
    assert_eq!(info["hdseed"], SEED, "the seed did not survive encryption");
}
