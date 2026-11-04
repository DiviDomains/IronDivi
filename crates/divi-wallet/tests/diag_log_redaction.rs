// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Verifies that `manager.rs`, `backup.rs`, and `WalletDb::backup_to` wrap
//! wallet names and filesystem paths in `divi_primitives::redact` pseudonyms
//! (`WalletLabel` / `WalletValue`) when `-logwalletdetail` is off (the default).

use divi_primitives::ChainMode;
use divi_wallet::backup::backup_at_start;
use divi_wallet::{HdWallet, Network, WalletDb, WalletManager};
use tempfile::tempdir;
use tracing::level_filters::LevelFilter;

fn logged_trace<T>(f: impl FnOnce() -> T) -> (T, String) {
    #[derive(Clone)]
    struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf(Default::default());
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let out = tracing::subscriber::with_default(subscriber, f);
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (out, text)
}

#[test]
fn wallet_manager_and_backup_logs_redact_names_and_paths_by_default() {
    assert!(
        !divi_primitives::redact::wallet_detail(),
        "default run must keep wallet_detail() == false"
    );

    let root = tempdir().unwrap();
    let canary_dir = root.path().join("canary-secret-dir-9912");
    std::fs::create_dir_all(&canary_dir).unwrap();

    let ((), log) = logged_trace(|| {
        // 1. WalletManager lifecycle: create, set_default, save_all, unload, load, add_wallet, shutdown
        let manager = WalletManager::new(canary_dir.clone(), Network::Regtest);
        let alpha = manager.create_wallet("canary-wallet-alpha", None).unwrap();
        let beta = manager.create_wallet("canary-wallet-beta", None).unwrap();
        manager.set_default_wallet("canary-wallet-beta").unwrap();
        manager.save_all().unwrap();

        // Manual hot backup on WalletDb
        let manual_target = canary_dir.join("canary-manual-backup-4411");
        alpha.backup_to(&manual_target).unwrap();
        drop(alpha);
        drop(beta);

        manager.unload_wallet("canary-wallet-beta").unwrap();
        let reloaded = manager.load_wallet("canary-wallet-beta").unwrap();
        drop(reloaded);
        manager.unload_wallet("canary-wallet-alpha").unwrap();
        manager.shutdown().unwrap();

        let gamma_path = canary_dir.join("canary-wallet-gamma.dat");
        let gamma_hd = HdWallet::new(ChainMode::Divi).unwrap();
        let gamma = std::sync::Arc::new(
            WalletDb::create_persistent(&gamma_path, Network::Regtest, gamma_hd).unwrap(),
        );
        manager.add_wallet("canary-wallet-gamma", gamma).unwrap();
        manager.shutdown().unwrap();

        // 2. Startup backup: missing wallet path, initial backup copy, and old-backup pruning
        let missing_wallet = canary_dir.join("canary-missing-wallet-7788");
        backup_at_start(&missing_wallet, &canary_dir, 1).unwrap();

        let closed_wallet = canary_dir.join("canary-closed-wallet-5566");
        std::fs::create_dir_all(&closed_wallet).unwrap();
        std::fs::write(closed_wallet.join("CURRENT"), b"ok").unwrap();

        divi_primitives::clock::set_mock_time(1_792_806_600);
        backup_at_start(&closed_wallet, &canary_dir, 1).unwrap();
        // Ensure distinct mtime for deterministic pruning
        std::thread::sleep(std::time::Duration::from_millis(20));
        divi_primitives::clock::set_mock_time(1_792_806_720);
        backup_at_start(&closed_wallet, &canary_dir, 1).unwrap();
        divi_primitives::clock::set_mock_time(0);
    });

    // Verify expected structured log events actually fired with pseudonyms
    for expected in [
        "Creating new wallet ",
        "Loading wallet ",
        "Saving wallet ",
        "Default wallet set to ",
        "New default wallet: ",
        "Added wallet ",
        "Wallet backed up to ",
        "Wallet file not found at ",
        "Creating backup of ",
        "Old backup deleted: ",
        "wlb-",
        "wal-",
    ] {
        assert!(
            log.contains(expected),
            "expected `{expected}` in captured log:\n{log}"
        );
    }

    // Verify zero canary names or paths leaked anywhere in the log stream
    for canary in [
        "canary-secret-dir-9912",
        "canary-wallet-alpha",
        "canary-wallet-beta",
        "canary-wallet-gamma",
        "canary-manual-backup-4411",
        "canary-missing-wallet-7788",
        "canary-closed-wallet-5566",
    ] {
        let leaked: Vec<&str> = log.lines().filter(|l| l.contains(canary)).collect();
        assert!(
            leaked.is_empty(),
            "canary `{canary}` leaked in log lines:\n{}",
            leaked.join("\n")
        );
    }
}
