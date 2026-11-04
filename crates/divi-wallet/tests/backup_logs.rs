// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The start-up wallet backups' log lines as Divi Core 3.0.0 writes them,
//! checked against divid with scripts/wallet-copies/run.sh.

use divi_wallet::backup::backup_at_start;
use tempfile::tempdir;

/// The log lines written while `f` runs on this thread
fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
    // Divi Core's exact paths are printed when `-logwalletdetail=1` is on
    divi_primitives::redact::set_wallet_detail(true);
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
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let out = tracing::subscriber::with_default(subscriber, f);
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (out, text)
}

/// The backup lines of `log`, without their time stamps, levels and targets
fn backup_lines(log: &str) -> Vec<String> {
    const STARTS: [&str; 4] = [
        "backing up wallet",
        "Wallet file not found at ",
        "Creating backup of ",
        "Failed to create backup",
    ];
    log.lines()
        .filter_map(|l| {
            STARTS
                .iter()
                .filter_map(|s| l.find(s))
                .min()
                .map(|i| l[i..].to_string())
        })
        .collect()
}

/// A first start has no wallet yet: Divi Core logs that it backs up, then
/// that the wallet is not there for each of the two backups, and makes
/// neither folder (init.cpp:939, WalletBackupFeatureContainer.cpp:24-33)
#[test]
fn no_wallet_yet_is_logged_for_both_backups() {
    let dir = tempdir().unwrap();
    let wallet = dir.path().join("wallet");
    let (result, log) = logged(|| backup_at_start(&wallet, dir.path(), 20));
    result.unwrap();
    let missing = format!(
        "Wallet file not found at {}. Skipping backup...",
        wallet.display()
    );
    assert_eq!(
        backup_lines(&log),
        vec!["backing up wallet".to_string(), missing.clone(), missing]
    );
    assert!(!dir.path().join("backups").exists());
    assert!(!dir.path().join("monthlyBackups").exists());
}

/// With a wallet there, Divi Core logs "backing up wallet" once at the start
/// and again before each of the two backups, each copy followed by its
/// "Creating backup of" line; the monthly one only when none is there yet
/// (init.cpp:939, WalletBackupFeatureContainer.cpp:41, WalletBackupCreator.cpp:48)
#[test]
fn each_backup_logs_that_it_backs_up() {
    let dir = tempdir().unwrap();
    let wallet = dir.path().join("wallet");
    std::fs::create_dir_all(&wallet).unwrap();
    std::fs::write(wallet.join("CURRENT"), b"x").unwrap();
    let (result, log) = logged(|| backup_at_start(&wallet, dir.path(), 20));
    result.unwrap();
    let lines = backup_lines(&log);
    let made = |sub: &str| {
        lines
            .iter()
            .any(|l| l.starts_with("Creating backup of ") && l.contains(sub))
    };
    assert_eq!(
        lines
            .iter()
            .map(|l| if l.starts_with("Creating backup of ") {
                "Creating backup of"
            } else {
                l.as_str()
            })
            .collect::<Vec<_>>(),
        vec![
            "backing up wallet",
            "backing up wallet",
            "Creating backup of",
            "backing up wallet",
            "Creating backup of",
        ],
        "{lines:?}"
    );
    assert!(made("/backups/") && made("/monthlyBackups/"), "{lines:?}");
    // A second start: the monthly backup is not due, so it only logs
    let (result, log) = logged(|| backup_at_start(&wallet, dir.path(), 20));
    result.unwrap();
    let starts: Vec<_> = backup_lines(&log)
        .into_iter()
        .filter(|l| l == "backing up wallet")
        .collect();
    assert_eq!(starts.len(), 3, "{log}");
}

/// A backup of that minute already there: Divi Core's copy fails, it logs
/// "Failed to create backup" and keeps the one there (WalletBackupCreator.cpp:44-55)
#[test]
fn a_backup_name_already_there_is_a_failed_backup() {
    let dir = tempdir().unwrap();
    let wallet = dir.path().join("wallet");
    std::fs::create_dir_all(&wallet).unwrap();
    std::fs::write(wallet.join("CURRENT"), b"new").unwrap();
    // This minute's name and the next one's, so the test does not race the clock
    let now = std::time::SystemTime::now();
    for at in [now, now + std::time::Duration::from_secs(60)] {
        let taken = dir
            .path()
            .join("backups")
            .join(format!("wallet{}", divi_wallet::backup::time_suffix(at)));
        std::fs::create_dir_all(&taken).unwrap();
        std::fs::write(taken.join("CURRENT"), b"old").unwrap();
    }
    let (result, log) = logged(|| backup_at_start(&wallet, dir.path(), 20));
    result.unwrap();
    let lines = backup_lines(&log);
    assert_eq!(
        lines.get(2).map(String::as_str),
        Some("Failed to create backup"),
        "{lines:?}"
    );
    assert!(!log.contains("already exists"), "{log}");
    for entry in std::fs::read_dir(dir.path().join("backups")).unwrap() {
        let copy = entry.unwrap().path();
        assert_eq!(std::fs::read(copy.join("CURRENT")).unwrap(), b"old");
    }
}
