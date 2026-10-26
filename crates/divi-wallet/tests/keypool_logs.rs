// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The wallet's log lines as Divi Core 3.0.0's wallet writes them, checked
//! against divid with scripts/wallet-logs/run.sh.

use divi_primitives::ChainMode;
use divi_wallet::{HdWallet, Network, WalletDb};
use tempfile::tempdir;

/// The log lines written while `f` runs on this thread
fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
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

/// The keypool lines of `log`, without their time stamps and levels
fn keypool_lines(log: &str) -> Vec<String> {
    log.lines()
        .filter_map(|l| l.find("keypool ").map(|i| l[i..].to_string()))
        .collect()
}

/// The keypool's lines as Divi Core writes them: a key added with its pool
/// number, the pool's size and its chain; a key handed out reserved and kept,
/// the pool topped up first; a change key reserved and returned for a send
/// with no change. The numbers carry on once the wallet is opened again
/// (wallet.cpp:2093-2112, :2122-2176)
#[test]
fn keypool_lines_number_the_keys_as_divid_does() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("w");
    let wallet = WalletDb::create_persistent(
        &path,
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    )
    .unwrap();
    wallet.keystore().set_keypool_target(2);
    let (_, log) = logged(|| wallet.top_up_keypool().unwrap());
    assert_eq!(
        keypool_lines(&log),
        [
            "keypool added key 1, size=1, internal=0",
            "keypool added key 2, size=2, internal=0",
            "keypool added key 3, size=3, internal=1",
            "keypool added key 4, size=4, internal=1",
        ]
    );
    let (_, log) = logged(|| wallet.new_receiving_address().unwrap());
    assert_eq!(keypool_lines(&log), ["keypool reserve 1", "keypool keep 1"]);
    let (_, log) = logged(|| wallet.new_change_address().unwrap());
    assert_eq!(
        keypool_lines(&log),
        [
            "keypool added key 5, size=4, internal=0",
            "keypool reserve 3",
            "keypool keep 3",
        ]
    );
    let (_, log) = logged(|| wallet.reserve_and_return_change().unwrap());
    assert_eq!(
        keypool_lines(&log),
        [
            "keypool added key 6, size=4, internal=1",
            "keypool reserve 4",
            "keypool return 4",
        ]
    );
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Regtest).unwrap();
    wallet.keystore().set_keypool_target(2);
    let (_, log) = logged(|| wallet.new_receiving_address().unwrap());
    assert_eq!(keypool_lines(&log), ["keypool reserve 2", "keypool keep 2"]);
}
