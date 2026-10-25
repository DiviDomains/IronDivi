// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! What the wallet file holds when the process dies part-way through a write:
//! a stop point ends the operation where a crash would, and the wallet is
//! opened again as a restart would open it.

use super::*;
use crate::fault;
use tempfile::tempdir;

fn new_wallet(path: &std::path::Path) -> WalletDb {
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    WalletDb::create_persistent(path, Network::Mainnet, hd).unwrap()
}

/// A passphrase change is one write: after a stop the wallet opens with the
/// old passphrase or the new one (Divi Core writes salt and sealed master key
/// as one `mkey` record)
#[test]
fn stop_during_passphrase_change_keeps_wallet_openable() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pass.dat");
    {
        let wallet = new_wallet(&path);
        wallet.encrypt_wallet("old passphrase").unwrap();
        fault::arm("passphrase salt written", 0);
        assert!(wallet
            .change_passphrase("old passphrase", "new passphrase")
            .is_err());
        fault::disarm();
    }
    let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
    let old = wallet.unlock("old passphrase", 0).is_ok();
    let new = wallet.unlock("new passphrase", 0).is_ok();
    assert!(old || new, "neither passphrase opens the wallet");
}

/// A full save is one write: a stop cannot leave a coin un-spent by a reorg
/// without its spent mark and without its coin row
#[test]
fn stop_during_save_keeps_coin_restored_by_reorg() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("save.dat");
    let fund;
    {
        let wallet = new_wallet(&path);
        let send;
        (fund, send) = fixture(&wallet);
        wallet.save().unwrap();
        scan(&wallet, 1, std::slice::from_ref(&fund));
        wallet.save_incremental().unwrap();
        scan(&wallet, 2, std::slice::from_ref(&send));
        wallet.save_incremental().unwrap();

        wallet.handle_reorg(1);
        fault::arm("wallet deletes written", 0);
        assert!(wallet.save().is_err());
        fault::disarm();
    }
    let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
    let coin = OutPoint::new(fund.txid(), 0);
    let scan_height = wallet.last_scan_height();
    // Either the save happened (coin back) or not (coin still spent at height
    // 2, which the scan height 2 still covers): never a coin that is gone
    if scan_height == 1 {
        assert!(outpoints(&wallet).contains(&coin));
        assert_eq!(wallet.get_balance().as_sat(), 100 * COIN);
    } else {
        assert!(
            outpoints(&wallet).contains(&coin) || wallet.spent.read().contains(&coin),
            "coin neither unspent nor spent"
        );
    }
}

/// The wallet remembers which blocks it scanned across a restart, as Divi
/// Core's best-block locator does: a chain whose block at the scan height is
/// a different block is rolled back to the fork and scanned again
#[test]
fn restart_on_replaced_block_at_scan_height_rescans_it() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("locator.dat");
    let (fund, other);
    {
        let wallet = new_wallet(&path);
        (fund, _) = fixture(&wallet);
        let addr = wallet.new_receiving_address().unwrap();
        other = tx(
            &[(Hash256::from_bytes([8u8; 32]), 0)],
            vec![(50 * COIN, mine(&addr))],
        );
        wallet.save().unwrap();
        let branch_a = TestChain::new(0, &[&[], std::slice::from_ref(&fund)]);
        assert!(branch_a.sync(&wallet).is_empty());
        wallet.save_incremental().unwrap();
        assert_eq!(wallet.get_balance().as_sat(), 100 * COIN);
    }
    // Restart on a chain whose block 2 is another block, paying 50 instead
    let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
    assert_eq!(wallet.last_scan_height(), 2);
    let branch_b = TestChain::new(1, &[&[], std::slice::from_ref(&other)]);
    branch_b.sync(&wallet);
    assert_eq!(
        outpoints(&wallet),
        HashSet::from([OutPoint::new(other.txid(), 0)]),
        "the replaced block's coin stayed or the new block was not scanned"
    );
    assert_eq!(wallet.get_balance().as_sat(), 50 * COIN);
}
