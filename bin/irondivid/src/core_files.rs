// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Divi Core's files where irondivid starts: a Core data directory or wallet
//! file is refused before anything is opened or written, a `wallet.dat` left
//! in the data directory is named in the log, and the collateral of every
//! `masternode.conf` entry is locked as Divi Core does.

use anyhow::{bail, Result};
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::OutPoint;
use divi_wallet::WalletDb;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// What the recovery phrase does not carry, said wherever a Core wallet is met
const PHRASE_NOTE: &str = "The 24-word recovery phrase (dumphdinfo in divid; WALLET_MNEMONIC on \
     irondivid's first start) restores only the keys made from the seed. Imported keys, \
     watch-only addresses, multisig scripts, vaults and labels are not in it: move them by hand \
     (dumpprivkey / importprivkey, importaddress, addmultisigaddress, addvault, setaccount) and \
     keep wallet.dat until they show in irondivid.";

/// Whether `path` is a Berkeley DB file, as Divi Core's wallet.dat is: the
/// magic number at byte 12 of the first page (btree 0x053162, hash 0x061561),
/// in either byte order
pub fn is_berkeley_db(path: &Path) -> bool {
    let mut head = [0u8; 16];
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    if file.read_exact(&mut head).is_err() {
        return false;
    }
    let magic = [head[12], head[13], head[14], head[15]];
    [0x0005_3162u32, 0x0006_1561]
        .iter()
        .any(|m| magic == m.to_le_bytes() || magic == m.to_be_bytes())
}

/// The wallet folder: `-wallet=<name>` is within the data directory, as
/// divid's, and the default is `<datadir>/wallet`
pub fn wallet_dir(data_dir: &Path, wallet: Option<&Path>) -> PathBuf {
    match wallet {
        Some(p) if p.is_relative() => data_dir.join(p),
        Some(p) => p.to_path_buf(),
        None => data_dir.join("wallet"),
    }
}

/// Refuse to start on a Divi Core data directory, or with a wallet path that
/// is a file or a folder holding Core's wallet.dat. Runs before irondivid
/// opens or writes anything, so the folder is left exactly as it was.
pub fn refuse_at_start(data_dir: &Path, wallet: Option<&Path>, disable_wallet: bool) -> Result<()> {
    if let Some(found) = divi_storage::datadir::divi_core_datadir(data_dir) {
        bail!(
            "{} is a Divi Core data directory ({found}). irondivid keeps its own data in a \
             different format and cannot use Divi Core's; nothing was opened or written. \
             Give irondivid a folder of its own with --datadir (the default is ~/.irondivi), \
             and keep this one for divid.",
            data_dir.display()
        );
    }
    if disable_wallet {
        return Ok(());
    }
    let wallet = &wallet_dir(data_dir, wallet);
    if wallet.is_file() {
        if is_berkeley_db(wallet) {
            bail!(
                "{} is a Divi Core wallet file (Berkeley DB). irondivid cannot read it and has \
                 not opened or changed it; its wallet is a folder of its own (--wallet names \
                 that folder). {PHRASE_NOTE}",
                wallet.display()
            );
        }
        bail!(
            "{} is a file; irondivid's wallet is a folder (--wallet names that folder)",
            wallet.display()
        );
    }
    if wallet.join("wallet.dat").is_file() {
        bail!(
            "{} holds a Divi Core wallet.dat; irondivid's wallet needs a folder of its own and \
             has not opened or changed anything there. Point --wallet at another folder. \
             {PHRASE_NOTE}",
            wallet.display()
        );
    }
    Ok(())
}

/// Name a `wallet.dat` left in the data directory: irondivid never reads it
pub fn warn_core_wallet(data_dir: &Path) {
    let path = data_dir.join("wallet.dat");
    if path.is_file() {
        warn!(
            "{} is a Divi Core wallet file. irondivid does not read wallet.dat and will not \
             open or change it; irondivid's wallet is the folder {}. {PHRASE_NOTE}",
            path.display(),
            data_dir.join("wallet").display()
        );
    }
}

/// Divi Core's masternode.conf header, written when there is no file
/// (masternodeconfig.cpp:53-64)
const MASTERNODE_CONF_HEADER: &str = "# Masternode config file\n\
# Format: alias IP:port masternodeprivkey collateral_output_txid collateral_output_index\n\
# Example: mn1 127.0.0.2:51472 93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg 2bcd3c84c84f87eaa86e4e56834c92927a07f9e18718810b92e0d0324456a67c 0\n";

/// Make `masternode.conf` with Divi Core's header when the data directory has
/// none, as divid does at every start; an existing file is left as it is
pub fn ensure_masternode_conf(data_dir: &Path) {
    let path = data_dir.join("masternode.conf");
    if path.exists() {
        return;
    }
    if let Err(e) = std::fs::write(&path, MASTERNODE_CONF_HEADER) {
        warn!("Could not create {}: {}", path.display(), e);
    }
}

/// Lock the collateral of every `masternode.conf` entry in the wallet, as
/// Divi Core does when the wallet loads (init.cpp:1246-1258,
/// MasternodeModule.cpp:454-466, `-mnconflock` default 1): coin selection
/// and the staker skip locked coins. Returns how many were locked.
pub fn lock_masternode_collateral(wallet: &WalletDb, data_dir: &Path) -> usize {
    let entries = divi_rpc::mn_broadcast::read_conf(&data_dir.join("masternode.conf"));
    if entries.is_empty() {
        return 0;
    }
    info!("Locking Masternodes:");
    let mut locked = 0;
    for entry in entries {
        info!("  {} {}", entry.tx_hash, entry.out_idx);
        match (Hash256::from_hex(&entry.tx_hash), entry.out_idx.parse::<u32>()) {
            (Ok(txid), Ok(vout)) => {
                wallet.set_coin_locked(OutPoint { txid, vout }, true);
                locked += 1;
            }
            _ => warn!(
                "masternode.conf entry {}: collateral {} {} is not a txid and output index; not locked",
                entry.alias, entry.tx_hash, entry.out_idx
            ),
        }
    }
    locked
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::ChainMode;
    use divi_wallet::{HdWallet, Network};

    /// The first page of a Berkeley DB btree file, as Divi Core writes wallet.dat
    fn bdb_file(path: &Path) {
        let mut page = vec![0u8; 4096];
        page[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        std::fs::write(path, page).unwrap();
    }

    #[test]
    fn berkeley_db_magic() {
        let dir = tempfile::tempdir().unwrap();
        let bdb = dir.path().join("wallet.dat");
        bdb_file(&bdb);
        assert!(is_berkeley_db(&bdb));
        let other = dir.path().join("other");
        std::fs::write(&other, [0u8; 64]).unwrap();
        assert!(!is_berkeley_db(&other));
        assert!(!is_berkeley_db(&dir.path().join("missing")));
    }

    #[test]
    fn wallet_paths_that_are_core_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let core = dir.path().join("core");
        std::fs::create_dir_all(&core).unwrap();
        bdb_file(&core.join("wallet.dat"));

        let err = refuse_at_start(&data, Some(&core.join("wallet.dat")), false).unwrap_err();
        assert!(err.to_string().contains("Divi Core wallet file"), "{err}");
        let err = refuse_at_start(&data, Some(&core), false).unwrap_err();
        assert!(
            err.to_string().contains("holds a Divi Core wallet.dat"),
            "{err}"
        );
        // -wallet=wallet.dat (divid's default name) is within the data directory
        let err = refuse_at_start(&core, Some(Path::new("wallet.dat")), false).unwrap_err();
        assert!(err.to_string().contains("Divi Core wallet file"), "{err}");
        // --disablewallet: the wallet path is not used
        refuse_at_start(&data, Some(&core.join("wallet.dat")), true).unwrap();
        // The default wallet folder, and a wallet.dat beside it (warned, not refused)
        bdb_file(&data.join("wallet.dat"));
        refuse_at_start(&data, None, false).unwrap();
        assert_eq!(
            std::fs::read_dir(&data).unwrap().count(),
            1,
            "nothing written"
        );
    }

    /// A data directory without masternode.conf gets divid's header file; an
    /// existing one is not touched
    #[test]
    fn masternode_conf_is_made_with_divid_s_header() {
        let dir = tempfile::tempdir().unwrap();
        ensure_masternode_conf(dir.path());
        let made = std::fs::read_to_string(dir.path().join("masternode.conf")).unwrap();
        assert!(made.starts_with("# Masternode config file\n# Format: alias IP:port"));
        assert_eq!(made.lines().count(), 3);
        assert!(divi_rpc::mn_broadcast::read_conf(&dir.path().join("masternode.conf")).is_empty());
        std::fs::write(
            dir.path().join("masternode.conf"),
            "mn1 1.2.3.4:51472 k t 0\n",
        )
        .unwrap();
        ensure_masternode_conf(dir.path());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("masternode.conf")).unwrap(),
            "mn1 1.2.3.4:51472 k t 0\n"
        );
    }

    #[test]
    fn masternode_conf_collateral_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let txid = Hash256::from_bytes([7; 32]);
        std::fs::write(
            dir.path().join("masternode.conf"),
            format!(
                "# Masternode config file\n\
                 mn1 127.0.0.2:51476 privkey {txid} 1\n\
                 mn2 127.0.0.3:51476 privkey not-a-txid 0\n"
            ),
        )
        .unwrap();
        let hd = HdWallet::new(ChainMode::Divi).unwrap();
        let wallet = WalletDb::with_hd_wallet(Network::Regtest, hd);
        assert_eq!(lock_masternode_collateral(&wallet, dir.path()), 1);
        assert_eq!(wallet.locked_coins(), vec![OutPoint { txid, vout: 1 }]);
        // No masternode.conf: nothing locked
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(lock_masternode_collateral(&wallet, empty.path()), 0);
    }
}
