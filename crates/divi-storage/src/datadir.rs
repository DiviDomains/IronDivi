// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Checks on a data directory before irondivid opens or writes anything in it:
//! a Divi Core data directory is refused, and a chain database records the
//! network it was made for.

use crate::chain::{ChainParams, NetworkType};
use crate::database::ChainDatabase;
use crate::error::StorageError;
use divi_primitives::ChainMode;
use std::path::Path;

/// Metadata key holding the network a chain database was made for
const NETWORK_KEY: &[u8] = b"network";

/// The reason `path` is a database irondivid did not make, if it is one: a
/// folder with a LevelDB `CURRENT` file and neither a RocksDB `OPTIONS-*` nor
/// `IDENTITY` file, as Divi Core's `chainstate/` and `blocks/index/` are.
/// RocksDB writes an options file into every database it opens, but only at
/// the end of the open; a new database gets its `IDENTITY` file before its
/// `CURRENT` file (db_impl_open.cc, DBImpl::NewDB), so a first open cut short
/// by a crash is still recognised as irondivid's. LevelDB has no `IDENTITY`.
pub fn foreign_database(path: &Path) -> Option<String> {
    if !path.join("CURRENT").is_file() {
        return None;
    }
    let entries = std::fs::read_dir(path).ok()?;
    let has_rocksdb_file = entries.flatten().any(|e| {
        let name = e.file_name().to_string_lossy().into_owned();
        name.starts_with("OPTIONS-") || name == "IDENTITY"
    });
    (!has_rocksdb_file).then(|| {
        format!(
            "{} holds a LevelDB database, which irondivid did not make \
             (Divi Core keeps its chain in LevelDB databases like this one)",
            path.display()
        )
    })
}

/// Refuse to open `path` as a RocksDB database when it holds one irondivid did not make
pub fn refuse_foreign_database(path: &Path) -> Result<(), StorageError> {
    match foreign_database(path) {
        Some(reason) => Err(StorageError::NotIronDivi(format!(
            "{reason}; irondivid will not open or change it"
        ))),
        None => Ok(()),
    }
}

/// What makes `dir` a Divi Core data directory, if it is one: Core's block
/// files or block index (`blocks/blk*.dat`, `blocks/index/`), its LevelDB
/// `chainstate/`, or the same under Core's `testnet3/` or `regtest/`
/// network folders (Divi Core DataDirectory.cpp:111-112, chainparamsbase.cpp).
/// irondivid keeps its chain in `chainstate/` (RocksDB) and never makes `blocks/`.
pub fn divi_core_datadir(dir: &Path) -> Option<String> {
    let chain_data = |d: &Path| -> Option<String> {
        let blocks = d.join("blocks");
        if blocks.join("index").is_dir() {
            return Some(format!(
                "Divi Core's block index {}",
                blocks.join("index").display()
            ));
        }
        if let Ok(entries) = std::fs::read_dir(&blocks) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("blk") && name.ends_with(".dat") {
                    return Some(format!("Divi Core's block file {}", e.path().display()));
                }
            }
        }
        foreign_database(&d.join("chainstate"))
    };
    chain_data(dir).or_else(|| {
        ["testnet3", "regtest"]
            .iter()
            .find_map(|net| chain_data(&dir.join(net)))
    })
}

pub(crate) fn network_name(params: &ChainParams) -> String {
    let network = match params.network_type {
        NetworkType::Mainnet => "mainnet",
        NetworkType::Testnet => "testnet",
        NetworkType::Regtest => "regtest",
    };
    match params.chain_mode {
        ChainMode::Divi => network.to_string(),
        ChainMode::PrivateDivi => format!("privatedivi {network}"),
    }
}

/// Check that `db` was made for the network of `params` and record it on a
/// database that has none yet. A database from before the network was
/// recorded is checked by its genesis block.
pub(crate) fn check_network(db: &ChainDatabase, params: &ChainParams) -> Result<(), StorageError> {
    let wanted = network_name(params);
    let wrong = |stored: &str| {
        StorageError::WrongNetwork(format!(
            "this chain database was made for {stored}, but irondivid was started for {wanted}; \
             each network needs its own --datadir: start with the network options that made \
             it, or use another --datadir"
        ))
    };
    if let Some(stored) = db.get_metadata(NETWORK_KEY)? {
        let stored = String::from_utf8_lossy(&stored).into_owned();
        return if stored == wanted {
            Ok(())
        } else {
            Err(wrong(&stored))
        };
    }
    if let Some(genesis) = db.get_height_mapping(0)? {
        if genesis != params.genesis_hash {
            return Err(wrong(&format!("another network (genesis block {genesis})")));
        }
    }
    db.put_metadata(NETWORK_KEY, wanted.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;
    use std::sync::Arc;

    /// A LevelDB folder as Divi Core leaves it: CURRENT, MANIFEST, LOG, no OPTIONS file
    fn leveldb_folder(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("CURRENT"), "MANIFEST-000002\n").unwrap();
        std::fs::write(path.join("MANIFEST-000002"), [0u8; 16]).unwrap();
        std::fs::write(path.join("LOG"), "Recovering log #1\n").unwrap();
        std::fs::write(path.join("000003.ldb"), [1u8; 32]).unwrap();
    }

    fn listing(path: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<_> = std::fs::read_dir(path)
            .unwrap()
            .flatten()
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn chain_database_refuses_a_leveldb_folder_and_leaves_it_alone() {
        let dir = tempfile::tempdir().unwrap();
        let chainstate = dir.path().join("chainstate");
        leveldb_folder(&chainstate);
        let before = listing(&chainstate);
        let err = ChainDatabase::open(&chainstate)
            .err()
            .expect("a LevelDB folder must not open as a chain database");
        assert!(matches!(err, StorageError::NotIronDivi(_)), "{err}");
        assert!(err.to_string().contains("LevelDB"), "{err}");
        assert_eq!(listing(&chainstate), before, "nothing written");
    }

    #[test]
    fn tx_index_refuses_a_leveldb_folder() {
        let dir = tempfile::tempdir().unwrap();
        leveldb_folder(dir.path());
        let err = crate::txindex::TxIndex::open(dir.path())
            .err()
            .expect("a LevelDB folder must not open as the tx index");
        assert!(matches!(err, StorageError::NotIronDivi(_)), "{err}");
    }

    #[test]
    fn own_databases_still_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chainstate");
        drop(ChainDatabase::open(&path).unwrap());
        assert!(foreign_database(&path).is_none());
        ChainDatabase::open(&path).unwrap();
        assert!(divi_core_datadir(dir.path()).is_none());
    }

    /// A RocksDB folder whose first open was cut short before RocksDB wrote
    /// its options file, as a kill -9 at the first start leaves it
    fn cut_short(path: &Path) {
        for e in std::fs::read_dir(path).unwrap().flatten() {
            if e.file_name().to_string_lossy().starts_with("OPTIONS-") {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        assert!(path.join("IDENTITY").is_file() && path.join("CURRENT").is_file());
    }

    #[test]
    fn database_cut_short_at_its_first_open_opens_again() {
        let dir = tempfile::tempdir().unwrap();
        let chainstate = dir.path().join("chainstate");
        drop(ChainDatabase::open(&chainstate).unwrap());
        cut_short(&chainstate);
        assert!(foreign_database(&chainstate).is_none());
        assert!(divi_core_datadir(dir.path()).is_none());
        ChainDatabase::open(&chainstate).unwrap();

        let txindex = dir.path().join("txindex");
        drop(crate::txindex::TxIndex::open(&txindex).unwrap());
        cut_short(&txindex);
        crate::txindex::TxIndex::open(&txindex).unwrap();
    }

    #[test]
    fn divi_core_datadirs_are_recognised() {
        // Core mainnet layout
        let core = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(core.path().join("blocks")).unwrap();
        std::fs::write(core.path().join("blocks/blk00000.dat"), [0u8; 8]).unwrap();
        assert!(divi_core_datadir(core.path())
            .unwrap()
            .contains("blk00000.dat"));

        // Core regtest folder under a datadir: only regtest/ holds chain data
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("regtest/blocks/index")).unwrap();
        assert!(divi_core_datadir(root.path()).is_some());
        assert!(divi_core_datadir(&root.path().join("regtest")).is_some());

        // Core chainstate alone
        let cs = tempfile::tempdir().unwrap();
        leveldb_folder(&cs.path().join("chainstate"));
        assert!(divi_core_datadir(cs.path()).is_some());

        // A folder with only a wallet.dat is not a chain datadir
        let w = tempfile::tempdir().unwrap();
        std::fs::write(w.path().join("wallet.dat"), [0u8; 8]).unwrap();
        assert!(divi_core_datadir(w.path()).is_none());
    }

    fn params(network: NetworkType) -> ChainParams {
        ChainParams::for_network(network, ChainMode::Divi)
    }

    #[test]
    fn chain_database_of_another_network_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chainstate");
        {
            let db = Arc::new(ChainDatabase::open(&path).unwrap());
            Chain::new(db, params(NetworkType::Regtest)).unwrap();
        }
        let db = Arc::new(ChainDatabase::open(&path).unwrap());
        let err = Chain::new(db.clone(), params(NetworkType::Testnet))
            .err()
            .expect("a regtest chain database must not open as testnet");
        assert!(matches!(err, StorageError::WrongNetwork(_)), "{err}");
        assert!(err.to_string().contains("made for regtest"), "{err}");
        // The right network still opens it
        Chain::new(db, params(NetworkType::Regtest)).unwrap();
    }

    #[test]
    fn database_without_a_recorded_network_is_checked_by_its_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chainstate");
        {
            let db = Arc::new(ChainDatabase::open(&path).unwrap());
            Chain::new(db.clone(), params(NetworkType::Regtest)).unwrap();
            // As written before the network was recorded
            db.delete_metadata(NETWORK_KEY).unwrap();
        }
        let db = Arc::new(ChainDatabase::open(&path).unwrap());
        let err = Chain::new(db.clone(), params(NetworkType::Mainnet))
            .err()
            .expect("genesis of another network");
        assert!(matches!(err, StorageError::WrongNetwork(_)), "{err}");
        Chain::new(db.clone(), params(NetworkType::Regtest)).unwrap();
        assert_eq!(
            db.get_metadata(NETWORK_KEY).unwrap().as_deref(),
            Some(&b"regtest"[..])
        );
    }
}
