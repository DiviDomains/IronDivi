// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Opening a chain that must already be there (as `--export-chain` does):
//! nothing is created where there is none, an empty database is not given a
//! genesis block, and a chain the node made opens with its blocks.

use divi_primitives::ChainMode;
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType, StorageError};
use std::sync::Arc;

fn regtest() -> ChainParams {
    ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi)
}

#[test]
fn missing_database_is_refused_and_not_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chainstate");
    let err = ChainDatabase::open_existing(&path).err().expect("opened");
    assert!(matches!(err, StorageError::NotFound(_)), "{err}");
    assert!(!path.exists(), "chainstate was created");

    // An empty folder is not a database either
    std::fs::create_dir_all(&path).unwrap();
    assert!(ChainDatabase::open_existing(&path).is_err());
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
}

#[test]
fn empty_database_is_not_given_a_genesis_block() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chainstate");
    drop(ChainDatabase::open(&path).unwrap());
    let db = Arc::new(ChainDatabase::open_existing(&path).unwrap());
    let err = Chain::open_existing(db.clone(), regtest())
        .err()
        .expect("an empty chain opened");
    assert!(matches!(err, StorageError::ChainState(_)), "{err}");
    assert!(db.get_block_index_by_height(0).unwrap().is_none());
}

#[test]
fn chain_made_by_the_node_opens_with_its_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chainstate");
    let genesis = {
        let db = Arc::new(ChainDatabase::open(&path).unwrap());
        Chain::new(db, regtest()).unwrap().tip().unwrap().hash
    };
    let db = Arc::new(ChainDatabase::open_existing(&path).unwrap());
    let chain = Chain::open_existing(db.clone(), regtest()).unwrap();
    assert_eq!(chain.tip().unwrap().hash, genesis);
    drop(chain);
    // and is still checked for its network, as at start
    let testnet = ChainParams::for_network(NetworkType::Testnet, ChainMode::Divi);
    let err = Chain::open_existing(db, testnet)
        .err()
        .expect("wrong network");
    assert!(matches!(err, StorageError::WrongNetwork(_)), "{err}");
}
