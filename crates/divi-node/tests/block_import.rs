// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Blocks imported at start from `bootstrap.dat` and `-loadblock` files, as
//! Divi Core imports them (init.cpp:560-722): records of message start, size
//! and block, found by scanning; blocks before a damaged or cut-off record
//! still load, another network's file loads nothing, a block whose parent is
//! not known is skipped, and bootstrap.dat is renamed bootstrap.dat.old.

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use std::path::Path;

fn config(dir: &Path) -> NodeConfig {
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.to_path_buf();
    config
}

/// `n` regtest proof-of-work blocks on a fresh chain
fn mined_blocks(n: usize) -> Vec<Block> {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::new(config(dir.path())).unwrap();
    let mut blocks = Vec::new();
    for _ in 0..n {
        let parent = node.chain().tip().unwrap();
        let mut sig = divi_storage::bip34_height_script(parent.height + 1);
        sig.push(0);
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = parent.hash;
        block.header.time = parent.time + 60;
        block.header.bits = 0x207fffff;
        block.transactions = vec![Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250 * 100_000_000),
                Script::new_p2pkh(&[7; 20]),
            )],
            lock_time: 0,
        }];
        block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        node.chain().accept_block(block.clone()).unwrap();
        blocks.push(block);
    }
    blocks
}

/// The records of `blocks` in Divi Core's block-file format
fn block_file(blocks: &[Block], magic: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    for block in blocks {
        let bytes = serialize(block);
        out.extend_from_slice(&magic);
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

fn regtest_magic() -> [u8; 4] {
    NodeConfig::regtest(ChainMode::Divi).network.magic
}

/// A fresh node started with `file` given as -loadblock: its height
fn height_after_loadblock(file: &[u8]) -> u32 {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    std::fs::write(&path, file).unwrap();
    let mut config = config(&dir.path().join("node"));
    config.load_block = vec![path];
    Node::new(config).unwrap().chain().height()
}

/// bootstrap.dat in the data directory is imported at start and renamed
/// bootstrap.dat.old (init.cpp:698-711)
#[test]
fn bootstrap_dat_in_the_datadir_is_imported_and_renamed() {
    let blocks = mined_blocks(12);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("bootstrap.dat"),
        block_file(&blocks, regtest_magic()),
    )
    .unwrap();
    let node = Node::new(config(dir.path())).unwrap();
    assert_eq!(node.chain().height(), 12, "bootstrap.dat was not imported");
    assert_eq!(
        node.chain().tip().unwrap().hash,
        divi_crypto::compute_block_hash(&blocks[11].header)
    );
    drop(node);
    assert!(!dir.path().join("bootstrap.dat").exists());
    assert!(dir.path().join("bootstrap.dat.old").exists());
    // Imported once: the next start has nothing to import and keeps the chain
    assert_eq!(Node::new(config(dir.path())).unwrap().chain().height(), 12);
}

/// -loadblock files: the whole chain, junk between records skipped, the
/// blocks before a cut-off record, nothing from another network
#[test]
fn loadblock_files_are_imported_as_core_imports_them() {
    let blocks = mined_blocks(20);
    let magic = regtest_magic();
    let file = block_file(&blocks, magic);

    assert_eq!(height_after_loadblock(&file), 20);

    // Junk before and between records (a record header search resumes
    // one byte further after anything that is not a record)
    let mut junky = vec![0xAA; 37];
    let half = block_file(&blocks[..10], magic);
    junky.extend_from_slice(&half);
    junky.extend_from_slice(&magic[..2]);
    junky.extend_from_slice(&[0x00; 13]);
    junky.extend_from_slice(&block_file(&blocks[10..], magic));
    assert_eq!(height_after_loadblock(&junky), 20);

    // Cut off inside the 15th record: blocks 1-14 load
    let cut = block_file(&blocks[..14], magic).len() + 8 + 30;
    assert_eq!(height_after_loadblock(&file[..cut]), 14);

    // Another network's message start: nothing matches, nothing loads
    let mainnet = NodeConfig::default().network.magic;
    assert_ne!(mainnet, magic);
    assert_eq!(height_after_loadblock(&block_file(&blocks, mainnet)), 0);
}

/// Outside -reindex a block read before its parent is skipped, not kept
/// for later (init.cpp:608-615; only -reindex queues such blocks)
#[test]
fn a_block_before_its_parent_is_skipped() {
    let blocks = mined_blocks(6);
    let order = [
        &blocks[0], &blocks[2], &blocks[1], &blocks[3], &blocks[4], &blocks[5],
    ];
    let shuffled: Vec<Block> = order.iter().map(|b| (*b).clone()).collect();
    // 1 loads, 3 is skipped (2 unknown), 2 loads, then 4's parent 3 is not
    // known and so on: the chain ends at 2
    assert_eq!(
        height_after_loadblock(&block_file(&shuffled, regtest_magic())),
        2
    );
}

/// A -loadblock file that is not there is passed over with a warning
#[test]
fn a_missing_loadblock_file_is_passed_over() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(dir.path());
    config.load_block = vec![dir.path().join("no-such-file.dat")];
    assert_eq!(Node::new(config).unwrap().chain().height(), 0);
}
