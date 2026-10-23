// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Divi Core's answer to `getblocks` (main.cpp): at the limit the last hash is
//! remembered so that, when the peer asks for that block, our tip follows.

use divi_network::GetBlocksMessage;
use divi_node::config::NodeConfig;
use divi_node::{getblocks_reply, Node};
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;

fn mine(node: &Node) -> Hash256 {
    let chain = node.chain();
    let tip = chain.tip().unwrap();
    let mut tag = divi_storage::bip34_height_script(tip.height + 1);
    tag.extend_from_slice(&(tip.height + 1).to_le_bytes());
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(tag))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250 * 100_000_000),
            Script::new_p2pkh(&[0xee; 20]),
        )],
        lock_time: 0,
    };
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = tip.hash;
    block.header.time = tip.time + 60;
    block.header.bits = 0x207fffff;
    block.transactions = vec![coinbase];
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    let hash = divi_crypto::compute_block_hash(&block.header);
    chain.accept_block(block).unwrap();
    hash
}

#[test]
fn full_answer_remembers_its_last_hash() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    let node = Node::new(config).unwrap();
    let genesis = node.chain().tip().unwrap().hash;
    let hashes: Vec<Hash256> = (0..12).map(|_| mine(&node)).collect();

    let from_genesis = GetBlocksMessage::new(vec![genesis], Hash256::zero());
    let (items, continue_at) = getblocks_reply(node.chain(), &from_genesis, 5);
    assert_eq!(
        items.iter().map(|i| i.hash).collect::<Vec<_>>(),
        hashes[..5].to_vec()
    );
    assert_eq!(continue_at, Some(hashes[4]));

    // Fewer than the limit left: no continuation
    let near_tip = GetBlocksMessage::new(vec![hashes[8]], Hash256::zero());
    let (items, continue_at) = getblocks_reply(node.chain(), &near_tip, 5);
    assert_eq!(items.len(), 3);
    assert_eq!(continue_at, None);

    // The stop hash ends the answer
    let to_stop = GetBlocksMessage::new(vec![genesis], hashes[1]);
    let (items, continue_at) = getblocks_reply(node.chain(), &to_stop, 5);
    assert_eq!(items.len(), 2);
    assert_eq!(continue_at, None);

    // An unknown locator starts after genesis
    let unknown = GetBlocksMessage::new(vec![Hash256::from_bytes([9; 32])], Hash256::zero());
    let (items, _) = getblocks_reply(node.chain(), &unknown, 5);
    assert_eq!(items[0].hash, hashes[0]);
}
