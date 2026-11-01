// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The `reject` a node sends the peer that offered it a block it refuses before
//! connecting it, as Divi Core does (main.cpp:840-843; CheckBlock,
//! BlockCheckingHelpers.cpp:24-96, ContextualCheckBlock and its header check,
//! ChainExtensionService.cpp:292-382): the code and reason of the check, and the
//! block's hash.

mod common;
use common::raw_peer::*;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

/// A work block on the node's tip that is valid; `edit` breaks it, and the
/// merkle root and the work are made again unless `keep_merkle`
fn block_on_tip(
    t: &TestNode,
    keep_merkle: bool,
    edit: impl FnOnce(&mut Block),
) -> (Block, Hash256) {
    let tip = t.node.chain().tip().unwrap();
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
    edit(&mut block);
    if !keep_merkle {
        block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    }
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    let hash = divi_crypto::compute_block_hash(&block.header);
    (block, hash)
}

/// A transaction that spends an output that does not exist
fn spender(n: u8) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(
            OutPoint::new(Hash256::from_bytes([n; 32]), 0),
            Script::new(),
            0xffff_ffff,
        )],
        vout: vec![TxOut::new(Amount::from_sat(1), Script::new_p2pkh(&[n; 20]))],
        lock_time: 0,
    }
}

struct Case {
    name: &'static str,
    keep_merkle: bool,
    edit: fn(&mut Block),
    /// Divi Core's reject code and reason
    reject: (u8, &'static str),
}

const INVALID: u8 = 0x10;
const OBSOLETE: u8 = 0x11;

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "bad merkle root",
            keep_merkle: true,
            edit: |b| b.header.merkle_root = Hash256::from_bytes([9; 32]),
            reject: (INVALID, "bad-txnmrklroot"),
        },
        Case {
            name: "a repeated transaction",
            keep_merkle: true,
            edit: |b| {
                b.transactions.push(spender(1));
                b.transactions.push(spender(2));
                b.header.merkle_root = divi_crypto::compute_merkle_root(&b.transactions);
                b.transactions.push(spender(2));
            },
            reject: (INVALID, "bad-txns-duplicate"),
        },
        Case {
            name: "no coinbase",
            keep_merkle: false,
            edit: |b| b.transactions = vec![spender(1)],
            reject: (INVALID, "bad-cb-missing"),
        },
        Case {
            name: "two coinbases",
            keep_merkle: false,
            edit: |b| {
                let mut second = b.transactions[0].clone();
                second.vin[0].script_sig = Script::from_bytes(vec![1, 2, 3]);
                b.transactions.push(second);
            },
            reject: (INVALID, "bad-cb-multiple"),
        },
        Case {
            name: "a coinbase that does not begin with the height",
            keep_merkle: false,
            edit: |b| b.transactions[0].vin[0].script_sig = Script::from_bytes(vec![1, 77, 3]),
            reject: (INVALID, "bad-cb-height"),
        },
        Case {
            name: "a time three hours ahead",
            keep_merkle: false,
            edit: |b| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32;
                b.header.time = now + 3 * 60 * 60;
            },
            reject: (INVALID, "time-too-new"),
        },
        Case {
            name: "a time no later than the median past",
            keep_merkle: false,
            edit: |b| b.header.time = 1,
            reject: (INVALID, "time-too-old"),
        },
        Case {
            name: "version 2",
            keep_merkle: false,
            edit: |b| b.header.version = 2,
            reject: (OBSOLETE, "bad-version"),
        },
        Case {
            name: "a transaction without inputs",
            keep_merkle: false,
            edit: |b| {
                let mut tx = spender(1);
                tx.vin.clear();
                b.transactions.push(tx);
            },
            reject: (INVALID, "bad-txns-vin-empty"),
        },
        Case {
            name: "a transaction without outputs",
            keep_merkle: false,
            edit: |b| {
                let mut tx = spender(1);
                tx.vout.clear();
                b.transactions.push(tx);
            },
            reject: (INVALID, "bad-txns-vout-empty"),
        },
        Case {
            name: "a transaction over 100,000 bytes",
            keep_merkle: false,
            edit: |b| {
                let mut tx = spender(1);
                tx.vout[0].script_pubkey = Script::from_bytes(vec![0x51; 100_500]);
                b.transactions.push(tx);
            },
            reject: (INVALID, "bad-txns-oversize"),
        },
        Case {
            name: "a negative output",
            keep_merkle: false,
            edit: |b| {
                let mut tx = spender(1);
                tx.vout[0].value = Amount::from_sat(-1);
                b.transactions.push(tx);
            },
            reject: (INVALID, "bad-txns-vout-negative-or-toolarge"),
        },
        Case {
            name: "a block of more than 2,000,000 bytes",
            keep_merkle: false,
            edit: |b| {
                for n in 0..23 {
                    let mut tx = spender(n + 1);
                    tx.vout[0].script_pubkey = Script::from_bytes(vec![0x51; 90_000]);
                    b.transactions.push(tx);
                }
            },
            reject: (INVALID, "bad-blk-length"),
        },
        Case {
            name: "21,000 signature operations",
            keep_merkle: false,
            edit: |b| {
                let mut tx = spender(1);
                tx.vout[0].script_pubkey = Script::from_bytes(vec![0xac; 21_000]);
                b.transactions.push(tx);
            },
            reject: (INVALID, "bad-blk-sigops"),
        },
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_block_is_answered_with_its_reject() {
    let t = TestNode::start().await;
    for (k, case) in cases().into_iter().enumerate() {
        let (block, hash) = block_on_tip(&t, case.keep_merkle, case.edit);
        let mut peer = RawPeer::connect(&t, &format!("127.0.0.{}", 2 + k)).await;
        peer.handshake().await;
        peer.send("block", &serialize(&block)).await;
        let payload = peer
            .expect("reject", WAIT)
            .await
            .unwrap_or_else(|| panic!("{}: no reject", case.name));
        let (message, code, reason) = parse_reject(&payload);
        assert_eq!(
            (message.as_str(), code, reason.as_str()),
            ("block", case.reject.0, case.reject.1),
            "{}",
            case.name
        );
        assert_eq!(
            &payload[payload.len() - 32..],
            hash.as_bytes(),
            "{}: the hash",
            case.name
        );
        assert_eq!(t.node.chain().height(), 0, "{}: the tip moved", case.name);
    }
}

/// A valid block is taken and draws no reject
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_valid_block_draws_no_reject() {
    let t = TestNode::start().await;
    let (block, _) = block_on_tip(&t, false, |_| {});
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;
    peer.send("block", &serialize(&block)).await;
    assert_eq!(peer.expect("reject", QUIET).await, None);
    assert_eq!(t.node.chain().height(), 1);
}

/// A block whose parent the node does not know, offered without being asked for:
/// Divi Core answers with a getblocks that stops at the block (main.cpp:820-830),
/// and with one that stops at its parent when the peer sends it again
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_with_an_unknown_parent_is_answered_with_getblocks() {
    let t = TestNode::start().await;
    let (block, hash) = block_on_tip(&t, false, |b| {
        b.header.prev_block = Hash256::from_bytes([0x33; 32])
    });
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;
    // what the node says to a new peer on its own comes first
    while let Recv::Message(..) = peer.recv(std::time::Duration::from_secs(2)).await {}
    let stop_of =
        |payload: &[u8]| -> Hash256 { Hash256::from_slice(&payload[payload.len() - 32..]) };
    peer.send("block", &serialize(&block)).await;
    let asked = peer.expect("getblocks", WAIT).await.expect("getblocks");
    assert_eq!(stop_of(&asked), hash);
    peer.send("block", &serialize(&block)).await;
    let asked = peer
        .expect("getblocks", WAIT)
        .await
        .expect("getblocks again");
    assert_eq!(stop_of(&asked), Hash256::from_bytes([0x33; 32]));
}
