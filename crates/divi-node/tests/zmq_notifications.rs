// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! hashtx is sent in Divi Core's order: when a transaction enters the
//! mempool; for a connected block, the mempool transactions it conflicts
//! with and then its own; for a disconnected block, the transactions the
//! mempool takes back and then the block's own, and not again when the
//! mempool here takes them back after the reorganisation
//! (ChainTipManager.cpp:139-190, MempoolConsensus.cpp:419). A subscriber
//! written here speaks ZMTP 3.0.

use divi_crypto::KeyPair;
use divi_node::config::NodeConfig;
use divi_node::zmq::{ZmqConfig, ZmqNotifier};
use divi_node::{update_mempool_after_reorg, Node};
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_script::TransactionSignatureChecker;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;
const MATURITY: u32 = 20;

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes())
}

fn spend(kp: &KeyPair, coin: OutPoint, value: i64, fee: i64) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffffffff)],
        vout: vec![TxOut::new(Amount::from_sat(value - fee), p2pkh(kp))],
        lock_time: 0,
    };
    let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_sat(value));
    let sighash = checker.signature_hash(&p2pkh(kp), 1);
    let mut sig = divi_crypto::sign_hash(kp.secret_key(), &sighash)
        .unwrap()
        .to_der();
    sig.push(1);
    let pubkey = kp.public_key().to_bytes();
    let mut ss = vec![sig.len() as u8];
    ss.extend_from_slice(&sig);
    ss.push(pubkey.len() as u8);
    ss.extend_from_slice(&pubkey);
    tx.vin[0].script_sig = Script::from_bytes(ss);
    tx
}

/// A block on `parent` paying its coinbase to `kp`, confirming `txs`
fn block_on(node: &Node, kp: &KeyPair, parent: Hash256, tag: u8, txs: &[Transaction]) -> Block {
    let parent = node.chain().get_block_index(&parent).unwrap().unwrap();
    let height = parent.height + 1;
    let mut sig = divi_storage::bip34_height_script(height);
    sig.push(tag);
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
        vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), p2pkh(kp))],
        lock_time: 0,
    };
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = parent.hash;
    block.header.time = parent.time + 60 + u32::from(tag);
    block.header.bits = 0x207fffff;
    block.transactions = vec![coinbase];
    block.transactions.extend_from_slice(txs);
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    block
}

fn free_port() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let seed = std::collections::hash_map::RandomState::new();
    for i in 0u32..1000 {
        let mut h = seed.build_hasher();
        h.write_u32(i);
        let port = 20000 + (h.finish() % 12768) as u16;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port in 20000-32767");
}

struct Subscriber(TcpStream);

fn frame(body: &[u8], command: bool) -> Vec<u8> {
    let mut out = vec![if command { 4 } else { 0 }, body.len() as u8];
    out.extend_from_slice(body);
    out
}

impl Subscriber {
    fn connect(port: u16) -> Self {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut greeting = [0u8; 64];
        greeting[0] = 0xff;
        greeting[9] = 0x7f;
        greeting[10] = 3;
        greeting[12..16].copy_from_slice(b"NULL");
        s.write_all(&greeting).unwrap();
        let mut peer = [0u8; 64];
        s.read_exact(&mut peer).unwrap();
        let mut ready = vec![5u8];
        ready.extend_from_slice(b"READY");
        ready.push(11);
        ready.extend_from_slice(b"Socket-Type");
        ready.extend_from_slice(&3u32.to_be_bytes());
        ready.extend_from_slice(b"SUB");
        s.write_all(&frame(&ready, true)).unwrap();
        let mut sub = Subscriber(s);
        assert!(sub.frame().unwrap().0, "READY");
        sub.0.write_all(&frame(b"\x01hashtx", false)).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        sub
    }

    fn frame(&mut self) -> Option<(bool, bool, Vec<u8>)> {
        let mut head = [0u8; 2];
        self.0.read_exact(&mut head).ok()?;
        let mut body = vec![0u8; head[1] as usize];
        self.0.read_exact(&mut body).ok()?;
        Some((head[0] & 4 != 0, head[0] & 1 != 0, body))
    }

    /// The txids of the next `n` hashtx messages, checking the sequence numbers
    fn hashtx(&mut self, n: usize, first_sequence: u32) -> Vec<String> {
        (0..n)
            .map(|i| {
                let (_, _, topic) = self.frame().expect("a message");
                assert_eq!(topic, b"hashtx");
                let (_, _, body) = self.frame().unwrap();
                let (_, more, seq) = self.frame().unwrap();
                assert!(!more);
                assert_eq!(
                    u32::from_le_bytes(seq.try_into().unwrap()),
                    first_sequence + i as u32
                );
                body.iter().map(|b| format!("{b:02x}")).collect::<String>()
            })
            .collect()
    }

    fn quiet(&mut self) -> bool {
        self.0
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let quiet = self.frame().is_none();
        self.0
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        quiet
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hashtx_follows_cores_order_through_a_reorganisation() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    let node = Node::new(config).unwrap();
    let key = KeyPair::new_random();
    let mine = |txs: &[Transaction]| {
        let tip = node.chain().tip().unwrap().hash;
        let block = block_on(&node, &key, tip, 0, txs);
        let coinbase = block.transactions[0].txid();
        node.chain().accept_block(block).unwrap();
        coinbase
    };
    let coin = OutPoint::new(mine(&[]), 0);
    for _ in 0..MATURITY {
        mine(&[]);
    }

    let port = free_port();
    let _zmq = ZmqNotifier::start(
        &ZmqConfig {
            hashtx: Some(format!("tcp://127.0.0.1:{port}")),
            ..Default::default()
        },
        node.chain(),
        node.mempool(),
    )
    .expect("bound");
    let mut sub = Subscriber::connect(port);
    // Sequence 0 went to the genesis transaction of the new data directory
    let mut seq = 1;
    let id = |tx: &Transaction| tx.txid().to_string();

    // Into the mempool
    let a = spend(&key, coin, 1250 * COIN, FEE);
    node.mempool()
        .add(a.clone(), Amount::from_sat(FEE))
        .unwrap();
    assert_eq!(sub.hashtx(1, seq), vec![id(&a)]);
    seq += 1;

    // A block with it: the block's transactions
    let fork = node.chain().tip().unwrap().hash;
    let cb = mine(std::slice::from_ref(&a));
    node.mempool().remove_for_block(&[a.txid()]);
    assert_eq!(sub.hashtx(2, seq), vec![cb.to_string(), id(&a)]);
    seq += 2;

    // Two blocks on the parent replace it: `a` back in the mempool, then the
    // disconnected block's transactions, then each new block's
    let mut parent = fork;
    let mut orphaned = Vec::new();
    let mut new_coinbases = Vec::new();
    for _ in 0..2 {
        let block = block_on(&node, &key, parent, 1, &[]);
        new_coinbases.push(block.transactions[0].txid().to_string());
        let result = node.chain().accept_block(block).unwrap();
        parent = result.hash;
        if result.reorg_fork_height.is_some() {
            orphaned = result.orphaned_transactions;
        }
    }
    let mut expected = vec![id(&a), cb.to_string(), id(&a)];
    expected.extend(new_coinbases);
    assert_eq!(sub.hashtx(expected.len(), seq), expected);
    seq += expected.len() as u32;
    // The mempool here takes `a` back after the reorganisation: not sent again
    update_mempool_after_reorg(node.chain(), node.mempool(), orphaned);
    assert!(node.mempool().contains(&a.txid()));
    assert!(sub.quiet());

    // A block spending the same coin: first `a`, which it conflicts with
    let a2 = spend(&key, coin, 1250 * COIN, 2 * FEE);
    let cb = mine(std::slice::from_ref(&a2));
    assert_eq!(sub.hashtx(3, seq), vec![id(&a), cb.to_string(), id(&a2)]);
    assert!(sub.quiet());
}
