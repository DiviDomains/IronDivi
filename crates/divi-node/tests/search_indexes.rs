// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The address, spent and transaction indexes hold what Divi Core's hold
//! (IndexDatabaseUpdateCollector.cpp, BlockConnectionService.cpp, txdb.cpp,
//! rpcmisc.cpp), after blocks are connected and after a reorganisation
//! disconnects them, and keep the index settings the chain database was made
//! with.

use divi_crypto::KeyPair;
use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::RpcServer;
use divi_script::{StakingVaultScript, TransactionSignatureChecker};
use divi_wallet::{Address, Network};
use serde_json::{json, Value};
use std::path::Path;

const COIN: i64 = 100_000_000;
const FEE: i64 = 10_000_000;

/// Regtest coinbase maturity (Divi Core chainparams.cpp:479)
const MATURITY: u32 = 20;

fn hash160(kp: &KeyPair) -> [u8; 20] {
    *divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes()
}

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(&hash160(kp))
}

fn address(hash: [u8; 20]) -> String {
    Address::from_pubkey_hash(Hash160::from_bytes(hash), Network::Regtest).to_base58()
}

fn script_address(hash: [u8; 20]) -> String {
    Address::p2sh(Hash160::from_bytes(hash), Network::Regtest).to_base58()
}

/// The txid with every scriptSig cleared (Core's GetBareTxid)
fn bare_txid(tx: &Transaction) -> Hash256 {
    let mut stripped = tx.clone();
    for input in &mut stripped.vin {
        input.script_sig = Script::new();
    }
    stripped.txid()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Spend `coin`, paying `kp`, to `outputs`, signed by `kp`
fn spend(kp: &KeyPair, coin: OutPoint, value: i64, outputs: Vec<TxOut>) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffffffff)],
        vout: outputs,
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

struct Indexes {
    txindex: bool,
    addressindex: bool,
    spentindex: bool,
}

const ALL: Indexes = Indexes {
    txindex: true,
    addressindex: true,
    spentindex: true,
};

fn start_node(dir: &Path, indexes: &Indexes) -> Result<Node, divi_node::NodeError> {
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.to_path_buf();
    config.index.txindex = indexes.txindex;
    config.index.addressindex = indexes.addressindex;
    config.index.spentindex = indexes.spentindex;
    Node::new(config)
}

struct TestNode {
    dir: tempfile::TempDir,
    node: Node,
    rpc: RpcServer,
    key: KeyPair,
}

impl TestNode {
    fn new(indexes: &Indexes) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let node = start_node(dir.path(), indexes).unwrap();
        let rpc = RpcServer::new(node.chain().clone());
        rpc.set_mempool(node.mempool().clone());
        TestNode {
            dir,
            node,
            rpc,
            key: KeyPair::new_random(),
        }
    }

    /// The reply to an RPC call: its result, or its error message
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let request = serde_json::from_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        }))
        .unwrap();
        let reply = serde_json::to_value(self.rpc.handle_request(request)).unwrap();
        match reply.get("error") {
            Some(e) if !e.is_null() => Err(e["message"].as_str().unwrap_or("").to_string()),
            _ => Ok(reply["result"].clone()),
        }
    }

    fn ok(&self, method: &str, params: Value) -> Value {
        self.call(method, params.clone())
            .unwrap_or_else(|e| panic!("{} {} failed: {}", method, params, e))
    }

    /// A block on `parent` paying its coinbase to the node's key (`tag` makes
    /// blocks of different branches differ) and confirming `txs`
    fn block_on(&self, parent: Hash256, tag: u8, txs: &[Transaction]) -> Block {
        let parent = self.node.chain().get_block_index(&parent).unwrap().unwrap();
        let height = parent.height + 1;
        let mut sig = divi_storage::bip34_height_script(height);
        sig.push(tag);
        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), p2pkh(&self.key))],
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

    fn tip(&self) -> Hash256 {
        self.node.chain().tip().unwrap().hash
    }

    fn height(&self) -> u32 {
        self.node.chain().height()
    }

    /// Extend the active chain by one block and return its coinbase coin
    fn mine(&self, txs: &[Transaction]) -> OutPoint {
        let block = self.block_on(self.tip(), 0, txs);
        let coin = OutPoint::new(block.transactions[0].txid(), 0);
        self.node.chain().accept_block(block).unwrap();
        coin
    }

    /// A coinbase coin spendable in the next block
    fn mature_coin(&self) -> OutPoint {
        let coin = self.mine(&[]);
        for _ in 0..MATURITY {
            self.mine(&[]);
        }
        coin
    }

    /// Build `n` blocks on `fork`, the last confirming `last_txs`, and hand
    /// them to the chain; they must become the active chain
    fn branch(&self, fork: Hash256, n: usize, last_txs: &[Transaction]) {
        let mut parent = fork;
        for i in 0..n {
            let txs = if i + 1 == n { last_txs } else { &[] };
            let block = self.block_on(parent, 1, txs);
            parent = self.node.chain().accept_block(block).unwrap().hash;
        }
        assert_eq!(
            self.tip(),
            parent,
            "the branch must become the active chain"
        );
    }
}

/// One send paying a key-hash address, a script-hash address, a staking
/// vault and a data output, and a second send spending the first output
struct Sends {
    coin: OutPoint,
    payee: [u8; 20],
    script_hash: [u8; 20],
    vault_owner: [u8; 20],
    vault_key: [u8; 20],
    vault_script: Script,
    first: Transaction,
    first_height: u32,
    second: Transaction,
}

fn make_sends(t: &TestNode) -> Sends {
    let coin = t.mature_coin();
    let payee_key = KeyPair::new_random();
    let payee = hash160(&payee_key);
    let script_hash = [0x33; 20];
    let vault_owner = hash160(&KeyPair::new_random());
    let vault_key = hash160(&KeyPair::new_random());
    let vault_script = StakingVaultScript::new(vault_owner, vault_key).to_script();
    let first = spend(
        &t.key,
        coin,
        1250 * COIN,
        vec![
            TxOut::new(Amount::from_sat(100 * COIN), Script::new_p2pkh(&payee)),
            TxOut::new(Amount::from_sat(200 * COIN), Script::new_p2sh(&script_hash)),
            TxOut::new(Amount::from_sat(300 * COIN), vault_script.clone()),
            TxOut::new(
                Amount::from_sat(0),
                Script::from_bytes(vec![0x6a, 0x01, 0x07]),
            ),
            TxOut::new(Amount::from_sat(650 * COIN - FEE), p2pkh(&t.key)),
        ],
    );
    t.mine(std::slice::from_ref(&first));
    let first_height = t.height();
    let second = spend(
        &payee_key,
        OutPoint::new(first.txid(), 0),
        100 * COIN,
        vec![TxOut::new(
            Amount::from_sat(100 * COIN - FEE),
            p2pkh(&t.key),
        )],
    );
    t.mine(std::slice::from_ref(&second));
    Sends {
        coin,
        payee,
        script_hash,
        vault_owner,
        vault_key,
        vault_script,
        first,
        first_height,
        second,
    }
}

/// Connected blocks: each output paying a key hash, script hash or vault is
/// a receive under its address type and hash (a vault under its owner's key
/// hash, type 3), each input spending one is a spend (a negative delta, its
/// unspent entry gone, a spent entry naming the input), and data outputs are
/// not indexed (IndexDatabaseUpdateCollector.cpp:12-97)
#[test]
fn connected_blocks_are_indexed_as_core_indexes_them() {
    let t = TestNode::new(&ALL);
    let s = make_sends(&t);
    let h = s.first_height;
    let first = s.first.txid().to_string();
    let second = s.second.txid().to_string();
    let payee = address(s.payee);

    assert_eq!(
        t.ok("getaddressdeltas", json!([payee])),
        json!([
            {"satoshis": 100 * COIN, "txid": first, "index": 0, "blockindex": 1, "height": h, "address": payee},
            {"satoshis": -100 * COIN, "txid": second, "index": 0, "blockindex": 1, "height": h + 1, "address": payee},
        ])
    );
    assert_eq!(t.ok("getaddressutxos", json!([payee])), json!([]));
    assert_eq!(
        t.ok("getaddressbalance", json!([payee])),
        json!({"balance": 0, "received": 100 * COIN})
    );
    assert_eq!(
        t.ok("getaddresstxids", json!([payee])),
        json!([first, second])
    );

    let p2sh = script_address(s.script_hash);
    assert_eq!(
        t.ok("getaddressutxos", json!([{"addresses": [p2sh]}])),
        json!([{
            "address": p2sh, "txid": first, "outputIndex": 1,
            "script": hex(Script::new_p2sh(&s.script_hash).as_bytes()),
            "satoshis": 200 * COIN, "height": h,
        }])
    );

    // The vault is found under its owner's address with only_vaults, and
    // under nothing else
    let owner = address(s.vault_owner);
    assert_eq!(
        t.ok("getaddressutxos", json!([owner, true])),
        json!([{
            "address": owner, "txid": first, "outputIndex": 2,
            "script": hex(s.vault_script.as_bytes()),
            "satoshis": 300 * COIN, "height": h,
        }])
    );
    assert_eq!(t.ok("getaddressutxos", json!([owner])), json!([]));
    assert_eq!(
        t.ok("getaddressutxos", json!([address(s.vault_key), true])),
        json!([])
    );
    assert!(
        t.call("getaddressutxos", json!([p2sh, true])).is_err(),
        "only_vaults refuses a script-hash address"
    );

    // The node's own key: the spent coinbase is gone from its unspent outputs
    let own = address(hash160(&t.key));
    let utxos = t.ok("getaddressutxos", json!([own]));
    let coin_txid = s.coin.txid.to_string();
    assert!(
        !utxos
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["txid"] == json!(coin_txid)),
        "a spent coin is not an unspent output"
    );

    // Spent index: the input that spent each output
    assert_eq!(
        t.ok("getspentinfo", json!([{"txid": coin_txid, "index": 0}])),
        json!({"txid": first, "index": 0, "height": h})
    );
    assert_eq!(
        t.ok("getspentinfo", json!([{"txid": first, "index": 0}])),
        json!({"txid": second, "index": 0, "height": h + 1})
    );
    assert_eq!(
        t.call("getspentinfo", json!([{"txid": first, "index": 1}])),
        Err("Unable to get spent info".to_string())
    );
}

/// Height ranges and several addresses (rpcmisc.cpp getaddresstxids,
/// getaddressdeltas; txdb.cpp ReadAddressIndex)
#[test]
fn ranges_and_several_addresses_read_as_core_reads_them() {
    let t = TestNode::new(&ALL);
    let s = make_sends(&t);
    let h = s.first_height;
    let first = s.first.txid().to_string();
    let second = s.second.txid().to_string();
    let payee = address(s.payee);
    let p2sh = script_address(s.script_hash);

    let ranged = |start: u32, end: u32| {
        t.ok(
            "getaddresstxids",
            json!([{"addresses": [payee], "start": start, "end": end}]),
        )
    };
    assert_eq!(ranged(h + 1, h + 1), json!([second]));
    assert_eq!(ranged(h, h), json!([first]));
    assert_eq!(ranged(1, h - 1), json!([]));

    let deltas = t.ok(
        "getaddressdeltas",
        json!([{"addresses": [payee], "start": h, "end": h + 1, "chainInfo": true}]),
    );
    assert_eq!(deltas["deltas"].as_array().unwrap().len(), 2);
    let hash_at = |height: u32| {
        t.node
            .chain()
            .get_block_index_by_height(height)
            .unwrap()
            .unwrap()
            .hash
            .to_string()
    };
    assert_eq!(deltas["start"], json!({"hash": hash_at(h), "height": h}));
    assert_eq!(
        deltas["end"],
        json!({"hash": hash_at(h + 1), "height": h + 1})
    );
    assert_eq!(
        t.call(
            "getaddressdeltas",
            json!([{"addresses": [payee], "start": h + 1, "end": h}])
        ),
        Err("End value is expected to be greater than start".to_string())
    );

    // Several addresses: one txid per (height, txid), by height then txid
    let mut both = vec![(h, first.clone()), (h + 1, second.clone())];
    both.sort();
    assert_eq!(
        t.ok("getaddresstxids", json!([{"addresses": [p2sh, payee]}])),
        json!(both.into_iter().map(|(_, txid)| txid).collect::<Vec<_>>())
    );
    assert_eq!(
        t.ok("getaddressbalance", json!([{"addresses": [payee, p2sh]}])),
        json!({"balance": 200 * COIN, "received": 300 * COIN})
    );
}

/// A reorganisation disconnecting the two sends erases their deltas and
/// unspent entries, restores the coins they spent and erases their spent
/// entries. The restored unspent entry carries the disconnected block's
/// height, as Core writes it (IndexDatabaseUpdateCollector.cpp:125-129).
#[test]
fn disconnected_blocks_are_reversed_as_core_reverses_them() {
    let t = TestNode::new(&ALL);
    let s = make_sends(&t);
    let h = s.first_height;
    let fork = t
        .node
        .chain()
        .get_block_index_by_height(h - 1)
        .unwrap()
        .unwrap()
        .hash;
    t.branch(fork, 3, &[]);

    let payee = address(s.payee);
    assert_eq!(t.ok("getaddressdeltas", json!([payee])), json!([]));
    assert_eq!(t.ok("getaddressutxos", json!([payee])), json!([]));
    assert_eq!(
        t.ok("getaddressbalance", json!([payee])),
        json!({"balance": 0, "received": 0})
    );
    assert_eq!(
        t.ok("getaddressutxos", json!([script_address(s.script_hash)])),
        json!([])
    );
    assert_eq!(
        t.ok("getaddressutxos", json!([address(s.vault_owner), true])),
        json!([])
    );

    let coin_txid = s.coin.txid.to_string();
    let own = address(hash160(&t.key));
    let utxos = t.ok("getaddressutxos", json!([own]));
    let restored: Vec<&Value> = utxos
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["txid"] == json!(coin_txid))
        .collect();
    assert_eq!(restored.len(), 1, "the spent coin is unspent again");
    assert_eq!(
        restored[0]["height"],
        json!(h),
        "restored at the disconnected block's height, as Core restores it"
    );
    assert_eq!(
        t.call("getspentinfo", json!([{"txid": coin_txid, "index": 0}])),
        Err("Unable to get spent info".to_string())
    );

    // Confirmed again on the new chain: indexed at its new place
    let first = s.first.txid().to_string();
    t.mine(std::slice::from_ref(&s.first));
    let now = t.height();
    assert_eq!(
        t.ok("getaddressdeltas", json!([payee])),
        json!([{"satoshis": 100 * COIN, "txid": first, "index": 0, "blockindex": 1, "height": now, "address": payee}])
    );
    assert_eq!(
        t.ok("getspentinfo", json!([{"txid": coin_txid, "index": 0}])),
        json!({"txid": first, "index": 0, "height": now})
    );
}

/// Core erases spent entries on disconnect only when the address index is on
/// (BlockConnectionService.cpp:187-192): with the spent index alone they stay
#[test]
fn spent_entries_outlive_a_disconnect_without_the_address_index() {
    let t = TestNode::new(&Indexes {
        txindex: true,
        addressindex: false,
        spentindex: true,
    });
    let s = make_sends(&t);
    let h = s.first_height;
    let fork = t
        .node
        .chain()
        .get_block_index_by_height(h - 1)
        .unwrap()
        .unwrap()
        .hash;
    t.branch(fork, 3, &[]);
    assert_eq!(
        t.ok(
            "getspentinfo",
            json!([{"txid": s.coin.txid.to_string(), "index": 0}])
        ),
        json!({"txid": s.first.txid().to_string(), "index": 0, "height": h})
    );
}

/// The transaction index keeps a disconnected block's transactions, shown at
/// height -1 with no confirmations (Core's DisconnectBlock leaves the index;
/// rpcrawtransaction.cpp:223-232)
#[test]
fn transaction_index_keeps_disconnected_transactions() {
    let t = TestNode::new(&ALL);
    let s = make_sends(&t);
    let first = s.first.txid().to_string();
    let old_block = t
        .node
        .chain()
        .get_block_index_by_height(s.first_height)
        .unwrap()
        .unwrap()
        .hash;
    let fork = t
        .node
        .chain()
        .get_block_index_by_height(s.first_height - 1)
        .unwrap()
        .unwrap()
        .hash;
    t.branch(fork, 3, &[]);
    let after = t.ok("getrawtransaction", json!([first, 1]));
    assert_eq!(after["txid"], json!(first));
    assert_eq!(after["blockhash"], json!(old_block.to_string()));
    assert_eq!(after["height"], json!(-1));
    assert_eq!(after["confirmations"], json!(0));
}

/// Transactions are found by bare txid too, in blocks and in the mempool
/// (txdb.cpp:206-231, TransactionDiskAccessor.cpp GetTransaction)
#[test]
fn transactions_are_found_by_bare_txid() {
    let t = TestNode::new(&ALL);
    let s = make_sends(&t);
    let bare = bare_txid(&s.first);
    assert_ne!(bare, s.first.txid());
    assert_eq!(
        t.ok("getrawtransaction", json!([bare.to_string(), 1]))["txid"],
        json!(s.first.txid().to_string())
    );

    let pending = spend(
        &t.key,
        t.mature_coin(),
        1250 * COIN,
        vec![TxOut::new(
            Amount::from_sat(1250 * COIN - FEE),
            p2pkh(&t.key),
        )],
    );
    t.node
        .mempool()
        .add(pending.clone(), Amount::from_sat(FEE))
        .unwrap();
    assert_eq!(
        t.ok(
            "getrawtransaction",
            json!([bare_txid(&pending).to_string(), 1])
        )["txid"],
        json!(pending.txid().to_string())
    );
}

/// The index settings are those the chain database was made with: the
/// address and spent indexes stay as they were, a changed -txindex refuses
/// to start (ChainExtensionService.cpp:700-706, init.cpp:1103-1106)
#[test]
fn index_settings_stay_with_the_chain_database() {
    let t = TestNode::new(&ALL);
    let s = make_sends(&t);
    let dir = t.dir;
    drop(t.rpc);
    drop(t.node);

    let none = Indexes {
        txindex: true,
        addressindex: false,
        spentindex: false,
    };
    let node = start_node(dir.path(), &none).unwrap();
    let rpc = RpcServer::new(node.chain().clone());
    let call = |method: &str, params: Value| {
        let request = serde_json::from_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        }))
        .unwrap();
        serde_json::to_value(rpc.handle_request(request)).unwrap()
    };
    let reply = call("getaddressutxos", json!([script_address(s.script_hash)]));
    assert_eq!(
        reply["result"][0]["txid"],
        json!(s.first.txid().to_string()),
        "the address index stays on: {}",
        reply
    );
    let reply = call(
        "getspentinfo",
        json!([{"txid": s.first.txid().to_string(), "index": 0}]),
    );
    assert_eq!(
        reply["result"]["txid"],
        json!(s.second.txid().to_string()),
        "the spent index stays on: {}",
        reply
    );
    drop(rpc);
    drop(node);

    let no_txindex = Indexes {
        txindex: false,
        addressindex: true,
        spentindex: true,
    };
    match start_node(dir.path(), &no_txindex) {
        Err(e) => assert!(
            e.to_string().contains("-reindex to change -txindex"),
            "{}",
            e
        ),
        Ok(_) => panic!("a changed -txindex must refuse to start"),
    }

    // A new chain database takes the settings it is made with
    let fresh = tempfile::tempdir().unwrap();
    let node = start_node(fresh.path(), &no_txindex).unwrap();
    drop(node);
    assert!(start_node(fresh.path(), &no_txindex).is_ok());
}

/// Drop the stored index flags, as a database from before they were kept
fn forget_index_flags(dir: &Path) {
    let db = divi_storage::ChainDatabase::open(dir.join("chainstate")).unwrap();
    for key in [
        &b"flag_txindex"[..],
        b"flag_addressindex",
        b"flag_spentindex",
    ] {
        db.delete_metadata(key).unwrap();
    }
}

/// A database with no stored index flags that ran with -txindex=0, started
/// with the default -txindex=1: as in Divi Core, either the index covers
/// every block or the start is refused (init.cpp:1103-1106), never an index
/// of only the newest blocks. The chain is longer than the 100 blocks the
/// index catch-up rechecks; it is written straight to the chain database
/// (proof-of-work blocks past 100, no index flags, no transaction index), as
/// an older irondivid run with -txindex=0 left it.
#[test]
fn txindex_switched_on_over_an_unflagged_database_covers_every_block() {
    let start = |dir: &Path, txindex: bool| {
        start_node(
            dir,
            &Indexes {
                txindex,
                addressindex: false,
                spentindex: false,
            },
        )
    };
    let mine = |chain: &divi_storage::Chain| -> Hash256 {
        let parent = chain.tip().unwrap();
        let mut sig = divi_storage::bip34_height_script(parent.height + 1);
        sig.push(0);
        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(COIN),
                Script::new_p2pkh(&[7; 20]),
            )],
            lock_time: 0,
        };
        let txid = coinbase.txid();
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = parent.hash;
        block.header.time = parent.time + 60;
        block.header.bits = 0x207fffff;
        block.transactions = vec![coinbase];
        block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        chain.accept_block(block).unwrap();
        txid
    };

    let dir = tempfile::tempdir().unwrap();
    let block2 = {
        let db = std::sync::Arc::new(
            divi_storage::ChainDatabase::open(dir.path().join("chainstate")).unwrap(),
        );
        let mut params = divi_storage::ChainParams::for_network(
            divi_storage::NetworkType::Regtest,
            ChainMode::Divi,
        );
        params.check_block_work = false;
        let chain = divi_storage::Chain::new(db, params).unwrap();
        let txids: Vec<Hash256> = (0..120).map(|_| mine(&chain)).collect();
        assert_eq!(chain.height(), 120);
        txids[1]
    };
    forget_index_flags(dir.path());

    match start(dir.path(), true) {
        Err(e) => assert!(e.to_string().contains("-reindex to change -txindex"), "{e}"),
        Ok(node) => {
            let rpc = RpcServer::new(node.chain().clone());
            let request = serde_json::from_value(json!({
                "jsonrpc": "2.0", "id": 1, "method": "getrawtransaction",
                "params": [block2.to_string()],
            }))
            .unwrap();
            let reply = serde_json::to_value(rpc.handle_request(request)).unwrap();
            assert!(
                reply["error"].is_null() && reply["result"].is_string(),
                "block 2's transaction is not indexed: {reply}"
            );
            drop(rpc);
            drop(node);
            // and the next start keeps it
            assert!(start(dir.path(), true).is_ok());
        }
    }
}

/// A database installed from a snapshot has no blocks below its base, so it
/// cannot have a full transaction index: the index is recorded as off, the
/// node starts, and later starts with the default -txindex=1 still start
#[test]
fn snapshot_database_runs_without_a_transaction_index() {
    let none = Indexes {
        txindex: false,
        addressindex: false,
        spentindex: false,
    };
    let t = TestNode::new(&none);
    for _ in 0..5 {
        t.mine(&[]);
    }
    let tip = t.tip();
    let dir = t.dir;
    drop(t.rpc);
    drop(t.node);
    forget_index_flags(dir.path());
    {
        let db = divi_storage::ChainDatabase::open(dir.path().join("chainstate")).unwrap();
        db.set_snapshot_base(5, &tip).unwrap();
    }

    let txindex = Indexes {
        txindex: true,
        addressindex: false,
        spentindex: false,
    };
    drop(start_node(dir.path(), &txindex).unwrap());
    let db = divi_storage::ChainDatabase::open(dir.path().join("chainstate")).unwrap();
    let flags = divi_storage::search_index::IndexFlags::load(&db)
        .unwrap()
        .unwrap();
    assert!(
        !flags.txindex,
        "a snapshot database recorded the index as on"
    );
    drop(db);
    assert!(start_node(dir.path(), &txindex).is_ok());
}
