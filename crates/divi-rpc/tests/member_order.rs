// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Replies whose members and items come in the order Divi Core 3.0.0 writes
//! them (the replies scripts compare it on live nodes): an object's members in
//! the order its handler pushes them (json_spirit Object), irondivid's own
//! members after them, and lists in the order of the map divid takes them from.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    transaction::{Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType, SearchIndex};
use divi_wallet::{Address, HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

struct Node {
    chain: Arc<Chain>,
    wallet: Arc<WalletDb>,
    server: RpcServer,
    _dir: tempfile::TempDir,
}

/// A regtest node with the transaction, address and spent indexes and a wallet
fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let mut chain = Chain::new(
        db.clone(),
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    chain.enable_tx_index(Arc::new(TxIndex::open(dir.path().join("txindex")).unwrap()));
    chain.enable_search_index(Arc::new(SearchIndex::new(db, true, true)));
    let chain = Arc::new(chain);
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain.clone(), wallet.clone());
    Node {
        chain,
        wallet,
        server,
        _dir: dir,
    }
}

impl Node {
    fn ok(&self, method: &str, params: Vec<Value>) -> Value {
        let r = self.server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params: Params::Array(params),
        });
        assert!(
            r.error.is_none(),
            "{method}: {:?}",
            r.error.map(|e| e.message)
        );
        r.result.unwrap()
    }

    /// Mine a block with `txs` whose coinbase pays 1250 DIVI to `pay_to`; the
    /// wallet scans it
    fn mine(&self, txs: Vec<Transaction>, pay_to: &Address) -> Transaction {
        let tip = self.chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        let mut cb_sig = divi_storage::bip34_height_script(height);
        cb_sig.extend_from_slice(&height.to_le_bytes());
        block.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(cb_sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250 * COIN),
                Script::new_p2pkh(pay_to.hash.as_bytes()),
            )],
            lock_time: 0,
        });
        block.transactions.extend(txs);
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        let time = block.header.time;
        let txs = block.transactions.clone();
        let hash = self.chain.accept_block(block).unwrap().hash;
        self.wallet.scan_block(hash, height, time, &txs);
        self.server.set_height(height);
        txs[0].clone()
    }
}

fn nobody() -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest)
}

fn keys(v: &Value) -> Vec<&str> {
    v.as_object()
        .unwrap_or_else(|| panic!("not an object: {v}"))
        .keys()
        .map(String::as_str)
        .collect()
}

/// getblock: blockToJSON's members (JsonBlockHelpers.cpp:38-77), then
/// irondivid's mediantime and nTx
#[test]
fn getblock_members_are_in_cores_order() {
    let n = node();
    n.mine(vec![], &nobody());
    n.mine(vec![], &nobody());
    let hash = n.ok("getblockhash", vec![json!(1)]);
    assert_eq!(
        keys(&n.ok("getblock", vec![hash])),
        [
            "hash",
            "confirmations",
            "size",
            "height",
            "version",
            "merkleroot",
            "acc_checkpoint",
            "tx",
            "time",
            "nonce",
            "bits",
            "difficulty",
            "chainwork",
            "previousblockhash",
            "nextblockhash",
            "moneysupply",
            "mediantime",
            "nTx"
        ]
    );
}

/// getblockheader: blockHeaderToJSON's members (JsonBlockHelpers.cpp:80-91),
/// then irondivid's own
#[test]
fn getblockheader_members_are_in_cores_order() {
    let n = node();
    n.mine(vec![], &nobody());
    n.mine(vec![], &nobody());
    let hash = n.ok("getblockhash", vec![json!(1)]);
    assert_eq!(
        keys(&n.ok("getblockheader", vec![hash])),
        [
            "version",
            "previousblockhash",
            "merkleroot",
            "time",
            "bits",
            "nonce",
            "hash",
            "confirmations",
            "height",
            "mediantime",
            "difficulty",
            "chainwork",
            "nTx",
            "nextblockhash"
        ]
    );
}

/// A wallet with `n` mature coins of 1250 DIVI on new address-book addresses
fn funded(n: usize) -> (Node, Vec<Transaction>) {
    let node = node();
    let coinbases = (0..n)
        .map(|_| {
            let to = node.wallet.new_receiving_address().unwrap();
            node.wallet.set_label(&to, "").unwrap();
            node.mine(vec![], &to)
        })
        .collect();
    // Coinbase maturity 20 on regtest
    for _ in 0..20 {
        node.mine(vec![], &nobody());
    }
    (node, coinbases)
}

/// listunspent: an item's members as rpcrawtransaction.cpp:330-352 pushes them
/// (account after address), then irondivid's solvable and ischange
#[test]
fn listunspent_members_are_in_cores_order() {
    let (n, _) = funded(1);
    let list = n.ok("listunspent", vec![]);
    assert_eq!(
        keys(&list[0]),
        [
            "txid",
            "vout",
            "address",
            "account",
            "scriptPubKey",
            "amount",
            "confirmations",
            "spendable",
            "solvable",
            "ischange"
        ]
    );
}

/// listunspent: the confirmed coins, then the unconfirmed ones
/// (AvailableUtxoCollector.cpp:33-41), each in txid order
#[test]
fn listunspent_lists_confirmed_coins_before_unconfirmed() {
    let (n, coinbases) = funded(3);
    let confirmed: Vec<String> = coinbases[1..]
        .iter()
        .map(|c| c.txid().to_string())
        .collect();
    // A send from the first coin to the wallet whose txid comes before a
    // confirmed coin's, so txid order alone would put it among them
    let to = n.wallet.new_receiving_address().unwrap();
    let send = (1..200)
        .map(|fee| {
            let (mut tx, prev) = divi_wallet::TransactionBuilder::new()
                .add_input(
                    divi_primitives::transaction::OutPoint::new(coinbases[0].txid(), 0),
                    coinbases[0].vout[0].script_pubkey.clone(),
                )
                .add_output_to_address(Amount::from_sat(1250 * COIN - fee * 10_000), &to)
                .build();
            divi_wallet::TransactionSigner::new(n.wallet.keystore())
                .sign_all_inputs(&mut tx, &prev)
                .unwrap();
            tx
        })
        .find(|tx| confirmed.iter().any(|c| tx.txid().to_string() < *c))
        .unwrap();
    assert!(n.wallet.add_mempool_tx(&send));
    let list = n.ok("listunspent", vec![json!(0)]);
    let txids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["txid"].as_str().unwrap())
        .collect();
    let mut expected: Vec<&str> = confirmed.iter().map(String::as_str).collect();
    expected.sort();
    let send_txid = send.txid().to_string();
    expected.push(&send_txid);
    assert_eq!(txids, expected);
}

/// getwalletinfo: rpcwallet.cpp:2894-2906, then irondivid's own members
#[test]
fn getwalletinfo_members_are_in_cores_order() {
    let (n, _) = funded(1);
    assert_eq!(
        keys(&n.ok("getwalletinfo", vec![])),
        [
            "active_wallet",
            "walletversion",
            "balance",
            "unconfirmed_balance",
            "immature_balance",
            "spendable_balance",
            "vaulted_balance",
            "txcount",
            "keypoolsize",
            "encryption_status",
            "walletname",
            "keypoololdest",
            "paytxfee",
            "hdmasterkeyid"
        ]
    );
}

/// validateaddress of a wallet key: the pubkey with the visitor's members,
/// before the account (rpcmisc.cpp:236-247, :349-372)
#[test]
fn validateaddress_members_are_in_cores_order() {
    let n = node();
    let address = n.wallet.new_receiving_address().unwrap();
    n.wallet.set_label(&address, "").unwrap();
    let reply = n.ok("validateaddress", vec![json!(address.to_string())]);
    let order: Vec<&str> = keys(&reply)
        .into_iter()
        .filter(|k| !["hdkeypath", "hdchainid"].contains(k))
        .collect();
    assert_eq!(
        order,
        [
            "isvalid",
            "address",
            "scriptPubKey",
            "ismine",
            "iswatchonly",
            "isscript",
            "pubkey",
            "iscompressed",
            "account"
        ]
    );
}

/// getaddressesbyaccount: in the order of divid's address book, a std::map
/// keyed by CTxDestination: key hashes by their uint160, compared from the last
/// byte (rpcwallet.cpp:670, uint256.cpp:139-148)
#[test]
fn getaddressesbyaccount_is_in_address_book_order() {
    let n = node();
    let mut made: Vec<Address> = (0..8)
        .map(|_| n.wallet.new_receiving_address().unwrap())
        .collect();
    for a in &made {
        n.wallet.set_label(a, "acct").unwrap();
    }
    made.sort_by_key(|a| {
        let mut h = a.hash.as_bytes().to_vec();
        h.reverse();
        h
    });
    let expected: Vec<String> = made.iter().map(|a| a.to_string()).collect();
    assert_eq!(
        n.ok("getaddressesbyaccount", vec![json!("acct")]),
        json!(expected)
    );
}

/// getrawtransaction: hex, then TxToJSONExpanded's members with the block's
/// and size last (rpcrawtransaction.cpp:56-135, :245-246)
#[test]
fn getrawtransaction_members_are_in_cores_order() {
    let n = node();
    let coinbase = n.mine(vec![], &nobody());
    let reply = n.ok(
        "getrawtransaction",
        vec![json!(coinbase.txid().to_string()), json!(1)],
    );
    assert_eq!(
        keys(&reply),
        [
            "hex",
            "txid",
            "baretxid",
            "version",
            "locktime",
            "vin",
            "vout",
            "blockhash",
            "height",
            "confirmations",
            "time",
            "blocktime",
            "size"
        ]
    );
}

/// An input with the spent index: value, valueSat and address before
/// sequence (rpcrawtransaction.cpp:66-88)
#[test]
fn getrawtransaction_input_members_are_in_cores_order() {
    let n = node();
    let to = n.wallet.new_receiving_address().unwrap();
    let coinbase = n.mine(vec![], &to);
    for _ in 0..20 {
        n.mine(vec![], &nobody());
    }
    let (mut tx, prev) = divi_wallet::TransactionBuilder::new()
        .add_input(
            divi_primitives::transaction::OutPoint::new(coinbase.txid(), 0),
            coinbase.vout[0].script_pubkey.clone(),
        )
        .add_output_to_address(Amount::from_sat(1249 * COIN), &nobody())
        .build();
    divi_wallet::TransactionSigner::new(n.wallet.keystore())
        .sign_all_inputs(&mut tx, &prev)
        .unwrap();
    n.mine(vec![tx.clone()], &nobody());
    let reply = n.ok(
        "getrawtransaction",
        vec![json!(tx.txid().to_string()), json!(1)],
    );
    assert_eq!(
        keys(&reply["vin"][0]),
        [
            "txid",
            "vout",
            "scriptSig",
            "value",
            "valueSat",
            "address",
            "sequence"
        ]
    );
}

/// decoderawtransaction: TxToJSON's members (JsonTxHelpers.cpp:39-73)
#[test]
fn decoderawtransaction_members_are_in_cores_order() {
    let n = node();
    let coinbase = n.mine(vec![], &nobody());
    let hex = n.ok(
        "getrawtransaction",
        vec![json!(coinbase.txid().to_string())],
    );
    assert_eq!(
        keys(&n.ok("decoderawtransaction", vec![hex])),
        ["txid", "baretxid", "version", "locktime", "vin", "vout"]
    );
}

/// getinfo: rpcmisc.cpp:138-157, the wallet's members after protocolversion;
/// then irondivid's own
#[test]
fn getinfo_members_are_in_cores_order() {
    let n = node();
    n.mine(vec![], &nobody());
    assert_eq!(
        keys(&n.ok("getinfo", vec![])),
        [
            "version",
            "protocolversion",
            "walletversion",
            "balance",
            "blocks",
            "timeoffset",
            "connections",
            "proxy",
            "difficulty",
            "testnet",
            "moneysupply",
            "relayfee",
            "staking status",
            "errors",
            "keypoololdest",
            "keypoolsize",
            "paytxfee"
        ]
    );
}
