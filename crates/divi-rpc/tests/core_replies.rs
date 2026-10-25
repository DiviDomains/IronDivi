// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Replies and errors of chain, raw transaction and wallet RPCs as Divi Core
//! 3.0.0 gives them (rpcblockchain.cpp, JsonBlockHelpers.cpp, JsonTxHelpers.cpp,
//! rpcrawtransaction.cpp, rpcdump.cpp, rpcwallet.cpp, rpcserver.cpp).

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType, SearchIndex};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
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
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, (i32, String)> {
        let r = self.server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params: Params::Array(params),
        });
        match r.error {
            Some(e) => Err((e.code, e.message)),
            None => Ok(r.result.unwrap()),
        }
    }

    fn ok(&self, method: &str, params: Vec<Value>) -> Value {
        self.call(method, params)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }

    fn err(&self, method: &str, params: Vec<Value>) -> (i32, String) {
        match self.call(method, params) {
            Err(e) => e,
            Ok(v) => panic!("{method} answered {v}, expected an error"),
        }
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

/// The genesis block as Divi Core shows it: chainwork counts its own work
/// (2 for regtest's 0x207fffff), no previousblockhash key, moneysupply 0
#[test]
fn genesis_block_fields() {
    let n = node();
    let genesis = n.ok("getblockhash", vec![json!(0)]);
    let block = n.ok("getblock", vec![genesis.clone()]);
    let work = format!("{:064x}", 2);
    assert_eq!(block["chainwork"], json!(work), "{block}");
    assert!(block.get("previousblockhash").is_none(), "{block}");
    assert_eq!(block["moneysupply"], json!(0.0), "{block}");
    let header = n.ok("getblockheader", vec![genesis]);
    assert_eq!(header["chainwork"], json!(work), "{header}");
    assert!(header.get("previousblockhash").is_none(), "{header}");
    let info = n.ok("getblockchaininfo", vec![]);
    assert_eq!(info["chainwork"], json!(work), "{info}");

    // one more block adds its own work: 4
    n.mine(vec![], &nobody());
    let tip = n.ok("getbestblockhash", vec![]);
    let block = n.ok("getblock", vec![tip]);
    assert_eq!(block["chainwork"], json!(format!("{:064x}", 4)), "{block}");
}

/// getblockhash out of range is -8; a block hash that names no block is -5
/// "Block not found", whatever the text (rpcblockchain.cpp:162-163, :214-216)
#[test]
fn block_lookup_errors() {
    let n = node();
    let range = (-8, "Block height out of range".to_string());
    assert_eq!(n.err("getblockhash", vec![json!(-1)]), range);
    assert_eq!(n.err("getblockhash", vec![json!(5)]), range);
    let not_found = (-5, "Block not found".to_string());
    for hash in [json!("zz"), json!("00".repeat(32))] {
        assert_eq!(n.err("getblock", vec![hash.clone()]), not_found);
        assert_eq!(n.err("getblockheader", vec![hash]), not_found);
    }
}

/// help for an unknown command is text, not an error (rpcserver.cpp:283-285)
#[test]
fn help_for_unknown_command() {
    let n = node();
    assert_eq!(
        n.ok("help", vec![json!("nosuch")]),
        json!("help: unknown command: nosuch")
    );
}

/// Scripts carry reqSigs whenever they have destinations, decodescript always
/// gives p2sh, and bad hex is -8 (JsonTxHelpers.cpp:15-37, rpcrawtransaction.cpp:527-564)
#[test]
fn scripts_as_core_shows_them() {
    let n = node();
    let p2pkh = hex::encode(Script::new_p2pkh(&[7; 20]).as_bytes());
    let d = n.ok("decodescript", vec![json!(p2pkh)]);
    assert_eq!(d["reqSigs"], json!(1), "{d}");
    assert_eq!(d["type"], json!("pubkeyhash"), "{d}");
    let p2sh = hex::encode(Script::new_p2sh(&[7; 20]).as_bytes());
    let d = n.ok("decodescript", vec![json!(p2sh)]);
    assert!(d["p2sh"].is_string(), "{d}");
    assert_eq!(
        n.err("decodescript", vec![json!("zz")]),
        (
            -8,
            "argument must be hexadecimal string (not 'zz')".to_string()
        )
    );

    // decoderawtransaction shows reqSigs for a one-key output
    let raw = n.ok(
        "createrawtransaction",
        vec![
            json!([{"txid": "11".repeat(32), "vout": 0}]),
            json!({ nobody().to_base58(): 1.5 }),
        ],
    );
    let d = n.ok("decoderawtransaction", vec![raw]);
    assert_eq!(d["vout"][0]["scriptPubKey"]["reqSigs"], json!(1), "{d}");
}

/// Raw transaction argument errors (rpcrawtransaction.cpp:166, :361-462, :487)
#[test]
fn raw_transaction_errors() {
    let n = node();
    let failed = (-22, "TX decode failed".to_string());
    assert_eq!(n.err("decoderawtransaction", vec![json!("zz")]), failed);
    assert_eq!(n.err("decoderawtransaction", vec![json!("00")]), failed);
    assert_eq!(
        n.err("getrawtransaction", vec![json!("zz"), json!(1)]),
        (
            -8,
            "parameter 1 must be hexadecimal string (not 'zz')".to_string()
        )
    );
    let to = json!({ nobody().to_base58(): 1 });
    let txid = "11".repeat(32);
    assert_eq!(
        n.err(
            "createrawtransaction",
            vec![json!([{"txid": txid, "vout": -1}]), to.clone()]
        ),
        (-8, "Invalid parameter, vout must be positive".to_string())
    );
    assert_eq!(
        n.err("createrawtransaction", vec![json!([{"txid": txid}]), to]),
        (-8, "Invalid parameter, missing vout key".to_string())
    );
    assert_eq!(
        n.err(
            "createrawtransaction",
            vec![json!([]), json!({ nobody().to_base58(): "x" })]
        ),
        (-1, "value is type str, expected real".to_string())
    );
    // a hex key is a raw output script
    let raw = n.ok(
        "createrawtransaction",
        vec![json!([]), json!({"6a0568656c6c6f": 0})],
    );
    let d = n.ok("decoderawtransaction", vec![raw]);
    assert_eq!(
        d["vout"][0]["scriptPubKey"]["hex"],
        json!("6a0568656c6c6f"),
        "{d}"
    );
    // gettxout of text that is no hash is null (uint256 of it names nothing)
    assert_eq!(n.ok("gettxout", vec![json!("zz"), json!(0)]), Value::Null);
}

/// getrawtransaction adds each input's value, valueSat and address and each
/// spent output's spentTxId, spentIndex and spentHeight from the spent index
/// (rpcrawtransaction.cpp:72-110)
#[test]
fn raw_transaction_spent_index_fields() {
    let n = node();
    let funder = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let cb_addr = funder.new_receiving_address().unwrap();
    let coinbase = n.mine(vec![], &cb_addr);
    for _ in 0..20 {
        n.mine(vec![], &nobody());
    }
    let (mut tx, prev) = TransactionBuilder::new()
        .add_input(
            OutPoint::new(coinbase.txid(), 0),
            coinbase.vout[0].script_pubkey.clone(),
        )
        .add_output_to_address(Amount::from_sat(1249 * COIN), &nobody())
        .build();
    TransactionSigner::new(funder.keystore())
        .sign_all_inputs(&mut tx, &prev)
        .unwrap();
    n.mine(vec![tx.clone()], &nobody());
    let height = n.chain.height();

    let spend = n.ok(
        "getrawtransaction",
        vec![json!(tx.txid().to_string()), json!(1)],
    );
    let vin = &spend["vin"][0];
    assert_eq!(vin["valueSat"], json!(1250 * COIN), "{spend}");
    assert_eq!(vin["value"], json!(1250.0), "{spend}");
    assert_eq!(vin["address"], json!(cb_addr.to_base58()), "{spend}");

    let funding = n.ok(
        "getrawtransaction",
        vec![json!(coinbase.txid().to_string()), json!(1)],
    );
    let out = &funding["vout"][0];
    assert_eq!(out["spentTxId"], json!(tx.txid().to_string()), "{funding}");
    assert_eq!(out["spentIndex"], json!(0), "{funding}");
    assert_eq!(out["spentHeight"], json!(height), "{funding}");
}

/// Key export and import errors (rpcdump.cpp:70-73, :186-193)
#[test]
fn key_errors() {
    let n = node();
    let unknown = nobody().to_base58();
    assert_eq!(
        n.err("dumpprivkey", vec![json!(unknown)]),
        (
            -4,
            format!("Private key for address {unknown} is not known")
        )
    );
    let script = Address::p2sh(Hash160::from_bytes([9; 20]), Network::Regtest).to_base58();
    assert_eq!(
        n.err("dumpprivkey", vec![json!(script)]),
        (-3, "Address does not refer to a key".to_string())
    );
    assert_eq!(
        n.err("importprivkey", vec![json!("notakey")]),
        (-5, "Invalid private key encoding".to_string())
    );
}

/// addmultisigaddress answers the address alone (rpcwallet.cpp:1736-1781)
#[test]
fn addmultisigaddress_answers_the_address() {
    let n = node();
    let addr = n.ok("getnewaddress", vec![]);
    let pubkey = n.ok("validateaddress", vec![addr])["pubkey"].clone();
    let made = n.ok("createmultisig", vec![json!(1), json!([pubkey.clone()])]);
    let added = n.ok("addmultisigaddress", vec![json!(1), json!([pubkey])]);
    assert_eq!(added, made["address"]);
}

/// SendMoney checks the total before building: 0 is -8 "Invalid amount", more
/// than the balance -6 with both totals (rpcwallet.cpp:741-754); listunspent's
/// bad address text (rpcrawtransaction.cpp:276)
#[test]
fn send_and_list_errors() {
    let n = node();
    let to = nobody().to_base58();
    assert_eq!(
        n.err("sendtoaddress", vec![json!(to), json!(1)]),
        (
            -6,
            "Insufficient funds: 100000000(total requested) is greater than 0(total available)"
                .to_string()
        )
    );
    assert_eq!(
        n.err("sendmany", vec![json!(""), json!({})]),
        (-8, "Invalid amount".to_string())
    );
    assert_eq!(
        n.err("sendtoaddress", vec![json!(to), json!("x")]),
        (-1, "value is type str, expected real".to_string())
    );
    assert_eq!(
        n.err(
            "listunspent",
            vec![json!(1), json!(9999999), json!(["xyz"])]
        ),
        (-5, "Invalid DIVI address: xyz".to_string())
    );
}

/// Vault argument errors (rpcwallet.cpp:952-966, :1240-1249)
#[test]
fn vault_errors() {
    let n = node();
    assert_eq!(
        n.err("fundvault", vec![json!("xyz"), json!(1)]),
        (-5, "Invalid manager DIVI address".to_string())
    );
    assert_eq!(
        n.err("addvault", vec![json!("xyz"), json!("00".repeat(32))]),
        (-8, "Could not parse vault encoding!".to_string())
    );
}

/// Divi Core's RPCTypeCheck on positional arguments (rpcserver.cpp:195-212,
/// used by rpcmisc.cpp:539, rpcrawtransaction.cpp:286, :396, :514, :550, :649,
/// :847, rpcwallet.cpp:2776-2778): -3 "Expected type X, got Y"; getblockhash's
/// get_int is json_spirit's -1 "value is type X, expected int"
#[test]
fn argument_types_are_checked_as_core_checks_them() {
    let n = node();
    let expected = |want: &str, got: &str| (-3, format!("Expected type {want}, got {got}"));
    assert_eq!(
        n.err("decoderawtransaction", vec![json!(5)]),
        expected("str", "int")
    );
    assert_eq!(
        n.err("decodescript", vec![json!(true)]),
        expected("str", "bool")
    );
    assert_eq!(
        n.err("sendrawtransaction", vec![json!([])]),
        expected("str", "array")
    );
    assert_eq!(
        n.err("sendrawtransaction", vec![json!("00"), json!(1)]),
        expected("bool", "int")
    );
    assert_eq!(
        n.err("listunspent", vec![json!("1")]),
        expected("int", "str")
    );
    assert_eq!(
        n.err("listunspent", vec![json!(1), json!(9), json!("x")]),
        expected("array", "str")
    );
    assert_eq!(
        n.err("createrawtransaction", vec![json!({}), json!({})]),
        expected("array", "obj")
    );
    assert_eq!(
        n.err("lockunspent", vec![json!(1)]),
        expected("bool", "int")
    );
    assert_eq!(
        n.err("signrawtransaction", vec![json!(1)]),
        expected("str", "int")
    );
    assert_eq!(
        n.err("getblockhash", vec![json!("1")]),
        (-1, "value is type str, expected int".to_string())
    );
    assert_eq!(
        n.err("getblockhash", vec![json!(1.5)]),
        (-1, "value is type real, expected int".to_string())
    );
}

/// stop answers as divid does (rpcserver.cpp:317)
#[test]
fn stop_reply_text() {
    let n = node();
    n.server.set_shutdown_callback(Arc::new(|| {}));
    assert_eq!(n.ok("stop", vec![]), json!("DIVI server stopping"));
}
