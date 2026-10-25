// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! getaddressutxos against a regtest chain with the address index, in the
//! request and result shape of Divi Core 3.0.0 (rpcmisc.cpp), which is what
//! BasicSwap's Divi interface sends and reads (its divi.conf sets
//! addressindex=1).

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash160,
    script::Script,
    transaction::{Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_script::StakingVaultScript;
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType, SearchIndex};
use divi_wallet::{Address, Network};
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

fn new_chain() -> (Arc<Chain>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let mut chain = Chain::new(
        db.clone(),
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    chain.enable_search_index(Arc::new(SearchIndex::new(db, true, false)));
    (Arc::new(chain), dir)
}

/// Mine a block whose coinbase pays 1250 DIVI to `pay_to`
fn mine(chain: &Chain, pay_to: &Address) {
    mine_to_script(chain, pay_to.script_pubkey());
}

/// Mine a block whose coinbase pays 1250 DIVI to `script`
fn mine_to_script(chain: &Chain, script: Script) {
    let tip = chain.tip().unwrap();
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
        vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), script)],
        lock_time: 0,
    });
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    chain.accept_block(block).unwrap();
    assert_eq!(chain.height(), height, "block was not connected");
}

fn address(byte: u8) -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([byte; 20]), Network::Regtest)
}

/// getaddressutxos as the RPC server answers it
struct Rpc(RpcServer);

impl Rpc {
    fn for_chain(chain: Arc<Chain>) -> Self {
        Rpc(RpcServer::new(chain))
    }

    fn get_address_utxos(&self, params: Vec<Value>) -> Result<Value, String> {
        let reply = self.0.handle_request(Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "getaddressutxos".to_string(),
            params: Params::Array(params),
        });
        match reply.error {
            Some(e) => Err(e.message),
            None => Ok(reply.result.unwrap()),
        }
    }
}

/// Blocks 1 and 3 pay `a`, block 2 pays `b`
fn setup() -> (Arc<Chain>, tempfile::TempDir, Address, Address) {
    let (chain, dir) = new_chain();
    let (a, b) = (address(0xa1), address(0xb2));
    mine(&chain, &a);
    mine(&chain, &b);
    mine(&chain, &a);
    (chain, dir, a, b)
}

#[test]
fn object_form_returns_core_fields_sorted_by_height() {
    let (chain, _dir, a, b) = setup();
    let rpc = Rpc::for_chain(chain.clone());

    let r = rpc
        .get_address_utxos(vec![json!({
            "addresses": [a.to_base58(), b.to_base58()]
        })])
        .unwrap();
    let rows = r.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let heights: Vec<u64> = rows.iter().map(|u| u["height"].as_u64().unwrap()).collect();
    assert_eq!(heights, vec![1, 2, 3]);

    let first = &rows[0];
    assert_eq!(first["address"], a.to_base58());
    assert_eq!(first["outputIndex"], 0);
    assert_eq!(first["satoshis"], 1250 * COIN);
    assert_eq!(first["script"], a.script_pubkey().to_hex());
    assert_eq!(first["txid"].as_str().unwrap().len(), 64);
    let block1 = chain
        .get_block(&chain.get_block_index_by_height(1).unwrap().unwrap().hash)
        .unwrap()
        .unwrap();
    assert_eq!(first["txid"], block1.transactions[0].txid().to_string());
    assert_eq!(rows[1]["address"], b.to_base58());
}

#[test]
fn string_form_and_chain_info() {
    let (chain, _dir, a, _b) = setup();
    let rpc = Rpc::for_chain(chain.clone());

    let r = rpc.get_address_utxos(vec![json!(a.to_base58())]).unwrap();
    assert_eq!(r.as_array().unwrap().len(), 2);

    let r = rpc
        .get_address_utxos(vec![json!({
            "addresses": [a.to_base58()],
            "chainInfo": true
        })])
        .unwrap();
    assert_eq!(r["utxos"].as_array().unwrap().len(), 2);
    assert_eq!(r["height"], 3);
    assert_eq!(r["hash"], chain.tip().unwrap().hash.to_string());
}

#[test]
fn unfunded_and_invalid_addresses() {
    let (chain, _dir, _a, _b) = setup();
    let rpc = Rpc::for_chain(chain);

    let r = rpc
        .get_address_utxos(vec![json!({"addresses": [address(0xc3).to_base58()]})])
        .unwrap();
    assert_eq!(r, json!([]));

    // No address at all is an empty reply, as in Core (rpcmisc.cpp:580-589)
    let r = rpc
        .get_address_utxos(vec![json!({"addresses": []})])
        .unwrap();
    assert_eq!(r, json!([]));

    let mainnet = Address::from_pubkey_hash(Hash160::from_bytes([0xa1; 20]), Network::Mainnet);
    let err = rpc
        .get_address_utxos(vec![json!({"addresses": [mainnet.to_base58()]})])
        .unwrap_err();
    assert!(err.contains("Invalid address"), "{:?}", err);
}

/// Divi Core indexes a staking vault under its owner's key hash, so
/// `only_vaults` returns the vaults an address owns and nothing else, and
/// without it a P2PKH address never returns a vault.
#[test]
fn only_vaults_returns_vaults_by_owner() {
    let (chain, _dir, a, b) = setup();
    let vault = StakingVaultScript::new([0xa1; 20], [0xd4; 20]).to_script();
    mine_to_script(&chain, vault.clone());
    let rpc = Rpc::for_chain(chain);

    let r = rpc.get_address_utxos(vec![json!(a.to_base58())]).unwrap();
    assert_eq!(
        r.as_array().unwrap().len(),
        2,
        "plain lookup includes a vault"
    );

    let r = rpc
        .get_address_utxos(vec![json!(a.to_base58()), json!(true)])
        .unwrap();
    let rows = r.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["address"], a.to_base58());
    assert_eq!(rows[0]["script"], vault.to_hex());
    assert_eq!(rows[0]["height"], 4);
    assert_eq!(rows[0]["satoshis"], 1250 * COIN);

    let r = rpc
        .get_address_utxos(vec![
            json!({"addresses": [a.to_base58(), b.to_base58()], "chainInfo": true}),
            json!(true),
        ])
        .unwrap();
    assert_eq!(r["utxos"].as_array().unwrap().len(), 1);
    assert_eq!(r["height"], 4);

    // The vault key does not own the vault, and false is the plain lookup
    for (addr, flag, want) in [
        (address(0xd4), true, 0),
        (b.clone(), true, 0),
        (a.clone(), false, 2),
    ] {
        let r = rpc
            .get_address_utxos(vec![json!(addr.to_base58()), json!(flag)])
            .unwrap();
        assert_eq!(
            r.as_array().unwrap().len(),
            want,
            "{} {}",
            addr.to_base58(),
            flag
        );
    }

    let p2sh = Address::p2sh(Hash160::from_bytes([0xa1; 20]), Network::Regtest);
    let err = rpc
        .get_address_utxos(vec![json!(p2sh.to_base58()), json!(true)])
        .unwrap_err();
    assert!(err.contains("Invalid address"), "{:?}", err);
}

/// The object form takes a page: "skip" and "limit", oldest first
#[test]
fn object_form_pages_with_skip_and_limit() {
    let (chain, _dir, a, b) = setup();
    let rpc = Rpc::for_chain(chain);
    let heights = |extra: Value| -> Vec<u64> {
        let mut req = json!({ "addresses": [a.to_base58(), b.to_base58()] });
        for (k, v) in extra.as_object().unwrap() {
            req[k] = v.clone();
        }
        rpc.get_address_utxos(vec![req])
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["height"].as_u64().unwrap())
            .collect()
    };
    assert_eq!(heights(json!({ "skip": 1 })), vec![2, 3]);
    assert_eq!(heights(json!({ "limit": 2 })), vec![1, 2]);
    assert_eq!(heights(json!({ "skip": 1, "limit": 1 })), vec![2]);
    assert_eq!(heights(json!({ "skip": 5 })), Vec::<u64>::new());
}
