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

//! Key RPCs on a locked wallet and import rescans, against Divi Core 3.0.0
//! behaviour (rpcwallet.cpp, rpcdump.cpp).

use divi_crypto::compute_merkle_root;
use divi_crypto::keys::SecretKey;
use divi_primitives::{
    amount::Amount,
    block::Block,
    script::Script,
    transaction::{Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Error, Params, WalletRpc};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{encode_wif, Address, HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;

const PASS: &str = "correct horse battery staple";

fn p(v: Vec<Value>) -> Params {
    Params::Array(v)
}

fn rpc_code(e: Error) -> (i32, String) {
    match e {
        Error::Rpc(r) => (r.code, r.message),
        other => panic!("expected an RPC error, got {:?}", other),
    }
}

/// An encrypted, locked wallet on disk, as `encryptwallet` leaves it
fn encrypted_rpc(path: &Path) -> (WalletRpc, Arc<WalletDb>) {
    let db = Arc::new(
        WalletDb::create_persistent(
            path,
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    let rpc = WalletRpc::with_wallet(db.clone());
    rpc.encrypt_wallet(&p(vec![json!(PASS)])).unwrap();
    assert_eq!(
        rpc.get_wallet_info(&Params::None).unwrap()["encryption_status"],
        "locked"
    );
    (rpc, db)
}

#[test]
fn getnewaddress_while_locked_keeps_label_and_key_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w");
    let (addr, change) = {
        let (rpc, _db) = encrypted_rpc(&path);
        let addr = rpc
            .get_new_address(&p(vec![json!("lab")]))
            .expect("getnewaddress on a locked wallet");
        assert_eq!(rpc.get_account(&p(vec![addr.clone()])).unwrap(), "lab");
        assert_eq!(
            rpc.get_addresses_by_account(&p(vec![json!("lab")]))
                .unwrap(),
            json!([addr.clone()])
        );
        let change = rpc
            .get_raw_change_address(&Params::None)
            .expect("getrawchangeaddress on a locked wallet");
        (addr, change)
    };

    // Restart: no save, no block in between
    let db = Arc::new(WalletDb::open(&path, Network::Regtest).unwrap());
    let rpc = WalletRpc::with_wallet(db.clone());
    for a in [&addr, &change] {
        let info = rpc.validate_address(&p(vec![a.clone()])).unwrap();
        assert_eq!(info["ismine"], true, "{} lost", a);
        assert_eq!(info["iswatchonly"], false, "{} turned watch-only", a);
    }
    assert_eq!(rpc.get_account(&p(vec![addr.clone()])).unwrap(), "lab");

    // The private key is there after unlock
    rpc.wallet_passphrase(&p(vec![json!(PASS), json!(60)]))
        .unwrap();
    let wif = rpc.dump_privkey(&p(vec![addr.clone()])).unwrap();
    let key = divi_wallet::decode_wif(wif.as_str().unwrap()).unwrap();
    let secret = divi_crypto::keys::SecretKey::from_bytes(&key.key_bytes).unwrap();
    assert_eq!(
        divi_wallet::Address::p2pkh(&secret.public_key(), Network::Regtest).to_string(),
        addr.as_str().unwrap()
    );
    // Not handed out a second time
    assert_ne!(rpc.get_new_address(&Params::None).unwrap(), addr);
}

#[test]
fn locked_keypool_runs_out_with_minus_12() {
    let dir = tempfile::tempdir().unwrap();
    let (rpc, _db) = encrypted_rpc(&dir.path().join("w"));
    let keypoolsize = |rpc: &WalletRpc| {
        rpc.get_wallet_info(&Params::None).unwrap()["keypoolsize"]
            .as_u64()
            .unwrap()
    };
    let full = keypoolsize(&rpc);

    let mut handed = 0u64;
    let err = loop {
        match rpc.get_new_address(&Params::None) {
            Ok(_) => handed += 1,
            Err(e) => break rpc_code(e),
        }
        assert!(handed <= full, "more keys handed out than the pool held");
    };
    assert_eq!(
        err,
        (
            -12,
            "Error: Keypool ran out, please call keypoolrefill first".to_string()
        )
    );
    assert!(handed > 0);
    // getwalletinfo reports the real pool, not a constant
    assert_eq!(keypoolsize(&rpc), full - handed);

    // keypoolrefill needs the passphrase, then getnewaddress works locked again
    assert_eq!(
        rpc_code(rpc.keypool_refill(&Params::None).unwrap_err()).0,
        -13
    );
    rpc.wallet_passphrase(&p(vec![json!(PASS), json!(60)]))
        .unwrap();
    rpc.keypool_refill(&Params::None).unwrap();
    rpc.wallet_lock(&Params::None).unwrap();
    assert_eq!(keypoolsize(&rpc), full);
    rpc.get_new_address(&Params::None).unwrap();
}

const COIN: i64 = 100_000_000;

/// A regtest chain and a wallet that follows it block by block
struct Net {
    chain: Arc<Chain>,
    _dir: tempfile::TempDir,
    wallet: Arc<WalletDb>,
    rpc: WalletRpc,
}

impl Net {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
        let chain = Arc::new(
            Chain::new(
                db,
                ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
            )
            .unwrap(),
        );
        let wallet = Arc::new(WalletDb::with_hd_wallet(
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        ));
        let rpc = WalletRpc::with_wallet_and_chain(wallet.clone(), chain.clone());
        Net {
            chain,
            _dir: dir,
            wallet,
            rpc,
        }
    }

    /// Mine a block whose coinbase pays `divi` to `pay_to`; the wallet scans it
    fn mine_to(&self, pay_to: &Address, divi: i64) {
        let tip = self.chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        // BIP34: the coinbase starts with the height
        let mut cb_sig = divi_storage::bip34_height_script(height);
        cb_sig.extend_from_slice(&height.to_le_bytes());
        block.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(cb_sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(divi * COIN),
                Script::new_p2pkh(pay_to.hash.as_bytes()),
            )],
            lock_time: 0,
        });
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        // Proof of work for the block's bits
        let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        let time = block.header.time;
        let txs = block.transactions.clone();
        let hash = self.chain.accept_block(block).unwrap().hash;
        assert_eq!(self.chain.height(), height, "block was not connected");
        self.wallet.scan_block(hash, height, time, &txs);
    }

    /// Sum of the wallet's coins at `addr`
    fn coins_at(&self, addr: &Address) -> i64 {
        let addr = addr.to_string();
        self.wallet
            .get_utxos()
            .iter()
            .filter(|u| u.address == addr)
            .map(|u| u.value.as_sat())
            .sum()
    }
}

/// A key the wallet does not know, funded with 25 DIVI two blocks deep
fn funded_foreign_key(net: &Net) -> (SecretKey, Address) {
    let key = SecretKey::new_random();
    let addr = Address::p2pkh(&key.public_key(), Network::Regtest);
    net.mine_to(&addr, 25);
    let own = net.wallet.new_receiving_address().unwrap();
    net.mine_to(&own, 1);
    assert_eq!(
        net.coins_at(&addr),
        0,
        "sanity: the wallet does not know the key yet"
    );
    (key, addr)
}

fn wif(key: &SecretKey) -> Value {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(key.as_bytes());
    json!(encode_wif(&bytes, true, Network::Regtest))
}

#[test]
fn importprivkey_rescan_true_finds_past_coins() {
    let net = Net::new();
    let (key, addr) = funded_foreign_key(&net);

    net.rpc
        .import_privkey(&p(vec![wif(&key), json!("imp"), json!(true)]))
        .unwrap();
    assert_eq!(
        net.coins_at(&addr),
        25 * COIN,
        "rescan did not find the coin"
    );
    assert_eq!(
        net.rpc
            .get_account(&p(vec![json!(addr.to_string())]))
            .unwrap(),
        "imp"
    );
    // The default for rescan is true as well
    let (key2, addr2) = funded_foreign_key(&net);
    net.rpc.import_privkey(&p(vec![wif(&key2)])).unwrap();
    assert_eq!(net.coins_at(&addr2), 25 * COIN);
    // The wallet's own coins are still there after the full rescan
    assert!(net.wallet.get_utxos().len() >= 4);
}

#[test]
fn importprivkey_rescan_false_waits_for_rescanblockchain() {
    let net = Net::new();
    let (key, addr) = funded_foreign_key(&net);

    net.rpc
        .import_privkey(&p(vec![wif(&key), json!(""), json!(false)]))
        .unwrap();
    assert!(net.wallet.is_mine(&addr));
    assert_eq!(net.coins_at(&addr), 0, "rescan=false must not scan");

    net.rpc.rescan_blockchain(&Params::None).unwrap();
    assert_eq!(net.coins_at(&addr), 25 * COIN);
}

#[test]
fn importaddress_rescan_true_shows_past_coins_watch_only() {
    let net = Net::new();
    let (_key, addr) = funded_foreign_key(&net);

    net.rpc
        .import_address(&p(vec![json!(addr.to_string()), json!(""), json!(true)]))
        .unwrap();
    assert_eq!(
        net.coins_at(&addr),
        25 * COIN,
        "rescan did not find the coin"
    );
    let info = net
        .rpc
        .validate_address(&p(vec![json!(addr.to_string())]))
        .unwrap();
    // Divi Core: ismine is the spendable flag, a watched address is not
    assert_eq!(info["ismine"], false);
    assert_eq!(info["iswatchonly"], true);
}

#[test]
fn importaddress_rescan_false_waits_for_rescanblockchain() {
    let net = Net::new();
    let (_key, addr) = funded_foreign_key(&net);

    net.rpc
        .import_address(&p(vec![json!(addr.to_string()), json!("w"), json!(false)]))
        .unwrap();
    assert_eq!(net.coins_at(&addr), 0, "rescan=false must not scan");
    assert_eq!(
        net.rpc
            .get_account(&p(vec![json!(addr.to_string())]))
            .unwrap(),
        "w"
    );

    net.rpc.rescan_blockchain(&Params::None).unwrap();
    assert_eq!(net.coins_at(&addr), 25 * COIN);
}
