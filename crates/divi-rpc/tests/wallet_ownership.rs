// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Which outputs the wallet owns, and the balances and keys that follow from
//! it, as Divi Core 3.0.0's wallet (wallet_ismine.cpp, wallet.cpp,
//! WalletBalanceCalculator.cpp, rpcwallet.cpp, rpcdump.cpp).

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, WalletRpc};
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{
    Address, ExtendedPrivateKey, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb,
};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

/// A regtest chain, a funder wallet with a mature coinbase, and the wallet
/// under test
struct Net {
    chain: Arc<Chain>,
    _dir: tempfile::TempDir,
    funder: Arc<WalletDb>,
    wallet: Arc<WalletDb>,
    submitted: Arc<Mutex<Vec<Transaction>>>,
    miner: Address,
}

impl Net {
    fn new() -> Self {
        Self::with_wallet(|_| {
            Arc::new(WalletDb::with_hd_wallet(
                Network::Regtest,
                HdWallet::new(ChainMode::Divi).unwrap(),
            ))
        })
    }

    fn with_wallet(make: impl FnOnce(&std::path::Path) -> Arc<WalletDb>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
        let mut chain = Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap();
        chain.enable_tx_index(Arc::new(TxIndex::open(dir.path().join("txindex")).unwrap()));
        let wallet = make(dir.path());
        Net {
            chain: Arc::new(chain),
            _dir: dir,
            funder: Arc::new(WalletDb::with_hd_wallet(
                Network::Regtest,
                HdWallet::new(ChainMode::Divi).unwrap(),
            )),
            wallet,
            submitted: Arc::new(Mutex::new(Vec::new())),
            miner: Address::from_pubkey_hash(Hash160::from_bytes([0x99; 20]), Network::Regtest),
        }
    }

    fn rpc(&self) -> WalletRpc {
        let rpc = WalletRpc::with_wallet_and_chain(self.wallet.clone(), self.chain.clone());
        let submitted = self.submitted.clone();
        rpc.set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            submitted.lock().push(tx);
            Ok(txid)
        }));
        rpc
    }

    /// Mine a block holding `txs` whose coinbase pays 1250 DIVI to `pay_to`;
    /// both wallets scan it
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
        assert_eq!(self.chain.height(), height, "block was not connected");
        for w in [&self.funder, &self.wallet] {
            w.scan_block(hash, height, time, &txs);
        }
        txs[0].clone()
    }

    /// Pay these scripts (values in satoshis) from a mature coinbase of the
    /// funder, in one confirmed transaction; returns it
    fn fund(&self, outputs: &[(Script, i64)]) -> Transaction {
        let cb_addr = self.funder.new_receiving_address().unwrap();
        let coinbase = self.mine(vec![], &cb_addr);
        // Coinbase maturity 20 on regtest: spendable with 21 confirmations
        for _ in 0..20 {
            self.mine(vec![], &self.miner);
        }
        let mut builder = TransactionBuilder::new().add_input(
            OutPoint::new(coinbase.txid(), 0),
            coinbase.vout[0].script_pubkey.clone(),
        );
        for (script, value) in outputs {
            builder = builder.add_output(Amount::from_sat(*value), script.clone());
        }
        let rest = 1250 * COIN - outputs.iter().map(|(_, v)| v).sum::<i64>() - COIN / 100;
        builder = builder.add_output_to_address(Amount::from_sat(rest), &self.miner);
        let (mut tx, prev) = builder.build();
        assert_eq!(
            TransactionSigner::new(self.funder.keystore())
                .sign_all_inputs(&mut tx, &prev)
                .unwrap(),
            1
        );
        self.mine(vec![tx.clone()], &self.miner);
        tx
    }

    fn last_submitted(&self) -> Transaction {
        self.submitted
            .lock()
            .last()
            .cloned()
            .expect("a transaction was sent")
    }

    /// Public key of a new receiving key of the wallet under test
    fn new_pubkey(&self) -> Vec<u8> {
        let addr = self.wallet.new_receiving_address().unwrap();
        self.wallet
            .get_key_by_address(&addr)
            .unwrap()
            .pubkey_bytes()
    }
}

fn p(v: Vec<Value>) -> Params {
    Params::Array(v)
}

fn dest() -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest)
}

fn stranger_pubkey() -> Vec<u8> {
    let secret = divi_crypto::keys::SecretKey::from_bytes(&[0x5a; 32]).unwrap();
    secret.public_key().to_bytes().to_vec()
}

fn push(script: &mut Vec<u8>, data: &[u8]) {
    script.push(data.len() as u8);
    script.extend_from_slice(data);
}

fn p2pk(pubkey: &[u8]) -> Script {
    let mut s = Vec::new();
    push(&mut s, pubkey);
    s.push(0xac);
    Script::from_bytes(s)
}

fn multisig(required: u8, pubkeys: &[&[u8]]) -> Script {
    let mut s = vec![0x50 + required];
    for key in pubkeys {
        push(&mut s, key);
    }
    s.push(0x50 + pubkeys.len() as u8);
    s.push(0xae);
    Script::from_bytes(s)
}

fn p2sh_of(address: &str) -> Script {
    Address::from_base58(address).unwrap().script_pubkey()
}

fn amount(v: &Value) -> i64 {
    (v.as_f64().unwrap() * COIN as f64).round() as i64
}

fn unspent_scripts(rpc: &WalletRpc) -> Vec<String> {
    let list = rpc.list_unspent(&p(vec![])).unwrap();
    let mut scripts: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["scriptPubKey"].as_str().unwrap().to_string())
        .collect();
    scripts.sort();
    scripts
}

/// P2PK of a wallet key, a P2SH whose redeem script is a 1-of-1 of a wallet
/// key, and a bare 2-of-2 of wallet keys are spendable coins of the wallet:
/// counted by getbalance, listed by listunspent, received at their address.
/// A P2SH multisig with a key not the wallet's is not (wallet_ismine.cpp:60-104).
#[test]
fn p2pk_p2sh_and_multisig_coins_are_the_wallets() {
    let net = Net::new();
    let rpc = net.rpc();
    let key1 = net.new_pubkey();
    let key2 = net.new_pubkey();
    let p2sh_mine = rpc
        .add_multisig_address(&p(vec![json!(1), json!([hex::encode(&key1)])]))
        .unwrap();
    let p2sh_mine = p2sh_mine["address"]
        .as_str()
        .or(p2sh_mine.as_str())
        .unwrap()
        .to_string();
    let p2sh_shared = rpc
        .add_multisig_address(&p(vec![
            json!(1),
            json!([hex::encode(&key1), hex::encode(stranger_pubkey())]),
        ]))
        .unwrap();
    let p2sh_shared = p2sh_shared["address"]
        .as_str()
        .or(p2sh_shared.as_str())
        .unwrap()
        .to_string();
    let coins = [
        (p2pk(&key1), 20 * COIN),
        (p2sh_of(&p2sh_mine), 10 * COIN),
        (multisig(2, &[&key1, &key2]), 30 * COIN),
        (p2sh_of(&p2sh_shared), 7 * COIN),
        (multisig(1, &[&key1, &stranger_pubkey()]), 5 * COIN),
    ];
    net.fund(&coins);

    assert_eq!(amount(&rpc.get_balance(&p(vec![])).unwrap()), 60 * COIN);
    let mut expected: Vec<String> = coins[..3]
        .iter()
        .map(|(s, _)| hex::encode(s.as_bytes()))
        .collect();
    expected.sort();
    assert_eq!(unspent_scripts(&rpc), expected);
    assert_eq!(
        amount(
            &rpc.get_received_by_address(&p(vec![json!(p2sh_mine)]))
                .unwrap()
        ),
        10 * COIN
    );
    let info = rpc.validate_address(&p(vec![json!(p2sh_mine)])).unwrap();
    assert_eq!(info["ismine"], json!(true));
    let info = rpc.validate_address(&p(vec![json!(p2sh_shared)])).unwrap();
    assert_eq!(info["ismine"], json!(false));
}

/// Divi Core records a transaction only when it pays or spends a spendable
/// output (wallet.cpp:1292-1311): a payment to an address imported with
/// importaddress is in no balance, listunspent or listtransactions.
#[test]
fn watched_address_coins_are_not_recorded() {
    let net = Net::new();
    let rpc = net.rpc();
    let watched = Address::from_pubkey_hash(Hash160::from_bytes([0x77; 20]), Network::Regtest);
    rpc.import_address(&p(vec![
        json!(watched.to_string()),
        json!(""),
        json!(false),
    ]))
    .unwrap();
    let mine = net.wallet.new_receiving_address().unwrap();
    net.fund(&[(mine.script_pubkey(), 3 * COIN)]);
    let tx = net.fund(&[(watched.script_pubkey(), 9 * COIN)]);

    assert_eq!(
        unspent_scripts(&rpc),
        vec![hex::encode(mine.script_pubkey().as_bytes())]
    );
    let listed = rpc
        .list_transactions(&p(vec![json!("*"), json!(100), json!(0), json!(true)]))
        .unwrap();
    assert!(
        !listed
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["txid"] == json!(tx.txid().to_string())),
        "the payment to a watched address was recorded: {}",
        listed
    );
    assert_eq!(
        amount(
            &rpc.get_received_by_address(&p(vec![json!(watched.to_string())]))
                .unwrap()
        ),
        0
    );
}

/// A send spends P2PK and P2SH multisig coins, signing them as Divi Core's
/// SignSignature does (wallet.cpp:1609-1624)
#[test]
fn sends_spend_p2pk_and_p2sh_coins() {
    let net = Net::new();
    let rpc = net.rpc();
    let key = net.new_pubkey();
    let p2sh = rpc
        .add_multisig_address(&p(vec![json!(1), json!([hex::encode(&key)])]))
        .unwrap();
    let p2sh = p2sh["address"]
        .as_str()
        .or(p2sh.as_str())
        .unwrap()
        .to_string();
    let funding = net.fund(&[(p2pk(&key), 20 * COIN), (p2sh_of(&p2sh), 10 * COIN)]);

    rpc.send_to_address(&p(vec![json!(dest().to_string()), json!(25.0)]))
        .unwrap();
    let tx = net.last_submitted();
    assert_eq!(tx.vin.len(), 2);
    for (i, input) in tx.vin.iter().enumerate() {
        assert_eq!(input.prevout.txid, funding.txid());
        let prev = &funding.vout[input.prevout.vout as usize];
        assert!(
            divi_script::verify_input(&tx, i, &prev.script_pubkey, prev.value).is_ok(),
            "input {} does not verify",
            i
        );
    }
}

/// getbalance counts confirmed coins only: after a send, the change is in
/// getunconfirmedbalance and in getwalletinfo's spendable_balance, not in
/// getbalance (WalletBalanceCalculator.cpp, probe of Core 3.0.0: 220 → 200)
#[test]
fn unconfirmed_change_is_unconfirmed_balance() {
    let net = Net::new();
    let rpc = net.rpc();
    let mine = net.wallet.new_receiving_address().unwrap();
    net.fund(&[(mine.script_pubkey(), 100 * COIN)]);
    rpc.send_to_address(&p(vec![json!(dest().to_string()), json!(1.0)]))
        .unwrap();
    let tx = net.last_submitted();
    assert!(net.wallet.add_mempool_tx(&tx));
    let change: i64 = tx
        .vout
        .iter()
        .filter(|o| o.script_pubkey != dest().script_pubkey())
        .map(|o| o.value.as_sat())
        .sum();

    assert_eq!(amount(&rpc.get_balance(&p(vec![])).unwrap()), 0);
    assert_eq!(
        amount(&rpc.get_unconfirmed_balance(&p(vec![])).unwrap()),
        change
    );
    let info = rpc.get_wallet_info(&p(vec![])).unwrap();
    assert_eq!(amount(&info["balance"]), 0);
    assert_eq!(amount(&info["unconfirmed_balance"]), change);
    assert_eq!(amount(&info["spendable_balance"]), change);
}

/// getbalance "*" is GetBalance whatever the minconf (rpcwallet.cpp:1577-1578)
#[test]
fn getbalance_star_ignores_minconf() {
    let net = Net::new();
    let rpc = net.rpc();
    let mine = net.wallet.new_receiving_address().unwrap();
    net.fund(&[(mine.script_pubkey(), 5 * COIN)]);
    assert_eq!(
        amount(&rpc.get_balance(&p(vec![json!("*"), json!(6)])).unwrap()),
        5 * COIN
    );
}

/// keypoolrefill n fills n receiving and n change keys, and a new wallet's
/// keypool holds Divi Core's default of 1000 per chain (wallet.cpp:2057-2120)
#[test]
fn keypool_is_sized_per_chain() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Arc::new(
        WalletDb::create_persistent(
            &dir.path().join("w"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    let rpc = WalletRpc::with_wallet(wallet.clone());
    rpc.keypool_refill(&p(vec![json!(10)])).unwrap();
    let info = rpc.get_wallet_info(&p(vec![])).unwrap();
    assert_eq!(info["keypoolsize"], json!(20));
    rpc.keypool_refill(&p(vec![])).unwrap();
    let info = rpc.get_wallet_info(&p(vec![])).unwrap();
    assert_eq!(info["keypoolsize"], json!(2000));
}

/// BIP39 seed of the "abandon ... about" test mnemonic (public test vector)
const ABANDON_SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
                            9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

fn abandon_mnemonic() -> String {
    ["abandon"; 11].join(" ") + " about"
}

/// Address of key m/44'/coin'/0'/0/index of a seed
fn receiving_address(seed: &[u8], coin: u32, index: u32) -> Address {
    let key = ExtendedPrivateKey::from_seed(seed)
        .unwrap()
        .derive_hardened(44)
        .unwrap()
        .derive_hardened(coin)
        .unwrap()
        .derive_hardened(0)
        .unwrap()
        .derive_normal(0)
        .unwrap()
        .derive_normal(index)
        .unwrap();
    divi_wallet::KeyEntry::with_hd_path(key.secret_key().unwrap(), String::new())
        .address(Network::Regtest)
}

/// A regtest or testnet wallet derives with coin type 1, as Divi Core
/// (chainparams.cpp nExtCoinType), and keeps it when reopened
#[test]
fn testnet_and_regtest_wallets_use_cores_coin_type() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w");
    let seed = hex::decode(ABANDON_SEED.replace(' ', "")).unwrap();
    let first = {
        let hd = HdWallet::from_mnemonic(&abandon_mnemonic(), None, ChainMode::Divi).unwrap();
        let wallet = WalletDb::create_persistent(&path, Network::Regtest, hd).unwrap();
        let addr = wallet.new_receiving_address().unwrap();
        wallet.save().unwrap();
        addr
    };
    assert_eq!(first, receiving_address(&seed, 1, 0));
    let wallet = WalletDb::open(&path, Network::Regtest).unwrap();
    assert_eq!(
        wallet.new_receiving_address().unwrap(),
        receiving_address(&seed, 1, 1)
    );
}

/// A seed made with a BIP39 passphrase (Divi Core's -mnemonicpassphrase)
/// keeps deriving with it after a restart and after encryption, and
/// dumphdinfo shows it (rpcdump.cpp:221-233)
#[test]
fn mnemonic_passphrase_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w");
    let mnemonic = abandon_mnemonic();
    // BIP39 vector: "abandon ... about" with passphrase "TREZOR"
    let seed = hex::decode(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
         1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    )
    .unwrap();
    {
        let hd = HdWallet::from_mnemonic(&mnemonic, Some("TREZOR"), ChainMode::Divi).unwrap();
        let wallet = WalletDb::create_persistent(&path, Network::Regtest, hd).unwrap();
        wallet.save().unwrap();
    }
    let wallet = Arc::new(WalletDb::open(&path, Network::Regtest).unwrap());
    assert_eq!(
        wallet.new_receiving_address().unwrap(),
        receiving_address(&seed, 1, 0)
    );
    let rpc = WalletRpc::with_wallet(wallet.clone());
    let info = rpc.dump_hd_info(&p(vec![])).unwrap();
    assert_eq!(info["mnemonicpassphrase"], json!("TREZOR"));
    assert_eq!(info["hdseed"], json!(hex::encode(&seed)));

    wallet.encrypt_wallet("correct horse").unwrap();
    wallet.save().unwrap();
    drop(rpc);
    drop(wallet);
    let wallet = Arc::new(WalletDb::open(&path, Network::Regtest).unwrap());
    wallet.unlock("correct horse", 0).unwrap();
    assert_eq!(
        wallet.new_receiving_address().unwrap(),
        receiving_address(&seed, 1, 1)
    );
    let rpc = WalletRpc::with_wallet(wallet.clone());
    let info = rpc.dump_hd_info(&p(vec![])).unwrap();
    assert_eq!(info["mnemonicpassphrase"], json!("TREZOR"));
}
