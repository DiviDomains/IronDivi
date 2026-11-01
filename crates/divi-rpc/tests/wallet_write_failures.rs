// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Wallet RPCs while the wallet's writes fail, as on a full disk, answer as
//! Divi Core 3.0.0's do (scripts/wallet-write-failures compares the daemons).
//! The tests lower the file size limit of the whole process, so each holds
//! LIMIT while it runs and no other test shares this binary.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Error, Params, WalletRpc};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

/// Held by each test while it changes the file size limit
static LIMIT: Mutex<()> = Mutex::new(());

/// Set the soft file size limit of the process; a write past it fails with
/// EFBIG, since SIGXFSZ is ignored
fn file_size_limit(bytes: libc::rlim_t) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit), 0);
        limit.rlim_cur = bytes.min(limit.rlim_max);
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
    }
}

fn writes_fail() {
    file_size_limit(1);
}

fn writes_work() {
    file_size_limit(libc::RLIM_INFINITY);
}

/// A regtest chain, a funder wallet in memory, and the wallet under test on disk
struct Net {
    chain: Arc<Chain>,
    dir: tempfile::TempDir,
    funder: Arc<WalletDb>,
    wallet: Arc<WalletDb>,
    miner: Address,
}

impl Net {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
        let chain = Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap();
        let wallet = WalletDb::create_persistent(
            &dir.path().join("wallet"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap();
        Net {
            chain: Arc::new(chain),
            funder: Arc::new(WalletDb::with_hd_wallet(
                Network::Regtest,
                HdWallet::new(ChainMode::Divi).unwrap(),
            )),
            wallet: Arc::new(wallet),
            dir,
            miner: Address::from_pubkey_hash(Hash160::from_bytes([0x99; 20]), Network::Regtest),
        }
    }

    fn rpc(&self) -> WalletRpc {
        let rpc = WalletRpc::with_wallet_and_chain(self.wallet.clone(), self.chain.clone());
        // The node hands a send to the wallet as it takes it into its mempool
        let wallet = self.wallet.clone();
        rpc.set_tx_submit(Arc::new(move |tx: Transaction| {
            wallet.add_mempool_tx(&tx);
            Ok(tx.txid())
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
        for w in [&self.funder, &self.wallet] {
            w.scan_block(hash, height, time, &txs);
        }
        txs[0].clone()
    }

    /// Give the wallet under test two confirmed coins of 100 DIVI
    fn fund(&self) {
        let cb_addr = self.funder.new_receiving_address().unwrap();
        let coinbase = self.mine(vec![], &cb_addr);
        // Coinbase maturity 20 on regtest: spendable with 21 confirmations
        for _ in 0..20 {
            self.mine(vec![], &self.miner);
        }
        let to = self.wallet.new_receiving_address().unwrap();
        let (mut tx, prev) = TransactionBuilder::new()
            .add_input(
                OutPoint::new(coinbase.txid(), 0),
                coinbase.vout[0].script_pubkey.clone(),
            )
            .add_output_to_address(Amount::from_sat(100 * COIN), &to)
            .add_output_to_address(Amount::from_sat(100 * COIN), &to)
            .add_output_to_address(Amount::from_sat(1049 * COIN), &self.miner)
            .build();
        TransactionSigner::new(self.funder.keystore())
            .sign_all_inputs(&mut tx, &prev)
            .unwrap();
        self.mine(vec![tx], &self.miner);
        self.wallet.save().unwrap();
    }
}

impl Net {
    /// Pay `value` to `to` in a confirmed coin, from a mature coinbase of the funder
    fn fund_to(&self, to: &Address, value: i64) {
        let cb_addr = self.funder.new_receiving_address().unwrap();
        let coinbase = self.mine(vec![], &cb_addr);
        for _ in 0..20 {
            self.mine(vec![], &self.miner);
        }
        let (mut tx, prev) = TransactionBuilder::new()
            .add_input(
                OutPoint::new(coinbase.txid(), 0),
                coinbase.vout[0].script_pubkey.clone(),
            )
            .add_output_to_address(Amount::from_sat(value), to)
            .add_output_to_address(Amount::from_sat(1249 * COIN - value), &self.miner)
            .build();
        TransactionSigner::new(self.funder.keystore())
            .sign_all_inputs(&mut tx, &prev)
            .unwrap();
        self.mine(vec![tx], &self.miner);
    }
}

/// A coin the wallet holds the wrong key for, so a send of it cannot be
/// signed (as crates/divi-rpc/tests/wallet_sends.rs makes one)
fn unsignable_coin(net: &Net, value: i64) {
    use divi_crypto::keys::SecretKey;
    use divi_wallet::KeyEntry;
    let owner = KeyEntry::imported(SecretKey::new_random(), true).address(Network::Regtest);
    let wrong = KeyEntry::imported(SecretKey::new_random(), true);
    net.wallet.keystore().add_key_with_hash(owner.hash, wrong);
    net.fund_to(&owner, value);
}

fn p(v: Vec<Value>) -> Params {
    Params::Array(v)
}

fn dest() -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest)
}

/// The code and message of an RPC error
fn rpc_error(result: Result<Value, Error>) -> (i32, String) {
    match result {
        Err(Error::Rpc(e)) => (e.code, e.message),
        other => panic!("not an RPC error: {:?}", other),
    }
}

/// With its keypool full, divid sends while its writes fail: the change key
/// was written when the pool was topped up, KeepKey does not read ErasePool's
/// result (wallet.cpp:2158-2163) and AddToWallet logs the write it could not
/// make (wallet.cpp:1271-1274). A key it must derive cannot be written, and
/// the derivation throws (wallet.cpp:2346-2347): getnewaddress then answers
/// -1 with that text. setaccount does not read SetAddressLabel's result
/// (rpcwallet.cpp:616). Once writes work again the wallet writes again
#[test]
fn sends_and_keys_while_writes_fail_answer_as_divid() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    net.fund();
    let rpc = net.rpc();
    rpc.keypool_refill(&p(vec![])).unwrap();
    let own = net.wallet.new_receiving_address().unwrap();
    rpc.keypool_refill(&p(vec![])).unwrap();

    writes_fail();
    let from_pool = rpc.get_new_address(&p(vec![]));
    writes_work();
    let from_pool = from_pool.expect("getnewaddress from a full keypool");

    rpc.keypool_refill(&p(vec![]))
        .expect("keypoolrefill once writes work again");
    writes_fail();
    let sent = rpc.send_to_address(&p(vec![json!(dest().to_string()), json!(10.0)]));
    let derived = rpc.get_new_address(&p(vec![]));
    let label = rpc.set_account(&p(vec![json!(own.to_string()), json!("lbl")]));
    writes_work();
    let sent = sent.expect("sendtoaddress with a full keypool");
    assert_eq!(
        rpc_error(derived),
        (-1, "loadHDChain: WriteHDChain failed".to_string())
    );
    assert_eq!(label.expect("setaccount"), Value::Null);

    let again = rpc
        .send_to_address(&p(vec![json!(dest().to_string()), json!(11.0)]))
        .expect("sendtoaddress once writes work again");
    net.wallet.save().expect("a save once writes work again");

    // The send made while writes failed is kept in memory until a block
    // confirms it, as Divi Core keeps it in mapWallet (wallet.cpp:1271-1274);
    // the one made once writes work again is on disk
    let path = net.dir.path().join("wallet");
    let again = Hash256::from_hex(again.as_str().unwrap()).unwrap();
    assert!(net
        .wallet
        .get_transaction(&Hash256::from_hex(sent.as_str().unwrap()).unwrap())
        .is_some());
    drop(rpc);
    let Net { wallet, .. } = net;
    drop(wallet);
    let reopened = WalletDb::open(&path, Network::Regtest).unwrap();
    assert!(
        reopened.get_transaction(&again).is_some(),
        "{} on disk",
        again
    );
    let from_pool = Address::from_base58(from_pool.as_str().unwrap()).unwrap();
    assert!(
        reopened.is_mine(&from_pool),
        "the key from the pool is on disk"
    );
    assert_eq!(reopened.get_account(&own), "lbl", "the label is on disk");
}

/// encryptwallet whose writes fail answers with Divi Core's text, which
/// names no cause (rpcwallet.cpp:2729-2730), and leaves the wallet as it was
#[test]
fn encryptwallet_while_writes_fail_answers_as_divid() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    let rpc = net.rpc();
    writes_fail();
    let reply = rpc.encrypt_wallet(&p(vec![json!("throwaway-pass")]));
    writes_work();
    assert_eq!(
        rpc_error(reply),
        (-16, "Error: Failed to encrypt the wallet.".to_string())
    );
    assert!(!net.wallet.is_encrypted());
}

/// A send that fails after its coins are chosen, here a fee the receiver pays
/// that would leave the payment as dust, with the key pool one short: Divi
/// Core reserves the change key first, and the reservation's top-up throws
/// when it cannot write the new key (wallet.cpp:1786-1793, :2129-2130,
/// :2339-2347). The reply is the derivation's, and the key pool is as it was
#[test]
fn a_failed_send_whose_key_pool_top_up_cannot_be_written_answers_as_divid() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    net.fund();
    let rpc = net.rpc();
    rpc.keypool_refill(&p(vec![])).unwrap();
    net.wallet.new_receiving_address().unwrap();
    let size = net.wallet.keypool_size();
    writes_fail();
    let reply = rpc.send_to_address(&p(vec![
        json!(dest().to_string()),
        json!(0.00006),
        json!("receiver_pays"),
    ]));
    let after = net.wallet.keypool_size();
    writes_work();
    assert_eq!(
        rpc_error(reply),
        (-1, "loadHDChain: WriteHDChain failed".to_string())
    );
    assert_eq!(after, size, "the key pool after the failed send");
}

/// keypoolrefill whose new keys cannot be written: Divi Core derives each key
/// inside its WritePool call, and the derivation throws when it cannot write
/// the HD chain (wallet.cpp:2104, :2339-2347), so its reply is that one and
/// "TopUpKeyPool: writing generated key failed" (:2104-2105) is not reached.
/// The key pool is as it was
#[test]
fn keypoolrefill_whose_keys_cannot_be_written_answers_as_divid() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    let rpc = net.rpc();
    rpc.keypool_refill(&p(vec![])).unwrap();
    net.wallet.new_receiving_address().unwrap();
    let size = net.wallet.keypool_size();
    writes_fail();
    let reply = rpc.keypool_refill(&p(vec![]));
    let after = net.wallet.keypool_size();
    writes_work();
    assert_eq!(
        rpc_error(reply),
        (-1, "loadHDChain: WriteHDChain failed".to_string())
    );
    assert_eq!(after, size, "the key pool after the failed refill");
}

/// A send that cannot be signed while the wallet's writes fail, the key pool
/// full: its change key comes from the pool (no key to write), and the send
/// gives it back in memory, as Divi Core's CReserveKey::ReturnKey does
/// (reservekey.cpp:44-51, wallet.cpp:1805-1809). The reply is Divi Core's,
/// the pool and the next change key are as before, during and after a restart
#[test]
fn a_send_that_cannot_be_signed_while_writes_fail_leaves_the_key_pool_as_it_was() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    unsignable_coin(&net, 10 * COIN);
    net.wallet.top_up_keypool().unwrap();
    net.wallet.save().unwrap();
    let pool = net.wallet.keypool_size();
    let indices = net.wallet.keystore().get_indices();
    let rpc = net.rpc();
    writes_fail();
    let reply = rpc.send_to_address(&p(vec![json!(dest().to_string()), json!(1)]));
    let during = (
        net.wallet.keypool_size(),
        net.wallet.keystore().get_indices(),
    );
    writes_work();
    assert_eq!(
        rpc_error(reply),
        (-4, "Signing transaction failed".to_string())
    );
    assert_eq!(during, (pool, indices), "the key pool and the next keys");

    net.wallet.save().unwrap();
    let path = net.dir.path().join("wallet");
    drop(rpc);
    let Net { wallet, .. } = net;
    drop(wallet);
    let reopened = WalletDb::open(&path, Network::Regtest).unwrap();
    assert_eq!(
        reopened.keystore().get_indices(),
        indices,
        "the next keys after a restart"
    );
}

/// The log lines written while `f` runs on this thread. One global subscriber
/// writes each thread's lines to that thread's buffer (as wallet_sends.rs)
fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
    thread_local! {
        static LINES: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    struct ThreadLines;
    impl std::io::Write for ThreadLines {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            LINES.with(|lines| lines.borrow_mut().extend_from_slice(data));
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(|| ThreadLines)
            .init();
    });
    LINES.with(|lines| lines.borrow_mut().clear());
    let out = f();
    let text =
        LINES.with(|lines| String::from_utf8(std::mem::take(&mut *lines.borrow_mut())).unwrap());
    (out, text)
}

/// A wallet with a keypool of 2 a chain, one receiving key short, as each
/// getnewaddress leaves it: its next top-up must write a key
fn one_key_short(net: &Net) -> WalletRpc {
    net.wallet.keystore().set_keypool_target(2);
    let rpc = net.rpc();
    rpc.keypool_refill(&p(vec![])).unwrap();
    rpc.get_new_address(&p(vec![])).unwrap();
    rpc
}

/// Divi Core's derivation throws before a key it cannot write joins the pool,
/// so a getnewaddress, keypoolrefill or send whose top-up cannot write logs no
/// "keypool added", nor a reservation (wallet.cpp:2104-2112, :2339-2347)
#[test]
fn a_key_that_cannot_be_written_logs_no_keypool_line() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    let rpc = one_key_short(&net);
    // Its key comes from the pool, which its top-up leaves one short again
    net.fund();
    writes_fail();
    let (address, address_log) = logged(|| rpc.get_new_address(&p(vec![])));
    let (refill, refill_log) = logged(|| rpc.keypool_refill(&p(vec![json!(3)])));
    let (sent, send_log) =
        logged(|| rpc.send_to_address(&p(vec![json!(dest().to_string()), json!(1)])));
    writes_work();
    assert!(address.is_err() && refill.is_err() && sent.is_err());
    for log in [address_log, refill_log, send_log] {
        assert!(!log.contains("keypool"), "{log}");
    }
}

/// After a top-up that could not write its keys, the pool's numbers are as
/// Divi Core leaves them, which never added a key nor took one: the next key
/// is numbered one past the newest in the pool, and the oldest receiving key
/// is the one reserved (wallet.cpp:2093-2112, :2154)
#[test]
fn a_key_that_cannot_be_written_leaves_the_pool_numbers_as_they_were() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    let rpc = one_key_short(&net);
    let numbers = net.wallet.keystore().pool_numbers();
    writes_fail();
    assert!(rpc.get_new_address(&p(vec![])).is_err());
    assert!(rpc.keypool_refill(&p(vec![json!(3)])).is_err());
    writes_work();
    assert_eq!(net.wallet.keystore().pool_numbers(), numbers);

    let newest = numbers.iter().map(|n| n.2).max().unwrap();
    let oldest = numbers.iter().filter(|n| !n.0).map(|n| n.2).min().unwrap();
    let (_, log) = logged(|| rpc.get_new_address(&p(vec![])).unwrap());
    assert!(
        log.contains(&format!("keypool added key {}, ", newest + 1)),
        "{log}"
    );
    assert!(
        log.contains(&format!("keypool reserve {oldest}\n")),
        "{log}"
    );
}

/// A send that needs no change reserves a change key and returns it after its
/// top-up; a top-up that cannot write throws first (wallet.cpp:2104-2106,
/// :2129-2130), so the send logs no reservation nor return
#[test]
fn a_send_without_change_whose_top_up_cannot_be_written_logs_no_reservation() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    let rpc = one_key_short(&net);
    // Its key comes from the pool, which its top-up leaves one short again
    net.fund();
    writes_fail();
    let (sent, log) = logged(|| {
        rpc.send_to_address(&p(vec![
            json!(dest().to_string()),
            json!(1),
            json!("sweep_funds"),
        ]))
    });
    writes_work();
    assert_eq!(
        rpc_error(sent),
        (-1, "loadHDChain: WriteHDChain failed".to_string())
    );
    assert!(!log.contains("keypool"), "{log}");
}

/// encryptwallet and walletpassphrase top the keypool up (wallet.cpp:1011-1015,
/// rpcwallet.cpp:2617-2620); a key they cannot write throws before it joins the
/// pool (wallet.cpp:2357-2360), so the pool is as it was
#[test]
fn encryption_and_unlock_top_ups_that_cannot_be_written_leave_the_pool_as_it_was() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    let rpc = one_key_short(&net);
    let pool = net.wallet.keypool_size();
    writes_fail();
    assert!(rpc
        .encrypt_wallet(&p(vec![json!("throwaway-pass")]))
        .is_err());
    writes_work();
    assert_eq!(net.wallet.keypool_size(), pool, "after encryptwallet");

    rpc.encrypt_wallet(&p(vec![json!("throwaway-pass")]))
        .unwrap();
    // A locked getnewaddress takes a pool key and does not top up
    rpc.get_new_address(&p(vec![])).unwrap();
    let pool = net.wallet.keypool_size();
    writes_fail();
    let _ = rpc.wallet_passphrase(&p(vec![json!("throwaway-pass"), json!(60)]));
    writes_work();
    assert_eq!(net.wallet.keypool_size(), pool, "after walletpassphrase");
}

/// On an encrypted wallet Divi Core's derivation writes the encrypted chain,
/// and a key it cannot write answers with that write's text
/// (wallet.cpp:503-506, :2359-2360)
#[test]
fn a_key_that_cannot_be_written_on_an_encrypted_wallet_names_the_encrypted_chain() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    let rpc = one_key_short(&net);
    rpc.encrypt_wallet(&p(vec![json!("throwaway-pass")]))
        .unwrap();
    rpc.wallet_passphrase(&p(vec![json!("throwaway-pass"), json!(60)]))
        .unwrap();
    rpc.get_new_address(&p(vec![])).unwrap();
    writes_fail();
    let address = rpc.get_new_address(&p(vec![]));
    writes_work();
    assert_eq!(
        rpc_error(address),
        (
            -1,
            "loadCryptedHDChain: WriteCryptedHDChain failed".to_string()
        )
    );
}

/// walletpassphrase unlocks, then tops the keypool up; a key it cannot write
/// throws there, so the call answers with that write's text, the wallet stays
/// unlocked and no timer is set (rpcwallet.cpp:2617-2627, wallet.cpp:2359-2360)
#[test]
fn walletpassphrase_whose_top_up_cannot_be_written_answers_as_divid() {
    let _limit = LIMIT.lock();
    let net = Net::new();
    let rpc = one_key_short(&net);
    rpc.encrypt_wallet(&p(vec![json!("throwaway-pass")]))
        .unwrap();
    rpc.get_new_address(&p(vec![])).unwrap();
    writes_fail();
    let reply = rpc.wallet_passphrase(&p(vec![json!("throwaway-pass"), json!(60)]));
    writes_work();
    assert_eq!(
        rpc_error(reply),
        (
            -1,
            "loadCryptedHDChain: WriteCryptedHDChain failed".to_string()
        )
    );
    let info = rpc.get_wallet_info(&p(vec![])).unwrap();
    assert_eq!(info["encryption_status"], "unlocked");
    assert_eq!(info["unlocked_until"], 0);
}
