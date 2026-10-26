// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Wallet calls that overlap. Divi Core runs each wallet call under cs_main
//! (rpcserver.cpp:1060-1094), and its unlock timer relocks under cs_wallet
//! (:1160-1174), so walletlock and the timer come before or after a send,
//! never in the middle of one.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::error::Error;
use divi_rpc::{Params, WalletRpc};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};

const COIN: i64 = 100_000_000;
const COINS: usize = 300;

/// A regtest chain, a funder wallet with mature coins, and an encrypted
/// wallet under test
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
        wallet.save().unwrap();
        wallet.encrypt_wallet("pw").unwrap();
        Net {
            chain: Arc::new(chain),
            _dir: dir,
            funder: Arc::new(WalletDb::with_hd_wallet(
                Network::Regtest,
                HdWallet::new(ChainMode::Divi).unwrap(),
            )),
            wallet: Arc::new(wallet),
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

    /// Give the wallet under test `count` confirmed coins of 0.1 DIVI, from
    /// mature coinbases of the funder, at most `COINS` to a transaction;
    /// returns their address
    fn fund(&self, count: usize) -> Address {
        let cb_addr = self.funder.new_receiving_address().unwrap();
        let coinbases: Vec<Transaction> = (0..count.div_ceil(COINS))
            .map(|_| self.mine(vec![], &cb_addr))
            .collect();
        // Coinbase maturity 20 on regtest: spendable with 21 confirmations
        for _ in 0..20 {
            self.mine(vec![], &self.miner);
        }
        let addr = self.wallet.new_receiving_address().unwrap();
        let mut txs = Vec::new();
        let mut left = count;
        for coinbase in coinbases {
            let n = left.min(COINS);
            left -= n;
            let mut builder = TransactionBuilder::new().add_input(
                OutPoint::new(coinbase.txid(), 0),
                coinbase.vout[0].script_pubkey.clone(),
            );
            for _ in 0..n {
                builder = builder.add_output_to_address(Amount::from_sat(COIN / 10), &addr);
            }
            let rest = 1250 * COIN - n as i64 * (COIN / 10) - COIN / 100;
            builder = builder.add_output_to_address(Amount::from_sat(rest), &self.miner);
            let (mut tx, prev) = builder.build();
            TransactionSigner::new(self.funder.keystore())
                .sign_all_inputs(&mut tx, &prev)
                .unwrap();
            txs.push(tx);
        }
        self.mine(txs, &self.miner);
        addr
    }
}

fn p(v: Vec<Value>) -> Params {
    Params::Array(v)
}

fn code(e: &Error) -> i32 {
    match e {
        Error::Rpc(e) => e.code,
        other => panic!("not an RPC error: {other:?}"),
    }
}

/// A walletlock that comes while a send of some 250 inputs (long to sign) is
/// under way: once the send has made its change key, it has got past its
/// unlock check, and the lock comes then. The send is made in full, never cut
/// short by keys taken away in the middle; the wallet is locked afterwards,
/// its keys gone from memory, and a send after the lock is refused with -13.
#[test]
fn walletlock_during_a_send_comes_before_or_after_it() {
    let net = Net::new();
    let rpc = net.rpc();
    let dest = Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest);
    for round in 0..3 {
        let funded = net.fund(COINS);
        rpc.wallet_passphrase(&p(vec![json!("pw"), json!(0)]))
            .unwrap();
        let sent_before = net.submitted.lock().len();
        let change_before = net.wallet.keystore().get_indices().1;
        let send_done = AtomicBool::new(false);
        let barrier = Barrier::new(2);
        let (send, lock) = std::thread::scope(|s| {
            let send = s.spawn(|| {
                barrier.wait();
                let out = rpc.send_to_address(&p(vec![json!(dest.to_string()), json!(25.0)]));
                send_done.store(true, Ordering::SeqCst);
                out
            });
            let lock = s.spawn(|| {
                barrier.wait();
                // The change key is made before the inputs are signed
                while net.wallet.keystore().get_indices().1 == change_before
                    && !send_done.load(Ordering::SeqCst)
                {
                    std::thread::yield_now();
                }
                let mid_send = !send_done.load(Ordering::SeqCst);
                (mid_send, rpc.wallet_lock(&p(vec![])))
            });
            (send.join().unwrap(), lock.join().unwrap())
        });
        let (mid_send, lock) = lock;
        assert!(
            mid_send,
            "round {round}: the send ended before it made its change key: {send:?}"
        );
        assert_eq!(lock.unwrap(), Value::Null, "round {round}: walletlock");
        if let Err(e) = &send {
            panic!("round {round}: a send under way when the lock came failed: {e:?}");
        }
        assert_eq!(net.submitted.lock().len(), sent_before + 1);
        let tx = net.submitted.lock().last().cloned().unwrap();
        assert!(
            tx.vin.len() > 200 && tx.vin.iter().all(|i| !i.script_sig.is_empty()),
            "round {round}: a send with unsigned inputs"
        );
        assert!(
            net.wallet.is_locked(),
            "round {round}: not locked afterwards"
        );
        let key = net.wallet.get_key_by_address(&funded).unwrap();
        assert!(
            key.secret.is_none(),
            "round {round}: a private key is still in memory after the lock"
        );
        let after = rpc
            .send_to_address(&p(vec![json!(dest.to_string()), json!(1.0)]))
            .unwrap_err();
        assert_eq!(code(&after), -13, "round {round}: a send after the lock");
    }
}

/// A block holding the wallet's own send, scanned while the wallet is read:
/// every reply shows the wallet before the block or after it. In Divi Core a
/// block's wallet update and a wallet call both run under cs_main. While
/// irondivid scanned such a block, the send's change was already a confirmed
/// coin but still an output of the send in the mempool, so listunspent 0 and
/// getbalance at minconf 0 counted it twice.
#[test]
fn a_block_with_an_own_send_is_never_counted_twice() {
    let net = Net::new();
    let rpc = net.rpc();
    let dest = Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest);
    rpc.wallet_passphrase(&p(vec![json!("pw"), json!(0)]))
        .unwrap();
    net.fund(10 * COINS);
    let mut seen_twice = 0;
    let mut over = 0;
    for round in 0..10 {
        // About 250 inputs, so the block takes a while to scan
        rpc.send_to_address(&p(vec![json!(dest.to_string()), json!(25.0)]))
            .unwrap_or_else(|e| panic!("round {round}: {e:?}"));
        let tx = net.submitted.lock().last().cloned().unwrap();
        assert!(net.wallet.add_mempool_tx(&tx));
        let height = net.chain.height();
        let ceiling = net.wallet.get_confirmed_balance(height, 0);
        let done = AtomicBool::new(false);
        std::thread::scope(|s| {
            let reader = s.spawn(|| {
                let (mut twice, mut above) = (0, 0);
                while !done.load(Ordering::SeqCst) {
                    let coins = net.wallet.get_utxos();
                    let outpoints: std::collections::HashSet<_> =
                        coins.iter().map(|u| u.outpoint()).collect();
                    if outpoints.len() != coins.len() {
                        twice += 1;
                    }
                    if net.wallet.get_confirmed_balance(height + 1, 0) > ceiling {
                        above += 1;
                    }
                }
                (twice, above)
            });
            net.mine(vec![tx], &net.miner);
            done.store(true, Ordering::SeqCst);
            let (twice, above) = reader.join().unwrap();
            seen_twice += twice;
            over += above;
        });
    }
    assert_eq!(seen_twice, 0, "replies listing a coin twice");
    assert_eq!(over, 0, "balances above the wallet's coins");
}
