// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Regtest block builders for the block-rule tests: PoW blocks with a real proof
//! of work for regtest's bits, and signed PoS blocks.
#![allow(dead_code)]

use divi_consensus::block_subsidy;
use divi_crypto::{compute_block_hash, compute_merkle_root, SecretKey};
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_storage::{BlockIndex, Chain, ChainDatabase, ChainParams, NetworkType, StorageError};
use std::sync::Arc;
use tempfile::TempDir;

pub const COIN: i64 = 100_000_000;
/// Regtest's PoW limit, ~uint256(0) >> 1, which it never retargets from
pub const REGTEST_BITS: u32 = 0x207fffff;

/// A stake or coinbase output we can spend: where, how much, and at what height
#[derive(Clone, Copy)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub height: u32,
}

pub struct TestChain {
    _dir: TempDir,
    pub chain: Chain,
    pub key: SecretKey,
    pub pay: Script,
    pub tag: std::cell::Cell<u32>,
}

pub fn regtest() -> ChainParams {
    ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi)
}

pub fn err_text<T>(r: Result<T, StorageError>) -> String {
    match r {
        Ok(_) => String::from("<accepted>"),
        Err(e) => e.to_string(),
    }
}

/// Grind the nonce until the header hash meets its bits
pub fn mine(block: &mut Block) {
    let target = Hash256::from_compact(block.header.bits);
    while compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
}

/// A nonce whose hash does NOT meet the bits
pub fn mine_failing(block: &mut Block) {
    let target = Hash256::from_compact(block.header.bits);
    while compute_block_hash(&block.header) <= target {
        block.header.nonce += 1;
    }
}

pub fn sign_input(tx: &mut Transaction, i: usize, script: &Script, value: Amount, key: &SecretKey) {
    let sighash =
        divi_script::TransactionSignatureChecker::new(tx, i, value).signature_hash(script, 1);
    let mut sig = divi_crypto::sign_hash(key, &sighash).unwrap().to_der();
    sig.push(1);
    let pubkey = key.public_key().to_bytes();
    let mut ss = vec![sig.len() as u8];
    ss.extend_from_slice(&sig);
    ss.push(pubkey.len() as u8);
    ss.extend_from_slice(&pubkey);
    tx.vin[i].script_sig = Script::from_bytes(ss);
}

impl TestChain {
    pub fn new(params: ChainParams) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Chain::new(db, params).unwrap();
        let key = SecretKey::from_bytes(&[7u8; 32]).unwrap();
        let pay = Script::new_p2pkh(key.public_key().pubkey_hash().as_bytes());
        TestChain {
            _dir: dir,
            chain,
            key,
            pay,
            tag: std::cell::Cell::new(0),
        }
    }

    pub fn tip(&self) -> BlockIndex {
        self.chain.tip().unwrap()
    }

    pub fn index(&self, hash: &Hash256) -> BlockIndex {
        self.chain.get_block_index(hash).unwrap().unwrap()
    }

    /// A coinbase with a unique script
    pub fn coinbase(&self, height: u32, outputs: Vec<TxOut>) -> Transaction {
        let tag = self.tag.get() + 1;
        self.tag.set(tag);
        let mut sig = vec![8u8];
        sig.extend_from_slice(&height.to_le_bytes());
        sig.extend_from_slice(&tag.to_le_bytes());
        Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: outputs,
            lock_time: 0,
        }
    }

    /// An unmined PoW block on `parent` whose coinbase pays `value` to us
    pub fn pow_block_raw(
        &self,
        parent: &BlockIndex,
        value: Amount,
        extra: Vec<Transaction>,
    ) -> Block {
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = parent.hash;
        block.header.time = parent.time + 60;
        block.header.bits = REGTEST_BITS;
        block.transactions =
            vec![self.coinbase(parent.height + 1, vec![TxOut::new(value, self.pay.clone())])];
        block.transactions.extend(extra);
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        block
    }

    pub fn pow_block(&self, parent: &BlockIndex, value: Amount, extra: Vec<Transaction>) -> Block {
        let mut block = self.pow_block_raw(parent, value, extra);
        mine(&mut block);
        block
    }

    /// Mine `n` PoW blocks of 1250 DIVI on the tip; returns their coinbases
    pub fn extend_pow(&self, n: u32) -> Vec<Coin> {
        let mut coins = Vec::new();
        for _ in 0..n {
            let tip = self.tip();
            let block = self.pow_block(&tip, Amount::from_sat(1250 * COIN), vec![]);
            let cb = block.transactions[0].txid();
            self.chain.accept_block(block).unwrap();
            assert_eq!(self.chain.height(), tip.height + 1);
            coins.push(Coin {
                outpoint: OutPoint::new(cb, 0),
                value: Amount::from_sat(1250 * COIN),
                height: tip.height + 1,
            });
        }
        coins
    }

    /// The coinstake reward a regtest block at `height` may claim
    pub fn stake_reward(height: u32) -> Amount {
        let r = block_subsidy::get_block_subsidy(height, 100);
        r.stake + r.masternode
    }

    /// A signed PoS block on `parent` staking `kernel`. `edit` may change the
    /// coinstake before it is signed and the block before it is signed.
    pub fn pos_block(
        &self,
        parent: &BlockIndex,
        time: u32,
        kernel: Coin,
        edit_coinstake: impl FnOnce(&mut Transaction),
        edit_block: impl FnOnce(&mut Block),
    ) -> Block {
        let height = parent.height + 1;
        let mut coinstake = Transaction {
            version: 1,
            vin: vec![TxIn::new(kernel.outpoint, Script::new(), 0xffff_ffff)],
            vout: vec![
                TxOut::new(Amount::ZERO, Script::default()),
                TxOut::new(kernel.value + Self::stake_reward(height), self.pay.clone()),
            ],
            lock_time: 0,
        };
        edit_coinstake(&mut coinstake);
        sign_input(&mut coinstake, 0, &self.pay, kernel.value, &self.key);
        let marker = self.coinbase(height, vec![TxOut::new(Amount::ZERO, Script::default())]);

        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = parent.hash;
        block.header.time = time;
        block.header.bits = REGTEST_BITS;
        block.transactions = vec![marker, coinstake];
        edit_block(&mut block);
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        let hash = compute_block_hash(&block.header);
        block.block_sig = divi_crypto::sign_hash_recoverable(&self.key, hash.as_bytes())
            .unwrap()
            .to_compact_with_recovery()
            .to_vec();
        block
    }

    pub fn simple_pos(&self, parent: &BlockIndex, kernel: Coin) -> Block {
        self.pos_block(parent, parent.time + 60, kernel, |_| {}, |_| {})
    }

    /// The coinstake's staked output of `block`, as a coin
    pub fn stake_of(block: &Block, height: u32) -> Coin {
        Coin {
            outpoint: OutPoint::new(block.transactions[1].txid(), 1),
            value: block.transactions[1].vout[1].value,
            height,
        }
    }

    /// A transaction spending `coin` (ours) to `outputs`
    pub fn spend(&self, coin: Coin, outputs: Vec<TxOut>) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(coin.outpoint, Script::new(), 0xffff_ffff)],
            vout: outputs,
            lock_time: 0,
        };
        sign_input(&mut tx, 0, &self.pay, coin.value, &self.key);
        tx
    }
}

pub fn resign(t: &TestChain, mut b: Block) -> Block {
    let hash = compute_block_hash(&b.header);
    b.block_sig = divi_crypto::sign_hash_recoverable(&t.key, hash.as_bytes())
        .unwrap()
        .to_compact_with_recovery()
        .to_vec();
    b
}
