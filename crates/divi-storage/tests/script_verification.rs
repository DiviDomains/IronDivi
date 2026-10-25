// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Block connection verifies every input script under Divi Core's mandatory
//! flags (coinstakes included, during initial sync too) and refuses a block
//! holding an input that fails. Valid spends of every kind on the chain are
//! still accepted.

use divi_crypto::KeyPair;
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_script::{StakingVaultScript, TransactionSignatureChecker};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

fn push(out: &mut Vec<u8>, data: &[u8]) {
    assert!(data.len() < 0x4c);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

fn p2pkh(kp: &KeyPair) -> Script {
    Script::new_p2pkh(divi_crypto::hash160(&kp.public_key().to_bytes()).as_bytes())
}

/// 2-of-3 multisig redeem script and its P2SH output script
fn multisig(keys: &[KeyPair; 3]) -> (Script, Script) {
    let mut redeem = vec![0x52];
    for k in keys {
        push(&mut redeem, &k.public_key().to_bytes());
    }
    redeem.extend_from_slice(&[0x53, 0xae]);
    let hash = divi_crypto::hash160(&redeem);
    (
        Script::from_bytes(redeem),
        Script::new_p2sh(hash.as_bytes()),
    )
}

fn vault(owner: &KeyPair, manager: &KeyPair) -> Script {
    let h = |k: &KeyPair| *divi_crypto::hash160(&k.public_key().to_bytes()).as_bytes();
    StakingVaultScript::new(h(owner), h(manager)).to_script()
}

/// DER signature plus SIGHASH_ALL over `script_code` for input `i`
fn sign(tx: &Transaction, i: usize, script_code: &Script, value: i64, kp: &KeyPair) -> Vec<u8> {
    let checker = TransactionSignatureChecker::new(tx, i, Amount::from_sat(value));
    let sighash = checker.signature_hash(script_code, 1);
    let mut sig = divi_crypto::sign_hash(kp.secret_key(), &sighash)
        .unwrap()
        .to_der();
    sig.push(1);
    sig
}

fn spend(prevout: OutPoint, value: i64, to: Script) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(prevout, Script::new(), 0xffffffff)],
        vout: vec![TxOut::new(Amount::from_sat(value - 1_000_000), to)],
        lock_time: 0,
    }
}

struct TestChain {
    _dir: tempfile::TempDir,
    chain: Chain,
    miner: KeyPair,
}

impl TestChain {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap();
        TestChain {
            _dir: dir,
            chain,
            miner: KeyPair::new_random(),
        }
    }

    fn coinbase(&self, height: u32, payee: Script) -> Transaction {
        // BIP34: the coinbase starts with the height
        let mut sig = divi_storage::bip34_height_script(height);
        sig.extend_from_slice(&height.to_le_bytes());
        Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), payee)],
            lock_time: 0,
        }
    }

    fn block(&self, txs: Vec<Transaction>) -> Block {
        let tip = self.chain.tip().unwrap();
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        block.transactions = txs;
        block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
        let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        block
    }

    /// Mine a PoW block whose coinbase pays `payee`, plus `txs`; returns
    /// whether the chain accepted it as its new tip
    fn mine(&self, payee: Script, txs: Vec<Transaction>) -> bool {
        let height = self.chain.height() + 1;
        let mut all = vec![self.coinbase(height, payee)];
        all.extend(txs);
        let block = self.block(all);
        self.chain.accept_block(block).is_ok() && self.chain.height() == height
    }

    /// Fund `script` with a 1250 DIVI coinbase and let it mature (20 blocks on regtest)
    fn fund(&self, script: Script) -> (OutPoint, i64) {
        let height = self.chain.height() + 1;
        let cb = self.coinbase(height, script);
        let outpoint = OutPoint::new(cb.txid(), 0);
        let block = self.block(vec![cb]);
        self.chain.accept_block(block).unwrap();
        for _ in 0..20 {
            assert!(self.mine(p2pkh(&self.miner), vec![]));
        }
        (outpoint, 1250 * COIN)
    }

    /// Mine PoW blocks up to the last PoW block, so the next block may be PoS
    fn mine_to_last_pow_block(&self) {
        while self.chain.height() < 100 {
            assert!(self.mine(p2pkh(&self.miner), vec![]));
        }
    }
}

#[test]
fn block_with_unsigned_spend_is_refused() {
    let t = TestChain::new();
    let owner = KeyPair::new_random();
    let (coin, value) = t.fund(p2pkh(&owner));
    let height = t.chain.height();

    let tx = spend(coin, value, p2pkh(&KeyPair::new_random()));
    assert!(!t.mine(p2pkh(&t.miner), vec![tx]));
    assert_eq!(t.chain.height(), height);
    // The coin is still unspent
    assert!(t.chain.get_utxo(&coin).unwrap().is_some());
}

#[test]
fn block_with_wrong_key_spend_is_refused() {
    let t = TestChain::new();
    let owner = KeyPair::new_random();
    let stranger_key = KeyPair::new_random();
    let (coin, value) = t.fund(p2pkh(&owner));

    let mut tx = spend(coin, value, p2pkh(&stranger_key));
    let sig = sign(&tx, 0, &p2pkh(&owner), value, &stranger_key);
    let mut ss = Vec::new();
    push(&mut ss, &sig);
    push(&mut ss, &stranger_key.public_key().to_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert!(!t.mine(p2pkh(&t.miner), vec![tx]));
}

#[test]
fn block_with_wrong_redeem_script_is_refused() {
    let t = TestChain::new();
    let keys = [
        KeyPair::new_random(),
        KeyPair::new_random(),
        KeyPair::new_random(),
    ];
    let (_, p2sh) = multisig(&keys);
    let (coin, value) = t.fund(p2sh);

    // A 1-of-1 redeem script of the spender's own key, not the funded hash
    let stranger_key = KeyPair::new_random();
    let mut other = vec![0x51];
    push(&mut other, &stranger_key.public_key().to_bytes());
    other.extend_from_slice(&[0x51, 0xae]);
    let other = Script::from_bytes(other);
    let mut tx = spend(coin, value, p2pkh(&stranger_key));
    let sig = sign(&tx, 0, &other, value, &stranger_key);
    let mut ss = vec![0x00];
    push(&mut ss, &sig);
    push(&mut ss, other.as_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert!(!t.mine(p2pkh(&t.miner), vec![tx]));
}

#[test]
fn multisig_with_empty_signatures_is_refused() {
    // An empty signature counts as a failed check, as in Divi Core
    let t = TestChain::new();
    let keys = [
        KeyPair::new_random(),
        KeyPair::new_random(),
        KeyPair::new_random(),
    ];
    let (redeem, p2sh) = multisig(&keys);
    let (coin, value) = t.fund(p2sh);
    let mut tx = spend(coin, value, p2pkh(&KeyPair::new_random()));
    let mut ss = vec![0x00, 0x00, 0x00, 0x4c, redeem.as_bytes().len() as u8];
    ss.extend_from_slice(redeem.as_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert!(!t.mine(p2pkh(&t.miner), vec![tx]));
}

#[test]
fn signed_p2pkh_spend_is_accepted() {
    let t = TestChain::new();
    let owner = KeyPair::new_random();
    let (coin, value) = t.fund(p2pkh(&owner));
    let mut tx = spend(coin, value, p2pkh(&KeyPair::new_random()));
    let sig = sign(&tx, 0, &p2pkh(&owner), value, &owner);
    let mut ss = Vec::new();
    push(&mut ss, &sig);
    push(&mut ss, &owner.public_key().to_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert!(t.mine(p2pkh(&t.miner), vec![tx]));
    assert!(t.chain.get_utxo(&coin).unwrap().is_none());
}

#[test]
fn p2sh_multisig_spend_is_accepted() {
    let t = TestChain::new();
    let keys = [
        KeyPair::new_random(),
        KeyPair::new_random(),
        KeyPair::new_random(),
    ];
    let (redeem, p2sh) = multisig(&keys);
    let (coin, value) = t.fund(p2sh);
    let mut tx = spend(coin, value, p2pkh(&KeyPair::new_random()));
    let s0 = sign(&tx, 0, &redeem, value, &keys[0]);
    let s2 = sign(&tx, 0, &redeem, value, &keys[2]);
    let mut ss = vec![0x00];
    push(&mut ss, &s0);
    push(&mut ss, &s2);
    ss.extend_from_slice(&[0x4c, redeem.as_bytes().len() as u8]);
    ss.extend_from_slice(redeem.as_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert!(t.mine(p2pkh(&t.miner), vec![tx]));
}

fn vault_script_sig(sig: &[u8], kp: &KeyPair, owner: bool) -> Script {
    let mut ss = Vec::new();
    push(&mut ss, sig);
    push(&mut ss, &kp.public_key().to_bytes());
    ss.push(if owner { 0x51 } else { 0x00 });
    Script::from_bytes(ss)
}

#[test]
fn vault_owner_reclaim_is_accepted_and_manager_spend_outside_coinstake_refused() {
    let t = TestChain::new();
    let owner = KeyPair::new_random();
    let manager = KeyPair::new_random();
    let vault_spk = vault(&owner, &manager);

    // The manager may not move vault funds in an ordinary transaction
    let (coin, value) = t.fund(vault_spk.clone());
    let mut tx = spend(coin, value, p2pkh(&manager));
    let sig = sign(&tx, 0, &vault_spk, value, &manager);
    tx.vin[0].script_sig = vault_script_sig(&sig, &manager, false);
    assert!(!t.mine(p2pkh(&t.miner), vec![tx]));

    // The owner reclaims
    let mut tx = spend(coin, value, p2pkh(&owner));
    let sig = sign(&tx, 0, &vault_spk, value, &owner);
    tx.vin[0].script_sig = vault_script_sig(&sig, &owner, true);
    assert!(t.mine(p2pkh(&t.miner), vec![tx]));
}

/// A PoS block whose coinstake spends `coin` (a vault output) with the
/// manager key and pays the vault back; signed by the manager
fn vault_stake_block(
    t: &TestChain,
    coin: OutPoint,
    value: i64,
    vault_spk: &Script,
    signer: &KeyPair,
) -> Block {
    // Paying the vault the stake and masternode shares satisfies the rule both
    // before and after DeprecateMasternodes
    let reward = divi_consensus::block_subsidy::get_block_subsidy(t.chain.height() + 1, 100);
    let back = Amount::from_sat(value) + reward.stake + reward.masternode;
    vault_stake_block_paying(t, coin, value, vault_spk, signer, vec![back], vec![])
}

/// A vault stake block whose coinstake pays `vault_outs` back to the vault, then `others`
fn vault_stake_block_paying(
    t: &TestChain,
    coin: OutPoint,
    value: i64,
    vault_spk: &Script,
    signer: &KeyPair,
    vault_outs: Vec<Amount>,
    others: Vec<TxOut>,
) -> Block {
    let height = t.chain.height() + 1;
    let mut coinbase = t.coinbase(height, Script::new());
    coinbase.vout = vec![TxOut::new(Amount::ZERO, Script::new())];
    let mut vout = vec![TxOut::new(Amount::ZERO, Script::new())];
    vout.extend(
        vault_outs
            .into_iter()
            .map(|v| TxOut::new(v, vault_spk.clone())),
    );
    vout.extend(others);
    let mut stake = Transaction {
        version: 1,
        vin: vec![TxIn::new(coin, Script::new(), 0xffffffff)],
        vout,
        lock_time: 0,
    };
    let sig = sign(&stake, 0, vault_spk, value, signer);
    stake.vin[0].script_sig = vault_script_sig(&sig, signer, false);
    let mut block = t.block(vec![coinbase, stake]);
    let hash = divi_crypto::compute_block_hash(&block.header);
    let rsig = divi_crypto::sign_hash_recoverable(signer.secret_key(), hash.as_bytes()).unwrap();
    block.block_sig = rsig.to_compact_with_recovery().to_vec();
    block
}

/// Before DeprecateMasternodes (median time past 2023-08-23; these regtest blocks
/// carry 2018 times) the vault gets its input plus the stake share only, and the
/// masternode share goes to another payee. Mainnet block 1,191,825 has this shape:
/// in 62000 (vault), out 31209 + 31209 (vault, split), 495 to a pubkey hash.
#[test]
fn vault_stake_paying_the_masternode_elsewhere_is_accepted() {
    let t = TestChain::new();
    let owner = KeyPair::new_random();
    let manager = KeyPair::new_random();
    let vault_spk = vault(&owner, &manager);
    let (coin, value) = t.fund(vault_spk.clone());
    t.mine_to_last_pow_block();
    let height = t.chain.height();
    let reward = divi_consensus::block_subsidy::get_block_subsidy(height + 1, 100);
    assert!(reward.masternode > Amount::ZERO);
    // Split in two halves would need 10,000 DIVI each; this vault holds 1250, so
    // the stake share goes into the one vault output
    let back = Amount::from_sat(value) + reward.stake;
    let masternode = TxOut::new(reward.masternode, p2pkh(&KeyPair::new_random()));
    let block = vault_stake_block_paying(
        &t,
        coin,
        value,
        &vault_spk,
        &manager,
        vec![back],
        vec![masternode],
    );
    t.chain
        .accept_block(block)
        .expect("vault keeps the stake share, the masternode share is paid elsewhere");
    assert_eq!(t.chain.height(), height + 1);
}

/// A vault coinstake that pays itself less than its input plus the stake share is refused
#[test]
fn vault_stake_paying_itself_too_little_is_refused() {
    let t = TestChain::new();
    let owner = KeyPair::new_random();
    let manager = KeyPair::new_random();
    let vault_spk = vault(&owner, &manager);
    let (coin, value) = t.fund(vault_spk.clone());
    t.mine_to_last_pow_block();
    let height = t.chain.height();
    let reward = divi_consensus::block_subsidy::get_block_subsidy(height + 1, 100);
    let back = Amount::from_sat(value) + reward.stake - Amount::from_sat(1);
    let elsewhere = TxOut::new(
        reward.masternode + Amount::from_sat(1),
        p2pkh(&KeyPair::new_random()),
    );
    let block = vault_stake_block_paying(
        &t,
        coin,
        value,
        &vault_spk,
        &manager,
        vec![back],
        vec![elsewhere],
    );
    let err = t.chain.accept_block(block).unwrap_err().to_string();
    assert!(err.contains("Vault output value"), "{err}");
    assert_eq!(t.chain.height(), height);
}

#[test]
fn vault_manager_stake_is_accepted() {
    let t = TestChain::new();
    let owner = KeyPair::new_random();
    let manager = KeyPair::new_random();
    let vault_spk = vault(&owner, &manager);
    let (coin, value) = t.fund(vault_spk.clone());
    t.mine_to_last_pow_block();
    let height = t.chain.height();

    let block = vault_stake_block(&t, coin, value, &vault_spk, &manager);
    t.chain
        .accept_block(block)
        .expect("vault stake by the manager");
    assert_eq!(t.chain.height(), height + 1);
}

#[test]
fn vault_stake_signed_by_wrong_key_is_refused() {
    let t = TestChain::new();
    let owner = KeyPair::new_random();
    let manager = KeyPair::new_random();
    let vault_spk = vault(&owner, &manager);
    let (coin, value) = t.fund(vault_spk.clone());
    t.mine_to_last_pow_block();
    let height = t.chain.height();

    // The coinstake input is signed by a key that is not the manager's; the
    // block signature is the manager's, so only the script check catches it
    let stranger_key = KeyPair::new_random();
    let mut block = vault_stake_block(&t, coin, value, &vault_spk, &manager);
    let stake = &mut block.transactions[1];
    let sig = sign(stake, 0, &vault_spk, value, &stranger_key);
    stake.vin[0].script_sig = vault_script_sig(&sig, &stranger_key, false);
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    let hash = divi_crypto::compute_block_hash(&block.header);
    let rsig = divi_crypto::sign_hash_recoverable(manager.secret_key(), hash.as_bytes()).unwrap();
    block.block_sig = rsig.to_compact_with_recovery().to_vec();

    assert!(t.chain.accept_block(block).is_err() || t.chain.height() == height);
    assert_eq!(t.chain.height(), height);
}

// NODE-2: signatures that Divi Core's SignatureHash and EvalScript accept
// under the mandatory flags must be accepted in a block too. The sighash
// here is computed independently of divi-script, the way C++ does it.

/// C++ `SignatureHash` for a hash type whose base is neither NONE nor SINGLE,
/// ANYONECANPAY clear: other scriptSigs blanked, the scriptCode without its
/// OP_CODESEPARATORs in the signed input, and the full 32-bit type appended
fn cpp_sighash_all(tx: &Transaction, i: usize, script_code: &[u8], hash_type: u32) -> [u8; 32] {
    let mut c = tx.clone();
    for input in c.vin.iter_mut() {
        input.script_sig = Script::new();
    }
    // Direct pushes and single-byte opcodes only
    let mut code = Vec::new();
    let mut pc = 0;
    while pc < script_code.len() {
        let op = script_code[pc];
        if (1..=75).contains(&op) {
            code.extend_from_slice(&script_code[pc..pc + 1 + op as usize]);
            pc += 1 + op as usize;
        } else {
            if op != 0xab {
                code.push(op);
            }
            pc += 1;
        }
    }
    c.vin[i].script_sig = Script::from_bytes(code);
    let mut data = divi_primitives::serialize::serialize(&c);
    data.extend_from_slice(&hash_type.to_le_bytes());
    divi_crypto::double_sha256(&data)
}

/// n - s on the secp256k1 group order, big-endian
fn negate_s(s: &[u8]) -> [u8; 32] {
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = N[i] as i16 - s[i] as i16 - borrow;
        borrow = if d < 0 {
            d += 256;
            1
        } else {
            0
        };
        out[i] = d as u8;
    }
    out
}

/// Fund `<pk> CHECKSIG` (with `prefix` opcodes before the push), spend it
/// with a signature of `hash_type`, and report whether the block was accepted
fn mine_pubkey_spend(prefix: &[u8], hash_type: u8, high_s: bool) -> bool {
    let t = TestChain::new();
    let owner = KeyPair::new_random();
    let mut spk = prefix.to_vec();
    push(&mut spk, &owner.public_key().to_bytes());
    spk.push(0xac);
    let spk = Script::from_bytes(spk);
    let (coin, value) = t.fund(spk.clone());

    let mut tx = spend(coin, value, p2pkh(&KeyPair::new_random()));
    let h = cpp_sighash_all(&tx, 0, spk.as_bytes(), hash_type as u32);
    let low = divi_crypto::sign_hash(owner.secret_key(), &h).unwrap();
    let mut sig = if high_s {
        let mut c = low.to_compact();
        let s = negate_s(&c[32..]);
        c[32..].copy_from_slice(&s);
        divi_crypto::signature::Signature::from_compact(&c)
            .unwrap()
            .to_der()
    } else {
        low.to_der()
    };
    sig.push(hash_type);
    let mut ss = Vec::new();
    push(&mut ss, &sig);
    tx.vin[0].script_sig = Script::from_bytes(ss);
    let accepted = t.mine(p2pkh(&t.miner), vec![tx]);
    assert_eq!(accepted, t.chain.get_utxo(&coin).unwrap().is_none());
    accepted
}

#[test]
fn node02_sighash_all_control_is_accepted() {
    assert!(mine_pubkey_spend(&[], 0x01, false));
}

#[test]
fn node02_undefined_hashtypes_are_accepted_as_in_core() {
    // 0x41, 0x00 and 0x04 all hash as ALL with the raw type appended
    for hash_type in [0x41, 0x00, 0x04] {
        assert!(
            mine_pubkey_spend(&[], hash_type, false),
            "hash type {hash_type:#04x}"
        );
    }
}

#[test]
fn node02_high_s_signature_is_accepted_as_in_core() {
    // LOW_S is policy, not a mandatory flag
    assert!(mine_pubkey_spend(&[], 0x01, true));
}

#[test]
fn node02_codeseparator_is_dropped_from_script_code() {
    assert!(mine_pubkey_spend(&[0xab], 0x01, false));
}

#[test]
fn node02_p2sh_spend_with_non_push_script_sig_is_refused() {
    // A valid 2-of-3 spend, but the scriptSig holds an opcode (OP_NOP) before
    // the pushes; Core's P2SH rule needs a push-only scriptSig
    let t = TestChain::new();
    let keys = [
        KeyPair::new_random(),
        KeyPair::new_random(),
        KeyPair::new_random(),
    ];
    let (redeem, p2sh) = multisig(&keys);
    let (coin, value) = t.fund(p2sh);
    let mut tx = spend(coin, value, p2pkh(&KeyPair::new_random()));
    let s0 = sign(&tx, 0, &redeem, value, &keys[0]);
    let s2 = sign(&tx, 0, &redeem, value, &keys[2]);
    let mut ss = vec![0x61, 0x00];
    push(&mut ss, &s0);
    push(&mut ss, &s2);
    ss.extend_from_slice(&[0x4c, redeem.as_bytes().len() as u8]);
    ss.extend_from_slice(redeem.as_bytes());
    tx.vin[0].script_sig = Script::from_bytes(ss);
    assert!(!t.mine(p2pkh(&t.miner), vec![tx]));
    assert!(t.chain.get_utxo(&coin).unwrap().is_some());
}
