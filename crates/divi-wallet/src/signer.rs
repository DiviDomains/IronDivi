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

//! Transaction signing
//!
//! Provides functionality to sign transactions using wallet keys.

use crate::address::Address;
use crate::error::WalletError;
use crate::keystore::KeyStore;
use divi_crypto::keys::{PublicKey, SecretKey};
use divi_crypto::signature::sign_hash;
use divi_primitives::amount::Amount;
use divi_primitives::constants::CURRENT_TX_VERSION;
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::{SigHashType, StakingVaultScript};
use sha2::{Digest, Sha256};

/// Compute sighash for transaction input
///
/// This creates the hash that must be signed to authorize spending an input.
pub fn sighash(
    tx: &Transaction,
    input_index: usize,
    script_code: &Script,
    sighash_type: SigHashType,
    anyone_can_pay: bool,
) -> Result<Hash256, WalletError> {
    if input_index >= tx.vin.len() {
        return Err(WalletError::TransactionError(format!(
            "Input index {} out of bounds (tx has {} inputs)",
            input_index,
            tx.vin.len()
        )));
    }

    // Build modified transaction for signing
    let mut tx_copy = tx.clone();

    // Clear all input scripts
    for input in tx_copy.vin.iter_mut() {
        input.script_sig = Script::new();
    }

    // Set the script for the input being signed
    tx_copy.vin[input_index].script_sig = script_code.clone();

    // Handle different sighash types
    match sighash_type {
        SigHashType::All => {
            // SIGHASH_ALL: Sign all inputs and outputs (default)
        }
        SigHashType::None => {
            // SIGHASH_NONE: Sign all inputs, no outputs
            tx_copy.vout.clear();
            // Set all other input sequences to 0
            for (i, input) in tx_copy.vin.iter_mut().enumerate() {
                if i != input_index {
                    input.sequence = 0;
                }
            }
        }
        SigHashType::Single => {
            // SIGHASH_SINGLE: Sign all inputs, only output at same index
            if input_index >= tx_copy.vout.len() {
                // If no matching output, return 1 (special case)
                return Ok(Hash256::from_bytes([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1,
                ]));
            }
            // Keep only the output at input_index
            let output = tx_copy.vout[input_index].clone();
            tx_copy.vout.clear();
            for _ in 0..input_index {
                tx_copy
                    .vout
                    .push(TxOut::new(Amount::from_sat(-1), Script::new()));
            }
            tx_copy.vout.push(output);
            // Set all other input sequences to 0
            for (i, input) in tx_copy.vin.iter_mut().enumerate() {
                if i != input_index {
                    input.sequence = 0;
                }
            }
        }
        SigHashType::AnyoneCanPay => {
            // This shouldn't happen as ANYONECANPAY is a modifier
        }
    }

    // Handle ANYONECANPAY modifier
    if anyone_can_pay {
        // Only keep the input being signed
        let input = tx_copy.vin[input_index].clone();
        tx_copy.vin.clear();
        tx_copy.vin.push(input);
    }

    // Serialize and double-hash
    let mut data = serialize(&tx_copy);

    // Append sighash type as 4-byte LE
    let hash_type_value = if anyone_can_pay {
        (sighash_type as u32) | 0x80
    } else {
        sighash_type as u32
    };
    data.extend_from_slice(&hash_type_value.to_le_bytes());

    // Double SHA256
    let hash = double_sha256(&data);

    Ok(Hash256::from_bytes(hash))
}

/// Double SHA256 hash
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Sign a single transaction input
pub fn sign_input(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    secret_key: &SecretKey,
    sighash_type: SigHashType,
) -> Result<Vec<u8>, WalletError> {
    sign_input_with_flags(
        tx,
        input_index,
        script_pubkey,
        secret_key,
        sighash_type,
        false,
    )
}

/// Sign a single transaction input, optionally with SIGHASH_ANYONECANPAY
pub fn sign_input_with_flags(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    secret_key: &SecretKey,
    sighash_type: SigHashType,
    anyone_can_pay: bool,
) -> Result<Vec<u8>, WalletError> {
    let hash = sighash(tx, input_index, script_pubkey, sighash_type, anyone_can_pay)?;

    let signature = sign_hash(secret_key, hash.as_bytes())
        .map_err(|e| WalletError::TransactionError(e.to_string()))?;

    // Append sighash type byte to DER signature
    let mut sig_bytes = signature.to_der();
    let acp = if anyone_can_pay { 0x80 } else { 0 };
    sig_bytes.push(sighash_type as u8 | acp);

    Ok(sig_bytes)
}

/// Create a P2PKH script sig from signature and public key
pub fn create_p2pkh_script_sig(signature: &[u8], pubkey: &PublicKey) -> Script {
    create_p2pkh_script_sig_with_pubkey(signature, &pubkey.to_bytes())
}

/// Create a P2PKH script sig from a signature and serialized public key (33 or 65 bytes)
pub fn create_p2pkh_script_sig_with_pubkey(signature: &[u8], pubkey_bytes: &[u8]) -> Script {
    let mut script_data = Vec::new();

    // Push signature
    script_data.push(signature.len() as u8);
    script_data.extend_from_slice(signature);

    // Push public key
    script_data.push(pubkey_bytes.len() as u8);
    script_data.extend_from_slice(pubkey_bytes);

    Script::from_bytes(script_data)
}

/// Create a vault owner scriptSig: `<signature> <pubkey> OP_TRUE`
///
/// OP_TRUE (0x51) selects the IF branch of the vault script, which is the owner path.
pub fn create_vault_owner_script_sig(signature: &[u8], pubkey: &PublicKey) -> Script {
    create_vault_owner_script_sig_with_pubkey(signature, &pubkey.to_bytes())
}

/// Vault owner scriptSig from a serialized public key (33 or 65 bytes)
pub fn create_vault_owner_script_sig_with_pubkey(signature: &[u8], pubkey_bytes: &[u8]) -> Script {
    let mut script_data = Vec::new();

    // Push signature
    script_data.push(signature.len() as u8);
    script_data.extend_from_slice(signature);

    // Push public key
    script_data.push(pubkey_bytes.len() as u8);
    script_data.extend_from_slice(pubkey_bytes);

    // OP_TRUE (= OP_1 = 0x51) — selects the IF (owner) branch
    script_data.push(0x51);

    Script::from_bytes(script_data)
}

/// A signature (with its hash type byte) and the serialized public key that made it
type SignatureAndPubkey = (Vec<u8>, Vec<u8>);

/// Transaction signer that uses keystore for signing
pub struct TransactionSigner<'a> {
    keystore: &'a KeyStore,
    /// Hash type and ANYONECANPAY flag used by sign_and_merge_input
    hash_type: (SigHashType, bool),
}

impl<'a> TransactionSigner<'a> {
    /// Create a new transaction signer
    pub fn new(keystore: &'a KeyStore) -> Self {
        TransactionSigner {
            keystore,
            hash_type: (SigHashType::All, false),
        }
    }

    /// Sign with this hash type (signrawtransaction's sighashtype) instead of ALL
    pub fn with_hash_type(mut self, sighash_type: SigHashType, anyone_can_pay: bool) -> Self {
        self.hash_type = (sighash_type, anyone_can_pay);
        self
    }

    /// Sign a transaction input using a specific address's key
    pub fn sign_input_with_address(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        script_pubkey: &Script,
        address: &Address,
    ) -> Result<(), WalletError> {
        let entry = self.keystore.get_key_by_address(address).ok_or_else(|| {
            WalletError::KeyNotFound(format!("No key found for address {}", address))
        })?;

        // Check if this is a watch-only address
        if entry.is_watch_only {
            return Err(WalletError::KeyNotFound(format!(
                "Address {} is watch-only, cannot sign transactions",
                address
            )));
        }

        let secret = entry.secret.as_ref().ok_or_else(|| {
            WalletError::KeyNotFound(format!("No private key for address {}", address))
        })?;

        let sig = sign_input(tx, input_index, script_pubkey, secret, SigHashType::All)?;
        let script_sig = create_p2pkh_script_sig_with_pubkey(&sig, &entry.pubkey_bytes());

        tx.vin[input_index].script_sig = script_sig;
        Ok(())
    }

    /// Attempt to sign all inputs in a transaction
    /// Returns the number of inputs successfully signed
    pub fn sign_all_inputs(
        &self,
        tx: &mut Transaction,
        input_scripts: &[Script],
    ) -> Result<usize, WalletError> {
        if input_scripts.len() != tx.vin.len() {
            return Err(WalletError::TransactionError(format!(
                "Expected {} scripts, got {}",
                tx.vin.len(),
                input_scripts.len()
            )));
        }

        let mut signed = 0;
        for (i, script) in input_scripts.iter().enumerate() {
            // Try to extract address from script and find key
            if let Some(hash_bytes) = script.extract_p2pkh_hash() {
                let hash = Hash160::from_bytes(hash_bytes);
                if let Some(entry) = self.keystore.get_key(&hash) {
                    // Skip watch-only keys (can't sign)
                    if entry.is_watch_only || entry.secret.is_none() {
                        continue;
                    }

                    let secret = entry.secret.as_ref().unwrap();
                    let sig = sign_input(tx, i, script, secret, SigHashType::All)?;
                    let script_sig =
                        create_p2pkh_script_sig_with_pubkey(&sig, &entry.pubkey_bytes());
                    tx.vin[i].script_sig = script_sig;
                    signed += 1;
                }
            } else if let Some(vault) = StakingVaultScript::from_script(script) {
                // Vault script: sign with the owner key (IF branch)
                let owner_hash = Hash160::from_bytes(vault.owner_pubkey_hash);
                if let Some(entry) = self.keystore.get_key(&owner_hash) {
                    // Skip watch-only keys (can't sign)
                    if entry.is_watch_only || entry.secret.is_none() {
                        continue;
                    }

                    let secret = entry.secret.as_ref().unwrap();
                    // The sighash uses the full vault script as script_code
                    let sig = sign_input(tx, i, script, secret, SigHashType::All)?;
                    // scriptSig: <sig> <pubkey> OP_TRUE  (selects the owner/IF branch)
                    let script_sig =
                        create_vault_owner_script_sig_with_pubkey(&sig, &entry.pubkey_bytes());
                    tx.vin[i].script_sig = script_sig;
                    signed += 1;
                }
            }
        }

        Ok(signed)
    }
}

/// Append a minimal data push to a script
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0 => script.push(0x00),
        n @ 1..=75 => script.push(n as u8),
        n @ 76..=255 => script.extend_from_slice(&[0x4c, n as u8]),
        n => {
            script.push(0x4d);
            script.extend_from_slice(&(n as u16).to_le_bytes());
        }
    }
    script.extend_from_slice(data);
}

/// The data pushes of a push-only scriptSig (None if it holds any other opcode)
fn script_pushes(script: &Script) -> Option<Vec<Vec<u8>>> {
    use divi_script::ScriptItem;
    divi_script::ScriptIterator::new(script.as_bytes())
        .map(|item| match item {
            ScriptItem::PushData(d) => Some(d),
            ScriptItem::Opcode(op) if (0x51..=0x60).contains(&op) => Some(vec![op - 0x50]),
            _ => None,
        })
        .collect()
}

fn script_of(pushes: &[Vec<u8>]) -> Script {
    let mut out = Vec::new();
    for p in pushes {
        push_data(&mut out, p);
    }
    Script::from_bytes(out)
}

fn hash160_of(data: &[u8]) -> Hash160 {
    divi_crypto::hash160(data)
}

impl<'a> TransactionSigner<'a> {
    /// Sign input `index` the way Divi Core's signrawtransaction does: produce the
    /// signatures our keys allow for `script_pubkey` (P2PKH, P2PK, bare multisig, vault
    /// owner, and P2SH wrapping any of them, with the redeem script from `redeem_script`),
    /// merge them with the signatures already in the input, and return whether the input
    /// now verifies.
    pub fn sign_and_merge_input(
        &self,
        tx: &mut Transaction,
        index: usize,
        script_pubkey: &Script,
        redeem_script: &dyn Fn(&Hash160) -> Option<Script>,
    ) -> Result<bool, WalletError> {
        if index >= tx.vin.len() {
            return Err(WalletError::TransactionError(format!(
                "Input {} out of range",
                index
            )));
        }
        let existing = std::mem::take(&mut tx.vin[index].script_sig);
        let ours = self.produce(tx, index, script_pubkey, redeem_script, true)?;
        tx.vin[index].script_sig = combine_signatures(tx, index, script_pubkey, &ours, &existing);
        Ok(divi_script::verify_input(tx, index, script_pubkey, Amount::ZERO).is_ok())
    }

    /// Signature for `script_code` with the key for `hash`, if we hold its private key
    fn sign_with(
        &self,
        tx: &Transaction,
        index: usize,
        script_code: &Script,
        hash: &Hash160,
    ) -> Result<Option<SignatureAndPubkey>, WalletError> {
        let Some(entry) = self.keystore.get_key(hash) else {
            return Ok(None);
        };
        let Some(secret) = entry.secret.as_ref().filter(|_| !entry.is_watch_only) else {
            return Ok(None);
        };
        let (sighash_type, anyone_can_pay) = self.hash_type;
        let sig =
            sign_input_with_flags(tx, index, script_code, secret, sighash_type, anyone_can_pay)?;
        Ok(Some((sig, entry.pubkey_bytes())))
    }

    /// Divi Core's SignSignature/Solver: the scriptSig our keys can produce (maybe partial)
    fn produce(
        &self,
        tx: &Transaction,
        index: usize,
        script: &Script,
        redeem_script: &dyn Fn(&Hash160) -> Option<Script>,
        allow_p2sh: bool,
    ) -> Result<Script, WalletError> {
        use divi_script::standard::{extract_script_type, ScriptType};

        let (script_type, solutions) = extract_script_type(script.as_bytes());
        let mut out = Vec::new();
        match script_type {
            ScriptType::PubKeyHash => {
                let hash = hash160_from_slice(&solutions[0]);
                if let Some((sig, public)) = self.sign_with(tx, index, script, &hash)? {
                    push_data(&mut out, &sig);
                    push_data(&mut out, &public);
                }
            }
            ScriptType::PubKey => {
                let pubkey = &solutions[0];
                if let Some((sig, public)) =
                    self.sign_with(tx, index, script, &hash160_of(pubkey))?
                {
                    if public == *pubkey {
                        push_data(&mut out, &sig);
                    }
                }
            }
            ScriptType::Multisig => {
                let required = solutions[0][0] as usize;
                let mut signed = 0;
                out.push(0x00); // CHECKMULTISIG pops one item too many
                for pubkey in &solutions[1..solutions.len() - 1] {
                    if signed == required {
                        break;
                    }
                    if let Some((sig, public)) =
                        self.sign_with(tx, index, script, &hash160_of(pubkey))?
                    {
                        if public == *pubkey {
                            push_data(&mut out, &sig);
                            signed += 1;
                        }
                    }
                }
            }
            ScriptType::Vault => {
                if let Some(vault) = StakingVaultScript::from_script(script) {
                    let owner = Hash160::from_bytes(vault.owner_pubkey_hash);
                    if let Some((sig, public)) = self.sign_with(tx, index, script, &owner)? {
                        out = create_vault_owner_script_sig_with_pubkey(&sig, &public).into_bytes();
                    }
                }
            }
            ScriptType::ScriptHash if allow_p2sh => {
                let hash = hash160_from_slice(&solutions[0]);
                if let Some(redeem) = redeem_script(&hash) {
                    let inner = self.produce(tx, index, &redeem, redeem_script, false)?;
                    out = inner.into_bytes();
                    push_data(&mut out, redeem.as_bytes());
                }
            }
            _ => {}
        }
        Ok(Script::from_bytes(out))
    }
}

fn hash160_from_slice(bytes: &[u8]) -> Hash160 {
    let mut h = [0u8; 20];
    h.copy_from_slice(&bytes[..20]);
    Hash160::from_bytes(h)
}

/// Divi Core's CombineSignatures: merge two scriptSigs for the same input
fn combine_signatures(
    tx: &Transaction,
    index: usize,
    script_pubkey: &Script,
    ours: &Script,
    theirs: &Script,
) -> Script {
    use divi_script::standard::{extract_script_type, ScriptType};

    let (Some(sigs1), Some(sigs2)) = (script_pushes(ours), script_pushes(theirs)) else {
        return if ours.is_empty() {
            theirs.clone()
        } else {
            ours.clone()
        };
    };
    let first_empty = |s: &[Vec<u8>]| s.first().is_none_or(|x| x.is_empty());
    let last_empty = |s: &[Vec<u8>]| s.last().is_none_or(|x| x.is_empty());

    let (script_type, solutions) = extract_script_type(script_pubkey.as_bytes());
    match script_type {
        ScriptType::Multisig => {
            combine_multisig(tx, index, script_pubkey, &solutions, &sigs1, &sigs2)
        }
        ScriptType::ScriptHash => {
            if last_empty(&sigs1) {
                return theirs.clone();
            }
            if last_empty(&sigs2) {
                return ours.clone();
            }
            // Both carry the redeem script: merge what sits below it
            let redeem = Script::from_bytes(sigs1[sigs1.len() - 1].clone());
            let inner1 = script_of(&sigs1[..sigs1.len() - 1]);
            let inner2 = script_of(&sigs2[..sigs2.len() - 1]);
            let mut merged = combine_signatures(tx, index, &redeem, &inner1, &inner2).into_bytes();
            push_data(&mut merged, redeem.as_bytes());
            Script::from_bytes(merged)
        }
        _ => {
            // Signatures are bigger than placeholders or empty scripts
            if first_empty(&sigs1) {
                theirs.clone()
            } else {
                ours.clone()
            }
        }
    }
}

/// Divi Core's CombineMultisig: every valid signature, in pubkey order, padded with OP_0
fn combine_multisig(
    tx: &Transaction,
    index: usize,
    script: &Script,
    solutions: &[Vec<u8>],
    sigs1: &[Vec<u8>],
    sigs2: &[Vec<u8>],
) -> Script {
    use divi_script::SignatureChecker;

    let checker = divi_script::TransactionSignatureChecker::new(tx, index, Amount::ZERO);
    let required = solutions[0][0] as usize;
    let pubkeys = &solutions[1..solutions.len() - 1];
    let mut by_key: Vec<Option<&Vec<u8>>> = vec![None; pubkeys.len()];
    for sig in sigs1.iter().chain(sigs2).filter(|s| !s.is_empty()) {
        for (k, pubkey) in pubkeys.iter().enumerate() {
            if by_key[k].is_none() && checker.check_sig(sig, pubkey, script) {
                by_key[k] = Some(sig);
                break;
            }
        }
    }
    let mut out = vec![0x00];
    let mut have = 0;
    for sig in by_key.into_iter().flatten() {
        if have == required {
            break;
        }
        push_data(&mut out, sig);
        have += 1;
    }
    out.resize(out.len() + (required - have), 0x00);
    Script::from_bytes(out)
}

/// Simple transaction builder for creating unsigned transactions
pub struct TransactionBuilder {
    version: i32,
    inputs: Vec<(OutPoint, Script)>,
    outputs: Vec<TxOut>,
    lock_time: u32,
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        TransactionBuilder {
            version: CURRENT_TX_VERSION,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    /// Set transaction version
    pub fn version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }

    /// Add an input
    pub fn add_input(mut self, outpoint: OutPoint, prev_script_pubkey: Script) -> Self {
        self.inputs.push((outpoint, prev_script_pubkey));
        self
    }

    /// Add an output
    pub fn add_output(mut self, value: Amount, script_pubkey: Script) -> Self {
        self.outputs.push(TxOut::new(value, script_pubkey));
        self
    }

    /// Add an output paying an address (P2PKH or P2SH)
    pub fn add_output_to_address(self, value: Amount, address: &Address) -> Self {
        let script = address.script_pubkey();
        self.add_output(value, script)
    }

    /// Set lock time
    pub fn lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = lock_time;
        self
    }

    /// Build the unsigned transaction and return input scripts for signing
    pub fn build(self) -> (Transaction, Vec<Script>) {
        let mut tx = Transaction::new();
        tx.version = self.version;
        tx.lock_time = self.lock_time;

        let mut prev_scripts = Vec::new();

        for (outpoint, prev_script) in self.inputs {
            tx.vin.push(TxIn::new(
                outpoint,
                Script::new(), // Empty for unsigned tx
                0xffffffff,    // SEQUENCE_FINAL
            ));
            prev_scripts.push(prev_script);
        }

        tx.vout = self.outputs;

        (tx, prev_scripts)
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::hd::HdWallet;
    use divi_primitives::constants::SEQUENCE_FINAL;
    use divi_primitives::ChainMode;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_sighash_all() {
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(
                Amount::from_divi(50),
                Script::new_p2pkh(&[0u8; 20]),
            )],
            lock_time: 0,
        };

        let script_code = Script::new_p2pkh(&[0u8; 20]);
        let hash = sighash(&tx, 0, &script_code, SigHashType::All, false).unwrap();

        // Hash should be deterministic
        let hash2 = sighash(&tx, 0, &script_code, SigHashType::All, false).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sign_and_build_script_sig() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let key = wallet.derive_receiving(0, 0).unwrap();
        let secret = key.secret_key().unwrap();
        let pubkey = secret.public_key();

        let tx = Transaction {
            version: 2,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(
                Amount::from_divi(50),
                Script::new_p2pkh(&[0u8; 20]),
            )],
            lock_time: 0,
        };

        let script_pubkey = Script::new_p2pkh(&[0u8; 20]);
        let sig = sign_input(&tx, 0, &script_pubkey, &secret, SigHashType::All).unwrap();

        // Signature should end with SIGHASH_ALL byte
        assert_eq!(*sig.last().unwrap(), SigHashType::All as u8);

        // Create script sig
        let script_sig = create_p2pkh_script_sig(&sig, &pubkey);
        assert!(!script_sig.is_empty());
    }

    #[test]
    fn test_transaction_builder() {
        let prev_outpoint = OutPoint::new(Hash256::from_bytes([1u8; 32]), 0);
        let prev_script = Script::new_p2pkh(&[0u8; 20]);

        let (tx, prev_scripts) = TransactionBuilder::new()
            .version(2)
            .add_input(prev_outpoint, prev_script.clone())
            .add_output(Amount::from_divi(50), Script::new_p2pkh(&[1u8; 20]))
            .lock_time(0)
            .build();

        assert_eq!(tx.version, 2);
        assert_eq!(tx.vin.len(), 1);
        assert_eq!(tx.vout.len(), 1);
        assert_eq!(prev_scripts.len(), 1);
        assert_eq!(prev_scripts[0], prev_script);
    }

    #[test]
    fn test_transaction_signer() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);

        // Generate an address
        let addr = store.new_receiving_address().unwrap();

        // Build a transaction spending to this address
        let prev_outpoint = OutPoint::new(Hash256::from_bytes([1u8; 32]), 0);
        let prev_script = Script::new_p2pkh(addr.hash.as_bytes());

        let (mut tx, prev_scripts) = TransactionBuilder::new()
            .add_input(prev_outpoint, prev_script)
            .add_output(Amount::from_divi(50), Script::new_p2pkh(&[1u8; 20]))
            .build();

        // Sign with the transaction signer
        let signer = TransactionSigner::new(&store);
        let signed = signer.sign_all_inputs(&mut tx, &prev_scripts).unwrap();

        assert_eq!(signed, 1);
        assert!(!tx.vin[0].script_sig.is_empty());
    }

    #[test]
    fn test_sighash_out_of_bounds() {
        let tx = Transaction {
            version: 2,
            vin: vec![],
            vout: vec![],
            lock_time: 0,
        };

        let result = sighash(&tx, 0, &Script::new(), SigHashType::All, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_sighash_none() {
        let tx = Transaction {
            version: 2,
            vin: vec![
                TxIn::new(
                    OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                    Script::new(),
                    SEQUENCE_FINAL,
                ),
                TxIn::new(
                    OutPoint::new(Hash256::from_bytes([2u8; 32]), 0),
                    Script::new(),
                    SEQUENCE_FINAL,
                ),
            ],
            vout: vec![TxOut::new(Amount::from_divi(50), Script::new())],
            lock_time: 0,
        };

        let script_code = Script::new_p2pkh(&[0u8; 20]);
        let hash = sighash(&tx, 0, &script_code, SigHashType::None, false).unwrap();

        // Hash should be valid (non-zero)
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_sighash_single() {
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(Amount::from_divi(50), Script::new())],
            lock_time: 0,
        };

        let script_code = Script::new_p2pkh(&[0u8; 20]);
        let hash = sighash(&tx, 0, &script_code, SigHashType::Single, false).unwrap();

        // Hash should be valid
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_sighash_anyonecanpay() {
        let tx = Transaction {
            version: 2,
            vin: vec![
                TxIn::new(
                    OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                    Script::new(),
                    SEQUENCE_FINAL,
                ),
                TxIn::new(
                    OutPoint::new(Hash256::from_bytes([2u8; 32]), 0),
                    Script::new(),
                    SEQUENCE_FINAL,
                ),
            ],
            vout: vec![TxOut::new(Amount::from_divi(50), Script::new())],
            lock_time: 0,
        };

        let script_code = Script::new_p2pkh(&[0u8; 20]);
        let hash = sighash(&tx, 0, &script_code, SigHashType::All, true).unwrap();

        // Hash should be different with ANYONECANPAY
        let hash_no_acp = sighash(&tx, 0, &script_code, SigHashType::All, false).unwrap();
        assert_ne!(hash, hash_no_acp);
    }
}
