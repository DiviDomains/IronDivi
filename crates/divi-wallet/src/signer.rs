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
    let hash = sighash(tx, input_index, script_pubkey, sighash_type, false)?;

    let signature = sign_hash(secret_key, hash.as_bytes())
        .map_err(|e| WalletError::TransactionError(e.to_string()))?;

    // Append sighash type byte to DER signature
    let mut sig_bytes = signature.to_der();
    sig_bytes.push(sighash_type as u8);

    Ok(sig_bytes)
}

/// Create a P2PKH script sig from signature and public key
pub fn create_p2pkh_script_sig(signature: &[u8], pubkey: &PublicKey) -> Script {
    let mut script_data = Vec::new();

    // Push signature
    script_data.push(signature.len() as u8);
    script_data.extend_from_slice(signature);

    // Push public key (compressed)
    let pubkey_bytes = pubkey.to_bytes();
    script_data.push(pubkey_bytes.len() as u8);
    script_data.extend_from_slice(&pubkey_bytes);

    Script::from_bytes(script_data)
}

/// Create a vault owner scriptSig: `<signature> <pubkey> OP_TRUE`
///
/// OP_TRUE (0x51) selects the IF branch of the vault script, which is the owner path.
pub fn create_vault_owner_script_sig(signature: &[u8], pubkey: &PublicKey) -> Script {
    let mut script_data = Vec::new();

    // Push signature
    script_data.push(signature.len() as u8);
    script_data.extend_from_slice(signature);

    // Push public key (compressed)
    let pubkey_bytes = pubkey.to_bytes();
    script_data.push(pubkey_bytes.len() as u8);
    script_data.extend_from_slice(&pubkey_bytes);

    // OP_TRUE (= OP_1 = 0x51) — selects the IF (owner) branch
    script_data.push(0x51);

    Script::from_bytes(script_data)
}

/// Transaction signer that uses keystore for signing
pub struct TransactionSigner<'a> {
    keystore: &'a KeyStore,
}

impl<'a> TransactionSigner<'a> {
    /// Create a new transaction signer
    pub fn new(keystore: &'a KeyStore) -> Self {
        TransactionSigner { keystore }
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
        let script_sig = create_p2pkh_script_sig(&sig, &entry.public);

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
                    let script_sig = create_p2pkh_script_sig(&sig, &entry.public);
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
                    let script_sig = create_vault_owner_script_sig(&sig, &entry.public);
                    tx.vin[i].script_sig = script_sig;
                    signed += 1;
                }
            }
        }

        Ok(signed)
    }
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

    /// Add a P2PKH output to an address
    pub fn add_output_to_address(self, value: Amount, address: &Address) -> Self {
        let script = Script::new_p2pkh(address.hash.as_bytes());
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
