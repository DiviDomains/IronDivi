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

//! Coinstake transaction building
//!
//! This module provides functionality to build coinstake transactions for
//! spending vault funds via the manager/vault path (OP_ELSE branch).
//!
//! # Manager Path Spending
//!
//! Vault scripts use an OP_IF structure where:
//! - Owner path (OP_IF branch): Can spend anytime with owner key
//! - Manager path (OP_ELSE branch): Requires OP_REQUIRE_COINSTAKE, can only spend via coinstake
//!
//! The manager path scriptSig format is:
//! ```text
//! <signature> <pubkey> OP_FALSE
//! ```
//!
//! The OP_FALSE (0x00) selects the OP_ELSE branch of the vault script.

use crate::error::WalletError;
use crate::wallet_db::WalletUtxo;
use crate::Address;
use divi_crypto::keys::SecretKey;
use divi_crypto::signature::sign_hash;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::opcodes::Opcode;
use divi_script::SigHashType;
use sha2::{Digest, Sha256};

/// Builder for coinstake transactions
///
/// Coinstake transactions are used for staking and for spending vault funds
/// via the manager path. They have the following structure:
///
/// - First output is empty (marker for coinstake)
/// - At least one non-null input
/// - Version 2
pub struct CoinstakeBuilder {
    /// Transaction inputs with their prevout scripts
    inputs: Vec<(OutPoint, Script)>,
    /// Transaction outputs
    outputs: Vec<TxOut>,
    /// Lock time
    lock_time: u32,
}

impl CoinstakeBuilder {
    /// Create a new coinstake builder
    pub fn new() -> Self {
        CoinstakeBuilder {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    /// Add a vault input for manager-path spending
    ///
    /// # Arguments
    /// * `utxo` - The vault UTXO to spend
    ///
    /// # Notes
    /// The vault script is stored in the UTXO's script_pubkey.
    pub fn add_vault_input(&mut self, utxo: &WalletUtxo) -> &mut Self {
        let outpoint = OutPoint::new(utxo.txid, utxo.vout);
        self.inputs.push((outpoint, utxo.script_pubkey.clone()));
        self
    }

    /// Add a vault input from components
    pub fn add_vault_input_from_parts(
        &mut self,
        txid: Hash256,
        vout: u32,
        script_pubkey: Script,
    ) -> &mut Self {
        let outpoint = OutPoint::new(txid, vout);
        self.inputs.push((outpoint, script_pubkey));
        self
    }

    /// Add an output to a destination address
    pub fn add_output(&mut self, address: &Address, amount: Amount) -> &mut Self {
        let script = Script::new_p2pkh(address.hash.as_bytes());
        self.outputs.push(TxOut::new(amount, script));
        self
    }

    /// Add a custom output with raw script
    pub fn add_output_raw(&mut self, amount: Amount, script_pubkey: Script) -> &mut Self {
        self.outputs.push(TxOut::new(amount, script_pubkey));
        self
    }

    /// Set the lock time
    pub fn lock_time(&mut self, lock_time: u32) -> &mut Self {
        self.lock_time = lock_time;
        self
    }

    /// Build the unsigned coinstake transaction
    ///
    /// Returns the transaction with empty script_sig fields and the prevout scripts
    /// needed for signing.
    ///
    /// # Coinstake Structure
    /// - Version: 2
    /// - First output: Empty (coinstake marker)
    /// - Subsequent outputs: Destination outputs
    pub fn build(&self) -> Result<(Transaction, Vec<Script>), WalletError> {
        if self.inputs.is_empty() {
            return Err(WalletError::TransactionError(
                "Coinstake requires at least one input".into(),
            ));
        }

        if self.outputs.is_empty() {
            return Err(WalletError::TransactionError(
                "Coinstake requires at least one destination output".into(),
            ));
        }

        let mut tx = Transaction::new();
        tx.version = 1; // C++ Divi requires version 1 for coinstake
        tx.lock_time = self.lock_time;

        // Build inputs with empty script_sig
        let mut prev_scripts = Vec::new();
        for (outpoint, prev_script) in &self.inputs {
            tx.vin.push(TxIn::new(
                outpoint.clone(),
                Script::new(),
                0xffffffff, // SEQUENCE_FINAL
            ));
            prev_scripts.push(prev_script.clone());
        }

        // First output is empty (coinstake marker)
        tx.vout.push(TxOut::empty());

        // Add destination outputs
        for output in &self.outputs {
            tx.vout.push(output.clone());
        }

        // Verify this is a valid coinstake structure
        if !tx.is_coinstake() {
            return Err(WalletError::TransactionError(
                "Built transaction is not a valid coinstake".into(),
            ));
        }

        Ok((tx, prev_scripts))
    }

    /// Sign the coinstake transaction using the manager path
    ///
    /// This creates a scriptSig that selects the OP_ELSE branch of the vault script.
    ///
    /// # Arguments
    /// * `tx` - The unsigned transaction to sign
    /// * `input_index` - Which input to sign
    /// * `prev_script` - The vault script being spent
    /// * `manager_key` - The manager's secret key
    ///
    /// # ScriptSig Format
    /// ```text
    /// <signature> <pubkey> OP_FALSE
    /// ```
    ///
    /// The OP_FALSE (0x00) causes the OP_IF to skip to OP_ELSE, selecting the manager path.
    pub fn sign_manager_path(
        tx: &mut Transaction,
        input_index: usize,
        prev_script: &Script,
        manager_key: &SecretKey,
    ) -> Result<(), WalletError> {
        if input_index >= tx.vin.len() {
            return Err(WalletError::TransactionError(format!(
                "Input index {} out of bounds (tx has {} inputs)",
                input_index,
                tx.vin.len()
            )));
        }

        // Compute sighash for the input
        let sighash = compute_sighash(tx, input_index, prev_script, SigHashType::All)?;

        // Sign the hash
        let signature = sign_hash(manager_key, sighash.as_bytes())
            .map_err(|e| WalletError::TransactionError(format!("Signing failed: {}", e)))?;

        // Get the DER-encoded signature and append SIGHASH_ALL type
        let mut sig_bytes = signature.to_der();
        sig_bytes.push(SigHashType::All as u8);

        // Get the public key
        let pubkey = manager_key.public_key();
        let pubkey_bytes = pubkey.to_bytes();

        // Build the scriptSig: <sig> <pubkey> OP_FALSE
        let script_sig = create_vault_manager_script_sig(&sig_bytes, &pubkey_bytes);

        tx.vin[input_index].script_sig = script_sig;

        Ok(())
    }

    /// Sign all inputs using the manager path
    ///
    /// All inputs must use the same vault script and manager key.
    pub fn sign_all_manager_path(
        tx: &mut Transaction,
        prev_scripts: &[Script],
        manager_key: &SecretKey,
    ) -> Result<usize, WalletError> {
        if prev_scripts.len() != tx.vin.len() {
            return Err(WalletError::TransactionError(format!(
                "Script count mismatch: {} scripts, {} inputs",
                prev_scripts.len(),
                tx.vin.len()
            )));
        }

        let mut signed = 0;
        for (i, prev_script) in prev_scripts.iter().enumerate() {
            Self::sign_manager_path(tx, i, prev_script, manager_key)?;
            signed += 1;
        }

        Ok(signed)
    }
}

impl Default for CoinstakeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create the scriptSig for vault manager path spending
///
/// Format: <signature_length> <signature> <pubkey_length> <pubkey> OP_FALSE
fn create_vault_manager_script_sig(signature: &[u8], pubkey: &[u8]) -> Script {
    let mut script_data = Vec::new();

    // Push signature
    script_data.push(signature.len() as u8);
    script_data.extend_from_slice(signature);

    // Push public key (33 bytes for compressed)
    script_data.push(pubkey.len() as u8);
    script_data.extend_from_slice(pubkey);

    // Push OP_FALSE (0x00) to select OP_ELSE branch
    // We use OP_0 which is the same as OP_FALSE
    script_data.push(Opcode::OP_0 as u8);

    Script::from_bytes(script_data)
}

/// Compute sighash for a transaction input
///
/// This is the hash that must be signed to authorize spending.
fn compute_sighash(
    tx: &Transaction,
    input_index: usize,
    script_code: &Script,
    sighash_type: SigHashType,
) -> Result<Hash256, WalletError> {
    if input_index >= tx.vin.len() {
        return Err(WalletError::TransactionError(format!(
            "Input index {} out of bounds",
            input_index
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

    // For SIGHASH_ALL, we sign all inputs and outputs (default behavior)
    if sighash_type != SigHashType::All {
        return Err(WalletError::TransactionError(
            "Only SIGHASH_ALL is currently supported for coinstake".into(),
        ));
    }

    // Serialize the modified transaction
    let mut data = serialize(&tx_copy);

    // Append sighash type as 4-byte little-endian
    data.extend_from_slice(&(sighash_type as u32).to_le_bytes());

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdWallet;
    use crate::Network;
    use divi_primitives::ChainMode;
    use divi_script::StakingVaultScript;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn create_test_vault_script() -> Script {
        let owner_hash = [0x11u8; 20];
        let manager_hash = [0x22u8; 20];
        StakingVaultScript::new(owner_hash, manager_hash).to_script()
    }

    #[test]
    fn test_coinstake_builder_basic() {
        let vault_script = create_test_vault_script();

        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([1u8; 32]), 0, vault_script.clone());

        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xaa; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(100));

        let (tx, prev_scripts) = builder.build().unwrap();

        // Verify coinstake structure
        assert!(tx.is_coinstake());
        assert_eq!(tx.vin.len(), 1);
        assert_eq!(tx.vout.len(), 2); // Empty marker + destination
        assert!(tx.vout[0].is_empty());
        assert_eq!(prev_scripts.len(), 1);
    }

    #[test]
    fn test_coinstake_empty_inputs_fails() {
        let mut builder = CoinstakeBuilder::new();
        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xaa; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(100));

        let result = builder.build();
        assert!(result.is_err());
    }

    #[test]
    fn test_coinstake_empty_outputs_fails() {
        let vault_script = create_test_vault_script();

        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([1u8; 32]), 0, vault_script);

        let result = builder.build();
        assert!(result.is_err());
    }

    #[test]
    fn test_manager_script_sig_format() {
        // Create a mock signature and pubkey
        let signature = vec![0x30, 0x44]; // DER signature prefix
        let pubkey = [0x02u8; 33]; // Compressed pubkey

        let script_sig = create_vault_manager_script_sig(&signature, &pubkey);
        let bytes = script_sig.as_bytes();

        // Verify structure: sig_len + sig + pubkey_len + pubkey + OP_FALSE
        assert_eq!(bytes[0], 2); // signature length
        assert_eq!(bytes[1], 0x30);
        assert_eq!(bytes[2], 0x44);
        assert_eq!(bytes[3], 33); // pubkey length
        assert_eq!(bytes[4], 0x02);
        // Last byte should be OP_FALSE (0x00)
        assert_eq!(bytes[bytes.len() - 1], 0x00);
    }

    #[test]
    fn test_coinstake_signing() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let key = wallet.derive_receiving(0, 0).unwrap();
        let manager_key = key.secret_key().unwrap();
        let manager_pubkey = manager_key.public_key();

        // Create vault script with our key as manager
        let manager_hash = divi_crypto::hash160(&manager_pubkey.to_bytes());
        let owner_hash = [0x11u8; 20];
        let mut manager_hash_array = [0u8; 20];
        manager_hash_array.copy_from_slice(manager_hash.as_ref());

        let vault_script = StakingVaultScript::new(owner_hash, manager_hash_array).to_script();

        // Build coinstake
        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([1u8; 32]), 0, vault_script.clone());

        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xaa; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(100));

        let (mut tx, prev_scripts) = builder.build().unwrap();

        // Sign using manager path
        CoinstakeBuilder::sign_manager_path(&mut tx, 0, &prev_scripts[0], &manager_key).unwrap();

        // Verify input is signed
        assert!(!tx.vin[0].script_sig.is_empty());

        // Verify script_sig ends with OP_FALSE (0x00)
        let sig_bytes = tx.vin[0].script_sig.as_bytes();
        assert_eq!(sig_bytes[sig_bytes.len() - 1], 0x00);
    }

    #[test]
    fn test_coinstake_sign_all() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let key = wallet.derive_receiving(0, 0).unwrap();
        let manager_key = key.secret_key().unwrap();
        let manager_pubkey = manager_key.public_key();

        let manager_hash = divi_crypto::hash160(&manager_pubkey.to_bytes());
        let owner_hash = [0x11u8; 20];
        let mut manager_hash_array = [0u8; 20];
        manager_hash_array.copy_from_slice(manager_hash.as_ref());

        let vault_script = StakingVaultScript::new(owner_hash, manager_hash_array).to_script();

        // Build coinstake with multiple inputs
        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([1u8; 32]), 0, vault_script.clone());
        builder.add_vault_input_from_parts(Hash256::from_bytes([2u8; 32]), 1, vault_script.clone());

        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xaa; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(200));

        let (mut tx, prev_scripts) = builder.build().unwrap();

        // Sign all inputs
        let signed =
            CoinstakeBuilder::sign_all_manager_path(&mut tx, &prev_scripts, &manager_key).unwrap();

        assert_eq!(signed, 2);
        assert!(!tx.vin[0].script_sig.is_empty());
        assert!(!tx.vin[1].script_sig.is_empty());
    }

    #[test]
    fn test_sighash_computation() {
        let vault_script = create_test_vault_script();

        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([1u8; 32]), 0, vault_script.clone());

        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xaa; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(100));

        let (tx, prev_scripts) = builder.build().unwrap();

        // Compute sighash
        let hash = compute_sighash(&tx, 0, &prev_scripts[0], SigHashType::All).unwrap();

        // Should be deterministic
        let hash2 = compute_sighash(&tx, 0, &prev_scripts[0], SigHashType::All).unwrap();
        assert_eq!(hash, hash2);

        // Should be non-zero
        assert!(!hash.is_zero());
    }

    // -------- Additional missing tests --------

    #[test]
    fn test_sign_manager_path_out_of_bounds_fails() {
        let vault_script = create_test_vault_script();

        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([1u8; 32]), 0, vault_script.clone());

        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xbb; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(50));

        let (mut tx, prev_scripts) = builder.build().unwrap();

        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let manager_key = wallet.derive_receiving(0, 0).unwrap().secret_key().unwrap();

        // Input index 99 does not exist → must return an error
        let result =
            CoinstakeBuilder::sign_manager_path(&mut tx, 99, &prev_scripts[0], &manager_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_all_mismatched_script_count_fails() {
        let vault_script = create_test_vault_script();

        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([1u8; 32]), 0, vault_script.clone());
        builder.add_vault_input_from_parts(Hash256::from_bytes([2u8; 32]), 1, vault_script.clone());

        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xcc; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(100));

        let (mut tx, _prev_scripts) = builder.build().unwrap();

        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let manager_key = wallet.derive_receiving(0, 0).unwrap().secret_key().unwrap();

        // Provide only 1 script for a tx with 2 inputs → mismatch error
        let wrong_scripts = vec![vault_script];
        let result = CoinstakeBuilder::sign_all_manager_path(&mut tx, &wrong_scripts, &manager_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_manager_script_sig_contains_pubkey() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let key = wallet.derive_receiving(0, 0).unwrap();
        let manager_key = key.secret_key().unwrap();
        let pubkey_bytes = manager_key.public_key().to_bytes();

        let manager_hash = divi_crypto::hash160(&pubkey_bytes);
        let owner_hash = [0x11u8; 20];
        let mut manager_hash_array = [0u8; 20];
        manager_hash_array.copy_from_slice(manager_hash.as_ref());

        let vault_script = StakingVaultScript::new(owner_hash, manager_hash_array).to_script();

        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([1u8; 32]), 0, vault_script.clone());

        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xdd; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(100));

        let (mut tx, prev_scripts) = builder.build().unwrap();
        CoinstakeBuilder::sign_manager_path(&mut tx, 0, &prev_scripts[0], &manager_key).unwrap();

        let sig_bytes = tx.vin[0].script_sig.as_bytes();

        // sig_len is first byte; after the sig is pubkey_len (should be 33 for compressed)
        let sig_len = sig_bytes[0] as usize;
        let pubkey_len_idx = 1 + sig_len;
        assert_eq!(
            sig_bytes[pubkey_len_idx], 33,
            "Pubkey should be 33-byte compressed"
        );

        // The 33 pubkey bytes must match our public key
        let extracted_pubkey = &sig_bytes[pubkey_len_idx + 1..pubkey_len_idx + 34];
        assert_eq!(extracted_pubkey, &pubkey_bytes[..]);

        // Last byte is OP_FALSE (0x00)
        assert_eq!(sig_bytes[sig_bytes.len() - 1], 0x00);
    }

    #[test]
    fn test_coinstake_version_is_1() {
        let vault_script = create_test_vault_script();

        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([5u8; 32]), 0, vault_script);

        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xee; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(50));

        let (tx, _) = builder.build().unwrap();

        // C++ Divi requires version 1 for coinstake
        assert_eq!(tx.version, 1);
    }

    #[test]
    fn test_coinstake_first_output_empty_marker() {
        let vault_script = create_test_vault_script();

        let mut builder = CoinstakeBuilder::new();
        builder.add_vault_input_from_parts(Hash256::from_bytes([6u8; 32]), 0, vault_script);

        let dest_addr = Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xff; 20]),
            Network::Mainnet,
        );
        builder.add_output(&dest_addr, Amount::from_divi(200));

        let (tx, _) = builder.build().unwrap();

        // vout[0] must be the empty coinstake marker
        assert!(tx.vout[0].is_empty());
        // vout[1] is the real output
        assert!(!tx.vout[1].is_empty());
    }

    #[test]
    fn test_default_coinstake_builder_same_as_new() {
        // CoinstakeBuilder::default() must behave identically to CoinstakeBuilder::new()
        let b1 = CoinstakeBuilder::new();
        let b2 = CoinstakeBuilder::default();

        // Both should fail to build (no inputs/outputs) with the same error type
        let r1 = b1.build();
        let r2 = b2.build();
        assert!(r1.is_err());
        assert!(r2.is_err());
    }
}
