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

//! Transaction signature checker for script verification
//!
//! This module provides a SignatureChecker implementation that verifies
//! ECDSA signatures against actual transaction data, enabling full script
//! validation during block acceptance.

use crate::error::SigHashType;
use crate::interpreter::SignatureChecker;
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{Transaction, TxOut};
use sha2::{Digest, Sha256};

/// Transaction signature checker that verifies signatures against actual transaction data
///
/// This implements the SignatureChecker trait, enabling the script interpreter
/// to verify ECDSA signatures during script execution (OP_CHECKSIG, etc).
pub struct TransactionSignatureChecker<'a> {
    /// The transaction being validated
    tx: &'a Transaction,
    /// Index of the input being validated
    input_index: usize,
    /// Value of the UTXO being spent (for segwit-style sighash, not used in legacy)
    #[allow(dead_code)]
    amount: Amount,
}

impl<'a> TransactionSignatureChecker<'a> {
    /// Create a new transaction signature checker
    ///
    /// # Arguments
    /// * `tx` - The transaction containing the input being validated
    /// * `input_index` - Index of the input whose script is being executed
    /// * `amount` - Value of the UTXO being spent (for future segwit support)
    pub fn new(tx: &'a Transaction, input_index: usize, amount: Amount) -> Self {
        TransactionSignatureChecker {
            tx,
            input_index,
            amount,
        }
    }

    /// Compute the sighash for legacy (pre-segwit) transactions
    ///
    /// This matches Bitcoin/Divi's SignatureHash() function behavior.
    fn compute_sighash(
        &self,
        script_code: &Script,
        sighash_type: SigHashType,
        anyone_can_pay: bool,
    ) -> Result<[u8; 32], &'static str> {
        if self.input_index >= self.tx.vin.len() {
            return Err("Input index out of bounds");
        }

        // Build modified transaction for signing
        let mut tx_copy = self.tx.clone();

        // Clear all input scripts
        for input in tx_copy.vin.iter_mut() {
            input.script_sig = Script::new();
        }

        // Set the script code for the input being signed
        // (this is the scriptPubKey of the output being spent)
        tx_copy.vin[self.input_index].script_sig = script_code.clone();

        // Handle different sighash types
        match sighash_type {
            SigHashType::All => {
                // SIGHASH_ALL: Sign all inputs and outputs (default)
                // No modification needed
            }
            SigHashType::None => {
                // SIGHASH_NONE: Sign all inputs, no outputs
                tx_copy.vout.clear();
                // Set all other input sequences to 0
                for (i, input) in tx_copy.vin.iter_mut().enumerate() {
                    if i != self.input_index {
                        input.sequence = 0;
                    }
                }
            }
            SigHashType::Single => {
                // SIGHASH_SINGLE: Sign all inputs, only output at same index
                if self.input_index >= tx_copy.vout.len() {
                    // If no matching output, return 1 (special case from Bitcoin)
                    let mut result = [0u8; 32];
                    result[0] = 1;
                    return Ok(result);
                }
                // Keep only the output at input_index
                let output = tx_copy.vout[self.input_index].clone();
                tx_copy.vout.clear();
                // Fill outputs before input_index with empty outputs
                for _ in 0..self.input_index {
                    tx_copy
                        .vout
                        .push(TxOut::new(Amount::from_sat(-1), Script::new()));
                }
                tx_copy.vout.push(output);
                // Set all other input sequences to 0
                for (i, input) in tx_copy.vin.iter_mut().enumerate() {
                    if i != self.input_index {
                        input.sequence = 0;
                    }
                }
            }
            SigHashType::AnyoneCanPay => {
                // This shouldn't happen as ANYONECANPAY is a modifier, not a base type
            }
        }

        // Handle ANYONECANPAY modifier
        if anyone_can_pay {
            // Only keep the input being signed
            let input = tx_copy.vin[self.input_index].clone();
            tx_copy.vin.clear();
            tx_copy.vin.push(input);
        }

        // Serialize and compute hash
        let mut data = serialize(&tx_copy);

        // Append sighash type as 4-byte LE
        let hash_type_value = if anyone_can_pay {
            (sighash_type as u32) | 0x80
        } else {
            sighash_type as u32
        };
        data.extend_from_slice(&hash_type_value.to_le_bytes());

        // Double SHA256
        Ok(double_sha256(&data))
    }
}

/// Double SHA256 hash
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

impl SignatureChecker for TransactionSignatureChecker<'_> {
    fn check_sig(&self, sig: &[u8], pubkey: &[u8], script_code: &Script) -> bool {
        // Empty signature always fails
        if sig.is_empty() {
            return false;
        }

        // Parse sighash type from last byte of signature
        let sighash_byte = sig[sig.len() - 1];
        let (sighash_type, anyone_can_pay) = match SigHashType::from_u8(sighash_byte) {
            Some((st, acp)) => (st, acp),
            None => return false, // Invalid sighash type
        };

        // The actual DER signature is everything except the last byte
        let der_sig = &sig[..sig.len() - 1];

        // Compute the sighash
        let sighash = match self.compute_sighash(script_code, sighash_type, anyone_can_pay) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Parse the public key
        let pk = match divi_crypto::PublicKey::from_bytes(pubkey) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Parse the DER signature
        let signature = match divi_crypto::Signature::from_der(der_sig) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Verify the signature
        divi_crypto::verify_hash(&pk, &signature, &sighash)
    }

    fn check_lock_time(&self, lock_time: i64) -> bool {
        // CHECKLOCKTIMEVERIFY (BIP65) validation
        // The lock time must be:
        // 1. Non-negative (already checked by caller)
        // 2. Same type as transaction lock_time (both block height or both timestamp)
        // 3. Less than or equal to transaction lock_time
        // 4. Input sequence must not be SEQUENCE_FINAL (0xffffffff)

        let tx_lock_time = self.tx.lock_time as i64;

        // Check sequence is not final
        if self.input_index < self.tx.vin.len()
            && self.tx.vin[self.input_index].sequence == 0xffffffff
        {
            return false;
        }

        // Lock time type threshold (500000000 = median timestamp ~1985)
        const LOCKTIME_THRESHOLD: i64 = 500_000_000;

        // Both must be same type (either both heights or both timestamps)
        let script_is_timestamp = lock_time >= LOCKTIME_THRESHOLD;
        let tx_is_timestamp = tx_lock_time >= LOCKTIME_THRESHOLD;
        if script_is_timestamp != tx_is_timestamp {
            return false;
        }

        // Script lock time must be <= transaction lock time
        lock_time <= tx_lock_time
    }

    fn check_sequence(&self, sequence: i64) -> bool {
        // CHECKSEQUENCEVERIFY (BIP112) validation
        // This validates relative lock times

        // Check if the disable flag is set in the script sequence
        const SEQUENCE_LOCKTIME_DISABLE_FLAG: i64 = 1 << 31;
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return true; // Disabled, always passes
        }

        // Transaction version must be >= 2 for CSV
        if self.tx.version < 2 {
            return false;
        }

        // Get the input's sequence
        if self.input_index >= self.tx.vin.len() {
            return false;
        }
        let tx_sequence = self.tx.vin[self.input_index].sequence as i64;

        // Check if transaction input's disable flag is set
        if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return false;
        }

        // Type flag determines if it's time-based or block-based
        const SEQUENCE_LOCKTIME_TYPE_FLAG: i64 = 1 << 22;
        let script_is_time = sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0;
        let tx_is_time = tx_sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0;

        // Both must be same type
        if script_is_time != tx_is_time {
            return false;
        }

        // Mask to get the actual lock time value (lower 16 bits)
        const SEQUENCE_LOCKTIME_MASK: i64 = 0x0000ffff;
        let script_value = sequence & SEQUENCE_LOCKTIME_MASK;
        let tx_value = tx_sequence & SEQUENCE_LOCKTIME_MASK;

        // Script sequence must be <= transaction input sequence
        script_value <= tx_value
    }
}

/// Verify a transaction input's scripts
///
/// This is the main entry point for verifying that a transaction input
/// correctly spends its referenced output.
///
/// # Arguments
/// * `tx` - The spending transaction
/// * `input_index` - Index of the input to verify
/// * `script_pubkey` - The scriptPubKey of the output being spent
/// * `amount` - Value of the output being spent
///
/// # Returns
/// * `Ok(())` if the scripts verify successfully
/// * `Err(ScriptError)` if verification fails
pub fn verify_input(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    amount: Amount,
) -> Result<(), crate::error::ScriptError> {
    use crate::error::ScriptFlags;
    use crate::interpreter::verify_script;

    if input_index >= tx.vin.len() {
        return Err(crate::error::ScriptError::InvalidStackOperation);
    }

    let script_sig = &tx.vin[input_index].script_sig;
    let checker = TransactionSignatureChecker::new(tx, input_index, amount);

    // Use standard verification flags
    let flags = ScriptFlags::standard();

    verify_script(script_sig, script_pubkey, flags, &checker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_crypto::keys::KeyPair;
    use divi_primitives::constants::SEQUENCE_FINAL;
    use divi_primitives::hash::Hash256;
    use divi_primitives::transaction::{OutPoint, TxIn};

    fn create_test_keypair() -> KeyPair {
        KeyPair::new_random()
    }

    fn create_simple_tx() -> Transaction {
        Transaction {
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
        }
    }

    #[test]
    fn test_checker_empty_signature_fails() {
        let tx = create_simple_tx();
        let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_divi(50));
        let script_code = Script::new_p2pkh(&[0u8; 20]);

        // Empty signature should fail
        assert!(!checker.check_sig(&[], &[0u8; 33], &script_code));
    }

    #[test]
    fn test_checker_invalid_sighash_type_fails() {
        let tx = create_simple_tx();
        let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_divi(50));
        let script_code = Script::new_p2pkh(&[0u8; 20]);

        // Signature with invalid sighash type (0x00) should fail
        let bad_sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00];
        assert!(!checker.check_sig(&bad_sig, &[0u8; 33], &script_code));
    }

    #[test]
    fn test_checker_invalid_pubkey_fails() {
        let tx = create_simple_tx();
        let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_divi(50));
        let script_code = Script::new_p2pkh(&[0u8; 20]);

        // Valid-ish signature with invalid pubkey should fail
        let sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];
        assert!(!checker.check_sig(&sig, &[0x00; 33], &script_code));
    }

    #[test]
    fn test_valid_signature_verification() {
        let kp = create_test_keypair();
        let pubkey = kp.public_key();
        let pubkey_hash = pubkey.pubkey_hash();

        // Create a transaction spending to our key
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(
                Amount::from_divi(49),
                Script::new_p2pkh(pubkey_hash.as_bytes()),
            )],
            lock_time: 0,
        };

        // The script code is the scriptPubKey of the output being spent
        let script_code = Script::new_p2pkh(pubkey_hash.as_bytes());

        // Create the checker
        let checker = TransactionSignatureChecker::new(&tx, 0, Amount::from_divi(50));

        // Compute the sighash
        let sighash = checker
            .compute_sighash(&script_code, SigHashType::All, false)
            .unwrap();

        // Sign the hash
        let signature = divi_crypto::sign_hash(kp.secret_key(), &sighash).unwrap();

        // Build the full signature with sighash type appended
        let mut full_sig = signature.to_der();
        full_sig.push(SigHashType::All as u8);

        // Verify the signature
        let pubkey_bytes = pubkey.to_bytes();
        assert!(checker.check_sig(&full_sig, &pubkey_bytes, &script_code));

        // Verify with wrong pubkey fails
        let wrong_kp = create_test_keypair();
        let wrong_pubkey_bytes = wrong_kp.public_key().to_bytes();
        assert!(!checker.check_sig(&full_sig, &wrong_pubkey_bytes, &script_code));

        // Verify with modified signature fails
        let mut bad_sig = full_sig.clone();
        if bad_sig.len() > 5 {
            bad_sig[4] ^= 0xff; // Flip some bits in the signature
        }
        assert!(!checker.check_sig(&bad_sig, &pubkey_bytes, &script_code));
    }

    #[test]
    fn test_check_lock_time() {
        // Transaction with lock_time = 500000
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                0xfffffffe, // Not SEQUENCE_FINAL
            )],
            vout: vec![],
            lock_time: 500000,
        };
        let checker = TransactionSignatureChecker::new(&tx, 0, Amount::ZERO);

        // Should pass for lock_time <= tx.lock_time
        assert!(checker.check_lock_time(499999));
        assert!(checker.check_lock_time(500000));

        // Should fail for lock_time > tx.lock_time
        assert!(!checker.check_lock_time(500001));

        // Should fail if sequence is FINAL
        let tx_final = Transaction {
            version: 2,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![],
            lock_time: 500000,
        };
        let checker_final = TransactionSignatureChecker::new(&tx_final, 0, Amount::ZERO);
        assert!(!checker_final.check_lock_time(400000));
    }

    #[test]
    fn test_check_sequence() {
        // Transaction with version 2 and sequence 100
        let tx = Transaction {
            version: 2,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                100,
            )],
            vout: vec![],
            lock_time: 0,
        };
        let checker = TransactionSignatureChecker::new(&tx, 0, Amount::ZERO);

        // Should pass for sequence <= input.sequence
        assert!(checker.check_sequence(50));
        assert!(checker.check_sequence(100));

        // Should fail for sequence > input.sequence
        assert!(!checker.check_sequence(101));

        // Should pass if disable flag is set in script
        assert!(checker.check_sequence(1 << 31));

        // Should fail for version 1 transactions
        let tx_v1 = Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                100,
            )],
            vout: vec![],
            lock_time: 0,
        };
        let checker_v1 = TransactionSignatureChecker::new(&tx_v1, 0, Amount::ZERO);
        assert!(!checker_v1.check_sequence(50));
    }
}
