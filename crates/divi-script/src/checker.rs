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

use crate::interpreter::{get_op, SignatureChecker};
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::Transaction;
use sha2::{Digest, Sha256};

/// Transaction signature checker that verifies signatures against actual transaction data
///
/// This implements the SignatureChecker trait, enabling the script interpreter
/// to verify ECDSA signatures during script execution (OP_CHECKSIG, etc).
/// It follows Divi Core's `TransactionSignatureChecker`
/// (script/SignatureCheckers.cpp).
pub struct TransactionSignatureChecker<'a> {
    /// The transaction being validated
    tx: &'a Transaction,
    /// Index of the input being validated
    input_index: usize,
    /// Value of the UTXO being spent (OP_LIMIT_TRANSFER)
    amount: Amount,
}

impl<'a> TransactionSignatureChecker<'a> {
    /// Create a new transaction signature checker
    ///
    /// # Arguments
    /// * `tx` - The transaction containing the input being validated
    /// * `input_index` - Index of the input whose script is being executed
    /// * `amount` - Value of the UTXO being spent
    pub fn new(tx: &'a Transaction, input_index: usize, amount: Amount) -> Self {
        TransactionSignatureChecker {
            tx,
            input_index,
            amount,
        }
    }

    /// Value of the output being spent
    pub fn amount(&self) -> Amount {
        self.amount
    }

    /// Divi Core's `SignatureHash` for this input. `hash_type` is the raw
    /// last byte of the signature: NONE/SINGLE come from its low 5 bits and
    /// ANYONECANPAY from bit 7, and the byte itself is hashed as a 4-byte
    /// integer, whatever its other bits.
    pub fn signature_hash(&self, script_code: &Script, hash_type: i32) -> [u8; 32] {
        signature_hash(script_code, self.tx, self.input_index, hash_type)
    }
}

/// Divi Core's `SignatureHash` (script/SignatureCheckers.cpp). Out-of-range
/// inputs, and SIGHASH_SINGLE without a matching output, hash to the value 1,
/// as in Core.
pub fn signature_hash(
    script_code: &Script,
    tx: &Transaction,
    input_index: usize,
    hash_type: i32,
) -> [u8; 32] {
    let mut one = [0u8; 32];
    one[0] = 1;
    if input_index >= tx.vin.len() {
        return one;
    }
    let anyone_can_pay = hash_type & 0x80 != 0;
    let hash_single = hash_type & 0x1f == 3;
    let hash_none = hash_type & 0x1f == 2;
    if hash_single && input_index >= tx.vout.len() {
        return one;
    }

    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&tx.version.to_le_bytes());
    let inputs: Vec<usize> = if anyone_can_pay {
        vec![input_index]
    } else {
        (0..tx.vin.len()).collect()
    };
    compact_size(&mut data, inputs.len() as u64);
    for n in inputs {
        let input = &tx.vin[n];
        data.extend_from_slice(&serialize(&input.prevout));
        if n == input_index {
            serialize_script_code(&mut data, script_code.as_bytes());
        } else {
            // Blank out other inputs' signatures
            compact_size(&mut data, 0);
        }
        let sequence = if n != input_index && (hash_single || hash_none) {
            0
        } else {
            input.sequence
        };
        data.extend_from_slice(&sequence.to_le_bytes());
    }
    let outputs = if hash_none {
        0
    } else if hash_single {
        input_index + 1
    } else {
        tx.vout.len()
    };
    compact_size(&mut data, outputs as u64);
    for n in 0..outputs {
        if hash_single && n != input_index {
            // CTxOut(): value -1, empty script
            data.extend_from_slice(&(-1i64).to_le_bytes());
            compact_size(&mut data, 0);
        } else {
            data.extend_from_slice(&serialize(&tx.vout[n]));
        }
    }
    data.extend_from_slice(&tx.lock_time.to_le_bytes());
    data.extend_from_slice(&hash_type.to_le_bytes());
    double_sha256(&data)
}

fn compact_size(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&serialize(&divi_primitives::CompactSize(n)));
}

/// Core's `SerializeScriptCode`: the script without its OP_CODESEPARATORs,
/// prefixed by the size Core computes (which counts the full script when a
/// truncated push stops the copy, exactly as Core does)
fn serialize_script_code(out: &mut Vec<u8>, code: &[u8]) {
    const OP_CODESEPARATOR: u8 = 0xab;
    let mut separators = 0usize;
    let mut pc = 0usize;
    while let Some((opcode, _)) = get_op(code, &mut pc) {
        if opcode == OP_CODESEPARATOR {
            separators += 1;
        }
    }
    compact_size(out, (code.len() - separators) as u64);
    let mut pc = 0usize;
    let mut begin = 0usize;
    while let Some((opcode, _)) = get_op(code, &mut pc) {
        if opcode == OP_CODESEPARATOR {
            out.extend_from_slice(&code[begin..pc - 1]);
            begin = pc;
        }
    }
    if begin != code.len() {
        out.extend_from_slice(&code[begin..pc]);
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

/// Divi Core's `CPubKey::Verify` for `sighash`: the key's length must match
/// its header byte, the signature is parsed with the lax DER parser and
/// normalized to low S before verifying (high-S signatures are valid).
pub fn verify_ecdsa_lax(pubkey: &[u8], der_sig: &[u8], sighash: &[u8; 32]) -> bool {
    use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
    let expected_len = match pubkey.first() {
        Some(2) | Some(3) => 33,
        Some(4) | Some(6) | Some(7) => 65,
        _ => return false,
    };
    if pubkey.len() != expected_len || der_sig.is_empty() {
        return false;
    }
    let Ok(key) = PublicKey::from_slice(pubkey) else {
        return false;
    };
    let Ok(mut sig) = Signature::from_der_lax(der_sig) else {
        return false;
    };
    sig.normalize_s();
    thread_local! {
        static SECP: Secp256k1<secp256k1::VerifyOnly> = Secp256k1::verification_only();
    }
    let msg = Message::from_digest(*sighash);
    SECP.with(|secp| secp.verify_ecdsa(&msg, &sig, &key).is_ok())
}

impl SignatureChecker for TransactionSignatureChecker<'_> {
    /// Reference: Divi/divi/src/script/SignatureCheckers.cpp CheckCoinstake
    fn check_coinstake(&self) -> bool {
        self.tx.is_coinstake()
    }

    /// Reference: Divi/divi/src/script/SignatureCheckers.cpp CheckSig
    fn check_sig(&self, sig: &[u8], pubkey: &[u8], script_code: &Script) -> bool {
        // The hash type is one byte tacked on to the end of the signature
        let Some((&hash_type, der_sig)) = sig.split_last() else {
            return false;
        };
        let sighash = self.signature_hash(script_code, hash_type as i32);
        verify_ecdsa_lax(pubkey, der_sig, &sighash)
    }

    /// Reference: Divi/divi/src/script/SignatureCheckers.cpp CheckTransferLimit
    fn check_transfer_limit(&self, minimum_change: i64, change_script: &[u8]) -> bool {
        if minimum_change < 1 {
            return true;
        }
        match self.tx.vout.get(self.input_index) {
            Some(out) => {
                out.script_pubkey.as_bytes() == change_script
                    && minimum_change <= out.value.as_sat()
            }
            None => false,
        }
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
/// * `flags` - Script verification flags, e.g. [`ScriptFlags::mandatory`]
///   for blocks or [`ScriptFlags::policy`] for the mempool
///
/// # Returns
/// * `Ok(())` if the scripts verify successfully
/// * `Err(ScriptError)` if verification fails
///
/// [`ScriptFlags::mandatory`]: crate::error::ScriptFlags::mandatory
/// [`ScriptFlags::policy`]: crate::error::ScriptFlags::policy
pub fn verify_input_with_flags(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    amount: Amount,
    flags: crate::error::ScriptFlags,
) -> Result<(), crate::error::ScriptError> {
    if input_index >= tx.vin.len() {
        return Err(crate::error::ScriptError::InvalidStackOperation);
    }
    let checker = TransactionSignatureChecker::new(tx, input_index, amount);
    crate::interpreter::verify_script_with_amount(
        &tx.vin[input_index].script_sig,
        script_pubkey,
        amount.as_sat(),
        flags,
        &checker,
    )
}

/// Verify one input of `tx` against the output it spends, under
/// [`ScriptFlags::standard`](crate::error::ScriptFlags::standard)
pub fn verify_input(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    amount: Amount,
) -> Result<(), crate::error::ScriptError> {
    verify_input_with_flags(
        tx,
        input_index,
        script_pubkey,
        amount,
        crate::error::ScriptFlags::standard(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SigHashType;
    use divi_crypto::keys::KeyPair;
    use divi_primitives::constants::SEQUENCE_FINAL;
    use divi_primitives::hash::Hash256;
    use divi_primitives::transaction::TxOut;
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
        let sighash = checker.signature_hash(&script_code, 1);

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

    /// Sign input 0 of `tx` against `script_pubkey` and set its scriptSig to
    /// `<sig> <pubkey> <branch>` (branch true = owner path, false = vault path).
    fn sign_vault_input(tx: &mut Transaction, script_pubkey: &Script, kp: &KeyPair, owner: bool) {
        let checker = TransactionSignatureChecker::new(tx, 0, Amount::from_divi(15000));
        let sighash = checker.signature_hash(script_pubkey, 1);
        let mut sig = divi_crypto::sign_hash(kp.secret_key(), &sighash)
            .unwrap()
            .to_der();
        sig.push(SigHashType::All as u8);
        let pubkey = kp.public_key().to_bytes();

        let mut script_sig = vec![sig.len() as u8];
        script_sig.extend_from_slice(&sig);
        script_sig.push(pubkey.len() as u8);
        script_sig.extend_from_slice(&pubkey);
        script_sig.push(if owner {
            crate::opcodes::Opcode::OP_1 as u8
        } else {
            crate::opcodes::Opcode::OP_0 as u8
        });
        tx.vin[0].script_sig = Script::from_bytes(script_sig);
    }

    fn vault_spend_tx(coinstake: bool) -> Transaction {
        let marker = if coinstake {
            TxOut::new(Amount::ZERO, Script::new())
        } else {
            TxOut::new(Amount::from_divi(1), Script::new_p2pkh(&[0u8; 20]))
        };
        Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([7u8; 32]), 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![
                marker,
                TxOut::new(Amount::from_divi(15000), Script::new_p2pkh(&[0u8; 20])),
            ],
            lock_time: 0,
        }
    }

    /// Port of Divi Core script_tests.cpp "Vault spend but not coinstake",
    /// "Owner spend regardless" and "Vault spend with coinstake", run through
    /// verify_input with the standard flags (which include REQUIRE_COINSTAKE).
    #[test]
    fn test_vault_spend_requires_coinstake() {
        let owner = create_test_keypair();
        let manager = create_test_keypair();
        let vault = crate::vault::StakingVaultScript::new(
            *owner.public_key().pubkey_hash().as_bytes(),
            *manager.public_key().pubkey_hash().as_bytes(),
        )
        .to_script();
        let value = Amount::from_divi(15000);

        // Vault spend but not coinstake: rejected
        let mut tx = vault_spend_tx(false);
        assert!(!tx.is_coinstake());
        sign_vault_input(&mut tx, &vault, &manager, false);
        assert!(matches!(
            verify_input(&tx, 0, &vault, value),
            Err(crate::error::ScriptError::RequireCoinstake)
        ));

        // Owner spend regardless: accepted
        let mut tx = vault_spend_tx(false);
        sign_vault_input(&mut tx, &vault, &owner, true);
        verify_input(&tx, 0, &vault, value).expect("owner spend");

        // Vault spend with coinstake: accepted
        let mut tx = vault_spend_tx(true);
        assert!(tx.is_coinstake());
        sign_vault_input(&mut tx, &vault, &manager, false);
        verify_input(&tx, 0, &vault, value).expect("vault spend in coinstake");

        // The manager key cannot take the owner path
        let mut tx = vault_spend_tx(false);
        sign_vault_input(&mut tx, &vault, &manager, true);
        assert!(verify_input(&tx, 0, &vault, value).is_err());
    }
}
