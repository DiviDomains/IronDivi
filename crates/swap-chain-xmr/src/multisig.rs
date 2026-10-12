// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The 2-of-2 P2SH multisig output `Tx_lock`/`Tx_cancel` pay into
//! (`docs/plans/swap-poc/xmr-design.md`, `## DIVI scripts`), and the presigned-transaction
//! spend helper every one of `Tx_cancel`/`Tx_refund`/`Tx_punish`/`Tx_redeem` builds on:
//!
//! ```text
//! redeemScript:  OP_2 <pubkey_a> <pubkey_b> OP_2 OP_CHECKMULTISIG
//! scriptSig:     OP_0 <sig_a> <sig_b> <redeemScript>
//! ```
//!
//! No `OP_IF`/`OP_ELSE` branching and no `OP_CHECKLOCKTIMEVERIFY`: every spend of this
//! output is a specific presigned transaction with its own `nLockTime`, so the design
//! leans on the base "a transaction with a future `nLockTime` and a non-final input can't
//! be mined" rule (`divi_primitives::transaction::Transaction::is_final`) instead of an
//! in-script timelock — see the design doc for why DIVI's live consensus can't do CSV and
//! doesn't need to here.

use divi_crypto::hash::hash160;
use divi_crypto::keys::SecretKey;
use divi_crypto::signature::sign_hash;
use divi_primitives::amount::Amount;
use divi_primitives::constants::CURRENT_TX_VERSION;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::SigHashType;
use divi_swap::htlc::push_data;
use divi_wallet::signer::sighash;
use thiserror::Error;

/// Errors building or signing a presigned multisig spend.
#[derive(Debug, Error)]
pub enum MultisigError {
    /// Sighash computation failed (e.g. `input_index` out of range).
    #[error("sighash: {0}")]
    Sighash(String),
    /// Signing failed at the `divi-crypto` layer.
    #[error("sign: {0}")]
    Sign(String),
}

/// `OP_2 <pubkey_a> <pubkey_b> OP_2 OP_CHECKMULTISIG`. `pubkey_a`/`pubkey_b` are compressed
/// secp256k1 points, in the order signatures must appear in the scriptSig.
pub fn redeem_script(pubkey_a: &[u8; 33], pubkey_b: &[u8; 33]) -> Vec<u8> {
    const OP_2: u8 = 0x52;
    const OP_CHECKMULTISIG: u8 = 0xae;
    let mut s = Vec::with_capacity(2 + 34 + 34 + 1);
    s.push(OP_2);
    push_data(&mut s, pubkey_a);
    push_data(&mut s, pubkey_b);
    s.push(OP_2);
    s.push(OP_CHECKMULTISIG);
    s
}

/// The P2SH scriptPubKey for a redeem script.
pub fn script_pubkey(redeem_script: &[u8]) -> Script {
    Script::new_p2sh(hash160(redeem_script).as_bytes())
}

/// `OP_0 <sig_a> <sig_b> <redeemScript>` — `sig_a`/`sig_b` already carry their trailing
/// sighash-type byte (as produced by [`sign_input`]), in the same order as `redeem_script`'s
/// pubkeys.
pub fn script_sig(sig_a: &[u8], sig_b: &[u8], redeem_script: &[u8]) -> Script {
    let mut s = Vec::new();
    push_data(&mut s, &[]); // OP_0: CHECKMULTISIG's off-by-one dummy element
    push_data(&mut s, sig_a);
    push_data(&mut s, sig_b);
    push_data(&mut s, redeem_script);
    Script::from_bytes(s)
}

/// Sign input `input_index` of `tx` for the multisig `redeem_script` (used as the legacy
/// sighash scriptCode — the P2SH outer scriptPubKey is never the scriptCode). Returns a DER
/// signature with the trailing `SIGHASH_ALL` byte, ready for [`script_sig`].
pub fn sign_input(
    tx: &Transaction,
    input_index: usize,
    redeem_script: &Script,
    secret_key: &SecretKey,
) -> Result<Vec<u8>, MultisigError> {
    let hash = sighash(tx, input_index, redeem_script, SigHashType::All, false)
        .map_err(|e| MultisigError::Sighash(e.to_string()))?;
    let signature =
        sign_hash(secret_key, hash.as_bytes()).map_err(|e| MultisigError::Sign(e.to_string()))?;
    let mut sig_bytes = signature.to_der();
    sig_bytes.push(SigHashType::All as u8);
    Ok(sig_bytes)
}

/// Build a transaction with one input spending `prevout` (value `input_value`, locked by
/// `redeem_script`) and one output, signed by both `secret_a` and `secret_b` — the shape
/// every `Tx_cancel`/`Tx_refund`/`Tx_punish`/`Tx_redeem` template takes in
/// `xmr-design.md`'s `## Protocol` (there, one of the two signatures is an adaptor
/// signature instead; this is the plain-multisig skeleton step 2 proves before step 7
/// swaps one signer in for `swap-adaptor`).
///
/// `sequence` must be non-final (e.g. [`divi_swap::htlc::REFUND_SEQUENCE`]) for
/// `lock_time` to actually gate inclusion — see the module docs.
#[allow(clippy::too_many_arguments)]
pub fn build_presigned_spend(
    prevout: OutPoint,
    input_value: Amount,
    redeem_script_bytes: &[u8],
    secret_a: &SecretKey,
    secret_b: &SecretKey,
    output: TxOut,
    lock_time: u32,
    sequence: u32,
) -> Result<Transaction, MultisigError> {
    let _ = input_value; // not yet needed by legacy sighash; kept for the segwit-less API's symmetry with swap-chain-btc/ltc.
    let mut tx = Transaction {
        version: CURRENT_TX_VERSION,
        vin: vec![TxIn::new(prevout, Script::new(), sequence)],
        vout: vec![output],
        lock_time,
    };

    let redeem = Script::from_bytes(redeem_script_bytes.to_vec());
    let sig_a = sign_input(&tx, 0, &redeem, secret_a)?;
    let sig_b = sign_input(&tx, 0, &redeem, secret_b)?;
    tx.vin[0].script_sig = script_sig(&sig_a, &sig_b, redeem_script_bytes);
    Ok(tx)
}

/// Build the `Tx_lock`-shaped funding transaction: a single output paying `amount` to the
/// 2-of-2 `script_pubkey`. Unsigned — funding spends the maker's ordinary coins, which
/// `swap-chain-xmr` doesn't select or own here (`ChainBackend::build_funding` territory,
/// out of scope for this skeleton).
pub fn funding_output(redeem_script_bytes: &[u8], amount: Amount) -> TxOut {
    TxOut::new(amount, script_pubkey(redeem_script_bytes))
}

/// A throwaway `OutPoint` for tests that don't need a real funding tx on hand.
pub fn test_outpoint(byte: u8) -> OutPoint {
    OutPoint::new(Hash256::from_bytes([byte; 32]), 0)
}
