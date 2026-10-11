// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Build-plan step 7 (`docs/plans/swap-poc/xmr-design.md`): the full
//! `Tx_redeem`/`Tx_refund`/`Tx_punish` set, with the **corrected** signer/completer roles
//! (the design doc's `## Protocol` section had these backwards in an earlier draft —
//! fixed after the `oracle` checked them against `comit-network/xmr-btc-swap`'s actual
//! `alice`/`bob` state machines):
//!
//! - **`Tx_redeem`** (pays Taker): Maker's signature is adaptor-encrypted under Taker's
//!   point `X`; Taker's is plain. Taker completes (she holds the decryption key `s_t`)
//!   and broadcasts — claiming the DIVI, and revealing `s_t` to Maker in the process.
//! - **`Tx_refund`** (pays Maker): Taker's signature is adaptor-encrypted under Maker's
//!   point `Y`; Maker's is plain. Maker completes (he holds `s_m`) and broadcasts —
//!   reclaiming his DIVI, and revealing `s_m` to Taker, who needs it to reclaim her own
//!   locked XMR (see the design doc for why this is the mechanism that keeps the abort
//!   path from stranding her funds).
//! - **`Tx_punish`** (pays Taker, everything): no adaptor signature at all — it's a
//!   plain 2-of-2 presigned transaction ([`crate::multisig::build_presigned_spend`]
//!   already builds this shape; there's no new function here, just the right call).
//!
//! Each party's DIVI-side multisig key (`a'`/`b'` on the `Tx_cancel` output, in the
//! design doc's notation) is used for *both* a plain signature (on whichever
//! transaction calls for their plain half) and an adaptor-encrypted one (on whichever
//! calls for their encrypted half) — [`divi_secret_to_adaptor_scalar`] bridges the same
//! underlying secp256k1 scalar between `divi-crypto`'s and `swap-adaptor`'s types so
//! both roles use the identical key.

use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::{verify_input, ScriptError, SigHashType};
use divi_wallet::signer::sighash;
use swap_adaptor::adaptor::{AdaptorSigner, EncryptedSignature, Point, Scalar};
use thiserror::Error;

use crate::adaptor_bridge::to_divi_script_sig;
use crate::multisig::{script_sig, sign_input};

/// Errors building or completing an adaptor-signed presigned spend.
#[derive(Debug, Error)]
pub enum TemplateError {
    /// Legacy sighash/signing failed (see [`crate::multisig::MultisigError`]).
    #[error("multisig: {0}")]
    Multisig(#[from] crate::multisig::MultisigError),
    /// Re-encoding the completed adaptor signature into a DIVI scriptSig failed.
    #[error("adaptor bridge: {0}")]
    AdaptorBridge(#[from] divi_crypto::error::CryptoError),
    /// The decrypted signature doesn't verify against the counterparty's claimed
    /// adaptor point — wrong decryption key, or the encrypted signature was never
    /// valid for this transaction in the first place.
    #[error("completed signature failed adaptor verification")]
    BadCompletion,
}

/// Bridges a DIVI secp256k1 secret key (`divi-crypto`'s type) into `swap-adaptor`'s
/// scalar type, so the *same* key that signs plainly on one transaction can also
/// produce an adaptor-encrypted signature on another — both curves, both libraries,
/// same 32-byte big-endian scalar encoding (checked against `secp256kfun::Scalar`'s own
/// docs, which state it is big-endian, matching `divi-crypto`'s raw secret key bytes).
pub fn divi_secret_to_adaptor_scalar(sk: &SecretKey) -> Scalar {
    let bytes: [u8; 32] = sk.as_bytes().try_into().expect("secret key is 32 bytes");
    Scalar::from_bytes(bytes)
        .expect("a valid secp256k1 secret key is always a valid secp256kfun scalar")
}

fn unsigned_spend(prevout: OutPoint, output: TxOut, lock_time: u32, sequence: u32) -> Transaction {
    Transaction {
        version: 2,
        vin: vec![TxIn::new(prevout, Script::new(), sequence)],
        vout: vec![output],
        lock_time,
    }
}

/// `Tx_redeem`, Maker's half: an adaptor-encrypted signature over the spend of `prevout`
/// (the `Tx_lock`/`Tx_cancel` output) paying `output` to Taker, encrypted under Taker's
/// point `taker_x_point` (`X = s_t·G`). Maker sends this to Taker at setup; it does not
/// move anything on-chain by itself.
pub fn maker_encrypts_tx_redeem(
    prevout: OutPoint,
    redeem_script_bytes: &[u8],
    maker_key: &SecretKey,
    taker_x_point: &Point,
    output: TxOut,
    sequence: u32,
) -> Result<(Transaction, EncryptedSignature), TemplateError> {
    let tx = unsigned_spend(prevout, output, 0, sequence);
    let redeem_script_obj = Script::from_bytes(redeem_script_bytes.to_vec());
    let hash = sighash(&tx, 0, &redeem_script_obj, SigHashType::All, false)
        .map_err(|e| crate::multisig::MultisigError::Sighash(e.to_string()))?;
    let maker_scalar = divi_secret_to_adaptor_scalar(maker_key);
    let adaptor = AdaptorSigner::new();
    let encrypted = adaptor.encrypted_sign(&maker_scalar, taker_x_point, hash.as_bytes());
    Ok((tx, encrypted))
}

/// `Tx_redeem`, Taker's completion: decrypts Maker's encrypted signature with `s_t`,
/// signs her own plain half with `taker_key`, and assembles the final, broadcastable
/// transaction. This is the step that reveals `s_t` to anyone (Maker) watching the
/// chain, per `xmr-design.md`'s `## Protocol`.
pub fn taker_completes_tx_redeem(
    mut tx: Transaction,
    redeem_script_bytes: &[u8],
    maker_verification_point: &Point,
    maker_encrypted_sig: EncryptedSignature,
    taker_key: &SecretKey,
    s_t: &Scalar,
) -> Result<Transaction, TemplateError> {
    let adaptor = AdaptorSigner::new();
    let completed_maker_sig = adaptor.decrypt_signature(s_t, maker_encrypted_sig);
    let redeem_script_obj = Script::from_bytes(redeem_script_bytes.to_vec());
    let sighash_bytes = sighash(&tx, 0, &redeem_script_obj, SigHashType::All, false)
        .map_err(|e| crate::multisig::MultisigError::Sighash(e.to_string()))?;
    if !adaptor.verify(
        maker_verification_point,
        sighash_bytes.as_bytes(),
        &completed_maker_sig,
    ) {
        // Wrong s_t, or Maker's encrypted signature was never valid for this tx --
        // fail now rather than build a scriptSig that would only fail later, less
        // informatively, in verify_input.
        return Err(TemplateError::BadCompletion);
    }
    let sig_maker = to_divi_script_sig(&completed_maker_sig)?;
    let sig_taker = sign_input(&tx, 0, &redeem_script_obj, taker_key)?;
    tx.vin[0].script_sig = script_sig(&sig_maker, &sig_taker, redeem_script_bytes);
    Ok(tx)
}

/// `Tx_refund`, Taker's half: an adaptor-encrypted signature over the spend of
/// `prevout` (the `Tx_cancel` output) paying `output` to Maker, encrypted under Maker's
/// point `maker_y_point` (`Y = s_m·G`). `lock_time` is `t_refund`.
pub fn taker_encrypts_tx_refund(
    prevout: OutPoint,
    redeem_script_bytes: &[u8],
    taker_key: &SecretKey,
    maker_y_point: &Point,
    output: TxOut,
    lock_time: u32,
    sequence: u32,
) -> Result<(Transaction, EncryptedSignature), TemplateError> {
    let tx = unsigned_spend(prevout, output, lock_time, sequence);
    let redeem_script_obj = Script::from_bytes(redeem_script_bytes.to_vec());
    let hash = sighash(&tx, 0, &redeem_script_obj, SigHashType::All, false)
        .map_err(|e| crate::multisig::MultisigError::Sighash(e.to_string()))?;
    let taker_scalar = divi_secret_to_adaptor_scalar(taker_key);
    let adaptor = AdaptorSigner::new();
    let encrypted = adaptor.encrypted_sign(&taker_scalar, maker_y_point, hash.as_bytes());
    Ok((tx, encrypted))
}

/// `Tx_refund`, Maker's completion: decrypts Taker's encrypted signature with `s_m`,
/// signs his own plain half, and assembles the final transaction. Revealing `s_m` here
/// is what lets Taker later reclaim her own locked XMR.
pub fn maker_completes_tx_refund(
    mut tx: Transaction,
    redeem_script_bytes: &[u8],
    taker_verification_point: &Point,
    taker_encrypted_sig: EncryptedSignature,
    maker_key: &SecretKey,
    s_m: &Scalar,
) -> Result<Transaction, TemplateError> {
    let adaptor = AdaptorSigner::new();
    let completed_taker_sig = adaptor.decrypt_signature(s_m, taker_encrypted_sig);
    let redeem_script_obj = Script::from_bytes(redeem_script_bytes.to_vec());
    let sighash_bytes = sighash(&tx, 0, &redeem_script_obj, SigHashType::All, false)
        .map_err(|e| crate::multisig::MultisigError::Sighash(e.to_string()))?;
    if !adaptor.verify(
        taker_verification_point,
        sighash_bytes.as_bytes(),
        &completed_taker_sig,
    ) {
        return Err(TemplateError::BadCompletion);
    }
    let sig_taker = to_divi_script_sig(&completed_taker_sig)?;
    let sig_maker = sign_input(&tx, 0, &redeem_script_obj, maker_key)?;
    tx.vin[0].script_sig = script_sig(&sig_maker, &sig_taker, redeem_script_bytes);
    Ok(tx)
}

/// Extract the completer's secret from a decrypted signature plus the encrypted
/// signature it was decrypted from — the step that lets the *other* party (whoever
/// didn't complete it) recover the secret once the completed signature is on-chain.
/// Used identically for Maker recovering `s_t` from a broadcast `Tx_redeem` and for
/// Taker recovering `s_m` from a broadcast `Tx_refund`.
pub fn recover_secret_from_chain(
    encryption_point: &Point,
    completed_signature: &swap_adaptor::adaptor::Signature,
    encrypted_signature: &EncryptedSignature,
) -> Option<Scalar> {
    AdaptorSigner::new().recover_decryption_key(
        encryption_point,
        completed_signature,
        encrypted_signature,
    )
}

/// Verify a finished spend (any of `Tx_redeem`/`Tx_refund`/`Tx_punish`) actually
/// satisfies the 2-of-2 `OP_CHECKMULTISIG` — the same mock-consensus check
/// [`crate::multisig`] uses, re-exported here for template-level tests/callers so they
/// don't need to import `divi_script` directly.
pub fn verify_spend(
    tx: &Transaction,
    script_pubkey: &Script,
    input_value: Amount,
) -> Result<(), ScriptError> {
    verify_input(tx, 0, script_pubkey, input_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multisig::{build_presigned_spend, redeem_script, script_pubkey, test_outpoint};
    use divi_swap::htlc::REFUND_SEQUENCE;
    use rand::thread_rng;
    use swap_adaptor::adaptor::AdaptorSigner;

    const MAKER_KEY: [u8; 32] = [0x11; 32];
    const TAKER_KEY: [u8; 32] = [0x22; 32];

    fn keys() -> (SecretKey, SecretKey) {
        (
            SecretKey::from_bytes(&MAKER_KEY).unwrap(),
            SecretKey::from_bytes(&TAKER_KEY).unwrap(),
        )
    }

    fn payout(to_byte: u8) -> TxOut {
        TxOut::new(
            Amount::from_sat(9_000),
            divi_primitives::script::Script::new_p2pkh(&[to_byte; 20]),
        )
    }

    /// `Tx_redeem`: Maker encrypts, Taker completes with `s_t` and broadcasts. The
    /// completed spend satisfies the 2-of-2 script exactly like a plain one, and
    /// Maker can recover `s_t` from the gap between his encrypted and the now-completed
    /// signature -- the property the whole design's happy path depends on.
    #[test]
    fn tx_redeem_completes_and_reveals_s_t_to_maker() {
        let (maker_key, taker_key) = keys();
        let s_t = Scalar::random(&mut thread_rng());
        let adaptor = AdaptorSigner::new();
        let x_point = adaptor.verification_key_for(&s_t);

        let pubkey_maker = maker_key.public_key().serialize_compressed();
        let pubkey_taker = taker_key.public_key().serialize_compressed();
        let redeem = redeem_script(&pubkey_maker, &pubkey_taker);
        let spk = script_pubkey(&redeem);

        let (tx, maker_encrypted) = maker_encrypts_tx_redeem(
            test_outpoint(1),
            &redeem,
            &maker_key,
            &x_point,
            payout(9),
            REFUND_SEQUENCE,
        )
        .unwrap();

        let maker_verification_point =
            adaptor.verification_key_for(&divi_secret_to_adaptor_scalar(&maker_key));
        let completed_tx = taker_completes_tx_redeem(
            tx,
            &redeem,
            &maker_verification_point,
            maker_encrypted.clone(),
            &taker_key,
            &s_t,
        )
        .unwrap();

        verify_spend(&completed_tx, &spk, Amount::from_sat(10_000)).unwrap();

        // Maker recovers s_t from the gap between his own encrypted signature (which
        // he already held from setup) and the completed one Taker just broadcast.
        let completed_maker_sig = adaptor.decrypt_signature(&s_t, maker_encrypted.clone());
        let recovered = recover_secret_from_chain(&x_point, &completed_maker_sig, &maker_encrypted)
            .expect("maker must recover s_t from the broadcast Tx_redeem");
        assert_eq!(recovered, s_t);
    }

    /// `Tx_refund`: the mirror image -- Taker encrypts, Maker completes with `s_m` and
    /// broadcasts, revealing `s_m` to Taker so she can reclaim her own locked XMR.
    #[test]
    fn tx_refund_completes_and_reveals_s_m_to_taker() {
        let (maker_key, taker_key) = keys();
        let s_m = Scalar::random(&mut thread_rng());
        let adaptor = AdaptorSigner::new();
        let y_point = adaptor.verification_key_for(&s_m);

        let pubkey_maker = maker_key.public_key().serialize_compressed();
        let pubkey_taker = taker_key.public_key().serialize_compressed();
        let redeem = redeem_script(&pubkey_maker, &pubkey_taker);
        let spk = script_pubkey(&redeem);
        const T_REFUND: u32 = 2_000_000_000;

        let (tx, taker_encrypted) = taker_encrypts_tx_refund(
            test_outpoint(2),
            &redeem,
            &taker_key,
            &y_point,
            payout(7),
            T_REFUND,
            REFUND_SEQUENCE,
        )
        .unwrap();

        let taker_verification_point =
            adaptor.verification_key_for(&divi_secret_to_adaptor_scalar(&taker_key));
        let completed_tx = maker_completes_tx_refund(
            tx,
            &redeem,
            &taker_verification_point,
            taker_encrypted.clone(),
            &maker_key,
            &s_m,
        )
        .unwrap();

        verify_spend(&completed_tx, &spk, Amount::from_sat(10_000)).unwrap();
        assert!(
            !completed_tx.is_final(0, T_REFUND - 1),
            "Tx_refund must not be minable before t_refund"
        );
        assert!(completed_tx.is_final(0, T_REFUND + 1));

        let completed_taker_sig = adaptor.decrypt_signature(&s_m, taker_encrypted.clone());
        let recovered = recover_secret_from_chain(&y_point, &completed_taker_sig, &taker_encrypted)
            .expect("taker must recover s_m from the broadcast Tx_refund");
        assert_eq!(recovered, s_m);
    }

    /// `Tx_punish`: plain 2-of-2, no adaptor at all, pays everything to **Taker** (not
    /// Maker -- the earlier draft had this backwards too). Just a named exercise of
    /// `build_presigned_spend` in the punish direction/timelock, pinning the shape.
    #[test]
    fn tx_punish_is_plain_and_pays_taker() {
        let (maker_key, taker_key) = keys();
        let pubkey_maker = maker_key.public_key().serialize_compressed();
        let pubkey_taker = taker_key.public_key().serialize_compressed();
        let redeem = redeem_script(&pubkey_maker, &pubkey_taker);
        let spk = script_pubkey(&redeem);
        const T_PUNISH: u32 = 2_100_000_000;

        // Maker signs at setup; Taker holds the fully-built tx and broadcasts after
        // t_punish. build_presigned_spend signs both sides immediately since this path
        // needs no adaptor exchange -- Maker's plain signature is handed over once and
        // never needs completing.
        let tx = build_presigned_spend(
            test_outpoint(3),
            Amount::from_sat(10_000),
            &redeem,
            &maker_key,
            &taker_key,
            payout(7), // pays Taker
            T_PUNISH,
            REFUND_SEQUENCE,
        )
        .unwrap();

        verify_spend(&tx, &spk, Amount::from_sat(10_000)).unwrap();
        assert!(!tx.is_final(0, T_PUNISH - 1));
        assert!(tx.is_final(0, T_PUNISH + 1));
    }

    /// Completing `Tx_redeem` with the wrong `s_t` must not satisfy the script --
    /// otherwise anyone could claim without actually knowing the Taker's secret.
    #[test]
    fn tx_redeem_fails_with_wrong_secret() {
        let (maker_key, taker_key) = keys();
        let s_t = Scalar::random(&mut thread_rng());
        let wrong_s_t = Scalar::random(&mut thread_rng());
        let adaptor = AdaptorSigner::new();
        let x_point = adaptor.verification_key_for(&s_t);

        let pubkey_maker = maker_key.public_key().serialize_compressed();
        let pubkey_taker = taker_key.public_key().serialize_compressed();
        let redeem = redeem_script(&pubkey_maker, &pubkey_taker);

        let (tx, maker_encrypted) = maker_encrypts_tx_redeem(
            test_outpoint(1),
            &redeem,
            &maker_key,
            &x_point,
            payout(9),
            REFUND_SEQUENCE,
        )
        .unwrap();

        let maker_verification_point =
            adaptor.verification_key_for(&divi_secret_to_adaptor_scalar(&maker_key));
        let err = taker_completes_tx_redeem(
            tx,
            &redeem,
            &maker_verification_point,
            maker_encrypted,
            &taker_key,
            &wrong_s_t,
        )
        .unwrap_err();

        assert!(matches!(err, TemplateError::BadCompletion));
    }
}
