// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Bridges a `swap-adaptor` ECDSA (adaptor) signature into a DIVI scriptSig.
//!
//! `swap-adaptor` is built on `secp256kfun`/`ecdsa_fun` — a from-scratch secp256k1
//! implementation, independent of the `secp256k1` (libsecp256k1 bindings) this repo's
//! `divi-crypto` uses. Both speak the same curve and the same signature *encoding*
//! (`ecdsa_fun` advertises itself as "Bitcoin compatible"), so a signature produced by one
//! verifies fine under the other — this module is the one place that conversion happens,
//! and the test below is the load-bearing proof for `xmr-design.md`'s whole design: that
//! completing an adaptor signature (`swap-adaptor::adaptor`) yields something DIVI's own
//! script verifier accepts exactly like an ordinary multisig signature, with no special
//! support needed on the DIVI side.

use divi_crypto::signature::Signature as DiviSignature;
use divi_script::SigHashType;
use swap_adaptor::adaptor::{Point, Signature as AdaptorSignature};

/// `ecdsa_fun`'s raw 64-byte `(R_x, s)` encoding is byte-identical to `divi-crypto`'s
/// "compact" signature format, so this is a pure re-encode into DER + a trailing
/// `SIGHASH_ALL` byte — no cryptographic conversion, both sides already speak the same
/// curve and the same low-S convention (`ecdsa_fun::ECDSA::sign`/`decrypt_signature`
/// always normalize to low-S, matching DIVI's `SCRIPT_VERIFY_LOW_S` policy).
pub fn to_divi_script_sig(
    sig: &AdaptorSignature,
) -> Result<Vec<u8>, divi_crypto::error::CryptoError> {
    let divi_sig = DiviSignature::from_compact(&sig.to_bytes())?;
    let mut bytes = divi_sig.to_der();
    bytes.push(SigHashType::All as u8);
    Ok(bytes)
}

/// `secp256kfun::Point`'s compressed SEC1 encoding (`[0x02|0x03] || x`) is the same
/// format `divi-crypto`/the redeem script expect — this is just a type-level cast point,
/// kept as a named function so callers don't have to know that.
pub fn to_divi_pubkey(point: &Point) -> [u8; 33] {
    point.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_crypto::keys::SecretKey;
    use divi_primitives::amount::Amount;
    use divi_primitives::transaction::TxOut;
    use divi_script::verify_input;
    use swap_adaptor::adaptor::{AdaptorSigner, Scalar};

    use crate::multisig::{redeem_script, script_pubkey, test_outpoint};

    /// The claim this whole design rests on: take a transaction one party has already
    /// half-signed normally (A, via `divi-crypto`), complete the other party's signature
    /// via `swap-adaptor`'s ECDSA adaptor (as `Tx_redeem` does in `xmr-design.md`'s
    /// `## Protocol` once Maker decrypts Taker's encrypted signature), and confirm
    /// `divi_script::verify_input` accepts the result exactly like a plain multisig spend.
    #[test]
    fn adaptor_completed_signature_satisfies_divi_checkmultisig() {
        let key_a = SecretKey::from_bytes(&[0x44; 32]).unwrap();
        let pubkey_a = key_a.public_key().serialize_compressed();

        // B's "key" is a secp256kfun scalar/point pair instead of a divi-crypto one --
        // this is Taker's adaptor signing key in the design, never a plain SecretKey.
        let adaptor = AdaptorSigner::new();
        let mut rng = rand::thread_rng();
        let signing_key_b = Scalar::random(&mut rng);
        let pubkey_b = to_divi_pubkey(&adaptor.verification_key_for(&signing_key_b));

        let redeem = redeem_script(&pubkey_a, &pubkey_b);
        let spk = script_pubkey(&redeem);
        let payout = TxOut::new(
            Amount::from_sat(9_000),
            divi_primitives::script::Script::new_p2pkh(&[5u8; 20]),
        );

        // Build the unsigned skeleton the same way build_presigned_spend does internally,
        // then sign input 0 for A normally and for B via the adaptor path.
        let mut tx = divi_primitives::transaction::Transaction {
            version: divi_primitives::constants::CURRENT_TX_VERSION,
            vin: vec![divi_primitives::transaction::TxIn::new(
                test_outpoint(9),
                divi_primitives::script::Script::new(),
                divi_swap::htlc::REFUND_SEQUENCE,
            )],
            vout: vec![payout],
            lock_time: 0,
        };
        let redeem_script_obj = divi_primitives::script::Script::from_bytes(redeem.clone());
        let sig_a = crate::multisig::sign_input(&tx, 0, &redeem_script_obj, &key_a).unwrap();

        let sighash =
            divi_wallet::signer::sighash(&tx, 0, &redeem_script_obj, SigHashType::All, false)
                .unwrap();

        // The encryption key would be Maker's half in the real protocol; here it's just
        // thrown away immediately since this test only exercises the decrypt -> verify leg.
        let decryption_key = Scalar::random(&mut rng);
        let encryption_key = adaptor.encryption_key_for(&decryption_key);
        let encrypted = adaptor.encrypted_sign(&signing_key_b, &encryption_key, sighash.as_bytes());
        let completed = adaptor.decrypt_signature(&decryption_key, encrypted);
        assert!(adaptor.verify(
            &adaptor.verification_key_for(&signing_key_b),
            sighash.as_bytes(),
            &completed
        ));

        let sig_b = to_divi_script_sig(&completed).unwrap();
        tx.vin[0].script_sig = crate::multisig::script_sig(&sig_a, &sig_b, &redeem);

        verify_input(&tx, 0, &spk, Amount::from_sat(10_000)).unwrap();
    }

    /// Decrypting under the *wrong* key must not produce a signature that satisfies the
    /// script — otherwise the "only the real decryption key completes the signature"
    /// property the whole design leans on (Maker must actually know Taker's secret to
    /// finish `Tx_redeem`) wouldn't hold.
    #[test]
    fn decrypting_with_wrong_key_does_not_satisfy_script() {
        let key_a = SecretKey::from_bytes(&[0x44; 32]).unwrap();
        let pubkey_a = key_a.public_key().serialize_compressed();
        let adaptor = AdaptorSigner::new();
        let mut rng = rand::thread_rng();
        let signing_key_b = Scalar::random(&mut rng);
        let pubkey_b = to_divi_pubkey(&adaptor.verification_key_for(&signing_key_b));
        let redeem = redeem_script(&pubkey_a, &pubkey_b);
        let spk = script_pubkey(&redeem);

        let mut tx = divi_primitives::transaction::Transaction {
            version: divi_primitives::constants::CURRENT_TX_VERSION,
            vin: vec![divi_primitives::transaction::TxIn::new(
                test_outpoint(9),
                divi_primitives::script::Script::new(),
                divi_swap::htlc::REFUND_SEQUENCE,
            )],
            vout: vec![TxOut::new(
                Amount::from_sat(9_000),
                divi_primitives::script::Script::new_p2pkh(&[5u8; 20]),
            )],
            lock_time: 0,
        };
        let redeem_script_obj = divi_primitives::script::Script::from_bytes(redeem.clone());
        let sig_a = crate::multisig::sign_input(&tx, 0, &redeem_script_obj, &key_a).unwrap();
        let sighash =
            divi_wallet::signer::sighash(&tx, 0, &redeem_script_obj, SigHashType::All, false)
                .unwrap();

        let decryption_key = Scalar::random(&mut rng);
        let encryption_key = adaptor.encryption_key_for(&decryption_key);
        let encrypted = adaptor.encrypted_sign(&signing_key_b, &encryption_key, sighash.as_bytes());

        let wrong_decryption_key = Scalar::random(&mut rng);
        let bogus = adaptor.decrypt_signature(&wrong_decryption_key, encrypted);
        let sig_b = to_divi_script_sig(&bogus).unwrap();
        tx.vin[0].script_sig = crate::multisig::script_sig(&sig_a, &sig_b, &redeem);

        assert!(verify_input(&tx, 0, &spk, Amount::from_sat(10_000)).is_err());
    }
}
