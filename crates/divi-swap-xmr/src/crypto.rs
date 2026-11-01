// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Glue between the protocol's three key representations — DIVI secp256k1 keys
//! (`divi-crypto`), `swap-adaptor`'s secp256k1 scalars/points, and the DLEQ's ed25519
//! scalars/points (which double as the Monero spend-key shares) — plus the per-party pieces
//! of the 2-of-2 that `swap-chain-xmr` builds whole: one party's plain signature, checking
//! the other's, and reading a completed adaptor signature back out of a broadcast spend.

use curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
use divi_crypto::keys::{PublicKey, SecretKey};
use divi_crypto::signature::{verify_hash, Signature as DiviSignature};
use divi_primitives::script::Script;
use divi_primitives::transaction::Transaction;
use divi_script::SigHashType;
use divi_wallet::signer::sighash;
use swap_adaptor::adaptor::{AdaptorSigner, EncryptedSignature, Point, Scalar, Signature};
use swap_adaptor::dleq::{PointQ, ScalarQ};
use swap_chain_xmr::swap_templates::{divi_secret_to_adaptor_scalar, recover_secret_from_chain};
use swap_chain_xmr::{lock_scripts, multisig};

use divi_swap::{Result, SwapError};

/// Which multisig signer: the maker's key is first in the redeem script, the taker's second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signer {
    /// `a`, first pubkey / first signature.
    Maker,
    /// `b`, second pubkey / second signature.
    Taker,
}

/// The secp256k1 form of a DLEQ secret: the same 252-bit number, big-endian.
pub fn secp_of(s: &ScalarQ) -> Scalar {
    let mut b = s.to_bytes();
    b.reverse();
    Scalar::from_bytes(b).expect("a DLEQ secret is clamped below 2^252, a valid secp256k1 scalar")
}

/// The ed25519 form of a secp256k1 scalar recovered from the chain, if it is one (a
/// recovered DLEQ secret always is).
pub fn ed_of(s: &Scalar) -> Option<ScalarQ> {
    let mut b = s.to_bytes();
    b.reverse();
    ScalarQ::from_canonical_bytes(b)
}

/// `s·G` on ed25519: a Monero spend-key share's public half.
pub fn ed_pub(s: &ScalarQ) -> PointQ {
    s * &ED25519_BASEPOINT_TABLE
}

/// The 2-of-2 Monero output's public spend key `S_m + S_t`, compressed.
pub fn shared_spend_key(maker_share: &PointQ, taker_share: &PointQ) -> [u8; 32] {
    (maker_share + taker_share).compress().to_bytes()
}

/// The adaptor-verification point of a DIVI multisig key (its public key as a
/// `swap-adaptor` point).
pub fn verification_point(sk: &SecretKey) -> Point {
    AdaptorSigner::new().verification_key_for(&divi_secret_to_adaptor_scalar(sk))
}

/// A counterparty's compressed DIVI pubkey as a `swap-adaptor` point.
pub fn point_of_pubkey(pk: &[u8; 33]) -> Result<Point> {
    Point::from_bytes(*pk).ok_or_else(|| SwapError::InvalidParams("not a secp256k1 pubkey".into()))
}

/// Redeem script and P2SH scriptPubKey of the swap's 2-of-2 `{maker, taker}`.
pub fn multisig_script(maker_pk: &[u8; 33], taker_pk: &[u8; 33]) -> (Vec<u8>, Script) {
    let redeem = multisig::redeem_script(maker_pk, taker_pk);
    let spk = multisig::script_pubkey(&redeem);
    (redeem, spk)
}

/// The legacy SIGHASH_ALL digest of `tx`'s single input spending the 2-of-2.
pub fn digest(tx: &Transaction, redeem: &[u8]) -> Result<[u8; 32]> {
    let h = sighash(
        tx,
        0,
        &Script::from_bytes(redeem.to_vec()),
        SigHashType::All,
        false,
    )
    .map_err(|e| SwapError::Other(format!("sighash: {e}")))?;
    Ok(*h.as_bytes())
}

/// This party's plain signature on `tx`'s 2-of-2 input (DER + SIGHASH_ALL byte).
pub fn sign_plain(tx: &Transaction, redeem: &[u8], key: &SecretKey) -> Result<Vec<u8>> {
    multisig::sign_input(tx, 0, &Script::from_bytes(redeem.to_vec()), key)
        .map_err(|e| SwapError::Other(format!("sign: {e}")))
}

/// Whether `sig` (DER + SIGHASH_ALL byte) is `pubkey`'s valid signature on `tx`'s input.
pub fn verify_plain(tx: &Transaction, redeem: &[u8], pubkey: &[u8; 33], sig: &[u8]) -> bool {
    let Some((&ty, der)) = sig.split_last() else {
        return false;
    };
    if ty != SigHashType::All as u8 {
        return false;
    }
    let (Ok(s), Ok(pk), Ok(h)) = (
        DiviSignature::from_der(der),
        PublicKey::from_bytes(pubkey),
        digest(tx, redeem),
    ) else {
        return false;
    };
    verify_hash(&pk, &s, &h)
}

/// Whether `enc` is `signer_pk`'s adaptor signature on `tx`'s input, encrypted under `enc_point`.
pub fn verify_encrypted(
    tx: &Transaction,
    redeem: &[u8],
    signer_pk: &[u8; 33],
    enc_point: &Point,
    enc: &EncryptedSignature,
) -> bool {
    let (Ok(vk), Ok(h)) = (point_of_pubkey(signer_pk), digest(tx, redeem)) else {
        return false;
    };
    AdaptorSigner::new().verify_encrypted_signature(&vk, enc_point, &h, enc)
}

/// Put both plain signatures into `tx`'s two-key input: `Tx_lock`'s redeem branch or
/// `Tx_cancel`'s refund branch (the same `OP_0 <a> <b> OP_1 <redeem>` layout).
pub fn assemble(
    mut tx: Transaction,
    redeem: &[u8],
    maker_sig: &[u8],
    taker_sig: &[u8],
) -> Transaction {
    tx.vin[0].script_sig = lock_scripts::redeem_sig(maker_sig, taker_sig, redeem);
    tx
}

/// The `who` signature in a broadcast two-key spend (`Tx_redeem` or `Tx_refund`), as a
/// `swap-adaptor` signature. Read by stack position from the top, so any push encoding a
/// staker re-wraps it in still parses.
pub fn signature_in(tx: &Transaction, who: Signer) -> Option<Signature> {
    // Stack, top last: [.., sig_maker, sig_taker, selector, redeem].
    let items = lock_scripts::stack_items(tx.vin.first()?.script_sig.as_bytes())?;
    let n = items.len();
    if n < 4 {
        return None;
    }
    let sig = &items[match who {
        Signer::Maker => n - 4,
        Signer::Taker => n - 3,
    }];
    let (_, der) = sig.split_last()?;
    let compact = DiviSignature::from_der(der).ok()?.to_compact();
    Signature::from_bytes(compact)
}

/// The secret a broadcast spend reveals: `who`'s completed signature in `tx` against the
/// encrypted one we hold, under `enc_point` (whose discrete log comes out), as ed25519.
pub fn recover(
    tx: &Transaction,
    who: Signer,
    enc_point: &Point,
    encrypted: &EncryptedSignature,
) -> Option<ScalarQ> {
    let completed = signature_in(tx, who)?;
    let s = recover_secret_from_chain(enc_point, &completed, encrypted)?;
    ed_of(&s)
}

/// Re-encode a two-key spend completed by `swap_templates` (`OP_0 <a> <b> <redeem>`) in the
/// branch layout every C1 script expects, `OP_0 <a> <b> OP_1 <redeem>`.
pub fn two_key(tx: Transaction, redeem: &[u8]) -> Result<Transaction> {
    let items = tx
        .vin
        .first()
        .and_then(|i| lock_scripts::stack_items(i.script_sig.as_bytes()));
    match items.as_deref() {
        Some([z, a, b, r]) if z.is_empty() && r.as_slice() == redeem => {
            let (a, b) = (a.clone(), b.clone());
            Ok(assemble(tx, redeem, &a, &b))
        }
        _ => Err(SwapError::Other("not a completed 2-of-2 spend".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_adaptor::dleq::random_clamped_secret;

    #[test]
    fn scalar_round_trip_between_curves() {
        let s = random_clamped_secret(&mut rand::thread_rng());
        assert_eq!(ed_of(&secp_of(&s)), Some(s));
        // The DLEQ's secp256k1 claim point is the adaptor encryption key of that scalar.
        let (_, (p, q)) = crate::nums::dleq().prove(&s, &mut rand::thread_rng());
        assert_eq!(AdaptorSigner::new().encryption_key_for(&secp_of(&s)), p);
        assert_eq!(ed_pub(&s), q);
    }
}
