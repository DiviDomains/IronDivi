// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::transaction::{Transaction, TxOut};
use divi_script::verify_input;
use divi_swap::htlc::REFUND_SEQUENCE;

use crate::multisig::{
    build_presigned_spend, redeem_script, script_pubkey, test_outpoint, MultisigError,
};

const KEY_A: [u8; 32] = [0x11; 32];
const KEY_B: [u8; 32] = [0x22; 32];
const KEY_WRONG: [u8; 32] = [0x33; 32];

fn keys() -> (SecretKey, SecretKey) {
    (
        SecretKey::from_bytes(&KEY_A).unwrap(),
        SecretKey::from_bytes(&KEY_B).unwrap(),
    )
}

fn redeem() -> Vec<u8> {
    let (a, b) = keys();
    redeem_script(
        &a.public_key().serialize_compressed(),
        &b.public_key().serialize_compressed(),
    )
}

fn payout() -> TxOut {
    TxOut::new(
        Amount::from_sat(9_000),
        divi_primitives::script::Script::new_p2pkh(&[7u8; 20]),
    )
}

/// The core skeleton claim: a 2-of-2 P2SH spend signed by both parties verifies against
/// the real (reimplemented) DIVI script interpreter, the same mock-consensus check
/// `swap-chain-btc` runs via libbitcoinconsensus (`tx.rs` module docs there) — just backed
/// by `divi-script` instead, since there is no libdiviconsensus binding.
#[test]
fn multisig_spend_verifies() {
    let (a, b) = keys();
    let redeem = redeem();
    let spk = script_pubkey(&redeem);

    let tx = build_presigned_spend(
        test_outpoint(1),
        Amount::from_sat(10_000),
        &redeem,
        &a,
        &b,
        payout(),
        0,
        REFUND_SEQUENCE,
    )
    .unwrap();

    verify_input(&tx, 0, &spk, Amount::from_sat(10_000)).unwrap();
}

/// Signature order must match pubkey order in the redeem script — this is standard
/// `OP_CHECKMULTISIG` behaviour, not specific to this skeleton, but worth pinning since
/// `xmr-design.md` depends on it (Maker/Taker signatures are never interchangeable).
#[test]
fn multisig_spend_fails_with_swapped_signature_order() {
    let (a, b) = keys();
    let redeem = redeem();
    let spk = script_pubkey(&redeem);

    // Sign with the keys swapped, so script_sig carries B's sig first, A's second --
    // CHECKMULTISIG tries sig[0] against pubkey_a first, and B's sig won't satisfy it.
    let tx = build_presigned_spend(
        test_outpoint(1),
        Amount::from_sat(10_000),
        &redeem,
        &b,
        &a,
        payout(),
        0,
        REFUND_SEQUENCE,
    )
    .unwrap();

    assert!(verify_input(&tx, 0, &spk, Amount::from_sat(10_000)).is_err());
}

/// A signature from a key that isn't one of the two in the redeem script must not let the
/// spend through, no matter which slot it's placed in.
#[test]
fn multisig_spend_fails_with_unrelated_key() {
    let (a, _b) = keys();
    let wrong = SecretKey::from_bytes(&KEY_WRONG).unwrap();
    let redeem = redeem();
    let spk = script_pubkey(&redeem);

    let tx = build_presigned_spend(
        test_outpoint(1),
        Amount::from_sat(10_000),
        &redeem,
        &a,
        &wrong,
        payout(),
        0,
        REFUND_SEQUENCE,
    )
    .unwrap();

    assert!(verify_input(&tx, 0, &spk, Amount::from_sat(10_000)).is_err());
}

/// The `nLockTime` schedule `xmr-design.md`'s `## Protocol`/`## DIVI scripts` relies on
/// instead of CSV/CLTV: a presigned spend with a future `nLockTime` and a non-final input
/// cannot be mined yet.
#[test]
fn presigned_spend_is_not_final_before_locktime() {
    let (a, b) = keys();
    let redeem = redeem();
    const T_CANCEL: u32 = 2_000_000_000;

    let tx = build_presigned_spend(
        test_outpoint(2),
        Amount::from_sat(10_000),
        &redeem,
        &a,
        &b,
        payout(),
        T_CANCEL,
        REFUND_SEQUENCE,
    )
    .unwrap();

    assert!(!tx.is_final(0, T_CANCEL - 1));
}

/// ...and is minable once the schedule's deadline has passed, with no opcode involved.
#[test]
fn presigned_spend_is_final_after_locktime() {
    let (a, b) = keys();
    let redeem = redeem();
    const T_CANCEL: u32 = 2_000_000_000;

    let tx = build_presigned_spend(
        test_outpoint(2),
        Amount::from_sat(10_000),
        &redeem,
        &a,
        &b,
        payout(),
        T_CANCEL,
        REFUND_SEQUENCE,
    )
    .unwrap();

    assert!(tx.is_final(0, T_CANCEL + 1));
}

/// `lock_time = 0` (used for `Tx_redeem`, which has no schedule of its own in the design)
/// must be final immediately, same as any ordinary DIVI transaction.
#[test]
fn zero_locktime_spend_is_always_final() {
    let (a, b) = keys();
    let redeem = redeem();

    let tx = build_presigned_spend(
        test_outpoint(3),
        Amount::from_sat(10_000),
        &redeem,
        &a,
        &b,
        payout(),
        0,
        REFUND_SEQUENCE,
    )
    .unwrap();

    assert!(tx.is_final(0, 0));
}

/// `sign_input`/`build_presigned_spend` surface a typed error rather than panicking on a
/// malformed input index.
#[test]
fn sign_input_rejects_out_of_range_index() {
    let (a, _) = keys();
    let redeem = divi_primitives::script::Script::from_bytes(redeem());
    let tx = Transaction::new();
    let err = crate::multisig::sign_input(&tx, 0, &redeem, &a).unwrap_err();
    assert!(matches!(err, MultisigError::Sighash(_)));
}
