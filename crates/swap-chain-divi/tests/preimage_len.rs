// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! F3: the HTLC claim branch run under the real DIVI interpreter with preimages of every length.
//! The redeem script is the same bytes on DIVI, BTC, LTC and ZEC (`HtlcParams::redeem_script_v`).

use divi_primitives::script::Script;
use divi_script::error::ScriptFlags;
use divi_script::interpreter::{verify_script, SignatureChecker};
use divi_swap::htlc::{push_data, ScriptVersion, OP_1};
use divi_swap::HtlcParams;
use sha2::{Digest, Sha256};
use swap_chain_divi::htlc_script_pubkey_v;

struct AcceptAll;
impl SignatureChecker for AcceptAll {
    fn check_sig(&self, _: &[u8], _: &[u8], _: &Script) -> bool {
        true
    }
    fn check_lock_time(&self, _: i64) -> bool {
        true
    }
    fn check_sequence(&self, _: i64) -> bool {
        true
    }
}

fn params(preimage: &[u8]) -> HtlcParams {
    HtlcParams {
        hash: Sha256::digest(preimage).into(),
        claim_pubkey: [2; 33],
        refund_pubkey: [3; 33],
        locktime: 1_900_000_000,
    }
}

/// Run the claim branch with `preimage` pushed as-is; `true` when the script accepts.
fn claims(version: ScriptVersion, preimage: &[u8]) -> bool {
    let h = params(preimage);
    let mut sig = Vec::new();
    push_data(&mut sig, &[0x30; 9]);
    push_data(&mut sig, preimage);
    sig.push(OP_1);
    push_data(&mut sig, &h.redeem_script_v(version));
    verify_script(
        &Script::from_bytes(sig),
        &htlc_script_pubkey_v(&h, version),
        ScriptFlags::standard(),
        &AcceptAll,
    )
    .is_ok()
}

#[test]
fn v1_claims_only_with_a_32_byte_preimage() {
    assert!(claims(ScriptVersion::V1, &[7; 32]));
    for n in [0usize, 1, 31, 33, 64, 80, 81, 520] {
        assert!(
            !claims(ScriptVersion::V1, &vec![7; n]),
            "V1 accepted {n} bytes"
        );
    }
}

/// The exploit this lane closes: the in-flight (V0) script claims with any length.
/// Kept so the old-record behaviour is stated, not forgotten.
#[test]
fn v0_in_flight_script_accepts_any_length() {
    for n in [31usize, 32, 33, 81, 520] {
        assert!(
            claims(ScriptVersion::V0, &vec![7; n]),
            "V0 refused {n} bytes"
        );
    }
}

#[test]
fn v1_refund_branch_still_works() {
    let h = params(&[7; 32]);
    let mut sig = Vec::new();
    push_data(&mut sig, &[0x30; 9]);
    sig.push(0x00);
    push_data(&mut sig, &h.redeem_script_v(ScriptVersion::V1));
    verify_script(
        &Script::from_bytes(sig),
        &htlc_script_pubkey_v(&h, ScriptVersion::V1),
        ScriptFlags::standard(),
        &AcceptAll,
    )
    .expect("refund");
}
