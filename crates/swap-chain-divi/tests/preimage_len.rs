// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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
        script_version: Default::default(),
    }
}

/// Minimal valid BIP66 low-S DER ECDSA signature (`r = 1, s = 1`) + `SIGHASH_ALL` (`0x01`),
/// required because `ScriptFlags::standard()` enforces `DERSIG` / `STRICTENC` / `LOW_S`
/// before calling `SignatureChecker::check_sig`.
const DUMMY_DER_SIG: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];

/// Run the claim branch with `preimage` pushed as-is; `true` when the script accepts.
fn claims(version: ScriptVersion, preimage: &[u8]) -> bool {
    let h = params(preimage);
    let mut sig = Vec::new();
    push_data(&mut sig, DUMMY_DER_SIG);
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
    push_data(&mut sig, DUMMY_DER_SIG);
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

/// The params exactly as the maker now builds them (`script_version: V1`), through the
/// version-free entry points the backend calls: 31/32/33 bytes.
#[test]
fn maker_built_v1_params_claim_only_32_bytes() {
    for (n, ok) in [(31usize, false), (32, true), (33, false)] {
        let pre = vec![7u8; n];
        let h = HtlcParams {
            script_version: ScriptVersion::V1,
            ..params(&pre)
        };
        assert_eq!(h.redeem_script().len(), 118);
        let mut sig = Vec::new();
        push_data(&mut sig, DUMMY_DER_SIG);
        push_data(&mut sig, &pre);
        sig.push(OP_1);
        push_data(&mut sig, &h.redeem_script());
        let r = verify_script(
            &Script::from_bytes(sig),
            &swap_chain_divi::htlc_script_pubkey(&h),
            ScriptFlags::standard(),
            &AcceptAll,
        );
        assert_eq!(r.is_ok(), ok, "{n} bytes");
    }
}
