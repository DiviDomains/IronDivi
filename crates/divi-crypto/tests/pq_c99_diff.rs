// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Cross-FFI Differential Test Harness between the Self-Contained C99 Reference PQ
//! Implementation (`crates/divi-crypto/c99_ref/divi_pqcrypto.{h,c}`) and Pure-Rust
//! `divi_crypto::pq` (`DIP-PQ-1`, Track 7C Phase 1 `P1.3c`).
//!
//! Proves:
//! 1. `c99_ref/divi_pqcrypto.{h,c}` contains zero floating-point tokens (`float`/`double`),
//!    zero external library includes, and compiles cleanly with `cc -std=c99 -O2 -fno-fast-math
//!    -Wall -Wextra -Werror`.
//! 2. `100%` bit-for-bit parity between C99 and Rust across all positive vectors and all 17
//!    adversarial negative vectors in `crates/divi-crypto/tests/vectors/pq_dip_pq_1.json`.
//! 3. `10,000+` randomized / mutated differential fuzz iterations across key hashing,
//!    domain-separated `SHA-512` prehashing, `HMAC-SHA512` / `SHAKE256` BIP39 -> PQ HD
//!    derivation, canonical `ML-DSA-44` / `FN-DSA-512` / `SLH-DSA-128s` / `LMS-SHA256-M32-H10`
//!    encoding validators, and `LMS-SHA256-M32-H10` signature verification where C99 and Rust
//!    agree `100%` of the time.

use std::collections::BTreeMap;
use std::process::Command;

use divi_crypto::pq::{
    compute_pq_signing_prehash_with_pk_hash, derive_pq_leaf, derive_pq_master, hmac_sha512,
    pq_address_key_hash_256, pq_key_hash_256, verify_lms_prehash, verify_lms_with_domain,
    PqDomainTag, PqError, PqSchemeId, Shake256Xof,
};
use divi_crypto::sha256;

const PQ_DIP_PQ_1_JSON: &str = include_str!("vectors/pq_dip_pq_1.json");
const C99_HEADER_SRC: &str = include_str!("../c99_ref/divi_pqcrypto.h");
const C99_IMPL_SRC: &str = include_str!("../c99_ref/divi_pqcrypto.c");

// ============================================================================
// C99 Reference FFI Bindings (linked via build.rs `divi_pqcrypto_c99`)
// ============================================================================

const DIVI_PQ_OK: i32 = 0;
const DIVI_PQ_ERR_UNKNOWN_SCHEME_ID: i32 = -2;
const DIVI_PQ_ERR_NON_HARDENED_DERIVATION: i32 = -4;
const DIVI_PQ_ERR_INVALID_PUBKEY_LEN: i32 = -5;
const DIVI_PQ_ERR_INVALID_SIG_LEN: i32 = -6;
const DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN: i32 = -7;
const DIVI_PQ_ERR_NON_CANONICAL_PUBKEY: i32 = -8;
const DIVI_PQ_ERR_NON_CANONICAL_SIG: i32 = -9;
const DIVI_PQ_ERR_LMS_INVALID_TYPECODE: i32 = -10;
const DIVI_PQ_ERR_LMS_INVALID_LEAF_INDEX: i32 = -11;
const DIVI_PQ_ERR_LMS_NON_ZERO_RESERVED: i32 = -12;
const DIVI_PQ_ERR_VERIFICATION_FAILED: i32 = -13;
#[allow(dead_code)]
const DIVI_PQ_ERR_UNKNOWN_DOMAIN_TAG: i32 = -14;

extern "C" {
    fn divi_pq_sha256(data: *const u8, len: usize, out_hash: *mut u8);
    #[allow(dead_code)]
    fn divi_pq_sha512(data: *const u8, len: usize, out_hash: *mut u8);
    fn divi_pq_hmac_sha512(
        key: *const u8,
        key_len: usize,
        data: *const u8,
        data_len: usize,
        out_mac: *mut u8,
    );
    fn divi_pq_shake256(input: *const u8, input_len: usize, output: *mut u8, output_len: usize);

    fn divi_pq_key_hash_256(scheme_id: u8, pk: *const u8, pk_len: usize, out_hash: *mut u8);
    fn divi_pq_address_key_hash_256(scheme_id: u8, pk: *const u8, pk_len: usize, out_hash: *mut u8);
    fn divi_pq_signing_prehash(
        domain_tag: *const u8,
        domain_tag_len: usize,
        network_magic: *const u8,
        scheme_id: u8,
        pk_hash_256: *const u8,
        payload_hash_256: *const u8,
        out_prehash: *mut u8,
    );
    fn divi_pq_signing_prehash_var(
        domain_tag: *const u8,
        domain_tag_len: usize,
        network_magic: *const u8,
        scheme_id: u8,
        pk_hash_256: *const u8,
        ctx_payload: *const u8,
        ctx_payload_len: usize,
        out_prehash: *mut u8,
    );

    fn divi_pq_derive_master(bip39_seed: *const u8, out_k: *mut u8, out_c: *mut u8) -> i32;
    fn divi_pq_derive_child_raw(
        parent_k: *const u8,
        parent_c: *const u8,
        raw_child_index: u32,
        out_k: *mut u8,
        out_c: *mut u8,
    ) -> i32;
    fn divi_pq_derive_leaf(
        bip39_seed: *const u8,
        coin_type: u32,
        account: u32,
        scheme_id: u8,
        index: u32,
        out_k_leaf: *mut u8,
        out_c_leaf: *mut u8,
        out_keygen_stream: *mut u8,
        stream_len: usize,
    ) -> i32;

    fn divi_pq_scheme_is_valid(scheme_id: u8) -> i32;
    fn divi_pq_scheme_pubkey_len(scheme_id: u8) -> usize;
    fn divi_pq_scheme_sig_len(scheme_id: u8) -> usize;
    fn divi_pq_scheme_seed_len(scheme_id: u8) -> usize;
    fn divi_pq_scheme_allowed_in_domain(
        scheme_id: u8,
        domain_tag: *const u8,
        domain_tag_len: usize,
    ) -> i32;
    fn divi_pq_validate_pubkey_encoding(scheme_id: u8, pk: *const u8, pk_len: usize) -> i32;
    fn divi_pq_validate_sig_encoding(scheme_id: u8, sig: *const u8, sig_len: usize) -> i32;

    fn divi_pq_lms_m32_h10_verify(
        pk: *const u8,
        pk_len: usize,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
        sig_len: usize,
    ) -> i32;
    fn divi_pq_lms_m32_h10_verify_with_domain(
        domain_tag: *const u8,
        domain_tag_len: usize,
        network_magic: *const u8,
        pk: *const u8,
        pk_len: usize,
        ctx_payload: *const u8,
        ctx_payload_len: usize,
        sig: *const u8,
        sig_len: usize,
    ) -> i32;
}

// ============================================================================
// Safe Rust Wrappers around C99 FFI Calls
// ============================================================================

fn c99_key_hash_256(scheme_id: u8, pk: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        divi_pq_key_hash_256(scheme_id, pk.as_ptr(), pk.len(), out.as_mut_ptr());
    }
    out
}

fn c99_address_key_hash_256(scheme_id: u8, pk: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        divi_pq_address_key_hash_256(scheme_id, pk.as_ptr(), pk.len(), out.as_mut_ptr());
    }
    out
}

fn c99_signing_prehash_32(
    domain_tag: &str,
    network_magic: [u8; 4],
    scheme_id: u8,
    pk_hash_256: &[u8; 32],
    payload_hash_256: &[u8; 32],
) -> [u8; 64] {
    let mut out = [0u8; 64];
    unsafe {
        divi_pq_signing_prehash(
            domain_tag.as_bytes().as_ptr(),
            domain_tag.len(),
            network_magic.as_ptr(),
            scheme_id,
            pk_hash_256.as_ptr(),
            payload_hash_256.as_ptr(),
            out.as_mut_ptr(),
        );
    }
    out
}

fn c99_signing_prehash_var(
    domain_tag: &str,
    network_magic: [u8; 4],
    scheme_id: u8,
    pk_hash_256: &[u8; 32],
    ctx_payload: &[u8],
) -> [u8; 64] {
    let mut out = [0u8; 64];
    unsafe {
        divi_pq_signing_prehash_var(
            domain_tag.as_bytes().as_ptr(),
            domain_tag.len(),
            network_magic.as_ptr(),
            scheme_id,
            pk_hash_256.as_ptr(),
            ctx_payload.as_ptr(),
            ctx_payload.len(),
            out.as_mut_ptr(),
        );
    }
    out
}

fn c99_derive_master(bip39_seed: &[u8; 64]) -> (i32, [u8; 32], [u8; 32]) {
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    let rc = unsafe { divi_pq_derive_master(bip39_seed.as_ptr(), k.as_mut_ptr(), c.as_mut_ptr()) };
    (rc, k, c)
}

fn c99_derive_child_raw(
    parent_k: &[u8; 32],
    parent_c: &[u8; 32],
    raw_idx: u32,
) -> (i32, [u8; 32], [u8; 32]) {
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    let rc = unsafe {
        divi_pq_derive_child_raw(
            parent_k.as_ptr(),
            parent_c.as_ptr(),
            raw_idx,
            k.as_mut_ptr(),
            c.as_mut_ptr(),
        )
    };
    (rc, k, c)
}

fn c99_derive_leaf(
    bip39_seed: &[u8; 64],
    coin_type: u32,
    account: u32,
    scheme_id: u8,
    index: u32,
    stream_len: usize,
) -> (i32, [u8; 32], [u8; 32], Vec<u8>) {
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    let mut stream = vec![0u8; stream_len];
    let rc = unsafe {
        divi_pq_derive_leaf(
            bip39_seed.as_ptr(),
            coin_type,
            account,
            scheme_id,
            index,
            k.as_mut_ptr(),
            c.as_mut_ptr(),
            stream.as_mut_ptr(),
            stream_len,
        )
    };
    (rc, k, c, stream)
}

fn c99_lms_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> i32 {
    unsafe {
        divi_pq_lms_m32_h10_verify(
            pk.as_ptr(),
            pk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        )
    }
}

fn c99_lms_verify_with_domain(
    domain_tag: &str,
    network_magic: [u8; 4],
    pk: &[u8],
    ctx_payload: &[u8],
    sig: &[u8],
) -> i32 {
    unsafe {
        divi_pq_lms_m32_h10_verify_with_domain(
            domain_tag.as_bytes().as_ptr(),
            domain_tag.len(),
            network_magic.as_ptr(),
            pk.as_ptr(),
            pk.len(),
            ctx_payload.as_ptr(),
            ctx_payload.len(),
            sig.as_ptr(),
            sig.len(),
        )
    }
}

/// Map a Rust `Result<(), PqError>` from `verify_lms_prehash` / `verify_lms_with_domain` to the
/// exact C99 error category so we can assert both boolean agreement and specific error-class parity.
fn map_rust_lms_result_to_c99_code(res: &Result<(), PqError>) -> &'static [i32] {
    match res {
        Ok(()) => &[DIVI_PQ_OK],
        Err(PqError::InvalidPublicKeyLength { .. }) => &[DIVI_PQ_ERR_INVALID_PUBKEY_LEN],
        Err(PqError::InvalidSignatureLength { .. }) => &[DIVI_PQ_ERR_INVALID_SIG_LEN],
        Err(PqError::SchemeForbiddenInDomain { .. }) => &[DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN],
        Err(PqError::NonCanonicalPublicKey { reason, .. }) => {
            if reason.contains("typecode") {
                &[DIVI_PQ_ERR_LMS_INVALID_TYPECODE]
            } else if reason.contains("reserved") {
                &[DIVI_PQ_ERR_LMS_NON_ZERO_RESERVED]
            } else {
                &[DIVI_PQ_ERR_NON_CANONICAL_PUBKEY]
            }
        }
        Err(PqError::NonCanonicalSignature { reason, .. }) => {
            if reason.contains("leaf index") {
                &[DIVI_PQ_ERR_LMS_INVALID_LEAF_INDEX]
            } else if reason.contains("typecode") {
                &[DIVI_PQ_ERR_LMS_INVALID_TYPECODE]
            } else if reason.contains("reserved") {
                &[DIVI_PQ_ERR_LMS_NON_ZERO_RESERVED]
            } else {
                &[DIVI_PQ_ERR_NON_CANONICAL_SIG]
            }
        }
        Err(PqError::VerificationFailed) => &[DIVI_PQ_ERR_VERIFICATION_FAILED],
        Err(PqError::UnknownSchemeId(_)) => &[DIVI_PQ_ERR_UNKNOWN_SCHEME_ID],
        Err(PqError::NonHardenedPqDerivationForbidden(_)) => &[DIVI_PQ_ERR_NON_HARDENED_DERIVATION],
        Err(_) => &[-999],
    }
}

// ============================================================================
// Self-Contained JSON Parser & Deterministic SplitMix64 PRNG
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    Str(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    fn get(&self, key: &str) -> &JsonValue {
        match self {
            JsonValue::Object(map) => map
                .get(key)
                .unwrap_or_else(|| panic!("missing JSON key `{key}`")),
            _ => panic!("expected JSON object when looking up `{key}`"),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            JsonValue::Str(s) => s.as_str(),
            _ => panic!("expected JSON string, got {self:?}"),
        }
    }

    fn as_u64(&self) -> u64 {
        match self {
            JsonValue::Number(n) => *n,
            _ => panic!("expected JSON number, got {self:?}"),
        }
    }

    fn as_u32(&self) -> u32 {
        u32::try_from(self.as_u64()).expect("JSON number out of u32 range")
    }

    fn as_u8(&self) -> u8 {
        u8::try_from(self.as_u64()).expect("JSON number out of u8 range")
    }

    fn as_usize(&self) -> usize {
        usize::try_from(self.as_u64()).expect("JSON number out of usize range")
    }

    fn as_array(&self) -> &[JsonValue] {
        match self {
            JsonValue::Array(arr) => arr.as_slice(),
            _ => panic!("expected JSON array, got {self:?}"),
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn parse(input: &'a str) -> JsonValue {
        let mut parser = Self {
            bytes: input.as_bytes(),
            pos: 0,
        };
        let value = parser.parse_value();
        parser.skip_ws();
        assert_eq!(parser.pos, parser.bytes.len());
        value
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> u8 {
        self.bytes[self.pos]
    }

    fn next_byte(&mut self) -> u8 {
        let b = self.peek();
        self.pos += 1;
        b
    }

    fn expect_byte(&mut self, expected: u8) {
        self.skip_ws();
        let actual = self.next_byte();
        assert_eq!(actual, expected);
    }

    fn parse_value(&mut self) -> JsonValue {
        self.skip_ws();
        match self.peek() {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => JsonValue::Str(self.parse_string()),
            b't' => {
                self.pos += 4;
                JsonValue::Bool(true)
            }
            b'f' => {
                self.pos += 5;
                JsonValue::Bool(false)
            }
            b'n' => {
                self.pos += 4;
                JsonValue::Null
            }
            b'0'..=b'9' => self.parse_number(),
            other => panic!("unexpected JSON byte `{}`", other as char),
        }
    }

    fn parse_object(&mut self) -> JsonValue {
        self.expect_byte(b'{');
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == b'}' {
            self.pos += 1;
            return JsonValue::Object(map);
        }
        loop {
            self.skip_ws();
            let key = self.parse_string();
            self.expect_byte(b':');
            let val = self.parse_value();
            map.insert(key, val);
            self.skip_ws();
            match self.next_byte() {
                b',' => continue,
                b'}' => break,
                other => panic!("unexpected `{}` in object", other as char),
            }
        }
        JsonValue::Object(map)
    }

    fn parse_array(&mut self) -> JsonValue {
        self.expect_byte(b'[');
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == b']' {
            self.pos += 1;
            return JsonValue::Array(items);
        }
        loop {
            items.push(self.parse_value());
            self.skip_ws();
            match self.next_byte() {
                b',' => continue,
                b']' => break,
                other => panic!("unexpected `{}` in array", other as char),
            }
        }
        JsonValue::Array(items)
    }

    fn parse_string(&mut self) -> String {
        self.expect_byte(b'"');
        let mut out = String::new();
        loop {
            let b = self.next_byte();
            match b {
                b'"' => break,
                b'\\' => {
                    let esc = self.next_byte();
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        other => panic!("unsupported escape `\\{}`", other as char),
                    }
                }
                other => out.push(other as char),
            }
        }
        out
    }

    fn parse_number(&mut self) -> JsonValue {
        let start = self.pos;
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
        JsonValue::Number(s.parse().unwrap())
    }
}

fn decode_hex_array<const N: usize>(hex_str: &str) -> [u8; N] {
    let bytes = hex::decode(hex_str).expect("valid hex string");
    assert_eq!(bytes.len(), N);
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    arr
}

/// Deterministic `SplitMix64` PRNG for reproducible 10,000+ differential fuzz iterations.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let w = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&w[..chunk.len()]);
        }
    }
}

// ============================================================================
// 1. Static Source & Strict C99 Compiler Gate (-std=c99 -O2 -fno-fast-math -Werror)
// ============================================================================

#[test]
fn test_c99_ref_zero_floating_point_and_strict_c99_compiler_gate() {
    // Verify zero floating-point tokens in code lines (excluding comments)
    for (filename, src) in [
        ("divi_pqcrypto.h", C99_HEADER_SRC),
        ("divi_pqcrypto.c", C99_IMPL_SRC),
    ] {
        for (line_no, raw_line) in src.lines().enumerate() {
            let trimmed = raw_line.trim();
            if trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.starts_with("//") {
                continue;
            }
            let code_part = trimmed.split("/*").next().unwrap_or(trimmed);
            for forbidden in ["float", "double", "long double"] {
                assert!(
                    !code_part
                        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .any(|tok| tok == forbidden),
                    "{filename}:{} contains forbidden floating-point type `{forbidden}`",
                    line_no + 1
                );
            }
        }
    }

    // Also invoke `cc -std=c99 -O2 -fno-fast-math -Wall -Wextra -Werror -c` directly at test
    // runtime to prove standalone C99 compilation without any Cargo/Rust wrapper headers.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let c_path = format!("{manifest_dir}/c99_ref/divi_pqcrypto.c");
    let include_dir = format!("{manifest_dir}/c99_ref");
    let out_obj =
        std::env::temp_dir().join(format!("divi_pqcrypto_c99_check_{}.o", std::process::id()));

    let cc_bin = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let output = Command::new(&cc_bin)
        .args([
            "-std=c99",
            "-O2",
            "-fno-fast-math",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            &include_dir,
            "-c",
            &c_path,
            "-o",
        ])
        .arg(&out_obj)
        .output()
        .expect("failed to invoke C99 compiler `cc`");

    let _ = std::fs::remove_file(&out_obj);
    assert!(
        output.status.success(),
        "`{cc_bin} -std=c99 -O2 -fno-fast-math -Wall -Wextra -Werror` failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// ============================================================================
// 2. Canonical JSON Vector Suite 100% C99-vs-Rust Differential Parity
// ============================================================================

#[test]
fn test_c99_vs_rust_json_positive_vectors_1_through_4_parity() {
    let root = JsonParser::parse(PQ_DIP_PQ_1_JSON);

    // --- Vector 1: Key Hashes (0x01 .. 0x04) ---
    for entry in root.get("vector_1_key_hashes").as_array() {
        let id = entry.get("id").as_str();
        let scheme_byte = entry.get("scheme_id").as_u8();
        let scheme = PqSchemeId::from_byte(scheme_byte).unwrap();
        let pubkey_bytes = hex::decode(entry.get("pubkey_hex").as_str()).unwrap();

        assert_eq!(unsafe { divi_pq_scheme_is_valid(scheme_byte) }, 1);
        assert_eq!(
            unsafe { divi_pq_scheme_pubkey_len(scheme_byte) },
            scheme.pubkey_len()
        );
        assert_eq!(
            unsafe { divi_pq_scheme_sig_len(scheme_byte) },
            scheme.signature_len()
        );
        assert_eq!(
            unsafe { divi_pq_scheme_seed_len(scheme_byte) },
            scheme.keygen_seed_len()
        );

        let rust_enc = scheme.validate_pubkey_encoding(&pubkey_bytes);
        let c99_enc = unsafe {
            divi_pq_validate_pubkey_encoding(scheme_byte, pubkey_bytes.as_ptr(), pubkey_bytes.len())
        };
        assert!(rust_enc.is_ok());
        assert_eq!(c99_enc, DIVI_PQ_OK, "{id}: C99 pubkey encoding check");

        let rust_kh = pq_key_hash_256(scheme, &pubkey_bytes);
        let c99_kh = c99_key_hash_256(scheme_byte, &pubkey_bytes);
        assert_eq!(c99_kh, rust_kh, "{id}: C99 vs Rust pq_key_hash_256");
        assert_eq!(
            hex::encode(c99_kh),
            entry.get("pq_key_hash_256_hex").as_str()
        );

        let rust_ah = pq_address_key_hash_256(scheme, &pubkey_bytes);
        let c99_ah = c99_address_key_hash_256(scheme_byte, &pubkey_bytes);
        assert_eq!(c99_ah, rust_ah, "{id}: C99 vs Rust pq_address_key_hash_256");
        assert_eq!(
            hex::encode(c99_ah),
            entry.get("pq_address_key_hash_256_hex").as_str()
        );
    }

    // --- Vector 2: BIP39 -> PQ HD Master & Leaf Derivation ---
    let hd = root.get("vector_2_hd_derivation");
    let bip39_seed: [u8; 64] = decode_hex_array(hd.get("bip39_seed_hex").as_str());
    let rust_master = derive_pq_master(&bip39_seed).unwrap();
    let (c_rc, c_k_master, c_c_master) = c99_derive_master(&bip39_seed);
    assert_eq!(c_rc, DIVI_PQ_OK);
    assert_eq!(&c_k_master, rust_master.key_bytes());
    assert_eq!(&c_c_master, rust_master.chain_code_bytes());

    for entry in hd.get("leaves").as_array() {
        let id = entry.get("id").as_str();
        let coin_type = entry.get("coin_type").as_u32();
        let account = entry.get("account").as_u32();
        let scheme_byte = entry.get("scheme_id").as_u8();
        let scheme = PqSchemeId::from_byte(scheme_byte).unwrap();
        let index = entry.get("index").as_u32();

        let rust_leaf = derive_pq_leaf(&bip39_seed, coin_type, account, scheme, index).unwrap();
        let (rc, c_k_leaf, c_c_leaf, c_stream_64) =
            c99_derive_leaf(&bip39_seed, coin_type, account, scheme_byte, index, 64);
        assert_eq!(rc, DIVI_PQ_OK, "{id}: C99 derive_leaf status");
        assert_eq!(&c_k_leaf, rust_leaf.k_leaf(), "{id}: k_leaf C99 vs Rust");
        assert_eq!(&c_c_leaf, rust_leaf.c_leaf(), "{id}: c_leaf C99 vs Rust");
        assert_eq!(
            c_stream_64.as_slice(),
            rust_leaf.keygen_stream_64(),
            "{id}: keygen_stream_64 C99 vs Rust"
        );
        let seed_len = scheme.keygen_seed_len();
        assert_eq!(
            &c_stream_64[..seed_len],
            rust_leaf.algorithm_seed(),
            "{id}: algorithm_seed C99 vs Rust"
        );
    }

    // --- Vector 3: Domain-Separated Signing Prehashes ---
    for entry in root.get("vector_3_signing_prehashes").as_array() {
        let id = entry.get("id").as_str();
        let domain_tag_str = entry.get("domain_tag").as_str();
        let domain_tag = PqDomainTag::from_tag(domain_tag_str).unwrap();
        let network_magic: [u8; 4] = decode_hex_array(entry.get("network_magic_hex").as_str());
        let scheme_byte = entry.get("scheme_id").as_u8();
        let scheme = PqSchemeId::from_byte(scheme_byte).unwrap();
        let pk_hash256: [u8; 32] = decode_hex_array(entry.get("pk_hash256_hex").as_str());
        let ctx_payload = hex::decode(entry.get("ctx_payload_hex").as_str()).unwrap();

        let rust_prehash = compute_pq_signing_prehash_with_pk_hash(
            domain_tag,
            network_magic,
            scheme,
            &pk_hash256,
            &ctx_payload,
        );
        let c99_prehash = c99_signing_prehash_var(
            domain_tag_str,
            network_magic,
            scheme_byte,
            &pk_hash256,
            &ctx_payload,
        );
        assert_eq!(c99_prehash, rust_prehash, "{id}: C99 vs Rust prehash");

        // When payload is 32 bytes (tx-input & coinstake-kernel), verify fixed 32-byte helper too
        if ctx_payload.len() == 32 {
            let mut payload_32 = [0u8; 32];
            payload_32.copy_from_slice(&ctx_payload);
            let c99_fixed = c99_signing_prehash_32(
                domain_tag_str,
                network_magic,
                scheme_byte,
                &pk_hash256,
                &payload_32,
            );
            assert_eq!(c99_fixed, rust_prehash, "{id}: C99 fixed-32 prehash");
        }
    }

    // --- Vector 4: LMS-SHA256-M32-H10 Verification (q=0 and q=1) ---
    let v4 = root.get("vector_4_lms_sha256_m32_h10");
    let pk = hex::decode(v4.get("public_key_hex").as_str()).unwrap();
    let prehash: [u8; 64] = decode_hex_array(v4.get("signing_prehash_hex").as_str());
    let network_magic: [u8; 4] = decode_hex_array(v4.get("network_magic_hex").as_str());
    let spork_payload = hex::decode(v4.get("spork_payload_hex").as_str()).unwrap();
    let sig_q0 = hex::decode(v4.get("sig_q0_hex").as_str()).unwrap();
    let sig_q1 = hex::decode(v4.get("sig_q1_hex").as_str()).unwrap();

    for (label, sig) in [("q=0", &sig_q0), ("q=1", &sig_q1)] {
        let rust_raw = verify_lms_prehash(&pk, &prehash, sig);
        let c99_raw = c99_lms_verify(&pk, &prehash, sig);
        assert!(rust_raw.is_ok(), "{label}: Rust raw verify");
        assert_eq!(c99_raw, DIVI_PQ_OK, "{label}: C99 raw verify");

        let rust_dom = verify_lms_with_domain(
            PqDomainTag::SporkV1,
            network_magic,
            &pk,
            &spork_payload,
            sig,
        );
        let c99_dom =
            c99_lms_verify_with_domain("Divi-PQ-Spork-v1", network_magic, &pk, &spork_payload, sig);
        assert!(rust_dom.is_ok(), "{label}: Rust domain verify");
        assert_eq!(c99_dom, DIVI_PQ_OK, "{label}: C99 domain verify");
    }

    // Also verify SHA-256 of sig_q0 and sig_q1 via C99 divi_pq_sha256
    for (sig, expected_sha_key) in [
        (&sig_q0, "sig_q0_sha256_hex"),
        (&sig_q1, "sig_q1_sha256_hex"),
    ] {
        let mut c_sha = [0u8; 32];
        unsafe {
            divi_pq_sha256(sig.as_ptr(), sig.len(), c_sha.as_mut_ptr());
        }
        assert_eq!(c_sha, sha256(sig));
        assert_eq!(hex::encode(c_sha), v4.get(expected_sha_key).as_str());
    }
}

#[test]
fn test_c99_vs_rust_json_all_17_adversarial_negative_vectors_parity() {
    let root = JsonParser::parse(PQ_DIP_PQ_1_JSON);
    let hd = root.get("vector_2_hd_derivation");
    let bip39_seed: [u8; 64] = decode_hex_array(hd.get("bip39_seed_hex").as_str());
    let rust_master = derive_pq_master(&bip39_seed).unwrap();
    let (_, c_master_k, c_master_c) = c99_derive_master(&bip39_seed);

    let v4 = root.get("vector_4_lms_sha256_m32_h10");
    let valid_pk = hex::decode(v4.get("public_key_hex").as_str()).unwrap();
    let valid_sig = hex::decode(v4.get("sig_q0_hex").as_str()).unwrap();
    let valid_magic: [u8; 4] = decode_hex_array(v4.get("network_magic_hex").as_str());
    let valid_payload = hex::decode(v4.get("spork_payload_hex").as_str()).unwrap();

    let negatives = root.get("negative_vectors").as_array();
    assert_eq!(
        negatives.len(),
        17,
        "Expected all 17 adversarial negative vectors"
    );

    for entry in negatives {
        let id = entry.get("id").as_str();
        let mutation = entry.get("mutation").as_str();
        let expected_error = entry.get("expected_error").as_str();

        match mutation {
            "append_sig_hex" => {
                let extra = hex::decode(entry.get("append_hex").as_str()).unwrap();
                let mut mutated_sig = valid_sig.clone();
                mutated_sig.extend_from_slice(&extra);

                let rust_res = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &valid_pk,
                    &valid_payload,
                    &mutated_sig,
                );
                let c99_rc = c99_lms_verify_with_domain(
                    "Divi-PQ-Spork-v1",
                    valid_magic,
                    &valid_pk,
                    &valid_payload,
                    &mutated_sig,
                );
                assert!(rust_res.is_err());
                assert_eq!(c99_rc, DIVI_PQ_ERR_INVALID_SIG_LEN);
                assert!(map_rust_lms_result_to_c99_code(&rust_res).contains(&c99_rc));
                assert_eq!(expected_error, "InvalidSignatureLength");
            }
            "append_pk_hex" => {
                let extra = hex::decode(entry.get("append_hex").as_str()).unwrap();
                let mut mutated_pk = valid_pk.clone();
                mutated_pk.extend_from_slice(&extra);

                let rust_res = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &mutated_pk,
                    &valid_payload,
                    &valid_sig,
                );
                let c99_rc = c99_lms_verify_with_domain(
                    "Divi-PQ-Spork-v1",
                    valid_magic,
                    &mutated_pk,
                    &valid_payload,
                    &valid_sig,
                );
                assert!(rust_res.is_err());
                assert_eq!(c99_rc, DIVI_PQ_ERR_INVALID_PUBKEY_LEN);
                assert!(map_rust_lms_result_to_c99_code(&rust_res).contains(&c99_rc));
                assert_eq!(expected_error, "InvalidPublicKeyLength");
            }
            "truncate_pk_len" => {
                let trunc_len = entry.get("truncate_len").as_usize();
                let mutated_pk = &valid_pk[..trunc_len];

                let rust_res = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    mutated_pk,
                    &valid_payload,
                    &valid_sig,
                );
                let c99_rc = c99_lms_verify_with_domain(
                    "Divi-PQ-Spork-v1",
                    valid_magic,
                    mutated_pk,
                    &valid_payload,
                    &valid_sig,
                );
                assert!(rust_res.is_err());
                assert_eq!(c99_rc, DIVI_PQ_ERR_INVALID_PUBKEY_LEN);
                assert!(map_rust_lms_result_to_c99_code(&rust_res).contains(&c99_rc));
                assert_eq!(expected_error, "InvalidPublicKeyLength");
            }
            "overwrite_pk_u32be" => {
                let offset = entry.get("byte_offset").as_usize();
                let val = entry.get("u32be_value").as_u32();
                let mut mutated_pk = valid_pk.clone();
                mutated_pk[offset..offset + 4].copy_from_slice(&val.to_be_bytes());

                let rust_res = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &mutated_pk,
                    &valid_payload,
                    &valid_sig,
                );
                let c99_rc = c99_lms_verify_with_domain(
                    "Divi-PQ-Spork-v1",
                    valid_magic,
                    &mutated_pk,
                    &valid_payload,
                    &valid_sig,
                );
                assert!(rust_res.is_err());
                assert_eq!(c99_rc, DIVI_PQ_ERR_LMS_INVALID_TYPECODE);
                assert!(
                    map_rust_lms_result_to_c99_code(&rust_res).contains(&c99_rc),
                    "{id}: rust={rust_res:?}, c99={c99_rc}"
                );
                assert_eq!(expected_error, "InvalidAlgorithmTypecode");
            }
            "overwrite_sig_u32be" => {
                let offset = entry.get("byte_offset").as_usize();
                let val = entry.get("u32be_value").as_u32();
                let mut mutated_sig = valid_sig.clone();
                mutated_sig[offset..offset + 4].copy_from_slice(&val.to_be_bytes());

                let rust_res = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &valid_pk,
                    &valid_payload,
                    &mutated_sig,
                );
                let c99_rc = c99_lms_verify_with_domain(
                    "Divi-PQ-Spork-v1",
                    valid_magic,
                    &valid_pk,
                    &valid_payload,
                    &mutated_sig,
                );
                assert!(rust_res.is_err());
                let expected_c99 = match expected_error {
                    "InvalidAlgorithmTypecode" => DIVI_PQ_ERR_LMS_INVALID_TYPECODE,
                    "InvalidLeafIndex" => DIVI_PQ_ERR_LMS_INVALID_LEAF_INDEX,
                    other => panic!("{id}: unexpected expected_error `{other}`"),
                };
                assert_eq!(c99_rc, expected_c99, "{id}: C99 code mismatch");
                assert!(
                    map_rust_lms_result_to_c99_code(&rust_res).contains(&c99_rc),
                    "{id}: rust={rust_res:?}, c99={c99_rc}"
                );
            }
            "xor_sig_byte" => {
                let offset = entry.get("byte_offset").as_usize();
                let mask = entry.get("xor_mask").as_u8();
                let mut mutated_sig = valid_sig.clone();
                mutated_sig[offset] ^= mask;

                let rust_res = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &valid_pk,
                    &valid_payload,
                    &mutated_sig,
                );
                let c99_rc = c99_lms_verify_with_domain(
                    "Divi-PQ-Spork-v1",
                    valid_magic,
                    &valid_pk,
                    &valid_payload,
                    &mutated_sig,
                );
                assert_eq!(rust_res, Err(PqError::VerificationFailed));
                assert_eq!(c99_rc, DIVI_PQ_ERR_VERIFICATION_FAILED);
                assert_eq!(expected_error, "VerificationFailed");
            }
            "domain_tag_mismatch" => {
                let wrong_tag_str = entry.get("verify_domain_tag").as_str();
                let wrong_domain = PqDomainTag::from_tag(wrong_tag_str).unwrap();
                let verify_magic: [u8; 4] =
                    decode_hex_array(entry.get("verify_network_magic_hex").as_str());

                let rust_res = verify_lms_with_domain(
                    wrong_domain,
                    verify_magic,
                    &valid_pk,
                    &valid_payload,
                    &valid_sig,
                );
                let c99_rc = c99_lms_verify_with_domain(
                    wrong_tag_str,
                    verify_magic,
                    &valid_pk,
                    &valid_payload,
                    &valid_sig,
                );
                assert!(matches!(
                    rust_res,
                    Err(PqError::SchemeForbiddenInDomain { .. })
                ));
                assert_eq!(c99_rc, DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN);

                // Also test raw prehash verification when signed under SporkV1 but hashed under TxSigV1
                let pk_hash = c99_key_hash_256(4, &valid_pk);
                let wrong_prehash = c99_signing_prehash_var(
                    wrong_tag_str,
                    verify_magic,
                    4,
                    &pk_hash,
                    &valid_payload,
                );
                assert_eq!(
                    verify_lms_prehash(&valid_pk, &wrong_prehash, &valid_sig),
                    Err(PqError::VerificationFailed)
                );
                assert_eq!(
                    c99_lms_verify(&valid_pk, &wrong_prehash, &valid_sig),
                    DIVI_PQ_ERR_VERIFICATION_FAILED
                );
            }
            "network_magic_mismatch" => {
                let verify_tag_str = entry.get("verify_domain_tag").as_str();
                let verify_domain = PqDomainTag::from_tag(verify_tag_str).unwrap();
                let wrong_magic: [u8; 4] =
                    decode_hex_array(entry.get("verify_network_magic_hex").as_str());

                let rust_res = verify_lms_with_domain(
                    verify_domain,
                    wrong_magic,
                    &valid_pk,
                    &valid_payload,
                    &valid_sig,
                );
                let c99_rc = c99_lms_verify_with_domain(
                    verify_tag_str,
                    wrong_magic,
                    &valid_pk,
                    &valid_payload,
                    &valid_sig,
                );
                assert_eq!(rust_res, Err(PqError::VerificationFailed));
                assert_eq!(c99_rc, DIVI_PQ_ERR_VERIFICATION_FAILED);
            }
            "unhardened_hd_index" => {
                let bad_leaf_idx = entry.get("leaf_index_u32").as_u32();
                let bad_raw_idx = entry.get("raw_child_index_u32").as_u32();

                let rust_leaf_res =
                    derive_pq_leaf(&bip39_seed, 301, 0, PqSchemeId::MlDsa44, bad_leaf_idx);
                let (c99_leaf_rc, _, _, _) =
                    c99_derive_leaf(&bip39_seed, 301, 0, 1, bad_leaf_idx, 64);
                assert_eq!(
                    rust_leaf_res,
                    Err(PqError::NonHardenedPqDerivationForbidden(bad_leaf_idx))
                );
                assert_eq!(c99_leaf_rc, DIVI_PQ_ERR_NON_HARDENED_DERIVATION);

                let rust_raw_res = rust_master.derive_child_raw(bad_raw_idx);
                let (c99_raw_rc, _, _) =
                    c99_derive_child_raw(&c_master_k, &c_master_c, bad_raw_idx);
                assert_eq!(
                    rust_raw_res,
                    Err(PqError::NonHardenedPqDerivationForbidden(bad_raw_idx))
                );
                assert_eq!(c99_raw_rc, DIVI_PQ_ERR_NON_HARDENED_DERIVATION);
            }
            "unknown_scheme_id" => {
                for val in entry.get("invalid_scheme_bytes").as_array() {
                    let b = val.as_u8();
                    assert_eq!(PqSchemeId::from_byte(b), Err(PqError::UnknownSchemeId(b)));
                    assert_eq!(unsafe { divi_pq_scheme_is_valid(b) }, 0);
                    let (c_rc, _, _, _) = c99_derive_leaf(&bip39_seed, 301, 0, b, 0, 64);
                    assert_eq!(c_rc, DIVI_PQ_ERR_UNKNOWN_SCHEME_ID);
                }
                let spork_only_byte = entry.get("spork_only_scheme_byte").as_u8();
                let spork_only = PqSchemeId::from_byte(spork_only_byte).unwrap();
                for dom_val in entry.get("forbidden_domains").as_array() {
                    let dom_str = dom_val.as_str();
                    let dom = PqDomainTag::from_tag(dom_str).unwrap();
                    assert!(!spork_only.is_allowed_in_domain(dom));
                    let c_dom_rc = unsafe {
                        divi_pq_scheme_allowed_in_domain(
                            spork_only_byte,
                            dom_str.as_bytes().as_ptr(),
                            dom_str.len(),
                        )
                    };
                    assert_eq!(c_dom_rc, DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN);
                }
            }
            other => panic!("{id}: unknown mutation `{other}`"),
        }
    }
}

// ============================================================================
// 3. 12,000+ Randomized / Mutated Differential Fuzz Iterations (C99 vs Rust)
// ============================================================================

#[test]
fn test_c99_vs_rust_12000_differential_fuzz_iterations() {
    let root = JsonParser::parse(PQ_DIP_PQ_1_JSON);
    let v4 = root.get("vector_4_lms_sha256_m32_h10");
    let valid_pk = hex::decode(v4.get("public_key_hex").as_str()).unwrap();
    let valid_sig_q0 = hex::decode(v4.get("sig_q0_hex").as_str()).unwrap();
    let valid_sig_q1 = hex::decode(v4.get("sig_q1_hex").as_str()).unwrap();
    let valid_prehash: [u8; 64] = decode_hex_array(v4.get("signing_prehash_hex").as_str());
    let valid_magic: [u8; 4] = decode_hex_array(v4.get("network_magic_hex").as_str());
    let valid_payload = hex::decode(v4.get("spork_payload_hex").as_str()).unwrap();

    let mut rng = SplitMix64::new(0x4449_5649_5051_3133); // "DIVIPQ13"
    let mut total_iterations = 0usize;

    // ------------------------------------------------------------------------
    // Fuzz Bank A (3,000 iterations): Key Hashing, SHA-256/512, HMAC-SHA512,
    // SHAKE256, and Domain-Separated Signing Prehashes across random lengths,
    // schemes, network magics, and payloads.
    // ------------------------------------------------------------------------
    let domain_tags = [
        ("Divi-PQ-TxSig-v1", PqDomainTag::TxSigV1),
        ("Divi-PQ-BlockSig-v1", PqDomainTag::BlockSigV1),
        ("Divi-PQ-Spork-v1", PqDomainTag::SporkV1),
    ];
    let schemes = [
        (1u8, PqSchemeId::MlDsa44),
        (2u8, PqSchemeId::FnDsa512),
        (3u8, PqSchemeId::SlhDsa128s),
        (4u8, PqSchemeId::LmsSha256M32H10),
    ];

    for iter in 0..3_000usize {
        let (scheme_byte, scheme) = schemes[iter % schemes.len()];
        let (tag_str, tag_enum) = domain_tags[(iter / 4) % domain_tags.len()];

        // Random public key buffer (0..1500 bytes, spanning multi-block SHA-256 boundaries)
        let pk_len = (rng.next_u32() as usize) % 1500;
        let mut pk_buf = vec![0u8; pk_len];
        rng.fill_bytes(&mut pk_buf);

        let rust_kh = pq_key_hash_256(scheme, &pk_buf);
        let c99_kh = c99_key_hash_256(scheme_byte, &pk_buf);
        assert_eq!(c99_kh, rust_kh, "Fuzz A iter {iter}: pq_key_hash_256");

        let rust_ah = pq_address_key_hash_256(scheme, &pk_buf);
        let c99_ah = c99_address_key_hash_256(scheme_byte, &pk_buf);
        assert_eq!(
            c99_ah, rust_ah,
            "Fuzz A iter {iter}: pq_address_key_hash_256"
        );

        // Random payload (0..300 bytes, spanning multi-block SHA-512 128-byte boundaries)
        let payload_len = (rng.next_u32() as usize) % 300;
        let mut payload = vec![0u8; payload_len];
        rng.fill_bytes(&mut payload);

        let mut magic = [0u8; 4];
        rng.fill_bytes(&mut magic);

        let rust_pre =
            compute_pq_signing_prehash_with_pk_hash(tag_enum, magic, scheme, &rust_kh, &payload);
        let c99_pre = c99_signing_prehash_var(tag_str, magic, scheme_byte, &c99_kh, &payload);
        assert_eq!(c99_pre, rust_pre, "Fuzz A iter {iter}: signing_prehash_var");

        // Also test fixed 32-byte payload prehash every 3rd iteration
        if iter % 3 == 0 {
            let mut payload32 = [0u8; 32];
            rng.fill_bytes(&mut payload32);
            let rust_pre32 = compute_pq_signing_prehash_with_pk_hash(
                tag_enum, magic, scheme, &rust_kh, &payload32,
            );
            let c99_pre32 =
                c99_signing_prehash_32(tag_str, magic, scheme_byte, &c99_kh, &payload32);
            assert_eq!(
                c99_pre32, rust_pre32,
                "Fuzz A iter {iter}: signing_prehash_32"
            );
        }

        // Also test SHAKE256 across multi-rate (136-byte) input & output boundaries
        if iter % 5 == 0 {
            let out_len = 1 + ((rng.next_u32() as usize) % 300);
            let mut rust_xof = Shake256Xof::new();
            rust_xof.update(&pk_buf);
            let mut rust_out = vec![0u8; out_len];
            rust_xof.squeeze(&mut rust_out);

            let mut c99_out = vec![0u8; out_len];
            unsafe {
                divi_pq_shake256(pk_buf.as_ptr(), pk_buf.len(), c99_out.as_mut_ptr(), out_len);
            }
            assert_eq!(c99_out, rust_out, "Fuzz A iter {iter}: SHAKE256 XOF");
        }

        // Also test HMAC-SHA512 with keys shorter and longer than 128 bytes
        if iter % 6 == 0 {
            let key_len = (rng.next_u32() as usize) % 200;
            let mut key = vec![0u8; key_len];
            rng.fill_bytes(&mut key);
            let rust_mac = hmac_sha512(&key, &payload);
            let mut c99_mac = [0u8; 64];
            unsafe {
                divi_pq_hmac_sha512(
                    key.as_ptr(),
                    key.len(),
                    payload.as_ptr(),
                    payload.len(),
                    c99_mac.as_mut_ptr(),
                );
            }
            assert_eq!(c99_mac, rust_mac, "Fuzz A iter {iter}: HMAC-SHA512");
        }

        total_iterations += 1;
    }

    // ------------------------------------------------------------------------
    // Fuzz Bank B (2,500 iterations): Randomized BIP39 Seeds, Valid & Invalid
    // Scheme IDs, Hardened vs Unhardened Child Indices, and Stream Lengths.
    // ------------------------------------------------------------------------
    for iter in 0..2_500usize {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);

        let rust_master = derive_pq_master(&seed).unwrap();
        let (c_rc, c_k, c_c) = c99_derive_master(&seed);
        assert_eq!(c_rc, DIVI_PQ_OK);
        assert_eq!(&c_k, rust_master.key_bytes());
        assert_eq!(&c_c, rust_master.chain_code_bytes());

        // Pick scheme_id: 80% valid (1..=4), 20% invalid (0, 5..=255)
        let scheme_byte = if iter % 5 == 0 {
            let r = rng.next_u8();
            if (1..=4).contains(&r) {
                0
            } else {
                r
            }
        } else {
            ((iter % 4) as u8) + 1
        };

        // Pick coin_type, account, index: 85% valid (< 0x80000000), 15% unhardened-overflow (>= 0x80000000)
        let mut coin_type = rng.next_u32() & 0x7fff_ffff;
        let mut account = rng.next_u32() & 0x7fff_ffff;
        let mut index = rng.next_u32() & 0x7fff_ffff;
        if iter % 7 == 0 {
            match iter % 3 {
                0 => coin_type |= 0x8000_0000,
                1 => account |= 0x8000_0000,
                _ => index |= 0x8000_0000,
            }
        }

        let (c_leaf_rc, c_kl, c_cl, c_stream) =
            c99_derive_leaf(&seed, coin_type, account, scheme_byte, index, 64);

        match PqSchemeId::from_byte(scheme_byte) {
            Err(PqError::UnknownSchemeId(_)) => {
                assert_eq!(
                    c_leaf_rc, DIVI_PQ_ERR_UNKNOWN_SCHEME_ID,
                    "Fuzz B iter {iter}: invalid scheme_id {scheme_byte}"
                );
            }
            Ok(scheme) => {
                let rust_leaf_res = derive_pq_leaf(&seed, coin_type, account, scheme, index);
                match rust_leaf_res {
                    Ok(leaf) => {
                        assert_eq!(c_leaf_rc, DIVI_PQ_OK, "Fuzz B iter {iter}");
                        assert_eq!(&c_kl, leaf.k_leaf());
                        assert_eq!(&c_cl, leaf.c_leaf());
                        assert_eq!(c_stream.as_slice(), leaf.keygen_stream_64());
                    }
                    Err(PqError::NonHardenedPqDerivationForbidden(_)) => {
                        assert_eq!(c_leaf_rc, DIVI_PQ_ERR_NON_HARDENED_DERIVATION);
                    }
                    Err(other) => panic!("unexpected derive_pq_leaf error: {other:?}"),
                }
            }
            Err(other) => panic!("unexpected from_byte error: {other:?}"),
        }

        // Also fuzz raw child derivation with random u32 index
        let raw_idx = rng.next_u32();
        let rust_child = rust_master.derive_child_raw(raw_idx);
        let (c_child_rc, c_ck, c_cc) = c99_derive_child_raw(&c_k, &c_c, raw_idx);
        match rust_child {
            Ok(child) => {
                assert_eq!(c_child_rc, DIVI_PQ_OK);
                assert_eq!(&c_ck, child.key_bytes());
                assert_eq!(&c_cc, child.chain_code_bytes());
            }
            Err(PqError::NonHardenedPqDerivationForbidden(_)) => {
                assert_eq!(c_child_rc, DIVI_PQ_ERR_NON_HARDENED_DERIVATION);
            }
            Err(other) => panic!("unexpected derive_child_raw error: {other:?}"),
        }

        total_iterations += 1;
    }

    // ------------------------------------------------------------------------
    // Fuzz Bank C (4,500 iterations): Structure-Aware & Mutated LMS-SHA256-M32-H10
    // Signature & Public-Key Verification Differential Fuzzing.
    // Covers: valid q=0/q=1, single-bit flips across all 2,512 signature bytes,
    // single-bit flips across all 60 pubkey bytes, random u32be header/typecode/q/
    // reserved mutations, truncations, trailing bytes, and domain/magic mutations.
    // ------------------------------------------------------------------------
    for iter in 0..4_500usize {
        let base_sig = if (iter & 1) == 0 {
            &valid_sig_q0
        } else {
            &valid_sig_q1
        };
        let mut pk = valid_pk.clone();
        let mut sig = base_sig.clone();
        let mut msg = valid_prehash;

        match iter % 15 {
            0 => {
                // Unmutated valid signature (must pass both C99 and Rust)
            }
            1..=5 => {
                // Single-bit flip at a deterministic or random offset across all 2,512 sig bytes
                let offset = (iter * 13 + (rng.next_u32() as usize)) % sig.len();
                let bit = 1u8 << (rng.next_u8() & 7);
                sig[offset] ^= bit;
            }
            6 => {
                // Single-bit flip in public key (header, tree_id, merkle_root, or reserved tail)
                let offset = (rng.next_u32() as usize) % pk.len();
                let bit = 1u8 << (rng.next_u8() & 7);
                pk[offset] ^= bit;
            }
            7 => {
                // Mutate leaf index q in sig[0..4] (including boundary values 1023, 1024, u32::MAX)
                let q_candidates = [0u32, 1, 511, 1023, 1024, 1025, 0x7fff_ffff, 0xffff_ffff];
                let q_val = q_candidates[(rng.next_u32() as usize) % q_candidates.len()];
                sig[0..4].copy_from_slice(&q_val.to_be_bytes());
            }
            8 => {
                // Mutate LMOTS typecode in sig[4..8] or LMS typecode in sig[2184..2188]
                let bad_type = rng.next_u32();
                if (rng.next_u8() & 1) == 0 {
                    sig[4..8].copy_from_slice(&bad_type.to_be_bytes());
                } else {
                    sig[2184..2188].copy_from_slice(&bad_type.to_be_bytes());
                }
            }
            9 => {
                // Mutate reserved tail in pk[56..60] or sig[2508..2512]
                let non_zero = 1u32.wrapping_add(rng.next_u32() & 0x0fff_ffff);
                if (rng.next_u8() & 1) == 0 {
                    pk[56..60].copy_from_slice(&non_zero.to_be_bytes());
                } else {
                    sig[2508..2512].copy_from_slice(&non_zero.to_be_bytes());
                }
            }
            10 => {
                // Truncate or append bytes to signature
                if (rng.next_u8() & 1) == 0 {
                    let new_len = (rng.next_u32() as usize) % sig.len();
                    sig.truncate(new_len);
                } else {
                    let extra_len = 1 + ((rng.next_u32() as usize) % 16);
                    sig.extend(std::iter::repeat_n(rng.next_u8(), extra_len));
                }
            }
            11 => {
                // Truncate or append bytes to public key
                if (rng.next_u8() & 1) == 0 {
                    let new_len = (rng.next_u32() as usize) % pk.len();
                    pk.truncate(new_len);
                } else {
                    let extra_len = 1 + ((rng.next_u32() as usize) % 16);
                    pk.extend(std::iter::repeat_n(rng.next_u8(), extra_len));
                }
            }
            12 => {
                // Bit-flip in the 64-byte message prehash
                let offset = (rng.next_u32() as usize) % 64;
                msg[offset] ^= 1u8 << (rng.next_u8() & 7);
            }
            13 => {
                // Multi-byte corruption across LMOTS chains and Merkle path
                for _ in 0..4 {
                    let offset = (rng.next_u32() as usize) % sig.len();
                    sig[offset] ^= rng.next_u8() | 1;
                }
            }
            _ => {
                // Completely random 60-byte pk and 2512-byte sig
                rng.fill_bytes(&mut pk);
                rng.fill_bytes(&mut sig);
            }
        }

        let rust_res = verify_lms_prehash(&pk, &msg, &sig);
        let c99_rc = c99_lms_verify(&pk, &msg, &sig);

        assert_eq!(
            c99_rc == DIVI_PQ_OK,
            rust_res.is_ok(),
            "Fuzz C iter {iter}: C99 ({c99_rc}) vs Rust ({rust_res:?}) boolean disagreement"
        );
        assert!(
            map_rust_lms_result_to_c99_code(&rust_res).contains(&c99_rc),
            "Fuzz C iter {iter}: C99 ({c99_rc}) vs Rust ({rust_res:?}) error code class mismatch"
        );

        // Also test domain-wrapped verification on every 3rd iteration
        if iter % 3 == 0 {
            let (tag_str, tag_enum) = domain_tags[(iter / 3) % domain_tags.len()];
            let mut magic = valid_magic;
            if iter % 9 == 0 {
                magic[0] ^= 0xff;
            }
            let rust_dom = verify_lms_with_domain(tag_enum, magic, &pk, &valid_payload, &sig);
            let c99_dom = c99_lms_verify_with_domain(tag_str, magic, &pk, &valid_payload, &sig);
            assert_eq!(
                c99_dom == DIVI_PQ_OK,
                rust_dom.is_ok(),
                "Fuzz C domain iter {iter}: C99 ({c99_dom}) vs Rust ({rust_dom:?})"
            );
            assert!(
                map_rust_lms_result_to_c99_code(&rust_dom).contains(&c99_dom),
                "Fuzz C domain iter {iter}: C99 ({c99_dom}) vs Rust ({rust_dom:?}) code mismatch"
            );
        }

        total_iterations += 1;
    }

    // ------------------------------------------------------------------------
    // Fuzz Bank D (2,500 iterations): Canonical Encoding Validators for
    // ML-DSA-44 (0x01), FN-DSA-512 (0x02), SLH-DSA-128s (0x03), and LMS (0x04)
    // across valid, boundary, and mutated public keys and signatures.
    // ------------------------------------------------------------------------
    for iter in 0..2_500usize {
        match iter % 4 {
            0 => {
                // ML-DSA-44 signature encoding validator (2,420 bytes)
                // Construct a canonically valid ML-DSA-44 signature (all u_i = 131072 -> z_i = 0)
                // Each 9-byte chunk packs four 18-bit unsigned integers u0=u1=u2=u3 = 0x20000:
                // b0=0, b1=0, b2=0x02, b3=0, b4=0x08, b5=0, b6=0x20, b7=0, b8=0x80
                let mut sig = vec![0u8; 2420];
                for chunk in sig[32..2336].chunks_mut(9) {
                    chunk.copy_from_slice(&[0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x20, 0x00, 0x80]);
                }

                // Mutate on non-zero subcases
                match (iter / 4) % 6 {
                    0 => {
                        // Valid with valid monotonic hints (2 hints in poly 0, 1 hint in poly 2)
                        sig[2336] = 3;
                        sig[2337] = 19;
                        sig[2338] = 42;
                        sig[2336 + 80] = 2;
                        sig[2336 + 81] = 2;
                        sig[2336 + 82] = 3;
                        sig[2336 + 83] = 3;
                    }
                    1 => {
                        // Out-of-range z coefficient (z = gamma1 = 131072 >= 130994)
                        let chunk_idx = (rng.next_u32() as usize) % 256;
                        let start = 32 + chunk_idx * 9;
                        sig[start..start + 9].fill(0);
                    }
                    2 => {
                        // Non-monotonic hint offset or offset > 80
                        sig[2336 + 80] = 5;
                        sig[2336 + 81] = if (rng.next_u8() & 1) == 0 { 4 } else { 81 };
                    }
                    3 => {
                        // Non-ascending hint indices within a polynomial
                        sig[2336] = 10;
                        sig[2337] = 10;
                        sig[2336 + 80] = 2;
                        sig[2336 + 81] = 2;
                        sig[2336 + 82] = 2;
                        sig[2336 + 83] = 2;
                    }
                    4 => {
                        // Non-zero byte in unused hint padding tail
                        sig[2336 + 79] = 1;
                    }
                    _ => {
                        // Random mutation in z or hints
                        let pos = (rng.next_u32() as usize) % sig.len();
                        sig[pos] ^= rng.next_u8() | 1;
                    }
                }

                let rust_ok = PqSchemeId::MlDsa44
                    .validate_signature_encoding(&sig)
                    .is_ok();
                let c99_rc = unsafe { divi_pq_validate_sig_encoding(1, sig.as_ptr(), sig.len()) };
                assert_eq!(
                    c99_rc == DIVI_PQ_OK,
                    rust_ok,
                    "Fuzz D ML-DSA-44 sig iter {iter}: c99={c99_rc}, rust_ok={rust_ok}"
                );
            }
            1 => {
                // FN-DSA-512 public key encoding validator (897 bytes)
                let mut pk = vec![0u8; 897];
                pk[0] = 0x09;
                match (iter / 4) % 4 {
                    0 => {
                        // Valid coefficients < 12289
                    }
                    1 => {
                        // Wrong header byte
                        pk[0] = rng.next_u8() ^ 0x09;
                        if pk[0] == 0x09 {
                            pk[0] = 0x08;
                        }
                    }
                    2 => {
                        // Out-of-range 14-bit coefficient (>= 12289)
                        let idx = 1 + ((rng.next_u32() as usize) % 890);
                        pk[idx] = 0xff;
                        pk[idx + 1] = 0xff;
                    }
                    _ => {
                        // Random byte fill
                        rng.fill_bytes(&mut pk[1..]);
                    }
                }

                let rust_ok = PqSchemeId::FnDsa512.validate_pubkey_encoding(&pk).is_ok();
                let c99_rc = unsafe { divi_pq_validate_pubkey_encoding(2, pk.as_ptr(), pk.len()) };
                assert_eq!(
                    c99_rc == DIVI_PQ_OK,
                    rust_ok,
                    "Fuzz D FN-DSA-512 pk iter {iter}: c99={c99_rc}, rust_ok={rust_ok}"
                );
            }
            2 => {
                // FN-DSA-512 signature encoding validator (666 bytes)
                // A all-zero coefficient stream encodes each of the 512 coefficients as:
                // sign=0 (1 bit), u_low=0000000 (7 bits), u_high=1 (1 terminating bit) = 9 bits per coeff.
                // Build a valid 512-coeff stream first:
                let mut sig = vec![0u8; 666];
                sig[0] = 0x39;
                for coeff_idx in 0..512usize {
                    let bit_idx = coeff_idx * 9 + 8; // 9th bit of each 9-bit group is '1'
                    sig[41 + (bit_idx >> 3)] |= 1u8 << (7 - (bit_idx & 7));
                }

                match (iter / 4) % 5 {
                    0 => {
                        // Valid canonical encoding
                    }
                    1 => {
                        // Wrong header byte
                        sig[0] = 0x38;
                    }
                    2 => {
                        // -0 encoding on first coefficient (set sign bit 0 to 1 while mag == 0)
                        sig[41] |= 0x80;
                    }
                    3 => {
                        // Non-zero trailing padding bit at very last bit (bit 4999)
                        sig[665] |= 0x01;
                    }
                    _ => {
                        // Random byte mutation in compressed payload
                        let pos = 41 + ((rng.next_u32() as usize) % 625);
                        sig[pos] ^= rng.next_u8() | 1;
                    }
                }

                let rust_ok = PqSchemeId::FnDsa512
                    .validate_signature_encoding(&sig)
                    .is_ok();
                let c99_rc = unsafe { divi_pq_validate_sig_encoding(2, sig.as_ptr(), sig.len()) };
                assert_eq!(
                    c99_rc == DIVI_PQ_OK,
                    rust_ok,
                    "Fuzz D FN-DSA-512 sig iter {iter}: c99={c99_rc}, rust_ok={rust_ok}"
                );
            }
            _ => {
                // SLH-DSA-128s & LMS length / encoding checks
                let (scheme_byte, scheme) = schemes[(rng.next_u32() as usize) % schemes.len()];
                let len_delta = (iter % 3) as isize - 1; // -1, 0, +1
                let pk_len = (scheme.pubkey_len() as isize + len_delta) as usize;
                let mut pk = vec![0u8; pk_len];
                rng.fill_bytes(&mut pk);

                let rust_ok = scheme.validate_pubkey_encoding(&pk).is_ok();
                let c99_rc =
                    unsafe { divi_pq_validate_pubkey_encoding(scheme_byte, pk.as_ptr(), pk.len()) };
                assert_eq!(c99_rc == DIVI_PQ_OK, rust_ok);
            }
        }

        total_iterations += 1;
    }

    assert!(
        total_iterations >= 10_000,
        "Expected >= 10,000 differential fuzz iterations, ran {total_iterations}"
    );
}
