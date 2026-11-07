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

//! Canonical Cross-Language Differential JSON Test Vector Runner & Adversarial Negative Corpus
//! (`DIP-PQ-1`, Track 7C Phase 1 `P1.3b`).
//!
//! Consumes `crates/divi-crypto/tests/vectors/pq_dip_pq_1.json` (shared between Rust `irondivid`
//! and C++ `divid`) and verifies:
//! - `Vector 1`: `pq_key_hash_256` & `pq_address_key_hash_256` across schemes `0x01`–`0x04`
//! - `Vector 2`: Deterministic BIP39 -> PQ HD master and leaf derivation across schemes `0x01`–`0x04`
//!   and networks (`divi-mainnet` `301'`, `divi-testnet` `1'`, `privatedivi-mainnet` `801'`)
//! - `Vector 3`: `DIVI-PQ-SIG-V1` domain-separated `SHA-512` signing prehash across `tx-input`,
//!   `coinstake-kernel`, `pos-block`, and `spork`
//! - `Vector 4`: `LMS-SHA256-M32-H10` / `LMOTS-SHA256-N32-W4` deterministic keygen, `q=0` and `q=1`
//!   signatures, and verification
//! - `Negative Corpus` (17 vectors): trailing garbage bytes, truncated pubkey, wrong `u32be` LMS/LMOTS
//!   typecodes, leaf index `q >= 1024`, bit-flipped `LMOTS` chain `y[i]`, bit-flipped `LMS` Merkle
//!   authentication path node `path[h]`, domain tag / network magic mismatch, non-hardened child
//!   derivation index, and unknown/role-forbidden scheme IDs.

use std::collections::BTreeMap;

use divi_crypto::pq::{
    compute_pq_signing_prehash_with_pk_hash, derive_pq_leaf, derive_pq_leaf_from_master,
    derive_pq_master, pq_address_key_hash_256, pq_key_hash_256, serialize_pq_signing_preimage,
    verify_lms_prehash, verify_lms_with_domain, LmsPrivateKey, LmsPublicKey, PqDomainTag, PqError,
    PqSchemeId,
};
use divi_crypto::sha256;

const PQ_DIP_PQ_1_JSON: &str = include_str!("vectors/pq_dip_pq_1.json");

// ============================================================================
// Self-Contained RFC 8259 JSON Parser (Zero External Test-Crate Dependencies)
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
        assert_eq!(
            parser.pos,
            parser.bytes.len(),
            "unexpected trailing bytes in JSON vector file"
        );
        value
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> u8 {
        assert!(self.pos < self.bytes.len(), "unexpected EOF in JSON");
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
        assert_eq!(
            actual,
            expected,
            "expected JSON byte `{}` at pos {}, got `{}`",
            expected as char,
            self.pos - 1,
            actual as char
        );
    }

    fn parse_value(&mut self) -> JsonValue {
        self.skip_ws();
        match self.peek() {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => JsonValue::Str(self.parse_string()),
            b't' => {
                assert_eq!(&self.bytes[self.pos..self.pos + 4], b"true");
                self.pos += 4;
                JsonValue::Bool(true)
            }
            b'f' => {
                assert_eq!(&self.bytes[self.pos..self.pos + 5], b"false");
                self.pos += 5;
                JsonValue::Bool(false)
            }
            b'n' => {
                assert_eq!(&self.bytes[self.pos..self.pos + 4], b"null");
                self.pos += 4;
                JsonValue::Null
            }
            b'0'..=b'9' => self.parse_number(),
            other => panic!(
                "unexpected JSON byte `{}` at pos {}",
                other as char, self.pos
            ),
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
                other => panic!(
                    "expected `,` or `}}` in JSON object, got `{}`",
                    other as char
                ),
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
                other => panic!("expected `,` or `]` in JSON array, got `{}`", other as char),
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
                        other => panic!("unsupported JSON escape `\\{}`", other as char),
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
        let n: u64 = s.parse().expect("invalid unsigned integer in JSON");
        JsonValue::Number(n)
    }
}

fn decode_hex_array<const N: usize>(hex_str: &str) -> [u8; N] {
    let bytes = hex::decode(hex_str).expect("valid hex string in vector");
    assert_eq!(bytes.len(), N, "unexpected byte length for hex field");
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    arr
}

#[test]
fn test_json_vector_suite_metadata_and_on_disk_sync() {
    let disk_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/pq_dip_pq_1.json"
    );
    let disk_contents =
        std::fs::read_to_string(disk_path).expect("pq_dip_pq_1.json must exist on disk");
    assert_eq!(disk_contents, PQ_DIP_PQ_1_JSON);

    let root = JsonParser::parse(PQ_DIP_PQ_1_JSON);
    assert_eq!(root.get("schema_version").as_u64(), 1);
    assert_eq!(root.get("dip").as_str(), "DIP-PQ-1");
}

#[test]
fn test_json_vector_1_key_hash_256_and_address_key_hash_256() {
    let root = JsonParser::parse(PQ_DIP_PQ_1_JSON);
    let vectors = root.get("vector_1_key_hashes").as_array();
    assert_eq!(
        vectors.len(),
        4,
        "Vector 1 must cover all 4 DIP-PQ-1 schemes"
    );

    for entry in vectors {
        let id = entry.get("id").as_str();
        let scheme_byte = entry.get("scheme_id").as_u8();
        let scheme = PqSchemeId::from_byte(scheme_byte)
            .unwrap_or_else(|e| panic!("{id}: valid scheme_id expected: {e}"));
        let expected_len = entry.get("pubkey_len").as_usize();
        assert_eq!(
            scheme.pubkey_len(),
            expected_len,
            "{id}: pubkey_len mismatch"
        );

        let pubkey_bytes = hex::decode(entry.get("pubkey_hex").as_str()).unwrap();
        assert_eq!(
            pubkey_bytes.len(),
            expected_len,
            "{id}: decoded pubkey length"
        );
        scheme
            .validate_pubkey_encoding(&pubkey_bytes)
            .unwrap_or_else(|e| panic!("{id}: canonical pubkey encoding failed: {e}"));

        let key_hash = pq_key_hash_256(scheme, &pubkey_bytes);
        let addr_hash = pq_address_key_hash_256(scheme, &pubkey_bytes);
        assert_ne!(
            key_hash, addr_hash,
            "{id}: prehash key binding and address commitment must be domain-separated"
        );
        assert_eq!(
            hex::encode(key_hash),
            entry.get("pq_key_hash_256_hex").as_str(),
            "{id}: pq_key_hash_256 mismatch"
        );
        assert_eq!(
            hex::encode(addr_hash),
            entry.get("pq_address_key_hash_256_hex").as_str(),
            "{id}: pq_address_key_hash_256 mismatch"
        );
    }
}

#[test]
fn test_json_vector_2_bip39_to_pq_hd_master_and_leaf_derivation() {
    let root = JsonParser::parse(PQ_DIP_PQ_1_JSON);
    let hd = root.get("vector_2_hd_derivation");

    let bip39_seed = hex::decode(hd.get("bip39_seed_hex").as_str()).unwrap();
    let master = derive_pq_master(&bip39_seed).expect("valid 64-byte BIP39 seed");
    assert_eq!(
        hex::encode(master.key_bytes()),
        hd.get("k_master_hex").as_str(),
        "master k_master mismatch"
    );
    assert_eq!(
        hex::encode(master.chain_code_bytes()),
        hd.get("c_master_hex").as_str(),
        "master c_master mismatch"
    );

    let leaves = hd.get("leaves").as_array();
    assert!(
        leaves.len() >= 10,
        "Vector 2 must test schemes 0x01..0x04 across Divi Mainnet, Testnet, and PrivateDivi"
    );

    for entry in leaves {
        let id = entry.get("id").as_str();
        let coin_type = entry.get("coin_type").as_u32();
        let account = entry.get("account").as_u32();
        let scheme = PqSchemeId::from_byte(entry.get("scheme_id").as_u8()).unwrap();
        let index = entry.get("index").as_u32();

        let leaf_direct = derive_pq_leaf(&bip39_seed, coin_type, account, scheme, index)
            .unwrap_or_else(|e| panic!("{id}: derive_pq_leaf failed: {e}"));
        let leaf_from_master =
            derive_pq_leaf_from_master(&master, coin_type, account, scheme, index)
                .unwrap_or_else(|e| panic!("{id}: derive_pq_leaf_from_master failed: {e}"));
        assert_eq!(
            leaf_direct, leaf_from_master,
            "{id}: master vs seed leaf parity"
        );

        assert_eq!(
            hex::encode(leaf_direct.k_leaf()),
            entry.get("k_leaf_hex").as_str(),
            "{id}: k_leaf mismatch"
        );
        assert_eq!(
            hex::encode(leaf_direct.c_leaf()),
            entry.get("c_leaf_hex").as_str(),
            "{id}: c_leaf mismatch"
        );
        assert_eq!(
            leaf_direct.algorithm_seed().len(),
            entry.get("algorithm_seed_len").as_usize(),
            "{id}: algorithm_seed_len mismatch"
        );
        assert_eq!(
            hex::encode(leaf_direct.algorithm_seed()),
            entry.get("algorithm_seed_hex").as_str(),
            "{id}: algorithm_seed mismatch"
        );
        assert_eq!(
            hex::encode(leaf_direct.keygen_stream_64()),
            entry.get("keygen_stream_64_hex").as_str(),
            "{id}: keygen_stream_64 mismatch"
        );
    }
}

#[test]
fn test_json_vector_3_domain_separated_signing_prehashes() {
    let root = JsonParser::parse(PQ_DIP_PQ_1_JSON);
    let prehashes = root.get("vector_3_signing_prehashes").as_array();
    assert!(
        prehashes.len() >= 5,
        "Vector 3 must cover tx-input, coinstake-kernel, pos-block, spork, and cross-network"
    );

    let mut seen_roles = Vec::new();
    for entry in prehashes {
        let id = entry.get("id").as_str();
        let role = entry.get("role").as_str();
        seen_roles.push(role.to_string());

        let domain_tag_str = entry.get("domain_tag").as_str();
        let domain_tag = PqDomainTag::from_tag(domain_tag_str)
            .unwrap_or_else(|| panic!("{id}: unknown domain_tag `{domain_tag_str}`"));
        let network_magic: [u8; 4] = decode_hex_array(entry.get("network_magic_hex").as_str());
        let scheme = PqSchemeId::from_byte(entry.get("scheme_id").as_u8()).unwrap();
        let pk_hash256: [u8; 32] = decode_hex_array(entry.get("pk_hash256_hex").as_str());
        let ctx_payload = hex::decode(entry.get("ctx_payload_hex").as_str()).unwrap();

        assert!(
            scheme.is_allowed_in_domain(domain_tag),
            "{id}: scheme {scheme:?} must be allowed in {domain_tag:?}"
        );

        let preimage = serialize_pq_signing_preimage(
            domain_tag,
            network_magic,
            scheme,
            &pk_hash256,
            &ctx_payload,
        );
        assert_eq!(
            hex::encode(&preimage),
            entry.get("preimage_hex").as_str(),
            "{id}: preimage_hex mismatch"
        );

        let prehash = compute_pq_signing_prehash_with_pk_hash(
            domain_tag,
            network_magic,
            scheme,
            &pk_hash256,
            &ctx_payload,
        );
        assert_eq!(
            hex::encode(prehash),
            entry.get("prehash_sha512_hex").as_str(),
            "{id}: prehash_sha512_hex mismatch"
        );
    }

    for required_role in ["tx-input", "coinstake-kernel", "pos-block", "spork"] {
        assert!(
            seen_roles.iter().any(|r| r == required_role),
            "missing required prehash role `{required_role}`"
        );
    }
}

#[test]
fn test_json_vector_4_lms_sha256_m32_h10_deterministic_keygen_sign_and_verify() {
    let root = JsonParser::parse(PQ_DIP_PQ_1_JSON);
    let hd = root.get("vector_2_hd_derivation");
    let bip39_seed = hex::decode(hd.get("bip39_seed_hex").as_str()).unwrap();

    let v4 = root.get("vector_4_lms_sha256_m32_h10");
    let tree_id: [u8; 16] = decode_hex_array(v4.get("tree_id_hex").as_str());
    let master_seed: [u8; 32] = decode_hex_array(v4.get("master_seed_hex").as_str());
    let expected_pk: [u8; 60] = decode_hex_array(v4.get("public_key_hex").as_str());
    let expected_root: [u8; 32] = decode_hex_array(v4.get("merkle_root_hex").as_str());
    let expected_prehash: [u8; 64] = decode_hex_array(v4.get("signing_prehash_hex").as_str());
    let network_magic: [u8; 4] = decode_hex_array(v4.get("network_magic_hex").as_str());
    let spork_payload = hex::decode(v4.get("spork_payload_hex").as_str()).unwrap();

    // Derive from BIP39 leaf m/44'/301'/0'/4'/0' and directly from (I, SEED)
    let lms_leaf =
        derive_pq_leaf(&bip39_seed, 301, 0, PqSchemeId::LmsSha256M32H10, 0).expect("LMS HD leaf");
    let mut sk_from_leaf = LmsPrivateKey::from_pq_leaf(&lms_leaf).expect("LMS keygen from leaf");
    let sk_from_seed = LmsPrivateKey::from_seed(tree_id, master_seed);

    assert_eq!(sk_from_leaf.public_key_bytes(), &expected_pk);
    assert_eq!(sk_from_seed.public_key_bytes(), &expected_pk);

    let parsed_pk = LmsPublicKey::from_bytes(&expected_pk).expect("canonical 60-byte LMS pubkey");
    assert_eq!(parsed_pk.tree_id(), tree_id);
    assert_eq!(parsed_pk.root(), expected_root);

    assert_eq!(
        hex::encode(pq_key_hash_256(PqSchemeId::LmsSha256M32H10, &expected_pk)),
        v4.get("pq_key_hash_256_hex").as_str()
    );
    assert_eq!(
        hex::encode(pq_address_key_hash_256(
            PqSchemeId::LmsSha256M32H10,
            &expected_pk
        )),
        v4.get("pq_address_key_hash_256_hex").as_str()
    );

    // Sign leaf q = 0
    assert_eq!(sk_from_leaf.next_leaf_index(), 0);
    let sig_q0 = sk_from_leaf
        .sign_spork(network_magic, &spork_payload)
        .expect("q=0 Spork signature");
    assert_eq!(sk_from_leaf.next_leaf_index(), 1);
    assert_eq!(hex::encode(sig_q0), v4.get("sig_q0_hex").as_str());
    assert_eq!(
        hex::encode(sha256(&sig_q0)),
        v4.get("sig_q0_sha256_hex").as_str()
    );

    // Sign leaf q = 1
    let sig_q1 = sk_from_leaf
        .sign_spork(network_magic, &spork_payload)
        .expect("q=1 Spork signature");
    assert_eq!(sk_from_leaf.next_leaf_index(), 2);
    assert_eq!(hex::encode(sig_q1), v4.get("sig_q1_hex").as_str());
    assert_eq!(
        hex::encode(sha256(&sig_q1)),
        v4.get("sig_q1_sha256_hex").as_str()
    );

    // Verify both signatures via domain wrapper and raw prehash verifier
    verify_lms_with_domain(
        PqDomainTag::SporkV1,
        network_magic,
        &expected_pk,
        &spork_payload,
        &sig_q0,
    )
    .expect("q=0 must verify with domain");
    verify_lms_prehash(&expected_pk, &expected_prehash, &sig_q0)
        .expect("q=0 must verify with prehash");
    verify_lms_with_domain(
        PqDomainTag::SporkV1,
        network_magic,
        &expected_pk,
        &spork_payload,
        &sig_q1,
    )
    .expect("q=1 must verify with domain");
}

#[test]
fn test_json_adversarial_negative_corpus() {
    let root = JsonParser::parse(PQ_DIP_PQ_1_JSON);
    let hd = root.get("vector_2_hd_derivation");
    let bip39_seed = hex::decode(hd.get("bip39_seed_hex").as_str()).unwrap();
    let master = derive_pq_master(&bip39_seed).unwrap();

    let v4 = root.get("vector_4_lms_sha256_m32_h10");
    let valid_pk = hex::decode(v4.get("public_key_hex").as_str()).unwrap();
    let valid_sig = hex::decode(v4.get("sig_q0_hex").as_str()).unwrap();
    let valid_magic: [u8; 4] = decode_hex_array(v4.get("network_magic_hex").as_str());
    let valid_payload = hex::decode(v4.get("spork_payload_hex").as_str()).unwrap();

    let negatives = root.get("negative_vectors").as_array();
    assert!(
        negatives.len() >= 12,
        "Adversarial corpus must contain at least 12 negative vectors, got {}",
        negatives.len()
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
                let err = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &valid_pk,
                    &valid_payload,
                    &mutated_sig,
                )
                .expect_err(&format!("{id}: must reject trailing signature bytes"));
                assert_eq!(expected_error, "InvalidSignatureLength");
                assert!(
                    matches!(
                        err,
                        PqError::InvalidSignatureLength {
                            scheme: PqSchemeId::LmsSha256M32H10,
                            expected: 2512,
                            actual: 2513,
                        }
                    ),
                    "{id}: unexpected error {err:?}"
                );
            }
            "append_pk_hex" => {
                let extra = hex::decode(entry.get("append_hex").as_str()).unwrap();
                let mut mutated_pk = valid_pk.clone();
                mutated_pk.extend_from_slice(&extra);
                let err = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &mutated_pk,
                    &valid_payload,
                    &valid_sig,
                )
                .expect_err(&format!("{id}: must reject trailing public key bytes"));
                assert_eq!(expected_error, "InvalidPublicKeyLength");
                assert!(
                    matches!(
                        err,
                        PqError::InvalidPublicKeyLength {
                            scheme: PqSchemeId::LmsSha256M32H10,
                            expected: 60,
                            actual: 61,
                        }
                    ),
                    "{id}: unexpected error {err:?}"
                );
            }
            "truncate_pk_len" => {
                let trunc_len = entry.get("truncate_len").as_usize();
                let mutated_pk = &valid_pk[..trunc_len];
                let err = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    mutated_pk,
                    &valid_payload,
                    &valid_sig,
                )
                .expect_err(&format!("{id}: must reject truncated public key"));
                assert_eq!(expected_error, "InvalidPublicKeyLength");
                assert!(
                    matches!(
                        err,
                        PqError::InvalidPublicKeyLength {
                            scheme: PqSchemeId::LmsSha256M32H10,
                            expected: 60,
                            actual,
                        } if actual == trunc_len
                    ),
                    "{id}: unexpected error {err:?}"
                );
            }
            "overwrite_pk_u32be" => {
                let offset = entry.get("byte_offset").as_usize();
                let val = entry.get("u32be_value").as_u32();
                let mut mutated_pk = valid_pk.clone();
                mutated_pk[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
                let err = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &mutated_pk,
                    &valid_payload,
                    &valid_sig,
                )
                .expect_err(&format!("{id}: must reject wrong public key u32be header"));
                assert_eq!(expected_error, "InvalidAlgorithmTypecode");
                assert!(
                    matches!(
                        err,
                        PqError::NonCanonicalPublicKey {
                            scheme: PqSchemeId::LmsSha256M32H10,
                            ..
                        }
                    ),
                    "{id}: unexpected error {err:?}"
                );
            }
            "overwrite_sig_u32be" => {
                let offset = entry.get("byte_offset").as_usize();
                let val = entry.get("u32be_value").as_u32();
                let mut mutated_sig = valid_sig.clone();
                mutated_sig[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
                let err = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &valid_pk,
                    &valid_payload,
                    &mutated_sig,
                )
                .expect_err(&format!("{id}: must reject invalid signature u32be field"));
                assert!(
                    matches!(
                        expected_error,
                        "InvalidAlgorithmTypecode" | "InvalidLeafIndex"
                    ),
                    "{id}: unexpected expected_error tag `{expected_error}`"
                );
                assert!(
                    matches!(
                        err,
                        PqError::NonCanonicalSignature {
                            scheme: PqSchemeId::LmsSha256M32H10,
                            ..
                        }
                    ),
                    "{id}: unexpected error {err:?}"
                );
            }
            "xor_sig_byte" => {
                let offset = entry.get("byte_offset").as_usize();
                let mask = entry.get("xor_mask").as_u8();
                let mut mutated_sig = valid_sig.clone();
                mutated_sig[offset] ^= mask;
                let err = verify_lms_with_domain(
                    PqDomainTag::SporkV1,
                    valid_magic,
                    &valid_pk,
                    &valid_payload,
                    &mutated_sig,
                )
                .expect_err(&format!("{id}: must reject bit-flipped signature byte"));
                assert_eq!(expected_error, "VerificationFailed");
                assert_eq!(err, PqError::VerificationFailed, "{id}: error mismatch");
            }
            "domain_tag_mismatch" => {
                let wrong_domain =
                    PqDomainTag::from_tag(entry.get("verify_domain_tag").as_str()).unwrap();
                let verify_magic: [u8; 4] =
                    decode_hex_array(entry.get("verify_network_magic_hex").as_str());
                let err = verify_lms_with_domain(
                    wrong_domain,
                    verify_magic,
                    &valid_pk,
                    &valid_payload,
                    &valid_sig,
                )
                .expect_err(&format!("{id}: must reject domain tag mismatch"));
                assert_eq!(expected_error, "DomainTagMismatch");
                assert_eq!(
                    err,
                    PqError::SchemeForbiddenInDomain {
                        scheme: PqSchemeId::LmsSha256M32H10,
                        domain: wrong_domain,
                    }
                );

                // Even if an attacker computes a TxSigV1 prehash directly and passes it to raw
                // verify_lms_prehash, the signature must fail cryptographic verification.
                let wrong_prehash = divi_crypto::pq::compute_pq_signing_prehash(
                    wrong_domain,
                    verify_magic,
                    PqSchemeId::LmsSha256M32H10,
                    &valid_pk,
                    &valid_payload,
                );
                assert_eq!(
                    verify_lms_prehash(&valid_pk, &wrong_prehash, &valid_sig),
                    Err(PqError::VerificationFailed)
                );
            }
            "network_magic_mismatch" => {
                let verify_domain =
                    PqDomainTag::from_tag(entry.get("verify_domain_tag").as_str()).unwrap();
                let wrong_magic: [u8; 4] =
                    decode_hex_array(entry.get("verify_network_magic_hex").as_str());
                let err = verify_lms_with_domain(
                    verify_domain,
                    wrong_magic,
                    &valid_pk,
                    &valid_payload,
                    &valid_sig,
                )
                .expect_err(&format!("{id}: must reject cross-network replay"));
                assert_eq!(expected_error, "VerificationFailed");
                assert_eq!(err, PqError::VerificationFailed);
            }
            "unhardened_hd_index" => {
                let bad_leaf_idx = entry.get("leaf_index_u32").as_u32();
                let bad_raw_idx = entry.get("raw_child_index_u32").as_u32();
                assert_eq!(expected_error, "UnhardenedIndexError");

                let err_leaf =
                    derive_pq_leaf(&bip39_seed, 301, 0, PqSchemeId::MlDsa44, bad_leaf_idx)
                        .expect_err(&format!(
                            "{id}: derive_pq_leaf must reject index >= 0x80000000"
                        ));
                assert_eq!(
                    err_leaf,
                    PqError::NonHardenedPqDerivationForbidden(bad_leaf_idx)
                );

                let err_raw = master.derive_child_raw(bad_raw_idx).expect_err(&format!(
                    "{id}: derive_child_raw must reject index < 0x80000000"
                ));
                assert_eq!(
                    err_raw,
                    PqError::NonHardenedPqDerivationForbidden(bad_raw_idx)
                );
            }
            "unknown_scheme_id" => {
                assert_eq!(expected_error, "UnknownSchemeId");
                for val in entry.get("invalid_scheme_bytes").as_array() {
                    let b = val.as_u8();
                    assert_eq!(
                        PqSchemeId::from_byte(b),
                        Err(PqError::UnknownSchemeId(b)),
                        "{id}: scheme byte 0x{b:02x} must be rejected"
                    );
                }
                let spork_only =
                    PqSchemeId::from_byte(entry.get("spork_only_scheme_byte").as_u8()).unwrap();
                for dom_val in entry.get("forbidden_domains").as_array() {
                    let dom = PqDomainTag::from_tag(dom_val.as_str()).unwrap();
                    assert!(
                        !spork_only.is_allowed_in_domain(dom),
                        "{id}: {spork_only:?} must be forbidden in {dom:?}"
                    );
                }
            }
            other => panic!("{id}: unknown negative vector mutation `{other}`"),
        }
    }
}
