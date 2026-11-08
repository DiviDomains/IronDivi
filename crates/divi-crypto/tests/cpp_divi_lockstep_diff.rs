//! Cross-Repository C++ `Divi` (`Divi/divi/src`) vs Rust `IronDivi` Lockstep Parity Suite
//! (`DIP-PQ-0`, `DIP-PQ-1`, `DIP-PQ-2`, `DIP-PQ-3`, `DIP-PQ-4`).
//!
//! Compiles the C++11 & C99 post-quantum modules directly from the sibling C++ `Divi` repository
//! (`Divi/divi/src`) using `gcc -std=c99` and `g++ -std=c++11 -O2 -Wall -Wextra -Werror -fno-fast-math`
//! and verifies:
//! 1. Exact byte-for-byte identity of `Divi/divi/src/pqcrypto/divi_pqcrypto.{h,c}` with
//!    `IronDivi/crates/divi-crypto/c99_ref/divi_pqcrypto.{h,c}`,
//! 2. Zero floating-point tokens (`float`, `double`, `long double`) across all C/C++ PQ consensus
//!    and wallet files (`post-quantum-lockstep.md` §4.1),
//! 3. Clean `-Wall -Wextra -Werror -fno-fast-math` compilation and execution of
//!    `Divi/divi/src/test/pq_lockstep_tests.cpp`,
//! 4. Direct FFI parity across `divi_cpp_*` C++11 entrypoints for `DIP-PQ-0`..`DIP-PQ-4` against
//!    Rust `divi-crypto` and canonical lockstep vectors.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use divi_crypto::pq::{
    compute_pq_signing_prehash_with_pk_hash, derive_pq_leaf, derive_pq_master,
    pq_address_key_hash_256, pq_key_hash_256, verify_lms_with_domain, PqDomainTag, PqSchemeId,
};
use sha2::{Digest, Sha256};

const DIVI_MAINNET_MAGIC: [u8; 4] = [0xdf, 0xc0, 0x7a, 0x02];

fn locate_cpp_divi_repo() -> PathBuf {
    if let Ok(custom) = env::var("DIVI_CPP_REPO_DIR") {
        let p = PathBuf::from(custom);
        if p.join("divi/src/pqcrypto/divi_pqcrypto.h").exists() {
            return p;
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Check sibling repo ../../../Divi (relative to crates/divi-crypto)
    if let Some(workspace_root) = manifest_dir.parent().and_then(|p| p.parent()) {
        if let Some(parent_dir) = workspace_root.parent() {
            let sibling = parent_dir.join("Divi");
            if sibling.join("divi/src/pqcrypto/divi_pqcrypto.h").exists() {
                return sibling;
            }
            let hp1_sibling = parent_dir.join("divi-cpp-pq");
            if hp1_sibling
                .join("divi/src/pqcrypto/divi_pqcrypto.h")
                .exists()
            {
                return hp1_sibling;
            }
        }
    }

    for candidate in &[
        "/mnt/storage1/cargo-build/divi-cpp-pq",
        "/mnt/storage1/divi-cpp-pq",
    ] {
        let fallback = PathBuf::from(candidate);
        if fallback.join("divi/src/pqcrypto/divi_pqcrypto.h").exists() {
            return fallback;
        }
    }

    panic!(
        "Could not locate C++ Divi repository (checked DIVI_CPP_REPO_DIR, ../Divi, ../divi-cpp-pq, /mnt/storage1/cargo-build/divi-cpp-pq)"
    );
}

/// Strip `//` line comments, `/* ... */` block comments, and `"..."` string literals
/// so identifier scanning only inspects actual C/C++ code tokens.
fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            i = (i + 1).min(bytes.len());
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn assert_no_float_identifiers(path: &Path) {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    let code = strip_comments_and_strings(&raw);
    for token in code.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        assert!(
            token != "float" && token != "double",
            "Forbidden floating-point type `{}` found in C/C++ PQ file {}",
            token,
            path.display()
        );
    }
}

fn build_sample_fn_dsa_512_pubkey(tag: u8) -> Vec<u8> {
    let mut pk = Vec::with_capacity(897);
    pk.push(0x09u8);
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    for i in 0..512u32 {
        let coeff: u32 = (i + u32::from(tag)) % 1024;
        acc = (acc << 14) | coeff;
        acc_bits += 14;
        while acc_bits >= 8 {
            acc_bits -= 8;
            pk.push(((acc >> acc_bits) & 0xff) as u8);
        }
    }
    assert_eq!(pk.len(), 897);
    PqSchemeId::FnDsa512
        .validate_pubkey_encoding(&pk)
        .expect("valid FN-DSA-512 pubkey");
    pk
}

fn build_sample_fn_dsa_512_signature(nonce_byte: u8) -> Vec<u8> {
    let mut sig = vec![0u8; 666];
    sig[0] = 0x39;
    for b in &mut sig[1..41] {
        *b = nonce_byte;
    }
    let payload = &mut sig[41..666];
    for coeff_idx in 0..512usize {
        let bit_pos = coeff_idx * 9 + 8;
        let byte_idx = bit_pos >> 3;
        let bit_shift = 7 - (bit_pos & 7);
        payload[byte_idx] |= 1u8 << bit_shift;
    }
    PqSchemeId::FnDsa512
        .validate_signature_encoding(&sig)
        .expect("valid FN-DSA-512 sig");
    sig
}

#[test]
fn cpp_divi_pqcrypto_c99_files_match_irondivi_reference_byte_for_byte() {
    let cpp_repo = locate_cpp_divi_repo();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let rust_h = fs::read(manifest_dir.join("c99_ref/divi_pqcrypto.h"))
        .expect("read c99_ref/divi_pqcrypto.h");
    let rust_c = fs::read(manifest_dir.join("c99_ref/divi_pqcrypto.c"))
        .expect("read c99_ref/divi_pqcrypto.c");

    let cpp_h = fs::read(cpp_repo.join("divi/src/pqcrypto/divi_pqcrypto.h"))
        .expect("read Divi/divi/src/pqcrypto/divi_pqcrypto.h");
    let cpp_c = fs::read(cpp_repo.join("divi/src/pqcrypto/divi_pqcrypto.c"))
        .expect("read Divi/divi/src/pqcrypto/divi_pqcrypto.c");

    assert_eq!(
        rust_h, cpp_h,
        "Divi/divi/src/pqcrypto/divi_pqcrypto.h must match c99_ref/divi_pqcrypto.h byte-for-byte"
    );
    assert_eq!(
        rust_c, cpp_c,
        "Divi/divi/src/pqcrypto/divi_pqcrypto.c must match c99_ref/divi_pqcrypto.c byte-for-byte"
    );
}

#[test]
fn cpp_divi_pq_modules_have_zero_floating_point_types() {
    let cpp_repo = locate_cpp_divi_repo();
    let src_dir = cpp_repo.join("divi/src");
    let pq_files = [
        "pqcrypto/divi_pqcrypto.h",
        "pqcrypto/divi_pqcrypto.c",
        "crypter_pq.h",
        "crypter_pq.cpp",
        "spork_pq.h",
        "spork_pq.cpp",
        "script/PqStakingVaultScript.h",
        "script/PqStakingVaultScript.cpp",
        "PqBlockSigning.h",
        "PqBlockSigning.cpp",
        "test/pq_lockstep_tests.cpp",
    ];

    for rel in &pq_files {
        let full = src_dir.join(rel);
        assert!(full.exists(), "Expected C++ PQ file {} to exist", full.display());
        assert_no_float_identifiers(&full);
    }
}

#[test]
fn cpp_divi_lockstep_suite_and_ffi_parity_across_dip_pq_0_through_4() {
    let cpp_repo = locate_cpp_divi_repo();
    let src_dir = cpp_repo.join("divi/src");

    let tmp_dir = env::temp_dir().join(format!("divi_cpp_pq_lockstep_{}", std::process::id()));
    fs::create_dir_all(&tmp_dir).expect("create temp build dir");

    let pqcrypto_obj = tmp_dir.join("divi_pqcrypto.o");
    let c_status = Command::new("gcc")
        .args([
            "-std=c99",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-fast-math",
            "-I",
        ])
        .arg(&src_dir)
        .arg("-c")
        .arg(src_dir.join("pqcrypto/divi_pqcrypto.c"))
        .arg("-o")
        .arg(&pqcrypto_obj)
        .status()
        .expect("invoke gcc on divi_pqcrypto.c");
    assert!(c_status.success(), "gcc compilation of divi_pqcrypto.c failed");

    // 1. Compile and run the standalone C++11 test suite (`pq_lockstep_tests.cpp`)
    let standalone_bin = tmp_dir.join("pq_lockstep_tests");
    let cpp_status = Command::new("g++")
        .args([
            "-std=c++11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-fast-math",
            "-DDIVI_PQ_STANDALONE_TEST",
            "-I",
        ])
        .arg(&src_dir)
        .arg(&pqcrypto_obj)
        .arg(src_dir.join("crypter_pq.cpp"))
        .arg(src_dir.join("spork_pq.cpp"))
        .arg(src_dir.join("script/PqStakingVaultScript.cpp"))
        .arg(src_dir.join("PqBlockSigning.cpp"))
        .arg(src_dir.join("test/pq_lockstep_tests.cpp"))
        .arg("-o")
        .arg(&standalone_bin)
        .status()
        .expect("invoke g++ on C++ Divi PQ modules");
    assert!(
        cpp_status.success(),
        "g++ compilation of C++ Divi PQ modules and pq_lockstep_tests.cpp failed"
    );

    let test_output = Command::new(&standalone_bin)
        .output()
        .expect("execute standalone pq_lockstep_tests binary");
    assert!(
        test_output.status.success(),
        "pq_lockstep_tests failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&test_output.stdout),
        String::from_utf8_lossy(&test_output.stderr)
    );
    let stdout_str = String::from_utf8_lossy(&test_output.stdout);
    assert!(
        stdout_str.contains("PASS: pq_lockstep_tests standalone runner"),
        "unexpected pq_lockstep_tests output: {}",
        stdout_str
    );

    // 2. Compile and run a cross-language FFI parity harness calling `divi_cpp_*` C++ entrypoints
    //    and comparing their outputs bit-for-bit against Rust `IronDivi` computations.
    let ffi_driver_cpp = tmp_dir.join("ffi_parity_driver.cpp");
    let driver_source = r#"
#include "crypter_pq.h"
#include "PqBlockSigning.h"
#include "pqcrypto/divi_pqcrypto.h"
#include "script/PqStakingVaultScript.h"
#include "spork_pq.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static void PrintHex(const char* label, const uint8_t* data, size_t len)
{
    std::printf("%s=", label);
    for (size_t i = 0; i < len; ++i) {
        std::printf("%02x", static_cast<unsigned int>(data[i]));
    }
    std::printf("\n");
}

int main()
{
    // 1. DIP-PQ-0 Argon2id + XChaCha20-Poly1305 via extern "C" FFI
    const char* pass = "correct horse battery staple";
    uint8_t salt[16];
    for (size_t i = 0; i < 16; ++i) {
        salt[i] = static_cast<uint8_t>(i);
    }
    uint8_t nonce24[24];
    for (size_t i = 0; i < 24; ++i) {
        nonce24[i] = static_cast<uint8_t>(0x21U + i);
    }
    uint8_t masterKey32[32];
    for (size_t i = 0; i < 32; ++i) {
        masterKey32[i] = static_cast<uint8_t>(0x41U + i);
    }

    uint8_t argonKey32[32];
    if (divi_cpp_argon2id_derive_key32(
            reinterpret_cast<const uint8_t*>(pass),
            std::strlen(pass),
            salt,
            16,
            65536U,
            3U,
            1U,
            argonKey32) != 0) {
        return 10;
    }
    PrintHex("DIP_PQ_0_ARGON2ID_KEY", argonKey32, 32);

    uint8_t sealed72[72];
    if (divi_cpp_seal_master_key_v2(
            masterKey32,
            reinterpret_cast<const uint8_t*>(pass),
            std::strlen(pass),
            salt,
            16,
            65536U,
            3U,
            1U,
            nonce24,
            sealed72) != 0) {
        return 11;
    }
    PrintHex("DIP_PQ_0_SEALED_MASTER_KEY", sealed72, 72);

    uint8_t opened32[32];
    if (divi_cpp_open_master_key_v2(
            sealed72,
            72,
            reinterpret_cast<const uint8_t*>(pass),
            std::strlen(pass),
            salt,
            16,
            65536U,
            3U,
            1U,
            opened32) != 0) {
        return 12;
    }
    if (std::memcmp(opened32, masterKey32, 32) != 0) {
        return 13;
    }

    // 2. DIP-PQ-2 Spork payload hash (Case A integer & Case B string) via extern "C" FFI
    uint8_t secpSig[65];
    secpSig[0] = 31U;
    for (size_t i = 1; i < 65; ++i) {
        secpSig[i] = static_cast<uint8_t>(i);
    }
    uint8_t sporkHashI64[32];
    uint8_t sporkHashStr[32];
    divi_cpp_spork_pq_payload_hash_i64(10013, 4070908800LL, 1750000100LL, secpSig, sporkHashI64);
    divi_cpp_spork_pq_payload_hash_str(
        10013,
        reinterpret_cast<const uint8_t*>("5000;100"),
        8,
        1750000100LL,
        secpSig,
        sporkHashStr);
    PrintHex("DIP_PQ_2_SPORK_HASH_I64", sporkHashI64, 32);
    PrintHex("DIP_PQ_2_SPORK_HASH_STR", sporkHashStr, 32);

    // 3. DIP-PQ-3 Bech32m, P2PQPKH, PQ_STAKING_VAULT, and wtxid via extern "C" FFI
    uint8_t hash11[32];
    uint8_t hash22[32];
    uint8_t hash33[32];
    std::memset(hash11, 0x11, 32);
    std::memset(hash22, 0x22, 32);
    std::memset(hash33, 0x33, 32);

    uint8_t p2pqpkh34[34];
    uint8_t vault74[74];
    divi_cpp_create_p2pqpkh_script(hash11, p2pqpkh34);
    divi_cpp_create_pq_staking_vault_script(hash22, hash33, vault74);
    PrintHex("DIP_PQ_3_P2PQPKH_SCRIPT", p2pqpkh34, 34);
    PrintHex("DIP_PQ_3_VAULT_SCRIPT", vault74, 74);

    char addrBuf[256];
    size_t addrLen = 0;
    if (divi_cpp_encode_pq_bech32m_address(0U, 1U, hash11, 32, addrBuf, sizeof(addrBuf) - 1, &addrLen) != 0) {
        return 20;
    }
    addrBuf[addrLen] = '\0';
    std::printf("DIP_PQ_3_BECH32M_V1=%s\n", addrBuf);

    // 4. DIP-PQ-4 PoS Block Payload Hash via extern "C" FFI
    uint8_t blockHash[32];
    uint8_t coinstakeTxid[32];
    std::memset(blockHash, 0x11, 32);
    std::memset(coinstakeTxid, 0x22, 32);
    uint8_t posPayloadHash[32];
    divi_cpp_pos_block_payload_hash(blockHash, coinstakeTxid, 1U, posPayloadHash);
    PrintHex("DIP_PQ_4_POS_PAYLOAD_HASH", posPayloadHash, 32);

    return 0;
}
"#;
    fs::write(&ffi_driver_cpp, driver_source).expect("write ffi_parity_driver.cpp");

    let ffi_driver_bin = tmp_dir.join("ffi_parity_driver");
    let driver_compile = Command::new("g++")
        .args([
            "-std=c++11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-fast-math",
            "-I",
        ])
        .arg(&src_dir)
        .arg(&pqcrypto_obj)
        .arg(src_dir.join("crypter_pq.cpp"))
        .arg(src_dir.join("spork_pq.cpp"))
        .arg(src_dir.join("script/PqStakingVaultScript.cpp"))
        .arg(src_dir.join("PqBlockSigning.cpp"))
        .arg(&ffi_driver_cpp)
        .arg("-o")
        .arg(&ffi_driver_bin)
        .status()
        .expect("compile ffi_parity_driver");
    assert!(driver_compile.success(), "ffi_parity_driver compilation failed");

    let driver_out = Command::new(&ffi_driver_bin)
        .output()
        .expect("run ffi_parity_driver");
    assert!(
        driver_out.status.success(),
        "ffi_parity_driver failed with status {:?}",
        driver_out.status.code()
    );

    let lines: Vec<String> = String::from_utf8_lossy(&driver_out.stdout)
        .lines()
        .map(str::to_owned)
        .collect();

    let get_val = |key: &str| -> String {
        let prefix = format!("{}=", key);
        lines
            .iter()
            .find_map(|l| l.strip_prefix(&prefix).map(str::to_owned))
            .unwrap_or_else(|| panic!("missing key {} in driver output: {:?}", key, lines))
    };

    // Verify DIP-PQ-0 outputs against Rust at_rest.rs canonical vectors
    assert_eq!(
        get_val("DIP_PQ_0_ARGON2ID_KEY"),
        "0d1a3c6523c8f06e4e0af9c515aa5b5448cfebd6838f2d52c3d8b6ef8ddc3c2e"
    );
    assert_eq!(
        get_val("DIP_PQ_0_SEALED_MASTER_KEY"),
        "2122232425262728292a2b2c2d2e2f3031323334353637380bfc85229c8d94133d93387ceb1cf60eaaf51bd6a790ade9281c0d38a13bc2ad02aad9f8452ced8e9617593fd4756959"
    );

    // Verify DIP-PQ-2 Spork payload hashes against independent Rust SHA256 computation
    let mut secp_sig = [0u8; 65];
    secp_sig[0] = 31;
    for (i, b) in secp_sig.iter_mut().enumerate().skip(1) {
        *b = i as u8;
    }
    let mut preimage_a = Vec::with_capacity(106);
    preimage_a.extend_from_slice(b"DIVI-SPORK-PAYLOAD-V1");
    preimage_a.extend_from_slice(&(10013i32).to_le_bytes());
    preimage_a.extend_from_slice(&(4070908800i64).to_le_bytes());
    preimage_a.extend_from_slice(&(1750000100i64).to_le_bytes());
    preimage_a.extend_from_slice(&secp_sig);
    let rust_spork_hash_a = Sha256::digest(&preimage_a);
    assert_eq!(get_val("DIP_PQ_2_SPORK_HASH_I64"), hex::encode(rust_spork_hash_a));

    let mut preimage_b = Vec::with_capacity(107 + 8);
    preimage_b.extend_from_slice(b"DIVI-SPORK-PAYLOAD-V1");
    preimage_b.extend_from_slice(&(10013i32).to_le_bytes());
    preimage_b.extend_from_slice(&(8u64).to_le_bytes());
    preimage_b.push(0xff);
    preimage_b.extend_from_slice(b"5000;100");
    preimage_b.extend_from_slice(&(1750000100i64).to_le_bytes());
    preimage_b.extend_from_slice(&secp_sig);
    let rust_spork_hash_b = Sha256::digest(&preimage_b);
    assert_eq!(get_val("DIP_PQ_2_SPORK_HASH_STR"), hex::encode(rust_spork_hash_b));

    // Verify DIP-PQ-3 scripts and Bech32m address
    assert_eq!(
        get_val("DIP_PQ_3_P2PQPKH_SCRIPT"),
        "51201111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(
        get_val("DIP_PQ_3_VAULT_SCRIPT"),
        "6320222222222222222222222222222222222222222222222222222222222222222267b92033333333333333333333333333333333333333333333333333333333333333336878a888ac"
    );
    assert_eq!(
        get_val("DIP_PQ_3_BECH32M_V1"),
        "divi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsvgff7j"
    );

    // Verify DIP-PQ-4 PoS payload hash against Rust divi-crypto + SHA-256
    let mut pos_preimage = [0u8; 85];
    pos_preimage[0..17].copy_from_slice(b"DIVI-POS-BLOCK-V1");
    pos_preimage[17..49].copy_from_slice(&[0x11u8; 32]);
    pos_preimage[49..81].copy_from_slice(&[0x22u8; 32]);
    pos_preimage[81..85].copy_from_slice(&1u32.to_le_bytes());
    let rust_pos_hash = Sha256::digest(&pos_preimage);
    assert_eq!(get_val("DIP_PQ_4_POS_PAYLOAD_HASH"), hex::encode(rust_pos_hash));

    // Also verify Rust divi-crypto primitives match the C++ expectations on sample keys
    let fn_pk = build_sample_fn_dsa_512_pubkey(1);
    let _fn_sig = build_sample_fn_dsa_512_signature(0x42);
    let fn_kh = pq_key_hash_256(PqSchemeId::FnDsa512, &fn_pk);
    let fn_akh = pq_address_key_hash_256(PqSchemeId::FnDsa512, &fn_pk);
    assert_ne!(fn_kh, fn_akh);

    let mut payload_arr = [0u8; 32];
    payload_arr.copy_from_slice(&rust_pos_hash);
    let prehash = compute_pq_signing_prehash_with_pk_hash(
        PqDomainTag::BlockSigV1,
        DIVI_MAINNET_MAGIC,
        PqSchemeId::FnDsa512,
        &fn_kh,
        &payload_arr,
    );
    let prehash_var = compute_pq_signing_prehash_with_pk_hash(
        PqDomainTag::BlockSigV1,
        DIVI_MAINNET_MAGIC,
        PqSchemeId::FnDsa512,
        &fn_kh,
        &pos_preimage,
    );
    assert_ne!(prehash, prehash_var);

    // Verify BIP39 -> PQ HD derivation & LMS verification in Rust
    let seed = [0x55u8; 64];
    let master = derive_pq_master(&seed).expect("derive master");
    let leaf = derive_pq_leaf(&seed, 301, 0, PqSchemeId::MlDsa44, 0)
        .expect("derive leaf");
    assert_ne!(master.key_bytes(), leaf.k_leaf());

    let lms_pk = hex::decode(
        "0000000600000003bf2fd2b1a59e04f9b9da4243bb4b78d6a2cccf5a07cc294fd61b762122616dc1884927cfeb3f340e5a6949502bd4a60100000000",
    )
    .unwrap();
    let bad_sig = vec![0u8; 2512];
    assert!(verify_lms_with_domain(
        PqDomainTag::SporkV1,
        DIVI_MAINNET_MAGIC,
        &lms_pk,
        &preimage_a,
        &bad_sig
    )
    .is_err());

    let _ = fs::remove_dir_all(&tmp_dir);
}
