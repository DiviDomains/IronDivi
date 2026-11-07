/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 human
 * IronDivi - https://github.com/DiviDomains/IronDivi
 *
 * Self-contained pure-integer C99 reference implementation of DIP-PQ-1
 * post-quantum cryptographic primitives, domain-separated SHA-512 prehashing,
 * deterministic BIP39 -> PQ HD derivation (HMAC-SHA512 + SHAKE256), canonical
 * encoding validators, and LMS-SHA256-M32-H10 / LMOTS-SHA256-N32-W4
 * verification (Track 7C Phase 1 P1.3c).
 *
 * Strictly zero external library dependencies and zero floating-point types or
 * instructions (-fno-fast-math compatible).
 */

#ifndef DIVI_PQCRYPTO_H
#define DIVI_PQCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * DIP-PQ-1 Scheme Identifiers & Fixed Byte Lengths
 * ========================================================================== */

#define DIVI_PQ_SCHEME_MLDSA44           0x01u
#define DIVI_PQ_SCHEME_FNDSA512          0x02u
#define DIVI_PQ_SCHEME_SLHDSA128S        0x03u
#define DIVI_PQ_SCHEME_LMS_SHA256_M32_H10 0x04u

#define DIVI_PQ_MLDSA44_PUBKEY_LEN       1312u
#define DIVI_PQ_MLDSA44_SIG_LEN          2420u
#define DIVI_PQ_MLDSA44_SEED_LEN         32u

#define DIVI_PQ_FNDSA512_PUBKEY_LEN      897u
#define DIVI_PQ_FNDSA512_SIG_LEN         666u
#define DIVI_PQ_FNDSA512_SEED_LEN        64u

#define DIVI_PQ_SLHDSA128S_PUBKEY_LEN    32u
#define DIVI_PQ_SLHDSA128S_SIG_LEN       7856u
#define DIVI_PQ_SLHDSA128S_SEED_LEN      48u

#define DIVI_PQ_LMS_H10_PUBKEY_LEN       60u
#define DIVI_PQ_LMS_H10_SIG_LEN          2512u
#define DIVI_PQ_LMS_H10_SEED_LEN         48u

#define DIVI_PQ_HARDENED_BIT             0x80000000u
#define DIVI_PQ_BIP44_PURPOSE            44u
#define DIVI_PQ_LMS_TREE_HEIGHT          10u
#define DIVI_PQ_LMS_NUM_LEAVES           1024u
#define DIVI_PQ_LMS_TYPE_M32_H10         0x00000006u
#define DIVI_PQ_LMOTS_TYPE_N32_W4        0x00000003u
#define DIVI_PQ_LMOTS_W4_CHAINS          67u

/* ==========================================================================
 * Exact Error Codes (1:1 mapping with Rust divi_crypto::pq::PqError)
 * ========================================================================== */

#define DIVI_PQ_OK                               0
#define DIVI_PQ_ERR_NULL_PTR                    (-1)
#define DIVI_PQ_ERR_UNKNOWN_SCHEME_ID           (-2)
#define DIVI_PQ_ERR_INVALID_BIP39_SEED_LEN      (-3)
#define DIVI_PQ_ERR_NON_HARDENED_DERIVATION     (-4)
#define DIVI_PQ_ERR_INVALID_PUBKEY_LEN          (-5)
#define DIVI_PQ_ERR_INVALID_SIG_LEN             (-6)
#define DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN  (-7)
#define DIVI_PQ_ERR_NON_CANONICAL_PUBKEY        (-8)
#define DIVI_PQ_ERR_NON_CANONICAL_SIG           (-9)
#define DIVI_PQ_ERR_LMS_INVALID_TYPECODE        (-10)
#define DIVI_PQ_ERR_LMS_INVALID_LEAF_INDEX      (-11)
#define DIVI_PQ_ERR_LMS_NON_ZERO_RESERVED       (-12)
#define DIVI_PQ_ERR_VERIFICATION_FAILED         (-13)
#define DIVI_PQ_ERR_UNKNOWN_DOMAIN_TAG          (-14)

/* ==========================================================================
 * Self-Contained Hash & XOF Primitives (SHA-256, SHA-512, HMAC-SHA512, SHAKE256)
 * ========================================================================== */

void divi_pq_sha256(const uint8_t *data, size_t len, uint8_t out_hash[32]);

void divi_pq_sha512(const uint8_t *data, size_t len, uint8_t out_hash[64]);

void divi_pq_hmac_sha512(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t out_mac[64]
);

void divi_pq_shake256(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len
);

/* ==========================================================================
 * DIP-PQ-1 Key Hashing & Domain-Separated Signing Prehash
 * ========================================================================== */

/* Compute SHA-256(u8(scheme_id) || pk[0..pk_len]) (DIP-PQ-1 §4.2). */
void divi_pq_key_hash_256(
    uint8_t scheme_id,
    const uint8_t *pk,
    size_t pk_len,
    uint8_t out_hash[32]
);

/* Compute SHA-256("Divi-PQ-PubKey-v1" || u8(scheme_id) || pk[0..pk_len]) (DIP-PQ-1 §5.5). */
void divi_pq_address_key_hash_256(
    uint8_t scheme_id,
    const uint8_t *pk,
    size_t pk_len,
    uint8_t out_hash[32]
);

/* Compute SHA-512(u8(|domain_tag|) || domain_tag || network_magic[4] || u8(scheme_id) || pk_hash_256[32] || payload_hash_256[32])
 * for a 32-byte payload digest (DIP-PQ-1 §4.2). */
void divi_pq_signing_prehash(
    const char *domain_tag,
    size_t domain_tag_len,
    const uint8_t network_magic[4],
    uint8_t scheme_id,
    const uint8_t pk_hash_256[32],
    const uint8_t payload_hash_256[32],
    uint8_t out_prehash[64]
);

/* Compute SHA-512(u8(|domain_tag|) || domain_tag || network_magic[4] || u8(scheme_id) || pk_hash_256[32] || ctx_payload[0..ctx_payload_len])
 * for an arbitrary-length context payload (tx-input 32 B, pos-block 64 B, spork 20 B, etc., DIP-PQ-1 §4.2). */
void divi_pq_signing_prehash_var(
    const char *domain_tag,
    size_t domain_tag_len,
    const uint8_t network_magic[4],
    uint8_t scheme_id,
    const uint8_t pk_hash_256[32],
    const uint8_t *ctx_payload,
    size_t ctx_payload_len,
    uint8_t out_prehash[64]
);

/* ==========================================================================
 * DIP-PQ-1 Deterministic BIP39 -> PQ HD Derivation
 * ========================================================================== */

/* Derive root PQ master key (k_master, c_master) from a 64-byte BIP39 seed via
 * HMAC-SHA512("Divi PQ seed v1", bip39_seed) (DIP-PQ-1 §5.1). */
int divi_pq_derive_master(
    const uint8_t bip39_seed[64],
    uint8_t out_k[32],
    uint8_t out_c[32]
);

/* Derive a single hardened child step CKDpriv_PQ((k_parent, c_parent), raw_child_index) (DIP-PQ-1 §5.2).
 * Returns DIVI_PQ_ERR_NON_HARDENED_DERIVATION if (raw_child_index & 0x80000000u) == 0. */
int divi_pq_derive_child_raw(
    const uint8_t parent_k[32],
    const uint8_t parent_c[32],
    uint32_t raw_child_index,
    uint8_t out_k[32],
    uint8_t out_c[32]
);

/* Derive leaf node at m / 44' / coin_type' / account' / scheme_id' / index' and expand
 * SHAKE256("Divi-PQ-Keygen-v1" || u8(scheme_id) || k_leaf || c_leaf) into out_keygen_stream[0..stream_len]
 * (DIP-PQ-1 §5.3 - §5.4). */
int divi_pq_derive_leaf(
    const uint8_t bip39_seed[64],
    uint32_t coin_type,
    uint32_t account,
    uint8_t scheme_id,
    uint32_t index,
    uint8_t out_k_leaf[32],
    uint8_t out_c_leaf[32],
    uint8_t *out_keygen_stream,
    size_t stream_len
);

/* ==========================================================================
 * DIP-PQ-1 Canonical Encoding & Domain Policy Validators
 * ========================================================================== */

int divi_pq_scheme_is_valid(uint8_t scheme_id);
size_t divi_pq_scheme_pubkey_len(uint8_t scheme_id);
size_t divi_pq_scheme_sig_len(uint8_t scheme_id);
size_t divi_pq_scheme_seed_len(uint8_t scheme_id);

int divi_pq_scheme_allowed_in_domain(
    uint8_t scheme_id,
    const char *domain_tag,
    size_t domain_tag_len
);

int divi_pq_validate_pubkey_encoding(
    uint8_t scheme_id,
    const uint8_t *pk,
    size_t pk_len
);

int divi_pq_validate_sig_encoding(
    uint8_t scheme_id,
    const uint8_t *sig,
    size_t sig_len
);

/* ==========================================================================
 * LMS-SHA256-M32-H10 / LMOTS-SHA256-N32-W4 Verification (DIP-PQ-1 §2.1 #4, §3.5)
 * ========================================================================== */

/* Verify a 2,512-byte LMS-SHA256-M32-H10 signature against a 60-byte public key and
 * raw message (typically the 64-byte SHA-512 signing prehash).
 * Returns DIVI_PQ_OK (0) on valid signature, or a negative DIVI_PQ_ERR_* code on failure. */
int divi_pq_lms_m32_h10_verify(
    const uint8_t *pk,
    size_t pk_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sig,
    size_t sig_len
);

/* Verify an LMS-SHA256-M32-H10 signature with full domain-tag role check ("Divi-PQ-Spork-v1" only)
 * and SHA-512 domain-separated prehash computation. */
int divi_pq_lms_m32_h10_verify_with_domain(
    const char *domain_tag,
    size_t domain_tag_len,
    const uint8_t network_magic[4],
    const uint8_t *pk,
    size_t pk_len,
    const uint8_t *ctx_payload,
    size_t ctx_payload_len,
    const uint8_t *sig,
    size_t sig_len
);

#ifdef __cplusplus
}
#endif

#endif /* DIVI_PQCRYPTO_H */
