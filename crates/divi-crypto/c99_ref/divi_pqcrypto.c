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
 * Zero external library dependencies (<stdint.h>, <stddef.h>, <string.h> only).
 * Zero floating-point types or instructions (-fno-fast-math compatible).
 */

#include "divi_pqcrypto.h"
#include <string.h>

/* ==========================================================================
 * Byte-Order & Bit-Manipulation Helpers (Pure Integer)
 * ========================================================================== */

static uint32_t load_be32(const uint8_t b[4]) {
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |
           ((uint32_t)b[3]);
}

static void store_be32(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
}

static void store_be16(uint8_t out[2], uint16_t v) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)(v);
}

static uint64_t load_be64(const uint8_t b[8]) {
    return ((uint64_t)b[0] << 56) |
           ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) |
           ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  |
           ((uint64_t)b[7]);
}

static void store_be64(uint8_t out[8], uint64_t v) {
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)(v);
}

static uint64_t load_le64(const uint8_t b[8]) {
    return ((uint64_t)b[0])       |
           ((uint64_t)b[1] << 8)  |
           ((uint64_t)b[2] << 16) |
           ((uint64_t)b[3] << 24) |
           ((uint64_t)b[4] << 32) |
           ((uint64_t)b[5] << 40) |
           ((uint64_t)b[6] << 48) |
           ((uint64_t)b[7] << 56);
}

static void store_le64(uint8_t out[8], uint64_t v) {
    out[0] = (uint8_t)(v);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

static uint32_t rotr32(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32u - n));
}

static uint64_t rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64u - n));
}

static uint64_t rotl64(uint64_t x, unsigned int n) {
    return (x << n) | (x >> (64u - n));
}

static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
}

/* ==========================================================================
 * Self-Contained FIPS 180-4 SHA-256
 * ========================================================================== */

typedef struct {
    uint32_t state[8];
    uint64_t bit_len;
    uint8_t buf[64];
    size_t buf_len;
} sha256_ctx_t;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    size_t i;
    for (i = 0; i < 16; ++i) {
        w[i] = load_be32(&block[i * 4]);
    }
    for (i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bit_len = 0;
    ctx->buf_len = 0;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (len == 0) {
        return;
    }
    ctx->bit_len += (uint64_t)len * 8u;
    while (len > 0) {
        size_t take = 64u - ctx->buf_len;
        if (take > len) {
            take = len;
        }
        memcpy(&ctx->buf[ctx->buf_len], data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == 64u) {
            sha256_compress(ctx->state, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t out[32]) {
    ctx->buf[ctx->buf_len++] = 0x80u;
    if (ctx->buf_len > 56u) {
        while (ctx->buf_len < 64u) {
            ctx->buf[ctx->buf_len++] = 0;
        }
        sha256_compress(ctx->state, ctx->buf);
        ctx->buf_len = 0;
    }
    while (ctx->buf_len < 56u) {
        ctx->buf[ctx->buf_len++] = 0;
    }
    store_be64(&ctx->buf[56], ctx->bit_len);
    sha256_compress(ctx->state, ctx->buf);

    for (size_t i = 0; i < 8; ++i) {
        store_be32(&out[i * 4], ctx->state[i]);
    }
    secure_zero(ctx, sizeof(*ctx));
}

void divi_pq_sha256(const uint8_t *data, size_t len, uint8_t out_hash[32]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    if (data != NULL && len > 0) {
        sha256_update(&ctx, data, len);
    }
    sha256_final(&ctx, out_hash);
}

/* ==========================================================================
 * Self-Contained FIPS 180-4 SHA-512 & RFC 2104 HMAC-SHA512
 * ========================================================================== */

typedef struct {
    uint64_t state[8];
    uint64_t bit_len_low;
    uint64_t bit_len_high;
    uint8_t buf[128];
    size_t buf_len;
} sha512_ctx_t;

static const uint64_t SHA512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void sha512_compress(uint64_t state[8], const uint8_t block[128]) {
    uint64_t w[80];
    size_t i;
    for (i = 0; i < 16; ++i) {
        w[i] = load_be64(&block[i * 8]);
    }
    for (i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];
    uint64_t e = state[4];
    uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];

    for (i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t temp1 = h + S1 + ch + SHA512_K[i] + w[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static void sha512_init(sha512_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->bit_len_low = 0;
    ctx->bit_len_high = 0;
    ctx->buf_len = 0;
}

static void sha512_update(sha512_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (len == 0) {
        return;
    }
    uint64_t add_bits = (uint64_t)len << 3;
    ctx->bit_len_low += add_bits;
    if (ctx->bit_len_low < add_bits) {
        ctx->bit_len_high += 1;
    }
    ctx->bit_len_high += (uint64_t)len >> 61;

    while (len > 0) {
        size_t take = 128u - ctx->buf_len;
        if (take > len) {
            take = len;
        }
        memcpy(&ctx->buf[ctx->buf_len], data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == 128u) {
            sha512_compress(ctx->state, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void sha512_final(sha512_ctx_t *ctx, uint8_t out[64]) {
    ctx->buf[ctx->buf_len++] = 0x80u;
    if (ctx->buf_len > 112u) {
        while (ctx->buf_len < 128u) {
            ctx->buf[ctx->buf_len++] = 0;
        }
        sha512_compress(ctx->state, ctx->buf);
        ctx->buf_len = 0;
    }
    while (ctx->buf_len < 112u) {
        ctx->buf[ctx->buf_len++] = 0;
    }
    store_be64(&ctx->buf[112], ctx->bit_len_high);
    store_be64(&ctx->buf[120], ctx->bit_len_low);
    sha512_compress(ctx->state, ctx->buf);

    for (size_t i = 0; i < 8; ++i) {
        store_be64(&out[i * 8], ctx->state[i]);
    }
    secure_zero(ctx, sizeof(*ctx));
}

void divi_pq_sha512(const uint8_t *data, size_t len, uint8_t out_hash[64]) {
    sha512_ctx_t ctx;
    sha512_init(&ctx);
    if (data != NULL && len > 0) {
        sha512_update(&ctx, data, len);
    }
    sha512_final(&ctx, out_hash);
}

void divi_pq_hmac_sha512(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t out_mac[64]
) {
    uint8_t k_block[128];
    uint8_t ipad[128];
    uint8_t opad[128];
    uint8_t inner_digest[64];

    memset(k_block, 0, sizeof(k_block));
    if (key_len > 128u) {
        divi_pq_sha512(key, key_len, k_block);
    } else if (key != NULL && key_len > 0) {
        memcpy(k_block, key, key_len);
    }

    for (size_t i = 0; i < 128u; ++i) {
        ipad[i] = k_block[i] ^ 0x36u;
        opad[i] = k_block[i] ^ 0x5cu;
    }

    sha512_ctx_t inner;
    sha512_init(&inner);
    sha512_update(&inner, ipad, 128u);
    if (data != NULL && data_len > 0) {
        sha512_update(&inner, data, data_len);
    }
    sha512_final(&inner, inner_digest);

    sha512_ctx_t outer;
    sha512_init(&outer);
    sha512_update(&outer, opad, 128u);
    sha512_update(&outer, inner_digest, 64u);
    sha512_final(&outer, out_mac);

    secure_zero(k_block, sizeof(k_block));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
    secure_zero(inner_digest, sizeof(inner_digest));
}

/* ==========================================================================
 * Self-Contained FIPS 202 Keccak-f[1600] & SHAKE256
 * ========================================================================== */

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const unsigned int KECCAK_RHO[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const size_t KECCAK_PI[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static void keccak_f1600(uint64_t state[25]) {
    for (size_t round = 0; round < 24u; ++round) {
        uint64_t c[5];
        for (size_t x = 0; x < 5u; ++x) {
            c[x] = state[x] ^ state[x + 5u] ^ state[x + 10u] ^ state[x + 15u] ^ state[x + 20u];
        }
        for (size_t x = 0; x < 5u; ++x) {
            uint64_t d = c[(x + 4u) % 5u] ^ rotl64(c[(x + 1u) % 5u], 1);
            for (size_t y = 0; y < 25u; y += 5u) {
                state[x + y] ^= d;
            }
        }

        uint64_t current = state[1];
        for (size_t i = 0; i < 24u; ++i) {
            size_t pi_idx = KECCAK_PI[i];
            uint64_t tmp = state[pi_idx];
            state[pi_idx] = rotl64(current, KECCAK_RHO[i]);
            current = tmp;
        }

        for (size_t y = 0; y < 25u; y += 5u) {
            uint64_t r0 = state[y];
            uint64_t r1 = state[y + 1u];
            uint64_t r2 = state[y + 2u];
            uint64_t r3 = state[y + 3u];
            uint64_t r4 = state[y + 4u];
            state[y]      = r0 ^ ((~r1) & r2);
            state[y + 1u] = r1 ^ ((~r2) & r3);
            state[y + 2u] = r2 ^ ((~r3) & r4);
            state[y + 3u] = r3 ^ ((~r4) & r0);
            state[y + 4u] = r4 ^ ((~r0) & r1);
        }

        state[0] ^= KECCAK_RC[round];
    }
}

void divi_pq_shake256(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len
) {
    /* SHAKE256 rate r = 136 bytes (1088 bits) */
    uint64_t state[25];
    uint8_t buf[136];
    size_t pos = 0;

    memset(state, 0, sizeof(state));
    memset(buf, 0, sizeof(buf));

    while (input_len > 0) {
        size_t take = 136u - pos;
        if (take > input_len) {
            take = input_len;
        }
        memcpy(&buf[pos], input, take);
        pos += take;
        input += take;
        input_len -= take;
        if (pos == 136u) {
            for (size_t i = 0; i < 17u; ++i) {
                state[i] ^= load_le64(&buf[i * 8u]);
            }
            memset(buf, 0, sizeof(buf));
            keccak_f1600(state);
            pos = 0;
        }
    }

    /* SHAKE256 domain suffix 0x1f + pad10*1 final bit 0x80 */
    buf[pos] ^= 0x1fu;
    buf[135] ^= 0x80u;
    for (size_t i = 0; i < 17u; ++i) {
        state[i] ^= load_le64(&buf[i * 8u]);
    }
    keccak_f1600(state);

    for (size_t i = 0; i < 17u; ++i) {
        store_le64(&buf[i * 8u], state[i]);
    }
    pos = 0;

    while (output_len > 0) {
        if (pos == 136u) {
            keccak_f1600(state);
            for (size_t i = 0; i < 17u; ++i) {
                store_le64(&buf[i * 8u], state[i]);
            }
            pos = 0;
        }
        size_t take = 136u - pos;
        if (take > output_len) {
            take = output_len;
        }
        memcpy(output, &buf[pos], take);
        pos += take;
        output += take;
        output_len -= take;
    }

    secure_zero(state, sizeof(state));
    secure_zero(buf, sizeof(buf));
}

/* ==========================================================================
 * DIP-PQ-1 Key Hashing & Domain-Separated Signing Prehashes
 * ========================================================================== */

static const uint8_t PQ_PUBKEY_COMMITMENT_DOMAIN[17] = "Divi-PQ-PubKey-v1";
static const uint8_t PQ_HD_MASTER_KEY_DOMAIN[15]     = "Divi PQ seed v1";
static const uint8_t PQ_KEYGEN_STREAM_DOMAIN[17]     = "Divi-PQ-Keygen-v1";

void divi_pq_key_hash_256(
    uint8_t scheme_id,
    const uint8_t *pk,
    size_t pk_len,
    uint8_t out_hash[32]
) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, &scheme_id, 1u);
    if (pk != NULL && pk_len > 0) {
        sha256_update(&ctx, pk, pk_len);
    }
    sha256_final(&ctx, out_hash);
}

void divi_pq_address_key_hash_256(
    uint8_t scheme_id,
    const uint8_t *pk,
    size_t pk_len,
    uint8_t out_hash[32]
) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, PQ_PUBKEY_COMMITMENT_DOMAIN, sizeof(PQ_PUBKEY_COMMITMENT_DOMAIN));
    sha256_update(&ctx, &scheme_id, 1u);
    if (pk != NULL && pk_len > 0) {
        sha256_update(&ctx, pk, pk_len);
    }
    sha256_final(&ctx, out_hash);
}

void divi_pq_signing_prehash_var(
    const char *domain_tag,
    size_t domain_tag_len,
    const uint8_t network_magic[4],
    uint8_t scheme_id,
    const uint8_t pk_hash_256[32],
    const uint8_t *ctx_payload,
    size_t ctx_payload_len,
    uint8_t out_prehash[64]
) {
    uint8_t tag_len_u8 = (uint8_t)domain_tag_len;
    sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, &tag_len_u8, 1u);
    if (domain_tag != NULL && domain_tag_len > 0) {
        sha512_update(&ctx, (const uint8_t *)domain_tag, domain_tag_len);
    }
    sha512_update(&ctx, network_magic, 4u);
    sha512_update(&ctx, &scheme_id, 1u);
    sha512_update(&ctx, pk_hash_256, 32u);
    if (ctx_payload != NULL && ctx_payload_len > 0) {
        sha512_update(&ctx, ctx_payload, ctx_payload_len);
    }
    sha512_final(&ctx, out_prehash);
}

void divi_pq_signing_prehash(
    const char *domain_tag,
    size_t domain_tag_len,
    const uint8_t network_magic[4],
    uint8_t scheme_id,
    const uint8_t pk_hash_256[32],
    const uint8_t payload_hash_256[32],
    uint8_t out_prehash[64]
) {
    divi_pq_signing_prehash_var(
        domain_tag,
        domain_tag_len,
        network_magic,
        scheme_id,
        pk_hash_256,
        payload_hash_256,
        32u,
        out_prehash
    );
}

/* ==========================================================================
 * DIP-PQ-1 Scheme Metadata & Domain Policy Validators
 * ========================================================================== */

int divi_pq_scheme_is_valid(uint8_t scheme_id) {
    return (scheme_id >= DIVI_PQ_SCHEME_MLDSA44 &&
            scheme_id <= DIVI_PQ_SCHEME_LMS_SHA256_M32_H10) ? 1 : 0;
}

size_t divi_pq_scheme_pubkey_len(uint8_t scheme_id) {
    switch (scheme_id) {
        case DIVI_PQ_SCHEME_MLDSA44:            return DIVI_PQ_MLDSA44_PUBKEY_LEN;
        case DIVI_PQ_SCHEME_FNDSA512:           return DIVI_PQ_FNDSA512_PUBKEY_LEN;
        case DIVI_PQ_SCHEME_SLHDSA128S:         return DIVI_PQ_SLHDSA128S_PUBKEY_LEN;
        case DIVI_PQ_SCHEME_LMS_SHA256_M32_H10: return DIVI_PQ_LMS_H10_PUBKEY_LEN;
        default:                                return 0u;
    }
}

size_t divi_pq_scheme_sig_len(uint8_t scheme_id) {
    switch (scheme_id) {
        case DIVI_PQ_SCHEME_MLDSA44:            return DIVI_PQ_MLDSA44_SIG_LEN;
        case DIVI_PQ_SCHEME_FNDSA512:           return DIVI_PQ_FNDSA512_SIG_LEN;
        case DIVI_PQ_SCHEME_SLHDSA128S:         return DIVI_PQ_SLHDSA128S_SIG_LEN;
        case DIVI_PQ_SCHEME_LMS_SHA256_M32_H10: return DIVI_PQ_LMS_H10_SIG_LEN;
        default:                                return 0u;
    }
}

size_t divi_pq_scheme_seed_len(uint8_t scheme_id) {
    switch (scheme_id) {
        case DIVI_PQ_SCHEME_MLDSA44:            return DIVI_PQ_MLDSA44_SEED_LEN;
        case DIVI_PQ_SCHEME_FNDSA512:           return DIVI_PQ_FNDSA512_SEED_LEN;
        case DIVI_PQ_SCHEME_SLHDSA128S:         return DIVI_PQ_SLHDSA128S_SEED_LEN;
        case DIVI_PQ_SCHEME_LMS_SHA256_M32_H10: return DIVI_PQ_LMS_H10_SEED_LEN;
        default:                                return 0u;
    }
}

int divi_pq_scheme_allowed_in_domain(
    uint8_t scheme_id,
    const char *domain_tag,
    size_t domain_tag_len
) {
    if (!divi_pq_scheme_is_valid(scheme_id)) {
        return DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
    }
    if (domain_tag == NULL) {
        return DIVI_PQ_ERR_NULL_PTR;
    }

    int is_tx    = (domain_tag_len == 16u && memcmp(domain_tag, "Divi-PQ-TxSig-v1", 16u) == 0);
    int is_block = (domain_tag_len == 19u && memcmp(domain_tag, "Divi-PQ-BlockSig-v1", 19u) == 0);
    int is_spork = (domain_tag_len == 16u && memcmp(domain_tag, "Divi-PQ-Spork-v1", 16u) == 0);

    if (!is_tx && !is_block && !is_spork) {
        return DIVI_PQ_ERR_UNKNOWN_DOMAIN_TAG;
    }

    switch (scheme_id) {
        case DIVI_PQ_SCHEME_MLDSA44:
        case DIVI_PQ_SCHEME_FNDSA512:
            return DIVI_PQ_OK;
        case DIVI_PQ_SCHEME_SLHDSA128S:
            return (is_tx || is_spork) ? DIVI_PQ_OK : DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN;
        case DIVI_PQ_SCHEME_LMS_SHA256_M32_H10:
            return is_spork ? DIVI_PQ_OK : DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN;
        default:
            return DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
    }
}

/* ==========================================================================
 * DIP-PQ-1 Deterministic BIP39 -> PQ HD Derivation
 * ========================================================================== */

int divi_pq_derive_master(
    const uint8_t bip39_seed[64],
    uint8_t out_k[32],
    uint8_t out_c[32]
) {
    if (bip39_seed == NULL || out_k == NULL || out_c == NULL) {
        return DIVI_PQ_ERR_NULL_PTR;
    }
    uint8_t i_master[64];
    divi_pq_hmac_sha512(
        PQ_HD_MASTER_KEY_DOMAIN,
        sizeof(PQ_HD_MASTER_KEY_DOMAIN),
        bip39_seed,
        64u,
        i_master
    );
    memcpy(out_k, &i_master[0], 32u);
    memcpy(out_c, &i_master[32], 32u);
    secure_zero(i_master, sizeof(i_master));
    return DIVI_PQ_OK;
}

int divi_pq_derive_child_raw(
    const uint8_t parent_k[32],
    const uint8_t parent_c[32],
    uint32_t raw_child_index,
    uint8_t out_k[32],
    uint8_t out_c[32]
) {
    if (parent_k == NULL || parent_c == NULL || out_k == NULL || out_c == NULL) {
        return DIVI_PQ_ERR_NULL_PTR;
    }
    if ((raw_child_index & DIVI_PQ_HARDENED_BIT) == 0u) {
        return DIVI_PQ_ERR_NON_HARDENED_DERIVATION;
    }

    uint8_t data[37];
    uint8_t i_out[64];
    data[0] = 0x00u;
    memcpy(&data[1], parent_k, 32u);
    store_be32(&data[33], raw_child_index);

    divi_pq_hmac_sha512(parent_c, 32u, data, sizeof(data), i_out);
    memcpy(out_k, &i_out[0], 32u);
    memcpy(out_c, &i_out[32], 32u);

    secure_zero(data, sizeof(data));
    secure_zero(i_out, sizeof(i_out));
    return DIVI_PQ_OK;
}

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
) {
    if (bip39_seed == NULL || out_k_leaf == NULL || out_c_leaf == NULL) {
        return DIVI_PQ_ERR_NULL_PTR;
    }
    if (stream_len > 0 && out_keygen_stream == NULL) {
        return DIVI_PQ_ERR_NULL_PTR;
    }
    if (!divi_pq_scheme_is_valid(scheme_id)) {
        return DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
    }
    if ((coin_type & DIVI_PQ_HARDENED_BIT) != 0u ||
        (account & DIVI_PQ_HARDENED_BIT) != 0u ||
        (index & DIVI_PQ_HARDENED_BIT) != 0u) {
        return DIVI_PQ_ERR_NON_HARDENED_DERIVATION;
    }

    uint8_t k[32];
    uint8_t c[32];
    int rc = divi_pq_derive_master(bip39_seed, k, c);
    if (rc != DIVI_PQ_OK) {
        return rc;
    }

    uint32_t path[5];
    path[0] = DIVI_PQ_BIP44_PURPOSE | DIVI_PQ_HARDENED_BIT;
    path[1] = coin_type | DIVI_PQ_HARDENED_BIT;
    path[2] = account | DIVI_PQ_HARDENED_BIT;
    path[3] = ((uint32_t)scheme_id) | DIVI_PQ_HARDENED_BIT;
    path[4] = index | DIVI_PQ_HARDENED_BIT;

    for (size_t step = 0; step < 5u; ++step) {
        rc = divi_pq_derive_child_raw(k, c, path[step], k, c);
        if (rc != DIVI_PQ_OK) {
            secure_zero(k, sizeof(k));
            secure_zero(c, sizeof(c));
            return rc;
        }
    }

    memcpy(out_k_leaf, k, 32u);
    memcpy(out_c_leaf, c, 32u);

    if (stream_len > 0) {
        /* SHAKE256("Divi-PQ-Keygen-v1" || u8(scheme_id) || k_leaf[32] || c_leaf[32]) */
        uint8_t shake_in[17u + 1u + 32u + 32u];
        memcpy(&shake_in[0], PQ_KEYGEN_STREAM_DOMAIN, 17u);
        shake_in[17] = scheme_id;
        memcpy(&shake_in[18], k, 32u);
        memcpy(&shake_in[50], c, 32u);
        divi_pq_shake256(shake_in, sizeof(shake_in), out_keygen_stream, stream_len);
        secure_zero(shake_in, sizeof(shake_in));
    }

    secure_zero(k, sizeof(k));
    secure_zero(c, sizeof(c));
    return DIVI_PQ_OK;
}

/* ==========================================================================
 * DIP-PQ-1 Pure-Integer Canonical Encoding Validators
 * ========================================================================== */

static int validate_mldsa44_sig(const uint8_t sig[2420]) {
    const int32_t GAMMA1  = 131072; /* 2^17 */
    const int32_t BETA    = 78;
    const int32_t Z_BOUND = GAMMA1 - BETA; /* 130994 */
    const size_t  OMEGA   = 80u;
    const size_t  K       = 4u;

    const uint8_t *z_packed = &sig[32];
    for (size_t idx = 0; idx < 256u; ++idx) {
        const uint8_t *chunk = &z_packed[idx * 9u];
        uint32_t b0 = chunk[0];
        uint32_t b1 = chunk[1];
        uint32_t b2 = chunk[2];
        uint32_t b3 = chunk[3];
        uint32_t b4 = chunk[4];
        uint32_t b5 = chunk[5];
        uint32_t b6 = chunk[6];
        uint32_t b7 = chunk[7];
        uint32_t b8 = chunk[8];

        uint32_t u[4];
        u[0] = (b0 | (b1 << 8) | (b2 << 16)) & 0x3ffffu;
        u[1] = ((b2 >> 2) | (b3 << 6) | (b4 << 14)) & 0x3ffffu;
        u[2] = ((b4 >> 4) | (b5 << 4) | (b6 << 12)) & 0x3ffffu;
        u[3] = ((b6 >> 6) | (b7 << 2) | (b8 << 10)) & 0x3ffffu;

        for (size_t j = 0; j < 4u; ++j) {
            int32_t z = GAMMA1 - (int32_t)u[j];
            if (z <= -Z_BOUND || z >= Z_BOUND) {
                return DIVI_PQ_ERR_NON_CANONICAL_SIG;
            }
        }
    }

    const uint8_t *h_bytes = &sig[2336];
    size_t prev_offset = 0u;
    for (size_t i = 0; i < K; ++i) {
        size_t cur_offset = (size_t)h_bytes[OMEGA + i];
        if (cur_offset < prev_offset || cur_offset > OMEGA) {
            return DIVI_PQ_ERR_NON_CANONICAL_SIG;
        }
        for (size_t j = prev_offset + 1u; j < cur_offset; ++j) {
            if (h_bytes[j - 1u] >= h_bytes[j]) {
                return DIVI_PQ_ERR_NON_CANONICAL_SIG;
            }
        }
        prev_offset = cur_offset;
    }

    for (size_t j = prev_offset; j < OMEGA; ++j) {
        if (h_bytes[j] != 0u) {
            return DIVI_PQ_ERR_NON_CANONICAL_SIG;
        }
    }
    return DIVI_PQ_OK;
}

static int validate_fndsa512_pubkey(const uint8_t pk[897]) {
    if (pk[0] != 0x09u) {
        return DIVI_PQ_ERR_NON_CANONICAL_PUBKEY;
    }
    uint32_t acc = 0u;
    unsigned int acc_bits = 0u;
    for (size_t i = 1u; i < 897u; ++i) {
        acc = (acc << 8) | (uint32_t)pk[i];
        acc_bits += 8u;
        while (acc_bits >= 14u) {
            acc_bits -= 14u;
            uint32_t coeff = (acc >> acc_bits) & 0x3fffu;
            if (coeff >= 12289u) {
                return DIVI_PQ_ERR_NON_CANONICAL_PUBKEY;
            }
        }
    }
    return DIVI_PQ_OK;
}

static int fndsa_read_bit(const uint8_t *payload, size_t total_bits, size_t pos, uint8_t *out_bit) {
    if (pos >= total_bits) {
        return -1;
    }
    uint8_t byte = payload[pos >> 3];
    unsigned int shift = (unsigned int)(7u - (pos & 7u));
    *out_bit = (uint8_t)((byte >> shift) & 1u);
    return 0;
}

static int validate_fndsa512_sig(const uint8_t sig[666]) {
    if (sig[0] != 0x39u) {
        return DIVI_PQ_ERR_NON_CANONICAL_SIG;
    }
    const uint8_t *payload = &sig[41]; /* 625 bytes = 5000 bits */
    const size_t total_bits = 625u * 8u;
    size_t bit_pos = 0u;
    uint8_t bit = 0u;

    for (size_t c = 0; c < 512u; ++c) {
        if (fndsa_read_bit(payload, total_bits, bit_pos++, &bit) != 0) {
            return DIVI_PQ_ERR_NON_CANONICAL_SIG;
        }
        uint8_t sign_bit = bit;

        uint32_t u_low = 0u;
        for (size_t b = 0; b < 7u; ++b) {
            if (fndsa_read_bit(payload, total_bits, bit_pos++, &bit) != 0) {
                return DIVI_PQ_ERR_NON_CANONICAL_SIG;
            }
            u_low = (u_low << 1) | (uint32_t)bit;
        }

        uint32_t u_high = 0u;
        for (;;) {
            if (fndsa_read_bit(payload, total_bits, bit_pos++, &bit) != 0) {
                return DIVI_PQ_ERR_NON_CANONICAL_SIG;
            }
            if (bit == 1u) {
                break;
            }
            u_high += 1u;
            if (u_high > 16u) {
                return DIVI_PQ_ERR_NON_CANONICAL_SIG;
            }
        }

        uint32_t mag = u_low + (u_high << 7);
        if (mag == 0u && sign_bit == 1u) {
            return DIVI_PQ_ERR_NON_CANONICAL_SIG;
        }
        if (mag > 2047u) {
            return DIVI_PQ_ERR_NON_CANONICAL_SIG;
        }
    }

    while (bit_pos < total_bits) {
        if (fndsa_read_bit(payload, total_bits, bit_pos++, &bit) != 0 || bit != 0u) {
            return DIVI_PQ_ERR_NON_CANONICAL_SIG;
        }
    }
    return DIVI_PQ_OK;
}

static int validate_lms_pubkey_detailed(const uint8_t pk[60]) {
    uint32_t lms_type   = load_be32(&pk[0]);
    uint32_t lmots_type = load_be32(&pk[4]);
    uint32_t reserved   = load_be32(&pk[56]);

    if (lms_type != DIVI_PQ_LMS_TYPE_M32_H10 || lmots_type != DIVI_PQ_LMOTS_TYPE_N32_W4) {
        return DIVI_PQ_ERR_LMS_INVALID_TYPECODE;
    }
    if (reserved != 0u) {
        return DIVI_PQ_ERR_LMS_NON_ZERO_RESERVED;
    }
    return DIVI_PQ_OK;
}

static int validate_lms_sig_detailed(const uint8_t sig[2512]) {
    uint32_t q          = load_be32(&sig[0]);
    uint32_t lmots_type = load_be32(&sig[4]);
    uint32_t lms_type   = load_be32(&sig[2184]);
    uint32_t reserved   = load_be32(&sig[2508]);

    if (q >= DIVI_PQ_LMS_NUM_LEAVES) {
        return DIVI_PQ_ERR_LMS_INVALID_LEAF_INDEX;
    }
    if (lmots_type != DIVI_PQ_LMOTS_TYPE_N32_W4 || lms_type != DIVI_PQ_LMS_TYPE_M32_H10) {
        return DIVI_PQ_ERR_LMS_INVALID_TYPECODE;
    }
    if (reserved != 0u) {
        return DIVI_PQ_ERR_LMS_NON_ZERO_RESERVED;
    }
    return DIVI_PQ_OK;
}

int divi_pq_validate_pubkey_encoding(
    uint8_t scheme_id,
    const uint8_t *pk,
    size_t pk_len
) {
    if (!divi_pq_scheme_is_valid(scheme_id)) {
        return DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
    }
    if (pk == NULL) {
        return DIVI_PQ_ERR_NULL_PTR;
    }
    size_t expected = divi_pq_scheme_pubkey_len(scheme_id);
    if (pk_len != expected) {
        return DIVI_PQ_ERR_INVALID_PUBKEY_LEN;
    }
    switch (scheme_id) {
        case DIVI_PQ_SCHEME_MLDSA44:
        case DIVI_PQ_SCHEME_SLHDSA128S:
            return DIVI_PQ_OK;
        case DIVI_PQ_SCHEME_FNDSA512:
            return validate_fndsa512_pubkey(pk);
        case DIVI_PQ_SCHEME_LMS_SHA256_M32_H10: {
            int rc = validate_lms_pubkey_detailed(pk);
            return (rc == DIVI_PQ_OK) ? DIVI_PQ_OK : DIVI_PQ_ERR_NON_CANONICAL_PUBKEY;
        }
        default:
            return DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
    }
}

int divi_pq_validate_sig_encoding(
    uint8_t scheme_id,
    const uint8_t *sig,
    size_t sig_len
) {
    if (!divi_pq_scheme_is_valid(scheme_id)) {
        return DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
    }
    if (sig == NULL) {
        return DIVI_PQ_ERR_NULL_PTR;
    }
    size_t expected = divi_pq_scheme_sig_len(scheme_id);
    if (sig_len != expected) {
        return DIVI_PQ_ERR_INVALID_SIG_LEN;
    }
    switch (scheme_id) {
        case DIVI_PQ_SCHEME_MLDSA44:
            return validate_mldsa44_sig(sig);
        case DIVI_PQ_SCHEME_FNDSA512:
            return validate_fndsa512_sig(sig);
        case DIVI_PQ_SCHEME_SLHDSA128S:
            return DIVI_PQ_OK;
        case DIVI_PQ_SCHEME_LMS_SHA256_M32_H10: {
            int rc = validate_lms_sig_detailed(sig);
            return (rc == DIVI_PQ_OK) ? DIVI_PQ_OK : DIVI_PQ_ERR_NON_CANONICAL_SIG;
        }
        default:
            return DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
    }
}

/* ==========================================================================
 * LMS-SHA256-M32-H10 / LMOTS-SHA256-N32-W4 Verification (DIP-PQ-1 §3.5)
 * ========================================================================== */

static uint8_t lmots_w4_coef(const uint8_t *bytes, size_t i) {
    uint8_t b = bytes[i >> 1];
    if ((i & 1u) == 0u) {
        return (uint8_t)((b >> 4) & 0x0fu);
    } else {
        return (uint8_t)(b & 0x0fu);
    }
}

static void lmots_w4_hash_and_checksum(
    const uint8_t tree_id[16],
    uint32_t q,
    const uint8_t randomizer_c[32],
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_q_ext[34]
) {
    static const uint8_t D_MESG[2] = { 0x81u, 0x81u };
    uint8_t q_be[4];
    store_be32(q_be, q);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, tree_id, 16u);
    sha256_update(&ctx, q_be, 4u);
    sha256_update(&ctx, D_MESG, 2u);
    sha256_update(&ctx, randomizer_c, 32u);
    if (msg != NULL && msg_len > 0) {
        sha256_update(&ctx, msg, msg_len);
    }
    sha256_final(&ctx, out_q_ext);

    uint16_t sum = 0u;
    for (size_t i = 0; i < 64u; ++i) {
        sum = (uint16_t)(sum + (15u - (uint16_t)lmots_w4_coef(out_q_ext, i)));
    }
    uint16_t cksm_shifted = (uint16_t)(sum << 4);
    store_be16(&out_q_ext[32], cksm_shifted);
}

static void lmots_advance_chain(
    const uint8_t tree_id[16],
    uint32_t q,
    uint16_t chain_idx,
    const uint8_t start_val[32],
    uint8_t j_start,
    uint8_t j_end,
    uint8_t out_val[32]
) {
    uint8_t q_be[4];
    uint8_t i_be[2];
    store_be32(q_be, q);
    store_be16(i_be, chain_idx);

    memcpy(out_val, start_val, 32u);
    for (uint8_t j = j_start; j < j_end; ++j) {
        sha256_ctx_t ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, tree_id, 16u);
        sha256_update(&ctx, q_be, 4u);
        sha256_update(&ctx, i_be, 2u);
        sha256_update(&ctx, &j, 1u);
        sha256_update(&ctx, out_val, 32u);
        sha256_final(&ctx, out_val);
    }
}

int divi_pq_lms_m32_h10_verify(
    const uint8_t *pk,
    size_t pk_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sig,
    size_t sig_len
) {
    if (pk == NULL || sig == NULL || (msg == NULL && msg_len > 0)) {
        return DIVI_PQ_ERR_NULL_PTR;
    }
    if (pk_len != DIVI_PQ_LMS_H10_PUBKEY_LEN) {
        return DIVI_PQ_ERR_INVALID_PUBKEY_LEN;
    }
    if (sig_len != DIVI_PQ_LMS_H10_SIG_LEN) {
        return DIVI_PQ_ERR_INVALID_SIG_LEN;
    }

    int pk_rc = validate_lms_pubkey_detailed(pk);
    if (pk_rc != DIVI_PQ_OK) {
        return pk_rc;
    }
    int sig_rc = validate_lms_sig_detailed(sig);
    if (sig_rc != DIVI_PQ_OK) {
        return sig_rc;
    }

    static const uint8_t D_PBLC[2] = { 0x80u, 0x80u };
    static const uint8_t D_LEAF[2] = { 0x82u, 0x82u };
    static const uint8_t D_INTR[2] = { 0x83u, 0x83u };

    const uint8_t *tree_id       = &pk[8];
    const uint8_t *expected_root = &pk[24];
    uint32_t q                   = load_be32(&sig[0]);
    const uint8_t *randomizer_c  = &sig[8];

    uint8_t q_ext[34];
    lmots_w4_hash_and_checksum(tree_id, q, randomizer_c, msg, msg_len, q_ext);

    uint8_t q_be[4];
    store_be32(q_be, q);

    sha256_ctx_t kc_ctx;
    sha256_init(&kc_ctx);
    sha256_update(&kc_ctx, tree_id, 16u);
    sha256_update(&kc_ctx, q_be, 4u);
    sha256_update(&kc_ctx, D_PBLC, 2u);

    for (size_t i = 0; i < DIVI_PQ_LMOTS_W4_CHAINS; ++i) {
        uint8_t a_i = lmots_w4_coef(q_ext, i);
        const uint8_t *y_i = &sig[40u + i * 32u];
        uint8_t z_i[32];
        lmots_advance_chain(tree_id, q, (uint16_t)i, y_i, a_i, 15u, z_i);
        sha256_update(&kc_ctx, z_i, 32u);
    }

    uint8_t kc[32];
    sha256_final(&kc_ctx, kc);

    uint32_t node_num = DIVI_PQ_LMS_NUM_LEAVES + q;
    uint8_t node_be[4];
    store_be32(node_be, node_num);

    uint8_t tmp[32];
    sha256_ctx_t leaf_ctx;
    sha256_init(&leaf_ctx);
    sha256_update(&leaf_ctx, tree_id, 16u);
    sha256_update(&leaf_ctx, node_be, 4u);
    sha256_update(&leaf_ctx, D_LEAF, 2u);
    sha256_update(&leaf_ctx, kc, 32u);
    sha256_final(&leaf_ctx, tmp);

    for (size_t level = 0; level < DIVI_PQ_LMS_TREE_HEIGHT; ++level) {
        const uint8_t *sibling = &sig[2188u + level * 32u];
        uint32_t parent_num = node_num >> 1;
        uint8_t parent_be[4];
        store_be32(parent_be, parent_num);

        sha256_ctx_t intr_ctx;
        sha256_init(&intr_ctx);
        sha256_update(&intr_ctx, tree_id, 16u);
        sha256_update(&intr_ctx, parent_be, 4u);
        sha256_update(&intr_ctx, D_INTR, 2u);
        if ((node_num & 1u) == 1u) {
            sha256_update(&intr_ctx, sibling, 32u);
            sha256_update(&intr_ctx, tmp, 32u);
        } else {
            sha256_update(&intr_ctx, tmp, 32u);
            sha256_update(&intr_ctx, sibling, 32u);
        }
        sha256_final(&intr_ctx, tmp);
        node_num = parent_num;
    }

    uint8_t diff = 0u;
    for (size_t i = 0; i < 32u; ++i) {
        diff |= (uint8_t)(tmp[i] ^ expected_root[i]);
    }
    return (diff == 0u) ? DIVI_PQ_OK : DIVI_PQ_ERR_VERIFICATION_FAILED;
}

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
) {
    if (network_magic == NULL || pk == NULL || sig == NULL) {
        return DIVI_PQ_ERR_NULL_PTR;
    }
    int dom_rc = divi_pq_scheme_allowed_in_domain(
        DIVI_PQ_SCHEME_LMS_SHA256_M32_H10,
        domain_tag,
        domain_tag_len
    );
    if (dom_rc != DIVI_PQ_OK) {
        return dom_rc;
    }

    uint8_t pk_hash[32];
    uint8_t prehash[64];
    divi_pq_key_hash_256(DIVI_PQ_SCHEME_LMS_SHA256_M32_H10, pk, pk_len, pk_hash);
    divi_pq_signing_prehash_var(
        domain_tag,
        domain_tag_len,
        network_magic,
        DIVI_PQ_SCHEME_LMS_SHA256_M32_H10,
        pk_hash,
        ctx_payload,
        ctx_payload_len,
        prehash
    );

    return divi_pq_lms_m32_h10_verify(pk, pk_len, prehash, sizeof(prehash), sig, sig_len);
}
