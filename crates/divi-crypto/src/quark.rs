// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Quark hash algorithm (used by Divi for block headers with version < 4)
//!
//! Quark is a chained hash algorithm that uses 6 different hash functions
//! (Blake512, BMW512, Groestl512, JH512, Keccak512, Skein512) in a specific
//! sequence with conditional branching based on bit 3 of intermediate results.
//!
//! The algorithm:
//! 1. Blake512(input)
//! 2. BMW512
//! 3. if bit3: Groestl512 else Skein512
//! 4. Groestl512
//! 5. JH512
//! 6. if bit3: Blake512 else BMW512
//! 7. Keccak512
//! 8. Skein512
//! 9. if bit3: Keccak512 else JH512
//! 10. Truncate to 256 bits

use std::ffi::c_void;

// The sphlib `size_t` parameter is `usize` in Rust's C FFI.
// All sphlib functions take `void*` context, `const void*` data, `size_t` len.

/// Aligned buffer for holding sphlib context structs (opaque to Rust).
/// 512 bytes with 16-byte alignment is more than enough for any sphlib context.
/// The largest context is sph_keccak_context at ~360 bytes.
#[repr(C, align(16))]
struct SphContext {
    _data: [u8; 512],
}

impl SphContext {
    fn new() -> Self {
        SphContext { _data: [0u8; 512] }
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self._data.as_mut_ptr() as *mut c_void
    }
}

extern "C" {
    // Blake-512
    fn sph_blake512_init(cc: *mut c_void);
    fn sph_blake512(cc: *mut c_void, data: *const c_void, len: usize);
    fn sph_blake512_close(cc: *mut c_void, dst: *mut c_void);

    // BMW-512
    fn sph_bmw512_init(cc: *mut c_void);
    fn sph_bmw512(cc: *mut c_void, data: *const c_void, len: usize);
    fn sph_bmw512_close(cc: *mut c_void, dst: *mut c_void);

    // Groestl-512
    fn sph_groestl512_init(cc: *mut c_void);
    fn sph_groestl512(cc: *mut c_void, data: *const c_void, len: usize);
    fn sph_groestl512_close(cc: *mut c_void, dst: *mut c_void);

    // JH-512
    fn sph_jh512_init(cc: *mut c_void);
    fn sph_jh512(cc: *mut c_void, data: *const c_void, len: usize);
    fn sph_jh512_close(cc: *mut c_void, dst: *mut c_void);

    // Keccak-512
    fn sph_keccak512_init(cc: *mut c_void);
    fn sph_keccak512(cc: *mut c_void, data: *const c_void, len: usize);
    fn sph_keccak512_close(cc: *mut c_void, dst: *mut c_void);

    // Skein-512
    fn sph_skein512_init(cc: *mut c_void);
    fn sph_skein512(cc: *mut c_void, data: *const c_void, len: usize);
    fn sph_skein512_close(cc: *mut c_void, dst: *mut c_void);
}

/// Perform one round of an sphlib 512-bit hash: init, update, close.
///
/// # Safety
/// `input` and `output` must point to valid memory of the indicated sizes.
unsafe fn sph_round(
    init_fn: unsafe extern "C" fn(*mut c_void),
    update_fn: unsafe extern "C" fn(*mut c_void, *const c_void, usize),
    close_fn: unsafe extern "C" fn(*mut c_void, *mut c_void),
    input: *const u8,
    input_len: usize,
    output: *mut u8,
) {
    let mut ctx = SphContext::new();
    let cc = ctx.as_mut_ptr();
    init_fn(cc);
    update_fn(cc, input as *const c_void, input_len);
    close_fn(cc, output as *mut c_void);
}

/// Convenience macros are replaced by inline unsafe calls below to avoid
/// borrow-checker issues with simultaneous references to different array slots.

/// Compute the Quark hash of `data`, returning a 256-bit (32-byte) result.
///
/// This matches the C++ `HashQuark` function from Divi's `hash.h`.
/// The conditional branches check bit 3 (mask = 8) of the first byte
/// of each intermediate 512-bit hash (little-endian uint512 representation).
pub fn hash_quark(data: &[u8]) -> [u8; 32] {
    // 9 intermediate 512-bit hashes, matching the C++ `uint512 hash[9]`.
    let mut hash = [[0u8; 64]; 9];

    unsafe {
        // We use raw pointers to avoid Rust borrow-checker issues with
        // simultaneous immutable/mutable borrows on different array indices.
        let h = hash.as_mut_ptr();

        // Step 1: Blake512(input) -> hash[0]
        sph_round(
            sph_blake512_init,
            sph_blake512,
            sph_blake512_close,
            data.as_ptr(),
            data.len(),
            (*h.add(0)).as_mut_ptr(),
        );

        // Step 2: BMW512(hash[0]) -> hash[1]
        sph_round(
            sph_bmw512_init,
            sph_bmw512,
            sph_bmw512_close,
            (*h.add(0)).as_ptr(),
            64,
            (*h.add(1)).as_mut_ptr(),
        );

        // Step 3: conditional on bit 3 of hash[1][0]
        if (*h.add(1))[0] & 8 != 0 {
            sph_round(
                sph_groestl512_init,
                sph_groestl512,
                sph_groestl512_close,
                (*h.add(1)).as_ptr(),
                64,
                (*h.add(2)).as_mut_ptr(),
            );
        } else {
            sph_round(
                sph_skein512_init,
                sph_skein512,
                sph_skein512_close,
                (*h.add(1)).as_ptr(),
                64,
                (*h.add(2)).as_mut_ptr(),
            );
        }

        // Step 4: Groestl512(hash[2]) -> hash[3]
        sph_round(
            sph_groestl512_init,
            sph_groestl512,
            sph_groestl512_close,
            (*h.add(2)).as_ptr(),
            64,
            (*h.add(3)).as_mut_ptr(),
        );

        // Step 5: JH512(hash[3]) -> hash[4]
        sph_round(
            sph_jh512_init,
            sph_jh512,
            sph_jh512_close,
            (*h.add(3)).as_ptr(),
            64,
            (*h.add(4)).as_mut_ptr(),
        );

        // Step 6: conditional on bit 3 of hash[4][0]
        if (*h.add(4))[0] & 8 != 0 {
            sph_round(
                sph_blake512_init,
                sph_blake512,
                sph_blake512_close,
                (*h.add(4)).as_ptr(),
                64,
                (*h.add(5)).as_mut_ptr(),
            );
        } else {
            sph_round(
                sph_bmw512_init,
                sph_bmw512,
                sph_bmw512_close,
                (*h.add(4)).as_ptr(),
                64,
                (*h.add(5)).as_mut_ptr(),
            );
        }

        // Step 7: Keccak512(hash[5]) -> hash[6]
        sph_round(
            sph_keccak512_init,
            sph_keccak512,
            sph_keccak512_close,
            (*h.add(5)).as_ptr(),
            64,
            (*h.add(6)).as_mut_ptr(),
        );

        // Step 8: Skein512(hash[6]) -> hash[7]
        sph_round(
            sph_skein512_init,
            sph_skein512,
            sph_skein512_close,
            (*h.add(6)).as_ptr(),
            64,
            (*h.add(7)).as_mut_ptr(),
        );

        // Step 9: conditional on bit 3 of hash[7][0]
        if (*h.add(7))[0] & 8 != 0 {
            sph_round(
                sph_keccak512_init,
                sph_keccak512,
                sph_keccak512_close,
                (*h.add(7)).as_ptr(),
                64,
                (*h.add(8)).as_mut_ptr(),
            );
        } else {
            sph_round(
                sph_jh512_init,
                sph_jh512,
                sph_jh512_close,
                (*h.add(7)).as_ptr(),
                64,
                (*h.add(8)).as_mut_ptr(),
            );
        }
    }

    // Step 10: truncate hash[8] to 256 bits (first 32 bytes).
    // This matches C++ uint512::trim256() which returns the low 256 bits.
    // In little-endian byte storage, that is the first 32 bytes.
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[8][..32]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_quark_deterministic() {
        // Same input should always produce same output
        let data = b"test data for quark hash";
        let hash1 = hash_quark(data);
        let hash2 = hash_quark(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_quark_different_inputs() {
        // Different inputs should produce different outputs
        let hash1 = hash_quark(b"input one");
        let hash2 = hash_quark(b"input two");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_quark_empty_input() {
        // Should handle empty input without panicking
        let hash = hash_quark(b"");
        assert_eq!(hash.len(), 32);
        // The hash of empty data should not be all zeros
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_quark_80_byte_header() {
        // Block headers are 80 bytes; verify we handle that size correctly
        let header = [0u8; 80];
        let hash = hash_quark(&header);
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_quark_privatedivi_mainnet_genesis() {
        // PrivateDivi mainnet genesis header (80 bytes) from C++ node
        // Expected hash: 00000cde87387f76349797373bd8e30809334433210820b8bb17bdde6e8b1e80
        let header_hex = "010000000000000000000000000000000000000000000000000000000000000000000000bdc4956fc6d7d68d5d776c0e68bfe9116ab76366b2020bb9f03a5236bae923416a779069f0ff0f1e5a320000";
        let header_bytes = hex::decode(header_hex).unwrap();
        assert_eq!(header_bytes.len(), 80);

        let hash = hash_quark(&header_bytes);

        // The hash is in internal byte order (little-endian)
        // The display format reverses the bytes
        let mut display_bytes = hash;
        display_bytes.reverse();
        let computed = hex::encode(display_bytes);

        assert_eq!(
            computed, "00000cde87387f76349797373bd8e30809334433210820b8bb17bdde6e8b1e80",
            "Quark hash of PrivateDivi mainnet genesis header should match C++ node"
        );
    }
}
