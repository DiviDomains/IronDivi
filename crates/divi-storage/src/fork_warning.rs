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

//! The pieces of Divi Core's fork warning (ForkWarningHelpers.cpp) that need
//! no chain: the work comparison and the numbers its log lines print.

use divi_consensus::get_block_proof;
use std::cmp::Ordering;

/// The log line of CheckForkWarningConditions for an invalid chain with more
/// work than the best one (ForkWarningHelpers.cpp:51)
pub const INVALID_CHAIN_LOG: &str = "CheckForkWarningConditions: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.";

/// 256-bit little-endian addition, saturating
fn add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    if carry != 0 {
        [0xff; 32]
    } else {
        out
    }
}

/// Compare two little-endian 256-bit values
fn cmp(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

/// Whether `invalid_work` is more than the tip's chain work plus six of the
/// tip's block proofs: getMostWorkForInvalidBlockIndex() > nChainWork +
/// getBlockProof() * 6 (ForkWarningHelpers.cpp:35)
pub fn invalid_work_is_large(invalid_work: &[u8; 32], tip_work: &[u8; 32], tip_bits: u32) -> bool {
    let proof = get_block_proof(tip_bits);
    let mut limit = *tip_work;
    for _ in 0..6 {
        limit = add(&limit, &proof);
    }
    cmp(invalid_work, &limit) == Ordering::Greater
}

/// log2 of a chain work, as Core prints it: log(nChainWork.getdouble()) / log(2.0)
pub fn log2_work(work: &[u8; 32]) -> f64 {
    let value = work
        .iter()
        .rev()
        .fold(0f64, |acc, &byte| acc * 256.0 + byte as f64);
    value.ln() / 2f64.ln()
}

/// A number as printf's `%.8g` writes it
pub fn format_g8(x: f64) -> String {
    if x == 0.0 || !x.is_finite() {
        return if x.is_finite() {
            "0".to_string()
        } else {
            x.to_string()
        };
    }
    let exp = x.abs().log10().floor() as i32;
    if !(-4..8).contains(&exp) {
        let s = format!("{:.7e}", x);
        let (mantissa, e) = s.split_once('e').unwrap_or((&s, "0"));
        let mantissa = mantissa.trim_end_matches('0').trim_end_matches('.');
        let e: i32 = e.parse().unwrap_or(0);
        return format!("{mantissa}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs());
    }
    let s = format!("{:.*}", (7 - exp).max(0) as usize, x);
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

/// A block time as Core's DateTimeStrFormat("%Y-%m-%d %H:%M:%S", t) writes it
pub fn date(time: u32) -> String {
    chrono::DateTime::from_timestamp(i64::from(time), 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(n: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[..8].copy_from_slice(&n.to_le_bytes());
        w
    }

    #[test]
    fn large_means_more_than_six_tip_proofs_ahead() {
        // Regtest's limit bits: every block is worth the same work
        let bits = 0x207fffff;
        let proof = u64::from_le_bytes(get_block_proof(bits)[..8].try_into().unwrap());
        let tip = work(100 * proof);
        assert!(!invalid_work_is_large(&work(106 * proof), &tip, bits));
        assert!(invalid_work_is_large(&work(106 * proof + 1), &tip, bits));
        assert!(!invalid_work_is_large(&work(10 * proof), &tip, bits));
    }

    #[test]
    fn numbers_print_as_core_prints_them() {
        assert_eq!(format_g8(8.0), "8");
        assert_eq!(format_g8(7.9068906), "7.9068906");
        assert_eq!(format_g8(64.123456789), "64.123457");
        assert_eq!(format_g8(99.999999999), "100");
        assert_eq!(format_g8(0.5), "0.5");
        assert_eq!(log2_work(&work(256)), 8.0);
        assert_eq!(date(1537971708), "2018-09-26 14:21:48");
    }
}
