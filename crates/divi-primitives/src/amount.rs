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

//! Amount type representing DIVI values in satoshis

use crate::constants::COIN;
use crate::error::Error;
use crate::serialize::{Decodable, Encodable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::{Read, Write};
use std::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};

/// An amount of DIVI in satoshis (1 DIVI = 10^8 satoshis)
///
/// Internally stored as i64 to match C++ CAmount type.
/// Negative amounts are used for fee calculations.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(pub i64);

impl Amount {
    /// Zero amount
    pub const ZERO: Amount = Amount(0);

    /// One satoshi
    pub const ONE_SAT: Amount = Amount(1);

    /// One DIVI
    pub const ONE_DIVI: Amount = Amount(COIN);

    /// Create amount from satoshis
    pub const fn from_sat(satoshis: i64) -> Self {
        Amount(satoshis)
    }

    /// Create amount from DIVI (whole units)
    pub fn from_divi(divi: i64) -> Self {
        Amount(divi * COIN)
    }

    /// Create amount from DIVI with decimal precision
    pub fn from_divi_f64(divi: f64) -> Self {
        Amount((divi * COIN as f64) as i64)
    }

    /// Get amount in satoshis
    pub fn as_sat(&self) -> i64 {
        self.0
    }

    /// Get amount in DIVI (whole units, truncated)
    pub fn as_divi(&self) -> i64 {
        self.0 / COIN
    }

    /// Get amount in DIVI as float
    pub fn as_divi_f64(&self) -> f64 {
        self.0 as f64 / COIN as f64
    }

    /// Check if amount is zero
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Check if amount is positive
    pub fn is_positive(&self) -> bool {
        self.0 > 0
    }

    /// Check if amount is negative
    pub fn is_negative(&self) -> bool {
        self.0 < 0
    }

    /// Get absolute value
    pub fn abs(&self) -> Self {
        Amount(self.0.abs())
    }

    /// Saturating addition
    pub fn saturating_add(&self, other: Amount) -> Self {
        Amount(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction
    pub fn saturating_sub(&self, other: Amount) -> Self {
        Amount(self.0.saturating_sub(other.0))
    }

    /// Checked addition
    pub fn checked_add(&self, other: Amount) -> Option<Self> {
        self.0.checked_add(other.0).map(Amount)
    }

    /// Checked subtraction
    pub fn checked_sub(&self, other: Amount) -> Option<Self> {
        self.0.checked_sub(other.0).map(Amount)
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({} sat = {} DIVI)", self.0, self.as_divi_f64())
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as DIVI with up to 8 decimal places
        let divi = self.0 / COIN;
        let sat = (self.0 % COIN).abs();

        if sat == 0 {
            write!(f, "{} DIVI", divi)
        } else {
            // Format with appropriate decimal places
            let decimal = format!("{:08}", sat);
            let trimmed = decimal.trim_end_matches('0');
            write!(f, "{}.{} DIVI", divi, trimmed)
        }
    }
}

impl Add for Amount {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Amount(self.0 + other.0)
    }
}

impl Sub for Amount {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Amount(self.0 - other.0)
    }
}

impl Mul<i64> for Amount {
    type Output = Self;

    fn mul(self, rhs: i64) -> Self {
        Amount(self.0 * rhs)
    }
}

impl Div<i64> for Amount {
    type Output = Self;

    fn div(self, rhs: i64) -> Self {
        Amount(self.0 / rhs)
    }
}

impl AddAssign for Amount {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl SubAssign for Amount {
    fn sub_assign(&mut self, other: Self) {
        self.0 -= other.0;
    }
}

impl From<i64> for Amount {
    fn from(satoshis: i64) -> Self {
        Amount(satoshis)
    }
}

impl From<Amount> for i64 {
    fn from(amount: Amount) -> Self {
        amount.0
    }
}

impl Encodable for Amount {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_i64::<LittleEndian>(self.0)?;
        Ok(8)
    }

    fn encoded_size(&self) -> usize {
        8
    }
}

impl Decodable for Amount {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(Amount(reader.read_i64::<LittleEndian>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::{deserialize, serialize};

    #[test]
    fn test_amount_from_divi() {
        let amt = Amount::from_divi(100);
        assert_eq!(amt.as_sat(), 100 * COIN);
        assert_eq!(amt.as_divi(), 100);
    }

    #[test]
    fn test_amount_from_sat() {
        let amt = Amount::from_sat(50_000_000); // 0.5 DIVI
        assert_eq!(amt.as_divi_f64(), 0.5);
    }

    #[test]
    fn test_amount_arithmetic() {
        let a = Amount::from_divi(10);
        let b = Amount::from_divi(3);

        assert_eq!((a + b).as_divi(), 13);
        assert_eq!((a - b).as_divi(), 7);
        assert_eq!((a * 2).as_divi(), 20);
        assert_eq!((a / 2).as_divi(), 5);
    }

    #[test]
    fn test_amount_display() {
        assert_eq!(format!("{}", Amount::from_divi(100)), "100 DIVI");
        assert_eq!(format!("{}", Amount::from_sat(50_000_000)), "0.5 DIVI");
        assert_eq!(
            format!("{}", Amount::from_sat(123_456_789)),
            "1.23456789 DIVI"
        );
    }

    #[test]
    fn test_amount_serialization() {
        let amt = Amount::from_divi(100);
        let encoded = serialize(&amt);
        assert_eq!(encoded.len(), 8);

        let decoded: Amount = deserialize(&encoded).unwrap();
        assert_eq!(decoded, amt);
    }

    #[test]
    fn test_negative_amount() {
        let amt = Amount::from_sat(-100);
        assert!(amt.is_negative());
        assert_eq!(amt.abs().as_sat(), 100);

        // Serialization should work with negative
        let encoded = serialize(&amt);
        let decoded: Amount = deserialize(&encoded).unwrap();
        assert_eq!(decoded, amt);
    }

    // ---- NEW: zero amount ----

    #[test]
    fn test_amount_zero() {
        let zero = Amount::ZERO;
        assert!(zero.is_zero());
        assert!(!zero.is_positive());
        assert!(!zero.is_negative());
        assert_eq!(zero.as_sat(), 0);
        assert_eq!(zero.as_divi(), 0);
        assert_eq!(format!("{}", zero), "0 DIVI");
    }

    #[test]
    fn test_amount_zero_serialization() {
        let zero = Amount::ZERO;
        let encoded = serialize(&zero);
        assert_eq!(
            encoded,
            vec![0u8; 8],
            "zero amount should serialize to 8 zero bytes"
        );
        let decoded: Amount = deserialize(&encoded).unwrap();
        assert_eq!(decoded, zero);
    }

    // ---- NEW: COIN constant ----

    #[test]
    fn test_amount_one_divi_equals_coin() {
        assert_eq!(
            Amount::ONE_DIVI.as_sat(),
            COIN,
            "ONE_DIVI should equal COIN ({} satoshis)",
            COIN
        );
        assert_eq!(Amount::ONE_DIVI.as_divi(), 1);
    }

    // ---- NEW: MAX_MONEY ----

    #[test]
    fn test_amount_max_money() {
        use crate::constants::MAX_MONEY;
        // 21 billion DIVI
        assert_eq!(MAX_MONEY.as_divi(), 21_000_000_000i64);
        assert!(MAX_MONEY.is_positive());
    }

    // ---- NEW: f64 conversion precision ----

    #[test]
    fn test_amount_from_divi_f64_precision() {
        // 1.5 DIVI = 150_000_000 satoshis
        let amt = Amount::from_divi_f64(1.5);
        assert_eq!(amt.as_sat(), 150_000_000);
    }

    #[test]
    fn test_amount_from_divi_f64_small() {
        // 0.001 DIVI = 100_000 satoshis
        let amt = Amount::from_divi_f64(0.001);
        assert_eq!(amt.as_sat(), 100_000);
    }

    #[test]
    fn test_amount_as_divi_f64_fractional() {
        let amt = Amount::from_sat(50_000_000); // 0.5 DIVI
        let f = amt.as_divi_f64();
        assert!((f - 0.5).abs() < 1e-9, "Expected 0.5, got {}", f);
    }

    // ---- NEW: checked / saturating arithmetic ----

    #[test]
    fn test_amount_checked_add_ok() {
        let a = Amount::from_divi(10);
        let b = Amount::from_divi(5);
        let result = a.checked_add(b).unwrap();
        assert_eq!(result.as_divi(), 15);
    }

    #[test]
    fn test_amount_checked_add_overflow() {
        let max = Amount(i64::MAX);
        let one = Amount::ONE_SAT;
        assert!(
            max.checked_add(one).is_none(),
            "i64::MAX + 1 should overflow"
        );
    }

    #[test]
    fn test_amount_checked_sub_ok() {
        let a = Amount::from_divi(10);
        let b = Amount::from_divi(3);
        let result = a.checked_sub(b).unwrap();
        assert_eq!(result.as_divi(), 7);
    }

    #[test]
    fn test_amount_checked_sub_underflow() {
        let min = Amount(i64::MIN);
        let one = Amount::ONE_SAT;
        assert!(
            min.checked_sub(one).is_none(),
            "i64::MIN - 1 should underflow"
        );
    }

    #[test]
    fn test_amount_saturating_add() {
        let max = Amount(i64::MAX);
        let one = Amount::ONE_SAT;
        let result = max.saturating_add(one);
        assert_eq!(
            result,
            Amount(i64::MAX),
            "saturating_add should clamp at i64::MAX"
        );
    }

    #[test]
    fn test_amount_saturating_sub() {
        let min = Amount(i64::MIN);
        let one = Amount::ONE_SAT;
        let result = min.saturating_sub(one);
        assert_eq!(
            result,
            Amount(i64::MIN),
            "saturating_sub should clamp at i64::MIN"
        );
    }

    // ---- NEW: From<i64> / Into<i64> ----

    #[test]
    fn test_amount_from_into_i64() {
        let sat: i64 = 123_456_789;
        let amt = Amount::from(sat);
        assert_eq!(amt.as_sat(), sat);
        let back: i64 = amt.into();
        assert_eq!(back, sat);
    }

    // ---- NEW: AddAssign / SubAssign ----

    #[test]
    fn test_amount_add_assign() {
        let mut a = Amount::from_divi(10);
        a += Amount::from_divi(5);
        assert_eq!(a.as_divi(), 15);
    }

    #[test]
    fn test_amount_sub_assign() {
        let mut a = Amount::from_divi(10);
        a -= Amount::from_divi(3);
        assert_eq!(a.as_divi(), 7);
    }

    // ---- NEW: display for various fractional forms ----

    #[test]
    fn test_amount_display_zero_satoshi() {
        // Display should show "0 DIVI" not "0.00000000 DIVI"
        assert_eq!(format!("{}", Amount::ZERO), "0 DIVI");
    }

    #[test]
    fn test_amount_display_one_sat() {
        // 1 satoshi = 0.00000001 DIVI
        assert_eq!(format!("{}", Amount::ONE_SAT), "0.00000001 DIVI");
    }

    #[test]
    fn test_amount_serialization_little_endian_layout() {
        // Amount(1) should serialize as [01 00 00 00 00 00 00 00] (LE i64)
        let amt = Amount::from_sat(1);
        let encoded = serialize(&amt);
        assert_eq!(
            encoded,
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_amount_encoded_size_always_eight() {
        assert_eq!(Amount::ZERO.encoded_size(), 8);
        assert_eq!(Amount::ONE_DIVI.encoded_size(), 8);
        assert_eq!(Amount(i64::MAX).encoded_size(), 8);
        assert_eq!(Amount(i64::MIN).encoded_size(), 8);
    }
}
