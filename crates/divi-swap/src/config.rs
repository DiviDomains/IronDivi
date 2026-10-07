// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Timeout and confirmation profiles (plan §3.1). Config, not constants.

use serde::{Deserialize, Serialize};

use crate::error::{Result, SwapError};

/// Named profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Production timeouts.
    Mainnet,
    /// Public testnets (DIVI testnet, BTC signet).
    Testnet,
}

/// Swap timing and confirmation requirements. All durations in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapConfig {
    /// Taker's BTC HTLC: refund locktime = lock time + this.
    pub taker_timeout_secs: u32,
    /// Maker's DIVI HTLC: refund locktime = lock time + this.
    pub maker_timeout_secs: u32,
    /// Confirmations required on the taker's BTC lock before the maker locks.
    pub btc_confirmations: u32,
    /// Confirmations required on the maker's DIVI lock before the taker claims.
    pub divi_confirmations: u32,
    /// How far BTC median time past lags wall clock (≈ 1 h).
    pub btc_mtp_lag_secs: u32,
    /// Time the maker needs to get its BTC claim confirmed after learning the preimage.
    pub claim_margin_secs: u32,
    /// Quote validity.
    pub quote_expiry_secs: u32,
}

impl SwapConfig {
    /// Minimum gap between the two timeouts regardless of the other parameters.
    pub const MIN_TIMEOUT_GAP_SECS: u32 = 3 * 3600;

    /// The built-in profile.
    pub fn profile(p: Profile) -> Self {
        match p {
            Profile::Mainnet => SwapConfig {
                taker_timeout_secs: 24 * 3600,
                maker_timeout_secs: 12 * 3600,
                btc_confirmations: 2,
                divi_confirmations: 10,
                btc_mtp_lag_secs: 3600,
                claim_margin_secs: 3600,
                quote_expiry_secs: 60,
            },
            Profile::Testnet => SwapConfig {
                taker_timeout_secs: 6 * 3600,
                maker_timeout_secs: 3 * 3600,
                btc_confirmations: 1,
                divi_confirmations: 3,
                btc_mtp_lag_secs: 3600,
                claim_margin_secs: 1800,
                quote_expiry_secs: 60,
            },
        }
    }

    /// Required minimum of `taker_timeout − maker_timeout`.
    pub fn required_gap_secs(&self) -> u32 {
        Self::MIN_TIMEOUT_GAP_SECS.max(2 * self.btc_mtp_lag_secs + self.claim_margin_secs)
    }

    /// Enforce `taker_timeout − maker_timeout ≥ max(3 h, 2 × BTC MTP lag + claim margin)`.
    ///
    /// ```
    /// use divi_swap::{Profile, SwapConfig};
    /// assert!(SwapConfig::profile(Profile::Testnet).validate().is_ok());
    /// let mut c = SwapConfig::profile(Profile::Testnet);
    /// c.maker_timeout_secs = 4 * 3600;
    /// assert!(c.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        let gap = self
            .taker_timeout_secs
            .checked_sub(self.maker_timeout_secs)
            .ok_or_else(|| {
                SwapError::InvalidParams("taker timeout must exceed maker timeout".into())
            })?;
        if gap < self.required_gap_secs() {
            return Err(SwapError::InvalidParams(format!(
                "timeout gap {gap}s < required {}s",
                self.required_gap_secs()
            )));
        }
        if self.btc_confirmations == 0 || self.divi_confirmations == 0 {
            return Err(SwapError::InvalidParams(
                "confirmations must be at least 1".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_profiles_valid() {
        SwapConfig::profile(Profile::Mainnet).validate().unwrap();
        SwapConfig::profile(Profile::Testnet).validate().unwrap();
    }

    #[test]
    fn lag_dominates_gap() {
        let mut c = SwapConfig::profile(Profile::Testnet);
        c.btc_mtp_lag_secs = 2 * 3600;
        assert_eq!(c.required_gap_secs(), 4 * 3600 + 1800);
        assert!(c.validate().is_err());
    }
}
