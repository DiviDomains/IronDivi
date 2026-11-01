// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Named EVM testnets this crate knows defaults for. [`UsdcBackend`](crate::UsdcBackend)
//! itself is network-agnostic — it only ever sees an RPC URL, an HTLC address and a token
//! address, all supplied by the caller — so this enum is pure convenience: it lets a config
//! file or CLI flag say `"base-sepolia"` instead of spelling out the token address and a
//! public RPC URL by hand.

use std::fmt;
use std::str::FromStr;

use crate::{BASE_SEPOLIA_USDC, SEPOLIA_USDC};

/// An EVM testnet `UsdcBackend` can run on. Picks defaults for the USDC token address and a
/// free public RPC endpoint; both can still be overridden explicitly by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsdcNetwork {
    #[default]
    Sepolia,
    BaseSepolia,
}

impl UsdcNetwork {
    /// Circle test USDC on this network.
    pub fn usdc_token(self) -> &'static str {
        match self {
            UsdcNetwork::Sepolia => SEPOLIA_USDC,
            UsdcNetwork::BaseSepolia => BASE_SEPOLIA_USDC,
        }
    }

    /// A free public RPC endpoint for this network (no API key needed). Still overridable:
    /// this is only the default when a caller doesn't supply its own.
    pub fn default_rpc_url(self) -> &'static str {
        match self {
            UsdcNetwork::Sepolia => "https://ethereum-sepolia-rpc.publicnode.com",
            UsdcNetwork::BaseSepolia => "https://sepolia.base.org",
        }
    }

    /// This network's chain id (<https://chainlist.org>). Informational only — alloy reads
    /// the chain id from the RPC itself when signing, so nothing here enforces it; it is a
    /// convenience for anyone wiring up monitoring or sanity checks.
    pub fn chain_id(self) -> u64 {
        match self {
            UsdcNetwork::Sepolia => 11_155_111,
            UsdcNetwork::BaseSepolia => 84_532,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            UsdcNetwork::Sepolia => "sepolia",
            UsdcNetwork::BaseSepolia => "base-sepolia",
        }
    }
}

impl FromStr for UsdcNetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sepolia" => Ok(UsdcNetwork::Sepolia),
            "base-sepolia" => Ok(UsdcNetwork::BaseSepolia),
            other => Err(format!(
                "unknown USDC network {other:?} (want \"sepolia\" or \"base-sepolia\")"
            )),
        }
    }
}

impl fmt::Display for UsdcNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_its_own_string_form() {
        for n in [UsdcNetwork::Sepolia, UsdcNetwork::BaseSepolia] {
            assert_eq!(n.as_str().parse::<UsdcNetwork>().unwrap(), n);
            assert_eq!(n.to_string(), n.as_str());
        }
    }

    #[test]
    fn defaults_to_sepolia() {
        assert_eq!(UsdcNetwork::default(), UsdcNetwork::Sepolia);
    }

    #[test]
    fn each_network_has_a_distinct_token_and_chain_id() {
        assert_eq!(UsdcNetwork::Sepolia.usdc_token(), SEPOLIA_USDC);
        assert_eq!(UsdcNetwork::BaseSepolia.usdc_token(), BASE_SEPOLIA_USDC);
        assert_ne!(
            UsdcNetwork::Sepolia.chain_id(),
            UsdcNetwork::BaseSepolia.chain_id()
        );
        assert_eq!(UsdcNetwork::BaseSepolia.chain_id(), 84_532);
    }

    #[test]
    fn rejects_unknown_names() {
        assert!("mainnet".parse::<UsdcNetwork>().is_err());
        assert!("".parse::<UsdcNetwork>().is_err());
    }
}
