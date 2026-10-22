// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Named EVM networks (two testnets, two mainnets) this crate knows defaults for. [`UsdcBackend`](crate::UsdcBackend)
//! itself is network-agnostic — it only ever sees an RPC URL, an HTLC address and a token
//! address, all supplied by the caller — so this enum is pure convenience: it lets a config
//! file or CLI flag say `"base-sepolia"` instead of spelling out the token address and a
//! public RPC URL by hand.

use std::fmt;
use std::str::FromStr;

use crate::{BASE_SEPOLIA_USDC, BASE_USDC, ETHEREUM_USDC, SEPOLIA_USDC};

/// An EVM network `UsdcBackend` can run on. Picks defaults for the USDC token address and a
/// free public RPC endpoint; both can still be overridden explicitly by the caller.
/// `Ethereum` and `Base` are mainnets (real money): see [`UsdcNetwork::is_mainnet`]; the
/// daemon and CLI refuse them without an explicit `allow_mainnet` / `--allow-mainnet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsdcNetwork {
    #[default]
    Sepolia,
    BaseSepolia,
    /// Ethereum mainnet (chain id 1), native Circle USDC.
    Ethereum,
    /// Base mainnet (chain id 8453), native Circle USDC.
    Base,
}

impl UsdcNetwork {
    /// Circle USDC on this network (test USDC on the testnets, native USDC on mainnets).
    pub fn usdc_token(self) -> &'static str {
        match self {
            UsdcNetwork::Sepolia => SEPOLIA_USDC,
            UsdcNetwork::BaseSepolia => BASE_SEPOLIA_USDC,
            UsdcNetwork::Ethereum => ETHEREUM_USDC,
            UsdcNetwork::Base => BASE_USDC,
        }
    }

    /// A free public RPC endpoint for this network (no API key needed). Still overridable:
    /// this is only the default when a caller doesn't supply its own.
    pub fn default_rpc_url(self) -> &'static str {
        match self {
            UsdcNetwork::Sepolia => "https://ethereum-sepolia-rpc.publicnode.com",
            UsdcNetwork::BaseSepolia => "https://sepolia.base.org",
            UsdcNetwork::Ethereum => "https://ethereum-rpc.publicnode.com",
            UsdcNetwork::Base => "https://mainnet.base.org",
        }
    }

    /// This network's chain id (<https://chainlist.org>). Informational only — alloy reads
    /// the chain id from the RPC itself when signing, so nothing here enforces it; it is a
    /// convenience for anyone wiring up monitoring or sanity checks.
    pub fn chain_id(self) -> u64 {
        match self {
            UsdcNetwork::Sepolia => 11_155_111,
            UsdcNetwork::BaseSepolia => 84_532,
            UsdcNetwork::Ethereum => 1,
            UsdcNetwork::Base => 8_453,
        }
    }

    /// `true` for the networks that move real money (`Ethereum`, `Base`).
    pub fn is_mainnet(self) -> bool {
        matches!(self, UsdcNetwork::Ethereum | UsdcNetwork::Base)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            UsdcNetwork::Sepolia => "sepolia",
            UsdcNetwork::BaseSepolia => "base-sepolia",
            UsdcNetwork::Ethereum => "ethereum",
            UsdcNetwork::Base => "base",
        }
    }
}

impl FromStr for UsdcNetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sepolia" => Ok(UsdcNetwork::Sepolia),
            "base-sepolia" => Ok(UsdcNetwork::BaseSepolia),
            "ethereum" => Ok(UsdcNetwork::Ethereum),
            "base" => Ok(UsdcNetwork::Base),
            other => Err(format!(
                "unknown USDC network {other:?} (want \"sepolia\", \"base-sepolia\", \
                 \"ethereum\" or \"base\")"
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

    const ALL: [UsdcNetwork; 4] = [
        UsdcNetwork::Sepolia,
        UsdcNetwork::BaseSepolia,
        UsdcNetwork::Ethereum,
        UsdcNetwork::Base,
    ];

    #[test]
    fn round_trips_through_its_own_string_form() {
        for n in ALL {
            assert_eq!(n.as_str().parse::<UsdcNetwork>().unwrap(), n);
            assert_eq!(n.to_string(), n.as_str());
        }
        assert_eq!(UsdcNetwork::Ethereum.as_str(), "ethereum");
        assert_eq!(UsdcNetwork::Base.as_str(), "base");
    }

    #[test]
    fn defaults_to_sepolia() {
        assert_eq!(UsdcNetwork::default(), UsdcNetwork::Sepolia);
    }

    #[test]
    fn each_network_has_a_distinct_token_and_chain_id() {
        assert_eq!(UsdcNetwork::Sepolia.usdc_token(), SEPOLIA_USDC);
        assert_eq!(UsdcNetwork::BaseSepolia.usdc_token(), BASE_SEPOLIA_USDC);
        assert_eq!(UsdcNetwork::Ethereum.usdc_token(), ETHEREUM_USDC);
        assert_eq!(UsdcNetwork::Base.usdc_token(), BASE_USDC);
        assert_eq!(UsdcNetwork::BaseSepolia.chain_id(), 84_532);
        assert_eq!(UsdcNetwork::Ethereum.chain_id(), 1);
        assert_eq!(UsdcNetwork::Base.chain_id(), 8_453);
        for (i, a) in ALL.iter().enumerate() {
            for b in &ALL[i + 1..] {
                assert_ne!(a.chain_id(), b.chain_id(), "{a} vs {b}");
                assert_ne!(
                    a.usdc_token().to_lowercase(),
                    b.usdc_token().to_lowercase(),
                    "{a} vs {b}"
                );
                assert_ne!(a.default_rpc_url(), b.default_rpc_url(), "{a} vs {b}");
            }
        }
    }

    #[test]
    fn is_mainnet_truth_table() {
        assert!(!UsdcNetwork::Sepolia.is_mainnet());
        assert!(!UsdcNetwork::BaseSepolia.is_mainnet());
        assert!(UsdcNetwork::Ethereum.is_mainnet());
        assert!(UsdcNetwork::Base.is_mainnet());
    }

    #[test]
    fn rejects_unknown_names() {
        let e = "mainnet".parse::<UsdcNetwork>().unwrap_err();
        for name in ["sepolia", "base-sepolia", "ethereum", "base"] {
            assert!(e.contains(&format!("{name:?}")), "{e}");
        }
        assert!("".parse::<UsdcNetwork>().is_err());
    }
}
