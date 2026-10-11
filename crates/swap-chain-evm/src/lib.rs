// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! EVM (USDC) hash-time-locked contract client for the DIVI swap engine.
//!
//! The contract is `contracts/htlc/src/Erc20Htlc.sol` (Foundry; `forge test` there is the
//! contract's own acceptance). This crate is the alloy client against it: deploy, lock
//! (approve + lock), claim, refund, read swap state, and recover the preimage from
//! `Claimed` logs. See `docs/plans/swap-poc/usdc-design.md` for how an account chain like
//! this fits (or does not fit) the `divi_swap::ChainBackend` contract.

mod artifact;
mod backend;
mod contract;
mod embedded_bytecode;
mod network;

pub mod client;

pub use alloy::signers::local::PrivateKeySigner;
pub use artifact::{bytecode, foundry_available};
pub use backend::{amount_to_usdc_units, usdc_units_to_amount, UsdcBackend};
pub use client::{connect_provider, deploy_contract, swap_id, EvmHtlcClient, SwapState};
pub use contract::{IErc20, IErc20Htlc, IMockErc20};
pub use embedded_bytecode::{erc20_htlc_bytecode, ERC20_HTLC_BYTECODE_HEX};
pub use network::UsdcNetwork;

/// Circle test USDC — Ethereum Sepolia.
/// Source: <https://developers.circle.com/stablecoins/usdc-contract-addresses> and
/// confirmed on Sepolia Etherscan, 2026-10-11.
pub const SEPOLIA_USDC: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";

/// Circle test USDC — Base Sepolia.
/// Source: <https://developers.circle.com/stablecoins/usdc-contract-addresses>, 2026-10-11.
pub const BASE_SEPOLIA_USDC: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

#[cfg(test)]
mod tests;
