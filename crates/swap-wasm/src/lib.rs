// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The swap taker for the IronDivi browser extension.
//!
//! Runs the [`divi_swap::Taker`] in the extension's service worker: swap records are sealed
//! under a seed-derived key ([`store`]), flushed to the host before any broadcast
//! ([`durable`]), and only a whitelisted summary of each swap reaches the UI ([`view`]).
//! Testnet only.

pub mod durable;
pub mod engine;
pub mod maker;
pub mod store;
pub mod view;

#[cfg(target_arch = "wasm32")]
mod bindings;

#[cfg(test)]
mod tests;

pub use durable::{Durable, Persister, Sink};
pub use engine::{Addresses, CoinIn, Config, Engine};
pub use maker::MakerClient;
pub use store::{store_prefix, EncryptedStore, Entry};
pub use view::SwapSummary;
