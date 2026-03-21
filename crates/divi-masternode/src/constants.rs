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

//! Consensus-critical constants for the Divi masternode system.
//!
//! These constants define fork activation heights and other consensus parameters
//! that MUST match the C++ Divi implementation exactly to avoid chain splits.

/// Fork height at which masternode payment validation becomes active.
///
/// Before this height, masternode payments are not validated.
/// At and after this height, blocks must pay the correct masternode winner.
///
/// This matches the C++ Divi fork activation at block 205,000.
pub const MASTERNODE_PAYMENT_FORK_HEIGHT: u32 = 205_000;

/// Masternode payment percentage before the fork (45%)
pub const MASTERNODE_PAYMENT_PERCENTAGE_PRE_FORK: f64 = 0.45;

/// Masternode payment percentage after the fork (60%)
pub const MASTERNODE_PAYMENT_PERCENTAGE_POST_FORK: f64 = 0.60;
