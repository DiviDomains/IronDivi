// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! DIVI-side presigned 2-of-2 multisig skeleton for the DIVI<->XMR adaptor-signature swap
//! (`docs/plans/swap-poc/xmr-design.md`, build-plan step 2). Builds and verifies the
//! `Tx_lock`/`Tx_cancel`-shaped 2-of-2 P2SH output and presigned spends of it, and proves
//! the `nLockTime` schedule (not CSV/CLTV — see [`multisig`] docs) is enforced. The
//! adaptor-signature and cross-group-DLEQ pieces live in `swap-adaptor`; the full
//! `Tx_refund`/`Tx_punish`/`Tx_redeem` wiring and Monero side are later build-plan steps.

pub mod multisig;

#[cfg(test)]
mod tests;
