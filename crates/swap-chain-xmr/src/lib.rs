// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! DIVI-side transaction building for the DIVI<->XMR adaptor-signature swap
//! (`docs/plans/swap-poc/xmr-design.md`): the `Tx_lock`/`Tx_cancel`-shaped 2-of-2 P2SH
//! output and presigned spends of it ([`multisig`], build-plan step 2), proving the
//! `nLockTime` schedule (not CSV/CLTV — see its docs) is enforced; and the bridge from a
//! `swap-adaptor` ECDSA adaptor signature into a DIVI scriptSig ([`adaptor_bridge`]),
//! proving a completed adaptor signature satisfies `OP_CHECKMULTISIG` exactly like a
//! plain one. The cross-group DLEQ and the Monero side are not here yet — DLEQ lives in
//! `swap-adaptor`, Monero is a later build-plan step.

pub mod adaptor_bridge;
pub mod multisig;

#[cfg(test)]
mod tests;
