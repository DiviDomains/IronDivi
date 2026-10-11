// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Chain-agnostic cryptography for the DIVI<->XMR adaptor-signature swap
//! (`docs/plans/swap-poc/xmr-design.md`): ECDSA adaptor signatures
//! ([`adaptor`]) and the cross-group (secp256k1 / ed25519) discrete-log
//! equality proof ([`dleq`]) that binds an adaptor secret to a Monero
//! spend-key share. No DIVI or Monero I/O here — see `crates/swap-chain-xmr`
//! for the DIVI-side transaction templates this feeds.

pub mod adaptor;
pub mod dleq;
