// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! DIVI `ChainBackend` over the services.divi.domains JSON-RPC proxy.
//!
//! Lane **divi** (docs/plans/swap-poc/lanes/divi.md) owns this crate. The Wave 0 live
//! proof (`examples/cltv_proof.rs`) shows the transaction shapes that the chain accepts.
