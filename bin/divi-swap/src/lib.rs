// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Taker + operator CLI library: a typed client for the maker's HTTP API and the taker flow.

pub mod client;
pub mod flow;
pub mod session;
pub mod txids;
pub mod wallet;

pub use client::MakerClient;
pub use flow::{run_swap, run_swap_gated, ClaimGate, ClaimPolicy, RunOpts};
pub use session::Sessions;
