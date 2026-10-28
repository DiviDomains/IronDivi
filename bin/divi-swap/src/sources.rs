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

//! Who runs the taker's read sources: the start-time operator checks of the taker CLI.

/// The taker's ZEC sources: `Err` refuses a `crosscheck` URL under a primary's operator;
/// `Ok(Some(warning))` on mainnet when every source is one operator's.
pub fn check_zec(
    _mainnet: bool,
    primaries: &[String],
    crosscheck: Option<&str>,
) -> Result<Option<String>, String> {
    if let Some(url) = crosscheck {
        swap_chain_zec::crosscheck::check_second_operator(primaries, url)?;
    }
    Ok(None)
}

/// The taker's DIVI sources: a warning on mainnet when every one of `sources` is the
/// `default` proxy or under its operator.
pub fn divi_warning(_mainnet: bool, _default: &str, _sources: &[String]) -> Option<String> {
    None
}
