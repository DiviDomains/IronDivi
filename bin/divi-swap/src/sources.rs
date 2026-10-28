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

//! Who runs the taker's read sources: the start-time operator checks of the taker CLI, on
//! the helper the daemon uses ([`divi_swap::operator`]). On mainnet they warn; whether a
//! mainnet taker should be refused instead is Bert's call on the taker start rule.

use divi_swap::operator;

/// The taker's ZEC sources: `Err` refuses a `crosscheck` URL under a primary's operator (as
/// the daemon does); `Ok(Some(warning))` on mainnet when the daemon's second-operator rule
/// would refuse (no `crosscheck` and every primary one operator's), naming the endpoints.
pub fn check_zec(
    mainnet: bool,
    primaries: &[String],
    crosscheck: Option<&str>,
) -> Result<Option<String>, String> {
    if let Some(url) = crosscheck {
        operator::check_second_operator("lightwalletd endpoint", primaries, url)?;
    }
    if !mainnet || !operator::needs_second_operator(primaries, crosscheck) {
        return Ok(None);
    }
    Ok(Some(format!(
        "ZEC: every lightwalletd endpoint ({}) is one operator's and --zec-crosscheck-url is \
         unset: that operator alone can show this taker a ZEC lock that does not exist, or \
         hide or swallow a spend, and the taker acts on it (colluding-operators.md L2, L4). \
         Set --zec-crosscheck-url to a lightwalletd run by a second operator.",
        primaries.join(", ")
    )))
}

/// The taker's DIVI sources: a warning on mainnet when every one of `sources` is the
/// `default` proxy or under its operator, naming the endpoint and the risk.
pub fn divi_warning(mainnet: bool, default: &str, sources: &[String]) -> Option<String> {
    if !mainnet || !sources.iter().all(|s| operator::same_operator(s, default)) {
        return None;
    }
    Some(format!(
        "DIVI: every DIVI source of this taker ({}) is the default proxy {default} or under its \
         operator, which by its hostname is the project that runs the reference maker: one \
         operator can then show this taker a maker lock that does not exist and take the \
         taker's leg once it claims, or report a false median time (colluding-operators.md \
         L2, L4). Set --divi-rpc-url to an own DIVI node, or --divi-fallback-rpc-url to \
         another operator's.",
        sources.join(", ")
    ))
}
