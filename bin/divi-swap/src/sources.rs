// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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
//! the helper the daemon uses ([`divi_swap::operator`]). On mainnet, every DIVI source on
//! one operator is refused unless `--allow-single-source` (then warned at every start, as
//! the daemon's `allow_single_source`); one ZEC operator is warned.

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

/// The taker's DIVI start rule, the daemon's `require_second_source` for the taker: where
/// [`divi_warning`] fires, `Err` refuses the start unless `allow_single_source`, and with it
/// `Ok(Some(warning))`, to be printed at every start; `Ok(None)` otherwise.
pub fn check_divi(
    mainnet: bool,
    allow_single_source: bool,
    default: &str,
    sources: &[String],
) -> Result<Option<String>, String> {
    let Some(w) = divi_warning(mainnet, default, sources) else {
        return Ok(None);
    };
    if !allow_single_source {
        return Err(format!(
            "{w} A mainnet taker needs a second, independent DIVI source; set one, or pass \
             --allow-single-source to run on one source deliberately"
        ));
    }
    Ok(Some(format!(
        "{w} This mainnet taker runs on a single DIVI operator (--allow-single-source): one \
         lying or broken endpoint is trusted for HTLC, confirmation and spend reads"
    )))
}
