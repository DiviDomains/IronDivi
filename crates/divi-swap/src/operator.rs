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

//! Who runs an endpoint: the registrable-domain heuristic behind every operator check (EH's
//! ZEC cross-check, the daemon's ZEC mainnet rule, and the taker CLI's DIVI and ZEC
//! warnings). It tells an accidental same-operator pair apart; it does not catch one operator
//! under two domains, two names on one IP, or one hosting provider.

/// Second-level labels under which a two-letter country code is a public suffix
/// (`example.co.uk`). An approximation of the Public Suffix List, enough to tell two
/// operators apart; it does not know private suffixes.
const CC_SECOND_LEVEL: [&str; 7] = ["ac", "co", "com", "edu", "gov", "net", "org"];

/// The operator an endpoint URL belongs to: its host's registrable domain (the last two DNS
/// labels, three under a `co.uk`-style suffix), or the host itself for an IP address or a
/// one-label name. `None` when `url` is not an `http(s)://host…` URL.
pub fn operator_domain(url: &str) -> Option<String> {
    let uri: http::Uri = url.trim().parse().ok()?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) {
        return None;
    }
    let host = uri
        .host()?
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Some(host);
    }
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    let keep = if n >= 3 && labels[n - 1].len() == 2 && CC_SECOND_LEVEL.contains(&labels[n - 2]) {
        3
    } else {
        2
    };
    Some(labels[n.saturating_sub(keep)..].join("."))
}

/// `Ok` when `url` is a usable second operator for `primaries` (each a `kind`, named in the
/// refusal): it has a host, and that host is not under the registrable domain of **any**
/// primary endpoint (one shared with a failover endpoint would compare that operator with
/// itself whenever the primary fails over to it).
pub fn check_second_operator(kind: &str, primaries: &[String], url: &str) -> Result<(), String> {
    let domain =
        operator_domain(url).ok_or_else(|| format!("{url:?} is not an https://host:port URL"))?;
    if let Some(p) = primaries
        .iter()
        .find(|p| operator_domain(p).as_deref() == Some(domain.as_str()))
    {
        return Err(format!(
            "{url} is under {domain}, the same operator as the {kind} {p}: that is not a \
             second operator"
        ));
    }
    Ok(())
}

/// Whether `endpoints` already span more than one operator (by [`operator_domain`]; an
/// endpoint that is not a URL counts as no operator).
pub fn has_second_operator(endpoints: &[String]) -> bool {
    let mut domains = endpoints.iter().filter_map(|e| operator_domain(e));
    match domains.next() {
        Some(first) => domains.any(|d| d != first),
        None => false,
    }
}

/// The mainnet second-operator rule: no `second` operator URL is set and every primary
/// endpoint is one operator's. The daemon refuses that on mainnet unless waived; the taker
/// CLI warns.
pub fn needs_second_operator(primaries: &[String], second: Option<&str>) -> bool {
    second.is_none() && !has_second_operator(primaries)
}

/// Whether `url` is `reference` itself (ignoring a trailing `/`) or under its operator.
pub fn same_operator(url: &str, reference: &str) -> bool {
    let norm = |u: &str| u.trim().trim_end_matches('/').to_ascii_lowercase();
    if norm(url) == norm(reference) {
        return true;
    }
    match (operator_domain(url), operator_domain(reference)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_operator_is_the_url_or_its_registrable_domain() {
        let proxy = "https://services.divi.domains/api/rpc/";
        assert!(same_operator(proxy, proxy));
        assert!(same_operator(
            "https://services.divi.domains/api/rpc",
            proxy
        ));
        assert!(same_operator("https://other.divi.domains:8443/x", proxy));
        assert!(!same_operator("http://127.0.0.1:51473", proxy));
        assert!(!same_operator("https://divi.own-node.example", proxy));
        assert!(!same_operator("not a url", proxy));
    }

    #[test]
    fn a_second_operator_is_needed_without_a_second_url_or_a_second_domain() {
        let one = vec!["https://a.x.org".to_string(), "https://b.x.org".to_string()];
        assert!(needs_second_operator(&one, None));
        assert!(!needs_second_operator(&one, Some("https://y.org")));
        let two = vec!["https://a.x.org".to_string(), "https://y.org".to_string()];
        assert!(!needs_second_operator(&two, None));
        assert!(needs_second_operator(&[], None));
    }
}
