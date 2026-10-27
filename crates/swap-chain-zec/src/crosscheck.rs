// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Opt-in ZEC tip cross-check against a **second lightwalletd operator**.
//!
//! The mainnet default endpoints ([`crate::MAINNET_LIGHTWALLETD`]) are three hostnames under
//! one operator's domain, and [`crate::LIGHTWALLETD_EXTRA_ENV`] only appends failover
//! endpoints, so one operator can show a fake tip. This asks a lightwalletd run by someone
//! else for its tip, and compares the block hashes at the lower of the two tips and
//! [`CROSSCHECK_DEPTH`] below it. It is a sanity check, not a UTXO source, and it changes no
//! confirmation count, lag, timeout or failover order.
//!
//! The lower tip (not the primary's) is used so that the few seconds by which one operator
//! leads the other cannot cause a false `Disagree`; a lag of more than [`MAX_LAG`] blocks is
//! `Unavailable` (the second operator is behind), not a comparison.

use divi_swap::{Outpoint, SwapError};

use crate::grpc::LightwalletdClient;

type Result<T> = std::result::Result<T, SwapError>;

/// How far below the compared tip the second compared block sits. A comparison depth only —
/// it is **not** a confirmation count and nothing else reads it.
pub const CROSSCHECK_DEPTH: u64 = 6;

/// The largest tip difference (blocks) still compared. Beyond it the lagging side cannot
/// vouch for the other's recent blocks: [`CrossCheckOutcome::Unavailable`].
pub const MAX_LAG: u64 = 6;

/// Result of one cross-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCheckOutcome {
    /// Both operators report the same hashes at `height` and `height - CROSSCHECK_DEPTH`.
    Agree { height: u64, hash: String },
    /// They report different hashes at `height`: refuse to proceed.
    Disagree {
        height: u64,
        primary_hash: String,
        primary_url: String,
        other_hash: String,
        other_url: String,
    },
    /// Could not compare (unreachable, malformed answer, one side too far behind).
    Unavailable { reason: String },
}

impl CrossCheckOutcome {
    /// The refusal text for a `Disagree`, naming both endpoints and both hashes.
    pub fn disagree_message(&self) -> Option<String> {
        match self {
            Self::Disagree {
                height,
                primary_hash,
                primary_url,
                other_hash,
                other_url,
            } => Some(format!(
                "zec tip cross-check FAILED at height {height}: primary lightwalletd \
                 {primary_url} says {primary_hash}, second operator {other_url} says \
                 {other_hash}; refusing"
            )),
            _ => None,
        }
    }
}

/// The primary list as the messages name it (the endpoint that answered is not reported by
/// the failover client, so every candidate is named).
fn primary_label(primary: &LightwalletdClient) -> String {
    primary.endpoints().join(", ")
}

fn other_label(other: &LightwalletdClient) -> String {
    other.endpoints().join(", ")
}

/// Compare `primary` with `other` (the second operator). Never returns an error: every
/// failure is [`CrossCheckOutcome::Unavailable`] so the caller applies the policy.
pub async fn tip_crosscheck(
    primary: &LightwalletdClient,
    other: &LightwalletdClient,
) -> CrossCheckOutcome {
    let unavailable = |reason: String| CrossCheckOutcome::Unavailable { reason };
    let (primary_url, other_url) = (primary_label(primary), other_label(other));
    let (p_tip, o_tip) = match tokio::join!(primary.latest_block(), other.latest_block()) {
        (Ok(p), Ok(o)) => (p.height, o.height),
        (Err(e), _) => return unavailable(format!("{primary_url}: tip: {e:?}")),
        (_, Err(e)) => return unavailable(format!("{other_url}: tip: {e:?}")),
    };
    let height = p_tip.min(o_tip);
    let lag = p_tip.abs_diff(o_tip);
    if lag > MAX_LAG {
        return unavailable(format!(
            "tips {lag} blocks apart (primary {primary_url} at {p_tip}, second operator \
             {other_url} at {o_tip}; more than {MAX_LAG})"
        ));
    }
    let Some(deep) = height.checked_sub(CROSSCHECK_DEPTH) else {
        return unavailable(format!("tip {height} below depth {CROSSCHECK_DEPTH}"));
    };
    // The compared tip first: a lie there is the one that matters for a broadcast now.
    let mut agreed = None;
    for h in [height, deep] {
        let (p, o) = match tokio::join!(block_hash(primary, h), block_hash(other, h)) {
            (Ok(p), Ok(o)) => (p, o),
            (Err(e), _) => return unavailable(format!("{primary_url}: {e}")),
            (_, Err(e)) => return unavailable(format!("{other_url}: {e}")),
        };
        if p != o {
            return CrossCheckOutcome::Disagree {
                height: h,
                primary_hash: p,
                primary_url,
                other_hash: o,
                other_url,
            };
        }
        agreed.get_or_insert(p);
    }
    CrossCheckOutcome::Agree {
        height,
        hash: agreed.expect("two heights compared"),
    }
}

/// The display-order hash of the block at `height`, refusing an answer for another height.
async fn block_hash(
    client: &LightwalletdClient,
    height: u64,
) -> std::result::Result<String, String> {
    let block = client
        .block(height)
        .await
        .map_err(|e| format!("block {height}: {e:?}"))?;
    if block.height != height {
        return Err(format!(
            "GetBlock({height}) answered block {}",
            block.height
        ));
    }
    crate::display_block_hash(&block.hash).map_err(|e| format!("block {height}: {e}"))
}

/// Startup policy: `Disagree` is [`SwapError::Transient`] naming both endpoints,
/// `Unavailable` logs a warning and continues.
pub async fn enforce_at_startup(
    primary: &LightwalletdClient,
    other: &LightwalletdClient,
) -> Result<()> {
    let second = other_label(other);
    match tip_crosscheck(primary, other).await {
        CrossCheckOutcome::Agree { height, hash } => {
            tracing::info!(height, %hash, second_operator = %second, "zec tip cross-check agrees");
            Ok(())
        }
        CrossCheckOutcome::Unavailable { reason } => {
            tracing::warn!(
                %reason, second_operator = %second,
                "zec tip cross-check unavailable at startup; continuing (claims and refunds \
                 wait for it)"
            );
            Ok(())
        }
        d @ CrossCheckOutcome::Disagree { .. } => Err(SwapError::Transient(
            d.disagree_message().expect("disagree"),
        )),
    }
}

/// Before a claim or refund (`what`) of `at`: `Disagree` and `Unavailable` are both
/// [`SwapError::Transient`] (fail closed; the engine retries).
pub async fn enforce_before_spend(
    primary: &LightwalletdClient,
    other: &LightwalletdClient,
    what: &str,
    at: &Outpoint,
) -> Result<()> {
    match tip_crosscheck(primary, other).await {
        CrossCheckOutcome::Agree { height, hash } => {
            tracing::debug!(height, %hash, outpoint = %at, "zec {what} cross-check agrees");
            Ok(())
        }
        CrossCheckOutcome::Unavailable { reason } => Err(SwapError::Transient(format!(
            "zec tip cross-check unavailable ({reason}); second operator {}: {what} of {at} \
             held until it answers",
            other_label(other)
        ))),
        d @ CrossCheckOutcome::Disagree { .. } => Err(SwapError::Transient(format!(
            "{}; {what} of {at} held",
            d.disagree_message().expect("disagree")
        ))),
    }
}

/// Second-level labels under which a two-letter country code is a public suffix
/// (`example.co.uk`). An approximation of the Public Suffix List, enough to tell two
/// lightwalletd operators apart; it does not know private suffixes.
const CC_SECOND_LEVEL: [&str; 7] = ["ac", "co", "com", "edu", "gov", "net", "org"];

/// The operator a lightwalletd URL belongs to: its host's registrable domain (the last two
/// DNS labels, three under a `co.uk`-style suffix), or the host itself for an IP address or
/// a one-label name. `None` when `url` is not an `http(s)://host…` URL.
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

/// `Ok` when `url` is a usable second operator for `primaries`: it has a host, and that host
/// is not under the registrable domain of **any** primary endpoint (one shared with a
/// failover endpoint would compare that operator with itself whenever the primary fails
/// over to it).
pub fn check_second_operator(primaries: &[String], url: &str) -> std::result::Result<(), String> {
    let domain =
        operator_domain(url).ok_or_else(|| format!("{url:?} is not an https://host:port URL"))?;
    if let Some(p) = primaries
        .iter()
        .find(|p| operator_domain(p).as_deref() == Some(domain.as_str()))
    {
        return Err(format!(
            "{url} is under {domain}, the same operator as the lightwalletd endpoint {p}: \
             that is not a second operator"
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use divi_swap::Txid;

    use super::*;
    use crate::grpc::RetryPolicy;
    use crate::lwd_stub::Lightwalletd;

    const TIP: u64 = 40;

    fn fast() -> RetryPolicy {
        RetryPolicy {
            attempts: 1,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
        }
    }

    fn client(url: &str) -> LightwalletdClient {
        LightwalletdClient::new(vec![url.to_string()], fast()).unwrap()
    }

    fn at() -> Outpoint {
        Outpoint {
            txid: Txid([0x42; 32]),
            vout: 0,
        }
    }

    #[tokio::test]
    async fn two_operators_on_one_chain_agree_at_the_tip() {
        let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
        let out = tip_crosscheck(&client(p.endpoint()), &client(o.endpoint())).await;
        assert_eq!(
            out,
            CrossCheckOutcome::Agree {
                height: TIP,
                hash: p.hash_at(TIP)
            }
        );
        enforce_at_startup(&client(p.endpoint()), &client(o.endpoint()))
            .await
            .unwrap();
        enforce_before_spend(&client(p.endpoint()), &client(o.endpoint()), "claim", &at())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_different_hash_at_the_tip_or_six_below_is_transient_naming_both_endpoints() {
        for height in [TIP, TIP - CROSSCHECK_DEPTH] {
            let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
            o.tamper(height);
            let (pc, oc) = (client(p.endpoint()), client(o.endpoint()));
            let out = tip_crosscheck(&pc, &oc).await;
            assert!(
                matches!(out, CrossCheckOutcome::Disagree { height: h, .. } if h == height),
                "{height}: {out:?}"
            );
            let msg = out.disagree_message().expect("disagree");
            for needle in [p.endpoint(), o.endpoint()] {
                assert!(msg.contains(needle), "{msg} lacks {needle}");
            }
            for err in [
                enforce_at_startup(&pc, &oc).await.unwrap_err(),
                enforce_before_spend(&pc, &oc, "refund", &at())
                    .await
                    .unwrap_err(),
            ] {
                let SwapError::Transient(m) = &err else {
                    panic!("{height}: not transient: {err:?}");
                };
                assert!(m.contains(p.endpoint()) && m.contains(o.endpoint()), "{m}");
            }
        }
    }

    #[tokio::test]
    async fn an_unreachable_second_operator_holds_a_spend_but_only_warns_at_startup() {
        let p = Lightwalletd::start(TIP);
        // Port 1 on loopback refuses.
        let (pc, oc) = (client(p.endpoint()), client("http://127.0.0.1:1"));
        assert!(
            matches!(
                tip_crosscheck(&pc, &oc).await,
                CrossCheckOutcome::Unavailable { .. }
            ),
            "unreachable must be unavailable"
        );
        enforce_at_startup(&pc, &oc)
            .await
            .expect("startup only warns");
        for what in ["claim", "refund"] {
            let err = enforce_before_spend(&pc, &oc, what, &at())
                .await
                .unwrap_err();
            let SwapError::Transient(m) = &err else {
                panic!("{what}: not transient: {err:?}");
            };
            assert!(m.contains("127.0.0.1:1") && m.contains(what), "{m}");
        }
    }

    #[tokio::test]
    async fn a_one_block_lag_compares_at_the_lower_tip() {
        // Either side may be the one behind.
        for (ph, oh) in [(TIP, TIP - 1), (TIP - 1, TIP)] {
            let (p, o) = (Lightwalletd::start(ph), Lightwalletd::start(oh));
            let out = tip_crosscheck(&client(p.endpoint()), &client(o.endpoint())).await;
            assert_eq!(
                out,
                CrossCheckOutcome::Agree {
                    height: TIP - 1,
                    hash: p.hash_at(TIP - 1)
                },
                "{ph}/{oh}"
            );
        }
    }

    #[tokio::test]
    async fn a_second_operator_far_behind_is_unavailable_not_a_comparison() {
        let (p, o) = (
            Lightwalletd::start(TIP),
            Lightwalletd::start(TIP - MAX_LAG - 1),
        );
        let (pc, oc) = (client(p.endpoint()), client(o.endpoint()));
        let out = tip_crosscheck(&pc, &oc).await;
        assert!(
            matches!(out, CrossCheckOutcome::Unavailable { .. }),
            "{out:?}"
        );
        assert!(matches!(
            enforce_before_spend(&pc, &oc, "claim", &at()).await,
            Err(SwapError::Transient(_))
        ));
    }

    #[test]
    fn operator_domain_is_the_registrable_domain() {
        for (url, want) in [
            ("https://zec.rocks:443", "zec.rocks"),
            ("https://na.zec.rocks:443", "zec.rocks"),
            ("https://EU.Zec.Rocks.:443", "zec.rocks"),
            ("https://lwd.example.co.uk:9067", "example.co.uk"),
            ("http://127.0.0.1:9067", "127.0.0.1"),
        ] {
            assert_eq!(operator_domain(url).as_deref(), Some(want), "{url}");
        }
        assert_eq!(operator_domain("not a url"), None);
    }

    #[test]
    fn a_crosscheck_url_of_the_primary_operator_is_refused() {
        let primaries: Vec<String> = crate::MAINNET_LIGHTWALLETD
            .iter()
            .map(|s| s.to_string())
            .collect();
        for same in ["https://zec.rocks:443", "https://ap.zec.rocks:9067"] {
            let e = check_second_operator(&primaries, same).unwrap_err();
            assert!(e.contains("zec.rocks"), "{e}");
        }
        check_second_operator(&primaries, "https://lwd.other-operator.net:9067").unwrap();
        assert!(check_second_operator(&primaries, "nonsense").is_err());
    }

    #[test]
    fn the_mainnet_defaults_are_one_operator() {
        let mut eps: Vec<String> = crate::MAINNET_LIGHTWALLETD
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(!has_second_operator(&eps));
        eps.push("not a url".into());
        assert!(!has_second_operator(&eps));
        eps.push("https://lwd.other-operator.net:9067".into());
        assert!(has_second_operator(&eps));
    }
}
