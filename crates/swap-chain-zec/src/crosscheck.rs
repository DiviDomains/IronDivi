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
//!
//! It also checks the lock itself (ET): every `htlc_output` (the maker about to fund against
//! the taker's lock, the taker about to claim the maker's) reads the output from the second
//! operator too ([`lock_view`]) and needs the agreed script and the same value there
//! ([`agree_lock`]), failing closed.

use divi_swap::{LockedOutput, Outpoint, SwapError};

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

/// A claim or refund the cross-check holds: the [`SwapError::Held`] to return, naming both
/// operators, and whether they disagreed (`false`: the second could not vouch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendHold {
    /// The error the build returns.
    pub error: SwapError,
    /// The operators reported different blocks (one of them is lying).
    pub disagree: bool,
}

/// Before a claim or refund (`what`) of `at`: `None` on agreement; `Disagree` and
/// `Unavailable` both hold it as [`SwapError::Held`] (fail closed; the engine retries until
/// its deadline for that spend, then builds it on the primary alone,
/// [`divi_swap::ChainBackend::primary_only`]).
pub async fn spend_hold(
    primary: &LightwalletdClient,
    other: &LightwalletdClient,
    what: &str,
    at: &Outpoint,
) -> Option<SpendHold> {
    match tip_crosscheck(primary, other).await {
        CrossCheckOutcome::Agree { height, hash } => {
            tracing::debug!(height, %hash, outpoint = %at, "zec {what} cross-check agrees");
            None
        }
        CrossCheckOutcome::Unavailable { reason } => Some(SpendHold {
            error: SwapError::Held(format!(
                "zec tip cross-check unavailable ({reason}); primary lightwalletd {}, second \
                 operator {}: {what} of {at} held until it answers",
                primary_label(primary),
                other_label(other)
            )),
            disagree: false,
        }),
        d @ CrossCheckOutcome::Disagree { .. } => Some(SpendHold {
            error: SwapError::Held(format!(
                "{}; {what} of {at} held",
                d.disagree_message().expect("disagree")
            )),
            disagree: true,
        }),
    }
}

/// [`spend_hold`] as a result: `Ok` on agreement, else its [`SwapError::Held`].
pub async fn enforce_before_spend(
    primary: &LightwalletdClient,
    other: &LightwalletdClient,
    what: &str,
    at: &Outpoint,
) -> Result<()> {
    match spend_hold(primary, other, what, at).await {
        None => Ok(()),
        Some(hold) => Err(hold.error),
    }
}

/// A lock output as the second operator shows it ([`lock_view`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockView {
    script_pubkey: Vec<u8>,
    value: u64,
    confirmations: u32,
}

/// `other`'s view of output `at`, read as the primary's is: `GetTransaction` (an answer that
/// is not `at`'s transaction is refused, [`crate::not_requested`]), then (when mined)
/// `GetLatestBlock` for its confirmations. An error completes "second operator …".
pub(crate) async fn lock_view(
    other: &LightwalletdClient,
    at: &Outpoint,
) -> std::result::Result<LockView, String> {
    let raw = other
        .get_transaction(&at.txid.0)
        .await
        .map_err(|e| format!("could not be read (GetTransaction: {e:?})"))?
        .ok_or_else(|| "has no such transaction".to_string())?;
    let parsed = crate::tx::ParsedTx::parse(&raw.data)
        .map_err(|e| format!("answered a transaction that does not parse ({e})"))?;
    if let Some(why) = crate::not_requested(&parsed, &at.txid.0) {
        return Err(why);
    }
    let out = parsed
        .vout
        .get(at.vout as usize)
        .ok_or_else(|| format!("has no output {} in that transaction", at.vout))?;
    let confirmations = if raw.height == 0 || raw.height == u64::MAX {
        0
    } else {
        let tip = other
            .latest_block()
            .await
            .map_err(|e| format!("could not be read (GetLatestBlock: {e:?})"))?
            .height;
        (tip.saturating_sub(raw.height) + 1) as u32
    };
    Ok(LockView {
        script_pubkey: out.script_pubkey.clone(),
        value: out.value,
        confirmations,
    })
}

/// Agree the primary's lock read (`mine`, already matched against the agreed script `want`)
/// with the second operator's (`theirs`), as `swap-chain-ltc`'s `agree_lock` (EL) and
/// `swap-chain-btc`'s `quorum::agree_htlc_output` do: the agreed script on both, equal
/// values, the lower confirmation count. Anything else, a second operator that could not be
/// read included, is [`SwapError::Transient`] naming both operators: the maker about to
/// fund and the taker about to reveal wait and read again.
pub(crate) fn agree_lock(
    at: &Outpoint,
    want: &[u8],
    mine: LockedOutput,
    primary: &LightwalletdClient,
    theirs: std::result::Result<LockView, String>,
    other: &LightwalletdClient,
) -> Result<LockedOutput> {
    let zat = mine.amount.to_sat();
    let refuse = |what: String| {
        SwapError::Transient(format!(
            "zec lock cross-check FAILED for {at}: primary lightwalletd {} shows the agreed \
             HTLC script with {zat} zat, second operator {} {what}; not acting on the lock",
            primary_label(primary),
            other_label(other)
        ))
    };
    match theirs {
        Err(what) => Err(refuse(what)),
        Ok(v) if v.script_pubkey != want => Err(refuse(format!(
            "shows scriptPubKey {} there",
            hex::encode(&v.script_pubkey)
        ))),
        Ok(v) if v.value != zat => Err(refuse(format!("shows {} zat there", v.value))),
        Ok(v) => Ok(LockedOutput {
            amount: mine.amount,
            confirmations: mine.confirmations.min(v.confirmations),
        }),
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

    const ZAT: u64 = 250_000;

    fn view(script_pubkey: &[u8], value: u64) -> std::result::Result<LockView, String> {
        Ok(LockView {
            script_pubkey: script_pubkey.to_vec(),
            value,
            confirmations: 3,
        })
    }

    fn mine() -> LockedOutput {
        LockedOutput {
            amount: divi_swap::Amount::from_sat(ZAT),
            confirmations: 5,
        }
    }

    /// `agree_lock` alone (since EW a well-formed answer with another script or value at the
    /// outpoint is another transaction, refused before this comparison): another script at
    /// the second operator is refused, naming it and both operators.
    #[test]
    fn agree_lock_names_the_script() {
        let (p, o) = (client("http://p.example:1"), client("http://o.example:2"));
        let (want, other) = ([0xa9u8, 0x14, 0x01], [0x76u8, 0xa9, 0x02]);
        let got = agree_lock(&at(), &want, mine(), &p, view(&other, ZAT), &o);
        let Err(SwapError::Transient(m)) = &got else {
            panic!("not refused: {got:?}");
        };
        for needle in [hex::encode(other), "p.example".into(), "o.example".into()] {
            assert!(m.contains(&needle), "{m} lacks {needle}");
        }
    }

    /// `agree_lock` alone: any other value is refused, naming it; the same value agrees at
    /// the lower confirmation count.
    #[test]
    fn agree_lock_names_the_value() {
        let (p, o) = (client("http://p.example:1"), client("http://o.example:2"));
        let want = [0xa9u8, 0x14, 0x01];
        for value in [ZAT - 1, ZAT / 2, ZAT + 1] {
            let got = agree_lock(&at(), &want, mine(), &p, view(&want, value), &o);
            let Err(SwapError::Transient(m)) = &got else {
                panic!("{value}: not refused: {got:?}");
            };
            assert!(m.contains(&value.to_string()), "{m}");
        }
        let ok = agree_lock(&at(), &want, mine(), &p, view(&want, ZAT), &o).unwrap();
        assert_eq!(ok.confirmations, 3);
        assert_eq!(ok.amount, mine().amount);
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
    async fn a_different_hash_at_the_tip_or_six_below_refuses_naming_both_endpoints() {
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
            // At startup a refusal; before a spend a hold.
            let startup = enforce_at_startup(&pc, &oc).await.unwrap_err();
            let SwapError::Transient(m) = &startup else {
                panic!("{height}: not transient: {startup:?}");
            };
            assert!(m.contains(p.endpoint()) && m.contains(o.endpoint()), "{m}");
            let hold = spend_hold(&pc, &oc, "refund", &at()).await.expect("held");
            assert!(hold.disagree);
            let SwapError::Held(m) = &hold.error else {
                panic!("{height}: not held: {hold:?}");
            };
            assert!(m.contains(p.endpoint()) && m.contains(o.endpoint()), "{m}");
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
            let hold = spend_hold(&pc, &oc, what, &at()).await.expect("held");
            assert!(!hold.disagree, "down is not a disagreement");
            let SwapError::Held(m) = &hold.error else {
                panic!("{what}: not held: {hold:?}");
            };
            assert!(
                m.contains("127.0.0.1:1") && m.contains(p.endpoint()) && m.contains(what),
                "{m}"
            );
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
            Err(SwapError::Held(_))
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
