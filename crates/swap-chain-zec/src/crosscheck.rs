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
        let _ = self;
        None
    }
}

/// Compare `primary` with `other` (the second operator). Never returns an error: every
/// failure is [`CrossCheckOutcome::Unavailable`] so the caller applies the policy.
pub async fn tip_crosscheck(
    primary: &LightwalletdClient,
    other: &LightwalletdClient,
) -> CrossCheckOutcome {
    let _ = (primary, other);
    CrossCheckOutcome::Unavailable {
        reason: "not implemented".into(),
    }
}

/// Startup policy: `Disagree` is [`SwapError::Transient`] naming both endpoints,
/// `Unavailable` logs a warning and continues.
pub async fn enforce_at_startup(
    primary: &LightwalletdClient,
    other: &LightwalletdClient,
) -> Result<()> {
    let _ = (primary, other);
    Ok(())
}

/// Before a claim or refund (`what`) of `at`: `Disagree` and `Unavailable` are both
/// [`SwapError::Transient`] (fail closed; the engine retries).
pub async fn enforce_before_spend(
    primary: &LightwalletdClient,
    other: &LightwalletdClient,
    what: &str,
    at: &Outpoint,
) -> Result<()> {
    let _ = (primary, other, what, at);
    Ok(())
}

/// The operator a lightwalletd URL belongs to: its host's registrable domain.
pub fn operator_domain(url: &str) -> Option<String> {
    let _ = url;
    None
}

/// `Ok` when `url` is a usable second operator for `primaries`.
pub fn check_second_operator(primaries: &[String], url: &str) -> std::result::Result<(), String> {
    let _ = (primaries, url);
    Ok(())
}

/// Whether `endpoints` already span more than one operator.
pub fn has_second_operator(endpoints: &[String]) -> bool {
    let _ = endpoints;
    true
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
        eps.push("https://lwd.other-operator.net:9067".into());
        assert!(has_second_operator(&eps));
    }
}
