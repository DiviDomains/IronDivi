// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Opt-in LTC **mainnet** tip-hash cross-check against a source that is not Esplora.
//!
//! The primary (`litecoinspace.org/api`) is the only mainnet Esplora API we know of, so a
//! lying or forked primary would go unnoticed. This asks one independent explorer (Blockbook
//! or BlockCypher) for the hash of the block [`CROSSCHECK_DEPTH`] below the primary's tip and
//! compares it with the primary's hash at that height. It is a sanity check, not a UTXO
//! source, and it changes no confirmation count, lag or timeout.
//!
//! `H - 6` (not the tip) is used so that ordinary one-to-few-block reorgs and the few
//! seconds by which one explorer leads another cannot cause a false `Disagree`.

use std::str::FromStr;

use serde_json::Value;

use crate::client::{EsploraClient, RetryPolicy};

/// How far below the primary's tip the compared block sits. A comparison depth only — it is
/// **not** a confirmation count and nothing else reads it.
pub const CROSSCHECK_DEPTH: u64 = 6;

/// Blockbook mainnet API base (keyless).
pub const BLOCKBOOK_MAINNET: &str = "https://litecoinblockexplorer.net/api/v2";

/// BlockCypher LTC mainnet API base (keyless, rate limited).
pub const BLOCKCYPHER_MAINNET: &str = "https://api.blockcypher.com/v1/ltc/main";

/// Which independent source to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossCheckSource {
    /// `GET {base}/block-index/{height}` → `{"blockHash":"…"}`.
    Blockbook,
    /// `GET {base}/blocks/{height}` → `{"hash":"…", …}`.
    BlockCypher,
}

impl CrossCheckSource {
    /// Default mainnet API base for this source.
    pub fn default_base(self) -> &'static str {
        match self {
            Self::Blockbook => BLOCKBOOK_MAINNET,
            Self::BlockCypher => BLOCKCYPHER_MAINNET,
        }
    }

    /// Config / CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blockbook => "blockbook",
            Self::BlockCypher => "blockcypher",
        }
    }

    /// Parse the config / CLI value. `off` is `Ok(None)`; anything unknown is an error.
    pub fn parse_opt(s: &str) -> Result<Option<Self>, String> {
        match s {
            "off" => Ok(None),
            other => other.parse().map(Some),
        }
    }

    fn path(self, height: u64) -> String {
        match self {
            Self::Blockbook => format!("/block-index/{height}"),
            Self::BlockCypher => format!("/blocks/{height}"),
        }
    }

    /// Pull the block hash out of this source's response body.
    fn hash_from(self, body: &str) -> Result<String, String> {
        let v: Value = serde_json::from_str(body).map_err(|e| format!("not JSON: {e}"))?;
        let key = match self {
            Self::Blockbook => "blockHash",
            Self::BlockCypher => "hash",
        };
        // Blockbook answers 200 with an empty hash for a height it has not indexed yet.
        let h = v[key]
            .as_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| format!("no {key:?} in response"))?;
        normalize_hash(h)
    }
}

impl FromStr for CrossCheckSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "blockbook" => Ok(Self::Blockbook),
            "blockcypher" => Ok(Self::BlockCypher),
            other => Err(format!(
                "ltc crosscheck {other:?} unsupported: blockbook, blockcypher or off"
            )),
        }
    }
}

/// Lower-case a 64-hex block hash; anything else is rejected.
fn normalize_hash(h: &str) -> Result<String, String> {
    let h = h.trim().to_ascii_lowercase();
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(h)
    } else {
        Err(format!("not a 64-hex block hash: {h:?}"))
    }
}

/// Result of one cross-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCheckOutcome {
    /// Both sources report the same hash at `height`.
    Agree { height: u64, hash: String },
    /// They report different hashes at `height`: refuse to proceed.
    Disagree {
        height: u64,
        primary_hash: String,
        primary_url: String,
        other_hash: String,
        other_url: String,
    },
    /// Could not compare (network error, rate limit, malformed body, source behind).
    Unavailable { reason: String },
}

impl CrossCheckOutcome {
    /// The refusal text for a `Disagree`, naming both hashes and both URLs.
    pub fn disagree_message(&self) -> Option<String> {
        match self {
            Self::Disagree {
                height,
                primary_hash,
                primary_url,
                other_hash,
                other_url,
            } => Some(format!(
                "ltc tip cross-check FAILED at height {height}: primary {primary_url} says \
                 {primary_hash}, independent source {other_url} says {other_hash}; refusing"
            )),
            _ => None,
        }
    }
}

/// Compare `primary`'s hash at `tip - CROSSCHECK_DEPTH` with `source`'s, asking `source` at
/// `source_base` (use [`CrossCheckSource::default_base`]). Never returns an error: every
/// failure is [`CrossCheckOutcome::Unavailable`] so the caller decides (warn and continue).
pub async fn tip_crosscheck(
    primary: &EsploraClient,
    source: CrossCheckSource,
    source_base: &str,
    retry: RetryPolicy,
) -> CrossCheckOutcome {
    let unavailable = |reason: String| CrossCheckOutcome::Unavailable { reason };
    let other = match EsploraClient::new(vec![source_base.to_string()], retry) {
        Ok(c) => c,
        Err(e) => return unavailable(format!("{} client: {e}", source.as_str())),
    };
    let primary_base = primary.primary_url().to_string();

    let tip: u64 = match primary.get("/blocks/tip/height").await {
        Ok(b) => match b.trim().parse() {
            Ok(h) => h,
            Err(_) => return unavailable(format!("{primary_base}: tip height not a number")),
        },
        Err(e) => return unavailable(format!("{primary_base}: tip height: {e:?}")),
    };
    let height = match tip.checked_sub(CROSSCHECK_DEPTH) {
        Some(h) => h,
        None => return unavailable(format!("{primary_base}: tip {tip} below depth")),
    };

    let primary_hash = match primary.get(&format!("/block-height/{height}")).await {
        Ok(b) => match normalize_hash(&b) {
            Ok(h) => h,
            Err(e) => return unavailable(format!("{primary_base}: {e}")),
        },
        Err(e) => return unavailable(format!("{primary_base}: hash at {height}: {e:?}")),
    };

    let other_path = source.path(height);
    let other_url = format!("{}{other_path}", source_base.trim_end_matches('/'));
    let other_hash = match other.get(&other_path).await {
        Ok(body) => match source.hash_from(&body) {
            Ok(h) => h,
            Err(e) => return unavailable(format!("{other_url}: {e}")),
        },
        Err(e) => return unavailable(format!("{other_url}: {e:?}")),
    };

    if other_hash == primary_hash {
        CrossCheckOutcome::Agree {
            height,
            hash: primary_hash,
        }
    } else {
        CrossCheckOutcome::Disagree {
            height,
            primary_hash,
            primary_url: format!("{primary_base}/block-height/{height}"),
            other_hash,
            other_url,
        }
    }
}

/// Run the check for a mainnet backend and apply the policy: `Disagree` is an error naming
/// both hashes and URLs, `Unavailable` logs a warning and continues. `source = None` (`off`)
/// makes no request.
pub async fn enforce(
    primary: &EsploraClient,
    source: Option<CrossCheckSource>,
    source_base: Option<&str>,
    retry: RetryPolicy,
) -> Result<(), divi_swap::SwapError> {
    let Some(source) = source else {
        return Ok(());
    };
    let base = source_base.unwrap_or_else(|| source.default_base());
    match tip_crosscheck(primary, source, base, retry).await {
        CrossCheckOutcome::Agree { height, hash } => {
            tracing::info!(height, %hash, source = source.as_str(), "ltc tip cross-check agrees");
            Ok(())
        }
        CrossCheckOutcome::Unavailable { reason } => {
            tracing::warn!(%reason, source = source.as_str(), "ltc tip cross-check unavailable; continuing");
            Ok(())
        }
        d @ CrossCheckOutcome::Disagree { .. } => Err(divi_swap::SwapError::Other(
            d.disagree_message().expect("disagree"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const H_A: &str = "bb06e9077c1907d25a1d986ac281b6d119228b8eae984c21b59fcfdb4af66b11";
    const H_B: &str = "ac6f27fa7cfdc204f13f93fcd48ce5f57a4a858b950b4de8ac89979b3b5f0b43";
    const TIP: u64 = 3_199_583;
    const AT: u64 = TIP - CROSSCHECK_DEPTH;

    fn fast() -> RetryPolicy {
        RetryPolicy {
            attempts: 1,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
        }
    }

    async fn primary(hash: &str) -> (MockServer, EsploraClient) {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string(TIP.to_string()))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/block-height/{AT}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(hash))
            .mount(&s)
            .await;
        let c = EsploraClient::new(vec![s.uri()], fast()).unwrap();
        (s, c)
    }

    async fn source(kind: CrossCheckSource, resp: ResponseTemplate) -> MockServer {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(kind.path(AT)))
            .respond_with(resp)
            .mount(&s)
            .await;
        s
    }

    fn bb(hash: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(format!(r#"{{"blockHash":"{hash}"}}"#))
    }

    fn bc(hash: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"height":{AT},"hash":"{hash}","prev_block":"x"}}"#
        ))
    }

    #[tokio::test]
    async fn agree_on_both_source_shapes() {
        for (kind, resp) in [
            (CrossCheckSource::Blockbook, bb(H_A)),
            (CrossCheckSource::BlockCypher, bc(&H_A.to_uppercase())),
        ] {
            let (_p, pc) = primary(H_A).await;
            let s = source(kind, resp).await;
            let out = tip_crosscheck(&pc, kind, &s.uri(), fast()).await;
            assert_eq!(
                out,
                CrossCheckOutcome::Agree {
                    height: AT,
                    hash: H_A.into()
                },
                "{kind:?}"
            );
        }
    }

    #[tokio::test]
    async fn disagree_names_both_hashes_and_both_urls() {
        for (kind, resp) in [
            (CrossCheckSource::Blockbook, bb(H_B)),
            (CrossCheckSource::BlockCypher, bc(H_B)),
        ] {
            let (p, pc) = primary(H_A).await;
            let s = source(kind, resp).await;
            let out = tip_crosscheck(&pc, kind, &s.uri(), fast()).await;
            let msg = out.disagree_message().expect("disagree");
            for needle in [H_A, H_B, &p.uri(), &s.uri()] {
                assert!(msg.contains(needle), "{msg} lacks {needle}");
            }
            let err = enforce(&pc, Some(kind), Some(&s.uri()), fast())
                .await
                .unwrap_err();
            assert!(err.to_string().contains(H_B), "{err}");
        }
    }

    #[tokio::test]
    async fn source_unavailable_continues() {
        for kind in [CrossCheckSource::Blockbook, CrossCheckSource::BlockCypher] {
            for status in [404, 429, 500] {
                let (_p, pc) = primary(H_A).await;
                let s = source(kind, ResponseTemplate::new(status)).await;
                let out = tip_crosscheck(&pc, kind, &s.uri(), fast()).await;
                assert!(
                    matches!(out, CrossCheckOutcome::Unavailable { .. }),
                    "{kind:?} {status}: {out:?}"
                );
                enforce(&pc, Some(kind), Some(&s.uri()), fast())
                    .await
                    .expect("unavailable must not refuse");
            }
        }
    }

    #[tokio::test]
    async fn source_unreachable_is_unavailable() {
        let (_p, pc) = primary(H_A).await;
        let dead = MockServer::start().await;
        let base = dead.uri();
        drop(dead);
        let out = tip_crosscheck(&pc, CrossCheckSource::Blockbook, &base, fast()).await;
        assert!(
            matches!(out, CrossCheckOutcome::Unavailable { .. }),
            "{out:?}"
        );
    }

    #[tokio::test]
    async fn malformed_bodies_are_unavailable_not_agree_or_disagree() {
        let bad = [
            ResponseTemplate::new(200).set_body_string("<html>oops</html>"),
            ResponseTemplate::new(200).set_body_string("{}"),
            // Blockbook's answer for a height it has not indexed.
            ResponseTemplate::new(200).set_body_string(r#"{"blockHash":""}"#),
            ResponseTemplate::new(200).set_body_string(r#"{"blockHash":"zz","hash":"12"}"#),
        ];
        for kind in [CrossCheckSource::Blockbook, CrossCheckSource::BlockCypher] {
            for resp in &bad {
                let (_p, pc) = primary(H_A).await;
                let s = source(kind, resp.clone()).await;
                let out = tip_crosscheck(&pc, kind, &s.uri(), fast()).await;
                assert!(
                    matches!(out, CrossCheckOutcome::Unavailable { .. }),
                    "{kind:?}: {out:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn malformed_primary_is_unavailable() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-a-number"))
            .mount(&s)
            .await;
        let pc = EsploraClient::new(vec![s.uri()], fast()).unwrap();
        let out = tip_crosscheck(
            &pc,
            CrossCheckSource::Blockbook,
            "http://127.0.0.1:1",
            fast(),
        )
        .await;
        assert!(
            matches!(out, CrossCheckOutcome::Unavailable { .. }),
            "{out:?}"
        );
    }

    #[tokio::test]
    async fn off_makes_no_request() {
        let (p, pc) = primary(H_A).await;
        enforce(&pc, None, None, fast()).await.unwrap();
        assert!(p.received_requests().await.unwrap().is_empty());
    }

    /// Read-only smoke against live Litecoin mainnet (GET only, no keys):
    /// `cargo test -p swap-chain-ltc --features live -- --ignored live_mainnet_agrees --nocapture`.
    #[cfg(feature = "live")]
    #[tokio::test]
    #[ignore = "network"]
    async fn live_mainnet_agrees() {
        let pc = EsploraClient::new(
            vec![crate::LITECOINSPACE_MAINNET.to_string()],
            RetryPolicy::default(),
        )
        .unwrap();
        for kind in [CrossCheckSource::Blockbook, CrossCheckSource::BlockCypher] {
            let out = tip_crosscheck(&pc, kind, kind.default_base(), RetryPolicy::default()).await;
            println!("{}: {out:?}", kind.as_str());
            assert!(
                !matches!(out, CrossCheckOutcome::Disagree { .. }),
                "{out:?}"
            );
        }
    }

    #[test]
    fn parse_values() {
        assert_eq!(CrossCheckSource::parse_opt("off"), Ok(None));
        assert_eq!(
            CrossCheckSource::parse_opt("blockbook"),
            Ok(Some(CrossCheckSource::Blockbook))
        );
        assert_eq!(
            CrossCheckSource::parse_opt("blockcypher"),
            Ok(Some(CrossCheckSource::BlockCypher))
        );
        assert!(CrossCheckSource::parse_opt("esplora").is_err());
    }
}
