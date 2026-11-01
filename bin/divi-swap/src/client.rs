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

//! Typed HTTP client for `divi-swapd`.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use divi_swap::api::{AcceptRequest, LockNotice, Offer, Quote, SwapView};
use divi_swap_xmr::api::{
    JRoundReply, JRoundRequest, SetupRequest, SigsRequest, XmrLockNotice, XmrSwapView,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// How long [`MakerClient::wait_ready`] waits for a maker that is still scanning its DIVI
/// wallet (it answers `503 wallet scan in progress` to quotes until then), and how often it
/// looks.
#[derive(Clone, Copy, Debug)]
pub struct ReadyWait {
    pub timeout: Duration,
    pub poll: Duration,
}

impl Default for ReadyWait {
    fn default() -> Self {
        ReadyWait {
            timeout: Duration::from_secs(600),
            poll: Duration::from_secs(5),
        }
    }
}

/// A non-success HTTP status from the maker (the error's text is unchanged:
/// `maker returned <status>: <body>`).
#[derive(Debug)]
pub struct MakerStatus {
    pub status: reqwest::StatusCode,
    pub body: String,
}

impl std::fmt::Display for MakerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "maker returned {}: {}", self.status, self.body)
    }
}

impl std::error::Error for MakerStatus {}

/// True if `e` is the maker answering 503 (wallet scan in progress, or a transient chain
/// error): worth retrying.
pub fn is_unavailable(e: &anyhow::Error) -> bool {
    e.downcast_ref::<MakerStatus>()
        .is_some_and(|s| s.status == reqwest::StatusCode::SERVICE_UNAVAILABLE)
}

/// The part of `/healthz` the taker reads.
#[derive(Deserialize)]
struct Health {
    /// Absent on makers older than the background scan: treated as ready.
    divi_scan: Option<ScanHealth>,
}

#[derive(Deserialize)]
struct ScanHealth {
    /// `scanning`, `done` or `failed`.
    state: String,
    #[serde(default)]
    next_height: u64,
    #[serde(default)]
    target_height: u64,
    error: Option<String>,
}

#[derive(Clone)]
pub struct MakerClient {
    base: String,
    http: reqwest::Client,
    ready: ReadyWait,
}

impl MakerClient {
    /// `base` includes any path prefix, e.g. `https://host/swap`.
    pub fn new(base: &str) -> Self {
        MakerClient {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                // The xmr setup and 2P-ECDSA exchanges may wait on Paillier primes (~90 s).
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .expect("reqwest client"),
            ready: ReadyWait::default(),
        }
    }

    /// Replaces the default [`ReadyWait`].
    pub fn with_ready_wait(mut self, ready: ReadyWait) -> Self {
        self.ready = ready;
        self
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let body = resp.text().await.context("reading maker response")?;
        if !status.is_success() {
            return Err(MakerStatus { status, body }.into());
        }
        serde_json::from_str(&body).with_context(|| format!("decoding maker response: {body}"))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        Self::decode(resp).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {path}"))?;
        Self::decode(resp).await
    }

    /// Waits (up to [`ReadyWait::timeout`]) until the maker's `/healthz` reports its DIVI
    /// wallet scan `done`, logging each wait. A maker that cannot be reached is waited for
    /// too (it may be restarting); a scan that `failed` is an error at once.
    pub async fn wait_ready(&self) -> Result<()> {
        let started = Instant::now();
        loop {
            let last = match self.get::<Health>("/healthz").await {
                Ok(Health { divi_scan: None }) => return Ok(()),
                Ok(Health { divi_scan: Some(s) }) => match s.state.as_str() {
                    "done" => return Ok(()),
                    "failed" => bail!(
                        "maker {}: its DIVI wallet scan failed: {}",
                        self.base,
                        s.error.as_deref().unwrap_or("no detail")
                    ),
                    state => {
                        tracing::info!(
                            maker = %self.base,
                            state,
                            next_height = s.next_height,
                            target_height = s.target_height,
                            "maker's DIVI wallet scan is not done; waiting before negotiating"
                        );
                        format!("scan {state} at {}/{}", s.next_height, s.target_height)
                    }
                },
                Err(e) => {
                    tracing::info!(maker = %self.base, error = %e, "maker /healthz unavailable; waiting");
                    e.to_string()
                }
            };
            if started.elapsed() + self.ready.poll > self.ready.timeout {
                bail!(
                    "maker {} not ready after {:?} (last: {last})",
                    self.base,
                    self.ready.timeout
                );
            }
            tokio::time::sleep(self.ready.poll).await;
        }
    }

    /// [`MakerClient::quote`], retrying a 503 (the maker's scan restarted, or a transient
    /// chain error) every [`ReadyWait::poll`] for up to [`ReadyWait::timeout`].
    pub async fn quote_retrying(&self, offer_id: &str, btc_sats: u64) -> Result<Quote> {
        let started = Instant::now();
        loop {
            match self.quote(offer_id, btc_sats).await {
                Err(e)
                    if is_unavailable(&e)
                        && started.elapsed() + self.ready.poll <= self.ready.timeout =>
                {
                    tracing::info!(maker = %self.base, error = %e, "quote unavailable; retrying");
                    tokio::time::sleep(self.ready.poll).await;
                }
                r => return r,
            }
        }
    }

    pub async fn offers(&self) -> Result<Vec<Offer>> {
        self.get("/offers").await
    }

    pub async fn quote(&self, offer_id: &str, btc_sats: u64) -> Result<Quote> {
        self.get(&format!("/offers/{offer_id}/quote?btc_sats={btc_sats}"))
            .await
    }

    pub async fn accept(&self, req: &AcceptRequest) -> Result<SwapView> {
        self.post("/swaps", req).await
    }

    pub async fn lock(&self, swap_id: &str, notice: &LockNotice) -> Result<SwapView> {
        self.post(&format!("/swaps/{swap_id}/lock"), notice).await
    }

    pub async fn swap(&self, swap_id: &str) -> Result<SwapView> {
        self.get(&format!("/swaps/{swap_id}")).await
    }

    // ---- DIVI<->XMR adaptor swap (`divi_swap_xmr`) ----

    pub async fn xmr_setup(&self, req: &SetupRequest) -> Result<JRoundReply> {
        self.post("/xmr/swaps", req).await
    }

    pub async fn xmr_j(&self, swap_id: &str, req: &JRoundRequest) -> Result<JRoundReply> {
        self.post(&format!("/xmr/swaps/{swap_id}/j"), req).await
    }

    pub async fn xmr_sigs(&self, swap_id: &str, req: &SigsRequest) -> Result<XmrSwapView> {
        self.post(&format!("/xmr/swaps/{swap_id}/sigs"), req).await
    }

    pub async fn xmr_lock(&self, swap_id: &str, notice: &XmrLockNotice) -> Result<XmrSwapView> {
        self.post(&format!("/xmr/swaps/{swap_id}/xmr-lock"), notice)
            .await
    }

    pub async fn xmr_swap(&self, swap_id: &str) -> Result<XmrSwapView> {
        self.get(&format!("/xmr/swaps/{swap_id}")).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Json, Router};

    use super::*;

    #[derive(Clone)]
    struct Fake {
        health: Arc<AtomicUsize>,
        quotes: Arc<AtomicUsize>,
        state: &'static str,
        scanning: usize,
        quote_503: usize,
    }

    async fn healthz(State(s): State<Fake>) -> Json<serde_json::Value> {
        let n = s.health.fetch_add(1, Ordering::SeqCst);
        let state = if n < s.scanning { s.state } else { "done" };
        Json(serde_json::json!({
            "ok": state == "done",
            "divi_scan": {"state": state, "next_height": n, "target_height": 100, "error": "boom"},
        }))
    }

    async fn quote(State(s): State<Fake>) -> (StatusCode, String) {
        if s.quotes.fetch_add(1, Ordering::SeqCst) < s.quote_503 {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"wallet scan in progress"}"#.into(),
            )
        } else {
            (StatusCode::IM_A_TEAPOT, r#"{"error":"reached"}"#.into())
        }
    }

    /// A maker whose `/healthz` reports `state` for the first `scanning` requests, then
    /// `done`, and whose quote route answers 503 for the first `quote_503` requests. Returns
    /// the base URL and the `/healthz` hit counter.
    async fn maker(
        state: &'static str,
        scanning: usize,
        quote_503: usize,
    ) -> (String, Arc<AtomicUsize>) {
        let health = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/offers/:id/quote", get(quote))
            .with_state(Fake {
                health: health.clone(),
                quotes: Arc::new(AtomicUsize::new(0)),
                state,
                scanning,
                quote_503,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), health)
    }

    fn fast(base: &str, timeout_ms: u64) -> MakerClient {
        MakerClient::new(base).with_ready_wait(ReadyWait {
            timeout: Duration::from_millis(timeout_ms),
            poll: Duration::from_millis(10),
        })
    }

    #[tokio::test]
    async fn waits_for_the_scan_to_finish() {
        let (base, hits) = maker("scanning", 3, 0).await;
        fast(&base, 5_000).wait_ready().await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn a_failed_scan_is_an_error_at_once() {
        let (base, hits) = maker("failed", 1_000, 0).await;
        let e = fast(&base, 5_000).wait_ready().await.unwrap_err();
        assert!(e.to_string().contains("scan failed: boom"), "{e}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_wait_is_bounded() {
        let (base, _) = maker("scanning", usize::MAX, 0).await;
        let e = fast(&base, 100).wait_ready().await.unwrap_err();
        assert!(e.to_string().contains("not ready after"), "{e}");
        // An unreachable maker is waited for, within the same bound.
        let e = fast("http://127.0.0.1:9", 100)
            .wait_ready()
            .await
            .unwrap_err();
        assert!(e.to_string().contains("not ready after"), "{e}");
    }

    #[tokio::test]
    async fn quote_retries_503_only() {
        let (base, _) = maker("done", 0, 2).await;
        let e = fast(&base, 5_000).quote_retrying("o", 1).await.unwrap_err();
        // Past the two 503s to the route's next answer, which is not retried.
        assert!(e.to_string().contains("418"), "{e}");
        assert!(!is_unavailable(&e));
        // Out of time, the 503 itself comes back.
        let (base, _) = maker("done", 0, usize::MAX).await;
        let e = fast(&base, 50).quote_retrying("o", 1).await.unwrap_err();
        assert!(is_unavailable(&e), "{e}");
        assert!(e.to_string().contains("wallet scan in progress"), "{e}");
    }
}
