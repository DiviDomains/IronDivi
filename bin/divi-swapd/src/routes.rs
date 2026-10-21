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

//! HTTP routes. Request/response bodies are the frozen `divi_swap::api` types.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::scan::{ScanInfo, ScanState, ScanStatus};
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use divi_swap::api::{AcceptRequest, LockNotice, Offer, Quote, SwapView};
use divi_swap::{Chain, ChainBackend, Maker, SwapError};
use divi_swap_xmr::api::{
    JRoundReply, JRoundRequest, SetupRequest, SigsRequest, XmrLockNotice, XmrSwapView,
    SWAP_TOKEN_HEADER,
};
use divi_swap_xmr::XmrMaker;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;

/// Requests one IP may make to a rate-limited route (quote, XMR setup) per
/// [`RATE_WINDOW`]. An honest taker makes one quote and one setup per swap, so 20 a minute is
/// generous; each setup costs the maker a Paillier-prime generation and reserved coins.
/// Behind a reverse proxy every client shares the proxy's address: limit at the proxy then.
pub const RATE_LIMIT_PER_WINDOW: u32 = 20;
/// Length of the fixed window [`RATE_LIMIT_PER_WINDOW`] counts in.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Most distinct IPs the limiter tracks; at this many, expired windows are swept first and,
/// if it is still full, an unknown IP is refused (a flood of spoofed sources cannot grow the
/// map without bound).
const RATE_MAX_TRACKED: usize = 10_000;

/// Fixed-window per-IP request counter.
pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: parking_lot::Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    /// At most `max` requests per `window` per IP.
    pub fn new(max: u32, window: Duration) -> Self {
        RateLimiter {
            max,
            window,
            hits: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Count one request from `ip` at `now`; `false` when it is over the limit.
    pub fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        let mut hits = self.hits.lock();
        if hits.len() >= RATE_MAX_TRACKED && !hits.contains_key(&ip) {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
            if hits.len() >= RATE_MAX_TRACKED {
                return false;
            }
        }
        let e = hits.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= self.window {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= self.max
    }
}

/// 429 past the limit. The peer address comes from the connection (`ConnectInfo`); a router
/// served without it (in-process tests) shares one unspecified-address bucket.
async fn rate_limit(State(l): State<Arc<RateLimiter>>, req: Request, next: Next) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip());
    if l.allow(ip, Instant::now()) {
        next.run(req).await
    } else {
        ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into()).into_response()
    }
}

/// Gate for every `/xmr/swaps/:id...` route, run before the body is parsed (a 422 for a bad
/// body would otherwise tell a prober the id exists). A missing, wrong or unknown-swap token
/// is the same 404 an unknown swap id gets.
async fn swap_token_gate(
    State(x): State<Arc<XmrMaker>>,
    Path(params): Path<HashMap<String, String>>,
    req: Request,
    next: Next,
) -> Response {
    let id = params.get("id").map(String::as_str).unwrap_or("");
    let token = req
        .headers()
        .get(SWAP_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if x.authorize(id, token) {
        next.run(req).await
    } else {
        ApiError(StatusCode::NOT_FOUND, format!("no xmr swap {id}")).into_response()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub maker: Arc<Maker>,
    pub divi: Arc<dyn ChainBackend>,
    /// The BTC backend. Other counter chains are reached through `maker`.
    pub btc: Arc<dyn ChainBackend>,
    pub scan: ScanStatus,
}

impl AppState {
    /// 503 while the wallet's coin set is incomplete.
    fn require_wallet(&self) -> Result<(), ApiError> {
        if self.scan.is_done() {
            Ok(())
        } else {
            Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "wallet scan in progress".into(),
            ))
        }
    }
}

/// Build the router, nested under `prefix` (empty or `/seg`).
pub fn router(state: AppState, prefix: &str) -> Router {
    router_with_xmr(state, None, prefix)
}

/// [`router`] plus, when `xmr` is given, the DIVI<->XMR adaptor-swap routes
/// (`divi_swap_xmr`): `POST /xmr/swaps` (setup), `POST /xmr/swaps/:id/j` (the 2P-ECDSA
/// exchanges of the joint cancel key), `POST /xmr/swaps/:id/sigs`,
/// `POST /xmr/swaps/:id/xmr-lock`, `GET /xmr/swaps/:id`. Every `:id` route needs the swap's
/// `X-Swap-Token` (else 404); there is no listing. Quote and setup are rate limited per IP
/// (429). Its offers and quotes go through
/// the hashlock maker's `/offers` routes (the engine is registered with
/// `Maker::with_engine`).
pub fn router_with_xmr(state: AppState, xmr: Option<Arc<XmrMaker>>, prefix: &str) -> Router {
    let limiter = Arc::new(RateLimiter::new(RATE_LIMIT_PER_WINDOW, RATE_WINDOW));
    let limited = || middleware::from_fn_with_state(limiter.clone(), rate_limit);
    let mut api = Router::new()
        .route("/healthz", get(healthz))
        .route("/offers", get(offers))
        .route("/offers/:id/quote", get(quote).route_layer(limited()))
        .route("/swaps", post(accept).get(list_swaps))
        .route("/swaps/:id", get(get_swap))
        .route("/swaps/:id/lock", post(lock))
        .with_state(state);
    if let Some(x) = xmr {
        api = api.merge(
            Router::new()
                .route("/xmr/swaps", post(xmr_setup).route_layer(limited()))
                .merge(
                    Router::new()
                        .route("/xmr/swaps/:id", get(xmr_get))
                        .route("/xmr/swaps/:id/j", post(xmr_j))
                        .route("/xmr/swaps/:id/sigs", post(xmr_sigs))
                        .route("/xmr/swaps/:id/xmr-lock", post(xmr_lock))
                        .route_layer(middleware::from_fn_with_state(x.clone(), swap_token_gate)),
                )
                .with_state(x),
        );
    }
    let app = if prefix.is_empty() {
        api
    } else {
        Router::new().nest(prefix, api)
    };
    app.layer(TraceLayer::new_for_http())
}

/// JSON error body with a status derived from the error kind.
struct ApiError(StatusCode, String);

impl From<SwapError> for ApiError {
    fn from(e: SwapError) -> Self {
        let status = match &e {
            SwapError::InvalidParams(_) => StatusCode::BAD_REQUEST,
            SwapError::Transient(_) | SwapError::Premature(_) => StatusCode::SERVICE_UNAVAILABLE,
            SwapError::Rejected(_) | SwapError::InsufficientFunds(_) => StatusCode::CONFLICT,
            SwapError::Storage(_) | SwapError::Secret(_) | SwapError::Other(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        ApiError(status, e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

#[derive(Serialize)]
struct ChainHealth {
    tip: Option<u64>,
    error: Option<String>,
}

#[derive(Serialize)]
struct Health {
    ok: bool,
    version: &'static str,
    divi: ChainHealth,
    btc: ChainHealth,
    /// Counter chains other than BTC (LTC, ZEC, …), by ticker; omitted when there are none.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    counters: BTreeMap<Chain, ChainHealth>,
    divi_scan: ScanInfo,
}

async fn chain_health(b: &Arc<dyn ChainBackend>) -> ChainHealth {
    match b.tip_height().await {
        Ok(h) => ChainHealth {
            tip: Some(h),
            error: None,
        },
        Err(e) => ChainHealth {
            tip: None,
            error: Some(e.to_string()),
        },
    }
}

async fn healthz(State(s): State<AppState>) -> Json<Health> {
    let (divi, btc) = tokio::join!(chain_health(&s.divi), chain_health(&s.btc));
    let mut counters = BTreeMap::new();
    for c in s.maker.counter_chains() {
        if c == s.btc.chain() {
            continue;
        }
        if let Some(b) = s.maker.backend(c) {
            counters.insert(c, chain_health(&b).await);
        }
    }
    let scan = s.scan.info();
    let chains_ok = counters.values().all(|h| h.error.is_none());
    Json(Health {
        ok: divi.error.is_none()
            && btc.error.is_none()
            && chains_ok
            && scan.state == ScanState::Done,
        version: env!("CARGO_PKG_VERSION"),
        divi,
        btc,
        counters,
        divi_scan: scan,
    })
}

async fn offers(State(s): State<AppState>) -> Json<Vec<Offer>> {
    Json(s.maker.offers())
}

#[derive(Deserialize)]
struct QuoteParams {
    btc_sats: u64,
}

async fn quote(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(p): Query<QuoteParams>,
) -> Result<Json<Quote>, ApiError> {
    s.require_wallet()?;
    Ok(Json(s.maker.quote(&id, p.btc_sats).await?))
}

async fn accept(
    State(s): State<AppState>,
    Json(req): Json<AcceptRequest>,
) -> Result<(StatusCode, Json<SwapView>), ApiError> {
    s.require_wallet()?;
    Ok((StatusCode::CREATED, Json(s.maker.accept(req).await?)))
}

async fn list_swaps(State(s): State<AppState>) -> Result<Json<Vec<SwapView>>, ApiError> {
    Ok(Json(s.maker.list()?))
}

async fn get_swap(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SwapView>, ApiError> {
    s.maker
        .view(&id)?
        .map(Json)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("no swap {id}")))
}

async fn lock(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(notice): Json<LockNotice>,
) -> Result<Json<SwapView>, ApiError> {
    Ok(Json(s.maker.notify_lock(&id, notice).await?))
}

async fn xmr_setup(
    State(x): State<Arc<XmrMaker>>,
    Json(req): Json<SetupRequest>,
) -> Result<(StatusCode, Json<JRoundReply>), ApiError> {
    Ok((StatusCode::CREATED, Json(x.setup(req).await?)))
}

async fn xmr_j(
    State(x): State<Arc<XmrMaker>>,
    Path(id): Path<String>,
    Json(req): Json<JRoundRequest>,
) -> Result<Json<JRoundReply>, ApiError> {
    Ok(Json(x.j_round(&id, req).await?))
}

async fn xmr_sigs(
    State(x): State<Arc<XmrMaker>>,
    Path(id): Path<String>,
    Json(req): Json<SigsRequest>,
) -> Result<Json<XmrSwapView>, ApiError> {
    Ok(Json(x.sigs(&id, req).await?))
}

async fn xmr_lock(
    State(x): State<Arc<XmrMaker>>,
    Path(id): Path<String>,
    Json(notice): Json<XmrLockNotice>,
) -> Result<Json<XmrSwapView>, ApiError> {
    Ok(Json(x.xmr_locked(&id, notice).await?))
}

async fn xmr_get(
    State(x): State<Arc<XmrMaker>>,
    Path(id): Path<String>,
) -> Result<Json<XmrSwapView>, ApiError> {
    x.view(&id)?
        .map(Json)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("no xmr swap {id}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limiter_counts_per_ip_per_window() {
        let l = RateLimiter::new(3, Duration::from_secs(60));
        let (a, b): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        let t0 = Instant::now();
        assert!([0, 1, 2].iter().all(|_| l.allow(a, t0)));
        assert!(!l.allow(a, t0), "the 4th in the window");
        assert!(l.allow(b, t0), "another address has its own count");
        assert!(!l.allow(a, t0 + Duration::from_secs(59)));
        assert!(l.allow(a, t0 + Duration::from_secs(60)), "a new window");
    }
}
