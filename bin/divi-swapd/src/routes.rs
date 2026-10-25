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
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::{Json, Router};
use divi_swap::api::{
    AcceptReply, AcceptRequest, LockNotice, Offer, Quote, SwapView, OPERATOR_TOKEN_HEADER,
    SWAP_TOKEN_HEADER as HASHLOCK_TOKEN_HEADER, SWAP_TOKEN_SUPPORT_HEADER,
};
use divi_swap::{Chain, ChainBackend, Maker, Store, SwapError};
use divi_swap_xmr::api::{
    JRoundReply, JRoundRequest, SetupRequest, SigsRequest, XmrLockNotice, XmrSwapView,
    SWAP_TOKEN_HEADER,
};
use divi_swap_xmr::maker::{new_swap_token, token_matches};
use divi_swap_xmr::XmrMaker;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;

/// Requests one IP may make to a rate-limited route (quote, XMR setup) per
/// [`RATE_WINDOW`]. An honest taker makes one quote and one setup per swap, so 20 a minute is
/// generous; each setup costs the maker a Paillier-prime generation and reserved coins.
/// Behind a reverse proxy every client shares the proxy's address unless `trust_proxy_headers`
/// is set (see [`client_ip`]).
pub const RATE_LIMIT_PER_WINDOW: u32 = 20;
/// Requests one IP may make per [`RATE_WINDOW`] to the swap-state-changing routes
/// (`POST /swaps` accept, `POST /swaps/:id/lock`). A taker makes one of each per swap (a
/// retry or two on a transient error); 20 leaves room for several swaps a minute from one
/// NAT address. A separate limiter from the quote/setup one so a swap's negotiation calls
/// do not eat into each other.
pub const WRITE_LIMIT_PER_WINDOW: u32 = 20;
/// Requests one IP may make per [`RATE_WINDOW`] to `GET /swaps` and `GET /swaps/:id`. A live
/// taker polls `GET /swaps/:id` once per `--poll-secs` (default 10 s = 6 a minute; 1 s = 60).
/// 300 is 5x the 1 s case, and a separate limiter keeps status polling from exhausting the
/// accept/lock budget.
pub const READ_LIMIT_PER_WINDOW: u32 = 300;
/// Requests one IP may make per [`RATE_WINDOW`] to the public reads `GET /healthz` and
/// `GET /offers`, in one bucket of their own. A health monitor polls every 10-60 s (1-6 a
/// minute; `swap-watch` and a taker's `wait_ready` are in that range), the landing page makes
/// one of each per view, and a taker one `/healthz` per poll while the scan runs. 600 is ten a
/// second: 10x a monitor polling every second, with room for a shared proxy bucket while
/// `trust_proxy_headers` is off. Enough to stop a flood from turning every request into chain
/// RPCs (`/healthz` asks each chain for its tip).
pub const PUBLIC_READ_LIMIT_PER_WINDOW: u32 = 600;
/// Requests one IP may make per [`RATE_WINDOW`] to the token-gated XMR routes
/// (`GET /xmr/swaps/:id`, `POST .../j`, `/sigs`, `/xmr-lock`), counted before the token is
/// checked. An honest taker's busiest minute is the setup: at most `MAX_J_EXCHANGES` (64,
/// about ten in practice) `/j` calls and one `/sigs`, then one `GET` per poll and at most one
/// `/xmr-lock` beside it: 64 + 1 + 2 * 60 = 185 at `--poll-secs 1`, 77 at the default 10 s.
pub const XMR_SWAP_LIMIT_PER_WINDOW: u32 = 300;
/// Token misses (the 404 of a wrong, missing or other-swap token, or an unknown id) one IP may
/// make per [`RATE_WINDOW`] on the XMR `:id` routes. Past it every XMR `:id` request from that
/// IP is a 429 for the rest of the window, right token or not, so a prober cannot keep
/// testing tokens. An honest taker reads its token from its own session file and never
/// misses; 20 leaves room for an operator's typos.
pub const XMR_TOKEN_MISS_LIMIT_PER_WINDOW: u32 = 20;
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

    /// Whether `ip` has used its whole budget in the current window, without counting a request.
    pub fn exhausted(&self, ip: IpAddr, now: Instant) -> bool {
        self.hits
            .lock()
            .get(&ip)
            .is_some_and(|(start, n)| now.duration_since(*start) < self.window && *n >= self.max)
    }
}

/// The limiter and whether its key may come from proxy headers.
#[derive(Clone)]
struct RateState {
    limiter: Arc<RateLimiter>,
    trust_proxy_headers: bool,
}

/// The address a request is rate limited under. The peer address comes from the connection
/// (`ConnectInfo`); a router served without it (in-process tests) shares one
/// unspecified-address bucket. With `trust_proxy_headers` the LAST address in
/// `X-Forwarded-For` (else `X-Real-IP`) wins when it parses, else the peer address: the last
/// entry is the one the nearest proxy wrote (nginx's `$proxy_add_x_forwarded_for` appends
/// `$remote_addr`), while earlier entries are whatever the client sent. Without
/// it the headers are never read: any client can send them, so honouring them by default
/// would let it pick its own bucket and defeat the limit.
fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, trust_proxy_headers: bool) -> IpAddr {
    let peer = peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if !trust_proxy_headers {
        return peer;
    }
    let header_ip = |name: &str, first_of_list: bool| -> Option<IpAddr> {
        let v = headers.get(name)?.to_str().ok()?;
        let v = if first_of_list {
            v.rsplit(',').next()?
        } else {
            v
        };
        v.trim().parse().ok()
    };
    header_ip("x-forwarded-for", true)
        .or_else(|| header_ip("x-real-ip", false))
        .unwrap_or(peer)
}

/// [`client_ip`] of a request, its peer taken from `ConnectInfo`.
fn request_ip(req: &Request, trust_proxy_headers: bool) -> IpAddr {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    client_ip(req.headers(), peer, trust_proxy_headers)
}

fn too_many() -> Response {
    ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into()).into_response()
}

/// 429 past the limit.
async fn rate_limit(State(l): State<RateState>, req: Request, next: Next) -> Response {
    let ip = request_ip(&req, l.trust_proxy_headers);
    if l.limiter.allow(ip, Instant::now()) {
        next.run(req).await
    } else {
        too_many()
    }
}

/// Counts the 404s of the route it wraps per IP ([`XMR_TOKEN_MISS_LIMIT_PER_WINDOW`]); once an
/// IP has used its misses, every request from it is a 429 until the window ends, before the
/// token is looked at.
async fn token_miss_limit(State(l): State<RateState>, req: Request, next: Next) -> Response {
    let ip = request_ip(&req, l.trust_proxy_headers);
    if l.limiter.exhausted(ip, Instant::now()) {
        return too_many();
    }
    let resp = next.run(req).await;
    if resp.status() == StatusCode::NOT_FOUND {
        l.limiter.allow(ip, Instant::now());
    }
    resp
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

/// `docs` kind holding a hashlock swap's token, keyed by the maker's swap id. A swap with no
/// such document predates tokens (or was accepted with tokenless swaps allowed): a legacy swap.
const TOKEN_KIND: &str = "hashlock_swap_token";

#[derive(Serialize, Deserialize)]
struct TokenDoc {
    token: String,
}

/// What the hashlock routes check: the per-swap tokens (kept beside the swaps in the maker's
/// database, through the docs table) and the operator token for the full listing.
#[derive(Clone)]
pub struct HashlockAuth {
    store: Store,
    operator_token: Option<Arc<String>>,
    allow_tokenless: bool,
}

impl HashlockAuth {
    /// Tokens are kept in `store`: pass the maker's own (a clone shares the connection).
    pub fn new(store: Store) -> Self {
        HashlockAuth {
            store,
            operator_token: None,
            allow_tokenless: false,
        }
    }

    /// The credential for `GET /swaps` (the listing); `None` or empty leaves the listing a 404.
    pub fn with_operator_token(mut self, token: Option<String>) -> Self {
        self.operator_token = token.filter(|t| !t.is_empty()).map(Arc::new);
        self
    }

    /// Let a taker that does not send `X-Swap-Token-Support` open a swap with no token (it is
    /// then a legacy swap: readable and lockable by anyone who knows its id).
    pub fn allow_tokenless(mut self, allow: bool) -> Self {
        self.allow_tokenless = allow;
        self
    }
}

/// The reply every refused hashlock swap call gets, whether the id is unknown or the token is
/// missing, wrong or another swap's.
fn no_swap(id: &str) -> Response {
    ApiError(StatusCode::NOT_FOUND, format!("no swap {id}")).into_response()
}

#[derive(Clone)]
struct SwapGate {
    auth: HashlockAuth,
    maker: Arc<Maker>,
}

/// Gate for `GET /swaps/:id` and `POST /swaps/:id/lock`, run before the body is parsed. A swap
/// with a token needs it in `X-Swap-Token`; a legacy swap (no token document) is open, as it
/// was; an unknown id is refused. All refusals are the one 404 of [`no_swap`].
async fn hashlock_token_gate(
    State(g): State<SwapGate>,
    Path(params): Path<HashMap<String, String>>,
    req: Request,
    next: Next,
) -> Response {
    let id = params.get("id").map(String::as_str).unwrap_or("");
    let given = req
        .headers()
        .get(HASHLOCK_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ok = match g.auth.store.get_doc::<TokenDoc>(TOKEN_KIND, id) {
        Ok(Some(d)) => token_matches(&d.token, given),
        Ok(None) => matches!(g.maker.view(id), Ok(Some(_))),
        Err(_) => false,
    };
    if ok {
        next.run(req).await
    } else {
        no_swap(id)
    }
}

/// Gate for `GET /swaps`: the operator token, or a bare 404 (the answer for a route that does
/// not exist). With no operator token configured the listing is always a 404.
async fn operator_gate(State(a): State<HashlockAuth>, req: Request, next: Next) -> Response {
    let given = req
        .headers()
        .get(OPERATOR_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match &a.operator_token {
        Some(t) if token_matches(t, given) => next.run(req).await,
        _ => StatusCode::NOT_FOUND.into_response(),
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
    router_with_proxy(state, xmr, prefix, false)
}

/// [`router_with_xmr`] with `trust_proxy_headers`: key the rate limit on the client address
/// a reverse proxy you control puts in `X-Forwarded-For`/`X-Real-IP` instead of the socket
/// peer (which is the proxy's own address for every client).
pub fn router_with_proxy(
    state: AppState,
    xmr: Option<Arc<XmrMaker>>,
    prefix: &str,
    trust_proxy_headers: bool,
) -> Router {
    // Swap tokens in memory only, no operator token: for in-process tests. The daemon calls
    // `router_with_auth` with the maker's own store.
    let auth = HashlockAuth::new(Store::in_memory().expect("in-memory store"));
    router_with_auth(state, xmr, prefix, trust_proxy_headers, auth)
}

/// [`router_with_proxy`] with the hashlock routes' credentials: every `/swaps/:id` call needs
/// the swap's `X-Swap-Token` (the same 404 as an unknown id otherwise; a swap with no token on
/// record is legacy and stays open), and `GET /swaps` needs the operator token (else 404).
pub fn router_with_auth(
    state: AppState,
    xmr: Option<Arc<XmrMaker>>,
    prefix: &str,
    trust_proxy_headers: bool,
    auth: HashlockAuth,
) -> Router {
    let gate = || {
        middleware::from_fn_with_state(
            SwapGate {
                auth: auth.clone(),
                maker: state.maker.clone(),
            },
            hashlock_token_gate,
        )
    };
    let operator = middleware::from_fn_with_state(auth.clone(), operator_gate);
    let rate = RateState {
        limiter: Arc::new(RateLimiter::new(RATE_LIMIT_PER_WINDOW, RATE_WINDOW)),
        trust_proxy_headers,
    };
    let limited = || middleware::from_fn_with_state(rate.clone(), rate_limit);
    let bucket = |max: u32| {
        middleware::from_fn_with_state(
            RateState {
                limiter: Arc::new(RateLimiter::new(max, RATE_WINDOW)),
                trust_proxy_headers,
            },
            rate_limit,
        )
    };
    let writes = bucket(WRITE_LIMIT_PER_WINDOW);
    let reads = bucket(READ_LIMIT_PER_WINDOW);
    let public = bucket(PUBLIC_READ_LIMIT_PER_WINDOW);
    let mut api = Router::new()
        .route("/healthz", get(healthz).route_layer(public.clone()))
        .route("/offers", get(offers).route_layer(public))
        .route("/offers/:id/quote", get(quote).route_layer(limited()))
        .route(
            "/swaps",
            post(accept).route_layer(writes.clone()).merge(
                get(list_swaps)
                    .route_layer(operator)
                    .route_layer(reads.clone()),
            ),
        )
        .route(
            "/swaps/:id",
            get(get_swap).route_layer(gate()).route_layer(reads),
        )
        .route(
            "/swaps/:id/lock",
            post(lock).route_layer(gate()).route_layer(writes),
        )
        .layer(Extension(auth.clone()))
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
                        .route_layer(middleware::from_fn_with_state(x.clone(), swap_token_gate))
                        .route_layer(middleware::from_fn_with_state(
                            RateState {
                                limiter: Arc::new(RateLimiter::new(
                                    XMR_TOKEN_MISS_LIMIT_PER_WINDOW,
                                    RATE_WINDOW,
                                )),
                                trust_proxy_headers,
                            },
                            token_miss_limit,
                        ))
                        .route_layer(bucket(XMR_SWAP_LIMIT_PER_WINDOW)),
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
            SwapError::Storage(_)
            | SwapError::StoreTooNew { .. }
            | SwapError::Secret(_)
            | SwapError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
    Extension(auth): Extension<HashlockAuth>,
    headers: HeaderMap,
    Json(req): Json<AcceptRequest>,
) -> Result<(StatusCode, Json<AcceptReply>), ApiError> {
    s.require_wallet()?;
    let tokens = headers
        .get(SWAP_TOKEN_SUPPORT_HEADER)
        .and_then(|v| v.to_str().ok())
        == Some("1");
    // Before the quote is spent: a taker that would never learn the token must not open a swap
    // it could not read.
    if !tokens && !auth.allow_tokenless {
        return Err(ApiError(
            StatusCode::UPGRADE_REQUIRED,
            format!(
                "this maker gives each swap a token; upgrade the taker to one that sends \
                 {SWAP_TOKEN_SUPPORT_HEADER}: 1 and returns the token in {HASHLOCK_TOKEN_HEADER}"
            ),
        ));
    }
    let view = s.maker.accept(req).await?;
    let swap_token = if tokens {
        let token = new_swap_token();
        auth.store
            .put_doc(
                TOKEN_KIND,
                &view.id,
                &TokenDoc {
                    token: token.clone(),
                },
            )
            .map_err(|_| {
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not store the swap token".into(),
                )
            })?;
        Some(token)
    } else {
        None
    };
    Ok((StatusCode::CREATED, Json(AcceptReply { view, swap_token })))
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

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn proxy_headers_are_ignored_unless_trusted() {
        let peer: IpAddr = "10.0.0.9".parse().unwrap();
        let h = headers(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-real-ip", "203.0.113.8"),
        ]);
        assert_eq!(
            client_ip(&h, Some(peer), false),
            peer,
            "default: spoofable, so unread"
        );
        assert_eq!(
            client_ip(&h, None, false),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn trusted_proxy_headers_pick_the_client_and_garbage_falls_back() {
        let peer: IpAddr = "10.0.0.9".parse().unwrap();
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let xff = headers(&[("x-forwarded-for", "10.1.1.1, 203.0.113.7")]);
        assert_eq!(
            client_ip(&xff, Some(peer), true),
            ip("203.0.113.7"),
            "last entry: the one the proxy wrote"
        );
        let v6 = headers(&[("x-forwarded-for", " 2001:db8::1 ")]);
        assert_eq!(client_ip(&v6, Some(peer), true), ip("2001:db8::1"));
        let real = headers(&[("x-real-ip", "203.0.113.8")]);
        assert_eq!(client_ip(&real, Some(peer), true), ip("203.0.113.8"));
        let both = headers(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-real-ip", "203.0.113.8"),
        ]);
        assert_eq!(
            client_ip(&both, Some(peer), true),
            ip("203.0.113.7"),
            "XFF before X-Real-IP"
        );
        let bad_xff = headers(&[
            ("x-forwarded-for", "nonsense"),
            ("x-real-ip", "203.0.113.8"),
        ]);
        assert_eq!(client_ip(&bad_xff, Some(peer), true), ip("203.0.113.8"));
        let garbage = headers(&[("x-forwarded-for", "nonsense"), ("x-real-ip", "also,bad")]);
        assert_eq!(
            client_ip(&garbage, Some(peer), true),
            peer,
            "socket address"
        );
        assert_eq!(client_ip(&HeaderMap::new(), Some(peer), true), peer);
    }
}
