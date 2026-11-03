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

//! HTTP routes. Request/response bodies are the frozen `divi_swap::api` types.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::proxy::ProxyTrust;
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
/// (`POST /swaps` accept, and `POST /swaps/:id/lock` refused by its token gate). A taker
/// makes one of each per swap (a retry or two on a transient error); 20 leaves room for
/// several swaps a minute from one NAT address. A lock with the right token counts in its
/// swap's own bucket of the same size instead (a legacy swap's, per swap and IP). A separate
/// limiter from the quote/setup one so a swap's negotiation calls do not eat into each other.
pub const WRITE_LIMIT_PER_WINDOW: u32 = 20;
/// Requests one IP may make per [`RATE_WINDOW`] to `GET /swaps`, and to `GET /swaps/:id`
/// refused by its token gate; one swap may get as many with its right token, in its own
/// bucket (a legacy swap as many per IP). A live taker polls `GET /swaps/:id` once per
/// `--poll-secs` (default 10 s = 6 a minute; 1 s = 60). 300 is 5x the 1 s case, and a
/// separate limiter keeps status polling from exhausting the accept/lock budget.
pub const READ_LIMIT_PER_WINDOW: u32 = 300;
/// Requests one IP may make per [`RATE_WINDOW`] to the public reads `GET /healthz` and
/// `GET /offers`, in one bucket of their own. A health monitor polls every 10-60 s (1-6 a
/// minute; `swap-watch` and a taker's `wait_ready` are in that range), the landing page makes
/// one of each per view, and a taker one `/healthz` per poll while the scan runs. 600 is ten a
/// second: 10x a monitor polling every second, with room for a shared proxy bucket while
/// `trust_proxy_headers` is off. Enough to stop a flood from turning every request into chain
/// RPCs (`/healthz` asks each chain for its tip).
pub const PUBLIC_READ_LIMIT_PER_WINDOW: u32 = 600;
/// Requests one swap may get per [`RATE_WINDOW`] on the token-gated XMR routes
/// (`GET /xmr/swaps/:id`, `POST .../j`, `/sigs`, `/xmr-lock`) with its right token, counted
/// per swap id rather than per IP: clients sharing an address (behind a proxy with
/// `trust_proxy_headers` off) cannot spend each other's budget. Requests without the right
/// token count only as misses ([`XMR_TOKEN_MISS_LIMIT_PER_WINDOW`]): these routes have no
/// per-IP bucket, as one this size could never refuse before the miss limit. An honest
/// taker's busiest minute is the setup: at most `MAX_J_EXCHANGES` (64, about ten in practice)
/// `/j` calls and one `/sigs`, then one `GET` per poll and at most one `/xmr-lock` beside it:
/// 64 + 1 + 2 * 60 = 185 at `--poll-secs 1`, 77 at the default 10 s.
pub const XMR_SWAP_LIMIT_PER_WINDOW: u32 = 300;
/// Token misses (a wrong, missing or other-swap token, or an unknown id) one IP may make per
/// [`RATE_WINDOW`] on the XMR `:id` routes and the hashlock ones (`GET /swaps/:id`,
/// `POST /swaps/:id/lock`) together: one budget, so a prober gets 20 misses in all, not 20 on
/// each. Past it every request from that IP to those routes without the right token is a 429
/// for the rest of the window; a request with the right token still passes, so a prober
/// sharing an address cannot lock a taker out.
/// The 429-versus-200 split does tell a locked-out prober which guess is right, so the limit
/// slows guessing only up to the lockout; what stops guessing is the token's 256 bits
/// ([`new_swap_token`]). An honest taker reads its token from its own session file and never
/// misses; 20 leaves room for an operator's typos.
pub const XMR_TOKEN_MISS_LIMIT_PER_WINDOW: u32 = 20;
/// Length of the fixed window [`RATE_LIMIT_PER_WINDOW`] counts in.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Most distinct IPs the limiter tracks; at this many, expired windows are swept first and,
/// if it is still full, an unknown IP is refused (a flood of spoofed sources cannot grow the
/// map without bound).
const RATE_MAX_TRACKED: usize = 10_000;

/// Fixed-window request counter, per IP unless keyed otherwise (the XMR per-swap bucket keys
/// on the swap id).
pub struct RateLimiter<K = IpAddr> {
    max: u32,
    window: Duration,
    hits: parking_lot::Mutex<HashMap<K, (Instant, u32)>>,
}

impl<K: Hash + Eq> RateLimiter<K> {
    /// At most `max` requests per `window` per IP.
    pub fn new(max: u32, window: Duration) -> Self {
        RateLimiter {
            max,
            window,
            hits: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Count one request from `ip` at `now`; `false` when it is over the limit.
    pub fn allow(&self, ip: K, now: Instant) -> bool {
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
    pub fn exhausted(&self, ip: &K, now: Instant) -> bool {
        self.hits
            .lock()
            .get(ip)
            .is_some_and(|(start, n)| now.duration_since(*start) < self.window && *n >= self.max)
    }
}

/// The limiter and which peers may name the client in proxy headers.
#[derive(Clone)]
struct RateState {
    limiter: Arc<RateLimiter>,
    proxy: ProxyTrust,
}

/// The address a request is rate limited under. The peer address comes from the connection
/// (`ConnectInfo`); a router served without it (in-process tests) shares one
/// unspecified-address bucket. When `proxy` trusts the peer (`trust_proxy_headers` on and the
/// peer in `trusted_proxies`), the LAST address in `X-Forwarded-For` (else `X-Real-IP`) wins
/// when it parses, else the peer address: the last entry is the one the nearest proxy wrote
/// (nginx's `$proxy_add_x_forwarded_for` appends `$remote_addr`), while earlier entries are
/// whatever the client sent. From any other peer the headers are never read: any client can
/// send them, so honouring them from a client that reached the daemon directly would let it
/// pick its own bucket and defeat the limit.
fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, proxy: &ProxyTrust) -> IpAddr {
    let peer = peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if !proxy.trusts(peer) {
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
fn request_ip(req: &Request, proxy: &ProxyTrust) -> IpAddr {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    client_ip(req.headers(), peer, proxy)
}

fn too_many() -> Response {
    ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into()).into_response()
}

/// 429 past the limit.
async fn rate_limit(State(l): State<RateState>, req: Request, next: Next) -> Response {
    let ip = request_ip(&req, &l.proxy);
    if l.limiter.allow(ip, Instant::now()) {
        next.run(req).await
    } else {
        too_many()
    }
}

/// The limits in front of the XMR `:id` routes and the maker that checks their tokens.
#[derive(Clone)]
struct XmrGate {
    maker: Arc<XmrMaker>,
    /// Requests with the right token, per swap id ([`XMR_SWAP_LIMIT_PER_WINDOW`]).
    per_swap: Arc<RateLimiter<String>>,
    /// Requests without it, as token misses per IP ([`XMR_TOKEN_MISS_LIMIT_PER_WINDOW`]),
    /// shared with the hashlock `:id` routes. No per-IP bucket: the misses bind first.
    misses: Arc<RateLimiter>,
    proxy: ProxyTrust,
}

/// Gate for every `/xmr/swaps/:id...` route, run before the body is parsed (a 422 for a bad
/// body would otherwise tell a prober the id exists). A request with the right token counts
/// in its swap's bucket only, so nothing another client on the same address does can use it
/// up. Any other request (missing, wrong or another swap's token, or an unknown id; the same
/// 404) counts as one of the address's misses (shared with the hashlock `:id` routes) and is
/// a 429 once they are used up. A wrong token for a real id never touches that id's bucket.
async fn xmr_swap_gate(
    State(g): State<XmrGate>,
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
    let now = Instant::now();
    if g.maker.authorize(id, token) {
        return if g.per_swap.allow(id.to_owned(), now) {
            next.run(req).await
        } else {
            too_many()
        };
    }
    let ip = request_ip(&req, &g.proxy);
    refuse(None, &g.misses, ip, now, || {
        ApiError(StatusCode::NOT_FOUND, format!("no xmr swap {id}")).into_response()
    })
}

/// A request a token gate turned away: a 429 once `ip` has used up its misses or its bucket
/// (`per_ip`, on a route that has one), else one more miss and `refusal`.
fn refuse(
    per_ip: Option<&RateLimiter>,
    misses: &RateLimiter,
    ip: IpAddr,
    now: Instant,
    refusal: impl FnOnce() -> Response,
) -> Response {
    if misses.exhausted(&ip, now) || per_ip.is_some_and(|b| !b.allow(ip, now)) {
        return too_many();
    }
    misses.allow(ip, now);
    refusal()
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
    /// Requests the gate lets through with the right token, per swap id (the route's size).
    per_swap: Arc<RateLimiter<String>>,
    /// Requests to a legacy swap, per (swap id, IP) (the same size): anyone may call one by
    /// its id, so one address cannot spend another's budget on it.
    legacy: Arc<RateLimiter<(String, IpAddr)>>,
    /// Requests it refuses, per IP: the route's bucket, shared with `GET /swaps` (reads) or
    /// `POST /swaps` (writes).
    per_ip: Arc<RateLimiter>,
    /// Token misses per IP on both hashlock `:id` routes ([`XMR_TOKEN_MISS_LIMIT_PER_WINDOW`]),
    /// shared with the XMR ones.
    misses: Arc<RateLimiter>,
    proxy: ProxyTrust,
}

/// Gate for `GET /swaps/:id` and `POST /swaps/:id/lock`, run before the body is parsed. A swap
/// with a token needs it in `X-Swap-Token`; a legacy swap (no token document) is open, as it
/// was; an unknown id is refused. All refusals are the one 404 of [`no_swap`]. As on the XMR
/// routes, a request with the right token counts in its swap's bucket only, and a refused one
/// in the address's bucket and as one of its misses (shared with the XMR routes), a 429 once
/// either is used up; a wrong token for a real id never touches that id's bucket. A legacy
/// swap counts per swap and address.
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
    let now = Instant::now();
    let ip = request_ip(&req, &g.proxy);
    let allowed = match g.auth.store.get_doc::<TokenDoc>(TOKEN_KIND, id) {
        Ok(Some(d)) if token_matches(&d.token, given) => g.per_swap.allow(id.to_owned(), now),
        Ok(None) if matches!(g.maker.view(id), Ok(Some(_))) => {
            g.legacy.allow((id.to_owned(), ip), now)
        }
        _ => return refuse(Some(&g.per_ip), &g.misses, ip, now, || no_swap(id)),
    };
    if allowed {
        next.run(req).await
    } else {
        too_many()
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
/// peer (which is the proxy's own address for every client), for requests from a proxy on this
/// host ([`ProxyTrust::loopback`], the default `trusted_proxies`).
pub fn router_with_proxy(
    state: AppState,
    xmr: Option<Arc<XmrMaker>>,
    prefix: &str,
    trust_proxy_headers: bool,
) -> Router {
    // Swap tokens in memory only, no operator token: for in-process tests. The daemon calls
    // `router_with_auth` with the maker's own store.
    let auth = HashlockAuth::new(Store::in_memory().expect("in-memory store"));
    let proxy = if trust_proxy_headers {
        ProxyTrust::loopback()
    } else {
        ProxyTrust::off()
    };
    router_with_auth(state, xmr, prefix, proxy, auth)
}

/// [`router_with_proxy`] with the hashlock routes' credentials: every `/swaps/:id` call needs
/// the swap's `X-Swap-Token` (the same 404 as an unknown id otherwise; a swap with no token on
/// record is legacy and stays open), and `GET /swaps` needs the operator token (else 404).
/// `proxy` names the peers whose `X-Forwarded-For`/`X-Real-IP` the rate limits key on
/// ([`ProxyTrust::off`]: none).
pub fn router_with_auth(
    state: AppState,
    xmr: Option<Arc<XmrMaker>>,
    prefix: &str,
    proxy: ProxyTrust,
    auth: HashlockAuth,
) -> Router {
    let write_ips = Arc::new(RateLimiter::new(WRITE_LIMIT_PER_WINDOW, RATE_WINDOW));
    let read_ips = Arc::new(RateLimiter::new(READ_LIMIT_PER_WINDOW, RATE_WINDOW));
    let misses = Arc::new(RateLimiter::new(
        XMR_TOKEN_MISS_LIMIT_PER_WINDOW,
        RATE_WINDOW,
    ));
    let gate = |max: u32, per_ip: &Arc<RateLimiter>| {
        middleware::from_fn_with_state(
            SwapGate {
                auth: auth.clone(),
                maker: state.maker.clone(),
                per_swap: Arc::new(RateLimiter::new(max, RATE_WINDOW)),
                legacy: Arc::new(RateLimiter::new(max, RATE_WINDOW)),
                per_ip: per_ip.clone(),
                misses: misses.clone(),
                proxy: proxy.clone(),
            },
            hashlock_token_gate,
        )
    };
    let operator = middleware::from_fn_with_state(auth.clone(), operator_gate);
    let rate = RateState {
        limiter: Arc::new(RateLimiter::new(RATE_LIMIT_PER_WINDOW, RATE_WINDOW)),
        proxy: proxy.clone(),
    };
    let limited = || middleware::from_fn_with_state(rate.clone(), rate_limit);
    let on = |limiter: Arc<RateLimiter>| {
        middleware::from_fn_with_state(
            RateState {
                limiter,
                proxy: proxy.clone(),
            },
            rate_limit,
        )
    };
    let writes = on(write_ips.clone());
    let reads = on(read_ips.clone());
    let public = on(Arc::new(RateLimiter::new(
        PUBLIC_READ_LIMIT_PER_WINDOW,
        RATE_WINDOW,
    )));
    let mut api = Router::new()
        .route("/healthz", get(healthz).route_layer(public.clone()))
        .route("/offers", get(offers).route_layer(public))
        .route("/offers/:id/quote", get(quote).route_layer(limited()))
        .route(
            "/swaps",
            post(accept)
                .route_layer(writes)
                .merge(get(list_swaps).route_layer(operator).route_layer(reads)),
        )
        .route(
            "/swaps/:id",
            get(get_swap).route_layer(gate(READ_LIMIT_PER_WINDOW, &read_ips)),
        )
        .route(
            "/swaps/:id/lock",
            post(lock).route_layer(gate(WRITE_LIMIT_PER_WINDOW, &write_ips)),
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
                        .route_layer(middleware::from_fn_with_state(
                            XmrGate {
                                maker: x.clone(),
                                per_swap: Arc::new(RateLimiter::new(
                                    XMR_SWAP_LIMIT_PER_WINDOW,
                                    RATE_WINDOW,
                                )),
                                misses: misses.clone(),
                                proxy: proxy.clone(),
                            },
                            xmr_swap_gate,
                        )),
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
            SwapError::Transient(_) | SwapError::Premature(_) | SwapError::Held(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            SwapError::Rejected(_) | SwapError::InputsHeld(_) | SwapError::InsufficientFunds(_) => {
                StatusCode::CONFLICT
            }
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
    Ok(Json(
        s.maker
            .notify_lock_with_divi_ready(&id, notice, s.scan.is_done())
            .await?,
    ))
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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn proxy_headers_are_ignored_unless_trusted() {
        let peer = ip("127.0.0.1");
        let h = headers(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-real-ip", "203.0.113.8"),
        ]);
        let off = ProxyTrust::off();
        assert_eq!(
            client_ip(&h, Some(peer), &off),
            peer,
            "flag off: spoofable, so unread, even from loopback"
        );
        assert_eq!(client_ip(&h, None, &off), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            client_ip(&h, None, &ProxyTrust::loopback()),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "no peer address: nothing to trust"
        );
    }

    /// Fails on 75c9b7c, where the flag alone made any peer's headers count (the key was
    /// 1.2.3.4).
    #[test]
    fn an_untrusted_peer_is_keyed_on_itself_whatever_its_headers_say() {
        let proxy = ProxyTrust::loopback();
        let peer = ip("203.0.113.9");
        let xff = headers(&[("x-forwarded-for", "1.2.3.4")]);
        assert_eq!(client_ip(&xff, Some(peer), &proxy), peer);
        let real = headers(&[("x-real-ip", "1.2.3.4")]);
        assert_eq!(client_ip(&real, Some(peer), &proxy), peer);
        assert_eq!(
            client_ip(&xff, Some(ip("127.0.0.2")), &proxy),
            ip("127.0.0.2"),
            "127.0.0.1/32 only"
        );
        let elsewhere = ProxyTrust::proxies(["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(
            client_ip(&xff, Some(ip("127.0.0.1")), &elsewhere),
            ip("127.0.0.1"),
            "loopback is trusted only when listed"
        );
        assert_eq!(
            client_ip(&xff, Some(ip("10.2.3.4")), &elsewhere),
            ip("1.2.3.4")
        );
    }

    #[test]
    fn trusted_proxy_headers_pick_the_client_and_garbage_falls_back() {
        let proxy = ProxyTrust::loopback();
        let peer = ip("127.0.0.1");
        let xff = headers(&[("x-forwarded-for", "10.1.1.1, 203.0.113.7")]);
        assert_eq!(
            client_ip(&xff, Some(peer), &proxy),
            ip("203.0.113.7"),
            "last entry: the one the proxy wrote"
        );
        assert_eq!(
            client_ip(&xff, Some(ip("::1")), &proxy),
            ip("203.0.113.7"),
            "IPv6 loopback"
        );
        assert_eq!(
            client_ip(&xff, Some(ip("::ffff:127.0.0.1")), &proxy),
            ip("203.0.113.7"),
            "IPv4 loopback on a dual-stack listener"
        );
        let v6 = headers(&[("x-forwarded-for", " 2001:db8::1 ")]);
        assert_eq!(client_ip(&v6, Some(peer), &proxy), ip("2001:db8::1"));
        let real = headers(&[("x-real-ip", "203.0.113.8")]);
        assert_eq!(client_ip(&real, Some(peer), &proxy), ip("203.0.113.8"));
        let both = headers(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-real-ip", "203.0.113.8"),
        ]);
        assert_eq!(
            client_ip(&both, Some(peer), &proxy),
            ip("203.0.113.7"),
            "XFF before X-Real-IP"
        );
        let bad_xff = headers(&[
            ("x-forwarded-for", "nonsense"),
            ("x-real-ip", "203.0.113.8"),
        ]);
        assert_eq!(client_ip(&bad_xff, Some(peer), &proxy), ip("203.0.113.8"));
        let garbage = headers(&[("x-forwarded-for", "nonsense"), ("x-real-ip", "also,bad")]);
        assert_eq!(
            client_ip(&garbage, Some(peer), &proxy),
            peer,
            "socket address"
        );
        assert_eq!(client_ip(&HeaderMap::new(), Some(peer), &proxy), peer);
    }
}
