// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! IronDivi's optional web interface, on with `-webui`. It listens on the
//! loopback unless told otherwise, signs in with its own password (set once
//! with a token from the data directory) or an enrolled WebAuthn P-256 passkey,
//! and calls the daemon in-process: the RPC password never reaches the browser.
//! It keeps the wallet's keys in: no key exports, spending unlocks of ten
//! minutes at most, and nothing but reads until the wallet is encrypted.

pub mod auth;
pub mod chainview;
pub mod conffile;
pub mod gate;
pub mod launch;
pub mod node_passkey;
pub mod schema;
pub mod wallets;
pub mod webauthn;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use divi_rpc::{logctl, Params, RequestId, RpcServer};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{broadcast, Semaphore};
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

use auth::{AuthStore, LoginLimiter, Sessions, COOKIE_NAME, MIN_PASSWORD_LEN};

/// The web interface's port when `-webuiport` is not given: the RPC port's
/// neighbourhood, one per network
pub fn default_port(private_divi: bool, testnet: bool, regtest: bool) -> u16 {
    let base = if private_divi { 52480 } else { 51480 };
    base + if regtest {
        2
    } else if testnet {
        1
    } else {
        0
    }
}

/// How the web interface runs, from `-webui*` and the daemon's settings
#[derive(Debug, Clone)]
pub struct WebUiConfig {
    pub bind: SocketAddr,
    /// `-webuiallowremote`: a bind off the loopback is allowed
    pub allow_remote: bool,
    /// `-webuiallowhost`: names the browser may call this interface by
    pub allow_hosts: Vec<String>,
    pub data_dir: PathBuf,
    /// The config file the daemon read (or would read)
    pub conf_path: PathBuf,
    /// "main", "test" or "regtest"
    pub network: String,
    /// "divi" or "privatedivi"
    pub chain_mode: String,
    /// The values the command line gave, which win over the file
    pub cli: conffile::Values,
    /// `-webuiopen`: open the browser at start, signed in, when someone is
    /// at the screen
    pub open_browser: bool,
}

/// The interface with its port taken, before the daemon's RPC server exists
pub struct Prepared {
    listener: std::net::TcpListener,
    config: WebUiConfig,
    auth: AuthStore,
    sidechains: Option<Router>,
}

/// Take the port and read the password file. Run before the node starts, so
/// a port in use stops the daemon at once.
pub fn prepare(config: WebUiConfig) -> anyhow::Result<Prepared> {
    if !config.bind.ip().is_loopback() && !config.allow_remote {
        anyhow::bail!(
            "-webuibind={} is not a loopback address; the web interface is plain HTTP, \
             so set -webuiallowremote=1 only behind a TLS proxy or a private network",
            config.bind.ip()
        );
    }
    let auth = AuthStore::open(&config.data_dir).context("web interface password file")?;
    let listener = std::net::TcpListener::bind(config.bind)
        .with_context(|| format!("Unable to bind the web interface to {}", config.bind))?;
    listener.set_nonblocking(true)?;
    if !config.bind.ip().is_loopback() {
        warn!(
            "The web interface listens on {} in plain HTTP; reach it through TLS or a private network",
            config.bind
        );
    }
    let url = format!("http://{}/", display_host(&config.bind));
    info!("Web interface on {}", url);
    if auth.setup_required() {
        info!(
            "Web interface setup: open {}#/setup and enter the token in {}",
            url,
            auth.setup_token_path().display()
        );
    }
    Ok(Prepared {
        listener,
        config,
        auth,
        sidechains: None,
    })
}

/// Show `localhost:<port>` for loopback and unspecified binds so browsers treat
/// the URL as a Potentially Trustworthy Origin where WebAuthn passkeys work.
fn display_host(addr: &SocketAddr) -> String {
    if addr.ip().is_unspecified() || addr.ip().is_loopback() {
        format!("localhost:{}", addr.port())
    } else {
        addr.to_string()
    }
}

struct Shared {
    config: WebUiConfig,
    auth: AuthStore,
    challenges: webauthn::ChallengeStore,
    sessions: Sessions,
    limiter: LoginLimiter,
    /// Password hashing takes 19 MiB and some tens of milliseconds; two at once
    hashing: Semaphore,
    /// Host header values accepted, lowercase
    hosts: Vec<String>,
    rpc: Arc<RpcServer>,
    launch: launch::LaunchToken,
    wallets: wallets::WalletStore,
    node_passkeys: node_passkey::NodePasskeyStore,
    /// The node's Electrum backend, which the wallets read; None without
    /// txindex and addressindex
    electrum: Option<Arc<divi_electrum::Backend>>,
}

impl Prepared {
    /// Serve the sidechain market's API under `/api/sidechains`. Its paths are
    /// relative to that prefix; the interface adds sign-in and its guard.
    pub fn with_sidechains(mut self, api: Router) -> Self {
        self.sidechains = Some(api);
        self
    }

    /// Serve until the daemon shuts down
    pub fn spawn(
        self,
        rpc: Arc<RpcServer>,
        electrum: Option<Arc<divi_electrum::Backend>>,
        mut shutdown: broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let Prepared {
            listener,
            config,
            auth,
            sidechains,
        } = self;
        let shared = Arc::new(Shared {
            hosts: allowed_hosts(&config),
            wallets: wallets::WalletStore::new(
                &config.data_dir,
                &config.network,
                &config.chain_mode,
            ),
            node_passkeys: node_passkey::NodePasskeyStore::new(&config.data_dir),
            config,
            auth,
            challenges: webauthn::ChallengeStore::default(),
            sessions: Sessions::default(),
            limiter: LoginLimiter::default(),
            hashing: Semaphore::new(2),
            rpc,
            launch: launch::LaunchToken::default(),
            electrum,
        });
        tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => l,
                Err(e) => {
                    warn!("Web interface stopped: {}", e);
                    return;
                }
            };
            if shared.config.open_browser && launch::desktop_session() {
                // The URL carries the token: it goes to the opener, never the log
                let url = format!(
                    "http://{}/launch?t={}",
                    display_host(&shared.config.bind),
                    shared.launch.issue()
                );
                if launch::open_browser(&url) {
                    info!("Web interface: opened the browser");
                } else {
                    info!("Web interface: no browser to open; sign in at the address above");
                }
            }
            let app = router(shared, sidechains.unwrap_or_else(no_sidechains));
            let served = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = shutdown.recv().await;
            })
            .await;
            if let Err(e) = served {
                warn!("Web interface stopped: {}", e);
            }
        })
    }
}

fn allowed_hosts(config: &WebUiConfig) -> Vec<String> {
    let port = config.bind.port();
    let mut names: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into()];
    if !config.bind.ip().is_unspecified() {
        names.push(match config.bind.ip() {
            IpAddr::V6(v6) => format!("[{v6}]"),
            ip => ip.to_string(),
        });
    }
    let mut hosts = Vec::new();
    for name in names {
        let candidate = format!("{name}:{port}");
        if !hosts.contains(&candidate) {
            hosts.push(candidate);
        }
    }
    for name in &config.allow_hosts {
        let name = name.trim().to_lowercase();
        if name.is_empty() {
            continue;
        }
        // As given (with its own port, or none behind a proxy on 443) and
        // with this interface's port
        hosts.push(format!("{name}:{port}"));
        hosts.push(name);
    }
    hosts
}

/// What `/api/sidechains` answers when the node has no sidechain market
fn no_sidechains() -> Router {
    Router::new().fallback(|| async {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "the sidechain market is not installed in this node",
                "code": "not_installed",
            })),
        )
    })
}

/// Sidechain API calls need a session; anything but a read also its CSRF token
async fn sidechains_signed_in(State(s): State<Arc<Shared>>, req: Request, next: Next) -> Response {
    let write = req.method() != Method::GET && req.method() != Method::HEAD;
    match signed_in(&s, req.headers(), write) {
        Ok(_) => next.run(req).await,
        Err(e) => e.into_response(),
    }
}

fn router(shared: Arc<Shared>, sidechains: Router) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(|| js(include_str!("../static/app.js"))))
        .route("/pay.js", get(|| js(include_str!("../static/pay.js"))))
        .route(
            "/qrcode.js",
            get(|| js(include_str!("../static/qrcode.js"))),
        )
        .route("/jsqr.js", get(|| js(include_str!("../static/jsqr.js"))))
        .route("/nft.js", get(|| js(include_str!("../static/nft.js"))))
        .route(
            "/nftkit.js",
            get(|| js(include_str!("../static/nftkit.js"))),
        )
        .route(
            "/wallets.js",
            get(|| js(include_str!("../static/wallets.js"))),
        )
        .route(
            "/sidechains.js",
            get(|| js(include_str!("../static/sidechains.js"))),
        )
        .route("/app.css", get(app_css))
        .route("/launch", get(launch_in))
        .route("/api/state", get(api_state))
        .route("/api/auth/status", get(api_auth_status))
        .route(
            "/api/auth/passkey/login/start",
            post(api_passkey_login_start),
        )
        .route(
            "/api/auth/passkey/login/finish",
            post(api_passkey_login_finish),
        )
        .route(
            "/api/auth/passkey/register/start",
            post(api_passkey_register_start),
        )
        .route(
            "/api/auth/passkey/register/finish",
            post(api_passkey_register_finish),
        )
        .route("/api/auth/passkey/:id", delete(api_passkey_delete))
        .route("/api/setup", post(api_setup))
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route("/api/password", post(api_password))
        .route("/api/rpc", post(api_rpc))
        .route("/api/settings", get(api_settings).post(api_save_settings))
        .route("/api/logs", get(api_logs).post(api_log_filter))
        .route("/api/wallets", get(api_wallets))
        .route("/api/wallets/create", post(api_wallet_create))
        .route("/api/wallets/import", post(api_wallet_import))
        .route("/api/wallets/:id", get(api_wallet_show))
        .route("/api/wallets/:id/backup", get(api_wallet_backup))
        .route(
            "/api/wallets/:id/passkeys/:slot_id",
            delete(api_wallet_passkey_delete),
        )
        .route("/api/wallets/:id/:action", post(api_wallet_action))
        .route(
            "/api/node-wallet/passkeys",
            get(api_node_passkeys_list).post(api_node_passkeys_enroll),
        )
        .route(
            "/api/node-wallet/unlock-passkey",
            post(api_node_passkeys_unlock),
        )
        .route(
            "/api/node-wallet/passkeys/:slot_id",
            delete(api_node_passkeys_delete),
        )
        .route("/api/nft/*path", get(api_nft).post(api_nft))
        .nest_service(
            "/api/sidechains",
            sidechains.layer(axum::middleware::from_fn_with_state(
                shared.clone(),
                sidechains_signed_in,
            )),
        )
        .layer(axum::middleware::from_fn_with_state(shared.clone(), guard))
        .layer(DefaultBodyLimit::max(1 << 20))
        .with_state(shared)
}

const CSP: &str = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
                   form-action 'self'; object-src 'none'";

/// Every request: a known Host (no DNS rebinding), a same-origin JSON POST,
/// PUT or DELETE, and headers that keep the page out of frames and caches
async fn guard(State(s): State<Arc<Shared>>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_lowercase);
    let Some(host) = host.filter(|h| s.hosts.contains(h)) else {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "unknown host; see -webuiallowhost",
        )
            .into_response();
    };
    if req.method() == Method::POST
        || req.method() == Method::PUT
        || req.method() == Method::DELETE
    {
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|h| h.to_str().ok());
        let same = origin.is_some_and(|o| {
            let o = o.to_lowercase();
            o == format!("http://{host}") || o == format!("https://{host}")
        });
        if !same {
            return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
        }
        let json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|c| c.starts_with("application/json"));
        if !json && !raw_upload(req.method(), req.uri().path()) {
            return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected JSON").into_response();
        }
    } else if req.method() != Method::GET && req.method() != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if api { "no-store" } else { "no-cache" }),
    );
    res
}

/// The NFT service the NFT page's kit calls through `/api/nft/`. Testnet
/// only: on any other network the proxy answers 404.
const NFT_API_TESTNET: &str = "https://nft-testnet.irondivi.com/nft/api/";
/// The service's own cap on a pinned image, plus room for nothing else
const NFT_FILE_LIMIT: usize = 8 << 20;
/// The largest answer passed back to the page
const NFT_REPLY_LIMIT: usize = 16 << 20;

/// The one POST that is not JSON: an image sent to be pinned, as raw bytes
/// with its own type. Same origin, session and CSRF token still apply.
fn raw_upload(method: &Method, path: &str) -> bool {
    method == Method::POST && path == "/api/nft/ipfs/file"
}

/// The service URL for `/api/nft/<path>?<query>`, or `None` off testnet or
/// for a path that could step outside the service's API
fn nft_upstream(network: &str, path: &str, query: Option<&str>) -> Option<String> {
    if network != "test" || path.is_empty() || path.starts_with('/') {
        return None;
    }
    let safe = |c: char| c.is_ascii_alphanumeric() || "/_-.".contains(c);
    if !path.chars().all(safe)
        || path
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return None;
    }
    let mut url = format!("{NFT_API_TESTNET}{path}");
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        if !q.chars().all(|c| c.is_ascii_graphic() && c != '#') {
            return None;
        }
        url.push('?');
        url.push_str(q);
    }
    Some(url)
}

fn nft_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("TLS client")
    })
}

/// `/api/nft/*`: the NFT page's kit reaching the testnet NFT service. A read
/// needs the session, a write also its CSRF token. Only the body, its type
/// and the service's own bearer token go upstream; never the session cookie.
async fn api_nft(State(s): State<Arc<Shared>>, req: Request) -> ApiResult {
    let write = req.method() != Method::GET && req.method() != Method::HEAD;
    signed_in(&s, req.headers(), write)?;
    let path = req.uri().path().strip_prefix("/api/nft/").unwrap_or("");
    let Some(url) = nft_upstream(&s.config.network, path, req.uri().query()) else {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "the NFT service is reached on testnet only".into(),
        ));
    };
    let mut up = nft_client().request(req.method().clone(), url);
    for name in [header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT] {
        if let Some(v) = req.headers().get(&name) {
            up = up.header(name, v.clone());
        }
    }
    if write {
        let body = axum::body::to_bytes(req.into_body(), NFT_FILE_LIMIT + 4096)
            .await
            .map_err(|_| ApiError(StatusCode::PAYLOAD_TOO_LARGE, "over 8 MiB".into()))?;
        up = up.body(body);
    }
    let gone = |_| {
        ApiError(
            StatusCode::BAD_GATEWAY,
            "the NFT service did not answer".into(),
        )
    };
    let res = up.send().await.map_err(gone)?;
    let status = res.status();
    let kind = res.headers().get(header::CONTENT_TYPE).cloned();
    if res
        .content_length()
        .is_some_and(|n| n > NFT_REPLY_LIMIT as u64)
    {
        return Err(ApiError(
            StatusCode::BAD_GATEWAY,
            "the NFT service answered too much".into(),
        ));
    }
    let body = res.bytes().await.map_err(gone)?;
    if body.len() > NFT_REPLY_LIMIT {
        return Err(ApiError(
            StatusCode::BAD_GATEWAY,
            "the NFT service answered too much".into(),
        ));
    }
    let mut out = (status, body).into_response();
    if let Some(kind) = kind {
        out.headers_mut().insert(header::CONTENT_TYPE, kind);
    }
    Ok(out)
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../static/index.html"),
    )
}

/// A script compiled in from `static/`: the app, the payment request format,
/// and the vendored QR encoder and decoder
async fn js(body: &'static str) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        body,
    )
}

async fn app_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../static/app.css"),
    )
}

/// A refusal the page shows as is
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

type ApiResult = Result<Response, ApiError>;

fn host_rp_id(headers: &HeaderMap) -> Result<String, ApiError> {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    webauthn::rp_id_from_host(host).map_err(bad)
}

fn cookie_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE_NAME)
        .map(|(_, v)| v.to_string())
}

/// The signed-in session's cookie; a write must also carry its CSRF token
fn signed_in(s: &Shared, headers: &HeaderMap, post: bool) -> Result<String, ApiError> {
    let denied = || ApiError(StatusCode::UNAUTHORIZED, "sign in first".into());
    let cookie = cookie_of(headers).ok_or_else(denied)?;
    let csrf = s.sessions.touch(&cookie).ok_or_else(denied)?;
    if post {
        let sent = headers
            .get("x-csrf-token")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if !auth::constant_time_eq(sent.as_bytes(), csrf.as_bytes()) {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "stale page; reload it".into(),
            ));
        }
    }
    Ok(cookie)
}

fn session_cookie(value: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{COOKIE_NAME}={value}; HttpOnly; SameSite=Strict; Path=/"
    ))
    .expect("hex cookie")
}

fn started(s: &Shared) -> Response {
    let session = s.sessions.create();
    let mut res = Json(json!({ "ok": true, "csrf": session.csrf })).into_response();
    res.headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&session.cookie));
    res
}

#[derive(Deserialize)]
struct LaunchQuery {
    #[serde(default)]
    t: String,
}

/// `/launch?t=<token>`: the browser the daemon opened signs in. A spent or
/// wrong token (a prefetch, a reload) lands on the sign-in page instead.
async fn launch_in(State(s): State<Arc<Shared>>, Query(q): Query<LaunchQuery>) -> Response {
    let mut res = (StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response();
    if s.launch.redeem(&q.t) {
        let session = s.sessions.create();
        res.headers_mut()
            .insert(header::SET_COOKIE, session_cookie(&session.cookie));
        info!("Web interface: signed in the browser it opened");
    }
    res
}

/// The wallet's `encryption_status`; None without a wallet
fn wallet_status(s: &Shared) -> Option<&'static str> {
    s.rpc.wallet().wallet_db().map(|w| w.encryption_status())
}

async fn api_state(State(s): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let csrf = cookie_of(&headers).and_then(|c| s.sessions.touch(&c));
    let mut state = json!({
        "setup_required": s.auth.setup_required(),
        "signed_in": csrf.is_some(),
        "has_passkey": s.auth.has_passkey(),
        "network": s.config.network,
        "chain_mode": s.config.chain_mode,
        "version": env!("CARGO_PKG_VERSION"),
        "min_password": MIN_PASSWORD_LEN,
        "max_full_unlock": gate::MAX_FULL_UNLOCK_SECS,
    });
    if let Some(csrf) = csrf {
        state["csrf"] = json!(csrf);
        state["wallet"] = json!(wallet_status(&s));
        state["conf"] = json!(s.config.conf_path.display().to_string());
        state["passkeys"] = json!(s.auth.passkey_summaries());
        state["node_passkeys"] = json!(s.node_passkeys.list());
    }
    Json(state).into_response()
}

async fn api_auth_status(State(s): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let signed = cookie_of(&headers).and_then(|c| s.sessions.touch(&c)).is_some();
    let mut status = json!({
        "setup_required": s.auth.setup_required(),
        "signed_in": signed,
        "has_passkey": s.auth.has_passkey(),
    });
    if signed {
        status["passkeys"] = json!(s.auth.passkey_summaries());
    }
    Json(status).into_response()
}

/// Run blocking work off the async worker threads
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    tokio::task::spawn_blocking(work).await
}

/// Run a password hash off the async threads, two at a time
async fn hashing<T: Send + 'static>(
    s: &Arc<Shared>,
    work: impl FnOnce(&AuthStore) -> T + Send + 'static,
) -> Result<T, ApiError> {
    let _permit = s
        .hashing
        .acquire()
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "shutting down".into()))?;
    let shared = Arc::clone(s);
    blocking(move || work(&shared.auth))
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "hashing failed".into()))
}

fn throttle(s: &Shared, ip: IpAddr) -> Result<(), ApiError> {
    match s.limiter.wait(ip) {
        Some(wait) => Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            format!("too many tries; wait {} s", wait.as_secs().max(1)),
        )),
        None => Ok(()),
    }
}

#[derive(Deserialize)]
struct SetupBody {
    #[serde(default)]
    token: String,
    password: String,
}

async fn api_setup(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<SetupBody>,
) -> ApiResult {
    if !s.auth.setup_required() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "the password is already set".into(),
        ));
    }
    throttle(&s, peer.ip())?;
    // The browser the daemon opened is already as trusted as the token
    let launched = signed_in(&s, &headers, true).ok();
    if launched.is_none() && !s.auth.check_setup_token(body.token.trim()) {
        s.limiter.failed(peer.ip());
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "wrong setup token".into(),
        ));
    }
    if body.password.chars().count() < MIN_PASSWORD_LEN {
        return Err(bad(format!(
            "the password needs {MIN_PASSWORD_LEN} characters or more"
        )));
    }
    let password = Zeroizing::new(body.password);
    hashing(&s, move |a| a.set_password(&password))
        .await?
        .map_err(|e| bad(e.to_string()))?;
    s.limiter.succeeded(peer.ip());
    info!("Web interface password set");
    if let Some(cookie) = launched {
        s.sessions.remove(&cookie);
    }
    Ok(started(&s))
}

#[derive(Deserialize)]
struct LoginBody {
    password: String,
}

async fn api_login(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginBody>,
) -> ApiResult {
    if s.auth.setup_required() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "set the password first".into(),
        ));
    }
    throttle(&s, peer.ip())?;
    let password = Zeroizing::new(body.password);
    if !hashing(&s, move |a| a.verify(&password)).await? {
        s.limiter.failed(peer.ip());
        warn!("Web interface: failed sign-in from {}", peer.ip());
        return Err(ApiError(StatusCode::UNAUTHORIZED, "wrong password".into()));
    }
    s.limiter.succeeded(peer.ip());
    Ok(started(&s))
}

async fn api_passkey_login_start(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult {
    if s.auth.setup_required() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "set the password first".into(),
        ));
    }
    throttle(&s, peer.ip())?;
    let rp_id = host_rp_id(&headers)?;
    let allow: Vec<Value> = s
        .auth
        .passkeys()
        .into_iter()
        .filter(|p| p.rp_id == rp_id)
        .map(|p| json!({ "id": p.credential_id_b64url, "type": "public-key" }))
        .collect();
    if allow.is_empty() {
        return Err(bad("no passkey is registered for this host"));
    }
    let challenge = s.challenges.issue(webauthn::Purpose::Login, rp_id.clone());
    Ok(Json(json!({
        "challenge": challenge,
        "rp_id": rp_id,
        "allow_credentials": allow,
    }))
    .into_response())
}

#[derive(Deserialize)]
struct PasskeyLoginFinishBody {
    #[serde(alias = "credentialId")]
    credential_id: String,
    #[serde(alias = "clientDataJSON")]
    client_data_json: String,
    #[serde(alias = "authenticatorData")]
    authenticator_data: String,
    signature: String,
}

async fn api_passkey_login_finish(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<PasskeyLoginFinishBody>,
) -> ApiResult {
    if s.auth.setup_required() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "set the password first".into(),
        ));
    }
    throttle(&s, peer.ip())?;
    let passkeys = s.auth.passkeys();
    let verified = webauthn::verify_assertion(
        &s.challenges,
        &s.hosts,
        &passkeys,
        &body.credential_id,
        &body.client_data_json,
        &body.authenticator_data,
        &body.signature,
    );
    let (cred, new_sign_count) = match verified {
        Ok(v) => v,
        Err(msg) => {
            s.limiter.failed(peer.ip());
            warn!("Web interface: failed passkey sign-in from {}: {}", peer.ip(), msg);
            return Err(ApiError(StatusCode::UNAUTHORIZED, msg));
        }
    };
    if let Err(e) = s.auth.update_passkey_sign_count(&cred.id, new_sign_count) {
        warn!("Web interface: could not update passkey sign_count: {}", e);
    }
    s.limiter.succeeded(peer.ip());
    Ok(started(&s))
}

#[derive(Deserialize)]
struct PasskeyRegisterStartBody {
    password: String,
    #[serde(default)]
    label: String,
}

async fn api_passkey_register_start(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasskeyRegisterStartBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    throttle(&s, peer.ip())?;
    let rp_id = host_rp_id(&headers)?;
    let label = auth::clean_label(&body.label, "Passkey").map_err(bad)?;
    let password = Zeroizing::new(body.password);
    if !hashing(&s, move |a| a.verify(&password)).await? {
        s.limiter.failed(peer.ip());
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "wrong current password".into(),
        ));
    }
    s.limiter.succeeded(peer.ip());
    let exclude: Vec<Value> = s
        .auth
        .passkeys()
        .into_iter()
        .filter(|p| p.rp_id == rp_id)
        .map(|p| json!({ "id": p.credential_id_b64url, "type": "public-key" }))
        .collect();
    let challenge = s
        .challenges
        .issue(webauthn::Purpose::Register { label }, rp_id.clone());
    Ok(Json(json!({
        "challenge": challenge,
        "rp_id": rp_id,
        "rp_name": "IronDivi WebUI",
        "user": {
            "id": webauthn::b64url_encode(b"irondivi-webui-admin"),
            "name": "admin",
            "display_name": "IronDivi Admin",
        },
        "exclude_credentials": exclude,
    }))
    .into_response())
}

#[derive(Deserialize)]
struct PasskeyRegisterFinishBody {
    #[serde(alias = "clientDataJSON")]
    client_data_json: String,
    #[serde(alias = "attestationObject")]
    attestation_object: String,
}

async fn api_passkey_register_finish(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    Json(body): Json<PasskeyRegisterFinishBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    let verified = webauthn::verify_registration(
        &s.challenges,
        &s.hosts,
        &body.client_data_json,
        &body.attestation_object,
    )
    .map_err(bad)?;
    let summary = s
        .auth
        .add_passkey(
            &verified.label,
            verified.credential_id_b64url,
            verified.public_key_sec1_hex,
            verified.rp_id,
            verified.sign_count,
        )
        .map_err(bad)?;
    info!("Web interface registered admin passkey {}", summary.id);
    Ok(Json(json!({ "ok": true, "passkey": summary })).into_response())
}

#[derive(Deserialize)]
struct PasskeyDeleteBody {
    password: String,
}

async fn api_passkey_delete(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<PasskeyDeleteBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    throttle(&s, peer.ip())?;
    let password = Zeroizing::new(body.password);
    if !hashing(&s, move |a| a.verify(&password)).await? {
        s.limiter.failed(peer.ip());
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "wrong current password".into(),
        ));
    }
    s.limiter.succeeded(peer.ip());
    if !s.auth.remove_passkey(&id).map_err(bad)? {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such passkey".into()));
    }
    info!("Web interface removed admin passkey {}", id);
    Ok(Json(json!({ "ok": true })).into_response())
}

async fn api_logout(State(s): State<Arc<Shared>>, headers: HeaderMap) -> ApiResult {
    let cookie = signed_in(&s, &headers, true)?;
    s.sessions.remove(&cookie);
    let mut res = Json(json!({ "ok": true })).into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("irondivi_webui=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    Ok(res)
}

#[derive(Deserialize)]
struct PasswordBody {
    current: String,
    new: String,
}

async fn api_password(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> ApiResult {
    let cookie = signed_in(&s, &headers, true)?;
    throttle(&s, peer.ip())?;
    if body.new.chars().count() < MIN_PASSWORD_LEN {
        return Err(bad(format!(
            "the password needs {MIN_PASSWORD_LEN} characters or more"
        )));
    }
    let current = Zeroizing::new(body.current);
    let new = Zeroizing::new(body.new);
    let changed = hashing(&s, move |a| {
        if !a.verify(&current) {
            return Ok(false);
        }
        a.set_password(&new).map(|_| true)
    })
    .await?
    .map_err(|e| bad(e.to_string()))?;
    if !changed {
        s.limiter.failed(peer.ip());
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "wrong current password".into(),
        ));
    }
    // Every other browser signs in again
    s.sessions.remove_all_but(Some(&cookie));
    info!("Web interface password changed");
    Ok(Json(json!({ "ok": true })).into_response())
}

/// Call the daemon in-process, as its RPC server would
async fn call(s: &Arc<Shared>, method: &str, params: Vec<Value>) -> Result<Value, (i64, String)> {
    let request = divi_rpc::Request {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    };
    let rpc = Arc::clone(&s.rpc);
    let response = blocking(move || rpc.handle_request_from(request, divi_rpc::Caller::webui()))
        .await
        .map_err(|_| (-1, "the call failed".to_string()))?;
    match response.error {
        Some(e) => Err((e.code as i64, e.message)),
        None => Ok(response.result.unwrap_or(Value::Null)),
    }
}

#[derive(Deserialize)]
struct RpcBody {
    method: String,
    #[serde(default)]
    params: Vec<Value>,
}

async fn api_rpc(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RpcBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    let method = body.method.trim().to_string();
    gate::check(&method, &body.params, wallet_status(&s))
        .map_err(|e| ApiError(StatusCode::FORBIDDEN, e))?;
    // diag A15: the call, never its parameters
    let transport = divi_rpc::diag_rpc::Transport::WebUi;
    let watch = divi_rpc::diag_rpc::begin(&method, transport);
    let result = call(&s, &method, body.params).await;
    watch.finish(
        &method,
        transport,
        Some(peer.ip()),
        true,
        result.as_ref().err().map(|(c, m)| (*c, m.as_str())),
    );
    if method == "walletpassphrasechange" && result.is_ok() {
        let _ = s.node_passkeys.clear_all();
    }
    Ok(match result {
        Ok(result) => Json(json!({ "result": result })),
        Err((code, message)) => Json(json!({ "error": { "code": code, "message": message } })),
    }
    .into_response())
}

/// Option values for the page: a secret's value never leaves, only that it is set
fn visible(values: &conffile::Values) -> Value {
    let mut shown = serde_json::Map::new();
    let mut secrets = Vec::new();
    let mut other = Vec::new();
    for (key, list) in values {
        match schema::find(key) {
            Some(o) if o.secret => secrets.push(key.clone()),
            Some(_) => {
                shown.insert(key.clone(), json!(list));
            }
            // An option the page does not know may be a key; its name only
            None => other.push(key.clone()),
        }
    }
    json!({ "values": shown, "secrets": secrets, "other": other })
}

async fn api_settings(State(s): State<Arc<Shared>>, headers: HeaderMap) -> ApiResult {
    signed_in(&s, &headers, false)?;
    let path = s.config.conf_path.clone();
    let (file, format) = blocking(move || {
        let text = std::fs::read_to_string(&path).ok();
        let format = conffile::format_of(&path, text.as_deref());
        (conffile::read_file(&path), format)
    })
    .await
    .map_err(|_| bad("cannot read the config file"))?;
    let file = file.map_err(bad)?;
    Ok(Json(json!({
        "schema": schema::to_json(),
        "conf": s.config.conf_path.display().to_string(),
        "format": match format { conffile::Format::Toml => "toml", conffile::Format::Divi => "divi" },
        "file": visible(&file),
        "cli": visible(&s.config.cli),
        "wallet": wallet_status(&s),
    }))
    .into_response())
}

#[derive(Deserialize)]
struct ChangeBody {
    key: String,
    values: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct SettingsBody {
    changes: Vec<ChangeBody>,
}

async fn api_save_settings(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    Json(body): Json<SettingsBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    if wallet_status(&s) == Some("unencrypted") {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "encrypt the wallet on the Security page before changing settings".into(),
        ));
    }
    if body.changes.is_empty() {
        return Err(bad("nothing to save"));
    }
    let mut changes = Vec::new();
    for c in &body.changes {
        let o = schema::find(&c.key).ok_or_else(|| bad(format!("{}: no such option", c.key)))?;
        if !o.writable {
            return Err(bad(format!("{} is not set from the web interface", o.key)));
        }
        if changes.iter().any(|x: &conffile::Change| x.key == o.key) {
            return Err(bad(format!("{} given twice", o.key)));
        }
        let values = match &c.values {
            None => None,
            Some(list) => {
                let list: Vec<String> = list
                    .iter()
                    .map(|v| schema::normalize(o, v))
                    .collect::<Result<_, _>>()
                    .map_err(bad)?;
                let list: Vec<String> = list
                    .into_iter()
                    .filter(|v| !v.is_empty() || !o.multi)
                    .collect();
                if !o.multi && list.len() > 1 {
                    return Err(bad(format!("{} takes one value", o.key)));
                }
                (!list.is_empty()).then_some(list)
            }
        };
        changes.push(conffile::Change {
            key: o.key.to_string(),
            values,
            toml: match o.kind {
                schema::Kind::Bool => conffile::TomlType::Bool,
                schema::Kind::Int(..) => conffile::TomlType::Int,
                _ => conffile::TomlType::Str,
            },
            multi: o.multi,
        });
    }
    let path = s.config.conf_path.clone();
    let to_write = changes.clone();
    // What the file held, to tell the daemon which peers came and went
    let before = blocking(move || {
        let before = conffile::read_file(&path).unwrap_or_default();
        conffile::apply(&path, &to_write).map(|()| before)
    })
    .await
    .map_err(|_| bad("cannot write the config file"))?
    .map_err(bad)?;
    info!(
        "Web interface changed {} in {}",
        changes
            .iter()
            .map(|c| c.key.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        divi_primitives::redact::WalletValue(&s.config.conf_path.to_string_lossy())
    );

    // What the running daemon takes now; the rest waits for a restart
    let mut live = Vec::new();
    let mut restart = Vec::new();
    for c in &changes {
        let overridden = s.config.cli.contains_key(&c.key);
        let method = schema::LIVE
            .iter()
            .find(|(k, _)| *k == c.key)
            .map(|(_, m)| *m);
        match (method, &c.values, overridden) {
            (Some(_), values, false) if c.key == "debug" || c.key == "loglevel" => {
                let outcome = set_log_filter(&c.key, values.as_deref());
                live.push(json!({ "key": c.key, "ok": outcome.is_ok(), "error": outcome.err() }));
            }
            (Some(_), values, false) if c.key == "addnode" => {
                let was: Vec<String> = before.get("addnode").cloned().unwrap_or_default();
                let now: Vec<String> = values.clone().unwrap_or_default();
                let mut errors = Vec::new();
                for (peer, how) in was
                    .iter()
                    .filter(|p| !now.contains(p))
                    .map(|p| (p, "remove"))
                    .chain(now.iter().filter(|p| !was.contains(p)).map(|p| (p, "add")))
                {
                    if let Err((_, m)) = call(&s, "addnode", vec![json!(peer), json!(how)]).await {
                        errors.push(format!("{peer}: {m}"));
                    }
                }
                live.push(json!({
                    "key": c.key,
                    "ok": errors.is_empty(),
                    "error": (!errors.is_empty()).then(|| errors.join("; ")),
                }));
            }
            (Some(method), Some(values), false) => {
                let param = match c.toml {
                    conffile::TomlType::Bool => json!(values[0] == "1"),
                    _ => serde_json::from_str::<Value>(&values[0]).unwrap_or(json!(values[0])),
                };
                let outcome = call(&s, method, vec![param]).await;
                live.push(json!({
                    "key": c.key,
                    "ok": outcome.is_ok(),
                    "error": outcome.err().map(|(_, m)| m),
                }));
            }
            _ => restart.push(c.key.clone()),
        }
    }
    let overridden: Vec<&String> = changes
        .iter()
        .map(|c| &c.key)
        .filter(|k| s.config.cli.contains_key(*k))
        .collect();
    Ok(Json(json!({
        "ok": true,
        "live": live,
        "restart": restart,
        "overridden": overridden,
    }))
    .into_response())
}

/// Apply a saved -debug or -loglevel to the running daemon's log filter
fn set_log_filter(key: &str, values: Option<&[String]>) -> Result<(), String> {
    let control = logctl::control().ok_or("the log filter cannot change in this process")?;
    if key == "loglevel" {
        let level = values
            .and_then(|v| v.first())
            .map(String::as_str)
            .unwrap_or("info");
        control.set(Some(level), None)
    } else {
        control.set(None, Some(values.unwrap_or(&[])))
    }
    .map(|_| ())
}

#[derive(Deserialize)]
struct LogsQuery {
    #[serde(default)]
    after: u64,
}

/// The log lines kept in memory after `after`, the filter now in force and
/// the categories there are
async fn api_logs(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    Query(q): Query<LogsQuery>,
) -> ApiResult {
    signed_in(&s, &headers, false)?;
    let control = logctl::control().ok_or_else(|| bad("no log view in this process"))?;
    let (lines, next) = control.lines_after(q.after, 500);
    Ok(Json(json!({
        "lines": lines,
        "next": next,
        "state": control.state(),
        "levels": logctl::LEVELS,
        "categories": logctl::CATEGORIES.iter().map(|(c, _)| *c).collect::<Vec<_>>(),
    }))
    .into_response())
}

#[derive(Deserialize)]
struct LogFilterBody {
    level: Option<String>,
    categories: Option<Vec<String>>,
}

/// Change the log filter now, without touching the config file
async fn api_log_filter(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    Json(body): Json<LogFilterBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    let control =
        logctl::control().ok_or_else(|| bad("the log filter cannot change in this process"))?;
    let state = control
        .set(body.level.as_deref(), body.categories.as_deref())
        .map_err(bad)?;
    info!(
        "Web interface set the log filter: level {}, debug {}",
        state.level,
        if state.categories.is_empty() {
            "none".into()
        } else {
            state.categories.join(",")
        }
    );
    Ok(Json(json!({ "state": state })).into_response())
}

/// Run a wallet's key derivation (64 MiB) off the async threads, two at a time
async fn sealed<T: Send + 'static>(
    s: &Arc<Shared>,
    work: impl FnOnce(&wallets::WalletStore) -> wallets::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    let _permit = s
        .hashing
        .acquire()
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "shutting down".into()))?;
    let shared = Arc::clone(s);
    blocking(move || work(&shared.wallets))
        .await
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the wallet task failed".into(),
            )
        })?
        .map_err(bad)
}

/// A wallet as the page sees it: never its sealed words or sealed_dek
fn wallet_json(w: &wallets::WalletFile, active: Option<&str>) -> Value {
    json!({
        "id": w.id,
        "name": w.name,
        "version": w.version,
        "created": w.created,
        "network": w.network,
        "active": active == Some(w.id.as_str()),
        "receive": w.receive.iter().take(w.next_receive as usize).collect::<Vec<_>>(),
        "derived": w.receive.len() + w.change.len(),
        "passkeys": w.passkey_summaries(),
    })
}

const NO_INDEX: &str =
    "the wallets read the node's Electrum backend: set txindex=1 and addressindex=1 and restart the node";

/// The wallet's balance, coins and history through the Electrum backend
async fn chain_view(s: &Shared, w: &wallets::WalletFile) -> Result<chainview::View, ApiError> {
    let backend = s.electrum.clone().ok_or_else(|| bad(NO_INDEX))?;
    let addresses = wallets::WalletStore::watched(w);
    let network = wallets::network_of(&s.config.network);
    blocking(move || chainview::read(&backend, &addresses, network))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(|e| {
            if e.contains("ddress index is off") {
                bad(NO_INDEX)
            } else {
                bad(e)
            }
        })
}

async fn api_wallets(State(s): State<Arc<Shared>>, headers: HeaderMap) -> ApiResult {
    signed_in(&s, &headers, false)?;
    let active = s.wallets.active();
    let list: Vec<Value> = s
        .wallets
        .list()
        .iter()
        .map(|w| wallet_json(w, active.as_deref()))
        .collect();
    Ok(
        Json(json!({ "wallets": list, "active": active, "network": s.config.network }))
            .into_response(),
    )
}

#[derive(Deserialize)]
struct WalletCreateBody {
    name: String,
    passphrase: String,
    /// Restore these words rather than make new ones
    #[serde(default)]
    words: Option<String>,
    #[serde(default)]
    bip39_passphrase: Option<String>,
}

impl Drop for WalletCreateBody {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        if let Some(w) = self.words.as_mut() {
            w.zeroize();
        }
        if let Some(p) = self.bip39_passphrase.as_mut() {
            p.zeroize();
        }
    }
}

/// Make or restore a wallet; new words are in the answer this once, to write down
async fn api_wallet_create(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    Json(body): Json<WalletCreateBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    let restoring = body.words.is_some();
    let (w, words) = sealed(&s, move |store| {
        store.create(
            &body.name,
            &body.passphrase,
            body.words.as_deref(),
            body.bip39_passphrase.as_deref(),
        )
    })
    .await?;
    info!(
        "Web interface {} wallet {}",
        if restoring { "restored" } else { "created" },
        w.id
    );
    let active = s.wallets.active();
    let mut out = json!({ "wallet": wallet_json(&w, active.as_deref()) });
    if !restoring {
        out["words"] = json!(words.as_str());
    }
    Ok(Json(out).into_response())
}

#[derive(Deserialize)]
struct WalletImportBody {
    /// The backup file's text
    backup: String,
    passphrase: String,
}

impl Drop for WalletImportBody {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

async fn api_wallet_import(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    Json(body): Json<WalletImportBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    let w = sealed(&s, move |store| {
        store.import(body.backup.as_bytes(), &body.passphrase)
    })
    .await?;
    info!("Web interface imported wallet {}", w.id);
    let active = s.wallets.active();
    Ok(Json(json!({ "wallet": wallet_json(&w, active.as_deref()) })).into_response())
}

/// A wallet's balance, coins and history, mempool included
async fn api_wallet_show(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    signed_in(&s, &headers, false)?;
    let w = s.wallets.get(&id).map_err(bad)?;
    let view = chain_view(&s, &w).await?;
    let history: Vec<Value> = view
        .history
        .iter()
        .map(|l| json!({ "txid": l.txid, "height": l.height, "satoshis": l.satoshis }))
        .collect();
    let active = s.wallets.active();
    Ok(Json(json!({
        "wallet": wallet_json(&w, active.as_deref()),
        "balance": { "confirmed": view.confirmed, "pending": view.pending },
        "coins": view.coins.len(),
        "history": history,
    }))
    .into_response())
}

/// The backup file: the wallet with its words sealed under its passphrase
async fn api_wallet_backup(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    signed_in(&s, &headers, false)?;
    let w = s.wallets.get(&id).map_err(bad)?;
    let file = s.wallets.backup(&id).map_err(bad)?;
    let name: String = w
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let disposition = format!(
        "attachment; filename=\"irondivi-wallet-{name}-{}.json\"",
        w.network
    );
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition).map_err(|_| bad("bad wallet name"))?,
            ),
        ],
        file,
    )
        .into_response())
}

#[derive(Deserialize, Clone)]
struct PasskeyUnlockInput {
    slot_id: String,
    prf_output: String,
}

impl Drop for PasskeyUnlockInput {
    fn drop(&mut self) {
        self.prf_output.zeroize();
    }
}

#[derive(Deserialize, Default)]
struct WalletActionBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    passkey: Option<PasskeyUnlockInput>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    credential_id: Option<String>,
    #[serde(default)]
    prf_salt: Option<String>,
    #[serde(default)]
    rp_id: Option<String>,
    #[serde(default)]
    prf_output: Option<String>,
    #[serde(default)]
    to: Option<String>,
    /// DIVI, as a decimal string
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    fee_from_amount: bool,
}

impl Drop for WalletActionBody {
    fn drop(&mut self) {
        if let Some(p) = self.passphrase.as_mut() {
            p.zeroize();
        }
        if let Some(p) = self.prf_output.as_mut() {
            p.zeroize();
        }
    }
}

fn select_wallet_auth<'a>(
    passphrase: Option<&'a str>,
    passkey: Option<&'a PasskeyUnlockInput>,
) -> Result<wallets::WalletAuth<'a>, String> {
    if let Some(pk) = passkey {
        return Ok(wallets::WalletAuth::Passkey {
            slot_id: &pk.slot_id,
            prf_output_b64: &pk.prf_output,
        });
    }
    if let Some(p) = passphrase.filter(|p| !p.is_empty()) {
        return Ok(wallets::WalletAuth::Passphrase(p));
    }
    Err("enter the wallet passphrase or use an enrolled passkey".into())
}

/// DIVI as a decimal string to satoshis
fn parse_divi(text: &str) -> Option<i64> {
    let text = text.trim();
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && frac.is_empty()
        || frac.len() > 8
        || !whole
            .bytes()
            .chain(frac.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: i64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let frac: i64 = format!("{frac:0<8}").parse().ok()?;
    whole
        .checked_mul(100_000_000)?
        .checked_add(frac)
        .filter(|v| *v > 0)
}

/// rename, switch, delete, words, address, send, and passkeys (enroll)
async fn api_wallet_action(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    axum::extract::Path((id, action)): axum::extract::Path<(String, String)>,
    Json(body): Json<WalletActionBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    let out = match action.as_str() {
        "rename" => {
            let w = s
                .wallets
                .rename(&id, body.name.as_deref().unwrap_or_default())
                .map_err(bad)?;
            json!({ "wallet": wallet_json(&w, s.wallets.active().as_deref()) })
        }
        "switch" => {
            s.wallets.set_active(&id).map_err(bad)?;
            json!({ "active": id })
        }
        "passkeys" => {
            let host_rp = host_rp_id(&headers)?;
            if let Some(sent_rp) = body.rp_id.as_deref().filter(|r| !r.is_empty()) {
                let checked = webauthn::rp_id_from_host(sent_rp).map_err(bad)?;
                if checked != host_rp {
                    return Err(bad("passkey rp_id does not match this host"));
                }
            }
            let wallet_id = id.clone();
            let (w, summary) = sealed(&s, move |store| {
                store.add_passkey(
                    &wallet_id,
                    body.passphrase.as_deref().unwrap_or_default(),
                    body.label.as_deref().unwrap_or_default(),
                    body.credential_id.as_deref().unwrap_or_default(),
                    body.prf_salt.as_deref().unwrap_or_default(),
                    &host_rp,
                    body.prf_output.as_deref().unwrap_or_default(),
                )
            })
            .await?;
            info!("Web interface enrolled passkey {} on wallet {}", summary.id, id);
            let active = s.wallets.active();
            json!({
                "ok": true,
                "wallet": wallet_json(&w, active.as_deref()),
                "passkey": summary,
            })
        }
        "delete" => {
            let gone = id.clone();
            sealed(&s, move |store| {
                let auth = select_wallet_auth(body.passphrase.as_deref(), body.passkey.as_ref())?;
                store.delete_with(&gone, auth)
            })
            .await?;
            info!("Web interface deleted wallet {}", id);
            json!({ "ok": true })
        }
        "words" => {
            let words = sealed(&s, move |store| {
                let auth = select_wallet_auth(body.passphrase.as_deref(), body.passkey.as_ref())?;
                store.words_with(&id, auth)
            })
            .await?;
            json!({ "words": words.as_str() })
        }
        "address" => {
            let address = sealed(&s, move |store| {
                let auth = select_wallet_auth(body.passphrase.as_deref(), body.passkey.as_ref()).ok();
                store.next_address_with(&id, auth)
            })
            .await?;
            json!({ "address": address })
        }
        "send" => {
            let to = body
                .to
                .clone()
                .ok_or_else(|| bad("send to which address?"))?;
            let amount = body
                .amount
                .as_deref()
                .and_then(parse_divi)
                .ok_or_else(|| bad("the amount is DIVI, more than 0, at most 8 decimals"))?;
            let w = s.wallets.get(&id).map_err(bad)?;
            let coins = chain_view(&s, &w).await?.coins;
            let tip = call(&s, "getblockcount", vec![])
                .await
                .map_err(|(c, m)| bad(format!("{m} ({c})")))?;
            let tip = tip.as_u64().unwrap_or(0) as u32;
            let fee_from_amount = body.fee_from_amount;
            let (hex, txid, fee) = sealed(&s, move |store| {
                let auth = select_wallet_auth(body.passphrase.as_deref(), body.passkey.as_ref())?;
                store.sign_send_with(
                    &id,
                    auth,
                    &coins,
                    tip,
                    wallets::SendRequest {
                        to: &to,
                        amount: divi_primitives::amount::Amount::from_sat(amount),
                        fee_from_amount,
                        policy: Default::default(),
                    },
                )
            })
            .await?;
            let sent = call(&s, "sendrawtransaction", vec![json!(hex)])
                .await
                .map_err(|(c, m)| bad(format!("the node refused the transaction: {m} ({c})")))?;
            json!({ "txid": sent.as_str().unwrap_or(&txid), "fee": fee })
        }
        _ => {
            return Err(ApiError(
                StatusCode::NOT_FOUND,
                "no such wallet action".into(),
            ))
        }
    };
    Ok(Json(out).into_response())
}

#[derive(Deserialize, Default)]
struct WalletPasskeyDeleteBody {
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    passkey: Option<PasskeyUnlockInput>,
}

impl Drop for WalletPasskeyDeleteBody {
    fn drop(&mut self) {
        if let Some(p) = self.passphrase.as_mut() {
            p.zeroize();
        }
    }
}

async fn api_wallet_passkey_delete(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    axum::extract::Path((id, slot_id)): axum::extract::Path<(String, String)>,
    Json(body): Json<WalletPasskeyDeleteBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    let wallet_id = id.clone();
    let slot = slot_id.clone();
    let w = sealed(&s, move |store| {
        let auth = select_wallet_auth(body.passphrase.as_deref(), body.passkey.as_ref())?;
        store.remove_passkey(&wallet_id, &slot, auth)
    })
    .await?;
    info!(
        "Web interface removed passkey {} from wallet {}",
        slot_id, id
    );
    let active = s.wallets.active();
    Ok(Json(json!({ "ok": true, "wallet": wallet_json(&w, active.as_deref()) })).into_response())
}

async fn api_node_passkeys_list(State(s): State<Arc<Shared>>, headers: HeaderMap) -> ApiResult {
    signed_in(&s, &headers, false)?;
    Ok(Json(json!({
        "passkeys": s.node_passkeys.list(),
        "wallet": wallet_status(&s),
    }))
    .into_response())
}

#[derive(Deserialize)]
struct NodePasskeyEnrollBody {
    passphrase: String,
    #[serde(default)]
    label: String,
    credential_id: String,
    prf_salt: String,
    #[serde(default)]
    rp_id: String,
    prf_output: String,
}

impl Drop for NodePasskeyEnrollBody {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        self.prf_output.zeroize();
    }
}

async fn api_node_passkeys_enroll(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<NodePasskeyEnrollBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    throttle(&s, peer.ip())?;
    let host_rp = host_rp_id(&headers)?;
    if !body.rp_id.is_empty() {
        let checked = webauthn::rp_id_from_host(&body.rp_id).map_err(bad)?;
        if checked != host_rp {
            return Err(bad("passkey rp_id does not match this host"));
        }
    }
    let Some(before) = wallet_status(&s) else {
        return Err(bad("the daemon has no wallet loaded"));
    };
    if before == "unencrypted" {
        return Err(bad("encrypt the wallet on the Security page first"));
    }
    if body.passphrase.is_empty() {
        return Err(bad("enter the wallet passphrase"));
    }

    // Verify the node wallet passphrase against `walletpassphrase` for 1 second
    // and immediately restore the previous lock / staking-only state.
    let probe = match before {
        "unlocked-for-staking" => {
            call(
                &s,
                "walletpassphrase",
                vec![json!(body.passphrase.as_str()), json!(1), json!(true)],
            )
            .await
        }
        "unlocked" => {
            call(
                &s,
                "walletpassphrase",
                vec![json!(body.passphrase.as_str()), json!(60), json!(false)],
            )
            .await
        }
        _ => {
            call(
                &s,
                "walletpassphrase",
                vec![json!(body.passphrase.as_str()), json!(1), json!(false)],
            )
            .await
        }
    };
    if let Err((_, msg)) = probe {
        s.limiter.failed(peer.ip());
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            format!("wrong wallet passphrase: {msg}"),
        ));
    }
    match before {
        "unlocked-for-staking" => {
            let _ = call(
                &s,
                "walletpassphrase",
                vec![json!(body.passphrase.as_str()), json!(0), json!(true)],
            )
            .await;
        }
        "locked" => {
            let _ = call(&s, "walletlock", vec![]).await;
        }
        _ => {}
    }

    let summary = s
        .node_passkeys
        .enroll(
            &body.passphrase,
            &body.label,
            &body.credential_id,
            &body.prf_salt,
            &host_rp,
            &body.prf_output,
        )
        .map_err(bad)?;
    s.limiter.succeeded(peer.ip());
    info!("Web interface enrolled node wallet passkey {}", summary.id);
    Ok(Json(json!({ "ok": true, "passkey": summary })).into_response())
}

#[derive(Deserialize)]
struct NodePasskeyUnlockBody {
    slot_id: String,
    prf_output: String,
    #[serde(default)]
    staking_only: bool,
    #[serde(default)]
    timeout: Option<i64>,
}

impl Drop for NodePasskeyUnlockBody {
    fn drop(&mut self) {
        self.prf_output.zeroize();
    }
}

async fn api_node_passkeys_unlock(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<NodePasskeyUnlockBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    throttle(&s, peer.ip())?;
    let timeout = if body.staking_only {
        body.timeout.unwrap_or(0)
    } else {
        body.timeout.unwrap_or(60)
    };
    gate::check(
        "walletpassphrase",
        &[json!(""), json!(timeout), json!(body.staking_only)],
        wallet_status(&s),
    )
    .map_err(|e| ApiError(StatusCode::FORBIDDEN, e))?;

    let passphrase = match s.node_passkeys.unwrap(&body.slot_id, &body.prf_output) {
        Ok(p) => p,
        Err(msg) => {
            s.limiter.failed(peer.ip());
            return Err(ApiError(StatusCode::UNAUTHORIZED, msg));
        }
    };
    let transport = divi_rpc::diag_rpc::Transport::WebUi;
    let watch = divi_rpc::diag_rpc::begin("walletpassphrase", transport);
    let result = call(
        &s,
        "walletpassphrase",
        vec![
            json!(passphrase.as_str()),
            json!(timeout),
            json!(body.staking_only),
        ],
    )
    .await;
    drop(passphrase);
    watch.finish(
        "walletpassphrase",
        transport,
        Some(peer.ip()),
        true,
        result.as_ref().err().map(|(c, m)| (*c, m.as_str())),
    );
    match result {
        Ok(_) => {
            s.limiter.succeeded(peer.ip());
            Ok(Json(json!({ "ok": true, "wallet": wallet_status(&s) })).into_response())
        }
        Err((code, msg)) => {
            s.limiter.failed(peer.ip());
            Err(bad(format!("{msg} ({code})")))
        }
    }
}

async fn api_node_passkeys_delete(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    axum::extract::Path(slot_id): axum::extract::Path<String>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    if !s.node_passkeys.remove(&slot_id).map_err(bad)? {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "no such node wallet passkey".into(),
        ));
    }
    info!("Web interface removed node wallet passkey {}", slot_id);
    Ok(Json(json!({ "ok": true })).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(bind: &str, hosts: &[&str]) -> WebUiConfig {
        WebUiConfig {
            bind: bind.parse().unwrap(),
            allow_remote: false,
            allow_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            data_dir: PathBuf::new(),
            conf_path: PathBuf::new(),
            network: "regtest".into(),
            chain_mode: "divi".into(),
            cli: Default::default(),
            open_browser: false,
        }
    }

    #[test]
    fn ports_by_network() {
        assert_eq!(default_port(false, false, false), 51480);
        assert_eq!(default_port(false, true, false), 51481);
        assert_eq!(default_port(false, false, true), 51482);
        assert_eq!(default_port(true, false, true), 52482);
    }

    #[test]
    fn display_host_maps_loopback_and_unspecified_to_localhost() {
        assert_eq!(
            display_host(&"127.0.0.1:51482".parse().unwrap()),
            "localhost:51482"
        );
        assert_eq!(
            display_host(&"[::1]:51482".parse().unwrap()),
            "localhost:51482"
        );
        assert_eq!(
            display_host(&"0.0.0.0:51482".parse().unwrap()),
            "localhost:51482"
        );
        assert_eq!(
            display_host(&"192.0.2.10:51482".parse().unwrap()),
            "192.0.2.10:51482"
        );
    }

    #[test]
    fn hosts_are_the_loopback_and_those_allowed() {
        let hosts = allowed_hosts(&config("127.0.0.1:51482", &["Node.Example"]));
        assert!(hosts.contains(&"localhost:51482".to_string()));
        assert!(hosts.contains(&"127.0.0.1:51482".to_string()));
        assert!(hosts.contains(&"[::1]:51482".to_string()));
        assert!(hosts.contains(&"node.example".to_string()));
        assert!(hosts.contains(&"node.example:51482".to_string()));
        assert!(!hosts.contains(&"localhost:80".to_string()));
        assert!(!hosts.iter().any(|h| h.starts_with("evil")));
    }

    #[test]
    fn a_remote_bind_needs_leave() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config("0.0.0.0:0", &[]);
        c.data_dir = dir.path().to_path_buf();
        assert!(prepare(c.clone()).is_err());
        c.allow_remote = true;
        assert!(prepare(c).is_ok());
    }

    #[test]
    fn secrets_show_as_set_only() {
        let mut v = conffile::Values::new();
        v.insert("rpcpassword".into(), vec!["hunter2".into()]);
        v.insert("port".into(), vec!["1".into()]);
        v.insert("masternodeprivkey".into(), vec!["k".into()]);
        v.insert("unknowncustomkey".into(), vec!["u".into()]);
        let shown = visible(&v).to_string();
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("\"k\""));
        assert!(!shown.contains("\"u\""));
        assert!(shown.contains("rpcpassword"));
    }

    #[test]
    fn the_nft_proxy_is_testnet_only_and_stays_in_the_api() {
        let base = NFT_API_TESTNET;
        assert_eq!(
            nft_upstream("test", "status", None),
            Some(format!("{base}status"))
        );
        assert_eq!(
            nft_upstream("test", "address/yAbc/utxos", Some("x=1")),
            Some(format!("{base}address/yAbc/utxos?x=1"))
        );
        assert_eq!(nft_upstream("main", "status", None), None);
        assert_eq!(nft_upstream("regtest", "status", None), None);
        for bad in [
            "", "/status", "../x", "a/../b", "a//b", "a/./b", "a b", "a%2f..", "a\\b",
        ] {
            assert_eq!(nft_upstream("test", bad, None), None, "{bad:?}");
        }
        assert_eq!(nft_upstream("test", "status", Some("a#b")), None);
        assert!(raw_upload(&Method::POST, "/api/nft/ipfs/file"));
        assert!(!raw_upload(&Method::POST, "/api/nft/ipfs/json"));
        assert!(!raw_upload(&Method::PUT, "/api/nft/ipfs/file"));
        assert!(!raw_upload(&Method::POST, "/api/rpc"));
    }

    #[test]
    fn divi_amounts_parse_exactly() {
        assert_eq!(parse_divi("1"), Some(100_000_000));
        assert_eq!(parse_divi(" 0.5 "), Some(50_000_000));
        assert_eq!(parse_divi(".00000001"), Some(1));
        assert_eq!(parse_divi("12.3456789"), Some(1_234_567_890));
        for bad in [
            "",
            ".",
            "0",
            "0.0",
            "-1",
            "1e3",
            "1.000000001",
            "1,5",
            "99999999999999999999",
        ] {
            assert_eq!(parse_divi(bad), None, "{bad:?}");
        }
    }
}
