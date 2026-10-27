// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! IronDivi's optional web interface, on with `-webui`. It listens on the
//! loopback unless told otherwise, signs in with its own password (set once
//! with a token from the data directory), and calls the daemon in-process:
//! the RPC password never reaches the browser. It keeps the wallet's keys
//! in: no key exports, spending unlocks of ten minutes at most, and nothing
//! but reads until the wallet is encrypted.

pub mod auth;
pub mod conffile;
pub mod gate;
pub mod schema;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use divi_rpc::{Params, RequestId, RpcServer};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{broadcast, Semaphore};
use tracing::{info, warn};

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
}

/// The interface with its port taken, before the daemon's RPC server exists
pub struct Prepared {
    listener: std::net::TcpListener,
    config: WebUiConfig,
    auth: AuthStore,
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
    })
}

fn display_host(addr: &SocketAddr) -> String {
    if addr.ip().is_unspecified() {
        format!("localhost:{}", addr.port())
    } else {
        addr.to_string()
    }
}

struct Shared {
    config: WebUiConfig,
    auth: AuthStore,
    sessions: Sessions,
    limiter: LoginLimiter,
    /// Password hashing takes 19 MiB and some tens of milliseconds; two at once
    hashing: Semaphore,
    /// Host header values accepted, lowercase
    hosts: Vec<String>,
    rpc: Arc<RpcServer>,
}

impl Prepared {
    /// Serve until the daemon shuts down
    pub fn spawn(
        self,
        rpc: Arc<RpcServer>,
        mut shutdown: broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let Prepared {
            listener,
            config,
            auth,
        } = self;
        let shared = Arc::new(Shared {
            hosts: allowed_hosts(&config),
            config,
            auth,
            sessions: Sessions::default(),
            limiter: LoginLimiter::default(),
            hashing: Semaphore::new(2),
            rpc,
        });
        tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => l,
                Err(e) => {
                    warn!("Web interface stopped: {}", e);
                    return;
                }
            };
            let app = router(shared);
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
        hosts.push(format!("{name}:{port}"));
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

fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(|| js(include_str!("../static/app.js"))))
        .route("/pay.js", get(|| js(include_str!("../static/pay.js"))))
        .route(
            "/qrcode.js",
            get(|| js(include_str!("../static/qrcode.js"))),
        )
        .route("/jsqr.js", get(|| js(include_str!("../static/jsqr.js"))))
        .route("/app.css", get(app_css))
        .route("/api/state", get(api_state))
        .route("/api/setup", post(api_setup))
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route("/api/password", post(api_password))
        .route("/api/rpc", post(api_rpc))
        .route("/api/settings", get(api_settings).post(api_save_settings))
        .layer(axum::middleware::from_fn_with_state(shared.clone(), guard))
        .layer(DefaultBodyLimit::max(1 << 20))
        .with_state(shared)
}

const CSP: &str = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
                   form-action 'self'; object-src 'none'";

/// Every request: a known Host (no DNS rebinding), a same-origin JSON POST,
/// and headers that keep the page out of frames and caches
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
    if req.method() == Method::POST {
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
        if !json {
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

/// The signed-in session's cookie; a POST must also carry its CSRF token
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

/// The wallet's `encryption_status`; None without a wallet
fn wallet_status(s: &Shared) -> Option<&'static str> {
    s.rpc.wallet().wallet_db().map(|w| w.encryption_status())
}

async fn api_state(State(s): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let csrf = cookie_of(&headers).and_then(|c| s.sessions.touch(&c));
    let mut state = json!({
        "setup_required": s.auth.setup_required(),
        "signed_in": csrf.is_some(),
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
    }
    Json(state).into_response()
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
    tokio::task::spawn_blocking(move || work(&shared.auth))
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
    token: String,
    password: String,
}

async fn api_setup(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<SetupBody>,
) -> ApiResult {
    if !s.auth.setup_required() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "the password is already set".into(),
        ));
    }
    throttle(&s, peer.ip())?;
    if !s.auth.check_setup_token(body.token.trim()) {
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
    let password = zeroize::Zeroizing::new(body.password);
    hashing(&s, move |a| a.set_password(&password))
        .await?
        .map_err(|e| bad(e.to_string()))?;
    s.limiter.succeeded(peer.ip());
    info!("Web interface password set");
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
    let password = zeroize::Zeroizing::new(body.password);
    if !hashing(&s, move |a| a.verify(&password)).await? {
        s.limiter.failed(peer.ip());
        warn!("Web interface: failed sign-in from {}", peer.ip());
        return Err(ApiError(StatusCode::UNAUTHORIZED, "wrong password".into()));
    }
    s.limiter.succeeded(peer.ip());
    Ok(started(&s))
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
    let current = zeroize::Zeroizing::new(body.current);
    let new = zeroize::Zeroizing::new(body.new);
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
    let response = tokio::task::spawn_blocking(move || rpc.handle_request(request))
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
    headers: HeaderMap,
    Json(body): Json<RpcBody>,
) -> ApiResult {
    signed_in(&s, &headers, true)?;
    let method = body.method.trim().to_string();
    gate::check(&method, &body.params, wallet_status(&s))
        .map_err(|e| ApiError(StatusCode::FORBIDDEN, e))?;
    Ok(match call(&s, &method, body.params).await {
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
    let (file, format) = tokio::task::spawn_blocking(move || {
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
    tokio::task::spawn_blocking(move || conffile::apply(&path, &to_write))
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
        s.config.conf_path.display()
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
    fn hosts_are_the_loopback_and_those_allowed() {
        let hosts = allowed_hosts(&config("127.0.0.1:51482", &["Node.Example"]));
        assert!(hosts.contains(&"localhost:51482".to_string()));
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
        let shown = visible(&v).to_string();
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("\"k\""));
        assert!(shown.contains("rpcpassword"));
    }
}
