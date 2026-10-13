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

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::scan::{ScanInfo, ScanState, ScanStatus};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use divi_swap::api::{AcceptRequest, LockNotice, Offer, Quote, SwapView};
use divi_swap::{Chain, ChainBackend, Maker, SwapError};
use divi_swap_xmr::api::{SetupReply, SetupRequest, SigsRequest, XmrLockNotice, XmrSwapView};
use divi_swap_xmr::XmrMaker;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;

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
/// (`divi_swap_xmr`): `POST /xmr/swaps` (setup), `POST /xmr/swaps/:id/sigs`,
/// `POST /xmr/swaps/:id/xmr-lock`, `GET /xmr/swaps[/:id]`. Its offers and quotes go through
/// the hashlock maker's `/offers` routes (the engine is registered with
/// `Maker::with_engine`).
pub fn router_with_xmr(state: AppState, xmr: Option<Arc<XmrMaker>>, prefix: &str) -> Router {
    let mut api = Router::new()
        .route("/healthz", get(healthz))
        .route("/offers", get(offers))
        .route("/offers/:id/quote", get(quote))
        .route("/swaps", post(accept).get(list_swaps))
        .route("/swaps/:id", get(get_swap))
        .route("/swaps/:id/lock", post(lock))
        .with_state(state);
    if let Some(x) = xmr {
        api = api.merge(
            Router::new()
                .route("/xmr/swaps", post(xmr_setup).get(xmr_list))
                .route("/xmr/swaps/:id", get(xmr_get))
                .route("/xmr/swaps/:id/sigs", post(xmr_sigs))
                .route("/xmr/swaps/:id/xmr-lock", post(xmr_lock))
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
) -> Result<(StatusCode, Json<SetupReply>), ApiError> {
    Ok((StatusCode::CREATED, Json(x.setup(req).await?)))
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

async fn xmr_list(State(x): State<Arc<XmrMaker>>) -> Result<Json<Vec<XmrSwapView>>, ApiError> {
    Ok(Json(x.list()?))
}
