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

//! Hashlock route auth (F5): `GET /swaps/:id` and `POST /swaps/:id/lock` need the swap's
//! `X-Swap-Token`, `GET /swaps` (the listing) needs the operator credential, and every
//! refusal is the same 404 an unknown id gets. No network: in-process daemon, mock chains.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use divi_swap::api::{AcceptRequest, SwapView};
use divi_swap::{Store, SwapState};
use divi_swap_cli::{flow, MakerClient, Sessions};
use divi_swapd::{router_with_auth, AppState, HashlockAuth, ScanStatus};
use serde_json::{json, Value};

const SUPPORT: &str = "x-swap-token-support";
const SWAP_TOKEN: &str = "x-swap-token";
const OPERATOR: &str = "x-operator-token";

struct Served {
    base: String,
    handle: tokio::task::JoinHandle<()>,
}

/// A daemon over a fresh world with the given operator credential and tokenless policy.
async fn serve_with(w: &World, operator: Option<&str>, tokenless: bool) -> Served {
    let state = AppState {
        maker: w.maker(Store::in_memory().unwrap()),
        divi: Arc::new(w.maker_divi.clone()),
        btc: Arc::new(w.maker_btc.clone()),
        scan: ScanStatus::done(),
    };
    let auth = HashlockAuth::new(Store::in_memory().unwrap())
        .with_operator_token(operator.map(str::to_string))
        .allow_tokenless(tokenless);
    let app = router_with_auth(state, None, "/swap", false, auth);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/swap", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Served { base, handle }
}

/// Fresh quote, then `POST /swaps`; `support` adds `X-Swap-Token-Support: 1`.
async fn take(w: &World, base: &str, support: bool) -> (u16, Value) {
    let q: Value = reqwest::get(format!(
        "{base}/offers/{OFFER_ID}/quote?btc_sats={BTC_SATS}"
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    take_quote(w, base, &q["id"], support).await
}

async fn take_quote(w: &World, base: &str, quote_id: &Value, support: bool) -> (u16, Value) {
    let body = json!({
        "quote_id": quote_id,
        "hash": hex::encode(rand::random::<[u8; 32]>()),
        "taker_btc_pubkey": hex::encode(w.taker_btc_pub()),
        "taker_divi_pubkey": hex::encode(w.taker_divi_pub()),
    });
    let mut req = reqwest::Client::new()
        .post(format!("{base}/swaps"))
        .json(&body);
    if support {
        req = req.header(SUPPORT, "1");
    }
    let r = req.send().await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

/// A token-bearing swap: returns (id, token).
async fn open_swap(w: &World, base: &str) -> (String, String) {
    let (code, v) = take(w, base, true).await;
    assert_eq!(code, 201, "accept: {v}");
    (
        v["id"].as_str().unwrap().to_string(),
        v["swap_token"].as_str().unwrap().to_string(),
    )
}

async fn call(method: &str, url: &str, header: Option<(&str, &str)>) -> (u16, String) {
    let c = reqwest::Client::new();
    let mut req = match method {
        "GET" => c.get(url),
        _ => c.post(url).json(&json!({})),
    };
    if let Some((k, v)) = header {
        req = req.header(k, v);
    }
    let r = req.send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test]
async fn accept_without_token_support_is_426_and_spends_no_quote() {
    let w = World::new();
    let s = serve_with(&w, Some("op"), false).await;
    let q: Value = reqwest::get(format!(
        "{}/offers/{OFFER_ID}/quote?btc_sats={BTC_SATS}",
        s.base
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let (code, body) = take_quote(&w, &s.base, &q["id"], false).await;
    assert_eq!(code, 426, "old taker is told to upgrade: {body}");
    assert!(body["error"].as_str().unwrap().contains("upgrade"));
    // The quote was not consumed: the same quote id accepts with the header.
    let (code, v) = take_quote(&w, &s.base, &q["id"], true).await;
    assert_eq!(code, 201, "{v}");
    s.handle.abort();
}

#[tokio::test]
async fn accept_reply_keeps_the_view_fields_and_adds_a_token() {
    let w = World::new();
    let s = serve_with(&w, Some("op"), false).await;
    let (code, v) = take(&w, &s.base, true).await;
    assert_eq!(code, 201);
    // An old taker decodes the reply as a bare SwapView: the flattened fields are all there.
    let view: SwapView = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(view.state, SwapState::Accepted);
    let token = v["swap_token"].as_str().unwrap();
    assert_eq!(token.len(), 64);
    assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
    s.handle.abort();
}

#[tokio::test]
async fn get_swap_needs_its_own_token_and_refusals_match_unknown_id() {
    let w = World::new();
    let s = serve_with(&w, Some("op"), false).await;
    let (id, token) = open_swap(&w, &s.base).await;
    let (_, other_token) = open_swap(&w, &s.base).await;
    let url = format!("{}/swaps/{id}", s.base);

    let unknown = call("GET", &format!("{}/swaps/{}", s.base, "no-such-id"), None).await;
    assert_eq!(unknown.0, 404);
    for (what, h) in [
        ("no token", None),
        ("wrong token", Some((SWAP_TOKEN, "00".repeat(32)))),
        ("empty token", Some((SWAP_TOKEN, String::new()))),
        (
            "another swap's token",
            Some((SWAP_TOKEN, other_token.clone())),
        ),
        ("the operator token", Some((SWAP_TOKEN, "op".to_string()))),
    ] {
        let (code, body) = call("GET", &url, h.as_ref().map(|(k, v)| (*k, v.as_str()))).await;
        assert_eq!(code, 404, "{what}");
        assert_eq!(
            body,
            unknown.1.replace("no-such-id", &id),
            "{what}: same body as an unknown id"
        );
        assert!(!body.contains(&token) && !body.contains(&other_token));
    }
    let (code, body) = call("GET", &url, Some((SWAP_TOKEN, &token))).await;
    assert_eq!(code, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["state"], "Accepted");
    assert_eq!(v["id"], id);
    assert!(!body.contains(&token), "the view never carries the token");
    s.handle.abort();
}

#[tokio::test]
async fn lock_needs_its_own_token_and_refusals_match_unknown_id() {
    let w = World::new();
    let s = serve_with(&w, Some("op"), false).await;
    let (id, token) = open_swap(&w, &s.base).await;
    let (_, other_token) = open_swap(&w, &s.base).await;
    let url = format!("{}/swaps/{id}/lock", s.base);

    let unknown = call("POST", &format!("{}/swaps/no-such-id/lock", s.base), None).await;
    assert_eq!(unknown.0, 404);
    for (what, h) in [
        ("no token", None),
        ("wrong token", Some((SWAP_TOKEN, "ff".repeat(32)))),
        (
            "another swap's token",
            Some((SWAP_TOKEN, other_token.clone())),
        ),
    ] {
        let (code, body) = call("POST", &url, h.as_ref().map(|(k, v)| (*k, v.as_str()))).await;
        assert_eq!(code, 404, "{what}");
        assert_eq!(body, unknown.1.replace("no-such-id", &id), "{what}");
        assert!(!body.contains(&token));
    }
    // The right token reaches the handler (an empty body is then a 4xx from the extractor,
    // not the swap 404).
    let (code, body) = call("POST", &url, Some((SWAP_TOKEN, &token))).await;
    assert_ne!(
        body,
        unknown.1.replace("no-such-id", &id),
        "gate let it through"
    );
    assert!(
        code == 400 || code == 422,
        "handler rejects the body: {code}"
    );
    s.handle.abort();
}

#[tokio::test]
async fn listing_needs_the_operator_token() {
    let w = World::new();
    let s = serve_with(&w, Some("op-secret"), false).await;
    let (_, swap_token) = open_swap(&w, &s.base).await;
    let url = format!("{}/swaps", s.base);

    for (what, h) in [
        ("no credential", None),
        ("wrong operator token", Some((OPERATOR, "nope".to_string()))),
        ("empty operator token", Some((OPERATOR, String::new()))),
        ("a swap token", Some((OPERATOR, swap_token.clone()))),
        (
            "swap token in the swap header",
            Some((SWAP_TOKEN, swap_token.clone())),
        ),
    ] {
        let (code, body) = call("GET", &url, h.as_ref().map(|(k, v)| (*k, v.as_str()))).await;
        assert_eq!(code, 404, "{what}");
        assert!(!body.contains("Accepted"), "{what}: nothing listed");
    }
    let (code, body) = call("GET", &url, Some((OPERATOR, "op-secret"))).await;
    assert_eq!(code, 200);
    let list: Vec<SwapView> = serde_json::from_str(&body).unwrap();
    assert_eq!(list.len(), 1);
    assert!(
        !body.contains(&swap_token),
        "the listing never carries swap tokens"
    );
    s.handle.abort();
}

#[tokio::test]
async fn listing_is_closed_when_no_operator_token_is_configured() {
    let w = World::new();
    let s = serve_with(&w, None, false).await;
    let _ = open_swap(&w, &s.base).await;
    let url = format!("{}/swaps", s.base);
    for h in [None, Some((OPERATOR, "")), Some((OPERATOR, "anything"))] {
        let (code, _) = call("GET", &url, h).await;
        assert_eq!(
            code, 404,
            "unset credential matches nothing, not everything"
        );
    }
    s.handle.abort();
}

/// A swap with no token record (opened by a pre-token maker, or tokenless by config) keeps
/// working by id alone, exactly as before; only the listing is closed.
#[tokio::test]
async fn legacy_swap_stays_readable_and_lockable_by_id_but_never_listed() {
    let w = World::new();
    let s = serve_with(&w, Some("op"), true).await;
    let (code, v) = take(&w, &s.base, false).await;
    assert_eq!(code, 201, "tokenless allowed by config: {v}");
    assert!(v.get("swap_token").is_none(), "no token is issued: {v}");
    let id = v["id"].as_str().unwrap();

    let (code, body) = call("GET", &format!("{}/swaps/{id}", s.base), None).await;
    assert_eq!(code, 200, "legacy read by id");
    assert!(body.contains("Accepted"));
    let (code, _) = call("POST", &format!("{}/swaps/{id}/lock", s.base), None).await;
    assert_ne!(code, 404, "legacy lock reaches the handler");
    // An unknown id is still the plain 404, and the listing is still closed.
    assert_eq!(
        call("GET", &format!("{}/swaps/zzz", s.base), None).await.0,
        404
    );
    assert_eq!(call("GET", &format!("{}/swaps", s.base), None).await.0, 404);
    s.handle.abort();
}

/// With tokenless off (the default) a tokenless taker cannot create a legacy swap at all.
#[tokio::test]
async fn tokenless_swaps_are_off_by_default() {
    let w = World::new();
    let s = serve_with(&w, Some("op"), false).await;
    let (code, _) = take(&w, &s.base, false).await;
    assert_eq!(code, 426);
    let (_, list) = call("GET", &format!("{}/swaps", s.base), Some((OPERATOR, "op"))).await;
    assert_eq!(serde_json::from_str::<Vec<Value>>(&list).unwrap().len(), 0);
    s.handle.abort();
}

/// The taker CLI end to end against the real router: begin saves the token in the session,
/// `lock` and `swap` send it, and a client that lost it is refused with the plain 404.
#[tokio::test]
async fn taker_cli_stores_and_sends_the_swap_token() {
    let w = World::new();
    let s = serve_with(&w, Some("op"), false).await;
    let dir = tempfile::tempdir().unwrap();
    let taker = w.taker(&dir.path().join("t.db"));
    let sessions = Sessions::beside(&dir.path().join("t.db"));
    let client = MakerClient::new(&s.base);

    let local = flow::begin(&taker, &client, &sessions, OFFER_ID, BTC_SATS)
        .await
        .unwrap();
    let sess = sessions.get(&local).unwrap();
    assert_eq!(
        sess.swap_token.len(),
        64,
        "token saved in the session sidecar"
    );

    // A fresh process: client rebuilt from the saved session.
    let again = MakerClient::new(&s.base).with_swap_token(&sess.maker_swap_id, &sess.swap_token);
    assert_eq!(
        again.swap(&sess.maker_swap_id).await.unwrap().state,
        SwapState::Accepted
    );
    flow::lock(&taker, &again, &sessions, &local).await.unwrap();

    // Without the token the same call is the unknown-id error.
    let bare = MakerClient::new(&s.base);
    let err = bare
        .swap(&sess.maker_swap_id)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("404") || err.contains("no swap"), "{err}");
    assert!(!err.contains(&sess.swap_token));
    s.handle.abort();
}

type Seen = Arc<Mutex<Vec<(String, Option<String>, bool)>>>;

/// A scripted maker that records, per request, the path, `X-Swap-Token` and whether
/// `X-Swap-Token-Support` was present. `issue` makes its accept reply carry a token.
async fn mock_maker(w: &World, issue: Option<&'static str>) -> (String, Seen) {
    use axum::extract::State;
    use axum::http::{HeaderMap, Uri};
    use axum::routing::{get, post};

    let real = serve_with(w, Some("op"), true).await;
    // Reuse a real accept reply body (valid SwapView) from a tokenless swap.
    let (_, view) = take(w, &real.base, false).await;
    let id = view["id"].as_str().unwrap().to_string();
    let seen: Seen = Arc::default();

    async fn record(
        State((seen, view, issue)): State<(Seen, Value, Option<&'static str>)>,
        uri: Uri,
        h: HeaderMap,
    ) -> axum::Json<Value> {
        let tok = h.get(SWAP_TOKEN).map(|v| v.to_str().unwrap().to_string());
        seen.lock()
            .unwrap()
            .push((uri.path().to_string(), tok, h.contains_key(SUPPORT)));
        let mut v = view;
        if let (Some(t), true) = (issue, uri.path().ends_with("/swaps")) {
            v["swap_token"] = t.into();
        }
        axum::Json(v)
    }
    let app = axum::Router::new()
        .route("/swaps", post(record))
        .route("/swaps/:id", get(record))
        .route("/swaps/:id/lock", post(record))
        .with_state((seen.clone(), view, issue));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // keep the real daemon alive for the test's duration
    std::mem::forget(real);
    (format!("{base}|{id}"), seen)
}

fn accept_req(w: &World) -> AcceptRequest {
    serde_json::from_value(json!({
        "quote_id": "q",
        "hash": hex::encode([7u8; 32]),
        "taker_btc_pubkey": hex::encode(w.taker_btc_pub()),
        "taker_divi_pubkey": hex::encode(w.taker_divi_pub()),
    }))
    .unwrap()
}

#[tokio::test]
async fn client_sends_the_token_a_maker_issued_and_only_that() {
    let w = World::new();
    let (spec, seen) = mock_maker(&w, Some("aa11")).await;
    let (base, id) = spec.split_once('|').unwrap();
    let client = MakerClient::new(base);
    let view = client.accept(&accept_req(&w)).await.unwrap();
    assert_eq!(view.id, id);
    assert_eq!(client.swap_token(&view.id).as_deref(), Some("aa11"));
    client.swap(&view.id).await.unwrap();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen[0],
        ("/swaps".to_string(), None, true),
        "accept: support header, no token"
    );
    assert_eq!(seen[1].1.as_deref(), Some("aa11"), "GET carries the token");
    assert!(seen
        .iter()
        .skip(1)
        .all(|(_, t, _)| t.as_deref() == Some("aa11")));
}

/// A pre-token maker returns a bare view: the new taker saves no token and sends no header.
#[tokio::test]
async fn client_against_a_pre_token_maker_sends_no_token_header() {
    let w = World::new();
    let (spec, seen) = mock_maker(&w, None).await;
    let (base, _) = spec.split_once('|').unwrap();
    let client = MakerClient::new(base);
    let view = client.accept(&accept_req(&w)).await.unwrap();
    assert_eq!(client.swap_token(&view.id), None);
    client.swap(&view.id).await.unwrap();
    let seen = seen.lock().unwrap().clone();
    assert!(seen.iter().all(|(_, t, _)| t.is_none()), "{seen:?}");
}

/// A malformed accept reply holding a token must not echo the body (token) in the error.
#[tokio::test]
async fn accept_decode_error_does_not_echo_the_token() {
    use axum::routing::post;
    let secret = "deadbeef".repeat(8);
    let body = json!({"swap_token": secret, "garbage": true});
    let app = axum::Router::new().route(
        "/swaps",
        post(move || {
            let b = body.clone();
            async move { (axum::http::StatusCode::CREATED, axum::Json(b)) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let w = World::new();
    let err = MakerClient::new(&base)
        .accept(&accept_req(&w))
        .await
        .unwrap_err();
    let shown = format!("{err:#} {err:?}");
    assert!(!shown.contains(&secret), "token leaked into the error");
}

#[tokio::test]
async fn accept_reply_debug_redacts_the_token() {
    let w = World::new();
    let s = serve_with(&w, Some("op"), false).await;
    let (code, v) = take(&w, &s.base, true).await;
    assert_eq!(code, 201);
    let token = v["swap_token"].as_str().unwrap().to_string();
    let reply: divi_swap::api::AcceptReply = serde_json::from_value(v).unwrap();
    assert!(!format!("{reply:?}").contains(&token));
    assert!(!format!("{reply:#?}").contains(&token));
    s.handle.abort();
}
