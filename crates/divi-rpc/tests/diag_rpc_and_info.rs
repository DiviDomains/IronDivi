// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Tests for A15 JSON-RPC HTTP recording, panic-hook in-flight visibility,
//! `diag_rpc::calls()`, and A10 `getdiaginfo` (`Caller` gating V2/W5, `diag_key`
//! secrecy & pseudonym HMACs, `known_values` pages, and N1 SipHash-2-4 tags).

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request as HttpRequest, StatusCode};
use divi_primitives::diag_rpc::{self, InFlight, Transport};
use divi_rpc::{
    create_router_with_auth, Caller, CallerTransport, Params, Request, RequestId, RpcConfig,
    RpcServer, Subnet,
};
use divi_storage::{Chain, ChainDatabase, ChainParams};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

fn test_server_with_wallet() -> (Arc<RpcServer>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(
                divi_storage::chain::NetworkType::Regtest,
                divi_primitives::ChainMode::Divi,
            ),
        )
        .unwrap(),
    );
    let wallet = Arc::new(divi_wallet::WalletDb::with_hd_wallet(
        divi_wallet::Network::Regtest,
        divi_wallet::HdWallet::new(divi_primitives::ChainMode::Divi).unwrap(),
    ));
    let addr = wallet.new_receiving_address().unwrap();
    wallet.set_label(&addr, "canary-diag-label-3141").unwrap();
    (Arc::new(RpcServer::with_wallet(chain, wallet)), dir)
}

fn rpc_config_allowing_lan() -> RpcConfig {
    let mut cfg = RpcConfig {
        username: Some("test".into()),
        password: Some("test".into()),
        ..RpcConfig::default()
    };
    cfg.allowed.push(Subnet::parse("203.0.113.0/24").unwrap());
    cfg
}

async fn post_rpc(
    app: &axum::Router,
    peer: SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, Value) {
    let mut builder = HttpRequest::builder()
        .method("POST")
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json")
        // base64("test:test")
        .header("authorization", "Basic dGVzdDp0ZXN0");
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let mut req = builder.body(Body::from(body.to_string())).unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    let mut svc = app.clone();
    let res = tower::Service::call(&mut svc, req)
        .await
        .unwrap_or_else(|e| match e {});
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 4 << 20)
        .await
        .unwrap();
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

#[tokio::test]
async fn jsonrpc_http_records_calls_and_exposes_inflight_to_panic_hook() {
    #[derive(Clone, Debug)]
    struct Recorded {
        method: String,
        transport: Transport,
        caller: Option<std::net::IpAddr>,
        authenticated: bool,
        error_code: Option<i64>,
    }
    static RECORDED: std::sync::OnceLock<Mutex<Vec<Recorded>>> = std::sync::OnceLock::new();
    let sink_vec = RECORDED.get_or_init(|| Mutex::new(Vec::new()));
    let _ = diag_rpc::install(Box::new(|d| {
        if let Some(v) = RECORDED.get() {
            v.lock().unwrap().push(Recorded {
                method: d.method.to_string(),
                transport: d.transport,
                caller: d.caller,
                authenticated: d.authenticated,
                error_code: d.error.map(|e| e.0),
            });
        }
    }));

    let (server, _dir) = test_server_with_wallet();
    server.set_log_levels_callback(Arc::new(|spec| {
        if spec == "trigger_panic" {
            panic!("deliberate handler panic for A15 test");
        }
        Ok(spec.to_string())
    }));
    let app = create_router_with_auth(Arc::clone(&server), &rpc_config_allowing_lan());
    let lo: SocketAddr = "127.0.0.1:41234".parse().unwrap();

    let before_calls = diag_rpc::calls();
    sink_vec.lock().unwrap().clear();

    // 1. Single call on `/`
    let (st, v) = post_rpc(
        &app,
        lo,
        "/",
        &[],
        r#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}"#,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["result"], json!(0));

    // 2. Wallet route `/wallet/main` + unknown method (-32601 -> recorded as "unknown") in a batch
    let (st, v) = post_rpc(
        &app,
        lo,
        "/wallet/main",
        &[],
        r#"[{"jsonrpc":"1.0","id":2,"method":"getdiaginfo","params":[]},{"jsonrpc":"1.0","id":3,"method":"not_a_real_method_xyz","params":[]}]"#,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(v.as_array().unwrap()[0]["error"].is_null());
    assert_eq!(v.as_array().unwrap()[1]["error"]["code"], json!(-32601));

    assert!(diag_rpc::calls() >= before_calls + 3);
    {
        let recs = sink_vec.lock().unwrap();
        assert!(
            recs.iter().any(|r| r.method == "getblockcount"
                && r.transport == Transport::JsonRpc
                && r.caller == Some(lo.ip())
                && r.authenticated
                && r.error_code.is_none()),
            "{recs:?}"
        );
        assert!(
            recs.iter()
                .any(|r| r.method == "getdiaginfo" && r.error_code.is_none()),
            "{recs:?}"
        );
        assert!(
            recs.iter()
                .any(|r| r.method == "unknown" && r.error_code == Some(-32601)),
            "{recs:?}"
        );
    }

    // 3. Panicking handler: the panic hook MUST observe `setlogconfig` in `diag_rpc::in_flight()`
    // before unwinding, and `Drop` MUST clear the slot once unwinding finishes.
    let captured_inflight: Arc<Mutex<Vec<InFlight>>> = Arc::new(Mutex::new(Vec::new()));
    let cap_for_hook = Arc::clone(&captured_inflight);
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info
            .payload()
            .downcast_ref::<&str>()
            .is_some_and(|s| s.contains("deliberate handler panic"))
        {
            *cap_for_hook.lock().unwrap() = diag_rpc::in_flight();
        }
    }));

    let calls_before_panic = diag_rpc::calls();
    let app_clone = app.clone();
    let join = tokio::spawn(async move {
        post_rpc(
            &app_clone,
            lo,
            "/",
            &[],
            r#"{"jsonrpc":"1.0","id":9,"method":"setlogconfig","params":["trigger_panic"]}"#,
        )
        .await
    })
    .await;
    std::panic::set_hook(prev_hook);

    assert!(join.is_err(), "panicking RPC handler must propagate panic");
    let seen = captured_inflight.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|c| c.method == "setlogconfig" && c.transport == Transport::JsonRpc),
        "panic hook did not see setlogconfig in flight: {seen:?}"
    );
    assert!(
        !diag_rpc::in_flight()
            .iter()
            .any(|c| c.method == "setlogconfig"),
        "in-flight slot must be cleared on unwind"
    );
    assert!(diag_rpc::calls() > calls_before_panic);
}

#[tokio::test]
async fn getdiaginfo_enforces_caller_gating_diag_key_secrecy_and_n1_tags() {
    std::env::set_var(
        "CANARY_RPC_SECRET_TOKEN",
        "super-secret-canary-value-9911-do-not-leak",
    );
    std::env::set_var("CANARY_PLAIN_HOST_TAG", "plain-env-canary-value-7722");

    // Print a wallet label pseudonym so the process pseudonym table holds it
    let _ = divi_primitives::redact::WalletLabel("canary-diag-label-3141").to_string();

    let (server, _dir) = test_server_with_wallet();
    let app = create_router_with_auth(Arc::clone(&server), &rpc_config_allowing_lan());

    let lo_v4: SocketAddr = "127.0.0.1:41235".parse().unwrap();
    let lo_v6: SocketAddr = "[::1]:41235".parse().unwrap();
    let remote: SocketAddr = "203.0.113.42:41235".parse().unwrap();

    let diag_key_bytes = [0x5au8; 32];
    let diag_key_hex = hex::encode(diag_key_bytes);

    // 1. Malformed diag_key is refused with "invalid diag_key" and NEVER echoes the key
    let bad_key = "CANARY-BAD-DIAG-KEY-5544";
    let (_, bad_reply) = post_rpc(
        &app,
        lo_v4,
        "/",
        &[],
        &json!({
            "jsonrpc": "1.0",
            "id": 1,
            "method": "getdiaginfo",
            "params": [{"diag_key": bad_key}]
        })
        .to_string(),
    )
    .await;
    let err_msg = bad_reply["error"]["message"].as_str().unwrap_or("");
    assert_eq!(err_msg, "invalid diag_key", "{bad_reply}");
    assert!(!bad_reply.to_string().contains(bad_key));

    // 2. V2 & W5: known_values refused to remote caller, proxy headers, WebUi, Electrum, Internal, and missing Caller extension
    let kv_body = json!({
        "jsonrpc": "1.0",
        "id": 2,
        "method": "getdiaginfo",
        "params": [{"diag_key": diag_key_hex, "known_values": 0}]
    })
    .to_string();

    // Remote caller on `/` and `/wallet/main`
    for path in ["/", "/wallet/main"] {
        let (_, r) = post_rpc(&app, remote, path, &[], &kv_body).await;
        assert_eq!(
            r["error"]["message"],
            json!("known_values is local only"),
            "remote on {path}: {r}"
        );
    }

    // Proxy headers on loopback (`/`, `/wallet/main`)
    for (hdr, val) in [
        ("x-forwarded-for", "203.0.113.42"),
        ("forwarded", "for=203.0.113.42"),
        ("x-real-ip", "203.0.113.42"),
    ] {
        for path in ["/", "/wallet/main"] {
            let (_, r) = post_rpc(&app, lo_v4, path, &[(hdr, val)], &kv_body).await;
            assert_eq!(
                r["error"]["message"],
                json!("known_values is local only"),
                "{hdr} on {path}: {r}"
            );
        }
    }

    // WebUi, Electrum, Internal, Unknown callers via handle_request_from / handle_request
    for caller in [
        Caller::webui(),
        Caller::electrum(),
        Caller::internal(),
        Caller::unknown(),
    ] {
        assert_ne!(caller.transport, CallerTransport::JsonRpc, "{caller:?}");
        let resp = server.handle_request_from(
            Request {
                jsonrpc: "2.0".into(),
                id: RequestId::Number(1),
                method: "getdiaginfo".into(),
                params: Params::Array(vec![json!({"known_values": 0})]),
            },
            caller,
        );
        assert_eq!(
            resp.error.as_ref().map(|e| e.message.as_str()),
            Some("known_values is local only"),
            "{caller:?}: {resp:?}"
        );
    }

    // W5: A test router mounting `/wallet/:wallet_name` without the access middleware (no `Caller` extension)
    let mut bare_svc = divi_rpc::server::test_bare_wallet_router(Arc::clone(&server));
    let req = HttpRequest::builder()
        .method("POST")
        .uri("/wallet/bare")
        .header("content-type", "application/json")
        .body(Body::from(kv_body.clone()))
        .unwrap();
    let res = tower::Service::call(&mut bare_svc, req)
        .await
        .unwrap_or_else(|e| match e {});
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let bare_reply: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        bare_reply["error"]["message"],
        json!("known_values is local only"),
        "{bare_reply}"
    );

    // 3. Allowed on loopback IPv4 & IPv6 (`/` and `/wallet/main`) with no proxy headers!
    for (peer, path) in [(lo_v4, "/"), (lo_v6, "/wallet/main")] {
        let (st, ok_reply) = post_rpc(&app, peer, path, &[], &kv_body).await;
        assert_eq!(st, StatusCode::OK, "{ok_reply}");
        assert!(ok_reply["error"].is_null(), "{ok_reply}");
        let res = &ok_reply["result"];
        assert!(!ok_reply.to_string().contains(&diag_key_hex));
        assert!(
            !ok_reply
                .to_string()
                .contains("super-secret-canary-value-9911-do-not-leak"),
            "secret env value leaked in known_values!"
        );

        // Verify pseudonym_map contains HMAC(diag_key, "canary-diag-label-3141")
        let pmap = res["pseudonym_map"].as_object().expect("pseudonym_map");
        let label_pseudo =
            divi_primitives::redact::WalletLabel("canary-diag-label-3141").to_string();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&diag_key_bytes).unwrap();
        mac.update(b"canary-diag-label-3141");
        let expected_hmac = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            pmap.get(&label_pseudo).and_then(Value::as_str),
            Some(expected_hmac.as_str()),
            "pseudonym_map mismatch: {pmap:?}"
        );

        // Collect all pages of known_values
        let mut all_entries = Vec::new();
        let mut page = 0u64;
        loop {
            let page_body = json!({
                "jsonrpc": "1.0",
                "id": 10 + page,
                "method": "getdiaginfo",
                "params": [{"diag_key": diag_key_hex, "known_values": page}]
            })
            .to_string();
            let (_, pr) = post_rpc(&app, peer, path, &[], &page_body).await;
            let kv = &pr["result"]["known_values"];
            all_entries.extend(kv["values"].as_array().unwrap().iter().cloned());
            if !kv["has_more"].as_bool().unwrap_or(false) {
                break;
            }
            page += 1;
        }

        // Wallet label & address present in known_values
        assert!(
            all_entries
                .iter()
                .any(|e| e["kind"] == "label" && e["value"] == "canary-diag-label-3141"),
            "missing wallet label in known_values"
        );
        // Non-secret env value present
        assert!(
            all_entries
                .iter()
                .any(|e| e["kind"] == "env" && e["value"] == "plain-env-canary-value-7722"),
            "missing plain env value in known_values"
        );
        // Secret-named env variable present ONLY as HMAC, length, and N1 SipHash-2-4 tag (never R_b bits!)
        let secret_val = b"super-secret-canary-value-9911-do-not-leak";
        let secret_entry = all_entries
            .iter()
            .find(|e| e["kind"] == "secret_env" && e["name"] == "CANARY_RPC_SECRET_TOKEN")
            .expect("missing secret_env entry for CANARY_RPC_SECRET_TOKEN");
        assert!(secret_entry.get("value").is_none(), "{secret_entry}");
        assert_eq!(secret_entry["len"].as_u64(), Some(secret_val.len() as u64));

        let mut smac = <Hmac<Sha256> as Mac>::new_from_slice(&diag_key_bytes).unwrap();
        smac.update(secret_val);
        assert_eq!(
            secret_entry["hmac"].as_str(),
            Some(hex::encode(smac.finalize().into_bytes()).as_str())
        );

        let (r_b, expected_sip_tag) =
            divi_rpc::server::compute_n1_secret_tag(&diag_key_bytes, secret_val);
        let got_tag = secret_entry["tag"].as_u64().expect("tag") as u16;
        assert_eq!(got_tag, expected_sip_tag);
        assert_ne!(
            got_tag,
            (r_b & 0xffff) as u16,
            "N1: tag must be SipHash-2-4 over R_b bytes, never R_b's own bits"
        );
    }
}
