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

//! Rate limits on the hashlock routes and the client address behind a proxy.

mod common;

use std::sync::Arc;

use common::*;
use divi_swap::Store;
use divi_swapd::{
    router_with_auth, router_with_proxy, AppState, HashlockAuth, ProxyTrust, ScanStatus,
    PUBLIC_READ_LIMIT_PER_WINDOW, READ_LIMIT_PER_WINDOW, WRITE_LIMIT_PER_WINDOW,
    XMR_TOKEN_MISS_LIMIT_PER_WINDOW,
};

fn state() -> AppState {
    let w = World::new();
    AppState {
        maker: w.maker(Store::in_memory().unwrap()),
        divi: Arc::new(w.maker_divi.clone()),
        btc: Arc::new(w.maker_btc.clone()),
        scan: ScanStatus::done(),
    }
}

/// `trust`: `trust_proxy_headers` with the default `trusted_proxies`, so this test's loopback
/// connections are a trusted proxy.
async fn serve_proxy(trust: bool) -> (String, tokio::task::JoinHandle<()>) {
    serve(router_with_proxy(state(), None, "/swap", trust)).await
}

/// `trust_proxy_headers` on with `trusted_proxies = proxies`.
async fn serve_trusting(proxies: &[&str]) -> (String, tokio::task::JoinHandle<()>) {
    let proxy = ProxyTrust::proxies(proxies.iter().map(|p| p.parse().unwrap()));
    let auth = HashlockAuth::new(Store::in_memory().unwrap());
    serve(router_with_auth(state(), None, "/swap", proxy, auth)).await
}

async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (format!("http://{addr}/swap"), h)
}

/// Status of one request; `xff` is sent as `X-Forwarded-For` when given.
async fn hit(c: &reqwest::Client, method: &str, url: &str, xff: Option<&str>) -> u16 {
    let mut r = match method {
        "GET" => c.get(url),
        _ => c
            .post(url)
            .header("content-type", "application/json")
            .body("{}"),
    };
    if let Some(x) = xff {
        r = r.header("x-forwarded-for", x);
    }
    r.send().await.unwrap().status().as_u16()
}

async fn first_429(
    c: &reqwest::Client,
    method: &str,
    url: &str,
    max: u32,
    xff: impl Fn(u32) -> Option<String>,
) -> Option<u32> {
    for i in 1..=max + 1 {
        if hit(c, method, url, xff(i).as_deref()).await == 429 {
            return Some(i);
        }
    }
    None
}

#[tokio::test]
async fn accept_and_lock_are_limited_together_and_reads_do_not_block_them() {
    let (base, h) = serve_proxy(false).await;
    let c = reqwest::Client::new();
    // Exhaust the read bucket with the listing (an unknown id would hit the miss limit first).
    let n = first_429(
        &c,
        "GET",
        &format!("{base}/swaps"),
        READ_LIMIT_PER_WINDOW,
        |_| None,
    )
    .await;
    assert_eq!(n, Some(READ_LIMIT_PER_WINDOW + 1), "read bucket size");
    assert_eq!(
        hit(&c, "GET", &format!("{base}/swaps/nope"), None).await,
        429,
        "a refused GET /swaps/:id shares it"
    );
    // Writes are untouched by the exhausted reads: a full write budget still passes.
    for i in 0..WRITE_LIMIT_PER_WINDOW {
        let (m, p) = if i % 2 == 0 {
            ("POST", "/swaps")
        } else {
            ("POST", "/swaps/nope/lock")
        };
        assert_ne!(
            hit(&c, m, &format!("{base}{p}"), None).await,
            429,
            "write {i}"
        );
    }
    // Accept and lock share one bucket: the next of either is 429.
    assert_eq!(
        hit(&c, "POST", &format!("{base}/swaps"), None).await,
        429,
        "accept"
    );
    assert_eq!(
        hit(&c, "POST", &format!("{base}/swaps/nope/lock"), None).await,
        429,
        "lock"
    );
    // The public reads have a bucket of their own.
    assert_eq!(hit(&c, "GET", &format!("{base}/healthz"), None).await, 200);
    assert_eq!(hit(&c, "GET", &format!("{base}/offers"), None).await, 200);
    h.abort();
}

#[tokio::test]
async fn writes_exhausting_their_bucket_do_not_block_status_reads() {
    let (base, h) = serve_proxy(false).await;
    let c = reqwest::Client::new();
    // Accept, not a lock: refused locks would also use up the misses `GET /swaps/:id` shares.
    let n = first_429(
        &c,
        "POST",
        &format!("{base}/swaps"),
        WRITE_LIMIT_PER_WINDOW,
        |_| None,
    )
    .await;
    assert_eq!(n, Some(WRITE_LIMIT_PER_WINDOW + 1));
    assert_ne!(
        hit(&c, "GET", &format!("{base}/swaps/nope"), None).await,
        429
    );
    assert_ne!(hit(&c, "GET", &format!("{base}/swaps"), None).await, 429);
    h.abort();
}

#[tokio::test]
async fn a_spoofed_forwarded_for_cannot_get_a_fresh_bucket_under_trust_proxy_headers() {
    let (base, h) = serve_proxy(true).await;
    let c = reqwest::Client::new();
    let url = format!("{base}/swaps");
    // nginx's old `$proxy_add_x_forwarded_for` shape: the client's own entries, then the
    // address nginx saw. The first entry changes every request; the last does not.
    let n = first_429(&c, "POST", &url, WRITE_LIMIT_PER_WINDOW, |i| {
        Some(format!("203.0.113.{i}, 198.51.100.9"))
    })
    .await;
    assert_eq!(
        n,
        Some(WRITE_LIMIT_PER_WINDOW + 1),
        "spoofed first entry is ignored"
    );
    // The shipped snippet's shape (`X-Forwarded-For $remote_addr`): one address, the same.
    assert_eq!(hit(&c, "POST", &url, Some("198.51.100.9")).await, 429);
    // A different real client (a different last entry) has its own bucket.
    assert_ne!(
        hit(&c, "POST", &url, Some("203.0.113.1, 198.51.100.10")).await,
        429
    );
    h.abort();
}

/// A client that reaches the daemon directly (its address is not in `trusted_proxies`) cannot
/// pick its bucket with `X-Forwarded-For`: rotating it, its 21st token miss on `GET /swaps/:id`
/// is still a 429. Fails on 75c9b7c, where the flag alone made any peer's header count.
#[tokio::test]
async fn an_untrusted_peer_rotating_forwarded_for_is_429_on_its_21st_miss() {
    // The proxy is elsewhere; this test's loopback connection is a client, not the proxy.
    let (base, h) = serve_trusting(&["192.0.2.0/24", "2001:db8::/32"]).await;
    let c = reqwest::Client::new();
    let n = first_429(
        &c,
        "GET",
        &format!("{base}/swaps/nope"),
        XMR_TOKEN_MISS_LIMIT_PER_WINDOW,
        |i| Some(format!("198.51.100.{i}")),
    )
    .await;
    assert_eq!(
        n,
        Some(XMR_TOKEN_MISS_LIMIT_PER_WINDOW + 1),
        "keyed on the socket peer"
    );
    h.abort();
}

/// Two clients behind a proxy on this host (the default `trusted_proxies`) keep separate
/// buckets: one using up its token misses leaves the other's whole.
#[tokio::test]
async fn two_clients_behind_a_loopback_proxy_keep_separate_buckets() {
    let (base, h) = serve_proxy(true).await;
    let c = reqwest::Client::new();
    let url = format!("{base}/swaps/nope");
    let n = first_429(&c, "GET", &url, XMR_TOKEN_MISS_LIMIT_PER_WINDOW, |_| {
        Some("198.51.100.1".into())
    })
    .await;
    assert_eq!(n, Some(XMR_TOKEN_MISS_LIMIT_PER_WINDOW + 1), "first client");
    assert_eq!(hit(&c, "GET", &url, Some("198.51.100.2")).await, 404);
    assert_eq!(
        hit(&c, "GET", &url, Some("203.0.113.5, 198.51.100.2")).await,
        404,
        "the last entry names the client"
    );
    assert_eq!(hit(&c, "GET", &url, Some("198.51.100.1")).await, 429);
    h.abort();
}

#[tokio::test]
async fn forwarded_for_is_ignored_without_trust_proxy_headers() {
    let (base, h) = serve_proxy(false).await;
    let c = reqwest::Client::new();
    let url = format!("{base}/swaps");
    let n = first_429(&c, "POST", &url, WRITE_LIMIT_PER_WINDOW, |i| {
        Some(format!("198.51.100.{i}"))
    })
    .await;
    assert_eq!(
        n,
        Some(WRITE_LIMIT_PER_WINDOW + 1),
        "one socket bucket whatever the header says"
    );
    h.abort();
}

/// `/healthz` and `GET /offers` share one generous public bucket, apart from the swap reads.
/// Fails on 7361ae6, where both were unlimited.
#[tokio::test]
async fn healthz_and_offers_share_a_public_bucket() {
    let (base, h) = serve_proxy(false).await;
    let c = reqwest::Client::new();
    let n = first_429(
        &c,
        "GET",
        &format!("{base}/healthz"),
        PUBLIC_READ_LIMIT_PER_WINDOW,
        |_| None,
    )
    .await;
    assert_eq!(
        n,
        Some(PUBLIC_READ_LIMIT_PER_WINDOW + 1),
        "public bucket size"
    );
    assert_eq!(
        hit(&c, "GET", &format!("{base}/offers"), None).await,
        429,
        "GET /offers shares it"
    );
    // Swap status reads are not in it.
    assert_ne!(
        hit(&c, "GET", &format!("{base}/swaps/nope"), None).await,
        429
    );
    h.abort();
}

/// Under `trust_proxy_headers` a client changing the first `X-Forwarded-For` entry keeps the
/// public bucket of the last one (the address the proxy wrote).
#[tokio::test]
async fn a_spoofed_forwarded_for_cannot_get_a_fresh_public_bucket() {
    let (base, h) = serve_proxy(true).await;
    let c = reqwest::Client::new();
    let url = format!("{base}/offers");
    let n = first_429(&c, "GET", &url, PUBLIC_READ_LIMIT_PER_WINDOW, |i| {
        Some(format!("203.0.113.{}, 198.51.100.9", i % 250))
    })
    .await;
    assert_eq!(n, Some(PUBLIC_READ_LIMIT_PER_WINDOW + 1));
    assert_ne!(
        hit(&c, "GET", &url, Some("203.0.113.1, 198.51.100.10")).await,
        429,
        "another real client has its own bucket"
    );
    h.abort();
}
