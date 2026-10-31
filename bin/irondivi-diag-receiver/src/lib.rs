// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! §9: the receiver for `irondivi-cli diag` packages.
//!
//! - `PUT /v1/upload` takes one `age`-encrypted body of at most [`CAP`]
//!   bytes. A body that does not start with the `age` header is refused
//!   before anything is written. The answer is a ticket: 8 characters
//!   from a 32-letter alphabet, from the OS's randomness, derived from
//!   nothing about the sender.
//! - Stored, under the ticket: the ciphertext, and a `.meta` file with
//!   its size, its SHA-256 and the arrival time. Nothing else.
//! - Rate limits by client address **in memory only** ([`Limiter`]): 10
//!   uploads an hour and 1 GB a day. The address arrives from nginx in
//!   [`PEER_HEADER`] and is hashed at once with a key drawn at start-up,
//!   so the process holds no address, only a keyed hash that means
//!   nothing after a restart. Every `PUT` counts, refused ones included.
//! - Packages are deleted [`RETENTION_SECS`] after arrival ([`sweep`]), or
//!   when the developer closes the ticket (`DELETE /v1/dev/<ticket>`).
//! - Developer routes (`/v1/dev…`) need `Authorization: Bearer <token>`;
//!   the receiver holds only the token's SHA-256.
//!
//! Nothing about a request is logged or written: no tracing, no access
//! log, and errors answer the client without being printed.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path as UrlPath, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Router;
use futures::StreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

/// The largest body taken: 100 MiB
pub const CAP: u64 = 100 * 1024 * 1024;
/// Uploads per address per hour
pub const PER_HOUR: usize = 10;
/// Bytes per address per day
pub const PER_DAY_BYTES: u64 = 1_000_000_000;
/// 90 days
pub const RETENTION_SECS: u64 = 90 * 24 * 3600;
/// Set by nginx to the client address; read only to key the limiter
pub const PEER_HEADER: &str = "x-diag-peer";
/// The first line of every `age` file (binary format)
pub const AGE_HEADER: &[u8] = b"age-encryption.org/v1\n";
/// Crockford's base32: no I, L, O or U
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const TICKET_LEN: usize = 8;
/// Prefix of a body still arriving; never a valid ticket
const INCOMING: &str = ".incoming-";

const HOUR: u64 = 3600;
const DAY: u64 = 24 * 3600;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A fresh random ticket
pub fn new_ticket() -> String {
    let mut b = [0u8; TICKET_LEN];
    rand::rngs::OsRng.fill_bytes(&mut b);
    // 256 is a multiple of 32, so masking is uniform
    b.iter().map(|x| ALPHABET[(*x & 31) as usize] as char).collect()
}

pub fn is_ticket(s: &str) -> bool {
    s.len() == TICKET_LEN && s.bytes().all(|c| ALPHABET.contains(&c))
}

/// What is stored beside each package, and nothing more
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Meta {
    pub size: u64,
    pub sha256: String,
    /// Unix seconds
    pub arrived: u64,
}

// ------------------------------------------------------------- limiter

#[derive(Default)]
struct Bucket {
    /// arrival of each upload in the last hour
    uploads: VecDeque<u64>,
    /// (time, bytes) in the last day
    bytes: VecDeque<(u64, u64)>,
}

impl Bucket {
    fn prune(&mut self, now: u64) {
        while self.uploads.front().is_some_and(|t| now.saturating_sub(*t) >= HOUR) {
            self.uploads.pop_front();
        }
        while self.bytes.front().is_some_and(|(t, _)| now.saturating_sub(*t) >= DAY) {
            self.bytes.pop_front();
        }
    }
    fn day_bytes(&self) -> u64 {
        self.bytes.iter().map(|(_, b)| b).sum()
    }
    fn is_empty(&self) -> bool {
        self.uploads.is_empty() && self.bytes.is_empty()
    }
}

/// Keyed hash of a client address → its windows. Memory only.
pub struct Limiter {
    key: [u8; 32],
    buckets: Mutex<HashMap<[u8; 16], Bucket>>,
}

impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Limiter {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Limiter { key, buckets: Mutex::new(HashMap::new()) }
    }

    /// The address is hashed here and dropped by the caller
    pub fn peer(&self, addr: &str) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(self.key);
        h.update(addr.as_bytes());
        let d = h.finalize();
        let mut k = [0u8; 16];
        k.copy_from_slice(&d[..16]);
        k
    }

    /// Count an upload attempt; `Err` names the limit it would pass
    pub fn admit(&self, peer: [u8; 16], declared: u64, now: u64) -> Result<(), &'static str> {
        let mut m = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let b = m.entry(peer).or_default();
        b.prune(now);
        if b.uploads.len() >= PER_HOUR {
            return Err("rate limited: 10 uploads an hour from one address; try again later");
        }
        if b.day_bytes() + declared > PER_DAY_BYTES {
            return Err("rate limited: 1 GB a day from one address; try again tomorrow");
        }
        b.uploads.push_back(now);
        Ok(())
    }

    /// Bytes received so far today, `extra` included; `false` = over the day's cap
    pub fn within_day(&self, peer: [u8; 16], extra: u64, now: u64) -> bool {
        let mut m = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let b = m.entry(peer).or_default();
        b.prune(now);
        b.day_bytes() + extra <= PER_DAY_BYTES
    }

    pub fn record_bytes(&self, peer: [u8; 16], n: u64, now: u64) {
        if n == 0 {
            return;
        }
        let mut m = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        m.entry(peer).or_default().bytes.push_back((now, n));
    }

    /// Forget every window that has passed
    pub fn forget_old(&self, now: u64) {
        let mut m = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, b| {
            b.prune(now);
            !b.is_empty()
        });
    }

    pub fn tracked(&self) -> usize {
        self.buckets.lock().map(|m| m.len()).unwrap_or(0)
    }
}

// ------------------------------------------------------------- storage

pub fn age_path(dir: &Path, t: &str) -> PathBuf {
    dir.join(format!("{t}.age"))
}

pub fn meta_path(dir: &Path, t: &str) -> PathBuf {
    dir.join(format!("{t}.meta"))
}

pub fn read_meta(dir: &Path, t: &str) -> Option<Meta> {
    let s = std::fs::read(meta_path(dir, t)).ok()?;
    serde_json::from_slice(&s).ok()
}

/// Delete packages older than [`RETENTION_SECS`] and bodies left half
/// written for over a day (a crash mid-upload). Returns how many went.
pub fn sweep(dir: &Path, now: u64) -> io::Result<usize> {
    let mut gone = 0;
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(t) = name.strip_suffix(".meta") {
            if !is_ticket(t) {
                continue;
            }
            let old = match read_meta(dir, t) {
                Some(m) => now.saturating_sub(m.arrived) >= RETENTION_SECS,
                None => false,
            };
            if old {
                let _ = std::fs::remove_file(age_path(dir, t));
                let _ = std::fs::remove_file(meta_path(dir, t));
                gone += 1;
            }
        } else if name.starts_with(INCOMING) {
            let age = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .map(|d| now.saturating_sub(d.as_secs()))
                .unwrap_or(0);
            if age >= DAY {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    Ok(gone)
}

// ------------------------------------------------------------- service

pub struct Config {
    pub data: PathBuf,
    /// SHA-256 of the developer token; `None` turns the developer routes off
    pub token_sha256: Option<[u8; 32]>,
}

pub struct AppState {
    pub cfg: Config,
    pub limiter: Limiter,
}

pub fn router(st: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/upload", put(upload))
        .route("/v1/dev", get(dev_list))
        .route("/v1/dev/:ticket", get(dev_get).delete(dev_delete))
        .route("/v1/health", get(|| async { "ok\n" }))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found\n") })
        // the body is streamed and capped by `upload` itself
        .layer(DefaultBodyLimit::disable())
        .with_state(st)
}

fn refuse(code: StatusCode, msg: &str) -> Response {
    (code, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], format!("{msg}\n")).into_response()
}

#[derive(Serialize)]
struct Receipt<'a> {
    ticket: &'a str,
    sha256: &'a str,
    size: u64,
    retention_days: u64,
}

async fn upload(State(st): State<Arc<AppState>>, headers: HeaderMap, body: Body) -> Response {
    let t0 = now();
    // the address is hashed and not kept
    let peer = st.limiter.peer(headers.get(PEER_HEADER).and_then(|v| v.to_str().ok()).unwrap_or(""));
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > CAP) {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, "too large: the limit is 100 MiB; diag splits larger packages");
    }
    if let Err(why) = st.limiter.admit(peer, declared.unwrap_or(0), t0) {
        return refuse(StatusCode::TOO_MANY_REQUESTS, why);
    }
    let r = receive(&st, peer, body).await;
    match r {
        Ok((ticket, meta)) => {
            let receipt = Receipt { ticket: &ticket, sha256: &meta.sha256, size: meta.size, retention_days: RETENTION_SECS / DAY };
            (StatusCode::CREATED, axum::Json(receipt)).into_response()
        }
        Err((code, msg)) => refuse(code, msg),
    }
}

/// Stream the body to a private temp file in the data dir, then link it
/// under a new ticket. On any refusal the temp file is removed.
async fn receive(st: &AppState, peer: [u8; 16], body: Body) -> Result<(String, Meta), (StatusCode, &'static str)> {
    let dir = &st.cfg.data;
    let mut stream = body.into_data_stream();
    let mut head: Vec<u8> = Vec::with_capacity(AGE_HEADER.len());
    let mut pending: Vec<bytes_vec::Chunk> = Vec::new();
    let mut total: u64 = 0;
    let lost = (StatusCode::BAD_REQUEST, "the upload was cut off");
    // the header check comes before anything touches the disk
    while head.len() < AGE_HEADER.len() {
        match stream.next().await {
            Some(Ok(c)) => {
                total += c.len() as u64;
                let need = AGE_HEADER.len() - head.len();
                head.extend_from_slice(&c[..need.min(c.len())]);
                pending.push(c);
            }
            Some(Err(_)) => return Err(lost),
            None => break,
        }
    }
    if head != AGE_HEADER {
        return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "refused: not an age-encrypted file (no age header)"));
    }
    let tmp = dir.join(format!("{INCOMING}{}", hex::encode(rand::random::<[u8; 8]>())));
    let mut f = open_private(&tmp).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "the receiver cannot store it now"))?;
    let mut h = Sha256::new();
    let fail = |code, msg| {
        let tmp = tmp.clone();
        async move {
            let _ = tokio::fs::remove_file(&tmp).await;
            Err((code, msg))
        }
    };
    for c in pending.drain(..) {
        h.update(&c);
        if f.write_all(&c).await.is_err() {
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "the receiver cannot store it now").await;
        }
    }
    let now0 = now();
    while let Some(c) = stream.next().await {
        let c = match c {
            Ok(c) => c,
            Err(_) => return fail(lost.0, lost.1).await,
        };
        total += c.len() as u64;
        if total > CAP {
            st.limiter.record_bytes(peer, total, now0);
            return fail(StatusCode::PAYLOAD_TOO_LARGE, "too large: the limit is 100 MiB; diag splits larger packages").await;
        }
        if !st.limiter.within_day(peer, total, now0) {
            st.limiter.record_bytes(peer, total, now0);
            return fail(StatusCode::TOO_MANY_REQUESTS, "rate limited: 1 GB a day from one address; try again tomorrow").await;
        }
        h.update(&c);
        if f.write_all(&c).await.is_err() {
            return fail(StatusCode::INTERNAL_SERVER_ERROR, "the receiver cannot store it now").await;
        }
    }
    st.limiter.record_bytes(peer, total, now0);
    if f.sync_all().await.is_err() {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "the receiver cannot store it now").await;
    }
    drop(f);
    let meta = Meta { size: total, sha256: hex::encode(h.finalize()), arrived: now() };
    // a hard link fails on an existing name, so a collision draws again
    let mut ticket = None;
    for _ in 0..16 {
        let t = new_ticket();
        if tokio::fs::hard_link(&tmp, age_path(dir, &t)).await.is_ok() {
            ticket = Some(t);
            break;
        }
    }
    let _ = tokio::fs::remove_file(&tmp).await;
    let Some(t) = ticket else {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "the receiver cannot store it now"));
    };
    let mp = meta_path(dir, &t);
    let ok = match open_private(&mp).await {
        Ok(mut m) => m.write_all(&serde_json::to_vec(&meta).unwrap_or_default()).await.is_ok() && m.sync_all().await.is_ok(),
        Err(_) => false,
    };
    if !ok {
        let _ = tokio::fs::remove_file(age_path(dir, &t)).await;
        let _ = tokio::fs::remove_file(&mp).await;
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "the receiver cannot store it now"));
    }
    Ok((t, meta))
}

mod bytes_vec {
    pub type Chunk = axum::body::Bytes;
}

async fn open_private(p: &Path) -> io::Result<tokio::fs::File> {
    let mut o = tokio::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(0o600);
    o.open(p).await
}

fn authorised(st: &AppState, headers: &HeaderMap) -> bool {
    let Some(want) = st.cfg.token_sha256 else {
        return false;
    };
    let Some(got) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    let d: [u8; 32] = Sha256::digest(got.trim().as_bytes()).into();
    d.ct_eq(&want).into()
}

async fn dev_list(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorised(&st, &headers) {
        return refuse(StatusCode::UNAUTHORIZED, "unauthorised");
    }
    let mut out: Vec<serde_json::Value> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&st.cfg.data) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if let Some(t) = n.strip_suffix(".meta").filter(|t| is_ticket(t)) {
                if let Some(m) = read_meta(&st.cfg.data, t) {
                    out.push(serde_json::json!({"ticket": t, "size": m.size, "sha256": m.sha256, "arrived": m.arrived}));
                }
            }
        }
    }
    out.sort_by_key(|v| v["arrived"].as_u64());
    axum::Json(out).into_response()
}

async fn dev_get(State(st): State<Arc<AppState>>, UrlPath(t): UrlPath<String>, headers: HeaderMap) -> Response {
    if !authorised(&st, &headers) {
        return refuse(StatusCode::UNAUTHORIZED, "unauthorised");
    }
    let t = t.to_ascii_uppercase();
    if !is_ticket(&t) {
        return refuse(StatusCode::NOT_FOUND, "no such ticket");
    }
    let (Some(m), Ok(f)) = (read_meta(&st.cfg.data, &t), tokio::fs::File::open(age_path(&st.cfg.data, &t)).await) else {
        return refuse(StatusCode::NOT_FOUND, "no such ticket");
    };
    let stream = tokio_util_stream(f);
    let mut r = Response::new(Body::from_stream(stream));
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(m.size));
    if let Ok(v) = HeaderValue::from_str(&m.sha256) {
        h.insert("x-diag-sha256", v);
    }
    h.insert("x-diag-arrived", HeaderValue::from(m.arrived));
    r
}

/// A file as a stream of chunks, without pulling in tokio-util
fn tokio_util_stream(f: tokio::fs::File) -> impl futures::Stream<Item = io::Result<axum::body::Bytes>> {
    use tokio::io::AsyncReadExt;
    futures::stream::unfold(Some(f), |f| async move {
        let mut f = f?;
        let mut buf = vec![0u8; 64 * 1024];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(axum::body::Bytes::from(buf)), Some(f)))
            }
            Err(e) => Some((Err(e), None)),
        }
    })
}

async fn dev_delete(State(st): State<Arc<AppState>>, UrlPath(t): UrlPath<String>, headers: HeaderMap) -> Response {
    if !authorised(&st, &headers) {
        return refuse(StatusCode::UNAUTHORIZED, "unauthorised");
    }
    let t = t.to_ascii_uppercase();
    if !is_ticket(&t) || read_meta(&st.cfg.data, &t).is_none() {
        return refuse(StatusCode::NOT_FOUND, "no such ticket");
    }
    let a = tokio::fs::remove_file(age_path(&st.cfg.data, &t)).await;
    let b = tokio::fs::remove_file(meta_path(&st.cfg.data, &t)).await;
    if a.is_err() || b.is_err() {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not delete it all");
    }
    refuse(StatusCode::OK, "closed and deleted")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn alphabet_is_32_distinct_letters() {
        let mut v = ALPHABET.to_vec();
        v.sort();
        v.dedup();
        assert_eq!(v.len(), 32);
    }

    #[test]
    fn tickets_are_8_from_the_alphabet_and_differ() {
        let a: Vec<String> = (0..200).map(|_| new_ticket()).collect();
        for t in &a {
            assert!(is_ticket(t), "{t}");
        }
        let mut b = a.clone();
        b.sort();
        b.dedup();
        assert!(b.len() > 195);
        assert!(!is_ticket("../../etc"));
        assert!(!is_ticket("ABCDEFGI"));
    }

    #[test]
    fn limiter_10_an_hour_then_forgets() {
        let l = Limiter::new();
        let p = l.peer("192.0.2.1");
        assert_ne!(p, l.peer("192.0.2.2"));
        for i in 0..10 {
            assert!(l.admit(p, 1, 1000 + i).is_ok(), "{i}");
        }
        assert!(l.admit(p, 1, 1010).unwrap_err().contains("10 uploads"));
        // another address is not affected
        assert!(l.admit(l.peer("192.0.2.2"), 1, 1010).is_ok());
        // an hour after the first, one slot frees
        assert!(l.admit(p, 1, 1000 + HOUR).is_ok());
        l.forget_old(1000 + 2 * DAY);
        assert_eq!(l.tracked(), 0);
    }

    #[test]
    fn limiter_1gb_a_day() {
        let l = Limiter::new();
        let p = l.peer("198.51.100.7");
        l.record_bytes(p, PER_DAY_BYTES - 10, 5);
        assert!(l.admit(p, 11, 6).unwrap_err().contains("1 GB"));
        assert!(l.within_day(p, 10, 6));
        assert!(!l.within_day(p, 11, 6));
        assert!(l.admit(p, 11, 5 + DAY).is_ok());
    }

    #[test]
    fn sweep_deletes_after_90_days_only() {
        let d = tempfile::tempdir().unwrap();
        let m = |t: &str, arrived| {
            std::fs::write(age_path(d.path(), t), b"x").unwrap();
            std::fs::write(meta_path(d.path(), t), serde_json::to_vec(&Meta { size: 1, sha256: "s".into(), arrived }).unwrap()).unwrap();
        };
        m("AAAAAAAA", 100);
        m("BBBBBBBB", 100 + RETENTION_SECS);
        assert_eq!(sweep(d.path(), 99 + RETENTION_SECS).unwrap(), 0);
        assert_eq!(sweep(d.path(), 100 + RETENTION_SECS).unwrap(), 1);
        assert!(!age_path(d.path(), "AAAAAAAA").exists());
        assert!(!meta_path(d.path(), "AAAAAAAA").exists());
        assert!(age_path(d.path(), "BBBBBBBB").exists());
    }

    const TOKEN: &str = "test-token-not-a-secret";

    fn app(d: &Path) -> (Router, Arc<AppState>) {
        let st = Arc::new(AppState {
            cfg: Config { data: d.to_path_buf(), token_sha256: Some(Sha256::digest(TOKEN).into()) },
            limiter: Limiter::new(),
        });
        (router(st.clone()), st)
    }

    async fn put_body(r: &Router, body: Vec<u8>, peer: &str) -> (StatusCode, Vec<u8>) {
        let req = Request::put("/v1/upload").header(PEER_HEADER, peer).body(Body::from(body)).unwrap();
        let resp = r.clone().oneshot(req).await.unwrap();
        let s = resp.status();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
        (s, b)
    }

    fn files(d: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn upload_stores_only_body_size_hash_time_and_download_round_trips() {
        let d = tempfile::tempdir().unwrap();
        let (r, _) = app(d.path());
        let mut body = AGE_HEADER.to_vec();
        body.extend((0..200_000u32).map(|i| (i * 7) as u8));
        let peer = "203.0.113.77";
        let (s, b) = put_body(&r, body.clone(), peer).await;
        assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&b));
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        let t = v["ticket"].as_str().unwrap().to_string();
        assert!(is_ticket(&t));
        assert_eq!(v["sha256"], hex::encode(Sha256::digest(&body)));
        assert_eq!(files(d.path()), vec![format!("{t}.age"), format!("{t}.meta")]);
        assert_eq!(std::fs::read(age_path(d.path(), &t)).unwrap(), body);
        let meta = std::fs::read_to_string(meta_path(d.path(), &t)).unwrap();
        let keys: Vec<String> = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&meta).unwrap().keys().cloned().collect();
        assert_eq!(keys, vec!["arrived", "sha256", "size"]);
        // the address is nowhere on disk
        for f in files(d.path()) {
            let c = std::fs::read(d.path().join(f)).unwrap();
            assert!(!c.windows(peer.len()).any(|w| w == peer.as_bytes()));
        }
        // developer download: refused without the token, identical with it
        let get = |auth: Option<&str>| {
            let mut q = Request::get(format!("/v1/dev/{t}"));
            if let Some(a) = auth {
                q = q.header(header::AUTHORIZATION, format!("Bearer {a}"));
            }
            q.body(Body::empty()).unwrap()
        };
        assert_eq!(r.clone().oneshot(get(None)).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(r.clone().oneshot(get(Some("wrong"))).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        let resp = r.clone().oneshot(get(Some(TOKEN))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let got = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(got.as_ref(), body.as_slice());
        // closing deletes it
        let del = Request::delete(format!("/v1/dev/{t}")).header(header::AUTHORIZATION, format!("Bearer {TOKEN}")).body(Body::empty()).unwrap();
        assert_eq!(r.clone().oneshot(del).await.unwrap().status(), StatusCode::OK);
        assert!(files(d.path()).is_empty());
    }

    #[tokio::test]
    async fn non_age_is_refused_and_nothing_written() {
        let d = tempfile::tempdir().unwrap();
        let (r, _) = app(d.path());
        for body in [b"hello world, not age at all".to_vec(), Vec::new(), b"age-encryption.org/v2\n".to_vec(), b"age".to_vec()] {
            let (s, b) = put_body(&r, body, "192.0.2.9").await;
            assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{}", String::from_utf8_lossy(&b));
        }
        assert!(files(d.path()).is_empty());
    }

    #[tokio::test]
    async fn eleventh_upload_in_an_hour_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let (r, _) = app(d.path());
        let body = [AGE_HEADER, b"x"].concat();
        for i in 0..10 {
            let (s, _) = put_body(&r, body.clone(), "192.0.2.10").await;
            assert_eq!(s, StatusCode::CREATED, "{i}");
        }
        let (s, b) = put_body(&r, body.clone(), "192.0.2.10").await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert!(String::from_utf8_lossy(&b).contains("10 uploads"));
        let (s, _) = put_body(&r, body, "192.0.2.11").await;
        assert_eq!(s, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn over_the_cap_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let (r, _) = app(d.path());
        let req = Request::put("/v1/upload").header(header::CONTENT_LENGTH, CAP + 1).body(Body::from(AGE_HEADER.to_vec())).unwrap();
        assert_eq!(r.clone().oneshot(req).await.unwrap().status(), StatusCode::PAYLOAD_TOO_LARGE);
        // no Content-Length: counted while streaming
        let chunks = (0..=(CAP / (1 << 20))).map(|i| {
            let mut c = vec![0u8; 1 << 20];
            if i == 0 {
                c[..AGE_HEADER.len()].copy_from_slice(AGE_HEADER);
            }
            Ok::<_, io::Error>(axum::body::Bytes::from(c))
        });
        let req = Request::put("/v1/upload").body(Body::from_stream(futures::stream::iter(chunks))).unwrap();
        assert_eq!(r.clone().oneshot(req).await.unwrap().status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(files(d.path()).is_empty());
    }

    #[tokio::test]
    async fn dev_routes_off_without_a_token() {
        let d = tempfile::tempdir().unwrap();
        let st = Arc::new(AppState { cfg: Config { data: d.path().to_path_buf(), token_sha256: None }, limiter: Limiter::new() });
        let r = router(st);
        let q = Request::get("/v1/dev").header(header::AUTHORIZATION, "Bearer ").body(Body::empty()).unwrap();
        assert_eq!(r.oneshot(q).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
}
