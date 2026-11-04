// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! HTTP client for a `divi-swapd` maker, usable from the browser.

use divi_swap::api::{
    AcceptReply, AcceptRequest, LockNotice, Offer, Quote, SwapView, SWAP_TOKEN_HEADER,
    SWAP_TOKEN_SUPPORT_HEADER,
};
use divi_swap::{Result, SwapError};
use serde::de::DeserializeOwned;

/// Talks to one maker.
#[derive(Clone)]
pub struct MakerClient {
    base: String,
    http: reqwest::Client,
}

/// Ids the maker hands out go into URL paths; refuse anything that could change the path.
fn path_id(id: &str) -> Result<&str> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(id)
    } else {
        Err(SwapError::InvalidParams(format!("bad id {id:?}")))
    }
}

fn transient(e: reqwest::Error) -> SwapError {
    SwapError::Transient(e.to_string())
}

impl MakerClient {
    /// Client for the maker at `base` (e.g. `https://divi.cx/swap`).
    pub fn new(base: &str) -> Result<Self> {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(std::time::Duration::from_secs(60));
        Ok(MakerClient {
            base: base.trim_end_matches('/').to_string(),
            http: builder
                .build()
                .map_err(|e| SwapError::Other(e.to_string()))?,
        })
    }

    async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let body = resp.text().await.map_err(transient)?;
        if !status.is_success() {
            let body: String = body.chars().take(300).collect();
            let msg = format!("maker answered {status}: {body}");
            return Err(if status.is_server_error() || status.as_u16() == 429 {
                SwapError::Transient(msg)
            } else {
                SwapError::Rejected(msg)
            });
        }
        serde_json::from_str(&body).map_err(|e| SwapError::Other(format!("maker response: {e}")))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .map_err(transient)?;
        Self::decode(resp).await
    }

    /// The maker's offers.
    pub async fn offers(&self) -> Result<Vec<Offer>> {
        self.get("/offers").await
    }

    /// A firm quote for `btc_sats` of the counter coin.
    pub async fn quote(&self, offer_id: &str, btc_sats: u64) -> Result<Quote> {
        let id = path_id(offer_id)?;
        self.get(&format!("/offers/{id}/quote?btc_sats={btc_sats}"))
            .await
    }

    /// Accept a quote, declaring support for per-swap tokens (`x-swap-token-support: 1`).
    pub async fn accept(&self, req: &AcceptRequest) -> Result<AcceptReply> {
        let resp = self
            .http
            .post(format!("{}/swaps", self.base))
            .header(SWAP_TOKEN_SUPPORT_HEADER, "1")
            .json(req)
            .send()
            .await
            .map_err(transient)?;
        let status = resp.status();
        let body = resp.text().await.map_err(transient)?;
        if !status.is_success() {
            let body: String = body.chars().take(300).collect();
            let msg = format!("maker answered {status}: {body}");
            return Err(if status.is_server_error() || status.as_u16() == 429 {
                SwapError::Transient(msg)
            } else {
                SwapError::Rejected(msg)
            });
        }
        // Never echo `body` on a decode error: a 2xx accept body carries `swap_token`.
        serde_json::from_str(&body)
            .map_err(|e| SwapError::Other(format!("maker accept response: {e}")))
    }

    /// Tell the maker where the taker's lock is, authenticating with `token` when present.
    pub async fn lock(
        &self,
        swap_id: &str,
        token: Option<&str>,
        notice: &LockNotice,
    ) -> Result<SwapView> {
        let id = path_id(swap_id)?;
        let mut rb = self
            .http
            .post(format!("{}/swaps/{id}/lock", self.base))
            .json(notice);
        if let Some(t) = token.filter(|t| !t.is_empty()) {
            rb = rb.header(SWAP_TOKEN_HEADER, t);
        }
        let resp = rb.send().await.map_err(transient)?;
        Self::decode(resp).await
    }

    /// The maker's view of a swap, authenticating with `token` when present.
    pub async fn swap(&self, swap_id: &str, token: Option<&str>) -> Result<SwapView> {
        let id = path_id(swap_id)?;
        let mut rb = self.http.get(format!("{}/swaps/{id}", self.base));
        if let Some(t) = token.filter(|t| !t.is_empty()) {
            rb = rb.header(SWAP_TOKEN_HEADER, t);
        }
        let resp = rb.send().await.map_err(transient)?;
        Self::decode(resp).await
    }
}
