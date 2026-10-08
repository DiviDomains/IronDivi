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

//! Typed HTTP client for `divi-swapd`.

use anyhow::{anyhow, Context, Result};
use divi_swap::api::{AcceptRequest, LockNotice, Offer, Quote, SwapView};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Clone)]
pub struct MakerClient {
    base: String,
    http: reqwest::Client,
}

impl MakerClient {
    /// `base` includes any path prefix, e.g. `https://host/swap`.
    pub fn new(base: &str) -> Self {
        MakerClient {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let body = resp.text().await.context("reading maker response")?;
        if !status.is_success() {
            return Err(anyhow!("maker returned {status}: {body}"));
        }
        serde_json::from_str(&body).with_context(|| format!("decoding maker response: {body}"))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        Self::decode(resp).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {path}"))?;
        Self::decode(resp).await
    }

    pub async fn offers(&self) -> Result<Vec<Offer>> {
        self.get("/offers").await
    }

    pub async fn quote(&self, offer_id: &str, btc_sats: u64) -> Result<Quote> {
        self.get(&format!("/offers/{offer_id}/quote?btc_sats={btc_sats}"))
            .await
    }

    pub async fn accept(&self, req: &AcceptRequest) -> Result<SwapView> {
        self.post("/swaps", req).await
    }

    pub async fn lock(&self, swap_id: &str, notice: &LockNotice) -> Result<SwapView> {
        self.post(&format!("/swaps/{swap_id}/lock"), notice).await
    }

    pub async fn swap(&self, swap_id: &str) -> Result<SwapView> {
        self.get(&format!("/swaps/{swap_id}")).await
    }
}
