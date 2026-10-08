// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Esplora HTTP client with exponential backoff, `Retry-After` handling on 429, and
//! fallback from the primary to the secondary endpoint.

use std::time::Duration;

use divi_swap::SwapError;
use reqwest::{Method, StatusCode};

/// Retry / backoff settings.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Attempts per endpoint (>= 1).
    pub attempts: u32,
    /// First backoff; doubles each retry.
    pub base_delay: Duration,
    /// Upper bound on any single wait, including a server `Retry-After`.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 4,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        }
    }
}

/// A non-retryable HTTP answer (4xx other than 429).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpFailure {
    /// Status code.
    pub status: u16,
    /// Response body (Esplora puts the node's reject reason here).
    pub body: String,
}

/// Outcome of a request that reached a server and was not worth retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// 4xx other than 429: the server understood and refused.
    Http(HttpFailure),
    /// Network errors, 5xx (except 501) or 429 on every endpoint and attempt.
    Transient(String),
}

impl From<ClientError> for SwapError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Http(f) => {
                SwapError::Other(format!("esplora HTTP {}: {}", f.status, f.body))
            }
            ClientError::Transient(m) => SwapError::Transient(m),
        }
    }
}

/// Esplora client over an ordered list of base URLs (primary first).
#[derive(Debug, Clone)]
pub struct EsploraClient {
    http: reqwest::Client,
    endpoints: Vec<String>,
    retry: RetryPolicy,
}

impl EsploraClient {
    /// `endpoints` are base URLs such as `https://mempool.space/signet/api`.
    pub fn new(endpoints: Vec<String>, retry: RetryPolicy) -> Result<Self, SwapError> {
        if endpoints.is_empty() {
            return Err(SwapError::InvalidParams("no Esplora endpoints".into()));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| SwapError::Other(format!("http client: {e}")))?;
        let endpoints = endpoints
            .into_iter()
            .map(|e| e.trim_end_matches('/').to_string())
            .collect();
        Ok(Self {
            http,
            endpoints,
            retry,
        })
    }

    /// GET `path` and return the body.
    pub async fn get(&self, path: &str) -> Result<String, ClientError> {
        self.send(Method::GET, path, None).await
    }

    /// GET `path`; a 404 becomes `Ok(None)`.
    pub async fn get_opt(&self, path: &str) -> Result<Option<String>, ClientError> {
        match self.get(path).await {
            Ok(b) => Ok(Some(b)),
            Err(ClientError::Http(f)) if f.status == 404 => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// POST a text body.
    pub async fn post(&self, path: &str, body: String) -> Result<String, ClientError> {
        self.send(Method::POST, path, Some(body)).await
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<String>,
    ) -> Result<String, ClientError> {
        let mut last = String::from("no attempt made");
        for (i, base) in self.endpoints.iter().enumerate() {
            let url = format!("{base}{path}");
            let mut delay = self.retry.base_delay;
            for attempt in 1..=self.retry.attempts.max(1) {
                let mut req = self.http.request(method.clone(), &url);
                if let Some(b) = &body {
                    req = req.body(b.clone());
                }
                let wait = match req.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        let retry_after = resp
                            .headers()
                            .get(reqwest::header::RETRY_AFTER)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.trim().parse::<u64>().ok())
                            .map(Duration::from_secs);
                        let text = resp.text().await.unwrap_or_default();
                        if status.is_success() {
                            return Ok(text);
                        }
                        if status == StatusCode::TOO_MANY_REQUESTS
                            || (status.is_server_error() && status != StatusCode::NOT_IMPLEMENTED)
                        {
                            last = format!("{url}: HTTP {status}");
                            retry_after.unwrap_or(delay)
                        } else {
                            return Err(ClientError::Http(HttpFailure {
                                status: status.as_u16(),
                                body: text,
                            }));
                        }
                    }
                    Err(e) => {
                        last = format!("{url}: {e}");
                        delay
                    }
                };
                if attempt < self.retry.attempts.max(1) {
                    tracing::debug!(%last, attempt, "esplora retry");
                    tokio::time::sleep(wait.min(self.retry.max_delay)).await;
                    delay = (delay * 2).min(self.retry.max_delay);
                }
            }
            if i + 1 < self.endpoints.len() {
                tracing::warn!(%last, "esplora endpoint exhausted, falling back");
            }
        }
        Err(ClientError::Transient(last))
    }
}
