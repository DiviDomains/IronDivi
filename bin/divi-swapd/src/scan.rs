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

//! Background DIVI wallet scan: progress shared with `/healthz`, the routes and the scheduler.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::Serialize;
use swap_chain_divi::DiviBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanState {
    Scanning,
    Done,
    Failed,
}

/// Snapshot reported under `divi_scan` in `/healthz`.
#[derive(Debug, Clone, Serialize)]
pub struct ScanInfo {
    pub state: ScanState,
    pub next_height: u64,
    pub target_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Shared scan progress. Anything that needs the wallet's coins waits for [`ScanStatus::is_done`].
#[derive(Clone)]
pub struct ScanStatus(Arc<Mutex<ScanInfo>>);

impl ScanStatus {
    fn new(state: ScanState) -> Self {
        ScanStatus(Arc::new(Mutex::new(ScanInfo {
            state,
            next_height: 0,
            target_height: 0,
            error: None,
        })))
    }

    /// No scan to wait for (mock chains, or no `scan_from_height`).
    pub fn done() -> Self {
        Self::new(ScanState::Done)
    }

    /// A scan is about to start.
    pub fn scanning() -> Self {
        Self::new(ScanState::Scanning)
    }

    pub fn info(&self) -> ScanInfo {
        self.0.lock().clone()
    }

    pub fn is_done(&self) -> bool {
        self.0.lock().state == ScanState::Done
    }

    fn set(&self, state: ScanState, next: u64, target: u64, error: Option<String>) {
        *self.0.lock() = ScanInfo {
            state,
            next_height: next,
            target_height: target,
            error,
        };
    }
}

/// What the scan driver needs from the DIVI backend.
pub trait WalletScan: Send + Sync {
    /// Cursor persisted with the wallet.
    fn scanned_height(&self) -> Option<u64>;
    fn tip(&self) -> impl Future<Output = Result<u64, String>> + Send;
    /// Scan `from..=to` and persist the cursor `to + 1`.
    fn scan_range(&self, from: u64, to: u64) -> impl Future<Output = Result<u64, String>> + Send;
}

impl WalletScan for DiviBackend {
    fn scanned_height(&self) -> Option<u64> {
        DiviBackend::scanned_height(self)
    }
    async fn tip(&self) -> Result<u64, String> {
        divi_swap::ChainBackend::tip_height(self)
            .await
            .map_err(|e| e.to_string())
    }
    async fn scan_range(&self, from: u64, to: u64) -> Result<u64, String> {
        DiviBackend::scan_range(self, from, to)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Scan to the tip in `chunk`-block steps, resuming from `max(scan_from, saved cursor)`.
/// A failure is logged, reported in `status`, and retried after `retry` from the saved cursor.
/// Returns once the scan has reached the tip.
pub async fn run_scan<S: WalletScan>(
    s: &S,
    scan_from: u64,
    status: &ScanStatus,
    chunk: u64,
    retry: Duration,
) {
    let mut next = scan_from.max(s.scanned_height().unwrap_or(0));
    let mut target = next.saturating_sub(1);
    tracing::info!(next, scan_from, "divi wallet scan starting");
    loop {
        match scan_pass(s, &mut next, &mut target, status, chunk.max(1)).await {
            Ok(()) => {
                status.set(ScanState::Done, next, target, None);
                tracing::info!(next, "divi wallet scan done");
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, next, "divi wallet scan failed; will retry");
                // Resume from whatever the wallet persisted.
                next = next.max(s.scanned_height().unwrap_or(0));
                status.set(ScanState::Failed, next, target, Some(e));
                tokio::time::sleep(retry).await;
            }
        }
    }
}

async fn scan_pass<S: WalletScan>(
    s: &S,
    next: &mut u64,
    target: &mut u64,
    status: &ScanStatus,
    chunk: u64,
) -> Result<(), String> {
    loop {
        *target = s.tip().await?;
        status.set(ScanState::Scanning, *next, *target, None);
        if *next > *target {
            return Ok(());
        }
        while *next <= *target {
            let to = (*next + chunk - 1).min(*target);
            *next = s.scan_range(*next, to).await?;
            status.set(ScanState::Scanning, *next, *target, None);
        }
        // Blocks may have arrived during the scan; loop until the tip is stable.
    }
}
