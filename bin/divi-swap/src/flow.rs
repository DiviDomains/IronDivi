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

//! The whole taker flow, shared by `divi-swap run` and the end-to-end tests.

use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use divi_swap::{Taker, TakerState};

use crate::client::MakerClient;
use crate::session::{Session, Sessions};

pub struct RunOpts {
    /// Give up (without refunding) after this long.
    pub timeout: Duration,
    /// Pause between polls of the maker.
    pub poll: Duration,
}

impl Default for RunOpts {
    fn default() -> Self {
        RunOpts {
            timeout: Duration::from_secs(8 * 3600),
            poll: Duration::from_secs(10),
        }
    }
}

/// Quote, accept, lock, then step the taker until `Done`. `pump` is called once per poll
/// (the CLI passes a no-op; tests use it to mine blocks on simulated chains).
/// Returns the local swap id and the final taker state.
pub async fn run_swap(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    offer_id: &str,
    btc_sats: u64,
    opts: &RunOpts,
    pump: &mut dyn FnMut(),
) -> Result<(String, TakerState)> {
    let local = begin(taker, client, sessions, offer_id, btc_sats).await?;
    lock(taker, client, sessions, &local).await?;
    let started = Instant::now();
    loop {
        pump();
        let state = step(taker, client, sessions, &local).await?;
        if state == TakerState::Done {
            return Ok((local, state));
        }
        if started.elapsed() > opts.timeout {
            bail!("timed out in taker state {state:?}; swap {local} left in place — rerun `status`/`refund`");
        }
        tokio::time::sleep(opts.poll).await;
    }
}

/// Fresh quote → prepare → `POST /swaps` → record the maker's reply. Returns the local id.
pub async fn begin(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    offer_id: &str,
    btc_sats: u64,
) -> Result<String> {
    let quote = client.quote(offer_id, btc_sats).await?;
    let (local, req) = taker.prepare(&quote).await?;
    let view = client.accept(&req).await?;
    sessions.put(
        &local,
        Session {
            maker_url: client.base().to_string(),
            maker_swap_id: view.id.clone(),
        },
    )?;
    taker.accepted(&local, &view).await?;
    Ok(local)
}

/// Fund the BTC HTLC and tell the maker.
pub async fn lock(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    local: &str,
) -> Result<()> {
    let session = sessions.get(local)?;
    let notice = taker.lock(local).await?;
    client.lock(&session.maker_swap_id, &notice).await?;
    Ok(())
}

/// One taker step against the maker's latest view (`None` if the maker is unreachable).
pub async fn step(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    local: &str,
) -> Result<TakerState> {
    let session = sessions.get(local)?;
    let view = match client.swap(&session.maker_swap_id).await {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, "maker unreachable; stepping without its view");
            None
        }
    };
    Ok(taker.step(local, view.as_ref()).await?)
}
