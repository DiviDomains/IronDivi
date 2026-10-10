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

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use divi_swap::taker::TAKER_SAFETY_MARGIN_SECS;
use divi_swap::{Chain, ChainBackend, Store, Taker, TakerState};

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

/// When the taker may claim the maker's DIVI lock (end-to-end scenarios).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimPolicy {
    /// As soon as the lock is verified and confirmed (the normal flow).
    Asap,
    /// Hold the claim until the DIVI median time is within this many seconds of the maker's
    /// refund locktime (case D, "late claim"). Must exceed the taker's safety margin.
    NotBefore { secs_before_timeout: u32 },
    /// Never claim; wait out the BTC timelock and refund (case C).
    Never,
}

impl ClaimPolicy {
    /// Reject a late-claim lead the engine would itself refuse to claim with.
    pub fn validate(&self) -> Result<()> {
        if let ClaimPolicy::NotBefore {
            secs_before_timeout,
        } = self
        {
            if *secs_before_timeout <= TAKER_SAFETY_MARGIN_SECS {
                bail!(
                    "--claim-not-before must exceed the taker safety margin ({TAKER_SAFETY_MARGIN_SECS}s), \
                     or the engine refuses to claim"
                );
            }
        }
        Ok(())
    }
}

/// What a gated run needs to read from: the taker's own store (the maker lock's locktime)
/// and the backend of the maker-leg chain (its median time): DIVI going forward, BTC in
/// reverse.
pub struct ClaimGate {
    pub policy: ClaimPolicy,
    pub store: Store,
    pub divi: Arc<dyn ChainBackend>,
    pub btc: Arc<dyn ChainBackend>,
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
    run_swap_gated(
        taker, client, sessions, offer_id, btc_sats, opts, pump, None,
    )
    .await
}

/// [`run_swap`] with an optional [`ClaimGate`]. Under a non-`Asap` policy the taker is
/// halted on entering `MakerLockConfirmed` (verified, persisted, not claimed) and released
/// when the policy allows. Prints `claim_secs_before_timeout=<n>` when it releases.
#[allow(clippy::too_many_arguments)]
pub async fn run_swap_gated(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    offer_id: &str,
    btc_sats: u64,
    opts: &RunOpts,
    pump: &mut dyn FnMut(),
    gate: Option<&ClaimGate>,
) -> Result<(String, TakerState)> {
    let mut gate = gate.filter(|g| g.policy != ClaimPolicy::Asap);
    if let Some(g) = gate {
        g.policy.validate()?;
        taker.halt_after(Some(TakerState::MakerLockConfirmed));
    }
    let local = begin(taker, client, sessions, offer_id, btc_sats).await?;
    lock(taker, client, sessions, &local).await?;
    let started = Instant::now();
    let mut held = false;
    loop {
        pump();
        let state = match (gate, held) {
            // Verified and persisted but not claimed: do not step (a step would claim).
            (Some(g), true) if !release(g, &local).await? => TakerState::MakerLockConfirmed,
            (Some(_), true) => {
                taker.halt_after(None);
                gate = None;
                step(taker, client, sessions, &local).await?
            }
            _ => step(taker, client, sessions, &local).await?,
        };
        if state == TakerState::Done {
            return Ok((local, state));
        }
        held = gate.is_some() && state == TakerState::MakerLockConfirmed;
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

/// Whether the gate's policy now allows the claim (or, for `Never`, the claim window
/// has closed so the next step takes the refund path).
async fn release(g: &ClaimGate, local: &str) -> Result<bool> {
    let rec = g
        .store
        .get_taker_swap(local)?
        .ok_or_else(|| anyhow::anyhow!("no taker record {local}"))?;
    let (htlc, chain) = match rec.quote.direction.maker_chain() {
        Chain::Divi => (rec.divi_htlc, &g.divi),
        Chain::Btc => (rec.btc_htlc, &g.btc),
    };
    let locktime = htlc
        .ok_or_else(|| anyhow::anyhow!("MakerLockConfirmed without a maker-leg lock"))?
        .locktime;
    let mtp = chain.median_time_past().await?;
    let open_at = match g.policy {
        ClaimPolicy::Asap => 0,
        ClaimPolicy::NotBefore {
            secs_before_timeout,
        } => locktime.saturating_sub(secs_before_timeout),
        ClaimPolicy::Never => locktime,
    };
    if mtp < open_at {
        return Ok(false);
    }
    println!(
        "claim_secs_before_timeout={} policy={:?}",
        locktime.saturating_sub(mtp),
        g.policy
    );
    Ok(true)
}
