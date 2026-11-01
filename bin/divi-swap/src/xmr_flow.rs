// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The taker flow for `counter_chain = "xmr"` offers (the adaptor-signature swap,
//! `divi_swap_xmr`): the same shape as [`crate::flow`] for the hashlock coins, over the
//! maker's `/xmr/swaps` routes.

use std::time::Instant;

use anyhow::{bail, Result};
use divi_swap_xmr::taker::JNext;
use divi_swap_xmr::{XmrTaker, XmrTakerState};

use crate::flow::RunOpts;
use crate::session::{Session, Sessions};
use crate::MakerClient;

/// Upper bound on `POST /xmr/swaps/:id/j` exchanges (keying and signing take about ten).
const MAX_J_EXCHANGES: usize = 64;

/// Wait for the maker's DIVI wallet scan ([`MakerClient::wait_ready`]) → fresh quote →
/// prepare → `POST /xmr/swaps` → the 2P-ECDSA exchanges of `J` (`POST /xmr/swaps/:id/j`;
/// our side verifies the maker's setup before signing `Tx_cancel`) → send our signatures (the
/// maker then broadcasts `Tx_lock`). Returns the local id.
pub async fn begin(
    taker: &XmrTaker,
    client: &MakerClient,
    sessions: &Sessions,
    offer_id: &str,
    btc_sats: u64,
) -> Result<String> {
    client.wait_ready().await?;
    taker.warm_primes().await?;
    let quote = client.quote_retrying(offer_id, btc_sats).await?;
    if quote.counter_chain != divi_swap::Chain::Xmr {
        bail!(
            "offer {offer_id} swaps DIVI against {}; this is the xmr flow",
            quote.counter_chain
        );
    }
    let (local, req) = taker.prepare(&quote).await?;
    let reply = client.xmr_setup(&req).await?;
    sessions.put(
        &local,
        Session {
            maker_url: client.base().to_string(),
            maker_swap_id: reply.swap_id.clone(),
        },
    )?;
    let id = reply.swap_id.clone();
    let mut reply = reply;
    let mut exchanges = 0;
    let sigs = loop {
        match taker.j_step(&local, reply).await? {
            JNext::Sigs(sigs) => break sigs,
            JNext::Send(req) => {
                exchanges += 1;
                if exchanges > MAX_J_EXCHANGES {
                    bail!("2P-ECDSA with the maker did not finish in {MAX_J_EXCHANGES} exchanges");
                }
                reply = client.xmr_j(&id, &req).await?;
            }
        }
    };
    tracing::info!(swap = %local, exchanges, "joint cancel key J made and Tx_cancel signed");
    client.xmr_sigs(&id, &sigs).await?;
    Ok(local)
}

/// One taker step against the maker's latest view (`None` if unreachable); reports our XMR
/// lock to the maker once it exists.
pub async fn step(
    taker: &XmrTaker,
    client: &MakerClient,
    sessions: &Sessions,
    local: &str,
) -> Result<XmrTakerState> {
    let id = sessions.get(local)?.maker_swap_id;
    let view = match client.xmr_swap(&id).await {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, "maker unreachable; stepping without its view");
            None
        }
    };
    let state = taker.step(local, view.as_ref()).await?;
    if let Some(notice) = taker.lock_notice(local)? {
        if view.as_ref().is_some_and(|v| v.xmr_lock_txid.is_none()) {
            client.xmr_lock(&id, &notice).await?;
        }
    }
    Ok(state)
}

/// [`begin`], then [`step`] until `Done`. `pump` runs once per poll (tests mine blocks with
/// it). Returns the local id and how the swap ended (`redeemed`, `refunded`, `punished`,
/// `cancelled`).
pub async fn run(
    taker: &XmrTaker,
    client: &MakerClient,
    sessions: &Sessions,
    offer_id: &str,
    btc_sats: u64,
    opts: &RunOpts,
    pump: &mut dyn FnMut(),
) -> Result<(String, String)> {
    let local = begin(taker, client, sessions, offer_id, btc_sats).await?;
    let started = Instant::now();
    loop {
        pump();
        let state = match step(taker, client, sessions, &local).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "xmr taker step failed; retrying");
                XmrTakerState::Prepared
            }
        };
        if state == XmrTakerState::Done {
            let outcome = taker
                .record(&local)?
                .and_then(|r| r.outcome)
                .unwrap_or_default();
            return Ok((local, outcome));
        }
        if started.elapsed() > opts.timeout {
            bail!("timed out; xmr swap {local} left in place — rerun `claim` to keep stepping it");
        }
        tokio::time::sleep(opts.poll).await;
    }
}
