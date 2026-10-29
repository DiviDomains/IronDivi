// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! What the extension's UI may see of a swap.
//!
//! A whitelist: the preimage and raw transactions never leave the engine. A claim's raw
//! transaction would reveal the preimage before it is broadcast.

use divi_swap::store::TakerRecord;
use divi_swap::{Chain, Direction, TakerState};
use serde::Serialize;

const MAX_ERROR: usize = 200;

/// One swap for display.
#[derive(Debug, Clone, Serialize)]
pub struct SwapSummary {
    pub id: String,
    pub state: TakerState,
    pub maker_swap_id: Option<String>,
    pub direction: Direction,
    pub counter_chain: Chain,
    pub btc_amount: u64,
    pub divi_amount: u64,
    pub expires_at: u64,
    /// The chain the taker locks on.
    pub taker_chain: Chain,
    pub taker_lock_txid: Option<String>,
    pub taker_locktime: Option<u32>,
    pub maker_lock_txid: Option<String>,
    pub maker_locktime: Option<u32>,
    pub claim_txid: Option<String>,
    pub refund_txid: Option<String>,
    pub claim_declined: Option<String>,
    pub last_error: Option<String>,
}

impl From<&TakerRecord> for SwapSummary {
    fn from(r: &TakerRecord) -> Self {
        let q = &r.quote;
        SwapSummary {
            id: r.id.clone(),
            state: r.state,
            maker_swap_id: r.maker_swap_id.clone(),
            direction: q.direction,
            counter_chain: q.counter_chain,
            btc_amount: q.btc_amount.to_sat(),
            divi_amount: q.divi_amount.to_sat(),
            expires_at: q.expires_at,
            taker_chain: q.taker_chain(),
            taker_lock_txid: r.taker_leg_funding.as_ref().map(|f| f.tx.txid.to_string()),
            taker_locktime: r.taker_leg_htlc.as_ref().map(|h| h.locktime),
            maker_lock_txid: r.maker_leg_outpoint.as_ref().map(|o| o.txid.to_string()),
            maker_locktime: r.maker_leg_htlc.as_ref().map(|h| h.locktime),
            claim_txid: r.maker_leg_claim.as_ref().map(|t| t.txid.to_string()),
            refund_txid: r.taker_leg_refund.as_ref().map(|t| t.txid.to_string()),
            claim_declined: r.claim_declined.clone(),
            last_error: r
                .last_error
                .as_ref()
                .map(|e| e.chars().take(MAX_ERROR).collect()),
        }
    }
}
