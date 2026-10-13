// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Wire messages of the adaptor swap (the `divi-swapd` `/xmr/...` routes). No secret ever
//! appears here: only public keys, adaptor points, DLEQ proofs, unsigned transactions and
//! signatures. The shared Monero *view* key is exchanged on purpose — it lets both sides see
//! the 2-of-2 output, never spend it (`xmr-design.md` `## Stagenet`).

use divi_primitives::hash::Hash256;
use divi_primitives::transaction::{OutPoint, Transaction};
use serde::{Deserialize, Serialize};
use swap_adaptor::adaptor::{EncryptedSignature, Point};
use swap_adaptor::dleq::{CrossCurveDLEQProof, PointQ};

use crate::maker::XmrMakerState;
use crate::wire;
use divi_swap::api::Quote;
use divi_swap::{Result, SwapError};

/// A DIVI outpoint on the wire (txid as `Hash256::to_hex`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireOutpoint {
    /// Funding transaction id.
    pub txid: String,
    /// Output index.
    pub vout: u32,
}

impl WireOutpoint {
    /// From a DIVI outpoint.
    pub fn of(op: &OutPoint) -> Self {
        WireOutpoint {
            txid: op.txid.to_hex(),
            vout: op.vout,
        }
    }

    /// Back to a DIVI outpoint.
    pub fn outpoint(&self) -> Result<OutPoint> {
        let txid = Hash256::from_hex(&self.txid)
            .map_err(|e| SwapError::InvalidParams(format!("txid: {e}")))?;
        Ok(OutPoint::new(txid, self.vout))
    }
}

/// Step 1, taker → maker (`POST /xmr/swaps`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupRequest {
    /// The quote being accepted (`counter_chain = "xmr"`).
    pub quote_id: String,
    /// `b`: the taker's per-swap key in the DIVI 2-of-2.
    #[serde(with = "wire::b33")]
    pub taker_divi_pubkey: [u8; 33],
    /// Where `Tx_redeem` (and `Tx_punish`) pay the taker.
    #[serde(with = "wire::bytes")]
    pub taker_payout_script: Vec<u8>,
    /// `X = s_t·G` (secp256k1): the maker encrypts his `Tx_redeem` signature under it.
    #[serde(with = "wire::secp_point")]
    pub x_point: Point,
    /// `S_t = s_t·G` (ed25519): the taker's Monero spend-key share.
    #[serde(with = "wire::ed_point")]
    pub taker_xmr_share: PointQ,
    /// Proves `X` and `S_t` share one secret.
    pub taker_proof: CrossCurveDLEQProof,
}

/// Step 2, maker → taker (the reply to `POST /xmr/swaps`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupReply {
    /// The maker's swap id (`/xmr/swaps/:id`).
    pub swap_id: String,
    /// The accepted quote.
    pub quote: Quote,
    /// `a`: the maker's per-swap key in the DIVI 2-of-2.
    #[serde(with = "wire::b33")]
    pub maker_divi_pubkey: [u8; 33],
    /// `Y = s_m·G` (secp256k1): the taker encrypts her `Tx_refund` signature under it.
    #[serde(with = "wire::secp_point")]
    pub y_point: Point,
    /// `S_m = s_m·G` (ed25519): the maker's Monero spend-key share.
    #[serde(with = "wire::ed_point")]
    pub maker_xmr_share: PointQ,
    /// Proves `Y` and `S_m` share one secret.
    pub maker_proof: CrossCurveDLEQProof,
    /// The shared Monero private view key (both must see the 2-of-2 output).
    #[serde(with = "wire::b32")]
    pub xmr_view_secret: [u8; 32],
    /// XMR the taker must lock, piconero.
    pub xmr_amount: u64,
    /// `Tx_lock`'s 2-of-2 output (built and signed by the maker, not yet broadcast).
    pub lock_outpoint: WireOutpoint,
    /// Its value, sats.
    pub lock_amount: u64,
    /// `nLockTime` of `Tx_cancel` and `Tx_refund` (unix seconds, DIVI MTP).
    pub t_cancel: u32,
    /// `nLockTime` of `Tx_punish`.
    pub t_punish: u32,
    /// DIVI fee each presigned transaction pays, sats.
    pub divi_fee_sats: u64,
    /// `Tx_cancel`: lock → a 2-of-2 output; unsigned.
    #[serde(with = "wire::divi_tx")]
    pub tx_cancel: Transaction,
    /// The maker's plain signature on `Tx_cancel`.
    #[serde(with = "wire::bytes")]
    pub maker_cancel_sig: Vec<u8>,
    /// Where `Tx_refund` pays the maker. `Tx_refund` and `Tx_punish` spend the *signed*
    /// `Tx_cancel` — its txid covers both signatures (no segwit on DIVI) — so they are
    /// built by both sides only once the taker has signed `Tx_cancel` ([`after_cancel`]).
    #[serde(with = "wire::bytes")]
    pub maker_refund_script: Vec<u8>,
}

/// `Tx_refund` and `Tx_punish` for a signed `Tx_cancel` (deterministic: both sides build the
/// same bytes): each spends its 2-of-2 output, less one more fee, at `t_cancel` / `t_punish`.
pub fn after_cancel(
    tx_cancel_signed: &Transaction,
    fee: u64,
    maker_refund_script: &[u8],
    taker_payout_script: &[u8],
    t_cancel: u32,
    t_punish: u32,
) -> (Transaction, Transaction) {
    use divi_primitives::script::Script;
    let op = OutPoint::new(tx_cancel_signed.txid(), 0);
    let value = (tx_cancel_signed.vout[0].value.as_sat() as u64).saturating_sub(fee);
    let refund = crate::maker::spend(
        op,
        value,
        Script::from_bytes(maker_refund_script.to_vec()),
        t_cancel,
    );
    let punish = crate::maker::spend(
        op,
        value,
        Script::from_bytes(taker_payout_script.to_vec()),
        t_punish,
    );
    (refund, punish)
}

/// Step 3, taker → maker (`POST /xmr/swaps/:id/sigs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigsRequest {
    /// The taker's plain signature on `Tx_cancel`.
    #[serde(with = "wire::bytes")]
    pub taker_cancel_sig: Vec<u8>,
    /// The taker's `Tx_refund` signature, adaptor-encrypted under `Y`.
    #[serde(with = "wire::enc_sig")]
    pub taker_refund_encsig: EncryptedSignature,
}

/// Step 4, taker → maker (`POST /xmr/swaps/:id/xmr-lock`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmrLockNotice {
    /// The taker's Monero lock transaction id.
    pub xmr_txid: String,
}

/// Step 5, in the maker's view once the taker's XMR lock is confirmed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemOffer {
    /// `Tx_redeem`: lock → the taker; unsigned.
    #[serde(with = "wire::divi_tx")]
    pub tx_redeem: Transaction,
    /// The maker's `Tx_redeem` signature, adaptor-encrypted under `X`.
    #[serde(with = "wire::enc_sig")]
    pub maker_redeem_encsig: EncryptedSignature,
}

/// `GET /xmr/swaps/:id` — what either party may see. Never contains a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmrSwapView {
    /// Swap id.
    pub id: String,
    /// Maker-side state.
    pub state: XmrMakerState,
    /// The quote.
    pub quote: Quote,
    /// `Tx_lock` txid, once built.
    pub lock_txid: Option<String>,
    /// The taker's reported XMR lock.
    pub xmr_lock_txid: Option<String>,
    /// Present once the maker has seen the XMR lock confirmed (and `t_cancel` is not near).
    pub redeem: Option<RedeemOffer>,
    /// `Tx_cancel` txid, once broadcast.
    pub cancel_txid: Option<String>,
    /// `Tx_refund` txid, once broadcast.
    pub refund_txid: Option<String>,
    /// The maker's plain signature on `Tx_punish` (hex), present from `locked` on: the taker
    /// verifies and keeps it before she locks any XMR.
    pub maker_punish_sig: Option<String>,
    /// Last error the maker hit on this swap.
    pub last_error: Option<String>,
}
