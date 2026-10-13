// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The taker side of the adaptor swap (holds XMR, buys DIVI), used by the `divi-swap` CLI.
//!
//! ```text
//! Prepared → Accepted → XmrLocking → XmrLocked → Redeemed → Done (outcome "redeemed")
//!   (Accepted / XmrLocking / XmrLocked, past t_cancel) → Cancelled →
//!       { Recovering → Done ("refunded": s_m from Tx_refund, XMR swept back)
//!       | Punishing → Done ("punished": Tx_punish took the DIVI)
//!       | Done ("cancelled": nothing of ours was locked) }
//! ```
//!
//! Nothing is trusted from the maker's messages that the chain can check: `Tx_lock` must be
//! on chain with the right script and amount before XMR moves, every template is checked
//! against what it must spend and pay, and every signature the maker hands over is verified
//! before it is relied on.

use std::str::FromStr;
use std::sync::Arc;

use divi_crypto::keys::SecretKey;

use divi_primitives::transaction::{OutPoint, Transaction};
use divi_swap::api::Quote;
use divi_swap::htlc::REFUND_SEQUENCE;
use divi_swap::{Chain, Result, Store, SwapError};
use serde::{Deserialize, Serialize};
use swap_adaptor::adaptor::{AdaptorSigner, EncryptedSignature};
use swap_adaptor::dleq::{random_clamped_secret, ScalarQ};
use swap_chain_xmr::swap_templates::{taker_completes_tx_redeem, taker_encrypts_tx_refund};

use crate::api::{RedeemOffer, SetupReply, SetupRequest, SigsRequest, XmrLockNotice, XmrSwapView};
use crate::chain::{DiviChain, MoneroChain};
use crate::crypto::{self, Signer};
use crate::{nums, wire, XmrConfig, PICONERO_PER_COUNTER_SAT};

/// Store document kind of taker records.
pub const KIND: &str = "xmr_taker";

/// Taker-side state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XmrTakerState {
    /// Secrets generated and persisted; setup request built.
    Prepared,
    /// The maker's setup verified; our signatures built.
    Accepted,
    /// `Tx_lock` confirmed; about to lock XMR (persisted first: locking is not idempotent).
    XmrLocking,
    /// XMR locked.
    XmrLocked,
    /// `Tx_redeem` completed and persisted (broadcast follows): the DIVI is ours.
    Redeemed,
    /// `Tx_cancel` is out.
    Cancelled,
    /// `s_m` recovered from the maker's `Tx_refund`; sweeping our XMR back.
    Recovering,
    /// `Tx_punish` persisted (broadcast follows).
    Punishing,
    /// Finished; see the record's `outcome`.
    Done,
}

/// The taker's persisted view of one swap (holds `b` and `s_t`; store mode 0600).
#[derive(Clone, Serialize, Deserialize)]
pub struct XmrTakerRecord {
    /// Local id.
    pub id: String,
    /// Current state.
    pub state: XmrTakerState,
    /// The quote.
    pub quote: Quote,
    /// `b`: per-swap DIVI multisig key.
    #[serde(with = "wire::divi_secret")]
    pub divi_key: SecretKey,
    /// `s_t`: Monero spend-key share and `Tx_redeem` adaptor secret.
    #[serde(with = "wire::ed_scalar")]
    pub s_t: ScalarQ,
    /// Where the DIVI is paid.
    #[serde(with = "wire::bytes")]
    pub payout_script: Vec<u8>,
    /// The maker's verified setup reply.
    pub setup: Option<SetupReply>,
    /// Our `Tx_cancel` signature.
    pub cancel_sig: Option<String>,
    /// Our encrypted `Tx_refund` signature.
    pub refund_encsig: Option<String>,
    /// `Tx_punish` (unsigned), built over the signed `Tx_cancel`.
    #[serde(with = "wire::opt_divi_tx")]
    pub tx_punish: Option<Transaction>,
    /// The maker's verified `Tx_punish` signature (hex); required before we lock XMR.
    pub maker_punish_sig: Option<String>,
    /// Our XMR lock.
    pub xmr_txid: Option<String>,
    /// `Tx_redeem`, completed (persisted before broadcast).
    #[serde(with = "wire::opt_divi_tx")]
    pub redeem_signed: Option<Transaction>,
    /// `Tx_punish`, signed (persisted before broadcast).
    #[serde(with = "wire::opt_divi_tx")]
    pub punish_signed: Option<Transaction>,
    /// `s_m`, recovered from `Tx_refund` (hex scalar).
    pub s_m: Option<String>,
    /// Our sweep of the XMR back.
    pub sweep_txid: Option<String>,
    /// How it ended: `redeemed`, `refunded`, `punished`, `cancelled`.
    pub outcome: Option<String>,
    /// Last error.
    pub last_error: Option<String>,
}

impl XmrTakerRecord {
    fn setup(&self) -> Result<&SetupReply> {
        self.setup
            .as_ref()
            .ok_or_else(|| SwapError::Other("no verified setup".into()))
    }

    fn taker_pk(&self) -> [u8; 33] {
        self.divi_key.public_key().serialize_compressed()
    }

    fn redeem_script(&self) -> Result<Vec<u8>> {
        Ok(crypto::multisig_script(&self.setup()?.maker_divi_pubkey, &self.taker_pk()).0)
    }

    fn shared_spend_key(&self) -> Result<[u8; 32]> {
        Ok(crypto::shared_spend_key(
            &self.setup()?.maker_xmr_share,
            &crypto::ed_pub(&self.s_t),
        ))
    }

    fn punish_signed(&self) -> Result<Transaction> {
        let (Some(tx), Some(maker)) = (&self.tx_punish, &self.maker_punish_sig) else {
            return Err(SwapError::Other("no Tx_punish signature".into()));
        };
        let maker = hex::decode(maker).map_err(|e| SwapError::Other(format!("punish sig: {e}")))?;
        let redeem = self.redeem_script()?;
        let mine = crypto::sign_plain(tx, &redeem, &self.divi_key)?;
        Ok(crypto::assemble(tx.clone(), &redeem, &maker, &mine))
    }

    fn cancel_signed(&self) -> Result<Transaction> {
        let s = self.setup()?;
        let mine = hex::decode(self.cancel_sig.as_deref().unwrap_or_default())
            .map_err(|e| SwapError::Other(format!("stored cancel sig: {e}")))?;
        Ok(crypto::assemble(
            s.tx_cancel.clone(),
            &self.redeem_script()?,
            &s.maker_cancel_sig,
            &mine,
        ))
    }
}

enum Flow {
    Idle,
    Moved,
}

/// Taker engine for `counter_chain = "xmr"` quotes.
pub struct XmrTaker {
    cfg: XmrConfig,
    divi: Arc<dyn DiviChain>,
    xmr: Arc<dyn MoneroChain>,
    store: Store,
    gate: tokio::sync::Mutex<()>,
}

impl XmrTaker {
    /// New taker engine: `divi` receives the DIVI, `xmr` pays the XMR.
    pub fn new(
        cfg: XmrConfig,
        divi: Arc<dyn DiviChain>,
        xmr: Arc<dyn MoneroChain>,
        store: Store,
    ) -> Result<Self> {
        cfg.validate()?;
        Ok(XmrTaker {
            cfg,
            divi,
            xmr,
            store,
            gate: tokio::sync::Mutex::new(()),
        })
    }

    /// Step 1: generate and persist `b` and `s_t`; returns the local id and the request to
    /// `POST /xmr/swaps`.
    pub async fn prepare(&self, quote: &Quote) -> Result<(String, SetupRequest)> {
        if quote.counter_chain != Chain::Xmr {
            return Err(SwapError::InvalidParams("not an xmr quote".into()));
        }
        let (divi_key, s_t, proof, x_point, share) = {
            let mut rng = rand::thread_rng();
            let s_t = random_clamped_secret(&mut rng);
            let (proof, (x, share)) = nums::dleq().prove(&s_t, &mut rng);
            (SecretKey::new_random(), s_t, proof, x, share)
        };
        let payout = self.divi.payout_script();
        let rec = XmrTakerRecord {
            id: uuid::Uuid::new_v4().to_string(),
            state: XmrTakerState::Prepared,
            quote: quote.clone(),
            divi_key,
            s_t,
            payout_script: payout.as_bytes().to_vec(),
            setup: None,
            cancel_sig: None,
            refund_encsig: None,
            tx_punish: None,
            maker_punish_sig: None,
            xmr_txid: None,
            redeem_signed: None,
            punish_signed: None,
            s_m: None,
            sweep_txid: None,
            outcome: None,
            last_error: None,
        };
        self.store.put_doc(KIND, &rec.id, &rec)?;
        Ok((
            rec.id.clone(),
            SetupRequest {
                quote_id: quote.id.clone(),
                taker_divi_pubkey: rec.taker_pk(),
                taker_payout_script: rec.payout_script.clone(),
                x_point,
                taker_xmr_share: share,
                taker_proof: proof,
            },
        ))
    }

    /// Step 2 → 3: verify the maker's setup in full, then sign `Tx_cancel` and encrypt-sign
    /// `Tx_refund`. Returns the request to `POST /xmr/swaps/:id/sigs`.
    pub async fn accepted(&self, local_id: &str, reply: SetupReply) -> Result<SigsRequest> {
        let _g = self.gate.lock().await;
        let mut r = self.load(local_id)?;
        if r.state != XmrTakerState::Prepared {
            return Err(SwapError::InvalidParams(format!(
                "swap is {:?}, not awaiting the maker's setup",
                r.state
            )));
        }
        let bad = |what: &str| SwapError::InvalidParams(format!("maker's setup: {what}"));
        let q = &reply.quote;
        if q.id != r.quote.id
            || q.btc_amount != r.quote.btc_amount
            || q.divi_amount != r.quote.divi_amount
            || q.counter_chain != Chain::Xmr
        {
            return Err(bad("reply is for a different quote"));
        }
        if !nums::dleq().verify(&reply.maker_proof, (reply.y_point, reply.maker_xmr_share)) {
            return Err(bad("DLEQ proof does not bind Y to S_m"));
        }
        if reply.xmr_amount != r.quote.btc_amount.0 * PICONERO_PER_COUNTER_SAT {
            return Err(bad("XMR amount does not match the quote"));
        }
        let maker_pk = reply.maker_divi_pubkey;
        crypto::point_of_pubkey(&maker_pk)?;
        let (redeem, spk) = crypto::multisig_script(&maker_pk, &r.taker_pk());
        let lock_op = reply.lock_outpoint.outpoint()?;
        let tx_cancel = &reply.tx_cancel;
        if reply.lock_amount < r.quote.divi_amount.0 + self.cfg.divi_fee_sats
            || reply.divi_fee_sats > self.cfg.divi_fee_sats
        {
            return Err(bad("Tx_lock holds less than the quote plus the redeem fee"));
        }
        if tx_cancel.vin.len() != 1
            || tx_cancel.vout.len() != 1
            || tx_cancel.vin[0].prevout != lock_op
            || tx_cancel.vin[0].sequence != REFUND_SEQUENCE
            || tx_cancel.lock_time != reply.t_cancel
            || tx_cancel.vout[0].script_pubkey != spk
        {
            return Err(bad(
                "Tx_cancel does not move Tx_lock to the 2-of-2 at t_cancel",
            ));
        }
        let mtp = self.divi.median_time_past().await?;
        if reply.t_cancel < mtp + 2 * self.cfg.redeem_margin_secs
            || reply.t_punish < reply.t_cancel + self.cfg.redeem_margin_secs
        {
            return Err(bad("timelocks leave no room to redeem or to punish"));
        }
        if !crypto::verify_plain(tx_cancel, &redeem, &maker_pk, &reply.maker_cancel_sig) {
            return Err(bad("signature on Tx_cancel is invalid"));
        }

        let cancel_sig = crypto::sign_plain(tx_cancel, &redeem, &r.divi_key)?;
        let cancel_signed = crypto::assemble(
            tx_cancel.clone(),
            &redeem,
            &reply.maker_cancel_sig,
            &cancel_sig,
        );
        let (refund, punish) = crate::api::after_cancel(
            &cancel_signed,
            reply.divi_fee_sats,
            &reply.maker_refund_script,
            &r.payout_script,
            reply.t_cancel,
            reply.t_punish,
        );
        let (built, encsig) = taker_encrypts_tx_refund(
            OutPoint::new(cancel_signed.txid(), 0),
            &redeem,
            &r.divi_key,
            &reply.y_point,
            refund.vout[0].clone(),
            refund.lock_time,
            refund.vin[0].sequence,
        )
        .map_err(|e| SwapError::Other(format!("Tx_refund: {e}")))?;
        if built.txid() != refund.txid() {
            return Err(SwapError::Other("rebuilt Tx_refund differs".into()));
        }
        r.tx_punish = Some(punish);
        r.cancel_sig = Some(hex::encode(&cancel_sig));
        r.refund_encsig = Some(encsig.to_string());
        r.setup = Some(reply);
        self.enter(&mut r, XmrTakerState::Accepted)?;
        Ok(SigsRequest {
            taker_cancel_sig: cancel_sig,
            taker_refund_encsig: encsig,
        })
    }

    /// The maker's swap id for `local_id` (from the verified setup).
    pub fn maker_swap_id(&self, local_id: &str) -> Result<String> {
        Ok(self.load(local_id)?.setup()?.swap_id.clone())
    }

    /// The notice to `POST /xmr/swaps/:id/xmr-lock`, once our XMR lock exists.
    pub fn lock_notice(&self, local_id: &str) -> Result<Option<XmrLockNotice>> {
        Ok(self
            .load(local_id)?
            .xmr_txid
            .map(|xmr_txid| XmrLockNotice { xmr_txid }))
    }

    /// The record (tests, status).
    pub fn record(&self, local_id: &str) -> Result<Option<XmrTakerRecord>> {
        self.store.get_doc(KIND, local_id)
    }

    /// Advance using the maker's latest view (`None` if unreachable). Idempotent.
    pub async fn step(&self, local_id: &str, maker: Option<&XmrSwapView>) -> Result<XmrTakerState> {
        let _g = self.gate.lock().await;
        let mut r = self.load(local_id)?;
        if r.state == XmrTakerState::Done {
            return Ok(r.state);
        }
        let had_error = r.last_error.take().is_some();
        for _ in 0..16 {
            match self.advance(&mut r, maker).await {
                Ok(Flow::Moved) => {}
                Ok(Flow::Idle) => break,
                Err(e) => {
                    r.last_error = Some(e.to_string());
                    self.store.put_doc(KIND, &r.id, &r)?;
                    return Err(e);
                }
            }
        }
        if had_error && r.last_error.is_none() {
            self.store.put_doc(KIND, &r.id, &r)?;
        }
        Ok(r.state)
    }

    fn load(&self, id: &str) -> Result<XmrTakerRecord> {
        self.store
            .get_doc(KIND, id)?
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown xmr swap {id:?}")))
    }

    fn enter(&self, r: &mut XmrTakerRecord, next: XmrTakerState) -> Result<Flow> {
        tracing::info!(swap = %r.id, from = ?r.state, to = ?next, "xmr taker");
        r.state = next;
        self.store.put_doc(KIND, &r.id, r)?;
        Ok(Flow::Moved)
    }

    fn finish(&self, r: &mut XmrTakerRecord, outcome: &str) -> Result<Flow> {
        r.outcome = Some(outcome.into());
        self.enter(r, XmrTakerState::Done)
    }

    async fn advance(&self, r: &mut XmrTakerRecord, maker: Option<&XmrSwapView>) -> Result<Flow> {
        use XmrTakerState::*;
        match r.state {
            Prepared | Done => Ok(Flow::Idle),
            Accepted => self.on_accepted(r, maker).await,
            XmrLocking => {
                let spend_pub = r.shared_spend_key()?;
                let view = r.setup()?.xmr_view_secret;
                // Recover a crash between locking and persisting: the lock may already exist.
                let txid = match self.xmr.find_lock(&spend_pub, &view).await? {
                    Some(o) => o.txid,
                    None => {
                        self.xmr
                            .lock(&spend_pub, &view, r.setup()?.xmr_amount)
                            .await?
                    }
                };
                r.xmr_txid = Some(txid);
                self.enter(r, XmrLocked)
            }
            XmrLocked => self.on_xmr_locked(r, maker).await,
            Redeemed => {
                let tx = r
                    .redeem_signed
                    .clone()
                    .ok_or_else(|| SwapError::Other("Redeemed without Tx_redeem".into()))?;
                match self.divi.broadcast(&tx).await {
                    Ok(()) => {}
                    // Tx_cancel won the race: fall back to the refund path.
                    Err(SwapError::Rejected(_)) => return self.enter(r, Cancelled),
                    Err(e) => return Err(e),
                }
                if self.divi.confirmations(&tx.txid()).await?.unwrap_or(0) >= 1 {
                    return self.finish(r, "redeemed");
                }
                Ok(Flow::Idle)
            }
            Cancelled => self.on_cancelled(r).await,
            Recovering => self.on_recovering(r).await,
            Punishing => {
                let tx = r
                    .punish_signed
                    .clone()
                    .ok_or_else(|| SwapError::Other("Punishing without Tx_punish".into()))?;
                match self.divi.broadcast(&tx).await {
                    Ok(()) => {}
                    Err(SwapError::Premature(_)) => return Ok(Flow::Idle),
                    // The maker's Tx_refund got there first: recover s_m instead.
                    Err(SwapError::Rejected(_)) => return self.enter(r, Cancelled),
                    Err(e) => return Err(e),
                }
                if self.divi.confirmations(&tx.txid()).await?.unwrap_or(0) >= 1 {
                    return self.finish(r, "punished");
                }
                Ok(Flow::Idle)
            }
        }
    }

    /// Past `t_cancel`: put `Tx_cancel` out (either side may) and go to the abort path.
    async fn cancel_if_due(&self, r: &mut XmrTakerRecord) -> Result<Option<Flow>> {
        let s = r.setup()?;
        let lock_op = s.lock_outpoint.outpoint()?;
        let t_cancel = s.t_cancel;
        let tx = r.cancel_signed()?;
        if let Some(spender) = self.divi.find_spend(&lock_op).await? {
            if spender.txid() == tx.txid() {
                return self.enter(r, XmrTakerState::Cancelled).map(Some);
            }
        }
        if self.divi.median_time_past().await? <= t_cancel {
            return Ok(None);
        }
        match self.divi.broadcast(&tx).await {
            Ok(()) => self.enter(r, XmrTakerState::Cancelled).map(Some),
            Err(SwapError::Premature(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Wait for `Tx_lock` (right script, right amount, confirmed); then lock XMR.
    async fn on_accepted(
        &self,
        r: &mut XmrTakerRecord,
        maker: Option<&XmrSwapView>,
    ) -> Result<Flow> {
        if let Some(f) = self.cancel_if_due(r).await? {
            return Ok(f);
        }
        if r.maker_punish_sig.is_none() {
            // Without the maker's Tx_punish signature we never lock XMR.
            let Some(sig) = maker.and_then(|m| m.maker_punish_sig.clone()) else {
                return Ok(Flow::Idle);
            };
            let bytes =
                hex::decode(&sig).map_err(|e| SwapError::Other(format!("punish sig: {e}")))?;
            let tx = r
                .tx_punish
                .clone()
                .ok_or_else(|| SwapError::Other("no Tx_punish".into()))?;
            if !crypto::verify_plain(
                &tx,
                &r.redeem_script()?,
                &r.setup()?.maker_divi_pubkey,
                &bytes,
            ) {
                return Err(SwapError::Other(
                    "maker's Tx_punish signature is invalid".into(),
                ));
            }
            r.maker_punish_sig = Some(sig);
            self.store.put_doc(KIND, &r.id, r)?;
        }
        let s = r.setup()?;
        let (_, spk) = crypto::multisig_script(&s.maker_divi_pubkey, &r.taker_pk());
        let Some((out, confs)) = self.divi.output(&s.lock_outpoint.outpoint()?).await? else {
            return Ok(Flow::Idle);
        };
        if out.script_pubkey != spk || out.value.as_sat() as u64 != s.lock_amount {
            return Err(SwapError::Other(
                "Tx_lock does not pay the agreed 2-of-2 amount".into(),
            ));
        }
        if confs < self.cfg.divi_confirmations {
            return Ok(Flow::Idle);
        }
        // Locking XMR needs time left to see it confirm and redeem before t_cancel.
        let mtp = self.divi.median_time_past().await?;
        if mtp + 2 * self.cfg.redeem_margin_secs >= s.t_cancel {
            return Ok(Flow::Idle);
        }
        self.enter(r, XmrTakerState::XmrLocking)
    }

    /// XMR is locked: redeem once the maker's encrypted signature is there and checks out.
    async fn on_xmr_locked(
        &self,
        r: &mut XmrTakerRecord,
        maker: Option<&XmrSwapView>,
    ) -> Result<Flow> {
        if let Some(f) = self.cancel_if_due(r).await? {
            return Ok(f);
        }
        let Some(offer) = maker.and_then(|m| m.redeem.as_ref()) else {
            return Ok(Flow::Idle);
        };
        let mtp = self.divi.median_time_past().await?;
        let s = r.setup()?;
        if mtp + self.cfg.redeem_margin_secs >= s.t_cancel {
            return Ok(Flow::Idle); // too close to t_cancel: let the abort path run
        }
        let tx = self.check_redeem_offer(r, offer)?;
        let completed = taker_completes_tx_redeem(
            tx,
            &r.redeem_script()?,
            &crypto::point_of_pubkey(&s.maker_divi_pubkey)?,
            offer.maker_redeem_encsig.clone(),
            &r.divi_key,
            &crypto::secp_of(&r.s_t),
        )
        .map_err(|e| SwapError::Other(format!("Tx_redeem: {e}")))?;
        r.redeem_signed = Some(completed);
        self.enter(r, XmrTakerState::Redeemed) // persisted before broadcast
    }

    fn check_redeem_offer(&self, r: &XmrTakerRecord, offer: &RedeemOffer) -> Result<Transaction> {
        let s = r.setup()?;
        let bad = |what: &str| SwapError::Other(format!("maker's redeem offer: {what}"));
        let tx = &offer.tx_redeem;
        if tx.vin.len() != 1
            || tx.vout.len() != 1
            || tx.vin[0].prevout != s.lock_outpoint.outpoint()?
            || tx.lock_time != 0
        {
            return Err(bad("Tx_redeem does not spend Tx_lock unconditionally"));
        }
        if tx.vout[0].script_pubkey.as_bytes() != r.payout_script.as_slice()
            || (tx.vout[0].value.as_sat() as u64) < r.quote.divi_amount.0
        {
            return Err(bad("Tx_redeem does not pay us the quoted DIVI"));
        }
        let x_point = AdaptorSigner::new().encryption_key_for(&crypto::secp_of(&r.s_t));
        if !crypto::verify_encrypted(
            tx,
            &r.redeem_script()?,
            &s.maker_divi_pubkey,
            &x_point,
            &offer.maker_redeem_encsig,
        ) {
            return Err(bad("encrypted Tx_redeem signature is invalid"));
        }
        Ok(tx.clone())
    }

    /// `Tx_cancel` is out: the maker's `Tx_refund` hands us `s_m`; past `t_punish` we punish.
    async fn on_cancelled(&self, r: &mut XmrTakerRecord) -> Result<Flow> {
        let tx_cancel = r.cancel_signed()?;
        self.divi.broadcast(&tx_cancel).await?; // idempotent
        let cancel_op = OutPoint::new(tx_cancel.txid(), 0);
        let s = r.setup()?.clone();
        if let Some(spender) = self.divi.find_spend(&cancel_op).await? {
            if r.punish_signed
                .as_ref()
                .is_some_and(|p| p.txid() == spender.txid())
            {
                return self.finish(r, "punished");
            }
            if r.xmr_txid.is_none() {
                return self.finish(r, "cancelled"); // nothing of ours to recover
            }
            let encsig = r
                .refund_encsig
                .as_deref()
                .and_then(|e| EncryptedSignature::from_str(e).ok())
                .ok_or_else(|| SwapError::Other("no refund encsig".into()))?;
            let s_m = crypto::recover(&spender, Signer::Taker, &s.y_point, &encsig)
                .filter(|m| crypto::ed_pub(m) == s.maker_xmr_share)
                .ok_or_else(|| SwapError::Other("could not recover s_m from Tx_refund".into()))?;
            r.s_m = Some(hex::encode(s_m.to_bytes()));
            return self.enter(r, XmrTakerState::Recovering);
        }
        if self.divi.median_time_past().await? > s.t_punish && r.maker_punish_sig.is_some() {
            r.punish_signed = Some(r.punish_signed()?);
            return self.enter(r, XmrTakerState::Punishing);
        }
        Ok(Flow::Idle)
    }

    async fn on_recovering(&self, r: &mut XmrTakerRecord) -> Result<Flow> {
        let s_m = r
            .s_m
            .as_deref()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(ScalarQ::from_canonical_bytes)
            .ok_or_else(|| SwapError::Other("Recovering without s_m".into()))?;
        let view = r.setup()?.xmr_view_secret;
        let spend_pub = r.shared_spend_key()?;
        let txid = match r.sweep_txid.clone() {
            Some(t) => t,
            None => {
                let lock = self
                    .xmr
                    .find_lock(&spend_pub, &view)
                    .await?
                    .ok_or_else(|| SwapError::Other("our XMR lock vanished".into()))?;
                let full = (r.s_t + s_m).to_bytes();
                match self.xmr.sweep(&lock, &full, &view).await {
                    Ok(t) => {
                        r.sweep_txid = Some(t.clone());
                        self.store.put_doc(KIND, &r.id, r)?;
                        t
                    }
                    Err(SwapError::Premature(_)) => return Ok(Flow::Idle),
                    Err(e) => return Err(e),
                }
            }
        };
        if self.xmr.confirmations(&txid).await?.unwrap_or(0) >= 1 {
            return self.finish(r, "refunded");
        }
        Ok(Flow::Idle)
    }
}
