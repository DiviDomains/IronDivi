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
//! Prepared (keying J) → Accepted → XmrLocking → XmrLocked → Redeemed → Done (outcome "redeemed")
//!   (Accepted / XmrLocked, past t_cancel) → Cancelled →
//!       { Recovering → Done ("refunded": s_m from Tx_refund, XMR swept back)
//!       | Punishing → Done ("punished": Tx_punish took the DIVI)
//!       | Done ("cancelled": nothing of ours was locked) }
//! ```
//!
//! Nothing is trusted from the maker's messages that the chain can check: `Tx_lock` must be
//! on chain with the right script and amount before XMR moves, every template is checked
//! against what it must spend and pay, and every signature the maker hands over is verified
//! before it is relied on.
//!
//! C1: `Tx_cancel` is signed once by the 2P-ECDSA joint key `J` ([`crate::jsig`]) during
//! setup, so the maker can never sign a second spend of the lock's cancel branch. `Tx_punish`
//! is the taker's alone (its branch of [`CancelScript`]), so she needs nothing from the maker
//! to punish. Her encrypted `Tx_refund` signature is given for every encoding of `Tx_cancel`
//! ([`lock_scripts::cancel_variants`]).

use std::collections::{BTreeMap, HashMap};
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
use swap_chain_xmr::lock_scripts::{self, CancelScript, LockScript, LockSpend, CANCEL_VARIANTS};
use swap_chain_xmr::swap_templates::{taker_completes_tx_redeem, taker_encrypts_tx_refund};

use crate::api::{
    JRoundReply, JRoundRequest, RedeemOffer, RefundEncsig, SetupReply, SetupRequest, SigsRequest,
    XmrLockNotice, XmrSwapView,
};
use crate::chain::{DiviChain, MoneroChain};
use crate::crypto::{self, Signer};
use crate::jsig::{self, JSession, JStatus, Primes, TAKER};
use crate::maker::PrimesFn;
use crate::{nums, wire, XmrConfig, PICONERO_PER_COUNTER_SAT};

/// Store document kind of taker records. New with C1: pre-C1 records (`xmr_taker`) have a
/// different shape and are left alone.
pub const KIND: &str = "xmr_taker_c1";

/// Taker-side state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XmrTakerState {
    /// Secrets generated and persisted; keying `J` with the maker (in memory).
    Prepared,
    /// The maker's setup verified, `σ_J` and our encrypted refunds built.
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

/// The taker's persisted view of one swap (holds `b` and `s_t`; store mode 0600). Never
/// holds the `J` share.
#[derive(Clone, Serialize, Deserialize)]
pub struct XmrTakerRecord {
    /// Local id.
    pub id: String,
    /// Current state.
    pub state: XmrTakerState,
    /// The quote.
    pub quote: Quote,
    /// `b`: per-swap DIVI key.
    #[serde(with = "wire::divi_secret")]
    pub divi_key: SecretKey,
    /// `s_t`: Monero spend-key share and `Tx_redeem` adaptor secret.
    #[serde(with = "wire::ed_scalar")]
    pub s_t: ScalarQ,
    /// Where the DIVI is paid.
    #[serde(with = "wire::bytes")]
    pub payout_script: Vec<u8>,
    /// The 2P-ECDSA session id.
    #[serde(with = "wire::b32")]
    pub j_sid: [u8; 32],
    /// The maker's verified setup reply.
    pub setup: Option<SetupReply>,
    /// `σ_J` on `Tx_cancel` (hex).
    pub cancel_sig: Option<String>,
    /// Our encrypted `Tx_refund` signatures, by the txid of the `Tx_cancel` encoding.
    pub refund_encsigs: BTreeMap<String, String>,
    /// The encoding of `Tx_cancel` seen spending `Tx_lock`.
    #[serde(with = "wire::opt_divi_tx")]
    pub cancel_actual: Option<Transaction>,
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

    fn lock_script(&self) -> Result<LockScript> {
        let s = self.setup()?;
        Ok(LockScript {
            maker: s.maker_divi_pubkey,
            taker: self.taker_pk(),
            joint: s.joint_pubkey,
            t_cancel: s.t_cancel,
            t_late: s.t_late,
        })
    }

    fn redeem_script(&self) -> Result<Vec<u8>> {
        Ok(self.lock_script()?.redeem_script())
    }

    fn cancel_redeem(&self) -> Result<Vec<u8>> {
        let s = self.setup()?;
        Ok(CancelScript {
            maker: s.maker_divi_pubkey,
            taker: self.taker_pk(),
            t_punish: s.t_punish,
        }
        .redeem_script())
    }

    fn shared_spend_key(&self) -> Result<[u8; 32]> {
        Ok(crypto::shared_spend_key(
            &self.setup()?.maker_xmr_share,
            &crypto::ed_pub(&self.s_t),
        ))
    }

    fn sigma(&self) -> Result<Vec<u8>> {
        hex::decode(self.cancel_sig.as_deref().unwrap_or_default())
            .map_err(|e| SwapError::Other(format!("stored cancel sig: {e}")))
    }

    /// `Tx_cancel` with `σ_J`, canonically encoded.
    fn cancel_signed(&self) -> Result<Transaction> {
        let mut tx = self.setup()?.tx_cancel.clone();
        tx.vin[0].script_sig = lock_scripts::cancel_sig(&self.sigma()?, &self.redeem_script()?);
        Ok(tx)
    }

    /// The `Tx_cancel` the refund / punish spend: the one seen, else ours.
    fn cancel_tx(&self) -> Result<Transaction> {
        match &self.cancel_actual {
            Some(t) => Ok(t.clone()),
            None => self.cancel_signed(),
        }
    }

    fn sigs_request(&self) -> Result<SigsRequest> {
        let refund_encsigs = self
            .refund_encsigs
            .iter()
            .map(|(txid, e)| {
                Ok(RefundEncsig {
                    cancel_txid: txid.clone(),
                    encsig: EncryptedSignature::from_str(e)
                        .map_err(|_| SwapError::Other("stored refund encsig".into()))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(SigsRequest {
            cancel_sig: self.sigma()?,
            refund_encsigs,
        })
    }
}

enum Flow {
    Idle,
    Moved,
}

/// What [`XmrTaker::j_step`] wants sent next.
pub enum JNext {
    /// More `J` messages: `POST /xmr/swaps/:id/j`.
    Send(JRoundRequest),
    /// Keying and signing are done: `POST /xmr/swaps/:id/sigs`.
    Sigs(SigsRequest),
}

/// One swap's keying, in memory only.
struct Keying {
    session: Arc<JSession>,
    /// The maker's swap id (from his first reply).
    swap_id: Option<String>,
    /// The maker's setup as received (verified once `J` is known here).
    setup: Option<SetupReply>,
    /// `J`, once our keygen finished.
    joint: Option<[u8; 33]>,
    /// The setup verified and our signing started.
    signing: bool,
    /// Our side's `σ_J`.
    sig: Option<Vec<u8>>,
}

/// Taker engine for `counter_chain = "xmr"` quotes.
pub struct XmrTaker {
    cfg: XmrConfig,
    divi: Arc<dyn DiviChain>,
    xmr: Arc<dyn MoneroChain>,
    store: Store,
    gate: tokio::sync::Mutex<()>,
    keying: parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<Keying>>>>,
    primes_fn: PrimesFn,
    /// Primes made by [`XmrTaker::warm_primes`], taken by the next [`XmrTaker::prepare`].
    warm: parking_lot::Mutex<Vec<Primes>>,
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
            keying: parking_lot::Mutex::new(HashMap::new()),
            primes_fn: Arc::new(jsig::generate_primes),
            warm: parking_lot::Mutex::new(Vec::new()),
        })
    }

    /// Replace the Paillier prime generator (tests hand out precomputed ones).
    pub fn with_primes(mut self, f: PrimesFn) -> Self {
        self.primes_fn = f;
        self
    }

    /// Generate the Paillier primes for the next [`XmrTaker::prepare`] now (20–90 s), so they
    /// are ready before a quote is fetched: generating them between quote and setup can outlast
    /// the quote.
    pub async fn warm_primes(&self) -> Result<()> {
        let f = self.primes_fn.clone();
        let primes: Primes = jsig::blocking(move || Ok(f())).await?;
        self.warm.lock().push(primes);
        Ok(())
    }

    /// Step 1: generate and persist `b` and `s_t`, start our side of the `J` keying (20–90 s
    /// generating Paillier primes); returns the local id and the request to `POST /xmr/swaps`.
    pub async fn prepare(&self, quote: &Quote) -> Result<(String, SetupRequest)> {
        if quote.counter_chain != Chain::Xmr {
            return Err(SwapError::InvalidParams("not an xmr quote".into()));
        }
        let (divi_key, s_t, proof, x_point, share, j_sid) = {
            let mut rng = rand::thread_rng();
            let s_t = random_clamped_secret(&mut rng);
            let (proof, (x, share)) = nums::dleq().prove(&s_t, &mut rng);
            let mut sid = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut sid);
            (SecretKey::new_random(), s_t, proof, x, share, sid)
        };
        let payout = self.divi.payout_script();
        let rec = XmrTakerRecord {
            id: uuid::Uuid::new_v4().to_string(),
            state: XmrTakerState::Prepared,
            quote: quote.clone(),
            divi_key,
            s_t,
            payout_script: payout.as_bytes().to_vec(),
            j_sid,
            setup: None,
            cancel_sig: None,
            refund_encsigs: BTreeMap::new(),
            cancel_actual: None,
            xmr_txid: None,
            redeem_signed: None,
            punish_signed: None,
            s_m: None,
            sweep_txid: None,
            outcome: None,
            last_error: None,
        };
        self.store.put_doc(KIND, &rec.id, &rec)?;
        let warm = self.warm.lock().pop();
        let primes: Primes = match warm {
            Some(p) => p,
            None => {
                let f = self.primes_fn.clone();
                jsig::blocking(move || Ok(f())).await?
            }
        };
        let session = Arc::new(JSession::start(&j_sid, TAKER, primes));
        let s = session.clone();
        let first = jsig::blocking(move || s.round(Vec::new())).await?;
        self.keying.lock().insert(
            rec.id.clone(),
            Arc::new(tokio::sync::Mutex::new(Keying {
                session,
                swap_id: None,
                setup: None,
                joint: None,
                signing: false,
                sig: None,
            })),
        );
        Ok((
            rec.id.clone(),
            SetupRequest {
                quote_id: quote.id.clone(),
                taker_divi_pubkey: rec.taker_pk(),
                taker_payout_script: rec.payout_script.clone(),
                x_point,
                taker_xmr_share: share,
                taker_proof: proof,
                j_sid,
                j_msgs: first.outgoing,
                j_scheme: jsig::SCHEME.to_string(),
            },
        ))
    }

    /// Step 2: one maker reply of the `J` keying / signing. Verifies his setup in full as
    /// soon as both it and `J` are known, before signing anything; once both sides hold
    /// `σ_J`, builds our encrypted `Tx_refund` signature for each `Tx_cancel` encoding.
    pub async fn j_step(&self, local_id: &str, reply: JRoundReply) -> Result<JNext> {
        let entry = self.keying.lock().get(local_id).cloned().ok_or_else(|| {
            SwapError::InvalidParams(
                "no 2P-ECDSA session for this swap (finished, or the taker restarted)".into(),
            )
        })?;
        let mut k = entry.lock().await;
        let res = self.j_step_inner(local_id, &mut k, reply).await;
        if !matches!(res, Ok(JNext::Send(_))) {
            self.keying.lock().remove(local_id);
        }
        res
    }

    async fn j_step_inner(
        &self,
        local_id: &str,
        k: &mut Keying,
        reply: JRoundReply,
    ) -> Result<JNext> {
        match &k.swap_id {
            None => k.swap_id = Some(reply.swap_id.clone()),
            Some(id) if *id != reply.swap_id => {
                return Err(SwapError::InvalidParams("reply is for another swap".into()))
            }
            Some(_) => {}
        }
        if k.setup.is_none() {
            k.setup = reply.setup.clone();
        }
        let mut out = Vec::new();
        // Never feed the session after it signed: it is over.
        if k.sig.is_none() {
            let s = k.session.clone();
            let msgs = reply.msgs;
            let round = jsig::blocking(move || s.round(msgs)).await?;
            out.extend(round.outgoing);
            let mut status = round.status;
            if let JStatus::KeyReady(j) = status {
                k.joint = Some(j);
            }
            if !k.signing {
                if let (Some(j), Some(setup)) = (k.joint, k.setup.clone()) {
                    let digest = self.verify_setup(local_id, setup, j).await?;
                    k.signing = true;
                    let s = k.session.clone();
                    let more = jsig::blocking(move || s.sign(digest)).await?;
                    out.extend(more.outgoing);
                    status = more.status;
                }
            }
            if let JStatus::Signed(sig) = status {
                k.sig = Some(sig);
            }
        }
        match (&k.sig, reply.signed) {
            (Some(sig), true) => Ok(JNext::Sigs(self.finish_keying(local_id, sig).await?)),
            _ => Ok(JNext::Send(JRoundRequest { msgs: out })),
        }
    }

    /// The maker's setup, checked against `J` and everything we agreed; persisted on the
    /// record (still `Prepared`). Returns `Tx_cancel`'s sighash to sign under `J`.
    async fn verify_setup(
        &self,
        local_id: &str,
        reply: SetupReply,
        j: [u8; 33],
    ) -> Result<[u8; 32]> {
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
        if reply.joint_pubkey != j {
            return Err(bad("J is not the key we computed together"));
        }
        let maker_pk = reply.maker_divi_pubkey;
        crypto::point_of_pubkey(&maker_pk)?;
        if reply.lock_amount < r.quote.divi_amount.0 + self.cfg.divi_fee_sats
            || reply.divi_fee_sats > self.cfg.divi_fee_sats
        {
            return Err(bad("Tx_lock holds less than the quote plus the redeem fee"));
        }
        let lock = LockScript {
            maker: maker_pk,
            taker: r.taker_pk(),
            joint: j,
            t_cancel: reply.t_cancel,
            t_late: reply.t_late,
        };
        let cancel = CancelScript {
            maker: maker_pk,
            taker: r.taker_pk(),
            t_punish: reply.t_punish,
        };
        let lock_op = reply.lock_outpoint.outpoint()?;
        let tx_cancel = &reply.tx_cancel;
        if tx_cancel.vin.len() != 1
            || tx_cancel.vout.len() != 1
            || tx_cancel.vin[0].prevout != lock_op
            || tx_cancel.vin[0].sequence != REFUND_SEQUENCE
            || tx_cancel.lock_time != reply.t_cancel
            || tx_cancel.vout[0].script_pubkey != cancel.script_pubkey()
            || tx_cancel.vout[0].value.as_sat() as u64 + reply.divi_fee_sats != reply.lock_amount
        {
            return Err(bad(
                "Tx_cancel does not move Tx_lock to the cancel script at t_cancel",
            ));
        }
        let mtp = self.divi.median_time_past().await?;
        let margin = self.cfg.redeem_margin_secs;
        if reply.t_cancel < mtp + 2 * margin
            || reply.t_punish < reply.t_cancel + margin
            || reply.t_late < reply.t_punish.saturating_add(self.cfg.late_after_secs)
        {
            return Err(bad(
                "timelocks leave no room to redeem, to punish, or to cancel before t_late",
            ));
        }
        let digest = crypto::digest(tx_cancel, &lock.redeem_script())?;
        r.setup = Some(reply);
        self.store.put_doc(KIND, &r.id, &r)?;
        Ok(digest)
    }

    /// Both sides hold `σ_J`: encrypt-sign `Tx_refund` for every `Tx_cancel` encoding.
    async fn finish_keying(&self, local_id: &str, sig: &[u8]) -> Result<SigsRequest> {
        let _g = self.gate.lock().await;
        let mut r = self.load(local_id)?;
        let s = r.setup()?.clone();
        let redeem = r.redeem_script()?;
        let cancel_redeem = r.cancel_redeem()?;
        if !crypto::verify_plain(&s.tx_cancel, &redeem, &s.joint_pubkey, sig) {
            return Err(SwapError::Other(
                "2P-ECDSA produced an invalid Tx_cancel signature".into(),
            ));
        }
        let variants = lock_scripts::cancel_variants(&s.tx_cancel, sig, &redeem);
        if variants.len() != CANCEL_VARIANTS {
            return Err(SwapError::Other(format!(
                "{} Tx_cancel encodings, expected {CANCEL_VARIANTS}",
                variants.len()
            )));
        }
        let mut encsigs = BTreeMap::new();
        for v in &variants {
            let (refund, _) = crate::api::after_cancel(
                v,
                s.divi_fee_sats,
                &s.maker_refund_script,
                &r.payout_script,
                s.t_cancel,
                s.t_punish,
            );
            let (built, encsig) = taker_encrypts_tx_refund(
                OutPoint::new(v.txid(), 0),
                &cancel_redeem,
                &r.divi_key,
                &s.y_point,
                refund.vout[0].clone(),
                refund.lock_time,
                refund.vin[0].sequence,
            )
            .map_err(|e| SwapError::Other(format!("Tx_refund: {e}")))?;
            if built.txid() != refund.txid() {
                return Err(SwapError::Other("rebuilt Tx_refund differs".into()));
            }
            encsigs.insert(v.txid().to_hex(), encsig.to_string());
        }
        r.cancel_sig = Some(hex::encode(sig));
        r.refund_encsigs = encsigs;
        self.enter(&mut r, XmrTakerState::Accepted)?;
        r.sigs_request()
    }

    /// The request to `POST /xmr/swaps/:id/sigs` again (the maker accepts it idempotently).
    pub fn sigs_request(&self, local_id: &str) -> Result<SigsRequest> {
        self.load(local_id)?.sigs_request()
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
            Accepted => self.on_accepted(r).await,
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
        let redeem = r.redeem_script()?;
        if let Some(spender) = self.divi.find_spend(&lock_op).await? {
            match lock_scripts::lock_spend_branch(&spender, &redeem) {
                Some(LockSpend::Cancel) => {
                    r.cancel_actual = Some(spender);
                    return self.enter(r, XmrTakerState::Cancelled).map(Some);
                }
                Some(LockSpend::Late) => {
                    if r.xmr_txid.is_none() {
                        return self.finish(r, "cancelled").map(Some);
                    }
                    return Err(SwapError::Other(
                        "the maker took Tx_lock through the late branch with our XMR locked".into(),
                    ));
                }
                // Only we can complete Tx_redeem; nothing else spends it.
                Some(LockSpend::Redeem { .. }) | None => {}
            }
        }
        if self.divi.median_time_past().await? <= t_cancel {
            return Ok(None);
        }
        let tx = r.cancel_signed()?;
        match self.divi.broadcast(&tx).await {
            Ok(()) => self.enter(r, XmrTakerState::Cancelled).map(Some),
            Err(SwapError::Premature(_)) => Ok(None),
            // Tx_lock never appeared (or another Tx_cancel encoding is pending): with no XMR
            // of ours locked there is nothing to recover.
            Err(SwapError::Rejected(_)) if r.xmr_txid.is_none() => {
                self.finish(r, "cancelled").map(Some)
            }
            Err(SwapError::Rejected(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Wait for `Tx_lock` (right script, right amount, confirmed); then lock XMR.
    async fn on_accepted(&self, r: &mut XmrTakerRecord) -> Result<Flow> {
        if let Some(f) = self.cancel_if_due(r).await? {
            return Ok(f);
        }
        let s = r.setup()?;
        let spk = r.lock_script()?.script_pubkey();
        // A re-encoded Tx_lock (other txid) never shows here: we then never lock XMR.
        let Some((out, confs)) = self.divi.output(&s.lock_outpoint.outpoint()?).await? else {
            return Ok(Flow::Idle);
        };
        if out.script_pubkey != spk || out.value.as_sat() as u64 != s.lock_amount {
            return Err(SwapError::Other(
                "Tx_lock does not pay the agreed lock script and amount".into(),
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
        let redeem = r.redeem_script()?;
        let completed = taker_completes_tx_redeem(
            tx,
            &redeem,
            &crypto::point_of_pubkey(&s.maker_divi_pubkey)?,
            offer.maker_redeem_encsig.clone(),
            &r.divi_key,
            &crypto::secp_of(&r.s_t),
        )
        .map_err(|e| SwapError::Other(format!("Tx_redeem: {e}")))?;
        r.redeem_signed = Some(crypto::two_key(completed, &redeem)?);
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

    /// The `Tx_cancel` encoding that spends `Tx_lock`, once seen (recorded); until then
    /// ours, (re)broadcast.
    async fn actual_cancel(&self, r: &mut XmrTakerRecord) -> Result<Transaction> {
        let lock_op = r.setup()?.lock_outpoint.outpoint()?;
        match self.divi.find_spend(&lock_op).await? {
            Some(sp) => match lock_scripts::lock_spend_branch(&sp, &r.redeem_script()?) {
                Some(LockSpend::Cancel) => {
                    if r.cancel_actual.as_ref().map(Transaction::txid) != Some(sp.txid()) {
                        r.cancel_actual = Some(sp.clone());
                        self.store.put_doc(KIND, &r.id, r)?;
                    }
                    Ok(sp)
                }
                _ => Err(SwapError::Other(format!(
                    "Tx_lock spent by {}, not a Tx_cancel, after cancelling",
                    sp.txid().to_hex()
                ))),
            },
            None => {
                let c = r.cancel_tx()?;
                match self.divi.broadcast(&c).await {
                    // Rejected: another encoding is in the mempool; seen once mined.
                    Ok(()) | Err(SwapError::Rejected(_)) => Ok(c),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// `Tx_cancel` is out: the maker's `Tx_refund` hands us `s_m`; past `t_punish` we punish.
    async fn on_cancelled(&self, r: &mut XmrTakerRecord) -> Result<Flow> {
        if r.redeem_signed.is_some() {
            // Our Tx_redeem lost to Tx_cancel, or won after all: whichever is on chain.
            let lock_op = r.setup()?.lock_outpoint.outpoint()?;
            if let Some(sp) = self.divi.find_spend(&lock_op).await? {
                if matches!(
                    lock_scripts::lock_spend_branch(&sp, &r.redeem_script()?),
                    Some(LockSpend::Redeem { .. })
                ) {
                    return self.enter(r, XmrTakerState::Redeemed);
                }
            }
        }
        let cancel = self.actual_cancel(r).await?;
        if r.xmr_txid.is_none() {
            return self.finish(r, "cancelled"); // nothing of ours to recover
        }
        let cancel_op = OutPoint::new(cancel.txid(), 0);
        let s = r.setup()?.clone();
        let cancel_redeem = r.cancel_redeem()?;
        if let Some(spender) = self.divi.find_spend(&cancel_op).await? {
            if lock_scripts::refund_spend_sigs(&spender, &cancel_redeem).is_none() {
                // Not the two-key branch: only our Tx_punish can spend the other one.
                r.punish_signed = Some(spender);
                return self.finish(r, "punished");
            }
            let txid = cancel.txid().to_hex();
            let encsig = r
                .refund_encsigs
                .get(&txid)
                .and_then(|e| EncryptedSignature::from_str(e).ok())
                .ok_or_else(|| {
                    SwapError::Other(format!("no refund encsig for Tx_cancel encoding {txid}"))
                })?;
            let s_m = crypto::recover(&spender, Signer::Taker, &s.y_point, &encsig)
                .filter(|m| crypto::ed_pub(m) == s.maker_xmr_share)
                .ok_or_else(|| SwapError::Other("could not recover s_m from Tx_refund".into()))?;
            r.s_m = Some(hex::encode(s_m.to_bytes()));
            return self.enter(r, XmrTakerState::Recovering);
        }
        if self.divi.median_time_past().await? > s.t_punish {
            let (_, mut punish) = crate::api::after_cancel(
                &cancel,
                s.divi_fee_sats,
                &s.maker_refund_script,
                &r.payout_script,
                s.t_cancel,
                s.t_punish,
            );
            let sig = crypto::sign_plain(&punish, &cancel_redeem, &r.divi_key)?;
            punish.vin[0].script_sig = lock_scripts::punish_sig(&sig, &cancel_redeem);
            r.punish_signed = Some(punish);
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
