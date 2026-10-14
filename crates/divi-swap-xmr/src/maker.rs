// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The maker side of the adaptor swap (holds DIVI, buys XMR).
//!
//! ```text
//! Accepted → Locked → XmrReported → RedeemOffered → Redeemed → Swept → Done
//!            (any of Locked..RedeemOffered, past t_cancel) → Cancelled → Refunded → Done
//!                                                             Cancelled → Punished (terminal)
//! Accepted → Aborted   (the taker never sent her signatures; nothing was ever broadcast)
//! ```
//!
//! Two ordering rules carry the safety, both stricter than the happy-path list in
//! `xmr-design.md` `## Protocol` step 1 (which has the maker hand over his encrypted
//! `Tx_redeem` signature during setup — that would let the taker take the DIVI as soon as
//! `Tx_lock` confirms without ever locking XMR; xmr-btc-swap sends it only after the XMR lock):
//! - `Tx_lock` is broadcast only after the taker's `Tx_cancel` signature and her encrypted
//!   `Tx_refund` signature verified, so the maker can always get his DIVI back.
//! - The encrypted `Tx_redeem` signature is produced only after the taker's XMR lock is seen
//!   with `xmr_confirmations`, and only while `t_cancel` is more than `redeem_margin_secs` away.
//!
//! Every transition and every signed transaction is persisted before the side effect it
//! precedes; [`XmrMaker::step`] is idempotent and safe to re-run after a crash.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_swap::api::{Direction, Offer, Quote};
use divi_swap::htlc::REFUND_SEQUENCE;
use divi_swap::store::QuoteRecord;
use divi_swap::{Amount as SwapAmount, Chain, Result, Store, SwapError};
use serde::{Deserialize, Serialize};
use swap_adaptor::adaptor::{EncryptedSignature, Point};
use swap_adaptor::dleq::{random_clamped_secret, PointQ, ScalarQ};
use swap_chain_xmr::swap_templates::{maker_completes_tx_refund, maker_encrypts_tx_redeem};

use crate::api::{
    RedeemOffer, SetupReply, SetupRequest, SigsRequest, WireOutpoint, XmrLockNotice, XmrSwapView,
};
use crate::chain::{DiviChain, MoneroChain};
use crate::crypto::{self, Signer};
use crate::{nums, wire, XmrConfig, PICONERO_PER_COUNTER_SAT};

/// Store document kind of maker records.
pub const KIND: &str = "xmr_maker";

/// Maker-side state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XmrMakerState {
    /// Setup reply sent; `Tx_lock` built and signed, not broadcast. No coins committed.
    Accepted,
    /// The taker's signatures verified; `Tx_lock` persisted and (re)broadcast.
    Locked,
    /// The taker reported her XMR lock (not yet verified).
    XmrReported,
    /// Her XMR lock is confirmed; the encrypted `Tx_redeem` signature is published.
    RedeemOffered,
    /// `Tx_redeem` is on chain; `s_t` recovered from it.
    Redeemed,
    /// The XMR sweep is broadcast.
    Swept,
    /// `Tx_cancel` is broadcast (or seen).
    Cancelled,
    /// `Tx_refund` is broadcast (DIVI back to the maker; reveals `s_m` to the taker).
    Refunded,
    /// The taker's `Tx_punish` took the DIVI. Terminal.
    Punished,
    /// Ended before anything was broadcast. Terminal.
    Aborted,
    /// Finished. Terminal.
    Done,
}

impl XmrMakerState {
    /// No further transitions.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            XmrMakerState::Done | XmrMakerState::Aborted | XmrMakerState::Punished
        )
    }
}

/// The maker's persisted view of one swap (holds the maker's per-swap secrets: the store is
/// mode 0600, like the hashlock taker's preimage).
#[derive(Clone, Serialize, Deserialize)]
pub struct XmrMakerRecord {
    /// Swap id.
    pub id: String,
    /// Wall clock when accepted.
    pub created_at: u64,
    /// Current state.
    pub state: XmrMakerState,
    /// The quote.
    pub quote: Quote,
    /// `a`: per-swap DIVI multisig key.
    #[serde(with = "wire::divi_secret")]
    pub divi_key: SecretKey,
    /// `s_m`: Monero spend-key share and `Tx_refund` adaptor secret.
    #[serde(with = "wire::ed_scalar")]
    pub s_m: ScalarQ,
    /// Shared Monero view key.
    #[serde(with = "wire::b32")]
    pub view_secret: [u8; 32],
    /// `b`.
    #[serde(with = "wire::b33")]
    pub taker_pk: [u8; 33],
    /// The taker's payout script.
    #[serde(with = "wire::bytes")]
    pub taker_payout: Vec<u8>,
    /// `X`.
    #[serde(with = "wire::secp_point")]
    pub x_point: Point,
    /// `S_t`.
    #[serde(with = "wire::ed_point")]
    pub taker_share: PointQ,
    /// XMR expected, piconero.
    pub xmr_amount: u64,
    /// The 2-of-2 redeem script `{a, b}`.
    #[serde(with = "wire::bytes")]
    pub redeem_script: Vec<u8>,
    /// `Tx_lock`, signed, broadcast from `Locked` on.
    #[serde(with = "wire::divi_tx")]
    pub tx_lock: Transaction,
    /// `Tx_lock`'s 2-of-2 output index.
    pub lock_vout: u32,
    /// Its value, sats.
    pub lock_amount: u64,
    /// `nLockTime` of `Tx_cancel` / `Tx_refund`.
    pub t_cancel: u32,
    /// `nLockTime` of `Tx_punish`.
    pub t_punish: u32,
    /// Unsigned `Tx_cancel`.
    #[serde(with = "wire::divi_tx")]
    pub tx_cancel: Transaction,
    /// Our signature on it.
    #[serde(with = "wire::bytes")]
    pub maker_cancel_sig: Vec<u8>,
    /// Where `Tx_refund` pays us.
    #[serde(with = "wire::bytes")]
    pub refund_script: Vec<u8>,
    /// `Tx_cancel` with both signatures (from `Locked` on): its txid is what `Tx_refund`
    /// and `Tx_punish` spend.
    #[serde(with = "wire::opt_divi_tx")]
    pub cancel_signed: Option<Transaction>,
    /// Unsigned `Tx_refund` (from `Locked` on).
    #[serde(with = "wire::opt_divi_tx")]
    pub tx_refund: Option<Transaction>,
    /// Unsigned `Tx_punish` (from `Locked` on).
    #[serde(with = "wire::opt_divi_tx")]
    pub tx_punish: Option<Transaction>,
    /// Our signature on `Tx_punish` (hex; handed to the taker in the view).
    pub maker_punish_sig: Option<String>,
    /// The taker's `Tx_cancel` signature.
    pub taker_cancel_sig: Option<String>,
    /// The taker's encrypted `Tx_refund` signature.
    pub taker_refund_encsig: Option<String>,
    /// The taker's reported XMR lock.
    pub xmr_txid: Option<String>,
    /// Unsigned `Tx_redeem`, once offered.
    #[serde(with = "wire::opt_divi_tx")]
    pub tx_redeem: Option<Transaction>,
    /// Our encrypted `Tx_redeem` signature, once offered.
    pub redeem_encsig: Option<String>,
    /// `s_t`, recovered from `Tx_redeem` (hex scalar).
    pub s_t: Option<String>,
    /// Our XMR sweep.
    pub sweep_txid: Option<String>,
    /// `Tx_refund`, completed and signed (persisted before broadcast).
    #[serde(with = "wire::opt_divi_tx")]
    pub refund_signed: Option<Transaction>,
    /// Last error.
    pub last_error: Option<String>,
}

impl XmrMakerRecord {
    fn lock_outpoint(&self) -> OutPoint {
        OutPoint::new(self.tx_lock.txid(), self.lock_vout)
    }

    fn cancel_signed(&self) -> Result<&Transaction> {
        self.cancel_signed
            .as_ref()
            .ok_or_else(|| SwapError::Other("no signed Tx_cancel".into()))
    }

    fn maker_pk(&self) -> [u8; 33] {
        self.divi_key.public_key().serialize_compressed()
    }

    fn shared_spend_key(&self) -> [u8; 32] {
        crypto::shared_spend_key(&crypto::ed_pub(&self.s_m), &self.taker_share)
    }

    fn view(&self) -> XmrSwapView {
        let redeem = match (&self.tx_redeem, &self.redeem_encsig) {
            (Some(tx), Some(es)) => EncryptedSignature::from_str(es).ok().map(|e| RedeemOffer {
                tx_redeem: tx.clone(),
                maker_redeem_encsig: e,
            }),
            _ => None,
        };
        let broadcast = !matches!(self.state, XmrMakerState::Accepted | XmrMakerState::Aborted);
        XmrSwapView {
            id: self.id.clone(),
            state: self.state,
            quote: self.quote.clone(),
            lock_txid: broadcast.then(|| self.tx_lock.txid().to_hex()),
            xmr_lock_txid: self.xmr_txid.clone(),
            redeem,
            // Cancelled at some point: still in that branch, or refunded since (even if Done).
            cancel_txid: (matches!(
                self.state,
                XmrMakerState::Cancelled | XmrMakerState::Refunded | XmrMakerState::Punished
            ) || self.refund_signed.is_some())
            .then(|| self.cancel_signed.as_ref().map(|t| t.txid().to_hex()))
            .flatten(),
            refund_txid: self.refund_signed.as_ref().map(|t| t.txid().to_hex()),
            maker_punish_sig: self.maker_punish_sig.clone(),
            last_error: self.last_error.clone(),
        }
    }
}

enum Flow {
    Idle,
    Moved,
}

/// An unsigned single-input spend of a 2-of-2 output (the shape of every presigned tx).
pub(crate) fn spend(prevout: OutPoint, value: u64, to: Script, lock_time: u32) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(prevout, Script::new(), REFUND_SEQUENCE)],
        vout: vec![TxOut::new(Amount::from_sat(value as i64), to)],
        lock_time,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Maker engine for `counter_chain = "xmr"` offers.
pub struct XmrMaker {
    cfg: XmrConfig,
    divi: Arc<dyn DiviChain>,
    xmr: Arc<dyn MoneroChain>,
    store: Store,
    offers: Vec<Offer>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// One lock per swap, held across a swap's load → `advance` → persist. It replaces a
    /// single engine-wide gate, under which one slow Monero scan (`find_lock`) stalled every
    /// other swap's step and every request. What that gate actually protected was this
    /// read-modify-write: two concurrent steps of one swap (a request's `step` and the
    /// scheduler's `tick`, or `xmr_locked` recording a txid) would each persist their own
    /// copy and lose the other's update. Nothing it covered was shared between swaps:
    /// - coin selection for `Tx_lock` happens in `setup`, which never took the gate; the
    ///   live DIVI wallet selects and reserves coins under its own wallet lock
    ///   (`swap_chain_xmr::divi_chain`), so two swaps cannot pick the same coins;
    /// - each `Store` write is atomic under the store's connection lock, and every swap
    ///   writes only its own document;
    /// - the quote bookkeeping `setup` does has its own lock, `quotes_in_setup`.
    ///
    /// Entries are dropped once nobody holds them (`swap_lock`).
    swap_locks: parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Quote ids a `setup` is working on. `setup` checks a quote is unused, then awaits the
    /// DIVI wallet and chain, then marks it used; without this two concurrent setups on one
    /// quote would both pass the check and open two swaps for it. Never held across an await.
    quotes_in_setup: parking_lot::Mutex<HashSet<String>>,
}

/// Removes a quote id from `XmrMaker::quotes_in_setup` when `setup` returns.
struct QuoteClaim<'a> {
    set: &'a parking_lot::Mutex<HashSet<String>>,
    id: String,
}

impl Drop for QuoteClaim<'_> {
    fn drop(&mut self) {
        self.set.lock().remove(&self.id);
    }
}

impl XmrMaker {
    /// New engine. `offers` must all be `counter_chain = "xmr"`, `taker_pays_btc` (the maker
    /// always holds the DIVI leg in this protocol).
    pub fn new(
        cfg: XmrConfig,
        divi: Arc<dyn DiviChain>,
        xmr: Arc<dyn MoneroChain>,
        store: Store,
        offers: Vec<Offer>,
    ) -> Result<Self> {
        cfg.validate()?;
        for o in &offers {
            if o.counter_chain != Chain::Xmr || o.direction != Direction::TakerPaysBtc {
                return Err(SwapError::InvalidParams(format!(
                    "offer {}: the adaptor engine serves xmr, taker_pays_btc only",
                    o.id
                )));
            }
        }
        Ok(XmrMaker {
            cfg,
            divi,
            xmr,
            store,
            offers,
            clock: Arc::new(unix_now),
            swap_locks: parking_lot::Mutex::new(HashMap::new()),
            quotes_in_setup: parking_lot::Mutex::new(HashSet::new()),
        })
    }

    /// Replace the wall clock (quote expiry, the signatures wait).
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// The offers this engine serves.
    pub fn offers(&self) -> Vec<Offer> {
        self.offers.clone()
    }

    /// Issue a quote for `btc_sats` 1e-8-XMR units. The per-swap keys come in the setup
    /// reply, so the quote's `maker_*_pubkey` fields are zero here.
    pub async fn quote(&self, offer_id: &str, btc_sats: u64) -> Result<Quote> {
        let offer = self
            .offers
            .iter()
            .find(|o| o.id == offer_id)
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown offer {offer_id:?}")))?;
        if btc_sats < offer.min_btc_sats || btc_sats > offer.max_btc_sats {
            return Err(SwapError::InvalidParams(format!(
                "{btc_sats} outside offer range {}..={}",
                offer.min_btc_sats, offer.max_btc_sats
            )));
        }
        let divi_amount = offer.divi_for(btc_sats);
        if divi_amount.0 == 0 {
            return Err(SwapError::InvalidParams("swap is worth no DIVI".into()));
        }
        let quote = Quote {
            id: uuid::Uuid::new_v4().to_string(),
            offer_id: offer.id.clone(),
            direction: Direction::TakerPaysBtc,
            counter_chain: Chain::Xmr,
            btc_amount: SwapAmount(btc_sats),
            divi_amount,
            expires_at: (self.clock)() + self.cfg.quote_expiry_secs as u64,
            maker_btc_pubkey: [0; 33],
            maker_divi_pubkey: [0; 33],
            taker_timeout_secs: self.cfg.cancel_after_secs + self.cfg.punish_after_secs,
            maker_timeout_secs: self.cfg.cancel_after_secs,
            btc_confirmations: self.cfg.xmr_confirmations,
            divi_confirmations: self.cfg.divi_confirmations,
        };
        self.store.put_quote(&QuoteRecord {
            quote: quote.clone(),
            used: false,
        })?;
        Ok(quote)
    }

    /// Step 1 → 2: verify the taker's DLEQ proof, generate our keys, build `Tx_lock` (not
    /// broadcast) and the presigned templates, sign `Tx_cancel` and `Tx_punish`.
    pub async fn setup(&self, req: SetupRequest) -> Result<SetupReply> {
        let _claim = {
            let mut set = self.quotes_in_setup.lock();
            if !set.insert(req.quote_id.clone()) {
                return Err(SwapError::InvalidParams("quote already being used".into()));
            }
            QuoteClaim {
                set: &self.quotes_in_setup,
                id: req.quote_id.clone(),
            }
        };
        let mut qr = self
            .store
            .get_quote(&req.quote_id)?
            .ok_or_else(|| SwapError::InvalidParams("unknown quote".into()))?;
        if qr.used {
            return Err(SwapError::InvalidParams("quote already used".into()));
        }
        let quote = qr.quote.clone();
        if quote.counter_chain != Chain::Xmr {
            return Err(SwapError::InvalidParams(
                "not an xmr quote: use POST /swaps".into(),
            ));
        }
        if (self.clock)() > quote.expires_at {
            return Err(SwapError::InvalidParams("quote expired".into()));
        }
        if !nums::dleq().verify(&req.taker_proof, (req.x_point, req.taker_xmr_share)) {
            return Err(SwapError::InvalidParams(
                "taker's DLEQ proof does not bind X to S_t".into(),
            ));
        }
        crypto::point_of_pubkey(&req.taker_divi_pubkey)?;
        let payout = Script::from_bytes(req.taker_payout_script.clone());
        if !(payout.is_p2pkh() || payout.is_p2sh()) {
            return Err(SwapError::InvalidParams(
                "taker payout must be a P2PKH or P2SH script".into(),
            ));
        }

        // `ThreadRng` is not `Send`: keep it out of scope across the awaits below.
        let (divi_key, s_m, maker_proof, y_point, maker_share, view_secret) = {
            let mut rng = rand::thread_rng();
            let s_m = random_clamped_secret(&mut rng);
            let (proof, (y, share)) = nums::dleq().prove(&s_m, &mut rng);
            let view = random_clamped_secret(&mut rng).to_bytes();
            (SecretKey::new_random(), s_m, proof, y, share, view)
        };
        let maker_pk = divi_key.public_key().serialize_compressed();
        let (redeem, spk) = crypto::multisig_script(&maker_pk, &req.taker_divi_pubkey);

        let fee = self.cfg.divi_fee_sats;
        let lock_amount = quote.divi_amount.0 + fee;
        let tx_lock = self.divi.build_funding(&spk, lock_amount).await?;
        let lock_vout = tx_lock
            .vout
            .iter()
            .position(|o| o.script_pubkey == spk && o.value.as_sat() as u64 == lock_amount)
            .ok_or_else(|| SwapError::Other("Tx_lock lacks the 2-of-2 output".into()))?
            as u32;
        let lock_op = OutPoint::new(tx_lock.txid(), lock_vout);
        let mtp = self.divi.median_time_past().await?;
        let t_cancel = mtp
            .checked_add(self.cfg.cancel_after_secs)
            .ok_or_else(|| SwapError::InvalidParams("t_cancel overflow".into()))?;
        let t_punish = t_cancel + self.cfg.punish_after_secs;
        let tx_cancel = spend(lock_op, lock_amount - fee, spk.clone(), t_cancel);
        let maker_cancel_sig = crypto::sign_plain(&tx_cancel, &redeem, &divi_key)?;
        let refund_script = self.divi.payout_script().as_bytes().to_vec();

        let rec = XmrMakerRecord {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: (self.clock)(),
            state: XmrMakerState::Accepted,
            quote: quote.clone(),
            divi_key,
            s_m,
            view_secret,
            taker_pk: req.taker_divi_pubkey,
            taker_payout: req.taker_payout_script,
            x_point: req.x_point,
            taker_share: req.taker_xmr_share,
            xmr_amount: quote.btc_amount.0 * PICONERO_PER_COUNTER_SAT,
            redeem_script: redeem,
            tx_lock,
            lock_vout,
            lock_amount,
            t_cancel,
            t_punish,
            tx_cancel: tx_cancel.clone(),
            maker_cancel_sig: maker_cancel_sig.clone(),
            refund_script: refund_script.clone(),
            cancel_signed: None,
            tx_refund: None,
            tx_punish: None,
            maker_punish_sig: None,
            taker_cancel_sig: None,
            taker_refund_encsig: None,
            xmr_txid: None,
            tx_redeem: None,
            redeem_encsig: None,
            s_t: None,
            sweep_txid: None,
            refund_signed: None,
            last_error: None,
        };
        qr.used = true;
        self.store.put_quote(&qr)?;
        self.store.put_doc(KIND, &rec.id, &rec)?;
        Ok(SetupReply {
            swap_id: rec.id.clone(),
            quote,
            maker_divi_pubkey: maker_pk,
            y_point,
            maker_xmr_share: maker_share,
            maker_proof,
            xmr_view_secret: view_secret,
            xmr_amount: rec.xmr_amount,
            lock_outpoint: WireOutpoint::of(&lock_op),
            lock_amount,
            t_cancel,
            t_punish,
            divi_fee_sats: fee,
            tx_cancel,
            maker_cancel_sig,
            maker_refund_script: refund_script,
        })
    }

    /// Step 3: the taker's `Tx_cancel` signature and encrypted `Tx_refund` signature. Both are
    /// verified before anything is broadcast; then `Tx_lock` goes out.
    pub async fn sigs(&self, swap_id: &str, req: SigsRequest) -> Result<XmrSwapView> {
        {
            let lock = self.swap_lock(swap_id);
            let _g = lock.lock().await;
            let mut r = self.load(swap_id)?;
            let encsig = req.taker_refund_encsig.to_string();
            let cancel_sig = hex::encode(&req.taker_cancel_sig);
            match r.state {
                XmrMakerState::Accepted => {}
                _ if r.taker_cancel_sig.as_deref() == Some(cancel_sig.as_str())
                    && r.taker_refund_encsig.as_deref() == Some(encsig.as_str()) =>
                {
                    return Ok(r.view());
                }
                s => {
                    return Err(SwapError::InvalidParams(format!(
                        "swap is {s:?}, not awaiting signatures"
                    )))
                }
            }
            if !crypto::verify_plain(
                &r.tx_cancel,
                &r.redeem_script,
                &r.taker_pk,
                &req.taker_cancel_sig,
            ) {
                return Err(SwapError::InvalidParams(
                    "taker's Tx_cancel signature is invalid".into(),
                ));
            }
            let cancel_signed = crypto::assemble(
                r.tx_cancel.clone(),
                &r.redeem_script,
                &r.maker_cancel_sig,
                &req.taker_cancel_sig,
            );
            let (tx_refund, tx_punish) = crate::api::after_cancel(
                &cancel_signed,
                self.cfg.divi_fee_sats,
                &r.refund_script,
                &r.taker_payout,
                r.t_cancel,
                r.t_punish,
            );
            let y_point = swap_adaptor::adaptor::AdaptorSigner::new()
                .encryption_key_for(&crypto::secp_of(&r.s_m));
            if !crypto::verify_encrypted(
                &tx_refund,
                &r.redeem_script,
                &r.taker_pk,
                &y_point,
                &req.taker_refund_encsig,
            ) {
                return Err(SwapError::InvalidParams(
                    "taker's encrypted Tx_refund signature is invalid".into(),
                ));
            }
            let punish_sig = crypto::sign_plain(&tx_punish, &r.redeem_script, &r.divi_key)?;
            r.taker_cancel_sig = Some(cancel_sig);
            r.taker_refund_encsig = Some(encsig);
            r.cancel_signed = Some(cancel_signed);
            r.tx_refund = Some(tx_refund);
            r.tx_punish = Some(tx_punish);
            r.maker_punish_sig = Some(hex::encode(punish_sig));
            self.enter(&mut r, XmrMakerState::Locked)?; // persisted before Tx_lock goes out
        }
        let _ = self.step(swap_id).await;
        self.view(swap_id)?
            .ok_or_else(|| SwapError::Other("swap vanished".into()))
    }

    /// Step 4: the taker says she locked XMR in `notice.xmr_txid`. Verified on the Monero
    /// chain by [`XmrMaker::step`], not trusted. Records the notice and returns: the next
    /// [`XmrMaker::tick`] does the verification, whose first `find_lock` can scan hundreds of
    /// blocks on a remote monerod — longer than the taker's HTTP timeout if run in the request.
    pub async fn xmr_locked(&self, swap_id: &str, notice: XmrLockNotice) -> Result<XmrSwapView> {
        {
            let lock = self.swap_lock(swap_id);
            let _g = lock.lock().await;
            let mut r = self.load(swap_id)?;
            match (&r.xmr_txid, r.state) {
                (Some(t), _) if *t == notice.xmr_txid => {}
                (Some(_), _) => {
                    return Err(SwapError::InvalidParams(
                        "a different XMR lock was already reported".into(),
                    ))
                }
                (None, XmrMakerState::Locked) => {
                    r.xmr_txid = Some(notice.xmr_txid);
                    self.enter(&mut r, XmrMakerState::XmrReported)?;
                }
                (None, s) => {
                    return Err(SwapError::InvalidParams(format!(
                        "swap is {s:?}, not awaiting an XMR lock"
                    )))
                }
            }
        }
        self.view(swap_id)?
            .ok_or_else(|| SwapError::Other("swap vanished".into()))
    }

    /// Current view of one swap.
    pub fn view(&self, swap_id: &str) -> Result<Option<XmrSwapView>> {
        Ok(self
            .store
            .get_doc::<XmrMakerRecord>(KIND, swap_id)?
            .map(|r| r.view()))
    }

    /// All swaps, newest first.
    pub fn list(&self) -> Result<Vec<XmrSwapView>> {
        Ok(self
            .store
            .list_docs::<XmrMakerRecord>(KIND)?
            .iter()
            .map(XmrMakerRecord::view)
            .collect())
    }

    /// Swaps in `store` this engine has not finished: a daemon must keep the engine (and its
    /// chains) running while there are any, even with every xmr offer switched off.
    pub fn open_swaps(store: &Store) -> Result<usize> {
        Ok(store
            .list_docs::<XmrMakerRecord>(KIND)?
            .iter()
            .filter(|r| !r.state.is_terminal())
            .count())
    }

    /// The lock serializing `swap_id`'s read-modify-write. Entries nobody else holds are
    /// pruned on the way: a strong count of 1 means no step holds or awaits that lock, so a
    /// later call simply makes a fresh one.
    fn swap_lock(&self, swap_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.swap_locks.lock();
        locks.retain(|id, l| id == swap_id || Arc::strong_count(l) > 1);
        locks.entry(swap_id.to_string()).or_default().clone()
    }

    /// `step` every non-terminal swap; errors are recorded on the swap. Sequential: each swap
    /// has its own lock, so a request for another swap is never held up behind this loop.
    pub async fn tick(&self) -> Result<()> {
        for r in self.store.list_docs::<XmrMakerRecord>(KIND)? {
            if !r.state.is_terminal() {
                let _ = self.step(&r.id).await;
            }
        }
        Ok(())
    }

    /// Advance one swap as far as it goes now. Idempotent; safe after a restart.
    pub async fn step(&self, swap_id: &str) -> Result<XmrMakerState> {
        let lock = self.swap_lock(swap_id);
        let _g = lock.lock().await;
        let mut r = self.load(swap_id)?;
        if r.state.is_terminal() {
            return Ok(r.state);
        }
        let had_error = r.last_error.take().is_some();
        for _ in 0..16 {
            match self.advance(&mut r).await {
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

    fn load(&self, id: &str) -> Result<XmrMakerRecord> {
        self.store
            .get_doc(KIND, id)?
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown xmr swap {id:?}")))
    }

    fn enter(&self, r: &mut XmrMakerRecord, next: XmrMakerState) -> Result<Flow> {
        tracing::info!(swap = %r.id, from = ?r.state, to = ?next, "xmr maker");
        r.state = next;
        self.store.put_doc(KIND, &r.id, r)?;
        Ok(Flow::Moved)
    }

    async fn advance(&self, r: &mut XmrMakerRecord) -> Result<Flow> {
        use XmrMakerState::*;
        match r.state {
            Accepted => {
                if (self.clock)() > r.created_at + self.cfg.sigs_wait_secs {
                    r.last_error = Some("aborted: the taker never sent her signatures".into());
                    return self.enter(r, Aborted);
                }
                Ok(Flow::Idle)
            }
            Locked | XmrReported | RedeemOffered => self.on_locked(r).await,
            Redeemed => self.on_redeemed(r).await,
            Swept => {
                let txid = r.sweep_txid.clone().unwrap_or_default();
                if self.xmr.confirmations(&txid).await?.unwrap_or(0) >= 1 {
                    return self.enter(r, Done);
                }
                Ok(Flow::Idle)
            }
            Cancelled => self.on_cancelled(r).await,
            Refunded => {
                let tx = r
                    .refund_signed
                    .clone()
                    .ok_or_else(|| SwapError::Other("Refunded without a refund tx".into()))?;
                self.divi.broadcast(&tx).await?; // dropped from the mempool? same bytes again
                if self.divi.confirmations(&tx.txid()).await?.unwrap_or(0) >= 1 {
                    return self.enter(r, Done);
                }
                Ok(Flow::Idle)
            }
            Punished | Aborted | Done => Ok(Flow::Idle),
        }
    }

    /// `Tx_lock` is (being) broadcast: watch it, offer redeem once the XMR is locked, recover
    /// `s_t` if the taker redeemed, cancel past `t_cancel`.
    async fn on_locked(&self, r: &mut XmrMakerRecord) -> Result<Flow> {
        self.divi.broadcast(&r.tx_lock).await?;
        let lock_op = r.lock_outpoint();
        if let Some(spender) = self.divi.find_spend(&lock_op).await? {
            if spender.txid() == r.cancel_signed()?.txid() {
                return self.enter(r, XmrMakerState::Cancelled);
            }
            // Anything else spending the 2-of-2 has both signatures: it is the taker's
            // completed Tx_redeem, and our completed signature in it reveals s_t.
            let encsig = r
                .redeem_encsig
                .as_deref()
                .and_then(|s| EncryptedSignature::from_str(s).ok())
                .ok_or_else(|| {
                    SwapError::Other(
                        "Tx_lock spent by an unknown tx before redeem was offered".into(),
                    )
                })?;
            let s_t = crypto::recover(&spender, Signer::Maker, &r.x_point, &encsig)
                .filter(|s| crypto::ed_pub(s) == r.taker_share)
                .ok_or_else(|| SwapError::Other("could not recover s_t from Tx_redeem".into()))?;
            r.s_t = Some(hex::encode(s_t.to_bytes()));
            return self.enter(r, XmrMakerState::Redeemed);
        }
        let mtp = self.divi.median_time_past().await?;
        if mtp > r.t_cancel {
            let tx = r.cancel_signed()?.clone();
            match self.divi.broadcast(&tx).await {
                Ok(()) => return self.enter(r, XmrMakerState::Cancelled),
                Err(SwapError::Premature(_)) => return Ok(Flow::Idle),
                // The taker's Tx_redeem won the race: the next pass recovers s_t.
                Err(SwapError::Rejected(_)) => return Ok(Flow::Idle),
                Err(e) => return Err(e),
            }
        }
        if r.state == XmrMakerState::XmrReported {
            let found = self
                .xmr
                .find_lock(&r.shared_spend_key(), &r.view_secret)
                .await?;
            let ok = found.as_ref().is_some_and(|o| {
                o.amount >= r.xmr_amount && o.confirmations >= self.cfg.xmr_confirmations
            });
            if ok && mtp + self.cfg.redeem_margin_secs < r.t_cancel {
                let (tx, encsig) = maker_encrypts_tx_redeem(
                    lock_op,
                    &r.redeem_script,
                    &r.divi_key,
                    &r.x_point,
                    TxOut::new(
                        Amount::from_sat((r.lock_amount - self.cfg.divi_fee_sats) as i64),
                        Script::from_bytes(r.taker_payout.clone()),
                    ),
                    REFUND_SEQUENCE,
                )
                .map_err(|e| SwapError::Other(format!("Tx_redeem: {e}")))?;
                r.tx_redeem = Some(tx);
                r.redeem_encsig = Some(encsig.to_string());
                return self.enter(r, XmrMakerState::RedeemOffered);
            }
        }
        Ok(Flow::Idle)
    }

    async fn on_redeemed(&self, r: &mut XmrMakerRecord) -> Result<Flow> {
        let s_t = r
            .s_t
            .as_deref()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(ScalarQ::from_canonical_bytes)
            .ok_or_else(|| SwapError::Other("Redeemed without s_t".into()))?;
        let lock = self
            .xmr
            .find_lock(&r.shared_spend_key(), &r.view_secret)
            .await?
            .ok_or_else(|| SwapError::Other("the XMR lock vanished".into()))?;
        let full = (r.s_m + s_t).to_bytes();
        match self.xmr.sweep(&lock, &full, &r.view_secret).await {
            Ok(txid) => {
                r.sweep_txid = Some(txid);
                self.enter(r, XmrMakerState::Swept)
            }
            Err(SwapError::Premature(_)) => Ok(Flow::Idle),
            Err(e) => Err(e),
        }
    }

    /// `Tx_cancel` is out: refund (revealing `s_m`) unless the taker punished first.
    async fn on_cancelled(&self, r: &mut XmrMakerRecord) -> Result<Flow> {
        let cancel = r.cancel_signed()?.clone();
        self.divi.broadcast(&cancel).await?; // idempotent
        let cancel_op = OutPoint::new(cancel.txid(), 0);
        if let Some(spender) = self.divi.find_spend(&cancel_op).await? {
            if r.refund_signed
                .as_ref()
                .is_some_and(|t| t.txid() == spender.txid())
            {
                return self.enter(r, XmrMakerState::Refunded);
            }
            r.last_error = Some("the taker punished: Tx_punish took the DIVI".into());
            return self.enter(r, XmrMakerState::Punished);
        }
        let refund = match r.refund_signed.clone() {
            Some(t) => t,
            None => {
                let encsig = r
                    .taker_refund_encsig
                    .as_deref()
                    .and_then(|s| EncryptedSignature::from_str(s).ok())
                    .ok_or_else(|| SwapError::Other("no taker refund signature".into()))?;
                let unsigned = r
                    .tx_refund
                    .clone()
                    .ok_or_else(|| SwapError::Other("no Tx_refund".into()))?;
                let t = maker_completes_tx_refund(
                    unsigned,
                    &r.redeem_script,
                    &crypto::point_of_pubkey(&r.taker_pk)?,
                    encsig,
                    &r.divi_key,
                    &crypto::secp_of(&r.s_m),
                )
                .map_err(|e| SwapError::Other(format!("Tx_refund: {e}")))?;
                r.refund_signed = Some(t.clone());
                self.store.put_doc(KIND, &r.id, r)?; // write-ahead
                t
            }
        };
        match self.divi.broadcast(&refund).await {
            Ok(()) => self.enter(r, XmrMakerState::Refunded),
            Err(SwapError::Premature(_)) => Ok(Flow::Idle),
            Err(e) => Err(e),
        }
    }

    #[doc(hidden)]
    pub fn record(&self, id: &str) -> Result<Option<XmrMakerRecord>> {
        self.store.get_doc(KIND, id)
    }

    #[doc(hidden)]
    pub fn maker_pk_of(r: &XmrMakerRecord) -> [u8; 33] {
        r.maker_pk()
    }
}

#[async_trait::async_trait]
impl divi_swap::OfferEngine for XmrMaker {
    fn offers(&self) -> Vec<Offer> {
        XmrMaker::offers(self)
    }

    async fn quote(&self, offer_id: &str, btc_sats: u64) -> Result<Quote> {
        XmrMaker::quote(self, offer_id, btc_sats).await
    }

    async fn tick(&self) -> Result<()> {
        XmrMaker::tick(self).await
    }
}
