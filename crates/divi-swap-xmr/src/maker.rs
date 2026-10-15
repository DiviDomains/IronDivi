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
//! (keying: in memory only) → Accepted → Locked → XmrReported → RedeemOffered → Redeemed → Swept → Done
//!            (any of Locked..RedeemOffered, past t_cancel) → Cancelled → Refunded → Done
//!                                                             Cancelled → Punished (terminal)
//!            (Tx_lock never cancelled, past t_late)         → Reclaimed → Done
//! Accepted → Aborted   (the taker never sent her signatures; nothing was ever broadcast)
//! ```
//!
//! C1 (`docs/plans/swap-poc/xmr-c1-design.md`): `Tx_cancel` is signed by the 2P-ECDSA joint
//! key `J`, exactly once, during setup ([`crate::jsig`]); neither side can ever sign a second
//! transaction spending the lock's cancel branch. Because a staker may re-encode the signed
//! `Tx_cancel` (changing its txid), the taker sends one encrypted `Tx_refund` signature for
//! each of its [`CANCEL_VARIANTS`] encodings, and the maker refunds whichever one was mined.
//!
//! Ordering rules that carry the safety:
//! - `Tx_lock` is broadcast only after `σ_J` exists and the taker's encrypted `Tx_refund`
//!   signatures for every `Tx_cancel` encoding verified, so the maker can always get his
//!   DIVI back.
//! - The encrypted `Tx_redeem` signature is produced only after the taker's XMR lock is seen
//!   with `xmr_confirmations`, and only while `t_cancel` is more than `redeem_margin_secs` away.
//! - If `Tx_lock` itself was re-encoded on chain (its txid changed, so `σ_J` signs a spend of
//!   an output that will never exist), the maker never offers redeem and takes the lock back
//!   through the late branch after `t_late`.
//!
//! Every transition and every signed transaction is persisted before the side effect it
//! precedes; [`XmrMaker::step`] is idempotent and safe to re-run after a crash. The keying
//! phase is not: the key share lives only in its [`JSession`], so a restart before `σ_J`
//! aborts the swap (nothing was broadcast yet).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
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
use swap_adaptor::dleq::{random_clamped_secret, CrossCurveDLEQProof, PointQ, ScalarQ};
use swap_chain_xmr::lock_scripts::{self, CancelScript, LockScript, LockSpend, CANCEL_VARIANTS};
use swap_chain_xmr::swap_templates::{maker_completes_tx_refund, maker_encrypts_tx_redeem};

use crate::api::{
    JRoundReply, JRoundRequest, RedeemOffer, SetupReply, SetupRequest, SigsRequest, WireOutpoint,
    XmrLockNotice, XmrSwapView,
};
use crate::chain::{DiviChain, MoneroChain};
use crate::crypto::{self, Signer};
use crate::jsig::{self, JRound, JSession, JStatus, Primes, MAKER};
use crate::{nums, wire, XmrConfig, PICONERO_PER_COUNTER_SAT};

/// Store document kind of maker records. New with C1: records of the pre-C1 kind
/// (`xmr_maker`) have a different shape and are left alone.
pub const KIND: &str = "xmr_maker_c1";

/// Store document kind marking a 2P-ECDSA session id as used (never reused, across restarts).
const SID_KIND: &str = "xmr_maker_jsid";

/// Paillier primes kept ready, so a setup does not wait 20–90 s generating them.
const PRIMES_POOL: usize = 2;

/// Maker-side state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XmrMakerState {
    /// `J` exists; `Tx_lock` built, not broadcast. No coins committed.
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
    /// `Tx_cancel` (some encoding of it) is broadcast or seen.
    Cancelled,
    /// `Tx_refund` is broadcast (DIVI back to the maker; reveals `s_m` to the taker).
    Refunded,
    /// The taker's `Tx_punish` took the DIVI. Terminal.
    Punished,
    /// The maker's late-branch spend of `Tx_lock` is broadcast (no cancel happened).
    Reclaimed,
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
/// mode 0600, like the hashlock taker's preimage). Never holds the `J` share.
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
    /// `a`: per-swap DIVI key.
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
    /// The 2P-ECDSA session id.
    #[serde(with = "wire::b32")]
    pub j_sid: [u8; 32],
    /// `J`.
    #[serde(with = "wire::b33")]
    pub joint_pk: [u8; 33],
    /// `Tx_lock`'s redeem script ([`LockScript`]).
    #[serde(with = "wire::bytes")]
    pub redeem_script: Vec<u8>,
    /// `Tx_cancel`'s redeem script ([`CancelScript`]).
    #[serde(with = "wire::bytes")]
    pub cancel_redeem: Vec<u8>,
    /// `Tx_lock`, signed, broadcast from `Locked` on.
    #[serde(with = "wire::divi_tx")]
    pub tx_lock: Transaction,
    /// The encoding of `Tx_lock` actually mined, when a staker re-encoded it (other txid).
    #[serde(with = "wire::opt_divi_tx")]
    pub lock_actual: Option<Transaction>,
    /// `Tx_lock`'s lock output index.
    pub lock_vout: u32,
    /// Its value, sats.
    pub lock_amount: u64,
    /// `nLockTime` of `Tx_cancel` / `Tx_refund`.
    pub t_cancel: u32,
    /// `nLockTime` of `Tx_punish`.
    pub t_punish: u32,
    /// `nLockTime` of the maker's late spend of `Tx_lock`.
    pub t_late: u32,
    /// Unsigned `Tx_cancel`.
    #[serde(with = "wire::divi_tx")]
    pub tx_cancel: Transaction,
    /// `σ_J` on it (empty until the signing finished).
    #[serde(with = "wire::bytes")]
    pub cancel_sig: Vec<u8>,
    /// Where `Tx_refund` pays us.
    #[serde(with = "wire::bytes")]
    pub refund_script: Vec<u8>,
    /// `Tx_cancel` with `σ_J`, canonically encoded (from `Locked` on).
    #[serde(with = "wire::opt_divi_tx")]
    pub cancel_signed: Option<Transaction>,
    /// The encoding of `Tx_cancel` seen spending `Tx_lock`.
    #[serde(with = "wire::opt_divi_tx")]
    pub cancel_actual: Option<Transaction>,
    /// The `Tx_cancel` signature the taker sent (hex), for idempotent retries of `sigs`.
    pub taker_cancel_sig: Option<String>,
    /// The taker's encrypted `Tx_refund` signatures, by the txid of the `Tx_cancel`
    /// encoding each refund spends.
    pub refund_encsigs: BTreeMap<String, String>,
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
    /// `Tx_refund`, completed and signed (persisted before broadcast), or as seen on chain.
    #[serde(with = "wire::opt_divi_tx")]
    pub refund_signed: Option<Transaction>,
    /// The late-branch spend of `Tx_lock` (persisted before broadcast), or as seen on chain.
    #[serde(with = "wire::opt_divi_tx")]
    pub late_signed: Option<Transaction>,
    /// Last error.
    pub last_error: Option<String>,
}

impl XmrMakerRecord {
    /// `Tx_lock` as it is (or will be) on chain.
    fn lock_tx(&self) -> &Transaction {
        self.lock_actual.as_ref().unwrap_or(&self.tx_lock)
    }

    fn lock_outpoint(&self) -> OutPoint {
        OutPoint::new(self.lock_tx().txid(), self.lock_vout)
    }

    fn cancel_signed(&self) -> Result<&Transaction> {
        self.cancel_signed
            .as_ref()
            .ok_or_else(|| SwapError::Other("no signed Tx_cancel".into()))
    }

    /// The `Tx_cancel` the refund must spend: the one seen, else ours.
    fn cancel_tx(&self) -> Result<&Transaction> {
        match &self.cancel_actual {
            Some(t) => Ok(t),
            None => self.cancel_signed(),
        }
    }

    fn maker_pk(&self) -> [u8; 33] {
        self.divi_key.public_key().serialize_compressed()
    }

    fn shared_spend_key(&self) -> [u8; 32] {
        crypto::shared_spend_key(&crypto::ed_pub(&self.s_m), &self.taker_share)
    }

    fn view(&self) -> XmrSwapView {
        use XmrMakerState::*;
        let redeem = match (&self.tx_redeem, &self.redeem_encsig) {
            (Some(tx), Some(es)) => EncryptedSignature::from_str(es).ok().map(|e| RedeemOffer {
                tx_redeem: tx.clone(),
                maker_redeem_encsig: e,
            }),
            _ => None,
        };
        let broadcast = !matches!(self.state, Accepted | Aborted);
        let cancelled =
            matches!(self.state, Cancelled | Refunded | Punished) || self.refund_signed.is_some();
        XmrSwapView {
            id: self.id.clone(),
            state: self.state,
            quote: self.quote.clone(),
            lock_txid: broadcast.then(|| self.lock_tx().txid().to_hex()),
            xmr_lock_txid: self.xmr_txid.clone(),
            redeem,
            // Cancelled at some point: still in that branch, or refunded since (even if Done).
            cancel_txid: cancelled
                .then(|| self.cancel_tx().ok().map(|t| t.txid().to_hex()))
                .flatten(),
            refund_txid: self.refund_signed.as_ref().map(|t| t.txid().to_hex()),
            last_error: self.last_error.clone(),
            t_cancel: Some(self.t_cancel),
            t_punish: Some(self.t_punish),
            t_late: Some(self.t_late),
            late_txid: self.late_signed.as_ref().map(|t| t.txid().to_hex()),
        }
    }
}

enum Flow {
    Idle,
    Moved,
}

/// An unsigned single-input spend (the shape of every presigned tx).
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

/// What a setup holds before `J` exists (nothing persisted yet).
struct Pending {
    quote: Quote,
    req: SetupRequest,
    divi_key: SecretKey,
    s_m: ScalarQ,
    maker_proof: CrossCurveDLEQProof,
    y_point: Point,
    maker_share: PointQ,
    view_secret: [u8; 32],
}

/// One swap's keying, in memory only: the session holds our `J` share.
/// One swap's keying state; the lock serializes its rounds.
type KeyingSlot = Arc<tokio::sync::Mutex<Keying>>;

struct Keying {
    session: Arc<JSession>,
    pending: Pending,
    /// Built once `J` exists (the record is persisted then).
    setup: Option<SetupReply>,
    /// `σ_J` is out; the session (and the share) is gone.
    signed: bool,
}

/// Prime generator (replaceable in tests).
pub type PrimesFn = Arc<dyn Fn() -> Primes + Send + Sync>;

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
    /// - coin selection for `Tx_lock` happens during keying, under no gate; the live DIVI
    ///   wallet selects and reserves coins under its own wallet lock
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
    /// Swaps still keying, with their start time (pruned after `sigs_wait_secs`). The inner
    /// lock serializes one swap's rounds.
    keying: parking_lot::Mutex<HashMap<String, (u64, KeyingSlot)>>,
    primes: Arc<parking_lot::Mutex<Vec<Primes>>>,
    primes_fn: PrimesFn,
    primes_filling: Arc<AtomicBool>,
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
            keying: parking_lot::Mutex::new(HashMap::new()),
            primes: Arc::new(parking_lot::Mutex::new(Vec::new())),
            primes_fn: Arc::new(jsig::generate_primes),
            primes_filling: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Replace the wall clock (quote expiry, the signatures wait).
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Replace the Paillier prime generator (tests hand out precomputed ones).
    pub fn with_primes(mut self, f: PrimesFn) -> Self {
        self.primes_fn = f;
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

    async fn take_primes(&self) -> Result<Primes> {
        if let Some(p) = self.primes.lock().pop() {
            return Ok(p);
        }
        let f = self.primes_fn.clone();
        jsig::blocking(move || Ok(f())).await
    }

    /// Top the prime pool up in the background (one filler at a time).
    fn refill_primes(&self) {
        if self.primes.lock().len() >= PRIMES_POOL
            || self.primes_filling.swap(true, Ordering::SeqCst)
        {
            return;
        }
        let (pool, f, flag) = (
            self.primes.clone(),
            self.primes_fn.clone(),
            self.primes_filling.clone(),
        );
        tokio::task::spawn_blocking(move || {
            while pool.lock().len() < PRIMES_POOL {
                let p = f();
                pool.lock().push(p);
            }
            flag.store(false, Ordering::SeqCst);
        });
    }

    /// Step 1: verify the taker's DLEQ proof, generate our keys, start our side of the
    /// 2P-ECDSA session for `J` and answer its first round. Nothing is persisted but the
    /// used quote and session id until `J` exists.
    pub async fn setup(&self, req: SetupRequest) -> Result<JRoundReply> {
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
        let sid_key = hex::encode(req.j_sid);
        if self.store.get_doc::<bool>(SID_KIND, &sid_key)?.is_some() {
            return Err(SwapError::InvalidParams(
                "2P-ECDSA session id already used".into(),
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
        qr.used = true;
        self.store.put_quote(&qr)?;
        self.store.put_doc(SID_KIND, &sid_key, &true)?;

        let primes = self.take_primes().await?;
        let id = uuid::Uuid::new_v4().to_string();
        let session = Arc::new(JSession::start(&req.j_sid, MAKER, primes));
        let first = req.j_msgs.clone();
        let s = session.clone();
        let round = jsig::blocking(move || s.round(first)).await?;
        let entry = Arc::new(tokio::sync::Mutex::new(Keying {
            session,
            pending: Pending {
                quote,
                req,
                divi_key,
                s_m,
                maker_proof,
                y_point,
                maker_share,
                view_secret,
            },
            setup: None,
            signed: false,
        }));
        self.keying
            .lock()
            .insert(id.clone(), ((self.clock)(), entry.clone()));
        let mut k = entry.lock().await;
        let res = self.after_round(&id, &mut k, round).await;
        if res.is_err() {
            self.keying.lock().remove(&id);
        }
        res
    }

    /// The taker's next 2P-ECDSA messages: answer them. Once `J` exists the reply carries
    /// the setup (`Tx_lock` and `Tx_cancel`, `Tx_lock` not broadcast) and our signing
    /// messages on `Tx_cancel`; `signed` once our side has `σ_J`.
    pub async fn j_round(&self, swap_id: &str, req: JRoundRequest) -> Result<JRoundReply> {
        let entry = self
            .keying
            .lock()
            .get(swap_id)
            .map(|(_, e)| e.clone())
            .ok_or_else(|| {
                SwapError::InvalidParams(
                    "no 2P-ECDSA session for this swap (finished, expired, or the maker restarted)"
                        .into(),
                )
            })?;
        let mut k = entry.lock().await;
        if k.signed {
            // A retried request after we finished: nothing more to send.
            return Ok(JRoundReply {
                swap_id: swap_id.to_string(),
                msgs: Vec::new(),
                setup: k.setup.clone(),
                signed: true,
            });
        }
        let s = k.session.clone();
        let res = match jsig::blocking(move || s.round(req.msgs)).await {
            Ok(round) => self.after_round(swap_id, &mut k, round).await,
            Err(e) => Err(e),
        };
        if res.is_err() {
            self.keying.lock().remove(swap_id);
        }
        res
    }

    async fn after_round(&self, id: &str, k: &mut Keying, round: JRound) -> Result<JRoundReply> {
        let mut msgs = round.outgoing;
        let mut status = round.status;
        if let JStatus::KeyReady(j) = status {
            if k.setup.is_none() {
                let (reply, digest) = self.persist_setup(id, &k.pending, j).await?;
                k.setup = Some(reply);
                let s = k.session.clone();
                let more = jsig::blocking(move || s.sign(digest)).await?;
                msgs.extend(more.outgoing);
                status = more.status;
            }
        }
        if let JStatus::Signed(sig) = status {
            let lock = self.swap_lock(id);
            let _g = lock.lock().await;
            let mut r = self.load(id)?;
            if !crypto::verify_plain(&r.tx_cancel, &r.redeem_script, &r.joint_pk, &sig) {
                return Err(SwapError::Other(
                    "2P-ECDSA produced an invalid Tx_cancel signature".into(),
                ));
            }
            r.cancel_sig = sig;
            self.store.put_doc(KIND, &r.id, &r)?;
            k.signed = true;
        }
        Ok(JRoundReply {
            swap_id: id.to_string(),
            msgs,
            setup: k.setup.clone(),
            signed: k.signed,
        })
    }

    /// `J` exists: build `Tx_lock` (not broadcast) and `Tx_cancel`, persist the record in
    /// `Accepted`. Returns the setup reply and `Tx_cancel`'s sighash for the signing.
    async fn persist_setup(
        &self,
        id: &str,
        p: &Pending,
        joint_pk: [u8; 33],
    ) -> Result<(SetupReply, [u8; 32])> {
        let maker_pk = p.divi_key.public_key().serialize_compressed();
        let taker_pk = p.req.taker_divi_pubkey;
        let fee = self.cfg.divi_fee_sats;
        let lock_amount = p.quote.divi_amount.0 + fee;
        let mtp = self.divi.median_time_past().await?;
        let t_cancel = mtp
            .checked_add(self.cfg.cancel_after_secs)
            .ok_or_else(|| SwapError::InvalidParams("t_cancel overflow".into()))?;
        let t_punish = t_cancel + self.cfg.punish_after_secs;
        let t_late = t_punish + self.cfg.late_after_secs;
        let lock = LockScript {
            maker: maker_pk,
            taker: taker_pk,
            joint: joint_pk,
            t_cancel,
            t_late,
        };
        let cancel = CancelScript {
            maker: maker_pk,
            taker: taker_pk,
            t_punish,
        };
        let (redeem, spk) = (lock.redeem_script(), lock.script_pubkey());
        let tx_lock = self.divi.build_funding(&spk, lock_amount).await?;
        let lock_vout = tx_lock
            .vout
            .iter()
            .position(|o| o.script_pubkey == spk && o.value.as_sat() as u64 == lock_amount)
            .ok_or_else(|| SwapError::Other("Tx_lock lacks the lock output".into()))?
            as u32;
        let lock_op = OutPoint::new(tx_lock.txid(), lock_vout);
        let tx_cancel = spend(lock_op, lock_amount - fee, cancel.script_pubkey(), t_cancel);
        let digest = crypto::digest(&tx_cancel, &redeem)?;
        let refund_script = self.divi.payout_script().as_bytes().to_vec();
        let rec = XmrMakerRecord {
            id: id.to_string(),
            created_at: (self.clock)(),
            state: XmrMakerState::Accepted,
            quote: p.quote.clone(),
            divi_key: p.divi_key.clone(),
            s_m: p.s_m,
            view_secret: p.view_secret,
            taker_pk,
            taker_payout: p.req.taker_payout_script.clone(),
            x_point: p.req.x_point,
            taker_share: p.req.taker_xmr_share,
            xmr_amount: p.quote.btc_amount.0 * PICONERO_PER_COUNTER_SAT,
            j_sid: p.req.j_sid,
            joint_pk,
            redeem_script: redeem,
            cancel_redeem: cancel.redeem_script(),
            tx_lock,
            lock_actual: None,
            lock_vout,
            lock_amount,
            t_cancel,
            t_punish,
            t_late,
            tx_cancel: tx_cancel.clone(),
            cancel_sig: Vec::new(),
            refund_script: refund_script.clone(),
            cancel_signed: None,
            cancel_actual: None,
            taker_cancel_sig: None,
            refund_encsigs: BTreeMap::new(),
            xmr_txid: None,
            tx_redeem: None,
            redeem_encsig: None,
            s_t: None,
            sweep_txid: None,
            refund_signed: None,
            late_signed: None,
            last_error: None,
        };
        self.store.put_doc(KIND, &rec.id, &rec)?;
        Ok((
            SetupReply {
                swap_id: rec.id.clone(),
                quote: rec.quote.clone(),
                maker_divi_pubkey: maker_pk,
                y_point: p.y_point,
                maker_xmr_share: p.maker_share,
                maker_proof: p.maker_proof.clone(),
                xmr_view_secret: p.view_secret,
                xmr_amount: rec.xmr_amount,
                joint_pubkey: joint_pk,
                lock_outpoint: WireOutpoint::of(&lock_op),
                lock_amount,
                t_cancel,
                t_punish,
                t_late,
                divi_fee_sats: fee,
                tx_cancel,
                maker_refund_script: refund_script,
            },
            digest,
        ))
    }

    /// Step 3: the taker's `Tx_cancel` signature (`σ_J`) and her encrypted `Tx_refund`
    /// signature for every encoding of `Tx_cancel`. All are verified before anything is
    /// broadcast; then `Tx_lock` goes out.
    pub async fn sigs(&self, swap_id: &str, req: SigsRequest) -> Result<XmrSwapView> {
        {
            let lock = self.swap_lock(swap_id);
            let _g = lock.lock().await;
            let mut r = self.load(swap_id)?;
            let cancel_sig = hex::encode(&req.cancel_sig);
            let encsigs: BTreeMap<String, String> = req
                .refund_encsigs
                .iter()
                .map(|e| (e.cancel_txid.clone(), e.encsig.to_string()))
                .collect();
            match r.state {
                XmrMakerState::Accepted => {}
                _ if r.taker_cancel_sig.as_deref() == Some(cancel_sig.as_str())
                    && r.refund_encsigs == encsigs =>
                {
                    return Ok(r.view());
                }
                s => {
                    return Err(SwapError::InvalidParams(format!(
                        "swap is {s:?}, not awaiting signatures"
                    )))
                }
            }
            if r.cancel_sig.is_empty() {
                return Err(SwapError::InvalidParams(
                    "Tx_cancel is not signed under J yet".into(),
                ));
            }
            if !crypto::verify_plain(&r.tx_cancel, &r.redeem_script, &r.joint_pk, &req.cancel_sig) {
                return Err(SwapError::InvalidParams(
                    "the Tx_cancel signature is not valid under J".into(),
                ));
            }
            let cancel_signed = {
                let mut t = r.tx_cancel.clone();
                t.vin[0].script_sig = lock_scripts::cancel_sig(&r.cancel_sig, &r.redeem_script);
                t
            };
            let variants =
                lock_scripts::cancel_variants(&r.tx_cancel, &r.cancel_sig, &r.redeem_script);
            if variants.len() != CANCEL_VARIANTS || encsigs.len() != CANCEL_VARIANTS {
                return Err(SwapError::InvalidParams(format!(
                    "need {CANCEL_VARIANTS} encrypted Tx_refund signatures, got {}",
                    encsigs.len()
                )));
            }
            let y_point = swap_adaptor::adaptor::AdaptorSigner::new()
                .encryption_key_for(&crypto::secp_of(&r.s_m));
            for v in &variants {
                let txid = v.txid().to_hex();
                let encsig = req
                    .refund_encsigs
                    .iter()
                    .find(|e| e.cancel_txid == txid)
                    .ok_or_else(|| {
                        SwapError::InvalidParams(format!(
                            "no encrypted Tx_refund signature for Tx_cancel encoding {txid}"
                        ))
                    })?;
                let (refund, _) = crate::api::after_cancel(
                    v,
                    self.cfg.divi_fee_sats,
                    &r.refund_script,
                    &r.taker_payout,
                    r.t_cancel,
                    r.t_punish,
                );
                if !crypto::verify_encrypted(
                    &refund,
                    &r.cancel_redeem,
                    &r.taker_pk,
                    &y_point,
                    &encsig.encsig,
                ) {
                    return Err(SwapError::InvalidParams(format!(
                        "taker's encrypted Tx_refund signature for {txid} is invalid"
                    )));
                }
            }
            r.taker_cancel_sig = Some(cancel_sig);
            r.refund_encsigs = encsigs;
            r.cancel_signed = Some(cancel_signed);
            self.enter(&mut r, XmrMakerState::Locked)?; // persisted before Tx_lock goes out
        }
        self.keying.lock().remove(swap_id);
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
    /// Also drops stale keying sessions and keeps the prime pool full.
    pub async fn tick(&self) -> Result<()> {
        let now = (self.clock)();
        let wait = self.cfg.sigs_wait_secs;
        self.keying
            .lock()
            .retain(|_, (at, k)| now <= *at + wait || k.try_lock().is_err());
        self.refill_primes();
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
                    self.keying.lock().remove(&r.id);
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
            Refunded => self.on_refunded(r).await,
            Reclaimed => self.on_reclaimed(r).await,
            Punished | Aborted | Done => Ok(Flow::Idle),
        }
    }

    /// A different encoding of `Tx_lock` (same inputs, same lock output, other txid) is
    /// what spends our funding input: a staker re-encoded it.
    async fn malleated_lock(&self, r: &XmrMakerRecord) -> Result<Option<Transaction>> {
        let canonical = OutPoint::new(r.tx_lock.txid(), r.lock_vout);
        if self.divi.output(&canonical).await?.is_some() {
            return Ok(None);
        }
        let Some(input) = r.tx_lock.vin.first() else {
            return Ok(None);
        };
        match self.divi.find_spend(&input.prevout).await? {
            Some(sp) if sp.txid() != r.tx_lock.txid() => {
                let want = &r.tx_lock.vout[r.lock_vout as usize];
                let same = sp.vout.get(r.lock_vout as usize).is_some_and(|o| {
                    o.value == want.value && o.script_pubkey == want.script_pubkey
                });
                if same {
                    Ok(Some(sp))
                } else {
                    Err(SwapError::Other(format!(
                        "Tx_lock's funding input was spent by an unrelated tx {}",
                        sp.txid().to_hex()
                    )))
                }
            }
            _ => Ok(None),
        }
    }

    /// `Tx_lock` is (being) broadcast: watch it, offer redeem once the XMR is locked, recover
    /// `s_t` if the taker redeemed, cancel past `t_cancel`, take it back late if it was
    /// re-encoded.
    async fn on_locked(&self, r: &mut XmrMakerRecord) -> Result<Flow> {
        if r.lock_actual.is_none() {
            // Broadcasting our encoding is the cheap test: only a spent funding input refuses
            // it. Just then look for the spender, a scan from the funding coin's height
            // (thousands of blocks on a remote node for an old coin).
            if let Err(e) = self.divi.broadcast(&r.tx_lock).await {
                if !matches!(e, SwapError::Rejected(_)) {
                    return Err(e);
                }
                let Some(actual) = self.malleated_lock(r).await? else {
                    return Err(e);
                };
                tracing::warn!(swap = %r.id, txid = %actual.txid().to_hex(),
                    "Tx_lock was re-encoded on chain: no redeem, late branch only");
                r.lock_actual = Some(actual);
                r.last_error = Some(
                    "Tx_lock was re-encoded on chain: Tx_cancel is void, reclaiming after t_late"
                        .into(),
                );
                self.store.put_doc(KIND, &r.id, r)?;
                return Ok(Flow::Moved);
            }
        } else {
            self.divi.broadcast(&r.lock_tx().clone()).await?;
        }
        let lock_op = r.lock_outpoint();
        if let Some(spender) = self.divi.find_spend(&lock_op).await? {
            return match lock_scripts::lock_spend_branch(&spender, &r.redeem_script) {
                Some(LockSpend::Cancel) => {
                    r.cancel_actual = Some(spender);
                    self.enter(r, XmrMakerState::Cancelled)
                }
                Some(LockSpend::Late) => {
                    r.late_signed = Some(spender);
                    self.enter(r, XmrMakerState::Reclaimed)
                }
                // Both signatures: the taker's completed Tx_redeem, and our completed
                // signature in it reveals s_t.
                Some(LockSpend::Redeem { .. }) => {
                    let encsig = r
                        .redeem_encsig
                        .as_deref()
                        .and_then(|s| EncryptedSignature::from_str(s).ok())
                        .ok_or_else(|| {
                            SwapError::Other("Tx_lock redeemed before redeem was offered".into())
                        })?;
                    let s_t = crypto::recover(&spender, Signer::Maker, &r.x_point, &encsig)
                        .filter(|s| crypto::ed_pub(s) == r.taker_share)
                        .ok_or_else(|| {
                            SwapError::Other("could not recover s_t from Tx_redeem".into())
                        })?;
                    r.s_t = Some(hex::encode(s_t.to_bytes()));
                    self.enter(r, XmrMakerState::Redeemed)
                }
                None => Err(SwapError::Other(format!(
                    "Tx_lock spent by {}, which matches no branch",
                    spender.txid().to_hex()
                ))),
            };
        }
        let mtp = self.divi.median_time_past().await?;
        if r.lock_actual.is_some() {
            // σ_J signed a spend of the canonical txid, which will never exist.
            if mtp > r.t_late {
                return self.reclaim(r).await;
            }
            return Ok(Flow::Idle);
        }
        if mtp > r.t_cancel {
            let tx = r.cancel_signed()?.clone();
            match self.divi.broadcast(&tx).await {
                Ok(()) => {
                    r.cancel_actual = Some(tx);
                    return self.enter(r, XmrMakerState::Cancelled);
                }
                Err(SwapError::Premature(_)) => return Ok(Flow::Idle),
                // Another spend won the race (Tx_redeem, or another Tx_cancel encoding in
                // the mempool): the next pass classifies it.
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

    /// Past `t_late` with `Tx_lock` unspent: take it back alone (late branch).
    async fn reclaim(&self, r: &mut XmrMakerRecord) -> Result<Flow> {
        let tx = match r.late_signed.clone() {
            Some(t) => t,
            None => {
                let mut t = spend(
                    r.lock_outpoint(),
                    r.lock_amount - self.cfg.divi_fee_sats,
                    Script::from_bytes(r.refund_script.clone()),
                    r.t_late,
                );
                let sig = crypto::sign_plain(&t, &r.redeem_script, &r.divi_key)?;
                t.vin[0].script_sig = lock_scripts::late_sig(&sig, &r.redeem_script);
                r.late_signed = Some(t.clone());
                self.store.put_doc(KIND, &r.id, r)?; // write-ahead
                t
            }
        };
        match self.divi.broadcast(&tx).await {
            Ok(()) => self.enter(r, XmrMakerState::Reclaimed),
            Err(SwapError::Premature(_)) => Ok(Flow::Idle),
            Err(e) => Err(e),
        }
    }

    async fn on_reclaimed(&self, r: &mut XmrMakerRecord) -> Result<Flow> {
        if let Some(sp) = self.divi.find_spend(&r.lock_outpoint()).await? {
            if self.divi.confirmations(&sp.txid()).await?.unwrap_or(0) >= 1 {
                r.late_signed = Some(sp);
                return self.enter(r, XmrMakerState::Done);
            }
            return Ok(Flow::Idle);
        }
        if let Some(t) = r.late_signed.clone() {
            self.divi.broadcast(&t).await?; // dropped from the mempool? same bytes again
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

    /// The `Tx_cancel` encoding that spends `Tx_lock`, once seen (recorded); until then
    /// ours, (re)broadcast.
    async fn actual_cancel(&self, r: &mut XmrMakerRecord) -> Result<Transaction> {
        match self.divi.find_spend(&r.lock_outpoint()).await? {
            Some(sp) => match lock_scripts::lock_spend_branch(&sp, &r.redeem_script) {
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
                let c = r.cancel_tx()?.clone();
                match self.divi.broadcast(&c).await {
                    // Rejected: another encoding is in the mempool; seen once mined.
                    Ok(()) | Err(SwapError::Rejected(_)) => Ok(c),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// `Tx_cancel` is out: refund (revealing `s_m`) unless the taker punished first.
    async fn on_cancelled(&self, r: &mut XmrMakerRecord) -> Result<Flow> {
        let cancel = self.actual_cancel(r).await?;
        let cancel_op = OutPoint::new(cancel.txid(), 0);
        if let Some(spender) = self.divi.find_spend(&cancel_op).await? {
            if lock_scripts::refund_spend_sigs(&spender, &r.cancel_redeem).is_some() {
                r.refund_signed = Some(spender); // ours, as mined (maybe re-encoded)
                return self.enter(r, XmrMakerState::Refunded);
            }
            r.last_error = Some("the taker punished: Tx_punish took the DIVI".into());
            return self.enter(r, XmrMakerState::Punished);
        }
        let refund = match r
            .refund_signed
            .clone()
            .filter(|t| t.vin[0].prevout == cancel_op)
        {
            Some(t) => t,
            None => {
                let txid = cancel.txid().to_hex();
                let encsig = r
                    .refund_encsigs
                    .get(&txid)
                    .and_then(|s| EncryptedSignature::from_str(s).ok())
                    .ok_or_else(|| {
                        SwapError::Other(format!(
                            "Tx_cancel {txid} is not one of the {CANCEL_VARIANTS} encodings the \
                             taker signed a refund for"
                        ))
                    })?;
                let (unsigned, _) = crate::api::after_cancel(
                    &cancel,
                    self.cfg.divi_fee_sats,
                    &r.refund_script,
                    &r.taker_payout,
                    r.t_cancel,
                    r.t_punish,
                );
                let t = maker_completes_tx_refund(
                    unsigned,
                    &r.cancel_redeem,
                    &crypto::point_of_pubkey(&r.taker_pk)?,
                    encsig,
                    &r.divi_key,
                    &crypto::secp_of(&r.s_m),
                )
                .map_err(|e| SwapError::Other(format!("Tx_refund: {e}")))?;
                let t = crypto::two_key(t, &r.cancel_redeem)?;
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

    async fn on_refunded(&self, r: &mut XmrMakerRecord) -> Result<Flow> {
        let cancel_op = OutPoint::new(r.cancel_tx()?.txid(), 0);
        if let Some(sp) = self.divi.find_spend(&cancel_op).await? {
            if lock_scripts::refund_spend_sigs(&sp, &r.cancel_redeem).is_none() {
                r.last_error = Some("the taker punished: Tx_punish took the DIVI".into());
                return self.enter(r, XmrMakerState::Punished);
            }
            if self.divi.confirmations(&sp.txid()).await?.unwrap_or(0) >= 1 {
                r.refund_signed = Some(sp);
                return self.enter(r, XmrMakerState::Done);
            }
            return Ok(Flow::Idle);
        }
        let tx = r
            .refund_signed
            .clone()
            .ok_or_else(|| SwapError::Other("Refunded without a refund tx".into()))?;
        self.divi.broadcast(&tx).await?; // dropped from the mempool? same bytes again
        Ok(Flow::Idle)
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
