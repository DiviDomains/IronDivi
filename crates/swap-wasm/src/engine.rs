// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The taker as the extension drives it: begin, lock, tick, refund.

use std::sync::Arc;

use divi_swap::api::{Direction, Offer, SwapView};
use divi_swap::store::{StoreBackend, Table};
use divi_swap::{
    rt, Chain, ChainBackend, Outpoint, Profile, QuoteIntent, Result, Store, SwapError, Taker,
    TakerState, Txid,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use swap_chain_divi::{DiviBackend, Utxo};
use swap_keys::{Net, SwapKeys};

use crate::durable::{Durable, Persister, Sink, WALLET_DOC};
use crate::maker::MakerClient;
use crate::selection::{SelectionSpec, Selections};
use crate::store::EncryptedStore;
use crate::view::SwapSummary;

/// `Table::Docs` namespace for per-swap hashlock tokens issued by `POST /swaps`.
const SWAP_TOKEN_DOC: &str = "swap_token";

#[derive(Serialize, Deserialize)]
struct StoredSwapToken {
    token: String,
}

/// Endpoints. Testnet only: the engine derives testnet keys whatever this says.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub maker_url: String,
    pub divi_rpc: String,
    pub btc_endpoints: Vec<String>,
    pub ltc_endpoints: Vec<String>,
    /// Address index of the swap keys (the extension's own DIVI address is 0).
    #[serde(default)]
    pub index: u32,
    /// The timeout and confirmation floor a maker's terms are held to before anything is
    /// accepted or locked ([`Taker::with_profile_floor`]). Default `testnet`; `mainnet` is
    /// only ever stricter.
    #[serde(default = "testnet")]
    pub profile: Profile,
}

fn testnet() -> Profile {
    Profile::Testnet
}

/// Largest integer a JS number holds exactly (`Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_JS_INTEGER: u64 = (1 << 53) - 1;

/// An offer as the UI shows it: the offer itself (JSON numbers, which JS rounds past
/// [`MAX_SAFE_JS_INTEGER`]) plus its amounts as exact decimal strings, and the selection
/// token that pins exactly these terms ([`crate::selection`]). `selection` is `null` and
/// `ambiguous` true when the maker listed the id more than once: such an offer cannot be
/// taken.
#[derive(Debug, Clone, Serialize)]
pub struct OfferView {
    #[serde(flatten)]
    pub offer: Offer,
    pub exact: ExactTerms,
    pub selection: Option<String>,
    pub ambiguous: bool,
}

/// An offer's u64 terms as decimal strings.
#[derive(Debug, Clone, Serialize)]
pub struct ExactTerms {
    pub divi_sats_per_btc: String,
    pub min_btc_sats: String,
    pub max_btc_sats: String,
}

impl OfferView {
    fn new(offer: Offer, selection: Option<String>) -> Self {
        OfferView {
            exact: ExactTerms {
                divi_sats_per_btc: offer.divi_sats_per_btc.to_string(),
                min_btc_sats: offer.min_btc_sats.to_string(),
                max_btc_sats: offer.max_btc_sats.to_string(),
            },
            ambiguous: selection.is_none(),
            selection,
            offer,
        }
    }
}

/// The extension's explicit limits for `beginWithIntent`. Every u64 is a decimal string or
/// a JSON integer no larger than [`MAX_SAFE_JS_INTEGER`]; unknown keys are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentSpec {
    pub offer_id: String,
    pub btc_sats: serde_json::Value,
    pub counter_chain: Chain,
    pub direction: Direction,
    pub limit_divi_sats_per_btc: serde_json::Value,
    #[serde(default)]
    pub min_remaining_secs: Option<serde_json::Value>,
    #[serde(default)]
    pub max_taker_timeout_secs: Option<u32>,
}

impl IntentSpec {
    /// Parse `json` into the [`QuoteIntent`] it describes.
    pub fn parse(json: &str) -> Result<QuoteIntent> {
        let spec: IntentSpec = serde_json::from_str(json)
            .map_err(|e| SwapError::InvalidParams(format!("bad intent: {e}")))?;
        spec.intent()
    }

    pub fn intent(&self) -> Result<QuoteIntent> {
        let mut intent = QuoteIntent::with_limit(
            &self.offer_id,
            exact_u64("btc_sats", &self.btc_sats)?,
            self.counter_chain,
            self.direction,
            exact_u64("limit_divi_sats_per_btc", &self.limit_divi_sats_per_btc)?,
        )?
        .with_max_taker_timeout_secs(self.max_taker_timeout_secs);
        if let Some(v) = &self.min_remaining_secs {
            intent = intent.with_min_remaining_secs(exact_u64("min_remaining_secs", v)?);
        }
        Ok(intent)
    }
}

/// A u64 from JS without rounding: a decimal string of digits, or a JSON integer JS can hold
/// exactly. Fractions, exponents, negatives and unsafe integers are refused.
pub fn exact_u64(name: &str, v: &serde_json::Value) -> Result<u64> {
    let bad = || SwapError::InvalidParams(format!("{name}: not an exact amount: {v}"));
    match v {
        serde_json::Value::String(s) => {
            if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            s.parse().map_err(|_| bad())
        }
        serde_json::Value::Number(n) => n
            .as_u64()
            .filter(|&n| n <= MAX_SAFE_JS_INTEGER)
            .ok_or_else(bad),
        _ => Err(bad()),
    }
}

/// A DIVI coin as the extension's address index reports it (`getaddressutxos`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoinIn {
    pub txid: String,
    pub output_index: u32,
    pub satoshis: u64,
}

/// The taker's own addresses, for funding and display.
#[derive(Debug, Clone, Serialize)]
pub struct Addresses {
    pub divi: String,
    pub btc: String,
    pub ltc: String,
}

/// One browser taker over one seed.
pub struct Engine {
    taker: Taker,
    maker: MakerClient,
    store: Store,
    persister: Arc<Persister>,
    divi: Arc<DiviBackend>,
    addresses: Addresses,
    /// Every offer selection [`offers`](Self::offers) issued, by token: what
    /// [`begin_selected`](Self::begin_selected) holds a quote to. Never rewritten by a later
    /// listing.
    selections: Mutex<Selections>,
}

impl Engine {
    /// Build the engine for `seed` over `store`, persisting through `sink`.
    pub fn new(
        seed: &[u8],
        cfg: &Config,
        store: Arc<EncryptedStore>,
        sink: Arc<dyn Sink>,
    ) -> Result<Self> {
        let keys = SwapKeys::from_seed(seed, Net::Testnet, cfg.index)
            .map_err(|e| SwapError::Secret(e.to_string()))?;
        let divi = Arc::new(DiviBackend::new(
            &cfg.divi_rpc,
            keys.divi.clone(),
            divi_wallet::Network::Testnet,
            swap_chain_divi::FeePolicy::default(),
            None,
        )?);
        if let Some(json) = store.get(Table::Docs(WALLET_DOC.0), WALLET_DOC.1)? {
            divi.load_wallet_json(&json)?;
        }
        let btc = swap_chain_btc::BtcBackend::new(
            cfg.btc_endpoints.clone(),
            keys.btc,
            swap_chain_btc::FeePolicy::default(),
            swap_chain_btc::RetryPolicy::default(),
        )?;
        let ltc = swap_chain_ltc::LtcBackend::new(
            cfg.ltc_endpoints.clone(),
            keys.ltc,
            swap_chain_ltc::FeePolicy::default(),
            swap_chain_ltc::RetryPolicy::default(),
        )?;
        let addresses = Addresses {
            divi: divi.address(),
            btc: btc.address().to_string(),
            ltc: ltc.address().to_string(),
        };
        let backend: Arc<dyn StoreBackend> = store.clone();
        let swaps = Store::with_backend(backend);
        let persister = Arc::new(Persister::new(store, Some(divi.clone()), sink));
        let durable = |b: Arc<dyn ChainBackend>| -> Arc<dyn ChainBackend> {
            Arc::new(Durable::new(b, persister.clone()))
        };
        let taker = Taker::with_counters(
            durable(divi.clone()),
            vec![durable(Arc::new(btc)), durable(Arc::new(ltc))],
            swaps.clone(),
        )
        .with_profile_floor(cfg.profile);
        Ok(Engine {
            taker,
            maker: MakerClient::new(&cfg.maker_url)?,
            store: swaps,
            persister,
            divi,
            addresses,
            selections: Mutex::new(Selections::random()?),
        })
    }

    /// Assemble from parts (tests drive mock chains through this). `taker` keeps whatever
    /// profile floor it was built with.
    pub fn from_parts(
        taker: Taker,
        maker: MakerClient,
        store: Store,
        persister: Arc<Persister>,
        divi: Arc<DiviBackend>,
        addresses: Addresses,
    ) -> Result<Self> {
        Ok(Engine {
            taker,
            maker,
            store,
            persister,
            divi,
            addresses,
            selections: Mutex::new(Selections::random()?),
        })
    }

    /// The profile floor quotes are held to, if any.
    pub fn profile_floor(&self) -> Option<Profile> {
        self.taker.profile_floor()
    }

    /// The taker's addresses.
    pub fn addresses(&self) -> &Addresses {
        &self.addresses
    }

    /// The maker's offers for chains this taker holds a key on, each with a selection token
    /// for exactly the terms returned. Each call is a new listing: it adds tokens and never
    /// changes what an earlier token selects, so another view or a refresh cannot alter the
    /// terms a user is looking at. An id the maker lists more than once (on any chain) gets
    /// no token.
    pub async fn offers(&self) -> Result<Vec<OfferView>> {
        let chains = self.taker.counter_chains();
        let listed = self.maker.offers().await?;
        let offers: Vec<Offer> = listed
            .iter()
            .filter(|o| chains.contains(&o.counter_chain))
            .cloned()
            .collect();
        let tokens = self.selections.lock().record(
            listed.iter().map(|o| o.id.as_str()),
            &offers,
            rt::unix_now(),
        )?;
        Ok(offers
            .into_iter()
            .zip(tokens)
            .map(|(o, t)| OfferView::new(o, t))
            .collect())
    }

    /// Quote and accept on the offer `spec.selection` names, held to the terms that listing
    /// returned for it ([`QuoteIntent::for_offer`]). `spec` repeats every term the UI showed
    /// and must match them exactly. Refused without a request when the selection is unknown
    /// (never issued, or forgotten across a restart or lock), stale, or for an ambiguous id.
    /// Nothing is locked yet.
    pub async fn begin_selected(&self, spec: &SelectionSpec) -> Result<SwapSummary> {
        let offer = self
            .selections
            .lock()
            .get(&spec.selection, rt::unix_now())?;
        self.begin_with_intent(&spec.intent(&offer)?).await
    }

    /// Age every selection by `secs` (tests only).
    #[cfg(test)]
    pub(crate) fn age_selections(&self, secs: u64) {
        self.selections.lock().age(secs);
    }

    /// Quote and accept per `intent`: the maker's quote must honour it
    /// ([`QuoteIntent::check_quote`]) and, under the profile floor, its HTLC timing must be
    /// workable ([`QuoteIntent::check_htlc_terms`]) before a preimage is generated; it must
    /// still have `intent.min_remaining_secs` to run after the swap is persisted, right
    /// before it is accepted. Nothing is locked yet.
    pub async fn begin_with_intent(&self, intent: &QuoteIntent) -> Result<SwapSummary> {
        intent.validate()?;
        if !self.taker.counter_chains().contains(&intent.counter_chain) {
            return Err(SwapError::InvalidParams(format!(
                "no key for {}",
                intent.counter_chain.as_str()
            )));
        }
        let quote = self.maker.quote(&intent.offer_id, intent.btc_sats).await?;
        intent.check_quote(&quote, rt::unix_now())?;
        if let Some(p) = self.taker.profile_floor() {
            intent.check_htlc_terms(&quote, p, &|c| self.taker.claim_deadline(c))?;
        }
        let (id, req) = self.taker.prepare(&quote).await?;
        self.persister.save().await?;
        intent.check_deadline(&quote, rt::unix_now())?;
        let reply = self.maker.accept(&req).await?;
        if let Some(token) = reply.swap_token.filter(|t| !t.is_empty()) {
            self.store
                .put_doc(SWAP_TOKEN_DOC, &reply.view.id, &StoredSwapToken { token })?;
        }
        self.taker.accepted(&id, &reply.view).await?;
        self.persister.save().await?;
        self.summary(&id)
    }

    /// Lock the taker leg and tell the maker. Once the lock is broadcast a maker failure is
    /// not an error: [`tick`](Self::tick) re-sends the notice.
    pub async fn lock(&self, id: &str) -> Result<SwapSummary> {
        let notice = self.taker.lock(id).await?;
        self.persister.save().await?;
        let maker_id = self.maker_id(id)?;
        let token = self.swap_token(&maker_id)?;
        let _ = self.maker.lock(&maker_id, token.as_deref(), &notice).await;
        self.summary(id)
    }

    /// Advance every open swap: claim, refund, or re-announce a lock the maker missed.
    pub async fn tick(&self) -> Result<Vec<SwapSummary>> {
        for r in self.store.list_taker_swaps()? {
            if matches!(
                r.state,
                TakerState::Done | TakerState::Prepared | TakerState::Accepted
            ) {
                continue;
            }
            let token = match &r.maker_swap_id {
                Some(m) => self.swap_token(m)?,
                None => None,
            };
            let view: Option<SwapView> = match &r.maker_swap_id {
                Some(m) => self.maker.swap(m, token.as_deref()).await.ok(),
                None => None,
            };
            if r.state == TakerState::Locked {
                let before_timeout = r
                    .taker_leg_htlc
                    .is_some_and(|h| rt::unix_now() < h.locktime as u64);
                if before_timeout {
                    if let Some(v) = &view {
                        if v.taker_leg.outpoint.is_none()
                            && v.state == divi_swap::SwapState::Accepted
                        {
                            if let Ok(notice) = self.taker.lock(&r.id).await {
                                let _ = self.persister.save().await;
                                if self
                                    .maker
                                    .lock(&v.id, token.as_deref(), &notice)
                                    .await
                                    .is_ok()
                                {
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
            // Errors are recorded on the swap (last_error) and retried next tick.
            let _ = self.taker.step(&r.id, view.as_ref()).await;
        }
        self.persister.save().await?;
        self.swaps()
    }

    /// Refund the taker leg once its timeout has passed; never claims.
    pub async fn refund(&self, id: &str) -> Result<SwapSummary> {
        let _ = self.taker.refund(id).await;
        self.persister.save().await?;
        self.summary(id)
    }

    /// Every swap, newest first.
    pub fn swaps(&self) -> Result<Vec<SwapSummary>> {
        Ok(self
            .store
            .list_taker_swaps()?
            .iter()
            .map(SwapSummary::from)
            .collect())
    }

    /// Replace the DIVI coin set with the address index's view; returns how many coins
    /// were new.
    pub async fn sync_divi_coins(&self, coins: &[CoinIn]) -> Result<usize> {
        let utxos = coins
            .iter()
            .map(|c| {
                Ok(Utxo {
                    outpoint: Outpoint {
                        txid: Txid::from_rpc_hex(&c.txid)?,
                        vout: c.output_index,
                    },
                    value: c.satoshis,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let added = self.divi.sync_coins(&utxos)?;
        self.persister.save().await?;
        Ok(added)
    }

    /// Chains the taker can trade DIVI against.
    pub fn counter_chains(&self) -> Vec<Chain> {
        self.taker.counter_chains()
    }

    fn maker_id(&self, id: &str) -> Result<String> {
        self.store
            .get_taker_swap(id)?
            .and_then(|r| r.maker_swap_id)
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown swap {id}")))
    }

    fn swap_token(&self, maker_id: &str) -> Result<Option<String>> {
        Ok(self
            .store
            .get_doc::<StoredSwapToken>(SWAP_TOKEN_DOC, maker_id)?
            .map(|d| d.token)
            .filter(|t| !t.is_empty()))
    }

    fn summary(&self, id: &str) -> Result<SwapSummary> {
        self.store
            .get_taker_swap(id)?
            .as_ref()
            .map(SwapSummary::from)
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown swap {id}")))
    }
}
