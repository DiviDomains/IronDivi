// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The taker as the extension drives it: begin, lock, tick, refund.

use std::sync::Arc;

use divi_swap::api::{Offer, SwapView};
use divi_swap::store::{StoreBackend, Table};
use divi_swap::{
    rt, Chain, ChainBackend, Outpoint, Result, Store, SwapError, Taker, TakerState, Txid,
};
use serde::{Deserialize, Serialize};
use swap_chain_divi::{DiviBackend, Utxo};
use swap_keys::{Net, SwapKeys};

use crate::durable::{Durable, Persister, Sink, WALLET_DOC};
use crate::maker::MakerClient;
use crate::store::EncryptedStore;
use crate::view::SwapSummary;

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
        );
        Ok(Engine {
            taker,
            maker: MakerClient::new(&cfg.maker_url)?,
            store: swaps,
            persister,
            divi,
            addresses,
        })
    }

    /// Assemble from parts (tests drive mock chains through this).
    pub fn from_parts(
        taker: Taker,
        maker: MakerClient,
        store: Store,
        persister: Arc<Persister>,
        divi: Arc<DiviBackend>,
        addresses: Addresses,
    ) -> Self {
        Engine {
            taker,
            maker,
            store,
            persister,
            divi,
            addresses,
        }
    }

    /// The taker's addresses.
    pub fn addresses(&self) -> &Addresses {
        &self.addresses
    }

    /// The maker's offers for chains this taker holds a key on.
    pub async fn offers(&self) -> Result<Vec<Offer>> {
        let chains = self.taker.counter_chains();
        let offers = self.maker.offers().await?;
        Ok(offers
            .into_iter()
            .filter(|o| chains.contains(&o.counter_chain))
            .collect())
    }

    /// Quote and accept `btc_sats` of the counter coin on `offer_id`. Nothing is locked yet.
    pub async fn begin(&self, offer_id: &str, btc_sats: u64) -> Result<SwapSummary> {
        let quote = self.maker.quote(offer_id, btc_sats).await?;
        if quote.offer_id != offer_id || quote.btc_amount.to_sat() != btc_sats {
            return Err(SwapError::Rejected(
                "the maker quoted something other than what was asked".into(),
            ));
        }
        if quote.expires_at <= rt::unix_now() {
            return Err(SwapError::Rejected("the quote has already expired".into()));
        }
        if !self.taker.counter_chains().contains(&quote.counter_chain) {
            return Err(SwapError::InvalidParams(format!(
                "no key for {}",
                quote.counter_chain.as_str()
            )));
        }
        let (id, req) = self.taker.prepare(&quote).await?;
        self.persister.save().await?;
        let view = self.maker.accept(&req).await?;
        self.taker.accepted(&id, &view).await?;
        self.persister.save().await?;
        self.summary(&id)
    }

    /// Lock the taker leg and tell the maker. Once the lock is broadcast a maker failure is
    /// not an error: [`tick`](Self::tick) re-sends the notice.
    pub async fn lock(&self, id: &str) -> Result<SwapSummary> {
        let notice = self.taker.lock(id).await?;
        self.persister.save().await?;
        let maker_id = self.maker_id(id)?;
        let _ = self.maker.lock(&maker_id, &notice).await;
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
            let view: Option<SwapView> = match &r.maker_swap_id {
                Some(m) => self.maker.swap(m).await.ok(),
                None => None,
            };
            if r.state == TakerState::Locked {
                if let Some(v) = &view {
                    if v.taker_leg.outpoint.is_none() {
                        if let Ok(notice) = self.taker.lock(&r.id).await {
                            let _ = self.persister.save().await;
                            let _ = self.maker.lock(&v.id, &notice).await;
                        }
                        continue;
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

    fn summary(&self, id: &str) -> Result<SwapSummary> {
        self.store
            .get_taker_swap(id)?
            .as_ref()
            .map(SwapSummary::from)
            .ok_or_else(|| SwapError::InvalidParams(format!("unknown swap {id}")))
    }
}
