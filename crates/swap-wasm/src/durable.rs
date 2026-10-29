// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Persist before broadcast.
//!
//! The engine writes a swap's record (preimage included) before it broadcasts, but in the
//! browser a write only reaches the in-memory [`EncryptedStore`] until the host stores it.
//! [`Durable`] wraps each chain backend so that every broadcast first flushes the pending
//! records to the host and refuses to broadcast if that fails: coins never move while the
//! secret that recovers them exists only in memory.

use std::sync::Arc;

use async_trait::async_trait;
use divi_swap::store::{StoreBackend, Table};
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, LockedOutput, Outpoint, Result, SignedTx,
    SpendInfo, SwapError, Txid,
};
use parking_lot::Mutex;
use swap_chain_divi::DiviBackend;

use crate::store::{EncryptedStore, Entry};

/// Where sealed entries go: `chrome.storage.local` in the extension.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Sink: Send + Sync {
    /// Store `entries` durably; `Err` means none can be assumed stored.
    async fn persist(&self, entries: &[Entry]) -> std::result::Result<(), String>;
}

/// Flushes the store (and the DIVI wallet's coin set) to the [`Sink`].
pub struct Persister {
    store: Arc<EncryptedStore>,
    divi: Option<Arc<DiviBackend>>,
    last_wallet: Mutex<Option<String>>,
    sink: Arc<dyn Sink>,
    gate: tokio::sync::Mutex<()>,
}

/// Document kind and id of the DIVI wallet's coin set.
pub const WALLET_DOC: (&str, &str) = ("divi_wallet", "wallet");

impl Persister {
    /// New persister; `divi`'s coin set is saved with the swaps.
    pub fn new(
        store: Arc<EncryptedStore>,
        divi: Option<Arc<DiviBackend>>,
        sink: Arc<dyn Sink>,
    ) -> Self {
        Persister {
            store,
            divi,
            last_wallet: Mutex::new(None),
            sink,
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Persist everything written so far. Saves are serialised, so entries reach the sink
    /// in write order.
    pub async fn save(&self) -> Result<()> {
        let _gate = self.gate.lock().await;
        if let Some(divi) = &self.divi {
            let json = divi.wallet_json()?;
            let changed = self.last_wallet.lock().as_deref() != Some(json.as_str());
            if changed {
                self.store
                    .put(Table::Docs(WALLET_DOC.0), WALLET_DOC.1, &json, None)?;
                *self.last_wallet.lock() = Some(json);
            }
        }
        let pending = self.store.take_pending();
        if pending.is_empty() {
            return Ok(());
        }
        if let Err(e) = self.sink.persist(&pending).await {
            self.store.requeue(pending);
            return Err(SwapError::Storage(format!(
                "cannot persist swap state: {e}"
            )));
        }
        Ok(())
    }
}

/// A chain backend whose broadcasts wait for [`Persister::save`].
pub struct Durable {
    inner: Arc<dyn ChainBackend>,
    persister: Arc<Persister>,
}

impl Durable {
    /// Wrap `inner`.
    pub fn new(inner: Arc<dyn ChainBackend>, persister: Arc<Persister>) -> Self {
        Durable { inner, persister }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ChainBackend for Durable {
    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn pubkey(&self) -> [u8; 33] {
        self.inner.pubkey()
    }

    async fn tip_height(&self) -> Result<u64> {
        self.inner.tip_height().await
    }

    async fn median_time_past(&self) -> Result<u32> {
        self.inner.median_time_past().await
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        self.inner.build_funding(htlc, amount).await
    }

    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx> {
        self.inner.build_claim(htlc, at, amount, preimage).await
    }

    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        self.inner.build_refund(htlc, at, amount).await
    }

    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        self.persister.save().await?;
        let sent = self.inner.broadcast(tx).await;
        // The backend may have marked coins spent; a failure here is retried next save.
        let _ = self.persister.save().await;
        sent
    }

    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        self.inner.confirmations(txid).await
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        self.inner.htlc_output(htlc, at).await
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        self.inner.find_spend(outpoint, from_height).await
    }
}
