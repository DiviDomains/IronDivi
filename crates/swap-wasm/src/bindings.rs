// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! JavaScript surface. Every async method returns a Promise of a JSON string; errors
//! reject with an `Error` whose message is the engine's.

use std::rc::Rc;
use std::sync::Arc;

use async_trait::async_trait;
use js_sys::{Function, Promise};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, JsFuture};
use zeroize::Zeroizing;

use crate::durable::Sink;
use crate::engine::{CoinIn, Config, Engine, IntentSpec};
use crate::selection::SelectionSpec;
use crate::store::{store_prefix, EncryptedStore, Entry};

/// Calls the host's `persist(entriesJson)`, which returns a Promise.
struct JsSink {
    persist: Function,
}

// SAFETY: wasm32 without threads; the function never leaves the one JS thread.
unsafe impl Send for JsSink {}
unsafe impl Sync for JsSink {}

#[async_trait(?Send)]
impl Sink for JsSink {
    async fn persist(&self, entries: &[Entry]) -> Result<(), String> {
        let json = serde_json::to_string(entries).map_err(|e| e.to_string())?;
        let ret = self
            .persist
            .call1(&JsValue::NULL, &JsValue::from_str(&json))
            .map_err(js_message)?;
        if let Ok(p) = ret.dyn_into::<Promise>() {
            JsFuture::from(p).await.map_err(js_message)?;
        }
        Ok(())
    }
}

fn js_message(v: JsValue) -> String {
    v.dyn_ref::<js_sys::Error>()
        .map(|e| String::from(e.message()))
        .or_else(|| v.as_string())
        .unwrap_or_else(|| "persist failed".into())
}

fn err(e: impl std::fmt::Display) -> JsValue {
    JsError::new(&e.to_string()).into()
}

fn json<T: Serialize>(v: &T) -> Result<JsValue, JsValue> {
    serde_json::to_string(v).map(JsValue::from).map_err(err)
}

/// The swap taker for one wallet seed.
#[wasm_bindgen]
pub struct WasmTaker {
    engine: Rc<Engine>,
}

#[wasm_bindgen]
impl WasmTaker {
    /// `seed`: the wallet's BIP39 seed (wiped after use). `snapshotJson`: every stored entry
    /// under [`storePrefix`](Self::store_prefix) as `[{key, seq, ct}]`. `persist(entriesJson)`
    /// must store the entries and resolve only once they are durable.
    #[wasm_bindgen(constructor)]
    pub fn new(
        seed: Vec<u8>,
        config_json: &str,
        snapshot_json: &str,
        persist: Function,
    ) -> Result<WasmTaker, JsValue> {
        let seed = Zeroizing::new(seed);
        let cfg: Config = serde_json::from_str(config_json).map_err(err)?;
        let snapshot: Vec<Entry> = serde_json::from_str(snapshot_json).map_err(err)?;
        let store = Arc::new(EncryptedStore::open(&seed, &snapshot).map_err(err)?);
        let engine = Engine::new(&seed, &cfg, store, Arc::new(JsSink { persist })).map_err(err)?;
        Ok(WasmTaker {
            engine: Rc::new(engine),
        })
    }

    /// Storage key prefix for `seed`'s entries.
    #[wasm_bindgen(js_name = storePrefix)]
    pub fn store_prefix(seed: Vec<u8>) -> String {
        let seed = Zeroizing::new(seed);
        store_prefix(&seed)
    }

    /// `{divi, btc, ltc}` as JSON.
    pub fn addresses(&self) -> Result<String, JsValue> {
        serde_json::to_string(self.engine.addresses()).map_err(err)
    }

    /// Every swap, newest first, as JSON.
    pub fn swaps(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.engine.swaps().map_err(err)?).map_err(err)
    }

    /// The maker's offers this taker can take, each with `exact`: its price and range as
    /// decimal strings (the plain numbers round in JS past 2^53 - 1), and `selection`: the
    /// token `beginSelected` takes for exactly these terms (`null`, with `ambiguous: true`,
    /// when the maker lists the id more than once). A later call never changes what an
    /// earlier token selects.
    pub fn offers(&self) -> Promise {
        let e = self.engine.clone();
        future_to_promise(async move { json(&e.offers().await.map_err(err)?) })
    }

    /// Quote and accept on a selected offer, held to the terms its token pins:
    /// `{selection, offer_id, direction, counter_chain, divi_sats_per_btc, min_btc_sats,
    /// max_btc_sats, btc_sats, min_remaining_secs?, max_taker_timeout_secs?}` (snake_case;
    /// u64 terms as canonical decimal strings; unknown keys refused). Every displayed term
    /// must match the selection. A missing, stale or ambiguous selection is refused. Nothing
    /// is locked.
    #[wasm_bindgen(js_name = beginSelected)]
    pub fn begin_selected(&self, selection_json: String) -> Promise {
        let e = self.engine.clone();
        future_to_promise(async move {
            let spec = SelectionSpec::parse(&selection_json).map_err(err)?;
            json(&e.begin_selected(&spec).await.map_err(err)?)
        })
    }

    /// Quote and accept per `intentJson`, explicit limits ([`IntentSpec`]):
    /// `{offer_id, btc_sats, counter_chain, direction, limit_divi_sats_per_btc,
    /// min_remaining_secs?, max_taker_timeout_secs?}` (snake_case; unknown keys are refused;
    /// amounts as decimal strings, or integers up to 2^53 - 1). Nothing is locked.
    #[wasm_bindgen(js_name = beginWithIntent)]
    pub fn begin_with_intent(&self, intent_json: String) -> Promise {
        let e = self.engine.clone();
        future_to_promise(async move {
            let intent = IntentSpec::parse(&intent_json).map_err(err)?;
            json(&e.begin_with_intent(&intent).await.map_err(err)?)
        })
    }

    /// Lock the taker leg.
    pub fn lock(&self, id: String) -> Promise {
        let e = self.engine.clone();
        future_to_promise(async move { json(&e.lock(&id).await.map_err(err)?) })
    }

    /// Advance every open swap; resolves to all swaps.
    pub fn tick(&self) -> Promise {
        let e = self.engine.clone();
        future_to_promise(async move { json(&e.tick().await.map_err(err)?) })
    }

    /// Refund a swap whose timeout has passed.
    pub fn refund(&self, id: String) -> Promise {
        let e = self.engine.clone();
        future_to_promise(async move { json(&e.refund(&id).await.map_err(err)?) })
    }

    /// Replace the DIVI coin set with `[{txid, outputIndex, satoshis}]`.
    #[wasm_bindgen(js_name = syncDiviCoins)]
    pub fn sync_divi_coins(&self, coins_json: String) -> Promise {
        let e = self.engine.clone();
        future_to_promise(async move {
            let coins: Vec<CoinIn> = serde_json::from_str(&coins_json).map_err(err)?;
            json(&e.sync_divi_coins(&coins).await.map_err(err)?)
        })
    }
}
