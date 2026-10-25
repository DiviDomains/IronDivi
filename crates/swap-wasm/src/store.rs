// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Encrypted swap store for the browser.
//!
//! Taker records hold the swap preimage, so nothing reaches `chrome.storage.local` in the
//! clear. Each record is sealed with XChaCha20-Poly1305 under a key derived (HKDF-SHA256)
//! from the wallet seed; the associated data binds the ciphertext to its storage key and
//! write sequence, so a record cannot be moved to another key undetected. Replaying an
//! older ciphertext for the same key is not detected; the storage is local to the profile.
//!
//! Writes land in an in-memory cache at once and queue as [`Entry`]s for the host to
//! persist ([`take_pending`](EncryptedStore::take_pending)).

use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use divi_swap::store::{MakerMeta, StoreBackend, Table};
use divi_swap::{Result, SwapError};
use hkdf::Hkdf;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

const KEY_INFO: &[u8] = b"irondivi-swap-store-v1";
const ID_INFO: &[u8] = b"irondivi-swap-store-id-v1";
const NONCE_LEN: usize = 24;

/// One sealed record as the host stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Storage key, `swap:<fp>:<table>:<id>`.
    pub key: String,
    /// Write sequence; part of the associated data.
    pub seq: u64,
    /// Hex of nonce ‖ ciphertext.
    pub ct: String,
}

#[derive(Serialize, Deserialize)]
struct Plain {
    order: u64,
    json: String,
}

struct Inner {
    /// key → (insertion order, seq, json)
    cache: HashMap<String, (u64, u64, String)>,
    next_order: u64,
    seq: u64,
    pending: Vec<Entry>,
}

/// [`StoreBackend`] that seals every record under a seed-derived key.
pub struct EncryptedStore {
    key: Zeroizing<[u8; 32]>,
    prefix: String,
    inner: Mutex<Inner>,
}

/// `swap:<fp>:` for `seed`, where `fp` is a seed fingerprint that reveals nothing about it.
pub fn store_prefix(seed: &[u8]) -> String {
    let mut fp = [0u8; 8];
    Hkdf::<Sha256>::new(None, seed)
        .expand(ID_INFO, &mut fp)
        .expect("8 bytes is a valid HKDF length");
    format!("swap:{}:", hex::encode(fp))
}

fn table_name(table: Table<'_>) -> String {
    match table {
        Table::Quotes => "quotes".into(),
        Table::MakerSwaps => "maker_swaps".into(),
        Table::TakerSwaps => "taker_swaps".into(),
        Table::Docs(kind) => format!("docs/{kind}"),
    }
}

fn storage(e: impl std::fmt::Display) -> SwapError {
    SwapError::Storage(e.to_string())
}

impl EncryptedStore {
    /// Open the store for `seed` from `snapshot`, the host's stored entries (any prefix).
    /// Entries of other seeds are ignored; one of ours that fails to open is an error.
    pub fn open(seed: &[u8], snapshot: &[Entry]) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, seed)
            .expand(KEY_INFO, key.as_mut())
            .map_err(storage)?;
        let store = EncryptedStore {
            key,
            prefix: store_prefix(seed),
            inner: Mutex::new(Inner {
                cache: HashMap::new(),
                next_order: 0,
                seq: 0,
                pending: Vec::new(),
            }),
        };
        {
            let mut inner = store.inner.lock();
            for e in snapshot.iter().filter(|e| e.key.starts_with(&store.prefix)) {
                let plain = store.open_entry(e)?;
                inner.next_order = inner.next_order.max(plain.order + 1);
                inner.seq = inner.seq.max(e.seq);
                inner
                    .cache
                    .insert(e.key.clone(), (plain.order, e.seq, plain.json));
            }
        }
        Ok(store)
    }

    /// This seed's storage key prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&self.key[..]))
    }

    fn aad(key: &str, seq: u64) -> Vec<u8> {
        let mut aad = key.as_bytes().to_vec();
        aad.extend_from_slice(&seq.to_be_bytes());
        aad
    }

    fn seal(&self, key: &str, seq: u64, plain: &Plain) -> Result<Entry> {
        let msg = Zeroizing::new(serde_json::to_vec(plain).map_err(storage)?);
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(storage)?;
        let aad = Self::aad(key, seq);
        let ct = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &msg,
                    aad: &aad,
                },
            )
            .map_err(|_| SwapError::Storage("encryption failed".into()))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(Entry {
            key: key.to_string(),
            seq,
            ct: hex::encode(out),
        })
    }

    fn open_entry(&self, e: &Entry) -> Result<Plain> {
        let bytes = hex::decode(&e.ct).map_err(storage)?;
        if bytes.len() < NONCE_LEN {
            return Err(SwapError::Storage(format!("{}: truncated", e.key)));
        }
        let (nonce, ct) = bytes.split_at(NONCE_LEN);
        let aad = Self::aad(&e.key, e.seq);
        let msg = Zeroizing::new(
            self.cipher()
                .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
                .map_err(|_| SwapError::Storage(format!("{}: cannot decrypt", e.key)))?,
        );
        serde_json::from_slice(&msg).map_err(storage)
    }

    fn full_key(&self, table: Table<'_>, id: &str) -> String {
        format!("{}{}:{id}", self.prefix, table_name(table))
    }

    /// Drain the entries written since the last call, for the host to persist.
    pub fn take_pending(&self) -> Vec<Entry> {
        std::mem::take(&mut self.inner.lock().pending)
    }

    /// Put back entries whose persisting failed, unless a newer write of the same key
    /// has superseded them.
    pub fn requeue(&self, entries: Vec<Entry>) {
        let mut inner = self.inner.lock();
        let mut back: Vec<Entry> = entries
            .into_iter()
            .filter(|e| {
                let newer_cached = inner.cache.get(&e.key).is_some_and(|c| c.1 > e.seq);
                let pending = inner.pending.iter().any(|p| p.key == e.key);
                !newer_cached && !pending
            })
            .collect();
        back.append(&mut inner.pending);
        inner.pending = back;
    }
}

impl StoreBackend for EncryptedStore {
    fn put(
        &self,
        table: Table<'_>,
        id: &str,
        json: &str,
        _maker: Option<MakerMeta<'_>>,
    ) -> Result<()> {
        let key = self.full_key(table, id);
        let mut inner = self.inner.lock();
        let order = match inner.cache.get(&key) {
            Some(c) => c.0,
            None => {
                inner.next_order += 1;
                inner.next_order - 1
            }
        };
        let seq = inner.seq + 1;
        let entry = self.seal(
            &key,
            seq,
            &Plain {
                order,
                json: json.to_string(),
            },
        )?;
        inner.seq = seq;
        inner
            .cache
            .insert(key.clone(), (order, seq, json.to_string()));
        inner.pending.retain(|p| p.key != key);
        inner.pending.push(entry);
        Ok(())
    }

    fn get(&self, table: Table<'_>, id: &str) -> Result<Option<String>> {
        let key = self.full_key(table, id);
        Ok(self.inner.lock().cache.get(&key).map(|c| c.2.clone()))
    }

    fn list(&self, table: Table<'_>) -> Result<Vec<String>> {
        let prefix = format!("{}{}:", self.prefix, table_name(table));
        let inner = self.inner.lock();
        let mut rows: Vec<&(u64, u64, String)> = inner
            .cache
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v)
            .collect();
        rows.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(rows.into_iter().map(|r| r.2.clone()).collect())
    }
}
