// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! SQLite persistence for maker and taker swaps (file mode 0600; the taker's preimage
//! lives here). **Lane engine** owns the implementation; `open`/`in_memory` are frozen.
//!
//! Every record is one JSON document written in a single statement, so a transition and
//! the signed transaction it refers to become durable together (write-ahead, plan §3.2).

use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::api::Quote;
use crate::error::{Result, SwapError};
use crate::htlc::HtlcParams;
use crate::state::SwapState;
use crate::taker::TakerState;
use crate::types::{Amount, Funding, Outpoint, SignedTx};

/// Swap database handle. Cheap to clone.
#[derive(Clone)]
pub struct Store {
    conn: std::sync::Arc<parking_lot::Mutex<Connection>>,
}

/// A quote as issued, with whether a swap has consumed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteRecord {
    /// The quote.
    pub quote: Quote,
    /// Set once a swap was created from it (a quote is single use).
    pub used: bool,
}

/// The maker's persisted view of one swap. Legs are role-based: the *taker leg* is on
/// `quote.direction.taker_chain()`, the *maker leg* on `maker_chain()`. Pre-direction records
/// (taker leg = BTC, maker leg = DIVI) load through the serde aliases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerRecord {
    /// Swap id.
    pub id: String,
    /// Wall-clock seconds when the swap was accepted.
    pub created_at: u64,
    /// Current state.
    pub state: SwapState,
    /// The quote being executed.
    pub quote: Quote,
    /// Taker's preimage hash.
    pub hash: [u8; 32],
    /// Taker's pubkey on the maker-leg chain (`claim_pubkey` of the maker-leg HTLC).
    #[serde(with = "hex33", alias = "taker_divi_pubkey")]
    pub taker_maker_leg_pubkey: [u8; 33],
    /// The taker-leg HTLC the taker must fund.
    #[serde(alias = "btc_htlc")]
    pub taker_leg_htlc: HtlcParams,
    /// Where the taker says it funded it.
    #[serde(alias = "btc_outpoint")]
    pub taker_leg_outpoint: Option<Outpoint>,
    /// Value actually seen locked in the taker-leg HTLC.
    #[serde(alias = "btc_locked")]
    pub taker_leg_locked: Option<Amount>,
    /// The maker-leg HTLC, fixed when the maker locks.
    #[serde(alias = "divi_htlc")]
    pub maker_leg_htlc: Option<HtlcParams>,
    /// The signed maker-leg funding tx (persisted before broadcast).
    #[serde(alias = "divi_funding")]
    pub maker_leg_funding: Option<Funding>,
    /// Maker-leg chain height from which to scan for the taker's claim.
    #[serde(alias = "divi_scan_from")]
    pub maker_leg_scan_from: u64,
    /// The signed maker-leg refund tx, once built.
    #[serde(alias = "divi_refund")]
    pub maker_leg_refund: Option<SignedTx>,
    /// The preimage, once the taker revealed it.
    pub preimage: Option<[u8; 32]>,
    /// The signed taker-leg claim tx, once built.
    #[serde(alias = "btc_claim")]
    pub taker_leg_claim: Option<SignedTx>,
    /// Last error the scheduler hit.
    pub last_error: Option<String>,
}

/// The taker's persisted view of one swap (role-based legs, see [`MakerRecord`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakerRecord {
    /// Local swap id.
    pub id: String,
    /// Current state.
    pub state: TakerState,
    /// The quote being executed.
    pub quote: Quote,
    /// The swap preimage. Stored with the DB at mode 0600.
    pub preimage: [u8; 32],
    /// SHA256 of `preimage`.
    pub hash: [u8; 32],
    /// The maker's id for this swap.
    pub maker_swap_id: Option<String>,
    /// The taker-leg HTLC (our refund key).
    #[serde(alias = "btc_htlc")]
    pub taker_leg_htlc: Option<HtlcParams>,
    /// The signed taker-leg funding tx (persisted before broadcast).
    #[serde(alias = "btc_funding")]
    pub taker_leg_funding: Option<Funding>,
    /// The maker's HTLC, once verified.
    #[serde(alias = "divi_htlc")]
    pub maker_leg_htlc: Option<HtlcParams>,
    /// The maker's lock output, once verified.
    #[serde(alias = "divi_outpoint")]
    pub maker_leg_outpoint: Option<Outpoint>,
    /// Value of the maker's lock.
    #[serde(alias = "divi_amount")]
    pub maker_leg_amount: Option<Amount>,
    /// The signed maker-leg claim tx (persisted before broadcast).
    #[serde(alias = "divi_claim")]
    pub maker_leg_claim: Option<SignedTx>,
    /// The signed taker-leg refund tx (persisted before broadcast).
    #[serde(alias = "btc_refund")]
    pub taker_leg_refund: Option<SignedTx>,
    /// Last error.
    pub last_error: Option<String>,
}

fn storage<E: std::fmt::Display>(e: E) -> SwapError {
    SwapError::Storage(e.to_string())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS quotes (
    id TEXT PRIMARY KEY,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS maker_swaps (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS taker_swaps (
    id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL,
    json TEXT NOT NULL
);
";

impl Store {
    /// Open (creating if needed) the database at `path`, migrating the schema.
    ///
    /// The file is created with mode 0600 before SQLite touches it.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            create_private(path)?;
        }
        let conn = Connection::open(path).map_err(storage)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
        Self::init(conn)
    }

    /// A throwaway in-memory database (tests).
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(storage)?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA).map_err(storage)?;
        Ok(Store {
            conn: std::sync::Arc::new(parking_lot::Mutex::new(conn)),
        })
    }

    // ---- quotes ----

    /// Insert or replace a quote.
    pub fn put_quote(&self, rec: &QuoteRecord) -> Result<()> {
        self.put_json(
            "INSERT INTO quotes (id, json) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            &rec.quote.id,
            rec,
        )
    }

    /// Fetch a quote.
    pub fn get_quote(&self, id: &str) -> Result<Option<QuoteRecord>> {
        self.get_json("SELECT json FROM quotes WHERE id = ?1", id)
    }

    // ---- maker swaps ----

    /// Insert or replace a maker swap.
    pub fn put_maker_swap(&self, rec: &MakerRecord) -> Result<()> {
        let json = serde_json::to_string(rec).map_err(storage)?;
        self.conn
            .lock()
            .execute(
                "INSERT INTO maker_swaps (id, created_at, state, json) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET state = excluded.state, json = excluded.json",
                params![rec.id, rec.created_at as i64, rec.state.as_str(), json],
            )
            .map_err(storage)?;
        Ok(())
    }

    /// Fetch a maker swap.
    pub fn get_maker_swap(&self, id: &str) -> Result<Option<MakerRecord>> {
        self.get_json("SELECT json FROM maker_swaps WHERE id = ?1", id)
    }

    /// All maker swaps, newest first.
    pub fn list_maker_swaps(&self) -> Result<Vec<MakerRecord>> {
        self.list_json("SELECT json FROM maker_swaps ORDER BY created_at DESC, rowid DESC")
    }

    // ---- taker swaps ----

    /// Insert or replace a taker swap.
    pub fn put_taker_swap(&self, rec: &TakerRecord) -> Result<()> {
        let json = serde_json::to_string(rec).map_err(storage)?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO taker_swaps (id, seq, json)
             VALUES (?1, (SELECT COALESCE(MAX(seq), 0) + 1 FROM taker_swaps), ?2)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            params![rec.id, json],
        )
        .map_err(storage)?;
        Ok(())
    }

    /// Fetch a taker swap.
    pub fn get_taker_swap(&self, id: &str) -> Result<Option<TakerRecord>> {
        self.get_json("SELECT json FROM taker_swaps WHERE id = ?1", id)
    }

    /// All taker swaps, newest first.
    pub fn list_taker_swaps(&self) -> Result<Vec<TakerRecord>> {
        self.list_json("SELECT json FROM taker_swaps ORDER BY seq DESC")
    }

    // ---- helpers ----

    fn put_json<T: Serialize>(&self, sql: &str, id: &str, v: &T) -> Result<()> {
        let json = serde_json::to_string(v).map_err(storage)?;
        self.conn
            .lock()
            .execute(sql, params![id, json])
            .map_err(storage)?;
        Ok(())
    }

    fn get_json<T: DeserializeOwned>(&self, sql: &str, id: &str) -> Result<Option<T>> {
        let json: Option<String> = self
            .conn
            .lock()
            .query_row(sql, params![id], |r| r.get(0))
            .optional()
            .map_err(storage)?;
        json.map(|j| serde_json::from_str(&j).map_err(storage))
            .transpose()
    }

    fn list_json<T: DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(sql).map_err(storage)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(storage)?;
        rows.map(|j| serde_json::from_str(&j.map_err(storage)?).map_err(storage))
            .collect()
    }
}

#[cfg(unix)]
fn create_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map(|_| ())
        .map_err(storage)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> Result<()> {
    std::fs::File::create(path).map(|_| ()).map_err(storage)
}

mod hex33 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        hex::decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote(id: &str) -> Quote {
        Quote {
            id: id.into(),
            offer_id: "o".into(),
            direction: crate::api::Direction::TakerPaysBtc,
            btc_amount: Amount(1),
            divi_amount: Amount(2),
            expires_at: 3,
            maker_btc_pubkey: [2; 33],
            maker_divi_pubkey: [3; 33],
            taker_timeout_secs: 4,
            maker_timeout_secs: 5,
            btc_confirmations: 1,
            divi_confirmations: 1,
        }
    }

    fn maker_rec(id: &str, created_at: u64) -> MakerRecord {
        MakerRecord {
            id: id.into(),
            created_at,
            state: SwapState::Accepted,
            quote: quote("q"),
            hash: [1; 32],
            taker_maker_leg_pubkey: [2; 33],
            taker_leg_htlc: HtlcParams {
                hash: [1; 32],
                claim_pubkey: [2; 33],
                refund_pubkey: [3; 33],
                locktime: 1_800_000_000,
            },
            taker_leg_outpoint: None,
            taker_leg_locked: None,
            maker_leg_htlc: None,
            maker_leg_funding: None,
            maker_leg_scan_from: 0,
            maker_leg_refund: None,
            preimage: None,
            taker_leg_claim: None,
            last_error: None,
        }
    }

    #[test]
    fn store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swaps.db");
        let store = Store::open(&path).unwrap();
        let rec = maker_rec("a", 10);
        store.put_maker_swap(&rec).unwrap();
        store.put_maker_swap(&maker_rec("b", 20)).unwrap();
        let q = QuoteRecord {
            quote: quote("q1"),
            used: false,
        };
        store.put_quote(&q).unwrap();
        drop(store);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.get_maker_swap("a").unwrap(), Some(rec));
        assert_eq!(store.get_maker_swap("zz").unwrap(), None);
        assert_eq!(store.get_quote("q1").unwrap(), Some(q));
        let ids: Vec<_> = store
            .list_maker_swaps()
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, ["b", "a"]);
    }

    #[cfg(unix)]
    #[test]
    fn store_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swaps.db");
        let store = Store::open(&path).unwrap();
        store.put_maker_swap(&maker_rec("a", 1)).unwrap();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{:?}", entry.path());
        }
    }
}
