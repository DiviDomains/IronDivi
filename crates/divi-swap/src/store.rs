// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Persistence for maker and taker swaps. **Lane engine** owns the implementation;
//! `open`/`in_memory` are frozen.
//!
//! Every record is one JSON document written in a single backend call, so a transition and
//! the signed transaction it refers to become durable together (write-ahead, plan §3.2).
//!
//! Native builds use SQLite (file mode 0600; the taker's preimage lives here). The
//! [`StoreBackend`] trait lets a host without SQLite (the wasm32 taker in the IronDivi
//! browser extension) supply its own durable storage via [`Store::with_backend`];
//! [`MemoryBackend`] is the in-process reference implementation.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::Quote;
use crate::error::{Result, SwapError};
use crate::htlc::HtlcParams;
use crate::state::SwapState;
use crate::taker::TakerState;
use crate::types::{Amount, Funding, Outpoint, SignedTx};

/// Swap database handle. Cheap to clone.
#[derive(Clone)]
pub struct Store {
    backend: Arc<dyn StoreBackend>,
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
/// `quote.taker_chain()`, the *maker leg* on `quote.maker_chain()`. Pre-direction records
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
    /// Set once the taker decided never to claim the maker leg (its locktime was too close
    /// to claim safely when the lock confirmed). Terminal for the claim path: the swap only
    /// waits out the taker-leg refund. Absent in records written before the field existed.
    #[serde(default)]
    pub claim_declined: Option<String>,
    /// Last error.
    pub last_error: Option<String>,
}

fn storage<E: std::fmt::Display>(e: E) -> SwapError {
    SwapError::Storage(e.to_string())
}

/// A table of the swap database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table<'a> {
    /// Issued quotes ([`QuoteRecord`]).
    Quotes,
    /// Maker swaps ([`MakerRecord`]).
    MakerSwaps,
    /// Taker swaps ([`TakerRecord`]).
    TakerSwaps,
    /// Other engines' documents of one kind (see [`Store::put_doc`]).
    Docs(&'a str),
}

/// Columns a maker-swap row carries besides its JSON (SQLite indexes them).
#[derive(Debug, Clone, Copy)]
pub struct MakerMeta<'a> {
    /// [`MakerRecord::created_at`].
    pub created_at: u64,
    /// [`SwapState::as_str`] of [`MakerRecord::state`].
    pub state: &'a str,
}

/// `Send + Sync` on native targets, where swaps run on a multi-threaded runtime; nothing
/// on wasm32, which is single-threaded and whose JS-backed handles are `!Send`.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSendSync: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> MaybeSendSync for T {}
/// `Send + Sync` on native targets; nothing on wasm32.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSendSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSendSync for T {}

/// Durable JSON-document storage behind [`Store`].
///
/// Contract: `put` is an upsert that is durable when it returns `Ok` (the engine broadcasts
/// a transaction only after the record holding it was put); an upsert keeps the row's
/// original insertion position. `list` returns the table's documents newest first by
/// first insertion.
pub trait StoreBackend: MaybeSendSync {
    /// Insert or replace document `id` in `table`. `maker` is `Some` exactly for
    /// [`Table::MakerSwaps`].
    fn put(
        &self,
        table: Table<'_>,
        id: &str,
        json: &str,
        maker: Option<MakerMeta<'_>>,
    ) -> Result<()>;
    /// Fetch document `id` from `table`.
    fn get(&self, table: Table<'_>, id: &str) -> Result<Option<String>>;
    /// All documents in `table`, newest first by first insertion.
    fn list(&self, table: Table<'_>) -> Result<Vec<String>>;
}

impl Store {
    /// Open (creating if needed) the database at `path`, migrating the schema.
    ///
    /// The file is created with mode 0600 before SQLite touches it.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn open(path: &std::path::Path) -> Result<Self> {
        Ok(Self::with_backend(Arc::new(sqlite::SqliteBackend::open(
            path,
        )?)))
    }

    /// A throwaway in-memory database (tests).
    pub fn in_memory() -> Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        return Ok(Self::with_backend(Arc::new(
            sqlite::SqliteBackend::in_memory()?,
        )));
        #[cfg(target_arch = "wasm32")]
        return Ok(Self::with_backend(Arc::new(MemoryBackend::default())));
    }

    /// A store over a caller-supplied backend (the browser extension's durable storage).
    pub fn with_backend(backend: Arc<dyn StoreBackend>) -> Self {
        Store { backend }
    }

    // ---- quotes ----

    /// Insert or replace a quote.
    pub fn put_quote(&self, rec: &QuoteRecord) -> Result<()> {
        self.put_json(Table::Quotes, &rec.quote.id, rec, None)
    }

    /// Fetch a quote.
    pub fn get_quote(&self, id: &str) -> Result<Option<QuoteRecord>> {
        self.get_json(Table::Quotes, id)
    }

    // ---- maker swaps ----

    /// Insert or replace a maker swap.
    pub fn put_maker_swap(&self, rec: &MakerRecord) -> Result<()> {
        let meta = MakerMeta {
            created_at: rec.created_at,
            state: rec.state.as_str(),
        };
        self.put_json(Table::MakerSwaps, &rec.id, rec, Some(meta))
    }

    /// Fetch a maker swap.
    pub fn get_maker_swap(&self, id: &str) -> Result<Option<MakerRecord>> {
        self.get_json(Table::MakerSwaps, id)
    }

    /// All maker swaps, newest first.
    pub fn list_maker_swaps(&self) -> Result<Vec<MakerRecord>> {
        let mut recs: Vec<MakerRecord> = self.list_json(Table::MakerSwaps)?;
        // Backends list by insertion; a stable sort keeps that as the tie-break.
        recs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(recs)
    }

    // ---- taker swaps ----

    /// Insert or replace a taker swap.
    pub fn put_taker_swap(&self, rec: &TakerRecord) -> Result<()> {
        self.put_json(Table::TakerSwaps, &rec.id, rec, None)
    }

    /// Fetch a taker swap.
    pub fn get_taker_swap(&self, id: &str) -> Result<Option<TakerRecord>> {
        self.get_json(Table::TakerSwaps, id)
    }

    /// All taker swaps, newest first.
    pub fn list_taker_swaps(&self) -> Result<Vec<TakerRecord>> {
        self.list_json(Table::TakerSwaps)
    }

    // ---- other engines' records ----

    /// Insert or replace a JSON document of `kind` (e.g. `"xmr_maker"`): storage for swap
    /// engines that live outside this crate (the DIVI<->XMR adaptor swap) but share its
    /// database, file mode and single-statement write-ahead property.
    pub fn put_doc<T: Serialize>(&self, kind: &str, id: &str, doc: &T) -> Result<()> {
        self.put_json(Table::Docs(kind), id, doc, None)
    }

    /// Fetch a document of `kind`.
    pub fn get_doc<T: DeserializeOwned>(&self, kind: &str, id: &str) -> Result<Option<T>> {
        self.get_json(Table::Docs(kind), id)
    }

    /// All documents of `kind`, newest first.
    pub fn list_docs<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        self.list_json(Table::Docs(kind))
    }

    // ---- helpers ----

    fn put_json<T: Serialize>(
        &self,
        table: Table<'_>,
        id: &str,
        v: &T,
        maker: Option<MakerMeta<'_>>,
    ) -> Result<()> {
        let json = serde_json::to_string(v).map_err(storage)?;
        self.backend.put(table, id, &json, maker)
    }

    fn get_json<T: DeserializeOwned>(&self, table: Table<'_>, id: &str) -> Result<Option<T>> {
        self.backend
            .get(table, id)?
            .map(|j| serde_json::from_str(&j).map_err(storage))
            .transpose()
    }

    fn list_json<T: DeserializeOwned>(&self, table: Table<'_>) -> Result<Vec<T>> {
        self.backend
            .list(table)?
            .iter()
            .map(|j| serde_json::from_str(j).map_err(storage))
            .collect()
    }
}

/// In-process [`StoreBackend`]: the reference implementation of the contract, and the
/// wasm32 [`Store::in_memory`]. Nothing survives the process.
#[derive(Default)]
pub struct MemoryBackend {
    tables: parking_lot::Mutex<std::collections::BTreeMap<String, MemTable>>,
}

#[derive(Default)]
struct MemTable {
    next_seq: u64,
    rows: std::collections::HashMap<String, (u64, String)>,
}

fn table_key(table: Table<'_>) -> String {
    match table {
        Table::Quotes => "quotes".into(),
        Table::MakerSwaps => "maker_swaps".into(),
        Table::TakerSwaps => "taker_swaps".into(),
        Table::Docs(kind) => format!("docs/{kind}"),
    }
}

impl StoreBackend for MemoryBackend {
    fn put(&self, table: Table<'_>, id: &str, json: &str, _: Option<MakerMeta<'_>>) -> Result<()> {
        let mut tables = self.tables.lock();
        let t = tables.entry(table_key(table)).or_default();
        match t.rows.get_mut(id) {
            Some(row) => row.1 = json.to_string(),
            None => {
                t.next_seq += 1;
                t.rows
                    .insert(id.to_string(), (t.next_seq, json.to_string()));
            }
        }
        Ok(())
    }

    fn get(&self, table: Table<'_>, id: &str) -> Result<Option<String>> {
        let tables = self.tables.lock();
        Ok(tables
            .get(&table_key(table))
            .and_then(|t| t.rows.get(id))
            .map(|(_, j)| j.clone()))
    }

    fn list(&self, table: Table<'_>) -> Result<Vec<String>> {
        let tables = self.tables.lock();
        let Some(t) = tables.get(&table_key(table)) else {
            return Ok(Vec::new());
        };
        let mut rows: Vec<_> = t.rows.values().collect();
        rows.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(rows.into_iter().map(|(_, j)| j.clone()).collect())
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod sqlite {
    use rusqlite::{params, Connection, OptionalExtension};
    use std::path::Path;

    use super::{storage, MakerMeta, StoreBackend, Table};
    use crate::error::{Result, SwapError};

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
CREATE TABLE IF NOT EXISTS docs (
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    json TEXT NOT NULL,
    PRIMARY KEY (kind, id)
);
";

    /// The SQLite backend (native default): one statement per write.
    pub(super) struct SqliteBackend {
        conn: parking_lot::Mutex<Connection>,
    }

    impl SqliteBackend {
        pub(super) fn open(path: &Path) -> Result<Self> {
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

        pub(super) fn in_memory() -> Result<Self> {
            Self::init(Connection::open_in_memory().map_err(storage)?)
        }

        fn init(conn: Connection) -> Result<Self> {
            conn.execute_batch(SCHEMA).map_err(storage)?;
            Ok(SqliteBackend {
                conn: parking_lot::Mutex::new(conn),
            })
        }
    }

    impl StoreBackend for SqliteBackend {
        fn put(
            &self,
            table: Table<'_>,
            id: &str,
            json: &str,
            maker: Option<MakerMeta<'_>>,
        ) -> Result<()> {
            let conn = self.conn.lock();
            match table {
                Table::Quotes => conn.execute(
                    "INSERT INTO quotes (id, json) VALUES (?1, ?2)
                     ON CONFLICT(id) DO UPDATE SET json = excluded.json",
                    params![id, json],
                ),
                Table::MakerSwaps => {
                    let m = maker.ok_or_else(|| {
                        SwapError::Storage("maker swap written without its columns".into())
                    })?;
                    conn.execute(
                        "INSERT INTO maker_swaps (id, created_at, state, json) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(id) DO UPDATE SET state = excluded.state, json = excluded.json",
                        params![id, m.created_at as i64, m.state, json],
                    )
                }
                Table::TakerSwaps => conn.execute(
                    "INSERT INTO taker_swaps (id, seq, json)
                     VALUES (?1, (SELECT COALESCE(MAX(seq), 0) + 1 FROM taker_swaps), ?2)
                     ON CONFLICT(id) DO UPDATE SET json = excluded.json",
                    params![id, json],
                ),
                Table::Docs(kind) => conn.execute(
                    "INSERT INTO docs (kind, id, seq, json)
                     VALUES (?1, ?2, (SELECT COALESCE(MAX(seq), 0) + 1 FROM docs), ?3)
                     ON CONFLICT(kind, id) DO UPDATE SET json = excluded.json",
                    params![kind, id, json],
                ),
            }
            .map_err(storage)?;
            Ok(())
        }

        fn get(&self, table: Table<'_>, id: &str) -> Result<Option<String>> {
            let conn = self.conn.lock();
            match table {
                Table::Quotes => {
                    conn.query_row("SELECT json FROM quotes WHERE id = ?1", params![id], |r| {
                        r.get(0)
                    })
                }
                Table::MakerSwaps => conn.query_row(
                    "SELECT json FROM maker_swaps WHERE id = ?1",
                    params![id],
                    |r| r.get(0),
                ),
                Table::TakerSwaps => conn.query_row(
                    "SELECT json FROM taker_swaps WHERE id = ?1",
                    params![id],
                    |r| r.get(0),
                ),
                Table::Docs(kind) => conn.query_row(
                    "SELECT json FROM docs WHERE kind = ?1 AND id = ?2",
                    params![kind, id],
                    |r| r.get(0),
                ),
            }
            .optional()
            .map_err(storage)
        }

        fn list(&self, table: Table<'_>) -> Result<Vec<String>> {
            let conn = self.conn.lock();
            let (sql, kind) = match table {
                Table::Quotes => ("SELECT json FROM quotes ORDER BY rowid DESC", None),
                Table::MakerSwaps => (
                    "SELECT json FROM maker_swaps ORDER BY created_at DESC, rowid DESC",
                    None,
                ),
                Table::TakerSwaps => ("SELECT json FROM taker_swaps ORDER BY seq DESC", None),
                Table::Docs(kind) => (
                    "SELECT json FROM docs WHERE kind = ?1 ORDER BY seq DESC",
                    Some(kind),
                ),
            };
            let mut stmt = conn.prepare(sql).map_err(storage)?;
            fn json(r: &rusqlite::Row<'_>) -> rusqlite::Result<String> {
                r.get(0)
            }
            let rows = match kind {
                Some(k) => stmt.query_map(params![k], json),
                None => stmt.query_map([], json),
            }
            .map_err(storage)?;
            rows.map(|j| j.map_err(storage)).collect()
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
            counter_chain: crate::types::Chain::Btc,
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

    #[test]
    fn docs_round_trip_by_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swaps.db");
        let store = Store::open(&path).unwrap();
        store
            .put_doc("k1", "a", &serde_json::json!({"n": 1}))
            .unwrap();
        store
            .put_doc("k1", "b", &serde_json::json!({"n": 2}))
            .unwrap();
        store
            .put_doc("k2", "a", &serde_json::json!({"n": 3}))
            .unwrap();
        store
            .put_doc("k1", "a", &serde_json::json!({"n": 4}))
            .unwrap(); // replace keeps order
        drop(store);
        let store = Store::open(&path).unwrap();
        let a: Option<serde_json::Value> = store.get_doc("k1", "a").unwrap();
        assert_eq!(a.unwrap()["n"], 4);
        assert_eq!(
            store
                .get_doc::<serde_json::Value>("k2", "a")
                .unwrap()
                .unwrap()["n"],
            3
        );
        assert!(store
            .get_doc::<serde_json::Value>("k3", "a")
            .unwrap()
            .is_none());
        let k1: Vec<serde_json::Value> = store.list_docs("k1").unwrap();
        assert_eq!(
            k1.iter()
                .map(|v| v["n"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            [2, 4]
        );
        // The hashlock tables are untouched by documents.
        assert!(store.list_maker_swaps().unwrap().is_empty());
    }

    /// The in-process backend keeps the SQLite backend's contract: upserts keep their
    /// position, maker swaps list by `created_at` then insertion, docs stay per kind.
    #[test]
    fn memory_backend_matches_sqlite() {
        fn exercise(store: &Store) -> (Vec<String>, Vec<serde_json::Value>, Option<QuoteRecord>) {
            store.put_maker_swap(&maker_rec("a", 10)).unwrap();
            store.put_maker_swap(&maker_rec("b", 30)).unwrap();
            store.put_maker_swap(&maker_rec("c", 10)).unwrap();
            store.put_maker_swap(&maker_rec("a", 10)).unwrap();
            store
                .put_doc("k", "x", &serde_json::json!({"n": 1}))
                .unwrap();
            store
                .put_doc("k", "y", &serde_json::json!({"n": 2}))
                .unwrap();
            store
                .put_doc("k", "x", &serde_json::json!({"n": 3}))
                .unwrap();
            store
                .put_quote(&QuoteRecord {
                    quote: quote("q"),
                    used: true,
                })
                .unwrap();
            let ids = store
                .list_maker_swaps()
                .unwrap()
                .into_iter()
                .map(|r| r.id)
                .collect();
            (
                ids,
                store.list_docs("k").unwrap(),
                store.get_quote("q").unwrap(),
            )
        }
        let sqlite = exercise(&Store::in_memory().unwrap());
        let memory = exercise(&Store::with_backend(Arc::new(MemoryBackend::default())));
        assert_eq!(sqlite.0, ["b", "c", "a"]);
        assert_eq!(sqlite, memory);
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
