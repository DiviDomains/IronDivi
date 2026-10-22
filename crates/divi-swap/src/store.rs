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
/// `quote.taker_chain()`, the *maker leg* on `quote.maker_chain()`. Pre-direction records
/// (taker leg = BTC, maker leg = DIVI) load through the serde aliases.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Maker-chain MTP read when the maker-leg locktime was set; sent to the taker.
    #[serde(default)]
    pub maker_mtp_at_lock: Option<u32>,
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
    /// Set once a re-broadcast of the maker lock was refused for good (its inputs are gone):
    /// the watcher stops re-sending and keeps reporting one error. Absent in older records.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub maker_lock_dropped: bool,
}

/// The taker's persisted view of one swap (role-based legs, see [`MakerRecord`]).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// What a secret prints as in `Debug` output.
const REDACTED: &str = "<redacted>";

// `Debug` is written by hand so a stray `{:?}` never prints the preimage. Every field is
// listed; adding a field to the struct without listing it here fails to compile.
impl std::fmt::Debug for MakerRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let MakerRecord {
            id,
            created_at,
            state,
            quote,
            hash,
            taker_maker_leg_pubkey,
            taker_leg_htlc,
            taker_leg_outpoint,
            taker_leg_locked,
            maker_leg_htlc,
            maker_leg_funding,
            maker_leg_scan_from,
            maker_mtp_at_lock,
            maker_leg_refund,
            preimage,
            taker_leg_claim,
            last_error,
            maker_lock_dropped,
        } = self;
        f.debug_struct("MakerRecord")
            .field("id", id)
            .field("created_at", created_at)
            .field("state", state)
            .field("quote", quote)
            .field("hash", hash)
            .field("taker_maker_leg_pubkey", taker_maker_leg_pubkey)
            .field("taker_leg_htlc", taker_leg_htlc)
            .field("taker_leg_outpoint", taker_leg_outpoint)
            .field("taker_leg_locked", taker_leg_locked)
            .field("maker_leg_htlc", maker_leg_htlc)
            .field("maker_leg_funding", maker_leg_funding)
            .field("maker_leg_scan_from", maker_leg_scan_from)
            .field("maker_mtp_at_lock", maker_mtp_at_lock)
            .field("maker_leg_refund", maker_leg_refund)
            .field("preimage", &preimage.as_ref().map(|_| REDACTED))
            .field("taker_leg_claim", taker_leg_claim)
            .field("last_error", last_error)
            .field("maker_lock_dropped", maker_lock_dropped)
            .finish()
    }
}

impl std::fmt::Debug for TakerRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let TakerRecord {
            id,
            state,
            quote,
            preimage: _,
            hash,
            maker_swap_id,
            taker_leg_htlc,
            taker_leg_funding,
            maker_leg_htlc,
            maker_leg_outpoint,
            maker_leg_amount,
            maker_leg_claim,
            taker_leg_refund,
            claim_declined,
            last_error,
        } = self;
        f.debug_struct("TakerRecord")
            .field("id", id)
            .field("state", state)
            .field("quote", quote)
            .field("preimage", &REDACTED)
            .field("hash", hash)
            .field("maker_swap_id", maker_swap_id)
            .field("taker_leg_htlc", taker_leg_htlc)
            .field("taker_leg_funding", taker_leg_funding)
            .field("maker_leg_htlc", maker_leg_htlc)
            .field("maker_leg_outpoint", maker_leg_outpoint)
            .field("maker_leg_amount", maker_leg_amount)
            .field("maker_leg_claim", maker_leg_claim)
            .field("taker_leg_refund", taker_leg_refund)
            .field("claim_declined", claim_declined)
            .field("last_error", last_error)
            .finish()
    }
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
CREATE TABLE IF NOT EXISTS docs (
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    json TEXT NOT NULL,
    PRIMARY KEY (kind, id)
);
";

/// One maker swap per hashlock. The hash lives in the record JSON (`$.hash`, a 32-number
/// array), so this is an expression index; `put_maker_swap` of a second swap for a hash fails
/// even if the engine's gate were bypassed.
const UNIQUE_HASH_INDEX: &str = "maker_swaps_hash_unique";

/// Create the unique-hash index (idempotent). A database that already holds two swaps for one
/// hash cannot take it: that is logged loudly and the store runs without the index (the
/// engine's gate is then the only guard, as before) rather than refusing to start.
fn ensure_unique_hash(conn: &Connection) -> Result<()> {
    let dup: Option<(String, i64)> = conn
        .query_row(
            "SELECT json_extract(json, '$.hash'), COUNT(*) FROM maker_swaps
             GROUP BY json_extract(json, '$.hash') HAVING COUNT(*) > 1 LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    if let Some((hash, n)) = dup {
        tracing::error!(
            %hash, swaps = n,
            "maker_swaps holds several swaps for one hashlock: NOT creating the unique-hash index; \
             one swap per hash is enforced only by the engine gate until the duplicates are resolved"
        );
        return Ok(());
    }
    conn.execute_batch(&format!(
        "CREATE UNIQUE INDEX IF NOT EXISTS {UNIQUE_HASH_INDEX}
         ON maker_swaps (json_extract(json, '$.hash'))"
    ))
    .map_err(storage)
}

impl Store {
    /// Open (creating if needed) the database at `path`, migrating the schema.
    ///
    /// A new file is created with mode 0600 before SQLite touches it. An existing database
    /// and its `-wal`/`-shm` that are looser than 0600 (an older build, a copied file) are
    /// tightened to 0600 with a warning; one that cannot be tightened is an error, because
    /// the file holds the preimage and per-swap keys. [`Store::open_read_only`] never chmods.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            create_private(path)?;
        }
        tighten_existing(path)?;
        let conn = Connection::open(path).map_err(storage)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
        // SQLite has now created (or reopened) the sidecars.
        tighten_existing(path)?;
        Self::init(conn)
    }

    /// Open an existing database read-only: no file is created, no pragma or schema is
    /// written (so it is safe next to a running daemon, and an absent `path` is an error,
    /// never an empty store). For inspection tools such as `divi-swapd --xmr-inflight`.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(storage)?;
        Ok(Store {
            conn: std::sync::Arc::new(parking_lot::Mutex::new(conn)),
        })
    }

    /// A throwaway in-memory database (tests).
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(storage)?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA).map_err(storage)?;
        ensure_unique_hash(&conn)?;
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

    /// Every stored quote (any order).
    pub fn list_quotes(&self) -> Result<Vec<QuoteRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT json FROM quotes").map_err(storage)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(storage)?;
        rows.map(|j| serde_json::from_str(&j.map_err(storage)?).map_err(storage))
            .collect()
    }

    /// Drop a quote (a no-op for an unknown id).
    pub fn delete_quote(&self, id: &str) -> Result<()> {
        self.conn
            .lock()
            .execute("DELETE FROM quotes WHERE id = ?1", params![id])
            .map_err(storage)?;
        Ok(())
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

    // ---- other engines' records ----

    /// Insert or replace a JSON document of `kind` (e.g. `"xmr_maker"`): storage for swap
    /// engines that live outside this crate (the DIVI<->XMR adaptor swap) but share its
    /// database, file mode and single-statement write-ahead property.
    pub fn put_doc<T: Serialize>(&self, kind: &str, id: &str, doc: &T) -> Result<()> {
        let json = serde_json::to_string(doc).map_err(storage)?;
        self.conn
            .lock()
            .execute(
                "INSERT INTO docs (kind, id, seq, json)
                 VALUES (?1, ?2, (SELECT COALESCE(MAX(seq), 0) + 1 FROM docs), ?3)
                 ON CONFLICT(kind, id) DO UPDATE SET json = excluded.json",
                params![kind, id, json],
            )
            .map_err(storage)?;
        Ok(())
    }

    /// Fetch a document of `kind`.
    pub fn get_doc<T: DeserializeOwned>(&self, kind: &str, id: &str) -> Result<Option<T>> {
        let json: Option<String> = self
            .conn
            .lock()
            .query_row(
                "SELECT json FROM docs WHERE kind = ?1 AND id = ?2",
                params![kind, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        json.map(|j| serde_json::from_str(&j).map_err(storage))
            .transpose()
    }

    /// All documents of `kind`, newest first.
    pub fn list_docs<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT json FROM docs WHERE kind = ?1 ORDER BY seq DESC")
            .map_err(storage)?;
        let rows = stmt
            .query_map(params![kind], |r| r.get::<_, String>(0))
            .map_err(storage)?;
        rows.map(|j| serde_json::from_str(&j.map_err(storage)?).map_err(storage))
            .collect()
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

/// Tighten `path` and its `-wal`/`-shm` to 0600 when they exist and are looser. A file the
/// process cannot chmod (not the owner) is an error rather than a silent pass: the caller is
/// about to put secrets into it.
#[cfg(unix)]
fn tighten_existing(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let p = std::path::PathBuf::from(name);
        let mode = match std::fs::metadata(&p) {
            Ok(m) => m.permissions().mode() & 0o777,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(storage(format!("{}: {e}", p.display()))),
        };
        if mode & 0o077 == 0 {
            continue;
        }
        tracing::warn!(
            path = %p.display(), old_mode = format!("{mode:04o}"),
            "swap database file was readable beyond its owner; tightening to 0600"
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            storage(format!(
                "{} has mode {mode:04o} and cannot be tightened to 0600 ({e}); it holds swap \
                 secrets, so the store will not open it",
                p.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn tighten_existing(_path: &Path) -> Result<()> {
    Ok(())
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
                script_version: Default::default(),
            },
            taker_leg_outpoint: None,
            taker_leg_locked: None,
            maker_leg_htlc: None,
            maker_leg_funding: None,
            maker_leg_scan_from: 0,
            maker_mtp_at_lock: None,
            maker_leg_refund: None,
            preimage: None,
            taker_leg_claim: None,
            last_error: None,
            maker_lock_dropped: false,
        }
    }

    #[test]
    fn store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swaps.db");
        let store = Store::open(&path).unwrap();
        let rec = maker_rec("a", 10);
        store.put_maker_swap(&rec).unwrap();
        store.put_maker_swap(&with_hash("b", 20, [2; 32])).unwrap();
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

    // ---- unique maker hash ----

    fn has_hash_index(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
            params![UNIQUE_HASH_INDEX],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            == 1
    }

    fn with_hash(id: &str, created_at: u64, hash: [u8; 32]) -> MakerRecord {
        let mut r = maker_rec(id, created_at);
        r.hash = hash;
        r.taker_leg_htlc.hash = hash;
        r
    }

    /// A database as the previous binary left it: the schema without the index, rows in it.
    fn old_db(path: &Path, recs: &[MakerRecord]) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        for r in recs {
            conn.execute(
                "INSERT INTO maker_swaps (id, created_at, state, json) VALUES (?1, ?2, ?3, ?4)",
                params![
                    r.id,
                    r.created_at as i64,
                    r.state.as_str(),
                    serde_json::to_string(r).unwrap()
                ],
            )
            .unwrap();
        }
    }

    #[test]
    fn second_maker_swap_for_one_hash_is_refused_by_the_store() {
        let s = Store::in_memory().unwrap();
        s.put_maker_swap(&with_hash("a", 1, [7; 32])).unwrap();
        let err = s.put_maker_swap(&with_hash("b", 2, [7; 32])).unwrap_err();
        assert!(matches!(err, SwapError::Storage(_)), "{err:?}");
        assert_eq!(s.list_maker_swaps().unwrap().len(), 1);
        // The same swap updated, and another hash, are fine.
        let mut a = with_hash("a", 1, [7; 32]);
        a.last_error = Some("x".into());
        s.put_maker_swap(&a).unwrap();
        s.put_maker_swap(&with_hash("c", 3, [8; 32])).unwrap();
        assert_eq!(s.list_maker_swaps().unwrap().len(), 2);
    }

    #[test]
    fn migration_on_a_database_with_rows_adds_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap.db");
        old_db(
            &path,
            &[with_hash("a", 1, [1; 32]), with_hash("b", 2, [2; 32])],
        );
        let s = Store::open(&path).unwrap();
        assert_eq!(s.list_maker_swaps().unwrap().len(), 2);
        assert!(has_hash_index(&Connection::open(&path).unwrap()));
        assert!(s.put_maker_swap(&with_hash("c", 3, [1; 32])).is_err());
        // Idempotent: a second open is fine.
        drop(s);
        Store::open(&path).unwrap();
    }

    #[test]
    fn migration_on_a_database_with_a_duplicate_hash_keeps_running_without_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap.db");
        old_db(
            &path,
            &[with_hash("a", 1, [9; 32]), with_hash("b", 2, [9; 32])],
        );
        let s = Store::open(&path).unwrap(); // must not refuse to start
        assert!(!has_hash_index(&Connection::open(&path).unwrap()));
        assert_eq!(s.list_maker_swaps().unwrap().len(), 2);
        // Existing rows stay writable, the store keeps working.
        let mut a = with_hash("a", 1, [9; 32]);
        a.last_error = Some("still updatable".into());
        s.put_maker_swap(&a).unwrap();
        s.put_maker_swap(&with_hash("c", 3, [5; 32])).unwrap();
    }

    #[test]
    fn database_with_only_the_old_tables_opens_and_an_old_writer_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap.db");
        old_db(&path, &[]);
        let s = Store::open(&path).unwrap();
        s.put_maker_swap(&with_hash("a", 1, [3; 32])).unwrap();
        drop(s);
        // What the previous binary does against the migrated file: open (old SCHEMA is
        // IF NOT EXISTS, never mentions the index) and upsert by id.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let r = with_hash("a", 1, [3; 32]);
        conn.execute(
            "INSERT INTO maker_swaps (id, created_at, state, json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET state = excluded.state, json = excluded.json",
            params![
                r.id,
                1i64,
                r.state.as_str(),
                serde_json::to_string(&r).unwrap()
            ],
        )
        .unwrap();
    }
}
