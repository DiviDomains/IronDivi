// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Reservation of the wallet inputs a broadcast transaction spends.
//!
//! The DIVI wallet tombstones the inputs of a transaction it broadcasts; the BTC, LTC and
//! ZEC backends select coins from a live address query instead, so a lock that dropped out of
//! the mempool would hand its inputs to the next swap. A backend holding an
//! [`InputReservations`] writes the inputs here **before** it broadcasts (a failed write
//! blocks the broadcast), filters them out of coin selection, and releases them once the
//! transaction is seen confirmed. "Not seen" never releases: that is the bug.
//!
//! The table lives in the swap database next to the `Store` tables but on its own SQLite
//! connection, so it does not touch the `Store` schema.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{params, Connection};

use crate::error::{Result, SwapError};
use crate::types::{Chain, Outpoint, Txid};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS input_reservation (
    chain       TEXT    NOT NULL,
    in_txid     TEXT    NOT NULL,
    in_vout     INTEGER NOT NULL,
    reserved_by TEXT    NOT NULL,
    PRIMARY KEY (chain, in_txid, in_vout)
);
CREATE INDEX IF NOT EXISTS input_reservation_by_tx ON input_reservation (chain, reserved_by);
";

fn storage<E: std::fmt::Display>(e: E) -> SwapError {
    SwapError::Storage(e.to_string())
}

/// Persisted set of reserved inputs, keyed by the transaction that spends them. Cheap to clone.
#[derive(Clone)]
pub struct InputReservations {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for InputReservations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InputReservations").finish_non_exhaustive()
    }
}

impl InputReservations {
    /// Open (creating if needed) the reservation table in the swap database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(storage)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage)?;
        Self::init(conn)
    }

    /// A throwaway in-memory table (tests).
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(storage)?)
    }

    /// Open an existing database read-only: reads work, every [`Self::reserve`] fails. For
    /// inspection and for proving that a failed write blocks a broadcast.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(storage)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA).map_err(storage)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Reserve `inputs` for `txid`, all or none. Idempotent: reserving the same inputs for the
    /// same transaction again is a no-op, so a re-broadcast of the persisted bytes is safe.
    /// Inputs already reserved by a *different* transaction are an error (`Rejected`): that
    /// transaction conflicts with a live one.
    pub fn reserve(&self, chain: Chain, txid: &Txid, inputs: &[Outpoint]) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(storage)?;
        let by = txid.to_rpc_hex();
        let c = chain.to_string();
        for i in inputs {
            let owner: Option<String> = tx
                .query_row(
                    "SELECT reserved_by FROM input_reservation \
                     WHERE chain = ?1 AND in_txid = ?2 AND in_vout = ?3",
                    params![c, i.txid.to_rpc_hex(), i.vout],
                    |r| r.get(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(e),
                })
                .map_err(storage)?;
            match owner {
                Some(o) if o == by => {}
                Some(o) => {
                    return Err(SwapError::Rejected(format!(
                        "input {}:{} is reserved by {o}",
                        i.txid, i.vout
                    )))
                }
                None => {
                    tx.execute(
                        "INSERT INTO input_reservation (chain, in_txid, in_vout, reserved_by) \
                         VALUES (?1, ?2, ?3, ?4)",
                        params![c, i.txid.to_rpc_hex(), i.vout, by],
                    )
                    .map_err(storage)?;
                }
            }
        }
        tx.commit().map_err(storage)
    }

    /// Release every input reserved for `txid` (it is confirmed, so its inputs are spent).
    /// Returns how many rows were released; releasing nothing is fine.
    pub fn release_tx(&self, chain: Chain, txid: &Txid) -> Result<usize> {
        self.conn
            .lock()
            .execute(
                "DELETE FROM input_reservation WHERE chain = ?1 AND reserved_by = ?2",
                params![chain.to_string(), txid.to_rpc_hex()],
            )
            .map_err(storage)
    }

    /// Every input currently reserved on `chain`.
    pub fn reserved(&self, chain: Chain) -> Result<HashSet<Outpoint>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT in_txid, in_vout FROM input_reservation WHERE chain = ?1")
            .map_err(storage)?;
        let rows = stmt
            .query_map(params![chain.to_string()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?))
            })
            .map_err(storage)?;
        let mut out = HashSet::new();
        for row in rows {
            let (txid, vout) = row.map_err(storage)?;
            out.insert(Outpoint {
                txid: Txid::from_rpc_hex(&txid)?,
                vout,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(n: u8, vout: u32) -> Outpoint {
        Outpoint {
            txid: Txid([n; 32]),
            vout,
        }
    }

    #[test]
    fn reserve_filter_release_roundtrip() {
        let r = InputReservations::in_memory().unwrap();
        let t = Txid([9; 32]);
        r.reserve(Chain::Btc, &t, &[op(1, 0), op(2, 1)]).unwrap();
        r.reserve(Chain::Btc, &t, &[op(1, 0)]).unwrap(); // idempotent
        assert_eq!(r.reserved(Chain::Btc).unwrap().len(), 2);
        assert!(r.reserved(Chain::Ltc).unwrap().is_empty());
        assert_eq!(r.release_tx(Chain::Btc, &t).unwrap(), 2);
        assert!(r.reserved(Chain::Btc).unwrap().is_empty());
        assert_eq!(r.release_tx(Chain::Btc, &t).unwrap(), 0);
    }

    #[test]
    fn a_second_transaction_cannot_take_reserved_inputs_and_nothing_partial_lands() {
        let r = InputReservations::in_memory().unwrap();
        r.reserve(Chain::Btc, &Txid([9; 32]), &[op(1, 0)]).unwrap();
        let err = r
            .reserve(Chain::Btc, &Txid([8; 32]), &[op(5, 0), op(1, 0)])
            .unwrap_err();
        assert!(matches!(err, SwapError::Rejected(_)));
        assert_eq!(r.reserved(Chain::Btc).unwrap().len(), 1);
    }

    #[test]
    fn reservations_survive_a_reopen_and_a_read_only_handle_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swap.db");
        let t = Txid([9; 32]);
        InputReservations::open(&db)
            .unwrap()
            .reserve(Chain::Zec, &t, &[op(1, 0)])
            .unwrap();
        let ro = InputReservations::open_read_only(&db).unwrap();
        assert_eq!(ro.reserved(Chain::Zec).unwrap().len(), 1);
        assert!(ro.reserve(Chain::Zec, &t, &[op(2, 0)]).is_err());
        assert_eq!(
            InputReservations::open(&db)
                .unwrap()
                .reserved(Chain::Zec)
                .unwrap(),
            HashSet::from([op(1, 0)])
        );
    }
}
