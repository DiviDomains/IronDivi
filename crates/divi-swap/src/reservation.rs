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
//! transaction is seen confirmed. "Not seen" never releases: that is the bug. The one
//! exception is [`InputReservations::release_expired`]: a lock still not seen once its own
//! swap's deadline has passed was dropped, and would be refundable at once if it came back.
//!
//! The table lives in the swap database next to the `Store` tables but on its own SQLite
//! connection, so it does not touch the `Store` schema.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{params, Connection};

use crate::backend::ChainBackend;
use crate::error::{Result, SwapError};
use crate::store::Store;
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

/// One reserved input, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRow {
    /// Chain the input belongs to.
    pub chain: Chain,
    /// The reserved wallet input.
    pub input: Outpoint,
    /// The transaction that spends it (the one that was, or is to be, broadcast).
    pub reserved_by: Txid,
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

    /// Open an existing database for an operator write, refusing while any other connection
    /// (the daemon) has it open. The connection takes SQLite's EXCLUSIVE locking mode before
    /// its first access, and in WAL mode that needs the shared-memory lock no other open
    /// connection leaves free; the lock is then held until this handle is dropped, so the
    /// daemon cannot start writing mid-release either. Never creates the file or the table.
    pub fn open_exclusive(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(storage)?;
        let busy = |e: rusqlite::Error| {
            SwapError::Storage(format!(
                "swap database is in use (is divi-swapd running? stop it first): {e}"
            ))
        };
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")
            .map_err(storage)?;
        // The first read/write is what actually takes the lock.
        conn.execute_batch("BEGIN IMMEDIATE; COMMIT;")
            .map_err(busy)?;
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

    /// Every reservation on every chain, ordered by chain, reserving txid, then input. A
    /// database that predates the table lists as empty.
    pub fn list_all(&self) -> Result<Vec<ReservationRow>> {
        let conn = self.conn.lock();
        let have: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'input_reservation'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(storage)?
            > 0;
        if !have {
            return Ok(Vec::new());
        }
        let mut stmt = conn
            .prepare(
                "SELECT chain, in_txid, in_vout, reserved_by FROM input_reservation \
                 ORDER BY chain, reserved_by, in_txid, in_vout",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(storage)?;
        let mut out = Vec::new();
        for row in rows {
            let (chain, txid, vout, by) = row.map_err(storage)?;
            out.push(ReservationRow {
                chain: chain.parse()?,
                input: Outpoint {
                    txid: Txid::from_rpc_hex(&txid)?,
                    vout,
                },
                reserved_by: Txid::from_rpc_hex(&by)?,
            });
        }
        Ok(out)
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

    /// Release the inputs of each lock in `locks` (its txid and its HTLC locktime, the
    /// swap's deadline) that holds a reservation on `backend`'s chain, once `backend`'s
    /// median time past has reached the deadline and `backend` finds the lock neither in
    /// the mempool nor on chain. Such a lock was dropped; if it ever came back it would be
    /// refundable at once, so its inputs can fund the next swap without risking funds, and
    /// a rebroadcast of it after they are reused is refused by [`Self::reserve`]. A lock in
    /// the mempool or on chain, or before its deadline, keeps its inputs; so does every
    /// reservation `locks` does not name (`divi-swapd --release-reservation` is the
    /// override for those). A backend error stops the sweep with the error and releases
    /// nothing more. Returns how many inputs were released.
    pub async fn release_expired(
        &self,
        backend: &dyn ChainBackend,
        locks: &[(Txid, u32)],
    ) -> Result<usize> {
        let chain = backend.chain();
        let held: HashSet<Txid> = self
            .list_all()?
            .into_iter()
            .filter(|r| r.chain == chain)
            .map(|r| r.reserved_by)
            .collect();
        let due: Vec<_> = locks.iter().filter(|(t, _)| held.contains(t)).collect();
        if due.is_empty() {
            return Ok(0);
        }
        let mtp = backend.median_time_past().await?;
        let mut released = 0;
        for (txid, deadline) in due {
            if mtp >= *deadline && backend.confirmations(txid).await?.is_none() {
                released += self.release_tx(chain, txid)?;
            }
        }
        Ok(released)
    }

    /// [`Self::release_expired`] over every swap in `store` that funds a lock on
    /// `backend`'s chain ([`swap_locks`]).
    pub async fn release_expired_swaps(
        &self,
        store: &Store,
        backend: &dyn ChainBackend,
    ) -> Result<usize> {
        self.release_expired(backend, &swap_locks(store, backend.chain())?)
            .await
    }
}

/// The `(txid, HTLC locktime)` of every lock a swap in `store` funded on `chain`: the maker
/// leg of each maker swap and the taker leg of each taker swap, whatever their state.
pub fn swap_locks(store: &Store, chain: Chain) -> Result<Vec<(Txid, u32)>> {
    let mut out = Vec::new();
    for s in store.list_maker_swaps()? {
        if let (true, Some(h), Some(f)) = (
            s.quote.maker_chain() == chain,
            &s.maker_leg_htlc,
            &s.maker_leg_funding,
        ) {
            out.push((f.tx.txid, h.locktime));
        }
    }
    for s in store.list_taker_swaps()? {
        if let (true, Some(h), Some(f)) = (
            s.quote.taker_chain() == chain,
            &s.taker_leg_htlc,
            &s.taker_leg_funding,
        ) {
            out.push((f.tx.txid, h.locktime));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc::HtlcParams;
    use crate::mock::{MockBackend, MockChain};
    use crate::types::Amount;

    const T0: u32 = 1_700_000_000;
    const DEADLINE: u32 = T0 + 3_600;

    /// A BTC mock chain at MTP `T0` and a funded wallet on it.
    fn chain() -> (MockChain, MockBackend) {
        let c = MockChain::new(Chain::Btc, T0, 600);
        let b = c.backend(4, Amount(10 * Amount::COIN));
        (c, b)
    }

    /// Broadcast a lock (hash `[n; 32]`, deadline [`DEADLINE`]) and reserve input `[n; 32]:0`
    /// for it, as a live backend does.
    async fn lock(r: &InputReservations, b: &MockBackend, n: u8) -> Txid {
        let htlc = HtlcParams {
            hash: [n; 32],
            claim_pubkey: [2; 33],
            refund_pubkey: [3; 33],
            locktime: DEADLINE,
            script_version: Default::default(),
        };
        let f = b.build_funding(&htlc, Amount(1_000)).await.unwrap();
        b.broadcast(&f.tx).await.unwrap();
        r.reserve(Chain::Btc, &f.tx.txid, &[op(n, 0)]).unwrap();
        f.tx.txid
    }

    fn held_by(r: &InputReservations) -> HashSet<Txid> {
        r.list_all()
            .unwrap()
            .into_iter()
            .map(|r| r.reserved_by)
            .collect()
    }

    #[tokio::test]
    async fn a_dropped_lock_past_its_deadline_releases_its_inputs() {
        let (c, b) = chain();
        let r = InputReservations::in_memory().unwrap();
        let t = lock(&r, &b, 1).await;
        c.forget(&t); // gone from the mempool and from every block
        let locks = [(t, DEADLINE)];

        c.advance_time(DEADLINE - T0 - 1);
        assert_eq!(r.release_expired(&b, &locks).await.unwrap(), 0);
        assert_eq!(held_by(&r), HashSet::from([t]), "one second early: kept");

        c.advance_time(1);
        assert_eq!(r.release_expired(&b, &locks).await.unwrap(), 1);
        assert!(r.reserved(Chain::Btc).unwrap().is_empty());
        assert_eq!(r.release_expired(&b, &locks).await.unwrap(), 0);
        // The freed input can fund the next lock.
        r.reserve(Chain::Btc, &Txid([0x77; 32]), &[op(1, 0)])
            .unwrap();
    }

    #[tokio::test]
    async fn a_lock_in_the_mempool_or_on_chain_keeps_its_inputs_past_its_deadline() {
        let (c, b) = chain();
        let r = InputReservations::in_memory().unwrap();
        let mined = lock(&r, &b, 1).await;
        c.mine(1);
        let pending = lock(&r, &b, 2).await;
        c.advance_time(2 * 3_600);
        let locks = [(mined, DEADLINE), (pending, DEADLINE)];
        assert_eq!(r.release_expired(&b, &locks).await.unwrap(), 0);
        c.unconfirm(&mined); // reorged back into the mempool
        assert_eq!(r.release_expired(&b, &locks).await.unwrap(), 0);
        assert_eq!(held_by(&r), HashSet::from([mined, pending]));
    }

    #[tokio::test]
    async fn an_unreachable_backend_an_unnamed_lock_or_another_chain_keeps_the_inputs() {
        let (c, b) = chain();
        let r = InputReservations::in_memory().unwrap();
        let named = lock(&r, &b, 1).await;
        let orphan = lock(&r, &b, 2).await;
        c.forget(&named);
        c.forget(&orphan);
        // Same txid reserved on LTC: a BTC sweep never touches it.
        r.reserve(Chain::Ltc, &named, &[op(3, 0)]).unwrap();
        c.advance_time(2 * 3_600);
        let locks = [(named, DEADLINE)];

        c.set_offline(true);
        assert!(r.release_expired(&b, &locks).await.is_err());
        assert_eq!(r.list_all().unwrap().len(), 3, "an error releases nothing");

        c.set_offline(false);
        assert_eq!(r.release_expired(&b, &locks).await.unwrap(), 1);
        let left: Vec<_> = r
            .list_all()
            .unwrap()
            .into_iter()
            .map(|r| (r.chain, r.reserved_by))
            .collect();
        assert_eq!(left, vec![(Chain::Btc, orphan), (Chain::Ltc, named)]);
    }

    #[tokio::test]
    async fn nothing_held_never_asks_the_backend() {
        let (c, b) = chain();
        let r = InputReservations::in_memory().unwrap();
        c.set_offline(true);
        let locks = [(Txid([1; 32]), DEADLINE)];
        assert_eq!(r.release_expired(&b, &locks).await.unwrap(), 0);
    }

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
