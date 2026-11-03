// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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

#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
use std::collections::HashSet;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use parking_lot::Mutex;
#[cfg(not(target_arch = "wasm32"))]
use rusqlite::{params, Connection};

#[cfg(not(target_arch = "wasm32"))]
use crate::backend::{ChainBackend, TipHeader};
use crate::error::Result;
#[cfg(not(target_arch = "wasm32"))]
use crate::error::SwapError;
#[cfg(not(target_arch = "wasm32"))]
use crate::store::Store;
#[cfg(not(target_arch = "wasm32"))]
use crate::types::SignedTx;
use crate::types::{Chain, Outpoint, Txid};

#[cfg(not(target_arch = "wasm32"))]
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS input_reservation (
    chain       TEXT    NOT NULL,
    in_txid     TEXT    NOT NULL,
    in_vout     INTEGER NOT NULL,
    reserved_by TEXT    NOT NULL,
    PRIMARY KEY (chain, in_txid, in_vout)
);
CREATE INDEX IF NOT EXISTS input_reservation_by_tx ON input_reservation (chain, reserved_by);
CREATE TABLE IF NOT EXISTS lock_absence (
    chain               TEXT    NOT NULL,
    lock_txid           TEXT    NOT NULL,
    first_absent_height INTEGER NOT NULL,
    first_absent_hash   TEXT,
    first_absent_after  INTEGER,
    PRIMARY KEY (chain, lock_txid)
);
CREATE TABLE IF NOT EXISTS expiry_tip (
    chain  TEXT    NOT NULL PRIMARY KEY,
    height INTEGER NOT NULL
);
";

/// Blocks between the first and the releasing absent check of a lock past its deadline.
pub const EXPIRY_ABSENT_BLOCKS: u64 = 6;

/// How far behind the wall clock a backend's tip may be, in target block spacings, for the
/// expiry sweep to count blocks from it at once. A tip further behind still counts, but only
/// from the first tip whose median time past reaches the wall clock of the check that found
/// the lock absent.
pub const EXPIRY_MAX_TIP_LAG_BLOCKS: u32 = 2;

/// How far behind the wall clock a backend's tip may be, in seconds, for the expiry sweep to
/// check anything at all.
pub const EXPIRY_MAX_TIP_AGE_SECS: u32 = 24 * 60 * 60;

/// How far ahead of the wall clock a backend's tip time may be, in seconds, for the expiry
/// sweep to trust it: the consensus future limit (`MAX_FUTURE_BLOCK_TIME` in Bitcoin Core and
/// Litecoin Core, `MAX_FUTURE_BLOCK_TIME_LOCAL` in zcashd), used for every chain.
pub const EXPIRY_MAX_TIP_LEAD_SECS: u32 = 2 * 60 * 60;

/// Where the expiry sweep may start counting a lock's absent blocks: a per-chain setting
/// (`expiry_start` in divi-swapd's `[divi]`, `[btc]`, `[ltc]` and `[zec]`;
/// `--divi-expiry-start`, `--btc-expiry-start`, `--ltc-expiry-start` and
/// `--zec-expiry-start` in the CLI), passed to [`InputReservations::release_expired_from`]
/// for the chain it sweeps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExpiryStart {
    /// `"tip"` (the default): a first absent check at a tip whose own time is within
    /// [`EXPIRY_MAX_TIP_LAG_BLOCKS`] target spacings of the wall clock counts at once; one at
    /// a tip further behind is pending until the backend's median time past reaches that
    /// check's clock.
    #[default]
    Tip,
    /// `"mtp"`: every first absent check is pending until the backend's median time past
    /// reaches that check's clock, however fresh the tip looks, so a replayed tip stamped
    /// near the clock cannot start the count. Every release on the chain comes about five
    /// blocks later.
    Mtp,
}

impl std::str::FromStr for ExpiryStart {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "tip" => Ok(Self::Tip),
            "mtp" => Ok(Self::Mtp),
            other => Err(format!("must be \"tip\" or \"mtp\", got {other:?}")),
        }
    }
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

/// Stub reservation handle on `wasm32` (browser extension builds use [`crate::StoreBackend`]).
#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, Default)]
pub struct InputReservations;

#[cfg(target_arch = "wasm32")]
impl InputReservations {
    /// A throwaway in-memory table.
    pub fn in_memory() -> Result<Self> {
        Ok(Self)
    }

    /// Reserve `inputs` for `txid`.
    pub fn reserve(&self, _chain: Chain, _txid: &Txid, _inputs: &[Outpoint]) -> Result<()> {
        Ok(())
    }

    /// Release reservations held by `txid` on `chain`.
    pub fn release_tx(&self, _chain: Chain, _txid: &Txid) -> Result<usize> {
        Ok(0)
    }

    /// Every reserved input across all chains.
    pub fn list_all(&self) -> Result<Vec<ReservationRow>> {
        Ok(Vec::new())
    }

    /// Reserved inputs on `chain`.
    pub fn reserved(&self, _chain: Chain) -> Result<HashSet<Outpoint>> {
        Ok(HashSet::new())
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;

    /// A tip time more than [`EXPIRY_MAX_TIP_LAG_BLOCKS`] target spacings behind `now`, or from
    /// a backend that does not say its spacing.
    fn tip_is_behind(tip_time: u32, spacing: Option<u32>, now: u32) -> bool {
        !spacing.is_some_and(|s| now.saturating_sub(tip_time) <= EXPIRY_MAX_TIP_LAG_BLOCKS * s)
    }

    /// A tip time more than [`EXPIRY_MAX_TIP_AGE_SECS`] behind `now`.
    fn tip_is_dead(tip_time: u32, now: u32) -> bool {
        now.saturating_sub(tip_time) > EXPIRY_MAX_TIP_AGE_SECS
    }

    /// A tip time, or a median time past, more than [`EXPIRY_MAX_TIP_LEAD_SECS`] ahead of
    /// `now`: no node would have accepted it, so the backend or the clock is wrong.
    fn tip_is_ahead(tip_time: u32, now: u32) -> bool {
        tip_time.saturating_sub(now) > EXPIRY_MAX_TIP_LEAD_SECS
    }

    /// A `lock_absence` row: its block height and hash, and the `now` a pending record waits for.
    type AbsenceRecord = (u64, Option<String>, Option<u32>);

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
            let conn =
                Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
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
            let conn =
                Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
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
            // A table from before the block hash was stored: add the column. Its old rows keep
            // a NULL hash, and the sweep re-anchors them at its next fresh check.
            let has_hash: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('lock_absence') \
                 WHERE name = 'first_absent_hash'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(storage)?
                > 0;
            if !has_hash {
                conn.execute_batch("ALTER TABLE lock_absence ADD COLUMN first_absent_hash TEXT")
                    .map_err(storage)?;
            }
            // A table from before pending records: add the column. Its old rows were recorded
            // at a tip within two spacings of the clock, so a NULL (counting) suits them.
            let has_after: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('lock_absence') \
                 WHERE name = 'first_absent_after'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(storage)?
                > 0;
            if !has_after {
                conn.execute_batch(
                    "ALTER TABLE lock_absence ADD COLUMN first_absent_after INTEGER",
                )
                .map_err(storage)?;
            }
            Ok(Self {
                conn: Arc::new(Mutex::new(conn)),
            })
        }

        /// Reserve `inputs` for `txid`, all or none. Idempotent: reserving the same inputs for the
        /// same transaction again is a no-op, so a re-broadcast of the persisted bytes is safe.
        /// Inputs already reserved by a *different* transaction are an error (`InputsHeld`): that
        /// transaction conflicts with a live one, and the caller must not send it.
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
                        return Err(SwapError::InputsHeld(format!(
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
        /// median time past has reached the deadline and `backend` has found the lock neither in
        /// the mempool nor on chain on two checks at least [`EXPIRY_ABSENT_BLOCKS`] blocks
        /// apart by its tip height. Such a lock was dropped; if it ever came back it would be
        /// refundable at once, so its inputs can fund the next swap without risking funds, and
        /// a rebroadcast of it after they are reused is refused by [`Self::reserve`].
        ///
        /// The first absent check past the deadline records its tip block (height and hash) in
        /// `lock_absence` (so a restart keeps it); a check that finds the lock clears the record.
        /// Only blocks mined after that check count, so a syncing endpoint replaying old blocks
        /// never releases: a record made at a tip more than [`EXPIRY_MAX_TIP_LAG_BLOCKS`] target
        /// spacings behind `now` is pending, keeps that check's `now`, and follows the tip until
        /// the backend's median time past reaches it. A tip block's own time does not end it: a
        /// miner may stamp a block up to [`EXPIRY_MAX_TIP_LEAD_SECS`] ahead of real time, so an
        /// endpoint replaying blocks from before the check could show one past it, while MTP
        /// (monotonic by consensus, the median of the last eleven blocks) cannot run ahead of
        /// real time like that. If the tip at which MTP reaches it is the block right after the
        /// record's, the record starts counting where it is; otherwise it moves to the tip and
        /// counts from there. MTP trails the tip by about six blocks, so a pending record on a
        /// sparse chain whose blocks come minutes apart releases about
        /// [`EXPIRY_ABSENT_BLOCKS`] + 5 blocks after the first check, once they are mined.
        /// A record made at a tip within [`EXPIRY_MAX_TIP_LAG_BLOCKS`] spacings of `now` counts at
        /// once here; [`Self::release_expired_from`] with [`ExpiryStart::Mtp`] makes it pending
        /// too (a chain's opt-in, at the cost of about five more blocks before each release).
        /// A lock in the mempool or on chain, or before its deadline, keeps its inputs; so does
        /// every reservation `locks` does not name (`divi-swapd --release-reservation` is the
        /// override for those). Each sweep reads the tip's height, hash and time from one block
        /// ([`ChainBackend::tip_header`]), and checks only while that tip is plausible, in this
        /// order:
        /// - a tip time more than [`EXPIRY_MAX_TIP_AGE_SECS`] behind `now` (unix seconds), or a
        ///   backend that reports no spacing, is stale; so is a tip time more than
        ///   [`EXPIRY_MAX_TIP_LEAD_SECS`] ahead of `now`. Nothing is checked, recorded or
        ///   released;
        /// - a tip height below the highest fresh one seen (`expiry_tip`) is a lagging fallback
        ///   endpoint or a reorg to a shorter chain: the records are kept, nothing is released,
        ///   and the high-water mark stays;
        /// - a median time past ([`ChainBackend::median_time_past`]) more than
        ///   [`EXPIRY_MAX_TIP_LEAD_SECS`] ahead of `now` is treated as a tip past that limit:
        ///   nothing is checked, recorded or released, no record moves and the high-water mark
        ///   stays. A valid chain's MTP is a median of block times each accepted within that
        ///   limit, so it cannot be past it either; one that is comes from a wrong backend or
        ///   clock (the tip and MTP are separate reads, maybe from separate endpoints), and a
        ///   pending record must not start its count on an MTP the clock cannot vouch for;
        /// - a record whose block is no longer on the backend's main chain
        ///   ([`ChainBackend::in_best_chain`]) was reorged out: it is replaced by one at the
        ///   current tip, so the count starts over. A record from before hashes were stored is
        ///   re-anchored the same way. A pending record is only ever moved forward, so neither
        ///   a lagging endpoint (stopped by the high-water mark) nor a stale one can reset a
        ///   counting record.
        ///
        /// Each case is logged. A backend error stops the sweep with the error and releases
        /// nothing more. Returns how many inputs were released.
        pub async fn release_expired(
            &self,
            backend: &dyn ChainBackend,
            locks: &[(Txid, u32)],
            now: u32,
        ) -> Result<usize> {
            self.release_expired_from(backend, locks, now, ExpiryStart::Tip)
                .await
        }

        /// [`Self::release_expired`], with `start` saying where a first absent check may start
        /// its count. [`ExpiryStart::Tip`] is exactly [`Self::release_expired`]. With
        /// [`ExpiryStart::Mtp`], a record made at a tip that looks fresh (within
        /// [`EXPIRY_MAX_TIP_LAG_BLOCKS`] spacings of `now`) is pending exactly like one made at a
        /// tip further behind: it keeps that check's `now` in `first_absent_after`, follows the
        /// tip while the backend's median time past is before it, and then counts as above. So
        /// does a record restarted after a reorg or re-anchored for want of a hash. A replayed tip
        /// stamped near the clock then cannot start a count on blocks from before the check;
        /// the cost is that MTP trails the tip by about six blocks, so every release on that
        /// chain comes about five blocks later (11 blocks after the first check instead of 6 on a
        /// chain swept at each block). The stale, ahead, high-water and reorg guards are the
        /// same for both.
        pub async fn release_expired_from(
            &self,
            backend: &dyn ChainBackend,
            locks: &[(Txid, u32)],
            now: u32,
            start: ExpiryStart,
        ) -> Result<usize> {
            let chain = backend.chain();
            let held: HashSet<Txid> = self
                .list_all()?
                .into_iter()
                .filter(|r| r.chain == chain)
                .map(|r| r.reserved_by)
                .collect();
            self.forget_absences(chain, |t| !held.contains(t))?;
            let due: Vec<_> = locks.iter().filter(|(t, _)| held.contains(t)).collect();
            if due.is_empty() {
                return Ok(0);
            }
            let tip = backend.tip_header().await?;
            let spacing = backend.target_block_secs();
            if spacing.is_none() || tip_is_dead(tip.time, now) {
                tracing::warn!(
                    %chain,
                    height = tip.height,
                    tip_time = tip.time,
                    now,
                    ?spacing,
                    "backend tip is stale; not releasing expired locks"
                );
                return Ok(0);
            }
            // The `now` a record made at this tip waits for, unless it counts at once: with
            // `ExpiryStart::Mtp` it never does, however fresh the tip looks.
            let pending =
                (start == ExpiryStart::Mtp || tip_is_behind(tip.time, spacing, now)).then_some(now);
            if tip_is_ahead(tip.time, now) {
                tracing::warn!(
                    %chain,
                    height = tip.height,
                    tip_time = tip.time,
                    now,
                    limit = EXPIRY_MAX_TIP_LEAD_SECS,
                    "backend tip time is past the consensus future limit; not releasing expired locks"
                );
                return Ok(0);
            }
            if let Some(last) = self.last_tip(chain)?.filter(|l| tip.height < *l) {
                tracing::warn!(
                    %chain,
                    height = tip.height,
                    last,
                    "backend tip height went backwards (lagging endpoint or reorg); \
                     keeping lock absence records, not releasing"
                );
                return Ok(0);
            }
            let mtp = backend.median_time_past().await?;
            if tip_is_ahead(mtp, now) {
                tracing::warn!(
                    %chain,
                    height = tip.height,
                    mtp,
                    now,
                    limit = EXPIRY_MAX_TIP_LEAD_SECS,
                    "backend median time past is past the consensus future limit; \
                     not releasing expired locks"
                );
                return Ok(0);
            }
            self.record_tip(chain, tip.height)?;
            let mut on_chain: HashMap<(u64, String), bool> = HashMap::new();
            let mut released = 0;
            for (txid, deadline) in due {
                if mtp < *deadline {
                    continue;
                }
                if backend.confirmations(txid).await?.is_some() {
                    self.forget_absences(chain, |t| t == txid)?;
                    continue;
                }
                let (first, hash) = match self.absence(chain, txid)? {
                    None => {
                        self.record_absence(chain, txid, &tip, pending)?;
                        continue;
                    }
                    Some((_, _, Some(after))) if mtp < after => {
                        // MTP is still before the first absent check, so the tip may be a
                        // replayed block from before it, whatever its own time says: follow it.
                        self.record_absence(chain, txid, &tip, Some(after))?;
                        continue;
                    }
                    Some((first, Some(hash), Some(_))) if tip.height == first + 1 => {
                        tracing::info!(
                            %chain,
                            %txid,
                            first,
                            height = tip.height,
                            "first block after the absent check; the lock's count starts"
                        );
                        self.record_absence(
                            chain,
                            txid,
                            &TipHeader {
                                height: first,
                                hash: hash.clone(),
                                time: tip.time,
                            },
                            None,
                        )?;
                        (first, hash)
                    }
                    Some((first, _, Some(_))) => {
                        tracing::info!(
                            %chain,
                            %txid,
                            first,
                            height = tip.height,
                            "tip is past the absent check; the lock's count starts at the tip"
                        );
                        self.record_absence(chain, txid, &tip, None)?;
                        continue;
                    }
                    Some((first, None, None)) => {
                        tracing::warn!(
                            %chain,
                            %txid,
                            first,
                            height = tip.height,
                            "lock absence record has no block hash; re-anchoring it at the tip"
                        );
                        self.record_absence(chain, txid, &tip, pending)?;
                        continue;
                    }
                    Some((first, Some(hash), None)) => (first, hash),
                };
                if first > tip.height {
                    continue;
                }
                let key = (first, hash);
                let kept = match on_chain.get(&key) {
                    Some(k) => *k,
                    None => {
                        let k = backend.in_best_chain(key.0, &key.1).await?;
                        on_chain.insert(key.clone(), k);
                        k
                    }
                };
                if !kept {
                    tracing::warn!(
                        %chain,
                        %txid,
                        first,
                        hash = %key.1,
                        height = tip.height,
                        "first absent block was reorged out; restarting the count at the tip"
                    );
                    self.record_absence(chain, txid, &tip, pending)?;
                } else if tip.height >= first + EXPIRY_ABSENT_BLOCKS {
                    released += self.release_tx(chain, txid)?;
                    self.forget_absences(chain, |t| t == txid)?;
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
            now: u32,
        ) -> Result<usize> {
            self.release_expired_swaps_from(store, backend, now, ExpiryStart::Tip)
                .await
        }

        /// [`Self::release_expired_swaps`] with `start` ([`Self::release_expired_from`]): a
        /// chain's `expiry_start` setting.
        pub async fn release_expired_swaps_from(
            &self,
            store: &Store,
            backend: &dyn ChainBackend,
            now: u32,
            start: ExpiryStart,
        ) -> Result<usize> {
            self.release_expired_from(backend, &swap_locks(store, backend.chain())?, now, start)
                .await
        }

        /// The tip height at which the expiry sweep first found `lock` absent past its
        /// deadline, if that record stands. Reads records from before hashes were stored too.
        pub fn first_absent_height(&self, chain: Chain, lock: &Txid) -> Result<Option<u64>> {
            self.conn
            .lock()
            .query_row(
                "SELECT first_absent_height FROM lock_absence WHERE chain = ?1 AND lock_txid = ?2",
                params![chain.to_string(), lock.to_rpc_hex()],
                |r| r.get::<_, i64>(0),
            )
            .map(|h| Some(h as u64))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })
            .map_err(storage)
        }

        /// The tip block (height, and hash unless the record predates hashes) at which the
        /// expiry sweep first found `lock` absent past its deadline, if that record stands.
        pub fn first_absent_block(
            &self,
            chain: Chain,
            lock: &Txid,
        ) -> Result<Option<(u64, Option<String>)>> {
            self.conn
                .lock()
                .query_row(
                    "SELECT first_absent_height, first_absent_hash FROM lock_absence \
                 WHERE chain = ?1 AND lock_txid = ?2",
                    params![chain.to_string(), lock.to_rpc_hex()],
                    |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, Option<String>>(1)?)),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(e),
                })
                .map_err(storage)
        }

        /// `lock`'s absence record: its block (height, and hash unless it predates hashes) and,
        /// while it is pending, the `now` of the check that made it.
        fn absence(&self, chain: Chain, lock: &Txid) -> Result<Option<AbsenceRecord>> {
            self.conn
                .lock()
                .query_row(
                    "SELECT first_absent_height, first_absent_hash, first_absent_after \
                 FROM lock_absence WHERE chain = ?1 AND lock_txid = ?2",
                    params![chain.to_string(), lock.to_rpc_hex()],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)? as u64,
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, Option<u32>>(2)?,
                        ))
                    },
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(e),
                })
                .map_err(storage)
        }

        /// Record (or re-anchor) `lock`'s first absent check at `tip`, pending until a tip block
        /// time reaches `after` if one is given.
        fn record_absence(
            &self,
            chain: Chain,
            lock: &Txid,
            tip: &TipHeader,
            after: Option<u32>,
        ) -> Result<()> {
            self.conn
                .lock()
                .execute(
                    "INSERT INTO lock_absence \
                 (chain, lock_txid, first_absent_height, first_absent_hash, first_absent_after) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (chain, lock_txid) DO UPDATE SET \
                 first_absent_height = excluded.first_absent_height, \
                 first_absent_hash = excluded.first_absent_hash, \
                 first_absent_after = excluded.first_absent_after",
                    params![
                        chain.to_string(),
                        lock.to_rpc_hex(),
                        tip.height as i64,
                        tip.hash,
                        after
                    ],
                )
                .map(|_| ())
                .map_err(storage)
        }

        /// Delete the absence records on `chain` whose lock `which` selects.
        fn forget_absences(&self, chain: Chain, which: impl Fn(&Txid) -> bool) -> Result<()> {
            let conn = self.conn.lock();
            let mut stmt = conn
                .prepare("SELECT lock_txid FROM lock_absence WHERE chain = ?1")
                .map_err(storage)?;
            let ids = stmt
                .query_map(params![chain.to_string()], |r| r.get::<_, String>(0))
                .map_err(storage)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(storage)?;
            for id in ids {
                if which(&Txid::from_rpc_hex(&id)?) {
                    conn.execute(
                        "DELETE FROM lock_absence WHERE chain = ?1 AND lock_txid = ?2",
                        params![chain.to_string(), id],
                    )
                    .map_err(storage)?;
                }
            }
            Ok(())
        }

        fn last_tip(&self, chain: Chain) -> Result<Option<u64>> {
            self.conn
                .lock()
                .query_row(
                    "SELECT height FROM expiry_tip WHERE chain = ?1",
                    params![chain.to_string()],
                    |r| r.get::<_, i64>(0),
                )
                .map(|h| Some(h as u64))
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(e),
                })
                .map_err(storage)
        }

        fn record_tip(&self, chain: Chain, height: u64) -> Result<()> {
            self.conn
                .lock()
                .execute(
                    "INSERT INTO expiry_tip (chain, height) VALUES (?1, ?2) \
                 ON CONFLICT (chain) DO UPDATE SET height = excluded.height",
                    params![chain.to_string(), height as i64],
                )
                .map(|_| ())
                .map_err(storage)
        }
    }

    /// One lock a swap funded: its signed tx, its HTLC locktime (the swap's deadline) once the
    /// swap stored the HTLC, and whether the swap is finished.
    struct SwapLock {
        tx: SignedTx,
        locktime: Option<u32>,
        finished: bool,
    }

    /// Every lock a swap in `store` funded on `chain`: the maker leg of each maker swap and the
    /// taker leg of each taker swap, whatever their state.
    fn locks_on(store: &Store, chain: Chain) -> Result<Vec<SwapLock>> {
        let mut out = Vec::new();
        for s in store.list_maker_swaps()? {
            if let (true, Some(f)) = (s.quote.maker_chain() == chain, &s.maker_leg_funding) {
                out.push(SwapLock {
                    tx: f.tx.clone(),
                    locktime: s.maker_leg_htlc.map(|h| h.locktime),
                    finished: matches!(s.state, crate::SwapState::Done | crate::SwapState::Lost),
                });
            }
        }
        for s in store.list_taker_swaps()? {
            if let (true, Some(f)) = (s.quote.taker_chain() == chain, &s.taker_leg_funding) {
                out.push(SwapLock {
                    tx: f.tx.clone(),
                    locktime: s.taker_leg_htlc.map(|h| h.locktime),
                    finished: s.state.is_terminal(),
                });
            }
        }
        Ok(out)
    }

    /// The `(txid, HTLC locktime)` of every lock a swap in `store` funded on `chain`: the maker
    /// leg of each maker swap and the taker leg of each taker swap, whatever their state.
    pub fn swap_locks(store: &Store, chain: Chain) -> Result<Vec<(Txid, u32)>> {
        Ok(locks_on(store, chain)?
            .into_iter()
            .filter_map(|l| Some((l.tx.txid, l.locktime?)))
            .collect())
    }

    impl InputReservations {
        /// The transactions holding a reservation on `chain`.
        fn holders(&self, chain: Chain) -> Result<HashSet<Txid>> {
            Ok(self
                .list_all()?
                .into_iter()
                .filter(|r| r.chain == chain)
                .map(|r| r.reserved_by)
                .collect())
        }

        /// Release the reservations held by the lock on `chain` of every finished swap (`Done`
        /// or `Lost`) in `store` (maker or taker); returns how many inputs were released. A
        /// finished swap's lock is on chain (a claim or its refund spent it), so its inputs can
        /// never be selected again anyway; an `Aborted` maker swap whose unsent lock was rejected
        /// keeps its row for [`Self::release_expired_swaps_and_bookings`]'s absence check. Only
        /// rows still held are touched: running it again, or after a restart, releases nothing
        /// twice, and a swap that is not finished keeps its reservation however often it runs.
        pub fn release_finished_swaps(&self, store: &Store, chain: Chain) -> Result<usize> {
            let held = self.holders(chain)?;
            if held.is_empty() {
                return Ok(0);
            }
            let mut released = 0;
            for l in locks_on(store, chain)? {
                if l.finished && held.contains(&l.tx.txid) {
                    released += self.release_tx(chain, &l.tx.txid)?;
                }
            }
            Ok(released)
        }

        /// [`Self::release_expired_swaps`] on `backend` with `start` ([`Self::release_expired_from`]),
        /// then the wallet booking of each lock it
        /// released: a wallet that tombstoned a lock's inputs when it was broadcast (the DIVI
        /// wallet file) gets them back through [`ChainBackend::release_dead_lock`] once the
        /// backend has its own proof that they are unspent (no proof, nothing given back: the
        /// coins stay out of the wallet, never spent twice; a failure only warns). Returns how
        /// many inputs the table released.
        pub async fn release_expired_swaps_and_bookings(
            &self,
            store: &Store,
            backend: &dyn ChainBackend,
            now: u32,
            start: ExpiryStart,
        ) -> Result<usize> {
            let chain = backend.chain();
            let before = self.holders(chain)?;
            if before.is_empty() {
                return Ok(0);
            }
            let released = self
                .release_expired_from(backend, &swap_locks(store, chain)?, now, start)
                .await?;
            if released == 0 {
                return Ok(0);
            }
            let after = self.holders(chain)?;
            for l in locks_on(store, chain)? {
                let txid = l.tx.txid;
                if !before.contains(&txid) || after.contains(&txid) {
                    continue;
                }
                if let Err(e) = backend.release_dead_lock(&l.tx).await {
                    tracing::warn!(%chain, %txid, error = %e, "dropped lock: wallet booking kept");
                }
            }
            Ok(released)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::htlc::HtlcParams;
        use crate::mock::{MockBackend, MockChain};
        use crate::types::{Amount, SignedTx};

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
            lock_tx(r, b, n).await.txid
        }

        /// [`lock`], keeping the signed bytes for a rebroadcast.
        async fn lock_tx(r: &InputReservations, b: &MockBackend, n: u8) -> SignedTx {
            let htlc = HtlcParams {
                hash: [n; 32],
                claim_pubkey: [2; 33],
                refund_pubkey: [3; 33],
                locktime: DEADLINE,
                script_version: Default::default(),
            };
            let f = b.build_funding(&htlc, Amount(1_000)).await.unwrap();
            b.broadcast(&f.tx).await.unwrap();
            r.reserve(b.chain(), &f.tx.txid, &[op(n, 0)]).unwrap();
            f.tx
        }

        fn held_by(r: &InputReservations) -> HashSet<Txid> {
            r.list_all()
                .unwrap()
                .into_iter()
                .map(|r| r.reserved_by)
                .collect()
        }

        /// One sweep with the wall clock at the mock's own clock: a fresh backend.
        async fn sweep(
            r: &InputReservations,
            c: &MockChain,
            b: &MockBackend,
            locks: &[(Txid, u32)],
        ) -> usize {
            r.release_expired(b, locks, c.mtp()).await.unwrap()
        }

        #[tokio::test]
        async fn a_dropped_lock_past_its_deadline_releases_after_two_absent_checks_six_blocks_apart(
        ) {
            let (c, b) = chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t); // gone from the mempool and from every block
            let locks = [(t, DEADLINE)];

            c.advance_time(DEADLINE - T0 - 1);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            assert_eq!(
                r.first_absent_height(Chain::Btc, &t).unwrap(),
                None,
                "before the deadline nothing counts"
            );

            c.advance_time(1);
            let first = c.height();
            assert_eq!(
                sweep(&r, &c, &b, &locks).await,
                0,
                "one absent check is not enough"
            );
            assert_eq!(r.first_absent_height(Chain::Btc, &t).unwrap(), Some(first));
            assert_eq!(
                sweep(&r, &c, &b, &locks).await,
                0,
                "a second check at the same height is not a new one"
            );
            c.mine(EXPIRY_ABSENT_BLOCKS - 1);
            assert_eq!(
                sweep(&r, &c, &b, &locks).await,
                0,
                "five blocks apart: kept"
            );
            assert_eq!(held_by(&r), HashSet::from([t]));

            c.mine(1);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 1);
            assert!(r.reserved(Chain::Btc).unwrap().is_empty());
            assert_eq!(r.first_absent_height(Chain::Btc, &t).unwrap(), None);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            // The freed input can fund the next lock.
            r.reserve(Chain::Btc, &Txid([0x77; 32]), &[op(1, 0)])
                .unwrap();
        }

        /// A DIVI mock chain (60 s target spacing) at MTP `T0` and a funded wallet on it.
        fn divi_chain() -> (MockChain, MockBackend) {
            let c = MockChain::new(Chain::Divi, T0, 60);
            let b = c.backend(4, Amount(10 * Amount::COIN));
            (c, b)
        }

        /// One block `gap` seconds after the tip (the mock mines one target spacing on).
        fn mine_after(c: &MockChain, gap: u32) {
            c.mine(1);
            c.advance_time(gap - 60);
        }

        #[tokio::test]
        async fn a_sparse_but_live_divi_tip_releases_after_the_usual_absent_blocks() {
            let (c, b) = divi_chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t);
            c.advance_time(DEADLINE - T0);
            let locks = [(t, DEADLINE)];

            // Ten minutes between blocks; each sweep runs three minutes after the tip block,
            // so the tip is always more than two 60 s spacings behind the wall clock.
            let first = c.height();
            let mut released = 0;
            for _ in 0..EXPIRY_ABSENT_BLOCKS {
                released += r.release_expired(&b, &locks, c.mtp() + 180).await.unwrap();
                assert_eq!(released, 0, "fewer than six blocks past the first check");
                mine_after(&c, 600);
            }
            assert_eq!(c.height(), first + EXPIRY_ABSENT_BLOCKS);
            assert_eq!(
                r.release_expired(&b, &locks, c.mtp() + 180).await.unwrap(),
                1,
                "six live blocks past the first absent check"
            );
            assert!(r.reserved(Chain::Divi).unwrap().is_empty());
            assert_eq!(r.first_absent_height(Chain::Divi, &t).unwrap(), None);
        }

        #[tokio::test]
        async fn a_sparse_divi_tip_whose_mtp_trails_it_starts_counting_once_mtp_passes_the_check() {
            let (c, b) = divi_chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t);
            c.advance_time(DEADLINE - T0);
            let locks = [(t, DEADLINE)];
            // Blocks ten minutes apart, MTP five blocks behind the tip's time (the median of the
            // last eleven), sweeps three minutes after each block: the first check is pending, and
            // MTP passes its clock six blocks on. The count starts at the block before that one
            // (the record's), so the release comes eleven blocks after the first check.
            b.set_tip_lead(5 * 600);
            let first = c.height();
            let sweep = |c: &MockChain| c.mtp() + 5 * 600 + 180;
            let mut released = 0;
            for _ in 0..2 * EXPIRY_ABSENT_BLOCKS - 1 {
                released += r.release_expired(&b, &locks, sweep(&c)).await.unwrap();
                assert_eq!(
                    released,
                    0,
                    "block {}: MTP not yet six blocks past the check",
                    c.height()
                );
                mine_after(&c, 600);
            }
            assert_eq!(c.height(), first + 2 * EXPIRY_ABSENT_BLOCKS - 1);
            assert_eq!(r.release_expired(&b, &locks, sweep(&c)).await.unwrap(), 1);
        }

        #[tokio::test]
        async fn a_syncing_divi_endpoint_releases_nothing() {
            let (c, b) = divi_chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t);
            let locks = [(t, DEADLINE)];
            // The wall clock is three hours past the deadline; the endpoint replays the chain
            // from an hour before the deadline, many blocks (60 s of chain time each) per second
            // of wall clock, its tip always more than two spacings behind the clock.
            let now = DEADLINE + 3 * 3_600;
            let mut sweeps = 0;
            while c.mtp() + 180 < now {
                assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
                c.mine(1);
                sweeps += 1;
            }
            assert!(sweeps > 200);
            assert_eq!(
                held_by(&r),
                HashSet::from([t]),
                "replayed blocks never count"
            );
            // Caught up: the count runs over the blocks mined after the first absent check.
            assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
            for i in 1..=EXPIRY_ABSENT_BLOCKS {
                mine_after(&c, 600);
                assert_eq!(
                    r.release_expired(&b, &locks, c.mtp() + 180).await.unwrap(),
                    usize::from(i == EXPIRY_ABSENT_BLOCKS),
                    "live block {i}"
                );
            }
        }

        /// A DIVI lock past its deadline whose first absent check is made at a tip an hour behind
        /// the wall clock (`after`), so its record is pending. Returns the lock list and `after`.
        async fn pending_divi_lock(
            r: &InputReservations,
            c: &MockChain,
            b: &MockBackend,
        ) -> ([(Txid, u32); 1], u32) {
            let t = lock(r, b, 1).await;
            c.forget(&t);
            c.advance_time(DEADLINE - T0);
            let locks = [(t, DEADLINE)];
            let after = c.mtp() + 3_600;
            assert_eq!(r.release_expired(b, &locks, after).await.unwrap(), 0);
            assert_eq!(
                r.absence(Chain::Divi, &t).unwrap(),
                Some((c.height(), Some(c.tip_hash()), Some(after)))
            );
            (locks, after)
        }

        #[tokio::test]
        async fn a_replayed_tip_stamped_ahead_of_the_first_check_counts_nothing_until_mtp_passes_it(
        ) {
            let (c, b) = divi_chain();
            let r = InputReservations::in_memory().unwrap();
            let (locks, after) = pending_divi_lock(&r, &c, &b).await;
            let t = locks[0].0;
            // The endpoint replays the hour of blocks before the check, a second of wall clock
            // each, every block stamped 70 minutes ahead of the chain's MTP: each tip's time is
            // past `after`, and within the future limit, but every block predates the check.
            b.set_tip_lead(3_600 + 600);
            let mut now = after;
            loop {
                c.mine(1);
                now += 1;
                assert_eq!(
                    r.release_expired(&b, &locks, now).await.unwrap(),
                    0,
                    "replayed block {}",
                    c.height()
                );
                if c.mtp() >= after {
                    break;
                }
                assert_eq!(
                    r.absence(Chain::Divi, &t).unwrap(),
                    Some((c.height(), Some(c.tip_hash()), Some(after))),
                    "MTP {} is before the check: the record follows the tip",
                    c.mtp()
                );
            }
            // MTP reached the check at the block right after the record's: the count starts
            // where the record is, and runs the usual six blocks.
            let first = c.height() - 1;
            assert_eq!(
                r.absence(Chain::Divi, &t).unwrap(),
                Some((first, Some(c.block_hash(first)), None))
            );
            c.mine(EXPIRY_ABSENT_BLOCKS - 2);
            assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
            assert_eq!(held_by(&r), HashSet::from([t]));
            c.mine(1);
            assert_eq!(c.height(), first + EXPIRY_ABSENT_BLOCKS);
            assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 1);
            assert_eq!(r.first_absent_height(Chain::Divi, &t).unwrap(), None);
        }

        #[tokio::test]
        async fn a_pending_record_seen_again_only_past_mtp_starts_its_count_at_the_tip() {
            let (c, b) = divi_chain();
            let r = InputReservations::in_memory().unwrap();
            let (locks, after) = pending_divi_lock(&r, &c, &b).await;
            let t = locks[0].0;
            b.set_tip_lead(3_600 + 600);
            // Ten replayed blocks unseen, then a sweep: the tip's time is past the check, its
            // MTP is not, so the record follows the tip and counts nothing.
            c.mine(10);
            let now = after + 60;
            assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
            assert_eq!(
                r.absence(Chain::Divi, &t).unwrap(),
                Some((c.height(), Some(c.tip_hash()), Some(after)))
            );
            // The next sweep comes once MTP is past the check, many blocks on: the count starts
            // at that tip.
            while c.mtp() < after + 60 {
                c.mine(1);
            }
            let now = now + 120;
            assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
            let first = c.height();
            assert_eq!(
                r.absence(Chain::Divi, &t).unwrap(),
                Some((first, Some(c.tip_hash()), None))
            );
            c.mine(EXPIRY_ABSENT_BLOCKS - 1);
            assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
            assert_eq!(held_by(&r), HashSet::from([t]));
            c.mine(1);
            assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 1);
        }

        /// One sweep of a DIVI chain: the tip height, the inputs released, and the lock's record
        /// (its height and, while pending, the clock it waits for) after the sweep.
        type Step = (u64, usize, Option<(u64, Option<u32>)>);

        /// A DIVI lock past its deadline, swept once at its first absent check and then once
        /// after each of `blocks` blocks mined `gap` seconds apart. Every tip is stamped `lead`
        /// seconds ahead of the chain's MTP, and each sweep runs `lag` seconds after the tip's
        /// time. `start` is the setting passed to [`InputReservations::release_expired_from`];
        /// `None` calls [`InputReservations::release_expired`], the API every chain used before
        /// the setting. Returns the first check's height and clock, and one [`Step`] per sweep.
        async fn divi_trace(
            start: Option<ExpiryStart>,
            lead: u32,
            lag: u32,
            gap: u32,
            blocks: u64,
        ) -> (u64, u32, Vec<Step>) {
            let (c, b) = divi_chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t);
            c.advance_time(DEADLINE - T0);
            b.set_tip_lead(lead);
            let locks = [(t, DEADLINE)];
            let first = c.height();
            let clock = |c: &MockChain| c.mtp() + lead + lag;
            let after = clock(&c);
            let mut steps = Vec::new();
            for i in 0..=blocks {
                if i > 0 {
                    mine_after(&c, gap);
                }
                let now = clock(&c);
                let released = match start {
                    Some(s) => r.release_expired_from(&b, &locks, now, s).await,
                    None => r.release_expired(&b, &locks, now).await,
                }
                .unwrap();
                let record = r.absence(Chain::Divi, &t).unwrap();
                if let Some((h, hash, _)) = &record {
                    assert_eq!(hash.as_deref(), Some(c.block_hash(*h).as_str()));
                }
                steps.push((c.height(), released, record.map(|(h, _, a)| (h, a))));
            }
            (first, after, steps)
        }

        /// A dense DIVI chain (one block a minute) whose tips each look fresh (swept at the tip's
        /// own time) while MTP trails them by five blocks, as a real median of eleven does.
        async fn fresh_divi_trace(start: Option<ExpiryStart>) -> (u64, u32, Vec<Step>) {
            divi_trace(start, 5 * 60, 0, 60, 2 * EXPIRY_ABSENT_BLOCKS).await
        }

        #[tokio::test]
        async fn with_expiry_start_mtp_a_record_at_a_fresh_tip_is_pending_and_follows_the_tip() {
            let (first, after, steps) = fresh_divi_trace(Some(ExpiryStart::Mtp)).await;
            // The first check's tip looks fresh, but its MTP is five blocks before the check's
            // clock: the record is pending on that clock, and follows the tip while MTP is
            // before it, releasing nothing.
            assert_eq!(steps[0], (first, 0, Some((first, Some(after)))));
            for (i, step) in steps.iter().enumerate().take(5).skip(1) {
                let h = first + i as u64;
                assert_eq!(*step, (h, 0, Some((h, Some(after)))), "block {h}");
            }
        }

        #[tokio::test]
        async fn with_expiry_start_mtp_the_count_starts_once_mtp_passes_the_check_and_runs_six_blocks(
        ) {
            let (first, _, steps) = fresh_divi_trace(Some(ExpiryStart::Mtp)).await;
            // Five blocks on, MTP reaches the check's clock at the block right after the
            // record's: by EE's rule the count starts at the record, and the lock is released
            // the usual six blocks after it.
            let start = first + 4;
            assert_eq!(steps[5], (first + 5, 0, Some((start, None))));
            for step in &steps[6..10] {
                assert_eq!(*step, (step.0, 0, Some((start, None))), "block {}", step.0);
            }
            assert_eq!(steps[10], (start + EXPIRY_ABSENT_BLOCKS, 1, None));
            assert!(steps[11..].iter().all(|s| s.1 == 0 && s.2.is_none()));
        }

        #[tokio::test]
        async fn with_expiry_start_mtp_a_stale_tip_record_is_as_with_the_default() {
            // EE's sparse chain (blocks ten minutes apart, MTP five blocks behind the tip,
            // sweeps three minutes after each block) and EA's (MTP at the tip's time): the
            // first check is made at a tip more than two spacings behind the clock, so it is
            // pending with either setting, and every sweep is the same.
            for lead in [5 * 600, 0] {
                let tip = divi_trace(Some(ExpiryStart::Tip), lead, 180, 600, 12).await;
                let mtp = divi_trace(Some(ExpiryStart::Mtp), lead, 180, 600, 12).await;
                assert_eq!(mtp, tip, "lead {lead}");
                let (first, after, steps) = mtp;
                assert_eq!(steps[0], (first, 0, Some((first, Some(after)))));
                let at = if lead == 0 { 6 } else { 11 };
                assert_eq!(steps.iter().position(|s| s.1 == 1), Some(at), "lead {lead}");
            }
            // EE's replayed tip stamped ahead of the first check: the record follows the tip
            // until MTP passes the check with either setting.
            for start in [ExpiryStart::Tip, ExpiryStart::Mtp] {
                let (c, b) = divi_chain();
                let r = InputReservations::in_memory().unwrap();
                let (locks, after) = pending_divi_lock(&r, &c, &b).await;
                b.set_tip_lead(3_600 + 600);
                let mut now = after;
                while c.mtp() < after {
                    c.mine(1);
                    now += 1;
                    assert_eq!(
                        r.release_expired_from(&b, &locks, now, start)
                            .await
                            .unwrap(),
                        0
                    );
                }
                let first = c.height() - 1;
                assert_eq!(
                    r.absence(Chain::Divi, &locks[0].0).unwrap(),
                    Some((first, Some(c.block_hash(first)), None)),
                    "{start:?}"
                );
            }
        }

        #[tokio::test]
        async fn the_default_expiry_start_is_todays_rule_and_a_fresh_tip_counts_at_once() {
            assert_eq!(ExpiryStart::default(), ExpiryStart::Tip);
            let today = fresh_divi_trace(None).await;
            let default = fresh_divi_trace(Some(ExpiryStart::default())).await;
            assert_eq!(default, today);
            // Today's rule: the fresh tip's record counts at once, and the lock is released six
            // blocks after the first check, four blocks before "mtp" releases it.
            let (first, _, steps) = today;
            assert_eq!(steps[0], (first, 0, Some((first, None))));
            assert_eq!(
                steps.iter().position(|s| s.1 == 1),
                Some(EXPIRY_ABSENT_BLOCKS as usize)
            );
            let (_, _, mtp) = fresh_divi_trace(Some(ExpiryStart::Mtp)).await;
            assert_ne!(mtp, steps);
            assert_eq!(
                mtp.iter().position(|s| s.1 == 1),
                Some(EXPIRY_ABSENT_BLOCKS as usize + 4)
            );
        }

        #[test]
        fn expiry_start_parses_tip_and_mtp_only() {
            assert_eq!("tip".parse(), Ok(ExpiryStart::Tip));
            assert_eq!("mtp".parse(), Ok(ExpiryStart::Mtp));
            for bad in ["", "MTP", "median", "tip "] {
                assert!(bad.parse::<ExpiryStart>().is_err(), "{bad:?}");
            }
        }

        #[tokio::test]
        async fn the_first_absent_height_survives_a_reopen() {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("swap.db");
            let (c, b) = chain();
            let t = {
                let r = InputReservations::open(&db).unwrap();
                let t = lock(&r, &b, 1).await;
                c.forget(&t);
                c.advance_time(2 * 3_600);
                assert_eq!(sweep(&r, &c, &b, &[(t, DEADLINE)]).await, 0);
                t
            };
            c.mine(EXPIRY_ABSENT_BLOCKS);
            let r = InputReservations::open(&db).unwrap();
            assert!(r.first_absent_height(Chain::Btc, &t).unwrap().is_some());
            assert_eq!(
                sweep(&r, &c, &b, &[(t, DEADLINE)]).await,
                1,
                "the restart did not reset the count"
            );
        }

        #[tokio::test]
        async fn a_lagging_backend_releases_nothing_until_its_tip_passes_the_first_checks_clock() {
            let (c, b) = chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t);
            c.advance_time(2 * 3_600);
            let locks = [(t, DEADLINE)];
            let limit = EXPIRY_MAX_TIP_LAG_BLOCKS * 600;

            // A tip one second more than a day behind the wall clock: nothing is recorded.
            let dead = c.mtp() + EXPIRY_MAX_TIP_AGE_SECS + 1;
            assert_eq!(r.release_expired(&b, &locks, dead).await.unwrap(), 0);
            assert_eq!(r.first_absent_height(Chain::Btc, &t).unwrap(), None);

            // The wall clock stops ten blocks and one second past two spacings ahead of the
            // tip: every block the endpoint catches up on was mined before the first check, so
            // the record follows the tip and nothing is released, ten blocks on.
            let now = c.mtp() + 10 * 600 + limit + 1;
            for _ in 0..10 {
                assert_eq!(r.release_expired(&b, &locks, now).await.unwrap(), 0);
                assert_eq!(
                    r.first_absent_height(Chain::Btc, &t).unwrap(),
                    Some(c.height())
                );
                c.mine(1);
            }
            // Three more blocks, the tip still one second past two spacings behind: a tip newer
            // than the first check moves the record there and starts the count.
            c.mine(3);
            let stale = |c: &MockChain| c.mtp() + limit + 1;
            assert_eq!(r.release_expired(&b, &locks, stale(&c)).await.unwrap(), 0);
            let live = c.height();
            assert_eq!(r.first_absent_height(Chain::Btc, &t).unwrap(), Some(live));
            c.mine(EXPIRY_ABSENT_BLOCKS - 1);
            assert_eq!(r.release_expired(&b, &locks, stale(&c)).await.unwrap(), 0);
            assert_eq!(held_by(&r), HashSet::from([t]));
            c.mine(1);
            assert_eq!(r.release_expired(&b, &locks, stale(&c)).await.unwrap(), 1);
        }

        #[test]
        fn pending_records_from_older_tables_read_as_counting() {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("swap.db");
            {
                // The DM table shape: a hash column, no pending column.
                let conn = Connection::open(&db).unwrap();
                conn.execute_batch(
                    "CREATE TABLE lock_absence (chain TEXT NOT NULL, lock_txid TEXT NOT NULL, \
                 first_absent_height INTEGER NOT NULL, first_absent_hash TEXT, \
                 PRIMARY KEY (chain, lock_txid));",
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO lock_absence VALUES (?1, ?2, 7, 'ab')",
                    params![Chain::Btc.to_string(), Txid([1; 32]).to_rpc_hex()],
                )
                .unwrap();
            }
            let r = InputReservations::open(&db).unwrap();
            assert_eq!(
                r.absence(Chain::Btc, &Txid([1; 32])).unwrap(),
                Some((7, Some("ab".into()), None))
            );
            drop(r);
            InputReservations::open(&db).unwrap(); // a second open does not migrate again
        }

        #[tokio::test]
        async fn a_lock_seen_absent_then_present_keeps_its_inputs_and_clears_the_record() {
            let (c, b) = chain();
            let r = InputReservations::in_memory().unwrap();
            let f = lock_tx(&r, &b, 1).await;
            let t = f.txid;
            c.forget(&t);
            c.advance_time(2 * 3_600);
            let locks = [(t, DEADLINE)];

            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            assert!(r.first_absent_height(Chain::Btc, &t).unwrap().is_some());
            b.broadcast(&f).await.unwrap(); // back in the mempool
            c.mine(EXPIRY_ABSENT_BLOCKS);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            assert_eq!(
                r.first_absent_height(Chain::Btc, &t).unwrap(),
                None,
                "seen present: cleared"
            );

            // Gone again: the count starts over from this height.
            c.forget(&t);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            assert_eq!(
                r.first_absent_height(Chain::Btc, &t).unwrap(),
                Some(c.height())
            );
            assert_eq!(held_by(&r), HashSet::from([t]));
        }

        #[tokio::test]
        async fn a_lagging_fallback_keeps_the_records_and_the_release_waits_for_it_to_catch_up() {
            let (c, b) = chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t);
            c.advance_time(2 * 3_600);
            let locks = [(t, DEADLINE)];

            let first = c.height();
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            c.mine(3);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            // The primary fails over to an endpoint one block behind: the height goes back, but
            // its tip is still fresh by time.
            b.set_lag(1);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0, "height went backwards");
            assert_eq!(
                r.first_absent_block(Chain::Btc, &t).unwrap(),
                Some((first, Some(c.block_hash(first)))),
                "a lagging endpoint keeps the record"
            );
            // Still one behind, but past the high-water mark: it counts again, from the record.
            c.mine(EXPIRY_ABSENT_BLOCKS - 3);
            assert_eq!(
                sweep(&r, &c, &b, &locks).await,
                0,
                "five blocks apart: kept"
            );
            assert_eq!(held_by(&r), HashSet::from([t]));
            b.set_lag(0);
            assert_eq!(
                sweep(&r, &c, &b, &locks).await,
                1,
                "caught up: six blocks past the record"
            );
        }

        #[tokio::test]
        async fn a_lagging_fallback_releases_nothing_even_where_its_own_view_is_six_blocks_on() {
            let (c, b) = chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            let live = lock(&r, &b, 2).await;
            c.forget(&t);
            c.advance_time(2 * 3_600);

            assert_eq!(sweep(&r, &c, &b, &[(t, DEADLINE)]).await, 0);
            c.mine(EXPIRY_ABSENT_BLOCKS + 1);
            // A sweep that does not name `t` still raises the high-water mark.
            assert_eq!(sweep(&r, &c, &b, &[(live, DEADLINE)]).await, 0);
            // Six blocks past the record by the lagging endpoint's tip, one below the mark.
            b.set_lag(1);
            assert_eq!(
                sweep(&r, &c, &b, &[(t, DEADLINE)]).await,
                0,
                "height went backwards"
            );
            assert_eq!(held_by(&r), HashSet::from([t, live]));
            b.set_lag(0);
            assert_eq!(sweep(&r, &c, &b, &[(t, DEADLINE)]).await, 1);
        }

        #[tokio::test]
        async fn a_reorg_of_the_first_absent_block_clears_its_record_and_restarts_the_count() {
            let (c, b) = chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t);
            c.advance_time(DEADLINE - T0);
            c.mine(10);
            let locks = [(t, DEADLINE)];

            let first = c.height();
            let old = c.block_hash(first);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            c.mine(2);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            // A reorg to a chain that replaces the first absent block.
            c.rewind(3);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0, "height went backwards");
            assert_eq!(
                r.first_absent_block(Chain::Btc, &t).unwrap(),
                Some((first, Some(old.clone()))),
                "a lower height alone keeps the record"
            );
            c.mine(4);
            assert_ne!(c.block_hash(first), old, "the block was replaced");
            let tip = c.height();
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            assert_eq!(
                r.first_absent_block(Chain::Btc, &t).unwrap(),
                Some((tip, Some(c.block_hash(tip)))),
                "the reorged-out record is replaced by one at the tip"
            );
            // Six blocks past the old record but not the new one: kept.
            c.mine(EXPIRY_ABSENT_BLOCKS - 1);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            assert_eq!(held_by(&r), HashSet::from([t]));
            c.mine(1);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 1);
        }

        #[tokio::test]
        async fn a_tip_past_the_consensus_future_limit_releases_nothing_and_records_nothing() {
            let (c, b) = chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t);
            c.advance_time(2 * 3_600);
            let locks = [(t, DEADLINE)];

            // The wall clock is one second more than 7200 s behind the tip's time.
            let ahead = |c: &MockChain| c.mtp() - EXPIRY_MAX_TIP_LEAD_SECS - 1;
            assert_eq!(r.release_expired(&b, &locks, ahead(&c)).await.unwrap(), 0);
            assert_eq!(r.first_absent_height(Chain::Btc, &t).unwrap(), None);

            // Exactly 7200 s ahead is fresh: the first check records.
            assert_eq!(
                r.release_expired(&b, &locks, c.mtp() - EXPIRY_MAX_TIP_LEAD_SECS)
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(
                r.first_absent_height(Chain::Btc, &t).unwrap(),
                Some(c.height())
            );
            c.mine(EXPIRY_ABSENT_BLOCKS);
            assert_eq!(r.release_expired(&b, &locks, ahead(&c)).await.unwrap(), 0);
            assert_eq!(held_by(&r), HashSet::from([t]));
            assert_eq!(sweep(&r, &c, &b, &locks).await, 1);
        }

        #[tokio::test]
        async fn an_mtp_past_the_consensus_future_limit_releases_nothing_and_records_nothing() {
            // The tip's own time is the wall clock; the MTP read (a separate request, maybe to
            // another endpoint) is past the 7200 s future limit, as no valid chain's could be.
            for start in [ExpiryStart::Tip, ExpiryStart::Mtp] {
                let (c, b) = chain();
                let r = InputReservations::in_memory().unwrap();
                let t = lock(&r, &b, 1).await;
                c.forget(&t);
                c.advance_time(DEADLINE - T0);
                let locks = [(t, DEADLINE)];
                let swept = |now| r.release_expired_from(&b, &locks, now, start);

                b.set_mtp_lead(EXPIRY_MAX_TIP_LEAD_SECS + 1);
                assert_eq!(swept(c.mtp()).await.unwrap(), 0);
                assert_eq!(r.absence(Chain::Btc, &t).unwrap(), None, "{start:?}");
                assert_eq!(r.last_tip(Chain::Btc).unwrap(), None, "{start:?}");

                // Exactly 7200 s ahead is not past the limit: the first check records.
                b.set_mtp_lead(EXPIRY_MAX_TIP_LEAD_SECS);
                let now = c.mtp();
                assert_eq!(swept(now).await.unwrap(), 0);
                let first = c.height();
                let pending = (start == ExpiryStart::Mtp).then_some(now);
                assert_eq!(
                    r.absence(Chain::Btc, &t).unwrap(),
                    Some((first, Some(c.tip_hash()), pending)),
                    "{start:?}"
                );
            }
        }

        /// A DIVI lock past its deadline with a record counting from the first check, made at a
        /// fresh tip with the default start.
        async fn counting_divi_lock(
            r: &InputReservations,
            c: &MockChain,
            b: &MockBackend,
        ) -> ([(Txid, u32); 1], AbsenceRecord) {
            let t = lock(r, b, 1).await;
            c.forget(&t);
            c.advance_time(DEADLINE - T0);
            let locks = [(t, DEADLINE)];
            assert_eq!(r.release_expired(b, &locks, c.mtp()).await.unwrap(), 0);
            let record = (c.height(), Some(c.tip_hash()), None);
            assert_eq!(r.absence(Chain::Divi, &t).unwrap(), Some(record.clone()));
            (locks, record)
        }

        #[tokio::test]
        async fn a_run_of_blocks_whose_mtp_is_past_the_future_limit_counts_nothing_and_moves_no_record(
        ) {
            for start in [ExpiryStart::Tip, ExpiryStart::Mtp] {
                let (c, b) = divi_chain();
                let r = InputReservations::in_memory().unwrap();
                let (locks, record) = counting_divi_lock(&r, &c, &b).await;
                let t = locks[0].0;
                let high_water = r.last_tip(Chain::Divi).unwrap();
                // Twelve blocks, each stamped at the 2 h future limit, whose MTP read is one
                // second past it: every sweep is refused, the record and the high-water mark
                // stay where they were, even twice the usual count on.
                b.set_tip_lead(EXPIRY_MAX_TIP_LEAD_SECS);
                b.set_mtp_lead(EXPIRY_MAX_TIP_LEAD_SECS + 1);
                for _ in 0..2 * EXPIRY_ABSENT_BLOCKS {
                    c.mine(1);
                    let now = c.mtp();
                    assert_eq!(
                        r.release_expired_from(&b, &locks, now, start)
                            .await
                            .unwrap(),
                        0,
                        "{start:?} block {}",
                        c.height()
                    );
                    assert_eq!(r.absence(Chain::Divi, &t).unwrap(), Some(record.clone()));
                    assert_eq!(r.last_tip(Chain::Divi).unwrap(), high_water);
                }
                assert_eq!(held_by(&r), HashSet::from([t]));
                // At the limit the MTP is trusted again, and the count stands from the record.
                b.set_mtp_lead(EXPIRY_MAX_TIP_LEAD_SECS);
                assert_eq!(
                    r.release_expired_from(&b, &locks, c.mtp(), start)
                        .await
                        .unwrap(),
                    1,
                    "{start:?}"
                );
            }
        }

        #[tokio::test]
        async fn a_pending_count_starts_only_once_mtp_is_past_the_check_and_within_the_future_limit(
        ) {
            // A pending record from a stale tip (either start) and one from a fresh tip under
            // "mtp": a sweep whose MTP is past the check but more than 7200 s ahead of the
            // clock leaves the record pending where it is; the next sweep at a trusted MTP
            // starts the count from the record.
            for (start, stale) in [
                (ExpiryStart::Tip, true),
                (ExpiryStart::Mtp, true),
                (ExpiryStart::Mtp, false),
            ] {
                let (c, b) = divi_chain();
                let r = InputReservations::in_memory().unwrap();
                let t = lock(&r, &b, 1).await;
                c.forget(&t);
                c.advance_time(DEADLINE - T0);
                let locks = [(t, DEADLINE)];
                let after = if stale { c.mtp() + 3_600 } else { c.mtp() };
                let swept = |now| r.release_expired_from(&b, &locks, now, start);
                assert_eq!(swept(after).await.unwrap(), 0);
                let record = (c.height(), Some(c.tip_hash()), Some(after));
                assert_eq!(r.absence(Chain::Divi, &t).unwrap(), Some(record.clone()));

                c.mine(1);
                let now = after + 60;
                b.set_mtp_lead(now - c.mtp() + EXPIRY_MAX_TIP_LEAD_SECS + 1);
                assert_eq!(swept(now).await.unwrap(), 0);
                assert_eq!(
                    r.absence(Chain::Divi, &t).unwrap(),
                    Some(record.clone()),
                    "{start:?} stale {stale}"
                );

                b.set_mtp_lead(now - c.mtp() + EXPIRY_MAX_TIP_LEAD_SECS);
                assert_eq!(swept(now).await.unwrap(), 0);
                assert_eq!(
                    r.absence(Chain::Divi, &t).unwrap(),
                    Some((record.0, record.1.clone(), None)),
                    "{start:?} stale {stale}"
                );
                c.mine(EXPIRY_ABSENT_BLOCKS - 1);
                b.set_mtp_lead(0);
                assert_eq!(swept(now).await.unwrap(), 1, "{start:?} stale {stale}");
            }
        }

        #[tokio::test]
        async fn a_consistent_run_stamped_at_the_future_limit_traces_as_before() {
            // Regression guard: a run of twelve blocks each stamped at the 2 h future limit
            // (tip time 7200 s ahead of the clock, MTP 6900 s ahead: the median of eleven
            // such stamps trails the tip by five blocks) is within every limit, so it counts
            // as on b4cc18b; one second further and the tip-ahead guard refuses every sweep.
            for start in [None, Some(ExpiryStart::Tip), Some(ExpiryStart::Mtp)] {
                for (tip_lead, mtp_lead) in [
                    (EXPIRY_MAX_TIP_LEAD_SECS, EXPIRY_MAX_TIP_LEAD_SECS - 300),
                    (EXPIRY_MAX_TIP_LEAD_SECS + 1, EXPIRY_MAX_TIP_LEAD_SECS - 299),
                ] {
                    let (c, b) = divi_chain();
                    let r = InputReservations::in_memory().unwrap();
                    let t = lock(&r, &b, 1).await;
                    c.forget(&t);
                    c.advance_time(DEADLINE - T0);
                    b.set_tip_lead(tip_lead);
                    b.set_mtp_lead(mtp_lead);
                    let locks = [(t, DEADLINE)];
                    let (first, after) = (c.height(), c.mtp());
                    let mut steps: Vec<Step> = Vec::new();
                    for i in 0..=2 * EXPIRY_ABSENT_BLOCKS {
                        if i > 0 {
                            c.mine(1);
                        }
                        let now = c.mtp();
                        let released = match start {
                            Some(s) => r.release_expired_from(&b, &locks, now, s).await,
                            None => r.release_expired(&b, &locks, now).await,
                        }
                        .unwrap();
                        let record = r.absence(Chain::Divi, &t).unwrap();
                        steps.push((c.height(), released, record.map(|(h, _, a)| (h, a))));
                    }
                    let expected: Vec<Step> = (0..=2 * EXPIRY_ABSENT_BLOCKS)
                        .map(|i| {
                            let h = first + i;
                            if tip_lead > EXPIRY_MAX_TIP_LEAD_SECS {
                                (h, 0, None)
                            } else if i == 0 && start == Some(ExpiryStart::Mtp) {
                                (h, 0, Some((first, Some(after))))
                            } else if i < EXPIRY_ABSENT_BLOCKS {
                                (h, 0, Some((first, None)))
                            } else if i == EXPIRY_ABSENT_BLOCKS {
                                (h, 1, None)
                            } else {
                                (h, 0, None)
                            }
                        })
                        .collect();
                    assert_eq!(steps, expected, "{start:?} tip lead {tip_lead}");
                }
            }
        }

        #[tokio::test]
        async fn an_absence_record_from_before_block_hashes_is_read_and_re_anchored() {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("swap.db");
            let (c, b) = chain();
            let t = lock(&InputReservations::in_memory().unwrap(), &b, 1).await;
            c.forget(&t);
            c.advance_time(2 * 3_600);
            c.mine(EXPIRY_ABSENT_BLOCKS);
            let old = c.height() - EXPIRY_ABSENT_BLOCKS;
            {
                // The DL3 table shape, with a record six blocks old.
                let conn = Connection::open(&db).unwrap();
                conn.execute_batch(
                    "CREATE TABLE input_reservation (chain TEXT NOT NULL, in_txid TEXT NOT NULL, \
                 in_vout INTEGER NOT NULL, reserved_by TEXT NOT NULL, \
                 PRIMARY KEY (chain, in_txid, in_vout));
                 CREATE TABLE lock_absence (chain TEXT NOT NULL, lock_txid TEXT NOT NULL, \
                 first_absent_height INTEGER NOT NULL, PRIMARY KEY (chain, lock_txid));",
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO input_reservation VALUES (?1, ?2, 0, ?3)",
                    params![
                        Chain::Btc.to_string(),
                        op(1, 0).txid.to_rpc_hex(),
                        t.to_rpc_hex()
                    ],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO lock_absence VALUES (?1, ?2, ?3)",
                    params![Chain::Btc.to_string(), t.to_rpc_hex(), old as i64],
                )
                .unwrap();
            }
            let r = InputReservations::open(&db).unwrap();
            assert_eq!(held_by(&r), HashSet::from([t]));
            assert_eq!(r.first_absent_height(Chain::Btc, &t).unwrap(), Some(old));
            assert_eq!(
                r.first_absent_block(Chain::Btc, &t).unwrap(),
                Some((old, None))
            );

            assert_eq!(
                sweep(&r, &c, &b, &[(t, DEADLINE)]).await,
                0,
                "no hash to check the old block against: not released"
            );
            let tip = c.height();
            assert_eq!(
                r.first_absent_block(Chain::Btc, &t).unwrap(),
                Some((tip, Some(c.block_hash(tip))))
            );
            c.mine(EXPIRY_ABSENT_BLOCKS);
            assert_eq!(sweep(&r, &c, &b, &[(t, DEADLINE)]).await, 1);
            drop(r);
            InputReservations::open(&db).unwrap(); // a second open does not migrate again
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
            for _ in 0..2 {
                assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
                c.mine(EXPIRY_ABSENT_BLOCKS);
                c.unconfirm(&pending);
            }
            c.unconfirm(&mined); // reorged back into the mempool
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            assert_eq!(held_by(&r), HashSet::from([mined, pending]));
            assert_eq!(r.first_absent_height(Chain::Btc, &mined).unwrap(), None);
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
            assert!(r.release_expired(&b, &locks, c.mtp()).await.is_err());
            assert_eq!(r.list_all().unwrap().len(), 3, "an error releases nothing");

            c.set_offline(false);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 0);
            c.mine(EXPIRY_ABSENT_BLOCKS);
            assert_eq!(sweep(&r, &c, &b, &locks).await, 1);
            let left: Vec<_> = r
                .list_all()
                .unwrap()
                .into_iter()
                .map(|r| (r.chain, r.reserved_by))
                .collect();
            assert_eq!(left, vec![(Chain::Btc, orphan), (Chain::Ltc, named)]);
            assert_eq!(r.first_absent_height(Chain::Btc, &orphan).unwrap(), None);
        }

        #[tokio::test]
        async fn a_released_reservation_drops_its_absence_record() {
            let (c, b) = chain();
            let r = InputReservations::in_memory().unwrap();
            let t = lock(&r, &b, 1).await;
            c.forget(&t);
            c.advance_time(2 * 3_600);
            assert_eq!(sweep(&r, &c, &b, &[(t, DEADLINE)]).await, 0);
            assert!(r.first_absent_height(Chain::Btc, &t).unwrap().is_some());
            r.release_tx(Chain::Btc, &t).unwrap(); // the operator override
            assert_eq!(sweep(&r, &c, &b, &[]).await, 0);
            assert_eq!(r.first_absent_height(Chain::Btc, &t).unwrap(), None);
        }

        #[tokio::test]
        async fn nothing_held_never_asks_the_backend() {
            let (c, b) = chain();
            let r = InputReservations::in_memory().unwrap();
            c.set_offline(true);
            let locks = [(Txid([1; 32]), DEADLINE)];
            assert_eq!(r.release_expired(&b, &locks, 0).await.unwrap(), 0);
        }

        #[test]
        fn a_backend_without_a_spacing_is_never_fresh() {
            assert!(!tip_is_behind(100, Some(600), 1_300));
            assert!(tip_is_behind(100, Some(600), 1_301));
            assert!(tip_is_behind(100, None, 100));
            assert!(!tip_is_dead(100, 100 + 86_400));
            assert!(tip_is_dead(100, 100 + 86_401), "a day behind the clock");
            assert!(
                !tip_is_behind(100, Some(600), 50) && !tip_is_ahead(100, 50),
                "a tip a little ahead of the clock is not stale"
            );
            assert!(!tip_is_ahead(10_000, 10_000 - 7_200));
            assert!(
                tip_is_ahead(10_000, 10_000 - 7_201),
                "past the consensus future limit"
            );
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
            assert!(matches!(err, SwapError::InputsHeld(_)), "{err:?}");
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
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{swap_locks, InputReservations};
