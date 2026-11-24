// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Persisted, reorg-aware progress of the engine's spend reads (H2, review finding S10).
//!
//! The BTC/LTC block-scan fallback and the ZEC compact-block scan read at most a bounded
//! window of blocks per call. Before H2 every read started again from the lock (or, for the
//! maker's own leg, from the height read when it was built), so a spend mined more than one
//! window later was never seen: a taker who claimed the maker leg late kept both legs.
//!
//! Each spend read the engine makes now resumes where the previous one stopped. The
//! backend's [`SpendScan`] says how far a pass read and by which block hash; the mark is
//! kept as a `spend_cursor` document in the swap store, one per swap and [`Watch`]:
//!
//! - `NotYet { through: Some(mark), .. }`: no spend from the start of the pass through
//!   `mark`; the next read starts at `mark` (its block is read again, so the backend can check
//!   its hash in the same request);
//! - `Reorged`: the marked block is no longer on the best chain; the mark is dropped and the
//!   read starts again from the lock in the same call. A block at a height is the same only
//!   if all its ancestors are, so a matching hash proves every earlier pass still holds;
//! - `NotYet { through: None, .. }` (a backend that reads through the tip in one call, or
//!   answers from an index): nothing is kept and every read starts from the lock, as before;
//! - `Spent`: returned to the caller; the mark is left as it was, so if the spend is reorged
//!   out the next read still resumes from a block it checked.
//!
//! A read without a document (an older database, or one the previous binary wrote) starts
//! from the lock: the cursor only ever saves work, it never decides that a spend is absent.
//! No table or schema version changes: the documents live in the existing `docs` table, which
//! a previous binary neither lists nor reads under this kind, and they are dropped when the
//! swap reaches a terminal state.

use serde::{Deserialize, Serialize};

use crate::backend::ChainBackend;
use crate::error::{Result, SwapError};
use crate::hold;
use crate::store::Store;
use crate::types::{Outpoint, ScanMark, SpendInfo, SpendScan};

/// The `docs` kind the cursors are stored under.
pub(crate) const DOC_KIND: &str = "spend_cursor";

/// Which spend read a cursor belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Watch {
    /// Maker: the taker's claim of the maker leg (it carries the preimage).
    MakerLegClaim,
    /// Maker: the taker's refund of the taker leg.
    MakerTakerLegRefund,
    /// Taker: the maker's refund of the maker leg.
    TakerMakerLegRefund,
    /// Taker: the maker's claim of the taker leg.
    TakerTakerLegClaim,
}

impl Watch {
    /// The maker's reads.
    pub(crate) const MAKER: [Watch; 2] = [Watch::MakerLegClaim, Watch::MakerTakerLegRefund];
    /// The taker's reads.
    pub(crate) const TAKER: [Watch; 2] = [Watch::TakerMakerLegRefund, Watch::TakerTakerLegClaim];

    fn as_str(self) -> &'static str {
        match self {
            Watch::MakerLegClaim => "maker/maker_leg",
            Watch::MakerTakerLegRefund => "maker/taker_leg",
            Watch::TakerMakerLegRefund => "taker/maker_leg",
            Watch::TakerTakerLegClaim => "taker/taker_leg",
        }
    }
}

/// The document id of `swap`'s cursor for `watch`.
pub(crate) fn key(swap: &str, watch: Watch) -> String {
    format!("{}/{swap}", watch.as_str())
}

/// One persisted cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SpendCursor {
    /// The lock whose spend is read. A cursor for another outpoint is ignored.
    pub(crate) outpoint: Outpoint,
    /// Older cursors did not track continuity at the lower boundary.
    #[serde(default)]
    covered_floor: bool,
    /// Earliest height covered by this scan.
    pub(crate) floor: u64,
    /// The last block read with no spend in it or before it (from `floor`).
    pub(crate) through: ScanMark,
    /// Whether that pass reached the tip it read.
    pub(crate) complete: bool,
    /// Reorgs seen under this cursor (diagnostic).
    #[serde(default)]
    pub(crate) reorgs: u32,
}

/// A read a refund waits on: held reads are made on the primary alone from the refund
/// deadline ([`hold::scan_spend`]).
pub(crate) struct Held<'a> {
    pub(crate) locktime: u32,
    pub(crate) margin: u32,
    pub(crate) last_error: &'a mut Option<String>,
}

/// What a spend read learned about `outpoint` (H2 review finding S10b).
///
/// Before this, `find_spend` returned `Option<SpendInfo>` and a bounded-window backend that
/// had not yet read through the tip answered `None`, exactly as a backend that had read the
/// whole chain and seen no spend. A caller that refunds or claims on "no spend" then acted on
/// a window that could still hide the spender. The two cases are now distinct:
///
/// - [`Found::Spend`]: a transaction spending the outpoint was seen.
/// - [`Found::NoneThroughTip`]: the read covered the chain through the tip and saw no spend,
///   so none exists as of this read. A no-spend-dependent decision (a refund, a terminal) may
///   proceed.
/// - [`Found::Pending`]: only a bounded window was read and it held no spend; whether one
///   exists past it is unknown. The mark is saved, so the next read resumes further on, but no
///   no-spend-dependent decision may be taken on it. A caller treats it as "come back later".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Found {
    /// A transaction spending the outpoint.
    Spend(SpendInfo),
    /// Read through the tip: no spend exists as of this read.
    NoneThroughTip,
    /// Only a bounded window was read and held no spend; past it is unknown.
    Pending,
}

impl Found {
    /// The spend, if one was seen. `NoneThroughTip` and `Pending` are both `None`, so an
    /// existing caller that only distinguishes "a spend" from "not a spend" keeps working;
    /// a caller that makes a no-spend-dependent decision must first check [`Found::is_pending`].
    pub(crate) fn spend(self) -> Option<SpendInfo> {
        match self {
            Found::Spend(s) => Some(s),
            Found::NoneThroughTip | Found::Pending => None,
        }
    }

    /// True while only a bounded window has been read: no no-spend decision may be taken yet.
    pub(crate) fn is_pending(&self) -> bool {
        matches!(self, Found::Pending)
    }
}

/// The spend of `outpoint` (a lock mined no earlier than `floor`), reading on from `swap`'s
/// cursor for `watch` and saving how far it got. See [`Found`]: a bounded-window read that has
/// not reached the tip returns [`Found::Pending`], never a bare "no spend".
pub(crate) async fn find_spend(
    store: &Store,
    swap: &str,
    watch: Watch,
    backend: &dyn ChainBackend,
    outpoint: &Outpoint,
    floor: u64,
    mut held: Option<Held<'_>>,
) -> Result<Found> {
    let mut p = Progress::load(store, swap, watch, *outpoint, floor);
    loop {
        let (from, resume) = p.pass();
        let scan = match held.as_mut() {
            Some(h) => {
                hold::scan_spend(
                    backend,
                    outpoint,
                    from,
                    resume.as_ref(),
                    h.locktime,
                    h.margin,
                    swap,
                    &mut *h.last_error,
                )
                .await?
            }
            None => backend.scan_spend(outpoint, from, resume.as_ref()).await?,
        };
        match p.record(scan, resume.is_some())? {
            Step::Done(found) => return Ok(found),
            Step::Again => continue,
        }
    }
}

/// Drop `swap`'s cursors for `watches` (a terminal swap reads no spend again). A failure is
/// logged: a left-over document is ignored by any later read of another outpoint.
pub(crate) fn forget(store: &Store, swap: &str, watches: &[Watch]) {
    for w in watches {
        if let Err(e) = store.delete_doc(DOC_KIND, &key(swap, *w)) {
            tracing::warn!(
                swap,
                watch = w.as_str(),
                "could not drop a spend cursor: {e}"
            );
        }
    }
}

enum Step {
    Done(Found),
    Again,
}

/// One read's cursor: what was loaded, and whether this read already started over.
struct Progress<'a> {
    store: &'a Store,
    key: String,
    outpoint: Outpoint,
    floor: u64,
    saved: Option<SpendCursor>,
    /// A pass reported [`SpendScan::Reorged`]: the saved mark is void for this read.
    restarted: bool,
}

impl<'a> Progress<'a> {
    fn load(store: &'a Store, swap: &str, watch: Watch, outpoint: Outpoint, floor: u64) -> Self {
        let key = key(swap, watch);
        let saved = match store.get_doc::<SpendCursor>(DOC_KIND, &key) {
            Ok(Some(c)) if c.outpoint == outpoint => Some(c),
            Ok(_) => None,
            // Reading from the lock is always correct, only slower.
            Err(e) => {
                tracing::warn!(swap, %outpoint, "spend cursor unreadable, reading from the lock: {e}");
                None
            }
        };
        Progress {
            store,
            key,
            outpoint,
            floor,
            saved,
            restarted: false,
        }
    }

    /// Where the next pass starts, and the mark it must check.
    ///
    /// Resume only if the saved scan covers the prefix from the current floor.
    fn pass(&self) -> (u64, Option<ScanMark>) {
        match &self.saved {
            Some(c)
                if !self.restarted
                    && c.covered_floor
                    && c.floor <= self.floor
                    && c.through.height >= self.floor =>
            {
                (c.through.height, Some(c.through.clone()))
            }
            _ => (self.floor, None),
        }
    }

    /// Take in one pass's answer (`resumed`: the pass was given a mark to check).
    ///
    /// A pass that saw no spend is [`Found::NoneThroughTip`] only when it read through the tip
    /// (`complete`); a bounded pass short of the tip is [`Found::Pending`], so no caller takes
    /// a no-spend-dependent decision on a window that could still hide the spender. The mark is
    /// saved either way, so the next read resumes rather than starting over.
    fn record(&mut self, scan: SpendScan, resumed: bool) -> Result<Step> {
        match scan {
            SpendScan::Spent(s) => Ok(Step::Done(Found::Spend(s))),
            SpendScan::NotYet {
                through: None,
                complete,
            } => {
                // A void mark would only send the next read through this restart again.
                if self.restarted {
                    self.store.delete_doc(DOC_KIND, &self.key)?;
                }
                // No mark to resume from: a `complete` index answer is definitive; an
                // incomplete one (a backend that read a bounded window but reported no mark)
                // cannot advance, so it is held as Pending rather than mistaken for "no spend".
                Ok(Step::Done(if complete {
                    Found::NoneThroughTip
                } else {
                    Found::Pending
                }))
            }
            SpendScan::NotYet {
                through: Some(mark),
                complete,
            } => {
                let reorgs =
                    self.saved.as_ref().map_or(0, |c| c.reorgs) + u32::from(self.restarted);
                let cursor = SpendCursor {
                    outpoint: self.outpoint,
                    covered_floor: true,
                    floor: if resumed {
                        self.saved.as_ref().map_or(self.floor, |c| c.floor)
                    } else {
                        self.floor
                    },
                    through: mark,
                    complete,
                    reorgs,
                };
                if self.restarted || self.saved.as_ref() != Some(&cursor) {
                    self.store.put_doc(DOC_KIND, &self.key, &cursor)?;
                }
                Ok(Step::Done(if complete {
                    Found::NoneThroughTip
                } else {
                    Found::Pending
                }))
            }
            SpendScan::Reorged if resumed => {
                tracing::warn!(
                    cursor = %self.key,
                    through = ?self.saved.as_ref().map(|c| &c.through),
                    "spend scan: the chain reorganised under the cursor; reading again from \
                     the lock"
                );
                self.restarted = true;
                Ok(Step::Again)
            }
            SpendScan::Reorged => Err(SwapError::Transient(format!(
                "spend scan of {} reported a reorg without a mark to check",
                self.outpoint
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc::{new_preimage, HtlcParams};
    use crate::mock::{MockBackend, MockChain};
    use crate::types::{Amount, Chain};

    const SWAP: &str = "h2-swap";
    const WATCH: Watch = Watch::MakerLegClaim;

    /// A lock mined at height 1 (the floor), then `before` empty blocks, the taker's claim
    /// in the next block, and `after` more blocks. The chain's spend scan reads `window`
    /// blocks per pass.
    async fn claimed_late(
        before: u64,
        after: u64,
        window: u64,
    ) -> (MockChain, MockBackend, Outpoint) {
        let chain = MockChain::new(Chain::Btc, 1_800_000_000, 600);
        let maker = chain.backend(1, Amount(10_000_000));
        let taker = chain.backend(2, Amount(0));
        let (pre, hash) = new_preimage();
        let h = HtlcParams {
            hash,
            claim_pubkey: taker.pubkey(),
            refund_pubkey: maker.pubkey(),
            locktime: 1_900_000_000,
            script_version: Default::default(),
        };
        let f = maker.build_funding(&h, Amount(5_000_000)).await.unwrap();
        maker.broadcast(&f.tx).await.unwrap();
        chain.mine(1);
        chain.mine(before);
        let c = taker
            .build_claim(&h, &f.outpoint, f.amount, &pre)
            .await
            .unwrap();
        taker.broadcast(&c).await.unwrap();
        chain.mine(1 + after);
        chain.set_scan_window(window);
        (chain, maker, f.outpoint)
    }

    async fn read(store: &Store, b: &MockBackend, at: &Outpoint) -> Found {
        find_spend(store, SWAP, WATCH, b, at, 1, None)
            .await
            .unwrap()
    }

    fn saved(store: &Store) -> Option<SpendCursor> {
        store.get_doc(DOC_KIND, &key(SWAP, WATCH)).unwrap()
    }

    /// A claim three windows past the lock: each read advances the persisted mark by one
    /// window (scanned-through block identity = the chain's block there) until it is found.
    /// Each short pass is [`Found::Pending`], never a bare "no spend".
    #[tokio::test]
    async fn a_spend_beyond_one_window_is_found_by_reads_that_advance() {
        let (chain, b, at) = claimed_late(24, 20, 10).await;
        let store = Store::in_memory().unwrap();
        assert_eq!(read(&store, &b, &at).await, Found::Pending);
        let c = saved(&store).expect("mark saved");
        assert_eq!(c.through.height, 10);
        assert_eq!(c.through.hash, chain.block_hash(10));
        assert!(!c.complete);
        assert_eq!(read(&store, &b, &at).await, Found::Pending);
        assert_eq!(saved(&store).unwrap().through.height, 19);
        let spend = read(&store, &b, &at)
            .await
            .spend()
            .expect("found on the third read");
        assert_eq!(spend.height, Some(26));
        // Found: the mark stays on a block that was checked.
        assert_eq!(saved(&store).unwrap().through.height, 19);
        assert_eq!(chain.scan_passes(), 3);
    }

    /// A restart between windows (a new process on the same database) resumes from the
    /// persisted mark, not from the lock.
    #[tokio::test]
    async fn a_restart_between_windows_resumes_from_the_mark() {
        let (chain, b, at) = claimed_late(24, 20, 10).await;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        {
            let store = Store::open(&db).unwrap();
            assert_eq!(read(&store, &b, &at).await, Found::Pending);
            assert_eq!(read(&store, &b, &at).await, Found::Pending);
        }
        let store = Store::open(&db).unwrap();
        assert_eq!(saved(&store).unwrap().through.height, 19);
        assert!(matches!(read(&store, &b, &at).await, Found::Spend(_)));
        assert_eq!(
            chain.scan_passes(),
            3,
            "the restarted read did not start over"
        );
    }

    #[tokio::test]
    async fn corrected_floor_after_restart_finds_spend_in_skipped_prefix() {
        let (chain, b, at) = claimed_late(0, 20, 10).await;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        {
            let store = Store::open(&db).unwrap();
            let confirmations = b.confirmations(&at.txid).await.unwrap().unwrap();
            chain.mine(2);
            let floor = b.tip_height().await.unwrap() + 1 - u64::from(confirmations);
            assert_eq!(floor, 3);
            assert_eq!(
                find_spend(&store, SWAP, WATCH, &b, &at, floor, None)
                    .await
                    .unwrap(),
                Found::Pending
            );
        }
        let store = Store::open(&db).unwrap();
        assert!(matches!(read(&store, &b, &at).await, Found::Spend(_)));
    }

    /// A shallow reorg replaces the marked block and re-mines the claim below the old mark:
    /// the resumed pass sees the changed hash, the read starts again from the lock, and the
    /// claim is still found.
    #[tokio::test]
    async fn a_shallow_reorg_under_the_mark_restarts_from_the_lock() {
        let (chain, b, at) = claimed_late(14, 2, 10).await;
        let store = Store::in_memory().unwrap();
        // Lock at 1, claim at 16, tip 18: the first pass reads 1..=10.
        assert_eq!(read(&store, &b, &at).await, Found::Pending);
        assert_eq!(
            read(&store, &b, &at).await.spend().unwrap().height,
            Some(16)
        );
        // The mark (10) and the claim are replaced; the claim is mined again at 9, tip 11.
        chain.rewind(10);
        chain.mine(3);
        let before = saved(&store).unwrap();
        assert_eq!(before.through.height, 10);
        assert_ne!(before.through.hash, chain.block_hash(10));
        assert_eq!(read(&store, &b, &at).await.spend().unwrap().height, Some(9));
        // The restart pass found it from the lock in the same call.
        assert_eq!(chain.scan_passes(), 4);
    }

    /// An index-like backend (window 0) answers through the tip: no cursor is written, and a
    /// stale one for another outpoint is ignored.
    #[tokio::test]
    async fn an_index_answer_keeps_no_cursor() {
        let (chain, b, at) = claimed_late(24, 20, 0).await;
        let store = Store::in_memory().unwrap();
        let other = Outpoint {
            txid: crate::types::Txid([9; 32]),
            vout: 0,
        };
        assert_eq!(read(&store, &b, &other).await, Found::NoneThroughTip);
        assert!(saved(&store).is_none());
        assert_eq!(
            read(&store, &b, &at).await.spend().unwrap().height,
            Some(26)
        );
        assert_eq!(chain.scan_passes(), 0);
        forget(&store, SWAP, &Watch::MAKER);
        assert!(saved(&store).is_none());
    }

    /// The core of review finding S10b: a bounded window that has not reached the tip is
    /// [`Found::Pending`], distinct from the [`Found::NoneThroughTip`] an index backend gives,
    /// even though both carry no spend. The mark is saved so the next read resumes.
    #[tokio::test]
    async fn an_incomplete_window_is_pending_not_no_spend() {
        // Claim 26 blocks past the lock, window 10: the first pass reads 1..=10, short of it.
        let (_chain, b, at) = claimed_late(24, 20, 10).await;
        let store = Store::in_memory().unwrap();
        let got = read(&store, &b, &at).await;
        assert_eq!(got, Found::Pending);
        assert!(got.is_pending());
        assert_eq!(got.spend(), None);
        // The mark advanced so the next read does not repeat this window.
        let c = saved(&store).expect("mark saved on a pending read");
        assert_eq!(c.through.height, 10);
        assert!(!c.complete);

        // An index backend over the same unspent outpoint is definitive, not pending.
        let (_c2, b2, _spent) = claimed_late(0, 0, 0).await;
        let other = Outpoint {
            txid: crate::types::Txid([7; 32]),
            vout: 0,
        };
        let got2 = find_spend(&store, "other-swap", WATCH, &b2, &other, 1, None)
            .await
            .unwrap();
        assert_eq!(got2, Found::NoneThroughTip);
        assert!(!got2.is_pending());
    }
}
