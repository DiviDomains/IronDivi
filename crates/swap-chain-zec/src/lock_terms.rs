// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The lock's terms from both lightwalletd operators (ET). With `[zec].crosscheck_url` set,
//! [`ZecBackend`]'s `htlc_output` (the maker about to fund against the taker's ZEC lock, the
//! taker about to reveal the preimage against the maker's) must see the agreed HTLC script
//! and the same value at the outpoint on the second operator too, and fails closed
//! (`Transient`) otherwise. Off, it reads the primary alone, request for request as before.
//!
//! The backend tests read a lock from two [`Lightwalletd`] stubs; the engine tests run a
//! [`Maker`] and a [`Taker`] on [`MockChain`]s whose ZEC lock reads go through a real
//! cross-checked [`ZecBackend`] (the stubs serve what the mock chain holds, and the second
//! operator what the test makes it say).

use divi_swap::{Amount, ChainBackend, HtlcParams, LockedOutput, Outpoint, SwapError, Txid};

use crate::address::{htlc_script_pubkey, TransparentAddress};
use crate::lwd_stub::{raw_tx, tx_of, txid_of, Lightwalletd};
use crate::ZecBackend;

/// The stubs' tip in the backend tests.
const TIP: u64 = 40;
const ZAT: u64 = 250_000;
/// The value of the output in front of the lock.
const FILLER: u64 = 1_000;

fn htlc() -> HtlcParams {
    HtlcParams {
        hash: [0x24; 32],
        claim_pubkey: pk(0x02),
        refund_pubkey: pk(0x03),
        locktime: 1_800_000_000,
        script_version: Default::default(),
    }
}

fn pk(n: u8) -> [u8; 33] {
    let sk = secp256k1::SecretKey::from_slice(&[n; 32]).unwrap();
    sk.public_key(&secp256k1::Secp256k1::new()).serialize()
}

/// The agreed lock: output 1 of [`lock_tx`]`(ZAT, agreed)`, under that transaction's own
/// txid (EW: an answer that does not hash to the txid asked for is never read).
fn at() -> Outpoint {
    Outpoint {
        txid: Txid(txid_of(&lock_tx(ZAT, agreed_spk(&htlc())))),
        vout: 1,
    }
}

/// Output 1 of a transaction with another script there, under its own txid.
fn other_at() -> Outpoint {
    Outpoint {
        txid: Txid(txid_of(&lock_tx(ZAT, other_spk()))),
        vout: 1,
    }
}

fn agreed_spk(h: &HtlcParams) -> Vec<u8> {
    htlc_script_pubkey(&h.redeem_script())
}

fn other_spk() -> Vec<u8> {
    TransparentAddress::p2pkh(&pk(0x09)).script_pubkey()
}

/// A lock transaction: a filler output, then `(value, spk)` at vout 1.
fn lock_tx(value: u64, spk: Vec<u8>) -> Vec<u8> {
    raw_tx(&[(FILLER, other_spk()), (value, spk)])
}

/// Both operators at [`TIP`]; `primary` holds the agreed lock at `height`.
fn pair(height: u64) -> (Lightwalletd, Lightwalletd) {
    let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
    p.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), height);
    (p, o)
}

fn checked(p: &Lightwalletd, o: &Lightwalletd) -> ZecBackend {
    p.backend()
        .with_crosscheck(Some(o.endpoint().to_string()))
        .unwrap()
}

/// `htlc_output` refused the lock as `Transient`, naming both operators and no secret.
async fn refused(p: &Lightwalletd, o: &Lightwalletd, case: &str) -> String {
    let b = checked(p, o);
    let got = b.htlc_output(&htlc(), &at()).await;
    let Err(SwapError::Transient(m)) = &got else {
        panic!("{case}: the lock was not refused: {got:?}");
    };
    for needle in [p.endpoint(), o.endpoint()] {
        assert!(m.contains(needle), "{case}: {m} lacks {needle}");
    }
    // The stub backend's key ([0x33; 32]) appears in no message.
    assert!(!m.contains(&hex::encode([0x33u8; 32])), "{case}: {m}");
    m.clone()
}

/// Off: the primary alone, `GetTransaction` then (when mined) `GetLatestBlock`, as before;
/// a second operator that is not configured is never asked.
#[tokio::test]
async fn off_reads_the_primary_alone_request_for_request() {
    for (height, confs, calls) in [
        (TIP - 2, 3, &["GetTransaction", "GetLatestBlock"][..]),
        (0, 0, &["GetTransaction"][..]),
    ] {
        let (p, o) = pair(height);
        o.put_tx(at().txid.0, lock_tx(ZAT, other_spk()), height);
        let b = p.backend().with_crosscheck(None).unwrap();
        let got = b.htlc_output(&htlc(), &at()).await.unwrap();
        assert_eq!(
            got,
            Some(LockedOutput {
                amount: Amount::from_sat(ZAT),
                confirmations: confs
            }),
            "{height}"
        );
        assert_eq!(p.take_calls(), calls, "{height}");
        assert!(o.take_calls().is_empty(), "{height}");
        // Another script at the outpoint is still `None` on the primary alone.
        p.put_honest(lock_tx(ZAT, other_spk()), height);
        assert_eq!(b.htlc_output(&htlc(), &other_at()).await.unwrap(), None);
    }
}

/// Wrong script: the primary shows the agreed HTLC and the full value, the second operator
/// another scriptPubKey at the outpoint. Such an answer is another transaction, so it is
/// refused whichever check sees it first (EW binds the txid; `crosscheck`'s `agree_lock_names_the_script`
/// keeps the script comparison's own refusal).
#[tokio::test]
async fn a_second_operator_showing_another_script_refuses_the_lock() {
    let (p, o) = pair(TIP - 2);
    o.put_tx(at().txid.0, lock_tx(ZAT, other_spk()), TIP - 2);
    refused(&p, &o, "other script").await;
}

/// Short value (and, as values must be equal, a larger one): the agreed script on both.
#[tokio::test]
async fn a_second_operator_showing_another_value_refuses_the_lock() {
    for value in [ZAT - 1, ZAT / 2, ZAT + 1] {
        let (p, o) = pair(TIP - 2);
        o.put_tx(at().txid.0, lock_tx(value, agreed_spk(&htlc())), TIP - 2);
        refused(&p, &o, &format!("value {value}")).await;
    }
}

/// Missing at the second: no such transaction, or no output at the lock's index.
#[tokio::test]
async fn a_lock_the_second_operator_does_not_have_is_refused() {
    let (p, o) = pair(TIP - 2);
    refused(&p, &o, "no such tx").await;
    o.put_tx(at().txid.0, raw_tx(&[(ZAT, agreed_spk(&htlc()))]), TIP - 2);
    refused(&p, &o, "no such vout").await;
}

/// Second operator down: refused (nothing is at risk while the maker waits before funding
/// or the taker before revealing).
#[tokio::test]
async fn an_unreachable_second_operator_refuses_the_lock() {
    let (p, o) = pair(TIP - 2);
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    o.set_down(true);
    refused(&p, &o, "down").await;
}

/// The seconds in a refusal's "failing this lock for N s" (EX).
fn failing_secs(m: &str) -> u64 {
    let (_, rest) = m
        .split_once("failing this lock for ")
        .unwrap_or_else(|| panic!("{m} does not say how long the second operator has failed"));
    rest.split(' ').next().unwrap().parse().unwrap()
}

/// EX: a second operator that accepts the call and never answers is refused within the
/// read's budget, naming it, not after the transport's own timeouts.
#[tokio::test]
async fn a_hanging_second_operator_is_refused_within_the_budget() {
    let (p, o) = pair(TIP - 2);
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    o.set_hang(true);
    let b = checked(&p, &o).with_second_budget(std::time::Duration::from_millis(200));
    let got = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        b.htlc_output(&htlc(), &at()),
    )
    .await
    .expect("the lock read waited on a hanging second operator past its budget");
    let Err(SwapError::Transient(m)) = &got else {
        panic!("the lock was not refused: {got:?}");
    };
    for needle in [p.endpoint(), o.endpoint(), "did not answer within"] {
        assert!(m.contains(needle), "{m} lacks {needle}");
    }
}

/// EX: the refusal says how long the second operator has been failing this lock, counted
/// from its first refusal and restarted by an agreement.
#[tokio::test]
async fn a_failing_second_operator_is_named_with_how_long_it_has_failed() {
    let (p, o) = pair(TIP - 2);
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    o.set_down(true);
    let b = checked(&p, &o);
    let first = b.htlc_output(&htlc(), &at()).await.unwrap_err().to_string();
    assert!(first.contains(o.endpoint()), "{first}");
    assert_eq!(failing_secs(&first), 0, "{first}");
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let later = b.htlc_output(&htlc(), &at()).await.unwrap_err().to_string();
    assert!(failing_secs(&later) >= 1, "{later}");
    o.set_down(false);
    assert!(b.htlc_output(&htlc(), &at()).await.unwrap().is_some());
    // FB: the agreement is kept while the primary is unchanged; one more block on the
    // primary takes the count past what the second vouched for, so it is asked again.
    p.mine(1);
    o.set_down(true);
    let again = b.htlc_output(&htlc(), &at()).await.unwrap_err().to_string();
    assert_eq!(
        failing_secs(&again),
        0,
        "an agreement restarts the count: {again}"
    );
}

/// Both agree: the lock, at the lower of the two confirmation counts.
#[tokio::test]
async fn both_operators_agreeing_give_the_lower_confirmations() {
    for (p_height, o_height, confs) in [
        (TIP - 5, TIP - 2, 3),
        (TIP - 2, TIP - 5, 3),
        (TIP - 5, 0, 0),
        (0, TIP - 5, 0),
    ] {
        let (p, o) = pair(p_height);
        o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), o_height);
        let got = checked(&p, &o).htlc_output(&htlc(), &at()).await.unwrap();
        assert_eq!(
            got,
            Some(LockedOutput {
                amount: Amount::from_sat(ZAT),
                confirmations: confs
            }),
            "{p_height}/{o_height}"
        );
        assert!(
            o.take_calls().contains(&"GetTransaction"),
            "{p_height}/{o_height}: the second operator was not asked"
        );
    }
}

/// Nothing to agree when the primary shows no matching lock: no side acts on `None`, and
/// the second operator is not asked.
#[tokio::test]
async fn no_lock_on_the_primary_asks_nothing_of_the_second() {
    let (p, o) = pair(TIP - 2);
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    p.put_honest(lock_tx(ZAT, other_spk()), TIP - 2);
    let b = checked(&p, &o);
    assert_eq!(b.htlc_output(&htlc(), &other_at()).await.unwrap(), None);
    p.drop_tx(at().txid.0);
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), None);
    assert!(o.take_calls().is_empty());
}

// ---- FB: the agreed lock kept per height ----------------------------------------------------

/// The lock at [`TIP`]` - 2` on both operators (3 confirmations), read once: agreed.
async fn agreed_once(p: &Lightwalletd, o: &Lightwalletd) -> ZecBackend {
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    let b = checked(p, o);
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(3)));
    assert_eq!(b.agreed_locks(), 1, "a mined agreement is kept");
    p.take_calls();
    o.take_calls();
    b
}

fn lo(confirmations: u32) -> LockedOutput {
    LockedOutput {
        amount: Amount::from_sat(ZAT),
        confirmations,
    }
}

fn count(calls: &[&str], method: &str) -> usize {
    calls.iter().filter(|c| **c == method).count()
}

/// A mined lock both operators agree on, read N times at the same tip, costs the second
/// operator one `GetTransaction` (its first read) and nothing after; the primary is still
/// read in full every time.
#[tokio::test]
async fn a_mined_agreed_lock_read_n_times_asks_the_second_operator_once() {
    const N: usize = 6;
    let (p, o) = pair(TIP - 2);
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    let b = checked(&p, &o);
    for n in 0..N {
        assert_eq!(
            b.htlc_output(&htlc(), &at()).await.unwrap(),
            Some(lo(3)),
            "{n}"
        );
    }
    let (pc, oc) = (p.take_calls(), o.take_calls());
    assert_eq!(count(&oc, "GetTransaction"), 1, "second operator: {oc:?}");
    assert_eq!(count(&oc, "GetLatestBlock"), 1, "second operator: {oc:?}");
    assert_eq!(count(&pc, "GetTransaction"), N, "primary: {pc:?}");
    assert_eq!(count(&pc, "GetLatestBlock"), N, "primary: {pc:?}");
    assert_eq!(b.agreed_locks(), 1);
}

/// The count from a kept agreement is never above what the second operator last vouched
/// for: when the primary's tip moves past it, the second is asked for its tip (only), and
/// a second operator behind the primary keeps the count down, as a fresh read would.
#[tokio::test]
async fn a_kept_agreement_counts_no_higher_than_the_second_operators_tip() {
    let (p, o) = pair(TIP - 2);
    let b = agreed_once(&p, &o).await;
    // Both one block on: 4, asking the second for its tip only.
    p.mine(1);
    o.mine(1);
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(4)));
    assert_eq!(o.take_calls(), ["GetLatestBlock"]);
    // The primary alone races ahead (or lies about its tip): still 4.
    p.mine(5);
    for _ in 0..3 {
        assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(4)));
    }
    let oc = o.take_calls();
    assert_eq!(count(&oc, "GetTransaction"), 0, "{oc:?}");
    // The second catches up: the primary's count again.
    o.mine(5);
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(9)));
    assert_eq!(b.agreed_locks(), 1);
}

/// Manager (a): same txid and vout, the primary's block at the lock's height replaced. The
/// kept agreement is not used: the second operator is asked again and its answer re-checked
/// (here it no longer has the transaction: refused).
#[tokio::test]
async fn a_reorg_at_the_locks_height_asks_again_and_refuses_another_answer() {
    let (p, o) = pair(TIP - 2);
    let b = agreed_once(&p, &o).await;
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(3)));
    assert!(o.take_calls().is_empty(), "a kept agreement asks nothing");
    // The top three blocks (the lock's among them) replaced on the primary; the lock is
    // still shown at the same height, in a block with another hash.
    p.reorg(3);
    o.drop_tx(at().txid.0);
    let m = refused(&p, &o, "reorg").await;
    assert!(m.contains("has no such transaction"), "{m}");
    // `refused` builds its own backend; this one must re-ask too.
    let got = b.htlc_output(&htlc(), &at()).await;
    assert!(matches!(got, Err(SwapError::Transient(_))), "{got:?}");
    assert_eq!(count(&o.take_calls(), "GetTransaction"), 2);
    assert_eq!(b.agreed_locks(), 0, "the reorged agreement is dropped");
    // Re-mined on the second operator's chain too: asked again, agreed again.
    o.reorg(3);
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(3)));
    assert_eq!(count(&o.take_calls(), "GetTransaction"), 1);
}

/// After a kept agreement the primary changes (the lock now at another height) and the
/// second operator shows something else: `Transient`, not the kept agreement.
#[tokio::test]
async fn a_later_disagreement_after_a_kept_agreement_is_refused() {
    let (p, o) = pair(TIP - 2);
    let b = agreed_once(&p, &o).await;
    p.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 1);
    o.put_tx(at().txid.0, lock_tx(ZAT, other_spk()), TIP - 1);
    let got = b.htlc_output(&htlc(), &at()).await;
    let Err(SwapError::Transient(m)) = &got else {
        panic!("a kept agreement outlived the primary's change: {got:?}");
    };
    assert!(m.contains(o.endpoint()), "{m}");
    assert_eq!(b.agreed_locks(), 0);
    // Gone from the primary: `None`, and the entry stays dropped.
    p.drop_tx(at().txid.0);
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), None);
}

/// A mempool lock is never kept: every read asks the second operator.
#[tokio::test]
async fn a_mempool_lock_is_asked_every_time() {
    let (p, o) = pair(0);
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), 0);
    let b = checked(&p, &o);
    for _ in 0..3 {
        assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(0)));
    }
    assert_eq!(count(&o.take_calls(), "GetTransaction"), 3);
    assert_eq!(b.agreed_locks(), 0);
}

/// Nothing but an agreement on one block is kept: a refusal (another script), a second
/// operator down or hanging, and an agreement at two different heights or in two different
/// blocks are all asked again at the next read.
#[tokio::test]
async fn refusals_and_unmatched_blocks_are_never_kept() {
    // Refused: another script at the second operator.
    let (p, o) = pair(TIP - 2);
    o.put_tx(at().txid.0, lock_tx(ZAT, other_spk()), TIP - 2);
    let b = checked(&p, &o);
    for _ in 0..2 {
        assert!(b.htlc_output(&htlc(), &at()).await.is_err());
    }
    assert_eq!(count(&o.take_calls(), "GetTransaction"), 2);
    assert_eq!(b.agreed_locks(), 0);
    // Down, then hanging: refused each time, then the honest answer is asked for.
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    let b = checked(&p, &o).with_second_budget(std::time::Duration::from_millis(200));
    for (down, hang) in [(true, false), (false, true)] {
        o.set_down(down);
        o.set_hang(hang);
        assert!(b.htlc_output(&htlc(), &at()).await.is_err());
        assert_eq!(b.agreed_locks(), 0, "{down}/{hang}");
    }
    o.set_hang(false);
    o.take_calls();
    assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(3)));
    assert_eq!(count(&o.take_calls(), "GetTransaction"), 1);
    // Agreed at two different heights (the lower count), or at one height in two different
    // blocks: an agreement, never kept.
    for tamper in [false, true] {
        let (p, o) = pair(TIP - 2);
        let o_height = if tamper { TIP - 2 } else { TIP - 4 };
        if tamper {
            o.tamper(TIP - 2);
        }
        o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), o_height);
        let b = checked(&p, &o);
        for _ in 0..2 {
            assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(3)));
        }
        assert_eq!(count(&o.take_calls(), "GetTransaction"), 2, "{tamper}");
        assert_eq!(b.agreed_locks(), 0, "{tamper}");
    }
}

/// Bounded: at most `LOCK_CACHE_CAP` agreements per backend, the oldest dropped first.
#[tokio::test]
async fn kept_agreements_are_capped() {
    let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
    let b = checked(&p, &o);
    let n = crate::LOCK_CACHE_CAP + 3;
    let mut outpoints = Vec::new();
    for i in 0..n {
        let raw = raw_tx(&[(FILLER + i as u64, other_spk()), (ZAT, agreed_spk(&htlc()))]);
        p.put_honest(raw.clone(), TIP - 2);
        let txid = o.put_honest(raw, TIP - 2);
        let op = Outpoint {
            txid: Txid(txid),
            vout: 1,
        };
        assert_eq!(
            b.htlc_output(&htlc(), &op).await.unwrap(),
            Some(lo(3)),
            "{i}"
        );
        outpoints.push(op);
    }
    assert_eq!(b.agreed_locks(), crate::LOCK_CACHE_CAP);
    o.take_calls();
    // The newest is kept, the oldest was dropped.
    b.htlc_output(&htlc(), &outpoints[n - 1]).await.unwrap();
    assert!(o.take_calls().is_empty());
    b.htlc_output(&htlc(), &outpoints[0]).await.unwrap();
    assert_eq!(count(&o.take_calls(), "GetTransaction"), 1);
}

/// Manager (b), at the backend: `lock_finished` (the engine's call when the swap reaching a
/// terminal state) drops the lock's entry; the next read would ask afresh.
#[tokio::test]
async fn a_finished_lock_is_dropped() {
    let (p, o) = pair(TIP - 2);
    let b = agreed_once(&p, &o).await;
    b.lock_finished(&other_at());
    assert_eq!(b.agreed_locks(), 1, "another lock's end drops nothing");
    b.lock_finished(&at());
    assert_eq!(b.agreed_locks(), 0);
    b.htlc_output(&htlc(), &at()).await.unwrap();
    assert_eq!(count(&o.take_calls(), "GetTransaction"), 1);
}

/// Off and in EM's primary-only view: no cache, request for request as before, however
/// often the lock is read.
#[tokio::test]
async fn off_and_primary_only_keep_nothing_request_for_request() {
    let (p, o) = pair(TIP - 2);
    o.put_tx(at().txid.0, lock_tx(ZAT, agreed_spk(&htlc())), TIP - 2);
    let off = p.backend().with_crosscheck(None).unwrap();
    let full = checked(&p, &o);
    let view = full.primary_only().expect("a primary-only view");
    for b in [&off as &dyn ChainBackend, view.as_ref()] {
        p.take_calls();
        for _ in 0..3 {
            assert_eq!(b.htlc_output(&htlc(), &at()).await.unwrap(), Some(lo(3)));
        }
        assert_eq!(
            p.take_calls(),
            ["GetTransaction", "GetLatestBlock"].repeat(3)
        );
        assert!(o.take_calls().is_empty());
    }
    assert_eq!(off.agreed_locks(), 0);
}

// ---- The engine at both acting points -----------------------------------------------------

/// `#[cfg(test)]` again (the module is test-only already) so the source scan in
/// `divi-swap`'s `taker_floor_entry_points` reads the `Taker::new` below as test code.
#[cfg(test)]
mod engine {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use divi_swap::api::{Direction, Offer};
    use divi_swap::backend::TipHeader;
    use divi_swap::mock::{MockBackend, MockChain, TxKind};
    use divi_swap::{
        Chain, ClaimSizes, FeeBump, Funding, Maker, Profile, Result, SignedTx, SpendInfo, Store,
        SwapConfig, SwapState, Taker, TakerState,
    };

    use super::*;

    const T0: u32 = 1_800_000_000;
    const FUNDS: u64 = 2_000_000_000;
    /// The stubs' tip in the engine tests: above any confirmation count a run reaches.
    const STUB_TIP: u64 = 10_000;
    /// The second operator's lock-read budget in the engine tests (EX).
    const BUDGET: Duration = Duration::from_millis(200);
    /// How long one maker tick or taker step may take before the test calls it hung (EX).
    const STEP_LIMIT: Duration = Duration::from_secs(10);

    /// What the second operator shows of a lock the mock chain (and the primary) holds.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Second {
        Honest,
        OtherScript,
        Short,
        NoTx,
        NoVout,
        Down,
        /// Accepts every call and never answers (EX).
        Hang,
    }

    const LIES: [Second; 5] = [
        Second::OtherScript,
        Second::Short,
        Second::NoTx,
        Second::NoVout,
        Second::Down,
    ];

    /// A ZEC [`MockBackend`] whose `htlc_output` is a cross-checked [`ZecBackend`]'s, over two
    /// stubs that serve the mock chain's lock (the primary as it is, the second per [`Second`]).
    #[derive(Clone)]
    struct CrossRead {
        mock: MockBackend,
        zec: Arc<ZecBackend>,
        primary: Arc<Lightwalletd>,
        second: Arc<Lightwalletd>,
        shows: Arc<Mutex<Second>>,
        /// The primary shows the lock buried [`LIE_DEPTH`] blocks deep, whatever the mock
        /// chain holds (EX).
        primary_lies: Arc<AtomicBool>,
        /// The outpoint the stubs know each mock lock by ([`CrossRead::serve`]), so the
        /// engine's `lock_finished` reaches the backend's entry (FB).
        served: Arc<Mutex<std::collections::HashMap<Outpoint, Outpoint>>>,
    }

    /// How deep a lying primary shows a lock.
    const LIE_DEPTH: u64 = 500;

    impl CrossRead {
        /// `crosscheck`: false reads the primary alone (`[zec].crosscheck_url` unset); the
        /// second stub then runs but is never configured.
        fn with_crosscheck(mock: MockBackend, crosscheck: bool) -> Self {
            let (primary, second) = (Lightwalletd::start(STUB_TIP), Lightwalletd::start(STUB_TIP));
            let zec = match crosscheck {
                true => checked(&primary, &second).with_second_budget(BUDGET),
                false => primary.backend().with_crosscheck(None).unwrap(),
            };
            CrossRead {
                mock,
                zec: Arc::new(zec),
                primary: Arc::new(primary),
                second: Arc::new(second),
                shows: Arc::new(Mutex::new(Second::Honest)),
                primary_lies: Arc::new(AtomicBool::new(false)),
                served: Arc::default(),
            }
        }

        fn shows(&self, s: Second) {
            *self.shows.lock().unwrap() = s;
            self.second.set_down(s == Second::Down);
            self.second.set_hang(s == Second::Hang);
        }

        fn primary_lies(&self) {
            self.primary_lies.store(true, Ordering::SeqCst);
        }

        fn second_url(&self) -> &str {
            self.second.endpoint()
        }

        /// Serve the mock chain's view of `at` on both stubs, as a v5 transaction spending
        /// `at`'s mock txid (one per lock) under its own ZEC txid; returns the outpoint the
        /// stubs know it by (`at` itself, which no stub holds, when the mock chain has none).
        /// The second operator's lies are answers to `GetTransaction` of that txid.
        fn serve(&self, htlc: &HtlcParams, at: &Outpoint, real: Option<LockedOutput>) -> Outpoint {
            let Some(lo) = real else {
                return *at;
            };
            let height = match lo.confirmations {
                _ if self.primary_lies.load(Ordering::SeqCst) => STUB_TIP + 1 - LIE_DEPTH,
                0 => 0,
                c => STUB_TIP + 1 - u64::from(c),
            };
            let outputs = |value: u64, spk: Vec<u8>| {
                let mut v = vec![(FILLER, other_spk()); at.vout as usize];
                v.push((value, spk));
                tx_of(5, at.txid.0, &v).serialize()
            };
            let (zat, spk) = (lo.amount.to_sat(), agreed_spk(htlc));
            let txid = self.primary.put_honest(outputs(zat, spk.clone()), height);
            let stub_at = Outpoint {
                txid: Txid(txid),
                vout: at.vout,
            };
            self.served.lock().unwrap().insert(*at, stub_at);
            match *self.shows.lock().unwrap() {
                Second::Honest | Second::Down | Second::Hang => {
                    self.second.put_tx(txid, outputs(zat, spk), height)
                }
                Second::OtherScript => self.second.put_tx(txid, outputs(zat, other_spk()), height),
                Second::Short => self.second.put_tx(txid, outputs(zat - 1, spk), height),
                Second::NoTx => self.second.drop_tx(txid),
                Second::NoVout => {
                    let v = vec![(FILLER, other_spk()); at.vout as usize];
                    self.second
                        .put_tx(txid, tx_of(5, at.txid.0, &v).serialize(), height)
                }
            }
            stub_at
        }
    }

    #[async_trait]
    impl ChainBackend for CrossRead {
        fn chain(&self) -> Chain {
            self.mock.chain()
        }
        fn pubkey(&self) -> [u8; 33] {
            self.mock.pubkey()
        }
        async fn tip_height(&self) -> Result<u64> {
            self.mock.tip_height().await
        }
        async fn tip_hash(&self) -> Result<String> {
            self.mock.tip_hash().await
        }
        async fn median_time_past(&self) -> Result<u32> {
            self.mock.median_time_past().await
        }
        fn refund_final(&self, mtp: u32, locktime: u32) -> bool {
            self.mock.refund_final(mtp, locktime)
        }
        async fn tip_header(&self) -> Result<TipHeader> {
            self.mock.tip_header().await
        }
        async fn in_best_chain(&self, height: u64, hash: &str) -> Result<bool> {
            self.mock.in_best_chain(height, hash).await
        }
        fn target_block_secs(&self) -> Option<u32> {
            self.mock.target_block_secs()
        }
        async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
            self.mock.build_funding(htlc, amount).await
        }
        async fn build_claim(
            &self,
            htlc: &HtlcParams,
            at: &Outpoint,
            amount: Amount,
            preimage: &[u8; 32],
        ) -> Result<SignedTx> {
            self.mock.build_claim(htlc, at, amount, preimage).await
        }
        async fn build_refund(
            &self,
            htlc: &HtlcParams,
            at: &Outpoint,
            amount: Amount,
        ) -> Result<SignedTx> {
            self.mock.build_refund(htlc, at, amount).await
        }
        async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
            self.mock.broadcast(tx).await
        }
        async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
            self.mock.confirmations(txid).await
        }
        async fn htlc_output(
            &self,
            htlc: &HtlcParams,
            at: &Outpoint,
        ) -> Result<Option<LockedOutput>> {
            let real = self.mock.htlc_output(htlc, at).await?;
            let at = self.serve(htlc, at, real);
            self.zec.htlc_output(htlc, &at).await
        }
        async fn find_spend(
            &self,
            outpoint: &Outpoint,
            from_height: u64,
        ) -> Result<Option<SpendInfo>> {
            self.mock.find_spend(outpoint, from_height).await
        }
        fn lock_finished(&self, at: &Outpoint) {
            if let Some(stub_at) = self.served.lock().unwrap().get(at) {
                self.zec.lock_finished(stub_at);
            }
        }
        async fn release_dead_lock(&self, lock: &SignedTx) -> Result<bool> {
            self.mock.release_dead_lock(lock).await
        }
        async fn spendable(&self) -> Result<Option<Amount>> {
            self.mock.spendable().await
        }
        fn fee_bump(&self) -> FeeBump {
            self.mock.fee_bump()
        }
        async fn claim_feerate(&self) -> Result<Option<u64>> {
            self.mock.claim_feerate().await
        }
        fn claim_sizes(&self, htlc: &HtlcParams) -> Option<ClaimSizes> {
            self.mock.claim_sizes(htlc)
        }
        fn primary_only(&self) -> Option<Arc<dyn ChainBackend>> {
            self.mock.primary_only()
        }
    }

    struct World {
        divi: MockChain,
        zec: MockChain,
        mdivi: MockBackend,
        mzec: CrossRead,
        tzec: CrossRead,
        store: Store,
        maker: Maker,
        taker: Taker,
    }

    impl World {
        fn new(dir: Direction) -> World {
            Self::with_crosscheck(dir, true)
        }

        fn with_crosscheck(dir: Direction, crosscheck: bool) -> World {
            let divi = MockChain::new(Chain::Divi, T0, 60);
            let zec = MockChain::new(Chain::Zec, T0, 75);
            let mdivi = divi.backend(1, Amount(FUNDS));
            let mzec = CrossRead::with_crosscheck(zec.backend(2, Amount(FUNDS)), crosscheck);
            let tdivi = divi.backend(3, Amount(FUNDS));
            let tzec = CrossRead::with_crosscheck(zec.backend(4, Amount(FUNDS)), crosscheck);
            let store = Store::in_memory().unwrap();
            let maker = Maker::new(
                SwapConfig::profile(Profile::Testnet),
                Arc::new(mdivi.clone()),
                Arc::new(mzec.clone()),
                store.clone(),
                vec![Offer {
                    id: "o".into(),
                    direction: dir,
                    counter_chain: Chain::Zec,
                    divi_sats_per_btc: 50_000_000_000,
                    min_btc_sats: 10_000,
                    max_btc_sats: 5_000_000,
                }],
            )
            .unwrap();
            let taker = Taker::new(Arc::new(tdivi), Arc::new(tzec.clone()), store.clone());
            World {
                divi,
                zec,
                mdivi,
                mzec,
                tzec,
                store,
                maker,
                taker,
            }
        }

        /// Quote, accept and lock the taker leg; returns (taker swap id, maker swap id).
        async fn through_taker_lock(&self) -> (String, String) {
            let q = self.maker.quote("o", 1_000_000).await.unwrap();
            let (tid, req) = self.taker.prepare(&q).await.unwrap();
            let v = self.maker.accept(req).await.unwrap();
            self.taker.accepted(&tid, &v).await.unwrap();
            let notice = self.taker.lock(&tid).await.unwrap();
            let mid = self.maker.notify_lock(&v.id, notice).await.unwrap().id;
            (tid, mid)
        }

        async fn run(&self, tid: &str, mid: &str, rounds: usize) {
            for _ in 0..rounds {
                self.round(tid, mid).await;
            }
        }

        /// One block on each chain, then one maker tick and one taker step, each of which
        /// must return within [`STEP_LIMIT`] (EX: a hanging second operator must not hang
        /// the engine).
        async fn round(&self, tid: &str, mid: &str) {
            self.divi.mine(1);
            self.zec.mine(1);
            let _ = tokio::time::timeout(STEP_LIMIT, self.maker.tick())
                .await
                .expect("a maker tick hung");
            let v = self.maker.view(mid).unwrap();
            let _ = tokio::time::timeout(STEP_LIMIT, self.taker.step(tid, v.as_ref()))
                .await
                .expect("a taker step hung");
        }

        /// Rounds until `done` holds (at most `max`); the number of rounds run.
        async fn run_until(
            &self,
            tid: &str,
            mid: &str,
            max: usize,
            done: impl Fn(&World) -> bool,
        ) -> usize {
            for n in 1..=max {
                self.round(tid, mid).await;
                if done(self) {
                    return n;
                }
            }
            max
        }

        fn taker_record(&self, tid: &str) -> divi_swap::store::TakerRecord {
            self.store.get_taker_swap(tid).unwrap().unwrap()
        }

        /// The taker's own leg came back by refund.
        fn taker_refunded(&self, tid: &str) -> bool {
            matches!(
                self.taker_record(tid).state,
                TakerState::Refunded | TakerState::Done
            ) && self.taker_record(tid).maker_leg_claim.is_none()
        }

        fn maker_state(&self, mid: &str) -> (SwapState, Option<String>) {
            let r = self.store.get_maker_swap(mid).unwrap().unwrap();
            (r.state, r.last_error)
        }
    }

    /// Control: with the cross-check on and the second operator honest, a swap completes in
    /// both directions (ZEC as the taker leg, then as the maker leg).
    #[tokio::test]
    async fn agreeing_operators_complete_the_swap_both_ways() {
        for dir in [Direction::TakerPaysBtc, Direction::TakerPaysDivi] {
            let w = World::new(dir);
            let (tid, mid) = w.through_taker_lock().await;
            w.run(&tid, &mid, 80).await;
            assert_eq!(w.maker_state(&mid).0, SwapState::Done, "{dir:?}");
            let t = w.store.get_taker_swap(&tid).unwrap().unwrap();
            assert_eq!(t.state, TakerState::Done, "{dir:?}");
        }
    }

    /// Maker, funding point (ZEC is the taker leg): a taker lock the second operator does not
    /// show as agreed is never funded against; the maker waits, naming the refusal.
    #[tokio::test]
    async fn the_maker_does_not_fund_against_a_lock_the_second_operator_disputes() {
        for lie in LIES {
            let w = World::new(Direction::TakerPaysBtc);
            w.mzec.shows(lie);
            let (tid, mid) = w.through_taker_lock().await;
            w.run(&tid, &mid, 30).await;
            let (state, why) = w.maker_state(&mid);
            assert_eq!(w.mdivi.funding_calls(), 0, "{lie:?}: the maker funded");
            assert!(
                matches!(state, SwapState::Accepted | SwapState::TakerLockSeen),
                "{lie:?}: {state:?}"
            );
            let why = why.unwrap_or_default();
            assert!(
                why.contains("zec lock cross-check FAILED"),
                "{lie:?}: {why}"
            );
        }
    }

    /// Taker, claim point (ZEC is the maker leg): a maker lock the second operator does not show
    /// as agreed is never claimed, so the preimage stays secret.
    #[tokio::test]
    async fn the_taker_does_not_claim_a_lock_the_second_operator_disputes() {
        for lie in LIES {
            let w = World::new(Direction::TakerPaysDivi);
            w.tzec.shows(lie);
            let (tid, mid) = w.through_taker_lock().await;
            w.run(&tid, &mid, 40).await;
            assert_eq!(
                w.zec.attempts(TxKind::Claim),
                0,
                "{lie:?}: the taker claimed"
            );
            let t = w.store.get_taker_swap(&tid).unwrap().unwrap();
            assert!(t.maker_leg_claim.is_none(), "{lie:?}");
            let why = t.last_error.unwrap_or_default();
            assert!(
                why.contains("zec lock cross-check FAILED"),
                "{lie:?}: {why}"
            );
        }
    }

    // ---- EX: a deadline on the wait for the second operator ------------------------------

    /// The maker's funding deadline: less than its lock plus the claim margin is left on the
    /// taker leg (`taker_window_too_short`, the point past which it never funds anyway).
    async fn past_funding_deadline(w: &World, mid: &str) -> bool {
        let r = w.store.get_maker_swap(mid).unwrap().unwrap();
        let cfg = SwapConfig::profile(Profile::Testnet);
        let mtp = w.mzec.median_time_past().await.unwrap();
        let remaining = r.taker_leg_htlc.locktime.saturating_sub(mtp);
        remaining < r.quote.maker_timeout_secs + cfg.claim_margin_secs
    }

    fn aborted(w: &World, mid: &str) -> bool {
        w.maker_state(mid).0 == SwapState::Aborted
    }

    /// The maker (ZEC as the taker leg) with a second operator that `shows` its failure
    /// from the start: it never funds, waits up to the funding deadline and no further,
    /// then aborts naming the second operator; the taker's lock comes back by refund.
    /// Returns the maker's abort text.
    async fn the_maker_exits_at_the_funding_deadline(shows: Second) -> String {
        let w = World::new(Direction::TakerPaysBtc);
        w.mzec.shows(shows);
        let (tid, mid) = w.through_taker_lock().await;
        // Well before the deadline the maker still waits (fail closed, as before).
        w.run(&tid, &mid, 60).await;
        assert!(!past_funding_deadline(&w, &mid).await, "{shows:?}");
        assert!(
            !aborted(&w, &mid),
            "{shows:?}: aborted early: {:?}",
            w.maker_state(&mid)
        );
        let n = w.run_until(&tid, &mid, 400, |w| aborted(w, &mid)).await;
        let (state, why) = w.maker_state(&mid);
        assert_eq!(
            state,
            SwapState::Aborted,
            "{shows:?}: after {n} more rounds: {why:?}"
        );
        assert!(
            past_funding_deadline(&w, &mid).await,
            "{shows:?}: aborted before the deadline"
        );
        assert_eq!(w.mdivi.funding_calls(), 0, "{shows:?}: the maker funded");
        let why = why.unwrap_or_default();
        for needle in [
            "aborted",
            w.mzec.second_url(),
            "zec lock cross-check FAILED",
        ] {
            assert!(why.contains(needle), "{shows:?}: {why} lacks {needle}");
        }
        assert!(failing_secs(&why) < 3600, "{shows:?}: {why}");
        w.run_until(&tid, &mid, 400, |w| w.taker_refunded(&tid))
            .await;
        assert!(
            w.taker_refunded(&tid),
            "{shows:?}: {:?}",
            w.taker_record(&tid).state
        );
        assert!(
            w.zec.attempts(TxKind::Refund) > 0,
            "{shows:?}: no taker refund"
        );
        assert_eq!(w.mdivi.funding_calls(), 0, "{shows:?}: the maker funded");
        why
    }

    /// EX: the second operator down from the start.
    #[tokio::test]
    async fn a_second_operator_down_from_the_start_ends_the_maker_wait_at_the_deadline() {
        the_maker_exits_at_the_funding_deadline(Second::Down).await;
    }

    /// EX: the second operator never sees the lock the primary shows (from the mempool on).
    #[tokio::test]
    async fn a_second_operator_that_never_sees_the_lock_ends_the_maker_wait_at_the_deadline() {
        let why = the_maker_exits_at_the_funding_deadline(Second::NoTx).await;
        assert!(why.contains("has no such transaction"), "{why}");
    }

    /// EX (required by the Manager): the second operator's read hangs, never answering, past
    /// the deadline. The maker never funds and the taker's refund path is reached.
    #[tokio::test]
    async fn a_hanging_second_operator_never_gets_funded_against_and_the_taker_refunds() {
        let w = World::new(Direction::TakerPaysBtc);
        w.mzec.shows(Second::Hang);
        let (tid, mid) = w.through_taker_lock().await;
        w.run_until(&tid, &mid, 600, |w| w.taker_refunded(&tid))
            .await;
        assert_eq!(w.mdivi.funding_calls(), 0, "the maker funded");
        assert!(w.taker_refunded(&tid), "{:?}", w.taker_record(&tid).state);
        assert!(w.zec.attempts(TxKind::Refund) > 0, "no taker refund");
        let (state, why) = w.maker_state(&mid);
        assert_eq!(state, SwapState::Aborted, "{why:?}");
        let why = why.unwrap_or_default();
        for needle in [w.mzec.second_url(), "did not answer within"] {
            assert!(why.contains(needle), "{why} lacks {needle}");
        }
    }

    /// A second operator that is `gone` for 40 rounds, then back with an honest answer well
    /// before either deadline: the swap proceeds and completes both ways.
    async fn back_before_the_deadline(gone: Second) {
        for dir in [Direction::TakerPaysBtc, Direction::TakerPaysDivi] {
            let w = World::new(dir);
            let side = match dir {
                Direction::TakerPaysBtc => &w.mzec,
                _ => &w.tzec,
            };
            side.shows(gone);
            let (tid, mid) = w.through_taker_lock().await;
            w.run(&tid, &mid, 40).await;
            side.shows(Second::Honest);
            w.run(&tid, &mid, 120).await;
            assert_eq!(w.maker_state(&mid).0, SwapState::Done, "{dir:?}/{gone:?}");
            assert_eq!(
                w.taker_record(&tid).state,
                TakerState::Done,
                "{dir:?}/{gone:?}"
            );
        }
    }

    /// EX control: a second operator that was down comes back before the deadline.
    #[tokio::test]
    async fn a_second_operator_back_before_the_deadline_lets_the_swap_complete() {
        back_before_the_deadline(Second::Down).await;
    }

    /// EX: a second operator that hung (each read cut at its budget, the engine never held
    /// past it) comes back before the deadline.
    #[tokio::test]
    async fn a_second_operator_that_hung_and_came_back_lets_the_swap_complete() {
        back_before_the_deadline(Second::Hang).await;
    }

    /// EX, the taker (ZEC as the maker leg): with the second operator down it never reveals;
    /// at the claim deadline it declines, naming the second operator, and its own leg comes
    /// back by refund at its locktime as before.
    #[tokio::test]
    async fn the_taker_never_reveals_and_declines_at_the_claim_deadline() {
        for gone in [Second::Down, Second::Hang, Second::NoTx] {
            let w = World::new(Direction::TakerPaysDivi);
            w.tzec.shows(gone);
            let (tid, mid) = w.through_taker_lock().await;
            w.run(&tid, &mid, 40).await;
            let t = w.taker_record(&tid);
            assert!(
                t.claim_declined.is_none(),
                "{gone:?}: declined early: {t:?}"
            );
            w.run_until(&tid, &mid, 600, |w| w.taker_refunded(&tid))
                .await;
            let t = w.taker_record(&tid);
            assert!(w.taker_refunded(&tid), "{gone:?}: {:?}", t.state);
            assert_eq!(
                w.zec.attempts(TxKind::Claim),
                0,
                "{gone:?}: the taker claimed"
            );
            assert!(
                w.divi.attempts(TxKind::Refund) > 0,
                "{gone:?}: no taker refund"
            );
            let declined = t.claim_declined.unwrap_or_default();
            for needle in [w.tzec.second_url(), "zec lock cross-check FAILED"] {
                assert!(
                    declined.contains(needle),
                    "{gone:?}: {declined:?} lacks {needle}"
                );
            }
        }
    }

    /// EX: the deadline is never a primary-only fallback. A primary that shows the lock
    /// deeply buried, with the second operator down, never gets the maker to fund nor the
    /// taker to reveal, before or after the deadline; both end on the existing exits.
    #[tokio::test]
    async fn a_lying_primary_and_a_down_second_operator_never_fund_or_reveal() {
        for dir in [Direction::TakerPaysBtc, Direction::TakerPaysDivi] {
            let w = World::new(dir);
            for side in [&w.mzec, &w.tzec] {
                side.primary_lies();
                side.shows(Second::Down);
            }
            let (tid, mid) = w.through_taker_lock().await;
            w.run_until(&tid, &mid, 600, |w| w.taker_refunded(&tid))
                .await;
            assert!(
                w.taker_refunded(&tid),
                "{dir:?}: {:?}",
                w.taker_record(&tid).state
            );
            assert_eq!(w.zec.attempts(TxKind::Claim), 0, "{dir:?}: a ZEC claim");
            assert!(w.zec.primary_only_builds().is_empty(), "{dir:?}");
            assert!(w.divi.primary_only_builds().is_empty(), "{dir:?}");
            match dir {
                Direction::TakerPaysBtc => {
                    assert_eq!(w.mdivi.funding_calls(), 0, "the maker funded");
                    assert!(aborted(&w, &mid), "{:?}", w.maker_state(&mid));
                }
                _ => {
                    let t = w.taker_record(&tid);
                    assert!(t.maker_leg_claim.is_none());
                    let declined = t.claim_declined.unwrap_or_default();
                    assert!(declined.contains(w.tzec.second_url()), "{declined:?}");
                }
            }
        }
    }

    /// EX pin: with `[zec].crosscheck_url` unset nothing changes. A second operator that is
    /// down or hangs is never asked, and the swap completes both ways.
    #[tokio::test]
    async fn with_the_crosscheck_off_a_silent_second_operator_changes_nothing() {
        for dir in [Direction::TakerPaysBtc, Direction::TakerPaysDivi] {
            for gone in [Second::Down, Second::Hang] {
                let w = World::with_crosscheck(dir, false);
                for side in [&w.mzec, &w.tzec] {
                    side.shows(gone);
                }
                let (tid, mid) = w.through_taker_lock().await;
                w.run(&tid, &mid, 80).await;
                assert_eq!(w.maker_state(&mid).0, SwapState::Done, "{dir:?}/{gone:?}");
                assert_eq!(
                    w.taker_record(&tid).state,
                    TakerState::Done,
                    "{dir:?}/{gone:?}"
                );
                for side in [&w.mzec, &w.tzec] {
                    side.second.set_hang(false);
                    assert!(side.second.take_calls().is_empty(), "{dir:?}/{gone:?}");
                }
            }
        }
    }

    // ---- FB: the agreed lock kept per height, at the engine --------------------------------

    /// Manager (b): with honest operators the reading side keeps the agreed lock while the
    /// swap confirms it, and drops it once its swap reaches a terminal state (maker: ZEC as
    /// the taker leg; taker: ZEC as the maker leg), so a long-running daemon does not grow
    /// the cache.
    #[tokio::test]
    async fn the_kept_agreement_is_dropped_when_the_swap_ends() {
        for dir in [Direction::TakerPaysBtc, Direction::TakerPaysDivi] {
            let w = World::new(dir);
            let reader = match dir {
                Direction::TakerPaysBtc => &w.mzec,
                _ => &w.tzec,
            };
            let (tid, mid) = w.through_taker_lock().await;
            let mut kept = false;
            for _ in 0..80 {
                w.round(&tid, &mid).await;
                kept |= reader.zec.agreed_locks() > 0;
                if w.maker_state(&mid).0 == SwapState::Done
                    && w.taker_record(&tid).state == TakerState::Done
                {
                    break;
                }
            }
            assert_eq!(w.maker_state(&mid).0, SwapState::Done, "{dir:?}");
            assert_eq!(w.taker_record(&tid).state, TakerState::Done, "{dir:?}");
            assert!(kept, "{dir:?}: no agreement was ever kept");
            assert_eq!(
                reader.zec.agreed_locks(),
                0,
                "{dir:?}: kept past the swap's end"
            );
        }
    }
}
