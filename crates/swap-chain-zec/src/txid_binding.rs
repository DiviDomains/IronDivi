// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A lightwalletd operator's answer to `GetTransaction(T)` must hash to `T` (EW). Every
//! read of a transaction by txid ([`ZecBackend`]'s lock read, the second operator's
//! `lock_view`, `confirmations`, `find_spend`) gets another well-formed transaction from a
//! [`Lightwalletd`] stub under the txid it asks for, and must refuse it as
//! [`SwapError::Transient`] naming the operator and both txids (never a secret), while the
//! honest answer reads as before. v5 (ZIP-244) and v6 (ZIP-229) cover both txid rules the
//! parser accepts; a v4 answer does not parse and is refused too.

use divi_swap::{Amount, ChainBackend, HtlcParams, LockedOutput, Outpoint, SwapError, Txid};
use sha2::Digest;

use crate::address::{htlc_script_pubkey, TransparentAddress};
use crate::grpc::{CompactTx, CompactTxIn};
use crate::lwd_stub::{tx_of, txid_of, Lightwalletd};
use crate::ZecBackend;

const TIP: u64 = 40;
const ZAT: u64 = 250_000;
const FILLER: u64 = 1_000;
/// The txid rules: v5 (ZIP-244) and v6 (ZIP-229).
const VERSIONS: [u32; 2] = [5, 6];

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

fn agreed_spk() -> Vec<u8> {
    htlc_script_pubkey(&htlc().redeem_script())
}

fn other_spk() -> Vec<u8> {
    TransparentAddress::p2pkh(&pk(0x09)).script_pubkey()
}

/// A lock of `version` spending `prevout`:0: a filler output, then the agreed HTLC at vout 1.
/// Two prevouts give two transactions with the same output 1 and different txids.
fn lock_raw(version: u32, prevout: u8) -> Vec<u8> {
    tx_of(
        version,
        [prevout; 32],
        &[(FILLER, other_spk()), (ZAT, agreed_spk())],
    )
    .serialize()
}

/// The honest lock, and the substitute an operator answers instead (same vout 1).
fn honest_and_substitute(version: u32) -> (Vec<u8>, Vec<u8>) {
    (lock_raw(version, 0x11), lock_raw(version, 0x22))
}

fn lock_at(raw: &[u8]) -> Outpoint {
    Outpoint {
        txid: Txid(txid_of(raw)),
        vout: 1,
    }
}

fn checked(p: &Lightwalletd, o: &Lightwalletd) -> ZecBackend {
    p.backend()
        .with_crosscheck(Some(o.endpoint().to_string()))
        .unwrap()
}

/// `got` is a `Transient` refusal naming every one of `needles`, and not the stub key.
fn transient<T: std::fmt::Debug>(got: &divi_swap::Result<T>, needles: &[String], case: &str) {
    let Err(SwapError::Transient(m)) = got else {
        panic!("{case}: not refused as transient: {got:?}");
    };
    for needle in needles {
        assert!(m.contains(needle.as_str()), "{case}: {m} lacks {needle}");
    }
    // The stub backend's key ([0x33; 32]) appears in no message.
    assert!(!m.contains(&hex::encode([0x33u8; 32])), "{case}: {m}");
}

/// A v4 (Sapling) transparent transaction with output 1 the agreed HTLC, and its legacy
/// txid (double SHA-256, internal order). The parser takes v5 and v6 only.
fn v4_lock() -> (Vec<u8>, [u8; 32]) {
    let mut raw = Vec::new();
    raw.extend_from_slice(&0x8000_0004u32.to_le_bytes());
    raw.extend_from_slice(&0x892f_2085u32.to_le_bytes());
    raw.push(1); // vin
    raw.extend_from_slice(&[0x11; 32]);
    raw.extend_from_slice(&0u32.to_le_bytes());
    raw.extend_from_slice(&[1, 0x51]);
    raw.extend_from_slice(&u32::MAX.to_le_bytes());
    raw.push(2); // vout
    for (value, spk) in [(FILLER, other_spk()), (ZAT, agreed_spk())] {
        raw.extend_from_slice(&value.to_le_bytes());
        raw.push(spk.len() as u8);
        raw.extend_from_slice(&spk);
    }
    raw.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
    raw.extend_from_slice(&0u32.to_le_bytes()); // nExpiryHeight
    raw.extend_from_slice(&0i64.to_le_bytes()); // valueBalance
    raw.extend_from_slice(&[0, 0, 0]); // no spends, outputs or JoinSplits
    let txid: [u8; 32] = sha2::Sha256::digest(sha2::Sha256::digest(&raw)).into();
    (raw, txid)
}

// ---- The lock read ------------------------------------------------------------------------

/// Control: the honest lock reads as before on the primary alone and cross-checked.
#[tokio::test]
async fn an_honest_lock_reads_unchanged() {
    for version in VERSIONS {
        let (honest, _) = honest_and_substitute(version);
        let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
        p.put_honest(honest.clone(), TIP - 2);
        o.put_honest(honest.clone(), TIP - 2);
        let want = Some(LockedOutput {
            amount: Amount::from_sat(ZAT),
            confirmations: 3,
        });
        let alone = p.backend().htlc_output(&htlc(), &lock_at(&honest)).await;
        assert_eq!(alone.unwrap(), want, "v{version} alone");
        let both = checked(&p, &o)
            .htlc_output(&htlc(), &lock_at(&honest))
            .await;
        assert_eq!(both.unwrap(), want, "v{version} cross-checked");
    }
}

/// The primary answers `GetTransaction(T)` with T', whose output 1 is the agreed HTLC and
/// value: not a lock, a `Transient` naming the primary, T and T'. With the cross-check off
/// (the default) the primary alone decided.
#[tokio::test]
async fn the_primary_answering_another_transaction_is_not_a_lock() {
    for version in VERSIONS {
        let (honest, substitute) = honest_and_substitute(version);
        let at = lock_at(&honest);
        for height in [TIP - 2, 0] {
            let p = Lightwalletd::start(TIP);
            p.put_tx(at.txid.0, substitute.clone(), height);
            let got = p.backend().htlc_output(&htlc(), &at).await;
            transient(
                &got,
                &[
                    p.endpoint().to_string(),
                    at.txid.to_string(),
                    Txid(txid_of(&substitute)).to_string(),
                ],
                &format!("v{version} at {height}"),
            );
        }
    }
}

/// The same with the cross-check on and the second operator honest: refused before the
/// second operator is asked.
#[tokio::test]
async fn a_cross_checked_primary_answering_another_transaction_is_refused() {
    for version in VERSIONS {
        let (honest, substitute) = honest_and_substitute(version);
        let at = lock_at(&honest);
        let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
        p.put_tx(at.txid.0, substitute.clone(), TIP - 2);
        o.put_honest(honest.clone(), TIP - 2);
        let got = checked(&p, &o).htlc_output(&htlc(), &at).await;
        transient(
            &got,
            &[p.endpoint().to_string(), at.txid.to_string()],
            &format!("v{version}"),
        );
    }
}

/// The second operator (`[zec].crosscheck_url`, `lock_view`) answers T' for T: the lock
/// cross-check refuses, naming both operators and T'.
#[tokio::test]
async fn the_second_operator_answering_another_transaction_refuses_the_lock() {
    for version in VERSIONS {
        let (honest, substitute) = honest_and_substitute(version);
        let at = lock_at(&honest);
        let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
        p.put_honest(honest.clone(), TIP - 2);
        o.put_tx(at.txid.0, substitute.clone(), TIP - 2);
        let got = checked(&p, &o).htlc_output(&htlc(), &at).await;
        transient(
            &got,
            &[
                "zec lock cross-check FAILED".to_string(),
                p.endpoint().to_string(),
                o.endpoint().to_string(),
                Txid(txid_of(&substitute)).to_string(),
            ],
            &format!("v{version}"),
        );
    }
}

/// Both operators answering the same T' (ET's remaining case): refused on each side.
#[tokio::test]
async fn both_operators_answering_the_same_other_transaction_are_refused() {
    for version in VERSIONS {
        let (honest, substitute) = honest_and_substitute(version);
        let at = lock_at(&honest);
        let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
        p.put_tx(at.txid.0, substitute.clone(), TIP - 2);
        o.put_tx(at.txid.0, substitute.clone(), TIP - 2);
        let got = checked(&p, &o).htlc_output(&htlc(), &at).await;
        transient(&got, &[p.endpoint().to_string()], &format!("v{version}"));
    }
}

/// A v4 answer does not parse, so it is never a lock, on either operator (control: true
/// before EW as well).
#[tokio::test]
async fn a_v4_answer_is_never_a_lock() {
    let (raw, txid) = v4_lock();
    let at = Outpoint {
        txid: Txid(txid),
        vout: 1,
    };
    let p = Lightwalletd::start(TIP);
    p.put_tx(txid, raw.clone(), TIP - 2);
    assert!(p.backend().htlc_output(&htlc(), &at).await.is_err());

    let (honest, _) = honest_and_substitute(5);
    let at = lock_at(&honest);
    let (p, o) = (Lightwalletd::start(TIP), Lightwalletd::start(TIP));
    p.put_honest(honest, TIP - 2);
    o.put_tx(at.txid.0, raw, TIP - 2);
    let got = checked(&p, &o).htlc_output(&htlc(), &at).await;
    transient(
        &got,
        &["zec lock cross-check FAILED".to_string()],
        "v4 at the second",
    );
}

// ---- confirmations ------------------------------------------------------------------------

/// `confirmations(T)` (the lock's, a claim's, a refund's; it also releases input
/// reservations): T' answered at a mined height is not T confirmed. Control: the honest
/// answer counts as before, and an unknown txid is still `None`.
#[tokio::test]
async fn confirmations_refuse_another_transaction() {
    for version in VERSIONS {
        let (honest, substitute) = honest_and_substitute(version);
        let txid = Txid(txid_of(&honest));
        let p = Lightwalletd::start(TIP);
        let b = p.backend();
        assert_eq!(b.confirmations(&txid).await.unwrap(), None, "v{version}");
        for height in [TIP - 2, 0] {
            p.put_tx(txid.0, substitute.clone(), height);
            let got = b.confirmations(&txid).await;
            transient(
                &got,
                &[
                    p.endpoint().to_string(),
                    txid.to_string(),
                    Txid(txid_of(&substitute)).to_string(),
                ],
                &format!("v{version} at {height}"),
            );
        }
        for (height, confs) in [(TIP - 2, 3), (0, 0)] {
            p.put_honest(honest.clone(), height);
            let got = b.confirmations(&txid).await.unwrap();
            assert_eq!(got, Some(confs), "v{version} at {height}");
        }
    }
}

/// A v4 answer to `confirmations` cannot be checked against the txid: refused.
#[tokio::test]
async fn confirmations_refuse_a_v4_answer() {
    let (raw, txid) = v4_lock();
    let p = Lightwalletd::start(TIP);
    p.put_tx(txid, raw, TIP - 2);
    let got = p.backend().confirmations(&Txid(txid)).await;
    transient(&got, &[p.endpoint().to_string()], "v4");
}

// ---- find_spend ---------------------------------------------------------------------------

/// The lock `find_spend` watches.
fn watched() -> Outpoint {
    lock_at(&lock_raw(5, 0x11))
}

/// A spend of `prevout` with one output of `value`, of `version`.
fn spend_raw(version: u32, prevout: Outpoint, value: u64) -> Vec<u8> {
    let mut t = tx_of(version, prevout.txid.0, &[(value, other_spk())]);
    t.vin[0].prevout.n = prevout.vout;
    t.vin[0].script_sig = vec![0x51, 0x52];
    t.serialize()
}

/// The block at `height` names `spender` as spending `at` at input 0.
fn block_names(p: &Lightwalletd, height: u64, spender: [u8; 32], at: Outpoint) {
    p.put_compact_tx(
        height,
        CompactTx {
            index: 0,
            txid: spender.to_vec(),
            vin: vec![CompactTxIn {
                prevout_txid: at.txid.0.to_vec(),
                prevout_index: at.vout,
            }],
        },
    );
}

/// Control: the honest spender is found with its scriptSig, as before.
#[tokio::test]
async fn find_spend_reads_the_honest_spender() {
    for version in VERSIONS {
        let p = Lightwalletd::start(TIP);
        let spend = spend_raw(version, watched(), ZAT - 2_000);
        let s = p.put_honest(spend, TIP - 3);
        block_names(&p, TIP - 3, s, watched());
        let got = p.backend().find_spend(&watched(), TIP - 5).await.unwrap();
        let info = got.expect("found");
        assert_eq!(
            (info.txid, info.input_index, info.height),
            (Txid(s), 0, Some(TIP - 3)),
            "v{version}"
        );
        assert_eq!(info.script_sig, vec![0x51, 0x52], "v{version}");
    }
}

/// The compact block names spender S; `GetTransaction(S)` answers S' (another spend of the
/// same lock): its scriptSig is not S's, so the spend is not read from it.
#[tokio::test]
async fn find_spend_refuses_another_transaction_for_the_spender() {
    for version in VERSIONS {
        let p = Lightwalletd::start(TIP);
        let s = txid_of(&spend_raw(version, watched(), ZAT - 2_000));
        let substitute = spend_raw(version, watched(), ZAT - 3_000);
        p.put_tx(s, substitute.clone(), TIP - 3);
        block_names(&p, TIP - 3, s, watched());
        let got = p.backend().find_spend(&watched(), TIP - 5).await;
        transient(
            &got,
            &[
                p.endpoint().to_string(),
                Txid(s).to_string(),
                Txid(txid_of(&substitute)).to_string(),
            ],
            &format!("v{version}"),
        );
    }
}

/// The compact block names a real transaction, answered honestly, whose input does not spend
/// the lock: refused, not read as the lock's spend.
#[tokio::test]
async fn find_spend_refuses_a_spender_that_spends_something_else() {
    for version in VERSIONS {
        let p = Lightwalletd::start(TIP);
        let elsewhere = Outpoint {
            txid: Txid([0x99; 32]),
            vout: 1,
        };
        let s = p.put_honest(spend_raw(version, elsewhere, ZAT), TIP - 3);
        block_names(&p, TIP - 3, s, watched());
        let got = p.backend().find_spend(&watched(), TIP - 5).await;
        transient(
            &got,
            &[p.endpoint().to_string(), Txid(s).to_string()],
            &format!("v{version}"),
        );
    }
}
