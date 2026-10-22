// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The C1 fix's scripts (`docs/plans/swap-poc/xmr-c1-design.md` §4): `Tx_lock`'s
//! three-branch output, `Tx_cancel`'s refund-or-punish output, their scriptSigs, and the
//! finite set of `Tx_cancel` encodings a staker can mine.
//!
//! ```text
//! Tx_lock:   OP_DUP OP_1 OP_EQUAL
//!            OP_IF   OP_DROP OP_2 <a> <b> OP_2 OP_CHECKMULTISIG                  redeem  [0x01]
//!            OP_ELSE OP_DUP OP_2 OP_EQUAL
//!                    OP_IF   OP_DROP OP_DEPTH OP_1 OP_EQUALVERIFY
//!                            <t_cancel> OP_CLTV OP_DROP <J> OP_CHECKSIG         cancel  [0x02]
//!                    OP_ELSE OP_3 OP_EQUALVERIFY
//!                            <t_late> OP_CLTV OP_DROP <a> OP_CHECKSIG           late    [0x03]
//!                    OP_ENDIF
//!            OP_ENDIF
//! Tx_cancel: OP_IF   OP_2 <a> <b> OP_2 OP_CHECKMULTISIG                         refund
//!            OP_ELSE <t_punish> OP_CLTV OP_DROP <b> OP_CHECKSIG                 punish
//!            OP_ENDIF
//! ```
//!
//! `J` is the 2P-ECDSA joint key signed exactly once, on `Tx_cancel`. The `OP_EQUAL`
//! selectors and the `OP_DEPTH` guard leave a staker [`CANCEL_VARIANTS`] encodings of a
//! signed `Tx_cancel` and no more; [`cancel_variants`] lists them so the taker can
//! adaptor-sign a `Tx_refund` for every one.
//!
//! Nothing is presigned against the txid of `Tx_redeem`, the late spend, `Tx_refund` or
//! `Tx_punish`, so their encodings need no such care. Readers of a broadcast spend
//! ([`stack_items`], [`lock_spend_branch`]) index from the top of the stack, which a
//! staker cannot move (anything extra goes underneath).

use divi_crypto::hash::hash160;
use divi_crypto::signature::Signature as DiviSignature;
use divi_primitives::script::Script;
use divi_primitives::transaction::Transaction;
use divi_swap::htlc::{
    push_data, script_num, OP_0, OP_1, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_DROP, OP_ELSE,
    OP_ENDIF, OP_EQUALVERIFY, OP_IF,
};

const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_DUP: u8 = 0x76;
const OP_EQUAL: u8 = 0x87;
const OP_DEPTH: u8 = 0x74;
const OP_CHECKMULTISIG: u8 = 0xae;

/// Selector of the redeem branch (stack bytes, exactly).
pub const SEL_REDEEM: u8 = 0x01;
/// Selector of the cancel branch.
pub const SEL_CANCEL: u8 = 0x02;
/// Selector of the maker's late escape.
pub const SEL_LATE: u8 = 0x03;

/// How many encodings of one signed `Tx_cancel` a staker can mine: `σ_J` S-flip (2) ×
/// its push encodings (4) × the selector's (5) × the redeem script's (3). Pinned by a test.
pub const CANCEL_VARIANTS: usize = 120;

/// The public parts of `Tx_lock`'s output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockScript {
    /// `a`: the maker's key (redeem 2-of-2, and alone on the late escape).
    pub maker: [u8; 33],
    /// `b`: the taker's key (redeem 2-of-2).
    pub taker: [u8; 33],
    /// `J`: the 2P-ECDSA joint key, signed once on `Tx_cancel`.
    pub joint: [u8; 33],
    /// The cancel branch opens at this MTP (unix seconds).
    pub t_cancel: u32,
    /// The maker's late escape opens at this MTP.
    pub t_late: u32,
}

fn multisig_into(s: &mut Vec<u8>, a: &[u8; 33], b: &[u8; 33]) {
    s.push(OP_2);
    push_data(s, a);
    push_data(s, b);
    s.extend([OP_2, OP_CHECKMULTISIG]);
}

fn after_into(s: &mut Vec<u8>, t: u32, key: &[u8; 33]) {
    push_data(s, &script_num(t as i64));
    s.extend([OP_CHECKLOCKTIMEVERIFY, OP_DROP]);
    push_data(s, key);
    s.push(OP_CHECKSIG);
}

impl LockScript {
    /// The redeem script (also every lock spend's sighash scriptCode).
    pub fn redeem_script(&self) -> Vec<u8> {
        let mut s = vec![OP_DUP, OP_1, OP_EQUAL, OP_IF, OP_DROP];
        multisig_into(&mut s, &self.maker, &self.taker);
        s.extend([OP_ELSE, OP_DUP, OP_2, OP_EQUAL, OP_IF, OP_DROP]);
        s.extend([OP_DEPTH, OP_1, OP_EQUALVERIFY]);
        after_into(&mut s, self.t_cancel, &self.joint);
        s.extend([OP_ELSE, OP_3, OP_EQUALVERIFY]);
        after_into(&mut s, self.t_late, &self.maker);
        s.extend([OP_ENDIF, OP_ENDIF]);
        s
    }

    /// Its P2SH scriptPubKey.
    pub fn script_pubkey(&self) -> Script {
        p2sh(&self.redeem_script())
    }
}

/// The public parts of `Tx_cancel`'s output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelScript {
    /// `a`: the maker's key (refund 2-of-2).
    pub maker: [u8; 33],
    /// `b`: the taker's key (refund 2-of-2, and alone on punish).
    pub taker: [u8; 33],
    /// Punish opens at this MTP.
    pub t_punish: u32,
}

impl CancelScript {
    /// The redeem script.
    pub fn redeem_script(&self) -> Vec<u8> {
        let mut s = vec![OP_IF];
        multisig_into(&mut s, &self.maker, &self.taker);
        s.push(OP_ELSE);
        after_into(&mut s, self.t_punish, &self.taker);
        s.push(OP_ENDIF);
        s
    }

    /// Its P2SH scriptPubKey.
    pub fn script_pubkey(&self) -> Script {
        p2sh(&self.redeem_script())
    }
}

/// P2SH scriptPubKey of a redeem script.
pub fn p2sh(redeem: &[u8]) -> Script {
    Script::new_p2sh(hash160(redeem).as_bytes())
}

/// `Tx_lock` redeem branch: `OP_0 <sig_a> <sig_b> OP_1 <redeem>` (sigs carry the
/// sighash byte).
pub fn redeem_sig(sig_maker: &[u8], sig_taker: &[u8], redeem: &[u8]) -> Script {
    let mut s = vec![OP_0];
    push_data(&mut s, sig_maker);
    push_data(&mut s, sig_taker);
    s.push(OP_1);
    push_data(&mut s, redeem);
    Script::from_bytes(s)
}

/// `Tx_lock` cancel branch, canonical encoding: `<σ_J> OP_2 <redeem>`.
pub fn cancel_sig(sig_joint: &[u8], redeem: &[u8]) -> Script {
    let mut s = Vec::new();
    push_data(&mut s, sig_joint);
    s.push(OP_2);
    push_data(&mut s, redeem);
    Script::from_bytes(s)
}

/// `Tx_lock` late branch: `<sig_a> OP_3 <redeem>`.
pub fn late_sig(sig_maker: &[u8], redeem: &[u8]) -> Script {
    let mut s = Vec::new();
    push_data(&mut s, sig_maker);
    s.push(OP_3);
    push_data(&mut s, redeem);
    Script::from_bytes(s)
}

/// `Tx_cancel` refund branch: `OP_0 <sig_a> <sig_b> OP_1 <redeem>`.
pub fn refund_sig(sig_maker: &[u8], sig_taker: &[u8], redeem: &[u8]) -> Script {
    redeem_sig(sig_maker, sig_taker, redeem)
}

/// `Tx_cancel` punish branch: `<sig_b> OP_0 <redeem>`.
pub fn punish_sig(sig_taker: &[u8], redeem: &[u8]) -> Script {
    let mut s = Vec::new();
    push_data(&mut s, sig_taker);
    s.push(OP_0);
    push_data(&mut s, redeem);
    Script::from_bytes(s)
}

/// The stack a push-only scriptSig leaves, bottom first (`OP_0` → empty, `OP_n` → `[n]`,
/// `OP_1NEGATE` → `[0x81]`); `None` if it is not push-only or is truncated.
pub fn stack_items(script_sig: &[u8]) -> Option<Vec<Vec<u8>>> {
    let s = script_sig;
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let op = s[i];
        i += 1;
        let len = match op {
            0x00 => 0,
            0x01..=0x4b => op as usize,
            0x4c => {
                let n = *s.get(i)? as usize;
                i += 1;
                n
            }
            0x4d => {
                let n = u16::from_le_bytes([*s.get(i)?, *s.get(i + 1)?]) as usize;
                i += 2;
                n
            }
            0x4e => {
                let b = s.get(i..i + 4)?;
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
            0x4f => {
                out.push(vec![0x81]);
                continue;
            }
            0x51..=0x60 => {
                out.push(vec![op - 0x50]);
                continue;
            }
            _ => return None,
        };
        out.push(s.get(i..i + len)?.to_vec());
        i += len;
    }
    Some(out)
}

/// Which branch a broadcast spend of `Tx_lock` took, with the signatures it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockSpend {
    /// Happy path: the maker's and the taker's signatures (`Tx_redeem`).
    Redeem {
        /// `a`'s signature (DER + sighash byte).
        sig_maker: Vec<u8>,
        /// `b`'s signature.
        sig_taker: Vec<u8>,
    },
    /// `Tx_cancel` (some encoding of it).
    Cancel,
    /// The maker's late escape.
    Late,
}

/// The branch of a `Tx_lock` spend whose last push is `redeem`; `None` if it does not
/// spend this script (or is not a valid shape of any branch).
pub fn lock_spend_branch(tx: &Transaction, redeem: &[u8]) -> Option<LockSpend> {
    let items = stack_items(tx.vin.first()?.script_sig.as_bytes())?;
    let n = items.len();
    if n < 3 || items[n - 1] != redeem {
        return None;
    }
    match items[n - 2].as_slice() {
        [SEL_REDEEM] if n >= 5 => Some(LockSpend::Redeem {
            sig_maker: items[n - 4].clone(),
            sig_taker: items[n - 3].clone(),
        }),
        [SEL_CANCEL] => Some(LockSpend::Cancel),
        [SEL_LATE] => Some(LockSpend::Late),
        _ => None,
    }
}

/// The two signatures of a `Tx_cancel` refund-branch spend (`Tx_refund`): `(a, b)`.
pub fn refund_spend_sigs(tx: &Transaction, redeem: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let items = stack_items(tx.vin.first()?.script_sig.as_bytes())?;
    let n = items.len();
    if n < 5 || items[n - 1] != redeem || items[n - 2].is_empty() {
        return None;
    }
    Some((items[n - 4].clone(), items[n - 3].clone()))
}

/// Every consensus-valid encoding of `data` as one push: direct, `PUSHDATA1/2/4`, and the
/// small-number opcode where one exists.
pub fn push_encodings(data: &[u8]) -> Vec<Vec<u8>> {
    let n = data.len();
    // A small-number opcode carries the value itself: no data follows it.
    let mut out: Vec<Vec<u8>> = match data {
        [] => vec![vec![OP_0]],
        [v @ 1..=16] => vec![vec![0x50 + v]],
        [0x81] => vec![vec![0x4f]],
        _ => Vec::new(),
    };
    let with = |head: Vec<u8>| [head.as_slice(), data].concat();
    if (1..=0x4b).contains(&n) {
        out.push(with(vec![n as u8]));
    }
    if n <= 0xff {
        out.push(with(vec![0x4c, n as u8]));
    }
    if n <= 0xffff {
        let l = (n as u16).to_le_bytes();
        out.push(with(vec![0x4d, l[0], l[1]]));
    }
    let l = (n as u32).to_le_bytes();
    out.push(with(vec![0x4e, l[0], l[1], l[2], l[3]]));
    out
}

/// secp256k1 group order, big-endian.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The other S of an ECDSA signature (`s → n − s`), DER + the same sighash byte. Divi's
/// consensus takes both (LOW_S is relay policy only).
pub fn s_flip(sig: &[u8]) -> Option<Vec<u8>> {
    let (&ty, der) = sig.split_last()?;
    let mut c = DiviSignature::from_der(der).ok()?.to_compact();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = ORDER[i] as i16 - c[32 + i] as i16 - borrow;
        borrow = (d < 0) as i16;
        c[32 + i] = d.rem_euclid(256) as u8;
    }
    let mut out = DiviSignature::from_compact(&c).ok()?.to_der();
    out.push(ty);
    Some(out)
}

/// Every `Tx_cancel` a staker can mine from the signed one: the cancel scriptSig's
/// `<σ_J> <0x02> <redeem>` over each S of `σ_J` and every push encoding of each part.
/// `sig_joint` is `σ_J` (DER + SIGHASH_ALL), in either S form.
pub fn cancel_variants(
    tx_cancel: &Transaction,
    sig_joint: &[u8],
    redeem: &[u8],
) -> Vec<Transaction> {
    let mut sigs = vec![sig_joint.to_vec()];
    if let Some(f) = s_flip(sig_joint) {
        sigs.push(f);
    }
    let sels = push_encodings(&[SEL_CANCEL]);
    let reds = push_encodings(redeem);
    let mut out = Vec::with_capacity(CANCEL_VARIANTS);
    for sig in &sigs {
        for s in push_encodings(sig) {
            for sel in &sels {
                for r in &reds {
                    let mut tx = tx_cancel.clone();
                    tx.vin[0].script_sig = Script::from_bytes([s.as_slice(), sel, r].concat());
                    out.push(tx);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multisig::{sign_input, test_outpoint};
    use divi_crypto::keys::SecretKey;
    use divi_primitives::amount::Amount;
    use divi_primitives::constants::CURRENT_TX_VERSION;
    use divi_primitives::transaction::{TxIn, TxOut};
    use divi_script::{verify_script, ScriptError, ScriptFlags, TransactionSignatureChecker};
    use divi_swap::htlc::REFUND_SEQUENCE;
    use std::collections::HashSet;

    const T_CANCEL: u32 = 1_800_000_000;
    const T_PUNISH: u32 = 1_800_003_600;
    const T_LATE: u32 = 1_800_010_000;

    fn key(b: u8) -> SecretKey {
        SecretKey::from_bytes(&[b; 32]).unwrap()
    }
    fn pk(k: &SecretKey) -> [u8; 33] {
        k.public_key().serialize_compressed()
    }

    struct Fx {
        a: SecretKey,
        b: SecretKey,
        j: SecretKey,
        lock: LockScript,
    }

    fn fx() -> Fx {
        let (a, b, j) = (key(0x11), key(0x22), key(0x33));
        let lock = LockScript {
            maker: pk(&a),
            taker: pk(&b),
            joint: pk(&j),
            t_cancel: T_CANCEL,
            t_late: T_LATE,
        };
        Fx { a, b, j, lock }
    }

    fn spend(lock_time: u32, to: Script) -> Transaction {
        Transaction {
            version: CURRENT_TX_VERSION,
            vin: vec![TxIn::new(test_outpoint(7), Script::new(), REFUND_SEQUENCE)],
            vout: vec![TxOut::new(Amount::from_sat(9_000), to)],
            lock_time,
        }
    }

    /// Divi's mandatory (block) flags: no LOW_S, MINIMALDATA, NULLDUMMY, SIGPUSHONLY or
    /// CLEANSTACK — the staker's view.
    fn consensus() -> ScriptFlags {
        ScriptFlags::from_bits(
            ScriptFlags::P2SH | ScriptFlags::DERSIG | ScriptFlags::CHECKLOCKTIMEVERIFY,
        )
    }

    fn check(tx: &Transaction, spk: &Script) -> Result<(), ScriptError> {
        let checker = TransactionSignatureChecker::new(tx, 0, Amount::from_sat(10_000));
        verify_script(&tx.vin[0].script_sig, spk, consensus(), &checker)
    }

    fn sign(tx: &Transaction, redeem: &[u8], k: &SecretKey) -> Vec<u8> {
        sign_input(tx, 0, &Script::from_bytes(redeem.to_vec()), k).unwrap()
    }

    fn signed_cancel(f: &Fx) -> (Transaction, Vec<u8>) {
        let redeem = f.lock.redeem_script();
        let mut tx = spend(T_CANCEL, Script::new_p2pkh(&[1; 20]));
        let sig = sign(&tx, &redeem, &f.j);
        tx.vin[0].script_sig = cancel_sig(&sig, &redeem);
        (tx, sig)
    }

    #[test]
    fn redeem_branch_needs_both_keys() {
        let f = fx();
        let redeem = f.lock.redeem_script();
        let mut tx = spend(0, Script::new_p2pkh(&[9; 20]));
        let (sa, sb) = (sign(&tx, &redeem, &f.a), sign(&tx, &redeem, &f.b));
        tx.vin[0].script_sig = redeem_sig(&sa, &sb, &redeem);
        check(&tx, &f.lock.script_pubkey()).unwrap();
        assert_eq!(
            lock_spend_branch(&tx, &redeem),
            Some(LockSpend::Redeem {
                sig_maker: sa.clone(),
                sig_taker: sb.clone()
            })
        );
        tx.vin[0].script_sig = redeem_sig(&sa, &sa, &redeem);
        assert!(check(&tx, &f.lock.script_pubkey()).is_err());
    }

    #[test]
    fn cancel_branch_needs_joint_key_and_t_cancel() {
        let f = fx();
        let redeem = f.lock.redeem_script();
        let (tx, _) = signed_cancel(&f);
        check(&tx, &f.lock.script_pubkey()).unwrap();
        assert_eq!(lock_spend_branch(&tx, &redeem), Some(LockSpend::Cancel));

        // Any other key, or an earlier nLockTime, fails.
        let mut other = spend(T_CANCEL, Script::new_p2pkh(&[1; 20]));
        let s = sign(&other, &redeem, &f.a);
        other.vin[0].script_sig = cancel_sig(&s, &redeem);
        assert!(check(&other, &f.lock.script_pubkey()).is_err());
        let mut early = spend(T_CANCEL - 1, Script::new_p2pkh(&[1; 20]));
        let s = sign(&early, &redeem, &f.j);
        early.vin[0].script_sig = cancel_sig(&s, &redeem);
        assert!(check(&early, &f.lock.script_pubkey()).is_err());
    }

    /// The depth guard: a push slipped under `σ_J` (which CHECKSIG would ignore) fails.
    #[test]
    fn cancel_branch_rejects_extra_pushes() {
        let f = fx();
        let redeem = f.lock.redeem_script();
        let (mut tx, sig) = signed_cancel(&f);
        for junk in [vec![OP_0], vec![OP_1], vec![0x01, 0x07]] {
            let mut s = junk;
            s.extend_from_slice(cancel_sig(&sig, &redeem).as_bytes());
            tx.vin[0].script_sig = Script::from_bytes(s);
            assert!(check(&tx, &f.lock.script_pubkey()).is_err());
        }
    }

    #[test]
    fn late_branch_is_the_maker_alone_after_t_late() {
        let f = fx();
        let redeem = f.lock.redeem_script();
        let mut tx = spend(T_LATE, Script::new_p2pkh(&[2; 20]));
        let s = sign(&tx, &redeem, &f.a);
        tx.vin[0].script_sig = late_sig(&s, &redeem);
        check(&tx, &f.lock.script_pubkey()).unwrap();
        assert_eq!(lock_spend_branch(&tx, &redeem), Some(LockSpend::Late));

        let mut early = spend(T_LATE - 1, Script::new_p2pkh(&[2; 20]));
        let s = sign(&early, &redeem, &f.a);
        early.vin[0].script_sig = late_sig(&s, &redeem);
        assert!(check(&early, &f.lock.script_pubkey()).is_err());
        let mut taker = spend(T_LATE, Script::new_p2pkh(&[2; 20]));
        let s = sign(&taker, &redeem, &f.b);
        taker.vin[0].script_sig = late_sig(&s, &redeem);
        assert!(check(&taker, &f.lock.script_pubkey()).is_err());
    }

    /// Bare-`OP_IF` truthiness does not open a branch: only the exact selector bytes do.
    #[test]
    fn selectors_are_exact_bytes() {
        let f = fx();
        let redeem = f.lock.redeem_script();
        let (mut tx, sig) = signed_cancel(&f);
        for sel in [vec![0x01, 0x82], vec![0x02, 0x02, 0x00], vec![0x01, 0x12]] {
            let mut s = Vec::new();
            push_data(&mut s, &sig);
            s.extend(sel);
            push_data(&mut s, &redeem);
            tx.vin[0].script_sig = Script::from_bytes(s);
            assert!(check(&tx, &f.lock.script_pubkey()).is_err());
        }
    }

    /// The variant set: exactly [`CANCEL_VARIANTS`] distinct txids, every one valid under
    /// consensus flags (Divi Core, and IronDivi's checker since it follows Core, accept
    /// high-S signatures), and every one read back as the cancel branch.
    #[test]
    fn cancel_variants_are_exactly_120() {
        let f = fx();
        let redeem = f.lock.redeem_script();
        assert!(
            (0x4c..=0xff).contains(&redeem.len()),
            "redeem push is PUSHDATA1-sized"
        );
        let (tx, sig) = signed_cancel(&f);
        let vs = cancel_variants(&tx, &sig, &redeem);
        assert_eq!(vs.len(), CANCEL_VARIANTS);
        let ids: HashSet<_> = vs.iter().map(|v| v.txid()).collect();
        assert_eq!(ids.len(), CANCEL_VARIANTS);
        assert!(
            ids.contains(&tx.txid()),
            "the canonical encoding is one of them"
        );
        let flipped = s_flip(&sig).unwrap();
        assert_ne!(flipped, sig);
        assert_eq!(s_flip(&flipped).unwrap(), sig);
        let mut valid = 0;
        for v in &vs {
            assert_eq!(lock_spend_branch(v, &redeem), Some(LockSpend::Cancel));
            if check(v, &f.lock.script_pubkey()).is_ok() {
                valid += 1;
            }
        }
        assert_eq!(valid, CANCEL_VARIANTS);
        // The set is the same whichever S form it starts from.
        let from_flip: HashSet<_> = cancel_variants(&tx, &flipped, &redeem)
            .iter()
            .map(|v| v.txid())
            .collect();
        assert_eq!(from_flip, ids);
    }

    #[test]
    fn cancel_output_refund_and_punish() {
        let f = fx();
        let c = CancelScript {
            maker: pk(&f.a),
            taker: pk(&f.b),
            t_punish: T_PUNISH,
        };
        let redeem = c.redeem_script();
        let mut refund = spend(T_CANCEL, Script::new_p2pkh(&[3; 20]));
        let (sa, sb) = (sign(&refund, &redeem, &f.a), sign(&refund, &redeem, &f.b));
        refund.vin[0].script_sig = refund_sig(&sa, &sb, &redeem);
        check(&refund, &c.script_pubkey()).unwrap();
        assert_eq!(refund_spend_sigs(&refund, &redeem), Some((sa, sb)));

        let mut punish = spend(T_PUNISH, Script::new_p2pkh(&[4; 20]));
        let s = sign(&punish, &redeem, &f.b);
        punish.vin[0].script_sig = punish_sig(&s, &redeem);
        check(&punish, &c.script_pubkey()).unwrap();
        assert_eq!(refund_spend_sigs(&punish, &redeem), None);

        let mut early = spend(T_PUNISH - 1, Script::new_p2pkh(&[4; 20]));
        let s = sign(&early, &redeem, &f.b);
        early.vin[0].script_sig = punish_sig(&s, &redeem);
        assert!(check(&early, &c.script_pubkey()).is_err());
        let mut maker = spend(T_PUNISH, Script::new_p2pkh(&[4; 20]));
        let s = sign(&maker, &redeem, &f.a);
        maker.vin[0].script_sig = punish_sig(&s, &redeem);
        assert!(check(&maker, &c.script_pubkey()).is_err());
    }

    #[test]
    fn stack_items_reads_every_push_form() {
        let s = [
            0x00, 0x51, 0x60, 0x4f, 0x01, 0xaa, 0x4c, 0x01, 0xbb, 0x4d, 0x01, 0x00, 0xcc,
        ];
        assert_eq!(
            stack_items(&s).unwrap(),
            vec![
                vec![],
                vec![1],
                vec![16],
                vec![0x81],
                vec![0xaa],
                vec![0xbb],
                vec![0xcc]
            ]
        );
        assert_eq!(stack_items(&[0x76]), None);
        assert_eq!(stack_items(&[0x02, 0x01]), None);
    }
}
