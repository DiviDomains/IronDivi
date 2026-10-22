// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `Debug` for the persisted XMR swap records, written by hand so a stray `{:?}` never
//! prints a per-swap secret (`divi_key`, `s_m`, `s_t`, `view_secret`, `swap_token`).
//! Every field is listed in a destructuring pattern, so a field added to a record without
//! a decision here fails to compile. Serialization is untouched.

use std::fmt;

use crate::maker::XmrMakerRecord;
use crate::taker::XmrTakerRecord;

const REDACTED: &str = "<redacted>";

/// `Some("<redacted>")` / `None`: shows whether a secret is present, never its value.
fn opt(v: &Option<String>) -> Option<&'static str> {
    v.as_ref().map(|_| REDACTED)
}

impl fmt::Debug for XmrMakerRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let XmrMakerRecord {
            id,
            swap_token: _,
            created_at,
            state,
            quote,
            divi_key: _,
            s_m: _,
            view_secret: _,
            taker_pk,
            taker_payout,
            x_point: _,
            taker_share: _,
            xmr_amount,
            j_sid,
            joint_pk,
            redeem_script,
            cancel_redeem,
            tx_lock,
            lock_actual,
            lock_vout,
            lock_amount,
            t_cancel,
            t_punish,
            t_late,
            tx_cancel,
            cancel_sig,
            refund_script,
            cancel_signed,
            cancel_actual,
            taker_cancel_sig,
            refund_encsigs,
            xmr_txid,
            tx_redeem,
            redeem_encsig,
            s_t,
            sweep_txid,
            refund_signed,
            late_signed,
            last_error,
        } = self;
        f.debug_struct("XmrMakerRecord")
            .field("id", id)
            .field("swap_token", &REDACTED)
            .field("created_at", created_at)
            .field("state", state)
            .field("quote", quote)
            .field("divi_key", &REDACTED)
            .field("s_m", &REDACTED)
            .field("view_secret", &REDACTED)
            .field("taker_pk", &hex::encode(taker_pk))
            .field("taker_payout", &hex::encode(taker_payout))
            .field("x_point", &"<point>")
            .field("taker_share", &"<point>")
            .field("xmr_amount", xmr_amount)
            .field("j_sid", &hex::encode(j_sid))
            .field("joint_pk", &hex::encode(joint_pk))
            .field("redeem_script", &hex::encode(redeem_script))
            .field("cancel_redeem", &hex::encode(cancel_redeem))
            .field("tx_lock", &tx_lock.txid())
            .field("lock_actual", &lock_actual.as_ref().map(|t| t.txid()))
            .field("lock_vout", lock_vout)
            .field("lock_amount", lock_amount)
            .field("t_cancel", t_cancel)
            .field("t_punish", t_punish)
            .field("t_late", t_late)
            .field("tx_cancel", &tx_cancel.txid())
            .field("cancel_sig", &hex::encode(cancel_sig))
            .field("refund_script", &hex::encode(refund_script))
            .field("cancel_signed", &cancel_signed.as_ref().map(|t| t.txid()))
            .field("cancel_actual", &cancel_actual.as_ref().map(|t| t.txid()))
            .field("taker_cancel_sig", taker_cancel_sig)
            .field("refund_encsigs", refund_encsigs)
            .field("xmr_txid", xmr_txid)
            .field("tx_redeem", &tx_redeem.as_ref().map(|t| t.txid()))
            .field("redeem_encsig", redeem_encsig)
            .field("s_t", &opt(s_t))
            .field("sweep_txid", sweep_txid)
            .field("refund_signed", &refund_signed.as_ref().map(|t| t.txid()))
            .field("late_signed", &late_signed.as_ref().map(|t| t.txid()))
            .field("last_error", last_error)
            .finish()
    }
}

impl fmt::Debug for XmrTakerRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let XmrTakerRecord {
            id,
            state,
            quote,
            divi_key: _,
            s_t: _,
            prepare_mtp,
            payout_script,
            j_sid,
            setup,
            cancel_sig,
            refund_encsigs,
            cancel_actual,
            xmr_txid,
            redeem_signed,
            punish_signed,
            s_m,
            sweep_txid,
            outcome,
            last_error,
        } = self;
        f.debug_struct("XmrTakerRecord")
            .field("id", id)
            .field("state", state)
            .field("quote", quote)
            .field("divi_key", &REDACTED)
            .field("s_t", &REDACTED)
            .field("prepare_mtp", prepare_mtp)
            .field("payout_script", &hex::encode(payout_script))
            .field("j_sid", &hex::encode(j_sid))
            .field("setup", setup)
            .field("cancel_sig", cancel_sig)
            .field("refund_encsigs", refund_encsigs)
            .field("cancel_actual", &cancel_actual.as_ref().map(|t| t.txid()))
            .field("xmr_txid", xmr_txid)
            .field("redeem_signed", &redeem_signed.as_ref().map(|t| t.txid()))
            .field("punish_signed", &punish_signed.as_ref().map(|t| t.txid()))
            .field("s_m", &opt(s_m))
            .field("sweep_txid", sweep_txid)
            .field("outcome", outcome)
            .field("last_error", last_error)
            .finish()
    }
}
