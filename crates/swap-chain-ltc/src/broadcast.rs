// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Posting one transaction to the primary and the secondary Esplora (`[ltc].dual_broadcast`).
//!
//! Rule (single-source-design.md section 5, broadcast row; as `swap-chain-btc`'s): a primary
//! that drops or refuses a claim must not keep it off the network, so both endpoints get every POST. Either one
//! accepting it (Esplora answers our txid; `POST /tx` in single-source-design.FACTS.md), or
//! reporting it already known, is a broadcast; the other is logged at WARN with both
//! endpoints named. A 200 that names another txid has not taken our transaction. With
//! neither accepting, a node refusal is returned before another txid, and that before an
//! unreachable endpoint (primary first in each), so a refund's `Premature` still reaches the
//! engine; the message names both endpoints and their answers.

use divi_swap::{SignedTx, SwapError};

use crate::client::{ClientError, EsploraClient};
use crate::{classify_broadcast_error, is_already_known};

/// One endpoint's answer to `POST /tx`.
enum Posted {
    Accepted,
    /// 2xx naming another transaction.
    OtherTxid(String),
    /// 4xx: the node's reject reason.
    Refused(String),
    /// Network error, 5xx or 429 on every attempt.
    Unreachable(String),
}

impl Posted {
    fn describe(&self, ours: &str) -> String {
        match self {
            Posted::Accepted => "accepted".into(),
            Posted::OtherTxid(t) => format!("answered txid {t}, ours is {ours}"),
            Posted::Refused(b) => format!("refused: {}", b.trim()),
            Posted::Unreachable(m) => format!("unreachable: {m}"),
        }
    }
}

async fn post_on(es: &EsploraClient, tx: &SignedTx) -> Posted {
    match es.post("/tx", hex::encode(&tx.raw)).await {
        Ok(body) => {
            let got = body.trim().to_ascii_lowercase();
            if got == tx.txid.to_rpc_hex() {
                Posted::Accepted
            } else {
                Posted::OtherTxid(got)
            }
        }
        Err(ClientError::Http(f)) if is_already_known(&f.body) => Posted::Accepted,
        Err(ClientError::Http(f)) => Posted::Refused(f.body),
        Err(ClientError::Transient(m)) => Posted::Unreachable(m),
    }
}

/// Neither endpoint accepted the transaction.
pub(crate) struct NotPosted {
    /// A refusal said its inputs are missing or spent: the caller checks whether the
    /// transaction itself is already on chain, as the single-endpoint path does.
    pub missing_or_spent: bool,
    pub err: SwapError,
}

/// POST `tx` to `primary` and `secondary` at once.
pub(crate) async fn post_both(
    primary: &EsploraClient,
    secondary: &EsploraClient,
    tx: &SignedTx,
) -> Result<(), NotPosted> {
    let (a, b) = tokio::join!(post_on(primary, tx), post_on(secondary, tx));
    let ours = tx.txid.to_rpc_hex();
    let answers = [(primary.primary_url(), a), (secondary.primary_url(), b)];
    let detail = answers
        .iter()
        .map(|(url, p)| format!("{url}: {}", p.describe(&ours)))
        .collect::<Vec<_>>()
        .join("; ");
    if answers.iter().any(|(_, p)| matches!(p, Posted::Accepted)) {
        if answers.iter().any(|(_, p)| !matches!(p, Posted::Accepted)) {
            tracing::warn!(txid = %ours, "broadcast taken by one Esplora endpoint only: {detail}");
        }
        return Ok(());
    }
    let missing_or_spent = answers.iter().any(
        |(_, p)| matches!(p, Posted::Refused(b) if b.to_ascii_lowercase().contains("missingorspent")),
    );
    let refused = answers.iter().find_map(|(_, p)| match p {
        Posted::Refused(b) => Some(b),
        _ => None,
    });
    let other_txid = answers
        .iter()
        .any(|(_, p)| matches!(p, Posted::OtherTxid(_)));
    let err = match refused {
        // The node's own classification, with both endpoints' answers as the message.
        Some(body) => match classify_broadcast_error(body) {
            SwapError::Premature(_) => SwapError::Premature(detail),
            _ => SwapError::Rejected(detail),
        },
        None if other_txid => SwapError::Other(detail),
        None => SwapError::Transient(detail),
    };
    Err(NotPosted {
        missing_or_spent,
        err,
    })
}
