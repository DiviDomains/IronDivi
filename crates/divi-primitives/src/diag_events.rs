// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Chain events the node records in `chain-events.log` (diag plan A12)
//!
//! The library crates that see an invalid block, a refused relayed
//! transaction or a ban call [`emit`]; the node binary installs the one
//! [`Sink`] at start that formats and writes them (and decides which are
//! the wallet's own and so are not written). With no sink installed (tests,
//! tools) an event costs a load and a branch. The same events carry what
//! the A13 replay bundles keep (the block, the message bytes).

use crate::{Block, Hash256, Transaction};
use std::net::IpAddr;
use std::sync::OnceLock;

/// One chain event, borrowed from the caller
#[derive(Debug)]
pub enum Event<'a> {
    /// A block refused with a misbehaviour score (`height` when its parent
    /// is known; `peer` when the block's source is still known)
    InvalidBlock {
        hash: Hash256,
        height: Option<u32>,
        reason: &'a str,
        peer: Option<IpAddr>,
        /// The block, when the caller still holds it (A13)
        block: Option<&'a Block>,
        /// The error's variant, the code path that refused it (A13)
        code: &'a str,
    },
    /// A transaction a peer relayed that the mempool refused with a reject
    /// message (not a missing-inputs orphan, not one already held)
    RejectedTx {
        txid: Hash256,
        tx: &'a Transaction,
        reason: &'a str,
    },
    /// An address banned, for misbehaviour or by `setban`
    Ban { ip: IpAddr, reason: &'a str },
    /// A P2P message that did not parse, or that added misbehaviour score
    /// (A13 `bad-messages/`). Not a `chain-events.log` record.
    BadMessage {
        peer: Option<IpAddr>,
        /// The command, when known (a score is added without it)
        command: &'a str,
        /// The start of the payload, when held (at most [`MESSAGE_HEAD`])
        head: &'a [u8],
        /// The parse error, or the cause the score was added for
        error: &'a str,
        /// The score added; 0 for a parse failure
        score: u32,
    },
    /// A block this node staked that its own chain refused (A13
    /// `own-invalid/`). Not a `chain-events.log` record: no line names it.
    OwnBlockRejected {
        block: &'a Block,
        reason: &'a str,
        code: &'a str,
    },
    /// A transaction a local caller submitted that the node refused (A13
    /// `own-invalid/`, A15 "sent from here"). Not a `chain-events.log`
    /// record.
    OwnTxRejected {
        txid: Hash256,
        tx: &'a Transaction,
        reason: &'a str,
    },
}

/// The bytes of a message kept for `bad-messages/`
pub const MESSAGE_HEAD: usize = 4096;

/// The variant name of an error's `Debug` form, its code path: `Foo` of
/// `Foo { .. }` or `Foo(..)`
pub fn code_of(debug: &str) -> &str {
    let end = debug
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(debug.len());
    &debug[..end]
}

/// The writer the node installs
pub type Sink = Box<dyn Fn(&Event<'_>) + Send + Sync>;

static SINK: OnceLock<Sink> = OnceLock::new();

/// Install the sink; only the first call takes effect
pub fn install(sink: Sink) -> bool {
    SINK.set(sink).is_ok()
}

/// Hand an event to the sink, if there is one
pub fn emit(event: &Event<'_>) {
    if let Some(sink) = SINK.get() {
        sink(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_is_the_variant_name() {
        assert_eq!(code_of("InvalidBlock(\"bad\")"), "InvalidBlock");
        assert_eq!(code_of("UtxoNotFound { txid: 1 }"), "UtxoNotFound");
        assert_eq!(code_of("Orphan"), "Orphan");
        assert_eq!(code_of(""), "");
    }
}
