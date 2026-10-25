// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Divi Core's AbortNode (ValidationState.cpp:17-27): a write the node cannot
//! make, a block, its undo data, the coins or an index (ChainExtensionService.cpp:513-518,
//! BlockConnectionService.cpp:111-192, FlushChainState.cpp:37-58), stops the
//! node. The message goes to the log as `*** <message>`, and the handler the
//! daemon registered starts its shutdown, once.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

type Handler = Box<dyn Fn(&str) + Send + Sync>;

static HANDLER: OnceLock<Handler> = OnceLock::new();
static ABORTED: AtomicBool = AtomicBool::new(false);

/// What runs when the node aborts (the daemon: start the shutdown). Set once;
/// later calls are ignored.
pub fn set_handler(handler: Handler) {
    let _ = HANDLER.set(handler);
}

/// Stop the node: log `*** <message>` and run the handler, the first time only
pub fn abort_node(message: &str) {
    tracing::error!("*** {}", message);
    if !ABORTED.swap(true, Ordering::SeqCst) {
        if let Some(handler) = HANDLER.get() {
            handler(message);
        }
    }
}

/// True once the node has aborted
pub fn aborted() -> bool {
    ABORTED.load(Ordering::SeqCst)
}
