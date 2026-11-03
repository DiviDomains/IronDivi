// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Calls the node answered, for `rpc-methods.log` (diag plan A15)
//!
//! Each transport's request handler calls [`begin`] when a call starts and
//! [`Call::finish`] when it returns. The call sits in a fixed in-flight
//! table meanwhile, which [`in_flight`] reads without a lock (the A17
//! watchdog, `getdiaginfo`). On finish the call goes to the one [`Sink`]
//! the node binary installs. Never a parameter: the method name, the
//! transport, the caller's address and the result code only, plus the
//! error text, which the sink masks before keeping it.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

/// Where a call came in
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    JsonRpc = 1,
    Electrum = 2,
    WebUi = 3,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::JsonRpc => "jsonrpc",
            Transport::Electrum => "electrum",
            Transport::WebUi => "webui",
        }
    }

    fn from_u8(v: u8) -> Option<Transport> {
        match v {
            1 => Some(Transport::JsonRpc),
            2 => Some(Transport::Electrum),
            3 => Some(Transport::WebUi),
            _ => None,
        }
    }
}

/// One finished call, borrowed from the handler
#[derive(Debug)]
pub struct Done<'a> {
    pub method: &'a str,
    pub transport: Transport,
    /// The caller's address, when the transport knows it
    pub caller: Option<IpAddr>,
    /// Authenticated (a JSON-RPC password or cookie, a signed-in Web UI);
    /// a remote caller that is not is treated as public
    pub authenticated: bool,
    /// The error code and message, or None for success
    pub error: Option<(i64, &'a str)>,
    pub micros: u64,
}

/// The writer the node installs
pub type Sink = Box<dyn Fn(&Done<'_>) + Send + Sync>;

static SINK: OnceLock<Sink> = OnceLock::new();

/// Install the sink; only the first call takes effect
pub fn install(sink: Sink) -> bool {
    SINK.set(sink).is_ok()
}

/// The store of transactions submitted from here (A15 "sent from here")
pub type SentSink = Box<dyn Fn(&crate::hash::Hash256) + Send + Sync>;

static SENT: OnceLock<SentSink> = OnceLock::new();

thread_local! {
    static REMOTE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Install the sent-from-here store; only the first call takes effect
pub fn install_sent(sink: SentSink) -> bool {
    SENT.set(sink).is_ok()
}

/// Run `f` on this thread as a remote caller's request (a public
/// Electrum client): what it submits is not "sent from here"
pub fn as_remote<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            REMOTE.with(|r| r.set(self.0));
        }
    }
    let _reset = Reset(REMOTE.with(|r| r.replace(true)));
    f()
}

/// Whether this thread is running a remote caller's request
pub fn is_remote() -> bool {
    REMOTE.with(|r| r.get())
}

/// A transaction submitted for broadcast, accepted or not: recorded as
/// sent from here unless a remote caller sent it
pub fn sent(txid: &crate::hash::Hash256) {
    if is_remote() {
        return;
    }
    if let Some(sink) = SENT.get() {
        sink(txid);
    }
}

/// In-flight slots; a call that finds them all taken is still counted,
/// just not listed as in flight
const SLOTS: usize = 64;
/// Bytes of a method name kept in a slot (longer names are cut)
const NAME: usize = 32;
/// A slot being written
const BUSY: u64 = u64::MAX;

struct Slot {
    /// Milliseconds since [`epoch`] the call started, plus one; 0 is free
    start: AtomicU64,
    transport: AtomicU8,
    name: [AtomicU64; NAME / 8],
}

#[allow(clippy::declare_interior_mutable_const)]
const FREE: Slot = Slot {
    start: AtomicU64::new(0),
    transport: AtomicU8::new(0),
    name: [const { AtomicU64::new(0) }; NAME / 8],
};

static TABLE: [Slot; SLOTS] = [FREE; SLOTS];

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn now_ms() -> u64 {
    epoch().elapsed().as_millis() as u64
}

/// A call in progress; [`Call::finish`] reports it (a call dropped
/// without finishing, a handler that panicked, is only cleared)
pub struct Call {
    slot: Option<usize>,
    started: Instant,
}

/// The name a call is recorded under: a caller can send any text as a
/// method, so a name that is not a plain method name, or one the node did
/// not know (-32601), is `unknown`
pub fn name<'a>(method: &'a str, error: Option<(i64, &str)>) -> &'a str {
    let plain = !method.is_empty()
        && method.len() <= 64
        && method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_');
    if plain && !matches!(error, Some((-32601, _))) {
        method
    } else {
        "unknown"
    }
}

/// A call starts
pub fn begin(method: &str, transport: Transport) -> Call {
    let method = name(method, None);
    let started = Instant::now();
    let mut slot = None;
    for (i, s) in TABLE.iter().enumerate() {
        if s.start
            .compare_exchange(0, BUSY, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let mut bytes = [0u8; NAME];
            let n = method.len().min(NAME);
            bytes[..n].copy_from_slice(&method.as_bytes()[..n]);
            for (w, chunk) in s.name.iter().zip(bytes.chunks(8)) {
                w.store(
                    u64::from_le_bytes(chunk.try_into().unwrap_or_default()),
                    Ordering::Relaxed,
                );
            }
            s.transport.store(transport as u8, Ordering::Relaxed);
            s.start.store(now_ms() + 1, Ordering::Release);
            slot = Some(i);
            break;
        }
    }
    Call { slot, started }
}

impl Call {
    /// The call returned
    pub fn finish(
        mut self,
        method: &str,
        transport: Transport,
        caller: Option<IpAddr>,
        authenticated: bool,
        error: Option<(i64, &str)>,
    ) {
        let micros = self.started.elapsed().as_micros() as u64;
        self.clear();
        if let Some(sink) = SINK.get() {
            sink(&Done {
                method: name(method, error),
                transport,
                caller,
                authenticated,
                error,
                micros,
            });
        }
    }

    fn clear(&mut self) {
        if let Some(i) = self.slot.take() {
            TABLE[i].start.store(0, Ordering::Release);
        }
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        self.clear();
    }
}

/// A call in flight: method, transport, milliseconds since it started
#[derive(Debug, Clone, PartialEq)]
pub struct InFlight {
    pub method: String,
    pub transport: Transport,
    pub for_ms: u64,
}

/// The calls in flight now, read without a lock; a slot that changed
/// while it was read is left out
pub fn in_flight() -> Vec<InFlight> {
    let now = now_ms();
    let mut out = Vec::new();
    for s in TABLE.iter() {
        let start = s.start.load(Ordering::Acquire);
        if start == 0 || start == BUSY {
            continue;
        }
        let mut bytes = Vec::with_capacity(NAME);
        for w in &s.name {
            bytes.extend_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
        }
        let transport = Transport::from_u8(s.transport.load(Ordering::Relaxed));
        if s.start.load(Ordering::Acquire) != start {
            continue;
        }
        let Some(transport) = transport else {
            continue;
        };
        let len = bytes.iter().position(|b| *b == 0).unwrap_or(NAME);
        out.push(InFlight {
            method: String::from_utf8_lossy(&bytes[..len]).into_owned(),
            transport,
            for_ms: now.saturating_sub(start - 1),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_is_in_flight_until_it_returns() {
        let call = begin(
            "a_test_method_name_longer_than_32_bytes",
            Transport::Electrum,
        );
        let listed = in_flight();
        let mine: Vec<_> = listed
            .iter()
            .filter(|c| c.method.starts_with("a_test_method"))
            .collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].method.len(), NAME);
        assert_eq!(mine[0].transport, Transport::Electrum);
        call.finish("x", Transport::Electrum, None, false, None);
        assert_eq!(name("getinfo", None), "getinfo");
        assert_eq!(name("getinfo", Some((-32601, "x"))), "unknown");
        assert_eq!(name("get info\n", None), "unknown");
        assert!(!in_flight()
            .iter()
            .any(|c| c.method.starts_with("a_test_method")));
        // Dropped without finishing (a panic): cleared too
        let call = begin("b_test", Transport::WebUi);
        drop(call);
        assert!(!in_flight().iter().any(|c| c.method == "b_test"));
    }

    #[test]
    fn a_remote_callers_broadcast_is_not_sent_from_here() {
        assert!(!REMOTE.with(|r| r.get()));
        let inner = as_remote(|| as_remote(|| REMOTE.with(|r| r.get())));
        assert!(inner);
        assert!(!REMOTE.with(|r| r.get()));
    }
}
