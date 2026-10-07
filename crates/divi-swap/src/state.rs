// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Maker-side swap states (plan §3.2).
//!
//! ```text
//! Quoted → Accepted → TakerLockSeen → TakerLockConfirmed → MakerLocked → MakerLockConfirmed →
//!   { TakerClaimed → MakerClaimed → Done | MakerRefundable → MakerRefunded → Done }
//! Quoted / Accepted / TakerLockSeen → Aborted   (taker never locked, or lock invalid)
//! ```
//! `MakerLocked` means "funding tx built and persisted"; broadcast follows (write-ahead).
//! The preimage learned in `TakerClaimed` is stored on the swap record, not in the enum.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Maker-side swap state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwapState {
    /// Quote issued, not yet accepted (expires after 60 s).
    Quoted,
    /// Taker accepted; maker waits for the taker's BTC lock.
    Accepted,
    /// Taker's lock is visible (mempool or < required confirmations) and matches the HTLC.
    TakerLockSeen,
    /// Taker's lock has the required confirmations. Still **no** maker coins reserved.
    TakerLockConfirmed,
    /// Maker funding tx built (coin selection happened here) and persisted; broadcast next.
    MakerLocked,
    /// Maker's DIVI lock has the required confirmations; waiting for the taker to claim.
    MakerLockConfirmed,
    /// Taker claimed the DIVI; the preimage is known.
    TakerClaimed,
    /// Maker claimed the BTC.
    MakerClaimed,
    /// Maker's lock timed out without a claim; refund is (about to be) valid.
    MakerRefundable,
    /// Maker's refund confirmed.
    MakerRefunded,
    /// Ended before the maker locked anything. Terminal.
    Aborted,
    /// Finished (claimed or refunded). Terminal.
    Done,
}

impl SwapState {
    /// Every state, in pipeline order.
    pub const ALL: [SwapState; 12] = [
        SwapState::Quoted,
        SwapState::Accepted,
        SwapState::TakerLockSeen,
        SwapState::TakerLockConfirmed,
        SwapState::MakerLocked,
        SwapState::MakerLockConfirmed,
        SwapState::TakerClaimed,
        SwapState::MakerClaimed,
        SwapState::MakerRefundable,
        SwapState::MakerRefunded,
        SwapState::Aborted,
        SwapState::Done,
    ];

    /// No further transitions.
    pub fn is_terminal(self) -> bool {
        matches!(self, SwapState::Done | SwapState::Aborted)
    }

    /// Whether the maker may hold DIVI coins for this swap in this state. Coin selection
    /// happens on the `TakerLockConfirmed → MakerLocked` edge and never earlier.
    pub fn maker_coins_reserved(self) -> bool {
        matches!(
            self,
            SwapState::MakerLocked
                | SwapState::MakerLockConfirmed
                | SwapState::TakerClaimed
                | SwapState::MakerClaimed
                | SwapState::MakerRefundable
                | SwapState::MakerRefunded
        )
    }

    /// The allowed transition table.
    pub fn can_transition_to(self, next: SwapState) -> bool {
        use SwapState::*;
        matches!(
            (self, next),
            (Quoted, Accepted)
                | (Quoted, Aborted)
                | (Accepted, TakerLockSeen)
                | (Accepted, Aborted)
                | (TakerLockSeen, TakerLockConfirmed)
                | (TakerLockSeen, Aborted)
                | (TakerLockConfirmed, MakerLocked)
                | (TakerLockConfirmed, Aborted)
                | (MakerLocked, MakerLockConfirmed)
                | (MakerLocked, MakerRefundable)
                | (MakerLockConfirmed, TakerClaimed)
                | (MakerLockConfirmed, MakerRefundable)
                | (MakerRefundable, TakerClaimed)
                | (MakerRefundable, MakerRefunded)
                | (TakerClaimed, MakerClaimed)
                | (MakerClaimed, Done)
                | (MakerRefunded, Done)
        )
    }

    /// Stable name used in the database and the HTTP API.
    pub fn as_str(self) -> &'static str {
        use SwapState::*;
        match self {
            Quoted => "quoted",
            Accepted => "accepted",
            TakerLockSeen => "taker_lock_seen",
            TakerLockConfirmed => "taker_lock_confirmed",
            MakerLocked => "maker_locked",
            MakerLockConfirmed => "maker_lock_confirmed",
            TakerClaimed => "taker_claimed",
            MakerClaimed => "maker_claimed",
            MakerRefundable => "maker_refundable",
            MakerRefunded => "maker_refunded",
            Aborted => "aborted",
            Done => "done",
        }
    }
}

impl fmt::Display for SwapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SwapState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SwapState::ALL
            .into_iter()
            .find(|st| st.as_str() == s)
            .ok_or_else(|| format!("unknown swap state {s:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for s in SwapState::ALL {
            assert_eq!(s.as_str().parse::<SwapState>().unwrap(), s);
        }
    }

    #[test]
    fn no_coins_before_maker_locked() {
        use SwapState::*;
        for s in [Quoted, Accepted, TakerLockSeen, TakerLockConfirmed, Aborted] {
            assert!(!s.maker_coins_reserved(), "{s}");
        }
        // The only way into a coins-reserved state from a non-reserved one is via
        // TakerLockConfirmed → MakerLocked.
        for a in SwapState::ALL {
            for b in SwapState::ALL {
                if a.can_transition_to(b) && !a.maker_coins_reserved() && b.maker_coins_reserved() {
                    assert_eq!((a, b), (TakerLockConfirmed, MakerLocked));
                }
            }
        }
    }

    #[test]
    fn terminal_states_have_no_exits() {
        for a in SwapState::ALL.into_iter().filter(|s| s.is_terminal()) {
            assert!(SwapState::ALL.iter().all(|b| !a.can_transition_to(*b)));
        }
    }
}
