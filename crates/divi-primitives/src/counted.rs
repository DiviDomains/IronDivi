//! Counters for the A11 counted sites.
//!
//! A counted site writes no log line of its own: an own staked block, an own
//! transaction or a wallet change would stand out by its line, its time and
//! its order next to a peer's. The site bumps its counter instead, and the
//! node writes one count line per site every hour, zeros included, in one
//! fixed format (`irondivid::counts`). The keys are stable short names, never
//! line numbers or values, so a count line says how often, never what.
//!
//! The counters are `AtomicU32`, lock-free on every target the node builds,
//! so a signal handler can copy them with plain loads.

use std::sync::atomic::{AtomicU32, Ordering};

macro_rules! sites {
    ($($id:ident = $key:literal,)*) => {
        /// A counted site
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Site {
            $($id,)*
        }

        /// The key of each site, in `Site` order
        pub const KEYS: &[&str] = &[$($key,)*];

        impl Site {
            /// Every site, in order
            pub const ALL: &[Site] = &[$(Site::$id,)*];
        }
    };
}

sites! {
    // The staker (A11 "Staker default-deny"; staker.rs)
    StakerStaked = "staker.staked",
    StakerNoUtxos = "staker.no-utxos",
    StakerNoProof = "staker.no-proof",
    StakerRateLimited = "staker.rate-limited",
    StakerRatePassed = "staker.rate-passed",
    StakerFirstAtHeight = "staker.first-at-height",
    StakerErrorNoTip = "staker.error.no-tip",
    StakerErrorDifficulty = "staker.error.difficulty",
    StakerSelfAcceptFailed = "staker.self-accept.failed",
    StakerSelfAcceptReorg = "staker.self-accept.reorg",
    StakerPhantomEvicted = "staker.phantom-evicted",
    StakerPhantomSaveFailed = "staker.phantom-save-failed",
    StakerReserveLimited = "staker.reserve-limited",
    StakerVaultUtxos = "staker.vault-utxos",
    StakerAttempt = "staker.attempt",
    StakerModifierMismatch = "staker.modifier-mismatch",
    StakerHashproofOk = "staker.hashproof-ok",
    StakerUtxoNoProof = "staker.utxo-no-proof",
    StakerUtxoSetupFailed = "staker.utxo-setup-failed",
    StakerMtpSkip = "staker.mtp-skip",
    StakerStakeFound = "staker.stake-found",
    StakerCreateFailed = "staker.create-failed",
    StakerNoBlockIndex = "staker.no-block-index",
    StakerLotteryBlock = "staker.lottery-block",
    StakerLotteryNoWinners = "staker.lottery-no-winners",
    StakerTreasuryBlock = "staker.treasury-block",
    StakerSign = "staker.sign",
    StakerSignMismatch = "staker.sign.mismatch",
    StakerSignRecoverFailed = "staker.sign.recover-failed",
    StakerVaultSign = "staker.vault-sign",
    StakerVaultSignMismatch = "staker.vault-sign.mismatch",
    StakerVaultCoinstake = "staker.vault-coinstake",
    StakerCoinstakeCombine = "staker.coinstake-combine",
    StakerBlockRewards = "staker.block-rewards",
    // The wallet's connect path (A11 "Wallet lines on the connect path";
    // wallet_db.rs)
    WalletSave = "wallet.save",
    WalletUtxoAdded = "wallet.utxo-added",
    WalletUtxoSpent = "wallet.utxo-spent",
    WalletSpentPersistFailed = "wallet.spent-persist-failed",
    WalletTxAdded = "wallet.tx-added",
    WalletReceived = "wallet.received",
    WalletSpent = "wallet.spent",
    WalletTx = "wallet.tx",
    WalletForgetFailed = "wallet.forget-failed",
    WalletMempoolDropped = "wallet.mempool-dropped",
    WalletRollback = "wallet.rollback",
    WalletRollbackRemoveFailed = "wallet.rollback.remove-failed",
    WalletRollbackRestored = "wallet.rollback.restored",
    WalletRollbackHeights = "wallet.rollback.heights",
    // The mempool (connect path and transaction path; mempool.rs, node.rs)
    MempoolAdded = "mempool.added",
    MempoolRemoved = "mempool.removed",
    MempoolNonFinal = "mempool.non-final",
    MempoolUnspendable = "mempool.unspendable",
    MempoolConflict = "mempool.conflict",
    MempoolReorgNotReturned = "mempool.reorg-not-returned",
    // Transaction relay (A11 "Own transactions log like peer transactions";
    // relay.rs)
    RelayInv = "relay.inv",
    RelayRequested = "relay.requested",
    RelayAlreadyHave = "relay.already-have",
    RelayGetdataNotTx = "relay.getdata.not-tx",
    RelayGetdataMissing = "relay.getdata.missing",
    RelayInvSendFailed = "relay.inv-send-failed",
    // The own-only send lines of the RPC wallet (divi-rpc wallet.rs)
    RpcSent = "rpc.sent",
    RpcVaultFunded = "rpc.vault-funded",
    RpcAllocated = "rpc.allocated",
    RpcSentFrom = "rpc.sent-from",
}

/// How many sites there are
pub const COUNT: usize = KEYS.len();

/// One counter per site
pub struct Counters([AtomicU32; COUNT]);

impl Counters {
    pub const fn new() -> Counters {
        Counters([const { AtomicU32::new(0) }; COUNT])
    }

    /// Count `n` more at `site`
    pub fn add(&self, site: Site, n: u32) {
        self.0[site as usize].fetch_add(n, Ordering::Relaxed);
    }

    /// The count at site index `i` since the last `take`, without resetting
    /// it: a plain atomic load, safe in a signal handler
    pub fn load(&self, i: usize) -> u32 {
        self.0[i].load(Ordering::Relaxed)
    }

    /// Every count since the last `take`, each reset to zero in the same
    /// atomic step, so a count made meanwhile goes to the next hour
    pub fn take(&self) -> [u32; COUNT] {
        std::array::from_fn(|i| self.0[i].swap(0, Ordering::Relaxed))
    }
}

impl Default for Counters {
    fn default() -> Self {
        Counters::new()
    }
}

/// The node's counters
pub static COUNTERS: Counters = Counters::new();

/// Count one more at `site`
pub fn hit(site: Site) {
    COUNTERS.add(site, 1);
}

/// Count `n` more at `site`
pub fn add(site: Site, n: usize) {
    COUNTERS.add(site, u32::try_from(n).unwrap_or(u32::MAX));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_short_and_plain() {
        let mut seen = std::collections::HashSet::new();
        for key in KEYS {
            assert!(seen.insert(*key), "duplicate key {}", key);
            assert!(key.len() <= 40, "{}", key);
            assert!(
                key.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'-'),
                "{}",
                key
            );
        }
        assert_eq!(KEYS[Site::StakerStaked as usize], "staker.staked");
        assert_eq!(KEYS[Site::RpcSentFrom as usize], "rpc.sent-from");
        for (i, site) in Site::ALL.iter().enumerate() {
            assert_eq!(*site as usize, i);
        }
    }

    #[test]
    fn take_returns_and_resets() {
        let c = Counters::new();
        c.add(Site::MempoolAdded, 1);
        c.add(Site::MempoolAdded, 2);
        c.add(Site::WalletTx, 5);
        assert_eq!(c.load(Site::MempoolAdded as usize), 3);
        // A load leaves the count in place
        assert_eq!(c.load(Site::MempoolAdded as usize), 3);
        let t = c.take();
        assert_eq!(t[Site::MempoolAdded as usize], 3);
        assert_eq!(t[Site::WalletTx as usize], 5);
        assert_eq!(t.iter().map(|&n| n as u64).sum::<u64>(), 8);
        assert!(c.take().iter().all(|&n| n == 0));
    }
}
