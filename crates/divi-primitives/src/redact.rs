//! Wallet-linked values in log lines (diag plan A11)
//!
//! A value that says what this wallet did (a txid it sent, an address it
//! owns, an amount, a label, an outpoint it stakes, a block it staked, a
//! swap) is wrapped in one of the types below before it reaches a log
//! macro. Their `Display` and `Debug` print a per-run pseudonym: an
//! HMAC-SHA256 of the value under a random key that exists only in this
//! process's memory, so the same value reads the same within one run and
//! cannot be linked across runs or reversed. Amounts print their order of
//! magnitude only.
//!
//! `-logwalletdetail=1` (start only) makes them print the real values, for
//! the user's own debugging; [`set_wallet_detail`] is called once at start.
//!
//! The types are for wallet context only. A value that appears as an entry
//! of a public record (a tip hash, a txid in a block or the mempool, a
//! payee in a winners list) is printed with its public type whatever its
//! owner, so ownership never changes how a public entry is printed.

use crate::{Hash256, OutPoint};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

static DETAIL: AtomicBool = AtomicBool::new(false);
static KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// Print real values instead of pseudonyms (`-logwalletdetail=1`); set once
/// at start, before the first log line
pub fn set_wallet_detail(on: bool) {
    DETAIL.store(on, Ordering::SeqCst);
}

/// Whether wallet values print in clear in this run
pub fn wallet_detail() -> bool {
    DETAIL.load(Ordering::Relaxed)
}

/// The run's key: 32 bytes from the OS, read once
fn key() -> &'static [u8; 32] {
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        if !os_random(&mut k) {
            // No /dev/urandom (Windows): std's per-process random hash keys,
            // which come from the OS, mixed with the time and the pid
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hasher};
            let mut h = Sha256::new();
            for i in 0..8u64 {
                let mut s = RandomState::new().build_hasher();
                s.write_u64(i);
                h.update(s.finish().to_le_bytes());
            }
            h.update(std::process::id().to_le_bytes());
            if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                h.update(d.as_nanos().to_le_bytes());
            }
            k.copy_from_slice(&h.finalize());
        }
        k
    })
}

#[cfg(unix)]
fn os_random(out: &mut [u8; 32]) -> bool {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(out))
        .is_ok()
}

#[cfg(not(unix))]
fn os_random(_out: &mut [u8; 32]) -> bool {
    false
}

/// HMAC-SHA256 (RFC 2104) of `tag`, a zero byte and `data` under the run key
fn mac(tag: &str, data: &[u8]) -> [u8; 32] {
    let key = key();
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(tag.as_bytes())
        .chain_update([0u8])
        .chain_update(data)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::new().chain_update(opad).chain_update(inner).finalize());
    out
}

/// `<prefix>-<8 hex>`: the first four bytes of the value's HMAC
fn pseudonym(f: &mut fmt::Formatter<'_>, prefix: &str, data: &[u8]) -> fmt::Result {
    let m = mac(prefix, data);
    write!(f, "{}-{:02x}{:02x}{:02x}{:02x}", prefix, m[0], m[1], m[2], m[3])
}

macro_rules! both {
    ($t:ident < $l:lifetime >) => {
        impl<$l> fmt::Debug for $t<$l> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }
    };
    ($t:ident) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }
    };
}

/// A txid this wallet sent, received or holds: `wtx-xxxxxxxx`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WalletTxid(pub Hash256);

impl fmt::Display for WalletTxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wallet_detail() {
            return fmt::Display::fmt(&self.0, f);
        }
        pseudonym(f, "wtx", self.0.as_bytes())
    }
}
both!(WalletTxid);

/// An address of this wallet, or one it paid: `wad-xxxxxxxx`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WalletAddress<'a>(pub &'a str);

impl fmt::Display for WalletAddress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wallet_detail() {
            return f.write_str(self.0);
        }
        pseudonym(f, "wad", self.0.as_bytes())
    }
}
both!(WalletAddress<'a>);

/// A label or account name: `wlb-xxxxxxxx`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WalletLabel<'a>(pub &'a str);

impl fmt::Display for WalletLabel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wallet_detail() {
            return f.write_str(self.0);
        }
        pseudonym(f, "wlb", self.0.as_bytes())
    }
}
both!(WalletLabel<'a>);

/// An amount in satoshis: `amt-0`, or `amt-1eN` with N the power of ten
/// at or below it (`amt-1e8` is 1 to 9.99… DIVI); negative ones `amt--1eN`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WalletAmount(pub i64);

impl fmt::Display for WalletAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wallet_detail() {
            return write!(f, "{} sats", self.0);
        }
        if self.0 == 0 {
            return f.write_str("amt-0");
        }
        let sign = if self.0 < 0 { "-" } else { "" };
        write!(f, "amt-{}1e{}", sign, self.0.unsigned_abs().ilog10())
    }
}
both!(WalletAmount);

/// An outpoint this wallet owns (a staked or spent UTXO): `wout-xxxxxxxx`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OwnOutpoint(pub Hash256, pub u32);

impl OwnOutpoint {
    pub fn of(o: &OutPoint) -> Self {
        OwnOutpoint(o.txid, o.vout)
    }
}

impl fmt::Display for OwnOutpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wallet_detail() {
            return write!(f, "{}:{}", self.0, self.1);
        }
        let mut data = [0u8; 36];
        data[..32].copy_from_slice(self.0.as_bytes());
        data[32..].copy_from_slice(&self.1.to_le_bytes());
        pseudonym(f, "wout", &data)
    }
}
both!(OwnOutpoint);

/// A block this wallet staked, in wallet context ("staked block …"):
/// `wblk-xxxxxxxx`. In a public record the same block is a `BlockHash`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OwnBlockHash(pub Hash256);

impl fmt::Display for OwnBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wallet_detail() {
            return fmt::Display::fmt(&self.0, f);
        }
        pseudonym(f, "wblk", self.0.as_bytes())
    }
}
both!(OwnBlockHash);

/// A swap identifier: `swp-xxxxxxxx`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SwapId<'a>(pub &'a str);

impl fmt::Display for SwapId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wallet_detail() {
            return f.write_str(self.0);
        }
        pseudonym(f, "swp", self.0.as_bytes())
    }
}
both!(SwapId<'a>);

/// An Electrum scripthash a client subscribed to (one of its wallet's
/// scripts): `wsh-xxxxxxxx`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WalletScripthash<'a>(pub &'a str);

impl fmt::Display for WalletScripthash<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wallet_detail() {
            return f.write_str(self.0);
        }
        pseudonym(f, "wsh", self.0.as_bytes())
    }
}
both!(WalletScripthash<'a>);

/// Any other wallet value with no type of its own (a key id, a vault
/// name, a collateral line): `wal-xxxxxxxx`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WalletValue<'a>(pub &'a str);

impl fmt::Display for WalletValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wallet_detail() {
            return f.write_str(self.0);
        }
        pseudonym(f, "wal", self.0.as_bytes())
    }
}
both!(WalletValue<'a>);

#[cfg(test)]
mod tests {
    use super::*;

    // Tests share the DETAIL flag; none of them turns it on
    #[test]
    fn same_value_same_pseudonym_and_no_clear_text() {
        let h = Hash256([0xab; 32]);
        let a = WalletTxid(h).to_string();
        assert_eq!(a, WalletTxid(h).to_string());
        assert_eq!(a, format!("{:?}", WalletTxid(h)));
        assert!(a.starts_with("wtx-") && a.len() == 12, "{}", a);
        assert!(!a.contains("abab"));
        assert_ne!(a, WalletTxid(Hash256([0xac; 32])).to_string());
        // The prefix is part of the HMAC input: one value, two types, two names
        assert_ne!(
            a[4..],
            OwnBlockHash(h).to_string()[5..],
            "a txid and a block hash of the same bytes must not share a name"
        );
        let addr = WalletAddress("DCANARYaddress7f3e").to_string();
        assert!(addr.starts_with("wad-") && !addr.contains("CANARY"));
        let label = format!("{:?}", WalletLabel("CANARY-LABEL-7f3e"));
        assert!(label.starts_with("wlb-") && !label.contains("CANARY"));
    }

    #[test]
    fn amounts_print_their_magnitude_only() {
        assert_eq!(WalletAmount(0).to_string(), "amt-0");
        assert_eq!(WalletAmount(123_456_789).to_string(), "amt-1e8");
        assert_eq!(WalletAmount(99).to_string(), "amt-1e1");
        assert_eq!(WalletAmount(-5).to_string(), "amt--1e0");
        assert_eq!(WalletAmount(i64::MIN).to_string(), "amt--1e18");
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2_shape() {
        // The construction, checked against a known HMAC-SHA256 vector with
        // the key "Jefe": the run key is random, so the vector is computed
        // through the same code with that key in place
        fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
            let mut ipad = [0x36u8; 64];
            let mut opad = [0x5cu8; 64];
            for (i, b) in key.iter().enumerate() {
                ipad[i] ^= b;
                opad[i] ^= b;
            }
            let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&Sha256::new().chain_update(opad).chain_update(inner).finalize());
            out
        }
        let m = hmac(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            m[..4],
            [0x5b, 0xdc, 0xc1, 0x46],
            "RFC 4231 test case 2 starts 5bdcc146"
        );
    }
}
