// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Byte-exact C++ Divi masternode broadcast / ping wire format.
//!
//! The RPCs `setupmasternode`, `signmnbroadcast`, `broadcaststartmasternode`, `importmnbroadcast`
//! and `listmnbroadcasts` exchange the broadcast as hex of the C++ `CMasternodeBroadcast`
//! serialization, and the C++ network only accepts that layout in an `mnb` message. This module
//! is that layout:
//!
//! ```text
//! CMasternodeBroadcast: vin, addr, pubKeyCollateralAddress, pubKeyMasternode, signature,
//!                       sigTime(i64), protocolVersion(i32), lastPing, tier(i32)
//! CTxIn:   prevout.hash(32) prevout.n(u32) scriptSig(varbytes) nSequence(u32)
//! CService: 16-byte IPv6-mapped address, port (big endian u16)
//! CPubKey / signature: varbytes
//! CMasternodePing: vin, blockHash(32), sigTime(i64), signature(varbytes)
//! ```
//!
//! Hashes are stored in internal (little-endian) byte order, like `uint256`.

use divi_crypto::{double_sha256, sign_hash_recoverable, RecoverableSig, SecretKey};
use std::fmt;

/// C++ `strMessageMagic` for masternode message signatures.
const MESSAGE_MAGIC: &[u8] = b"DarkNet Signed Message:\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The data ended before the structure was complete
    Truncated,
    /// A length field is larger than the data (or an absurd size)
    BadLength,
    /// Bytes remain after a complete structure
    TrailingData,
    /// Signing failed
    Signing(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "data truncated"),
            WireError::BadLength => write!(f, "invalid length field"),
            WireError::TrailingData => write!(f, "unexpected trailing data"),
            WireError::Signing(e) => write!(f, "signing failed: {}", e),
        }
    }
}

impl std::error::Error for WireError {}

fn write_compact_size(out: &mut Vec<u8>, n: usize) {
    if n < 0xFD {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

fn write_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::BadLength)?;
        if end > self.data.len() {
            return Err(WireError::Truncated);
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u32_le(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn i32_le(&mut self) -> Result<i32, WireError> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn i64_le(&mut self) -> Result<i64, WireError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn compact_size(&mut self) -> Result<usize, WireError> {
        let first = self.take(1)?[0];
        let n = match first {
            0xFD => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64,
            0xFE => u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64,
            0xFF => u64::from_le_bytes(self.take(8)?.try_into().unwrap()),
            b => b as u64,
        };
        // C++ MAX_SIZE
        if n > 0x0200_0000 {
            return Err(WireError::BadLength);
        }
        Ok(n as usize)
    }

    fn varbytes(&mut self) -> Result<Vec<u8>, WireError> {
        let n = self.compact_size()?;
        Ok(self.take(n)?.to_vec())
    }

    fn hash(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}

/// Hex of a hash as `uint256::ToString` prints it (byte-reversed).
fn hash_to_string(h: &[u8; 32]) -> String {
    h.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

/// C++ `CTxIn`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppTxIn {
    pub prevout_hash: [u8; 32],
    pub prevout_n: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

impl CppTxIn {
    /// A bare input referencing `prevout` (what masternode broadcasts carry)
    pub fn new(prevout_hash: [u8; 32], prevout_n: u32) -> Self {
        Self {
            prevout_hash,
            prevout_n,
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.prevout_hash);
        out.extend_from_slice(&self.prevout_n.to_le_bytes());
        write_varbytes(out, &self.script_sig);
        out.extend_from_slice(&self.sequence.to_le_bytes());
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            prevout_hash: r.hash()?,
            prevout_n: r.u32_le()?,
            script_sig: r.varbytes()?,
            sequence: r.u32_le()?,
        })
    }

    /// C++ `CTxIn::ToString` (used inside the ping message to sign).
    ///
    /// `scriptSig.ToString().substr(0,24)` is the script asm, which is empty for the bare
    /// inputs masternode messages carry; a non-empty script is rendered as hex, which only
    /// matters for hand-built messages.
    pub fn to_cpp_string(&self) -> String {
        let hash = hash_to_string(&self.prevout_hash);
        let null = self.prevout_hash == [0u8; 32] && self.prevout_n == u32::MAX;
        let mut s = format!("CTxIn(COutPoint({}, {})", &hash[..10], self.prevout_n);
        if null {
            let hex: String = self
                .script_sig
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            s.push_str(&format!(", coinbase {}", hex));
        } else {
            let hex: String = self
                .script_sig
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            s.push_str(&format!(", scriptSig={}", &hex[..hex.len().min(24)]));
        }
        if self.sequence != u32::MAX {
            s.push_str(&format!(", nSequence={}", self.sequence));
        }
        s.push(')');
        s
    }
}

/// C++ `CMasternodePing`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppPing {
    pub vin: CppTxIn,
    pub block_hash: [u8; 32],
    pub sig_time: i64,
    pub signature: Vec<u8>,
}

impl CppPing {
    fn encode(&self, out: &mut Vec<u8>) {
        self.vin.encode(out);
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.sig_time.to_le_bytes());
        write_varbytes(out, &self.signature);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            vin: CppTxIn::decode(r)?,
            block_hash: r.hash()?,
            sig_time: r.i64_le()?,
            signature: r.varbytes()?,
        })
    }

    /// C++ `CMasternodePing::getMessageToSign`: `vin.ToString() + blockHash.ToString() + sigTime`
    pub fn message_to_sign(&self) -> Vec<u8> {
        format!(
            "{}{}{}",
            self.vin.to_cpp_string(),
            hash_to_string(&self.block_hash),
            self.sig_time
        )
        .into_bytes()
    }

    /// Sign the ping with the masternode key
    pub fn sign(&mut self, key: &SecretKey) -> Result<(), WireError> {
        self.signature = sign_message(key, &self.message_to_sign())?;
        Ok(())
    }
}

/// C++ `CMasternodeBroadcast`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppBroadcast {
    pub vin: CppTxIn,
    /// `CService` address as 16 bytes (IPv4 is `::ffff:a.b.c.d`)
    pub ip: [u8; 16],
    pub port: u16,
    pub pubkey_collateral: Vec<u8>,
    pub pubkey_masternode: Vec<u8>,
    pub signature: Vec<u8>,
    pub sig_time: i64,
    pub protocol_version: i32,
    pub last_ping: CppPing,
    /// C++ `MasternodeTier` as an int (0 copper .. 4 diamond)
    pub tier: i32,
}

impl CppBroadcast {
    /// Serialize exactly like `CDataStream << CMasternodeBroadcast`
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(400);
        self.vin.encode(&mut out);
        out.extend_from_slice(&self.ip);
        out.extend_from_slice(&self.port.to_be_bytes());
        write_varbytes(&mut out, &self.pubkey_collateral);
        write_varbytes(&mut out, &self.pubkey_masternode);
        write_varbytes(&mut out, &self.signature);
        out.extend_from_slice(&self.sig_time.to_le_bytes());
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        self.last_ping.encode(&mut out);
        out.extend_from_slice(&self.tier.to_le_bytes());
        out
    }

    /// Parse a broadcast; the whole input must be consumed
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader { data, pos: 0 };
        let vin = CppTxIn::decode(&mut r)?;
        let ip: [u8; 16] = r.take(16)?.try_into().unwrap();
        let port = u16::from_be_bytes(r.take(2)?.try_into().unwrap());
        let pubkey_collateral = r.varbytes()?;
        let pubkey_masternode = r.varbytes()?;
        let signature = r.varbytes()?;
        let sig_time = r.i64_le()?;
        let protocol_version = r.i32_le()?;
        let last_ping = CppPing::decode(&mut r)?;
        let tier = r.i32_le()?;
        if r.pos != data.len() {
            return Err(WireError::TrailingData);
        }
        Ok(Self {
            vin,
            ip,
            port,
            pubkey_collateral,
            pubkey_masternode,
            signature,
            sig_time,
            protocol_version,
            last_ping,
            tier,
        })
    }

    /// Set the address from an IPv4/IPv6 address and port
    pub fn set_service(&mut self, addr: std::net::IpAddr, port: u16) {
        self.ip = match addr {
            std::net::IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
            std::net::IpAddr::V6(a) => a.octets(),
        };
        self.port = port;
    }

    /// C++ `CService::ToString`: `a.b.c.d:port` for IPv4, `[x:x:...]:port` for IPv6 (groups are
    /// not zero-compressed in the C++ formatter).
    pub fn service_string(&self) -> String {
        const V4_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
        if self.ip[..12] == V4_PREFIX {
            format!(
                "{}.{}.{}.{}:{}",
                self.ip[12], self.ip[13], self.ip[14], self.ip[15], self.port
            )
        } else {
            let groups: Vec<String> = self
                .ip
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            format!("[{}]:{}", groups.join(":"), self.port)
        }
    }

    /// C++ `CMasternodeBroadcast::getMessageToSign`:
    /// `addr.ToString() + sigTime + pubKeyCollateral bytes + pubKeyMasternode bytes + protocolVersion`
    pub fn message_to_sign(&self) -> Vec<u8> {
        let mut m = self.service_string().into_bytes();
        m.extend_from_slice(self.sig_time.to_string().as_bytes());
        m.extend_from_slice(&self.pubkey_collateral);
        m.extend_from_slice(&self.pubkey_masternode);
        m.extend_from_slice(self.protocol_version.to_string().as_bytes());
        m
    }

    /// Sign the broadcast with the collateral key (`CObfuScationSigner::SignMessage`)
    pub fn sign(&mut self, key: &SecretKey) -> Result<(), WireError> {
        self.signature = sign_message(key, &self.message_to_sign())?;
        Ok(())
    }

    /// True when `signature` recovers to `pubkey_collateral`
    pub fn signature_is_valid(&self) -> bool {
        verify_message(
            &self.pubkey_collateral,
            &self.signature,
            &self.message_to_sign(),
        )
    }
}

/// `CHashWriter << strMessageMagic << strMessage` (each as a length-prefixed string), double SHA256
fn message_hash(message: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(MESSAGE_MAGIC.len() + message.len() + 6);
    write_varbytes(&mut buf, MESSAGE_MAGIC);
    write_varbytes(&mut buf, message);
    double_sha256(&buf)
}

/// 65-byte compact recoverable signature over a masternode message
pub fn sign_message(key: &SecretKey, message: &[u8]) -> Result<Vec<u8>, WireError> {
    let sig = sign_hash_recoverable(key, &message_hash(message))
        .map_err(|e| WireError::Signing(e.to_string()))?;
    Ok(sig.to_compact_with_recovery().to_vec())
}

/// Check that `signature` over `message` recovers to `pubkey`
pub fn verify_message(pubkey: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let Ok(sig) = RecoverableSig::from_compact_with_recovery(signature) else {
        return false;
    };
    match sig.recover_from_hash(&message_hash(message)) {
        Ok(recovered) => recovered.to_bytes() == pubkey,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CppBroadcast {
        let mut b = CppBroadcast {
            vin: CppTxIn::new([7u8; 32], 1),
            ip: [0; 16],
            port: 51474,
            pubkey_collateral: vec![2; 33],
            pubkey_masternode: vec![3; 33],
            signature: vec![],
            sig_time: 1_700_000_000,
            protocol_version: 70920,
            last_ping: CppPing {
                vin: CppTxIn::new([7u8; 32], 1),
                block_hash: [9u8; 32],
                sig_time: 1_700_000_100,
                signature: vec![],
            },
            tier: 2,
        };
        b.set_service("10.1.2.3".parse().unwrap(), 51474);
        b
    }

    #[test]
    fn encode_layout_and_roundtrip() {
        let b = sample();
        let bytes = b.encode();
        // vin: 32 + 4 + 1 + 4, addr 16 + 2, two 33-byte keys + len, empty sig, 8 + 4, ping, tier
        let vin = 32 + 4 + 1 + 4;
        let ping = vin + 32 + 8 + 1;
        assert_eq!(bytes.len(), vin + 18 + 34 + 34 + 1 + 8 + 4 + ping + 4);
        assert_eq!(&bytes[vin + 10..vin + 16], &[0xff, 0xff, 10, 1, 2, 3][..]);
        // port is big endian
        assert_eq!(&bytes[vin + 16..vin + 18], &51474u16.to_be_bytes()[..]);
        assert_eq!(CppBroadcast::decode(&bytes).unwrap(), b);
    }

    #[test]
    fn decode_rejects_bad_input() {
        let bytes = sample().encode();
        assert_eq!(
            CppBroadcast::decode(&bytes[..bytes.len() - 1]),
            Err(WireError::Truncated)
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(CppBroadcast::decode(&extra), Err(WireError::TrailingData));
        assert!(CppBroadcast::decode(&[]).is_err());
    }

    #[test]
    fn service_and_message_strings() {
        let b = sample();
        assert_eq!(b.service_string(), "10.1.2.3:51474");
        let mut m = b"10.1.2.3:514741700000000".to_vec();
        m.extend_from_slice(&[2; 33]);
        m.extend_from_slice(&[3; 33]);
        m.extend_from_slice(b"70920");
        assert_eq!(b.message_to_sign(), m);

        let mut v6 = sample();
        v6.set_service("2001:db8::1".parse().unwrap(), 5);
        assert_eq!(v6.service_string(), "[2001:db8:0:0:0:0:0:1]:5");
    }

    #[test]
    fn ping_message_uses_cpp_txin_string() {
        let mut p = sample().last_ping;
        p.vin = CppTxIn::new(
            {
                let mut h = [0u8; 32];
                h[31] = 0xab;
                h[30] = 0xcd;
                h
            },
            3,
        );
        let msg = String::from_utf8(p.message_to_sign()).unwrap();
        assert!(
            msg.starts_with("CTxIn(COutPoint(abcd000000, 3), scriptSig=)"),
            "{}",
            msg
        );
        assert!(msg.ends_with("1700000100"));
    }

    #[test]
    fn sign_and_verify_with_collateral_key() {
        let key = SecretKey::from_bytes(&[0x11; 32]).unwrap();
        let pubkey = key.public_key().to_bytes();
        let mut b = sample();
        b.pubkey_collateral = pubkey;
        b.sign(&key).unwrap();
        assert_eq!(b.signature.len(), 65);
        assert!(b.signature_is_valid());
        // any change to the signed fields invalidates it
        b.sig_time += 1;
        assert!(!b.signature_is_valid());
    }
}
