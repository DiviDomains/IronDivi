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

use crate::tier::MasternodeTier;
use divi_primitives::error::Error;
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::{Decodable, Encodable};
use divi_primitives::transaction::OutPoint;
use std::io::{Read, Write};
use std::net::SocketAddrV6;

#[cfg(test)]
use std::net::Ipv6Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceAddr(SocketAddrV6);

impl ServiceAddr {
    pub fn new(addr: SocketAddrV6) -> Self {
        ServiceAddr(addr)
    }

    pub fn inner(&self) -> &SocketAddrV6 {
        &self.0
    }

    pub fn into_inner(self) -> SocketAddrV6 {
        self.0
    }
}

impl From<SocketAddrV6> for ServiceAddr {
    fn from(addr: SocketAddrV6) -> Self {
        ServiceAddr(addr)
    }
}

impl From<ServiceAddr> for SocketAddrV6 {
    fn from(addr: ServiceAddr) -> Self {
        addr.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MasternodeStatus {
    PreEnabled = 0,
    Enabled = 1,
    Expired = 2,
    OutpointSpent = 3,
    Remove = 4,
    WatchdogExpired = 5,
    PoseBan = 6,
    VinSpent = 7,
}

impl Default for MasternodeStatus {
    fn default() -> Self {
        MasternodeStatus::PreEnabled
    }
}

impl MasternodeStatus {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => MasternodeStatus::PreEnabled,
            1 => MasternodeStatus::Enabled,
            2 => MasternodeStatus::Expired,
            3 => MasternodeStatus::OutpointSpent,
            4 => MasternodeStatus::Remove,
            5 => MasternodeStatus::WatchdogExpired,
            6 => MasternodeStatus::PoseBan,
            7 => MasternodeStatus::VinSpent,
            _ => MasternodeStatus::PreEnabled,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn is_active(self) -> bool {
        matches!(self, MasternodeStatus::Enabled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Masternode {
    pub vin: OutPoint,
    pub addr: ServiceAddr,
    pub pubkey_collateral: Vec<u8>,
    pub pubkey_masternode: Vec<u8>,
    pub sig_time: i64,
    pub last_dsq: i64,
    pub time_last_checked: i64,
    pub time_last_paid: i64,
    pub time_last_watchdog_vote: i64,
    pub status: MasternodeStatus,
    pub protocol_version: i32,
    pub tier: MasternodeTier,
    pub signature: Vec<u8>,
    pub pose_score: i32,
    pub pose_ban_height: Option<u32>,
}

impl Masternode {
    pub fn new(
        vin: OutPoint,
        addr: ServiceAddr,
        pubkey_collateral: Vec<u8>,
        pubkey_masternode: Vec<u8>,
        tier: MasternodeTier,
        protocol_version: i32,
    ) -> Self {
        Masternode {
            vin,
            addr,
            pubkey_collateral,
            pubkey_masternode,
            sig_time: 0,
            last_dsq: 0,
            time_last_checked: 0,
            time_last_paid: 0,
            time_last_watchdog_vote: 0,
            status: MasternodeStatus::PreEnabled,
            protocol_version,
            tier,
            signature: Vec::new(),
            pose_score: 0,
            pose_ban_height: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.status.is_active()
    }

    pub fn outpoint(&self) -> OutPoint {
        self.vin
    }

    pub fn update_last_seen(&mut self, time: i64) {
        self.time_last_checked = time;
    }

    pub fn mark_as_paid(&mut self, time: i64) {
        self.time_last_paid = time;
    }

    pub fn update_status(&mut self, status: MasternodeStatus) {
        self.status = status;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasternodeBroadcast {
    pub vin: OutPoint,
    pub addr: ServiceAddr,
    pub pubkey_collateral: Vec<u8>,
    pub pubkey_masternode: Vec<u8>,
    pub sig_time: i64,
    pub protocol_version: i32,
    pub tier: MasternodeTier,
    pub signature: Vec<u8>,
}

impl MasternodeBroadcast {
    pub fn new(
        vin: OutPoint,
        addr: ServiceAddr,
        pubkey_collateral: Vec<u8>,
        pubkey_masternode: Vec<u8>,
        tier: MasternodeTier,
        protocol_version: i32,
        sig_time: i64,
    ) -> Self {
        MasternodeBroadcast {
            vin,
            addr,
            pubkey_collateral,
            pubkey_masternode,
            sig_time,
            protocol_version,
            tier,
            signature: Vec::new(),
        }
    }

    pub fn to_masternode(&self) -> Masternode {
        Masternode {
            vin: self.vin,
            addr: self.addr,
            pubkey_collateral: self.pubkey_collateral.clone(),
            pubkey_masternode: self.pubkey_masternode.clone(),
            sig_time: self.sig_time,
            last_dsq: 0,
            time_last_checked: 0,
            time_last_paid: 0,
            time_last_watchdog_vote: 0,
            status: MasternodeStatus::PreEnabled,
            protocol_version: self.protocol_version,
            tier: self.tier,
            signature: self.signature.clone(),
            pose_score: 0,
            pose_ban_height: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasternodePing {
    pub vin: OutPoint,
    pub block_hash: Hash256,
    pub sig_time: i64,
    pub signature: Vec<u8>,
}

impl MasternodePing {
    pub fn new(vin: OutPoint, block_hash: Hash256, sig_time: i64) -> Self {
        MasternodePing {
            vin,
            block_hash,
            sig_time,
            signature: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasternodePaymentWinner {
    pub vin_masternode: OutPoint,
    pub block_height: i32,
    pub payee_script: Vec<u8>,
    pub signature: Vec<u8>,
}

impl MasternodePaymentWinner {
    pub fn new(vin_masternode: OutPoint, block_height: i32, payee_script: Vec<u8>) -> Self {
        MasternodePaymentWinner {
            vin_masternode,
            block_height,
            payee_script,
            signature: Vec::new(),
        }
    }
}

// Serialization implementations matching C++ Divi's binary format

// ServiceAddr serialization (CService format: 16-byte IPv6 + 2-byte port)
impl Encodable for ServiceAddr {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = 0;
        // Write IPv6 address as 16 bytes
        size += self.0.ip().octets().encode(writer)?;
        // Write port as little-endian u16
        size += self.0.port().encode(writer)?;
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        16 + 2 // IPv6 (16 bytes) + port (2 bytes)
    }
}

impl Decodable for ServiceAddr {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        // Read 16-byte IPv6 address
        let octets = <[u8; 16]>::decode(reader)?;
        let ip = std::net::Ipv6Addr::from(octets);
        // Read 2-byte port (little-endian)
        let port = u16::decode(reader)?;
        Ok(ServiceAddr(SocketAddrV6::new(ip, port, 0, 0)))
    }
}

// Masternode serialization (matches CMasternode C++ format)
impl Encodable for Masternode {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = 0;
        size += self.vin.encode(writer)?;
        size += self.addr.encode(writer)?;
        size += self.pubkey_collateral.encode(writer)?;
        size += self.pubkey_masternode.encode(writer)?;
        size += self.signature.encode(writer)?;
        size += self.sig_time.encode(writer)?;
        size += self.last_dsq.encode(writer)?;
        size += self.protocol_version.encode(writer)?;
        size += (self.status.to_u8() as i32).encode(writer)?; // nActiveState as i32
        size += self.time_last_paid.encode(writer)?;
        size += self.time_last_watchdog_vote.encode(writer)?;
        size += self.tier.to_u8().encode(writer)?;
        size += self.pose_score.encode(writer)?;
        size += match self.pose_ban_height {
            Some(h) => {
                size += 1u8.encode(writer)?;
                h.encode(writer)?
            }
            None => 0u8.encode(writer)?,
        };
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        self.vin.encoded_size()
            + self.addr.encoded_size()
            + self.pubkey_collateral.encoded_size()
            + self.pubkey_masternode.encoded_size()
            + self.signature.encoded_size()
            + 8 // sig_time
            + 8 // last_dsq
            + 4 // protocol_version
            + 4 // status (i32)
            + 8 // time_last_paid
            + 8 // time_last_watchdog_vote
            + 1 // tier
            + 4 // pose_score
            + 1 // pose_ban_height flag
            + if self.pose_ban_height.is_some() { 4 } else { 0 }
    }
}

impl Decodable for Masternode {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let vin = OutPoint::decode(reader)?;
        let addr = ServiceAddr::decode(reader)?;
        let pubkey_collateral = Vec::<u8>::decode(reader)?;
        let pubkey_masternode = Vec::<u8>::decode(reader)?;
        let signature = Vec::<u8>::decode(reader)?;
        let sig_time = i64::decode(reader)?;
        let last_dsq = i64::decode(reader)?;
        let protocol_version = i32::decode(reader)?;
        let status_raw = i32::decode(reader)?;
        let time_last_paid = i64::decode(reader)?;
        let time_last_watchdog_vote = i64::decode(reader)?;
        let tier_byte = u8::decode(reader)?;
        let pose_score = i32::decode(reader)?;
        let pose_ban_flag = u8::decode(reader)?;
        let pose_ban_height = if pose_ban_flag != 0 {
            Some(u32::decode(reader)?)
        } else {
            None
        };

        Ok(Masternode {
            vin,
            addr,
            pubkey_collateral,
            pubkey_masternode,
            sig_time,
            last_dsq,
            time_last_checked: 0, // Not serialized
            time_last_paid,
            time_last_watchdog_vote,
            status: MasternodeStatus::from_u8(status_raw as u8),
            protocol_version,
            tier: MasternodeTier::from_u8(tier_byte),
            signature,
            pose_score,
            pose_ban_height,
        })
    }
}

// MasternodeBroadcast serialization (matches CMasternodeBroadcast C++ format)
impl Encodable for MasternodeBroadcast {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = 0;
        size += self.vin.encode(writer)?;
        size += self.addr.encode(writer)?;
        size += self.pubkey_collateral.encode(writer)?;
        size += self.pubkey_masternode.encode(writer)?;
        size += self.signature.encode(writer)?;
        size += self.sig_time.encode(writer)?;
        size += self.protocol_version.encode(writer)?;
        size += self.tier.to_u8().encode(writer)?;
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        self.vin.encoded_size()
            + self.addr.encoded_size()
            + self.pubkey_collateral.encoded_size()
            + self.pubkey_masternode.encoded_size()
            + self.signature.encoded_size()
            + 8 // sig_time
            + 4 // protocol_version
            + 1 // tier
    }
}

impl Decodable for MasternodeBroadcast {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let vin = OutPoint::decode(reader)?;
        let addr = ServiceAddr::decode(reader)?;
        let pubkey_collateral = Vec::<u8>::decode(reader)?;
        let pubkey_masternode = Vec::<u8>::decode(reader)?;
        let signature = Vec::<u8>::decode(reader)?;
        let sig_time = i64::decode(reader)?;
        let protocol_version = i32::decode(reader)?;
        let tier_byte = u8::decode(reader)?;

        Ok(MasternodeBroadcast {
            vin,
            addr,
            pubkey_collateral,
            pubkey_masternode,
            sig_time,
            protocol_version,
            tier: MasternodeTier::from_u8(tier_byte),
            signature,
        })
    }
}

// MasternodePing serialization (matches CMasternodePing C++ format)
impl Encodable for MasternodePing {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = 0;
        size += self.vin.encode(writer)?;
        size += self.block_hash.encode(writer)?;
        size += self.sig_time.encode(writer)?;
        size += self.signature.encode(writer)?;
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        self.vin.encoded_size()
            + self.block_hash.encoded_size()
            + 8 // sig_time
            + self.signature.encoded_size()
    }
}

impl Decodable for MasternodePing {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let vin = OutPoint::decode(reader)?;
        let block_hash = Hash256::decode(reader)?;
        let sig_time = i64::decode(reader)?;
        let signature = Vec::<u8>::decode(reader)?;

        Ok(MasternodePing {
            vin,
            block_hash,
            sig_time,
            signature,
        })
    }
}

// MasternodePaymentWinner serialization (matches CMasternodePaymentWinner C++ format)
impl Encodable for MasternodePaymentWinner {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = 0;
        size += self.vin_masternode.encode(writer)?;
        size += self.block_height.encode(writer)?;
        size += self.payee_script.encode(writer)?;
        size += self.signature.encode(writer)?;
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        self.vin_masternode.encoded_size()
            + 4 // block_height
            + self.payee_script.encoded_size()
            + self.signature.encoded_size()
    }
}

impl Decodable for MasternodePaymentWinner {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let vin_masternode = OutPoint::decode(reader)?;
        let block_height = i32::decode(reader)?;
        let payee_script = Vec::<u8>::decode(reader)?;
        let signature = Vec::<u8>::decode(reader)?;

        Ok(MasternodePaymentWinner {
            vin_masternode,
            block_height,
            payee_script,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masternode_status_conversion() {
        assert_eq!(MasternodeStatus::from_u8(0), MasternodeStatus::PreEnabled);
        assert_eq!(MasternodeStatus::from_u8(1), MasternodeStatus::Enabled);
        assert_eq!(MasternodeStatus::from_u8(2), MasternodeStatus::Expired);
        assert_eq!(
            MasternodeStatus::from_u8(3),
            MasternodeStatus::OutpointSpent
        );
        assert_eq!(MasternodeStatus::from_u8(4), MasternodeStatus::Remove);
        assert_eq!(
            MasternodeStatus::from_u8(5),
            MasternodeStatus::WatchdogExpired
        );
        assert_eq!(MasternodeStatus::from_u8(6), MasternodeStatus::PoseBan);
        assert_eq!(MasternodeStatus::from_u8(7), MasternodeStatus::VinSpent);
        assert_eq!(MasternodeStatus::from_u8(99), MasternodeStatus::PreEnabled);
    }

    #[test]
    fn test_masternode_status_to_u8() {
        assert_eq!(MasternodeStatus::PreEnabled.to_u8(), 0);
        assert_eq!(MasternodeStatus::Enabled.to_u8(), 1);
        assert_eq!(MasternodeStatus::Expired.to_u8(), 2);
        assert_eq!(MasternodeStatus::OutpointSpent.to_u8(), 3);
        assert_eq!(MasternodeStatus::Remove.to_u8(), 4);
        assert_eq!(MasternodeStatus::WatchdogExpired.to_u8(), 5);
        assert_eq!(MasternodeStatus::PoseBan.to_u8(), 6);
        assert_eq!(MasternodeStatus::VinSpent.to_u8(), 7);
    }

    #[test]
    fn test_masternode_status_is_active() {
        assert!(!MasternodeStatus::PreEnabled.is_active());
        assert!(MasternodeStatus::Enabled.is_active());
        assert!(!MasternodeStatus::Expired.is_active());
        assert!(!MasternodeStatus::OutpointSpent.is_active());
    }

    #[test]
    fn test_masternode_creation() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mn = Masternode::new(
            OutPoint::null(),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Copper,
            70000,
        );

        assert_eq!(mn.tier, MasternodeTier::Copper);
        assert_eq!(mn.protocol_version, 70000);
        assert_eq!(mn.status, MasternodeStatus::PreEnabled);
        assert!(!mn.is_enabled());
        assert_eq!(mn.pubkey_collateral, vec![1, 2, 3]);
        assert_eq!(mn.pubkey_masternode, vec![4, 5, 6]);
    }

    #[test]
    fn test_masternode_broadcast_to_masternode() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mnb = MasternodeBroadcast::new(
            OutPoint::null(),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
            1234567890,
        );

        let mn = mnb.to_masternode();
        assert_eq!(mn.tier, MasternodeTier::Gold);
        assert_eq!(mn.protocol_version, 70000);
        assert_eq!(mn.sig_time, 1234567890);
        assert_eq!(mn.status, MasternodeStatus::PreEnabled);
    }

    #[test]
    fn test_masternode_ping_creation() {
        let ping = MasternodePing::new(OutPoint::null(), Hash256::zero(), 1234567890);
        assert_eq!(ping.sig_time, 1234567890);
        assert_eq!(ping.block_hash, Hash256::zero());
        assert_eq!(ping.signature, Vec::<u8>::new());
    }

    #[test]
    fn test_masternode_payment_winner_creation() {
        let winner = MasternodePaymentWinner::new(OutPoint::null(), 12345, vec![1, 2, 3]);
        assert_eq!(winner.block_height, 12345);
        assert_eq!(winner.payee_script, vec![1, 2, 3]);
        assert_eq!(winner.signature, Vec::<u8>::new());
    }

    #[test]
    fn test_masternode_update_methods() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mut mn = Masternode::new(
            OutPoint::null(),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Silver,
            70000,
        );

        mn.update_last_seen(999);
        assert_eq!(mn.time_last_checked, 999);

        mn.mark_as_paid(1000);
        assert_eq!(mn.time_last_paid, 1000);

        mn.update_status(MasternodeStatus::Enabled);
        assert_eq!(mn.status, MasternodeStatus::Enabled);
        assert!(mn.is_enabled());
    }

    #[test]
    fn test_service_addr_serialization() {
        use divi_primitives::serialize::{deserialize, serialize};

        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let encoded = serialize(&addr);
        assert_eq!(encoded.len(), 18);

        let decoded: ServiceAddr = deserialize(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_masternode_broadcast_serialization() {
        use divi_primitives::serialize::{deserialize, serialize};

        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mnb = MasternodeBroadcast::new(
            OutPoint::null(),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
            1234567890,
        );

        let encoded = serialize(&mnb);
        let decoded: MasternodeBroadcast = deserialize(&encoded).unwrap();

        assert_eq!(decoded.vin, mnb.vin);
        assert_eq!(decoded.addr, mnb.addr);
        assert_eq!(decoded.pubkey_collateral, mnb.pubkey_collateral);
        assert_eq!(decoded.pubkey_masternode, mnb.pubkey_masternode);
        assert_eq!(decoded.sig_time, mnb.sig_time);
        assert_eq!(decoded.protocol_version, mnb.protocol_version);
        assert_eq!(decoded.tier, mnb.tier);
        assert_eq!(decoded.signature, mnb.signature);
    }

    #[test]
    fn test_masternode_ping_serialization() {
        use divi_primitives::serialize::{deserialize, serialize};

        let ping = MasternodePing::new(OutPoint::null(), Hash256::zero(), 1234567890);

        let encoded = serialize(&ping);
        let decoded: MasternodePing = deserialize(&encoded).unwrap();

        assert_eq!(decoded.vin, ping.vin);
        assert_eq!(decoded.block_hash, ping.block_hash);
        assert_eq!(decoded.sig_time, ping.sig_time);
        assert_eq!(decoded.signature, ping.signature);
    }

    #[test]
    fn test_masternode_payment_winner_serialization() {
        use divi_primitives::serialize::{deserialize, serialize};

        let winner = MasternodePaymentWinner::new(OutPoint::null(), 12345, vec![0x76, 0xa9, 0x14]);

        let encoded = serialize(&winner);
        let decoded: MasternodePaymentWinner = deserialize(&encoded).unwrap();

        assert_eq!(decoded.vin_masternode, winner.vin_masternode);
        assert_eq!(decoded.block_height, winner.block_height);
        assert_eq!(decoded.payee_script, winner.payee_script);
        assert_eq!(decoded.signature, winner.signature);
    }

    #[test]
    fn test_masternode_serialization() {
        use divi_primitives::serialize::{deserialize, serialize};

        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mn = Masternode::new(
            OutPoint::null(),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Platinum,
            70000,
        );

        let encoded = serialize(&mn);
        let decoded: Masternode = deserialize(&encoded).unwrap();

        assert_eq!(decoded.vin, mn.vin);
        assert_eq!(decoded.addr, mn.addr);
        assert_eq!(decoded.pubkey_collateral, mn.pubkey_collateral);
        assert_eq!(decoded.pubkey_masternode, mn.pubkey_masternode);
        assert_eq!(decoded.sig_time, mn.sig_time);
        assert_eq!(decoded.last_dsq, mn.last_dsq);
        assert_eq!(decoded.status, mn.status);
        assert_eq!(decoded.protocol_version, mn.protocol_version);
        assert_eq!(decoded.tier, mn.tier);
        assert_eq!(decoded.time_last_paid, mn.time_last_paid);
        assert_eq!(decoded.time_last_watchdog_vote, mn.time_last_watchdog_vote);
    }
}
