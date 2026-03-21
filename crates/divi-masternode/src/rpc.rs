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

//! Masternode RPC command implementations
//!
//! This module provides RPC commands for interacting with the masternode system,
//! matching the C++ Divi RPC interface for compatibility.
//!
//! # Available Commands
//!
//! ## Query Commands
//!
//! ### list(mode)
//! Lists all masternodes with various detail levels.
//!
//! **Modes**:
//! - `"status"` (default) - Shows only masternode status
//! - `"addr"` - Shows only network addresses
//! - `"full"` - Shows complete masternode information
//!
//! **Returns**: `MasternodeListResponse` with HashMap of outpoint -> info
//!
//! **Example**:
//! ```rust
//! # use divi_masternode::{MasternodeRpc, MasternodeManager};
//! let manager = MasternodeManager::new();
//! let rpc = MasternodeRpc::new(manager);
//!
//! // List with status (default)
//! let status_list = rpc.list(None);
//!
//! // List with full details
//! let full_list = rpc.list(Some("full".to_string()));
//! ```
//!
//! ### count()
//! Returns count statistics for masternodes.
//!
//! **Returns**: `MasternodeCountResponse` with:
//! - `total` - Total number of masternodes
//! - `enabled` - Number of enabled masternodes
//! - `copper`, `silver`, `gold`, `platinum`, `diamond` - Count per tier
//!
//! **Example**:
//! ```rust
//! # use divi_masternode::{MasternodeRpc, MasternodeManager};
//! let manager = MasternodeManager::new();
//! let rpc = MasternodeRpc::new(manager);
//!
//! let counts = rpc.count();
//! println!("Total: {}, Enabled: {}", counts.total, counts.enabled);
//! println!("Diamond tier: {}", counts.diamond);
//! ```
//!
//! ### get_status(outpoint)
//! Gets detailed status for a specific masternode.
//!
//! **Parameters**:
//! - `outpoint` - The transaction outpoint identifying the masternode
//!
//! **Returns**: `Result<MasternodeInfo, String>` with complete masternode details
//!
//! **Example**:
//! ```rust
//! # use divi_masternode::{MasternodeRpc, MasternodeManager};
//! # use divi_primitives::{Hash256, OutPoint};
//! # let manager = MasternodeManager::new();
//! # let rpc = MasternodeRpc::new(manager);
//! # let outpoint = OutPoint::new(Hash256::zero(), 0);
//! match rpc.get_status(outpoint) {
//!     Ok(info) => println!("Status: {}, Tier: {}", info.status, info.tier),
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! ```
//!
//! ## Payment Commands
//!
//! ### get_winners(tracker, start_height, count)
//! Gets the expected payment winners for a range of block heights.
//!
//! **Parameters**:
//! - `tracker` - PaymentVoteTracker with voting data
//! - `start_height` - Starting block height
//! - `count` - Number of blocks to query
//!
//! **Returns**: `Vec<MasternodeWinnerInfo>` with winner data for each height
//!
//! **Example**:
//! ```rust
//! # use divi_masternode::{MasternodeRpc, MasternodeManager, PaymentVoteTracker};
//! # let manager = MasternodeManager::new();
//! # let rpc = MasternodeRpc::new(manager);
//! let tracker = PaymentVoteTracker::new(10, 3);
//!
//! // Get winners for next 10 blocks starting at height 100000
//! let winners = rpc.get_winners(&tracker, 100000, 10);
//! for winner in winners {
//!     println!("Height {}: {:?}", winner.height, winner.winner);
//! }
//! ```
//!
//! ### get_current_winner(tracker, height)
//! Gets the expected payment winner for a specific block height.
//!
//! **Parameters**:
//! - `tracker` - PaymentVoteTracker with voting data
//! - `height` - Block height to query
//!
//! **Returns**: `Option<MasternodeWinnerInfo>` with winner data
//!
//! **Example**:
//! ```rust
//! # use divi_masternode::{MasternodeRpc, MasternodeManager, PaymentVoteTracker};
//! # let manager = MasternodeManager::new();
//! # let rpc = MasternodeRpc::new(manager);
//! # let tracker = PaymentVoteTracker::new(10, 3);
//! if let Some(winner) = rpc.get_current_winner(&tracker, 100000) {
//!     println!("Winner at height {}: {:?}", winner.height, winner.winner);
//! }
//! ```
//!
//! # JSON Response Formats
//!
//! ## MasternodeListResponse
//! ```json
//! {
//!   "masternodes": {
//!     "txid:vout": {
//!       "address": "[::1]:9999",
//!       "status": "ENABLED",
//!       "protocol": 70000,
//!       "tier": "GOLD",
//!       "lastseen": 1234567890,
//!       "lastpaid": 1234567800,
//!       "pose_score": 0
//!     }
//!   }
//! }
//! ```
//!
//! ## MasternodeCountResponse
//! ```json
//! {
//!   "total": 1234,
//!   "enabled": 1189,
//!   "copper": 456,
//!   "silver": 321,
//!   "gold": 234,
//!   "platinum": 123,
//!   "diamond": 55
//! }
//! ```
//!
//! ## MasternodeWinnerInfo
//! ```json
//! {
//!   "height": 100000,
//!   "winner": "txid:vout",
//!   "payee": "03a1b2c3..."
//! }
//! ```
//!
//! # Thread Safety
//!
//! All RPC commands are thread-safe. The `MasternodeManager` uses `Arc<RwLock<>>`
//! internally, allowing concurrent reads and exclusive writes.
//!
//! # Compatibility
//!
//! These RPC commands match the C++ Divi RPC interface (src/rpc/masternode.cpp)
//! for drop-in compatibility with existing Divi infrastructure.

use crate::manager::MasternodeManager;
use crate::masternode::MasternodeStatus;
use crate::payments::PaymentVoteTracker;
use crate::tier::MasternodeTier;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::OutPoint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeListResponse {
    pub masternodes: HashMap<String, MasternodeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeInfo {
    pub address: String,
    pub status: String,
    pub protocol: i32,
    pub tier: String,
    pub lastseen: i64,
    pub lastpaid: i64,
    pub pose_score: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeCountResponse {
    pub total: usize,
    pub enabled: usize,
    pub copper: usize,
    pub silver: usize,
    pub gold: usize,
    pub platinum: usize,
    pub diamond: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeWinnerInfo {
    pub height: i32,
    pub winner: Option<String>,
    pub payee: Option<String>,
}

pub struct MasternodeRpc {
    manager: MasternodeManager,
}

impl MasternodeRpc {
    pub fn new(manager: MasternodeManager) -> Self {
        MasternodeRpc { manager }
    }

    pub fn list(&self, mode: Option<String>) -> MasternodeListResponse {
        let mode = mode.unwrap_or_else(|| "status".to_string());
        let masternodes = self.manager.get_all();

        let mut result = HashMap::new();

        for mn in masternodes {
            let outpoint_str = format!("{}:{}", mn.vin.txid, mn.vin.vout);

            let info = match mode.as_str() {
                "addr" => MasternodeInfo {
                    address: format!("{:?}", mn.addr),
                    status: String::new(),
                    protocol: 0,
                    tier: String::new(),
                    lastseen: 0,
                    lastpaid: 0,
                    pose_score: 0,
                },
                "full" => MasternodeInfo {
                    address: format!("{:?}", mn.addr),
                    status: status_to_string(mn.status),
                    protocol: mn.protocol_version,
                    tier: tier_to_string(mn.tier),
                    lastseen: mn.time_last_checked,
                    lastpaid: mn.time_last_paid,
                    pose_score: mn.pose_score,
                },
                _ => MasternodeInfo {
                    address: String::new(),
                    status: status_to_string(mn.status),
                    protocol: 0,
                    tier: String::new(),
                    lastseen: 0,
                    lastpaid: 0,
                    pose_score: 0,
                },
            };

            result.insert(outpoint_str, info);
        }

        MasternodeListResponse {
            masternodes: result,
        }
    }

    pub fn count(&self) -> MasternodeCountResponse {
        MasternodeCountResponse {
            total: self.manager.count(),
            enabled: self.manager.count_enabled(),
            copper: self.manager.count_by_tier(MasternodeTier::Copper),
            silver: self.manager.count_by_tier(MasternodeTier::Silver),
            gold: self.manager.count_by_tier(MasternodeTier::Gold),
            platinum: self.manager.count_by_tier(MasternodeTier::Platinum),
            diamond: self.manager.count_by_tier(MasternodeTier::Diamond),
        }
    }

    pub fn get_winners(
        &self,
        vote_tracker: &PaymentVoteTracker,
        start_height: i32,
        count: usize,
    ) -> Vec<MasternodeWinnerInfo> {
        let mut winners = Vec::new();

        for i in 0..count {
            let height = start_height + i as i32;
            let winner_outpoint = vote_tracker.get_consensus_winner(height);

            let (winner_str, payee_str) = if let Some(outpoint) = winner_outpoint {
                let winner = format!("{}:{}", outpoint.txid, outpoint.vout);

                if let Some(mn) = self.manager.get(outpoint) {
                    let payee = hex::encode(mn.pubkey_masternode.as_slice());
                    (Some(winner), Some(payee))
                } else {
                    (Some(winner), None)
                }
            } else {
                (None, None)
            };

            winners.push(MasternodeWinnerInfo {
                height,
                winner: winner_str,
                payee: payee_str,
            });
        }

        winners
    }

    pub fn get_status(&self, outpoint: OutPoint) -> Result<MasternodeInfo, String> {
        if let Some(mn) = self.manager.get(outpoint) {
            Ok(MasternodeInfo {
                address: format!("{:?}", mn.addr),
                status: status_to_string(mn.status),
                protocol: mn.protocol_version,
                tier: tier_to_string(mn.tier),
                lastseen: mn.time_last_checked,
                lastpaid: mn.time_last_paid,
                pose_score: mn.pose_score,
            })
        } else {
            Err(format!(
                "Masternode not found: {}:{}",
                outpoint.txid, outpoint.vout
            ))
        }
    }

    pub fn get_current_winner(
        &self,
        vote_tracker: &PaymentVoteTracker,
        height: i32,
    ) -> Option<MasternodeWinnerInfo> {
        let winner_outpoint = vote_tracker.get_consensus_winner(height);

        let (winner_str, payee_str) = if let Some(outpoint) = winner_outpoint {
            let winner = format!("{}:{}", outpoint.txid, outpoint.vout);

            if let Some(mn) = self.manager.get(outpoint) {
                let payee = hex::encode(mn.pubkey_masternode.as_slice());
                (Some(winner), Some(payee))
            } else {
                (Some(winner), None)
            }
        } else {
            (None, None)
        };

        Some(MasternodeWinnerInfo {
            height,
            winner: winner_str,
            payee: payee_str,
        })
    }
}

fn status_to_string(status: MasternodeStatus) -> String {
    match status {
        MasternodeStatus::PreEnabled => "PRE_ENABLED".to_string(),
        MasternodeStatus::Enabled => "ENABLED".to_string(),
        MasternodeStatus::Expired => "EXPIRED".to_string(),
        MasternodeStatus::OutpointSpent => "OUTPOINT_SPENT".to_string(),
        MasternodeStatus::Remove => "REMOVE".to_string(),
        MasternodeStatus::WatchdogExpired => "WATCHDOG_EXPIRED".to_string(),
        MasternodeStatus::PoseBan => "POSE_BAN".to_string(),
        MasternodeStatus::VinSpent => "VIN_SPENT".to_string(),
    }
}

fn tier_to_string(tier: MasternodeTier) -> String {
    match tier {
        MasternodeTier::Copper => "COPPER".to_string(),
        MasternodeTier::Silver => "SILVER".to_string(),
        MasternodeTier::Gold => "GOLD".to_string(),
        MasternodeTier::Platinum => "PLATINUM".to_string(),
        MasternodeTier::Diamond => "DIAMOND".to_string(),
        MasternodeTier::Invalid => "INVALID".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masternode::{MasternodeBroadcast, ServiceAddr};
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn test_rpc_new() {
        let manager = MasternodeManager::new();
        let rpc = MasternodeRpc::new(manager);
        assert_eq!(rpc.count().total, 0);
    }

    #[test]
    fn test_rpc_list_empty() {
        let manager = MasternodeManager::new();
        let rpc = MasternodeRpc::new(manager);
        let result = rpc.list(None);
        assert!(result.masternodes.is_empty());
    }

    #[test]
    fn test_rpc_list_status_mode() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let mnb = MasternodeBroadcast::new(
            outpoint,
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
            0,
        );
        manager.add(mnb).unwrap();
        manager
            .update_status(outpoint, MasternodeStatus::Enabled)
            .unwrap();

        let rpc = MasternodeRpc::new(manager);
        let result = rpc.list(Some("status".to_string()));

        assert_eq!(result.masternodes.len(), 1);
        let key = format!("{}:{}", Hash256::zero(), 0);
        assert!(result.masternodes.contains_key(&key));
        assert_eq!(result.masternodes[&key].status, "ENABLED");
    }

    #[test]
    fn test_rpc_list_full_mode() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let mnb = MasternodeBroadcast::new(
            outpoint,
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Platinum,
            70000,
            0,
        );
        manager.add(mnb).unwrap();

        let rpc = MasternodeRpc::new(manager);
        let result = rpc.list(Some("full".to_string()));

        assert_eq!(result.masternodes.len(), 1);
        let key = format!("{}:{}", Hash256::zero(), 0);
        let info = &result.masternodes[&key];
        assert_eq!(info.tier, "PLATINUM");
        assert_eq!(info.protocol, 70000);
    }

    #[test]
    fn test_rpc_count_empty() {
        let manager = MasternodeManager::new();
        let rpc = MasternodeRpc::new(manager);
        let result = rpc.count();

        assert_eq!(result.total, 0);
        assert_eq!(result.enabled, 0);
        assert_eq!(result.copper, 0);
        assert_eq!(result.silver, 0);
        assert_eq!(result.gold, 0);
        assert_eq!(result.platinum, 0);
        assert_eq!(result.diamond, 0);
    }

    #[test]
    fn test_rpc_count_mixed_tiers() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        let tiers = vec![
            MasternodeTier::Copper,
            MasternodeTier::Copper,
            MasternodeTier::Silver,
            MasternodeTier::Gold,
            MasternodeTier::Diamond,
        ];

        for (i, tier) in tiers.iter().enumerate() {
            let outpoint = OutPoint::new(Hash256::zero(), i as u32);
            let mnb = MasternodeBroadcast::new(
                outpoint,
                addr.clone(),
                vec![1, 2, 3],
                vec![4, 5, 6],
                *tier,
                70000,
                0,
            );
            manager.add(mnb).unwrap();
            if i % 2 == 0 {
                manager
                    .update_status(outpoint, MasternodeStatus::Enabled)
                    .unwrap();
            }
        }

        let rpc = MasternodeRpc::new(manager);
        let result = rpc.count();

        assert_eq!(result.total, 5);
        assert_eq!(result.enabled, 3);
        assert_eq!(result.copper, 2);
        assert_eq!(result.silver, 1);
        assert_eq!(result.gold, 1);
        assert_eq!(result.platinum, 0);
        assert_eq!(result.diamond, 1);
    }

    #[test]
    fn test_rpc_get_winners_empty() {
        let manager = MasternodeManager::new();
        let tracker = PaymentVoteTracker::new(10, 3);
        let rpc = MasternodeRpc::new(manager);

        let winners = rpc.get_winners(&tracker, 100, 5);

        assert_eq!(winners.len(), 5);
        for winner in winners {
            assert!(winner.winner.is_none());
            assert!(winner.payee.is_none());
        }
    }

    #[test]
    fn test_status_to_string() {
        assert_eq!(status_to_string(MasternodeStatus::Enabled), "ENABLED");
        assert_eq!(
            status_to_string(MasternodeStatus::PreEnabled),
            "PRE_ENABLED"
        );
        assert_eq!(status_to_string(MasternodeStatus::Expired), "EXPIRED");
    }

    #[test]
    fn test_tier_to_string() {
        assert_eq!(tier_to_string(MasternodeTier::Copper), "COPPER");
        assert_eq!(tier_to_string(MasternodeTier::Silver), "SILVER");
        assert_eq!(tier_to_string(MasternodeTier::Gold), "GOLD");
        assert_eq!(tier_to_string(MasternodeTier::Platinum), "PLATINUM");
        assert_eq!(tier_to_string(MasternodeTier::Diamond), "DIAMOND");
    }

    #[test]
    fn test_rpc_get_status_not_found() {
        let manager = MasternodeManager::new();
        let rpc = MasternodeRpc::new(manager);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let result = rpc.get_status(outpoint);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_rpc_get_status_found() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let mnb = MasternodeBroadcast::new(
            outpoint,
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Silver,
            70000,
            0,
        );
        manager.add(mnb).unwrap();
        manager
            .update_status(outpoint, MasternodeStatus::Enabled)
            .unwrap();

        let rpc = MasternodeRpc::new(manager);
        let result = rpc.get_status(outpoint);

        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.status, "ENABLED");
        assert_eq!(info.tier, "SILVER");
        assert_eq!(info.protocol, 70000);
    }

    #[test]
    fn test_rpc_get_current_winner_no_votes() {
        let manager = MasternodeManager::new();
        let tracker = PaymentVoteTracker::new(10, 3);
        let rpc = MasternodeRpc::new(manager);

        let winner = rpc.get_current_winner(&tracker, 100);

        assert!(winner.is_some());
        let winner_info = winner.unwrap();
        assert_eq!(winner_info.height, 100);
        assert!(winner_info.winner.is_none());
        assert!(winner_info.payee.is_none());
    }

    #[test]
    fn test_rpc_get_current_winner_with_vote() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let mnb = MasternodeBroadcast::new(
            outpoint,
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
            0,
        );
        manager.add(mnb).unwrap();

        let tracker = PaymentVoteTracker::new(10, 1);
        let vote = crate::masternode::MasternodePaymentWinner::new(outpoint, 100, vec![]);
        tracker.add_vote(vote).unwrap();

        let rpc = MasternodeRpc::new(manager);
        let winner = rpc.get_current_winner(&tracker, 100);

        assert!(winner.is_some());
        let winner_info = winner.unwrap();
        assert_eq!(winner_info.height, 100);
        assert!(winner_info.winner.is_some());
        assert!(winner_info.payee.is_some());
        assert_eq!(
            winner_info.winner.unwrap(),
            format!("{}:0", Hash256::zero())
        );
    }

    #[test]
    fn test_rpc_get_status_multiple_statuses() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        let test_cases = vec![
            (MasternodeStatus::PreEnabled, "PRE_ENABLED"),
            (MasternodeStatus::Enabled, "ENABLED"),
            (MasternodeStatus::Expired, "EXPIRED"),
            (MasternodeStatus::PoseBan, "POSE_BAN"),
        ];

        for (i, (status, expected_str)) in test_cases.iter().enumerate() {
            let manager = MasternodeManager::new();
            let outpoint = OutPoint::new(Hash256::zero(), i as u32);
            let mnb = MasternodeBroadcast::new(
                outpoint,
                addr.clone(),
                vec![1, 2, 3],
                vec![4, 5, 6],
                MasternodeTier::Copper,
                70000,
                0,
            );
            manager.add(mnb).unwrap();
            manager.update_status(outpoint, *status).unwrap();

            let rpc = MasternodeRpc::new(manager);
            let result = rpc.get_status(outpoint).unwrap();
            assert_eq!(result.status, *expected_str);
        }
    }

    #[test]
    fn test_rpc_get_winners_with_multiple_votes() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        let outpoint1 = OutPoint::new(Hash256::zero(), 0);
        let outpoint2 = OutPoint::new(Hash256::zero(), 1);

        let mnb1 = MasternodeBroadcast::new(
            outpoint1,
            addr.clone(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Diamond,
            70000,
            0,
        );
        let mnb2 = MasternodeBroadcast::new(
            outpoint2,
            addr,
            vec![7, 8, 9],
            vec![10, 11, 12],
            MasternodeTier::Platinum,
            70000,
            0,
        );
        manager.add(mnb1).unwrap();
        manager.add(mnb2).unwrap();

        let tracker = PaymentVoteTracker::new(10, 1);
        let vote1 = crate::masternode::MasternodePaymentWinner::new(outpoint1, 100, vec![]);
        let vote2 = crate::masternode::MasternodePaymentWinner::new(outpoint2, 101, vec![]);
        tracker.add_vote(vote1).unwrap();
        tracker.add_vote(vote2).unwrap();

        let rpc = MasternodeRpc::new(manager);
        let winners = rpc.get_winners(&tracker, 100, 2);

        assert_eq!(winners.len(), 2);
        assert!(winners[0].winner.is_some());
        assert!(winners[1].winner.is_some());
        assert_eq!(winners[0].height, 100);
        assert_eq!(winners[1].height, 101);
    }

    #[test]
    fn test_rpc_get_current_winner_masternode_not_in_registry() {
        let manager = MasternodeManager::new();
        let tracker = PaymentVoteTracker::new(10, 1);

        let outpoint = OutPoint::new(Hash256::zero(), 99);
        let vote = crate::masternode::MasternodePaymentWinner::new(outpoint, 100, vec![]);
        tracker.add_vote(vote).unwrap();

        let rpc = MasternodeRpc::new(manager);
        let winner = rpc.get_current_winner(&tracker, 100);

        assert!(winner.is_some());
        let winner_info = winner.unwrap();
        assert!(winner_info.winner.is_some());
        assert!(winner_info.payee.is_none());
    }

    #[test]
    fn test_rpc_list_addr_mode() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let mnb = MasternodeBroadcast::new(
            outpoint,
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Diamond,
            70000,
            0,
        );
        manager.add(mnb).unwrap();

        let rpc = MasternodeRpc::new(manager);
        let result = rpc.list(Some("addr".to_string()));

        assert_eq!(result.masternodes.len(), 1);
        let key = format!("{}:{}", Hash256::zero(), 0);
        let info = &result.masternodes[&key];
        assert!(!info.address.is_empty());
        assert_eq!(info.status, "");
        assert_eq!(info.tier, "");
        assert_eq!(info.protocol, 0);
    }

    #[test]
    fn test_rpc_count_only_enabled() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        for i in 0..5 {
            let outpoint = OutPoint::new(Hash256::zero(), i);
            let mnb = MasternodeBroadcast::new(
                outpoint,
                addr.clone(),
                vec![1, 2, 3],
                vec![4, 5, 6],
                MasternodeTier::Silver,
                70000,
                0,
            );
            manager.add(mnb).unwrap();
        }

        manager
            .update_status(OutPoint::new(Hash256::zero(), 0), MasternodeStatus::Enabled)
            .unwrap();
        manager
            .update_status(OutPoint::new(Hash256::zero(), 1), MasternodeStatus::Enabled)
            .unwrap();
        manager
            .update_status(OutPoint::new(Hash256::zero(), 2), MasternodeStatus::Expired)
            .unwrap();

        let rpc = MasternodeRpc::new(manager);
        let result = rpc.count();

        assert_eq!(result.total, 5);
        assert_eq!(result.enabled, 2);
        assert_eq!(result.silver, 5);
    }

    #[test]
    fn test_rpc_get_winners_sequential_heights() {
        let manager = MasternodeManager::new();
        let tracker = PaymentVoteTracker::new(10, 1);

        let rpc = MasternodeRpc::new(manager);
        let winners = rpc.get_winners(&tracker, 1000, 10);

        assert_eq!(winners.len(), 10);
        for (i, winner) in winners.iter().enumerate() {
            assert_eq!(winner.height, 1000 + i as i32);
        }
    }

    #[test]
    fn test_rpc_list_with_multiple_tiers() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        let tiers = vec![
            MasternodeTier::Copper,
            MasternodeTier::Silver,
            MasternodeTier::Gold,
            MasternodeTier::Platinum,
            MasternodeTier::Diamond,
        ];

        for (i, tier) in tiers.iter().enumerate() {
            let outpoint = OutPoint::new(Hash256::zero(), i as u32);
            let mnb = MasternodeBroadcast::new(
                outpoint,
                addr.clone(),
                vec![1, 2, 3],
                vec![4, 5, 6],
                *tier,
                70000,
                0,
            );
            manager.add(mnb).unwrap();
        }

        let rpc = MasternodeRpc::new(manager);
        let result = rpc.list(Some("full".to_string()));

        assert_eq!(result.masternodes.len(), 5);

        let tier_names: Vec<String> = result
            .masternodes
            .values()
            .map(|info| info.tier.clone())
            .collect();

        assert!(tier_names.contains(&"COPPER".to_string()));
        assert!(tier_names.contains(&"SILVER".to_string()));
        assert!(tier_names.contains(&"GOLD".to_string()));
        assert!(tier_names.contains(&"PLATINUM".to_string()));
        assert!(tier_names.contains(&"DIAMOND".to_string()));
    }

    #[test]
    fn test_rpc_get_status_with_different_protocols() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        let protocols = vec![70000, 70001, 70002, 70003];

        for (i, protocol) in protocols.iter().enumerate() {
            let outpoint = OutPoint::new(Hash256::zero(), i as u32);
            let mnb = MasternodeBroadcast::new(
                outpoint,
                addr.clone(),
                vec![1, 2, 3],
                vec![4, 5, 6],
                MasternodeTier::Gold,
                *protocol,
                0,
            );
            manager.add(mnb).unwrap();

            let rpc = MasternodeRpc::new(manager.clone());
            let result = rpc.get_status(outpoint).unwrap();
            assert_eq!(result.protocol, *protocol);
        }
    }

    #[test]
    fn test_rpc_count_all_tiers() {
        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        let tier_counts = vec![
            (MasternodeTier::Copper, 10),
            (MasternodeTier::Silver, 5),
            (MasternodeTier::Gold, 3),
            (MasternodeTier::Platinum, 2),
            (MasternodeTier::Diamond, 1),
        ];

        let mut vout = 0u32;
        for (tier, count) in tier_counts {
            for _ in 0..count {
                let outpoint = OutPoint::new(Hash256::zero(), vout);
                let mnb = MasternodeBroadcast::new(
                    outpoint,
                    addr.clone(),
                    vec![1, 2, 3],
                    vec![4, 5, 6],
                    tier,
                    70000,
                    0,
                );
                manager.add(mnb).unwrap();
                vout += 1;
            }
        }

        let rpc = MasternodeRpc::new(manager);
        let result = rpc.count();

        assert_eq!(result.total, 21);
        assert_eq!(result.copper, 10);
        assert_eq!(result.silver, 5);
        assert_eq!(result.gold, 3);
        assert_eq!(result.platinum, 2);
        assert_eq!(result.diamond, 1);
    }

    #[test]
    fn test_rpc_get_winners_empty_range() {
        let manager = MasternodeManager::new();
        let tracker = PaymentVoteTracker::new(10, 1);

        let rpc = MasternodeRpc::new(manager);
        let winners = rpc.get_winners(&tracker, 100, 0);

        assert_eq!(winners.len(), 0);
    }

    #[test]
    fn test_rpc_get_status_invalid_outpoint() {
        let manager = MasternodeManager::new();
        let rpc = MasternodeRpc::new(manager);

        let outpoint = OutPoint::new(Hash256::zero(), 999);
        let result = rpc.get_status(outpoint);

        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("not found"));
        assert!(error_msg.contains(&format!("{}", Hash256::zero())));
        assert!(error_msg.contains("999"));
    }

    #[test]
    fn test_masternode_info_json_includes_pose_score() {
        let info = MasternodeInfo {
            address: "[::1]:9999".to_string(),
            status: "ENABLED".to_string(),
            protocol: 70000,
            tier: "GOLD".to_string(),
            lastseen: 1234567890,
            lastpaid: 1234567800,
            pose_score: 5,
        };

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["pose_score"], 5);
        assert_eq!(json["status"], "ENABLED");
        assert_eq!(json["tier"], "GOLD");
    }
}
