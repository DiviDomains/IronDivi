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

use crate::masternode::{MasternodeBroadcast, MasternodePaymentWinner, MasternodePing};
use divi_primitives::error::Error;
use divi_primitives::serialize::{Decodable, Encodable};
use divi_primitives::transaction::OutPoint;

pub const MESSAGE_DSEG: &str = "dseg";
pub const MESSAGE_MNB: &str = "mnb";
pub const MESSAGE_MNP: &str = "mnp";
pub const MESSAGE_MNW: &str = "mnw";
pub const MESSAGE_MNWB: &str = "mnwb";
pub const MESSAGE_SSC: &str = "ssc";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasternodeMessage {
    RequestList(RequestMasternodeList),
    Broadcast(MasternodeBroadcast),
    Ping(MasternodePing),
    PaymentVote(MasternodePaymentWinner),
    PaymentBlock(MasternodePaymentBlock),
    SyncStatusCount(SyncStatusCount),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMasternodeList {
    pub vin: Option<OutPoint>,
}

impl RequestMasternodeList {
    pub fn new() -> Self {
        RequestMasternodeList { vin: None }
    }

    pub fn for_masternode(vin: OutPoint) -> Self {
        RequestMasternodeList { vin: Some(vin) }
    }

    pub fn is_full_list(&self) -> bool {
        self.vin.is_none()
    }
}

impl Default for RequestMasternodeList {
    fn default() -> Self {
        Self::new()
    }
}

impl Encodable for RequestMasternodeList {
    fn encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        // The dseg message format is:
        // - If requesting full list: no vin (empty message)
        // - If requesting specific masternode: serialize the vin
        if let Some(ref vin) = self.vin {
            vin.encode(writer)
        } else {
            // Empty message for full list request
            Ok(0)
        }
    }

    fn encoded_size(&self) -> usize {
        if let Some(ref vin) = self.vin {
            vin.encoded_size()
        } else {
            0
        }
    }
}

impl Decodable for RequestMasternodeList {
    fn decode<R: std::io::Read>(reader: &mut R) -> Result<Self, Error> {
        // Try to read an OutPoint - if the payload is empty, it's a full list request
        // We peek by trying to read - if we get UnexpectedEof, it's empty
        match OutPoint::decode(reader) {
            Ok(vin) => Ok(RequestMasternodeList { vin: Some(vin) }),
            Err(Error::UnexpectedEof) => {
                // Empty payload means request full list
                Ok(RequestMasternodeList { vin: None })
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasternodePaymentBlock {
    pub block_height: i32,
    pub winners: Vec<MasternodePaymentWinner>,
}

impl MasternodePaymentBlock {
    pub fn new(block_height: i32) -> Self {
        MasternodePaymentBlock {
            block_height,
            winners: Vec::new(),
        }
    }

    pub fn add_winner(&mut self, winner: MasternodePaymentWinner) {
        self.winners.push(winner);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStage {
    Initial = 0,
    Sporks = 1,
    List = 2,
    Winners = 3,
    Finished = 998,
    Failed = 999,
}

impl SyncStage {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => SyncStage::Initial,
            1 => SyncStage::Sporks,
            2 => SyncStage::List,
            3 => SyncStage::Winners,
            998 => SyncStage::Finished,
            999 => SyncStage::Failed,
            _ => SyncStage::Initial,
        }
    }

    pub fn to_u32(self) -> u32 {
        self as u32
    }

    pub fn is_synced(self) -> bool {
        self == SyncStage::Finished
    }

    pub fn name(self) -> &'static str {
        match self {
            SyncStage::Initial => "INITIAL",
            SyncStage::Sporks => "SPORKS",
            SyncStage::List => "LIST",
            SyncStage::Winners => "WINNERS",
            SyncStage::Finished => "FINISHED",
            SyncStage::Failed => "FAILED",
        }
    }
}

impl Default for SyncStage {
    fn default() -> Self {
        SyncStage::Initial
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatusCount {
    pub stage: SyncStage,
    pub item_count: u32,
}

impl SyncStatusCount {
    pub fn new(stage: SyncStage, item_count: u32) -> Self {
        SyncStatusCount { stage, item_count }
    }
}

#[derive(Clone)]
pub struct SyncStatus {
    current_stage: SyncStage,
    last_update_time: i64,
    request_count: u32,
    timeout_seconds: i64,
}

impl SyncStatus {
    pub fn new() -> Self {
        SyncStatus {
            current_stage: SyncStage::Initial,
            last_update_time: 0,
            request_count: 0,
            timeout_seconds: 5 * 60,
        }
    }

    pub fn current_stage(&self) -> SyncStage {
        self.current_stage
    }

    pub fn is_synced(&self) -> bool {
        self.current_stage.is_synced()
    }

    pub fn advance_to(&mut self, stage: SyncStage, current_time: i64) {
        self.current_stage = stage;
        self.last_update_time = current_time;
        self.request_count = 0;
    }

    pub fn bump_request(&mut self) {
        self.request_count += 1;
    }

    pub fn is_timeout(&self, current_time: i64) -> bool {
        current_time - self.last_update_time > self.timeout_seconds
    }

    pub fn process_tick(
        &mut self,
        current_time: i64,
        masternode_count: usize,
        winner_count: usize,
    ) -> Option<SyncAction> {
        if self.is_synced() {
            return None;
        }

        match self.current_stage {
            SyncStage::Initial | SyncStage::Failed => {
                self.advance_to(SyncStage::Sporks, current_time);
                Some(SyncAction::RequestSporks)
            }

            SyncStage::Sporks => {
                if self.is_timeout(current_time) {
                    self.advance_to(SyncStage::List, current_time);
                    Some(SyncAction::RequestMasternodeList)
                } else {
                    None
                }
            }

            SyncStage::List => {
                if masternode_count > 0 {
                    self.advance_to(SyncStage::Winners, current_time);
                    Some(SyncAction::RequestWinners)
                } else if self.is_timeout(current_time) {
                    self.bump_request();
                    self.last_update_time = current_time;
                    Some(SyncAction::RequestMasternodeList)
                } else {
                    None
                }
            }

            SyncStage::Winners => {
                if winner_count > 0 {
                    self.advance_to(SyncStage::Finished, current_time);
                    Some(SyncAction::SyncComplete)
                } else if self.is_timeout(current_time) {
                    self.bump_request();
                    self.last_update_time = current_time;
                    Some(SyncAction::RequestWinners)
                } else {
                    None
                }
            }

            SyncStage::Finished => None,
        }
    }

    pub fn reset(&mut self) {
        self.current_stage = SyncStage::Initial;
        self.last_update_time = 0;
        self.request_count = 0;
    }
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    RequestSporks,
    RequestMasternodeList,
    RequestWinners,
    SyncComplete,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_stage_conversion() {
        assert_eq!(SyncStage::from_u32(0), SyncStage::Initial);
        assert_eq!(SyncStage::from_u32(1), SyncStage::Sporks);
        assert_eq!(SyncStage::from_u32(2), SyncStage::List);
        assert_eq!(SyncStage::from_u32(3), SyncStage::Winners);
        assert_eq!(SyncStage::from_u32(998), SyncStage::Finished);
        assert_eq!(SyncStage::from_u32(999), SyncStage::Failed);
        assert_eq!(SyncStage::from_u32(9999), SyncStage::Initial);
    }

    #[test]
    fn test_sync_stage_to_u32() {
        assert_eq!(SyncStage::Initial.to_u32(), 0);
        assert_eq!(SyncStage::Sporks.to_u32(), 1);
        assert_eq!(SyncStage::List.to_u32(), 2);
        assert_eq!(SyncStage::Winners.to_u32(), 3);
        assert_eq!(SyncStage::Finished.to_u32(), 998);
        assert_eq!(SyncStage::Failed.to_u32(), 999);
    }

    #[test]
    fn test_sync_stage_is_synced() {
        assert!(!SyncStage::Initial.is_synced());
        assert!(!SyncStage::Sporks.is_synced());
        assert!(!SyncStage::List.is_synced());
        assert!(!SyncStage::Winners.is_synced());
        assert!(SyncStage::Finished.is_synced());
        assert!(!SyncStage::Failed.is_synced());
    }

    #[test]
    fn test_sync_stage_names() {
        assert_eq!(SyncStage::Initial.name(), "INITIAL");
        assert_eq!(SyncStage::Sporks.name(), "SPORKS");
        assert_eq!(SyncStage::List.name(), "LIST");
        assert_eq!(SyncStage::Winners.name(), "WINNERS");
        assert_eq!(SyncStage::Finished.name(), "FINISHED");
        assert_eq!(SyncStage::Failed.name(), "FAILED");
    }

    #[test]
    fn test_request_masternode_list() {
        let req = RequestMasternodeList::new();
        assert!(req.is_full_list());
        assert_eq!(req.vin, None);

        let outpoint = OutPoint::null();
        let req = RequestMasternodeList::for_masternode(outpoint);
        assert!(!req.is_full_list());
        assert_eq!(req.vin, Some(outpoint));
    }

    #[test]
    fn test_masternode_payment_block() {
        let mut block = MasternodePaymentBlock::new(12345);
        assert_eq!(block.block_height, 12345);
        assert_eq!(block.winners.len(), 0);

        let winner = MasternodePaymentWinner::new(OutPoint::null(), 12345, vec![1, 2, 3]);
        block.add_winner(winner.clone());
        assert_eq!(block.winners.len(), 1);
        assert_eq!(block.winners[0], winner);
    }

    #[test]
    fn test_sync_status_creation() {
        let status = SyncStatus::new();
        assert_eq!(status.current_stage(), SyncStage::Initial);
        assert!(!status.is_synced());
        assert_eq!(status.request_count, 0);
    }

    #[test]
    fn test_sync_status_advance() {
        let mut status = SyncStatus::new();
        status.advance_to(SyncStage::Sporks, 1000);
        assert_eq!(status.current_stage(), SyncStage::Sporks);
        assert_eq!(status.last_update_time, 1000);
        assert_eq!(status.request_count, 0);
    }

    #[test]
    fn test_sync_status_timeout() {
        let mut status = SyncStatus::new();
        status.last_update_time = 1000;
        status.timeout_seconds = 300;

        assert!(!status.is_timeout(1200));
        assert!(status.is_timeout(1301));
    }

    #[test]
    fn test_sync_status_process_tick_initial() {
        let mut status = SyncStatus::new();
        let action = status.process_tick(1000, 0, 0);
        assert_eq!(action, Some(SyncAction::RequestSporks));
        assert_eq!(status.current_stage(), SyncStage::Sporks);
    }

    #[test]
    fn test_sync_status_process_tick_sporks_timeout() {
        let mut status = SyncStatus::new();
        status.advance_to(SyncStage::Sporks, 1000);
        status.timeout_seconds = 100;

        let action = status.process_tick(1101, 0, 0);
        assert_eq!(action, Some(SyncAction::RequestMasternodeList));
        assert_eq!(status.current_stage(), SyncStage::List);
    }

    #[test]
    fn test_sync_status_process_tick_list_got_masternodes() {
        let mut status = SyncStatus::new();
        status.advance_to(SyncStage::List, 1000);

        let action = status.process_tick(1100, 10, 0);
        assert_eq!(action, Some(SyncAction::RequestWinners));
        assert_eq!(status.current_stage(), SyncStage::Winners);
    }

    #[test]
    fn test_sync_status_process_tick_list_timeout() {
        let mut status = SyncStatus::new();
        status.advance_to(SyncStage::List, 1000);
        status.timeout_seconds = 100;

        let action = status.process_tick(1101, 0, 0);
        assert_eq!(action, Some(SyncAction::RequestMasternodeList));
        assert_eq!(status.current_stage(), SyncStage::List);
        assert_eq!(status.request_count, 1);
    }

    #[test]
    fn test_sync_status_process_tick_winners_got_winners() {
        let mut status = SyncStatus::new();
        status.advance_to(SyncStage::Winners, 1000);

        let action = status.process_tick(1100, 10, 5);
        assert_eq!(action, Some(SyncAction::SyncComplete));
        assert_eq!(status.current_stage(), SyncStage::Finished);
        assert!(status.is_synced());
    }

    #[test]
    fn test_sync_status_process_tick_finished() {
        let mut status = SyncStatus::new();
        status.advance_to(SyncStage::Finished, 1000);

        let action = status.process_tick(2000, 10, 5);
        assert_eq!(action, None);
        assert_eq!(status.current_stage(), SyncStage::Finished);
    }

    #[test]
    fn test_sync_status_reset() {
        let mut status = SyncStatus::new();
        status.advance_to(SyncStage::Finished, 1000);
        status.bump_request();

        status.reset();
        assert_eq!(status.current_stage(), SyncStage::Initial);
        assert_eq!(status.last_update_time, 0);
        assert_eq!(status.request_count, 0);
    }

    #[test]
    fn test_sync_status_complete_flow() {
        let mut status = SyncStatus::new();
        status.timeout_seconds = 100;

        let action = status.process_tick(1000, 0, 0);
        assert_eq!(action, Some(SyncAction::RequestSporks));
        assert_eq!(status.current_stage(), SyncStage::Sporks);

        let action = status.process_tick(1101, 0, 0);
        assert_eq!(action, Some(SyncAction::RequestMasternodeList));
        assert_eq!(status.current_stage(), SyncStage::List);

        let action = status.process_tick(1200, 10, 0);
        assert_eq!(action, Some(SyncAction::RequestWinners));
        assert_eq!(status.current_stage(), SyncStage::Winners);

        let action = status.process_tick(1300, 10, 5);
        assert_eq!(action, Some(SyncAction::SyncComplete));
        assert_eq!(status.current_stage(), SyncStage::Finished);

        let action = status.process_tick(2000, 10, 5);
        assert_eq!(action, None);
        assert!(status.is_synced());
    }
}
