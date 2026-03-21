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

use crate::constants::{
    MASTERNODE_PAYMENT_FORK_HEIGHT, MASTERNODE_PAYMENT_PERCENTAGE_POST_FORK,
    MASTERNODE_PAYMENT_PERCENTAGE_PRE_FORK,
};
use crate::manager::MasternodeManager;
use crate::masternode::{Masternode, MasternodePaymentWinner, MasternodeStatus};
use crate::tier::MasternodeTier;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::{OutPoint, Transaction};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

pub fn calculate_score(outpoint: &OutPoint, tier: MasternodeTier, block_hash: &Hash256) -> Hash256 {
    let rounds = tier.score_multiplier();

    let mut hasher = Sha256::new();
    hasher.update(block_hash.as_bytes());
    hasher.update(&outpoint.txid.as_bytes());
    hasher.update(&outpoint.vout.to_le_bytes());

    let mut hash = double_sha256(&hasher.finalize());

    for _ in 0..rounds {
        hash = double_sha256(&hash);
    }

    Hash256::from_bytes(hash)
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

impl Masternode {
    pub fn calculate_score(&self, block_hash: &Hash256) -> Hash256 {
        calculate_score(&self.vin, self.tier, block_hash)
    }

    pub fn is_valid_for_payment(&self) -> bool {
        // Must be enabled AND not PoSe-banned AND pose_score < 100
        self.status == MasternodeStatus::Enabled && self.pose_score < 100
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentWinner {
    pub masternode: Masternode,
    pub score: Hash256,
}

pub fn find_payment_winner(
    manager: &MasternodeManager,
    block_hash: &Hash256,
) -> Option<PaymentWinner> {
    let masternodes = manager.get_enabled();

    if masternodes.is_empty() {
        return None;
    }

    let mut best_score = Hash256::zero();
    let mut best_masternode: Option<Masternode> = None;

    for mn in masternodes {
        if !mn.is_valid_for_payment() {
            continue;
        }

        let score = mn.calculate_score(block_hash);

        if score > best_score {
            best_score = score;
            best_masternode = Some(mn);
        }
    }

    best_masternode.map(|mn| PaymentWinner {
        masternode: mn,
        score: best_score,
    })
}

pub fn find_top_n_winners(
    manager: &MasternodeManager,
    block_hash: &Hash256,
    n: usize,
) -> Vec<PaymentWinner> {
    let masternodes = manager.get_enabled();

    if masternodes.is_empty() || n == 0 {
        return Vec::new();
    }

    let mut winners: Vec<PaymentWinner> = masternodes
        .into_iter()
        .filter(|mn| mn.is_valid_for_payment())
        .map(|mn| {
            let score = mn.calculate_score(block_hash);
            PaymentWinner {
                masternode: mn,
                score,
            }
        })
        .collect();

    winners.sort_by(|a, b| b.score.cmp(&a.score));
    winners.truncate(n);
    winners
}

pub fn calculate_block_subsidy(block_height: i32) -> Amount {
    if block_height < MASTERNODE_PAYMENT_FORK_HEIGHT as i32 {
        Amount::from_divi(1250)
    } else if block_height < 345600 {
        Amount::from_divi(2433)
    } else {
        let years_elapsed = (block_height - 345600) / 525600;
        let base = 2433i64;
        let decay_factor = 0.95_f64;
        let subsidy = (base as f64) * decay_factor.powi(years_elapsed);
        Amount::from_divi(subsidy.max(1.0) as i64)
    }
}

pub fn calculate_masternode_payment(block_height: i32, block_reward: Amount) -> Amount {
    let percentage = if block_height < MASTERNODE_PAYMENT_FORK_HEIGHT as i32 {
        MASTERNODE_PAYMENT_PERCENTAGE_PRE_FORK
    } else {
        MASTERNODE_PAYMENT_PERCENTAGE_POST_FORK
    };

    let payment_sats = (block_reward.as_sat() as f64 * percentage) as i64;
    Amount::from_sat(payment_sats)
}

pub fn get_tier_payment_multiplier(tier: MasternodeTier) -> f64 {
    match tier {
        MasternodeTier::Copper => 1.0,
        MasternodeTier::Silver => 3.0,
        MasternodeTier::Gold => 10.0,
        MasternodeTier::Platinum => 30.0,
        MasternodeTier::Diamond => 100.0,
        MasternodeTier::Invalid => 0.0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentValidationError {
    NoExpectedPayee,
    PayeeNotFound,
    InsufficientPayment { expected: Amount, actual: Amount },
    InvalidBlockHeight,
    NoMasternodeWinner,
}

pub fn validate_block_payment(
    tx: &Transaction,
    block_height: i32,
    expected_payee: &[u8],
    block_reward: Amount,
) -> Result<(), PaymentValidationError> {
    if block_height < 0 {
        return Err(PaymentValidationError::InvalidBlockHeight);
    }

    if expected_payee.is_empty() {
        return Err(PaymentValidationError::NoExpectedPayee);
    }

    let expected_payment = calculate_masternode_payment(block_height, block_reward);

    for output in &tx.vout {
        if output.script_pubkey.as_bytes() == expected_payee {
            if output.value >= expected_payment {
                return Ok(());
            } else {
                return Err(PaymentValidationError::InsufficientPayment {
                    expected: expected_payment,
                    actual: output.value,
                });
            }
        }
    }

    Err(PaymentValidationError::PayeeNotFound)
}

pub fn get_expected_payment_winner(
    manager: &MasternodeManager,
    vote_tracker: &PaymentVoteTracker,
    block_hash: &Hash256,
    block_height: i32,
) -> Result<OutPoint, PaymentValidationError> {
    if let Some(consensus_winner) = vote_tracker.get_consensus_winner(block_height) {
        return Ok(consensus_winner);
    }

    if let Some(winner) = find_payment_winner(manager, block_hash) {
        return Ok(winner.masternode.vin);
    }

    Err(PaymentValidationError::NoMasternodeWinner)
}

#[derive(Debug, Clone)]
struct BlockVotes {
    votes: HashMap<OutPoint, Vec<MasternodePaymentWinner>>,
    consensus_winner: Option<OutPoint>,
}

impl BlockVotes {
    fn new() -> Self {
        BlockVotes {
            votes: HashMap::new(),
            consensus_winner: None,
        }
    }

    fn add_vote(&mut self, vote: MasternodePaymentWinner) {
        let votes = self
            .votes
            .entry(vote.vin_masternode)
            .or_insert_with(Vec::new);
        votes.push(vote);
        self.consensus_winner = None;
    }

    fn get_vote_count(&self, outpoint: &OutPoint) -> usize {
        self.votes.get(outpoint).map(|v| v.len()).unwrap_or(0)
    }

    fn calculate_consensus(&mut self) -> Option<OutPoint> {
        if self.votes.is_empty() {
            return None;
        }

        let mut max_votes = 0;
        let mut winner: Option<OutPoint> = None;

        for (outpoint, votes) in &self.votes {
            let vote_count = votes.len();
            if vote_count > max_votes {
                max_votes = vote_count;
                winner = Some(*outpoint);
            }
        }

        self.consensus_winner = winner;
        winner
    }

    fn get_consensus_winner(&self) -> Option<OutPoint> {
        self.consensus_winner
    }

    fn has_minimum_votes(&self, min_votes: usize) -> bool {
        self.votes.values().any(|votes| votes.len() >= min_votes)
    }
}

pub struct PaymentVoteTracker {
    votes_by_height: Arc<RwLock<HashMap<i32, BlockVotes>>>,
    vote_expiration_blocks: i32,
    minimum_votes_for_consensus: usize,
}

impl PaymentVoteTracker {
    pub fn new(vote_expiration_blocks: i32, minimum_votes_for_consensus: usize) -> Self {
        PaymentVoteTracker {
            votes_by_height: Arc::new(RwLock::new(HashMap::new())),
            vote_expiration_blocks,
            minimum_votes_for_consensus,
        }
    }

    pub fn add_vote(&self, vote: MasternodePaymentWinner) -> Result<(), String> {
        if vote.block_height < 0 {
            return Err("Invalid block height".to_string());
        }

        let mut votes = self.votes_by_height.write();
        let block_votes = votes
            .entry(vote.block_height)
            .or_insert_with(BlockVotes::new);
        block_votes.add_vote(vote);

        Ok(())
    }

    pub fn get_vote_count(&self, block_height: i32, outpoint: &OutPoint) -> usize {
        let votes = self.votes_by_height.read();
        votes
            .get(&block_height)
            .map(|bv| bv.get_vote_count(outpoint))
            .unwrap_or(0)
    }

    pub fn get_consensus_winner(&self, block_height: i32) -> Option<OutPoint> {
        let mut votes = self.votes_by_height.write();
        if let Some(block_votes) = votes.get_mut(&block_height) {
            block_votes.calculate_consensus()
        } else {
            None
        }
    }

    pub fn has_consensus(&self, block_height: i32) -> bool {
        let votes = self.votes_by_height.read();
        votes
            .get(&block_height)
            .map(|bv| bv.has_minimum_votes(self.minimum_votes_for_consensus))
            .unwrap_or(false)
    }

    pub fn cleanup_old_votes(&self, current_height: i32) {
        let expiration_height = current_height - self.vote_expiration_blocks;
        let mut votes = self.votes_by_height.write();
        votes.retain(|&height, _| height > expiration_height);
    }

    pub fn get_all_votes(&self, block_height: i32) -> Vec<(OutPoint, usize)> {
        let votes = self.votes_by_height.read();
        if let Some(block_votes) = votes.get(&block_height) {
            block_votes
                .votes
                .iter()
                .map(|(outpoint, votes)| (*outpoint, votes.len()))
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn clear(&self) {
        let mut votes = self.votes_by_height.write();
        votes.clear();
    }
}

impl Default for PaymentVoteTracker {
    fn default() -> Self {
        PaymentVoteTracker::new(10, 3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masternode::ServiceAddr;
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn test_calculate_score_deterministic() {
        let outpoint = OutPoint::new(Hash256::zero(), 0);
        let block_hash = Hash256::zero();

        let score1 = calculate_score(&outpoint, MasternodeTier::Copper, &block_hash);
        let score2 = calculate_score(&outpoint, MasternodeTier::Copper, &block_hash);

        assert_eq!(score1, score2);
    }

    #[test]
    fn test_calculate_score_different_tiers() {
        let outpoint = OutPoint::new(Hash256::zero(), 0);
        let block_hash = Hash256::zero();

        let copper_score = calculate_score(&outpoint, MasternodeTier::Copper, &block_hash);
        let gold_score = calculate_score(&outpoint, MasternodeTier::Gold, &block_hash);

        assert_ne!(copper_score, gold_score);
    }

    #[test]
    fn test_calculate_score_different_outpoints() {
        let outpoint1 = OutPoint::new(Hash256::zero(), 0);
        let outpoint2 = OutPoint::new(Hash256::zero(), 1);
        let block_hash = Hash256::zero();

        let score1 = calculate_score(&outpoint1, MasternodeTier::Copper, &block_hash);
        let score2 = calculate_score(&outpoint2, MasternodeTier::Copper, &block_hash);

        assert_ne!(score1, score2);
    }

    #[test]
    fn test_calculate_score_different_blocks() {
        let outpoint = OutPoint::new(Hash256::zero(), 0);
        let block_hash1 = Hash256::zero();
        let block_hash2 =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let score1 = calculate_score(&outpoint, MasternodeTier::Copper, &block_hash1);
        let score2 = calculate_score(&outpoint, MasternodeTier::Copper, &block_hash2);

        assert_ne!(score1, score2);
    }

    #[test]
    fn test_masternode_calculate_score() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mn = Masternode::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
        );

        let block_hash = Hash256::zero();
        let score = mn.calculate_score(&block_hash);

        assert!(!score.is_zero());
    }

    #[test]
    fn test_tier_score_multiplier_values() {
        assert_eq!(MasternodeTier::Copper.score_multiplier(), 20);
        assert_eq!(MasternodeTier::Silver.score_multiplier(), 63);
        assert_eq!(MasternodeTier::Gold.score_multiplier(), 220);
        assert_eq!(MasternodeTier::Platinum.score_multiplier(), 690);
        assert_eq!(MasternodeTier::Diamond.score_multiplier(), 2400);
    }

    #[test]
    fn test_double_sha256() {
        let data = b"test";
        let result1 = double_sha256(data);
        let result2 = double_sha256(data);

        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    #[test]
    fn test_score_ordering_copper_vs_silver() {
        let outpoint = OutPoint::new(
            Hash256::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
            0,
        );
        let block_hash =
            Hash256::from_hex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
                .unwrap();

        let copper_score = calculate_score(&outpoint, MasternodeTier::Copper, &block_hash);
        let silver_score = calculate_score(&outpoint, MasternodeTier::Silver, &block_hash);

        assert_ne!(copper_score, silver_score);
    }

    #[test]
    fn test_find_payment_winner_empty_manager() {
        let manager = MasternodeManager::new();
        let block_hash = Hash256::zero();

        let winner = find_payment_winner(&manager, &block_hash);

        assert!(winner.is_none());
    }

    #[test]
    fn test_find_payment_winner_single_masternode() {
        use crate::masternode::MasternodeBroadcast;

        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let outpoint = OutPoint::new(Hash256::zero(), 0);
        let mnb = MasternodeBroadcast::new(
            outpoint,
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Copper,
            70000,
            0,
        );

        manager.add(mnb).unwrap();
        manager
            .update_status(outpoint, MasternodeStatus::Enabled)
            .unwrap();

        let block_hash = Hash256::zero();
        let winner = find_payment_winner(&manager, &block_hash);

        assert!(winner.is_some());
        let winner = winner.unwrap();
        assert_eq!(winner.masternode.vin, outpoint);
        assert_eq!(winner.masternode.tier, MasternodeTier::Copper);
    }

    #[test]
    fn test_find_payment_winner_multiple_masternodes() {
        use crate::masternode::MasternodeBroadcast;

        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        for i in 0..5 {
            let outpoint = OutPoint::new(Hash256::zero(), i);
            let mnb = MasternodeBroadcast::new(
                outpoint,
                addr.clone(),
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
        }

        let block_hash = Hash256::zero();
        let winner = find_payment_winner(&manager, &block_hash);

        assert!(winner.is_some());
        let winner = winner.unwrap();
        assert!(!winner.score.is_zero());
    }

    #[test]
    fn test_find_payment_winner_deterministic() {
        use crate::masternode::MasternodeBroadcast;

        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        for i in 0..3 {
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
            manager
                .update_status(outpoint, MasternodeStatus::Enabled)
                .unwrap();
        }

        let block_hash = Hash256::zero();
        let winner1 = find_payment_winner(&manager, &block_hash);
        let winner2 = find_payment_winner(&manager, &block_hash);

        assert!(winner1.is_some());
        assert!(winner2.is_some());
        assert_eq!(
            winner1.unwrap().masternode.vin,
            winner2.unwrap().masternode.vin
        );
    }

    #[test]
    fn test_find_top_n_winners_empty() {
        let manager = MasternodeManager::new();
        let block_hash = Hash256::zero();

        let winners = find_top_n_winners(&manager, &block_hash, 3);

        assert!(winners.is_empty());
    }

    #[test]
    fn test_find_top_n_winners() {
        use crate::masternode::MasternodeBroadcast;

        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        for i in 0..5 {
            let outpoint = OutPoint::new(Hash256::zero(), i);
            let mnb = MasternodeBroadcast::new(
                outpoint,
                addr.clone(),
                vec![1, 2, 3],
                vec![4, 5, 6],
                MasternodeTier::Platinum,
                70000,
                0,
            );
            manager.add(mnb).unwrap();
            manager
                .update_status(outpoint, MasternodeStatus::Enabled)
                .unwrap();
        }

        let block_hash = Hash256::zero();
        let winners = find_top_n_winners(&manager, &block_hash, 3);

        assert_eq!(winners.len(), 3);
        for i in 0..winners.len() - 1 {
            assert!(winners[i].score >= winners[i + 1].score);
        }
    }

    #[test]
    fn test_find_top_n_winners_more_than_available() {
        use crate::masternode::MasternodeBroadcast;

        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        for i in 0..3 {
            let outpoint = OutPoint::new(Hash256::zero(), i);
            let mnb = MasternodeBroadcast::new(
                outpoint,
                addr.clone(),
                vec![1, 2, 3],
                vec![4, 5, 6],
                MasternodeTier::Diamond,
                70000,
                0,
            );
            manager.add(mnb).unwrap();
            manager
                .update_status(outpoint, MasternodeStatus::Enabled)
                .unwrap();
        }

        let block_hash = Hash256::zero();
        let winners = find_top_n_winners(&manager, &block_hash, 10);

        assert_eq!(winners.len(), 3);
    }

    #[test]
    fn test_masternode_is_valid_for_payment() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mut mn = Masternode::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
        );

        mn.status = MasternodeStatus::Enabled;

        assert!(mn.is_valid_for_payment());
    }

    #[test]
    fn test_vote_tracker_new() {
        let tracker = PaymentVoteTracker::new(10, 3);
        assert!(tracker.get_consensus_winner(100).is_none());
    }

    #[test]
    fn test_vote_tracker_default() {
        let tracker = PaymentVoteTracker::default();
        assert!(tracker.get_consensus_winner(100).is_none());
    }

    #[test]
    fn test_add_vote_single() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);
        let vote = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);

        let result = tracker.add_vote(vote);
        assert!(result.is_ok());
        assert_eq!(tracker.get_vote_count(100, &outpoint), 1);
    }

    #[test]
    fn test_add_vote_invalid_height() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);
        let vote = MasternodePaymentWinner::new(outpoint, -1, vec![1, 2, 3]);

        let result = tracker.add_vote(vote);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid block height");
    }

    #[test]
    fn test_add_multiple_votes_same_masternode() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        for _ in 0..3 {
            let vote = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
            tracker.add_vote(vote).unwrap();
        }

        assert_eq!(tracker.get_vote_count(100, &outpoint), 3);
    }

    #[test]
    fn test_add_votes_different_masternodes() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint1 = OutPoint::new(Hash256::zero(), 0);
        let outpoint2 = OutPoint::new(Hash256::zero(), 1);

        let vote1 = MasternodePaymentWinner::new(outpoint1, 100, vec![1, 2, 3]);
        let vote2 = MasternodePaymentWinner::new(outpoint2, 100, vec![4, 5, 6]);

        tracker.add_vote(vote1).unwrap();
        tracker.add_vote(vote2).unwrap();

        assert_eq!(tracker.get_vote_count(100, &outpoint1), 1);
        assert_eq!(tracker.get_vote_count(100, &outpoint2), 1);
    }

    #[test]
    fn test_get_consensus_winner_no_votes() {
        let tracker = PaymentVoteTracker::new(10, 3);
        assert!(tracker.get_consensus_winner(100).is_none());
    }

    #[test]
    fn test_get_consensus_winner_single_candidate() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        for _ in 0..5 {
            let vote = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
            tracker.add_vote(vote).unwrap();
        }

        let winner = tracker.get_consensus_winner(100);
        assert!(winner.is_some());
        assert_eq!(winner.unwrap(), outpoint);
    }

    #[test]
    fn test_get_consensus_winner_multiple_candidates() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint1 = OutPoint::new(Hash256::zero(), 0);
        let outpoint2 = OutPoint::new(Hash256::zero(), 1);

        for _ in 0..3 {
            let vote1 = MasternodePaymentWinner::new(outpoint1, 100, vec![1, 2, 3]);
            tracker.add_vote(vote1).unwrap();
        }

        for _ in 0..5 {
            let vote2 = MasternodePaymentWinner::new(outpoint2, 100, vec![4, 5, 6]);
            tracker.add_vote(vote2).unwrap();
        }

        let winner = tracker.get_consensus_winner(100);
        assert!(winner.is_some());
        assert_eq!(winner.unwrap(), outpoint2);
    }

    #[test]
    fn test_has_consensus_below_threshold() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        for _ in 0..2 {
            let vote = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
            tracker.add_vote(vote).unwrap();
        }

        assert!(!tracker.has_consensus(100));
    }

    #[test]
    fn test_has_consensus_at_threshold() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        for _ in 0..3 {
            let vote = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
            tracker.add_vote(vote).unwrap();
        }

        assert!(tracker.has_consensus(100));
    }

    #[test]
    fn test_has_consensus_above_threshold() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        for _ in 0..5 {
            let vote = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
            tracker.add_vote(vote).unwrap();
        }

        assert!(tracker.has_consensus(100));
    }

    #[test]
    fn test_cleanup_old_votes() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let vote1 = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
        let vote2 = MasternodePaymentWinner::new(outpoint, 150, vec![1, 2, 3]);

        tracker.add_vote(vote1).unwrap();
        tracker.add_vote(vote2).unwrap();

        assert_eq!(tracker.get_vote_count(100, &outpoint), 1);
        assert_eq!(tracker.get_vote_count(150, &outpoint), 1);

        tracker.cleanup_old_votes(155);

        assert_eq!(tracker.get_vote_count(100, &outpoint), 0);
        assert_eq!(tracker.get_vote_count(150, &outpoint), 1);
    }

    #[test]
    fn test_cleanup_preserves_recent_votes() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let vote = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
        tracker.add_vote(vote).unwrap();

        tracker.cleanup_old_votes(105);

        assert_eq!(tracker.get_vote_count(100, &outpoint), 1);
    }

    #[test]
    fn test_get_all_votes_empty() {
        let tracker = PaymentVoteTracker::new(10, 3);
        let votes = tracker.get_all_votes(100);
        assert!(votes.is_empty());
    }

    #[test]
    fn test_get_all_votes() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint1 = OutPoint::new(Hash256::zero(), 0);
        let outpoint2 = OutPoint::new(Hash256::zero(), 1);

        for _ in 0..3 {
            let vote1 = MasternodePaymentWinner::new(outpoint1, 100, vec![1, 2, 3]);
            tracker.add_vote(vote1).unwrap();
        }

        for _ in 0..2 {
            let vote2 = MasternodePaymentWinner::new(outpoint2, 100, vec![4, 5, 6]);
            tracker.add_vote(vote2).unwrap();
        }

        let votes = tracker.get_all_votes(100);
        assert_eq!(votes.len(), 2);

        let vote_map: HashMap<OutPoint, usize> = votes.into_iter().collect();
        assert_eq!(vote_map.get(&outpoint1), Some(&3));
        assert_eq!(vote_map.get(&outpoint2), Some(&2));
    }

    #[test]
    fn test_clear() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let vote = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
        tracker.add_vote(vote).unwrap();

        assert_eq!(tracker.get_vote_count(100, &outpoint), 1);

        tracker.clear();

        assert_eq!(tracker.get_vote_count(100, &outpoint), 0);
        assert!(tracker.get_consensus_winner(100).is_none());
    }

    #[test]
    fn test_votes_isolated_by_height() {
        use crate::masternode::MasternodePaymentWinner;

        let tracker = PaymentVoteTracker::new(10, 3);
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        let vote1 = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
        let vote2 = MasternodePaymentWinner::new(outpoint, 200, vec![1, 2, 3]);

        tracker.add_vote(vote1).unwrap();
        tracker.add_vote(vote2).unwrap();

        assert_eq!(tracker.get_vote_count(100, &outpoint), 1);
        assert_eq!(tracker.get_vote_count(200, &outpoint), 1);
        assert_eq!(tracker.get_vote_count(150, &outpoint), 0);
    }

    #[test]
    fn test_calculate_block_subsidy_early() {
        let subsidy = calculate_block_subsidy(100000);
        assert_eq!(subsidy, Amount::from_divi(1250));
    }

    #[test]
    fn test_calculate_block_subsidy_mid() {
        let subsidy = calculate_block_subsidy(250000);
        assert_eq!(subsidy, Amount::from_divi(2433));
    }

    #[test]
    fn test_calculate_block_subsidy_late() {
        let subsidy = calculate_block_subsidy(400000);
        assert!(subsidy > Amount::from_divi(0));
        assert!(subsidy <= Amount::from_divi(2433));
    }

    #[test]
    fn test_calculate_masternode_payment_early() {
        let block_reward = Amount::from_divi(1250);
        let payment = calculate_masternode_payment(100000, block_reward);
        let expected = Amount::from_sat(((1250i64 * 100_000_000) as f64 * 0.45) as i64);
        assert_eq!(payment, expected);
    }

    #[test]
    fn test_calculate_masternode_payment_late() {
        let block_reward = Amount::from_divi(2433);
        let payment = calculate_masternode_payment(250000, block_reward);
        let expected = Amount::from_sat(((2433i64 * 100_000_000) as f64 * 0.60) as i64);
        assert_eq!(payment, expected);
    }

    #[test]
    fn test_get_tier_payment_multiplier() {
        assert_eq!(get_tier_payment_multiplier(MasternodeTier::Copper), 1.0);
        assert_eq!(get_tier_payment_multiplier(MasternodeTier::Silver), 3.0);
        assert_eq!(get_tier_payment_multiplier(MasternodeTier::Gold), 10.0);
        assert_eq!(get_tier_payment_multiplier(MasternodeTier::Platinum), 30.0);
        assert_eq!(get_tier_payment_multiplier(MasternodeTier::Diamond), 100.0);
    }

    #[test]
    fn test_validate_block_payment_invalid_height() {
        use divi_primitives::transaction::{Transaction, TxOut};

        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![],
            lock_time: 0,
        };

        let result = validate_block_payment(&tx, -1, &[1, 2, 3], Amount::from_divi(1000));
        assert!(matches!(
            result,
            Err(PaymentValidationError::InvalidBlockHeight)
        ));
    }

    #[test]
    fn test_validate_block_payment_no_payee() {
        use divi_primitives::transaction::{Transaction, TxOut};

        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![],
            lock_time: 0,
        };

        let result = validate_block_payment(&tx, 100, &[], Amount::from_divi(1000));
        assert!(matches!(
            result,
            Err(PaymentValidationError::NoExpectedPayee)
        ));
    }

    #[test]
    fn test_validate_block_payment_payee_not_found() {
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{Transaction, TxOut};

        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![TxOut {
                value: Amount::from_divi(500),
                script_pubkey: Script::from(vec![4, 5, 6]),
            }],
            lock_time: 0,
        };

        let expected_payee = vec![1, 2, 3];
        let result = validate_block_payment(&tx, 250000, &expected_payee, Amount::from_divi(1000));
        assert!(matches!(result, Err(PaymentValidationError::PayeeNotFound)));
    }

    #[test]
    fn test_validate_block_payment_insufficient_payment() {
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{Transaction, TxOut};

        let expected_payee = vec![1, 2, 3];
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![TxOut {
                value: Amount::from_divi(100),
                script_pubkey: Script::from(expected_payee.clone()),
            }],
            lock_time: 0,
        };

        let result = validate_block_payment(&tx, 250000, &expected_payee, Amount::from_divi(2433));
        assert!(matches!(
            result,
            Err(PaymentValidationError::InsufficientPayment { .. })
        ));
    }

    #[test]
    fn test_validate_block_payment_success() {
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{Transaction, TxOut};

        let expected_payee = vec![1, 2, 3];
        let block_reward = Amount::from_divi(2433);
        let masternode_payment = calculate_masternode_payment(250000, block_reward);

        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![TxOut {
                value: masternode_payment,
                script_pubkey: Script::from(expected_payee.clone()),
            }],
            lock_time: 0,
        };

        let result = validate_block_payment(&tx, 250000, &expected_payee, block_reward);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_block_payment_overpayment_ok() {
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{Transaction, TxOut};

        let expected_payee = vec![1, 2, 3];
        let block_reward = Amount::from_divi(2433);
        let masternode_payment = calculate_masternode_payment(250000, block_reward);
        let overpayment = Amount::from_sat(masternode_payment.as_sat() + 100_000_000);

        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![TxOut {
                value: overpayment,
                script_pubkey: Script::from(expected_payee.clone()),
            }],
            lock_time: 0,
        };

        let result = validate_block_payment(&tx, 250000, &expected_payee, block_reward);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_expected_payment_winner_from_votes() {
        use crate::masternode::MasternodePaymentWinner;

        let manager = MasternodeManager::new();
        let tracker = PaymentVoteTracker::new(10, 3);
        let block_hash = Hash256::zero();
        let outpoint = OutPoint::new(Hash256::zero(), 0);

        for _ in 0..3 {
            let vote = MasternodePaymentWinner::new(outpoint, 100, vec![1, 2, 3]);
            tracker.add_vote(vote).unwrap();
        }

        let result = get_expected_payment_winner(&manager, &tracker, &block_hash, 100);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), outpoint);
    }

    #[test]
    fn test_get_expected_payment_winner_from_score() {
        use crate::masternode::MasternodeBroadcast;

        let manager = MasternodeManager::new();
        let tracker = PaymentVoteTracker::new(10, 3);
        let block_hash = Hash256::zero();
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

        let result = get_expected_payment_winner(&manager, &tracker, &block_hash, 100);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), outpoint);
    }

    #[test]
    fn test_get_expected_payment_winner_no_winner() {
        let manager = MasternodeManager::new();
        let tracker = PaymentVoteTracker::new(10, 3);
        let block_hash = Hash256::zero();

        let result = get_expected_payment_winner(&manager, &tracker, &block_hash, 100);
        assert!(matches!(
            result,
            Err(PaymentValidationError::NoMasternodeWinner)
        ));
    }

    // ============================================================
    // POSE PAYMENT FILTERING TESTS
    // Added for MN-007 - Filtering PoSe-banned masternodes from payments
    // ============================================================

    #[test]
    fn test_masternode_pose_banned_not_valid_for_payment() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mut mn = Masternode::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
        );

        mn.status = MasternodeStatus::Enabled;
        mn.pose_score = 100;

        assert!(!mn.is_valid_for_payment());
    }

    #[test]
    fn test_masternode_pose_score_below_threshold_valid_for_payment() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mut mn = Masternode::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
        );

        mn.status = MasternodeStatus::Enabled;
        mn.pose_score = 99;

        assert!(mn.is_valid_for_payment());
    }

    #[test]
    fn test_find_payment_winner_skips_pose_banned() {
        use crate::masternode::MasternodeBroadcast;

        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        // Create two masternodes
        let outpoint1 = OutPoint::new(Hash256::zero(), 0);
        let mnb1 = MasternodeBroadcast::new(
            outpoint1,
            addr.clone(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Copper,
            70000,
            0,
        );

        let outpoint2 = OutPoint::new(Hash256::zero(), 1);
        let mnb2 = MasternodeBroadcast::new(
            outpoint2,
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Copper,
            70000,
            0,
        );

        manager.add(mnb1).unwrap();
        manager.add(mnb2).unwrap();

        // Enable both
        manager
            .update_status(outpoint1, MasternodeStatus::Enabled)
            .unwrap();
        manager
            .update_status(outpoint2, MasternodeStatus::Enabled)
            .unwrap();

        // PoSe-ban the first one
        manager.increase_pose_score(&outpoint1, 100).unwrap();

        let block_hash = Hash256::zero();
        let winner = find_payment_winner(&manager, &block_hash);

        // Winner should be outpoint2, not outpoint1
        assert!(winner.is_some());
        let winner = winner.unwrap();
        assert_eq!(winner.masternode.vin, outpoint2);
    }

    #[test]
    fn test_find_payment_winner_all_pose_banned_returns_none() {
        use crate::masternode::MasternodeBroadcast;

        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        // Create two masternodes
        let outpoint1 = OutPoint::new(Hash256::zero(), 0);
        let mnb1 = MasternodeBroadcast::new(
            outpoint1,
            addr.clone(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Copper,
            70000,
            0,
        );

        let outpoint2 = OutPoint::new(Hash256::zero(), 1);
        let mnb2 = MasternodeBroadcast::new(
            outpoint2,
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Copper,
            70000,
            0,
        );

        manager.add(mnb1).unwrap();
        manager.add(mnb2).unwrap();

        // Enable both
        manager
            .update_status(outpoint1, MasternodeStatus::Enabled)
            .unwrap();
        manager
            .update_status(outpoint2, MasternodeStatus::Enabled)
            .unwrap();

        // PoSe-ban both
        manager.increase_pose_score(&outpoint1, 100).unwrap();
        manager.increase_pose_score(&outpoint2, 100).unwrap();

        let block_hash = Hash256::zero();
        let winner = find_payment_winner(&manager, &block_hash);

        // No winner since all are PoSe-banned
        assert!(winner.is_none());
    }

    #[test]
    fn test_find_top_n_winners_filters_pose_banned() {
        use crate::masternode::MasternodeBroadcast;

        let manager = MasternodeManager::new();
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

        // Create 5 masternodes
        for i in 0..5 {
            let outpoint = OutPoint::new(Hash256::zero(), i);
            let mnb = MasternodeBroadcast::new(
                outpoint,
                addr.clone(),
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
        }

        // PoSe-ban 2 of them
        manager
            .increase_pose_score(&OutPoint::new(Hash256::zero(), 0), 100)
            .unwrap();
        manager
            .increase_pose_score(&OutPoint::new(Hash256::zero(), 2), 100)
            .unwrap();

        let block_hash = Hash256::zero();
        let winners = find_top_n_winners(&manager, &block_hash, 5);

        // Should only return 3 winners (5 total - 2 banned)
        assert_eq!(winners.len(), 3);

        // Verify none of the winners are the banned ones
        for winner in winners {
            assert_ne!(winner.masternode.vin.vout, 0);
            assert_ne!(winner.masternode.vin.vout, 2);
        }
    }

    #[test]
    fn test_masternode_status_pose_ban_not_valid_for_payment() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mut mn = Masternode::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
        );

        mn.status = MasternodeStatus::PoseBan;
        mn.pose_score = 100;

        assert!(!mn.is_valid_for_payment());
    }

    #[test]
    fn test_masternode_high_pose_score_but_not_enabled_not_valid() {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let mut mn = Masternode::new(
            OutPoint::new(Hash256::zero(), 0),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            MasternodeTier::Gold,
            70000,
        );

        mn.status = MasternodeStatus::PreEnabled;
        mn.pose_score = 50;

        assert!(!mn.is_valid_for_payment());
    }
}
