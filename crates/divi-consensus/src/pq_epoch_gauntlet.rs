// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! `Track 7D Phase 3 P3.4`: Mixed-Epoch Post-Quantum Consensus Transition & Reorg Gauntlet.
//!
//! Validates deterministic multi-epoch chain progression and cross-fork reorganizations across:
//! 1. **Proof-of-Work (`ProofOfWork`)** (`height <= pow_last_height`),
//! 2. **Pre-Fork Classical Proof-of-Stake (`PreForkClassicalPos`)** (`block_time < pq_witness_vault_activation_time`),
//! 3. **Exact Activation Boundary & Dual-Transition PQ PoS (`DualTransitionPqPos`)**
//!    (`block_time >= pq_witness_vault_activation_time && block_time < pq_strict_blocksig_cutoff_time`,
//!    supporting `-manual_fork=<timestamp>` override parity), and
//! 4. **Post-Cutoff Strict PQ PoS (`PostCutoffStrictPqPos`)** (`block_time >= pq_strict_blocksig_cutoff_time`).
//!
//! Enforces:
//! - Pre-fork rejection of `DIP-PQ-3` (`P2PQPKH` / `PQ_STAKING_VAULT`) coinstake scripts, segregated
//!   PQ witness bytes, and `DIP-PQ-4` `PqBlockSigEnvelope` signatures before activation,
//! - Post-fork `DIP-PQ-3` witness Merkle commitment integrity (`header_witness_merkle_root == computed_witness_merkle_root`)
//!   and block weight caps (`base_bytes * 4 + witness_bytes <= 8,000,000` WU and `raw_bytes <= 2,000,000` B),
//! - `CheckCoinstakeForVaults` value preservation (`returned_to_vault >= prevout_value`) and
//!   `>= 10,000 DIVI` (`1_000_000_000_000` sat) per-output vault split enforcement across both
//!   classical `STAKING_VAULT` (`50 B`) and post-quantum `PQ_STAKING_VAULT` (`74 B`) outputs,
//! - `DIP-PQ-4` `vchBlockSig` staker key binding, cold-owner vault key prohibition, and 64-byte
//!   `SHA-512` `BlockSigV1` signing prehash verification,
//! - Lottery and Treasury superblock coexistence across classical and PQ epochs, and
//! - Atomic rollback and cross-fork reorg validation (`apply_reorg_across_fork_boundary`) without state leakage.

use crate::lottery::{
    is_coinstake_valid_for_lottery, update_lottery_winners, LOTTERY_TICKET_MINIMUM,
};
use crate::pq_block_sig::{
    is_classical_coinstake_script, parse_pq_coinstake_script, verify_block_sig_envelope_binding,
    CoinstakeStakerBinding, PosBlockAuthPolicy, PqBlockSigError, VerifiedBlockSigBinding,
};
use crate::treasury::{superblock_payout, SuperblockPayout};
use divi_primitives::{Hash256, LotteryWinners, Script, Transaction};
use thiserror::Error;

/// Minimum funding per staking vault output (`10,000 DIVI` = `1_000_000_000_000` satoshis).
pub const MIN_VAULT_FUNDING_SAT: i64 = LOTTERY_TICKET_MINIMUM;

/// Base-byte scale factor (`4`) for `DIP-PQ-3` block weight calculation (`base_bytes * 4 + witness_bytes`).
pub const GAUNTLET_WITNESS_SCALE_FACTOR: usize = 4;

/// Maximum total block weight (`8,000,000` weight units inside Divi's `2 MB` cap, `DIP-PQ-3` §2.5).
pub const MAX_GAUNTLET_BLOCK_WEIGHT: usize = 8_000_000;

/// Maximum raw serialized block byte size (`2,000,000` bytes = `MAX_BLOCK_SIZE_CURRENT`, `DIP-PQ-3` §2.5).
pub const MAX_GAUNTLET_BLOCK_RAW_BYTES: usize = 2_000_000;

/// Exact byte length of a classical 2-key `STAKING_VAULT` script (`50` bytes).
const CLASSICAL_STAKING_VAULT_LEN: usize = 50;

/// Consensus epoch classification for a block at `(height, block_time)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqConsensusEpoch {
    /// Early Proof-of-Work phase (`height <= pow_last_height`).
    ProofOfWork,
    /// Classical Proof-of-Stake prior to `DIP-PQ-3` / `DIP-PQ-4` activation (`ClassicalOnly`).
    PreForkClassicalPos,
    /// Post-fork transition epoch allowing classical and PQ stakers while requiring `PostQuantumV1`
    /// `vchBlockSig` on all 256-bit PQ coinstake outputs (`PqRequiredForPqOutputs`).
    DualTransitionPqPos,
    /// Post-cutoff Proof-of-Stake epoch requiring 256-bit PQ coinstake outputs and `PostQuantumV1`
    /// `vchBlockSig` on every new PoS block (`PqRequiredAllAfter`).
    PostCutoffStrictPqPos,
}

/// Multi-epoch activation and consensus parameters for the `P3.4` transition & reorg gauntlet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqEpochConfig {
    /// 4-byte network magic (`[0xdf, 0xf0, 0xc8, 0xf3]` on Divi mainnet) bound into `DIP-PQ-4` prehashes.
    pub network_magic: [u8; 4],
    /// Last Proof-of-Work block height (`height <= pow_last_height` is PoW; `height > pow_last_height` is PoS).
    pub pow_last_height: u32,
    /// Activation timestamp for `DIP-PQ-2` hybrid Spork signatures.
    pub hybrid_spork_activation_time: u32,
    /// Activation timestamp for `DIP-PQ-3` segregated witness, `P2PQPKH`, and `PQ_STAKING_VAULT`.
    pub pq_witness_vault_activation_time: u32,
    /// Activation timestamp for `DIP-PQ-4` post-quantum `vchBlockSig` envelopes.
    pub pq_dual_blocksig_activation_time: u32,
    /// Strict cutoff timestamp after which classical `secp256k1` `vchBlockSig` is rejected.
    pub pq_strict_blocksig_cutoff_time: u32,
    /// Optional `-manual_fork=<timestamp>` override (`P1.1`) overriding `pq_witness_vault_activation_time`
    /// and `pq_dual_blocksig_activation_time` in regtest/interop gauntlets.
    pub manual_fork_override_time: Option<u32>,
    /// Minimum required value per vault output in a coinstake transaction (`10,000 DIVI` default).
    pub min_vault_funding_sat: i64,
    /// Height at which lottery cycle evaluation starts.
    pub lottery_start_height: u32,
    /// Number of blocks per lottery cycle (`10` on regtest, `10,080` on mainnet).
    pub lottery_cycle: u32,
    /// Height at which treasury cycle evaluation starts.
    pub treasury_start_height: u32,
    /// Number of blocks per treasury cycle (`50` on regtest, `10,081` on mainnet).
    pub treasury_cycle: u32,
}

impl PqEpochConfig {
    /// Construct a standard regtest multi-epoch gauntlet configuration.
    pub const fn regtest_default() -> Self {
        Self {
            network_magic: [0xfc, 0xc1, 0xb7, 0xdc],
            pow_last_height: 100,
            hybrid_spork_activation_time: 1_750_000_000,
            pq_witness_vault_activation_time: 1_750_001_000,
            pq_dual_blocksig_activation_time: 1_750_001_000,
            pq_strict_blocksig_cutoff_time: 1_750_005_000,
            manual_fork_override_time: None,
            min_vault_funding_sat: MIN_VAULT_FUNDING_SAT,
            lottery_start_height: crate::lottery::regtest::LOTTERY_START_BLOCK,
            lottery_cycle: crate::lottery::regtest::LOTTERY_CYCLE,
            treasury_start_height: crate::treasury::regtest::TREASURY_START_BLOCK,
            treasury_cycle: crate::treasury::regtest::TREASURY_CYCLE,
        }
    }

    /// Return a copy of this configuration with `-manual_fork=<timestamp>` override enabled (`P1.1`).
    pub const fn with_manual_fork(mut self, timestamp: u32) -> Self {
        self.manual_fork_override_time = Some(timestamp);
        self
    }

    /// Clear any `-manual_fork` override.
    pub const fn without_manual_fork(mut self) -> Self {
        self.manual_fork_override_time = None;
        self
    }

    /// Effective timestamp at which `DIP-PQ-3` segregated witness and 256-bit PQ scripts activate.
    pub const fn effective_pq_witness_vault_time(&self) -> u32 {
        match self.manual_fork_override_time {
            Some(override_time) => override_time,
            None => self.pq_witness_vault_activation_time,
        }
    }

    /// Effective timestamp at which `DIP-PQ-4` post-quantum `vchBlockSig` envelopes activate.
    pub const fn effective_dual_blocksig_time(&self) -> u32 {
        match self.manual_fork_override_time {
            Some(override_time) => override_time,
            None => self.pq_dual_blocksig_activation_time,
        }
    }

    /// Returns `true` if `DIP-PQ-3` segregated witness and 256-bit PQ scripts are active at `block_time`.
    pub const fn is_pq_witness_and_vault_active(&self, block_time: u32) -> bool {
        block_time >= self.effective_pq_witness_vault_time()
    }

    /// Returns `true` when transitioning from `prev_block_time < activation` to `block_time >= activation`.
    pub const fn is_activation_boundary_crossing(
        &self,
        prev_block_time: u32,
        block_time: u32,
    ) -> bool {
        let act = self.effective_pq_witness_vault_time();
        prev_block_time < act && block_time >= act
    }

    /// Determine the consensus epoch for a candidate block at `(height, block_time)`.
    pub const fn epoch_at(&self, height: u32, block_time: u32) -> PqConsensusEpoch {
        if height <= self.pow_last_height {
            PqConsensusEpoch::ProofOfWork
        } else if block_time < self.effective_pq_witness_vault_time()
            || block_time < self.effective_dual_blocksig_time()
        {
            PqConsensusEpoch::PreForkClassicalPos
        } else if block_time < self.pq_strict_blocksig_cutoff_time {
            PqConsensusEpoch::DualTransitionPqPos
        } else {
            PqConsensusEpoch::PostCutoffStrictPqPos
        }
    }

    /// Determine the `DIP-PQ-4` [`PosBlockAuthPolicy`] in effect at `block_time`.
    pub const fn pos_block_auth_policy_at(&self, block_time: u32) -> PosBlockAuthPolicy {
        if block_time < self.effective_dual_blocksig_time() {
            PosBlockAuthPolicy::ClassicalOnly
        } else if block_time < self.pq_strict_blocksig_cutoff_time {
            PosBlockAuthPolicy::PqRequiredForPqOutputs {
                network_magic: self.network_magic,
            }
        } else {
            PosBlockAuthPolicy::PqRequiredAllAfter {
                network_magic: self.network_magic,
                cutoff_block_time: self.pq_strict_blocksig_cutoff_time,
            }
        }
    }
}

/// Candidate block submitted to the mixed-epoch consensus transition & reorg gauntlet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GauntletBlockCandidate {
    /// Block height (`tip.height + 1`).
    pub height: u32,
    /// Block header hash.
    pub block_hash: Hash256,
    /// Parent block header hash (`tip.block_hash`).
    pub prev_block_hash: Hash256,
    /// Block header timestamp (seconds since Unix epoch).
    pub block_time: u32,
    /// Incremental chain work contributed by this block (`> 0`).
    pub block_work: u64,
    /// `false` for Proof-of-Work blocks, `true` for Proof-of-Stake blocks.
    pub is_proof_of_stake: bool,
    /// Coinstake transaction (`Some` for PoS blocks, `None` for PoW blocks).
    pub coinstake_tx: Option<Transaction>,
    /// The staked input's previous output `scriptPubKey` (used to enforce `CheckCoinstakeForVaults`).
    pub coinstake_prevout_script: Option<Script>,
    /// The staked input's previous output value in satoshis.
    pub coinstake_prevout_value_sat: i64,
    /// Serialized `vchBlockSig` bytes (empty for PoW, 65B/DER for classical PoS, `PqBlockSigEnvelope` for PQ PoS).
    pub vch_block_sig: Vec<u8>,
    /// Base serialized block size (excluding segregated PQ witness stacks).
    pub base_block_bytes: usize,
    /// Segregated PQ witness byte size (`0` before `DIP-PQ-3` activation).
    pub witness_bytes: usize,
    /// 32-byte witness Merkle root committed in the block header / coinstake commitment.
    pub header_witness_merkle_root: [u8; 32],
    /// 32-byte witness Merkle root computed over the block's transaction `PqTxWitness` stacks.
    pub computed_witness_merkle_root: [u8; 32],
    /// Optional expected 64-byte `DIP-PQ-4` `BlockSigV1` signing prehash for cryptographic binding verification.
    pub expected_signing_prehash_512: Option<[u8; 64]>,
}

/// Summary of a validated block connected to [`GauntletChainState`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedEpochBlockSummary {
    /// Block height.
    pub height: u32,
    /// Block header hash.
    pub block_hash: Hash256,
    /// Parent block header hash.
    pub prev_block_hash: Hash256,
    /// Block timestamp.
    pub block_time: u32,
    /// Incremental work of this block.
    pub block_work: u64,
    /// Cumulative chain work up to and including this block.
    pub cumulative_work: u128,
    /// Consensus epoch classification of this block.
    pub epoch: PqConsensusEpoch,
    /// Whether this block crossed the `DIP-PQ-3`/`DIP-PQ-4` activation timestamp from its parent.
    pub crossed_activation_boundary: bool,
    /// Whether this block's timestamp equals the exact fork activation timestamp (`block_time == activation_time`).
    pub is_exact_activation_timestamp: bool,
    /// Computed `DIP-PQ-3` block weight (`base_block_bytes * 4 + witness_bytes`).
    pub block_weight: usize,
    /// Verified `vchBlockSig` binding (`None` for PoW blocks).
    pub verified_sig_binding: Option<VerifiedBlockSigBinding>,
    /// Superblock payout status at this height (`Treasury`, `Lottery`, or `None`).
    pub superblock_payout: SuperblockPayout,
    /// Whether this block's coinstake qualified for the lottery pool (`> 10,000 DIVI`).
    pub lottery_eligible: bool,
}

/// Summary report returned by [`GauntletChainState::apply_reorg_across_fork_boundary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorgExecutionReport {
    /// Common ancestor height where the reorg branched.
    pub fork_ancestor_height: u32,
    /// Common ancestor block hash.
    pub fork_ancestor_hash: Hash256,
    /// Number of blocks disconnected from the old active chain.
    pub disconnected_count: usize,
    /// Number of blocks connected from the replacement branch.
    pub connected_count: usize,
    /// `true` if disconnecting rewound the chain from a post-fork PQ epoch back into pre-fork classical state.
    pub rewound_across_activation_boundary: bool,
    /// `true` if connecting the replacement branch crossed the fork activation boundary forward again.
    pub reconnected_across_activation_boundary: bool,
    /// Cumulative chain work prior to the reorganization.
    pub old_cumulative_work: u128,
    /// Cumulative chain work of the newly activated heavier chain.
    pub new_cumulative_work: u128,
    /// New active tip block hash.
    pub new_tip_hash: Hash256,
    /// Consensus epoch at the new active tip.
    pub new_tip_epoch: PqConsensusEpoch,
}

/// Consensus errors raised by the mixed-epoch transition & reorg gauntlet.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GauntletError {
    #[error("non-sequential block height: expected {expected}, got {actual}")]
    NonSequentialHeight { expected: u32, actual: u32 },

    #[error("previous block hash mismatch: expected {expected}, got {actual}")]
    PrevBlockHashMismatch { expected: Hash256, actual: Hash256 },

    #[error("block timestamp {block_time} is earlier than parent timestamp {prev_time}")]
    NonMonotonicBlockTime { prev_time: u32, block_time: u32 },

    #[error("block at height {height} has zero block_work")]
    ZeroBlockWork { height: u32 },

    #[error("invalid Proof-of-Work block at height {height}: {reason}")]
    InvalidProofOfWorkBlock { height: u32, reason: &'static str },

    #[error("missing or invalid coinstake transaction at height {height}: {reason}")]
    MissingOrInvalidCoinstake { height: u32, reason: &'static str },

    #[error("256-bit post-quantum coinstake script is forbidden at height {height} (block_time {block_time} < activation_time {activation_time})")]
    PreActivationPqScriptForbidden {
        height: u32,
        block_time: u32,
        activation_time: u32,
    },

    #[error("segregated PQ witness data ({witness_bytes} B) is forbidden before activation at height {height} (block_time {block_time})")]
    PreActivationWitnessDataForbidden {
        height: u32,
        block_time: u32,
        witness_bytes: usize,
    },

    #[error("PQ witness Merkle root mismatch at height {height}")]
    WitnessMerkleRootMismatch {
        height: u32,
        header_root: [u8; 32],
        computed_root: [u8; 32],
    },

    #[error("block at height {height} exceeds DIP-PQ-3 weight/size limits (base={base_bytes} B, witness={witness_bytes} B, weight={weight} WU)")]
    BlockWeightExceeded {
        height: u32,
        base_bytes: usize,
        witness_bytes: usize,
        weight: usize,
    },

    #[error("vault coinstake at height {height} failed CheckCoinstakeForVaults value preservation: staked {prevout_sat} sat, returned {returned_sat} sat")]
    VaultPrincipalUnderfunded {
        height: u32,
        prevout_sat: i64,
        returned_sat: i64,
    },

    #[error("vault coinstake output #{output_index} at height {height} has {output_sat} sat, below minimum {minimum_sat} sat (10,000 DIVI)")]
    VaultSplitBelowMinimum {
        height: u32,
        output_index: usize,
        output_sat: i64,
        minimum_sat: i64,
    },

    #[error("DIP-PQ-4 block signature validation error: {0}")]
    BlockSigValidation(#[from] PqBlockSigError),

    #[error("DIP-PQ-4 64-byte BlockSigV1 signing prehash mismatch at height {height}")]
    SigningPrehashMismatch {
        height: u32,
        expected: Vec<u8>,
        actual: Vec<u8>,
    },

    #[error("cannot disconnect genesis block")]
    CannotDisconnectGenesis,

    #[error("reorg fork ancestor {target_hash} not found in active chain")]
    ReorgCommonAncestorNotFound { target_hash: Hash256 },

    #[error("replacement chain work ({candidate_work}) is not strictly heavier than active chain work ({current_work})")]
    ReorgCandidateNotHeavier {
        current_work: u128,
        candidate_work: u128,
    },
}

/// Check whether `script` is a canonical `50`-byte classical `STAKING_VAULT` script.
fn is_classical_staking_vault(script: &Script) -> bool {
    let b = script.as_bytes();
    b.len() == CLASSICAL_STAKING_VAULT_LEN
        && b[0] == 0x63
        && b[1] == 0x14
        && b[22] == 0x67
        && b[23] == 0xb9
        && b[24] == 0x14
        && b[45] == 0x68
        && b[46] == 0x78
        && b[47] == 0xa9
        && b[48] == 0x88
        && b[49] == 0xac
}

/// Check whether `script` is either a classical `50`-byte `STAKING_VAULT` or a `74`-byte `PQ_STAKING_VAULT`.
pub fn is_any_staking_vault_script(script: &Script) -> bool {
    is_classical_staking_vault(script)
        || matches!(
            parse_pq_coinstake_script(script),
            Some(CoinstakeStakerBinding::PqStakingVault { .. })
        )
}

/// Validate `DIP-PQ-3` block weight (`<= 8,000,000` WU) and raw byte cap (`<= 2,000,000` B).
pub fn validate_gauntlet_block_weight(
    height: u32,
    base_bytes: usize,
    witness_bytes: usize,
) -> Result<usize, GauntletError> {
    let weight = base_bytes
        .saturating_mul(GAUNTLET_WITNESS_SCALE_FACTOR)
        .saturating_add(witness_bytes);
    let raw_bytes = base_bytes.saturating_add(witness_bytes);
    if weight > MAX_GAUNTLET_BLOCK_WEIGHT || raw_bytes > MAX_GAUNTLET_BLOCK_RAW_BYTES {
        return Err(GauntletError::BlockWeightExceeded {
            height,
            base_bytes,
            witness_bytes,
            weight,
        });
    }
    Ok(weight)
}

/// Stateful multi-epoch chain verifier supporting block connection, tip disconnection, and atomic
/// cross-fork reorganizations (`P3.4`).
#[derive(Debug, Clone)]
pub struct GauntletChainState {
    config: PqEpochConfig,
    blocks: Vec<ConnectedEpochBlockSummary>,
    lottery_winners_history: Vec<LotteryWinners>,
    classical_pos_blocks_connected: usize,
    pq_pos_blocks_connected: usize,
    activation_boundary_crossings: usize,
}

impl GauntletChainState {
    /// Initialize a new chain state anchored at the genesis block (`height = 0`).
    pub fn new_with_genesis(
        config: PqEpochConfig,
        genesis_hash: Hash256,
        genesis_time: u32,
    ) -> Self {
        let genesis_summary = ConnectedEpochBlockSummary {
            height: 0,
            block_hash: genesis_hash,
            prev_block_hash: Hash256::zero(),
            block_time: genesis_time,
            block_work: 1,
            cumulative_work: 1,
            epoch: PqConsensusEpoch::ProofOfWork,
            crossed_activation_boundary: false,
            is_exact_activation_timestamp: false,
            block_weight: 320,
            verified_sig_binding: None,
            superblock_payout: SuperblockPayout::None,
            lottery_eligible: false,
        };
        Self {
            config,
            blocks: vec![genesis_summary],
            lottery_winners_history: vec![LotteryWinners::new(0)],
            classical_pos_blocks_connected: 0,
            pq_pos_blocks_connected: 0,
            activation_boundary_crossings: 0,
        }
    }

    /// Return the active [`PqEpochConfig`].
    pub const fn config(&self) -> &PqEpochConfig {
        &self.config
    }

    /// Return the current active chain tip summary.
    pub fn tip(&self) -> &ConnectedEpochBlockSummary {
        self.blocks.last().expect("genesis block always present")
    }

    /// Return the current active tip height.
    pub fn height(&self) -> u32 {
        self.tip().height
    }

    /// Return the current active tip's consensus epoch.
    pub fn current_epoch(&self) -> PqConsensusEpoch {
        self.tip().epoch
    }

    /// Return the cumulative work of the active chain.
    pub fn cumulative_work(&self) -> u128 {
        self.tip().cumulative_work
    }

    /// Return the active [`LotteryWinners`] at the current tip.
    pub fn current_lottery_winners(&self) -> &LotteryWinners {
        self.lottery_winners_history
            .last()
            .expect("genesis lottery state always present")
    }

    /// Return all connected blocks from genesis (`0`) through `tip.height`.
    pub fn blocks(&self) -> &[ConnectedEpochBlockSummary] {
        &self.blocks
    }

    /// Total number of classical PoS blocks currently connected on the active chain.
    pub const fn classical_pos_blocks_connected(&self) -> usize {
        self.classical_pos_blocks_connected
    }

    /// Total number of post-quantum PoS blocks (`PostQuantumV1`) currently connected on the active chain.
    pub const fn pq_pos_blocks_connected(&self) -> usize {
        self.pq_pos_blocks_connected
    }

    /// Number of forward activation boundary crossings currently on the active chain.
    pub const fn activation_boundary_crossings(&self) -> usize {
        self.activation_boundary_crossings
    }

    /// Validate and connect the next candidate block onto the active tip.
    pub fn connect_block(
        &mut self,
        candidate: GauntletBlockCandidate,
    ) -> Result<ConnectedEpochBlockSummary, GauntletError> {
        let parent = self.tip().clone();
        let expected_height = parent.height + 1;
        if candidate.height != expected_height {
            return Err(GauntletError::NonSequentialHeight {
                expected: expected_height,
                actual: candidate.height,
            });
        }
        if candidate.prev_block_hash != parent.block_hash {
            return Err(GauntletError::PrevBlockHashMismatch {
                expected: parent.block_hash,
                actual: candidate.prev_block_hash,
            });
        }
        if candidate.block_time < parent.block_time {
            return Err(GauntletError::NonMonotonicBlockTime {
                prev_time: parent.block_time,
                block_time: candidate.block_time,
            });
        }
        if candidate.block_work == 0 {
            return Err(GauntletError::ZeroBlockWork {
                height: candidate.height,
            });
        }

        let pq_witness_active = self
            .config
            .is_pq_witness_and_vault_active(candidate.block_time);
        if !pq_witness_active {
            if candidate.witness_bytes != 0 || candidate.header_witness_merkle_root != [0u8; 32] {
                return Err(GauntletError::PreActivationWitnessDataForbidden {
                    height: candidate.height,
                    block_time: candidate.block_time,
                    witness_bytes: candidate.witness_bytes.max(1),
                });
            }
        } else if candidate.header_witness_merkle_root != candidate.computed_witness_merkle_root {
            return Err(GauntletError::WitnessMerkleRootMismatch {
                height: candidate.height,
                header_root: candidate.header_witness_merkle_root,
                computed_root: candidate.computed_witness_merkle_root,
            });
        }

        let block_weight = validate_gauntlet_block_weight(
            candidate.height,
            candidate.base_block_bytes,
            candidate.witness_bytes,
        )?;

        let epoch = self.config.epoch_at(candidate.height, candidate.block_time);
        let crossed_activation_boundary = self
            .config
            .is_activation_boundary_crossing(parent.block_time, candidate.block_time);
        let is_exact_activation_timestamp =
            candidate.block_time == self.config.effective_pq_witness_vault_time();

        let (verified_sig_binding, lottery_eligible, next_lottery_winners) = match epoch {
            PqConsensusEpoch::ProofOfWork => {
                if candidate.is_proof_of_stake {
                    return Err(GauntletError::InvalidProofOfWorkBlock {
                        height: candidate.height,
                        reason: "PoW epoch block cannot be marked Proof-of-Stake",
                    });
                }
                if candidate.coinstake_tx.is_some() {
                    return Err(GauntletError::InvalidProofOfWorkBlock {
                        height: candidate.height,
                        reason: "PoW epoch block must not contain a coinstake transaction",
                    });
                }
                if !candidate.vch_block_sig.is_empty() {
                    return Err(GauntletError::InvalidProofOfWorkBlock {
                        height: candidate.height,
                        reason: "PoW epoch block must have an empty vchBlockSig",
                    });
                }
                (None, false, self.current_lottery_winners().clone())
            }
            PqConsensusEpoch::PreForkClassicalPos
            | PqConsensusEpoch::DualTransitionPqPos
            | PqConsensusEpoch::PostCutoffStrictPqPos => {
                if !candidate.is_proof_of_stake {
                    return Err(GauntletError::MissingOrInvalidCoinstake {
                        height: candidate.height,
                        reason: "PoS epoch block must have is_proof_of_stake = true",
                    });
                }
                let coinstake_tx = candidate.coinstake_tx.as_ref().ok_or(
                    GauntletError::MissingOrInvalidCoinstake {
                        height: candidate.height,
                        reason: "PoS block is missing coinstake_tx",
                    },
                )?;
                if !coinstake_tx.is_coinstake() || coinstake_tx.vout.len() < 2 {
                    return Err(GauntletError::MissingOrInvalidCoinstake {
                        height: candidate.height,
                        reason: "coinstake_tx does not satisfy Transaction::is_coinstake()",
                    });
                }

                let coinstake_script = &coinstake_tx.vout[1].script_pubkey;
                let is_pq_script = parse_pq_coinstake_script(coinstake_script).is_some();

                if !pq_witness_active && is_pq_script {
                    return Err(GauntletError::PreActivationPqScriptForbidden {
                        height: candidate.height,
                        block_time: candidate.block_time,
                        activation_time: self.config.effective_pq_witness_vault_time(),
                    });
                }

                if !is_pq_script && !is_classical_coinstake_script(coinstake_script) {
                    return Err(GauntletError::BlockSigValidation(
                        PqBlockSigError::UnsupportedCoinstakeScriptForClassicalBlockSig,
                    ));
                }

                // Enforce CheckCoinstakeForVaults for both classical 50B STAKING_VAULT and 74B PQ_STAKING_VAULT
                let vault_script_to_check = match &candidate.coinstake_prevout_script {
                    Some(prev_script) if is_any_staking_vault_script(prev_script) => {
                        Some(prev_script)
                    }
                    _ if is_any_staking_vault_script(coinstake_script) => Some(coinstake_script),
                    _ => None,
                };

                if let Some(vault_script) = vault_script_to_check {
                    let mut returned_to_vault_sat: i64 = 0;
                    for (idx, out) in coinstake_tx.vout.iter().enumerate().skip(1) {
                        if &out.script_pubkey == vault_script {
                            let val_sat = out.value.as_sat();
                            if val_sat < self.config.min_vault_funding_sat {
                                return Err(GauntletError::VaultSplitBelowMinimum {
                                    height: candidate.height,
                                    output_index: idx,
                                    output_sat: val_sat,
                                    minimum_sat: self.config.min_vault_funding_sat,
                                });
                            }
                            returned_to_vault_sat = returned_to_vault_sat.saturating_add(val_sat);
                        }
                    }
                    if returned_to_vault_sat < candidate.coinstake_prevout_value_sat {
                        return Err(GauntletError::VaultPrincipalUnderfunded {
                            height: candidate.height,
                            prevout_sat: candidate.coinstake_prevout_value_sat,
                            returned_sat: returned_to_vault_sat,
                        });
                    }
                }

                let policy = self.config.pos_block_auth_policy_at(candidate.block_time);
                let coinstake_txid = coinstake_tx.txid();
                let verified = verify_block_sig_envelope_binding(
                    &candidate.vch_block_sig,
                    coinstake_script,
                    candidate.block_hash.as_bytes(),
                    coinstake_txid.as_bytes(),
                    1,
                    candidate.block_time,
                    &policy,
                )?;

                if let Some(expected_prehash) = candidate.expected_signing_prehash_512 {
                    match &verified {
                        VerifiedBlockSigBinding::PostQuantumV1 {
                            signing_prehash_512,
                            ..
                        } => {
                            if *signing_prehash_512 != expected_prehash {
                                return Err(GauntletError::SigningPrehashMismatch {
                                    height: candidate.height,
                                    expected: expected_prehash.to_vec(),
                                    actual: signing_prehash_512.to_vec(),
                                });
                            }
                        }
                        VerifiedBlockSigBinding::ClassicalSecp256k1 => {
                            return Err(GauntletError::SigningPrehashMismatch {
                                height: candidate.height,
                                expected: expected_prehash.to_vec(),
                                actual: vec![0u8; 64],
                            });
                        }
                    }
                }

                // Update lottery state across epoch transitions
                let sp = superblock_payout(
                    candidate.height,
                    self.config.treasury_start_height,
                    self.config.treasury_cycle,
                    self.config.lottery_start_height,
                    self.config.lottery_cycle,
                );
                let base_winners = if sp == SuperblockPayout::Lottery {
                    LotteryWinners::new(candidate.height)
                } else {
                    self.current_lottery_winners().clone()
                };

                let eligible = is_coinstake_valid_for_lottery(coinstake_tx);
                let updated_winners =
                    if eligible && candidate.height >= self.config.lottery_start_height {
                        let last_lottery_h = crate::lottery::get_last_lottery_height(
                            candidate.height,
                            self.config.lottery_start_height,
                            self.config.lottery_cycle,
                        );
                        let last_lottery_hash = self
                            .blocks
                            .get(last_lottery_h as usize)
                            .map(|b| b.block_hash)
                            .unwrap_or(parent.block_hash);
                        update_lottery_winners(
                            &base_winners,
                            coinstake_txid,
                            coinstake_script.clone(),
                            &last_lottery_hash,
                            candidate.height,
                        )
                        .unwrap_or(base_winners)
                    } else {
                        base_winners
                    };

                (Some(verified), eligible, updated_winners)
            }
        };

        let sp_payout = superblock_payout(
            candidate.height,
            self.config.treasury_start_height,
            self.config.treasury_cycle,
            self.config.lottery_start_height,
            self.config.lottery_cycle,
        );

        let cumulative_work = parent
            .cumulative_work
            .saturating_add(u128::from(candidate.block_work));

        let summary = ConnectedEpochBlockSummary {
            height: candidate.height,
            block_hash: candidate.block_hash,
            prev_block_hash: candidate.prev_block_hash,
            block_time: candidate.block_time,
            block_work: candidate.block_work,
            cumulative_work,
            epoch,
            crossed_activation_boundary,
            is_exact_activation_timestamp,
            block_weight,
            verified_sig_binding,
            superblock_payout: sp_payout,
            lottery_eligible,
        };

        match &summary.verified_sig_binding {
            Some(VerifiedBlockSigBinding::ClassicalSecp256k1) => {
                self.classical_pos_blocks_connected += 1;
            }
            Some(VerifiedBlockSigBinding::PostQuantumV1 { .. }) => {
                self.pq_pos_blocks_connected += 1;
            }
            None => {}
        }
        if summary.crossed_activation_boundary {
            self.activation_boundary_crossings += 1;
        }

        self.blocks.push(summary.clone());
        self.lottery_winners_history.push(next_lottery_winners);
        Ok(summary)
    }

    /// Disconnect the current active tip block, restoring all chain counters and lottery state
    /// to the exact parent block state.
    pub fn disconnect_tip(&mut self) -> Result<ConnectedEpochBlockSummary, GauntletError> {
        if self.blocks.len() <= 1 {
            return Err(GauntletError::CannotDisconnectGenesis);
        }
        let popped = self.blocks.pop().expect("checked len > 1");
        self.lottery_winners_history.pop();

        match &popped.verified_sig_binding {
            Some(VerifiedBlockSigBinding::ClassicalSecp256k1) => {
                self.classical_pos_blocks_connected =
                    self.classical_pos_blocks_connected.saturating_sub(1);
            }
            Some(VerifiedBlockSigBinding::PostQuantumV1 { .. }) => {
                self.pq_pos_blocks_connected = self.pq_pos_blocks_connected.saturating_sub(1);
            }
            None => {}
        }
        if popped.crossed_activation_boundary {
            self.activation_boundary_crossings =
                self.activation_boundary_crossings.saturating_sub(1);
        }

        Ok(popped)
    }

    /// Execute an atomic reorganization from `fork_ancestor_hash` onto `replacement_branch`.
    ///
    /// If any block in `replacement_branch` fails consensus validation or if the resulting
    /// `cumulative_work` is not strictly greater than the pre-reorg chain work, `self` is
    /// atomically rolled back to its exact pre-reorg state without state leakage.
    pub fn apply_reorg_across_fork_boundary(
        &mut self,
        fork_ancestor_hash: Hash256,
        replacement_branch: Vec<GauntletBlockCandidate>,
    ) -> Result<ReorgExecutionReport, GauntletError> {
        let ancestor_pos = self
            .blocks
            .iter()
            .rposition(|b| b.block_hash == fork_ancestor_hash)
            .ok_or(GauntletError::ReorgCommonAncestorNotFound {
                target_hash: fork_ancestor_hash,
            })?;

        let snapshot = self.clone();
        let old_cumulative_work = self.cumulative_work();
        let pre_reorg_pq_active = self
            .config
            .is_pq_witness_and_vault_active(self.tip().block_time);

        let mut disconnected_count = 0usize;
        while self.blocks.len() - 1 > ancestor_pos {
            if let Err(e) = self.disconnect_tip() {
                *self = snapshot;
                return Err(e);
            }
            disconnected_count += 1;
        }

        let ancestor_summary = self.tip().clone();
        let ancestor_pq_active = self
            .config
            .is_pq_witness_and_vault_active(ancestor_summary.block_time);
        let rewound_across_activation_boundary = pre_reorg_pq_active && !ancestor_pq_active;

        let mut reconnected_across_activation_boundary = false;
        let mut connected_count = 0usize;
        for candidate in replacement_branch {
            match self.connect_block(candidate) {
                Ok(summary) => {
                    if summary.crossed_activation_boundary {
                        reconnected_across_activation_boundary = true;
                    }
                    connected_count += 1;
                }
                Err(err) => {
                    *self = snapshot;
                    return Err(err);
                }
            }
        }

        let new_cumulative_work = self.cumulative_work();
        if new_cumulative_work <= old_cumulative_work {
            *self = snapshot;
            return Err(GauntletError::ReorgCandidateNotHeavier {
                current_work: old_cumulative_work,
                candidate_work: new_cumulative_work,
            });
        }

        Ok(ReorgExecutionReport {
            fork_ancestor_height: ancestor_summary.height,
            fork_ancestor_hash,
            disconnected_count,
            connected_count,
            rewound_across_activation_boundary,
            reconnected_across_activation_boundary,
            old_cumulative_work,
            new_cumulative_work,
            new_tip_hash: self.tip().block_hash,
            new_tip_epoch: self.tip().epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_block_sig::{compute_pos_block_signing_prehash, PqBlockSigEnvelope};
    use divi_crypto::pq::{pq_address_key_hash_256, PqSchemeId};
    use divi_primitives::{Amount, OutPoint, TxIn, TxOut};
    use sha2::{Digest, Sha256};

    fn deterministic_hash(tag: u8, height: u32) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update([tag]);
        hasher.update(height.to_le_bytes());
        Hash256::from_bytes(hasher.finalize().into())
    }

    fn sample_fndsa512_pubkey(tag: u8) -> Vec<u8> {
        let mut pk = Vec::with_capacity(897);
        pk.push(0x09);
        let mut acc: u32 = 0;
        let mut acc_bits: u32 = 0;
        for i in 0..512u32 {
            let coeff = (i + u32::from(tag)) % 1024;
            acc = (acc << 14) | coeff;
            acc_bits += 14;
            while acc_bits >= 8 {
                acc_bits -= 8;
                pk.push(((acc >> acc_bits) & 0xff) as u8);
            }
        }
        assert_eq!(pk.len(), 897);
        pk
    }

    fn sample_fndsa512_signature(nonce_byte: u8) -> Vec<u8> {
        let mut sig = vec![0u8; 666];
        sig[0] = 0x39;
        for b in &mut sig[1..41] {
            *b = nonce_byte;
        }
        let payload = &mut sig[41..666];
        for coeff_idx in 0..512usize {
            let bit_pos = coeff_idx * 9 + 8;
            let byte_idx = bit_pos >> 3;
            let bit_shift = 7 - (bit_pos & 7);
            payload[byte_idx] |= 1u8 << bit_shift;
        }
        sig
    }

    fn sample_mldsa44_pubkey(tag: u8) -> Vec<u8> {
        let mut pk = vec![0u8; 1312];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(tag);
        }
        pk
    }

    fn sample_mldsa44_signature(c_tilde_byte: u8) -> Vec<u8> {
        let mut sig = vec![0u8; 2420];
        for b in &mut sig[0..32] {
            *b = c_tilde_byte;
        }
        let zero_z_chunk: [u8; 9] = [0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x20, 0x00, 0x80];
        for chunk in sig[32..2336].as_chunks_mut::<9>().0 {
            chunk.copy_from_slice(&zero_z_chunk);
        }
        sig
    }

    fn classical_compact_sig(fill: u8) -> Vec<u8> {
        let mut sig = vec![fill; 65];
        sig[0] = 0x1b;
        sig
    }

    fn build_classical_p2pkh_script(hash20: [u8; 20]) -> Script {
        Script::new_p2pkh(&hash20)
    }

    fn build_classical_vault_script(owner20: [u8; 20], vault20: [u8; 20]) -> Script {
        let mut b = Vec::with_capacity(50);
        b.push(0x63);
        b.push(0x14);
        b.extend_from_slice(&owner20);
        b.push(0x67);
        b.push(0xb9);
        b.push(0x14);
        b.extend_from_slice(&vault20);
        b.push(0x68);
        b.push(0x78);
        b.push(0xa9);
        b.push(0x88);
        b.push(0xac);
        Script::from_bytes(b)
    }

    fn build_pq_vault_script(owner32: [u8; 32], vault32: [u8; 32]) -> Script {
        let mut b = Vec::with_capacity(74);
        b.push(0x63);
        b.push(0x20);
        b.extend_from_slice(&owner32);
        b.push(0x67);
        b.push(0xb9);
        b.push(0x20);
        b.extend_from_slice(&vault32);
        b.push(0x68);
        b.push(0x78);
        b.push(0xa8);
        b.push(0x88);
        b.push(0xac);
        Script::from_bytes(b)
    }

    fn build_p2pqpkh_script(addr32: [u8; 32]) -> Script {
        let mut b = Vec::with_capacity(34);
        b.push(0x51);
        b.push(0x20);
        b.extend_from_slice(&addr32);
        Script::from_bytes(b)
    }

    fn build_coinstake_tx(height: u32, outputs: Vec<(Script, i64)>) -> Transaction {
        let mut tx = Transaction::new();
        tx.version = 1;
        tx.vin.push(TxIn::new(
            OutPoint::new(deterministic_hash(0xaa, height), 0),
            Script::new(),
            0xffff_ffff,
        ));
        tx.vout.push(TxOut::empty());
        for (script, sat) in outputs {
            tx.vout.push(TxOut::new(Amount::from_sat(sat), script));
        }
        assert!(tx.is_coinstake());
        tx
    }

    fn make_pow_candidate(
        height: u32,
        prev_block_hash: Hash256,
        block_time: u32,
        work: u64,
    ) -> GauntletBlockCandidate {
        GauntletBlockCandidate {
            height,
            block_hash: deterministic_hash(0x01, height),
            prev_block_hash,
            block_time,
            block_work: work,
            is_proof_of_stake: false,
            coinstake_tx: None,
            coinstake_prevout_script: None,
            coinstake_prevout_value_sat: 0,
            vch_block_sig: Vec::new(),
            base_block_bytes: 500,
            witness_bytes: 0,
            header_witness_merkle_root: [0u8; 32],
            computed_witness_merkle_root: [0u8; 32],
            expected_signing_prehash_512: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_classical_pos_candidate(
        height: u32,
        prev_block_hash: Hash256,
        block_time: u32,
        work: u64,
        script: Script,
        prevout_sat: i64,
        output_splits_sat: Vec<i64>,
        branch_tag: u8,
    ) -> GauntletBlockCandidate {
        let outputs = output_splits_sat
            .into_iter()
            .map(|sat| (script.clone(), sat))
            .collect();
        let coinstake_tx = build_coinstake_tx(height ^ (u32::from(branch_tag) << 24), outputs);
        GauntletBlockCandidate {
            height,
            block_hash: deterministic_hash(branch_tag, height),
            prev_block_hash,
            block_time,
            block_work: work,
            is_proof_of_stake: true,
            coinstake_tx: Some(coinstake_tx),
            coinstake_prevout_script: Some(script),
            coinstake_prevout_value_sat: prevout_sat,
            vch_block_sig: classical_compact_sig(branch_tag),
            base_block_bytes: 1_200,
            witness_bytes: 0,
            header_witness_merkle_root: [0u8; 32],
            computed_witness_merkle_root: [0u8; 32],
            expected_signing_prehash_512: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_pq_pos_candidate(
        config: &PqEpochConfig,
        height: u32,
        prev_block_hash: Hash256,
        block_time: u32,
        work: u64,
        scheme: PqSchemeId,
        use_vault: bool,
        prevout_sat: i64,
        output_splits_sat: Vec<i64>,
        branch_tag: u8,
    ) -> GauntletBlockCandidate {
        let (pk, sig) = match scheme {
            PqSchemeId::FnDsa512 => (
                sample_fndsa512_pubkey(branch_tag),
                sample_fndsa512_signature(branch_tag),
            ),
            PqSchemeId::MlDsa44 => (
                sample_mldsa44_pubkey(branch_tag),
                sample_mldsa44_signature(branch_tag),
            ),
            _ => unreachable!("only FN-DSA-512 and ML-DSA-44 allowed for BlockSigV1"),
        };
        let hot_hash32 = pq_address_key_hash_256(scheme, &pk);
        let cold_owner_hash32 = [branch_tag ^ 0xdd; 32];
        let script = if use_vault {
            build_pq_vault_script(cold_owner_hash32, hot_hash32)
        } else {
            build_p2pqpkh_script(hot_hash32)
        };
        let outputs = output_splits_sat
            .into_iter()
            .map(|sat| (script.clone(), sat))
            .collect();
        let coinstake_tx = build_coinstake_tx(height ^ (u32::from(branch_tag) << 20), outputs);
        let coinstake_txid = coinstake_tx.txid();
        let block_hash = deterministic_hash(branch_tag, height);
        let env = PqBlockSigEnvelope::new(scheme, pk.clone(), sig).expect("valid PQ envelope");
        let prehash = compute_pos_block_signing_prehash(
            config.network_magic,
            scheme,
            &pk,
            block_hash.as_bytes(),
            coinstake_txid.as_bytes(),
            1,
        )
        .expect("valid prehash");
        let witness_root = [branch_tag.wrapping_add(1); 32];
        GauntletBlockCandidate {
            height,
            block_hash,
            prev_block_hash,
            block_time,
            block_work: work,
            is_proof_of_stake: true,
            coinstake_tx: Some(coinstake_tx),
            coinstake_prevout_script: Some(script),
            coinstake_prevout_value_sat: prevout_sat,
            vch_block_sig: env.encode(),
            base_block_bytes: 1_500,
            witness_bytes: 1_600,
            header_witness_merkle_root: witness_root,
            computed_witness_merkle_root: witness_root,
            expected_signing_prehash_512: Some(prehash),
        }
    }

    #[test]
    fn test_01_epoch_config_classification_and_manual_fork_override() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 10;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;
        cfg.pq_strict_blocksig_cutoff_time = 3_000;

        assert_eq!(cfg.epoch_at(5, 1_500), PqConsensusEpoch::ProofOfWork);
        assert_eq!(cfg.epoch_at(10, 2_500), PqConsensusEpoch::ProofOfWork);
        assert_eq!(
            cfg.epoch_at(11, 1_999),
            PqConsensusEpoch::PreForkClassicalPos
        );
        assert_eq!(
            cfg.epoch_at(11, 2_000),
            PqConsensusEpoch::DualTransitionPqPos
        );
        assert_eq!(
            cfg.epoch_at(11, 2_999),
            PqConsensusEpoch::DualTransitionPqPos
        );
        assert_eq!(
            cfg.epoch_at(11, 3_000),
            PqConsensusEpoch::PostCutoffStrictPqPos
        );

        // -manual_fork=1500 overrides activation to 1500
        let overridden = cfg.with_manual_fork(1_500);
        assert_eq!(overridden.effective_pq_witness_vault_time(), 1_500);
        assert_eq!(
            overridden.epoch_at(11, 1_500),
            PqConsensusEpoch::DualTransitionPqPos
        );
        assert_eq!(
            overridden.without_manual_fork().epoch_at(11, 1_500),
            PqConsensusEpoch::PreForkClassicalPos
        );
    }

    #[test]
    fn test_02_pow_epoch_rejects_pos_or_non_empty_block_sig() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 5;
        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);

        let mut bad_pow = make_pow_candidate(1, genesis, 1_060, 10);
        bad_pow.is_proof_of_stake = true;
        assert!(matches!(
            chain.connect_block(bad_pow),
            Err(GauntletError::InvalidProofOfWorkBlock { height: 1, .. })
        ));

        let mut bad_sig_pow = make_pow_candidate(1, genesis, 1_060, 10);
        bad_sig_pow.vch_block_sig = vec![0x1b; 65];
        assert!(matches!(
            chain.connect_block(bad_sig_pow),
            Err(GauntletError::InvalidProofOfWorkBlock { height: 1, .. })
        ));

        let valid_pow = make_pow_candidate(1, genesis, 1_060, 10);
        let summary = chain.connect_block(valid_pow).unwrap();
        assert_eq!(summary.epoch, PqConsensusEpoch::ProofOfWork);
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn test_03_pre_fork_rejects_pq_coinstake_scripts_and_pq_block_sig() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;
        cfg.pq_strict_blocksig_cutoff_time = 3_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 1_060, 10))
            .unwrap();

        // Attempt PQ PoS block at t = 1_999 (< 2_000)
        let mut pq_early = make_pq_pos_candidate(
            &cfg,
            2,
            pow1.block_hash,
            1_999,
            20,
            PqSchemeId::FnDsa512,
            true,
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 1_000],
            0x11,
        );
        // Even if witness_bytes are stripped to 0, pre-activation PQ script must be rejected
        pq_early.witness_bytes = 0;
        pq_early.header_witness_merkle_root = [0u8; 32];
        pq_early.computed_witness_merkle_root = [0u8; 32];

        assert!(matches!(
            chain.connect_block(pq_early),
            Err(GauntletError::PreActivationPqScriptForbidden {
                height: 2,
                block_time: 1_999,
                activation_time: 2_000
            })
        ));
    }

    #[test]
    fn test_04_pre_fork_rejects_segregated_witness_bytes() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 1_060, 10))
            .unwrap();

        let mut classical_with_witness = make_classical_pos_candidate(
            2,
            pow1.block_hash,
            1_500,
            20,
            build_classical_p2pkh_script([0x22; 20]),
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 500],
            0x22,
        );
        classical_with_witness.witness_bytes = 128;
        assert!(matches!(
            chain.connect_block(classical_with_witness),
            Err(GauntletError::PreActivationWitnessDataForbidden {
                height: 2,
                block_time: 1_500,
                witness_bytes: 128
            })
        ));
    }

    #[test]
    fn test_05_exact_activation_boundary_transition_block_time_equals_activation() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;
        cfg.pq_strict_blocksig_cutoff_time = 3_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 1_060, 10))
            .unwrap();

        // Block 2 at t = 1_999 (last pre-fork classical PoS block)
        let pre_fork = chain
            .connect_block(make_classical_pos_candidate(
                2,
                pow1.block_hash,
                1_999,
                20,
                build_classical_vault_script([0x11; 20], [0x22; 20]),
                MIN_VAULT_FUNDING_SAT,
                vec![MIN_VAULT_FUNDING_SAT + 100],
                0x02,
            ))
            .unwrap();
        assert_eq!(pre_fork.epoch, PqConsensusEpoch::PreForkClassicalPos);
        assert!(!pre_fork.crossed_activation_boundary);

        // Block 3 at exact activation boundary t == 2_000 using PQ_STAKING_VAULT + FN-DSA-512
        let exact_boundary = chain
            .connect_block(make_pq_pos_candidate(
                &cfg,
                3,
                pre_fork.block_hash,
                2_000,
                25,
                PqSchemeId::FnDsa512,
                true,
                MIN_VAULT_FUNDING_SAT,
                vec![MIN_VAULT_FUNDING_SAT + 200],
                0x03,
            ))
            .unwrap();
        assert_eq!(exact_boundary.epoch, PqConsensusEpoch::DualTransitionPqPos);
        assert!(exact_boundary.crossed_activation_boundary);
        assert!(exact_boundary.is_exact_activation_timestamp);
        assert_eq!(chain.activation_boundary_crossings(), 1);
        assert_eq!(chain.classical_pos_blocks_connected(), 1);
        assert_eq!(chain.pq_pos_blocks_connected(), 1);
    }

    #[test]
    fn test_06_post_cutoff_rejects_classical_block_sig_and_accepts_fndsa_and_mldsa() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;
        cfg.pq_strict_blocksig_cutoff_time = 3_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 2_500, 10))
            .unwrap();

        // At t = 3_000 (strict cutoff), classical secp256k1 block sig must fail
        let classical_after_cutoff = make_classical_pos_candidate(
            2,
            pow1.block_hash,
            3_000,
            20,
            build_classical_p2pkh_script([0x33; 20]),
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 100],
            0x33,
        );
        assert!(matches!(
            chain.connect_block(classical_after_cutoff),
            Err(GauntletError::BlockSigValidation(
                PqBlockSigError::MissingPostQuantumBlockSigAfterCutoff {
                    block_time: 3_000,
                    cutoff_block_time: 3_000
                }
            ))
        ));

        // ML-DSA-44 P2PQPKH block at t = 3_000 succeeds
        let mldsa_block = chain
            .connect_block(make_pq_pos_candidate(
                &cfg,
                2,
                pow1.block_hash,
                3_000,
                25,
                PqSchemeId::MlDsa44,
                false,
                MIN_VAULT_FUNDING_SAT,
                vec![MIN_VAULT_FUNDING_SAT + 250],
                0x44,
            ))
            .unwrap();
        assert_eq!(mldsa_block.epoch, PqConsensusEpoch::PostCutoffStrictPqPos);
    }

    #[test]
    fn test_07_pq_staking_vault_split_preservation_above_10k_divi() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 2_000, 10))
            .unwrap();

        // Stake 25,000 DIVI in a PQ_STAKING_VAULT and split into two vault outputs:
        // 12,500 DIVI + 12,510 DIVI (both >= 10,000 DIVI, sum = 25,010 DIVI >= 25,000 DIVI)
        let prevout_sat = 25_000 * 100_000_000;
        let split_a = 12_500 * 100_000_000;
        let split_b = 12_510 * 100_000_000;
        let candidate = make_pq_pos_candidate(
            &cfg,
            2,
            pow1.block_hash,
            2_060,
            30,
            PqSchemeId::FnDsa512,
            true,
            prevout_sat,
            vec![split_a, split_b],
            0x55,
        );
        let summary = chain.connect_block(candidate).unwrap();
        assert!(summary.lottery_eligible);
    }

    #[test]
    fn test_08_pq_staking_vault_rejects_split_output_below_10k_divi() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 2_000, 10))
            .unwrap();

        // Stake 20,000 DIVI and split into 15,000 DIVI + 5,010 DIVI (second output < 10,000 DIVI)
        let prevout_sat = 20_000 * 100_000_000;
        let split_a = 15_000 * 100_000_000;
        let split_b = 5_010 * 100_000_000;
        let bad_split = make_pq_pos_candidate(
            &cfg,
            2,
            pow1.block_hash,
            2_060,
            30,
            PqSchemeId::FnDsa512,
            true,
            prevout_sat,
            vec![split_a, split_b],
            0x56,
        );
        assert!(matches!(
            chain.connect_block(bad_split),
            Err(GauntletError::VaultSplitBelowMinimum {
                height: 2,
                output_index: 2,
                output_sat,
                minimum_sat: MIN_VAULT_FUNDING_SAT
            }) if output_sat == split_b
        ));
    }

    #[test]
    fn test_09_pq_staking_vault_rejects_underfunded_principal() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 2_000, 10))
            .unwrap();

        // Staked 15,000 DIVI, but coinstake only returns 12,000 DIVI to vault
        let prevout_sat = 15_000 * 100_000_000;
        let returned_sat = 12_000 * 100_000_000;
        let underfunded = make_pq_pos_candidate(
            &cfg,
            2,
            pow1.block_hash,
            2_060,
            30,
            PqSchemeId::FnDsa512,
            true,
            prevout_sat,
            vec![returned_sat],
            0x57,
        );
        assert!(matches!(
            chain.connect_block(underfunded),
            Err(GauntletError::VaultPrincipalUnderfunded {
                height: 2,
                prevout_sat: p,
                returned_sat: r
            }) if p == prevout_sat && r == returned_sat
        ));
    }

    #[test]
    fn test_10_cold_owner_key_rejected_for_pq_vault_block_signing() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 2_000, 10))
            .unwrap();

        let owner_pk = sample_fndsa512_pubkey(0x70);
        let owner_sig = sample_fndsa512_signature(0x70);
        let owner_hash32 = pq_address_key_hash_256(PqSchemeId::FnDsa512, &owner_pk);
        let hot_vault_hash32 = [0x88; 32];
        let vault_script = build_pq_vault_script(owner_hash32, hot_vault_hash32);

        let coinstake_tx = build_coinstake_tx(
            2,
            vec![(vault_script.clone(), MIN_VAULT_FUNDING_SAT + 1_000)],
        );
        let env =
            PqBlockSigEnvelope::new(PqSchemeId::FnDsa512, owner_pk, owner_sig).expect("envelope");
        let candidate = GauntletBlockCandidate {
            height: 2,
            block_hash: deterministic_hash(0x70, 2),
            prev_block_hash: pow1.block_hash,
            block_time: 2_060,
            block_work: 20,
            is_proof_of_stake: true,
            coinstake_tx: Some(coinstake_tx),
            coinstake_prevout_script: Some(vault_script),
            coinstake_prevout_value_sat: MIN_VAULT_FUNDING_SAT,
            vch_block_sig: env.encode(),
            base_block_bytes: 1_200,
            witness_bytes: 1_500,
            header_witness_merkle_root: [0x11; 32],
            computed_witness_merkle_root: [0x11; 32],
            expected_signing_prehash_512: None,
        };

        assert!(matches!(
            chain.connect_block(candidate),
            Err(GauntletError::BlockSigValidation(
                PqBlockSigError::ColdOwnerKeyForbiddenForBlockSigning { .. }
            ))
        ));
    }

    #[test]
    fn test_11_mutated_witness_merkle_root_and_mutated_block_sig_rejected() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 2_000, 10))
            .unwrap();

        let valid = make_pq_pos_candidate(
            &cfg,
            2,
            pow1.block_hash,
            2_060,
            25,
            PqSchemeId::FnDsa512,
            true,
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 100],
            0x60,
        );

        // 1. Mutate header witness Merkle root
        let mut bad_witness_root = valid.clone();
        bad_witness_root.header_witness_merkle_root[0] ^= 0xff;
        assert!(matches!(
            chain.connect_block(bad_witness_root),
            Err(GauntletError::WitnessMerkleRootMismatch { height: 2, .. })
        ));

        // 2. Mutate last byte of FN-DSA-512 padded signature (sets non-zero bit in zero padding tail)
        let mut bad_sig_padding = valid.clone();
        let last_idx = bad_sig_padding.vch_block_sig.len() - 1;
        bad_sig_padding.vch_block_sig[last_idx] ^= 0x01;
        assert!(matches!(
            chain.connect_block(bad_sig_padding),
            Err(GauntletError::BlockSigValidation(_))
        ));

        // 3. Mutate expected signing prehash
        let mut bad_prehash = valid;
        bad_prehash.expected_signing_prehash_512 = Some([0xff; 64]);
        assert!(matches!(
            chain.connect_block(bad_prehash),
            Err(GauntletError::SigningPrehashMismatch { height: 2, .. })
        ));
    }

    #[test]
    fn test_12_block_weight_and_raw_size_caps_enforced() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let pow1 = chain
            .connect_block(make_pow_candidate(1, genesis, 2_000, 10))
            .unwrap();

        let mut overweight = make_pq_pos_candidate(
            &cfg,
            2,
            pow1.block_hash,
            2_060,
            25,
            PqSchemeId::FnDsa512,
            true,
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 100],
            0x61,
        );
        // 1,600,000 B base + 500,000 B witness = 2,100,000 B > 2 MB raw cap
        overweight.base_block_bytes = 1_600_000;
        overweight.witness_bytes = 500_000;
        assert!(matches!(
            chain.connect_block(overweight),
            Err(GauntletError::BlockWeightExceeded { height: 2, .. })
        ));
    }

    #[test]
    fn test_13_reorg_across_fork_boundary_restores_and_revalidates_cleanly() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 2;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;
        cfg.pq_strict_blocksig_cutoff_time = 3_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);

        let b1 = chain
            .connect_block(make_pow_candidate(1, genesis, 1_100, 10))
            .unwrap();
        let b2 = chain
            .connect_block(make_pow_candidate(2, b1.block_hash, 1_200, 10))
            .unwrap();

        // Pre-fork classical PoS block at height 3 (t = 1_900) — this will be our fork ancestor
        let b3_ancestor = chain
            .connect_block(make_classical_pos_candidate(
                3,
                b2.block_hash,
                1_900,
                20,
                build_classical_vault_script([0x01; 20], [0x02; 20]),
                MIN_VAULT_FUNDING_SAT,
                vec![MIN_VAULT_FUNDING_SAT + 500],
                0x10,
            ))
            .unwrap();

        // Branch A crosses activation at height 4 (t = 2_000) and height 5 (t = 2_060)
        let b4_a = chain
            .connect_block(make_pq_pos_candidate(
                &cfg,
                4,
                b3_ancestor.block_hash,
                2_000,
                20,
                PqSchemeId::FnDsa512,
                true,
                MIN_VAULT_FUNDING_SAT,
                vec![MIN_VAULT_FUNDING_SAT + 500],
                0x20,
            ))
            .unwrap();
        let _b5_a = chain
            .connect_block(make_pq_pos_candidate(
                &cfg,
                5,
                b4_a.block_hash,
                2_060,
                20,
                PqSchemeId::FnDsa512,
                true,
                MIN_VAULT_FUNDING_SAT,
                vec![MIN_VAULT_FUNDING_SAT + 500],
                0x21,
            ))
            .unwrap();

        assert_eq!(chain.height(), 5);
        assert_eq!(chain.classical_pos_blocks_connected(), 1);
        assert_eq!(chain.pq_pos_blocks_connected(), 2);
        assert_eq!(chain.activation_boundary_crossings(), 1);

        // Build heavier Branch B starting from b3_ancestor:
        // - height 4B at t = 1_950 (still pre-fork classical PoS!)
        // - height 5B at t = 2_000 (exact activation boundary with ML-DSA-44!)
        // - height 6B at t = 3_050 (post-cutoff strict PQ PoS with FN-DSA-512!)
        let b4_b = make_classical_pos_candidate(
            4,
            b3_ancestor.block_hash,
            1_950,
            25,
            build_classical_vault_script([0x03; 20], [0x04; 20]),
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 600],
            0x30,
        );
        let b4_b_hash = b4_b.block_hash;
        let b5_b = make_pq_pos_candidate(
            &cfg,
            5,
            b4_b_hash,
            2_000,
            30,
            PqSchemeId::MlDsa44,
            true,
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 700],
            0x31,
        );
        let b5_b_hash = b5_b.block_hash;
        let b6_b = make_pq_pos_candidate(
            &cfg,
            6,
            b5_b_hash,
            3_050,
            35,
            PqSchemeId::FnDsa512,
            false,
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 800],
            0x32,
        );
        let b6_b_hash = b6_b.block_hash;

        let report = chain
            .apply_reorg_across_fork_boundary(b3_ancestor.block_hash, vec![b4_b, b5_b, b6_b])
            .unwrap();

        assert_eq!(report.fork_ancestor_height, 3);
        assert_eq!(report.disconnected_count, 2);
        assert_eq!(report.connected_count, 3);
        assert!(report.rewound_across_activation_boundary);
        assert!(report.reconnected_across_activation_boundary);
        assert_eq!(report.new_tip_hash, b6_b_hash);
        assert_eq!(
            report.new_tip_epoch,
            PqConsensusEpoch::PostCutoffStrictPqPos
        );
        assert_eq!(chain.height(), 6);
        assert_eq!(chain.classical_pos_blocks_connected(), 2); // b3_ancestor + b4_b
        assert_eq!(chain.pq_pos_blocks_connected(), 2); // b5_b + b6_b
        assert_eq!(chain.activation_boundary_crossings(), 1);
    }

    #[test]
    fn test_14_reorg_rolls_back_atomically_on_invalid_replacement_block() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let b1 = chain
            .connect_block(make_pow_candidate(1, genesis, 1_500, 10))
            .unwrap();
        let b2 = chain
            .connect_block(make_classical_pos_candidate(
                2,
                b1.block_hash,
                1_900,
                20,
                build_classical_p2pkh_script([0x11; 20]),
                MIN_VAULT_FUNDING_SAT,
                vec![MIN_VAULT_FUNDING_SAT + 100],
                0x11,
            ))
            .unwrap();
        let b3 = chain
            .connect_block(make_pq_pos_candidate(
                &cfg,
                3,
                b2.block_hash,
                2_050,
                25,
                PqSchemeId::FnDsa512,
                true,
                MIN_VAULT_FUNDING_SAT,
                vec![MIN_VAULT_FUNDING_SAT + 200],
                0x12,
            ))
            .unwrap();

        let pre_reorg_tip = chain.tip().clone();
        let pre_reorg_work = chain.cumulative_work();

        // Replacement branch has a valid block at height 2, followed by a pre-fork PQ script at t=1_950 (invalid!)
        let rep2 = make_classical_pos_candidate(
            2,
            b1.block_hash,
            1_850,
            50,
            build_classical_p2pkh_script([0x22; 20]),
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 100],
            0x41,
        );
        let mut rep3_invalid = make_pq_pos_candidate(
            &cfg,
            3,
            rep2.block_hash,
            1_950, // < 2_000 activation!
            50,
            PqSchemeId::FnDsa512,
            true,
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 200],
            0x42,
        );
        rep3_invalid.witness_bytes = 0;
        rep3_invalid.header_witness_merkle_root = [0u8; 32];
        rep3_invalid.computed_witness_merkle_root = [0u8; 32];

        let res = chain.apply_reorg_across_fork_boundary(b1.block_hash, vec![rep2, rep3_invalid]);
        assert!(matches!(
            res,
            Err(GauntletError::PreActivationPqScriptForbidden { height: 3, .. })
        ));

        // Verify zero state leakage: active chain is untouched at b3
        assert_eq!(chain.tip(), &pre_reorg_tip);
        assert_eq!(chain.tip().block_hash, b3.block_hash);
        assert_eq!(chain.cumulative_work(), pre_reorg_work);
        assert_eq!(chain.classical_pos_blocks_connected(), 1);
        assert_eq!(chain.pq_pos_blocks_connected(), 1);
    }

    #[test]
    fn test_15_reorg_rejected_when_replacement_chain_has_equal_or_less_work() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 1;
        cfg.pq_witness_vault_activation_time = 2_000;
        cfg.pq_dual_blocksig_activation_time = 2_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);
        let b1 = chain
            .connect_block(make_pow_candidate(1, genesis, 1_500, 10))
            .unwrap();
        let b2 = chain
            .connect_block(make_pq_pos_candidate(
                &cfg,
                2,
                b1.block_hash,
                2_010,
                30,
                PqSchemeId::FnDsa512,
                true,
                MIN_VAULT_FUNDING_SAT,
                vec![MIN_VAULT_FUNDING_SAT + 100],
                0x51,
            ))
            .unwrap();

        // Replacement has work 30 (equal, not strictly heavier)
        let rep2 = make_pq_pos_candidate(
            &cfg,
            2,
            b1.block_hash,
            2_020,
            30,
            PqSchemeId::MlDsa44,
            true,
            MIN_VAULT_FUNDING_SAT,
            vec![MIN_VAULT_FUNDING_SAT + 100],
            0x52,
        );
        let res = chain.apply_reorg_across_fork_boundary(b1.block_hash, vec![rep2]);
        assert!(matches!(
            res,
            Err(GauntletError::ReorgCandidateNotHeavier { .. })
        ));
        assert_eq!(chain.tip().block_hash, b2.block_hash);
    }

    #[test]
    fn test_16_superblock_lottery_and_treasury_coexistence_across_pq_epochs() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 100;
        cfg.pq_witness_vault_activation_time = 1_750_001_260;
        cfg.pq_dual_blocksig_activation_time = 1_750_001_260;
        cfg.pq_strict_blocksig_cutoff_time = 1_750_005_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_750_000_000);

        let mut prev_hash = genesis;
        let mut t = 1_750_000_010u32;
        for h in 1..=100 {
            let s = chain
                .connect_block(make_pow_candidate(h, prev_hash, t, 10))
                .unwrap();
            prev_hash = s.block_hash;
            t += 10;
        }

        // Heights 101..=155 cross lottery blocks (110, 120, 130, 140) and treasury block (150)
        // Activate PQ at height 125
        let mut saw_lottery = 0usize;
        let mut saw_treasury = 0usize;
        for h in 101..=155 {
            if h == 125 {
                t = cfg.pq_witness_vault_activation_time;
            } else {
                t += 10;
            }
            let cand = if h < 125 {
                make_classical_pos_candidate(
                    h,
                    prev_hash,
                    t,
                    20,
                    build_classical_vault_script([0x11; 20], [0x22; 20]),
                    MIN_VAULT_FUNDING_SAT,
                    vec![MIN_VAULT_FUNDING_SAT + 1_000],
                    (h & 0xff) as u8,
                )
            } else {
                make_pq_pos_candidate(
                    &cfg,
                    h,
                    prev_hash,
                    t,
                    25,
                    PqSchemeId::FnDsa512,
                    true,
                    MIN_VAULT_FUNDING_SAT,
                    vec![MIN_VAULT_FUNDING_SAT + 1_000],
                    (h & 0xff) as u8,
                )
            };
            let s = chain.connect_block(cand).unwrap();
            match s.superblock_payout {
                SuperblockPayout::Lottery => saw_lottery += 1,
                SuperblockPayout::Treasury => saw_treasury += 1,
                SuperblockPayout::None => {}
            }
            prev_hash = s.block_hash;
        }
        assert!(saw_lottery >= 4);
        assert_eq!(saw_treasury, 1);
        assert!(!chain.current_lottery_winners().coinstakes.is_empty());
    }

    #[test]
    fn test_17_disconnect_genesis_and_unknown_reorg_ancestor_errors() {
        let cfg = PqEpochConfig::regtest_default();
        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);

        assert_eq!(
            chain.disconnect_tip(),
            Err(GauntletError::CannotDisconnectGenesis)
        );

        let unknown = deterministic_hash(0xff, 999);
        assert_eq!(
            chain.apply_reorg_across_fork_boundary(unknown, Vec::new()),
            Err(GauntletError::ReorgCommonAncestorNotFound {
                target_hash: unknown
            })
        );
    }

    #[test]
    fn test_18_thousand_block_mixed_staker_epoch_transition_and_reorg_gauntlet() {
        let mut cfg = PqEpochConfig::regtest_default();
        cfg.pow_last_height = 100;
        // Activation at block 400 (t = 1_000 + 400 * 60 = 25_000)
        // Strict cutoff at block 750 (t = 1_000 + 750 * 60 = 46_000)
        cfg.pq_witness_vault_activation_time = 25_000;
        cfg.pq_dual_blocksig_activation_time = 25_000;
        cfg.pq_strict_blocksig_cutoff_time = 46_000;

        let genesis = deterministic_hash(0x00, 0);
        let mut chain = GauntletChainState::new_with_genesis(cfg, genesis, 1_000);

        let mut prev_hash = genesis;
        let mut fork_ancestor_395_hash = Hash256::zero();
        let mut fork_ancestor_395_time = 0u32;

        for h in 1..=1_000u32 {
            let block_time = 1_000 + h * 60;
            let tag = ((h % 251) as u8).max(1);
            let candidate = if h <= 100 {
                make_pow_candidate(h, prev_hash, block_time, 10)
            } else if h < 400 {
                // Pre-fork classical PoS: alternate classical STAKING_VAULT and P2PKH
                let script = if h % 2 == 0 {
                    build_classical_vault_script([tag; 20], [tag.wrapping_add(1); 20])
                } else {
                    build_classical_p2pkh_script([tag; 20])
                };
                make_classical_pos_candidate(
                    h,
                    prev_hash,
                    block_time,
                    20,
                    script,
                    MIN_VAULT_FUNDING_SAT,
                    vec![MIN_VAULT_FUNDING_SAT + 10_000],
                    tag,
                )
            } else if h < 750 {
                // DualTransitionPqPos: mix classical vault stakers, FN-DSA-512 PQ vaults, and ML-DSA-44 P2PQPKH
                match h % 3 {
                    0 => make_classical_pos_candidate(
                        h,
                        prev_hash,
                        block_time,
                        25,
                        build_classical_vault_script([tag; 20], [tag.wrapping_add(3); 20]),
                        MIN_VAULT_FUNDING_SAT,
                        vec![MIN_VAULT_FUNDING_SAT + 20_000],
                        tag,
                    ),
                    1 => make_pq_pos_candidate(
                        &cfg,
                        h,
                        prev_hash,
                        block_time,
                        25,
                        PqSchemeId::FnDsa512,
                        true,
                        20_000 * 100_000_000,
                        vec![10_000 * 100_000_000, 10_001 * 100_000_000],
                        tag,
                    ),
                    _ => make_pq_pos_candidate(
                        &cfg,
                        h,
                        prev_hash,
                        block_time,
                        25,
                        PqSchemeId::MlDsa44,
                        false,
                        MIN_VAULT_FUNDING_SAT,
                        vec![MIN_VAULT_FUNDING_SAT + 30_000],
                        tag,
                    ),
                }
            } else {
                // PostCutoffStrictPqPos: strictly PQ stakers (FN-DSA-512 and ML-DSA-44)
                let scheme = if h % 2 == 0 {
                    PqSchemeId::FnDsa512
                } else {
                    PqSchemeId::MlDsa44
                };
                make_pq_pos_candidate(
                    &cfg,
                    h,
                    prev_hash,
                    block_time,
                    30,
                    scheme,
                    h % 4 != 0,
                    MIN_VAULT_FUNDING_SAT,
                    vec![MIN_VAULT_FUNDING_SAT + 50_000],
                    tag,
                )
            };

            let summary = chain.connect_block(candidate).unwrap();
            if h == 395 {
                fork_ancestor_395_hash = summary.block_hash;
                fork_ancestor_395_time = summary.block_time;
            }
            if h == 400 {
                assert!(summary.crossed_activation_boundary);
                assert!(summary.is_exact_activation_timestamp);
                assert_eq!(summary.epoch, PqConsensusEpoch::DualTransitionPqPos);
            }
            if h == 750 {
                assert_eq!(summary.epoch, PqConsensusEpoch::PostCutoffStrictPqPos);
            }
            prev_hash = summary.block_hash;
        }

        assert_eq!(chain.height(), 1_000);
        assert_eq!(chain.activation_boundary_crossings(), 1);
        assert!(chain.classical_pos_blocks_connected() > 400);
        assert!(chain.pq_pos_blocks_connected() > 450);

        // Now execute a deep cross-fork reorg from height 395 (pre-fork) through height 410 (post-fork)
        // with higher per-block work so the 16-block replacement branch outweighs blocks 396..=1000!
        let mut replacement = Vec::with_capacity(15);
        let mut rep_prev = fork_ancestor_395_hash;
        for h in 396..=410u32 {
            let block_time = fork_ancestor_395_time + (h - 395) * 60;
            let cand = if block_time < cfg.pq_witness_vault_activation_time {
                make_classical_pos_candidate(
                    h,
                    rep_prev,
                    block_time,
                    2_000,
                    build_classical_vault_script([0x99; 20], [0xaa; 20]),
                    MIN_VAULT_FUNDING_SAT,
                    vec![MIN_VAULT_FUNDING_SAT + 500],
                    0x90 + (h - 395) as u8,
                )
            } else {
                make_pq_pos_candidate(
                    &cfg,
                    h,
                    rep_prev,
                    block_time,
                    2_000,
                    PqSchemeId::FnDsa512,
                    true,
                    MIN_VAULT_FUNDING_SAT,
                    vec![MIN_VAULT_FUNDING_SAT + 500],
                    0x90 + (h - 395) as u8,
                )
            };
            rep_prev = cand.block_hash;
            replacement.push(cand);
        }

        let reorg_report = chain
            .apply_reorg_across_fork_boundary(fork_ancestor_395_hash, replacement)
            .unwrap();
        assert_eq!(reorg_report.fork_ancestor_height, 395);
        assert_eq!(reorg_report.disconnected_count, 605);
        assert_eq!(reorg_report.connected_count, 15);
        assert!(reorg_report.rewound_across_activation_boundary);
        assert!(reorg_report.reconnected_across_activation_boundary);
        assert_eq!(chain.height(), 410);
        assert_eq!(chain.activation_boundary_crossings(), 1);
    }
}
