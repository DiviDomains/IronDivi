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

//! `Track 7D Phase 4` (`Phase 4.3`): Voluntary Holder Migration — Vault & Post-Quantum Sweep Planner.
//!
//! Provides a deterministic, **zero-confiscation** migration planner for `irondivi-cli`,
//! `divi-webui`, and browser/web wallets so holders with historically exposed `secp256k1`
//! public keys (direct `P2PK` outputs, direct `P2PKH` Proof-of-Stake stakers whose `CPubKey`
//! was revealed via `vchBlockSig` `RecoverCompact`, un-swept legacy Masternode collaterals
//! that broadcast `pubKeyCollateralAddress`, and reused `P2PKH` addresses) can voluntarily
//! sweep their funds into 256-bit `PQ_STAKING_VAULT` (`74 B`), `P2PQPKH` (`34 B`), or
//! classical 2-key `STAKING_VAULT` (`50 B`) outputs well ahead of the 2030s CRQC horizon.
//!
//! # Key Guarantees
//!
//! 1. **Zero Forced Confiscation:** Only wallet-owned UTXOs supplied by the holder are planned;
//!    already-insulated `DIP-PQ-3` (`PQ_STAKING_VAULT` and `P2PQPKH`) UTXOs are skipped by default
//!    so repeated sweep runs are strictly idempotent.
//! 2. **Risk-Ordered Prioritization:** Immediately Shor-exposed UTXOs (`DirectPubKeyExposedP2PK`,
//!    `DirectPubKeyExposedPosStaker`, `LegacyMasternodeCollateral`, `ReusedAddressP2PKH`) are
//!    ordered ahead of unexposed `Hash160`-only UTXOs.
//! 3. **Consensus Vault Threshold Enforcement (`>= 10,000 DIVI`):** Sweeps targeting
//!    `PQ_STAKING_VAULT` or `STAKING_VAULT` enforce the `10,000 DIVI` (`1,000,000,000,000` sat)
//!    minimum per vault output (`CheckCoinstakeForVaults`), with configurable sub-threshold
//!    fallback to `P2PQPKH` single-key 256-bit outputs or explicit rejection.
//! 4. **Deterministic Weight & Fee Accounting:** Respects `max_inputs_per_tx` and `max_tx_weight`
//!    (`<= MAX_PQ_BLOCK_WEIGHT`) and computes exact byte/weight-proportional fees (`fee_per_kb_sat`).

use divi_primitives::amount::Amount;
use divi_primitives::constants::COIN;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::{
    compute_pq_tx_weight, create_p2pqpkh_script, create_pq_staking_vault_script, is_p2pk,
    is_p2pqpkh_script, is_pq_staking_vault_script, is_staking_vault_script,
    summarize_staking_posture, StakingVaultScript, MAX_PQ_BLOCK_WEIGHT,
};
use std::cmp::Reverse;
use thiserror::Error;

/// Consensus minimum funding required per staking vault output (`10,000 DIVI` = `1_000_000_000_000` sat).
pub const MIN_VAULT_SWEEP_OUTPUT_SAT: i64 = 10_000 * COIN;

/// Default fee rate in satoshis per 1,000 virtual/serialized bytes (`10,000` sat/KB = `10` sat/B).
pub const DEFAULT_SWEEP_FEE_PER_KB_SAT: u64 = 10_000;

/// Default maximum inputs bundled into a single voluntary sweep transaction (`64`).
pub const DEFAULT_MAX_SWEEP_INPUTS_PER_TX: usize = 64;

/// Default maximum transaction weight per sweep batch (`400,000` WU, 5% of `MAX_PQ_BLOCK_WEIGHT`).
pub const DEFAULT_MAX_SWEEP_TX_WEIGHT: usize = 400_000;

/// Minimum non-dust output value (`5,460` satoshis) for fallback `P2PQPKH` outputs.
pub const MIN_NON_DUST_OUTPUT_SAT: i64 = 5_460;

/// Estimated serialized base size of a transaction header (`version` 4B + `vin` count 1B + `vout` count 1B + `lock_time` 4B = `10` B).
const TX_BASE_OVERHEAD_BYTES: usize = 10;

/// Estimated base input size for a classical `secp256k1` spend (`36 B` outpoint + `1 B` len + `107 B` `scriptSig` + `4 B` sequence = `148` B).
const CLASSICAL_INPUT_BASE_BYTES: usize = 148;

/// Estimated base input size for a `DIP-PQ-3` segregated-witness spend (`36 B` outpoint + `1 B` empty `scriptSig` + `4 B` sequence = `41` B).
const PQ_INPUT_BASE_BYTES: usize = 41;

/// Estimated segregated witness bytes for a `DIP-PQ-3` `FN-DSA-512` input (`~1,570` B).
const PQ_INPUT_WITNESS_BYTES: usize = 1_570;

/// Quantum key-exposure classification for a wallet UTXO (`docs/plans/post-quantum-lockstep.md` §2.2 & Phase 4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuantumExposureReason {
    /// Legacy `P2PK` (`<pubkey> OP_CHECKSIG`) output where the raw 33-byte or 65-byte `secp256k1`
    /// public key is directly visible in `scriptPubKey` on-chain.
    DirectPubKeyExposedP2PK,
    /// Classical `P2PKH` UTXO that has minted a Proof-of-Stake block, revealing its full 33-byte
    /// `CPubKey` in `vchBlockSig` via `RecoverCompact`.
    DirectPubKeyExposedPosStaker,
    /// Un-swept historical Masternode collateral UTXO whose `pubKeyCollateralAddress` was broadcast
    /// in a `CMasternodeBroadcast` message.
    LegacyMasternodeCollateral,
    /// Classical `P2PKH` (or classical vault with a previously spent owner branch) whose public key
    /// was already revealed on-chain by a prior spend from the same address.
    ReusedAddressP2PKH,
    /// Fresh, unspent classical `P2PKH` output (`Hash160`-only on-chain, `address_spend_count == 0`,
    /// never staked). Protected against immediate Shor recovery until first spend (`2^80` Grover preimage).
    UnexposedClassicalP2PKH,
    /// Classical 2-key `STAKING_VAULT` (`50 B`) whose cold `ownerKeyHash` (`Hash160`) has never spent.
    ClassicalVaultInsulated,
    /// `DIP-PQ-3` 256-bit post-quantum native output (`34 B` `P2PQPKH` or `74 B` `PQ_STAKING_VAULT`,
    /// `2^128` `SHA-256` preimage + lattice/hash signature).
    PostQuantumNative,
}

impl QuantumExposureReason {
    /// Deterministic priority rank (`0` = highest urgency to sweep first, `6` = already PQ-native).
    pub const fn priority_rank(self) -> u8 {
        match self {
            Self::DirectPubKeyExposedP2PK => 0,
            Self::DirectPubKeyExposedPosStaker => 1,
            Self::LegacyMasternodeCollateral => 2,
            Self::ReusedAddressP2PKH => 3,
            Self::UnexposedClassicalP2PKH => 4,
            Self::ClassicalVaultInsulated => 5,
            Self::PostQuantumNative => 6,
        }
    }

    /// Returns `true` if the underlying `secp256k1` public key is already exposed on-chain or in P2P
    /// history to offline Shor discrete-logarithm recovery.
    pub const fn is_shor_exposed_immediately(self) -> bool {
        matches!(
            self,
            Self::DirectPubKeyExposedP2PK
                | Self::DirectPubKeyExposedPosStaker
                | Self::LegacyMasternodeCollateral
                | Self::ReusedAddressP2PKH
        )
    }

    /// Returns `true` if this UTXO is already a 256-bit `DIP-PQ-3` post-quantum output.
    pub const fn is_post_quantum_native(self) -> bool {
        matches!(self, Self::PostQuantumNative)
    }
}

/// Target-neutral wallet UTXO descriptor annotated with on-chain key-exposure metadata for
/// voluntary post-quantum sweep planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackableWalletUtxo {
    /// Transaction hash containing this output.
    pub txid: Hash256,
    /// Output index within `txid`.
    pub vout: u32,
    /// Output value in satoshis.
    pub value: Amount,
    /// Locking script (`scriptPubKey`).
    pub script_pubkey: Script,
    /// Encoded wallet address label.
    pub address: String,
    /// Number of historical spends from this address/key recorded by the wallet or indexer.
    pub address_spend_count: u32,
    /// Whether this UTXO (or its address key) has signed a classical PoS block (`vchBlockSig`).
    pub has_staked_pos_block: bool,
    /// Whether this UTXO was previously registered as a legacy Masternode collateral.
    pub is_legacy_masternode_collateral: bool,
    /// Whether this UTXO is mature and spendable at the current chain height.
    pub is_mature: bool,
}

impl TrackableWalletUtxo {
    /// Construct a new [`TrackableWalletUtxo`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        txid: Hash256,
        vout: u32,
        value: Amount,
        script_pubkey: Script,
        address: impl Into<String>,
        address_spend_count: u32,
        has_staked_pos_block: bool,
        is_legacy_masternode_collateral: bool,
        is_mature: bool,
    ) -> Self {
        Self {
            txid,
            vout,
            value,
            script_pubkey,
            address: address.into(),
            address_spend_count,
            has_staked_pos_block,
            is_legacy_masternode_collateral,
            is_mature,
        }
    }

    /// Construct a [`TrackableWalletUtxo`] from a native [`crate::wallet_db::WalletUtxo`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_wallet_utxo(
        utxo: &crate::wallet_db::WalletUtxo,
        current_height: u32,
        maturity: u32,
        address_spend_count: u32,
        has_staked_pos_block: bool,
        is_legacy_masternode_collateral: bool,
    ) -> Self {
        let is_mature = utxo.is_mature(current_height, maturity);
        let staked_direct_p2pkh = utxo.is_coinstake
            && !is_staking_vault_script(&utxo.script_pubkey)
            && is_pq_staking_vault_script(&utxo.script_pubkey).is_none()
            && is_p2pqpkh_script(&utxo.script_pubkey).is_none();
        Self {
            txid: utxo.txid,
            vout: utxo.vout,
            value: utxo.value,
            script_pubkey: utxo.script_pubkey.clone(),
            address: utxo.address.clone(),
            address_spend_count,
            has_staked_pos_block: has_staked_pos_block || staked_direct_p2pkh,
            is_legacy_masternode_collateral,
            is_mature,
        }
    }

    /// Return the [`OutPoint`] for this UTXO.
    pub fn outpoint(&self) -> OutPoint {
        OutPoint::new(self.txid, self.vout)
    }

    /// Classify the quantum key-exposure posture of this UTXO.
    pub fn classify_exposure(&self) -> QuantumExposureReason {
        if is_pq_staking_vault_script(&self.script_pubkey).is_some()
            || is_p2pqpkh_script(&self.script_pubkey).is_some()
        {
            return QuantumExposureReason::PostQuantumNative;
        }
        if is_staking_vault_script(&self.script_pubkey) {
            // If the cold owner branch of a classical vault was ever spent (`address_spend_count > 0`),
            // its owner pubkey was revealed on-chain and should be swept like a reused address.
            if self.address_spend_count > 0 {
                return QuantumExposureReason::ReusedAddressP2PKH;
            }
            return QuantumExposureReason::ClassicalVaultInsulated;
        }
        if is_p2pk(&self.script_pubkey) {
            return QuantumExposureReason::DirectPubKeyExposedP2PK;
        }
        if self.is_legacy_masternode_collateral {
            return QuantumExposureReason::LegacyMasternodeCollateral;
        }
        if self.has_staked_pos_block {
            return QuantumExposureReason::DirectPubKeyExposedPosStaker;
        }
        if self.address_spend_count > 0 {
            return QuantumExposureReason::ReusedAddressP2PKH;
        }
        QuantumExposureReason::UnexposedClassicalP2PKH
    }
}

/// Destination script template for a voluntary vault / post-quantum sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqSweepDestination {
    /// Classical 2-key `STAKING_VAULT` (`50` bytes, `Hash160` commitments) for pre-fork vault insulation.
    ClassicalStakingVault {
        owner_pubkey_hash20: [u8; 20],
        vault_pubkey_hash20: [u8; 20],
    },
    /// `DIP-PQ-3` 256-bit `PQ_STAKING_VAULT` (`74` bytes, `SHA-256` `pq_address_key_hash_256` commitments).
    PqStakingVault {
        owner_key_hash32: [u8; 32],
        vault_key_hash32: [u8; 32],
    },
    /// `DIP-PQ-3` 256-bit `P2PQPKH` (`34` bytes, `OP_1 PUSH32 <addr_key_hash32>`) single-key output.
    PqSingleKey { addr_key_hash32: [u8; 32] },
}

impl PqSweepDestination {
    /// Build the canonical `scriptPubKey` for this sweep destination via `divi-script::vault`.
    pub fn to_script_pubkey(&self) -> Script {
        match self {
            Self::ClassicalStakingVault {
                owner_pubkey_hash20,
                vault_pubkey_hash20,
            } => StakingVaultScript::new(*owner_pubkey_hash20, *vault_pubkey_hash20).to_script(),
            Self::PqStakingVault {
                owner_key_hash32,
                vault_key_hash32,
            } => create_pq_staking_vault_script(owner_key_hash32, vault_key_hash32),
            Self::PqSingleKey { addr_key_hash32 } => create_p2pqpkh_script(addr_key_hash32),
        }
    }

    /// Returns `true` if this destination is a staking vault (`ClassicalStakingVault` or `PqStakingVault`).
    pub const fn is_vault(&self) -> bool {
        matches!(
            self,
            Self::ClassicalStakingVault { .. } | Self::PqStakingVault { .. }
        )
    }

    /// Returns `true` if this destination uses 256-bit `DIP-PQ-3` commitments (`PqStakingVault` or `PqSingleKey`).
    pub const fn is_post_quantum_256(&self) -> bool {
        matches!(self, Self::PqStakingVault { .. } | Self::PqSingleKey { .. })
    }

    /// Validate that a vault destination does not reuse the same key hash for cold owner and hot vault manager.
    pub fn validate_non_degenerate(&self) -> Result<(), PqSweepError> {
        match self {
            Self::ClassicalStakingVault {
                owner_pubkey_hash20,
                vault_pubkey_hash20,
            } if owner_pubkey_hash20 == vault_pubkey_hash20 => {
                Err(PqSweepError::DegenerateVaultKeys)
            }
            Self::PqStakingVault {
                owner_key_hash32,
                vault_key_hash32,
            } if owner_key_hash32 == vault_key_hash32 => Err(PqSweepError::DegenerateVaultKeys),
            _ => Ok(()),
        }
    }
}

/// Policy governing how the sweep planner handles net sweep balances below `10,000 DIVI`
/// (`1_000_000_000_000` sat) when the primary destination is a staking vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubThresholdVaultPolicy {
    /// Reject the sweep with [`PqSweepError::BelowMinimumVaultThreshold`] when a batch cannot fund
    /// at least one `>= 10,000 DIVI` vault output.
    RejectBelowMinimum,
    /// Route sub-`10,000 DIVI` sweeps (or sub-`10,000 DIVI` split remainders) to a 256-bit `P2PQPKH`
    /// fallback output so small holders can still sweep exposed `secp256k1` UTXOs to PQ safety.
    FallbackToPqSingleKey { fallback_addr_key_hash32: [u8; 32] },
}

/// Configuration for [`plan_voluntary_pq_sweep`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSweepPlanConfig {
    /// Primary destination (`PQ_STAKING_VAULT`, `ClassicalStakingVault`, or `PqSingleKey`).
    pub primary_destination: PqSweepDestination,
    /// Behavior when a batch's net value after fees is `< min_vault_funding_sat` (`10,000 DIVI`).
    pub sub_threshold_policy: SubThresholdVaultPolicy,
    /// Fee rate in satoshis per 1,000 serialized bytes (or weight-equivalent virtual bytes).
    pub fee_per_kb_sat: u64,
    /// Maximum number of inputs to bundle in a single sweep transaction.
    pub max_inputs_per_tx: usize,
    /// Maximum `DIP-PQ-3` transaction weight (`base_bytes * 4 + witness_bytes`) per sweep transaction.
    pub max_tx_weight: usize,
    /// Minimum satoshis required per vault output (`>= 10,000 DIVI` = `1_000_000_000_000` sat).
    pub min_vault_funding_sat: i64,
    /// Optional target maximum value per vault output for splitting large balances into multiple
    /// `>= 10,000 DIVI` vault UTXOs.
    pub max_vault_piece_sat: Option<i64>,
    /// Whether to include unexposed classical `P2PKH` UTXOs (`address_spend_count == 0`) alongside
    /// immediately Shor-exposed UTXOs.
    pub include_unexposed_classical: bool,
    /// Whether to sweep existing classical 50-byte `STAKING_VAULT` UTXOs (e.g. when upgrading to
    /// 74-byte 256-bit `PQ_STAKING_VAULT`).
    pub include_classical_vaults: bool,
    /// Whether to re-sweep UTXOs that are already `PostQuantumNative` (`false` by default for idempotency).
    pub resweep_pq_native: bool,
}

impl PqSweepPlanConfig {
    /// Construct a default `PQ_STAKING_VAULT` sweep configuration.
    pub const fn new_pq_vault(
        owner_key_hash32: [u8; 32],
        vault_key_hash32: [u8; 32],
        sub_threshold_policy: SubThresholdVaultPolicy,
    ) -> Self {
        Self {
            primary_destination: PqSweepDestination::PqStakingVault {
                owner_key_hash32,
                vault_key_hash32,
            },
            sub_threshold_policy,
            fee_per_kb_sat: DEFAULT_SWEEP_FEE_PER_KB_SAT,
            max_inputs_per_tx: DEFAULT_MAX_SWEEP_INPUTS_PER_TX,
            max_tx_weight: DEFAULT_MAX_SWEEP_TX_WEIGHT,
            min_vault_funding_sat: MIN_VAULT_SWEEP_OUTPUT_SAT,
            max_vault_piece_sat: None,
            include_unexposed_classical: true,
            include_classical_vaults: true,
            resweep_pq_native: false,
        }
    }

    /// Construct a default `P2PQPKH` single-key post-quantum sweep configuration.
    pub const fn new_pq_single_key(addr_key_hash32: [u8; 32]) -> Self {
        Self {
            primary_destination: PqSweepDestination::PqSingleKey { addr_key_hash32 },
            sub_threshold_policy: SubThresholdVaultPolicy::FallbackToPqSingleKey {
                fallback_addr_key_hash32: addr_key_hash32,
            },
            fee_per_kb_sat: DEFAULT_SWEEP_FEE_PER_KB_SAT,
            max_inputs_per_tx: DEFAULT_MAX_SWEEP_INPUTS_PER_TX,
            max_tx_weight: DEFAULT_MAX_SWEEP_TX_WEIGHT,
            min_vault_funding_sat: MIN_VAULT_SWEEP_OUTPUT_SAT,
            max_vault_piece_sat: None,
            include_unexposed_classical: true,
            include_classical_vaults: false,
            resweep_pq_native: false,
        }
    }
}

/// One planned sweep transaction batch produced by [`plan_voluntary_pq_sweep`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSweepBatchTx {
    /// Zero-based batch index.
    pub batch_index: usize,
    /// Ordered wallet UTXOs consumed by this transaction.
    pub inputs: Vec<TrackableWalletUtxo>,
    /// Unsigned sweep transaction with canonical `TxIn`s and destination `TxOut`s.
    pub unsigned_tx: Transaction,
    /// Sum of input values in satoshis.
    pub input_total_sat: i64,
    /// Sum of output values in satoshis (`input_total_sat - fee_sat`).
    pub output_total_sat: i64,
    /// Deterministic fee in satoshis deducted from this batch.
    pub fee_sat: i64,
    /// Estimated base transaction bytes.
    pub estimated_base_bytes: usize,
    /// Estimated segregated witness bytes.
    pub estimated_witness_bytes: usize,
    /// Estimated `DIP-PQ-3` transaction weight (`base_bytes * 4 + witness_bytes`).
    pub estimated_weight: usize,
    /// Number of vault outputs (`PQ_STAKING_VAULT` or `STAKING_VAULT`) created in this batch.
    pub vault_output_count: usize,
    /// Number of `P2PQPKH` single-key outputs created in this batch.
    pub p2pqpkh_output_count: usize,
}

/// Complete voluntary sweep plan and post-sweep quantum posture audit summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSweepPlan {
    /// Planned sweep transaction batches in execution order.
    pub batches: Vec<PqSweepBatchTx>,
    /// UTXOs intentionally left untouched (already `PostQuantumNative`, unexposed classical when excluded, or immature).
    pub skipped_utxos: Vec<TrackableWalletUtxo>,
    /// Total number of swept inputs across all batches.
    pub swept_input_count: usize,
    /// Number of swept inputs that had historically exposed public keys (`DirectPubKeyExposedP2PK`,
    /// `DirectPubKeyExposedPosStaker`, `LegacyMasternodeCollateral`, or `ReusedAddressP2PKH`).
    pub exposed_input_count: usize,
    /// Sum of input satoshis across all swept batches.
    pub total_input_value_sat: i64,
    /// Sum of output satoshis locked into vault/PQ-insulated scripts across all batches.
    pub insulated_output_value_sat: i64,
    /// Sum of transaction fees in satoshis across all batches.
    pub total_fee_sat: i64,
    /// Aggregate wallet staking posture label before executing the sweep (`"vault_only"` or `"mixed_or_direct_p2pkh"`).
    pub pre_sweep_posture: &'static str,
    /// Aggregate wallet staking posture label after executing the sweep (`"vault_only"` when all remaining UTXOs are insulated).
    pub post_sweep_posture: &'static str,
}

/// Errors returned by [`plan_voluntary_pq_sweep`].
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PqSweepError {
    #[error("invalid PQ sweep configuration: {0}")]
    InvalidConfiguration(&'static str),

    #[error(
        "staking vault destination must use distinct cold owner and hot vault manager key hashes"
    )]
    DegenerateVaultKeys,

    #[error("no eligible wallet UTXOs require sweeping under the current configuration")]
    NoEligibleUtxosToSweep,

    #[error("net sweep balance {net_value_sat} sat is below minimum vault threshold {minimum_sat} sat (10,000 DIVI)")]
    BelowMinimumVaultThreshold {
        net_value_sat: i64,
        minimum_sat: i64,
    },

    #[error("batch input value {input_value_sat} sat is insufficient to cover required fee {required_fee_sat} sat and non-dust output")]
    InsufficientValueForFee {
        input_value_sat: i64,
        required_fee_sat: i64,
    },
}

fn estimate_input_bytes(utxo: &TrackableWalletUtxo) -> (usize, usize) {
    if utxo.classify_exposure().is_post_quantum_native() {
        (PQ_INPUT_BASE_BYTES, PQ_INPUT_WITNESS_BYTES)
    } else {
        (CLASSICAL_INPUT_BASE_BYTES, 0)
    }
}

fn estimate_output_bytes(script: &Script) -> usize {
    // 8-byte value + 1-byte script length CompactSize + script.len()
    8 + 1 + script.len()
}

fn compute_fee_from_weight_and_rate(
    base_bytes: usize,
    witness_bytes: usize,
    fee_per_kb_sat: u64,
) -> i64 {
    let weight = compute_pq_tx_weight(base_bytes, witness_bytes);
    let virtual_bytes = weight.div_ceil(4).max(base_bytes) as u64;
    let fee = (virtual_bytes.saturating_mul(fee_per_kb_sat)).div_ceil(1_000);
    i64::try_from(fee.max(1)).unwrap_or(i64::MAX)
}

fn is_utxo_eligible_for_sweep(utxo: &TrackableWalletUtxo, config: &PqSweepPlanConfig) -> bool {
    if !utxo.is_mature || utxo.value.as_sat() <= 0 {
        return false;
    }
    match utxo.classify_exposure() {
        QuantumExposureReason::DirectPubKeyExposedP2PK
        | QuantumExposureReason::DirectPubKeyExposedPosStaker
        | QuantumExposureReason::LegacyMasternodeCollateral
        | QuantumExposureReason::ReusedAddressP2PKH => true,
        QuantumExposureReason::UnexposedClassicalP2PKH => config.include_unexposed_classical,
        QuantumExposureReason::ClassicalVaultInsulated => config.include_classical_vaults,
        QuantumExposureReason::PostQuantumNative => config.resweep_pq_native,
    }
}

/// Plan a deterministic, voluntary sweep of exposed classical UTXOs into post-quantum or vault-insulated outputs.
pub fn plan_voluntary_pq_sweep(
    utxos: &[TrackableWalletUtxo],
    config: &PqSweepPlanConfig,
) -> Result<PqSweepPlan, PqSweepError> {
    if config.fee_per_kb_sat == 0 {
        return Err(PqSweepError::InvalidConfiguration(
            "fee_per_kb_sat must be > 0",
        ));
    }
    if config.max_inputs_per_tx == 0 {
        return Err(PqSweepError::InvalidConfiguration(
            "max_inputs_per_tx must be > 0",
        ));
    }
    if config.max_tx_weight == 0 || config.max_tx_weight > MAX_PQ_BLOCK_WEIGHT {
        return Err(PqSweepError::InvalidConfiguration(
            "max_tx_weight must be in 1..=MAX_PQ_BLOCK_WEIGHT",
        ));
    }
    if config.min_vault_funding_sat < MIN_VAULT_SWEEP_OUTPUT_SAT {
        return Err(PqSweepError::InvalidConfiguration(
            "min_vault_funding_sat must be >= 10,000 DIVI (1_000_000_000_000 sat)",
        ));
    }
    if let Some(piece_cap) = config.max_vault_piece_sat {
        if piece_cap < config.min_vault_funding_sat {
            return Err(PqSweepError::InvalidConfiguration(
                "max_vault_piece_sat must be >= min_vault_funding_sat",
            ));
        }
    }
    config.primary_destination.validate_non_degenerate()?;

    let pre_sweep_posture = summarize_staking_posture(utxos.iter().map(|u| &u.script_pubkey));

    let mut eligible: Vec<TrackableWalletUtxo> = Vec::new();
    let mut skipped_utxos: Vec<TrackableWalletUtxo> = Vec::new();

    for utxo in utxos {
        if is_utxo_eligible_for_sweep(utxo, config) {
            eligible.push(utxo.clone());
        } else {
            skipped_utxos.push(utxo.clone());
        }
    }

    if eligible.is_empty() {
        return Err(PqSweepError::NoEligibleUtxosToSweep);
    }

    // Sort deterministically: highest exposure risk first, then largest value first, then canonical outpoint
    eligible.sort_by_key(|u| {
        (
            u.classify_exposure().priority_rank(),
            Reverse(u.value.as_sat()),
            u.txid,
            u.vout,
        )
    });

    let primary_script = config.primary_destination.to_script_pubkey();
    let single_output_bytes = estimate_output_bytes(&primary_script);

    // Partition eligible inputs into batches respecting max_inputs_per_tx and max_tx_weight
    let mut raw_batches: Vec<Vec<TrackableWalletUtxo>> = Vec::new();
    let mut current_batch: Vec<TrackableWalletUtxo> = Vec::new();
    let mut current_base_bytes = TX_BASE_OVERHEAD_BYTES + single_output_bytes;
    let mut current_witness_bytes = 0usize;

    for utxo in eligible {
        let (in_base, in_wit) = estimate_input_bytes(&utxo);
        let next_base = current_base_bytes + in_base;
        let next_wit = current_witness_bytes + in_wit;
        let next_weight = compute_pq_tx_weight(next_base, next_wit);

        if !current_batch.is_empty()
            && (current_batch.len() >= config.max_inputs_per_tx
                || next_weight > config.max_tx_weight)
        {
            raw_batches.push(current_batch);
            current_batch = Vec::new();
            current_base_bytes = TX_BASE_OVERHEAD_BYTES + single_output_bytes;
            current_witness_bytes = 0;
        }

        current_base_bytes += in_base;
        current_witness_bytes += in_wit;
        current_batch.push(utxo);
    }
    if !current_batch.is_empty() {
        raw_batches.push(current_batch);
    }

    let mut planned_batches = Vec::with_capacity(raw_batches.len());
    let mut swept_input_count = 0usize;
    let mut exposed_input_count = 0usize;
    let mut total_input_value_sat = 0i64;
    let mut insulated_output_value_sat = 0i64;
    let mut total_fee_sat = 0i64;

    for (batch_index, batch_inputs) in raw_batches.into_iter().enumerate() {
        let input_total_sat: i64 = batch_inputs.iter().map(|u| u.value.as_sat()).sum();
        let (inputs_base_bytes, inputs_witness_bytes) =
            batch_inputs.iter().fold((0usize, 0usize), |(b, w), u| {
                let (ib, iw) = estimate_input_bytes(u);
                (b + ib, w + iw)
            });

        // Plan outputs and exact fee for this batch
        let (outputs, fee_sat, vault_output_count, p2pqpkh_output_count, total_base_bytes) =
            plan_batch_outputs_and_fee(
                input_total_sat,
                inputs_base_bytes,
                inputs_witness_bytes,
                &primary_script,
                config,
            )?;

        let estimated_weight = compute_pq_tx_weight(total_base_bytes, inputs_witness_bytes);
        let output_total_sat: i64 = outputs.iter().map(|o| o.value.as_sat()).sum();
        debug_assert_eq!(output_total_sat + fee_sat, input_total_sat);

        let mut unsigned_tx = Transaction::new();
        unsigned_tx.version = 2;
        unsigned_tx.lock_time = 0;
        for u in &batch_inputs {
            unsigned_tx
                .vin
                .push(TxIn::new(u.outpoint(), Script::new(), 0xffff_ffff));
        }
        unsigned_tx.vout = outputs;

        swept_input_count += batch_inputs.len();
        exposed_input_count += batch_inputs
            .iter()
            .filter(|u| u.classify_exposure().is_shor_exposed_immediately())
            .count();
        total_input_value_sat = total_input_value_sat.saturating_add(input_total_sat);
        insulated_output_value_sat = insulated_output_value_sat.saturating_add(output_total_sat);
        total_fee_sat = total_fee_sat.saturating_add(fee_sat);

        planned_batches.push(PqSweepBatchTx {
            batch_index,
            inputs: batch_inputs,
            unsigned_tx,
            input_total_sat,
            output_total_sat,
            fee_sat,
            estimated_base_bytes: total_base_bytes,
            estimated_witness_bytes: inputs_witness_bytes,
            estimated_weight,
            vault_output_count,
            p2pqpkh_output_count,
        });
    }

    // Compute post-sweep posture across all newly created batch outputs + remaining mature skipped UTXOs
    let mut post_scripts: Vec<&Script> = Vec::new();
    for batch in &planned_batches {
        for out in &batch.unsigned_tx.vout {
            post_scripts.push(&out.script_pubkey);
        }
    }
    for skipped in &skipped_utxos {
        if skipped.is_mature {
            post_scripts.push(&skipped.script_pubkey);
        }
    }
    let post_sweep_posture = summarize_staking_posture(post_scripts);

    Ok(PqSweepPlan {
        batches: planned_batches,
        skipped_utxos,
        swept_input_count,
        exposed_input_count,
        total_input_value_sat,
        insulated_output_value_sat,
        total_fee_sat,
        pre_sweep_posture,
        post_sweep_posture,
    })
}

fn plan_batch_outputs_and_fee(
    input_total_sat: i64,
    inputs_base_bytes: usize,
    inputs_witness_bytes: usize,
    primary_script: &Script,
    config: &PqSweepPlanConfig,
) -> Result<(Vec<TxOut>, i64, usize, usize, usize), PqSweepError> {
    let primary_out_bytes = estimate_output_bytes(primary_script);

    if !config.primary_destination.is_vault() {
        // Single-key P2PQPKH destination
        let total_base_bytes = TX_BASE_OVERHEAD_BYTES + inputs_base_bytes + primary_out_bytes;
        let fee_sat = compute_fee_from_weight_and_rate(
            total_base_bytes,
            inputs_witness_bytes,
            config.fee_per_kb_sat,
        );
        let net_sat = input_total_sat - fee_sat;
        if net_sat < MIN_NON_DUST_OUTPUT_SAT {
            return Err(PqSweepError::InsufficientValueForFee {
                input_value_sat: input_total_sat,
                required_fee_sat: fee_sat + MIN_NON_DUST_OUTPUT_SAT,
            });
        }
        return Ok((
            vec![TxOut::new(
                Amount::from_sat(net_sat),
                primary_script.clone(),
            )],
            fee_sat,
            0,
            1,
            total_base_bytes,
        ));
    }

    // Vault destination (PQ_STAKING_VAULT or ClassicalStakingVault)
    // Determine how many vault pieces we want if max_vault_piece_sat is configured
    let single_vault_base = TX_BASE_OVERHEAD_BYTES + inputs_base_bytes + primary_out_bytes;
    let single_vault_fee = compute_fee_from_weight_and_rate(
        single_vault_base,
        inputs_witness_bytes,
        config.fee_per_kb_sat,
    );
    let prelim_net_sat = input_total_sat - single_vault_fee;

    if prelim_net_sat <= 0 {
        return Err(PqSweepError::InsufficientValueForFee {
            input_value_sat: input_total_sat,
            required_fee_sat: single_vault_fee + MIN_NON_DUST_OUTPUT_SAT,
        });
    }

    if prelim_net_sat < config.min_vault_funding_sat {
        match config.sub_threshold_policy {
            SubThresholdVaultPolicy::RejectBelowMinimum => {
                return Err(PqSweepError::BelowMinimumVaultThreshold {
                    net_value_sat: prelim_net_sat,
                    minimum_sat: config.min_vault_funding_sat,
                });
            }
            SubThresholdVaultPolicy::FallbackToPqSingleKey {
                fallback_addr_key_hash32,
            } => {
                let fallback_script = create_p2pqpkh_script(&fallback_addr_key_hash32);
                let fallback_out_bytes = estimate_output_bytes(&fallback_script);
                let total_base_bytes =
                    TX_BASE_OVERHEAD_BYTES + inputs_base_bytes + fallback_out_bytes;
                let fee_sat = compute_fee_from_weight_and_rate(
                    total_base_bytes,
                    inputs_witness_bytes,
                    config.fee_per_kb_sat,
                );
                let net_sat = input_total_sat - fee_sat;
                if net_sat < MIN_NON_DUST_OUTPUT_SAT {
                    return Err(PqSweepError::InsufficientValueForFee {
                        input_value_sat: input_total_sat,
                        required_fee_sat: fee_sat + MIN_NON_DUST_OUTPUT_SAT,
                    });
                }
                return Ok((
                    vec![TxOut::new(Amount::from_sat(net_sat), fallback_script)],
                    fee_sat,
                    0,
                    1,
                    total_base_bytes,
                ));
            }
        }
    }

    // Net balance is >= min_vault_funding_sat (10,000 DIVI)
    let desired_vault_count = match config.max_vault_piece_sat {
        Some(piece_cap) if prelim_net_sat > piece_cap => {
            let max_by_min = (prelim_net_sat / config.min_vault_funding_sat) as usize;
            let needed_by_cap = (prelim_net_sat as u64).div_ceil(piece_cap as u64) as usize;
            // If remainder would be < min_vault_funding_sat, fold remainder into the last vault output
            needed_by_cap.min(max_by_min).max(1)
        }
        _ => 1,
    };

    // Recompute exact fee for `desired_vault_count` vault outputs
    let mut vault_count = desired_vault_count;
    loop {
        let total_base_bytes =
            TX_BASE_OVERHEAD_BYTES + inputs_base_bytes + vault_count * primary_out_bytes;
        let fee_sat = compute_fee_from_weight_and_rate(
            total_base_bytes,
            inputs_witness_bytes,
            config.fee_per_kb_sat,
        );
        let net_sat = input_total_sat - fee_sat;
        if net_sat >= (vault_count as i64) * config.min_vault_funding_sat {
            let base_piece = net_sat / (vault_count as i64);
            let remainder = net_sat % (vault_count as i64);
            let mut outputs = Vec::with_capacity(vault_count);
            for i in 0..vault_count {
                let piece_sat = if i + 1 == vault_count {
                    base_piece + remainder
                } else {
                    base_piece
                };
                debug_assert!(piece_sat >= config.min_vault_funding_sat);
                outputs.push(TxOut::new(
                    Amount::from_sat(piece_sat),
                    primary_script.clone(),
                ));
            }
            return Ok((outputs, fee_sat, vault_count, 0, total_base_bytes));
        }
        if vault_count > 1 {
            vault_count -= 1;
        } else {
            return Err(PqSweepError::BelowMinimumVaultThreshold {
                net_value_sat: net_sat,
                minimum_sat: config.min_vault_funding_sat,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_script::Opcode;
    use sha2::{Digest, Sha256};

    fn make_txid(tag: u8) -> Hash256 {
        let mut h = Sha256::new();
        h.update([tag]);
        Hash256::from_bytes(h.finalize().into())
    }

    fn make_p2pk_script(tag: u8) -> Script {
        let mut bytes = Vec::with_capacity(35);
        bytes.push(33);
        bytes.push(0x02);
        bytes.extend_from_slice(&[tag; 32]);
        bytes.push(Opcode::OP_CHECKSIG as u8);
        Script::from_bytes(bytes)
    }

    fn make_p2pkh_script(tag: u8) -> Script {
        Script::new_p2pkh(&[tag; 20])
    }

    fn make_classical_vault_script(owner_tag: u8, vault_tag: u8) -> Script {
        StakingVaultScript::new([owner_tag; 20], [vault_tag; 20]).to_script()
    }

    fn make_pq_vault_script(owner_tag: u8, vault_tag: u8) -> Script {
        create_pq_staking_vault_script(&[owner_tag; 32], &[vault_tag; 32])
    }

    fn make_p2pqpkh_script(tag: u8) -> Script {
        create_p2pqpkh_script(&[tag; 32])
    }

    #[test]
    fn test_01_exposure_classification_across_all_utxo_categories() {
        let p2pk = TrackableWalletUtxo::new(
            make_txid(1),
            0,
            Amount::from_divi(5_000),
            make_p2pk_script(0x11),
            "DLegacyP2pk",
            0,
            false,
            false,
            true,
        );
        assert_eq!(
            p2pk.classify_exposure(),
            QuantumExposureReason::DirectPubKeyExposedP2PK
        );
        assert!(p2pk.classify_exposure().is_shor_exposed_immediately());

        let staked_p2pkh = TrackableWalletUtxo::new(
            make_txid(2),
            0,
            Amount::from_divi(15_000),
            make_p2pkh_script(0x22),
            "DStakedP2pkh",
            0,
            true,
            false,
            true,
        );
        assert_eq!(
            staked_p2pkh.classify_exposure(),
            QuantumExposureReason::DirectPubKeyExposedPosStaker
        );

        let mn_collateral = TrackableWalletUtxo::new(
            make_txid(3),
            0,
            Amount::from_divi(100_000),
            make_p2pkh_script(0x33),
            "DMasternodeCollateral",
            0,
            false,
            true,
            true,
        );
        assert_eq!(
            mn_collateral.classify_exposure(),
            QuantumExposureReason::LegacyMasternodeCollateral
        );

        let reused_p2pkh = TrackableWalletUtxo::new(
            make_txid(4),
            0,
            Amount::from_divi(2_000),
            make_p2pkh_script(0x44),
            "DReusedAddr",
            2,
            false,
            false,
            true,
        );
        assert_eq!(
            reused_p2pkh.classify_exposure(),
            QuantumExposureReason::ReusedAddressP2PKH
        );

        let fresh_p2pkh = TrackableWalletUtxo::new(
            make_txid(5),
            0,
            Amount::from_divi(2_000),
            make_p2pkh_script(0x55),
            "DFreshAddr",
            0,
            false,
            false,
            true,
        );
        assert_eq!(
            fresh_p2pkh.classify_exposure(),
            QuantumExposureReason::UnexposedClassicalP2PKH
        );
        assert!(!fresh_p2pkh
            .classify_exposure()
            .is_shor_exposed_immediately());

        let classical_vault = TrackableWalletUtxo::new(
            make_txid(6),
            0,
            Amount::from_divi(20_000),
            make_classical_vault_script(0x61, 0x62),
            "DClassicalVault",
            0,
            true,
            false,
            true,
        );
        assert_eq!(
            classical_vault.classify_exposure(),
            QuantumExposureReason::ClassicalVaultInsulated
        );

        let pq_vault = TrackableWalletUtxo::new(
            make_txid(7),
            0,
            Amount::from_divi(20_000),
            make_pq_vault_script(0x71, 0x72),
            "divi1pqvault",
            0,
            true,
            false,
            true,
        );
        assert_eq!(
            pq_vault.classify_exposure(),
            QuantumExposureReason::PostQuantumNative
        );
        assert!(pq_vault.classify_exposure().is_post_quantum_native());
    }

    #[test]
    fn test_02_classical_vault_with_spent_owner_branch_classified_as_reused() {
        let owner_spent_vault = TrackableWalletUtxo::new(
            make_txid(8),
            0,
            Amount::from_divi(12_000),
            make_classical_vault_script(0x81, 0x82),
            "DClassicalVaultSpentOwner",
            1, // owner branch spent once -> owner pubkey revealed on-chain
            true,
            false,
            true,
        );
        assert_eq!(
            owner_spent_vault.classify_exposure(),
            QuantumExposureReason::ReusedAddressP2PKH
        );
        assert!(owner_spent_vault
            .classify_exposure()
            .is_shor_exposed_immediately());
    }

    #[test]
    fn test_03_priority_ordering_sweeps_most_exposed_utxos_first() {
        let mut cfg = PqSweepPlanConfig::new_pq_vault(
            [0xa1; 32],
            [0xb2; 32],
            SubThresholdVaultPolicy::RejectBelowMinimum,
        );
        cfg.max_inputs_per_tx = 2;

        // Provide UTXOs in reverse risk order
        let utxos = vec![
            TrackableWalletUtxo::new(
                make_txid(10),
                0,
                Amount::from_divi(15_000),
                make_p2pkh_script(0x10),
                "DFresh",
                0,
                false,
                false,
                true,
            ),
            TrackableWalletUtxo::new(
                make_txid(11),
                0,
                Amount::from_divi(15_000),
                make_p2pkh_script(0x11),
                "DReused",
                3,
                false,
                false,
                true,
            ),
            TrackableWalletUtxo::new(
                make_txid(12),
                0,
                Amount::from_divi(15_000),
                make_p2pkh_script(0x12),
                "DMasternode",
                0,
                false,
                true,
                true,
            ),
            TrackableWalletUtxo::new(
                make_txid(13),
                0,
                Amount::from_divi(15_000),
                make_p2pk_script(0x13),
                "DP2PK",
                0,
                false,
                false,
                true,
            ),
        ];

        let plan = plan_voluntary_pq_sweep(&utxos, &cfg).unwrap();
        assert_eq!(plan.batches.len(), 2);
        // Batch 0 must contain P2PK (rank 0) and Masternode collateral (rank 2)
        assert_eq!(
            plan.batches[0].inputs[0].classify_exposure(),
            QuantumExposureReason::DirectPubKeyExposedP2PK
        );
        assert_eq!(
            plan.batches[0].inputs[1].classify_exposure(),
            QuantumExposureReason::LegacyMasternodeCollateral
        );
        // Batch 1 must contain Reused P2PKH (rank 3) and Fresh P2PKH (rank 4)
        assert_eq!(
            plan.batches[1].inputs[0].classify_exposure(),
            QuantumExposureReason::ReusedAddressP2PKH
        );
        assert_eq!(
            plan.batches[1].inputs[1].classify_exposure(),
            QuantumExposureReason::UnexposedClassicalP2PKH
        );
    }

    #[test]
    fn test_04_pq_vault_sweep_preserves_exact_fee_and_post_sweep_posture() {
        let cfg = PqSweepPlanConfig::new_pq_vault(
            [0x11; 32],
            [0x22; 32],
            SubThresholdVaultPolicy::RejectBelowMinimum,
        );

        let utxos = vec![
            TrackableWalletUtxo::new(
                make_txid(20),
                0,
                Amount::from_divi(12_000),
                make_p2pkh_script(0x20),
                "DStaker1",
                0,
                true,
                false,
                true,
            ),
            TrackableWalletUtxo::new(
                make_txid(21),
                1,
                Amount::from_divi(8_000),
                make_p2pk_script(0x21),
                "DP2pk1",
                0,
                false,
                false,
                true,
            ),
        ];

        let plan = plan_voluntary_pq_sweep(&utxos, &cfg).unwrap();
        assert_eq!(plan.batches.len(), 1);
        assert_eq!(plan.swept_input_count, 2);
        assert_eq!(plan.exposed_input_count, 2);
        assert_eq!(plan.pre_sweep_posture, "mixed_or_direct_p2pkh");
        assert_eq!(plan.post_sweep_posture, "vault_only");
        assert_eq!(
            plan.total_input_value_sat,
            plan.insulated_output_value_sat + plan.total_fee_sat
        );
        assert!(plan.total_fee_sat > 0);
        assert_eq!(plan.batches[0].vault_output_count, 1);
        assert_eq!(plan.batches[0].unsigned_tx.vout[0].script_pubkey.len(), 74);
    }

    #[test]
    fn test_05_sub_threshold_vault_sweep_rejected_under_reject_policy() {
        let cfg = PqSweepPlanConfig::new_pq_vault(
            [0x11; 32],
            [0x22; 32],
            SubThresholdVaultPolicy::RejectBelowMinimum,
        );

        // 9,999 DIVI is below the 10,000 DIVI vault minimum
        let utxos = vec![TrackableWalletUtxo::new(
            make_txid(30),
            0,
            Amount::from_divi(9_999),
            make_p2pkh_script(0x30),
            "DSmallHolder",
            1,
            false,
            false,
            true,
        )];

        let res = plan_voluntary_pq_sweep(&utxos, &cfg);
        assert!(matches!(
            res,
            Err(PqSweepError::BelowMinimumVaultThreshold {
                minimum_sat: MIN_VAULT_SWEEP_OUTPUT_SAT,
                ..
            })
        ));
    }

    #[test]
    fn test_06_sub_threshold_vault_sweep_routes_to_p2pqpkh_under_fallback_policy() {
        let fallback_hash = [0x99; 32];
        let cfg = PqSweepPlanConfig::new_pq_vault(
            [0x11; 32],
            [0x22; 32],
            SubThresholdVaultPolicy::FallbackToPqSingleKey {
                fallback_addr_key_hash32: fallback_hash,
            },
        );

        let utxos = vec![TrackableWalletUtxo::new(
            make_txid(31),
            0,
            Amount::from_divi(500),
            make_p2pkh_script(0x31),
            "DSmallExposed",
            2,
            false,
            false,
            true,
        )];

        let plan = plan_voluntary_pq_sweep(&utxos, &cfg).unwrap();
        assert_eq!(plan.batches.len(), 1);
        assert_eq!(plan.batches[0].vault_output_count, 0);
        assert_eq!(plan.batches[0].p2pqpkh_output_count, 1);
        assert_eq!(
            plan.batches[0].unsigned_tx.vout[0].script_pubkey,
            create_p2pqpkh_script(&fallback_hash)
        );
        assert_eq!(plan.post_sweep_posture, "vault_only");
    }

    #[test]
    fn test_07_large_balance_splits_into_multiple_vault_outputs_above_10k_divi() {
        let mut cfg = PqSweepPlanConfig::new_pq_vault(
            [0x11; 32],
            [0x22; 32],
            SubThresholdVaultPolicy::RejectBelowMinimum,
        );
        // Target max 20,000 DIVI per vault piece
        cfg.max_vault_piece_sat = Some(20_000 * COIN);

        // 50,000 DIVI legacy Masternode collateral -> splits into 3 PQ_STAKING_VAULT outputs
        // (~16,666 DIVI each, all >= 10,000 DIVI)
        let utxos = vec![TrackableWalletUtxo::new(
            make_txid(40),
            0,
            Amount::from_divi(50_000),
            make_p2pkh_script(0x40),
            "DMnCollateral50k",
            0,
            false,
            true,
            true,
        )];

        let plan = plan_voluntary_pq_sweep(&utxos, &cfg).unwrap();
        assert_eq!(plan.batches.len(), 1);
        let batch = &plan.batches[0];
        assert_eq!(batch.vault_output_count, 3);
        for out in &batch.unsigned_tx.vout {
            assert!(out.value.as_sat() >= MIN_VAULT_SWEEP_OUTPUT_SAT);
            assert!(is_pq_staking_vault_script(&out.script_pubkey).is_some());
        }
        assert_eq!(
            batch.output_total_sat + batch.fee_sat,
            batch.input_total_sat
        );
    }

    #[test]
    fn test_08_idempotency_skips_already_migrated_pq_native_utxos() {
        let cfg = PqSweepPlanConfig::new_pq_vault(
            [0x11; 32],
            [0x22; 32],
            SubThresholdVaultPolicy::RejectBelowMinimum,
        );

        let pq_vault_utxo = TrackableWalletUtxo::new(
            make_txid(50),
            0,
            Amount::from_divi(25_000),
            make_pq_vault_script(0x11, 0x22),
            "divi1pqvault",
            0,
            true,
            false,
            true,
        );
        let p2pqpkh_utxo = TrackableWalletUtxo::new(
            make_txid(51),
            0,
            Amount::from_divi(5_000),
            make_p2pqpkh_script(0x33),
            "divi1p2pqpkh",
            0,
            false,
            false,
            true,
        );

        // When all UTXOs are already PostQuantumNative, planner returns NoEligibleUtxosToSweep
        let res = plan_voluntary_pq_sweep(&[pq_vault_utxo.clone(), p2pqpkh_utxo.clone()], &cfg);
        assert_eq!(res, Err(PqSweepError::NoEligibleUtxosToSweep));

        // When mixed with 1 exposed classical UTXO, only the classical UTXO is swept and the 2 PQ UTXOs are in skipped_utxos
        let exposed = TrackableWalletUtxo::new(
            make_txid(52),
            0,
            Amount::from_divi(15_000),
            make_p2pk_script(0x52),
            "DExposedP2pk",
            0,
            false,
            false,
            true,
        );
        let plan = plan_voluntary_pq_sweep(&[pq_vault_utxo, p2pqpkh_utxo, exposed], &cfg).unwrap();
        assert_eq!(plan.swept_input_count, 1);
        assert_eq!(plan.skipped_utxos.len(), 2);
        assert_eq!(plan.post_sweep_posture, "vault_only");
    }

    #[test]
    fn test_09_immature_coinbase_or_coinstake_utxos_skipped() {
        let cfg = PqSweepPlanConfig::new_pq_single_key([0x77; 32]);

        let immature = TrackableWalletUtxo::new(
            make_txid(60),
            0,
            Amount::from_divi(20_000),
            make_p2pkh_script(0x60),
            "DImmature",
            1,
            true,
            false,
            false, // not mature yet
        );
        let mature = TrackableWalletUtxo::new(
            make_txid(61),
            0,
            Amount::from_divi(1_000),
            make_p2pkh_script(0x61),
            "DMature",
            1,
            false,
            false,
            true,
        );

        let plan = plan_voluntary_pq_sweep(&[immature, mature], &cfg).unwrap();
        assert_eq!(plan.swept_input_count, 1);
        assert_eq!(plan.skipped_utxos.len(), 1);
        assert!(!plan.skipped_utxos[0].is_mature);
    }

    #[test]
    fn test_10_degenerate_vault_keys_rejected() {
        let same_hash32 = [0xaa; 32];
        let bad_pq_cfg = PqSweepPlanConfig::new_pq_vault(
            same_hash32,
            same_hash32,
            SubThresholdVaultPolicy::RejectBelowMinimum,
        );
        let utxo = TrackableWalletUtxo::new(
            make_txid(70),
            0,
            Amount::from_divi(20_000),
            make_p2pkh_script(0x70),
            "DAddr",
            1,
            false,
            false,
            true,
        );
        assert_eq!(
            plan_voluntary_pq_sweep(std::slice::from_ref(&utxo), &bad_pq_cfg),
            Err(PqSweepError::DegenerateVaultKeys)
        );

        let mut bad_classical_cfg = bad_pq_cfg;
        bad_classical_cfg.primary_destination = PqSweepDestination::ClassicalStakingVault {
            owner_pubkey_hash20: [0xbb; 20],
            vault_pubkey_hash20: [0xbb; 20],
        };
        assert_eq!(
            plan_voluntary_pq_sweep(&[utxo], &bad_classical_cfg),
            Err(PqSweepError::DegenerateVaultKeys)
        );
    }

    #[test]
    fn test_11_classical_staking_vault_destination_produces_50_byte_script() {
        let mut cfg = PqSweepPlanConfig::new_pq_vault(
            [0x11; 32],
            [0x22; 32],
            SubThresholdVaultPolicy::RejectBelowMinimum,
        );
        cfg.primary_destination = PqSweepDestination::ClassicalStakingVault {
            owner_pubkey_hash20: [0x11; 20],
            vault_pubkey_hash20: [0x22; 20],
        };

        let utxo = TrackableWalletUtxo::new(
            make_txid(80),
            0,
            Amount::from_divi(15_000),
            make_p2pkh_script(0x80),
            "DDirectStaker",
            0,
            true,
            false,
            true,
        );

        let plan = plan_voluntary_pq_sweep(&[utxo], &cfg).unwrap();
        assert_eq!(plan.batches.len(), 1);
        let out_script = &plan.batches[0].unsigned_tx.vout[0].script_pubkey;
        assert_eq!(out_script.len(), 50);
        assert!(is_staking_vault_script(out_script));
        assert_eq!(plan.post_sweep_posture, "vault_only");
    }

    #[test]
    fn test_12_batching_respects_max_inputs_per_tx_and_max_tx_weight() {
        let mut cfg = PqSweepPlanConfig::new_pq_single_key([0x88; 32]);
        cfg.max_inputs_per_tx = 3;

        let utxos: Vec<TrackableWalletUtxo> = (0..10u8)
            .map(|i| {
                TrackableWalletUtxo::new(
                    make_txid(90 + i),
                    u32::from(i),
                    Amount::from_divi(5_000),
                    make_p2pkh_script(i),
                    format!("DAddr{i}"),
                    1,
                    false,
                    false,
                    true,
                )
            })
            .collect();

        let plan = plan_voluntary_pq_sweep(&utxos, &cfg).unwrap();
        assert_eq!(plan.batches.len(), 4); // 3 + 3 + 3 + 1
        assert_eq!(plan.batches[0].inputs.len(), 3);
        assert_eq!(plan.batches[1].inputs.len(), 3);
        assert_eq!(plan.batches[2].inputs.len(), 3);
        assert_eq!(plan.batches[3].inputs.len(), 1);
        assert_eq!(plan.swept_input_count, 10);
    }

    #[test]
    fn test_13_dust_input_insufficient_for_fee_returns_error() {
        let cfg = PqSweepPlanConfig::new_pq_single_key([0x99; 32]);
        let dust_utxo = TrackableWalletUtxo::new(
            make_txid(110),
            0,
            Amount::from_sat(1_000), // 1,000 sat < 5,460 sat dust + fee
            make_p2pkh_script(0x99),
            "DDust",
            1,
            false,
            false,
            true,
        );

        let res = plan_voluntary_pq_sweep(&[dust_utxo], &cfg);
        assert!(matches!(
            res,
            Err(PqSweepError::InsufficientValueForFee { .. })
        ));
    }

    #[test]
    fn test_14_exclude_unexposed_classical_leaves_fresh_p2pkh_untouched() {
        let mut cfg = PqSweepPlanConfig::new_pq_single_key([0xaa; 32]);
        cfg.include_unexposed_classical = false;

        let exposed = TrackableWalletUtxo::new(
            make_txid(120),
            0,
            Amount::from_divi(1_000),
            make_p2pk_script(0x11),
            "DP2PK",
            0,
            false,
            false,
            true,
        );
        let unexposed = TrackableWalletUtxo::new(
            make_txid(121),
            0,
            Amount::from_divi(1_000),
            make_p2pkh_script(0x22),
            "DFreshP2PKH",
            0,
            false,
            false,
            true,
        );

        let plan = plan_voluntary_pq_sweep(&[exposed, unexposed], &cfg).unwrap();
        assert_eq!(plan.swept_input_count, 1);
        assert_eq!(plan.exposed_input_count, 1);
        assert_eq!(plan.skipped_utxos.len(), 1);
        // Because an unexposed classical P2PKH remains in the wallet, post_sweep_posture reflects that
        assert_eq!(plan.post_sweep_posture, "mixed_or_direct_p2pkh");
    }

    #[test]
    fn test_15_invalid_config_parameters_rejected() {
        let mut cfg = PqSweepPlanConfig::new_pq_single_key([0xbb; 32]);
        cfg.fee_per_kb_sat = 0;
        assert!(matches!(
            plan_voluntary_pq_sweep(&[], &cfg),
            Err(PqSweepError::InvalidConfiguration(_))
        ));

        let mut cfg2 = PqSweepPlanConfig::new_pq_single_key([0xbb; 32]);
        cfg2.max_inputs_per_tx = 0;
        assert!(matches!(
            plan_voluntary_pq_sweep(&[], &cfg2),
            Err(PqSweepError::InvalidConfiguration(_))
        ));

        let mut cfg3 = PqSweepPlanConfig::new_pq_single_key([0xbb; 32]);
        cfg3.min_vault_funding_sat = MIN_VAULT_SWEEP_OUTPUT_SAT - 1;
        assert!(matches!(
            plan_voluntary_pq_sweep(&[], &cfg3),
            Err(PqSweepError::InvalidConfiguration(_))
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_16_from_wallet_utxo_conversion_marks_direct_coinstake_as_exposed() {
        let mut w_utxo = crate::wallet_db::WalletUtxo::new(
            make_txid(130),
            0,
            Amount::from_divi(15_000),
            make_p2pkh_script(0x33),
            "DDirectStaker".to_string(),
        );
        w_utxo.height = Some(100);
        w_utxo.is_coinstake = true;

        let trackable = TrackableWalletUtxo::from_wallet_utxo(&w_utxo, 250, 100, 0, false, false);
        assert!(trackable.is_mature);
        assert!(trackable.has_staked_pos_block);
        assert_eq!(
            trackable.classify_exposure(),
            QuantumExposureReason::DirectPubKeyExposedPosStaker
        );
    }
}
