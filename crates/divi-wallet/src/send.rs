// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! How a wallet send picks its coins, its fee and its change, as Divi Core's
//! `CWallet::CreateTransaction` does (wallet.cpp:1563-1856) with the
//! `MinimumFeeCoinSelectionAlgorithm` (MinimumFeeCoinSelectionAlgorithm.cpp)
//! its send RPCs use.
//!
//! The fee is the minimum relay fee of an estimate made before signing: the
//! transaction with its payees and no inputs, plus a nominal change output and
//! the largest scriptSig each input can need (plus 40 bytes for the rest of the
//! input). Selection always leaves room for change that is not dust; change
//! that turns out to be dust goes to the fee.

use crate::wallet_db::WalletUtxo;
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::transaction::{Transaction, TxOut};

/// Divi Core `DEFAULT_TX_RELAY_FEE_PER_KILOBYTE` (defaultValues.h:38)
pub const MIN_RELAY_FEE_PER_KB: i64 = 10_000;

/// Divi Core `DEFAULT_TRANSACTION_MAXFEE`, the `-maxtxfee` default (defaultValues.h:34)
pub const DEFAULT_MAX_TX_FEE: Amount = Amount::from_sat(100 * 100_000_000);

/// Divi Core `MAX_STANDARD_TX_SIZE` (defaultValues.h:54)
pub const MAX_STANDARD_TX_SIZE: usize = 100_000;

/// Divi Core `SignatureSizeEstimator::MaximumScriptSigBytesForP2PK`: a
/// signature of at most 73 bytes and its push
const MAX_SCRIPT_SIG_P2PK: usize = 74;

/// Divi Core `SignatureSizeEstimator::MaximumScriptSigBytesForP2PKH`, for a key
/// the wallet does not hold
const MAX_SCRIPT_SIG_P2PKH: usize = 140;

/// Who pays the fee (Divi Core `TransactionFeeMode`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeMode {
    /// The fee comes on top of the payments (the default)
    SenderPays,
    /// `receiver_pays`: the fee is taken from the payments
    ReceiverPays,
    /// `sweep_funds`: every coin goes to the one payee, less the fee
    SweepFunds,
}

impl FeeMode {
    /// The fee mode argument of sendtoaddress, reclaimvaultfunds and
    /// debitvaultbyname: `receiver_pays` or `sweep_funds`; anything else is
    /// not a fee mode
    pub fn parse(mode: &str) -> Option<FeeMode> {
        match mode {
            "receiver_pays" => Some(FeeMode::ReceiverPays),
            "sweep_funds" => Some(FeeMode::SweepFunds),
            _ => None,
        }
    }
}

/// Size Divi Core counts for the change output before it exists
/// (`ChangeOutputType`, MinimumFeeCoinSelectionAlgorithm.h:11-15)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// Ordinary sends
    P2pkh,
    /// Sends from vaults; selection then prefers the least confirmed coins
    Vault,
}

impl ChangeKind {
    fn nominal_size(self) -> usize {
        match self {
            ChangeKind::P2pkh => 34,
            ChangeKind::Vault => 59,
        }
    }
}

/// A coin the send may spend
#[derive(Debug, Clone)]
pub struct SendCoin {
    pub utxo: WalletUtxo,
    /// Confirmations at the tip
    pub depth: u32,
    /// Divi Core `MaxBytesNeededForScriptSig`: the largest scriptSig it can
    /// need plus 40 bytes (I_SignatureSizeEstimator.h:9-12)
    pub input_bytes: usize,
}

/// Divi Core `MaxBytesNeededForSigning` for a script the wallet can spend
/// (SignatureSizeEstimator.cpp), given the public keys and redeem scripts the
/// wallet holds; `None` when Core would give `UINT_MAX` (it cannot spend it).
pub fn max_script_sig_bytes(
    script: &Script,
    pubkey_len: &dyn Fn(&[u8; 20]) -> Option<usize>,
    redeem_script: &dyn Fn(&[u8; 20]) -> Option<Script>,
) -> Option<usize> {
    max_script_sig_bytes_inner(script, pubkey_len, redeem_script, false)
}

fn max_script_sig_bytes_inner(
    script: &Script,
    pubkey_len: &dyn Fn(&[u8; 20]) -> Option<usize>,
    redeem_script: &dyn Fn(&[u8; 20]) -> Option<Script>,
    is_subscript: bool,
) -> Option<usize> {
    use divi_script::{extract_script_type, ScriptType};
    let hash20 = |data: &[u8]| -> Option<[u8; 20]> { data.try_into().ok() };
    let (kind, solutions) = extract_script_type(script.as_bytes());
    match kind {
        ScriptType::PubKey => Some(MAX_SCRIPT_SIG_P2PK),
        ScriptType::PubKeyHash => {
            let hash = hash20(solutions.first()?)?;
            Some(match pubkey_len(&hash) {
                Some(len) => MAX_SCRIPT_SIG_P2PK + 1 + len,
                None => MAX_SCRIPT_SIG_P2PKH,
            })
        }
        ScriptType::Vault => {
            // Owner key first, then the manager key
            for solution in solutions.iter().take(2) {
                if let Some(len) = pubkey_len(&hash20(solution)?) {
                    return Some(MAX_SCRIPT_SIG_P2PK + 1 + len + 1);
                }
            }
            Some(MAX_SCRIPT_SIG_P2PKH + 1)
        }
        ScriptType::Multisig => {
            // [m, pubkeys..., n]
            let keys = solutions.get(1..solutions.len().saturating_sub(1))?;
            let known = keys
                .iter()
                .filter(|key| {
                    let hash: [u8; 20] = *divi_crypto::hash160(key).as_bytes();
                    pubkey_len(&hash).is_some()
                })
                .count();
            Some(1 + known * MAX_SCRIPT_SIG_P2PK)
        }
        ScriptType::ScriptHash if !is_subscript => {
            let subscript = redeem_script(&hash20(solutions.first()?)?)?;
            let inner = max_script_sig_bytes_inner(&subscript, pubkey_len, redeem_script, true)?;
            Some(inner + push_size(subscript.len()))
        }
        _ => None,
    }
}

/// Bytes of `CScript() << data` for data of `len` bytes
fn push_size(len: usize) -> usize {
    len + match len {
        0..=0x4b => 1,
        0x4c..=0xff => 2,
        0x100..=0xffff => 3,
        _ => 5,
    }
}

/// Divi Core `CFeeRate::GetFee` at `per_kb` (FeeRate.cpp:35-43)
pub fn fee_for_size(size: usize, per_kb: i64) -> i64 {
    let fee = per_kb * size as i64 / 1000;
    if fee == 0 && per_kb > 0 {
        per_kb
    } else {
        fee
    }
}

/// Divi Core `MinimumValueForNonDust()` without an output: three times the fee
/// of 182 bytes (FeeAndPriorityCalculator.cpp:26-29)
fn min_change_without_output(per_kb: i64) -> i64 {
    3 * fee_for_size(182, per_kb)
}

/// Why a send cannot be built, with Divi Core's message
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// "Must provide at least one destination for funds."
    NoPayees,
    /// "Transaction output(s) amount too small"
    DustOutput,
    /// "Transaction amounts must be positive. Total output may not exceed limits."
    NotPositive,
    /// "Insufficient funds to meet coin selection algorithm requirements."
    InsufficientFunds,
    /// "Insufficient funds to to pay for tx fee for the requested coin selection algorithm."
    CannotPayFee,
    /// "Cannot subtract needed fees from outputs."
    CannotSubtractFee,
    /// "Cannot sweep inputs."
    CannotSweep,
    /// "Transaction too large"
    TooLarge,
    /// "Selected too few inputs to meet fees"
    FeeTooLow,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SendError::NoPayees => "Must provide at least one destination for funds.",
            SendError::DustOutput => "Transaction output(s) amount too small",
            SendError::NotPositive => {
                "Transaction amounts must be positive. Total output may not exceed limits."
            }
            SendError::InsufficientFunds => {
                "Insufficient funds to meet coin selection algorithm requirements."
            }
            SendError::CannotPayFee => {
                "Insufficient funds to to pay for tx fee for the requested coin selection algorithm."
            }
            SendError::CannotSubtractFee => "Cannot subtract needed fees from outputs.",
            SendError::CannotSweep => "Cannot sweep inputs.",
            SendError::TooLarge => "Transaction too large",
            SendError::FeeTooLow => "Selected too few inputs to meet fees",
        })
    }
}

/// A send ready to sign: the coins to spend, the payee outputs (after any fee
/// taken from them) and the change, if any; the change output goes after the
/// payees
#[derive(Debug, Clone)]
pub struct SendPlan {
    pub inputs: Vec<WalletUtxo>,
    pub outputs: Vec<TxOut>,
    pub change: Option<Amount>,
    pub fee: Amount,
}

/// Fee rate and limit of a send
#[derive(Debug, Clone, Copy)]
pub struct FeePolicy {
    pub per_kb: i64,
    pub max_fee: Amount,
}

impl Default for FeePolicy {
    fn default() -> Self {
        FeePolicy {
            per_kb: MIN_RELAY_FEE_PER_KB,
            max_fee: DEFAULT_MAX_TX_FEE,
        }
    }
}

fn unsigned_tx(inputs: &[&SendCoin], outputs: &[TxOut]) -> Transaction {
    use divi_primitives::transaction::TxIn;
    Transaction {
        version: 1,
        vin: inputs
            .iter()
            .map(|c| TxIn::new(c.utxo.outpoint(), Script::new(), 0xffff_ffff))
            .collect(),
        vout: outputs.to_vec(),
        lock_time: 0,
    }
}

fn value_out(outputs: &[TxOut]) -> i64 {
    outputs.iter().map(|o| o.value.as_sat()).sum()
}

/// Divi Core `BasicCoinSelectionAlgorithm::SelectCoins` with the
/// `MinimumFeeCoinSelectionAlgorithm` ordering
/// (MinimumFeeCoinSelectionAlgorithm.cpp:40-140). `in_tx` are coins already
/// in the transaction (a sweep estimate). Adds the estimated fee to `fees`.
fn basic_select<'a>(
    outputs: &[TxOut],
    in_tx: &[&'a SendCoin],
    coins: &'a [SendCoin],
    change: ChangeKind,
    policy: FeePolicy,
    fees: &mut i64,
) -> Vec<&'a SendCoin> {
    let fee = |size: usize| fee_for_size(size, policy.per_kb);
    let initial = unsigned_tx(in_tx, outputs).size();
    let mut already_covered = 0i64;
    *fees += fee(initial);
    let mut candidates: Vec<&SendCoin> = Vec::new();
    let mut available = 0i64;
    for coin in coins {
        if in_tx
            .iter()
            .any(|c| c.utxo.outpoint() == coin.utxo.outpoint())
        {
            already_covered += coin.utxo.value.as_sat();
            *fees += fee(coin.input_bytes);
            continue;
        }
        candidates.push(coin);
        available += coin.utxo.value.as_sat();
    }
    let target = value_out(outputs) - already_covered;
    let needed = target + min_change_without_output(policy.per_kb) + *fees;
    if needed > available {
        return Vec::new();
    }

    // Core's priority (MinimumFeeCoinSelectionAlgorithm.cpp:127-140): for vault
    // change the least confirmed coin first; then coins that cover the need
    // alone, the smaller scriptSig first; then the larger value net of its own
    // input fee first
    let gap = |c: &SendCoin| c.utxo.value.as_sat() - fee(c.input_bytes);
    candidates.sort_by_key(|c| {
        let depth = if change == ChangeKind::Vault {
            c.depth
        } else {
            0
        };
        let covers = gap(c) >= needed;
        let rank = if covers { 0 } else { -gap(c) };
        (depth, !covers, rank, c.input_bytes)
    });

    let mut selected = Vec::new();
    let mut covered = 0i64;
    let mut bytes = change.nominal_size();
    for coin in candidates {
        selected.push(coin);
        covered += gap(coin);
        bytes += coin.input_bytes;
        if bytes >= MAX_STANDARD_TX_SIZE {
            return Vec::new();
        }
        if covered >= needed {
            *fees += fee(bytes);
            if policy.max_fee.as_sat() < *fees {
                return Vec::new();
            }
            return selected;
        }
    }
    Vec::new()
}

/// Divi Core `SubtractFeesFromOutputs` (wallet.cpp:1647-1685): take `fees`
/// from the payees in order, each kept at its dust limit, then from change
fn subtract_fees_from_outputs(
    fees: i64,
    outputs: &mut [TxOut],
    change: &mut i64,
    per_kb: i64,
) -> bool {
    if fees < 1 {
        return true;
    }
    let initially = value_out(outputs);
    if fees > initially + *change {
        return false;
    }
    let mut paid = 0i64;
    for out in outputs.iter_mut() {
        if paid >= fees {
            break;
        }
        let minimum = out.min_non_dust_value(per_kb).as_sat();
        let available = (out.value.as_sat() - minimum).max(0);
        let take = available.min(fees - paid);
        paid += take;
        out.value = Amount::from_sat(out.value.as_sat() - take);
    }
    let min_change = min_change_without_output(per_kb);
    let from_change = paid < fees;
    let change_can_pay = (*change + paid - fees) >= min_change;
    *change += paid;
    if from_change {
        if !change_can_pay {
            return false;
        }
        *change -= fees;
    }
    *change >= min_change && value_out(outputs) == initially - fees
}

/// Plan a send of `payees` from `coins` as Divi Core's `CreateTransaction`
/// and `SelectInputsProvideSignaturesAndFees` do (wallet.cpp:1753-1856).
pub fn plan_send(
    payees: &[TxOut],
    coins: &[SendCoin],
    mode: FeeMode,
    change_kind: ChangeKind,
    change_script: &Script,
    policy: FeePolicy,
) -> Result<SendPlan, SendError> {
    if payees.is_empty() {
        return Err(SendError::NoPayees);
    }
    if payees.iter().any(|o| o.is_dust_at(policy.per_kb)) {
        return Err(SendError::DustOutput);
    }
    let mut outputs = payees.to_vec();
    let total = value_out(&outputs);
    if mode != FeeMode::SweepFunds && total <= 0 {
        return Err(SendError::NotPositive);
    }

    let sweep = mode == FeeMode::SweepFunds;
    let mut fees = 0i64;
    let selected: Vec<&SendCoin> = if sweep {
        // SweepFundsCoinSelectionAlgorithm (wallet.cpp:1719-1750): every coin,
        // the fee estimated on the transaction spending them all
        let all: Vec<&SendCoin> = coins.iter().collect();
        let mut estimate = outputs.clone();
        estimate[0].value = Amount::from_sat(all.iter().map(|c| c.utxo.value.as_sat()).sum());
        basic_select(&estimate, &all, coins, change_kind, policy, &mut fees);
        all
    } else {
        basic_select(&outputs, &[], coins, change_kind, policy, &mut fees)
    };
    let value_in: i64 = selected.iter().map(|c| c.utxo.value.as_sat()).sum();
    let total_with_fees = if sweep { value_in } else { total + fees };
    if selected.is_empty() || value_in < total_with_fees {
        return Err(SendError::InsufficientFunds);
    }
    if sweep && value_in < fees {
        return Err(SendError::CannotPayFee);
    }

    let mut change = value_in - total_with_fees;
    match mode {
        FeeMode::ReceiverPays => {
            if !subtract_fees_from_outputs(fees, &mut outputs, &mut change, policy.per_kb) {
                return Err(SendError::CannotSubtractFee);
            }
        }
        FeeMode::SweepFunds => {
            // SweepInputsAndTakeFeesFromOutputs (wallet.cpp:1687-1697)
            if outputs.len() != 1 {
                return Err(SendError::CannotSweep);
            }
            outputs[0].value = Amount::from_sat(value_in);
            let mut discarded = min_change_without_output(policy.per_kb);
            if !subtract_fees_from_outputs(fees, &mut outputs, &mut discarded, policy.per_kb) {
                return Err(SendError::CannotSweep);
            }
        }
        FeeMode::SenderPays => {}
    }

    // SetChangeOutput (wallet.cpp:1707-1717): dust change goes to the fee.
    // `change_script` is the change output's script, or one of the same shape.
    let change = if change > 0 {
        if TxOut::new(Amount::from_sat(change), change_script.clone()).is_dust_at(policy.per_kb) {
            fees += change;
            None
        } else {
            Some(Amount::from_sat(change))
        }
    } else {
        None
    };

    Ok(SendPlan {
        inputs: selected.iter().map(|c| c.utxo.clone()).collect(),
        outputs,
        change,
        fee: Amount::from_sat(fees),
    })
}

/// Divi Core's check of the signed transaction
/// (`CheckFeesAreSufficientAndUpdateFeeAsNeeded`, wallet.cpp:1584-1603): not
/// too large, and the fee at least the minimum fee of its size (capped at the
/// maximum fee)
pub fn check_signed(tx: &Transaction, fee: Amount, policy: FeePolicy) -> Result<(), SendError> {
    let size = tx.size();
    if size >= MAX_STANDARD_TX_SIZE {
        return Err(SendError::TooLarge);
    }
    let needed = fee_for_size(size, policy.per_kb).min(policy.max_fee.as_sat());
    if fee.as_sat() < needed {
        return Err(SendError::FeeTooLow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::hash::Hash256;

    const COIN: i64 = 100_000_000;
    /// A compressed-key P2PKH input as Divi Core sizes it: 74 + 1 + 33 + 40
    const P2PKH_INPUT: usize = 148;

    fn p2pkh(tag: u8) -> Script {
        Script::new_p2pkh(&[tag; 20])
    }

    fn coin(tag: u8, sats: i64, depth: u32) -> SendCoin {
        let mut utxo = WalletUtxo::new(
            Hash256::from_bytes([tag; 32]),
            0,
            Amount::from_sat(sats),
            p2pkh(0xaa),
            String::new(),
        );
        utxo.height = Some(1);
        SendCoin {
            utxo,
            depth,
            input_bytes: P2PKH_INPUT,
        }
    }

    fn plan(payees: &[TxOut], coins: &[SendCoin], mode: FeeMode) -> Result<SendPlan, SendError> {
        plan_send(
            payees,
            coins,
            mode,
            ChangeKind::P2pkh,
            &p2pkh(0),
            FeePolicy::default(),
        )
    }

    fn pay(sats: i64) -> TxOut {
        TxOut::new(Amount::from_sat(sats), p2pkh(0xbb))
    }

    /// The fees a Divi Core 3.0.0 regtest wallet paid: 2,260 sat for one input
    /// and one payee (226 bytes), 3,740 for two inputs (373 bytes)
    #[test]
    fn fee_is_divi_core_s_estimate() {
        let one = plan(
            &[pay(10 * COIN)],
            &[coin(1, 1250 * COIN, 30)],
            FeeMode::SenderPays,
        )
        .unwrap();
        assert_eq!(one.fee.as_sat(), 2_260);
        assert_eq!(one.inputs.len(), 1);
        assert_eq!(one.change.unwrap().as_sat(), 1240 * COIN - 2_260);

        let coins = [coin(1, 1250 * COIN, 30), coin(2, 1250 * COIN, 30)];
        let two = plan(&[pay(2000 * COIN)], &coins, FeeMode::SenderPays).unwrap();
        assert_eq!(two.fee.as_sat(), 3_740);
        assert_eq!(two.inputs.len(), 2);
    }

    /// Selection leaves room for change that is not dust: a coin that covers
    /// the payment and fee but would leave less than 5,460 sat of change takes
    /// another coin with it
    #[test]
    fn selection_leaves_room_for_non_dust_change() {
        let tight = coin(1, 10 * COIN + 2_260 + 1_000, 30);
        let small = coin(2, COIN, 30);
        let p = plan(
            &[pay(10 * COIN)],
            &[tight.clone(), small],
            FeeMode::SenderPays,
        )
        .unwrap();
        assert_eq!(p.inputs.len(), 2);
        assert_eq!(p.fee.as_sat(), 3_740);
        // With only that coin there is not enough
        assert_eq!(
            plan(&[pay(10 * COIN)], &[tight], FeeMode::SenderPays).unwrap_err(),
            SendError::InsufficientFunds
        );
    }

    /// A coin that covers the whole need alone is preferred to adding up
    /// larger-first; otherwise the largest coins go first
    #[test]
    fn selection_order_is_core_s() {
        let coins = [
            coin(1, 5 * COIN, 30),
            coin(2, 50 * COIN, 30),
            coin(3, 3 * COIN, 30),
        ];
        let p = plan(&[pay(4 * COIN)], &coins, FeeMode::SenderPays).unwrap();
        assert_eq!(p.inputs.len(), 1);
        let p = plan(&[pay(52 * COIN)], &coins, FeeMode::SenderPays).unwrap();
        let picked: Vec<i64> = p.inputs.iter().map(|u| u.value.as_sat()).collect();
        assert_eq!(picked, vec![50 * COIN, 5 * COIN]);
    }

    /// Change below its dust limit goes to the fee
    #[test]
    fn dust_change_goes_to_the_fee() {
        // With a second coin selection has room, but the change of a coin
        // chosen to cover exactly can still fall under 5,460 sat: here 5,120
        let need = 10 * COIN + 5_460 + 440;
        let exact = coin(1, need + 1_480, 30);
        let p = plan(&[pay(10 * COIN)], &[exact], FeeMode::SenderPays).unwrap();
        assert_eq!(p.change, None);
        assert_eq!(p.fee.as_sat(), 2_260 + 5_120);
    }

    /// receiver_pays: the payee gets the amount less the fee, the sender the
    /// rest as change (Divi Core SubtractFeesFromOutputs)
    #[test]
    fn receiver_pays_takes_the_fee_from_the_payment() {
        let p = plan(
            &[pay(10 * COIN)],
            &[coin(1, 1250 * COIN, 30)],
            FeeMode::ReceiverPays,
        )
        .unwrap();
        assert_eq!(p.outputs[0].value.as_sat(), 10 * COIN - 2_260);
        assert_eq!(p.change.unwrap().as_sat(), 1240 * COIN);
        assert_eq!(p.fee.as_sat(), 2_260);
    }

    /// sweep_funds: every coin to the one payee, less the fee estimated on the
    /// transaction spending them all
    #[test]
    fn sweep_spends_every_coin_to_one_payee() {
        let coins = [coin(1, 1250 * COIN, 30), coin(2, 7 * COIN, 30)];
        let p = plan(&[pay(COIN)], &coins, FeeMode::SweepFunds).unwrap();
        assert_eq!(p.inputs.len(), 2);
        assert_eq!(p.change, None);
        // 126 unsigned bytes (two inputs, one P2PKH output) and 2 x 148
        assert_eq!(p.fee.as_sat(), 1_260 + 2 * 1_480);
        assert_eq!(p.outputs[0].value.as_sat(), 1257 * COIN - p.fee.as_sat());
        assert_eq!(
            plan(&[pay(COIN), pay(COIN)], &coins, FeeMode::SweepFunds).unwrap_err(),
            SendError::CannotSweep
        );
    }

    /// Vault sends take the least confirmed coin first
    #[test]
    fn vault_selection_prefers_the_least_confirmed_coin() {
        let coins = [coin(1, 900 * COIN, 50), coin(2, 800 * COIN, 5)];
        let p = plan_send(
            &[pay(100 * COIN)],
            &coins,
            FeeMode::SenderPays,
            ChangeKind::Vault,
            &p2pkh(0),
            FeePolicy::default(),
        )
        .unwrap();
        assert_eq!(p.inputs[0].value.as_sat(), 800 * COIN);
    }

    /// Divi Core refuses a dust payee, a send above the standard size, and a
    /// fee above -maxtxfee
    #[test]
    fn refusals_are_core_s() {
        assert_eq!(
            plan(&[pay(5_000)], &[coin(1, COIN, 30)], FeeMode::SenderPays).unwrap_err(),
            SendError::DustOutput
        );
        // 700 inputs of 148 bytes pass 100,000 bytes before covering
        let many: Vec<SendCoin> = (0..700)
            .map(|i| coin((i % 250) as u8, COIN / 10, 30))
            .collect();
        assert_eq!(
            plan(&[pay(69 * COIN)], &many, FeeMode::SenderPays).unwrap_err(),
            SendError::InsufficientFunds
        );
        let tight = FeePolicy {
            per_kb: MIN_RELAY_FEE_PER_KB,
            max_fee: Amount::from_sat(2_000),
        };
        assert_eq!(
            plan_send(
                &[pay(10 * COIN)],
                &[coin(1, 1250 * COIN, 30)],
                FeeMode::SenderPays,
                ChangeKind::P2pkh,
                &p2pkh(0),
                tight,
            )
            .unwrap_err(),
            SendError::InsufficientFunds
        );
    }

    /// Divi Core's scriptSig estimates (SignatureSizeEstimator.cpp)
    #[test]
    fn script_sig_estimates_are_core_s() {
        let known = |_: &[u8; 20]| Some(33usize);
        let unknown = |_: &[u8; 20]| None;
        let no_script = |_: &[u8; 20]| None;
        assert_eq!(
            max_script_sig_bytes(&p2pkh(1), &known, &no_script),
            Some(108)
        );
        assert_eq!(
            max_script_sig_bytes(&p2pkh(1), &unknown, &no_script),
            Some(140)
        );
        let vault = divi_script::StakingVaultScript::new([1; 20], [2; 20]).to_script();
        assert_eq!(max_script_sig_bytes(&vault, &known, &no_script), Some(109));
        assert_eq!(
            max_script_sig_bytes(&vault, &unknown, &no_script),
            Some(141)
        );
        assert_eq!(
            max_script_sig_bytes(&Script::from_bytes(vec![0x51]), &known, &no_script),
            None
        );
    }

    /// A signed transaction whose fee is below the minimum for its size is
    /// refused
    #[test]
    fn signed_fee_is_checked() {
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![pay(COIN); 3],
            lock_time: 0,
        };
        let size = tx.size() as i64;
        assert!(check_signed(&tx, Amount::from_sat(size * 10), FeePolicy::default()).is_ok());
        assert_eq!(
            check_signed(&tx, Amount::from_sat(size * 10 - 1), FeePolicy::default()).unwrap_err(),
            SendError::FeeTooLow
        );
    }
}
