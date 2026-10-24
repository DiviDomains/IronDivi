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

//! Wallet RPC methods
//!
//! JSON-RPC methods for wallet operations including address generation,
//! balance queries, and transaction management.

use crate::error::{codes, Error, RpcError};
use crate::protocol::Params;
use base64::{engine::general_purpose::STANDARD, Engine};
use bip39::Mnemonic;
use divi_primitives::amount::Amount;
use divi_primitives::constants::MAX_MONEY;
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::script::Script;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::{OutPoint, Transaction, TxOut, DEFAULT_MIN_RELAY_FEE_PER_KB};
use divi_script::opcodes::Opcode;
use divi_script::StakingVaultScript;
use divi_storage::chain::NetworkType;
use divi_storage::Chain;
use divi_wallet::send::{
    check_signed, max_script_sig_bytes, plan_send, ChangeKind, FeeMode, FeePolicy, SendCoin,
    SendError, SendPlan,
};
use divi_wallet::{
    wallet_db::VaultMetadata, Address, Network, TransactionBuilder, TransactionSigner, WalletDb,
};
use parking_lot::RwLock;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Parse a DIVI amount parameter the way Core's AmountFromValue does
/// (JsonTxHelpers.cpp): reject negatives, values above MaxMoneyOut, and zero
/// unless `allow_zero`; round to the nearest satoshi rather than truncating.
/// Core's MaxMoneyOut is per-network; only the mainnet MAX_MONEY exists here,
/// which is at most 0.03% below the test/regtest limit.
/// Divi Core `EnsureNoOutputsAreDust`: a send whose output would be dust is
/// refused with -4 before anything is built, signed or committed.
fn ensure_not_dust(value: Amount, script: &Script) -> Result<(), Error> {
    if TxOut::new(value, script.clone()).is_dust_at(DEFAULT_MIN_RELAY_FEE_PER_KB) {
        return Err(RpcError::new(
            codes::WALLET_ERROR,
            "Transaction output(s) amount too small",
        )
        .into());
    }
    Ok(())
}

/// Where a send's change goes
enum ChangeTo {
    /// A new change key, taken only when there is change (Divi Core's
    /// CReserveKey, returned to the keypool otherwise)
    NewKey,
    /// A given script (debitvaultbyname: back to the vault)
    Script(Script),
}

impl ChangeTo {
    /// A script of the change output's shape, for its dust limit
    fn template(&self) -> Script {
        match self {
            ChangeTo::NewKey => Script::new_p2pkh(&[0; 20]),
            ChangeTo::Script(script) => script.clone(),
        }
    }
}

/// RPC error for a send that cannot be built: Divi Core's SendMoney answers
/// every CreateTransaction failure with -4 and its text (rpcwallet.cpp:794-798);
/// a total above the balance is caught before, by [`check_send_total`]
fn send_error(e: SendError) -> Error {
    RpcError::new(codes::WALLET_ERROR, e.to_string()).into()
}

/// Divi Core SendMoney's checks before building (rpcwallet.cpp:741-754): a
/// total of 0 or less is -8 "Invalid amount", more than `available` (the
/// spendable, account or vaulted balance) is -6 with both totals in satoshis
fn check_send_total(payees: &[TxOut], available: Amount) -> Result<(), Error> {
    let total: i64 = payees.iter().map(|o| o.value.as_sat()).sum();
    if total <= 0 {
        return Err(RpcError::new(codes::INVALID_PARAMETER, "Invalid amount").into());
    }
    if total > available.as_sat() {
        return Err(RpcError::new(
            codes::WALLET_INSUFFICIENT_FUNDS,
            format!(
                "Insufficient funds: {}(total requested) is greater than {}(total available)",
                total,
                available.as_sat()
            ),
        )
        .into());
    }
    Ok(())
}

/// The value of `coins`
fn coins_value(coins: &[divi_wallet::WalletUtxo]) -> Amount {
    Amount::from_sat(coins.iter().map(|u| u.value.as_sat()).sum())
}

/// Divi Core's GetSpendableBalance (WalletBalanceCalculator.cpp:80-87):
/// confirmed mature coins plus unconfirmed ones whose inputs were all ours,
/// vaults left out
fn spendable_balance(wallet: &WalletDb, height: u32) -> Amount {
    coins_value(&wallet.get_spendable_utxos(height, 0))
}

/// IronDivi's `subtractfeefromamount` for sendmany (Divi Core has none): the
/// fee is split evenly over the listed outputs, the first taking the
/// remainder, and the sender keeps that much more as change; if that change
/// would be dust it goes to the fee, as all dust change does
fn subtract_fee_from_outputs(plan: &mut SendPlan, outputs: &[usize]) -> Result<(), Error> {
    let fee = plan.fee.as_sat();
    let n = outputs.len() as i64;
    for (k, &i) in outputs.iter().enumerate() {
        let share = fee / n + if k == 0 { fee % n } else { 0 };
        let out = &mut plan.outputs[i];
        let reduced = TxOut::new(
            Amount::from_sat(out.value.as_sat() - share),
            out.script_pubkey.clone(),
        );
        if reduced.value.as_sat() <= 0 || reduced.is_dust_at(DEFAULT_MIN_RELAY_FEE_PER_KB) {
            return Err(
                RpcError::invalid_params("Amount is too small to subtract the fee from").into(),
            );
        }
        *out = reduced;
    }
    let change = plan.change.map_or(0, |c| c.as_sat()) + fee;
    if TxOut::new(Amount::from_sat(change), Script::new_p2pkh(&[0; 20]))
        .is_dust_at(DEFAULT_MIN_RELAY_FEE_PER_KB)
    {
        plan.change = None;
        plan.fee = Amount::from_sat(fee + fee);
    } else {
        plan.change = Some(Amount::from_sat(change));
    }
    Ok(())
}

/// The fee mode argument of sendtoaddress, reclaimvaultfunds and
/// debitvaultbyname (Divi Core rpcwallet.cpp:1336-1356, :1118-1132, :1162-1184)
fn parse_fee_mode(mode: Option<&str>, allow_metadata: bool) -> Result<FeeMode, Error> {
    match mode {
        None | Some("") => Ok(FeeMode::SenderPays),
        Some("metadata") if allow_metadata => Ok(FeeMode::SenderPays),
        Some(other) => FeeMode::parse(other).ok_or_else(|| {
            RpcError::new(
                codes::INVALID_PARAMETER,
                "Unknown option for reclaiming vault funds",
            )
            .into()
        }),
    }
}

/// Divi Core `EnsureWalletIsUnlocked`: sends, signing and key exports need a full
/// unlock, so a wallet unlocked for staking only is refused like a locked one.
fn ensure_fully_unlocked(wallet: &WalletDb) -> Result<(), Error> {
    if !wallet.is_fully_unlocked() {
        return Err(RpcError::new(
            codes::WALLET_UNLOCK_NEEDED,
            "Error: Please enter the wallet passphrase with walletpassphrase first.",
        )
        .into());
    }
    Ok(())
}

/// RPC error for a failed getnewaddress-style key request, as Divi Core
fn new_key_error(e: divi_wallet::WalletError) -> Error {
    match e {
        divi_wallet::WalletError::KeypoolRanOut => RpcError::new(
            codes::WALLET_KEYPOOL_RAN_OUT,
            "Error: Keypool ran out, please call keypoolrefill first",
        ),
        divi_wallet::WalletError::WalletLocked => {
            RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked")
        }
        _ => RpcError::new(codes::WALLET_ERROR, e.to_string()),
    }
    .into()
}

fn amount_from_value(value: &serde_json::Value, allow_zero: bool) -> Result<Amount, Error> {
    let invalid = || RpcError::new(codes::TYPE_ERROR, "Invalid amount");
    // json_spirit's get_real on anything but a number (rpcserver.cpp:1107-1108)
    let divi = value.as_f64().ok_or_else(|| {
        RpcError::new(
            codes::MISC_ERROR,
            format!("value is type {}, expected real", json_spirit_type(value)),
        )
    })?;
    if !(0.0..=MAX_MONEY.as_divi_f64()).contains(&divi) {
        return Err(invalid().into());
    }
    let amount = Amount::from_divi_f64(divi);
    if (!allow_zero && amount.is_zero()) || amount > MAX_MONEY {
        return Err(invalid().into());
    }
    Ok(amount)
}

/// The type name json_spirit gives a value in its "value is type X, expected Y"
/// errors (json_spirit_value.h Value_type_name)
pub(crate) fn json_spirit_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Object(_) => "obj",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::String(_) => "str",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(n) if n.is_f64() => "real",
        serde_json::Value::Number(_) => "int",
        serde_json::Value::Null => "null",
    }
}

/// Compute the "bare txid": the txid of `tx` with every input's `scriptSig`
/// cleared, matching Core's `CTransaction::GetBareTxid()`
/// (primitives/transaction.cpp). Signing a transaction fills in scriptSigs,
/// which changes `txid()`; the bare txid stays stable across that, so it is
/// the identifier adaptor-signature swaps commit to before any signature
/// exists. Coinbase transactions have no real signature, so Core defines
/// their bare txid as equal to the normal txid (clearing the coinbase
/// scriptSig would otherwise collide distinct coinbases on the same bare
/// txid); mirror that special case here.
pub(crate) fn bare_txid(tx: &Transaction) -> Hash256 {
    if tx.is_coinbase() {
        return tx.txid();
    }
    let mut stripped = tx.clone();
    for input in &mut stripped.vin {
        input.script_sig = Script::new();
    }
    stripped.txid()
}

/// A script as Divi Core's ScriptPubKeyToJSON shows it (JsonTxHelpers.cpp:15-37):
/// asm, hex (when asked), then reqSigs and addresses whenever the script has
/// standard destinations
pub(crate) fn script_pubkey_to_json(
    script_bytes: &[u8],
    network: Network,
    include_hex: bool,
) -> serde_json::Value {
    use divi_script::{extract_destinations, extract_script_type, get_script_type_name, to_asm};
    let (script_type, _solutions) = extract_script_type(script_bytes);
    let mut script_obj = json!({
        "asm": to_asm(script_bytes),
        "type": get_script_type_name(script_type),
    });
    if include_hex {
        script_obj["hex"] = json!(hex::encode(script_bytes));
    }
    if let Some((_stype, destinations, req_sigs)) = extract_destinations(script_bytes) {
        script_obj["reqSigs"] = json!(req_sigs);
        let addresses: Vec<String> = destinations
            .iter()
            .map(|dest| match dest {
                divi_script::Destination::PubKeyHash(pkh) => {
                    Address::from_pubkey_hash(Hash160::from_bytes(*pkh), network).to_base58()
                }
                divi_script::Destination::ScriptHash(sh) => {
                    Address::p2sh(Hash160::from_bytes(*sh), network).to_base58()
                }
            })
            .collect();
        script_obj["addresses"] = json!(addresses);
    }
    script_obj
}

/// Divi Core's ParseHexV (rpcserver.cpp): a non-empty, even-length hex string,
/// else -8 "<name> must be hexadecimal string (not '<value>')"
pub(crate) fn parse_hex_v(value: &str, name: &str) -> Result<Vec<u8>, Error> {
    match hex::decode(value) {
        Ok(bytes) if !bytes.is_empty() => Ok(bytes),
        _ => Err(RpcError::new(
            codes::INVALID_PARAMETER,
            format!("{name} must be hexadecimal string (not '{value}')"),
        )
        .into()),
    }
}

/// Decoded transaction as `getrawtransaction <txid> 1` shows it (without the block fields),
/// with addresses encoded for `network`.
pub(crate) fn tx_to_json(tx: &Transaction, network: Network) -> serde_json::Value {
    use divi_script::to_asm;

    let vin: Vec<serde_json::Value> = tx
        .vin
        .iter()
        .map(|input| {
            if input.prevout.txid == Hash256::zero() && input.prevout.vout == 0xffffffff {
                return json!({
                    "coinbase": hex::encode(input.script_sig.as_bytes()),
                    "sequence": input.sequence,
                });
            }
            json!({
                "txid": input.prevout.txid.to_string(),
                "vout": input.prevout.vout,
                "scriptSig": {
                    "asm": to_asm(input.script_sig.as_bytes()),
                    "hex": hex::encode(input.script_sig.as_bytes()),
                },
                "sequence": input.sequence,
            })
        })
        .collect();

    let vout: Vec<serde_json::Value> = tx
        .vout
        .iter()
        .enumerate()
        .map(|(n, output)| {
            let script_obj = script_pubkey_to_json(output.script_pubkey.as_bytes(), network, true);
            json!({
                "value": output.value.as_divi_f64(),
                "valueSat": output.value.as_sat(),
                "n": n,
                "scriptPubKey": script_obj,
            })
        })
        .collect();

    let hex_value = hex::encode(serialize(tx));
    json!({
        "hex": hex_value,
        "txid": tx.txid().to_string(),
        "baretxid": bare_txid(tx).to_string(),
        "version": tx.version,
        "locktime": tx.lock_time,
        "size": hex_value.len() / 2,
        "vin": vin,
        "vout": vout,
    })
}

/// What Divi Core's TxToJSONExpanded adds from the spent index
/// (rpcrawtransaction.cpp:72-110): each input's value, valueSat and address,
/// and each spent output's spentTxId, spentIndex and spentHeight
fn add_spent_info(
    result: &mut serde_json::Value,
    tx: &Transaction,
    chain: &Chain,
    network: Network,
) {
    use divi_storage::SpentIndexKey;
    let Some(search) = chain.search_index().filter(|s| s.spent_enabled()) else {
        return;
    };
    if !tx.is_coinbase() {
        for (input, entry) in tx
            .vin
            .iter()
            .zip(result["vin"].as_array_mut().into_iter().flatten())
        {
            let key = SpentIndexKey::new(input.prevout.txid, input.prevout.vout);
            let Ok(Some(spent)) = search.read_spent(&key) else {
                continue;
            };
            let hash = Hash160::from_bytes(spent.address_hash);
            let address = match spent.address_type {
                1 => Some(Address::from_pubkey_hash(hash, network).to_base58()),
                2 => Some(Address::p2sh(hash, network).to_base58()),
                _ => None,
            };
            entry["value"] = json!(spent.amount.as_divi_f64());
            entry["valueSat"] = json!(spent.amount.as_sat());
            if let Some(address) = address {
                entry["address"] = json!(address);
            }
        }
    }
    let txid = tx.txid();
    let bare = bare_txid(tx);
    for (n, entry) in result["vout"]
        .as_array_mut()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let n = n as u32;
        let found = search
            .read_spent(&SpentIndexKey::new(txid, n))
            .ok()
            .flatten()
            .or_else(|| {
                search
                    .read_spent(&SpentIndexKey::new(bare, n))
                    .ok()
                    .flatten()
            });
        if let Some(spent) = found {
            entry["spentTxId"] = json!(spent.spending_txid.to_string());
            entry["spentIndex"] = json!(spent.input_index);
            entry["spentHeight"] = json!(spent.block_height);
        }
    }
}

/// Base64 decoding as Divi Core's DecodeBase64 does it: decoding stops at the first
/// character outside the alphabet, and only a dangling partial group (without the
/// matching '=' padding) makes the input invalid.
fn decode_base64_like_core(s: &str) -> Option<Vec<u8>> {
    let (out, valid) = decode_base64_core(s);
    valid.then_some(out)
}

/// Divi Core's DecodeBase64: the bytes decoded up to the first character that
/// is not base64, and whether the input was valid (`pfInvalid`)
fn decode_base64_core(s: &str) -> (Vec<u8>, bool) {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let (mut out, mut mode, mut left, mut i) = (Vec::new(), 0, 0u8, 0);
    while let Some(dec) = bytes.get(i).copied().and_then(value) {
        i += 1;
        match mode {
            0 => left = dec,
            1 => {
                out.push((left << 2) | (dec >> 4));
                left = dec & 15;
            }
            2 => {
                out.push((left << 4) | (dec >> 2));
                left = dec & 3;
            }
            _ => out.push((left << 6) | dec),
        }
        mode = (mode + 1) % 4;
    }
    let rest = &bytes[i..];
    let ends_group = |n: usize| rest.get(n).copied().and_then(value).is_none();
    let valid = match mode {
        0 => true,
        1 => false,
        2 => left == 0 && rest.starts_with(b"==") && ends_group(2),
        _ => left == 0 && rest.starts_with(b"=") && ends_group(1),
    };
    (out, valid)
}

/// Divi Core's ParseHex: skip whitespace before each byte, stop at the first
/// pair that is not two hex digits
fn parse_hex_like_core(s: &str) -> Vec<u8> {
    let digit = |c: Option<&u8>| (*c? as char).to_digit(16).map(|d| d as u8);
    let bytes = s.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    loop {
        while bytes.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
            i += 1;
        }
        let (Some(hi), Some(lo)) = (digit(bytes.get(i)), digit(bytes.get(i + 1))) else {
            return out;
        };
        out.push((hi << 4) | lo);
        i += 2;
    }
}

/// Callback for submitting transactions to the mempool and network
pub type TxSubmitCallback =
    Arc<dyn Fn(Transaction) -> Result<Hash256, TxSubmitError> + Send + Sync>;

/// Why the node refused a transaction handed to the submit callback
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxSubmitError {
    /// Refused by the mempool with Divi Core's reject code and reason;
    /// RPC -26 "<code>: <reason>"
    Rejected { code: u8, reason: String },
    /// An input is neither in the chain nor the mempool; RPC -26
    /// "Unknown inputs being spent"
    UnknownInputs,
    /// Any other failure; RPC -25 with the message
    Failed(String),
}

impl From<String> for TxSubmitError {
    fn from(message: String) -> Self {
        TxSubmitError::Failed(message)
    }
}

/// Divi Core DEFAULT_TRANSACTION_MAXFEE: sendrawtransaction refuses a higher fee
/// unless allowhighfees is given
const MAX_TX_FEE: Amount = Amount::from_sat(100 * 100_000_000);

/// Wallet RPC handler
pub struct WalletRpc {
    wallet: Arc<RwLock<Option<Arc<WalletDb>>>>,
    height: Arc<RwLock<u32>>,
    tx_submit: RwLock<Option<TxSubmitCallback>>,
    chain: Option<Arc<Chain>>,
    /// Fetches pruned blocks from full-history peers during rescan
    block_fetcher: RwLock<Option<Arc<dyn crate::blockchain::BlockFetcher>>>,
    /// Node mempool: unconfirmed spends, and `getrawtransaction` for pool transactions
    mempool: RwLock<Option<Arc<dyn crate::blockchain::MempoolProvider>>>,
}

/// Scan the active chain into the wallet, in order, from its last scanned
/// height up to the tip (rolling back first if the chain switched under it).
/// Returns the heights whose block could not be read (pruned); they are
/// skipped.
pub fn sync_wallet_with_chain(wallet: &WalletDb, chain: &Chain) -> Vec<u32> {
    wallet.sync_to_tip(
        chain.height(),
        |height| {
            chain
                .get_block_index_by_height(height)
                .ok()
                .flatten()
                .map(|index| index.hash)
        },
        |height| {
            let index = chain.get_block_index_by_height(height).ok().flatten()?;
            let block = chain.get_block(&index.hash).ok().flatten()?;
            Some((index.hash, block))
        },
    )
}

impl WalletRpc {
    /// Amount received per address over all outputs the wallet received at
    /// `min_conf` or more, spent or not, with the fewest confirmations among
    /// them. Coinbase outputs are left out, as in Core's received-by RPCs.
    fn received_by_address(&self, wallet: &WalletDb, min_conf: u32) -> HashMap<String, (i64, u32)> {
        let height = self.current_height();
        let mut by_addr: HashMap<String, (i64, u32)> = HashMap::new();
        for output in wallet.received_outputs() {
            let confs = output.confirmations(height);
            // A bare multisig output has no address to tally under
            if output.is_coinbase || confs < min_conf || output.address.is_empty() {
                continue;
            }
            let entry = by_addr.entry(output.address).or_insert((0, u32::MAX));
            entry.0 += output.value.as_sat();
            entry.1 = entry.1.min(confs);
        }
        by_addr
    }

    /// Bring the wallet up to the active chain after the chain moved without
    /// a block notification (invalidateblock, reconsiderblock)
    pub fn sync_with_chain(&self) {
        let (Some(chain), Ok(wallet)) = (self.chain.as_ref(), self.get_wallet()) else {
            return;
        };
        sync_wallet_with_chain(&wallet, chain);
        if let Err(e) = wallet.save_incremental() {
            warn!("Failed to save wallet after chain sync: {}", e);
        }
    }

    pub fn new() -> Self {
        WalletRpc {
            wallet: Arc::new(RwLock::new(None)),
            height: Arc::new(RwLock::new(0)),
            tx_submit: RwLock::new(None),
            block_fetcher: RwLock::new(None),
            mempool: RwLock::new(None),
            chain: None,
        }
    }

    pub fn set_block_fetcher(&self, fetcher: Arc<dyn crate::blockchain::BlockFetcher>) {
        *self.block_fetcher.write() = Some(fetcher);
    }

    /// Set the node mempool
    pub fn set_mempool(&self, mempool: Arc<dyn crate::blockchain::MempoolProvider>) {
        *self.mempool.write() = Some(mempool);
    }

    /// Address-encoding network of the chain this node runs on (the wallet's when
    /// there is no chain); every address or key the RPC prints uses it
    fn address_network(&self) -> Network {
        use divi_storage::chain::NetworkType;
        match self.chain.as_ref().map(|c| c.network_type()) {
            Some(NetworkType::Mainnet) => Network::Mainnet,
            Some(NetworkType::Testnet) => Network::Testnet,
            Some(NetworkType::Regtest) => Network::Regtest,
            None => self
                .wallet
                .read()
                .as_ref()
                .map(|w| w.network())
                .unwrap_or(Network::Mainnet),
        }
    }

    pub fn with_wallet(wallet: Arc<WalletDb>) -> Self {
        WalletRpc {
            wallet: Arc::new(RwLock::new(Some(wallet))),
            height: Arc::new(RwLock::new(0)),
            tx_submit: RwLock::new(None),
            block_fetcher: RwLock::new(None),
            mempool: RwLock::new(None),
            chain: None,
        }
    }

    /// Create with chain reference (needed for rescan)
    pub fn with_chain(chain: Arc<Chain>) -> Self {
        WalletRpc {
            wallet: Arc::new(RwLock::new(None)),
            height: Arc::new(RwLock::new(0)),
            tx_submit: RwLock::new(None),
            block_fetcher: RwLock::new(None),
            mempool: RwLock::new(None),
            chain: Some(chain),
        }
    }

    /// Create with wallet and chain
    pub fn with_wallet_and_chain(wallet: Arc<WalletDb>, chain: Arc<Chain>) -> Self {
        WalletRpc {
            wallet: Arc::new(RwLock::new(Some(wallet))),
            height: Arc::new(RwLock::new(0)),
            tx_submit: RwLock::new(None),
            block_fetcher: RwLock::new(None),
            mempool: RwLock::new(None),
            chain: Some(chain),
        }
    }

    /// Set the wallet
    pub fn set_wallet(&self, wallet: Arc<WalletDb>) {
        *self.wallet.write() = Some(wallet);
    }

    /// Update the current chain height
    pub fn set_height(&self, height: u32) {
        *self.height.write() = height;
    }

    /// Set the transaction submission callback
    pub fn set_tx_submit(&self, callback: TxSubmitCallback) {
        *self.tx_submit.write() = Some(callback);
    }

    /// The loaded wallet, if any
    pub fn wallet_db(&self) -> Option<Arc<WalletDb>> {
        self.wallet.read().clone()
    }

    /// Get the wallet or return an error
    fn get_wallet(&self) -> Result<Arc<WalletDb>, Error> {
        self.wallet
            .read()
            .clone()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Wallet not loaded").into())
    }

    /// Network this node runs on: the chain's, else the loaded wallet's
    fn network(&self) -> Network {
        if let Some(ref chain) = self.chain {
            return match chain.network_type() {
                NetworkType::Mainnet => Network::Mainnet,
                NetworkType::Testnet => Network::Testnet,
                NetworkType::Regtest => Network::Regtest,
            };
        }
        self.wallet
            .read()
            .as_ref()
            .map(|w| w.network())
            .unwrap_or(Network::Mainnet)
    }

    /// Decode an address given to an RPC; an address of another network is invalid
    fn decode_address(&self, s: &str) -> Result<Address, divi_wallet::WalletError> {
        Address::from_base58_for_network(s, self.network())
    }

    /// Get current height
    fn current_height(&self) -> u32 {
        // Try to get height from chain first (most accurate)
        if let Some(ref chain) = self.chain {
            return chain.height();
        }
        // Fallback to cached height if chain not available
        *self.height.read()
    }

    /// Submit a transaction to mempool and broadcast
    fn submit_transaction(&self, tx: Transaction) -> Result<Hash256, Error> {
        let callback = self.tx_submit.read();
        let callback = callback.as_ref().ok_or_else(|| {
            RpcError::new(codes::MISC_ERROR, "Transaction submission not configured")
        })?;

        // Divi Core sendrawtransaction (rpcrawtransaction.cpp) codes and texts
        callback(tx).map_err(|e| match e {
            TxSubmitError::Rejected { code, reason } => {
                RpcError::new(codes::VERIFY_REJECTED, format!("{}: {}", code, reason)).into()
            }
            TxSubmitError::UnknownInputs => {
                RpcError::new(codes::VERIFY_REJECTED, "Unknown inputs being spent").into()
            }
            TxSubmitError::Failed(message) => RpcError::new(codes::VERIFY_ERROR, message).into(),
        })
    }

    /// getnewaddress - Generate a new receiving address
    ///
    /// Works while the wallet is locked, from the keypool, as in Divi Core.
    pub fn get_new_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let label = params.get_str(0).unwrap_or("");

        let address = wallet.new_receiving_address().map_err(new_key_error)?;
        wallet.set_label(&address, label).map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to store label: {}", e))
        })?;

        debug!("Generated new address: {}", address);
        Ok(serde_json::json!(address.to_string()))
    }

    /// getrawchangeaddress - Generate a new change address
    pub fn get_raw_change_address(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let address = wallet.new_change_address().map_err(new_key_error)?;

        debug!("Generated new change address: {}", address);
        Ok(serde_json::json!(address.to_string()))
    }

    /// validateaddress - Validate a Divi address
    pub fn validate_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        match self.decode_address(addr_str) {
            Ok(addr) => {
                let wallet_guard = self.wallet.read();
                let known = wallet_guard
                    .as_ref()
                    .map(|w| w.is_mine(&addr))
                    .unwrap_or(false);
                let is_watch_only = wallet_guard
                    .as_ref()
                    .map(|w| w.is_watch_only(&addr))
                    .unwrap_or(false);
                // Divi Core: ismine means spendable; a watched address is
                // iswatchonly only
                let is_mine = known && !is_watch_only;

                let mut result = serde_json::json!({
                    "isvalid": true,
                    "address": addr_str,
                    "scriptPubKey": format!("76a914{}88ac", hex::encode(addr.hash.as_bytes())),
                    "ismine": is_mine,
                    "iswatchonly": is_watch_only,
                    "isscript": addr.addr_type == divi_wallet::AddressType::P2SH,
                });

                if let (true, Some(wallet)) = (known, wallet_guard.as_ref()) {
                    result["account"] = serde_json::json!(wallet.get_account(&addr));
                }
                if is_mine {
                    if let Some(wallet) = wallet_guard.as_ref() {
                        if let Some(key_entry) = wallet.get_key_by_address(&addr) {
                            let pubkey_hex = hex::encode(key_entry.pubkey_bytes());
                            result["pubkey"] = serde_json::json!(pubkey_hex);
                            result["iscompressed"] = serde_json::json!(key_entry.compressed);

                            if let Some(ref hd_path) = key_entry.hd_path {
                                result["hdkeypath"] = serde_json::json!(hd_path);
                            }

                            if let Some(chain_id) = wallet.get_hd_chain_id() {
                                result["hdchainid"] = serde_json::json!(chain_id);
                            }
                        }
                    }
                }

                Ok(result)
            }
            Err(_) => Ok(serde_json::json!({
                "isvalid": false,
            })),
        }
    }

    /// getaddressinfo - Get detailed address information
    pub fn get_address_info(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let addr = self
            .decode_address(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        let wallet = self.get_wallet()?;
        let known = wallet.is_mine(&addr);
        let is_watch_only = wallet.is_watch_only(&addr);
        let is_mine = known && !is_watch_only;
        let labels: Vec<String> = if known {
            vec![wallet.get_account(&addr)]
        } else {
            Vec::new()
        };

        // Get HD key path if available
        let hd_key_path = wallet
            .get_key_by_address(&addr)
            .and_then(|entry| entry.hd_path);

        let mut response = serde_json::json!({
            "address": addr_str,
            "scriptPubKey": format!("76a914{}88ac", hex::encode(addr.hash.as_bytes())),
            "ismine": is_mine,
            "iswatchonly": is_watch_only,
            "isscript": addr.addr_type == divi_wallet::AddressType::P2SH,
            "ischange": wallet.is_change_address(&addr),
            "labels": labels,
        });

        // Add hdkeypath field if present
        if let Some(path) = hd_key_path {
            response["hdkeypath"] = serde_json::json!(path);
        }

        Ok(response)
    }

    /// getbalance - Get wallet balance
    pub fn get_balance(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        // Divi Core (rpcwallet.cpp:1577-1578): with no params or account "*"
        // it returns GetBalance(), whatever minconf: confirmed, mature coins.
        // For another account, our own 0-conf change counts at any minconf and
        // others' 0-conf payments count only at minconf 0. IronDivi also
        // accepts a bare numeric minconf as the first param.
        let height = self.current_height();
        let balance = if params.is_empty() || params.get_str(0) == Some("*") {
            wallet.get_balance()
        } else {
            let min_conf = if params.get_str(0).is_some() {
                params.get_u64(1).unwrap_or(1)
            } else {
                params.get_u64(0).unwrap_or(1)
            } as u32;
            wallet.get_confirmed_balance(height, min_conf)
        };

        // Return as DIVI (not satoshis)
        let divi = balance.as_sat() as f64 / 100_000_000.0;
        Ok(serde_json::json!(divi))
    }

    /// getunconfirmedbalance - Get unconfirmed balance
    pub fn get_unconfirmed_balance(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let balance = wallet.get_unconfirmed_balance();
        let divi = balance.as_sat() as f64 / 100_000_000.0;
        Ok(serde_json::json!(divi))
    }

    /// getimmaturebalance - Get immature balance (stake/coinbase rewards)
    pub fn get_immature_balance(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let height = self.current_height();
        let balance = wallet.get_immature_balance(height, wallet.coinbase_maturity());
        let divi = balance.as_sat() as f64 / 100_000_000.0;
        Ok(serde_json::json!(divi))
    }

    /// getwalletinfo - Get wallet state info
    pub fn get_wallet_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let height = self.current_height();
        // Same figures as getbalance, getunconfirmedbalance, getimmaturebalance
        let balance = wallet.get_balance();
        let unconfirmed = wallet.get_unconfirmed_balance();
        let immature = wallet.get_immature_balance(height, wallet.coinbase_maturity());

        // Core: spendable_balance excludes every vault, vaulted_balance is the
        // coins in vaults we own (a managed vault is in neither)
        let spendable = wallet.get_spendable_balance(height);
        let vaulted = wallet.get_vaulted_balance();

        let divi_balance = balance.as_sat() as f64 / 100_000_000.0;
        let divi_unconfirmed = unconfirmed.as_sat() as f64 / 100_000_000.0;
        let divi_immature = immature.as_sat() as f64 / 100_000_000.0;

        let mut info = serde_json::json!({
            "walletname": "wallet.dat",
            "active_wallet": "wallet.dat",
            "walletversion": 120200,
            "balance": divi_balance,
            "spendable_balance": spendable.as_divi_f64(),
            "vaulted_balance": vaulted.as_divi_f64(),
            "encryption_status": wallet.encryption_status(),
            "unconfirmed_balance": divi_unconfirmed,
            "immature_balance": divi_immature,
            "txcount": wallet.get_transactions(None).len(),
            "keypoololdest": wallet.keypool_oldest(),
            "keypoolsize": wallet.keypool_size(),
            "paytxfee": 0.0001,
            "hdmasterkeyid": wallet.hd_master_key_id()
        });
        // Core sends unlocked_until only for an encrypted wallet; clients such
        // as BasicSwap read its presence as "encrypted" and 0 as "locked"
        if wallet.is_encrypted() {
            info["unlocked_until"] = serde_json::json!(wallet.unlocked_until());
        }
        Ok(info)
    }

    /// listunspent - List unspent transaction outputs
    pub fn list_unspent(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        // Optional parameters
        let min_conf = params.get_u64(0).unwrap_or(1) as u32;
        let max_conf = params.get_u64(1).unwrap_or(9999999) as u32;

        // Optional ["address", ...] filter. As in Core, a bad address is -5
        // and a repeated one is -8.
        let addresses: Option<HashSet<String>> = match params.get(2) {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Array(items)) => {
                let mut set = HashSet::new();
                for item in items {
                    let addr = item
                        .as_str()
                        .filter(|a| Address::from_base58(a).is_ok())
                        .ok_or_else(|| {
                            RpcError::new(
                                codes::INVALID_ADDRESS_OR_KEY,
                                format!("Invalid DIVI address: {}", item.as_str().unwrap_or("")),
                            )
                        })?;
                    if !set.insert(addr.to_string()) {
                        return Err(RpcError::new(
                            codes::INVALID_PARAMETER,
                            format!("Invalid parameter, duplicated address: {}", addr),
                        )
                        .into());
                    }
                }
                Some(set)
            }
            Some(_) => {
                return Err(
                    RpcError::new(codes::TYPE_ERROR, "Expected type array for addresses").into(),
                )
            }
        };

        let height = self.current_height();
        // What Core's AvailableCoins gives a send (rpcrawtransaction.cpp:310,
        // AvailableUtxoCalculator.cpp:3-30, 60-90): spendable coins only (no
        // vault or watched output), mature, not spent by a wallet transaction,
        // unconfirmed ones only when every input was ours, and not locked by
        // lockunspent
        let mut utxos = wallet.get_spendable_utxos(height, 0);
        // In txid order, as Divi Core walks its wallet map
        utxos.sort_by_key(|u| (u.txid.to_string(), u.vout));

        let result: Vec<_> = utxos
            .iter()
            .filter(|utxo| {
                let confs = utxo.confirmations(height);
                confs >= min_conf && confs <= max_conf
            })
            .filter(|utxo| !wallet.is_coin_locked(&utxo.outpoint()))
            .filter(|utxo| {
                addresses
                    .as_ref()
                    .is_none_or(|set| set.contains(&utxo.address))
            })
            .map(|utxo| {
                let divi = utxo.value.as_sat() as f64 / 100_000_000.0;
                let is_change = wallet.is_change_address_str(&utxo.address);

                let mut entry = serde_json::json!({
                    "txid": utxo.txid.to_string(),
                    "vout": utxo.vout,
                    "address": utxo.address,
                    "scriptPubKey": hex::encode(utxo.script_pubkey.as_bytes()),
                    "amount": divi,
                    "confirmations": utxo.confirmations(height),
                    "spendable": true,
                    "solvable": true,
                    "ischange": is_change,
                });
                // A bare multisig output has no address (Core's ExtractDestination)
                if utxo.address.is_empty() {
                    entry.as_object_mut().map(|o| o.remove("address"));
                }
                // Divi Core gives the account of an address-book address (not
                // change) and a P2SH coin's redeem script
                // (rpcrawtransaction.cpp:320-334)
                if let Ok(addr) = Address::from_base58(&utxo.address) {
                    if !is_change {
                        entry["account"] = json!(wallet.get_account(&addr));
                    }
                    if addr.addr_type == divi_wallet::address::AddressType::P2SH {
                        if let Some(redeem) = wallet.get_script(&addr.hash) {
                            entry["redeemScript"] = json!(hex::encode(redeem.as_bytes()));
                        }
                    }
                }
                entry
            })
            .collect();

        Ok(serde_json::json!(result))
    }

    /// History entries as Divi Core builds them, for one call
    fn history<'a>(&'a self, wallet: &'a WalletDb) -> crate::wallet_history::History<'a> {
        crate::wallet_history::History::new(
            wallet,
            self.chain.as_deref(),
            self.mempool.read().clone(),
            self.address_network(),
            self.current_height(),
        )
    }

    /// gettransaction as Divi Core (rpcwallet.cpp:2452-2490)
    pub fn get_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let txid_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("txid required"))?;
        let watch = params.get_bool(1).unwrap_or(false);
        let not_wallet = || {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                "Invalid or non-wallet transaction id",
            )
        };
        // `hash.SetHex(...)`: text that is no hash names no wallet transaction
        let txid = Hash256::from_hex(txid_str).map_err(|_| not_wallet())?;

        let wallet = self.get_wallet()?;
        let record = wallet.history_record(&txid).ok_or_else(not_wallet)?;
        self.history(&wallet)
            .transaction(&record, watch)
            .ok_or_else(|| not_wallet().into())
    }

    /// listtransactions ( "account" count from includeWatchonly ) as Divi Core
    /// (rpcwallet.cpp:2215-2318): one entry per output sent or received, the
    /// newest `count` after skipping `from`, oldest first
    pub fn list_transactions(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let account = params.get_str(0).unwrap_or("*").to_string();
        let count = params.get_i64(1).unwrap_or(10);
        let from = params.get_i64(2).unwrap_or(0);
        let watch = params.get_bool(3).unwrap_or(false);
        if count < 0 {
            return Err(RpcError::new(codes::INVALID_PARAMETER, "Negative count").into());
        }
        if from < 0 {
            return Err(RpcError::new(codes::INVALID_PARAMETER, "Negative from").into());
        }
        let (count, from) = (count as usize, from as usize);

        let history = self.history(&wallet);
        let mut entries: Vec<serde_json::Value> = Vec::new();
        // newest transaction first, each one's entries in order
        for record in history.ordered_records().iter().rev() {
            history.details(record, &account, 0, true, watch, &mut entries);
            if entries.len() >= count + from {
                break;
            }
        }
        let from = from.min(entries.len());
        let count = count.min(entries.len() - from);
        let mut window: Vec<_> = entries.drain(from..from + count).collect();
        window.reverse();
        Ok(serde_json::json!(window))
    }

    /// listsinceblock ( "blockhash" target-confirmations includeWatchonly ) as
    /// Divi Core (rpcwallet.cpp:2364-2450)
    pub fn list_since_block(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;
        let height = self.current_height();

        // An unknown or malformed hash lists everything
        let since_height = params
            .get_str(0)
            .and_then(|h| Hash256::from_hex(h).ok())
            .and_then(|hash| {
                self.chain
                    .as_ref()
                    .and_then(|c| c.get_block_index(&hash).ok().flatten())
            })
            .map(|index| index.height);
        let target = match params.get(1) {
            None => 1,
            Some(_) => params.get_i64(1).unwrap_or(0),
        };
        if target < 1 {
            return Err(RpcError::new(codes::INVALID_PARAMETER, "Invalid parameter").into());
        }
        let watch = params.get_bool(2).unwrap_or(false);
        let depth = since_height.map(|h| 1 + height as i64 - h as i64);

        let history = self.history(&wallet);
        let mut transactions = Vec::new();
        // Divi Core walks its wallet map, which is in txid order
        let mut records = history.ordered_records();
        records.sort_by_key(|r| r.txid.to_string());
        for record in records {
            let mut entries = Vec::new();
            history.details(&record, "*", 0, true, watch, &mut entries);
            let keep = |e: &serde_json::Value| match depth {
                None => true,
                Some(d) => e["confirmations"].as_i64().unwrap_or(0) < d,
            };
            transactions.extend(entries.into_iter().filter(keep));
        }

        // chain[Height() + 1 - target_confirms]; null (zeros) below genesis
        let last_height = height as i64 + 1 - target;
        let lastblock = self
            .chain
            .as_ref()
            .filter(|_| last_height >= 0)
            .and_then(|c| {
                c.get_block_index_by_height(last_height as u32)
                    .ok()
                    .flatten()
            })
            .map(|i| i.hash)
            .unwrap_or_else(Hash256::zero);

        Ok(serde_json::json!({
            "transactions": transactions,
            "lastblock": lastblock.to_string()
        }))
    }

    /// walletpassphrase - Unlock wallet for specified time
    pub fn wallet_passphrase(&self, params: &Params) -> Result<serde_json::Value, Error> {
        if let Ok(wallet) = self.get_wallet() {
            if !wallet.is_encrypted() {
                return Err(RpcError::new(
                    codes::WALLET_WRONG_ENC_STATE,
                    "Error: running with an unencrypted wallet, but walletpassphrase was called.",
                )
                .into());
            }
        }
        let passphrase = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Passphrase required"))?;
        let timeout = params
            .get_u64(1)
            .ok_or_else(|| RpcError::invalid_params("Timeout required"))?;
        // Divi Core's third argument: unlock for staking only
        let staking_only = params.get_bool(2).unwrap_or(false);

        let wallet = self.get_wallet()?;

        if !wallet.is_encrypted() {
            return Err(RpcError::new(
                codes::WALLET_WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletpassphrase was called.",
            )
            .into());
        }

        if staking_only && wallet.is_unlocked_for_staking_only() {
            return Err(RpcError::new(
                codes::WALLET_ALREADY_UNLOCKED,
                "Error: Wallet is already unlocked for staking.",
            )
            .into());
        }

        wallet
            .unlock_for(passphrase, timeout as u32, staking_only)
            .map_err(|e| match e {
                divi_wallet::WalletError::WrongPassphrase
                | divi_wallet::WalletError::InvalidPassphrase => RpcError::new(
                    codes::WALLET_PASSPHRASE_INCORRECT,
                    "Error: The wallet passphrase entered was incorrect.",
                ),
                other => RpcError::new(codes::WALLET_ERROR, other.to_string()),
            })?;

        Ok(serde_json::Value::Null)
    }

    /// walletlock - Lock the wallet
    pub fn wallet_lock(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        if !wallet.is_encrypted() {
            return Err(RpcError::new(
                codes::WALLET_WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletlock was called.",
            )
            .into());
        }

        wallet.lock();
        Ok(serde_json::Value::Null)
    }

    pub fn dump_privkey(&self, params: &Params) -> Result<serde_json::Value, Error> {
        use divi_wallet::address::{encode_wif, Network};

        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let addr = self
            .decode_address(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address"))?;

        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        // rpcdump.cpp:186-193: a script address is -3, an unknown key -4
        if addr.addr_type == divi_wallet::address::AddressType::P2SH {
            return Err(RpcError::new(codes::TYPE_ERROR, "Address does not refer to a key").into());
        }
        let not_known = || {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("Private key for address {addr_str} is not known"),
            )
        };
        let key_entry = wallet
            .keystore()
            .get_key_by_address(&addr)
            .ok_or_else(not_known)?;

        let network = match addr.network {
            divi_wallet::address::Network::Mainnet => Network::Mainnet,
            divi_wallet::address::Network::Testnet => Network::Testnet,
            divi_wallet::address::Network::Regtest => Network::Regtest,
        };

        let secret = key_entry.secret.as_ref().ok_or_else(not_known)?;
        let key_bytes = secret.as_bytes();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key_bytes);
        let wif = encode_wif(&key_array, key_entry.compressed, network);

        Ok(serde_json::json!(wif))
    }

    pub fn import_privkey(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wif = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Private key required"))?;

        // Optional label parameter
        let label = params.get_str(1).map(|s| s.to_string());

        let rescan = params.get_bool(2).unwrap_or(true);

        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        // Decode the WIF private key
        // rpcdump.cpp:70-73
        let wif_key = divi_wallet::decode_wif(wif).map_err(|_| {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                "Invalid private key encoding",
            )
        })?;

        // Create a SecretKey from the decoded bytes
        let secret =
            divi_crypto::keys::SecretKey::from_bytes(&wif_key.key_bytes).map_err(|_| {
                RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    "Private key outside allowed range",
                )
            })?;

        // As Divi Core: the label is set even for a key already held, and a key
        // already held is not imported or rescanned again. The key is compressed
        // or not as the WIF says (Divi Core's CBitcoinSecret), which decides its address.
        let address = divi_wallet::KeyEntry::imported(secret.clone(), wif_key.compressed)
            .address(wallet.network());
        let held = wallet.is_mine(&address) && !wallet.is_watch_only(&address);
        if !held {
            wallet.import_key_with_compression(secret, wif_key.compressed, label.clone());
            info!("Imported private key for address: {}", address);
        }
        wallet
            .set_label(&address, label.as_deref().unwrap_or(""))
            .map_err(|e| {
                RpcError::new(codes::WALLET_ERROR, format!("Failed to store label: {}", e))
            })?;
        if held {
            return Ok(serde_json::Value::Null);
        }

        wallet.save().map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to save wallet: {}", e))
        })?;

        // A WIF carries no birth time, so the scan starts at genesis
        if rescan {
            self.rescan_after_import(&wallet)?;
        }
        Ok(serde_json::Value::Null)
    }

    /// Rescan blocks `start_height..=stop_height` into the wallet and save it.
    /// Returns the number of blocks scanned. Shared by `rescanblockchain` and the
    /// import RPCs.
    fn rescan_range(
        &self,
        wallet: &WalletDb,
        chain: &Arc<Chain>,
        start_height: u32,
        stop_height: u32,
    ) -> Result<u32, Error> {
        // Do not wipe the wallet if the first block cannot be had at all
        let fetcher = self.block_fetcher.read().clone();
        if let Some(first) = chain.get_block_index_by_height(start_height)? {
            if crate::blockchain::load_block_or_fetch(chain, fetcher.as_ref(), &first)?.is_none() {
                return Err(RpcError::new(
                    codes::MISC_ERROR,
                    format!(
                        "Block {} is pruned and no full-history peer returned it; rescan from a later height (prune height {})",
                        start_height,
                        chain.prune_height()
                    ),
                )
                .into());
            }
        }

        let current_height = chain.height();

        // A full rescan rebuilds the wallet; a partial one replaces only what
        // the range recorded. Block notifications wait on the wallet's scan
        // lock meanwhile, so none is scanned out of order.
        let (scanned, unreadable) =
            wallet.rescan(start_height, stop_height, current_height, |height| {
                let index = chain.get_block_index_by_height(height).ok().flatten()?;
                let block = crate::blockchain::load_block_or_fetch(chain, fetcher.as_ref(), &index)
                    .ok()
                    .flatten()?;
                Some((index.hash, block))
            });
        if let Some(height) = unreadable {
            info!(
                "Block at height {} not available, stopping rescan (total scanned: {})",
                height, scanned
            );
        }

        info!("Rescan complete: scanned {} blocks", scanned);

        wallet.save().map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("Failed to save wallet after rescan: {}", e),
            )
        })?;
        Ok(scanned)
    }

    /// Rescan the whole chain after an import, as Divi Core's
    /// `ScanForWalletTransactions(chainActive.Genesis())`. Without a chain (a
    /// wallet-only handler) there is nothing to scan.
    fn rescan_after_import(&self, wallet: &WalletDb) -> Result<(), Error> {
        let Some(chain) = self.chain.as_ref() else {
            return Ok(());
        };
        let tip = chain.height();
        info!("Rescanning blocks 0 to {} after import", tip);
        self.rescan_range(wallet, chain, 0, tip)?;
        Ok(())
    }

    /// rescanblockchain - Rescan the blockchain for wallet transactions
    ///
    /// Arguments:
    /// 1. start_height (numeric, optional, default=0) - block height where rescan should begin
    /// 2. stop_height (numeric, optional, default=chain tip) - block height where rescan should end
    ///
    /// Returns:
    /// {
    ///   "start_height": n,
    ///   "stop_height": n
    /// }
    pub fn rescan_blockchain(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let chain = self
            .chain
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Chain not available for rescan"))?;

        // Get start height (default to 0)
        let start_height = params.get_i64(0).unwrap_or(0).max(0) as u32;

        // Get stop height (default to chain tip)
        let current_height = chain.height();
        let stop_height = params
            .get_i64(1)
            .map(|h| (h as u32).min(current_height))
            .unwrap_or(current_height);

        // Validate range
        if start_height > stop_height {
            return Err(RpcError::invalid_params(format!(
                "Invalid range: start_height ({}) > stop_height ({})",
                start_height, stop_height
            ))
            .into());
        }

        info!(
            "Rescanning blockchain from height {} to {}",
            start_height, stop_height
        );

        let scanned = self.rescan_range(&wallet, chain, start_height, stop_height)?;

        let actual_stop = if scanned > 0 {
            start_height + scanned - 1
        } else {
            start_height
        };

        Ok(serde_json::json!({
            "start_height": start_height,
            "stop_height": actual_stop
        }))
    }

    /// The coins a send may spend, as Divi Core hands them to its coin
    /// selection: not locked by `lockunspent` (AvailableUtxoCalculator.cpp:91),
    /// each with Core's estimate of its input: the largest scriptSig it can
    /// need plus 40 bytes. A coin Core cannot size is left out.
    fn send_coins(
        wallet: &WalletDb,
        coins: Vec<divi_wallet::WalletUtxo>,
        height: u32,
    ) -> Vec<SendCoin> {
        let pubkey_len = |hash: &[u8; 20]| {
            wallet
                .keystore()
                .get_key(&Hash160::from_bytes(*hash))
                .map(|entry| entry.public.to_bytes().len())
        };
        let redeem = |hash: &[u8; 20]| wallet.get_script(&Hash160::from_bytes(*hash));
        coins
            .into_iter()
            .filter(|utxo| !wallet.is_coin_locked(&utxo.outpoint()))
            .filter_map(|utxo| {
                let script_sig = max_script_sig_bytes(&utxo.script_pubkey, &pubkey_len, &redeem)?;
                Some(SendCoin {
                    depth: utxo.confirmations(height),
                    input_bytes: script_sig + 40,
                    utxo,
                })
            })
            .collect()
    }

    /// The coins of `account`, as Divi Core's AccountCoinSelector filters them
    /// for a named account (rpcwallet.cpp:445-459); all coins for ""
    fn account_coins(
        wallet: &WalletDb,
        account: &str,
        coins: Vec<divi_wallet::WalletUtxo>,
    ) -> Vec<divi_wallet::WalletUtxo> {
        if account.is_empty() {
            return coins;
        }
        coins
            .into_iter()
            .filter(|utxo| {
                Address::from_base58(&utxo.address)
                    .is_ok_and(|address| wallet.get_account(&address) == account)
            })
            .collect()
    }

    /// Plan a send as Divi Core's CreateTransaction does
    fn plan(
        payees: &[TxOut],
        coins: &[SendCoin],
        mode: FeeMode,
        kind: ChangeKind,
        change_to: &ChangeTo,
    ) -> Result<SendPlan, Error> {
        plan_send(
            payees,
            coins,
            mode,
            kind,
            &change_to.template(),
            FeePolicy::default(),
        )
        .map_err(send_error)
    }

    /// Sign a planned send, check it as Divi Core does once signed, and
    /// submit it. The change key is taken only when there is change.
    fn sign_and_submit(
        &self,
        wallet: &WalletDb,
        plan: &SendPlan,
        change_to: ChangeTo,
    ) -> Result<Hash256, Error> {
        let mut builder = TransactionBuilder::new();
        for utxo in &plan.inputs {
            builder = builder.add_input(utxo.outpoint(), utxo.script_pubkey.clone());
        }
        for out in &plan.outputs {
            builder = builder.add_output(out.value, out.script_pubkey.clone());
        }
        if let Some(change) = plan.change {
            let script = match change_to {
                ChangeTo::NewKey => wallet
                    .new_change_address()
                    .map_err(|e| {
                        RpcError::new(
                            codes::WALLET_ERROR,
                            format!("Failed to generate change address: {}", e),
                        )
                    })?
                    .script_pubkey(),
                ChangeTo::Script(script) => script,
            };
            builder = builder.add_output(change, script);
        }
        let (mut tx, prev_scripts) = builder.build();

        // Every coin type the wallet spends (P2PKH, P2PK, multisig, P2SH with
        // a stored redeem script), as Core's SignSignature (wallet.cpp:1609-1624)
        let signer = TransactionSigner::new(wallet.keystore());
        let redeem_script = |hash: &Hash160| wallet.get_script(hash);
        let mut signed_count = 0;
        for (i, script) in prev_scripts.iter().enumerate() {
            let verified = signer
                .sign_and_merge_input(&mut tx, i, script, &redeem_script)
                .map_err(|e| {
                    RpcError::new(
                        codes::WALLET_ERROR,
                        format!("Failed to sign transaction: {}", e),
                    )
                })?;
            signed_count += usize::from(verified);
        }
        if signed_count != plan.inputs.len() {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!(
                    "Only signed {} of {} inputs",
                    signed_count,
                    plan.inputs.len()
                ),
            )
            .into());
        }
        check_signed(&tx, plan.fee, FeePolicy::default()).map_err(send_error)?;
        self.submit_transaction(tx)
    }

    /// sendtoaddress - Send amount to a given address
    pub fn send_to_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        // C++ checks the argument count (usage, -1) before anything else
        let amount_value = params
            .get(1)
            .ok_or_else(|| RpcError::invalid_params("Amount required"))?;

        let dest_addr = self
            .decode_address(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address"))?;

        let send_amount = amount_from_value(amount_value, false)?;

        // Divi Core: receiver_pays, sweep_funds or metadata (comments)
        let mode = parse_fee_mode(params.get_str(2), true)?;

        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        let payees = [TxOut::new(send_amount, dest_addr.script_pubkey())];
        check_send_total(&payees, spendable_balance(&wallet, self.current_height()))?;
        ensure_not_dust(send_amount, &dest_addr.script_pubkey())?;

        let height = self.current_height();
        let coins = Self::send_coins(&wallet, wallet.get_send_candidates(height, 1), height);
        let plan = Self::plan(&payees, &coins, mode, ChangeKind::P2pkh, &ChangeTo::NewKey)?;
        let txid = self.sign_and_submit(&wallet, &plan, ChangeTo::NewKey)?;

        info!(
            "Sent {} DIVI to {} (txid: {})",
            send_amount.as_divi_f64(),
            addr_str,
            txid
        );

        Ok(serde_json::json!(txid.to_string()))
    }

    /// createrawtransaction - Create an unsigned raw transaction
    pub fn create_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        // Divi Core createrawtransaction (rpcrawtransaction.cpp:361-462):
        // params[0] = inputs array: [{"txid": "...", "vout": n}, ...]
        // params[1] = outputs object {"address or script hex": amount, ...},
        //             or an array of one-entry objects

        let inputs = params
            .get(0)
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::invalid_params("Inputs array required"))?;

        let outputs: Vec<(String, serde_json::Value)> = match params.get(1) {
            Some(serde_json::Value::Object(map)) => {
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            }
            Some(serde_json::Value::Array(entries)) => {
                let mut pairs = Vec::new();
                for entry in entries {
                    let Some(obj) = entry.as_object() else {
                        return Err(RpcError::new(
                            codes::TYPE_ERROR,
                            "output entries must be objects",
                        )
                        .into());
                    };
                    if obj.len() != 1 {
                        return Err(RpcError::new(
                            codes::INVALID_PARAMETER,
                            "output entries must have a single element",
                        )
                        .into());
                    }
                    pairs.extend(obj.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
                pairs
            }
            Some(_) => {
                return Err(
                    RpcError::new(codes::TYPE_ERROR, "outputs must be array or object").into(),
                )
            }
            None => return Err(RpcError::invalid_params("Outputs object required").into()),
        };

        let mut builder = TransactionBuilder::new();

        // Add inputs
        for input in inputs {
            // ParseHashO(o, "txid")
            let txid_str = input.get("txid").and_then(|v| v.as_str()).unwrap_or("");
            let txid = Hash256::from_hex(txid_str).map_err(|_| {
                RpcError::new(
                    codes::INVALID_PARAMETER,
                    format!("txid must be hexadecimal string (not '{txid_str}')"),
                )
            })?;

            let vout = input.get("vout").and_then(|v| v.as_i64()).ok_or_else(|| {
                RpcError::new(
                    codes::INVALID_PARAMETER,
                    "Invalid parameter, missing vout key",
                )
            })?;
            if vout < 0 {
                return Err(RpcError::new(
                    codes::INVALID_PARAMETER,
                    "Invalid parameter, vout must be positive",
                )
                .into());
            }

            // For createrawtransaction, we don't need the prev script (that's for signing)
            builder = builder.add_input(OutPoint::new(txid, vout as u32), Script::new());
        }

        // Add outputs: a hex (or empty) key is a raw script, anything else an address
        let mut seen = HashSet::new();
        for (key, amount_value) in &outputs {
            let amount = amount_from_value(amount_value, true)?;
            if key.is_empty() || (key.len() % 2 == 0 && hex::decode(key).is_ok()) {
                let script = Script::from_bytes(hex::decode(key).unwrap_or_default());
                builder = builder.add_output(amount, script);
                continue;
            }
            let addr = self.decode_address(key).map_err(|_| {
                RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    format!("Invalid DIVI address: {}", key),
                )
            })?;
            if !seen.insert(addr.to_base58()) {
                return Err(RpcError::new(
                    codes::INVALID_PARAMETER,
                    format!("Invalid parameter, duplicated address: {}", key),
                )
                .into());
            }
            builder = builder.add_output_to_address(amount, &addr);
        }

        let (tx, _) = builder.build();

        // Serialize to hex
        let raw = serialize(&tx);
        Ok(serde_json::json!(hex::encode(raw)))
    }

    /// signrawtransaction - Sign a raw transaction with wallet keys
    pub fn sign_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        use divi_script::SigHashType;

        let hex_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Transaction hex required"))?;

        let wallet = self.get_wallet()?;

        // With privkeys, Divi Core signs only with those keys (a temporary keystore)
        // and does not need the wallet unlocked
        let given_keys = match params.get(2).filter(|v| !v.is_null()) {
            Some(keys) => {
                let keys = keys
                    .as_array()
                    .ok_or_else(|| RpcError::new(codes::TYPE_ERROR, "privkeys must be an array"))?;
                let store = divi_wallet::KeyStore::new(self.address_network());
                for key in keys {
                    let invalid =
                        || RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid private key");
                    let wif = key
                        .as_str()
                        .and_then(|k| divi_wallet::decode_wif(k).ok())
                        .ok_or_else(invalid)?;
                    let secret =
                        divi_crypto::keys::SecretKey::from_bytes(&wif.key_bytes).map_err(|_| {
                            RpcError::new(
                                codes::INVALID_ADDRESS_OR_KEY,
                                "Private key outside allowed range",
                            )
                        })?;
                    store.import_key_with_compression(secret, wif.compressed, None);
                }
                Some(store)
            }
            None => None,
        };

        if given_keys.is_none() {
            ensure_fully_unlocked(&wallet)?;
        }

        // Decode transaction
        let tx_bytes = hex::decode(hex_str)
            .map_err(|_| RpcError::new(codes::INVALID_PARAMETER, "Invalid transaction hex"))?;

        let mut tx: Transaction = deserialize(&tx_bytes).map_err(|e| {
            RpcError::new(
                codes::DESERIALIZATION_ERROR,
                format!("TX decode failed: {}", e),
            )
        })?;

        // Previous outputs given in the call, matched to inputs by outpoint, and any
        // redeem scripts given with P2SH outputs
        let mut given: std::collections::HashMap<OutPoint, Script> = Default::default();
        let mut redeem_scripts: std::collections::HashMap<Hash160, Script> = Default::default();
        if let Some(prevtxs) = params.get(1).filter(|v| !v.is_null()) {
            let prevtxs = prevtxs
                .as_array()
                .ok_or_else(|| RpcError::new(codes::TYPE_ERROR, "prevtxs must be an array"))?;
            for prevtx in prevtxs {
                let bad = || {
                    RpcError::new(
                        codes::DESERIALIZATION_ERROR,
                        "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}",
                    )
                };
                let txid = prevtx
                    .get("txid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(bad)
                    .and_then(|t| {
                        Hash256::from_hex(t).map_err(|_| {
                            RpcError::new(codes::INVALID_PARAMETER, "txid must be hexadecimal")
                        })
                    })?;
                let vout = prevtx
                    .get("vout")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(bad)?;
                if vout < 0 {
                    return Err(RpcError::new(
                        codes::DESERIALIZATION_ERROR,
                        "vout must be positive",
                    )
                    .into());
                }
                let script_hex = prevtx
                    .get("scriptPubKey")
                    .and_then(|v| v.as_str())
                    .ok_or_else(bad)?;
                let script_pubkey = Script::from_bytes(hex::decode(script_hex).map_err(|_| {
                    RpcError::new(codes::INVALID_PARAMETER, "scriptPubKey must be hexadecimal")
                })?);

                if let Some(rs_hex) = prevtx.get("redeemScript").filter(|v| !v.is_null()) {
                    let rs_bytes = rs_hex
                        .as_str()
                        .and_then(|h| hex::decode(h).ok())
                        .ok_or_else(|| {
                            RpcError::new(
                                codes::INVALID_PARAMETER,
                                "redeemScript must be hexadecimal",
                            )
                        })?;
                    let rs_hash = divi_crypto::hash160(&rs_bytes);
                    if script_pubkey.extract_p2sh_hash() != Some(*rs_hash.as_bytes()) {
                        return Err(RpcError::new(
                            codes::INVALID_PARAMETER,
                            "redeemScript does not match scriptPubKey",
                        )
                        .into());
                    }
                    redeem_scripts.insert(rs_hash, Script::from_bytes(rs_bytes));
                }
                given.insert(OutPoint::new(txid, vout as u32), script_pubkey);
            }
        }

        // sighashtype, as Divi Core's mapSigHashValues
        let (sighash_type, anyone_can_pay) = match params.get(3).filter(|v| !v.is_null()) {
            None => (SigHashType::All, false),
            Some(v) => match v.as_str() {
                Some("ALL") => (SigHashType::All, false),
                Some("ALL|ANYONECANPAY") => (SigHashType::All, true),
                Some("NONE") => (SigHashType::None, false),
                Some("NONE|ANYONECANPAY") => (SigHashType::None, true),
                Some("SINGLE") => (SigHashType::Single, false),
                Some("SINGLE|ANYONECANPAY") => (SigHashType::Single, true),
                _ => {
                    return Err(
                        RpcError::new(codes::INVALID_PARAMETER, "Invalid sighash param").into(),
                    )
                }
            },
        };
        let hash_single = sighash_type == SigHashType::Single;

        // Sign what we can and merge with the signatures already present
        let mempool = self.mempool.read().clone();
        // Given keys use only the redeem scripts given with them, as in Divi Core
        let redeem_script = |h: &Hash160| {
            redeem_scripts
                .get(h)
                .cloned()
                .or_else(|| given_keys.is_none().then(|| wallet.get_script(h)).flatten())
        };
        let signer = TransactionSigner::new(given_keys.as_ref().unwrap_or(wallet.keystore()))
            .with_hash_type(sighash_type, anyone_can_pay);
        let no_keys = divi_wallet::KeyStore::new(self.address_network());
        let merge_only = TransactionSigner::new(&no_keys);
        let mut complete = true;
        for i in 0..tx.vin.len() {
            let outpoint = tx.vin[i].prevout;
            let script_pubkey = given
                .get(&outpoint)
                .cloned()
                .or_else(|| wallet.get_utxo(&outpoint).map(|u| u.script_pubkey))
                .or_else(|| {
                    let chain = self.chain.as_ref()?;
                    chain
                        .get_utxo(&outpoint)
                        .ok()
                        .flatten()
                        .map(|u| u.script_pubkey)
                })
                .or_else(|| {
                    let tx = mempool.as_ref()?.get_transaction(&outpoint.txid)?;
                    Some(tx.vout.get(outpoint.vout as usize)?.script_pubkey.clone())
                });
            let Some(script_pubkey) = script_pubkey else {
                complete = false;
                continue;
            };
            // Only sign SIGHASH_SINGLE if there's a corresponding output (Divi Core);
            // the signatures already in the input are still merged and checked
            let signer = if hash_single && i >= tx.vout.len() {
                &merge_only
            } else {
                &signer
            };
            let verified = signer
                .sign_and_merge_input(&mut tx, i, &script_pubkey, &redeem_script)
                .map_err(|e| {
                    RpcError::new(codes::WALLET_ERROR, format!("Failed to sign: {}", e))
                })?;
            complete &= verified;
        }

        // Serialize signed transaction
        let raw = serialize(&tx);

        Ok(serde_json::json!({
            "hex": hex::encode(raw),
            "complete": complete
        }))
    }

    /// signtransactionwithaddresskey - sign one input with the wallet key of an address.
    ///
    /// Mirrors C++: SIGHASH_SINGLE over a `<pubkey> OP_CHECKSIG` dummy script, and the result is
    /// the asm of the resulting scriptSig (the bare signature).
    pub fn sign_transaction_with_address_key(
        &self,
        params: &Params,
    ) -> Result<serde_json::Value, Error> {
        use divi_script::SigHashType;
        if params.len() != 3 {
            return Err(RpcError::new(
                codes::MISC_ERROR,
                "signtransactionwithaddresskey \"hexstring\" \"address\" inputindex",
            )
            .into());
        }
        let hex_str = params.get_str(0).ok_or_else(|| {
            RpcError::new(codes::INVALID_PARAMETER, "Invalid parameter, expected hex")
        })?;
        let input_index = params
            .get_i64(2)
            .ok_or_else(|| RpcError::new(codes::TYPE_ERROR, "Expected type int for inputindex"))?;
        let tx_bytes = hex::decode(hex_str).map_err(|_| {
            RpcError::new(
                codes::INVALID_PARAMETER,
                "Transaction hex data must be hexadecimal",
            )
        })?;
        let mut tx: Transaction = deserialize(&tx_bytes)
            .map_err(|_| RpcError::new(codes::DESERIALIZATION_ERROR, "TX decode failed"))?;
        let address = self
            .decode_address(params.get_str(1).unwrap_or(""))
            .map_err(|_| {
                RpcError::new(codes::WALLET_ERROR, "Unable to sign for unknown address")
            })?;
        let wallet = self.get_wallet()?;
        let entry = wallet
            .keystore()
            .get_key_by_address(&address)
            .ok_or_else(|| {
                RpcError::new(codes::WALLET_ERROR, "Unable to sign for unknown address")
            })?;
        let unable = || RpcError::new(codes::WALLET_ERROR, "Unable to sign for input");
        let secret = entry
            .secret
            .as_ref()
            .filter(|_| !entry.is_watch_only)
            .ok_or_else(unable)?;
        if input_index < 0 || input_index as usize >= tx.vin.len() {
            return Err(unable().into());
        }
        let mut dummy = vec![];
        let pk = entry.pubkey_bytes();
        dummy.push(pk.len() as u8);
        dummy.extend_from_slice(&pk);
        dummy.push(0xac); // OP_CHECKSIG
        let script_code = Script::from_bytes(dummy);
        let sig = divi_wallet::signer::sign_input(
            &tx,
            input_index as usize,
            &script_code,
            secret,
            SigHashType::Single,
        )
        .map_err(|_| unable())?;
        let mut script_sig = vec![sig.len() as u8];
        script_sig.extend_from_slice(&sig);
        tx.vin[input_index as usize].script_sig = Script::from_bytes(script_sig);
        Ok(json!(divi_script::to_asm(
            tx.vin[input_index as usize].script_sig.as_bytes()
        )))
    }

    /// sendrawtransaction - Submit a raw transaction to the network
    pub fn send_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let hex_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Transaction hex required"))?;

        // Decode transaction
        let tx_bytes = hex::decode(hex_str)
            .map_err(|_| RpcError::new(codes::DESERIALIZATION_ERROR, "TX decode failed"))?;

        let tx: Transaction = deserialize(&tx_bytes).map_err(|e| {
            RpcError::new(
                codes::DESERIALIZATION_ERROR,
                format!("TX decode failed: {}", e),
            )
        })?;

        let txid = tx.txid();
        let allow_high_fees = params.get_bool(1).unwrap_or(false);

        if let Some(ref chain) = self.chain {
            // Divi Core: an output of the txid in the UTXO set means it is
            // already confirmed
            let in_chain = (0..tx.vout.len() as u32)
                .any(|n| matches!(chain.get_utxo(&OutPoint::new(txid, n)), Ok(Some(_))));
            if in_chain {
                return Err(RpcError::new(
                    codes::VERIFY_ALREADY_IN_CHAIN,
                    "transaction already in block chain",
                )
                .into());
            }
            // ComputeFeeTotalsAndIfInputsAreKnown (rpcrawtransaction.cpp:810-826,
            // :875-881): each input must be an output in the chain's coins or of
            // a mempool transaction, else -26 "Unknown inputs being spent". A
            // transaction already in the mempool skips this, as in Core.
            let mempool = self.mempool.read().clone();
            let pooled = |id: &Hash256| mempool.as_ref().and_then(|m| m.get_transaction(id));
            if pooled(&txid).is_none() {
                let known = tx.vin.iter().all(|i| {
                    matches!(chain.get_utxo(&i.prevout), Ok(Some(_)))
                        || pooled(&i.prevout.txid)
                            .is_some_and(|p| (i.prevout.vout as usize) < p.vout.len())
                });
                if !known {
                    return Err(RpcError::new(
                        codes::VERIFY_REJECTED,
                        "Unknown inputs being spent",
                    )
                    .into());
                }
            }
            // Fee cap. Inputs still in the mempool are not visible here; such a
            // transaction is checked by the mempool only.
            let inputs: Option<Amount> = tx.vin.iter().try_fold(Amount::ZERO, |sum, i| match chain
                .get_utxo(&i.prevout)
            {
                Ok(Some(u)) => Some(sum + u.value),
                _ => None,
            });
            if let Some(inputs) = inputs {
                let outputs = tx.vout.iter().fold(Amount::ZERO, |a, o| a + o.value);
                if !allow_high_fees && inputs - outputs > MAX_TX_FEE {
                    return Err(RpcError::new(
                        codes::VERIFY_REJECTED,
                        "Fees being paid are in excess of maximum fee, but fee override is not provided",
                    )
                    .into());
                }
            }
        }

        // Submit to mempool and broadcast
        self.submit_transaction(tx)?;

        info!("Broadcasted transaction {}", txid);

        Ok(serde_json::json!(txid.to_string()))
    }

    /// getrawtransaction - Get raw transaction data
    ///
    /// Looks in the mempool first, then the transaction index, as Divi Core's
    /// GetTransaction does.
    pub fn get_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let txid_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("txid required"))?;

        // ParseHashV (rpcrawtransaction.cpp:166)
        let txid = Hash256::from_hex(txid_str).map_err(|_| {
            RpcError::new(
                codes::INVALID_PARAMETER,
                format!("parameter 1 must be hexadecimal string (not '{txid_str}')"),
            )
        })?;

        // Accept both bool and numeric types for verbose parameter
        // Test script passes "1" as string, which get_bool() rejects
        // So we try get_i64() first (handles both numbers and numeric strings)
        let verbose = params
            .get_i64(1)
            .map(|n| n != 0)
            .or_else(|| params.get_bool(1))
            .unwrap_or(false);

        let chain = self
            .chain
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Chain not available"))?;

        let in_mempool = self.mempool.read().as_ref().and_then(|m| {
            // By txid or bare txid, as Divi Core's GetTransaction
            m.get_transaction(&txid)
                .or_else(|| m.get_transaction_by_bare_txid(&txid))
        });
        let (tx, location) = match in_mempool {
            Some(tx) => (tx, None),
            None => {
                let found = chain.get_transaction_with_location(&txid).map_err(|e| {
                    RpcError::new(codes::DATABASE_ERROR, format!("Database error: {}", e))
                })?;
                let found = match found {
                    Some(found) => Some(found),
                    // Without the transaction index, Divi Core finds the block
                    // through an unspent output of the transaction
                    // (TransactionDiskAccessor.cpp:88-110)
                    None if !chain.has_tx_index() => Self::find_through_coins(chain, &txid),
                    None => None,
                };
                let (tx, location) = found.ok_or_else(|| {
                    RpcError::new(
                        codes::INVALID_ADDRESS_OR_KEY,
                        "No information available about transaction",
                    )
                })?;
                (tx, Some(location))
            }
        };

        if !verbose {
            return Ok(serde_json::json!(hex::encode(serialize(&tx))));
        }

        let mut result = tx_to_json(&tx, self.address_network());
        add_spent_info(&mut result, &tx, chain, self.address_network());
        // A mempool transaction has no block fields, as in Divi Core
        if let Some(location) = location {
            let block_index = chain
                .get_block_index(&location.block_hash)
                .map_err(|e| {
                    RpcError::new(codes::DATABASE_ERROR, format!("Database error: {}", e))
                })?
                .ok_or_else(|| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Block not found"))?;

            result["blockhash"] = json!(location.block_hash.to_string());
            // The transaction index keeps the entries of disconnected blocks;
            // Divi Core shows such a transaction at height -1 with no
            // confirmations (rpcrawtransaction.cpp:223-232)
            let on_active_chain = chain
                .get_block_index_by_height(block_index.height)
                .map_err(|e| {
                    RpcError::new(codes::DATABASE_ERROR, format!("Database error: {}", e))
                })?
                .is_some_and(|active| active.hash == location.block_hash);
            if on_active_chain {
                let confirmations = chain.height() - block_index.height + 1;
                result["confirmations"] = json!(confirmations);
                result["time"] = json!(block_index.time);
                result["blocktime"] = json!(block_index.time);
                result["height"] = json!(block_index.height);
            } else {
                result["height"] = json!(-1);
                result["confirmations"] = json!(0);
            }
        }
        Ok(result)
    }

    /// The transaction and its place in the block that an unspent output of it
    /// names, scanned for the txid or the bare txid
    fn find_through_coins(
        chain: &Chain,
        txid: &Hash256,
    ) -> Option<(Transaction, divi_storage::txindex::TxLocation)> {
        let height = chain.spendable_output_height_of(txid).ok().flatten()?;
        if height == 0 {
            return None;
        }
        let index = chain.get_block_index_by_height(height).ok().flatten()?;
        let block = chain.get_block(&index.hash).ok().flatten()?;
        block
            .transactions
            .iter()
            .position(|t| t.txid() == *txid || bare_txid(t) == *txid)
            .map(|pos| {
                (
                    block.transactions[pos].clone(),
                    divi_storage::txindex::TxLocation::new(index.hash, pos as u32),
                )
            })
    }

    /// decoderawtransaction - Decode a raw transaction hex string
    pub fn decode_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let hex_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("hex string required"))?;

        // DecodeHexTx failing either way is "TX decode failed" (rpcrawtransaction.cpp:487)
        let decode_failed = || RpcError::new(codes::DESERIALIZATION_ERROR, "TX decode failed");
        let tx_bytes = hex::decode(hex_str).map_err(|_| decode_failed())?;
        let tx: divi_primitives::transaction::Transaction =
            deserialize(&tx_bytes).map_err(|_| decode_failed())?;

        let mut result = tx_to_json(&tx, self.address_network());
        if let Some(obj) = result.as_object_mut() {
            obj.remove("hex");
            obj.remove("size");
        }
        Ok(result)
    }

    /// getaddressesbylabel - Get addresses with a label
    pub fn get_addresses_by_label(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let label = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Label required"))?;
        let wallet = self.get_wallet()?;

        let addresses = wallet.get_addresses_by_account(label);
        if addresses.is_empty() {
            return Err(RpcError::new(
                codes::WALLET_INVALID_ACCOUNT_NAME,
                format!("No addresses with label {}", label),
            )
            .into());
        }
        let result: serde_json::Map<String, serde_json::Value> = addresses
            .into_iter()
            .map(|addr| (addr, serde_json::json!({ "purpose": "receive" })))
            .collect();

        Ok(serde_json::json!(result))
    }

    /// listreceivedbyaddress - List amounts received by address
    /// listreceivedbyaddress ( minconf includeempty includeWatchonly ) as Divi
    /// Core's ListReceived (rpcwallet.cpp:1793-1912): address-book addresses
    /// (not change) with the amount received, the fewest confirmations and the
    /// transactions; with includeempty also those that received nothing
    pub fn list_received_by_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let min_conf = params.get_u64(0).unwrap_or(1) as u32;
        let include_empty = params.get_bool(1).unwrap_or(false);

        let height = self.current_height();
        let mut by_addr: HashMap<String, (i64, u32, Vec<String>)> = HashMap::new();
        for output in wallet.received_outputs() {
            let confs = output.confirmations(height);
            if output.is_coinbase || confs < min_conf {
                continue;
            }
            let entry = by_addr
                .entry(output.address.clone())
                .or_insert((0, u32::MAX, Vec::new()));
            entry.0 += output.value.as_sat();
            entry.1 = entry.1.min(confs);
            entry.2.push(output.txid.to_string());
        }

        let mut addresses: Vec<String> = wallet
            .list_accounts()
            .into_values()
            .flatten()
            .filter(|a| !wallet.is_change_address_str(a))
            .collect();
        for addr in by_addr.keys() {
            if !wallet.is_change_address_str(addr) && !addresses.contains(addr) {
                addresses.push(addr.clone());
            }
        }
        addresses.sort();
        addresses.dedup();

        let result: Vec<_> = addresses
            .iter()
            .filter_map(|addr| {
                let tally = by_addr.get(addr);
                if tally.is_none() && !include_empty {
                    return None;
                }
                let (sat, confs, txids) = tally.cloned().unwrap_or((0, u32::MAX, Vec::new()));
                let confs = if confs == u32::MAX { 0 } else { confs };
                let label = Address::from_base58(addr)
                    .map(|a| wallet.get_account(&a))
                    .unwrap_or_default();
                Some(serde_json::json!({
                    "address": addr,
                    "account": label,
                    "amount": sat as f64 / 100_000_000.0,
                    "confirmations": confs,
                    "bcconfirmations": confs,
                    "txids": txids,
                    "label": label,
                }))
            })
            .collect();

        Ok(serde_json::json!(result))
    }

    // ========== Vault Helper Functions ==========

    /// Parse vault encoding string into owner and manager addresses.
    ///
    /// Divi vault commands accept addresses in two formats:
    /// - `"manager_address"` - Manager address only (owner derived or not needed)
    /// - `"owner_address:manager_address"` - Both owner and manager addresses
    ///
    /// # Arguments
    /// * `encoding` - The vault address encoding string
    ///
    /// # Returns
    /// * `Ok((Some(owner), manager))` - When both addresses provided (colon-separated)
    /// * `Ok((None, manager))` - When only manager address provided
    /// * `Err(...)` - When encoding format is invalid (more than one colon)
    ///
    /// # Examples
    /// ```ignore
    /// // Manager only
    /// let (owner, manager) = rpc.parse_vault_encoding("DManagerAddr...")?;
    /// assert!(owner.is_none());
    /// assert_eq!(manager, "DManagerAddr...");
    ///
    /// // Both owner and manager
    /// let (owner, manager) = rpc.parse_vault_encoding("DOwnerAddr...:DManagerAddr...")?;
    /// assert_eq!(owner.unwrap(), "DOwnerAddr...");
    /// assert_eq!(manager, "DManagerAddr...");
    /// ```
    ///
    /// # Errors
    /// Returns `RpcError::invalid_params` if the encoding contains more than one colon
    /// or is otherwise malformed.
    ///
    /// # Used By
    /// - `addvault` - Requires both owner and manager
    /// - `removevault` - Requires both owner and manager
    /// - `fundvault` - Requires both owner and manager
    /// - `debitvaultbyname` - Requires both owner and manager
    fn parse_vault_encoding(&self, encoding: &str) -> Result<(Option<String>, String), Error> {
        let parts: Vec<&str> = encoding.split(':').collect();
        match parts.len() {
            1 => Ok((None, parts[0].to_string())),
            2 => Ok((Some(parts[0].to_string()), parts[1].to_string())),
            _ => Err(RpcError::invalid_params(
                "Invalid vault encoding. Expected format: [owner_address:]manager_address",
            )
            .into()),
        }
    }

    /// Convert a Divi address string to its Hash160 representation.
    ///
    /// Vault scripts require 20-byte Hash160 values (public key hashes) for both
    /// owner and manager addresses. This function validates the address format and
    /// extracts the underlying hash.
    ///
    /// # Arguments
    /// * `address_str` - Base58-encoded Divi address (starts with 'D')
    ///
    /// # Returns
    /// * `Ok([u8; 20])` - The 20-byte Hash160 extracted from the address
    /// * `Err(...)` - If the address is invalid or malformed
    ///
    /// # Examples
    /// ```ignore
    /// let hash = rpc.address_to_hash160("DOwnerAddr...")?;
    /// assert_eq!(hash.len(), 20);
    /// ```
    ///
    /// # Errors
    /// Returns `RpcError::invalid_params` if:
    /// - Address is not valid Base58
    /// - Address has incorrect checksum
    /// - Address is not a valid Divi mainnet address
    ///
    /// # Used By
    /// - `addvault` - Converts owner and manager addresses to hashes
    /// - `removevault` - Converts owner and manager addresses to hashes
    /// - `fundvault` - Converts owner and manager addresses to hashes
    /// - `debitvaultbyname` - Converts owner and manager addresses to hashes
    ///
    /// # Note
    /// The resulting Hash160 is used to construct a 50-byte `StakingVaultScript`:
    /// ```text
    /// OP_IF <owner_hash> OP_ELSE OP_REQUIRE_COINSTAKE <manager_hash> OP_ENDIF ...
    /// ```
    fn address_to_hash160(&self, address_str: &str) -> Result<[u8; 20], Error> {
        let address = self
            .decode_address(address_str)
            .map_err(|e| RpcError::invalid_params(format!("Invalid Divi address: {}", e)))?;

        let mut hash = [0u8; 20];
        hash.copy_from_slice(address.hash.as_bytes());
        Ok(hash)
    }

    /// Add a vault - Vault manager accepts to stake a vault script
    pub fn add_vault(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let vault_addresses = params.get_str(0).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: owner_address:manager_address")
        })?;
        let funding_tx = params.get_str(1).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: funding_txhash")
        })?;

        // Divi Core addvault (rpcwallet.cpp:1231-1304)
        let Some((owner_str, manager_str)) = vault_addresses.split_once(':') else {
            return Err(
                RpcError::new(codes::INVALID_PARAMETER, "Could not parse vault encoding!").into(),
            );
        };
        let key_hash = |address: &str, which: &str| -> Result<[u8; 20], Error> {
            match self.decode_address(address) {
                Ok(a) if a.addr_type == divi_wallet::address::AddressType::P2PKH => {
                    Ok(*a.hash.as_bytes())
                }
                _ => Err(RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    format!("Vault Registry Failed: Invalid {which} DIVI address"),
                )
                .into()),
            }
        };
        let manager_hash = key_hash(manager_str, "manager")?;
        let owner_hash = key_hash(owner_str, "owner")?;
        let (owner_addr, manager_addr) = (Some(owner_str.to_string()), manager_str.to_string());
        let sync_failed = || RpcError::invalid_request("AddingVaultScript: Unable to sync TX!");
        {
            let wallet = self.get_wallet()?;
            let manager =
                Address::from_pubkey_hash(Hash160::from_bytes(manager_hash), wallet.network());
            if wallet.keystore().get_key_by_address(&manager).is_none() {
                return Err(RpcError::invalid_request(
                    "AddingVaultScript: Does not have matching manager key!",
                )
                .into());
            }
        }

        let vault_script = StakingVaultScript::new(owner_hash, manager_hash).to_script();

        // `uint256(params[1].get_str())`: text that is not a hash finds no transaction
        let funding_txid = Hash256::from_hex(funding_tx).unwrap_or_else(|_| Hash256::zero());

        // Verify transaction exists in chain
        let chain = self
            .chain
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Chain not available"))?;

        // Not found: {"succeeded": false}, as GetTransaction failing in Core
        let Some(tx) = chain.get_transaction(&funding_txid).ok().flatten() else {
            return Ok(json!({"succeeded": false}));
        };

        // Verify transaction has output paying to vault script
        let vault_script_bytes = vault_script.as_bytes();
        let vault_outpoints: Vec<OutPoint> = tx
            .vout
            .iter()
            .enumerate()
            .filter(|(_, out)| out.script_pubkey.as_bytes() == vault_script_bytes)
            .map(|(vout, _)| OutPoint::new(funding_txid, vout as u32))
            .collect();

        // CWallet::AddVault finding nothing to add
        if vault_outpoints.is_empty() {
            return Err(sync_failed().into());
        }

        // Only coins still in the UTXO set and not spent by a mempool
        // transaction can be staked; a spent funding output is refused
        let mempool = self.mempool.read().clone();
        let unspent_in_chain = |op: &OutPoint| chain.get_utxo(op).ok().flatten().is_some();
        let spent_in_mempool = |op: &OutPoint| mempool.as_ref().is_some_and(|m| m.is_spent(op));
        let live = vault_outpoints
            .iter()
            .filter(|op| unspent_in_chain(op) && !spent_in_mempool(op))
            .count();
        // IronDivi refuses a spent funding output, which could never stake;
        // Divi Core with -vault=1 adds it anyway
        if live == 0 {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!(
                    "AddingVaultScript: the vault output of transaction {} is already spent",
                    funding_tx
                ),
            )
            .into());
        }

        // Store vault metadata
        let wallet = self.get_wallet()?;
        let metadata = VaultMetadata {
            owner_address: owner_addr.unwrap(), // Already validated above
            manager_address: manager_addr,
            vault_script: vault_script_bytes.to_vec(),
            funding_txid: *funding_txid.as_bytes(),
        };

        wallet.store_vault(metadata);

        // Scan the funding transaction for vault UTXOs
        // This picks up vault outputs from the transaction that was already confirmed
        if let Ok(Some((fund_tx, location))) = chain.get_transaction_with_location(&funding_txid) {
            // Get block height from location
            let height = chain
                .get_block_index(&location.block_hash)
                .ok()
                .flatten()
                .map(|idx| idx.height);

            if height.is_none() {
                tracing::warn!("Could not determine height for funding tx {}, vault UTXOs may not be stakeable until next rescan", funding_tx);
            }

            wallet.scan_transaction(&fund_tx, Some(location.block_hash), height, None);
            // The scan records every vault output of the transaction; drop
            // those already spent on chain so no phantom balance appears
            for op in vault_outpoints.iter().filter(|op| !unspent_in_chain(op)) {
                wallet.spend_utxo(op);
            }
            tracing::info!(
                "Scanned funding tx {} at height {:?} for vault UTXOs",
                funding_tx,
                height
            );
        } else {
            tracing::warn!(
                "Could not find funding tx {} with location for vault rescan",
                funding_tx
            );
        }

        Ok(json!({"succeeded": true}))
    }

    /// Remove a vault - Vault manager rejects staking a vault script
    pub fn remove_vault(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let vault_addresses = params.get_str(0).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: owner_address:manager_address")
        })?;
        if !vault_addresses.contains(':') {
            return Err(
                RpcError::new(codes::INVALID_PARAMETER, "Could not parse vault encoding!").into(),
            );
        }
        // Divi Core takes the encoding only; an optional funding txid is
        // still accepted (and echoed back) for older IronDivi callers
        let tx_hash = params.get_str(1);

        let (owner_addr, manager_addr) = self.parse_vault_encoding(vault_addresses)?;
        let owner_hash = if let Some(ref addr) = owner_addr {
            self.address_to_hash160(addr)?
        } else {
            return Err(RpcError::invalid_params(
                "Owner address is required. Use format: owner_address:manager_address",
            )
            .into());
        };
        let manager_hash = self.address_to_hash160(&manager_addr)?;

        let vault_script = StakingVaultScript::new(owner_hash, manager_hash).to_script();

        let wallet = self.get_wallet()?;

        let vault_script_bytes = vault_script.as_bytes().to_vec();
        let vault_exists = wallet.get_vault(&vault_script_bytes).is_some();

        if !vault_exists {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!("Vault {} not found in wallet", vault_addresses),
            )
            .into());
        }

        let removed = wallet.remove_vault(&vault_script_bytes);

        if !removed {
            return Err(RpcError::new(codes::WALLET_ERROR, "Failed to remove vault").into());
        }

        let mut result = serde_json::json!({
            "removal_status": true,
            "result": "success",
            "message": format!("Vault {} removed successfully", vault_addresses),
        });
        if let Some(tx_hash) = tx_hash {
            result["tx_hash"] = json!(tx_hash);
        }
        Ok(result)
    }

    /// Get coin availability - Show available vault funds
    pub fn get_coin_availability(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let verbose = params.get_bool(0).unwrap_or(false);
        let wallet = self.get_wallet()?;

        let chain = self
            .chain
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Chain not available"))?;

        let height = chain.height();

        // Get all vaults
        let vaults = wallet.get_all_vaults();
        let total_vaults = vaults.len();

        // Balance of each registered vault, from every vault output we hold
        let mut vault_balances = std::collections::HashMap::new();
        for utxo in wallet.get_vault_utxos(height, 1) {
            let script_key = utxo.script_pubkey.as_bytes().to_vec();
            *vault_balances.entry(script_key).or_insert(Amount::ZERO) += utxo.value;
        }

        // Build response
        let mut result = Vec::new();
        for vault in vaults {
            let balance = vault_balances
                .get(&vault.vault_script)
                .copied()
                .unwrap_or(Amount::ZERO);
            result.push(json!({
                "owner": vault.owner_address,
                "manager": vault.manager_address,
                "balance": balance.as_divi_f64(),
                "balance_sat": balance.as_sat()
            }));
        }

        // C++ shape (AvailableUtxoCalculator): Vaulted = vaults we own,
        // Stakable = plain coins plus vaults we manage, Spendable = plain coins.
        // The node has no coin-age filter here.
        let owned_vaults = wallet.get_owned_vault_utxos(height, 1);
        let plain = wallet.get_spendable_utxos(height, 1);
        let mut stakable = plain.clone();
        stakable.extend(
            wallet
                .get_stakeable_vault_utxos(height, 1)
                .into_iter()
                .map(|(u, _)| u),
        );
        let network = wallet.network();
        let sum = |us: &[divi_wallet::wallet_db::WalletUtxo]| -> f64 {
            us.iter()
                .fold(Amount::ZERO, |a, u| a + u.value)
                .as_divi_f64()
        };
        let describe = |us: &[divi_wallet::wallet_db::WalletUtxo]| -> serde_json::Value {
            let mut by_script: std::collections::BTreeMap<Vec<u8>, (Amount, Vec<String>)> =
                Default::default();
            for u in us {
                let e = by_script
                    .entry(u.script_pubkey.as_bytes().to_vec())
                    .or_insert((Amount::ZERO, Vec::new()));
                e.0 += u.value;
                let txid = u.txid.to_string();
                if !e.1.contains(&txid) {
                    e.1.push(txid);
                }
            }
            let mut all_vaults = Vec::new();
            let mut vault_total = Amount::ZERO;
            for (script, (value, txids)) in by_script {
                if let Some(v) = StakingVaultScript::from_script(&Script::from_bytes(script)) {
                    let addr = |h: [u8; 20]| {
                        Address::from_pubkey_hash(
                            divi_primitives::hash::Hash160::from_bytes(h),
                            network,
                        )
                        .to_string()
                    };
                    vault_total += value;
                    all_vaults.push(json!({
                        "vault": format!("{}:{}", addr(v.owner_pubkey_hash), addr(v.vault_pubkey_hash)),
                        "value": value.as_divi_f64(),
                        "txids": txids,
                    }));
                }
            }
            let total = us.iter().fold(Amount::ZERO, |a, u| a + u.value);
            json!({"AllVaults": all_vaults, "NonVaults": (total - vault_total).as_divi_f64()})
        };
        let (vaulted, stakable, spendable) = if verbose {
            (
                describe(&owned_vaults),
                describe(&stakable),
                describe(&plain),
            )
        } else {
            (
                json!(sum(&owned_vaults)),
                json!(sum(&stakable)),
                json!(sum(&plain)),
            )
        };
        Ok(json!({
            "Vaulted": vaulted,
            "Stakable": stakable,
            "Spendable": spendable,
            "vaults": result,
            "total_vaults": total_vaults
        }))
    }

    /// Fund a vault - Adds funds to existing vault
    pub fn fund_vault(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        let vault_encoding = params.get_str(0).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: [owner_address:]manager_address")
        })?;

        let send_amount = amount_from_value(
            params
                .get(1)
                .ok_or_else(|| RpcError::invalid_params("Missing required parameter: amount"))?,
            false,
        )?;

        // parseVaultAddressEncoding (rpcwallet.cpp:920-950): without an owner
        // a new key of the wallet owns the vault
        let (owner_addr, manager_addr) = match vault_encoding.split_once(':') {
            Some((owner, manager)) => (owner.to_string(), manager.to_string()),
            None => (
                wallet
                    .new_receiving_address()
                    .map_err(new_key_error)?
                    .to_base58(),
                vault_encoding.to_string(),
            ),
        };
        // validateAndConstructVaultScriptFromParsedAddresses (rpcwallet.cpp:952-966)
        let key_hash = |address: &str, which: &str| -> Result<[u8; 20], Error> {
            match self.decode_address(address) {
                Ok(a) if a.addr_type == divi_wallet::address::AddressType::P2PKH => {
                    Ok(*a.hash.as_bytes())
                }
                _ => Err(RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    format!("Invalid {which} DIVI address"),
                )
                .into()),
            }
        };
        let manager_hash = key_hash(&manager_addr, "manager")?;
        let owner_hash = key_hash(&owner_addr, "owner")?;
        let encoding = format!("{owner_addr}:{manager_addr}");
        let vault_script = StakingVaultScript::new(owner_hash, manager_hash).to_script();
        let payees = [TxOut::new(send_amount, vault_script.clone())];
        check_send_total(&payees, spendable_balance(&wallet, self.current_height()))?;
        ensure_not_dust(send_amount, &vault_script)?;

        let height = self.current_height();

        // An ordinary send to the vault script (Divi Core fundvault: not from vaults)
        let coins = Self::send_coins(&wallet, wallet.get_send_candidates(height, 1), height);
        let plan = Self::plan(
            &payees,
            &coins,
            FeeMode::SenderPays,
            ChangeKind::P2pkh,
            &ChangeTo::NewKey,
        )?;
        let vault_script_bytes = vault_script.as_bytes().to_vec();
        let txid = self.sign_and_submit(&wallet, &plan, ChangeTo::NewKey)?;

        // Register the vault in the wallet so it can be tracked for staking/reclaiming
        let metadata = VaultMetadata {
            owner_address: owner_addr,
            manager_address: manager_addr,
            vault_script: vault_script_bytes,
            funding_txid: *txid.as_bytes(),
        };
        wallet.store_vault(metadata);

        info!(
            "Funded vault {} with {} DIVI (txid: {})",
            vault_encoding,
            send_amount.as_divi_f64(),
            txid
        );

        // rpcwallet.cpp:1059-1062
        Ok(serde_json::json!({
            "txhash": txid.to_string(),
            "vault": [{"encoding": encoding}],
        }))
    }

    /// Debit vault by name - pay out of one vault with the owner key; the rest
    /// stays in that vault (Divi Core sets the change script to the vault)
    pub fn debit_vault_by_name(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let vault_encoding = params.get_str(0).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: vault-encoding")
        })?;
        let destination = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: diviaddress"))?;
        let send_amount = amount_from_value(
            params
                .get(2)
                .ok_or_else(|| RpcError::invalid_params("Missing required parameter: amount"))?,
            false,
        )?;

        let invalid_encoding = || -> Error {
            RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid Vault Encoding").into()
        };
        let (owner_addr, manager_addr) = self
            .parse_vault_encoding(vault_encoding)
            .map_err(|_| invalid_encoding())?;
        let owner_addr = owner_addr.ok_or_else(invalid_encoding)?;
        let owner_hash = self
            .address_to_hash160(&owner_addr)
            .map_err(|_| invalid_encoding())?;
        let manager_hash = self
            .address_to_hash160(&manager_addr)
            .map_err(|_| invalid_encoding())?;
        let vault_script = StakingVaultScript::new(owner_hash, manager_hash).to_script();

        let wallet = self.get_wallet()?;
        if wallet.vault_role(&vault_script) != Some(divi_wallet::wallet_db::VaultRole::Owned) {
            return Err(RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                format!("Vault owner key is unknown: address={}", owner_addr),
            )
            .into());
        }

        let dest_addr = self
            .decode_address(destination)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address"))?;
        let mode = parse_fee_mode(params.get_str(3), false)?;

        ensure_fully_unlocked(&wallet)?;

        check_send_total(
            &[TxOut::new(send_amount, dest_addr.script_pubkey())],
            wallet.get_vaulted_balance(),
        )?;
        ensure_not_dust(send_amount, &dest_addr.script_pubkey())?;

        let height = self.current_height();
        let candidates: Vec<_> = wallet
            .get_owned_vault_utxos(height, 1)
            .into_iter()
            .filter(|u| u.script_pubkey == vault_script)
            .collect();
        if candidates.is_empty() {
            return Err(RpcError::new(
                codes::WALLET_INSUFFICIENT_FUNDS,
                format!("No funds available in vault {}", vault_encoding),
            )
            .into());
        }

        // Divi Core VaultCoinSelector for this vault; change back to the vault
        let coins = Self::send_coins(&wallet, candidates, height);
        let payees = [TxOut::new(send_amount, dest_addr.script_pubkey())];
        let change_to = ChangeTo::Script(vault_script);
        let plan = Self::plan(&payees, &coins, mode, ChangeKind::Vault, &change_to)?;
        let txid = self.sign_and_submit(&wallet, &plan, change_to)?;
        Ok(json!(txid.to_string()))
    }

    /// Reclaim vault funds - Withdraw from vault using owner key (can spend anytime)
    pub fn reclaim_vault_funds(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        let destination = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: diviaddress"))?;

        let send_amount = amount_from_value(
            params
                .get(1)
                .ok_or_else(|| RpcError::invalid_params("Missing required parameter: amount"))?,
            false,
        )?;

        let dest_addr = self
            .decode_address(destination)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address"))?;
        let mode = parse_fee_mode(params.get_str(2), true)?;

        check_send_total(
            &[TxOut::new(send_amount, dest_addr.script_pubkey())],
            wallet.get_vaulted_balance(),
        )?;
        ensure_not_dust(send_amount, &dest_addr.script_pubkey())?;

        let height = self.current_height();

        // Vault outputs whose owner key we hold, registered or not (Divi Core's
        // OWNED_VAULT_COINS); a manager key alone gives nothing to reclaim
        let owned_vault_utxos = wallet.get_owned_vault_utxos(height, 1);

        if owned_vault_utxos.is_empty() {
            return Err(
                RpcError::new(codes::WALLET_ERROR, "No vault funds available to reclaim").into(),
            );
        }

        // Divi Core VaultCoinSelector over every owned vault; with no change
        // script given, the change goes to a new key (rpcwallet.cpp:1158-1186,
        // wallet.cpp:1905-1910)
        let coins = Self::send_coins(&wallet, owned_vault_utxos, height);
        let payees = [TxOut::new(send_amount, dest_addr.script_pubkey())];
        let plan = Self::plan(&payees, &coins, mode, ChangeKind::Vault, &ChangeTo::NewKey)?;
        let txid = self.sign_and_submit(&wallet, &plan, ChangeTo::NewKey)?;
        // SendMoneyToAddress: the txid alone (rpcwallet.cpp:1189)
        Ok(json!(txid.to_string()))
    }

    /// BIP38 encrypt private key
    pub fn bip38_encrypt(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: diviaddress"))?;
        let passphrase = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: passphrase"))?;

        // Parse address
        let addr = self
            .decode_address(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address"))?;

        // Get wallet and check if locked
        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        // Get the private key for this address
        let key_entry = wallet.keystore().get_key_by_address(&addr).ok_or_else(|| {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                "Private key for address not found in wallet",
            )
        })?;

        // Extract key bytes - ensure not watch-only
        let secret = key_entry.secret.as_ref().ok_or_else(|| {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                "Address is watch-only, cannot export private key",
            )
        })?;
        let key_bytes = secret.as_bytes();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key_bytes);

        // Encrypt using BIP38 in the key's own form (as PIVX's bip38encrypt, which this
        // RPC follows; Divi Core's own BIP38 RPCs keep the flag the same way)
        let encrypted = divi_crypto::bip38_encrypt(&key_array, passphrase, key_entry.compressed)
            .map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("BIP38 encryption failed: {}", e),
                )
            })?;

        Ok(json!(encrypted))
    }

    /// Generate a fresh key (not stored in the wallet) and return it BIP38-encrypted
    pub fn bip38_paper_wallet(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let passphrase = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: password"))?;

        let wallet = self.get_wallet()?;
        ensure_fully_unlocked(&wallet)?;
        let network = wallet.network();

        let secret = divi_crypto::keys::SecretKey::new_random();
        let address = Address::p2pkh(&secret.public_key(), network).to_base58();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(secret.as_bytes());

        let encrypted = divi_crypto::bip38_encrypt(&key_array, passphrase, true).map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("BIP38 encryption failed: {}", e),
            )
        })?;

        Ok(json!({ "Address": address, "Encrypted Key": encrypted }))
    }

    /// BIP38 decrypt private key
    pub fn bip38_decrypt(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let encrypted_key = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: bip38key"))?;
        let passphrase = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: passphrase"))?;

        // Decrypt the BIP38 encrypted key
        let (private_key, compressed) = divi_crypto::bip38_decrypt(encrypted_key, passphrase)
            .map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("BIP38 decryption failed: {}", e),
                )
            })?;

        let network = self.address_network();

        // Encode as WIF
        use divi_wallet::address::encode_wif;
        let wif = encode_wif(&private_key, compressed, network);

        Ok(json!(wif))
    }

    /// loadwallet "filename" — refused: the wallet cannot be swapped on a running node.
    ///
    /// irondivid hands its one wallet to the block, mempool and reorg callbacks, the
    /// staker and the pruner at start, so replacing it here would leave them writing to
    /// the old one. The error says how to switch wallets today.
    pub fn load_wallet(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let filename = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: filename"))?;

        let current = self
            .wallet
            .read()
            .as_ref()
            .map(|w| w.database_path().display().to_string());
        let now = match current {
            Some(path) => format!("this node's wallet is {}", path),
            None => "this node runs without a wallet".to_string(),
        };
        Err(RpcError::new(
            codes::WALLET_ERROR,
            format!(
                "loadwallet is not supported: irondivid opens one wallet when it starts and \
                 keeps it until it stops ({now}). To use \"{filename}\" instead, stop irondivid \
                 and start it again with --wallet=<path to that wallet's directory>."
            ),
        )
        .into())
    }

    /// Allocate treasury funds
    pub fn allocate_funds(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let _target = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: target"))?;
        let _locktime = params
            .get_i64(1)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: locktime"))?;

        Err(RpcError::new(
            codes::MISC_ERROR,
            "Treasury fund allocation requires governance subsystem implementation. This RPC command is used for treasury and governance operations to allocate funds for community proposals. The governance system requires masternode voting integration. This feature will be added in a future release. For treasury operations, please use the C++ Divi client."
        ).into())
    }

    /// Decode a script
    ///
    /// Parameters:
    /// - hex: Script hex string
    ///
    /// Returns: JSON object with script details
    pub fn decode_script(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let hex_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing hex parameter"))?;

        let script_bytes =
            hex::decode(hex_str).map_err(|_| RpcError::invalid_params("Invalid script hex"))?;

        let _script = Script::from(script_bytes.clone());

        // Get script type
        let (script_type, solutions) = divi_script::extract_script_type(&script_bytes);
        let type_name = divi_script::get_script_type_name(script_type);

        let network = self.address_network();

        // Extract addresses based on script type
        let mut addresses: Vec<String> = Vec::new();
        let mut req_sigs: Option<usize> = None;

        match script_type {
            divi_script::ScriptType::PubKeyHash => {
                if solutions.len() == 1 && solutions[0].len() == 20 {
                    let mut hash = [0u8; 20];
                    hash.copy_from_slice(&solutions[0]);
                    let addr = Address::from_pubkey_hash(Hash160(hash), network);
                    addresses.push(addr.to_string());
                    req_sigs = Some(1);
                }
            }
            divi_script::ScriptType::ScriptHash => {
                if solutions.len() == 1 && solutions[0].len() == 20 {
                    let mut hash = [0u8; 20];
                    hash.copy_from_slice(&solutions[0]);
                    let addr = Address::p2sh(Hash160(hash), network);
                    addresses.push(addr.to_string());
                    req_sigs = Some(1);
                }
            }
            divi_script::ScriptType::PubKey => {
                // P2PK: compute hash160 of pubkey to get address
                if solutions.len() == 1 && (solutions[0].len() == 33 || solutions[0].len() == 65) {
                    let hash = divi_crypto::hash160(&solutions[0]);
                    let addr = Address::from_pubkey_hash(hash, network);
                    addresses.push(addr.to_string());
                    req_sigs = Some(1);
                }
            }
            divi_script::ScriptType::Multisig => {
                // Multisig: first solution is m, last is n, middle are pubkeys
                if solutions.len() >= 3 {
                    let m = solutions[0].first().copied().unwrap_or(0) as usize;
                    let _n = solutions
                        .last()
                        .and_then(|s| s.first().copied())
                        .unwrap_or(0) as usize;
                    req_sigs = Some(m);

                    // Skip first (m) and last (n) elements
                    for pubkey in &solutions[1..solutions.len() - 1] {
                        if pubkey.len() == 33 || pubkey.len() == 65 {
                            let hash = divi_crypto::hash160(pubkey);
                            let addr = Address::from_pubkey_hash(hash, network);
                            addresses.push(addr.to_string());
                        }
                    }
                }
            }
            divi_script::ScriptType::Vault => {
                // Vault scripts have owner and vault hashes
                if solutions.len() == 2 {
                    // First is owner hash, second is vault hash
                    for sol in solutions.iter() {
                        if sol.len() == 20 {
                            let mut hash = [0u8; 20];
                            hash.copy_from_slice(sol);
                            let addr = Address::from_pubkey_hash(Hash160(hash), network);
                            addresses.push(addr.to_string());
                        }
                    }
                    req_sigs = Some(1);
                }
            }
            divi_script::ScriptType::NullData => {
                // OP_RETURN data scripts have no addresses
                req_sigs = Some(0);
            }
            _ => {
                // NonStandard, HTLC, etc. - no addresses extracted
            }
        }

        // Build response
        let mut result = serde_json::json!({
            "asm": divi_script::to_asm(&script_bytes),
            "hex": hex_str,
            "type": type_name,
        });

        // Add addresses if present
        if !addresses.is_empty() {
            result["addresses"] = serde_json::json!(addresses);
        }

        // Add reqSigs if determined
        if let Some(sigs) = req_sigs {
            result["reqSigs"] = serde_json::json!(sigs);
        }

        // For P2SH, also include the P2SH address this script would create
        if script_type != divi_script::ScriptType::ScriptHash {
            let script_hash = divi_crypto::hash160(&script_bytes);
            let p2sh_addr = Address::p2sh(script_hash, network);
            result["p2sh"] = serde_json::json!(p2sh_addr.to_string());
        }

        Ok(result)
    }

    /// sendmany - Send to multiple addresses in one transaction
    pub fn send_many(&self, params: &Params) -> Result<serde_json::Value, Error> {
        // Divi Core spends only the named account's coins ("" for all)
        let account = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Account required"))?;

        // Get amounts object {"address": amount, ...}
        let amounts = params
            .get(1)
            .and_then(|v| v.as_object())
            .ok_or_else(|| RpcError::invalid_params("Amounts object required"))?;

        // Optional minconf (default 1); in Divi Core the third argument is a comment
        let min_conf = params.get_u64(2).unwrap_or(1) as u32;

        // Optional subtractfeefromamount array - addresses to subtract fee from
        let subtract_fee_from: Vec<String> = params
            .get(4)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        let height = self.current_height();

        // Divi Core parseMultiSendJson (rpcwallet.cpp:1652-1692): an amount, or
        // {"amount": a, "repetitions": n} for n outputs of a
        let mut payees: Vec<TxOut> = Vec::new();
        let mut subtract_outputs: Vec<usize> = Vec::new();
        for (addr_str, amount_value) in amounts {
            let addr = self.decode_address(addr_str).map_err(|_| {
                RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    format!("Invalid DIVI address: {}", addr_str),
                )
            })?;
            let (amount, repetitions) = match amount_value.as_object() {
                Some(details) => {
                    let amount = details.get("amount").ok_or_else(|| {
                        RpcError::new(
                            codes::INVALID_PARAMETER,
                            format!("Unable to parse amount for: {}", addr_str),
                        )
                    })?;
                    let repetitions = details
                        .get("repetitions")
                        .and_then(|r| r.as_i64())
                        .ok_or_else(|| {
                            RpcError::new(
                                codes::INVALID_PARAMETER,
                                format!("Unable to parse repetitions for: {}", addr_str),
                            )
                        })?;
                    (
                        amount_from_value(amount, false)?,
                        repetitions.max(1) as usize,
                    )
                }
                None => (amount_from_value(amount_value, false)?, 1),
            };
            for _ in 0..repetitions {
                if subtract_fee_from.contains(addr_str) {
                    subtract_outputs.push(payees.len());
                }
                payees.push(TxOut::new(amount, addr.script_pubkey()));
            }
        }

        // No recipients is a total of 0: -8 "Invalid amount", as Divi Core
        let available = if account.is_empty() {
            spendable_balance(&wallet, height)
        } else {
            coins_value(&Self::account_coins(
                &wallet,
                account,
                wallet.get_send_candidates(height, 1),
            ))
        };
        check_send_total(&payees, available)?;
        for out in &payees {
            ensure_not_dust(out.value, &out.script_pubkey)?;
        }

        let candidates = Self::account_coins(
            &wallet,
            account,
            wallet.get_send_candidates(height, min_conf),
        );
        let coins = Self::send_coins(&wallet, candidates, height);
        let mut plan = Self::plan(
            &payees,
            &coins,
            FeeMode::SenderPays,
            ChangeKind::P2pkh,
            &ChangeTo::NewKey,
        )?;
        if !subtract_outputs.is_empty() {
            subtract_fee_from_outputs(&mut plan, &subtract_outputs)?;
        }
        let txid = self.sign_and_submit(&wallet, &plan, ChangeTo::NewKey)?;

        info!("Sent {} outputs (txid: {})", plan.outputs.len(), txid);

        Ok(serde_json::json!(txid.to_string()))
    }

    /// walletpassphrasechange - Change wallet passphrase
    pub fn wallet_passphrase_change(&self, params: &Params) -> Result<serde_json::Value, Error> {
        if let Ok(wallet) = self.get_wallet() {
            if !wallet.is_encrypted() {
                return Err(RpcError::new(
                    codes::WALLET_WRONG_ENC_STATE,
                    "Error: running with an unencrypted wallet, but walletpassphrasechange was called.",
                )
                .into());
            }
        }
        let old_passphrase = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Old passphrase required"))?;
        let new_passphrase = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("New passphrase required"))?;

        if old_passphrase.is_empty() || new_passphrase.is_empty() {
            return Err(RpcError::new(
                codes::MISC_ERROR,
                "walletpassphrasechange <oldpassphrase> <newpassphrase>\n\
                 Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.",
            )
            .into());
        }

        let wallet = self.get_wallet()?;

        if !wallet.is_encrypted() {
            return Err(RpcError::new(
                codes::WALLET_WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletpassphrasechange was called.",
            )
            .into());
        }

        // Change the passphrase
        wallet
            .change_passphrase(old_passphrase, new_passphrase)
            .map_err(|e| match e {
                divi_wallet::WalletError::WrongPassphrase => RpcError::new(
                    codes::WALLET_PASSPHRASE_INCORRECT,
                    "Error: The wallet passphrase entered was incorrect.",
                ),
                other => RpcError::new(codes::WALLET_ENCRYPTION_FAILED, other.to_string()),
            })?;

        Ok(serde_json::Value::Null)
    }

    /// encryptwallet - Encrypt the wallet with a passphrase (one-way; leaves it locked)
    pub fn encrypt_wallet(&self, params: &Params) -> Result<serde_json::Value, Error> {
        if let Ok(wallet) = self.get_wallet() {
            if wallet.is_encrypted() {
                return Err(RpcError::new(
                    codes::WALLET_WRONG_ENC_STATE,
                    "Error: running with an encrypted wallet, but encryptwallet was called.",
                )
                .into());
            }
        }
        let passphrase = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("encryptwallet \"passphrase\""))?;
        if passphrase.is_empty() {
            return Err(RpcError::new(
                codes::MISC_ERROR,
                "encryptwallet <passphrase>\nEncrypts the wallet with <passphrase>.",
            )
            .into());
        }

        let wallet = self.get_wallet()?;

        if wallet.is_encrypted() {
            return Err(RpcError::new(
                codes::WALLET_WRONG_ENC_STATE,
                "Error: running with an encrypted wallet, but encryptwallet was called.",
            )
            .into());
        }

        wallet.encrypt_wallet(passphrase).map_err(|e| {
            RpcError::new(
                codes::WALLET_ENCRYPTION_FAILED,
                format!("Error: Failed to encrypt the wallet: {}", e),
            )
        })?;

        // Unlike C++ Divi, the node keeps running: the wallet is already locked and
        // its plaintext secrets are gone from memory and disk.
        Ok(serde_json::json!(
            "wallet encrypted; the wallet is now locked. Use walletpassphrase to unlock it. \
             Back up your wallet again: earlier backups are not encrypted."
        ))
    }

    /// getreceivedbyaddress - Get total amount received by an address
    pub fn get_received_by_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let min_conf = params.get_u64(1).unwrap_or(1) as u32;

        let addr = self
            .decode_address(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address"))?;

        let wallet = self.get_wallet()?;

        if !wallet.is_mine(&addr) {
            return Ok(serde_json::json!(0.0));
        }

        // Everything received at the address, including coins since spent:
        // outputs paying exactly its script, so a P2PK output to its key is not
        // counted (rpcwallet.cpp:1468-1480). Coinbase outputs are left out.
        let height = self.current_height();
        let script = addr.script_pubkey();
        let total: i64 = wallet
            .received_outputs()
            .iter()
            .filter(|o| !o.is_coinbase && o.script_pubkey == script)
            .filter(|o| o.confirmations(height) >= min_conf)
            .map(|o| o.value.as_sat())
            .sum();

        let divi = total as f64 / 100_000_000.0;
        Ok(serde_json::json!(divi))
    }

    /// importaddress - Import a watch-only address
    pub fn import_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_or_script = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address or script required"))?;

        let label = params.get_str(1);
        let rescan = params.get_bool(2).unwrap_or(true);
        let _p2sh = params.get_bool(3).unwrap_or(false);

        let wallet = self.get_wallet()?;

        // Try to parse as address first
        let addr = if let Ok(address) = self.decode_address(addr_or_script) {
            address
        } else {
            // Try as hex script
            let script_bytes = hex::decode(addr_or_script).map_err(|_| {
                RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    "Invalid DIVI address or script",
                )
            })?;

            let script = Script::from_bytes(script_bytes);

            // Extract address from script (P2PKH or P2SH)
            if let Some(hash_bytes) = script.extract_p2pkh_hash() {
                // P2PKH script
                let hash = divi_primitives::hash::Hash160::from_bytes(hash_bytes);
                Address::from_pubkey_hash(hash, wallet.network())
            } else if let Some(hash_bytes) = script.extract_p2sh_hash() {
                // P2SH script
                let hash = divi_primitives::hash::Hash160::from_bytes(hash_bytes);
                Address::p2sh(hash, wallet.network())
            } else {
                return Err(RpcError::new(
                    codes::WALLET_ERROR,
                    "Only P2PKH and P2SH scripts are supported for watch-only import",
                )
                .into());
            }
        };

        if wallet.is_mine(&addr) && !wallet.is_watch_only(&addr) {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                "The wallet already contains the private key for this address",
            )
            .into());
        }
        // As Core: an address already watched only gets its label
        // (rpcdump.cpp:150-156)
        if wallet.is_watch_only(&addr) {
            wallet.set_label(&addr, label.unwrap_or("")).map_err(|e| {
                RpcError::new(codes::WALLET_ERROR, format!("Failed to store label: {}", e))
            })?;
            return Ok(serde_json::Value::Null);
        }

        // Import as watch-only address
        wallet
            .import_watch_only_address(&addr, label.map(|s| s.to_string()))
            .map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Failed to import watch-only address: {}", e),
                )
            })?;

        info!("Imported watch-only address: {}", addr);
        wallet.set_label(&addr, label.unwrap_or("")).map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to store label: {}", e))
        })?;

        // Save wallet
        wallet.save().map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to save wallet: {}", e))
        })?;

        // Past coins to the address show only after a scan, as in Divi Core
        if rescan {
            self.rescan_after_import(&wallet)?;
        }

        Ok(serde_json::Value::Null)
    }

    /// addmultisigaddress - Create a multisig address and add to wallet
    pub fn add_multisig_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let nrequired = params
            .get_u64(0)
            .ok_or_else(|| RpcError::invalid_params("nrequired parameter required"))?
            as usize;

        let keys_array = params
            .get(1)
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::invalid_params("Keys array required"))?;

        let _account = params.get_str(2).unwrap_or("");

        if nrequired < 1 {
            return Err(RpcError::invalid_params("nrequired must be at least 1").into());
        }

        if keys_array.is_empty() {
            return Err(RpcError::invalid_params("Keys array cannot be empty").into());
        }

        if nrequired > keys_array.len() {
            return Err(RpcError::invalid_params(format!(
                "nrequired ({}) cannot be greater than number of keys ({})",
                nrequired,
                keys_array.len()
            ))
            .into());
        }

        // Parse keys (addresses or public keys)
        let mut pubkeys = Vec::new();
        let wallet = self.get_wallet()?;

        for key_val in keys_array {
            let key_str = key_val.as_str().ok_or_else(|| {
                RpcError::invalid_params("Keys must be strings (addresses or hex pubkeys)")
            })?;

            // Try to parse as address first
            if let Ok(addr) = self.decode_address(key_str) {
                // Get pubkey from wallet
                if let Some(key_entry) = wallet.get_key_by_address(&addr) {
                    pubkeys.push(key_entry.pubkey_bytes());
                } else {
                    return Err(RpcError::new(
                        codes::INVALID_ADDRESS_OR_KEY,
                        format!("Address not found in wallet: {}", key_str),
                    )
                    .into());
                }
            } else if let Ok(pubkey_bytes) = hex::decode(key_str) {
                // Use hex-encoded public key directly
                if pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65 {
                    return Err(RpcError::invalid_params(format!(
                        "Invalid public key length: {}",
                        key_str
                    ))
                    .into());
                }
                pubkeys.push(pubkey_bytes);
            } else {
                return Err(RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    format!("Invalid key: {}", key_str),
                )
                .into());
            }
        }

        // Create multisig redeem script
        use divi_script::opcodes::Opcode;
        let mut script_bytes = Vec::new();

        // OP_n (number required)
        if (1..=16).contains(&nrequired) {
            script_bytes.push(Opcode::OP_1 as u8 + (nrequired as u8 - 1));
        } else {
            return Err(RpcError::invalid_params("nrequired must be between 1 and 16").into());
        }

        // Add public keys
        for pubkey in &pubkeys {
            script_bytes.push(pubkey.len() as u8);
            script_bytes.extend_from_slice(pubkey);
        }

        // OP_m (total keys)
        let m = pubkeys.len();
        if (1..=16).contains(&m) {
            script_bytes.push(Opcode::OP_1 as u8 + (m as u8 - 1));
        } else {
            return Err(RpcError::invalid_params("Number of keys must be between 1 and 16").into());
        }

        // OP_CHECKMULTISIG
        script_bytes.push(Opcode::OP_CHECKMULTISIG as u8);

        let redeem_script = Script::from_bytes(script_bytes);

        // Create P2SH address from redeem script hash
        use divi_crypto::hash160;
        let script_hash = hash160(redeem_script.as_bytes());
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(script_hash.as_ref());
        let p2sh_addr = Address::p2sh(
            divi_primitives::hash::Hash160::from_bytes(hash_bytes),
            wallet.network(),
        );

        wallet.add_script(redeem_script.clone()).map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("Failed to store redeem script: {}", e),
            )
        })?;

        wallet.save().map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to save wallet: {}", e))
        })?;

        info!(
            "Created multisig address {} and stored redeem script",
            p2sh_addr.to_base58()
        );

        // Divi Core answers the address alone (rpcwallet.cpp:1736-1781)
        Ok(serde_json::json!(p2sh_addr.to_base58()))
    }

    /// keypoolrefill - Refill the keypool with pre-generated keys
    ///
    /// # Arguments
    /// * `newsize` - Optional new keypool target size (default: 100)
    ///
    /// This pre-generates HD-derived keys for faster address generation.
    pub fn keypool_refill(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let newsize = params.get_u64(0).map(|s| s as u32);

        if let Some(size) = newsize {
            if size == 0 {
                return Err(RpcError::invalid_params("Keypool size must be at least 1").into());
            }
        }

        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        // Actually refill the keypool
        let generated = wallet
            .refill_keypool(newsize)
            .map_err(|e| RpcError::internal_error(format!("Failed to refill keypool: {}", e)))?;

        info!("Keypool refilled with {} new keys", generated);

        Ok(serde_json::Value::Null)
    }

    /// getkeypoolsize - Get the current keypool size
    ///
    /// Returns the number of pre-generated but unused keys in the keypool.
    /// This represents the buffer of keys available for immediate use without
    /// requiring additional key derivation operations.
    pub fn get_keypool_size(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;
        let size = wallet.keypool_size();
        Ok(serde_json::json!(size))
    }

    /// sendfrom - Send from a specific account (legacy)
    pub fn send_from(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let account = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Account required"))?;

        let addr_str = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let send_amount = amount_from_value(
            params
                .get(2)
                .ok_or_else(|| RpcError::invalid_params("Amount required"))?,
            false,
        )?;

        let min_conf = params.get_u64(3).unwrap_or(1) as u32;
        let _comment = params.get_str(4);
        let _comment_to = params.get_str(5);

        let dest_addr = self
            .decode_address(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address"))?;

        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        let height = self.current_height();
        let available = if account.is_empty() {
            spendable_balance(&wallet, height)
        } else {
            coins_value(&Self::account_coins(
                &wallet,
                account,
                wallet.get_send_candidates(height, 1),
            ))
        };
        check_send_total(
            &[TxOut::new(send_amount, dest_addr.script_pubkey())],
            available,
        )?;
        ensure_not_dust(send_amount, &dest_addr.script_pubkey())?;

        if !account.is_empty() && wallet.get_addresses_by_account(account).is_empty() {
            return Err(RpcError::new(
                codes::WALLET_INVALID_ACCOUNT_NAME,
                format!("Account '{}' has no addresses", account),
            )
            .into());
        }

        // Only the account's coins, as Divi Core's AccountCoinSelector
        let candidates = Self::account_coins(
            &wallet,
            account,
            wallet.get_send_candidates(height, min_conf),
        );
        let coins = Self::send_coins(&wallet, candidates, height);
        let payees = [TxOut::new(send_amount, dest_addr.script_pubkey())];
        let plan = Self::plan(
            &payees,
            &coins,
            FeeMode::SenderPays,
            ChangeKind::P2pkh,
            &ChangeTo::NewKey,
        )?;
        let txid = self.sign_and_submit(&wallet, &plan, ChangeTo::NewKey)?;

        info!(
            "Sent {} DIVI from account '{}' to {} (txid: {})",
            send_amount.as_divi_f64(),
            account,
            addr_str,
            txid
        );

        Ok(serde_json::json!(txid.to_string()))
    }

    /// listlockunspent - Returns list of temporarily unspendable outputs
    pub fn list_lock_unspent(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet_guard = self.wallet.read();
        let wallet = wallet_guard
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Wallet not loaded"))?;
        let result: Vec<_> = wallet
            .locked_coins()
            .iter()
            .map(|outpoint| {
                serde_json::json!({
                    "txid": outpoint.txid.to_string(),
                    "vout": outpoint.vout
                })
            })
            .collect();
        Ok(serde_json::json!(result))
    }

    /// lockunspent - Lock or unlock UTXOs
    pub fn lock_unspent(&self, params: &Params) -> Result<serde_json::Value, Error> {
        if params.is_empty() || params.len() > 2 {
            return Err(RpcError::invalid_params(
                "lockunspent unlock [{\"txid\":\"txid\",\"vout\":n},...]",
            )
            .into());
        }
        let unlock = params
            .get_bool(0)
            .ok_or_else(|| RpcError::new(codes::TYPE_ERROR, "Expected boolean for unlock"))?;

        let outputs_array = params
            .get(1)
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::invalid_params("outputs array required"))?;

        let wallet_guard = self.wallet.read();
        let wallet = wallet_guard
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Wallet not loaded"))?;

        for output in outputs_array {
            let txid_str = output
                .get("txid")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RpcError::invalid_params("txid required"))?;

            let vout = output
                .get("vout")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| RpcError::invalid_params("vout required"))?
                as u32;

            let txid = Hash256::from_hex(txid_str)
                .map_err(|_| RpcError::invalid_params("Invalid txid"))?;

            let outpoint = OutPoint { txid, vout };

            wallet.set_coin_locked(outpoint, !unlock);
        }

        Ok(serde_json::Value::Bool(true))
    }

    /// dumphdinfo - Display HD wallet seed information
    pub fn dump_hd_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet_guard = self.wallet.read();
        let wallet = wallet_guard
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Wallet not loaded"))?;

        if !wallet.is_fully_unlocked() {
            return Err(RpcError::new(
                codes::WALLET_UNLOCK_NEEDED,
                "Error: Please enter the wallet passphrase with walletpassphrase first.",
            )
            .into());
        }

        let path = wallet.hd_account_path().unwrap_or_default();
        // A wallet made from a seed has no words: Core shows the seed and an
        // empty mnemonic (rpcdump.cpp:229-231)
        if wallet.mnemonic().is_none() {
            if let Some(seed) = wallet.hd_seed() {
                return Ok(serde_json::json!({
                    "hdseed": hex::encode(&seed[..]),
                    "mnemonic": "",
                    "mnemonicpassphrase": "",
                    "hdaccountpath": path
                }));
            }
        }

        let mnemonic = wallet
            .mnemonic()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "No mnemonic found in wallet"))?;

        let mnemonic_obj: Mnemonic = mnemonic
            .parse()
            .map_err(|e| RpcError::new(codes::WALLET_ERROR, format!("Invalid mnemonic: {}", e)))?;

        // The seed is made with the mnemonic passphrase, as Core's CHDChain
        // (rpcdump.cpp:221-233)
        let passphrase = wallet.mnemonic_passphrase().unwrap_or_default();
        let seed = mnemonic_obj.to_seed(passphrase.as_str());
        let hdseed_hex = hex::encode(&seed[0..64]);

        // The account path names the coin type, so a restore elsewhere can
        // use the same one (wallets made before the coin type followed the
        // network keep 301 on testnet)
        Ok(serde_json::json!({
            "hdseed": hdseed_hex,
            "mnemonic": mnemonic,
            "mnemonicpassphrase": passphrase,
            "hdaccountpath": path
        }))
    }

    /// backupwallet - write a consistent copy of the wallet to destination
    pub fn backup_wallet(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let destination = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Destination path required"))?;

        let wallet = self.get_wallet()?;
        wallet
            .backup_to(std::path::Path::new(destination))
            .map_err(|e| {
                // Core's reply (rpcwallet.cpp:2538); the cause goes to the log
                warn!("backupwallet to {}: {}", destination, e);
                RpcError::new(codes::WALLET_ERROR, "Error: Wallet backup failed!")
            })?;
        Ok(serde_json::Value::Null)
    }
}

/// Compute the double-SHA256 hash of a message with the DarkNet magic prefix,
/// matching C++ Divi's CHashWriter-based signmessage/verifymessage protocol.
///
/// C++ uses `CHashWriter::operator<<(const std::string&)` which writes:
///   CompactSize(len) || bytes
/// so the full serialized data is:
///   CompactSize(24) || "DarkNet Signed Message:\n" || CompactSize(len(msg)) || msg
/// then Hash256 (double-SHA256) of that buffer.
pub fn message_magic_hash(message: &[u8]) -> [u8; 32] {
    const MAGIC: &[u8] = b"DarkNet Signed Message:\n"; // 24 bytes

    /// Write a Bitcoin CompactSize (varint) into `buf`.
    fn write_compact_size(buf: &mut Vec<u8>, n: usize) {
        if n < 0xFD {
            buf.push(n as u8);
        } else if n <= 0xFFFF {
            buf.push(0xFD);
            buf.push((n & 0xFF) as u8);
            buf.push(((n >> 8) & 0xFF) as u8);
        } else if n <= 0xFFFF_FFFF {
            buf.push(0xFE);
            buf.push((n & 0xFF) as u8);
            buf.push(((n >> 8) & 0xFF) as u8);
            buf.push(((n >> 16) & 0xFF) as u8);
            buf.push(((n >> 24) & 0xFF) as u8);
        } else {
            buf.push(0xFF);
            for i in 0..8 {
                buf.push(((n >> (8 * i)) & 0xFF) as u8);
            }
        }
    }

    let mut data = Vec::with_capacity(1 + MAGIC.len() + 9 + message.len());
    write_compact_size(&mut data, MAGIC.len());
    data.extend_from_slice(MAGIC);
    write_compact_size(&mut data, message.len());
    data.extend_from_slice(message);

    divi_crypto::double_sha256(&data)
}

impl WalletRpc {
    /// signmessage - Sign a message with the private key of an address
    pub fn sign_message(&self, params: &Params) -> Result<serde_json::Value, Error> {
        if params.len() < 2 || params.len() > 4 {
            return Err(RpcError::invalid_params(
                "signmessage \"diviaddress\" \"message\" ( \"input_format\" \"output_format\" )",
            )
            .into());
        }
        let address_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;
        let text = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Message required"))?;
        let format = |i: usize| {
            params
                .get_str(i)
                .ok_or_else(|| RpcError::invalid_params("Format must be a string"))
        };
        // Divi Core: "hex" or "b64" decode the message first; anything else is text
        let message = match (params.len() > 2).then(|| format(2)).transpose()? {
            Some("hex") => parse_hex_like_core(text),
            Some("b64") => decode_base64_core(text).0,
            _ => text.as_bytes().to_vec(),
        };
        let hex_output = params.len() == 4 && format(3)? == "hex";

        let wallet = self.get_wallet()?;

        ensure_fully_unlocked(&wallet)?;

        // Parse address (error codes as Divi Core's signmessage)
        let address = self
            .decode_address(address_str)
            .map_err(|_| RpcError::new(codes::TYPE_ERROR, "Invalid address"))?;
        if address.addr_type != divi_wallet::AddressType::P2PKH {
            return Err(RpcError::new(codes::TYPE_ERROR, "Address does not refer to key").into());
        }

        // Get private key for this address; watch-only keys have none
        let no_key = || RpcError::new(codes::WALLET_ERROR, "Private key not available");
        let key_entry = wallet
            .keystore()
            .get_key_by_address(&address)
            .ok_or_else(no_key)?;
        let secret = key_entry.secret.as_ref().ok_or_else(no_key)?;

        // Hash with the DarkNet magic prefix to match C++ Divi's CHashWriter protocol
        let hash = message_magic_hash(&message);
        let signature = divi_crypto::sign_hash_recoverable(secret, &hash)
            .map_err(|e| RpcError::new(codes::MISC_ERROR, format!("Signing failed: {}", e)))?;

        // 65 bytes: header (27 + recid, +4 for a compressed key) + r + s
        let sig_bytes = if key_entry.compressed {
            signature.to_compact_with_recovery()
        } else {
            signature.to_compact_with_recovery_uncompressed()
        };
        if hex_output {
            return Ok(serde_json::Value::String(hex::encode(sig_bytes)));
        }
        let sig_b64 = STANDARD.encode(sig_bytes);

        debug!("Signed message with address {}", address_str);
        // Return as plain string, not wrapped in json!()
        Ok(serde_json::Value::String(sig_b64))
    }

    /// verifymessage - Verify a signed message
    pub fn verify_message(&self, params: &Params) -> Result<serde_json::Value, Error> {
        if params.len() != 3 {
            return Err(RpcError::invalid_params(
                "verifymessage \"diviaddress\" \"signature\" \"message\"",
            )
            .into());
        }
        let address_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;
        let signature_b64 = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Signature required"))?;
        let message = params
            .get_str(2)
            .ok_or_else(|| RpcError::invalid_params("Message required"))?;

        // Parse address (error codes as Divi Core's verifymessage)
        let address = self
            .decode_address(address_str)
            .map_err(|_| RpcError::new(codes::TYPE_ERROR, "Invalid address"))?;
        if address.addr_type != divi_wallet::AddressType::P2PKH {
            return Err(RpcError::new(codes::TYPE_ERROR, "Address does not refer to key").into());
        }

        // Decode base64 signature
        let sig_bytes = decode_base64_like_core(signature_b64).ok_or_else(|| {
            RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding")
        })?;

        // A signature that does not parse or recover is "not verified", not an error
        let Ok(signature) = divi_crypto::RecoverableSig::from_compact_with_recovery(&sig_bytes)
        else {
            return Ok(serde_json::Value::Bool(false));
        };

        // Recover the public key from the signature using the DarkNet magic-prefixed hash
        let hash = message_magic_hash(message.as_bytes());
        let Ok(recovered_pubkey) = signature.recover_from_hash(&hash) else {
            return Ok(serde_json::Value::Bool(false));
        };

        // Derive the address from the recovered key in the form the header names
        // (CPubKey::RecoverCompact: 27..30 uncompressed, 31..34 compressed)
        let recovered_bytes = if (27..=30).contains(&sig_bytes[0]) {
            recovered_pubkey.serialize_uncompressed().to_vec()
        } else {
            recovered_pubkey.to_bytes()
        };
        let recovered_address =
            Address::from_pubkey_hash(divi_crypto::hash160(&recovered_bytes), address.network);

        // Check if recovered address matches the claimed address
        let valid = recovered_address == address;

        debug!(
            "Verified message signature: address={}, valid={}",
            address_str, valid
        );
        Ok(serde_json::Value::Bool(valid))
    }

    /// createmultisig - Create a multisig address
    pub fn create_multisig(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let nrequired = params.get_i64(0).ok_or_else(|| {
            RpcError::invalid_params("nrequired (number of required signatures) required")
        })?;

        let keys_array = params
            .get(1)
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::invalid_params("keys array required"))?;

        if nrequired < 1 {
            return Err(RpcError::invalid_params("nrequired must be at least 1").into());
        }

        if keys_array.is_empty() {
            return Err(RpcError::invalid_params("keys array cannot be empty").into());
        }

        if nrequired as usize > keys_array.len() {
            return Err(RpcError::invalid_params(
                "nrequired cannot be greater than number of keys",
            )
            .into());
        }

        let mut pubkeys = Vec::new();

        for key_val in keys_array {
            let key_str = key_val.as_str().ok_or_else(|| {
                RpcError::invalid_params("Each key must be a string (hex pubkey or address)")
            })?;

            // Serialized as given: an uncompressed key stays 65 bytes, as in Core
            let pubkey = if key_str.len() == 66 || key_str.len() == 130 {
                divi_crypto::keys::PublicKey::from_hex(key_str)
                    .map_err(|_| RpcError::new(codes::MISC_ERROR, "Invalid hex public key"))?;
                hex::decode(key_str)
                    .map_err(|_| RpcError::new(codes::MISC_ERROR, "Invalid hex public key"))?
            } else {
                let address = self
                    .decode_address(key_str)
                    .map_err(|_| RpcError::new(codes::MISC_ERROR, "Invalid address"))?;

                let wallet_guard = self.wallet.read();
                if let Some(wallet) = wallet_guard.as_ref() {
                    wallet
                        .keystore()
                        .get_key_by_address(&address)
                        .map(|entry| entry.pubkey_bytes())
                        .ok_or_else(|| {
                            RpcError::new(
                                codes::MISC_ERROR,
                                "Address not found in wallet - cannot extract pubkey",
                            )
                        })?
                } else {
                    return Err(RpcError::new(
                        codes::WALLET_ERROR,
                        "Wallet not available - addresses require pubkey lookup",
                    )
                    .into());
                }
            };

            pubkeys.push(pubkey);
        }

        let mut redeem_script = Vec::new();

        redeem_script.push(0x50 + nrequired as u8);

        for pubkey_bytes in &pubkeys {
            redeem_script.push(pubkey_bytes.len() as u8);
            redeem_script.extend_from_slice(pubkey_bytes);
        }

        redeem_script.push(0x50 + pubkeys.len() as u8);
        redeem_script.push(Opcode::OP_CHECKMULTISIG as u8);

        let script_hash = divi_crypto::hash160(&redeem_script);

        let network = self.address_network();
        let address = Address::p2sh(script_hash, network);
        let address_str = address.to_base58();

        Ok(serde_json::json!({
            "address": address_str,
            "redeemScript": hex::encode(&redeem_script)
        }))
    }

    pub fn get_account(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let address_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let address = self
            .decode_address(address_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address"))?;

        let wallet = self.get_wallet()?;
        let account = wallet.get_account(&address);

        Ok(serde_json::json!(account))
    }

    pub fn set_account(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let address_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;
        // C++: the account is optional (defaults to "") and the address is checked first
        let account = params.get_str(1).unwrap_or("");

        let address = self
            .decode_address(address_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address"))?;

        let wallet = self.get_wallet()?;

        if !wallet.is_mine(&address) {
            return Err(RpcError::new(
                codes::MISC_ERROR,
                "setaccount can only be used with own address",
            )
            .into());
        }

        wallet.set_account(&address, account);

        wallet.save().map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to save wallet: {}", e))
        })?;

        Ok(serde_json::Value::Null)
    }

    pub fn get_account_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let account = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Account required"))?;

        let wallet = self.get_wallet()?;

        // Divi Core's GetAccountAddress (rpcwallet.cpp:315-375): the account's
        // last address, unless a wallet transaction already pays it
        let addresses = wallet.get_addresses_by_account(account);
        if let Some(last) = addresses.last() {
            let paid = wallet.received_outputs().iter().any(|o| &o.address == last);
            if !paid {
                return Ok(serde_json::json!(last));
            }
        }

        let new_addr = wallet.new_receiving_address().map_err(new_key_error)?;

        wallet.set_label(&new_addr, account).map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to store label: {}", e))
        })?;

        Ok(serde_json::json!(new_addr.to_string()))
    }

    pub fn get_addresses_by_account(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let account = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Account required"))?;

        let wallet = self.get_wallet()?;
        let addresses = wallet.get_addresses_by_account(account);

        Ok(serde_json::json!(addresses))
    }

    pub fn list_accounts(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let min_conf = params.get_u64(0).unwrap_or(1) as u32;
        let _include_watchonly = params.get_bool(1).unwrap_or(false);

        let height = self.current_height();
        let accounts = wallet.list_accounts();

        let mut result = serde_json::Map::new();

        for (account_name, addresses) in accounts {
            let mut account_balance = Amount::ZERO;

            for addr_str in addresses {
                let utxos = wallet.get_utxos();
                for utxo in utxos {
                    if utxo.address == addr_str {
                        let confs = utxo.confirmations(height);
                        if confs >= min_conf && utxo.is_mature(height, wallet.coinbase_maturity()) {
                            account_balance += utxo.value;
                        }
                    }
                }
            }

            let divi = account_balance.as_sat() as f64 / 100_000_000.0;
            result.insert(account_name, serde_json::json!(divi));
        }
        // C++ always lists the default account ""
        result
            .entry(String::new())
            .or_insert(serde_json::json!(0.0));

        Ok(serde_json::json!(result))
    }

    pub fn get_received_by_account(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let account = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Account required"))?;

        let min_conf = params.get_u64(1).unwrap_or(1) as u32;

        let wallet = self.get_wallet()?;
        let received = self.received_by_address(&wallet, min_conf);

        let total: i64 = wallet
            .get_addresses_by_account(account)
            .iter()
            .filter_map(|addr| received.get(addr))
            .map(|(amount, _)| amount)
            .sum();

        let divi = total as f64 / 100_000_000.0;
        Ok(serde_json::json!(divi))
    }

    pub fn list_received_by_account(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let min_conf = params.get_u64(0).unwrap_or(1) as u32;
        let include_empty = params.get_bool(1).unwrap_or(false);
        let _include_watchonly = params.get_bool(2).unwrap_or(false);

        let accounts = wallet.list_accounts();
        let received = self.received_by_address(&wallet, min_conf);

        let mut result = Vec::new();

        for (account_name, addresses) in accounts {
            let mut account_total = Amount::ZERO;
            let mut min_confirmations = u32::MAX;

            for addr_str in addresses {
                if let Some((amount, confs)) = received.get(&addr_str) {
                    account_total += Amount::from_sat(*amount);
                    min_confirmations = min_confirmations.min(*confs);
                }
            }

            if account_total > Amount::ZERO || include_empty {
                let divi = account_total.as_sat() as f64 / 100_000_000.0;
                result.push(serde_json::json!({
                    "account": account_name,
                    "amount": divi,
                    "confirmations": if min_confirmations == u32::MAX { 0 } else { min_confirmations },
                    "bcconfirmations": if min_confirmations == u32::MAX { 0 } else { min_confirmations }
                }));
            }
        }

        Ok(serde_json::json!(result))
    }
}

impl Default for WalletRpc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::ChainMode;
    use divi_wallet::{HdWallet, Network};

    fn create_test_wallet_rpc() -> WalletRpc {
        let wallet = HdWallet::new(ChainMode::Divi).unwrap();
        let wallet_db = Arc::new(WalletDb::with_hd_wallet(Network::Mainnet, wallet));
        WalletRpc::with_wallet(wallet_db)
    }

    fn rpc_code(e: Error) -> i32 {
        match e {
            Error::Rpc(r) => r.code,
            other => panic!("expected an RPC error, got {:?}", other),
        }
    }

    #[test]
    fn sendrawtransaction_non_final_is_rejected_with_26() {
        // Divi Core answers -26 "64: non-final"; other submit failures stay -25
        use divi_primitives::transaction::{TxIn, TxOut};
        let rpc = create_test_wallet_rpc();
        rpc.set_tx_submit(Arc::new(
            |_tx: Transaction| -> Result<Hash256, TxSubmitError> {
                Err(TxSubmitError::Rejected {
                    code: 64,
                    reason: "non-final".to_string(),
                })
            },
        ));
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([7; 32]), 0),
                Script::new(),
                0,
            )],
            vout: vec![TxOut::new(
                divi_primitives::amount::Amount::from_sat(1000),
                Script::new(),
            )],
            lock_time: 4_000_000_000,
        };
        let hex = hex::encode(divi_primitives::serialize::serialize(&tx));
        let err = rpc
            .send_raw_transaction(&Params::Array(vec![serde_json::json!(hex)]))
            .unwrap_err();
        match err {
            Error::Rpc(r) => {
                assert_eq!(r.code, codes::VERIFY_REJECTED);
                assert_eq!(r.message, "64: non-final");
            }
            other => panic!("expected an RPC error, got {:?}", other),
        }
    }

    #[test]
    fn error_code_order_matches_cpp() {
        let rpc = create_test_wallet_rpc();
        let p = |v: &[&str]| Params::Array(v.iter().map(|s| serde_json::json!(s)).collect());
        // sendtoaddress: argument count (usage, -1) before address validity
        assert_eq!(
            rpc_code(rpc.send_to_address(&p(&["__bad__"])).unwrap_err()),
            codes::MISC_ERROR
        );
        // setaccount: address validity (-5) before the account is required
        assert_eq!(
            rpc_code(rpc.set_account(&p(&["__bad__"])).unwrap_err()),
            codes::INVALID_ADDRESS_OR_KEY
        );
        // importaddress: neither an address nor hex script is -5
        assert_eq!(
            rpc_code(rpc.import_address(&p(&["__bad__"])).unwrap_err()),
            codes::INVALID_ADDRESS_OR_KEY
        );
        // removevault without "owner:manager" is -8
        assert_eq!(
            rpc_code(rpc.remove_vault(&p(&["__bad__"])).unwrap_err()),
            codes::INVALID_PARAMETER
        );
        // lockunspent without arguments is usage (-1)
        assert_eq!(
            rpc_code(rpc.lock_unspent(&Params::None).unwrap_err()),
            codes::MISC_ERROR
        );
    }

    /// lockunspent locks the coin in the wallet itself, where the staker
    /// sees it (Divi Core keeps locked coins out of the stake set)
    #[test]
    fn lockunspent_locks_the_coin_in_the_wallet() {
        let rpc = create_test_wallet_rpc();
        let wallet = rpc.wallet_db().unwrap();
        let coin = OutPoint::new(Hash256::from_bytes([9; 32]), 2);
        let entry = json!([{ "txid": coin.txid.to_string(), "vout": 2 }]);
        rpc.lock_unspent(&Params::Array(vec![json!(false), entry.clone()]))
            .unwrap();
        assert!(wallet.is_coin_locked(&coin));
        assert_eq!(
            rpc.list_lock_unspent(&Params::None).unwrap(),
            json!([{ "txid": coin.txid.to_string(), "vout": 2 }])
        );
        rpc.lock_unspent(&Params::Array(vec![json!(true), entry]))
            .unwrap();
        assert!(!wallet.is_coin_locked(&coin));
        assert_eq!(rpc.list_lock_unspent(&Params::None).unwrap(), json!([]));
    }

    #[test]
    fn signtransactionwithaddresskey_signs_with_wallet_key() {
        use divi_primitives::transaction::{TxIn, TxOut};
        let rpc = create_test_wallet_rpc();
        let addr = rpc
            .get_new_address(&Params::None)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([7; 32]), 0),
                Script::new(),
                0xffff_ffff,
            )],
            vout: vec![TxOut::new(Amount::from_sat(1000), Script::new())],
            lock_time: 0,
        };
        let hex = hex::encode(serialize(&tx));
        let params = Params::Array(vec![json!(hex), json!(addr), json!(0)]);
        let asm = rpc.sign_transaction_with_address_key(&params).unwrap();
        let asm = asm.as_str().unwrap();
        // a bare DER signature ending in the SIGHASH_SINGLE byte
        assert!(asm.starts_with("30") && asm.ends_with("03"), "{}", asm);
        // unknown address and bad input index are wallet errors
        let other = Params::Array(vec![json!(hex), json!("not-an-address"), json!(0)]);
        assert_eq!(
            rpc_code(rpc.sign_transaction_with_address_key(&other).unwrap_err()),
            codes::WALLET_ERROR
        );
        let oob = Params::Array(vec![json!(hex), json!(addr), json!(5)]);
        assert_eq!(
            rpc_code(rpc.sign_transaction_with_address_key(&oob).unwrap_err()),
            codes::WALLET_ERROR
        );
    }

    /// loadwallet used to say "restart IronDivi with the -wallet=<filename> option", but
    /// irondivid's option is --wallet=<directory>. The refusal must name the real option
    /// and the wallet in use, and must not switch or create anything.
    #[test]
    fn loadwallet_refusal_names_the_real_option_and_current_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_dir = dir.path().join("w");
        let hd = HdWallet::new(ChainMode::Divi).unwrap();
        let db = WalletDb::create_persistent(&wallet_dir, Network::Testnet, hd).unwrap();
        let rpc = WalletRpc::with_wallet(Arc::new(db));
        let before = rpc.get_wallet_info(&Params::None).unwrap();
        let p = Params::Array(vec![serde_json::json!("heir.dat")]);
        let err = rpc.load_wallet(&p).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--wallet="), "{msg}");
        assert!(!msg.contains("-wallet=<filename>"), "{msg}");
        assert!(msg.contains(&wallet_dir.display().to_string()), "{msg}");
        assert!(msg.contains("heir.dat"), "{msg}");
        assert_eq!(rpc_code(err), codes::WALLET_ERROR);
        assert!(!dir.path().join("heir.dat").exists());
        assert_eq!(rpc.get_wallet_info(&Params::None).unwrap(), before);

        let msg = WalletRpc::new().load_wallet(&p).unwrap_err().to_string();
        assert!(
            msg.contains("without a wallet") && msg.contains("--wallet="),
            "{msg}"
        );
    }

    #[test]
    fn encryptwallet_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let hd = HdWallet::new(ChainMode::Divi).unwrap();
        let db = WalletDb::create_persistent(&dir.path().join("w"), Network::Testnet, hd).unwrap();
        let rpc = WalletRpc::with_wallet(Arc::new(db));
        let p = |v: &[&str]| Params::Array(v.iter().map(|s| serde_json::json!(s)).collect());

        // Unencrypted: unlock/lock/change are wrong-state errors, status is unencrypted
        let info = rpc.get_wallet_info(&Params::None).unwrap();
        assert_eq!(info["encryption_status"], "unencrypted");
        assert_eq!(
            rpc_code(rpc.wallet_passphrase_change(&p(&["a", "b"])).unwrap_err()),
            codes::WALLET_WRONG_ENC_STATE
        );

        assert!(rpc.encrypt_wallet(&p(&["secret pass"])).is_ok());
        assert_eq!(
            rpc.get_wallet_info(&Params::None).unwrap()["encryption_status"],
            "locked"
        );
        // Second encryption is refused
        assert_eq!(
            rpc_code(rpc.encrypt_wallet(&p(&["again"])).unwrap_err()),
            codes::WALLET_WRONG_ENC_STATE
        );
        // A locked wallet hands out new addresses from its keypool, as Divi Core
        assert!(rpc.get_new_address(&Params::None).is_ok());

        // Wrong passphrase, then right one
        let unlock = |pass: &str| {
            rpc.wallet_passphrase(&Params::Array(vec![
                serde_json::json!(pass),
                serde_json::json!(60),
            ]))
        };
        assert_eq!(
            rpc_code(unlock("wrong").unwrap_err()),
            codes::WALLET_PASSPHRASE_INCORRECT
        );
        unlock("secret pass").unwrap();
        assert_eq!(
            rpc.get_wallet_info(&Params::None).unwrap()["encryption_status"],
            "unlocked"
        );
        assert!(rpc.get_new_address(&Params::None).is_ok());

        // Change passphrase: wrong old fails, right old works, old no longer unlocks
        assert_eq!(
            rpc_code(
                rpc.wallet_passphrase_change(&p(&["nope", "x"]))
                    .unwrap_err()
            ),
            codes::WALLET_PASSPHRASE_INCORRECT
        );
        rpc.wallet_passphrase_change(&p(&["secret pass", "other pass"]))
            .unwrap();
        rpc.wallet_lock(&Params::None).unwrap();
        assert!(unlock("secret pass").is_err());
        unlock("other pass").unwrap();
    }

    #[test]
    fn baretxid_differs_from_txid_for_signed_tx() {
        // Mirrors Core's BareTxid_tests.cpp: the bare txid is the hash of the tx
        // with every scriptSig cleared, so it must survive signing unchanged
        // while the real txid changes as soon as a scriptSig is filled in.
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

        let mut tx = Transaction::new();
        tx.vin.push(TxIn::new(
            OutPoint::new(Hash256::from_bytes([9u8; 32]), 0),
            Script::new(),
            0xffff_ffff,
        ));
        tx.vout.push(TxOut::new(
            Amount::from_divi(1),
            Script::new_p2pkh(&[3u8; 20]),
        ));

        // Unsigned: scriptSig is already empty, so txid and baretxid coincide.
        let unsigned_txid = tx.txid();
        let unsigned_bare = bare_txid(&tx);
        assert_eq!(unsigned_bare, unsigned_txid);

        // Sign by filling in a scriptSig, as a signer would just before broadcast.
        tx.vin[0].script_sig = Script::from_bytes(vec![0x47, 0x30, 0x44, 0x02, 0x20, 0xaa]);
        let signed_txid = tx.txid();
        let signed_bare = bare_txid(&tx);

        assert_ne!(
            signed_txid, signed_bare,
            "signing must change txid but not baretxid"
        );
        assert_eq!(
            signed_bare, unsigned_bare,
            "baretxid must stay stable across signing"
        );

        // RPC wiring: decode_raw_transaction must surface the distinct values.
        let rpc = create_test_wallet_rpc();
        let params = Params::Array(vec![serde_json::json!(hex::encode(serialize(&tx)))]);
        let decoded = rpc.decode_raw_transaction(&params).unwrap();
        assert_eq!(decoded["txid"].as_str().unwrap(), signed_txid.to_string());
        assert_eq!(
            decoded["baretxid"].as_str().unwrap(),
            unsigned_bare.to_string()
        );
        assert_ne!(decoded["txid"], decoded["baretxid"]);

        // A different scriptSig over the same unsigned content must land on the
        // same baretxid too (it only commits to prevout/sequence/vout/version/locktime).
        tx.vin[0].script_sig = Script::from_bytes(vec![0x48, 0x30, 0x45, 0x02, 0x21, 0xbb, 0xcc]);
        assert_eq!(bare_txid(&tx), unsigned_bare);
    }

    #[test]
    fn baretxid_equals_txid_for_coinbase() {
        // Core special-cases coinbase: it has no real signature, but clearing
        // its scriptSig anyway could collide two distinct coinbases on one
        // bare txid, so Core defines the coinbase bare txid as the normal txid.
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{Transaction, TxIn, TxOut};

        let mut tx = Transaction::new();
        tx.vin.push(TxIn::coinbase(Script::from_bytes(vec![
            0x04, 0xff, 0xff, 0x00, 0x1d,
        ])));
        tx.vout
            .push(TxOut::new(Amount::from_divi(50), Script::new()));

        assert_eq!(bare_txid(&tx), tx.txid());

        // Changing the coinbase scriptSig (height/extranonce) must still move
        // the bare txid, unlike the non-coinbase case.
        let txid_before = tx.txid();
        tx.vin[0].script_sig = Script::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d, 0x01]);
        assert_ne!(bare_txid(&tx), txid_before);
    }

    #[test]
    fn test_decode_raw_transaction_keeps_fractional_value() {
        // Core prints ValueFromAmount (decimal DIVI) plus valueSat; truncating to
        // whole DIVI hid the 0.4023402 of change from the 1,000 DIVI send.
        use divi_primitives::script::Script;
        use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

        let mut tx = Transaction::new();
        tx.vin.push(TxIn::new(
            OutPoint::new(Hash256::from_bytes([7u8; 32]), 0),
            Script::new(),
            0xffff_ffff,
        ));
        tx.vout.push(TxOut::new(
            Amount::from_sat(9_072_940_234_020),
            Script::new_p2pkh(&[1u8; 20]),
        ));
        tx.vout.push(TxOut::new(
            Amount::from_sat(3_000),
            Script::new_p2pkh(&[2u8; 20]),
        ));

        let rpc = create_test_wallet_rpc();
        let params = Params::Array(vec![serde_json::json!(hex::encode(serialize(&tx)))]);
        let result = rpc.decode_raw_transaction(&params).unwrap();

        assert_eq!(result["vout"][0]["value"].as_f64().unwrap(), 90_729.4023402);
        assert_eq!(
            result["vout"][0]["valueSat"].as_i64().unwrap(),
            9_072_940_234_020
        );
        assert_eq!(result["vout"][1]["value"].as_f64().unwrap(), 0.00003);
        assert_eq!(result["vout"][1]["valueSat"].as_i64().unwrap(), 3_000);
    }

    #[test]
    fn test_create_raw_transaction_rounds_amount_like_core() {
        // 0.29 * 1e8 is 28999999.999999996; Core's roundint64 gives 29,000,000.
        let rpc = create_test_wallet_rpc();
        let addr = rpc.get_new_address(&Params::None).unwrap();
        let addr = addr.as_str().unwrap();

        let params = Params::Array(vec![
            serde_json::json!([{ "txid": "07".repeat(32), "vout": 0 }]),
            serde_json::json!({ addr: 0.29 }),
        ]);
        let hex = rpc.create_raw_transaction(&params).unwrap();
        let decoded = rpc
            .decode_raw_transaction(&Params::Array(vec![hex]))
            .unwrap();

        assert_eq!(decoded["vout"][0]["valueSat"].as_i64().unwrap(), 29_000_000);
    }

    #[test]
    fn test_amount_from_value_matches_core_validation() {
        use serde_json::json;

        assert_eq!(
            amount_from_value(&json!(19.99), false).unwrap().as_sat(),
            1_999_000_000
        );
        assert_eq!(
            amount_from_value(&json!(5), false).unwrap().as_sat(),
            500_000_000
        );
        // Zero is only allowed where Core passes allowZero (createrawtransaction).
        assert!(amount_from_value(&json!(0), false).is_err());
        assert!(amount_from_value(&json!(0), true).unwrap().is_zero());
        // Rounds to zero, so it is rejected like a literal zero.
        assert!(amount_from_value(&json!(0.000000001), false).is_err());
        assert!(amount_from_value(&json!(-1), true).is_err());
        assert!(amount_from_value(&json!(MAX_MONEY.as_divi() + 1), true).is_err());
        assert!(amount_from_value(&json!("0.29"), true).is_err());
    }

    #[test]
    fn test_get_new_address() {
        let rpc = create_test_wallet_rpc();
        let result = rpc.get_new_address(&Params::None).unwrap();

        let addr = result.as_str().unwrap();
        assert!(addr.starts_with('D')); // Mainnet address
    }

    #[test]
    fn test_validate_address() {
        let rpc = create_test_wallet_rpc();

        // Generate an address first
        let addr = rpc.get_new_address(&Params::None).unwrap();
        let addr_str = addr.as_str().unwrap();

        // Validate it
        let params = Params::Array(vec![serde_json::json!(addr_str)]);
        let result = rpc.validate_address(&params).unwrap();

        assert_eq!(result["isvalid"], true);
        assert_eq!(result["ismine"], true);
    }

    #[test]
    fn test_validate_invalid_address() {
        let rpc = create_test_wallet_rpc();
        let params = Params::Array(vec![serde_json::json!("invalid")]);
        let result = rpc.validate_address(&params).unwrap();

        assert_eq!(result["isvalid"], false);
    }

    #[test]
    fn test_get_balance() {
        let rpc = create_test_wallet_rpc();
        let result = rpc.get_balance(&Params::None).unwrap();

        assert_eq!(result.as_f64().unwrap(), 0.0);
    }

    #[test]
    fn test_list_unspent() {
        let rpc = create_test_wallet_rpc();
        let result = rpc.list_unspent(&Params::None).unwrap();

        let list = result.as_array().unwrap();
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_list_transactions() {
        let rpc = create_test_wallet_rpc();
        let result = rpc.list_transactions(&Params::None).unwrap();

        let list = result.as_array().unwrap();
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_get_wallet_info() {
        let rpc = create_test_wallet_rpc();
        let result = rpc.get_wallet_info(&Params::None).unwrap();

        assert_eq!(result["balance"], 0.0);
        assert_eq!(result["unconfirmed_balance"], 0.0);

        // Verify keypoolsize is a number
        let keypool_size = result["keypoolsize"].as_u64();
        assert!(keypool_size.is_some());

        // Verify hdmasterkeyid is a hex string (empty or 40 chars for 20-byte hash)
        let hd_master_key_id = result["hdmasterkeyid"].as_str();
        assert!(hd_master_key_id.is_some());
        let key_id_str = hd_master_key_id.unwrap();
        assert!(key_id_str.is_empty() || key_id_str.len() == 40);
        if !key_id_str.is_empty() {
            // Should be valid hex
            assert!(key_id_str.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // Verify keypoololdest is a timestamp
        let keypool_oldest = result["keypoololdest"].as_u64();
        assert!(keypool_oldest.is_some());
    }

    #[test]
    fn test_account_commands() {
        let rpc = create_test_wallet_rpc();

        let addr1_result = rpc.get_new_address(&Params::None).unwrap();
        let addr1 = addr1_result.as_str().unwrap();

        let account_result = rpc
            .get_account(&Params::Array(vec![serde_json::json!(addr1)]))
            .unwrap();
        assert_eq!(account_result.as_str().unwrap(), "");

        let _ = rpc
            .set_account(&Params::Array(vec![
                serde_json::json!(addr1),
                serde_json::json!("testaccount"),
            ]))
            .unwrap();

        let account_result = rpc
            .get_account(&Params::Array(vec![serde_json::json!(addr1)]))
            .unwrap();
        assert_eq!(account_result.as_str().unwrap(), "testaccount");

        let addresses = rpc
            .get_addresses_by_account(&Params::Array(vec![serde_json::json!("testaccount")]))
            .unwrap();
        let addr_list = addresses.as_array().unwrap();
        assert_eq!(addr_list.len(), 1);
        assert_eq!(addr_list[0].as_str().unwrap(), addr1);

        let account_addr = rpc
            .get_account_address(&Params::Array(vec![serde_json::json!("testaccount")]))
            .unwrap();
        assert_eq!(account_addr.as_str().unwrap(), addr1);

        let accounts = rpc.list_accounts(&Params::None).unwrap();
        let accounts_obj = accounts.as_object().unwrap();
        assert!(accounts_obj.contains_key("testaccount"));
        assert_eq!(accounts_obj["testaccount"], 0.0);

        let received = rpc
            .get_received_by_account(&Params::Array(vec![serde_json::json!("testaccount")]))
            .unwrap();
        assert_eq!(received.as_f64().unwrap(), 0.0);

        let received_list = rpc
            .list_received_by_account(&Params::Array(vec![
                serde_json::json!(1),
                serde_json::json!(true),
            ]))
            .unwrap();
        // getnewaddress put the account-address under "" as well, as Divi Core
        let list = received_list.as_array().unwrap();
        let entry: Vec<_> = list
            .iter()
            .filter(|e| e["account"] == "testaccount")
            .collect();
        assert_eq!(entry.len(), 1);
        assert_eq!(entry[0]["amount"], 0.0);
    }

    #[test]
    fn test_decode_script_p2pkh() {
        let rpc = create_test_wallet_rpc();

        // Standard P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        // 76a914<hash160>88ac
        let p2pkh_script = "76a914000102030405060708090a0b0c0d0e0f1011121388ac";

        let result = rpc
            .decode_script(&Params::Array(vec![serde_json::json!(p2pkh_script)]))
            .unwrap();

        assert!(result.is_object());
        assert_eq!(result["type"], "pubkeyhash");
        assert!(result["hex"].as_str().unwrap() == p2pkh_script);
        assert!(result["asm"].as_str().is_some());
        assert!(result["addresses"].is_array());
        let addrs = result["addresses"].as_array().unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].as_str().unwrap().starts_with('D')); // Mainnet address
        assert_eq!(result["reqSigs"], 1);
        assert!(result["p2sh"].as_str().is_some()); // P2SH of this script
    }

    #[test]
    fn test_decode_script_p2sh() {
        let rpc = create_test_wallet_rpc();

        // Standard P2SH script: OP_HASH160 <20 bytes> OP_EQUAL
        // a914<hash160>87
        let p2sh_script = "a914000102030405060708090a0b0c0d0e0f1011121387";

        let result = rpc
            .decode_script(&Params::Array(vec![serde_json::json!(p2sh_script)]))
            .unwrap();

        assert!(result.is_object());
        assert_eq!(result["type"], "scripthash");
        assert!(result["addresses"].is_array());
        let addrs = result["addresses"].as_array().unwrap();
        assert_eq!(addrs.len(), 1);
        // P2SH addresses with version byte 13 start with '6' on Divi mainnet
        let addr = addrs[0].as_str().unwrap();
        assert!(
            addr.starts_with('6'),
            "P2SH address should start with '6', got: {}",
            addr
        );
        assert_eq!(result["reqSigs"], 1);
    }

    #[test]
    fn test_decode_script_nulldata() {
        let rpc = create_test_wallet_rpc();

        // OP_RETURN data script: OP_RETURN <data>
        // 6a0568656c6c6f ("hello")
        let nulldata_script = "6a0568656c6c6f";

        let result = rpc
            .decode_script(&Params::Array(vec![serde_json::json!(nulldata_script)]))
            .unwrap();

        assert!(result.is_object());
        assert_eq!(result["type"], "nulldata");
        // Nulldata scripts have no addresses
        assert!(result.get("addresses").is_none());
        assert_eq!(result["reqSigs"], 0);
    }

    #[test]
    fn test_getaddressinfo_change_tracking() {
        let rpc = create_test_wallet_rpc();

        // Generate a receiving address
        let receiving_addr_result = rpc.get_new_address(&Params::None).unwrap();
        let receiving_addr = receiving_addr_result.as_str().unwrap();

        // Generate a change address directly through the wallet manager
        let wallet = rpc.get_wallet().unwrap();
        let change_addr = wallet.new_change_address().unwrap();

        // Test receiving address - should have ischange=false
        let params = Params::Array(vec![serde_json::json!(receiving_addr)]);
        let result = rpc.get_address_info(&params).unwrap();

        assert_eq!(result["address"], receiving_addr);
        assert_eq!(result["ismine"], true);
        assert_eq!(
            result["ischange"], false,
            "Receiving address should have ischange=false"
        );

        // Test change address - should have ischange=true
        let params = Params::Array(vec![serde_json::json!(change_addr.to_string())]);
        let result = rpc.get_address_info(&params).unwrap();

        assert_eq!(result["address"], change_addr.to_string());
        assert_eq!(result["ismine"], true);
        assert_eq!(
            result["ischange"], true,
            "Change address should have ischange=true"
        );
    }

    #[test]
    fn test_getaddressinfo_hdkeypath() {
        let rpc = create_test_wallet_rpc();

        // Generate a receiving address (should have HD path m/44'/301'/0'/0/0)
        let receiving_addr_result = rpc.get_new_address(&Params::None).unwrap();
        let receiving_addr = receiving_addr_result.as_str().unwrap();

        // Generate a change address (should have HD path m/44'/301'/0'/1/0)
        let wallet = rpc.get_wallet().unwrap();
        let change_addr = wallet.new_change_address().unwrap();

        // Test receiving address - should have hdkeypath with /0/ (receiving chain)
        let params = Params::Array(vec![serde_json::json!(receiving_addr)]);
        let result = rpc.get_address_info(&params).unwrap();

        assert_eq!(result["address"], receiving_addr);
        assert!(
            result.get("hdkeypath").is_some(),
            "HD-derived address should have hdkeypath field"
        );
        let hdkeypath = result["hdkeypath"].as_str().unwrap();
        assert!(
            hdkeypath.starts_with("m/44'/301'/0'/0/"),
            "Receiving address should have /0/ in path"
        );

        // Test change address - should have hdkeypath with /1/ (change chain)
        let params = Params::Array(vec![serde_json::json!(change_addr.to_string())]);
        let result = rpc.get_address_info(&params).unwrap();

        assert_eq!(result["address"], change_addr.to_string());
        assert!(
            result.get("hdkeypath").is_some(),
            "HD-derived address should have hdkeypath field"
        );
        let hdkeypath = result["hdkeypath"].as_str().unwrap();
        assert!(
            hdkeypath.starts_with("m/44'/301'/0'/1/"),
            "Change address should have /1/ in path"
        );

        // Test imported non-HD key - should not have hdkeypath
        use divi_crypto::keys::SecretKey;
        let imported_key = SecretKey::new_random();
        let imported_addr = wallet.import_key(imported_key, None);

        let params = Params::Array(vec![serde_json::json!(imported_addr.to_string())]);
        let result = rpc.get_address_info(&params).unwrap();

        assert_eq!(result["address"], imported_addr.to_string());
        assert!(
            result.get("hdkeypath").is_none(),
            "Imported non-HD key should not have hdkeypath field"
        );
    }

    /// A change key made by sendtoaddress must be on disk before the call returns:
    /// lock right after the send and restart, with no block in between.
    #[test]
    fn test_send_change_key_survives_lock_and_restart() {
        use divi_wallet::wallet_db::WalletUtxo;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let p = |v: Vec<serde_json::Value>| Params::Array(v);
        {
            let hd = HdWallet::from_mnemonic(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                None,
                ChainMode::Divi,
            )
            .unwrap();
            let wallet = WalletDb::create_persistent(&path, Network::Regtest, hd).unwrap();
            wallet.save().unwrap();
            wallet.encrypt_wallet("pw").unwrap();
            wallet.unlock("pw", 60).unwrap();
            let funding = wallet.new_receiving_address().unwrap();
            wallet.save().unwrap();
            wallet.lock();
            let mut utxo = WalletUtxo::new(
                Hash256::from_bytes([7u8; 32]),
                0,
                Amount::from_divi(100),
                Script::from_bytes(
                    hex::decode(format!(
                        "76a914{}88ac",
                        hex::encode(funding.hash.as_bytes())
                    ))
                    .unwrap(),
                ),
                funding.to_string(),
            );
            utxo.height = Some(1);
            wallet.add_utxo(utxo);

            let rpc = WalletRpc::with_wallet(Arc::new(wallet));
            rpc.set_height(10);
            rpc.set_tx_submit(Arc::new(|tx: Transaction| Ok(tx.txid())));
            rpc.wallet_passphrase(&p(vec![json!("pw"), json!(60)]))
                .unwrap();
            let dest = Address::p2pkh(
                &divi_crypto::keys::SecretKey::new_random().public_key(),
                Network::Regtest,
            );
            rpc.send_to_address(&p(vec![json!(dest.to_string()), json!(1.0)]))
                .unwrap();
            rpc.wallet_lock(&Params::None).unwrap();
        }

        let wallet = Arc::new(WalletDb::open(&path, Network::Regtest).unwrap());
        // The keypool holds change keys too; take the one handed out
        let (_, issued) = wallet.keystore().get_indices();
        assert_eq!(issued, 1);
        let change: Vec<Address> = wallet
            .get_addresses()
            .into_iter()
            .filter(|a| wallet.is_change_address(a))
            .filter(|a| {
                wallet
                    .get_key_by_address(a)
                    .and_then(|e| e.hd_path)
                    .is_some_and(|path| path.ends_with("/1/0"))
            })
            .collect();
        assert_eq!(change.len(), 1, "change key not stored");
        let rpc = WalletRpc::with_wallet(wallet);
        let info = rpc
            .validate_address(&p(vec![json!(change[0].to_string())]))
            .unwrap();
        assert_eq!(info["ismine"], true);
        assert_eq!(info["iswatchonly"], false);
        rpc.wallet_passphrase(&p(vec![json!("pw"), json!(60)]))
            .unwrap();
        let wif = rpc
            .dump_privkey(&p(vec![json!(change[0].to_string())]))
            .unwrap();
        assert!(!wif.as_str().unwrap().is_empty());
    }
}

/// Regressions for send checks and wallet unlock state.
/// Only public RPC entry points are used, so the same tests run on older trees.
#[cfg(test)]
mod send_unlock_regression {
    use super::*;
    use divi_primitives::ChainMode;
    use divi_wallet::HdWallet;

    fn rpc_on(network: Network) -> (WalletRpc, Arc<WalletDb>) {
        let db = Arc::new(WalletDb::with_hd_wallet(
            network,
            HdWallet::new(ChainMode::Divi).unwrap(),
        ));
        (WalletRpc::with_wallet(db.clone()), db)
    }

    fn p(values: Vec<serde_json::Value>) -> Params {
        Params::Array(values)
    }

    fn err(result: Result<serde_json::Value, Error>) -> (i32, String) {
        match result {
            Err(Error::Rpc(r)) => (r.code, r.message),
            other => panic!("expected an RPC error, got {:?}", other),
        }
    }

    fn address(hash: u8, network: Network) -> String {
        Address::from_pubkey_hash(Hash160::from_bytes([hash; 20]), network).to_base58()
    }

    type Sent = Arc<parking_lot::Mutex<Vec<Transaction>>>;

    /// Testnet wallet holding one confirmed 10 DIVI coin; submitted txs are captured
    fn funded_rpc() -> (WalletRpc, Arc<WalletDb>, Sent) {
        let (rpc, db) = rpc_on(Network::Testnet);
        let sent = fund(&rpc, &db);
        (rpc, db, sent)
    }

    fn fund(rpc: &WalletRpc, db: &WalletDb) -> Sent {
        let addr = db.new_receiving_address().unwrap();
        db.add_utxo(divi_wallet::WalletUtxo {
            txid: Hash256::from_bytes([3; 32]),
            vout: 0,
            value: Amount::from_divi(10),
            script_pubkey: Script::new_p2pkh(addr.hash.as_bytes()),
            height: Some(100),
            is_coinbase: false,
            is_coinstake: false,
            address: addr.to_string(),
        });
        rpc.set_height(200);
        let sent: Sent = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let capture = sent.clone();
        rpc.set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            capture.lock().push(tx);
            Ok(txid)
        }));
        sent
    }

    const PASS: &str = "throwaway test passphrase";

    /// Encrypted (so locked) persistent testnet wallet with one coin
    fn encrypted_rpc() -> (tempfile::TempDir, WalletRpc, Arc<WalletDb>, Sent) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            WalletDb::create_persistent(
                &dir.path().join("w"),
                Network::Testnet,
                HdWallet::new(ChainMode::Divi).unwrap(),
            )
            .unwrap(),
        );
        let rpc = WalletRpc::with_wallet(db.clone());
        let sent = fund(&rpc, &db);
        rpc.encrypt_wallet(&p(vec![json!(PASS)])).unwrap();
        (dir, rpc, db, sent)
    }

    fn status(rpc: &WalletRpc) -> String {
        rpc.get_wallet_info(&Params::None).unwrap()["encryption_status"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn unlock(
        rpc: &WalletRpc,
        timeout: u64,
        staking_only: bool,
    ) -> Result<serde_json::Value, Error> {
        rpc.wallet_passphrase(&p(vec![json!(PASS), json!(timeout), json!(staking_only)]))
    }

    #[test]
    fn staking_only_unlock_refuses_sends_and_exports() {
        let (_dir, rpc, db, sent) = encrypted_rpc();
        assert_eq!(status(&rpc), "locked", "wallet should start locked");

        unlock(&rpc, 0, true).unwrap();
        assert_eq!(status(&rpc), "unlocked-for-staking");
        assert!(!db.is_locked(), "staking needs the keys in memory");

        let to = address(8, Network::Testnet);
        let own = rpc.get_new_address(&Params::None).unwrap();
        let need_unlock = codes::WALLET_UNLOCK_NEEDED;
        assert_eq!(
            err(rpc.send_to_address(&p(vec![json!(to), json!(1.0)]))).0,
            need_unlock
        );
        assert_eq!(
            err(rpc.send_from(&p(vec![json!(""), json!(to), json!(1.0)]))).0,
            need_unlock
        );
        assert_eq!(err(rpc.dump_privkey(&p(vec![own.clone()]))).0, need_unlock);
        assert_eq!(err(rpc.dump_hd_info(&Params::None)).0, need_unlock);
        assert_eq!(
            err(rpc.sign_message(&p(vec![own, json!("hello")]))).0,
            need_unlock
        );
        assert!(sent.lock().is_empty());

        // Divi Core: a second staking-only unlock is -17
        assert_eq!(err(unlock(&rpc, 0, true)).0, codes::WALLET_ALREADY_UNLOCKED);

        // A full unlock allows the send
        unlock(&rpc, 0, false).unwrap();
        assert_eq!(status(&rpc), "unlocked");
        rpc.send_to_address(&p(vec![json!(to), json!(1.0)]))
            .unwrap();
        assert_eq!(sent.lock().len(), 1);
    }

    #[test]
    fn hdmasterkeyid_shown_while_locked() {
        let (_dir, rpc, _db, _sent) = encrypted_rpc();
        assert_eq!(status(&rpc), "locked");
        let locked = rpc.get_wallet_info(&Params::None).unwrap()["hdmasterkeyid"].clone();
        unlock(&rpc, 0, false).unwrap();
        let unlocked = rpc.get_wallet_info(&Params::None).unwrap()["hdmasterkeyid"].clone();
        assert_ne!(unlocked, json!(""));
        assert_eq!(locked, unlocked);
    }

    #[test]
    fn short_unlock_falls_back_to_staking_only() {
        let (_dir, rpc, db, _sent) = encrypted_rpc();
        unlock(&rpc, 0, true).unwrap();
        unlock(&rpc, 1, false).unwrap();
        assert_eq!(status(&rpc), "unlocked");
        std::thread::sleep(std::time::Duration::from_millis(1300));
        assert_eq!(status(&rpc), "unlocked-for-staking");
        assert!(
            !db.is_locked(),
            "staking stopped when the short unlock ended"
        );

        // Without a staking unlock before it, a timed unlock ends locked
        rpc.wallet_lock(&Params::None).unwrap();
        assert_eq!(status(&rpc), "locked");
        unlock(&rpc, 1, false).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1300));
        assert_eq!(status(&rpc), "locked");
        assert!(db.is_locked());
    }

    fn dust_error() -> (i32, String) {
        (
            codes::WALLET_ERROR,
            "Transaction output(s) amount too small".into(),
        )
    }

    #[test]
    fn dust_send_is_refused_before_anything_is_submitted() {
        let (rpc, _, sent) = funded_rpc();
        let to = address(8, Network::Testnet);
        // The testnet send that was accepted and never relayed, and Divi Core's refusal
        for amount in [0.000001, 0.00001] {
            assert_eq!(
                err(rpc.send_to_address(&p(vec![json!(to), json!(amount)]))),
                dust_error(),
                "sendtoaddress {}",
                amount
            );
            assert_eq!(
                err(rpc.send_from(&p(vec![json!(""), json!(to), json!(amount)]))),
                dust_error(),
                "sendfrom {}",
                amount
            );
            let mut outputs = serde_json::Map::new();
            outputs.insert(to.clone(), json!(amount));
            assert_eq!(
                err(rpc.send_many(&p(vec![json!(""), serde_json::Value::Object(outputs)]))),
                dust_error(),
                "sendmany {}",
                amount
            );
        }
        assert!(sent.lock().is_empty(), "a dust send reached the mempool");

        // Divi Core accepts 0.0000546 (5460 sat, the P2PKH dust limit)
        rpc.send_to_address(&p(vec![json!(to), json!(0.0000546)]))
            .unwrap();
        assert_eq!(sent.lock().len(), 1);
    }

    /// A send that needs many inputs must still pay the relay minimum
    /// (10000 sat/kB) for its real size, or no node relays it
    #[test]
    fn many_input_send_pays_relay_fee() {
        let (rpc, db) = rpc_on(Network::Testnet);
        for i in 0..12u8 {
            let addr = db.new_receiving_address().unwrap();
            db.add_utxo(divi_wallet::WalletUtxo {
                txid: Hash256::from_bytes([40 + i; 32]),
                vout: 0,
                value: Amount::from_divi(1),
                script_pubkey: Script::new_p2pkh(addr.hash.as_bytes()),
                height: Some(100),
                is_coinbase: false,
                is_coinstake: false,
                address: addr.to_string(),
            });
        }
        rpc.set_height(200);
        let sent: Sent = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let capture = sent.clone();
        rpc.set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            capture.lock().push(tx);
            Ok(txid)
        }));
        let to = address(8, Network::Testnet);
        rpc.send_to_address(&p(vec![json!(to), json!(11.5)]))
            .unwrap();
        let sent = sent.lock();
        let tx = &sent[0];
        assert_eq!(tx.vin.len(), 12);
        let out: i64 = tx.vout.iter().map(|o| o.value.as_sat()).sum();
        let fee = 12 * 100_000_000 - out;
        let min = DEFAULT_MIN_RELAY_FEE_PER_KB * tx.size() as i64 / 1000;
        assert!(
            fee >= min,
            "fee {} sat for {} bytes is below the relay minimum {}",
            fee,
            tx.size(),
            min
        );
    }

    /// Mempool refusals reach the RPC as Divi Core's sendrawtransaction errors
    #[test]
    fn submit_errors_use_divi_core_codes() {
        let cases = [
            (
                TxSubmitError::Rejected {
                    code: 64,
                    reason: "dust".into(),
                },
                (codes::VERIFY_REJECTED, "64: dust"),
            ),
            (
                TxSubmitError::Rejected {
                    code: 66,
                    reason: "insufficient fee".into(),
                },
                (codes::VERIFY_REJECTED, "66: insufficient fee"),
            ),
            (
                TxSubmitError::UnknownInputs,
                (codes::VERIFY_REJECTED, "Unknown inputs being spent"),
            ),
            (
                TxSubmitError::Failed("boom".into()),
                (codes::VERIFY_ERROR, "boom"),
            ),
        ];
        for (error, (want_code, want_message)) in cases {
            let (rpc, _) = rpc_on(Network::Testnet);
            rpc.set_tx_submit(Arc::new(move |_tx: Transaction| Err(error.clone())));
            let tx = Transaction {
                version: 1,
                vin: vec![],
                vout: vec![],
                lock_time: 0,
            };
            let hex = hex::encode(serialize(&tx));
            assert_eq!(
                err(rpc.send_raw_transaction(&p(vec![json!(hex)]))),
                (want_code, want_message.to_string())
            );
        }
    }

    /// Passphrase RPC errors use Divi Core's codes and texts (rpcwallet.cpp)
    #[test]
    fn passphrase_errors_match_divi_core() {
        let (rpc, _) = rpc_on(Network::Testnet);
        let unencrypted = |call: &str| {
            format!(
                "Error: running with an unencrypted wallet, but {} was called.",
                call
            )
        };
        assert_eq!(
            err(rpc.wallet_passphrase(&p(vec![json!("x"), json!(60)]))),
            (
                codes::WALLET_WRONG_ENC_STATE,
                unencrypted("walletpassphrase")
            )
        );
        assert_eq!(
            err(rpc.wallet_lock(&Params::None)),
            (codes::WALLET_WRONG_ENC_STATE, unencrypted("walletlock"))
        );
        assert_eq!(
            err(rpc.wallet_passphrase_change(&p(vec![json!("a"), json!("b")]))),
            (
                codes::WALLET_WRONG_ENC_STATE,
                unencrypted("walletpassphrasechange")
            )
        );
        assert_eq!(
            err(rpc.encrypt_wallet(&p(vec![json!("")]))),
            (
                codes::MISC_ERROR,
                "encryptwallet <passphrase>\nEncrypts the wallet with <passphrase>.".to_string()
            )
        );

        let (_dir, rpc, _db, _sent) = encrypted_rpc();
        let incorrect = (
            codes::WALLET_PASSPHRASE_INCORRECT,
            "Error: The wallet passphrase entered was incorrect.".to_string(),
        );
        assert_eq!(
            err(rpc.wallet_passphrase(&p(vec![json!("not it"), json!(60)]))),
            incorrect
        );
        assert_eq!(
            err(rpc.wallet_passphrase_change(&p(vec![json!("not it"), json!("new")]))),
            incorrect
        );
    }

    #[test]
    fn change_below_dust_goes_to_fee() {
        let (rpc, _, sent) = funded_rpc();
        let to = address(8, Network::Testnet);
        // 10 DIVI in. Divi Core's selection needs the payment, 5,460 sat of
        // room for change and the 440 + 1,480 sat input estimate: this amount
        // just fits, and the 5,120 sat left (below the 5,460 dust limit once
        // the 340 sat change estimate is paid) goes to the fee.
        let amount = (1_000_000_000i64 - 7_380) as f64 / 100_000_000.0;
        rpc.send_to_address(&p(vec![json!(to), json!(amount)]))
            .unwrap();
        let sent = sent.lock();
        assert_eq!(sent.len(), 1);
        for out in &sent[0].vout {
            assert!(
                out.value.as_sat() >= 5460,
                "dust output of {} sat",
                out.value.as_sat()
            );
        }
    }

    #[test]
    fn validateaddress_rejects_other_network() {
        let (rpc, _) = rpc_on(Network::Testnet);
        let mainnet = address(7, Network::Mainnet);
        let testnet = address(7, Network::Testnet);
        let r = rpc.validate_address(&p(vec![json!(mainnet)])).unwrap();
        assert_eq!(r["isvalid"], false, "mainnet-form address on testnet");
        let r = rpc.validate_address(&p(vec![json!(testnet)])).unwrap();
        assert_eq!(r["isvalid"], true);

        let (rpc, _) = rpc_on(Network::Mainnet);
        let r = rpc.validate_address(&p(vec![json!(testnet)])).unwrap();
        assert_eq!(r["isvalid"], false, "testnet-form address on mainnet");
        let r = rpc.validate_address(&p(vec![json!(mainnet)])).unwrap();
        assert_eq!(r["isvalid"], true);

        // Regtest uses the testnet prefixes
        let (rpc, _) = rpc_on(Network::Regtest);
        let r = rpc.validate_address(&p(vec![json!(testnet)])).unwrap();
        assert_eq!(r["isvalid"], true);
        let r = rpc.validate_address(&p(vec![json!(mainnet)])).unwrap();
        assert_eq!(r["isvalid"], false);
    }

    #[test]
    fn sendtoaddress_rejects_mainnet_address_on_testnet() {
        let (rpc, _) = rpc_on(Network::Testnet);
        let mainnet = address(7, Network::Mainnet);
        assert_eq!(
            err(rpc.send_to_address(&p(vec![json!(mainnet), json!(1.0)]))),
            (codes::INVALID_ADDRESS_OR_KEY, "Invalid DIVI address".into())
        );
    }

    #[test]
    fn every_address_rpc_rejects_other_network() {
        let (rpc, _) = rpc_on(Network::Testnet);
        let m = address(9, Network::Mainnet);
        let mut outputs = serde_json::Map::new();
        outputs.insert(m.clone(), json!(1.0));
        let outputs = serde_json::Value::Object(outputs);
        let invalid = codes::INVALID_ADDRESS_OR_KEY;
        let cases: Vec<(&str, Result<serde_json::Value, Error>, i32)> = vec![
            (
                "sendfrom",
                rpc.send_from(&p(vec![json!(""), json!(m), json!(1.0)])),
                invalid,
            ),
            (
                "sendmany",
                rpc.send_many(&p(vec![json!(""), outputs.clone()])),
                invalid,
            ),
            (
                "createrawtransaction",
                rpc.create_raw_transaction(&p(vec![json!([]), outputs])),
                invalid,
            ),
            (
                "getreceivedbyaddress",
                rpc.get_received_by_address(&p(vec![json!(m)])),
                invalid,
            ),
            ("dumpprivkey", rpc.dump_privkey(&p(vec![json!(m)])), invalid),
            (
                "getaddressinfo",
                rpc.get_address_info(&p(vec![json!(m)])),
                invalid,
            ),
            ("getaccount", rpc.get_account(&p(vec![json!(m)])), invalid),
            (
                "setaccount",
                rpc.set_account(&p(vec![json!(m), json!("acct")])),
                invalid,
            ),
            (
                "importaddress",
                rpc.import_address(&p(vec![json!(m), json!(""), json!(false)])),
                invalid,
            ),
            (
                "bip38encrypt",
                rpc.bip38_encrypt(&p(vec![json!(m), json!("pw")])),
                invalid,
            ),
            (
                "signmessage",
                rpc.sign_message(&p(vec![json!(m), json!("hello")])),
                codes::TYPE_ERROR,
            ),
            (
                "verifymessage",
                rpc.verify_message(&p(vec![json!(m), json!("c2ln"), json!("hello")])),
                codes::TYPE_ERROR,
            ),
        ];
        for (name, result, code) in cases {
            assert_eq!(
                err(result).0,
                code,
                "{} accepted a mainnet-form address",
                name
            );
        }
    }
}

/// Wallet accounting over a real (regtest) chain: rescans, received totals,
/// UTXO filters and history amounts
#[cfg(test)]
mod accounting_tests {
    use super::*;
    use divi_primitives::block::Block;
    use divi_primitives::transaction::{TxIn, TxOut};
    use divi_primitives::ChainMode;
    use divi_storage::{ChainDatabase, ChainParams, NetworkType};
    use divi_wallet::{HdWallet, Network};
    use serde_json::json;

    const COIN: i64 = 100_000_000;

    struct Fixture {
        _dir: tempfile::TempDir,
        chain: Arc<Chain>,
        wallet: Arc<WalletDb>,
        rpc: WalletRpc,
        /// Paid by the coinbases of blocks 1-4
        miner: String,
        /// Paid 249.99 by `spend` in block 5
        second: String,
        /// Block 5's send: block 1's coin, 1000 to a stranger, 249.99 to `second`
        spend: Transaction,
    }

    fn stranger() -> Script {
        Script::new_p2pkh(&[0xaa; 20])
    }

    fn script_of(addr: &str) -> Script {
        let a = Address::from_base58(addr).unwrap();
        Script::new_p2pkh(a.hash.as_bytes())
    }

    /// Sign every input of `tx` with the wallet's keys: blocks must now
    /// carry valid scripts. The coins spent are P2PKH outputs in the chain.
    fn sign_with_wallet(wallet: &WalletDb, chain: &Chain, tx: &mut Transaction) {
        let scripts: Vec<Script> = tx
            .vin
            .iter()
            .map(|i| chain.get_utxo(&i.prevout).unwrap().unwrap().script_pubkey)
            .collect();
        let signed = divi_wallet::signer::TransactionSigner::new(wallet.keystore())
            .sign_all_inputs(tx, &scripts)
            .unwrap();
        assert_eq!(signed, tx.vin.len());
    }

    /// Mine a block on the tip: a coinbase paying `payee`, then `txs`
    fn mine(chain: &Chain, payee: Script, txs: &[Transaction]) -> Block {
        let tip = chain.tip().unwrap();
        let height = tip.height + 1;
        // BIP34: the coinbase starts with the height
        let mut sig = divi_storage::bip34_height_script(height);
        sig.extend_from_slice(&height.to_le_bytes());
        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), payee)],
            lock_time: 0,
        };
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        block.transactions.push(coinbase);
        block.transactions.extend_from_slice(txs);
        block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
        // Proof of work for the block's bits
        let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        chain.accept_block(block.clone()).unwrap();
        block
    }

    fn fixture() -> Fixture {
        fixture_with(|_| {
            let hd = HdWallet::new(ChainMode::Divi).unwrap();
            WalletDb::with_hd_wallet(Network::Regtest, hd)
        })
    }

    fn fixture_with(make_wallet: impl FnOnce(&std::path::Path) -> WalletDb) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
        let chain = Arc::new(
            Chain::new(
                db,
                ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
            )
            .unwrap(),
        );
        let wallet = Arc::new(make_wallet(dir.path()));
        let miner = wallet.new_receiving_address().unwrap().to_string();
        let second = wallet.new_receiving_address().unwrap().to_string();

        let first = mine(&chain, script_of(&miner), &[]);
        for _ in 2..=4 {
            mine(&chain, script_of(&miner), &[]);
        }
        // Regtest coinbases mature after 20 blocks: blocks 5-23 pay a stranger, so
        // at the spend (block 24) the coinbases of blocks 1-4 are mature
        for _ in 5..=23 {
            mine(&chain, stranger(), &[]);
        }
        let spend = Transaction {
            version: 1,
            vin: vec![TxIn::new(
                divi_primitives::transaction::OutPoint::new(first.transactions[0].txid(), 0),
                Script::default(),
                0xffffffff,
            )],
            vout: vec![
                TxOut::new(Amount::from_sat(1000 * COIN), stranger()),
                TxOut::new(Amount::from_sat(250 * COIN - 1_000_000), script_of(&second)),
            ],
            lock_time: 0,
        };
        let mut spend = spend;
        sign_with_wallet(&wallet, &chain, &mut spend);
        mine(&chain, stranger(), std::slice::from_ref(&spend));
        assert_eq!(chain.height(), FIXTURE_HEIGHT);

        let rpc = WalletRpc::with_wallet_and_chain(wallet.clone(), chain.clone());
        rpc.rescan_blockchain(&Params::Array(vec![])).unwrap();
        Fixture {
            _dir: dir,
            chain,
            wallet,
            rpc,
            miner,
            second,
            spend,
        }
    }

    /// Height of the fixture's spend block, its tip
    const FIXTURE_HEIGHT: u32 = 24;

    /// Balance after the fixture's blocks: three 1250 coinbases plus 249.99
    const BALANCE: i64 = 3 * 1250 * COIN + 250 * COIN - 1_000_000;

    #[test]
    fn partial_rescan_keeps_coins_below_start() {
        let f = fixture();
        assert_eq!(f.wallet.get_balance().as_sat(), BALANCE);
        assert_eq!(f.chain.height(), FIXTURE_HEIGHT);

        for start in [3, FIXTURE_HEIGHT, 1] {
            let r = f
                .rpc
                .rescan_blockchain(&Params::Array(vec![json!(start)]))
                .unwrap();
            assert_eq!(r["start_height"], json!(start));
            assert_eq!(r["stop_height"], json!(FIXTURE_HEIGHT));
            assert_eq!(
                f.wallet.get_balance().as_sat(),
                BALANCE,
                "after rescanblockchain {}",
                start
            );
        }
        // The send recorded in the spend block is still a single send
        let sent = f.wallet.get_transaction(&f.spend.txid()).unwrap();
        assert_eq!(sent.block_height, Some(FIXTURE_HEIGHT));
        assert_eq!(sent.category, "send");
    }

    #[test]
    fn partial_rescan_with_stop_keeps_coins_above_stop() {
        let f = fixture();
        f.rpc
            .rescan_blockchain(&Params::Array(vec![json!(2), json!(3)]))
            .unwrap();
        assert_eq!(f.wallet.get_balance().as_sat(), BALANCE);
        assert_eq!(f.wallet.get_utxos().len(), 4);
        assert!(f.wallet.get_utxos().iter().any(|u| u.address == f.second));
    }

    #[test]
    fn full_rescan_repair_survives_restart() {
        let f = fixture_with(|dir| {
            let hd = HdWallet::new(ChainMode::Divi).unwrap();
            WalletDb::create_persistent(&dir.join("wallet"), Network::Regtest, hd).unwrap()
        });
        f.wallet.save().unwrap();
        // A coin wrongly marked spent (e.g. by a block that was later orphaned)
        let coin = f
            .wallet
            .get_utxos()
            .into_iter()
            .find(|u| u.address == f.miner)
            .unwrap()
            .outpoint();
        f.wallet.spend_utxo(&coin).unwrap();
        f.wallet.save().unwrap();
        assert_eq!(f.wallet.get_balance().as_sat(), BALANCE - 1250 * COIN);

        f.rpc.rescan_blockchain(&Params::Array(vec![])).unwrap();
        assert_eq!(f.wallet.get_balance().as_sat(), BALANCE);

        let path = f._dir.path().join("wallet");
        drop(f.rpc);
        drop(f.wallet);
        let reopened = WalletDb::open(&path, Network::Regtest).unwrap();
        assert!(reopened.has_utxo(&coin));
        assert_eq!(reopened.get_balance().as_sat(), BALANCE);
    }

    #[test]
    fn full_rescans_agree() {
        let f = fixture();
        let utxos = |w: &WalletDb| {
            let mut v: Vec<_> = w
                .get_utxos()
                .iter()
                .map(|u| (u.outpoint(), u.value.as_sat()))
                .collect();
            v.sort_by_key(|(o, _)| (o.txid, o.vout));
            v
        };
        let before = utxos(&f.wallet);
        f.rpc.rescan_blockchain(&Params::Array(vec![])).unwrap();
        let first = utxos(&f.wallet);
        f.rpc
            .rescan_blockchain(&Params::Array(vec![json!(0)]))
            .unwrap();
        let second = utxos(&f.wallet);
        assert_eq!(first, before);
        assert_eq!(second, first);
        assert_eq!(f.wallet.get_balance().as_sat(), BALANCE);
    }

    /// Spend `second`'s 249.99 coin to a stranger in block 6 and rescan
    fn spend_second(f: &Fixture) {
        let coin = f
            .wallet
            .get_utxos()
            .into_iter()
            .find(|u| u.address == f.second)
            .unwrap();
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(coin.outpoint(), Script::default(), 0xffffffff)],
            vout: vec![TxOut::new(
                Amount::from_sat(coin.value.as_sat() - 1_000_000),
                stranger(),
            )],
            lock_time: 0,
        };
        let mut tx = tx;
        sign_with_wallet(&f.wallet, &f.chain, &mut tx);
        mine(&f.chain, stranger(), &[tx]);
        f.rpc.rescan_blockchain(&Params::Array(vec![])).unwrap();
        assert!(!f.wallet.get_utxos().iter().any(|u| u.address == f.second));
    }

    #[test]
    fn received_by_address_counts_spent_coins() {
        let f = fixture();
        spend_second(&f);
        let received = |addr: &str, minconf: u32| {
            f.rpc
                .get_received_by_address(&Params::Array(vec![json!(addr), json!(minconf)]))
                .unwrap()
        };
        // Received in block 5, spent in block 6: still received
        assert_eq!(received(&f.second, 1), json!(249.99));
        assert_eq!(received(&f.second, 2), json!(249.99));
        // Block 5 has 2 confirmations at height 6
        assert_eq!(received(&f.second, 3), json!(0.0));
        // Coinbase outputs are not counted (Core skips coinbase transactions)
        assert_eq!(received(&f.miner, 1), json!(0.0));
    }

    #[test]
    fn received_by_lists_and_accounts_count_spent_coins() {
        let f = fixture();
        f.rpc
            .set_account(&Params::Array(vec![json!(f.second), json!("savings")]))
            .unwrap();
        spend_second(&f);

        let list = f
            .rpc
            .list_received_by_address(&Params::Array(vec![json!(1)]))
            .unwrap();
        let entry = list
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["address"] == json!(f.second))
            .expect("second address listed");
        assert_eq!(entry["amount"], json!(249.99));
        assert_eq!(entry["confirmations"], json!(2));

        assert_eq!(
            f.rpc
                .get_received_by_account(&Params::Array(vec![json!("savings"), json!(1)]))
                .unwrap(),
            json!(249.99)
        );
        let accounts = f
            .rpc
            .list_received_by_account(&Params::Array(vec![json!(1)]))
            .unwrap();
        let savings = accounts
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["account"] == json!("savings"))
            .expect("savings account listed");
        assert_eq!(savings["amount"], json!(249.99));
    }

    #[test]
    fn list_unspent_filters_by_address() {
        let f = fixture();
        let list = |params: Vec<serde_json::Value>| {
            f.rpc
                .list_unspent(&Params::Array(params))
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u["address"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(list(vec![]).len(), 4);

        let only_second = list(vec![json!(1), json!(9999999), json!([f.second])]);
        assert_eq!(only_second, vec![f.second.clone()]);

        let only_miner = list(vec![json!(1), json!(9999999), json!([f.miner])]);
        assert_eq!(only_miner.len(), 3);
        assert!(only_miner.iter().all(|a| *a == f.miner));

        assert_eq!(
            list(vec![json!(1), json!(9999999), json!([f.miner, f.second])]).len(),
            4
        );
        assert!(list(vec![json!(1), json!(9999999), json!([])]).is_empty());
    }

    #[test]
    fn list_unspent_rejects_bad_address_filter() {
        let f = fixture();
        let code = |filter: serde_json::Value| match f.rpc.list_unspent(&Params::Array(vec![
            json!(1),
            json!(9999999),
            filter,
        ])) {
            Err(Error::Rpc(e)) => e.code,
            other => panic!("expected an RPC error, got {:?}", other),
        };
        assert_eq!(code(json!(["notanaddress"])), codes::INVALID_ADDRESS_OR_KEY);
        assert_eq!(code(json!([f.second, f.second])), codes::INVALID_PARAMETER);
        assert_eq!(code(json!(f.second)), codes::TYPE_ERROR);
    }

    #[test]
    fn history_amount_excludes_fee() {
        let f = fixture();
        let txid = f.spend.txid().to_string();
        // Block 5's send: 1000 to a stranger, 0.01 fee, change to our address
        let tx = f
            .rpc
            .get_transaction(&Params::Array(vec![json!(txid)]))
            .unwrap();
        // Divi Core's gettransaction: amount is credit less debit (the fee
        // included) and fee is positive; the send entry keeps amount and a
        // negative fee (rpcwallet.cpp:2476-2480, :2167-2173)
        assert_eq!(tx["amount"], json!(-1000.01));
        assert_eq!(tx["fee"], json!(0.01));
        assert_eq!(tx["details"][0]["amount"], json!(-1000.0));
        assert_eq!(tx["details"][0]["fee"], json!(-0.01));

        let listed = f
            .rpc
            .list_transactions(&Params::Array(vec![json!("*"), json!(100)]))
            .unwrap();
        let entry = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["txid"] == json!(txid) && e["address"] == json!(stranger_address()))
            .expect("send listed");
        assert_eq!(entry["amount"], json!(-1000.0));
        assert_eq!(entry["fee"], json!(-0.01));

        let since = f.rpc.list_since_block(&Params::Array(vec![])).unwrap();
        let entry = since["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["txid"] == json!(txid) && e["address"] == json!(stranger_address()))
            .expect("send in listsinceblock");
        assert_eq!(entry["amount"], json!(-1000.0));
        assert_eq!(entry["fee"], json!(-0.01));

        // A receive has no fee and its amount is unchanged
        let coinbase = f
            .wallet
            .get_transactions(None)
            .into_iter()
            .find(|t| t.category == "coinbase")
            .unwrap();
        let tx = f
            .rpc
            .get_transaction(&Params::Array(vec![json!(coinbase.txid.to_string())]))
            .unwrap();
        assert_eq!(tx["amount"], json!(1250.0));
        assert_eq!(tx["fee"], serde_json::Value::Null);
    }

    fn stranger_address() -> String {
        Address::from_pubkey_hash(
            divi_primitives::hash::Hash160::from_bytes([0xaa; 20]),
            Network::Regtest,
        )
        .to_string()
    }

    #[test]
    fn send_does_not_spend_own_unconfirmed_change() {
        let f = fixture();
        // Our own tx spends every confirmed coin: 100 DIVI change comes back
        // unconfirmed (trusted, as all inputs are ours)
        let coins = f.wallet.get_utxos();
        let total: i64 = coins.iter().map(|u| u.value.as_sat()).sum();
        let own = Transaction {
            version: 1,
            vin: coins
                .iter()
                .map(|u| TxIn::new(u.outpoint(), Script::default(), 0xffffffff))
                .collect(),
            vout: vec![
                TxOut::new(Amount::from_sat(total - 100 * COIN - 1_000_000), stranger()),
                TxOut::new(Amount::from_sat(100 * COIN), script_of(&f.miner)),
            ],
            lock_time: 0,
        };
        assert!(f.wallet.add_mempool_tx(&own));
        // Core's getbalance counts confirmed coins only; the change is
        // unconfirmed balance until it confirms (wallet.cpp:1395-1412)
        assert_eq!(
            f.rpc.get_balance(&Params::Array(vec![])).unwrap(),
            json!(0.0)
        );
        assert_eq!(
            f.rpc
                .get_unconfirmed_balance(&Params::Array(vec![]))
                .unwrap(),
            json!(100.0)
        );

        let submitted = Arc::new(parking_lot::Mutex::new(None));
        let sink = submitted.clone();
        f.rpc.set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            *sink.lock() = Some(tx);
            Ok(txid)
        }));
        // Divi Core spends only confirmed coins unless -spendzeroconfchange
        // (off by default)
        assert!(f
            .rpc
            .send_to_address(&Params::Array(vec![json!(stranger_address()), json!(10)]))
            .is_err());
        assert!(submitted.lock().is_none());
    }

    #[test]
    fn balances_leave_out_immature_rewards() {
        let f = fixture();
        // A fresh coinbase to us at the tip is immature (regtest maturity 1)
        mine(&f.chain, script_of(&f.miner), &[]);
        f.rpc.rescan_blockchain(&Params::Array(vec![])).unwrap();
        let none = || Params::Array(vec![]);

        assert_eq!(
            f.rpc.get_balance(&none()).unwrap(),
            json!(BALANCE as f64 / 1e8)
        );
        assert_eq!(
            f.rpc
                .get_balance(&Params::Array(vec![json!("*"), json!(1)]))
                .unwrap(),
            json!(BALANCE as f64 / 1e8)
        );
        assert_eq!(f.rpc.get_immature_balance(&none()).unwrap(), json!(1250.0));
        let info = f.rpc.get_wallet_info(&none()).unwrap();
        assert_eq!(info["balance"], json!(BALANCE as f64 / 1e8));
        assert_eq!(info["immature_balance"], json!(1250.0));

        // getbalance matches what a send can select
        let selectable: i64 = f
            .wallet
            .get_spendable_utxos(f.chain.height(), 1)
            .iter()
            .map(|u| u.value.as_sat())
            .sum();
        assert_eq!(selectable, BALANCE);
    }

    #[test]
    fn list_unspent_leaves_out_vault_outputs() {
        let f = fixture();
        // A vault managed by our `second` key, funded with 50 DIVI in block 6
        let manager = Address::from_base58(&f.second).unwrap();
        let mut owner = [0u8; 20];
        owner.copy_from_slice(&[0xcc; 20]);
        let vault = StakingVaultScript::new(owner, *manager.hash.as_bytes()).to_script();
        f.wallet.store_vault(divi_wallet::wallet_db::VaultMetadata {
            owner_address: String::new(),
            manager_address: f.second.clone(),
            vault_script: vault.as_bytes().to_vec(),
            funding_txid: [0u8; 32],
        });
        let coin = f
            .wallet
            .get_utxos()
            .into_iter()
            .find(|u| u.address == f.miner)
            .unwrap();
        let fund = Transaction {
            version: 1,
            vin: vec![TxIn::new(coin.outpoint(), Script::default(), 0xffffffff)],
            vout: vec![
                TxOut::new(Amount::from_sat(50 * COIN), vault.clone()),
                TxOut::new(
                    Amount::from_sat(1200 * COIN - 1_000_000),
                    script_of(&f.miner),
                ),
            ],
            lock_time: 0,
        };
        let mut fund = fund;
        sign_with_wallet(&f.wallet, &f.chain, &mut fund);
        mine(&f.chain, stranger(), &[fund]);
        f.rpc.rescan_blockchain(&Params::Array(vec![])).unwrap();
        assert!(f
            .wallet
            .get_utxos()
            .iter()
            .any(|u| u.script_pubkey == vault));

        let listed = f.rpc.list_unspent(&Params::Array(vec![])).unwrap();
        let listed = listed.as_array().unwrap();
        assert_eq!(listed.len(), 4);
        assert!(listed
            .iter()
            .all(|u| u["scriptPubKey"] != json!(hex::encode(vault.as_bytes()))));
    }
}
