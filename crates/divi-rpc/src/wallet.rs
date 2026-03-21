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
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::script::Script;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::{OutPoint, Transaction};
use divi_script::opcodes::Opcode;
use divi_script::StakingVaultScript;
use divi_storage::Chain;
use divi_wallet::{
    wallet_db::VaultMetadata, Address, Network, TransactionBuilder, TransactionSigner, WalletDb,
};
use parking_lot::RwLock;
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

/// Callback for submitting transactions to the mempool and network
pub type TxSubmitCallback = Arc<dyn Fn(Transaction) -> Result<Hash256, String> + Send + Sync>;

/// Wallet RPC handler
pub struct WalletRpc {
    wallet: Arc<RwLock<Option<Arc<WalletDb>>>>,
    height: Arc<RwLock<u32>>,
    tx_submit: RwLock<Option<TxSubmitCallback>>,
    chain: Option<Arc<Chain>>,
    locked_utxos: Arc<RwLock<HashSet<OutPoint>>>,
}

impl WalletRpc {
    pub fn new() -> Self {
        WalletRpc {
            wallet: Arc::new(RwLock::new(None)),
            height: Arc::new(RwLock::new(0)),
            tx_submit: RwLock::new(None),
            chain: None,
            locked_utxos: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn with_wallet(wallet: Arc<WalletDb>) -> Self {
        WalletRpc {
            wallet: Arc::new(RwLock::new(Some(wallet))),
            height: Arc::new(RwLock::new(0)),
            tx_submit: RwLock::new(None),
            chain: None,
            locked_utxos: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create with chain reference (needed for rescan)
    pub fn with_chain(chain: Arc<Chain>) -> Self {
        WalletRpc {
            wallet: Arc::new(RwLock::new(None)),
            height: Arc::new(RwLock::new(0)),
            tx_submit: RwLock::new(None),
            chain: Some(chain),
            locked_utxos: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create with wallet and chain
    pub fn with_wallet_and_chain(wallet: Arc<WalletDb>, chain: Arc<Chain>) -> Self {
        WalletRpc {
            wallet: Arc::new(RwLock::new(Some(wallet))),
            height: Arc::new(RwLock::new(0)),
            tx_submit: RwLock::new(None),
            chain: Some(chain),
            locked_utxos: Arc::new(RwLock::new(HashSet::new())),
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

    /// Get the wallet or return an error
    fn get_wallet(&self) -> Result<Arc<WalletDb>, Error> {
        self.wallet
            .read()
            .clone()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Wallet not loaded").into())
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

        callback(tx).map_err(|e| RpcError::new(codes::VERIFY_ERROR, e).into())
    }

    /// getnewaddress - Generate a new receiving address
    pub fn get_new_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        // Optional label parameter (ignored for now)
        let _label = params.get_str(0).unwrap_or("");

        let address = wallet.new_receiving_address().map_err(|e| match e {
            divi_wallet::WalletError::WalletLocked => {
                RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked")
            }
            _ => RpcError::new(codes::WALLET_ERROR, e.to_string()),
        })?;

        debug!("Generated new address: {}", address);
        Ok(serde_json::json!(address.to_string()))
    }

    /// getrawchangeaddress - Generate a new change address
    pub fn get_raw_change_address(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let address = wallet.new_change_address().map_err(|e| match e {
            divi_wallet::WalletError::WalletLocked => {
                RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked")
            }
            _ => RpcError::new(codes::WALLET_ERROR, e.to_string()),
        })?;

        debug!("Generated new change address: {}", address);
        Ok(serde_json::json!(address.to_string()))
    }

    /// validateaddress - Validate a Divi address
    pub fn validate_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        match Address::from_base58(addr_str) {
            Ok(addr) => {
                let wallet_guard = self.wallet.read();
                let is_mine = wallet_guard
                    .as_ref()
                    .map(|w| w.is_mine(&addr))
                    .unwrap_or(false);

                let mut result = serde_json::json!({
                    "isvalid": true,
                    "address": addr_str,
                    "scriptPubKey": format!("76a914{}88ac", hex::encode(addr.hash.as_bytes())),
                    "ismine": is_mine,
                    "iswatchonly": false,
                    "isscript": addr.addr_type == divi_wallet::AddressType::P2SH,
                });

                if is_mine {
                    if let Some(wallet) = wallet_guard.as_ref() {
                        if let Some(key_entry) = wallet.get_key_by_address(&addr) {
                            let pubkey_hex = hex::encode(key_entry.public.to_bytes());
                            result["pubkey"] = serde_json::json!(pubkey_hex);
                            result["iscompressed"] = serde_json::json!(true);
                            result["account"] = serde_json::json!("");

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

        let addr = Address::from_base58(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        let wallet = self.get_wallet()?;
        let is_mine = wallet.is_mine(&addr);
        let is_watch_only = wallet.is_watch_only(&addr);

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
            "labels": [],
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

        // Optional minconf parameter (default 1)
        let min_conf = params.get_u64(0).unwrap_or(1) as u32;

        let height = self.current_height();
        let balance = if min_conf == 0 {
            wallet.get_balance()
        } else {
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
        let balance = wallet.get_immature_balance(height, 100); // 100 block maturity
        let divi = balance.as_sat() as f64 / 100_000_000.0;
        Ok(serde_json::json!(divi))
    }

    /// getwalletinfo - Get wallet state info
    pub fn get_wallet_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let height = self.current_height();
        let balance = wallet.get_confirmed_balance(height, 1);
        let unconfirmed = wallet.get_unconfirmed_balance();
        let immature = wallet.get_immature_balance(height, 100);

        let divi_balance = balance.as_sat() as f64 / 100_000_000.0;
        let divi_unconfirmed = unconfirmed.as_sat() as f64 / 100_000_000.0;
        let divi_immature = immature.as_sat() as f64 / 100_000_000.0;

        Ok(serde_json::json!({
            "walletname": "wallet.dat",
            "walletversion": 120200,
            "balance": divi_balance,
            "unconfirmed_balance": divi_unconfirmed,
            "immature_balance": divi_immature,
            "txcount": wallet.get_transactions(None).len(),
            "keypoololdest": wallet.keypool_oldest(),
            // Report keypool_target (100) as a minimum when the keypool hasn't been
            // explicitly pre-generated; HD wallets derive keys on demand so the
            // effective available key count is always at least the target size.
            "keypoolsize": std::cmp::max(wallet.keypool_size(), 100u32),
            "unlocked_until": if wallet.is_locked() { 0 } else { 0 },
            "paytxfee": 0.0001,
            "hdmasterkeyid": wallet.hd_master_key_id()
        }))
    }

    /// listunspent - List unspent transaction outputs
    pub fn list_unspent(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        // Optional parameters
        let min_conf = params.get_u64(0).unwrap_or(1) as u32;
        let max_conf = params.get_u64(1).unwrap_or(9999999) as u32;

        let height = self.current_height();
        let utxos = wallet.get_utxos();

        let result: Vec<_> = utxos
            .iter()
            .filter(|utxo| {
                let confs = utxo.confirmations(height);
                confs >= min_conf && confs <= max_conf
            })
            .map(|utxo| {
                let divi = utxo.value.as_sat() as f64 / 100_000_000.0;
                let is_change = wallet.is_change_address_str(&utxo.address);

                // Check if this address is watch-only
                let is_watch_only = if let Ok(addr) = Address::from_base58(&utxo.address) {
                    wallet.is_watch_only(&addr)
                } else {
                    false
                };

                // UTXO is spendable if mature AND not watch-only
                let spendable =
                    utxo.is_mature(height, wallet.coinbase_maturity()) && !is_watch_only;

                serde_json::json!({
                    "txid": utxo.txid.to_string(),
                    "vout": utxo.vout,
                    "address": utxo.address,
                    "scriptPubKey": hex::encode(utxo.script_pubkey.as_bytes()),
                    "amount": divi,
                    "confirmations": utxo.confirmations(height),
                    "spendable": spendable,
                    "solvable": true,
                    "ischange": is_change,
                })
            })
            .collect();

        Ok(serde_json::json!(result))
    }

    /// gettransaction - Get detailed information about a wallet transaction
    pub fn get_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let txid_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("txid required"))?;

        let txid = divi_primitives::hash::Hash256::from_hex(txid_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid txid"))?;

        let wallet = self.get_wallet()?;

        let tx = wallet
            .get_transaction(&txid)
            .ok_or_else(|| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Transaction not found"))?;

        let height = self.current_height();
        let confirmations = match tx.block_height {
            Some(h) if height >= h => height - h + 1,
            _ => 0,
        };

        let divi_amount = tx.amount as f64 / 100_000_000.0;
        // Fee is shown as negative for sent transactions (C++ Divi convention)
        let divi_fee = tx.fee.map(|f| -(f.as_sat() as f64 / 100_000_000.0));

        Ok(serde_json::json!({
            "amount": divi_amount,
            "fee": divi_fee,
            "confirmations": confirmations,
            "blockhash": tx.block_hash.map(|h| h.to_string()),
            "blockheight": tx.block_height,
            "blocktime": tx.timestamp,
            "txid": tx.txid.to_string(),
            "time": tx.timestamp,
            "timereceived": tx.timestamp,
            "details": [{
                "category": tx.category,
                "amount": divi_amount,
            }],
        }))
    }

    /// listtransactions - List recent transactions
    /// C++ signature: listtransactions ( "account" count skip )
    /// params[0] = account (string, ignored — we don't use accounts)
    /// params[1] = count (default 10)
    /// params[2] = skip (default 0)
    pub fn list_transactions(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        // params[0] is account name (string) — skip it
        // params[1] is count, params[2] is skip
        let count = params.get_u64(1).unwrap_or(10) as usize;
        let skip = params.get_u64(2).unwrap_or(0) as usize;

        let height = self.current_height();
        let mut txs = wallet.get_transactions(None);

        // Apply skip and count
        if skip > 0 {
            txs = txs.into_iter().skip(skip).collect();
        }
        txs.truncate(count);

        let result: Vec<_> = txs
            .iter()
            .map(|tx| {
                let confirmations = match tx.block_height {
                    Some(h) if height >= h => height - h + 1,
                    _ => 0,
                };
                let divi_amount = tx.amount as f64 / 100_000_000.0;

                let mut entry = serde_json::json!({
                    "category": tx.category,
                    "amount": divi_amount,
                    "confirmations": confirmations,
                    "blockhash": tx.block_hash.map(|h| h.to_string()),
                    "blockheight": tx.block_height,
                    "txid": tx.txid.to_string(),
                    "time": tx.timestamp,
                    "timereceived": tx.timestamp,
                });

                // Include fee for sent transactions (C++ Divi compatibility)
                if let Some(fee) = tx.fee {
                    let fee_divi = fee.as_sat() as f64 / 100_000_000.0;
                    entry["fee"] = serde_json::json!(-fee_divi); // Negative as per C++ convention
                }

                entry
            })
            .collect();

        Ok(serde_json::json!(result))
    }

    /// listsinceblock - List transactions since a given block
    pub fn list_since_block(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let since_height = if let Some(blockhash_str) = params.get_str(0) {
            let blockhash = Hash256::from_hex(blockhash_str)
                .map_err(|_| RpcError::invalid_params("Invalid block hash"))?;

            if let Some(chain) = &self.chain {
                let block_index = chain
                    .get_block_index(&blockhash)
                    .map_err(|e| RpcError::internal_error(format!("Failed to get block: {}", e)))?
                    .ok_or_else(|| RpcError::new(codes::INVALID_PARAMETER, "Block not found"))?;
                block_index.height
            } else {
                return Err(RpcError::internal_error("Chain not available").into());
            }
        } else {
            0
        };

        let target_confirmations = params.get_u64(1).unwrap_or(1) as u32;
        let current_height = self.current_height();
        let all_txs = wallet.get_transactions(None);

        let filtered_txs: Vec<_> = all_txs
            .iter()
            .filter(|tx| {
                if let Some(tx_height) = tx.block_height {
                    if tx_height <= since_height {
                        return false;
                    }
                    let confirmations = if current_height >= tx_height {
                        current_height - tx_height + 1
                    } else {
                        0
                    };
                    confirmations >= target_confirmations
                } else {
                    target_confirmations == 0
                }
            })
            .map(|tx| {
                let confirmations = match tx.block_height {
                    Some(h) if current_height >= h => current_height - h + 1,
                    _ => 0,
                };
                let divi_amount = tx.amount as f64 / 100_000_000.0;

                let mut entry = serde_json::json!({
                    "category": tx.category,
                    "amount": divi_amount,
                    "confirmations": confirmations,
                    "blockhash": tx.block_hash.map(|h| h.to_string()),
                    "blockheight": tx.block_height,
                    "txid": tx.txid.to_string(),
                    "time": tx.timestamp,
                    "timereceived": tx.timestamp,
                });

                // Include fee for sent transactions (C++ Divi compatibility)
                if let Some(fee) = tx.fee {
                    let fee_divi = fee.as_sat() as f64 / 100_000_000.0;
                    entry["fee"] = serde_json::json!(-fee_divi); // Negative as per C++ convention
                }

                entry
            })
            .collect();

        let lastblock = if let Some(chain) = &self.chain {
            chain
                .tip()
                .map(|tip| tip.hash.to_string())
                .unwrap_or_else(|| {
                    String::from("0000000000000000000000000000000000000000000000000000000000000000")
                })
        } else {
            String::from("0000000000000000000000000000000000000000000000000000000000000000")
        };

        Ok(serde_json::json!({
            "transactions": filtered_txs,
            "lastblock": lastblock
        }))
    }

    /// walletpassphrase - Unlock wallet for specified time
    pub fn wallet_passphrase(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let passphrase = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Passphrase required"))?;
        let timeout = params
            .get_u64(1)
            .ok_or_else(|| RpcError::invalid_params("Timeout required"))?;

        let wallet = self.get_wallet()?;

        if !wallet.is_encrypted() {
            return Err(
                RpcError::new(codes::WALLET_WRONG_ENC_STATE, "Wallet is not encrypted").into(),
            );
        }

        wallet.unlock(passphrase, timeout as u32).map_err(|_| {
            RpcError::new(codes::WALLET_PASSPHRASE_INCORRECT, "Incorrect passphrase")
        })?;

        Ok(serde_json::Value::Null)
    }

    /// walletlock - Lock the wallet
    pub fn wallet_lock(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        if !wallet.is_encrypted() {
            return Err(
                RpcError::new(codes::WALLET_WRONG_ENC_STATE, "Wallet is not encrypted").into(),
            );
        }

        wallet.lock();
        Ok(serde_json::Value::Null)
    }

    pub fn dump_privkey(&self, params: &Params) -> Result<serde_json::Value, Error> {
        use divi_wallet::address::{encode_wif, Network};

        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let addr = Address::from_base58(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        let wallet = self.get_wallet()?;

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

        let key_entry = wallet.keystore().get_key_by_address(&addr).ok_or_else(|| {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                "Private key for address not found in wallet",
            )
        })?;

        let network = match addr.network {
            divi_wallet::address::Network::Mainnet => Network::Mainnet,
            divi_wallet::address::Network::Testnet => Network::Testnet,
            divi_wallet::address::Network::Regtest => Network::Regtest,
        };

        let secret = key_entry.secret.as_ref().ok_or_else(|| {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                "Address is watch-only, cannot dump private key",
            )
        })?;
        let key_bytes = secret.as_bytes();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key_bytes);
        let wif = encode_wif(&key_array, true, network);

        Ok(serde_json::json!(wif))
    }

    pub fn import_privkey(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wif = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Private key required"))?;

        // Optional label parameter
        let label = params.get_str(1).map(|s| s.to_string());

        // Optional rescan parameter (default true, but we don't implement rescan yet)
        let _rescan = params.get_bool(2).unwrap_or(true);

        let wallet = self.get_wallet()?;

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

        // Decode the WIF private key
        let wif_key = divi_wallet::decode_wif(wif).map_err(|e| {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                format!("Invalid private key: {}", e),
            )
        })?;

        // Create a SecretKey from the decoded bytes
        let secret = divi_crypto::keys::SecretKey::from_bytes(&wif_key.key_bytes).map_err(|e| {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                format!("Invalid key bytes: {}", e),
            )
        })?;

        // Import the key
        let address = wallet.import_key(secret, label);

        info!("Imported private key for address: {}", address);

        wallet.save().map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to save wallet: {}", e))
        })?;

        // Note: rescan not implemented - caller should manually rescan if needed
        Ok(serde_json::Value::Null)
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

        let chain = self.chain.as_ref().ok_or_else(|| {
            RpcError::new(codes::INTERNAL_ERROR, "Chain not available for rescan")
        })?;

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

        info!("Clearing existing wallet data before rescan");
        wallet.clear_transactions_and_utxos();

        // Iterate through blocks and scan
        let mut scanned = 0;
        for height in start_height..=stop_height {
            // Get block index
            let index = match chain.get_block_index_by_height(height)? {
                Some(idx) => idx,
                None => {
                    info!(
                        "Block index at height {} not found, stopping rescan (total scanned: {})",
                        height, scanned
                    );
                    break;
                }
            };

            // Get full block
            let block = match chain.get_block(&index.hash)? {
                Some(blk) => blk,
                None => {
                    info!("Block data for hash {} at height {} not found, stopping rescan (total scanned: {})", 
                          index.hash, height, scanned);
                    break;
                }
            };

            // Check if block has transactions
            if block.transactions.is_empty() {
                debug!("Block at height {} has no transactions, skipping", height);
                scanned += 1;
                continue;
            }

            // Scan the block
            wallet.scan_block(index.hash, height, &block.transactions);
            scanned += 1;

            // Log progress every 1000 blocks
            if scanned % 1000 == 0 {
                info!(
                    "Rescan progress: {}/{} blocks",
                    scanned,
                    stop_height - start_height + 1
                );
            }
        }

        info!("Rescan complete: scanned {} blocks", scanned);

        wallet.save().map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("Failed to save wallet after rescan: {}", e),
            )
        })?;

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

    /// sendtoaddress - Send amount to a given address
    pub fn send_to_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let dest_addr = Address::from_base58(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        let amount_divi = params
            .get(1)
            .and_then(|v| v.as_f64())
            .ok_or_else(|| RpcError::invalid_params("Amount required"))?;

        let send_amount = Amount::from_sat((amount_divi * 100_000_000.0) as i64);

        let wallet = self.get_wallet()?;

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

        let height = self.current_height();

        // Get spendable UTXOs (1 confirmation minimum)
        let mut utxos = wallet.get_spendable_utxos(height, 1);

        // Sort by value descending for simple coin selection
        utxos.sort_by(|a, b| b.value.cmp(&a.value));

        // Fee estimation: ~1000 satoshis per input + 500 per output
        let base_fee = Amount::from_sat(1000);
        let per_input_fee = Amount::from_sat(1000);
        let per_output_fee = Amount::from_sat(500);

        // Simple coin selection: select UTXOs until we have enough
        let mut selected = Vec::new();
        let mut total_input = Amount::ZERO;
        let min_output = Amount::from_sat(546); // Dust limit

        for utxo in utxos {
            selected.push(utxo.clone());
            total_input = total_input + utxo.value;

            // Calculate required amount (send + fee estimate)
            let num_inputs = selected.len() as i64;
            let est_fee = base_fee
                + Amount::from_sat(
                    per_input_fee.as_sat() * num_inputs + per_output_fee.as_sat() * 2,
                );
            let required = send_amount + est_fee;

            if total_input >= required {
                break;
            }
        }

        // Check if we have enough funds
        let num_inputs = selected.len() as i64;
        let fee = base_fee
            + Amount::from_sat(per_input_fee.as_sat() * num_inputs + per_output_fee.as_sat() * 2);
        let required = send_amount + fee;

        if total_input < required {
            return Err(RpcError::new(
                codes::WALLET_INSUFFICIENT_FUNDS,
                format!(
                    "Insufficient funds. Have {} DIVI, need {} DIVI",
                    total_input.as_sat() as f64 / 100_000_000.0,
                    required.as_sat() as f64 / 100_000_000.0
                ),
            )
            .into());
        }

        // Get change address
        let change_addr = wallet.new_change_address().map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("Failed to generate change address: {}", e),
            )
        })?;

        // Build the transaction
        let mut builder = TransactionBuilder::new();

        // Add inputs
        for utxo in &selected {
            builder = builder.add_input(utxo.outpoint(), utxo.script_pubkey.clone());
        }

        // Add destination output
        builder = builder.add_output_to_address(send_amount, &dest_addr);

        // Add change output if significant
        let change_amount = total_input - send_amount - fee;
        if change_amount >= min_output {
            builder = builder.add_output_to_address(change_amount, &change_addr);
        }

        let (mut tx, prev_scripts) = builder.build();

        // Sign the transaction
        let signer = TransactionSigner::new(wallet.keystore());
        let signed_count = signer
            .sign_all_inputs(&mut tx, &prev_scripts)
            .map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Failed to sign transaction: {}", e),
                )
            })?;

        if signed_count != selected.len() {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!("Only signed {} of {} inputs", signed_count, selected.len()),
            )
            .into());
        }

        // Calculate txid
        let txid = tx.txid();

        // Submit to mempool and broadcast
        self.submit_transaction(tx)?;

        info!("Sent {} DIVI to {} (txid: {})", amount_divi, addr_str, txid);

        Ok(serde_json::json!(txid.to_string()))
    }

    /// createrawtransaction - Create an unsigned raw transaction
    pub fn create_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        // params[0] = inputs array: [{"txid": "...", "vout": n}, ...]
        // params[1] = outputs object: {"address": amount, ...}

        let inputs = params
            .get(0)
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::invalid_params("Inputs array required"))?;

        let outputs = params
            .get(1)
            .and_then(|v| v.as_object())
            .ok_or_else(|| RpcError::invalid_params("Outputs object required"))?;

        let mut builder = TransactionBuilder::new();

        // Add inputs
        for input in inputs {
            let txid_str = input
                .get("txid")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RpcError::invalid_params("Input txid required"))?;

            let vout = input
                .get("vout")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| RpcError::invalid_params("Input vout required"))?
                as u32;

            let txid = Hash256::from_hex(txid_str)
                .map_err(|_| RpcError::invalid_params(format!("Invalid txid: {}", txid_str)))?;

            // For createrawtransaction, we don't need the prev script (that's for signing)
            builder = builder.add_input(OutPoint::new(txid, vout), Script::new());
        }

        // Add outputs
        for (addr_str, amount_value) in outputs {
            let amount_divi = amount_value.as_f64().ok_or_else(|| {
                RpcError::invalid_params(format!("Invalid amount for {}", addr_str))
            })?;

            let amount = Amount::from_sat((amount_divi * 100_000_000.0) as i64);

            let addr = Address::from_base58(addr_str).map_err(|_| {
                RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    format!("Invalid address: {}", addr_str),
                )
            })?;

            builder = builder.add_output_to_address(amount, &addr);
        }

        let (tx, _) = builder.build();

        // Serialize to hex
        let raw = serialize(&tx);
        Ok(serde_json::json!(hex::encode(raw)))
    }

    /// signrawtransaction - Sign a raw transaction with wallet keys
    pub fn sign_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let hex_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Transaction hex required"))?;

        let wallet = self.get_wallet()?;

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

        // Decode transaction
        let tx_bytes = hex::decode(hex_str)
            .map_err(|_| RpcError::invalid_params("Invalid transaction hex"))?;

        let mut tx: Transaction = deserialize(&tx_bytes).map_err(|e| {
            RpcError::invalid_params(format!("Failed to decode transaction: {}", e))
        })?;

        // Optional: prevtxs array with previous outputs for signing
        let prevtxs = params.get(1).and_then(|v| v.as_array());

        // Build list of previous output scripts
        let mut prev_scripts: Vec<Script> = Vec::new();

        if let Some(prevtxs) = prevtxs {
            for prevtx in prevtxs {
                let script_hex = prevtx
                    .get("scriptPubKey")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RpcError::invalid_params("prevtx scriptPubKey required"))?;

                let script_bytes = hex::decode(script_hex)
                    .map_err(|_| RpcError::invalid_params("Invalid scriptPubKey hex"))?;

                prev_scripts.push(Script::from_bytes(script_bytes));
            }
        } else {
            // Try to look up UTXOs from wallet
            for input in &tx.vin {
                let outpoint = OutPoint::new(input.prevout.txid, input.prevout.vout);
                if let Some(utxo) = wallet.get_utxo(&outpoint) {
                    prev_scripts.push(utxo.script_pubkey);
                } else {
                    // Unknown UTXO, use empty script (signing will fail for this input)
                    prev_scripts.push(Script::new());
                }
            }
        }

        // Sign inputs
        let signer = TransactionSigner::new(wallet.keystore());
        let signed = signer
            .sign_all_inputs(&mut tx, &prev_scripts)
            .map_err(|e| RpcError::new(codes::WALLET_ERROR, format!("Failed to sign: {}", e)))?;

        let complete = signed == tx.vin.len();

        // Serialize signed transaction
        let raw = serialize(&tx);

        Ok(serde_json::json!({
            "hex": hex::encode(raw),
            "complete": complete
        }))
    }

    /// sendrawtransaction - Submit a raw transaction to the network
    pub fn send_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let hex_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Transaction hex required"))?;

        // Decode transaction
        let tx_bytes = hex::decode(hex_str)
            .map_err(|_| RpcError::invalid_params("Invalid transaction hex"))?;

        let tx: Transaction = deserialize(&tx_bytes).map_err(|e| {
            RpcError::invalid_params(format!("Failed to decode transaction: {}", e))
        })?;

        let txid = tx.txid();

        // Submit to mempool and broadcast
        self.submit_transaction(tx)?;

        info!("Broadcasted transaction {}", txid);

        Ok(serde_json::json!(txid.to_string()))
    }

    /// getrawtransaction - Get raw transaction data
    pub fn get_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        use divi_script::{
            extract_destinations, extract_script_type, get_script_type_name, to_asm,
        };
        let txid_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("txid required"))?;

        let txid = Hash256::from_hex(txid_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid txid"))?;

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

        if !verbose {
            let tx = chain
                .get_transaction(&txid)
                .map_err(|e| {
                    RpcError::new(codes::DATABASE_ERROR, format!("Database error: {}", e))
                })?
                .ok_or_else(|| {
                    RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Transaction not found")
                })?;

            let hex = hex::encode(serialize(&tx));
            Ok(serde_json::json!(hex))
        } else {
            let result = chain
                .get_transaction_with_location(&txid)
                .map_err(|e| {
                    RpcError::new(codes::DATABASE_ERROR, format!("Database error: {}", e))
                })?
                .ok_or_else(|| {
                    RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Transaction not found")
                })?;

            let (tx, location) = result;
            let txid_value = tx.txid().to_string();
            let hex_value = hex::encode(serialize(&tx));
            let size = hex_value.len() / 2;

            let block_index = chain
                .get_block_index(&location.block_hash)
                .map_err(|e| {
                    RpcError::new(codes::DATABASE_ERROR, format!("Database error: {}", e))
                })?
                .ok_or_else(|| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Block not found"))?;

            let tip_height = chain.height();
            let confirmations = if block_index.height <= tip_height {
                tip_height - block_index.height + 1
            } else {
                0
            };

            let vin: Vec<serde_json::Value> = tx
                .vin
                .iter()
                .map(|input| {
                    serde_json::json!({
                        "txid": input.prevout.txid.to_string(),
                        "vout": input.prevout.vout,
                        "scriptSig": {
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
                    let script_bytes = output.script_pubkey.as_bytes();
                    let (script_type, _solutions) = extract_script_type(script_bytes);
                    let type_name = get_script_type_name(script_type);
                    let asm = to_asm(script_bytes);

                    let mut script_obj = serde_json::json!({
                        "asm": asm,
                        "hex": hex::encode(script_bytes),
                        "type": type_name,
                    });

                    // Extract addresses if available
                    if let Some((_stype, destinations, req_sigs)) =
                        extract_destinations(script_bytes)
                    {
                        if req_sigs > 1 {
                            script_obj["reqSigs"] = serde_json::json!(req_sigs);
                        }

                        let addresses: Vec<String> = destinations
                            .iter()
                            .filter_map(|dest| match dest {
                                divi_script::Destination::PubKeyHash(pkh) => {
                                    let mut bytes = [0u8; 20];
                                    bytes.copy_from_slice(&pkh[..]);
                                    let addr = Address::from_pubkey_hash(
                                        Hash160::from_bytes(bytes),
                                        Network::Mainnet,
                                    );
                                    Some(addr.to_base58())
                                }
                                divi_script::Destination::ScriptHash(sh) => {
                                    let mut bytes = [0u8; 20];
                                    bytes.copy_from_slice(&sh[..]);
                                    let addr =
                                        Address::p2sh(Hash160::from_bytes(bytes), Network::Mainnet);
                                    Some(addr.to_base58())
                                }
                            })
                            .collect();

                        if !addresses.is_empty() {
                            script_obj["addresses"] = serde_json::json!(addresses);
                        }
                    }

                    serde_json::json!({
                        "value": output.value.as_divi(),
                        "n": n,
                        "scriptPubKey": script_obj,
                    })
                })
                .collect();

            Ok(serde_json::json!({
                "hex": hex_value,
                "txid": txid_value,
                "baretxid": txid_value,
                "version": tx.version,
                "locktime": tx.lock_time,
                "size": size,
                "vin": vin,
                "vout": vout,
                "blockhash": location.block_hash.to_string(),
                "confirmations": confirmations,
                "time": block_index.time,
                "blocktime": block_index.time,
                "height": block_index.height,
            }))
        }
    }

    pub fn decode_raw_transaction(&self, params: &Params) -> Result<serde_json::Value, Error> {
        use divi_script::{
            extract_destinations, extract_script_type, get_script_type_name, to_asm,
        };
        let hex_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("hex string required"))?;

        let tx_bytes = hex::decode(hex_str)
            .map_err(|_| RpcError::new(codes::DESERIALIZATION_ERROR, "Invalid hex string"))?;

        let tx: divi_primitives::transaction::Transaction =
            deserialize(&tx_bytes).map_err(|e| {
                RpcError::new(
                    codes::DESERIALIZATION_ERROR,
                    format!("Failed to decode transaction: {}", e),
                )
            })?;

        let txid_value = tx.txid().to_string();

        let vin: Vec<serde_json::Value> = tx
            .vin
            .iter()
            .map(|input| {
                if input.prevout.txid == Hash256::zero() && input.prevout.vout == 0xffffffff {
                    serde_json::json!({
                        "coinbase": hex::encode(input.script_sig.as_bytes()),
                        "sequence": input.sequence,
                    })
                } else {
                    let script_bytes = input.script_sig.as_bytes();
                    let asm = to_asm(script_bytes);

                    serde_json::json!({
                        "txid": input.prevout.txid.to_string(),
                        "vout": input.prevout.vout,
                        "scriptSig": {
                            "asm": asm,
                            "hex": hex::encode(script_bytes),
                        },
                        "sequence": input.sequence,
                    })
                }
            })
            .collect();

        let vout: Vec<serde_json::Value> = tx
            .vout
            .iter()
            .enumerate()
            .map(|(n, output)| {
                let script_bytes = output.script_pubkey.as_bytes();
                let (script_type, _solutions) = extract_script_type(script_bytes);
                let type_name = get_script_type_name(script_type);
                let asm = to_asm(script_bytes);

                let mut script_obj = serde_json::json!({
                    "asm": asm,
                    "hex": hex::encode(script_bytes),
                    "type": type_name,
                });

                // Extract addresses if available
                if let Some((_stype, destinations, req_sigs)) = extract_destinations(script_bytes) {
                    if req_sigs > 1 {
                        script_obj["reqSigs"] = serde_json::json!(req_sigs);
                    }

                    let addresses: Vec<String> = destinations
                        .iter()
                        .filter_map(|dest| match dest {
                            divi_script::Destination::PubKeyHash(pkh) => {
                                let mut bytes = [0u8; 20];
                                bytes.copy_from_slice(&pkh[..]);
                                let addr = Address::from_pubkey_hash(
                                    Hash160::from_bytes(bytes),
                                    Network::Mainnet,
                                );
                                Some(addr.to_base58())
                            }
                            divi_script::Destination::ScriptHash(sh) => {
                                let mut bytes = [0u8; 20];
                                bytes.copy_from_slice(&sh[..]);
                                let addr =
                                    Address::p2sh(Hash160::from_bytes(bytes), Network::Mainnet);
                                Some(addr.to_base58())
                            }
                        })
                        .collect();

                    if !addresses.is_empty() {
                        script_obj["addresses"] = serde_json::json!(addresses);
                    }
                }

                serde_json::json!({
                    "value": output.value.as_divi(),
                    "n": n,
                    "scriptPubKey": script_obj,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "txid": txid_value,
            "baretxid": txid_value,
            "version": tx.version,
            "locktime": tx.lock_time,
            "vin": vin,
            "vout": vout,
        }))
    }

    /// getaddressesbylabel - Get addresses with a label
    pub fn get_addresses_by_label(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        // For now, return all addresses (labels not implemented)
        let addresses = wallet.get_addresses();
        let result: serde_json::Map<String, serde_json::Value> = addresses
            .iter()
            .map(|addr| {
                (
                    addr.to_string(),
                    serde_json::json!({ "purpose": "receive" }),
                )
            })
            .collect();

        Ok(serde_json::json!(result))
    }

    /// listreceivedbyaddress - List amounts received by address
    pub fn list_received_by_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let min_conf = params.get_u64(0).unwrap_or(1) as u32;
        let _include_empty = params.get_bool(1).unwrap_or(false);

        let height = self.current_height();
        let utxos = wallet.get_utxos();

        // Aggregate by address
        let mut by_addr: std::collections::HashMap<String, (i64, u32)> =
            std::collections::HashMap::new();

        for utxo in utxos {
            let confs = utxo.confirmations(height);
            if confs >= min_conf {
                let entry = by_addr.entry(utxo.address.clone()).or_insert((0, u32::MAX));
                entry.0 += utxo.value.as_sat() as i64;
                if confs < entry.1 {
                    entry.1 = confs;
                }
            }
        }

        let result: Vec<_> = by_addr
            .iter()
            .map(|(addr, (amount, confs))| {
                let divi = *amount as f64 / 100_000_000.0;
                serde_json::json!({
                    "address": addr,
                    "amount": divi,
                    "confirmations": confs,
                    "label": "",
                })
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
        let address = Address::from_base58(address_str)
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

        // Parse funding transaction ID
        let funding_txid = Hash256::from_hex(funding_tx).map_err(|_| {
            RpcError::invalid_params(format!("Invalid transaction ID: {}", funding_tx))
        })?;

        // Verify transaction exists in chain
        let chain = self
            .chain
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Chain not available"))?;

        let tx = chain
            .get_transaction(&funding_txid)
            .map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Failed to query transaction: {}", e),
                )
            })?
            .ok_or_else(|| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Transaction {} not found", funding_tx),
                )
            })?;

        // Verify transaction has output paying to vault script
        let vault_script_bytes = vault_script.as_bytes();
        let has_vault_output = tx
            .vout
            .iter()
            .any(|out| out.script_pubkey.as_bytes() == vault_script_bytes);

        if !has_vault_output {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!(
                    "Transaction {} does not pay to the specified vault script",
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

            wallet.scan_transaction(&fund_tx, Some(location.block_hash), height);
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

        // Return success
        Ok(json!({
            "result": "success",
            "message": format!("Vault {} added successfully", vault_addresses)
        }))
    }

    /// Remove a vault - Vault manager rejects staking a vault script
    pub fn remove_vault(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let vault_addresses = params.get_str(0).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: owner_address:manager_address")
        })?;
        let tx_hash = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: tx_hash"))?;

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

        Ok(serde_json::json!({
            "result": "success",
            "message": format!("Vault {} removed successfully", vault_addresses),
            "tx_hash": tx_hash
        }))
    }

    /// Get coin availability - Show available vault funds
    pub fn get_coin_availability(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let chain = self
            .chain
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::INTERNAL_ERROR, "Chain not available"))?;

        let height = chain.height();

        // Get all vaults
        let vaults = wallet.get_all_vaults();
        let total_vaults = vaults.len();

        // Get vault UTXOs (mature, confirmed vault outputs)
        let vault_utxos = wallet.get_vault_utxos(height, 1);

        // Group by vault script and calculate totals
        let mut vault_balances = std::collections::HashMap::new();
        for utxo in vault_utxos {
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
                "balance": balance.as_divi(),
                "balance_sat": balance.as_sat()
            }));
        }

        Ok(json!({
            "vaults": result,
            "total_vaults": total_vaults
        }))
    }

    /// Fund a vault - Adds funds to existing vault
    pub fn fund_vault(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

        let vault_encoding = params.get_str(0).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: [owner_address:]manager_address")
        })?;

        let amount_divi = params
            .get(1)
            .and_then(|v| v.as_f64())
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: amount"))?;

        let send_amount = Amount::from_sat((amount_divi * 100_000_000.0) as i64);

        let (owner_addr, manager_addr) = self.parse_vault_encoding(vault_encoding)?;

        let owner_hash = if let Some(ref addr) = owner_addr {
            self.address_to_hash160(addr)?
        } else {
            return Err(RpcError::invalid_params(
                "Owner address is required for funding vault. Use format: owner_address:manager_address"
            ).into());
        };

        let manager_hash = self.address_to_hash160(&manager_addr)?;

        let vault_script = StakingVaultScript::new(owner_hash, manager_hash).to_script();

        let height = self.current_height();

        // Get spendable UTXOs (1 confirmation minimum)
        let mut utxos = wallet.get_spendable_utxos(height, 1);

        // Sort by value descending for simple coin selection
        utxos.sort_by(|a, b| b.value.cmp(&a.value));

        // Fee estimation: ~1000 satoshis per input + 500 per output
        let base_fee = Amount::from_sat(1000);
        let per_input_fee = Amount::from_sat(1000);
        let per_output_fee = Amount::from_sat(500);

        // Simple coin selection: select UTXOs until we have enough
        let mut selected = Vec::new();
        let mut total_input = Amount::ZERO;
        let min_output = Amount::from_sat(546); // Dust limit

        for utxo in utxos {
            selected.push(utxo.clone());
            total_input = total_input + utxo.value;

            // Calculate required amount (send + fee estimate)
            let num_inputs = selected.len() as i64;
            let est_fee = base_fee
                + Amount::from_sat(
                    per_input_fee.as_sat() * num_inputs + per_output_fee.as_sat() * 2,
                );
            let required = send_amount + est_fee;

            if total_input >= required {
                break;
            }
        }

        // Check if we have enough funds
        let num_inputs = selected.len() as i64;
        let fee = base_fee
            + Amount::from_sat(per_input_fee.as_sat() * num_inputs + per_output_fee.as_sat() * 2);
        let required = send_amount + fee;

        if total_input < required {
            return Err(RpcError::new(
                codes::WALLET_INSUFFICIENT_FUNDS,
                format!(
                    "Insufficient funds. Have {} DIVI, need {} DIVI",
                    total_input.as_sat() as f64 / 100_000_000.0,
                    required.as_sat() as f64 / 100_000_000.0
                ),
            )
            .into());
        }

        // Get change address
        let change_addr = wallet.new_change_address().map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("Failed to generate change address: {}", e),
            )
        })?;

        // Build the transaction
        let mut builder = TransactionBuilder::new();

        // Add inputs
        for utxo in &selected {
            builder = builder.add_input(utxo.outpoint(), utxo.script_pubkey.clone());
        }

        // Add vault output
        let vault_script_bytes = vault_script.as_bytes().to_vec();
        builder = builder.add_output(send_amount, vault_script);

        // Add change output if significant
        let change_amount = total_input - send_amount - fee;
        if change_amount >= min_output {
            builder = builder.add_output_to_address(change_amount, &change_addr);
        }

        let (mut tx, prev_scripts) = builder.build();

        // Sign the transaction
        let signer = TransactionSigner::new(wallet.keystore());
        let signed_count = signer
            .sign_all_inputs(&mut tx, &prev_scripts)
            .map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Failed to sign transaction: {}", e),
                )
            })?;

        if signed_count != selected.len() {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!("Only signed {} of {} inputs", signed_count, selected.len()),
            )
            .into());
        }

        // Calculate txid
        let txid = tx.txid();

        // Submit to mempool and broadcast
        self.submit_transaction(tx)?;

        // Register the vault in the wallet so it can be tracked for staking/reclaiming
        let metadata = VaultMetadata {
            owner_address: owner_addr.unwrap(),
            manager_address: manager_addr,
            vault_script: vault_script_bytes,
            funding_txid: *txid.as_bytes(),
        };
        wallet.store_vault(metadata);

        info!(
            "Funded vault {} with {} DIVI (txid: {})",
            vault_encoding, amount_divi, txid
        );

        Ok(serde_json::json!(txid.to_string()))
    }

    /// Debit vault by name - Withdraws funds from vault using vault manager key (coinstake only)
    pub fn debit_vault_by_name(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let vault_encoding = params.get_str(0).ok_or_else(|| {
            RpcError::invalid_params("Missing required parameter: vault-encoding")
        })?;
        let destination = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: diviaddress"))?;
        let amount = params
            .get(2)
            .and_then(|v| v.as_f64())
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: amount"))?;
        let _fee_mode = params.get_str(3);

        let (owner_addr, manager_addr) = self.parse_vault_encoding(vault_encoding)?;
        let _ = Address::from_base58(destination)
            .map_err(|e| RpcError::invalid_params(format!("Invalid destination address: {}", e)))?;

        let owner_hash = if let Some(ref addr) = owner_addr {
            self.address_to_hash160(addr)?
        } else {
            return Err(RpcError::invalid_params(
                "Owner address is required. Use format: owner_address:manager_address",
            )
            .into());
        };
        let manager_hash = self.address_to_hash160(&manager_addr)?;

        let _vault_script = StakingVaultScript::new(owner_hash, manager_hash).to_script();

        Err(RpcError::new(
            codes::INTERNAL_ERROR,
            format!(
                "debitvaultbyname not yet implemented. This command requires coinstake creation, which is outside the current scope. The vault manager can ONLY spend vault funds via coinstake transactions (OP_REQUIRE_COINSTAKE enforces this). This command would create a coinstake spending {} DIVI from vault {} to {}. Full implementation requires: (1) Coinstake transaction building, (2) Kernel hash computation, (3) Proof-of-stake validation",
                amount, vault_encoding, destination
            )
        ).into())
    }

    /// Reclaim vault funds - Withdraw from vault using owner key (can spend anytime)
    pub fn reclaim_vault_funds(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

        let destination = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: diviaddress"))?;

        let amount_divi = params
            .get(1)
            .and_then(|v| v.as_f64())
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: amount"))?;

        let send_amount = Amount::from_sat((amount_divi * 100_000_000.0) as i64);

        let dest_addr = Address::from_base58(destination)
            .map_err(|e| RpcError::invalid_params(format!("Invalid destination address: {}", e)))?;

        let chain = self
            .chain
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::INTERNAL_ERROR, "Chain not available"))?;
        let height = chain.height();

        let vault_utxos = wallet.get_vault_utxos(height, 1);

        if vault_utxos.is_empty() {
            return Err(
                RpcError::new(codes::WALLET_ERROR, "No vault funds available to reclaim").into(),
            );
        }

        // Filter vault UTXOs to only those where we have the owner's private key
        let keystore = wallet.keystore();
        let owned_vault_utxos: Vec<_> = vault_utxos
            .into_iter()
            .filter(|utxo| {
                if let Some(vault) =
                    divi_script::StakingVaultScript::from_script(&utxo.script_pubkey)
                {
                    let owner_hash =
                        divi_primitives::hash::Hash160::from_bytes(vault.owner_pubkey_hash);
                    if let Some(entry) = keystore.get_key(&owner_hash) {
                        !entry.is_watch_only && entry.secret.is_some()
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .collect();

        if owned_vault_utxos.is_empty() {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                "No vault funds available to reclaim (no owner keys found for any vaults)",
            )
            .into());
        }

        let mut selected = Vec::new();
        let mut total_input = Amount::ZERO;

        for utxo in owned_vault_utxos {
            selected.push(utxo.clone());
            total_input = total_input + utxo.value;

            let base_fee = Amount::from_sat(1000);
            let per_input_fee = Amount::from_sat(1000);
            let per_output_fee = Amount::from_sat(500);
            let fee = base_fee
                + Amount::from_sat(
                    per_input_fee.as_sat() * selected.len() as i64 + per_output_fee.as_sat() * 2,
                );

            if total_input >= send_amount + fee {
                break;
            }
        }

        let base_fee = Amount::from_sat(1000);
        let per_input_fee = Amount::from_sat(1000);
        let per_output_fee = Amount::from_sat(500);
        let final_fee = base_fee
            + Amount::from_sat(
                per_input_fee.as_sat() * selected.len() as i64 + per_output_fee.as_sat() * 2,
            );

        if total_input < send_amount + final_fee {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!(
                    "Insufficient vault funds. Have {}, need {}",
                    total_input.as_divi(),
                    (send_amount + final_fee).as_divi()
                ),
            )
            .into());
        }

        let change_amount = total_input - send_amount - final_fee;

        let change_addr = wallet.new_change_address().map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("Failed to generate change address: {}", e),
            )
        })?;

        let mut builder = TransactionBuilder::new();
        for utxo in &selected {
            builder = builder.add_input(utxo.outpoint(), utxo.script_pubkey.clone());
        }
        builder = builder.add_output_to_address(send_amount, &dest_addr);

        let min_output = Amount::from_sat(546);
        if change_amount >= min_output {
            builder = builder.add_output_to_address(change_amount, &change_addr);
        }

        let (mut tx, prev_scripts) = builder.build();

        // NOTE: Vault scripts use OP_IF with owner key in the true branch (push 1).
        // TransactionSigner must have the owner's private key to sign successfully.
        let signer = TransactionSigner::new(wallet.keystore());
        let signed_count = signer
            .sign_all_inputs(&mut tx, &prev_scripts)
            .map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Failed to sign transaction: {}", e),
                )
            })?;

        if signed_count != selected.len() {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!(
                    "Only signed {}/{} inputs. Wallet may not have owner keys for all vaults.",
                    signed_count,
                    selected.len()
                ),
            )
            .into());
        }

        let txid = tx.txid();
        self.submit_transaction(tx)?;

        Ok(json!({
            "txid": txid.to_string(),
            "amount": send_amount.as_divi(),
            "fee": final_fee.as_divi()
        }))
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
        let addr = Address::from_base58(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        // Get wallet and check if locked
        let wallet = self.get_wallet()?;

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

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

        // Encrypt using BIP38 (always use compressed for modern wallets)
        let encrypted = divi_crypto::bip38_encrypt(&key_array, passphrase, true).map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("BIP38 encryption failed: {}", e),
            )
        })?;

        Ok(json!(encrypted))
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

        // Determine network from wallet, defaulting to mainnet
        let wallet_guard = self.wallet.read();
        let network = wallet_guard
            .as_ref()
            .map(|w| w.network())
            .unwrap_or(Network::Mainnet);
        drop(wallet_guard);

        // Encode as WIF
        use divi_wallet::address::encode_wif;
        let wif = encode_wif(&private_key, compressed, network);

        Ok(json!(wif))
    }

    /// Load wallet from file
    pub fn load_wallet(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let _filename = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: filename"))?;

        Err(RpcError::new(
            codes::WALLET_ERROR,
            "Multiple wallet support not yet implemented. IronDivi currently supports one active wallet at a time. To use a different wallet, restart IronDivi with the -wallet=<filename> option. Multi-wallet support will be added in a future release."
        ).into())
    }

    /// Get lottery block winners
    pub fn get_lottery_block_winners(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let _height = params
            .get_i64(0)
            .ok_or_else(|| RpcError::invalid_params("Missing required parameter: block_height"))?;

        Err(RpcError::new(
            codes::INTERNAL_ERROR,
            "Lottery functionality is a Divi-specific feature that requires lottery subsystem implementation. The Divi lottery system randomly selects winning addresses from staking participants and distributes lottery rewards at specific block heights. This feature will be added in a future release. For lottery information, please use the C++ Divi client."
        ).into())
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
            codes::INTERNAL_ERROR,
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

        // Get network from wallet if available, otherwise default to Mainnet
        let network = self
            .wallet
            .read()
            .as_ref()
            .map(|w| w.network())
            .unwrap_or(Network::Mainnet);

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
        // Get account (ignored for now, legacy feature)
        let _account = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Account required"))?;

        // Get amounts object {"address": amount, ...}
        let amounts = params
            .get(1)
            .and_then(|v| v.as_object())
            .ok_or_else(|| RpcError::invalid_params("Amounts object required"))?;

        // Optional minconf (default 1)
        let min_conf = params.get_u64(2).unwrap_or(1) as u32;

        // Optional comment (ignored)
        let _comment = params.get_str(3);

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

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

        let height = self.current_height();

        // Parse and validate all outputs first
        let mut outputs: Vec<(Address, Amount)> = Vec::new();
        let mut total_send = Amount::ZERO;

        for (addr_str, amount_value) in amounts {
            let amount_divi = amount_value.as_f64().ok_or_else(|| {
                RpcError::invalid_params(format!("Invalid amount for {}", addr_str))
            })?;

            if amount_divi <= 0.0 {
                return Err(RpcError::invalid_params(format!(
                    "Invalid amount for {}: must be positive",
                    addr_str
                ))
                .into());
            }

            let amount = Amount::from_sat((amount_divi * 100_000_000.0) as i64);
            let addr = Address::from_base58(addr_str).map_err(|_| {
                RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    format!("Invalid address: {}", addr_str),
                )
            })?;

            outputs.push((addr, amount));
            total_send = total_send + amount;
        }

        if outputs.is_empty() {
            return Err(RpcError::invalid_params("No recipients specified").into());
        }

        // Get spendable UTXOs
        let mut utxos = wallet.get_spendable_utxos(height, min_conf);
        utxos.sort_by(|a, b| b.value.cmp(&a.value));

        // Simple coin selection
        let base_fee = Amount::from_sat(1000);
        let per_input_fee = Amount::from_sat(1000);
        let per_output_fee = Amount::from_sat(500);

        let mut selected = Vec::new();
        let mut total_input = Amount::ZERO;
        let num_outputs = outputs.len() as i64 + 1; // +1 for change

        for utxo in utxos {
            selected.push(utxo.clone());
            total_input = total_input + utxo.value;

            let num_inputs = selected.len() as i64;
            let est_fee = base_fee
                + Amount::from_sat(
                    per_input_fee.as_sat() * num_inputs + per_output_fee.as_sat() * num_outputs,
                );
            let required = total_send + est_fee;

            if total_input >= required {
                break;
            }
        }

        // Check if we have enough funds
        let num_inputs = selected.len() as i64;
        let fee = base_fee
            + Amount::from_sat(
                per_input_fee.as_sat() * num_inputs + per_output_fee.as_sat() * num_outputs,
            );
        let required = total_send + fee;

        if total_input < required {
            return Err(RpcError::new(
                codes::WALLET_INSUFFICIENT_FUNDS,
                format!(
                    "Insufficient funds. Have {} DIVI, need {} DIVI",
                    total_input.as_sat() as f64 / 100_000_000.0,
                    required.as_sat() as f64 / 100_000_000.0
                ),
            )
            .into());
        }

        let mut adjusted_outputs = outputs.clone();
        let mut adjusted_total_send = total_send;

        if !subtract_fee_from.is_empty() {
            let fee_per_output = Amount::from_sat(fee.as_sat() / subtract_fee_from.len() as i64);

            for (addr, amount) in adjusted_outputs.iter_mut() {
                let addr_str = addr.to_base58();
                if subtract_fee_from.contains(&addr_str) {
                    if *amount <= fee_per_output {
                        return Err(RpcError::invalid_params(format!(
                            "Amount for {} is too small to subtract fee from",
                            addr_str
                        ))
                        .into());
                    }
                    *amount = *amount - fee_per_output;
                    adjusted_total_send = adjusted_total_send - fee_per_output;
                }
            }
        }

        // Get change address
        let change_addr = wallet.new_change_address().map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("Failed to generate change address: {}", e),
            )
        })?;

        // Build transaction
        let mut builder = TransactionBuilder::new();

        // Add inputs
        for utxo in &selected {
            builder = builder.add_input(utxo.outpoint(), utxo.script_pubkey.clone());
        }

        for (addr, amount) in adjusted_outputs {
            builder = builder.add_output_to_address(amount, &addr);
        }

        // Add change output if significant
        let min_output = Amount::from_sat(546); // Dust limit
        let change_amount = total_input - adjusted_total_send - fee;
        if change_amount >= min_output {
            builder = builder.add_output_to_address(change_amount, &change_addr);
        }

        let (mut tx, prev_scripts) = builder.build();

        // Sign the transaction
        let signer = TransactionSigner::new(wallet.keystore());
        let signed_count = signer
            .sign_all_inputs(&mut tx, &prev_scripts)
            .map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Failed to sign transaction: {}", e),
                )
            })?;

        if signed_count != selected.len() {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!("Only signed {} of {} inputs", signed_count, selected.len()),
            )
            .into());
        }

        // Calculate txid and submit
        let txid = tx.txid();
        self.submit_transaction(tx)?;

        info!("Sent to {} addresses (txid: {})", amounts.len(), txid);

        Ok(serde_json::json!(txid.to_string()))
    }

    /// walletpassphrasechange - Change wallet passphrase
    pub fn wallet_passphrase_change(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let old_passphrase = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Old passphrase required"))?;
        let new_passphrase = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("New passphrase required"))?;

        if old_passphrase.is_empty() || new_passphrase.is_empty() {
            return Err(RpcError::invalid_params("Passphrases cannot be empty").into());
        }

        let wallet = self.get_wallet()?;

        if !wallet.is_encrypted() {
            return Err(
                RpcError::new(codes::WALLET_WRONG_ENC_STATE, "Wallet is not encrypted").into(),
            );
        }

        // Change the passphrase
        wallet
            .change_passphrase(old_passphrase, new_passphrase)
            .map_err(|_| {
                RpcError::new(codes::WALLET_PASSPHRASE_INCORRECT, "Incorrect passphrase")
            })?;

        Ok(serde_json::Value::Null)
    }

    /// getreceivedbyaddress - Get total amount received by an address
    pub fn get_received_by_address(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;

        let min_conf = params.get_u64(1).unwrap_or(1) as u32;

        let addr = Address::from_base58(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        let wallet = self.get_wallet()?;

        if !wallet.is_mine(&addr) {
            return Ok(serde_json::json!(0.0));
        }

        let height = self.current_height();
        let utxos = wallet.get_utxos();

        // Sum all UTXOs for this address with sufficient confirmations
        let mut total = 0i64;
        for utxo in utxos {
            if utxo.address == addr_str && utxo.confirmations(height) >= min_conf {
                total += utxo.value.as_sat();
            }
        }

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
        let addr = if let Ok(address) = Address::from_base58(addr_or_script) {
            address
        } else {
            // Try as hex script
            let script_bytes = hex::decode(addr_or_script)
                .map_err(|_| RpcError::invalid_params("Invalid address or script hex"))?;

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

        if wallet.is_mine(&addr) {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                "The wallet already contains the private key for this address",
            )
            .into());
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

        // Rescan blockchain if requested
        if rescan {
            info!("Note: Blockchain rescan for watch-only address not yet fully implemented");
            // TODO: Trigger blockchain rescan to find historical transactions
            // For now, only new transactions will be tracked
        }

        // Save wallet
        wallet.save().map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to save wallet: {}", e))
        })?;

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
            if let Ok(addr) = Address::from_base58(key_str) {
                // Get pubkey from wallet
                if let Some(key_entry) = wallet.get_key_by_address(&addr) {
                    pubkeys.push(key_entry.public.to_bytes().to_vec());
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
        if nrequired >= 1 && nrequired <= 16 {
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
        if m >= 1 && m <= 16 {
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

        Ok(serde_json::json!({
            "address": p2sh_addr.to_base58(),
            "redeemScript": hex::encode(redeem_script.as_bytes())
        }))
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

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

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

        let amount_divi = params
            .get(2)
            .and_then(|v| v.as_f64())
            .ok_or_else(|| RpcError::invalid_params("Amount required"))?;

        let min_conf = params.get_u64(3).unwrap_or(1) as u32;
        let _comment = params.get_str(4);
        let _comment_to = params.get_str(5);

        if amount_divi <= 0.0 {
            return Err(RpcError::invalid_params("Amount must be positive").into());
        }

        let send_amount = Amount::from_sat((amount_divi * 100_000_000.0) as i64);

        let dest_addr = Address::from_base58(addr_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        let wallet = self.get_wallet()?;

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

        let height = self.current_height();

        // Get addresses for the specified account
        let account_addresses = wallet.get_addresses_by_account(account);

        if account_addresses.is_empty() && !account.is_empty() {
            return Err(RpcError::new(
                codes::WALLET_INVALID_ACCOUNT_NAME,
                format!("Account '{}' has no addresses", account),
            )
            .into());
        }

        // Get UTXOs only from account addresses
        let all_utxos = wallet.get_spendable_utxos(height, min_conf);
        let mut utxos: Vec<_> = if account.is_empty() {
            // Empty account means default account - use all addresses
            all_utxos
        } else {
            // Filter to only account addresses
            let account_addr_set: std::collections::HashSet<_> = account_addresses.iter().collect();
            all_utxos
                .into_iter()
                .filter(|utxo| account_addr_set.contains(&utxo.address))
                .collect()
        };

        utxos.sort_by(|a, b| b.value.cmp(&a.value));

        // Fee estimation
        let base_fee = Amount::from_sat(1000);
        let per_input_fee = Amount::from_sat(1000);
        let per_output_fee = Amount::from_sat(500);

        // Simple coin selection
        let mut selected = Vec::new();
        let mut total_input = Amount::ZERO;
        let min_output = Amount::from_sat(546);

        for utxo in utxos {
            selected.push(utxo.clone());
            total_input = total_input + utxo.value;

            let num_inputs = selected.len() as i64;
            let est_fee = base_fee
                + Amount::from_sat(
                    per_input_fee.as_sat() * num_inputs + per_output_fee.as_sat() * 2,
                );
            let required = send_amount + est_fee;

            if total_input >= required {
                break;
            }
        }

        // Check if we have enough funds from this account
        let num_inputs = selected.len() as i64;
        let fee = base_fee
            + Amount::from_sat(per_input_fee.as_sat() * num_inputs + per_output_fee.as_sat() * 2);
        let required = send_amount + fee;

        if total_input < required {
            return Err(RpcError::new(
                codes::WALLET_INSUFFICIENT_FUNDS,
                format!(
                    "Account '{}' has insufficient funds. Have {} DIVI, need {} DIVI",
                    account,
                    total_input.as_sat() as f64 / 100_000_000.0,
                    required.as_sat() as f64 / 100_000_000.0
                ),
            )
            .into());
        }

        // Get change address
        let change_addr = wallet.new_change_address().map_err(|e| {
            RpcError::new(
                codes::WALLET_ERROR,
                format!("Failed to generate change address: {}", e),
            )
        })?;

        // Build transaction
        let mut builder = TransactionBuilder::new();

        // Add inputs
        for utxo in &selected {
            builder = builder.add_input(utxo.outpoint(), utxo.script_pubkey.clone());
        }

        // Add destination output
        builder = builder.add_output_to_address(send_amount, &dest_addr);

        // Add change output if significant
        let change_amount = total_input - send_amount - fee;
        if change_amount >= min_output {
            builder = builder.add_output_to_address(change_amount, &change_addr);
        }

        let (mut tx, prev_scripts) = builder.build();

        // Sign the transaction
        let signer = TransactionSigner::new(wallet.keystore());
        let signed_count = signer
            .sign_all_inputs(&mut tx, &prev_scripts)
            .map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Failed to sign transaction: {}", e),
                )
            })?;

        if signed_count != selected.len() {
            return Err(RpcError::new(
                codes::WALLET_ERROR,
                format!("Only signed {} of {} inputs", signed_count, selected.len()),
            )
            .into());
        }

        // Calculate txid and submit
        let txid = tx.txid();
        self.submit_transaction(tx)?;

        info!(
            "Sent {} DIVI from account '{}' to {} (txid: {})",
            amount_divi, account, addr_str, txid
        );

        Ok(serde_json::json!(txid.to_string()))
    }

    /// listlockunspent - Returns list of temporarily unspendable outputs
    pub fn list_lock_unspent(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let locked = self.locked_utxos.read();
        let result: Vec<_> = locked
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
        let unlock = params
            .get_bool(0)
            .ok_or_else(|| RpcError::invalid_params("unlock parameter required"))?;

        let outputs_array = params
            .get(1)
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::invalid_params("outputs array required"))?;

        let mut locked = self.locked_utxos.write();

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

            if unlock {
                locked.remove(&outpoint);
            } else {
                locked.insert(outpoint);
            }
        }

        Ok(serde_json::Value::Bool(true))
    }

    /// dumphdinfo - Display HD wallet seed information
    pub fn dump_hd_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let wallet_guard = self.wallet.read();
        let wallet = wallet_guard
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Wallet not loaded"))?;

        if wallet.is_locked() {
            return Err(RpcError::new(
                codes::WALLET_UNLOCK_NEEDED,
                "Error: Please enter the wallet passphrase with walletpassphrase first.",
            )
            .into());
        }

        let mnemonic = wallet
            .mnemonic()
            .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "No mnemonic found in wallet"))?;

        let mnemonic_obj: Mnemonic = mnemonic
            .parse()
            .map_err(|e| RpcError::new(codes::WALLET_ERROR, format!("Invalid mnemonic: {}", e)))?;

        let seed = mnemonic_obj.to_seed("");
        let hdseed_hex = hex::encode(&seed[0..64]);

        Ok(serde_json::json!({
            "hdseed": hdseed_hex,
            "mnemonic": mnemonic,
            "mnemonicpassphrase": ""
        }))
    }

    /// backupwallet - Copy wallet.dat to destination
    pub fn backup_wallet(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let destination = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Destination path required"))?;

        let wallet = self.get_wallet()?;

        // Get the wallet database path
        let wallet_path = wallet.database_path();

        let src = std::path::Path::new(&wallet_path);
        let dst = std::path::Path::new(destination);

        // RocksDB uses a directory; legacy wallets use a single file.
        if src.is_dir() {
            Self::copy_dir_recursively(src, dst).map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Failed to backup wallet: {}", e),
                )
            })?;
        } else {
            // Ensure parent directory exists for file destination
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    RpcError::new(
                        codes::WALLET_ERROR,
                        format!("Failed to create destination directory: {}", e),
                    )
                })?;
            }
            std::fs::copy(src, dst).map_err(|e| {
                RpcError::new(
                    codes::WALLET_ERROR,
                    format!("Failed to backup wallet: {}", e),
                )
            })?;
        }

        info!("Wallet backed up to: {}", destination);
        Ok(serde_json::Value::Null)
    }

    fn copy_dir_recursively(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let dst_path = dst.join(entry.file_name());
            if ty.is_dir() {
                Self::copy_dir_recursively(&entry.path(), &dst_path)?;
            } else {
                std::fs::copy(entry.path(), dst_path)?;
            }
        }
        Ok(())
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
fn message_magic_hash(message: &[u8]) -> [u8; 32] {
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
        let address_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;
        let message = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Message required"))?;

        let wallet = self.get_wallet()?;

        if wallet.is_locked() {
            return Err(RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked").into());
        }

        // Parse address
        let address = Address::from_base58(address_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        // Get private key for this address
        let key_entry = wallet
            .keystore()
            .get_key_by_address(&address)
            .ok_or_else(|| {
                RpcError::new(
                    codes::INVALID_ADDRESS_OR_KEY,
                    "Private key for address not found in wallet",
                )
            })?;

        // Sign the message with recoverable signature - ensure not watch-only
        let secret = key_entry.secret.as_ref().ok_or_else(|| {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                "Address is watch-only, cannot sign messages",
            )
        })?;

        // Hash with the DarkNet magic prefix to match C++ Divi's CHashWriter protocol
        let hash = message_magic_hash(message.as_bytes());
        let signature = divi_crypto::sign_hash_recoverable(secret, &hash)
            .map_err(|e| RpcError::new(codes::INTERNAL_ERROR, format!("Signing failed: {}", e)))?;

        // Return base64-encoded signature (65 bytes: recovery_id + r + s)
        let sig_bytes = signature.to_compact_with_recovery();
        let sig_b64 = STANDARD.encode(sig_bytes);

        debug!("Signed message with address {}", address_str);
        // Return as plain string, not wrapped in json!()
        Ok(serde_json::Value::String(sig_b64))
    }

    /// verifymessage - Verify a signed message
    pub fn verify_message(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let address_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;
        let signature_b64 = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Signature required"))?;
        let message = params
            .get_str(2)
            .ok_or_else(|| RpcError::invalid_params("Message required"))?;

        // Parse address
        let address = Address::from_base58(address_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        // Decode base64 signature
        let sig_bytes = STANDARD.decode(signature_b64).map_err(|_| {
            RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid base64 signature")
        })?;

        // Parse recoverable signature
        let signature = divi_crypto::RecoverableSig::from_compact_with_recovery(&sig_bytes)
            .map_err(|_| {
                RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid signature format")
            })?;

        // Recover the public key from the signature using the DarkNet magic-prefixed hash
        let hash = message_magic_hash(message.as_bytes());
        let recovered_pubkey = signature.recover_from_hash(&hash).map_err(|_| {
            RpcError::new(
                codes::INVALID_ADDRESS_OR_KEY,
                "Failed to recover public key",
            )
        })?;

        // Derive address from recovered public key
        let recovered_address = Address::p2pkh(&recovered_pubkey, address.network);

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

            let pubkey = if key_str.len() == 66 || key_str.len() == 130 {
                divi_crypto::keys::PublicKey::from_hex(key_str).map_err(|_| {
                    RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid hex public key")
                })?
            } else {
                let address = Address::from_base58(key_str)
                    .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

                let wallet_guard = self.wallet.read();
                if let Some(wallet) = wallet_guard.as_ref() {
                    wallet
                        .keystore()
                        .get_key_by_address(&address)
                        .map(|entry| entry.public.clone())
                        .ok_or_else(|| {
                            RpcError::new(
                                codes::INVALID_ADDRESS_OR_KEY,
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

        for pubkey in &pubkeys {
            let pubkey_bytes = pubkey.to_bytes();
            redeem_script.push(pubkey_bytes.len() as u8);
            redeem_script.extend_from_slice(&pubkey_bytes);
        }

        redeem_script.push(0x50 + pubkeys.len() as u8);
        redeem_script.push(Opcode::OP_CHECKMULTISIG as u8);

        let script_hash = divi_crypto::hash160(&redeem_script);

        let network = self
            .wallet
            .read()
            .as_ref()
            .map(|w| w.network())
            .unwrap_or(Network::Mainnet);

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

        let address = Address::from_base58(address_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

        let wallet = self.get_wallet()?;
        let account = wallet.get_account(&address);

        Ok(serde_json::json!(account))
    }

    pub fn set_account(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let address_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Address required"))?;
        let account = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Account required"))?;

        let address = Address::from_base58(address_str)
            .map_err(|_| RpcError::new(codes::INVALID_ADDRESS_OR_KEY, "Invalid address"))?;

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

        let addresses = wallet.get_addresses_by_account(account);

        if let Some(existing_addr) = addresses.first() {
            return Ok(serde_json::json!(existing_addr));
        }

        let new_addr = wallet.new_receiving_address().map_err(|e| match e {
            divi_wallet::WalletError::WalletLocked => {
                RpcError::new(codes::WALLET_UNLOCK_NEEDED, "Wallet is locked")
            }
            _ => RpcError::new(codes::WALLET_ERROR, e.to_string()),
        })?;

        wallet.set_account(&new_addr, account);

        wallet.save().map_err(|e| {
            RpcError::new(codes::WALLET_ERROR, format!("Failed to save wallet: {}", e))
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
                            account_balance = account_balance + utxo.value;
                        }
                    }
                }
            }

            let divi = account_balance.as_sat() as f64 / 100_000_000.0;
            result.insert(account_name, serde_json::json!(divi));
        }

        Ok(serde_json::json!(result))
    }

    pub fn get_received_by_account(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let account = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Account required"))?;

        let min_conf = params.get_u64(1).unwrap_or(1) as u32;

        let wallet = self.get_wallet()?;
        let height = self.current_height();

        let addresses = wallet.get_addresses_by_account(account);
        let mut total = Amount::ZERO;

        for addr_str in addresses {
            let utxos = wallet.get_utxos();
            for utxo in utxos {
                if utxo.address == addr_str {
                    let confs = utxo.confirmations(height);
                    if confs >= min_conf {
                        total = total + utxo.value;
                    }
                }
            }
        }

        let divi = total.as_sat() as f64 / 100_000_000.0;
        Ok(serde_json::json!(divi))
    }

    pub fn list_received_by_account(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let wallet = self.get_wallet()?;

        let min_conf = params.get_u64(0).unwrap_or(1) as u32;
        let include_empty = params.get_bool(1).unwrap_or(false);
        let _include_watchonly = params.get_bool(2).unwrap_or(false);

        let height = self.current_height();
        let accounts = wallet.list_accounts();

        let mut result = Vec::new();

        for (account_name, addresses) in accounts {
            let mut account_total = Amount::ZERO;
            let mut min_confirmations = u32::MAX;

            for addr_str in addresses {
                let utxos = wallet.get_utxos();
                for utxo in utxos {
                    if utxo.address == addr_str {
                        let confs = utxo.confirmations(height);
                        if confs >= min_conf {
                            account_total = account_total + utxo.value;
                            if confs < min_confirmations {
                                min_confirmations = confs;
                            }
                        }
                    }
                }
            }

            if account_total > Amount::ZERO || include_empty {
                let divi = account_total.as_sat() as f64 / 100_000_000.0;
                result.push(serde_json::json!({
                    "account": account_name,
                    "amount": divi,
                    "confirmations": if min_confirmations == u32::MAX { 0 } else { min_confirmations }
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
        let list = received_list.as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["account"], "testaccount");
        assert_eq!(list[0]["amount"], 0.0);
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
}
