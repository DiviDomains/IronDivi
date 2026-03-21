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

//! JSON-RPC server
//!
//! HTTP server for handling JSON-RPC requests using axum.

use crate::blockchain::BlockchainRpc;
use crate::error::{Error, RpcError};
use crate::lite_wallet::LiteWalletRpc;
use crate::masternode::MasternodeRpc;
use crate::network::NetworkRpc;
use crate::protocol::{Params, Request, Response};
use crate::spork::SporkRpc;
use crate::staking::StakingRpc;
use crate::wallet::WalletRpc;
use divi_network::PeerManager;
use divi_storage::{AddressIndex, Chain};
use divi_wallet::WalletDb;

use axum::{
    extract::{Path, State},
    http::{header, Method, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info};

/// RPC server configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Listen address
    pub bind_address: SocketAddr,
    /// RPC username (optional)
    pub username: Option<String>,
    /// RPC password (optional)
    pub password: Option<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        RpcConfig {
            bind_address: "127.0.0.1:9998".parse().unwrap(),
            username: None,
            password: None,
        }
    }
}

/// Log configuration for RPC queries
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogConfigInfo {
    /// Maximum size of each log file in bytes
    pub max_file_size: u64,
    /// Number of log files to keep
    pub max_files: u32,
    /// Whether debug logging is enabled
    pub debug: bool,
    /// Whether logging to console instead of file
    pub print_to_console: bool,
}

/// RPC server state
pub struct RpcServer {
    blockchain: BlockchainRpc,
    network: RwLock<NetworkRpc>,
    wallet: WalletRpc,
    staking: StakingRpc,
    lite_wallet: RwLock<LiteWalletRpc>,
    masternode: MasternodeRpc,
    spork: SporkRpc,
    log_config: RwLock<Option<LogConfigInfo>>,
}

impl RpcServer {
    /// Create a new RPC server
    pub fn new(chain: Arc<Chain>) -> Self {
        RpcServer {
            blockchain: BlockchainRpc::new(chain.clone()),
            network: RwLock::new(NetworkRpc::new()),
            wallet: WalletRpc::with_chain(chain),
            staking: StakingRpc::new(),
            lite_wallet: RwLock::new(LiteWalletRpc::new()),
            masternode: MasternodeRpc::new(),
            spork: SporkRpc::new(),
            log_config: RwLock::new(None),
        }
    }

    /// Create a new RPC server with wallet
    pub fn with_wallet(chain: Arc<Chain>, wallet: Arc<WalletDb>) -> Self {
        RpcServer {
            blockchain: BlockchainRpc::new(chain.clone()),
            network: RwLock::new(NetworkRpc::new()),
            wallet: WalletRpc::with_wallet_and_chain(wallet, chain),
            staking: StakingRpc::new(),
            lite_wallet: RwLock::new(LiteWalletRpc::new()),
            masternode: MasternodeRpc::new(),
            spork: SporkRpc::new(),
            log_config: RwLock::new(None),
        }
    }

    /// Create a new RPC server with peer manager
    pub fn with_peer_manager(chain: Arc<Chain>, peer_manager: Arc<PeerManager>) -> Self {
        RpcServer {
            blockchain: BlockchainRpc::new(chain.clone()),
            network: RwLock::new(NetworkRpc::with_peer_manager(peer_manager)),
            wallet: WalletRpc::with_chain(chain),
            staking: StakingRpc::new(),
            lite_wallet: RwLock::new(LiteWalletRpc::new()),
            masternode: MasternodeRpc::new(),
            spork: SporkRpc::new(),
            log_config: RwLock::new(None),
        }
    }

    /// Create a new RPC server with wallet and peer manager
    pub fn with_wallet_and_peer_manager(
        chain: Arc<Chain>,
        wallet: Arc<WalletDb>,
        peer_manager: Arc<PeerManager>,
    ) -> Self {
        RpcServer {
            blockchain: BlockchainRpc::new(chain.clone()),
            network: RwLock::new(NetworkRpc::with_peer_manager(peer_manager)),
            wallet: WalletRpc::with_wallet_and_chain(wallet, chain),
            staking: StakingRpc::new(),
            lite_wallet: RwLock::new(LiteWalletRpc::new()),
            masternode: MasternodeRpc::new(),
            spork: SporkRpc::new(),
            log_config: RwLock::new(None),
        }
    }

    /// Set the address index for lite wallet services
    pub fn set_address_index(&self, chain: Arc<Chain>, index: Arc<AddressIndex>) {
        let mut lite_wallet = self.lite_wallet.write();
        lite_wallet.set_chain(chain);
        lite_wallet.set_address_index(index);
    }

    /// Get a reference to the staking RPC handler
    pub fn staking(&self) -> &StakingRpc {
        &self.staking
    }

    /// Get a reference to the wallet RPC handler
    pub fn wallet(&self) -> &WalletRpc {
        &self.wallet
    }

    /// Set the wallet
    pub fn set_wallet(&self, wallet: Arc<WalletDb>) {
        self.wallet.set_wallet(wallet);
    }

    /// Set the peer manager
    pub fn set_peer_manager(&self, peer_manager: Arc<PeerManager>) {
        self.network.write().set_peer_manager(peer_manager);
    }

    pub fn set_mempool(&self, mempool: Arc<dyn crate::blockchain::MempoolProvider>) {
        self.blockchain.set_mempool(mempool.clone());
        self.lite_wallet.write().set_mempool(mempool);
    }

    /// Set the masternode manager
    pub fn set_masternode_manager(&self, manager: divi_masternode::MasternodeManager) {
        self.masternode.set_manager(manager);
    }

    /// Update chain height (for wallet confirmations)
    pub fn set_height(&self, height: u32) {
        self.wallet.set_height(height);
    }

    /// Set the log configuration for RPC queries
    pub fn set_log_config(&self, config: LogConfigInfo) {
        *self.log_config.write() = Some(config);
    }

    /// Get current log configuration
    fn get_log_config(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let config = self.log_config.read();
        match &*config {
            Some(c) => Ok(serde_json::json!({
                "max_file_size": c.max_file_size,
                "max_file_size_mb": c.max_file_size / 1_048_576,
                "max_files": c.max_files,
                "debug": c.debug,
                "print_to_console": c.print_to_console
            })),
            None => Ok(serde_json::json!({
                "error": "Log configuration not available"
            })),
        }
    }

    /// Set log configuration (note: only debug level can be changed at runtime)
    fn set_log_config_rpc(&self, params: &Params) -> Result<serde_json::Value, Error> {
        // Parse parameters
        let debug = params.get_bool(0);

        if let Some(debug_enabled) = debug {
            let mut config = self.log_config.write();
            if let Some(ref mut c) = *config {
                c.debug = debug_enabled;
                // Note: Actually changing the log level at runtime would require
                // using tracing_subscriber's reload functionality, which is more complex.
                // For now, we just update the stored config for informational purposes.
                return Ok(serde_json::json!({
                    "success": true,
                    "message": "Debug setting updated. Note: File size and count settings require restart.",
                    "debug": debug_enabled
                }));
            }
        }

        Err(
            RpcError::invalid_params("setlogconfig requires a boolean parameter for debug mode")
                .into(),
        )
    }

    /// Composite getinfo handler that pulls data from all subsystems.
    ///
    /// Unlike the old BlockchainRpc::get_info() which only had access to Chain,
    /// this method composes data from blockchain, network, wallet, and staking.
    fn get_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        use divi_consensus::bits_to_difficulty;
        use divi_network::constants::PROTOCOL_VERSION;
        use divi_storage::chain::NetworkType;

        let chain = self.blockchain.chain();
        let tip = chain.tip();
        let (height, difficulty) = match &tip {
            Some(t) => (t.height, bits_to_difficulty(t.bits)),
            None => (0, 1.0),
        };

        let network_type = chain.network_type();

        // Connection count from network subsystem
        let connections = self
            .network
            .read()
            .get_connection_count(&Params::None)
            .ok()
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Wallet data (balance, keypoololdest, keypoolsize)
        let (balance, keypoololdest, keypoolsize) = match self.wallet.get_wallet_info(&Params::None)
        {
            Ok(info) => (
                info["balance"].as_f64().unwrap_or(0.0),
                info["keypoololdest"].as_u64().unwrap_or(0),
                info["keypoolsize"].as_u64().unwrap_or(0),
            ),
            Err(_) => (0.0, 0, 0),
        };

        // Staking status from staking subsystem
        let staking_status_text = match self.staking.get_staking_status(&Params::None) {
            Ok(info) => info["staking status"]
                .as_str()
                .unwrap_or("Staking Not Active")
                .to_string(),
            Err(_) => "Staking Not Active".to_string(),
        };

        Ok(serde_json::json!({
            "version": 2000000,
            "protocolversion": PROTOCOL_VERSION,
            "blocks": height,
            "timeoffset": 0,
            "connections": connections,
            "proxy": "",
            "difficulty": difficulty,
            "testnet": matches!(network_type, NetworkType::Testnet),
            "moneysupply": 0, // TODO: cache from UTXO set — calling get_utxo_stats() on every getinfo is too expensive
            "keypoololdest": keypoololdest,
            "keypoolsize": keypoolsize,
            "balance": balance,
            "paytxfee": 0.0,
            "relayfee": 0.0001,
            "staking status": staking_status_text,
            "errors": ""
        }))
    }

    /// Handle a single RPC request
    pub fn handle_request(&self, request: Request) -> Response {
        let id = request.id.clone();

        match self.dispatch(&request.method, &request.params) {
            Ok(result) => Response::success(id, result),
            Err(Error::Rpc(rpc_err)) => Response::error(id, rpc_err),
            Err(e) => Response::error(id, RpcError::internal_error(e.to_string())),
        }
    }

    /// Dispatch a method call
    fn dispatch(&self, method: &str, params: &Params) -> Result<serde_json::Value, Error> {
        match method {
            // Blockchain methods
            "getblockcount" => self.blockchain.get_block_count(params),
            "getbestblockhash" => self.blockchain.get_best_block_hash(params),
            "getblockhash" => self.blockchain.get_block_hash(params),
            "getblock" => self.blockchain.get_block(params),
            "getblockheader" => self.blockchain.get_block_header(params),
            "getblockchaininfo" => self.blockchain.get_blockchain_info(params),
            "getinfo" => self.get_info(params),
            "getchaintips" => self.blockchain.get_chain_tips(params),
            "getdifficulty" => self.blockchain.get_difficulty(params),
            "gettxoutsetinfo" => self.blockchain.get_txout_set_info(params),
            "getrawmempool" => self.blockchain.get_raw_mempool(params),
            "prioritisetransaction" => self.blockchain.prioritise_transaction(params),
            "gettxout" => self.blockchain.get_tx_out(params),
            "decodescript" => self.blockchain.decode_script(params),
            "verifychain" => self.blockchain.verifychain(params),
            "getmininginfo" => self.blockchain.getmininginfo(params),

            // Address index methods
            "getaddressdeltas" => self.blockchain.get_address_deltas(params),
            "getaddresstxids" => self.blockchain.get_address_txids(params),
            "getspentinfo" => self.blockchain.get_spent_info(params),

            // Mining/generation methods
            "generateblock" => self.blockchain.generate_block(params),
            "setgenerate" => self.blockchain.set_generate(params),

            // Network methods
            "getnetworkinfo" => self.network.read().get_network_info(params),
            "getpeerinfo" => self.network.read().get_peer_info(params),
            "getconnectioncount" => self.network.read().get_connection_count(params),
            "ping" => self.network.read().ping(params),
            "getnettotals" => self.network.read().get_net_totals(params),
            "addnode" => self.network.read().add_node(params),
            "getaddednodeinfo" => self.network.read().get_added_node_info(params),
            "setban" => self.network.read().set_ban(params),
            "listbanned" => self.network.read().list_banned(params),
            "clearbanned" => self.network.read().clear_banned(params),
            "disconnectnode" => self.network.read().disconnect_node(params),
            "getpeerscores" => self.network.read().get_peer_scores(params),

            // Wallet methods
            "getnewaddress" => self.wallet.get_new_address(params),
            "getrawchangeaddress" => self.wallet.get_raw_change_address(params),
            "validateaddress" => self.wallet.validate_address(params),
            "getaddressinfo" => self.wallet.get_address_info(params),
            "getbalance" => self.wallet.get_balance(params),
            "getunconfirmedbalance" => self.wallet.get_unconfirmed_balance(params),
            "getimmaturebalance" => self.wallet.get_immature_balance(params),
            "getwalletinfo" => self.wallet.get_wallet_info(params),
            "listunspent" => self.wallet.list_unspent(params),
            "gettransaction" => self.wallet.get_transaction(params),
            "listtransactions" => self.wallet.list_transactions(params),
            "listsinceblock" => self.wallet.list_since_block(params),
            "walletpassphrase" => self.wallet.wallet_passphrase(params),
            "walletlock" => self.wallet.wallet_lock(params),
            "dumpprivkey" => self.wallet.dump_privkey(params),
            "dumphdinfo" => self.wallet.dump_hd_info(params),
            "importprivkey" => self.wallet.import_privkey(params),
            "rescanblockchain" => self.wallet.rescan_blockchain(params),
            "sendtoaddress" => self.wallet.send_to_address(params),
            "getaddressesbylabel" => self.wallet.get_addresses_by_label(params),
            "listreceivedbyaddress" => self.wallet.list_received_by_address(params),
            "backupwallet" => self.wallet.backup_wallet(params),
            "signmessage" => self.wallet.sign_message(params),
            "verifymessage" => self.wallet.verify_message(params),
            "createmultisig" => self.wallet.create_multisig(params),
            "getaccount" => self.wallet.get_account(params),
            "setaccount" => self.wallet.set_account(params),
            "getaccountaddress" => self.wallet.get_account_address(params),
            "getaddressesbyaccount" => self.wallet.get_addresses_by_account(params),
            "listaccounts" => self.wallet.list_accounts(params),
            "getreceivedbyaccount" => self.wallet.get_received_by_account(params),
            "listreceivedbyaccount" => self.wallet.list_received_by_account(params),
            "sendmany" => self.wallet.send_many(params),
            "sendfrom" => self.wallet.send_from(params),
            "walletpassphrasechange" => self.wallet.wallet_passphrase_change(params),
            "getreceivedbyaddress" => self.wallet.get_received_by_address(params),
            "importaddress" => self.wallet.import_address(params),
            "addmultisigaddress" => self.wallet.add_multisig_address(params),
            "keypoolrefill" => self.wallet.keypool_refill(params),
            "getkeypoolsize" => self.wallet.get_keypool_size(params),
            "bip38encrypt" => self.wallet.bip38_encrypt(params),
            "bip38decrypt" => self.wallet.bip38_decrypt(params),
            "loadwallet" => self.wallet.load_wallet(params),
            "getlotteryblockwinners" => self.wallet.get_lottery_block_winners(params),
            "allocatefunds" => self.wallet.allocate_funds(params),

            // Raw transaction methods
            "createrawtransaction" => self.wallet.create_raw_transaction(params),
            "signrawtransaction" => self.wallet.sign_raw_transaction(params),
            "signrawtransactionwithwallet" => self.wallet.sign_raw_transaction(params),
            "sendrawtransaction" => self.wallet.send_raw_transaction(params),
            "getrawtransaction" => self.wallet.get_raw_transaction(params),
            "decoderawtransaction" => self.wallet.decode_raw_transaction(params),
            "listlockunspent" => self.wallet.list_lock_unspent(params),
            "lockunspent" => self.wallet.lock_unspent(params),

            // Staking methods
            "getstakingstatus" => self.staking.get_staking_status(params),
            "getmintinginfo" => self.staking.get_minting_info(params),
            "setstaking" => self.staking.set_staking(params),
            "reservebalance" => self.staking.reserve_balance(params),

            // Lite wallet methods (external address queries)
            "getaddressbalance" => self.lite_wallet.read().get_address_balance(params),
            "getaddressutxos" => self.lite_wallet.read().get_address_utxos(params),
            "getaddresshistory" => self.lite_wallet.read().get_address_history(params),
            "gettxindex" => self.lite_wallet.read().get_tx_index(params),
            "estimatefee" => self.lite_wallet.read().estimate_fee(params),
            "estimatesmartfee" => self.lite_wallet.read().estimate_smart_fee(params),
            "estimatepriority" => self.lite_wallet.read().estimate_priority(params),
            "getmempoolinfo" => self.lite_wallet.read().get_mempool_info(params),
            "validateaddresses" => self.lite_wallet.read().validate_addresses(params),
            "getlitewalletinfo" => self.lite_wallet.read().get_lite_wallet_info(params),

            // Masternode methods
            "getmasternodecount" => self.masternode.get_masternode_count(params),
            "getmasternodestatus" => self.masternode.get_masternode_status(params),
            "getmasternodewinners" => self.masternode.get_masternode_winners(params),
            "listmasternodes" => self.masternode.list_masternodes(params),
            "setupmasternode" => self.masternode.setup_masternode(params),
            "startmasternode" => self.masternode.start_masternode(params),
            "broadcaststartmasternode" => self.masternode.broadcast_start_masternode(params),
            "signmnbroadcast" => self.masternode.sign_mn_broadcast(params),
            "importmnbroadcast" => self.masternode.import_mn_broadcast(params),
            "listmnbroadcasts" => self.masternode.list_mn_broadcasts(params),
            "verifymasternodesetup" => self.masternode.verify_masternode_setup(params),
            "mnsync" => self.masternode.mnsync(params),

            // Spork methods
            "spork" => self.spork.spork(params),

            // Vault methods
            "addvault" => self.wallet.add_vault(params),
            "removevault" => self.wallet.remove_vault(params),
            "getcoinavailability" => self.wallet.get_coin_availability(params),
            "fundvault" => self.wallet.fund_vault(params),
            "debitvaultbyname" => self.wallet.debit_vault_by_name(params),
            "reclaimvaultfunds" => self.wallet.reclaim_vault_funds(params),

            // Logging methods
            "getlogconfig" => self.get_log_config(params),
            "setlogconfig" => self.set_log_config_rpc(params),

            // Utility methods
            "help" => self.help(params),
            "stop" => self.stop(params),

            // Unknown method
            _ => Err(RpcError::method_not_found(method).into()),
        }
    }

    /// Help method - list available methods
    fn help(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let method = params.get_str(0);

        if let Some(method) = method {
            // Return help for specific method
            let help = match method {
                // Blockchain
                "getblockcount" => "getblockcount\n\nReturns the number of blocks in the longest blockchain.",
                "getbestblockhash" => "getbestblockhash\n\nReturns the hash of the best (tip) block in the longest blockchain.",
                "getblockhash" => "getblockhash height\n\nReturns hash of block in best-block-chain at height provided.",
                "getblock" => "getblock \"blockhash\" ( verbosity )\n\nIf verbosity is 0, returns hex-encoded data.\nIf verbosity is 1 (default), returns a JSON object.\nIf verbosity is 2, returns JSON object with transaction data.",
                "getblockheader" => "getblockheader \"blockhash\" ( verbose )\n\nIf verbose is false, returns hex-encoded data.\nIf verbose is true (default), returns a JSON object.",
                "getblockchaininfo" => "getblockchaininfo\n\nReturns an object containing various state info regarding blockchain processing.",
                "getchaintips" => "getchaintips\n\nReturn information about all known tips in the block tree.",
                "getdifficulty" => "getdifficulty\n\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.",
                "gettxoutsetinfo" => "gettxoutsetinfo\n\nReturns statistics about the unspent transaction output set.",
                "getrawmempool" => "getrawmempool\n\nReturns all transaction ids in memory pool.",
                "prioritisetransaction" => "prioritisetransaction <txid> <priority delta> <fee delta>\n\nAccepts the transaction into mined blocks at a higher (or lower) priority.",
                "gettxout" => "gettxout \"txid\" n ( include_mempool )\n\nReturns details about an unspent transaction output.",
                "generateblock" => "generateblock ( options )\n\nTry to generate a single block with extra options (regtest only - not yet implemented).",
                "setgenerate" => "setgenerate numberofblocks\n\nGenerate blocks immediately (regtest only - not yet implemented).",
                // Network
                "getnetworkinfo" => "getnetworkinfo\n\nReturns an object containing various state info regarding P2P networking.",
                "getpeerinfo" => "getpeerinfo\n\nReturns data about each connected network node as a json array of objects.",
                "getconnectioncount" => "getconnectioncount\n\nReturns the number of connections to other nodes.",
                "ping" => "ping\n\nRequests that a ping be sent to all other nodes.",
                "getnettotals" => "getnettotals\n\nReturns information about network traffic, including bytes in, bytes out, and current time.",
                "addnode" => "addnode \"node\" \"command\"\n\nAttempts to add or remove a node from the addnode list.",
                "getaddednodeinfo" => "getaddednodeinfo ( \"node\" )\n\nReturns information about the given added node.",
                "setban" => "setban \"ip\" \"add|remove\" ( bantime ) ( absolute )\n\nAttempts add or remove an IP from the banned list.\n\nArguments:\n1. \"ip\"       (string, required) The IP (see getpeerinfo for nodes ip)\n2. \"command\"  (string, required) 'add' to add, 'remove' to remove\n3. bantime    (numeric, optional) Time in seconds (default: 86400)\n4. absolute   (boolean, optional) If set, bantime is absolute timestamp",
                "listbanned" => "listbanned\n\nList all banned IPs/subnets.",
                "clearbanned" => "clearbanned\n\nClear all banned IPs.",
                "disconnectnode" => "disconnectnode \"address\"\n\nDisconnects a peer by address.\n\nArguments:\n1. \"address\"  (string, required) The IP address:port of the node",
                "getpeerscores" => "getpeerscores\n\nReturns peer scoring and reliability information for debugging.",
                // Wallet
                "getnewaddress" => "getnewaddress ( \"label\" )\n\nReturns a new Divi address for receiving payments.",
                "getrawchangeaddress" => "getrawchangeaddress\n\nReturns a new Divi address for receiving change.",
                "validateaddress" => "validateaddress \"address\"\n\nReturn information about the given divi address.",
                "getaddressinfo" => "getaddressinfo \"address\"\n\nReturn information about the given divi address.",
                "getbalance" => "getbalance ( minconf )\n\nReturns the total available balance.",
                "getunconfirmedbalance" => "getunconfirmedbalance\n\nReturns the server's total unconfirmed balance.",
                "getimmaturebalance" => "getimmaturebalance\n\nReturns the server's total immature balance.",
                "getwalletinfo" => "getwalletinfo\n\nReturns an object containing various wallet state info.",
                "listunspent" => "listunspent ( minconf maxconf )\n\nReturns array of unspent transaction outputs.",
                "gettransaction" => "gettransaction \"txid\"\n\nGet detailed information about an in-wallet transaction.",
                "listtransactions" => "listtransactions ( count skip )\n\nReturns up to 'count' most recent transactions.",
                "listsinceblock" => "listsinceblock ( \"blockhash\" target_confirmations )\n\nGet all transactions in blocks since block [blockhash], or all transactions if omitted.",
                "walletpassphrase" => "walletpassphrase \"passphrase\" timeout\n\nUnlocks the wallet for 'timeout' seconds.",
                "walletlock" => "walletlock\n\nLocks the wallet.",
                "dumpprivkey" => "dumpprivkey \"address\"\n\nReveals the private key corresponding to 'address'.",
                "dumphdinfo" => "dumphdinfo\n\nReturns an object containing sensitive private info about this HD wallet.",
                "importprivkey" => "importprivkey \"privkey\" ( \"label\" rescan )\n\nAdds a private key to your wallet.",
                "sendtoaddress" => "sendtoaddress \"address\" amount\n\nSend an amount to a given address.",
                "getaddressesbylabel" => "getaddressesbylabel \"label\"\n\nReturns the list of addresses assigned the specified label.",
                "listreceivedbyaddress" => "listreceivedbyaddress ( minconf include_empty )\n\nList balances by receiving address.",
                "createmultisig" => "createmultisig nrequired [\"key\",...]\n\nCreates a multi-signature address with n signature of m keys required.\nReturns a json object with the address and redeemScript.",
                "getaccount" => "getaccount \"address\"\n\nReturns the account associated with the given address.",
                "setaccount" => "setaccount \"address\" \"account\"\n\nSets the account associated with the given address.",
                "getaccountaddress" => "getaccountaddress \"account\"\n\nReturns the current DIVI address for receiving payments to this account.",
                "getaddressesbyaccount" => "getaddressesbyaccount \"account\"\n\nReturns the list of addresses for the given account.",
                "listaccounts" => "listaccounts ( minconf includeWatchonly )\n\nReturns Object that has account names as keys, account balances as values.",
                "getreceivedbyaccount" => "getreceivedbyaccount \"account\" ( minconf )\n\nReturns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.",
                "listreceivedbyaccount" => "listreceivedbyaccount ( minconf includeempty includeWatchonly )\n\nList balances by account.",
                "sendmany" => "sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] )\n\nSend multiple times. Amounts are double-precision floating point numbers.\n\nArguments:\n1. \"fromaccount\"  (string, required) The account to send from, can be \"\" for the default\n2. \"amounts\"      (object, required) A json object with addresses and amounts\n    {\n      \"address\":amount (numeric) The address is the key, the amount in DIVI is the value\n      ,...\n    }\n3. minconf         (numeric, optional, default=1) Only use funds with at least this many confirmations\n4. \"comment\"      (string, optional) A comment\n5. subtractfeefrom (array, optional) Addresses to subtract fee from\n\nResult:\n\"transactionid\"   (string) The transaction id for the send. Only 1 transaction is created.",
                "sendfrom" => "sendfrom \"fromaccount\" \"toaddress\" amount ( minconf \"comment\" \"comment-to\" )\n\nSent an amount from an account to a divi address.\n\nArguments:\n1. \"fromaccount\"  (string, required) The name of the account to send funds from\n2. \"toaddress\"    (string, required) The divi address to send funds to\n3. amount          (numeric, required) The amount in DIVI (transaction fee added on top)\n4. \"comment\"      (string, optional) A comment for the transaction\n5. \"comment-to\"   (string, optional) A comment for who you're sending to\n\nResult:\n\"transactionid\"   (string) The transaction id.",
                "walletpassphrasechange" => "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n\nArguments:\n1. \"oldpassphrase\"  (string) The current passphrase\n2. \"newpassphrase\"  (string) The new passphrase",
                "getreceivedbyaddress" => "getreceivedbyaddress \"address\" ( minconf )\n\nReturns the total amount received by the given address in transactions with at least minconf confirmations.\n\nArguments:\n1. \"address\"  (string, required) The divi address for transactions\n2. minconf     (numeric, optional, default=1) Only include transactions confirmed at least this many times\n\nResult:\namount         (numeric) The total amount in DIVI received at this address.",
                "importaddress" => "importaddress \"address\" ( \"label\" rescan p2sh )\n\nAdds an address or script (in hex) that can be watched as if it were in your wallet but cannot be used to spend.\n\nArguments:\n1. \"address\"  (string, required) The address\n2. \"label\"    (string, optional, default=\"\") An optional label\n3. rescan      (boolean, optional, default=true) Rescan the wallet for transactions\n4. p2sh        (boolean, optional, default=false) Add as P2SH address\n\nNote: This call can take minutes to complete if rescan is true.",
                "addmultisigaddress" => "addmultisigaddress nrequired [\"key\",...] ( \"account\" )\n\nAdd a nrequired-to-sign multisignature address to the wallet.\nEach key is a DIVI address or hex-encoded public key.\nIf 'account' is specified, assign address to that account.\n\nArguments:\n1. nrequired      (numeric, required) The number of required signatures out of the n keys\n2. \"keys\"        (array, required) A json array of divi addresses or hex-encoded public keys\n     [\n       \"address\"  (string) divi address or hex-encoded public key\n       ...,\n     ]\n3. \"account\"     (string, optional) An account to assign the addresses to\n\nResult:\n{\n  \"address\":\"multisigaddress\",    (string) The value of the new multisig address\n  \"redeemScript\":\"script\"         (string) The string value of the hex-encoded redemption script\n}",
                "keypoolrefill" => "keypoolrefill ( newsize )\n\nFills the keypool.\n\nArguments:\n1. newsize  (numeric, optional, default=100) The new keypool size",
                "getkeypoolsize" => "getkeypoolsize\n\nReturns the number of keys in the keypool.\n\nResult:\n  n    (numeric) The number of pre-generated but unused keys in the keypool",
                "decodescript" => "decodescript \"hexstring\"\n\nDecode a hex-encoded script.\n\nArguments:\n1. \"hexstring\"  (string) the hex encoded script\n\nResult:\n{\n  \"asm\":\"asm\",      (string) Script public key\n  \"hex\":\"hex\",      (string) hex encoded public key\n  \"type\":\"type\",    (string) The output type\n  \"reqSigs\": n,      (numeric) The required signatures\n  \"addresses\": [     (json array of string)\n     \"address\"       (string) divi address\n     ,...\n  ],\n  \"p2sh\":\"address\"   (string) address of P2SH script wrapping this redeem script\n}",
                // Address index
                "getaddressdeltas" => "getaddressdeltas <address>|<addresses> (only_vaults)\n\nReturns all changes for an address (requires addressindex to be enabled).\n\nArguments:\naddress: (string) The base58check encoded address\n\"addresses\": (optional JSON object) An object with fields:\n               (1) '\"addresses\"' (required) array of base58check encoded addresses\n               (2) '\"start\"' (optional field) integer block height to start at\n               (3) '\"end\"' (optional field) integer block height to stop at\n               (4) '\"chainInfo\"' (optional field) bool flag to include chain info\n\"only_vaults\" (boolean, optional) Only return utxos spendable by the specified addresses\n\nResult:\n[\n  {\n    \"satoshis\"  (number) The difference of satoshis\n    \"txid\"  (string) The related txid\n    \"index\"  (number) The related input or output index\n    \"height\"  (number) The block height\n    \"address\"  (string) The base58check encoded address\n  }\n]\n\nExamples:\n> divi-cli getaddressdeltas '{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getaddressdeltas\", \"params\": [{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/",
                "getaddresstxids" => "getaddresstxids <address>|<addresses> (only_vaults)\n\nReturns the txids for an address(es) (requires addressindex to be enabled).\n\nArguments:\naddress: (string) The base58check encoded address\n\"addresses\": (optional JSON object) An object with fields:\n               (1) '\"addresses\"' (required) array of base58check encoded addresses\n               (2) '\"start\"' (optional field) integer block height to start at\n               (3) '\"end\"' (optional field) integer block height to stop at\n\"only_vaults\" (boolean, optional) Only return utxos spendable by the specified addresses\n\nResult:\n[\n  \"transactionid\"  (string) The transaction id\n  ,...\n]\n\nExamples:\n> divi-cli getaddresstxids '{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getaddresstxids\", \"params\": [{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/",
                "getspentinfo" => "getspentinfo {txid:,index:}\n\nReturns the txid and index where an output is spent.\n\nArguments:\n{\n  \"txid\" (string) The hex string of the txid\n  \"index\" (number) The start block height\n}\n\nResult:\n{\n  \"txid\"  (string) The transaction id\n  \"index\"  (number) The spending input index\n  ,...\n}\n\nExamples:\n> divi-cli getspentinfo '{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}'\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getspentinfo\", \"params\": [{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/",
                // Raw transactions
                "createrawtransaction" => "createrawtransaction [{\"txid\":\"...\",\"vout\":n},...] {\"address\":amount,...}\n\nCreate an unsigned raw transaction.",
                "signrawtransaction" => "signrawtransaction \"hexstring\" ( [{\"txid\":\"...\",\"scriptPubKey\":\"...\"},...] )\n\nSign a raw transaction with wallet keys.",
                "signrawtransactionwithwallet" => "signrawtransactionwithwallet \"hexstring\" ( [{\"txid\":\"...\",\"scriptPubKey\":\"...\"},...] )\n\nSign a raw transaction with wallet keys.",
                "sendrawtransaction" => "sendrawtransaction \"hexstring\"\n\nSubmit a raw transaction to the network.",
                "getrawtransaction" => "getrawtransaction \"txid\" ( verbose )\n\nReturn the raw transaction data.",
                "decoderawtransaction" => "decoderawtransaction \"hexstring\"\n\nReturn a JSON object representing the serialized transaction.",
                "listlockunspent" => "listlockunspent\n\nReturns list of temporarily unspendable outputs.",
                "lockunspent" => "lockunspent unlock [{\"txid\":\"txid\",\"vout\":n},...]\n\nUpdates list of temporarily unspendable outputs.",
                // Staking
                "getstakingstatus" => "getstakingstatus\n\nReturns an object containing staking information.",
                "getmintinginfo" => "getmintinginfo\n\nReturns detailed staking/minting information.",
                "setstaking" => "setstaking true|false\n\nEnable or disable staking.",
                "reservebalance" => "reservebalance ( true|false amount )\n\nShow or set reserve balance for staking.",
                // Lite wallet (external address queries)
                "getaddressbalance" => "getaddressbalance \"address\" ( minconf )\n\nReturns the balance for an external address.\nDoes not require a local wallet.",
                "getaddressutxos" => "getaddressutxos \"address\" ( minconf maxconf )\n\nReturns UTXOs for an external address.\nDoes not require a local wallet.",
                "getaddresshistory" => "getaddresshistory \"address\" ( skip limit )\n\nReturns transaction history for an external address.\nDoes not require a local wallet.",
                "gettxindex" => "gettxindex \"txid\"\n\nReturns block location info for a transaction.",
                "estimatefee" => "estimatefee ( nblocks )\n\nEstimates the fee per kilobyte needed for confirmation in nblocks.",
                "estimatesmartfee" => "estimatesmartfee ( nblocks )\n\nEstimates the smart fee per kilobyte needed for confirmation.",
                "getmempoolinfo" => "getmempoolinfo\n\nReturns details on the active state of the mempool.",
                "validateaddresses" => "validateaddresses [\"address\",...]\n\nValidates multiple addresses at once.",
                "getlitewalletinfo" => "getlitewalletinfo\n\nReturns info about lite wallet service availability.",
                // Masternode
                "getmasternodecount" => "getmasternodecount\n\nGet masternode count values\n\nResult:\n{\n  \"total\": n,        (numeric) Total masternodes\n  \"stable\": n,       (numeric) Stable count\n  \"obfcompat\": n,    (numeric) Obfuscation Compatible\n  \"enabled\": n,      (numeric) Enabled masternodes\n  \"inqueue\": n       (numeric) Masternodes in queue\n}\n\nExamples:\n> divi-cli getmasternodecount \n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getmasternodecount\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/",
                "getmasternodestatus" => "getmasternodestatus\n\nPrint masternode status\n\nResult:\n{\n  \"txhash\": \"xxxx\",      (string) Collateral transaction hash\n  \"outputidx\": n,        (numeric) Collateral transaction output index number\n  \"netaddr\": \"xxxx\",     (string) Masternode network address\n  \"addr\": \"xxxx\",        (string) DIVI address for masternode payments\n  \"status\": \"xxxx\",      (string) Masternode status\n  \"message\": \"xxxx\"      (string) Masternode status message\n}\n\nExamples:\n> divi-cli getmasternodestatus \n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getmasternodestatus\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/",
                "getmasternodewinners" => "getmasternodewinners ( blocks \"filter\" )\n\nPrint the masternode winners for the last n blocks\n\nArguments:\n1. blocks      (numeric, optional) Number of previous blocks to show (default: 10)\n2. filter      (string, optional) Search filter matching MN address\n\nResult (single winner):\n[\n  {\n    \"nHeight\": n,           (numeric) block height\n    \"winner\": {\n      \"address\": \"xxxx\",    (string) DIVI MN Address\n      \"nVotes\": n,          (numeric) Number of votes for winner\n    }\n  }\n  ,...\n]\n\nResult (multiple winners):\n[\n  {\n    \"nHeight\": n,           (numeric) block height\n    \"winner\": [\n      {\n        \"address\": \"xxxx\",  (string) DIVI MN Address\n        \"nVotes\": n,        (numeric) Number of votes for winner\n      }\n      ,...\n    ]\n  }\n  ,...\n]\n\nExamples:\n> divi-cli getmasternodewinners \n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getmasternodewinners\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/",
                "listmasternodes" => "listmasternodes ( \"filter\" )\n\nGet a ranked list of masternodes\n\nArguments:\n1. \"filter\"    (string, optional) Filter search text. Partial match by txhash, status, or addr.\n\nResult:\n[\n  {\n    \"rank\": n,           (numeric) Masternode Rank (or 0 if not enabled)\n    \"txhash\": \"hash\",    (string) Collateral transaction hash\n    \"outidx\": n,         (numeric) Collateral transaction output index\n    \"status\": s,         (string) Status (ENABLED/EXPIRED/REMOVE/etc)\n    \"addr\": \"addr\",      (string) Masternode DIVI address\n    \"version\": v,        (numeric) Masternode protocol version\n    \"lastseen\": ttt,     (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last seen\n    \"activetime\": ttt,   (numeric) The time in seconds since epoch (Jan 1 1970 GMT) masternode has been active\n    \"lastpaid\": ttt,     (numeric) The time in seconds since epoch (Jan 1 1970 GMT) masternode was last paid\n  }\n  ,...\n]\n\nExamples:\n> divi-cli masternodelist \n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"masternodelist\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/",
                "setupmasternode" => "setupmasternode alias txhash outputIndex collateralPubKey ip_address\n\nStarts escrows funds for some purpose.\n\nArguments:\n1. alias\t\t\t    (string, required) Helpful identifier to recognize this masternode later. \n2. txHash              (string, required) Funding transaction hash or bare txid. \n3. outputIndex         (string, required) Output index transaction. \n4. collateralPubkey    (string, required) collateral pubkey. \n5. ip_address          (string, required) Local ip address of this node\n\nResult:\n\"protocol_version\"\t\t\t(string) Protocol version used for serialization.\n\"message_to_sign\"\t\t\t(string) Hex-encoded msg requiring collateral signature.\n\"config_line\"\t\t\t    (string) Configuration data needed in the.\n\"broadcast_data\"\t\t\t    (string) funding transaction id necessary for next step.",
                "startmasternode" => "startmasternode alias\n\nVerifies the escrowed funds for the masternode and returns the necessary info for your and its configuration files.\n\nArguments:\n1. alias\t\t\t(string, required) helpful identifier to recognize this allocation later.\n2. deferRelay  (bool, optional) returns broadcast data to delegate signaling masternode start.\n\nResult:\n\"status\"\t(string) status of masternode",
                "broadcaststartmasternode" => "broadcaststartmasternode hex sig\n\nVerifies the escrowed funds for the masternode and returns the necessary info for your and its configuration files.\n\nArguments:\n1. broadcast_hex\t\t\t (hex, required) hex representation of broadcast data.\n2. appendBroadcastSignature (hex, optional) hex representation of collateral signature.\n\nResult:\n\"status\"\t(string) status of broadcast",
                "signmnbroadcast" => "signmnbroadcast mnhex\n\nStarts escrows funds for some purpose.\n\nArguments:\n1. mnhex\t\t\t    (string, required) Serialized masternode broadcast to be signed. \n\nResult:\n\"broadcast_data\"\t\t\t    (string) Signed broadcast data in serialized format.",
                "importmnbroadcast" => "importmnbroadcast \"broadcast_hex\"\n\nImport a pre-signed masternode broadcast into the wallet.\n\nArguments:\n1. broadcast_hex    (hex, required) hex representation of broadcast data\n\nResult:\ntrue|false          (boolean) true on success",
                "listmnbroadcasts" => "listmnbroadcasts\n\nLists pre-signed masternode broadcasts stored in the wallet\n\nResult:\n[\n  {\n    \"txhash\": \"hash\",    (string) Collateral transaction hash\n    \"outidx\": n,         (numeric) Collateral transaction output index\n    \"broadcast\": \"hex\"   (string) Stored broadcast data as hex string\n  }, ...\n]",
                "verifymasternodesetup" => "verifymasternodesetup ip_address sigtime collateralPubKey masternodePubKey\n\nStarts escrows funds for some purpose.\n\nArguments:\n1. ip_address\t\t\t (string, required) Local ip address of this node. \n2. sigtime              (string, required) Timestamp for signature \n3. collateralPubKey     (string, required) Collateral pubkey \n4. masternodePubKey     (string, required) Masternode pubkey. \n\nResult:\n\"expected_message\"\t\t\t    (bool) Expected masternode-broadcast message",
                "mnsync" => "mnsync \"status|reset\"\n\nReturns the sync status or resets sync.\n\nArguments:\n1. \"mode\"    (string, required) either 'status' or 'reset'\n\nResult ('status' mode):\n{\n  \"IsBlockchainSynced\": true|false,\n  \"timestampOfLastMasternodeListUpdate\": xxxx,\n  \"timestampOfLastMasternodeWinnerUpdate\": xxxx,\n  \"currentMasternodeSyncStatus\": n\n}",
                // Spork
                "spork" => "spork <name> [<value>]\n\nShow or update network sporks.\n\n<name> is the spork name, or 'show' to show all current spork settings, 'active' to show which sporks are active\n<value> is a epoch datetime to enable or disable spork",
                // Utility
                "verifychain" => "verifychain ( numblocks )\n\nVerifies blockchain database.\n\nArguments:\n1. numblocks    (numeric, optional, default=288, 0=all) The number of blocks to check.\n\nResult:\ntrue|false       (boolean) Verified or not",
                "getmininginfo" => "getmininginfo\n\nReturns a json object containing mining-related information.\n\nResult:\n{\n  \"blocks\": nnn,             (numeric) The current block\n  \"currentblocksize\": nnn,   (numeric) The last block size\n  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n  \"errors\": \"...\"          (string) Current errors\n  \"pooledtx\": n              (numeric) The size of the mem pool\n  \"chain\": \"xxxx\"         (string) current network name\n}",
                "bip38encrypt" => "bip38encrypt \"diviaddress\" \"passphrase\"\n\nEncrypts a private key with a passphrase using BIP38.\n\nArguments:\n1. \"diviaddress\"   (string, required) The divi address\n2. \"passphrase\"    (string, required) The passphrase\n\nResult:\n\"key\"                (string) The encrypted private key",
                "bip38decrypt" => "bip38decrypt \"bip38key\" \"passphrase\"\n\nDecrypts a BIP38 encrypted private key.\n\nArguments:\n1. \"bip38key\"      (string, required) The encrypted private key\n2. \"passphrase\"    (string, required) The passphrase\n\nResult:\n\"key\"                (string) The decrypted private key in WIF format",
                "loadwallet" => "loadwallet \"filename\"\n\nLoads wallet into memory.\n\nArguments:\n1. \"filename\"       (string, required) The filename of the wallet.dat to be loaded.",
                "getlotteryblockwinners" => "getlotteryblockwinners [block_height]\n\nReturns the lottery winners for a specific block.\n\nArguments:\n1. block_height    (numeric, required) The block height",
                "allocatefunds" => "allocatefunds purpose alias tier ( \"pay wallet\" ( \"voting wallet\" ) )\n\nAllocates treasury funds for governance purposes.\n\nArguments:\n1. purpose    (string, required) The purpose of allocation\n2. alias      (string, required) Identifier for this allocation",
                // Vault
                "addvault" => "addvault \"<owner_address>:<manager_address>\" funding_txhash\n\nAllows vault manager to accept to stake the indicated vault script.\n\nArguments:\n1. \"<owner_address>:<manager_address>\"  (string, required) Vault representation as a pair of addresses.\n2. \"tx_hash\"  (string, required) The transaction hash to search for the initial funding.",
                "removevault" => "removevault \"<owner_address>:<manager_address>\" tx_hash\n\nAllows vault manager to reject staking the indicated vault script.\n\nArguments:\n1. \"<owner_address>:<manager_address>\"  (string, required) Vault representation as a pair of addresses.\n2. \"tx_hash\"  (string, required) The transaction hash to search for the initial funding.",
                "getcoinavailability" => "getcoinavailability\n\nReturns available vault funds breakdown by vault type.\n\nResult:\n{\n  \"vaults\": [\n    {\n      \"owner\": \"address\",      (string) Owner address\n      \"manager\": \"address\",    (string) Manager address\n      \"balance\": x.xxx,         (numeric) Balance in DIVI\n      \"balance_sat\": n          (numeric) Balance in satoshis\n    }\n  ],\n  \"total_vaults\": n            (numeric) Total number of vaults\n}",
                "fundvault" => "fundvault \"[owner_address:]manager_address\" amount\n\nSend an amount to a given vault manager address. The amount is a real and is rounded to the nearest 0.00000001\n\nRequires wallet passphrase to be set with walletpassphrase call.\nArguments:\n1. \"[owner_address:]manager_address\" (string, required)\n   \"owner_address\" -> The address of the key owning the vault funds. Needs ':' separator if used.\n   \"manager_address\" -> The divi address owned by the vault manager.\n2. \"amount\"      (numeric, required) The amount in DIVI to send. eg 0.1",
                "debitvaultbyname" => "debitvaultbyname vault-encoding destination amount (feeMode)\n\nWithdraw an amount from a specific vaults to a destination address. The amount is a real and is rounded to the nearest 0.00000001\n\nRequires wallet passphrase to be set with walletpassphrase call.\nArguments:\n1. \"vault-encoding\"  (string, required) The vault encoding to withdraw from.\n2. \"diviaddress\"  (string, required) The divi address of your choosing to send to.\n3. \"amount\"      (numeric, required) The amount in DIVI to move. eg 0.1\n4. \"fee mode\"      (string, optional) The fee + change output calculation mode\n\nResult:\n\"transactionid\"  (string) The transaction id.",
                "reclaimvaultfunds" => "reclaimvaultfunds destination amount (feeMode|metadata) ( \"comment\" \"comment-to\" )\n\nWithdraw an amount from your vaults into a separate address. The amount is a real and is rounded to the nearest 0.00000001\n\nRequires wallet passphrase to be set with walletpassphrase call.\nArguments:\n1. \"diviaddress\"  (string, required) The divi address of your choosing to send to.\n2. \"amount\"      (numeric, required) The amount in DIVI to move. eg 0.1\n\nResult:\n\"transactionid\"  (string) The transaction id.",
                // Logging
                "getlogconfig" => "getlogconfig\n\nReturns the current logging configuration.\n\nResult:\n{\n  \"max_file_size\": n,      (numeric) Maximum log file size in bytes\n  \"max_file_size_mb\": n,   (numeric) Maximum log file size in MB\n  \"max_files\": n,          (numeric) Number of log files to keep\n  \"debug\": true|false,     (boolean) Whether debug logging is enabled\n  \"print_to_console\": true|false  (boolean) Whether logging to console\n}",
                "setlogconfig" => "setlogconfig debug\n\nSets log configuration. Note: only debug level can be changed at runtime.\nFile size and count settings require a restart.\n\nArguments:\n1. debug    (boolean, required) Enable or disable debug logging\n\nResult:\n{\n  \"success\": true|false,\n  \"message\": \"...\",\n  \"debug\": true|false\n}",
                // Control
                "help" => "help ( \"command\" )\n\nList all commands, or get help for a specified command.",
                "stop" => "stop\n\nStop Divi server.",
                _ => return Err(RpcError::method_not_found(method).into()),
            };
            Ok(serde_json::Value::String(help.to_string()))
        } else {
            // Return list of all methods
            let methods = vec![
                "== Blockchain ==",
                "getbestblockhash",
                "getblock",
                "getblockchaininfo",
                "getblockcount",
                "getblockhash",
                "getblockheader",
                "getchaintips",
                "getdifficulty",
                "getinfo",
                "getmininginfo",
                "getrawmempool",
                "gettxout",
                "gettxoutsetinfo",
                "prioritisetransaction",
                "verifychain",
                "",
                "== Address Index ==",
                "getaddressdeltas",
                "getaddresstxids",
                "getspentinfo",
                "",
                "== Generating ==",
                "generateblock",
                "setgenerate",
                "",
                "== Network ==",
                "addnode",
                "clearbanned",
                "disconnectnode",
                "getaddednodeinfo",
                "getconnectioncount",
                "getnetworkinfo",
                "getnettotals",
                "getpeerinfo",
                "getpeerscores",
                "listbanned",
                "ping",
                "setban",
                "",
                "== Wallet ==",
                "addmultisigaddress",
                "allocatefunds",
                "bip38decrypt",
                "bip38encrypt",
                "dumphdinfo",
                "dumpprivkey",
                "getaccount",
                "getaccountaddress",
                "getaddressinfo",
                "getaddressesbylabel",
                "getaddressesbyaccount",
                "getbalance",
                "getimmaturebalance",
                "getlotteryblockwinners",
                "getnewaddress",
                "getrawchangeaddress",
                "getreceivedbyaccount",
                "getreceivedbyaddress",
                "gettransaction",
                "getunconfirmedbalance",
                "getwalletinfo",
                "importaddress",
                "importprivkey",
                "keypoolrefill",
                "getkeypoolsize",
                "listaccounts",
                "listreceivedbyaccount",
                "listreceivedbyaddress",
                "listsinceblock",
                "listtransactions",
                "listunspent",
                "loadwallet",
                "sendfrom",
                "sendmany",
                "sendtoaddress",
                "setaccount",
                "validateaddress",
                "walletlock",
                "walletpassphrase",
                "walletpassphrasechange",
                "",
                "== Util ==",
                "createmultisig",
                "",
                "== Rawtransactions ==",
                "createrawtransaction",
                "decoderawtransaction",
                "decodescript",
                "getrawtransaction",
                "listlockunspent",
                "lockunspent",
                "sendrawtransaction",
                "signrawtransaction",
                "signrawtransactionwithwallet",
                "",
                "== Staking ==",
                "getmintinginfo",
                "getstakingstatus",
                "reservebalance",
                "setstaking",
                "",
                "== Lite Wallet ==",
                "estimatefee",
                "estimatesmartfee",
                "getaddressbalance",
                "getaddresshistory",
                "getaddressutxos",
                "getlitewalletinfo",
                "getmempoolinfo",
                "gettxindex",
                "validateaddresses",
                "",
                "== Masternode ==",
                "broadcaststartmasternode",
                "getmasternodecount",
                "getmasternodestatus",
                "getmasternodewinners",
                "importmnbroadcast",
                "listmasternodes",
                "listmnbroadcasts",
                "mnsync",
                "setupmasternode",
                "signmnbroadcast",
                "startmasternode",
                "verifymasternodesetup",
                "",
                "== Spork ==",
                "spork",
                "",
                "== Vault ==",
                "addvault",
                "debitvaultbyname",
                "fundvault",
                "getcoinavailability",
                "reclaimvaultfunds",
                "removevault",
                "",
                "== Logging ==",
                "getlogconfig",
                "setlogconfig",
                "",
                "== Control ==",
                "help",
                "stop",
            ];
            Ok(serde_json::Value::String(methods.join("\n")))
        }
    }

    /// Stop server (placeholder)
    fn stop(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        Ok(serde_json::Value::String(
            "Divi server stopping".to_string(),
        ))
    }
}

/// HTTP handler for JSON-RPC requests
async fn handle_rpc(State(server): State<Arc<RpcServer>>, body: String) -> impl IntoResponse {
    debug!("RPC request: {}", body);

    // Parse the JSON-RPC request
    let response = match serde_json::from_str::<Request>(&body) {
        Ok(request) => server.handle_request(request),
        Err(e) => {
            // Try to parse as batch request
            if let Ok(requests) = serde_json::from_str::<Vec<Request>>(&body) {
                // Handle batch request
                let responses: Vec<Response> = requests
                    .into_iter()
                    .map(|req| server.handle_request(req))
                    .collect();

                let json = serde_json::to_string(&responses).unwrap_or_default();
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    json,
                );
            }

            // Parse error
            error!("Failed to parse RPC request: {}", e);
            Response::error_only(RpcError::parse_error())
        }
    };

    let json = serde_json::to_string(&response).unwrap_or_default();
    debug!("RPC response: {}", json);

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
}

/// HTTP handler for wallet-specific JSON-RPC requests
async fn handle_wallet_rpc(
    State(server): State<Arc<RpcServer>>,
    Path(wallet_name): Path<String>,
    body: String,
) -> impl IntoResponse {
    debug!("RPC request for wallet '{}': {}", wallet_name, body);

    // TODO: In the future, we could use wallet_name to route to specific wallet instances
    // For now, we just log it and pass through to the default wallet
    // This enables multi-wallet CLI support even if server only has one wallet loaded

    // Parse the JSON-RPC request
    let response = match serde_json::from_str::<Request>(&body) {
        Ok(request) => server.handle_request(request),
        Err(e) => {
            // Try to parse as batch request
            if let Ok(requests) = serde_json::from_str::<Vec<Request>>(&body) {
                // Handle batch request
                let responses: Vec<Response> = requests
                    .into_iter()
                    .map(|req| server.handle_request(req))
                    .collect();

                let json = serde_json::to_string(&responses).unwrap_or_default();
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    json,
                );
            }

            // Parse error
            error!("Failed to parse RPC request: {}", e);
            Response::error_only(RpcError::parse_error())
        }
    };

    let json = serde_json::to_string(&response).unwrap_or_default();
    debug!("RPC response for wallet '{}': {}", wallet_name, json);

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
}

/// Create the axum router for RPC
pub fn create_router(server: Arc<RpcServer>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    Router::new()
        .route("/", post(handle_rpc))
        .route("/wallet/:wallet_name", post(handle_wallet_rpc))
        .with_state(server)
        .layer(cors)
}

/// Start the RPC server
pub async fn start_server(config: RpcConfig, chain: Arc<Chain>) -> Result<(), Error> {
    let server = Arc::new(RpcServer::new(chain));
    let app = create_router(server);

    info!("Starting RPC server on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Start the RPC server with peer manager
pub async fn start_server_with_peer_manager(
    config: RpcConfig,
    chain: Arc<Chain>,
    peer_manager: Arc<PeerManager>,
) -> Result<(), Error> {
    start_server_with_peer_manager_and_setup(config, chain, peer_manager, |_| {}).await
}

pub async fn start_server_with_peer_manager_and_setup<F>(
    config: RpcConfig,
    chain: Arc<Chain>,
    peer_manager: Arc<PeerManager>,
    setup_callbacks: F,
) -> Result<(), Error>
where
    F: FnOnce(&Arc<RpcServer>),
{
    let server = Arc::new(RpcServer::with_peer_manager(chain, peer_manager));

    setup_callbacks(&server);

    let app = create_router(server);

    info!("Starting RPC server on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Start the RPC server with wallet, peer manager, and optional staker
pub async fn start_server_with_wallet_peer_and_staker<F>(
    config: RpcConfig,
    chain: Arc<Chain>,
    wallet: Arc<WalletDb>,
    peer_manager: Arc<PeerManager>,
    setup_callbacks: F,
) -> Result<(), Error>
where
    F: FnOnce(&Arc<RpcServer>),
{
    let server = Arc::new(RpcServer::with_wallet_and_peer_manager(
        chain,
        wallet,
        peer_manager,
    ));

    // Allow caller to set up callbacks
    setup_callbacks(&server);

    let app = create_router(server);

    info!("Starting RPC server on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Start the RPC server with wallet and peer manager
pub async fn start_server_with_wallet_and_peer_manager(
    config: RpcConfig,
    chain: Arc<Chain>,
    wallet: Arc<WalletDb>,
    peer_manager: Arc<PeerManager>,
) -> Result<(), Error> {
    start_server_with_wallet_peer_and_staker(config, chain, wallet, peer_manager, |_| {}).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RequestId;
    use divi_storage::{ChainDatabase, ChainParams};
    use tempfile::tempdir;

    fn create_test_server() -> (Arc<RpcServer>, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let chain = Arc::new(Chain::new(db, ChainParams::default()).unwrap());
        let server = Arc::new(RpcServer::new(chain));
        (server, dir)
    }

    #[test]
    fn test_getblockcount_empty_chain() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "getblockcount".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
        assert_eq!(response.result.unwrap(), serde_json::json!(0));
    }

    #[test]
    fn test_method_not_found() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "nonexistent".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.error.is_some());
        assert_eq!(
            response.error.unwrap().code,
            crate::error::codes::METHOD_NOT_FOUND
        );
    }

    #[test]
    fn test_help() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "help".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
        let help = response.result.unwrap();
        assert!(help.as_str().unwrap().contains("getblockcount"));
    }

    #[test]
    fn test_help_specific_method() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "help".to_string(),
            params: Params::Array(vec![serde_json::json!("getblockcount")]),
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
        let help = response.result.unwrap();
        assert!(help.as_str().unwrap().contains("longest blockchain"));
    }

    #[test]
    fn test_getblockchaininfo() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "getblockchaininfo".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
        let info = response.result.unwrap();
        assert_eq!(info["chain"], "main");
        assert_eq!(info["blocks"], 0);
    }

    // ============================================================
    // MISSING TESTS: error codes, request parsing, method dispatch
    // ============================================================

    #[test]
    fn test_error_code_method_not_found_is_minus_32601() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "thisMethodDoesNotExist".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32601);
    }

    #[test]
    fn test_error_code_invalid_params_value() {
        use crate::error::codes;
        assert_eq!(codes::INVALID_REQUEST, -32600);
        assert_eq!(codes::METHOD_NOT_FOUND, -32601);
        assert_eq!(codes::INVALID_PARAMS, -32602);
        assert_eq!(codes::INTERNAL_ERROR, -32603);
    }

    #[test]
    fn test_request_parsing_null_id() {
        let json = r#"{"jsonrpc":"2.0","id":null,"method":"getblockcount","params":[]}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, RequestId::Null);
        assert_eq!(req.method, "getblockcount");
    }

    #[test]
    fn test_request_parsing_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"myreq","method":"getblockcount","params":[]}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, RequestId::String("myreq".to_string()));
    }

    #[test]
    fn test_request_parsing_no_params_field() {
        // params field is optional in JSON-RPC 2.0
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "getblockcount");
        assert!(req.params.is_empty());
    }

    #[test]
    fn test_method_dispatch_getblockcount() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "getblockcount".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.error.is_none());
        assert!(response.result.is_some());
    }

    #[test]
    fn test_method_dispatch_getnetworkinfo() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "getnetworkinfo".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.error.is_none());
        assert!(response.result.is_some());
    }

    #[test]
    fn test_method_dispatch_getmempoolinfo() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "getmempoolinfo".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.error.is_none());
        assert!(response.result.is_some());
    }

    #[test]
    fn test_method_dispatch_getstakingstatus() {
        // getstakingstatus requires a staking callback to be set; without one it returns an error
        // (that is the correct behavior — not a method-not-found error)
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "getstakingstatus".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        // Without a staking callback registered, the method returns an error
        // but it IS a registered method (not -32601 method-not-found)
        if let Some(err) = response.error {
            assert_ne!(err.code, -32601, "Should not be method-not-found");
        }
        // It either succeeded (if a default is available) or errored with a non-method-not-found code
    }

    #[test]
    fn test_help_lists_all_methods() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "help".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
        let help_text = response.result.unwrap();
        let help_str = help_text.as_str().unwrap();

        // All major methods should be listed
        assert!(help_str.contains("getblockcount"));
        assert!(help_str.contains("getblockchaininfo"));
        assert!(help_str.contains("getnetworkinfo"));
        assert!(help_str.contains("help"));
    }

    #[test]
    fn test_help_unknown_method_returns_error() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "help".to_string(),
            params: Params::Array(vec![serde_json::json!("nonexistentmethod")]),
        };

        let response = server.handle_request(request);
        // Help for an unknown method should return an error
        assert!(response.error.is_some());
    }

    #[test]
    fn test_response_id_is_preserved() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(42),
            method: "getblockcount".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert_eq!(response.id, RequestId::Number(42));
    }

    #[test]
    fn test_response_jsonrpc_version_is_2_0() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "getblockcount".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert_eq!(response.jsonrpc, "2.0");
    }

    #[test]
    fn test_error_response_has_no_result() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "unknownmethod".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.error.is_some());
        assert!(response.result.is_none());
    }

    #[test]
    fn test_success_response_has_no_error() {
        let (server, _dir) = create_test_server();
        let request = Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "getblockcount".to_string(),
            params: Params::None,
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_rpc_error_construction() {
        use crate::error::{codes, RpcError};

        let err = RpcError::method_not_found("testmethod");
        assert_eq!(err.code, codes::METHOD_NOT_FOUND);
        assert!(err.message.contains("testmethod"));

        let err = RpcError::invalid_params("bad param");
        assert_eq!(err.code, codes::INVALID_PARAMS);

        let err = RpcError::invalid_request("bad request");
        assert_eq!(err.code, codes::INVALID_REQUEST);

        let err = RpcError::internal_error("oops");
        assert_eq!(err.code, codes::INTERNAL_ERROR);

        let err = RpcError::parse_error();
        assert_eq!(err.code, codes::PARSE_ERROR);
        assert_eq!(err.code, -32700);
    }
}
