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
use crate::error::{codes, Error, RpcError};
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

use crate::access::{AccessConfig, Denial, MethodGrant, RpcAccess};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request as HttpRequest, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::post,
    Extension, Router,
};
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{debug, error, info, warn};

/// RPC server configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Listen address
    pub bind_address: SocketAddr,
    /// RPC username (optional)
    pub username: Option<String>,
    /// RPC password (optional)
    pub password: Option<String>,
    /// Peer, host, origin, rpcauth and whitelist settings
    pub access: AccessConfig,
    /// Largest request body accepted, in bytes; a bigger one gets HTTP 413
    pub max_request_size: usize,
}

/// Default for [`RpcConfig::max_request_size`]: room for submitblock with a
/// full 2 MB block in hex
pub const DEFAULT_MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;

/// Most calls one batch may hold; a bigger batch is refused whole
pub const MAX_BATCH_CALLS: usize = 100;

/// Most requests run at once. Handlers block (RocksDB, signing, scans), so
/// they run on the blocking pool, and a flood of requests waits here instead
/// of starving the runtime that drives P2P, staking and masternode pings.
const MAX_CONCURRENT_REQUESTS: usize = 16;

impl Default for RpcConfig {
    fn default() -> Self {
        RpcConfig {
            bind_address: "127.0.0.1:9998".parse().unwrap(),
            username: None,
            password: None,
            access: AccessConfig::default(),
            max_request_size: DEFAULT_MAX_REQUEST_SIZE,
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

/// Callback that starts a clean node shutdown (the same path as SIGTERM)
pub type ShutdownCallback = Arc<dyn Fn() + Send + Sync>;

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
    shutdown: RwLock<Option<ShutdownCallback>>,
}

impl RpcServer {
    /// Create a new RPC server
    pub fn new(chain: Arc<Chain>) -> Self {
        RpcServer {
            blockchain: BlockchainRpc::new(chain.clone()),
            network: RwLock::new(NetworkRpc::new()),
            wallet: WalletRpc::with_chain(chain.clone()),
            staking: StakingRpc::new(),
            lite_wallet: RwLock::new(LiteWalletRpc::for_chain(chain.clone())),
            masternode: MasternodeRpc::new(),
            spork: SporkRpc::new(),
            log_config: RwLock::new(None),
            shutdown: RwLock::new(None),
        }
    }

    /// Create a new RPC server with wallet
    pub fn with_wallet(chain: Arc<Chain>, wallet: Arc<WalletDb>) -> Self {
        RpcServer {
            blockchain: BlockchainRpc::new(chain.clone()),
            network: RwLock::new(NetworkRpc::new()),
            wallet: WalletRpc::with_wallet_and_chain(wallet, chain.clone()),
            staking: StakingRpc::new(),
            lite_wallet: RwLock::new(LiteWalletRpc::for_chain(chain.clone())),
            masternode: MasternodeRpc::new(),
            spork: SporkRpc::new(),
            log_config: RwLock::new(None),
            shutdown: RwLock::new(None),
        }
    }

    /// Create a new RPC server with peer manager
    pub fn with_peer_manager(chain: Arc<Chain>, peer_manager: Arc<PeerManager>) -> Self {
        RpcServer {
            blockchain: BlockchainRpc::new(chain.clone()),
            network: RwLock::new(NetworkRpc::with_peer_manager(peer_manager)),
            wallet: WalletRpc::with_chain(chain.clone()),
            staking: StakingRpc::new(),
            lite_wallet: RwLock::new(LiteWalletRpc::for_chain(chain.clone())),
            masternode: MasternodeRpc::new(),
            spork: SporkRpc::new(),
            log_config: RwLock::new(None),
            shutdown: RwLock::new(None),
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
            wallet: WalletRpc::with_wallet_and_chain(wallet, chain.clone()),
            staking: StakingRpc::new(),
            lite_wallet: RwLock::new(LiteWalletRpc::for_chain(chain.clone())),
            masternode: MasternodeRpc::new(),
            spork: SporkRpc::new(),
            log_config: RwLock::new(None),
            shutdown: RwLock::new(None),
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
        self.wallet.set_mempool(mempool.clone());
        self.lite_wallet.write().set_mempool(mempool);
    }

    /// Let `getblock` fetch pruned blocks from full-history peers
    pub fn set_block_fetcher(&self, fetcher: Arc<dyn crate::blockchain::BlockFetcher>) {
        self.wallet.set_block_fetcher(fetcher.clone());
        self.blockchain.set_block_fetcher(fetcher);
    }

    /// Set the spork manager that backs the `spork` RPC
    pub fn set_spork_manager(&self, sporks: Arc<divi_network::SporkManager>) {
        self.spork.set_manager(sporks);
    }

    /// Set the masternode manager
    pub fn set_masternode_manager(&self, manager: divi_masternode::MasternodeManager) {
        self.masternode.set_manager(manager);
    }

    /// Set the datadir used by the masternode RPCs (`masternode.conf`, stored broadcasts)
    pub fn set_masternode_datadir(&self, dir: std::path::PathBuf) {
        self.masternode.set_datadir(dir);
    }

    /// Set the hook that relays raw masternode broadcasts to peers
    pub fn set_masternode_relay(&self, relay: crate::mn_broadcast::BroadcastRelay) {
        self.masternode.set_broadcast_relay(relay);
    }

    /// Update chain height (for wallet confirmations)
    pub fn set_height(&self, height: u32) {
        self.wallet.set_height(height);
    }

    /// Set the hook that the `stop` RPC uses to shut the node down
    pub fn set_shutdown_callback(&self, callback: ShutdownCallback) {
        *self.shutdown.write() = Some(callback);
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
            "version": "3.0.0.0",
            "protocolversion": PROTOCOL_VERSION,
            "walletversion": 120200,
            "blocks": height,
            "timeoffset": 0,
            "connections": connections,
            "proxy": "",
            "difficulty": difficulty,
            "testnet": matches!(network_type, NetworkType::Testnet),
            "moneysupply": self.blockchain.money_supply(),
            "keypoololdest": keypoololdest,
            "keypoolsize": keypoolsize,
            "balance": balance,
            "paytxfee": 0.0,
            "relayfee": 0.0001,
            "staking status": staking_status_text,
            "errors": ""
        }))
    }

    /// setmocktime - C++ only honours this on regtest; this node has no mock clock at all.
    fn set_mock_time(&self, params: &Params) -> Result<serde_json::Value, Error> {
        use divi_storage::chain::NetworkType;

        if params.get_i64(0).is_none() {
            return Err(RpcError::invalid_params("setmocktime timestamp").into());
        }
        if !matches!(self.blockchain.chain().network_type(), NetworkType::Regtest) {
            return Err(RpcError::new(
                codes::MISC_ERROR,
                "setmocktime for regression testing (-regtest mode) only",
            )
            .into());
        }
        Err(RpcError::new(
            codes::MISC_ERROR,
            "setmocktime is not supported by this node",
        )
        .into())
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
            "invalidateblock" | "reconsiderblock" | "reverseblocktransactions" => {
                let result = self.blockchain.invalidate_block_family(method, params);
                // The active chain may have changed without a block notification
                self.wallet.sync_with_chain();
                result
            }
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
            "ban" => self.network.read().ban(params),
            "setmocktime" => self.set_mock_time(params),
            "getinvalid" => Ok(serde_json::json!([{
                // C++ 3.0.0 builds these from empty maps, so the report is always empty
                "addresses_with_invalid": {},
                "total_unspent": "0.00",
                "total_minted": "0.00",
                "total_valid_used": "0.00",
            }])),
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
            "encryptwallet" => self.wallet.encrypt_wallet(params),
            "getreceivedbyaddress" => self.wallet.get_received_by_address(params),
            "importaddress" => self.wallet.import_address(params),
            "addmultisigaddress" => self.wallet.add_multisig_address(params),
            "keypoolrefill" => self.wallet.keypool_refill(params),
            "getkeypoolsize" => self.wallet.get_keypool_size(params),
            "bip38encrypt" => self.wallet.bip38_encrypt(params),
            "bip38decrypt" => self.wallet.bip38_decrypt(params),
            "bip38paperwallet" => self.wallet.bip38_paper_wallet(params),
            "loadwallet" => self.wallet.load_wallet(params),
            "getlotteryblockwinners" => self.blockchain.get_lottery_block_winners(params),
            "allocatefunds" => self.wallet.allocate_funds(params),

            // Raw transaction methods
            "createrawtransaction" => self.wallet.create_raw_transaction(params),
            "signrawtransaction" => self.wallet.sign_raw_transaction(params),
            "signrawtransactionwithwallet" => self.wallet.sign_raw_transaction(params),
            "signtransactionwithaddresskey" => {
                self.wallet.sign_transaction_with_address_key(params)
            }
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
            "getstakesplitthreshold" => self.staking.get_stake_split_threshold(params),
            "setstakesplitthreshold" => self.staking.set_stake_split_threshold(params),

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
            "getmasternodewinners" => self
                .masternode
                .get_masternode_winners(params, self.blockchain.tip_height()),
            "listmasternodes" => self.masternode.list_masternodes(params),
            "setupmasternode"
            | "startmasternode"
            | "broadcaststartmasternode"
            | "signmnbroadcast" => {
                use crate::mn_broadcast::MnContext;
                use divi_storage::chain::NetworkType;
                let chain = self.blockchain.chain();
                let ctx = MnContext {
                    chain,
                    wallet: self.wallet.wallet_db(),
                };
                match method {
                    "setupmasternode" => {
                        let port = match chain.network_type() {
                            NetworkType::Mainnet => 51472,
                            NetworkType::Testnet => 51474,
                            _ => 51476,
                        };
                        self.masternode.setup_masternode(params, &ctx, port)
                    }
                    "startmasternode" => self.masternode.start_masternode(params, &ctx),
                    "broadcaststartmasternode" => {
                        self.masternode.broadcast_start_masternode(params, &ctx)
                    }
                    _ => self.masternode.sign_mn_broadcast(params, &ctx),
                }
            }
            "importmnbroadcast" => self.masternode.import_mn_broadcast(params),
            "listmnbroadcasts" => self.masternode.list_mn_broadcasts(params),
            "verifymasternodesetup" => {
                use divi_storage::chain::NetworkType;
                let port = match self.blockchain.chain().network_type() {
                    NetworkType::Mainnet => 51472,
                    NetworkType::Testnet => 51474,
                    _ => 51476,
                };
                self.masternode.verify_masternode_setup(params, port)
            }
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
                "getblock" => "getblock \"blockhash\" ( verbosity )\n\nIf verbosity is 0 or false, returns hex-encoded data.\nIf verbosity is 1 or true (default), returns a JSON object with the transaction ids.\nIf verbosity is 2, returns a JSON object whose \"tx\" holds each transaction decoded as getrawtransaction <txid> 1 shows it.",
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
                "getinfo" => "getinfo\n\nReturns an object containing various state info (version, blocks, connections, difficulty, balance, staking status).",
                "getinvalid" => "getinvalid ( \"all\" )\n\nGet a summary of invalidated outpoints.\n\nArguments:\n1. all   (string, optional) return a full list of outpoints even if they are spent",
                "invalidateblock" => "invalidateblock \"hash\"\n\nPermanently marks a block as invalid, as if it violated a consensus rule.\n\nArguments:\n1. hash   (string, required) the hash of the block to mark as invalid",
                "reconsiderblock" => "reconsiderblock \"hash\"\n\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\nThis can be used to undo the effects of invalidateblock.\n\nArguments:\n1. hash   (string, required) the hash of the block to reconsider",
                "reverseblocktransactions" => "reverseblocktransactions \"hash\"\n\nRolls the block's transactions back out of the coin database and connects them again.\n\nArguments:\n1. hash   (string, required) the hash of the block",
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
                "ban" => "ban \"ip_address\"\n\nBans the connected peer with this IP address.\n('outdated' is refused: peer versions are not recorded after the handshake.)\n\nArguments:\n1. \"ip_address\"  (string, required) The IP address of a connected peer",
                "setmocktime" => "setmocktime timestamp\n\nSet the local time to given timestamp (-regtest only).\nThis node has no mock clock, so the call always returns an error.\n\nArguments:\n1. timestamp  (integer, required) Unix seconds-since-epoch timestamp",
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
                "walletpassphrase" => "walletpassphrase \"passphrase\" timeout ( stakingOnly )\n\nUnlocks the wallet for 'timeout' seconds (0: until walletlock).\nWith stakingOnly true the keys are only used for staking: sends, signing and key exports are refused.",
                "encryptwallet" => "encryptwallet \"passphrase\"\n\nEncrypts the wallet with 'passphrase'. This is for first time encryption; after that, use walletpassphrasechange. The wallet is left locked, and a private-key or seed operation then needs walletpassphrase first.\n\nArguments:\n1. \"passphrase\"  (string, required) The passphrase to encrypt the wallet with.",
                "walletlock" => "walletlock\n\nLocks the wallet.",
                "dumpprivkey" => "dumpprivkey \"address\"\n\nReveals the private key corresponding to 'address'.",
                "dumphdinfo" => "dumphdinfo\n\nReturns an object containing sensitive private info about this HD wallet.",
                "importprivkey" => "importprivkey \"privkey\" ( \"label\" rescan )\n\nAdds a private key to your wallet.",
                "rescanblockchain" => "rescanblockchain ( start_height stop_height )\n\nRescan the local blockchain for wallet related transactions.\n\nArguments:\n1. start_height  (numeric, optional, default=0) block height where the rescan should start\n2. stop_height   (numeric, optional, default=tip) the last block height that should be scanned",
                "backupwallet" => "backupwallet \"destination\"\n\nSafely copies the wallet to destination, which can be a directory or a path with filename.\n\nArguments:\n1. \"destination\"   (string) The destination directory or file",
                "signmessage" => "signmessage \"diviaddress\" \"message\" ( \"input_format\" \"output_format\" )\n\nSign a message with the private key of an address.\nRequires the wallet to be unlocked if it is encrypted.\n\nArguments:\n1. \"diviaddress\"  (string, required) The divi address to use for the private key.\n2. \"message\"      (string, required) The message to create a signature of.\n3. \"input_format\" (string, optional) ['hex'|'b64'] Message encoding format. Default plaintext\n4. \"output_format\" (string, optional) ['hex'] Signature encoding format. Default base64\n\nResult:\n\"signature\"        (string) The signature of the message encoded in base 64",
                "verifymessage" => "verifymessage \"diviaddress\" \"signature\" \"message\"\n\nVerify a signed message.\n\nArguments:\n1. \"diviaddress\"  (string, required) The divi address to use for the signature.\n2. \"signature\"    (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n3. \"message\"      (string, required) The message that was signed.\n\nResult:\ntrue|false   (boolean) If the signature is verified or not.",
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
                "signrawtransaction" => "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey\",...] sighashtype )\n\nSign the inputs of a raw transaction with wallet keys and merge with the signatures already in it.\nA P2SH input needs its redeemScript, given here or stored in the wallet (addmultisigaddress).\nIf private keys (WIF) are given, only those keys sign, the wallet is not used and need not be unlocked.\n\n4. \"sighashtype\"  (string, optional, default=ALL) The signature hash type. Must be one of\n       \"ALL\"\n       \"NONE\"\n       \"SINGLE\"\n       \"ALL|ANYONECANPAY\"\n       \"NONE|ANYONECANPAY\"\n       \"SINGLE|ANYONECANPAY\"\n\nResult:\n{\n  \"hex\": \"value\",   (string) The raw transaction with signature(s)\n  \"complete\": true|false   (boolean) If the transaction has a complete set of signatures\n}",
                "signrawtransactionwithwallet" => "signrawtransactionwithwallet \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey\",...] sighashtype )\n\nSign the inputs of a raw transaction with wallet keys and merge with the signatures already in it.\nA P2SH input needs its redeemScript, given here or stored in the wallet (addmultisigaddress).\nIf private keys (WIF) are given, only those keys sign, the wallet is not used and need not be unlocked.\n\n4. \"sighashtype\"  (string, optional, default=ALL) The signature hash type. Must be one of\n       \"ALL\"\n       \"NONE\"\n       \"SINGLE\"\n       \"ALL|ANYONECANPAY\"\n       \"NONE|ANYONECANPAY\"\n       \"SINGLE|ANYONECANPAY\"\n\nResult:\n{\n  \"hex\": \"value\",   (string) The raw transaction with signature(s)\n  \"complete\": true|false   (boolean) If the transaction has a complete set of signatures\n}",
                "signtransactionwithaddresskey" => "signtransactionwithaddresskey \"hexstring\" \"address\" inputindex\n\nSigns one input with the wallet key of an address (SIGHASH_SINGLE) and returns the signature script as asm.\n\nArguments:\n1. \"hexstring\"  (string, required) The transaction hex string\n2. \"address\"    (string, required) The wallet address whose key signs\n3. inputindex    (numeric, required) The input to sign",
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
                "getstakesplitthreshold" => "getstakesplitthreshold\n\nReturns the stake split threshold in DIVI (startup value: -stakesplitthreshold, default 20000).",
                "setstakesplitthreshold" => "setstakesplitthreshold value\n\nSet the stake split threshold in whole DIVI for this run: a stake whose value plus reward exceeds it is paid back as two outputs; smaller coins of the same address are combined up to half of it.",
                // Lite wallet (external address queries)
                "getaddressbalance" => "getaddressbalance \"address\" ( minconf )\n\nReturns the balance for an external address.\nDoes not require a local wallet.",
                "getaddressutxos" => "getaddressutxos \"address\" ( minconf maxconf skip limit )\n\nReturns UTXOs for an external address, at most limit (default and most 1000) after skipping skip of them.\nDoes not require a local wallet.",
                "getaddresshistory" => "getaddresshistory \"address\" ( skip limit )\n\nReturns transaction history for an external address.\nDoes not require a local wallet.",
                "gettxindex" => "gettxindex \"txid\"\n\nReturns block location info for a transaction.",
                "estimatefee" => "estimatefee ( nblocks )\n\nEstimates the fee per kilobyte needed for confirmation in nblocks.",
                "estimatepriority" => "estimatepriority nblocks\n\nDeprecated. Always returns -1.",
                "estimatesmartfee" => "estimatesmartfee ( nblocks )\n\nEstimates the smart fee per kilobyte needed for confirmation.",
                "getmempoolinfo" => "getmempoolinfo\n\nReturns details on the active state of the mempool.",
                "validateaddresses" => "validateaddresses [\"address\",...]\n\nValidates up to 1000 addresses at once.",
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
                "bip38paperwallet" => "bip38paperwallet \"passphrase\"\n\nCreates a new key that is not stored in the wallet and returns its address and the key encrypted with BIP38.\nRequires the wallet to be unlocked if it is encrypted.\n\nArguments:\n1. \"passphrase\"    (string, required) The passphrase that encrypts the key\n\nResult:\n{\n  \"Address\": \"address\",        (string) The divi address of the new key\n  \"Encrypted Key\": \"key\"       (string) The BIP38 encrypted private key\n}",
                "bip38decrypt" => "bip38decrypt \"bip38key\" \"passphrase\"\n\nDecrypts a BIP38 encrypted private key.\n\nArguments:\n1. \"bip38key\"      (string, required) The encrypted private key\n2. \"passphrase\"    (string, required) The passphrase\n\nResult:\n\"key\"                (string) The decrypted private key in WIF format",
                "loadwallet" => "loadwallet \"filename\"\n\nNot supported by IronDivi: irondivid opens one wallet when it starts and keeps it until it stops. To use another wallet, stop irondivid and start it with --wallet=<wallet directory>. Always returns an error.\n\nArguments:\n1. \"filename\"       (string, required) The wallet that would be loaded.",
                "getlotteryblockwinners" => "getlotteryblockwinners [block_height]\n\nReturns the lottery candidates recorded at a block.\n\nArguments:\n1. block_height    (numeric, optional) The block height (default and maximum: the tip)",
                "allocatefunds" => "allocatefunds purpose alias tier ( \"pay wallet\" ( \"voting wallet\" ) )\n\nAllocates treasury funds for governance purposes.\n\nArguments:\n1. purpose    (string, required) The purpose of allocation\n2. alias      (string, required) Identifier for this allocation",
                // Vault
                "addvault" => "addvault \"<owner_address>:<manager_address>\" funding_txhash\n\nAllows vault manager to accept to stake the indicated vault script.\n\nArguments:\n1. \"<owner_address>:<manager_address>\"  (string, required) Vault representation as a pair of addresses.\n2. \"tx_hash\"  (string, required) The transaction hash to search for the initial funding.",
                "removevault" => "removevault \"<owner_address>:<manager_address>\" ( tx_hash )\n\nAllows vault manager to reject staking the indicated vault script.\n\nArguments:\n1. \"<owner_address>:<manager_address>\"  (string, required) Vault representation as a pair of addresses.\n2. \"tx_hash\"  (string, optional) Ignored; accepted for older IronDivi callers.",
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
                "invalidateblock",
                "reconsiderblock",
                "reverseblocktransactions",
                "getdifficulty",
                "getinfo",
                "getinvalid",
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
                "ban",
                "",
                "== Wallet ==",
                "addmultisigaddress",
                "allocatefunds",
                "backupwallet",
                "bip38decrypt",
                "bip38encrypt",
                "bip38paperwallet",
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
                "rescanblockchain",
                "sendfrom",
                "sendmany",
                "sendtoaddress",
                "setaccount",
                "signmessage",
                "validateaddress",
                "encryptwallet",
                "walletlock",
                "walletpassphrase",
                "walletpassphrasechange",
                "",
                "== Util ==",
                "createmultisig",
                "setmocktime",
                "verifymessage",
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
                "signtransactionwithaddresskey",
                "",
                "== Staking ==",
                "getmintinginfo",
                "getstakingstatus",
                "reservebalance",
                "getstakesplitthreshold",
                "setstakesplitthreshold",
                "setstaking",
                "",
                "== Lite Wallet ==",
                "estimatefee",
                "estimatepriority",
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

    /// Stop server: hand off to the node's shutdown path, then answer as Divi Core does
    fn stop(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let shutdown = self.shutdown.read().clone();
        let Some(shutdown) = shutdown else {
            return Err(
                RpcError::new(codes::MISC_ERROR, "stop is not available on this server").into(),
            );
        };
        info!("RPC stop received, shutting down");
        shutdown();
        Ok(serde_json::Value::String(
            "Divi server stopping".to_string(),
        ))
    }
}

/// Run one JSON-RPC body (a single call or a batch) for a caller that may call
/// the methods in `grant`. A batch containing any method the caller may not
/// call is refused whole with HTTP 403, as Bitcoin Core does.
fn process_body(server: &RpcServer, grant: &MethodGrant, body: &str) -> axum::response::Response {
    let json_response = |json: String| {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            json,
        )
            .into_response()
    };
    let forbidden = |method: &str| {
        warn!("RPC method {method:?} refused by rpcwhitelist");
        StatusCode::FORBIDDEN.into_response()
    };

    // Never log a body or a result: they carry passphrases, private keys and
    // seeds (walletpassphrase, dumpprivkey, dumphdinfo, importprivkey...).
    // The method, the id and the sizes are enough to follow the traffic.
    match serde_json::from_str::<Request>(body) {
        Ok(request) => {
            if !grant.allows(&request.method) {
                return forbidden(&request.method);
            }
            let method = request.method.clone();
            let id = request.id.clone();
            let response = server.handle_request(request);
            let json = serde_json::to_string(&response).unwrap_or_default();
            debug!(
                "RPC {method} id={id:?}: {} byte request, {} byte response",
                body.len(),
                json.len()
            );
            json_response(json)
        }
        Err(e) => {
            if let Ok(requests) = serde_json::from_str::<Vec<Request>>(body) {
                if requests.len() > MAX_BATCH_CALLS {
                    warn!(
                        "RPC batch of {} calls refused (limit {MAX_BATCH_CALLS})",
                        requests.len()
                    );
                    return json_response(
                        serde_json::to_string(&Response::error_only(RpcError::invalid_request(
                            format!(
                                "Batch of {} calls is over the limit of {MAX_BATCH_CALLS}",
                                requests.len()
                            ),
                        )))
                        .unwrap_or_default(),
                    );
                }
                if let Some(denied) = requests.iter().find(|r| !grant.allows(&r.method)) {
                    return forbidden(&denied.method);
                }
                debug!(
                    "RPC batch of {} calls, {} bytes",
                    requests.len(),
                    body.len()
                );
                let responses: Vec<Response> = requests
                    .into_iter()
                    .map(|req| server.handle_request(req))
                    .collect();
                return json_response(serde_json::to_string(&responses).unwrap_or_default());
            }
            // The parse error can quote a value from the body: log only where
            error!(
                "Failed to parse RPC request ({:?} at line {} column {})",
                e.classify(),
                e.line(),
                e.column()
            );
            json_response(
                serde_json::to_string(&Response::error_only(RpcError::parse_error()))
                    .unwrap_or_default(),
            )
        }
    }
}

/// Run [`process_body`] on the blocking pool once one of the
/// [`MAX_CONCURRENT_REQUESTS`] slots is free.
async fn process_body_blocking(
    server: Arc<RpcServer>,
    slots: Arc<Semaphore>,
    grant: MethodGrant,
    body: String,
) -> axum::response::Response {
    let Ok(_slot) = slots.acquire_owned().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    tokio::task::spawn_blocking(move || process_body(&server, &grant, &body))
        .await
        .unwrap_or_else(|e| {
            error!("RPC handler failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}

/// HTTP handler for JSON-RPC requests
async fn handle_rpc(
    State(server): State<Arc<RpcServer>>,
    Extension(slots): Extension<Arc<Semaphore>>,
    Extension(grant): Extension<MethodGrant>,
    body: String,
) -> axum::response::Response {
    process_body_blocking(server, slots, grant, body).await
}

/// HTTP handler for wallet-specific JSON-RPC requests. The wallet name is not
/// used for routing yet: the server has one wallet, and this path lets
/// multi-wallet clients talk to it.
async fn handle_wallet_rpc(
    State(server): State<Arc<RpcServer>>,
    Path(_wallet_name): Path<String>,
    Extension(slots): Extension<Arc<Semaphore>>,
    Extension(grant): Extension<MethodGrant>,
    body: String,
) -> axum::response::Response {
    process_body_blocking(server, slots, grant, body).await
}

/// Build the access-control state for `config`. A malformed `rpcauth`,
/// `rpcwhitelist` or `rpcallowip` entry is an error.
pub fn rpc_access(config: &RpcConfig) -> Result<RpcAccess, Error> {
    RpcAccess::new(
        config.username.as_deref(),
        config.password.as_deref(),
        &config.access,
    )
    .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))
}

/// Create the axum router for RPC, enforcing the checks of [`crate::access`]:
/// peer address, `Host` header, `Origin` and HTTP Basic authentication, then
/// the caller's method whitelist. Without credentials every request is
/// refused: the RPC is never served open (irondivid fills in cookie
/// credentials when none are configured, see [`crate::auth_cookie`]). The
/// router must be served with [`ConnectInfo`] (see [`serve`]); without the
/// peer address every request is refused.
pub fn create_router_with_auth(server: Arc<RpcServer>, config: &RpcConfig) -> Router {
    let access = match rpc_access(config) {
        Ok(access) => access,
        Err(e) => {
            error!("Invalid RPC access configuration ({e}): every request will be refused");
            RpcAccess::new(None, None, &AccessConfig::default()).expect("empty config is valid")
        }
    };
    if !access.has_credentials() {
        error!("RPC has no credentials: every request will be refused");
    }
    build_router(server, Arc::new(access), config.max_request_size)
}

fn build_router(server: Arc<RpcServer>, access: Arc<RpcAccess>, max_request_size: usize) -> Router {
    let origins: Vec<HeaderValue> = access
        .allowed_origins()
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    let router = Router::new()
        .route("/", post(handle_rpc))
        .route("/wallet/:wallet_name", post(handle_wallet_rpc))
        .layer(Extension(Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS))))
        .layer(DefaultBodyLimit::max(max_request_size))
        .with_state(server);

    let router = router.layer(middleware::from_fn(
        move |connect: Option<ConnectInfo<SocketAddr>>, mut req: HttpRequest, next: Next| {
            let access = access.clone();
            async move {
                // The header borrows end here: the body is not Sync, so a
                // borrow of the request held across an await is not Send.
                let checked = {
                    let headers = req.headers();
                    let hdr = |name| headers.get(name).and_then(|v| v.to_str().ok());
                    access.check(
                        connect.map(|ConnectInfo(addr)| addr.ip()),
                        hdr(header::HOST),
                        hdr(header::ORIGIN),
                        hdr(header::AUTHORIZATION),
                    )
                };
                match checked {
                    Ok(grant) => {
                        req.extensions_mut().insert(grant);
                        next.run(req).await
                    }
                    Err(Denial::Unauthorized) => {
                        // Slow down password guessing, as Bitcoin Core does.
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        (
                            StatusCode::UNAUTHORIZED,
                            [(
                                header::WWW_AUTHENTICATE,
                                HeaderValue::from_static("Basic realm=\"jsonrpc\""),
                            )],
                        )
                            .into_response()
                    }
                    Err(denial) => {
                        warn!("RPC request refused: {denial:?}");
                        StatusCode::FORBIDDEN.into_response()
                    }
                }
            }
        },
    ));

    // Browsers get CORS headers only for the origins configured with
    // rpcalloworigin; with none configured there is no CORS layer at all.
    if origins.is_empty() {
        router
    } else {
        router.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::POST])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]),
        )
    }
}

/// Check the bind address against the access configuration, bind and serve
/// `server` with the peer address available to the access checks.
async fn serve(config: &RpcConfig, server: Arc<RpcServer>) -> Result<(), Error> {
    let access = rpc_access(config)?;
    access
        .check_bind(config.bind_address)
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
    let app = build_router(server, Arc::new(access), config.max_request_size);

    info!("Starting RPC server on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Start the RPC server
pub async fn start_server(config: RpcConfig, chain: Arc<Chain>) -> Result<(), Error> {
    let server = Arc::new(RpcServer::new(chain));
    serve(&config, server).await
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

    serve(&config, server).await
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

    serve(&config, server).await
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

    /// Run `f` with every log event, at any level, written to the returned buffer.
    fn capture_logs(f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buf.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn node04_rpc_bodies_and_results_are_never_logged() {
        let (server, _dir) = create_test_server();
        let secret = "correct-horse-battery-staple-4f2a";
        let logs = capture_logs(|| {
            // A call, a batch, and bodies that fail to parse, all carrying the secret
            for body in [
                format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"walletpassphrase","params":["{secret}",60]}}"#
                ),
                format!(
                    r#"[{{"jsonrpc":"2.0","id":1,"method":"encryptwallet","params":["{secret}"]}}]"#
                ),
                format!(r#"{{"jsonrpc":"2.0","id":1,"method":["{secret}"]}}"#),
                format!(r#"{{"method":"walletpassphrase","params":["{secret}"#),
            ] {
                let _ = process_body(&server, &MethodGrant::All, &body);
            }
        });
        assert!(logs.contains("RPC"), "the calls are still logged: {logs}");
        assert!(!logs.contains(secret), "a secret reached the log: {logs}");
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

    fn call(server: &RpcServer, method: &str, params: Params) -> Response {
        server.handle_request(Request {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params,
        })
    }

    #[test]
    fn stop_calls_the_shutdown_hook() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (server, _dir) = create_test_server();
        // No hook: refuse instead of claiming to stop
        assert!(call(&server, "stop", Params::None).error.is_some());

        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        server.set_shutdown_callback(Arc::new(move || {
            seen.fetch_add(1, Ordering::SeqCst);
        }));
        let r = call(&server, "stop", Params::None);
        assert_eq!(r.result, Some(serde_json::json!("Divi server stopping")));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_getinfo_parity_fields() {
        let (server, _dir) = create_test_server();
        let r = call(&server, "getinfo", Params::None).result.unwrap();
        assert!(r["version"].is_string());
        assert!(r["moneysupply"].is_number());
        assert_eq!(r["walletversion"], serde_json::json!(120200));
    }

    #[test]
    fn test_getinvalid_constant() {
        let (server, _dir) = create_test_server();
        let r = call(&server, "getinvalid", Params::None).result.unwrap();
        assert_eq!(r[0]["total_unspent"], serde_json::json!("0.00"));
    }

    #[test]
    fn test_setmocktime_is_an_honest_error() {
        let (server, _dir) = create_test_server();
        let resp = call(
            &server,
            "setmocktime",
            Params::Array(vec![serde_json::json!(1)]),
        );
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_ban_without_matching_peer_is_not_fatal() {
        let (server, _dir) = create_test_server();
        let resp = call(
            &server,
            "ban",
            Params::Array(vec![serde_json::json!("1.2.3.4")]),
        );
        // dispatched (not -32601 method-not-found), whatever the network state
        assert!(resp.error.is_none_or(|e| e.code != -32601));
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
        assert_eq!(err.code, codes::MISC_ERROR);

        let err = RpcError::invalid_request("bad request");
        assert_eq!(err.code, codes::INVALID_REQUEST);

        let err = RpcError::internal_error("oops");
        assert_eq!(err.code, codes::MISC_ERROR);

        let err = RpcError::parse_error();
        assert_eq!(err.code, codes::PARSE_ERROR);
        assert_eq!(err.code, -32700);
    }

    /// Serve `router` on a loopback port and POST one getblockcount to it.
    async fn status_of(router: Router, authorization: Option<String>) -> StatusCode {
        let body = r#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}"#;
        let auth = authorization
            .map(|a| format!("Authorization: {a}\r\n"))
            .unwrap_or_default();
        exchange(router, "POST", None, &auth, body).await.0
    }

    /// Serve `router` with connect info on a loopback port and send one
    /// request. `host` replaces the real `Host` header; `extra` holds further
    /// header lines, each ending in CRLF. Returns the status and raw response.
    async fn exchange(
        router: Router,
        method: &str,
        host: Option<&str>,
        extra: &str,
        body: &str,
    ) -> (StatusCode, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        let host = host.map(String::from).unwrap_or_else(|| addr.to_string());
        let request = format!(
            "{method} / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        let code: u16 = response
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or_else(|| panic!("bad HTTP response: {response:?}"));
        (StatusCode::from_u16(code).unwrap(), response)
    }

    fn basic(user: &str, password: &str) -> String {
        use base64::Engine;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    }

    #[tokio::test]
    async fn rpc_without_credentials_is_never_open() {
        // no rpcuser/rpcpassword must not mean an unauthenticated RPC
        for (user, pass) in [(None, None), (Some("alice"), None), (Some(""), Some(""))] {
            let (server, _dir) = create_test_server();
            let config = RpcConfig {
                username: user.map(String::from),
                password: pass.map(String::from),
                ..RpcConfig::default()
            };
            let router = create_router_with_auth(server, &config);
            assert_eq!(
                status_of(router.clone(), None).await,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                status_of(router, Some(basic("", ""))).await,
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn cookie_credentials_authenticate() {
        let (server, dir) = create_test_server();
        let (user, password, cookie) =
            crate::auth_cookie::resolve_rpc_auth(None, None, dir.path()).unwrap();
        assert!(cookie.is_some());
        let config = RpcConfig {
            username: Some(user.clone()),
            password: Some(password.clone()),
            ..RpcConfig::default()
        };
        let router = create_router_with_auth(server, &config);
        assert_eq!(
            status_of(router.clone(), None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_of(router.clone(), Some(basic(&user, "wrong"))).await,
            StatusCode::UNAUTHORIZED
        );
        // What a client reads from the cookie file works
        let contents = std::fs::read_to_string(cookie.as_ref().unwrap().path()).unwrap();
        let (u, p) = contents.split_once(':').unwrap();
        assert_eq!(status_of(router, Some(basic(u, p))).await, StatusCode::OK);
    }
    fn alice_config(access: AccessConfig) -> RpcConfig {
        RpcConfig {
            username: Some("alice".into()),
            password: Some("s3cret".into()),
            access,
            ..RpcConfig::default()
        }
    }

    const GETBLOCKCOUNT: &str = r#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}"#;

    #[tokio::test]
    async fn node01_cors_preflight_has_no_wildcard() {
        let preflight = "Origin: http://evil.example\r\nAccess-Control-Request-Method: POST\r\n";
        let (server, _dir) = create_test_server();
        let router = create_router_with_auth(server, &alice_config(AccessConfig::default()));
        let (_, response) = exchange(router, "OPTIONS", None, preflight, "").await;
        assert!(
            !response
                .to_ascii_lowercase()
                .contains("access-control-allow-origin"),
            "{response}"
        );

        // A configured origin is echoed exactly; any other gets nothing
        let access = AccessConfig {
            allow_origins: vec!["http://wallet.example".into()],
            ..AccessConfig::default()
        };
        let (server, _dir) = create_test_server();
        let router = create_router_with_auth(server, &alice_config(access));
        let (_, response) = exchange(router.clone(), "OPTIONS", None, preflight, "").await;
        assert!(!response.contains("*"), "{response}");
        assert!(!response.contains("evil.example"), "{response}");
        let good = "Origin: http://wallet.example\r\nAccess-Control-Request-Method: POST\r\n";
        let (_, response) = exchange(router, "OPTIONS", None, good, "").await;
        assert!(
            response
                .to_ascii_lowercase()
                .contains("access-control-allow-origin: http://wallet.example"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn node01_foreign_host_and_origin_are_forbidden() {
        let (server, _dir) = create_test_server();
        let router = create_router_with_auth(server, &alice_config(AccessConfig::default()));
        let auth = format!("Authorization: {}\r\n", basic("alice", "s3cret"));
        // DNS rebinding: the browser sends the attacker's hostname
        let (status, _) = exchange(
            router.clone(),
            "POST",
            Some("evil.example:9998"),
            &auth,
            GETBLOCKCOUNT,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // A page on another site posting with the user's credentials
        let with_origin = format!("{auth}Origin: http://evil.example\r\n");
        let (status, _) = exchange(router.clone(), "POST", None, &with_origin, GETBLOCKCOUNT).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = exchange(router, "POST", None, &auth, GETBLOCKCOUNT).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn node01_router_without_connect_info_refuses() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (server, _dir) = create_test_server();
        let router = create_router_with_auth(server, &alice_config(AccessConfig::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{GETBLOCKCOUNT}",
            basic("alice", "s3cret"),
            GETBLOCKCOUNT.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    }

    #[tokio::test]
    async fn node12_rpcauth_authenticates_end_to_end() {
        use hmac::{Hmac, Mac};
        let salt = "00112233445566778899aabbccddeeff";
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(salt.as_bytes()).unwrap();
        mac.update(b"b0b-pass");
        let line = format!("bob:{salt}${}", hex::encode(mac.finalize().into_bytes()));
        let access = AccessConfig {
            rpcauth: vec![line],
            ..AccessConfig::default()
        };
        let (server, _dir) = create_test_server();
        let router = create_router_with_auth(server, &alice_config(access));
        assert_eq!(
            status_of(router.clone(), Some(basic("bob", "b0b-pass"))).await,
            StatusCode::OK
        );
        assert_eq!(
            status_of(router.clone(), Some(basic("bob", "wrong"))).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_of(router, Some(basic("alice", "s3cret"))).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn node12_whitelist_denies_method_and_batch() {
        let access = AccessConfig {
            whitelist: vec!["alice:getblockcount,getbestblockhash".into()],
            ..AccessConfig::default()
        };
        let (server, _dir) = create_test_server();
        let router = create_router_with_auth(server, &alice_config(access));
        let auth = format!("Authorization: {}\r\n", basic("alice", "s3cret"));
        let (status, _) = exchange(router.clone(), "POST", None, &auth, GETBLOCKCOUNT).await;
        assert_eq!(status, StatusCode::OK);
        let stop = r#"{"jsonrpc":"1.0","id":1,"method":"stop","params":[]}"#;
        let (status, _) = exchange(router.clone(), "POST", None, &auth, stop).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let batch = format!("[{GETBLOCKCOUNT},{stop}]");
        let (status, _) = exchange(router.clone(), "POST", None, &auth, &batch).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let batch = format!("[{GETBLOCKCOUNT},{GETBLOCKCOUNT}]");
        let (status, _) = exchange(router, "POST", None, &auth, &batch).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn node12_serve_refuses_unsafe_bind() {
        let (server, _dir) = create_test_server();
        let mut config = alice_config(AccessConfig::default());
        config.bind_address = "0.0.0.0:0".parse().unwrap();
        let err = serve(&config, server).await.unwrap_err();
        assert!(err.to_string().contains("rpcallowip"), "{err}");
    }

    /// The JSON body of a raw HTTP response
    fn body_json(response: &str) -> serde_json::Value {
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body:?}"))
    }

    #[tokio::test]
    async fn node13_batch_over_the_limit_is_refused() {
        let (server, _dir) = create_test_server();
        let router = create_router_with_auth(server, &alice_config(AccessConfig::default()));
        let auth = format!("Authorization: {}\r\n", basic("alice", "s3cret"));

        let batch = format!("[{}]", vec![GETBLOCKCOUNT; MAX_BATCH_CALLS].join(","));
        let (status, response) = exchange(router.clone(), "POST", None, &auth, &batch).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body_json(&response).as_array().unwrap().len(),
            MAX_BATCH_CALLS
        );

        let batch = format!("[{}]", vec![GETBLOCKCOUNT; MAX_BATCH_CALLS + 1].join(","));
        let (status, response) = exchange(router, "POST", None, &auth, &batch).await;
        assert_eq!(status, StatusCode::OK);
        let reply = body_json(&response);
        assert!(
            reply.is_object(),
            "one error, not a batch of results: {reply}"
        );
        assert_eq!(reply["error"]["code"], -32600, "{reply}");
    }

    #[tokio::test]
    async fn node13_body_over_max_request_size_gets_413() {
        let (server, _dir) = create_test_server();
        let mut config = alice_config(AccessConfig::default());
        config.max_request_size = 1024;
        let router = create_router_with_auth(server, &config);
        let auth = format!("Authorization: {}\r\n", basic("alice", "s3cret"));

        let (status, _) = exchange(router.clone(), "POST", None, &auth, GETBLOCKCOUNT).await;
        assert_eq!(status, StatusCode::OK);
        let padding = " ".repeat(2000);
        let big = format!("{GETBLOCKCOUNT}{padding}");
        let (status, _) = exchange(router, "POST", None, &auth, &big).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn node13_default_body_limit_holds_a_full_block() {
        // submitblock sends a 2 MB block as 4 MB of hex
        assert!(RpcConfig::default().max_request_size >= 4 * 1024 * 1024 + 1024);
    }
}
