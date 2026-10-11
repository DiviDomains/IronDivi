// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Operational CLI for live EVM USDC setup (Sepolia or Base Sepolia): deploy `Erc20Htlc`,
//! move ETH (gas) and USDC between addresses, and check balances. Needs nothing beyond this
//! binary — no `forge`, no local chain — so it runs from a machine that has neither (the
//! orchestrator's Mac).
//!
//! The signing key is read from `SWAP_EVM_KEY_HEX` only: never a CLI argument (so it never
//! lands in shell history or `ps`), never printed, zeroized on drop. `balances` is
//! read-only and works without it.
//!
//! ```sh
//! cargo run -p swap-chain-evm --features live --example sepolia_ops -- balances --addr 0x...
//!
//! SWAP_EVM_KEY_HEX="$(op read 'op://.../password')" \
//!   cargo run -p swap-chain-evm --features live --example sepolia_ops -- deploy
//!
//! SWAP_EVM_KEY_HEX=<hex> cargo run -p swap-chain-evm --features live --example sepolia_ops \
//!   -- send-eth --to 0x... --wei 2000000000000000
//! SWAP_EVM_KEY_HEX=<hex> cargo run -p swap-chain-evm --features live --example sepolia_ops \
//!   -- send-usdc --to 0x... --units 5000000
//!
//! # Base Sepolia instead of the default (Ethereum) Sepolia:
//! cargo run -p swap-chain-evm --features live --example sepolia_ops -- \
//!   --network base-sepolia balances --addr 0x...
//! ```

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use clap::{Parser, Subcommand};
use swap_chain_evm::{
    connect_provider, deploy_contract, erc20_htlc_bytecode, IErc20, PrivateKeySigner, UsdcNetwork,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "sepolia_ops",
    about = "EVM USDC swap setup (Sepolia or Base Sepolia): deploy Erc20Htlc, fund addresses, check balances"
)]
struct Cli {
    /// Which EVM testnet: `sepolia` (default) or `base-sepolia`. Only picks defaults for
    /// `--rpc-url`/`--token` below when they are left unset.
    #[arg(long, default_value = "sepolia")]
    network: String,
    /// EVM JSON-RPC URL. Defaults to a free public endpoint for `--network`.
    #[arg(long, env = "SWAP_EVM_RPC_URL")]
    rpc_url: Option<String>,
    /// ERC-20 (USDC) token address. Defaults to Circle's test USDC for `--network`.
    #[arg(long)]
    token: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Deploy a fresh `Erc20Htlc` and print its address. Needs `SWAP_EVM_KEY_HEX`.
    Deploy,
    /// Send ETH (gas funds). Needs `SWAP_EVM_KEY_HEX`.
    SendEth {
        /// Recipient address.
        #[arg(long)]
        to: String,
        /// Amount in wei.
        #[arg(long)]
        wei: u128,
    },
    /// Send `--token` (USDC). Needs `SWAP_EVM_KEY_HEX`.
    SendUsdc {
        /// Recipient address.
        #[arg(long)]
        to: String,
        /// Amount in the token's base units (USDC has 6 decimals: 1_000_000 = 1 USDC).
        #[arg(long)]
        units: u64,
    },
    /// ETH and `--token` (USDC) balance of an address. Read-only: works without a key.
    Balances {
        #[arg(long)]
        addr: String,
    },
}

/// `SWAP_EVM_KEY_HEX`, zeroized on drop. Never read from argv, never printed.
fn read_key() -> Zeroizing<String> {
    Zeroizing::new(
        std::env::var("SWAP_EVM_KEY_HEX")
            .expect("SWAP_EVM_KEY_HEX not set (this subcommand signs a transaction)"),
    )
}

fn parse_addr(what: &str, s: &str) -> Address {
    s.parse()
        .unwrap_or_else(|e| panic!("bad {what} address {s:?}: {e}"))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let network: UsdcNetwork = cli
        .network
        .parse()
        .unwrap_or_else(|e| panic!("bad --network: {e}"));
    let rpc_url = cli
        .rpc_url
        .clone()
        .unwrap_or_else(|| network.default_rpc_url().to_string());
    let token = parse_addr(
        "--token",
        cli.token.as_deref().unwrap_or(network.usdc_token()),
    );

    match cli.cmd {
        Cmd::Balances { addr } => {
            let addr = parse_addr("--addr", &addr);
            let url = rpc_url.parse().expect("bad --rpc-url");
            let provider = DynProvider::new(ProviderBuilder::new().connect_http(url));
            let eth = provider.get_balance(addr).await.expect("get_balance");
            let usdc = IErc20::new(token, provider.clone())
                .balanceOf(addr)
                .call()
                .await
                .expect("balanceOf");
            println!("address: {addr}");
            println!("eth_wei: {eth}");
            println!("usdc_units: {usdc}");
        }
        Cmd::Deploy => {
            let key: PrivateKeySigner = read_key().trim().parse().expect("bad SWAP_EVM_KEY_HEX");
            let address = key.address();
            let provider = connect_provider(&rpc_url, key).expect("connect provider");
            eprintln!("deploying Erc20Htlc from {address} on {network}...");
            let htlc = deploy_contract(&provider, erc20_htlc_bytecode())
                .await
                .expect("deploy Erc20Htlc");
            println!("htlc_address: {htlc}");
        }
        Cmd::SendEth { to, wei } => {
            let key: PrivateKeySigner = read_key().trim().parse().expect("bad SWAP_EVM_KEY_HEX");
            let from = key.address();
            let to = parse_addr("--to", &to);
            let provider = connect_provider(&rpc_url, key).expect("connect provider");
            eprintln!("sending {wei} wei from {from} to {to} on {network}...");
            let tx = TransactionRequest::default()
                .with_to(to)
                .with_value(U256::from(wei));
            let receipt = provider
                .send_transaction(tx)
                .await
                .expect("send eth")
                .get_receipt()
                .await
                .expect("eth receipt");
            println!("tx: {}", receipt.transaction_hash);
            println!("gas_used: {}", receipt.gas_used);
        }
        Cmd::SendUsdc { to, units } => {
            let key: PrivateKeySigner = read_key().trim().parse().expect("bad SWAP_EVM_KEY_HEX");
            let from = key.address();
            let to = parse_addr("--to", &to);
            let provider = connect_provider(&rpc_url, key).expect("connect provider");
            eprintln!("sending {units} USDC base units from {from} to {to} on {network}...");
            let receipt = IErc20::new(token, provider)
                .transfer(to, U256::from(units))
                .send()
                .await
                .expect("send usdc")
                .get_receipt()
                .await
                .expect("usdc receipt");
            println!("tx: {}", receipt.transaction_hash);
            println!("gas_used: {}", receipt.gas_used);
        }
    }
}
