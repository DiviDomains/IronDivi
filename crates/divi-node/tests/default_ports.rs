// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The node serves JSON-RPC on Divi Core's default ports (chainparamsbase.cpp:
//! 51473 main, 51475 testnet and regtest), so divi-cli and code written for
//! divid reach it without -rpcport.

use divi_node::NodeConfig;
use divi_primitives::ChainMode;

#[test]
fn rpc_listens_on_divi_core_ports() {
    assert_eq!(NodeConfig::mainnet(ChainMode::Divi).rpc.port, 51473);
    assert_eq!(NodeConfig::testnet(ChainMode::Divi).rpc.port, 51475);
    assert_eq!(NodeConfig::regtest(ChainMode::Divi).rpc.port, 51475);
    assert_eq!(divi_node::RpcConfig::default().port, 51473);
    assert_eq!(divi_network::constants::DEFAULT_RPC_PORT_MAINNET, 51473);
    assert_eq!(divi_network::constants::DEFAULT_RPC_PORT_TESTNET, 51475);
    assert_eq!(divi_network::constants::DEFAULT_RPC_PORT_REGTEST, 51475);
}
