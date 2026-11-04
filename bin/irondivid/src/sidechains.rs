// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The sidechain market (`--features sidechains`): the `irondivi-sidechains`
//! service, mounted by the web interface at `/api/sidechains`. Without the
//! feature the interface answers there with 503 `not_installed`.

use divi_node::config::{NetworkType, NodeConfig};
use divi_rpc::RpcConfig;
use irondivi_sidechains::{Config, NodeInfo, Service};

/// The Sidechains page's API: the service over `<datadir>/sidechains`, its
/// registry scan and earnings read through this node's own RPC. Starts the
/// enabled chains and the background refresh; call inside the runtime.
pub fn router(config: &NodeConfig, rpc: &RpcConfig) -> axum::Router {
    let network = match config.network.network_type {
        NetworkType::Mainnet => dvsm_manifest::Network::Mainnet,
        NetworkType::Testnet => dvsm_manifest::Network::Testnet,
        NetworkType::Regtest => dvsm_manifest::Network::Regtest,
    };
    // A child reaches the RPC on loopback when it listens on every address
    let mut addr = rpc.bind_address;
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    let rpc_url = format!("http://{addr}");
    let node = NodeInfo {
        network,
        irondivid_version: env!("CARGO_PKG_VERSION").to_string(),
        txindex: config.index.txindex,
        addressindex: config.index.addressindex,
        rpc_url: rpc_url.clone(),
        rpc_user: rpc.username.clone(),
        rpc_password: rpc.password.clone(),
    };
    let mut cfg = Config::new(&config.data_dir, node);
    let mut client = dvsc_registry::Rpc::http(&rpc_url);
    if let (Some(user), Some(password)) = (&rpc.username, &rpc.password) {
        client = client.with_auth(user, password);
    }
    cfg.rpc = Some(client);
    let svc = Service::new(cfg);
    svc.spawn_background();
    irondivi_sidechains::router(svc)
}
