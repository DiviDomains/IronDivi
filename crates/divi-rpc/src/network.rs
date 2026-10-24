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

//! Network RPC methods
//!
//! Provides RPC methods for network-related queries.

use crate::error::{codes, Error, RpcError};
use crate::protocol::Params;
use divi_network::PeerManager;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Divi Core's addnode help, the error for a call it cannot take
/// (rpcnet.cpp:156-170)
const ADDNODE_USAGE: &str = "addnode \"node\" \"add|remove|onetry\"\n\nAttempts add or remove a node from the addnode list.\nOr try a connection to a node once.\n\nArguments:\n1. \"node\"     (string, required) The node (see getpeerinfo for nodes)\n2. \"command\"  (string, required) 'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once\n\nExamples:\n> divi-cli addnode \"192.168.0.6:51472\" \"onetry\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"addnode\", \"params\": [\"192.168.0.6:51472\", \"onetry\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n";

/// Network RPC handler
pub struct NetworkRpc {
    /// Peer manager for network queries
    peer_manager: Option<Arc<PeerManager>>,
}

impl NetworkRpc {
    /// Create a new network RPC handler without peer manager
    pub fn new() -> Self {
        NetworkRpc { peer_manager: None }
    }

    /// Create a new network RPC handler with peer manager
    pub fn with_peer_manager(peer_manager: Arc<PeerManager>) -> Self {
        NetworkRpc {
            peer_manager: Some(peer_manager),
        }
    }

    /// Set the peer manager
    pub fn set_peer_manager(&mut self, peer_manager: Arc<PeerManager>) {
        self.peer_manager = Some(peer_manager);
    }

    /// Get network info
    pub fn get_network_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let pm = self.peer_manager.as_ref();
        let connections = pm.map(|pm| pm.peer_count()).unwrap_or(0);
        let connections_in = pm.map(|pm| pm.inbound_count()).unwrap_or(0);
        let connections_out = pm.map(|pm| pm.outbound_count()).unwrap_or(0);
        let proxy = pm
            .and_then(|pm| pm.proxy())
            .map(|p| p.to_string())
            .unwrap_or_default();
        let local_services = pm
            .map(|pm| pm.services())
            .unwrap_or(divi_network::constants::services::NODE_NETWORK);

        Ok(serde_json::json!({
            "version": format!("{}.0", env!("CARGO_PKG_VERSION")),
            "subversion": divi_network::USER_AGENT,
            "protocolversion": divi_network::constants::protocol_version(),
            "localservices": format!("{:016x}", local_services),
            "timeoffset": self.time_offset(),
            "connections": connections,
            "connections_in": connections_in,
            "connections_out": connections_out,
            "networks": [
                {
                    "name": "ipv4",
                    "limited": false,
                    "reachable": true,
                    "proxy": proxy,
                    "proxy_randomize_credentials": false
                },
                {
                    "name": "ipv6",
                    "limited": false,
                    "reachable": true,
                    "proxy": proxy,
                    "proxy_randomize_credentials": false
                },
                {
                    // .onion peers cannot be addressed (peer addresses are IP only)
                    "name": "onion",
                    "limited": true,
                    "reachable": false,
                    "proxy": "",
                    "proxy_randomize_credentials": false
                }
            ],
            "relayfee": 0.0001,
            // Divi Core gives port and score as strings (NetworkLocalAddressHelpers.cpp:45-51)
            "localaddresses": pm
                .map(|pm| pm.local_addresses().list())
                .unwrap_or_default()
                .into_iter()
                .map(|a| serde_json::json!({
                    "address": a.address.to_string(),
                    "port": a.port.to_string(),
                    "score": a.score.to_string(),
                }))
                .collect::<Vec<_>>()
        }))
    }

    /// Network-adjusted time offset in seconds: the median of the connected peers'
    /// clock offsets, used once at least 5 peers are known (C++ `GetTimeOffset`)
    fn time_offset(&self) -> i64 {
        use std::sync::atomic::Ordering::Relaxed;
        let Some(pm) = &self.peer_manager else {
            return 0;
        };
        let mut offsets: Vec<i64> = pm
            .get_peer_details()
            .iter()
            .map(|(_, _, _, st, _)| st.time_offset.load(Relaxed))
            .collect();
        if offsets.len() < 5 {
            return 0;
        }
        offsets.sort_unstable();
        offsets[offsets.len() / 2]
    }

    /// Get peer info
    pub fn get_peer_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let peer_manager = match &self.peer_manager {
            Some(pm) => pm,
            None => return Ok(serde_json::json!([])),
        };

        use std::sync::atomic::Ordering::Relaxed;
        let peers = peer_manager.get_peer_details();
        let peer_infos: Vec<serde_json::Value> = peers
            .iter()
            .map(|(id, addr, inbound, st, banscore)| {
                let ping_us = st.ping_us.load(Relaxed);
                let ping_sent_us = st.ping_sent_us.load(Relaxed);
                let subver = st.subver.lock().clone();
                let mut info = serde_json::json!({
                    "id": id,
                    "addr": addr.to_string(),
                    "services": format!("{:016x}", st.services.load(Relaxed)),
                    "lastsend": st.last_send.load(Relaxed),
                    "lastrecv": st.last_recv.load(Relaxed),
                    "bytessent": st.bytes_sent.load(Relaxed),
                    "bytesrecv": st.bytes_recv.load(Relaxed),
                    "conntime": st.conn_time.load(Relaxed),
                    "pingtime": ping_us as f64 / 1_000_000.0,
                    "version": st.version.load(Relaxed),
                    "subver": subver,
                    "inbound": *inbound,
                    "startingheight": st.start_height.load(Relaxed),
                    "banscore": banscore,
                    "inflight": [],
                    "whitelisted": false,
                    "synced_headers": -1,
                    "synced_blocks": -1
                });
                // Like C++, pingwait is only present while a ping is unanswered
                if ping_sent_us != 0 {
                    let wait_us = divi_network::peer::unix_now_us().saturating_sub(ping_sent_us);
                    info["pingwait"] = serde_json::json!(wait_us as f64 / 1_000_000.0);
                }
                info
            })
            .collect();

        Ok(serde_json::json!(peer_infos))
    }

    /// Get connection count
    pub fn get_connection_count(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let count = self
            .peer_manager
            .as_ref()
            .map(|pm| pm.peer_count())
            .unwrap_or(0);

        Ok(serde_json::json!(count))
    }

    /// Add a node to connect to
    ///
    /// addnode "node" "add|remove|onetry"
    pub fn add_node(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let peer_manager = self
            .peer_manager
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Peer manager not available"))?;

        // Divi Core takes exactly a node and one of its three commands, as
        // written; anything else is answered with its help (rpcnet.cpp:156-170)
        let usage = || RpcError::new(codes::MISC_ERROR, ADDNODE_USAGE);
        let command = match (params.len(), params.get_str(0), params.get_str(1)) {
            (2, Some(_), Some(c)) if ["add", "remove", "onetry"].contains(&c) => c,
            _ => return Err(usage().into()),
        };
        let addr_str = params.get_str(0).unwrap_or_default();

        // An address without a port gets the network's (Params().GetDefaultPort())
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .or_else(|_| {
                addr_str
                    .parse::<IpAddr>()
                    .map(|ip| std::net::SocketAddr::new(ip, peer_manager.default_port()))
            })
            .map_err(|_| {
                RpcError::new(codes::CLIENT_INVALID_IP_OR_SUBNET, "Invalid address format")
            })?;

        match command {
            "add" => {
                if !peer_manager.add_node(addr) {
                    return Err(RpcError::new(
                        codes::CLIENT_NODE_ALREADY_ADDED,
                        "Error: Node already added",
                    )
                    .into());
                }
            }
            "remove" => {
                if !peer_manager.remove_added_node(&addr) {
                    return Err(RpcError::new(
                        codes::CLIENT_NODE_NOT_ADDED,
                        "Error: Node has not been added.",
                    )
                    .into());
                }
            }
            _ => {
                // Divi Core dials it once, now, and does not keep it in the list
                peer_manager.connect_once(addr);
            }
        }

        Ok(serde_json::Value::Null)
    }

    /// Get added node info
    pub fn get_added_node_info(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let peer_manager = self
            .peer_manager
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Peer manager not available"))?;

        let added_nodes = peer_manager.get_added_node_info();

        // Optional: filter by specific node address
        // C++ signature: getaddednodeinfo dns ( "node" ) -- the bool comes first
        if params.get(0).and_then(|v| v.as_bool()).is_none() {
            return Err(RpcError::new(
                codes::MISC_ERROR,
                "getaddednodeinfo dns ( \"node\" )\n\nArguments:\n1. dns   (boolean, required) true to include DNS details\n2. node  (string, optional) only return this added node",
            )
            .into());
        }
        let filter_addr: Option<std::net::SocketAddr> = params.get_str(1).and_then(|s| {
            if s.contains(':') {
                s.parse().ok()
            } else {
                format!("{}:51472", s).parse().ok()
            }
        });

        if params.get_str(1).is_some() && !added_nodes.iter().any(|n| filter_addr == Some(n.addr)) {
            return Err(RpcError::new(
                codes::CLIENT_NODE_NOT_ADDED,
                "Error: Node has not been added.",
            )
            .into());
        }

        let result: Vec<_> = added_nodes
            .iter()
            .filter(|n| filter_addr.is_none() || filter_addr == Some(n.addr))
            .map(|node| {
                serde_json::json!({
                    "addednode": node.addr.to_string(),
                    "connected": node.connected,
                    "addresses": if node.connected {
                        vec![serde_json::json!({
                            "address": node.addr.to_string(),
                            "connected": "outbound"
                        })]
                    } else {
                        vec![]
                    }
                })
            })
            .collect();

        Ok(serde_json::json!(result))
    }

    /// Ban a network address
    /// setban "ip" "add|remove" (bantime) (absolute)
    pub fn set_ban(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let peer_manager = self
            .peer_manager
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Peer manager not available"))?;

        let ip_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("IP address required"))?;

        let command = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Command required (add/remove)"))?;

        // Parse IP address (may have /subnet notation)
        let ip_str = ip_str.split('/').next().unwrap_or(ip_str);
        let ip: IpAddr = ip_str.parse().map_err(|_| {
            RpcError::new(
                codes::CLIENT_INVALID_IP_OR_SUBNET,
                format!("Invalid IP: {}", ip_str),
            )
        })?;

        match command.to_lowercase().as_str() {
            "add" => {
                // Ban time: missing or 0 means the node's -bantime (default 24 hours)
                let duration = match params.get_u64(2) {
                    Some(secs) if secs > 0 => Duration::from_secs(secs),
                    _ => peer_manager.scoring().ban_policy().1,
                };

                peer_manager.ban_ip(ip, duration, "Manually banned via RPC");
                Ok(serde_json::Value::Null)
            }
            "remove" => {
                if peer_manager.unban_ip(&ip) {
                    Ok(serde_json::Value::Null)
                } else {
                    Err(
                        RpcError::new(codes::CLIENT_INVALID_IP_OR_SUBNET, "IP not in ban list")
                            .into(),
                    )
                }
            }
            _ => Err(RpcError::invalid_params("Command must be 'add' or 'remove'").into()),
        }
    }

    /// List all banned IPs
    pub fn list_banned(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let peer_manager = match &self.peer_manager {
            Some(pm) => pm,
            None => return Ok(serde_json::json!([])),
        };

        let bans = peer_manager.scoring().list_bans();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let result: Vec<serde_json::Value> = bans
            .iter()
            .map(|ban| {
                serde_json::json!({
                    "address": ban.ip.to_string(),
                    // Unix times, as in Bitcoin Core's listbanned
                    "ban_created": now.saturating_sub(ban.created_at.elapsed().as_secs()),
                    "banned_until": now + ban.remaining().as_secs(),
                    "ban_reason": ban.reason,
                })
            })
            .collect();

        Ok(serde_json::json!(result))
    }

    /// Clear all banned IPs
    pub fn clear_banned(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let peer_manager = self
            .peer_manager
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Peer manager not available"))?;

        peer_manager.scoring().clear_bans();
        Ok(serde_json::Value::Null)
    }

    /// Disconnect a node
    pub fn disconnect_node(&self, params: &Params) -> Result<serde_json::Value, Error> {
        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Node address required"))?;

        let peer_manager = self
            .peer_manager
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Peer manager not available"))?;

        // Find peer by address and disconnect
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .map_err(|_| RpcError::invalid_params(format!("Invalid address: {}", addr_str)))?;

        let peers = peer_manager.peer_addresses();
        if !peers.contains(&addr) {
            return Err(
                RpcError::new(codes::CLIENT_NODE_NOT_CONNECTED, "Node not connected").into(),
            );
        }

        match peer_manager.peer_id_for_addr(&addr) {
            Some(peer_id) => {
                peer_manager.disconnect(peer_id);
                Ok(serde_json::Value::Null)
            }
            None => Err(RpcError::new(
                codes::CLIENT_NODE_NOT_CONNECTED,
                "Could not find peer to disconnect",
            )
            .into()),
        }
    }

    /// ban "outdated"|"ip" - ban and disconnect a connected peer (C++ `ban`).
    ///
    /// Like C++, only a currently connected peer can be banned; the ban is lifetime.
    pub fn ban(&self, params: &Params) -> Result<serde_json::Value, Error> {
        const LIFETIME: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

        let target = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("ban [outdated|<ip_address>]"))?;
        let peer_manager = self
            .peer_manager
            .as_ref()
            .ok_or_else(|| RpcError::new(codes::MISC_ERROR, "Peer manager not available"))?;

        if target == "outdated" {
            // Peer sub-versions are not recorded after the handshake, so "outdated" peers
            // cannot be identified; refuse rather than report an empty (false) success.
            return Err(RpcError::new(
                codes::MISC_ERROR,
                "ban outdated is not supported: peer versions are not tracked",
            )
            .into());
        }

        // C++ ban reports an unresolvable address the same way as an unknown peer
        let ip: IpAddr = match target.parse() {
            Ok(ip) => ip,
            Err(_) => {
                return Ok(serde_json::json!({ "Banned": "Could not find matching node to ban" }));
            }
        };
        let ids = peer_manager.peer_ids_for_ip(ip);
        if ids.is_empty() {
            return Ok(serde_json::json!({ "Banned": "Could not find matching node to ban" }));
        }
        peer_manager.ban_ip(ip, LIFETIME, "Manually banned via RPC");
        for id in ids {
            peer_manager.disconnect(id);
        }
        Ok(serde_json::json!({ "Banned": ip.to_string() }))
    }

    /// Get peer scoring info (debugging)
    pub fn get_peer_scores(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let peer_manager = match &self.peer_manager {
            Some(pm) => pm,
            None => return Ok(serde_json::json!([])),
        };

        let stats = peer_manager.scoring().all_stats();
        let result: Vec<serde_json::Value> = stats
            .iter()
            .map(|s| {
                serde_json::json!({
                    "peer_id": s.peer_id,
                    "ip": s.ip.to_string(),
                    "misbehavior_score": s.misbehavior_score,
                    "reliability_score": s.reliability_score(),
                    "blocks_received": s.blocks_received,
                    "txs_received": s.txs_received,
                    "avg_latency_ms": s.avg_latency_ms,
                    "is_responsive": s.is_responsive(),
                })
            })
            .collect();

        Ok(serde_json::json!(result))
    }

    /// ping - Queue a ping to every peer; the results show in getpeerinfo
    /// pingtime/pingwait (C++ `ping`)
    pub fn ping(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        if let Some(pm) = &self.peer_manager {
            pm.ping_all();
        }
        Ok(serde_json::Value::Null)
    }

    /// getnettotals - Get network traffic statistics
    pub fn get_net_totals(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let (total_sent, total_recv) = self
            .peer_manager
            .as_ref()
            .map(|pm| pm.get_net_totals())
            .unwrap_or((0, 0));

        Ok(serde_json::json!({
            "totalbytesrecv": total_recv,
            "totalbytessent": total_sent,
            "timemillis": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        }))
    }
}

impl Default for NetworkRpc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_rpc_creation() {
        let rpc = NetworkRpc::new();
        assert!(rpc.peer_manager.is_none());
    }

    #[test]
    fn test_get_connection_count_no_peers() {
        let rpc = NetworkRpc::new();
        let result = rpc.get_connection_count(&Params::None).unwrap();
        assert_eq!(result, serde_json::json!(0));
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn quiet_config() -> divi_network::PeerManagerConfig {
        divi_network::PeerManagerConfig {
            dns_seeds: vec![],
            static_peers: vec![],
            listen_addr: None,
            ..Default::default()
        }
    }

    /// Two nodes on localhost: the per-peer counters and the in/out split must be real.
    /// getpeerinfo used to show pingtime 0 (no ping until 30 s in, then rounded to whole
    /// milliseconds) and getnetworkinfo had no in/out split, so `-getinfo` printed 0/0.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peer_counters_and_connection_split_are_real() {
        use std::time::Duration;
        let listen: std::net::SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let server = PeerManager::new(divi_network::PeerManagerConfig {
            listen_addr: Some(listen),
            ..quiet_config()
        });
        tokio::spawn(Arc::clone(&server).start());
        let client = PeerManager::new(quiet_config());
        let mut connected = false;
        for _ in 0..50 {
            if Arc::clone(&client).connect_to_peer(listen).await.is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(connected, "client could not reach the local listener");

        let client_rpc = NetworkRpc::with_peer_manager(Arc::clone(&client));
        let server_rpc = NetworkRpc::with_peer_manager(Arc::clone(&server));
        let mut peer = serde_json::Value::Null;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let peers = client_rpc.get_peer_info(&Params::None).unwrap();
            if let Some(p) = peers.as_array().and_then(|a| a.first()) {
                if p["pingtime"].as_f64().unwrap_or(0.0) > 0.0 {
                    peer = p.clone();
                    break;
                }
            }
        }
        assert!(
            peer["pingtime"].as_f64().unwrap_or(0.0) > 0.0,
            "pingtime still 0 after 5 s"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let conntime = peer["conntime"].as_u64().unwrap();
        assert!(conntime > 0 && conntime <= now && now - conntime < 60);
        // version + verack + pong at least: 126 + 24 + 32 bytes on the wire
        assert!(peer["bytesrecv"].as_u64().unwrap() >= 182, "{peer}");
        assert!(peer["bytessent"].as_u64().unwrap() > 0);
        assert_eq!(peer["inbound"], false);

        let ni = client_rpc.get_network_info(&Params::None).unwrap();
        assert_eq!(ni["connections"], 1);
        assert_eq!(ni["connections_in"], 0);
        assert_eq!(ni["connections_out"], 1);
        let ni = server_rpc.get_network_info(&Params::None).unwrap();
        assert_eq!(ni["connections_in"], 1);
        assert_eq!(ni["connections_out"], 0);
        let inbound = &server_rpc.get_peer_info(&Params::None).unwrap()[0];
        assert_eq!(inbound["inbound"], true);
        assert!(inbound["bytesrecv"].as_u64().unwrap() > 0);
        client.disconnect_all();
        server.disconnect_all();
    }

    /// The `ping` RPC returned null without sending anything. It must queue a timed ping
    /// to every peer: the peer answers, and both sides count the traffic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ping_rpc_pings_every_peer() {
        use std::time::Duration;
        let listen: std::net::SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let server = PeerManager::new(divi_network::PeerManagerConfig {
            listen_addr: Some(listen),
            ..quiet_config()
        });
        tokio::spawn(Arc::clone(&server).start());
        let client = PeerManager::new(quiet_config());
        let mut connected = false;
        for _ in 0..50 {
            if Arc::clone(&client).connect_to_peer(listen).await.is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(connected);
        let client_rpc = NetworkRpc::with_peer_manager(Arc::clone(&client));
        let server_rpc = NetworkRpc::with_peer_manager(Arc::clone(&server));
        let peer = |rpc: &NetworkRpc| rpc.get_peer_info(&Params::None).unwrap()[0].clone();
        let n = |v: &serde_json::Value, k: &str| v[k].as_u64().unwrap_or(0);

        // Let the handshake pings finish in both directions, then the link is quiet
        // (next keep-alive is 30 s away)
        let mut settled = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let (c, s) = (peer(&client_rpc), peer(&server_rpc));
            if c["pingtime"].as_f64().unwrap_or(0.0) > 0.0
                && s["pingtime"].as_f64().unwrap_or(0.0) > 0.0
                && c.get("pingwait").is_none()
                && s.get("pingwait").is_none()
            {
                settled = true;
                break;
            }
        }
        assert!(settled, "handshake pings did not complete");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let (c0, s0) = (peer(&client_rpc), peer(&server_rpc));

        assert_eq!(
            client_rpc.ping(&Params::None).unwrap(),
            serde_json::Value::Null
        );
        // ping and pong are 32 bytes each on the wire (24-byte header + 8-byte nonce)
        let mut c1 = c0.clone();
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            c1 = peer(&client_rpc);
            if n(&c1, "bytesrecv") >= n(&c0, "bytesrecv") + 32 {
                break;
            }
        }
        assert_eq!(
            n(&c1, "bytessent"),
            n(&c0, "bytessent") + 32,
            "ping not sent: {c1}"
        );
        assert_eq!(
            n(&c1, "bytesrecv"),
            n(&c0, "bytesrecv") + 32,
            "no pong: {c1}"
        );
        let s1 = peer(&server_rpc);
        assert_eq!(n(&s1, "bytesrecv"), n(&s0, "bytesrecv") + 32);
        assert!(c1["pingtime"].as_f64().unwrap() > 0.0);
        assert!(c1.get("pingwait").is_none(), "pong was matched: {c1}");
        client.disconnect_all();
        server.disconnect_all();
    }

    /// Divi Core `addnode … onetry` (net.cpp addNode): dials now, by address and
    /// port even when a peer from that IP is connected, and is not kept in the
    /// added-node list
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_addnode_onetry_dials_once_now() {
        use std::time::Duration;
        let listen: std::net::SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let server = PeerManager::new(divi_network::PeerManagerConfig {
            listen_addr: Some(listen),
            ..quiet_config()
        });
        tokio::spawn(Arc::clone(&server).start());
        let client = PeerManager::new(quiet_config());
        let mut connected = false;
        for _ in 0..50 {
            if Arc::clone(&client).connect_to_peer(listen).await.is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(connected, "client did not connect to the server");

        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let rpc = NetworkRpc::with_peer_manager(Arc::clone(&client));
        rpc.add_node(&Params::Array(vec![
            serde_json::json!(target_addr.to_string()),
            serde_json::json!("onetry"),
        ]))
        .unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(10), target.accept()).await;
        assert!(accepted.is_ok(), "onetry did not dial");
        assert!(!client.is_added_node(&target_addr));
        client.disconnect_all();
        server.disconnect_all();
    }

    #[test]
    fn test_network_info_reports_proxy() {
        let proxy: std::net::SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let pm = PeerManager::new(divi_network::PeerManagerConfig {
            proxy: Some(proxy),
            ..quiet_config()
        });
        let ni = NetworkRpc::with_peer_manager(pm)
            .get_network_info(&Params::None)
            .unwrap();
        let nets = ni["networks"].as_array().unwrap();
        assert_eq!(nets[0]["name"], "ipv4");
        assert_eq!(nets[0]["proxy"], "127.0.0.1:9050");
        assert_eq!(nets[1]["proxy"], "127.0.0.1:9050");
        assert_eq!(nets[2]["reachable"], false);
        let ni = NetworkRpc::with_peer_manager(PeerManager::new(quiet_config()))
            .get_network_info(&Params::None)
            .unwrap();
        assert_eq!(ni["networks"][0]["proxy"], "");
    }

    /// The code and message of an RPC error
    fn rpc_err(r: Result<serde_json::Value, Error>) -> (i32, String) {
        match r {
            Err(Error::Rpc(e)) => (e.code, e.message),
            other => panic!("expected an RPC error, got {other:?}"),
        }
    }

    fn regtest_peers() -> Arc<PeerManager> {
        PeerManager::new(divi_network::PeerManagerConfig {
            default_port: 51476,
            ..quiet_config()
        })
    }

    /// addnode as Divi Core answers it (rpcnet.cpp:156-186): -23 and -24 with
    /// its texts, its help for a call it cannot take, and the network's port
    /// for an address given without one
    #[test]
    fn addnode_replies_as_divid() {
        let pm = regtest_peers();
        let rpc = NetworkRpc::with_peer_manager(Arc::clone(&pm));
        let call = |args: Vec<serde_json::Value>| rpc.add_node(&Params::Array(args));
        let (add, remove) = (serde_json::json!("add"), serde_json::json!("remove"));
        let node = serde_json::json!("192.0.2.1");

        assert_eq!(
            call(vec![node.clone(), add.clone()]).unwrap(),
            serde_json::Value::Null
        );
        assert_eq!(
            pm.get_added_node_info()[0].addr,
            "192.0.2.1:51476".parse().unwrap()
        );
        assert_eq!(
            rpc_err(call(vec![
                serde_json::json!("192.0.2.1:51476"),
                add.clone()
            ])),
            (-23, "Error: Node already added".to_string())
        );
        assert_eq!(
            call(vec![node.clone(), remove.clone()]).unwrap(),
            serde_json::Value::Null
        );
        assert_eq!(
            rpc_err(call(vec![node.clone(), remove])),
            (-24, "Error: Node has not been added.".to_string())
        );
        for bad in [
            vec![],
            vec![node.clone()],
            vec![node.clone(), serde_json::json!("ADD")],
            vec![node.clone(), serde_json::json!("badcommand")],
            vec![node, add, serde_json::json!(1)],
        ] {
            let (code, message) = rpc_err(call(bad.clone()));
            assert_eq!(code, -1, "{bad:?}");
            assert!(
                message.starts_with("addnode \"node\" \"add|remove|onetry\"\n\nAttempts add")
                    && message.ends_with("http://127.0.0.1:51473/\n"),
                "{bad:?}: {message}"
            );
        }
    }

    #[test]
    fn test_get_peer_info_no_manager() {
        let rpc = NetworkRpc::new();
        let result = rpc.get_peer_info(&Params::None).unwrap();
        assert_eq!(result, serde_json::json!([]));
    }
}
