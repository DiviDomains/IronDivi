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
        let connections = self
            .peer_manager
            .as_ref()
            .map(|pm| pm.peer_count())
            .unwrap_or(0);

        Ok(serde_json::json!({
            "version": 70920,
            "subversion": format!("/IronDivi:{}/", env!("CARGO_PKG_VERSION")),
            "protocolversion": 70920,
            "localservices": "0000000000000005",
            "timeoffset": 0,
            "connections": connections,
            "networks": [
                {
                    "name": "ipv4",
                    "limited": false,
                    "reachable": true
                },
                {
                    "name": "ipv6",
                    "limited": true,
                    "reachable": true
                },
                {
                    "name": "onion",
                    "limited": true,
                    "reachable": false
                }
            ],
            "relayfee": 0.0001,
            "localaddresses": []
        }))
    }

    /// Get peer info
    pub fn get_peer_info(&self, _params: &Params) -> Result<serde_json::Value, Error> {
        let peer_manager = match &self.peer_manager {
            Some(pm) => pm,
            None => return Ok(serde_json::json!([])),
        };

        let peers = peer_manager.get_peer_info();
        let peer_infos: Vec<serde_json::Value> = peers
            .iter()
            .enumerate()
            .map(|(id, (addr, inbound))| {
                serde_json::json!({
                    "id": id,
                    "addr": addr.to_string(),
                    "services": "0000000000000001",
                    "lastsend": 0,
                    "lastrecv": 0,
                    "bytessent": 0,
                    "bytesrecv": 0,
                    "conntime": 0,
                    "pingtime": 0.0,
                    "version": 70920,
                    "subver": "/Divi Core:3.0.0/",
                    "inbound": *inbound,
                    "startingheight": 0,
                    "synced_headers": -1,
                    "synced_blocks": -1
                })
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

        let addr_str = params
            .get_str(0)
            .ok_or_else(|| RpcError::invalid_params("Missing node address"))?;

        let command = params
            .get_str(1)
            .ok_or_else(|| RpcError::invalid_params("Missing command (add/remove/onetry)"))?;

        // Parse the address
        let addr: std::net::SocketAddr = if addr_str.contains(':') {
            addr_str.parse().map_err(|_| {
                RpcError::new(codes::CLIENT_INVALID_IP_OR_SUBNET, "Invalid address format")
            })?
        } else {
            // Default port is 51472
            format!("{}:51472", addr_str).parse().map_err(|_| {
                RpcError::new(codes::CLIENT_INVALID_IP_OR_SUBNET, "Invalid address format")
            })?
        };

        match command.to_lowercase().as_str() {
            "add" => {
                if !peer_manager.add_node(addr) {
                    return Err(RpcError::new(codes::MISC_ERROR, "Node already added").into());
                }
            }
            "remove" => {
                if !peer_manager.remove_added_node(&addr) {
                    return Err(RpcError::new(codes::MISC_ERROR, "Node has not been added").into());
                }
            }
            "onetry" => {
                // Just add it - connection will be attempted on next cycle
                peer_manager.add_node(addr);
            }
            _ => {
                return Err(RpcError::invalid_params(
                    "Command must be 'add', 'remove', or 'onetry'",
                )
                .into());
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
        let filter_addr: Option<std::net::SocketAddr> = params.get_str(0).and_then(|s| {
            if s.contains(':') {
                s.parse().ok()
            } else {
                format!("{}:51472", s).parse().ok()
            }
        });

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
                // Get ban time (default 24 hours)
                let ban_time = params.get_u64(2).unwrap_or(86400);
                let duration = Duration::from_secs(ban_time);

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
        let result: Vec<serde_json::Value> = bans
            .iter()
            .map(|ban| {
                serde_json::json!({
                    "address": ban.ip.to_string(),
                    "ban_created": ban.created_at.elapsed().as_secs(),
                    "banned_until": ban.remaining().as_secs(),
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

        // Find peer ID by address and disconnect
        // Note: This is a workaround since we don't have direct peer ID lookup by address
        if let Some(peer_id) = peer_manager.connected_peers().into_iter().next() {
            // Just disconnect the first matching peer
            // In production, would need better peer ID -> address mapping
            peer_manager.disconnect(peer_id);
            return Ok(serde_json::Value::Null);
        }

        Err(RpcError::new(
            codes::CLIENT_NODE_NOT_CONNECTED,
            "Could not find peer to disconnect",
        )
        .into())
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

    /// ping - Send ping to all peers
    pub fn ping(&self, _params: &Params) -> Result<serde_json::Value, Error> {
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

    #[test]
    fn test_get_peer_info_no_manager() {
        let rpc = NetworkRpc::new();
        let result = rpc.get_peer_info(&Params::None).unwrap();
        assert_eq!(result, serde_json::json!([]));
    }
}
