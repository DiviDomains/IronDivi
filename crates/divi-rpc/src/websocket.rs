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

//! WebSocket endpoint for real-time notifications
//!
//! Provides push notifications for lite wallet clients:
//! - Address balance changes
//! - New transactions for subscribed addresses
//! - Block notifications
//! - Mempool updates

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Maximum number of subscriptions per client
const MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 100;

/// Notification types sent to clients
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "data")]
pub enum Notification {
    /// New block notification
    #[serde(rename = "block")]
    Block {
        hash: String,
        height: u32,
        timestamp: u32,
    },

    /// Address received funds
    #[serde(rename = "address_received")]
    AddressReceived {
        address: String,
        txid: String,
        amount: i64,
        confirmations: u32,
    },

    /// Address spent funds
    #[serde(rename = "address_spent")]
    AddressSpent {
        address: String,
        txid: String,
        amount: i64,
        confirmations: u32,
    },

    /// Transaction confirmed
    #[serde(rename = "tx_confirmed")]
    TxConfirmed { txid: String, confirmations: u32 },

    /// Subscription confirmed
    #[serde(rename = "subscribed")]
    Subscribed { address: String },

    /// Unsubscription confirmed
    #[serde(rename = "unsubscribed")]
    Unsubscribed { address: String },

    /// Error message
    #[serde(rename = "error")]
    Error { message: String },

    /// Pong response
    #[serde(rename = "pong")]
    Pong { timestamp: u64 },
}

/// Client subscription request
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Subscribe to address notifications
    #[serde(rename = "subscribe")]
    Subscribe { address: String },

    /// Unsubscribe from address notifications
    #[serde(rename = "unsubscribe")]
    Unsubscribe { address: String },

    /// Subscribe to block notifications
    #[serde(rename = "subscribe_blocks")]
    SubscribeBlocks,

    /// Unsubscribe from block notifications
    #[serde(rename = "unsubscribe_blocks")]
    UnsubscribeBlocks,

    /// Ping to keep connection alive
    #[serde(rename = "ping")]
    Ping { timestamp: u64 },
}

/// Client session state
struct ClientSession {
    /// Subscribed addresses (as script_pubkey bytes)
    subscribed_addresses: HashSet<Vec<u8>>,
    /// Subscribe to block notifications
    subscribe_blocks: bool,
}

impl ClientSession {
    fn new() -> Self {
        ClientSession {
            subscribed_addresses: HashSet::new(),
            subscribe_blocks: false,
        }
    }
}

/// Notification hub for managing subscriptions and broadcasting
pub struct NotificationHub {
    /// Broadcast channel for notifications
    tx: broadcast::Sender<(Vec<u8>, Notification)>,
    /// Block notification channel
    block_tx: broadcast::Sender<Notification>,
    /// Address to script mapping for reverse lookup
    address_to_script: RwLock<HashMap<String, Vec<u8>>>,
}

impl NotificationHub {
    /// Create a new notification hub
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(10000);
        let (block_tx, _) = broadcast::channel(1000);

        Arc::new(NotificationHub {
            tx,
            block_tx,
            address_to_script: RwLock::new(HashMap::new()),
        })
    }

    /// Subscribe to notifications
    pub fn subscribe(&self) -> broadcast::Receiver<(Vec<u8>, Notification)> {
        self.tx.subscribe()
    }

    /// Subscribe to block notifications
    pub fn subscribe_blocks(&self) -> broadcast::Receiver<Notification> {
        self.block_tx.subscribe()
    }

    /// Notify about a new block
    pub fn notify_block(&self, hash: &Hash256, height: u32, timestamp: u32) {
        let notification = Notification::Block {
            hash: hash.to_string(),
            height,
            timestamp,
        };

        if let Err(e) = self.block_tx.send(notification) {
            debug!("No block subscribers: {}", e);
        }
    }

    /// Notify about address receiving funds
    pub fn notify_address_received(
        &self,
        script: &Script,
        address: &str,
        txid: &Hash256,
        amount: i64,
        confirmations: u32,
    ) {
        let notification = Notification::AddressReceived {
            address: address.to_string(),
            txid: txid.to_string(),
            amount,
            confirmations,
        };

        let key = script.as_bytes().to_vec();
        if let Err(e) = self.tx.send((key, notification)) {
            debug!("No address subscribers: {}", e);
        }
    }

    /// Notify about address spending funds
    pub fn notify_address_spent(
        &self,
        script: &Script,
        address: &str,
        txid: &Hash256,
        amount: i64,
        confirmations: u32,
    ) {
        let notification = Notification::AddressSpent {
            address: address.to_string(),
            txid: txid.to_string(),
            amount,
            confirmations,
        };

        let key = script.as_bytes().to_vec();
        if let Err(e) = self.tx.send((key, notification)) {
            debug!("No address subscribers: {}", e);
        }
    }

    /// Parse address to script
    fn parse_address(&self, addr_str: &str) -> Option<Vec<u8>> {
        use divi_primitives::script::Script;
        use divi_wallet::address::{Address, AddressType};

        let address = Address::from_base58(addr_str).ok()?;
        let script = match address.addr_type {
            AddressType::P2PKH => Script::new_p2pkh(address.hash.as_bytes()),
            AddressType::P2SH => Script::new_p2sh(address.hash.as_bytes()),
        };

        // Cache the mapping
        self.address_to_script
            .write()
            .insert(addr_str.to_string(), script.as_bytes().to_vec());

        Some(script.as_bytes().to_vec())
    }
}

impl Default for NotificationHub {
    fn default() -> Self {
        let hub = Self::new();
        // This is a bit awkward but we need to return Self, not Arc<Self>
        // In practice, always use new() which returns Arc<Self>
        NotificationHub {
            tx: hub.tx.clone(),
            block_tx: hub.block_tx.clone(),
            address_to_script: RwLock::new(HashMap::new()),
        }
    }
}

/// WebSocket state for axum
pub struct WsState {
    hub: Arc<NotificationHub>,
}

impl WsState {
    pub fn new(hub: Arc<NotificationHub>) -> Self {
        WsState { hub }
    }
}

/// WebSocket upgrade handler
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WsState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Handle a WebSocket connection
async fn handle_socket(socket: WebSocket, state: Arc<WsState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut session = ClientSession::new();

    // Subscribe to notification channels
    let mut addr_rx = state.hub.subscribe();
    let mut block_rx = state.hub.subscribe_blocks();

    info!("New WebSocket client connected");

    loop {
        tokio::select! {
            // Handle incoming messages from client
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(e) = handle_client_message(&text, &mut session, &state.hub, &mut sender).await {
                            warn!("Error handling client message: {}", e);
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!("WebSocket client disconnected");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if sender.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                    None => break,
                    _ => {}
                }
            }

            // Handle address notifications
            notification = addr_rx.recv() => {
                match notification {
                    Ok((script_key, notif)) => {
                        if session.subscribed_addresses.contains(&script_key) {
                            let json = serde_json::to_string(&notif).unwrap_or_default();
                            if sender.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Dropped {} notifications due to lag", n);
                    }
                    Err(_) => break,
                }
            }

            // Handle block notifications
            notification = block_rx.recv() => {
                match notification {
                    Ok(notif) => {
                        if session.subscribe_blocks {
                            let json = serde_json::to_string(&notif).unwrap_or_default();
                            if sender.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Dropped {} block notifications due to lag", n);
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

/// Handle a message from the client
async fn handle_client_message(
    text: &str,
    session: &mut ClientSession,
    hub: &NotificationHub,
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures::SinkExt;

    let msg: ClientMessage = serde_json::from_str(text)?;

    let response = match msg {
        ClientMessage::Subscribe { address } => {
            if session.subscribed_addresses.len() >= MAX_SUBSCRIPTIONS_PER_CLIENT {
                Notification::Error {
                    message: format!(
                        "Maximum {} subscriptions reached",
                        MAX_SUBSCRIPTIONS_PER_CLIENT
                    ),
                }
            } else if let Some(script_key) = hub.parse_address(&address) {
                session.subscribed_addresses.insert(script_key);
                Notification::Subscribed { address }
            } else {
                Notification::Error {
                    message: format!("Invalid address: {}", address),
                }
            }
        }

        ClientMessage::Unsubscribe { address } => {
            if let Some(script_key) = hub.parse_address(&address) {
                session.subscribed_addresses.remove(&script_key);
            }
            Notification::Unsubscribed { address }
        }

        ClientMessage::SubscribeBlocks => {
            session.subscribe_blocks = true;
            Notification::Subscribed {
                address: "blocks".to_string(),
            }
        }

        ClientMessage::UnsubscribeBlocks => {
            session.subscribe_blocks = false;
            Notification::Unsubscribed {
                address: "blocks".to_string(),
            }
        }

        ClientMessage::Ping { timestamp } => Notification::Pong { timestamp },
    };

    let json = serde_json::to_string(&response)?;
    sender.send(Message::Text(json)).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_serialization() {
        let notif = Notification::Block {
            hash: "abc123".to_string(),
            height: 12345,
            timestamp: 1638000000,
        };

        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("block"));
        assert!(json.contains("12345"));
    }

    #[test]
    fn test_client_message_deserialization() {
        let json = r#"{"type":"subscribe","address":"DJcNQYyJTwjWqKvkZ9xhvNsz3e4CYChSft"}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();

        match msg {
            ClientMessage::Subscribe { address } => {
                assert!(address.starts_with('D'));
            }
            _ => panic!("Expected Subscribe message"),
        }
    }

    #[test]
    fn test_ping_pong() {
        let json = r#"{"type":"ping","timestamp":1234567890}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();

        match msg {
            ClientMessage::Ping { timestamp } => {
                assert_eq!(timestamp, 1234567890);
            }
            _ => panic!("Expected Ping message"),
        }
    }

    #[test]
    fn test_notification_hub_creation() {
        let hub = NotificationHub::new();
        let _rx = hub.subscribe();
        let _block_rx = hub.subscribe_blocks();
    }
}
