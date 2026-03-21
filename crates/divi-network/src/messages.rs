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

//! Network message types and serialization
//!
//! This module defines all the P2P protocol messages.

use crate::constants::Magic;
use crate::error::NetworkError;
use crate::message::{InvItem, MessageHeader, NetAddr};
use crate::version::VersionMessage;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use divi_primitives::block::{Block, BlockHeader};
use divi_primitives::compact::CompactSize;
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::{deserialize, serialize, Decodable, Encodable};
use divi_primitives::transaction::Transaction;
use std::io::Cursor;

/// All network message types
#[derive(Debug, Clone)]
pub enum NetworkMessage {
    // Handshake
    /// Version message (initiates handshake)
    Version(VersionMessage),
    /// Version acknowledgement
    Verack,

    // Address management
    /// List of known addresses
    Addr(Vec<(u32, NetAddr)>), // (timestamp, addr)
    /// Request addresses
    GetAddr,

    // Inventory
    /// Inventory announcement
    Inv(Vec<InvItem>),
    /// Request specific items
    GetData(Vec<InvItem>),
    /// Items not found
    NotFound(Vec<InvItem>),

    // Blocks
    /// Request block headers starting from locator
    GetBlocks(GetBlocksMessage),
    /// Request headers starting from locator
    GetHeaders(GetHeadersMessage),
    /// Block headers response
    Headers(Vec<BlockHeader>),
    /// Full block data
    Block(Block),

    // Transactions
    /// Transaction data
    Tx(Transaction),

    // Ping/pong
    /// Ping request
    Ping(u64),
    /// Pong response
    Pong(u64),

    // Mempool
    /// Request mempool contents
    Mempool,

    // Reject
    /// Rejection message
    Reject(RejectMessage),

    // Alert (deprecated but still in protocol)
    /// Alert message
    Alert(Vec<u8>),

    // Filter
    /// Bloom filter load
    FilterLoad(Vec<u8>),
    /// Add to bloom filter
    FilterAdd(Vec<u8>),
    /// Clear bloom filter
    FilterClear,

    // Send headers preference
    /// Prefer headers announcements
    SendHeaders,

    // Spork messages (Divi-specific)
    /// Spork count announcement (sent after version)
    SporkCount(u32),
    /// Request all sporks
    GetSporks,
    /// Spork data
    Spork(SporkMessage),

    // Masternode sync messages (PIVX/Divi)
    /// Sync status count (masternode sync progress)
    SyncStatusCount { item_id: i32, count: i32 },
    /// Get masternode sync status
    GetSyncStatus,

    // Masternode messages (PIVX/Divi)
    /// Request masternode list (dseg)
    RequestMasternodeList(Vec<u8>),
    /// Masternode broadcast (mnb)
    MasternodeBroadcast(Vec<u8>),
    /// Masternode ping (mnp)
    MasternodePing(Vec<u8>),
    /// Masternode payment winner (mnw)
    MasternodeWinner(Vec<u8>),

    // Unknown/unhandled messages
    /// Unknown message type (command, payload)
    Unknown(String, Vec<u8>),
}

impl NetworkMessage {
    /// Get the command name for this message
    pub fn command(&self) -> &'static str {
        match self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::Addr(_) => "addr",
            NetworkMessage::GetAddr => "getaddr",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::Block(_) => "block",
            NetworkMessage::Tx(_) => "tx",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            NetworkMessage::Mempool => "mempool",
            NetworkMessage::Reject(_) => "reject",
            NetworkMessage::Alert(_) => "alert",
            NetworkMessage::FilterLoad(_) => "filterload",
            NetworkMessage::FilterAdd(_) => "filteradd",
            NetworkMessage::FilterClear => "filterclear",
            NetworkMessage::SporkCount(_) => "sporkcount",
            NetworkMessage::GetSporks => "getsporks",
            NetworkMessage::Spork(_) => "spork",
            NetworkMessage::SyncStatusCount { .. } => "ssc",
            NetworkMessage::GetSyncStatus => "govsync",
            NetworkMessage::SendHeaders => "sendheaders",
            NetworkMessage::RequestMasternodeList(_) => "dseg",
            NetworkMessage::MasternodeBroadcast(_) => "mnb",
            NetworkMessage::MasternodePing(_) => "mnp",
            NetworkMessage::MasternodeWinner(_) => "mnw",
            NetworkMessage::Unknown(cmd, _) => {
                // Note: This is a bit awkward since we return &'static str
                // but command is dynamic. This should only be used for logging.
                Box::leak(cmd.clone().into_boxed_str())
            }
        }
    }

    /// Serialize the message payload
    pub fn serialize_payload(&self) -> Result<Vec<u8>, NetworkError> {
        match self {
            NetworkMessage::Version(msg) => Ok(msg.serialize()),
            NetworkMessage::Verack => Ok(vec![]),
            NetworkMessage::GetAddr => Ok(vec![]),
            NetworkMessage::Mempool => Ok(vec![]),
            NetworkMessage::FilterClear => Ok(vec![]),
            NetworkMessage::SendHeaders => Ok(vec![]),

            NetworkMessage::Addr(addrs) => {
                let mut buf = Vec::new();
                let len = CompactSize::new(addrs.len() as u64);
                len.encode(&mut buf)
                    .map_err(|e| NetworkError::Serialization(e.to_string()))?;
                for (time, addr) in addrs {
                    buf.write_u32::<LittleEndian>(*time).unwrap();
                    buf.extend_from_slice(&addr.serialize());
                }
                Ok(buf)
            }

            NetworkMessage::Inv(items)
            | NetworkMessage::GetData(items)
            | NetworkMessage::NotFound(items) => {
                let mut buf = Vec::new();
                let len = CompactSize::new(items.len() as u64);
                len.encode(&mut buf)
                    .map_err(|e| NetworkError::Serialization(e.to_string()))?;
                for item in items {
                    buf.extend_from_slice(&item.serialize());
                }
                Ok(buf)
            }

            NetworkMessage::GetBlocks(msg) => Ok(msg.serialize()),
            NetworkMessage::GetHeaders(msg) => Ok(msg.serialize()),

            NetworkMessage::Headers(headers) => {
                let mut buf = Vec::new();
                let len = CompactSize::new(headers.len() as u64);
                len.encode(&mut buf)
                    .map_err(|e| NetworkError::Serialization(e.to_string()))?;
                for header in headers {
                    let header_bytes = serialize(header);
                    buf.extend_from_slice(&header_bytes);
                    // Headers message includes tx count (always 0 for headers-only)
                    buf.push(0);
                }
                Ok(buf)
            }

            NetworkMessage::Block(block) => Ok(serialize(block)),
            NetworkMessage::Tx(tx) => Ok(serialize(tx)),

            NetworkMessage::Ping(nonce) | NetworkMessage::Pong(nonce) => {
                let mut buf = Vec::with_capacity(8);
                buf.write_u64::<LittleEndian>(*nonce).unwrap();
                Ok(buf)
            }

            NetworkMessage::Reject(msg) => Ok(msg.serialize()),
            NetworkMessage::Alert(data)
            | NetworkMessage::FilterLoad(data)
            | NetworkMessage::FilterAdd(data)
            | NetworkMessage::RequestMasternodeList(data)
            | NetworkMessage::MasternodeBroadcast(data)
            | NetworkMessage::MasternodePing(data)
            | NetworkMessage::MasternodeWinner(data)
            | NetworkMessage::Unknown(_, data) => Ok(data.clone()),

            NetworkMessage::SporkCount(count) => {
                let mut buf = Vec::with_capacity(4);
                buf.write_u32::<LittleEndian>(*count).unwrap();
                Ok(buf)
            }
            NetworkMessage::GetSporks => Ok(vec![]),
            NetworkMessage::Spork(msg) => Ok(msg.serialize()),
            NetworkMessage::SyncStatusCount { item_id, count } => {
                let mut buf = Vec::with_capacity(8);
                buf.write_i32::<LittleEndian>(*item_id).unwrap();
                buf.write_i32::<LittleEndian>(*count).unwrap();
                Ok(buf)
            }
            NetworkMessage::GetSyncStatus => Ok(vec![]),
        }
    }

    /// Deserialize from command and payload
    pub fn deserialize(command: &str, payload: &[u8]) -> Result<Self, NetworkError> {
        match command {
            "version" => Ok(NetworkMessage::Version(VersionMessage::deserialize(
                payload,
            )?)),
            "verack" => Ok(NetworkMessage::Verack),
            "getaddr" => Ok(NetworkMessage::GetAddr),
            "mempool" => Ok(NetworkMessage::Mempool),
            "filterclear" => Ok(NetworkMessage::FilterClear),
            "sendheaders" => Ok(NetworkMessage::SendHeaders),

            "addr" => {
                let mut cursor = Cursor::new(payload);
                let count = CompactSize::decode(&mut cursor)
                    .map_err(|e| NetworkError::Deserialization(e.to_string()))?
                    .value() as usize;

                let mut addrs = Vec::with_capacity(count);
                for _ in 0..count {
                    let time = cursor.read_u32::<LittleEndian>()?;
                    let pos = cursor.position() as usize;
                    let addr = NetAddr::deserialize(&payload[pos..pos + 26])?;
                    cursor.set_position((pos + 26) as u64);
                    addrs.push((time, addr));
                }
                Ok(NetworkMessage::Addr(addrs))
            }

            "inv" | "getdata" | "notfound" => {
                let mut cursor = Cursor::new(payload);
                let count = CompactSize::decode(&mut cursor)
                    .map_err(|e| NetworkError::Deserialization(e.to_string()))?
                    .value() as usize;

                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let pos = cursor.position() as usize;
                    let item = InvItem::deserialize(&payload[pos..pos + 36])?;
                    cursor.set_position((pos + 36) as u64);
                    items.push(item);
                }

                // Check for unconsumed bytes
                let consumed = cursor.position() as usize;
                if consumed != payload.len() {
                    tracing::error!(
                        "{} deserialization consumed {} bytes but payload has {} bytes ({} unconsumed)",
                        command, consumed, payload.len(), payload.len() - consumed
                    );
                }

                Ok(match command {
                    "inv" => NetworkMessage::Inv(items),
                    "getdata" => NetworkMessage::GetData(items),
                    _ => NetworkMessage::NotFound(items),
                })
            }

            "getblocks" => Ok(NetworkMessage::GetBlocks(GetBlocksMessage::deserialize(
                payload,
            )?)),
            "getheaders" => Ok(NetworkMessage::GetHeaders(GetHeadersMessage::deserialize(
                payload,
            )?)),

            "headers" => {
                let mut cursor = Cursor::new(payload);
                let count = CompactSize::decode(&mut cursor)
                    .map_err(|e| NetworkError::Deserialization(e.to_string()))?
                    .value() as usize;

                let mut headers = Vec::with_capacity(count);
                for _ in 0..count {
                    let pos = cursor.position() as usize;
                    // Block headers are 80 bytes (v3) or 112 bytes (v4)
                    let header: BlockHeader = deserialize(&payload[pos..])
                        .map_err(|e| NetworkError::Deserialization(e.to_string()))?;
                    let header_size = header.encoded_size();
                    cursor.set_position((pos + header_size) as u64);

                    // Skip tx count (CompactSize, typically 0)
                    let _ = CompactSize::decode(&mut cursor)
                        .map_err(|e| NetworkError::Deserialization(e.to_string()))?;

                    headers.push(header);
                }

                // Check for unconsumed bytes
                let consumed = cursor.position() as usize;
                if consumed != payload.len() {
                    tracing::error!(
                        "headers deserialization consumed {} bytes but payload has {} bytes ({} unconsumed)",
                        consumed, payload.len(), payload.len() - consumed
                    );
                }

                Ok(NetworkMessage::Headers(headers))
            }

            "block" => {
                // Save larger blocks for analysis (blocks with multiple txs might show the issue)
                static BLOCK_SAVE_COUNT: std::sync::atomic::AtomicUsize =
                    std::sync::atomic::AtomicUsize::new(0);
                let save_count =
                    BLOCK_SAVE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if save_count < 5 && payload.len() > 1000 {
                    let filename = format!("/tmp/block_payload_{}.bin", save_count);
                    if let Ok(mut f) = std::fs::File::create(&filename) {
                        use std::io::Write;
                        let _ = f.write_all(payload);
                        tracing::info!("Saved block payload to {}", filename);
                    }
                }

                // Log payload info for debugging
                tracing::debug!(
                    "BLOCK_DEBUG: Received block payload, {} bytes, first 32: {:02x?}",
                    payload.len(),
                    &payload[..payload.len().min(32)]
                );

                // Use a cursor to track how many bytes are consumed
                let mut cursor = std::io::Cursor::new(payload);
                let block: Block = Block::decode(&mut cursor)
                    .map_err(|e| NetworkError::Deserialization(e.to_string()))?;

                let consumed = cursor.position() as usize;
                let total = payload.len();

                // Always log block parsing results for debugging
                let is_pos = block.is_proof_of_stake();

                // Verify: re-serialize and compare size
                let reserialized = divi_primitives::serialize::serialize(&block);
                let reser_size = reserialized.len();
                if reser_size != total {
                    tracing::error!(
                        "MISMATCH: payload={} bytes, reserialized={} bytes, diff={}, is_pos={}, tx_count={}, sig_len={}",
                        total, reser_size, reser_size as i64 - total as i64, is_pos, block.transactions.len(), block.block_sig.len()
                    );
                    // This means we're NOT parsing the same data the C++ serialized
                }

                tracing::debug!(
                    "BLOCK_DEBUG: Parsed block: consumed={}, total={}, reserialized={}, is_pos={}, tx_count={}, sig_len={}, header_version={}",
                    consumed, total, reser_size, is_pos, block.transactions.len(), block.block_sig.len(), block.header.version
                );

                if consumed != total {
                    let is_pos = block.is_proof_of_stake();
                    let tx_count = block.transactions.len();
                    let tx1_info = if tx_count > 1 {
                        let tx1 = &block.transactions[1];
                        let vin_ok = !tx1.vin.is_empty();
                        let prevout_ok = vin_ok && !tx1.vin[0].prevout.is_null();
                        let vout_count = tx1.vout.len();
                        let vout0_empty = vout_count >= 2 && tx1.vout[0].is_empty();
                        let vout0_value = if !tx1.vout.is_empty() {
                            tx1.vout[0].value.0
                        } else {
                            -1
                        };
                        let vout0_script_len = if !tx1.vout.is_empty() {
                            tx1.vout[0].script_pubkey.len()
                        } else {
                            0
                        };
                        format!(
                            "tx1: vin_ok={}, prevout_ok={}, vout_count={}, vout0_empty={}, vout0_value={}, vout0_script_len={}",
                            vin_ok, prevout_ok, vout_count, vout0_empty, vout0_value, vout0_script_len
                        )
                    } else {
                        format!("tx_count={}", tx_count)
                    };
                    let unconsumed_preview: Vec<u8> =
                        payload[consumed..].iter().take(32).cloned().collect();
                    tracing::error!(
                        "Block deserialization: consumed={}, total={}, unconsumed={}, is_pos={}, {}, unconsumed_bytes={:02x?}",
                        consumed, total, total - consumed, is_pos, tx1_info, unconsumed_preview
                    );
                }

                Ok(NetworkMessage::Block(block))
            }

            "tx" => {
                // Use a cursor to track how many bytes are consumed
                let mut cursor = std::io::Cursor::new(payload);
                let tx: Transaction = Transaction::decode(&mut cursor)
                    .map_err(|e| NetworkError::Deserialization(e.to_string()))?;

                let consumed = cursor.position() as usize;
                let total = payload.len();
                if consumed != total {
                    tracing::error!(
                        "TX deserialization consumed {} bytes but payload has {} bytes ({} unconsumed)",
                        consumed, total, total - consumed
                    );
                    tracing::error!(
                        "Unconsumed bytes: {:02x?}",
                        &payload[consumed..total.min(consumed + 64)]
                    );
                }

                Ok(NetworkMessage::Tx(tx))
            }

            "ping" => {
                let mut cursor = Cursor::new(payload);
                let nonce = cursor.read_u64::<LittleEndian>()?;
                Ok(NetworkMessage::Ping(nonce))
            }

            "pong" => {
                let mut cursor = Cursor::new(payload);
                let nonce = cursor.read_u64::<LittleEndian>()?;
                Ok(NetworkMessage::Pong(nonce))
            }

            "reject" => Ok(NetworkMessage::Reject(RejectMessage::deserialize(payload)?)),
            "alert" => Ok(NetworkMessage::Alert(payload.to_vec())),
            "filterload" => Ok(NetworkMessage::FilterLoad(payload.to_vec())),
            "filteradd" => Ok(NetworkMessage::FilterAdd(payload.to_vec())),

            // Spork messages
            "sporkcount" => {
                tracing::debug!(
                    "sporkcount payload ({} bytes): {:02x?}",
                    payload.len(),
                    payload
                );
                let mut cursor = Cursor::new(payload);
                let count = cursor.read_u32::<LittleEndian>()?;
                tracing::debug!("Parsed sporkcount: {}", count);

                // Check for unconsumed bytes
                let consumed = cursor.position() as usize;
                if consumed != payload.len() {
                    tracing::error!(
                        "sporkcount deserialization consumed {} bytes but payload has {} bytes ({} unconsumed)",
                        consumed, payload.len(), payload.len() - consumed
                    );
                    tracing::error!(
                        "Unconsumed sporkcount bytes: {:02x?}",
                        &payload[consumed..payload.len().min(consumed + 64)]
                    );
                }

                Ok(NetworkMessage::SporkCount(count))
            }
            "getsporks" => Ok(NetworkMessage::GetSporks),
            "spork" => Ok(NetworkMessage::Spork(SporkMessage::deserialize(payload)?)),

            // Masternode sync messages
            "ssc" => {
                tracing::info!("ssc payload ({} bytes): {:02x?}", payload.len(), payload);
                let mut cursor = Cursor::new(payload);
                let item_id = cursor.read_i32::<LittleEndian>()?;
                let count = cursor.read_i32::<LittleEndian>()?;
                tracing::info!("Parsed ssc: item_id={}, count={}", item_id, count);
                Ok(NetworkMessage::SyncStatusCount { item_id, count })
            }
            "govsync" => Ok(NetworkMessage::GetSyncStatus),

            // Masternode messages
            "dseg" => Ok(NetworkMessage::RequestMasternodeList(payload.to_vec())),
            "mnb" => Ok(NetworkMessage::MasternodeBroadcast(payload.to_vec())),
            "mnp" => Ok(NetworkMessage::MasternodePing(payload.to_vec())),
            "mnw" => Ok(NetworkMessage::MasternodeWinner(payload.to_vec())),

            // Unknown commands are captured for potential future handling
            _ => Ok(NetworkMessage::Unknown(
                command.to_string(),
                payload.to_vec(),
            )),
        }
    }

    /// Create a full message with header
    pub fn to_bytes(&self, magic: Magic) -> Result<Vec<u8>, NetworkError> {
        let payload = self.serialize_payload()?;
        let header = MessageHeader::new(magic, self.command(), &payload);

        let mut buf = Vec::with_capacity(24 + payload.len());
        buf.extend_from_slice(&header.serialize());
        buf.extend_from_slice(&payload);
        Ok(buf)
    }
}

/// GetBlocks/GetHeaders message
#[derive(Debug, Clone)]
pub struct GetBlocksMessage {
    /// Protocol version
    pub version: i32,
    /// Block locator hashes (from tip to genesis)
    pub locator_hashes: Vec<Hash256>,
    /// Stop hash (zero for unlimited)
    pub stop_hash: Hash256,
}

impl GetBlocksMessage {
    /// Create a new GetBlocks message
    pub fn new(locator_hashes: Vec<Hash256>, stop_hash: Hash256) -> Self {
        GetBlocksMessage {
            version: crate::constants::PROTOCOL_VERSION,
            locator_hashes,
            stop_hash,
        }
    }

    /// Serialize the message
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_i32::<LittleEndian>(self.version).unwrap();

        let len = CompactSize::new(self.locator_hashes.len() as u64);
        len.encode(&mut buf).unwrap();

        for hash in &self.locator_hashes {
            buf.extend_from_slice(hash.as_bytes());
        }

        buf.extend_from_slice(self.stop_hash.as_bytes());

        tracing::debug!(
            "GetBlocks/GetHeaders serialized: version={}, {} locators, stop={}, total {} bytes",
            self.version,
            self.locator_hashes.len(),
            self.stop_hash,
            buf.len()
        );
        if !self.locator_hashes.is_empty() {
            tracing::debug!("First locator raw bytes: {:02x?}", &buf[5..37]);
        }

        buf
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        let mut cursor = Cursor::new(data);
        let version = cursor.read_i32::<LittleEndian>()?;

        let count = CompactSize::decode(&mut cursor)
            .map_err(|e| NetworkError::Deserialization(e.to_string()))?
            .value() as usize;

        let mut locator_hashes = Vec::with_capacity(count);
        for _ in 0..count {
            let pos = cursor.position() as usize;
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&data[pos..pos + 32]);
            locator_hashes.push(Hash256::from_bytes(hash_bytes));
            cursor.set_position((pos + 32) as u64);
        }

        let pos = cursor.position() as usize;
        let mut stop_bytes = [0u8; 32];
        stop_bytes.copy_from_slice(&data[pos..pos + 32]);
        let stop_hash = Hash256::from_bytes(stop_bytes);

        Ok(GetBlocksMessage {
            version,
            locator_hashes,
            stop_hash,
        })
    }
}

/// GetHeaders message (same format as GetBlocks)
pub type GetHeadersMessage = GetBlocksMessage;

/// Reject message
#[derive(Debug, Clone)]
pub struct RejectMessage {
    /// Message being rejected
    pub message: String,
    /// Rejection code
    pub code: u8,
    /// Reason for rejection
    pub reason: String,
    /// Optional extra data (e.g., block/tx hash)
    pub data: Vec<u8>,
}

impl RejectMessage {
    /// Serialize the message
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let msg_bytes = self.message.as_bytes();
        let len = CompactSize::new(msg_bytes.len() as u64);
        len.encode(&mut buf).unwrap();
        buf.extend_from_slice(msg_bytes);

        buf.push(self.code);

        let reason_bytes = self.reason.as_bytes();
        let len = CompactSize::new(reason_bytes.len() as u64);
        len.encode(&mut buf).unwrap();
        buf.extend_from_slice(reason_bytes);

        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        let mut cursor = Cursor::new(data);

        let msg_len = CompactSize::decode(&mut cursor)
            .map_err(|e| NetworkError::Deserialization(e.to_string()))?
            .value() as usize;
        let pos = cursor.position() as usize;
        let message = String::from_utf8_lossy(&data[pos..pos + msg_len]).to_string();
        cursor.set_position((pos + msg_len) as u64);

        let code = cursor.read_u8()?;

        let reason_len = CompactSize::decode(&mut cursor)
            .map_err(|e| NetworkError::Deserialization(e.to_string()))?
            .value() as usize;
        let pos = cursor.position() as usize;
        let reason = String::from_utf8_lossy(&data[pos..pos + reason_len]).to_string();
        cursor.set_position((pos + reason_len) as u64);

        let pos = cursor.position() as usize;
        let extra_data = data[pos..].to_vec();

        Ok(RejectMessage {
            message,
            code,
            reason,
            data: extra_data,
        })
    }
}

/// Spork message - network parameter configuration
#[derive(Debug, Clone)]
pub struct SporkMessage {
    /// Spork identifier
    pub spork_id: i32,
    /// Spork value (string-encoded for flexibility)
    pub value: String,
    /// Time the spork was signed
    pub time_signed: i64,
    /// Cryptographic signature
    pub signature: Vec<u8>,
}

impl SporkMessage {
    /// Create a new spork message
    pub fn new(spork_id: i32, value: String, time_signed: i64) -> Self {
        SporkMessage {
            spork_id,
            value,
            time_signed,
            signature: vec![],
        }
    }

    /// Get the hash of this spork (for inventory tracking)
    pub fn hash(&self) -> Hash256 {
        use divi_crypto::double_sha256;
        let mut data = Vec::new();
        data.write_i32::<LittleEndian>(self.spork_id).unwrap();
        let value_bytes = self.value.as_bytes();
        let len = CompactSize::new(value_bytes.len() as u64);
        len.encode(&mut data).unwrap();
        data.extend_from_slice(value_bytes);
        data.write_i64::<LittleEndian>(self.time_signed).unwrap();
        Hash256::from_bytes(double_sha256(&data))
    }

    /// Serialize the message
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_i32::<LittleEndian>(self.spork_id).unwrap();

        let value_bytes = self.value.as_bytes();
        let len = CompactSize::new(value_bytes.len() as u64);
        len.encode(&mut buf).unwrap();
        buf.extend_from_slice(value_bytes);

        buf.write_i64::<LittleEndian>(self.time_signed).unwrap();

        let sig_len = CompactSize::new(self.signature.len() as u64);
        sig_len.encode(&mut buf).unwrap();
        buf.extend_from_slice(&self.signature);

        buf
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        let mut cursor = Cursor::new(data);
        let spork_id = cursor.read_i32::<LittleEndian>()?;

        let value_len = CompactSize::decode(&mut cursor)
            .map_err(|e| NetworkError::Deserialization(e.to_string()))?
            .value() as usize;
        let pos = cursor.position() as usize;
        let value = String::from_utf8_lossy(&data[pos..pos + value_len]).to_string();
        cursor.set_position((pos + value_len) as u64);

        let time_signed = cursor.read_i64::<LittleEndian>()?;

        let sig_len = CompactSize::decode(&mut cursor)
            .map_err(|e| NetworkError::Deserialization(e.to_string()))?
            .value() as usize;
        let pos = cursor.position() as usize;
        let signature = data[pos..pos + sig_len].to_vec();

        Ok(SporkMessage {
            spork_id,
            value,
            time_signed,
            signature,
        })
    }
}

/// Spork IDs (from Divi protocol)
pub mod spork_ids {
    pub const SPORK_2_SWIFTTX_ENABLED: i32 = 10001;
    pub const SPORK_3_SWIFTTX_BLOCK_FILTERING: i32 = 10002;
    pub const SPORK_5_INSTANTSEND_MAX_VALUE: i32 = 10004;
    pub const SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT: i32 = 10007;
    pub const SPORK_9_SUPERBLOCKS_ENABLED: i32 = 10008;
    pub const SPORK_10_MASTERNODE_PAY_UPDATED_NODES: i32 = 10009;
    pub const SPORK_12_RECONSIDER_BLOCKS: i32 = 10011;
    pub const SPORK_13_BLOCK_PAYMENTS: i32 = 10012;
    pub const SPORK_14_TX_FEE: i32 = 10013;
    pub const SPORK_15_BLOCK_VALUE: i32 = 10014;
    pub const SPORK_16_LOTTERY_TICKET_MIN_VALUE: i32 = 10015;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAINNET_MAGIC;

    #[test]
    fn test_verack_roundtrip() {
        let msg = NetworkMessage::Verack;
        let bytes = msg.to_bytes(MAINNET_MAGIC).unwrap();

        let header = MessageHeader::deserialize(&bytes[..24]).unwrap();
        assert_eq!(header.command_string(), "verack");
        assert_eq!(header.payload_size, 0);
    }

    #[test]
    fn test_ping_roundtrip() {
        let msg = NetworkMessage::Ping(0xdeadbeef);
        let bytes = msg.to_bytes(MAINNET_MAGIC).unwrap();

        let header = MessageHeader::deserialize(&bytes[..24]).unwrap();
        assert_eq!(header.command_string(), "ping");

        let deserialized = NetworkMessage::deserialize("ping", &bytes[24..]).unwrap();
        if let NetworkMessage::Ping(nonce) = deserialized {
            assert_eq!(nonce, 0xdeadbeef);
        } else {
            panic!("Expected Ping message");
        }
    }

    #[test]
    fn test_getblocks_roundtrip() {
        let locator = vec![
            Hash256::from_bytes([1u8; 32]),
            Hash256::from_bytes([2u8; 32]),
        ];
        let stop = Hash256::zero();

        let msg = NetworkMessage::GetBlocks(GetBlocksMessage::new(locator.clone(), stop));
        let payload = msg.serialize_payload().unwrap();

        let deserialized = NetworkMessage::deserialize("getblocks", &payload).unwrap();
        if let NetworkMessage::GetBlocks(inner) = deserialized {
            assert_eq!(inner.locator_hashes.len(), 2);
            assert_eq!(inner.locator_hashes[0], locator[0]);
            assert!(inner.stop_hash.is_zero());
        } else {
            panic!("Expected GetBlocks message");
        }
    }
}
