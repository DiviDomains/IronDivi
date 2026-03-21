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

//! Divi network message codec for cancellation-safe reading
//!
//! This codec implements tokio-util's `Decoder` trait to provide cancellation-safe
//! message framing. Unlike raw `read_exact`, the codec maintains its own buffer
//! so partial reads are preserved across cancellations.

use crate::constants::{Magic, MAX_MESSAGE_SIZE};
use crate::error::NetworkError;
use crate::message::{MessageHeader, HEADER_SIZE};
use crate::NetworkMessage;

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, trace, warn};

/// Codec for Divi P2P protocol messages
///
/// Message format:
/// - Header (24 bytes): magic(4) + command(12) + size(4) + checksum(4)
/// - Payload (variable): message-specific data
pub struct DiviCodec {
    /// Network magic bytes for validation
    magic: Magic,
    /// Current decode state
    state: DecodeState,
}

/// State machine for message decoding
#[derive(Debug, Clone)]
enum DecodeState {
    /// Waiting for complete header (24 bytes)
    Header,
    /// Header received, waiting for payload
    Payload { header: MessageHeader },
}

impl DiviCodec {
    /// Create a new codec for the given network magic
    pub fn new(magic: Magic) -> Self {
        Self {
            magic,
            state: DecodeState::Header,
        }
    }
}

impl Decoder for DiviCodec {
    type Item = NetworkMessage;
    type Error = NetworkError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match &self.state {
                DecodeState::Header => {
                    // Need at least HEADER_SIZE bytes
                    if src.len() < HEADER_SIZE {
                        // Reserve space for header if needed
                        src.reserve(HEADER_SIZE - src.len());
                        return Ok(None);
                    }

                    // Parse the header (don't consume yet - we need to validate magic first)
                    let header = MessageHeader::deserialize(&src[..HEADER_SIZE])?;

                    // Validate magic bytes
                    if !header.validate_magic(&self.magic) {
                        // Invalid magic - try to resync by scanning for valid magic
                        warn!(
                            "Invalid magic bytes: got {:02x?}, expected {:02x?}. Scanning for resync...",
                            header.magic, self.magic
                        );

                        // Look for magic bytes in the buffer
                        let magic_bytes: &[u8] = &self.magic;
                        if let Some(pos) = src.windows(4).position(|w| w == magic_bytes) {
                            if pos > 0 {
                                debug!(
                                    "Found magic at offset {}, discarding {} garbage bytes",
                                    pos, pos
                                );
                                // Discard bytes before magic
                                src.advance(pos);
                                // Continue to try parsing header again
                                continue;
                            }
                        } else {
                            // No magic found in buffer - discard all but last 3 bytes
                            // (magic could be split across buffer boundary)
                            if src.len() > 3 {
                                let discard = src.len() - 3;
                                debug!(
                                    "No magic found, discarding {} bytes, keeping last 3",
                                    discard
                                );
                                src.advance(discard);
                            }
                            return Ok(None);
                        }
                    }

                    // Validate payload size
                    if header.payload_size > MAX_MESSAGE_SIZE {
                        return Err(NetworkError::MessageTooLarge {
                            size: header.payload_size,
                            max: MAX_MESSAGE_SIZE,
                        });
                    }

                    trace!(
                        "Decoded header: cmd={}, payload_size={}",
                        header.command_string(),
                        header.payload_size
                    );

                    // Consume header bytes
                    src.advance(HEADER_SIZE);

                    // Transition to payload state
                    self.state = DecodeState::Payload { header };
                }

                DecodeState::Payload { header } => {
                    let payload_size = header.payload_size as usize;

                    // Need complete payload
                    if src.len() < payload_size {
                        // Reserve space for remaining payload
                        src.reserve(payload_size - src.len());
                        return Ok(None);
                    }

                    // Extract payload
                    let payload = &src[..payload_size];

                    // Validate checksum
                    if !header.validate_checksum(payload) {
                        // Reset state and return error
                        self.state = DecodeState::Header;
                        return Err(NetworkError::InvalidChecksum);
                    }

                    // Deserialize message
                    let command = header.command_string();

                    // Log block messages at trace level
                    if command == "block" {
                        tracing::trace!(
                            "Codec: Decoding block message ({} bytes payload)",
                            payload_size
                        );
                    }

                    let message = match NetworkMessage::deserialize(&command, payload) {
                        Ok(m) => m,
                        Err(e) => {
                            if command == "block" {
                                tracing::error!(
                                    "Codec: Failed to deserialize block message: {}",
                                    e
                                );
                            }
                            return Err(e);
                        }
                    };

                    trace!("Decoded message: {} ({} bytes)", command, payload_size);

                    // Consume payload bytes
                    src.advance(payload_size);

                    // Reset state for next message
                    self.state = DecodeState::Header;

                    return Ok(Some(message));
                }
            }
        }
    }
}

impl Encoder<NetworkMessage> for DiviCodec {
    type Error = NetworkError;

    fn encode(&mut self, item: NetworkMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = item.to_bytes(self.magic)?;
        dst.extend_from_slice(&bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAINNET_MAGIC;

    #[test]
    fn test_codec_decode_ping() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();

        // Create a ping message
        let ping = NetworkMessage::Ping(12345);
        let bytes = ping.to_bytes(MAINNET_MAGIC).unwrap();

        // Feed partial bytes - should return None
        buf.extend_from_slice(&bytes[..10]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 10); // Bytes preserved

        // Feed rest of message
        buf.extend_from_slice(&bytes[10..]);
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_some());

        if let Some(NetworkMessage::Ping(nonce)) = result {
            assert_eq!(nonce, 12345);
        } else {
            panic!("Expected Ping message");
        }

        assert_eq!(buf.len(), 0); // All bytes consumed
    }

    #[test]
    fn test_codec_decode_multiple_messages() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();

        // Create two messages
        let ping1 = NetworkMessage::Ping(111);
        let ping2 = NetworkMessage::Ping(222);

        buf.extend_from_slice(&ping1.to_bytes(MAINNET_MAGIC).unwrap());
        buf.extend_from_slice(&ping2.to_bytes(MAINNET_MAGIC).unwrap());

        // Decode first
        let msg1 = codec.decode(&mut buf).unwrap().unwrap();
        if let NetworkMessage::Ping(n) = msg1 {
            assert_eq!(n, 111);
        } else {
            panic!("Expected Ping");
        }

        // Decode second
        let msg2 = codec.decode(&mut buf).unwrap().unwrap();
        if let NetworkMessage::Ping(n) = msg2 {
            assert_eq!(n, 222);
        } else {
            panic!("Expected Ping");
        }

        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_codec_resync_on_garbage() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();

        // Add some garbage followed by a valid message
        buf.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]); // 4 garbage bytes
        let ping = NetworkMessage::Ping(999);
        buf.extend_from_slice(&ping.to_bytes(MAINNET_MAGIC).unwrap());

        // Should skip garbage and find the message
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_some());

        if let Some(NetworkMessage::Ping(nonce)) = result {
            assert_eq!(nonce, 999);
        } else {
            panic!("Expected Ping message");
        }
    }

    #[test]
    fn test_codec_encode() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();

        let ping = NetworkMessage::Ping(42);
        codec.encode(ping, &mut buf).unwrap();

        // Should produce same bytes as to_bytes
        let expected = NetworkMessage::Ping(42).to_bytes(MAINNET_MAGIC).unwrap();
        assert_eq!(&buf[..], &expected[..]);
    }
}
