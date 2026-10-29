// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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

/// How far ahead of the bytes received the buffer grows for a payload, so
/// a header announcing 2 MiB does not reserve 2 MiB before they are sent
/// (Divi Core `CNetMessage::readData`, Node.cpp:80-84)
const RECEIVE_AHEAD: usize = 256 * 1024;

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
    /// Bytes taken off the wire since the last `take_bytes_consumed`
    bytes_consumed: u64,
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
            bytes_consumed: 0,
        }
    }

    /// Bytes consumed from the stream (headers, payloads and skipped garbage) since
    /// the last call, then reset to zero
    pub fn take_bytes_consumed(&mut self) -> u64 {
        std::mem::take(&mut self.bytes_consumed)
    }
}

/// One message taken off the wire
#[derive(Debug)]
pub enum Decoded {
    /// A message that parsed
    Message(NetworkMessage),
    /// A message whose payload did not parse (Divi Core answers with a
    /// `reject` "error parsing message" and keeps the connection)
    Malformed {
        /// The message's command
        command: String,
        /// Why it did not parse
        error: String,
    },
}

impl Decoder for DiviCodec {
    type Item = Decoded;
    type Error = NetworkError;

    /// Divi Core's framing (`ProcessReceivedMessages`, `CNetMessage::readHeader`):
    /// a wrong magic or an oversized payload ends the connection, a bad
    /// checksum skips the message, and a payload that does not parse is
    /// reported as malformed
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match &self.state {
                DecodeState::Header => {
                    if src.len() < HEADER_SIZE {
                        src.reserve(HEADER_SIZE - src.len());
                        return Ok(None);
                    }

                    let header = MessageHeader::deserialize(&src[..HEADER_SIZE])?;
                    if !header.validate_magic(&self.magic) {
                        return Err(NetworkError::InvalidMagic);
                    }
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

                    src.advance(HEADER_SIZE);
                    self.bytes_consumed += HEADER_SIZE as u64;
                    self.state = DecodeState::Payload { header };
                }

                DecodeState::Payload { header } => {
                    let payload_size = header.payload_size as usize;
                    if src.len() < payload_size {
                        src.reserve((payload_size - src.len()).min(RECEIVE_AHEAD));
                        return Ok(None);
                    }

                    let payload = src.split_to(payload_size);
                    self.bytes_consumed += payload_size as u64;
                    let header = header.clone();
                    self.state = DecodeState::Header;

                    let command = header.command_string();
                    if !header.command_is_valid() {
                        warn!("{}: errors in the message header, message skipped", command);
                        continue;
                    }
                    if !header.validate_checksum(&payload) {
                        warn!("{}: checksum error, message skipped", command);
                        continue;
                    }

                    trace!("Decoded message: {} ({} bytes)", command, payload_size);
                    return Ok(Some(
                        match NetworkMessage::deserialize(&command, &payload) {
                            Ok(message) => Decoded::Message(message),
                            Err(e) => {
                                debug!("{}: payload does not parse: {}", command, e);
                                Decoded::Malformed {
                                    command,
                                    error: e.to_string(),
                                }
                            }
                        },
                    ));
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

    fn message(item: Option<Decoded>) -> NetworkMessage {
        match item {
            Some(Decoded::Message(m)) => m,
            other => panic!("expected a message, got {:?}", other),
        }
    }

    /// getpeerinfo bytesrecv comes from this count, so it must be the exact wire size
    #[test]
    fn test_codec_counts_exact_bytes_consumed() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();
        let ping = NetworkMessage::Ping(7).to_bytes(MAINNET_MAGIC).unwrap();
        let verack = NetworkMessage::Verack.to_bytes(MAINNET_MAGIC).unwrap();
        buf.extend_from_slice(&ping);
        buf.extend_from_slice(&verack);
        message(codec.decode(&mut buf).unwrap());
        assert_eq!(codec.take_bytes_consumed(), ping.len() as u64);
        message(codec.decode(&mut buf).unwrap());
        assert_eq!(codec.take_bytes_consumed(), verack.len() as u64);
        assert_eq!(codec.take_bytes_consumed(), 0);
    }

    #[test]
    fn test_codec_decode_ping() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();
        let bytes = NetworkMessage::Ping(12345).to_bytes(MAINNET_MAGIC).unwrap();

        // Partial bytes: nothing yet, bytes kept
        buf.extend_from_slice(&bytes[..10]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 10);

        buf.extend_from_slice(&bytes[10..]);
        assert!(matches!(
            message(codec.decode(&mut buf).unwrap()),
            NetworkMessage::Ping(12345)
        ));
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_codec_decode_multiple_messages() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&NetworkMessage::Ping(111).to_bytes(MAINNET_MAGIC).unwrap());
        buf.extend_from_slice(&NetworkMessage::Ping(222).to_bytes(MAINNET_MAGIC).unwrap());
        assert!(matches!(
            message(codec.decode(&mut buf).unwrap()),
            NetworkMessage::Ping(111)
        ));
        assert!(matches!(
            message(codec.decode(&mut buf).unwrap()),
            NetworkMessage::Ping(222)
        ));
        assert_eq!(buf.len(), 0);
    }

    /// Divi Core stops reading from a peer whose stream has a wrong magic
    #[test]
    fn wrong_magic_is_an_error() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        buf.extend_from_slice(&NetworkMessage::Ping(999).to_bytes(MAINNET_MAGIC).unwrap());
        assert!(matches!(
            codec.decode(&mut buf),
            Err(NetworkError::InvalidMagic)
        ));
    }

    /// A bad checksum skips that message only
    #[test]
    fn bad_checksum_skips_the_message() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();
        let mut bad = NetworkMessage::Ping(1).to_bytes(MAINNET_MAGIC).unwrap();
        bad[20] ^= 0xff;
        buf.extend_from_slice(&bad);
        buf.extend_from_slice(&NetworkMessage::Ping(2).to_bytes(MAINNET_MAGIC).unwrap());
        assert!(matches!(
            message(codec.decode(&mut buf).unwrap()),
            NetworkMessage::Ping(2)
        ));
    }

    /// A payload over 2 MiB ends the connection
    #[test]
    fn oversized_payload_is_an_error() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();
        let mut header = NetworkMessage::Ping(1).to_bytes(MAINNET_MAGIC).unwrap();
        header.truncate(HEADER_SIZE);
        header[16..20].copy_from_slice(&(MAX_MESSAGE_SIZE + 1).to_le_bytes());
        buf.extend_from_slice(&header);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(NetworkError::MessageTooLarge { .. })
        ));
    }

    /// A payload that does not parse is reported, and the next message still decodes
    #[test]
    fn malformed_payload_is_reported() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();
        let short_ping = crate::message::MessageHeader::new(MAINNET_MAGIC, "ping", &[1, 2]);
        buf.extend_from_slice(&short_ping.serialize());
        buf.extend_from_slice(&[1, 2]);
        buf.extend_from_slice(&NetworkMessage::Ping(3).to_bytes(MAINNET_MAGIC).unwrap());
        assert!(matches!(
            codec.decode(&mut buf).unwrap(),
            Some(Decoded::Malformed { ref command, .. }) if command == "ping"
        ));
        assert!(matches!(
            message(codec.decode(&mut buf).unwrap()),
            NetworkMessage::Ping(3)
        ));
    }

    #[test]
    fn test_codec_encode() {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::new();
        codec.encode(NetworkMessage::Ping(42), &mut buf).unwrap();
        let expected = NetworkMessage::Ping(42).to_bytes(MAINNET_MAGIC).unwrap();
        assert_eq!(&buf[..], &expected[..]);
    }
}
