// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Tier B Capability-Negotiated v2 Encrypted P2P Transport (`BIP-324` +
//! `ChaCha20-Poly1305` / `XChaCha20-Poly1305` + Hybrid Post-Quantum KEM hook).
//!
//! See `docs/plans/post-quantum-lockstep.md` §3 (Tier B) for the architectural
//! specification:
//!
//! - **Ephemeral `X25519` + Hybrid PQ KEM Hook**: Peers exchange 32-byte ephemeral
//!   `X25519` public keys (RFC 7748) and optionally mix a post-quantum KEM shared
//!   secret (e.g. `ML-KEM-768`) into the `HKDF-SHA256` session key schedule.
//! - **Authenticated AEAD Framing**: Packet lengths (3-byte 24-bit little-endian)
//!   are encrypted with forward-secret `FSChaCha20`, and packet bodies
//!   (`header_byte || payload`) are authenticated and encrypted with
//!   `ChaCha20-Poly1305` (RFC 8439) or `XChaCha20-Poly1305` with 16-byte
//!   `Poly1305` tags.
//! - **Forward-Secret Rekeying**: Both length and packet ciphers automatically
//!   ratchet keys every [`REKEY_INTERVAL`] (`224`) packets.
//! - **Transparent `v1` Plaintext Fallback**: Inbound and outbound handshakes
//!   inspect the peer's opening bytes for known `v1` network magic prefixes
//!   (`0xf9beb4d9` Bitcoin legacy magic, Divi `MAINNET_MAGIC` `0xdfa08d8f`,
//!   `TESTNET_MAGIC`, `REGTEST_MAGIC`, PrivateDivi magics, or caller-supplied
//!   `expected_magic`). When a peer speaks `v1`, the detector returns the
//!   buffered prefix untouched so the connection falls back to `DiviCodec` without
//!   dropping a single byte.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::constants::{
    Magic, MAINNET_MAGIC, MAX_MESSAGE_SIZE, PRIVATEDIVI_MAINNET_MAGIC, PRIVATEDIVI_REGTEST_MAGIC,
    PRIVATEDIVI_TESTNET_MAGIC, REGTEST_MAGIC, TESTNET_MAGIC,
};
use crate::error::NetworkError;
use crate::NetworkMessage;

type HmacSha256 = Hmac<Sha256>;

/// BIP-324 service flag (`1 << 11`) advertising v2 encrypted P2P transport support.
pub const NODE_P2P_V2: u64 = crate::constants::services::NODE_P2P_V2;

/// Number ofpackets between automatic forward-secret key ratchets (BIP-324).
pub const REKEY_INTERVAL: u64 = 224;

/// Encrypted packet length field size in bytes (24-bit little-endian).
pub const LENGTH_LEN: usize = 3;

/// Encrypted packet header byte length (`0x80` bit = decoy/ignore flag).
pub const HEADER_LEN: usize = 1;

/// Poly1305 authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Header flag indicating an ignored decoy packet.
pub const HEADER_IGNORE_BIT: u8 = 0x80;

/// Ephemeral X25519 public/secret key size in bytes.
pub const X25519_KEY_LEN: usize = 32;

/// Garbage terminator length in bytes (BIP-324).
pub const GARBAGE_TERMINATOR_LEN: usize = 16;

/// Session ID length in bytes.
pub const SESSION_ID_LEN: usize = 32;

/// Bitcoin legacy mainnet v1 magic (`0xf9beb4d9`), recognized alongside Divi magics
/// for automatic v1 fallback detection.
pub const BITCOIN_MAINNET_V1_MAGIC: Magic = [0xf9, 0xbe, 0xb4, 0xd9];

/// Maximum v2 packet payload length accepted on the wire.
pub const MAX_V2_PACKET_LEN: usize = (MAX_MESSAGE_SIZE as usize) + 64;

/// Handshake role on a P2P connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Outbound connection initiator.
    Initiator,
    /// Inbound connection responder.
    Responder,
}

/// Authenticated encryption mode for v2 packet bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AeadMode {
    /// Standard BIP-324 `ChaCha20-Poly1305` (RFC 8439, 96-bit packet counter nonce).
    #[default]
    ChaCha20Poly1305,
    /// Extended-nonce `XChaCha20-Poly1305` (derives a subkey via `HChaCha20` from
    /// a 192-bit epoch/counter nonce before `ChaCha20-Poly1305`).
    XChaCha20Poly1305,
}

/// Hook for mixing a post-quantum KEM shared secret (such as `ML-KEM-768`) into
/// the v2 `HKDF-SHA256` session key derivation alongside ephemeral `X25519`.
pub trait PqKemHook: Send + Sync {
    /// Name of the hybrid KEM scheme (used for domain separation).
    fn scheme_name(&self) -> &'static str;

    /// Initiator: generates an ephemeral PQ encapsulation key or handshake payload.
    fn initiator_begin(&self) -> Result<(Vec<u8>, Box<dyn PqKemInitiatorState>), NetworkError>;

    /// Responder: encapsulates a shared secret against `initiator_payload`,
    /// returning `(responder_ciphertext, pq_shared_secret)`.
    fn responder_encapsulate(
        &self,
        initiator_payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), NetworkError>;
}

/// Initiator state for completing a hybrid PQ KEM exchange.
pub trait PqKemInitiatorState: Send + Sync {
    /// Decapsulates `responder_payload` into the shared secret bytes.
    fn decapsulate(self: Box<Self>, responder_payload: &[u8]) -> Result<Vec<u8>, NetworkError>;
}

/// Deterministic / callback-driven hybrid PQ KEM hook for testing and custom KEM wiring.
pub struct DeterministicPqKem {
    scheme: &'static str,
    encap_len: usize,
    ct_len: usize,
}

impl DeterministicPqKem {
    /// Creates a deterministic hybrid PQ KEM hook with the given wire payload sizes.
    pub const fn new(scheme: &'static str, encap_len: usize, ct_len: usize) -> Self {
        Self {
            scheme,
            encap_len,
            ct_len,
        }
    }
}

struct DeterministicInitiatorState {
    secret_seed: [u8; 32],
    expected_ek_hash: [u8; 32],
    ct_len: usize,
}

impl PqKemHook for DeterministicPqKem {
    fn scheme_name(&self) -> &'static str {
        self.scheme
    }

    fn initiator_begin(&self) -> Result<(Vec<u8>, Box<dyn PqKemInitiatorState>), NetworkError> {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let payload = hkdf_expand_vec(&seed, b"divi-v2-pq-ek", self.encap_len);
        let ek_hash = hkdf_extract(b"divi-v2-pq-ek-hash", &payload);
        Ok((
            payload,
            Box::new(DeterministicInitiatorState {
                secret_seed: seed,
                expected_ek_hash: ek_hash,
                ct_len: self.ct_len,
            }),
        ))
    }

    fn responder_encapsulate(
        &self,
        initiator_payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), NetworkError> {
        if initiator_payload.len() != self.encap_len {
            return Err(NetworkError::HandshakeFailed(
                "invalid PQ KEM encapsulation key length".into(),
            ));
        }
        let ek_hash = hkdf_extract(b"divi-v2-pq-ek-hash", initiator_payload);
        let ct = hkdf_expand_vec(&ek_hash, b"divi-v2-pq-ct", self.ct_len);
        let ss = hkdf_expand_vec(&ek_hash, b"divi-v2-pq-ss", 32);
        Ok((ct, ss))
    }
}

impl PqKemInitiatorState for DeterministicInitiatorState {
    fn decapsulate(self: Box<Self>, responder_payload: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if responder_payload.len() != self.ct_len {
            return Err(NetworkError::HandshakeFailed(
                "invalid PQ KEM ciphertext length".into(),
            ));
        }
        let _ = self.secret_seed;
        let expected_ct = hkdf_expand_vec(&self.expected_ek_hash, b"divi-v2-pq-ct", self.ct_len);
        if !constant_time_eq(responder_payload, &expected_ct) {
            return Err(NetworkError::HandshakeFailed(
                "PQ KEM ciphertext verification failed".into(),
            ));
        }
        Ok(hkdf_expand_vec(
            &self.expected_ek_hash,
            b"divi-v2-pq-ss",
            32,
        ))
    }
}

/// Returns `true` if `prefix` (at least 4 bytes) starts with `expected_magic`,
/// Bitcoin legacy mainnet magic (`0xf9beb4d9`), or any Divi / PrivateDivi v1 magic.
pub fn is_v1_magic_prefix(prefix: &[u8], expected_magic: Magic) -> bool {
    if prefix.len() < 4 {
        return false;
    }
    let m: [u8; 4] = [prefix[0], prefix[1], prefix[2], prefix[3]];
    m == expected_magic
        || m == BITCOIN_MAINNET_V1_MAGIC
        || m == MAINNET_MAGIC
        || m == TESTNET_MAGIC
        || m == REGTEST_MAGIC
        || m == PRIVATEDIVI_MAINNET_MAGIC
        || m == PRIVATEDIVI_TESTNET_MAGIC
        || m == PRIVATEDIVI_REGTEST_MAGIC
}

/// Inspects an incoming byte prefix for a v1 P2P message header.
///
/// Detection succeeds if the first 4 bytes match a known v1 network magic
/// (and, when 16+ bytes are available, if the command field is valid ASCII
/// padded with NULs such as `"version\0\0\0\0\0"`).
pub fn detect_v1_prefix(prefix: &[u8], expected_magic: Magic) -> bool {
    if !is_v1_magic_prefix(prefix, expected_magic) {
        return false;
    }
    if prefix.len() >= 16 {
        let cmd = &prefix[4..16];
        let nul_pos = cmd.iter().position(|&b| b == 0).unwrap_or(12);
        if nul_pos == 0 {
            return false;
        }
        let ascii_ok = cmd[..nul_pos]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        let pad_ok = cmd[nul_pos..].iter().all(|&b| b == 0);
        return ascii_ok && pad_ok;
    }
    true
}

/// Ephemeral X25519 keypair for a v2 transport handshake.
#[derive(Clone)]
pub struct EphemeralX25519KeyPair {
    secret: [u8; X25519_KEY_LEN],
    public: [u8; X25519_KEY_LEN],
}

impl EphemeralX25519KeyPair {
    /// Generates a fresh random ephemeral X25519 keypair.
    pub fn generate() -> Self {
        let mut seed = [0u8; X25519_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::from_secret_bytes(seed)
    }

    /// Constructs a keypair from a 32-byte secret scalar.
    pub fn from_secret_bytes(mut secret: [u8; X25519_KEY_LEN]) -> Self {
        clamp_scalar(&mut secret);
        let public = x25519_basepoint(&secret);
        Self { secret, public }
    }

    /// Returns the 32-byte public key.
    pub fn public_key(&self) -> &[u8; X25519_KEY_LEN] {
        &self.public
    }

    /// Computes the 32-byte X25519 shared secret with `peer_public`.
    /// Rejects low-order / all-zero shared secrets.
    pub fn diffie_hellman(
        &self,
        peer_public: &[u8; X25519_KEY_LEN],
    ) -> Result<[u8; X25519_KEY_LEN], NetworkError> {
        let shared = x25519(&self.secret, peer_public);
        let mut acc = 0u8;
        for &b in &shared {
            acc |= b;
        }
        if acc == 0 {
            return Err(NetworkError::HandshakeFailed(
                "invalid low-order X25519 peer public key".into(),
            ));
        }
        Ok(shared)
    }
}

impl Drop for EphemeralX25519KeyPair {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

/// Session keys derived from the BIP-324 + optional hybrid PQ KEM key schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub initiator_l: [u8; 32],
    pub initiator_p: [u8; 32],
    pub responder_l: [u8; 32],
    pub responder_p: [u8; 32],
    pub initiator_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    pub responder_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    pub session_id: [u8; SESSION_ID_LEN],
}

/// Derives BIP-324 directional keys, garbage terminators, and session ID using
/// `HKDF-SHA256`, binding `magic`, `initiator_pub`, `responder_pub`, the
/// `X25519` ECDH shared secret, and an optional post-quantum KEM shared secret.
pub fn derive_session_keys(
    magic: Magic,
    initiator_pub: &[u8; X25519_KEY_LEN],
    responder_pub: &[u8; X25519_KEY_LEN],
    ecdh_shared_secret: &[u8; X25519_KEY_LEN],
    pq_shared_secret: Option<&[u8]>,
) -> SessionKeys {
    let mut salt = Vec::with_capacity(28);
    salt.extend_from_slice(b"bitcoin_v2_shared_secret");
    salt.extend_from_slice(&magic);

    let mut ikm = Vec::with_capacity(64 + pq_shared_secret.map_or(0, <[u8]>::len));
    ikm.extend_from_slice(initiator_pub);
    ikm.extend_from_slice(responder_pub);
    ikm.extend_from_slice(ecdh_shared_secret);
    if let Some(pq) = pq_shared_secret {
        ikm.extend_from_slice(b"|pq_kem|");
        ikm.extend_from_slice(pq);
    }

    let prk = hkdf_extract(&salt, &ikm);
    let initiator_l = hkdf_expand_32(&prk, b"initiator_L");
    let initiator_p = hkdf_expand_32(&prk, b"initiator_P");
    let responder_l = hkdf_expand_32(&prk, b"responder_L");
    let responder_p = hkdf_expand_32(&prk, b"responder_P");
    let gt = hkdf_expand_32(&prk, b"garbage_terminators");
    let mut initiator_garbage_terminator = [0u8; GARBAGE_TERMINATOR_LEN];
    let mut responder_garbage_terminator = [0u8; GARBAGE_TERMINATOR_LEN];
    initiator_garbage_terminator.copy_from_slice(&gt[..16]);
    responder_garbage_terminator.copy_from_slice(&gt[16..]);
    let session_id = hkdf_expand_32(&prk, b"session_id");

    SessionKeys {
        initiator_l,
        initiator_p,
        responder_l,
        responder_p,
        initiator_garbage_terminator,
        responder_garbage_terminator,
        session_id,
    }
}

/// Decoded v2 packet returned by [`V2PacketCipher::open_packet`] or [`V2Session::open_packet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedPacket {
    /// Whether the packet had the BIP-324 `IGNORE` (`0x80`) header bit set.
    pub ignore: bool,
    /// Low 7 bits of the header byte.
    pub header_flags: u8,
    /// Authenticated plaintext payload.
    pub contents: Vec<u8>,
}

/// Unidirectional BIP-324 packet cipher (`FSChaCha20` length cipher +
/// `FSChaCha20Poly1305` / `XChaCha20Poly1305` AEAD packet cipher with automatic
/// forward-secret rekeying every [`REKEY_INTERVAL`] packets).
#[derive(Clone)]
pub struct V2PacketCipher {
    length_key: [u8; 32],
    packet_key: [u8; 32],
    packet_idx: u64,
    rekey_epoch: u64,
    mode: AeadMode,
}

impl V2PacketCipher {
    /// Creates a new unidirectional cipher from 32-byte length and packet keys.
    pub fn new(length_key: [u8; 32], packet_key: [u8; 32], mode: AeadMode) -> Self {
        Self {
            length_key,
            packet_key,
            packet_idx: 0,
            rekey_epoch: 0,
            mode,
        }
    }

    /// Number of packets processed since the last rekey.
    pub fn packet_index_in_epoch(&self) -> u64 {
        self.packet_idx
    }

    /// Current forward-secrecy rekey epoch (`0`, `1`, `2`, ...).
    pub fn rekey_epoch(&self) -> u64 {
        self.rekey_epoch
    }

    /// Explicitly ratchets the length and packet keys forward.
    pub fn rekey_now(&mut self) {
        let mut rekey_nonce = [0xffu8; 12];
        rekey_nonce[..4].copy_from_slice(&(self.rekey_epoch as u32).to_le_bytes());
        let next_packet_block = chacha20_block(&self.packet_key, 0, &rekey_nonce);
        self.packet_key.copy_from_slice(&next_packet_block[..32]);

        let next_length_block = chacha20_block(&self.length_key, 0, &rekey_nonce);
        self.length_key.copy_from_slice(&next_length_block[..32]);

        self.packet_idx = 0;
        self.rekey_epoch += 1;
    }

    fn crypt_length(&self, len_bytes: [u8; LENGTH_LEN]) -> [u8; LENGTH_LEN] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&((self.packet_idx as u32) / 21).to_le_bytes());
        nonce[4..12].copy_from_slice(&self.rekey_epoch.to_le_bytes());
        let stream = chacha20_block(&self.length_key, 0, &nonce);
        let offset = ((self.packet_idx as usize) % 21) * LENGTH_LEN;
        [
            len_bytes[0] ^ stream[offset],
            len_bytes[1] ^ stream[offset + 1],
            len_bytes[2] ^ stream[offset + 2],
        ]
    }

    fn effective_key_and_nonce(&self) -> ([u8; 32], [u8; 12]) {
        let mut nonce12 = [0u8; 12];
        nonce12[..4].copy_from_slice(&(self.packet_idx as u32).to_le_bytes());
        nonce12[4..12].copy_from_slice(&self.rekey_epoch.to_le_bytes());
        match self.mode {
            AeadMode::ChaCha20Poly1305 => (self.packet_key, nonce12),
            AeadMode::XChaCha20Poly1305 => {
                let mut nonce16 = [0u8; 16];
                nonce16[..8].copy_from_slice(&self.packet_idx.to_le_bytes());
                nonce16[8..16].copy_from_slice(&self.rekey_epoch.to_le_bytes());
                let subkey = hchacha20(&self.packet_key, &nonce16);
                (subkey, nonce12)
            }
        }
    }

    fn advance_counter(&mut self) {
        self.packet_idx += 1;
        if self.packet_idx == REKEY_INTERVAL {
            self.rekey_now();
        }
    }

    /// Decrypts a 3-byte encrypted length header without advancing the packet counter.
    pub fn decrypt_length(&self, enc_len: [u8; LENGTH_LEN]) -> usize {
        let raw = self.crypt_length(enc_len);
        (raw[0] as usize) | ((raw[1] as usize) << 8) | ((raw[2] as usize) << 16)
    }

    /// Encrypts and authenticates a packet (`[enc_len(3) || enc_header(1) || enc_contents || tag(16)]`).
    pub fn seal_packet(
        &mut self,
        contents: &[u8],
        aad: &[u8],
        ignore: bool,
    ) -> Result<Vec<u8>, NetworkError> {
        if contents.len() > MAX_V2_PACKET_LEN {
            return Err(NetworkError::MessageTooLarge {
                size: contents.len() as u32,
                max: MAX_V2_PACKET_LEN as u32,
            });
        }
        let len = contents.len();
        let raw_len = [
            (len & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            ((len >> 16) & 0xff) as u8,
        ];
        let enc_len = self.crypt_length(raw_len);

        let mut plaintext = Vec::with_capacity(HEADER_LEN + len);
        plaintext.push(if ignore { HEADER_IGNORE_BIT } else { 0x00 });
        plaintext.extend_from_slice(contents);

        let (key, nonce) = self.effective_key_and_nonce();
        let (ciphertext, tag) = chacha20_poly1305_seal(&key, &nonce, aad, &plaintext);

        let mut out = Vec::with_capacity(LENGTH_LEN + ciphertext.len() + TAG_LEN);
        out.extend_from_slice(&enc_len);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);

        self.advance_counter();
        Ok(out)
    }

    /// Authenticates and decrypts a complete wire frame (`enc_len(3) || ciphertext(1 + len) || tag(16)`).
    pub fn open_packet(
        &mut self,
        frame: &[u8],
        aad: &[u8],
    ) -> Result<DecryptedPacket, NetworkError> {
        if frame.len() < LENGTH_LEN + HEADER_LEN + TAG_LEN {
            return Err(NetworkError::InvalidHeader(
                "v2 frame shorter than minimum header + tag".into(),
            ));
        }
        let enc_len: [u8; LENGTH_LEN] = [frame[0], frame[1], frame[2]];
        let contents_len = self.decrypt_length(enc_len);
        if contents_len > MAX_V2_PACKET_LEN {
            return Err(NetworkError::MessageTooLarge {
                size: contents_len as u32,
                max: MAX_V2_PACKET_LEN as u32,
            });
        }
        let expected_total = LENGTH_LEN + HEADER_LEN + contents_len + TAG_LEN;
        if frame.len() != expected_total {
            return Err(NetworkError::InvalidChecksum);
        }
        self.open_body(&frame[LENGTH_LEN..], aad)
    }

    /// Authenticates and decrypts the body portion (`ciphertext(1 + len) || tag(16)`)
    /// after [`Self::decrypt_length`] has already determined `contents_len`.
    pub fn open_body(
        &mut self,
        body_and_tag: &[u8],
        aad: &[u8],
    ) -> Result<DecryptedPacket, NetworkError> {
        if body_and_tag.len() < HEADER_LEN + TAG_LEN {
            return Err(NetworkError::InvalidChecksum);
        }
        let ct_len = body_and_tag.len() - TAG_LEN;
        let ciphertext = &body_and_tag[..ct_len];
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&body_and_tag[ct_len..]);

        let (key, nonce) = self.effective_key_and_nonce();
        let plaintext = chacha20_poly1305_open(&key, &nonce, aad, ciphertext, &tag)
            .ok_or(NetworkError::InvalidChecksum)?;

        self.advance_counter();
        let header = plaintext[0];
        Ok(DecryptedPacket {
            ignore: (header & HEADER_IGNORE_BIT) != 0,
            header_flags: header & !HEADER_IGNORE_BIT,
            contents: plaintext[1..].to_vec(),
        })
    }
}

/// Bidirectional BIP-324 encrypted P2P session.
pub struct V2Session {
    role: Role,
    magic: Magic,
    send_cipher: V2PacketCipher,
    recv_cipher: V2PacketCipher,
    send_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    recv_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    session_id: [u8; SESSION_ID_LEN],
}

impl V2Session {
    /// Creates a bidirectional `V2Session` for `role` from derived [`SessionKeys`].
    pub fn from_keys(role: Role, magic: Magic, keys: SessionKeys, mode: AeadMode) -> Self {
        let (send_l, send_p, recv_l, recv_p, send_garbage_terminator, recv_garbage_terminator) =
            match role {
                Role::Initiator => (
                    keys.initiator_l,
                    keys.initiator_p,
                    keys.responder_l,
                    keys.responder_p,
                    keys.initiator_garbage_terminator,
                    keys.responder_garbage_terminator,
                ),
                Role::Responder => (
                    keys.responder_l,
                    keys.responder_p,
                    keys.initiator_l,
                    keys.initiator_p,
                    keys.responder_garbage_terminator,
                    keys.initiator_garbage_terminator,
                ),
            };
        Self {
            role,
            magic,
            send_cipher: V2PacketCipher::new(send_l, send_p, mode),
            recv_cipher: V2PacketCipher::new(recv_l, recv_p, mode),
            send_garbage_terminator,
            recv_garbage_terminator,
            session_id: keys.session_id,
        }
    }

    /// Creates a matched `(initiator, responder)` session pair from ephemeral X25519
    /// keypairs and an optional post-quantum KEM shared secret.
    pub fn establish_pair(
        magic: Magic,
        initiator_kp: &EphemeralX25519KeyPair,
        responder_kp: &EphemeralX25519KeyPair,
        pq_shared_secret: Option<&[u8]>,
        mode: AeadMode,
    ) -> Result<(Self, Self), NetworkError> {
        let ss_i = initiator_kp.diffie_hellman(responder_kp.public_key())?;
        let ss_r = responder_kp.diffie_hellman(initiator_kp.public_key())?;
        debug_assert_eq!(ss_i, ss_r);

        let keys_i = derive_session_keys(
            magic,
            initiator_kp.public_key(),
            responder_kp.public_key(),
            &ss_i,
            pq_shared_secret,
        );
        let keys_r = derive_session_keys(
            magic,
            initiator_kp.public_key(),
            responder_kp.public_key(),
            &ss_r,
            pq_shared_secret,
        );
        Ok((
            Self::from_keys(Role::Initiator, magic, keys_i, mode),
            Self::from_keys(Role::Responder, magic, keys_r, mode),
        ))
    }

    /// Role of this endpoint (`Initiator` or `Responder`).
    pub fn role(&self) -> Role {
        self.role
    }

    /// Unique 32-byte session identifier shared by both endpoints.
    pub fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// Outbound 16-byte garbage terminator.
    pub fn send_garbage_terminator(&self) -> &[u8; GARBAGE_TERMINATOR_LEN] {
        &self.send_garbage_terminator
    }

    /// Expected inbound 16-byte garbage terminator.
    pub fn recv_garbage_terminator(&self) -> &[u8; GARBAGE_TERMINATOR_LEN] {
        &self.recv_garbage_terminator
    }

    /// Current `(send_rekey_epoch, recv_rekey_epoch)`.
    pub fn rekey_epochs(&self) -> (u64, u64) {
        (
            self.send_cipher.rekey_epoch(),
            self.recv_cipher.rekey_epoch(),
        )
    }

    /// Encrypts and authenticates an outbound packet.
    pub fn seal_packet(
        &mut self,
        contents: &[u8],
        aad: &[u8],
        ignore: bool,
    ) -> Result<Vec<u8>, NetworkError> {
        self.send_cipher.seal_packet(contents, aad, ignore)
    }

    /// Authenticates and decrypts an inbound packet frame.
    pub fn open_packet(
        &mut self,
        frame: &[u8],
        aad: &[u8],
    ) -> Result<DecryptedPacket, NetworkError> {
        self.recv_cipher.open_packet(frame, aad)
    }

    /// Serializes and encrypts a Divi [`NetworkMessage`] inside a v2 AEAD packet.
    pub fn seal_network_message(&mut self, msg: &NetworkMessage) -> Result<Vec<u8>, NetworkError> {
        let bytes = msg.to_bytes(self.magic)?;
        self.seal_packet(&bytes, &[], false)
    }

    /// Decrypts a v2 AEAD packet and deserializes the inner Divi [`NetworkMessage`].
    /// Returns `Ok(None)` if the packet was marked with the `IGNORE` decoy bit.
    pub fn open_network_message(
        &mut self,
        frame: &[u8],
    ) -> Result<Option<NetworkMessage>, NetworkError> {
        let pkt = self.open_packet(frame, &[])?;
        if pkt.ignore {
            return Ok(None);
        }
        if pkt.contents.len() < crate::message::HEADER_SIZE {
            return Err(NetworkError::InvalidHeader(
                "v2 inner message shorter than 24-byte Divi header".into(),
            ));
        }
        let header = crate::message::MessageHeader::deserialize(
            &pkt.contents[..crate::message::HEADER_SIZE],
        )?;
        if !header.validate_magic(&self.magic) {
            return Err(NetworkError::InvalidMagic);
        }
        let payload = &pkt.contents[crate::message::HEADER_SIZE..];
        if payload.len() != header.payload_size as usize {
            return Err(NetworkError::InvalidHeader(
                "v2 inner payload length mismatch".into(),
            ));
        }
        if !header.validate_checksum(payload) {
            return Err(NetworkError::InvalidChecksum);
        }
        let msg = NetworkMessage::deserialize(&header.command_string(), payload)?;
        Ok(Some(msg))
    }
}

/// Result of capability-negotiated P2P transport detection/handshake.
pub enum NegotiatedTransport<S> {
    /// Encrypted v2 transport established.
    V2(Box<V2TransportStream<S>>),
    /// Peer spoke v1 plaintext magic bytes; `prefix` holds the already-read
    /// initial bytes so the caller can replay `prefix` + `stream` into `DiviCodec`.
    V1Fallback { prefix: Vec<u8>, stream: S },
}

/// Async stream wrapper driving a [`V2Session`] over an underlying transport `S`.
pub struct V2TransportStream<S> {
    stream: S,
    session: V2Session,
}

impl<S> V2TransportStream<S> {
    /// Wraps an established [`V2Session`] and stream `S`.
    pub fn new(stream: S, session: V2Session) -> Self {
        Self { stream, session }
    }

    /// Reference to the underlying [`V2Session`].
    pub fn session(&self) -> &V2Session {
        &self.session
    }

    /// Mutable reference to the underlying [`V2Session`].
    pub fn session_mut(&mut self) -> &mut V2Session {
        &mut self.session
    }

    /// Consumes the wrapper and returns `(stream, session)`.
    pub fn into_parts(self) -> (S, V2Session) {
        (self.stream, self.session)
    }
}

impl<S> V2TransportStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Sends an encrypted v2 packet over the stream.
    pub async fn send_packet(
        &mut self,
        contents: &[u8],
        aad: &[u8],
        ignore: bool,
    ) -> Result<(), NetworkError> {
        let frame = self.session.seal_packet(contents, aad, ignore)?;
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Reads and authenticates the next v2 packet (including decoy packets).
    pub async fn recv_raw_packet(&mut self, aad: &[u8]) -> Result<DecryptedPacket, NetworkError> {
        let mut enc_len = [0u8; LENGTH_LEN];
        self.stream.read_exact(&mut enc_len).await?;
        let contents_len = self.session.recv_cipher.decrypt_length(enc_len);
        if contents_len > MAX_V2_PACKET_LEN {
            return Err(NetworkError::MessageTooLarge {
                size: contents_len as u32,
                max: MAX_V2_PACKET_LEN as u32,
            });
        }
        let mut body_and_tag = vec![0u8; HEADER_LEN + contents_len + TAG_LEN];
        self.stream.read_exact(&mut body_and_tag).await?;
        self.session.recv_cipher.open_body(&body_and_tag, aad)
    }

    /// Reads and authenticates the next non-ignored v2 application packet,
    /// transparently skipping any decoy (`ignore = true`) packets.
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>, NetworkError> {
        loop {
            let pkt = self.recv_raw_packet(&[]).await?;
            if !pkt.ignore {
                return Ok(pkt.contents);
            }
        }
    }

    /// Sends a serialized Divi [`NetworkMessage`] over the encrypted v2 stream.
    pub async fn send_message(&mut self, msg: &NetworkMessage) -> Result<(), NetworkError> {
        let bytes = msg.to_bytes(self.session.magic)?;
        self.send_packet(&bytes, &[], false).await
    }

    /// Receives the next Divi [`NetworkMessage`] from the encrypted v2 stream,
    /// transparently skipping decoy packets.
    pub async fn recv_message(&mut self) -> Result<NetworkMessage, NetworkError> {
        let contents = self.recv_packet().await?;
        if contents.len() < crate::message::HEADER_SIZE {
            return Err(NetworkError::InvalidHeader(
                "v2 inner message shorter than 24-byte Divi header".into(),
            ));
        }
        let header =
            crate::message::MessageHeader::deserialize(&contents[..crate::message::HEADER_SIZE])?;
        if !header.validate_magic(&self.session.magic) {
            return Err(NetworkError::InvalidMagic);
        }
        let payload = &contents[crate::message::HEADER_SIZE..];
        if payload.len() != header.payload_size as usize {
            return Err(NetworkError::InvalidHeader(
                "v2 inner payload length mismatch".into(),
            ));
        }
        if !header.validate_checksum(payload) {
            return Err(NetworkError::InvalidChecksum);
        }
        NetworkMessage::deserialize(&header.command_string(), payload)
    }
}

/// Negotiates an outbound v2 encrypted connection (with optional hybrid PQ KEM hook
/// and automatic v1 fallback detection if the remote peer immediately speaks v1 magic).
pub async fn negotiate_outbound<S>(
    mut stream: S,
    magic: Magic,
    mode: AeadMode,
    pq_hook: Option<&dyn PqKemHook>,
) -> Result<NegotiatedTransport<S>, NetworkError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let kp = EphemeralX25519KeyPair::generate();
    stream.write_all(kp.public_key()).await?;
    let pq_state = if let Some(hook) = pq_hook {
        let (pq_ek, state) = hook.initiator_begin()?;
        let len_u16 = (pq_ek.len() as u16).to_le_bytes();
        stream.write_all(&len_u16).await?;
        stream.write_all(&pq_ek).await?;
        Some(state)
    } else {
        None
    };
    stream.flush().await?;

    let mut first4 = [0u8; 4];
    stream.read_exact(&mut first4).await?;
    if detect_v1_prefix(&first4, magic) {
        return Ok(NegotiatedTransport::V1Fallback {
            prefix: first4.to_vec(),
            stream,
        });
    }

    let mut responder_pub = [0u8; X25519_KEY_LEN];
    responder_pub[..4].copy_from_slice(&first4);
    stream.read_exact(&mut responder_pub[4..]).await?;

    let pq_secret = if let Some(state) = pq_state {
        let mut ct_len_bytes = [0u8; 2];
        stream.read_exact(&mut ct_len_bytes).await?;
        let ct_len = u16::from_le_bytes(ct_len_bytes) as usize;
        if ct_len > 16 * 1024 {
            return Err(NetworkError::HandshakeFailed(
                "oversized PQ KEM ciphertext".into(),
            ));
        }
        let mut ct = vec![0u8; ct_len];
        stream.read_exact(&mut ct).await?;
        Some(state.decapsulate(&ct)?)
    } else {
        None
    };

    let ecdh = kp.diffie_hellman(&responder_pub)?;
    let keys = derive_session_keys(
        magic,
        kp.public_key(),
        &responder_pub,
        &ecdh,
        pq_secret.as_deref(),
    );
    let session = V2Session::from_keys(Role::Initiator, magic, keys, mode);
    let mut v2 = V2TransportStream::new(stream, session);

    // Send initiator garbage terminator + transport version packet (BIP-324)
    let term = *v2.session().send_garbage_terminator();
    v2.stream.write_all(&term).await?;
    v2.send_packet(b"divi-v2", &[], false).await?;

    let mut peer_term = [0u8; GARBAGE_TERMINATOR_LEN];
    v2.stream.read_exact(&mut peer_term).await?;
    if !constant_time_eq(&peer_term, v2.session().recv_garbage_terminator()) {
        return Err(NetworkError::HandshakeFailed(
            "responder garbage terminator mismatch".into(),
        ));
    }
    let ver_pkt = v2.recv_raw_packet(&[]).await?;
    if ver_pkt.contents != b"divi-v2" {
        return Err(NetworkError::HandshakeFailed(
            "unexpected responder transport version packet".into(),
        ));
    }

    Ok(NegotiatedTransport::V2(Box::new(v2)))
}

/// Negotiates an inbound connection, automatically falling back to `v1` if the
/// peer's first 4 bytes match `magic`, `0xf9beb4d9`, or any Divi network magic.
pub async fn negotiate_inbound<S>(
    mut stream: S,
    magic: Magic,
    mode: AeadMode,
    pq_hook: Option<&dyn PqKemHook>,
) -> Result<NegotiatedTransport<S>, NetworkError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut first4 = [0u8; 4];
    stream.read_exact(&mut first4).await?;
    if detect_v1_prefix(&first4, magic) {
        return Ok(NegotiatedTransport::V1Fallback {
            prefix: first4.to_vec(),
            stream,
        });
    }

    let mut initiator_pub = [0u8; X25519_KEY_LEN];
    initiator_pub[..4].copy_from_slice(&first4);
    stream.read_exact(&mut initiator_pub[4..]).await?;

    let pq_ct_and_ss = if let Some(hook) = pq_hook {
        let mut ek_len_bytes = [0u8; 2];
        stream.read_exact(&mut ek_len_bytes).await?;
        let ek_len = u16::from_le_bytes(ek_len_bytes) as usize;
        if ek_len > 16 * 1024 {
            return Err(NetworkError::HandshakeFailed(
                "oversized PQ KEM encapsulation key".into(),
            ));
        }
        let mut ek = vec![0u8; ek_len];
        stream.read_exact(&mut ek).await?;
        Some(hook.responder_encapsulate(&ek)?)
    } else {
        None
    };

    let kp = EphemeralX25519KeyPair::generate();
    let ecdh = kp.diffie_hellman(&initiator_pub)?;
    let pq_secret_ref = pq_ct_and_ss.as_ref().map(|(_, ss)| ss.as_slice());
    let keys = derive_session_keys(magic, &initiator_pub, kp.public_key(), &ecdh, pq_secret_ref);

    stream.write_all(kp.public_key()).await?;
    if let Some((ct, _)) = &pq_ct_and_ss {
        let len_u16 = (ct.len() as u16).to_le_bytes();
        stream.write_all(&len_u16).await?;
        stream.write_all(ct).await?;
    }
    stream.flush().await?;

    let session = V2Session::from_keys(Role::Responder, magic, keys, mode);
    let mut v2 = V2TransportStream::new(stream, session);

    let mut peer_term = [0u8; GARBAGE_TERMINATOR_LEN];
    v2.stream.read_exact(&mut peer_term).await?;
    if !constant_time_eq(&peer_term, v2.session().recv_garbage_terminator()) {
        return Err(NetworkError::HandshakeFailed(
            "initiator garbage terminator mismatch".into(),
        ));
    }
    let ver_pkt = v2.recv_raw_packet(&[]).await?;
    if ver_pkt.contents != b"divi-v2" {
        return Err(NetworkError::HandshakeFailed(
            "unexpected initiator transport version packet".into(),
        ));
    }

    let term = *v2.session().send_garbage_terminator();
    v2.stream.write_all(&term).await?;
    v2.send_packet(b"divi-v2", &[], false).await?;

    Ok(NegotiatedTransport::V2(Box::new(v2)))
}

/// Reconstructs a full stream by prepending `prefix` ahead of `stream` (for `v1` fallback).
pub fn replay_v1_stream<S>(
    prefix: Vec<u8>,
    stream: S,
) -> tokio::io::Chain<std::io::Cursor<Vec<u8>>, S>
where
    S: AsyncRead,
{
    tokio::io::AsyncReadExt::chain(std::io::Cursor::new(prefix), stream)
}

// ============================================================================
// HKDF-SHA256 (RFC 5869)
// ============================================================================

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn hkdf_expand_32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("HMAC accepts 32-byte key");
    mac.update(info);
    mac.update(&[0x01]);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn hkdf_expand_vec(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut prev = [0u8; 32];
    let mut counter = 1u8;
    while out.len() < len {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).unwrap();
        if counter > 1 {
            mac.update(&prev);
        }
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        prev.copy_from_slice(&block);
        let take = (len - out.len()).min(32);
        out.extend_from_slice(&prev[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// ChaCha20, HChaCha20 & Poly1305 AEAD (RFC 8439)
// ============================================================================

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[0] = 0x6170_7865;
    initial[1] = 0x3320_646e;
    initial[2] = 0x7962_2d32;
    initial[3] = 0x6b20_6574;
    for i in 0..8 {
        initial[4 + i] =
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    initial[12] = counter;
    for i in 0..3 {
        initial[13 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }

    let mut working = initial;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(initial[i]).to_le_bytes();
        out[4 * i..4 * i + 4].copy_from_slice(&word);
    }
    out
}

fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes([
            nonce16[4 * i],
            nonce16[4 * i + 1],
            nonce16[4 * i + 2],
            nonce16[4 * i + 3],
        ]);
    }

    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 32];
    for (idx, &word_idx) in [0usize, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
        out[4 * idx..4 * idx + 4].copy_from_slice(&state[word_idx].to_le_bytes());
    }
    out
}

fn chacha20_xor(key: &[u8; 32], initial_counter: u32, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = initial_counter;
    for chunk in data.chunks(64) {
        let block = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        for (&b, &k) in chunk.iter().zip(block.iter()) {
            out.push(b ^ k);
        }
    }
    out
}

fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; TAG_LEN] {
    let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) as u64;
    let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]) as u64;
    let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]) as u64;
    let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]) as u64;

    let r0 = t0 & 0x03ff_ffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff;
    let r4 = (t3 >> 8) & 0x000f_ffff;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    for chunk in msg.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;
        let hibit = if chunk.len() == 16 { 1u64 << 24 } else { 0u64 };

        let d0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as u64;
        let d1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]) as u64;
        let d2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]) as u64;
        let d3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]) as u64;

        h0 += d0 & 0x03ff_ffff;
        h1 += ((d0 >> 26) | (d1 << 6)) & 0x03ff_ffff;
        h2 += ((d1 >> 20) | (d2 << 12)) & 0x03ff_ffff;
        h3 += ((d2 >> 14) | (d3 << 18)) & 0x03ff_ffff;
        h4 += (d3 >> 8) | hibit;

        let m0 = (h0 as u128) * (r0 as u128)
            + (h1 as u128) * (s4 as u128)
            + (h2 as u128) * (s3 as u128)
            + (h3 as u128) * (s2 as u128)
            + (h4 as u128) * (s1 as u128);
        let m1 = (h0 as u128) * (r1 as u128)
            + (h1 as u128) * (r0 as u128)
            + (h2 as u128) * (s4 as u128)
            + (h3 as u128) * (s3 as u128)
            + (h4 as u128) * (s2 as u128);
        let m2 = (h0 as u128) * (r2 as u128)
            + (h1 as u128) * (r1 as u128)
            + (h2 as u128) * (r0 as u128)
            + (h3 as u128) * (s4 as u128)
            + (h4 as u128) * (s3 as u128);
        let m3 = (h0 as u128) * (r3 as u128)
            + (h1 as u128) * (r2 as u128)
            + (h2 as u128) * (r1 as u128)
            + (h3 as u128) * (r0 as u128)
            + (h4 as u128) * (s4 as u128);
        let m4 = (h0 as u128) * (r4 as u128)
            + (h1 as u128) * (r3 as u128)
            + (h2 as u128) * (r2 as u128)
            + (h3 as u128) * (r1 as u128)
            + (h4 as u128) * (r0 as u128);

        let mut c = (m0 >> 26) as u64;
        h0 = (m0 as u64) & 0x03ff_ffff;
        let m1 = m1 + (c as u128);
        c = (m1 >> 26) as u64;
        h1 = (m1 as u64) & 0x03ff_ffff;
        let m2 = m2 + (c as u128);
        c = (m2 >> 26) as u64;
        h2 = (m2 as u64) & 0x03ff_ffff;
        let m3 = m3 + (c as u128);
        c = (m3 >> 26) as u64;
        h3 = (m3 as u64) & 0x03ff_ffff;
        let m4 = m4 + (c as u128);
        c = (m4 >> 26) as u64;
        h4 = (m4 as u64) & 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;
    }

    let mut c = h1 >> 26;
    h1 &= 0x03ff_ffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x03ff_ffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x03ff_ffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x03ff_ffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x03ff_ffff;
    h1 += c;

    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x03ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x03ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x03ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x03ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    h0 = (h0 & !mask) | (g0 & mask);
    h1 = (h1 & !mask) | (g1 & mask);
    h2 = (h2 & !mask) | (g2 & mask);
    h3 = (h3 & !mask) | (g3 & mask);
    h4 = (h4 & !mask) | (g4 & mask);

    let f0 = ((h0 | (h1 << 26)) & 0xffff_ffff)
        + (u32::from_le_bytes([key[16], key[17], key[18], key[19]]) as u64);
    let f1 = (((h1 >> 6) | (h2 << 20)) & 0xffff_ffff)
        + (u32::from_le_bytes([key[20], key[21], key[22], key[23]]) as u64)
        + (f0 >> 32);
    let f2 = (((h2 >> 12) | (h3 << 14)) & 0xffff_ffff)
        + (u32::from_le_bytes([key[24], key[25], key[26], key[27]]) as u64)
        + (f1 >> 32);
    let f3 = (((h3 >> 18) | (h4 << 8)) & 0xffff_ffff)
        + (u32::from_le_bytes([key[28], key[29], key[30], key[31]]) as u64)
        + (f2 >> 32);

    let mut tag = [0u8; TAG_LEN];
    tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
    tag
}

fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let mut mac_data =
        Vec::with_capacity(aad.len().div_ceil(16) * 16 + ciphertext.len().div_ceil(16) * 16 + 16);
    mac_data.extend_from_slice(aad);
    if !aad.len().is_multiple_of(16) {
        mac_data.resize(mac_data.len() + (16 - (aad.len() % 16)), 0);
    }
    mac_data.extend_from_slice(ciphertext);
    if !ciphertext.len().is_multiple_of(16) {
        mac_data.resize(mac_data.len() + (16 - (ciphertext.len() % 16)), 0);
    }
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305_mac(&mac_data, otk)
}

fn chacha20_poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);
    let ciphertext = chacha20_xor(key, 1, nonce, plaintext);
    let tag = poly1305_aead_tag(&otk, aad, &ciphertext);
    (ciphertext, tag)
}

fn chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Option<Vec<u8>> {
    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);
    let expected_tag = poly1305_aead_tag(&otk, aad, ciphertext);
    if !constant_time_eq(tag, &expected_tag) {
        return None;
    }
    Some(chacha20_xor(key, 1, nonce, ciphertext))
}

// ============================================================================
// X25519 (RFC 7748 Montgomery Ladder over GF(2^255 - 19))
// ============================================================================

const MASK51: u64 = (1u64 << 51) - 1;

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Self = Self([0; 5]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);
    const A24: Self = Self([121665, 0, 0, 0, 0]);

    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load64 = |offset: usize| -> u64 {
            let mut b = [0u8; 8];
            let len = (32 - offset).min(8);
            b[..len].copy_from_slice(&bytes[offset..offset + len]);
            u64::from_le_bytes(b)
        };
        let l0 = load64(0) & MASK51;
        let l1 = (load64(6) >> 3) & MASK51;
        let l2 = (load64(12) >> 6) & MASK51;
        let l3 = (load64(19) >> 1) & MASK51;
        let l4 = (load64(24) >> 12) & ((1u64 << 51) - 1);
        Self([l0, l1, l2, l3, l4])
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut t = self.0;
        for _ in 0..2 {
            for i in 0..4 {
                let c = t[i] >> 51;
                t[i] &= MASK51;
                t[i + 1] += c;
            }
            let c = t[4] >> 51;
            t[4] &= MASK51;
            t[0] += c * 19;
        }

        // Compute u = t + 19; if u >= 2^255, t >= p
        let mut u = t;
        u[0] += 19;
        for i in 0..4 {
            let c = u[i] >> 51;
            u[i] &= MASK51;
            u[i + 1] += c;
        }
        let ge_p = u[4] >> 51;
        u[4] &= MASK51;

        let mask = ge_p.wrapping_sub(1); // 0 if t >= p, all-1s if t < p
        for i in 0..5 {
            t[i] = (t[i] & mask) | (u[i] & !mask);
        }

        let mut out = [0u8; 32];
        let v0 = t[0] | (t[1] << 51);
        let v1 = (t[1] >> 13) | (t[2] << 38);
        let v2 = (t[2] >> 26) | (t[3] << 25);
        let v3 = (t[3] >> 39) | (t[4] << 12);
        out[0..8].copy_from_slice(&v0.to_le_bytes());
        out[8..16].copy_from_slice(&v1.to_le_bytes());
        out[16..24].copy_from_slice(&v2.to_le_bytes());
        out[24..32].copy_from_slice(&v3.to_le_bytes());
        out
    }

    fn add(self, rhs: Self) -> Self {
        let mut out = [0u64; 5];
        for (i, item) in out.iter_mut().enumerate() {
            *item = self.0[i] + rhs.0[i];
        }
        Self(out).reduce_carries()
    }

    fn sub(self, rhs: Self) -> Self {
        // Add 2*p to avoid underflow before subtracting rhs
        let mut out = [
            self.0[0] + 0x000f_ffff_ffff_ffda - rhs.0[0],
            self.0[1] + 0x000f_ffff_ffff_fffe - rhs.0[1],
            self.0[2] + 0x000f_ffff_ffff_fffe - rhs.0[2],
            self.0[3] + 0x000f_ffff_ffff_fffe - rhs.0[3],
            self.0[4] + 0x000f_ffff_ffff_fffe - rhs.0[4],
        ];
        for i in 0..4 {
            let c = out[i] >> 51;
            out[i] &= MASK51;
            out[i + 1] += c;
        }
        let c = out[4] >> 51;
        out[4] &= MASK51;
        out[0] += c * 19;
        Self(out).reduce_carries()
    }

    fn reduce_carries(mut self) -> Self {
        for i in 0..4 {
            let c = self.0[i] >> 51;
            self.0[i] &= MASK51;
            self.0[i + 1] += c;
        }
        let c = self.0[4] >> 51;
        self.0[4] &= MASK51;
        self.0[0] += c * 19;
        let c0 = self.0[0] >> 51;
        self.0[0] &= MASK51;
        self.0[1] += c0;
        self
    }

    fn mul(self, rhs: Self) -> Self {
        let a = self.0.map(|x| x as u128);
        let b = rhs.0.map(|x| x as u128);
        let b19 = [0, b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];

        let mut t0 = a[0] * b[0] + a[1] * b19[4] + a[2] * b19[3] + a[3] * b19[2] + a[4] * b19[1];
        let mut t1 = a[0] * b[1] + a[1] * b[0] + a[2] * b19[4] + a[3] * b19[3] + a[4] * b19[2];
        let mut t2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b19[4] + a[4] * b19[3];
        let mut t3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b19[4];
        let mut t4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];

        let c0 = t0 >> 51;
        t0 &= MASK51 as u128;
        t1 += c0;
        let c1 = t1 >> 51;
        t1 &= MASK51 as u128;
        t2 += c1;
        let c2 = t2 >> 51;
        t2 &= MASK51 as u128;
        t3 += c2;
        let c3 = t3 >> 51;
        t3 &= MASK51 as u128;
        t4 += c3;
        let c4 = t4 >> 51;
        t4 &= MASK51 as u128;
        t0 += c4 * 19;
        let c0b = t0 >> 51;
        t0 &= MASK51 as u128;
        t1 += c0b;

        Self([t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64]).reduce_carries()
    }

    fn sq(self) -> Self {
        self.mul(self)
    }

    fn inv(self) -> Self {
        // z^(2^255 - 21)
        let mut acc = Self::ONE;
        let mut base = self;
        // 2^255 - 21 in binary: bits 0..254 where bits 0, 1, 3, 5..254 are set
        // (since 2^255 - 21 = (2^255 - 1) - 20, and 20 = 16 + 4 = 2^4 + 2^2)
        for bit in 0..255 {
            let is_set = bit != 2 && bit != 4;
            if is_set {
                acc = acc.mul(base);
            }
            base = base.sq();
        }
        acc
    }

    fn cswap(swap: u64, a: &mut Self, b: &mut Self) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let x = (a.0[i] ^ b.0[i]) & mask;
            a.0[i] ^= x;
            b.0[i] ^= x;
        }
    }
}

fn clamp_scalar(k: &mut [u8; 32]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// RFC 7748 `X25519(k, u)` scalar multiplication.
pub fn x25519(scalar: &[u8; 32], u_bytes: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    clamp_scalar(&mut k);
    let mut u_clean = *u_bytes;
    u_clean[31] &= 127;

    let x_1 = Fe::from_bytes(&u_clean);
    let mut x_2 = Fe::ONE;
    let mut z_2 = Fe::ZERO;
    let mut x_3 = x_1;
    let mut z_3 = Fe::ONE;
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let k_t = ((k[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= k_t;
        Fe::cswap(swap, &mut x_2, &mut x_3);
        Fe::cswap(swap, &mut z_2, &mut z_3);
        swap = k_t;

        let a = x_2.add(z_2);
        let aa = a.sq();
        let b = x_2.sub(z_2);
        let bb = b.sq();
        let e = aa.sub(bb);
        let c = x_3.add(z_3);
        let d = x_3.sub(z_3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x_3 = da.add(cb).sq();
        z_3 = x_1.mul(da.sub(cb).sq());
        x_2 = aa.mul(bb);
        z_2 = e.mul(aa.add(Fe::A24.mul(e)));
    }

    Fe::cswap(swap, &mut x_2, &mut x_3);
    Fe::cswap(swap, &mut z_2, &mut z_3);

    x_2.mul(z_2.inv()).to_bytes()
}

/// RFC 7748 basepoint (`u = 9`) public key derivation.
pub fn x25519_basepoint(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(scalar, &base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{services, PROTOCOL_VERSION};
    use crate::message::NetAddr;
    use crate::version::VersionMessage;
    use tokio::io::AsyncReadExt;

    #[test]
    fn rfc7748_x25519_test_vector_and_dh_agreement() {
        // RFC 7748 §6.1 Alice/Bob test vector
        let alice_priv: [u8; 32] =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let alice_expected_pub: [u8; 32] =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_priv: [u8; 32] =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_expected_pub: [u8; 32] =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_shared: [u8; 32] =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap()
                .try_into()
                .unwrap();

        let alice = EphemeralX25519KeyPair::from_secret_bytes(alice_priv);
        let bob = EphemeralX25519KeyPair::from_secret_bytes(bob_priv);
        assert_eq!(alice.public_key(), &alice_expected_pub);
        assert_eq!(bob.public_key(), &bob_expected_pub);
        assert_eq!(
            alice.diffie_hellman(bob.public_key()).unwrap(),
            expected_shared
        );
        assert_eq!(
            bob.diffie_hellman(alice.public_key()).unwrap(),
            expected_shared
        );
    }

    #[test]
    fn rfc8439_chacha20_poly1305_aead_vector() {
        let key: [u8; 32] =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = hex::decode("070000004041424344454647")
            .unwrap()
            .try_into()
            .unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_tag: [u8; 16] = hex::decode("1ae10b594f09e26a7e902ecbd0600691")
            .unwrap()
            .try_into()
            .unwrap();

        let (ct, tag) = chacha20_poly1305_seal(&key, &nonce, &aad, plaintext);
        assert_eq!(tag, expected_tag);
        let opened = chacha20_poly1305_open(&key, &nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(&opened[..], &plaintext[..]);
    }

    #[test]
    fn v2_session_bidirectional_framing_and_tamper_rejection() {
        let i_kp = EphemeralX25519KeyPair::generate();
        let r_kp = EphemeralX25519KeyPair::generate();
        let (mut initiator, mut responder) = V2Session::establish_pair(
            MAINNET_MAGIC,
            &i_kp,
            &r_kp,
            Some(b"hybrid-mlkem768-secret"),
            AeadMode::ChaCha20Poly1305,
        )
        .unwrap();
        assert_eq!(initiator.session_id(), responder.session_id());

        let frame = initiator
            .seal_packet(b"ping-from-initiator", b"aad-1", false)
            .unwrap();
        let pkt = responder.open_packet(&frame, b"aad-1").unwrap();
        assert!(!pkt.ignore);
        assert_eq!(pkt.contents, b"ping-from-initiator");

        // Decoy (ignore = true) packet round-trip
        let decoy = responder.seal_packet(b"decoy-bytes", b"", true).unwrap();
        let decoy_pkt = initiator.open_packet(&decoy, b"").unwrap();
        assert!(decoy_pkt.ignore);
        assert_eq!(decoy_pkt.contents, b"decoy-bytes");

        // Tamper rejection: flipping a payload bit, length bit, or tag bit must fail authentication
        let valid_frame = initiator
            .seal_packet(b"consensus-critical-p2p-msg", b"", false)
            .unwrap();
        for flip_pos in [0usize, LENGTH_LEN, valid_frame.len() - 1] {
            let mut corrupted = valid_frame.clone();
            corrupted[flip_pos] ^= 0x01;
            let mut test_responder = responder.clone_recv_state_for_test();
            assert!(test_responder.open_packet(&corrupted, b"").is_err());
        }
        // Original frame still opens cleanly on the untampered responder state
        let valid_pkt = responder.open_packet(&valid_frame, b"").unwrap();
        assert_eq!(valid_pkt.contents, b"consensus-critical-p2p-msg");
    }

    impl V2Session {
        fn clone_recv_state_for_test(&self) -> V2PacketCipher {
            self.recv_cipher.clone()
        }
    }

    #[test]
    fn v2_session_rekeys_automatically_every_224_packets_and_supports_xchacha20() {
        let i_kp = EphemeralX25519KeyPair::generate();
        let r_kp = EphemeralX25519KeyPair::generate();
        let (mut initiator, mut responder) = V2Session::establish_pair(
            REGTEST_MAGIC,
            &i_kp,
            &r_kp,
            None,
            AeadMode::XChaCha20Poly1305,
        )
        .unwrap();
        assert_eq!(initiator.rekey_epochs(), (0, 0));

        for idx in 0..(REKEY_INTERVAL * 2 + 5) {
            let msg = format!("packet-{idx}");
            let frame = initiator.seal_packet(msg.as_bytes(), b"", false).unwrap();
            let opened = responder.open_packet(&frame, b"").unwrap();
            assert_eq!(opened.contents, msg.as_bytes());
        }

        assert_eq!(initiator.rekey_epochs(), (2, 0));
        assert_eq!(responder.rekey_epochs(), (0, 2));
    }

    #[test]
    fn v1_magic_fallback_detector_recognizes_bitcoin_and_divi_magics() {
        // Bitcoin legacy 0xf9beb4d9 + "version\0\0\0\0\0"
        let mut btc_v1 = Vec::new();
        btc_v1.extend_from_slice(&BITCOIN_MAINNET_V1_MAGIC);
        btc_v1.extend_from_slice(b"version\0\0\0\0\0");
        assert!(detect_v1_prefix(&btc_v1, MAINNET_MAGIC));

        // Divi mainnet, testnet, regtest, PrivateDivi
        for magic in [
            MAINNET_MAGIC,
            TESTNET_MAGIC,
            REGTEST_MAGIC,
            PRIVATEDIVI_MAINNET_MAGIC,
        ] {
            let mut hdr = Vec::new();
            hdr.extend_from_slice(&magic);
            hdr.extend_from_slice(b"version\0\0\0\0\0");
            assert!(detect_v1_prefix(&hdr, magic));
        }

        // Non-magic random 32-byte X25519 public key is not misclassified as v1
        let non_magic = [0x11, 0x22, 0x33, 0x44, 0xff, 0x00, 0xaa, 0x55];
        assert!(!detect_v1_prefix(&non_magic, MAINNET_MAGIC));
    }

    #[tokio::test]
    async fn loopback_v2_handshake_with_hybrid_pq_hook_and_network_messages() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let pq_hook = DeterministicPqKem::new("X25519+ML-KEM-768", 64, 64);

        let (out_res, in_res) = tokio::join!(
            negotiate_outbound(
                client_io,
                REGTEST_MAGIC,
                AeadMode::ChaCha20Poly1305,
                Some(&pq_hook)
            ),
            negotiate_inbound(
                server_io,
                REGTEST_MAGIC,
                AeadMode::ChaCha20Poly1305,
                Some(&pq_hook)
            ),
        );

        let NegotiatedTransport::V2(mut client_v2) = out_res.unwrap() else {
            panic!("expected V2 transport on outbound");
        };
        let NegotiatedTransport::V2(mut server_v2) = in_res.unwrap() else {
            panic!("expected V2 transport on inbound");
        };
        assert_eq!(
            client_v2.session().session_id(),
            server_v2.session().session_id()
        );

        let version_msg = NetworkMessage::Version(VersionMessage {
            version: PROTOCOL_VERSION,
            services: services::NODE_NETWORK | NODE_P2P_V2,
            timestamp: 1_704_067_200,
            addr_recv: NetAddr::from_ipv4([127, 0, 0, 1], 51476, services::NODE_NETWORK),
            addr_from: NetAddr::from_ipv4([127, 0, 0, 1], 51476, services::NODE_NETWORK),
            nonce: 0xdead_beef_cafe_babe,
            user_agent: "/IronDivi:v2-test/".to_string(),
            start_height: 42,
            relay: true,
        });

        // Interleave a decoy packet before the real Version message
        client_v2
            .send_packet(b"chaff-decoy-packet", &[], true)
            .await
            .unwrap();
        client_v2.send_message(&version_msg).await.unwrap();

        let received = server_v2.recv_message().await.unwrap();
        assert_eq!(
            received.to_bytes(REGTEST_MAGIC).unwrap(),
            version_msg.to_bytes(REGTEST_MAGIC).unwrap()
        );

        server_v2
            .send_message(&NetworkMessage::Verack)
            .await
            .unwrap();
        let reply = client_v2.recv_message().await.unwrap();
        assert!(matches!(reply, NetworkMessage::Verack));
    }

    #[tokio::test]
    async fn loopback_inbound_transparently_falls_back_to_v1_on_magic_bytes() {
        let (mut v1_peer, server_io) = tokio::io::duplex(16 * 1024);

        let v1_version = NetworkMessage::Version(VersionMessage {
            version: PROTOCOL_VERSION,
            services: services::NODE_NETWORK,
            timestamp: 1_704_067_200,
            addr_recv: NetAddr::from_ipv4([127, 0, 0, 1], 51472, services::NODE_NETWORK),
            addr_from: NetAddr::from_ipv4([127, 0, 0, 1], 51472, services::NODE_NETWORK),
            nonce: 0x1234_5678,
            user_agent: "/DiviCore:3.0.0/".to_string(),
            start_height: 100,
            relay: true,
        });
        let raw_v1_bytes = v1_version.to_bytes(MAINNET_MAGIC).unwrap();
        v1_peer.write_all(&raw_v1_bytes).await.unwrap();
        v1_peer.flush().await.unwrap();

        let negotiated =
            negotiate_inbound(server_io, MAINNET_MAGIC, AeadMode::ChaCha20Poly1305, None)
                .await
                .unwrap();
        let NegotiatedTransport::V1Fallback { prefix, stream } = negotiated else {
            panic!("expected V1Fallback when peer sends v1 MAINNET_MAGIC");
        };
        assert_eq!(&prefix[..], &MAINNET_MAGIC[..]);

        // Replay prefix + stream and verify full v1 message bytes are intact
        let mut combined = replay_v1_stream(prefix, stream);
        let mut recovered = vec![0u8; raw_v1_bytes.len()];
        combined.read_exact(&mut recovered).await.unwrap();
        assert_eq!(recovered, raw_v1_bytes);
    }
}
