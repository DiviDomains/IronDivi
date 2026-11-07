// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Phase 0 (`P0.2`) Hybrid Post-Quantum TLS 1.3 (`X25519MLKEM768`) configuration
//! and crypto-provider helpers for IronDivi's TLS endpoints (`-electrumtls`,
//! `-electrumwss`, and outbound TLS clients).
//!
//! # Workspace `rustls 0.23.46` Inspection Summary
//!
//! - `crates/divi-electrum`: terminates `-electrumtls` and `-electrumwss` via
//!   `tokio-rustls 0.26` + `rustls 0.23.46` (`features = ["ring", "std", "tls12", "logging"]`).
//!   Using `ring` keeps release builds free of a C/CMake toolchain (`aws-lc-sys`),
//!   while this module equips the `ring` `CryptoProvider` with an IETF
//!   [`X25519MLKEM768`] (`NamedGroup::X25519MLKEM768` = `0x11ec`) hybrid
//!   post-quantum key-exchange implementation backed by pure-Rust NIST FIPS 203
//!   `ML-KEM-768` + `ring` `X25519`.
//! - `bin/irondivid`: delegates `-electrumtls` and `-electrumwss` listener setup
//!   to [`crate::prepare`] and exercises TLS/WSS handshakes in `tests/electrum.rs`.
//! - `crates/divi-webui` & `crates/divi-diag`: use `reqwest 0.12` (`rustls-tls`),
//!   which consumes the process-default `rustls::crypto::CryptoProvider` when
//!   installed via [`install_default_crypto_provider`].
//!
//! # Key-Exchange Policy & Classical Fallback
//!
//! Under [`TlsKxPolicy::HybridPostQuantumPreferred`] (the default), the provider
//! advertises key-exchange groups in priority order:
//!
//! 1. [`X25519MLKEM768`] (`NamedGroup::X25519MLKEM768`, `0x11ec`) — TLS 1.3 only,
//!    with `ActiveKeyExchange::hybrid_component()` returning the classical
//!    `X25519` share so TLS 1.3 clients send both hybrid and classical key shares
//!    in the initial `ClientHello` (zero `HelloRetryRequest` round-trip penalty
//!    when connecting to classical-only servers).
//! 2. `X25519` (`NamedGroup::X25519`, `0x001d`) — classical ECDHE fallback for
//!    existing Electrum/RPC TLS 1.3 and TLS 1.2 clients.
//! 3. `SECP256R1` (`NamedGroup::secp256r1`, `0x0017`) — NIST P-256 fallback.
//! 4. `SECP384R1` (`NamedGroup::secp384r1`, `0x0018`) — NIST P-384 fallback.

use std::sync::Arc;

use anyhow::Context;
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{CipherSuite, ClientConfig, Error as TlsError, NamedGroup, PeerMisbehaved};
use rustls::{ProtocolVersion, ServerConfig};

/// IETF `draft-ietf-tls-ecdhe-mlkem` sizes for `X25519MLKEM768` (`0x11ec`).
pub const X25519_LEN: usize = 32;
pub const MLKEM768_ENCAP_LEN: usize = 1184;
pub const MLKEM768_DECAP_LEN: usize = 2400;
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
pub const MLKEM768_SECRET_LEN: usize = 32;
pub const X25519MLKEM768_CLIENT_SHARE_LEN: usize = MLKEM768_ENCAP_LEN + X25519_LEN;
pub const X25519MLKEM768_SERVER_SHARE_LEN: usize = MLKEM768_CIPHERTEXT_LEN + X25519_LEN;
pub const X25519MLKEM768_COMBINED_SECRET_LEN: usize = MLKEM768_SECRET_LEN + X25519_LEN;

const INVALID_KEY_SHARE: TlsError = TlsError::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// Policy controlling which TLS key-exchange groups are offered and accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsKxPolicy {
    /// Prefer `X25519MLKEM768` (`0x11ec`) in TLS 1.3 while retaining classical
    /// `X25519`, `SECP256R1`, and `SECP384R1` fallback for legacy clients.
    #[default]
    HybridPostQuantumPreferred,
    /// Require hybrid post-quantum `X25519MLKEM768` (`0x11ec`) in TLS 1.3 only.
    HybridPostQuantumOnly,
    /// Offer only classical ECDHE groups (`X25519`, `SECP256R1`, `SECP384R1`).
    ClassicalOnly,
}

/// Hybrid post-quantum `X25519MLKEM768` (`0x11ec`) key-exchange group for `rustls`.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &HybridX25519MlKem768;

/// Builds the default IronDivi `rustls` [`CryptoProvider`] with
/// [`TlsKxPolicy::HybridPostQuantumPreferred`].
pub fn crypto_provider() -> Arc<CryptoProvider> {
    crypto_provider_with_policy(TlsKxPolicy::HybridPostQuantumPreferred)
}

/// Builds a `rustls` [`CryptoProvider`] configured for `policy`.
///
/// Cipher suites prioritize TLS 1.3 AEAD suites (`TLS13_AES_256_GCM_SHA384`,
/// `TLS13_CHACHA20_POLY1305_SHA256`, `TLS13_AES_128_GCM_SHA256`) ahead of
/// TLS 1.2 ECDHE suites for backward compatibility.
pub fn crypto_provider_with_policy(policy: TlsKxPolicy) -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    use rustls::crypto::ring::cipher_suite;
    provider.cipher_suites = vec![
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];

    use rustls::crypto::ring::kx_group::{SECP256R1, SECP384R1, X25519};
    provider.kx_groups = match policy {
        TlsKxPolicy::HybridPostQuantumPreferred => {
            vec![X25519MLKEM768, X25519, SECP256R1, SECP384R1]
        }
        TlsKxPolicy::HybridPostQuantumOnly => vec![X25519MLKEM768],
        TlsKxPolicy::ClassicalOnly => vec![X25519, SECP256R1, SECP384R1],
    };

    Arc::new(provider)
}

/// Installs the hybrid post-quantum [`CryptoProvider`] as the process-wide
/// `rustls` default if none has been installed yet. Returns `true` if a default
/// provider is active after this call.
pub fn install_default_crypto_provider() -> bool {
    if CryptoProvider::get_default().is_none() {
        let _ = CryptoProvider::install_default(
            (*crypto_provider_with_policy(TlsKxPolicy::HybridPostQuantumPreferred)).clone(),
        );
    }
    CryptoProvider::get_default().is_some()
}

/// Returns the ordered list of [`NamedGroup`] identifiers configured on `provider`.
pub fn supported_kx_groups(provider: &CryptoProvider) -> Vec<NamedGroup> {
    provider.kx_groups.iter().map(|g| g.name()).collect()
}

/// Returns `true` if `provider` advertises hybrid post-quantum `X25519MLKEM768`.
pub fn supports_hybrid_pq_kx(provider: &CryptoProvider) -> bool {
    provider
        .kx_groups
        .iter()
        .any(|g| g.name() == NamedGroup::X25519MLKEM768)
}

/// Returns the TLS 1.3 cipher suites configured on `provider`.
pub fn tls13_cipher_suites(provider: &CryptoProvider) -> Vec<CipherSuite> {
    provider
        .cipher_suites
        .iter()
        .filter(|cs| cs.version() == &rustls::version::TLS13)
        .map(|cs| cs.suite())
        .collect()
}

/// Builds a `rustls` [`ServerConfig`] with [`TlsKxPolicy::HybridPostQuantumPreferred`].
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<ServerConfig> {
    server_config_with_policy(certs, key, TlsKxPolicy::HybridPostQuantumPreferred)
}

/// Builds a `rustls` [`ServerConfig`] with the specified [`TlsKxPolicy`].
pub fn server_config_with_policy(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    policy: TlsKxPolicy,
) -> anyhow::Result<ServerConfig> {
    let _ = install_default_crypto_provider();
    let provider = crypto_provider_with_policy(policy);
    let versions: &[&rustls::SupportedProtocolVersion] = match policy {
        TlsKxPolicy::HybridPostQuantumOnly => &[&rustls::version::TLS13],
        TlsKxPolicy::HybridPostQuantumPreferred | TlsKxPolicy::ClassicalOnly => {
            rustls::DEFAULT_VERSIONS
        }
    };
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .context("electrum: invalid TLS protocol version configuration")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("electrum: the TLS certificate and key do not match")
}

/// Builds a `rustls` [`ClientConfig`] trusting `roots` with
/// [`TlsKxPolicy::HybridPostQuantumPreferred`].
pub fn client_config(roots: rustls::RootCertStore) -> anyhow::Result<ClientConfig> {
    client_config_with_policy(roots, TlsKxPolicy::HybridPostQuantumPreferred)
}

/// Builds a `rustls` [`ClientConfig`] trusting `roots` with the specified [`TlsKxPolicy`].
pub fn client_config_with_policy(
    roots: rustls::RootCertStore,
    policy: TlsKxPolicy,
) -> anyhow::Result<ClientConfig> {
    let _ = install_default_crypto_provider();
    let provider = crypto_provider_with_policy(policy);
    let versions: &[&rustls::SupportedProtocolVersion] = match policy {
        TlsKxPolicy::HybridPostQuantumOnly => &[&rustls::version::TLS13],
        TlsKxPolicy::HybridPostQuantumPreferred | TlsKxPolicy::ClassicalOnly => {
            rustls::DEFAULT_VERSIONS
        }
    };
    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .context("electrum: invalid TLS client protocol versions")?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[derive(Debug)]
struct HybridX25519MlKem768;

impl SupportedKxGroup for HybridX25519MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, TlsError> {
        let classical = rustls::crypto::ring::kx_group::X25519.start()?;
        let mut seed_d = [0u8; 32];
        let mut seed_z = [0u8; 32];
        fill_random(&mut seed_d)?;
        fill_random(&mut seed_z)?;
        let (ek, dk) = mlkem768::keygen_derand(&seed_d, &seed_z);

        let mut combined_pub_key = Vec::with_capacity(X25519MLKEM768_CLIENT_SHARE_LEN);
        combined_pub_key.extend_from_slice(&ek);
        combined_pub_key.extend_from_slice(classical.pub_key());

        Ok(Box::new(ActiveHybridX25519MlKem768 {
            classical,
            dk: Box::new(dk),
            combined_pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, TlsError> {
        if client_share.len() != X25519MLKEM768_CLIENT_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (pq_client_share, classical_client_share) = client_share.split_at(MLKEM768_ENCAP_LEN);

        let mut seed_m = [0u8; 32];
        fill_random(&mut seed_m)?;
        let (pq_ciphertext, pq_secret) =
            mlkem768::encaps_derand(pq_client_share, &seed_m).ok_or(INVALID_KEY_SHARE)?;
        let cl =
            rustls::crypto::ring::kx_group::X25519.start_and_complete(classical_client_share)?;

        let mut combined_pub_key = Vec::with_capacity(X25519MLKEM768_SERVER_SHARE_LEN);
        combined_pub_key.extend_from_slice(&pq_ciphertext);
        combined_pub_key.extend_from_slice(&cl.pub_key);

        let mut combined_secret = Vec::with_capacity(X25519MLKEM768_COMBINED_SECRET_LEN);
        combined_secret.extend_from_slice(&pq_secret);
        combined_secret.extend_from_slice(cl.secret.secret_bytes());

        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key: combined_pub_key,
            secret: SharedSecret::from(combined_secret),
        })
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn fips(&self) -> bool {
        false
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveHybridX25519MlKem768 {
    classical: Box<dyn ActiveKeyExchange>,
    dk: Box<[u8; MLKEM768_DECAP_LEN]>,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveHybridX25519MlKem768 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, TlsError> {
        if peer_pub_key.len() != X25519MLKEM768_SERVER_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (pq_server_share, classical_server_share) =
            peer_pub_key.split_at(MLKEM768_CIPHERTEXT_LEN);

        let cl_secret = self.classical.complete(classical_server_share)?;
        let pq_secret = mlkem768::decaps(&self.dk[..], pq_server_share).ok_or(INVALID_KEY_SHARE)?;

        let mut combined_secret = Vec::with_capacity(X25519MLKEM768_COMBINED_SECRET_LEN);
        combined_secret.extend_from_slice(&pq_secret);
        combined_secret.extend_from_slice(cl_secret.secret_bytes());

        Ok(SharedSecret::from(combined_secret))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, TlsError> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

fn fill_random(buf: &mut [u8]) -> Result<(), TlsError> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(buf)
        .map_err(|_| TlsError::FailedToGetRandomBytes)
}

/// Pure-Rust NIST FIPS 203 `ML-KEM-768` ($k=3, n=256, q=3329, \eta_1=2, \eta_2=2, d_u=10, d_v=4$).
pub mod mlkem768 {
    use super::{
        MLKEM768_CIPHERTEXT_LEN, MLKEM768_DECAP_LEN, MLKEM768_ENCAP_LEN, MLKEM768_SECRET_LEN,
    };

    const Q: u16 = 3329;
    const K: usize = 3;
    const N: usize = 256;

    const fn bitrev7(x: u8) -> u8 {
        ((x & 1) << 6)
            | (((x >> 1) & 1) << 5)
            | (((x >> 2) & 1) << 4)
            | (((x >> 3) & 1) << 3)
            | (((x >> 4) & 1) << 2)
            | (((x >> 5) & 1) << 1)
            | ((x >> 6) & 1)
    }

    const fn mod_pow(mut base: u32, mut exp: u8) -> u16 {
        let mut acc = 1u32;
        while exp > 0 {
            if (exp & 1) != 0 {
                acc = (acc * base) % (Q as u32);
            }
            base = (base * base) % (Q as u32);
            exp >>= 1;
        }
        acc as u16
    }

    const fn compute_zetas() -> [u16; 128] {
        let mut out = [0u16; 128];
        let mut i = 0usize;
        while i < 128 {
            out[i] = mod_pow(17, bitrev7(i as u8));
            i += 1;
        }
        out
    }

    const ZETAS: [u16; 128] = compute_zetas();

    type Poly = [u16; N];

    fn poly_add(a: &Poly, b: &Poly) -> Poly {
        let mut out = [0u16; N];
        for i in 0..N {
            out[i] = (a[i] + b[i]) % Q;
        }
        out
    }

    fn poly_sub(a: &Poly, b: &Poly) -> Poly {
        let mut out = [0u16; N];
        for i in 0..N {
            out[i] = (a[i] + Q - b[i]) % Q;
        }
        out
    }

    fn ntt(f: &mut Poly) {
        let mut k = 1usize;
        let mut len = 128usize;
        while len >= 2 {
            let mut start = 0usize;
            while start < N {
                let zeta = ZETAS[k] as u32;
                k += 1;
                for j in start..(start + len) {
                    let t = ((zeta * (f[j + len] as u32)) % (Q as u32)) as u16;
                    f[j + len] = (f[j] + Q - t) % Q;
                    f[j] = (f[j] + t) % Q;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    fn inv_ntt(f: &mut Poly) {
        let mut k = 127usize;
        let mut len = 2usize;
        while len <= 128 {
            let mut start = 0usize;
            while start < N {
                let zeta = ZETAS[k] as u32;
                k = k.wrapping_sub(1);
                for j in start..(start + len) {
                    let t = f[j];
                    f[j] = (t + f[j + len]) % Q;
                    let diff = (f[j + len] + Q - t) % Q;
                    f[j + len] = ((zeta * (diff as u32)) % (Q as u32)) as u16;
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        // 128^-1 mod 3329 = 3303
        for coeff in f.iter_mut() {
            *coeff = (((*coeff as u32) * 3303) % (Q as u32)) as u16;
        }
    }

    fn multiply_ntts(f: &Poly, g: &Poly) -> Poly {
        let mut h = [0u16; N];
        for i in 0..128 {
            let base_zeta = ZETAS[64 + (i >> 1)];
            let gamma = if (i & 1) == 0 {
                base_zeta as u32
            } else {
                (Q - base_zeta) as u32
            };
            let a0 = f[2 * i] as u32;
            let a1 = f[2 * i + 1] as u32;
            let b0 = g[2 * i] as u32;
            let b1 = g[2 * i + 1] as u32;
            let c0 = ((a0 * b0) % (Q as u32) + (((a1 * b1) % (Q as u32)) * gamma) % (Q as u32))
                % (Q as u32);
            let c1 = ((a0 * b1) % (Q as u32) + (a1 * b0) % (Q as u32)) % (Q as u32);
            h[2 * i] = c0 as u16;
            h[2 * i + 1] = c1 as u16;
        }
        h
    }

    fn sample_ntt(rho: &[u8; 32], j_col: u8, i_row: u8) -> Poly {
        let mut xof = KeccakSponge::new(168);
        xof.absorb(rho);
        xof.absorb(&[j_col, i_row]);
        xof.finalize(0x1f);

        let mut a = [0u16; N];
        let mut idx = 0usize;
        let mut buf = [0u8; 3];
        while idx < N {
            xof.squeeze(&mut buf);
            let d1 = (buf[0] as u16) | (((buf[1] & 0x0f) as u16) << 8);
            let d2 = ((buf[1] >> 4) as u16) | ((buf[2] as u16) << 4);
            if d1 < Q {
                a[idx] = d1;
                idx += 1;
            }
            if d2 < Q && idx < N {
                a[idx] = d2;
                idx += 1;
            }
        }
        a
    }

    fn sample_cbd2(sigma: &[u8; 32], nonce: u8) -> Poly {
        let mut prf = [0u8; 128];
        let mut sponge = KeccakSponge::new(136);
        sponge.absorb(sigma);
        sponge.absorb(&[nonce]);
        sponge.finalize(0x1f);
        sponge.squeeze(&mut prf);

        let mut f = [0u16; N];
        for i in 0..64 {
            let t = u16::from_le_bytes([prf[2 * i], prf[2 * i + 1]]);
            for j in 0..4 {
                let nibble = (t >> (4 * j)) & 0x0f;
                let a = (nibble & 1) + ((nibble >> 1) & 1);
                let b = ((nibble >> 2) & 1) + ((nibble >> 3) & 1);
                f[4 * i + j] = (a + Q - b) % Q;
            }
        }
        f
    }

    fn byte_encode_12(f: &Poly, out: &mut [u8; 384]) {
        for i in 0..128 {
            let a = f[2 * i];
            let b = f[2 * i + 1];
            out[3 * i] = (a & 0xff) as u8;
            out[3 * i + 1] = (((a >> 8) & 0x0f) | ((b & 0x0f) << 4)) as u8;
            out[3 * i + 2] = (b >> 4) as u8;
        }
    }

    fn byte_decode_12_checked(bytes: &[u8]) -> Option<Poly> {
        if bytes.len() != 384 {
            return None;
        }
        let mut f = [0u16; N];
        for i in 0..128 {
            let b0 = bytes[3 * i] as u16;
            let b1 = bytes[3 * i + 1] as u16;
            let b2 = bytes[3 * i + 2] as u16;
            let a = b0 | ((b1 & 0x0f) << 8);
            let b = (b1 >> 4) | (b2 << 4);
            if a >= Q || b >= Q {
                return None;
            }
            f[2 * i] = a;
            f[2 * i + 1] = b;
        }
        Some(f)
    }

    fn compress(x: u16, d: u32) -> u16 {
        let num = ((x as u64) << d) + ((Q as u64) / 2);
        ((num / (Q as u64)) & ((1u64 << d) - 1)) as u16
    }

    fn decompress(y: u16, d: u32) -> u16 {
        let num = (y as u64) * (Q as u64) + (1u64 << (d - 1));
        (num >> d) as u16
    }

    fn encode_poly_d10(f: &Poly, out: &mut [u8; 320]) {
        for i in 0..64 {
            let c0 = compress(f[4 * i], 10);
            let c1 = compress(f[4 * i + 1], 10);
            let c2 = compress(f[4 * i + 2], 10);
            let c3 = compress(f[4 * i + 3], 10);
            out[5 * i] = (c0 & 0xff) as u8;
            out[5 * i + 1] = (((c0 >> 8) & 0x03) | ((c1 & 0x3f) << 2)) as u8;
            out[5 * i + 2] = (((c1 >> 6) & 0x0f) | ((c2 & 0x0f) << 4)) as u8;
            out[5 * i + 3] = (((c2 >> 4) & 0x3f) | ((c3 & 0x03) << 6)) as u8;
            out[5 * i + 4] = (c3 >> 2) as u8;
        }
    }

    fn decode_poly_d10(bytes: &[u8]) -> Poly {
        let mut f = [0u16; N];
        for i in 0..64 {
            let b0 = bytes[5 * i] as u16;
            let b1 = bytes[5 * i + 1] as u16;
            let b2 = bytes[5 * i + 2] as u16;
            let b3 = bytes[5 * i + 3] as u16;
            let b4 = bytes[5 * i + 4] as u16;
            let c0 = b0 | ((b1 & 0x03) << 8);
            let c1 = (b1 >> 2) | ((b2 & 0x0f) << 6);
            let c2 = (b2 >> 4) | ((b3 & 0x3f) << 4);
            let c3 = (b3 >> 6) | (b4 << 2);
            f[4 * i] = decompress(c0, 10);
            f[4 * i + 1] = decompress(c1, 10);
            f[4 * i + 2] = decompress(c2, 10);
            f[4 * i + 3] = decompress(c3, 10);
        }
        f
    }

    fn encode_poly_d4(f: &Poly, out: &mut [u8; 128]) {
        for i in 0..128 {
            let c0 = compress(f[2 * i], 4) as u8;
            let c1 = compress(f[2 * i + 1], 4) as u8;
            out[i] = (c0 & 0x0f) | ((c1 & 0x0f) << 4);
        }
    }

    fn decode_poly_d4(bytes: &[u8]) -> Poly {
        let mut f = [0u16; N];
        for i in 0..128 {
            let b = bytes[i];
            f[2 * i] = decompress((b & 0x0f) as u16, 4);
            f[2 * i + 1] = decompress((b >> 4) as u16, 4);
        }
        f
    }

    fn decode_msg(m: &[u8; 32]) -> Poly {
        let mut f = [0u16; N];
        for i in 0..32 {
            for b in 0..8 {
                let bit = ((m[i] >> b) & 1) as u16;
                f[8 * i + b] = decompress(bit, 1);
            }
        }
        f
    }

    fn encode_msg(f: &Poly) -> [u8; 32] {
        let mut m = [0u8; 32];
        for i in 0..32 {
            let mut byte = 0u8;
            for b in 0..8 {
                let bit = compress(f[8 * i + b], 1) as u8;
                byte |= (bit & 1) << b;
            }
            m[i] = byte;
        }
        m
    }

    fn sha3_256(data: &[u8]) -> [u8; 32] {
        let mut sponge = KeccakSponge::new(136);
        sponge.absorb(data);
        sponge.finalize(0x06);
        let mut out = [0u8; 32];
        sponge.squeeze(&mut out);
        out
    }

    fn sha3_512_pair(a: &[u8], b: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut sponge = KeccakSponge::new(72);
        sponge.absorb(a);
        sponge.absorb(b);
        sponge.finalize(0x06);
        let mut buf = [0u8; 64];
        sponge.squeeze(&mut buf);
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        left.copy_from_slice(&buf[..32]);
        right.copy_from_slice(&buf[32..]);
        (left, right)
    }

    fn shake256_32(a: &[u8], b: &[u8]) -> [u8; 32] {
        let mut sponge = KeccakSponge::new(136);
        sponge.absorb(a);
        sponge.absorb(b);
        sponge.finalize(0x1f);
        let mut out = [0u8; 32];
        sponge.squeeze(&mut out);
        out
    }

    /// Deterministic `ML-KEM-768.KeyGen_internal(d, z)` (FIPS 203 Algorithm 16).
    pub fn keygen_derand(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> ([u8; MLKEM768_ENCAP_LEN], [u8; MLKEM768_DECAP_LEN]) {
        let (rho, sigma) = sha3_512_pair(d, &[K as u8]);

        let mut a_hat = [[[0u16; N]; K]; K];
        for (i, row) in a_hat.iter_mut().enumerate() {
            for (j, cell) in row.iter_mut().enumerate() {
                *cell = sample_ntt(&rho, j as u8, i as u8);
            }
        }

        let mut s_hat = [[0u16; N]; K];
        let mut e_hat = [[0u16; N]; K];
        for i in 0..K {
            s_hat[i] = sample_cbd2(&sigma, i as u8);
            ntt(&mut s_hat[i]);
            e_hat[i] = sample_cbd2(&sigma, (K + i) as u8);
            ntt(&mut e_hat[i]);
        }

        let mut t_hat = [[0u16; N]; K];
        for i in 0..K {
            let mut acc = e_hat[i];
            for j in 0..K {
                let prod = multiply_ntts(&a_hat[i][j], &s_hat[j]);
                acc = poly_add(&acc, &prod);
            }
            t_hat[i] = acc;
        }

        let mut ek = [0u8; MLKEM768_ENCAP_LEN];
        for i in 0..K {
            let slice: &mut [u8; 384] = (&mut ek[384 * i..384 * (i + 1)]).try_into().unwrap();
            byte_encode_12(&t_hat[i], slice);
        }
        ek[1152..1184].copy_from_slice(&rho);

        let h_ek = sha3_256(&ek);
        let mut dk = [0u8; MLKEM768_DECAP_LEN];
        for i in 0..K {
            let slice: &mut [u8; 384] = (&mut dk[384 * i..384 * (i + 1)]).try_into().unwrap();
            byte_encode_12(&s_hat[i], slice);
        }
        dk[1152..2336].copy_from_slice(&ek);
        dk[2336..2368].copy_from_slice(&h_ek);
        dk[2368..2400].copy_from_slice(z);

        (ek, dk)
    }

    fn kpke_encrypt(
        ek: &[u8],
        m: &[u8; 32],
        r: &[u8; 32],
    ) -> Option<[u8; MLKEM768_CIPHERTEXT_LEN]> {
        if ek.len() != MLKEM768_ENCAP_LEN {
            return None;
        }
        let mut t_hat = [[0u16; N]; K];
        for (i, poly) in t_hat.iter_mut().enumerate() {
            *poly = byte_decode_12_checked(&ek[384 * i..384 * (i + 1)])?;
        }
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&ek[1152..1184]);

        let mut r_hat = [[0u16; N]; K];
        let mut e1 = [[0u16; N]; K];
        for i in 0..K {
            r_hat[i] = sample_cbd2(r, i as u8);
            ntt(&mut r_hat[i]);
            e1[i] = sample_cbd2(r, (K + i) as u8);
        }
        let e2 = sample_cbd2(r, (2 * K) as u8);

        let mut u = [[0u16; N]; K];
        for i in 0..K {
            let mut acc = [0u16; N];
            for (j, r_j) in r_hat.iter().enumerate() {
                // Transpose A_hat[j][i] = SampleNTT(rho, i, j)
                let a_ji = sample_ntt(&rho, i as u8, j as u8);
                let prod = multiply_ntts(&a_ji, r_j);
                acc = poly_add(&acc, &prod);
            }
            inv_ntt(&mut acc);
            u[i] = poly_add(&acc, &e1[i]);
        }

        let mut v_ntt = [0u16; N];
        for i in 0..K {
            let prod = multiply_ntts(&t_hat[i], &r_hat[i]);
            v_ntt = poly_add(&v_ntt, &prod);
        }
        inv_ntt(&mut v_ntt);
        let mu = decode_msg(m);
        let v = poly_add(&poly_add(&v_ntt, &e2), &mu);

        let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
        for i in 0..K {
            let slice: &mut [u8; 320] = (&mut ct[320 * i..320 * (i + 1)]).try_into().unwrap();
            encode_poly_d10(&u[i], slice);
        }
        let v_slice: &mut [u8; 128] = (&mut ct[960..1088]).try_into().unwrap();
        encode_poly_d4(&v, v_slice);

        Some(ct)
    }

    fn kpke_decrypt(dk_pke: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
        if dk_pke.len() != 1152 || ct.len() != MLKEM768_CIPHERTEXT_LEN {
            return None;
        }
        let mut s_hat = [[0u16; N]; K];
        for (i, poly) in s_hat.iter_mut().enumerate() {
            *poly = byte_decode_12_checked(&dk_pke[384 * i..384 * (i + 1)])?;
        }
        let mut u_hat = [[0u16; N]; K];
        for i in 0..K {
            u_hat[i] = decode_poly_d10(&ct[320 * i..320 * (i + 1)]);
            ntt(&mut u_hat[i]);
        }
        let v = decode_poly_d4(&ct[960..1088]);

        let mut s_dot_u = [0u16; N];
        for i in 0..K {
            let prod = multiply_ntts(&s_hat[i], &u_hat[i]);
            s_dot_u = poly_add(&s_dot_u, &prod);
        }
        inv_ntt(&mut s_dot_u);
        let w = poly_sub(&v, &s_dot_u);
        Some(encode_msg(&w))
    }

    /// Deterministic `ML-KEM-768.Encaps_internal(ek, m)` (FIPS 203 Algorithm 17)
    /// including the mandatory §7.2 encapsulation key modulus check.
    pub fn encaps_derand(
        ek: &[u8],
        m: &[u8; 32],
    ) -> Option<([u8; MLKEM768_CIPHERTEXT_LEN], [u8; MLKEM768_SECRET_LEN])> {
        if ek.len() != MLKEM768_ENCAP_LEN {
            return None;
        }
        let h_ek = sha3_256(ek);
        let (k_shared, r_coins) = sha3_512_pair(m, &h_ek);
        let ct = kpke_encrypt(ek, m, &r_coins)?;
        Some((ct, k_shared))
    }

    /// `ML-KEM-768.Decaps_internal(dk, c)` (FIPS 203 Algorithm 18) with constant-time
    /// implicit rejection (`J(z || c)`).
    pub fn decaps(dk: &[u8], ct: &[u8]) -> Option<[u8; MLKEM768_SECRET_LEN]> {
        if dk.len() != MLKEM768_DECAP_LEN || ct.len() != MLKEM768_CIPHERTEXT_LEN {
            return None;
        }
        let dk_pke = &dk[..1152];
        let ek_pke = &dk[1152..2336];
        let h = &dk[2336..2368];
        let z = &dk[2368..2400];

        let m_prime = kpke_decrypt(dk_pke, ct)?;
        let (k_prime, r_prime) = sha3_512_pair(&m_prime, h);
        let k_bar = shake256_32(z, ct);
        let c_prime = kpke_encrypt(ek_pke, &m_prime, &r_prime)?;

        let mut diff = 0u8;
        for (a, b) in ct.iter().zip(c_prime.iter()) {
            diff |= a ^ b;
        }
        // mask is 0x00 if ct == c_prime, 0xff if ct != c_prime
        let mask = ((diff as u16).wrapping_sub(1) >> 8) as u8 ^ 0xff;
        let mut out = [0u8; MLKEM768_SECRET_LEN];
        for i in 0..MLKEM768_SECRET_LEN {
            out[i] = (k_prime[i] & !mask) | (k_bar[i] & mask);
        }
        Some(out)
    }

    const KECCAK_RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    const KECCAK_ROT: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];

    const KECCAK_PILN: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    fn keccak_f1600(st: &mut [u64; 25]) {
        for &rc in &KECCAK_RC {
            let mut bc = [0u64; 5];
            for i in 0..5 {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }
            for i in 0..5 {
                let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
                for j in (0..25).step_by(5) {
                    st[j + i] ^= t;
                }
            }
            let mut t = st[1];
            for i in 0..24 {
                let j = KECCAK_PILN[i];
                let tmp = st[j];
                st[j] = t.rotate_left(KECCAK_ROT[i]);
                t = tmp;
            }
            for j in (0..25).step_by(5) {
                let row = [st[j], st[j + 1], st[j + 2], st[j + 3], st[j + 4]];
                for i in 0..5 {
                    st[j + i] ^= (!row[(i + 1) % 5]) & row[(i + 2) % 5];
                }
            }
            st[0] ^= rc;
        }
    }

    struct KeccakSponge {
        state: [u64; 25],
        rate: usize,
        pos: usize,
    }

    impl KeccakSponge {
        fn new(rate: usize) -> Self {
            Self {
                state: [0u64; 25],
                rate,
                pos: 0,
            }
        }

        fn absorb(&mut self, data: &[u8]) {
            for &b in data {
                let word = self.pos / 8;
                let shift = (self.pos % 8) * 8;
                self.state[word] ^= (b as u64) << shift;
                self.pos += 1;
                if self.pos == self.rate {
                    keccak_f1600(&mut self.state);
                    self.pos = 0;
                }
            }
        }

        fn finalize(&mut self, domain_sep: u8) {
            let word = self.pos / 8;
            let shift = (self.pos % 8) * 8;
            self.state[word] ^= (domain_sep as u64) << shift;
            let last_word = (self.rate - 1) / 8;
            let last_shift = ((self.rate - 1) % 8) * 8;
            self.state[last_word] ^= 0x80u64 << last_shift;
            keccak_f1600(&mut self.state);
            self.pos = 0;
        }

        fn squeeze(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                if self.pos == self.rate {
                    keccak_f1600(&mut self.state);
                    self.pos = 0;
                }
                let word = self.pos / 8;
                let shift = (self.pos % 8) * 8;
                *b = ((self.state[word] >> shift) & 0xff) as u8;
                self.pos += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("bin/irondivid/tests/fixtures/electrum")
    }

    fn load_test_certs_and_roots() -> (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        rustls::RootCertStore,
    ) {
        let dir = fixture_dir();
        let certs = CertificateDer::pem_file_iter(dir.join("cert.pem"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(dir.join("key.pem")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        let ca_bytes = std::fs::read(dir.join("ca.pem")).unwrap();
        for cert in CertificateDer::pem_slice_iter(&ca_bytes) {
            roots.add(cert.unwrap()).unwrap();
        }
        (certs, key, roots)
    }

    fn drive_handshake_and_exchange(
        client_cfg: Arc<ClientConfig>,
        server_cfg: Arc<ServerConfig>,
    ) -> Result<(NamedGroup, ProtocolVersion), TlsError> {
        let mut client =
            rustls::ClientConnection::new(client_cfg, "localhost".try_into().unwrap())?;
        let mut server = rustls::ServerConnection::new(server_cfg)?;

        let mut buf = Vec::new();
        while client.is_handshaking() || server.is_handshaking() {
            buf.clear();
            while client.wants_write() {
                client.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                let mut slice = &buf[..];
                while !slice.is_empty() {
                    server.read_tls(&mut slice).unwrap();
                    server.process_new_packets()?;
                }
            }

            buf.clear();
            while server.wants_write() {
                server.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                let mut slice = &buf[..];
                while !slice.is_empty() {
                    client.read_tls(&mut slice).unwrap();
                    client.process_new_packets()?;
                }
            }
        }

        // Verify bidirectional encrypted application data over the session
        client
            .writer()
            .write_all(b"{\"id\":1,\"method\":\"server.version\"}\n")
            .unwrap();
        buf.clear();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut &buf[..]).unwrap();
        server.process_new_packets()?;
        let mut received = [0u8; 35];
        server.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, b"{\"id\":1,\"method\":\"server.version\"}\n");

        let client_kx = client.negotiated_key_exchange_group().unwrap().name();
        let server_kx = server.negotiated_key_exchange_group().unwrap().name();
        assert_eq!(client_kx, server_kx);
        let proto = client.protocol_version().unwrap();
        assert_eq!(Some(proto), server.protocol_version());
        Ok((client_kx, proto))
    }

    #[test]
    fn provider_inspects_hybrid_pq_kx_and_tls13_cipher_suites() {
        let provider = crypto_provider();
        assert!(supports_hybrid_pq_kx(&provider));
        let groups = supported_kx_groups(&provider);
        assert_eq!(
            groups,
            vec![
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1,
            ]
        );
        let suites = tls13_cipher_suites(&provider);
        assert_eq!(
            suites,
            vec![
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
            ]
        );
        assert!(install_default_crypto_provider());
    }

    #[test]
    fn mlkem768_round_trip_implicit_rejection_and_modulus_check() {
        let d = [0x42u8; 32];
        let z = [0x99u8; 32];
        let m = [0x5au8; 32];
        let (ek, dk) = mlkem768::keygen_derand(&d, &z);
        let (ct, ss_enc) = mlkem768::encaps_derand(&ek, &m).expect("valid ek must encapsulate");
        let ss_dec = mlkem768::decaps(&dk, &ct).expect("valid ct must decapsulate");
        assert_eq!(ss_enc, ss_dec);

        // Tampering with ciphertext triggers FIPS 203 implicit rejection (different secret, no panic)
        let mut tampered_ct = ct;
        tampered_ct[0] ^= 0x01;
        let ss_rejected = mlkem768::decaps(&dk, &tampered_ct).unwrap();
        assert_ne!(ss_enc, ss_rejected);

        // Out-of-range polynomial coefficient (>= 3329) in encapsulation key is rejected
        let mut bad_ek = ek;
        bad_ek[0] = 0xff;
        bad_ek[1] = (bad_ek[1] & 0xf0) | 0x0f; // 0x0fff = 4095 >= 3329
        assert!(mlkem768::encaps_derand(&bad_ek, &m).is_none());
    }

    #[test]
    fn tls13_negotiates_x25519_mlkem768_when_both_endpoints_support_it() {
        let (certs, key, roots) = load_test_certs_and_roots();
        let server_cfg = Arc::new(
            server_config_with_policy(certs, key, TlsKxPolicy::HybridPostQuantumPreferred).unwrap(),
        );
        let client_cfg = Arc::new(
            client_config_with_policy(roots, TlsKxPolicy::HybridPostQuantumPreferred).unwrap(),
        );
        let (kx, proto) = drive_handshake_and_exchange(client_cfg, server_cfg).unwrap();
        assert_eq!(proto, ProtocolVersion::TLSv1_3);
        assert_eq!(kx, NamedGroup::X25519MLKEM768);
    }

    #[test]
    fn tls13_falls_back_to_classical_x25519_for_older_clients() {
        let (certs, key, roots) = load_test_certs_and_roots();
        let server_cfg = Arc::new(
            server_config_with_policy(certs, key, TlsKxPolicy::HybridPostQuantumPreferred).unwrap(),
        );
        let classical_client_cfg =
            Arc::new(client_config_with_policy(roots, TlsKxPolicy::ClassicalOnly).unwrap());
        let (kx, proto) = drive_handshake_and_exchange(classical_client_cfg, server_cfg).unwrap();
        assert_eq!(proto, ProtocolVersion::TLSv1_3);
        assert_eq!(kx, NamedGroup::X25519);
    }

    #[test]
    fn tls13_hybrid_client_falls_back_to_classical_x25519_server_without_hrr() {
        let (certs, key, roots) = load_test_certs_and_roots();
        let classical_server_cfg =
            Arc::new(server_config_with_policy(certs, key, TlsKxPolicy::ClassicalOnly).unwrap());
        let hybrid_client_cfg = Arc::new(
            client_config_with_policy(roots, TlsKxPolicy::HybridPostQuantumPreferred).unwrap(),
        );
        let (kx, proto) =
            drive_handshake_and_exchange(hybrid_client_cfg, classical_server_cfg).unwrap();
        assert_eq!(proto, ProtocolVersion::TLSv1_3);
        assert_eq!(kx, NamedGroup::X25519);
    }

    #[test]
    fn strict_hybrid_pq_only_rejects_classical_only_client() {
        let (certs, key, roots) = load_test_certs_and_roots();
        let strict_server_cfg = Arc::new(
            server_config_with_policy(certs, key, TlsKxPolicy::HybridPostQuantumOnly).unwrap(),
        );
        let classical_client_cfg =
            Arc::new(client_config_with_policy(roots, TlsKxPolicy::ClassicalOnly).unwrap());
        assert!(drive_handshake_and_exchange(classical_client_cfg, strict_server_cfg).is_err());
    }
}
