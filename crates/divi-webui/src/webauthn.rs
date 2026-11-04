// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Server-side WebAuthn registration and P-256 ECDSA assertion verification,
//! plus base64url and 32-byte PRF input helpers shared with the wallet slots.

use std::io::Cursor;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ciborium::Value as CborValue;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use parking_lot::Mutex;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{constant_time_eq, AdminPasskey};

/// Active WebAuthn challenges kept at once; oldest goes when full
const MAX_CHALLENGES: usize = 32;
/// How long a browser has to finish a registration or sign-in ceremony
const CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// Largest CBOR attestation object accepted
const MAX_ATTESTATION_BYTES: usize = 16 * 1024;
/// WebAuthn authenticatorData flag bits
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(text: &str) -> Result<Vec<u8>, String> {
    let trimmed = text.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|_| "invalid base64url data".to_string())
}

/// Decode a 32-byte base64url secret (such as a WebAuthn PRF output) into a
/// zeroizing buffer, refusing empty or all-zero material.
pub fn decode_prf_secret(b64: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut raw = Zeroizing::new(b64url_decode(b64)?);
    if raw.len() != 32 {
        return Err("passkey PRF output must be 32 bytes".into());
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    raw.zeroize();
    if constant_time_eq(&out[..], &[0u8; 32]) {
        return Err("passkey PRF output is empty".into());
    }
    Ok(out)
}

/// Decode a 32-byte base64url salt used for WebAuthn PRF evaluation.
pub fn decode_prf_salt(b64: &str) -> Result<[u8; 32], String> {
    let raw = b64url_decode(b64)?;
    if raw.len() != 32 {
        return Err("passkey PRF salt must be 32 bytes".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Extract a valid WebAuthn Relying Party ID from a verified `Host` header.
/// Browsers forbid IP addresses as WebAuthn RP IDs (`127.0.0.1`, `[::1]`),
/// requiring `localhost` or a domain name.
pub fn rp_id_from_host(host: &str) -> Result<String, String> {
    let host = host.trim().to_lowercase();
    if host.starts_with('[') {
        return Err(
            "passkeys require localhost or a domain name, not an IP address; open http://localhost instead"
                .into(),
        );
    }
    let name = match host.rsplit_once(':') {
        Some((h, _port)) => h,
        None => host.as_str(),
    };
    if name.is_empty() || name.parse::<IpAddr>().is_ok() {
        return Err(
            "passkeys require localhost or a domain name, not an IP address; open http://localhost instead"
                .into(),
        );
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err("invalid host name for passkey".into());
    }
    Ok(name.to_string())
}

/// Verify that `clientDataJSON.origin` belongs to an allowed WebUI host and
/// matches `rp_id`. Plain `http://` is permitted only on `localhost`.
pub fn check_origin(origin: &str, rp_id: &str, allowed_hosts: &[String]) -> Result<(), String> {
    let origin = origin.trim().to_lowercase();
    let (https, host_port) = if let Some(rest) = origin.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("unexpected WebAuthn origin scheme".into());
    };
    if host_port.is_empty() || host_port.contains('/') {
        return Err("unexpected WebAuthn origin".into());
    }
    let host_allowed = allowed_hosts.iter().any(|h| h == host_port)
        || (!https && !host_port.contains(':') && allowed_hosts.contains(&format!("{host_port}:80")))
        || (https
            && !host_port.contains(':')
            && allowed_hosts.contains(&format!("{host_port}:443")));
    if !host_allowed {
        return Err("WebAuthn origin is not an allowed host of this interface".into());
    }
    let origin_rp = rp_id_from_host(host_port)?;
    if !https && origin_rp != "localhost" {
        return Err("passkeys over HTTP are allowed on localhost only; use HTTPS".into());
    }
    if origin_rp != rp_id {
        return Err("WebAuthn origin does not match the relying party".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    Register { label: String },
    Login,
}

#[derive(Debug, Clone)]
struct PendingChallenge {
    challenge: [u8; 32],
    purpose: Purpose,
    rp_id: String,
    created: Instant,
}

/// Short-lived, single-use WebAuthn challenges bound to ceremony purpose and RP ID.
#[derive(Default)]
pub struct ChallengeStore {
    list: Mutex<Vec<PendingChallenge>>,
}

impl ChallengeStore {
    pub fn issue(&self, purpose: Purpose, rp_id: String) -> String {
        let mut challenge = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        let now = Instant::now();
        let mut list = self.list.lock();
        list.retain(|c| now.duration_since(c.created) < CHALLENGE_TTL);
        while list.len() >= MAX_CHALLENGES {
            list.remove(0);
        }
        list.push(PendingChallenge {
            challenge,
            purpose,
            rp_id,
            created: now,
        });
        b64url_encode(&challenge)
    }

    fn consume_register(&self, challenge: &[u8]) -> Result<(String, String), String> {
        let now = Instant::now();
        let mut list = self.list.lock();
        list.retain(|c| now.duration_since(c.created) < CHALLENGE_TTL);
        let pos = list.iter().position(|c| {
            matches!(c.purpose, Purpose::Register { .. })
                && constant_time_eq(&c.challenge, challenge)
        });
        match pos {
            Some(i) => {
                let item = list.remove(i);
                match item.purpose {
                    Purpose::Register { label } => Ok((item.rp_id, label)),
                    Purpose::Login => unreachable!(),
                }
            }
            None => Err("passkey challenge expired or already used; try again".into()),
        }
    }

    fn consume_login(&self, challenge: &[u8]) -> Result<String, String> {
        let now = Instant::now();
        let mut list = self.list.lock();
        list.retain(|c| now.duration_since(c.created) < CHALLENGE_TTL);
        let pos = list
            .iter()
            .position(|c| c.purpose == Purpose::Login && constant_time_eq(&c.challenge, challenge));
        match pos {
            Some(i) => Ok(list.remove(i).rp_id),
            None => Err("passkey challenge expired or already used; try again".into()),
        }
    }
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct VerifiedRegistration {
    pub label: String,
    pub credential_id_b64url: String,
    pub public_key_sec1_hex: String,
    pub rp_id: String,
    pub sign_count: u32,
}

fn cbor_int(v: &CborValue) -> Option<i64> {
    match v {
        CborValue::Integer(i) => i128::from(*i).try_into().ok(),
        _ => None,
    }
}

fn cbor_bytes(v: &CborValue) -> Option<&[u8]> {
    match v {
        CborValue::Bytes(b) => Some(b.as_slice()),
        _ => None,
    }
}

fn cbor_text(v: &CborValue) -> Option<&str> {
    match v {
        CborValue::Text(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Extract the uncompressed SEC1 P-256 public key (`0x04 || x || y`) from a
/// CBOR COSE_Key map (`kty = 2` EC2, `alg = -7` ES256, `crv = 1` P-256).
fn parse_cose_p256_key(bytes: &[u8]) -> Result<[u8; 65], String> {
    let mut cursor = Cursor::new(bytes);
    let cose: CborValue = ciborium::from_reader(&mut cursor)
        .map_err(|_| "cannot parse passkey COSE public key".to_string())?;
    let CborValue::Map(entries) = cose else {
        return Err("passkey public key is not a COSE map".into());
    };
    let find = |key: i64| -> Option<&CborValue> {
        entries
            .iter()
            .find(|(k, _)| cbor_int(k) == Some(key))
            .map(|(_, v)| v)
    };
    if find(1).and_then(cbor_int) != Some(2) {
        return Err("unsupported passkey key type (expected EC2)".into());
    }
    if find(3).and_then(cbor_int) != Some(-7) {
        return Err("unsupported passkey algorithm (expected ES256)".into());
    }
    if find(-1).and_then(cbor_int) != Some(1) {
        return Err("unsupported passkey curve (expected P-256)".into());
    }
    let x = find(-2)
        .and_then(cbor_bytes)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| "invalid P-256 x coordinate in passkey".to_string())?;
    let y = find(-3)
        .and_then(cbor_bytes)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| "invalid P-256 y coordinate in passkey".to_string())?;
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..65].copy_from_slice(y);
    VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| "passkey P-256 public key is not on the curve".to_string())?;
    Ok(sec1)
}

/// Verify a WebAuthn `navigator.credentials.create` response and extract the
/// attested P-256 public key and credential ID.
pub fn verify_registration(
    challenges: &ChallengeStore,
    allowed_hosts: &[String],
    client_data_b64: &str,
    attestation_object_b64: &str,
) -> Result<VerifiedRegistration, String> {
    let client_data_raw = b64url_decode(client_data_b64)?;
    let client_data: ClientData = serde_json::from_slice(&client_data_raw)
        .map_err(|_| "invalid WebAuthn clientDataJSON".to_string())?;
    if client_data.kind != "webauthn.create" {
        return Err("unexpected WebAuthn ceremony type".into());
    }
    if client_data.cross_origin == Some(true) {
        return Err("cross-origin WebAuthn registration refused".into());
    }
    let challenge = b64url_decode(&client_data.challenge)?;
    if challenge.len() != 32 {
        return Err("invalid WebAuthn challenge".into());
    }
    let (rp_id, label) = challenges.consume_register(&challenge)?;
    check_origin(&client_data.origin, &rp_id, allowed_hosts)?;

    let att_raw = b64url_decode(attestation_object_b64)?;
    if att_raw.len() > MAX_ATTESTATION_BYTES {
        return Err("attestation object too large".into());
    }
    let att: CborValue = ciborium::from_reader(Cursor::new(&att_raw))
        .map_err(|_| "invalid CBOR attestationObject".to_string())?;
    let CborValue::Map(att_map) = att else {
        return Err("attestationObject is not a CBOR map".into());
    };
    let auth_data = att_map
        .iter()
        .find(|(k, _)| cbor_text(k) == Some("authData"))
        .and_then(|(_, v)| cbor_bytes(v))
        .ok_or_else(|| "attestationObject missing authData".to_string())?;

    if auth_data.len() < 55 {
        return Err("authenticatorData too short".into());
    }
    let expected_rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if !constant_time_eq(&auth_data[..32], &expected_rp_hash) {
        return Err("passkey rpIdHash mismatch".into());
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 {
        return Err("passkey user presence flag missing".into());
    }
    if flags & FLAG_UV == 0 {
        return Err("passkey user verification required".into());
    }
    if flags & FLAG_AT == 0 {
        return Err("passkey attested credential data missing".into());
    }
    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if cred_len == 0 || cred_len > 1023 || auth_data.len() <= 55 + cred_len {
        return Err("invalid passkey credential ID length".into());
    }
    let credential_id = &auth_data[55..55 + cred_len];
    let sec1 = parse_cose_p256_key(&auth_data[55 + cred_len..])?;

    Ok(VerifiedRegistration {
        label,
        credential_id_b64url: b64url_encode(credential_id),
        public_key_sec1_hex: hex::encode(sec1),
        rp_id,
        sign_count,
    })
}

/// Verify a WebAuthn `navigator.credentials.get` P-256 ECDSA assertion.
/// Consumes the one-time challenge before inspecting the credential so failed
/// or unknown-credential probes cannot replay challenges.
pub fn verify_assertion<'a>(
    challenges: &ChallengeStore,
    allowed_hosts: &[String],
    passkeys: &'a [AdminPasskey],
    credential_id_b64: &str,
    client_data_b64: &str,
    authenticator_data_b64: &str,
    signature_b64: &str,
) -> Result<(&'a AdminPasskey, u32), String> {
    let client_data_raw = b64url_decode(client_data_b64)?;
    let client_data: ClientData = serde_json::from_slice(&client_data_raw)
        .map_err(|_| "invalid WebAuthn clientDataJSON".to_string())?;
    if client_data.kind != "webauthn.get" {
        return Err("unexpected WebAuthn ceremony type".into());
    }
    if client_data.cross_origin == Some(true) {
        return Err("cross-origin WebAuthn assertion refused".into());
    }
    let challenge = b64url_decode(&client_data.challenge)?;
    if challenge.len() != 32 {
        return Err("invalid WebAuthn challenge".into());
    }
    let challenge_rp_id = challenges.consume_login(&challenge)?;

    let cred_raw = b64url_decode(credential_id_b64)?;
    if cred_raw.is_empty() || cred_raw.len() > 1023 {
        return Err("invalid credential ID".into());
    }
    let canonical_cred_id = b64url_encode(&cred_raw);
    let cred = passkeys
        .iter()
        .find(|p| {
            p.rp_id == challenge_rp_id
                && constant_time_eq(
                    p.credential_id_b64url.as_bytes(),
                    canonical_cred_id.as_bytes(),
                )
        })
        .ok_or_else(|| "unknown passkey".to_string())?;

    check_origin(&client_data.origin, &cred.rp_id, allowed_hosts)?;

    let auth_data = b64url_decode(authenticator_data_b64)?;
    if auth_data.len() < 37 {
        return Err("authenticatorData too short".into());
    }
    let expected_rp_hash: [u8; 32] = Sha256::digest(cred.rp_id.as_bytes()).into();
    if !constant_time_eq(&auth_data[..32], &expected_rp_hash) {
        return Err("passkey rpIdHash mismatch".into());
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 {
        return Err("passkey user presence flag missing".into());
    }
    if flags & FLAG_UV == 0 {
        return Err("passkey user verification required".into());
    }
    let new_sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if (cred.sign_count > 0 || new_sign_count > 0) && new_sign_count <= cred.sign_count {
        return Err("passkey signature counter did not advance".into());
    }

    let sec1 = hex::decode(&cred.public_key_sec1_hex)
        .map_err(|_| "stored passkey public key damaged".to_string())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| "stored passkey public key invalid".to_string())?;
    let sig_der = b64url_decode(signature_b64)?;
    let sig =
        Signature::from_der(&sig_der).map_err(|_| "invalid passkey ECDSA signature".to_string())?;
    // WebAuthn authenticators emit both low-S and high-S DER ECDSA signatures.
    let sig = sig.normalize_s().unwrap_or(sig);

    let client_hash = Sha256::digest(&client_data_raw);
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&client_hash);
    verifying_key
        .verify(&signed, &sig)
        .map_err(|_| "passkey signature verification failed".to_string())?;

    Ok((cred, new_sign_count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    fn test_signing_key() -> SigningKey {
        let mut seed = [7u8; 32];
        seed[0] = 0x42;
        SigningKey::from_bytes((&seed).into()).unwrap()
    }

    fn build_attestation(
        sk: &SigningKey,
        rp_id: &str,
        cred_id: &[u8],
        flags: u8,
        sign_count: u32,
        with_ext: bool,
    ) -> String {
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = point.x().unwrap().as_slice();
        let y = point.y().unwrap().as_slice();

        let cose = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
            (CborValue::Integer(3.into()), CborValue::Integer((-7).into())),
            (CborValue::Integer((-1).into()), CborValue::Integer(1.into())),
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(x.to_vec()),
            ),
            (
                CborValue::Integer((-3).into()),
                CborValue::Bytes(y.to_vec()),
            ),
        ]);
        let mut cose_bytes = Vec::new();
        ciborium::into_writer(&cose, &mut cose_bytes).unwrap();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(flags | if with_ext { 0x80 } else { 0 });
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(cred_id);
        auth_data.extend_from_slice(&cose_bytes);
        if with_ext {
            let ext = CborValue::Map(vec![(
                CborValue::Text("prf".into()),
                CborValue::Map(vec![(CborValue::Text("enabled".into()), CborValue::Bool(true))]),
            )]);
            ciborium::into_writer(&ext, &mut auth_data).unwrap();
        }

        let att = CborValue::Map(vec![
            (CborValue::Text("fmt".into()), CborValue::Text("none".into())),
            (CborValue::Text("attStmt".into()), CborValue::Map(vec![])),
            (
                CborValue::Text("authData".into()),
                CborValue::Bytes(auth_data),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&att, &mut out).unwrap();
        b64url_encode(&out)
    }

    #[test]
    fn rp_id_rejects_ip_and_accepts_localhost_or_domain() {
        assert_eq!(rp_id_from_host("localhost:51482").unwrap(), "localhost");
        assert_eq!(rp_id_from_host("Node.Example:8443").unwrap(), "node.example");
        assert!(rp_id_from_host("127.0.0.1:51482").is_err());
        assert!(rp_id_from_host("[::1]:51482").is_err());
    }

    #[test]
    fn registration_and_assertion_round_trip_with_counter_and_replay_protection() {
        let store = ChallengeStore::default();
        let hosts = vec!["localhost:51482".to_string(), "127.0.0.1:51482".to_string()];
        let sk = test_signing_key();
        let cred_id = b"cred-irondivi-admin-1";

        let reg_chal = store.issue(
            Purpose::Register {
                label: "Touch ID".into(),
            },
            "localhost".into(),
        );
        let reg_client = serde_json::json!({
            "type": "webauthn.create",
            "challenge": reg_chal,
            "origin": "http://localhost:51482",
            "crossOrigin": false,
        });
        let reg_client_b64 = b64url_encode(reg_client.to_string().as_bytes());
        let att_b64 = build_attestation(
            &sk,
            "localhost",
            cred_id,
            FLAG_UP | FLAG_UV | FLAG_AT,
            1,
            true,
        );

        let reg = verify_registration(&store, &hosts, &reg_client_b64, &att_b64).unwrap();
        assert_eq!(reg.label, "Touch ID");
        assert_eq!(reg.rp_id, "localhost");
        assert_eq!(reg.sign_count, 1);
        // Replaying the same registration challenge fails
        assert!(verify_registration(&store, &hosts, &reg_client_b64, &att_b64).is_err());

        let stored = vec![AdminPasskey {
            id: "0123456789abcdef".into(),
            label: reg.label,
            credential_id_b64url: reg.credential_id_b64url.clone(),
            public_key_sec1_hex: reg.public_key_sec1_hex,
            rp_id: reg.rp_id,
            sign_count: reg.sign_count,
            created: 1_700_000_000,
        }];

        // Sign valid assertion with sign_count = 2
        let login_chal = store.issue(Purpose::Login, "localhost".into());
        let get_client = serde_json::json!({
            "type": "webauthn.get",
            "challenge": login_chal,
            "origin": "http://localhost:51482",
        });
        let get_client_raw = get_client.to_string().into_bytes();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(b"localhost"));
        auth_data.push(FLAG_UP | FLAG_UV);
        auth_data.extend_from_slice(&2u32.to_be_bytes());

        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&get_client_raw));
        let sig: Signature = sk.sign(&signed);
        let sig_b64 = b64url_encode(sig.to_der().as_bytes());

        let (matched, count) = verify_assertion(
            &store,
            &hosts,
            &stored,
            &reg.credential_id_b64url,
            &b64url_encode(&get_client_raw),
            &b64url_encode(&auth_data),
            &sig_b64,
        )
        .unwrap();
        assert_eq!(matched.id, "0123456789abcdef");
        assert_eq!(count, 2);

        // Replay with same challenge is rejected
        assert!(verify_assertion(
            &store,
            &hosts,
            &stored,
            &reg.credential_id_b64url,
            &b64url_encode(&get_client_raw),
            &b64url_encode(&auth_data),
            &sig_b64,
        )
        .is_err());

        // Stale sign_count (<= 1) with a fresh challenge is rejected
        let login_chal2 = store.issue(Purpose::Login, "localhost".into());
        let get_client2 = serde_json::json!({
            "type": "webauthn.get",
            "challenge": login_chal2,
            "origin": "http://localhost:51482",
        })
        .to_string()
        .into_bytes();
        let mut stale_auth = Vec::new();
        stale_auth.extend_from_slice(&Sha256::digest(b"localhost"));
        stale_auth.push(FLAG_UP | FLAG_UV);
        stale_auth.extend_from_slice(&1u32.to_be_bytes());
        let mut signed2 = stale_auth.clone();
        signed2.extend_from_slice(&Sha256::digest(&get_client2));
        let sig2: Signature = sk.sign(&signed2);
        assert!(verify_assertion(
            &store,
            &hosts,
            &stored,
            &reg.credential_id_b64url,
            &b64url_encode(&get_client2),
            &b64url_encode(&stale_auth),
            &b64url_encode(sig2.to_der().as_bytes()),
        )
        .is_err());
    }

    #[test]
    fn registration_rejects_missing_uv_and_wrong_origin() {
        let store = ChallengeStore::default();
        let hosts = vec!["localhost:51482".to_string(), "node.example".to_string()];
        let sk = test_signing_key();

        // Missing UV flag (only UP | AT)
        let chal = store.issue(
            Purpose::Register {
                label: "Key".into(),
            },
            "localhost".into(),
        );
        let client = b64url_encode(
            serde_json::json!({
                "type": "webauthn.create",
                "challenge": chal,
                "origin": "http://localhost:51482",
            })
            .to_string()
            .as_bytes(),
        );
        let att_no_uv = build_attestation(&sk, "localhost", b"id1", FLAG_UP | FLAG_AT, 0, false);
        assert!(verify_registration(&store, &hosts, &client, &att_no_uv).is_err());

        // Plain HTTP on non-localhost domain is rejected
        let chal2 = store.issue(
            Purpose::Register {
                label: "Key".into(),
            },
            "node.example".into(),
        );
        let client_http_remote = b64url_encode(
            serde_json::json!({
                "type": "webauthn.create",
                "challenge": chal2,
                "origin": "http://node.example",
            })
            .to_string()
            .as_bytes(),
        );
        let att_remote = build_attestation(
            &sk,
            "node.example",
            b"id2",
            FLAG_UP | FLAG_UV | FLAG_AT,
            0,
            false,
        );
        assert!(verify_registration(&store, &hosts, &client_http_remote, &att_remote).is_err());
    }
}
