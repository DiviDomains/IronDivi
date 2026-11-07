// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Optional WebAuthn PRF wrapper (`<datadir>/webui-node-passkey.json`, mode
//! `0600`) for sealing the node's `wallet.dat` passphrase without altering
//! `crates/divi-wallet` or the `wallet.dat` file format.

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{clean_label, random_hex, write_private};
use crate::webauthn::{
    b64url_decode, b64url_encode, decode_prf_salt, decode_prf_secret, rp_id_from_host,
};

pub const NODE_PASSKEY_FILE: &str = "webui-node-passkey.json";
const MAX_NODE_SLOTS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodePasskeyFile {
    version: u32,
    slots: Vec<NodePasskeySlot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePasskeySlot {
    pub id: String,
    pub label: String,
    pub credential_id: String,
    pub prf_salt: String,
    pub rp_id: String,
    /// Hex: 24-byte XNonce || XChaCha20Poly1305(passphrase)
    pub sealed_passphrase: String,
    pub created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodePasskeySummary {
    pub id: String,
    pub label: String,
    pub credential_id: String,
    pub prf_salt: String,
    pub rp_id: String,
    pub created: u64,
}

impl From<&NodePasskeySlot> for NodePasskeySummary {
    fn from(s: &NodePasskeySlot) -> Self {
        NodePasskeySummary {
            id: s.id.clone(),
            label: s.label.clone(),
            credential_id: s.credential_id.clone(),
            prf_salt: s.prf_salt.clone(),
            rp_id: s.rp_id.clone(),
            created: s.created,
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn slot_aad(slot_id: &str) -> String {
    format!("irondivi-webui-node-wallet/1/slot/{slot_id}")
}

fn derive_slot_key(
    slot_id: &str,
    prf_salt: &[u8; 32],
    prf_output: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let hk = Hkdf::<Sha256>::new(Some(prf_salt), prf_output);
    let info = slot_aad(slot_id);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), &mut key[..])
        .map_err(|_| "passkey HKDF expansion failed".to_string())?;
    Ok(key)
}

pub struct NodePasskeyStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl NodePasskeyStore {
    pub fn new(data_dir: &Path) -> Self {
        NodePasskeyStore {
            path: data_dir.join(NODE_PASSKEY_FILE),
            lock: Mutex::new(()),
        }
    }

    fn read_unlocked(&self) -> Result<NodePasskeyFile, String> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let file: NodePasskeyFile = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("{} unreadable: {e}", self.path.display()))?;
                if file.version != 1 {
                    return Err("unsupported node passkey file version".into());
                }
                Ok(file)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(NodePasskeyFile {
                version: 1,
                slots: Vec::new(),
            }),
            Err(e) => Err(format!("cannot read {}: {e}", self.path.display())),
        }
    }

    fn write_unlocked(&self, file: &NodePasskeyFile) -> Result<(), String> {
        if file.slots.is_empty() {
            match std::fs::remove_file(&self.path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(format!("cannot remove {}: {e}", self.path.display())),
            }
        }
        let text = serde_json::to_vec_pretty(file).map_err(|e| e.to_string())?;
        write_private(&self.path, &text)
            .map_err(|e| format!("cannot write {}: {e}", self.path.display()))
    }

    pub fn list(&self) -> Vec<NodePasskeySummary> {
        let _g = self.lock.lock();
        self.read_unlocked()
            .map(|f| f.slots.iter().map(NodePasskeySummary::from).collect())
            .unwrap_or_default()
    }

    /// Seal a verified node wallet passphrase under a new WebAuthn PRF slot.
    pub fn enroll(
        &self,
        passphrase: &str,
        label: &str,
        credential_id_b64: &str,
        prf_salt_b64: &str,
        rp_id: &str,
        prf_output_b64: &str,
    ) -> Result<NodePasskeySummary, String> {
        if passphrase.is_empty() {
            return Err("enter the wallet passphrase".into());
        }
        let label = clean_label(label, "Passkey")?;
        let rp_id = rp_id_from_host(rp_id)?;
        let cred_raw = b64url_decode(credential_id_b64)?;
        if cred_raw.is_empty() || cred_raw.len() > 1023 {
            return Err("invalid passkey credential ID".into());
        }
        let credential_id = b64url_encode(&cred_raw);
        let prf_salt = decode_prf_salt(prf_salt_b64)?;
        let prf_output = decode_prf_secret(prf_output_b64)?;

        let slot_id = random_hex(8);
        let key = derive_slot_key(&slot_id, &prf_salt, &prf_output)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = slot_aad(&slot_id);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: passphrase.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| "failed to seal wallet passphrase".to_string())?;
        let mut out = Vec::with_capacity(24 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        let _g = self.lock.lock();
        let mut file = self.read_unlocked()?;
        if file.slots.len() >= MAX_NODE_SLOTS {
            return Err(format!(
                "at most {MAX_NODE_SLOTS} node passkeys may be added"
            ));
        }
        if file.slots.iter().any(|s| s.credential_id == credential_id) {
            return Err("that passkey is already enrolled for the node wallet".into());
        }
        let slot = NodePasskeySlot {
            id: slot_id,
            label,
            credential_id,
            prf_salt: b64url_encode(&prf_salt),
            rp_id,
            sealed_passphrase: hex::encode(out),
            created: unix_now(),
        };
        let summary = NodePasskeySummary::from(&slot);
        file.slots.push(slot);
        self.write_unlocked(&file)?;
        Ok(summary)
    }

    /// Unwrap the node's `wallet.dat` passphrase into a `Zeroizing<String>`.
    pub fn unwrap(&self, slot_id: &str, prf_output_b64: &str) -> Result<Zeroizing<String>, String> {
        let prf_output = decode_prf_secret(prf_output_b64)?;
        let slot = {
            let _g = self.lock.lock();
            let file = self.read_unlocked()?;
            file.slots
                .into_iter()
                .find(|s| s.id == slot_id)
                .ok_or_else(|| "no such node wallet passkey".to_string())?
        };
        let prf_salt = decode_prf_salt(&slot.prf_salt)?;
        let sealed =
            hex::decode(&slot.sealed_passphrase).map_err(|_| "node passkey file damaged")?;
        if sealed.len() < 24 + 16 {
            return Err("node passkey file damaged".into());
        }
        let key = derive_slot_key(&slot.id, &prf_salt, &prf_output)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
        let (nonce, body) = sealed.split_at(24);
        let aad = slot_aad(&slot.id);
        let mut plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: body,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| "passkey did not unlock this wallet".to_string())?,
        );
        let text = std::str::from_utf8(&plain)
            .map(|s| Zeroizing::new(s.to_string()))
            .map_err(|_| "node passkey file damaged".to_string());
        plain.zeroize();
        text
    }

    pub fn remove(&self, slot_id: &str) -> Result<bool, String> {
        let _g = self.lock.lock();
        let mut file = self.read_unlocked()?;
        let before = file.slots.len();
        file.slots.retain(|s| s.id != slot_id);
        if file.slots.len() == before {
            return Ok(false);
        }
        self.write_unlocked(&file)?;
        Ok(true)
    }

    pub fn clear_all(&self) -> Result<(), String> {
        let _g = self.lock.lock();
        self.write_unlocked(&NodePasskeyFile {
            version: 1,
            slots: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unwrap_and_remove_node_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let store = NodePasskeyStore::new(dir.path());
        assert!(store.list().is_empty());

        let salt = b64url_encode(&[0x11u8; 32]);
        let prf = b64url_encode(&[0x22u8; 32]);
        let wrong_prf = b64url_encode(&[0x33u8; 32]);
        let cred = b64url_encode(b"node-cred-1");

        let summary = store
            .enroll(
                "my-node-wallet-secret",
                "Mac Touch ID",
                &cred,
                &salt,
                "localhost",
                &prf,
            )
            .unwrap();
        assert_eq!(store.list().len(), 1);

        let disk = std::fs::read_to_string(dir.path().join(NODE_PASSKEY_FILE)).unwrap();
        assert!(!disk.contains("my-node-wallet-secret"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(NODE_PASSKEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let opened = store.unwrap(&summary.id, &prf).unwrap();
        assert_eq!(opened.as_str(), "my-node-wallet-secret");
        assert!(store.unwrap(&summary.id, &wrong_prf).is_err());
        assert!(store.unwrap("0000000000000000", &prf).is_err());

        assert!(store.remove(&summary.id).unwrap());
        assert!(store.list().is_empty());
        assert!(!dir.path().join(NODE_PASSKEY_FILE).exists());
    }
}
