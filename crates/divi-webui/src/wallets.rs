// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The interface's own wallets, as many as one likes, beside the node's one
//! wallet. Each is an HD wallet whose recovery words are sealed in
//! `<datadir>/webui-wallets/`. Version 1 seals `Secret` directly under an
//! Argon2id key; Version 2 seals `Secret` under a random 32-byte DEK wrapped
//! by the mandatory Argon2id passphrase slot plus zero or more WebAuthn PRF
//! passkey slots (HKDF-SHA256 + XChaCha20-Poly1305).
//! The addresses are derived when the words are at hand and kept in the clear,
//! so a wallet's balance and history show without its passphrase: they come
//! through the node's Electrum backend (`chainview.rs`), mempool included.
//! The words leave the file only when unlocked, and never pass through the
//! console or `/api/rpc`.

use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::TxOut;
use divi_primitives::ChainMode;
use divi_wallet::send::{
    check_signed, max_script_sig_bytes, plan_send, ChangeKind, FeeMode, FeePolicy, SendCoin,
};
use divi_wallet::signer::create_p2pkh_script_sig;
use divi_wallet::{core_coin_type, sign_input, Address, HdWallet, Network, TransactionBuilder};
use hkdf::Hkdf;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::clean_label;
use crate::webauthn::{
    b64url_decode, b64url_encode, decode_prf_salt, decode_prf_secret, rp_id_from_host,
};

/// Addresses derived on each chain (receive, change) when the words are open;
/// more are derived when a send or a new address needs them
const GAP: u32 = 20;

/// The shortest wallet passphrase taken
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Legacy single-slot file format version
const VERSION_V1: u32 = 1;
/// Current DEK-envelope file format version
const VERSION_V2: u32 = 2;
/// Maximum passkey slots per wallet
const MAX_WALLET_PASSKEYS: usize = 16;

/// Argon2id cost of a wallet's key: 64 MiB, 3 passes
const KDF: Kdf = Kdf {
    m_kib: 64 * 1024,
    t: 3,
    p: 1,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Kdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// Primary Argon2id passphrase wrapper around the v2 32-byte DEK.
/// Every v2 wallet retains this slot so backup files stay portable across
/// machines with the passphrase alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseSlot {
    pub kind: String,
    pub kdf: Kdf,
    /// Hex (16 bytes)
    pub salt: String,
    /// Hex (24-byte XNonce || sealed 32-byte DEK)
    pub sealed_dek: String,
}

/// One WebAuthn PRF wrapper around the v2 32-byte DEK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPasskeySlot {
    pub id: String,
    pub label: String,
    /// Base64url credential ID
    pub credential_id: String,
    /// Base64url 32-byte PRF salt
    pub prf_salt: String,
    pub rp_id: String,
    /// Hex (24-byte XNonce || sealed 32-byte DEK)
    pub sealed_dek: String,
    pub created: u64,
}

/// Public passkey metadata sent to the page (never `sealed_dek`)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletPasskeySummary {
    pub id: String,
    pub label: String,
    pub credential_id: String,
    pub prf_salt: String,
    pub rp_id: String,
    pub created: u64,
}

impl From<&WalletPasskeySlot> for WalletPasskeySummary {
    fn from(s: &WalletPasskeySlot) -> Self {
        WalletPasskeySummary {
            id: s.id.clone(),
            label: s.label.clone(),
            credential_id: s.credential_id.clone(),
            prf_salt: s.prf_salt.clone(),
            rp_id: s.rp_id.clone(),
            created: s.created,
        }
    }
}

/// One wallet as stored, and as its backup file is
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFile {
    pub version: u32,
    pub id: String,
    pub name: String,
    /// Unix seconds
    pub created: u64,
    /// "main", "test" or "regtest": a wallet is used on the network it was made on
    pub network: String,
    pub chain_mode: String,
    pub coin_type: u32,
    pub kdf: Kdf,
    /// Hex (v1 salt, or mirrored primary passphrase salt on v2)
    pub salt: String,
    /// Hex: nonce, then the sealed words and BIP39 passphrase (under Argon2 key
    /// in v1, or under the 32-byte DEK in v2)
    pub sealed: String,
    /// Primary Argon2id DEK slot in v2 wallets
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase_slot: Option<PassphraseSlot>,
    /// Optional WebAuthn PRF DEK slots in v2 wallets
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<WalletPasskeySlot>,
    /// Receiving addresses by index
    pub receive: Vec<String>,
    /// Change addresses by index
    pub change: Vec<String>,
    /// The next receiving address to hand out
    pub next_receive: u32,
    /// The next change address a send takes
    pub next_change: u32,
}

impl WalletFile {
    pub fn passkey_summaries(&self) -> Vec<WalletPasskeySummary> {
        self.passkeys
            .iter()
            .map(WalletPasskeySummary::from)
            .collect()
    }
}

/// Owner proof when opening a wallet: either its passphrase or a WebAuthn PRF
/// evaluation for one of its enrolled passkey slots.
#[derive(Debug, Clone, Copy)]
pub enum WalletAuth<'a> {
    Passphrase(&'a str),
    Passkey {
        slot_id: &'a str,
        prf_output_b64: &'a str,
    },
}

#[derive(Serialize, Deserialize)]
struct Secret {
    words: String,
    bip39_passphrase: Option<String>,
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.words.zeroize();
        if let Some(p) = self.bip39_passphrase.as_mut() {
            p.zeroize();
        }
    }
}

/// The store's errors are sentences for the page
pub type Result<T> = std::result::Result<T, String>;

/// The wallets of this node's data directory
pub struct WalletStore {
    dir: PathBuf,
    network: String,
    chain_mode: String,
    /// One change to the files at a time
    lock: Mutex<()>,
}

/// What a send signs
pub struct SendRequest<'a> {
    pub to: &'a str,
    pub amount: Amount,
    /// Take the fee from the amount
    pub fee_from_amount: bool,
    pub policy: FeePolicy,
}

/// A coin the Electrum backend reports, in a block or in the mempool
#[derive(Debug, Clone)]
pub struct Coin {
    pub address: String,
    pub txid: String,
    pub vout: u32,
    pub value: i64,
    pub script_hex: String,
    pub height: Option<u32>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_id() -> String {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn clean_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err("a wallet name is 1 to 64 characters".into());
    }
    Ok(name.to_string())
}

fn derive_key(kdf: &Kdf, passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).map_err(|e| e.to_string())?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key[..])
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Legacy v1 AAD
fn aad_v1(w: &WalletFile) -> Vec<u8> {
    format!("irondivi-webui-wallet/1/{}/{}", w.network, w.coin_type).into_bytes()
}

/// v2 AAD for the DEK-encrypted `Secret`
fn aad_v2_secret(network: &str, coin_type: u32) -> Vec<u8> {
    format!("irondivi-webui-wallet/2/{network}/{coin_type}/secret").into_bytes()
}

/// v2 AAD for the primary Argon2id passphrase slot
fn aad_v2_passphrase_slot(network: &str, coin_type: u32) -> Vec<u8> {
    format!("irondivi-webui-wallet/2/{network}/{coin_type}/slot/passphrase").into_bytes()
}

/// v2 AAD for a WebAuthn PRF slot
fn aad_v2_passkey_slot(network: &str, coin_type: u32, slot_id: &str) -> Vec<u8> {
    format!("irondivi-webui-wallet/2/{network}/{coin_type}/slot/{slot_id}").into_bytes()
}

fn derive_prf_slot_key(
    slot_id: &str,
    prf_salt: &[u8; 32],
    prf_output: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(Some(prf_salt), prf_output);
    let info = format!("irondivi-webui-wallet/2/slot/{slot_id}");
    let mut slot_key = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), &mut slot_key[..])
        .map_err(|_| "passkey HKDF expansion failed".to_string())?;
    Ok(slot_key)
}

fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let body = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(24 + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(hex::encode(out))
}

fn aead_decrypt(
    key: &[u8; 32],
    sealed_hex: &str,
    aad: &[u8],
    wrong_key_msg: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let sealed = hex::decode(sealed_hex).map_err(|_| "wallet file damaged".to_string())?;
    if sealed.len() < 24 + 16 {
        return Err("wallet file damaged".into());
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let (nonce, body) = sealed.split_at(24);
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad })
        .map(Zeroizing::new)
        .map_err(|_| wrong_key_msg.to_string())
}

pub(crate) fn network_of(name: &str) -> Network {
    match name {
        "main" => Network::Mainnet,
        "regtest" => Network::Regtest,
        _ => Network::Testnet,
    }
}

fn chain_mode_of(name: &str) -> ChainMode {
    if name == "privatedivi" {
        ChainMode::PrivateDivi
    } else {
        ChainMode::Divi
    }
}

impl WalletStore {
    pub fn new(data_dir: &Path, network: &str, chain_mode: &str) -> Self {
        WalletStore {
            dir: data_dir.join("webui-wallets"),
            network: network.to_string(),
            chain_mode: chain_mode.to_string(),
            lock: Mutex::new(()),
        }
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn check_invariants(w: &WalletFile) -> Result<()> {
        match w.version {
            VERSION_V1 => Ok(()),
            VERSION_V2 => {
                let Some(slot) = &w.passphrase_slot else {
                    return Err("wallet file missing its passphrase slot".into());
                };
                if slot.kind != "argon2id" {
                    return Err("unsupported passphrase slot kind".into());
                }
                Ok(())
            }
            _ => Err("wallet file of an unknown version".into()),
        }
    }

    fn write(&self, w: &WalletFile) -> Result<()> {
        Self::check_invariants(w)?;
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let tmp = self.dir.join(format!(".{}.tmp", w.id));
        let text = serde_json::to_vec_pretty(w).map_err(|e| e.to_string())?;
        write_private(&tmp, &text)?;
        std::fs::rename(&tmp, self.path(&w.id)).map_err(|e| e.to_string())
    }

    pub fn get(&self, id: &str) -> Result<WalletFile> {
        if !valid_id(id) {
            return Err("no such wallet".into());
        }
        let text = std::fs::read(self.path(id)).map_err(|_| "no such wallet".to_string())?;
        let w: WalletFile =
            serde_json::from_slice(&text).map_err(|e| format!("wallet file unreadable: {e}"))?;
        Self::check_invariants(&w)?;
        Ok(w)
    }

    /// Every wallet of this network, oldest first
    pub fn list(&self) -> Vec<WalletFile> {
        let mut out: Vec<WalletFile> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let id = name.strip_suffix(".json")?;
                self.get(id).ok()
            })
            .filter(|w| w.network == self.network)
            .collect();
        out.sort_by(|a, b| a.created.cmp(&b.created).then(a.id.cmp(&b.id)));
        out
    }

    /// The wallet in use, if any is chosen and still there
    pub fn active(&self) -> Option<String> {
        let id = std::fs::read_to_string(self.dir.join("active")).ok()?;
        let id = id.trim();
        self.get(id).ok().filter(|w| w.network == self.network)?;
        Some(id.to_string())
    }

    pub fn set_active(&self, id: &str) -> Result<()> {
        let _g = self.lock.lock();
        self.get(id)?;
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        write_private(&self.dir.join("active"), id.as_bytes())
    }

    fn hd(&self, w: &WalletFile, secret: &Secret) -> Result<HdWallet> {
        Ok(HdWallet::from_mnemonic(
            &secret.words,
            secret.bip39_passphrase.as_deref(),
            chain_mode_of(&w.chain_mode),
        )
        .map_err(|e| e.to_string())?
        .with_coin_type(w.coin_type))
    }

    fn addresses(&self, hd: &HdWallet, change: bool, from: u32, to: u32) -> Result<Vec<String>> {
        let network = network_of(&self.network);
        (from..to)
            .map(|i| {
                let key = if change {
                    hd.derive_change(0, i)
                } else {
                    hd.derive_receiving(0, i)
                }
                .map_err(|e| e.to_string())?;
                let public = key
                    .public_key()
                    .and_then(|k| k.public_key())
                    .map_err(|e| e.to_string())?;
                Ok(Address::p2pkh(&public, network).to_string())
            })
            .collect()
    }

    /// Make a v2 wallet: new words when `words` is None, else restore them. The
    /// new words are returned once, to show; the file holds them sealed under a
    /// random DEK wrapped by the Argon2id passphrase slot.
    pub fn create(
        &self,
        name: &str,
        passphrase: &str,
        words: Option<&str>,
        bip39_passphrase: Option<&str>,
    ) -> Result<(WalletFile, Zeroizing<String>)> {
        let name = clean_name(name)?;
        if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
            return Err(format!(
                "a wallet passphrase is at least {MIN_PASSPHRASE_LEN} characters"
            ));
        }
        let mode = chain_mode_of(&self.chain_mode);
        let bip39 = bip39_passphrase.filter(|p| !p.is_empty());
        let hd = match words {
            Some(w) => {
                let w = Zeroizing::new(
                    w.split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .to_lowercase(),
                );
                HdWallet::from_mnemonic(&w, bip39, mode)
                    .map_err(|_| "those are not valid recovery words".to_string())?
            }
            None => HdWallet::generate(bip39, mode).map_err(|e| e.to_string())?,
        };
        let coin_type = core_coin_type(mode, self.network == "main");
        let hd = hd.with_coin_type(coin_type);
        let secret = Secret {
            words: hd.mnemonic().ok_or("no words")?.to_string(),
            bip39_passphrase: bip39.map(str::to_string),
        };
        let mut dek = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut dek[..]);
        let (sealed, pass_slot) =
            seal_v2(&self.network, coin_type, passphrase, &dek, &secret)?;
        let w = WalletFile {
            version: VERSION_V2,
            id: new_id(),
            name,
            created: now(),
            network: self.network.clone(),
            chain_mode: self.chain_mode.clone(),
            coin_type,
            kdf: pass_slot.kdf,
            salt: pass_slot.salt.clone(),
            sealed,
            passphrase_slot: Some(pass_slot),
            passkeys: Vec::new(),
            receive: self.addresses(&hd, false, 0, GAP)?,
            change: self.addresses(&hd, true, 0, GAP)?,
            next_receive: 0,
            next_change: 0,
        };
        let _g = self.lock.lock();
        self.write(&w)?;
        if self.active().is_none() {
            write_private(&self.dir.join("active"), w.id.as_bytes())?;
        }
        Ok((w, Zeroizing::new(secret.words.clone())))
    }

    fn open_v1(&self, w: &WalletFile, passphrase: &str) -> Result<Secret> {
        let salt = hex::decode(&w.salt).map_err(|_| "wallet file damaged".to_string())?;
        let key = derive_key(&w.kdf, passphrase, &salt)?;
        let plain = aead_decrypt(&key, &w.sealed, &aad_v1(w), "wrong passphrase")?;
        serde_json::from_slice(&plain).map_err(|_| "wallet file damaged".into())
    }

    fn unwrap_v2_dek(&self, w: &WalletFile, auth: WalletAuth<'_>) -> Result<Zeroizing<[u8; 32]>> {
        let pass_slot = w
            .passphrase_slot
            .as_ref()
            .ok_or_else(|| "wallet file missing its passphrase slot".to_string())?;
        if pass_slot.kind != "argon2id" {
            return Err("unsupported passphrase slot kind".into());
        }
        let dek_bytes = match auth {
            WalletAuth::Passphrase(passphrase) => {
                let salt =
                    hex::decode(&pass_slot.salt).map_err(|_| "wallet file damaged".to_string())?;
                let key = derive_key(&pass_slot.kdf, passphrase, &salt)?;
                aead_decrypt(
                    &key,
                    &pass_slot.sealed_dek,
                    &aad_v2_passphrase_slot(&w.network, w.coin_type),
                    "wrong passphrase",
                )?
            }
            WalletAuth::Passkey {
                slot_id,
                prf_output_b64,
            } => {
                let prf_output = decode_prf_secret(prf_output_b64)?;
                let slot = w
                    .passkeys
                    .iter()
                    .find(|s| s.id == slot_id)
                    .ok_or_else(|| "no such passkey on this wallet".to_string())?;
                let prf_salt = decode_prf_salt(&slot.prf_salt)?;
                let slot_key = derive_prf_slot_key(&slot.id, &prf_salt, &prf_output)?;
                aead_decrypt(
                    &slot_key,
                    &slot.sealed_dek,
                    &aad_v2_passkey_slot(&w.network, w.coin_type, &slot.id),
                    "passkey did not unlock this wallet",
                )?
            }
        };
        if dek_bytes.len() != 32 {
            return Err("wallet file damaged".into());
        }
        let mut dek = Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(&dek_bytes);
        Ok(dek)
    }

    fn open_v2_with_dek(&self, w: &WalletFile, dek: &[u8; 32]) -> Result<Secret> {
        let plain = aead_decrypt(
            dek,
            &w.sealed,
            &aad_v2_secret(&w.network, w.coin_type),
            "wallet file damaged",
        )?;
        serde_json::from_slice(&plain).map_err(|_| "wallet file damaged".into())
    }

    fn open_with(&self, w: &WalletFile, auth: WalletAuth<'_>) -> Result<Secret> {
        match w.version {
            VERSION_V1 => match auth {
                WalletAuth::Passphrase(p) => self.open_v1(w, p),
                WalletAuth::Passkey { .. } => Err("this wallet has no passkeys".into()),
            },
            VERSION_V2 => {
                let dek = self.unwrap_v2_dek(w, auth)?;
                self.open_v2_with_dek(w, &dek)
            }
            _ => Err("wallet file of an unknown version".into()),
        }
    }

    /// Enroll a WebAuthn PRF passkey slot on `id`. Verifies `passphrase` first
    /// and upgrades a v1 wallet to v2 in place while preserving its Argon2id
    /// passphrase slot.
    #[allow(clippy::too_many_arguments)]
    pub fn add_passkey(
        &self,
        id: &str,
        passphrase: &str,
        label: &str,
        credential_id_b64: &str,
        prf_salt_b64: &str,
        rp_id: &str,
        prf_output_b64: &str,
    ) -> Result<(WalletFile, WalletPasskeySummary)> {
        let label = clean_label(label, "Passkey")?;
        let rp_id = rp_id_from_host(rp_id)?;
        let cred_raw = b64url_decode(credential_id_b64)?;
        if cred_raw.is_empty() || cred_raw.len() > 1023 {
            return Err("invalid passkey credential ID".into());
        }
        let credential_id = b64url_encode(&cred_raw);
        let prf_salt = decode_prf_salt(prf_salt_b64)?;
        let prf_output = decode_prf_secret(prf_output_b64)?;

        let _g = self.lock.lock();
        let mut w = self.get(id)?;
        if w.passkeys.len() >= MAX_WALLET_PASSKEYS {
            return Err(format!("at most {MAX_WALLET_PASSKEYS} passkeys per wallet"));
        }
        if w.passkeys.iter().any(|s| s.credential_id == credential_id) {
            return Err("that passkey is already added to this wallet".into());
        }

        let dek: Zeroizing<[u8; 32]> = match w.version {
            VERSION_V1 => {
                let secret = self.open_v1(&w, passphrase)?;
                let mut new_dek = Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng.fill_bytes(&mut new_dek[..]);
                let (sealed, pass_slot) =
                    seal_v2(&w.network, w.coin_type, passphrase, &new_dek, &secret)?;
                w.version = VERSION_V2;
                w.kdf = pass_slot.kdf;
                w.salt = pass_slot.salt.clone();
                w.sealed = sealed;
                w.passphrase_slot = Some(pass_slot);
                new_dek
            }
            VERSION_V2 => {
                let dek = self.unwrap_v2_dek(&w, WalletAuth::Passphrase(passphrase))?;
                let _ = self.open_v2_with_dek(&w, &dek)?;
                dek
            }
            _ => return Err("wallet file of an unknown version".into()),
        };

        let slot_id = new_id();
        let slot_key = derive_prf_slot_key(&slot_id, &prf_salt, &prf_output)?;
        let sealed_dek = aead_encrypt(
            &slot_key,
            &dek[..],
            &aad_v2_passkey_slot(&w.network, w.coin_type, &slot_id),
        )?;
        let slot = WalletPasskeySlot {
            id: slot_id,
            label,
            credential_id,
            prf_salt: b64url_encode(&prf_salt),
            rp_id,
            sealed_dek,
            created: now(),
        };
        let summary = WalletPasskeySummary::from(&slot);
        w.passkeys.push(slot);
        self.write(&w)?;
        Ok((w, summary))
    }

    /// Remove a passkey PRF slot after verifying owner control via passphrase
    /// or passkey. Never removes the mandatory Argon2id passphrase slot.
    pub fn remove_passkey(
        &self,
        id: &str,
        slot_id: &str,
        auth: WalletAuth<'_>,
    ) -> Result<WalletFile> {
        let _g = self.lock.lock();
        let mut w = self.get(id)?;
        let _secret = self.open_with(&w, auth)?;
        let before = w.passkeys.len();
        w.passkeys.retain(|s| s.id != slot_id);
        if w.passkeys.len() == before {
            return Err("no such passkey on this wallet".into());
        }
        self.write(&w)?;
        Ok(w)
    }

    /// The recovery words, for the backup flow
    pub fn words(&self, id: &str, passphrase: &str) -> Result<Zeroizing<String>> {
        self.words_with(id, WalletAuth::Passphrase(passphrase))
    }

    pub fn words_with(&self, id: &str, auth: WalletAuth<'_>) -> Result<Zeroizing<String>> {
        let w = self.get(id)?;
        let s = self.open_with(&w, auth)?;
        Ok(Zeroizing::new(s.words.clone()))
    }

    pub fn rename(&self, id: &str, name: &str) -> Result<WalletFile> {
        let name = clean_name(name)?;
        let _g = self.lock.lock();
        let mut w = self.get(id)?;
        w.name = name;
        self.write(&w)?;
        Ok(w)
    }

    /// Remove a wallet; its passphrase or passkey proves the remover knows what goes
    pub fn delete(&self, id: &str, passphrase: &str) -> Result<()> {
        self.delete_with(id, WalletAuth::Passphrase(passphrase))
    }

    pub fn delete_with(&self, id: &str, auth: WalletAuth<'_>) -> Result<()> {
        let w = self.get(id)?;
        self.open_with(&w, auth)?;
        let _g = self.lock.lock();
        std::fs::remove_file(self.path(id)).map_err(|e| e.to_string())?;
        if std::fs::read_to_string(self.dir.join("active")).is_ok_and(|a| a.trim() == id) {
            let _ = std::fs::remove_file(self.dir.join("active"));
        }
        Ok(())
    }

    /// The backup file: the wallet as stored, words sealed
    pub fn backup(&self, id: &str) -> Result<Vec<u8>> {
        let w = self.get(id)?;
        serde_json::to_vec_pretty(&w).map_err(|e| e.to_string())
    }

    /// Take a backup file back (v1 or v2); its passphrase must open it. It gets
    /// a fresh id when one of that id is already here.
    pub fn import(&self, file: &[u8], passphrase: &str) -> Result<WalletFile> {
        let mut w: WalletFile =
            serde_json::from_slice(file).map_err(|_| "that is not a wallet backup".to_string())?;
        if w.version != VERSION_V1 && w.version != VERSION_V2 {
            return Err("a wallet backup of an unknown version".into());
        }
        Self::check_invariants(&w)?;
        if w.network != self.network {
            return Err(format!(
                "that wallet is for the {} network; this node runs {}",
                w.network, self.network
            ));
        }
        if !valid_id(&w.id) {
            return Err("that is not a wallet backup".into());
        }
        // The addresses kept in the clear are derived again rather than trusted
        let secret = self.open_with(&w, WalletAuth::Passphrase(passphrase))?;
        let hd = self.hd(&w, &secret)?;
        w.receive = self.addresses(&hd, false, 0, w.receive.len().max(GAP as usize) as u32)?;
        w.change = self.addresses(&hd, true, 0, w.change.len().max(GAP as usize) as u32)?;
        w.next_receive = w.next_receive.min(w.receive.len() as u32);
        w.next_change = w.next_change.min(w.change.len() as u32);
        let _g = self.lock.lock();
        if self.path(&w.id).exists() {
            w.id = new_id();
        }
        self.write(&w)?;
        Ok(w)
    }

    /// Hand out the next receiving address; past the derived ones an unlock is
    /// needed to derive more
    pub fn next_address(&self, id: &str, passphrase: Option<&str>) -> Result<String> {
        self.next_address_with(id, passphrase.map(WalletAuth::Passphrase))
    }

    pub fn next_address_with(&self, id: &str, auth: Option<WalletAuth<'_>>) -> Result<String> {
        let _g = self.lock.lock();
        let mut w = self.get(id)?;
        if w.next_receive as usize >= w.receive.len() {
            let auth = auth.ok_or("enter the wallet passphrase to derive more addresses")?;
            let secret = self.open_with(&w, auth)?;
            let hd = self.hd(&w, &secret)?;
            let from = w.receive.len() as u32;
            w.receive
                .extend(self.addresses(&hd, false, from, from + GAP)?);
        }
        let addr = w.receive[w.next_receive as usize].clone();
        w.next_receive += 1;
        self.write(&w)?;
        Ok(addr)
    }

    /// Every address the wallet watches
    pub fn watched(w: &WalletFile) -> Vec<String> {
        w.receive.iter().chain(w.change.iter()).cloned().collect()
    }

    /// Plan and sign a send from `coins`; the signed transaction's hex and txid
    pub fn sign_send(
        &self,
        id: &str,
        passphrase: &str,
        coins: &[Coin],
        tip: u32,
        req: SendRequest<'_>,
    ) -> Result<(String, String, i64)> {
        self.sign_send_with(id, WalletAuth::Passphrase(passphrase), coins, tip, req)
    }

    pub fn sign_send_with(
        &self,
        id: &str,
        auth: WalletAuth<'_>,
        coins: &[Coin],
        tip: u32,
        req: SendRequest<'_>,
    ) -> Result<(String, String, i64)> {
        let _g = self.lock.lock();
        let mut w = self.get(id)?;
        let secret = self.open_with(&w, auth)?;
        let hd = self.hd(&w, &secret)?;
        let network = network_of(&self.network);
        let to = Address::from_base58_for_network(req.to, network)
            .map_err(|_| "not an address of this network".to_string())?;
        let payee = TxOut {
            value: req.amount,
            script_pubkey: to.script_pubkey(),
        };
        // A change address the address index has not seen yet
        if w.next_change as usize >= w.change.len() {
            let from = w.change.len() as u32;
            w.change
                .extend(self.addresses(&hd, true, from, from + GAP)?);
        }
        let change_index = w.next_change;
        let change_addr =
            Address::from_base58_for_network(&w.change[change_index as usize], network)
                .map_err(|e| e.to_string())?;

        let pubkey_len = |_: &[u8; 20]| Some(33usize);
        let no_redeem = |_: &[u8; 20]| None;
        let send_coins: Vec<SendCoin> = coins
            .iter()
            .filter_map(|c| {
                let script = Script::from_bytes(hex::decode(&c.script_hex).ok()?);
                let bytes = max_script_sig_bytes(&script, &pubkey_len, &no_redeem)?;
                let mut utxo = divi_wallet::WalletUtxo::new(
                    Hash256::from_hex(&c.txid).ok()?,
                    c.vout,
                    Amount::from_sat(c.value),
                    script,
                    c.address.clone(),
                );
                utxo.height = c.height;
                Some(SendCoin {
                    depth: c.height.map(|h| tip.saturating_sub(h) + 1).unwrap_or(0),
                    input_bytes: bytes + 40,
                    utxo,
                })
            })
            .collect();
        let mode = if req.fee_from_amount {
            FeeMode::ReceiverPays
        } else {
            FeeMode::SenderPays
        };
        let plan = plan_send(
            &[payee],
            &send_coins,
            mode,
            ChangeKind::P2pkh,
            &change_addr.script_pubkey(),
            req.policy,
        )
        .map_err(|e| e.to_string())?;

        let mut builder = TransactionBuilder::new();
        for u in &plan.inputs {
            builder = builder.add_input(u.outpoint(), u.script_pubkey.clone());
        }
        for o in &plan.outputs {
            builder = builder.add_output(o.value, o.script_pubkey.clone());
        }
        if let Some(change) = plan.change {
            builder = builder.add_output(change, change_addr.script_pubkey());
        }
        let (mut tx, prev) = builder.build();
        let sigs = plan
            .inputs
            .iter()
            .enumerate()
            .map(|(i, u)| {
                let key = self.key_for(&w, &hd, &u.address)?;
                let secret = key.secret_key().map_err(|e| e.to_string())?;
                let public = key
                    .public_key()
                    .and_then(|k| k.public_key())
                    .map_err(|e| e.to_string())?;
                let sig = sign_input(&tx, i, &prev[i], &secret, divi_script::SigHashType::All)
                    .map_err(|e| e.to_string())?;
                Ok(create_p2pkh_script_sig(&sig, &public))
            })
            .collect::<Result<Vec<_>>>()?;
        for (i, s) in sigs.into_iter().enumerate() {
            tx.vin[i].script_sig = s;
        }
        check_signed(&tx, plan.fee, req.policy).map_err(|e| e.to_string())?;
        if plan.change.is_some() {
            w.next_change += 1;
            self.write(&w)?;
        }
        let hex = hex::encode(divi_primitives::serialize::serialize(&tx));
        Ok((hex, tx.txid().to_string(), plan.fee.as_sat()))
    }

    fn key_for(
        &self,
        w: &WalletFile,
        hd: &HdWallet,
        address: &str,
    ) -> Result<divi_wallet::ExtendedPrivateKey> {
        if let Some(i) = w.receive.iter().position(|a| a == address) {
            return hd.derive_receiving(0, i as u32).map_err(|e| e.to_string());
        }
        if let Some(i) = w.change.iter().position(|a| a == address) {
            return hd.derive_change(0, i as u32).map_err(|e| e.to_string());
        }
        Err(format!("{address} is not this wallet's"))
    }

    /// Sign a text message with the compressed P2PKH key of `address` using
    /// Divi Core's `"DarkNet Signed Message:\n"` magic prefix so `verifymessage`
    /// on `irondivid` / `divid` verifies the returned base64 signature.
    pub fn sign_message_with(
        &self,
        id: &str,
        auth: WalletAuth<'_>,
        address: &str,
        message: &str,
    ) -> Result<String> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let addr = address.trim();
        let network = network_of(&self.network);
        let decoded = Address::from_base58_for_network(addr, network)
            .map_err(|_| "not an address of this network".to_string())?;
        if decoded.addr_type != divi_wallet::AddressType::P2PKH {
            return Err("only P2PKH addresses can sign messages".into());
        }
        let w = self.get(id)?;
        let secret_words = self.open_with(&w, auth)?;
        let hd = self.hd(&w, &secret_words)?;
        let ext_key = self.key_for(&w, &hd, addr)?;
        let secret_key = ext_key.secret_key().map_err(|e| e.to_string())?;
        let hash = divi_rpc::wallet::message_magic_hash(message.as_bytes());
        let sig = divi_crypto::sign_hash_recoverable(&secret_key, &hash)
            .map_err(|e| format!("signing failed: {e}"))?;
        Ok(STANDARD.encode(sig.to_compact_with_recovery()))
    }
}

/// Seal `Secret` under `dek` and wrap `dek` under a fresh Argon2id passphrase slot.
fn seal_v2(
    network: &str,
    coin_type: u32,
    passphrase: &str,
    dek: &[u8; 32],
    secret: &Secret,
) -> Result<(String, PassphraseSlot)> {
    let plain_secret = Zeroizing::new(serde_json::to_vec(secret).map_err(|e| e.to_string())?);
    let sealed_secret = aead_encrypt(dek, &plain_secret, &aad_v2_secret(network, coin_type))?;

    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let pass_key = derive_key(&KDF, passphrase, &salt)?;
    let sealed_dek = aead_encrypt(
        &pass_key,
        dek,
        &aad_v2_passphrase_slot(network, coin_type),
    )?;
    let slot = PassphraseSlot {
        kind: "argon2id".into(),
        kdf: KDF,
        salt: hex::encode(salt),
        sealed_dek,
    };
    Ok((sealed_secret, slot))
}

#[cfg(test)]
fn seal_v1_for_test(w: &WalletFile, passphrase: &str, secret: &Secret) -> Result<String> {
    let salt = hex::decode(&w.salt).map_err(|e| e.to_string())?;
    let key = derive_key(&w.kdf, passphrase, &salt)?;
    let plain = Zeroizing::new(serde_json::to_vec(secret).map_err(|e| e.to_string())?);
    aead_encrypt(&key, &plain, &aad_v1(w))
}

/// Write a file only its owner can read
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| e.to_string())?;
    f.write_all(data).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> WalletStore {
        WalletStore::new(dir, "regtest", "divi")
    }

    #[test]
    fn create_restore_rename_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let (a, words) = s.create("Spending", "correct horse", None, None).unwrap();
        assert_eq!(a.version, 2);
        assert!(a.passphrase_slot.is_some());
        assert_eq!(words.split_whitespace().count(), 24);
        assert!(!serde_json::to_string(&a).unwrap().contains(words.as_str()));
        assert_eq!(s.active().as_deref(), Some(a.id.as_str()));

        // The same words give the same addresses
        let (b, _) = s
            .create("Restored", "another pass", Some(&words), None)
            .unwrap();
        assert_eq!(a.receive, b.receive);
        assert_eq!(s.list().len(), 2);

        assert_eq!(
            s.words(&a.id, "correct horse").unwrap().as_str(),
            words.as_str()
        );
        assert_eq!(
            s.words(&a.id, "wrong pass!").unwrap_err(),
            "wrong passphrase"
        );

        s.rename(&b.id, "Savings").unwrap();
        s.set_active(&b.id).unwrap();
        assert_eq!(s.active().as_deref(), Some(b.id.as_str()));
        assert!(s.delete(&b.id, "nope nope nope").is_err());
        s.delete(&b.id, "another pass").unwrap();
        assert_eq!(s.active(), None);
        assert_eq!(s.list().len(), 1);

        assert_eq!(s.next_address(&a.id, None).unwrap(), a.receive[0]);
        assert_eq!(s.next_address(&a.id, None).unwrap(), a.receive[1]);
    }

    #[test]
    fn backup_round_trip_and_short_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        assert!(s.create("x", "short", None, None).is_err());
        let (a, _) = s
            .create("Cold", "long enough", None, Some("extra"))
            .unwrap();
        let file = s.backup(&a.id).unwrap();
        let other = tempfile::tempdir().unwrap();
        let t = store(other.path());
        assert!(t.import(&file, "not it at all").is_err());
        let b = t.import(&file, "long enough").unwrap();
        assert_eq!(b.receive, a.receive);
        // A backup of another network is refused
        assert!(WalletStore::new(other.path(), "main", "divi")
            .import(&file, "long enough")
            .is_err());
    }

    #[test]
    fn v1_wallet_loads_migrates_to_v2_on_passkey_add_and_keeps_portable_backup() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());

        // Construct a real version 1 WalletFile on disk (with low KDF cost for fast test)
        let fast_kdf = Kdf {
            m_kib: 1024,
            t: 1,
            p: 1,
        };
        let hd = HdWallet::generate(None, ChainMode::Divi)
            .unwrap()
            .with_coin_type(1);
        let expected_words = hd.mnemonic().unwrap().to_string();
        let secret = Secret {
            words: expected_words.clone(),
            bip39_passphrase: None,
        };
        let mut v1 = WalletFile {
            version: 1,
            id: "0123456789abcdef".into(),
            name: "Legacy V1".into(),
            created: 1_700_000_000,
            network: "regtest".into(),
            chain_mode: "divi".into(),
            coin_type: 1,
            kdf: fast_kdf,
            salt: "00112233445566778899aabbccddeeff".into(),
            sealed: String::new(),
            passphrase_slot: None,
            passkeys: Vec::new(),
            receive: s.addresses(&hd, false, 0, GAP).unwrap(),
            change: s.addresses(&hd, true, 0, GAP).unwrap(),
            next_receive: 0,
            next_change: 0,
        };
        v1.sealed = seal_v1_for_test(&v1, "legacy-passphrase", &secret).unwrap();
        std::fs::create_dir_all(dir.path().join("webui-wallets")).unwrap();
        write_private(
            &dir.path().join("webui-wallets/0123456789abcdef.json"),
            &serde_json::to_vec_pretty(&v1).unwrap(),
        )
        .unwrap();

        // v1 opens with passphrase and imports cleanly before migration
        assert_eq!(
            s.words(&v1.id, "legacy-passphrase").unwrap().as_str(),
            expected_words
        );
        let v1_backup = s.backup(&v1.id).unwrap();
        let import_dir = tempfile::tempdir().unwrap();
        let imported_v1 = store(import_dir.path())
            .import(&v1_backup, "legacy-passphrase")
            .unwrap();
        assert_eq!(imported_v1.version, 1);

        // Enrolling a passkey requires the correct passphrase and upgrades v1 -> v2
        let salt_b64 = b64url_encode(&[0x55u8; 32]);
        let prf_b64 = b64url_encode(&[0x66u8; 32]);
        let wrong_prf_b64 = b64url_encode(&[0x77u8; 32]);
        let cred_b64 = b64url_encode(b"wallet-passkey-1");

        assert!(s
            .add_passkey(
                &v1.id,
                "wrong-passphrase",
                "Touch ID",
                &cred_b64,
                &salt_b64,
                "localhost",
                &prf_b64,
            )
            .is_err());

        let (upgraded, pk_summary) = s
            .add_passkey(
                &v1.id,
                "legacy-passphrase",
                "Touch ID",
                &cred_b64,
                &salt_b64,
                "localhost",
                &prf_b64,
            )
            .unwrap();
        assert_eq!(upgraded.version, 2);
        assert!(upgraded.passphrase_slot.is_some());
        assert_eq!(upgraded.passkeys.len(), 1);

        // Unlock words & sign send using ONLY the passkey PRF output
        assert_eq!(
            s.words_with(
                &v1.id,
                WalletAuth::Passkey {
                    slot_id: &pk_summary.id,
                    prf_output_b64: &prf_b64,
                },
            )
            .unwrap()
            .as_str(),
            expected_words
        );
        assert!(s
            .words_with(
                &v1.id,
                WalletAuth::Passkey {
                    slot_id: &pk_summary.id,
                    prf_output_b64: &wrong_prf_b64,
                },
            )
            .is_err());

        let pay_to = Address::from_base58_for_network(&upgraded.receive[3], Network::Regtest)
            .unwrap()
            .to_string();
        let utxo_addr =
            Address::from_base58_for_network(&upgraded.receive[0], Network::Regtest).unwrap();
        let coins = vec![Coin {
            address: upgraded.receive[0].clone(),
            txid: "11".repeat(32),
            vout: 0,
            value: 10 * 100_000_000,
            script_hex: hex::encode(utxo_addr.script_pubkey().as_bytes()),
            height: Some(1),
        }];
        let (raw_hex, txid, fee) = s
            .sign_send_with(
                &v1.id,
                WalletAuth::Passkey {
                    slot_id: &pk_summary.id,
                    prf_output_b64: &prf_b64,
                },
                &coins,
                10,
                SendRequest {
                    to: &pay_to,
                    amount: Amount::from_sat(2 * 100_000_000),
                    fee_from_amount: false,
                    policy: Default::default(),
                },
            )
            .unwrap();
        assert!(!raw_hex.is_empty());
        assert_eq!(txid.len(), 64);
        assert!(fee > 0);

        // Backup JSON of v2 wallet restores on another machine using ONLY the passphrase!
        let v2_backup = s.backup(&v1.id).unwrap();
        let other_machine = tempfile::tempdir().unwrap();
        let other_store = store(other_machine.path());
        let restored = other_store.import(&v2_backup, "legacy-passphrase").unwrap();
        assert_eq!(restored.version, 2);
        assert_eq!(
            other_store
                .words(&restored.id, "legacy-passphrase")
                .unwrap()
                .as_str(),
            expected_words
        );

        // Removing the passkey keeps the mandatory argon2id passphrase slot intact
        let after_remove = s
            .remove_passkey(
                &v1.id,
                &pk_summary.id,
                WalletAuth::Passphrase("legacy-passphrase"),
            )
            .unwrap();
        assert!(after_remove.passkeys.is_empty());
        assert!(after_remove.passphrase_slot.is_some());
        assert_eq!(
            s.words(&v1.id, "legacy-passphrase").unwrap().as_str(),
            expected_words
        );
    }

    #[test]
    fn sign_message_with_passphrase_and_passkey_matches_darknet_verifymessage() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let (w, _) = s
            .create("Signer", "correct horse battery", None, None)
            .unwrap();
        let addr = w.receive[0].clone();

        let salt_b64 = b64url_encode(&[0x33u8; 32]);
        let prf_b64 = b64url_encode(&[0x44u8; 32]);
        let cred_b64 = b64url_encode(b"signer-passkey-1");
        let (_, pk) = s
            .add_passkey(
                &w.id,
                "correct horse battery",
                "Touch ID",
                &cred_b64,
                &salt_b64,
                "localhost",
                &prf_b64,
            )
            .unwrap();

        let msg = "IronDivi Electrum passkey message signing test";
        let sig_pass = s
            .sign_message_with(
                &w.id,
                WalletAuth::Passphrase("correct horse battery"),
                &addr,
                msg,
            )
            .unwrap();
        let sig_pk = s
            .sign_message_with(
                &w.id,
                WalletAuth::Passkey {
                    slot_id: &pk.id,
                    prf_output_b64: &prf_b64,
                },
                &addr,
                msg,
            )
            .unwrap();
        assert_eq!(sig_pass, sig_pk);

        // Recover address exactly as WalletRpc::verify_message does
        let raw = STANDARD.decode(&sig_pk).unwrap();
        assert_eq!(raw.len(), 65);
        assert!((31..=34).contains(&raw[0]));
        let rec = divi_crypto::RecoverableSig::from_compact_with_recovery(&raw).unwrap();
        let hash = divi_rpc::wallet::message_magic_hash(msg.as_bytes());
        let pubkey = rec.recover_from_hash(&hash).unwrap();
        let recovered_addr = Address::from_pubkey_hash(
            divi_crypto::hash160(&pubkey.to_bytes()),
            Network::Regtest,
        )
        .to_string();
        assert_eq!(recovered_addr, addr);

        // Delete with passkey PRF
        s.delete_with(
            &w.id,
            WalletAuth::Passkey {
                slot_id: &pk.id,
                prf_output_b64: &prf_b64,
            },
        )
        .unwrap();
        assert!(s.list().is_empty());
    }
}
