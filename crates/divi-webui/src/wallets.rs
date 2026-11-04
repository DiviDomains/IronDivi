// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The interface's own wallets, as many as one likes, beside the node's one
//! wallet. Each is an HD wallet whose recovery words are sealed under its own
//! passphrase (Argon2id, XChaCha20-Poly1305) in `<datadir>/webui-wallets/`.
//! The addresses are derived when the words are at hand and kept in the clear,
//! so a wallet's balance and history show without its passphrase: they come
//! through the node's Electrum backend (`chainview.rs`), mempool included.
//! The words leave the file only when the passphrase is given, and never pass
//! through the console or `/api/rpc`.

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
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Addresses derived on each chain (receive, change) when the words are open;
/// more are derived when a send or a new address needs them
const GAP: u32 = 20;

/// The shortest wallet passphrase taken
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// File format version
const VERSION: u32 = 1;

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
    /// Hex
    pub salt: String,
    /// Hex: nonce, then the sealed words and BIP39 passphrase
    pub sealed: String,
    /// Receiving addresses by index
    pub receive: Vec<String>,
    /// Change addresses by index
    pub change: Vec<String>,
    /// The next receiving address to hand out
    pub next_receive: u32,
    /// The next change address a send takes
    pub next_change: u32,
}

#[derive(Serialize, Deserialize)]
struct Secret {
    words: String,
    bip39_passphrase: Option<String>,
}

impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
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

/// The associated data that ties the sealed words to their wallet and network
fn aad(w: &WalletFile) -> Vec<u8> {
    format!(
        "irondivi-webui-wallet/{}/{}/{}",
        w.version, w.network, w.coin_type
    )
    .into_bytes()
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

    fn write(&self, w: &WalletFile) -> Result<()> {
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
        serde_json::from_slice(&text).map_err(|e| format!("wallet file unreadable: {e}"))
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

    /// Make a wallet: new words when `words` is None, else restore them. The
    /// new words are returned once, to show; the file holds them sealed.
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
                let w = w
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();
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
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mut w = WalletFile {
            version: VERSION,
            id: new_id(),
            name,
            created: now(),
            network: self.network.clone(),
            chain_mode: self.chain_mode.clone(),
            coin_type,
            kdf: KDF,
            salt: hex::encode(salt),
            sealed: String::new(),
            receive: self.addresses(&hd, false, 0, GAP)?,
            change: self.addresses(&hd, true, 0, GAP)?,
            next_receive: 0,
            next_change: 0,
        };
        w.sealed = seal(&w, passphrase, &secret)?;
        let _g = self.lock.lock();
        self.write(&w)?;
        if self.active().is_none() {
            write_private(&self.dir.join("active"), w.id.as_bytes())?;
        }
        Ok((w, Zeroizing::new(secret.words.clone())))
    }

    fn open(&self, w: &WalletFile, passphrase: &str) -> Result<Secret> {
        let salt = hex::decode(&w.salt).map_err(|_| "wallet file damaged")?;
        let sealed = hex::decode(&w.sealed).map_err(|_| "wallet file damaged")?;
        if sealed.len() < 24 {
            return Err("wallet file damaged".into());
        }
        let key = derive_key(&w.kdf, passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
        let (nonce, body) = sealed.split_at(24);
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: body,
                        aad: &aad(w),
                    },
                )
                .map_err(|_| "wrong passphrase".to_string())?,
        );
        serde_json::from_slice(&plain).map_err(|_| "wallet file damaged".into())
    }

    /// The recovery words, for the backup flow
    pub fn words(&self, id: &str, passphrase: &str) -> Result<Zeroizing<String>> {
        let w = self.get(id)?;
        let s = self.open(&w, passphrase)?;
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

    /// Remove a wallet; its passphrase proves the remover knows what goes
    pub fn delete(&self, id: &str, passphrase: &str) -> Result<()> {
        let w = self.get(id)?;
        self.open(&w, passphrase)?;
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

    /// Take a backup file back; its passphrase must open it. It gets a fresh
    /// id when one of that id is already here.
    pub fn import(&self, file: &[u8], passphrase: &str) -> Result<WalletFile> {
        let mut w: WalletFile =
            serde_json::from_slice(file).map_err(|_| "that is not a wallet backup".to_string())?;
        if w.version != VERSION {
            return Err("a wallet backup of an unknown version".into());
        }
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
        let secret = self.open(&w, passphrase)?;
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

    /// Hand out the next receiving address; past the derived ones the
    /// passphrase is needed to derive more
    pub fn next_address(&self, id: &str, passphrase: Option<&str>) -> Result<String> {
        let _g = self.lock.lock();
        let mut w = self.get(id)?;
        if w.next_receive as usize >= w.receive.len() {
            let pass = passphrase.ok_or("enter the wallet passphrase to derive more addresses")?;
            let secret = self.open(&w, pass)?;
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
        let _g = self.lock.lock();
        let mut w = self.get(id)?;
        let secret = self.open(&w, passphrase)?;
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
}

fn seal(w: &WalletFile, passphrase: &str, secret: &Secret) -> Result<String> {
    let salt = hex::decode(&w.salt).map_err(|e| e.to_string())?;
    let key = derive_key(&w.kdf, passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let plain = Zeroizing::new(serde_json::to_vec(secret).map_err(|e| e.to_string())?);
    let body = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad(w),
            },
        )
        .map_err(|e| e.to_string())?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&body);
    Ok(hex::encode(out))
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
}
