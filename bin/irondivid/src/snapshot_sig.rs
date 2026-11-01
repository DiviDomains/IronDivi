// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Signed snapshot root hashes.
//!
//! A snapshot's `root_hash` (see `divi_storage::snapshot`) is what operators trust. This module
//! lets the publisher sign it with a Divi key and lets an importer check the signature against
//! a signer address it already knows (pinned out of band), so a snapshot fetched from any mirror
//! is accepted only if the pinned key vouched for exactly this root hash on this network.
//!
//! The signature is the ordinary Divi `signmessage` signature over a fixed message, so it can
//! also be checked with the `verifymessage` RPC. It lives next to the manifest as `ROOT.sig`.
//! The importer rebuilds the message from the manifest it actually read; it never trusts the
//! message text stored in the file.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use divi_crypto::{sign_hash_recoverable, KeyPair, RecoverableSig};
use divi_rpc::wallet::message_magic_hash;
use divi_storage::snapshot::SnapshotManifest;
use divi_wallet::{Address, Network};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// File name of the detached signature inside a snapshot directory.
pub const SIG_NAME: &str = "ROOT.sig";

#[derive(Debug, Serialize, Deserialize)]
pub struct RootSignature {
    /// Address of the signing key (informational; the importer uses its own pinned address).
    pub signer: String,
    /// The signed message, stored so `verifymessage` can be run by hand.
    pub message: String,
    /// Base64, 65-byte recoverable signature, same encoding as `signmessage`.
    pub signature: String,
}

/// The exact text that is signed for a manifest.
pub fn root_message(m: &SnapshotManifest) -> String {
    format!(
        "irondivi-snapshot-root\nnetwork={}\nroot_hash={}",
        m.network, m.root_hash
    )
}

fn network_of(m: &SnapshotManifest) -> Result<Network> {
    match m.network.as_str() {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        other => bail!("unknown network {other:?} in manifest"),
    }
}

/// Sign the manifest's root hash with a 32-byte secret key given as 64 hex characters.
pub fn sign_root(m: &SnapshotManifest, secret_hex: &str) -> Result<RootSignature> {
    let raw = hex::decode(secret_hex.trim()).context("signing key is not hex")?;
    let pair = KeyPair::from_secret_bytes(&raw).map_err(|e| anyhow!("bad signing key: {e}"))?;
    let message = root_message(m);
    let hash = message_magic_hash(message.as_bytes());
    let sig = sign_hash_recoverable(pair.secret_key(), &hash)
        .map_err(|e| anyhow!("signing failed: {e}"))?;
    Ok(RootSignature {
        signer: Address::p2pkh(pair.public_key(), network_of(m)?).to_base58(),
        message,
        signature: STANDARD.encode(sig.to_compact_with_recovery()),
    })
}

/// Check `sig` proves that the key behind `pinned_signer` signed this manifest's root hash.
pub fn verify_root(m: &SnapshotManifest, sig: &RootSignature, pinned_signer: &str) -> Result<()> {
    let pinned = Address::from_base58(pinned_signer.trim())
        .map_err(|e| anyhow!("bad pinned signer address: {e}"))?;
    let network = network_of(m)?;
    if pinned.network != network {
        bail!(
            "pinned signer is a {:?} address but the snapshot is for {}",
            pinned.network,
            m.network
        );
    }
    let raw = STANDARD
        .decode(sig.signature.trim())
        .context("signature is not base64")?;
    let rec = RecoverableSig::from_compact_with_recovery(&raw)
        .map_err(|e| anyhow!("bad signature: {e}"))?;
    let hash = message_magic_hash(root_message(m).as_bytes());
    let pubkey = rec
        .recover_from_hash(&hash)
        .map_err(|_| anyhow!("signature does not recover a key for this root hash"))?;
    if Address::p2pkh(&pubkey, network) != pinned {
        bail!("root hash is not signed by the pinned signer {pinned_signer}");
    }
    Ok(())
}

/// Write `ROOT.sig` into a snapshot directory.
pub fn write_sig(dir: &Path, sig: &RootSignature) -> Result<()> {
    let path = dir.join(SIG_NAME);
    std::fs::write(&path, serde_json::to_vec_pretty(sig)?)
        .with_context(|| format!("writing {}", path.display()))
}

/// Read the manifest and `ROOT.sig` from a snapshot directory and verify them against a signer.
pub fn verify_dir(dir: &Path, pinned_signer: &str) -> Result<SnapshotManifest> {
    let m = SnapshotManifest::read(dir).map_err(|e| anyhow!("{e}"))?;
    let raw = std::fs::read(dir.join(SIG_NAME))
        .with_context(|| format!("{} not found in {}", SIG_NAME, dir.display()))?;
    let sig: RootSignature = serde_json::from_slice(&raw).context("bad ROOT.sig")?;
    verify_root(&m, &sig, pinned_signer)?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const KEY_B: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    fn manifest(root: &str) -> SnapshotManifest {
        SnapshotManifest {
            format: 1,
            network: "testnet".into(),
            tip_height: 10,
            tip_hash: "ab".repeat(32),
            prune_height: 5,
            winners_strip_height: 5,
            files: vec![],
            root_hash: root.into(),
        }
    }

    #[test]
    fn signature_verifies_against_the_signer_address() {
        let m = manifest(&"11".repeat(32));
        let sig = sign_root(&m, KEY_A).unwrap();
        verify_root(&m, &sig, &sig.signer).unwrap();
    }

    #[test]
    fn a_different_signer_is_refused() {
        let m = manifest(&"11".repeat(32));
        let sig = sign_root(&m, KEY_A).unwrap();
        let other = sign_root(&m, KEY_B).unwrap().signer;
        assert!(verify_root(&m, &sig, &other).is_err());
    }

    #[test]
    fn a_changed_root_hash_is_refused() {
        let signed = manifest(&"11".repeat(32));
        let sig = sign_root(&signed, KEY_A).unwrap();
        let tampered = manifest(&"22".repeat(32));
        assert!(verify_root(&tampered, &sig, &sig.signer).is_err());
    }

    #[test]
    fn a_mainnet_address_is_refused_for_a_testnet_snapshot() {
        let m = manifest(&"11".repeat(32));
        let sig = sign_root(&m, KEY_A).unwrap();
        let mut mainnet = m.clone();
        mainnet.network = "mainnet".into();
        let mainnet_addr = sign_root(&mainnet, KEY_A).unwrap().signer;
        assert!(verify_root(&m, &sig, &mainnet_addr).is_err());
    }

    #[test]
    fn signature_is_what_verifymessage_expects() {
        // Same hash and encoding as the signmessage/verifymessage RPCs.
        let m = manifest(&"33".repeat(32));
        let sig = sign_root(&m, KEY_A).unwrap();
        assert_eq!(sig.message, root_message(&m));
        let raw = STANDARD.decode(&sig.signature).unwrap();
        assert_eq!(raw.len(), 65);
    }
}
