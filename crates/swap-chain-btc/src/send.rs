// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A plain P2WPKH-to-P2WPKH send — no HTLC. Moves funds directly between the testnet
//! wallets that reuse the BTC swap keys (`docs/plans/swap-poc/funding.md`), e.g. to
//! unblock a swap direction without a faucet. Shares coin selection and signing with
//! `tx.rs`'s HTLC funding path (`select_coins`/`skeleton`/`p2wpkh_sign`), so the empty-UTXO
//! fix there (`funding_fails_cleanly_with_no_utxos_at_all`) applies here too.

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{CompressedPublicKey, ScriptBuf, Transaction, WPubkeyHash, Witness};
use divi_swap::SwapError;

use crate::tx::{p2wpkh_sign, select_coins, skeleton, Coin, DUST_SATS};

/// Build, sign and consensus-verify a plain send of `sats` to `to_program` (a 20-byte
/// witness v0 program — a P2WPKH destination), change back to `sk`'s own P2WPKH address.
/// Does not broadcast.
pub fn build_send_tx(
    secp: &Secp256k1<All>,
    sk: &SecretKey,
    coins: &[Coin],
    to_program: [u8; 20],
    sats: u64,
    sat_per_vb: u64,
) -> Result<Transaction, SwapError> {
    if sats < DUST_SATS {
        return Err(SwapError::InvalidParams(format!("amount {sats} is dust")));
    }
    let pk = CompressedPublicKey(sk.public_key(secp));
    let my_spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let to_spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(to_program));
    if to_spk == my_spk {
        return Err(SwapError::InvalidParams(
            "destination is this key's own address".into(),
        ));
    }

    let (chosen, change_opt, _fee) = select_coins(coins, &to_spk, sats, &my_spk, &pk, sat_per_vb)?;
    let mut tx = skeleton(&chosen, &to_spk, sats, change_opt, &my_spk, &pk);
    for (i, c) in chosen.iter().enumerate() {
        let sig = p2wpkh_sign(secp, sk, &tx, i, &my_spk, c.value)?;
        tx.input[i].witness = Witness::from_slice(&[sig, pk.to_bytes().to_vec()]);
    }
    let raw = serialize(&tx);
    for (i, c) in chosen.iter().enumerate() {
        crate::tx::verify_input(&my_spk, i, c.value, &raw)
            .map_err(|e| SwapError::Other(format!("send input {i} fails consensus: {e}")))?;
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use bitcoin::OutPoint;

    use super::*;

    const KEY: [u8; 32] = [0x33; 32];
    const DEST_PROGRAM: [u8; 20] = [0x44; 20];

    fn coin(n: u8, value: u64, confirmed: bool) -> Coin {
        Coin {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([n; 32]), 0),
            value,
            confirmed,
        }
    }

    #[test]
    fn send_builds_signs_and_verifies() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&KEY).unwrap();
        let coins = [coin(1, 50_000, true)];
        let tx = build_send_tx(&secp, &sk, &coins, DEST_PROGRAM, 20_000, 2).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2, "change expected");
        assert_eq!(tx.output[0].value.to_sat(), 20_000);
        assert_eq!(
            tx.output[0].script_pubkey,
            ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(DEST_PROGRAM))
        );
        let pk = CompressedPublicKey(sk.public_key(&secp));
        let my_spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
        let raw = serialize(&tx);
        crate::tx::verify_input(&my_spk, 0, 50_000, &raw).unwrap();
    }

    #[test]
    fn send_folds_dust_change_into_fee() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&KEY).unwrap();
        // 20,000 to spend + ~1 sat/vB fee leaves well under DUST_SATS of change.
        let coins = [coin(1, 20_200, true)];
        let tx = build_send_tx(&secp, &sk, &coins, DEST_PROGRAM, 20_000, 1).unwrap();
        assert_eq!(tx.output.len(), 1, "no dust change output");
    }

    #[test]
    fn send_rejects_dust_amount() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&KEY).unwrap();
        let err = build_send_tx(&secp, &sk, &[], DEST_PROGRAM, 100, 1).unwrap_err();
        assert!(matches!(err, SwapError::InvalidParams(_)), "{err:?}");
    }

    #[test]
    fn send_fails_cleanly_with_no_utxos_at_all() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&KEY).unwrap();
        let err = build_send_tx(&secp, &sk, &[], DEST_PROGRAM, 20_000, 1).unwrap_err();
        assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
    }

    #[test]
    fn send_rejects_own_address_as_destination() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&KEY).unwrap();
        let pk = CompressedPublicKey(sk.public_key(&secp));
        let own_program = pk.wpubkey_hash().to_byte_array();
        let err = build_send_tx(&secp, &sk, &[], own_program, 20_000, 1).unwrap_err();
        assert!(matches!(err, SwapError::InvalidParams(_)), "{err:?}");
    }
}
