// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Pure transaction building and signing (no I/O): HTLC funding, claim and refund. Every
//! spend is verified with libbitcoinconsensus before it is returned.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize;
use bitcoin::ecdsa::Signature;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use divi_swap::htlc::REFUND_SEQUENCE;
use divi_swap::{HtlcParams, SwapError};
use sha2::{Digest, Sha256};

/// Outputs below this are non-standard dust (P2WPKH).
pub const DUST_SATS: u64 = 294;

/// Placeholder DER signature + sighash byte used to measure vsize before signing.
const DUMMY_SIG: [u8; 72] = [0u8; 72];

/// A spendable P2WPKH coin of the engine key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coin {
    /// The coin.
    pub outpoint: OutPoint,
    /// Value in satoshis.
    pub value: u64,
    /// Whether it is in a block.
    pub confirmed: bool,
}

/// The P2WSH script pubkey of an HTLC.
pub fn htlc_script_pubkey(htlc: &HtlcParams) -> ScriptBuf {
    ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(htlc.redeem_script()).wscript_hash())
}

/// Result of a funding build.
#[derive(Debug, Clone)]
pub struct BuiltFunding {
    /// Signed transaction.
    pub tx: Transaction,
    /// Index of the HTLC output.
    pub htlc_vout: u32,
    /// Fee paid, sats.
    pub fee: u64,
}

fn ceil_fee(sat_per_vb: u64, vsize: usize) -> u64 {
    sat_per_vb.max(1) * vsize as u64
}

fn p2wpkh_sign(
    secp: &Secp256k1<All>,
    sk: &SecretKey,
    tx: &Transaction,
    idx: usize,
    my_spk: &ScriptBuf,
    value: u64,
) -> Result<Vec<u8>, SwapError> {
    let h = SighashCache::new(tx)
        .p2wpkh_signature_hash(idx, my_spk, Amount::from_sat(value), EcdsaSighashType::All)
        .map_err(|e| SwapError::Other(format!("p2wpkh sighash: {e}")))?;
    let sig = secp.sign_ecdsa(&Message::from_digest(h.to_byte_array()), sk);
    Ok(Signature::sighash_all(sig).to_vec())
}

fn input(outpoint: OutPoint, sequence: Sequence) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence,
        witness: Witness::new(),
    }
}

/// Select coins (confirmed first, then largest first), pay `amount` to the HTLC, send
/// change to `sk`'s P2WPKH address, and sign.
pub fn build_funding_tx(
    secp: &Secp256k1<All>,
    sk: &SecretKey,
    coins: &[Coin],
    htlc: &HtlcParams,
    amount: u64,
    sat_per_vb: u64,
) -> Result<BuiltFunding, SwapError> {
    htlc.validate()?;
    if amount < DUST_SATS {
        return Err(SwapError::InvalidParams(format!("amount {amount} is dust")));
    }
    let pk = CompressedPublicKey(sk.public_key(secp));
    let my_spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let mut sorted = coins.to_vec();
    sorted.sort_by(|a, b| b.confirmed.cmp(&a.confirmed).then(b.value.cmp(&a.value)));

    let mut chosen: Vec<Coin> = Vec::new();
    let mut total = 0u64;
    let mut needed = 0u64;
    for c in sorted {
        chosen.push(c);
        total += c.value;
        let probe = skeleton(&chosen, htlc, amount, Some(0), &my_spk, &pk);
        needed = amount + ceil_fee(sat_per_vb, probe.vsize());
        if total >= needed {
            break;
        }
    }
    if total < needed {
        return Err(SwapError::InsufficientFunds(format!(
            "have {total} sats, need {needed} (amount {amount} + fee)"
        )));
    }

    let fee_with_change = needed - amount;
    let change = total - needed;
    let (change_opt, fee) = if change >= DUST_SATS {
        (Some(change), fee_with_change)
    } else {
        (None, total - amount)
    };
    let mut tx = skeleton(&chosen, htlc, amount, change_opt, &my_spk, &pk);
    for (i, c) in chosen.iter().enumerate() {
        let sig = p2wpkh_sign(secp, sk, &tx, i, &my_spk, c.value)?;
        tx.input[i].witness = Witness::from_slice(&[sig, pk.to_bytes().to_vec()]);
    }
    let raw = serialize(&tx);
    for (i, c) in chosen.iter().enumerate() {
        bitcoin::consensus::verify_script(&my_spk, i, Amount::from_sat(c.value), &raw)
            .map_err(|e| SwapError::Other(format!("funding input {i} fails consensus: {e:?}")))?;
    }
    Ok(BuiltFunding {
        tx,
        htlc_vout: 0,
        fee,
    })
}

/// Unsigned funding skeleton with dummy witnesses so `vsize()` is representative.
fn skeleton(
    chosen: &[Coin],
    htlc: &HtlcParams,
    amount: u64,
    change: Option<u64>,
    my_spk: &ScriptBuf,
    pk: &CompressedPublicKey,
) -> Transaction {
    let mut output = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: htlc_script_pubkey(htlc),
    }];
    if let Some(c) = change {
        output.push(TxOut {
            value: Amount::from_sat(c),
            script_pubkey: my_spk.clone(),
        });
    }
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: chosen
            .iter()
            .map(|c| {
                let mut i = input(c.outpoint, Sequence::MAX);
                i.witness = Witness::from_slice(&[DUMMY_SIG.to_vec(), pk.to_bytes().to_vec()]);
                i
            })
            .collect(),
        output,
    }
}

/// Which spend path to build.
#[derive(Debug, Clone, Copy)]
pub enum Spend<'a> {
    /// Claim with the preimage.
    Claim(&'a [u8; 32]),
    /// Refund after the locktime.
    Refund,
}

/// Build, sign and consensus-verify a claim or refund of the HTLC output `at` (`amount`
/// sats), paying `amount − fee` to the key's own P2WPKH address.
pub fn build_spend_tx(
    secp: &Secp256k1<All>,
    sk: &SecretKey,
    htlc: &HtlcParams,
    at: OutPoint,
    amount: u64,
    spend: Spend<'_>,
    sat_per_vb: u64,
) -> Result<Transaction, SwapError> {
    htlc.validate()?;
    let pk = CompressedPublicKey(sk.public_key(secp));
    let (expected, role) = match spend {
        Spend::Claim(_) => (htlc.claim_pubkey, "claim"),
        Spend::Refund => (htlc.refund_pubkey, "refund"),
    };
    if pk.to_bytes() != expected {
        return Err(SwapError::InvalidParams(format!(
            "backend key is not the HTLC {role} key"
        )));
    }
    if let Spend::Claim(pre) = spend {
        let h: [u8; 32] = Sha256::digest(pre).into();
        if h != htlc.hash {
            return Err(SwapError::InvalidParams(
                "preimage does not hash to the HTLC hash".into(),
            ));
        }
    }
    let ws = ScriptBuf::from_bytes(htlc.redeem_script());
    let witness_for = |sig: Vec<u8>| match spend {
        Spend::Claim(pre) => Witness::from_slice(&[sig, pre.to_vec(), vec![1], ws.to_bytes()]),
        Spend::Refund => Witness::from_slice(&[sig, vec![], ws.to_bytes()]),
    };
    let (lock_time, sequence) = match spend {
        Spend::Claim(_) => (LockTime::ZERO, Sequence::MAX),
        Spend::Refund => (
            LockTime::from_time(htlc.locktime)
                .map_err(|e| SwapError::InvalidParams(format!("locktime: {e}")))?,
            Sequence(REFUND_SEQUENCE),
        ),
    };
    let my_spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time,
        input: vec![input(at, sequence)],
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: my_spk,
        }],
    };
    tx.input[0].witness = witness_for(DUMMY_SIG.to_vec());
    let fee = ceil_fee(sat_per_vb, tx.vsize());
    let out = amount.checked_sub(fee).filter(|v| *v >= DUST_SATS);
    let out = out.ok_or_else(|| {
        SwapError::InsufficientFunds(format!("HTLC value {amount} does not cover fee {fee}"))
    })?;
    tx.output[0].value = Amount::from_sat(out);

    let h = SighashCache::new(&tx)
        .p2wsh_signature_hash(0, &ws, Amount::from_sat(amount), EcdsaSighashType::All)
        .map_err(|e| SwapError::Other(format!("p2wsh sighash: {e}")))?;
    let sig = secp.sign_ecdsa(&Message::from_digest(h.to_byte_array()), sk);
    tx.input[0].witness = witness_for(Signature::sighash_all(sig).to_vec());
    verify_htlc_spend(&tx, htlc, amount)?;
    Ok(tx)
}

/// Run libbitcoinconsensus over input 0 of `tx` against the HTLC's P2WSH output.
pub fn verify_htlc_spend(
    tx: &Transaction,
    htlc: &HtlcParams,
    amount: u64,
) -> Result<(), SwapError> {
    bitcoin::consensus::verify_script(
        &htlc_script_pubkey(htlc),
        0,
        Amount::from_sat(amount),
        &serialize(tx),
    )
    .map_err(|e| SwapError::Rejected(format!("spend fails consensus verification: {e:?}")))
}
