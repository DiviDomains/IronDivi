// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Divi Core's per-transaction coin record (`CCoins`, coins.h:74-232), as
//! `gettxoutsetinfo` sizes and hashes it (txdb.cpp:105-157).
//!
//! irondivid stores one record per output; Core stores one per transaction,
//! holding its unspent outputs. [`CoreCoins`] rebuilds Core's record from the
//! outputs of one transaction so both values can be computed as Core does.

use crate::utxo::Utxo;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::TxOut;

/// Script compression codes below this are special forms (compressor.h:37)
const SPECIAL_SCRIPTS: u64 = 6;

/// Bitcoin's `WriteVarInt` (serialize.h): MSB base-128, each continuation
/// byte one less than plain base-128
pub fn write_varint(out: &mut Vec<u8>, n: i64) {
    let mut n = n;
    let mut tmp = [0u8; 10];
    let mut len = 0;
    loop {
        tmp[len] = (n & 0x7f) as u8 | if len > 0 { 0x80 } else { 0 };
        if n <= 0x7f {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    out.extend(tmp[..=len].iter().rev());
}

/// `CTxOutCompressor::CompressAmount` (compressor.cpp:137-154)
pub fn compress_amount(mut n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut e = 0;
    while n.is_multiple_of(10) && e < 9 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = n % 10;
        n /= 10;
        1 + (n * 9 + d - 1) * 10 + e
    } else {
        1 + (n - 1) * 10 + 9
    }
}

/// `CScriptCompressor` (compressor.cpp:12-72, compressor.h:70-82): a
/// pay-to-key-hash, pay-to-script-hash or pay-to-key script in its short
/// form, any other script as VARINT(size + 6) and its bytes
fn write_compressed_script(out: &mut Vec<u8>, script: &[u8]) {
    const OP_DUP: u8 = 0x76;
    const OP_HASH160: u8 = 0xa9;
    const OP_EQUALVERIFY: u8 = 0x88;
    const OP_CHECKSIG: u8 = 0xac;
    const OP_EQUAL: u8 = 0x87;
    match script {
        [OP_DUP, OP_HASH160, 20, hash @ .., OP_EQUALVERIFY, OP_CHECKSIG] if hash.len() == 20 => {
            out.push(0x00);
            out.extend_from_slice(hash);
            return;
        }
        [OP_HASH160, 20, hash @ .., OP_EQUAL] if hash.len() == 20 => {
            out.push(0x01);
            out.extend_from_slice(hash);
            return;
        }
        [33, key @ .., OP_CHECKSIG] if key.len() == 33 && (key[0] == 0x02 || key[0] == 0x03) => {
            out.extend_from_slice(key);
            return;
        }
        [65, key @ .., OP_CHECKSIG]
            if key.len() == 65
                && key[0] == 0x04
                && divi_crypto::PublicKey::from_uncompressed(key).is_ok() =>
        {
            out.push(0x04 | (key[64] & 0x01));
            out.extend_from_slice(&key[1..33]);
            return;
        }
        _ => {}
    }
    write_varint(out, (script.len() as u64 + SPECIAL_SCRIPTS) as i64);
    out.extend_from_slice(script);
}

/// The unspent outputs of one transaction, as Divi Core keeps them in its
/// coin database
pub struct CoreCoins {
    pub version: i32,
    pub height: u32,
    pub coinbase: bool,
    pub coinstake: bool,
    /// `(vout, output)` in vout order, without spent outputs and without
    /// unspendable (OP_META) outputs, which Core drops (coins.cpp:54-61)
    pub outputs: Vec<(u32, TxOut)>,
}

impl CoreCoins {
    /// The record of one transaction from its irondivid records, in any vout
    /// order; `None` when none of them is kept by Core
    pub fn from_records(records: &mut [(u32, Utxo)]) -> Option<Self> {
        records.sort_by_key(|(vout, _)| *vout);
        let mut outputs = Vec::with_capacity(records.len());
        let mut first: Option<&Utxo> = None;
        for (vout, utxo) in records.iter() {
            if utxo.script_pubkey.is_op_return() {
                continue;
            }
            first.get_or_insert(utxo);
            outputs.push((*vout, TxOut::new(utxo.value, utxo.script_pubkey.clone())));
        }
        let first = first?;
        Some(CoreCoins {
            version: first.version,
            height: first.height,
            coinbase: first.is_coinbase,
            coinstake: first.is_coinstake,
            outputs,
        })
    }

    /// The record as Core writes it to disk (`CCoins::Serialize`,
    /// coins.h:165-192)
    pub fn disk_bytes(&self) -> Vec<u8> {
        let has = |vout: u32| self.outputs.iter().any(|(v, _)| *v == vout);
        let first = has(0);
        let second = has(1);
        // Availability bitmask for vout 2 and later, least significant byte first,
        // up to the last byte that has a bit set (`CCoins::CalcMaskSize`, coins.cpp:100-117)
        let mut mask: Vec<u8> = Vec::new();
        for (vout, _) in &self.outputs {
            if *vout >= 2 {
                let bit = (*vout - 2) as usize;
                if mask.len() <= bit / 8 {
                    mask.resize(bit / 8 + 1, 0);
                }
                mask[bit / 8] |= 1 << (bit % 8);
            }
        }
        let nonzero = mask.iter().filter(|b| **b != 0).count() as i64;
        let code = 16 * (nonzero - if first || second { 0 } else { 1 })
            + if self.coinbase { 1 } else { 0 }
            + if self.coinstake { 2 } else { 0 }
            + if first { 4 } else { 0 }
            + if second { 8 } else { 0 };

        let mut out = Vec::new();
        write_varint(&mut out, self.version as i64);
        write_varint(&mut out, code);
        out.extend_from_slice(&mask);
        for (_, txout) in &self.outputs {
            write_varint(
                &mut out,
                compress_amount(txout.value.as_sat() as u64) as i64,
            );
            write_compressed_script(&mut out, txout.script_pubkey.as_bytes());
        }
        write_varint(&mut out, self.height as i64);
        out
    }

    /// What `CCoinsViewDB::GetStats` feeds its hash for this record after the
    /// txid (txdb.cpp:131-146)
    pub fn write_stats_entry(&self, out: &mut Vec<u8>) {
        write_varint(out, self.version as i64);
        out.push(if self.coinbase { b'c' } else { b'n' });
        write_varint(out, self.height as i64);
        for (vout, txout) in &self.outputs {
            write_varint(out, *vout as i64 + 1);
            out.extend_from_slice(&serialize(txout));
        }
        write_varint(out, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::amount::Amount;
    use divi_primitives::script::Script;

    fn varint(n: i64) -> String {
        let mut out = Vec::new();
        write_varint(&mut out, n);
        hex::encode(out)
    }

    #[test]
    fn varint_as_core_writes_it() {
        assert_eq!(varint(0), "00");
        assert_eq!(varint(0x7f), "7f");
        assert_eq!(varint(0x80), "8000");
        assert_eq!(varint(0x1234), "a334");
        assert_eq!(varint(0xffff), "82fe7f");
    }

    #[test]
    fn amounts_compress_as_core() {
        assert_eq!(compress_amount(0), 0);
        assert_eq!(compress_amount(1), 1);
        assert_eq!(compress_amount(100_000_000), 9);
        // 600, written as VARINT 8358 in coins.h:50
        assert_eq!(compress_amount(60_000_000_000), 600);
    }

    /// The two records described in coins.h:41-72. That comment was written
    /// for Bitcoin's header code; Divi's (coins.h:172) takes bit 2 for a
    /// coinstake, so vout 0 is bit 4, vout 1 bit 8 and the mask size counts
    /// in steps of 16: code 4 becomes 8, code 9 becomes 0x11
    #[test]
    fn records_from_the_core_header_comment() {
        let p2pkh = |h: &str| Script::new_p2pkh(&hex::decode(h).unwrap().try_into().unwrap());
        let one = CoreCoins {
            version: 1,
            height: 203998,
            coinbase: false,
            coinstake: false,
            outputs: vec![(
                1,
                TxOut::new(
                    Amount::from_sat(60_000_000_000),
                    p2pkh("816115944e077fe7c803cfa57f29b36bf87c1d35"),
                ),
            )],
        };
        assert_eq!(
            hex::encode(one.disk_bytes()),
            "0108835800816115944e077fe7c803cfa57f29b36bf87c1d358bb85e"
        );

        let two = CoreCoins {
            version: 1,
            height: 120891,
            coinbase: true,
            coinstake: false,
            outputs: vec![
                (
                    4,
                    TxOut::new(
                        Amount::from_sat(234_925_952),
                        p2pkh("61b01caab50f1b8e9c50a5057eb43c2d9563a4ee"),
                    ),
                ),
                (
                    16,
                    TxOut::new(
                        Amount::from_sat(110_397),
                        p2pkh("8c988f1a4a4de2161e0f50aac7f17e7f9555caa4"),
                    ),
                ),
            ],
        };
        assert_eq!(
            hex::encode(two.disk_bytes()),
            "0111044086ef97d5790061b01caab50f1b8e9c50a5057eb43c2d9563a4eebbd123008c988f1a4a4de2161e0f50aac7f17e7f9555caa486af3b"
        );
    }

    #[test]
    fn op_meta_outputs_are_dropped() {
        let mut records = vec![(
            0,
            Utxo::new(
                Amount::from_sat(0),
                Script::from_bytes(vec![0x6a, 1, 2]),
                5,
                false,
                false,
            ),
        )];
        assert!(CoreCoins::from_records(&mut records).is_none());
    }
}
