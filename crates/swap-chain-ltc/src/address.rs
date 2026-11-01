// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Litecoin bech32 (segwit v0) address encoding.
//!
//! `bitcoin::Address` only knows the upstream `Network` variants, all of which share the
//! `bc`/`tb` HRPs — Litecoin's `ltc`/`tltc` HRPs need their own thin encoder over the same
//! witness-program bytes. The script and signature-hash rules are otherwise identical to
//! Bitcoin's (brief), so everything downstream of the scriptPubKey bytes reuses `bitcoin`
//! crate types unchanged.

use bech32::{segwit, Hrp};
use divi_swap::SwapError;

/// Litecoin testnet bech32 HRP.
pub const TLTC_HRP: &str = "tltc";
/// Litecoin mainnet bech32 HRP (unused in the POC; kept so the HRP is a single switch).
pub const LTC_HRP: &str = "ltc";

/// Encode a segwit v0 witness program (20 bytes for P2WPKH, 32 for P2WSH) as a bech32
/// address under `hrp` (e.g. [`TLTC_HRP`]).
pub fn encode_segwit_v0(hrp: &str, program: &[u8]) -> Result<String, SwapError> {
    let hrp = Hrp::parse(hrp).map_err(|e| SwapError::Other(format!("bad hrp {hrp:?}: {e}")))?;
    segwit::encode_v0(hrp, program)
        .map_err(|e| SwapError::Other(format!("bech32 segwit encode: {e}")))
}

/// Decode a segwit v0 bech32 address, returning `(hrp, witness_program)`.
pub fn decode_segwit_v0(address: &str) -> Result<(String, Vec<u8>), SwapError> {
    let (hrp, version, program) = segwit::decode(address)
        .map_err(|e| SwapError::InvalidParams(format!("bad segwit address: {e}")))?;
    if version != segwit::VERSION_0 {
        return Err(SwapError::InvalidParams(
            "expected witness version 0".into(),
        ));
    }
    Ok((hrp.to_string(), program))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tltc_address_encoding() {
        let program = [0x11u8; 20];
        let addr = encode_segwit_v0(TLTC_HRP, &program).unwrap();
        assert!(addr.starts_with("tltc1q"), "{addr}");
        let (hrp, decoded) = decode_segwit_v0(&addr).unwrap();
        assert_eq!(hrp, TLTC_HRP);
        assert_eq!(decoded, program);
    }

    #[test]
    fn p2wsh_program_round_trips() {
        let program = [0x22u8; 32];
        let addr = encode_segwit_v0(TLTC_HRP, &program).unwrap();
        let (hrp, decoded) = decode_segwit_v0(&addr).unwrap();
        assert_eq!(hrp, TLTC_HRP);
        assert_eq!(decoded, program);
    }

    #[test]
    fn rejects_bad_hrp() {
        assert!(encode_segwit_v0("", &[0u8; 20]).is_err());
    }

    /// LTC P2WPKH re-encodes the same witness program (hash160 of the pubkey) as the BTC
    /// `tb1…` address under HRP `tltc`, with no private key involved — the invariant
    /// `docs/plans/swap-poc/funding.md` (orchestrator decision 64ae2a0) relies on to reuse
    /// the existing `taker-btc`/`maker-btc` swap keys as the LTC funding addresses. If this
    /// ever fails, `LtcBackend`'s derivation disagrees with that table — stop and report it,
    /// per the orchestrator's instruction, rather than funding the wrong address.
    #[test]
    fn ltc_funding_addresses_match_funding_doc() {
        let cases = [
            (
                "tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg",
                "tltc1qa826ffe73xnqsm64x6fvln7sl0zp3rgf5gnf3p",
            ),
            (
                "tb1quqkt7c06svzt68f2y9uwf2jzgpd48k6ku45zrt",
                "tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz",
            ),
        ];
        for (btc_tb1, want_tltc) in cases {
            let (hrp, program) = decode_segwit_v0(btc_tb1).unwrap();
            assert_eq!(hrp, "tb");
            let got = encode_segwit_v0(TLTC_HRP, &program).unwrap();
            assert_eq!(got, want_tltc, "re-encoding {btc_tb1}");
        }
    }
}
