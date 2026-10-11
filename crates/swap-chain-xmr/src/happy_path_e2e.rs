// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Build-plan step 8 (`docs/plans/swap-poc/xmr-design.md`): the happy-path, end to end,
//! with throwaway keys — the whole `## Protocol` happy path chained in one test, not
//! scattered across the per-step modules.
//!
//! What this proves: every mechanical step of the design — both DLEQ proofs, both
//! parties' additive Monero key shares, `Tx_cancel`, `Tx_redeem` completing and
//! revealing `s_t` to Maker, and Maker's recovered `s_t` combining with his own `s_m`
//! into the exact Monero group secret — chains together correctly end to end, entirely
//! offline.
//!
//! What this does **not** prove, and why it's out of scope for this lane: actually
//! broadcasting any of this needs funded DIVI testnet coins and a stagenet Monero
//! wallet with real confirmations. Lane rule 5 (`_hp2.md`) is explicit that funded live
//! runs are the orchestrator's, from the Mac, through `secret get` — hp2 has no secrets
//! and no funded keys, by design. `stagenet_rpc`'s `live` feature already proves this
//! crate can *reach* a real stagenet node; actually funding and spending from it is
//! `docs/plans/swap-poc/status/xmr.md`'s parked item, not something this test can do.

#[cfg(test)]
mod tests {
    use ciphersuite::group::ff::PrimeField;
    use ciphersuite::group::GroupEncoding;
    use ciphersuite::{Ciphersuite, Ed25519};
    use divi_crypto::keys::SecretKey;
    use divi_primitives::amount::Amount;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::{OutPoint, TxOut};
    use dkg::Participant;
    use rand::thread_rng;
    use std::collections::HashMap;
    use swap_adaptor::adaptor::{AdaptorSigner, Scalar as SecpScalar};
    use swap_adaptor::dleq::{random_clamped_secret, CrossCurveDleq};

    use crate::monero_key_share::{additive_two_of_two_keys, dleq_secret_to_ed25519_scalar};
    use crate::multisig::{build_presigned_spend, funding_output, redeem_script, script_pubkey};
    use crate::swap_templates::{
        divi_secret_to_adaptor_scalar, maker_encrypts_tx_redeem, recover_secret_from_chain,
        taker_completes_tx_redeem, verify_spend,
    };

    const MAKER: Participant = match Participant::new(1) {
        Some(p) => p,
        None => unreachable!(),
    };
    const TAKER: Participant = match Participant::new(2) {
        Some(p) => p,
        None => unreachable!(),
    };

    #[test]
    fn happy_path_chains_dleq_monero_keys_and_tx_redeem() {
        let mut rng = thread_rng();

        // --- Setup: DIVI-side keys (the {a', b'} pair on Tx_cancel's output) ---
        let maker_divi_key = SecretKey::from_bytes(&[0xAA; 32]).unwrap();
        let taker_divi_key = SecretKey::from_bytes(&[0xBB; 32]).unwrap();
        let redeem = redeem_script(
            &maker_divi_key.public_key().serialize_compressed(),
            &taker_divi_key.public_key().serialize_compressed(),
        );
        let spk = script_pubkey(&redeem);

        // --- Step 1: both DLEQ proofs, one shared (NUMS-in-production, random-in-test)
        // generator instance -- both parties agree on it once at swap setup. ---
        let dleq = CrossCurveDleq::with_random_generators(&mut rng);

        let s_t = random_clamped_secret(&mut rng);
        let (proof_t, (x_point, s_t_ed_point)) = dleq.prove(&s_t, &mut rng);
        assert!(
            dleq.verify(&proof_t, (x_point, s_t_ed_point)),
            "Maker must be able to verify Taker's DLEQ proof before locking anything"
        );

        let s_m = random_clamped_secret(&mut rng);
        let (proof_m, (y_point, s_m_ed_point)) = dleq.prove(&s_m, &mut rng);
        assert!(
            dleq.verify(&proof_m, (y_point, s_m_ed_point)),
            "Taker must be able to verify Maker's DLEQ proof before locking anything"
        );

        // --- Step 1, continued: the Monero spend-key shares are *exactly* the DLEQ's
        // own ed25519 claim points, not independently recomputed -- otherwise the DLEQ
        // proofs wouldn't actually be binding anything to the real Monero key. ---
        let s_t_ed25519 = dleq_secret_to_ed25519_scalar(&s_t);
        let s_m_ed25519 = dleq_secret_to_ed25519_scalar(&s_m);
        let s_t_pub = Ed25519::generator() * s_t_ed25519;
        let s_m_pub = Ed25519::generator() * s_m_ed25519;
        assert_eq!(s_t_ed_point.compress().to_bytes(), s_t_pub.to_bytes());
        assert_eq!(s_m_ed_point.compress().to_bytes(), s_m_pub.to_bytes());

        let verification_shares = HashMap::from([(MAKER, s_m_pub), (TAKER, s_t_pub)]);
        let keys_taker =
            additive_two_of_two_keys(TAKER, s_t_ed25519, verification_shares.clone()).unwrap();
        let keys_maker = additive_two_of_two_keys(MAKER, s_m_ed25519, verification_shares).unwrap();
        let monero_group_key = keys_taker.group_key();
        assert_eq!(monero_group_key, keys_maker.group_key());

        // --- Step 2: Tx_lock (mocked as a bare outpoint -- funding it needs a real
        // DIVI testnet broadcast, out of scope here) pays into {a, b}; Tx_cancel moves
        // it to the same 2-of-2 (reusing one keypair across Tx_lock/_cancel is the
        // design doc's noted, allowed simplification -- fresh keys per leg are a
        // key-reuse hygiene practice, not a protocol requirement). ---
        let tx_lock_outpoint =
            OutPoint::new(divi_primitives::hash::Hash256::from_bytes([7; 32]), 0);
        const T_CANCEL: u32 = 2_000_000_000;
        let tx_cancel = build_presigned_spend(
            tx_lock_outpoint,
            Amount::from_sat(100_000),
            &redeem,
            &maker_divi_key,
            &taker_divi_key,
            funding_output(&redeem, Amount::from_sat(99_000)),
            T_CANCEL,
            divi_swap::htlc::REFUND_SEQUENCE,
        )
        .unwrap();
        verify_spend(&tx_cancel, &spk, Amount::from_sat(100_000)).unwrap();
        assert!(!tx_cancel.is_final(0, T_CANCEL - 1));
        assert!(tx_cancel.is_final(0, T_CANCEL + 1));

        // --- Step 3: Tx_redeem -- Maker encrypts under Taker's X, Taker completes with
        // s_t and broadcasts, claiming the DIVI. ---
        let tx_cancel_outpoint = OutPoint::new(tx_cancel.txid(), 0);
        let taker_payout = TxOut::new(Amount::from_sat(98_000), Script::new_p2pkh(&[9u8; 20]));
        let (tx_redeem_unsigned, maker_encrypted) = maker_encrypts_tx_redeem(
            tx_cancel_outpoint,
            &redeem,
            &maker_divi_key,
            &x_point,
            taker_payout,
            divi_swap::htlc::REFUND_SEQUENCE,
        )
        .unwrap();

        // Taker completes with s_t in its secp256k1 (swap-adaptor) representation --
        // the DLEQ only ever handed her the ed25519-side scalar and the secp256k1-side
        // *point* X, never the secp256k1 scalar itself (that would defeat the proof's
        // purpose); she derives it the same way the DLEQ's own tests do: canonical
        // bytes, reversed (ed25519 is little-endian, secp256kfun is big-endian).
        let s_t_secp = {
            let mut bytes = s_t.to_bytes();
            bytes.reverse();
            SecpScalar::from_bytes(bytes)
                .expect("a DLEQ secret clamped below 2^252 is always a valid secp256k1 scalar")
        };
        let adaptor = AdaptorSigner::new();
        assert_eq!(
            adaptor.verification_key_for(&s_t_secp),
            x_point,
            "Taker's own derived secp256k1 key must match the DLEQ's claimed point X"
        );

        let maker_verification_point =
            adaptor.verification_key_for(&divi_secret_to_adaptor_scalar(&maker_divi_key));
        let tx_redeem = taker_completes_tx_redeem(
            tx_redeem_unsigned,
            &redeem,
            &maker_verification_point,
            maker_encrypted.clone(),
            &taker_divi_key,
            &s_t_secp,
        )
        .unwrap();
        verify_spend(&tx_redeem, &spk, Amount::from_sat(99_000)).unwrap();

        // --- Step 4: Maker recovers s_t from the broadcast Tx_redeem, and combining it
        // with his own s_m reconstructs the full Monero spend secret. ---
        let completed_maker_sig = adaptor.decrypt_signature(&s_t_secp, maker_encrypted.clone());
        let recovered_s_t_secp =
            recover_secret_from_chain(&x_point, &completed_maker_sig, &maker_encrypted)
                .expect("Maker must recover s_t from the broadcast Tx_redeem");
        assert_eq!(recovered_s_t_secp, s_t_secp);

        // Bridge the recovered secp256k1 scalar back to its ed25519 representation --
        // same byte round trip [`crate::monero_key_share::dleq_secret_to_ed25519_scalar`]
        // uses, just starting from the recovered secp256k1 bytes reversed back to
        // little-endian, to confirm Maker ends up with exactly s_t_ed25519 again.
        let recovered_s_t_ed25519 = {
            let mut bytes = recovered_s_t_secp.to_bytes();
            bytes.reverse();
            <Ed25519 as Ciphersuite>::F::from_repr(bytes)
                .expect("recovered s_t must be a canonical Ed25519 scalar")
        };
        assert_eq!(recovered_s_t_ed25519, s_t_ed25519);

        // The actual claim the whole design rests on: Maker, having recovered s_t and
        // already knowing his own s_m, can reconstruct the full Monero private spend
        // key -- (s_m + s_t)*G must equal the group key both sides already agreed on.
        let reconstructed_group_key = Ed25519::generator() * (s_m_ed25519 + recovered_s_t_ed25519);
        assert_eq!(reconstructed_group_key, monero_group_key);
    }
}
