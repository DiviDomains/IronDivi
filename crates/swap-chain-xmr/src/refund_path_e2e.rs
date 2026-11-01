// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The abort path, end to end, entirely offline — the mirror image of
//! [`crate::happy_path_e2e`]: Taker never (or too slowly) completes `Tx_redeem`, so
//! after `t_cancel` either party broadcasts `Tx_cancel`, and after `t_refund` Maker
//! completes Taker's adaptor-encrypted `Tx_refund` to reclaim his DIVI — which reveals
//! `s_m` to Taker, letting her reconstruct her own Monero spend secret and reclaim her
//! locked XMR herself (`docs/plans/swap-poc/xmr-design.md`'s `## Protocol`, "Maker
//! locks DIVI, Taker locks XMR, then Maker broadcasts `Tx_refund`" failure case).
//!
//! What this proves: the same DLEQ-and-additive-key machinery
//! [`crate::happy_path_e2e`] chains for the redeem direction also chains correctly for
//! the refund direction — `Tx_cancel`, `Tx_refund` completing and revealing `s_m` to
//! Taker, and Taker's recovered `s_m` combining with her own `s_t` into the exact
//! Monero group secret. `swap_templates`'s per-function tests already cover
//! `Tx_refund` in isolation off a bare outpoint; this chains it off a real,
//! template-shaped `Tx_cancel` the way a live swap actually would.
//!
//! What this does **not** prove, same scope note as `happy_path_e2e`: no real
//! broadcast, no real Monero spend of the reconstructed secret — that's
//! [`crate::monero_sweep`]'s job, and it needs funded/live state this offline test
//! doesn't have.

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
        divi_secret_to_adaptor_scalar, maker_completes_tx_refund, recover_secret_from_chain,
        taker_encrypts_tx_refund, verify_spend,
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
    fn refund_path_chains_dleq_monero_keys_and_tx_refund() {
        let mut rng = thread_rng();

        // --- Setup: same as happy_path_e2e -- {a', b'} on Tx_cancel's output. ---
        let maker_divi_key = SecretKey::from_bytes(&[0xCC; 32]).unwrap();
        let taker_divi_key = SecretKey::from_bytes(&[0xDD; 32]).unwrap();
        let redeem = redeem_script(
            &maker_divi_key.public_key().serialize_compressed(),
            &taker_divi_key.public_key().serialize_compressed(),
        );
        let spk = script_pubkey(&redeem);

        // --- Step 1: both DLEQ proofs, same as the happy path -- the abort path needs
        // Maker's s_m <-> Y proof just as much as the happy path needs Taker's, since
        // it's what lets Taker trust Tx_refund actually hands her a usable scalar. ---
        let dleq = CrossCurveDleq::with_random_generators(&mut rng);

        let s_t = random_clamped_secret(&mut rng);
        let (_proof_t, (_x_point, _s_t_ed_point)) = dleq.prove(&s_t, &mut rng);
        let s_m = random_clamped_secret(&mut rng);
        let (proof_m, (y_point, s_m_ed_point)) = dleq.prove(&s_m, &mut rng);
        assert!(
            dleq.verify(&proof_m, (y_point, s_m_ed_point)),
            "Taker must be able to verify Maker's DLEQ proof before locking anything"
        );

        let s_t_ed25519 = dleq_secret_to_ed25519_scalar(&s_t);
        let s_m_ed25519 = dleq_secret_to_ed25519_scalar(&s_m);
        let s_t_pub = Ed25519::generator() * s_t_ed25519;
        let s_m_pub = Ed25519::generator() * s_m_ed25519;
        assert_eq!(s_m_ed_point.compress().to_bytes(), s_m_pub.to_bytes());

        let verification_shares = HashMap::from([(MAKER, s_m_pub), (TAKER, s_t_pub)]);
        let keys_taker =
            additive_two_of_two_keys(TAKER, s_t_ed25519, verification_shares.clone()).unwrap();
        let keys_maker = additive_two_of_two_keys(MAKER, s_m_ed25519, verification_shares).unwrap();
        let monero_group_key = keys_taker.group_key();
        assert_eq!(monero_group_key, keys_maker.group_key());

        // --- Step 2: Tx_lock (mocked, same as happy_path_e2e) -> Tx_cancel, identical
        // shape regardless of which direction the swap eventually resolves. ---
        let tx_lock_outpoint =
            OutPoint::new(divi_primitives::hash::Hash256::from_bytes([8; 32]), 0);
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

        // --- Step 3 (abort branch): Tx_refund -- Taker encrypts under Maker's Y, Maker
        // completes with s_m and broadcasts, reclaiming his DIVI. nLockTime = t_refund,
        // must not be minable before it (the whole point of the cancel/refund delay:
        // gives Tx_redeem a chance to land first if Taker is just slow, not absent). ---
        let tx_cancel_outpoint = OutPoint::new(tx_cancel.txid(), 0);
        const T_REFUND: u32 = 2_000_000_001;
        let maker_payout = TxOut::new(Amount::from_sat(98_000), Script::new_p2pkh(&[6u8; 20]));
        let (tx_refund_unsigned, taker_encrypted) = taker_encrypts_tx_refund(
            tx_cancel_outpoint,
            &redeem,
            &taker_divi_key,
            &y_point,
            maker_payout,
            T_REFUND,
            divi_swap::htlc::REFUND_SEQUENCE,
        )
        .unwrap();

        let s_m_secp = {
            let mut bytes = s_m.to_bytes();
            bytes.reverse();
            SecpScalar::from_bytes(bytes)
                .expect("a DLEQ secret clamped below 2^252 is always a valid secp256k1 scalar")
        };
        let adaptor = AdaptorSigner::new();
        assert_eq!(
            adaptor.verification_key_for(&s_m_secp),
            y_point,
            "Maker's own derived secp256k1 key must match the DLEQ's claimed point Y"
        );

        let taker_verification_point =
            adaptor.verification_key_for(&divi_secret_to_adaptor_scalar(&taker_divi_key));
        let tx_refund = maker_completes_tx_refund(
            tx_refund_unsigned,
            &redeem,
            &taker_verification_point,
            taker_encrypted.clone(),
            &maker_divi_key,
            &s_m_secp,
        )
        .unwrap();
        verify_spend(&tx_refund, &spk, Amount::from_sat(99_000)).unwrap();
        assert!(
            !tx_refund.is_final(0, T_REFUND - 1),
            "must not be minable before t_refund"
        );
        assert!(tx_refund.is_final(0, T_REFUND + 1));

        // --- Step 4 (abort branch): Taker recovers s_m from the broadcast Tx_refund,
        // and combining it with her own s_t reconstructs the full Monero spend secret
        // -- the mechanism that keeps her from being stranded when Maker backs out. ---
        let completed_taker_sig = adaptor.decrypt_signature(&s_m_secp, taker_encrypted.clone());
        let recovered_s_m_secp =
            recover_secret_from_chain(&y_point, &completed_taker_sig, &taker_encrypted)
                .expect("Taker must recover s_m from the broadcast Tx_refund");
        assert_eq!(recovered_s_m_secp, s_m_secp);

        let recovered_s_m_ed25519 = {
            let mut bytes = recovered_s_m_secp.to_bytes();
            bytes.reverse();
            <Ed25519 as Ciphersuite>::F::from_repr(bytes)
                .expect("recovered s_m must be a canonical Ed25519 scalar")
        };
        assert_eq!(recovered_s_m_ed25519, s_m_ed25519);

        // Taker, having recovered s_m and already knowing her own s_t, reconstructs the
        // full Monero private spend key -- (s_t + s_m)*G must equal the same group key
        // both sides agreed on at setup, same identity as the happy path's, just
        // assembled by the other party.
        let reconstructed_group_key = Ed25519::generator() * (s_t_ed25519 + recovered_s_m_ed25519);
        assert_eq!(reconstructed_group_key, monero_group_key);
    }
}
