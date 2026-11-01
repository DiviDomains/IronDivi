// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `xmr-design.md`'s `## Protocol` `### Roles` (updated 2026-10-12): Maker/Taker name the
//! **crypto-protocol** role (whoever locks DIVI first vs. whoever locks XMR), not a fixed
//! business identity. [`crate::happy_path_e2e`] already proves the "sell XMR" direction
//! (business-taker locks XMR, business-maker locks DIVI first). This proves the other
//! direction a market also needs — "buy XMR" (business-taker locks DIVI first and ends up
//! with the Monero; business-maker locks XMR and ends up with the DIVI) — using the exact
//! same [`crate::swap_templates`]/[`crate::multisig`] functions, just with the business
//! party in each crypto-role slot swapped. Nothing in those functions' signatures (plain
//! `SecretKey`/`Point`/`Scalar` arguments, no identity type) distinguishes the two; this test
//! is the evidence for that claim, not a code change to make it true.

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

    // Crypto-protocol participant IDs for the Monero additive key share -- same two slots
    // `happy_path_e2e` uses, just relabeled here to the crypto role each business party now
    // takes, so a reader can tell at a glance which business party sits in which slot.
    const CRYPTO_MAKER: Participant = match Participant::new(1) {
        Some(p) => p,
        None => unreachable!(),
    };
    const CRYPTO_TAKER: Participant = match Participant::new(2) {
        Some(p) => p,
        None => unreachable!(),
    };

    /// Buy-XMR direction: business-taker locks DIVI first, so *she* calls the `maker_*`
    /// functions and takes the crypto-Maker role; business-maker locks XMR and calls the
    /// `taker_*` functions as crypto-Taker. Completing the happy path must still pay the DIVI
    /// to the crypto-Taker slot (now business-maker) and hand the reconstructed Monero secret
    /// to the crypto-Maker slot (now business-taker) -- the mirror image of
    /// `happy_path_e2e`'s outcome, proving the swap is symmetric in business identity.
    #[test]
    fn buy_xmr_direction_business_taker_as_crypto_maker_chains_end_to_end() {
        let mut rng = thread_rng();

        // --- Setup: DIVI-side keys ({a', b'} on Tx_cancel's output). business_taker_divi_key
        // plays crypto-Maker (locks DIVI first); business_maker_divi_key plays crypto-Taker
        // (locks XMR). Swapped from happy_path_e2e's assignment on purpose. ---
        let business_taker_divi_key = SecretKey::from_bytes(&[0xCC; 32]).unwrap();
        let business_maker_divi_key = SecretKey::from_bytes(&[0xDD; 32]).unwrap();
        let redeem = redeem_script(
            &business_taker_divi_key.public_key().serialize_compressed(),
            &business_maker_divi_key.public_key().serialize_compressed(),
        );
        let spk = script_pubkey(&redeem);

        // --- Step 1: both DLEQ proofs. s_t/X is the crypto-Taker's secret/point (now
        // business-maker's); s_m/Y is the crypto-Maker's (now business-taker's) -- same
        // naming convention `swap_templates` itself uses, independent of business identity.
        let dleq = CrossCurveDleq::with_random_generators(&mut rng);

        let s_t = random_clamped_secret(&mut rng); // business-maker's (crypto-Taker)
        let (proof_t, (x_point, s_t_ed_point)) = dleq.prove(&s_t, &mut rng);
        assert!(
            dleq.verify(&proof_t, (x_point, s_t_ed_point)),
            "crypto-Maker (business-taker) must be able to verify crypto-Taker's DLEQ proof"
        );

        let s_m = random_clamped_secret(&mut rng); // business-taker's (crypto-Maker)
        let (proof_m, (y_point, s_m_ed_point)) = dleq.prove(&s_m, &mut rng);
        assert!(
            dleq.verify(&proof_m, (y_point, s_m_ed_point)),
            "crypto-Taker (business-maker) must be able to verify crypto-Maker's DLEQ proof"
        );

        let s_t_ed25519 = dleq_secret_to_ed25519_scalar(&s_t);
        let s_m_ed25519 = dleq_secret_to_ed25519_scalar(&s_m);
        let s_t_pub = Ed25519::generator() * s_t_ed25519;
        let s_m_pub = Ed25519::generator() * s_m_ed25519;
        assert_eq!(s_t_ed_point.compress().to_bytes(), s_t_pub.to_bytes());
        assert_eq!(s_m_ed_point.compress().to_bytes(), s_m_pub.to_bytes());

        let verification_shares = HashMap::from([(CRYPTO_MAKER, s_m_pub), (CRYPTO_TAKER, s_t_pub)]);
        let keys_crypto_taker =
            additive_two_of_two_keys(CRYPTO_TAKER, s_t_ed25519, verification_shares.clone())
                .unwrap();
        let keys_crypto_maker =
            additive_two_of_two_keys(CRYPTO_MAKER, s_m_ed25519, verification_shares).unwrap();
        let monero_group_key = keys_crypto_taker.group_key();
        assert_eq!(monero_group_key, keys_crypto_maker.group_key());

        // --- Step 2: Tx_lock (mocked as a bare outpoint) pays into {a, b}; Tx_cancel moves
        // it to the same 2-of-2. business_taker signs first (she's the DIVI locker). ---
        let tx_lock_outpoint =
            OutPoint::new(divi_primitives::hash::Hash256::from_bytes([8; 32]), 0);
        const T_CANCEL: u32 = 2_000_000_000;
        let tx_cancel = build_presigned_spend(
            tx_lock_outpoint,
            Amount::from_sat(100_000),
            &redeem,
            &business_taker_divi_key,
            &business_maker_divi_key,
            funding_output(&redeem, Amount::from_sat(99_000)),
            T_CANCEL,
            divi_swap::htlc::REFUND_SEQUENCE,
        )
        .unwrap();
        verify_spend(&tx_cancel, &spk, Amount::from_sat(100_000)).unwrap();
        assert!(!tx_cancel.is_final(0, T_CANCEL - 1));
        assert!(tx_cancel.is_final(0, T_CANCEL + 1));

        // --- Step 3: Tx_redeem -- business-taker (crypto-Maker) encrypts under business
        // -maker's (crypto-Taker's) X, business-maker completes with s_t and broadcasts,
        // claiming the DIVI. The DIVI payout goes to business-maker here -- the mirror of
        // happy_path_e2e, where it goes to the business-taker. ---
        let tx_cancel_outpoint = OutPoint::new(tx_cancel.txid(), 0);
        let business_maker_payout =
            TxOut::new(Amount::from_sat(98_000), Script::new_p2pkh(&[10u8; 20]));
        let (tx_redeem_unsigned, crypto_maker_encrypted) = maker_encrypts_tx_redeem(
            tx_cancel_outpoint,
            &redeem,
            &business_taker_divi_key,
            &x_point,
            business_maker_payout,
            divi_swap::htlc::REFUND_SEQUENCE,
        )
        .unwrap();

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
            "business-maker's own derived secp256k1 key must match the DLEQ's claimed point X"
        );

        let crypto_maker_verification_point =
            adaptor.verification_key_for(&divi_secret_to_adaptor_scalar(&business_taker_divi_key));
        let tx_redeem = taker_completes_tx_redeem(
            tx_redeem_unsigned,
            &redeem,
            &crypto_maker_verification_point,
            crypto_maker_encrypted.clone(),
            &business_maker_divi_key,
            &s_t_secp,
        )
        .unwrap();
        verify_spend(&tx_redeem, &spk, Amount::from_sat(99_000)).unwrap();

        // --- Step 4: business-taker (crypto-Maker) recovers s_t from the broadcast
        // Tx_redeem, and combining it with her own s_m reconstructs the full Monero spend
        // secret -- she bought the XMR with the DIVI she locked. ---
        let completed_crypto_maker_sig =
            adaptor.decrypt_signature(&s_t_secp, crypto_maker_encrypted.clone());
        let recovered_s_t_secp = recover_secret_from_chain(
            &x_point,
            &completed_crypto_maker_sig,
            &crypto_maker_encrypted,
        )
        .expect("business-taker (crypto-Maker) must recover s_t from the broadcast Tx_redeem");
        assert_eq!(recovered_s_t_secp, s_t_secp);

        let recovered_s_t_ed25519 = {
            let mut bytes = recovered_s_t_secp.to_bytes();
            bytes.reverse();
            <Ed25519 as Ciphersuite>::F::from_repr(bytes)
                .expect("recovered s_t must be a canonical Ed25519 scalar")
        };
        assert_eq!(recovered_s_t_ed25519, s_t_ed25519);

        // The buy-XMR claim this test exists to prove: business-taker, having locked DIVI
        // first and recovered s_t, can reconstruct the full Monero private spend key from her
        // own s_m plus the recovered s_t -- (s_m + s_t)*G must equal the group key both sides
        // already agreed on. Same equation as happy_path_e2e's, just with the business party
        // on each side of it swapped.
        let reconstructed_group_key = Ed25519::generator() * (s_m_ed25519 + recovered_s_t_ed25519);
        assert_eq!(reconstructed_group_key, monero_group_key);
    }
}
