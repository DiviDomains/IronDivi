// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Build-plan step 6 (`docs/plans/swap-poc/xmr-design.md`): wiring `swap-adaptor`'s
//! cross-group-DLEQ secret into one party's half of the 2-of-2 Monero spend key.
//!
//! [`monero_dkg`](crate::monero_dkg) built this on `dkg-pedpop` (the PedPoP/FROST
//! protocol), which turned out to be the wrong tool here (consulted the `oracle` on
//! this — a genuine consensus/crypto-shape doubt, per lane rule 7): PedPoP's final
//! secret share is a **Lagrange** share (`dkg-pedpop`'s `KeyMachine::calculate_share`
//! ends with `ThresholdKeys::new(.., Interpolation::Lagrange, ..)`), an aggregate of
//! both parties' polynomial evaluations — there is no way to make a party's resulting
//! share *equal* a scalar they chose and proved via DLEQ beforehand, which is exactly
//! what the swap needs (Taker must pick `x`, prove it dual-curve, and have `x` itself
//! — not some derived aggregate — be their Monero contribution).
//!
//! The actual Gugger/COMIT/Farcaster construction is simpler than PedPoP: **additive**
//! 2-of-2, `S = s_m*G + s_t*G`, each party freely choosing their own half. The `dkg`
//! crate supports this natively via [`dkg::Interpolation::Constant`] (legal exactly
//! when `t == n`, which 2-of-2 always is) — no Lagrange, no interactive secret-sharing
//! round at all, and the result is still a `dkg::ThresholdKeys<Ed25519>` that plugs into
//! `monero_wallet::send::multisig` exactly like [`monero_dkg`](crate::monero_dkg)'s did
//! (that signing code only ever calls `interpolation_factor`, never assumes Lagrange —
//! checked its source, not assumed).
//!
//! [`monero_dkg`](crate::monero_dkg)'s PedPoP round trip stays as a reference test that
//! the DKG dependency stack works; it is not this swap's actual key-generation path.

use ciphersuite::group::ff::{Field, PrimeField};
use ciphersuite::Ciphersuite;
use ciphersuite::Ed25519;
use dkg::{DkgError, Interpolation, Participant, ThresholdKeys, ThresholdParams};
use std::collections::HashMap;
use swap_adaptor::dleq::ScalarQ;
use zeroize::Zeroizing;

/// Convert a `swap-adaptor` DLEQ secret (`curve25519-dalek-ng`'s `Scalar`, clamped
/// below 2^252 — see [`swap_adaptor::dleq::random_clamped_secret`]) into the Ed25519
/// scalar type `monero-wallet`'s `ciphersuite::Ed25519` actually uses
/// (`dalek_ff_group::Scalar`, over mainstream `curve25519-dalek`). Both crates are the
/// same field (order ℓ) with the same canonical little-endian 32-byte encoding; this is
/// a pure re-encode, not a cryptographic conversion. Panics if `x` somehow isn't
/// canonical for the target type, which [`swap_adaptor::dleq::random_clamped_secret`]'s
/// clamp (< 2^252, well inside ℓ) guarantees can't happen.
pub fn dleq_secret_to_ed25519_scalar(x: &ScalarQ) -> <Ed25519 as Ciphersuite>::F {
    <Ed25519 as Ciphersuite>::F::from_repr(x.to_bytes())
        .expect("a DLEQ secret clamped below 2^252 is always a canonical Ed25519 scalar")
}

/// Build one party's additive 2-of-2 [`ThresholdKeys`]: `my_share` is this party's
/// private contribution (for Taker, [`dleq_secret_to_ed25519_scalar`] of their DLEQ
/// secret; for Maker, any freely-chosen scalar), `verification_shares` is both
/// parties' *public* contributions (`my_share * G` and the counterparty's, keyed by
/// [`Participant`]). Both parties must agree on the same `(t=2, n=2, index)` scheme and
/// the same `verification_shares` map — `xmr-design.md`'s key-exchange step.
pub fn additive_two_of_two_keys(
    my_index: Participant,
    my_share: <Ed25519 as Ciphersuite>::F,
    verification_shares: HashMap<Participant, <Ed25519 as Ciphersuite>::G>,
) -> Result<ThresholdKeys<Ed25519>, DkgError> {
    let params = ThresholdParams::new(2, 2, my_index).expect("t=n=2, i in 1..=2");
    ThresholdKeys::new(
        params,
        Interpolation::Constant(vec![<Ed25519 as Ciphersuite>::F::ONE; 2]),
        Zeroizing::new(my_share),
        verification_shares,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use std::ops::Deref;
    use swap_adaptor::dleq::{random_clamped_secret, CrossCurveDleq};

    const MAKER: Participant = match Participant::new(1) {
        Some(p) => p,
        None => unreachable!(),
    };
    const TAKER: Participant = match Participant::new(2) {
        Some(p) => p,
        None => unreachable!(),
    };

    /// The byte round-trip in [`dleq_secret_to_ed25519_scalar`] must land on *the same
    /// point* the DLEQ proof itself claims for the ed25519 side — if the encodings
    /// disagreed (e.g. a byte-order mistake), this would catch it even though both
    /// individually "work" in their own crate.
    #[test]
    fn converted_scalar_matches_dleq_claimed_point() {
        let mut rng = thread_rng();
        let dleq = CrossCurveDleq::with_random_generators(&mut rng);
        let x = random_clamped_secret(&mut rng);
        let (_proof, (_secp_point, ed_point)) = dleq.prove(&x, &mut rng);

        let x_ed = dleq_secret_to_ed25519_scalar(&x);
        let rebuilt_point = Ed25519::generator() * x_ed;

        // Compare via compressed bytes: ed_point is curve25519-dalek-ng's EdwardsPoint,
        // rebuilt_point is dalek_ff_group's (mainstream curve25519-dalek) -- different
        // physical crate versions, so bridge through the canonical compressed encoding
        // rather than trying to compare the types directly.
        use ciphersuite::group::GroupEncoding;
        assert_eq!(ed_point.compress().to_bytes(), rebuilt_point.to_bytes());
    }

    /// Taker's DLEQ secret becomes their literal Monero key share (not some PedPoP-style
    /// aggregate); Maker picks their own share freely; both derive the identical,
    /// additive group key `S = s_m*G + s_t*G` -- the property step 6 needed and PedPoP
    /// (module docs) couldn't provide.
    #[test]
    fn taker_dleq_secret_becomes_their_additive_monero_share() {
        let mut rng = thread_rng();

        // Taker's adaptor secret, proven dual-curve via the DLEQ (as Tx_redeem would).
        let dleq = CrossCurveDleq::with_random_generators(&mut rng);
        let x = random_clamped_secret(&mut rng);
        let (_proof, _claim) = dleq.prove(&x, &mut rng);
        let s_t = dleq_secret_to_ed25519_scalar(&x);

        // Maker's half: any freely-chosen scalar, nothing to do with the DLEQ.
        let s_m = <Ed25519 as Ciphersuite>::F::random(&mut rng);

        let s_m_pub = Ed25519::generator() * s_m;
        let s_t_pub = Ed25519::generator() * s_t;
        let verification_shares = HashMap::from([(MAKER, s_m_pub), (TAKER, s_t_pub)]);

        let keys_taker = additive_two_of_two_keys(TAKER, s_t, verification_shares.clone()).unwrap();
        let keys_maker = additive_two_of_two_keys(MAKER, s_m, verification_shares).unwrap();

        // Both parties agree on the group (public) spend key.
        assert_eq!(keys_taker.group_key(), keys_maker.group_key());

        // It really is the plain sum, not a Lagrange-interpolated aggregate.
        assert_eq!(keys_taker.group_key(), s_m_pub + s_t_pub);

        // Each party's own secret share is exactly what they chose -- unlike PedPoP,
        // nothing here derives from the other party's polynomial.
        assert_eq!(*keys_taker.original_secret_share().deref(), s_t);
        assert_eq!(*keys_maker.original_secret_share().deref(), s_m);
    }

    /// `ThresholdKeys::new` enforces `t == n` for `Interpolation::Constant` -- the
    /// one invariant this additive scheme actually depends on (2-of-2 always satisfies
    /// it, but worth pinning so a future 2-of-3 attempt fails loudly instead of quietly
    /// computing the wrong group key).
    #[test]
    fn constant_interpolation_rejects_t_less_than_n() {
        let params = ThresholdParams::new(2, 3, TAKER).unwrap();
        let shares = HashMap::from([
            (Participant::new(1).unwrap(), Ed25519::generator()),
            (TAKER, Ed25519::generator()),
            (Participant::new(3).unwrap(), Ed25519::generator()),
        ]);
        let err = ThresholdKeys::<Ed25519>::new(
            params,
            Interpolation::Constant(vec![<Ed25519 as Ciphersuite>::F::ONE; 3]),
            Zeroizing::new(<Ed25519 as Ciphersuite>::F::ONE),
            shares,
        )
        .unwrap_err();
        assert!(matches!(err, DkgError::InapplicableInterpolation(_)));
    }
}
