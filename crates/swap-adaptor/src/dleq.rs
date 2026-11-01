// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Cross-group discrete-log equality: proves a secp256k1 point and an ed25519 point were
//! both derived from the same secret scalar, without revealing it. `xmr-design.md`'s
//! `## DLEQ` section is the write-up; this is `sigma_fun`'s
//! `ext::dl_secp256k1_ed25519_eq::CrossCurveDLEQ` (the maintained successor to COMIT's
//! archived `cross-curve-dleq` proof of concept) under a crate-local name.
//!
//! This is what lets Maker trust that completing Taker's `Tx_redeem` adaptor signature
//! (`crate::adaptor`) hands Taker a secret that is *also* Taker's share of the Monero
//! multisig spend key — the two curves otherwise have no relationship a verifier could
//! check directly.

pub use curve25519_dalek_ng::{edwards::EdwardsPoint as PointQ, scalar::Scalar as ScalarQ};
pub use secp256kfun::{Point as PointP, Scalar as ScalarP};
pub use sigma_fun::ext::dl_secp256k1_ed25519_eq::CrossCurveDLEQProof;

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use sigma_fun::ext::dl_secp256k1_ed25519_eq::CrossCurveDLEQ as Inner;
use sigma_fun::HashTranscript;

type Transcript = HashTranscript<Sha256, ChaCha20Rng>;

/// [`CrossCurveDleq::nums`]'s secp256k1 generator, compressed SEC1 (33 bytes,
/// `0x02 || x`) -- the first `0x02 || SHA256(label || ctr)` (big-endian `u32`
/// counter) that is a valid x-coordinate, for `ctr` starting at 0 and the label
/// `"IronDivi swap-adaptor CrossCurveDleq h_p secp256k1 v1"`. Reproduced by
/// `tests::nums_matches_its_own_rederivation`; see [`CrossCurveDleq::nums`]'s docs for
/// why the bytes are pinned here instead of recomputed at runtime.
#[rustfmt::skip]
const H_P_BYTES: [u8; 33] = [
    0x02, 0x62, 0x98, 0xfc, 0xd1, 0x75, 0x34, 0x9a,
    0x64, 0x78, 0x59, 0xda, 0x1a, 0xcd, 0xfd, 0x2c,
    0x7b, 0xe0, 0x60, 0xa0, 0x36, 0x1d, 0x48, 0x0c,
    0xb7, 0x8e, 0x73, 0xe9, 0xb0, 0xbd, 0x94, 0xef,
    0xcb,
];

/// [`CrossCurveDleq::nums`]'s ed25519 generator, compressed (32 bytes) -- the first
/// `SHA256(label || ctr)` that decompresses to a point, times the cofactor (clearing
/// torsion into the prime-order subgroup) and non-identity, for `ctr` starting at 0
/// and the label `"IronDivi swap-adaptor CrossCurveDleq h_q ed25519 v1"`. Reproduced
/// by `tests::nums_matches_its_own_rederivation`.
#[rustfmt::skip]
const H_Q_BYTES: [u8; 32] = [
    0xd8, 0xb0, 0x70, 0xdc, 0x27, 0x7a, 0x0c, 0x39,
    0x9b, 0x78, 0x17, 0x9e, 0xda, 0x67, 0x6d, 0x5f,
    0x5d, 0x10, 0x47, 0x88, 0x14, 0xcb, 0xd6, 0x23,
    0x43, 0xa2, 0x1b, 0x5a, 0xc8, 0x10, 0xa2, 0x67,
];

/// Prover/verifier for one DLEQ instance. `h_p`/`h_q` are the Pedersen-commitment
/// generator points (one per curve) baked into the 252 per-bit commitments the proof is
/// built from.
///
/// **Must be nothing-up-my-sleeve, agreed by both parties — never prover-chosen per
/// proof.** If a prover could pick `h_p`/`h_q` itself knowing their discrete logs relative
/// to the curves' standard generators, it could forge commitments and the proof would no
/// longer bind the claimed points to one secret. [`CrossCurveDleq::with_random_generators`]
/// exists only for tests; real use needs a fixed, both-sides-verifiable pair (e.g. derived
/// by a public hash-to-curve, exchanged once at swap setup).
pub struct CrossCurveDleq {
    inner: Inner<Transcript>,
}

impl CrossCurveDleq {
    /// Build from an agreed `(h_p, h_q)` pair.
    pub fn new(h_p: PointP, h_q: PointQ) -> Self {
        Self {
            inner: Inner::new(h_p, h_q),
        }
    }

    /// `h_p`/`h_q` drawn from the RNG — fine for tests, **not** for real swaps (see the
    /// NUMS requirement on [`CrossCurveDleq`]).
    pub fn with_random_generators(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        use secp256kfun::Point;
        let h_p: PointP = loop {
            if let Some(p) = Point::random(rng).non_zero() {
                break p;
            }
        };
        // Match the library's own test helper: a random ed25519 scalar times the
        // basepoint, i.e. a uniformly random point in the prime-order subgroup.
        let h_q: PointQ =
            &random_clamped_secret(rng) * &curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
        Self::new(h_p, h_q)
    }

    /// The canonical, nothing-up-my-sleeve `(h_p, h_q)` pair every real swap must
    /// agree on (see the NUMS requirement on [`CrossCurveDleq`] -- a prover who chose
    /// these could forge the binding the whole proof exists to guarantee). Parses the
    /// fixed, hard-coded bytes in [`H_P_BYTES`]/[`H_Q_BYTES`] rather than recomputing
    /// them at runtime: the derivation (try-and-increment SHA-256 of a public,
    /// domain-separated label -- `secp256k1_nums_h_p_candidate`/`ed25519_nums_h_q_candidate`
    /// in the test module reproduce it) only has to run once, ever; pinning its output
    /// as a constant means a future `sigma_fun`/`curve25519-dalek-ng` upgrade changing
    /// some internal encoding detail can't silently mint a *different* pair than what
    /// an already-run swap agreed on -- `nums_matches_its_own_rederivation` is the
    /// drift alarm for that, not this function.
    pub fn nums() -> Self {
        Self::new(
            PointP::from_bytes(H_P_BYTES).expect("H_P_BYTES is a valid compressed secp256k1 point"),
            curve25519_dalek_ng::edwards::CompressedEdwardsY(H_Q_BYTES)
                .decompress()
                .expect("H_Q_BYTES is a valid compressed ed25519 point"),
        )
    }

    /// Prove `secret` is simultaneously the discrete log of a secp256k1 point and an
    /// ed25519 point, returning the proof and that `(secp256k1, ed25519)` point pair.
    /// `secret` must be clamped below 2^252 — use [`random_clamped_secret`]. Panics (via
    /// `sigma_fun`) if it isn't.
    pub fn prove(
        &self,
        secret: &ScalarQ,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (CrossCurveDLEQProof, (PointP, PointQ)) {
        self.inner.prove(secret, rng)
    }

    /// Verify `proof` demonstrates `claim` (`(secp256k1 point, ed25519 point)`) share one
    /// discrete log, under this instance's `(h_p, h_q)`.
    #[must_use]
    pub fn verify(&self, proof: &CrossCurveDLEQProof, claim: (PointP, PointQ)) -> bool {
        self.inner.verify(proof, claim)
    }
}

/// A uniformly random scalar clamped below 2^252 (bit 252 cleared), so it is
/// simultaneously a valid secp256k1 scalar (order ~2^256) and a valid ed25519 scalar
/// (order ~2^252.98) with no reduction ambiguity between the two — see `xmr-design.md`'s
/// `## DLEQ` for why that clamp is what makes the cross-group proof possible at all.
pub fn random_clamped_secret(rng: &mut impl RngCore) -> ScalarQ {
    let mut bytes = [0u8; 32];
    loop {
        rng.fill_bytes(&mut bytes);
        bytes[31] &= 0b0000_1111;
        if let Some(s) = ScalarQ::from_canonical_bytes(bytes) {
            if s != ScalarQ::zero() {
                return s;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use secp256kfun::{g, marker::*, Scalar as SecpScalar, G as GP};

    /// A correctly-constructed proof verifies, and the claimed secp256k1 point really is
    /// `secret * G` on that curve (sanity check the wrapper round-trips, not just that
    /// `verify` returns true for whatever `prove` hands back).
    #[test]
    fn valid_proof_verifies() {
        let mut rng = thread_rng();
        let dleq = CrossCurveDleq::with_random_generators(&mut rng);
        let secret = random_clamped_secret(&mut rng);

        let (proof, claim) = dleq.prove(&secret, &mut rng);
        assert!(dleq.verify(&proof, claim));

        let secp_secret = {
            let mut bytes = secret.to_bytes();
            bytes.reverse(); // secp256kfun scalars are big-endian; ed25519 scalars are little-endian.
            SecpScalar::<Secret>::from_bytes(bytes).unwrap()
        };
        assert_eq!(g!(secp_secret * GP).normalize(), claim.0);
    }

    /// Swapping in an unrelated secp256k1 point (same ed25519 half) must be rejected —
    /// this is the exact attack the proof exists to prevent: Maker must not be tricked
    /// into believing an unrelated point shares Taker's Monero-side secret.
    #[test]
    fn tampered_secp256k1_claim_is_rejected() {
        let mut rng = thread_rng();
        let dleq = CrossCurveDleq::with_random_generators(&mut rng);
        let secret = random_clamped_secret(&mut rng);
        let (proof, claim) = dleq.prove(&secret, &mut rng);

        let r = SecpScalar::random(&mut rng);
        let unrelated_point = g!(r * GP).normalize();
        assert!(!dleq.verify(&proof, (unrelated_point, claim.1)));
    }

    /// Same attack, mirrored on the ed25519 half.
    #[test]
    fn tampered_ed25519_claim_is_rejected() {
        let mut rng = thread_rng();
        let dleq = CrossCurveDleq::with_random_generators(&mut rng);
        let secret = random_clamped_secret(&mut rng);
        let (proof, claim) = dleq.prove(&secret, &mut rng);

        let unrelated_ed25519 = &random_clamped_secret(&mut rng)
            * &curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
        assert!(!dleq.verify(&proof, (claim.0, unrelated_ed25519)));
    }

    /// A proof made under one `(h_p, h_q)` instance must not verify under a different,
    /// independently-generated instance — commitments are only meaningful relative to the
    /// generators they were made against.
    #[test]
    fn proof_does_not_verify_under_different_generators() {
        let mut rng = thread_rng();
        let dleq_a = CrossCurveDleq::with_random_generators(&mut rng);
        let dleq_b = CrossCurveDleq::with_random_generators(&mut rng);
        let secret = random_clamped_secret(&mut rng);

        let (proof, claim) = dleq_a.prove(&secret, &mut rng);
        assert!(!dleq_b.verify(&proof, claim));
    }

    /// [`CrossCurveDleq::nums`]'s pinned bytes must actually reproduce the real
    /// try-and-increment derivation they're supposed to be a frozen snapshot of --
    /// the drift alarm the module docs promise: if a future dependency bump ever
    /// changed anything about secp256k1/ed25519 point encoding, this fails loudly
    /// instead of `nums()` silently handing out a different pair than a previously
    /// run swap agreed on.
    #[test]
    fn nums_matches_its_own_rederivation() {
        use curve25519_dalek_ng::edwards::CompressedEdwardsY;
        use curve25519_dalek_ng::traits::IsIdentity;
        use sha2::Digest as _;

        const LABEL_P: &[u8] = b"IronDivi swap-adaptor CrossCurveDleq h_p secp256k1 v1";
        const LABEL_Q: &[u8] = b"IronDivi swap-adaptor CrossCurveDleq h_q ed25519 v1";

        fn candidate(label: &[u8], counter: u32) -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(label);
            h.update(counter.to_be_bytes());
            h.finalize().into()
        }

        let h_p: PointP = (0u32..)
            .find_map(|ctr| {
                let mut bytes = [0u8; 33];
                bytes[0] = 0x02;
                bytes[1..].copy_from_slice(&candidate(LABEL_P, ctr));
                PointP::from_bytes(bytes)
            })
            .expect("about half of all x-coordinates are on the curve");
        assert_eq!(
            h_p.to_bytes(),
            H_P_BYTES,
            "H_P_BYTES is stale -- re-derive and update it"
        );

        let h_q: PointQ = (0u32..)
            .find_map(|ctr| {
                CompressedEdwardsY(candidate(LABEL_Q, ctr))
                    .decompress()
                    .map(|p| p.mul_by_cofactor())
                    .filter(|p| !p.is_identity())
            })
            .expect("about half of all y-coordinates decompress");
        assert_eq!(
            h_q.compress().to_bytes(),
            H_Q_BYTES,
            "H_Q_BYTES is stale -- re-derive and update it"
        );
    }

    /// `nums()` must actually build a usable, working DLEQ instance against its own
    /// pinned generators -- the real thing [`nums_matches_its_own_rederivation`]
    /// doesn't exercise (it only checks the bytes, not that they parse into a working
    /// proof system).
    #[test]
    fn nums_proves_and_verifies() {
        let mut rng = thread_rng();
        let dleq = CrossCurveDleq::nums();
        let secret = random_clamped_secret(&mut rng);
        let (proof, claim) = dleq.prove(&secret, &mut rng);
        assert!(dleq.verify(&proof, claim));
    }
}
