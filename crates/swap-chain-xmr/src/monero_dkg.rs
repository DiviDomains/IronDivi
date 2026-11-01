// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Build-plan step 5 (`docs/plans/swap-poc/xmr-design.md`): the Monero-side 2-of-2 key
//! generation. `monero-wallet`'s `multisig` feature signs with `modular-frost`, but key
//! *generation* lives one layer down in `dkg-pedpop` (the PedPoP protocol from the FROST
//! paper) — `modular-frost` only signs given already-generated `ThresholdKeys`.
//!
//! This module is step 5a: prove the PedPoP round trip itself produces matching keys for
//! two parties entirely offline, using `ciphersuite::Ed25519` (the same curve group
//! `monero-wallet` itself uses — not `dalek_ff_group::Ristretto`, which is a *different*,
//! prime-order-only group `dkg-pedpop`'s own test suite happens to use for convenience but
//! isn't the one Monero actually needs). Full wire-format compatibility with
//! `monero-wallet`'s own multisig types, and the stagenet broadcast/spend proof, are step
//! 5b — real network time (stagenet confirmations), not just more Rust, so left for a
//! dedicated pass.
//!
//! The protocol is 3 rounds, all point-to-point/broadcast message passing (no on-chain
//! transactions here at all):
//!
//! 1. [`KeyGenMachine::generate_coefficients`] — each party broadcasts [`Commitments`] (as
//!    an [`EncryptionKeyMessage`]) to the other.
//! 2. [`SecretShareMachine::generate_secret_shares`] — each party, given the other's
//!    commitments, broadcasts an encrypted secret share.
//! 3. [`KeyMachine::calculate_share`]` + [`BlameMachine::complete`] — each party combines
//!    its own polynomial evaluation with the share it received, producing [`ThresholdKeys`]
//!    that encode the SAME group (public) key but a *different* secret share each —
//!    exactly the "2-of-2 Monero spend key, neither party alone can derive it" property
//!    `xmr-design.md`'s `## Protocol` needs.

#[cfg(test)]
mod tests {
    use ciphersuite::group::ff::PrimeField;
    use ciphersuite::Ed25519;
    use dkg::{Participant, ThresholdKeys, ThresholdParams};
    use dkg_pedpop::KeyGenMachine;
    use rand_core::OsRng;
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    const CONTEXT: [u8; 32] = *b"IronDivi xmr lane PedPoP test   ";

    /// Run the full 2-of-2 PedPoP round trip, returning both parties' resulting keys.
    fn pedpop_2_of_2() -> (ThresholdKeys<Ed25519>, ThresholdKeys<Ed25519>) {
        let party_a = Participant::new(1).unwrap();
        let party_b = Participant::new(2).unwrap();

        // Round 1: each party generates coefficients and broadcasts commitments.
        let machine_a =
            KeyGenMachine::<Ed25519>::new(ThresholdParams::new(2, 2, party_a).unwrap(), CONTEXT);
        let machine_b =
            KeyGenMachine::<Ed25519>::new(ThresholdParams::new(2, 2, party_b).unwrap(), CONTEXT);
        let (machine_a, commitments_a) = machine_a.generate_coefficients(&mut OsRng);
        let (machine_b, commitments_b) = machine_b.generate_coefficients(&mut OsRng);

        // Round 2: each party receives the OTHER's commitments (never its own) and
        // broadcasts an encrypted secret share per recipient.
        let (machine_a, mut shares_from_a) = machine_a
            .generate_secret_shares(&mut OsRng, HashMap::from([(party_b, commitments_b)]))
            .unwrap();
        let (machine_b, mut shares_from_b) = machine_b
            .generate_secret_shares(&mut OsRng, HashMap::from([(party_a, commitments_a)]))
            .unwrap();

        // Round 3: each party takes in the share addressed to it and finalizes.
        let keys_a = machine_a
            .calculate_share(
                &mut OsRng,
                HashMap::from([(party_b, shares_from_b.remove(&party_a).unwrap())]),
            )
            .unwrap()
            .complete();
        let keys_b = machine_b
            .calculate_share(
                &mut OsRng,
                HashMap::from([(party_a, shares_from_a.remove(&party_b).unwrap())]),
            )
            .unwrap()
            .complete();

        (keys_a, keys_b)
    }

    /// Both parties agree on the shared (group) public key -- the "2-of-2 Monero spend
    /// public key" the swap's lock output would use -- while each holds a *different*
    /// secret share, so neither alone is the spend key.
    #[test]
    fn two_of_two_pedpop_round_trip_produces_matching_keys() {
        let (keys_a, keys_b) = pedpop_2_of_2();
        assert_eq!(keys_a.group_key(), keys_b.group_key());
        assert_ne!(
            keys_a.original_secret_share().to_repr(),
            keys_b.original_secret_share().to_repr()
        );
    }

    /// Step 5b, first slice: the group key the PedPoP round trip produces bridges
    /// directly into `monero-wallet`'s own Ed25519 point type (`ciphersuite::Ed25519`'s
    /// `G` is `dalek_ff_group::EdwardsPoint`, a public-field wrapper around
    /// `curve25519_dalek::EdwardsPoint` -- the exact type `monero_wallet::ed25519::Point`
    /// converts from), and from there into a real Monero stagenet address — the address
    /// the swap's lock output would actually pay XMR to.
    ///
    /// The view key is a simplification: a real 2-of-2 multisig conventionally shares the
    /// view key in the clear between both parties (only the spend key needs threshold
    /// protection, since knowing the view key alone only lets you *see* funds, not spend
    /// them) rather than generating it independently per party as done here.
    #[test]
    fn group_key_derives_a_real_stagenet_address() {
        let (keys_a, keys_b) = pedpop_2_of_2();

        let spend_point = monero_wallet::ed25519::Point::from(keys_a.group_key().0);
        let view_key = Zeroizing::new(monero_wallet::ed25519::Scalar::random(&mut OsRng));
        let view_pair = monero_wallet::ViewPair::new(spend_point, view_key).unwrap();
        let address = view_pair.legacy_address(monero_wallet::address::Network::Stagenet);

        // Both parties' view of the group key must produce the identical address --
        // this is the address the maker/taker agree the swap's XMR lock pays into.
        let spend_point_b = monero_wallet::ed25519::Point::from(keys_b.group_key().0);
        assert_eq!(spend_point, spend_point_b);

        let rendered = address.to_string();
        assert!(!rendered.is_empty());
    }
}
