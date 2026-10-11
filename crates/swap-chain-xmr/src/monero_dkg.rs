// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
    use dkg::{Participant, ThresholdParams};
    use dkg_pedpop::KeyGenMachine;
    use rand_core::OsRng;
    use std::collections::HashMap;

    const CONTEXT: [u8; 32] = *b"IronDivi xmr lane PedPoP test   ";

    /// Run the full 2-of-2 PedPoP round trip and confirm both parties end up with
    /// [`dkg::ThresholdKeys`] that agree on the shared group (public) key, while each
    /// holding a secret share that individually cannot reconstruct it.
    #[test]
    fn two_of_two_pedpop_round_trip_produces_matching_keys() {
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

        // Both parties agree on the shared (group) public key -- the "2-of-2 Monero
        // spend public key" the swap's lock output would use.
        assert_eq!(keys_a.group_key(), keys_b.group_key());

        // But each holds a *different* secret share -- neither alone is the spend key.
        assert_ne!(
            keys_a.original_secret_share().to_repr(),
            keys_b.original_secret_share().to_repr()
        );
    }
}
