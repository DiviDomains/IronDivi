// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The DLEQ instance both parties use: `swap_adaptor`'s canonical nothing-up-my-sleeve
//! generator pair ([`CrossCurveDleq::nums`], pinned bytes). A prover who chose the
//! generators could forge the cross-curve proof, so neither party ever picks them.

use swap_adaptor::dleq::CrossCurveDleq;

/// The DLEQ prover/verifier both parties use.
pub fn dleq() -> CrossCurveDleq {
    CrossCurveDleq::nums()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_adaptor::dleq::random_clamped_secret;

    #[test]
    fn proofs_verify_under_the_nums_pair_and_bind_the_secret() {
        let mut rng = rand::thread_rng();
        let s = random_clamped_secret(&mut rng);
        let (proof, claim) = dleq().prove(&s, &mut rng);
        assert!(dleq().verify(&proof, claim));
        // A different secret's points do not verify under this proof.
        let other = random_clamped_secret(&mut rng);
        let (_, other_claim) = dleq().prove(&other, &mut rng);
        assert!(!dleq().verify(&proof, (claim.0, other_claim.1)));
        assert!(!dleq().verify(&proof, (other_claim.0, claim.1)));
    }
}
