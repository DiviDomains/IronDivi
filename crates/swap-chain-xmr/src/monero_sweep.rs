// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The final Monero sweep: once one party has recovered the other's secret (via a
//! broadcast `Tx_redeem` or `Tx_refund`, see [`crate::swap_templates`]) and combined it
//! with their own additive share (see [`crate::monero_key_share`]), spending the 2-of-2
//! lock output is no longer a cooperative multisig signing round -- that party now holds
//! the FULL private spend key as an ordinary scalar, and this is just a normal,
//! single-key wallet send.
//!
//! The one genuinely new piece this module needs is bridging the recovered/combined
//! secret, a `ciphersuite::Ed25519` scalar (the type [`crate::monero_key_share`] and the
//! rest of this crate use), into `monero_wallet`'s own scalar type
//! (`monero_wallet::ed25519::Scalar`, re-exported from the separate `monero-ed25519`
//! crate) -- numerically the same field, but two physically distinct Rust types with no
//! `From` impl between them, since they come from unrelated crates in the dependency
//! tree. [`to_monero_scalar`] does that bridge via the canonical byte encoding both
//! sides agree on.
//!
//! Building the actual spend ([`sweep`]) uses a two-pass fee calculation: the fee a
//! `monero_wallet::send::SignableTransaction` requires depends only on its *shape*
//! (input/output/ring counts), not on the amounts moved, so the only way to pay out
//! exactly `input value - fee` with no change output (true sweeps have none, see
//! [`monero_wallet::send::Change::fingerprintable`]'s docs: with no change output
//! anything unaccounted-for is just silently burned as extra fee) is to build once with
//! a placeholder amount to learn [`monero_wallet::send::SignableTransaction::necessary_fee`],
//! then rebuild with the corrected payout.
//!
//! Decoy selection (`monero_wallet::OutputWithDecoys::new`) needs an
//! `impl monero_wallet::interface::ProvidesDecoys` to draw ring members from -- in
//! production this is the real stagenet/mainnet daemon; `sweep` takes an
//! already-selected [`monero_wallet::OutputWithDecoys`] so it doesn't care which. The
//! tests below build a synthetic in-memory mock for this, proving decoy selection and
//! signing both work without a live daemon -- see the tests' module docs for the one
//! piece this crate's real, published test suite always needs a live/regtest node for
//! instead (producing a *new*, from-scratch [`monero_wallet::WalletOutput`] for an
//! arbitrary key pair), and why that's a genuine ecosystem constraint this module works
//! around rather than reimplements.

use ciphersuite::group::ff::PrimeField;
use ciphersuite::{Ciphersuite, Ed25519};
use monero_wallet::address::MoneroAddress;
use monero_wallet::ed25519::Scalar as MoneroScalar;
use monero_wallet::interface::FeeRate;
use monero_wallet::ringct::RctType;
use monero_wallet::send::{Change, SendError, SignableTransaction};
use monero_wallet::transaction::Transaction;
use monero_wallet::{OutputWithDecoys, WalletOutput};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Bridges a `ciphersuite::Ed25519` scalar -- e.g. the combined `s_m + recovered s_t`
/// (or `s_t + recovered s_m`, for the abort path) full Monero spend secret -- into
/// `monero_wallet`'s own scalar type. Both are the same field (order ℓ) with the same
/// canonical little-endian 32-byte encoding; this is a pure re-encode, not a
/// cryptographic conversion, the same style of bridge
/// [`crate::monero_key_share::dleq_secret_to_ed25519_scalar`] already does for a
/// different pair of physically-distinct-but-numerically-identical scalar types.
pub fn to_monero_scalar(secret: &<Ed25519 as Ciphersuite>::F) -> Zeroizing<MoneroScalar> {
    let bytes = secret.to_repr();
    Zeroizing::new(
        MoneroScalar::read(&mut bytes.as_ref())
            .expect("a canonical Ed25519 scalar is always a valid Monero scalar"),
    )
}

/// Build and sign a transaction sweeping the full value of `output` (minus the
/// necessary fee; no change output, since a sweep has nothing left to return to
/// yourself) to `destination`. Monero requires at least two outputs per transaction
/// (`monero_wallet::send`'s own `validate`), so with no change output to supply the
/// second one, the payout is split across two payments to the same `destination`
/// rather than one -- a real (if slightly unusual) shape, not a workaround specific to
/// this module. `full_spend_key` is the recovered, combined private spend key -- see
/// the module docs for why this is an ordinary single-key send, not a cooperative
/// multisig signing round. `outgoing_view_key` seeds this transaction's internal RNG
/// and must be treated as a secret (`monero_wallet::send::SignableTransaction::new`'s
/// own docs).
pub fn sweep(
    rng: &mut (impl RngCore + CryptoRng),
    output: &WalletOutput,
    decoys: OutputWithDecoys,
    destination: MoneroAddress,
    outgoing_view_key: [u8; 32],
    fee_rate: FeeRate,
    full_spend_key: &<Ed25519 as Ciphersuite>::F,
) -> Result<Transaction, SendError> {
    let amount = output.commitment().amount;

    // Pass 1: placeholder payments, just to learn the fee this transaction's shape
    // requires (see the module docs -- fee depends on weight, not on amounts; two
    // zero-amount payments satisfy the >= 2 output requirement for this probe).
    let placeholder = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        Zeroizing::new(outgoing_view_key),
        vec![decoys.clone()],
        vec![(destination, 0), (destination, 0)],
        Change::fingerprintable(None),
        vec![],
        fee_rate,
    )?;
    let fee = placeholder.necessary_fee();

    // Pass 2: the real payout, split across the same two outputs, summing to exactly
    // `amount - fee` so nothing beyond the necessary fee is lost to having no change.
    let payout = amount.saturating_sub(fee);
    let half = payout / 2;
    let tx = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        Zeroizing::new(outgoing_view_key),
        vec![decoys],
        vec![(destination, half), (destination, payout - half)],
        Change::fingerprintable(None),
        vec![],
        fee_rate,
    )?;
    tx.sign(rng, &to_monero_scalar(full_spend_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::group::ff::Field;
    use monero_wallet::address::Network;
    use monero_wallet::block::Block;
    use monero_wallet::ed25519::Point;
    use monero_wallet::interface::{
        EvaluateUnlocked, InterfaceError, ProvidesBlockchainMeta, ProvidesUnvalidatedDecoys,
        TransactionsError,
    };
    use monero_wallet::transaction::Pruned;
    use monero_wallet::{Scanner, ViewPair};
    use rand_core::OsRng;

    // --- Fixture: a known-good (spend key, view key, confirmed tx, confirmed block)
    // tuple, copied verbatim from `monero-wallet` 0.2.0's own internal test vectors
    // (`src/tests/scan.rs`, `scan_long_encrypted_amount` -- not part of its public API,
    // so copied as plain data rather than imported). This sidesteps the one thing that
    // genuinely has no offline API in this crate: minting a *new* `WalletOutput` for an
    // arbitrary key pair requires correctly deriving Monero's one-time output key via
    // the sender's ephemeral transaction key (real transaction-construction crypto the
    // crate's own `send` module only ever exercises against a real/regtest daemon in
    // its own test suite -- see `tests/send.rs`, which always uses a live `Rpc`).
    // Reusing a known-valid (tx, block) pair and scanning it for real with `Scanner`
    // (fully public, no daemon needed -- see module docs) gets a real `WalletOutput`
    // without needing to solve that; what this module actually needs to prove --
    // decoy selection and signing against an arbitrary full spend key -- doesn't care
    // whose output it is.
    const SPEND_KEY: &str = "ccf0ea10e1ea64354f42fa710c2b318e581969cf49046d809d1f0aadb3fc7a02";
    const VIEW_KEY: &str = "a28b4b2085592881df94ee95da332c16b5bb773eb8bb74730208cbb236c73806";
    #[rustfmt::skip]
    const PRUNED_TX: &str = "020001020003060101cf60390bb71aa15eb24037772012d59dc68cb4b6211e1c93206db09a6c346261020002ee8ca293511571c0005e1c144e49d09b8ff03046dbafb3e064a34cb9fc1994b600029e2e5cd08c8681dbcf2ce66071467e835f7e86613fbfed3c4fb170127b94e1072c01d3ce2a622c6e06ed465f81017dd6188c3a6e3d8e65a846f9c98416da0e150a82020901c553d35e54111bd001e0bbcbf289d701ce90e309ead2b487ec1d4d8af5d649543eb99a7620f6b54e532898527be29704f050e6f06de61e5967b2ddd506b4d6d36546065d6aae156ac7bec18c99580c07867fb98cb29853edbafec91af2df605c12f9aaa81a9165625afb6649f5a652012c5ba6612351140e1fb4a8463cc765d0a9bb7d999ba35750f365c5285d77230b76c7a612784f4845812a2899f2ca6a304fee61362db59b263115c27d2ce78af6b1d9e939c1f4036c7707851f41abe6458cf1c748353e593469ebf43536a939f7";
    #[rustfmt::skip]
    const BLOCK: &str = "0202e8e28efe04db09e2fc4d57854786220bd33e0169ff692440d27ae3932b9219df9ab1d7260b00000000014101ff050580d0acf30e02704972eb1878e94686b62fa4c0202f3e7e3a263073bd6edd751990ea769494ee80c0fc82aa0202edac72ab7c5745d4acaa95f76a3b76e238a55743cd51efb586f968e09821788d80d0dbc3f40202f9b4cf3141aac4203a1aaed01f09326615544997d1b68964928d9aafd07e38e580a0e5b9c29101023405e3aa75b1b7adf04e8c7faa3c3d45616ae740a8b11fb7cc1555dd8b9e4c9180c0dfda8ee90602d2b78accfe1c2ae57bed4fe3385f7735a988f160ef3bbc1f9d7a0c911c26ffd92101d2d55b5066d247a97696be4a84bf70873e4f149687f57e606eb6682f11650e1701b74773bbea995079805398052da9b69244bda034b089b50e4d9151dedb59a12f";
    const OUTPUT_INDEX_FOR_FIRST_RINGCT_OUTPUT: u64 = 0;

    fn scan_fixture_output() -> WalletOutput {
        let spend_key = Zeroizing::new(
            MoneroScalar::read(&mut hex::decode(SPEND_KEY).unwrap().as_slice()).unwrap(),
        );
        let view_key = Zeroizing::new(
            MoneroScalar::read(&mut hex::decode(VIEW_KEY).unwrap().as_slice()).unwrap(),
        );
        let spend_pub = {
            use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
            Point::from(&(*spend_key).into() * ED25519_BASEPOINT_TABLE)
        };
        let view_pair = ViewPair::new(spend_pub, view_key).unwrap();
        let mut scanner = Scanner::new(view_pair);

        let tx =
            Transaction::<Pruned>::read(&mut hex::decode(PRUNED_TX).unwrap().as_slice()).unwrap();
        let block = Block::read(&mut hex::decode(BLOCK).unwrap().as_slice()).unwrap();
        let scannable_block = monero_wallet::interface::ScannableBlock {
            block,
            transactions: vec![tx],
            output_index_for_first_ringct_output: Some(OUTPUT_INDEX_FOR_FIRST_RINGCT_OUTPUT),
        };

        scanner
            .scan(scannable_block)
            .unwrap()
            .not_additionally_locked()
            .swap_remove(0)
    }

    /// `ProvidesDecoys` needs real (if synthetic) chain shape, not just plausible
    /// numbers, to satisfy `OutputWithDecoys::new`'s decoy-selection algorithm (a
    /// Gamma-distributed "age" sample mapped through an output-arrival-rate estimate
    /// derived from the distribution itself -- `monero-wallet`'s own `decoys.rs`).
    /// These constants were tuned so that estimate (`per_second`) puts the sampling
    /// distribution's typical output squarely inside `BOUND`, not an order of
    /// magnitude outside it -- see the comments below for the arithmetic. This mirrors
    /// a real, if tiny and fast-growing, Monero chain: it does not need to look like
    /// a decade of real mainnet history, just be internally self-consistent.
    // `ClsagBulletproofPlus` needs exactly 16 ring members (`send/mod.rs`'s `validate`),
    // i.e. 15 decoys -- tuned these so the Gamma-sampled "age" (mode exp(~12) ≈ 162755,
    // per `rand_distr::Gamma(19.28, 1/1.61)`), after `per_second` scaling, lands well
    // inside `[0, BOUND)` most of the time: `per_second ≈ ((DISTRIBUTION_LEN-1)*STEP) /
    // (DISTRIBUTION_LEN*BLOCK_TIME) ≈ 7.7`, so the mode maps to `≈ 162755*7.7 ≈ 1.25M`,
    // comfortably inside `BOUND ≈ 2.02M`.
    const DISTRIBUTION_LEN: usize = 30;
    const BASE: u64 = 2_000_000;
    const STEP: u64 = 958;

    struct MockDecoys {
        real_index: u64,
        real_key: Point,
        real_commitment: Point,
    }

    fn synthetic_point(seed: u64) -> Point {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::Scalar as DalekScalar;
        // seed + 1: never multiply by the zero scalar (that would yield the identity,
        // which `select_n` explicitly rejects as an unusable ring member).
        Point::from(&DalekScalar::from(seed + 1) * ED25519_BASEPOINT_TABLE)
    }

    impl ProvidesBlockchainMeta for MockDecoys {
        fn latest_block_number(
            &self,
        ) -> impl Send + core::future::Future<Output = Result<usize, InterfaceError>> {
            async move { Ok(DISTRIBUTION_LEN - 1) }
        }
    }

    impl ProvidesUnvalidatedDecoys for MockDecoys {
        fn ringct_output_distribution(
            &self,
            _range: impl Send + core::ops::RangeBounds<usize>,
        ) -> impl Send + core::future::Future<Output = Result<Vec<u64>, InterfaceError>> {
            async move {
                Ok((0..DISTRIBUTION_LEN as u64)
                    .map(|i| BASE + i * STEP)
                    .collect())
            }
        }

        fn unlocked_ringct_outputs(
            &self,
            indexes: &[u64],
            _evaluate_unlocked: EvaluateUnlocked,
        ) -> impl Send + core::future::Future<Output = Result<Vec<Option<[Point; 2]>>, TransactionsError>>
        {
            let real_index = self.real_index;
            let real_key = self.real_key;
            let real_commitment = self.real_commitment;
            let indexes = indexes.to_vec();
            async move {
                Ok(indexes
                    .into_iter()
                    .map(|i| {
                        if i == real_index {
                            Some([real_key, real_commitment])
                        } else {
                            Some([synthetic_point(i), synthetic_point(i.wrapping_add(1 << 32))])
                        }
                    })
                    .collect())
            }
        }
    }

    /// Decoy selection + the two-pass fee + signing, end to end, no live daemon: a
    /// known-good `WalletOutput` (see `scan_fixture_output`'s docs on why it's sourced
    /// this way), a synthetic `ProvidesDecoys`, and `sweep`'s real code path.
    ///
    /// Decoy sampling is probabilistic by design (mirrors real Monero wallets, not a
    /// flaw in this test) -- `DISTRIBUTION_LEN`/`BASE`/`STEP` were tuned so a single
    /// attempt should succeed the large majority of the time, and this retries a
    /// bounded few times to absorb the residual sampling variance rather than risk
    /// occasional flakiness from a single draw.
    #[test]
    fn sweep_builds_and_signs_against_synthetic_decoys() {
        let output = scan_fixture_output();
        assert_eq!(
            output.index_on_blockchain(),
            OUTPUT_INDEX_FOR_FIRST_RINGCT_OUTPUT
        );

        let mock = MockDecoys {
            real_index: output.index_on_blockchain(),
            real_key: output.key(),
            real_commitment: output.commitment().commit(),
        };

        let mut rng = OsRng;
        let mut decoys = None;
        for _ in 0..8 {
            if let Ok(d) = futures::executor::block_on(OutputWithDecoys::new(
                &mut rng,
                &mock,
                16, // RctType::ClsagBulletproofPlus requires exactly 16 ring members
                DISTRIBUTION_LEN - 1,
                output.clone(),
            )) {
                decoys = Some(d);
                break;
            }
        }
        let decoys = decoys.expect("decoy selection should succeed within a handful of attempts");

        // The actual claim: bridge a ciphersuite::Ed25519 scalar built from the SAME
        // canonical bytes as the fixture's known spend key -- simulating "the combined
        // secret this crate's monero_key_share/swap_templates machinery recovered" --
        // and confirm it round-trips correctly AND actually signs a valid spend.
        let spend_key_bytes = hex::decode(SPEND_KEY).unwrap();
        let full_spend_key =
            <Ed25519 as Ciphersuite>::F::from_repr(spend_key_bytes.as_slice().try_into().unwrap())
                .unwrap();
        assert_ne!(full_spend_key, <Ed25519 as Ciphersuite>::F::ZERO);

        let destination_view_pair = ViewPair::new(
            Point::from(
                &curve25519_dalek::Scalar::from(777u64)
                    * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE,
            ),
            Zeroizing::new(MoneroScalar::read(&mut [7u8; 32].as_slice()).unwrap()),
        )
        .unwrap();
        let destination = destination_view_pair.legacy_address(Network::Stagenet);

        let fee_rate = FeeRate::new(1, 1).unwrap();
        let tx = sweep(
            &mut rng,
            &output,
            decoys,
            destination,
            [9u8; 32],
            fee_rate,
            &full_spend_key,
        )
        .expect("a known-good output, synthetic decoys, and the real spend key must sign");

        match tx {
            Transaction::V2 { proofs, .. } => {
                let proofs = proofs.expect("a signed RingCT transaction has proofs");
                assert!(
                    matches!(
                        proofs.prunable,
                        monero_wallet::ringct::RctPrunable::Clsag { .. }
                    ),
                    "ClsagBulletproofPlus must produce CLSAG proofs"
                );
            }
            Transaction::V1 { .. } => panic!("a RingCT sweep must produce a V2 transaction"),
        }
    }
}
