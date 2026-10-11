# Lane xmr status

- done: baretxid fix (`f8f7e9b`); build-plan steps 2-4 (`3e99c00`); step 7's bridge
  (`0139101`); root `Cargo.toml` wiring (`c73478e`, `cf80ac0`); step 5a (`02e6f0c`);
  step 5b (`23265e7`). Confirmed clean after lane-sync.
  New this round — **step 6, done, and a correction to step 5a/5b's foundation**:
  - Before writing step 6, hit a genuine protocol-design question and escalated to the
    `oracle` per lane rule 7 rather than guess: does PedPoP/FROST's threshold-share
    output (what steps 5a/5b built on) actually support binding a party's Monero key
    share to a pre-chosen, DLEQ-proven adaptor secret? **No.** PedPoP's final share is a
    *Lagrange* share — `dkg-pedpop`'s `KeyMachine::calculate_share` ends with
    `ThresholdKeys::new(.., Interpolation::Lagrange, ..)`, an aggregate of both parties'
    polynomial evaluations. There's no API to make a party's resulting share *equal* a
    scalar they picked beforehand. The oracle verified (against actual `dkg`/`dkg-pedpop`
    source, not docs) that the real Gugger/COMIT/Farcaster construction is **additive**
    2-of-2 (`S = s_m*G + s_t*G`, each party freely choosing their half), and that the
    `dkg` crate supports this natively via `Interpolation::Constant` (legal exactly when
    `t == n`, which 2-of-2 always is) — no interactive secret-sharing round needed at all.
  - New `crates/swap-chain-xmr/src/monero_key_share.rs` (production code — `pub mod`,
    not test-only like `monero_dkg`): `dleq_secret_to_ed25519_scalar` (a canonical-bytes
    re-encode from `swap-adaptor`'s DLEQ secret, `curve25519-dalek-ng`'s `Scalar`, into
    `ciphersuite::Ed25519`'s scalar type, `dalek_ff_group::Scalar` over mainstream
    `curve25519-dalek` — two different physical crate versions of the same field, no
    cryptographic conversion, just a 32-byte round trip) and `additive_two_of_two_keys`
    (wraps `ThresholdKeys::new` with `Interpolation::Constant`).
  - 3 new tests: the byte re-encode lands on the *same point* the DLEQ proof itself
    claims (compared via compressed bytes, since the two curve25519-dalek versions
    aren't directly comparable as Rust types) — catches a byte-order mistake that would
    otherwise pass each crate's own checks individually; Taker's DLEQ secret literally
    *becomes* their Monero share (not a derived aggregate) and both parties converge on
    the plain-sum group key; `Interpolation::Constant` is rejected when `t != n` (pins
    the one invariant this scheme depends on).
  - `monero_dkg`'s PedPoP round trip (step 5a) is demoted to doc-noted reference-only —
    it proved the DKG dependency stack works, but isn't this swap's key-generation path.
    Not removed (still a valid, passing test; no reason to delete working, documented
    code). `monero_key_share` moved `dkg`/`ciphersuite` from dev- to regular
    dependencies, since this module's non-test code uses them.
  - 15 tests total in swap-chain-xmr with `--features live` (was 12); `cargo fmt`,
    `clippy -p swap-chain-xmr --all-targets [--features live] -- -D warnings`, and
    `cargo clippy --workspace --all-targets -- -D warnings` all green; `Cargo.lock`
    unchanged (no new crates, just dependencies moving sections).
- running: nothing.
- broken: none in my paths.
- left, in order:
  - step 5b's deferred final slice: fund the address `monero_dkg`'s (now reference-only)
    test derives and prove a live 2-of-2 cooperative spend — needs real stagenet
    block-time (self-mine via `getblocktemplate`/`submitblock`, no faucet) and both
    parties' live participation in `monero_wallet::send::multisig`. Worth doing once
    with `monero_key_share`'s additive keys (not `monero_dkg`'s PedPoP ones) rather than
    folding into a code-only round — genuinely gated on elapsed time, not more Rust.
  - step 7 remainder: the rest of the `Tx_cancel`/`Tx_refund`/`Tx_punish`/`Tx_redeem`
    template set, now with a concrete Monero-side key-share story to build against
    (the bridge module already proves the DIVI-side mechanics).
  - step 8: happy-path e2e, DIVI testnet + Monero stagenet, throwaway keys.
  - step 9: engine-integration proposal.
- decisions: switched the Monero key-generation approach from PedPoP/FROST threshold
  shares (steps 5a/5b) to additive `Interpolation::Constant` shares (step 6) — see the
  `- done:` entry above for the full reasoning, verified by the `oracle` against actual
  `dkg`/`dkg-pedpop` source before implementing, not guessed.
- needs: nothing right now.
