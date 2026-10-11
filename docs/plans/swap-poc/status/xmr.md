# Lane xmr status

- done: baretxid fix (`f8f7e9b`); build-plan steps 2-4, `crates/swap-adaptor` +
  `crates/swap-chain-xmr` (`3e99c00`); step 7's bridge, adaptor signatures into DIVI
  scriptSigs (`0139101`); root `Cargo.toml` membership + lockfile (`c73478e`, `cf80ac0`).
  Confirmed clean after lane-sync: both crates build, 17 tests pass
  (`cargo test -p swap-adaptor -p swap-chain-xmr`), full `cargo clippy --workspace
  --all-targets -- -D warnings` is green (the earlier unrelated `swap-chain-evm`
  unused-import failure is gone too — fixed by that lane in the meantime).
  New this round — **step 5a**: a 2-of-2 PedPoP distributed-key-generation round trip,
  entirely offline, in new `crates/swap-chain-xmr/src/monero_dkg.rs`:
  - Both parties run the real 3-round protocol (`KeyGenMachine::generate_coefficients` ->
    `SecretShareMachine::generate_secret_shares` -> `KeyMachine::calculate_share` ->
    `BlameMachine::complete`) using `ciphersuite::Ed25519` — the actual Ed25519 group
    `monero-wallet`'s own `multisig` feature uses, not the `Ristretto` group
    `dkg-pedpop`'s own test suite happens to use (checked `dkg-pedpop`'s actual source to
    get the exact call sequence, not guessed).
  - Test confirms both parties converge on the *same* group (public) key while holding
    *different* secret shares — the "2-of-2 spend key neither party alone can derive"
    property `xmr-design.md`'s `## Protocol` needs.
  - Hit and resolved **two real upstream packaging bugs** getting there, both now pinned
    around in `swap-chain-xmr/Cargo.toml` with comments explaining why:
    1. `dkg-pedpop` 0.6.0 (crates.io) uses `multiexp::BatchVerifier` without itself
       requesting `multiexp`'s `"batch"` feature — added `multiexp = {version="0.4",
       features=["batch"]}` directly so Cargo's feature unification covers it.
    2. `schnorr-signatures` 0.5.3 widened its `multiexp` requirement from the strict
       `^0.4` every sibling crate (`dkg-pedpop`, `modular-frost`) uses to `>=0.4.2,<=0.5`
       — since 0.4.x and 0.5.x are different Cargo "SemVer compatibility classes" for a
       0.x crate, this makes Cargo resolve *two separate incompatible copies* of
       `multiexp` in one build (`BatchVerifier` type mismatch). Pinned
       `schnorr-signatures = "=0.5.2"` (the version before the widening) to force the
       whole tree back onto one `multiexp` line. Neither of these is fixable without a
       `[patch.crates-io]` in the *workspace root* Cargo.toml (which I can't touch,
       lane rule 2) — the version pins are the correct workaround from a dependent crate.
  - Not yet done: wire-format compatibility with `monero-wallet`'s own multisig types
    specifically (it may wrap `ciphersuite::Ed25519` keys differently than this raw test
    does), and anything touching an actual stagenet node (broadcast, confirmations) —
    that's step 5b, deliberately left for a dedicated pass since it needs real wall-clock
    time waiting on block confirmations, not just more Rust.
- running: nothing.
- broken: none in my paths.
- left: step 5b (wire `ciphersuite::Ed25519` keys into `monero-wallet`'s actual multisig
  API and prove a stagenet spend — needs real network time); step 6 (wire the
  `swap-adaptor` secret through the cross-group DLEQ into one party's share of this
  Monero key, closing the loop between the DIVI-side adaptor signature and the Monero
  spend key the design depends on); step 7's remainder (the rest of the
  `Tx_cancel`/`Tx_refund`/`Tx_punish`/`Tx_redeem` template set — the bridge module proves
  the mechanics, the multi-tx wiring itself is still open); step 8 (happy-path e2e,
  DIVI testnet + Monero stagenet); step 9 (engine-integration proposal).
- decisions: no new architectural decisions in xmr-design.md this round. Confirmed (by
  reading `dkg-pedpop`'s actual source, not docs) that `modular-frost` only *signs* given
  pre-generated `ThresholdKeys` — `dkg-pedpop` is genuinely where key generation lives,
  as recorded last round.
- needs: nothing right now.
