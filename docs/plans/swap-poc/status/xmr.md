# Lane xmr status

- done: baretxid fix (`f8f7e9b`); build-plan steps 2-4 (`3e99c00`); step 7's bridge
  (`0139101`); root `Cargo.toml` wiring (`c73478e`, `cf80ac0`); step 5a, the 2-of-2 PedPoP
  key-generation round trip (`02e6f0c`). Confirmed clean after lane-sync.
  New this round — **step 5b, first slice**: bridged the PedPoP group key into a real
  Monero address, in `crates/swap-chain-xmr/src/monero_dkg.rs`:
  - `ciphersuite::Ed25519`'s group type is `dalek_ff_group::EdwardsPoint`, a public-field
    tuple wrapper (`pub struct EdwardsPoint(pub curve25519_dalek::EdwardsPoint)`, checked
    the macro that generates it, not assumed) — so `keys.group_key().0` is directly the
    raw `curve25519_dalek::EdwardsPoint` `monero_wallet::ed25519::Point::from(..)` wants.
    No conversion shim needed, just one field access.
  - New test `group_key_derives_a_real_stagenet_address`: runs the step 5a round trip,
    bridges the group key as above, builds a `monero_wallet::ViewPair` (view key
    generated fresh per test — see the test's doc comment on why a real swap would share
    this in the clear instead), and renders a real stagenet `MoneroAddress`. Both
    parties' view of the group key produce the identical point/address, confirmed by
    assertion.
  - 11 tests total in swap-chain-xmr now (was 10); `cargo fmt`/`clippy -p swap-chain-xmr
    --all-targets -- -D warnings`/`cargo clippy --workspace --all-targets -- -D warnings`
    all green.
  - What this does *not* yet prove: that address is unfunded and untested against a live
    node — no RPC client wired up yet, no XMR sent, no spend attempted. That's the rest
    of step 5b.
- running: nothing.
- broken: none in my paths.
- left, in order:
  - step 5b remainder: wire an async RPC client (`monero-simple-request-rpc` ->
    `monero-daemon-rpc`'s `MoneroDaemon<T>`, needs `tokio`) to one of the public stagenet
    nodes already confirmed live (`node[1-3].monerodevs.org:38089`, etc. — checked two
    rounds ago), fund the derived address (stagenet mining is permissionless but still
    needs real wall-clock time to accumulate spendable confirmations — flag as needing
    a dedicated pass, not a quick addition), and prove a 2-of-2 cooperative spend via
    `monero_wallet::send::multisig` (confirmed last round it consumes `ThresholdKeys<
    Ed25519>` directly, the exact type step 5a/5b already produce).
  - step 6: wire the `swap-adaptor` secret through the cross-group DLEQ into one party's
    share of this Monero key — closes the loop between the DIVI-side adaptor signature
    and the Monero spend key the whole design depends on.
  - step 7 remainder: the rest of the `Tx_cancel`/`Tx_refund`/`Tx_punish`/`Tx_redeem`
    template set (the bridge module proves the mechanics; the multi-tx wiring itself is
    still open).
  - step 8: happy-path e2e, DIVI testnet + Monero stagenet, throwaway keys.
  - step 9: engine-integration proposal.
- decisions: no new architectural decisions in xmr-design.md this round — this was
  implementation following the plan already written.
- needs: nothing right now.
