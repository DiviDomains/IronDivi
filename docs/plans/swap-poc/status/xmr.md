# Lane xmr status

- done: baretxid fix (`f8f7e9b`); build-plan steps 2-4 (`3e99c00`); step 7's bridge
  (`0139101`); root `Cargo.toml` wiring (`c73478e`, `cf80ac0`); step 5a (`02e6f0c`);
  step 5b first slice, the stagenet-address bridge (`23265e7`). Confirmed clean after
  lane-sync (no conflicts this round — the orchestrator's intent-to-add fix held).
  New this round — **step 5b, remainder**: live (read-only) RPC connectivity, in new
  `crates/swap-chain-xmr/src/stagenet_rpc.rs`:
  - `monero_simple_request_rpc::SimpleRequestTransport::new(url)` returns a ready-to-use
    `MoneroDaemon<SimpleRequestTransport>` directly (one async call, no separate
    transport/client wiring needed) — confirmed against its actual source rather than
    assumed.
  - New test `connects_to_public_stagenet_node`, gated behind a new `live` Cargo feature
    (same convention as `swap-chain-btc`/`swap-chain-divi`'s `#[cfg(feature = "live")]
    mod live` — no `#[ignore]` needed, the feature gate alone keeps it out of a plain
    `cargo test`): connects to `node.monerodevs.org:38089` and calls
    `ProvidesBlockchainMeta::latest_block_number()`. **Ran it for real** — got back a live
    stagenet height, confirming this crate is genuinely live-ready, not just type-checked
    against docs.
  - 12 tests total in swap-chain-xmr with `--features live` (11 without, matching before);
    `cargo fmt`, `clippy -p swap-chain-xmr --all-targets [--features live] -- -D
    warnings`, and `cargo clippy --workspace --all-targets -- -D warnings` all green in
    both configurations.
  - Still not done, and the reason step 5b was split across two rounds rather than forced
    into one: funding the derived address and proving an actual 2-of-2 cooperative spend.
    Stagenet mining is permissionless but needs real wall-clock time to accumulate
    spendable confirmations (block time ~2 min, and `monero_wallet::send::multisig`
    itself is a multi-round protocol needing both parties' live participation) — this is
    the first `- left:` item below, and it's the one piece of steps 5-9 that's actually
    bottlenecked on elapsed time rather than more Rust.
- running: nothing.
- broken: none in my paths.
- left, in order:
  - step 5b, final slice: fund the address `monero_dkg`'s test derives (self-mine on
    stagenet via `getblocktemplate`/`submitblock` against the already-confirmed-live
    node — no faucet needed, but real block-time waiting), then prove a live 2-of-2
    cooperative spend via `monero_wallet::send::multisig` (confirmed two rounds ago it
    consumes `ThresholdKeys<Ed25519>` directly — exactly what step 5a/5b already
    produce). This is the one step so far that's genuinely gated on elapsed time, not
    more code; worth a dedicated pass rather than folding into the next round.
  - step 6: wire the `swap-adaptor` secret through the cross-group DLEQ into one party's
    share of this Monero key — closes the loop between the DIVI-side adaptor signature
    and the Monero spend key the whole design depends on.
  - step 7 remainder: the rest of the `Tx_cancel`/`Tx_refund`/`Tx_punish`/`Tx_redeem`
    template set (the bridge module proves the mechanics; the multi-tx wiring itself is
    still open).
  - step 8: happy-path e2e, DIVI testnet + Monero stagenet, throwaway keys.
  - step 9: engine-integration proposal.
- decisions: no new architectural decisions in xmr-design.md this round.
- needs: nothing right now.
