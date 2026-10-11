# Lane xmr status

- done: baretxid fix (`f8f7e9b`); build-plan steps 2-4 (`3e99c00`); step 7's bridge
  (`0139101`); root `Cargo.toml` wiring (`c73478e`, `cf80ac0`); step 5a (`02e6f0c`);
  step 5b (`23265e7`); step 6 (`6f4c32a`); step 7 + the two-secret protocol correction
  (`f54edba`). Confirmed clean after lane-sync.
  New this round — **step 8, mock happy-path e2e, done**: new
  `crates/swap-chain-xmr/src/happy_path_e2e.rs`, one test chaining every mechanical
  piece built so far into a single run of `## Protocol`'s happy path, with throwaway
  keys, entirely offline:
  1. Both DLEQ proofs (Taker's `s_t`↔`X`, Maker's `s_m`↔`Y`), verified by the other
     party, exactly as `## Protocol` step 1 specifies.
  2. Confirms the Monero verification shares fed into `monero_key_share`'s additive
     `ThresholdKeys` are *literally* the DLEQ proofs' own claimed ed25519 points
     (compared via compressed bytes) — not independently recomputed, so this actually
     exercises the DLEQ-to-Monero-key binding the design depends on, not a parallel
     construction that happens to agree.
  3. `Tx_cancel` (plain 2-of-2, `t_cancel`-gated) spending a mocked `Tx_lock` outpoint —
     funding `Tx_lock` for real needs a DIVI testnet broadcast, out of scope for this
     mock run.
  4. `Tx_redeem`: Maker encrypts under `X`, Taker completes with her derived secp256k1
     `s_t` (checked it matches the DLEQ's claimed point `X` before using it) and
     broadcasts.
  5. Maker recovers `s_t` from the chain, bridges it back to its ed25519 representation,
     and the punchline assertion: `(s_m + recovered_s_t)·G` equals the Monero group key
     both parties already agreed on in step 2 — the actual cryptographic claim the whole
     design rests on, checked by direct arithmetic, not just "the types matched."
  - 20 tests total in swap-chain-xmr with `--features live` (was 19); `cargo fmt`,
    `clippy -p swap-chain-xmr --all-targets [--features live] -- -D warnings`, and
    `cargo clippy --workspace --all-targets -- -D warnings` all green. No new
    dependencies — built entirely from steps 2-7's existing public functions.
  - Deliberately does **not** attempt real broadcast/funding: lane rule 5 reserves
    funded live runs for the orchestrator (Mac, `secret get`); hp2 has no secrets by
    design. `stagenet_rpc`'s `live` feature already proves this crate can *reach* a real
    node; the actual fund-and-spend is the one remaining item below.
- running: nothing.
- broken: none in my paths.
- left:
  - the one item genuinely gated on elapsed time, not more Rust: fund the address
    `monero_dkg`'s (reference-only) test derives and prove a live 2-of-2 cooperative
    spend on stagenet (self-mine via `getblocktemplate`/`submitblock`, no faucet; both
    parties' live participation in `monero_wallet::send::multisig`) — plus, symmetrically,
    an actual DIVI testnet broadcast of the mocked `Tx_lock`/`Tx_cancel`/`Tx_redeem`
    chain `happy_path_e2e.rs` proves offline. Should use `monero_key_share`'s additive
    keys. Worth a dedicated pass with real coordination, not foldable into a code round.
  - step 9: engine-integration proposal — the last build-plan step, and the one that
    doesn't depend on live infrastructure at all. Next up.
- decisions: none new this round — step 8 was implementation against the already-twice-
  corrected `## Protocol`/`## DLEQ` sections, not a new design question.
- needs: nothing right now.
