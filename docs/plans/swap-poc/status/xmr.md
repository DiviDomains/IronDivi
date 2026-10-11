# Lane xmr status

- done: baretxid fix (`f8f7e9b`); build-plan steps 2-4 (`3e99c00`); step 7's bridge
  (`0139101`); root `Cargo.toml` wiring (`c73478e`, `cf80ac0`); step 5a (`02e6f0c`);
  step 5b (`23265e7`); step 6 (`6f4c32a`). Confirmed clean after lane-sync.
  New this round — **step 7, done, and a second design correction** (after step 6's
  PedPoP→additive correction, same pattern: hit a design doubt, escalated to the
  `oracle` per lane rule 7 before writing code, fixed the doc first):
  - Before implementing `Tx_redeem`/`Tx_refund`/`Tx_punish`, re-reading xmr-design.md's
    own `## Protocol` table against its own explanatory prose turned up a
    self-contradiction (e.g. `Tx_refund`'s row said Maker's signature was the adaptor
    one, but the row's own rationale text said that "reveals nothing new" — a sign the
    table was just wrong). Escalated to the `oracle`, which verified against the actual
    reference implementation (`comit-network/xmr-btc-swap`'s `alice`/`bob` state
    machines) that the design had been using a **single shared secret `x`** throughout,
    when the real Gugger/COMIT construction needs **two independent secrets**, one per
    party, and had several signer/completer roles backwards. Rewrote `## Protocol` and
    `## DLEQ` accordingly:
    - `Tx_redeem` (pays Taker): **Maker's** sig is adaptor-encrypted under Taker's point
      `X = s_t·G`; **Taker** completes (she holds `s_t`) and broadcasts, revealing `s_t`
      to Maker.
    - `Tx_refund` (pays Maker): **Taker's** sig is adaptor-encrypted under a *second,
      independent* point `Y = s_m·G` (Maker's secret, not `x`); **Maker** completes (he
      holds `s_m`) and broadcasts, revealing `s_m` to Taker — the mechanism that lets her
      reclaim her own locked XMR on abort, otherwise impossible.
    - `Tx_punish` (pays **Taker**, not Maker — also backwards before): **plain** 2-of-2,
      no adaptor signature at all; Maker signs at setup, Taker holds and broadcasts it.
    - Two DLEQ proofs needed, not one: Taker proves `s_t`↔`X`, Maker proves `s_m`↔`Y`.
      `Tx_cancel` was the one row already correct.
  - New `crates/swap-chain-xmr/src/swap_templates.rs` (production code) implementing the
    corrected roles: `maker_encrypts_tx_redeem`/`taker_completes_tx_redeem`,
    `taker_encrypts_tx_refund`/`maker_completes_tx_refund` (both using
    `divi_secret_to_adaptor_scalar` to let the *same* DIVI multisig key sign both plainly
    and as an adaptor, depending on which transaction calls for which), and
    `recover_secret_from_chain` (the step that lets the non-completer learn the other's
    secret once a completed signature is on-chain). `Tx_punish` needed no new function —
    just the right call to the existing `multisig::build_presigned_spend`.
  - 4 new tests: `Tx_redeem` completes and Maker recovers `s_t`;  `Tx_refund` completes
    (respecting `t_refund`) and Taker recovers `s_m`; `Tx_punish` is plain and pays
    Taker; completing `Tx_redeem` with the wrong secret now fails *at completion time*
    (a `BadCompletion` error) rather than only later at script verification — caught one
    real bug this way: my first `Tx_refund` draft put the two signatures in the wrong
    scriptSig order relative to the redeem script's pubkey order (`OP_CHECKMULTISIG`
    needs them to match), which `verify_input` caught immediately as `EvalFalse`.
  - 19 tests total in swap-chain-xmr with `--features live` (was 15); `cargo fmt`,
    `clippy -p swap-chain-xmr --all-targets [--features live] -- -D warnings`, and
    `cargo clippy --workspace --all-targets -- -D warnings` all green. `Cargo.lock`/
    `Cargo.toml` unchanged — step 7 needed no new dependencies.
- running: nothing.
- broken: none in my paths.
- left, in order:
  - step 5b's deferred final slice: fund the address `monero_dkg`'s (reference-only)
    test derives and prove a live 2-of-2 cooperative spend — needs real stagenet
    block-time (self-mine via `getblocktemplate`/`submitblock`, no faucet) and both
    parties' live participation in `monero_wallet::send::multisig`. Should use
    `monero_key_share`'s additive keys, not `monero_dkg`'s PedPoP ones. Genuinely gated
    on elapsed time, not more Rust — worth a dedicated pass.
  - step 8: happy-path e2e, DIVI testnet + Monero stagenet, throwaway keys, now with a
    concrete DIVI-side transaction set (step 7) and Monero-side key story (step 6) to
    exercise end to end.
  - step 9: engine-integration proposal.
- decisions: corrected the single-secret model in `## Protocol`/`## DLEQ` to the
  two-secret model the real construction needs (see `- done:` above) — verified by the
  `oracle` against the actual reference implementation before writing step 7's code, not
  guessed. This is the second time this lane has caught and fixed a wrong assumption in
  its own earlier design-doc draft by escalating to the oracle before building on it
  (step 6's PedPoP→additive correction was the first) — worth continuing that habit for
  steps 8-9 too, since both touch protocol mechanics as subtle as this one was.
- needs: nothing right now.
