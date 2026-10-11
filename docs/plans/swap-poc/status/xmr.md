# Lane xmr status

- done: baretxid fix (`f8f7e9b`); build-plan steps 2-4 (`3e99c00`); step 7's bridge
  (`0139101`); root `Cargo.toml` wiring (`c73478e`, `cf80ac0`); step 5a (`02e6f0c`);
  step 5b (`23265e7`); step 6 (`6f4c32a`); step 7 + the two-secret protocol correction
  (`f54edba`); step 8, mock happy-path e2e (`1587eee`). Confirmed clean after lane-sync.
  **New this round — step 9, the engine-integration proposal, done.** The last build-plan
  step. Added `## Engine integration` to `xmr-design.md`:
  - Verdict: `divi_swap::ChainBackend`/`SwapState` do not fit, more fundamentally than
    the USDC lane's account-chain mismatch (`usdc-design.md` — that one's a shape
    mismatch within the same hashlock model; this one is a different model). Four
    structural mismatches, each actually load-bearing: (1) no hashlock/preimage at all —
    every `ChainBackend` claim/refund method is parameterized by `HtlcParams`/`preimage`,
    this design has neither; (2) four presigned DIVI transactions, not two, and three
    need an off-chain DLEQ-proof-and-encrypted-signature exchange *before* they can even
    be built — `ChainBackend` has no hook for "build something that depends on a value
    the counterparty sends first"; (3) a second, non-UTXO, no-scripting chain (Monero)
    needed *simultaneously*, not as an alternate counter-chain — `htlc_output`/
    `find_spend` are meaningless questions there; (4) three outcomes (redeem/refund/
    *punish*), not two, and `Tx_punish` is triggered by inaction, not an action —
    `SwapState`'s two terminal paths have no slot for it.
  - Option A (force a fit): considered and rejected as not even worth attempting —
    unlike USDC, where one specific compromise (keeping `approve` outside the
    write-ahead model) sufficed, there is no single compromise here; fixing all four
    mismatches would leave nothing of the original trait but its name.
  - Option B (recommended): a dedicated module outside `ChainBackend` entirely — a new
    state enum mirroring `## Protocol`'s own table, two narrow backend-shaped traits
    (DIVI-side reusing `crates/swap-chain-xmr`'s actual primitives; Monero-side wrapping
    `monero_key_share`/the stagenet RPC client this lane already built), a setup phase
    for the mutual DLEQ-proof exchange with no analog in today's `Quoted`/`Accepted`,
    and its own daemon/CLI path rather than `divi-swapd`'s existing offer pipeline.
  - What carries over regardless of which option: this lane's DIVI-side code
    (`crates/swap-chain-xmr`) already reuses `divi-wallet`/`divi-script`/
    `divi-primitives` the same way `swap-chain-divi` does, so a real implementation's
    DIVI RPC/broadcast plumbing could share code with `swap-chain-divi` even without
    sharing the `ChainBackend` trait.
  - Docs-only change; `check-xmr.sh` still passes (no required section names touched,
    `## Engine integration` is additional).
- running: nothing.
- broken: none in my paths.
- left: **all nine build-plan steps are done.** What remains is the one item repeatedly
  parked as genuinely gated on elapsed time/coordination, not more Rust or more design:
  - fund the address `monero_dkg`'s (reference-only) test derives and prove a live 2-of-2
    cooperative spend on stagenet (self-mine via `getblocktemplate`/`submitblock`, no
    faucet; both parties' live participation in `monero_wallet::send::multisig`), and
    symmetrically an actual DIVI testnet broadcast of the `Tx_lock`/`Tx_cancel`/
    `Tx_redeem` chain `happy_path_e2e.rs` already proves offline. Should use
    `monero_key_share`'s additive keys (not `monero_dkg`'s PedPoP reference ones). Needs
    real coordination between two throwaway identities and real wall-clock time for
    confirmations on both chains — worth a dedicated pass, not foldable into a code
    round, and per lane rule 5 the *funded* parts of this are the orchestrator's to run
    from the Mac in any case.
  - Separately, per `## Engine integration`'s recommendation above: deciding on and
    scoping the dedicated adaptor-swap module (Option B) is the orchestrator's call, not
    something for this lane to build unilaterally — see `- needs:` below.
- decisions: none new this round — step 9 was writing up the integration question the
  build plan already flagged, using the actual trait/state-machine source rather than
  assumption (same discipline as the two design corrections in earlier rounds).
- needs: the engine-integration decision itself — `## Engine integration`'s Option B
  (a dedicated module/trait pair for adaptor-signature swaps, outside `ChainBackend`) vs.
  any alternative the orchestrator prefers. This lane recommends Option B and explains
  why Option A isn't worth attempting, but the actual choice belongs to the orchestrator,
  same posture the plan already takes for USDC's wave 1c mismatch.
