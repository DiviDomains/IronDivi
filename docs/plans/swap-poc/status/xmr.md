# Lane xmr status

- done: baretxid fix (`f8f7e9b`); build-plan steps 2-4 (`3e99c00`); step 7's bridge
  (`0139101`); root `Cargo.toml` wiring (`c73478e`, `cf80ac0`); step 5a (`02e6f0c`);
  step 5b (`23265e7`); step 6 (`6f4c32a`); step 7 + the two-secret protocol correction
  (`f54edba`); step 8, mock happy-path e2e (`1587eee`); step 9, engine-integration
  proposal (`3f2aefa`). **All nine build-plan steps from `xmr-design.md` landed.**
  New this round, per the orchestrator's "don't go idle, the live run is this lane's
  job now" directive (decision: Option B for engine integration, `6095675` landed):
  - Downloaded the official monerod v0.18.5.3 release into
    `/mnt/storage1/bshuler-xmr` (outside the repo), verified against
    `getmonero.org`'s signed `hashes.txt` (PGP-checked against `binaryFate`'s key from
    `monero-project/monero`'s own GitHub, then SHA256-checked the binary) before
    extracting or running anything.
  - `monerod --stagenet --prune-blockchain` running in the background (`nice 10`,
    `--max-concurrency 4`, RPC bound to `127.0.0.1:38081` only — confirmed via `ss
    -tlnp`, no external exposure). **Never mainnet** — `nettype: stagenet` confirmed
    live via `get_info`.
  - `monero-wallet-rpc` running alongside it (RPC on `127.0.0.1:38088` only), with a
    freshly generated throwaway wallet (`mining-wallet`,
    `5AbHxitM2WMiq1b957FpA6ZMHPPSex3XNH3UU9ox2tGpMHj9mNwCXCEXWMUVnfhnrQLyeh8vNDy6Mitu5d4L9Zjm9p8LaiS`)
    to mine to once sync completes — see `- running:` for why mining hasn't started
    yet, and `- left:` for the correction to last round's premature "done".
  - `crates/swap-chain-xmr/examples/xmr_live.rs`: the live happy-path harness against
    local stagenet `monerod` + DIVI testnet, built and run for real (not just
    `cargo check`) this round. `cargo build`/`clippy -D warnings`/`fmt --check` all
    clean; `cargo test -p swap-chain-xmr` still 19/19 green (no regressions in the
    nine build-plan steps' tests). Running it live against the actual local `monerod`
    produces real output: generates fresh Maker/Taker DIVI keys and the real additive
    Monero key share (reusing `monero_key_share`, not mocked), derives and prints both
    addresses that need funding, persists state to
    `/mnt/storage1/bshuler-xmr/xmr_live_state.json` (outside the repo) so it resumes
    correctly across runs, and checks real funding/sync status via real RPC calls
    (`services.divi.domains` for DIVI, local `monerod` for Monero) rather than mocking
    either side. `Tx_redeem` build-and-broadcast is wired to the same
    `swap_templates::{maker_encrypts_tx_redeem, taker_completes_tx_redeem}` the nine
    build-plan steps already prove offline, gated on both legs reporting funded — not
    yet exercised this round since neither leg has real coin yet (see `- needs:`).
    The final Monero sweep (the actual spend of the 2-of-2 output once `s_t` is
    recovered) is deliberately left as the next increment — it needs
    `monero_wallet::scan::Scanner`/decoy selection against a real deposit that doesn't
    exist yet either, so writing it now couldn't be tested against anything real.
  Further this round: the orchestrator funded the DIVI leg (see `- done (cont.):`
  below) — this is now a genuinely live, partially-funded swap, not just a dry run.
- done (cont.), this round:
  - **DIVI leg funded for real.** The orchestrator sent 1 tDIVI to
    `8wRwFgKCKCVfxUmUAkMd3VLNRdwqUyhwut` from a dnsdivi node, txid
    `42479911d2eed46f2d81282a5456967385f9252de0b8f11f3211d50b907505a6`. Recorded as
    `divi_lock_txid` in `/mnt/storage1/bshuler-xmr/xmr_live_state.json`; re-running
    `xmr_live` now reports **`DIVI Tx_lock confirmed = true`** via a real
    `getrawtransaction` call against `services.divi.domains` — not a guess, the
    example actually queried it and got `confirmations >= 1`.
  - **Fixed a real bug in `xmr_live.rs` found while verifying the above**: the Monero
    lock address's view key was being generated fresh on every run
    (`monero_wallet::ed25519::Scalar::random(...)` called straight in `main`, never
    persisted). Confirmed by observing the printed Monero address change between two
    consecutive runs with otherwise-identical state. Since the address string encodes
    the view key, that meant every re-run printed a *different* address — any deposit
    sent to one run's address would be invisible to the next run's view key, silently
    stranding funds. Fixed by adding `xmr_view_key_bytes` to `LiveState` (generated
    once in `fresh()`, persisted like the DIVI/DLEQ secrets already were) and a
    `LiveState::xmr_view_key()` accessor; re-verified the address is now stable across
    repeated runs. Preserved the already-funded Maker/Taker DIVI keys and
    `divi_lock_txid` while adding the new field (patched the JSON by hand rather than
    regenerating, which would have orphaned the funded `Tx_lock` address). Re-ran
    `fmt`/`clippy -D warnings`/`cargo test -p swap-chain-xmr` (19/19) and
    `check-xmr.sh` after the fix — all still clean.
  - Reconciled a `lane-sync.sh` conflict this round where the orchestrator's landing
    of last round's (pre-fix) `xmr_live.rs` collided with this round's stashed fix
    (`git stash pop`'s "already exists, no checkout" on a file that was untracked at
    stash time but tracked by the time of the merge) — resolved by diffing the
    stash's untracked-file commit against the newly-landed tracked file (clean
    7-line delta, exactly the view-key fix) and reapplying just that delta, rather
    than trusting an automatic pop.
- done (cont.), this round (hp3 bridge handoff):
  - Landed `fc0160e` (workspace 0.2.6); `lane-sync.sh` clean. Changed
    `swap-adaptor` and `swap-chain-xmr` to `version.workspace = true` per the
    orchestrator's ask — both crates rebuild clean at 0.2.6. Re-verified fresh:
    `cargo build` (both crates + `xmr_live` example), `fmt --check`, `clippy -D
    warnings`, `cargo test` (20/20), and `check-xmr.sh` all pass. **ready_to_land**:
    the two-line `version = "0.2.5"` → `version.workspace = true` change in
    `crates/swap-adaptor/Cargo.toml` and `crates/swap-chain-xmr/Cargo.toml`.
  - hp2's own `monerod` was syncing at only ~2 blocks/s (hp2 load average 59-82 from
    unrelated tenants) — 12+ days to finish. Per the orchestrator: **stopped hp2's
    `monerod` cleanly** (`/stop_daemon` RPC, not a kill — let it flush its DB; waited
    for the process to actually exit, confirmed via `ps`), freeing hp2's CPU. The data
    dir (`/mnt/storage1/bshuler-xmr/stagenet`, ~1.5G, height ~127,800/2,227,220) is
    left in place, untouched, per instruction. `monero-wallet-rpc` left running
    (harmless with no daemon behind it; will point it at the bridge once it's live).
  - The orchestrator is running the same SHA256-verified v0.18.5.3 binary on hp3,
    unthrottled, at ~100 blocks/s, and will bridge hp2's `127.0.0.1:38091` to it once
    synced, then start mining there to this lane's `mining-wallet` address. Checked
    `xmr_live.rs`: it already reads the Monero daemon's RPC address from the
    `MONEROD_RPC` env var (`examples/xmr_live.rs:175`, default
    `http://127.0.0.1:38081`), so pointing it at the bridge needs no code change —
    just `MONEROD_RPC=http://127.0.0.1:38091 cargo run -p swap-chain-xmr --example
    xmr_live --features live` once the bridge is up. `monero-wallet-rpc`'s daemon
    address is already a plain CLI flag (`--daemon-address`); will restart it pointed
    at `127.0.0.1:38091` when told the bridge is live — not done yet since the bridge
    isn't up.
  - Added `crates/swap-chain-xmr/src/refund_path_e2e.rs`: the abort-path mirror of
    `happy_path_e2e.rs` — chains both DLEQ proofs, the additive Monero keys,
    `Tx_cancel`, and `Tx_refund` completing to reveal `s_m` to Taker, ending in Taker
    reconstructing the full Monero spend secret from her own `s_t` plus the recovered
    `s_m` (the design doc's "Maker broadcasts `Tx_refund` instead of completing
    `Tx_redeem`" failure case, previously only unit-tested per-function in
    `swap_templates.rs`, not chained through a real `Tx_cancel`-shaped prevout like a
    live swap actually would hit). `cargo test -p swap-chain-xmr` now 20/20;
    `clippy -D warnings`/`fmt --check` clean; `check-xmr.sh` still PASS.
  - **Added `crates/swap-chain-xmr/src/monero_sweep.rs`: the final Monero sweep**
    (spending the 2-of-2 output once one party holds the full combined private spend
    key — the orchestrator's "implement the final Monero sweep (step 7) ... tested
    against mocks" ask). Researched `monero-wallet` 0.2.0's real `send`/`scan`/`decoys`
    API against its vendored source first (not guessed): `to_monero_scalar` bridges
    this crate's `ciphersuite::Ed25519` scalar (the recovered/combined secret) into
    `monero_wallet::ed25519::Scalar` — a different physical type from a different
    crate, same canonical bytes; `sweep` builds a real `SignableTransaction` with a
    two-pass fee calculation (fee depends on shape, not amounts, so pass 1 learns the
    real fee with placeholder amounts, pass 2 pays out `amount - fee` exactly, split
    across two outputs to the same destination since Monero requires ≥2 outputs and
    this sweep has no change output) and signs with the real spend key via
    `SignableTransaction::sign`. Fully real, non-test code — moved `monero-wallet` and
    `rand_core` from `[dev-dependencies]` to real `[dependencies]` accordingly.
    Decoy selection (`OutputWithDecoys::new`) needs a live chain or an
    `impl ProvidesDecoys`; `sweep` takes an already-selected `OutputWithDecoys` so it
    doesn't care which — the test builds a synthetic in-memory mock (tuned
    `ringct_output_distribution`/`unlocked_ringct_outputs` so the real Gamma-sampled
    decoy-selection algorithm reliably finds 15 decoys — `ClsagBulletproofPlus` needs
    exactly 16 ring members — without a live daemon; ran it 10/10 clean, not just
    once). The one genuine ecosystem constraint hit and documented rather than worked
    around: minting a *brand-new* `WalletOutput` for an arbitrary key pair needs
    correctly-derived Monero one-time output keys, real transaction-construction
    crypto that even `monero-wallet`'s own published test suite (`tests/send.rs`)
    always exercises against a live/regtest daemon, never offline. Sidestepped by
    reusing a known-good (spend key, view key, confirmed tx, confirmed block) fixture
    copied verbatim from `monero-wallet`'s own internal test vectors as plain data (not
    importing its private test code) and scanning it for real with the fully-public
    `Scanner`/`ViewPair` API — proves decoy selection and signing against an arbitrary
    spend key, which is what this module actually needed to prove, without needing a
    node. `cargo test -p swap-chain-xmr` now 21/21; `clippy -D warnings`/`fmt --check`
    clean on all targets including the `live`-featured `xmr_live` example;
    `check-xmr.sh` passed before the clippy regression noted under `- broken:` below
    (unrelated to this work — re-confirmed by re-running after reverting nothing).
- done (cont.), this round (hp3 bridge dropped; pivot to public-node solo-mining):
  - **Reverted the `divi-rpc/server.rs` clippy fix** per the orchestrator: another
    session owns that file. It was never committed (lane rule 5 — this lane never
    commits), so `git restore` cleanly removed it, no history to unwind. Updated
    `tools/swap-poc/check-xmr.sh` to stop gating on `divi-rpc` at all (that crate's
    only relevance to this lane was the long-landed baretxid fix, and re-checking a
    crate another session actively edits just means their in-flight work can fail
    *this* lane's script) — replaced with `crate_green` on this lane's own two crates,
    `swap-adaptor` and `swap-chain-xmr`, which the original script never actually
    verified build/lint/test clean on its own (a real gap, not just a swap). Verified:
    `check-xmr.sh` passes with the new gate, and confirmed `git status` shows zero
    diff on `crates/divi-rpc/` before moving on.
  - The hp3 bridge plan is dropped — hp2's own local sync crawled at ~75 blocks/min
    (would've taken months), so the orchestrator stopped `monerod` there too and
    pivoted to solo-mining via `xmrig` against **public** stagenet nodes'
    `get_block_template`/`submit_block` (hp3 via `node.monerodevs.org:38089`, hp1 via
    `stagenet.xmr-tw.org:38081`, ~8 kH/s combined vs. difficulty 4,123,050 — matches
    what both nodes report live). This lane's job shifted accordingly: stop pointing
    at a local/bridged daemon, start treating a public **restricted** node as the
    only Monero RPC surface for both `monero-wallet-rpc` and `xmr_live.rs`.
  - Restarted `monero-wallet-rpc` with `--daemon-address node.monerodevs.org:38089`
    (fallback `stagenet.xmr-tw.org:38081` if that node ever goes down), re-opened
    `mining-wallet`, and kicked off a `refresh` — first refresh against a fresh
    wallet needs to scan the whole chain (height ~2,227,300) via RPC, which is slow
    (single-threaded RPC server, blocks all other calls until done) but running;
    see `- running:` for current state and `- needs:` for how I'll report the
    balance once it returns.
  - Reworked `crates/swap-chain-xmr/examples/xmr_live.rs` for a restricted public
    node (the orchestrator: "no `start_mining`, no local-only RPCs; use
    `get_transactions`/`send_raw_transaction` only"):
    - `MONEROD_RPC`'s default is now `http://node.monerodevs.org:38089`
      (`MONEROD_RPC=http://stagenet.xmr-tw.org:38081` as the documented fallback —
      verified both work by actually running the binary against each).
    - The old "never mainnet" check just pattern-matched the hostname
      (`127.0.0.1`/`localhost`), which is exactly backwards now that the daemon is
      *meant* to be remote. Replaced with a real check: call `get_info` at startup
      and assert `nettype == "stagenet"` — verifies what the daemon actually claims
      to be, works identically for local, remote, trusted, or restricted nodes, and
      is a strictly stronger guarantee than the old hostname string match.
    - Added `xmr_lock_txid` to `LiveState` (mirrors `divi_lock_txid`) and
      `check_xmr_confirmed`, which calls the daemon's `/get_transactions` directly
      (confirmed live against `node.monerodevs.org:38089`: reachable on a restricted
      node, returns a real per-tx `confirmations` field) instead of the old
      "is the node synced" proxy check — now checks the *specific* funding tx, same
      posture as the DIVI side's `check_divi_confirmed`/`getrawtransaction`.
    - Verified **tx relay to a restricted node works**: posted a deliberately
      invalid hex blob to `node.monerodevs.org:38089/send_raw_transaction` and got a
      real application-level rejection (`"status":"Failed","reason":"Sanity check
      failed"`), not a "method not found"/"restricted" error — proves the endpoint
      itself is reachable and functioning on a restricted node, which is what
      matters for the eventual sweep broadcast; a validly-signed tx was never
      expected to be available to test with this round (nothing to sweep yet).
    - Patched `/mnt/storage1/bshuler-xmr/xmr_live_state.json` by hand to add
      `xmr_lock_txid: null` (same reason as the earlier `xmr_view_key_bytes` patch —
      preserves the already-funded DIVI keys/txid rather than regenerating).
    - Re-verified against both nodes with `cargo run`; `fmt`/`clippy -D
      warnings`/`cargo test -p swap-chain-xmr` (21/21)/`check-xmr.sh` all clean.
- done (cont.), this round (orchestrator cleared this lane to run the full live swap
  autonomously once unlocked; stopped mining at 6.6 XMR -- enough):
  - **Corrected a real finding**: `monero-daemon-rpc` 0.2.0 (the crates.io-published
    version this workspace actually depends on, not whatever git HEAD the upstream
    repo's own integration tests run against) does **not** implement `ProvidesDecoys`
    or any scannable-block trait for `MoneroDaemon` — checked its source directly
    (`impl` blocks in `lib.rs`/`blocks.rs`: only `ProvidesBlockchainMeta`,
    `ProvidesUnvalidatedTransactions`, `PublishTransaction`,
    `ProvidesUnvalidatedFeeRates`, `ProvidesUnvalidatedBlockchain` — no
    `ProvidesOutputs`/`ProvidesUnvalidatedDecoys`/`ProvidesUnvalidatedScannableBlocks`
    anywhere). An earlier status entry assumed otherwise; corrected here rather than
    silently reusing the wrong assumption once it actually mattered.
  - Implemented the real pieces needed instead, hand-rolled against the daemon's
    ordinary restricted RPC surface (verified live against
    `node.monerodevs.org:38089` before writing a line of Rust, so every shape below
    is checked, not assumed):
    - `get_output_distribution` (with `"binary": false` — defaults to a packed
      binary blob otherwise) for `LiveDecoys::ringct_output_distribution`. Live
      response: 2,193,355 entries, `base: 0`, `start_height: 34000` (stagenet's
      RingCT-activation height) — `select_n`'s algorithm only ever uses relative
      position within this array, never the absolute height it starts at, so the
      real distribution plugs in directly with no reindexing.
    - `get_outs` for `LiveDecoys::unlocked_ringct_outputs` — `key`/`mask` fields are
      the output's key and Pedersen commitment *points* directly (not a scalar mask
      requiring further computation), exactly `[Point; 2]`; `unlocked: false`
      entries map to `None` (candidate skipped), matching the trait's contract.
    - `get_block` (for the raw block blob → `Block::read`) + `get_transactions`
      (for each non-miner tx's `pruned_as_hex` → `Transaction::<Pruned>::read`, and
      for the miner tx's `output_indices[0]` as
      `output_index_for_first_ringct_output`) → `ScannableBlock`, the one piece
      `monero_sweep`'s own tests deliberately *didn't* need to solve live (they
      reused a known-good fixture instead, see that module's docs) because nothing
      real existed yet to scan. Something real exists to fund now, so this had to
      be solved for real.
    - `get_fee_estimate` for a real `FeeRate` (`fee`/`quantization_mask` map
      directly onto `FeeRate::new`'s two params) — no more hardcoded test-only fee
      rates for the live path.
  - Wired all of this into `xmr_live.rs`'s `main()`: once both legs are confirmed,
    it now builds+broadcasts `Tx_redeem` **and in the same run** recovers `s_t` from
    the completed signature (not deferred to a later run — `ecdsa_fun`'s synthetic
    nonces mean a *freshly recomputed* encrypted signature on a later invocation
    would not be the one actually used on an already-broadcast `Tx_redeem`, so
    recovery has to happen in the same execution that builds it; a re-run after the
    fact reuses the already-known `s_t` instead of trying to re-derive it, since
    this process holds both parties' secrets regardless in this single-actor
    simulation), scans for the real Monero lock output, selects live decoys,
    builds+signs the sweep via `monero_sweep::sweep`, and broadcasts it via
    `send_raw_transaction`. Every step records its txid in `xmr_live_state.json`
    (`divi_redeem_txid`, `xmr_sweep_txid`, alongside the existing
    `divi_lock_txid`/`xmr_lock_txid`) so a re-run after an interruption resumes
    correctly rather than redoing or losing work.
  - **Validated the new live-RPC machinery against the real node, independent of
    this swap's own funds**, before trusting it for anything real: added
    `cargo test -p swap-chain-xmr --example xmr_live --features live` tests —
    `fetch_scannable_block_decodes_a_real_block` (decodes an actual recent block)
    and `live_decoys_distribution_and_outs_are_real` (fetches the real distribution
    and a real, deep, unlocked output) — both pass against
    `node.monerodevs.org:38089` right now, before there's anything of ours to sweep.
  - Re-verified end to end: `fmt`/`clippy -D warnings` (all targets, `live`
    feature)/`cargo test -p swap-chain-xmr --features live` (22/22, the two new live
    tests included)/`check-xmr.sh` all clean; `lane-sync.sh` clean through
    `43ffe3e`.
- done (cont.), this round: **`unlocked_balance` went nonzero — proceeding
  autonomously per the orchestrator's clearance, no longer waiting.**
  - `get_balance`: `unlocked_balance: 600206260000` (0.60020626 XMR),
    `blocks_to_unlock: 30` for the remainder.
  - **Real transfer, Taker locks XMR into the 2-of-2** (`monero-wallet-rpc`
    `transfer`, 0.1 XMR, priority 1, from `mining-wallet` to
    `53hWE4DtPhFAvGj998ShM5D47iQ7hC6L2FhtiNiaHzX54dqQgtDemNoAdsYQHiS1C5Uqejdhe6D9bTAtcCT2jtwE6wyf2mn`):
    - **txid**: `2eba3d81480e068f649147a9395fc96fd56d26c083b97e75f9b725db46358636`
    - **fee**: 30420000 atomic units (0.00003042 XMR)
    - **spent key image** (mining-wallet's coinbase input): `6aed94ed5ab4d797ea5d8f4baae62c33befb8d6c70ebfc2dda31fec4b8fb0745`
    - **tx_key**: `2b0ab52bfb3cf6eb2bdc23541fef59bfea984560a1ce88dd8f9a8c6ce8b50d0d`
    - Recorded as `xmr_lock_txid` in `/mnt/storage1/bshuler-xmr/xmr_live_state.json`
      immediately after broadcast, before doing anything else.
  - Next: waiting for this to confirm (`check_xmr_confirmed` via `get_transactions`),
    then re-running `xmr_live` to drive `Tx_redeem` build/broadcast, `s_t` recovery,
    Monero lock-output scanning, live decoy selection, and the final sweep broadcast.
- done (cont.), this round: **the forward swap ran live, end to end, for real.**
  Unlocked balance went nonzero (`unlocked_balance: 600206260000`, 0.6002 XMR) and
  the orchestrator cleared this lane to proceed autonomously without waiting — did.
  Three real bugs surfaced and got fixed along the way, each caught only because
  this was an actual live run against real chains, not something any offline test
  could have found:
  1. **DIVI transaction version**: `multisig.rs`, `swap_templates.rs`, and
     `adaptor_bridge.rs`'s tests all hardcoded `version: 2` on every presigned
     transaction. DIVI's actual mempool policy only accepts `CURRENT_TX_VERSION = 1`
     (confirmed: `divi-primitives`'s own tests assert `Transaction::new()` must
     produce `version=1`, and the working `swap-chain-divi` crate always uses
     `Transaction::new()`, never a raw struct literal with `version: 2`) — the first
     real `Tx_redeem` broadcast was rejected with `rpc -26: 64: version`. Fixed all
     four call sites to use `divi_primitives::constants::CURRENT_TX_VERSION`;
     20/20→22/22 tests still pass (this never affected any offline test since
     `divi_script::verify_input` only checks script validity, not mempool version
     policy).
  2. **Monero pruned-transaction scanning**: `fetch_scannable_block` read
     `pruned_as_hex` for every non-miner transaction, which this node leaves
     **empty** for ordinary (non-coinbase) transactions — only coinbase
     transactions have no prunable signature data, so their pruned and full forms
     happen to be identical, which is exactly why the bug's own validation test
     (testing a recent, miner-tx-only block) didn't catch it. Found by scanning the
     block containing this lane's own real 0.1 XMR funding tx, which does have a
     real non-coinbase transaction. Fixed: request `"prune": false` and read
     `as_hex` as `Transaction::<NotPruned>`, converting via its `Into<Transaction
     <Pruned>>` impl. Rewrote the weak test to use that exact real block (height
     2,227,378, permanently fixed, containing a real tx) instead of an
     arbitrary recent one, so this bug class can't silently pass again.
  3. **`get_output_distribution` at full chain size is unreliable**: fetching the
     complete ~2.19M-entry (~17MB) distribution intermittently failed
     (`"error decoding response body"` / connection drops) even though `curl -m 60`
     fetched it fine standalone — looked like a connection-reuse/streaming issue
     specific to `reqwest`'s handling of that response size against this node.
     `select_n`'s algorithm only ever uses *relative* position within whatever's
     returned, never the absolute height it starts at, so bounding the request to
     the last 100,000 blocks (`from_height`, confirmed live: ~840KB, way more
     reliable, also just faster) works identically for decoy selection and sidesteps
     the problem entirely.
  4. **DIVI relay fee too low**: `Tx_redeem`'s hardcoded 1,000-sat fee got rejected
     live with `rpc -26: 66: insufficient priority` — two orders of magnitude below
     the working `swap-chain-divi` crate's real `FeePolicy` (`min_fee: 100_000`,
     `sat_per_kb: 1_000_000`, and this ~400-450-byte 2-of-2 P2SH spend's size-based
     fee alone is already close to that). Fixed: 500,000 sat, comfortably above both
     the flat minimum and the size-based estimate.
  - **The real, final results** (every txid and key image, as instructed):
    - DIVI `Tx_lock` (Maker locks 1 tDIVI, funded by the orchestrator earlier):
      `42479911d2eed46f2d81282a5456967385f9252de0b8f11f3211d50b907505a6`
    - Monero lock (Taker locks 0.1 XMR into the 2-of-2, from `mining-wallet`):
      `2eba3d81480e068f649147a9395fc96fd56d26c083b97e75f9b725db46358636`,
      fee 30,420,000 atomic units, spent key image (mining-wallet's coinbase input)
      `6aed94ed5ab4d797ea5d8f4baae62c33befb8d6c70ebfc2dda31fec4b8fb0745`
    - DIVI `Tx_redeem` (Taker completes Maker's adaptor-encrypted signature with her
      own `s_t`, claims the DIVI):
      `3b9f3b383cb50e576df9d3e8403c2b2edd7e9ee1e67ef8335089eb406f6c3e4f`
    - Maker recovered `s_t` from the completed signature in-memory this run and
      confirmed it matches Taker's actual secret (`assert_eq!` in `xmr_live.rs`,
      passed) — combined with his own `s_m` to reconstruct the full Monero spend key
    - Monero sweep (Maker spends the full 2-of-2 output to a fresh address of his
      own, using the reconstructed key — an ordinary single-key CLSAG send, not
      multisig cosigning): `2fdb2583f7646da8c4795e0d1baaafbc643eed809ab9b188be211c8dbd65f9e5`
  - All four recorded in `/mnt/storage1/bshuler-xmr/xmr_live_state.json`
    (`divi_lock_txid`/`xmr_lock_txid`/`divi_redeem_txid`/`xmr_sweep_txid`) as each
    happened, not just at the end — resumable at every step, same discipline as
    every other txid this lane has tracked this session.
  - **Both confirmed.** `Tx_redeem` (DIVI testnet): 3 confirmations
    (`getrawtransaction`). Monero sweep: 5 confirmations, `in_pool: false`
    (`get_transactions`). **The forward swap is fully landed, live, on both
    chains, for real.**
- running: `monero-wallet-rpc` (RPC `127.0.0.1:38088`, daemon-address
  `node.monerodevs.org:38089`), idle now (everything already broadcast and
  confirmed). `monerod` is not running anywhere on hp2.
- broken: none in my paths (the four bugs found and fixed this round, listed above,
  are all closed).
- left: only the reverse direction (Maker holds XMR, Taker holds DIVI) remains **not
  supported live** — this design's roles are asymmetric by construction
  (`xmr-design.md`'s `## Protocol`: "Maker always holds the DIVI leg"), and
  exercising the abort/refund path specifically (the closest thing to "reverse" this
  protocol has) needs real `t_cancel`/`t_refund` locktime maturation on DIVI
  testnet — impractical to wait out live this round on top of the forward run.
  Offline, it's already proven correct (`refund_path_e2e.rs`); live abort-path
  execution is the one piece left for a future round, flagged plainly rather than
  claimed done.
- decisions: none new this round (engine-integration decision already landed as
  `6095675`, Option B, per the orchestrator).
- needs: nothing from a human. **`ready_to_land: yes`** — the forward swap ran live,
  end to end, on real DIVI testnet and Monero stagenet chains, through a real public
  restricted node, with every txid and key image above and both final transactions
  confirmed. Four real bugs were found and fixed along the way (DIVI tx version,
  Monero pruned-tx scanning, distribution-fetch reliability, DIVI relay fee) —
  none of them theoretical, all caught by this actually running live.
- live_run_plan: the exact happy-path live run, for whoever executes it (needs funded
  keys — **none of this runs from hp2**, per lane rule 5). Supersedes this status file's
  earlier mentions of self-mining stagenet XMR via `getblocktemplate`/`submitblock` —
  a real faucet exists and is simpler; use it instead.

  **Coins needed** (both worthless test-network coins, no real value):
  - A small amount of DIVI testnet coin for Maker's `Tx_lock` — 1 tDIVI is comfortably
    enough to cover the swap amount plus fees on every subsequent presigned spend.
  - 0.01 sXMR (stagenet XMR) for Taker to lock — one faucet request's worth (see below).

  **Faucet**: `https://cypherfaucet.com/xmr-stagenet` (checked live 2026-10-11; listed
  on getmonero.org, so a legitimate, maintained one, not a dead link). Enter a stagenet
  address, solve a CAPTCHA, receive 0.01 sXMR; capped at once per hour per
  address/IP. **The CAPTCHA means this step needs a human** — same exact blocker shape
  as `DECISIONS.md` #5 (the BTC lane's signet faucet), so whoever runs this live pass
  needs to visit the faucet page themselves once. A developer API exists for
  programmatic requests but needs contacting the operator for access — not pursued
  here since one manual drip is all this needs.
  - Fallback if the faucet is ever down/insufficient: self-mine via a locally-run
    `monerod --stagenet`'s `start_mining` JSON-RPC call to any address, no faucet
    needed (stagenet mining is permissionless) — but mined (coinbase) outputs need
    **60 confirmations (~2 h)** before spendable, vs. 10 confirmations (~20 min) for an
    ordinary received output like the faucet's. The faucet path is strictly faster
    when it's available; only fall back to mining if it isn't.

  **Keys**: all freshly generated for this one run, thrown away afterward, exactly like
  every other test in this lane — no 1Password entries needed (these coins have no
  value to protect). Generate at run time, not ahead of time:
  - Maker's and Taker's DIVI secp256k1 keypairs (`divi_crypto::keys::SecretKey::new_random()`
    or equivalent) — these are the `{a', b'}` pair in `xmr-design.md`'s notation.
  - Taker's own simple stagenet wallet (to receive the faucet drip before locking it
    into the 2-of-2) — any stagenet wallet works; `monero-wallet-cli --stagenet
    --generate-new-wallet <path>` is the straightforward option if a GUI isn't wanted.
  - The DLEQ secrets `s_t`/`s_m` and the resulting Monero 2-of-2 spend-key shares —
    generated by the swap code itself (`swap_adaptor::dleq::random_clamped_secret`,
    `crates/swap-chain-xmr/src/monero_key_share.rs`), not supplied externally.
  Run this whole thing from the orchestrator's Mac (or wherever holds `secret get`
  access and isn't hp2), not here — matches how every other lane's `live` tests work.

  **Commands / sequence** (numbers match `xmr-design.md`'s `## Protocol` `### Happy
  path` steps where they line up):
  1. Generate Maker/Taker DIVI keypairs; build the redeem script and its P2SH testnet
     address: `swap_chain_xmr::multisig::{redeem_script, script_pubkey}` for the
     scriptPubKey, `divi_wallet::Address::p2sh(hash, Network::Testnet)` for the
     human-readable address to fund.
  2. Run both DLEQ proofs (`swap_adaptor::dleq`), derive the additive Monero
     `ThresholdKeys` (`monero_key_share::additive_two_of_two_keys`), and the Monero
     stagenet address for the 2-of-2 lock output — identical code path to
     `crates/swap-chain-xmr/src/monero_dkg.rs`'s `group_key_derives_a_real_stagenet_address`
     test, just with `monero_key_share`'s keys instead of that test's PedPoP ones, and
     `Network::Stagenet` (already what that test uses).
  3. Visit `cypherfaucet.com/xmr-stagenet`, solve the CAPTCHA, send 0.01 sXMR to
     Taker's *own* stagenet wallet address (not the 2-of-2 address yet — a real swap's
     Taker already holds her XMR in her own wallet before locking it, so this mirrors
     that). Wait 10 confirmations (~20 min).
  4. From Taker's wallet, send the XMR into the 2-of-2 Monero address from step 2 —
     this is the actual "Taker locks XMR" step in `## Protocol`'s happy path step 2.
     Wait 10 confirmations (~20 min).
  5. Ask whoever holds `dnsdivi` SSH access (per `DECISIONS.md` #1, the established
     source for every other lane's live testnet DIVI) to run, from a dnsdivi node
     wallet: `divi-cli -conf=<testnet.conf> sendtoaddress <maker-p2sh-testnet-address>
     <amount>` — Maker's `Tx_lock`. Wait for 1-6 confirmations (DIVI testnet's existing
     profile, same as the BTC/DIVI lane's live runs).
  6. Build and broadcast `Tx_redeem` directly off `Tx_lock`'s output (the design
     permits spending `Tx_redeem` from either `Tx_lock` or `Tx_cancel` — skip
     `Tx_cancel` for this minimal happy-path run; it's already proven separately,
     offline, by `swap_templates::tests::tx_punish_is_plain_and_pays_taker` and
     `happy_path_e2e.rs`'s own use of it): `swap_templates::maker_encrypts_tx_redeem`
     then `taker_completes_tx_redeem`, broadcast the result via the same DIVI testnet
     RPC proxy (`services.divi.domains`) the BTC/DIVI lane's live tests already use.
     Wait for confirmation.
  7. Maker recovers `s_t` from the confirmed `Tx_redeem`
     (`swap_templates::recover_secret_from_chain`), combines it with his own `s_m`
     exactly as `happy_path_e2e.rs` checks arithmetically offline, and sweeps the full
     Monero 2-of-2 output to a fresh stagenet address of his own, with the now-fully-
     known private spend key (no multisig cooperation needed once Maker holds both
     halves) — the actual proof that the live run completed the swap, not just that
     the mock arithmetic checks out.
