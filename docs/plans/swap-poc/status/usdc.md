# Lane usdc status

- done:
  - **Wave 1c** (landed `a865d9c`): `Erc20Htlc.sol` + 15 Foundry tests; `swap-chain-evm` alloy
    client (deploy, lock=approve+lock, claim, refund, `swap_state`, `find_preimage`,
    pure-Rust `swap_id`) with `anvil_lock_claim`, `anvil_lock_refund`,
    `anvil_find_preimage_from_logs`, `swap_id_matches_contract`, `#[ignore] --features live`
    `live_sepolia_lock_claim`; `docs/plans/swap-poc/usdc-design.md` recommending Option A
    (map onto `ChainBackend`, no engine change).
  - **Wave 2** (this seam): orchestrator decided Option A (per their message). Implemented:
    - `Chain::Usdc` added to the engine (`crates/divi-swap/src/types.rs` `Chain::ALL`,
      `as_str`) and `ChainParams::builtin` (`crates/divi-swap/src/config.rs`): 12
      confirmations mainnet / 3 testnet (Ethereum's common safe-finality heuristic),
      180s/60s MTP lag (block-time jitter only — EVM has no MTP smoothing to lag).
    - `UsdcBackend` (`crates/swap-chain-evm/src/backend.rs`): full `ChainBackend` impl per
      the design doc — `build_funding` ensures ERC-20 allowance eagerly (broadcasts
      `approve` outside the write-ahead path) then signs-but-does-not-broadcast the `lock`
      call; `build_claim`/`build_refund` sign locally (fetch nonce + EIP-1559 fees, build
      and sign a `TxEnvelope` via the wallet directly, no provider-side "fill" RPC so the
      same code path works against anvil and real Sepolia); `broadcast` is the only method
      that sends anything, classifies "already known"/"nonce too low" as idempotent
      success; `htlc_output`/`find_spend` decode the funding tx's `Locked` log (and
      `Claimed`/`Refunded` logs for spends) rather than recomputing the swap id, since
      `HtlcParams` alone lacks `amount`/`token`; `pubkey()` is the backend's own compressed
      secp256k1 pubkey, cross-checked against `HtlcParams.claim_pubkey`/`refund_pubkey` via
      `eth_address_from_pubkey` (keccak256 of the uncompressed point, same derivation as
      every other EVM key).
    - Engine-sats ↔ USDC-base-units conversion (`amount_to_usdc_units`/
      `usdc_units_to_amount`, factor 100 = 1e8/1e6): rejects non-exact amounts rather than
      rounding, because the counterparty's `htlc_output`/`maker_leg_amount()` checks compare
      against the *quoted* amount, not whatever a backend might round it to — a silent round
      would always read as "underfunded". Tested (`usdc_unit_conversion_round_trips_and_rejects_dust`).
    - Wired into `divi-swapd` (`[usdc]` config section: `rpc_url`, `htlc`, `token` (defaults
      to Sepolia USDC), `key`; `live_backends`/`live_usdc` in `bin/divi-swapd/src/main.rs`)
      and the `divi-swap` CLI (`--usdc-key`/`--usdc-rpc-url`/`--usdc-htlc`/`--usdc-token`,
      `live_usdc_backend` in `bin/divi-swap/src/main.rs`). `--backend mock --counter-chain
      usdc` already worked for free (the CLI's mock path is generic over `Chain`).
    - `deploy/divi-swapd/divi-swapd.toml.example`: `[usdc]` section (htlc address is a
      zero-address placeholder — not deployed to Sepolia yet) and offers
      `divi-usdc-sepolia`/`usdc-divi-sepolia` (placeholder price), disabled by comment until
      the real htlc address lands.
    - `crates/divi-swap/tests/usdc.rs`: mock DIVI + a **real** `UsdcBackend` over a spawned
      anvil (not `MockBackend`), both directions, full maker+taker state machine through the
      engine. `usdc_swap_forward`/`usdc_swap_reverse` — happy path to `Done`, asserting the
      actual on-chain USDC balance moved by the exact quoted amount and the DIVI mock
      balance moved correspondingly; exercises `build_funding`/`build_claim`, address
      derivation, swap-id computation, log decoding and the unit conversion for real.
      `usdc_swap_refund_forward`/`usdc_swap_refund_reverse` — taker never claims, both legs
      time out (anvil's clock jumped forward via `evm_setNextBlockTimestamp`, no real
      waiting), both sides refund: exercises `UsdcBackend::build_refund` and the manual
      sign-without-a-provider-fill path, which the happy path alone never touches.
  - Merged a same-file conflict with the `ltc` lane's concurrent wiring into
    `bin/divi-swapd/{main.rs,config.rs,lib.rs,Cargo.toml}` and
    `bin/divi-swap/{main.rs,Cargo.toml}` (both lanes touch the live-backend dispatch); kept
    both chains' code paths. Full workspace-relevant test run after merging: `divi-swap`
    (unit + api/e2e/e2e_gated/e2e_ltc/multichain/scan/usdc integration suites),
    `divi-swap-cli`, `divi-swapd`, `swap-chain-evm` — all green, including the `ltc` lane's
    own tests (not just mine), so the merge didn't regress their work.
  - **funding.md verification** (orchestrator's explicit ask): confirmed
    `eth_address_from_pubkey` derives **exactly** the Sepolia addresses in
    `docs/plans/swap-poc/funding.md` from the existing taker-btc/maker-btc public compressed
    pubkeys (`RESULTS.md` Wave 0 — public data, no secret read). No discrepancy to report.
    Permanent regression test: `backend::tests::matches_funding_md_addresses`.
- running: nothing
- broken: none
- left: live Sepolia readiness is code-complete (`live_usdc`/`live_usdc_backend`,
  `UsdcSection`, `--usdc-*` flags) but **unexercised against the real network** — needs the
  Erc20Htlc contract actually deployed to Sepolia and the taker-btc/maker-btc keys funded
  with Sepolia ETH (gas) + test USDC at the addresses in `funding.md`. See blocked-on-human.
- decisions:
  - Circle test USDC addresses: Sepolia `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`, Base
    Sepolia `0x036CbD53842c5426634e7929541eC2318f3dCF7e` — source
    developers.circle.com/stablecoins/usdc-contract-addresses, cross-checked against Sepolia
    Etherscan (name/symbol/decimals match USDC) 2026-10-11.
  - `swap-chain-evm`'s provider uses alloy's `SimpleNonceManager`, not the default
    `CachedNonceManager`: the cached manager advances its local nonce optimistically before
    broadcast and does not resync after a transaction that reverts synchronously on send,
    wedging every later send behind a nonce gap the chain never fills. Cost real debugging
    time; flagging for whoever else writes an alloy-based backend.
  - `UsdcBackend::build_claim`/`build_refund` sign transactions **manually** (fetch
    nonce/chain-id/gas/fees via the provider, build a `TransactionRequest`, sign with the
    `EthereumWallet` directly) instead of using a provider-level "fill" step, because the
    only such RPC (`eth_fillTransaction`) is non-standard and not guaranteed to exist on a
    public Sepolia RPC endpoint — the manual path uses only `eth_getTransactionCount`,
    `eth_chainId`, `eth_estimateGas`, `eth_maxPriorityFeePerGas`-style fee estimation, and
    local signing, so the identical code runs against anvil and real Sepolia.
  - `Outpoint` for USDC is `{ txid: lock tx hash, vout: 0 }` — `vout` is never read; the
    swap id is always recovered by decoding the funding tx's `Locked` log (both
    `htlc_output` and `find_spend` do this), because `HtlcParams` alone (no `amount`, no
    `token`) is not enough to recompute the id locally.
  - Design recommendation (wave 1c, confirmed by the orchestrator for wave 2): map onto
    `ChainBackend` (Option A in `usdc-design.md`), not a second trait.
  - needs (orchestrator, wave 1e'/future, not blocking): none currently — `Chain::Usdc`
    landed directly since wave 1e (`multichain` lane) had already generalized the engine for
    counter chains by the time this wave started.
- incident: hp2's root filesystem (backs both `/home` and `/tmp`) hit 100% disk for ~13
  hours mid-session (every `Bash`/`Write`/`Edit` failed with `ENOSPC`); orchestrator freed
  space. `CARGO_INCREMENTAL=0` builds have been slow since (shared host, several lanes
  rebuilding from a cleared `target/` at once) — not a correctness issue, just wall-clock.
- **Wave 3** (this seam): the Mac has no `forge`, so the live-deploy/fund step is now a
  single Rust command instead of a shell-plus-forge recipe:
  - `crates/swap-chain-evm/examples/sepolia_ops.rs` (`--features live`): `deploy`,
    `send-eth`, `send-usdc`, `balances` (read-only, works with **no key**). The signing key
    comes from `SWAP_EVM_KEY_HEX` only — never argv, never printed, zeroized on drop.
    Deployment needs no `forge`/network build step: `erc20_htlc_bytecode()`
    (`crates/swap-chain-evm/src/embedded_bytecode.rs`) is the contract's bytecode checked
    in as a `.hex` file, with `embedded_bytecode::tests::embedded_bytecode_matches_a_fresh_forge_build`
    (hp2 only) catching drift if `Erc20Htlc.sol` ever changes without regenerating it.
  - Tested against anvil (dry-run `balances` with no key set, then `deploy`, `send-eth`,
    `send-usdc` with a throwaway anvil key) — all four subcommands work; see the gas
    numbers below, measured on the same anvil run.
  - `tools/swap-poc/usdc-live.sh`: deploy (idempotent, skip with `--htlc`) → fund the maker
    with gas ETH + a little USDC from the taker → `live_sepolia_lock_claim` → a real
    `divi-usdc-sepolia` swap (maker sells DIVI, taker pays USDC) through `divi-swapd` +
    `divi-swap`, mirroring `e2e.sh`'s structure (state dir outside the repo, `op://` refs
    passed through to the Rust binaries that resolve them, `secret get` preflight). Keys
    resolved here only for `sepolia_ops` calls (raw hex via `op read`, unset immediately
    after); `divi-swapd`/`divi-swap` get `op://` reference strings and resolve their own.
    **Untested beyond `sepolia_ops` itself** — it needs 1Password and the real network,
    neither available on hp2; written carefully against `e2e.sh`'s established pattern.
  - Gas measured for real (anvil, same contract bytecode that will go to Sepolia):
    deploy 725,869; `approve` 29,016–46,116 (cold vs. warm slot); `lock` ~184,146–201,246;
    `claim` 73,696; `refund` 70,293; plain ETH transfer 21,000; ERC-20 `transfer` (on
    `MockErc20`; the real proxied Sepolia USDC may cost somewhat more) 51,654.
- blocked-on-human: **yes** — only the actual funding/execution, everything else is done.
  The orchestrator already landed 20 USDC on the taker (`0x4bb95b0c…D60C`,
  tx `0xf5cc6366…28e3`); neither EVM address has Sepolia ETH yet, and the maker has no
  USDC. Exact ask, now minimal because `usdc-live.sh` funds the maker itself from the
  taker once the taker has gas:
  1. Send the **taker** (`0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C`) **~0.1 Sepolia ETH**
     (covers: deploying `Erc20Htlc` once, ~0.04 ETH with headroom over the measured 725,869
     gas; funding the maker with 0.02 ETH + 2 USDC; `live_sepolia_lock_claim`'s
     approve+lock+claim, ~0.02 ETH; one real swap's approve+lock+claim/refund, ~0.02 ETH).
     A Sepolia faucet (e.g. the one at sepoliafaucet.com, or Circle's own if it drips ETH)
     or any funded Sepolia key works — it does not need to be a "swap" key.
  2. Run `op://`-aware, with the real key resolved from 1Password (already set up per
     `funding.md`): `tools/swap-poc/usdc-live.sh` from a machine with `op`/`secret` and the
     Rust toolchain (the Mac). It deploys, funds the maker, proves `live_sepolia_lock_claim`,
     and runs one real `divi-usdc-sepolia` swap end to end; paste its
     `$state/results.txt` into this file once the printed txids confirm.
  No code changes are expected to be needed for step 2 — everything it calls already
  passes against anvil.
- **Wave 4** (this seam): `tools/swap-poc/usdc-live-dry-run.sh` — the anvil-backed proof
  that `usdc-live.sh` itself will work, with no secrets and no real network writes (safe
  anywhere, including hp2; run twice while writing it, both clean, exit 0). Spins up its
  own anvil, deploys a `MockErc20` (stands in for Sepolia USDC — nothing is deployed at the
  real USDC address on a fresh local chain) minted to a throwaway key, then runs the exact
  `sepolia_ops deploy`/`send-eth`/`send-usdc` commands `usdc-live.sh` runs, then
  `cargo test -p swap-chain-evm` (the anvil equivalent of `live_sepolia_lock_claim`, which
  can't itself run against anvil — it hardcodes the real Sepolia USDC address) and
  `cargo test -p divi-swap --test usdc` (a full DIVI<->USDC swap, both directions, proving
  the swap logic end to end). Scope boundary, stated in the script's own header: this
  proves the swap logic through the engine directly, not through the `divi-swapd`/
  `divi-swap` CLI *binaries* wired together over HTTP — doing that too would need the dry
  run to drive anvil's block production in lockstep with the daemon's confirmation polling
  from a second process, which `tests/usdc.rs` already does under full control inside one
  process (same boundary `e2e.sh` documents for its own `--backend mock`).
- **Wave 5** (this seam): Base Sepolia (chain id 84532) added as a second EVM network next
  to Sepolia, while Sepolia ETH funding is still pending. `UsdcBackend` itself needed no
  change — it already only ever sees an RPC URL, an HTLC address and a token address, so it
  was already network-agnostic; everything here is plumbing one layer up:
  - `swap_chain_evm::UsdcNetwork` (new, `crates/swap-chain-evm/src/network.rs`): `Sepolia`
    (default) or `BaseSepolia`, each with `usdc_token()`, `default_rpc_url()` (Sepolia:
    publicnode; Base Sepolia: `https://sepolia.base.org`), `chain_id()` (11155111 / 84532,
    informational only — alloy reads the real chain id from the RPC itself when signing),
    `FromStr`/`Display` as `"sepolia"`/`"base-sepolia"`.
  - `divi-swapd`'s `[usdc]` section gained `network` (default `"sepolia"`); `rpc_url` and
    `token` are now optional and fall back to `network`'s defaults when unset, still
    overridable explicitly either way. Bad `network` strings are rejected at config-load
    time (`DaemonConfig::validate`), not at backend-start time. One `[usdc]` section is still
    one `Chain::Usdc` backend — it serves one network at a time; relabelled offer ids are
    just an operator-facing convention (`counter_chain` stays `"usdc"` regardless), noted in
    a comment on `deploy/divi-swapd/divi-swapd.toml.example`.
  - `divi-swap` CLI gained `--usdc-network` (same default/fallback behavior); `sepolia_ops`
    gained `--network` (same). All three (`--network`/`--rpc-url`/`--token` on
    `sepolia_ops`, and `[usdc].network`/`.rpc_url`/`.token` in the daemon config) resolve
    the same way: explicit value wins, else the network's default.
  - `tools/swap-poc/usdc-live.sh` gained `--network sepolia|base-sepolia`; it mirrors the
    Rust defaults in a bash `case` (commented "keep in sync"), relabels the offer id
    `divi-usdc-$network`, and switches which ignored live test it runs
    (`live_sepolia_lock_claim` vs. the new `live_base_sepolia_lock_claim` —
    `crates/swap-chain-evm/src/tests.rs`, same shape, `#[ignore]`, needs its own funded key
    and is not run by anything today). EVM addresses are unchanged either way: Ethereum
    address derivation from a secp256k1 key doesn't depend on chain id, so the same
    taker/maker addresses from `funding.md` work on Base Sepolia too — only the RPC,
    deployed HTLC address and USDC token address move.
  - `tools/swap-poc/usdc-live-dry-run.sh` updated to pass `--network` through `sepolia_ops`
    alongside its existing `--rpc-url`/`--token` overrides, proving the "network plus
    explicit overrides" composition that `usdc-live.sh`'s funding step relies on. Re-run
    clean, exit 0 (11 passed, 2 ignored — `live_sepolia_lock_claim` and the new
    `live_base_sepolia_lock_claim`, correctly skipped by `cargo test`'s default filter).
  - Mock tests added, no keys/network needed: `network::tests` (round trip, defaults,
    distinct tokens/chain ids, rejects unknown names — `swap-chain-evm`); four
    `UsdcSection`-resolution tests in `bin/divi-swapd/src/config.rs` (default-to-sepolia,
    base-sepolia picks its own defaults, explicit override wins, unknown network rejected
    at load time); five tests in `bin/divi-swap/src/main.rs` covering the same shape for
    `--usdc-network` plus one proving `UsdcBackend::new` actually accepts both networks'
    `default_rpc_url()` strings without any network access.
  - No Base Sepolia funding exists yet (same blocked-on-human below) — `live_base_sepolia_lock_claim`
    is written and ready but has never been run against the real network; Sepolia stays the
    one usdc-live.sh actually exercises once funded.
  - `cargo fmt`/`cargo clippy --workspace --all-targets -- -D warnings` both clean after this
    seam (fmt reformatted `bin/divi-swap/src/main.rs` and `crates/swap-chain-evm/src/tests.rs`
    on save; one clippy fix — `UsdcNetwork`'s manual `impl Default` replaced with
    `#[derive(Default)]` + `#[default]` on `Sepolia`, clippy's own suggested fix).
- **Wave 5 fix** (this seam): shellcheck SC2034 on `tools/swap-poc/usdc-live.sh` —
  `taker_addr` was set but never read after the wave-5 refactor. Used it rather than
  dropped it: added a preflight right after building `sepolia_ops` that checks the taker
  actually has gas ETH on `$network` (`ops balances --addr "$taker_addr"`) before attempting
  deploy/funding, failing with a clear message instead of a confusing mid-deploy RPC error
  if the taker isn't funded yet. `shellcheck` clean on both `usdc-live.sh` and
  `usdc-live-dry-run.sh` now.
- **Wave 6** (this seam): Etherscan/Basescan links for every tx `usdc-live.sh` sends, and a
  case-c (refund) scenario for it — neither existed before (the script only ran one
  hardcoded happy-path forward swap).
  - Etherscan links: `deploy_contract_with_tx` (new, `crates/swap-chain-evm/src/client.rs`)
    is `deploy_contract` plus the deployment tx hash, since the orchestrator needs that link
    too; `sepolia_ops deploy` now prints `tx: 0x...` alongside `htlc_address: 0x...`.
    `usdc-live.sh`'s new `print_tx` helper prints `$explorer/tx/$hash` right after every send
    (deploy, maker ETH/USDC funding) and for every EVM-side txid in the post-swap `txids`
    output (`btc_lock`/`btc_claim_by_*`/`btc_refund_by_taker`/`btc_spend_by_maker` — named
    "btc" generically by `bin/divi-swap/src/txids.rs` regardless of the actual counter
    chain). `explorer` is `sepolia.etherscan.io` or `sepolia.basescan.org`, picked by
    `--network` the same way `usdc_token`/`default_rpc_url` already are.
  - Case-c: `usdc-live.sh` restructured around `--scenario happy|case-c|all --direction
    forward|reverse|both --dry-run`, modeled directly on `tools/swap-poc/ltc-live.sh`/
    `zec-live.sh` (same `[swap] maker_timeout_secs=3600/taker_timeout_secs=14410` override
    and `--never-claim` taker flag for case-c, same `--dry-run` boundary: stops after
    `accept`, before the first broadcast). Offers are now `divi-usdc-$network`/
    `usdc-divi-$network` for both directions in every scenario (previously only the forward
    offer existed). Maker ETH/USDC funding targets now scale with how many runs are
    requested (`total_runs` for gas — the maker signs an EVM claim or refund on every run
    regardless of direction; `reverse_runs` for USDC collateral — only a reverse run spends
    the maker's own USDC) instead of the old flat 0.02 ETH / 2 USDC.
  - **No `--backend mock`**: `Chain::Usdc` is not in `divi_swapd::MOCK_ONLY_CHAINS`, so a
    mock-backend maker has no USDC counter backend and cannot quote a usdc offer
    (`Maker::quote` calls `self.chain(counter)?.pubkey()`, which fails with no registered
    backend). Adding it would mean touching a constant shared with every other lane's mock
    assumptions (breaks `bin/divi-swapd/tests/multichain.rs`'s `Net`, which registers exactly
    Ltc/Zec/Btc backends and would then get an unregistered usdc offer) — out of scope here;
    flagging as a possible future orchestrator decision, not doing it unilaterally.
  - Checked, and ruled out as infeasible rather than skipped: running the real
    `divi-swapd`/`divi-swap` *binaries* for case-c against anvil (closing the gap
    `usdc-live-dry-run.sh`'s header already flagged). `--backend live` unconditionally needs
    real `[divi]`/`[btc]` connectivity (`live_backends` in `bin/divi-swapd/src/main.rs`
    bails if either is absent) — DIVI/BTC aren't EVM chains, so anvil cannot stand in for
    them. This is a structural limit of `--backend live`, not specific to case-c; it already
    blocked the happy path the same way.
  - What's actually "tested with mock" here, given the above: (1) the refund mechanics
    themselves were already proven at the engine level before this wave
    (`usdc_swap_refund_forward`/`usdc_swap_refund_reverse`, `crates/divi-swap/tests/usdc.rs`,
    already run by `usdc-live-dry-run.sh`); (2) two new unit tests in
    `bin/divi-swapd/src/config.rs` (`usdc_live_happy_scenario_toml_parses_and_serves_both_directions`,
    `usdc_live_case_c_scenario_toml_parses_with_its_swap_overrides`) parse the *exact* TOML
    shape `usdc-live.sh`'s new `run_scenario` generates for both scenarios (placeholder
    network/htlc/refs) through `DaemonConfig::parse`, catching drift between the bash and
    the real config parser with no secrets, daemon, or network needed; (3) `usdc-live.sh`
    itself cannot run on hp2 even with `--dry-run` (still needs a real `[divi]`/`[btc]`/
    `[usdc]` daemon) — verified by `bash -n` + `shellcheck` (both clean) and careful review
    instead.
  - `cargo fmt`/`cargo clippy --workspace --all-targets -- -D warnings` clean; full
    `swap-chain-evm`/`divi-swapd` test suites green (17 `divi-swapd` lib tests, up from 15);
    `usdc-live-dry-run.sh` re-run clean end to end (exit 0).
- **Wave 7** (this seam): still blocked on Sepolia ETH landing on the taker (no ETA); kept
  going on everything that doesn't need it.
  - `docs/plans/swap-poc/usdc-deploy.md` (new) + `deploy/divi-swapd/usdc-offers.toml` (new):
    the dnsdivi deploy checklist, modeled directly on `wave4-deploy.md`/`wave4-offers.toml`.
    The config append (`[usdc]`, both offers `enabled = false`, placeholder htlc) is safe to
    land on dnsdivi *today*, before the contract exists — pinned by the new test
    `usdc_offers_snippet_on_top_of_the_wave4_deployed_config` in
    `bin/divi-swapd/src/config.rs`. Includes the exact `sepolia_ops deploy` command and its
    gas estimate (725,869 gas, measured against anvil with the identical bytecode that goes
    to Sepolia; ~0.0007–0.007 ETH at Sepolia's typical 1–10 gwei). Live-checked (read-only,
    no keys) 2026-10-12: taker holds 20 USDC/0 ETH, maker holds 0 USDC/0 ETH — unchanged
    since the last check, cited directly in the doc so it doesn't go stale silently.
  - `usdc-live.sh` gained `--maker-url URL` (drive an already-running maker, e.g. dnsdivi
    once usdc-deploy.md lands there — mirrors `ltc-live.sh`/`zec-live.sh` exactly: builds
    only the taker binary, verifies the remote serves the right offers before swapping,
    keeps the remote's own timeout profile for case-c). Requires `--htlc` (no auto-deploy
    against someone else's maker) and skips the deploy+fund preamble and the
    `live_*_lock_claim` self-test entirely — those assume a locally-deployed contract this
    script controls, not one a remote operator already set up.
  - **`--dry-run` redefined**: it previously meant "quote+accept a real swap against a real
    local daemon, then stop before lock" (this lane's own choice last wave, modeled on
    ltc-live.sh) — that needed 1Password and a running `[divi]`/`[btc]`/`[usdc]` daemon
    either way, so it was never actually runnable from hp2. Orchestrator asked explicitly
    for `--dry-run` to check taker/maker ETH+USDC balances and print what's missing, which
    needs *no* keys (`sepolia_ops balances` is read-only) — implemented that instead,
    computing the same per-run funding targets the live funding step itself uses (plus a
    taker-side allowance for the one-time deploy/self-test/funding-send costs, skipped under
    `--maker-url`). Actually run on hp2 (needs nothing): confirms the taker already has
    enough USDC (20 ≥ 2 needed for two reverse runs) but needs ~0.107 ETH more for a full
    `--scenario all --direction both` run, and the maker needs ~0.08 ETH and 2 USDC — real,
    useful output, not merely exercised.
  - **Nonce-conflict / "already known" audit** (`crates/swap-chain-evm/src/backend.rs`):
    `is_already_known` previously folded `"nonce too low"` and `"replacement transaction
    underpriced"` into the same unconditional-success bucket as `"already known"`/`"already
    imported"`. That is only safe for the latter two (same tx hash genuinely already in the
    node's mempool). For the former two, *something* already occupies the nonce — usually
    our own earlier broadcast having since mined (safe: this backend's write-ahead design
    signs a claim/refund exactly once and only ever rebroadcasts the identical bytes), but
    not necessarily: a stale read from a load-balanced public RPC, or the same key used by
    a second process at once (against this lane's own rule, but not impossible), can mean a
    *different* transaction took the nonce — then the signed bytes we hold can never land
    under any nonce, and the old code would still return `Ok(tx.txid)`, so the engine would
    poll `confirmations(&that_txid)` forever: a silent livelock, not a crash, which is why it
    had gone unnoticed. Fix: split into `is_already_known` (unconditional success, as
    before) and `is_nonce_conflict` (new); on the latter, `broadcast` now checks whether
    *this* transaction's own hash has a receipt before declaring success, and returns
    `SwapError::Rejected` naming the problem when it does not.
    Regression tests on anvil (`crates/swap-chain-evm/src/tests.rs`):
    `broadcast_is_idempotent_once_its_own_tx_has_mined` (the safe case — resending an
    already-self-mined refund must still report success) and
    `broadcast_errors_when_a_different_tx_stole_the_nonce` (the bug this wave fixes —
    reproduced by signing a refund, then sending an unrelated transaction from the same key
    first so it takes the nonce, then broadcasting the stale signed bytes: must now error,
    where it previously would have returned a success for a transaction that can never
    mine). Both need a real locked-and-timed-out swap first (`build_refund`'s own
    `estimate_gas` reverts "no such swap" otherwise) — a new `locked_and_refundable` helper
    does that.
  - `cargo fmt`/`cargo clippy --workspace --all-targets -- -D warnings` clean; full
    `swap-chain-evm` (15 tests, 2 ignored), `divi-swapd` (18 lib tests, up from 17),
    `divi-swap-cli` and `divi-swap --test usdc` suites green; `shellcheck` clean on both
    `usdc-live.sh` and `usdc-live-dry-run.sh`; `usdc-live-dry-run.sh` re-run clean end to end.
- **hp2-land retry** (this seam): the first land attempt failed — this lane's base (`cbcafc3`)
  was stale against main (now `19f9388`, via `6f8f962`), so the orchestrator's patch did not
  apply. Decision: the orchestrator's message said "commit them", but `tools/swap-poc/
  lane-sync.sh` documents the opposite invariant in its own header ("Lanes never commit, so
  the landed changes reappear identical in the stash and pop cleanly"), matching this lane's
  binding "never commit or push" rule. Read "commit them" as "finalize them for landing" and
  ran `lane-sync.sh` instead of `git commit` — that is what actually fixes a stale-base land
  failure, and keeps the uncommitted-working-tree invariant the land tooling expects intact.
  `lane-sync.sh` hit a real stash-pop conflict in `tools/swap-poc/usdc-live.sh` and this
  status file: both were conflicts against *this lane's own, already-landed* Wave 6 content
  (the `ltc`/`zec` lanes never touch either file), confirmed by diffing each side — the
  stashed copy was a strict superset, so both were resolved by taking it whole, `git add`ed
  to clear the unmerged state, then **unstaged again** (`git reset`) to leave plain
  uncommitted working-tree diffs, matching every prior seam. Separately, `wave4-offers.toml`
  had changed upstream since this lane's test last read it (`0b10ac6`, the `ltc` lane: `ltc-
  divi-testnet` flipped from disabled to enabled, max raised to 190000) — the new
  `usdc_offers_snippet_on_top_of_the_wave4_deployed_config` test (added this wave, before
  the lane-sync) still asserted the old disabled shape; fixed to match `ltc-divi-testnet`
  now being served. All checks re-run clean after both fixes (`check-usdc.sh`, workspace
  clippy, `divi-swapd`/`swap-chain-evm`/`divi-swap-cli` suites, `shellcheck`, both dry runs).
- **Wave 8** (this seam): orchestrator asked to add `--scenario case-c` and `--network
  base-sepolia` to `usdc-live.sh` and prove case-c end to end on anvil via
  `evm_increaseTime`. Both flags already existed, landed in `50f18a2` (the prior seam) —
  `usdc-live.sh` has had `--scenario happy|case-c|all` and `--network sepolia|base-sepolia`
  since then; reconfirmed live just now (`--dry-run --network base-sepolia --scenario
  case-c` runs cleanly, no keys). Flagging this so the orchestrator's model of this lane
  stays accurate rather than silently redoing already-landed work.
  - New, actually new: case-c's refund timing is now also proven against `evm_increaseTime`
    (a *relative* clock advance), not just the existing `evm_setNextBlockTimestamp`
    (*absolute*) — different test/fork tooling supports one or the other, so proving both
    means case-c's refund path isn't accidentally resting on one RPC's specific semantics.
    `crates/divi-swap/tests/usdc.rs`: `jump_usdc_time` took a new `TimeJump` enum
    (`SetNextBlockTimestamp` | `IncreaseTime`); `refund_swap(dir, time_jump)` now threads it
    through. Two new tests, both directions:
    `usdc_swap_refund_forward_evm_increase_time`/`usdc_swap_refund_reverse_evm_increase_time`
    — same case-c proof as the existing `usdc_swap_refund_forward`/`_reverse` (taker never
    claims, both legs time out, both sides refund through `UsdcBackend::build_refund`), just
    advancing anvil's clock the other way. `evm_increaseTime` only takes effect on the next
    *mined* block (confirmed empirically against a scratch anvil instance: returns the
    applied delta, e.g. `99` for a requested `100`), so the jump is followed by an explicit
    `evm_mine` the same way the existing `mine_usdc_block` helper already does elsewhere.
  - `tools/swap-poc/usdc-live-dry-run.sh`'s doc comment and echo updated to name all 6
    `tests/usdc.rs` tests it now runs (was 4), including both new ones.
  - No live runs, no swap keys, as asked: everything proven on anvil with throwaway dev
    keys; `usdc-live.sh --dry-run` (no keys) re-checked after lane-sync for both networks.
  - `cargo fmt`/`cargo clippy --workspace --all-targets -- -D warnings` clean;
    `check-usdc.sh` PASS; full `divi-swap` suite green (121 tests across 6 binaries, up from
    119 — the 2 new tests), `tests/usdc.rs` specifically now 6/6; `shellcheck` clean on both
    `usdc-live.sh` and `usdc-live-dry-run.sh`; `usdc-live-dry-run.sh` re-run clean end to end.
- **Wave 9** (this seam): orchestrator asked (again) for `usdc-live.sh` to accept `--network
  base-sepolia` with a dry-run test, while still blocked on Sepolia ETH. As flagged last
  seam: `--network sepolia|base-sepolia` already exists on `usdc-live.sh` (landed `50f18a2`)
  — re-flagging once more so this doesn't keep getting re-requested as new work. What *was*
  missing, and is genuinely new this seam: an automated check that `--dry-run --network
  base-sepolia` actually reaches the real network, not just that the flag parses.
  `tools/swap-poc/usdc-live-dry-run.sh` gained a step 6: after its anvil-only proof, it now
  also runs `usdc-live.sh --dry-run --network sepolia` and `--dry-run --network
  base-sepolia` for real — safe to do even in an otherwise-offline-friendly script, since
  `--dry-run` only ever reads balances (`sepolia_ops balances`, no key, no broadcast). Ran
  clean just now: both networks resolve, both report real current balances (taker already
  holds 20 USDC on Sepolia, 0 on Base Sepolia — expected, it is a different token on a
  different chain; both still need Sepolia/Base-Sepolia ETH for gas). This is also the
  concrete evidence that Base Sepolia (chain id 84532, Circle USDC
  `0x036CbD53842c5426634e7929541eC2318f3dCF7e`) is a live, correctly-wired alternative the
  moment any faucet pays out there instead of Sepolia.
  - `cargo clippy --workspace --all-targets -- -D warnings` clean; `check-usdc.sh` PASS;
    `shellcheck` clean on both scripts; `usdc-live-dry-run.sh` re-run clean end to end
    (anvil proof + both real-network dry-runs, exit 0).
- **Wave 10** (this seam): usdc mock e2e for crash recovery — kill/restart the taker
  between `lock` and `claim`, both directions, on anvil. Mirrors `tests/engine.rs`'s
  `crash_taker_body`/`Crash::Taker(TakerState::Locked)` (the BTC/DIVI chaos-equivalent at
  the Rust level — there is no OS-process-kill chaos test anywhere in this repo; the only
  thing that actually kills a real binary is `tools/swap-poc/chaos/driver.py`, and it kills
  the *maker* (`divi-swapd`), never the taker), but with a real `UsdcBackend` over a spawned
  anvil for the counter leg instead of `MockChain` (that struct's harness is BTC/DIVI-
  `MockChain`-specific and isn't reusable for an account-chain backend without rewriting it).
  - `crates/divi-swap/tests/usdc.rs`: new `crash_taker_between_lock_and_claim(dir)` — opens
    a *file-backed* `Store` (not `in_memory`, so "restart" can reopen the same on-disk file
    with a fresh connection, exactly like `tests/engine.rs::H::restart`), runs quote→
    prepare→accept→accepted, arms `taker.halt_after(Some(TakerState::Locked))`, calls
    `taker.lock()` and confirms it halts right where `Taker::lock` persists the `Locked`
    transition and the signed-but-unbroadcast funding tx, *before* the `broadcast` call
    (`crates/divi-swap/src/taker.rs`) — i.e., the crash point is "funding tx signed and
    written to disk, never sent". Drops that `Taker`, reopens the store, builds a fresh
    `Taker` (the maker's own process never crashed, so it keeps its original store handle
    throughout) and resumes: `taker.lock()` again now hits the `Locked => {}` branch,
    skipping re-signing, and broadcasts the persisted tx for the first time. Finishes the
    swap through the normal tick/step loop and asserts the same balance invariants as
    `full_swap` — the crash+resume must not double-fund, double-claim, or lose anything.
    Two tests, both directions: `usdc_crash_taker_between_lock_and_claim_forward`/`_reverse`.
  - Why `Locked` specifically: it is the one crash point genuinely "between lock and claim"
    in `TakerState`'s own ordering (`Prepared, Accepted, Locked, MakerLockConfirmed,
    Claimed, Refunded, Done`) and the one `tests/engine.rs` itself already uses for this
    exact purpose on BTC/DIVI, so this is the same proof, not a new one invented for USDC.
  - Noted, not fixed (out of scope, not my crate): `cargo clippy --workspace --all-targets
    -- -D warnings` currently fails in `crates/divi-rpc/src/wallet.rs` (`len_zero`,
    landed `84e27d3`, the `rpc` lane, nothing to do with USDC/EVM). Scoped clippy on
    everything this seam touches is clean: `cargo clippy -p divi-swap --all-targets -- -D
    warnings` and `-p swap-chain-evm --all-targets --all-features` both exit 0.
  - `check-usdc.sh` PASS; full `tests/usdc.rs` suite green (8/8, up from 6 — the 2 new
    tests), each new test independently green.
- **Wave 11** (this seam): make the deployed maker ready to serve USDC the moment ETH
  arrives — the disabled-by-default offers already existed (`deploy/divi-swapd/
  usdc-offers.toml`, Wave 7: `divi-usdc-sepolia`/`usdc-divi-sepolia`, `[usdc]` with
  rpc_url/htlc/token; flagging again since this keeps getting re-requested as new work).
  What's genuinely new: divi-swapd now *also* refuses to serve an enabled usdc offer whose
  direction needs collateral the maker's live balance does not cover, independent of the
  config's own `enabled` flag.
  - `crates/swap-chain-evm/src/backend.rs`: `UsdcBackend::gas_and_token_balance()` (new) —
    the backend's own ETH + `self.token` balance in one call. `usdc_offer_is_fundable
    (direction, eth_wei, usdc_units, min_eth_wei, min_usdc_units) -> bool` (new, pure, no
    network): `taker_pays_btc` (`divi-usdc-sepolia`-shaped: maker sells DIVI it already
    holds, only claims the taker's USDC lock) needs only the gas floor; `taker_pays_divi`
    (`usdc-divi-sepolia`-shaped: maker sells USDC) needs both floors. Both exported.
  - `bin/divi-swapd/src/main.rs`: `live_usdc` now reads `(RPC URL, HTLC address, token)`
    from `[usdc]` exactly as before, additionally calls `gas_and_token_balance`, and checks
    every *enabled* usdc offer against it with `MIN_MAKER_ETH_WEI` (0.01 ETH) /
    `MIN_MAKER_USDC_UNITS` (10 USDC) — the orchestrator's exact numbers. An offer that fails
    is logged (`tracing::warn!`) and dropped from what the daemon actually serves; it is
    *not* a hard failure of the whole daemon (an unfunded usdc offer must not take down a
    daemon that's otherwise fine on BTC/LTC/ZEC). `live_backends` threads this through and
    now returns the already-filtered offer list; `main()` no longer needs its own filtering
    step (one return value removed a `cfg.offers.clone()` that would have ignored the gate).
  - Mock tests, no live network or swap keys:
    - `crates/swap-chain-evm/src/backend.rs` (pure, no anvil): `divi_usdc_offer_needs_only_gas`,
      `usdc_divi_offer_needs_gas_and_usdc_collateral`, `usdc_offer_fundability_is_exact_at_the_floor`.
    - `crates/swap-chain-evm/src/tests.rs` (anvil): `gas_and_token_balance_reports_eth_and_minted_usdc`.
    - `bin/divi-swapd/src/main.rs` (anvil, new `#[cfg(test)] mod tests`, `alloy` added as a
      dev-dependency): `live_usdc_excludes_an_enabled_but_underfunded_offer` — builds the
      real `live_usdc` against a spawned anvil from a literal `UsdcSection` (RPC URL, a
      freshly-deployed `Erc20Htlc`/`MockErc20` as htlc/token, a `credential:`-resolved
      throwaway key written to a tempdir with `CREDENTIALS_DIRECTORY` pointed at it — the
      real secret-resolution path, not bypassed), funds the maker with exactly the ETH
      floor and zero USDC, and confirms `divi-usdc-sepolia` is kept while `usdc-divi-sepolia`
      is excluded. This is the one test in the binary that touches `CREDENTIALS_DIRECTORY`,
      so there is no cross-test env-var race.
  - Updated `usdc-offers.toml`/`usdc-deploy.md` to document the new code-level gate as a
    second, independent safety net on top of the config's `enabled` flag (kept
    `enabled = false` as asked — belt and suspenders, not a replacement for it).
  - `check-usdc.sh` PASS; scoped clippy clean (`-p divi-swapd -p swap-chain-evm
    --all-targets --all-features -- -D warnings`, exit 0 — the pre-existing unrelated
    workspace-wide clippy failure in `crates/divi-rpc/src/wallet.rs`, noted last wave,
    is still there and still not mine); full `divi-swapd` test suite green across every
    binary (new tests included); `cargo fmt` clean.
- **Wave 12** (this seam): `tools/swap-poc/balances.sh` (new) — read-only balance dashboard
  for every coin this POC swaps (BTC testnet3, LTC testnet4, DIVI testnet, ZEC testnet,
  Sepolia ETH+USDC, Base Sepolia ETH+USDC), taker and maker, from public APIs only, no
  keys. Cross-lane tool (not usdc-scoped), built because the orchestrator asked directly.
  - Sources per coin, reused rather than reinvented: BTC/LTC via Esplora
    `/address/<addr>/utxo` summed over confirmed entries (same pattern as `e2e.sh`'s own
    maker-balance check); DIVI via the public `getaddressbalance` JSON-RPC method on
    `services.divi.domains` (needs no wallet/key — confirmed live against both real
    addresses while writing this; same RPC proxy `tools/swap-poc/lib.sh`'s `divi_confirmed`
    already curls); ZEC via `crates/swap-chain-zec/examples/check_addr_utxos.rs` (the `zec`
    lane's own read-only lightwalletd checker, landed `f6d759d` — reused as-is, not
    duplicated); Sepolia/Base Sepolia via `sepolia_ops balances` (this lane's own, already
    network-agnostic and keyless).
  - `--check`: exits 1 if anything is below its own live script's per-run funding minimum,
    printing every shortfall either way (informational mode always exits 0). Minimums, one
    source per coin, documented inline: BTC 15000 sats (`e2e.sh`'s `E2E_BTC_SATS` default +
    5000 fee buffer), LTC 105000 litoshi (`ltc-live.sh`'s `min_per_run`), ZEC 120000 zatoshi
    (`zec-live.sh`'s `min_per_run`), USDC 0.02 ETH + 1 USDC (`usdc-live.sh`'s
    `eth_per_run`/`usdc_units_per_run` at its default `--usdc-sats`, same on both networks
    since the backend is network-agnostic). DIVI has no fixed minimum anywhere — its amount
    is quote-derived and scales with whichever offer runs, unlike the others' flat per-run
    figures — so 100 tDIVI is this script's own conservative floor, explicitly flagged in
    the file as a judgment call rather than attributed to a script that doesn't define one.
  - Run for real just now (read-only, no keys, safe): correctly reports the current state —
    taker already holds 20 USDC on Sepolia (OK) but 0 ETH on both networks and the maker
    holds nothing on either network yet (7 `SHORT` lines, `--check` exits 1) — matches
    every other balance check this lane has done by hand this session.
  - `shellcheck`/`bash -n` clean; `check-usdc.sh` still PASS (unaffected — new file, no
    Rust changes this wave).
