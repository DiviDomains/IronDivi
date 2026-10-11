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
