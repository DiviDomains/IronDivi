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
