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
- blocked-on-human: no — everything above is done and testable without secrets. The one
  remaining item (live Sepolia exercise) is blocked, but there is nothing further for this
  lane to build toward it: deploying `Erc20Htlc` to Sepolia and funding the taker-btc/
  maker-btc addresses with Sepolia ETH + test USDC both need 1Password access (the Mac).
  Ask: orchestrator deploys `Erc20Htlc` to Sepolia (any key, the contract is a static
  template — e.g. `forge create` from `contracts/htlc` against an RPC + funded deployer key)
  and records its address in `[usdc].htlc` (replacing the placeholder in
  `divi-swapd.toml.example` and/or a live config), then funds the taker-btc/maker-btc
  Sepolia addresses in `funding.md` with Sepolia ETH (gas) and test USDC
  (faucet.circle.com). Once both exist, `live_sepolia_lock_claim` (`--features live`) and a
  real swap through `divi-swapd`/`divi-swap` with `--usdc-htlc <address>` are ready to run
  as-is — no code changes expected.
  into divi-swapd/divi-swap-cli, mock/anvil e2e happy-path and refund both directions,
  verify funding.md addresses
