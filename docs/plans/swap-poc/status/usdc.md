# Lane usdc status

- done: `Erc20Htlc.sol` (lock/claim/refund, checks-effects-interactions, local `SafeTransfer`
  lib instead of a pinned framework) + 15 Foundry tests (lock/claim, lock/refund, early refund
  rejected, wrong preimage rejected, double claim rejected, claim after refund rejected, 2
  fuzz tests) all green; `swap-chain-evm` alloy client (deploy, lock = approve+lock, claim,
  refund, `swap_state`, `find_preimage` from `Claimed` logs, pure-Rust `swap_id`) with
  `anvil_lock_claim`, `anvil_lock_refund`, `anvil_find_preimage_from_logs`,
  `swap_id_matches_contract` all green against a spawned anvil, plus `#[ignore] --features
  live` `live_sepolia_lock_claim` reading `SWAP_EVM_TEST_KEY_HEX`; `docs/plans/swap-poc/usdc-design.md`
  with a `## Recommendation` section.
- running: nothing
- broken: none
- left: nothing (live Sepolia run is the orchestrator's, from the Mac, with a funded key)
- decisions:
  - Circle test USDC addresses: Sepolia `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`, Base
    Sepolia `0x036CbD53842c5426634e7929541eC2318f3dCF7e` — source
    developers.circle.com/stablecoins/usdc-contract-addresses, cross-checked against Sepolia
    Etherscan (name/symbol/decimals match USDC) 2026-10-11.
  - `swap-chain-evm`'s provider uses alloy's `SimpleNonceManager` (fetches the pending nonce
    fresh per send), not the default `CachedNonceManager`: the cached manager advances its
    local nonce optimistically before broadcast and does not resync after a transaction that
    reverts synchronously on send (anvil mines-and-reverts in the same RPC call rather than
    returning a receipt with `status: 0`), which left every later send from that signer stuck
    "queued" in the mempool forever (confirmed via `cast rpc txpool_status`: `pending: 0,
    queued: 1`). Cost real debugging time (a test hang that looked like a dead anvil process
    but was a nonce gap no one was ever going to fill); flagging in case this one surprises
    whoever eventually writes the real `ChainBackend` impl in wave 2.
  - Foundry lint excludes `block-timestamp` and `missing-events-access-control` in
    `contracts/htlc/foundry.toml` — both are expected for an HTLC (the whole point is a
    `block.timestamp` comparison; the `swaps[id]=` write that trips the access-control lint
    is followed by `Locked` emission later in the same function, after the external
    `transferFrom`, per checks-effects-interactions).
  - Design recommendation: map onto `ChainBackend` (Option A in `usdc-design.md`), not a
    second trait — needs zero changes to the frozen engine contract. Full reasoning in the
    design doc; flags that XMR (wave 1d) may want a shared second-trait design later if its
    adaptor-signature shape also doesn't fit `ChainBackend`.
  - `swap-chain-evm`'s anvil tests build contract bytecode at test-*run* time (`forge build`
    shelled out from `src/artifact.rs`, reading `contracts/htlc/out/*.json`), not at Rust
    compile time, so there's one source of truth for the contract (no bytecode copy baked
    into the Rust crate to go stale) and no solc dependency for plain `cargo build`/`clippy`.
  - needs (orchestrator, wave 1e, not blocking USDC wave 2): `Chain::Usdc` variant in
    `crates/divi-swap/src/types.rs` `Chain` enum.
- incident: hp2's root filesystem (backs both `/home` and `/tmp`) hit 100% disk around 12:40
  and stayed there for ~13 hours of this session (every `Bash` call and `Write`/`Edit` failed
  with `ENOSPC`, including trivial no-op commands — confirmed via a same-session oracle
  subagent that the harness's own temp-dir plumbing was the blocker, not anything reclaimable
  from inside the session). Orchestrator freed 17 GB around hour 13; this file and the design
  doc are the two writes that failed mid-incident and were redone once space returned.
  `contracts/htlc/`, `crates/swap-chain-evm/`, and the `connect_provider` nonce fix all landed
  *before* the incident and were unaffected.
