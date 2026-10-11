# Lane usdc — `crates/swap-chain-evm/` and `contracts/htlc/`

Read `_hp2.md` and `_common.md` first. You own `crates/swap-chain-evm/`, `contracts/htlc/`, and
`docs/plans/swap-poc/status/usdc.md`, `docs/plans/swap-poc/usdc-design.md`.

**Contract** `contracts/htlc/src/Erc20Htlc.sol`: lock(token, amount, receiver, hashlock
(sha256, 32 bytes — same hash as the UTXO HTLCs), timelock (unix secs)) → swap id =
`keccak256(abi.encode(sender, receiver, token, amount, hashlock, timelock))`; claim(id, preimage)
pays the receiver and emits `Claimed(id, preimage)`; refund(id) after timelock pays the sender.
No owner, no upgradeability, no fee, reentrancy-safe (checks-effects-interactions), `SafeERC20`
semantics without importing a framework you can't pin. Foundry for build + tests (install it in
`~/.foundry` on hp2 if missing; pin the solc version in `foundry.toml`). Tests: lock/claim,
lock/refund, early refund rejected, wrong preimage rejected, double claim rejected, claim after
refund rejected, fuzz on amounts/timelocks.

**Client** `swap-chain-evm` (alloy): deploy, lock (approve + lock), claim, refund, read swap state,
and find the preimage from `Claimed` logs, against an `anvil` instance in tests (spawned by the
test; skip with a clear message if `anvil` is absent). Chains: Sepolia and Base Sepolia, using
Circle's test USDC addresses (look them up and record them with a source under `- decisions:`).

**Design** `docs/plans/swap-poc/usdc-design.md`: how an account chain fits the engine —
either map onto `ChainBackend` (`Outpoint` = lock tx hash + log index, `htlc_output` reads
contract state by id, `find_spend` reads `Claimed` events, `median_time_past` = latest block
timestamp) or a second trait; list what in `divi-swap` would have to change, and recommend one.

**Acceptance** (`tools/swap-poc/check-usdc.sh`): `forge test` green in `contracts/htlc`; crate
green; tests named `anvil_lock_claim`, `anvil_lock_refund`, `anvil_find_preimage_from_logs`,
`swap_id_matches_contract`; design doc exists with a `## Recommendation` section; an `#[ignore]`
+ `--features live` test `live_sepolia_lock_claim` reading env `SWAP_EVM_TEST_KEY_HEX`.
