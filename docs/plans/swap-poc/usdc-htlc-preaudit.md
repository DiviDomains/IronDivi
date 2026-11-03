# USDC/EVM `Erc20Htlc` — pre-audit (2026-10-22)

Scope: `contracts/htlc/src/Erc20Htlc.sol` (145 lines, solc 0.8.26, optimizer on, 200 runs) and how
`crates/swap-chain-evm` calls it. This is an internal pre-audit, **not** an audit: the mainnet-readiness item
stays open until an outside auditor has reviewed a deployment. No funds, no public network: every run was on a
throwaway local `anvil` (or Foundry's in-process EVM).

## Tooling (pinned)

| Tool | Image / version | Digest |
|---|---|---|
| Foundry (forge, anvil) | `ghcr.io/foundry-rs/foundry:v1.3.0` (forge/anvil 1.3.0, commit b918f9b) | `sha256:74a831a6046e7f04412802ee9eecfdce7009e983727c0cb7a91fe950ad203306` |
| Slither 0.11.6 | `ghcr.io/crytic/slither` (tag `latest` when pulled; pinned by digest) | `sha256:89d4127ec3bfeba9725a863c58dd96b01781ff73737871dd3b07606ebc4cf16b` |
| Aderyn 0.6.8 | Cyfrin release binary `aderyn-x86_64-unknown-linux-gnu.tar.xz`, https://github.com/Cyfrin/aderyn/releases/tag/aderyn-v0.6.8 (published 2026-01-22; 88 detectors) | tarball `sha256:ffd6ca658962e211a3ac821c646f69c8e14bf1b1001cbfe091bcd4535a691e46` (matches the release's own `.sha256` file and the GitHub asset digest); extracted binary `sha256:a268d616826901e17717b1bc6368d8b2c063045a46fb99a0c0f657f102d977ca` |

`anvil`/`forge` binaries were copied out of the pinned Foundry image into the builder's own directory (not a
system location) so the Rust anvil tests, which spawn `anvil` from `PATH`, could run on hp1.
Compiler: `solc 0.8.26`, optimizer 200 runs (`foundry.toml`); `pragma solidity 0.8.26` is exact. The Rust side
embeds bytecode built by the same `forge build` (`crates/swap-chain-evm/src/artifact.rs`) — verified: the anvil
tests deploy it and pass.

## Test and coverage numbers

| | before | after |
|---|---|---|
| `forge test` | 26 passed | **44 passed** (+18, file `test/Erc20HtlcPreaudit.t.sol`); **45 passed** after the coverage round (+1, `test_refundOfUnknownIdRejected`) |
| `src/Erc20Htlc.sol` lines / statements / branches / funcs | 100% / 100% / 90.0% (27/30) / 100% | 100% / 100% / **96.7% (29/30)** / 100%; **100% (30/30)** after the coverage round |
| Rust `cargo test -p swap-chain-evm -p divi-swap -p divi-swapd` (anvil on PATH) | 250 passed, 0 failed (3 packages) | **280 passed**, 0 failed (those plus `divi-swap-cli`, 30 tests); 295 after rebasing onto `signed/main` 42d8493, which brought other lanes tests |

All 30 branches are covered. The last one was identified from `forge coverage --report lcov`
(`BRDA:136,9,0,-`): the `require(s.sender != address(0), "Erc20Htlc: no such swap")` in `refund`
(`src/Erc20Htlc.sol:136`). It is reachable (any id that was never locked) and was simply never exercised, because
`claim`'s equivalent at :123 was. `test_refundOfUnknownIdRejected` now covers it: it asserts the exact revert
reason for an id differing from a real swap in one parameter and for `bytes32(0)`, and that no state is created and
no tokens move.

## Checklist

Verdicts: `ok` / `risky` / `defect`. Sources are file:line in this repo unless a URL is given.

| # | Hazard | Where | Test / evidence | Verdict |
|---|---|---|---|---|
| 1 | Reentrancy on claim | `Erc20Htlc.sol:121-131` (`claimed = true` at :128 before transfer :129) | `test_reentrantClaimCannotDoublePay`, `test_crossFunctionRefundDuringClaimRejected` | ok |
| 2 | Reentrancy on refund | `:134-144` | `test_reentrantRefundCannotDoublePay` | ok |
| 3 | Reentrancy on lock | `:81-117`; record written (:92-101) before `transferFrom` (:111) | `test_reentrantLockSameIdRejected` (reentrant relock of the same id is rejected) | ok |
| 4 | Checks-effects-interactions | claim/refund: flag then transfer then event; lock: record, then transfer, then balance check, then event | Slither `reentrancy-events` x3 (see triage): event after call is benign here | ok |
| 5 | ERC-20 return values | `SafeTransfer` `:16-30`: reverts on failed call or `false`, accepts empty return | `test_lockRejectsFalseReturningToken`, `test_lock/ClaimWorksWithNoReturnValueToken` | ok |
| 6 | Token address with no code (bare `call` to an EOA "succeeds") | `lock` calls `balanceOf` first (:110), a high-level call, which Solidity reverts on when the target has no code | `test_lockRejectsTokenWithoutCode` (no record written) | ok |
| 7 | Fee-on-transfer / rebasing | balance-delta check `:110-115` | `test_lockRejectsFeeOnTransferToken`. USDC (Circle FiatTokenV1) `_transfer` (:306) moves balances and emits `Transfer`, no fee or rebase: `https://github.com/circlefin/stablecoin-evm/blob/master/contracts/v1/FiatTokenV1.sol`. **verified** (source read 2026-10-22) | ok |
| 8 | USDC blacklist | FiatTokenV1 `transfer` (:287-293) requires `notBlacklisted(msg.sender)` and `notBlacklisted(to)`; `transferFrom` (:258-269) also `from` — same file, plus `v1/Blacklistable.sol`. **verified** | `test_blacklistedReceiverCannotBeClaimedButSenderRefunds`, `test_blacklistedSenderCannotRefundButReceiverClaims`, `test_blacklistedContractFreezesEscrow` | **risky** (see below) |
| 9 | USDC pause | `whenNotPaused` on `transfer` (:287) and `transferFrom` (:258), FiatTokenV1.sol. **verified** | `test_pausedTokenBlocksBothExitsUntilUnpaused` (exits revert while paused, work after) | **risky** |
| 10 | `block.timestamp` and skew | `lock` :87, `refund` :139. Margins are not changed by this lane | Slither `timestamp` x2 (intentional); `test_claimSucceedsExactlyAtTimelock`, `test_claimWinsRaceAtExactTimelock`, `testFuzz_atMostOnePayout` | ok (block-timestamp skew is small against the swap-level margin, but that margin was not re-derived here: `could not verify`) |
| 11 | Claim at/after timelock | `claim` has no deadline check, `refund` needs `>= timelock` | whichever lands first wins at the boundary: `test_claimWinsRaceAtExactTimelock`. Standard HTLC property; swap-level margin in `usdc-design.md` | ok (state to auditor) |
| 12 | Hash function and preimage length vs other legs | `claim` :126 `sha256(abi.encodePacked(bytes32))` = SHA-256 of 32 raw bytes. Rust: `divi-swap/src/htlc.rs:139` `Sha256::digest(preimage)`; the same hashlock is what the Rust anvil tests lock and claim with. | `test_hashlockIsSha256NotKeccak`, `test_preimageOfOtherLengthRejected`, Rust `anvil_lock_claim` | ok |
| 13 | Swap-id collision | `swapId` = keccak256 of `abi.encode` of 6 fixed-size words (`swapId` at :67) — no dynamic types, so no encoding ambiguity. Rust mirror `client.rs:57-76` | `test_swapIdMatchesContract`, Rust `swap_id_matches_contract` | ok |
| 14 | Replay | identical parameters rejected (:89); a settled record is kept, so it cannot be re-locked | `test_lockRejectsDuplicateId`, `test_settledSwapIdCannotBeRelocked` | ok |
| 15 | Who can call refund / claim, who is paid | anyone may call both; payout always to recorded `sender` / `receiver` | `test_anyoneCanClaimButReceiverIsPaid`, `test_anyoneCanRefundButSenderIsPaid` | ok |
| 16 | Claim front-running | the preimage is public in the mempool once `claim` is broadcast. A copycat can only pay the *receiver* (call is permissionless but payout fixed), so front-running cannot steal funds | `test_anyoneCanClaimButReceiverIsPaid` | ok (expected for HTLCs) |
| 17 | Events for every state change; Rust decodes them | `Locked` :116, `Claimed` :130, `Refunded` :143. Rust decodes `Locked` (`backend.rs:504,547`), `Claimed` (:559-573), `Refunded` (:588-) | `test_lockEmitsLocked`, `test_claimEmitsPreimage`, `test_refundEmitsRefunded`; Rust `anvil_find_preimage_from_logs` | ok |
| 18 | Integer overflow | solc 0.8.26 checked arithmetic; the only arithmetic is the balance delta (:113) | `testFuzz_lockClaimRoundTrip`, `testFuzz_atMostOnePayout` | ok |
| 19 | Zero amount / zero receiver / past timelock | `:85-87` | `test_lockRejectsZeroAmount`, `test_lockRejectsZeroReceiver`, `test_lockRejectsPastTimelock`, `test_lockRejectsTimelockEqualToNow` | ok |
| 20 | Zero sender used as "no swap" sentinel | `msg.sender` is never zero | n/a | ok |
| 21 | Owner / upgradeability of the HTLC | none: no owner, no proxy, no selfdestruct, no delegatecall (file read in full) | source read | ok |
| 22 | Solvency | contract balance = sum of unsettled amounts | `invariant_balanceEqualsOpenSwaps` (64 runs x depth 32, handler lock/claim/refund/warp) | ok |
| 23 | Upgradeability of USDC itself | `FiatTokenProxy is AdminUpgradeabilityProxy`; its admin can call `upgradeTo`/`upgradeToAndCall` (`ifAdmin`, AdminUpgradeabilityProxy.sol:107,121), so Circle can change token logic, blacklist and pause rules at any time. **verified** (https://github.com/circlefin/stablecoin-evm/blob/master/contracts/upgradeability/AdminUpgradeabilityProxy.sol, contracts/v1/FiatTokenProxy.sol:29, read 2026-10-22) | **risky** (outside the HTLC's control) |
| 24 | Static-analysis second opinion (Aderyn 0.6.8) | `L-1 Unsafe ERC20 Operation` x2 at :21, :27 (see Aderyn triage) | `test_lockClaimWorksWithNoReturnValueToken`, `test_lockRejectsFalseReturningToken` | ok (false positive; code-less-token reasoning marked `for auditor`) |

Counts: ok 20, risky 3 (rows 8, 9, 23), defect 0.

### What the "risky" rows mean for a locked swap

- A blacklisted **receiver** cannot be paid: `claim` reverts, so the preimage is *not* revealed on-chain, the funds stay
  escrowed, and the sender recovers them via `refund` after the timelock. The counter-leg (DIVI/BTC) is unaffected by
  this revert, so a taker who already paid on the other chain relies on its own refund path.
- A blacklisted **sender** cannot refund; the receiver can still claim.
- A **paused** token, or a blacklisted **HTLC contract**, freezes both exits until Circle lifts it. No HTLC-side fix
  exists without an owner key, and none should be added.
- The contract's behaviour was **not changed**; no row is a defect.

## Slither triage (0.11.6, `solc 0.8.26 --optimize --optimize-runs 200`, 102 detectors, 8 results)

| Detector (Slither class, per its docs; the log does not print it) | Location | Verdict | Reason |
|---|---|---|---|
| `reentrancy-balance` (High) | `lock` `:110-112` | false positive | `balanceBefore` is *meant* to be pre-call; the post-call read is the delta check. A reentrant token cannot relock the same id (row 3). |
| `reentrancy-events` (Low) x3 | `claim` :130, `refund` :143, `lock` :116 | false positive | State is written before the external call; only the event follows. Event order does not affect funds. |
| `timestamp` (Low) x2 | `lock` :87, `refund` :139 | true positive, accepted | A timestamp comparison is the HTLC's purpose (CLTV analogue); skew is seconds against hour-scale margins. |
| `low-level-calls` (Info) x2 | `SafeTransfer` :21, :26 | true positive, accepted | Needed to tolerate no-return tokens; the return data is checked. |

By class: High 1 (false positive), Low 5 (3 false positive, 2 accepted), Informational 2 (accepted).
Zero findings left open.

## Aderyn triage (0.6.8, `aderyn contracts/htlc`, scope `src/` = `Erc20Htlc.sol`, 99 nSLOC, 88 detectors)

Result: High 0, Low 1 (2 instances). Verbatim report summary: `L-1: Unsafe ERC20 Operation` at `src/Erc20Htlc.sol:21`
and `:27`.

| Detector | Location | Verdict | Reason |
|---|---|---|---|
| L-1 Unsafe ERC20 Operation (Low) | `SafeTransfer.safeTransfer` :21, `safeTransferFrom` :27 | false positive | The detector flags any raw `.call` of `transfer`/`transferFrom` and advises OpenZeppelin SafeERC20. `SafeTransfer` is the same pattern: it requires `ok` and either empty return data or a decoded `true` (:22, :28). Exercised by `test_lockClaimWorksWithNoReturnValueToken`, `test_lockRefundWorksWithNoReturnValueToken`, `test_lockRejectsFalseReturningToken` and the USDC revert mocks. Not replaced by OZ on purpose (no dependency); the same call sites are Slither `low-level-calls` (accepted above). One residual point for the auditor: `SafeTransfer` does not check `token.code.length` after the call, so a token address with no code would appear to succeed. `lock` rejects that case (`test_lockRejectsTokenWithoutCode`, via the balance-delta check at :112-115), and `claim`/`refund` only use tokens that already passed `lock`. `for auditor` (confirm the reasoning). |

Aderyn found nothing that Slither had not; no finding needed a contract change or a new test. The report is
reproducible: `aderyn .` in `contracts/htlc` with the pinned binary.

## Local end-to-end through the Rust client

`swap-chain-evm` can target a local chain: its tests spawn `anvil` (alloy `Anvil::new()`), deploy `MockErc20` and
`Erc20Htlc`, then run through the Rust client.
On hp1 (anvil from the pinned image on `PATH`) `anvil_lock_claim`, `anvil_lock_refund`,
`anvil_find_preimage_from_logs` and `swap_id_matches_contract` pass (4/4), as part of the 250-test baseline run. Additionally the CLI was driven against a local anvil (`divi-swap balance
--counter-chain usdc --usdc-rpc-url http://127.0.0.1:18545 ...`), see the defects below.

## The two defects from builder R's round

1. **CLI `balance` answered "needs --backend live" with the flag given — fixed.** Root cause:
   `bin/divi-swap/src/main.rs` `live_backends` returned `live: None` for `--counter-chain usdc` (the `Chain::Usdc` early
   return, :556), and `Cmd::Balance` (:939) treats `live: None` as "not the live backend" and bails with that
   message. USDC has no `CounterLive` handle (it is an EVM account, not a UTXO address). Fix: `Cmd::Balance` takes its
   own arm for USDC-live (`is_usdc_live`), builds the `UsdcBackend` and prints address, ETH (wei) and token units via
   the existing `gas_and_token_balance`; `UsdcBackend::address()` added. Unit test
   `balance_routes_usdc_live_to_its_own_path`. Repro before/after on a local anvil: before `Error: balance needs
   --backend live`; after `usdc_address=0xf39F…2266`, `usdc_eth_wei=9999998789807667221346`,
   `usdc_balance_units=0`. Note `--backend live` is the CLI default (`main.rs:45`).
2. **`check-usdc.sh` failing check — not reproducible, left alone.** On hp1 at `signed/main` (9565e95) with forge and
   anvil on `PATH` the script prints `PASS: usdc` (12 `ok:` lines). The script's first check runs `forge test` in `contracts/htlc` with `PATH="$HOME/.foundry/bin:$PATH"` and its other checks run cargo through `tools/swap-poc/lib.sh`; a missing forge on that host would fail the first check. The most likely cause
   is therefore the environment of the host that ran it (no Foundry on `PATH`), but that host's output was not available
   here: **could not verify**. The script was not edited.

## What an outside auditor should focus on

- Behaviour of locked swaps under USDC blacklist/pause/upgrade (rows 8, 9, 23): the HTLC has no mitigation by design.
- The claim/refund boundary at `timestamp == timelock` and the swap-level margin that sits above it (`usdc-design.md`).
- The permissionless `claim` plus the preimage becoming public: confirm the counter-leg timeouts leave the other party
  time to use the revealed preimage.
- `SafeTransfer` against non-standard tokens (it is used only with USDC in this project).
- The deployment: bytecode equality with the `forge build` output used by the Rust client, constructor-less deploy, address
  pinning in `--usdc-htlc` / `[usdc].htlc`.
