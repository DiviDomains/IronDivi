# XMR ↔ DIVI: plan from stagenet proof to mainnet

Status 2026-10-14: **not ready for mainnet.** The POC's definition of done is "proven on public
testnets" (`docs/plans/atomic-swap-poc.md` §1), and that is met for XMR: the redeem, refund and
punish paths ran live (RESULTS.md, 2026-10-12), and the deployed `divi-swapd` served a stagenet
swap on 2026-10-14. Mainnet is a separate decision Bert makes. This plan lists what stands
between the two; `mainnet-readiness.md` §XMR is the review it builds on.

Every phase ends with a gate. Nothing here flips the mainnet refusal
(`bin/divi-swapd/src/main.rs:182`, `bin/divi-swap/src/main.rs:610`) before phase D, and nothing
moves real funds before phase D.

## Phase A — code, testnet only (refusals stay in)

| # | Item | Where | Done when |
|---|---|---|---|
| A1 | ~~`POST /xmr-lock` ran `step` → `find_lock` (a 720-block remote scan) inside the request; the taker's 30 s client timed out~~ | `crates/divi-swap-xmr/src/maker.rs` `xmr_locked`; `bin/divi-swap/src/client.rs:37` | done 2026-10-14: the handler records and returns, and `tick` verifies. Test `xmr_lock_report_does_not_step_inline`. |
| A2 | Mainnet `XmrConfig` profile: DIVI depth matched to the shared engine's mainnet 10 (testnet is 3), XMR 10 (spendable age), fee margins | `crates/divi-swap-xmr/src/lib.rs:91-98`; `crates/divi-swap/src/config.rs` | `XmrConfig::mainnet()` exists with pinning tests; it is never selected while the refusals stand |
| A3 | A real `cancel_after`/`punish_after`/`redeem_margin` schedule derived from block times and confirmation depths (like `required_gap_secs`), not fixed testnet hours | `crates/divi-swap-xmr/src/lib.rs:69-116`; `maker.rs:404-406` | `validate()` rejects any schedule where a side can lose funds to a confirmation delay; property test |
| A4 | Maker-owned XMR wallet: the sweep goes to the maker's own wallet, never the taker's (stagenet sweeps into hp2's mining-wallet: a test topology) | `bin/divi-swapd/src/config.rs:143`; `main.rs:184` | maker sweep address belongs to a maker-only view key; balance-delta proof on stagenet |
| A5 | Own monerod (not the public restricted node), with a persisted scan cursor so `find_lock` does not rescan 720 blocks after a restart | `crates/divi-swap-xmr/src/live.rs:326` (`find_lock`), `:462` (`lookback_blocks: 720`) | maker on a self-hosted stagenet monerod; restart mid-swap rescans ≤ a few blocks |
| A6 | Taker waits for the maker's `/healthz` `divi_scan.state = done` (first run on 2026-10-14 got `503 wallet scan in progress`) | `bin/divi-swap/src/xmr_flow.rs` `begin` | taker retries/waits instead of exiting with 503 |
| A7 | One global `gate` mutex serialises every XMR swap's step, so one slow scan stalls all requests | `crates/divi-swap-xmr/src/maker.rs:265` | per-swap locking, or no network I/O held under the gate |
| A8 | Stagenet soak: many concurrent swaps through dnsdivi, including maker restarts mid-swap and every outcome (redeem/refund/punish) | `tools/swap-poc/` | ≥ 20 swaps, 0 stuck, 0 lost; results in RESULTS.md |

Gate A: all A-items done, CI green, soak clean. Bert reviews.

## Phase B — operations

| # | Item | Done when |
|---|---|---|
| B1 | Rollback covers toml + unit, not just the binary (`redeploy-maker.sh` keeps only `divi-swapd.prev`; 0.2.6 silently ignores `[xmr]`) | one command restores binary + toml + unit; rehearsed on stagenet |
| B1b | The redeploy in-flight gate reads only `/swaps`, not `/xmr/swaps` (`tools/swap-poc/redeploy-maker.sh`); an XMR swap mid-flight would not block a restart | gate refuses while any `/xmr/swaps` entry is non-terminal; test in `test-redeploy-maker.sh` |
| B2 | Alerting on any XMR swap with `last_error` set or stuck past its state's deadline, and on scan lag | an alert fires in a drill |
| B3 | Runbook: stuck swap, refund, punish, monerod down, key rotation | `docs/` runbook walked through once by a human |
| B4 | Key handling: `maker-divi-xmr` and the maker's XMR wallet keys on mainnet-grade custody, separate from the test keys | separate 1Password items, separate host |

## Phase C — external security review

Hand-written adaptor signatures, the cross-group DLEQ proof, encsig recovery and the DIVI script
templates (`crates/divi-swap-xmr/`, `crates/swap-chain-xmr/`) reviewed by someone outside the
project. Gate C: findings fixed or accepted in writing by Bert.

## Phase D — staged mainnet trials (needs Bert's explicit go)

Separate mainnet infrastructure (not dnsdivi testnet). Remove the two refusals only in this phase.
Dust-sized swaps first, with Bert at the keyboard, per-run confirmation, then a raised cap.
Each trial records lock/claim/sweep txids the same way RESULTS.md does.
