# XMR ↔ DIVI: plan from stagenet proof to mainnet

Status 2026-10-14: **not ready for mainnet.** The POC's definition of done is "proven on public
testnets" (`docs/plans/atomic-swap-poc.md` §1), and that is met for XMR: the redeem, refund and
punish paths ran live (RESULTS.md, 2026-10-12), and the deployed `divi-swapd` served a stagenet
swap on 2026-10-14. Mainnet is a separate decision Bert makes. This plan lists what stands
between the two; `mainnet-readiness.md` §XMR is the review it builds on.

Every phase ends with a gate. Nothing moves real funds before phase D. The hard mainnet refusal
became an explicit opt-in on 2026-10-14 (Bert's full go, decision log): mainnet now needs
`[xmr].allow_mainnet = true` (maker) or `--xmr-allow-mainnet` (taker), both off by default, and
nobody sets them before phase D.

## Phase A — code, testnet only (refusals stay in)

| # | Item | Where | Done when |
|---|---|---|---|
| A1 | ~~`POST /xmr-lock` ran `step` → `find_lock` (a 720-block remote scan) inside the request; the taker's 30 s client timed out~~ | `crates/divi-swap-xmr/src/maker.rs` `xmr_locked`; `bin/divi-swap/src/client.rs:37` | done 2026-10-14: the handler records and returns, and `tick` verifies. Test `xmr_lock_report_does_not_step_inline`. |
| A2 | Mainnet `XmrConfig` profile: DIVI depth matched to the shared engine's mainnet 10 (testnet is 3), XMR 10 (spendable age), fee margins | `crates/divi-swap-xmr/src/lib.rs:91-98`; `crates/divi-swap/src/config.rs` | ~~`XmrConfig::mainnet()` exists with pinning tests~~ done 2026-10-14: DIVI 10 / XMR 10 confirmations (read from their sources), `t_cancel` 12 h, `t_punish` +12 h, margin 2 h, presigned fee 0.01 DIVI; `mainnet_profile_pinned`. Selected only through `live::profile_for(Mainnet, allow_mainnet = true)` |
| A3 | A real `cancel_after`/`punish_after`/`redeem_margin` schedule derived from block times and confirmation depths (like `required_gap_secs`), not fixed testnet hours | `crates/divi-swap-xmr/src/lib.rs:69-116`; `maker.rs:404-406` | ~~`validate()` rejects any schedule where a side can lose funds to a confirmation delay; property test~~ done 2026-10-14: `ChainTiming` (60 s / 120 s blocks, ×3 slow blocks, 30 min MTP lag, 5 min reaction) → `min_{cancel,punish,redeem_margin}_secs`; testnet minimums 12 240 / 3 600 / 2 640 s, mainnet 20 400 / 7 200 / 3 900 s. `tests/schedule.rs`: 3 888 timings × 150 schedules against an independent worst-case timeline, plus tightness |
| A4 | Maker-owned XMR wallet: the sweep goes to the maker's own wallet, never the taker's (stagenet sweeps into hp2's mining-wallet: a test topology) | `bin/divi-swapd/src/config.rs:143`; `main.rs:184` | maker sweep address belongs to a maker-only view key; balance-delta proof on stagenet |
| A5 | Own monerod (not the public restricted node), with a persisted scan cursor so `find_lock` does not rescan 720 blocks after a restart | `crates/divi-swap-xmr/src/live.rs:326` (`find_lock`), `:462` (`lookback_blocks: 720`) | maker on a self-hosted stagenet monerod; restart mid-swap rescans ≤ a few blocks. **Code done 2026-10-14**: cursor persisted per lock address in the journal dir (3 tests). dnsdivi `monerod-stagenet` installed and syncing; switch-over pending its sync. A txid hint for `find_lock` (skip the scan entirely) is a possible follow-up, not needed for the gate. |
| A6 | ~~Taker waits for the maker's `/healthz` `divi_scan.state = done`~~ | `bin/divi-swap/src/client.rs`, `xmr_flow.rs` `begin` | done 2026-10-14: polls `/healthz` up to 600 s, `failed` stops at once, the quote retries only on 503 (4 tests) |
| A7 | One global `gate` mutex serialises every XMR swap's step, so one slow scan stalls all requests | `crates/divi-swap-xmr/src/maker.rs:265` | ~~per-swap locking~~ done 2026-10-14: one lock per swap (pruned when unheld), plus a quote claim that closes a concurrent-`setup` double-use race; `a_stuck_scan_does_not_hold_up_other_swaps` (fails with one shared lock). The taker keeps its global gate (it steps only its own swaps); `tick` is still sequential |
| A8 | Stagenet soak: many concurrent swaps through dnsdivi, including maker restarts mid-swap and every outcome (redeem/refund/punish) | `tools/swap-poc/` | ≥ 20 swaps, 0 stuck, 0 lost; results in RESULTS.md |

Gate A: all A-items done, CI green, soak clean. Bert reviews.

## Phase B — operations

| # | Item | Done when |
|---|---|---|
| B1 | Rollback covers toml + unit, not just the binary (`redeploy-maker.sh` keeps only `divi-swapd.prev`; 0.2.6 silently ignores `[xmr]`) | one command restores binary + toml + unit; rehearsed on stagenet. **Code done 2026-10-14**: `redeploy-maker.sh` snapshots all three to `/var/backups/divi-swapd/<ts>/` (sha256) and auto-restores on a failed health check; `rollback-maker.sh --to prev\|<ts>`. **Rehearsed 2026-10-14 on stagenet**: f919e5c deployed by `redeploy-maker.sh`; a marker comment appended to the live toml; `rollback-maker.sh --to prev` restored the 0.2.6 binary (eb87…) and the toml without the marker, healthy; `--to 20261014T164644Z` undid it (f423…, marker back), healthy; marker then removed. |
| B1b | The redeploy in-flight gate reads only `/swaps`, not `/xmr/swaps` (`tools/swap-poc/redeploy-maker.sh`); an XMR swap mid-flight would not block a restart | ~~gate refuses while any `/xmr/swaps` entry is non-terminal~~ done 2026-10-14: 404 = no XMR engine (pass), 5xx/garbage refuses; 32 new checks in `test-redeploy-maker.sh` |
| B2 | ~~Alerting on any XMR swap with `last_error` set or stuck past its state's deadline, and on scan lag~~ | done 2026-10-14: `deploy/divi-swapd/swap-watch/` on dnsdivi (5-min timer, Telegram). Drill: API pointed at a dead port sent the alert, the next run sent "healthy again". The monerod check is off until the maker uses the local node (A5). Added 2026-10-14: an alert when a `cancelled`/`refunded` swap is within 1 h of `t_punish` (the 12 h stuck alert came after the 3 h testnet punish window); drilled against a fake API (fires on the 20-min swap only). |
| B3 | Runbook: stuck swap, refund, punish, monerod down, key rotation | `docs/` runbook walked through once by a human. Written 2026-10-14: `xmr-runbook.md`. Agent walk-through against the live stagenet maker 2026-10-14 fixed three gaps: the swap view now carries `t_cancel`/`t_punish` (the runbook's most urgent check had no data), `swap-watch.sh dry-run` now reads `/etc/swap-watch.env` (it reported a monerod alert the timer never sends), and `punished` was mislabelled as the taker's loss. The human walk-through is still open. |
| B4 | Key handling: `maker-divi-xmr` and the maker's XMR wallet keys on mainnet-grade custody, separate from the test keys | separate 1Password items, separate host. Design below (§B4 key custody); the items are created in phase D |

### B4 key custody (design, 2026-10-14)

What the maker host must hold, and what it must not:

| Secret | On the maker host? | Why |
|---|---|---|
| `[xmr].divi_key` (funds `Tx_lock`, signs `Tx_cancel`/`Tx_refund`/`Tx_punish`) | yes: a hot key | the daemon signs refunds unattended, against the `t_punish` deadline. Cap the risk by funding: keep only the working float on this key (offer `max` × concurrent swaps), not a treasury |
| per-swap secrets (`s_m`, DLEQ, encsigs) | yes, in the SQLite state | generated per swap; `/var/lib/divi-swapd` 0700; backups of the DB are as sensitive as the key |
| maker XMR wallet spend key (sweep target) | **no** | the daemon only needs `sweep_address`. The spend key lives in 1Password (and a paper/offline copy for mainnet); a view-only wallet on another host proves receipts |
| `wallet_rpc_*` | **no** | `monero_chain::lock` (wallet RPC) is the taker's XMR lock; the maker never sends XMR from a wallet, and sweeps with the recovered key. Drop `monero-wallet-rpc` from the mainnet maker; make `wallet_rpc_url` optional in config |

Mainnet items are new 1Password items, never the stagenet ones renamed: `IronDivi Swap - maker-divi-xmr-mainnet`, `IronDivi Swap - maker-xmr-wallet-mainnet`, generated on Bert's machine at the keyboard (phase D). They go on a separate mainnet host, provisioned by `deploy.sh provision-secrets`. Rotation follows `xmr-runbook.md` §Keys.

Code consequences for the mainnet lift: `bin/divi-swapd/src/main.rs:193` hard-codes `DiviNetwork::Testnet` for the xmr DIVI address; it must follow the configured network. `wallet_rpc_url` should become optional for the maker.

## Phase C — external security review

Hand-written adaptor signatures, the cross-group DLEQ proof, encsig recovery and the DIVI script
templates (`crates/divi-swap-xmr/`, `crates/swap-chain-xmr/`) reviewed by someone outside the
project. Gate C: findings fixed or accepted in writing by Bert.

## Phase D — staged mainnet trials (needs Bert's explicit go)

Separate mainnet infrastructure (not dnsdivi testnet). The refusals are an opt-in since
2026-10-14 (`live::profile_for`); set `allow_mainnet` / `--xmr-allow-mainnet` only in this phase.
Mainnet also needs an explicit DIVI mainnet RPC (`[xmr].divi_rpc_url`, `--xmr-divi-rpc-url`): the
default is the testnet proxy and both binaries refuse it on mainnet.
Dust-sized swaps first, with Bert at the keyboard, per-run confirmation, then a raised cap.
Each trial records lock/claim/sweep txids the same way RESULTS.md does.

## Decision log

- 2026-10-14, Bert: **full go** — phases A and B, and the code change that lifts the mainnet
  refusal. Hard stop before any real-money swap: phase C needs an outside reviewer, phase D needs
  Bert at the keyboard. No mainnet or real-funds swap is run by an agent. Report at each gate.
