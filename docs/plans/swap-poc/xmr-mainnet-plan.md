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
| A1 | ~~`POST /xmr-lock` ran `step` → `find_lock` (a 720-block remote scan) inside the request; the taker's 30 s client timed out~~ | `crates/divi-swap-xmr/src/maker.rs` `xmr_locked`; `bin/divi-swap/src/client.rs:37` (pre-fix line; the maker client timeout is now `client.rs:103`, 300 s, and the `/healthz` wait default 600 s is `client.rs:42`) | done 2026-10-14: the handler records and returns, and `tick` verifies. Test `xmr_lock_report_does_not_step_inline`. |
| A2 | Mainnet `XmrConfig` profile: DIVI depth matched to the shared engine's mainnet 10 (testnet is 3), XMR 10 (spendable age), fee margins | `crates/divi-swap-xmr/src/lib.rs:91-98`; `crates/divi-swap/src/config.rs` | ~~`XmrConfig::mainnet()` exists with pinning tests~~ done 2026-10-14: DIVI 10 / XMR 10 confirmations (read from their sources), `t_cancel` 12 h, `t_punish` +12 h, margin 2 h, presigned fee 0.01 DIVI; `mainnet_profile_pinned`. Selected only through `live::profile_for(Mainnet, allow_mainnet = true)` |
| A3 | A real `cancel_after`/`punish_after`/`redeem_margin` schedule derived from block times and confirmation depths (like `required_gap_secs`), not fixed testnet hours | `crates/divi-swap-xmr/src/lib.rs:85-150,205-387`; `maker.rs:404-406` | ~~`validate()` rejects any schedule where a side can lose funds to a confirmation delay; property test~~ done 2026-10-14: `ChainTiming` (60 s / 120 s blocks, ×3 slow blocks, 30 min MTP lag, 5 min reaction) → `min_{cancel,punish,redeem_margin}_secs`; testnet minimums 12 240 / 3 600 / 2 640 s, mainnet 20 400 / 7 200 / 3 900 s. `tests/schedule.rs`: 3 888 timings × 150 schedules against an independent worst-case timeline, plus tightness |
| A4 | Maker-owned XMR wallet: the sweep goes to the maker's own wallet, never the taker's (stagenet sweeps into hp2's mining-wallet: a test topology) | `bin/divi-swapd/src/config.rs:237` (`sweep_address`); `main.rs:196-197` | maker sweep address belongs to a maker-only view key; balance-delta proof on stagenet | **done 2026-10-14**: view-only wallet from the maker's address + view key shows the two post-deploy sweeps (0.0019696 + 0.00196946 sXMR, height 2229221); RESULTS.md |
| A5 | Own monerod (not the public restricted node), with a persisted scan cursor so `find_lock` does not rescan 720 blocks after a restart | `crates/divi-swap-xmr/src/live.rs:412` (`find_lock`), `bin/divi-swapd/src/config.rs:261` (`lookback_blocks` default 720; field `live.rs:172`) | maker on a self-hosted stagenet monerod; restart mid-swap rescans ≤ a few blocks. **Code done 2026-10-14**: cursor persisted per lock address in the journal dir (3 tests). dnsdivi `monerod-stagenet` installed and syncing; switch-over pending its sync. A txid hint for `find_lock` (skip the scan entirely) is a possible follow-up, not needed for the gate. |
| A6 | ~~Taker waits for the maker's `/healthz` `divi_scan.state = done`~~ | `bin/divi-swap/src/client.rs`, `xmr_flow.rs` `begin` | done 2026-10-14: polls `/healthz` up to 600 s, `failed` stops at once, the quote retries only on 503 (4 tests) |
| A7 | One global `gate` mutex serialises every XMR swap's step, so one slow scan stalls all requests | `crates/divi-swap-xmr/src/maker.rs:417` (`swap_locks`; the pre-fix global `gate` was at `:265`) | ~~per-swap locking~~ done 2026-10-14: one lock per swap (pruned when unheld), plus a quote claim that closes a concurrent-`setup` double-use race; `a_stuck_scan_does_not_hold_up_other_swaps` (fails with one shared lock). The taker keeps its global gate (it steps only its own swaps); `tick` is still sequential |
| A8 | Stagenet soak: many concurrent swaps through dnsdivi, including maker restarts mid-swap and every outcome (redeem/refund/punish) | `tools/swap-poc/` | ≥ 20 swaps, 0 stuck, 0 lost; results in RESULTS.md **done 2026-10-15**: 22 maker swaps all `done`, 0 stuck, 0 lost: 14 redeemed, 2 restarts with swaps open, 4 accept-only + 3 lock-only refunded on both chains; 1 accept refused (one-coin maker DIVI wallet, nothing on chain). Punish evidence is the 2026-10-12 CLI-maker run. See RESULTS.md. |

Gate A: all A-items done, CI green, soak clean. Bert reviews.

## Phase B — operations

| # | Item | Done when |
|---|---|---|
| B1 | Rollback covers toml + unit, not just the binary (`redeploy-maker.sh` keeps only `divi-swapd.prev`; 0.2.6 silently ignores `[xmr]`) | one command restores binary + toml + unit; rehearsed on stagenet. **Code done 2026-10-14**: `redeploy-maker.sh` snapshots all three to `/var/backups/divi-swapd/<ts>/` (sha256) and auto-restores on a failed health check; `rollback-maker.sh --to prev\|<ts>`. **Rehearsed 2026-10-14 on stagenet**: f919e5c deployed by `redeploy-maker.sh`; a marker comment appended to the live toml; `rollback-maker.sh --to prev` restored the 0.2.6 binary (eb87…) and the toml without the marker, healthy; `--to 20261014T164644Z` undid it (f423…, marker back), healthy; marker then removed. |
| B1b | The redeploy in-flight gate reads only `/swaps`, not `/xmr/swaps` (`tools/swap-poc/redeploy-maker.sh`); an XMR swap mid-flight would not block a restart | ~~gate refuses while any `/xmr/swaps` entry is non-terminal~~ done 2026-10-14: 404 = no XMR engine (pass), 5xx/garbage refuses; 32 new checks in `test-redeploy-maker.sh`; **broken by C3 (`GET /xmr/swaps` removed), repaired 2026-10-22** (lane `redeploy-xmr-gate`): the XMR half now runs `divi-swapd --xmr-inflight` on the host over ssh (read-only store read, nothing exposed over HTTP); not yet run against the real maker |
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

Code consequences for the mainnet lift: the xmr DIVI address now follows the configured network (`bin/divi-swapd/src/main.rs:196-198`, done in f919e5c). `wallet_rpc_url` / `wallet_rpc_user` / `wallet_rpc_password` are now optional for the maker — **done 2026-10-22** (`bin/divi-swapd/src/config.rs`, `XmrSection.wallet_rpc_url: Option<String>`; `crates/divi-swap-xmr/src/live.rs`, `LiveMoneroConfig.wallet_rpc_url: Option<String>`, `lock` fails with a named error when it is unset). The taker CLI still requires `--xmr-wallet-rpc-url`.

## Phase C — external security review

Hand-written adaptor signatures, the cross-group DLEQ proof, encsig recovery and the DIVI script
templates (`crates/divi-swap-xmr/`, `crates/swap-chain-xmr/`) reviewed by someone outside the
project. Gate C: every **unfixed** finding accepted in writing by Bert. A finding fixed in code
leaves the gate when its fix lands (Bert, 2026-10-21: "if it is fixed, then revise it, no reason to
list fixed problems"); the fix reference stays in the Fixed table below, not in the gate. Gate list
today: none — every Phase C finding is fixed; what remains is the mainnet-swap decision itself.

The reviewer's brief is `xmr-review-brief.md` (pinned to a commit in its §8). Drafting it turned
up findings that block mainnet on their own, before any outside review. The gate is the first
table only.

**Open — the Gate C list (2026-10-21):** none.

**Fixed — off the gate, kept as the changelog:**

| # | Finding | Fix |
|---|---|---|
| C1 | **Counterparty malleation of `Tx_cancel`.** `Tx_refund`/`Tx_punish` spend `Tx_cancel` by txid (`crates/divi-swap-xmr/src/api.rs:129`); DIVI has no segwit, and each side holds the other's `Tx_cancel` signature, so either can re-sign its own half with a fresh nonce (a valid low-S signature, relayed normally) and broadcast a `Tx_cancel` with a different txid after `t_cancel`. Both presigned children are then invalid and both coins sit in a 2-of-2 neither side can spend alone: a ransom, not just a liveness risk. `xmr-design.md` §Risks covered only a miner. Needs a protocol change (or a written acceptance) before mainnet. Stakers can malleate too (NULLDUMMY/SIGPUSHONLY/CLEANSTACK/MINIMALDATA are relay-only), and any relay node can S-flip: Divi 3.0.0 does not make LOW_S standard (regtest 2026-10-15). | **fixed 2026-10-15** — 2P-ECDSA joint cancel key (Lindell-2017 J), OP_DEPTH guard, unilateral punish branch: `xmr-c1-design.md`; commits 3c24b32 / 5481207, stagenet maker 1841a12; all §7 tests PASS (`c1-regtest-results.md`, RESULTS.md, `c1-punish-results.md`); Bert chose option A 2026-10-15 |
| C2 | Taker does not check `Tx_cancel`'s output value (`taker.rs:277-287`, pre-fix lines); a tiny output zeroes `Tx_punish`. | **fixed in code 2026-10-15** (3c24b32: `taker.rs:509` rejects `tx_cancel.vout[0].value + divi_fee_sats != lock_amount`); regression test `the_taker_checks_tx_cancels_output_value` in `crates/divi-swap-xmr/tests/engine.rs` (reduced and dust value refused, exact value accepted) |
| C7 | Staker malleation of `Tx_lock`: `Tx_cancel` is presigned against `Tx_lock`'s txid before it confirms, and its P2PKH inputs are malleable by any staker. A malleated `Tx_lock` leaves the maker's DIVI in the 2-of-2 with no cancel (the taker locks nothing). | **fixed 2026-10-15** (3c24b32: maker-unilateral `t_late` branch, `maker.rs:194,231,1347,1395`, `taker.rs:502`; design `xmr-c1-design.md` §4.3; C1-design §7 test 7 "Malleated Tx_lock" PASS on regtest; unit regression tests `a_malleated_tx_lock_is_reclaimed_after_t_late` and `the_late_branch_stays_idle_on_the_normal_path` in `crates/divi-swap-xmr/tests/engine.rs`) |
| C3 | Unauthenticated setup reserved maker UTXOs that an abort never released; no auth or rate limit on XMR routes; `quote()` stored unbounded records. | **fixed 2026-10-21** (commit 1ef0c52: `release_funding` on every setup error/abort path and when `sigs_wait_secs` expires; `MAX_XMR_QUOTES` cap with expiry sweep; per-IP 20/60 s limiter → 429; per-swap 32-byte `X-Swap-Token`, mismatch → 404). Tests: `an_aborted_setup_releases_its_coins_and_a_locked_swap_keeps_them`, `the_quote_store_is_bounded`, `the_swap_token_gates_a_swap` (`crates/divi-swap-xmr/tests/engine.rs`); `xmr_swap_routes_need_the_swap_token`, `xmr_setup_is_rate_limited_per_ip` (`bin/divi-swapd/tests/e2e_xmr.rs`); `the_limiter_counts_per_ip_per_window` (`routes.rs`) |
| C6 | Lower: `/xmr/swaps` listed every swap and anyone could post the lock notice; `find_lock` took the first output (dust grief); one-confirmation `done`; unchecked `t_cancel + punish_after` add. | **fixed 2026-10-21** (commit 1ef0c52: no listing route, lookup by id + token; `find_lock(.., min_amount)` skips smaller outputs; maker `Done` waits for `xmr_confirmations` / `divi_confirmations`; `deadlines()` uses `checked_add` and the C5 bounds). Tests: `find_lock_skips_dust_to_the_lock_address`, `done_waits_for_the_profiles_confirmation_depth`, `setup_refuses_overflowing_timelocks`, `xmr_and_hashlock_routes_do_not_cross` (405 on the listing), `first_at_least` test in `swap-chain-xmr/src/monero_chain.rs`, `deadlines_are_checked_and_bounded` (`maker.rs`) |
| C4 | No check that the DIVI RPC is on the expected chain (`main.rs:183-187` compared only the URL, pre-fix lines; the chain check is now `check_divi_chain` at `bin/divi-swapd/src/main.rs:243` and `bin/divi-swap/src/main.rs:1066`); every timelock trusts its median time past. | **fixed 2026-10-21** (f3d343d: `DiviChain::chain_name` → `getblockchaininfo.chain`; `check_divi_chain` at `divi-swapd` and `divi-swap` XMR startup refuses a mismatch; test `divi_chain_check_accepts_a_match_and_refuses_a_mismatch` in `crates/divi-swap-xmr/tests/engine.rs`, and `chain_name_*` in `swap-chain-xmr/src/divi_chain.rs`) |
| C5 | Taker accepted any `t_cancel`/`t_punish` upper bound (`taker.rs:289-293`, pre-fix lines): a maker could hold her XMR for years. | **fixed 2026-10-21** (f3d343d: `taker.rs:536-537` rejects `t_cancel > mtp + MAX_CANCEL_AFTER_SECS` (24 h) and `t_punish > t_cancel + MAX_PUNISH_AFTER_SECS` (12 h), the largest values `tests/schedule.rs` considers; test `the_taker_bounds_t_cancel_and_t_punish_from_above`, accepted at the bound, refused one second above, for each) |
| C8 | A transient monerod connection error panics a taker task (`crates/swap-chain-xmr/src/live_rpc.rs:249` `expect("get_block reachable")`, pre-fix line; now `fetch_scannable_block` `live_rpc.rs:393` and `scan_block` `:480` return errors); seen twice in A8 on the public node and again in the C1 soak. The rerun resumed from the journal, but it must be an error, not a panic. | **fixed 2026-10-15** (1841a12: `fetch_scannable_block`/`scan_block`/`scan_for_lock_output` return errors; `find_lock`/`sweep` map them to `MoneroChainError::Rpc`); maker redeployed to dnsdivi 2026-10-15 16:29Z (sha `929c9b54…`) |
| C3 follow-ups | Builder J's three left items after the Gate C close: an orphan reservation (crash between `build_funding` and the record), pre-token records unreachable over HTTP, one shared rate bucket behind a proxy. | **fixed 2026-10-21** (commit 17ce839: first-`tick` sweep `release_orphan_funding` — the wallet file persists reservations; `migrate_pre_token` mints and stores a token; `trust_proxy_headers`, default off). Tests: `a_restart_sweeps_a_reservation_with_no_record_and_keeps_one_with_a_record`, `a_pre_token_record_gets_a_token_and_still_completes` (`crates/divi-swap-xmr/tests/engine.rs`), `release_unreferenced_frees_only_reservations_outside_keep` (`swap-chain-divi/src/wallet.rs`), `spoofed_forwarded_for_is_ignored_by_default`, `forwarded_for_selects_the_bucket_when_trusted`, `garbage_forwarded_for_falls_back_to_the_socket` (`bin/divi-swapd/tests/e2e_xmr.rs`), `proxy_headers_are_ignored_unless_trusted`, `trusted_proxy_headers_pick_the_client_and_garbage_falls_back` (`routes.rs`) |

## Phase D — staged mainnet trials (needs Bert's explicit go)

Separate mainnet infrastructure (not dnsdivi testnet). The refusals are an opt-in since
2026-10-14 (`live::profile_for`); set `allow_mainnet` / `--xmr-allow-mainnet` only in this phase.
Mainnet also needs an explicit DIVI mainnet RPC (`[xmr].divi_rpc_url`, `--xmr-divi-rpc-url`): the
default is the testnet proxy and both binaries refuse it on mainnet.
Dust-sized swaps first, with Bert at the keyboard, per-run confirmation, then a raised cap.
Each trial records lock/claim/sweep txids the same way RESULTS.md does.

## Decision log

- 2026-10-22: the XMR taker now refuses maker quotes and setups weaker than its own `--profile` floors (`XmrTaker::with_profile_floor`, `crates/divi-swap-xmr/src/taker.rs`) before any key or lock; no gate status, value or refusal changed.
- 2026-10-21, Bert (via the Manager, 14:05Z): "if it is fixed, then revise it, no reason to list fixed
  problems. if it is fixed, why do you need me?" — Gate C lists only unfixed findings; C1, C2, C7, C8 moved
  to the Fixed table with their commits; C3–C6 remained open then (C3 and C6 fixed later the same day); acceptance is asked for only when a mainnet
  XMR swap is proposed.
- 2026-10-14, Bert: **full go** — phases A and B, and the code change that lifts the mainnet
  refusal. Hard stop before any real-money swap: phase C needs an outside reviewer, phase D needs
  Bert at the keyboard. No mainnet or real-funds swap is run by an agent. Report at each gate.
