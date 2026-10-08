# Lane e2e-local — real testnet swaps, maker and taker both local (Wave 2)

Read `_common.md` first. You own `tools/swap-poc/e2e.sh`, `tools/swap-poc/e2e/`, `bin/divi-swap/`
(the daemon lane is finished; you may extend the CLI, e.g. test-only timing flags), and
`docs/plans/swap-poc/status/e2e-local.md`. Bugs you find in other crates: fix them only if the
owning lane is finished (all Wave 1 lanes are) and keep their check scripts green.

**Build** `tools/swap-poc/e2e.sh <happy|case-c|case-d>`: starts `divi-swapd` locally (maker keys
`maker-divi`/`maker-btc` via `op://` refs, DB under a temp dir **outside** the repo), runs the
`divi-swap` taker (`taker-divi`/`taker-btc`) against it on DIVI testnet + BTC signet, and prints
every txid. Run each scenario as a background command; never sleep-loop in context.

- **happy**: taker locks BTC → maker locks DIVI after confirmations → taker claims DIVI → maker
  claims BTC. Both claims confirmed.
- **case-c** (taker never claims): maker refunds DIVI after its timeout; taker refunds BTC after its
  timeout. You may use shorter timeouts than the `testnet` profile (e.g. maker 1800 s, taker
  1800 s + `required_gap_secs`) if `SwapConfig::validate` accepts them — record the values.
- **case-d** (late claim): taker claims DIVI shortly before the maker timeout (CLI flag such as
  `--claim-not-before <secs-before-timeout>`); maker still claims BTC.

BTC is scarce: ≤ 20,000 sats per swap; reuse refunds. If the taker-btc address is unfunded,
park (`- blocked-on-human: yes`) and see `PARKED.md` #1.

**Acceptance** (`tools/swap-poc/check-e2e-local.sh`): `e2e.sh` is shellcheck-clean, and your status
file carries confirmed txids for `happy_btc_lock`, `happy_divi_lock`, `happy_divi_claim`,
`happy_btc_claim`, `casec_btc_lock`, `casec_divi_lock`, `casec_divi_refund`, `casec_btc_refund`,
`cased_divi_claim`, `cased_btc_claim` (as `- <key>_txid: <txid>`), plus `- cased_claim_secs_before_timeout: <n>`.
Copy them into `docs/plans/swap-poc/RESULTS.md` under "Wave 2".
