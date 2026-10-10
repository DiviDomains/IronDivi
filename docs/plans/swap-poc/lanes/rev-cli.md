# Lane rev-cli — daemon offer + taker CLI for the reverse direction

Read `_common.md` and `../reverse-direction.md` first. You own `bin/divi-swap/`, `bin/divi-swapd/` and
`docs/plans/swap-poc/status/rev-cli.md`. The rev-engine lane makes the engine direction-aware in parallel;
`git pull --rebase origin main` often. Until it lands, your reverse e2e tests fail — write them anyway.

**Build:**
- divi-swapd: second default offer `btc-divi-testnet` (`Direction::TakerPaysDivi`, same rate and limits as
  `divi-btc-testnet`); config can set `direction` per offer. Existing configs (no `direction`) still parse.
- divi-swap: `--divi-wallet PATH` and `--divi-scan-from HEIGHT` for the taker's DIVI coins (live backend
  only; DiviBackend wallet path; refuse a path inside the git tree; file mode 0600; resume from its cursor).
  `quote/accept/run --offer` already pass through — make sure `run` works for both directions and that
  `--never-claim` / `--claim-not-before` act on whichever leg the taker claims.
- `txids` output exactly as in `reverse-direction.md` (forward keys unchanged — `tools/swap-poc/e2e.sh` reads them).
- `divi-swap balance` (live): prints the taker's DIVI and BTC balances (no keys), for funding checks.

**Acceptance** (`tools/swap-poc/check-rev-cli.sh`): divi-swapd and divi-swap-cli green, existing daemon tests
pass, new tests `offers_list_has_both_directions`, `e2e_mock_rev_happy_path`, `e2e_mock_rev_refund`
(daemon + taker over two MockChains, real HTTP), `txids_reverse_keys`, `old_config_without_direction_parses`;
`divi-swap balance --help` works.
