# Lane rev-tools — e2e script, chaos driver and CI for the reverse direction

Read `_common.md` and `../reverse-direction.md` first. You own `tools/swap-poc/e2e.sh`,
`tools/swap-poc/chaos/`, and `docs/plans/swap-poc/status/rev-tools.md`. Engine and CLI change in parallel
(lanes rev-engine, rev-cli); rebase often. The orchestrator does the live testnet runs; you make them possible.

**Build:**
- `e2e.sh … --offer <divi-btc-testnet|btc-divi-testnet>` (default forward, unchanged behaviour and output).
  Reverse: state dir `rev-<scenario>-<backend|deployed>`, txid prefix `rev_happy|rev_casec|rev_cased`
  (`deployed_rev_…` with `--maker-url`), keys from `divi-swap txids` per `reverse-direction.md`; pass
  `--divi-wallet "$state/../taker-divi-wallet.json"` to the taker for reverse; case-c reverse waits on
  `btc_spend_by_maker` (maker BTC refund) and `divi_refund_by_taker`. Before a live reverse run, check the
  maker has BTC (`/healthz` or the maker's offers) and the taker has DIVI (`divi-swap balance`), and die
  with a clear message if not. shellcheck clean.
- `--backend mock` plumbing works for both offers.
- chaos driver (`chaos/driver.py`): `--offer` passthrough so the chaos scenarios run reverse against mock.
- `tools/swap-poc/check-rev-live.sh` (the orchestrator's live acceptance): reads
  `docs/plans/swap-poc/status/rev-live.md` keys `rev_happy_{divi_lock,btc_lock,btc_claim,divi_claim}_txid`
  and `rev_casec_{divi_lock,btc_lock,btc_refund,divi_refund}_txid` (any of those may carry the
  `deployed_` prefix instead) and checks each confirmed with `lib.sh` helpers.

**Acceptance** (`tools/swap-poc/check-rev-tools.sh`): shellcheck clean on e2e.sh and check-rev-live.sh,
`e2e.sh happy --backend mock --offer btc-divi-testnet` and the forward mock both exit 0, chaos driver
`--help` shows `--offer`, and `python3 -m py_compile` passes on the chaos scripts.
