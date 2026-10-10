# Orchestrator status

- **Wave/step:** Reverse direction (Bert 2026-10-10: "add the reverse direction, sell divi for btc").
  Plan `docs/plans/swap-poc/reverse-direction.md`. Contract (`Direction`, role-based `SwapView` legs) on main `3b8bb1b`.
- **Lanes:** rev-engine, rev-cli, rev-tools all landed (main `4ae2ed8`, CI green; check-rev-{engine,cli,tools}.sh PASS
  on main) and their panes are closed. Tab 0:6 "Divi Swap 1" holds orchestrator `pane-3f088f33…`, secret-broker `ae8a03fc…`.
- **Deployed:** dnsdivi divi-swapd from `4ae2ed8` (v0.2.5): offers `divi-btc-testnet` + `btc-divi-testnet`; both old
  forward swaps load as Done; healthz ok.
- **Closed 2026-10-10:** the nine forward lane panes (engine, daemon, deploy, btc, divi, e2e-local, chaos, e2e-live,
  chaos-live) — all done, worktrees clean; tab "Divi Swap 2" emptied and gone.
- **Live prerequisites:** taker DIVI xy2MorbDhp35NxBHytHjv3LQo7fvHE4y3b funded 2000 tDIVI from dnsdivi node5
  (`e2a31cfa2a6b7e1e597e2a979ce2dd5c478629f2796b929071ee61e36cfb0b60`). Maker BTC tb1quqkt7c06svzt68f2y9uwf2jzgpd48k6ku45zrt
  funded 132,138 sats by Bert (`62e9c87e6fc08507ca3fdf5ff8a7a3e22dc0aa46e626ae11191a9e4f55ff78e2`).
- **Testnet coins stay with us** (Bert 2026-10-10: "keep all our testnet coind so i dont need to get more"): no sweeps.
- **Live reverse:** happy path Done/Done through the deployed maker, 4 txids confirmed (status/rev-live.md, `161c761`).
  Case C (both refund) running since 2026-10-10 against the deployed maker, log `~/.local/state/iron-divi-swap-poc/e2e-deployed-rev-casec.log`.
- **Left:** case C txids → rev-live.md, `check-rev-live.sh` PASS, RESULTS.md reverse section.
- **Forward POC:** DONE 2026-10-10 13:40 UTC (RESULTS.md §1). divi-swapd on dnsdivi v0.2.5 `504da62`, testnet3, healthy.
- **Compactions:** orchestrator 5
- Long briefs go in a file (`~/.local/state/iron-divi-swap-poc/briefs/`); a long `ctl submit` gets truncated.
