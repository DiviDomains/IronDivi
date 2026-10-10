# Orchestrator status

- **Wave/step:** Reverse direction (Bert 2026-10-10: "add the reverse direction, sell divi for btc").
  Plan `docs/plans/swap-poc/reverse-direction.md`. Contract (`Direction`, role-based `SwapView` legs) on main `3b8bb1b`.
- **Lanes (tab 0:6 "Divi Swap 1"):** rev-engine `34db330d…`, rev-cli `50dd3931…`, rev-tools `d97c4060…`
  (worktrees `~/code/IronDivi-swap-rev-*`, branches `swap/rev-*`, Stop hooks → `check-rev-*.sh`). Sonnet, narrow profile.
  Also in 0:6: orchestrator `pane-3f088f33…`, secret-broker `ae8a03fc…`.
- **Closed 2026-10-10:** the nine forward lane panes (engine, daemon, deploy, btc, divi, e2e-local, chaos, e2e-live,
  chaos-live) — all done, worktrees clean; tab "Divi Swap 2" emptied and gone.
- **Live prerequisites:** taker DIVI xy2MorbDhp35NxBHytHjv3LQo7fvHE4y3b funded 2000 tDIVI from dnsdivi node5
  (`e2a31cfa2a6b7e1e597e2a979ce2dd5c478629f2796b929071ee61e36cfb0b60`). Maker BTC tb1quqkt7c06svzt68f2y9uwf2jzgpd48k6ku45zrt
  is empty — needs Bert's tBTC (ask after engine/cli/tools are green and dnsdivi is redeployed).
- **Left:** merge-watch lanes; mock reverse e2e; redeploy dnsdivi (swaps.db must still load); live reverse happy + case C
  (`check-rev-live.sh`); RESULTS.md; sweep leftover tBTC to tb1qerzrlxcfu24davlur5sqmgzzgsal6wusda40er; close rev panes.
- **Forward POC:** DONE 2026-10-10 13:40 UTC (RESULTS.md §1). divi-swapd on dnsdivi v0.2.5 `504da62`, testnet3, healthy.
- **Compactions:** orchestrator 5
- Long briefs go in a file (`~/.local/state/iron-divi-swap-poc/briefs/`); a long `ctl submit` gets truncated.
