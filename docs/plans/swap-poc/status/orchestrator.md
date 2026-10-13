# Orchestrator status

- **USDC (2026-10-12):** validated-on-simulation (anvil 36/36, `898b1e2`; DECISIONS #12). Lane not held. Only remaining
  live step: Sepolia run, faucet-gated, parked not blocking (PARKED #3).

- **Wave/step:** Reverse direction (Bert 2026-10-10: "add the reverse direction, sell divi for btc").
  Plan `docs/plans/swap-poc/reverse-direction.md`. Contract (`Direction`, role-based `SwapView` legs) on main `3b8bb1b`.
- **Lanes:** rev-engine, rev-cli, rev-tools all landed (main `4ae2ed8`, CI green; check-rev-{engine,cli,tools}.sh PASS
  on main) and their panes are closed. Tab 0:6 "Divi Swap 1" holds orchestrator `pane-3f088f33…`, secret-broker `ae8a03fc…`.
- **Deployed (2026-10-13):** dnsdivi divi-swapd from `4e0ac26` (v0.2.6, sha256 `b5540e30…60ac`), via
  `redeploy-maker.sh --binary` after its in-flight gate passed; previous binary kept as `.prev`;
  healthz ok after a ~10 min DIVI rescan; serves BTC, LTC and ZEC tips.
- **Earlier:** dnsdivi divi-swapd from `4ae2ed8` (v0.2.5): offers `divi-btc-testnet` + `btc-divi-testnet`; both old
  forward swaps load as Done; healthz ok.
- **Closed 2026-10-10:** the nine forward lane panes (engine, daemon, deploy, btc, divi, e2e-local, chaos, e2e-live,
  chaos-live) — all done, worktrees clean; tab "Divi Swap 2" emptied and gone.
- **Live prerequisites:** taker DIVI xy2MorbDhp35NxBHytHjv3LQo7fvHE4y3b funded 2000 tDIVI from dnsdivi node5
  (`e2a31cfa2a6b7e1e597e2a979ce2dd5c478629f2796b929071ee61e36cfb0b60`). Maker BTC tb1quqkt7c06svzt68f2y9uwf2jzgpd48k6ku45zrt
  funded 132,138 sats by Bert (`62e9c87e6fc08507ca3fdf5ff8a7a3e22dc0aa46e626ae11191a9e4f55ff78e2`).
- **Testnet coins stay with us** (Bert 2026-10-10: "keep all our testnet coind so i dont need to get more"): no sweeps.
- **Reverse direction — parity plan** (2026-10-11; the forward suite is the bar; the runs share the maker-BTC and
  taker-DIVI keys, so they run one at a time, and timelocks set the wall-clock):
  1. live happy (deployed maker) — DONE 2026-10-10
  2. live case C, both refund (deployed maker) — DONE 2026-10-10
  3. live case D, late claim (local maker) — DONE 2026-10-11, swap `03bcb3e3…`, claimed 2398 s before the maker timeout
  4. live chaos `--scenario all --offer btc-divi-testnet` (crash at every state, refund, DIVI RPC 502, Esplora 429) —
     DONE 2026-10-11 18:22 EDT, all four scenarios PASS (RESULTS.md, status/rev-chaos.md); taker DIVI refund `d1a45509…`.
     Mock dry run PASS after `491f264`.
  5. staking invariant — holds by construction: in the reverse direction the maker locks BTC, never DIVI.
  6. record txids (status/rev-live.md, RESULTS.md), update the explainer page, commit, CI.
- **Forward POC:** DONE 2026-10-10 13:40 UTC (RESULTS.md §1). divi-swapd on dnsdivi v0.2.5 `504da62`, testnet3, healthy.
- **Compactions:** orchestrator 5
- Long briefs go in a file (`~/.local/state/iron-divi-swap-poc/briefs/`); a long `ctl submit` gets truncated.

## Multi-coin (plan: `multi-coin.md`)

- 2026-10-11: wave 0 landed — crate scaffolds `swap-chain-{ltc,zec,evm}`, lane briefs
  `lanes/{_hp2,ltc,zec,usdc,xmr}.md`, checks `check-{ltc,zec,usdc,xmr}.sh`, `hp2-land.sh`,
  `lane-sync.sh`. Lanes run on hp2 (`~/swap-lanes/<coin>`), panes in Avada tab "Swap coins".
- hp2 lanes authenticate with the long-lived `CLAUDE_CODE_OAUTH_TOKEN` from 1Password item
  `orch-claude-oauth`, piped to `hp2:~/.config/claude-swap/oauth.env` (600) and sourced by
  `hp2:~/.local/bin/claude_auto`. Onboarding, trust and the bypass prompt are pre-accepted there.
- 2026-10-12: the old account hit its usage limit; the lanes moved to account claude.ai.2. Token
  now from 1Password `Private/claude.ai.2` field `password` (old file kept as `oauth.env.old-account`).
  All five lanes were restarted with `--resume <their session>`, so the conversations carry over.
- running: lanes ltc, zec, usdc, xmr (wave 1a–1d, Sonnet) and **multichain** (wave 1e, Opus;
  `lanes/multichain.md`, `check-multichain.sh`), all on hp2.
- BTC reverse live chaos failed at 10:13: the driver defaulted to **signet**, so the maker's BTC
  wallet looked empty, and an empty coin list slipped past the funds check and panicked
  (`tx.rs` subtract overflow). Fixed in 7c867aa (empty wallet → `InsufficientFunds`; driver
  default testnet3). Swap 29378dca (taker DIVI locked, maker never funded) resumes with the fixed
  binaries; the maker funds or aborts safely, and the taker DIVI refunds at its timelock if not.
- landed from hp2 lanes: bb992e4 (ltc `LtcBackend`), f8f7e9b (xmr design + DIVI `bare_txid`),
  a865d9c (usdc `Erc20Htlc` + `swap-chain-evm`), d2b2742 (zec `ZecBackend`), f273975
  (multichain engine: DIVI vs any UTXO counter chain). `hp2-land.sh` hardened: refreshes
  `Cargo.lock` only when it had to drop the lane's copy, offline (1cabf5e); refuses a lane with
  unmerged files (f345af6). The first zec landing was refused for a `UU Cargo.lock` + stray files.
- a865d9c broke CI (unused `FromStr` import only the `live`-feature test uses); fixed on main.
- hp2 disk hit 100% at ~12:40 (other projects' remote-cargo targets + sccache; lanes ~23 GB). I
  removed my stale remote-cargo targets and the idle xmr/usdc lane targets; lanes build with
  `CARGO_INCREMENTAL=0`. The lane watcher also flags the disk at ≥ 97%.
- USDC engine fit: **Option A** (`UsdcBackend: ChainBackend` inside `swap-chain-evm`, no engine
  contract change), per `usdc-design.md`. XMR continues with build-plan steps 2–4 (mockable).
- wave 2 started: ltc, zec, usdc wire their backends into `divi-swapd`/`divi-swap` with mock e2e.
- 13:11: chaos driver now fails fast when the swap aborts, and a resumed run parks an aborted swap
  and starts over. Swap 29378dca was aborted by the maker ("taker-leg window too short") after
  the long interruption; its 600 DIVI taker lock (local f4140a43) is refunded by the taker after
  the chaos run (the maker never saw the preimage, so the coins are only the taker's). The rerun
  uses `--btc-sats 6000` (180 DIVI per swap) so all four scenarios fit the taker's free DIVI.
- 2026-10-13 status refresh (Mac DNS back): verify-results 137 checked, 0 missing, 1 excluded
  (first run flagged LTC `bea5d5d0…` MISSING; litecoinspace shows it confirmed at 4913450 — transient
  lookup, clean on rerun). dnsdivi maker 4e0ac26 healthz ok. Landed c84f65f (multichain: live
  DIVI-XMR backends, not run live; maker not redeployed with XMR). LTC + ZEC live both directions
  PASS on 4e0ac26; USDC parked on test ETH for gas; XMR live awaits Bert's explicit go. hp2 disk 95%
  (other sessions' ~/build, ~/remote-cargo; not touched).
