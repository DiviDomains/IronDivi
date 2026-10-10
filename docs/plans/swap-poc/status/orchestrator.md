# Orchestrator status

- **Wave/step:** Wave 3 — live proofs on BTC testnet3 (DECISIONS #8; Bert funded tb1qa826… with 197,253 sats, tx f5ee5dc8…).
- **Done:** Wave 0 (0.3 GO `c00ff9c`); Wave 1 gate green on main (CI green); lanes engine, daemon (live wiring `031504f`),
  deploy, divi done (divi unparked `358992d`; daemon Cargo.lock `b74079e` on swap/daemon, same entries already on main); e2e-local tooling `e4552fe`; chaos tooling done (mock-proven).
  Wave 3: deploy fix `8640cc0` (rust 1.98.1 pinned, nginx opt-in — DECISIONS #7); maker keys provisioned to
  dnsdivi `/etc/divi-swapd/credentials/{maker-divi,maker-btc}` root:root 0400 (op → ssh stdin).
  Secret resolution moved to the secret proxy (`secret get`, `7038c70`); one secret-broker Touch ID serves every lane.
  2026-10-10 00:38 UTC: dnsdivi redeployed (v0.2.5) and switched to testnet3 (`/etc/divi-swapd/divi-swapd.toml`,
  signet copy at `.signet.bak`); healthz ok, divi tip 342838, btc tip 5157803, maker balance 24,799.91965 tDIVI,
  swaps.db empty. deploy.sh health-check wait raised to 20 min (wallet scan from 339800 takes ~14 min).
  00:55 UTC: redeployed with bind-first (`a5b7a96`): `divi-swapd up` 1 s after start, healthz 200 with
  `divi_scan` scanning → done in 9 s (resumed from saved cursor 342820); network testnet. No probe outage.
- **Running:**
  - divi-swapd on dnsdivi (systemd, testnet3, healthy, bind-first)
  - secret-broker pane `ae8a03fc…` (tab 0:7) — keep it open while live runs need keys
  - btc lane: live_fund_claim_refund on testnet3; funding `9a5d15905f8295f472c5d5233a0970ba34adaffe823b0d415df79f1498cb1fae` confirmed
  - e2e-local lane: mock check, then happy → case-d → case-c (brief `~/.local/state/iron-divi-swap-poc/briefs/e2e-local.md`)
  - chaos lane: mock check, then waits for "GO chaos" (brief `…/briefs/chaos.md`)
- **Broken:** none. CI green on main through `7038c70`.
- **Parked:** none (PARKED #2 resolved 2026-10-10).
- **Compactions:** orchestrator 3; engine 1
- **Next (serialize taker funding — one funding UTXO chain):**
  1. e2e-local happy → case-d → case-c (each after the previous BTC lock confirms)
  2. chaos live; 3. e2e happy + case C vs deployed maker via `ssh -N -L 18480:127.0.0.1:18480 dnsdivi`
  4. sweep taker + maker BTC leftovers to tb1qerzrlxcfu24davlur5sqmgzzgsal6wusda40er (testnet3); RESULTS.md; final report
- Avada: lanes in tabs 0:6 "Divi Swap 1" (orchestrator, engine, daemon, deploy) and 0:7 "Divi Swap 2" (btc, divi, e2e-local, chaos, secret-broker).
  Long briefs go in a file; a long `ctl submit` gets truncated.
