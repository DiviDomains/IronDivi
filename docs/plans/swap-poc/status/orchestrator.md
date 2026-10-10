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
- **Running:** divi-swapd on dnsdivi (systemd, testnet3, healthy, bind-first). All lanes done.
- **Broken:** first live happy (01:05 UTC) aborted: maker misread taker lock `9b62069b…` as mismatched (esplora backend
  race) and taker failed on Core -27 'outputs already in utxo set'. Fixed in `53c2bb3` (e2e lane); 10k sats in HTLC
  `9b62069b…:0` refundable after locktime 1791620729 — e2e lane owns the refund. dnsdivi still runs pre-`53c2bb3`:
  redeploy before the deployed-maker e2e.
  05:42 UTC: dnsdivi redeployed from `504da62` (includes `53c2bb3`); healthz ok:true after an 83 s catch-up scan.
  Otherwise none. CI green on main through `7038c70`.
- **Parked:** none (PARKED #2 resolved 2026-10-10).
- **Compactions:** orchestrator 4; engine 1
- **DONE 2026-10-10 13:40 UTC:** every plan §1 item proven with confirmed txids (RESULTS.md §1 checklist).
  Deployed happy (maker `39a3401d`) and case C (maker `406b03ad`) Done on dnsdivi; chaos live done; e2e-local done.
  Tunnel closed. Leftover tBTC swept to the faucet return address (`3b4facaa…`, `1d80be5d…`).
  divi-swapd keeps running on dnsdivi (testnet3, no open swaps; maker BTC wallet now empty, DIVI ~24.8k tDIVI).
  Promo-page "Status" line: not applicable, no such page exists (Bert, 2026-10-10). Sweeps confirmed in block 5157959.
- Avada: lanes in tabs 0:6 "Divi Swap 1" (orchestrator, engine, daemon, deploy) and 0:7 "Divi Swap 2" (btc, divi, e2e-local, chaos, secret-broker).
  Long briefs go in a file; a long `ctl submit` gets truncated.
