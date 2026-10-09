# Orchestrator status

- **Wave/step:** Wave 3 — live proofs on BTC testnet3 (DECISIONS #8; Bert funded tb1qa826… with 197,253 sats, tx f5ee5dc8…).
- **Done:** Wave 0 (0.3 GO `c00ff9c`); Wave 1 gate green on main (CI green); lanes engine, daemon (live wiring `031504f`),
  deploy, divi done (divi unparked `358992d`; daemon Cargo.lock `b74079e` on swap/daemon, same entries already on main); e2e-local tooling `e4552fe`; chaos tooling done (mock-proven).
  Wave 3: deploy fix `8640cc0` (rust 1.98.1 pinned, nginx opt-in — DECISIONS #7); maker keys provisioned to
  dnsdivi `/etc/divi-swapd/credentials/{maker-divi,maker-btc}` root:root 0400 (op → ssh stdin).
- **Running:**
  - divi-swapd on dnsdivi (systemd, healthy)
  - sBTC funding watcher on `tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg`
  - lanes btc `e35d61d6…`, e2e-local `f4d4cac9…`, chaos `134f5516…`: parked blocked-on-human (sBTC)
  - e2e-local + chaos panes sit in Bert's tab 0:11 "deconstruct" (no move verb; closing needs Bert)
- **Broken:** none
- **Parked:** PARKED #2 — 1Password approval (dnsdivi ssh key + op read taker-btc) unanswered 23:23; redeploy did not reach the host, no tx broadcast. Retry from Next step 1 on Bert's next turn. Return leftovers to tb1qerzrlxcfu24davlur5sqmgzzgsal6wusda40er (testnet3).
- **Compactions:** orchestrator 2 (continuing on Bert's explicit 'continue orchestrating'); engine 1
- **Next (serialize taker funding — one funding UTXO):**
  1. redeploy dnsdivi with `ef4a9c9`, set `[btc] network="testnet"`, esplora mempool.space/testnet + blockstream testnet fallback, restart, healthz
  2. btc lane: rebase main, `SWAP_BTC_NETWORK=testnet` live_fund_claim_refund (also 0.4 evidence)
  3. after its fundings confirm: e2e-local happy → case-d → case-c (SWAP_BTC_NETWORK=testnet)
  4. chaos live; 5. e2e happy + case C vs deployed maker via `ssh -N -L 18480:127.0.0.1:18480 dnsdivi`
  6. sweep taker + maker BTC leftovers to Bert's return address; RESULTS.md; final report
- Avada: tab "Swap POC" (0:17); `new-pane` needs `--window 0` and focus-tab first.
