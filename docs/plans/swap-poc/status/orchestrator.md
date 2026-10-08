# Orchestrator status

- **Wave/step:** Wave 3 deploy in progress (`deploy.sh deploy` running; release build on dnsdivi). Wave 2 live runs wait on sBTC.
- **Done:** Wave 0 (0.3 GO `c00ff9c`); Wave 1 gate green on main (CI green); lanes engine, daemon (live wiring `031504f`),
  deploy, divi done; e2e-local tooling `e4552fe`; chaos tooling done (mock-proven).
  Wave 3: deploy fix `8640cc0` (rust 1.98.1 pinned, nginx opt-in — DECISIONS #7); maker keys provisioned to
  dnsdivi `/etc/divi-swapd/credentials/{maker-divi,maker-btc}` root:root 0400 (op → ssh stdin).
- **Running:**
  - deploy to dnsdivi (log `scratchpad/deploy.log`)
  - sBTC funding watcher on `tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg`
  - lanes btc `e35d61d6…`, e2e-local `f4d4cac9…`, chaos `134f5516…`: parked blocked-on-human (sBTC)
  - e2e-local + chaos panes sit in Bert's tab 0:11 "deconstruct" (no move verb; closing needs Bert)
- **Broken:** none
- **Parked:** PARKED.md #1 signet sBTC (faucet CAPTCHA) — blocks 0.4, btc live, e2e happy/C/D, chaos live, Wave 3 e2e
- **Compactions:** orchestrator 1; engine 1
- **Next:** healthz on dnsdivi → RESULTS; on funding: 0.4, btc live, e2e-local happy→case-c→case-d, chaos live; then e2e vs deployed maker via tunnel.
- Avada: tab "Swap POC" (0:17); `new-pane` needs `--window 0` and focus-tab first.
