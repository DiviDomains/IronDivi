# Orchestrator status

- **Wave/step:** Wave 0 0.3 refund wait (background) + 0.4 parked on sBTC; Wave 1 lanes engine/daemon/deploy running
- **Done:** 0.1 scaffold `5a753ab`; 0.2 contract; 0.6 four keys in 1Password; 0.5 maker-divi funded
  (`ac3c1522…d72a`); 0.3(a) DIVI claim `d5f9d1db…705c`; 0.3 early refund rejected `64: non-final`;
  0.7 briefs + checks (all proven failing); progress commit `cb1ce37`.
- **Running:**
  - 0.3(b) refund wait, pair 1 (`/tmp/…/scratchpad/divi-proof.json`); CLTV-violation probe, pair 2 (`divi-proof2.json`)
  - lane engine — worktree `~/code/IronDivi-swap-engine`, pane `3388d9f9-264f-4c41-ae16-bf7e8cc95f86`
  - lane daemon — worktree `~/code/IronDivi-swap-daemon`, pane `c7a9bd41-c736-4585-acaf-b06c69c62732`
  - lane deploy — worktree `~/code/IronDivi-swap-deploy`, pane `da878686-98f0-4448-bd17-dcf195f4ed13`
- **Broken:** none
- **Parked:** PARKED.md #1 signet sBTC (faucet CAPTCHA) — blocks 0.4 and btc lane live test only
- **Next:** on 0.3 pass → launch lanes divi and btc; Wave 1 gate.
- Avada: tab "Swap POC" (0:17), orchestrator pane `pane-096e7cf3-fa59-4aa4-9f3d-4b1204f386c3`; `new-pane` needs `--window 0`.
