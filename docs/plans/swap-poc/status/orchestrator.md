# Orchestrator status

- **Wave/step:** Wave 1: engine PASS, deploy PASS, daemon PASS (`5ff4710`; now wiring live backends), btc unit-done (live parked on sBTC), divi running. Early gate on main green (fmt/clippy/test). Needs landed `3d65648`.
- **Done:** 0.1 scaffold `5a753ab`; 0.2 contract; 0.6 four keys in 1Password; 0.5 maker-divi funded
  (`ac3c1522…d72a`); 0.3(a) DIVI claim `d5f9d1db…705c`; 0.3 early refund rejected `64: non-final`;
  0.7 briefs + checks (all proven failing); 0.3(b) CLTV refund `ac8216e7…c3ae` confirmed — **0.3 GO** (`c00ff9c`).
- **Running:**
  - 0.3(b) refund wait, pair 1 (`/tmp/…/scratchpad/divi-proof.json`); CLTV-violation probe, pair 2 (`divi-proof2.json`)
  - lane engine — worktree `~/code/IronDivi-swap-engine`, pane `3388d9f9-264f-4c41-ae16-bf7e8cc95f86`
  - lane daemon — worktree `~/code/IronDivi-swap-daemon`, pane `c7a9bd41-c736-4585-acaf-b06c69c62732`
  - lane deploy — worktree `~/code/IronDivi-swap-deploy`, pane `da878686-98f0-4448-bd17-dcf195f4ed13`
  - lane btc — worktree `~/code/IronDivi-swap-btc`, pane `e35d61d6-4779-4c41-a937-70d5db976125`
  - lane divi — worktree `~/code/IronDivi-swap-divi`, pane `6f364e5b-4711-4ed3-a986-9d40416372a3` (seed tx `03f9983c…bb1f`)
- **Broken:** none
- **Compactions:** engine 1 (2026-10-07)
- **Parked:** PARKED.md #1 signet sBTC (faucet CAPTCHA) — blocks 0.4 and btc lane live test only
- **Next:** watch lanes (watcher script in scratchpad); restart engine if it compacts twice; Wave 1 gate.
- Avada: tab "Swap POC" (0:17), orchestrator pane `pane-096e7cf3-fa59-4aa4-9f3d-4b1204f386c3`; `new-pane` needs `--window 0`.
