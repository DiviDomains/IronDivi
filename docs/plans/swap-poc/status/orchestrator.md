# Orchestrator status

- **Wave/step:** Wave 0 / 0.6 (keys) next
- **Done:** 0.1 scaffold (5 members, deps, Cargo.lock; `cargo build --workspace` green); 0.2 contract
  (`crates/divi-swap`: types, htlc, backend, state, config, error, api + Maker/Taker/Store signatures,
  MockBackend, secrets; 20 tests + doc tests green); 0.7 lane briefs `lanes/*.md`, check scripts
  `tools/swap-poc/check-*.sh` (all five proven failing 2026-10-07), Stop hook `tools/swap-poc/stop-hook.sh`.
  Probes: DIVI RPC proxy live; signet live; SSH dnsdivi OK; dnsdivi testnet wallets ≈ 3.4M tDIVI; `op` OK.
- **Running:** none
- **Broken:** none
- **Parked:** none
- **Next:** 0.6 keygen → 1Password (4 keys); 0.5 fund maker-divi from dnsdivi node5, taker-btc from
  uo1 faucet; 0.3 DIVI CLTV proof (go/no-go); 0.4 signet proof (refund wait ~3 h, background);
  Wave 1 panes in Avada tab "Swap POC" (orchestrator pane `pane-096e7cf3-fa59-4aa4-9f3d-4b1204f386c3`).
