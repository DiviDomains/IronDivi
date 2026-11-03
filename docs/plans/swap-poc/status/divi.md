# Lane divi status

- done: DiviBackend (rpc.rs, wallet.rs, lib.rs), 8 offline tests incl. wiremock, live_fund_claim_refund passed (fund, claim, refund all confirmed)
- running: nothing
- broken: none
- left: nothing
- live_fund_txid: db0078c0b400125dc5681341b887cd405ffb5e67faf539c9464b341d7c834702
- live_fund_b_txid: b65825714e520eb72cc511c532431a4624f23b028cee8414b6aa7f64f5f4694f
- live_claim_txid: b16e7eb7af3fd20d08741c0759d02d45c6498e472e69251ee8a55e434f4c3f95
- live_refund_txid: 454c1c1eedb9e5ae92c1954813a447d433c6bae455bc1b5ffcc4d8dec4b184b2
- decisions: MTP = median of last 11 block times (proxy returns mediantime null); wallet is local JSON + block scan since proxy has no address/spent index; seeded from 03f9… only, outputs of 6ff5… excluded
- note: stop-hook fmt/clippy/test FAILs were PATH only (cargo lives in /opt/homebrew/opt/rustup/bin)
- last_sha: d3bd5e9

## 2026-10-22 round: divi-mainnet-wiring (builder X, base 9565e95)

- done: the DIVI leg's network is selectable. `[divi].network` (testnet default | mainnet) + `[divi].allow_mainnet` in divi-swapd, `--divi-network` in divi-swap, `swap_chain_divi::{MAINNET_RPC, default_rpc}`; `check_profile_networks` now covers DIVI in both binaries so the profile must agree
- smoke: read-only on hp3 with a throwaway zero-balance key (deleted): CLI `balance` gives `D…` address and 0; daemon up on mainnet, `/swap/healthz` divi.tip 4269956; three config refusals; recorded in mainnet-readiness.md §DIVI
- endpoint: `https://services.divi.domains/api/rpc/` answers `chain = "main"` (verified); `/api/mainnet/rpc/` is a 404
- tests: 274 -> 286 passed, 0 failed (4 packages); fmt and clippy `--all-targets -D warnings` clean
- left: first funded mainnet swap; review of the DIVI mainnet confirmation count (not touched here)

## 2026-10-22 round: divi-confirmations-review (builder AD, base 97bc181)

- done: `docs/plans/swap-poc/divi-confirmations.md` — current counts with file:line (mainnet 10 `crates/divi-swap/src/config.rs:113`, testnet 3 `:123`), RPC evidence, time-to-N table, comparison with the other legs, recommendation (proposal, not applied). `mainnet-readiness.md`: BTC/LTC/ZEC daemon-smoke rows and the DIVI row now give the health path as `<path_prefix>/healthz` (`bin/divi-swapd/src/routes.rs:212,234-237`; default prefix empty `bin/divi-swapd/src/config.rs:447-449`), DIVI section links the review and carries the open item "DIVI mainnet confirmation count: decision pending (see divi-confirmations.md)".
- proof: public mainnet RPC `getblockchaininfo` chain `main` tip 4269973; 1000 blocks sampled: mean 59.5 s, median 40.5 s, p95 209 s, max 625 s, 173 negative gaps (non-monotonic timestamps); `getblockfinality`/`chainlock` not allowed, `getmasternodecount` total 0.
- left: `getchaintips` returns "Backend unavailable" on the public endpoint, so worst reorg/fork length is `could not verify` (needs a node we control or the operator allowing it); no second independent endpoint checked.
- needs: Human decides the mainnet count (proposal: keep 10; option 20).
- decisions: no confirmation, MTP, timeout or margin value changed. The BTC/LTC smokes ran with default config (empty prefix, `/healthz` correct for them); rows now state both forms instead of asserting one.
