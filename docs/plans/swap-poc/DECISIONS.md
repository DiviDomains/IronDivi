# Decisions taken by the orchestrator (headless — Bert can redirect any of these)

| # | Date | Decision | Why | Alternatives |
|---|---|---|---|---|
| 1 | 2026-10-07 | Testnet DIVI comes from the dnsdivi testnet node wallets (`/opt/divi-testnet/node5`, ~715k tDIVI) via `divi-cli -conf=… sendtoaddress` over SSH. | Brief's default source (1); `getbalance` showed ~3.4M tDIVI across node1–5. | vps1 faucet `:19150` (tailnet down); mock only. |
| 2 | 2026-10-07 | Engine keys live in 1Password vault `global_secret_store`, items `IronDivi Swap POC - <role>-<chain>` (roles maker/taker, chains divi/btc). | `secret-management.md` §3 default vault. | Dedicated vault. |
| 3 | 2026-10-07 | `ChainBackend` splits build from broadcast (`build_funding/build_claim/build_refund` → `SignedTx`, then `broadcast`), adds `pubkey()` and `htlc_output()`. | Write-ahead (§3.2) needs the signed bytes persisted **before** broadcast so a restart rebroadcasts the identical tx instead of re-selecting coins; each side must verify the other's lock. | Plan §3.1 sketch (`fund_htlc` broadcasting internally) — not crash-safe. |
| 4 | 2026-10-07 | Engine API (`api.rs`, and `Maker`/`Taker`/`Store` signatures) frozen in Wave 0 with `todo!()` bodies. | Lets the daemon lane build in parallel with the engine lane, as plan §5 requires. | Daemon waits for engine. |
| 5 | 2026-10-07 | Signet sBTC from `bitcoinfaucet.uo1.net` (proof-of-work captcha, solvable in the browser without a human). | Only public signet faucet found reachable without a human captcha. | Other faucets (unreachable / human captcha); ask Bert. |
| 6 | 2026-10-07 | Lanes get a per-worktree conditional Stop hook (`tools/swap-poc/stop-hook.sh <lane>` in `.claude/settings.local.json`, not committed). | Plan §4 "stop condition is a script", capped at 15 re-prompts. | No hook; orchestrator nudges only. |
