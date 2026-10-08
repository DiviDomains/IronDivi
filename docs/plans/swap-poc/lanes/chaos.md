# Lane chaos — crash and outage recovery on real testnets (Wave 2)

Read `_common.md` first. You own `tools/swap-poc/chaos/` and `docs/plans/swap-poc/status/chaos.md`.
Use `tools/swap-poc/e2e.sh` (lane e2e-local) or your own driver; coordinate through status files.
Do **not** change system networking (no pf/firewall/hosts edits): simulate outages with a local
fault-injecting HTTP proxy you write under `tools/swap-poc/chaos/` and point the daemon's
`rpc_url` / `esplora_url` at it.

**Runs** (each on a real DIVI-testnet + BTC-signet swap, ≤ 20,000 sats):
1. For every maker state `accepted, taker_lock_seen, taker_lock_confirmed, maker_locked,
   maker_lock_confirmed, taker_claimed, maker_claimed, maker_refundable, maker_refunded`:
   `kill -9` `divi-swapd` while the swap is in that state (watch `GET /swaps/:id` or the DB),
   restart it, and let the swap finish (`done`, claimed or refunded). `maker_refundable` /
   `maker_refunded` need a swap where the taker never claims (short timeouts allowed, see e2e-local).
   Several states can be covered by one swap with several kills.
2. DIVI RPC outage mid-swap (proxy returns connection refused / 502 for ≥ 5 min), then recovery.
3. Esplora 429 storm mid-swap (proxy returns 429 with `Retry-After` for ≥ 2 min), then recovery.

**Acceptance** (`tools/swap-poc/check-chaos.sh`): status file has, per run, a line
`- chaos_<state|rpc_outage|esplora_429>: <swap_id> <final_txid>` where the final txid (the
maker's BTC claim or DIVI refund) is confirmed, and no `- stuck:` lines.
