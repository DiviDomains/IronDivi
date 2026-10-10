# chaos lane status

- done: divi-swapd `[swap]` config overrides (maker/taker timeout, confirmations) so refund runs need not wait hours; validated by SwapConfig::validate
- done: tools/swap-poc/chaos/proxy.py (fault proxy: pass/502/reset/429+Retry-After/hang, runtime switch via POST /__chaos/mode/<m>); tested locally and pass-through against live Esplora
- done: tools/swap-poc/chaos/driver.py (scenarios crash, refund, rpc_outage, esplora_429; SQLite-trigger state hold, kill -9, restart, resume via progress.json); mock smoke green: accept, hold, kill -9, restart, row persisted in `accepted`
- running: nothing
- done: rebased on main (7038c70, testnet3); `SWAP_BTC_NETWORK=testnet driver.py --backend mock --scenario all` passes (mock = mechanics only: hold, kill -9, restart, persistence, 502/429 injection)
- broken: nothing
- left: live runs only, from the repo root: `python3 tools/swap-poc/chaos/driver.py --backend live --scenario all` (build `cargo build -p divi-swapd -p divi-swap-cli` first); paste its `- chaos_<key>: <swap_id> <txid>` lines (also in ~/.cache/swap-chaos/results.txt) into this file
- parked: waiting for orchestrator "GO chaos" (taker testnet3 funds are shared, live runs serialized); then run `SWAP_BTC_NETWORK=testnet python3 tools/swap-poc/chaos/driver.py --backend live --scenario all` in the background
- blocked-on-human: yes
- decisions: maker_refundable runs use maker_timeout 1800 s / taker 18000 s (gap 16200 = required 4.5 h); mock daemon loses its in-memory chains on kill -9, so mock only proves driver mechanics, completion is live-only; states are held with BEFORE INSERT/UPDATE triggers on maker_swaps (upsert fires the INSERT trigger), no engine change
- last_sha: 4b67f9e
