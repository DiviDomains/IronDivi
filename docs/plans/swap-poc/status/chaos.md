# chaos lane status

- done: divi-swapd `[swap]` config overrides (maker/taker timeout, confirmations) so refund runs need not wait hours; validated by SwapConfig::validate
- done: tools/swap-poc/chaos/proxy.py (fault proxy: pass/502/reset/429+Retry-After/hang, runtime switch via POST /__chaos/mode/<m>); tested locally and pass-through against live Esplora
- done: tools/swap-poc/chaos/driver.py (scenarios crash, rpc_outage, esplora_429, refund; SQLite-trigger state hold, kill -9, restart, resume via progress.json)
- done: rebased on main (3030324); mock suite green after rebase (`--backend mock --scenario all`, rc=0)
- done: live suite on DIVI testnet + BTC testnet3 (`SWAP_BTC_NETWORK=testnet driver.py --backend live --scenario all`, 2026-10-09 23:04 → 2026-10-10), log ~/.local/state/iron-divi-swap-poc/chaos-live.log
- running: driver waiting for the refund-scenario taker BTC refund (taker locktime 1791624351, BTC MTP-gated, ~04:30 local)
- broken: nothing
- parked: nothing
- blocked-on-human: no
- decisions: live runs use the testnet profile (maker 3 h / taker 6 h) except refund, which uses `[swap]` maker 3600 / taker 14410 (taker safety margin is 1800 s, so the old maker 1800 could never be accepted); one shared maker DIVI wallet seeded from the case-d wallet with `scan_from_height = 339800`, healthz waits for `divi_scan.state == done`; the next state's hold trigger is installed before each restart so the daemon cannot run past it; taker lock waits for a settled taker UTXO set and retries the write-ahead tx (same bytes) up to 60×; per-backend workdir ~/.cache/swap-chaos/<backend>, ports 186xx (scenario i → 18600+10i, proxies +1/+2) so it never collides with the e2e-local daemon
- last_sha: c2aa738

## crash recovery (kill -9 at each persisted state, restart, resume)

Swap d2051de4-8cf8-4fca-ab7f-e5b4699c27a2, one swap killed at every state in order, each restart resumed and the swap reached `done`:

| state | killed | recovered |
|---|---|---|
| accepted | 23:04:59 | yes |
| taker_lock_seen | 23:05:05 | yes |
| taker_lock_confirmed | yes | yes |
| maker_locked | yes | yes |
| maker_lock_confirmed | yes | yes |
| taker_claimed | yes | yes |
| maker_claimed | 23:08:39 | yes → done |

txids: taker BTC lock 9ba9be1708e9013b80d23a830e3e723b5d6509fbf6795e951b175861222dfcd4, maker DIVI lock e3f3b5fbbcd7ea023eef00ea17fca4d01817aefc5d7c6103bea14f23076ca4d1, maker BTC claim 0b61e19b182f7146a4d65815fd5d2b250674e9ad99d08dbe2623c0a8f4970062 (testnet3 block 5157836)

## fault injection

- rpc_outage: swap 1a91a4a7-7f2d-4277-a1fa-fe0e25dbddee, DIVI RPC returned 502 for 330 s mid-swap, daemon retried and completed. BTC lock b4dc8c81833e6508b3acfe3b4acd1b23f214350c4d523cdf196df4a4bd23dab9, DIVI lock 31a6d79010a643c4a9c71ef99eaf5354f1b496e4c2aa8e2019c41cddad8b1526, maker BTC claim 5474b74fcba7495d20b9f38627e4d0cb7ac95ec7faf6785a787a0a59b7fd275a (block 5157844)
- esplora_429: swap e91c1f27-2973-4bf7-bfbc-98f60011af46, Esplora returned 429 + Retry-After for 150 s, daemon backed off and completed. BTC lock 7b49c70cfbea194bc2e1ac55a1a5ab91a45dd42dcfbcfbbae0a1f10b037f8c09, DIVI lock 35f5f0d3d65ef7176edf98138fc4420b3b5b39b532f48582a4ae5841007786f8, maker BTC claim 4cee5258c334f807c148a55f22c3bec939018ec811b53562869a43df4f3adad4 (block 5157848)

## refund

- swap 4edafa7e-8e8a-4b31-a309-5055c83867df, taker never claims; maker killed -9 in `maker_refundable`, restarted, refunded its DIVI. BTC lock e3a43ab5e12a872d249f64d394f61b10b3ab0e4e2336166af3de28c3bef43596, DIVI lock d65481ea549a6271740ecdb58c5830c253c55ee263b80021e40b1c0f90cf2ab0, maker DIVI refund f3e366f107a521305749b1d43fbd7908e2927e93a351e89452e276df5a68308e
- taker side: taker correctly refused to claim the maker's lock ("locktime too close to claim safely", 1800 s margin); taker BTC refund: pending (BTC timelock)

## results

- chaos_accepted: d2051de4-8cf8-4fca-ab7f-e5b4699c27a2 0b61e19b182f7146a4d65815fd5d2b250674e9ad99d08dbe2623c0a8f4970062
- chaos_taker_lock_seen: d2051de4-8cf8-4fca-ab7f-e5b4699c27a2 0b61e19b182f7146a4d65815fd5d2b250674e9ad99d08dbe2623c0a8f4970062
- chaos_taker_lock_confirmed: d2051de4-8cf8-4fca-ab7f-e5b4699c27a2 0b61e19b182f7146a4d65815fd5d2b250674e9ad99d08dbe2623c0a8f4970062
- chaos_maker_locked: d2051de4-8cf8-4fca-ab7f-e5b4699c27a2 0b61e19b182f7146a4d65815fd5d2b250674e9ad99d08dbe2623c0a8f4970062
- chaos_maker_lock_confirmed: d2051de4-8cf8-4fca-ab7f-e5b4699c27a2 0b61e19b182f7146a4d65815fd5d2b250674e9ad99d08dbe2623c0a8f4970062
- chaos_taker_claimed: d2051de4-8cf8-4fca-ab7f-e5b4699c27a2 0b61e19b182f7146a4d65815fd5d2b250674e9ad99d08dbe2623c0a8f4970062
- chaos_maker_claimed: d2051de4-8cf8-4fca-ab7f-e5b4699c27a2 0b61e19b182f7146a4d65815fd5d2b250674e9ad99d08dbe2623c0a8f4970062
- chaos_maker_refundable: 4edafa7e-8e8a-4b31-a309-5055c83867df f3e366f107a521305749b1d43fbd7908e2927e93a351e89452e276df5a68308e
- chaos_maker_refunded: 4edafa7e-8e8a-4b31-a309-5055c83867df f3e366f107a521305749b1d43fbd7908e2927e93a351e89452e276df5a68308e
- chaos_rpc_outage: 1a91a4a7-7f2d-4277-a1fa-fe0e25dbddee 5474b74fcba7495d20b9f38627e4d0cb7ac95ec7faf6785a787a0a59b7fd275a
- chaos_esplora_429: e91c1f27-2973-4bf7-bfbc-98f60011af46 4cee5258c334f807c148a55f22c3bec939018ec811b53562869a43df4f3adad4
