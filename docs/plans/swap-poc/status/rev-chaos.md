# rev-chaos status — chaos suite, reverse direction (taker sells DIVI for BTC, offer `btc-divi-testnet`)

- running: `SWAP_BTC_NETWORK=testnet driver.py --backend live --scenario all --offer btc-divi-testnet --btc-sats 6000 --port 18700 --workdir ~/.cache/swap-chaos/rev-live`, started 2026-10-11 13:11 EDT, log ~/.local/state/iron-divi-swap-poc/chaos-rev-live.log
- decisions: 6000 sats = 180 tDIVI per swap; ports 18700 + 10i (crash, rpc_outage, esplora_429, refund); driver fails fast when a row turns `aborted` and parks the swap (`5135b4e`)
- blocked-on-human: no

## Parked first attempt
Swap `29378dca…` (taker local id `f4140a43-226b-49b4-981b-982c6d9a5584`) was aborted by the maker:
"taker-leg window too short to lock safely" (the run had been paused long enough that the taker's DIVI
lock left less than the maker's safety window). The maker never locked BTC and never saw the preimage, so
the 600 tDIVI in HTLC `3efc7375a2943da72d7ff78d18489c72560202dd6865a84c27a9ad3bae1b32d3:0` stays the
taker's; it is refunded after locktime 1791748987 (refund txid below once broadcast).
- taker DIVI refund: pending

## crash recovery (kill -9 at each persisted state, restart, resume) — PASS
Swap `e3ae6ba2-644e-4c0b-9e94-3edc65e2b690`, killed at accepted, taker_lock_seen, taker_lock_confirmed,
maker_locked, maker_lock_confirmed, taker_claimed, maker_claimed; every restart resumed; Done.

| leg | txid |
|---|---|
| taker DIVI lock (180 tDIVI) | b33c193a7644db937d5d33ac3c6e37e84554711fcd0c1490685f99313d90412c |
| maker BTC lock (6000 sats) | 7a296b06e88bda8383e97a00b5f4035b1c609a2c81db1bca42133ed61734ecf5 (block 5158292) |
| taker BTC claim | 4bda4c8d2984970d13f6951a4354a16468a42544be88b7fddc385bf4232aa639 |
| maker DIVI claim (preimage from the BTC spend) | 2e2992878de1e7d1edac2d8b08aacf455463dd6987990684b32b78829460a05e |

## rpc_outage (DIVI RPC 502 for 330 s, 13:34:56–13:40:26) — PASS
Swap `034a66db-1b89-4f19-9573-e82e35ae7a38` (taker `50fec34e…`), daemon retried through the outage, Done.

| leg | txid |
|---|---|
| taker DIVI lock | 93b125b848a9987e3917fcb06e4f2aa7e91536a6c9f1f6cc0164c0474da03c6a |
| maker BTC lock | ee12c94f884883987692a661149b6e5fa747b100c0ed75de32de24c399f45b35 |
| taker BTC claim | a533a88de3aeda47149935a4bcf7356f55aa5646b45846410f0687792a7448b0 |
| maker DIVI claim | 123e19083abbc2d119039e2c8d1d3f926ecd92a32e4f773392265098fe5b726f |

## esplora_429 (Esplora 429 + Retry-After, 13:54:20–13:56:50) — PASS
Swap `ef30f5db-d2bb-4096-b0ca-cf2b1429b3a0` (taker `d6c479db…`), daemon backed off through the 429s, Done.

| leg | txid |
|---|---|
| taker DIVI lock | 6c26796830e922f419617db0f72f3995e9b8563d40d8b67123d1bb7094e68caf |
| maker BTC lock | fc08d9e1f538665b8b3ce7b6ff9103e0f38ef5e0590fdab9b04901b08b333f07 |
| taker BTC claim | 9c694eedd8f8a3942122db286d06263b1f7aa9eabbf72240480a46aaa7b21163 |
| maker DIVI claim | e4549c7012953ff3ffb2dfb502f4f5aa20a7b296062b5b661f2c9a4ccf0bc1be |

## refund (maker killed in maker_refundable) — running (needs both timelocks to expire, hours)
