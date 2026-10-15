# C1 test 4: punish path on testnet / stagenet

Status: **PASS** (2026-10-15 23:21Z). With the maker silent after the taker's XMR lock, the taker
alone broadcast Tx_cancel (cancel branch, joint key J) after t_cancel and Tx_punish (her key b)
after t_punish, and took the 10 tDIVI. No refund of Tx_cancel:0 exists. Checks below.

Code: C1 as merged at `5dd9c77`, the same tree as `c1-impl` `61ca99a`. Maker binary: the lane-c1
release `divi-swapd` (sha256 prefix `4e06be9f74558c9d`), built on hp2. Taker binary:
`~/.cache/divi-swap-c1-61ca99a`.

## What the test shows

The maker locks DIVI in a C1 Tx_lock, and its cancel branch is keyed by the 2P-ECDSA joint key J.
The taker then locks XMR, and after that the maker goes silent and never refunds. Once t_cancel
passes, the taker library broadcasts Tx_cancel itself (the cancel branch, signed by J). Once
t_punish passes, it broadcasts Tx_punish (the punish branch of the Tx_cancel output, signed by
the taker key b) and takes the DIVI. The taker's XMR stays locked for good. That is the price of
the punish path by design.

## Setup

The shared maker `divi-swapd` on dnsdivi was **not touched**. A second, private maker ran on hp2:

- State dir `~/.local/state/c1-punish/` (0700). Fresh keys `creds/{maker-divi,maker-btc,maker-divi-xmr}`
  are `openssl rand -hex 32` in 0600 files, passed as `credential:<name>` through
  `CREDENTIALS_DIRECTORY`. The dnsdivi maker's keys and wallets were not reused.
- Listen `127.0.0.1:18483`, tunnelled to the Mac at the same port. Own db
  `data/swaps.db`.

Config (`divi-swapd.toml`, no secrets):

```toml
profile = "testnet"
listen = "127.0.0.1:18483"
db_path = ".../data/swaps.db"
tick_secs = 10

[divi]
rpc_url = "https://services.divi.domains/api/testnet/rpc/"
key = "credential:maker-divi"
wallet_path = ".../data/divi-wallet.json"
scan_from_height = 350880

[btc]            # required by live_backends even for an XMR-only offer; unused here
network = "testnet"
esplora_url = "https://mempool.space/testnet/api"
fallback_esplora_url = "https://blockstream.info/testnet/api"
key = "credential:maker-btc"

[xmr]
network = "stagenet"
monerod_url = "http://node.monerodevs.org:38089"
wallet_rpc_url = "http://127.0.0.1:1"   # deliberately dead: the punish path never sweeps
sweep_address = "<dnsdivi maker stagenet address; unused on this path>"
divi_key = "credential:maker-divi-xmr"
divi_wallet_path = ".../data/divi-xmr-wallet.json"
divi_fund_txids = ["1fbb8ee4a9550183a225531a7c198e67ef87f57b489066bc4aaed230ebea7921"]
lookback_blocks = 720

[[offers]]
id = "divi-xmr-stagenet"
direction = "taker_pays_btc"
counter_chain = "xmr"
enabled = true
divi_sats_per_btc = 500000000000
min_btc_sats = 100000
max_btc_sats = 400000
```

Funding: 50 tDIVI from the dnsdivi node5 testnet wallet went to the xmr-engine address
`yDZH567E8ENqXM9HNGcp1Z3ZVsfVXyzwjS`, txid
`1fbb8ee4a9550183a225531a7c198e67ef87f57b489066bc4aaed230ebea7921`.

The taker ran `tools/swap-poc/xmr-soak.sh --scenario lock-only --count 1 --maker
http://127.0.0.1:18483`, using the soak's usual taker keys, wallet-rpc and sweep address. Then
`tools/swap-poc/c1-punish-watch.sh` stopped the private maker as soon as its view left `locked`
(it fired at `xmr_reported`). After that, `tools/swap-poc/c1-punish-step.sh` ran the taker's
`claim` every 5 min with the maker unreachable.

## Timelocks

There is no way to set the timelocks. `live::profile_for("testnet")` returns `XmrConfig::testnet()`:
t_cancel 6 h after setup, punish 3 h, late 3 h, redeem margin 1 h, 3 DIVI and 10 XMR
confirmations, and a fee of 100000 sats. The lowest values that `validate` / taker setup would
accept are about 12240 s for cancel and 3600 s each for punish and late. Getting there would need
a code change, so this run used the defaults.

| | unix | UTC |
|---|---|---|
| t_cancel | 1792094796 | 2026-10-15T20:06:36Z |
| t_punish | 1792105596 | 2026-10-15T23:06:36Z |
| t_late | 1792116396 | 2026-10-16T02:06:36Z |

All three are checked against median-time-past (MTP), which runs about 5 min behind wall time.

## Swap

- Maker swap id `06bcf298-3922-4149-8df0-9752bc457b36`. Taker local id
  `3df0e8ee-753b-4ea3-9598-8096533c4b9c`.
- 200000 counter sats (0.002 XMR) for 10 tDIVI (`divi_amount` 1000000000).

| step | txid | height | time (UTC) |
|---|---|---|---|
| DIVI Tx_lock | `5631d134197999dcae4fea7498fec40f1d0827771c293b8625a9f6f886f257b4` | 350903 | 2026-10-15T14:15:06Z |
| XMR lock (stagenet) | `fd812260498226caa597a97f6f7d9ba617e7607c1e0cd8d4f0db7bdc7bd7c891` | in pool at 14:20Z (stagenet tip 2229875) | reported 14:19:29Z |
| Tx_cancel | `47cb5c867b902660a05640c160b84e60f7e4c5cd1f31c75fd0b9e302c2656792` | 351277 | block 2026-10-15T20:19:05Z |
| Tx_punish | `42e6fc493f6853b924b83de4fffa64cacb69880c7abbe9d194acef90d735909d` | 351450 | block 2026-10-15T23:16:59Z |

The XMR lock confirmed at stagenet height 2229875. Taker step states: `Cancelled` from 20:39Z,
`Punishing` 23:16:33Z, `Done` 23:21:33Z (`$R/step-states.log`).

Tx_lock output 0 is 10.001 tDIVI to the P2SH `8ubJJw89YMPakyMWsoZ5i2pBayc26b8KAx`. Output 1 is
change back to the maker.

Maker log, in order: `Accepted → Locked` 14:12:13Z, then `Locked → XmrReported` 14:19:29Z. The
watcher stopped the maker at 14:19:33Z. Its process is gone, and it was not restarted.

## Verification

All four checks hold (DIVI testnet node5, tip 351457 at 23:30Z; Tx_cancel 181 conf, Tx_punish 8):

1. Tx_cancel `vin[0]` = `5631d134…:0`; scriptSig `<σ (71 B)> 2 <redeem (174 B)>`. `decodescript`
   of that redeem gives p2sh `8ubJJw89YMPakyMWsoZ5i2pBayc26b8KAx`, Tx_lock:0's address. Selector 2
   is the cancel branch: `<t_cancel 1792094796> OP_CLTV OP_DROP <J> OP_CHECKSIG`, with
   `J = 03d088f8…dcea`, the taker db's `joint_pubkey`, distinct from `a = 021ba4fc…e60e` and
   `b = 0279c008…94fe`. The branch has a single key, so the block that mined it proves the
   signature verifies under J. nLockTime 1792094796 = t_cancel.
2. Tx_punish `vin[0]` = `47cb5c86…:0`; scriptSig `<sig_b (72 B)> 0 <cancel_redeem (116 B)>`.
   The cancel redeem hashes to `8kDTp5ZQXb6pWku8QuB4MQgMA5KvpuPUyh`, Tx_cancel:0's address; selector
   0 takes `<t_punish 1792105596> OP_CLTV OP_DROP <b> OP_CHECKSIG`. nLockTime = t_punish. Its one
   output, 9.999 tDIVI, pays `xy2MorbDhp35NxBHytHjv3LQo7fvHE4y3b` = script
   `76a914166a1461…5e9888ac`, the soak taker's payout script (the same as every happy swap's
   Tx_redeem).
3. `gettxout 47cb5c86… 0` is null: Tx_cancel:0 is spent, by Tx_punish. No refund exists.
4. XMR lock `fd812260…` confirmed at stagenet height 2229875; it stays locked for good (the price
   of the punish path).

Caveats: maker `61ca99a` (`4e06be9f…`) and taker `61ca99a`, not the later `a77ec9d` / `1841a12`
builds (the changes since touch only the broadcast order and monerod error handling, not the cancel or
punish path). The taker logged "maker unreachable" every step from 20:59Z on, as intended. The
Claude Code session's waiter was stopped once for low memory around 18:10Z; the stepper itself
(pid 32372) ran throughout.

## Resume and verify (after about 23:15Z)

The stepper runs detached on the Mac: `nohup .../c1-punish-step.sh`, pid in `$R/step.pid`, run
dir `$R = ~/.local/state/iron-divi-swap-poc/xmr-soak/c1-punish-20261015T140704Z`. It appends
one line every 5 min to `$R/step-states.log`. It exits after `taker Done` (in `$R/step.out`)
or at the 12 h cap, about 02:20Z on 10-16. Because of MTP lag, expect Tx_cancel around 20:12Z
and Tx_punish around 23:12Z. Both txids are in `$R/swap-1/step.log` and the taker db.

Conditions that must hold:
- **Do not restart the private hp2 maker** until Tx_punish has at least 1 confirmation. A
  restarted maker could refund Tx_cancel:0 through the 2-of-2 branch, and the test would fail.
- `secret-broker serve` must stay up, because every `claim` resolves the taker's op:// refs.
  The cache lasts until about 13:48Z on 10-16.
- node.monerodevs.org drops requests now and then. The stepper ignores a failed step and
  retries. If it exits without `taker Done`, rerunning it is safe, because the taker db and
  both locks persist.

Checks (DIVI testnet RPC `getrawtransaction <txid> 1`):
1. Tx_cancel `vin[0]` is `5631d134…:0`. Its scriptSig asm is `<sig> 2 <redeem>`, and
   hash160(redeem) is the P2SH of Tx_lock:0 (`8ubJJw89YMPakyMWsoZ5i2pBayc26b8KAx`). The
   signature verifies under J, not under a or b.
2. Tx_punish `vin[0]` is `<Tx_cancel>:0`. Its scriptSig asm is `<sig_b> 0 <cancel_redeem>`,
   and its output pays the taker's DIVI address.
3. Tx_cancel:0 is spent exactly once, by Tx_punish. No refund exists.
4. The XMR lock `fd812260…` is confirmed. Record its height.

## Reproduce

1. Fresh credential files and the config above on a host with the `divi-swapd` build. Start it
   with `CREDENTIALS_DIRECTORY=... setsid -f ./divi-swapd --config divi-swapd.toml`, then tunnel
   its port to the Mac.
2. Fund the `[xmr] divi_key` address from a testnet wallet, and list that txid in `divi_fund_txids`.
3. On the Mac, with `secret-broker serve` and the 38088 wallet-rpc tunnel up:
   `tools/swap-poc/c1-punish-watch.sh <run-dir> &`, then
   `tools/swap-poc/xmr-soak.sh --taker-bin <divi-swap> --count 1 --parallel 1 --scenario lock-only --maker http://127.0.0.1:18483 --out <run-dir>`.
4. `tools/swap-poc/c1-punish-step.sh <divi-swap> <run-dir>` until it prints `taker Done`.
