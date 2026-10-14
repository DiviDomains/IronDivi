# XMR ↔ DIVI maker runbook (divi-swapd on dnsdivi)

Plan item B3 in `xmr-mainnet-plan.md`. For whoever is on call for the maker: what the daemon does
by itself, what each alert means, and the few things a human must ever do. Stagenet today; the
same steps apply to mainnet with the mainnet host and its own keys (B4).

## What the daemon does by itself

`divi-swapd` runs every XMR swap through `XmrMaker::tick` (every poll, every swap); each step is
idempotent and persisted before its side effect, so a restart resumes where it stopped.

```text
accepted → locked → xmr_reported → redeem_offered → redeemed → swept → done      (happy path)
locked … redeem_offered, past t_cancel → cancelled → refunded → done            (refund)
                                         cancelled → punished                    (maker missed t_punish: the taker took the DIVI)
accepted → aborted   (taker never sent her signatures within sigs_wait; nothing broadcast)
```

Roles: the maker locks **DIVI**, the taker locks **XMR**. Times on the testnet profile
(`XmrConfig::testnet()`): `t_cancel` = lock + 6 h, `t_punish` = `t_cancel` + 3 h, redeem offered
only while more than 1 h remains before `t_cancel`, `sigs_wait` 30 min.

**The one deadline that costs the maker money:** once a swap is `cancelled`, the maker must get
`Tx_refund` confirmed before `t_punish`. After that the taker can broadcast `Tx_punish` and take
the DIVI. The daemon does this on its own; a human only matters if the daemon or the DIVI node is
down across that window. Every other failure is a delay, not a loss.

## Look at things

```sh
ssh dnsdivi 'curl -s 127.0.0.1:18480/healthz | jq .'            # backends, wallet scan state
ssh dnsdivi 'curl -s 127.0.0.1:18480/xmr/swaps | jq ".[] | {id,state,last_error}"'
ssh dnsdivi 'curl -s 127.0.0.1:18480/xmr/swaps/<id> | jq .'     # one swap, with its txids, t_cancel, t_punish
# every cancelled swap and how long until its t_punish (seconds; DIVI median time past lags wall
# time by up to ~30 min, so treat anything under an hour as urgent):
ssh dnsdivi 'curl -s 127.0.0.1:18480/xmr/swaps | jq -r ".[] | select(.state==\"cancelled\") | [.id, .t_punish - now] | @tsv"'
ssh dnsdivi sudo journalctl -u divi-swapd --since -1h | grep 'xmr maker'   # state transitions
ssh dnsdivi sudo /usr/local/bin/swap-watch.sh dry-run           # what the alert job sees now (reads /etc/swap-watch.env)
```

## Alerts (swap-watch, Telegram, every 5 min)

Each alert repeats every 6 h while the same problems persist. One "healthy again" message follows
when they clear.

| Alert | Meaning | Do |
|---|---|---|
| `divi-swapd is failed/inactive` | the daemon is down; **no swap advances**, including refunds | `journalctl -u divi-swapd -n 100`; fix the cause; `systemctl restart divi-swapd`. If the new binary is the cause, use [Rollback](#rollback). Check every `cancelled` swap's `t_punish` first and set the priority from that. |
| `/healthz not ok` | daemon up but not answering | as above |
| `wallet scan still scanning N min after start` | the DIVI wallet rescan after a restart is slow; takers get 503 until it finishes | wait; if it stays stuck past an hour, check the DIVI node (next row) |
| `divi backend: …` / `btc backend: …` | the daemon cannot reach a chain node | check the node behind `[divi].rpc_url` / `[btc]` in `/etc/divi-swapd/divi-swapd.toml` (stagenet: `services.divi.domains/api/testnet/rpc/`, a remote endpoint); the daemon retries on its own |
| `monerod-stagenet is …` / `monerod RPC not answering` | local monerod down | `systemctl restart monerod-stagenet`; `journalctl -u monerod-stagenet`. Disk full is the usual cause (`df -h /var/lib/monero-stagenet`). XMR lock checks and sweeps stall; DIVI refunds do not need monerod. Until A5's switch-over the maker uses the public stagenet node (`[xmr].monerod_url`) and this check is off (`MONEROD_URL=` in `/etc/swap-watch.env`). |
| `monerod not synchronized: height X of Y` | monerod fell behind (or is resyncing) | it catches up by itself; if the gap grows, check peers (`get_info` → `outgoing_connections_count`) |
| `xmr swap <id> stuck in accepted` | taker took a quote and never sent signatures | nothing: the maker aborts it after `sigs_wait`. If it stays, the daemon is not ticking: check the logs. |
| `xmr swap <id> stuck in <state> for 12 h` | longer than any healthy path (`t_cancel` + `t_punish` is 9 h) | read the swap and the log; see the table below |
| `xmr swap <id> (<state>): <error>` | the same `last_error` on two runs in a row | read it; most are a node timeout that is retried. Persistent ones: see below |

### A stuck swap, by state

| State | Waiting for | If it does not move |
|---|---|---|
| `locked` | `Tx_lock` to confirm, then the taker's XMR lock report | the taker may never lock XMR; past `t_cancel` the maker cancels by itself. Nothing to do. |
| `xmr_reported` | the taker's XMR lock to reach `xmr_confirmations` (10) | check that `xmr_txid` exists on a stagenet explorer and that monerod is synced; past `t_cancel` the maker cancels |
| `redeem_offered` | the taker to redeem DIVI with the encrypted signature | past `t_cancel` the maker cancels. If she redeemed late, the maker still recovers her key from the redeem and sweeps. |
| `redeemed` | the XMR sweep to the maker wallet (`sweep_address`) | monerod or the sweep is failing: read `last_error`. The XMR is the maker's (it holds the full key); nothing expires, so a slow sweep loses nothing. |
| `swept` | the sweep tx to get 1 confirmation | monerod sync |
| `cancelled` | `Tx_refund` to confirm | **urgent if `t_punish` is near.** The daemon rebroadcasts on every tick. If it is erroring, fix the DIVI node or the fee first. |
| `refunded` | `Tx_refund` to confirm | DIVI node; the same bytes are rebroadcast |

`punished` is terminal: the taker took the DIVI after `t_punish`. Record it with the txids
(`/xmr/swaps/<id>`) in `status/xmr.md` and find out why the refund did not land in time.

## Restart / redeploy

Never restart over an in-flight swap without a reason. `redeploy-maker.sh` refuses while any
hashlock (`/swaps`) or XMR (`/xmr/swaps`) swap is non-terminal (B1b):

```sh
ssh -N -L 18482:127.0.0.1:18480 dnsdivi &        # tunnel for the in-flight gate
tools/swap-poc/redeploy-maker.sh --check-only     # gate only
tools/swap-poc/redeploy-maker.sh --binary <path>  # ship a prebuilt linux binary
```

A restart mid-swap is safe by design (persisted state, idempotent steps). It costs time: the DIVI
wallet rescan. Keep restarts well away from a `cancelled` swap's `t_punish`.

## Rollback

`tools/swap-poc/rollback-maker.sh` (B1) restores the binary, `/etc/divi-swapd/divi-swapd.toml`
and the systemd unit together, then restarts and checks `/healthz`. It applies the same in-flight
gate. Restoring only the binary is not enough: 0.2.6 (`divi-swapd.pre-xmr`) silently ignores
`[xmr]`, so XMR swaps in flight would stop advancing. **Never roll back to a pre-XMR build with
XMR swaps in flight.** The SQLite state in `/var/lib/divi-swapd` is not migrated down.

## monerod

`monerod-stagenet.service`: v0.18.5.3 (signature checked) in `/opt/monero` → `/opt/monero-v…`,
user `monero`, pruned, data in `/var/lib/monero-stagenet`, restricted RPC on `127.0.0.1:38089`, no
inbound peers. Upgrade: download and check the new release's hashes.txt signature (binaryFate
key `81AC 591F E9C4 B65C 5806 AFC3 F0AF 4D46 2A0B DF92`), unpack next to the old one, move the
symlink, restart. Move it back to roll back.

## Keys

| Key | Where | Rotate |
|---|---|---|
| `maker-divi-xmr` (DIVI key that funds `Tx_lock`, signs refunds) | 1Password → `/etc/divi-swapd/credentials/` via `deploy.sh provision-secrets` | only with **no** XMR swap in flight: in-flight swaps' refund and punish paths are bound to the old key. Fund the new key's address and update `divi_fund_txids`. |
| maker XMR wallet (sweep target) | 1Password item "IronDivi Swap POC - maker-xmr-wallet-stagenet" (spend + view key, address) | generate a new one (`cargo run -p swap-chain-xmr --example xmr_keygen` on the build cluster, never the Mac; output piped straight into `op item create`, never to a file or the terminal); change `[xmr].sweep_address`; restart with nothing in `redeemed`. Sweep the old wallet's funds with `monero-wallet-cli --generate-from-keys`. |
| `maker-xmr-wallet-rpc` | 1Password → credentials | `provision-secrets`, restart |

Never put a key on the command line or in a file under git. Mainnet keys are separate items on a
separate host (B4).
