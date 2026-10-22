# divi-swapd deployment (dnsdivi, testnet POC)

Runs the maker daemon as a hardened systemd service behind the existing nginx. The plan is
`docs/plans/atomic-swap-poc.md` §5 Wave 3. SSH uses only the `dnsdivi` host alias.

| File | Installed at |
|---|---|
| `divi-swapd.service` | `/etc/systemd/system/` |
| `divi-swapd.toml.example` | `/etc/divi-swapd/divi-swapd.toml` (first deploy only; never overwritten) |
| `nginx-swap.conf` | `/etc/nginx/snippets/divi-swapd.conf` — include it once in the dnsdivi `server {}` block |
| `logrotate-divi-swapd` | `/etc/logrotate.d/divi-swapd` |

Service listens on `127.0.0.1:18480`; nginx exposes it at `/swap/`. State (SQLite) is in
`/var/lib/divi-swapd` (0700). The binary expects `--config <toml>` (daemon lane's CLI; adjust the
unit's `ExecStart` if it differs).

## Deploy

```sh
deploy/divi-swapd/deploy.sh --dry-run     # prints every step, runs none
deploy/divi-swapd/deploy.sh provision-secrets   # once, needs 1Password unlocked
deploy/divi-swapd/deploy.sh               # sync source, build ON dnsdivi, install, restart, healthz
```

Build happens on dnsdivi (no cross toolchain; needs rustup for `ubuntu` there). Add the
`include` line to nginx once, then `sudo nginx -t && sudo systemctl reload nginx`.

`[zec].network` defaults to `testnet`; switching it to `mainnet` also needs `allow_mainnet = true`
and a matching top-level `profile = "mainnet"`, so a mainnet cutover is never a one-line config
edit.
`[btc]` and `[ltc]` follow the same rule: `network = "mainnet"` needs `allow_mainnet = true` and `profile = "mainnet"`,
and with `esplora_url` unset the mainnet endpoints come from the crate defaults.
`[divi].rpc_url` is the DIVI JSON-RPC proxy (unset: the network's public default). The optional `[divi].fallback_rpc_url` (unset by default) adds a second, independent DIVI endpoint, ideally your own node: confirmations, the HTLC output, find-spend and the median time are then read on both, any disagreement is `Transient` (the engine retries later; nothing is decided on a split view), and a broadcast goes to both. It must differ from `rpc_url`. Making it mandatory on mainnet is an operator decision, not enforced.
`profile` (default `testnet`) must agree with every configured coin section (`[btc]`, `[ltc]`, `[zec]`, `[xmr]`, `[usdc]`): a mainnet profile with a test network, a mainnet network without `allow_mainnet`, or a testnet profile with a mainnet network is refused at config load. The taker CLI `divi-swap --profile mainnet` likewise refuses any maker quote whose confirmation depths or timeouts are weaker than the mainnet profile's, before it signs or funds anything.

`[usdc].network` defaults to `sepolia`; the mainnets `ethereum` and `base` likewise need
`allow_mainnet = true` and a matching top-level `profile = "mainnet"`.

## Secrets

Keys never touch disk locally or argv. `provision-secrets` runs `op read` and pipes the value
over ssh stdin into `/etc/divi-swapd/credentials/<name>` (root:root 0400). systemd's
`LoadCredential=` exposes them to the service in `$CREDENTIALS_DIRECTORY`; the config refers to
them as `credential:<name>`.

**Rotate:** change the 1Password item, rerun `deploy.sh provision-secrets`, then
`ssh dnsdivi sudo systemctl restart divi-swapd`. Do not rotate with an in-flight swap: its
HTLC refund key is the old key — let swaps reach `Done` first.

## Operate

```sh
ssh dnsdivi sudo journalctl -u divi-swapd -f
ssh dnsdivi sudo systemctl status divi-swapd
```

Logs go to the journal; cap with `SystemMaxUse=200M` in `/etc/systemd/journald.conf.d/`. The
logrotate file (10 MB, 5 rotations) applies only if the config sets a log file.

### XMR network check

With an `[xmr]` section the daemon asks the configured `monerod` for its `nettype` at start and refuses to start when it disagrees with `[xmr].network` (or reports mainnet without `allow_mainnet`).

### Rate limit behind a reverse proxy

The quote and XMR setup routes are limited to 20 requests a minute per client address; accept
and lock (`POST /swaps`, `POST /swaps/:id/lock`) to 20 a minute in their own bucket; and
`GET /swaps` and `GET /swaps/:id` to 300 a minute in a third, so a taker's status polling cannot
use up its accept/lock budget. `/healthz` and `GET /offers` are unlimited. By default the
address is the socket peer, so behind nginx every client shares the proxy's bucket.
Set `trust_proxy_headers = true` in `divi-swapd.toml` and the limiter keys on the LAST address in
`X-Forwarded-For` (else `X-Real-IP`; an unparseable value falls back to the socket peer). The
shipped `nginx-swap.conf` sets `X-Forwarded-For $remote_addr` (an overwrite, so the header is a
single address nginx chose), and the daemon takes the last entry, which is also what nginx's
`$proxy_add_x_forwarded_for` would have appended: a client-supplied header cannot pick the
bucket either way. Turn it on only behind a proxy you control and with the daemon reachable
only through it: if clients can reach the daemon directly, each can choose its own bucket and
the limit is void. It is off by default and the example config ships it commented out.

## Rollback

`deploy.sh rollback` restores `/usr/local/bin/divi-swapd.prev` and restarts. The DB is not
migrated down; use a prior binary only if its schema matches.

## swap-watch (Telegram alerts)

`swap-watch/swap-watch.sh` runs every 5 minutes (`swap-watch.timer`, oneshot service as root). It reads
hashlock swaps from `GET /swaps` and XMR swaps from the swap database through the installed binary:
`divi-swapd --config /etc/divi-swapd/divi-swapd.toml --xmr-inflight --xmr-watch`, run as `divi-swapd`
(`sudo -n -u`, since the database is 0600). That flag opens the store read-only (no write, no migration,
no pragma), so it cannot block the running daemon. It prints the usual `xmr_configured` and `in_flight`
lines, then `<id> TAB <state> TAB <t_punish or -> TAB <last_error>` for each non-terminal swap
(`cancelled` and `refunded` included; backslash, tab and newline in `last_error` are escaped). If the call fails
the job alerts `XMR swap state unreadable: …` instead of reporting no swaps. Overrides in
`/etc/swap-watch.env`: `SWAPD_BIN`, `SWAPD_CONFIG`, `SWAPD_USER` (empty runs it as the invoking user).

Install order on the maker host: (1) install the new `divi-swapd` binary (`tools/swap-poc/redeploy-maker.sh`);
(2) copy `swap-watch.sh` to `/usr/local/bin/swap-watch.sh`; (3) check with
`sudo /usr/local/bin/swap-watch.sh dry-run`. Installing the script first only gives the `unreadable`
alert, never a silent miss. Test: `tools/swap-poc/test-swap-watch.sh` (stubs, no network).
