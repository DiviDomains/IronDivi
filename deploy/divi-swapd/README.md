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
`[divi].rpc_url` is the DIVI JSON-RPC proxy (unset: the network's public default). The optional `[divi].fallback_rpc_url` (unset by default) adds a second, independent DIVI endpoint, ideally your own node: confirmations, the HTLC output, find-spend and the median time are then read on both, any disagreement is `Transient` (the engine retries later; nothing is decided on a split view), and a broadcast goes to both. It must differ from `rpc_url`. On a mainnet profile it is required (builder DU): divi-swapd refuses to start without it, and likewise without `[ltc].crosscheck` (`"blockbook"` or `"blockcypher"`) when an `[ltc]` section is present. To run on one source deliberately, set `allow_single_source = true` in that section (`[divi]` or `[ltc]`, each waives only its own section); the daemon then logs a warning at every start. Testnet configs are unchanged.
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
(`POST /swaps`) to 20 a minute in its own bucket; and `GET /swaps` to 300 a minute in a third,
so a taker's status polling cannot use up its accept/lock budget. `/healthz` and `GET /offers`
share a public bucket of 600 a minute.
On the token-gated `:id` routes a request with the swap's right token counts in that swap's own
bucket, so clients sharing an address cannot use up each other's: 20 a minute for
`POST /swaps/:id/lock`, 300 for `GET /swaps/:id`, 300 across the XMR routes
(`GET /xmr/swaps/:id`, `/j`, `/sigs`, `/xmr-lock`). A request for a legacy swap (no token)
counts in a bucket of the same size per swap and address, so one address cannot use up
another's on that id. Any other request (no, wrong or another swap's token, or an unknown id) is
a token miss: an address gets 20 a minute in all, across the hashlock and XMR `:id` routes
together. On the hashlock routes a miss also counts in the address's bucket for that route (the
accept bucket for a lock, the `GET /swaps` bucket for a read); the XMR routes have no
per-address bucket, as the 20 misses always run out first. Past the misses (or that bucket)
every such request from the address is a 429 until the window ends, while the right token still
passes. A wrong token for a real swap id never touches that swap's bucket. Once an
address is locked out, a 429 for a wrong token beside a 200 for the right one tells a guesser
which guess was right; what stops guessing is the token's 256 bits from the OS-seeded CSPRNG, not
the miss limit. The token compare is constant-time (`subtle`). `nginx-swap.conf` carries a commented `limit_req` example. By default the
address is the socket peer, so behind nginx every client shares the proxy's bucket.
Set `trust_proxy_headers = true` in `divi-swapd.toml` and the limiter keys on the LAST address in
`X-Forwarded-For` (else `X-Real-IP`; an unparseable value falls back to the socket peer). The
shipped `nginx-swap.conf` sets `X-Forwarded-For $remote_addr` (an overwrite, so the header is a
single address nginx chose), and the daemon takes the last entry, which is also what nginx's
`$proxy_add_x_forwarded_for` would have appended: a client-supplied header cannot pick the
bucket either way. Turn it on only behind a proxy you control and with the daemon reachable
only through it: if clients can reach the daemon directly, each can choose its own bucket and
the limit is void. It is off by default and the example config ships it commented out.

## Lock-input reservations (BTC, LTC, ZEC)

A BTC, LTC or ZEC maker lock reserves its wallet inputs in the swap database (table `input_reservation`)
from broadcast until the lock confirms; a lock that never confirms keeps them reserved, so those coins
stay out of coin selection. Two operator commands, same style as `--xmr-inflight` (documented under
swap-watch below and in `docs/plans/swap-poc/xmr-runbook.md`), run as the service user (the database is 0600):

```
divi-swapd --config /etc/divi-swapd/divi-swapd.toml --reservations
divi-swapd --config /etc/divi-swapd/divi-swapd.toml --release-reservation <txid> --chain btc [--yes]
```

- `--reservations` is read-only (same open as `--xmr-inflight`: no write, no migration, safe next to the
  running daemon; no node, key or network). It prints `reservations N`, then per input a tab-separated
  `<chain> <input txid>:<vout> <reserving txid> <swap id|unknown> <swap state|unknown>`.
- `--release-reservation` writes. First check, with a node of that chain, that `<txid>` is in no mempool and
  no block: releasing the inputs of a lock that can still confirm lets the next swap double-spend them.
  It refuses unless the swap that broadcast the txid is terminal (a maker swap `Done` or `Aborted`, a taker
  swap `Done`) or no swap row names it, refuses while any other process has the database open (stop `divi-swapd` first; it takes SQLite's
  exclusive lock and waits about 5 seconds), and without `--yes` only prints what it would release and
  exits 2. It never calls a node.
- Taker rows: a taker swap is matched on its taker-leg funding txid, and `--reservations` prints its real
  state. Only a taker swap in `Done` can be released. A taker in `Refunded` is not terminal (its refund is
  still to be broadcast and confirmed) and is refused, as are `Prepared`, `Accepted`, `Locked`,
  `MakerLockConfirmed` and `Claimed`. The `divi-swap` CLI taker does not reserve inputs today; this matters
  for a taker whose backends were given the swap database's reservations.

## Hashlock route credentials

* `POST /swaps` (accept) answers a taker that sent `X-Swap-Token-Support: 1` with the usual swap view plus
  `swap_token`. `GET /swaps/:id` and `POST /swaps/:id/lock` then need that value in `X-Swap-Token`; a missing,
  wrong or another swap's token is the same 404 as an unknown id, and a 429 once the address has used up its
  20 misses a minute (see the rate limits above). The CLI stores the token in its sidecar
  `<db>.sessions.json` and sends it itself.
* An old taker (no support header) gets 426 "upgrade the taker" and no quote is spent, unless the maker sets
  `allow_tokenless_swaps = true`. A swap made before this version has no token and stays open by id.
* `GET /swaps` (the listing) is for the operator: set `operator_token_file` in `divi-swapd.toml` (root:divi-swapd
  0640, one random line, made on the maker host) and send it as `X-Operator-Token`. Unset, the listing is a 404.
  Give `swap-watch` the same file (`OPERATOR_TOKEN_FILE`, default `/etc/divi-swapd/operator.token`) and
  `redeploy-maker.sh` / `rollback-maker.sh` `--operator-token-file PATH` (or env `OPERATOR_TOKEN_FILE`);
  `wave4-smoke.sh` takes the same flag. They pass it to curl on stdin, never on the command line.
* nginx: the default config forwards these headers; if a deployment filters headers, allow `X-Swap-Token`,
  `X-Swap-Token-Support` and `X-Operator-Token`.

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

## Website at /swap/ (testnet, read-only, not installed)

Five static pages (Home, How to swap, How it works and safety, Status, FAQ) in `www/`, one stylesheet and one same-origin script (`www/site/site.css`, `site.js`). No daemon change, no dependencies, no forms. The pages are generated from `gen-site.py` (`python3 gen-site.py www`); edit that, not the HTML. Third-party claims are listed in `FACTS-site.md`.

Layout: the home page is the exact location `= /swap/`; every other site file lives under `location ^~ /swap/site/` (alias `/var/www/divi-swap/site/`). `site` is not a daemon route, so no API path can collide. `/swap` without a slash gets nginx's usual 301 to `/swap/`. Every site response carries a strict CSP (self only), `nosniff` and `Referrer-Policy: no-referrer`; API data is inserted with `textContent` only.

Install adds ONLY the marked block in `site.fragment` to the live snippet `/etc/nginx/snippets/divi-swapd.conf`; the existing `location /swap/ { ... }` proxy block stays byte-identical. Do not fold the repo `nginx-swap.conf` X-Forwarded-For change into this install.

    deploy/divi-swapd/site-install.sh install            # dry run: prints the steps
    deploy/divi-swapd/site-install.sh install --apply    # backup, copy site, append block, nginx -t, reload
    deploy/divi-swapd/site-install.sh rollback --apply   # restore backup, nginx -t, reload, remove site files

Tests: `deploy/divi-swapd/test/run.sh` (node --test on the render functions, then a docker nginx proof against a mock daemon); add `--browser` for the headless-browser run (official Playwright image, 390 and 1280 px, fails on console errors or CSP violations; `SHOTS_DEST=dir` saves PNGs). Local preview: `deploy/divi-swapd/test/preview.sh [ready|scanning|error] [several|empty|hostile]` serves on `127.0.0.1:18490`.
