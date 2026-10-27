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
`[zec].crosscheck_url` (unset by default, off; builder EH) names a lightwalletd run by a second operator (`https://host:port`). At startup and before every ZEC claim and refund is built, divi-swapd asks both the primary list and that endpoint for their tips, takes the lower of the two (a one-block lead is not a disagreement), and compares the block hashes there and 6 blocks below. A different hash refuses the start, or holds the claim or refund (`Held`, retried next tick), naming both endpoints. A URL whose host is under the same registrable domain as any primary endpoint (for the defaults, `zec.rocks`) is refused at config load: that is not a second operator. The cost: before a claim or refund the check fails closed, so while the second operator is down, unreachable or more than 6 blocks behind, the claim or refund waits (`Held`) until it answers again; at startup the same condition only logs a warning. The wait is bounded in ZEC chain time (MTP; builder EM): a claim whose preimage is already public (the taker's after its first claim, the maker's of the taker leg) is built on the primary alone once less than the 1800 s ZEC claim margin is left before the counterparty's refund locktime, and a refund 1800 s after its own locktime; a taker's first claim, which would reveal the preimage, is never built on one source: it is declined at that margin and both legs refund. Each deadline action is logged at error level naming both endpoints and set as the swap's `last_error`; after a disagreement the spend built on the primary alone is also sent to the second operator (best effort). On a mainnet profile a second operator is required: divi-swapd refuses to start unless `crosscheck_url` is set, the endpoint list already spans two operators (`lightwalletd_url`/`fallback_lightwalletd_url`, or `SWAP_ZEC_LIGHTWALLETD_EXTRA` with the defaults), or `[zec].allow_single_source = true` waives it (logged at every start). An endpoint list of two operators satisfies the start rule but is only a failover: the tip is compared only with `crosscheck_url` set. Testnet configs are unchanged. The taker CLI's matching flag is `divi-swap --zec-crosscheck-url`.
`[btc]` and `[ltc]` follow the same rule: `network = "mainnet"` needs `allow_mainnet = true` and `profile = "mainnet"`,
and with `esplora_url` unset the mainnet endpoints come from the crate defaults.
`[btc].esplora_url` and `[btc].fallback_esplora_url` are the primary and secondary Esplora; by default the secondary is only a failover, so the reads a claim or refund rests on come from whichever one answered. `[btc].quorum_reads = true` (off by default) reads the spend of an outpoint (`find_spend`), the HTLC output and confirmations from both: a spend, an output or a confirmed transaction that only one reports, two different spenders, or two different output values is `Transient` (the engine retries; nothing is decided on a split view), and of two confirmation counts the lower is used. It needs two different endpoints (both keys set to different URLs, or both unset for the network's two defaults); otherwise the config is refused at load. The cost: quorum mode fails closed, so while either endpoint is down or rate-limited those reads stay `Transient`, and a claim or refund waits until both answer again (it does not fall back to one). Tip, median time, block status, funding and broadcast were primary-then-failover (closed by EI and EO, below). The taker CLI's matching flag is `divi-swap --btc-quorum-reads`.
With `quorum_reads` on, the tip reads ask both endpoints too (builder EI): the tip height and median time are the lower of the two; the tip hash and header are the lower tip once the other endpoint names the same block at that height (a block of lag is not a disagreement; two different blocks at one height are `Transient`); a block's best-chain status must be the same on both. Either endpoint failing makes these reads `Transient` as well. Funding (`spendable`, coin selection) and the broadcast POST: see the next paragraph (EO).

With `quorum_reads` on, every BTC broadcast (lock, claim, refund, fee bumps) is also POSTed to both endpoints at once (builder EO), so a primary that refuses or silently drops a claim cannot keep it off the network. Either endpoint taking it (answering our txid, or reporting it already known) is a broadcast; the other one's answer is logged at WARN with both endpoints named. A 200 that names another txid counts as not taken. Neither taking it returns the node's refusal as before (`Premature` before the locktime, else `Rejected`), its message naming both endpoints and their answers. The funding reads ask both endpoints as well: coin selection and `spendable` use only the coins both list at the same value (a coin only one lists is left out, with a warning, so the maker may report itself short rather than spend a coin that may not exist), and either UTXO read failing is `Transient`; the recommended fee rate is the higher of the two (one endpoint failing uses the other's, never blocking a claim or refund). The cost: a second POST per broadcast and a second UTXO and fee read per funding, claim or refund build.
`[divi].rpc_url` is the DIVI JSON-RPC proxy (unset: the network's public default). The optional `[divi].fallback_rpc_url` (unset by default) adds a second, independent DIVI endpoint, ideally your own node: confirmations, the HTLC output, find-spend and the median time are then read on both, any disagreement is `Transient` (the engine retries later; nothing is decided on a split view), and a broadcast goes to both. It must differ from `rpc_url`. On a mainnet profile it is required (builder DU): divi-swapd refuses to start without it, and likewise without `[ltc].crosscheck` (`"blockbook"` or `"blockcypher"`) when an `[ltc]` section is present. To run on one source deliberately, set `allow_single_source = true` in that section (`[divi]` or `[ltc]`, each waives only its own section); the daemon then logs a warning at every start. Testnet configs are unchanged.
`[ltc].dual_broadcast` (default `false`, opt-in; builder EO) POSTs every LTC broadcast (lock, claim, CPFP child, refund) to `[ltc].esplora_url` and `[ltc].fallback_esplora_url` at once, under the BTC rule above: either endpoint taking it is a broadcast, the other is logged at WARN, a 200 naming another txid is not taken, and neither taking it returns the node's refusal naming both endpoints. It needs both keys set to different URLs (the network's default list has one endpoint, and no public second LTC Esplora is known); otherwise the config is refused at load. The cross-check sources (`[ltc].crosscheck`) are read-only and not used for it. Reads, funding and fee rates are unchanged. The cost: a second POST per broadcast. The taker CLI has no matching flag yet.

`[ltc].crosscheck_before_claim` (default `false`, opt-in; builder ED) repeats the `[ltc].crosscheck` comparison before every LTC claim, not only at startup. It needs `crosscheck` set to a source and is refused at config load with `crosscheck = "off"`. A mismatch holds the claim (`Transient`, retried next tick); an unreachable or rate-limited source logs one warning per claim (source URL, reason, outpoint) and the claim goes ahead, because a claim stalled past the counterparty's refund timeout loses the coins. The result is reused until the primary's tip moves, so the source sees at most one request per LTC block (about 150 s); a hanging source can delay a claim by up to the 20 s HTTP timeout once per block. The taker CLI's matching flag is `--ltc-crosscheck-before-claim`.
`[divi].expiry_start` (default `"tip"`) sets where the lock-expiry sweep starts counting a dropped DIVI lock's absent blocks. With `"tip"` (today's rule), a first absent check made at a tip whose own time is within two block spacings of the clock counts at once. With `"mtp"`, every first absent check waits until the node's median time past reaches that check's clock, so an endpoint replaying old blocks with a tip stamped near the clock cannot start the count. The cost: about 5 to 6 more blocks before any DIVI release (11 blocks after the first absent check instead of 6). Any other value is refused at config load. The taker CLI's flag is `--divi-expiry-start tip|mtp`. Opt-in only; no deployed config sets it.

With `crosscheck_before_claim` on, every LTC lock read is cross-checked too (builder EL): before the maker funds against the taker's LTC lock, and before the taker claims the maker's LTC lock (revealing the preimage), the source must show the agreed HTLC script and the same value at the lock's outpoint (Blockbook `GET /api/v2/tx/{txid}`, BlockCypher `GET /txs/{txid}`); the lower of the two confirmation counts is used. A different script or value is refused as `Transient`, naming both URLs. Unlike the claim itself, this read **fails closed**: while the source is down, rate-limited or has not indexed the lock, the maker does not fund and the taker does not claim, because neither has revealed or paid anything yet (the taker's claim deadline still declines in time and its own leg refunds). Cost: one more request per lock read, reused until the primary's answer changes (about once per LTC block per lock), and a wait while the source is down.
Since builder EI the claim-time check also compares the block at `tip - 1` (a source one block behind still has it, so a block of lag is not a mismatch) and the spend of the output being claimed: a spend that only the primary or only the source shows, or two different spenders, holds the claim (`Transient`). An unreachable source, or one that has not indexed `tip - 1` yet, still warns and the claim goes ahead. The source now sees up to three requests per LTC block per claimed output. The startup `[ltc].crosscheck` is unchanged (`tip - 6` only); refunds, CPFP children and the broadcast are not cross-checked.
`--claim-fee-cap CHAIN=FEERATE` and `--claim-price-bump CHAIN=PCT` (repeatable flags, not config keys; BTC, LTC, USDC) set the cap and the node's replacement price bump of the maker's taker-leg claims. Since builder EJ a USDC claim whose estimate is already within one price bump of the cap (above `cap * 100 / (100 + bump)`, about 454.5 gwei under the 500 gwei default at geth's 10%) is signed at the cap, first or after a refusal, because no replacement of it could stay within the cap; every other claim pays what it did before. A floor above the cap still loses the leg.

`[btc].expiry_start`, `[ltc].expiry_start` and `[zec].expiry_start` (each default `"tip"`, same two values, any other refused at config load naming the key) set the same thing for that chain's dropped maker locks; each chain's sweep reads only its own key. With `"mtp"` a release on that chain comes about five blocks later (11 blocks after the first absent check instead of 6 when swept at every block). The taker CLI sweeps its `--counter-chain` when that is BTC, LTC or ZEC, with `--btc-expiry-start`, `--ltc-expiry-start` or `--zec-expiry-start tip|mtp` (default `tip`). USDC and XMR hold no input reservations and have no key. Opt-in only; the example config has each line commented out. On every chain, a sweep whose median time past is more than 2 h (the consensus future limit) ahead of the clock checks, records and releases nothing, as one whose tip time is.

Since builder EN the same switch also cross-checks every LTC `find_spend`, the read behind the maker's preimage watch and both sides' refund checks: the source's view of the lock transaction names the spender (Blockbook `vout[n].spentTxId`, BlockCypher `outputs[n].spent_by`) and the spender is read as raw hex (Blockbook `GET /api/v2/tx/{txid}` `hex`, or `GET /api/v2/tx-specific/{txid}` for a mempool spend; BlockCypher `GET /txs/{txid}?includeHex=true`), so its input, scriptSig and witness (the preimage) are compared byte for byte. A spend the primary hides or invents, a different spender, or the same spender with another witness is `Transient` naming both URLs (the engine reads again next tick; nothing is decided on it). When both agree, the fewer confirmations are used (the later block, or the mempool if either has it there). An unreachable, rate-limited or unparseable source logs one warning (source URL, reason, outpoint) and the primary's answer stands, as for the claim: failing closed here would hold the maker's refund, which reads `find_spend` first, behind a third-party explorer. Cost: one more request per `find_spend` poll while the lock is unspent, two once a spend shows (three for a Blockbook mempool spend), each reused for one LTC block time (150 s) while the primary's answer stands, so about one source read per LTC block per watched lock instead of one per 5 s tick. Off (the default) adds no request.
`profile` (default `testnet`) must agree with every configured coin section (`[btc]`, `[ltc]`, `[zec]`, `[xmr]`, `[usdc]`): a mainnet profile with a test network, a mainnet network without `allow_mainnet`, or a testnet profile with a mainnet network is refused at config load. The taker CLI `divi-swap --profile mainnet` likewise refuses any maker quote whose confirmation depths or timeouts are weaker than the mainnet profile's, before it signs or funds anything.

`[usdc].network` defaults to `sepolia`; the mainnets `ethereum` and `base` likewise need
`allow_mainnet = true` and a matching top-level `profile = "mainnet"`.

`[usdc].fallback_rpc_url` (unset by default) names a second, independent EVM JSON-RPC node, ideally your own. When set, the reads a claim or refund rests on (the HTLC lock, the spend of it, confirmations and the latest block time) are asked of both nodes: a lock or spend only one node reports, two different spends, or a lock at another amount is `Transient` (the engine retries; nothing is decided on a split view), and of two confirmation counts or block times the smaller is used. It must differ from `[usdc].rpc_url` (or the network's default when that is unset), or the config is refused at load. The cost: it fails closed, so while the second node is down, rate-limited or behind, those reads stay `Transient` and a claim or refund waits until it answers and catches up. Tip, sending, nonces, gas and balances stay on `rpc_url`. Not required on a mainnet profile. The taker CLI's matching flag is `divi-swap --usdc-fallback-rpc-url`.

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
bucket either way. The headers count only from a socket peer listed in `trusted_proxies`
(addresses or CIDR networks, default `["127.0.0.1/32", "::1/128"]`, a proxy on the same host);
a request from any other peer is keyed on that peer, whatever its headers say, so a client that
reaches the daemon directly cannot choose its own bucket. List a proxy on another host by its
address; `trust_proxy_headers = true` with an empty `trusted_proxies` is refused at start. Turn
it on only behind a proxy you control. It is off by default and the example config ships both
keys commented out.

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
