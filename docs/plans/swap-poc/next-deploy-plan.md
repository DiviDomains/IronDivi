# Next maker deploy plan: V1 scripts, swap tokens, operator token (testnet maker on dnsdivi, https://divi.cx/swap)

Status: PLAN ONLY. Nothing here has been run on dnsdivi. Needs Human's written approval before any step in
"Deploy" is run. Written 2026-10-22 by builder BP (hermetic harness on hp3, no funds, no network, no live host).

How to read the claims: a line marked `could not verify` was not checked from this lane, because this lane may
not ssh to dnsdivi and ran no cargo build. Everything else points at a file in the repo at `622220d`.

## What is live today
Per `DEPLOY-5366e10.md` (deployed 2026-10-22 18:26 UTC): `divi-swapd` built from `5366e10`, testnet profile, DIVI/BTC/LTC/ZEC
testnet and XMR stagenet, no `allow_mainnet`, no `trust_proxy_headers`, no DIVI fallback. All swaps terminal at that time.
`could not verify`: that the live config, swap list and unit are still as that document says (not read from the host).

## What would be installed
- A `divi-swapd` binary built from `private/signed/main` at `8c876bc` or newer (`git log 5366e10..8c876bc` is 7 commits):
  - `aa0d50b` (BE) new swaps lock with the V1 HTLC script, `OP_SIZE 32 OP_EQUALVERIFY` added (`crates/divi-swap/src/maker.rs:331,340`,
    `htlc.rs`), so only a 32-byte preimage can claim. The maker refuses a taker that locked the V0 script on a new swap
    (`refuse_downgraded_lock`, `maker.rs:409`).
  - `5af7f2c` (BD) swap tokens, operator token, 426 for old takers (`bin/divi-swapd/src/routes.rs:258,517`, `config.rs:485-494`).
  - `feced5e` (BK) the swap database and its `-wal`/`-shm` are tightened to 0600 on open (`crates/divi-swap/src/store.rs:290-292`).
    Live files are already 0600 per the 5366e10 plan, so no visible change.
  - `7f47ad0` (BH) the DIVI second source also checks tip and wallet reads; opt-in, unset live, so no change.
  - `607446d` docs only. `622220d` (BN) the landing page files: they are nginx files, not part of the binary; a separate step.
  - `8c876bc` (BL) the maker re-sends its persisted lock transaction if the lock is reorged out before `maker_leg_confs`, moves to
    refundable early when the lock is gone and `locktime - mtp < claim_margin_secs`, and records a one-time error if the re-send is
    refused for good (new record field `maker_lock_dropped`, written only when set, so stored JSON is unchanged until then;
    `store.rs`, `maker.rs` `watch_maker_lock`). No config key, no new route. A rollback binary does not re-send (see Rollback).
- The plan was written at `622220d` and re-checked against `8c876bc`: the config diff, routes and scripts are the same.
- Binary only, plus ONE new file and TWO new lines in the config (below). No unit change.
- The binary has not been built or tested at the new tip by this lane. If more commits land first, re-read this section. Before approval, the orchestrator builds it on hp1
  (`nice -n 10 cargo build --release --locked -p divi-swapd`) and records the sha256 here: `sha256 = <fill in>`.

## What changes for users
- A taker app built before `aa0d50b`/`5af7f2c` can no longer open a swap (details in "Old taker, step by step").
- A new taker gets a per-swap token in the accept reply and stores it; reading `GET /swaps/:id` or locking needs it.
  Without it the answer is the same 404 as an unknown id.
- Public `GET /swaps` (the full listing) turns into a 404 for everyone except the operator.
- New swaps use the V1 script: a different lock address from V0 swaps. Only taker apps from the new code build it.
- The landing page does not change with this binary.

## Truth table: config keys added since 5366e10
`git diff 5366e10..HEAD -- bin/divi-swapd/src/config.rs` shows exactly two keys, both in `DaemonConfig`:

| key | default | file:line | must the live config change? |
|---|---|---|---|
| `operator_token_file` (path) | unset: `GET /swaps` is 404 for everyone | `config.rs:489`, read at start by `operator_token()` `config.rs:531-545`; unreadable or empty file = start refuses | YES for the operator tools. Unset, the daemon starts fine but redeploy, rollback, swap-watch and wave4-smoke can no longer read the swap list and refuse (or report a problem). Set it. |
| `allow_tokenless_swaps` (bool) | `false` | `config.rs:494`, used at `main.rs:622`; check at `routes.rs:517` | NO. Leave it unset. See "Old taker". |

No other key was added to the daemon config. The DIVI fallback and `trust_proxy_headers` already
existed at 5366e10 and stay unset/unchanged. `could not verify` that no other crate has a config of its own that moved
(only `config.rs` of the daemon was diffed; the other changed crates are `swap-chain-*` library code).

### Every script that reads `GET /swaps`
| script | how it gets the operator token | refuses if missing? |
|---|---|---|
| `tools/swap-poc/redeploy-maker.sh` (gate) `:192-205` | `--operator-token-file PATH` or env `OPERATOR_TOKEN_FILE`, a LOCAL file; sent to curl on stdin (`--config -`) | yes: "no operator token" / "REFUSE" |
| `tools/swap-poc/rollback-maker.sh` `:121` | same flag/env, passed on to the redeploy gate | yes: "the in-flight gate refused; nothing was changed" |
| `tools/swap-poc/wave4-smoke.sh` `:40-50`, `:178` | same flag/env, curl stdin | skips the count with a note |
| `deploy/divi-swapd/swap-watch/swap-watch.sh` (header, `OPERATOR_TOKEN_FILE`) | reads `/etc/divi-swapd/operator.token` on the host (the timer runs as root), curl stdin | reports a problem, not "no swaps" |

WARNING, a silent miss: the OLD `swap-watch.sh` (the `5366e10` version) calls `curl "$API/swaps" | jq '.[]?'` with no header. Against
the new maker that is a 404 with an empty body, which jq turns into "no swaps". Alerts for stuck swaps would stop, quietly.
So the new `swap-watch.sh` goes on the host in the same change as the binary (step 5). `could not verify` whether swap-watch
is installed on dnsdivi at all (the 5366e10 plan does not say).

## Old taker, step by step
An "old taker" is a taker app built before `aa0d50b` and `5af7f2c`.
1. The old app asks for a quote: unchanged, works.
2. The old app sends accept without `X-Swap-Token-Support: 1`. The new maker answers **426** "upgrade the taker" (`routes.rs:517-526`)
   BEFORE the quote is spent and before anything is written. The old app prints that error. No swap exists, no coins moved.
   No in-flight swap can be stranded here: the old taker never reaches a state where it holds funds.
3. If the operator set `allow_tokenless_swaps = true` (do not): accept succeeds and the swap has no token. The accept reply carries the
   taker leg parameters with `script_version: V1` (`maker.rs:331`). The old app does not know that field (its `HtlcParams` has no such field and, by the code, serde ignores unknown fields;
   not run against a real old build), so by the code it builds the **V0** script and
   FUNDS it. Then `lock` runs `refuse_downgraded_lock`: the V0 output is found, the lock is refused ("taker lock uses the V0 HTLC
   script"), and the maker never funds its leg. The taker's coins sit in a V0 HTLC until its own refund timelock. So
   `allow_tokenless_swaps = true` converts a harmless 426 into locked-up taker funds for a pre-`aa0d50b` app, and still not a swap.
   `could not verify` by running a real old binary against a new maker: this is read from the code, and this lane has no old build.
   (A taker with the token support but without V1, if one ever shipped, would hit step 3's refusal the same way. None is known.)
4. A swap that was already in flight on the old maker is not affected by the new rules: its record has no token (stays open by id,
   as before) and no version (reads as V0, same script, claim and refund). It keeps going on the new binary
   (`maker.rs:649-652`, "V1 for a swap accepted now, V0 for one in flight"). The gate below refuses to deploy while any exists anyway,
   so on the intended path there are none.

### What `allow_tokenless_swaps` buys and costs
- Buys: a taker without token support is not turned away at accept. In practice nothing, because of step 3.
- Costs: the swap has no token, so anyone who learns its id can read it and call `lock` on it (`config.rs:485-494`); and the
  funds-locked outcome above. Recommendation: leave it `false`.

## Taker-app upgrade order
1. Publish the new taker app (built from the new tip) first, or at the same time. `could not verify` where it is distributed: BN's
   landing page says the app has no public download yet (engine.md, BN round), so there is nothing to upgrade today.
2. Only then install the new maker. Between a maker deploy and the app being available, nobody can open a swap. That is acceptable
   for testnet, and it is the reason the deploy waits for Human.
3. A new app against the OLD maker still works (it sends no token when none is issued: `bin/divi-swapd/tests/route_auth.rs:431`).
   So app first, maker second, is safe in both orders for the new app. Old apps are the ones that break.

## Operator steps in order (all on dnsdivi, over ssh, by the operator)
1. Create the token file; the value never prints and never goes in a command line or a git tree:
   ```sh
   sudo install -m 0640 -o root -g divi-swapd /dev/null /etc/divi-swapd/operator.token
   head -c 32 /dev/urandom | base64 | tr -d '=+/\n' | sudo tee /etc/divi-swapd/operator.token >/dev/null
   sudo stat -c '%a %U:%G %s' /etc/divi-swapd/operator.token     # expect: 640 root:divi-swapd and a non-zero size
   ```
   The `tee` is silenced and nothing echoes the value. Do this BEFORE installing the binary: a configured file that is missing or
   empty makes the daemon refuse to start (`config.rs:531-545`).
2. Add one line to `/etc/divi-swapd/divi-swapd.toml` (top level, next to the other daemon keys; edit as root):
   `operator_token_file = "/etc/divi-swapd/operator.token"`. Do not add `allow_tokenless_swaps`.
   Nothing else in the toml changes.
3. A local copy of the same value for the deploy scripts run from the Mac. Get it over ssh into a file that only you can read, in a
   directory outside any git tree:
   ```sh
   umask 077; ssh dnsdivi sudo cat /etc/divi-swapd/operator.token > ~/.config/divi-swap-operator.token
   ```
   Pass it as `--operator-token-file ~/.config/divi-swap-operator.token` (never the value). Delete it after the deploy if not needed.
4. swap-watch: `OPERATOR_TOKEN_FILE` already defaults to `/etc/divi-swapd/operator.token`, so no env change. The point is to copy the new
   `deploy/divi-swapd/swap-watch/swap-watch.sh` to `/usr/local/bin/swap-watch.sh` with the binary. Check with
   `sudo /usr/local/bin/swap-watch.sh dry-run` (README, swap-watch section): it must not report an unreadable token file or a refused listing.
5. nginx: no change. `deploy/divi-swapd/nginx-swap.conf` is a plain `proxy_pass` that forwards `X-Swap-Token`,
   `X-Swap-Token-Support` and `X-Operator-Token` (README, the paragraph before "## Rollback"). `could not verify` the live nginx file matches the repo
   snippet (the 5366e10 plan notes the live block already differs in `X-Forwarded-For`); if it filters headers, allow those three.
   The landing page (BN) is installed by its own script, `landing-install.sh`, separately and later.

## Checks (all before anything is installed)
Already done in this lane, hp3, no network, no funds:
- `tools/swap-poc/test-next-deploy.sh`: 49 ok / 0 fail. Runs the real redeploy and rollback scripts with the token end
  to end against a fake host and a real local HTTP server that returns 404 without the header; asserts the token reaches curl on
  stdin and appears on no argv; asserts a missing, empty, unreadable or wrong token refuses before anything is installed, snapshotted
  or restarted; an in-flight swap still refuses; rollback works with the token and refuses without. It also reruns itself against two
  deliberately broken copies of the script (token on argv; missing token not refused) and requires the harness to fail on each.
- `test-redeploy-maker.sh` 61 ok / 0 fail and `test-swap-watch.sh` all passed, at `622220d`; BL (`8c876bc`) changed no script or config.
- NOTE for the orchestrator: `test-redeploy-rollback.sh` (builder BM's file, not touched here) FAILS at `622220d` with 8 FAIL
  lines, because it predates the operator token: its gate refuses with "no operator token". It is a stale harness, not a script bug
  (the new harness covers the same path with the token). It needs `--operator-token-file` added; one line.

To do before approval (orchestrator, not this lane):
- Build at the final tip on hp1, run `cargo test --release -p divi-swap -p divi-swapd -p swap-chain-divi`, record counts and sha256 above.
- On dnsdivi, read-only: run the new binary from `/tmp` as `divi-swapd` with `--config /etc/divi-swapd/divi-swapd.toml --xmr-inflight`
  after steps 1-2 (it must exit 0 with the token file in place).
- Confirm `/etc/divi-swapd/divi-swapd.toml` has no `allow_tokenless_swaps` and no `trust_proxy_headers` as the 5366e10 plan states.

## Deploy
Run from the Mac in any checkout at `signed/main`, after the steps above:
```sh
ssh -o ExitOnForwardFailure=yes -f -N -L 18482:127.0.0.1:18480 dnsdivi
B=<path of the built binary>; shasum -a 256 "$B"                         # must equal the sha256 recorded above
T=~/.config/divi-swap-operator.token
tools/swap-poc/redeploy-maker.sh --binary "$B" --operator-token-file "$T" --dry-run   # read the plan
tools/swap-poc/redeploy-maker.sh --binary "$B" --operator-token-file "$T"             # the deploy
curl -fsS https://divi.cx/swap/healthz                                                 # expect ok
sudo /usr/local/bin/swap-watch.sh dry-run                                              # on dnsdivi, after step 4
pkill -f 'L 18482:127.0.0.1:18480'
```
The script refuses while any swap is not terminal (including XMR), snapshots binary+config+unit to `/var/backups/divi-swapd/<UTC>/` and
`prev/`, installs, restarts, waits up to 300 s for `/healthz` and restores `prev/` by itself if it does not come up.
Afterwards, from a new taker app on testnet: one full swap, and one old-app attempt that must print the 426 message.

## Rollback
```sh
ssh -o ExitOnForwardFailure=yes -f -N -L 18482:127.0.0.1:18480 dnsdivi
tools/swap-poc/rollback-maker.sh --dry-run --operator-token-file "$T"      # read it
tools/swap-poc/rollback-maker.sh --to prev --operator-token-file "$T"      # prev = the 5366e10 set this deploy replaced
pkill -f 'L 18482:127.0.0.1:18480'
```
- **Rule: no rollback below `aa0d50b` while any V1 swap is not terminal.** An older binary ignores `script_version`, reads a V1 record
  as V0, derives a different address and cannot find or claim the lock. The gate cannot see script versions, so it will not stop you:
  check `GET /swaps` yourself (any swap accepted after the deploy is V1). With only terminal swaps, rolling back is safe, and the
  old binary starts with the new toml key present (the daemon config has no `deny_unknown_fields`, so `operator_token_file` is
  ignored; `could not verify` by starting a real 5366e10 binary on the new toml).
- Rolling back below `8c876bc` drops the lock re-send: a maker lock reorged out of the chain is then not re-broadcast. The extra
  record field `maker_lock_dropped` is optional in the stored JSON; whether a 5366e10 binary reads a record that carries it is
  `could not verify` (it is only ever written after a refused re-send).
- Rolling back to 5366e10 makes `GET /swaps` open again for as long as that binary runs. Remove no token file; keep it for the next deploy.
- The rollback's own in-flight gate needs the same token file (this is why the flag is repeated above).

## Risk if deployed
- Every taker app built before the change is locked out until upgraded; today there is no public download (see upgrade order).
- A missing or empty `operator_token_file` stops the daemon from starting: the deploy script then restores `prev/` by itself
  (health check fails -> automatic restore), so the cost is a short outage, not a stuck maker.
- The old `swap-watch.sh` goes blind (404 -> "no swaps") if left in place: step 4 is not optional.
- A fresh wave of V1 swaps cannot be rolled back below `aa0d50b` until they are terminal.
- `trust_proxy_headers` stays unset: one shared rate-limit bucket (see 5366e10), unchanged by this deploy.

## Risk if not deployed
The live maker keeps accepting V0 taker locks: a hostile or old taker can lock a V0 script that accepts a non-32-byte preimage,
which the maker could never claim with (`maker.rs` comment on `refuse_downgraded_lock`); any swap id leaked in a log or URL lets a third
party read the swap and call `lock`; and `GET /swaps` lists every swap id to anyone. It is testnet/stagenet, so no real funds: the exposure
is abuse, and a live site that does not match the code under review.

## Not verified (summary)
Live host state (config, swap list, nginx, swap-watch install, taker-app distribution); a build and test run at the final tip; an
old-binary-on-new-DB and new-binary-on-old-toml start; behaviour of a real pre-`aa0d50b` taker app.
