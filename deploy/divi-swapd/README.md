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

## Rollback

`deploy.sh rollback` restores `/usr/local/bin/divi-swapd.prev` and restarts. The DB is not
migrated down; use a prior binary only if its schema matches.
