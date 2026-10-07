# Lane deploy — `deploy/divi-swapd/`

Read `_common.md` first. You own `deploy/divi-swapd/` and `docs/plans/swap-poc/status/deploy.md`.
**Do not touch dnsdivi** (no ssh): Wave 3 runs the deploy. Read
`~/code/divi-infrastructure/DEPLOYMENT.md` (divi-chatbot unit pattern) first.

**Build:**
- `divi-swapd.service`: dedicated unprivileged `User=divi-swapd`, `StateDirectory=divi-swapd`
  (DB lives there, 0600), `ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`,
  `PrivateTmp=yes`, `Restart=on-failure`, and keys via `LoadCredential=` (e.g.
  `LoadCredential=maker-divi:/etc/divi-swapd/credentials/maker-divi` — files root:root 0400,
  provisioned once from 1Password by `deploy.sh provision-secrets`, which reads with `op read`
  locally and writes over ssh **stdin**, never argv). Config refs `credential:maker-divi`.
- `nginx-swap.conf`: `location /swap/ { proxy_pass http://127.0.0.1:<port>/; … }` snippet for
  the existing dnsdivi server block, with sane timeouts and body size limit.
- `logrotate-divi-swapd`: `size 10M`, rotate 5, compress (if logging to file; else document
  journald `SystemMaxUse`).
- `divi-swapd.toml.example`: testnet config with secret refs, no secrets.
- `deploy.sh`: idempotent; `--dry-run` prints `DRY RUN` and every step it would run (the
  `ssh dnsdivi …` lines included) without executing; steps: build release (on dnsdivi or
  cross — decide and document), install binary, user, unit, nginx snippet (`nginx -t` before
  reload), logrotate, start, `curl …/swap/healthz`. Subcommand `provision-secrets`. SSH only via
  the `dnsdivi` host alias. `shellcheck` clean (`brew install shellcheck` if missing).
- `README.md`: operator runbook — deploy, provision, rotate keys, logs, rollback.

**Acceptance** (`tools/swap-poc/check-deploy.sh`): the files exist with the directives it
greps for, shellcheck clean, `deploy.sh --dry-run` exits 0 and prints the plan, and nothing
secret-looking in `deploy/divi-swapd/`.
