# Lane daemon — `bin/divi-swapd/`, `bin/divi-swap/`

Read `_common.md` first. You own `bin/divi-swapd/`, `bin/divi-swap/` and
`docs/plans/swap-poc/status/daemon.md`. You build against the frozen `divi_swap` API
(`Maker`, `Taker`, `Store`, `api::*`); the engine lane is filling those bodies **in parallel**
— until it lands, write your code and tests against the signatures and `MockBackend`, and
`git pull --rebase origin main` periodically. Your end-to-end tests go green once engine lands.

**divi-swapd** (maker): `axum` 0.7, TOML config (`--config`), listen address, DB path,
profile (`testnet`), offers, chain endpoints, and **secret refs** (`op://…` or
`credential:<name>` — resolve with `SecretRef`; never accept a key value in config/argv/env).
Routes: `GET /healthz` (200 + chain tips + version), `GET /offers`,
`GET /offers/:id/quote?btc_sats=N` (60 s expiry), `POST /swaps` (`AcceptRequest` → `SwapView`),
`POST /swaps/:id/lock` (`LockNotice`), `GET /swaps/:id`, `GET /swaps`. All under an optional
path prefix (`/swap` behind nginx). Scheduler task: `Maker::tick` at startup and every N s.
JSON logs via `tracing-subscriber`; never log keys or preimages before reveal.
`--backend mock` runs both chains on `MockChain` for local/CI use.

**divi-swap** (taker + operator CLI, `clap`): `quote --maker URL --offer ID --btc-sats N`,
`accept`, `lock`, `status`, `claim`, `refund`, and `run` (does the whole taker flow, polling
the maker and stepping `Taker` until `Done`, with a timeout), `--db`, secret refs for the
taker keys, `--backend mock|live`.

**Acceptance** (`tools/swap-poc/check-daemon.sh`): both crates green, no `todo!`, `--help`
works for `divi-swapd` and each CLI subcommand, and tests named `healthz_ok`, `offers_list`,
`quote_expires_after_60s`, `post_swaps_accepts_quote`, `get_swap_never_leaks_keys`,
`lock_notice_advances`, `scheduler_resumes_on_restart`, `e2e_mock_happy_path` and
`e2e_mock_refund` (daemon + taker engine over two `MockChain`s in one test, real HTTP on an
ephemeral port).
