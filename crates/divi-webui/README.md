# divi-webui — IronDivi's built-in web interface

Off unless `irondivid` is started with `-webui`. It serves a small single-page
app and a JSON API that calls the daemon in process (no RPC password needed).

## Options

| Option | Default | Meaning |
|---|---|---|
| `-webui` | off | Turn the web interface on (needs the RPC server; refused with `-server=0`) |
| `-webuiport=<port>` | 51480 / 51481 test / 51482 regtest (PrivateDivi 52480…) | Port |
| `-webuibind=<ip>` | 127.0.0.1 | Address to listen on |
| `-webuiallowremote` | off | Required before a non-loopback `-webuibind` is accepted. The interface is plain HTTP, so use it only behind a TLS proxy or on a private network |
| `-webuiallowhost=<host>` | — | Extra `Host:` names accepted (repeatable); loopback names always are |

All can also go in `divi.conf`.

## Security

- **First run:** the daemon writes a one-time setup token to
  `<datadir>/webui-setup-token` (its path, never its value, is logged). The
  setup page asks for the token and a new web UI password (Argon2id hash,
  stored in the data directory).
- **Sessions:** HttpOnly, SameSite=Strict cookie plus an `X-CSRF-Token` header
  on every POST; failed logins are rate-limited (429).
- **Every request:** Host allow-list (421 otherwise), same-Origin and JSON for
  POST, strict CSP with no inline script/style, `X-Frame-Options: DENY`,
  `no-store` on the API, 1 MB body cap.
- **Wallet rules** (`src/gate.rs`):
  - keys never leave: `dumpprivkey`, `dumpwallet`, `dumphdinfo` are refused;
  - an **unencrypted** wallet may only read and `encryptwallet` — nothing that
    spends, stakes or changes settings until it is encrypted;
  - unlocking is for **staking only** (`walletpassphrase p 0 true`), or for
    spending for at most 600 s.
- **Settings** save only once the wallet is encrypted; secret values
  (`rpcpassword`, …) show as "set" and are never sent to the browser.

## Pages

Dashboard · Security (encrypt, unlock for staking, lock, change passphrase,
change web UI password) · Settings (every option in `src/schema.rs`, grouped
by category; saves to `divi.conf` preserving comments and order, applies
`staking`/`stakesplitthreshold` live, flags the rest as needing a restart,
and shows options overridden on the command line) · Console.

Wallet, Staking, Vaults and Swaps are placeholders for the apps built next on
the same API (`/api/rpc` through the gate, `/api/settings`).

## Layout

- `src/lib.rs` — config, listener, router, middleware, handlers
- `src/auth.rs` — password hash, setup token, sessions, login limiter
- `src/gate.rs` — which RPC calls the web UI may make
- `src/schema.rs` — every setting: kind, range, default, help, live RPC
- `src/conffile.rs` — read/apply changes to `divi.conf` in place
- `static/` — `index.html`, `app.js`, `app.css` (compiled in)
