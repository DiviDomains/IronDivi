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
and shows options overridden on the command line) · Wallet · Console.

**Wallet** — balance, and payments by QR code both ways:

- *Request a payment:* amount, name, purpose and memo (all optional) become a
  `divi:<address>?amount=&label=&message=&memo=` link on a new address, shown
  as a QR code to hold up to the payer, with Copy and (on phones) Share.
- *Pay:* scan the payee's code, or type or paste an address or `divi:` link,
  check, confirm, send. Ways to scan: take a picture (phones; works over plain
  HTTP), open an image, the live camera, scan the screen (desktop: share a
  window or screen showing the code), or paste a screenshot. The live camera
  and the screen need HTTPS or localhost. The wallet is unlocked for 60 s to
  send and then put back as it was (locked, or staking only). A request's
  `memo` or `message` is kept as the wallet's own note on the payment: this
  page cannot write OP_META on the chain (the browser extension can).

The same link format is used by the IronDivi browser extension. Staking,
Vaults and Swaps are placeholders for the apps built next on the same API
(`/api/rpc` through the gate, `/api/settings`).

## Layout

- `src/lib.rs` — config, listener, router, middleware, handlers
- `src/auth.rs` — password hash, setup token, sessions, login limiter
- `src/gate.rs` — which RPC calls the web UI may make
- `src/schema.rs` — every setting: kind, range, default, help, live RPC
- `src/conffile.rs` — read/apply changes to `divi.conf` in place
- `static/` — `index.html`, `app.js`, `app.css`, `pay.js` (payment links), all
  compiled in; vendored unmodified: `qrcode.js` (qrcode-generator 1.4.4, MIT)
  and `jsqr.js` (jsQR 1.4.0, Apache-2.0, `jsqr.LICENSE`; loaded only to scan)
- `tests/pay_uri.test.js` — `node --test crates/divi-webui/tests/pay_uri.test.js`
