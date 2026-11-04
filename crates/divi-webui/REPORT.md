# IronDivi web interface — GUI spec report

Branch `webui`. Proven on regtest nodes on hp2, hp1 and hp3 (`-regtest -addressindex=1
-txindex=1`, webui on 127.0.0.1:29446, reached through an SSH tunnel), and then
on a testnet node on hp3 (`~/webui-testnet`, interface 29456; `T*` screenshots).
Screenshots are in the session notes folder `webui-proof/` (names below).

## 1. Auto-open and auto-login

- On start, a desktop run issues a one-time token (`launch.rs`), opens
  `http://<bind>/launch?t=<64 hex>` in the browser, and `/launch` swaps the
  token for a session cookie, then redirects to `/`. The token is single-use,
  compared in constant time, and expires after 60 s. It is never logged.
- Default on. Skipped when `SSH_CONNECTION`, `SSH_TTY` or `SSH_CLIENT` is set,
  and on Linux when neither `DISPLAY` nor `WAYLAND_DISPLAY` is set.
  `-webuiopen=0` turns it off. The setup-token / Argon2 password sign-in stays
  the fallback.
- **Known exposure:** the URL, with the token, is the browser opener's
  argument (`xdg-open`, `open`, `start`), so another local user can see it in
  the process list for the opener's short life. The token is single-use and
  lasts 60 s; the webui binds to loopback by default.
- Proof: `1-auto-login.jpg` (signed in from the launch URL, no password asked),
  `1b-password-set.jpg` (the password fallback).
  The proof node ran with a stub `xdg-open` that wrote the URL to a 0600 file.
- **Proven on testnet (2026-10-29)** on the hp3 testnet node (interface
  29456): the launch URL signed in with no password asked; reusing the same
  URL answered 303 with no session cookie (single-use); the token is in
  neither `node.out` nor `data/debug.log`. `T1-testnet-auto-login.jpg`.

## 2. Every config value

- The Settings page shows every option the daemon reads (84 options in
  `schema.rs`). The test `every_option_is_in_the_web_settings`
  (`bin/irondivid/src/main.rs`) fails when the daemon reads an option the
  schema lacks. Options in `UNSUPPORTED_OPTIONS` (taken from divid, ignored
  with a warning) are left out on purpose.
- Each option is marked **live** or **restart**.

| Applies live (no restart) | How |
|---|---|
| `staking` | `setstaking` |
| `stakesplitthreshold` | `setstakesplitthreshold` |
| `debug` (categories) | `setlogconfig` (new, `divi-rpc/src/logctl.rs`) |
| `loglevel` | `setlogconfig` |
| `addnode` | `addnode` |

  **Everything else needs a restart.** Saving writes the conf file either
  way; a live option is also applied to the running node at once.
- The Logs page tails the log live and shows node stats. Debug categories and
  the log level change there without a restart; that change lasts until the
  daemon restarts (Settings is where it persists). When `RUST_LOG` is set the
  daemon refuses live log changes, since the environment owns the filter.
- Proof: `2a-settings-live-restart-marks.jpg`, `2b-debug-applied-now.jpg`,
  `2c-logs-stats.jpg`, `2d-loglevel-live.jpg` (debug and loglevel). The other
  three were proven through `POST /api/settings` on the running node, with no
  restart: `addnode=127.0.0.1:29999` showed up in `getaddednodeinfo`,
  `stakesplitthreshold=2000` in `getstakesplitthreshold`, and `staking=0`
  turned `getstakingstatus` to "Staking Disabled"; the response listed all
  three under `live` with `ok: true` and nothing under `restart`.
- **Proven on testnet (2026-10-29)** on the hp3 testnet node (pid 431482
  throughout, so no restart): one `POST /api/settings` set `staking=0`,
  `stakesplitthreshold=2000`, `addnode=127.0.0.1:29999`, `debug=net` and
  `loglevel=debug`; the response listed all five under `live`, `ok: true`,
  nothing under `restart`. RPC agreed: "Staking Disabled", threshold 2000,
  the node in `getaddednodeinfo`, net lines in the log
  (`T2a-testnet-logs-debug-net.jpg`, `T2b-testnet-settings-staking-live.jpg`).
  A second POST put them back (`staking=1`, `stakesplitthreshold=20000`, no
  addnode, no debug, `loglevel=info`), again all live: "Staking Active",
  threshold 20000, `getaddednodeinfo` `[]`, same pid, and the conf file holds
  the restored values.

## 3. Multi-wallet (`wallets.rs`, `static/wallets.js`)

- Create, restore from words, import a backup file, rename, switch, delete.
  No limit on the number of wallets.
- Storage: `<datadir>/webui-wallets/<id>.json` (0600) in a 0700 directory, plus
  an `active` file. The recovery words are sealed with Argon2id +
  XChaCha20-Poly1305 under the wallet's own passphrase; the backup file is the
  same sealed JSON, so it holds no plaintext words.
- Words are shown once at creation, and again only with the passphrase.
  Delete needs the passphrase.
- **On the node's Electrum server:** balances, coins and history are read
  through `divi_electrum::Backend` (`chainview.rs`), the same backend the
  node's Electrum listeners serve. `irondivid` builds it from the node's own
  chain, mempool and RPC handles, so `divi-electrum` needed no change (the
  Electrum lane, session local_6efbe071, confirmed this is the interface to
  use). 20 receive and 20 change addresses are watched up front. Sends are
  signed in the webui and submitted with `sendrawtransaction`.
- The mempool counts: a payment shows at once as "Pending, in the mempool",
  and coins already spent in the mempool are left out of new sends. History is
  each transaction's net effect on the wallet (change netted out), newest
  first, mempool on top, up to the last 100 transactions.
- `gate.rs` still applies; `dumpprivkey`, `dumpwallet` and `dumphdinfo` return
  403 through `/api/rpc` ("keys never leave it").
- **Limits:**
  - needs `txindex=1` and `addressindex=1`. Without them the wallet page says
    which to set and to restart, and nothing else breaks;
  - history beyond the last 100 transactions is not shown (the balance still
    counts everything).
- Proof of the mempool (block 112–113): 12.5 DIVI sent to Savings from the
  node wallet, not mined. The page showed Pending 12.5 DIVI and a "pending"
  history line at once (`3j-wallet-mempool-pending.jpg`,
  `3k-history-pending-and-net.jpg`; the earlier 40.5 send now shows its net
  −40.5000226 DIVI). After one block, Pending 0 and Confirmed 221.9999774
  (`3l-wallet-confirmed-after-block.jpg`). A spend from the wallet while still
  in the mempool was not exercised live.
- Proof (regtest, block 111–112): created "Savings", funded with 250 DIVI,
  sent 40.5 DIVI from the UI (tx `dfdf925d…`, fee 0.0000226), balance
  209.4999774; renamed; wrong passphrase refused on delete; deleted; imported
  from the backup; restored from words as a second wallet with the same
  balance and history; switched. On disk: 0600 files, 0700 dir, and no
  plaintext words or passphrase in the wallet files, `node.out` or the data
  dir. After a node restart the wallet and its balance are unchanged.
  `3a-wallet-created-words-once.jpg` … `3i-wallet-after-restart-send-form.jpg`.
- **Proven on testnet (2026-10-29)** on the hp3 testnet node, served by its
  Electrum backend:
  - created "testnet-electrum-1" (id `6e2ced099a6da964`) in the UI; 24 words
    shown once (not screenshotted, since it shows the seed), 40 addresses
    watched, receive address `y4gzLvEKAVY8S1b3jQdMMJpPkmJTf8xbQj`
    (`T3a-testnet-wallet-created-address.jpg`);
  - funded with 25 DIVI from the node wallet (tx
    `feb51044d103e92eb4a3c631def19de8bcc09d34bc6e9734b6750e63821c23e7`; the
    node wallet paid the 0.0000226 fee): Pending 25 DIVI from the mempool at
    once (`T3b-testnet-wallet-pending-25.jpg`), then Confirmed 25 DIVI at
    block 371041 (`T3c-testnet-wallet-confirmed-25.jpg`);
  - sent 10 DIVI from the UI to `y7mxRxN8HHjhXhz48zaHj5WDLEhxJGsfvd` (tx
    `d4031728df9e16d9e0a7346c89771406c4b6267a288e6ba27284dcaa0e3a8b9d`, fee
    0.0000226 DIVI): history −10.0000226 pending
    (`T3d-testnet-wallet-sent-10-pending.jpg`), confirmed at block 371046
    (`T3e-testnet-wallet-send-confirmed.jpg`). The decoded tx has outputs
    10.0 to `y7mx…sfvd` and 14.9999774 change to
    `yEBT8SjYLAgArh1LDGSoo97PTjSE19DmQy`; 25 − 10 − 14.9999774 = 0.0000226
    fee. The API now reports confirmed 1,499,997,740 sat (14.9999774 DIVI);
  - created a second wallet "testnet-electrum-2" (id `60f1b4743d7e0e35`) and
    switched back to the first; the list shows both
    (`T3f-testnet-two-wallets.jpg`).

## 4. NFT page (`static/nft.js`, details in `NFT-PAGE.md`)

- Gallery, Mint, List and Send tabs per DT/1 (`DIVI-ASSET-STANDARD.md`).
- The gallery decodes DT/1 strictly from the wallet's coins and works now
  (`4a-nft-gallery.jpg`: no assets on this regtest wallet).
- **Mint and List are wired** to the NFT lane's wallet kit (divi-nft
  `packages/nft-kit` at 9b35408, `docs/WALLET-INTEGRATION.md`), on testnet
  only. The kit is bundled into `static/nftkit.js` by `nftkit/build.sh` from
  the pinned commit. It reaches the NFT service through a new `/api/nft/*`
  proxy in the interface: signed-in only, CSRF on writes, testnet only (404
  on any other network), and only to
  `nft-testnet.irondivi.com/nft/api`. The node wallet signs
  (`signmessage` for the service's sign-in, `signrawtransaction` for the
  transactions), and the kit checks each signed transaction against the one
  it built before it broadcasts. A locked wallet is unlocked with a
  passphrase field and put back afterwards.
- **Send stays off.** The kit has a TRANSFER builder, but a transfer built
  wrong burns the asset (§5), so the submit stays disabled until that
  builder is proven on testnet.
- The proxy's test (`the_nft_proxy_is_testnet_only_and_stays_in_the_api`)
  compiles and passes (see Tests).
- **Proven on testnet (2026-10-29):** a testnet `irondivid` with this
  branch runs on hp3 (`~/webui-testnet`, rpc 29455, interface 29456; hp1 was
  down and hp2 busy). Its wallet `y7mxRxN8HHjhXhz48zaHj5WDLEhxJGsfvd` holds
  500 tDIVI from the NFT lane (tx `c690c45b…`). The interface was opened over
  an ssh tunnel and driven in the browser.
  - The wallet had to be encrypted first: the gate (`gate.rs`) lets an
    unencrypted wallet make read calls only, so signing is refused until it
    is encrypted and unlocked.
  - **Mint:** `webui-proof.png` (944 bytes, sha256 `2f31a0e3…8ebe`) was
    pinned with its metadata (`ipfs://bafkreibzzuyoqcxwcwhn4etfimbmiureqy7co5l23wcsf4ylil5zg7ezvi`)
    and issued as asset
    `4f643d3e20153574a135872183d37a66ec49ec771029271f4b5bc05d27383f15`:
    carrier 0.0001 to the wallet, the DT/1 OP_RETURN, change back.
    `4b-nft-testnet-minted.jpg`.
  - **Indexed and locked:** the service indexed the asset at height 370470
    with owner `y7mx…sfvd` and `metaVerified: true`. The gallery shows it,
    and its coin was locked from the page. `4c-nft-testnet-gallery-locked.jpg`.
  - **List:** signed for 10 DIVI from the List tab. The page showed the
    0.1 DIVI organization royalty and reported "Listed for 10 DIVI (listing
    12)". The service's asset record now carries `listingPrice` 1000000000
    (10 DIVI). `4d-nft-testnet-listed.jpg`.
  - The hp3 testnet node and its wallet are left running for reuse; the
    wallet keeps its tDIVI. Its passphrase is in hp3
    `~/webui-testnet/wallet-pass` (0600, never printed); unlock with
    `python3 ~/webui-testnet/tpass.py unlock <seconds>`, and start the node
    with `bash ~/webui-testnet/testnet-start.sh`.
  - No CORS change was needed: the browser talks only to the interface, and
    the `/api/nft/*` proxy calls the service server-side without an Origin.

## 5. Sidechains (`static/sidechains.js`)

The brief asked for a nav slot. The sidechain-market lane (session
local_d5dca415) asked for its four-tab page on top, built to its spec
(`irondivi-sidechain-market/docs/GUI-API.md`); that page goes beyond the brief
and is in its own commit.

- **The page:** Available (cards with compatibility, cost, bond and earnings
  badges, a details drawer with what will run, signers and ports; Install),
  Installed (status, health, ports, disk, restarts, logs, start/stop/restart,
  rollback, auto-update policy, uninstall), Updates (from → to, security
  badge, Update), and Earnings (observed on the chain, kept apart from the
  operator's own claim; "not enough history" when thin). Installs, updates,
  rollbacks and uninstalls are jobs; the page follows each to the end.
- **The mount:** `Prepared::with_sidechains(Router)` nests the market's router
  at `/api/sidechains`, inside the interface's guard (known Host; same-origin
  JSON for POST and PUT) and behind sign-in: a read needs the session, a
  write also its CSRF token. The guard now treats PUT like POST; before, it
  refused every PUT. With no market built in, `/api/sidechains/*` answers
  503 `{"error": "the sidechain market is not installed in this node",
  "code": "not_installed"}` and the page says so.
- **Proven live** on a regtest node on hp1 (hp2 went into maintenance), with
  curl:
  - `GET /api/sidechains/available` with no session: 401 "sign in first";
  - the same, signed in: 503 `not_installed`;
  - `PUT /api/sidechains/x/policy`, signed in, with the CSRF token: 503
    `not_installed` (PUT now passes the guard);
  - the same PUT with no `Origin`: 403 "cross-origin request refused";
  - `POST /api/sidechains/x/install`, signed in, no CSRF token: 403 "stale
    page; reload it";
  - `DELETE /api/sidechains/x`: 405 (the spec uses no DELETE).

  The page with no market built in: `5-sidechains-not-installed.jpg`.
- **Rendered from fixtures:** the four tabs
  (`5a-sidechains-available.jpg` with a details drawer open,
  `5b-sidechains-installed.jpg`, `5c-sidechains-updates.jpg`,
  `5d-sidechains-earnings.jpg`). The page was fed fixture JSON for
  `/api/sidechains/*` in the browser (a `fetch` override; the rest of the
  page talked to the real node). Fixtures, matching the crate's `api.rs`
  types, are in the session notes `sidechain-fixtures/`.
- **The router is mounted** behind `irondivid`'s off-by-default `sidechains`
  feature (`bin/irondivid/src/sidechains.rs`). It takes `irondivi-sidechains`
  as a git dependency pinned to rev 52fbd26 of
  `bshuler/irondivi-sidechain-market`, runs the service over
  `<datadir>/sidechains`, reads the registry and earnings through the node's
  own RPC (on loopback), and nests `irondivi_sidechains::router(svc)` with
  `with_sidechains`. Without the feature the 503 `not_installed` path above
  is unchanged.
- **Proven live with the feature** on a regtest node on hp3, built with
  `--features irondivid/sidechains`. One real DVSC1 registration was put on
  the chain (payer `y5kDfVHDY5as1cHW54roM3g96Gpv311m2n`, 0.01 DIVI to the
  registry `yHkf3MUN4zLoXa84X1AXNvrSVg1TkF5cBh`, one OP_RETURN record; tx
  `c19d0f85…6cf27e` at height 112, 6+ confirmations). After the service's
  next registry scan (every 600 s), all four endpoints answered 200 through
  the interface, signed in:
  - `available`: the listing `webui-regtest-1` "WebUI Regtest Proof",
    network regtest, `manifest_error` "no manifest published", compatibility
    blocked;
  - `installed` and `updates`: `[]`;
  - `earnings`: the chain, model `none`, nothing observed.

  The four tabs on that API: `5f-live-available.jpg`, `5g-live-installed.jpg`,
  `5h-live-updates.jpg`, `5i-live-earnings.jpg` ("This sidechain pays node
  runners nothing"). The responses matched the page's expectations; no type
  mismatch was found to send to the market lane.
- **Live on testnet (2026-10-29)** on the hp3 testnet node, built with the
  feature. The startup registry scan failed (RPC not ready yet); the next
  one, 600 s later, read both real testnet registrations from the registry
  `yHkf3MUN4zLoXa84X1AXNvrSVg1TkF5cBh`:
  - "Divi Games" (`divi-games-testnet-1`, tx `a80ff9cc…179c`, height 364164):
    "no manifest published", blocked;
  - "dvsm test" (`dvsm-test-1`, root `yJgc6Kb9FqJPZezS5qGV4oLEuxy2nvqq5B`, tx
    `0827eafc91f9e12abecf5f01a5a3e9e6184f2f6f72722eab1180f55432999ccc`,
    height 370300): its manifest URL is
    `http://127.0.0.1:47811/www/dvsm-test-1/manifest.json`, which only
    resolves on the host where the market lane served it, so here it shows a
    fetch error and is blocked.

  Installed and Updates are empty, and Earnings shows model `none` for both.
  `T5a-testnet-sidechains-available-blocked.jpg`,
  `T5b-testnet-sidechains-installed-empty.jpg`,
  `T5c-testnet-sidechains-updates-empty.jpg`,
  `T5d-testnet-sidechains-earnings-none.jpg`.
- **Install, update, rollback, logs and uninstall, proven on testnet
  (2026-10-29)** from this page on the hp3 node. By Bert's choice, the market
  lane's signed public `www/dvsm-test-1/` files (not its vault) were copied to
  hp3 and served on 127.0.0.1:47811 with `python3 -m http.server`. Their
  hashes match the market lane's copies: `divi-gamechain` sha256
  `109845ce047552f3e8fab8b0c728eba9eba4fdad3e4de5c34a57ec96990cbb7e`,
  `manifest-1.json` `78cb24cf…45ec6`, `manifest-2.json` `70adf5db…c22c`.
  - The 12:34:12 UTC scan fetched sequence 1: "dvsm test", Compatible, Free,
    pays nothing, 1 GB disk, 128 MB RAM, with Install
    (`T5e-testnet-sidechains-compatible.jpg`).
  - **Install** (12:36:20 UTC): the file server logged the binary download;
    `/api/sidechains/installed` showed `divi-gamechain` 1.0.0, sequence 1,
    running, pid 454620, health ok, port api 47820/tcp, restarts 0. The
    installed `releases/1.0.0-1/divi-gamechain` has the manifest's sha256
    `109845ce…cbb7e`, and the chain's `/v1/info` answered (chain_id
    `divi-games-testnet-1`, network testnet, height 3)
    (`T5f-testnet-sidechains-install-done.jpg`,
    `T5g-testnet-sidechains-installed-running-1.0.0.jpg`).
  - **Update:** `manifest.json` was switched to sequence 2; the 12:44:12 scan
    offered "divi-gamechain 1.0.0 → 1.0.1", patch, Compatible
    (`T5h-testnet-sidechains-update-offered.jpg`). Update from the page:
    1.0.1, sequence 2, previous 1.0.0, pid 458779, health ok; Updates then
    read "Everything installed is up to date"
    (`T5i-testnet-sidechains-updated-up-to-date.jpg`,
    `T5j-testnet-sidechains-running-1.0.1.jpg`).
  - **Rollback** from the page: 1.0.0, sequence 1, previous 1.0.1, pid
    460655, running, health ok at 12:45:06Z
    (`T5k-testnet-sidechains-rolled-back-1.0.0.jpg`).
  - **Logs** open on the page and show the chain's lines
    (`T5l-testnet-sidechains-logs.jpg`). They carried raw ANSI colour codes
    (256 escape bytes in 20 lines); `sidechains.js` now strips them, checked
    against those same 20 lines in the browser (0 escapes left). The running
    binary still embeds the old file until the next rebuild.
  - **Uninstall** from the page, with "Also delete its data" ticked: the
    Installed tab reads "No sidechains are installed",
    `/api/sidechains/installed` returns `[]`, `data/sidechains/` on hp3 is
    empty and no `divi-gamechain` process runs
    (`T5m-testnet-sidechains-uninstalled.jpg`).

  Afterwards `manifest.json` was put back to sequence 1 (sha256
  `78cb24cf…45ec6`) and the file server was stopped. The files stay in
  `~/webui-testnet/sc-www` on hp3; to serve them again:
  `cd ~/webui-testnet/sc-www && python3 -m http.server 47811 --bind 127.0.0.1`.
- **Finding, chain cannot read the node:** the chain logged "Divi RPC
  unreachable … getblockcount: response is not JSON". The node does its part:
  the chain's process has `DIVI_RPC_URL`, `DIVI_RPC_USER` and
  `DIVI_RPC_PASSWORD` in its environment (names checked, values not read).
  But this `divi-gamechain` build contains none of those names; it reads only
  `divi_rpc = "http://127.0.0.1:29455"` from the `config.toml` the manifest's
  template renders, with no credentials, so the node's RPC answers 401. The
  market lane's own run used a public proxy that needs no auth. The fix
  belongs to the market lane (the chain should read the env credentials).
- **Not proven: observed earnings.** Both testnet sidechains declare earnings
  model `none`, so nothing pays a node and there is no number to show.

## Tests

`cargo test -p divi-webui -p irondivid` passed on hp3 at ffb2226 (the
`/api/nft` proxy and the `sidechains` mount included), both without the
feature and with `--features irondivid/sidechains`: every suite ok, 0
failed. The feature build of `irondivid` also passed. Earlier, the
Sidechains page passed the same tests on hp2 and on hp1, and the full
workspace test run passed before the last CSS/JS-only changes.
The daemon's flags, `-webuiopen` included, are documented in its usage text,
which the test `every_option_in_usage_is_read` keeps in step.
The ANSI-stripping change to `sidechains.js` is JS only; it passed
`node --check` and was not rebuilt or re-tested in Rust.

## NEEDS HUMAN

- **NFT Send:** stays disabled until the kit's TRANSFER builder is proven on
  testnet (the NFT lane's work).
- **Sidechain RPC credentials:** `divi-gamechain` ignores the
  `DIVI_RPC_USER`/`DIVI_RPC_PASSWORD` the node passes, so on a node with RPC
  auth it cannot read the chain tip. Hand it to the market lane.
- **Sidechain observed earnings:** need a testnet sidechain whose manifest
  declares a paying earnings model; both registered ones declare `none`.

## Status (2026-10-29)

| Item | Status |
|---|---|
| 1. Auto-open and auto-login | Proven on testnet |
| 2. Live config and debug-log editing | Proven on testnet |
| 3. Electrum-backed multi-wallets | Proven on testnet |
| 4. NFT page | Mint and List proven on testnet; Send disabled |
| 5. Sidechain market panel | Listing, install, update, rollback, logs and uninstall proven on testnet; observed earnings open (no paying sidechain) |
