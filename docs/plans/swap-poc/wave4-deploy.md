# Wave 4: LTC (and ZEC, switched off) on dnsdivi's divi-swapd

Human deploys this from the Mac. Prepared by lane multichain; nothing here has been run on
dnsdivi. Do not start until the BTC reverse chaos run has ended.

**What changes:** `divi-swapd` gains a live LTC backend (litecoinspace.org, Litecoin
testnet4) and serves `divi-ltc-testnet` (maker sells DIVI for LTC). `ltc-divi-testnet` (maker
buys DIVI with LTC) and both ZEC offers are in the config but `enabled = false`. The BTC
offers, `[divi]`, `[btc]`, the DB, credentials and the systemd unit are unchanged.

**Why the gated offers are off:**

| offer | maker locks | blocked on |
|---|---|---|
| `divi-ltc-testnet` | DIVI (already held) | nothing: **on** |
| `ltc-divi-testnet` | LTC | maker LTC address `tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz` holds 0 (checked 2026-10-11). The maker selects coins only after the taker's DIVI lock confirms, so an unfunded maker would leave a taker's DIVI locked until its 6 h refund. |
| `divi-zec-testnet`, `zec-divi-testnet` | DIVI / ZEC | TAZ on the NU7 chain for the maker `tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn` (and takers); `funding.md`: the faucet pays on the stale pre-NU7 fork |

A counter chain whose offers are all disabled, and on which no swap is in flight, gets no
backend: with ZEC off, divi-swapd does not contact lightwalletd and `/healthz` has no `zec`
entry.

## 0. Preconditions

- [ ] BTC reverse chaos run finished; nothing else is driving the maker.
- [ ] **No second maker on the same keys** while dnsdivi serves: `tools/swap-poc/ltc-live.sh
      --backend live`, `e2e.sh` and the chaos drivers start their *own* local `divi-swapd`
      with `maker-divi` / `maker-btc` and a separate DIVI wallet file. Two makers on one key
      track its coins independently and can pick the same UTXOs (a double spend that
      leaves one swap's funding rejected mid-swap). Run those as rehearsals before the
      deploy, not alongside it; check the Mac: `pgrep -fl divi-swapd` → nothing.
- [ ] No swap in flight (the restart is crash-safe, but a clean start is easier to read, and
      a rollback needs it, see §5):
      ```sh
      ssh dnsdivi "curl -s http://127.0.0.1:18480/swaps" \
        | jq '[.[] | select(.state != "Done" and .state != "Aborted")] | length'   # → 0
      ```
- [ ] Mac checkout clean, at `main` **at or after 6037821**: `git merge-base --is-ancestor
      6037821 HEAD && echo ok`. That main carries everything this deploy relies on: LTC
      wiring 5159f29, the counter_chain take check eeec09c, the `enabled` switch + this
      checklist cb345e1, and the two taker fixes 7dec6da / 6037821 (they live in the
      `divi-swap` taker CLI, so the takers' binary must come from the same main; the
      daemon picks them up too since both build the `divi-swap` engine crate).
      `deploy.sh` rsyncs the **working tree**, so no local edits.
- [ ] Taker CLI built from that main on the Mac: `cargo build --release -p divi-swap-cli`
      (`target/release/divi-swap`). A taker CLI older than 6037821 retries a too-late
      maker lock as an error on every poll instead of quietly waiting for its refund.
- [ ] dnsdivi has room for the build: `ssh dnsdivi df -h /opt` (the release build now also
      compiles swap-chain-ltc/-zec/-evm; allow ~3 GB under `/opt/divi-swapd/src/target`).
- [ ] Record what runs now: `ssh dnsdivi "curl -s http://127.0.0.1:18480/healthz | jq -r .version"`
      → `0.2.5` (the deployed binary; the wave-4 build reports `0.2.6`, the workspace
      version since the commit that bumped it), and
      `ssh dnsdivi "sha256sum /usr/local/bin/divi-swapd"` (after the deploy this is the
      `.prev` file's checksum).

## 1. Build target

`deploy/divi-swapd/deploy.sh` (unchanged) rsyncs the repo to `dnsdivi:/opt/divi-swapd/src`
and runs there: `cargo +1.98.1 build --release -p divi-swapd` (toolchain `TOOLCHAIN=1.98.1`,
ubuntu's rustup). The same command was run on hp2 from this tree with rustc 1.98.1 (cold
target, 9 m 31 s), and that binary was smoke-run live against this config (lane status).
Output: `/opt/divi-swapd/src/target/release/divi-swapd`, installed to
`/usr/local/bin/divi-swapd`; the previous binary is kept as `/usr/local/bin/divi-swapd.prev`.

Dry run first and read it: `deploy/divi-swapd/deploy.sh --dry-run`.

## 2. Config diff

`deploy.sh` never overwrites `/etc/divi-swapd/divi-swapd.toml`, so the change is an append
of `deploy/divi-swapd/wave4-offers.toml` (`[ltc]`, `[zec]`, four offers). It reuses the
`maker-btc` credential for LTC and ZEC (`funding.md`), which `divi-swapd.service` already
loads: **no `provision-secrets`, no unit change.**

**Order matters:** append the config *then* run `deploy.sh`, which installs the new binary
and restarts. Never restart the **old** binary with the new config: v0.2.5 ignores
`counter_chain` and `enabled` and would serve all four as BTC offers.

```sh
# a) back up, and make sure none of it is there already (a duplicate table fails to parse)
ssh dnsdivi "sudo cp -p /etc/divi-swapd/divi-swapd.toml /etc/divi-swapd/divi-swapd.toml.pre-wave4"
ssh dnsdivi "sudo grep -nE '^\[(ltc|zec|usdc)\]|ltc-divi|divi-ltc|zec-divi|divi-zec' /etc/divi-swapd/divi-swapd.toml" \
  && echo "STOP: already has wave-4 entries; merge by hand" || echo "clean"

# b) append (tee -a keeps owner/mode root:divi-swapd 0640)
ssh dnsdivi "sudo tee -a /etc/divi-swapd/divi-swapd.toml >/dev/null" < deploy/divi-swapd/wave4-offers.toml
ssh dnsdivi "sudo diff /etc/divi-swapd/divi-swapd.toml.pre-wave4 /etc/divi-swapd/divi-swapd.toml"   # only the snippet
```

The parse of exactly this shape (today's BTC-only config plus the snippet) is pinned by the
test `wave4_snippet_on_the_deployed_config` in `bin/divi-swapd/src/config.rs`. If dnsdivi's
file has drifted (extra `[swap]` overrides, edited offers), the diff in (b) shows it; the
snippet starts with a table header, so anything above it is unaffected.

## 3. Deploy

```sh
deploy/divi-swapd/deploy.sh          # sync, build on dnsdivi, install, restart, waits for /healthz
```

If the service does not come up: `ssh dnsdivi sudo journalctl -u divi-swapd -n 50`. A
config error is printed before any chain is contacted (e.g. `offer on ltc is enabled but
there is no [ltc] section` means the append in §2 did not land).

## 4. Checks (over the tunnel or on dnsdivi)

Scripted, read-only (no keys, no swap; opens and closes its own tunnel):
`tools/swap-poc/wave4-smoke.sh` (`--dry-run` prints the commands). It covers the health,
offers, LTC quote, old-client 400 and `divi-swap quote --counter-chain ltc` items below
and exits non-zero on any failure; the journal, checksum and real-swap items stay manual.

```sh
B=http://127.0.0.1:18480     # on dnsdivi; from the Mac: ssh -N -L 18480:127.0.0.1:18480 dnsdivi
```

- [ ] Startup log has `ltc backend ready`, `no enabled zec offer and no zec swap in flight; not starting the [zec] backend`,
      `offers disabled in config` (listing `ltc-divi-testnet`, `divi-zec-testnet`, `zec-divi-testnet`):
      `ssh dnsdivi "sudo journalctl -u divi-swapd -n 200 -o cat" | grep -E 'backend ready|zec|disabled'`
- [ ] New binary running: `curl -s $B/healthz | jq -r .version` → **`0.2.6`**;
      `ssh dnsdivi "sha256sum /usr/local/bin/divi-swapd /usr/local/bin/divi-swapd.prev"`
      → two different sums, `.prev` = the one recorded in §0; and `/offers` entries carry a
      `counter_chain` field (the v0.2.5 binary has none).
- [ ] Health: `curl -s $B/healthz | jq '{ok, version, divi: .divi.tip, btc: .btc.tip, counters}'`
      → `ok: true`, `version: "0.2.6"`, `counters.ltc.tip` a number with `error: null`,
      **no `zec`**.
      `/healthz` answers 200 even while `ok` is false, so `deploy.sh` returns as soon as the
      daemon is up; `ok` stays false until the DIVI wallet scan catches up from its saved
      cursor (`divi_scan.state`). Re-check until `true`.
- [ ] Offers: `curl -s $B/offers | jq -c '[.[] | [.id, .direction, .counter_chain]]'` →
      exactly `divi-btc-testnet` (btc), `btc-divi-testnet` (btc), `divi-ltc-testnet` (ltc).
- [ ] LTC quote: `curl -s "$B/offers/divi-ltc-testnet/quote?btc_sats=100000" | jq '{counter_chain, btc_amount, divi_amount, btc_confirmations, maker_btc_pubkey}'`
      → `counter_chain: "ltc"`, `divi_amount: 1000000000` (10 DIVI), `btc_confirmations: 2`
      (LTC, testnet profile).
- [ ] Gated offers refuse quotes: `ltc-divi-testnet`, `divi-zec-testnet` → HTTP 400.
- [ ] BTC unchanged: `curl -s "$B/offers/divi-btc-testnet/quote?btc_sats=10000" | jq .counter_chain` → `"btc"`.
- [ ] Old clients fail closed on LTC (creates nothing; the quote stays unused):
      ```sh
      Q=$(curl -s "$B/offers/divi-ltc-testnet/quote?btc_sats=100000" | jq -r .id)
      curl -s -XPOST $B/swaps -H 'content-type: application/json' -d "{\"quote_id\":\"$Q\",\"hash\":\"$(openssl rand -hex 32)\",\"taker_btc_pubkey\":\"02$(printf '11%.0s' {1..32})\",\"taker_divi_pubkey\":\"02$(printf '22%.0s' {1..32})\"}"
      # → 400 {"error":"invalid parameters: offer divi-ltc-testnet swaps DIVI against ltc, but this take request does not name a counter chain …"}
      curl -s $B/swaps | jq length   # unchanged
      ```
- [ ] A real LTC swap against dnsdivi, once the checks pass (forward only; tunnel up). Not
      `ltc-live.sh`: that drives its own local maker (see §0). The taker LTC address
      `tltc1qa826…` holds 0.01 LTC, enough for `min_btc_sats` = 0.001 LTC:
      ```sh
      ref() { echo "op://global_secret_store/IronDivi Swap POC - $1/password"; }
      D=~/.local/state/iron-divi-swap-poc/wave4-ltc; mkdir -p "$D"; chmod 700 "$D"   # outside the repo
      target/release/divi-swap --db "$D/taker.db" --backend live --counter-chain ltc \
        --divi-key "$(ref taker-divi)" --ltc-key "$(ref taker-btc)" \
        balance   # resolves both keys; ltc_address=tltc1qa826…, ltc_balance_sats >= 105000
      target/release/divi-swap --db "$D/taker.db" --backend live --counter-chain ltc \
        quote --maker http://127.0.0.1:18480 --offer divi-ltc-testnet --btc-sats 100000    # counter_chain "ltc"; no keys used
      # then the whole flow, in the background (hours at worst: case-C timelocks); prints "<local id> Done":
      target/release/divi-swap --db "$D/taker.db" --backend live --counter-chain ltc \
        --divi-key "$(ref taker-divi)" --ltc-key "$(ref taker-btc)" \
        run --maker http://127.0.0.1:18480 --offer divi-ltc-testnet --btc-sats 100000
      target/release/divi-swap --db "$D/taker.db" txids --swap <local id>   # maker_state=Done
      ```
      (`quote` broadcasts nothing and creates no swap; don't `accept` separately before
      `run`, which takes its own quote and would leave the accepted one to abort after 30
      min.) LTC keys reuse the BTC refs (`funding.md`).

## 5. Rollback

A v0.2.5 binary ignores `counter_chain` and `enabled`, so **never run it against the
wave-4 config**, and never while an LTC swap is in flight (it would treat the LTC leg as
BTC: it cannot claim or refund it). Prefer the soft rollback.

**Soft (new binary stays; stop LTC):** set `enabled = false` on `divi-ltc-testnet` in
`/etc/divi-swapd/divi-swapd.toml`, then `ssh dnsdivi sudo systemctl restart divi-swapd`. New
LTC takes stop (the offer leaves `/offers`). Swaps already under way on LTC keep running to
`Done`: the daemon still starts the `[ltc]` backend while any non-terminal LTC swap is in the
DB (log: `ltc backend ready`), and stops starting it once none is left. Do not delete the
`[ltc]` section while such a swap exists; the daemon refuses to start if you do
(`swaps in flight on ltc need the [ltc] section`). Count them:
`curl -s $B/swaps | jq '[.[] | select(.quote.counter_chain == "ltc" and .state != "Done" and .state != "Aborted")] | length'`.

**Full (back to the previous binary):**
1. Soft rollback first, and wait until that LTC count is 0.
2. Restore the config: `ssh dnsdivi "sudo cp -p /etc/divi-swapd/divi-swapd.toml.pre-wave4 /etc/divi-swapd/divi-swapd.toml"`.
3. `deploy/divi-swapd/deploy.sh rollback` (restores `/usr/local/bin/divi-swapd.prev`, restarts).
4. Re-run the BTC checks in §4; `/healthz` reports `version: "0.2.5"`, `/offers` shows the
   two BTC offers only, without a `counter_chain` field, and `sha256sum
   /usr/local/bin/divi-swapd` matches §0.

The DB needs no migration either way: records only gained fields (`counter_chain`), which
the old binary ignores; terminal LTC records stay terminal.

## 6. Later switches (no rebuild; edit the file, restart)

- **Reverse LTC** (`ltc-divi-testnet`): fund `tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz`
  with ≥ `max_btc_sats` + fees (0.1 LTC + fees as configured), confirm on litecoinspace,
  set `enabled = true`, restart, quote it. Without a faucet: `ltc_send` (ltc lane,
  `crates/swap-chain-ltc/examples/ltc_send.rs`, key from `SWAP_LTC_KEY_HEX` only, run on
  the Mac) can move LTC from the taker's 0.01 LTC to the maker; that cannot cover 0.1, so
  also lower this offer's `max_btc_sats` to what the maker then holds minus ~5000 litoshi
  of fees (e.g. send 400000, set `max_btc_sats = 300000`), and keep `min_btc_sats` ≤ it.

  **Done (orchestrator, 2026-10-12):** `ltc_send` moved LTC from the taker to the maker, the
  maker's balance landed at 190,000 + fees, so `ltc-divi-testnet` is live on dnsdivi with
  `enabled = true` and `max_btc_sats = 190000` (lower than the 300000 example above — the
  actual send amount; re-check the maker's real balance before raising it).
  `deploy/divi-swapd/wave4-offers.toml` and `wave4_snippet_on_the_deployed_config` both
  reflect this.
- **ZEC**: once the maker t-address holds TAZ on the NU7 chain, set `enabled = true` on both
  ZEC offers (or only `divi-zec-testnet`, which needs no maker TAZ), restart, then check
  `/healthz` shows `counters.zec` with a tip from `testnet.zec.rocks` (the only known
  lightwalletd; no fallback).
