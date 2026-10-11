# Wave 4: LTC (and ZEC, switched off) on dnsdivi's divi-swapd

Bert deploys this from the Mac. Prepared by lane multichain; nothing here has been run on
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
- [ ] No swap in flight (the restart is crash-safe, but a clean start is easier to read, and
      a rollback needs it, see §5):
      ```sh
      ssh dnsdivi "curl -s http://127.0.0.1:18480/swaps" \
        | jq '[.[] | select(.state != "Done" and .state != "Aborted")] | length'   # → 0
      ```
- [ ] Mac checkout clean, at `main` including the commit that added this file (it carries
      the `enabled` offer switch; the counter_chain take check is eeec09c, LTC wiring 5159f29).
      `deploy.sh` rsyncs the **working tree**, so no local edits.
- [ ] dnsdivi has room for the build: `ssh dnsdivi df -h /opt` (the release build now also
      compiles swap-chain-ltc/-zec/-evm; allow ~3 GB under `/opt/divi-swapd/src/target`).
- [ ] Record what runs now. `/healthz` `version` does **not** tell old from new: the
      workspace is still `0.2.5` on both (bump it on main first if you want it to, see lane
      status). Use the binary checksum instead:
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

```sh
B=http://127.0.0.1:18480     # on dnsdivi; from the Mac: ssh -N -L 18480:127.0.0.1:18480 dnsdivi
```

- [ ] Startup log has `ltc backend ready`, `no enabled zec offer and no zec swap in flight; not starting the [zec] backend`,
      `offers disabled in config` (listing `ltc-divi-testnet`, `divi-zec-testnet`, `zec-divi-testnet`):
      `ssh dnsdivi "sudo journalctl -u divi-swapd -n 200 -o cat" | grep -E 'backend ready|zec|disabled'`
- [ ] New binary running: `ssh dnsdivi "sha256sum /usr/local/bin/divi-swapd /usr/local/bin/divi-swapd.prev"`
      → two different sums, `.prev` = the one recorded in §0; and `/offers` entries carry a
      `counter_chain` field (the v0.2.5 binary has none).
- [ ] Health: `curl -s $B/healthz | jq '{ok, divi: .divi.tip, btc: .btc.tip, counters}'`
      → `ok: true`, `counters.ltc.tip` a number with `error: null`, **no `zec`**.
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
- [ ] A real LTC swap, once the checks pass: `tools/swap-poc/ltc-live.sh` (ltc lane;
      `--dry-run` first), forward direction only. Takers need the new `divi-swap` with
      `--counter-chain ltc --ltc-key …`; the taker LTC address holds 0.01 LTC (enough for
      `min_btc_sats` = 0.001 LTC swaps).

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
4. Re-run the BTC checks in §4; `/offers` shows the two BTC offers only, without a
   `counter_chain` field, and `sha256sum /usr/local/bin/divi-swapd` matches §0.

The DB needs no migration either way: records only gained fields (`counter_chain`), which
the old binary ignores; terminal LTC records stay terminal.

## 6. Later switches (no rebuild; edit the file, restart)

- **Reverse LTC** (`ltc-divi-testnet`): fund `tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz`
  with ≥ 0.1 LTC + fees (`max_btc_sats` = 0.1 LTC), confirm on litecoinspace, set
  `enabled = true`, restart, quote it.
- **ZEC**: once the maker t-address holds TAZ on the NU7 chain, set `enabled = true` on both
  ZEC offers (or only `divi-zec-testnet`, which needs no maker TAZ), restart, then check
  `/healthz` shows `counters.zec` with a tip from `testnet.zec.rocks` (the only known
  lightwalletd; no fallback).
