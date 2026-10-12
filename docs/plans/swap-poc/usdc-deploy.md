# USDC (Ethereum Sepolia) on dnsdivi's divi-swapd

Bert deploys this from the Mac. Prepared by lane `usdc`; nothing here has been run on
dnsdivi. The config append (§2) is safe to do at any time — both offers start `enabled =
false` and the placeholder htlc address is never dialed while they are. The contract deploy
(§3) and anything after it is blocked on Sepolia ETH landing on the taker (§0).

**What changes:** `divi-swapd` gains a live USDC backend (Ethereum Sepolia, Circle test
USDC) and, once funded, serves `divi-usdc-sepolia` (maker sells DIVI for USDC) and
`usdc-divi-sepolia` (maker buys DIVI with USDC). Both start `enabled = false`. The BTC/LTC
offers, `[divi]`, `[btc]`, `[ltc]`, the DB, credentials and the systemd unit are unchanged.

**Why both offers are off, and what un-gates each:**

| offer | maker locks | blocked on |
|---|---|---|
| `divi-usdc-sepolia` | DIVI (already held) | the real `[usdc].htlc` address (today a placeholder — see §3). Once that lands: nothing else — the taker already holds 20 USDC on Sepolia (tx `0xf5cc6366…28e3`, confirmed 2026-10-11) at `0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C`. |
| `usdc-divi-sepolia` | USDC | the real htlc address, **and** the maker holding USDC. Checked live (read-only, no keys) 2026-10-12: `0x995669a244d511542ca314e4068c754E3F555bd2` holds 0 ETH, 0 USDC. `tools/swap-poc/usdc-live.sh` funds the maker automatically from the taker once run, but that funding step itself needs the taker's Sepolia ETH for gas — the same thing §0 is blocked on. |

A counter chain whose offers are all disabled, and on which no swap is in flight, gets no
backend: with both usdc offers off, divi-swapd does not contact any EVM RPC and `/healthz`
has no `usdc` entry (same mechanism as wave 4's gated ZEC — `wave4-deploy.md`).

## 0. Preconditions (the actual blocker)

- [ ] **Sepolia ETH on the taker.** `0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C` needs
      gas to deploy the contract (§3) and to fund the maker. No ETA as of 2026-10-12; check
      with a read-only balance call (no keys, safe from anywhere):
      ```sh
      cargo run -q -p swap-chain-evm --features live --example sepolia_ops -- \
        balances --addr 0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C
      ```
      `tools/swap-poc/usdc-live.sh --dry-run` runs this same check for both the taker and
      the maker and prints exactly what is still missing.
- [ ] Mac checkout at or after `b99a0f5` (the `UsdcNetwork`/`[usdc].network` plumbing this
      doc's config snippet and commands rely on) and `cbcafc3` (the live driver's current
      shape). `git merge-base --is-ancestor b99a0f5 HEAD && echo ok`.
- [ ] Taker CLI and `sepolia_ops` built from that main on the Mac:
      `cargo build --release -p divi-swap-cli` and
      `cargo build --release -p swap-chain-evm --features live --example sepolia_ops`.
- [ ] No second maker on the same keys while dnsdivi serves usdc (same rule as wave 4,
      `wave4-deploy.md` §0) — `tools/swap-poc/usdc-live.sh` starts its *own* local
      divi-swapd with the `maker-divi`/`maker-btc` credentials and a separate DIVI wallet
      file; never run it against the same keys at the same time as dnsdivi serves an
      enabled usdc offer.

## 1. Build target

Same binary as wave 4 (`deploy/divi-swapd/deploy.sh`, `cargo +1.98.1 build --release -p
divi-swapd`) — no new target. The `swap-chain-evm` crate (and so EVM/USDC support) is
already part of the regular workspace build; nothing coin-specific to add here. Confirm the
installed version answers `/healthz`'s `.version` at or after this lane's EVM landings once
deployed.

## 2. Config diff (safe to do now, before the contract exists)

`deploy.sh` never overwrites `/etc/divi-swapd/divi-swapd.toml`, so the change is an append of
`deploy/divi-swapd/usdc-offers.toml` (`[usdc]`, two disabled offers). It reuses the
`maker-btc` credential (`funding.md`), already loaded by `divi-swapd.service`: **no
`provision-secrets`, no unit change.**

```sh
# a) back up, and make sure none of it is there already (a duplicate table fails to parse)
ssh dnsdivi "sudo cp -p /etc/divi-swapd/divi-swapd.toml /etc/divi-swapd/divi-swapd.toml.pre-usdc"
ssh dnsdivi "sudo grep -nE '^\[usdc\]|usdc-divi|divi-usdc' /etc/divi-swapd/divi-swapd.toml" \
  && echo "STOP: already has a usdc entry; merge by hand" || echo "clean"

# b) append (tee -a keeps owner/mode root:divi-swapd 0640)
ssh dnsdivi "sudo tee -a /etc/divi-swapd/divi-swapd.toml >/dev/null" < deploy/divi-swapd/usdc-offers.toml
ssh dnsdivi "sudo diff /etc/divi-swapd/divi-swapd.toml.pre-usdc /etc/divi-swapd/divi-swapd.toml"   # only the snippet

# c) restart to pick it up — harmless: both offers are disabled, and divi-swapd never
# starts a backend for a chain with no enabled offer and no swap in flight
ssh dnsdivi sudo systemctl restart divi-swapd
curl -s http://127.0.0.1:18480/healthz | jq '{ok, counters}'   # no "usdc" key yet — expected
```

The parse of exactly this shape (the wave-4-deployed config plus this snippet, contract
still undeployed) is pinned by the test
`usdc_offers_snippet_on_top_of_the_wave4_deployed_config` in `bin/divi-swapd/src/config.rs`.
If dnsdivi's file has drifted, the diff in (b) shows it.

## 3. Deploy the contract (blocked on §0)

One Rust command, no `forge` needed (`crates/swap-chain-evm/examples/sepolia_ops.rs`,
embeds the compiled bytecode). Run from the Mac once the taker has gas:

```sh
SWAP_EVM_KEY_HEX="$(op read 'op://global_secret_store/IronDivi Swap POC - taker-btc/password')" \
  cargo run -q -p swap-chain-evm --features live --example sepolia_ops -- deploy
# prints:
#   htlc_address: 0x...
#   tx: 0x...
```

**Gas estimate** (measured against anvil with the identical compiled bytecode that goes to
Sepolia — `docs/plans/swap-poc/status/usdc.md`): **725,869 gas**, one transaction, no
constructor args. At Sepolia's typically-observed 1–10 gwei that is roughly 0.0007–0.007
ETH; at a congested 50 gwei, roughly 0.036 ETH. `usdc-live.sh`'s own funding step sends the
maker 0.02 ETH per planned run as a separate, comfortable margin for *its* claim/refund
transactions (`approve` ~29–46k gas, `lock` ~185–201k, `claim` ~74k, `refund` ~70k) — the
deploy's own gas comes out of the taker's balance directly, not the maker's.

`tools/swap-poc/usdc-live.sh` runs this exact command itself when no `--htlc` is given
(idempotent: pass `--htlc 0x...` on later runs to skip redeploying). Either way, once you
have the real address:

```sh
# usdc-offers.toml's placeholder, now replaced:
ssh dnsdivi "sudo sed -i 's/^htlc = \"0x0*\"/htlc = \"0xREAL_ADDRESS_HERE\"/' /etc/divi-swapd/divi-swapd.toml"
ssh dnsdivi "sudo grep -A2 '^\[usdc\]' /etc/divi-swapd/divi-swapd.toml"   # confirm
ssh dnsdivi sudo systemctl restart divi-swapd
```

## 4. Flip `enabled = true` (blocked on §0 and §3)

`divi-usdc-sepolia` can flip the moment §3 lands — the taker is already funded (table
above). `usdc-divi-sepolia` additionally needs the maker to hold USDC; fund it first (either
`tools/swap-poc/usdc-live.sh`'s automatic funding step, or `sepolia_ops send-usdc --to
0x995669a244d511542ca314e4068c754E3F555bd2 --units <n>` directly from the taker key), then
check its balance the same read-only way as §0 before flipping.

```sh
ssh dnsdivi "sudo sed -i '/id = \"divi-usdc-sepolia\"/,/^$/ s/enabled = false/enabled = true/' /etc/divi-swapd/divi-swapd.toml"
ssh dnsdivi "sudo grep -B1 -A6 'divi-usdc-sepolia' /etc/divi-swapd/divi-swapd.toml"   # confirm only this offer flipped
ssh dnsdivi sudo systemctl restart divi-swapd
curl -s http://127.0.0.1:18480/healthz | jq '{ok, counters}'          # now has a "usdc" entry
curl -s "http://127.0.0.1:18480/offers/divi-usdc-sepolia/quote?btc_sats=1000000" \
  | jq '{counter_chain, btc_amount, divi_amount, btc_confirmations}'  # counter_chain: "usdc"
```

## 5. Rollback

**Soft (new config stays; stop usdc):** set `enabled = false` on whichever usdc offer was
flipped, `ssh dnsdivi sudo systemctl restart divi-swapd`. Swaps already under way on usdc
keep running to `Done` (same `swaps in flight` protection as every other counter chain —
`bin/divi-swapd/src/config.rs::counter_backends_to_start`); the daemon refuses to start if
you also remove the `[usdc]` section while one is in flight.

**Full (undo the append entirely):**
1. Soft rollback first; wait until `curl -s http://127.0.0.1:18480/swaps | jq '[.[] | select(.quote.counter_chain == "usdc" and .state != "Done" and .state != "Aborted")] | length'` is `0`.
2. `ssh dnsdivi "sudo cp -p /etc/divi-swapd/divi-swapd.toml.pre-usdc /etc/divi-swapd/divi-swapd.toml"`.
3. `ssh dnsdivi sudo systemctl restart divi-swapd`.
4. `/healthz` has no `usdc` entry again; `/offers` drops both usdc ids.

No DB migration needed either way: records only gained a `counter_chain` field (already true
since wave 4), which an older binary ignores; terminal usdc records stay terminal.
