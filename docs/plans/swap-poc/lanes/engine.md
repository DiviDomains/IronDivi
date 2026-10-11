# Lane engine — wave 1e, `crates/divi-swap/` + `bin/divi-swapd/` + `bin/divi-swap/`

Read `_hp2.md` and `_common.md` first. This lane **owns the engine contract** that `_hp2.md`
rule 2 reserves for the orchestrator (the orchestrator delegated it here): `crates/divi-swap/`,
`bin/divi-swapd/`, `bin/divi-swap/`, and `docs/plans/swap-poc/status/engine.md`. The coin lanes
(`ltc`, `zec`, `usdc`, `xmr`) write their engine needs under `- needs:` in their status files —
read those on hp2 at `~/swap-lanes/<coin>/docs/plans/swap-poc/status/<coin>.md` and take them
into account.

**Goal:** the engine swaps DIVI against **any UTXO counter chain**, not just BTC, without
breaking the deployed DIVI↔BTC swap.

1. `Chain` gains `Ltc` and `Zec` (account chains such as USDC wait for the usdc lane's proposal;
   do not add them). Keep the serde names of `Divi`/`Btc` unchanged.
2. The counter chain is part of the offer and the quote: `Offer.counter_chain` and
   `Quote.counter_chain`, `#[serde(default)]` = `Btc`. Collapse the `match` sites in
   `maker.rs`, `taker.rs`, `api.rs` (`Direction::taker_chain/maker_chain`) to "DIVI vs the
   counter chain", so a new UTXO chain needs no engine edit.
3. Amounts and pubkeys keep their JSON names (`btc_amount`, `maker_btc_pubkey`,
   `taker_btc_pubkey`, `btc_confirmations`, `divi_sats_per_btc`, `min_btc_sats`, …) on the
   wire and in the DB — the deployed v0.2.5 daemon and every persisted record use them. Rename
   the Rust fields to `counter_*` if you like, with `#[serde(rename = "btc_…")]`/aliases.
4. Per-chain settings: `SwapConfig` gets per-chain confirmations and MTP lag (a map or a
   per-chain struct) with today's BTC/DIVI values as defaults; old config TOML still parses.
5. **Old state still loads:** `crates/divi-swap/tests/fixtures/v0.2.5/*.json` are real
   persisted records (maker/taker, forward/reverse, both `Done`; the forward ones predate
   `direction`). A test `v025_records_still_load` deserializes all four into the current record
   types and checks `counter_chain == Btc` and the direction. Never edit those fixtures.
6. Daemon/CLI: `divi-swapd` builds the counter backend from config by chain (`[btc]` stays as
   is; `[ltc]`/`[zec]` sections are accepted when those crates expose a constructor — until then
   the mock backend only); offer ids `ltc-divi-testnet` / `divi-ltc-testnet` (and `zec-…`) exist
   on `--backend mock`. `divi-swap` (taker CLI) takes `--counter-chain` (default `btc`) for the
   mock backend.

**Acceptance** (`tools/swap-poc/check-engine.sh`): `divi-swap`, `divi-swapd`, `divi-swap-cli`
green (fmt, clippy `-D warnings`, tests); `Chain::Ltc` and `Chain::Zec` exist; tests
`v025_records_still_load`, `mock_swap_ltc_forward`, `mock_swap_ltc_reverse`,
`mock_swap_zec_forward`, `mock_swap_zec_reverse` (full engine swaps on `MockChain` with the
counter chain set to LTC/ZEC, reaching `Done` on both sides), `old_config_toml_parses`; and the
existing BTC suites still pass unchanged (do not weaken or delete an existing test).

Not in scope: real LTC/ZEC backends (lanes `ltc`/`zec`), the dnsdivi redeploy (orchestrator,
wave 4), anything live.
