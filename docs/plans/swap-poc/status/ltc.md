# Lane ltc status

- done:
  - **Wave 1**: `crates/swap-chain-ltc` implements `LtcBackend: ChainBackend` over Esplora
    HTTP (`litecoinspace.org/testnet/api`), modeled on `swap-chain-btc` (`tx.rs` copied
    verbatim — script/sighash/serialization are identical for Litecoin SegWit v0;
    `client.rs` copied verbatim — chain-agnostic Esplora client). `address.rs` for `tltc`
    bech32 (segwit v0) address encode/decode via the `bech32` crate directly, since
    `bitcoin::Address` only knows upstream `Network` variants (`bc`/`tb` HRPs), not
    Litecoin's `ltc`/`tltc`. `chain()` now returns `Chain::Ltc` (landed by the orchestrator
    in the multichain-engine commit `f273975`); updated from the Wave 1 `Chain::Btc`
    placeholder — see removed `- needs:` below.
  - **Wave 2**: wired the real `LtcBackend` into both binaries, both directions:
    - `bin/divi-swapd`: new `LtcSection` config (`network`, `esplora_url` default
      `swap_chain_ltc::LITECOINSPACE_TESTNET`, `fallback_esplora_url`, `key`); `DaemonConfig.ltc:
      Option<LtcSection>`; `live_ltc()` in `main.rs` (mirrors `live_btc()`) builds the
      backend and pushes it into `others`; `live_backends()` now accepts offers with
      `counter_chain = "ltc"` when `[ltc]` is configured (still requires `[divi]`+`[btc]`
      unconditionally — unchanged baseline) and gives a pointed error
      ("add [ltc] to the config") otherwise. Deploy example
      (`deploy/divi-swapd/divi-swapd.toml.example`) gained a `[ltc]` section and the
      `divi-ltc-testnet` / `ltc-divi-testnet` offers (both directions, `counter_chain =
      "ltc"`); `divi-swapd.service` gained `LoadCredential=maker-ltc:…` alongside the
      existing divi/btc lines (file path only — no key material, no 1Password item created).
    - `bin/divi-swap` (CLI): new `--ltc-key` flag; `live_backends()` now matches on
      `cli.counter_chain` (`Btc` | `Ltc` | bail for anything else, e.g. `zec`) and builds
      the matching live backend via a new shared `secp_key()` helper (dedupes the
      hex-decode-to-secp256k1-key logic the btc/ltc branches both need). `Backends.live`
      changed from a BTC-only concrete tuple to `Option<(Arc<DiviBackend>, CounterLive)>`
      where `CounterLive::{Btc,Ltc}` gives `Balance` a uniform `.address()` +
      `.esplora_endpoints()` across chains; `btc_balance()` renamed `chain_balance()` and
      now takes an endpoint list instead of a hardcoded-to-BTC network name (BTC and LTC
      serve the same Esplora JSON shape, so one function covers both).
  - **Mock e2e, both directions**: `bin/divi-swapd/tests/multichain.rs`
    (`daemon_swaps_ltc_and_zec_both_ways`, landed with the engine) already exercises the
    full taker flow for `divi-ltc-testnet` and `ltc-divi-testnet` against `MockChain` —
    confirmed passing (`cargo test -p divi-swapd --test multichain`), not written by this
    lane but verified as part of Wave 2's acceptance bar.
  - **Live-wiring smoke tests** (read-only / throwaway keys, no funds, no committed
    secrets): generated two local-entropy 32-byte keys into a scratch `$CREDENTIALS_DIRECTORY`,
    then (a) ran the CLI — `divi-swap --backend live --counter-chain ltc --ltc-key
    credential:ltc-key --divi-key credential:divi-key balance` — printed a correct `tltc1…`
    address and a real (zero) balance from litecoinspace.org; (b) ran the daemon with
    `[divi]`+`[btc]`+`[ltc]` all `credential:`-backed and the two ltc offers configured —
    logged `ltc backend ready`, came up, and `GET /offers` / `GET /healthz` showed both ltc
    offers and `"counters":{"ltc":{"tip":<real height>,"error":null}}`, `"ok":true`. All
    scratch files deleted after.
  - All of: `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo test` clean for `swap-chain-ltc`, `divi-swapd`, `divi-swap-cli`.
    `tools/swap-poc/check-ltc.sh` → PASS.
- running: nothing; idle until landed or redirected.
- left: `live_fund_claim_refund` (`#[ignore] --features live`, `crates/swap-chain-ltc`)
  needs a funded Litecoin testnet address and env `SWAP_LTC_TEST_KEY_HEX`; the daemon's
  `[ltc]` section needs a real `op://…`/`credential:` maker key and (if deployed) a
  1Password item + provisioned credential file — all orchestrator/Bert, from the Mac, per
  lane rules (no secrets, no funded keys on hp2). Everything else in the brief is done.
- decisions:
  - Primary Esplora endpoint `https://litecoinspace.org/testnet/api` verified live
    2026-10-11 (`/blocks/tip/height` → 200; `/v1/fees/recommended` → 200, all rates 1
    sat/vB). No independent public secondary mirror of this API shape was found (checked
    bitaps, blockchair, sochain, blockcypher, atomicwallet, a `testnet4` path on the same
    host — none serve a working Esplora-compatible testnet LTC API).
    `esplora_falls_back_to_secondary` / `esplora_retries_on_429` exercise the fallback /
    retry logic against synthetic wiremock servers, so this is not a coverage gap;
    `esplora_endpoints("testnet")` returns a single-element vec. Add a secondary there if
    one turns up later.
  - `testnet_api_reachable`'s "known block" is the Litecoin testnet4 genesis hash
    (`4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0`), fetched live from
    `/block-height/0` and hardcoded as the expected value — an invariant, not a guess.
  - `FeePolicy::default()` floor is 1 sat/vB (brief), vs. BTC's floor 2;
    `/v1/fees/recommended` is supported by litecoinspace.org and used the same way as the
    btc lane's mempool.space client.
  - `bech32 = "0.11"` added as a direct dependency of `swap-chain-ltc` (already pinned
    transitively via `bitcoin` in `Cargo.lock`, so this did not change any other crate's
    resolution) to reach `bech32::segwit::encode_v0/decode` directly with HRP `tltc`.
  - daemon's `[divi]`+`[btc]` stay mandatory for `--backend live` (unchanged from before
    this wave) — `[ltc]` is additive/optional, needed only when an offer's `counter_chain =
    "ltc"`. Did not relax the `[btc]`-mandatory rule: `AppState`/the `/healthz` JSON shape
    keep a dedicated top-level `btc` field distinct from `counters`, so BTC stays the
    always-present baseline chain; LTC (and any future chain) are additive via `others`/
    `counters`. Not part of this lane's owned paths, but the orchestrator asked for this
    wiring explicitly (multi-coin wave 2 instruction, 2026-10-11).
  - `MOCK_ONLY_CHAINS` (in `bin/divi-swapd/src/config.rs`) keeps `Ltc` in its list even
    though a live backend exists now — `--backend mock` always simulates every counter
    chain the same way (fast, hermetic, no network), independent of whether a live backend
    exists; only the doc comment was corrected, the behavior didn't change.
- needs: nothing from the orchestrator right now.
