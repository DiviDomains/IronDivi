# Lane zec status

- blocked-on-human: no — **funding confirmed on the correct NU7 chain, 2026-10-11 ~19:05
  EDT.** Wave 2 (daemon+CLI wiring, merged side by side with the LTC and USDC lanes) landed
  on main as `4fdae25`. Everything buildable is done. See "done" for the confirmed balances
  and the recommended per-run amount.
- parked: nothing right now. History, for context: the orchestrator's first fauzec.com claim
  (txid `9cf8c2203229ef9577857439452c22b63ba0981b3419ba02dce98a05d7049814`) paid 1 TAZ on a
  **pre-NU7 fork** (tip ~4,474,400, 75s blocks) — not the chain `testnet.zec.rocks` is on — so
  it was unspendable by us. I then found `https://faucet.testnet.valargroup.dev`, verified
  live and on the correct NU7 chain, which pays transparent `tm…` addresses directly (no
  shielded/PCZT hop). The orchestrator claimed from it themselves (Mac IP for the taker
  address, dnsdivi IP for the maker address, so neither counts against hp2's own 24h/IP
  quota — **do not also claim from hp2 today**, per the orchestrator). Both claims are now
  mined and confirmed; see "done" below. `zcash-devtool`'s PCZT flow (under
  "- decisions: funding path") is no longer needed unless this address/faucet ever needs
  topping up again later and the 24h-per-IP quota is the limiter.
- done:
  - **`zec-live.sh case-c` expected duration, reviewed against the local maker profile,
    2026-10-11 ~23:10 EDT.** `zec-live.sh`'s `case-c` TOML override is
    `maker_timeout_secs = 3600` (1h), `taker_timeout_secs = 14410` (~4h 10s — chosen to clear
    `SwapConfig::validate`'s minimum gap, `MIN_TIMEOUT_GAP_SECS = 3h`, by exactly 10s), CLI
    budget `--timeout-secs 21600` (6h). Measured real block times myself just now (read-only,
    no key — `GetLatestBlock`/`GetBlockRange` on `testnet.zec.rocks` for ZEC, `getblockcount`/
    `getblockhash`/`getblock` on `services.divi.domains` for DIVI, both over the last 500
    blocks): **ZEC ≈24.78 s/block** (matches the ~25s NU7 figure already in this file — the
    `ChainParams::builtin` doc comment calling it "75-second blocks" predates the NU7 fix and
    is now stale, though harmless: it only feeds `mtp_lag_secs`, which stays a generous 1800s
    either way, see below) and **DIVI ≈60.16 s/block** (matches the existing "1-minute
    blocks" assumption elsewhere in the repo). Confirmations required: 3 for both ZEC and
    DIVI on testnet (`SwapConfig::profile(Testnet)`); MTP lag doc comment: "about six block
    intervals" to go from broadcast to real median-time-past catching up to a locktime.
    - A key structural fact that explains the shape of the run: **`maker_state=Done` depends
      only on the maker's own leg**, not on the taker (`crates/divi-swap/src/maker.rs`:
      `on_maker_refundable` broadcasts the maker's refund once its own locktime clears, then
      `MakerRefunded → Done` fires as soon as that refund has 1 confirmation — nothing in
      that path reads the taker's state at all). So in case C the **maker finishes in roughly
      an hour**, while the **taker's own CLI `run` process keeps going for ~4 hours** because
      `--never-claim` (`ClaimPolicy::Never`) only releases the taker's claim-hold once the
      *maker leg's* MTP passes the maker's locktime (`bin/divi-swap/src/flow.rs::release`) —
      after which the taker still has to wait out its *own*, much longer, `taker_timeout_secs`
      before `on_refunded` (`crates/divi-swap/src/taker.rs`) can broadcast and confirm its
      refund. This is the standard HTLC safety shape (the second party to lock gets the
      shorter timeout so it can safely refund first) — not a bug, just worth knowing so
      "maker side went quiet an hour in" during a live run isn't mistaken for a stall.
    - **Expected durations** (broadcast-to-`Δ`≈confirmation wait before the other side locks,
      using 3-confirmation and 6-block-MTP-catchup as expected-value estimates — real timing
      has variance, this is not a guarantee):
      - *Forward* (`divi-zec-testnet`, taker locks ZEC first, maker locks DIVI second): maker
        done ≈ (taker-leg ZEC 3-conf wait ≈74s) + 3600s + (DIVI MTP catchup ≈361s) + (DIVI
        1-conf ≈60s) ≈ **4,095s ≈ 1h 8m**. Taker (and thus the overall run) done ≈ 14,410s +
        (ZEC MTP catchup ≈149s) + (ZEC 1-conf ≈25s) ≈ **14,584s ≈ 4h 3m** — inside the 21,600s
        (6h) CLI budget with **~1h 57m to spare**.
      - *Reverse* (`zec-divi-testnet`, taker locks DIVI first, maker locks ZEC second): maker
        done ≈ (taker-leg DIVI 3-conf wait ≈180s) + 3600s + (ZEC MTP catchup ≈149s) + (ZEC
        1-conf ≈25s) ≈ **3,954s ≈ 1h 6m**. Taker (overall run) done ≈ 14,410s + (DIVI MTP
        catchup ≈361s) + (DIVI 1-conf ≈60s) ≈ **14,831s ≈ 4h 7m** — inside the 6h budget with
        **~1h 53m to spare**.
    - **Conclusion: the existing `--timeout-secs 21600` budget is correct and doesn't need
      changing** — both directions land around 4h, with ~1h50m+ of margin either way. `happy`
      (not reviewed in depth here, not what was asked) uses the un-overridden
      `SwapConfig::profile(Testnet)` timeouts but the normal `ClaimPolicy::Asap` path, so it
      finishes in low minutes (dominated by confirmation waits, not the multi-hour timeout
      windows) — no 6h-scale wait there.
  - **Funding confirmed, read-only, 2026-10-11 ~19:05 EDT** (`GetAddressUtxos` on
    `testnet.zec.rocks`, via a new small checker,
    `crates/swap-chain-zec/examples/check_addr_utxos.rs` — no key needed, nothing signed; tip
    at check time was height 4,490,188, confirming this read itself is against the real NU7
    chain, not the pre-NU7 fork):
    - taker `tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk`: **12,500,000 zatoshi (0.125 TAZ)**, 1 UTXO,
      mined at height 4,490,184 (5 confirmations at check time), txid
      `13e335069477201682b6218b3c03b0ad2eed3c972c372ba0d2d216256f1fde8e` vout 0. Matches the
      orchestrator's claim id `8bef7ddd4ac16091ee480f1e41ca2f91`.
    - maker `tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn`: **12,500,000 zatoshi (0.125 TAZ)**, 1 UTXO,
      mined at height 4,490,184 (5 confirmations at check time), txid
      `ebd663bdb5473e6d8c3cfadd033b58d12a8ea2388853d0d03abe724e8f983a07` vout 0. Matches the
      orchestrator's claim id `a1718348432f963f4b4a7cbd52bda8c6`.
    - **Both are confirmed. `zec-live.sh happy` is unblocked for both directions.**
    - ~~Recommended ZEC amount per run~~ **superseded by the ZIP-317 fix below** — the
      ~500–600 zatoshi fee estimate here assumed a plain per-byte rate, which is wrong (see
      the live failure and fix just above/below). The real per-tx fee is ~10,000–15,000
      zatoshi; `E2E_ZEC_SATS=100000` is still comfortably correct (a `happy` run now spends
      up to ~120,000 zatoshi per side instead of ~105,000 — still <1% of the 12,500,000
      zatoshi available per address), no change needed there.
  - **Critical live-run fix, 2026-10-12 ~00:10 EDT: `swap-chain-zec` priced fees per byte;
    Zebra's NU7 mempool requires the ZIP-317 conventional fee, not a per-byte rate.** The
    orchestrator's first live happy-forward run failed at the taker's funding broadcast
    (nothing broadcast, no coins moved): `transaction rejected: ... failed to verify ZIP-317
    transaction rules, transaction was not inserted to mempool: Unpaid actions is higher
    than the limit`. Root cause: `tx.rs`'s `ceil_fee = zats_per_byte * size` priced every
    funding/claim/refund tx at a few hundred zatoshi (at `FeePolicy::default()` = 2 zat/
    byte), but [ZIP 317](https://zips.z.cash/zip-0317) sets a real floor of
    `marginal_fee(5000 zat) * max(grace_actions(2), logical_actions)`, where for an
    all-transparent tx `logical_actions = max(ceil(total vin bytes / 150), ceil(total vout
    bytes / 34))` — Zebra enforces this in its mempool acceptance rules regardless of what
    fee we actually attach, so every tx we built was being rejected before this was caught
    (coincidentally caught before any coins moved, since the taker's own funding broadcast
    is the very first thing a live run does).
    - Fixed in `crates/swap-chain-zec/src/tx.rs`: added `zip317_fee(vin, vout)` computing
      the formula above directly from each probe's actual `TxIn`/`TxOut` serialized byte
      lengths (via their own `write()`, so it can't drift from the real wire format), and
      `probe_fee(probe, zats_per_byte) = max(zip317_fee(...), ceil_fee(...))` — the larger of
      the ZIP-317 floor and the configured per-byte rate, so a future higher-priority
      per-byte rate still wins if ever raised past the floor. `build_funding_tx` (both the
      zero-coin seed and the coin-selection loop) and `build_spend_tx` (claim/refund) both
      switched from `ceil_fee` to `probe_fee` — every tx this backend builds is covered, not
      just funding. `funding_probe_size` became `funding_probe` (returns the probe `ZecTx`
      itself, not just a byte count) so both the per-byte and ZIP-317 numbers can be
      computed from the same probe.
    - For every shape this backend actually builds (1–2 inputs, 1–2 outputs), the ZIP-317
      floor lands on exactly its 2-action grace minimum, **10,000 zatoshi** — confirmed with
      a dedicated pinned unit test, `zip317_fee_pins_expected_values` (1-in/2-out = 10,000;
      1-in/1-out = 10,000 via the grace floor; 3-in/1-out = 15,000 once 3 inputs cross a
      3rd action at 150 bytes/action; 1-in/3-out = 15,000 the same way at 34 bytes/action).
      Also had to rework `funding_selects_coins_and_change`'s amounts/coin values (its old
      ones assumed a ~500 zat fee; the coin-selection *narrative* — two small coins needed,
      dust folds into the fee, a big coin covers a request alone, more coins get pulled in
      as the request grows, insufficient funds is reported — is unchanged, just rescaled,
      with the new exact fees pinned too: 10,000 for 1–2 inputs, 15,000 once a third coin is
      pulled in).
    - Also widened `zec-live.sh`'s `fee_buffer_sats` from 5,000 to 20,000 (covers the real
      10,000–15,000 zat floor twice over) — this only affects the script's printed
      "funding needed" estimate, not the actual on-chain amount (that's `build_funding_tx`'s
      own job, now ZIP-317-aware), but it was wrong/misleading before and is accurate now.
      The orchestrator also asked to widen "the needed-amount check in the funding build" —
      that's exactly `build_funding_tx`'s `needed` calculation above; no separate check
      elsewhere needed changing.
    - Verified: `cargo test -p swap-chain-zec` all green (11 passed, both new tests
      included); `check-zec.sh` and `check-zec-live.sh` (live dry run against
      `testnet.zec.rocks`, throwaway key, builds+signs+consensus-verifies a claim and refund
      with the new fee) both PASS. Did **not** verify against a real broadcast myself (no
      key on hp2) — that's the orchestrator's rerun from the Mac once this lands.
  - **Wave 1b** (`crates/swap-chain-zec/`): `ZecBackend` implementing `divi_swap::ChainBackend`
    over lightwalletd gRPC (`grpc.rs`), hand-rolled ZIP-244/ZIP-229 tx building+signing+digest
    (`tx.rs`), t-address Base58Check (`address.rs`). `ZecBackend::chain()` now correctly
    returns `Chain::Zec` (the placeholder noted in previous status updates was fixed the moment
    `Chain::Zec` landed on main in wave 1e).
  - **Wave 2** (just finished, this session): wired `ZecBackend` into both `bin/divi-swapd`
    (`[zec]` TOML section mirroring `[btc]`/`[ltc]`, `live_zec()` in `main.rs`, offers with
    `counter_chain = "zec"` now get a real backend instead of the old blanket
    `bail!("no live backend")`) and `bin/divi-swap` (`--counter-chain zec`, `--zec-key`,
    `CounterLive::Zec` alongside `Btc`/`Ltc`, `Cmd::Balance` prints `zec_address`/
    `zec_balance_zatoshi` via a new `ZecBackend::balance_zatoshi()` helper). The LTC lane
    landed equivalent wiring in the same commit window (`Chain::Ltc`/`LtcSection`/
    `CounterLive::Ltc`) — merged both sides together rather than picking one, since neither
    lane should silently clobber the other's wiring in these shared files. Mock e2e both
    directions already existed and still passes: `crates/divi-swap/tests/multichain.rs`
    (`mock_swap_zec_forward`/`mock_swap_zec_reverse`, engine-level) and
    `bin/divi-swapd/tests/multichain.rs` (`daemon_swaps_ltc_and_zec_both_ways`, real HTTP API,
    drives `zec-divi-testnet` and `divi-zec-testnet` to `Done` both ways). Full workspace
    (`swap-chain-zec`, `divi-swapd`, `divi-swap-cli`, `divi-swap` engine) green: fmt clean,
    clippy clean (`-D warnings`, `--all-targets --all-features`), every test suite passes
    including the slow property-based crash-recovery tests.
  - **Critical fix found and applied this session: the live testnet only mints v6
    transactions, not v5.** Ran a diagnostic (`tests::probe_live_tx_version`, `#[ignore]`,
    kept in the tree) that fetched 30+ real transactions from `testnet.zec.rocks` across a
    2000-block window: every single one — coinbase and ordinary transfers alike — had
    `version_bytes = 0x80000006`, `version_group_id = 0xD884B698`. The testnet has gone
    through NU6, NU6.1, NU6.3 ("Ironwood", which defines the v6 tx format per
    [ZIP 229](https://zips.z.cash/zip-0229)) and is now past NU7 activation
    (height 4,465,026; our probe ran at tip ≈4,489,566). v5 is still "consensus-valid" per the
    ZIP, but the live network evidently doesn't relay/mine it in practice, so my original
    all-v5 implementation would have had every transaction silently rejected the moment real
    funds were involved. Fixed:
    - `ZecTx` (everything this backend builds) now emits v6: `V6_VERSION_BYTES = 0x8000_0006`,
      `V6_VERSION_GROUP_ID = 0xD884_B698` (the latter cross-checked byte-for-byte against the
      live probe data), one extra trailing `0x00` byte for `nActionsIronwood = 0`.
    - The ZIP-244 digest tree gained the ZIP-229 amendments needed for an all-transparent v6
      tx: a 5th "Ironwood component digest" child (empty: `BLAKE2b-256("ZTxIdIronwd_H_v6", [])`)
      appended after Orchard, and a **new personalization for the Orchard digest itself**
      (`ZTxIdOrchardH_v6` vs v5's `ZTxIdOrchardHash`) — the ZIP mandates this even in the
      empty case, because v6 also moves the Sapling/Orchard/Ironwood anchors from effecting
      data to authorizing data (anchors never appear in our txs anyway, since we never have
      spends/actions, but the ZIP still requires the domain-separation change). New functions
      `combine_txid_v6`/`signature_digest_v6`/`ShieldedDigests::orchard_v6`/`ironwood_v6` in
      `tx.rs`; the existing v5 functions are untouched (still validated against all 10
      official ZIP-244 test vectors — `zip244_sighash_vectors` still passes) and now serve
      `ParsedTx::parse`'s v5 branch for robustness (the live network might still relay a
      stray v5 tx from an older wallet; v4/v5/v6 are all consensus-valid per ZIP 229).
      `ParsedTx::parse`/`txid()` detect v5 vs v6 from the version bytes and dispatch
      accordingly, including a trailing Ironwood section parse for v6.
    - Had the `oracle` agent independently review the whole v6/ZIP-229 diff against the exact
      spec text (no official v6 test vectors exist yet — checked
      `zcash/zcash-test-vectors`, its `TransactionV6` class is still the *withdrawn* ZIP-230
      design with a `zip233Amount` field and placeholder version-group-id, not the current
      ZIP-229/Ironwood one). Oracle confirmed the whole transparent-only path correct and
      found one real latent bug outside that path: `ParsedTx::parse` was computing the
      Sapling digest with v5 personalization/anchor-inclusion unconditionally, which would
      misparse a *foreign* v6 transaction that happens to carry real Sapling spends (ZIP-229
      renames `sapling_spends_noncompact_digest` to `ZTxIdSSpendNH_v6` and drops the anchor
      for v6). Fixed (`ShieldedDigests::sapling` now takes a `v6: bool`); added a
      serialize→parse→txid round-trip test (`claim_script_executes` now also asserts
      `ParsedTx::parse(&tx.serialize()).txid() == tx.txid()`) since that's the strongest
      self-check available without official v6 vectors.
    - Residual risk, stated plainly: without official v6 test vectors, the only *independent*
      ground truth I had was (a) the ZIP-229 spec text itself, read directly (not through a
      summarizer) and (b) the live version_group_id matching byte-for-byte. The
      `zcash_script`-based self-verification in `claim_script_executes`/etc. proves internal
      consistency (sign digest X, then verify against digest X) but — as the oracle flagged —
      does **not** independently prove digest X matches the real protocol, since the
      interpreter is handed our own digest via the `SighashCalculator` callback, not told to
      recompute it. The only way to fully close this gap is a real broadcast once funded,
      which per the no-secrets-on-hp2 rule has to be the orchestrator.
  - Verified `address.rs`'s t-address derivation against the funding table
    (`address::tests::funding_table_addresses_match`, permanent regression test): the
    taker-btc pubkey (`03a7f9cf…5f22f5`) derives `tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk` exactly,
    and maker-btc (`02d05bd3…343a7dd`) derives `tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn` exactly —
    matching `docs/plans/swap-poc/funding.md` and `tools/swap-poc/derive-addrs.py`'s
    methodology (same hash160, same `[0x1d,0x25]` prefix, same Base58Check). No address
    mismatch to report.
  - **Live-readiness dry run** (while funding stays blocked): added
    `crates/swap-chain-zec/examples/zec_live_dry_run.rs` + `tools/swap-poc/check-zec-live.sh`,
    modeled on the LTC lane's equivalent (`ltc_live_dry_run.rs`/`check-ltc-live.sh`). With a
    throwaway key (no funds needed), it resolves the real `testnet.zec.rocks` endpoint, reads
    the live consensus branch id, and builds+signs+consensus-verifies (via `zcash_script`,
    same as the unit tests) a claim and a refund HTLC spend — the first time the v6/NU7 digest
    path ran against a real, live-fetched consensus branch id rather than a hardcoded test
    constant. This directly narrows the "residual risk" noted above (still short of a real
    broadcast, but no longer only self-consistent against a value we chose ourselves).
    Running it immediately **found a real bug**: `build_funding_tx` panicked with
    `attempt to subtract with overflow` when called against an address with a completely
    empty UTXO set (a fresh, never-funded address — exactly this dry run's situation). Root
    cause: `needed` was seeded at `0` before the coin-selection loop, so when the loop ran
    zero times (no coins at all) the `total < needed` guard wrongly passed (`0 < 0` is
    false), falling through to `needed - amount` and underflowing. Same bug class the LTC
    lane hit and fixed in `566417a` — fixed the same way here: seed `needed` from the
    zero-input skeleton's probe size before the loop. Added a
    permanent regression test (`tx::tests::funding_selects_coins_and_change`, extended) for
    a fully-empty coin slice, not just an insufficient-but-nonempty one. Re-ran the dry run
    after the fix: now correctly reports `InsufficientFunds` and finishes clean. Fix is
    purely additive to coin selection, no change to the digest/serialization layer.
  - **`tools/swap-poc/zec-live.sh`**: the happy/case-C, both-direction live driver for ZEC,
    built from scratch this round — `swap-chain-zec` previously only had the dry-run example
    above, not a full driver like LTC's `ltc-live.sh`. Modeled directly on `ltc-live.sh`'s
    current form (including its `--maker-url` support from `a6efd8f`, so ZEC didn't lag
    behind on that from day one): `--scenario happy|case-c|all`, `--direction
    forward|reverse|both`, `--backend live|mock`, `--dry-run`, and `--maker-url URL` (drive an
    already-deployed maker over a tunnel, building nothing locally, keeping the remote's own
    timeout profile). Same `op://…`-ref-only key discipline, same funding-address/amount
    printout, same `--dry-run` stop-before-lock safety invariant. ZEC-specific swaps: `[zec]`
    TOML section (`lightwalletd_url` instead of `esplora_url`/`network`), `--zec-key` CLI
    flag, offers `divi-zec-testnet`/`zec-divi-testnet`, ports 18496/18497 (LTC's live script
    uses 18494/18495, so they don't collide if ever run side by side), price
    `divi_sats_per_btc = 500000000000` (5,000 DIVI/ZEC, matching `mock_counter_offers`'s ZEC
    price). Verified with `--backend mock --dry-run` both directions (quote+accept
    round-trips cleanly against a local mock daemon, no coins/network needed) and with
    `--backend live --dry-run` (fails at the expected point — no secret-broker on hp2 — which
    confirms the `[zec]` config/flag wiring reaches real key resolution before anything
    risky). `shellcheck` clean.
- running: nothing
- broken: nothing
- left:
  - Fund the two addresses (blocked-on-human, see "parked") — first attempt landed on a stale
    pre-NU7 fork and doesn't count. Likely fastest path now: one `curl -X POST` per address to
    `faucet.testnet.valargroup.dev/api/claim` (pays `tm…` directly, no PCZT hop) — see
    "parked" for the exact call and why I left executing it to the orchestrator (shared,
    24h-per-IP-rate-limited resource).
  - `live_fund_claim_refund` (needs `SWAP_ZEC_TEST_KEY_HEX`; orchestrator's to run, no
    secrets on hp2) — once funded, this is the only way to get a true independent
    confirmation that the v6 digest fix above is byte-correct (see residual risk above).
  - `check-e2e-local.sh`-equivalent for zec (a shell-level `--backend mock` e2e per the master
    plan's literal wording) doesn't exist for any non-BTC chain yet, including LTC — this
    looks like a plan-vs-reality gap across both lanes, not something specific to zec; the
    Rust-level mock tests (engine + daemon HTTP) already cover "mock e2e per coin, both
    directions" in spirit. Flagging rather than building one unprompted, since LTC is in the
    same boat and a shared convention (if the orchestrator wants one) should probably be
    designed once, not per-lane.
- decisions: Step-0 API choice — lightwalletd gRPC at `testnet.zec.rocks:443`; full rationale below.
  - **Step 0 API choice**: primary (and, so far, only) public Zcash testnet API confirmed
    reachable from hp2 is **lightwalletd gRPC at `testnet.zec.rocks:443`** (TLS+ALPN h2
    handshake confirmed; it's the default testnet server in Zecwallet-lite's config and in
    `zcash-devtool`'s `-s zecrocks` preset — same server the orchestrator's funding tooling
    will use). Its `CompactTxStreamer` service covers every primitive the brief needs:
    `GetLatestBlock` (tip height), `GetBlockRange` (per-block `time` for median-time-past, and
    `CompactTx.vin` prevout/index for `find_spend` block-scanning — no outspend/address-spent
    index exists, so `find_spend` always scans, capped at 200 blocks per call like the btc
    lane's fallback path), `GetTransaction` (raw tx + height), `SendTransaction` (broadcast),
    `GetAddressUtxos` (transparent UTXOs by t-address — mined-only, no mempool visibility,
    which is fine since funding only ever wants confirmed coins anyway), `GetLightdInfo`
    (`consensusBranchId` hex string, read fresh per build — this is what let the v6 fix above
    be purely additive to the digest/serialization layer with zero config/hardcoding changes).
    Ruled out: Blockchair has no Zcash testnet support (404 on `/zcash/testnet/*`). The classic
    Insight-API testnet explorer (`explorer.testnet.z.cash`) and every `*.lightwalletd.com`
    hostname tried are DNS-dead now, despite being cited by current web search results — those
    results are stale. `rpcnodelist.com`'s Zcash-testnet listing is likewise stale/wrong.
    `lightwalletd.testnet.electriccoin.co` resolves but answers neither port 443 nor 9067 as a
    gRPC endpoint. CryptoAPIs.io (fronting blockexplorer.one) has testnet coverage but needs
    an API key — out per no-secrets-on-hp2. **No second working endpoint found** — `grpc.rs`
    is written generically over a `Vec<String>` with retry+fallback, ships with one entry.
  - **Tx/sighash layer is hand-rolled** against the ZIP-244 (v5) and ZIP-229 (v6) specs and
    the *official* ZIP-244 test vectors (`zcash/zcash-test-vectors` `zip_0244.json`, embedded
    in `zip244_vectors.rs`) rather than depending on `zcash_primitives`/`zcash_transparent`.
    The full `zcash_primitives` stack pulls orchard/sapling/jubjub/bellman-style curve crypto
    a transparent-only HTLC never touches; the lighter `zcash_transparent` crate only exposes
    `SighashType`/`SignableInput` plumbing — the actual digest tree lives in
    `zcash_primitives`, so depending on it wouldn't avoid writing the digest code by hand
    anyway. Kept the added dependency surface to `blake2b_simd` + `bs58` (tiny, pure Rust).
    v5 validated byte-for-byte against all 10 official vectors (txid + all six sighash-type
    variants); v6 has no official vectors yet (see the NU6.3/v6 fix above for how that gap
    was handled — spec-text review + oracle review + live version_group_id cross-check +
    round-trip test, pending a real broadcast for full confidence).
  - **Script self-verification uses the `zcash_script` crate** (pure Rust reimplementation of
    Zcash's transparent interpreter — no C++ FFI), via its
    `CallbackTransactionSignatureChecker`, supplying our own digest. The brief's literal
    fallback suggestion (the `bitcoin` crate's interpreter) doesn't work here:
    `bitcoin::consensus::verify_script` recomputes *Bitcoin's own* sighash internally with no
    hook to substitute ours, so every signature we produce would be checked against the wrong
    message. Dropped the `bitcoin` crate as a dependency entirely.
  - HTLC funding/claim/refund scriptCode convention: for the backend's own P2PKH funding
    inputs, scriptCode = that input's P2PKH `scriptPubKey`; for the P2SH HTLC claim/refund
    input, scriptCode = the HTLC redeem script (not the P2SH wrapper) — `zcash_script`
    independently derives the same redeem script from the scriptSig during P2SH execution.
  - **Funding path** (for the orchestrator, no secrets on hp2 so I can't run this myself):
    the obvious "op read a funded key" path doesn't exist yet for ZEC — the chain needs an
    actual testnet-ZEC transfer, and the only faucet that currently works
    (zcashd end-of-life 2026-07-18 broke the old ones) is **fauzec.com**
    (Zcash Foundation, Zebra-backed, 1 TAZ/address/24h, API currently skips the captcha). It
    only pays to **shielded** addresses (Unified or Sapling — `supported_address_kinds`:
    `["unified","sapling"]` per its `/.well-known/openapi.json`), never transparent, so the
    funds need one hop through a shielded wallet before they can reach our transparent swap
    addresses. **`zcash-devtool`** (github.com/zcash/zcash-devtool, built by the Zcash org,
    uses the same `testnet.zec.rocks` server as us via its `-s zecrocks` preset) does exactly
    this hop via its PCZT (Partially Created Zcash Transaction) commands. Exact steps:

    1. `git clone https://github.com/zcash/zcash-devtool && cd zcash-devtool`
    2. Create a throwaway funding wallet (NOT the swap's own maker/taker key — just a relay):
       `cargo run --release --all-features -- wallet -w ~/zec-funding init --name zec-funding -i ~/zec-funding/age-key.txt -n test -s zecrocks`
    3. `cargo run --release --all-features -- wallet -w ~/zec-funding list-addresses` → note
       the Unified Address (UA) printed.
    4. Claim from the faucet (`ClaimRequest` schema needs `network` + `address`; `memo` is
       optional but fails validation for transparent recipients — not our case here since
       we're claiming to the UA, not a t-address):
       ```
       curl -s -X POST https://fauzec.com/api/v1/claim \
         -H 'content-type: application/json' \
         -d '{"network":"testnet","address":"<UA from step 3>"}'
       ```
       Response has a `request_id`; poll until terminal:
       `curl -s https://fauzec.com/api/v1/status/testnet/<request_id>` — watch for
       `"state":"confirmed"` (or `"failed"` with an `error_code`; the schema lists
       `address_on_cooldown`/`ip_on_cooldown`/`faucet_dry` etc. as the likely failure modes if
       this address or IP already claimed in the last 24h).
    5. `cargo run --release --all-features -- wallet -w ~/zec-funding sync -s zecrocks` then
       `wallet -w ~/zec-funding balance` to confirm the 1 TAZ (100,000,000 zatoshi) landed.
    6. PCZT-send to each swap address (repeat per recipient; `--value` is in zatoshi, so
       2,000,000 = 0.02 TAZ — plenty for many HTLC test rounds with room to spare):
       ```
       cargo run --release --all-features -- pczt -w ~/zec-funding create \
         --address tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk --value 2000000 > taker.pczt
       cargo run --release --all-features -- pczt -w ~/zec-funding prove < taker.pczt > taker.proven
       cargo run --release --all-features -- pczt -w ~/zec-funding sign \
         --identity ~/zec-funding/age-key.txt < taker.pczt > taker.signed
       cargo run --release --all-features -- pczt combine -i taker.signed -i taker.proven > taker.combined
       cargo run --release --all-features -- pczt -w ~/zec-funding send -s zecrocks < taker.combined
       ```
       Then the same for `tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn` (maker).
    7. I can confirm funding landed myself, read-only, no key needed — `GetAddressUtxos` on a
       known public address is exactly what `ZecBackend::balance_zatoshi()` already does; just
       ping me or I'll notice on my next check.

    Separately (not blocking, just worth stating): since the network is past NU6.3/NU7, the
    PCZT-created send above will itself be a v6 transaction with real Sapling/Orchard content
    (shielded spend from the funding wallet) — that's `zcash-devtool`'s problem, not mine, and
    doesn't exercise anything in my code. The transaction my code needs to get right starting
    from that funded t-address onward (building the HTLC funding tx, claim, refund) is the
    part validated above.
- needs: a second public testnet lightwalletd (or other read-only) endpoint, for fallback.
  Re-checked 2026-10-11 ~18:45 EDT: still none currently usable. `lwd.testnet.zec.pro:443`
  (Smart Block Software/zec.pro open infra, also referenced by `zcash-devtool`-adjacent
  tooling) TLS/ALPN-handshakes fine (`CN=zec.pro`, negotiates `h2`) but every actual HTTP/2
  request returns Cloudflare `521 web server is down` — origin is down fleet-wide right now
  (same result on its mainnet and explorer hosts too), so it's documented but not live.
  `testnet.zainod.zingolabs.dev` does not resolve (NXDOMAIN). No `grpcurl` on this host to
  confirm an actual `CompactTxStreamer` RPC beyond TLS/ALPN on any candidate — only
  `testnet.zec.rocks:443` is confirmed to answer real gRPC calls (it's what this crate
  already uses in production). `grpc.rs`'s `Vec<String>` retry+fallback plumbing is ready
  the moment a second one turns up live; nothing to build, just a URL to add.
