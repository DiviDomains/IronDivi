# Lane zec status

- blocked-on-human: yes — see "parked" below. Wave 2 (daemon+CLI wiring, merged side by side
  with the LTC and USDC lanes) landed on main as `4fdae25`; everything buildable without coins
  is done. Keep reading, this is not a full stop.
- parked: ZEC testnet funding. **Update 2026-10-11 ~18:45 EDT — found a faucet that pays
  transparent addresses directly, no shielded hop needed; this may unblock funding with zero
  secrets.** Earlier: the orchestrator's fauzec.com claim (txid
  `9cf8c2203229ef9577857439452c22b63ba0981b3419ba02dce98a05d7049814`) paid 1 TAZ on a
  **pre-NU7 fork** (tip ~4,474,400, 75s blocks) — not the chain `testnet.zec.rocks` (what
  `ZecBackend` targets) is on, which is past NU7 activation (height 4,465,026, tip
  ~4,489,857+, 25s blocks) — so that TAZ is unspendable by us. Do not switch `ZecBackend` to
  the pre-NU7 server; NU7 is the real testnet.
  - **New faucet, verified live and on the correct chain just now**:
    `https://faucet.testnet.valargroup.dev` (Valar Group; wallet is `zecd`,
    github.com/zecrocks/zecd, synced against "Zakura" NU7 testnet infra). I independently
    curled it myself (no secret involved — it's a public HTTP API, nothing resolved from
    1Password): `GET /api/status` → `{"network":"testnet","ready":true,"chainHeight":4490176,
    "walletSynced":true,...}`, height matching our own backend's live tip (`check-zec-live.sh`
    read ~4,489,906 minutes earlier) — this is the real NU7 chain, not the stale fork. Its own
    `/api/claim` error message confirms it accepts **`utest1…`, `ztestsapling…`, or `tm…`**
    addresses — i.e. it pays transparent t-addresses *directly*, unlike fauzec.com
    (shielded-only). If this holds, **the whole zcash-devtool/PCZT relay-wallet hop in the
    funding path below becomes unnecessary** for this faucet specifically: one `curl -X POST
    .../api/claim -d '{"address":"tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk"}'` (repeat for the
    maker address) could fund both swap addresses directly, no key/signature/human step at
    all. **I have not run this claim myself** — its documented limit is 0.125 TAZ per *IP*
    per 24h (`"payout":"0.125","ipLimit":"0.125","windowSeconds":86400`), and hp2's IP may be
    shared across lanes/sessions, so one claim exhausts the quota for a day; leaving the
    actual claim (which address first, whether to also try `ztestsapling…` to this faucet's
    own shielding-then-PCZT path as a backup) to the orchestrator's call rather than spending
    that scarce, shared resource unilaterally. Status page:
    `https://status.testnet.zakura.valargroup.dev/`.
  - Other faucets checked: `zcashfaucet.jinolabs.xyz` is reachable
    (`/api/status` → `"sender":"zallet"`, `"network":"testnet"`) but reports 0 drips in the
    last 7 days as of this check — looks paused/dry, not a reliable second source right now.
  - Funding still also has the slower fallback path if the faucet above doesn't pan out: a
    human with Mac/1Password access running `zcash-devtool`'s PCZT flow — exact steps are
    under "- decisions: funding path" below, copy-paste ready — but any faucet claim (fauzec
    or otherwise) must be verified against the NU7 chain before relying on it (check the
    claiming wallet's `-s zecrocks` sync reaches a NU7-height tip, not a stale fork, before
    trusting its balance).
  - Once either swap address (`tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk` taker,
    `tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn` maker) shows a balance via `GetAddressUtxos` on
    `testnet.zec.rocks` (I can verify myself, read-only, no key needed), I'll know funding
    actually landed. `live_fund_claim_refund` still also needs `SWAP_ZEC_TEST_KEY_HEX`, a
    secret, so running it is the orchestrator's either way.
- done:
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
