# Lane zec status

- done: `ZecBackend` (`impl ChainBackend for ZecBackend`, `crates/swap-chain-zec/src/lib.rs`) —
  wired onto lightwalletd's `CompactTxStreamer` gRPC (`grpc.rs`, hand-written, no protoc) for
  tip height, median-time-past (median of the last 11 blocks' `time` via `GetBlockRange`),
  funding coin selection (`GetAddressUtxos`), broadcast (`SendTransaction` + Premature/Rejected
  classification), confirmations/`htlc_output` (`GetTransaction`), and `find_spend`
  (`GetBlockRange` compact-tx scan for the spending txid/index, then `GetTransaction` for the
  full tx to read the scriptSig). Consensus branch id is read fresh from `GetLightdInfo` on
  every build (brief: never hard-code it). Transaction building/signing/ZIP-244
  digest/self-verification live in `tx.rs`; t-address encoding in `address.rs`.
  `cargo fmt -p swap-chain-zec` clean; `cargo clippy -p swap-chain-zec --all-targets
  --all-features -D warnings` clean; `cargo test -p swap-chain-zec --all-features` green
  (9 passed, 2 `#[ignore]`d); `testnet_api_reachable` run explicitly against the live API and
  PASSED (tip height, median-time-past, and consensus branch id all read successfully from
  `testnet.zec.rocks`).
- running: nothing
- broken: nothing
- left: `live_fund_claim_refund` (needs a funded testnet t-address + `SWAP_ZEC_TEST_KEY_HEX`,
  orchestrator's to run per the lane rules — no secrets on hp2); wave 2 engine wiring (offer
  `zec-divi-testnet`) once `Chain::Zec` lands (orchestrator, wave 1e) and this lane's
  `chain()` placeholder is updated.
- decisions: Step-0 API choice — lightwalletd gRPC at `testnet.zec.rocks:443`; full rationale below.
  - **Step 0 API choice**: primary (and, so far, only) public Zcash testnet API confirmed
    reachable from hp2 is **lightwalletd gRPC at `testnet.zec.rocks:443`** (TLS+ALPN h2
    handshake confirmed; it's the default testnet server in Zecwallet-lite's config, and
    `GetLightdInfo`/`GetLatestBlock` round-trip live as of this check). Its `CompactTxStreamer`
    service covers every primitive the brief needs: `GetLatestBlock` (tip height),
    `GetBlockRange` (per-block `time` for median-time-past, and `CompactTx.vin`
    prevout/index for `find_spend` block-scanning — no outspend/address-spent index exists, so
    `find_spend` always scans, capped at 200 blocks per call like the btc lane's fallback
    path), `GetTransaction` (raw tx + height), `SendTransaction` (broadcast),
    `GetAddressUtxos` (transparent UTXOs by t-address — mined-only, no mempool visibility,
    which is fine since funding only ever wants confirmed coins anyway), `GetLightdInfo`
    (`consensusBranchId` hex string, read fresh per build). Ruled out: Blockchair has no
    Zcash testnet support (404 on `/zcash/testnet/*`). The classic Insight-API testnet
    explorer (`explorer.testnet.z.cash`) and every `*.lightwalletd.com` hostname tried
    (`testnet.lightwalletd.com`, `mainnet.lightwalletd.com`) are DNS-dead now, despite being
    cited by current web search results — those results are stale.
    `rpcnodelist.com`'s Zcash-testnet listing is likewise stale/wrong (cites the dead
    `lightwalletd.com` host and an ethers.js snippet that makes no sense for Zcash).
    `lightwalletd.testnet.electriccoin.co` resolves but answers neither port 443 (TLS
    handshake failure) nor 9067 (filtered) as a gRPC endpoint. CryptoAPIs.io (fronting
    blockexplorer.one's testnet UI) does have testnet Zcash coverage but requires an API key —
    out per the no-secrets-on-hp2 rule and the "public, read-only" brief constraint anyway.
    **No second working endpoint has been found** — the client (`grpc.rs`) is written
    generically over a `Vec<String>` of endpoints with retry+fallback, but ships with one
    entry; see `- needs:`.
  - **Tx/sighash layer is hand-rolled** against the ZIP-244 spec and the *official* test
    vectors (`zcash/zcash-test-vectors` `zip_0244.json`, embedded in `zip244_vectors.rs`)
    rather than depending on `zcash_primitives`/`zcash_transparent`. Looked at both: the full
    `zcash_primitives` stack pulls orchard/sapling/jubjub/redjubjub/bellman-style curve crypto
    that a transparent-only HTLC never touches; the lighter `zcash_transparent` crate (0.10,
    genuinely small deps) only exposes `SighashType`/`SignableInput` plumbing in its `sighash`
    module — the actual digest tree (header/transparent/sapling/orchard BLAKE2b digests,
    ZIP-244 §T.1–T.4/S.2) lives in `zcash_primitives`, so depending on `zcash_transparent`
    alone wouldn't actually avoid writing the digest code by hand. Hand-rolling instead
    (`tx.rs`) kept the added dependency surface to `blake2b_simd` + `bs58` (both tiny, pure
    Rust, no elliptic-curve-pairing anything) and is validated byte-for-byte against all 10
    vectors in `zip_0244.json` — txid and all six sighash-type variants
    (ALL/NONE/SINGLE × with/without ANYONECANPAY). That validation needed a full structural
    parser (`ParsedTx::parse`) that walks an *arbitrary* (possibly shielded) v5 tx's
    Sapling/Orchard byte ranges as opaque fixed-size records, since the vectors are random
    transactions with real shielded content — this doubles as the parser `find_spend` needs
    to recompute the real txid of a counterparty's spend (not just our own transparent-only
    ones). Note: the vectors JSON reverses 32-byte fields for display
    (`zcash_test_vectors/output.py` `tv_value_json`, `bitcoin_flavoured=True` default for the
    "zcash" render target) — the test reverses them back before comparing; our internal digest
    representation is plain protocol order throughout, matching `divi_swap::Txid`'s own
    documented convention.
  - **Script self-verification uses the `zcash_script` crate** (0.6, pure Rust reimplementation
    of Zcash's transparent interpreter — no C++ FFI, no `zcashconsensus`, light deps:
    `bitflags`/`bounded-vec`/`ripemd`/`sha1`/`sha2`/`secp256k1`/`thiserror`), via its
    `interpreter::CallbackTransactionSignatureChecker`, which takes a `sighash:
    &dyn Fn(&Code, &HashType) -> Option<[u8;32]>` callback — we supply our own ZIP-244 digest
    there. This is what the brief's "Zcash's transparent interpreter matches for these
    opcodes" hint pointed at. Tried the brief's literal fallback suggestion (the `bitcoin`
    crate's interpreter) first and it doesn't work for this: `bitcoin::consensus::verify_script`
    goes through the `bitcoinconsensus` C FFI, which recomputes *Bitcoin's own* sighash
    internally from the tx bytes with no hook to substitute ours — every signature we produce
    (signed over the ZIP-244 digest) would be checked against the wrong message and rejected.
    `zcash_script`'s checker is built precisely for pluggable sighash calculation, so used it
    instead, dropping the `bitcoin` crate as a dependency entirely (not needed for anything
    else either).
  - **`Chain` enum workaround**: `crates/divi-swap/src/types.rs::Chain` only has `{Divi, Btc}`
    today — wave 1e "engine generalization" (adding `Chain::{Ltc,Zec,Usdc}`) is explicitly the
    orchestrator's job per `docs/plans/swap-poc/multi-coin.md`, not yet landed, and this lane
    doesn't own `divi-swap/src/types.rs`. `ZecBackend::chain()` returns `Chain::Btc` as a
    placeholder (closest script-shape match: same P2SH/CLTV/ECDSA-secp256k1 shape as BTC)
    until the real variant lands. Nothing in the engine consumes this value yet since wave 2
    wiring for zec hasn't started, so the placeholder is inert, not a correctness risk today.
    One-line fix (`Chain::Btc` → `Chain::Zec`) once the variant exists.
  - HTLC funding/claim/refund scriptCode convention follows standard Bitcoin-style legacy
    sighash semantics (same as the ZIP-244 spec's own test-vector generator): for the
    backend's own P2PKH funding inputs, scriptCode = that input's P2PKH `scriptPubKey`; for the
    P2SH HTLC claim/refund input, scriptCode = the HTLC redeem script (not the P2SH wrapper
    script) — `zcash_script`'s interpreter independently derives the same redeem script from
    the scriptSig during P2SH execution, so signing and verification agree without either side
    hard-coding which branch it's in.
- needs:
  - `Chain::Zec` variant in `crates/divi-swap/src/types.rs` (wave 1e, orchestrator) — see
    decision above.
  - A second public testnet lightwalletd (or other read-only) endpoint, for fallback, if
    anyone knows of one still alive — none found as of this check.
