# Dependency advisories: SQLite, `crypto-bigint`, `cggmp21`

Recorded against RustSec advisory-db revision `55e1c3dfbd834237a05bbbf7b50ba3b5be27b662`
(2026-11-21), `Cargo.lock` of this tree. Re-run the checks below before every release.

| Advisory | Crate in lock | Reaches | Status |
|---|---|---|---|
| RUSTSEC-2026-0459 (SQLite WAL, uninitialised page-cache read) | `libsqlite3-sys` 0.30.1 → **0.39.1** (`rusqlite` 0.32 → **0.41**, bundled SQLite 3.54.x) | `divi-swap` store and input reservations (swap tools only) | **Fixed** (`>= 0.39.0`). |
| RUSTSEC-2026-0387 (`crypto-bigint` timing variability, fixed `>= 0.7.6`) | `crypto-bigint` 0.5.5 | `swap-chain-evm`, `swap-chain-xmr`, `divi-swap-xmr`, `divi-swapd`, `divi-swap` | **Unresolved; real-value xmr and usdc held.** |
| RUSTSEC-2025-0127 (`cggmp21` presignatures, no fixed release) | `cggmp21` 0.6.3 | `divi-swap-xmr` (`jsig.rs`) | **Unresolved; real-value xmr held.** Applicability below. |

`irondivid` and `irondivi-cli` link none of the three affected crates (`crypto-bigint` there is
0.7.10, which is patched): `cargo deny check advisories` is clean for both roots.

## SQLite

`rusqlite` is a workspace dependency used only by `divi-swap` (not on `wasm32`). `divi-swap` opens its
store and reservation databases in WAL mode, so the advisory's trigger (opening a database whose
`-wal` sibling a less trusted party wrote) applies if an operator opens such files; the fix is the
bundled SQLite 3.54 in `libsqlite3-sys >= 0.39`. Moving to 0.41 also moves `hashlink` 0.9 → 0.12,
`thiserror` 2.0.18 → 2.0.21 (required by `rsqlite-vfs`, a `wasm32-unknown-unknown`-only dependency of
`rusqlite`'s default `ffi-sqlite-wasm-rs` feature) and drops `ahash`. API review for 0.33–0.41: no
`u64`/`usize` parameters (all `as i64`/`u32`), only `execute_batch` runs multiple statements, no
`ValueRef`, hook, vtab or statement-cache use, and the `PRAGMA`s used (`journal_mode`, `synchronous`,
`locking_mode`, `user_version`) are valid. Needs MSRV 1.89 (toolchain 1.98.1 here).

## `crypto-bigint` 0.5.5

Only the swap graph links it, through `elliptic-curve` 0.13 / `k256` 0.13 (`alloy-signer`,
`alloy-consensus`, `alloy-signer-local`, `generic-ec-curves`), `dalek-ff-group` (via `ciphersuite`/`dkg`
in `swap-chain-xmr`) and `monero-ed25519` (via `monero-wallet`). Every stable release published by
2026-11-21 pins `crypto-bigint ^0.5` or `elliptic-curve ^0.13`: `alloy-signer` 2.6.1, `dalek-ff-group`
0.5.0, `ciphersuite` 0.4.2, `dkg` 0.4.2, `monero-ed25519` 0.1.0. `elliptic-curve` 0.14 and `k256` 0.14
exist, but nothing here can adopt them without those upstreams or forking and patching them, which
this change does not do. Nothing was ignored, pinned back or patched.

Whether the timing leak is exploitable through these callers (EVM signing with `k256`, Monero
scalar/point code in `dalek-ff-group`, `generic-ec` secp256k1 in `divi-swap-xmr`) is not established,
and is not claimed either way.

## `cggmp21` 0.6.3

The advisory concerns two uses of `Presignature`: with HD derivation (`set_derivation_path`) and with
"raw" hash signing (`issue_partial_signature`). Locally: the workspace enables only
`curve-secp256k1` and `state-machine` (the `hd-wallet` feature is off, so `cggmp21-keygen/hd-wallet`
and `set_derivation_path` are not compiled), and `divi-swap-xmr/src/jsig.rs` imports only the
re-exported primitives (`generic_ec`, `paillier_zk`, `fast_paillier`, `security_level`,
`PregeneratedPrimes`); nothing calls `signing`, `Presignature` or `hd_wallet`. On that evidence the
two advisory scenarios are not reachable. This does not certify `jsig.rs`, the Paillier/ZK
primitives, or the unmaintained 0.6.x line; the advisory's fix is a migration to `cggmp24`, which
needs a reviewed replacement.

## Hold

The hold covers **new** real-value xmr and usdc swaps only. It never blocks config load, `status`,
`tip`, `balance`, `claim`, `refund`, or the engine paths that recover a swap already under way, so
an operator's refund path survives the cutover.

New-swap admission:

* usdc requires a non-mainnet label (`check_advisory_hold`) **and** an authenticated network: the
  RPC endpoint(s) must report the chain id of `[usdc].network` (`UsdcBackend::authenticated_chain_id`;
  alloy signs with the endpoint's chain id, so a label is not proof). A mismatch, disagreeing
  endpoints, or an unreadable endpoint is a hold, not admission.
* xmr requires a non-mainnet label; the monerod nettype check already authenticates the node.

Enforcement:

* `divi-swapd`: `DaemonConfig::advisory_holds()` and the live chain-id check feed
  `Maker::with_admission_hold` / `XmrMaker::with_admission_hold`. `quote`, `accept`, `setup` and
  the xmr rounds are refused (HTTP 400); swaps that never got to a lock are aborted; a signed maker lock not
  marked sent is kept unreleased and never first-broadcast (it may have gone out before a crash),
  and runs on once the chain shows it; funded swaps keep claiming, refunding and rebroadcasting. A held chain with no in-flight swap starts
  no backend. Holds are logged at startup.
* `divi-swap`: `accept` and `run` check admission before contacting the maker. Preparing a USDC
  quote records the endpoint-checked chain ID, token address, and HTLC address in the local session (mock sessions
  record a distinct mock identity). Before building or first broadcasting **either** leg, the
  taker requires the quote's USDC backend to recheck the chain ID and match both configured contract addresses. A different
  permitted testnet, a default label alone, or a missing backend is not sufficient. For a
  legacy unfunded `Accepted` session with no binding, accept a fresh quote; never infer the
  old network from new flags. After a crash, an unmarked signed lock is retained, not first
  sent without admission; a sent marker or positive chain observation allows recovery.
  Claims and refunds of funded swaps are not admission-gated. `XmrTaker` gates `prepare`
  and new XMR locks. Opening a native swap DB for writing upgrades its schema marker to 4;
  keep both CLI and daemon readers current. Older marker-aware binaries refuse the upgraded
  DB rather than silently dropping the binding. Do not roll back to pre-marker binaries.

Residuals: `eth_chainId` is endpoint-asserted (no genesis-hash pin; an operator-run RPC that lies is
out of scope). The maker records its own binding at accept and checks it before building and first sending its funding. The contract binding checks address continuity across restarts. It does not attest deployed bytecode. Recovery
signing still uses the advisory stack until it is replaced. btc, ltc, zec and divi do not link the
affected crates and are not held.

**Lift** when `cargo deny --offline --manifest-path bin/divi-swapd/Cargo.toml check advisories`
and the same for `bin/divi-swap` are clean without ignores: a release of the signer/Monero stack on
`crypto-bigint >= 0.7.6`, and a reviewed replacement or release for `cggmp21`.

## Commands

```
cargo metadata --locked --format-version 1 >/dev/null
cargo tree --locked -i crypto-bigint@0.5.5 -e normal,build --target all
for p in irondivid irondivi-cli divi-swapd divi-swap; do
  cargo deny --manifest-path bin/$p/Cargo.toml check advisories; done   # swap roots: 0387, 0127 expected
cargo deny check bans licenses sources
```
