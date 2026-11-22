# Security remediation validation

Validated baseline: `3dfacf7b518ec2eb7c32b43c209c463bb19f57cd`.

This change integrates network resource limits, web authority restrictions, wallet persistence, pre-activation post-quantum policy, private spork containment, C++ signed-message parity, coherent UTXO cache ownership, bounded Electrum processing, authenticated swap funding identity and conservative spend discovery/recovery.

## Validation

The final 1,610-file source manifest was verified against the Linux build before and after testing and against the applied main tree. Electrum/RPC/storage/daemon gates passed 269 tests; focused swap recovery passed 166 tests and three actual-daemon loopback scenarios. These counts overlap broader suites. The combined suite recorded 1,345 passes, one failure and 11 ignored tests. The failure, `embedded_bytecode_matches_a_fresh_forge_build`, reproduces the baseline byte-for-byte: both 3,500-byte arrays match the corresponding baseline arrays, differing from each other only at offsets 3457–3488 in Solidity metadata. Contract reproducibility remains unresolved; the full suite is not green.

C++ address controls matched on macOS. Windows execution remains unverified. Recovery tests use disposable signing material and simulated chains, not production funds.

## Operational constraints

Swap schema 4 requires compatible maker and taker programs. Ambiguous unfunded USDC records need a new authenticated quote. Existing signed transactions and reservations must be preserved during uncertain observations. Marker-aware older readers refuse upgraded databases. Pre-marker rollback requires reconciliation of all sends and reservations since backup; changing the database version alone is unsafe. Preserve a consistent SQLite database and WAL, journals, signed transactions and wallet reservations before upgrades. Read-only refusal on WAL databases can create empty WAL/shared-memory sidecars without changing the main database.

Electrum reserves one of eight backend slots for FIFO notification work, leaving seven concurrent request jobs. Each session retains at most one waiter. Slow admitted database work or client writes can delay later notifications. The 20,000-subscription test completes in 79 uncontended ticks; this is not a production latency guarantee.

No deployment or real-fund transaction is part of this change. This validation covers the integrated changes, not closure of every item in the broader security/performance review.

## Standard compact block-signature key encoding

The P2PKH and vault checks now hash the recovered key using the encoding selected by standard compact headers: 27–30 uncompressed, 31–34 compressed. This follows the pinned C++ Divi checker at `1b553a3b`. Storage and crypto suites passed 629 tests with one ignored test. Independent checks reran both focused regressions and the C++ historical checker. Mainnet block 2,000,000 has the same block hash and accepted signature in both clients. Historical coverage is one block; chain-wide replay, nonstandard headers, script classification, P2PK signature-policy parity and signing for uncompressed stake keys remain outside this correction.

## Undo integrity and restart recovery

Disconnect and startup verification reject missing, duplicate or extraneous undo coins and invalid coin heights or values. Retained origin outputs are checked before disconnect publication; legacy reconstruction fails when required history or an output is unavailable. Embedded UTXO decoding accepts only the historical versionless form or a four-byte version suffix. Versionless records default to version 1; a missing non-1 version cannot be recovered from those bytes alone.

The combined A1 and undo source passed 523 storage tests. Four targeted assertions failed with the prior verifier/decoder restored. Disposable snapshot-boundary tests cover refusal with coherent persisted state, restart, repair or legacy reconstruction, and comparison with clean replay. One real-chain test required an external database and was skipped. Pruned auxiliary provenance and persistent side-branch storage bounds remain open.

## Diagnostics admission, wallet timeout and snapshot installation

The diagnostics receiver groups IPv6 clients by /64, normalizes mapped IPv4 addresses, charges each received chunk atomically, and enforces the size and daily limits before writing the first chunk. Four upload permits, a ten-minute body deadline, cancellation cleanup, a 10 GiB store budget and a 1 GiB filesystem free-space floor bound the tested admission paths. These policies assume one receiver per directory on Unix. Other processes can consume free space after admission; filesystem operations themselves have no hard latency guarantee.

Wallet RPC validates a signed-integer timeout before changing unlock state. This deliberately differs from C++ malformed-input ordering while retaining zero and negative timeout behavior. Wallet migration and HD restoration are separate work.

Signed snapshot import pins the authenticated manifest root, verifies the copied staging files, and uses a private staging directory per attempt. Concurrent imports cannot delete each other's staging files; a completed nonempty database prevents another install. Signature-only CLI output explicitly states that payloads were not checked. Snapshot historical provenance remains subject to the known-state and auxiliary-data limitations above.

On the exact source, 11 snapshot tests, 15 receiver tests and four wallet passphrase tests passed, and irondivid built. Parent reruns confirmed the snapshot and receiver suites. Restoring the shared staging path caused the overlap regression to fail; removing the first-chunk bounds caused both size and daily-quota regressions to fail. Source hashes matched before and after the controls. Disposable CLI checks covered conflicting and case-insensitive matching explicit roots, changed payload rejection, and rejection of a replacement manifest against a saved authenticated root. The manifest and payload substitutions were not injected between verification and use within a single CLI invocation; those particular race schedules remain unexecuted. No production deployment or live-wallet operation was performed.

## Wallet persistence and HD recovery

Passphrase migration and key writes now distinguish confirmed, uncertain and cleanup-failed outcomes. A deferred lock retains undurable secrets in memory while refusing spends and exports, until persistence can finish. Cleanup covers logical records and visible files, not backups or physical media. Rollback to an older wallet implementation needs a pre-migration backup and its original passphrase, plus separate recovery of keys imported since that backup. See wallet-encryption.md for the operational details.

HD discovery refills receiving and change lookahead to a fixed point, replays earlier available history when later discovery reveals keys, and preserves the rewind across refill errors. Locked discovery records a durable replay obligation before advancing its cursor. After unlock, recovery saves transactions, scan progress and obligation clearance together. Each later deferred discovery reasserts the marker even if an earlier checkpoint reached disk but reported a sync error. Older encrypted checkpoints with ambiguous discovery trigger one conservative replay. Discovery remains limited by available block data and the configured address gap.

The preceding candidate passed 957 wallet, staking and RPC tests and a daemon compile check. Independent review added a regression for a checkpoint written despite a reported error; it failed with two of four payments recovered before the final correction and recovered all four afterward. The final source passed 29 focused wallet tests, a separate overlapping 20-case passphrase run, and four RPC passphrase tests. All 1,613 source hashes matched the applied tree and the two build hosts. The full 957-test suite was not repeated after this narrow final correction. All wallets and payments in these tests were disposable fixtures; hardware power-loss behavior, physical erasure and live-wallet migration were not exercised.

## Maker chain-time observation deadlines

Four maker chain-time reads now use the existing 20-second gate budget. The refund eligibility read shares that budget across the held-read decision and primary-only retry; expiry returns a retryable error before eligibility is evaluated. Existing backend errors retain their existing policy. No new timer surrounds transaction construction, broadcast, reservation mutations, confirmations or spend scans. This is a bound on cooperative observation waits, not on total step duration or recovery deadlines.

The native engine, held-read, pending-cursor, coin-race, admission and adapter reservation suites passed 384 tests. The applied maker source hash matches the tested source. The focused helper test verifies successful values, preserved backend errors and retryable timeout mapping. No production latency or scheduler fairness guarantee is established.

## Explicit swap simulation selection

The daemon defaults to live operation and rejects missing DIVI or BTC configuration before opening the swap store. Simulation requires `--backend mock`; existing simulation launchers must add it and use a separate database. Fully configured live launchers retain their command line. Backend selection flags conflict with store inspection and reservation-release commands. This does not bind a database to a backend identity: an explicit mock invocation can still select an inappropriate store.

The patched source passed 43 daemon tests, two startup/CLI tests and three funded USDC recovery scenarios using default live selection. Missing and partial configurations were checked against fresh and existing stores. All four changed source hashes matched the applied tree. No live service was restarted or deployed.

## Daemon database mode binding and legacy migration

New daemon databases atomically bind live or mock mode in SQLite application_id with schema 5 before recovery or reservation access. Opposite-mode startup and generic store writers refuse the bound store; read-only inspection remains available. Existing unbound stores require the explicit offline binding command documented in deploy/divi-swapd/README.md. Operators must establish the original mode from the original installation; BTC/DIVI records alone cannot prove it. Persisted USDC admissions can reject a contradictory declaration. The command only changes the two header fields transactionally and never starts backends or releases reservations.

Independent verification passed 64 Rust and five Python tests on the exact seven-file patch. The funded legacy fixture refused automatic startup, rejected contradictory mock attestation, preserved its complete logical SQL dump through live binding, and resumed daemon recovery against simulated endpoints. Tests cover competing declarations, immutable bindings, interrupted updates and unsupported layouts. Schema-4 reader refusal was separately verified by the builder.

Upgrade requires exclusive maintenance and a consistent backup. After schema-5 activity, recovery must use the current database and a binding-aware binary in its original mode; stale snapshots can lose funding and reservation history. Pre-marker binaries must remain offline. No real store was migrated and no deployment occurred.

## Maker completed-history enumeration

The native maker tick now filters terminal records in SQLite after validating serialized history and state tags in a consistent read transaction. It revalidates on external database commits; malformed records remain errors, inconsistent tags disable the fast path, and MakerRefunded still advances to Done. Full-history APIs and memory/browser fallback semantics are preserved. The applied two-file source matches the benchmark and reviewed manifests.

On hp1, three paired processes supplied 21 warm observations per path at each history size. At 5,000 completed swaps and one active record, median maker tick time was 208.970 ms before and 11.705 ms after; enumeration decoded 5,001 records (15,284,409 bytes) versus one (1,389 bytes). First candidate ticks still took 196–204 ms. At zero completed history, medians increased from 0.104 to 0.142 ms. These are local mock-chain measurements, not production latency or fairness guarantees; SQLite still scans tags and external commits can force full validation.

The builder ran 335 Rust tests and compiled the browser target. Independent review reran 15 store tests and verified snapshot/version behavior across concurrent external commits and rollback. Its migration suite initially reproduced both binders failing with database-is-locked, then passed on retry. That separate tool issue was corrected by retaining normal connection locking while using an exclusive binding transaction; five migration tests and 20 consecutive concurrent-binding reruns passed afterward.

## Incremental used-address persistence

Incremental wallet saves now detach a set of pending used addresses and write only those rows. Full saves still write the complete used-address set. Both save paths retain the persistence lock and union pending addresses back on error; marks concurrent with a successful save remain pending. HD observation, durable replay obligations, key storage and transaction/UTXO persistence retain their existing ordering.

Independent review replayed the patch against 87cc4823, matched both source hashes on hp1 and passed all 290 wallet library tests with no failures or filtering. Coverage includes concurrent successful full/incremental saves, failure followed by retry and reopen, locked HD replay and refill-failure recovery. The applied files match that reviewed source.

For one new synthetic fixed-width address with 10,000 existing addresses, the submitted RocksDB batch decreased from 10,003 operations and 200,074 bytes to three operations and 74 bytes, including two checkpoint writes. The reviewer reproduced the CSV summaries from all 189 raw records per build. These measure encoded batch submissions on disposable wallets, not physical disk writes or production latency. Transaction and UTXO dirty categories still rewrite their full category and remain separate optimization work.
