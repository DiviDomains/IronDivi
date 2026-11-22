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
