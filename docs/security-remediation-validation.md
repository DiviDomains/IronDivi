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
