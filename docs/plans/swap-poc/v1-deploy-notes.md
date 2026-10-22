# V1 script deploy notes: mixed V0/V1 safety

Applies from `aa0d50b` (builder BE, F3): every swap the maker creates locks both legs in the
size-checked V1 script. Swaps already in flight at that deploy keep the V0 script on both legs until
they end. This note is what an operator needs when V0 and V1 swaps share a store, and when a
rollback is considered.

## How a record decides its script

`HtlcParams.script_version` (`crates/divi-swap/src/htlc.rs:95`) is stored with each leg's HTLC in the
swap record. `redeem_script()` and `script_sha256()` (`htlc.rs:145`, `htlc.rs:177`) and the
BTC, LTC and DIVI `htlc_script_pubkey` (`swap-chain-btc/src/tx.rs:46`, `swap-chain-ltc/src/tx.rs:50`,
`swap-chain-divi/src/lib.rs:123`) all read the version from that record, never from config or the
binary's build. ZEC derives the script through `redeem_script()` (`swap-chain-zec/src/tx.rs:1325`).
V0 serializes without the field, byte for byte as before F3.

- A V0 record stays V0 on both legs through claim and refund: the maker builds its own leg with the
  version of the taker leg (`maker.rs:652`). New swaps are V1 (`maker.rs:331`, `maker.rs:340`).
- A V1 swap never accepts a V0 taker lock (`refuse_downgraded_lock`, `maker.rs:410`).
- Tests: `crates/divi-swap/tests/v0_inflight_inheritance.rs`.

## What an old taker client sees against a V1 maker

An old client does not know `script_version`. The maker's quote and accept reply carry a V1 taker
leg, so the old client deserializes it, drops the field (record types do not use
`deny_unknown_fields`; only `divi-swap-xmr/src/jsig.rs:144` and `:153` do), and rebuilds the V0
script. Its address differs from the maker's, so it funds an output the maker's V1 watch cannot see
(`htlc_output` on the V1 script finds nothing, shown by `old_binary_cannot_see_a_v1_output`), so the
maker never sees the lock. The swap does not complete; the taker's funds sit in a V0 HTLC and come back through the taker's own
refund path after its timeout. No funds are stolen, but the swap is not usable: upgrade the client
before swapping against a V1 maker.

## Rule: no rollback below `aa0d50b` while any V1 swap is not terminal

An older `divi-swapd` reading a V1 record silently rebuilds the V0 script and address. It then looks
for the wrong output, so it can neither claim nor refund that swap, and it can try to fund or spend a
script the counterparty is not watching. The same holds for an old `divi-swap` taker CLI opening a DB
that holds a V1 taker record: `Store::open` (`store.rs:204`) has no schema or version check, so it
opens without complaint.

Every swap created since `aa0d50b` is V1, so "any V1 swap not terminal" is "any swap in `/swaps`
not `Done` or `Aborted`, or any XMR swap not done, aborted or punished".

## Exact pre-rollback check

```sh
OPERATOR_TOKEN_FILE=<file with the maker operator token> \
  tools/swap-poc/redeploy-maker.sh --check-only   # must exit 0 and print no in-flight ids
```

`rollback-maker.sh` runs exactly this gate first and refuses (exit 1, "nothing was changed") on any
non-terminal swap, and with no or a wrong operator token (`GET /swaps` is operator-only, so it can
not confirm). `--dry-run` only prints the gate and runs nothing on the host. The one flag that
skips the gate is `--force-inflight`; it also lets a rollback through when the maker is down or the
installed binary is too old for `--xmr-inflight`. Do not pass it while a V1 swap is live. Applying
the snapshot by hand (`cp` of an old binary, `systemctl restart`) skips the gate too and is
forbidden by this rule.
Guard: `tools/swap-poc/test-rollback-v1-gate.sh` (every non-terminal state refused, bypasses named).

Before any rollback, also confirm no taker CLI DB on any machine you control holds a non-terminal
swap, and do not run an older `divi-swap` binary against a DB that does.

**2026-10-22 — swap DB schema-version marker.** `Store::open` now stamps `PRAGMA user_version = 2` (`STORE_SCHEMA_VERSION`; 1 = every DB before V1 scripts) and refuses a database stamped newer than the binary knows (`SwapError::StoreTooNew { found, supported }`), before any write; `open_read_only` refuses the same way and never writes. This protects the rollback case builder BM proved: an old binary on a DB holding V1 (`script_version`) records drops the field and rebuilds a V0 script (wrong address, cannot claim or refund). Binaries deployed before this marker have no check, so they still open a V1 DB silently: the deploy rule "never roll back across V1 with in-flight swaps" stays in force until every binary that can touch a swap DB carries the marker.
