# Block-expiry pruning: report

User documentation: `docs/block-expiry-pruning.md`.

## Status

Built, tested, pushed. **Live staking at `expire=0` is NOT yet demonstrated:** attempts run clean, no stake was won in about 7 hours
(expected at this weight). Do not describe it as proven.

## Config

| Surface | Name |
|---|---|
| CLI | `--expire <value>` |
| Environment | `IRONDIVI_EXPIRE` |
| Conf file | `expire = "30d"` (or the integers `0` / `-1`) |

Precedence: CLI > env > conf > default. An invalid value is a startup error.

## Suffixes

`s` seconds, `m` minutes, `h` hours, `d` days, `w` weeks, `mo` months (30 d), `y` years (365 d).
Lowercase, case-sensitive. A bare number is valid only as `-1` or `0`.

## Values

* `-1` (default): never expire.
* `0`: keep the last 2880 blocks (about 2 days) of bodies and undo data, nothing older.
  Headers, UTXO set and indexes are always kept.
* `N<unit>`: keep a time window, never below the 2880-block floor or the wallet's scanned height.

## Evidence

* Tests pass on hp3 for divi-storage, divi-rpc, divi-node and irondivid; clippy clean.
* Throwaway testnet node at `expire=0`, genesis to tip (348,687): 0 kernel/ancestor errors, 0 ERROR lines,
  clean restart (`pruned:true`, `pruneheight` 345,807), kept following the tip.
* `getblock` on a pruned block: clean "pruned data" error. Verbose `getblockheader`: works at every height.
* Disk: chainstate 864M pruned vs 926M unpruned at the same height (about 7%). Testnet blocks are tiny;
  mainnet saving is unmeasured.
* Not run live: `getrawtransaction` on a pruned tx; the wallet-floor path (nodes ran `--disablewallet`; unit-tested only).

## Staking at `expire=0`: attempts verified, no stake won (not proven)

* Broker came up; a fresh hp3 testnet wallet was funded with 205,000 tDIVI (3 UTXOs) from a testnet wallet
  (the hp2 swap wallet was not used). The node ran at `IRONDIVI_EXPIRE=0` and was `pruned:true`
  (`pruneheight` 346,883 at block 349,763) with `getstakingstatus` = "Staking Active".
* About 7 hours, 1,440+ staking attempts hashing all matured UTXOs: 0 setup failures, 0 errors, 0 modifier
  mismatches. **Zero stakes won.** The staker log summary hard-codes "0 success"; the real markers are
  "Hashproof SUCCESS" / "Found valid stake", and none appeared.
* Control: an unpruned wallet node with 100,000 tDIVI ran about 3 hours, also with zero wins.
* Why zero is expected: testnet difficulty is about 8,033, so network stake weight is about
  d*2^20/60, roughly 140M tDIVI. 205k is about 0.15% of that, or about 0.3 expected wins per 3 hours
  and under 1 over the whole run. A win needs days of runtime. The test is statistically too weak to
  show either success or failure.
* So: the staker runs correctly on a pruned node and nothing points at a pruning problem, but **a staked
  block from a pruned node has not been observed.** Supporting argument only: the staker does no
  block-body reads and consensus uses only the UTXO set and block index.
* To close it: leave a pruned wallet node running for days (or hold far more testnet coins) until it
  stakes, then confirm the coinstake block.

## Limitations

* Raw `getblockheader <hash> false` on pruned v4+ blocks is unavailable.
* A pruned node still advertises `NODE_NETWORK` and answers `notfound` for old blocks.
* Side-chain bodies are not pruned. No reindex exists; a pruned datadir can only be resynced.
* Load the wallet and let it catch up before enabling `expire`.

## Commits

74ac0d8 feature, d484f14 docs, 8c77192 (does not compile), dcc35b8 (fixes 8c77192), 8e431c0 docs,
9f2a81b lint and doc cleanup.

## Leftovers

`~/prune-test` and `~/prune-base` on hp3 (about 2.2G) are stopped and safe to delete (the pruned wallet holds the testnet coins; keep them).
Production dnsdivi / hp1 / hp2 were never touched; expiry is not enabled anywhere real.

## NEEDS HUMAN
- ~~Monero STAGENET atomic swap, parked 2026-10-14 on `secret-broker serve`.~~ **Resolved
  2026-10-14:** Bert started the broker; the swap ran end to end on stagenet (0.01 sXMR → 50 tDIVI,
  outcome `redeemed`). Txids in `docs/plans/swap-poc/RESULTS.md`. Stagenet only; mainnet is a separate decision.
- XMR swap C1 (cancel ransom): **full fix built and deployed to the stagenet maker** (Bert: option 3). dnsdivi runs `1841a12` since 2026-10-15 16:29Z. §7 tests: 5a/5b/7 PASS on a private Divi regtest, 1 (5/5 happy swaps redeemed), 2-3 (all 4 timed-out swaps cancelled and refunded, both lock-only takers got their XMR back) 4 (punish: a silent maker loses the DIVI to the taker, 2026-10-15 23:17Z) and 6 PASS live. **All §7 tests pass.** The soak found and fixed a maker stall (a77ec9d) and the C8 panic (1841a12). It also found that high-S signatures relay on Divi, so any node can malleate. Details: `docs/plans/swap-poc/status/xmr.md` "C1 full fix on stagenet". **Ruling 2026-10-15: you reviewed `xmr-c1-design.md` and chose option A, the full fix** (interim hardening first, Lindell-2017 2P-ECDSA for J, exhaustive presign over all 120 staker variants). Gap analysis and closure: `xmr-c1-design.md` §9. Only real gap was J (cggmp21). **Closed in code:** J is now Lindell-2017, built on the audited primitives cggmp21 already uses (paillier-zk, fast-paillier), with the taker generating the proof parameters and a wide mask. Both are mandatory fixes. ZenGo `multi-party-ecdsa` was dropped: its proof is unsound and it no longer compiles. All unit tests pass. **Deployed** to the stagenet maker 2026-10-16 03:13Z (sha `8391f72f…`); the §7 rerun (tests 1-4 and 6) on this build is running. Mainnet stays blocked until it passes. I treated the interim step as covered by the full build (its punish branch is live; the signature it withheld no longer exists). Say so if you want it built separately. The 120-variant presign is complete. **Mainnet stays blocked until the new build passes stagenet.** The hp2 root `divid` mnemonic fix (phrase moved from the command line into a root-only file) is approved and in progress.

## Thin staking: helpers + snapshot (2026-10-14)
Built on testnet: pruned nodes advertise `NODE_NETWORK_LIMITED` only (live bug fix); terminal lottery-winner
lists are never stripped; snapshot export/import (`--export-snapshot`, `--import-snapshot`, `snapshotbase` in
getblockchaininfo), live-tested hp3 copy -> hp1. Design doc §10 corrected, §11 added. `HistoryFetcher` (fetch + verify a pruned block from a full-history peer) built, unit-tested, and called from RPC `getblock` below `pruneheight` (live: hp1 fetched block 100 from hp3, byte-identical; refused with the peer gone; a silent full peer makes getblock wait up to 20 s per peer); not yet called from wallet rescan; no separate `fullnode=` option (use `addnode`). Live: snapshot-imported hp1 node synced forward past the snapshot tip and pruned cleanly. Earlier stripped test copies predate the terminals fix.

## Thin staking design (2026-10-14)
Design doc: `docs/plans/thin-staking.md`. Recommendation: ship pruned staking (`expire=0`) as the
thin mode, add snapshot bootstrap, build a true remote-node shim only if still needed.
Mainnet CF split measured (doc §8). Lottery-winner stripping built and validated on testnet (hp1 copy,
970 MB -> 105 MB with expire 0; clean restart, 0 errors). Not deployed anywhere real. ELI5 page published as an Artifact.
## NEEDS HUMAN
* Snapshot distribution channel: where do operators download snapshots, and do you want root hashes published (and by whom)?
* Who runs the full-history (`NODE_NETWORK`) nodes, so thin nodes have something to fetch from?
* Mainnet decision on `expire` + snapshots (everything so far is testnet only).

## Thin staking: status notes (2026-10-14)
* Snapshot staking gate built: a snapshot-imported node does not stake until its tip is past the snapshot base (live-checked on hp1).
* `fullnode=` was not added; `addnode`/`connect` plus the `NODE_NETWORK` filter identify full peers.
* `HistoryFetcher` is used by RPC `getblock` and live-tested on testnet; `getblockchaininfo` now shows `fullhistorypeers` and `lastblockfetch`; `rescanblockchain` uses the fetch (live-tested, refuses without wiping the wallet when no full peer); sync peer choice prefers full-history peers (unit-tested). Doc §10 work list is complete. Note: the hp3 prune-base node now runs from `~/bin/irondivid` (the old build dir was gone).
* A wallet on a snapshot-bootstrapped node has no history before the snapshot tip.
