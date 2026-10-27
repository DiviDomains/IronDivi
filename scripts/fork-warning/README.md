# Divi Core's fork warning next to irondivid

`run.sh` starts four regtest nodes: two divid miners and the two nodes compared, divid `divid-A` and irondivid
`irondivid-A`. It builds an invalid chain with more work than the nodes' own and compares, at each step, what Divi
Core's fork warning shows: getinfo's and getmininginfo's `"errors"`, safe mode, the log line and `-alertnotify`. Each
row prints one line:

- `PASS`: irondivid shows what divid shows;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, a step that could not be
done, interrupted, or over 15 minutes).

```sh
scripts/fork-warning/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/fork-warning/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: **8 ports**, `<port-base>` to `<port-base>+7` on 127.0.0.2 (p2p and RPC of each node).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute. However it ends, the nodes are stopped and their directories deleted. Needs bash and
python3 (standard library only). RPC passwords are made at random for each run and kept in each node's 0600
`divi.conf`. Every node runs with `connect=127.0.0.2:1`, so it dials no one by itself; the script joins nodes with
`addnode <node> onetry`.

## Nodes

| node | what it does |
|---|---|
| divid `divid-M` | mines the common chain and the long branch |
| divid `divid-N` | mines the compared nodes' own branch; never sees the long branch |
| divid `divid-A`, irondivid `irondivid-A` | the pair compared; each has `-alertnotify` writing to a file in its directory |

Every block is a proof-of-work block (regtest's last is at height 100), so every block is worth the same work and "six
blocks of work" is six blocks.

## Steps and rows

| step | what happens | rows |
|---|---|---|
| 1 | M mines to 60, all four take it; all four are restarted, which splits them | — |
| 2 | N mines 61 and 62, the pair takes them, N stops; M mines 20 more (61' to 80') | tip on the own branch |
| 3 | the pair dials M and moves to 80' | tip; errors |
| 4 | `invalidateblock 61'`: the pair is back at 62. The invalid block kept is 61', one block past the tip | the reply; tip; errors |
| 5 | M and the pair stop; the pair starts. The invalid block kept is now 80', the most work of the blocks marked failed (`BlockIndexLoading.cpp:67-68`); nothing is checked until a block connects | tip; errors |
| 6 | N starts and mines 63; the pair takes it. 80' is 17 blocks past it | errors; `getbalance` (refused in safe mode); `getblockcount` (allowed); the log line |
| 7 | N mines to 73 (80' seven blocks past it), then 74 (six) | errors at 73; the number of log lines since the restart; at 74: errors, `getbalance`, no new log line |
| 8 | `reconsiderblock 61'`: the pair moves back to 80' | the reply; tip; errors; whether `-alertnotify` ran |

## What Divi Core does

- `CheckForkWarningConditions` (`ForkWarningHelpers.cpp:20-58`) runs after each step of `ActivateBestChain`
  (`MostWorkChainTransitionMediator.cpp:153-157`) and in `InvalidChainFound` (`BlockInvalidationHelpers.cpp:91-110`),
  except in initial block download. When the invalid block with the most work
  (`mostWorkInvalidBlockIndex`) has more than the tip's chain work plus six of the tip's block proofs, it logs
  `CheckForkWarningConditions: Warning: Found invalid chain at least ~6 blocks longer than our best chain.` and sets
  `fLargeWorkInvalidChainFound`; otherwise it clears it.
- The flag makes the status bar and RPC warning `Warning: We do not appear to fully agree with our peers! You may
  need to upgrade, or other nodes may need to upgrade.` (`Warnings.cpp:44-46`). That is getinfo's and getmininginfo's
  `"errors"` (`rpcmisc.cpp:156`, `rpcmining.cpp:242`), and it puts the server in safe mode: calls not marked
  `okSafeMode` answer -2 `Safe mode: <warning>` (`rpcserver.cpp:1049-1054`).
- The invalid block kept is the block found invalid (`InvalidChainFound`), a candidate tip with a failed block below
  it (`BlockCheckingHelpers.cpp:340-341`), and at a start the most work of the blocks marked failed
  (`BlockIndexLoading.cpp:67-68`). `reconsiderblock` forgets it when it is that block or one above it
  (`ChainExtensionService.cpp:667-678`).
- The large valid fork half (`Warning: The network does not appear to fully agree!`, the `Large valid fork found` log
  line and `-alertnotify`) is never reached in 3.0.0: `CheckForkWarningConditionsOnNewFork` is given the lowest block
  of the batch being connected (`MostWorkChainTransitionMediator.cpp:21-25`, `:155`), which is on the active chain or
  one block above it, never seven blocks of work past the fork. The last row checks that `-alertnotify` does not run.

## KNOWN differences

None: every row matches divid at the time of writing.

## Proving a difference is caught

`FORK_WARNING_INJECT=<row name>` changes irondivid's value of that row before it is compared.
