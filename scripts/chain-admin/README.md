# Chain inspection and repair calls next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid on regtest, gives both one chain with a stale block, cuts
them apart, and then drives the same steps on each: `invalidateblock` and `reconsiderblock` in every position that
matters, a reorganization onto blocks each node mines, a restart, and the genesis block. After each step it compares
what the operator looks at:

- `getchaintips` (tips, heights, `branchlen`, status);
- `getblockchaininfo`, `getbestblockhash`, `getrawmempool`, `getbalance`;
- `gettxoutsetinfo` (all of it while both hold the same UTXO set; without `hash_serialized` once each has mined its
  own blocks);
- `getblock` and `getblockheader` of an invalidated and of a stale block (`confirmations`, `nextblockhash`);
- `verifychain` with no argument and with level and depth;
- `estimatefee`, `estimatesmartfee`, `estimatepriority` with no data, with transactions in the mempool, after blocks
  with fees and after a restart; the relay fee and the fee the wallet pays for its own send.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 20
minutes).

```sh
scripts/chain-admin/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/chain-admin/run.sh target/release ~/divi-3.0.0/bin 46650 /var/tmp
```

- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end, with both
  nodes stopped.
- `CHAIN_ADMIN_DUMP=<dir>`: both replies of every row that differs are written there.
- `CHAIN_ADMIN_LOGS=<dir>`: both nodes' logs are copied there at the end.
- `CHAIN_ADMIN_INJECT=<row name>`: irondivid's reply of that row is changed before it is compared (the row FAILs),
  to show a difference is caught.

A run takes about 2 minutes. It needs bash and python3 (standard library only). RPC passwords are made at random for
each run and kept in the 0600 `divi.conf`. irondivid's wallet is made from divid's phrase (read from `dumphdinfo`,
handed over in irondivid's environment as `WALLET_MNEMONIC`, never printed or put on a command line).

## Nodes

divid runs with `checkblockindex=0`. Regtest turns that self-check on by default and mainnet and testnet leave it
off; with it on, divid stops on an assertion (`BlockCheckingHelpers.cpp:231`) after a `reconsiderblock` of a branch
tip below an invalidated block, so it would not show what a live node does.

`getchaintips` `headers-only` is not compared: on regtest no RPC call leaves a side tip whose blocks are missing. By
the code both say `headers-only` when a block of the branch lacks its data (divid by the tip's `nChainTx == 0`, which
counts its parents, `rpcblockchain.cpp:534-536`; irondivid by walking the branch, `crates/divi-storage/src/chain.rs:1952-1953`,
:1972-1973); they differ only where R20 does, irondivid saying `invalid` first when the branch also holds an invalid
block (`docs/divid-differences.md` R20).

## Labels

Hashes are shown as labels so the two nodes compare after each mined its own blocks: `a<height>` for the shared
chain, `s45` for its stale block, `n<height>` for the blocks each node mines in the same step (`n<height>f` in step F),
`t41` to `t43` for the sends in blocks 41 to 43, `w1` and `w2` for each node's own sends in step F.

## Steps

| step | what is done on each node |
|---|---|
| setup | divid mines 40 blocks, then 41 to 43 with a send each, then 44 and 45; `invalidateblock` 45, two blocks (45, 46), `reconsiderblock` the old 45 (`s45`). irondivid follows, then restarts with no peer |
| A | the state; `getblock`/`getblockheader` of `s45` and `a45`; `verifychain`, `0 0`, `4 10`, `3 1000`, `1 1`, `4 -1`, three arguments; both calls with an unknown hash, text that is not a hash, a number, none, two arguments; `reconsiderblock` of a block that is not invalid; `getchaintips 1`, `gettxoutsetinfo 1` |
| B | `invalidateblock a43` (three blocks with sends go): the state, `getblock`/`getblockheader` of `a43`, `a42`, `a44`, `gettransaction t43`, `verifychain 4 0`; `a43` again; `a44` above it; `reconsiderblock a45` above it (its ancestors are cleared too) |
| D | `invalidateblock a45`, each node mines three blocks (`n45`..`n47`), `reconsiderblock a45` (the shorter branch stays a side branch); `invalidateblock a45` again while it is on the side branch, and back; `invalidateblock n47`, which leaves `n46` and `a46` with the same work, and back |
| E | `invalidateblock a44` below the fork; `reconsiderblock a44`; again, then `reconsiderblock a46` (the side tip: its ancestors are cleared, the other branch stays invalid), then `reconsiderblock n47` |
| F | two sends on each node, the fee estimates and the relay fee, the send's fee; one block each; the fee estimates; `invalidateblock` of the tip, both nodes restarted, the state, the fee estimates, `verifychain`; `reconsiderblock` of that tip |
| G | `invalidateblock` and `reconsiderblock` of the genesis block |

## KNOWN

| rows | divid | irondivid | reason |
|---|---|---|---|
| `estimatefee`, `estimatesmartfee`, `estimatepriority` (every step) | -32601 `Method not found` | the relay floor, or the mempool's fee rates; `estimatepriority` `"-1"` | Kept for Bitcoin-family clients (`docs/divid-differences.md` R1). No wallet send uses them: both wallets pay the relay fee for the size (`F: gettransaction w1 fee` is a PASS) |
| `getblockchaininfo headers` (never counted: PASS or KNOWN) | the best header it ever accepted, kept through `invalidateblock` (46 while `blocks` is 42) and below `blocks` after a restart and a `reconsiderblock` (47 while `blocks` is 48) | the best header on a chain it would take, never below `blocks` | divid's `pindexBestHeader` is set only when a header arrives or the index loads (`ChainSyncHelpers.cpp:17-23`, called from `ChainExtensionService.cpp:257` and `BlockIndexLoading.cpp:75`); irondivid's is its tip plus the headers waiting for their blocks (`crates/divi-network/src/sync.rs:519-521`, `crates/divi-rpc/src/blockchain.rs:409-414`). Not in `docs/divid-differences.md`: these rows are never counted, so nothing pins it. An operator reading divid's reply after `invalidateblock` would think the node is still syncing |
| `D side invalid: getchaintips` | `a46` valid-fork, while its parent `a45` is invalidated | `a46` invalid | divid reads only the tip's own flags (`rpcblockchain.cpp:531-533`); `invalidateblock` marks only active-chain blocks. irondivid looks down the branch, as the call's help defines `invalid` ("This branch contains at least one invalid block") (`docs/divid-differences.md` R20) |
| `D equal work` (4 rows) | moves to `a46` | stays on `n46` | Equal work after `invalidateblock`: divid takes the branch it received first in this run, and after a restart the one at the lower memory address (`CBlockIndexWorkComparator`, `BlockIndexWork.h:11-28`, blocks loaded from disk all have sequence 0). irondivid keeps its tip, as both nodes do for equal-work blocks that arrive; the next block decides on both (`docs/divid-differences.md` R21) |
| `G` (6 rows) | `invalidateblock` of the genesis block answers null and leaves the chain at height 0 with every other block invalid and a zero balance, until `reconsiderblock` of it | -20 `invalid block: cannot invalidate the genesis block`, nothing changes | divid disconnects every block, then fails to disconnect the genesis block and does not report it (`BlockInvalidationHelpers.cpp:133-143`, `rpcblockchain.cpp:636-646`) (`docs/divid-differences.md` R19) |

## Fixed

`F after restart: getchaintips`, `F after reconsider: getchaintips` (both FAIL on base 3dc474b): a side branch found
to sit above an invalidated block was marked failed on disk, so it stayed `invalid` across a restart even after the
invalidated block was reconsidered, and a block extending it was refused for good. divid keeps that mark in memory
only (`BlockCheckingHelpers.cpp:340-345`), so after a restart it is a `valid-fork` again. irondivid now does the same
(commit dcf4e60d, `crates/divi-storage/src/chain.rs` `inherited_failed`; test `test_inherited_failure_is_forgotten_at_restart`).
