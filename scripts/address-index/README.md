# One set of addresses through the address and spent indexes, next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, both with `-addressindex
-spentindex`. irondivid follows divid's chain. A set of addresses receives, sends, gets a multisig, coinbase,
coinstake and vault output, and keeps one spend in the mempool. Then the chain is taken back with `invalidateblock`
and given back with `reconsiderblock`. Both nodes are restarted, reindexed, started without the indexes, and started
with them again. At each step the same address and spent index calls go to both. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with a count of the rows and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/address-index/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/address-index/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` (divid p2p and RPC, then irondivid's), on 127.0.0.2, or on
  `ADDRESS_INDEX_HOST` when it is set.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run is stopped after 10 minutes. However it ends, both nodes are stopped and their directories deleted. Needs
bash and python3 (standard library only). RPC passwords are made at random for each run and kept in each node's
0600 `divi.conf`.

## Nodes and steps

divid listens and mines. irondivid dials it (`connect=`), so both build their indexes from the same blocks. Both run
with `staking=0` and `txindex=1`. The index settings go on the command line of each start.

1. divid mines 40 blocks and makes the addresses:
   - A, B, A2;
   - a vault owner and a vault manager;
   - a 1-of-2 multisig of A's and B's keys (`addmultisigaddress`);
   - N, from random bytes, so nobody pays it;
   - the address the coinbase of block 5 pays.
2. Block H1 (41): 10 and 3 to A, 5 to B, 7 to the multisig, and `fundvault owner:manager 20`.
3. Block H2 (42):
   - a raw transaction spends A's 10 DIVI coin to B;
   - X pays 4 to A2, and Y spends that output before either is mined, so the coin is made and spent in one block.
4. Blocks to 104, proof of stake from 101 on. The coinstake of block 103 names the coinstake address.
5. The mempool keeps a spend of B's 5 DIVI coin to A, and one more payment to A.

Then come the rows, in these views:

| view | done to both nodes first |
|---|---|
| `indexed` | nothing |
| `after invalidateblock H2` | `invalidateblock` of H2 (blocks H2 to 104 go, their transactions back to the mempool) |
| `after invalidateblock H1` | `invalidateblock` of H1 too |
| `after reconsiderblock` | `reconsiderblock` of H1 (the chain back to 104) |
| `after a restart` | a clean stop, started with the indexes |
| `after -reindex` | started with `-reindex` and the indexes |
| `started without the indexes` | started with `-addressindex=0 -spentindex=0`: divid follows the flags its block tree was made with (`txdb.cpp:498-511`), so the indexes stay on |
| `after -reindex without the indexes` | `-reindex -addressindex=0 -spentindex=0`: the flags are written again, off (`ChainExtensionService.cpp:700-706`) |
| `started with the indexes, not reindexed` | the indexes asked for, without `-reindex`: they stay off |
| `after -reindex with the indexes` | `-reindex` and the indexes: on again |

## Rows

In each view, each of `getaddresstxids`, `getaddressdeltas`, `getaddressbalance` and `getaddressutxos` is called with:

| forms | |
|---|---|
| addresses | A; `{addresses: [A]}`; `[A, B]`; `[B, A]`; `[A, B, A]`; A2; the multisig; `[A, multisig]`; the coinbase address; the coinstake address; the vault owner; the owner and the manager with `only_vaults`; `[A, owner]` with `only_vaults`; A with `only_vaults` false; the multisig with `only_vaults`; N; `notanaddress`; `[A, notanaddress]` |
| ranges, on `[A, B]` | `start`..`end` inside the chain, past the tip, reversed, equal; `start` as text, negative, 0, beyond a C++ `int`, alone; `{A}` with one height |
| chainInfo, on `[A, B]` | true, false, as text; with a range; with a range past the tip; `start` = `end` = the tip |

`getspentinfo` is called on:
- every outpoint spent in blocks H1 to 104 (named by the block, transaction and input that spend it);
- the coin spent in the mempool;
- two unspent outputs;
- an unknown txid;
- an index past the outputs, a negative index, an index as text, and an index beyond an `int`.

`getblockcount` is called too, and after each `invalidateblock` and `reconsiderblock`, the reply and whether each
mempool holds each of the run's transactions.

How a row compares:
- Both must have the same outcome: a result, or an error with the same code and message (divid's help texts by
  their first line).
- For a result, the field names, their order, JSON types and values must match. Satoshis are integers, as divid
  prints them.
- List items must be in divid's order:
  - `getaddresstxids` and `getaddressdeltas` in the order of divid's index, or, for several addresses, as divid
    sorts or concatenates them.
  - `getaddressutxos` is the exception: it is compared sorted by height, txid and output index. divid sorts its
    entries by height alone with `std::sort` (`rpcmisc.cpp:873-876`, `:980`), which is not stable, so the order
    within one height is accidental.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c):
- the calls are in `rpcmisc.cpp` (getaddresstxids :609, getaddressdeltas :693, getaddressbalance :817,
  getspentinfo :878, getaddressutxos :928);
- the index entries a block adds and takes away are in `IndexDatabaseUpdateCollector.cpp`;
- a disconnected block is in `BlockConnectionService.cpp:220-263`.

## KNOWN differences

None: no row differs from divid.

## Proving a difference is caught

`ADDRESS_INDEX_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`ADDRESS_INDEX_INJECT='indexed: getaddressbalance A'`: that row prints `FAIL` and the run exits 1.
`ADDRESS_INDEX_DUMP=<dir>` writes both replies of every row that differs to `<dir>`.
