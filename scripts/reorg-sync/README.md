# Reorganisations across a split network next to Divi Core

`run.sh` starts six regtest nodes, Divi Core 3.0.0 `divid` and irondivid, as two sides of a network that is split and
joined again. On each side the two chains compete; once joined, it compares what the nodes show: the tip,
`getchaintips`, the mempool, one shared wallet (`gettransaction`, `getbalance`, `listsinceblock`), and
`invalidateblock` / `reconsiderblock`. Each row prints one line:

- `PASS`: irondivid shows what divid shows;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/reorg-sync/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/reorg-sync/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: **12 ports**, `<port-base>` to `<port-base>+11` on 127.0.0.1 (p2p and RPC of each of the six nodes).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 4 to 5 minutes and is stopped after 10 minutes. However it ends, all six nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and
kept in each node's 0600 `divi.conf`. The shared wallet's phrase is read from divid's `dumphdinfo` reply and handed to
irondivid in its environment (`WALLET_MNEMONIC`) at its first start; it is never printed, written to a file or put on
a command line.

A node that exits while starting is reported with its exit code and the last 15 lines of its `debug.log` (or of its
stderr when it wrote no log). If those lines say `Address already in use` or `Unable to bind`, the node is given two
ports free at that moment (picked by the system) and started again, up to 5 times; the nodes that dial it follow, as
each `divi.conf` is written from the nodes' current ports at every start.

## Nodes

| side | bridge | behind the bridge (dialling it) |
|---|---|---|
| L | divid `bridge-L` | divid `divid-L` (holds the shared wallet), irondivid `irondivid-L` (the wallet restored) |
| R | divid `bridge-R` | divid `divid-R`, irondivid `irondivid-R` (the wallet restored) |

No node dials across, so starting all six again splits the network. `addnode <bridge-L> onetry` on `bridge-R` joins
it. The divid and the irondivid behind the same bridge see the network the same way: each row compares that pair. A
bridge, which sees the other side directly, knows more side branches than the nodes behind it, so bridges are not
compared. All nodes run with `staking=0`; blocks are made with `setgenerate`, which past height 100 (regtest's last
proof-of-work block) makes proof-of-stake blocks (each is checked to have a coinstake).

## Scenarios

| | what happens | rows |
|---|---|---|
| A | depth 1 (PoW): side L 1 block (divid), side R 2 (irondivid) | tip on all six, `getbestblockhash`, `getblockcount`, `getchaintips` per side; R won |
| B | depth 6 (PoW): side L spends coin X and coin Y and mines 6 (bridge L); side R spends coin X differently and mines 7 (irondivid R) | as A; `getrawmempool` per side; coin Y's spend back in side L's mempool; on side L's pair the shared wallet: `gettransaction` of both double spends and of Y's spend, `getbalance`, `listsinceblock <side L's lost tip>` |
| C | equal tips: 2 blocks each side, joined: each side keeps the tip it saw first; then side R's chain grows block by block (3 blocks, one at a time) | first seen and `getchaintips` per side; after the first and after the last block as A |
| D | depth 30 (PoW): side R 30 (irondivid), side L 31 (divid) wins; `irondivid-R` is restarted while it reorganises | as A; L won |
| E | proof of stake past height 100: depth 1 (R wins), 6 (L wins), 30 | as A; at depth 30 each side keeps its own tip (below) |
| F | on side L's pair: `invalidateblock <tip-2>`, then `reconsiderblock`, and both of an unknown block | the replies; `getblockcount`, `getbestblockhash`, `getchaintips` after each |

How a row compares: the same outcome (a result, or an error with the same code and message); for a result every
field's name, JSON type and value. `getchaintips` is compared after sorting by height and hash, `getrawmempool` and
`listsinceblock`'s transactions after sorting; `time` and `timereceived` of wallet transactions are not compared (they
are when a node saw the transaction).

Proof of stake 30 blocks deep: the other side's branch stakes coins made on that branch. Divi Core looks the stake's
input up in its own chain only (`GetTransaction`, `divi/src/BlockProofVerifier.cpp:66-70`, `TransactionDiskAccessor.cpp:49-110`)
and refuses the block (`BlockProofVerifier.cpp:147`, logged `read txPrev failed`), so neither side takes the other's
longer branch; the row checks that irondivid keeps its side's tip as divid does.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

None: every row matches divid at the time of writing.

## Proving a difference is caught

`REORG_SYNC_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`REORG_SYNC_INJECT='A depth 1: getchaintips (L)'`: that row prints `FAIL` and the run exits 1.
`REORG_SYNC_DUMP=<dir>` writes both replies of every row that differs to `<dir>`.
