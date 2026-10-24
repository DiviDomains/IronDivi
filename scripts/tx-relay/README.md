# Transaction relay in a mixed network next to Divi Core

`run.sh` starts six regtest nodes, Divi Core 3.0.0 `divid` and irondivid, sends transactions from each kind of node
and from a minimal peer of the script's own, and compares which mempools they reach, and whether within a bounded time,
between the divid and the irondivid behind the same divid bridge. Each row prints one line:

- `PASS`: irondivid does what divid does;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/tx-relay/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/tx-relay/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: **12 ports**, `<port-base>` to `<port-base>+11` on 127.0.0.1 (p2p and RPC of each of the six nodes).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 2 minutes and is stopped after 10 minutes. However it ends, all six nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and
kept in each node's 0600 `divi.conf`. The shared wallet's phrase is read from divid's `dumphdinfo` reply and handed to
irondivid in its environment (`WALLET_MNEMONIC`) at its first start; it is never printed, written to a file or put on
a command line.

A node that exits while starting is reported with its exit code and the last 15 lines of its `debug.log` (or of its
stderr when it wrote no log). If those lines say `Address already in use` or `Unable to bind`, the node is given two
ports free at that moment (picked by the system) and started again, up to 5 times; the nodes that dial it follow.

## Nodes

| side | bridge | behind the bridge (dialling it, and listening for the script's peer) |
|---|---|---|
| L | divid `bridge-L` | divid `divid-L` (holds the shared wallet), irondivid `irondivid-L` (the wallet restored); both with `-acceptnonstandard` |
| R | divid `bridge-R` | divid `divid-R`, irondivid `irondivid-R` (the wallet restored) |

The sides are joined by `addnode <bridge-L> onetry` on `bridge-R`, and split by starting all six again (no node dials
across). The divid and the irondivid behind the same bridge see the network the same way, so each row compares that
pair. All nodes run with `staking=0`.

The script's peer connects to a node behind bridge L, completes the handshake (`version`, `verack`, regtest magic,
protocol 70915) and sends `tx` messages in the order the row needs: this is the only way to deliver a child before
its parent, since a node's RPC does not take a transaction whose inputs it does not know.

## Rows

Arrival: a row says whether the transactions were in each node's mempool within 30 s (or, for the rows after a fixed
wait, after it); it is compared between the pair behind each bridge.

| step | rows |
|---|---|
| plain sends | one sent with `sendrawtransaction` to divid-L, one to irondivid-L; arrival on both sides |
| a parent and its child | sent in order to divid-L, and to irondivid-L; arrival of both on both sides |
| a child before its parent | the script's peer sends the child, then 2 s later the parent, to divid-L, and to irondivid-L: the child alone is not in the mempool; then arrival of both on both sides (Divi Core keeps it as an orphan and takes and relays it when the parent comes, `main.cpp:743-792`) |
| the relay fee floor | from coins one block old (too little priority to go free, `MempoolConsensus.cpp:255-259`): one satoshi under the floor (refused), exactly the floor (`CFeeRate::GetFee` of its size: taken and relayed); and no fee from an old coin (taken on priority) and its arrival. Compared by outcome and error code; the error texts are compared by `scripts/reject-replies` |
| non-standard | a spend to an `OP_TRUE` output on side L's pair, which runs with `-acceptnonstandard` (`MempoolConsensus.cpp:274`, `:291`): taken; not taken by side R or by bridge L, which run without it; each node then mines its own into a block |
| vault | `fundvault <owner>:<manager> 100` and, after a block, `reclaimvaultfunds <address> 50`, from divid-L and from irondivid-L; arrival on both sides |
| restart | side L's pair is started again with the wallet's unconfirmed sends in the mempool: the mempools after it, and whether the wallet's own send is back (Divi Core keeps no mempool file and puts the wallet's unconfirmed transactions back into its own mempool at start, `init.cpp:1262-1274`) |
| conflicting spends | split; divid-L and irondivid-R each spend the same coin; joined: each side keeps its own spend; then a block of side R confirms its spend, and side L's leaves both sides' mempools |

Not covered, because divid 3.0.0 has no such thing: `-whitelistrelay` and `-whitelistforcerelay` (its `-whitelist`
only exempts a peer from bans and trickles to it, `net.cpp:742-764`, `Node.cpp:700`), a mempool file, and a
rebroadcast within a bounded time (divid rebroadcasts mempool transactions at a random moment within 30 minutes,
`main.cpp:1245-1294`).

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

None: every row matches divid with `fix/tx-relay` (irondivid relays a transaction only once its mempool took it, and
an orphan once accepted; and it reads `-acceptnonstandard`). Without those fixes three rows FAIL: the child before its
parent sent to irondivid-L never leaves it; the non-standard transaction is refused; and so the mempool after the
restart differs.

## Proving a difference is caught

`TX_RELAY_INJECT=<row name>` changes irondivid's result of that row before it is compared, e.g.
`TX_RELAY_INJECT='plain send from divid-L (R)'`: that row prints `FAIL` and the run exits 1.
`TX_RELAY_DUMP=<dir>` writes both results of every row that differs to `<dir>`.
