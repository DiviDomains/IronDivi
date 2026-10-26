# Peer messages a node leaves unanswered, next to Divi Core

`run.sh` starts two Divi Core 3.0.0 `divid` and one irondivid on regtest, on the same chain, and has a raw P2P client
(Python, standard library only) send each of them the same message. It then sends a `ping` with a fresh nonce, and
another, and records every message the node sends up to each `pong`. A node handles a peer's messages one at a time,
in order (`main.cpp:1023-1077`), so a silence is told apart from a reply without timing:

- what a node answers comes before the pong of the next ping;
- what it sends from SendMessages comes before the pong of the ping after that. That covers a `getdata` it asks for
  (`main.cpp:1226-1243`) and its trickled addresses (`main.cpp:1298-1301`).

Each row compares the messages, in order, and the round they came in. Contents are compared by name: block heights,
the mempool transaction, the unknown hashes made here. The two divids must agree, or the row FAILs as not settled.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not; or the divids disagree; or a `KNOWN` row matches divid, or differs in another way.

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 15 minutes). A run takes about a minute and a half.

```sh
scripts/silent-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/silent-replies/run.sh target/release ~/divi-3.0.0/bin 53800 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`:
  - ports `<port-base>` to `<port-base>+5` on 127.0.0.2 (each node's p2p and RPC);
  - `<port-base>+6` on 127.0.0.3, where the client listens for a node's outbound connection.
  - The client connects from 127.0.0.9 to 127.0.0.254, a fresh address per row.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.
- `SILENT_REPLIES_INJECT=<row name>` changes irondivid's value of that row, which then FAILs (the proof that a
  difference is caught).

However it ends, every node is stopped and the directory deleted. RPC passwords are made at random for each run and
kept in each node's 0600 `divi.conf`; nothing secret is printed.

## The chain

- The first divid mines 120 blocks, which the other two nodes follow.
- It then replaces its tip with a longer branch, so the old tip is a valid block off the main chain on all three, one
  each had connected. divid serves such a block only once it has been connected (`BLOCK_VALID_SCRIPTS`,
  `main.cpp:213-247`).
- A transaction of its wallet goes into every mempool.
- Then each node restarts with no peer (`connect=127.0.0.2:1`) and `-externalip=240.0.0.9`, so its address book keeps
  the addresses given to it.

## Rows

Divi Core paths are under `divi/src/` at v3.0.0 (9e2f76c).

| messages | divid (what is compared on each node) |
|---|---|
| nothing | two empty rounds |
| `getdata` of a block, an unknown block, the side block, the mempool tx, an unknown tx, a confirmed tx (a coinbase) | the block; nothing; the side block; the tx; `notfound`; `notfound` (`ProcessGetData`, `main.cpp:283-347`) |
| `getdata` of the mempool tx and a `ping` in one write; and of the mempool tx and a malformed `spork` | the tx, then the pong; the tx, then the `reject` |
| `getdata` of a filtered block (type 3) of a known and of an unknown block | `merkleblock` and the block's txs: every peer has a match-all filter (`bloom.h:66`, `Node.cpp:556`, `main.cpp:249-281`); nothing. See KNOWN |
| `getdata` of an unknown item of each type 4..15 | `notfound`, also for the types nothing ever serves (4, 5, 8..13: `main.cpp:168-211`, `:321-327`) |
| `getdata` of type 0, 16, 99; of nothing | nothing (`protocol.cpp:146-149`) |
| `getdata` mixes: unknown tx, filtered block, unknown tx; unknown tx, unknown block, unknown tx; with type 99 or 4 between | a pass ends after a block or filtered block item: two `notfound`s, around whatever the block item gave |
| `getdata` of the tip after `invalidateblock` | nothing: a failed block is not `IsValid` (`chain.h:313-319`) |
| `inv` of the mempool tx, a known block, the side block | nothing |
| `inv` of an unknown item of each type 3..15, of type 0 and 99, of nothing | `getdata` for types 4, 5 (tx locks are never had, `main.cpp:143-146`), 6, 7, 14, 15; nothing for the rest |
| `getblocks` / `getheaders`: an unknown locator; from block 10 with hashStop 20 or unknown; from the tip; from the side block; an empty locator with hashStop the tip | an `inv` of up to 500 blocks after the fork point (block 1 on for an unknown or side-chain locator: `FindForkInGlobalIndex`, `main.cpp:84-96`), or nothing from the tip (`main.cpp:624-668`); `getheaders` is answered the same way |
| `headers` of an unknown header, of nothing, of a locator | nothing: no network reads `headers` (`main.cpp:669`, `chainparams.cpp:251`, `:360`, `:440`) |
| `mempool` | nothing: no handler in 3.0.0 |
| `getaddr`, twice, on an inbound connection, after 100 addresses | `addr` each time (`main.cpp:863-869`); the count is random and not compared |
| `getaddr` on a connection the node made (`addnode … onetry`) | nothing (inbound only, `main.cpp:863`) |
| `ping` with 8, 0, 4 and 9 bytes | `pong`; `reject ping 1 "error parsing message"` for 0 and 4 bytes (`Node.cpp:734-751`, `main.cpp:1054`) |
| `pong` not asked for; `verack` again; `version` again | nothing; nothing; `reject version 18 "Duplicate version message"` |
| unknown commands; `reject` of a tx, with only a message, empty | nothing (`main.cpp:940-966`) |
| `alert` of nothing, of two empty vectors; `addr` of nothing, of no addresses; `getblocks`, `getdata`, `inv` without a payload | `reject … 1 "error parsing message"` for each that does not parse (`main.cpp:1052-1054`): all but the alert of two empty vectors and the addr of no addresses, which get nothing |
| `tx` of the mempool tx again; of an orphan | nothing (`MempoolConsensus.cpp:297-300`; `main.cpp:784-792`) |
| `block` with an unknown parent, twice | `getblocks` up to it, then up to its parent (`main.cpp:822-833`) |
| `block` 5 again; the side block again | nothing |
| `getsporks`; `sporkcount` 0 and 3; `mnget` twice; `dseg` of the list twice, of an unknown masternode; `ssc` | nothing (no spork is active here); `getsporks` both times (`spork.cpp:261-273`); `ssc 3 0`, then nothing (asked too recently, `masternode-sync.cpp:155-170`); `ssc 2 0` both times; nothing; nothing (`masternode-sync.cpp:172-215`) |
| `inv` of an unknown block, then a new peer sends block 5 | `getdata` of it; then nothing. See KNOWN |

## KNOWN

| row | divid | irondivid | reason |
|---|---|---|---|
| `getdata of a filtered block (type 3) of block 5` | `merkleblock`, `tx` | nothing | irondivid offers no bloom filters (no NODE_BLOOM, a filter message scored 100), as divid run with `-peerbloomfilters=0`; see `scripts/handshake/README.md`. divid still gives every peer a match-all filter, so it answers a filtered block anyway |
| `getdata of an unknown tx, a filtered block 5, another unknown tx` | `merkleblock`, `tx`, `notfound`, `notfound` | `notfound`, `notfound` | the same; irondivid ends the getdata pass at the filtered block as divid does |
| `a block announced by a peer that has left: the next peer sends block 5` | nothing | `getdata` of the block the first peer announced | irondivid hands a block download from a peer that left to another connected peer (`crates/divi-network/src/sync.rs:622-664`). divid drops a peer's block availability and requests with it (`FinalizeNode`, `NodeStateRegistry.cpp:40-45`), and asks a peer only for blocks that peer announced (`FindNextBlocksToDownload`, `NodeStateRegistry.cpp:146`). Kept: a download survives a dropped peer. The row runs last, as the block stays pending in irondivid |
