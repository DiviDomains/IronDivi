# ZMQ notifications next to Divi Core

`run.sh` starts three fresh nodes on regtest: a Divi Core 3.0.0 `divid` that mines and sends, and a `divid` and an
irondivid that both follow it with `-zmqpubhashblock`, `-zmqpubhashtx`, `-zmqpubrawblock` and `-zmqpubrawtx`. A
subscriber on each of their ZMQ sockets records every message, and after each event the two followers' messages are
compared, socket by socket. Then a few nodes are started with addresses that cannot be bound. Each row prints one
line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/zmq-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/zmq-replies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid` (built with ZMQ: its `-help`
  lists the four `-zmqpub` options).
- `<port-base>`: ports `<port-base>` to `<port-base>+14` on 127.0.0.1: p2p and RPC of the miner, the divid follower and
  the irondivid follower (0-5); the followers' ZMQ sockets (6-8 divid, 9-11 irondivid); the option rows (12-14).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about two minutes and is stopped after 10 minutes. However it ends, every node is stopped and its
directory deleted. Needs bash and python3, standard library only: the subscriber speaks ZMTP 3.0 (greeting, NULL
mechanism, READY, a subscription to every topic) itself, so pyzmq is not needed. The followers run with
`disablewallet=1`; no key or phrase is used.

## Nodes and events

The miner listens; both followers dial it (`connect=`) and nothing else, so both see the same blocks and transactions
arrive the same way. Both run with `staking=0`. On each follower `hashblock` and `hashtx` share one address (one
socket), and `rawblock` and `rawtx` have one each.

| event | what the miner does |
|---|---|
| 25 blocks | mines 25 blocks, one at a time |
| a transaction | sends 10 DIVI to itself |
| a block with that transaction | mines one block |
| two transactions, then a block with both | two sends, then a block |
| a transaction and its block before the reorganization | a send, then a block with it |
| reorganization: two blocks replace one | `invalidateblock` on its tip, then two blocks on the parent; the followers switch when the second arrives |
| after restart, before any block | both followers are stopped and started again (nothing may be published) |
| after restart: a transaction and a block | a send and a block; the sequence numbers start from 0 again |

A row per event and socket compares the messages each follower published since the last event: the topic, the body
and the sequence number of each, in order. Before taking them, the script waits until both followers have the
miner's tip (and its sends in their mempools) and then 2 seconds more.

What divid publishes (Core paths under `divi/src/` of the Divi Core source at v3.0.0, commit 9e2f76c):

- Three frames per message: the topic, the body, and the notifier's sequence number, 4 bytes little-endian, counted
  from 0 at each start (`zmq/zmqpublishnotifier.cpp:129-145`). Notifiers sharing an address share one socket, each
  with its own sequence number (`:60-97`).
- `hashblock`/`hashtx`: the hash, in the order it is shown. `rawblock`/`rawtx`: the serialized block or transaction.
- A transaction when it enters the mempool (`MempoolConsensus.cpp:419`); for a connected block, the mempool
  transactions it conflicts with, then each of its transactions; for a disconnected block, the transactions the
  mempool takes back, then each of its transactions (`ChainTipManager.cpp:139-190`). On a new data directory the
  genesis transaction is sent first, before any subscriber can be there: the first `hashtx` seen is number 1.
- A block once per new tip, outside the initial block download (`ChainExtensionService.cpp:560-566`): after a
  reorganization only the new tip, not each block connected.

Option rows: a node (divid, then irondivid) is started with `zmqpubhashblock` on a free port and a second notifier
that cannot be bound. The row compares whether it started and whether the free port listens.

- an address that does not parse (`notanaddress`) for `zmqpubrawtx`;
- a port in use (held by the script) for `zmqpubrawtx`;
- a port in use for `zmqpubhashblock`, with `zmqpubrawtx` on the free port;
- the free port alone (it must listen).

divid checks the notifiers in its own order (hashblock, hashtx, rawblock, rawtx), not the order given. When one
cannot be bound it logs it (with `-debug=zmq`) and runs with no notifier at all; the address bound before it is closed
again (`zmqnotificationinterface.cpp:33-103`). There is no start error.

## KNOWN differences

- `options: a port in use, before a good one`: divid aborts at start. The failed bind shuts every notifier down, and
  `Shutdown` asserts a socket on the notifier after it, which was never set up (`zmqpublishnotifier.cpp:101`,
  `zmqnotificationinterface.cpp:23-31`, `:92-99`). irondivid starts with no notifier, as divid does when the address
  that fails is the last one.

## Proving a difference is caught

`ZMQ_REPLIES_INJECT=<row name>` changes the body of irondivid's last message of that row before it is compared, e.g.
`ZMQ_REPLIES_INJECT='a transaction: rawtx'`: that row prints `FAIL` and the run exits 1.
`ZMQ_REPLIES_DUMP=<dir>` writes both nodes' messages of every row to `<dir>`, for looking into a FAIL.
