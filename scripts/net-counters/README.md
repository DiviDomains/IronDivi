# Traffic counters, ping and the pool summary next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, side by side, and checks that the
numbers of `getnettotals`, the byte, time and ping fields of `getpeerinfo`, the `ping` call, `getmempoolinfo` and the
counts in `getnetworkinfo` move as divid's do. Each node first talks to a raw peer the script plays, which counts
every byte on its socket, so the counters can be compared with the bytes actually on the wire; then both nodes
follow one divid miner on one chain. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason (or a row that is not run, with why);
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/net-counters/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/net-counters/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2 (the miner's p2p and RPC, then divid's, then
  irondivid's). The raw peers connect from 127.0.0.3 and 127.0.0.4.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 4 minutes (130 s of it count automatic pings) and is stopped after 10 minutes. However it ends,
every node is stopped and the directory deleted. Needs bash and python3 (standard library only). RPC passwords are
made at random for each run and kept in each node's 0600 `divi.conf`.

## Nodes and steps

1. divid and irondivid start with `-disablewallet` and no peer.
2. A raw peer connects to each (its clock 100 s ahead, NODE_NETWORK, start height 0), completes the handshake and
   answers each ping after 0.3 s. Then: the `ping` call with the answers held back, a late answer, 130 s of
   automatic pings, and the peer leaving.
3. Both restart once with no peer, then again with `connect=` to a divid miner, which mines 104 blocks and sends
   three transactions, mines them, and two more after. Both nodes `invalidateblock` and `reconsiderblock` the block
   with the three, and restart with the last two in their pools.

## Rows

| row | what is compared |
|---|---|
| `getnettotals` keys and types; before any peer; `timemillis` | the members and their JSON types; `[recv, sent]` (0, 0); `timemillis` within 5 s of the clock, in ms |
| `getnettotals` / `getpeerinfo` bytes after the handshake, after 130 s of pings | `totalbytesrecv` and the peer's `bytesrecv` equal the bytes the raw peer sent; `totalbytessent` and `bytessent` lie between the bytes the raw peer had read just before and just after the call (headers counted, every message counted: divid counts at the socket, Node.cpp:252, :292) |
| `getpeerinfo` `lastsend`/`lastrecv`/`conntime`/`timeoffset` | within 10 s of now; the connect time within 3 s; `timeoffset` (divid's getpeerinfo has none, rpcnet.cpp:117-150) |
| `getnetworkinfo` (before any peer, with the peer 100 s ahead, after it left, following the miner, after the restart) | `connections`, `timeoffset` (one peer is not enough for divid's median, so 0), `localaddresses` |
| `getpeerinfo` ping after the handshake | one ping sent at the handshake (divid MaybeSendPing with nPingUsecStart 0, Node.cpp:1043-1069), `pingtime` the 0.3 s answer delay, no `pingwait` |
| `ping`; `ping` with an argument | `null`; -1 with the help text (rpcnet.cpp:51-65) |
| `getpeerinfo` while the ping is unanswered; after the late pong | one ping per peer from the call; `pingwait` shown and growing, `pingtime` kept; then no `pingwait` and `pingtime` the wait (NodeStats.cpp:24-37) |
| automatic pings in 130 s | the number of pings once a ping is answered: one, 120 s after the last (PING_INTERVAL, Node.cpp:1045) |
| `getnettotals` after the peer left | received unchanged, sent not lower: the totals keep a peer's bytes |
| after restart: `getnettotals` before any peer | (0, 0): the totals count from the start (NetworkUsageStats statics) |
| `getmempoolinfo` keys; empty; three transactions; bytes; after they confirm; after the block is invalidated; after `reconsiderblock`; before and after a restart | `size` and `bytes` (the transactions' serialized size); after `invalidateblock` the transactions are back (ChainTipManager.cpp disconnectTip); divid 3.0.0 keeps no pool across a restart |
| `getnettotals` after 104 blocks | received grew by at least the blocks' size and by less than twice it plus 50 kB; sent grew |
| `getpeerinfo` bytes of the miner within the totals | the peer's counts are at most the totals |

## KNOWN differences

- `getmempoolinfo` keys: irondivid adds `usage`, `maxmempool` and `mempoolminfee` (docs/divid-differences.md R13;
  divid: `rpcblockchain.cpp:569-574`).
- Not run: a peer that never answers a ping is dropped after 20 minutes on both (divid: `Node.cpp:829`), too long
  for this run; irondivid's rule is pinned by `crates/divi-network/src/connection.rs`
  `inactive_peers_time_out_after_twenty_minutes`.

No other row differs from divid.

## Proving a difference is caught

`NET_COUNTERS_INJECT=<row name>` changes irondivid's outcome of that row before it is compared, e.g.
`NET_COUNTERS_INJECT=ping`: that row prints `FAIL` and the run exits 1.
