# Network, masternode and spork RPC replies next to Divi Core

`run.sh` starts two fresh Divi Core 3.0.0 `divid` connected to each other and two fresh irondivid connected to each
other, all on regtest, makes the same network, masternode and spork calls on both kinds, and compares the replies
field by field, before and after a restart of all four. Each row prints one line:

- `PASS`: same as divid (or, for an `[irondivid only]` row, the expected outcome);
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/net-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/net-replies/run.sh target/release ~/divi-3.0.0/bin 54200 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.1: p2p and RPC of divid 1, divid 2, irondivid 1,
  irondivid 2.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 35 seconds and is stopped after 10 minutes. However it ends, all four nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run
and kept in each node's 0600 `divi.conf`.

## Nodes

Node 1 of each kind listens; node 2 dials it (`connect=`). Node 1 mines 5 blocks and node 2 follows. All run with
`staking=0` and `bantime=86400`. `addnode` and `setban` are given TEST-NET addresses (192.0.2.x, RFC 5737), where no
node answers, so no other port is touched. The calls are made on node 1 of each kind (it has an inbound peer);
`getpeerinfo` is compared on node 2 (an outbound peer) too.

## Rows

| calls | forms |
|---|---|
| state (before and after the restart) | `getconnectioncount`, `getpeerinfo` (node 1 and node 2), `getnetworkinfo`, `getnettotals`, `ping`, `getaddednodeinfo false` / `true` with none added, `spork show`, `spork active`, `getmasternodecount`, `listmasternodes`, `getmasternodestatus` (no masternode), `mnsync status`, `listbanned` |
| `addnode` | `add`, `add` again (-23), `remove`, `remove` again (-24), `onetry`, an unknown command and no arguments (divid's help); an address without a port |
| `getaddednodeinfo` | `false`, `false <node>`, `true <node>`, a node not added (-24), after `remove` and after `onetry`; an address without a port |
| `spork` | an update without the spork key (`failure`), an unknown spork (`Invalid spork name`), no arguments (help) |
| masternode | `listmasternodes <filter>`, `mnsync <bad mode>` (help), `masternode status` (not a divid method) |
| `setban`, `disconnectnode` | add, add again, a bad subnet, an absolute end time (and its `banned_until`), removing an address not banned; `disconnectnode` of an address not connected |
| `ban` | an address with no peer, `outdated`, node 2's address; `getconnectioncount` and `listbanned` after it; the ban across the restart; `clearbanned` |

How a row compares: the same outcome (a result, or an error with the same code and message; for divid's help texts
the first line); for a result every field's name, JSON type (an integer and a number with a fraction differ) and value,
list items in order. Left out of the value comparison, because they change from one moment to the next or with the
port a node was given: in `getpeerinfo` `id`, `addr`, `addrlocal`, `lastsend`, `lastrecv`, `bytessent`, `bytesrecv`,
`conntime`, `pingtime`, `pingwait`, `minping`, `timeoffset`; in `getnettotals` the byte counts and `timemillis`;
`timeoffset` in `getnetworkinfo`; `banned_until` and `ban_created` in `listbanned`.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

Each KNOWN row checks that the difference is exactly the one below: for an error or a result the exact pair of
replies, for an object that only the named fields differ. Any other outcome is a FAIL.

By design:

- `getpeerinfo` `subver`, `getnetworkinfo` `subversion`: irondivid names itself (`/IronDivi:<version>/`); divid
  gives `DIVI Core: 3.0.0.0`.
- `getnetworkinfo`: irondivid adds `connections_in` and `connections_out`; it shows `onion` as `limited`, since it
  cannot address .onion peers.
- `getmasternodecount`: irondivid adds the tier counts `copper`, `silver`, `gold`, `platinum`, `diamond`.
- `listbanned`: divid gives `{"banned:": "[\n<ip>,\n]"}`, one text under a key with a colon (`rpcmisc.cpp:1023-1030`,
  `PeerBanningService.cpp:23-34`); irondivid gives an array of bans (`docs/rpc-parity-audit.md`).
- `setban`, `disconnectnode`: not divid methods (`rpcserver.cpp:325-409`, divid answers `Method not found`); irondivid
  has them. The row checks irondivid's exact reply.
- `ban outdated`: irondivid does not ban outdated peers and says so (`docs/rpc-parity-audit.md`; divid:
  `net.cpp:357-393`).
- `ban <ip>` of node 2's address: divid compares the address given with each peer's `ip:port` text, so it never finds
  a connected peer (`net.cpp:395-407`) and answers `Could not find matching node to ban`; irondivid bans node 2. So
  after it `getconnectioncount` is 1 on divid and 0 on irondivid, and irondivid's `listbanned` has the entry. Neither
  keeps a ban across a restart.

Open (not closed yet):

- `getpeerinfo` `services`, `getnetworkinfo` `localservices`: divid advertises NODE_BLOOM (5,
  `NetworkLocalAddressHelpers.cpp:224-227`); irondivid does not serve bloom filters and gives 1.
- `getpeerinfo` `synced_headers`, `synced_blocks`: irondivid gives -1; divid the heights it has synced with the peer
  (`rpcnet.cpp:139-140`).
- `mnsync status` `currentMasternodeSyncStatus`: divid gives its masternode sync phase (0, and 1 after the restart,
  on regtest with no masternodes: `rpcmisc.cpp:212`, `masternode-sync.h:42-47`); irondivid has no masternode sync
  and gives 999 (finished).
- `getaddednodeinfo` of a node given without a port: divid keeps the node as written (`192.0.2.3`); irondivid keeps
  the address, with the network's port (`192.0.2.3:51476`).

## Proving a difference is caught

`NET_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`NET_REPLIES_INJECT='spork show'`: that row prints `FAIL` and the run exits 1.
`NET_REPLIES_DUMP=<dir>` writes both replies of every row that differs to `<dir>`, for looking into a FAIL.
