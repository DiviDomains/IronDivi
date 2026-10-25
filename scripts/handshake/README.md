# The peer handshake and the messages a peer sends rarely, next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, side by side, with no wallet and no
peer of their own, and runs the same cases against both from raw peers the script plays. For each case it compares
what the node sends back (command, order, fields), the peer's ban score in `getpeerinfo`, the peer's other
`getpeerinfo` fields where the case is about them, whether the connection stays open, and whether the address is
banned. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 10 minutes).

```sh
scripts/handshake/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/handshake/run.sh target/release ~/divi-3.0.0/bin 54250 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+11`. divid's p2p and RPC, then irondivid's, on 127.0.0.2;
  `<port-base>+10` and `+11` on 127.0.0.3 are the raw listeners the nodes dial in the self-connection case.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 3 minutes (the cases run on both nodes at once) and is stopped after 10. However it ends, both nodes
are stopped and their directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at
random for each run and kept in each node's 0600 `divi.conf`.

Run with divid in both places (a directory whose `irondivid` is a link to `divid`), every row gives the same answer
on both: each compares something divid itself does the same way each time. The 9 KNOWN rows then print FAIL
("listed as KNOWN, but now the same as divid"), and nothing else does.

## Nodes and peers

Both nodes run with `regtest=1`, `disablewallet=1`, `staking=0`, `discover=0`, `debug=net`, listen on 127.0.0.2 and
are connect-only to a port nothing listens on, so each sees only the raw peers made here. A raw peer connects from
its own loopback address (127.0.0.21 and up, one per case), so its `getpeerinfo` entry, ban score and ban are its
own. divid never bans a local peer for misbehaviour: at 100 it drops it (`main.cpp:1107-1125`), and irondivid does the
same, so a score of 100 shows as a closed connection.

"Replies" lists what the node sent after the case's message, leaving out what nodes send on their own (`ping`,
`getblocks`, `getheaders`, `inv`, `addr`, `getaddr`, `sporkcount` and masternode sync messages); the handshake rows
list everything.

## Rows

Core paths are under `divi/src/` of the Divi Core source at v3.0.0.

| case | what divid does |
|---|---|
| handshake | a version from the peer is answered with `version`, `verack`, `sporkcount` (inbound only), then `ping` and `getblocks`, before the peer's verack (`main.cpp:400-420`). The version's fields: protocol 70915, services 5 (NODE_NETWORK, NODE_BLOOM), the peer's address as 0.0.0.0:0 when it is not routable, `addr_from` 0.0.0.0 with the node's port, a nonce, start height, relay 1 (`Node.cpp:992-1005`). `getpeerinfo` version, subver, startingheight, banscore, inbound, services |
| version 70914 | `reject version 17 "Version must be 70915 or greater"`, disconnected, and the address banned, even a local one (`Node.cpp:981-990`, `main.cpp:374-378`); a new connection from it with protocol 70920 is refused until `clearbanned` |
| version 70915, services 0, start height 1000, relay 0, an empty sub-version | taken; `getpeerinfo` shows the fields as soon as the version is read, before the verack (`main.cpp:372-391`) |
| version with a 300-byte sub-version; of 85 and 10 bytes | `reject version 1 "error parsing message"` (`main.cpp:1053-1058`), the connection kept; startingheight -1 (`Node.cpp:561`) |
| version of 46 bytes | taken: the fields after addrMe are optional (`main.cpp:380-391`); startingheight -1 |
| a second version | `reject version 18 "Duplicate version message"`, score 1 (`main.cpp:358-362`) |
| the node's own nonce | the node dials a raw listener; a peer that sends that version's nonce back is dropped, not banned (`Node.cpp:887-890`, `main.cpp:394-399`) |
| before version: ping, verack, an unknown command | no reply, score 1 each, kept (`main.cpp:492-497`) |
| ping between version and verack | answered with the same nonce (`main.cpp:510-514` needs only the version) |
| ping with a nonce, with none, with 12 bytes | `pong` with it; `reject ping 1 "error parsing message"`; `pong` of the first 8 bytes (`Node.cpp:734-752`) |
| pong with the node's nonce, another nonce, nonce 0, 4 bytes; unasked | the ping ends and is timed; stays outstanding (`pingwait`); ends untimed; ends untimed; nothing. No reply, no score (`Node.cpp:754-808`) |
| alert with a bad signature, twice; empty | score 10 each, kept (`main.cpp:870-890`, `alert.cpp:151-155`); `reject alert 1 "error parsing message"` |
| dstx, empty or with a transaction | divid reads no transaction from it (`main.cpp:705-718`) and checks an empty one: `reject dstx 16 "bad-tx"` with a hash of zeros, score 10 + 100 (`BlockCheckingHelpers.cpp:101-103`, `MempoolConsensus.cpp:276-277`, `main.cpp:803-812`): dropped |
| reject of a tx (with a hash), of a version, empty, of a tx with no hash | no reply, no score, kept; with -debug the reason is in debug.log (`main.cpp:940-961`) |
| an unknown command; mempool | ignored, unscored: divid has no handler for either (`main.cpp:963-966`) |
| filteradd before filterload; filterload over 36000 bytes; filteradd of 521 bytes; filterclear | bloom filters are on (`net.cpp:1722`): kept, unscored (a peer starts with an empty filter, `Node.cpp:556`); 100, dropped; 100, dropped; kept (`main.cpp:900-939`) |
| a bad magic; a bad checksum; a command with a control character, or bytes after its NUL; a 12-letter command | dropped (`main.cpp:982-986`); skipped, the next message answered (`main.cpp:988-1009`, `protocol.cpp:76-85`); skipped; taken as an unknown command |
| size over 2 MiB, over 32 MiB (header only) | dropped as the header is read (`Node.cpp:66-69`, `:132-135`) |

## Not covered here

- Already compared by other scripts: the score and drop at 100 and `-banscore`/`-bantime` (`scripts/bans`, where a
  second version at `-banscore=1` is a row too); the handshake ping, `pingtime`/`pingwait` timing, the ping interval
  and the byte counters (`scripts/net-counters`); `getaddr`/`addr` (`scripts/addr-gossip`); `startingheight` after
  blocks (`scripts/net-replies`); the `reject` sent for a refused `tx` (`scripts/reject-replies`); `tx` relay
  (`scripts/tx-relay`).
- `getblocks`, `getheaders`, `getdata` and `getaddr` serving: `scripts/block-serve`.

## KNOWN differences

Each KNOWN row checks that the difference is exactly the one below; any other outcome is a FAIL.

- `handshake: version: services`, `addr_from`, and the `filteradd before filterload` and `filterclear` rows:
  irondivid offers no bloom filters, so it does not set NODE_BLOOM (4) and scores a filter message 100, as divid run
  with `-peerbloomfilters=0` does (`net.cpp:1722`, `main.cpp:892-898`). By design.
- `handshake: version: subver`: each names itself, divid `DIVI Core: 3.0.0.0` (`clientversion.cpp:82-86`),
  irondivid `/IronDivi:<version>/`. By design (divid's `ban outdated` reads it: KNOWN in `scripts/bans`).
- `version with a 300-byte sub-version` and `version of 85 bytes`, `getpeerinfo`: divid sets the peer's version and
  services before it reads the rest (`main.cpp:372-373`), so a version that fails to parse after addrMe leaves
  them set; irondivid keeps nothing from a version that does not parse. Both send the same reject and keep the
  connection.
