# Peer address gossip and peers.dat next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid on regtest and compares, case by case, what each does with
peer addresses, seen from outside only: what a node sends back to a raw peer or relays to a second one, the sender's
ban score, `getpeerinfo`, `getaddednodeinfo`, and the `peers.dat` file after a stop.

- `getaddr` from an inbound and an outbound peer, twice on one connection, and the answer's size and batching when the
  node knows 0, 10, about 1000 and 2500 addresses;
- `addr` with 1, 10, 1000 and 1001 entries; times an hour and 5 minutes ago, 10 and 11 minutes ahead, zero and
  100000000; unroutable, IPv6, onion-mapped and duplicate addresses; ports 0, 1 and 65535; what is kept, with which
  time and port, and what a second peer is relayed;
- `addnode` add / remove / onetry and `getaddednodeinfo`; `-addnode`, `-connect`, `-seednode`, `-listen=0`,
  `-discover` at start;
- `peers.dat` written at a clean stop and read at the next start, truncated, zero-length, with a wrong checksum, and
  each daemon's file read by the other; a `kill -9` between learning addresses and the dump.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 15 minutes).

```sh
scripts/addr-gossip/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/addr-gossip/run.sh target/release ~/divi-3.0.0/bin 54350 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+49`. The nodes use the first four (divid p2p and RPC, then
  irondivid's) on 127.0.0.2; the raw listeners `<port-base>+10` to `+39`; `<port-base>+49`, which nothing listens on,
  is each node's only `-connect` peer.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 7 minutes (one row waits up to 130 s for divid's added-node timer) and is stopped after 15. However
it ends, both nodes are stopped and their directories deleted. Needs bash and python3 (standard library only). RPC
passwords are made at random for each run and kept in each node's 0600 `divi.conf`.

## Nodes and peers

Both nodes listen on 127.0.0.2, are connect-only to a port nothing listens on, and have `discover=0`,
`externalip=1.0.0.255` and `externalip=2a0b:7280::255`. So neither dials an address it learns, and both count IPv4
and IPv6 as reachable: divid keeps a gossiped address only of a network it can reach, and a network is reachable once
a routable local address of it is known (`AddLocal`, `NetworkLocalAddressHelpers.cpp:81-104`). The last group runs
without `externalip` to show what divid does then (KNOWN below).

A raw peer connects from its own loopback address (127.0.1.1 and up, one per peer), does the version/verack handshake
and answers pings. A raw listener (127.0.0.31 and up, one port per node) takes a connection a node is told to make
(`addnode`, `-addnode`, `-connect`, `-seednode`) and plays the other side of the handshake.

The gossiped addresses are public IPv4 addresses, each in a /16 of its own (addrman buckets by group), on the regtest
port. Nothing dials them.

## Reading the book

`peers.dat` is read by the check itself: divid's (and irondivid's, when it writes divid's layout) through
`CAddrDB` and `CAddrMan::Serialize` (`AddrDB.cpp:26-57`, `addrman.h:276-326`), irondivid's older file by its own
header. divid drops a new address whose place in its new table is taken (`addrman.cpp:291-311`); the check works out
each missing address's place from the file's key (`addrman.cpp:20-32`, `netbase.cpp:952-1010`) and counts an address
whose place holds another as the other daemon's outcome, so a collision does not make a row differ.

The 1000-entry message is sent last, so its addresses do not take the places of the ones before it.

## Rows

| group | rows (each on both nodes) |
|---|---|
| empty book | `getnetworkinfo` networks; `getaddr` from an inbound peer: no addresses |
| outbound peer | `addnode … onetry` to a raw listener: connects; `getaddr` sent after the handshake (`main.cpp:438-442`); `getpeerinfo` `inbound` false; the listener's own `getaddr` is not answered (`main.cpp:863`); its answer to the node's `getaddr` is kept and not relayed (`fGetAddr`, `main.cpp:545`) |
| addr | 1, 10, 1000 and 1001 entries; the times, kinds and ports above, one per message; the same address and port again, the same address with another port, one address twice in a message. 1001 entries: the sender's banscore 20 and nothing kept (`main.cpp:529-532`). A time at or before 100000000 or more than 10 minutes ahead becomes 5 days ago (`:541-542`); every kept time is 2 hours older (`:553`) |
| relays | a second inbound peer gets each address of a message of at most 10 entries that is routable and newer than 10 minutes, at most once (`main.cpp:545-548`, `net.cpp:1498-1522`); an onion address goes to one peer only, chosen by a hash that may pick the sender, so it is not a row |
| getaddr | from the sender: none of the addresses it sent; from the second peer: none it was relayed; twice on one connection: no address in both answers (`setAddrKnown`, `main.cpp:543`, `:1087-1104`); every message at most 1000 |
| the book | after a clean stop: readable; a new peer's answer is 23% of the book (`ADDRMAN_GETADDR_MAX_PCT`); each case kept or not, the time and the port kept (one entry per IP, `addrman.h:184`) |
| restart | after a start the answer is 23% of the book read, all from it; the file after the next stop holds the same addresses |
| 2500 known | the answer: one message, at most 1000, 23% of the book, no repeats; about 1870 of the 2500 kept (one source group reaches 64 of the 1024 new buckets, 4096 places, `addrman.cpp:20-26`) |
| 10 known | 2 in the answer, none twice |
| swapped | each daemon's `peers.dat` planted in the other's data directory: the answer is what the writer gives reading its own, and the file after the next stop holds what was read |
| damaged | truncated, zero-length, a wrong checksum: the node starts, answers with nothing, and writes a readable empty file at the next stop (`net.cpp:1431-1438`) |
| unclean stop | 10 addresses learnt, then `kill -9`: the file has none of them (written at a clean stop and every 15 minutes, `net.cpp:83`, `:1471`, `:1480`); after the start the answer is the old book's |
| start options | `-addnode`, `-connect`, `-seednode`: the node connects, sends `getaddr`, and keeps the peer after its `addr` (a `-seednode` peer is dropped then, `main.cpp:556-557`; `-connect` still dials it, `net.cpp:1094-1096`); `-addnode` in `getaddednodeinfo`, and the peer kept after `addnode remove`; `-listen=0`: no inbound peer, an onetry peer gets `getaddr`; `-discover=0` and `=1` without `externalip`: how many local addresses |
| addnode | `add` (`null`), again (-23), the node connects within 130 s (divid every 2 minutes, `net.cpp:1270`) and sends `getaddr`; `getaddednodeinfo` true and false; `remove` (`null`, the peer stays), again (-24); `getaddednodeinfo` for a node not added (-24); `onetry`: connects, not listed |
| no local address | without `externalip`: `getnetworkinfo` networks, and what an `addr` of 10 public addresses leaves in the book |

## KNOWN

| row | divid | irondivid | reason |
|---|---|---|---|
| `no -externalip: addr of 10 public IPv4 addresses, kept` | 0 | 10 | divid counts IPv4 and IPv6 as reachable only once it knows a routable local address of its own (`vfReachable` starts false and only `AddLocal` sets it, `NetworkLocalAddressHelpers.cpp:18`, `:73-79`, `:163-167`) and keeps no gossiped address of a network it cannot reach (`main.cpp:544-551`): a node with `-discover=0` and no `-externalip`, or behind NAT with only private interface addresses, never keeps one. irondivid keeps them, a deliberate deviation so that a node behind NAT still learns peers (`docs/divid-differences.md` P3) |
