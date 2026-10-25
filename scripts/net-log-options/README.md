# Peer buffers, -onlynet and debug.log options next to Divi Core

`run.sh` puts the same raw peers and the same options to Divi Core 3.0.0 `divid` and to irondivid, each running on
its own on regtest, and compares what each does with six options: `-maxreceivebuffer`, `-maxsendbuffer`, `-onlynet`,
`-logtimestamps`, `-logips` and `-shrinkdebugfile`. Each row prints one line:

- `PASS`: the same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 20 minutes).

```sh
scripts/net-log-options/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/net-log-options/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+4` on 127.0.0.2: the node's p2p and RPC ports (one node runs at
  a time), and a listener that `-connect` dials.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end. Give an
  absolute path.

A run takes 8 to 12 minutes and is stopped after 20. However it ends, every node is stopped and its directory deleted.
Needs bash and python3 (standard library only). RPC passwords are made for the run and written only to each node's
mode-600 `divi.conf`.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## What divid does

| option | divid's rule | default |
|---|---|---|
| `-maxreceivebuffer` | A peer is not read while its received, unprocessed messages (each counted with its 24-byte header) pass the option × 1000 bytes (`Node.cpp:23`, `:335-339`). Nobody is dropped for it. | 5000 |
| `-maxsendbuffer` | While the bytes queued for a peer are at or over the option × 1000 (`Node.cpp:22`, `:397-412`), divid answers no more of its getdata and processes none of its messages, and goes on with them once the peer reads (`main.cpp:291-293`, `:1028`). An `inv` from a peer whose buffer is over twice the limit scores 50 (`main.cpp:593-596`). | 1000 |
| `-onlynet` | `ipv4`, `ipv6`, `tor` or `onion`, in any case (`netbase.cpp:70-77`); any other value stops the start with `Unknown network specified in -onlynet: '<value>'` (`net.cpp:1734-1740`). Every network not named is limited (`:1741-1746`): learnt addresses of it are not dialled (`net.cpp:1164`), an address of it is not taken as our own (`NetworkLocalAddressHelpers.cpp:90`), and `getnetworkinfo` shows it limited and not reachable (`rpcnet.cpp:323-324`). An address that is not routable, such as 127.0.0.2, is in no network and never limited; `-connect` and `-addnode` are dialled as given (`net.cpp:1282-1289`). | none |
| `-logtimestamps` | Each `debug.log` line begins with the time, `%Y-%m-%d %H:%M:%S` and a space, then the message (`Logging.cpp:179-184`). The console has no time. | 1 |
| `-logips` | Adds the peer's address to three lines: `Added connection` and `send version message` (category `net`) and `receive version message ... peeraddr=<address>` (`Node.cpp:577-580`, `:1000-1003`, `main.cpp:456-461`). Without it the log names a peer by `peer=<id>`. | 0 |
| `-shrinkdebugfile` | A `debug.log` over 10 MB is cut to its last 200 000 bytes at start, and at most every five minutes while running (`Logging.cpp:94-118`, `:186-191`, `:204-205`). | 1, or 0 with `-debug` |

## Rows

| rows | what is compared |
|---|---|
| `buffers, <options>: …` | with 100 blocks, at the defaults, `-maxsendbuffer=1` and `-maxreceivebuffer=50`: a raw peer with a 4 KB receive buffer asks for 50 000 blocks (one getdata, about 15 MB of answers) and reads nothing. Whether it is kept; whether a second peer gets a pong and a block within 10 s, and how fast; how much the first peer can then send (pings) before the node stops reading it, under or over 4 MB (the kernel buffers take 1 to 2 MB); whether it is kept after that, and its `banscore`; then it reads, and whether every block it asked for comes |
| `-onlynet=<values>: …` | `ipv4`, `IPv6`, `onion`, `tor`, two values, none, `bogus` and an empty value, with `-externalip` addresses of both families: whether the node starts (or the start error), `limited` and `reachable` of each network in `getnetworkinfo`, and `localaddresses` |
| `-onlynet=…: -connect=127.0.0.2 dialled` | under `-onlynet=ipv6` and `=onion`, whether a `-connect` to 127.0.0.2 is dialled |
| `debug.log, <options>: …` | a raw peer connects, sends its version and leaves; at the defaults, `-logips=1`, `-logtimestamps=0` and both: whether the lines begin with the time, whether any names a level or module, whether the peer's address (with its port) is anywhere in the log, whether a version line is logged and whether it names the peer by `peeraddr=` |
| `15 MB old debug.log, <options>: after start` | a 15 MB `debug.log` is in place at start; at the defaults, `-shrinkdebugfile=0`, `-debug` and `-debug -shrinkdebugfile=1`: whether it is cut to its last 200 000 bytes, kept whole, or rotated whole to `debug.log.1` |
| `options warned about as not supported` | all six options given: which of them irondivid names as not supported or unknown in its log |

Message texts are not compared, only the line shape and whether addresses appear in it.

### Why there is no row for some rules

- **`-maxreceivebuffer` itself:** divid reads no peer that has anything queued to be sent to it
  (`SelectCommunicationMode`, `Node.cpp:215-234`), so a peer that does not read is not read either, whatever the
  limit. The flood row shows the same amount taken at each value; what matters is that the peer is kept and others
  are served.
- **The `inv` score while the send buffer is over twice the limit:** the buffer gets there only when one message
  larger than the limit is queued while there is room, a race the script cannot make happen on purpose.
- **Learnt addresses of a limited network not dialled:** regtest addresses are not routable, so divid does not keep
  them (addrman). irondivid's rule is checked by its own tests.

## KNOWN differences

- **`onion limited` with no `-onlynet`, or with one naming `onion` or `tor`:** irondivid always shows onion as
  limited, since it cannot address .onion peers (as in `scripts/net-replies`). divid shows it limited only when
  `-onlynet` leaves it out.
- **`15 MB old debug.log, -shrinkdebugfile=0` and `-debug`:** divid keeps the old file whole. irondivid also rotates
  `debug.log` by size, so an old file over `-maxlogsize` is moved whole to `debug.log.1`
  (`docs/divid-differences.md` S6).

No other row differs from divid.
