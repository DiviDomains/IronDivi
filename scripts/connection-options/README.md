# Connection options next to Divi Core

`run.sh` compares how Divi Core 3.0.0 `divid` and irondivid take the options that decide which peers a node talks
to:

| option | divid's default | what it does in divid |
|---|---|---|
| `-whitelist=<net>` | none | an inbound peer from the network is whitelisted: let in although banned (net.cpp:742, :760), never banned or dropped for misbehaving, only "Warning: not punishing whitelisted peer" (main.cpp:1109-1127), its transactions relayed again even when already in the mempool (main.cpp:794-799), sent its invs without the trickle (Node.cpp:700) and a preferred block source (Node.cpp:1075). It still needs an inbound slot (net.cpp:757). A bad netmask stops the start (net.cpp:1749-1755) |
| `-whitebind=<addr>` | none | listens on the address (port required); every peer coming in on it is whitelisted. With `-whitebind` and no `-bind`, only the `-whitebind` addresses are listened on (net.cpp:1808-1823) |
| `-bind=<addr>` | all addresses | listens on each `-bind`, numeric only, on its own port or `-port` (net.cpp:1809-1814); soft-sets `-listen=1` (net.cpp:1675-1679); with `-listen=0` nothing listens (net.cpp:1803-1828) |
| `-connect=<ip>` | none | dials only these, in a loop (net.cpp:1086-1105), soft-sets `-dnsseed=0` and `-listen=0` (net.cpp:1682-1688). The `-addnode` thread and the `-seednode` one-shots still run beside it (net.cpp:1071-1084, :1214-1271). A dialled peer is still asked for addresses (`getaddr`, main.cpp:438-441), but none of them is dialled. `-connect=0` and `-noconnect` are a `-connect` list of one name that never resolves: nothing is dialled but the added nodes and one-shots |
| `-addnode=<ip>` | none | dialled by address every 2 minutes, one connection per IP, a banned address skipped (net.cpp:1214-1285) |
| `-seednode=<ip>` | none | dialled once by name, asked for addresses and dropped after its answer (net.cpp:1071-1084, main.cpp:556-557) |
| `-maxconnections=<n>` | 125 | atoi64, at most 1024 less one for `-bind` and one for `-whitebind` (at least one) less 150, at least 0 (net.cpp:1726-1728), and at most what the file limit allows less 150 (net.cpp:1661-1667). Inbound peers may use it less 16 (net.cpp:757). Dialled peers do not count against it: Divi Core f8c0d2e67 took the outbound semaphore out of every dial, so divid dials without a limit (net.cpp:1128-1179) |
| `-onlynet=<net>` | all | a name ParseNetwork does not know stops the start (net.cpp:1734-1741) |
| `-timeout=<ms>` | 5000 | the connect timeout; 0 or less is the default (net.cpp:1719, netbase.cpp:51-54) |
| `-maxuploadtarget`, `-peertimeout` | — | not divid options: stored and never read, without a word (Settings.cpp:130-150) |

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, a port in use, interrupted, or
over 30 minutes).

```sh
scripts/connection-options/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/connection-options/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+29`, checked to be free first. Each node gets a p2p, an RPC, a
  second `-bind` and a `-whitebind` port, and five raw targets.
- `[root]`: a fresh directory (mode 0700) is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.
- `CONNECTION_OPTIONS_ONLY=<text>` runs only the cases whose name holds the text.

A run takes about 6 to 10 minutes. However it ends, every node is stopped and every directory deleted. Needs bash,
`ss` and python3 (standard library only).

## Nothing leaves the host

- Both nodes listen on 127.0.0.150 (and 127.0.0.151 for a second `-bind`); RPC on 127.0.0.150 only.
- Raw peers connect from 127.0.0.160 to 127.0.0.192, one or more addresses per case, so a ban or a whitelist entry
  of one case does not reach another.
- Raw targets listen on 127.0.0.193 to 127.0.0.197, one address each, because divid dials an added node by address
  and skips one whose IP it is already connected to (net.cpp:1281-1285).
- No case has an address off the host: the misbehaving `addr` messages carry 127.1.x.y addresses, `-discover=0`,
  `-listenonion=0`, and no `-upnp`.
- RPC passwords are random per run, in 0600 `divi.conf` files.

## The raw peers

- **Peer:** connects from its own address, sends a version (`Divi Core: 3.0.0.0`, height 0), answers the verack,
  records each `inv` and answers pings.
- **Target:** listens for a node to dial it; answers the version with its own, a verack and a spork count of 0, as
  a divid answers a peer that dialled it (main.cpp:417-420). One case has targets that send no spork count.

## Cases

Each case starts both nodes on fresh regtest datadirs with the case's `divi.conf` lines and compares:
- the start: up, or the exit code and the first error line;
- `getpeerinfo` as (address, inbound, whitelisted), and `getnetworkinfo` `connections`;
- `listbanned`;
- whether a port listens and whether a raw peer gets in, stays or is dropped;
- which peers are told of a new block or of a transaction sent again;
- the log lines: divid's parameter interactions (net.cpp:1675-1716) and its refusals of a peer ("dropped (full)",
  "dropped (banned)", "not punishing whitelisted peer").

| group | cases |
|---|---|
| defaults | `-bind` only |
| `-whitelist` | two networks; a whitelisted and a plain peer misbehaving (5 `addr` messages of 1001); `ban outdated` of a whitelisted and a plain old peer, and both again; a bad netmask, twice |
| `-whitebind` | alone; with `-bind`; without a port |
| `-bind` | twice; twice with `-listen=0` |
| `-connect` | alone; to a peer that sends no spork count; `-connect=0` and `-noconnect`, each with `-addnode`; with `-addnode` and `-seednode` at the default, 1 and 0 `-maxconnections` |
| `-addnode` | twice, with `-maxconnections=1` and `=0` |
| inbound slots | `-maxconnections` 17, 16, 0, -1, empty and `abc` (with `-debug=net`); 16 without `-debug`; 16 with the peer whitelisted |
| `-onlynet` | `bogus` |
| `-timeout` | 1, 0, -5, `abc`, 100000 (each still dials its `-connect` peer) |
| not divid's | `-maxuploadtarget=100`, `-peertimeout=5` |
| relay | a new block to a plain, a whitelisted and a `-connect` peer; a transaction sent again by a plain and by a whitelisted peer |

## KNOWN

| rows | why |
|---|---|
| the starts of `-whitelist=127.0.0.1/33`, `-whitelist=not-a-net`, `-whitebind` without a port, `-onlynet=bogus` | the same error on both. divid then aborts (SIGABRT, exit -6) in the shutdown after the early InitError; irondivid exits 1, as `scripts/start-errors` lists |
| `listbanned` | divid answers `{"banned:": "<text list>"}`, irondivid an array; the same addresses (KNOWN in `scripts/bans` and `scripts/net-replies`) |
| `-maxuploadtarget=100`, `-peertimeout=5`: the log names the option | divid says nothing of an option it does not know; irondivid warns about each (`option_warning` in bin/irondivid/src/main.rs) [by design] |
| `-connect to a peer that sends no spork count`: what the peer was sent, and whether it is told of a new block | divid sends a peer it dialled nothing after the handshake (no ping, getblocks or inv) until that peer has sent its spork count and that many sporks (`CNode::CanSendMessagesToPeer`, Node.cpp:1024-1036); irondivid has no such wait. It belongs to the handshake, not to these options |

Not compared here, with the reason:

- **Dialling learnt addresses without a limit:** divid dials one address book entry per network group every 500 ms
  with no outbound limit (net.cpp:1128-1179). irondivid dials at most 16 (`dial_learnt`). The address book takes
  only routable addresses, so no host-only run can show it, and copying it would let irondivid open any number of
  connections on mainnet.
- **The file limit on `-maxconnections`:** divid lowers `-maxconnections` to the open-file limit less 150
  (net.cpp:1661-1667); irondivid does not. On hp1 the limit is 1048576, above any value the 1024 cap allows.
- **The trickle and the preferred block source of a whitelisted peer** (Node.cpp:700, :1075): timing and download
  order, not a reply a row can compare.
- **`-onlynet` with a known name:** irondivid only checks the name; what the networks then show is the `-onlynet`
  work's.

## Results on hp1 (divid 3.0.0)

| irondivid | PASS | KNOWN | FAIL | time |
|---|---|---|---|---|
| `fix/connection-options` (965e509), run 1 | 162 | 10 | 0 | 6 m 0 s |
| `fix/connection-options` (965e509), run 2 | 162 | 10 | 0 | 5 m 10 s |
| its base (d7389c0) | 128 | 10 | 34 | 7 m 2 s |

On the base, every FAIL is one of five differences: `-maxconnections` below 0, empty or text; the added nodes held
back by `-maxconnections`; only the first `-bind` listened on; the parameter interactions not logged; a refused
peer logged with other text.
