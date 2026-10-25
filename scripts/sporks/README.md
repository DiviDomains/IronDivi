# Spork messages next to Divi Core

`run.sh` starts two fresh Divi Core 3.0.0 `divid` and two fresh irondivid on regtest, sends the same spork messages
to both kinds from raw peers, and compares what each does. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason (none at present);
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15
minutes).

```sh
scripts/sporks/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a build of this tree
cargo build -p irondivid
scripts/sporks/run.sh target/debug ~/divi-3.0.0/bin 55400 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+49` on 127.0.0.2 (the last is the dead port below).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end, with every
  node stopped, however the run ends.

A run takes about a minute. Needs bash and python3 (standard library only). RPC passwords are made at random for each
run and kept in each node's 0600 `divi.conf`.

## Nodes

For each kind there are two nodes, both on 127.0.0.2: the receiver, and a second hop that dials the receiver and has a
raw observer connected to it. The receiver is connect-only to a dead port, so it dials nobody. Raw peers made here
connect to the receiver from their own addresses (127.0.0.11 and up), one per row, and answer `version` and `ping`.

## Rows

| rows | what is sent | what is compared |
|---|---|---|
| state | `spork show`, `spork active`, an unknown name, a set without the key, a set of a multi-value spork, no arguments, an unknown mode | the replies |
| after the handshake | nothing | the messages the node sends by itself, in order (`version`, `verack`, `sporkcount`), and the count |
| `getsporks` with no sporks | `getsporks` | no `spork` comes back; the peer stays |
| `sporkcount` | 0, 5, -1, a 2-byte payload, an empty payload | `getsporks` is sent back (or not); the peer stays |
| a spork with a bad signature | 16 kinds: a known id with a signature of the right shape (this time, a newer one, one long ago, time 0), a multi-value id, an unknown id, an unused id (10003), id 0, a negative id, an empty signature, 64 and 66 bytes, a recovery byte for an uncompressed key, a recovery byte 0, an empty value, a value of 5000 bytes | the connection is closed; no ban (a local peer is only dropped); the peer is gone from `getpeerinfo` |
| a spork that cannot be read | 3 bytes, nothing, bytes after the signature | whether the connection is closed |
| nothing is kept, served or announced | `getsporks` from a new peer; `spork show` and `active`; the observer on the second hop | no `spork` and no spork `inv` comes out; the count a new peer is told is 0; no peer is dropped from the second hop |
| `inv` of a spork | one it does not hold; the same twice; three at once | `getdata` for it, once; for all three |
| `getdata` of a spork | one it does not hold | `notfound` with the item |
| after a restart | the state rows again | the replies; the count; no spork served |

## What a node accepts

A spork is kept only if its signature recovers to the network's spork key. Regtest uses the testnet key
(divid `chainparams.cpp:443`; irondivid `crates/divi-network/src/spork.rs`), and `-sporkkey` is accepted only if it
belongs to that key (`spork.cpp:461-480`, `init.cpp:968-977`). Nobody here holds that key, so no spork can be signed
on regtest, and every spork this script sends is refused by both kinds. These rows therefore cannot be compared with
divid, and are tested on irondivid alone, with a key made in the test (`crates/divi-network/src/spork.rs`, tests;
`crates/divi-node/tests/spork_restart.rs`), citing the divid lines:

- a good spork is kept, written to the spork database and relayed as an `inv` (`spork.cpp:255-259`);
- a spork no newer than the active one is only counted, with no signature check (`spork.cpp:229-235`), except a
  multi-value spork (ids 10012 to 10015), which is checked and kept in time order (`spork.cpp:144-168`);
- a second spork with the same time as the active one is "seen" (`IsNewerSpork`, `spork.cpp:170-181`);
- sporks, their order, their count, and what a restart loads (`spork.cpp:192-211`);
- `getdata` of a held spork (`ShareSporkDataWithPeer`, `spork.cpp:41-50`).

The node tests seed a node's database with sporks, which divid also loads without checking them again
(`LoadSporksFromDB`, `spork.cpp:192-211`), and compare irondivid's answers with what that code gives.

## Calls already compared by other scripts

`net-replies` (`spork` without the key, an unknown name, no arguments), `masternode-replies` (`spork show` and `active`
before and after a restart, an unknown name, a set without the key, the value as a number, no arguments, an unknown
mode, `show` with a value, three arguments), `restart-options` (`spork show` after a restart, `-sporkkey` with a key
that is not the spork key), and `unclean-stop` (the sporks after `kill -9`). This script repeats a few `spork` calls
for the state it needs; it adds the wire.
