# What a node keeps across a restart, and block import, next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, side by side, and checks what each
keeps across a clean stop and a `kill -9`: addresses learnt from peers, bans, the masternode list, what a damaged
`peers.dat` or `mncache.dat` does to a start, and the files a new data directory gets. Then both import divid's own
block file: `-loadblock`, `-stopafterblockimport`, `bootstrap.dat`, a file with a bad block, a missing file, and
`-reindex` after an import. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with a count of the rows and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/restart-state/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/restart-state/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` (divid p2p and RPC, then irondivid's), on 127.0.0.2 (or
  `RESTART_STATE_HOST`); `<port-base>+49`, which nothing listens on, is each node's only `-connect` peer, so neither
  dials anything. The test peer connects from 127.0.0.3 (`RESTART_STATE_PEER`).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 3 minutes and is stopped after 10. However it ends, both nodes are stopped and their directories
deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and kept in
each node's 0600 `divi.conf`.

## Nodes

Both listen on their p2p port and are connect-only, with `externalip=1.0.0.255`: divid stores gossiped addresses
only of a network it can reach, and IPv4 counts as reachable once there is a routable local address (`AddLocal`,
`NetworkLocalAddressHelpers.cpp:81-104`); with `discover=0` the external address gives it one. Nothing dials it.

A test peer of the script's own speaks the regtest wire protocol (version 70915) from 127.0.0.3.

## Rows

| group | what is done, and compared |
|---|---|
| files | after one start and clean stop, each file of divid's data directory (its `regtest/` folder merged in): present in irondivid's too; and irondivid's files divid has not |
| addresses | the test peer gossips 100 public addresses (each in its own /16) in one `addr`; a new connection asks `getaddr`: right away, after a clean restart, after a `kill -9` and start, and after gossip then a `kill -9` and start. divid answers with 23% of what it holds (`ADDRMAN_GETADDR_MAX_PCT`; a bucket collision can drop one or two of the 100, so 15-23 count as "about 23%"); connections after the restart |
| bans | a peer of an old protocol version (70000, below divid's 70915) is disconnected and banned, local or not (`main.cpp:370-377`); `listbanned` names it; it cannot connect again; after a restart (divid keeps bans in memory only, `PeerBanningService.h`); after `clearbanned` |
| masternode list | `listmasternodes` after a restart |
| damaged files | `peers.dat` and `mncache.dat` planted empty, cut in half, or 300 random bytes in a stopped node: whether it starts (or its exact error) and what the file holds after a clean stop (rewritten, as planted, empty, gone) |
| import | divid mines 30 blocks; its `blocks/blk00000.dat` is imported into new data directories: `-loadblock` (height, tip); `-loadblock -stopafterblockimport` (the exit, then height and tip); the file as `<datadir>/regtest/bootstrap.dat` (height, tip, and the file renamed to `bootstrap.dat.old`, `init.cpp:698-711`); the file with a bad byte in block 15's merkle root (the import stops at 14); `-loadblock=<missing>` (a warning, height 0); `-reindex` after an import |

After a `kill -9` divid usually refuses its block database ("Block database corruption detected") and is started
with `-reindex`, as `scripts/unclean-stop` records; the rows compare what comes after.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c): `AddrDB.cpp`, `net.cpp`,
`addrman.cpp`, `main.cpp`, `MasternodeModule.cpp`, `flat-database.h`, `init.cpp`.

## KNOWN differences

Each KNOWN row checks the difference is exactly the one below; any other outcome is a FAIL.

- `file blocks/`, `file db.log`, `file wallet.dat`, `file mncache.dat`, `file sporks/`: irondivid keeps the same data
  in its own stores (blocks and the masternode list and sporks in its chain database, the wallet in `wallet/`), not in
  files of divid's format; divid never reads irondivid's data directory.
- `file mnpayments.dat`: irondivid keeps no payment votes across a restart; it has them from peers again (divid writes
  the file, and reads it only with a masternode list, `MasternodeModule.cpp:270-277`).
- `file netfulfilled.dat`: irondivid keeps no record of the masternode sync requests it answered across a restart
  (divid's expire after 5 minutes on regtest, `chainparams.cpp:506`).
- `files only irondivid has`: `wallet/` and `txindex/`, its own stores.
- `mncache.dat empty|truncated|garbage: start`: divid refuses to start on a `mncache.dat` it cannot read ("Error:
  Failed to load masternode cache from"): `CFlatDB::Load` gives up on anything but a readable header with bad data
  (`flat-database.h:225-245`, `MasternodeModule.cpp:262-266`). irondivid does not read `mncache.dat` and starts.
- `masternode list and payment votes kept across a restart` is not run: regtest has no masternode network to fill the
  list or send votes.

No other row differs from divid.

## Proving a difference is caught

`RESTART_STATE_INJECT=<row name>` marks irondivid's outcome of that row as changed, e.g.
`RESTART_STATE_INJECT='getaddr after a clean restart'`: that row prints `FAIL` and the run exits 1.
