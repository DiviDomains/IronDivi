# Refused starts and divi.conf next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest once each, then starts both again,
case by case, with the same bad or odd start: bad option values, options that conflict, `divi.conf` forms, missing
or unusable data directories, a second instance on one data directory, and `-?` / `-help` / `-version`. Each case
compares whether the node starts, its exit code and the first error line it prints. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with a count of the rows and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/start-errors/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/start-errors/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: the nodes' ports are `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then
  irondivid's). A few cases move a node to another port, all below `<port-base>+50`: an RPC port 10 above its own
  (the divi.conf rows that tell which value wins), 20 above (the second instance), a p2p port 40 above (`-listen=1`),
  and `<port-base>+49`, which nothing listens on, as both nodes' only peer.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 5 minutes and is stopped after 10. However it ends, every node is stopped and the directory
deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and kept in
each node's 0600 `divi.conf` in the run directory; no secret goes on a command line.

## How a case runs

After one clean start each node's data directory is kept as a template; each case starts from a copy of it, so a
case cannot spoil the next. Both nodes run a case at the same time. A case's outcome is one of:

- `up`: RPC answers (with the node's credentials) on its RPC port, or on the other port the case names;
- `running, no RPC`: neither answers nor exits within 10 s of nothing listening;
- `exit <code> "<line>"`: the exit code (a negative code is the signal that ended it) and the first stderr line that
  starts with `Error` (else the first line). The node's own data directory path reads `<datadir>` (divid keeps
  regtest data in `<datadir>/regtest`, irondivid in `<datadir>`), so the two lines compare.

A node still running when its outcome is known is killed: the next case starts from the template again. Rows with
`: warns` also compare whether the named warning is in the node's log.

## Rows

| group | cases |
|---|---|
| bad values | `-port` abc/0/70000, `-rpcport` abc/0/70000, `-maxconnections` -1/abc, `-dbcache` 0/99999999, `-par` -100/abc, `-keypool=-1`, `-paytxfee=abc`, `-mintxfee=abc` (neither is a divid 3.0.0 option), `-maxtxfee` abc/-1/99999999999, `-bind` garbage/300.1.1.1, `-externalip=garbage`, `-onlynet=bogus`, `-proxy=garbage`, `-timeout` 0/abc, `-banscore=0`, `-bantime=-1`, `-prune=550` (not a divid 3.0.0 option), an unknown option with and without a value, `-rpcbind=garbage` with `-rpcallowip`, `-rpcallowip` garbage and `1.2.3.4/99` |
| conflicts | `-bind` with `-listen=0`, `-connect` with `-listen=1`, `-rpcbind` without `-rpcallowip` (and its warning), `-txindex=0` on an indexed data directory, `-txindex=1`, `-server=0` |
| divi.conf | an unknown key, spaces around `=`, a comment after a value, a comment line, a repeated key (which value wins), the command line over the file, `[main]` and `[regtest]` sections, a line with no `=` (before and after the keys), an empty value, a key starting with `-`, `no<key>=1`, CRLF line ends, no `rpcpassword`, no `rpcuser` and no `rpcpassword`, an empty file with the options on the command line, `-conf=<missing>`, `-conf=<another file>`, `-conf=<a name relative to -datadir>`, an unreadable `divi.conf` |
| data directories | `-datadir=<missing>`, `-datadir=<a file>`, `-datadir=<a read-only directory>`, a second instance on the data directory of a running node |
| help | `-?`, `-help`, `-h`, `--help`, `-version`, `--version`, `-V`: exit code and first line of stdout |

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c): `divid.cpp` (AppInit: help,
data directory, config file), `init.cpp` (AppInit2), `net.cpp`, `rpcserver.cpp`, `Settings.cpp`.

## KNOWN differences

Each KNOWN row checks the difference is exactly the one below; any other outcome is a FAIL.

- `start -maxtxfee=abc`, `=-1`, `=99999999999`, `start -externalip=garbage`, `start -onlynet=bogus`,
  `start -proxy=garbage`: the same error line; divid then aborts (SIGABRT, exit -6) in the shutdown that follows an
  early InitError: `PrepareShutdown`'s `FlushStateToDisk` (`init.cpp:381`) asserts in `ChainstateManager::Get`
  (`ChainstateManager.cpp:102`) before the chain state exists. irondivid exits 1.
- `second instance on the same data directory`: divid's lock text (`init.cpp:850-862`) with irondivid's product
  phrase, "Divi Core or irondivid is probably already running." (as irondivid's P2P bind error says it); divid then
  aborts as above.
- `-conf=<a missing file>`, `divi.conf unreadable`: with no readable `divi.conf` both run as mainnet. divid refuses
  for want of an `rpcpassword` (`rpcserver.cpp:655-680`; mainnet requires one, `chainparams.cpp:245`) and aborts as
  above; irondivid makes an RPC cookie instead (by design, `crates/divi-rpc/src/auth_cookie.rs`) and refuses later:
  this regtest data directory as another network's, or the unreadable file by name (divid reads an unreadable file as
  none, `Settings.cpp:186-195`).
- `-datadir=<a read-only directory>`: divid dies on an uncaught `boost::filesystem_error` creating
  `<datadir>/regtest` ("EXCEPTION: N5boost10filesystem16filesystem_errorE ... Permission denied", SIGABRT);
  irondivid refuses with exit 1 and the error.
- `-?`, `-help`, `--help`, `-version`, `--version`: first line. irondivid names itself and its version
  ("IronDivi Daemon version v<version>") where divid prints "Divi Core Daemon version v3.0.0" (`divid.cpp:70-85`).
  The exit codes are the same (1).

No other row differs from divid.

## Proving a difference is caught

`START_ERRORS_INJECT=<row name>` gives irondivid a missing `-datadir` in that case, e.g.
`START_ERRORS_INJECT='start -timeout=0'`: that row prints `FAIL` and the run exits 1.
