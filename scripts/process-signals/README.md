# The daemons as processes next to Divi Core

`run.sh` starts Divi Core 3.0.0 `divid` and irondivid on regtest, each in its own data directory with a wallet and
500 blocks. It runs the same process cases on both and compares the outcomes, not the timings:
- SIGTERM and SIGINT idle, during start, during `-reindex` and during `-rescan`;
- SIGHUP with debug.log moved away;
- SIGPIPE;
- a second start on a data directory in use;
- the pid file;
- `-daemon`.

Each row prints one line:
- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15
minutes).

```sh
scripts/process-signals/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/process-signals/run.sh target/release ~/divi-3.0.0/bin 53700 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2, and 20 above them for the second start.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 8 minutes. Signals go only to the processes the script started, by their own pid, and run.sh
stops every process it lists (the `-daemon` child too) however the run ends. Needs bash and python3 (standard library
only). RPC passwords are made at random per run and kept in each node's 0600 `divi.conf`.

## What divid does (Core paths under `divi/src/`)

| case | divid |
|---|---|
| SIGTERM, SIGINT | a handler sets fRequestShutdown (init.cpp:508-511, :1388-1394), installed at the start of init |
| a stop during init | init returns `!fRequestShutdown` (init.cpp:1536-1539, :1661): false, so exit code 1 (divid.cpp:180); `Shutdown()` still runs (divid.cpp:166) |
| a stop after init | exit 0, log ending `MainShutdown: done` (init.cpp:418) |
| `-reindex` | runs in the import thread after init (init.cpp:686-728): a stop during it exits 0; the next start goes on with it |
| `-rescan` | runs in init, at the wallet load: a stop during it exits 1 |
| shutdown order | RPC, then the network with peers.dat (net.cpp:1474-1485), minting, masternode data, then the chain state, the wallet, the pid file, and the peer connections last (init.cpp:371-417) |
| SIGHUP | the next log write reopens debug.log (init.cpp:513-516, :1396-1401; Logging.cpp:173-178) |
| SIGPIPE | default action (ends the process), ignored only on Solaris (init.cpp:1404-1406) |
| the lock | `<datadir>/regtest/.lock`, waits 10 s, then `Error: Cannot obtain a lock on data directory <dir>. DIVI Core is probably already running.` (init.cpp:850-861), and divid aborts (SIGABRT) |
| the pid file | `-pid`, default `divid.pid`, relative to the network data directory (util.cpp:115-120); written after the lock (init.cpp:1470) as `<pid>\n` (util.cpp:122-128); removed at the end of `Shutdown()` (init.cpp:396); left by a kill and overwritten at the next start |
| `-daemon` | prints `DIVI server starting` on stdout and forks once; the parent exits 0; the child calls setsid and keeps the working directory and stdout/stderr (divid.cpp:122-140) |

## Rows

| rows | what is compared |
|---|---|
| pid file while running | missing, or whether it names the process and ends with a newline |
| SIGHUP | still running; a new debug.log written after a block; the moved log stopped growing |
| second start (other ports, same data directory) | exit code; the error up to the directory; the first node still answers; the first node's pid file |
| SIGTERM / SIGINT idle | exit code; the log ends with the node's shutdown line; pid file after; height and balance at the next start |
| SIGTERM / SIGINT during start (sent once the pid file is there, before RPC answers) | that RPC had not answered; exit code; pid file after; height and balance at the next start |
| SIGTERM / SIGINT during `-reindex` (sent a second after RPC answers, once divid's init has returned) | exit code; height and balance once the next start has the chain again |
| SIGTERM during `-rescan` (sent once the pid file is there) | exit code; height and balance at the next start |
| kill -9 | the pid file left; the next start names its own pid |
| `-pid=other.pid`, `-pid=<absolute>` | the file while running; after a clean stop |
| `-daemon` (started from the work directory) | the parent's exit code and first stdout line; the child answers RPC, has the parent's working directory and stdout, and stops on `stop` |
| a stop while staking (`staking=1`, a raw peer connected, SIGTERM after 15 s) | a peer to stake for; exit code; peers.dat written; the next start has the chain up to the stop, and its height and balance equal a `-rescan` start's (divid stops minting before it flushes, init.cpp:372-373, :381, :386) |
| a start and a clean stop | the lines on stderr (divid: its InitWarning about the unencrypted wallet, init.cpp:1227-1232) |
| SIGPIPE | still running |

Where a file lives differs by layout: divid keeps regtest files in `<datadir>/regtest`, irondivid in `<datadir>`. The
script reads each in its own place.

## KNOWN differences

- **`second start: exit code`:**
  - divid aborts once InitError has refused the lock: SIGABRT, -6 (init.cpp:850-861, :381; also KNOWN in
    scripts/start-errors).
  - irondivid exits 1 with the same error.
- **`SIGPIPE: still running`:**
  - divid keeps SIGPIPE's default action, which ends the process (init.cpp:1404-1406).
  - irondivid ignores it, as Rust programs do, so a stray SIGPIPE does not kill the node. By design.

## Proving a difference is caught

`PROCESS_SIGNALS_INJECT=<row name>` replaces irondivid's value in that row, which must then FAIL. Or run the base
build (aa40841), which fails the pid file, exit code and `-daemon` rows.
