# -forcestart, -sysperms, -rpcthreads and the alert options, next to Divi Core

`run.sh` starts Divi Core 3.0.0 `divid` and irondivid on regtest, each on a chain of its own, and compares what each
option visibly does. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches divid
  (the list below is out of date).

The rows cover:
- how a node starts after a `kill -9` (plain, with `-forcestart`, with `-reindex`);
- the modes of the files and directories it makes;
- how many RPC connections it serves at once;
- what it does with a raw peer's badly signed alert;
- the warning, and the `-alertnotify` command, that a run of newer-version blocks raises.

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 15 minutes).

```sh
scripts/start-rpc-options/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/start-rpc-options/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` (divid p2p and RPC, then irondivid's), on 127.0.0.2, or on
  `START_RPC_OPTIONS_HOST` when it is set. `<port-base>+49`, which nothing listens on, is each node's only `connect=`
  peer, so neither dials anything.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 6 minutes and is stopped after 15. However it ends, both nodes are stopped and their directories
deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and kept in
each node's 0600 `divi.conf`. The nodes are started with umask 022, so "the system default" is 0644 files and 0755
directories. The `-alertnotify` command only writes a marker file inside the node's own data directory.

## Rows

| group | what is done | what is compared |
|---|---|---|
| `-forcestart` | each node mines 30 blocks and is killed (`kill -9`); copies of that data directory are started plain, with `-forcestart`, with `-reindex`, with both; then a cleanly stopped one with `-forcestart` | whether it starts (or the exit code and first error line), and the height |
| `-sysperms` | a fresh node is started and stopped, with nothing, `-sysperms=0`, `-disablewallet`, `-sysperms -disablewallet`, and `-sysperms` with the wallet on | the set of file modes and the set of directory modes it made (divi.conf is the script's), or the start error |
| `-rpcthreads` | default, 1, 2, 0, -1: with N keep-alive connections held open, each with one call answered, a connection N+1 makes a call; then one held connection is closed | whether the Nth is answered, whether N+1 is answered while N are held (5 s), and once one closes. With 0 and -1: whether the node runs, and whether a call is answered |
| `-alerts` | default, `-alerts=0`, `-alerts=1`: a raw peer sends an alert in effect for every version, with a signature that is not the alert key's; then the same alert again | the raw peer's `banscore` in `getpeerinfo` after each |
| `-alertnotify` | a raw peer sends proof-of-work blocks on genesis: 52 of version 5, 50 of version 5, 52 of version 4; with `-alertnotify=echo %s > <datadir>/alert-marker`, and 52 of version 5 without it | the height, `getinfo` and `getmininginfo` `errors`, and what the command wrote |

What divid does (Core paths under `divi/src/` of Divi Core v3.0.0, commit 9e2f76c):
- **`-forcestart`:** after a stop that was not prepared, divid checks two things, unless given `-forcestart` or
  `-reindex` (`BlockIndexLoading.cpp:258-285`). Its best block must be in the block index, else it refuses with
  "Block database corruption detected! Failed to find best block in block index". Its coin database must be at that
  block, else it is rolled back and forward to it.
- **`-sysperms`:** without it, umask 077 (`init.cpp:1378-1385`). With it and the wallet on, divid refuses to start.
- **`-rpcthreads`:** N threads run the RPC service (`rpcserver.cpp:755-757`, default 4). Each serves one connection
  to its end, idle keep-alive waits included (`ServiceConnection`, `:1000-1010`).
- **`-alerts`:** read on by default (`net.cpp:1651-1659`). An alert that cannot be processed, here a bad signature,
  scores 10 (`main.cpp:870-890`). With `-alerts=0` the message is not read.
- **`-alertnotify` and the version warning:** once out of initial download (`ChainSyncHelpers.cpp:33-50`), more than
  50 of the last 100 blocks above version 4 set the warning "Warning: This version is obsolete, upgrade required!"
  and run the command once (`ChainTipManager.cpp:43-60`). The command gets `%s` replaced by the text, kept to the
  safe characters and in single quotes (`CAlert::Notify`, `alert.cpp:218-235`). getinfo and getmininginfo show the
  warning as `errors` (`rpcmisc.cpp:156`, `rpcmining.cpp:242`, `Warnings.cpp`).

The blocks are built by the script: a coinbase with the BIP34 height push paying nothing, a header of the given
version with an empty accumulator checkpoint, hashed with sha256d (version 4 and above) to the regtest target.

## KNOWN differences

- **`after kill -9: plain start`:** divid refuses with "Block database corruption detected!": its block index is
  behind its best block after the kill. irondivid writes each block's chain state in one batch and starts at its
  last whole block. The row passes if divid starts too (what divid had flushed when it was killed decides).
- **`after kill -9: -forcestart`:** both start. divid skips its checks and starts from what its coin database had
  flushed (here less than it had mined). irondivid starts from its last whole block, which is all of it.
- **`modes made with -sysperms (wallet on)`:** the same error. divid then aborts (SIGABRT, exit -6) in the shutdown
  after this early InitError, as `scripts/start-errors` records; irondivid exits 1.
- **`regtest alert signed with the alert key`:** not sent. A valid alert needs the private half of the regtest alert
  key (`chainparams.cpp:392`), which no test has. irondivid takes no signed alert (docs/divid-differences.md S7).

No other row differs from divid.

## Proving a difference is caught

`START_RPC_OPTIONS_INJECT=<row name>` changes irondivid's outcome of that row before it is compared, e.g.
`START_RPC_OPTIONS_INJECT='bad alert with -alerts=0'`: that row prints `FAIL` and the run exits 1.
