# The order of a stop next to Divi Core

`run.sh` starts Divi Core 3.0.0 `divid` and irondivid on regtest, each in its own data directory with a wallet and a
few blocks. It stops each twice, once by RPC `stop` and once by SIGTERM, restarting it between the two. For each stop
it records, from the stop's start to the process's exit:
- **file events:** the files the stop writes, in the order the kernel reports them (inotify), and the pid file's
  removal;
- **log lines:** the debug.log lines the stop writes, first to last;
- **RPC answers:** what an RPC call (`getblockcount`, asked every 10 ms on a new connection) gets while the stop runs.

It prints all three for both daemons, then compares the outcomes, not the timings.

Each row prints one line:
- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15
minutes). `STOP_ORDER_INJECT=<row name>` makes that row differ, to check that a difference is caught.

```sh
scripts/stop-order/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/stop-order/run.sh target/release ~/divi-3.0.0/bin 53800 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute. Signals go only to the processes the script started, and run.sh stops every process it
lists however the run ends. Needs Linux (inotify through libc), bash and python3 (standard library only). RPC
passwords are made at random per run and kept in each node's 0600 `divi.conf`. Nothing leaves the host: each node
binds 127.0.0.2, -connect points at a closed port, and DNS seeds are off.

## divid's stop (Core paths under `divi/src/`)

`DetectShutdownThread` sees the request (RPC `stop` calls `StartShutdown`, rpcserver.cpp:308-318; SIGTERM sets
fRequestShutdown, init.cpp:508-511), interrupts and joins the net threads (divid.cpp:42-53), then `Shutdown()`:

| step | where | what a user sees |
|---|---|---|
| `PrepareShutdown: In progress...` | init.cpp:360 | the stop's first line in debug.log |
| RPC stops | `StopRPCThreads`, rpcserver.cpp:774; connections already end at `ShutdownRequested` (rpcserver.cpp:1003) | a call made after `stop` gets no reply |
| `StopNode()`, peers.dat | net.cpp:1474-1484 (`DumpAddresses`, net.cpp:1059) | the line, then peers.dat written |
| minting, Tor | init.cpp:372-375 | none here (staking off) |
| mncache.dat, mnpayments.dat, netfulfilled.dat | `SaveMasternodeDataToDisk`, MasternodeModule.cpp:284-297 | written in that order, at every stop, each with its "Verifying … / Written info to … / … dump finished" lines |
| chain state and block index | `FlushStateToDisk`, init.cpp:381 | chainstate/ and blocks/ written |
| the wallet | `FinalizeMultiWalletModule` (init.cpp:1335-1341; `BerkleyDBEnvWrapper().Flush(true)`, MultiWalletModule.cpp:73-79) | wallet.dat and database/ written |
| the pid file | init.cpp:396 | removed |
| `MainShutdown: done` | init.cpp:418 | the stop's last line |

Divi Core 3.0.0 has no banlist.dat and no fee_estimates.dat. Its lock file (`.lock`, init.cpp:853) is never removed.

## Rows

| rows (each for `rpc` and `sigterm`) | what is compared |
|---|---|
| `rpc stop: the reply` | the reply to `stop` |
| exit code | the process's exit code |
| RPC while the stop runs | the kinds of answer seen in order (`ok`, `error <code>`, `no reply`) |
| the pid file removed | whether the stop removed it |
| the order of what both write | the order of the files both daemons write: peers.dat, the masternode list (mncache.dat or masternodes.list), mnpayments.dat, netfulfilled.dat, the chain state, the wallet, and the pid file's removal |
| divid's stop lines in the log, in order | `PrepareShutdown: In progress...`, `StopNode()` and `MainShutdown: done` |
| the masternode list written at the stop | whether the stop writes it (mncache.dat in both on the tip; irondivid's masternodes.list before it) |

A database directory (chainstate/, wallet/, database/) counts at its first write. A file written as `<name>.new` and
renamed counts as `<name>`.

## Known differences

None. Each difference this script finds on base-1c0b5e5 is fixed on fix/stop-order-2:
- RPC answered for about 200 ms after `stop`;
- peers.dat was written after mncache.dat, netfulfilled.dat and mnpayments.dat, and netfulfilled.dat before
  mnpayments.dat;
- the log had none of divid's three stop lines.

On base-a7dbc9b irondivid also wrote no masternode list at the stop (only masternodes.list, when the list changed);
since B13's mncache work it writes mncache.dat at every stop, as divid does.

Not compared, as the two keep them in different forms:
- blocks/ (divid's block index; irondivid keeps its index in chainstate/);
- txindex/ and sporks/;
- divid's db.log.
