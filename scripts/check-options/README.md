# The debug and check start options next to Divi Core

`run.sh` starts Divi Core 3.0.0 `divid` and irondivid on regtest with the debug and test options of divid's help
that no other script covers (`LicenseAndInfo.cpp:163-201`). The options are:
- `-checkblockindex`, `-checkmempool`;
- `-checkpoints`;
- `-dropmessagestest`, `-fuzzmessagestest`;
- `-flushwallet`;
- `-stopafterblockimport`;
- `-maxsigcachesize`;
- `-printpriority`.

For each, it compares whether the node starts, whether its log calls the option unknown or unsupported, what can be
seen of its effect, and whether `-help -help-debug` lists it.

Each row prints one line:
- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 25
minutes).

```sh
scripts/check-options/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/check-options/run.sh target/release ~/divi-3.0.0/bin 53700 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.2:
  - divid's p2p and RPC, then irondivid's;
  - then the two nodes of the `-loadblock` rows.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 10 minutes. However it ends, every node is stopped and the directories deleted. Needs bash and
python3 (standard library only). RPC passwords are made at random per run and kept in each node's 0600 `divi.conf`.

## The options in divid (Core paths under `divi/src/`)

| option | divid reads it | default | `=0` / `=1` / no value / `-1` / `abc` | what can be seen |
|---|---|---|---|---|
| `-checkblockindex` | `BlockCheckingHelpers.cpp:162`, a full check of the block index after each change | on with regtest, off otherwise (`chainparams.cpp:248, :358, :438, :516`) | boolean: off, on, on, on, off (`Settings.cpp:25-30`) | nothing while the index is sound: stays up |
| `-checkmempool=<n>` | `init.cpp:795`, read as a boolean although the help says every n transactions | as above | as above | nothing while the mempool is sound |
| `-checkpoints` | no: only in help (`LicenseAndInfo.cpp:165`) | | | nothing |
| `-dropmessagestest=<n>` | `main.cpp:473`, `Node.cpp:479`: a message is dropped when `GetRand(n) == 0` | unset | `=0`, `=1`, no value, `abc` drop every message; `-1` almost none | messages lost; the run uses 1000 and only checks that the node connects and stays up |
| `-fuzzmessagestest=<n>` | `Node.cpp:484-485`: one sent message in n is corrupted after the handshake | unset | as above | the same |
| `-flushwallet` | `init.cpp:1281`, a thread that flushes the wallet database | on | boolean | nothing |
| `-stopafterblockimport` | `init.cpp:724-727`, at the end of the import thread, which runs at every start (`init.cpp:686-728`) | off | boolean | the node stops right after it starts; with `-loadblock` after the import |
| `-maxsigcachesize=<n>` | `script/sigcache.cpp:51`, entries of the signature cache | 50000 | a number | nothing |
| `-printpriority` | no: only in help (`LicenseAndInfo.cpp:201`) | | | nothing: no priority line when a block is made |

divid never writes a word about an option it does not know or does not use.

## Rows

| rows | what is compared |
|---|---|
| `-help -help-debug lists -<option>` | whether the help output names it |
| start with every option `=0`, `=1`, with no value (command line), `=-1`, `=abc`; and per option and value, whether the log calls it unknown or unsupported | start outcome; the log lines |
| `-stopafterblockimport` with each value | up or stopped by itself, against refused (whether RPC answers before the stop is a race on both, and divid exits 1 when the stop comes during its init, 0 after); whether it has stopped within 60 s |
| `-loadblock=<blk00000.dat of divid>` with `-stopafterblockimport=1` on fresh data directories | start (up or stopped, as above), stopped within 120 s, start again, the height |
| `-checkmempool=1 -checkblockindex=1`, and both `=0` | up after three sends, two blocks, `invalidateblock` and `reconsiderblock` of the tip; blocks added; mempool size |
| `-printpriority=1` | whether a block made with a transaction writes a priority and fee line |
| `-dropmessagestest=1000`, `-fuzzmessagestest=1000` | the two nodes connected to each other; up after three blocks each (no timing compared) |

## KNOWN differences

- **`-help -help-debug lists -<option>`** (nine rows):
  - divid's help prints every option, the debug ones among them (`LicenseAndInfo.cpp:160-202`).
  - irondivid's `-help` is its own short summary of the common options, with no debug section (`USAGE`,
    bin/irondivid/src/main.rs:88-107). By design.

Not compared, so not rows; also KNOWN:
- **`-dropmessagestest` and `-fuzzmessagestest` are taken but not honoured** (bin/irondivid/src/main.rs,
  `NO_COUNTERPART`). They are fault injection for divid's own tests: random drops and corruption in its message
  layer (`main.cpp:473`, `Node.cpp:479-485`). irondivid takes them, as divid does, and leaves its messages alone.
- **`-checkblockindex`, `-checkmempool`, `-flushwallet` and `-maxsigcachesize` are taken; their effect cannot be
  seen from outside.** irondivid has no counterpart: its checks and caches are its own.
- **`-checkpoints` and `-printpriority` are taken with no effect, as in divid.**

## Proving a difference is caught

`CHECK_OPTIONS_INJECT=<row name>` replaces irondivid's value in that row, which must then FAIL. A build from before
fix/check-options (0859960) fails the 40 log rows.
