# The divid options no other script compares

`run.sh` starts Divi Core 3.0.0 `divid` and irondivid on regtest with each divid option that no other script or Rust
test compared with divid. That is every option divid reads (`GetArg`, `GetBoolArg`, `ParameterIsSet`,
`GetMultiParameter` in `src/`) or lists in its help (`LicenseAndInfo.cpp`) that was in none of irondivid's option
lists, or was in one with nothing comparing it. `-proxy`, `-onion`, `-listenonion`, `-torcontrol`, `-torpassword`
and `-proxyrandomize` are left to the proxy and onion work.

Each option is given as `=0`, `=1`, with no value, with a typical value (where it takes more than a boolean) and as
`=abc`, on the command line. Each start is on a copy of a data directory that holds a wallet and a 5-block chain.
The rows compare:
- whether the node starts (or its exit and first error line);
- the debug.log lines that name the option, as their message;
- the one effect the option has that a short regtest run can show (below).

Each row prints one line:
- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 15 minutes).

```sh
scripts/options-left/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/options-left/run.sh target/release ~/divi-3.0.0/bin 54350 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: six pairs of nodes run at once, on ports `<port-base>` to `<port-base>+23` on 127.0.0.2;
  `<port-base>+49`, which nothing listens on, is each node's only `-connect` peer.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute and is stopped after 15. However it ends, every node is stopped and its directory
deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and kept in
each node's 0600 `divi.conf`.

## Options and effects

| option | divid 3.0.0 | effect compared |
|---|---|---|
| `-accountlabels` | the default account's coins in every send (`rpcwallet.cpp:445-467`, `:715`) | none in a short run |
| `-activeversion` | the masternode protocol version (`version.cpp:11-17`, help `:174`) | none |
| `-benchmark` | true: "Warning: Unsupported argument -benchmark ignored, use -debug=bench." (`init.cpp:786-787`) | the line |
| `-blockversion` | regtest: the version of the blocks made (`BlockFactory.cpp:90-95`); below 3 a block it refuses (`ChainExtensionService.cpp:350-352`) | `setgenerate 1`: the block's version, or the error |
| `-dblogsize`, `-privdb` | its Berkeley DB wallet environment (`db.cpp:101`, `dbenv.cpp:68`) | none |
| `-debugnet` | true: "Warning: Unsupported argument -debugnet ignored, use -debug=net." (`init.cpp:773-774`) | the line |
| `-disablesafemode` | the calls safe mode refuses still run (`rpcserver.cpp:1052`) | with `-testsafemode` |
| `-force_rescan` | the start's wallet scan from the genesis block (`wallet.cpp:261-262`) | the "Scanning... from height H to N" line |
| `-help-debug` | the debug section of `-help` (`LicenseAndInfo.cpp:140-231`) | `-help -help-debug` against `-help` |
| `-manual_fork` | the time of two forks (`ForkActivation.cpp:50-55`) | none |
| `-mocktime` | the clock from the start (`divid.cpp:140-143`) | `setgenerate 1`: the block's time is the mock time, now, or other |
| `-nodebug` | `-debug=0`, as any `-no<name>` (InterpretNegativeSetting, `Settings.cpp:32`; help `:184`) | none |
| `-override_mnpayee` | a block with a bad masternode payment accepted (`BlockIncentivesPopulator.cpp:224`) | none |
| `-printcoinstake`, `-printstakemodifier`, `-windowtitle` | help only (`LicenseAndInfo.cpp:150`, `:215-216`) | none |
| `-prunewalletconfs` | the wallet's fully spent transactions left out in memory, and a line with the counts (`wallet.cpp:1162-1239`) | the "Pruned wallet transactions" line |
| `-recoverblockdb`, `-safe_shutdown` | the shutdown flag of its block index, and the recovery after a stop that was not prepared (`BlockIndexLoading.cpp:258-283`) | none |
| `-socks` | given at all: refused, "Error: Unsupported argument -socks found. …" (`init.cpp:776-777`) | the start |
| `-stakeupdatetime` | how often the staker selects its coins again (`PoSTransactionCreator.cpp:116`) | none |
| `-testsafemode` | safe mode: getinfo's errors "testsafemode enabled", the calls not marked okSafeMode refused with -2 (`Warnings.cpp:32-33`, `rpcserver.cpp:1049-1054`) | getinfo's errors and getbalance |
| `-tor` | true: refused, "Error: Unsupported argument -tor found, use -onion." (`init.cpp:779-781`) | the start |
| `-whitelisted_vault` | vault scripts the wallet takes (`init.cpp:1182-1191`) | none |
| `-blockmaxsize`, `-blockminsize` | atoi64 into an unsigned int, never refused (`BlockMemoryPoolTransactionCollector.cpp:18-42`) | none |
| `-dns` | name lookups for `-addnode`, `-connect` and the like | none |
| `-upnp` | UPnP port mapping; only `=0` and `=abc` are given, which turn it off, so the run makes no UPnP traffic | none |
| `-printtoconsole` | the log on stdout, and not in debug.log | whether stdout and debug.log have lines |
| `-daemon` | the started process exits 0 and leaves the node running (`divid.cpp:118-135`) | the start: "detached" |

A row `no option` gives the plain start's scan line, getinfo's errors and getbalance for comparison.

## KNOWN

| row | divid | irondivid | reason |
|---|---|---|---|
| `-socks…: start`, `-tor`, `-tor=1`, `-tor=<addr>: start` | the error, exit -6 | the same error, exit 1 | divid aborts (SIGABRT) in the shutdown after this early InitError, before the chain state exists (`init.cpp:381`, `ChainstateManager.cpp:102`), as for `-checklevel` (KNOWN in `scripts/chain-load-options`, `scripts/start-checks`, `scripts/restart-options`) |
| `-<accountlabels\|activeversion\|manual_fork\|override_mnpayee\|stakeupdatetime>…: log lines naming the option` | none | "Option -\<name\> is not supported by irondivid; ignored" | divid test aids for parts irondivid has but does not let an option change (`UNSUPPORTED_OPTIONS` in `bin/irondivid/src/main.rs`; `docs/divid-differences.md` S2) |
| `-help -help-debug: more options than -help` | yes | no | irondivid's `-help` is its own short summary of the common options, with no debug section (`USAGE`); also KNOWN in `scripts/check-options` |
