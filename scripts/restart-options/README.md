# Start-up options and restarts next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest and restarts both, in step, with
the same options: `-txindex` switched on and off with and without `-reindex`, `-minrelaytxfee` (refused values, and
the floor it sets), `-sporkkey`, and `spork show` across a restart. A start that is refused is compared by exit
code and by the error it prints on stderr. Then irondivid's `--export-chain`, which divid does not have, is
checked on its own against the outcome it should have. Each row prints one line:

- `PASS`: same as divid (or, for an `[irondivid only]` row, the expected outcome);
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/restart-options/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/restart-options/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 16 seconds and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run
and kept in the 0600 `divi.conf`; the `-sporkkey` row's key is made at random too, goes in `divi.conf` for that one
start, and is never printed or put on a command line.

## Nodes

The two nodes are not connected: each mines its own regtest chain (25 blocks, then a few for the transactions
below) and is restarted on the same datadir again and again. Both run with `staking=0`. Each makes, from its own
coins:

- T1, spending a coin to one output, and T2, spending that output: T1 is then fully spent, so only a transaction
  index finds it; T2 still has an unspent output;
- two coins of 0.01, spent one block later by the fee rows. They are too young and too small to go free on
  priority (`divi/src/MempoolConsensus.cpp:255-259`), so the relay fee floor decides.

## Rows

| step | rows (each on both nodes) |
|---|---|
| fresh start `-txindex=0` | starts; `getrawtransaction` of T1 (-5) and of T2 (found without the index, from the block its unspent output records: `divi/src/TransactionDiskAccessor.cpp:88-110`); `getnetworkinfo` `relayfee` (0.0001); `spork show` |
| restart `-txindex=1` | refused: exit 1, `Error: You need to rebuild the database using -reindex to change -txindex` (`divi/src/init.cpp:1104-1105`, given to `InitError` at `:1530`, which prints `Error: <text>`: `divi/src/noui.cpp:38-40`) |
| restart `-txindex=1 -reindex` | starts; same tip as before; T1 and T2 found, T1's hex is the one sent; `spork show` the same as before the restart |
| restart, `-txindex` not given | starts (the default is on); same tip; T1 and T2 found |
| restart `-txindex=0` | refused as above |
| restart `-txindex=0 -reindex` | starts; same tip; T1 -5, T2 |
| restart, `-txindex` not given | refused as above (the default is on, the index is off) |
| `-minrelaytxfee=0`, `0.0`, `abc`, `-0.0001` | refused: `Error: Invalid amount for -minrelaytxfee=<amount>: '<value>'` |
| `-minrelaytxfee=0.000015` | starts; same tip; `relayfee` 0.000015 in `getnetworkinfo` and `getinfo`; a 0.01 coin sent paying 200 satoshis is refused (-26 `66: insufficient priority`, the floor is about 285 for its 190 or so bytes), paying 400 it is accepted |
| `-sporkkey=<a key made here>` | refused: exit 1, `Error: Unable to sign spork message, wrong key?` (`divi/src/init.cpp:971-974`) |
| restart `-txindex=0` | starts; same tip |
| `--export-chain` (irondivid only) | see below |

How a row compares: same outcome (`up` or the process exit); for an exit the same code and the same `Error:` line on
stderr. For an RPC, the same result shape (a hex string, a txid, or the value itself for `relayfee` and
`spork show`), or for an error the same code and message.

### `--export-chain` (irondivid only)

With irondivid stopped, on its synced datadir, as `--export-chain --export-start 0 --export-end <tip>
--export-output <dir>`:

- exit 0; `blocks/<height>.json` for every height, each with the block hash `getblockhash` gave for that height;
  `manifest.json` with `chain` `regtest`, `block_count` tip + 1, `tip_hash` the tip, `export_complete` true;
- no file outside `chainstate/` added or changed in the datadir, and no `blocks/` folder made. Inside `chainstate/`
  the database replays its own log when it is opened, as it does at every node start, so it is not compared;
- `--export-end` one past the tip: exit 1, `above the chain height` on stderr, the output folder not made;
- an empty datadir (only `-regtest` given): exit 1, `No chain database in <datadir>/chainstate` on stderr, the
  datadir left empty, the output folder not made.

## KNOWN differences

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c). Each KNOWN row checks that the
difference is exactly this one; any other outcome is a FAIL.

- **`-minrelaytxfee` refused** (four rows): the same `Error:` line on both. divid then aborts (SIGABRT, exit -6
  here): the shutdown after this early `InitError` (`divi/src/init.cpp:823-829`) flushes the chain state
  (`divi/src/init.cpp:381`), and `ChainstateManager::Get` asserts (`divi/src/ChainstateManager.cpp:102`) because no
  chain state exists yet. irondivid exits 1: divid's abort is not copied.
- **A spork set on regtest and kept across a restart: not run.** Regtest uses testnet's spork key
  (`divi/src/chainparams.cpp:443`; `CRegTestParams` derives from `CTestNetParams`, `:457`) and its private key is
  not public, so no spork can be signed here. `spork show` across a restart is compared with the default values
  only. Signed multi-value sporks kept across a restart are covered by `crates/divi-node/tests/spork_restart.rs`.

## Proving a difference is caught

`RESTART_OPTIONS_INJECT=txindex-refusal` starts irondivid with `-txindex=1 -reindex` where both should be refused for
`-txindex=1` alone. That row then prints `FAIL` and the run exits 1.
