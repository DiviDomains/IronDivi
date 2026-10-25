# Block loading and chain checking options next to Divi Core

`run.sh` compares Divi Core 3.0.0's `divid` and irondivid on regtest for the start options that load blocks or check
the chain. divid mines 30 blocks and irondivid follows it. Then each exports the chain: divid as its own
`blocks/blk00000.dat`, irondivid with `--export-chain` (a `bootstrap.dat` in divid's block file format). The two files
must hold the same blocks, byte for byte.

Each export is then loaded, with each option, into a fresh pair of data directories. The rows compare:
- whether the node starts (or its exit and first error line);
- the tip: `getblockcount`, `getbestblockhash`, `getblockchaininfo` chain/blocks/headers/bestblockhash;
- `verifychain 4 0` and `verifychain 4 5`;
- the bootstrap files left, and whether the `-loadblock` files are untouched;
- the start-up log lines below.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 25 minutes).

```sh
scripts/chain-load-options/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/chain-load-options/run.sh target/release ~/divi-3.0.0/bin 54350 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's);
  `<port-base>+49`, which nothing listens on, is each node's only `-connect` peer once the chain is made.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 20 minutes and is stopped after 25. However it ends, both nodes are stopped and their directories
deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and kept in
each node's 0600 `divi.conf`.

## Log lines

These are divid's lines, each compared in the order it comes, with what it names:

| line | where |
|---|---|
| "Importing bootstrap.dat..." | `init.cpp:705` |
| "Importing blocks file \<file\>..." | `init.cpp:718` |
| "Warning: Could not open blocks file \<file\>" | `init.cpp:721` |
| "Loaded \<n\> blocks from external file" | `init.cpp:659` |
| "Reindexing block file blk\<n\>.dat..." | `init.cpp:675` |
| "Reindexing finished" | `init.cpp:681` |
| "Stopping after block import" | `init.cpp:726` |
| "Verifying last \<n\> blocks at level \<l\>" | `verifyDb.cpp:78`: at start (`-checkblocks`, `init.cpp:1116`), and for each `verifychain` (`rpcblockchain.cpp:422`) |

The rows `log lines naming -<option>` compare each line that names the option, as its message.

## Rows

| group | rows (each on both nodes) |
|---|---|
| exports | the number of blocks in each, and the same bytes block by block |
| `-loadblock` | divid's file; irondivid's; both, as two `-loadblock`; a missing file; a missing file then divid's |
| `bootstrap.dat` | divid's, then irondivid's, in `<datadir>/regtest` (divid's `GetDataDir()`, `init.cpp:699`; irondivid reads it there too); `bootstrap.dat` and a `-loadblock`. After the import it is `bootstrap.dat.old` (`init.cpp:704-707`) |
| `-reindex` | with `-loadblock` |
| `-stopafterblockimport` | with `-loadblock`: the exit (an import of 30 blocks can end before RPC answers, so only the exit counts), then a plain start: the chain |
| not divid's options | `-prune=550`, `-blocksonly=1`, `-stopatheight=5`, `-assumevalid=0` with `-loadblock`: the chain (all 30 blocks) and the lines naming the option |
| on the chain | a plain start; `-checkblocks` 0, 1, 10, -1, `abc`, 1000; `-checklevel` 0-4; `-checkpoints` 0 and 1; `-dbcache` 1, 4, 4096, 5000, -5; `-par` 0, -1, -100, 16, 17, `abc`; `-prune`, `-blocksonly`, `-stopatheight`, `-assumevalid`: the start, the chain, the verifying line, and the lines naming the option |

## What divid does with each option

| option | divid 3.0.0 |
|---|---|
| `-loadblock=<file>` (each) | read on the import thread after `bootstrap.dat`, in order; a file that does not open: "Warning: Could not open blocks file", and the next one (`init.cpp:692-723`) |
| `bootstrap.dat` | `<datadir>/regtest/bootstrap.dat` read first, then renamed `bootstrap.dat.old` (`init.cpp:698-713`) |
| `-reindex` | each `blk?????.dat` read again, then "Reindexing finished", then the imports (`init.cpp:663-690`) |
| `-stopafterblockimport` | stops once the imports are done: "Stopping after block import", exit 0 (`init.cpp:725-728`) |
| `-checkblocks=<n>` | atoi; VerifyDB at level 4 over the last n blocks at start, 0 or below every block, more than the height the height (`init.cpp:1116`, `verifyDb.cpp:73-78`); a failure is "Corrupted block database detected" |
| `-checklevel` | any value refused: "Error: Unsupported argument -checklevel found. Checklevel must be level 4." (`init.cpp:783-784`) |
| `-checkpoints` | only in the help (`LicenseAndInfo.cpp:165`); no code reads it, nothing logged |
| `-dbcache` | MiB, clamped to 4..4096, split between the block tree, coin database and coin cache, nothing logged (`init.cpp:1030`, `:1046-1056`) |
| `-par=<n>` | script-check threads: n, or the cores plus n for 0 and below; 1 or fewer is none; at most 16; no line names `-par`, the count is in "Using \<n\> threads for script verification" (`TransactionInputChecker.cpp:16-26`, `init.cpp:801`, `:965`; compared in `scripts/start-checks`) |
| `-prune`, `-blocksonly`, `-stopatheight`, `-assumevalid` | not divid 3.0.0 options: kept and never read, nothing logged (`Settings.cpp:130-150`) |

## KNOWN

| row | divid | irondivid | reason |
|---|---|---|---|
| `-checklevel=<0-4>: start` | the error, then exit -6 | the same error, exit 1 | divid aborts (SIGABRT) in the shutdown after this early InitError, before the chain state exists (`init.cpp:381`, `ChainstateManager.cpp:102`); also KNOWN in `scripts/start-checks` and `scripts/restart-options` |
| `-par=<n>: log lines naming -par` | none | "Option -par is not supported by irondivid; ignored" | divid sets its script-check threads; irondivid checks scripts on the thread that checks the block and has no such threads, so it names the option as not supported (`docs/divid-differences.md` S2) |
| `-reindex with -loadblock: log lines` | "Reindexing block file blk00000.dat..." before "Reindexing finished" | "Reindexing finished" only | irondivid keeps its blocks in its chain database, with no blk files (`scripts/restart-state`: file `blocks/`), and builds its indexes again from it; the other lines are the same |
| `-<prune\|blocksonly\|stopatheight\|assumevalid>…: log lines naming -<option>` | none | "Unknown option -\<name\>; ignored" | not divid options: divid keeps them and says nothing; irondivid names them (`docs/divid-differences.md` S1) [by design] |
