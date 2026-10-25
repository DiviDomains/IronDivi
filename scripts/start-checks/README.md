# Start-up chain checks next to Divi Core

`run.sh` compares how a Divi Core 3.0.0 `divid` and an irondivid start on a damaged or undamaged copy of the same
regtest chain:
- the start-up check of the newest blocks, under `-checkblocks` and `-checklevel`;
- `-par`;
- `-resync`.

Each case starts each daemon on a fresh copy of its own datadir, damaged as the case says, and compares:
- the start result;
- the exit code;
- the error the daemon prints (its first `Error` line on stderr);
- the debug.log lines and what is left on disk.

Divi Core's code is `divi/src/init.cpp:783-784` (`-checklevel`), `:801` (`-par`), `:901-930` and `:1480-1483`
(`-resync`), `:1113-1120` and `:1530` (the check and its error), and `divi/src/verifyDb.cpp:66-167` (VerifyDB).

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 20 minutes).

```sh
cargo build -p irondivid
cargo build -p divi-storage --example damage_block
cp target/debug/examples/damage_block target/debug/
scripts/start-checks/run.sh target/debug ~/divi-3.0.0/bin 54100 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid` and `damage_block` (`crates/divi-storage/examples/damage_block.rs`, a test
  tool that changes one block's data in a stopped irondivid's chain database); `<core-bin-dir>` holds `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.2: the two nodes, then the copies.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute and a half and is stopped after 20 minutes. However it ends, every node is stopped and
its directory deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run
and kept in the 0600 `divi.conf`. The wallet phrase is read from divid's `dumphdinfo` and handed to irondivid in its
environment (`WALLET_MNEMONIC`); it is never printed or put on a command line.

Only datadirs this run makes are damaged or resynced: copies under its own work directory. `-resync` is never run on
a live node, a replay, or a datadir anyone else uses.

## The chain and the damage

- **The chain:** divid mines 130 blocks; irondivid, with a wallet from the same phrase, follows them. Both stop, and
  every case starts from a copy of the stopped datadir, with no peer (`connect=127.0.0.2:1`, `listen=0`).
- **Damage on divid's copy:** in `regtest/blocks/blk00000.dat` and `rev00000.dat`, which a single chain fills in
  height order.
  - `block-bad`: one byte flipped inside the block's first transaction.
  - `block-missing`: the block's bytes zeroed, so it no longer reads back.
  - `undo-bad`: the last byte of the block's undo checksum flipped.
- **Damage on irondivid's copy:** `damage_block <copy>/chainstate <height> <kind>` changes the same block in the chain
  database.
  - `block-bad`: the last transaction's lock time changed, so the merkle root no longer matches.
  - `block-missing`: the block's data removed.
  - `undo-bad`: undo data that does not decode.

## Rows

| case | what is compared |
|---|---|
| an undamaged copy, default | starts; the log's `Verifying last N blocks at level L` and `No coin database inconsistencies` lines (see KNOWN) |
| `block-bad`, `block-missing`, `undo-bad` at the tip and 5 below it | refused: exit 1, `Error: Corrupted block database detected` (`init.cpp:1116-1119`, InitError `:1530`) |
| `block-bad` at tip-100 and tip-101, default `-checkblocks` (100) | tip-100 is refused, tip-101 starts: VerifyDB checks the heights from the tip down to tip-100 (`verifyDb.cpp:83-90`) |
| `block-bad` at height 10 with `-checkblocks=` 5, 0, -1, 200, abc | 5 starts; 0, -1, 200 and abc are refused: 0 or below checks every block (`:73-76`), more than the height checks every block, and `abc` reads as 0 |
| `block-bad` at tip-5 and tip-6 with `-checkblocks=5` | tip-5 refused, tip-6 starts |
| `block-bad` at height 1 with `-checkblocks=0` | refused |
| `block-bad` at height 0 (genesis) with `-checkblocks=0` | starts: a block with no parent is never checked (`:83`) |
| `-checklevel=` 4, 3, 0 | refused: `Error: Unsupported argument -checklevel found. Checklevel must be level 4.` (`init.cpp:783-784`; see KNOWN for the exit code) |
| `-par=` 0, 1, -1, 17 | starts, and a block mined then connects; the log (see KNOWN) |
| `-resync`, with the original divid as the only peer | starts; every chain folder is cleared (divid: blocks, chainstate, sporks; irondivid: chainstate, txindex) and every other folder kept; both sync back to the tip; the wallet and `divi.conf` are kept; the deletion is logged (`-resync: folder deleted: <path>`) |

## KNOWN

| row | divid | irondivid | reason |
|---|---|---|---|
| the log's `Verifying last N blocks at level L`, `No coin database inconsistencies` | `Verifying last 100 blocks at level 4`, then `No coin database inconsistencies in last …` | neither; `Verified the last N blocks in M ms` | irondivid's check covers divid's levels 0 to 3. It reads each block, checks its hash, merkle root and parent link, decodes its undo data, and undoes the tip blocks in memory against the coins (`crates/divi-storage/src/chain.rs` `verify_recent_blocks`, `verify_utxo_set_at_tip`). It does not run level 4, connecting those blocks again (`verifyDb.cpp:122-157`) |
| `-checklevel=` 4, 3, 0 | the error, then exit -6 | the same error, exit 1 | divid aborts (SIGABRT) in the shutdown after this early InitError, before the chain state exists (`init.cpp:381`, `ChainstateManager.cpp:102`); also KNOWN in `scripts/restart-options` |
| `-par=…: the log` | `Using <n> threads for script verification` (`init.cpp:965`) | `Option -par is not supported by irondivid; ignored` | `-par` sets divid's script check threads (`init.cpp:801`, `TransactionInputChecker.cpp:16-26`). irondivid checks scripts on the block's own thread. What is accepted is the same: the row before it checks a block still connects |
