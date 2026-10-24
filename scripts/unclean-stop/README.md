# Unclean stops of irondivid, next to Divi Core

`run.sh` kills irondivid with `kill -9` at seeded random points on regtest, starts it again, and compares its chain,
UTXO set, wallet and indexes with a clean node at the same point. Two Divi Core 3.0.0 `divid` nodes mine the chain.
Each row is then run once against `divid` for comparison.

```sh
cargo build --release -p irondivid
CORE_BIN=~/divi-3.0.0/bin scripts/unclean-stop/run.sh 54300
```

| variable | meaning (default) |
|---|---|
| `BIN` | directory holding `irondivid` (`target/release`) |
| `CORE_BIN` | directory holding Divi Core's `divid` (`divid` on `PATH`) |
| `SEED` | seed of the kill points (random, printed on the first line) |
| `WORK_ROOT` | a fresh directory is made under it and deleted at the end (`$TMPDIR`, else `/tmp`) |
| `UNCLEAN_KILLS` | kill points per row (5) |
| `UNCLEAN_BLOCKS` | length of the chain row 1 syncs (320) |
| `KEEP=1` | keep the work directory (node logs, the datadir of a failed point) when a row fails |

The script uses ports `<port-base>` to `<port-base>+9` and expects nothing at `<port-base>+49`. Nodes bind to
127.0.0.2, not 127.0.0.1: such ports are often inside the host's ephemeral range, and another program's client on
127.0.0.1 can hold one for a while, which stops divid from binding to it. A run takes about 5 minutes on an idle host; it is
stopped after 14. However it ends, every node is stopped and the work directory deleted (unless `KEEP=1` and a row failed).
Needs bash and python3 (standard library only). Passphrases are made at random for each run, live only in memory and
in RPC request bodies, and are never printed; private keys are compared by hash.

## Output

One line per kill point:

- `PASS <row>#<n> <what happened>`: the delay drawn, how the node came up again, where it stood, what was compared;
- `FAIL <row>#<n> <reason>`;
- `DIVID-OK <row>-divid#1 ...` / `DIVID-BAD <row>-divid#1 ...`: the same kill point on divid (not counted);
- `AS CORE <row> ...` / `DIFFERS <row> ...`: the divid run of the row next to irondivid's (pass/fail, and whether
  either needed `-reindex` to start again). A `DIFFERS` line is not counted as a failure either.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over time).
A kill point that is not consistent, or a node that does not start again, is a `FAIL`. A node that refuses to start
and names `-reindex` or a damaged database ("says what it needs") is started with `-reindex` and then checked;
the line says so (`restart=refused (...); started with -reindex`).

## Set-up

- core1 mines 320 blocks (proof of stake from block 101) and records `gettxoutsetinfo` after each block, so a
  restarted node's UTXO set can be compared at whatever block it stopped. Coins are sent and spent on the way, so the
  indexes have entries; core2 follows core1 and gets coins to stake with.
- A clean irondivid with `-txindex -addressindex -spentindex` follows core1. Its sync time is row 1's window.
- Templates (stopped cleanly): irondivid and divid synced with a funded wallet; the same, encrypted.

`gettxoutsetinfo` is compared by height, best block, transactions, txouts and total amount
(`hash_serialized` differs between the two implementations even at the same tip).

## Rows

| row | kill point | after the restart |
|---|---|---|
| `sync-kill` | fresh chain with the funded wallet, syncing 320 blocks from core1; delay 0.05 s .. 1.2 x the clean sync time | tip is a core1 block, UTXO set equals core1's at that block; then synced to core1: same as core1 and the clean irondivid, balance as before |
| `first-start-kill` | the first start on an empty datadir: irondivid 0-10 ms after it logs "Opening RocksDB" (the chain database is being made), divid 0-0.5 s after start | starts again (or says what it needs); tip a core1 block with the clean UTXO set; then synced to core1: same as core1 |
| `encrypt-kill` | during `encryptwallet`; delay 0 .. 1.3 x the call's time | the wallet is unencrypted, or opens with the passphrase; balance and `dumpprivkey` of a known address unchanged |
| `change-kill` | during `walletpassphrasechange`; same window | opens with the old or the new passphrase; balance and `dumpprivkey` unchanged |
| `reindex-kill` | start with `-reindex` and the three indexes; odd points a delay after start, even points 0-15 ms after "Building the transaction index" | started without `-reindex`: tip, UTXO set, `getrawtransaction` of the known txids, `getaddressbalance` of the known addresses, `getspentinfo` of the spent outputs equal the clean irondivid's |
| `spork-kill` | `spork SPORK_8_... <value>` then kill 0-300 ms later | `spork show`, `spork active`, `getnetworkinfo.relayfee` as before |
| `relayfee-kill` | started with `minrelaytxfee=0.00003`, kill 0-300 ms after RPC answers | same |
| `reorg-kill` | the node follows miner W; the other miner L mines a longer branch; the node is given L (`addnode onetry`) and killed: odd points 0-20 ms after "Disconnecting block", even ones 0-0.8 s after the addnode | tip is a block of W's or L's chain, UTXO set equals the record at that block (the line says old tip, partly disconnected, partly connected, new tip); then synced to L: same as L |

Nobody holds the regtest spork key (it is testnet's, and testnet peers carry no sporks), so no spork can be changed
on regtest: `spork-kill` checks that a refused change (`failure`, as divid answers) and a kill leave the shown sporks
as they were. Keeping a received spork across a restart is covered by the tests in `crates/divi-network`.

### Reorganizations and proof of stake

A block stakes a coin of the chain it extends, and a coin made on a branch can stake 20 blocks later (`nMaturity`).
A node on the other branch cannot check such a block (divid logs "read txPrev failed"), so each branch stays under
20 blocks, and after every point the miners join and take one chain again.

divid that has connected a lottery block (heights 110, 120, ...) and then reorganizes to a branch with another block
at that height refuses the new one ("IsValidLotteryPayment: No payment for winner"), though a fresh divid synced from
the same miner accepts that branch, as irondivid does. So the branch a node leaves holds no lottery block.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).
