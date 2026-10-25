# Lottery and treasury superblocks next to Divi Core

`run.sh` builds a regtest chain through lottery and treasury superblocks on one network of three nodes: two Divi Core
3.0.0 `divid` (A and B) and one irondivid (I). They take turns to stake, so each daemon makes superblocks the other
checks. After every block the script compares the lottery winners on divid and on irondivid, and then, at every
superblock, who is paid and how much. Then it offers blocks paying the wrong lottery winner or the wrong treasury
amount to divid and to irondivid from a raw peer. Last, it compares the winners again after `invalidateblock` and
`reconsiderblock`, a restart, and `-reindex`. Each row prints one line:

- `PASS`: the same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/superblocks/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/superblocks/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2: A's p2p and RPC, then irondivid's, then B's.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end. Give an
  absolute path.

A run takes 4 to 6 minutes and is stopped after 10 minutes. However it ends, every node is stopped and its directory
deleted. Needs bash and python3 (standard library only). RPC passwords are made for the run and written only to
each node's mode-600 `divi.conf`.

To find out more about a FAIL, two environment variables help:
- `SUPERBLOCKS_DUMP=<dir>` writes both replies of every differing row there;
- `SUPERBLOCKS_TRACE=1` prints each block's maker, its winner count and its coinstake outputs.

## The superblocks of regtest

Regtest (`divi/src/chainparams.cpp:473-498`):
- the last proof-of-work block is 100;
- coinbase and coinstake outputs mature after 20 blocks;
- subsidies halve every 100 blocks;
- the lottery starts at 101, every 10 blocks; the treasury starts at 102, every 50.

These rules hold until 10 × 50 = 500 (`SuperblockHeightValidator.cpp:6-11`, `LegacyBlockSubsidies.cpp:98-108`). So
lottery blocks are 110, 120, … and treasury blocks are 150, 200, 250, …. At a height that is both, treasury wins
(`BlockIncentivesPopulator.cpp:182-187`).

How a lottery is won:
- **Ticket:** a coinstake is a ticket when it pays more than 10 000 DIVI to its staker
  (`LotteryWinnersCalculator.cpp:27-61`).
- **Ranking:** the eleven best scores win. A script that won one of the last three lotteries is vetoed, and a
  script already listed is dropped first (`:63-150`, active from the UniformLotteryWinners fork).
- **Payout:** a lottery block pays the first winner half of the cycle's lottery reward, and each other winner a tenth
  of that half (`BlockIncentivesPopulator.cpp:48-64`).
- **Treasury:** a treasury block pays testnet's treasury and charity addresses (`:31-42`, `:66-90`).

The brief this script was written for gave regtest's cycles as 200 and 201. Those are testnet's
(`chainparams.cpp:407-410`); regtest's own are 10 and 50 (`:490-493`).

## Nodes and how staking is driven

- **Network:** A listens; I and B dial A (`connect=`). Every node runs with `staking=0`, `txindex`, `addressindex`
  and `spentindex`.
- **Coins:** A mines the 100 proof-of-work blocks, then sends 8 coins of 10 200 to 13 000 DIVI:
  - 1 to A;
  - 4 to I, two of them to one address, so one payee can win twice in a cycle;
  - 3 to B.
- **Staking:** each block is made by `setgenerate 1` on the node whose turn it is:
  - irondivid, then B, whenever it has a coin to stake (10 blocks deep, 20 for a coinstake output, as both daemons
    require: `wallet.cpp:1456`);
  - else A, with its coinbases, which are not tickets;
  - at a lottery or treasury height, divid A and irondivid in turn, so both daemons make superblocks.
- The chain goes to 216 that way, and on to the superblocks below.

## Rows

| rows | what is compared (divid A, or B where said, against irondivid) |
|---|---|
| `getlotteryblockwinners after block <h> (by <node>)` | after every block from 102: the whole reply (Is Lottery Block, Block Height, Block Hash, every candidate's Address, Rank and Score, in order) |
| `<kind> superblock <h>: …` | at every lottery and treasury height up to the tip: `getlotteryblockwinners <h>`; the same block hash; `getblock` (without `mediantime` and `nTx`, which irondivid adds: see `scripts/chain-replies`); the coinstake, `getrawtransaction <txid> 1` (each output's value and script); `getaddressbalance` of each payee (the winners at h−1, or the treasury and charity addresses) |
| `cycle to lottery block <h>` | the winners at h−1 on both: how many candidates, how many distinct payees. Cycles with fewer candidates than the eleven winners, with none (all vetoed), and with one payee twice all occur |
| `superblock <L> …: offered by a raw peer` | A, cut off from the network, makes the lottery superblock L (the first from 220 with three or more winners). Changed copies are signed again with A's keys: the coinstake by A's wallet, the block with the staker's key. Each is offered by a raw peer to divid B and to irondivid: the first winner's reward to another address, the first winner one satoshi less, the last winner left out; then the block as made. Compared: the `reject` the node sends (or that it drops the peer), and whether the block becomes its tip |
| `superblock <T> …: offered by a raw peer` | the same for the next treasury superblock T: the treasury one satoshi less, the treasury's amount to another address, the charity left out, the treasury one satoshi more; then the block as made |
| `after invalidateblock <h>` / `after reconsiderblock <h>` | on A and irondivid, back over T and over L: `getblockcount`, the winners at the tip, at h−1 and h; after `reconsiderblock`, the winners again at the tip |
| `after a restart` | all three restarted: the winners at 109, 110, 119, 149, 150, 151, L−1, L, T−1, T and the tip |
| `after -reindex` | A and irondivid restarted with `-reindex`: `getblockcount`, the winners at the same heights, and every superblock row again |
| `getlotteryblockwinners <argument>` | no argument, 0, 100 (before the start), 101, 105, 110, 111, 150, the tip, above the tip, text, a real, two arguments |
| `<call>: field order` | the order of the members of each kind of reply (see KNOWN) |

The number of rows varies a little from run to run: which coins stake, and so who wins and how many payees a
superblock has, depends on the stake kernels found on that run (368 to 372 rows in three runs). The checks are the
same every run.

How a row compares:
- Both must have the same outcome: a result, or an error with the same code and message.
- For a result, every member, type and value must match, and list items must come in divid's order.
- divid answers a wrong argument count with its help text, which is not compared; both must refuse with -1.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

- **`getlotteryblockwinners -1`:** not sent to divid. divid reads the block at height -1, a null pointer
  (`rpclottery.cpp:48-51`), and stops; irondivid's answer is shown only.
- **`getlotteryblockwinners`, `getblock` and `getrawtransaction`: field order.** irondivid writes the members of a
  result in name order; divid writes them in the order it adds them (json_spirit Object).
  `docs/divid-differences.md` R6 keeps this on purpose. The values are compared in every row, and the order once per
  kind of reply.

No other row differs from divid.
