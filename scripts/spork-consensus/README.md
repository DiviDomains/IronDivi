# Sporks 13 to 16 in consensus next to Divi Core

`run.sh` builds a regtest chain through the heights where four sporks take effect, on one network of three nodes
that hold the same sporks: two Divi Core 3.0.0 `divid` (A and B) and one irondivid (I). They take turns to stake, so
each daemon makes blocks the other checks. A divid and an irondivid that were given no sporks follow A as well.
Each row prints one line:

- `PASS`: the same as divid (or, for the rows that name an amount, the amount the rules and the sporks give);
- `KNOWN`: differs, in the way listed below with the reason (none at present);
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 20 minutes).

```sh
scripts/spork-consensus/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a build of this tree
cargo build -p irondivid -p spork-seed
scripts/spork-consensus/run.sh target/debug ~/divi-3.0.0/bin 55400 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid` and `spork-seed` (`cargo build -p spork-seed`, `tools/spork-seed`);
  `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+23` on 127.0.0.2: p2p and RPC of A, I, B and the two nodes
  without sporks (`+0` to `+9`), then the four relays below (`+20` to `+23`).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end. Give an
  absolute path.

A run takes about 10 minutes. However it ends, every node is stopped and its directory deleted. Needs bash and
python3 (standard library only). RPC passwords are made for the run and written only to each node's mode-600
`divi.conf`.

## How the sporks get to the nodes

A spork is accepted from the network only if it is signed by the network's spork key. Regtest uses the testnet key
(`chainparams.cpp:443`, `CRegTestParams` derives from `CTestNetParams` at `:457`), and nobody here holds its private
key (`-sporkkey` is accepted only for that key, `spork.cpp:461-480`, `init.cpp:968-977`). So the sporks are put in
each node's own spork database before it starts, which both kinds load without checking the signatures again
(`LoadSporksFromDB`, `spork.cpp:192-211`):

- divid: its `sporks` LevelDB, made here as a directory holding only a write-ahead log (LevelDB creates the rest and
  recovers the log), key = the id as 4 bytes, value = the spork as divid writes it;
- irondivid: `spork-seed <data-dir> <id> <value> <time>`, which stores it in the chain database as the node does.

Each daemon then acts as with sporks it accepted. What it cannot do is show them to a peer: a peer refuses a spork
whose signature is not the network's (and divid does so for the sporks 13 to 16 even when it holds an entry of the
same time, `spork.cpp:229-242`). So the nodes do not dial each other: each dials a relay (`SporkFilter` in
`check.py`) that passes everything else, makes the listener's `sporkcount` say 0, and drops `getsporks` and `spork`.
The wire handling of sporks itself is compared by `scripts/sporks`.

The entries, signed at second 1000 (so every block is later than they are):

| spork | entry | meaning |
|---|---|---|
| 16 `SPORK_16_LOTTERY_TICKET_MIN_VALUE` | `13500;150` | from height 150 a coinstake needs more than 13,500 DIVI to hold a lottery ticket |
| 15 `SPORK_15_BLOCK_VALUE` | `2000;200` | from 200 a block is worth 2,000 DIVI, not the halving schedule's 1,150 |
| 13 `SPORK_13_BLOCK_PAYMENTS` | `50;30;10;5;5;300` | from 300 stake 50, masternode 30, treasury 10, proposals 5, charity 5 percent |
| 14 `SPORK_14_TX_FEE` | `10000;300;100000;20000;50;0` | fees: held, but divid takes them only when the spork arrives, not from its database (`spork.cpp:253-257`, `:278-302`), so no row |

Spork 13 and 15 take effect only at a multiple of the halving interval, 100 on regtest (`spork.cpp:98-99`, `:118-119`).

## Rows

| rows | what is compared |
|---|---|
| `spork show`, `spork active` | the same on both, with the sporks given; and with none |
| `getlotteryblockwinners` after every block from 102 | the lottery winners on divid and irondivid |
| blocks 205 and 305 | A, alone, makes the block; a copy paying one satoshi over what spork 15 (205) or spork 13 (305) allows is offered by a raw peer to B and to irondivid, and for 305 one paying what the usual split allows; then the block as made. Both kinds refuse the copies and take the block. |
| reorg across 200 | A, alone, makes a longer chain from before 200, which B and irondivid take in place of theirs |
| what a block created | blocks 125, 199, 201, 205, 299, 301, 305 and 311: the coinstake's outputs less its inputs, against the rules and the sporks (996, 996, 1618.5, 1618.5, 1618.5, 1560, 1560, 1560 DIVI) |
| treasury blocks | 150, 200, 250, 300: what is paid the treasury and the charity, against the rewards at both ends of the cycle (9600, 15600 and 975 DIVI) |
| every lottery and treasury superblock | the winners, the same block, `getblock`, the coinstake, the payees' balances |
| nodes without the sporks | a divid and an irondivid stop at the same height, below 200 (at the first lottery block after 150 where spork 16 changes the winners), and both refuse the next block when it is offered |
| `invalidateblock` and `reconsiderblock` at 300 and 200 | the tip and the winners (B and irondivid, which hold the chain A left at the reorg) |
| a restart of all, `-reindex` of A and irondivid | the sporks, the tip, the winners at the heights above, the amounts again |

## Not compared

- **Spork 14.** divid reads it only when a spork arrives (`ExecuteSpork`, `spork.cpp:253-257`), so a spork 14 that was
  loaded from the database changes nothing in divid and there is nothing to compare. irondivid does the same; it is
  tested in `crates/divi-network/src/spork.rs` and `crates/divi-node/src/mempool.rs`.
- **Several entries of one spork.** divid's database holds the last entry added for each id (`spork.cpp:255`), so
  this setup gives each node one. How entries are kept in time order and chosen is tested in
  `crates/divi-consensus/src/spork_values.rs` and `crates/divi-storage/src/chain.rs`.
