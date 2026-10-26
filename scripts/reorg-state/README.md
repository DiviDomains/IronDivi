# Chain state other than the wallet across a reorganisation, next to Divi Core

`run.sh` starts six regtest nodes, Divi Core 3.0.0 `divid` and irondivid, as two sides of a network that is split and
joined again (the layout of `scripts/reorg-sync`): on each side a divid bridge, a divid and an irondivid behind it. Branches of
different lengths are built on the two sides, joined, and the divid and the irondivid behind each bridge are compared. Each
row prints one line:

- `PASS`: irondivid shows what divid shows;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 30 minutes
for a universe).

```sh
scripts/reorg-state/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a build of this tree
cargo build -p irondivid -p spork-seed
scripts/reorg-state/run.sh target/debug ~/divi-3.0.0/bin 55500 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid` and `spork-seed` (`cargo build -p spork-seed`); `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: **17 ports**, `<port-base>` to `<port-base>+16` on 127.0.0.2: the p2p and RPC port of each of the six nodes, and five relays (below).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 25 minutes (two universes, below). Needs bash and python3 (standard library only). RPC passwords are made at
random for each run and kept in each node's 0600 `divi.conf`; the shared wallet's phrase is read from divid's `dumphdinfo` and handed to
irondivid in its environment (`WALLET_MNEMONIC`), never printed or put on a command line.

## Nodes

As in `scripts/reorg-sync`: side L (bridge, divid-L, irondivid-L) and side R (bridge, divid-R, irondivid-R), split by restarting all six
(no node dials across) and joined by `addnode onetry` from bridge R. divid-L, irondivid-L and irondivid-R hold one wallet (divid-L's
phrase) and run `-vault=1`; the bridges and divid-R have wallets of their own. Side L's blocks are made by divid-L, side R's by irondivid-R.

Sporks are put in each node's own spork database before it starts, as in `scripts/spork-consensus`: nobody holds the regtest spork key,
so a spork cannot be signed and relayed. A node offers the sporks it holds to any peer that asks and the peer refuses them, so every
link goes through a relay (`SporkFilter`) that passes everything but the spork messages. What differs between the sides is therefore what
the nodes hold, as if each side's network had been given its spork. Side L holds the sporks of `L_SPORKS`, side R those of `R_SPORKS`.

A node that holds a spork the other side lacks cannot follow the other side past the next block that spork changes. So each spork case ends
with a split network, and has a network of its own: **universe 1** (`REORG_STATE_UNIVERSE=1`) and **universe 2**, which `run.sh` makes one after
the other.

## Cases

After each join: `getblockchaininfo`, `getchaintips`, `getbestblockhash`, `gettxoutsetinfo` (hash and totals) on the pair behind each bridge,
and that the longer side's tip is on all six nodes. `getblocktemplate` does not exist in Divi Core 3.0.0 (`rpcserver.cpp`'s mining table),
and irondivid answers the same "Method not found" (one row).

| universe | case | what happens | rows |
|---|---|---|---|
| 1 | proof of work, depth 1, 6 and 25 | side L adds N blocks, side R N+1; 25 is past the 20 blocks of coin maturity | state rows |
| 1 | proof of stake, depth 1 and 6 | the same past height 100 (the last proof-of-work block) | state rows |
| 1 | lottery and treasury at 150 | the fork at 144: both branches hold the lottery and treasury heights 150; then block 160 (a lottery height) made by divid-L and taken by all six | state rows, `getlotteryblockwinners` 140 to 152 and 158 to the tip, `getblock` 149 to 151 and 160 |
| 1 | a vault coinstake in the dropped branch | a vault (funded and registered before, 21 blocks deep) staked alone by divid-L on side L | state rows; `getbalance`, `getcoinavailability`, `getstakingstatus`, `listunspent` of the shared wallet on divid-L and irondivid-L; the dropped block paid a vault and left the chain |
| 1 | a stake on a coin whose funding is dropped | side L's owner pays the wallet, divid-L stakes that coin alone, on side L; side R is longer | the same |
| 1 | a vault funding in the dropped branch | side L funds the vault again, registers it, stakes it; side R is longer | the same |
| 1 | spork 15 on side L only (`2000;200`) | the fork at 194, side L 12 blocks, side R 13: side L's blocks pay 2000 from 200; side R grows on, 50 more blocks | state rows; `spork active`; the lottery winners and blocks 200, 201, 205; where side L then stops (the treasury block 250), and the tips, chain tips and UTXO set of both pairs |
| 2 | spork 13 differing (`50;30;10;5;5;300` on side L, `45;30;10;10;5;300` on side R) | the fork at 294, side L 8 blocks, side R 7: side R refuses side L's longer branch, so each side keeps its own tip | the same, and after side R grows by 4 |

## What Divi Core does, and irondivid with it

- A disconnected block's transactions go back to the mempool, the UTXO set is rolled back, the new branch is connected (`ChainTipManager.cpp:105-190`).
- The lottery winners are stored with each block index entry (`CBlockIndex::vLotteryWinnersCoinstakes`, computed when a block is connected from the
  previous block's: `BlockIndexLotteryUpdater.cpp:21-40`, `LotteryWinnersCalculator.cpp:154-200`), so each branch has its own and nothing is undone.
  irondivid keeps the same list in its block index entry (`BlockIndex::lottery_winners`, `chain.rs` `update_lottery_winners`).
- The treasury and lottery payments of a block follow from its height and the sporks at the time it is checked (`SuperblockHeightValidator.cpp:6-51`,
  `BlockIncentivesPopulator.cpp`), not from a stored state.
- Sporks 13 and 15 take effect at a multiple of the halving interval (`spork.cpp:98-99`, `:118-119`); a spork is not part of any branch.
- A masternode's collateral is looked up in the active chain (`masternodeman.cpp`); in irondivid `Manager::verify_collateral`.

## Not covered

- **Masternode collateral funded on the dropped branch.** A masternode needs a divid masternode node, 15 confirmations (deeper than a proof-of-stake
  branch of this kind can be, since a stake whose input is only on the other branch is refused, `scripts/reorg-sync` E) and the masternode sync
  stages; `scripts/mn-life` covers the collateral spent and the list after it, which is the same lookup.
- **Spork 14** (fees) is read by divid only when a spork arrives (`spork.cpp:253-257`), so a seeded one changes nothing; see `scripts/spork-consensus`.
- **A spork signed and relayed** on one side only: it cannot be signed (see above).

## KNOWN differences

None: every row matches divid at the time of writing.

## Proving a difference is caught

`REORG_STATE_INJECT=<row name>` changes irondivid's reply of that row before it is compared. `REORG_STATE_DUMP=<dir>` writes both replies of every row that differs to `<dir>`.
