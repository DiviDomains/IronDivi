# The wallet rows of a masternode payment, next to Divi Core

`run.sh` gets a masternode paid on a regtest network of Divi Core 3.0.0 `divid` and irondivid nodes, then compares
what the wallets that own the payee and the staker say about the paying block. It is scripts/mn-life with its payment
phase and one more section (`MN_LIFE_PAYMENTS=1 MN_LIFE_REWARDS=1`). It prints rows in the same form:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with a count of the rows and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over the time limit).

```sh
scripts/mn-reward/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/mn-reward/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- Ports `<port-base>` to `<port-base>+15` on 127.0.0.2 (eight nodes: mn-life's six and two fresh wallets).
- A run takes about 30 minutes and is stopped after 60: a masternode is ranked, and so can be paid, only 25 minutes
  after its broadcast was signed (`divi/src/masternode-payments.cpp:558`).

## How a masternode gets paid on regtest

Divi Core pays no masternode on any regtest block today. `DeprecateMasternodes` is active once the median time past
reaches 2023-08-23 (`divi/src/ForkActivation.cpp:31`, `:47-57`), and then `FillBlockPayee` skips the masternode payee
(`divi/src/BlockIncentivesPopulator.cpp:142-152`). scripts/mn-life's payment phase alone therefore never pays one.

`-manual_fork=<time>` moves `DeprecateMasternodes` (and `CheckLockTimeVerify`) to that time
(`divi/src/ForkActivation.cpp:21`, `:48-55`). This script gives it to every divid node, set to 2100-01-01:
- divid C, a staker, then pays the ranked masternode in its blocks: 540 of the 996 DIVI a block mints at these
  heights, the staker keeping the rest;
- irondivid does not take the option (it is in its unsupported options) and keeps the fork active, as every real
  network has had it since 2023. Its blocks pay no masternode, and it accepts C's blocks, as it checks what a block
  mints, not who is paid.

So the payments are made by divid C's blocks, to C's masternodes and to I's.

Two more things keep both masternodes paid:
- **The silver collaterals are locked** (`lockunspent false`) on their controllers when the payment phase starts. A
  controller locks its collaterals from masternode.conf when it starts (`divi/src/init.cpp:1246-1258`), and C and I
  have none. Unlocked, a collateral is a coin to stake like any other (`divi/src/wallet.cpp:1433-1462`). A masternode
  is paid to its collateral's address, so a stake from one of its rewards adds the collateral too, as coins of the
  same script are combined (`divi/src/PoSTransactionCreator.cpp:172-209`). That ends the masternode: in earlier runs
  irondivid I did it to mni2, and divid C likely did it to mnc2, which was then never paid. The controller restarts
  drop locks, so the locks are made after them.
- **The phase mines on past 20 blocks,** up to 40 and short of the treasury block (a height that is a multiple of 50),
  until a block has paid each controller's masternode. If one is still not paid, C's masternode list is printed.

That is enough for the wallet rows, which this script is for: a wallet's view of a coinstake does not depend on who
made it.

## The rows (section 9 of scripts/mn-life/check.py)

Divi Core gives a coinstake these rows (`ParseTransactionDetails`, `divi/src/rpcwallet.cpp:2016-2112`):
- the staker's wallet: one row for output 1, amount what it made. Its category is `stake_reward` when
  what it made is more than the block's stake reward, else `stake_reward+`. So a block that pays a masternode shows
  `stake_reward+` (456 made) and one that pays none shows `stake_reward` (996 made);
- once confirmed, each other output the wallet owns that is not the staker's script: `mn_reward`, or `lottery` on a
  lottery block, with its vout and address. Both are in the coinstake branch, `:2034-2107`.

The rows:

| rows | what is compared |
|---|---|
| `rewards: a block paid C's masternode and a block paid I's masternode` | both controllers' masternodes were paid during the payment phase |
| `rewards, the owner's own wallet: …` | C's rows for the first payment to C's masternode against I's rows for the first payment to I's: `listtransactions`, `gettransaction` `details` and `confirmations`, `listsinceblock` from the block before. Each row by category, amount, vout, account (the masternode's alias written `<alias>`, as each controller's masternodes have their own) and involvesWatchonly; confirmations against tip − height + 1 |
| `rewards, fresh wallets: importprivkey …` | a new divid wallet and a new irondivid wallet are given the payee and staker keys of the cases below, with a rescan |
| `rewards, fresh wallets, <case>: …` | for each case, the two new wallets' `listtransactions` rows of the coinstake, `gettransaction` whole, `listsinceblock` rows and `lastblock`, compared whole apart from `time` and `timereceived` |

The cases: C's block paying C's masternode, C's block paying I's masternode, and I's first block (a stake with no
masternode paid). The categories each case shows are printed with `#`.

## Votes after a collateral is spent

Divi Core checks a masternode at most every five seconds unless it takes a ping (`MASTERNODE_CHECK_SECONDS`,
`divi/src/masternodeman.cpp:153-180`, `:364-367`). So for up to five seconds after a collateral is spent, divid still
takes and relays that masternode's payment votes. irondivid before fix/mn-reward checked the collateral on every vote
and refused them ("masternode is not active", "payee not in the top of the payment queue"), so
`getmasternodewinners 20` lost a vote for good. When such a row fails, the script prints the entries that differ
and the reasons irondivid's debug.log gives for each vote it did not take.

## KNOWN differences

- **`getmasternodecount: tier counts divid lacks`**: as in scripts/mn-life.
- **`payments: blocks that pay a masternode`**: only divid is given `-manual_fork`, so only C's blocks pay a
  masternode.

## Secrets

- The masternode keys are throwaway regtest keys made in the run's directory, as in scripts/mn-life.
- divid 3.0.0 has no `dumpwallet` (`divi/src/rpcserver.cpp:420-464`). Each payee and staker key goes from
  `dumpprivkey` into `importprivkey` in the RPC request bodies only: never in a command line, a file or the output.
- RPC passwords are made at random for each run and kept in each node's 0600 `divi.conf`.
