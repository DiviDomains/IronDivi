# Wallet transaction history next to Divi Core, for each kind of transaction

`run.sh` starts six regtest nodes on 127.0.0.2:

- **S**, a Divi Core 3.0.0 `divid` that mines, stakes and pays;
- **C**, a `divid` wallet, the vault owner, and **I**, an irondivid restored from C's phrase;
- **M**, a `divid` vault manager (`vault=1`), and **N**, an irondivid manager restored from M's phrase;
- **X**, a `divid` that is cut off from the others to build the branch that orphans a stake.

After every step it compares each twin pair (C with I, M with N) field by field:

| reply | forms |
|---|---|
| `listtransactions` | `"*" 100000 0 true`, `"*" 100000 0 false`, `"" 100000 0 true`, `"*" 3 1 true` |
| `gettransaction` | every transaction either twin lists, and every one the run made, with includeWatchonly true and false |
| `listsinceblock` | none; the block before the step with target 1 and includeWatchonly |
| `getwalletinfo` | `balance`, `unconfirmed_balance`, `immature_balance`, `spendable_balance`, `vaulted_balance`, `txcount` |
| `getbalance` | none, `"*" 0`, `"*" 1 true`, `"*" 0 true`, `"" 0`, `"" 1 true`, `"acct1"`, `"acct1" 0`; and `getunconfirmedbalance` |

Every field of every entry is compared: category, amount and its sign, fee, vout, account, address, involvesWatchonly,
confirmations and bcconfirmations (0 in the mempool, -1 for a conflicted or orphaned transaction), generated,
blockhash, blockindex, blocktime, txid, baretxid, walletconflicts, hex, and the notes a send keeps. Entries are matched
by txid, category, vout, amount and address; the order of `listtransactions` is a row of its own.

**Clock fields.** `time` and `timereceived` come from each node's clock when it hears of a transaction, so they are
compared within 3 s past the relay gap: for a transaction the run waits on to reach every mempool, the seconds
between the twins' mempools first showing it (on a busy host one twin may hear of it 4 s after the other). The
`(relay gap …)` on a FAIL's `#` line gives it. `scripts/smart-time` compares the times exactly, by kind.

**Sends made by one twin.** The twin that made a send keeps its notes (`FromAccount`, `comment`, `to`) and lists its
send entries under the account it was sent from; the other twin only saw the transaction, as a divid that saw it
would. Each kind of send is therefore made once by C and once by I. The notes, the send entries' account and the send
entries `listtransactions ""` and `"acct1"` give are compared maker against maker (`<kind>, as its maker keeps it`
rows); the rest twin against twin.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

A FAIL row names the first difference and prints up to eleven more on `#` lines below it. The run ends with
`FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 25 minutes).

```sh
scripts/tx-history/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/tx-history/run.sh target/release ~/divi-3.0.0/bin 46300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+11` on 127.0.0.2, the p2p and RPC port of S, C, I, M, N and X. S
  listens; the others dial it. A node whose port another process holds starts again on two free ports
  (`scripts/lib/node_ports.py`) and the run prints `# <node>: ports <old>/<old> in use, starting again on <new>/<new>`.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes 10 to 15 minutes (hp1), and is stopped after 25. However it ends, every node is stopped and its
directory deleted. Needs bash and python3 (standard library only, and `scripts/lib`). The phrases are read from
`dumphdinfo` and handed to irondivid in its environment (`WALLET_MNEMONIC`); RPC passwords are random and written only
to each node's 0600 `divi.conf`. None is printed or put on a command line. `TX_HISTORY_INJECT=<row name>` marks that row as differing,
to show a difference is caught. `TX_HISTORY_DEBUG=<dir>` copies every node's debug.log there when a setup step fails.

At the end the run prints, for every transaction it made, what each twin shows (`# shows, at the end: …`:
confirmations, amount, fee, generated, blockhash present, walletconflicts, details, categories listed). These lines
are for reading; the rows above compare the same replies in full.

## Steps

1. S mines 2 blocks, C 3 (C's coinbases, immature: maturity is 20 on regtest), S 95 more (mature).
2. **Receives:** S pays C eight coins, four to the account `acct1`, and a `sendmany` paying C twice and S once; in the
   mempool, then mined.
3. **Sends,** each made by C and by I: `sendfrom acct1` and `sendmany acct1` (each from one coin of acct1's, the
   others locked), `sendtoaddress` to S, to C's own address (a `move`), with comment and comment-to, `sendmany` with
   one payee C's own, and `sendmany` with a comment; in the mempool, then mined.
4. **Stakes:** C's other coins swept into one young coin (`sendrawtransaction`), then C stakes a coin of 21000 alone
   (over `-stakesplitthreshold`, so split in two) and three coins of 1000 of one address (combined).
5. **Lottery:** S stakes the next lottery block, which pays C (it staked in the cycle). 21 blocks: the stakes mature.
6. **Vault:** C funds the vault `<C's address>:<M's address>` (`fundvault`), M and N `addvault`; M stakes the vault's
   coin; 21 blocks; C takes part back (`reclaimvaultfunds`), in the mempool, then mined.
7. **Treasury:** S stakes the next treasury block (150, 200, 250, …), which pays testnet's treasury and charity
   addresses. The twins watch both (`importaddress`), yet the block is in neither wallet (`gettransaction` -5):
   divid takes a transaction in only when it credits or debits spendable coins (addToWalletIfInvolvingMe,
   wallet.cpp:1292-1311), so a watched address paid by others never shows. The run prints the block's outputs and
   `validateaddress` of the treasury address on `#` lines.
8. **Conflict:** C sends to S; S mines a block holding a transaction of C's spending the same coins
   (`generateblock`, ignoring the mempool). The send is conflicted.
9. **Orphaned stake:** X is cut off and stakes three blocks; C stakes one on the others' chain; X joins and its branch
   takes over. C stakes a coin of 12000 S paid it before step 4, which is locked while C funds the vault (step 6) and
   makes the send of step 8, as divid may pick any coin for those.
10. **Never mined:** C sends to S; S mines only blocks that leave the mempool alone; at once, two blocks later, and
    after both twins restart.

## What divid does (Divi Core 3.0.0, `divi/src/`)

- `listtransactions`, `listsinceblock` and `gettransaction` details are ParseTransactionDetails
  (rpcwallet.cpp:2016-2213). A coinstake gives one `stake_reward+` (or `stake_reward` when the staker's outputs come to
  more than the stake reward) entry for the staker, `account` `""`, vout 1, amount the staker's outputs less what was
  staked; every other output of the coinstake that pays the wallet is `lottery` at a lottery height, else `mn_reward`,
  once the coinstake names a block. Another transaction whose inputs and outputs are all the wallet's is one `move`
  entry with `addresses`. Otherwise GetAmounts (:112-182) gives a `send` entry for each output not change when the
  wallet is debited, with the fee, and a `receive` (coinbase: `orphan`, `immature`, `generate`) for each output of the
  wallet.
- WalletTxToJSON (:245-270): `confirmations` is the block's depth on the active chain, else 0 in the mempool, else -1
  (MerkleTxConfirmationNumberCalculator.cpp:43-53); `blockhash`, `blockindex`, `blocktime` only above 0.
- `gettransaction` (:2452-2514): `amount` credit less debit, `fee` debit less the outputs when debited.
- `getwalletinfo` (:2873-2906) and `getbalance` (:1554-1595).
- Rebroadcast: every 0 to 30 minutes, when the tip moved since the last one, up to 32 mempool transactions that spend
  no other mempool transaction (main.cpp:1245-1294). At start, wallet transactions below 1 confirmation are offered to
  the mempool again (init.cpp:1262-1275).

## KNOWN differences

None.
